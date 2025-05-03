"""
Reconnaissance module for the vulnerability scanner.
This module handles the initial data gathering about targets.
"""

import logging
import socket
import dns.resolver
import requests
import re
import concurrent.futures
import json
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from .utils import normalize_url, is_valid_url
from .shodan_client import ShodanClient

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Reconnaissance:
    """Handles target reconnaissance including subdomain discovery, endpoint enumeration,
    and technology detection."""
    
    def __init__(self, target_url, depth='medium', max_workers=10, shodan_api_key=None):
        self.target_url = normalize_url(target_url)
        self.depth = depth  # low, medium, high
        self.max_workers = max_workers
        self.parsed_url = urlparse(self.target_url)
        self.base_domain = self.parsed_url.netloc
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })
        
        # Initialize Shodan client
        self.shodan_api_key = shodan_api_key or "nEdKgekg3bxrV26pP0pzoabiMTlRf5nr"
        self.shodan_client = ShodanClient(self.shodan_api_key)
        
        # Results storage
        self.subdomains = set()
        self.endpoints = set()
        self.technologies = set()
        self.open_ports = {}
        self.emails = set()
        self.ip_addresses = set()
        self.vulnerabilities = []
        self.shodan_data = {}
        
    def run_reconnaissance(self):
        """Main method to run all reconnaissance tasks"""
        logger.info(f"Starting reconnaissance on target: {self.target_url}")
        
        try:
            # Basic information
            self._gather_basic_info()
            
            # Subdomain enumeration (if we're scanning a domain, not an IP)
            if self.base_domain and not self._is_ip_address(self.base_domain):
                self._enumerate_subdomains()
            
            # Shodan intelligence gathering
            self._gather_shodan_intelligence()
            
            # Content discovery
            discovered_urls = self._crawl_website()
            
            # Technology detection
            self._detect_technologies()
            
            # Advanced techniques based on depth
            if self.depth in ['medium', 'high']:
                self._check_common_endpoints()
                self._extract_emails()
                
            if self.depth == 'high':
                self._port_scan()
                
            logger.info(f"Reconnaissance completed on {self.target_url}")
            
            return {
                'subdomains': list(self.subdomains),
                'endpoints': list(self.endpoints),
                'technologies': list(self.technologies),
                'open_ports': self.open_ports,
                'emails': list(self.emails),
                'ip_addresses': list(self.ip_addresses),
                'shodan_data': self.shodan_data,
                'vulnerabilities': self.vulnerabilities
            }
            
        except Exception as e:
            logger.error(f"Error during reconnaissance: {str(e)}")
            return {
                'error': str(e),
                'subdomains': list(self.subdomains),
                'endpoints': list(self.endpoints),
                'technologies': list(self.technologies),
                'open_ports': self.open_ports,
                'emails': list(self.emails),
                'ip_addresses': list(self.ip_addresses),
                'shodan_data': self.shodan_data,
                'vulnerabilities': self.vulnerabilities
            }
    
    def _gather_basic_info(self):
        """Gather basic information about the target"""
        try:
            # Resolve IP address
            ip_address = socket.gethostbyname(self.parsed_url.netloc)
            self.ip_addresses.add(ip_address)
            logger.info(f"Resolved IP address: {ip_address}")
            
            # Initial request to the target
            response = self.session.get(self.target_url, timeout=10)
            logger.info(f"Initial response: Status {response.status_code}")
            
            # Extract server headers
            server = response.headers.get('Server')
            if server:
                self.technologies.add(f"Server: {server}")
            
            # Check for other interesting headers
            for header in ['X-Powered-By', 'X-AspNet-Version', 'X-Runtime']:
                if header in response.headers:
                    self.technologies.add(f"{header}: {response.headers[header]}")
            
        except Exception as e:
            logger.error(f"Error gathering basic info: {str(e)}")
    
    def _enumerate_subdomains(self):
        """Enumerate subdomains of the target domain"""
        logger.info(f"Enumerating subdomains for {self.base_domain}")
        
        # Common subdomain prefixes
        common_prefixes = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
            'smtp', 'secure', 'vpn', 'api', 'dev', 'stage', 'test', 'admin',
            'portal', 'beta', 'gitlab', 'shop', 'app', 'auth', 'cdn'
        ]
        
        # Check common subdomains
        for prefix in common_prefixes:
            subdomain = f"{prefix}.{self.base_domain}"
            try:
                ip_address = socket.gethostbyname(subdomain)
                self.subdomains.add(subdomain)
                self.ip_addresses.add(ip_address)
                logger.info(f"Found subdomain: {subdomain} ({ip_address})")
            except:
                pass
                
        # Additional methods for medium/high depth
        if self.depth in ['medium', 'high']:
            # Try to find DNS records
            try:
                # MX records
                answers = dns.resolver.resolve(self.base_domain, 'MX')
                for rdata in answers:
                    mx_domain = str(rdata.exchange).rstrip('.')
                    if self.base_domain in mx_domain:
                        self.subdomains.add(mx_domain)
                        logger.info(f"Found subdomain from MX: {mx_domain}")
                
                # TXT records might contain SPF info with subdomains
                answers = dns.resolver.resolve(self.base_domain, 'TXT')
                for rdata in answers:
                    txt_record = str(rdata.strings[0])
                    if 'include:' in txt_record and self.base_domain in txt_record:
                        # Extract domains from SPF
                        spf_domains = re.findall(r'include:([^\s]+)', txt_record)
                        for domain in spf_domains:
                            if self.base_domain in domain:
                                self.subdomains.add(domain)
                                logger.info(f"Found subdomain from SPF: {domain}")
            except Exception as e:
                logger.error(f"Error in DNS enumeration: {str(e)}")
    
    def _crawl_website(self):
        """Crawl the website to discover endpoints"""
        logger.info(f"Crawling website: {self.target_url}")
        
        visited_urls = set()
        urls_to_visit = {self.target_url}
        discovered_urls = set()
        
        # Determine the crawl limit based on depth
        if self.depth == 'low':
            crawl_limit = 10
        elif self.depth == 'medium':
            crawl_limit = 30
        else:
            crawl_limit = 100
            
        while urls_to_visit and len(visited_urls) < crawl_limit:
            # Get a URL from the set
            current_url = urls_to_visit.pop()
            
            # Skip if already visited
            if current_url in visited_urls:
                continue
                
            visited_urls.add(current_url)
            logger.info(f"Crawling: {current_url}")
            
            try:
                response = self.session.get(current_url, timeout=10)
                
                # Skip non-HTML responses
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' not in content_type.lower():
                    continue
                    
                # Parse HTML
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find links
                for link in soup.find_all(['a', 'link', 'script', 'img', 'form']):
                    href = None
                    if link.name == 'a' and link.get('href'):
                        href = link.get('href')
                    elif link.name == 'link' and link.get('href'):
                        href = link.get('href')
                    elif link.name == 'script' and link.get('src'):
                        href = link.get('src')
                    elif link.name == 'img' and link.get('src'):
                        href = link.get('src')
                    elif link.name == 'form' and link.get('action'):
                        href = link.get('action')
                        
                    if href:
                        # Convert relative URL to absolute
                        if not href.startswith(('http://', 'https://')):
                            href = urljoin(current_url, href)
                            
                        # Only follow links to the same domain
                        parsed_href = urlparse(href)
                        if parsed_href.netloc == self.parsed_url.netloc or not parsed_href.netloc:
                            if is_valid_url(href):
                                discovered_urls.add(href)
                                self.endpoints.add(href)
                                
                                # Only add to visit queue if we're not at the limit
                                if len(visited_urls) < crawl_limit:
                                    urls_to_visit.add(href)
                
            except Exception as e:
                logger.error(f"Error crawling {current_url}: {str(e)}")
                
        logger.info(f"Crawling completed. Discovered {len(discovered_urls)} URLs")
        return discovered_urls
    
    def _detect_technologies(self):
        """Detect technologies used by the target website"""
        logger.info(f"Detecting technologies for {self.target_url}")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # Check content for common technology signatures
            content = response.text.lower()
            
            # Web frameworks
            if 'django' in content:
                self.technologies.add('Django')
            if 'laravel' in content:
                self.technologies.add('Laravel')
            if 'ruby on rails' in content or 'rails' in content:
                self.technologies.add('Ruby on Rails')
            if 'react' in content:
                self.technologies.add('React')
            if 'angular' in content:
                self.technologies.add('Angular')
            if 'vue' in content:
                self.technologies.add('Vue.js')
                
            # CMS
            if 'wordpress' in content:
                self.technologies.add('WordPress')
            if 'drupal' in content:
                self.technologies.add('Drupal')
            if 'joomla' in content:
                self.technologies.add('Joomla')
                
            # JavaScript libraries
            if 'jquery' in content:
                self.technologies.add('jQuery')
            if 'bootstrap' in content:
                self.technologies.add('Bootstrap')
                
            # Check for specific files
            for tech_file in ['/robots.txt', '/sitemap.xml', '/wp-login.php', '/administrator']:
                try:
                    tech_url = urljoin(self.target_url, tech_file)
                    r = self.session.get(tech_url, timeout=5)
                    if r.status_code == 200:
                        self.endpoints.add(tech_url)
                        if tech_file == '/wp-login.php':
                            self.technologies.add('WordPress')
                        elif tech_file == '/administrator' and 'joomla' in r.text.lower():
                            self.technologies.add('Joomla')
                except:
                    pass
            
        except Exception as e:
            logger.error(f"Error detecting technologies: {str(e)}")
    
    def _check_common_endpoints(self):
        """Check for common endpoints and directories"""
        logger.info("Checking common endpoints")
        
        common_endpoints = [
            '/admin', '/login', '/wp-admin', '/administrator', '/phpmyadmin',
            '/api', '/api/v1', '/api/v2', '/dashboard', '/console',
            '/register', '/signup', '/user', '/users', '/account',
            '/config', '/settings', '/backup', '/db', '/database',
            '/dev', '/test', '/staging', '/beta', '/debug',
            '/private', '/secret', '/hidden', '/logs', '/log',
            '/.git', '/.env', '/wp-config.php', '/config.php',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml'
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for endpoint in common_endpoints:
                url = urljoin(self.target_url, endpoint)
                futures.append(executor.submit(self._check_endpoint, url))
                
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.endpoints.add(result)
                except Exception as e:
                    logger.error(f"Error checking endpoint: {str(e)}")
    
    def _check_endpoint(self, url):
        """Check if an endpoint exists"""
        try:
            response = self.session.get(url, timeout=5, allow_redirects=False)
            if response.status_code in [200, 301, 302, 403]:
                logger.info(f"Found endpoint: {url} (Status: {response.status_code})")
                return url
        except:
            pass
        return None
    
    def _extract_emails(self):
        """Extract email addresses from the website"""
        logger.info("Extracting email addresses")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            content = response.text
            
            # Simple email regex pattern
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            found_emails = re.findall(email_pattern, content)
            
            for email in found_emails:
                # Validate it's an email for the target domain
                domain = email.split('@')[1]
                if self.base_domain in domain:
                    self.emails.add(email)
                    logger.info(f"Found email: {email}")
        
        except Exception as e:
            logger.error(f"Error extracting emails: {str(e)}")
    
    def _port_scan(self):
        """Scan common ports on the target"""
        logger.info(f"Scanning common ports on {self.ip_addresses}")
        
        # Common ports to scan
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        for ip_address in self.ip_addresses:
            self.open_ports[ip_address] = []
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip_address, port))
                    if result == 0:
                        self.open_ports[ip_address].append(port)
                        logger.info(f"Port {port} is open on {ip_address}")
                    sock.close()
                except:
                    continue
    
    def _gather_shodan_intelligence(self):
        """Use Shodan API to gather intelligence about the target"""
        logger.info("Gathering intelligence from Shodan")
        
        try:
            if not self.ip_addresses:
                # If no IP addresses have been found yet, get them
                try:
                    ip_address = socket.gethostbyname(self.parsed_url.netloc)
                    self.ip_addresses.add(ip_address)
                except Exception as e:
                    logger.error(f"Error resolving IP for Shodan intelligence: {str(e)}")
                    return
            
            # For each IP address, get Shodan information
            for ip_address in self.ip_addresses:
                logger.info(f"Querying Shodan for IP: {ip_address}")
                host_data = self.shodan_client.host_lookup(ip_address)
                
                if host_data:
                    # Store the raw Shodan data
                    self.shodan_data[ip_address] = host_data
                    
                    # Extract open ports
                    if not ip_address in self.open_ports:
                        self.open_ports[ip_address] = []
                        
                    for service in host_data.get('data', []):
                        port = service.get('port')
                        if port and port not in self.open_ports[ip_address]:
                            self.open_ports[ip_address].append(port)
                            logger.info(f"Shodan found open port {port} on {ip_address}")
                        
                        # Extract technologies
                        product = service.get('product')
                        if product:
                            self.technologies.add(f"Shodan: {product} {service.get('version', '')}")
                    
                    # Extract vulnerabilities
                    for vuln_id, vuln_details in host_data.get('vulns', {}).items():
                        vuln = {
                            'id': vuln_id,
                            'cvss': vuln_details.get('cvss'),
                            'summary': vuln_details.get('summary'),
                            'references': vuln_details.get('references', []),
                            'source': 'Shodan'
                        }
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Shodan found vulnerability: {vuln_id} (CVSS: {vuln.get('cvss')})")
                    
                    # Extract organization info
                    org = host_data.get('org')
                    if org:
                        logger.info(f"Organization: {org}")
                
                # If we have a domain, also get domain-specific information
                if not self._is_ip_address(self.base_domain):
                    domain_info = self.shodan_client.get_domain_info(self.target_url)
                    if domain_info:
                        # Add to shodan_data
                        self.shodan_data['domain_info'] = domain_info
                        
                        # Add subdomains
                        for subdomain in domain_info.get('subdomains', []):
                            self.subdomains.add(subdomain)
                            logger.info(f"Shodan found subdomain: {subdomain}")
                        
                        # Add technologies
                        for tech in domain_info.get('technologies', []):
                            self.technologies.add(f"Shodan: {tech}")
                            
                        # Add vulnerabilities
                        for vuln in domain_info.get('vulnerabilities', []):
                            self.vulnerabilities.append({
                                'id': vuln.get('id'),
                                'cvss': vuln.get('cvss'),
                                'summary': vuln.get('summary'),
                                'source': 'Shodan'
                            })
        
        except Exception as e:
            logger.error(f"Error gathering Shodan intelligence: {str(e)}")
    
    def _is_ip_address(self, address):
        """Check if a string is an IP address"""
        try:
            socket.inet_aton(address)
            return True
        except:
            return False
