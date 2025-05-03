"""
Shodan API Client Module for enhanced reconnaissance

This module integrates with Shodan's API to gather intelligence about targets,
including open ports, vulnerabilities, and exposed services.
"""

import requests
import os
import json
import time
import logging
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ShodanClient:
    """Client for interacting with the Shodan API to enhance reconnaissance capabilities."""
    
    def __init__(self, api_key=None):
        """
        Initialize the Shodan client.
        
        Args:
            api_key (str): Shodan API key. If not provided, will try to get from environment.
        """
        self.api_key = api_key or "nEdKgekg3bxrV26pP0pzoabiMTlRf5nr"
        self.base_url = "https://api.shodan.io"
        self.rate_limit_delay = 1  # Seconds between requests to avoid rate limiting
        
    def host_lookup(self, ip_address):
        """
        Lookup information about a specific IP address.
        
        Args:
            ip_address (str): IP address to lookup
            
        Returns:
            dict: Information about the host or None if not found
        """
        url = f"{self.base_url}/shodan/host/{ip_address}?key={self.api_key}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.info(f"No Shodan information found for {ip_address}")
                return None
            else:
                logger.warning(f"Error retrieving Shodan host data: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Exception in Shodan host lookup: {e}")
            return None
        finally:
            time.sleep(self.rate_limit_delay)  # Respect rate limits
    
    def search_domain(self, domain):
        """
        Search for information about a domain.
        
        Args:
            domain (str): Domain to search for
            
        Returns:
            list: List of results related to the domain
        """
        url = f"{self.base_url}/shodan/host/search?key={self.api_key}&query=hostname:{domain}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return response.json().get("matches", [])
            else:
                logger.warning(f"Error searching domain in Shodan: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Exception in Shodan domain search: {e}")
            return []
        finally:
            time.sleep(self.rate_limit_delay)  # Respect rate limits
    
    def get_domain_info(self, url):
        """
        Get comprehensive information about a domain from Shodan.
        
        Args:
            url (str): URL to analyze
            
        Returns:
            dict: Organized information about the domain
        """
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]
        
        # Search for the domain
        results = self.search_domain(domain)
        
        # Extract and organize information
        info = {
            "domain": domain,
            "ip_addresses": [],
            "open_ports": set(),
            "technologies": set(),
            "vulnerabilities": [],
        }
        
        # Process search results
        for result in results:
            # Get IP address
            ip = result.get("ip_str")
            if ip and ip not in info["ip_addresses"]:
                info["ip_addresses"].append(ip)
                
                # Get detailed information for this IP
                host_data = self.host_lookup(ip)
                if host_data:
                    # Get open ports
                    for port_data in host_data.get("data", []):
                        port = port_data.get("port")
                        if port:
                            info["open_ports"].add(port)
                        
                        # Get technologies
                        product = port_data.get("product")
                        if product:
                            info["technologies"].add(product)
                            
                    # Get vulnerabilities
                    for vuln in host_data.get("vulns", {}):
                        info["vulnerabilities"].append({
                            "id": vuln,
                            "cvss": host_data["vulns"][vuln].get("cvss"),
                            "summary": host_data["vulns"][vuln].get("summary")
                        })
        
        # Convert sets to lists for JSON serialization
        info["open_ports"] = sorted(list(info["open_ports"]))
        info["technologies"] = sorted(list(info["technologies"]))
        
        return info
    
    def get_ssl_information(self, ip_address):
        """
        Get SSL certificate information for a host.
        
        Args:
            ip_address (str): IP address to lookup
            
        Returns:
            dict: SSL certificate information or None if not available
        """
        host_data = self.host_lookup(ip_address)
        if not host_data:
            return None
            
        for service in host_data.get("data", []):
            if service.get("ssl"):
                return service["ssl"]
        
        return None