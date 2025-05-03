"""
Core scanner module that coordinates the scanning process.
"""

import logging
import threading
import time
from datetime import datetime
from urllib.parse import urlparse

from .recon import Reconnaissance
from .validators import Validator
from .exploits import ExploitGenerator
from .utils import normalize_url

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Scanner:
    """Main scanner class that coordinates the scanning process."""

    def __init__(self, target_url, scan_id=None, depth='medium'):
        self.target_url = normalize_url(target_url)
        self.scan_id = scan_id
        self.depth = depth
        self.parsed_url = urlparse(self.target_url)

        # Initialize components
        self.recon = Reconnaissance(self.target_url, depth=self.depth)
        self.validator = Validator()
        self.exploit_generator = ExploitGenerator()

        # State tracking
        self.status = 'initialized'
        self.progress = 0
        self.vulnerabilities = []
        self.recon_data = {}
        self.scan_thread = None

    def start_scan(self):
        """Start the scanning process synchronously"""
        logger.info(f"Starting scan on {self.target_url}")

        try:
            # Update scan status in database
            self._update_scan_status('in_progress', 0)
            self._update_scan_started()

            # Step 1: Reconnaissance (20% of progress)
            logger.info("Starting reconnaissance phase")
            self.recon_data = self.recon.run_reconnaissance()
            self._save_recon_data()
            self._update_scan_status('in_progress', 20)

            # Step 2: Vulnerability scanning (60% of progress)
            logger.info("Starting vulnerability scanning phase")
            self._scan_vulnerabilities()
            self._update_scan_status('in_progress', 80)

            # Step 3: Validation and exploit generation (20% of progress)
            logger.info("Starting validation phase")
            self._validate_vulnerabilities()
            self._update_scan_status('completed', 100)
            self._update_scan_completed()

            logger.info(f"Scan completed on {self.target_url}")
            return {
                'status': 'completed',
                'vulnerabilities': self.vulnerabilities,
                'recon_data': self.recon_data
            }

        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            self._update_scan_status('failed', self.progress)
            return {
                'status': 'failed',
                'error': str(e)
            }

    def start_scan_async(self):
        """Start the scanning process in a separate thread"""
        if self.scan_thread and self.scan_thread.is_alive():
            logger.warning("Scan already running")
            return False

        # Import Flask app to create an application context in the thread
        from app import app

        # Create a wrapper function that runs with app context
        def run_with_app_context():
            with app.app_context():
                self.start_scan()

        self.scan_thread = threading.Thread(target=run_with_app_context)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        return True

    def _scan_vulnerabilities(self):
        """Run vulnerability scans on the target"""
        endpoints = self.recon_data.get('endpoints', [])

        if not endpoints:
            endpoints = [self.target_url]

        # Track progress for this phase (20-80%)
        total_endpoints = len(endpoints)
        completed = 0

        for endpoint in endpoints:
            # XSS scanning
            self._scan_for_xss(endpoint)

            # SQL Injection scanning
            self._scan_for_sqli(endpoint)

            # CSRF scanning
            self._scan_for_csrf(endpoint)

            # Open redirect scanning
            self._scan_for_open_redirect(endpoint)

            # Server-side vulnerabilities
            self._scan_for_server_vulnerabilities(endpoint)

            # Update progress
            completed += 1
            progress = 20 + int(60 * (completed / total_endpoints))
            self._update_scan_status('in_progress', progress)

    def _scan_for_xss(self, url):
        """Scan for XSS vulnerabilities"""
        logger.info(f"Scanning for XSS on {url}")

        # Simple XSS payloads
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            "';alert(1);//",
            '<svg/onload=alert(1)>'
        ]

        # Create a helper method to save vulnerabilities in real-time
        def save_vulnerability_realtime(vulnerability):
            self.vulnerabilities.append(vulnerability)
            # Save this vulnerability to the database immediately
            try:
                from app import db, app
                from models import Vulnerability
                import json

                # Use Flask app context to save right away
                with app.app_context():
                    new_vuln = Vulnerability(
                        scan_id=self.scan_id,
                        title=vulnerability['title'],
                        description=vulnerability['description'],
                        vulnerability_type=vulnerability['vulnerability_type'],
                        severity=vulnerability['severity'],
                        affected_url=vulnerability['affected_url'],
                        proof_of_concept=vulnerability['proof_of_concept'],
                        is_verified=vulnerability['is_verified'],
                        is_false_positive=vulnerability.get('is_false_positive', False),
                        validation_steps=vulnerability.get('validation_steps', ''),
                        evidence=vulnerability['evidence']
                    )
                    db.session.add(new_vuln)
                    db.session.commit()
                    logger.info(f"Real-time saved: {vulnerability['vulnerability_type']} on {vulnerability['affected_url']}")
            except Exception as e:
                logger.error(f"Error saving vulnerability in real-time: {str(e)}")

        # Get form parameters from the URL
        import requests
        from bs4 import BeautifulSoup

        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all forms
            forms = soup.find_all('form')
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()

                # Build the form submission URL
                if not form_action:
                    form_action = url
                elif not form_action.startswith(('http://', 'https://')):
                    # Handle relative URLs
                    from urllib.parse import urljoin
                    form_action = urljoin(url, form_action)

                # Find all input fields
                input_fields = {}
                for input_field in form.find_all(['input', 'textarea']):
                    field_name = input_field.get('name')
                    if field_name:
                        input_fields[field_name] = input_field.get('value', '')

                # Test each input field with XSS payloads
                for field_name in input_fields:
                    for payload in xss_payloads:
                        test_data = input_fields.copy()
                        test_data[field_name] = payload

                        # Submit the form
                        try:
                            if form_method == 'post':
                                test_response = requests.post(form_action, data=test_data, timeout=10)
                            else:
                                test_response = requests.get(form_action, params=test_data, timeout=10)

                            # Check if the payload is reflected without encoding
                            if payload in test_response.text:
                                # Potential XSS found
                                vulnerability = {
                                    'title': 'Reflected XSS',
                                    'description': f'Potential XSS vulnerability found in {field_name} parameter',
                                    'vulnerability_type': 'XSS',
                                    'severity': 'high',
                                    'affected_url': form_action,
                                    'proof_of_concept': f'Submit {payload} in the {field_name} field',
                                    'is_verified': False,
                                    'evidence': {
                                        'payload': payload,
                                        'parameter': field_name,
                                        'form_action': form_action,
                                        'form_method': form_method
                                    }
                                }
                                save_vulnerability_realtime(vulnerability)
                                logger.warning(f"Potential XSS found on {form_action} in {field_name}")

                        except Exception as e:
                            logger.error(f"Error testing XSS on {form_action}: {str(e)}")

            # Also test URL parameters
            from urllib.parse import parse_qs, urlparse, urlencode, urlunparse

            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            if query_params:
                for param in query_params:
                    for payload in xss_payloads:
                        test_params = query_params.copy()
                        test_params[param] = [payload]

                        # Build test URL
                        test_url_parts = list(parsed_url)
                        test_url_parts[4] = urlencode(test_params, doseq=True)
                        test_url = urlunparse(test_url_parts)

                        try:
                            test_response = requests.get(test_url, timeout=10)

                            # Check if the payload is reflected without encoding
                            if payload in test_response.text:
                                # Potential XSS found
                                vulnerability = {
                                    'title': 'Reflected XSS',
                                    'description': f'Potential XSS vulnerability found in {param} parameter',
                                    'vulnerability_type': 'XSS',
                                    'severity': 'high',
                                    'affected_url': url,
                                    'proof_of_concept': f'Navigate to {test_url}',
                                    'is_verified': False,
                                    'evidence': {
                                        'payload': payload,
                                        'parameter': param,
                                        'test_url': test_url
                                    }
                                }
                                save_vulnerability_realtime(vulnerability)
                                logger.warning(f"Potential XSS found on {url} in {param}")

                        except Exception as e:
                            logger.error(f"Error testing XSS on URL {test_url}: {str(e)}")

        except Exception as e:
            logger.error(f"Error scanning for XSS on {url}: {str(e)}")

    def _scan_for_sqli(self, url):
        """Scan for SQL Injection vulnerabilities"""
        logger.info(f"Scanning for SQL Injection on {url}")

        # Simple SQLi payloads
        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "' OR 1=1#",
            "') OR ('1'='1",
            "admin' --",
            "1' OR '1' = '1",
            "1 OR 1=1"
        ]

        # Create a helper method to save vulnerabilities in real-time
        def save_vulnerability_realtime(vulnerability):
            self.vulnerabilities.append(vulnerability)
            # Save this vulnerability to the database immediately
            try:
                from app import db, app
                from models import Vulnerability
                import json

                # Use Flask app context to save right away
                with app.app_context():
                    new_vuln = Vulnerability(
                        scan_id=self.scan_id,
                        title=vulnerability['title'],
                        description=vulnerability['description'],
                        vulnerability_type=vulnerability['vulnerability_type'],
                        severity=vulnerability['severity'],
                        affected_url=vulnerability['affected_url'],
                        proof_of_concept=vulnerability['proof_of_concept'],
                        is_verified=vulnerability['is_verified'],
                        is_false_positive=vulnerability.get('is_false_positive', False),
                        validation_steps=vulnerability.get('validation_steps', ''),
                        evidence=vulnerability['evidence']
                    )
                    db.session.add(new_vuln)
                    db.session.commit()
                    logger.info(f"Real-time saved: {vulnerability['vulnerability_type']} on {vulnerability['affected_url']}")
            except Exception as e:
                logger.error(f"Error saving vulnerability in real-time: {str(e)}")

        # SQLi error patterns
        sqli_errors = [
            "sql syntax",
            "syntax error",
            "mysql_fetch",
            "mysql_num_rows",
            "mysql_query",
            "pg_query",
            "sqlite_query",
            "oracle error",
            "warning: mysql",
            "unclosed quotation mark",
            "division by zero",
            "supplied argument is not a valid mysql",
            "microsoft ole db provider for sql server"
        ]

        # Get form parameters and test them
        import requests
        from bs4 import BeautifulSoup

        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all forms
            forms = soup.find_all('form')
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()

                # Build the form submission URL
                if not form_action:
                    form_action = url
                elif not form_action.startswith(('http://', 'https://')):
                    # Handle relative URLs
                    from urllib.parse import urljoin
                    form_action = urljoin(url, form_action)

                # Find all input fields
                input_fields = {}
                for input_field in form.find_all(['input', 'textarea']):
                    field_name = input_field.get('name')
                    if field_name:
                        input_fields[field_name] = input_field.get('value', '')

                # Test each input field with SQLi payloads
                for field_name in input_fields:
                    for payload in sqli_payloads:
                        test_data = input_fields.copy()
                        test_data[field_name] = payload

                        # Submit the form
                        try:
                            if form_method == 'post':
                                test_response = requests.post(form_action, data=test_data, timeout=10)
                            else:
                                test_response = requests.get(form_action, params=test_data, timeout=10)

                            # Check for SQL errors in the response
                            content = test_response.text.lower()
                            for error in sqli_errors:
                                if error in content:
                                    # Potential SQLi found
                                    vulnerability = {
                                        'title': 'SQL Injection',
                                        'description': f'Potential SQL Injection vulnerability found in {field_name} parameter',
                                        'vulnerability_type': 'SQLi',
                                        'severity': 'critical',
                                        'affected_url': form_action,
                                        'proof_of_concept': f'Submit {payload} in the {field_name} field',
                                        'is_verified': False,
                                        'evidence': {
                                            'payload': payload,
                                            'parameter': field_name,
                                            'form_action': form_action,
                                            'form_method': form_method,
                                            'error': error
                                        }
                                    }
                                    save_vulnerability_realtime(vulnerability)
                                    logger.warning(f"Potential SQLi found on {form_action} in {field_name}")
                                    break

                        except Exception as e:
                            logger.error(f"Error testing SQLi on {form_action}: {str(e)}")

            # Test URL parameters
            from urllib.parse import parse_qs, urlparse, urlencode, urlunparse

            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            if query_params:
                for param in query_params:
                    for payload in sqli_payloads:
                        test_params = query_params.copy()
                        test_params[param] = [payload]

                        # Build test URL
                        test_url_parts = list(parsed_url)
                        test_url_parts[4] = urlencode(test_params, doseq=True)
                        test_url = urlunparse(test_url_parts)

                        try:
                            test_response = requests.get(test_url, timeout=10)

                            # Check for SQL errors in the response
                            content = test_response.text.lower()
                            for error in sqli_errors:
                                if error in content:
                                    # Potential SQLi found
                                    vulnerability = {
                                        'title': 'SQL Injection',
                                        'description': f'Potential SQL Injection vulnerability found in {param} parameter',
                                        'vulnerability_type': 'SQLi',
                                        'severity': 'critical',
                                        'affected_url': url,
                                        'proof_of_concept': f'Navigate to {test_url}',
                                        'is_verified': False,
                                        'evidence': {
                                            'payload': payload,
                                            'parameter': param,
                                            'test_url': test_url,
                                            'error': error
                                        }
                                    }
                                    save_vulnerability_realtime(vulnerability)
                                    logger.warning(f"Potential SQLi found on {url} in {param}")
                                    break

                        except Exception as e:
                            logger.error(f"Error testing SQLi on URL {test_url}: {str(e)}")

        except Exception as e:
            logger.error(f"Error scanning for SQLi on {url}: {str(e)}")

    def _scan_for_csrf(self, url):
        """Scan for CSRF vulnerabilities"""
        logger.info(f"Scanning for CSRF on {url}")

        import requests
        from bs4 import BeautifulSoup

        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all forms
            forms = soup.find_all('form')
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'post').lower()

                # Only check POST forms (GET forms don't need CSRF protection)
                if form_method != 'post':
                    continue

                # Build the form submission URL
                if not form_action:
                    form_action = url
                elif not form_action.startswith(('http://', 'https://')):
                    # Handle relative URLs
                    from urllib.parse import urljoin
                    form_action = urljoin(url, form_action)

                # Check for CSRF token
                csrf_fields = form.find_all(lambda tag: tag.name == 'input' and 
                                            (tag.get('name', '').lower() in ['csrf', 'csrf_token', 'csrftoken', 'xsrf', 
                                                                             'xsrf_token', '_csrf', '_token', 'token', 
                                                                             'anti-csrf', 'anti-xsrf', 'anticsrf', 'antixsrf'] or
                                             'csrf' in tag.get('name', '').lower()))

                if not csrf_fields:
                    # No CSRF token found
                    vulnerability = {
                        'title': 'Cross-Site Request Forgery (CSRF)',
                        'description': f'POST form without CSRF protection found',
                        'vulnerability_type': 'CSRF',
                        'severity': 'medium',
                        'affected_url': form_action,
                        'proof_of_concept': 'Submit the form from a different origin without any CSRF token',
                        'is_verified': False,
                        'evidence': {
                            'form_action': form_action,
                            'form_method': form_method,
                            'form_html': str(form)
                        }
                    }
                    self.vulnerabilities.append(vulnerability)
                    logger.warning(f"Potential CSRF vulnerability found on {form_action}")

        except Exception as e:
            logger.error(f"Error scanning for CSRF on {url}: {str(e)}")

    def _scan_for_open_redirect(self, url):
        """Scan for open redirect vulnerabilities"""
        logger.info(f"Scanning for open redirect on {url}")

        # Redirect test URLs
        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "https:///evil.com",
            "https://evil%E3%80%82com",
            "https://%65%76%69%6c%2e%63%6f%6d"  # URL encoded evil.com
        ]

        # Check URL parameters
        from urllib.parse import parse_qs, urlparse, urlencode, urlunparse
        import requests

        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        # Look for potential redirect parameters
        redirect_params = []
        for param in query_params:
            lower_param = param.lower()
            if any(keyword in lower_param for keyword in ['redirect', 'return', 'url', 'goto', 'next', 'target', 'destination', 'redir', 'link']):
                redirect_params.append(param)

        # Test each potential redirect parameter
        if redirect_params:
            for param in redirect_params:
                for payload in redirect_payloads:
                    test_params = query_params.copy()
                    test_params[param] = [payload]

                    # Build test URL
                    test_url_parts = list(parsed_url)
                    test_url_parts[4] = urlencode(test_params, doseq=True)
                    test_url = urlunparse(test_url_parts)

                    try:
                        test_response = requests.get(test_url, timeout=10, allow_redirects=False)

                        # Check for redirect to our payload
                        if test_response.status_code in [301, 302, 303, 307, 308]:
                            location = test_response.headers.get('Location', '')
                            payload_domain = urlparse(payload).netloc

                            if payload_domain and payload_domain in location:
                                # Open redirect found
                                vulnerability = {
                                    'title': 'Open Redirect',
                                    'description': f'Open redirect vulnerability found in {param} parameter',
                                    'vulnerability_type': 'Open Redirect',
                                    'severity': 'medium',
                                    'affected_url': url,
                                    'proof_of_concept': f'Navigate to {test_url}',
                                    'is_verified': False,
                                    'evidence': {
                                        'payload': payload,
                                        'parameter': param,
                                        'test_url': test_url,
                                        'redirect_location': location
                                    }
                                }
                                self.vulnerabilities.append(vulnerability)
                                logger.warning(f"Open redirect found on {url} in {param}")

                    except Exception as e:
                        logger.error(f"Error testing open redirect on {test_url}: {str(e)}")

    def _scan_for_server_vulnerabilities(self, url):
        """Scan for server-side vulnerabilities"""
        logger.info(f"Scanning for server-side vulnerabilities on {url}")

        # Check for sensitive files
        self._check_sensitive_files(url)

        # Check for security headers
        self._check_security_headers(url)

        # Check for information disclosure
        self._check_information_disclosure(url)

    def _check_sensitive_files(self, url):
        """Check for sensitive files and directories"""
        from urllib.parse import urljoin
        import requests

        sensitive_paths = [
            '/.git/config',
            '/.env',
            '/config.php',
            '/wp-config.php',
            '/config.yml',
            '/database.yml',
            '/settings.py',
            '/backup',
            '/backup.zip',
            '/backup.tar.gz',
            '/db.sqlite',
            '/dump.sql'
        ]

        for path in sensitive_paths:
            try:
                test_url = urljoin(url, path)
                response = requests.get(test_url, timeout=5)

                if response.status_code == 200:
                    # Check file content to reduce false positives
                    content = response.text.lower()

                    # Different content checks based on file type
                    is_sensitive = False

                    if path == '/.git/config' and ('[core]' in content or '[remote' in content):
                        is_sensitive = True
                    elif path == '/.env' and ('db_password' in content or 'api_key' in content or 'secret' in content):
                        is_sensitive = True
                    elif path.endswith('.php') and ('<?php' in content):
                        is_sensitive = True
                    elif path.endswith('.py') and ('import' in content or 'def ' in content):
                        is_sensitive = True
                    elif path.endswith('.yml') and ('password:' in content or 'secret:' in content):
                        is_sensitive = True
                    elif path.endswith(('.zip', '.tar.gz', '.sql', '.sqlite')) and response.headers.get('Content-Type') not in ['text/html', 'application/json']:
                        is_sensitive = True

                    if is_sensitive:
                        vulnerability = {
                            'title': 'Sensitive File Exposure',
                            'description': f'Sensitive file or configuration found at {path}',
                            'vulnerability_type': 'Information Disclosure',
                            'severity': 'high',
                            'affected_url': test_url,
                            'proof_of_concept': f'Navigate to {test_url}',
                            'is_verified': True,
                            'evidence': {
                                'path': path,
                                'content_sample': content[:200] if len(content) > 200 else content
                            }
                        }
                        self.vulnerabilities.append(vulnerability)
                        logger.warning(f"Sensitive file found at {test_url}")

            except Exception as e:
                logger.error(f"Error checking sensitive file {path}: {str(e)}")

    def _check_security_headers(self, url):
        """Check for missing security headers"""
        import requests

        try:
            response = requests.get(url, timeout=10)
            headers = response.headers

            security_headers = {
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'Content-Security-Policy': 'Missing Content-Security-Policy header',
                'X-Frame-Options': 'Missing X-Frame-Options header',
                'Strict-Transport-Security': 'Missing HSTS header',
                'Referrer-Policy': 'Missing Referrer-Policy header'
            }

            missing_headers = []

            for header, description in security_headers.items():
                if header not in headers:
                    missing_headers.append({
                        'header': header,
                        'description': description
                    })

            if missing_headers:
                vulnerability = {
                    'title': 'Missing Security Headers',
                    'description': f'The application is missing several security headers that help to protect against common attacks',
                    'vulnerability_type': 'Misconfiguration',
                    'severity': 'low',
                    'affected_url': url,
                    'proof_of_concept': 'Check response headers',
                    'is_verified': True,
                    'evidence': {
                        'missing_headers': missing_headers,
                        'current_headers': dict(headers)
                    }
                }
                self.vulnerabilities.append(vulnerability)
                logger.warning(f"Missing security headers on {url}")

        except Exception as e:
            logger.error(f"Error checking security headers on {url}: {str(e)}")

    def _check_information_disclosure(self, url):
        """Check for information disclosure in server headers and responses"""
        import requests

        try:
            response = requests.get(url, timeout=10)
            headers = response.headers

            # Check server header
            server = headers.get('Server', '')
            if server and any(tech in server for tech in ['apache', 'nginx', 'iis', 'tomcat', 'php', 'python']):
                vulnerability = {
                    'title': 'Server Information Disclosure',
                    'description': f'The server discloses software information in headers: {server}',
                    'vulnerability_type': 'Information Disclosure',
                    'severity': 'low',
                    'affected_url': url,
                    'proof_of_concept': 'Check Server header in response',
                    'is_verified': True,
                    'evidence': {
                        'header': 'Server',
                        'value': server
                    }
                }
                self.vulnerabilities.append(vulnerability)
                logger.warning(f"Server information disclosure on {url}: {server}")

            # Check X-Powered-By header
            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                vulnerability = {
                    'title': 'Technology Information Disclosure',
                    'description': f'The server discloses technology information in headers: {powered_by}',
                    'vulnerability_type': 'Information Disclosure',
                    'severity': 'low',
                    'affected_url': url,
                    'proof_of_concept': 'Check X-Powered-By header in response',
                    'is_verified': True,
                    'evidence': {
                        'header': 'X-Powered-By',
                        'value': powered_by
                    }
                }
                self.vulnerabilities.append(vulnerability)
                logger.warning(f"Technology information disclosure on {url}: {powered_by}")

            # Check for error messages with stack traces
            content = response.text.lower()
            if any(error in content for error in ['exception', 'stack trace', 'syntax error', 'traceback', 'debug', 'error in']):
                # Look for stack trace patterns
                import re
                stack_trace = re.search(r'(stack trace:?.*|traceback \(most recent call last\):|exception in thread|syntax error|runtime error)', content, re.IGNORECASE)

                if stack_trace:
                    vulnerability = {
                        'title': 'Error Information Disclosure',
                        'description': 'The application reveals error details or stack traces',
                        'vulnerability_type': 'Information Disclosure',
                        'severity': 'medium',
                        'affected_url': url,
                        'proof_of_concept': 'Visit the page and observe the error details',
                        'is_verified': True,
                        'evidence': {
                            'error_context': content[max(0, stack_trace.start() - 100):min(stack_trace.end() + 300, len(content))]
                        }
                    }
                    self.vulnerabilities.append(vulnerability)
                    logger.warning(f"Error information disclosure on {url}")

        except Exception as e:
            logger.error(f"Error checking information disclosure on {url}: {str(e)}")

    def _validate_vulnerabilities(self):
        """Validate found vulnerabilities to eliminate false positives"""
        logger.info("Validating vulnerabilities")

        # Create a list for validated vulnerabilities
        validated_vulnerabilities = []

        for vulnerability in self.vulnerabilities:
            # First check if this is a duplicate
            is_duplicate = False
            for validated in validated_vulnerabilities:
                if (validated['vulnerability_type'] == vulnerability['vulnerability_type'] and
                    validated['affected_url'] == vulnerability['affected_url']):
                    # Check for parameter-based duplicates in XSS and SQLi
                    if vulnerability['vulnerability_type'] in ['XSS', 'SQLi', 'Open Redirect']:
                        vuln_param = vulnerability['evidence'].get('parameter', '')
                        valid_param = validated['evidence'].get('parameter', '')
                        if vuln_param == valid_param:
                            is_duplicate = True
                            break
                    else:
                        is_duplicate = True
                        break

            if is_duplicate:
                continue

            # Multi-stage validation based on vulnerability type
            is_validated = False
            validation_steps = []

            try:
                if vulnerability['vulnerability_type'] == 'XSS':
                    is_validated, validation_steps = self.validator.validate_xss(vulnerability)
                elif vulnerability['vulnerability_type'] == 'SQLi':
                    is_validated, validation_steps = self.validator.validate_sqli(vulnerability)
                elif vulnerability['vulnerability_type'] == 'CSRF':
                    is_validated, validation_steps = self.validator.validate_csrf(vulnerability)
                elif vulnerability['vulnerability_type'] == 'Open Redirect':
                    is_validated, validation_steps = self.validator.validate_open_redirect(vulnerability)
                elif vulnerability['vulnerability_type'] == 'Information Disclosure':
                    # Information disclosure findings are usually already verified
                    is_validated = True
                    validation_steps = ['Verified by direct observation']
                elif vulnerability['vulnerability_type'] == 'Misconfiguration':
                    # Misconfigurations are usually already verified
                    is_validated = True
                    validation_steps = ['Verified by direct observation']
            except Exception as e:
                logger.error(f"Error validating {vulnerability['vulnerability_type']} vulnerability: {str(e)}")
                continue

            # Update the vulnerability with validation results
            vulnerability['is_verified'] = is_validated
            vulnerability['is_false_positive'] = notis_validated
            vulnerability['validation_steps'] = '\n'.join(validation_steps)

            # Only add validated vulnerabilities or include information disclosures (even if validation wasn't performed)
            if is_validated or vulnerability['is_verified']:
                # Generate exploit proof-of-concept if applicable
                if is_validated and vulnerability['vulnerability_type'] in ['XSS', 'SQLi', 'CSRF', 'Open Redirect']:
                    try:
                        poc = self.exploit_generator.generate_poc(vulnerability)
                        vulnerability['proof_of_concept'] = poc
                    except Exception as e:
                        logger.error(f"Error generating PoC: {str(e)}")

                validated_vulnerabilities.append(vulnerability)

        # Replace the original vulnerabilities list with the validated one
        self.vulnerabilities = validated_vulnerabilities

        # Save validated vulnerabilities to the database
        self._save_vulnerabilities()

        logger.info(f"Validation completed. Found {len(self.vulnerabilities)} real vulnerabilities.")

    def _save_vulnerabilities(self):
        """Save validated vulnerabilities to the database"""
        if not self.scan_id:
            return

        try:
            from app import db, app
            from models import Vulnerability
            import json

            # Use Flask app context
            with app.app_context():
                for vuln in self.vulnerabilities:
                    new_vuln = Vulnerability(
                        scan_id=self.scan_id,
                        title=vuln['title'],
                        description=vuln['description'],
                        vulnerability_type=vuln['vulnerability_type'],
                        severity=vuln['severity'],
                        affected_url=vuln['affected_url'],
                        proof_of_concept=vuln['proof_of_concept'],
                        is_verified=vuln['is_verified'],
                        is_false_positive=vuln.get('is_false_positive', False),
                        validation_steps=vuln.get('validation_steps', ''),
                        evidence=vuln['evidence']
                    )
                    db.session.add(new_vuln)

                db.session.commit()
                logger.info(f"Saved {len(self.vulnerabilities)} vulnerabilities to database")

        except Exception as e:
            logger.error(f"Error saving vulnerabilities to database: {str(e)}")

    def _save_recon_data(self):
        """Save reconnaissance data to the database"""
        if not self.scan_id:
            return

        try:
            from app import db, app
            from models import ReconnaissanceData
            import json

            # Use Flask app context
            with app.app_context():
                # Save subdomains
                for subdomain in self.recon_data.get('subdomains', []):
                    recon_data = ReconnaissanceData(
                        scan_id=self.scan_id,
                        data_type='subdomain',
                        data_value=subdomain
                    )
                    db.session.add(recon_data)

                # Save endpoints
                for endpoint in self.recon_data.get('endpoints', []):
                    recon_data = ReconnaissanceData(
                        scan_id=self.scan_id,
                        data_type='endpoint',
                        data_value=endpoint
                    )
                    db.session.add(recon_data)

                # Save technologies
                for tech in self.recon_data.get('technologies', []):
                    recon_data = ReconnaissanceData(
                        scan_id=self.scan_id,
                        data_type='technology',
                        data_value=tech
                    )
                    db.session.add(recon_data)

                # Save emails
                for email in self.recon_data.get('emails', []):
                    recon_data = ReconnaissanceData(
                        scan_id=self.scan_id,
                        data_type='email',
                        data_value=email
                    )
                    db.session.add(recon_data)

                # Save IP addresses
                for ip in self.recon_data.get('ip_addresses', []):
                    recon_data = ReconnaissanceData(
                        scan_id=self.scan_id,
                        data_type='ip_address',
                        data_value=ip
                    )
                    db.session.add(recon_data)

                # Save open ports
                for ip, ports in self.recon_data.get('open_ports', {}).items():
                    recon_data = ReconnaissanceData(
                        scan_id=self.scan_id,
                        data_type='open_ports',
                        data_value=f"{ip}: {', '.join(map(str, ports))}"
                    )
                    db.session.add(recon_data)

                db.session.commit()
                logger.info("Saved reconnaissance data to database")

        except Exception as e:
            logger.error(f"Error saving reconnaissance data to database: {str(e)}")

    def _update_scan_status(self, status, progress):
        """Update scan status in the database"""
        if not self.scan_id:
            return

        try:
            from app import db, app
            from models import Scan

            # Use Flask app context
            with app.app_context():
                scan = Scan.query.get(self.scan_id)
                if scan:
                    scan.status = status
                    scan.progress = progress
                    db.session.commit()
                    logger.info(f"Updated scan status: {status}, progress: {progress}%")

            # Update local status
            self.status = status
            self.progress = progress

        except Exception as e:
            logger.error(f"Error updating scan status: {str(e)}")

    def _update_scan_started(self):
        """Update scan start time in the database"""
        if not self.scan_id:
            return

        try:
            from app import db, app
            from models import Scan
            from datetime import datetime

            # Use Flask app context
            with app.app_context():
                scan = Scan.query.get(self.scan_id)
                if scan:
                    scan.started_at = datetime.utcnow()
                    db.session.commit()
                    logger.info(f"Updated scan start time")

        except Exception as e:
            logger.error(f"Error updating scan start time: {str(e)}")

    def _update_scan_completed(self):
        """Update scan completion time in the database"""
        if not self.scan_id:
            return

        try:
            from app import db, app
            from models import Scan
            from datetime import datetime

            # Use Flask app context
            with app.app_context():
                scan = Scan.query.get(self.scan_id)
                if scan:
                    scan.completed_at = datetime.utcnow()
                    db.session.commit()
                    logger.info(f"Updated scan completion time")

        except Exception as e:
            logger.error(f"Error updating scan completion time: {str(e)}")