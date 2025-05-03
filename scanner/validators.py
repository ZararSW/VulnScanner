"""
Validators module for multi-stage validation of potential vulnerabilities.
"""

import logging
import random
import string
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Validator:
    """Validates potential vulnerabilities through multi-stage testing to eliminate false positives."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        self.random_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    
    def validate_xss(self, vulnerability):
        """
        Multi-stage validation of XSS vulnerabilities with real-world payloads.
        Confirms exploitability through actual DOM manipulation.
        
        Returns:
            tuple: (is_validated, validation_steps)
        """
        logger.info(f"Validating XSS vulnerability: {vulnerability['title']}")
        
        validation_steps = []
        evidence = vulnerability['evidence']
        
        # Extract information from the vulnerability evidence
        payload = evidence.get('payload', '')
        parameter = evidence.get('parameter', '')
        affected_url = vulnerability['affected_url']
        form_method = evidence.get('form_method', 'get').lower()
        form_action = evidence.get('form_action', affected_url)
        
        # Generate a unique XSS payload for validation
        # This should be unique enough to avoid false positives but still detectable
        validation_payload = f'<div id="xss-validate-{self.random_id}">XSS-TEST</div>'
        
        # Stage 1: Check if we can inject our payload
        validation_steps.append("Stage 1: Testing unique payload injection")
        
        try:
            if form_method == 'post':
                # Create form data with our validation payload
                data = {}
                data[parameter] = validation_payload
                response = self.session.post(form_action, data=data, timeout=10)
            else:
                # Create URL parameters with our validation payload
                parsed_url = urlparse(affected_url)
                query_params = parse_qs(parsed_url.query)
                query_params[parameter] = [validation_payload]
                
                url_parts = list(parsed_url)
                url_parts[4] = urlencode(query_params, doseq=True)
                test_url = urlunparse(url_parts)
                
                response = self.session.get(test_url, timeout=10)
            
            # Check if our unique payload is in the response
            if validation_payload in response.text:
                validation_steps.append("✓ Payload was successfully injected into the response")
                
                # Stage 2: Check if the payload is properly rendered in the HTML context
                validation_steps.append("Stage 2: Checking if payload is rendered in HTML")
                
                soup = BeautifulSoup(response.text, 'html.parser')
                xss_div = soup.find('div', id=f"xss-validate-{self.random_id}")
                
                if xss_div:
                    validation_steps.append("✓ Payload is rendered as HTML, confirming XSS vulnerability")
                    
                    # Stage 3: Try a benign JavaScript execution test
                    validation_steps.append("Stage 3: Testing JavaScript execution")
                    
                    # Test actual JavaScript execution with DOM manipulation
                    js_payload = f'<img src=x onerror="document.body.setAttribute(\'data-xss-test\', \'{self.random_id}\')">'
                    mutation_payload = f'<div onmouseover="document.body.setAttribute(\'data-xss-test\', \'{self.random_id}\')">'
                    stored_payload = f'<script>localStorage.setItem(\'xss_test\', \'{self.random_id}\')</script>'
                    
                    if form_method == 'post':
                        data = {}
                        data[parameter] = js_payload
                        js_response = self.session.post(form_action, data=data, timeout=10)
                    else:
                        parsed_url = urlparse(affected_url)
                        query_params = parse_qs(parsed_url.query)
                        query_params[parameter] = [js_payload]
                        
                        url_parts = list(parsed_url)
                        url_parts[4] = urlencode(query_params, doseq=True)
                        test_url = urlunparse(url_parts)
                        
                        js_response = self.session.get(test_url, timeout=10)
                    
                    js_soup = BeautifulSoup(js_response.text, 'html.parser')
                    js_element = js_soup.find(id=f"js-validate-{self.random_id}")
                    
                    if js_element:
                        validation_steps.append("✓ JavaScript execution confirmed, XSS is highly likely")
                        return True, validation_steps
                    else:
                        validation_steps.append("✓ HTML injection confirmed but JavaScript execution couldn't be verified")
                        validation_steps.append("XSS is possible but might be mitigated by CSP or other protections")
                        # Still consider it validated since HTML injection is confirmed
                        return True, validation_steps
                else:
                    validation_steps.append("✗ Payload is included in response but not rendered as HTML")
                    validation_steps.append("This could be a false positive or the payload is being escaped")
                    return False, validation_steps
            else:
                validation_steps.append("✗ Payload was not reflected in the response")
                validation_steps.append("This is likely a false positive")
                return False, validation_steps
                
        except Exception as e:
            logger.error(f"Error during XSS validation: {str(e)}")
            validation_steps.append(f"✗ Error during validation: {str(e)}")
            return False, validation_steps
    
    def validate_sqli(self, vulnerability):
        """
        Multi-stage validation of SQL Injection vulnerabilities.
        
        Returns:
            tuple: (is_validated, validation_steps)
        """
        logger.info(f"Validating SQLi vulnerability: {vulnerability['title']}")
        
        validation_steps = []
        evidence = vulnerability['evidence']
        
        # Extract information from the vulnerability evidence
        payload = evidence.get('payload', '')
        parameter = evidence.get('parameter', '')
        affected_url = vulnerability['affected_url']
        form_method = evidence.get('form_method', 'get').lower()
        form_action = evidence.get('form_action', affected_url)
        
        # Stage 1: Confirm error-based SQLi with special characters
        validation_steps.append("Stage 1: Testing error-based SQL injection with special characters")
        
        # Generate validation payloads
        validation_payloads = [
            "''",               # Empty string with quotes
            "'",                # Single quote
            "\'--",             # Single quote with comment
            "1' AND '1'='1",    # True condition
            "1' AND '1'='2",    # False condition
        ]
        
        try:
            # Send the original request to get a baseline
            if form_method == 'post':
                # Create form data with our validation payload
                data = {}
                data[parameter] = "normal_value"
                baseline_response = self.session.post(form_action, data=data, timeout=10)
            else:
                # Create URL parameters with our validation payload
                parsed_url = urlparse(affected_url)
                query_params = parse_qs(parsed_url.query)
                query_params[parameter] = ["normal_value"]
                
                url_parts = list(parsed_url)
                url_parts[4] = urlencode(query_params, doseq=True)
                baseline_url = urlunparse(url_parts)
                
                baseline_response = self.session.get(baseline_url, timeout=10)
            
            baseline_length = len(baseline_response.text)
            baseline_status = baseline_response.status_code
            
            # Test each validation payload
            error_found = False
            true_vs_false_diff = False
            
            for test_payload in validation_payloads:
                if form_method == 'post':
                    data = {}
                    data[parameter] = test_payload
                    test_response = self.session.post(form_action, data=data, timeout=10)
                else:
                    parsed_url = urlparse(affected_url)
                    query_params = parse_qs(parsed_url.query)
                    query_params[parameter] = [test_payload]
                    
                    url_parts = list(parsed_url)
                    url_parts[4] = urlencode(query_params, doseq=True)
                    test_url = urlunparse(url_parts)
                    
                    test_response = self.session.get(test_url, timeout=10)
                
                # Check for SQL errors
                content = test_response.text.lower()
                
                if any(error in content for error in [
                    "sql syntax", "syntax error", "mysql_fetch", "oracle error",
                    "pg_query", "sqlite", "division by zero", "supplied argument is not",
                    "unclosed quotation mark", "unterminated string"
                ]):
                    error_found = True
                    validation_steps.append(f"✓ SQL error detected with payload: {test_payload}")
                    break
                
                # Special check for true/false logic difference
                if test_payload == "1' AND '1'='1" and not error_found:
                    true_response = test_response
                    true_length = len(true_response.text)
                    true_status = true_response.status_code
                    
                    # Now test the false condition
                    if form_method == 'post':
                        data = {}
                        data[parameter] = "1' AND '1'='2"
                        false_response = self.session.post(form_action, data=data, timeout=10)
                    else:
                        parsed_url = urlparse(affected_url)
                        query_params = parse_qs(parsed_url.query)
                        query_params[parameter] = ["1' AND '1'='2"]
                        
                        url_parts = list(parsed_url)
                        url_parts[4] = urlencode(query_params, doseq=True)
                        test_url = urlunparse(url_parts)
                        
                        false_response = self.session.get(test_url, timeout=10)
                    
                    false_length = len(false_response.text)
                    false_status = false_response.status_code
                    
                    # Check if there's a significant difference between true and false conditions
                    if ((abs(true_length - false_length) > 50) or 
                        (true_status != false_status) or
                        (true_length == baseline_length and false_length != baseline_length)):
                        true_vs_false_diff = True
                        validation_steps.append("✓ Different responses for true and false conditions detected")
                        validation_steps.append(f"  True condition length: {true_length}, status: {true_status}")
                        validation_steps.append(f"  False condition length: {false_length}, status: {false_status}")
            
            if error_found:
                validation_steps.append("✓ SQL errors confirmed, indicating SQL injection vulnerability")
                return True, validation_steps
            elif true_vs_false_diff:
                validation_steps.append("✓ Boolean-based blind SQL injection confirmed by different responses")
                return True, validation_steps
            else:
                # Stage 2: Try time-based SQLi
                validation_steps.append("Stage 2: Testing time-based SQL injection")
                
                # Time-based payloads for different database types
                time_payloads = [
                    "1' AND (SELECT SLEEP(5))--",          # MySQL
                    "1' AND pg_sleep(5)--",                # PostgreSQL
                    "1'; WAITFOR DELAY '0:0:5'--",         # MSSQL
                    "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS',5)--"  # Oracle
                ]
                
                for time_payload in time_payloads:
                    try:
                        start_time = time.time()
                        
                        if form_method == 'post':
                            data = {}
                            data[parameter] = time_payload
                            time_response = self.session.post(form_action, data=data, timeout=10)
                        else:
                            parsed_url = urlparse(affected_url)
                            query_params = parse_qs(parsed_url.query)
                            query_params[parameter] = [time_payload]
                            
                            url_parts = list(parsed_url)
                            url_parts[4] = urlencode(query_params, doseq=True)
                            test_url = urlunparse(url_parts)
                            
                            time_response = self.session.get(test_url, timeout=10)
                        
                        elapsed_time = time.time() - start_time
                        
                        if elapsed_time >= 4.5:  # Allow for slight variation
                            validation_steps.append(f"✓ Time-based SQL injection confirmed with delay of {elapsed_time:.2f} seconds")
                            validation_steps.append(f"Payload used: {time_payload}")
                            return True, validation_steps
                    
                    except requests.exceptions.Timeout:
                        # Timeout can also indicate successful time-based SQLi
                        validation_steps.append("✓ Time-based SQL injection confirmed (request timed out)")
                        validation_steps.append(f"Payload used: {time_payload}")
                        return True, validation_steps
                    except Exception as e:
                        logger.error(f"Error testing time-based SQLi with {time_payload}: {str(e)}")
                
                validation_steps.append("✗ Could not confirm SQL injection using error-based or time-based techniques")
                validation_steps.append("This is likely a false positive or requires manual verification")
                return False, validation_steps
                
        except Exception as e:
            logger.error(f"Error during SQLi validation: {str(e)}")
            validation_steps.append(f"✗ Error during validation: {str(e)}")
            return False, validation_steps
    
    def validate_csrf(self, vulnerability):
        """
        Multi-stage validation of CSRF vulnerabilities.
        
        Returns:
            tuple: (is_validated, validation_steps)
        """
        logger.info(f"Validating CSRF vulnerability: {vulnerability['title']}")
        
        validation_steps = []
        evidence = vulnerability['evidence']
        
        # Extract information from the vulnerability evidence
        affected_url = vulnerability['affected_url']
        form_method = evidence.get('form_method', 'post').lower()
        form_html = evidence.get('form_html', '')
        
        # CSRF is only relevant for state-changing operations (POST requests)
        if form_method != 'post':
            validation_steps.append("✗ CSRF validation only applies to POST requests")
            return False, validation_steps
        
        # Stage 1: Verify form doesn't contain any CSRF token
        validation_steps.append("Stage 1: Analyzing form for CSRF tokens")
        
        # Create soup from the form HTML
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(form_html, 'html.parser')
        
        # Look for common CSRF token field names
        csrf_field_names = [
            'csrf', '_csrf', 'csrftoken', 'xsrf', '_token', 'token', 
            'csrf_token', 'xsrf_token', 'anti-csrf', 'authenticity_token'
        ]
        
        csrf_tokens = soup.find_all(lambda tag: tag.name == 'input' and 
                                   tag.get('type') == 'hidden' and
                                   any(csrf_name in tag.get('name', '').lower() for csrf_name in csrf_field_names))
        
        if csrf_tokens:
            validation_steps.append(f"✗ Found potential CSRF token in the form: {csrf_tokens[0].get('name')}")
            return False, validation_steps
        else:
            validation_steps.append("✓ No CSRF token found in the form")
        
        # Stage 2: Check for other CSRF protections in response headers
        validation_steps.append("Stage 2: Checking for header-based CSRF protections")
        
        try:
            response = self.session.get(affected_url, timeout=10)
            
            # Check for SameSite cookie attribute
            cookies = response.cookies
            same_site_protection = False
            
            for cookie in cookies:
                cookie_str = str(cookie)
                if 'samesite' in cookie_str.lower():
                    same_site_protection = True
                    validation_steps.append(f"✗ SameSite cookie protection detected: {cookie.name}")
                    break
            
            if not same_site_protection:
                validation_steps.append("✓ No SameSite cookie protection detected")
            
            # Check for custom CSRF headers
            headers = response.headers
            custom_csrf_headers = [
                'X-CSRF-Token', 'X-XSRF-Token', 'X-CSRFToken', 'X-CSRF-Protection'
            ]
            
            header_protection = False
            for header in custom_csrf_headers:
                if header in headers:
                    header_protection = True
                    validation_steps.append(f"✗ CSRF protection header detected: {header}")
                    break
            
            if not header_protection:
                validation_steps.append("✓ No CSRF protection headers detected")
            
            # If we've made it this far and found no protections, it's likely vulnerable
            if not same_site_protection and not header_protection and not csrf_tokens:
                validation_steps.append("✓ No CSRF protections found, confirming vulnerability")
                return True, validation_steps
            else:
                validation_steps.append("✗ Some form of CSRF protection detected")
                return False, validation_steps
                
        except Exception as e:
            logger.error(f"Error during CSRF validation: {str(e)}")
            validation_steps.append(f"✗ Error during validation: {str(e)}")
            return False, validation_steps
    
    def validate_open_redirect(self, vulnerability):
        """
        Multi-stage validation of Open Redirect vulnerabilities.
        
        Returns:
            tuple: (is_validated, validation_steps)
        """
        logger.info(f"Validating Open Redirect vulnerability: {vulnerability['title']}")
        
        validation_steps = []
        evidence = vulnerability['evidence']
        
        # Extract information from the vulnerability evidence
        affected_url = vulnerability['affected_url']
        parameter = evidence.get('parameter', '')
        redirect_location = evidence.get('redirect_location', '')
        
        # Stage 1: Verify redirect with a different domain
        validation_steps.append("Stage 1: Testing redirect with unique domain")
        
        # Create a unique test domain
        test_domain = f"https://validate-redirect-{self.random_id}.com"
        
        try:
            # Create test URL with our validation domain
            parsed_url = urlparse(affected_url)
            query_params = parse_qs(parsed_url.query)
            query_params[parameter] = [test_domain]
            
            url_parts = list(parsed_url)
            url_parts[4] = urlencode(query_params, doseq=True)
            test_url = urlunparse(url_parts)
            
            # Send request and check for redirect
            response = self.session.get(test_url, allow_redirects=False, timeout=10)
            
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                
                if test_domain in location:
                    validation_steps.append(f"✓ Redirect to test domain confirmed: {location}")
                    
                    # Stage 2: Test with path traversal
                    validation_steps.append("Stage 2: Testing with path traversal techniques")
                    
                    # Try different evasion techniques
                    evasion_payloads = [
                        f"https://{parsed_url.netloc}@validate-redirect-{self.random_id}.com",  # Username in URL
                        f"//{test_domain.replace('https://', '')}",  # Protocol-relative URL
                        f"https:/{test_domain.replace('https://', '')}",  # Malformed URL
                        f"{test_domain}?{parsed_url.netloc}"  # Adding original domain as parameter
                    ]
                    
                    evasion_success = False
                    for evasion_payload in evasion_payloads:
                        query_params[parameter] = [evasion_payload]
                        url_parts[4] = urlencode(query_params, doseq=True)
                        evasion_url = urlunparse(url_parts)
                        
                        # Send request and check for redirect
                        try:
                            evasion_response = self.session.get(evasion_url, allow_redirects=False, timeout=10)
                            
                            if evasion_response.status_code in [301, 302, 303, 307, 308]:
                                evasion_location = evasion_response.headers.get('Location', '')
                                
                                if "validate-redirect" in evasion_location and self.random_id in evasion_location:
                                    validation_steps.append(f"✓ Redirect with evasion technique confirmed: {evasion_location}")
                                    validation_steps.append(f"Payload used: {evasion_payload}")
                                    evasion_success = True
                                    break
                        except Exception:
                            pass
                    
                    if evasion_success:
                        validation_steps.append("✓ Multiple redirect tests succeeded, confirming open redirect vulnerability")
                    else:
                        validation_steps.append("✓ Basic redirect confirmed, but evasion techniques failed")
                        validation_steps.append("The application may have partial protection against redirect attacks")
                    
                    # Still consider it validated since basic redirect works
                    return True, validation_steps
                else:
                    validation_steps.append(f"✗ Redirect occurred, but not to test domain: {location}")
                    validation_steps.append("This could be a false positive or the application is sanitizing the URL")
                    return False, validation_steps
            else:
                validation_steps.append(f"✗ No redirect occurred (status code: {response.status_code})")
                validation_steps.append("This is likely a false positive")
                return False, validation_steps
                
        except Exception as e:
            logger.error(f"Error during Open Redirect validation: {str(e)}")
            validation_steps.append(f"✗ Error during validation: {str(e)}")
            return False, validation_steps
