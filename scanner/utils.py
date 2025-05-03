"""
Utility functions for the vulnerability scanner.
"""

import logging
import re
from urllib.parse import urlparse, urljoin

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def normalize_url(url):
    """Normalize a URL to ensure it has a scheme and is properly formatted.
    
    Args:
        url (str): The URL to normalize.
        
    Returns:
        str: Normalized URL.
    """
    if not url:
        return None
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Ensure URL has a trailing slash if it's just a domain
    parsed = urlparse(url)
    if not parsed.path:
        url = url + '/'
    
    return url

def is_valid_url(url):
    """Check if a URL is valid.
    
    Args:
        url (str): The URL to check.
        
    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    if not url:
        return False
    
    # Check if the URL has a valid scheme
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    
    # Exclude common file extensions that are probably not useful for scanning
    excluded_extensions = [
        '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.ico', 
        '.svg', '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip',
        '.tar', '.gz', '.mp3', '.mp4', '.avi', '.mov', '.wmv', 
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
    ]
    
    if any(parsed.path.endswith(ext) for ext in excluded_extensions):
        return False
    
    # Exclude URLs with fragments only (e.g., #section)
    if not parsed.netloc and not parsed.path and parsed.fragment:
        return False
    
    # Exclude mailto, tel, etc.
    if parsed.scheme in ('mailto', 'tel', 'ftp', 'file'):
        return False
    
    return True

def is_same_domain(url1, url2):
    """Check if two URLs point to the same domain.
    
    Args:
        url1 (str): First URL.
        url2 (str): Second URL.
        
    Returns:
        bool: True if both URLs point to the same domain, False otherwise.
    """
    parsed1 = urlparse(url1)
    parsed2 = urlparse(url2)
    
    return parsed1.netloc == parsed2.netloc

def get_base_url(url):
    """Get the base URL (scheme + netloc) from a URL.
    
    Args:
        url (str): The URL to parse.
        
    Returns:
        str: The base URL.
    """
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def extract_domain(url):
    """Extract the domain from a URL.
    
    Args:
        url (str): The URL to extract domain from.
        
    Returns:
        str: The domain.
    """
    parsed = urlparse(url)
    return parsed.netloc

def is_ip_address(host):
    """Check if a hostname is an IP address.
    
    Args:
        host (str): The hostname to check.
        
    Returns:
        bool: True if the hostname is an IP address, False otherwise.
    """
    # Simple regex for IPv4 address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(ip_pattern, host))

def get_root_domain(domain):
    """Extract the root domain from a subdomain.
    
    Args:
        domain (str): The domain to extract the root from.
        
    Returns:
        str: The root domain.
    """
    # Handle IP addresses
    if is_ip_address(domain):
        return domain
        
    # Split by periods and take last two parts for most TLDs
    parts = domain.split('.')
    if len(parts) <= 2:
        return domain
    
    # Special case for known multi-part TLDs like .co.uk, .com.au
    known_tlds = [
        '.co.uk', '.com.au', '.com.br', '.co.nz', '.co.za', '.co.jp',
        '.org.uk', '.net.au', '.org.au', '.ac.uk', '.gov.au'
    ]
    
    for tld in known_tlds:
        if domain.endswith(tld):
            tld_parts = tld.count('.') + 1
            if len(parts) > tld_parts:
                return '.'.join(parts[-tld_parts-1:])
            return domain
    
    # Default case: return last two parts
    return '.'.join(parts[-2:])

def sanitize_filename(filename):
    """Sanitize a filename to make it safe for file system.
    
    Args:
        filename (str): The filename to sanitize.
        
    Returns:
        str: Sanitized filename.
    """
    # Replace invalid characters with underscore
    sanitized = re.sub(r'[\\/*?:"<>|]', '_', filename)
    # Limit length
    return sanitized[:255]

def truncate_string(text, max_length=100):
    """Truncate a string to the specified maximum length.
    
    Args:
        text (str): The text to truncate.
        max_length (int): Maximum length.
        
    Returns:
        str: Truncated text.
    """
    if not text:
        return ""
    
    if len(text) <= max_length:
        return text
    
    return text[:max_length] + "..."
