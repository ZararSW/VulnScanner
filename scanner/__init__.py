"""
Advanced Web Vulnerability Scanner with Bug Bounty Methodology
This package contains all the core scanning functionality for the vulnerability scanner.

Main components:
- Reconnaissance module
- Scanner core
- Validators for multi-stage validation
- Exploit generation and verification
- Utility functions
"""

from .scanner import Scanner
from .recon import Reconnaissance
from .validators import Validator
from .exploits import ExploitGenerator

__version__ = '0.1.0'
