"""
Custom Payload Generator for Web Exploitation
A comprehensive tool for generating evasion-ready payloads with Burp Suite integration
"""

__version__ = "1.0.0"
__author__ = "Security Researcher"
__email__ = "security@example.com"
__description__ = "Custom Payload Generator for Web Exploitation Testing"

import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.dirname(__file__))

from core.payload_generator import PayloadGenerator
from integrations.burp_api import BurpSuiteAPI

__all__ = [
    'PayloadGenerator',
    'BurpSuiteAPI'
]
