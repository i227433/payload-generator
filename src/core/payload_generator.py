"""
Core payload generation module
Handles the main payload generation logic and orchestration
"""

import random
import re
import sys
import os
from typing import List, Dict, Optional, Any
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.encoders import PayloadEncoder
from core.obfuscators import PayloadObfuscator
from modules.xss_generator import XSSGenerator
from modules.sqli_generator import SQLiGenerator
from modules.cmdi_generator import CMDiGenerator


class PayloadGenerator:
    """Main payload generator class that orchestrates all payload generation"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the payload generator
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.encoder = PayloadEncoder()
        self.obfuscator = PayloadObfuscator()
        
        # Initialize specialized generators with expected attribute names
        self.xss_gen = XSSGenerator()
        self.sqli_gen = SQLiGenerator()
        self.cmdi_gen = CMDiGenerator()
        
        # Also keep the full names for backward compatibility
        self.xss_generator = self.xss_gen
        self.sqli_generator = self.sqli_gen
        self.cmdi_generator = self.cmdi_gen
        
        # Load payload databases
        self._load_payload_databases()
    
    def _load_payload_databases(self):
        """Load payload databases from data files"""
        try:
            data_dir = Path(__file__).parent.parent.parent / "data" / "payloads"
            
            # Load XSS payloads
            xss_file = data_dir / "xss_payloads.json"
            if xss_file.exists():
                self.xss_generator.load_payload_database(str(xss_file))
            
            # Load SQLi payloads
            sqli_file = data_dir / "sqli_payloads.json"
            if sqli_file.exists():
                self.sqli_generator.load_payload_database(str(sqli_file))
            
            # Load CMDi payloads
            cmdi_file = data_dir / "cmdi_payloads.json"
            if cmdi_file.exists():
                self.cmdi_generator.load_payload_database(str(cmdi_file))
                
        except Exception as e:
            print(f"Warning: Could not load payload databases: {e}")
    
    def generate_xss_payloads(self, count: int = 5, context: str = 'html',
                             encoding: str = 'none', obfuscate: bool = False,
                             filter_bypass: bool = False, waf_evasion: bool = False) -> List[str]:
        """
        Generate XSS payloads with specified options
        
        Args:
            count: Number of payloads to generate
            context: XSS context (html, attribute, script, css, url)
            encoding: Encoding method to apply
            obfuscate: Whether to apply obfuscation
            filter_bypass: Whether to include filter bypass techniques
            waf_evasion: Whether to apply WAF evasion techniques
            
        Returns:
            List of generated XSS payloads
        """
        # Generate base payloads
        payloads = self.xss_generator.generate_payloads(
            count=count,
            context=context,
            filter_bypass=filter_bypass,
            waf_evasion=waf_evasion
        )
        
        # Apply transformations
        processed_payloads = []
        for payload in payloads:
            # Apply obfuscation first
            if obfuscate:
                payload = self.obfuscator.obfuscate_xss(payload)
            
            # Apply encoding
            if encoding != 'none':
                payload = self.encoder.encode(payload, encoding)
            
            processed_payloads.append(payload)
        
        return processed_payloads
    
    def generate_sqli_payloads(self, count: int = 5, database: str = 'mysql',
                              encoding: str = 'none', obfuscate: bool = False,
                              filter_bypass: bool = False, waf_evasion: bool = False,
                              blind: bool = False) -> List[str]:
        """
        Generate SQL injection payloads with specified options
        
        Args:
            count: Number of payloads to generate
            database: Database type (mysql, postgres, mssql, oracle, sqlite)
            encoding: Encoding method to apply
            obfuscate: Whether to apply obfuscation
            filter_bypass: Whether to include filter bypass techniques
            waf_evasion: Whether to apply WAF evasion techniques
            blind: Whether to generate blind injection payloads
            
        Returns:
            List of generated SQL injection payloads
        """
        # Generate base payloads
        payloads = self.sqli_generator.generate_payloads(
            count=count,
            database=database,
            filter_bypass=filter_bypass,
            waf_evasion=waf_evasion,
            blind=blind
        )
        
        # Apply transformations
        processed_payloads = []
        for payload in payloads:
            # Apply obfuscation first
            if obfuscate:
                payload = self.obfuscator.obfuscate_sqli(payload)
            
            # Apply encoding
            if encoding != 'none':
                payload = self.encoder.encode(payload, encoding)
            
            processed_payloads.append(payload)
        
        return processed_payloads
    
    def generate_cmdi_payloads(self, count: int = 5, platform: str = 'both',
                              encoding: str = 'none', obfuscate: bool = False,
                              filter_bypass: bool = False, waf_evasion: bool = False) -> List[str]:
        """
        Generate command injection payloads with specified options
        
        Args:
            count: Number of payloads to generate
            platform: Target platform (linux, windows, both)
            encoding: Encoding method to apply
            obfuscate: Whether to apply obfuscation
            filter_bypass: Whether to include filter bypass techniques
            waf_evasion: Whether to apply WAF evasion techniques
            
        Returns:
            List of generated command injection payloads
        """
        # Generate base payloads
        payloads = self.cmdi_generator.generate_payloads(
            count=count,
            platform=platform,
            filter_bypass=filter_bypass,
            waf_evasion=waf_evasion
        )
        
        # Apply transformations
        processed_payloads = []
        for payload in payloads:
            # Apply obfuscation first
            if obfuscate:
                payload = self.obfuscator.obfuscate_cmdi(payload)
            
            # Apply encoding
            if encoding != 'none':
                payload = self.encoder.encode(payload, encoding)
            
            processed_payloads.append(payload)
        
        return processed_payloads
    
    def generate_custom_payload(self, base_payload: str, transformations: List[str]) -> str:
        """
        Generate a custom payload with specified transformations
        
        Args:
            base_payload: Base payload string
            transformations: List of transformations to apply
            
        Returns:
            Transformed payload
        """
        payload = base_payload
        
        for transformation in transformations:
            if transformation.startswith('encode:'):
                encoding_type = transformation.split(':')[1]
                payload = self.encoder.encode(payload, encoding_type)
            elif transformation == 'obfuscate':
                # Auto-detect payload type for obfuscation
                if any(tag in payload.lower() for tag in ['<script', '<img', '<svg', 'javascript:']):
                    payload = self.obfuscator.obfuscate_xss(payload)
                elif any(keyword in payload.lower() for keyword in ['union', 'select', 'or', 'and']):
                    payload = self.obfuscator.obfuscate_sqli(payload)
                elif any(char in payload for char in [';', '&&', '||', '|', '`']):
                    payload = self.obfuscator.obfuscate_cmdi(payload)
        
        return payload
    
    def validate_payload(self, payload: str, payload_type: str) -> Dict[str, Any]:
        """
        Validate a payload for basic syntax and structure
        
        Args:
            payload: Payload to validate
            payload_type: Type of payload (xss, sqli, cmdi)
            
        Returns:
            Validation result dictionary
        """
        result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'score': 0
        }
        
        if payload_type.lower() == 'xss':
            result = self.xss_generator.validate_payload(payload)
        elif payload_type.lower() == 'sqli':
            result = self.sqli_generator.validate_payload(payload)
        elif payload_type.lower() == 'cmdi':
            result = self.cmdi_generator.validate_payload(payload)
        else:
            result['valid'] = False
            result['errors'].append(f"Unknown payload type: {payload_type}")
        
        return result
    
    def get_payload_stats(self) -> Dict[str, Any]:
        """
        Get statistics about available payloads
        
        Returns:
            Dictionary containing payload statistics
        """
        return {
            'xss_payloads': len(self.xss_generator.payload_database),
            'sqli_payloads': len(self.sqli_generator.payload_database),
            'cmdi_payloads': len(self.cmdi_generator.payload_database),
            'total_payloads': (
                len(self.xss_generator.payload_database) +
                len(self.sqli_generator.payload_database) +
                len(self.cmdi_generator.payload_database)
            ),
            'encoding_methods': self.encoder.get_available_encodings(),
            'obfuscation_methods': self.obfuscator.get_available_methods()
        }
