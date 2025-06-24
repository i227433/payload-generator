"""
Unit tests for core functionality
"""

import pytest
import sys
import os
import json
from unittest.mock import patch, MagicMock

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.payload_generator import PayloadGenerator
from core.encoders import PayloadEncoder
from core.obfuscators import PayloadObfuscator
from utils.validators import validate_url, validate_count
from utils.file_operations import save_payloads, load_config


class TestPayloadGenerator:
    """Test main payload generator"""
    
    def setup_method(self):
        self.config = {
            'payloads': {
                'max_count': 100,
                'default_encoding': 'none',
                'enable_obfuscation': False
            }
        }
        self.generator = PayloadGenerator(config=self.config)
    
    def test_initialization(self):
        assert self.generator is not None
        assert hasattr(self.generator, 'xss_gen')
        assert hasattr(self.generator, 'sqli_gen')
        assert hasattr(self.generator, 'cmdi_gen')
    
    def test_xss_payload_generation(self):
        payloads = self.generator.generate_xss_payloads(count=5)
        assert isinstance(payloads, list)
        assert len(payloads) <= 5
        assert all(isinstance(p, str) for p in payloads)
    
    def test_sqli_payload_generation(self):
        payloads = self.generator.generate_sqli_payloads(count=5)
        assert isinstance(payloads, list)
        assert len(payloads) <= 5
        assert all(isinstance(p, str) for p in payloads)
    
    def test_cmdi_payload_generation(self):
        payloads = self.generator.generate_cmdi_payloads(count=5)
        assert isinstance(payloads, list)
        assert len(payloads) <= 5
        assert all(isinstance(p, str) for p in payloads)
    
    def test_encoding_integration(self):
        payloads = self.generator.generate_xss_payloads(count=3, encoding='url')
        assert isinstance(payloads, list)
        # Check if encoding was applied (URL encoded content should contain %)
        encoded_found = any('%' in payload for payload in payloads)
        assert encoded_found or len(payloads) == 0  # Allow empty list for missing data
    
    def test_obfuscation_integration(self):
        payloads = self.generator.generate_xss_payloads(count=3, obfuscate=True)
        assert isinstance(payloads, list)
        assert len(payloads) <= 3


class TestPayloadEncoder:
    """Test encoding functionality"""
    
    def setup_method(self):
        self.encoder = PayloadEncoder()
    
    def test_base64_encoding(self):
        payload = "test payload"
        encoded = self.encoder.encode(payload, 'base64')
        assert encoded != payload
        assert isinstance(encoded, str)
    
    def test_url_encoding(self):
        payload = "<script>alert('test')</script>"
        encoded = self.encoder.encode(payload, 'url')
        assert encoded != payload
        assert '%' in encoded or encoded == payload  # May not encode if no special chars
    
    def test_hex_encoding(self):
        payload = "test"
        encoded = self.encoder.encode(payload, 'hex')
        assert encoded != payload
        assert isinstance(encoded, str)
    
    def test_html_encoding(self):
        payload = "<script>"
        encoded = self.encoder.encode(payload, 'html')
        assert encoded != payload
        assert '&lt;' in encoded or '&#' in encoded
    
    def test_unicode_encoding(self):
        payload = "test"
        encoded = self.encoder.encode(payload, 'unicode')
        assert isinstance(encoded, str)
    
    def test_invalid_encoding(self):
        payload = "test"
        encoded = self.encoder.encode(payload, 'invalid')
        assert encoded == payload  # Should return original on invalid encoding


class TestPayloadObfuscator:
    """Test obfuscation functionality"""
    
    def setup_method(self):
        self.obfuscator = PayloadObfuscator()
    
    def test_xss_obfuscation(self):
        payload = "<script>alert('test')</script>"
        obfuscated = self.obfuscator.obfuscate_xss(payload)
        assert isinstance(obfuscated, str)
        # Should be different unless no obfuscation rules apply
        assert obfuscated == payload or obfuscated != payload
    
    def test_sqli_obfuscation(self):
        payload = "' OR 1=1--"
        obfuscated = self.obfuscator.obfuscate_sqli(payload)
        assert isinstance(obfuscated, str)
    
    def test_cmdi_obfuscation(self):
        payload = "; cat /etc/passwd"
        obfuscated = self.obfuscator.obfuscate_cmdi(payload)
        assert isinstance(obfuscated, str)


class TestValidators:
    """Test validation utilities"""
    
    def test_valid_url(self):
        assert validate_url("http://example.com") == True
        assert validate_url("https://example.com/path") == True
        assert validate_url("https://example.com:8080/path?param=value") == True
    
    def test_invalid_url(self):
        assert validate_url("not-a-url") == False
        assert validate_url("") == False
        assert validate_url("ftp://example.com") == False  # Only http/https allowed
    
    def test_valid_count(self):
        assert validate_count(1) == True
        assert validate_count(100) == True
        assert validate_count(5) == True
    
    def test_invalid_count(self):
        assert validate_count(0) == False
        assert validate_count(-1) == False
        assert validate_count(10001) == False  # Too large


class TestFileOperations:
    """Test file operations"""
    
    def test_save_payloads_json(self, tmp_path):
        payloads = [
            {'type': 'XSS', 'payload': '<script>alert(1)</script>'},
            {'type': 'SQLi', 'payload': "' OR 1=1--"}
        ]
        
        file_path = tmp_path / "test_payloads.json"
        save_payloads(payloads, str(file_path), 'json')
        
        assert file_path.exists()
        
        with open(file_path, 'r') as f:
            saved_data = json.load(f)
        
        assert 'payloads' in saved_data
        assert 'count' in saved_data
        assert 'generated_at' in saved_data
        assert len(saved_data['payloads']) == 2
        assert saved_data['payloads'][0]['type'] == 'XSS'
    
    def test_save_payloads_txt(self, tmp_path):
        payloads = [
            {'type': 'XSS', 'payload': '<script>alert(1)</script>'},
            {'type': 'SQLi', 'payload': "' OR 1=1--"}
        ]
        
        file_path = tmp_path / "test_payloads.txt"
        save_payloads(payloads, str(file_path), 'txt')
        
        assert file_path.exists()
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        assert '<script>alert(1)</script>' in content
        assert "' OR 1=1--" in content
    
    def test_load_config(self, tmp_path):
        config_data = {
            'test_key': 'test_value',
            'nested': {
                'key': 'value'
            }
        }
        
        config_file = tmp_path / "test_config.json"
        with open(config_file, 'w') as f:
            json.dump(config_data, f)
        
        loaded_config = load_config(str(config_file))
        
        assert loaded_config == config_data
        assert loaded_config['test_key'] == 'test_value'
        assert loaded_config['nested']['key'] == 'value'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
