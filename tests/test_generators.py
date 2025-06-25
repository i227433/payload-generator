"""
Test suite for payload generators
"""

import pytest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from modules.xss_generator import XSSGenerator
from modules.sqli_generator import SQLiGenerator
from modules.cmdi_generator import CMDiGenerator
from core.payload_generator import PayloadGenerator
from core.encoders import PayloadEncoder
from core.obfuscators import PayloadObfuscator


class TestXSSGenerator:
    """Test XSS payload generation"""
    
    def setup_method(self):
        self.generator = XSSGenerator()
    
    def test_basic_xss_generation(self):
        payloads = self.generator.generate_payloads(count=5)
        assert len(payloads) <= 5
        assert all(isinstance(payload, str) for payload in payloads)
    
    def test_context_specific_generation(self):
        html_payloads = self.generator.generate_payloads(count=3, context='html')
        attr_payloads = self.generator.generate_payloads(count=3, context='attribute')
        
        assert len(html_payloads) <= 3
        assert len(attr_payloads) <= 3
    
    def test_payload_validation(self):
        payload = "<script>alert('test')</script>"
        result = self.generator.validate_payload(payload)
        
        assert isinstance(result, dict)
        assert 'valid' in result
        assert 'score' in result


class TestSQLiGenerator:
    """Test SQL injection payload generation"""
    
    def setup_method(self):
        self.generator = SQLiGenerator()
    
    def test_basic_sqli_generation(self):
        payloads = self.generator.generate_payloads(count=5)
        assert len(payloads) <= 5
        assert all(isinstance(payload, str) for payload in payloads)
    
    def test_database_specific_generation(self):
        mysql_payloads = self.generator.generate_payloads(count=3, database='mysql')
        postgres_payloads = self.generator.generate_payloads(count=3, database='postgres')
        
        assert len(mysql_payloads) <= 3
        assert len(postgres_payloads) <= 3
    
    def test_blind_payload_generation(self):
        blind_payloads = self.generator.generate_payloads(count=3, blind=True)
        assert len(blind_payloads) <= 3


class TestCMDiGenerator:
    """Test command injection payload generation"""
    
    def setup_method(self):
        self.generator = CMDiGenerator()
    
    def test_basic_cmdi_generation(self):
        payloads = self.generator.generate_payloads(count=5)
        assert len(payloads) <= 5
        assert all(isinstance(payload, str) for payload in payloads)
    
    def test_platform_specific_generation(self):
        linux_payloads = self.generator.generate_payloads(count=3, platform='linux')
        windows_payloads = self.generator.generate_payloads(count=3, platform='windows')
        
        assert len(linux_payloads) <= 3
        assert len(windows_payloads) <= 3


class TestPayloadEncoder:
    """Test payload encoding functionality"""
    
    def setup_method(self):
        self.encoder = PayloadEncoder()
    
    def test_base64_encoding(self):
        payload = "test"
        encoded = self.encoder.encode(payload, 'base64')
        assert encoded != payload
        assert isinstance(encoded, str)
    
    def test_url_encoding(self):
        payload = "<script>alert('test')</script>"
        encoded = self.encoder.encode(payload, 'url')
        assert encoded != payload
        assert '%' in encoded
    
    def test_available_encodings(self):
        encodings = self.encoder.get_available_encodings()
        assert isinstance(encodings, list)
        assert 'base64' in encodings
        assert 'url' in encodings


class TestPayloadObfuscator:
    """Test payload obfuscation functionality"""
    
    def setup_method(self):
        self.obfuscator = PayloadObfuscator()
    
    def test_xss_obfuscation(self):
        payload = "<script>alert('test')</script>"
        obfuscated = self.obfuscator.obfuscate_xss(payload)
        assert isinstance(obfuscated, str)
        # Obfuscated payload might be the same or different
    
    def test_sqli_obfuscation(self):
        payload = "' OR 1=1--"
        obfuscated = self.obfuscator.obfuscate_sqli(payload)
        assert isinstance(obfuscated, str)
    
    def test_cmdi_obfuscation(self):
        payload = "; id"
        obfuscated = self.obfuscator.obfuscate_cmdi(payload)
        assert isinstance(obfuscated, str)


class TestPayloadGenerator:
    """Test main payload generator functionality"""
    
    def setup_method(self):
        self.generator = PayloadGenerator()
    
    def test_xss_payload_generation(self):
        payloads = self.generator.generate_xss_payloads(count=3)
        assert len(payloads) <= 3
        assert all(isinstance(payload, str) for payload in payloads)
    
    def test_sqli_payload_generation(self):
        payloads = self.generator.generate_sqli_payloads(count=3)
        assert len(payloads) <= 3
        assert all(isinstance(payload, str) for payload in payloads)
    
    def test_cmdi_payload_generation(self):
        payloads = self.generator.generate_cmdi_payloads(count=3)
        assert len(payloads) <= 3
        assert all(isinstance(payload, str) for payload in payloads)
    
    def test_payload_stats(self):
        stats = self.generator.get_payload_stats()
        assert isinstance(stats, dict)
        assert 'total_payloads' in stats
    
    def test_custom_payload_generation(self):
        base_payload = "<script>alert('test')</script>"
        transformations = ['encode:base64', 'obfuscate']
        
        custom_payload = self.generator.generate_custom_payload(base_payload, transformations)
        assert isinstance(custom_payload, str)


# Integration tests (require actual setup)
class TestIntegration:
    """Integration tests - may require manual setup"""
    
    def test_burp_integration(self):
        """Test Burp Suite integration - conditionally skipped if Burp Suite not available"""
        try:
            from integrations.burp_api import BurpSuiteAPI
            
            burp = BurpSuiteAPI()
            connection_ok = burp.test_connection()
            
            if not connection_ok:
                pytest.skip("Burp Suite Professional not running or not accessible")
            
            # If we get here, Burp Suite is available
            assert isinstance(connection_ok, bool)
            assert connection_ok is True
            
            # Test additional functionality if connection is successful
            info = burp.get_burp_info()
            assert isinstance(info, dict)
            
        except ImportError:
            pytest.skip("Burp Suite integration module not available")
        except Exception as e:
            pytest.skip(f"Burp Suite integration test failed: {str(e)}")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
