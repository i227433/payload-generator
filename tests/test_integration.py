"""
Integration tests for the full application
"""

import pytest
import sys
import os
import json
import tempfile
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from main import main
from integrations.burp_api import BurpSuiteAPI


class TestCLIIntegration:
    """Test CLI integration"""
    
    def setup_method(self):
        self.runner = CliRunner()
    
    def test_help_command(self):
        result = self.runner.invoke(main, ['--help'])
        assert result.exit_code == 0
        assert 'Custom Payload Generator' in result.output
    
    def test_version_command(self):
        result = self.runner.invoke(main, ['--version'])
        assert result.exit_code == 0
        assert '1.0.0' in result.output
    
    def test_xss_generation(self):
        result = self.runner.invoke(main, ['--xss', '--count=3', '--verbose'])
        assert result.exit_code == 0
        assert 'XSS PAYLOADS' in result.output or 'Generated' in result.output
    
    def test_sqli_generation(self):
        result = self.runner.invoke(main, ['--sqli', '--count=3', '--verbose'])
        assert result.exit_code == 0
        assert 'SQL INJECTION PAYLOADS' in result.output or 'Generated' in result.output
    
    def test_cmdi_generation(self):
        result = self.runner.invoke(main, ['--cmdi', '--count=3', '--verbose'])
        assert result.exit_code == 0
        assert 'COMMAND INJECTION PAYLOADS' in result.output or 'Generated' in result.output
    
    def test_multiple_payload_types(self):
        result = self.runner.invoke(main, [
            '--xss', '--sqli', '--cmdi', 
            '--count=2', '--verbose'
        ])
        assert result.exit_code == 0
    
    def test_encoding_options(self):
        result = self.runner.invoke(main, [
            '--xss', '--count=2', 
            '--encode=url', '--verbose'
        ])
        assert result.exit_code == 0
    
    def test_obfuscation_option(self):
        result = self.runner.invoke(main, [
            '--xss', '--count=2', 
            '--obfuscate', '--verbose'
        ])
        assert result.exit_code == 0
    def test_platform_option(self):
        result = self.runner.invoke(main, [
            '--cmdi', '--count=2', 
            '--platform=windows', '--verbose'
        ])
        assert result.exit_code == 0
    
    def test_database_option(self):
        result = self.runner.invoke(main, [
            '--sqli', '--count=2', 
            '--database=mysql', '--verbose'
        ])
        assert result.exit_code == 0
    
    def test_context_option(self):
        result = self.runner.invoke(main, [
            '--xss', '--count=2', 
            '--context=attribute', '--verbose'
        ])
        assert result.exit_code == 0
    
    def test_save_to_file(self):
        import tempfile
        import os
        
        # Create a temporary file path without opening the file
        temp_dir = tempfile.gettempdir()
        temp_file = os.path.join(temp_dir, 'test_payloads.json')
        
        try:
            result = self.runner.invoke(main, [
                '--xss', '--count=2', 
                '--save', temp_file, '--verbose'
            ])
            
            assert result.exit_code == 0
            assert os.path.exists(temp_file)
            
            # Verify file content
            with open(temp_file, 'r') as f:
                data = json.load(f)
            assert isinstance(data, dict)
            assert 'payloads' in data
            assert 'count' in data
            assert len(data['payloads']) == 2
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
    
    def test_invalid_url(self):
        result = self.runner.invoke(main, [
            '--xss', '--target=invalid-url', '--verbose'
        ])
        assert result.exit_code == 1
        assert 'Invalid target URL' in result.output
    
    def test_invalid_count(self):
        result = self.runner.invoke(main, [
            '--xss', '--count=0', '--verbose'
        ])
        assert result.exit_code == 1
        assert 'Invalid count value' in result.output
    
    def test_no_payload_type(self):
        result = self.runner.invoke(main, [])
        assert result.exit_code == 0  # Shows banner and exits gracefully
    
    def test_filter_bypass_option(self):
        result = self.runner.invoke(main, [
            '--xss', '--count=2', 
            '--filter-bypass', '--verbose'
        ])
        assert result.exit_code == 0
    
    def test_waf_evasion_option(self):
        result = self.runner.invoke(main, [
            '--sqli', '--count=2', 
            '--waf-evasion', '--verbose'
        ])
        assert result.exit_code == 0
    
    def test_blind_sqli_option(self):
        result = self.runner.invoke(main, [
            '--sqli', '--count=2', 
            '--blind', '--verbose'
        ])
        assert result.exit_code == 0


class TestBurpSuiteIntegration:
    """Test Burp Suite API integration"""
    
    def setup_method(self):
        self.config = {
            'base_url': 'http://127.0.0.1:1337',
            'api_key': 'test_key',
            'timeout': 30,
            'retry_attempts': 3
        }
    
    def test_burp_api_initialization(self):
        api = BurpSuiteAPI(config=self.config)
        assert api is not None
        assert api.base_url == self.config['base_url']
        assert api.api_key == self.config['api_key']
    
    @patch.object(BurpSuiteAPI, 'test_connection')
    def test_connection_success(self, mock_test_connection):
        mock_test_connection.return_value = True
        
        api = BurpSuiteAPI(config=self.config)
        result = api.test_connection()
        assert result == True
    
    @patch.object(BurpSuiteAPI, 'test_connection')
    def test_connection_failure(self, mock_test_connection):
        mock_test_connection.return_value = False
        
        api = BurpSuiteAPI(config=self.config)
        result = api.test_connection()
        assert result == False
    
    @patch.object(BurpSuiteAPI, 'send_to_repeater')
    def test_send_to_repeater(self, mock_send_to_repeater):
        mock_send_to_repeater.return_value = True
        
        api = BurpSuiteAPI(config=self.config)
        result = api.send_to_repeater('http://example.com', '<script>alert(1)</script>')
        assert result == True
    
    @patch.object(BurpSuiteAPI, 'send_to_intruder')
    def test_send_to_intruder(self, mock_send_to_intruder):
        mock_send_to_intruder.return_value = True
        
        api = BurpSuiteAPI(config=self.config)
        payloads = ['payload1', 'payload2', 'payload3']
        result = api.send_to_intruder('http://example.com', payloads)
        assert result == True
    
    @patch.object(BurpSuiteAPI, 'get_site_map')
    def test_get_site_map(self, mock_get_site_map):
        mock_get_site_map.return_value = [
            {'url': 'http://example.com/page1'},
            {'url': 'http://example.com/page2'}
        ]
        
        api = BurpSuiteAPI(config=self.config)
        result = api.get_site_map()
        assert isinstance(result, list)
        assert len(result) == 2


class TestEndToEndWorkflow:
    """Test complete end-to-end workflows"""
    
    def setup_method(self):
        self.runner = CliRunner()
    
    def test_generate_and_save_xss_payloads(self):
        """Test generating XSS payloads and saving to file"""
        import tempfile
        import os
        
        # Create a temporary file path without opening the file
        temp_dir = tempfile.gettempdir()
        temp_file = os.path.join(temp_dir, 'test_xss_payloads.json')
        
        try:
            result = self.runner.invoke(main, [
                '--xss', '--count=5',
                '--encode=url', '--obfuscate',
                '--context=html', '--filter-bypass',
                '--save', temp_file, '--output=json',
                '--verbose'
            ])
            
            assert result.exit_code == 0
            assert os.path.exists(temp_file)
            
            with open(temp_file, 'r') as f:
                data = json.load(f)
            
            assert isinstance(data, dict)
            assert 'payloads' in data
            assert 'count' in data
            assert len(data['payloads']) <= 5
            
            for payload_data in data['payloads']:
                assert 'type' in payload_data
                assert 'payload' in payload_data
                assert payload_data['type'] == 'XSS'
        
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
    
    def test_generate_multiple_payload_types_with_options(self):
        """Test generating multiple payload types with various options"""
        result = self.runner.invoke(main, [
            '--xss', '--sqli', '--cmdi',
            '--count=3', '--encode=base64',
            '--waf-evasion', '--filter-bypass',
            '--platform=both', '--database=mysql',
            '--context=script', '--blind',
            '--verbose'
        ])
        
        assert result.exit_code == 0
        assert 'Generated' in result.output
    
    @patch('src.integrations.burp_api.BurpSuiteAPI.test_connection')
    @patch('src.integrations.burp_api.BurpSuiteAPI.send_to_repeater')
    def test_burp_integration_workflow(self, mock_send, mock_test):
        """Test complete Burp Suite integration workflow"""
        mock_test.return_value = True
        mock_send.return_value = True
        
        result = self.runner.invoke(main, [
            '--xss', '--count=2',
            '--target=http://example.com',
            '--burp', '--verbose'
        ])
        
        # Should not fail even if Burp is not actually running
        assert result.exit_code == 0
    
    def test_configuration_loading(self):
        """Test custom configuration loading"""
        config_data = {
            'payloads': {
                'max_count': 50,
                'default_encoding': 'url',
                'enable_obfuscation': True
            },
            'burp': {
                'base_url': 'http://localhost:8080',
                'api_key': 'custom_key'
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            config_file = f.name
        
        try:
            result = self.runner.invoke(main, [
                '--xss', '--count=5',
                '--config', config_file,
                '--verbose'
            ])
            
            assert result.exit_code == 0
        
        finally:
            if os.path.exists(config_file):
                os.unlink(config_file)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
