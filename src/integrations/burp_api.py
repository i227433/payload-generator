"""
Burp Suite Professional API integration module
Handles communication with Burp Suite REST API for                 return {'error': f'HTTP {response.status_code}', 'message': response.text}
        
        except Exception as e:
            return {'error': 'Connection failed', 'message': str(e)}
    
    def send_to_repeater(self, target_url: str, payload: str, 
                        method: str = 'GET', headers: Optional[Dict[str, str]] = None,
                        position: str = 'url') -> bool: testing and automation
"""

import json
import time
import requests
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse
import urllib3

# Disable SSL warnings for local Burp Suite API
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class BurpSuiteAPI:
    """Interface for Burp Suite Professional REST API"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Burp Suite API client
        
        Args:
            config: Configuration dictionary with API settings        """
        self.config = config or {
            'base_url': 'http://127.0.0.1:1337',
            'api_key': 'XVdsO6XnDDFBP9cFbAJPCUigEVZxT8mY',
            'timeout': 30,
            'retry_attempts': 3
        }
        
        self.base_url = self.config['base_url']
        self.api_key = self.config['api_key']
        self.timeout = self.config.get('timeout', 30)
        self.retry_attempts = self.config.get('retry_attempts', 3)
        
        # Construct API endpoint URL
        self.api_url = f"{self.base_url}/{self.api_key}"
        
        # Session for connection reuse
        self.session = requests.Session()
        self.session.verify = False  # For self-signed certificates        
        # Headers for API requests
        self.headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'PayloadGenerator/1.0'
        }
    
    def test_connection(self) -> bool:
        """
        Test connection to Burp Suite API
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            # Test the base API endpoint (works with Scanner API)
            response = self.session.get(
                self.api_url,
                headers=self.headers,
                timeout=self.timeout
            )
            if response.status_code == 200:
                return True
              # Fallback: test issue_definitions endpoint (Scanner API)
            response = self.session.get(
                f"{self.api_url}/issue_definitions",
                headers=self.headers,
                timeout=self.timeout
            )
            return response.status_code == 200            
        except Exception as e:
            print(f"Connection test failed: {e}")
            return False
    
    def get_burp_info(self) -> Dict[str, Any]:
        """
        Get Burp Suite version and configuration information
        
        Returns:
            Dictionary with Burp Suite information
        """
        try:
            # Try to get issue definitions (available in Scanner API)
            response = self.session.get(
                f"{self.api_url}/issue_definitions",
                headers=self.headers,
                timeout=self.timeout
            )
            if response.status_code == 200:
                issue_definitions = response.json()
                # Extract version from headers if available
                version = response.headers.get('X-Burp-Version', 'Unknown')
                return {
                    'version': version,
                    'api_type': 'Scanner API',
                    'available_endpoints': ['/issue_definitions', '/scan'],
                    'issue_definitions_count': len(issue_definitions) if isinstance(issue_definitions, list) else 0
                }
            else:
                return {'error': f'HTTP {response.status_code}', 'message': response.text}
        
        except Exception as e:
            return {'error': 'Connection failed', 'message': str(e)}
    
    def send_to_repeater(self, target_url: str, payload: str, 
                        method: str = 'GET', headers: Optional[Dict[str, str]] = None,
                        position: str = 'url') -> bool:
        """
        Send a payload to Burp Suite with multiple integration strategies
        
        Args:
            target_url: Target URL for the request
            payload: Payload to inject
            method: HTTP method (GET, POST, etc.)
            headers: Additional HTTP headers
            position: Where to inject payload (url, body, header)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Strategy 1: Try direct Repeater API
            if self._try_direct_repeater_api(target_url, payload, method, headers, position):
                return True
            
            # Strategy 2: Try creating request files for manual import
            if self._try_file_based_integration(target_url, payload, method, headers, position):
                return True
                
            # Strategy 3: Fallback to Scanner API
            return self._scan_with_payload(target_url, payload, method, headers, position)
            
        except Exception as e:
            print(f"Failed to send to Burp Suite: {e}")
            return False
    
    def _scan_with_payload(self, target_url: str, payload: str, 
                          method: str = 'GET', headers: Optional[Dict[str, str]] = None,
                          position: str = 'url') -> bool:
        """
        Internal method to perform a scan with a specific payload
        """
        try:
            # Prepare the target URL with payload
            if position == 'url':
                if '?' in target_url:
                    scan_url = f"{target_url}&test={payload}"
                else:
                    scan_url = f"{target_url}?test={payload}"
            else:
                scan_url = target_url
            
            # Prepare scan configuration
            scan_config = {
                "scan_configurations": [
                    {
                        "name": "Crawl and Audit - Fast",
                        "type": "CrawlAndAudit"
                    }
                ],
                "urls": [scan_url]
            }
            
            # Add custom headers if provided
            if headers:
                scan_config["application_logins"] = []
            
            # Send scan request
            response = self.session.post(
                f"{self.api_url}/scan",
                headers=self.headers,
                json=scan_config,
                timeout=self.timeout
            )
            
            return response.status_code == 201
            
        except Exception as e:
            print(f"Failed to scan with payload: {e}")
            return False
            response = self.session.post(
                f"{self.api_url}/burp/repeater",
                headers=self.headers,
                json=request_data,
                timeout=self.timeout
            )
            
            return response.status_code in [200, 201]
        
        except Exception as e:
            print(f"Failed to send to Repeater: {e}")
            return False
    
    def send_to_intruder(self, target_url: str, payloads: List[str],
                        attack_type: str = 'sniper', 
                        positions: Optional[List[str]] = None) -> bool:
        """
        Send payloads to Burp Suite Intruder
        
        Args:
            target_url: Target URL for the attack
            payloads: List of payloads to use
            attack_type: Intruder attack type (sniper, battering_ram, pitchfork, cluster_bomb)
            positions: Injection positions
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Prepare Intruder configuration
            intruder_config = {
                'url': target_url,
                'attack_type': attack_type,
                'payloads': payloads,
                'positions': positions or ['§payload§']
            }
            
            response = self.session.post(
                f"{self.api_url}/burp/intruder",
                headers=self.headers,
                json=intruder_config,
                timeout=self.timeout
            )
            
            return response.status_code in [200, 201]
        
        except Exception as e:
            print(f"Failed to send to Intruder: {e}")
            return False
    
    def start_active_scan(self, target_url: str, 
                         scan_config: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        Start an active scan on the target URL
        
        Args:
            target_url: URL to scan
            scan_config: Custom scan configuration
            
        Returns:
            Scan ID if successful, None otherwise
        """
        try:
            # Default scan configuration
            default_config = {
                'urls': [target_url],
                'scan_type': 'active',
                'scope': {
                    'include': [{'rule': target_url}]
                }
            }
            
            # Merge with custom configuration
            if scan_config:
                default_config.update(scan_config)
            
            response = self.session.post(
                f"{self.api_url}/burp/scanner/scans/active",
                headers=self.headers,
                json=default_config,
                timeout=self.timeout
            )
            
            if response.status_code in [200, 201]:
                result = response.json()
                return result.get('scan_id')
            
            return None
        
        except Exception as e:
            print(f"Failed to start active scan: {e}")
            return None
    
    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """
        Get status of an active scan
        
        Args:
            scan_id: ID of the scan to check
            
        Returns:
            Dictionary with scan status information
        """
        try:
            response = self.session.get(
                f"{self.api_url}/burp/scanner/scans/{scan_id}",
                headers=self.headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'HTTP {response.status_code}', 'message': response.text}
        
        except Exception as e:
            return {'error': 'Request failed', 'message': str(e)}
    
    def get_scan_results(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Get results from a completed scan
        
        Args:
            scan_id: ID of the scan
            
        Returns:
            List of vulnerability findings
        """
        try:
            response = self.session.get(
                f"{self.api_url}/burp/scanner/scans/{scan_id}/issues",
                headers=self.headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json().get('issues', [])
            else:
                return []
        
        except Exception as e:
            print(f"Failed to get scan results: {e}")
            return []
    
    def send_custom_request(self, target_url: str, payload: str,
                           method: str = 'GET', headers: Optional[Dict[str, str]] = None,
                           body: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Send a custom HTTP request with payload
        
        Args:
            target_url: Target URL
            payload: Payload to inject
            method: HTTP method
            headers: Custom headers
            body: Request body
            
        Returns:
            Response data or None if failed
        """
        try:
            # Inject payload into URL if no body specified
            if body is None:
                if '?' in target_url:
                    request_url = f"{target_url}&payload={payload}"
                else:
                    request_url = f"{target_url}?payload={payload}"
                request_body = ""
            else:
                request_url = target_url
                request_body = body.replace('{{payload}}', payload)
            
            # Custom request configuration
            request_config = {
                'url': request_url,
                'method': method.upper(),
                'headers': headers or {},
                'body': request_body
            }
            
            response = self.session.post(
                f"{self.api_url}/burp/http/request",
                headers=self.headers,
                json=request_config,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return None
        
        except Exception as e:
            print(f"Failed to send custom request: {e}")
            return None
    
    def get_proxy_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent proxy history entries
        
        Args:
            limit: Maximum number of entries to retrieve
            
        Returns:
            List of proxy history entries
        """
        try:
            params = {'limit': limit}
            response = self.session.get(
                f"{self.api_url}/burp/proxy/history",
                headers=self.headers,
                params=params,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json().get('entries', [])
            else:
                return []
        
        except Exception as e:
            print(f"Failed to get proxy history: {e}")
            return []
    
    def add_to_site_map(self, target_url: str) -> bool:
        """
        Add URL to Burp's site map
        
        Args:
            target_url: URL to add to site map
            
        Returns:
            True if successful, False otherwise
        """
        try:
            site_map_data = {
                'url': target_url,
                'method': 'GET'
            }
            
            response = self.session.post(
                f"{self.api_url}/burp/target/sitemap",
                headers=self.headers,
                json=site_map_data,
                timeout=self.timeout
            )
            
            return response.status_code in [200, 201]
        
        except Exception as e:
            print(f"Failed to add to site map: {e}")
            return False
    
    def set_scope(self, include_rules: List[str], 
                  exclude_rules: Optional[List[str]] = None) -> bool:
        """
        Set Burp Suite target scope
        
        Args:
            include_rules: List of URLs/patterns to include in scope
            exclude_rules: List of URLs/patterns to exclude from scope
            
        Returns:
            True if successful, False otherwise
        """
        try:
            scope_config = {
                'include': [{'rule': rule} for rule in include_rules],
                'exclude': [{'rule': rule} for rule in (exclude_rules or [])]
            }
            
            response = self.session.put(
                f"{self.api_url}/burp/target/scope",
                headers=self.headers,
                json=scope_config,
                timeout=self.timeout
            )
            
            return response.status_code in [200, 201]
        
        except Exception as e:
            print(f"Failed to set scope: {e}")
            return False
    
    def export_scan_report(self, scan_id: str, 
                          report_type: str = 'HTML') -> Optional[bytes]:
        """
        Export scan report in specified format
        
        Args:
            scan_id: ID of the scan
            report_type: Report format (HTML, XML, JSON)
            
        Returns:
            Report data as bytes or None if failed
        """
        try:
            params = {'format': report_type.lower()}
            response = self.session.get(
                f"{self.api_url}/burp/scanner/scans/{scan_id}/report",
                headers=self.headers,
                params=params,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.content
            else:
                return None
        
        except Exception as e:
            print(f"Failed to export scan report: {e}")
            return None
    
    def batch_test_payloads(self, target_url: str, payloads: List[str],
                           method: str = 'GET', delay: float = 0.5) -> List[Dict[str, Any]]:
        """
        Test multiple payloads against a target with response analysis
        
        Args:
            target_url: Target URL for testing
            payloads: List of payloads to test
            method: HTTP method to use
            delay: Delay between requests (seconds)
            
        Returns:
            List of test results
        """
        results = []
        
        for i, payload in enumerate(payloads, 1):
            try:
                print(f"Testing payload {i}/{len(payloads)}: {payload[:50]}...")
                
                # Send request with payload
                response_data = self.send_custom_request(
                    target_url, payload, method
                )
                
                if response_data:
                    # Analyze response for potential vulnerabilities
                    analysis = self._analyze_response(response_data, payload)
                    
                    results.append({
                        'payload': payload,
                        'response': response_data,
                        'analysis': analysis,
                        'timestamp': time.time()
                    })
                else:
                    results.append({
                        'payload': payload,
                        'error': 'Failed to get response',
                        'timestamp': time.time()
                    })
                
                # Delay between requests
                if delay > 0:
                    time.sleep(delay)
            
            except KeyboardInterrupt:
                print("Batch testing interrupted by user")
                break
            except Exception as e:
                results.append({
                    'payload': payload,
                    'error': str(e),
                    'timestamp': time.time()
                })
        
        return results
    
    def _analyze_response(self, response_data: Dict[str, Any], 
                         payload: str) -> Dict[str, Any]:
        """
        Analyze HTTP response for potential vulnerabilities
        
        Args:
            response_data: Response data from Burp API
            payload: The payload that was sent
            
        Returns:
            Analysis results dictionary
        """
        analysis = {
            'potential_vuln': False,
            'indicators': [],
            'confidence': 'low',
            'response_time': response_data.get('response_time', 0)
        }
        
        # Get response details
        status_code = response_data.get('status_code', 0)
        response_body = response_data.get('response_body', '')
        response_headers = response_data.get('response_headers', {})
        
        # XSS detection
        if any(tag in payload.lower() for tag in ['<script', '<img', '<svg', 'javascript:']):
            if payload in response_body:
                analysis['potential_vuln'] = True
                analysis['indicators'].append('XSS: Payload reflected in response')
                analysis['confidence'] = 'high'
        
        # SQL injection detection
        if any(keyword in payload.lower() for keyword in ['union', 'select', 'or 1=1']):
            error_indicators = [
                'sql syntax', 'mysql', 'postgresql', 'ora-', 'microsoft',
                'odbc', 'sqlite', 'syntax error'
            ]
            
            if any(error in response_body.lower() for error in error_indicators):
                analysis['potential_vuln'] = True
                analysis['indicators'].append('SQLi: Database error detected')
                analysis['confidence'] = 'medium'
        
        # Command injection detection
        if any(sep in payload for sep in [';', '&&', '||', '|', '`']):
            # Look for command output patterns
            command_outputs = [
                'uid=', 'gid=', 'groups=',  # Linux id command
                'windows nt', 'microsoft windows',  # Windows whoami
                'directory of', 'volume serial number'  # Windows dir
            ]
            
            if any(output in response_body.lower() for output in command_outputs):
                analysis['potential_vuln'] = True
                analysis['indicators'].append('CMDi: Command output detected')
                analysis['confidence'] = 'high'
        
        # Time-based detection
        if analysis['response_time'] > 5000:  # 5+ seconds
            if any(keyword in payload.lower() for keyword in ['sleep', 'waitfor', 'benchmark']):
                analysis['potential_vuln'] = True
                analysis['indicators'].append('Time-based: Unusual response delay')
                analysis['confidence'] = 'medium'
        
        # Error-based detection
        if status_code >= 500:
            analysis['indicators'].append(f'Server error: HTTP {status_code}')
        
        return analysis
    
    def close(self):
        """Close the API session"""
        if hasattr(self, 'session'):
            self.session.close()

    def get_site_map(self) -> List[Dict[str, Any]]:
        """
        Get Burp's site map
        
        Returns:
            List of site map entries
        """
        try:
            response = self.session.get(
                f"{self.api_url}/burp/target/sitemap",
                headers=self.headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return []
        
        except Exception as e:
            print(f"Failed to get site map: {e}")
            return []
    
    def _try_direct_repeater_api(self, target_url: str, payload: str, 
                                method: str, headers: Optional[Dict], position: str) -> bool:
        """Try direct Repeater API endpoints"""
        
        repeater_endpoints = [
            f"{self.api_url}/repeater",
            f"{self.api_url}/tools/repeater", 
            f"{self.api_url}/burp/repeater",
            f"{self.api_url}/api/repeater"
        ]
        
        # Prepare request data
        request_data = self._prepare_request_data(target_url, payload, method, headers, position)
        
        for endpoint in repeater_endpoints:
            try:
                response = self.session.post(endpoint, json=request_data, headers=self.headers, timeout=10)
                if response.status_code in [200, 201, 202]:
                    print(f"✓ Successfully sent to Repeater via {endpoint}")
                    return True
            except Exception as e:
                continue
        
        return False
    
    def _try_file_based_integration(self, target_url: str, payload: str,
                                  method: str, headers: Optional[Dict], position: str) -> bool:
        """Create request files for manual import into Burp Suite"""
        
        try:
            # Create HTTP request content
            request_content = self._create_http_request(target_url, payload, method, headers, position)
            
            # Save to file with timestamp
            import time
            timestamp = int(time.time())
            filename = f"burp_request_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write(request_content)
            
            print(f"✓ Request saved to {filename} - Import this file into Burp Suite Repeater")
            return True
            
        except Exception as e:
            print(f"File-based integration failed: {e}")
            return False
    
    def _prepare_request_data(self, target_url: str, payload: str, 
                            method: str, headers: Optional[Dict], position: str) -> Dict:
        """Prepare request data for API calls"""
        
        from urllib.parse import quote
        
        # Inject payload based on position
        if position == 'url':
            if '?' in target_url:
                url = f"{target_url}&test={quote(payload)}"
            else:
                url = f"{target_url}?test={quote(payload)}"
            body = ""
        elif position == 'body':
            url = target_url
            body = payload
        else:
            url = target_url
            body = ""
        
        request_headers = {
            'User-Agent': 'PayloadGenerator/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        
        if headers:
            request_headers.update(headers)
        
        if position == 'header':
            request_headers['X-Test-Payload'] = payload
        
        return {
            'url': url,
            'method': method.upper(),
            'headers': request_headers,
            'body': body,
            'follow_redirects': True
        }
    
    def _create_http_request(self, target_url: str, payload: str,
                           method: str, headers: Optional[Dict], position: str) -> str:
        """Create raw HTTP request for file export"""
        
        from urllib.parse import urlparse, quote
        parsed = urlparse(target_url)
        
        # Inject payload
        if position == 'url':
            if parsed.query:
                query = f"{parsed.query}&test={quote(payload)}"
            else:
                query = f"test={quote(payload)}"
            path = f"{parsed.path}?{query}" if query else parsed.path
        else:
            path = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path
        
        # Build HTTP request
        request_lines = [
            f"{method.upper()} {path} HTTP/1.1",
            f"Host: {parsed.netloc}",
            "User-Agent: PayloadGenerator/1.0",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection: keep-alive"
        ]
        
        if headers:
            for key, value in headers.items():
                request_lines.append(f"{key}: {value}")
        
        if position == 'header':
            request_lines.append(f"X-Test-Payload: {payload}")
        
        if position == 'body' and method.upper() in ['POST', 'PUT']:
            request_lines.extend([
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(payload)}",
                "",
                payload
            ])
        else:
            request_lines.append("")
        
        return "\r\n".join(request_lines)
