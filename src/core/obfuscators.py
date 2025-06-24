"""
Payload obfuscation module
Handles advanced obfuscation techniques for payload evasion
"""

import random
import re
from typing import List, Dict, Any


class PayloadObfuscator:
    """Handles advanced obfuscation of payloads for evasion"""
    
    def __init__(self):
        """Initialize the obfuscator with available methods"""
        self.xss_obfuscation_methods = [
            self._xss_case_variation,
            self._xss_comment_insertion,
            self._xss_whitespace_variation,
            self._xss_tag_variation,
            self._xss_attribute_quotes,
            self._xss_event_handler_variation
        ]
        
        self.sqli_obfuscation_methods = [
            self._sqli_case_variation,
            self._sqli_comment_insertion,
            self._sqli_whitespace_variation,
            self._sqli_function_variation,
            self._sqli_concatenation,
            self._sqli_parentheses_variation
        ]
        
        self.cmdi_obfuscation_methods = [
            self._cmdi_separator_variation,
            self._cmdi_quote_variation,
            self._cmdi_variable_insertion,
            self._cmdi_command_substitution,
            self._cmdi_encoding_tricks
        ]
    
    def obfuscate_xss(self, payload: str) -> str:
        """
        Apply XSS-specific obfuscation techniques
        
        Args:
            payload: XSS payload to obfuscate
            
        Returns:
            Obfuscated XSS payload
        """
        # Apply 2-3 random obfuscation methods
        methods = random.sample(self.xss_obfuscation_methods, 
                               min(3, len(self.xss_obfuscation_methods)))
        
        result = payload
        for method in methods:
            result = method(result)
        
        return result
    
    def obfuscate_sqli(self, payload: str) -> str:
        """
        Apply SQL injection-specific obfuscation techniques
        
        Args:
            payload: SQL injection payload to obfuscate
            
        Returns:
            Obfuscated SQL injection payload
        """
        # Apply 2-3 random obfuscation methods
        methods = random.sample(self.sqli_obfuscation_methods, 
                               min(3, len(self.sqli_obfuscation_methods)))
        
        result = payload
        for method in methods:
            result = method(result)
        
        return result
    
    def obfuscate_cmdi(self, payload: str) -> str:
        """
        Apply command injection-specific obfuscation techniques
        
        Args:
            payload: Command injection payload to obfuscate
            
        Returns:
            Obfuscated command injection payload
        """
        # Apply 2-3 random obfuscation methods
        methods = random.sample(self.cmdi_obfuscation_methods, 
                               min(3, len(self.cmdi_obfuscation_methods)))
        
        result = payload
        for method in methods:
            result = method(result)
        
        return result
    
    # XSS Obfuscation Methods
    def _xss_case_variation(self, payload: str) -> str:
        """Apply random case variation to XSS payload"""
        # Randomly change case of HTML tags and JavaScript keywords
        keywords = ['script', 'img', 'svg', 'iframe', 'object', 'embed', 
                   'javascript', 'alert', 'prompt', 'confirm', 'eval']
        
        result = payload
        for keyword in keywords:
            if keyword in result.lower():
                # Create random case variation
                varied_keyword = ''.join([
                    char.upper() if random.choice([True, False]) else char.lower()
                    for char in keyword
                ])
                result = re.sub(re.escape(keyword), varied_keyword, result, flags=re.IGNORECASE)
        
        return result
    
    def _xss_comment_insertion(self, payload: str) -> str:
        """Insert HTML comments for obfuscation"""
        comments = ['<!--x-->', '<!--y-->', '<!--z-->', '<!---->']
        
        # Insert comments in strategic places
        if '<' in payload:
            result = payload.replace('<', f'<{random.choice(comments)}')
        else:
            result = payload
        
        return result
    
    def _xss_whitespace_variation(self, payload: str) -> str:
        """Add various whitespace characters"""
        whitespace_chars = [' ', '\t', '\n', '\r', '\f', '\v']
        
        # Add random whitespace around operators and brackets
        operators = ['=', '(', ')', '{', '}', ';', ':']
        result = payload
        
        for op in operators:
            if op in result:
                ws = random.choice(whitespace_chars)
                result = result.replace(op, f'{ws}{op}{ws}')
        
        return result
    
    def _xss_tag_variation(self, payload: str) -> str:
        """Use alternative HTML tags"""
        tag_alternatives = {
            'script': ['SCRIPT', 'Script', 'sCrIpT'],
            'img': ['IMG', 'Img', 'ImG'],
            'svg': ['SVG', 'Svg', 'sVg'],
            'iframe': ['IFRAME', 'IFrame', 'iFrAmE']
        }
        
        result = payload
        for original, alternatives in tag_alternatives.items():
            if original in result.lower():
                result = re.sub(re.escape(original), random.choice(alternatives), 
                               result, flags=re.IGNORECASE)
        
        return result
    
    def _xss_attribute_quotes(self, payload: str) -> str:
        """Vary quote usage in HTML attributes"""
        # Replace double quotes with single quotes or vice versa
        if '"' in payload:
            result = payload.replace('"', "'")
        elif "'" in payload:
            result = payload.replace("'", '"')
        else:
            result = payload
        
        return result
    
    def _xss_event_handler_variation(self, payload: str) -> str:
        """Use alternative event handlers"""
        event_alternatives = {
            'onload': ['ONLOAD', 'OnLoad', 'onLoad'],
            'onerror': ['ONERROR', 'OnError', 'onError'],
            'onclick': ['ONCLICK', 'OnClick', 'onClick'],
            'onmouseover': ['ONMOUSEOVER', 'OnMouseOver', 'onMouseOver']
        }
        
        result = payload
        for original, alternatives in event_alternatives.items():
            if original in result.lower():
                result = re.sub(re.escape(original), random.choice(alternatives), 
                               result, flags=re.IGNORECASE)
        
        return result
    
    # SQL Injection Obfuscation Methods
    def _sqli_case_variation(self, payload: str) -> str:
        """Apply random case variation to SQL keywords"""
        keywords = ['select', 'union', 'where', 'from', 'and', 'or', 'order', 
                   'by', 'group', 'having', 'insert', 'update', 'delete']
        
        result = payload
        for keyword in keywords:
            if keyword in result.lower():
                varied_keyword = ''.join([
                    char.upper() if random.choice([True, False]) else char.lower()
                    for char in keyword
                ])
                result = re.sub(re.escape(keyword), varied_keyword, result, flags=re.IGNORECASE)
        
        return result
    
    def _sqli_comment_insertion(self, payload: str) -> str:
        """Insert SQL comments for obfuscation"""
        comments = ['/**/', '/*x*/', '-- ', '#']
        
        # Insert comments around keywords
        keywords = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR']
        result = payload.upper()
        
        for keyword in keywords:
            if keyword in result:
                comment = random.choice(comments)
                result = result.replace(keyword, f'{comment}{keyword}{comment}')
        
        return result
    
    def _sqli_whitespace_variation(self, payload: str) -> str:
        """Add various whitespace and tab characters"""
        whitespace_chars = [' ', '\t', '\n', '\r', '  ', '\t\t']
        
        # Replace single spaces with random whitespace
        result = re.sub(r' ', lambda m: random.choice(whitespace_chars), payload)
        
        return result
    
    def _sqli_function_variation(self, payload: str) -> str:
        """Use SQL function variations"""
        function_alternatives = {
            'concat': ['CONCAT', 'Concat', 'GROUP_CONCAT'],
            'substring': ['SUBSTRING', 'SUBSTR', 'MID'],
            'length': ['LENGTH', 'LEN', 'CHAR_LENGTH']
        }
        
        result = payload
        for original, alternatives in function_alternatives.items():
            if original in result.lower():
                result = re.sub(re.escape(original), random.choice(alternatives), 
                               result, flags=re.IGNORECASE)
        
        return result
    
    def _sqli_concatenation(self, payload: str) -> str:
        """Use string concatenation for obfuscation"""
        # Split string literals and concatenate them
        if "'" in payload:
            # Simple concatenation example
            result = payload.replace("'admin'", "'ad'+'min'")
            result = result.replace("'user'", "'us'+'er'")
        else:
            result = payload
        
        return result
    
    def _sqli_parentheses_variation(self, payload: str) -> str:
        """Add unnecessary parentheses"""
        # Add parentheses around expressions
        operators = ['AND', 'OR', '=', '<', '>']
        result = payload
        
        for op in operators:
            if op in result:
                result = re.sub(rf'(\w+)\s*{re.escape(op)}\s*(\w+)', 
                               rf'(\1) {op} (\2)', result)
        
        return result
    
    # Command Injection Obfuscation Methods
    def _cmdi_separator_variation(self, payload: str) -> str:
        """Use alternative command separators"""
        separators = {
            ';': ['&', '&&', '||'],
            '&': [';', '&&'],
            '&&': [';', '&', '    &&    '],
            '||': ['    ||    ', '; echo "x" ||']
        }
        
        result = payload
        for original, alternatives in separators.items():
            if original in result:
                result = result.replace(original, random.choice(alternatives))
        
        return result
    
    def _cmdi_quote_variation(self, payload: str) -> str:
        """Add quotes around commands"""
        commands = ['id', 'whoami', 'pwd', 'ls', 'dir', 'cat', 'type']
        
        result = payload
        for cmd in commands:
            if cmd in result:
                quote_style = random.choice(['"', "'"])
                result = result.replace(cmd, f'{quote_style}{cmd}{quote_style}')
        
        return result
    
    def _cmdi_variable_insertion(self, payload: str) -> str:
        """Insert environment variables"""
        # Linux variables
        if any(cmd in payload for cmd in ['ls', 'cat', 'id', 'whoami']):
            variables = ['${PATH:0:0}', '${IFS}', '$@', '${#}']
            var = random.choice(variables)
            # Insert variable in command
            result = re.sub(r'(\w+)', rf'\1{var}', payload, count=1)
        else:
            result = payload
        
        return result
    
    def _cmdi_command_substitution(self, payload: str) -> str:
        """Use command substitution techniques"""
        if 'id' in payload:
            alternatives = ['`id`', '$(id)', '${id}']
            result = payload.replace('id', random.choice(alternatives))
        elif 'whoami' in payload:
            alternatives = ['`whoami`', '$(whoami)', '${whoami}']
            result = payload.replace('whoami', random.choice(alternatives))
        else:
            result = payload
        
        return result
    
    def _cmdi_encoding_tricks(self, payload: str) -> str:
        """Apply encoding tricks to commands"""
        # Base64 encoding of commands
        if 'echo' in payload:
            # Simple obfuscation
            result = payload.replace('echo', 'ec"h"o')
        elif 'cat' in payload:
            result = payload.replace('cat', 'c"a"t')
        else:
            result = payload
        
        return result
    
    def get_available_methods(self) -> Dict[str, List[str]]:
        """Get available obfuscation methods by payload type"""
        return {
            'xss': [method.__name__ for method in self.xss_obfuscation_methods],
            'sqli': [method.__name__ for method in self.sqli_obfuscation_methods],
            'cmdi': [method.__name__ for method in self.cmdi_obfuscation_methods]
        }
    
    def apply_custom_obfuscation(self, payload: str, payload_type: str, 
                                methods: List[str]) -> str:
        """
        Apply specific obfuscation methods
        
        Args:
            payload: Payload to obfuscate
            payload_type: Type of payload (xss, sqli, cmdi)
            methods: List of method names to apply
            
        Returns:
            Obfuscated payload
        """
        result = payload
        
        if payload_type == 'xss':
            method_map = {method.__name__: method for method in self.xss_obfuscation_methods}
        elif payload_type == 'sqli':
            method_map = {method.__name__: method for method in self.sqli_obfuscation_methods}
        elif payload_type == 'cmdi':
            method_map = {method.__name__: method for method in self.cmdi_obfuscation_methods}
        else:
            return result
        
        for method_name in methods:
            if method_name in method_map:
                result = method_map[method_name](result)
        
        return result
