# API Reference

## Core Classes

### PayloadGenerator

Main class for generating web exploitation payloads.

```python
class PayloadGenerator:
    def __init__(self, config_path: str = None)
```

#### Methods

##### generate_xss()
```python
def generate_xss(
    self,
    payload_type: str = 'reflected',
    target: str = None,
    encoding: str = None,
    obfuscation: str = None,
    custom_payload: str = None
) -> str
```

Generate XSS payload with specified parameters.

**Parameters:**
- `payload_type` (str): Type of XSS payload ('reflected', 'stored', 'dom', 'blind')
- `target` (str): Target context (optional)
- `encoding` (str): Encoding method to apply
- `obfuscation` (str): Obfuscation technique
- `custom_payload` (str): Custom payload template

**Returns:**
- `str`: Generated XSS payload

**Example:**
```python
payload = generator.generate_xss(
    payload_type='reflected',
    encoding='url',
    obfuscation='basic'
)
```

##### generate_sqli()
```python
def generate_sqli(
    self,
    payload_type: str = 'union',
    database: str = 'mysql',
    encoding: str = None,
    obfuscation: str = None,
    custom_payload: str = None
) -> str
```

Generate SQL injection payload.

**Parameters:**
- `payload_type` (str): Type of SQL injection ('union', 'boolean', 'time', 'error')
- `database` (str): Target database type ('mysql', 'postgresql', 'mssql', 'oracle')
- `encoding` (str): Encoding method
- `obfuscation` (str): Obfuscation technique
- `custom_payload` (str): Custom payload template

**Returns:**
- `str`: Generated SQL injection payload

##### generate_cmdi()
```python
def generate_cmdi(
    self,
    payload_type: str = 'basic',
    platform: str = 'linux',
    encoding: str = None,
    obfuscation: str = None,
    custom_payload: str = None
) -> str
```

Generate command injection payload.

**Parameters:**
- `payload_type` (str): Type of command injection ('basic', 'reverse_shell', 'blind')
- `platform` (str): Target platform ('linux', 'windows', 'generic')
- `encoding` (str): Encoding method
- `obfuscation` (str): Obfuscation technique
- `custom_payload` (str): Custom payload template

**Returns:**
- `str`: Generated command injection payload

##### generate_batch()
```python
def generate_batch(self, payload_configs: List[Dict]) -> List[str]
```

Generate multiple payloads in batch.

**Parameters:**
- `payload_configs` (List[Dict]): List of payload configurations

**Returns:**
- `List[str]`: List of generated payloads

## Encoding Classes

### Encoders

Handles various encoding methods for payload obfuscation.

```python
class Encoders:
    @staticmethod
    def url_encode(payload: str) -> str
    
    @staticmethod
    def html_encode(payload: str) -> str
    
    @staticmethod
    def base64_encode(payload: str) -> str
    
    @staticmethod
    def unicode_encode(payload: str) -> str
    
    @staticmethod
    def hex_encode(payload: str) -> str
    
    @staticmethod
    def double_url_encode(payload: str) -> str
```

### Obfuscators

Provides obfuscation techniques for payload evasion.

```python
class Obfuscators:
    @staticmethod
    def basic_obfuscation(payload: str) -> str
    
    @staticmethod
    def advanced_obfuscation(payload: str) -> str
    
    @staticmethod
    def javascript_obfuscation(payload: str) -> str
    
    @staticmethod
    def sql_obfuscation(payload: str) -> str
    
    @staticmethod
    def case_variation(payload: str) -> str
    
    @staticmethod
    def comment_insertion(payload: str, comment_type: str = 'sql') -> str
```

## Integration Classes

### BurpAPI

Integration with Burp Suite Professional REST API.

```python
class BurpAPI:
    def __init__(self, host: str = '127.0.0.1', port: int = 1337, api_key: str = None)
```

#### Methods

##### connect()
```python
def connect(self) -> bool
```

Establish connection to Burp Suite API.

**Returns:**
- `bool`: True if connection successful

##### send_to_repeater()
```python
def send_to_repeater(
    self,
    url: str,
    method: str = 'GET',
    headers: Dict = None,
    body: str = None,
    payload: str = None
) -> Dict
```

Send request to Burp Repeater.

**Parameters:**
- `url` (str): Target URL
- `method` (str): HTTP method
- `headers` (Dict): HTTP headers
- `body` (str): Request body
- `payload` (str): Payload to inject

**Returns:**
- `Dict`: Response from Burp API

##### configure_intruder()
```python
def configure_intruder(
    self,
    url: str,
    payloads: List[str],
    positions: List[str],
    attack_type: str = 'sniper'
) -> Dict
```

Configure Burp Intruder attack.

##### start_active_scan()
```python
def start_active_scan(
    self,
    url: str,
    payload: str = None
) -> Dict
```

Start active scan with optional payload injection.

##### get_scan_results()
```python
def get_scan_results(self, scan_id: str) -> Dict
```

Retrieve scan results by scan ID.

## Utility Classes

### Validators

Input validation utilities.

```python
class Validators:
    @staticmethod
    def validate_url(url: str) -> bool
    
    @staticmethod
    def validate_payload_type(payload_type: str, valid_types: List[str]) -> bool
    
    @staticmethod
    def validate_encoding(encoding: str) -> bool
    
    @staticmethod
    def sanitize_input(input_string: str) -> str
```

### FileOperations

File handling utilities.

```python
class FileOperations:
    @staticmethod
    def read_json_file(file_path: str) -> Dict
    
    @staticmethod
    def write_json_file(data: Dict, file_path: str) -> None
    
    @staticmethod
    def read_text_file(file_path: str) -> str
    
    @staticmethod
    def write_text_file(content: str, file_path: str) -> None
    
    @staticmethod
    def append_to_file(content: str, file_path: str) -> None
```

## Specialized Generators

### XSSGenerator

Specialized XSS payload generation.

```python
class XSSGenerator:
    def generate_reflected_xss(self, context: str = None) -> str
    def generate_stored_xss(self, context: str = None) -> str
    def generate_dom_xss(self, context: str = None) -> str
    def generate_blind_xss(self, callback_url: str = None) -> str
```

### SQLiGenerator

Specialized SQL injection payload generation.

```python
class SQLiGenerator:
    def generate_union_sqli(self, columns: int = None, database: str = 'mysql') -> str
    def generate_boolean_sqli(self, database: str = 'mysql') -> str
    def generate_time_sqli(self, delay: int = 5, database: str = 'mysql') -> str
    def generate_error_sqli(self, database: str = 'mysql') -> str
```

### CMDiGenerator

Specialized command injection payload generation.

```python
class CMDiGenerator:
    def generate_basic_cmdi(self, command: str = 'id', platform: str = 'linux') -> str
    def generate_reverse_shell(self, ip: str, port: int, platform: str = 'linux') -> str
    def generate_blind_cmdi(self, callback_url: str = None, platform: str = 'linux') -> str
```

## Configuration Schema

### Main Configuration

```json
{
  "burp_api": {
    "host": "string",
    "port": "integer",
    "api_key": "string",
    "timeout": "integer"
  },
  "output": {
    "default_format": "string",
    "clipboard_enabled": "boolean",
    "file_encoding": "string"
  },
  "payloads": {
    "custom_payload_dir": "string",
    "load_custom_on_startup": "boolean"
  },
  "encoding": {
    "default_encoding": "string",
    "multiple_encoding": "boolean"
  },
  "logging": {
    "level": "string",
    "file": "string",
    "format": "string"
  }
}
```

## Error Handling

### Custom Exceptions

```python
class PayloadForgeError(Exception):
    """Base exception for payload forge errors"""
    pass

class ValidationError(PayloadForgeError):
    """Raised when input validation fails"""
    pass

class BurpAPIError(PayloadForgeError):
    """Raised when Burp API operations fail"""
    pass

class EncodingError(PayloadForgeError):
    """Raised when encoding operations fail"""
    pass
```

## Constants

### Payload Types

```python
XSS_TYPES = ['reflected', 'stored', 'dom', 'blind']
SQLI_TYPES = ['union', 'boolean', 'time', 'error']
CMDI_TYPES = ['basic', 'reverse_shell', 'blind']
```

### Encoding Methods

```python
ENCODING_METHODS = ['url', 'html', 'base64', 'unicode', 'hex', 'double_url']
```

### Obfuscation Techniques

```python
OBFUSCATION_METHODS = ['basic', 'advanced', 'javascript', 'sql', 'case_variation', 'comment_insertion']
```

### Database Types

```python
DATABASE_TYPES = ['mysql', 'postgresql', 'mssql', 'oracle', 'sqlite']
```

### Platforms

```python
PLATFORMS = ['linux', 'windows', 'generic']
```
