# Usage Guide

## Command Line Interface

### Basic Usage

Generate a simple XSS payload:
```bash
payload-forge xss --target "input field" --output console
```

Generate SQL injection payload with encoding:
```bash
payload-forge sqli --encoding url --obfuscation basic --output file:payloads.txt
```

Generate command injection payload:
```bash
payload-forge cmdi --payload-type "reverse_shell" --encoding base64
```

### Advanced Options

#### Payload Types

**XSS Payloads:**
- `reflected` - Basic reflected XSS
- `stored` - Persistent XSS
- `dom` - DOM-based XSS
- `blind` - Blind XSS with callback

**SQL Injection:**
- `union` - UNION-based injection
- `boolean` - Boolean-based blind
- `time` - Time-based blind
- `error` - Error-based injection

**Command Injection:**
- `basic` - Simple command execution
- `reverse_shell` - Reverse shell payloads
- `blind` - Blind command injection

#### Encoding Options

- `url` - URL encoding
- `html` - HTML entity encoding
- `base64` - Base64 encoding
- `unicode` - Unicode encoding
- `hex` - Hexadecimal encoding

#### Obfuscation Techniques

- `basic` - Simple string manipulation
- `advanced` - Complex obfuscation
- `javascript` - JS-specific obfuscation
- `sql` - SQL-specific techniques

### Output Formats

#### Console Output
```bash
payload-forge xss --output console
```

#### File Output
```bash
payload-forge xss --output file:my_payloads.txt
```

#### JSON Format
```bash
payload-forge xss --format json --output file:payloads.json
```

#### Clipboard
```bash
payload-forge xss --output clipboard
```

### Burp Suite Integration

#### Send to Repeater
```bash
payload-forge xss --burp-send-repeater --target-url "http://example.com/vulnerable"
```

#### Configure Intruder
```bash
payload-forge sqli --burp-intruder --intruder-positions "username=§PAYLOAD§"
```

#### Active Scan
```bash
payload-forge cmdi --burp-scan --scan-url "http://example.com/cmd"
```

### Batch Processing

Generate multiple payload types:
```bash
payload-forge batch --config batch_config.json
```

Example batch configuration:
```json
{
  "payloads": [
    {
      "type": "xss",
      "encoding": ["url", "html"],
      "output": "xss_payloads.txt"
    },
    {
      "type": "sqli",
      "payload_type": "union",
      "encoding": "url",
      "output": "sqli_payloads.txt"
    }
  ]
}
```

## Python API

### Basic Usage

```python
from payload_forge import PayloadGenerator

# Initialize generator
generator = PayloadGenerator()

# Generate XSS payload
xss_payload = generator.generate_xss(
    payload_type='reflected',
    encoding='url',
    obfuscation='basic'
)

print(xss_payload)
```

### Advanced Usage

```python
from payload_forge import PayloadGenerator
from payload_forge.integrations import BurpAPI

# Initialize with custom config
generator = PayloadGenerator(config_path='custom_config.json')

# Generate multiple payloads
payloads = generator.generate_batch([
    {'type': 'xss', 'encoding': 'url'},
    {'type': 'sqli', 'payload_type': 'union'},
    {'type': 'cmdi', 'payload_type': 'reverse_shell'}
])

# Burp Suite integration
burp = BurpAPI()
burp.connect()

for payload in payloads:
    burp.send_to_repeater(
        url='http://target.com/vulnerable',
        payload=payload
    )
```

### Custom Payloads

```python
# Add custom payload
generator.add_custom_payload(
    payload_type='xss',
    payload='<script>custom_payload()</script>',
    description='Custom XSS payload'
)

# Load payloads from file
generator.load_payloads_from_file('custom_payloads.json')
```

## Configuration

### Global Configuration

Edit `config.json`:

```json
{
  "burp_api": {
    "host": "127.0.0.1",
    "port": 1337,
    "api_key": "your-api-key",
    "timeout": 30
  },
  "output": {
    "default_format": "text",
    "clipboard_enabled": true,
    "file_encoding": "utf-8"
  },
  "payloads": {
    "custom_payload_dir": "data/custom_payloads/",
    "load_custom_on_startup": true
  },
  "encoding": {
    "default_encoding": "url",
    "multiple_encoding": false
  }
}
```

### Environment Variables

Set environment variables for sensitive data:

```bash
set BURP_API_KEY=your-api-key
set PAYLOAD_FORGE_CONFIG=path/to/config.json
```

## Best Practices

### Security Considerations

1. **Authorized Testing Only** - Only use on systems you own or have explicit permission to test
2. **Payload Validation** - Always validate payloads before execution
3. **Log Management** - Monitor and rotate logs regularly
4. **API Key Security** - Never commit API keys to version control

### Performance Tips

1. **Batch Processing** - Use batch mode for multiple payloads
2. **Caching** - Enable payload caching for repeated operations
3. **Output Formats** - Choose appropriate output format for your workflow

### Debugging

Enable debug mode:
```bash
payload-forge --debug xss --payload-type reflected
```

View logs:
```bash
tail -f logs/payload_forge.log
```

## Examples

See the [examples](../examples/) directory for more detailed usage examples and integration patterns.
