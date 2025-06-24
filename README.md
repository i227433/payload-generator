# Custom Payload Generator for Web Exploitation

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/workflow/status/username/payload-generator/CI)](https://github.com/username/payload-generator/actions)
[![Security Rating](https://img.shields.io/badge/security-A-green)](https://github.com/username/payload-generator)

A comprehensive, modular payload generation tool that produces evasion-ready payloads for common web vulnerabilities, including bypass techniques for input validation, WAFs, and blacklist filters, with full Burp Suite Professional integration.

## 🚀 Features

### Core Payload Generators
- **XSS Payload Generator**: Reflected, Stored, DOM-based XSS with advanced bypass techniques
- **SQL Injection Generator**: Error-based, Union-based, Boolean-blind, Time-based injections
- **Command Injection Generator**: Linux and Windows command injection with multiple techniques

### Advanced Capabilities
- **WAF Evasion**: Multiple bypass techniques for popular WAF solutions
- **Encoding & Obfuscation**: Base64, URL, Hex, Unicode encoding with obfuscation
- **Burp Suite Integration**: Full REST API integration with automated testing
- **Multiple Output Formats**: CLI, JSON, CSV, XML, and plain text export
- **Clipboard Integration**: Direct copy-paste functionality

## 📋 Requirements

- Windows 10+ (Development Environment)
- Python 3.8+
- Burp Suite Professional with REST API enabled
- Virtual Environment (recommended)

## 🛠️ Installation

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/username/payload-generator.git
cd payload-generator

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
set BURP_API_KEY=z8iaQVY3uhjGDLI1XfcdPFAgr7IujEH5
set BURP_API_URL=http://127.0.0.1:1337
```

### Burp Suite Configuration
1. Enable REST API in Burp Suite Professional
2. Set API endpoint to `http://127.0.0.1:1337`
3. Use API key: `z8iaQVY3uhjGDLI1XfcdPFAgr7IujEH5`
4. Ensure localhost network access

## 🎯 Quick Start

### Command Line Usage
```bash
# Generate XSS payloads
python src/main.py --xss --count=10 --encode=url

# Generate SQL injection payloads with WAF evasion
python src/main.py --sqli --waf-evasion --database=mysql --output=json

# Generate command injection payloads for Windows
python src/main.py --cmdi --platform=windows --obfuscate

# Send payloads directly to Burp Suite
python src/main.py --xss --target=http://example.com --burp

# Export to file with multiple formats
python src/main.py --sqli --save=payloads.json --output=json
```

### Python API Usage
```python
from src.core.payload_generator import PayloadGenerator
from src.integrations.burp_api import BurpSuiteAPI

# Initialize generators
generator = PayloadGenerator()
burp_api = BurpSuiteAPI()

# Generate XSS payloads
xss_payloads = generator.generate_xss_payloads(
    count=5,
    context='html',
    encoding='url'
)

# Send to Burp Suite
for payload in xss_payloads:
    burp_api.send_to_repeater('http://target.com', payload)
```

## 📖 Command Reference

### Core Flags
```
--xss                    Generate XSS payloads
--sqli                   Generate SQL injection payloads
--cmdi                   Generate command injection payloads
--encode=TYPE            Encoding type (base64, url, hex, unicode)
--obfuscate             Apply obfuscation techniques
--output=FORMAT         Output format (cli, json, csv, xml, txt)
--target=URL            Target URL for Burp integration
--count=N               Number of payloads to generate
--save=FILE             Save payloads to file
--burp                  Send directly to Burp Suite
```

### Advanced Options
```
--filter-bypass         Include filter bypass techniques
--waf-evasion          Apply WAF evasion methods
--platform=OS          Target platform (linux, windows, both)
--database=TYPE        Database type for SQLi (mysql, postgres, mssql, oracle)
--context=TYPE         XSS context (html, attribute, script, css)
--blind                Generate blind injection payloads
--verbose              Verbose output with explanations
```

## 🏗️ Project Structure

```
payload-generator/
├── src/
│   ├── main.py                 # Main CLI entry point
│   ├── core/                   # Core payload generation engine
│   ├── modules/                # Individual payload generators
│   ├── integrations/           # Burp Suite and other integrations
│   ├── gui/                    # Optional GUI interface
│   └── utils/                  # Utility functions
├── tests/                      # Comprehensive test suite
├── docs/                       # Documentation
├── examples/                   # Usage examples
├── data/                       # Payload databases
└── scripts/                    # Setup and utility scripts
```

## 🔧 Configuration

### Environment Variables
```bash
# Burp Suite Configuration
set BURP_API_KEY=z8iaQVY3uhjGDLI1XfcdPFAgr7IujEH5
set BURP_API_URL=http://127.0.0.1:1337
set BURP_TIMEOUT=30

# Application Configuration
set DEBUG_MODE=false
set LOG_LEVEL=INFO
set OUTPUT_DIR=./output
```

### Configuration File (config.json)
```json
{
    "burp": {
        "base_url": "http://127.0.0.1:1337",
        "api_key": "z8iaQVY3uhjGDLI1XfcdPFAgr7IujEH5",
        "timeout": 30,
        "retry_attempts": 3
    },
    "payloads": {
        "max_count": 1000,
        "default_encoding": "none",
        "enable_obfuscation": false
    }
}
```

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test modules
python -m pytest tests/test_generators.py
python -m pytest tests/test_burp_integration.py

# Run with coverage
python -m pytest tests/ --cov=src --cov-report=html
```

## 🛡️ Security Considerations

- All user inputs are validated and sanitized
- API keys are handled securely with environment variables
- File operations use safe practices with proper permissions
- Network requests include proper timeout and retry logic
- Input validation prevents injection attacks in the tool itself

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🐛 Troubleshooting

### Common Issues

**Burp Suite Connection Failed**
```bash
# Check if Burp Suite is running
netstat -an | findstr 1337

# Verify API key configuration
echo %BURP_API_KEY%
```

**Import Errors**
```bash
# Ensure virtual environment is activated
venv\Scripts\activate

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

**Permission Issues**
```bash
# Run as administrator if needed
# Ensure proper file permissions in output directory
```

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/username/payload-generator/issues)
- **Discussions**: [GitHub Discussions](https://github.com/username/payload-generator/discussions)
- **Security**: Report security issues to security@example.com

## 🏆 Acknowledgments

- Burp Suite Professional for API integration
- OWASP for web security guidance
- Security research community for payload techniques

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Users are responsible for complying with applicable laws and regulations.
