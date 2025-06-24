# Installation Guide

## Prerequisites

- Python 3.8 or higher
- Windows 10 or later
- Git (for development)
- Optional: Burp Suite Professional (for API integration)

## Installation Methods

### Method 1: Using pip (Recommended)

```bash
pip install payload-forge
```

### Method 2: From Source

1. Clone the repository:
```bash
git clone https://github.com/yourusername/payload-forge.git
cd payload-forge
```

2. Create a virtual environment:
```bash
python -m venv venv
venv\Scripts\activate  # On Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install in development mode:
```bash
pip install -e .
```

### Method 3: Using setup script

```bash
python setup.py install
```

## Configuration

1. Copy the default configuration:
```bash
cp config.json.example config.json
```

2. Edit `config.json` to match your environment:
```json
{
  "burp_api": {
    "host": "127.0.0.1",
    "port": 1337,
    "api_key": "your-api-key-here"
  },
  "output": {
    "default_format": "json",
    "clipboard_enabled": true
  }
}
```

## Verification

Test the installation:

```bash
payload-forge --help
```

Run basic tests:

```bash
python -m pytest tests/
```

## Troubleshooting

### Common Issues

1. **Import Errors**
   - Ensure Python path includes the src directory
   - Check virtual environment activation

2. **Permission Errors**
   - Run as administrator on Windows
   - Check file permissions

3. **API Connection Issues**
   - Verify Burp Suite is running
   - Check API key configuration
   - Ensure port is not blocked by firewall

### Getting Help

- Check the [Usage Guide](usage.md)
- View [Examples](../examples/)
- Open an issue on GitHub
