#!/usr/bin/env python3
"""
Installation and setup script for Payload Forge
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def run_command(command, description):
    """Run a system command with error handling"""
    print(f"📦 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        print(f"Error output: {e.stderr}")
        return False

def check_python_version():
    """Check if Python version is compatible"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8 or higher is required")
        print(f"Current version: {version.major}.{version.minor}.{version.micro}")
        return False
    
    print(f"✅ Python version {version.major}.{version.minor}.{version.micro} is compatible")
    return True

def create_virtual_environment():
    """Create a virtual environment"""
    venv_path = "venv"
    if os.path.exists(venv_path):
        print(f"📁 Virtual environment already exists at {venv_path}")
        return True
    
    return run_command(f"python -m venv {venv_path}", "Creating virtual environment")

def activate_virtual_environment():
    """Get activation command for virtual environment"""
    system = platform.system().lower()
    if system == "windows":
        return "venv\\Scripts\\activate"
    else:
        return "source venv/bin/activate"

def install_dependencies():
    """Install required dependencies"""
    commands = [
        ("python -m pip install --upgrade pip", "Upgrading pip"),
        ("pip install -r requirements.txt", "Installing dependencies"),
        ("pip install -e .", "Installing Payload Forge in development mode")
    ]
    
    for command, description in commands:
        if not run_command(command, description):
            return False
    return True

def create_config_file():
    """Create configuration file from template"""
    config_file = "config.json"
    if os.path.exists(config_file):
        print(f"📁 Configuration file already exists at {config_file}")
        return True
    
    config_template = {
        "burp_api": {
            "host": "127.0.0.1",
            "port": 1337,
            "api_key": "",
            "timeout": 30
        },
        "output": {
            "default_format": "text",
            "clipboard_enabled": True,
            "file_encoding": "utf-8"
        },
        "payloads": {
            "custom_payload_dir": "data/custom_payloads/",
            "load_custom_on_startup": True
        },
        "encoding": {
            "default_encoding": "url",
            "multiple_encoding": False
        },
        "logging": {
            "level": "INFO",
            "file": "logs/payload_forge.log",
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        }
    }
    
    import json
    try:
        with open(config_file, 'w') as f:
            json.dump(config_template, f, indent=2)
        print(f"✅ Created configuration file at {config_file}")
        return True
    except Exception as e:
        print(f"❌ Failed to create configuration file: {e}")
        return False

def create_directories():
    """Create necessary directories"""
    directories = [
        "logs",
        "data/custom_payloads",
        "output",
        "temp"
    ]
    
    for directory in directories:
        try:
            Path(directory).mkdir(parents=True, exist_ok=True)
            print(f"📁 Created directory: {directory}")
        except Exception as e:
            print(f"❌ Failed to create directory {directory}: {e}")
            return False
    
    return True

def run_tests():
    """Run test suite to verify installation"""
    return run_command("python -m pytest tests/ -v", "Running test suite")

def display_success_message():
    """Display success message with next steps"""
    system = platform.system().lower()
    activate_cmd = activate_virtual_environment()
    
    print("\n" + "="*60)
    print("🎉 PAYLOAD FORGE INSTALLATION COMPLETE! 🎉")
    print("="*60)
    print("\n📋 Next Steps:")
    print(f"1. Activate virtual environment: {activate_cmd}")
    print("2. Edit config.json to configure Burp Suite API settings")
    print("3. Test the installation: payload-forge --help")
    print("4. Generate your first payload: payload-forge xss --help")
    print("\n📚 Documentation:")
    print("- Installation: docs/installation.md")
    print("- Usage Guide: docs/usage.md")
    print("- API Reference: docs/api-reference.md")
    print("- Examples: examples/")
    print("\n🔧 Configuration:")
    print("- Edit config.json for custom settings")
    print("- Set BURP_API_KEY environment variable for API access")
    print("\n⚠️  Important:")
    print("- Only use on systems you own or have permission to test")
    print("- Follow responsible disclosure practices")
    print("="*60)

def main():
    """Main installation function"""
    print("🚀 Starting Payload Forge Installation")
    print("="*40)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Create virtual environment
    if not create_virtual_environment():
        print("❌ Installation failed at virtual environment creation")
        sys.exit(1)
    
    print(f"\n💡 To continue installation, activate the virtual environment:")
    print(f"   {activate_virtual_environment()}")
    print("   Then run this script again.\n")
    
    # Check if we're in a virtual environment
    if not hasattr(sys, 'real_prefix') and not (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("⚠️  Please activate the virtual environment and run this script again.")
        return
    
    # Install dependencies
    if not install_dependencies():
        print("❌ Installation failed at dependency installation")
        sys.exit(1)
    
    # Create configuration file
    if not create_config_file():
        print("❌ Installation failed at configuration creation")
        sys.exit(1)
    
    # Create directories
    if not create_directories():
        print("❌ Installation failed at directory creation")
        sys.exit(1)
    
    # Run tests
    print("\n🧪 Running tests to verify installation...")
    if run_tests():
        print("✅ All tests passed!")
    else:
        print("⚠️  Some tests failed, but installation may still be functional")
    
    # Display success message
    display_success_message()

if __name__ == "__main__":
    main()
