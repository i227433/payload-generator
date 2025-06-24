#!/usr/bin/env python3
"""
Comprehensive demonstration of the Custom Payload Generator
Shows all major features and capabilities of the tool
"""

import os
import sys
import json
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.payload_generator import PayloadGenerator
from integrations.burp_api import BurpSuiteAPI
from utils.validators import validate_url
from utils.file_operations import save_payloads

def print_header(title):
    """Print a formatted header"""
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")

def print_section(title):
    """Print a section header"""
    print(f"\n{'-' * 40}")
    print(f"  {title}")
    print(f"{'-' * 40}")

def demo_basic_functionality():
    """Demonstrate basic payload generation"""
    print_header("BASIC PAYLOAD GENERATION DEMO")
    
    # Initialize generator
    generator = PayloadGenerator()
    print("✓ PayloadGenerator initialized")
    
    # Generate XSS payloads
    print_section("XSS Payloads")
    xss_payloads = generator.generate_xss_payloads(count=3)
    for i, payload in enumerate(xss_payloads, 1):
        print(f"{i:2d}. {payload}")
    
    # Generate SQL injection payloads
    print_section("SQL Injection Payloads")
    sqli_payloads = generator.generate_sqli_payloads(count=3, database='mysql')
    for i, payload in enumerate(sqli_payloads, 1):
        print(f"{i:2d}. {payload}")
    
    # Generate command injection payloads
    print_section("Command Injection Payloads")
    cmdi_payloads = generator.generate_cmdi_payloads(count=3, platform='both')
    for i, payload in enumerate(cmdi_payloads, 1):
        print(f"{i:2d}. {payload}")

def demo_advanced_features():
    """Demonstrate advanced features like encoding and obfuscation"""
    print_header("ADVANCED FEATURES DEMO")
    
    generator = PayloadGenerator()
    
    # Demonstrate encoding
    print_section("URL Encoded XSS Payloads")
    encoded_payloads = generator.generate_xss_payloads(
        count=3, 
        encoding='url',
        context='html'
    )
    for i, payload in enumerate(encoded_payloads, 1):
        print(f"{i:2d}. {payload}")
    
    # Demonstrate obfuscation
    print_section("Obfuscated SQLi Payloads")
    obfuscated_payloads = generator.generate_sqli_payloads(
        count=3,
        obfuscate=True,
        waf_evasion=True,
        database='mysql'
    )
    for i, payload in enumerate(obfuscated_payloads, 1):
        print(f"{i:2d}. {payload}")
    
    # Demonstrate filter bypass
    print_section("Filter Bypass CMDi Payloads")
    bypass_payloads = generator.generate_cmdi_payloads(
        count=3,
        filter_bypass=True,
        platform='windows'
    )
    for i, payload in enumerate(bypass_payloads, 1):
        print(f"{i:2d}. {payload}")

def demo_file_operations():
    """Demonstrate file saving and loading"""
    print_header("FILE OPERATIONS DEMO")
    
    generator = PayloadGenerator()
    
    # Generate mixed payloads
    print_section("Generating Mixed Payload Set")
    all_payloads = []
    
    # XSS payloads
    xss_payloads = generator.generate_xss_payloads(count=2, context='html')
    all_payloads.extend([{'type': 'XSS', 'payload': p, 'context': 'html'} for p in xss_payloads])
    
    # SQLi payloads
    sqli_payloads = generator.generate_sqli_payloads(count=2, database='mysql')
    all_payloads.extend([{'type': 'SQLi', 'payload': p, 'database': 'mysql'} for p in sqli_payloads])
    
    # CMDi payloads
    cmdi_payloads = generator.generate_cmdi_payloads(count=2, platform='both')
    all_payloads.extend([{'type': 'CMDi', 'payload': p, 'platform': 'both'} for p in cmdi_payloads])
    
    print(f"Generated {len(all_payloads)} total payloads")
    
    # Save to different formats
    output_dir = Path("demo_output")
    output_dir.mkdir(exist_ok=True)
    
    # JSON format
    json_file = output_dir / "payloads.json"
    save_payloads(all_payloads, str(json_file), 'json')
    print(f"✓ Saved to JSON: {json_file}")
    
    # Text format
    txt_file = output_dir / "payloads.txt"
    save_payloads(all_payloads, str(txt_file), 'txt')
    print(f"✓ Saved to TXT: {txt_file}")
    
    # CSV format
    csv_file = output_dir / "payloads.csv"
    save_payloads(all_payloads, str(csv_file), 'csv')
    print(f"✓ Saved to CSV: {csv_file}")

def demo_context_awareness():
    """Demonstrate context-aware payload generation"""
    print_header("CONTEXT-AWARE PAYLOAD GENERATION")
    
    generator = PayloadGenerator()
    
    contexts = ['html', 'attribute', 'script', 'css', 'url']
    
    for context in contexts:
        print_section(f"XSS Payloads for {context.upper()} Context")
        payloads = generator.generate_xss_payloads(count=2, context=context)
        for i, payload in enumerate(payloads, 1):
            print(f"{i:2d}. {payload}")

def demo_database_specific():
    """Demonstrate database-specific SQL injection payloads"""
    print_header("DATABASE-SPECIFIC SQL INJECTION")
    
    generator = PayloadGenerator()
    
    databases = ['mysql', 'postgres', 'mssql', 'oracle', 'sqlite']
    
    for db in databases:
        print_section(f"SQL Injection for {db.upper()}")
        payloads = generator.generate_sqli_payloads(count=2, database=db)
        for i, payload in enumerate(payloads, 1):
            print(f"{i:2d}. {payload}")

def demo_burp_integration():
    """Demonstrate Burp Suite integration (mock)"""
    print_header("BURP SUITE INTEGRATION DEMO")
    
    print_section("Testing Burp Suite Connection")
    
    # Initialize Burp API
    burp_config = {
        'base_url': 'http://127.0.0.1:1337',
        'api_key': 'test_key',
        'timeout': 10
    }
    
    try:
        burp_api = BurpSuiteAPI(config=burp_config)
        print("✓ BurpSuiteAPI initialized")
        
        # Test connection (will likely fail unless Burp is running)
        if burp_api.test_connection():
            print("✓ Connected to Burp Suite Professional")
        else:
            print("⚠️  Could not connect to Burp Suite (not running or wrong config)")
        
        print("\nBurp Integration Features:")
        print("  • Send payloads to Repeater")
        print("  • Send payloads to Intruder") 
        print("  • Add URLs to site map")
        print("  • Get proxy history")
        print("  • Automated scanning integration")
        
    except Exception as e:
        print(f"❌ Burp integration error: {e}")

def demo_validation():
    """Demonstrate input validation"""
    print_header("INPUT VALIDATION DEMO")
    
    print_section("URL Validation")
    test_urls = [
        "http://example.com",
        "https://test.example.com:8080/path?param=value",
        "invalid-url",
        "ftp://example.com",
        ""
    ]
    
    for url in test_urls:
        result = "✓ Valid" if validate_url(url) else "❌ Invalid"
        print(f"{result:10} - {url or '(empty)'}")

def demo_performance():
    """Demonstrate performance with larger payload sets"""
    print_header("PERFORMANCE DEMO")
    
    generator = PayloadGenerator()
    
    print_section("Generating Large Payload Sets")
    
    start_time = time.time()
    
    # Generate large sets
    xss_payloads = generator.generate_xss_payloads(count=50)
    sqli_payloads = generator.generate_sqli_payloads(count=50)
    cmdi_payloads = generator.generate_cmdi_payloads(count=50)
    
    end_time = time.time()
    
    total_payloads = len(xss_payloads) + len(sqli_payloads) + len(cmdi_payloads)
    elapsed_time = end_time - start_time
    
    print(f"Generated {total_payloads} payloads in {elapsed_time:.3f} seconds")
    if elapsed_time > 0:
        print(f"Rate: {total_payloads/elapsed_time:.1f} payloads/second")
    else:
        print("Rate: Very fast (sub-millisecond generation)")

def main():
    """Run all demonstrations"""
    print("🎯 CUSTOM PAYLOAD GENERATOR - COMPREHENSIVE DEMO")
    print("=" * 60)
    print("This demonstration showcases all major features of the tool")
    print("For authorized security testing purposes only!")
    
    try:
        # Run all demonstrations
        demo_basic_functionality()
        demo_advanced_features()
        demo_context_awareness()
        demo_database_specific()
        demo_file_operations()
        demo_validation()
        demo_burp_integration()
        demo_performance()
        
        print_header("DEMO COMPLETE")
        print("✅ All demonstrations completed successfully!")
        print("\nNext Steps:")
        print("  1. Try the CLI: python src/main.py --help")
        print("  2. Generate custom payloads for your testing needs")
        print("  3. Integrate with Burp Suite Professional")
        print("  4. Explore the API for programmatic usage")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
