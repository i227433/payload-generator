#!/usr/bin/env python3
"""
Burp Suite integration example
Demonstrates how to integrate with Burp Suite Professional API
"""

import sys
import os
import time

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.payload_generator import PayloadGenerator
from integrations.burp_api import BurpSuiteAPI


def main():
    """Demonstrate Burp Suite integration functionality"""
    
    print("=== Custom Payload Generator - Burp Suite Integration Example ===\n")
    
    # Initialize components
    generator = PayloadGenerator()
    
    # Configuration for Burp Suite
    burp_config = {
        'base_url': 'http://127.0.0.1:1337',
        'api_key': 'z8iaQVY3uhjGDLI1XfcdPFAgr7IujEH5',
        'timeout': 30,
        'retry_attempts': 3
    }
    
    burp_api = BurpSuiteAPI(config=burp_config)
    
    print("1. Testing Burp Suite Connection")
    print("-" * 40)
    
    if burp_api.test_connection():
        print("✓ Successfully connected to Burp Suite API")
        
        # Get Burp Suite information
        burp_info = burp_api.get_burp_info()
        if 'error' not in burp_info:
            print(f"Burp Suite Version: {burp_info.get('burp_version', 'Unknown')}")
        else:
            print(f"Error getting Burp info: {burp_info['message']}")
    else:
        print("✗ Failed to connect to Burp Suite API")
        print("Make sure Burp Suite Professional is running with REST API enabled")
        print("API Endpoint: http://127.0.0.1:1337")
        print("API Key: z8iaQVY3uhjGDLI1XfcdPFAgr7IujEH5")
        return
    
    print("\n2. Generating Test Payloads")
    print("-" * 40)
    
    # Generate different types of payloads
    xss_payloads = generator.generate_xss_payloads(count=3, context='html')
    sqli_payloads = generator.generate_sqli_payloads(count=3, database='mysql')
    cmdi_payloads = generator.generate_cmdi_payloads(count=3, platform='both')
    
    all_payloads = []
    all_payloads.extend([{'type': 'XSS', 'payload': p} for p in xss_payloads])
    all_payloads.extend([{'type': 'SQLi', 'payload': p} for p in sqli_payloads])
    all_payloads.extend([{'type': 'CMDi', 'payload': p} for p in cmdi_payloads])
    
    print(f"Generated {len(all_payloads)} payloads for testing")
    
    # Example target URL (replace with actual target)
    target_url = "http://testphp.vulnweb.com/artists.php"
    
    print(f"\n3. Sending Payloads to Burp Suite Repeater")
    print("-" * 40)
    print(f"Target URL: {target_url}")
    
    # Send a few payloads to Repeater
    success_count = 0
    for i, payload_data in enumerate(all_payloads[:5], 1):  # Test first 5 payloads
        print(f"Sending payload {i}: {payload_data['type']} - {payload_data['payload'][:50]}...")
        
        if burp_api.send_to_repeater(target_url, payload_data['payload']):
            success_count += 1
            print("  ✓ Sent successfully")
        else:
            print("  ✗ Failed to send")
        
        time.sleep(0.5)  # Small delay between requests
    
    print(f"\nSent {success_count}/5 payloads to Burp Suite Repeater")
    
    print(f"\n4. Setting Target Scope")
    print("-" * 40)
    
    # Set scope to include our target
    scope_rules = [target_url]
    if burp_api.set_scope(scope_rules):
        print("✓ Target scope set successfully")
    else:
        print("✗ Failed to set target scope")
    
    print(f"\n5. Adding to Site Map")
    print("-" * 40)
    
    if burp_api.add_to_site_map(target_url):
        print("✓ URL added to site map")
    else:
        print("✗ Failed to add URL to site map")
    
    print(f"\n6. Custom Request Testing")
    print("-" * 40)
    
    # Send a custom request with payload
    test_payload = "<script>alert('XSS_TEST')</script>"
    print(f"Testing payload: {test_payload}")
    
    response = burp_api.send_custom_request(
        target_url, 
        test_payload, 
        method='GET'
    )
    
    if response:
        print("✓ Custom request sent successfully")
        print(f"Response status: {response.get('status_code', 'Unknown')}")
    else:
        print("✗ Custom request failed")
    
    print(f"\n7. Batch Payload Testing")
    print("-" * 40)
    
    # Test multiple payloads with response analysis
    test_payloads = [
        "<script>alert('test1')</script>",
        "' OR 1=1--",
        "; whoami"
    ]
    
    print(f"Testing {len(test_payloads)} payloads with response analysis...")
    
    results = burp_api.batch_test_payloads(
        target_url, 
        test_payloads, 
        method='GET', 
        delay=1.0
    )
    
    print(f"Batch testing complete. Results:")
    for i, result in enumerate(results, 1):
        print(f"  {i}. Payload: {result.get('payload', 'Unknown')[:30]}...")
        if 'error' in result:
            print(f"     Error: {result['error']}")
        else:
            analysis = result.get('analysis', {})
            print(f"     Potential vulnerability: {analysis.get('potential_vuln', False)}")
            if analysis.get('indicators'):
                print(f"     Indicators: {', '.join(analysis['indicators'])}")
    
    print(f"\n8. Starting Active Scan (Optional)")
    print("-" * 40)
    
    # Uncomment to start an active scan
    # scan_id = burp_api.start_active_scan(target_url)
    # if scan_id:
    #     print(f"✓ Active scan started with ID: {scan_id}")
    #     print("Check Burp Suite Scanner tab for progress")
    # else:
    #     print("✗ Failed to start active scan")
    
    print("Active scan skipped (uncomment code to enable)")
    
    print(f"\n9. Proxy History")
    print("-" * 40)
    
    # Get recent proxy history
    history = burp_api.get_proxy_history(limit=5)
    if history:
        print(f"Retrieved {len(history)} recent proxy entries")
        for i, entry in enumerate(history, 1):
            print(f"  {i}. {entry.get('method', 'GET')} {entry.get('url', 'Unknown')}")
    else:
        print("No proxy history retrieved")
    
    print(f"\n10. Cleanup")
    print("-" * 40)
    
    # Close the API session
    burp_api.close()
    print("✓ Burp Suite API session closed")
    
    print("\n=== Burp Suite Integration Example Complete ===")
    print("\nNext steps:")
    print("1. Check Burp Suite Repeater for sent requests")
    print("2. Review Site Map for discovered content")
    print("3. Analyze Scanner results if active scan was started")
    print("4. Customize payload generation based on findings")


if __name__ == '__main__':
    main()
