#!/usr/bin/env python3
"""
Custom Payload Generator for Web Exploitation
Main CLI entry point with comprehensive command-line interface
"""

import sys
import os
import json
import time
import click
from typing import List, Dict, Optional
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.payload_generator import PayloadGenerator
from integrations.burp_api import BurpSuiteAPI
from utils.validators import validate_url, validate_count
from utils.file_operations import save_payloads, load_config

# Initialize colorama for Windows
from colorama import init, Fore, Style
init(autoreset=True)

# Global configuration
CONFIG_FILE = Path(__file__).parent.parent / "config.json"
DEFAULT_CONFIG = {
    "burp": {
        "base_url": "http://127.0.0.1:1337",
        "api_key": "z8iaQVY3uhjGDLI1XfcdPFAgr7IujEH5",
        "timeout": 30,
        "retry_attempts": 3
    },
    "payloads": {
        "max_count": 1000,
        "default_encoding": "none",
        "enable_obfuscation": False
    }
}

def print_banner():
    """Print the application banner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                 CUSTOM PAYLOAD GENERATOR                      ║
║              Web Exploitation Testing Tool                   ║
║                   v1.0.0 - 2025                             ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}⚠️  For Authorized Security Testing Only ⚠️{Style.RESET_ALL}
"""
    click.echo(banner)

def load_application_config() -> Dict:
    """Load application configuration"""
    try:
        if CONFIG_FILE.exists():
            return load_config(str(CONFIG_FILE))
        else:
            # Create default config
            with open(CONFIG_FILE, 'w') as f:
                json.dump(DEFAULT_CONFIG, f, indent=4)
            return DEFAULT_CONFIG
    except Exception as e:
        click.echo(f"{Fore.RED}Error loading config: {e}{Style.RESET_ALL}")
        return DEFAULT_CONFIG

@click.command()
@click.option('--xss', is_flag=True, help='Generate XSS payloads')
@click.option('--sqli', is_flag=True, help='Generate SQL injection payloads')
@click.option('--cmdi', is_flag=True, help='Generate command injection payloads')
@click.option('--encode', type=click.Choice(['none', 'base64', 'url', 'hex', 'unicode', 'html']), 
              default='none', help='Encoding type')
@click.option('--obfuscate', is_flag=True, help='Apply obfuscation techniques')
@click.option('--output', type=click.Choice(['cli', 'json', 'csv', 'xml', 'txt']), 
              default='cli', help='Output format')
@click.option('--target', help='Target URL for Burp integration')
@click.option('--count', default=5, help='Number of payloads to generate')
@click.option('--save', help='Save payloads to file')
@click.option('--burp', is_flag=True, help='Send directly to Burp Suite')
@click.option('--filter-bypass', is_flag=True, help='Include filter bypass techniques')
@click.option('--waf-evasion', is_flag=True, help='Apply WAF evasion methods')
@click.option('--platform', type=click.Choice(['linux', 'windows', 'both']), 
              default='both', help='Target platform for command injection')
@click.option('--database', type=click.Choice(['mysql', 'postgres', 'mssql', 'oracle', 'sqlite']), 
              default='mysql', help='Database type for SQL injection')
@click.option('--context', type=click.Choice(['html', 'attribute', 'script', 'css', 'url']), 
              default='html', help='XSS context')
@click.option('--blind', is_flag=True, help='Generate blind injection payloads')
@click.option('--verbose', is_flag=True, help='Verbose output with explanations')
@click.option('--config', help='Custom configuration file path')
@click.version_option(version='1.0.0')
def main(xss: bool, sqli: bool, cmdi: bool, encode: str, obfuscate: bool,
         output: str, target: Optional[str], count: int, save: Optional[str],
         burp: bool, filter_bypass: bool, waf_evasion: bool, platform: str,
         database: str, context: str, blind: bool, verbose: bool,
         config: Optional[str]) -> None:
    """
    Custom Payload Generator for Web Exploitation
    
    A comprehensive tool for generating evasion-ready payloads for common web vulnerabilities
    with full Burp Suite Professional integration.
    
    Examples:
        payload-gen --xss --count=10 --encode=url
        payload-gen --sqli --waf-evasion --database=mysql --burp
        payload-gen --cmdi --platform=windows --obfuscate --save=payloads.json
    """
    
    # Print banner
    if not any([xss, sqli, cmdi]):
        print_banner()
    
    # Load configuration
    if config:
        app_config = load_config(config)
    else:
        app_config = load_application_config()
    
    # Validate inputs
    if count > app_config['payloads']['max_count']:
        click.echo(f"{Fore.RED}Error: Count exceeds maximum allowed ({app_config['payloads']['max_count']}){Style.RESET_ALL}")
        sys.exit(1)
    
    if target and not validate_url(target):
        click.echo(f"{Fore.RED}Error: Invalid target URL{Style.RESET_ALL}")
        sys.exit(1)
    
    if not validate_count(count):
        click.echo(f"{Fore.RED}Error: Invalid count value{Style.RESET_ALL}")
        sys.exit(1)
      # Check if at least one payload type is selected
    if not any([xss, sqli, cmdi]):
        click.echo(f"{Fore.YELLOW}No payload type selected. Use --help for available options.{Style.RESET_ALL}")
        return
    
    # Initialize payload generator
    try:
        generator = PayloadGenerator(config=app_config)
        
        if verbose:
            click.echo(f"{Fore.GREEN}✓ Payload generator initialized{Style.RESET_ALL}")
        
        # Initialize Burp Suite integration if needed
        burp_api = None
        if burp or target:
            try:
                burp_api = BurpSuiteAPI(config=app_config['burp'])
                if burp_api.test_connection():
                    if verbose:
                        click.echo(f"{Fore.GREEN}✓ Burp Suite API connection established{Style.RESET_ALL}")
                else:
                    click.echo(f"{Fore.RED}⚠️  Warning: Could not connect to Burp Suite API{Style.RESET_ALL}")
                    if burp:
                        click.echo("Continuing without Burp integration...")
                        burp = False
            except Exception as e:
                click.echo(f"{Fore.RED}Error initializing Burp Suite API: {e}{Style.RESET_ALL}")
                if burp:
                    click.echo("Continuing without Burp integration...")
                    burp = False
        
        all_payloads = []
        
        # Generate XSS payloads
        if xss:
            if verbose:
                click.echo(f"{Fore.BLUE}Generating XSS payloads...{Style.RESET_ALL}")
            
            xss_payloads = generator.generate_xss_payloads(
                count=count,
                context=context,
                encoding=encode,
                obfuscate=obfuscate,
                filter_bypass=filter_bypass,
                waf_evasion=waf_evasion
            )
            
            all_payloads.extend([{'type': 'XSS', 'payload': p, 'context': context} for p in xss_payloads])
            
            if output == 'cli':
                click.echo(f"\n{Fore.CYAN}=== XSS PAYLOADS ({len(xss_payloads)}) ==={Style.RESET_ALL}")
                for i, payload in enumerate(xss_payloads, 1):
                    click.echo(f"{Fore.GREEN}{i:2d}.{Style.RESET_ALL} {payload}")
        
        # Generate SQL injection payloads
        if sqli:
            if verbose:
                click.echo(f"{Fore.BLUE}Generating SQL injection payloads...{Style.RESET_ALL}")
            
            sqli_payloads = generator.generate_sqli_payloads(
                count=count,
                database=database,
                encoding=encode,
                obfuscate=obfuscate,
                filter_bypass=filter_bypass,
                waf_evasion=waf_evasion,
                blind=blind
            )
            
            all_payloads.extend([{'type': 'SQLi', 'payload': p, 'database': database} for p in sqli_payloads])
            
            if output == 'cli':
                click.echo(f"\n{Fore.CYAN}=== SQL INJECTION PAYLOADS ({len(sqli_payloads)}) ==={Style.RESET_ALL}")
                for i, payload in enumerate(sqli_payloads, 1):
                    click.echo(f"{Fore.GREEN}{i:2d}.{Style.RESET_ALL} {payload}")
        
        # Generate command injection payloads
        if cmdi:
            if verbose:
                click.echo(f"{Fore.BLUE}Generating command injection payloads...{Style.RESET_ALL}")
            
            cmdi_payloads = generator.generate_cmdi_payloads(
                count=count,
                platform=platform,
                encoding=encode,
                obfuscate=obfuscate,
                filter_bypass=filter_bypass,
                waf_evasion=waf_evasion
            )
            
            all_payloads.extend([{'type': 'CMDi', 'payload': p, 'platform': platform} for p in cmdi_payloads])
            
            if output == 'cli':
                click.echo(f"\n{Fore.CYAN}=== COMMAND INJECTION PAYLOADS ({len(cmdi_payloads)}) ==={Style.RESET_ALL}")
                for i, payload in enumerate(cmdi_payloads, 1):
                    click.echo(f"{Fore.GREEN}{i:2d}.{Style.RESET_ALL} {payload}")
        
        # Send to Burp Suite if requested
        if burp and burp_api and target:
            if verbose:
                click.echo(f"{Fore.BLUE}Sending payloads to Burp Suite...{Style.RESET_ALL}")
            
            success_count = 0
            for payload_data in all_payloads:
                try:
                    if burp_api.send_to_repeater(target, payload_data['payload']):
                        success_count += 1
                except Exception as e:
                    if verbose:
                        click.echo(f"{Fore.RED}Failed to send payload: {e}{Style.RESET_ALL}")
            
            click.echo(f"{Fore.GREEN}✓ Sent {success_count}/{len(all_payloads)} payloads to Burp Suite{Style.RESET_ALL}")
          # Handle different output formats
        if output != 'cli' and not save:
            # Output to stdout in the specified format
            if output == 'json':
                import json
                output_data = {
                    'payloads': all_payloads,
                    'count': len(all_payloads),
                    'generated_at': time.strftime('%Y-%m-%d %H:%M:%S')
                }
                click.echo(json.dumps(output_data, indent=2))
            elif output == 'csv':
                if all_payloads:
                    # Get all unique field names
                    fieldnames = set()
                    for payload in all_payloads:
                        fieldnames.update(payload.keys())
                    fieldnames = sorted(list(fieldnames))
                    
                    import csv
                    import sys
                    import io
                    output = io.StringIO()
                    writer = csv.DictWriter(output, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(all_payloads)
                    click.echo(output.getvalue())
            elif output == 'xml':
                import xml.etree.ElementTree as ET
                root = ET.Element('payloads')
                root.set('count', str(len(all_payloads)))
                root.set('generated_at', time.strftime('%Y-%m-%d %H:%M:%S'))
                
                for payload_data in all_payloads:
                    payload_elem = ET.SubElement(root, 'payload')
                    for key, value in payload_data.items():
                        elem = ET.SubElement(payload_elem, key)
                        elem.text = str(value)
                
                click.echo(ET.tostring(root, encoding='unicode'))
            elif output == 'txt':
                click.echo(f"# Payloads generated at {time.strftime('%Y-%m-%d %H:%M:%S')}")
                click.echo(f"# Total count: {len(all_payloads)}")
                click.echo()
                
                for i, payload_data in enumerate(all_payloads, 1):
                    click.echo(f"# Payload {i}")
                    for key, value in payload_data.items():
                        click.echo(f"# {key}: {value}")
                    click.echo(payload_data.get('payload', ''))
                    click.echo()        # Save to file if requested
        if save:
            try:
                # Auto-detect format from file extension if not explicitly set
                save_format = output
                if output == 'cli':  # Default CLI output, detect from file extension
                    if save.lower().endswith('.json'):
                        save_format = 'json'
                    elif save.lower().endswith('.csv'):
                        save_format = 'csv'
                    elif save.lower().endswith('.xml'):
                        save_format = 'xml'
                    elif save.lower().endswith('.txt'):
                        save_format = 'txt'
                    else:
                        save_format = 'json'  # Default to JSON
                
                if save_payloads(all_payloads, save, save_format):
                    click.echo(f"{Fore.GREEN}✓ Payloads saved to {save}{Style.RESET_ALL}")
                else:
                    click.echo(f"{Fore.RED}Failed to save payloads to {save}{Style.RESET_ALL}")
            except Exception as e:
                click.echo(f"{Fore.RED}Error saving payloads: {e}{Style.RESET_ALL}")
        
        # Summary
        if verbose and (output == 'cli' or save):
            total_payloads = len(all_payloads)
            click.echo(f"\n{Fore.GREEN}✓ Generated {total_payloads} total payloads{Style.RESET_ALL}")
            if encode != 'none':
                click.echo(f"{Fore.BLUE}  Encoding: {encode}{Style.RESET_ALL}")
            if obfuscate:
                click.echo(f"{Fore.BLUE}  Obfuscation: Applied{Style.RESET_ALL}")
            if filter_bypass:
                click.echo(f"{Fore.BLUE}  Filter bypass: Enabled{Style.RESET_ALL}")
            if waf_evasion:
                click.echo(f"{Fore.BLUE}  WAF evasion: Enabled{Style.RESET_ALL}")
    
    except KeyboardInterrupt:
        click.echo(f"\n{Fore.YELLOW}Operation cancelled by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        click.echo(f"{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
