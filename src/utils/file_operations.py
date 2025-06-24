"""
File operations utilities
Handles file I/O operations for payload data
"""

import json
import csv
import xml.etree.ElementTree as ET
import os
from pathlib import Path
from typing import List, Dict, Any, Union
import pyperclip


def save_payloads(payloads: List[Dict[str, Any]], file_path: str, 
                 output_format: str = 'json') -> bool:
    """
    Save payloads to file in specified format
    
    Args:
        payloads: List of payload dictionaries
        file_path: Output file path
        output_format: Output format (json, csv, xml, txt)
          Returns:
        True if successful, False otherwise
    """
    try:
        # Ensure directory exists
        dir_path = os.path.dirname(os.path.abspath(file_path))
        if dir_path:  # Only create directory if dir_path is not empty
            os.makedirs(dir_path, exist_ok=True)
        
        if output_format.lower() == 'json':
            return _save_as_json(payloads, file_path)
        elif output_format.lower() == 'csv':
            return _save_as_csv(payloads, file_path)
        elif output_format.lower() == 'xml':
            return _save_as_xml(payloads, file_path)
        elif output_format.lower() == 'txt':            return _save_as_txt(payloads, file_path)
        else:
            return False
    
    except Exception as e:
        return False


def _save_as_json(payloads: List[Dict[str, Any]], file_path: str) -> bool:
    """Save payloads as JSON file"""
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump({
                'payloads': payloads,
                'count': len(payloads),
                'generated_at': _get_timestamp()
            }, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        return False


def _save_as_csv(payloads: List[Dict[str, Any]], file_path: str) -> bool:
    """Save payloads as CSV file"""
    try:
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            if not payloads:
                return True
            
            # Get all unique field names
            fieldnames = set()
            for payload in payloads:
                fieldnames.update(payload.keys())
            
            fieldnames = sorted(list(fieldnames))
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(payloads)
        return True
    except Exception:
        return False


def _save_as_xml(payloads: List[Dict[str, Any]], file_path: str) -> bool:
    """Save payloads as XML file"""
    try:
        root = ET.Element('payloads')
        root.set('count', str(len(payloads)))
        root.set('generated_at', _get_timestamp())
        
        for payload_data in payloads:
            payload_elem = ET.SubElement(root, 'payload')
            
            for key, value in payload_data.items():
                elem = ET.SubElement(payload_elem, key)
                elem.text = str(value)
        
        tree = ET.ElementTree(root)
        tree.write(file_path, encoding='utf-8', xml_declaration=True)
        return True
    except Exception:
        return False


def _save_as_txt(payloads: List[Dict[str, Any]], file_path: str) -> bool:
    """Save payloads as plain text file"""
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f"# Payloads generated at {_get_timestamp()}\n")
            f.write(f"# Total count: {len(payloads)}\n\n")
            
            for i, payload_data in enumerate(payloads, 1):
                f.write(f"# Payload {i}\n")
                for key, value in payload_data.items():
                    f.write(f"# {key}: {value}\n")
                
                # Write the actual payload
                if 'payload' in payload_data:
                    f.write(f"{payload_data['payload']}\n")
                f.write("\n")
        
        return True
    except Exception:
        return False


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from JSON file
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        return {}


def save_config(config: Dict[str, Any], config_path: str) -> bool:
    """
    Save configuration to JSON file
    
    Args:
        config: Configuration dictionary
        config_path: Path to save configuration
        
    Returns:
        True if successful, False otherwise
    """
    try:
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving config: {e}")
        return False


def load_payload_list(file_path: str) -> List[str]:
    """
    Load list of payloads from file
    
    Args:
        file_path: Path to payload file
        
    Returns:
        List of payload strings
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Try to load as JSON first
            try:
                data = json.load(f)
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict) and 'payloads' in data:
                    return [p.get('payload', '') for p in data['payloads']]
            except json.JSONDecodeError:
                # Fall back to line-by-line reading
                f.seek(0)
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        print(f"Error loading payload list: {e}")
        return []


def copy_to_clipboard(text: str) -> bool:
    """
    Copy text to system clipboard
    
    Args:
        text: Text to copy
        
    Returns:
        True if successful, False otherwise
    """
    try:
        pyperclip.copy(text)
        return True
    except Exception as e:
        print(f"Error copying to clipboard: {e}")
        return False


def get_from_clipboard() -> str:
    """
    Get text from system clipboard
    
    Returns:
        Clipboard text content
    """
    try:
        return pyperclip.paste()
    except Exception as e:
        print(f"Error getting from clipboard: {e}")
        return ""


def create_backup(file_path: str) -> bool:
    """
    Create backup of existing file
    
    Args:
        file_path: Path to file to backup
        
    Returns:
        True if successful, False otherwise
    """
    try:
        if os.path.exists(file_path):
            backup_path = f"{file_path}.backup"
            
            # If backup already exists, create numbered backup
            counter = 1
            while os.path.exists(backup_path):
                backup_path = f"{file_path}.backup.{counter}"
                counter += 1
            
            import shutil
            shutil.copy2(file_path, backup_path)
            return True
        return True
    except Exception as e:
        print(f"Error creating backup: {e}")
        return False


def ensure_directory_exists(file_path: str) -> bool:
    """
    Ensure directory for file path exists
    
    Args:
        file_path: File path to check
        
    Returns:
        True if directory exists or was created, False otherwise
    """
    try:
        directory = os.path.dirname(os.path.abspath(file_path))
        os.makedirs(directory, exist_ok=True)
        return True
    except Exception as e:
        print(f"Error creating directory: {e}")
        return False


def get_file_size(file_path: str) -> int:
    """
    Get file size in bytes
    
    Args:
        file_path: Path to file
        
    Returns:
        File size in bytes, -1 if error
    """
    try:
        return os.path.getsize(file_path)
    except Exception:
        return -1


def is_file_accessible(file_path: str, mode: str = 'r') -> bool:
    """
    Check if file is accessible with specified mode
    
    Args:
        file_path: Path to file
        mode: Access mode ('r', 'w', 'rw')
        
    Returns:
        True if accessible, False otherwise
    """
    try:
        if not os.path.exists(file_path):
            return False
        
        if 'r' in mode and not os.access(file_path, os.R_OK):
            return False
        
        if 'w' in mode and not os.access(file_path, os.W_OK):
            return False
        
        return True
    except Exception:
        return False


def get_safe_filename(filename: str, directory: str = ".") -> str:
    """
    Get a safe filename that doesn't overwrite existing files
    
    Args:
        filename: Desired filename
        directory: Directory to check
        
    Returns:
        Safe filename that won't overwrite existing files
    """
    base_path = os.path.join(directory, filename)
    
    if not os.path.exists(base_path):
        return filename
    
    # Split filename and extension
    name, ext = os.path.splitext(filename)
    
    # Add counter until we find a non-existing filename
    counter = 1
    while True:
        new_filename = f"{name}_{counter}{ext}"
        new_path = os.path.join(directory, new_filename)
        
        if not os.path.exists(new_path):
            return new_filename
        
        counter += 1
        
        # Safety limit
        if counter > 9999:
            break
    
    return filename


def read_file_chunks(file_path: str, chunk_size: int = 8192):
    """
    Generator to read file in chunks
    
    Args:
        file_path: Path to file
        chunk_size: Size of each chunk in bytes
        
    Yields:
        File chunks as bytes
    """
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk
    except Exception as e:
        print(f"Error reading file chunks: {e}")


def append_to_file(file_path: str, content: str, 
                  add_timestamp: bool = True) -> bool:
    """
    Append content to file
    
    Args:
        file_path: Path to file
        content: Content to append
        add_timestamp: Whether to add timestamp
        
    Returns:
        True if successful, False otherwise
    """
    try:
        ensure_directory_exists(file_path)
        
        with open(file_path, 'a', encoding='utf-8') as f:
            if add_timestamp:
                f.write(f"\n# {_get_timestamp()}\n")
            f.write(content)
            f.write("\n")
        
        return True
    except Exception as e:
        print(f"Error appending to file: {e}")
        return False


def export_payloads_multiple_formats(payloads: List[Dict[str, Any]], 
                                   base_path: str) -> Dict[str, bool]:
    """
    Export payloads in multiple formats
    
    Args:
        payloads: List of payload dictionaries
        base_path: Base path for output files (without extension)
        
    Returns:
        Dictionary mapping format to success status
    """
    results = {}
    formats = ['json', 'csv', 'xml', 'txt']
    
    for fmt in formats:
        file_path = f"{base_path}.{fmt}"
        results[fmt] = save_payloads(payloads, file_path, fmt)
    
    return results


def _get_timestamp() -> str:
    """Get current timestamp as string"""
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def create_directory_structure(base_path: str) -> bool:
    """
    Create standard directory structure for payload generator
    
    Args:
        base_path: Base directory path
        
    Returns:
        True if successful, False otherwise
    """
    try:
        directories = [
            'output',
            'configs',
            'logs',
            'backups',
            'templates',
            'payloads'
        ]
        
        for directory in directories:
            dir_path = os.path.join(base_path, directory)
            os.makedirs(dir_path, exist_ok=True)
        
        return True
    except Exception as e:
        print(f"Error creating directory structure: {e}")
        return False


def cleanup_old_files(directory: str, days: int = 30) -> int:
    """
    Clean up old files in directory
    
    Args:
        directory: Directory to clean
        days: Files older than this many days will be deleted
        
    Returns:
        Number of files deleted
    """
    try:
        import time
        
        if not os.path.exists(directory):
            return 0
        
        current_time = time.time()
        cutoff_time = current_time - (days * 24 * 60 * 60)
        
        deleted_count = 0
        
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            
            if os.path.isfile(file_path):
                file_time = os.path.getmtime(file_path)
                
                if file_time < cutoff_time:
                    try:
                        os.remove(file_path)
                        deleted_count += 1
                    except Exception:
                        pass  # Skip files that can't be deleted
        
        return deleted_count
    
    except Exception as e:
        print(f"Error cleaning up old files: {e}")
        return 0
