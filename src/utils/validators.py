"""
Input validation utilities
Handles validation of user inputs and parameters
"""

import re
import os
from urllib.parse import urlparse
from typing import Any, List, Dict, Union


def validate_url(url: str) -> bool:
    """
    Validate if a string is a valid URL (HTTP/HTTPS only)
    
    Args:
        url: URL string to validate
        
    Returns:
        True if valid HTTP/HTTPS URL, False otherwise
    """
    try:
        result = urlparse(url)
        return all([
            result.scheme in ['http', 'https'],
            result.netloc
        ])
    except Exception:
        return False


def validate_count(count: Union[int, str]) -> bool:
    """
    Validate payload count parameter
    
    Args:
        count: Count value to validate
        
    Returns:
        True if valid count, False otherwise
    """
    try:
        count_int = int(count)
        return 1 <= count_int <= 1000
    except (ValueError, TypeError):
        return False


def validate_encoding_type(encoding: str) -> bool:
    """
    Validate encoding type parameter
    
    Args:
        encoding: Encoding type to validate
        
    Returns:
        True if valid encoding type, False otherwise
    """
    valid_encodings = [
        'none', 'base64', 'url', 'double_url', 'hex', 'unicode',
        'html', 'html_decimal', 'html_hex', 'javascript'
    ]
    return encoding.lower() in valid_encodings


def validate_output_format(format_type: str) -> bool:
    """
    Validate output format parameter
    
    Args:
        format_type: Output format to validate
        
    Returns:
        True if valid format, False otherwise
    """
    valid_formats = ['cli', 'json', 'csv', 'xml', 'txt']
    return format_type.lower() in valid_formats


def validate_platform(platform: str) -> bool:
    """
    Validate platform parameter
    
    Args:
        platform: Platform to validate
        
    Returns:
        True if valid platform, False otherwise
    """
    valid_platforms = ['linux', 'windows', 'both']
    return platform.lower() in valid_platforms


def validate_database_type(database: str) -> bool:
    """
    Validate database type parameter
    
    Args:
        database: Database type to validate
        
    Returns:
        True if valid database type, False otherwise
    """
    valid_databases = ['mysql', 'postgres', 'postgresql', 'mssql', 'oracle', 'sqlite']
    return database.lower() in valid_databases


def validate_xss_context(context: str) -> bool:
    """
    Validate XSS context parameter
    
    Args:
        context: XSS context to validate
        
    Returns:
        True if valid context, False otherwise
    """
    valid_contexts = ['html', 'attribute', 'script', 'css', 'url']
    return context.lower() in valid_contexts


def validate_file_path(file_path: str, check_writable: bool = True) -> bool:
    """
    Validate file path for output
    
    Args:
        file_path: File path to validate
        check_writable: Whether to check if directory is writable
        
    Returns:
        True if valid file path, False otherwise
    """
    try:
        # Check if path is not empty
        if not file_path.strip():
            return False
        
        # Get directory path
        directory = os.path.dirname(os.path.abspath(file_path))
        
        # Check if directory exists or can be created
        if not os.path.exists(directory):
            try:
                os.makedirs(directory, exist_ok=True)
            except OSError:
                return False
        
        # Check if directory is writable
        if check_writable and not os.access(directory, os.W_OK):
            return False
        
        # Check for dangerous file paths
        dangerous_patterns = [
            r'\.\./',  # Path traversal
            r'[<>:"|?*]',  # Invalid Windows characters
            r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$',  # Windows reserved names
        ]
        
        filename = os.path.basename(file_path)
        for pattern in dangerous_patterns:
            if re.search(pattern, filename, re.IGNORECASE):
                return False
        
        return True
    
    except Exception:
        return False


def validate_payload(payload: str, max_length: int = 10000) -> bool:
    """
    Basic payload validation
    
    Args:
        payload: Payload string to validate
        max_length: Maximum allowed payload length
        
    Returns:
        True if valid payload, False otherwise
    """
    try:
        # Check if payload is not empty
        if not payload.strip():
            return False
        
        # Check length
        if len(payload) > max_length:
            return False
        
        # Check for potentially dangerous characters (basic check)
        # Allow most characters but block null bytes and some control characters
        if '\x00' in payload:
            return False
        
        return True
    
    except Exception:
        return False


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe file operations
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove or replace dangerous characters
    sanitized = re.sub(r'[<>:"|?*]', '_', filename)
    
    # Remove path traversal patterns
    sanitized = re.sub(r'\.\./', '', sanitized)
    
    # Limit length
    if len(sanitized) > 255:
        name, ext = os.path.splitext(sanitized)
        sanitized = name[:255-len(ext)] + ext
    
    # Ensure it's not a Windows reserved name
    reserved_names = ['CON', 'PRN', 'AUX', 'NUL'] + [f'COM{i}' for i in range(1, 10)] + [f'LPT{i}' for i in range(1, 10)]
    base_name = sanitized.split('.')[0].upper()
    if base_name in reserved_names:
        sanitized = f"_{sanitized}"
    
    return sanitized


def validate_config_file(config_path: str) -> bool:
    """
    Validate configuration file path and accessibility
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        True if valid and accessible, False otherwise
    """
    try:
        # Check if file exists
        if not os.path.exists(config_path):
            return False
        
        # Check if it's a file (not directory)
        if not os.path.isfile(config_path):
            return False
        
        # Check if readable
        if not os.access(config_path, os.R_OK):
            return False
        
        # Check file extension
        valid_extensions = ['.json', '.yaml', '.yml', '.conf', '.cfg']
        _, ext = os.path.splitext(config_path)
        if ext.lower() not in valid_extensions:
            return False
        
        return True
    
    except Exception:
        return False


def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address format
    
    Args:
        ip: IP address string
        
    Returns:
        True if valid IP address, False otherwise
    """
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        for part in parts:
            if not part.isdigit():
                return False
            if not 0 <= int(part) <= 255:
                return False
        
        return True
    
    except Exception:
        return False


def validate_port(port: Union[int, str]) -> bool:
    """
    Validate port number
    
    Args:
        port: Port number to validate
        
    Returns:
        True if valid port, False otherwise
    """
    try:
        port_int = int(port)
        return 1 <= port_int <= 65535
    except (ValueError, TypeError):
        return False


def validate_api_key(api_key: str) -> bool:
    """
    Validate API key format
    
    Args:
        api_key: API key to validate
        
    Returns:
        True if valid format, False otherwise
    """
    try:
        # Check if not empty
        if not api_key.strip():
            return False
        
        # Check length (reasonable range for API keys)
        if not 10 <= len(api_key) <= 100:
            return False
        
        # Check for valid characters (alphanumeric)
        if not re.match(r'^[a-zA-Z0-9]+$', api_key):
            return False
        
        return True
    
    except Exception:
        return False


def validate_http_method(method: str) -> bool:
    """
    Validate HTTP method
    
    Args:
        method: HTTP method to validate
        
    Returns:
        True if valid method, False otherwise
    """
    valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
    return method.upper() in valid_methods


def validate_injection_position(position: str) -> bool:
    """
    Validate payload injection position
    
    Args:
        position: Injection position to validate
        
    Returns:
        True if valid position, False otherwise
    """
    valid_positions = ['url', 'body', 'header', 'cookie']
    return position.lower() in valid_positions


def sanitize_input(input_string: str, max_length: int = 1000) -> str:
    """
    Sanitize user input string
    
    Args:
        input_string: Input to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized input string
    """
    try:
        # Remove null bytes and control characters
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', input_string)
        
        # Limit length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        # Strip whitespace
        sanitized = sanitized.strip()
        
        return sanitized
    
    except Exception:
        return ""


def validate_batch_size(batch_size: Union[int, str]) -> bool:
    """
    Validate batch processing size
    
    Args:
        batch_size: Batch size to validate
        
    Returns:
        True if valid batch size, False otherwise
    """
    try:
        size_int = int(batch_size)
        return 1 <= size_int <= 100
    except (ValueError, TypeError):
        return False


def validate_timeout(timeout: Union[int, float, str]) -> bool:
    """
    Validate timeout value
    
    Args:
        timeout: Timeout value to validate
        
    Returns:
        True if valid timeout, False otherwise
    """
    try:
        timeout_float = float(timeout)
        return 0.1 <= timeout_float <= 300.0  # 0.1 seconds to 5 minutes
    except (ValueError, TypeError):
        return False


def validate_delay(delay: Union[int, float, str]) -> bool:
    """
    Validate delay value between requests
    
    Args:
        delay: Delay value to validate
        
    Returns:
        True if valid delay, False otherwise
    """
    try:
        delay_float = float(delay)
        return 0.0 <= delay_float <= 60.0  # 0 to 60 seconds
    except (ValueError, TypeError):
        return False


class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass


def validate_all_inputs(inputs: Dict[str, Any]) -> List[str]:
    """
    Validate multiple inputs and return list of errors
    
    Args:
        inputs: Dictionary of input values to validate
        
    Returns:
        List of validation error messages
    """
    errors = []
    
    # Validate each input type
    if 'url' in inputs and inputs['url']:
        if not validate_url(inputs['url']):
            errors.append("Invalid URL format")
    
    if 'count' in inputs and inputs['count'] is not None:
        if not validate_count(inputs['count']):
            errors.append("Count must be between 1 and 1000")
    
    if 'encoding' in inputs and inputs['encoding']:
        if not validate_encoding_type(inputs['encoding']):
            errors.append("Invalid encoding type")
    
    if 'output' in inputs and inputs['output']:
        if not validate_output_format(inputs['output']):
            errors.append("Invalid output format")
    
    if 'platform' in inputs and inputs['platform']:
        if not validate_platform(inputs['platform']):
            errors.append("Invalid platform (must be linux, windows, or both)")
    
    if 'database' in inputs and inputs['database']:
        if not validate_database_type(inputs['database']):
            errors.append("Invalid database type")
    
    if 'context' in inputs and inputs['context']:
        if not validate_xss_context(inputs['context']):
            errors.append("Invalid XSS context")
    
    if 'save' in inputs and inputs['save']:
        if not validate_file_path(inputs['save']):
            errors.append("Invalid or inaccessible file path")
    
    if 'api_key' in inputs and inputs['api_key']:
        if not validate_api_key(inputs['api_key']):
            errors.append("Invalid API key format")
    
    return errors
