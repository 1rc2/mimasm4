"""
SM4 Utility Functions
Hex and Base64 encoding, key/IV generation
"""

import os
import base64
import secrets


def generate_random_key():
    """Generate random 128-bit SM4 key"""
    return secrets.token_bytes(16)


def generate_random_iv():
    """Generate random 128-bit IV"""
    return secrets.token_bytes(16)


def bytes_to_hex(data):
    """Convert bytes to hex string"""
    return data.hex()


def hex_to_bytes(hex_str):
    """Convert hex string to bytes"""
    hex_str = hex_str.replace(' ', '').replace('-', '')
    if len(hex_str) % 2 != 0:
        raise ValueError("Hex string must have even length")
    return bytes.fromhex(hex_str)


def bytes_to_base64(data):
    """Convert bytes to Base64 string"""
    return base64.b64encode(data).decode('ascii')


def base64_to_bytes(base64_str):
    """Convert Base64 string to bytes"""
    return base64.b64decode(base64_str)


def format_hex(data, group_size=2):
    """Format hex with spaces every group_size characters"""
    hex_str = bytes_to_hex(data)
    return ' '.join([hex_str[i:i+group_size] for i in range(0, len(hex_str), group_size)])


def validate_key(key_str, key_type='hex'):
    """Validate and convert key input"""
    if key_type == 'hex':
        key_bytes = hex_to_bytes(key_str)
    elif key_type == 'base64':
        key_bytes = base64_to_bytes(key_str)
    elif key_type == 'bytes':
        key_bytes = key_str
    else:
        raise ValueError("Invalid key type")

    if len(key_bytes) != 16:
        raise ValueError(f"Key must be 128 bits (16 bytes), got {len(key_bytes)} bytes")

    return key_bytes


def validate_iv(iv_str, iv_type='hex'):
    """Validate and convert IV input"""
    if iv_str is None:
        return None

    if iv_type == 'hex':
        iv_bytes = hex_to_bytes(iv_str)
    elif iv_type == 'base64':
        iv_bytes = base64_to_bytes(iv_str)
    elif iv_type == 'bytes':
        iv_bytes = iv_str
    else:
        raise ValueError("Invalid IV type")

    if len(iv_bytes) != 16:
        raise ValueError(f"IV must be 128 bits (16 bytes), got {len(iv_bytes)} bytes")

    return iv_bytes


def get_file_size(file_path):
    """Get file size in bytes"""
    return os.path.getsize(file_path)


def format_size(size_bytes):
    """Format file size in human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"
