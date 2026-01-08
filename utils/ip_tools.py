"""
IP address utilities
"""
import ipaddress
from typing import Optional

def is_private_ip(ip_str: str) -> bool:
    """Check if IP is private"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False

def is_public_ip(ip_str: str) -> bool:
    """Check if IP is public"""
    return not is_private_ip(ip_str)

def is_multicast(ip_str: str) -> bool:
    """Check if IP is multicast"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_multicast
    except ValueError:
        return False

def is_loopback(ip_str: str) -> bool:
    """Check if IP is loopback"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_loopback
    except ValueError:
        return False

def ip_to_int(ip_str: str) -> Optional[int]:
    """Convert IP to integer"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return int(ip)
    except ValueError:
        return None

def int_to_ip(ip_int: int, version: int = 4) -> Optional[str]:
    """Convert integer to IP"""
    try:
        if version == 4:
            ip = ipaddress.IPv4Address(ip_int)
        else:
            ip = ipaddress.IPv6Address(ip_int)
        return str(ip)
    except ValueError:
        return None

def in_subnet(ip_str: str, subnet_str: str) -> bool:
    """Check if IP is in subnet"""
    try:
        ip = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(subnet_str, strict=False)
        return ip in network
    except ValueError:
        return False

def get_network(ip_str: str, prefix_len: int) -> Optional[str]:
    """Get network address from IP and prefix length"""
    try:
        interface = ipaddress.ip_interface(f"{ip_str}/{prefix_len}")
        return str(interface.network)
    except ValueError:
        return None