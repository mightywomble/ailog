"""Input validation utilities."""
import re
import logging

logger = logging.getLogger(__name__)

def validate_ip_addresses(ip_list):
    """
    Validate a list of IP addresses or hostnames.
    
    Args:
        ip_list: List of IP addresses or hostnames
        
    Returns:
        Tuple of (valid_ips, invalid_ips)
    """
    valid_ips = []
    invalid_ips = []
    
    ip_pattern = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    
    hostname_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    for ip in ip_list:
        ip = ip.strip()
        if ip_pattern.match(ip) or hostname_pattern.match(ip):
            valid_ips.append(ip)
            logger.debug(f"[VALIDATE] IP/hostname valid: {ip}")
        else:
            invalid_ips.append(ip)
            logger.warning(f"[VALIDATE] Invalid IP/hostname: {ip}")
    
    return valid_ips, invalid_ips

def validate_hostname(hostname):
    """Validate a single hostname."""
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    is_valid = bool(pattern.match(hostname))
    logger.debug(f"[VALIDATE] Hostname '{hostname}': {is_valid}")
    return is_valid
