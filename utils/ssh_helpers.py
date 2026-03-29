"""SSH connection and system information helpers."""
import logging
from wizard_helpers import test_ssh_connection as _test_ssh, get_system_info as _get_sys_info, collect_host_info as _collect_host

logger = logging.getLogger(__name__)

def test_ssh_connection(user: str, ip: str, ssh_key_path: str = None, timeout: int = 5) -> dict:
    """
    Test SSH connection to a host with logging.
    
    Args:
        user: SSH username
        ip: IP address or hostname
        ssh_key_path: Path to SSH private key
        timeout: Connection timeout in seconds
        
    Returns:
        dict with status, message, ip, user
    """
    logger.debug(f"[SSH] Testing connection to {user}@{ip}")
    result = _test_ssh(user, ip, ssh_key_path, timeout)
    logger.debug(f"[SSH] Result: {result['status']}")
    return result

def get_system_info(user: str, ip: str, ssh_key_path: str = None) -> dict:
    """
    Get system information from a host via SSH.
    
    Args:
        user: SSH username
        ip: IP address or hostname
        ssh_key_path: Path to SSH private key
        
    Returns:
        dict with system information (hostname, os, cpu, ram, disk, services)
    """
    logger.debug(f"[SSH] Collecting system info from {user}@{ip}")
    result = _get_sys_info(user, ip, ssh_key_path)
    logger.debug(f"[SSH] System info collected: {list(result.keys())}")
    return result

def collect_host_info(user: str, ip: str, ssh_key_path: str = None) -> dict:
    """
    Collect complete host information (connection test + system info).
    
    Args:
        user: SSH username
        ip: IP address or hostname
        ssh_key_path: Path to SSH private key
        
    Returns:
        dict with complete host information
    """
    logger.debug(f"[SSH] Collecting full host info for {user}@{ip}")
    
    # Test connection first
    conn_result = test_ssh_connection(user, ip, ssh_key_path)
    if conn_result['status'] != 'success':
        logger.warning(f"[SSH] Connection failed for {user}@{ip}")
        return {'connection': conn_result}
    
    # Get system info
    try:
        sys_info = get_system_info(user, ip, ssh_key_path)
        logger.info(f"[SSH] Successfully collected info for {user}@{ip}")
        return {
            'connection': conn_result,
            'system_info': sys_info
        }
    except Exception as e:
        logger.error(f"[SSH] Failed to collect system info from {user}@{ip}: {str(e)}")
        raise
