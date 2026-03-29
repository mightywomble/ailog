"""
Helper functions for device onboarding wizard
"""

import subprocess
import json
from datetime import datetime
from typing import Dict, List, Tuple, Optional

def test_ssh_connection(user: str, ip: str, ssh_key_path: str = None, timeout: int = 5) -> Dict:
    """
    Test SSH connection to a host
    Returns dict with status, message, and connection details
    """
    try:
        cmd = [
            "ssh", 
            "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", "UserKnownHostsFile=/dev/null"
        ]
        
        if ssh_key_path:
            cmd.extend(["-i", ssh_key_path])
        
        cmd.append(f"{user}@{ip}")
        cmd.append("echo 'SSH_SUCCESS'")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if result.returncode == 0 and "SSH_SUCCESS" in result.stdout:
            return {
                'status': 'success',
                'message': 'SSH connection successful',
                'ip': ip,
                'user': user
            }
        elif "Permission denied" in result.stderr or "Authentication failed" in result.stderr:
            return {
                'status': 'auth_error',
                'message': 'Authentication failed',
                'ip': ip,
                'user': user
            }
        else:
            return {
                'status': 'failed',
                'message': f'Connection failed: {result.stderr[:100]}',
                'ip': ip,
                'user': user
            }
    except subprocess.TimeoutExpired:
        return {
            'status': 'timeout',
            'message': 'Connection timed out',
            'ip': ip,
            'user': user
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Error: {str(e)[:100]}',
            'ip': ip,
            'user': user
        }


def execute_remote_command(user: str, ip: str, command: str, ssh_key_path: str = None, timeout: int = 10) -> Tuple[bool, str]:
    """
    Execute a command on a remote host via SSH
    Returns (success, output)
    """
    try:
        cmd = [
            "ssh",
            "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", "UserKnownHostsFile=/dev/null"
        ]
        
        if ssh_key_path:
            cmd.extend(["-i", ssh_key_path])
        
        cmd.append(f"{user}@{ip}")
        cmd.append(command)
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if result.returncode == 0:
            return (True, result.stdout)
        else:
            return (False, result.stderr)
    except subprocess.TimeoutExpired:
        return (False, "Command timed out")
    except Exception as e:
        return (False, str(e))


def collect_system_info(user: str, ip: str, ssh_key_path: str = None) -> Dict:
    """
    Collect comprehensive system information from a host
    Returns dict with collected info
    """
    info = {}
    
    # OS/Kernel version
    success, output = execute_remote_command(user, ip, "uname -a", ssh_key_path)
    if success:
        info['os_version'] = output.strip()
    
    # Hostname
    success, output = execute_remote_command(user, ip, "hostname", ssh_key_path)
    if success:
        info['hostname'] = output.strip()
    
    # RAM info (in bytes)
    success, output = execute_remote_command(user, ip, "free -b | grep Mem | awk '{print $2, $3}'", ssh_key_path)
    if success:
        try:
            parts = output.strip().split()
            info['ram_total'] = int(parts[0])
            info['ram_used'] = int(parts[1])
        except:
            pass
    
    # Disk info (in bytes)
    success, output = execute_remote_command(user, ip, "df -B1 / | tail -1 | awk '{print $2, $3}'", ssh_key_path)
    if success:
        try:
            parts = output.strip().split()
            info['disk_total'] = int(parts[0])
            info['disk_used'] = int(parts[1])
        except:
            pass
    
    # CPU info
    success, output = execute_remote_command(user, ip, "lscpu | grep 'Model name' | cut -d':' -f2", ssh_key_path)
    if success:
        info['cpu_type'] = output.strip()
    
    # CPU cores
    success, output = execute_remote_command(user, ip, "nproc", ssh_key_path)
    if success:
        try:
            info['cpu_cores'] = int(output.strip())
        except:
            pass
    
    # Main IP (try multiple methods)
    success, output = execute_remote_command(user, ip, 
        "hostname -I | awk '{print $1}' || ip -4 addr show scope global | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}' | head -1", 
        ssh_key_path)
    if success:
        info['main_ip'] = output.strip()
    
    # NetBird IP (if available)
    success, output = execute_remote_command(user, ip, "wg show 2>/dev/null | grep 'endpoint' | awk '{print $NF}' || echo ''", ssh_key_path)
    if success and output.strip():
        info['netbird_ip'] = output.strip()
    
    return info


def collect_services(user: str, ip: str, ssh_key_path: str = None) -> List[Dict]:
    """
    Collect systemd service information from a host
    Returns list of service dicts with name, status, is_running
    """
    services = []
    
    # Get all services with their status
    success, output = execute_remote_command(
        user, ip,
        "systemctl list-units --type=service --all --no-pager --output=json 2>/dev/null || systemctl list-units --type=service --all --no-pager",
        ssh_key_path
    )
    
    if success:
        try:
            # Try JSON output first
            service_list = json.loads(output)
            for svc in service_list:
                services.append({
                    'service_name': svc.get('unit', svc.get('name', '')),
                    'status': svc.get('active', svc.get('state', 'unknown')),
                    'is_running': svc.get('active', svc.get('state', '')) in ['active', 'running']
                })
        except:
            # Fallback to plain text parsing
            for line in output.split('\n'):
                if '.service' in line and len(line.strip()) > 0:
                    parts = line.split()
                    if len(parts) >= 3:
                        service_name = parts[0]
                        status = parts[2] if len(parts) > 2 else 'unknown'
                        services.append({
                            'service_name': service_name,
                            'status': status,
                            'is_running': status == 'active'
                        })
    
    return services
