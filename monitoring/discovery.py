import json
import re
from typing import Any, Dict, List, Optional, Tuple

from wizard_helpers import execute_remote_command


COMMON_PORTS = {
    22,
    53,
    80,
    443,
    445,
    3000,
    5000,
    5432,
    5672,
    6379,
    8080,
    8443,
    9000,
    9090,
    9100,
    9200,
    9300,
}

HTTP_LIKE_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8443, 9000}
TLS_LIKE_PORTS = {443, 8443}


def _parse_ss_listeners(output: str) -> List[Dict[str, Any]]:
    listeners: List[Dict[str, Any]] = []
    # ss -H -lntp4 output example:
    # LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=123,fd=3))
    for line in (output or '').splitlines():
        line = line.strip()
        if not line:
            continue
        parts = re.split(r"\s+", line)
        # We expect local address in column 3 (State Recv-Q Send-Q Local Address:Port ...)
        if len(parts) < 4:
            continue
        local = parts[3]
        m = re.match(r"^(?P<addr>[^:]+):(?P<port>\d+)$", local)
        if not m:
            continue
        addr = m.group('addr')
        port = int(m.group('port'))
        proc = None
        if 'users:(' in line:
            proc = line.split('users:(', 1)[1].rstrip(')')
        listeners.append({'bind': addr, 'port': port, 'process': proc})
    return listeners


def _parse_netstat_listeners(output: str) -> List[Dict[str, Any]]:
    listeners: List[Dict[str, Any]] = []
    # netstat -lntp (may require sudo for process names)
    for line in (output or '').splitlines():
        line = line.strip()
        if not line or line.startswith('Proto'):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 4:
            continue
        local = parts[3]
        # local could be 0.0.0.0:22 or :::80
        if ':' not in local:
            continue
        port_str = local.rsplit(':', 1)[-1]
        if not port_str.isdigit():
            continue
        port = int(port_str)
        proc = parts[-1] if parts else None
        listeners.append({'bind': local.rsplit(':', 1)[0], 'port': port, 'process': proc})
    return listeners


def collect_listening_ports_v4(user: str, ip: str, ssh_key_path: Optional[str]) -> Tuple[bool, List[Dict[str, Any]], str]:
    # Prefer ss; fallback to netstat
    ok, out = execute_remote_command(user, ip, 'ss -H -lntp4', ssh_key_path=ssh_key_path, timeout=15)
    if ok:
        return True, _parse_ss_listeners(out), ''

    ok2, out2 = execute_remote_command(user, ip, 'netstat -lntp 2>/dev/null | tail -n +3', ssh_key_path=ssh_key_path, timeout=20)
    if ok2:
        return True, _parse_netstat_listeners(out2), ''

    return False, [], (out or out2 or 'failed to collect listeners')


def collect_docker_inventory(user: str, ip: str, ssh_key_path: Optional[str]) -> Tuple[bool, Dict[str, Any], str]:
    ok, out = execute_remote_command(user, ip, 'command -v docker >/dev/null 2>&1 && echo DOCKER_OK || echo DOCKER_MISSING', ssh_key_path=ssh_key_path, timeout=10)
    if not ok:
        return False, {}, out or 'docker detection failed'

    if 'DOCKER_MISSING' in (out or ''):
        return True, {'docker': False, 'containers': []}, ''

    # Use json format for easier parsing
    cmd = r"docker ps --no-trunc --format '{{json .}}'"
    ok2, out2 = execute_remote_command(user, ip, cmd, ssh_key_path=ssh_key_path, timeout=30)
    if not ok2:
        return False, {}, out2 or 'docker ps failed'

    containers = []
    for line in (out2 or '').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        containers.append(obj)

    return True, {'docker': True, 'containers': containers}, ''


_PUBLISHED_PORT_RE = re.compile(r"(?P<host_ip>(?:\d+\.){3}\d+)?:(?P<host_port>\d+)->(?P<container_port>\d+)/(tcp|udp)")


def extract_published_ports_from_docker(containers: List[Dict[str, Any]]) -> List[int]:
    ports: List[int] = []
    for c in containers or []:
        p = (c.get('Ports') or '').strip()
        if not p:
            continue
        for m in _PUBLISHED_PORT_RE.finditer(p):
            try:
                ports.append(int(m.group('host_port')))
            except Exception:
                continue
    return sorted(set(ports))


def generate_monitor_candidates(
    host_ip: str,
    listeners: List[Dict[str, Any]],
    docker_inventory: Dict[str, Any],
    scan_profile: str,
    http_probe_results: Optional[Dict[int, Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    http_probe_results = http_probe_results or {}

    discovered_ports = {int(x['port']) for x in (listeners or []) if 'port' in x}

    if scan_profile == 'common':
        ports = sorted(p for p in discovered_ports if p in COMMON_PORTS)
    else:
        # '1-1024'
        ports = sorted(p for p in discovered_ports if 1 <= p <= 1024)

    docker_ports = extract_published_ports_from_docker((docker_inventory or {}).get('containers') or [])
    for p in docker_ports:
        if scan_profile == 'common' and p not in COMMON_PORTS:
            continue
        if scan_profile == '1-1024' and not (1 <= p <= 1024):
            continue
        ports.append(p)

    ports = sorted(set(ports))

    candidates: List[Dict[str, Any]] = []
    for port in ports:
        probe = http_probe_results.get(port) or {}
        if probe.get('is_http'):
            url = probe.get('url')
            if not url:
                scheme = 'https' if port in TLS_LIKE_PORTS else 'http'
                url = f'{scheme}://{host_ip}:{port}'
            candidates.append(
                {
                    'type': 'http',
                    'name': f'HTTP {host_ip}:{port}',
                    'config': {
                        'url': url,
                        'method': 'GET',
                        'acceptedStatusCodes': [200],
                        'followRedirects': True,
                        'ignoreSSL': True if port in TLS_LIKE_PORTS else False,
                    },
                    'port': port,
                }
            )
        else:
            candidates.append(
                {
                    'type': 'tcp',
                    'name': f'TCP {host_ip}:{port}',
                    'config': {'hostname': host_ip, 'port': port},
                    'port': port,
                }
            )

    return candidates
