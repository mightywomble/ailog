"""Docker endpoint discovery, host resolution and client factories.

Two transports are supported:

* ``socket``  - the host runs Docker; we talk to it over SSH using the docker
  CLI (works with a unix socket and needs no exposed API port).
* ``tcp``     - plain HTTP Docker Engine API, usually port 2375.
* ``tcp+tls`` - TLS protected Docker Engine API, usually port 2376.
"""
import json
import os
import socket
from typing import Any, Dict, Optional

try:  # Docker Engine API client (optional at runtime)
    import docker as _docker_sdk
    from docker.errors import DockerException
    HAS_SDK = True
except Exception:  # pragma: no cover - SDK missing is tolerated
    _docker_sdk = None
    HAS_SDK = False

    class DockerException(Exception):
        pass


from wizard_helpers import execute_remote_command
from monitoring.sshkeys import materialize_ssh_key_path

SSH_TIMEOUT = 10
PROBE_TIMEOUT = 4

DOCKER_BIN_CMD = "command -v docker >/dev/null 2>&1 && echo DOCKER_OK || echo DOCKER_MISSING"
DOCKER_SOCK_CMD = (
    "(sudo -n docker version --format '{{.Server.Version}}' 2>/dev/null "
    "|| docker version --format '{{.Server.Version}}' 2>/dev/null) "
    "&& echo SOCK_OK || echo SOCK_DENIED"
)
DOCKER_INFO_CMD = (
    "(sudo -n docker info --format '{{json .}}' 2>/dev/null "
    "|| docker info --format '{{json .}}' 2>/dev/null) "
    "|| echo DOCKER_INFO_FAILED"
)
NODE_LS_CMD = "docker node ls --format '{{.ID}}\t{{.Hostname}}\t{{.Status}}\t{{.Availability}}\t{{.ManagerStatus}}' 2>/dev/null"


# --------------------------------------------------------------------------
# host resolution
# --------------------------------------------------------------------------

def _hosts_file() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'hosts.json')


def load_config_hosts() -> Dict[str, Any]:
    try:
        with open(_hosts_file(), 'r') as fh:
            return json.load(fh) or {}
    except Exception:
        return {}


def resolve_host(host_key: str) -> Optional[Dict[str, Any]]:
    """Resolve an ailog host key (config id, ``db-<id>`` or ``local``).

    Returns ``{key, friendly_name, ip, user, ssh_key_id}`` or ``None``.
    """
    host_key = str(host_key)
    if host_key == 'local':
        return {'key': 'local', 'friendly_name': 'localhost', 'ip': '127.0.0.1', 'user': 'root', 'ssh_key_id': None}

    if host_key.startswith('db-'):
        try:
            from database import Host  # imported lazily to avoid circular import
            host_id = int(host_key[3:])
        except Exception:
            return None
        host = Host.query.get(host_id)
        if not host:
            return None
        return {
            'key': host_key,
            'friendly_name': host.friendly_name or host.hostname or host.ip_address,
            'ip': host.ip_address,
            'user': host.ssh_user or 'root',
            'ssh_key_id': host.ssh_key_id,
        }

    cfg = load_config_hosts().get(host_key)
    if not cfg:
        return None
    return {
        'key': host_key,
        'friendly_name': cfg.get('friendly_name') or cfg.get('ip') or host_key,
        'ip': cfg.get('ip'),
        'user': cfg.get('user') or 'root',
        'ssh_key_id': cfg.get('ssh_key_id'),
    }


def all_host_keys():
    keys = ['local']
    keys.extend(load_config_hosts().keys())
    try:
        from database import Host
        keys.extend([f'db-{h.id}' for h in Host.query.all()])
    except Exception:
        pass
    return keys


def ssh_key_path(ssh_key_id) -> Optional[str]:
    try:
        return materialize_ssh_key_path(ssh_key_id)
    except Exception:
        return None


def ssh_run(user: str, ip: str, command: str, ssh_key_id=None, timeout: int = SSH_TIMEOUT):
    return execute_remote_command(user, ip, command, ssh_key_path=ssh_key_path(ssh_key_id), timeout=timeout)


# --------------------------------------------------------------------------
# probes
# --------------------------------------------------------------------------

def probe_ssh_docker(user: str, ip: str, ssh_key_id=None) -> Dict[str, Any]:
    """Check for the docker CLI and a reachable unix socket over SSH."""
    ok, out = ssh_run(user, ip, DOCKER_BIN_CMD, ssh_key_id)
    if not (ok and 'DOCKER_OK' in (out or '')):
        return {'ok': False, 'reason': 'docker_not_installed'}
    ok, out = ssh_run(user, ip, DOCKER_SOCK_CMD, ssh_key_id)
    if not (ok and 'SOCK_OK' in (out or '')):
        return {'ok': False, 'reason': 'socket_denied'}
    version = (out or '').strip().splitlines()[0:1]
    return {'ok': True, 'mode': 'socket', 'server_version': version[0] if version else None}


def probe_tcp(ip: str, port: int, tls: bool = False, tls_verify: bool = False,
              ca_pem: str = None, cert_pem: str = None, key_pem: str = None,
              timeout: float = PROBE_TIMEOUT) -> Dict[str, Any]:
    """Ping a TCP Docker endpoint, first with a raw socket then with the SDK."""
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            pass
    except OSError as exc:
        return {'ok': False, 'reason': 'unreachable', 'error': str(exc)}

    if not HAS_SDK:
        return {'ok': True, 'mode': 'tcp+tls' if tls else 'tcp', 'server_version': None,
                'warning': 'docker python sdk not installed; ping not verified'}
    try:
        client = build_client('tcp+tls' if tls else 'tcp', ip=ip, port=port,
                              tls_verify=tls_verify, ca_pem=ca_pem,
                              cert_pem=cert_pem, key_pem=key_pem, timeout=timeout)
        version = client.version()
        client.close()
        return {'ok': True, 'mode': 'tcp+tls' if tls else 'tcp',
                'server_version': (version or {}).get('Version')}
    except Exception as exc:
        return {'ok': False, 'reason': 'api_error', 'error': str(exc)}


def discover_host(host_key: str, tcp_ports=(2375, 2376)) -> Dict[str, Any]:
    """Probe one host for a usable Docker endpoint, preferring SSH/unix socket."""
    host = resolve_host(host_key)
    if not host:
        return {'host_key': host_key, 'reachable': False, 'mode': None, 'error': 'host not found'}
    ip, user = host['ip'], host['user']

    result = {'host_key': host_key, 'friendly_name': host['friendly_name'], 'ip': ip,
              'reachable': False, 'mode': None, 'error': None}

    if host_key != 'local':
        ssh_res = probe_ssh_docker(user, ip, host.get('ssh_key_id'))
        if ssh_res.get('ok'):
            result.update(reachable=True, mode='socket', port=None, error=None,
                          server_version=ssh_res.get('server_version'))
            return result
        result['error'] = ssh_res.get('reason')

    # Plain TCP first (most homelab hosts), then TLS.
    for port, tls in ((tcp_ports[0], False), (tcp_ports[1], True)):
        if tls:
            # only probe TLS when something answered on the TLS port
            try:
                with socket.create_connection((ip, int(port)), timeout=PROBE_TIMEOUT):
                    pass
            except OSError:
                continue
            res = probe_tcp(ip, port, tls=True, tls_verify=False)
        else:
            res = probe_tcp(ip, port, tls=False)
        if res.get('ok'):
            result.update(reachable=True, mode=res['mode'], port=port, error=None,
                          server_version=res.get('server_version'))
            return result
        if not result.get('error'):
            result['error'] = res.get('reason') or res.get('error')

    if not result.get('error'):
        result['error'] = 'no docker endpoint found'
    return result


# --------------------------------------------------------------------------
# clients
# --------------------------------------------------------------------------

def build_client(mode: str, ip: str, port: Optional[int] = None, tls_verify: bool = True,
                 ca_pem: str = None, cert_pem: str = None, key_pem: str = None,
                 timeout: float = 10):
    if not HAS_SDK:
        raise RuntimeError('docker python SDK is not installed on the ailog server')
    if mode == 'tcp':
        return _docker_sdk.DockerClient(base_url=f'tcp://{ip}:{int(port or 2375)}',
                                        timeout=timeout, version='auto')
    if mode == 'tcp+tls':
        tls_cfg = None
        client_cert = (cert_pem, key_pem) if (cert_pem and key_pem) else None
        try:
            tls_cfg = _docker_sdk.tls.TLSConfig(
                client_cert=client_cert, ca_cert=ca_pem,
                verify=bool(tls_verify) if ca_pem else False,
                assert_hostname=False,
            )
        except Exception:
            tls_cfg = None
        return _docker_sdk.DockerClient(base_url=f'tcp://{ip}:{int(port or 2376)}',
                                        tls=tls_cfg, timeout=timeout, version='auto')
    raise ValueError(f"mode '{mode}' is not a TCP transport")
