"""Adapt Netdata fleet cards to the Monitoring page's snapshot shape.

The Monitoring page speaks exactly one shape (see ``metrics.collect.system_snapshot``).
Rather than teach the browser about two backends, this module presents a Netdata
node in that shape so a card looks the same whether its numbers came from one
SSH round trip or from the Netdata parent.

Fields Netdata does not expose cheaply (Docker container counts, bytes/second
rates) are left ``None``/absent instead of invented. The card then says "–",
which is the truth, rather than showing a stale or fabricated zero.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import client


def match_nodes(fleet: Dict[str, Any], hosts: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """``{host_key: netdata_node}`` for the nodes that map to an ailog host."""
    out: Dict[str, Dict[str, Any]] = {}
    for node in (fleet or {}).get('nodes') or []:
        key = client.resolve_host_key(node, hosts)
        if key:
            out[key] = node
    return out


# Netdata reports the OS as one human string ("Ubuntu", "Debian GNU/Linux 13",
# "macOS 15.1"). The SSH collector reports ``{family, id, name}``, and the host
# card picks its icon from ``id``/``family`` -- so a raw string silently drew
# the "unknown OS" monitor glyph on every Netdata-matched host.
_OS_IDS = {
    'ubuntu': 'ubuntu', 'debian': 'debian', 'raspbian': 'raspbian', 'mint': 'linuxmint',
    'alpine': 'alpine', 'arch': 'arch', 'manjaro': 'manjaro', 'endeavour': 'endeavouros',
    'fedora': 'fedora', 'centos': 'centos', 'red hat': 'rhel', 'rhel': 'rhel',
    'rocky': 'rocky', 'alma': 'almalinux', 'oracle': 'ol', 'amazon': 'amzn',
    'opensuse': 'opensuse', 'suse': 'suse',
    'freebsd': 'freebsd', 'openbsd': 'openbsd', 'netbsd': 'netbsd',
    'macos': 'macos', 'darwin': 'macos', 'osx': 'macos', 'windows': 'windows',
}


def os_shape(raw: Any) -> Any:
    """``{family, id, name}`` from Netdata's OS string (passthrough if unset)."""
    if isinstance(raw, dict) or not raw:
        return raw
    name = str(raw).strip()
    probe = name.lower()
    distro = ''
    for prefix, ident in _OS_IDS.items():
        if probe.startswith(prefix) or prefix in probe:
            distro = ident
            break
    if distro in ('macos', 'darwin'):
        family = 'darwin'
    elif distro == 'windows':
        family = 'windows'
    elif distro in ('freebsd', 'openbsd', 'netbsd'):
        family = 'bsd'
    else:
        family = 'linux'
    return {'family': family, 'id': distro, 'name': name}


def as_snapshot(host: Dict[str, Any], node: Dict[str, Any]) -> Dict[str, Any]:
    """One Netdata node as a Monitoring-page server snapshot."""
    ram_total = node.get('ram_total') or 0
    disk_total = node.get('disk_space') or 0
    mem_pct = node.get('mem_percent')
    disk_pct = node.get('disk_percent')
    mem_used = int(ram_total * (mem_pct or 0) / 100.0) if ram_total else 0
    disk_used = int(disk_total * (disk_pct or 0) / 100.0) if disk_total else 0
    name = host.get('friendly_name') or host.get('name') or node.get('name')
    return {
        'host_key': host.get('key'),
        'name': name,
        'ip': host.get('ip') or node.get('ip'),
        'ts': node.get('ts'),
        'online': node.get('online') is not False,
        'error': None,
        'hostname': node.get('hostname') or node.get('name'),
        'os': os_shape(node.get('os')),
        'uptime': None,
        # Docker presence comes from Netdata's docker.containers.running
        # context (present only where Docker runs), so the card badge survives
        # without an SSH round trip. Per-container detail still needs the
        # Docker page: only the running count is known here.
        'docker_installed': bool(node.get('docker_installed')),
        'docker_reachable': bool(node.get('docker_installed')),
        'docker_running': int(node.get('docker_running') or 0),
        'docker_total': 0,
        'metrics_source': 'netdata',
        'node_guid': node.get('guid'),
        'anomaly_rate': node.get('anomaly_rate'),
        'alerts': node.get('alerts') or {},
        'cpu': {
            'percent': node.get('cpu_percent'),
            'cores': node.get('cores'),
            'load1': node.get('load1'),
            'load5': None,
            'load15': None,
        },
        'mem': {
            'used': mem_used, 'total': ram_total,
            'percent': mem_pct, 'swap_used': 0, 'swap_total': 0,
        },
        'disk': {
            'used': disk_used, 'total': disk_total,
            'percent': disk_pct, 'mount': '/',
        },
        'net': {'rx': None, 'tx': None, 'rx_bps': None, 'tx_bps': None},
        'series': node.get('series') or {},
    }


def synthetic_host(node: Dict[str, Any]) -> Dict[str, Any]:
    """A Netdata-only node presented as a host dict + snapshot.

    The ``nd:`` prefix is deliberate: it can never collide with ``db-<id>`` or a
    ``hosts.json`` id, and every SSH/container path can refuse it explicitly.
    """
    host = {
        'key': f"nd:{node.get('name')}",
        'name': node.get('name'),
        'friendly_name': node.get('name'),
        'ip': node.get('ip'),
    }
    snapshot = as_snapshot(host, node)
    snapshot['netdata_only'] = True
    return snapshot


def is_netdata_key(host_key: Optional[str]) -> bool:
    return str(host_key or '').startswith('nd:')
