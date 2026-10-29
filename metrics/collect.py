"""System metrics (CPU / RAM / disk / network) for one host, fast.

The Monitoring page wants all hosts at once and refreshed every couple of
seconds, so this is deliberately cheaper than :mod:`dockermon.sshstats`: one
SSH command that only ``cat``s ``/proc`` files and runs ``df`` once.  Container
level numbers come from the existing Docker collectors (see
:func:`container_snapshot`) so there is exactly one implementation of "what is
this container doing".

CPU and network are counters, so the first sample of a host has no percentage
or rate - it seeds the cache and reports ``None``.  The second sample onwards
is a true delta.
"""

from __future__ import annotations

import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

from dockermon.parse import parse_df_root, parse_meminfo, parse_netdev, parse_proc_stat

MARK = '===AILOG_METRICS==='
SECTIONS = ('stat', 'mem', 'net', 'df', 'load', 'up', 'host', 'docker', 'dstate')

# host_key -> (wall clock, rx, tx, cpu_total, cpu_idle)
_rate_lock = threading.Lock()
_rate_cache: Dict[str, tuple] = {}

# (host_key, container id) -> (wall clock, rx, tx)
_container_rate_lock = threading.Lock()
_container_rate_cache: Dict[tuple, tuple] = {}

SSH_TIMEOUT = 20


def build_command() -> str:
    """One marker-delimited command; every section is independent so a
    missing file (e.g. no /proc/net/dev in a tiny container) only loses
    that section instead of failing the whole sample."""
    lines = []
    for name in SECTIONS:
        if name == 'stat':
            cmd = 'cat /proc/stat'
        elif name == 'mem':
            cmd = 'cat /proc/meminfo'
        elif name == 'net':
            cmd = 'cat /proc/net/dev'
        elif name == 'df':
            # -kP is portable (GNU + BSD); -B1 is GNU only and the app also
            # runs on macOS in development.
            cmd = 'df -kP /'
        elif name == 'load':
            cmd = 'cat /proc/loadavg'
        elif name == 'up':
            cmd = 'cat /proc/uptime'
        elif name == 'host':
            cmd = 'hostname'
        elif name == 'docker':
            cmd = 'command -v docker >/dev/null 2>&1 && echo yes || echo no'
        else:
            # Container counts (and a definitive "the engine answered") from
            # the same round trip: no separate Docker API call, no stale DB row.
            cmd = ("{ (sudo -n docker ps -a --format '{{.State}}' 2>/dev/null "
                   "|| docker ps -a --format '{{.State}}' 2>/dev/null) "
                   "&& echo AILOG_DOCKER_OK; } 2>/dev/null")
        lines.append(f"echo '{MARK}:{name}'; {cmd} 2>/dev/null")
    return '; '.join(lines)


def _split(output: str) -> Dict[str, str]:
    blocks: Dict[str, List[str]] = {}
    current = None
    for line in (output or '').splitlines():
        if line.startswith(MARK + ':'):
            current = line.split(':', 1)[1].strip()
            blocks.setdefault(current, [])
            continue
        if current is not None:
            blocks[current].append(line)
    return {k: '\n'.join(v).strip() for k, v in blocks.items()}


def _run(host: Dict[str, Any], command: str, timeout: int = SSH_TIMEOUT):
    """Run on ``local`` via a shell, everything else over SSH."""
    if host.get('key') == 'local':
        proc = subprocess.run(['bash', '-lc', command], capture_output=True,
                              text=True, timeout=timeout)
        return proc.returncode == 0, (proc.stdout or '') + (proc.stderr or '')

    from dockermon import endpoints as ep
    ok, out = ep.ssh_run(host.get('user') or 'root', host.get('ip'),
                         command, ssh_key_id=host.get('ssh_key_id'),
                         timeout=timeout)
    return ok, out or ''


def _float(value, default=0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _meminfo_value(text: str, key: str) -> int:
    """One /proc/meminfo field in bytes (parse_meminfo only returns the
    total/used/available trio, but the page also wants swap)."""
    for line in (text or '').splitlines():
        if line.startswith(key + ':'):
            try:
                return int(line.split(':', 1)[1].split()[0]) * 1024
            except (IndexError, ValueError):
                return 0
    return 0


def parse_system(text: str) -> Dict[str, Any]:
    """Parse the marker output into raw counters (no rates yet)."""
    blocks = _split(text)
    proc = parse_proc_stat(blocks.get('stat', '')) or {}
    mem = parse_meminfo(blocks.get('mem', ''))
    net = parse_netdev(blocks.get('net', ''))
    disk_total, disk_used = parse_df_root(blocks.get('df', ''))
    # parse_df_root returns the raw numbers; `df -kP` reports 1024-byte blocks.
    disk_total = (disk_total or 0) * 1024
    disk_used = (disk_used or 0) * 1024

    load = [_float(x) for x in (blocks.get('load', '').split() or [])[:3]]
    uptime = _float((blocks.get('up', '').split() or [0])[0])
    swap_total = _meminfo_value(blocks.get('mem', ''), 'SwapTotal')
    swap_free = _meminfo_value(blocks.get('mem', ''), 'SwapFree')

    states = [ln.strip().lower() for ln in (blocks.get('dstate', '') or '').splitlines()]
    docker_ok = 'ailog_docker_ok' in states
    states = [st for st in states if st and st != 'ailog_docker_ok']

    return {
        'cpu_total': proc.get('total') or 0,
        'cpu_idle': proc.get('idle') or 0,
        'mem_used': mem.get('used') or 0,
        'mem_total': mem.get('total') or 0,
        'mem_available': mem.get('available') or 0,
        'swap_used': max(0, swap_total - swap_free),
        'swap_total': swap_total,
        'rx': net.get('rx') or 0,
        'tx': net.get('tx') or 0,
        'disk_used': disk_used or 0,
        'disk_total': disk_total or 0,
        'load1': load[0] if len(load) > 0 else None,
        'load5': load[1] if len(load) > 1 else None,
        'load15': load[2] if len(load) > 2 else None,
        'uptime': uptime,
        'hostname': (blocks.get('host', '') or '').strip().splitlines()[0] if blocks.get('host') else None,
        'docker_installed': (blocks.get('docker', '') or '').strip().lower().startswith('yes'),
        'docker_reachable': docker_ok,
        'docker_running': sum(1 for st in states if st.startswith('running')),
        'docker_total': len(states),
    }


def _pct(used, total) -> Optional[float]:
    if not total:
        return None
    return round(100.0 * float(used) / float(total), 2)


def _rates(host_key: str, raw: Dict[str, Any], now: float) -> Dict[str, Optional[float]]:
    """Turn cumulative counters into cpu % and bytes/second."""
    with _rate_lock:
        prev = _rate_cache.get(host_key)
        _rate_cache[host_key] = (now, raw['rx'], raw['tx'],
                                 raw['cpu_total'], raw['cpu_idle'])
    if not prev:
        return {'cpu_percent': None, 'rx_bps': None, 'tx_bps': None}
    elapsed = max(now - prev[0], 0.001)
    rx_bps = max(0.0, (raw['rx'] - prev[1])) / elapsed
    tx_bps = max(0.0, (raw['tx'] - prev[2])) / elapsed
    cpu_pct = None
    total_delta = raw['cpu_total'] - prev[3]
    idle_delta = raw['cpu_idle'] - prev[4]
    if total_delta > 0:
        cpu_pct = round(100.0 * (total_delta - idle_delta) / total_delta, 2)
    return {'cpu_percent': cpu_pct, 'rx_bps': rx_bps, 'tx_bps': tx_bps}


def system_snapshot(host: Dict[str, Any]) -> Dict[str, Any]:
    """One sample for a host dict from ``endpoints.resolve_host()``."""
    key = host.get('key')
    now = time.time()
    base = {
        'host_key': key,
        'name': host.get('friendly_name') or key,
        'ip': host.get('ip'),
        'ts': now,
    }
    try:
        ok, out = _run(host, build_command())
        if not ok:
            raise RuntimeError((out or 'command failed').strip()[:300])
        raw = parse_system(out)
        if not raw['mem_total'] and not raw['cpu_total']:
            raise RuntimeError('no /proc data returned')
        rates = _rates(key, raw, now)
    except Exception as exc:  # an unreachable host must not break the page
        base.update({'online': False, 'error': str(exc)[:300]})
        return base

    cores = 0
    try:
        cores = len([1 for line in out.splitlines() if line.startswith('cpu')])
    except Exception:
        cores = 0

    base.update({
        'online': True,
        'error': None,
        'hostname': raw['hostname'] or base['name'],
        'uptime': raw['uptime'],
        'docker_installed': raw['docker_installed'],
        'docker_reachable': raw['docker_reachable'],
        'docker_running': raw['docker_running'],
        'docker_total': raw['docker_total'],
        'cpu': {
            'percent': rates['cpu_percent'],
            'cores': max(cores - 1, 1) if cores else 1,
            'load1': raw['load1'], 'load5': raw['load5'], 'load15': raw['load15'],
        },
        'mem': {
            'used': raw['mem_used'],
            'total': raw['mem_total'],
            'percent': _pct(raw['mem_used'], raw['mem_total']),
            'swap_used': raw['swap_used'],
            'swap_total': raw['swap_total'],
        },
        'disk': {
            'used': raw['disk_used'],
            'total': raw['disk_total'],
            'percent': _pct(raw['disk_used'], raw['disk_total']),
            'mount': '/',
        },
        'net': {
            'rx': raw['rx'], 'tx': raw['tx'],
            'rx_bps': rates['rx_bps'], 'tx_bps': rates['tx_bps'],
        },
    })
    return base


# --------------------------------------------------------------------------
# containers
# --------------------------------------------------------------------------

def container_snapshot(host_key: str) -> Dict[str, Any]:
    """Containers on one host with the same four datapoints as the host.

    Docker CPU/memory/disk come straight from the existing collectors; the
    container network counters are cumulative, so they are turned into
    bytes/second here with a per-container delta cache.
    """
    try:
        from dockermon import routes as docker_routes
        snap = docker_routes.host_snapshot(host_key)
    except Exception as exc:
        return {'reachable': False, 'error': str(exc)[:300], 'containers': []}

    now = time.time()
    rows: List[Dict[str, Any]] = []
    with _container_rate_lock:
        for c in snap.get('containers') or []:
            cid = c.get('id') or c.get('short_id')
            rx = int(c.get('net_rx') or 0)
            tx = int(c.get('net_tx') or 0)
            rates = None
            cache_key = (host_key, cid)
            prev = _container_rate_cache.get(cache_key)
            _container_rate_cache[cache_key] = (now, rx, tx)
            if prev:
                elapsed = max(now - prev[0], 0.001)
                rates = {
                    'rx_bps': max(0.0, (rx - prev[1])) / elapsed,
                    'tx_bps': max(0.0, (tx - prev[2])) / elapsed,
                }
            mem_used = int(c.get('mem_used') or 0)
            mem_limit = int(c.get('mem_limit') or 0)
            rows.append({
                'id': cid,
                'name': c.get('name'),
                'image': c.get('image'),
                'state': c.get('state'),
                'status': c.get('status'),
                'stack': c.get('stack'),
                'service': c.get('service'),
                'cpu_percent': c.get('cpu_percent'),
                'cpu_cores': c.get('cpu_cores'),
                'mem_used': mem_used,
                'mem_limit': mem_limit,
                'mem_percent': (round(100.0 * mem_used / mem_limit, 2)
                                if mem_limit else None),
                'disk_used': c.get('size_rw'),
                'disk_rootfs': c.get('size_rootfs'),
                'net_rx': rx,
                'net_tx': tx,
                'net_rx_bps': (rates or {}).get('rx_bps'),
                'net_tx_bps': (rates or {}).get('tx_bps'),
            })

    rows.sort(key=lambda r: (str(r.get('state')).lower() != 'running',
                             -(r.get('cpu_percent') or 0),
                             str(r.get('name'))))
    return {
        'reachable': True,
        'error': None,
        'engine_version': (snap.get('stats') or {}).get('engine_version'),
        'containers': rows,
    }


def reset_caches() -> None:
    """Tests: forget every delta so the next sample is treated as a first."""
    with _rate_lock:
        _rate_cache.clear()
    with _container_rate_lock:
        _container_rate_cache.clear()
