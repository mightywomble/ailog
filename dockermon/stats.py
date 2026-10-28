"""Live Docker statistics aggregation for ailog's Docker monitoring page.

Everything here is *pull-based and ephemeral*: no history is persisted. The
browser polls the JSON endpoints every couple of seconds and keeps its own
rolling window for the charts.

The helpers work against a ``docker`` Python SDK client (``DockerClient``) and
are deliberately tolerant: a single misbehaving container should never take
down the whole statistics response.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor


_rate_lock = threading.Lock()
# host_key -> (timestamp, rx_bytes, tx_bytes)
_rate_cache: dict[str, tuple[float, int, int]] = {}


def _as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _round(value, digits=2):
    if value is None:
        return None
    try:
        return round(float(value), digits)
    except (TypeError, ValueError):
        return None


def _cpu_percent(raw: dict) -> float | None:
    """CPU percentage from a raw ``/containers/{id}/stats`` document."""
    try:
        cpu = raw.get('cpu_stats') or {}
        pre = raw.get('precpu_stats') or {}
        cpu_usage = cpu.get('cpu_usage') or {}
        pre_usage = pre.get('cpu_usage') or {}
        cpu_delta = _as_int(cpu_usage.get('total_usage')) - _as_int(pre_usage.get('total_usage'))
        system_delta = _as_int(cpu.get('system_cpu_usage')) - _as_int(pre.get('system_cpu_usage'))
        online = _as_int(cpu.get('online_cpus')) or len(cpu_usage.get('percpu_usage') or []) or 1
        if cpu_delta <= 0 or system_delta <= 0:
            return 0.0
        return round((cpu_delta / system_delta) * online * 100.0, 2)
    except Exception:
        return None


def _mem(raw: dict) -> tuple[int, int, float | None]:
    mem = raw.get('memory_stats') or {}
    used = _as_int(mem.get('usage'))
    limit = _as_int(mem.get('limit'))
    cache = _as_int((mem.get('stats') or {}).get('cache'))
    if used and cache and used > cache:
        used -= cache
    pct = round(100.0 * used / limit, 2) if limit else None
    return used, limit, pct


def _net(raw: dict) -> tuple[int, int]:
    rx = tx = 0
    for iface in (raw.get('networks') or {}).values():
        rx += _as_int(iface.get('rx_bytes'))
        tx += _as_int(iface.get('tx_bytes'))
    return rx, tx


def container_stats(client, container_id: str) -> dict:
    """Fetch a single container's live stats (one-shot, non-streaming)."""
    info = {'id': container_id, 'cpu_percent': None, 'mem_used': 0, 'mem_limit': 0,
            'mem_percent': None, 'net_rx': 0, 'net_tx': 0, 'pids': None}
    try:
        raw = client.api.stats(container_id, stream=False, one_shot=True)
    except Exception as exc:  # container vanished / permission issue
        info['error'] = str(exc)
        return info
    if not isinstance(raw, dict):
        info['error'] = 'unexpected stats payload'
        return info
    used, limit, pct = _mem(raw)
    rx, tx = _net(raw)
    info.update({
        'cpu_percent': _cpu_percent(raw),
        'mem_used': used,
        'mem_limit': limit,
        'mem_percent': pct,
        'net_rx': rx,
        'net_tx': tx,
        'pids': _as_int((raw.get('pids_stats') or {}).get('current'), None),
    })
    return info


def _container_row(c) -> dict:
    labels = (c.attrs or {}).get('Labels') or {}
    return {
        'id': c.id,
        'short_id': (c.id or '')[:12],
        'name': (c.name or '').lstrip('/'),
        'image': c.image.tags[0].split(':')[0] if c.image and c.image.tags else (c.image.short_id if c.image else ''),
        'image_tag': c.image.tags[0].split(':')[-1] if c.image and c.image.tags else 'latest',
        'image_tags': list(c.image.tags) if c.image else [],
        'state': c.status,
        'status': c.status,
        'stack': labels.get('com.docker.stack.namespace'),
        'service': labels.get('com.docker.swarm.service.name'),
        'task_id': labels.get('com.docker.swarm.task.id'),
        'node_id': labels.get('com.docker.swarm.node.id'),
        'created': (c.attrs or {}).get('Created'),
    }


def collect_containers(client, stats_limit: int = 60, workers: int = 8) -> list[dict]:
    """All containers on the node (including stopped ones) with live stats."""
    try:
        containers = client.containers.list(all=True)
    except Exception:
        return []
    rows = [_container_row(c) for c in containers]
    running = [r for r in rows if (r.get('state') or '').lower() == 'running'][:stats_limit]
    if running:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(lambda r: container_stats(client, r['id']), running))
        by_id = {s['id']: s for s in results}
        for row in rows:
            stat = by_id.get(row['id'])
            if stat:
                row.update({k: stat.get(k) for k in
                            ('cpu_percent', 'mem_used', 'mem_limit', 'mem_percent',
                             'net_rx', 'net_tx', 'pids')})
    return rows


def collect_totals(client, containers: list[dict] | None = None) -> dict:
    """Aggregate live CPU/RAM/network usage for a Docker node.

    Network is summed across containers and converted to bytes/second using the
    delta against the previous poll for the same host.
    """
    try:
        info = client.info() or {}
    except Exception:
        info = {}
    cores = _as_int(info.get('NCPU'), 1) or 1
    mem_total = _as_int(info.get('MemTotal'))

    if containers is None:
        containers = collect_containers(client)
    running = [c for c in containers if (c.get('state') or '').lower() == 'running']

    cores_used = 0.0
    mem_used = 0
    mem_limit = 0
    rx_total = tx_total = 0
    for c in running:
        cpu = c.get('cpu_percent')
        if cpu:
            cores_used += float(cpu) * cores / 100.0
        mem_used += _as_int(c.get('mem_used'))
        mem_limit += _as_int(c.get('mem_limit'))
        rx_total += _as_int(c.get('net_rx'))
        tx_total += _as_int(c.get('net_tx'))

    cpu_pct = round(cores_used / cores * 100.0, 2) if cores else None
    limit = mem_total or mem_limit
    mem_pct = round(100.0 * mem_used / limit, 2) if limit else None

    now = time.time()
    key = info.get('ID') or info.get('Name') or 'node'
    with _rate_lock:
        prev = _rate_cache.get(key)
        _rate_cache[key] = (now, rx_total, tx_total)
    if prev:
        elapsed = max(now - prev[0], 0.001)
        rx_bps = max(0, (rx_total - prev[1])) / elapsed
        tx_bps = max(0, (tx_total - prev[2])) / elapsed
    else:
        rx_bps = tx_bps = 0.0

    return {
        'cpu_percent': cpu_pct,
        'cpu_cores': cores,
        'cpu_cores_used': round(cores_used, 2),
        'mem_used': mem_used,
        'mem_total': limit,
        'mem_percent': mem_pct,
        'net_rx': rx_total,
        'net_tx': tx_total,
        'net_rx_bps': round(rx_bps, 1),
        'net_tx_bps': round(tx_bps, 1),
        'containers_total': len(containers),
        'containers_running': len(running),
        'swarm': bool(info.get('Swarm') and (info.get('Swarm') or {}).get('LocalNodeState') == 'active'),
        'engine_version': info.get('ServerVersion'),
        'node_name': info.get('Name'),
        'images': _as_int(info.get('Images')),
        'ts': now,
    }


def node_info(client) -> dict:
    """Lightweight engine + swarm description for the page header."""
    out = {'engine': {}, 'swarm': None}
    try:
        info = client.info() or {}
    except Exception as exc:
        out['error'] = str(exc)
        return out
    out['engine'] = {
        'name': info.get('Name'),
        'server_version': info.get('ServerVersion'),
        'os': info.get('OperatingSystem'),
        'kernel': info.get('KernelVersion'),
        'arch': info.get('Architecture'),
        'cpus': info.get('NCPU'),
        'memory': info.get('MemTotal'),
        'containers': info.get('Containers'),
        'containers_running': info.get('ContainersRunning'),
        'images': info.get('Images'),
        'driver': info.get('Driver'),
    }
    swarm = info.get('Swarm') or {}
    if swarm.get('LocalNodeState') == 'active':
        out['swarm'] = {
            'local_node_state': swarm.get('LocalNodeState'),
            'control_available': swarm.get('ControlAvailable'),
            'node_id': swarm.get('NodeID'),
            'nodes': swarm.get('Nodes'),
            'managers': swarm.get('Managers'),
            'cluster': (swarm.get('Cluster') or {}).get('ID'),
        }
    return out


def swarm_nodes(client) -> list[dict]:
    """Cluster-wide node list (only meaningful on a swarm manager)."""
    try:
        nodes = client.nodes.list()
    except Exception:
        return []
    out = []
    for n in nodes:
        attrs = n.attrs or {}
        status = attrs.get('Status') or {}
        spec = attrs.get('Spec') or {}
        out.append({
            'id': n.id,
            'hostname': (spec.get('Annotations') or {}).get('hostname') or status.get('Addr'),
            'role': (spec.get('Role') or '').lower(),
            'state': status.get('State'),
            'availability': (spec.get('Availability') or '').lower(),
            'addr': status.get('Addr'),
            'version': (attrs.get('Version') or {}).get('Index'),
            'engine_version': ((attrs.get('Description') or {}).get('Engine') or {}).get('EngineVersion'),
            'cpus': ((attrs.get('Description') or {}).get('Resources') or {}).get('NanoCPUs', 0) / 1e9,
            'memory': ((attrs.get('Description') or {}).get('Resources') or {}).get('MemoryBytes'),
        })
    return out
