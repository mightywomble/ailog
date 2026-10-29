"""Swarm cluster view: master -> nodes, grouped per app (stack).

This is the part of dockervision that ailog did not have. ailog already knew
how to talk to a host and how to list its containers, but it had no idea that
a swarm is a tree of machines, and no way to answer "how much CPU is the
sonarr stack using across the cluster?".

Everything is collected over SSH from the manager: ``docker node ls`` gives
the topology, ``docker node inspect`` gives each node's address, and each node
then answers one combined command (containers + stats + disk + /proc) so a
cluster of N machines costs N+1 SSH round trips per refresh, not N*4.

The result is cached briefly (``AILOG_DOCKER_SWARM_TTL``, default 10s) because
the page polls it and a page load also asks for containers and stats.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

from . import history as hist
from . import sshstats
from .parse import aggregate_apps, downsample, finalize_apps

log = logging.getLogger(__name__)

NODE_WORKERS = 6
FAILURE_GRACE = 3  # consecutive misses before a node's ring buffer forgets it

_lock = threading.Lock()
_cluster_cache: dict[str, tuple[float, dict]] = {}
_addr_cache: dict[tuple[str, str], tuple[float, str]] = {}

# (host_key, hostname) -> {metric: deque}
_node_hist: dict[tuple[str, str], dict[str, deque]] = {}
# host_key -> app name -> {metric: deque}
_app_hist: dict[str, dict[str, dict[str, deque]]] = {}
_miss: dict[tuple[str, str], int] = {}

NODE_HIST_KEYS = ('cpu', 'mem_pct', 'net_rx', 'net_tx')


def _env_int(name, default, minimum=1):
    try:
        return max(minimum, int(os.environ.get(name, '') or default))
    except (TypeError, ValueError):
        return default


def ttl_seconds():
    return _env_int('AILOG_DOCKER_SWARM_TTL', 10)


def _norm_nodes(rows):
    """Normalise node rows to one shape regardless of transport.

    sshstats/parse_node_line yields {id, hostname, status, availability,
    manager}; the SDK yields {role, state, addr, ...}.
    """
    out = []
    for row in rows or []:
        node = dict(row)
        manager = (node.get('manager') or '').strip().lower()
        if not node.get('role'):
            node['role'] = ('manager'
                            if manager.startswith(('leader', 'reachable'))
                            else 'worker')
        if not node.get('state'):
            node['state'] = node.get('status') or ('ready' if manager else 'unknown')
        node.setdefault('addr', '')
        node.setdefault('availability', '')
        node.setdefault('engine_version', '')
        out.append(node)
    return out


def node_address(host_key, info, node_id, fallback='', max_age=600):
    """Resolve a node's SSH address, cached for ``max_age`` seconds."""
    key = (host_key, node_id)
    now = time.time()
    with _lock:
        hit = _addr_cache.get(key)
        if hit and now - hit[0] < max_age:
            return hit[1]
    addr = ''
    try:
        addr = sshstats.node_addr(
            info.get('user') or 'root', info.get('ip'), info.get('ssh_key_id'),
            node_id=node_id, timeout=8)
    except Exception as exc:
        log.debug('[dockermon] node inspect failed for %s: %s', node_id, exc)
    addr = addr or fallback or ''
    if addr:
        with _lock:
            _addr_cache[key] = (now, addr)
    return addr


def _spark(buffers, limit=hist.MAX_SERIES_POINTS):
    return {key: downsample(list(values), limit)
            for key, values in buffers.items()}


def _remember_node(host_key, hostname, metrics):
    with _lock:
        buffers = _node_hist.get((host_key, hostname))
        if buffers is None:
            size = hist.capacity()
            buffers = {key: deque(maxlen=size) for key in NODE_HIST_KEYS}
            _node_hist[(host_key, hostname)] = buffers
        buffers['cpu'].append(metrics.get('cpu_pct'))
        buffers['mem_pct'].append(metrics.get('mem_pct'))
        buffers['net_rx'].append(metrics.get('net_rx_bps'))
        buffers['net_tx'].append(metrics.get('net_tx_bps'))
        _miss[(host_key, hostname)] = 0
        return _spark(buffers)


def _remember_apps(host_key, apps):
    with _lock:
        store = _app_hist.setdefault(host_key, {})
        size = hist.capacity()
        for app in apps:
            buffers = store.get(app['name'])
            if buffers is None:
                buffers = {key: deque(maxlen=size) for key in hist.APP_KEYS}
                store[app['name']] = buffers
            buffers['cpu'].append(app.get('cpu_pct') or 0.0)
            buffers['mem_used'].append(app.get('mem_used') or 0.0)
            buffers['net_rx'].append(app.get('net_rx') or 0.0)
            buffers['net_tx'].append(app.get('net_tx') or 0.0)
        for name in list(store):
            if name in {a['name'] for a in apps}:
                continue
            store.pop(name, None)
        return {name: _spark(buf) for name, buf in store.items()}


def build(host_key, nodes, payloads, ts=None, errors=None):
    """Assemble the cluster view from per-node collections (pure)."""
    ts = ts or time.time()
    errors = errors or {}
    node_rows = []
    all_containers = []

    for node in nodes:
        hostname = node.get('hostname') or node.get('addr') or node.get('id')
        payload = payloads.get(node.get('id')) or {}
        metrics = payload.get('metrics') or {}
        containers = payload.get('containers') or []
        for container in containers:
            container['node'] = hostname
        all_containers.extend(containers)

        online = bool(payload)
        if online:
            spark = _remember_node(host_key, hostname, metrics)
        else:
            with _lock:
                buffers = _node_hist.get((host_key, hostname))
                spark = _spark(buffers) if buffers else {k: [] for k in NODE_HIST_KEYS}

        node_rows.append({
            'id': node.get('id'),
            'hostname': hostname,
            'role': node.get('role'),
            'state': node.get('state'),
            'availability': node.get('availability'),
            'manager': node.get('manager'),
            'addr': node.get('addr') or payload.get('addr') or '',
            'online': online,
            'error': errors.get(node.get('id')),
            'metrics': metrics,
            'docker_df': payload.get('docker_df') or {},
            'container_count': len(containers),
            'spark': spark,
        })

    apps = finalize_apps(aggregate_apps(all_containers))
    app_spark = _remember_apps(host_key, apps)

    online_nodes = [n for n in node_rows if n['online']]
    cores = sum((n['metrics'].get('cores') or 0) for n in online_nodes)
    cpu_busy = sum(((n['metrics'].get('cpu_pct') or 0.0) / 100.0
                    * (n['metrics'].get('cores') or 0)) for n in online_nodes)
    mem_used = sum((n['metrics'].get('mem_used') or 0) for n in online_nodes)
    mem_total = sum((n['metrics'].get('mem_total') or 0) for n in online_nodes)
    disk_used = sum((n['metrics'].get('disk_used') or 0) for n in online_nodes)
    disk_total = sum((n['metrics'].get('disk_total') or 0) for n in online_nodes)
    net_rx = sum((n['metrics'].get('net_rx_bps') or 0) for n in online_nodes)
    net_tx = sum((n['metrics'].get('net_tx_bps') or 0) for n in online_nodes)

    totals = {
        'nodes_total': len(node_rows),
        'nodes_online': len(online_nodes),
        'managers': sum(1 for n in node_rows
                        if (n.get('role') or '').lower() == 'manager'),
        'cores': cores,
        'cpu_pct': round(100.0 * cpu_busy / cores, 2) if cores else None,
        'cpu_cores_used': round(cpu_busy, 2),
        'mem_used': mem_used,
        'mem_total': mem_total,
        'mem_pct': round(100.0 * mem_used / mem_total, 2) if mem_total else None,
        'disk_used': disk_used,
        'disk_total': disk_total,
        'disk_pct': round(100.0 * disk_used / disk_total, 2) if disk_total else None,
        'net_rx_bps': round(net_rx, 1),
        'net_tx_bps': round(net_tx, 1),
        'containers_total': len(all_containers),
        'containers_running': sum(1 for c in all_containers
                                  if (c.get('state') or '').lower() == 'running'),
        'apps_total': len(apps),
    }

    return {
        'host_key': host_key,
        'generated': ts,
        'nodes': node_rows,
        'apps': apps,
        'app_spark': app_spark,
        'totals': totals,
        'partial': bool(errors),
        'errors': [{'node': n.get('hostname'), 'error': errors[n.get('id')]}
                   for n in nodes if n.get('id') in errors],
    }


_DF_TYPES = (('Images', 'images'), ('Containers', 'containers'),
             ('Volumes', 'volumes'), ('BuildCache', 'build_cache'))


def _master_df(info, client=None):
    """`docker system df` for the manager, over whichever transport works."""
    if client is not None:
        try:
            raw = client.df() or {}
        except Exception as exc:
            log.debug('[dockermon] sdk df failed: %s', exc)
            raw = {}
        if raw:
            out = {}
            for source, key in _DF_TYPES:
                block = raw.get(source)
                if not isinstance(block, dict):
                    continue
                out[key] = {
                    'count': len(block.get('Items') or []),
                    'size': sum(float(item.get('Size') or 0)
                                for item in (block.get('Items') or [])),
                    'reclaimable': 0.0,
                }
            return out
    try:
        return sshstats.disk_usage(
            info.get('user') or 'root', info.get('ip'),
            ssh_key_id=info.get('ssh_key_id'), timeout=15)
    except Exception as exc:
        log.debug('[dockermon] system df failed on the manager: %s', exc)
        return {}


def _collect_node(host_key, info, node, master_ip, master_name):
    """Collect one node; the manager itself reuses the caller's snapshot."""
    hostname = node.get('hostname') or ''
    if (node.get('addr') and node['addr'] == master_ip) or \
            (hostname and hostname == master_name):
        return None  # handled by the caller with the master snapshot

    addr = node.get('addr') or node_address(
        host_key, info, node.get('id'), fallback=hostname)
    if not addr:
        raise RuntimeError('no address for node %s' % (hostname or node.get('id')))
    payload = sshstats.swarm_node_snapshot(
        host_key, hostname, info.get('user') or 'root', addr,
        ssh_key_id=info.get('ssh_key_id'),
        timeout=_env_int('AILOG_DOCKER_NODE_TIMEOUT', 25),
    )
    payload['addr'] = addr
    return payload


def cluster(host_key, info, master_snap=None, transport='ssh', client=None):
    """Build (or reuse a cached) cluster view for ``host_key``."""
    now = time.time()
    with _lock:
        hit = _cluster_cache.get(host_key)
        if hit and now - hit[0] < ttl_seconds():
            return hit[1]

    master_snap = master_snap or {}
    if transport == 'ssh':
        nodes = _norm_nodes(master_snap.get('nodes') or [])
    else:
        from . import stats as dstats
        nodes = _norm_nodes(dstats.swarm_nodes(client) if client else [])
    if not nodes:
        return {'host_key': host_key, 'swarm': False, 'nodes': [],
                'apps': [], 'app_spark': {}, 'totals': {}, 'partial': False,
                'errors': [], 'generated': now}

    stats = master_snap.get('stats') or {}
    master_ip = info.get('ip') or ''
    master_name = stats.get('node_name') or ''

    # The manager hosting this request is itself a node: reuse its snapshot
    # instead of SSHing to ourselves, which also covers the single-node swarm.
    master_containers = master_snap.get('containers')
    if master_containers is None and transport != 'ssh' and client is not None:
        from . import stats as dstats
        master_containers = dstats.collect_containers(client)

    payloads = {}
    errors = {}
    for node in nodes:
        hostname = node.get('hostname') or ''
        is_self = ((node.get('addr') and node['addr'] == master_ip)
                   or (hostname and hostname == master_name)
                   or (len(nodes) == 1 and not node.get('addr')))
        if is_self:
            payloads[node.get('id')] = {
                'metrics': {
                    'cpu_pct': stats.get('cpu_percent'),
                    'cores': stats.get('cpu_cores'),
                    'mem_used': stats.get('mem_used'),
                    'mem_total': stats.get('mem_total'),
                    'mem_pct': stats.get('mem_percent'),
                    'disk_used': stats.get('disk_used'),
                    'disk_total': stats.get('disk_total'),
                    'disk_pct': stats.get('disk_percent'),
                    'net_rx_bps': stats.get('net_rx_bps'),
                    'net_tx_bps': stats.get('net_tx_bps'),
                },
                'containers': master_containers or [],
                # The live snapshot does not run `docker system df` (it polls
                # every 2s), so the manager asks for it once per cluster build.
                'docker_df': _master_df(info, client),
            }

    remote = [n for n in nodes if n.get('id') not in payloads]
    if remote:
        with ThreadPoolExecutor(max_workers=NODE_WORKERS) as pool:
            futures = {
                pool.submit(_collect_node, host_key, info, node,
                            master_ip, master_name): node
                for node in remote
            }
            for future, node in futures.items():
                try:
                    payload = future.result()
                except Exception as exc:
                    errors[node.get('id')] = str(exc)
                    log.debug('[dockermon] node %s failed: %s',
                              node.get('hostname'), exc)
                    continue
                if payload:
                    payloads[node.get('id')] = payload

    view = build(host_key, nodes, payloads, ts=time.time(), errors=errors)
    view['swarm'] = True
    view['master'] = {'host_key': host_key,
                      'name': info.get('friendly_name') or master_name,
                      'ip': master_ip}

    if view['totals'].get('nodes_online'):
        with _lock:
            _cluster_cache[host_key] = (time.time(), view)
    return view


def single_host(host_key, info, snap):
    """App grouping for a host that is not a swarm manager.

    The Apps view should not disappear just because a host runs plain
    containers: grouping by stack label still says something useful, and the
    card layout stays identical.
    """
    stats = (snap or {}).get('stats') or {}
    name = stats.get('node_name') or info.get('friendly_name') or host_key
    node = {
        'id': stats.get('node_name') or host_key,
        'hostname': name,
        'role': 'standalone',
        'state': 'ready',
        'availability': '',
        'addr': info.get('ip'),
        'manager': None,
    }
    payloads = {node['id']: {
        'metrics': {
            'cpu_pct': stats.get('cpu_percent'),
            'cores': stats.get('cpu_cores'),
            'mem_used': stats.get('mem_used'),
            'mem_total': stats.get('mem_total'),
            'mem_pct': stats.get('mem_percent'),
            'disk_used': stats.get('disk_used'),
            'disk_total': stats.get('disk_total'),
            'disk_pct': stats.get('disk_percent'),
            'net_rx_bps': stats.get('net_rx_bps'),
            'net_tx_bps': stats.get('net_tx_bps'),
        },
        'containers': (snap or {}).get('containers') or [],
        'docker_df': _master_df(info),
    }}
    view = build(host_key, [node], payloads, ts=time.time())
    view['swarm'] = False
    return view


def clear(host_key=None):
    with _lock:
        if host_key:
            _cluster_cache.pop(host_key, None)
        else:
            _cluster_cache.clear()
            _node_hist.clear()
            _app_hist.clear()
            _addr_cache.clear()
