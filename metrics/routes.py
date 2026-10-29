"""Monitoring page and its JSON API.

``/metrics`` renders a netdata-style grid: one card per host with CPU, RAM,
disk and network for the last few minutes, live.  Cards for hosts that have
Docker installed can be expanded to the same datapoints per container.

Polling, not SSE: the browser asks for ``/api/metrics/servers`` every couple of
seconds and the endpoint serves a short-lived cached snapshot, so N open views
cost the same as one.  The history the charts draw is kept in the browser,
which means no server-side storage and no per-view memory growth.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List

from flask import Blueprint, jsonify, render_template, request

from . import collect

metrics_bp = Blueprint('metrics', __name__)

# Collapse the burst of requests a page load (or several open tabs) produces
# into one collection round per interval.
SNAPSHOT_TTL = 1.5
SNAPSHOT_WORKERS = 8

_lock = threading.Lock()
_cache: Dict[str, Any] = {'ts': 0.0, 'payload': None}


def _host_list() -> List[Dict[str, Any]]:
    from dockermon import endpoints as ep
    out = []
    for key in ep.all_host_keys():
        host = ep.resolve_host(key)
        if host:
            out.append(host)
    return out


def _docker_block(host_key: str, online: bool, installed: bool) -> Dict[str, Any]:
    """Docker presence for the card badge, plus a container count."""
    block = {'installed': bool(installed), 'reachable': False,
             'containers_running': 0, 'containers_total': 0,
             'engine_version': None}
    if not installed or not online:
        return block
    try:
        from database import DockerEndpoint
        row = DockerEndpoint.query.filter_by(host_key=host_key).first()
        if row is not None:
            block['reachable'] = bool(getattr(row, 'is_reachable', False))
            block['engine_version'] = getattr(row, 'server_version', None)
    except Exception:
        pass
    return block


def collect_servers() -> Dict[str, Any]:
    """One round: every host in parallel, system stats for each."""
    hosts = _host_list()
    results: List[Dict[str, Any]] = []

    def one(host):
        snap = collect.system_snapshot(host)
        snap['docker'] = _docker_block(snap.get('host_key'),
                                       bool(snap.get('online')),
                                       bool(snap.get('docker_installed')))
        return snap

    if hosts:
        with ThreadPoolExecutor(max_workers=min(SNAPSHOT_WORKERS, len(hosts))) as pool:
            results = list(pool.map(one, hosts))

    results.sort(key=lambda s: (not s.get('online'), str(s.get('name')).lower()))
    return {'success': True, 'ts': time.time(), 'servers': results}


def servers_payload(force: bool = False) -> Dict[str, Any]:
    now = time.time()
    with _lock:
        if not force and _cache['payload'] and (now - _cache['ts']) < SNAPSHOT_TTL:
            return _cache['payload']
        payload = collect_servers()
        _cache['ts'] = time.time()
        _cache['payload'] = payload
        return payload


@metrics_bp.get('/metrics')
def metrics_page():
    embedded = request.args.get('embed') == '1'
    return render_template('metrics.html', embedded=embedded)


@metrics_bp.get('/api/metrics/servers')
def api_servers():
    force = request.args.get('refresh') == '1'
    return jsonify(servers_payload(force=force))


@metrics_bp.get('/api/metrics/containers')
def api_containers():
    host_key = request.args.get('host')
    if not host_key:
        return jsonify({'success': False, 'error': 'host is required'}), 400
    data = collect.container_snapshot(host_key)
    return jsonify({'success': True, 'host_key': host_key,
                    'ts': time.time(), **data})
