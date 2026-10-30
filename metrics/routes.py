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

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List

from flask import Blueprint, jsonify, render_template, request

from . import collect

metrics_bp = Blueprint('metrics', __name__)

logger = logging.getLogger(__name__)

# Collapse the burst of requests a page load (or several open tabs) produces
# into one collection round per interval.
SNAPSHOT_TTL = 1.5
SNAPSHOT_WORKERS = 8

# "Last online" comes from the hosts table, but a successful probe is itself
# evidence that a host is up, so the collector refreshes ``Host.last_seen``.
# Every host answers at most once a minute: plenty for a card that shows hours
# or days, and no write amplification from a two-second poll.
LAST_SEEN_WRITE_INTERVAL = 60

_lock = threading.Lock()
_cache: Dict[str, Any] = {'ts': 0.0, 'payload': None}

_seen_lock = threading.Lock()
_seen_written: Dict[str, float] = {}


def _host_list() -> List[Dict[str, Any]]:
    from dockermon import endpoints as ep
    out = []
    for key in ep.all_host_keys():
        host = ep.resolve_host(key)
        if host:
            out.append(host)
    return out


def _docker_block(snap: Dict[str, Any]) -> Dict[str, Any]:
    """Docker presence for the card badge, plus container counts.

    All three facts come from the same SSH round trip as the system stats, so
    the badge cannot disagree with the expansion (and does not depend on a
    Docker discovery pass having run recently).
    """
    installed = bool(snap.get('docker_installed'))
    reachable = bool(snap.get('docker_reachable')) and installed
    return {
        'installed': installed,
        'reachable': reachable,
        'containers_running': int(snap.get('docker_running') or 0) if reachable else 0,
        'containers_total': int(snap.get('docker_total') or 0) if reachable else 0,
        'engine_version': None,
    }


def _last_seen_map() -> Dict[str, Any]:
    """``{'db-<id>': iso8601 | None}`` for every host we have a record for.

    Config-file hosts (``hosts.json``) and ``local`` have no row, so they get
    no ``last_seen`` and the dashboard says so rather than inventing a time.
    """
    try:
        from database import Host
        out = {
            f'db-{h.id}': h.last_seen.isoformat() if h.last_seen else None
            for h in Host.query.all()
        }
    except Exception:  # a metrics round must never fail over a badge
        logger.debug('metrics: could not read last_seen', exc_info=True)
        return {}

    # A host with no recorded probe may still have a stored report; producing
    # one means the box answered at that moment, so the newest report is a
    # truthful "last seen" rather than an empty badge on day one.
    try:
        from sqlalchemy import func
        from database import LogReport
        latest = (LogReport.query
                  .with_entities(LogReport.host_key, func.max(LogReport.created_at))
                  .group_by(LogReport.host_key)
                  .all())
        for key, when in latest:
            if when and key in out and not out[key]:
                out[key] = when.isoformat()
    except Exception:
        logger.debug('metrics: could not read report times', exc_info=True)
    return out


def _note_online(results: List[Dict[str, Any]]) -> None:
    """Persist ``Host.last_seen`` for hosts that just answered, throttled."""
    now = time.time()
    due: List[int] = []
    with _seen_lock:
        for snap in results:
            key = str(snap.get('host_key') or '')
            if not key.startswith('db-') or snap.get('online') is not True:
                continue
            if now - _seen_written.get(key, 0.0) < LAST_SEEN_WRITE_INTERVAL:
                continue
            _seen_written[key] = now
            try:
                due.append(int(key[3:]))
            except ValueError:
                continue
    if not due:
        return

    from core.timeutil import utcnow
    try:
        from database import Host, db
        seen = utcnow()
        for host in Host.query.filter(Host.id.in_(due)).all():
            host.last_seen = seen
        db.session.commit()
    except Exception:
        logger.warning('metrics: could not record last_seen', exc_info=True)
        try:
            from database import db
            db.session.rollback()
        except Exception:
            pass


def collect_servers() -> Dict[str, Any]:
    """One round: every host in parallel, system stats for each."""
    hosts = _host_list()
    results: List[Dict[str, Any]] = []

    def one(host):
        snap = collect.system_snapshot(host)
        snap['docker'] = _docker_block(snap)
        return snap

    if hosts:
        with ThreadPoolExecutor(max_workers=min(SNAPSHOT_WORKERS, len(hosts))) as pool:
            results = list(pool.map(one, hosts))

    # Read last_seen before recording this round, so an offline host shows the
    # last time it *was* up instead of the moment we noticed it was down.
    seen = _last_seen_map()
    for snap in results:
        snap['last_seen'] = seen.get(str(snap.get('host_key') or ''))
    _note_online(results)

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
