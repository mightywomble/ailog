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
# Guards the *collection round*, not the cache.  It is deliberately separate
# from ``_lock`` so a request only ever holds the cache lock for an assignment:
# if a round is already in flight, everybody else is served the previous
# snapshot instead of queueing behind SSH.
_refresh_lock = threading.Lock()
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


def _netdata_round(hosts: List[Dict[str, Any]]):
    """Try one fleet query from Netdata.

    Returns ``(matched, extra, meta)`` where ``matched`` maps a host key to a
    ready snapshot, ``extra`` are Netdata-only nodes and ``meta`` describes the
    round. On any failure the caller falls back to SSH per host — a Netdata
    outage must never empty the Monitoring page.
    """
    try:
        from netdata import client, snapshot
        if not client.configured():
            return {}, [], None
        fleet = client.fleet_cards(after=-120, points=30)
    except Exception as exc:
        logger.debug('metrics: netdata round failed: %s', exc)
        return {}, [], None

    by_key = snapshot.match_nodes(fleet, hosts)
    matched = {key: snapshot.as_snapshot(host, node)
               for host in hosts
               for key in [host.get('key')]
               if (node := by_key.get(key))}
    extra = [snapshot.synthetic_host(node) for node in fleet.get('nodes') or []
             if client.resolve_host_key(node, hosts) is None]
    meta = {'source': 'netdata', 'nodes': len(fleet.get('nodes') or []),
            'ts': fleet.get('ts')}
    return matched, extra, meta


def collect_servers() -> Dict[str, Any]:
    """One round: Netdata for the fleet, SSH only for what it cannot see."""
    hosts = _host_list()
    results: List[Dict[str, Any]] = []
    matched, extra, netdata_meta = _netdata_round(hosts)

    def one(host):
        key = host.get('key')
        if key in matched:
            snap = matched[key]
            snap['docker'] = _docker_block(snap)
            return snap
        snap = collect.system_snapshot(host)
        snap['docker'] = _docker_block(snap)
        return snap

    if hosts:
        with ThreadPoolExecutor(max_workers=min(SNAPSHOT_WORKERS, len(hosts))) as pool:
            results = list(pool.map(one, hosts))
    results.extend(extra)

    # Read last_seen before recording this round, so an offline host shows the
    # last time it *was* up instead of the moment we noticed it was down.
    seen = _last_seen_map()
    for snap in results:
        snap['last_seen'] = seen.get(str(snap.get('host_key') or ''))
    _note_online(results)

    results.sort(key=lambda s: (not s.get('online'), str(s.get('name')).lower()))
    payload = {'success': True, 'ts': time.time(), 'servers': results}
    if netdata_meta:
        payload['source'] = netdata_meta
    return payload


def servers_payload(force: bool = False) -> Dict[str, Any]:
    """Return a snapshot, never blocking a request behind a live SSH round.

    The old version held one lock for the whole collection, so with two open
    tabs (desktop + phone) request B waited for request A's SSH round to finish
    -- and ``/api/overview`` waits on this same function, so the dashboard, the
    healthcheck and every other page queued behind it.  If a host was slow to
    answer, that queue grew until the browser gave up.

    Now: a fresh cache is returned as-is; if a round is already running the
    caller gets the previous snapshot (stale-while-revalidate).  Only a cold
    start -- no snapshot at all -- waits for the collection, because there is
    nothing truthful to serve yet.
    """
    with _lock:
        cached = _cache['payload']
        cached_ts = _cache['ts']
    if cached is not None and not force and (time.time() - cached_ts) < SNAPSHOT_TTL:
        return cached

    # ``blocking=cached is None``: join an in-flight round only when we have
    # nothing to serve.
    if not _refresh_lock.acquire(blocking=cached is None):
        return cached
    try:
        # Re-check: a round may have completed while we waited for the lock.
        with _lock:
            if _cache['payload'] is not None and not force and \
                    (time.time() - _cache['ts']) < SNAPSHOT_TTL:
                return _cache['payload']
        payload = collect_servers()
        with _lock:
            _cache['ts'] = time.time()
            _cache['payload'] = payload
        return payload
    finally:
        _refresh_lock.release()


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
    try:
        from netdata import snapshot
        if snapshot.is_netdata_key(host_key):
            return jsonify({'success': True, 'host_key': host_key, 'ts': time.time(),
                            'reachable': False, 'containers': [],
                            'error': 'Netdata-only node: containers are not collected without SSH'})
    except Exception:
        pass
    data = collect.container_snapshot(host_key)
    return jsonify({'success': True, 'host_key': host_key,
                    'ts': time.time(), **data})
