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

import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from flask import Blueprint, current_app, jsonify, render_template, request

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

# Docker presence over SSH, remembered per host.
#
# Netdata answers "is Docker here?" only where its Docker plugin is enabled, so
# on this fleet most nodes came back with docker_installed=False and lost the
# badge. The old SSH sample knew the answer, but running the whole sample again
# just for a badge would undo the Netdata win. Instead: probe presence alone
# (two tiny commands), keep it for a few minutes, and serve the last answer
# instantly. Presence changes when someone installs Docker, not every 2s.
DOCKER_PROBE_INTERVAL = 300.0   # seconds between probes of one host
DOCKER_PROBE_START_GAP = 20.0   # don't start rounds more often than this
_docker_lock = threading.Lock()
_docker_known: Dict[str, Dict[str, Any]] = {}
_docker_probing = False
_docker_round_started = 0.0


def _host_list() -> List[Dict[str, Any]]:
    from dockermon import endpoints as ep
    out = []
    for key in ep.all_host_keys():
        host = ep.resolve_host(key)
        if host:
            out.append(host)
    return out


def _app_object() -> Any:
    """The live Flask app, or None when called outside a request.

    Worker threads do not inherit a Flask app context (it is thread-local), and
    SSH key materialisation needs one -- without this every threaded SSH call
    failed with "could not materialize key ... Working outside of application
    context" and then "Permission denied (publickey)".
    """
    try:
        return current_app._get_current_object()
    except Exception:
        return None


# The probe result outlives the process: without this every deploy blanked the
# Docker marks for the minute it takes to SSH every host again.
DOCKER_STATE_KEY = 'metrics.docker_presence'
_docker_loaded = False


def _load_docker_state() -> None:
    global _docker_loaded
    with _docker_lock:
        if _docker_loaded:
            return
        _docker_loaded = True
    try:
        from database import AppSetting
        row = AppSetting.query.get(DOCKER_STATE_KEY)
        state = json.loads(row.value_json) if row and row.value_json else {}
        if isinstance(state, dict):
            with _docker_lock:
                for key, rec in state.items():
                    if isinstance(rec, dict) and key not in _docker_known:
                        _docker_known[key] = rec
    except Exception:
        logger.debug('metrics: could not load docker presence', exc_info=True)


def _save_docker_state() -> None:
    try:
        from database import AppSetting, db
        with _docker_lock:
            state = dict(_docker_known)
        row = AppSetting.query.get(DOCKER_STATE_KEY)
        payload = json.dumps(state)
        if row is None:
            db.session.add(AppSetting(key=DOCKER_STATE_KEY, value_json=payload))
        elif row.value_json != payload:
            row.value_json = payload
        else:
            return
        db.session.commit()
    except Exception:
        logger.debug('metrics: could not save docker presence', exc_info=True)
        try:
            from database import db
            db.session.rollback()
        except Exception:
            pass


def _remember_docker(host_key: str, facts: Dict[str, Any]) -> None:
    if not host_key or not facts:
        return
    record = dict(facts)
    record['ts'] = time.time()
    with _docker_lock:
        previous = _docker_known.get(host_key) or {}
        _docker_known[host_key] = record
    if (previous.get('installed'), previous.get('running')) != (record['installed'], record['running']):
        _save_docker_state()


def _known_docker(host_key: str) -> Optional[Dict[str, Any]]:
    _load_docker_state()
    with _docker_lock:
        return _docker_known.get(host_key)


def _probe_one(app_obj: Any, host: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if app_obj is None:
        return collect.docker_facts(host)
    with app_obj.app_context():
        return collect.docker_facts(host)


def _docker_probe_round(hosts: List[Dict[str, Any]], app_obj: Any = None) -> None:
    """SSH-probe Docker presence for hosts whose answer is stale.

    Runs in a daemon thread: a slow or unreachable box costs a background
    thread, never a request. Failures leave the previous answer in place.
    """
    global _docker_probing, _docker_round_started
    now = time.time()
    with _docker_lock:
        if _docker_probing or (now - _docker_round_started) < DOCKER_PROBE_START_GAP:
            return
        _docker_probing = True
        _docker_round_started = now
    try:
        due = []
        for host in hosts:
            key = str(host.get('key') or '')
            if not key or key.startswith('nd:'):
                continue
            rec = _known_docker(key)
            if rec and (now - rec.get('ts', 0)) < DOCKER_PROBE_INTERVAL:
                continue
            due.append(host)
        if not due:
            return
        def collect_due():
            with ThreadPoolExecutor(max_workers=min(SNAPSHOT_WORKERS, len(due))) as pool:
                for host, facts in zip(due, pool.map(lambda h: _probe_one(app_obj, h), due)):
                    if facts:
                        # remembering also persists, and that needs the app context
                        # on *this* thread, not just inside the workers
                        _remember_docker(str(host.get('key') or ''), facts)

        if app_obj is None:
            collect_due()
        else:
            with app_obj.app_context():
                collect_due()
    except Exception:
        logger.debug('metrics: docker probe round failed', exc_info=True)
    finally:
        with _docker_lock:
            _docker_probing = False


def _maybe_probe_docker(hosts: List[Dict[str, Any]]) -> None:
    """Kick a probe round without blocking the caller."""
    now = time.time()
    with _docker_lock:
        if _docker_probing or (now - _docker_round_started) < DOCKER_PROBE_START_GAP:
            return
        fresh = all(
            (_docker_known.get(str(h.get('key') or ''), {}).get('ts', 0) or 0) > now - DOCKER_PROBE_INTERVAL
            for h in hosts
            if h.get('key') and not str(h.get('key')).startswith('nd:')
        )
    if fresh:
        return
    threading.Thread(target=_docker_probe_round, args=(list(hosts), _app_object()),
                     daemon=True).start()


def _docker_block(snap: Dict[str, Any]) -> Dict[str, Any]:
    """Docker presence for the card badge, plus container counts.

    A snapshot that sampled Docker itself (SSH) wins; otherwise the remembered
    SSH probe answers, so a Netdata-only node still shows its Docker mark.
    """
    installed = bool(snap.get('docker_installed'))
    reachable = bool(snap.get('docker_reachable')) and installed
    running = int(snap.get('docker_running') or 0)
    total = int(snap.get('docker_total') or 0)
    if not installed:
        known = _known_docker(str(snap.get('host_key') or ''))
        if known:
            installed = bool(known.get('installed'))
            reachable = bool(known.get('reachable')) and installed
            running = int(known.get('running') or 0)
            total = int(known.get('total') or 0)
    return {
        'installed': installed,
        'reachable': reachable,
        'containers_running': running if reachable else 0,
        'containers_total': total if reachable else 0,
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
    # Prime the remembered answers (and the persisted copy) before the pool
    # threads start, so a restart keeps its Docker marks.
    _load_docker_state()
    # Keep Docker presence warm in the background; never waits for SSH.
    _maybe_probe_docker(hosts)
    matched, extra, netdata_meta = _netdata_round(hosts)

    flask_app = _app_object()

    def one(host):
        # The pool threads have no app context of their own; SSH needs one.
        if flask_app is None:
            return one_inner(host)
        with flask_app.app_context():
            return one_inner(host)

    def one_inner(host):
        key = host.get('key')
        if key in matched:
            snap = matched[key]
            snap['docker'] = _docker_block(snap)
            return snap
        snap = collect.system_snapshot(host)
        # This sample asked the host about Docker directly, so it is the best
        # answer we have: remember it and save the next probe a round trip.
        _remember_docker(str(key or ''), {
            'installed': bool(snap.get('docker_installed')),
            'reachable': bool(snap.get('docker_reachable')),
            'running': int(snap.get('docker_running') or 0),
            'total': int(snap.get('docker_total') or 0),
        })
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
