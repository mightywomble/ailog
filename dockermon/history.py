"""Rolling in-memory history for the Docker page.

ailog's Docker page used to draw its charts purely from what the browser had
polled since it was opened, so a refresh threw the graph away and there was no
way to see what a host did ten minutes ago.  This module keeps a small ring
buffer per Docker host, filled by a background sampler, and serves it to the
page so charts survive reloads and the swarm/app views can show sparklines.

Deliberately **not** persisted: the buffers live in process memory and are
lost on restart.  Anything that needs to outlive the process belongs in the
report pipeline, not here.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

from .parse import aggregate_apps, downsample

log = logging.getLogger(__name__)

DEFAULT_INTERVAL = 15      # seconds between samples
DEFAULT_MINUTES = 60       # rolling window
MAX_SERIES_POINTS = 240    # points sent to the browser
SAMPLER_WORKERS = 4

HOST_KEYS = (
    'cpu', 'mem_pct', 'mem_used', 'mem_total',
    'disk_pct', 'disk_used', 'disk_total',
    'net_rx', 'net_tx',
    'containers_running', 'containers_total',
)
APP_KEYS = ('cpu', 'mem_used', 'net_rx', 'net_tx')

# How many consecutive samples an app may be missing before its series is
# dropped (a stack that has been removed from the swarm).
APP_GRACE = 20

_lock = threading.Lock()
_hosts: dict[str, dict[str, deque]] = {}
_apps: dict[str, dict[str, dict[str, deque]]] = {}
_app_miss: dict[str, dict[str, int]] = {}
_ts: dict[str, deque] = {}
_revision: dict[str, int] = {}

_started = False
_start_lock = threading.Lock()
_thread = None
_stop = threading.Event()


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------

def _setting(key, default):
    """Read a DB-backed setting without importing ``app`` (avoids a cycle)."""
    try:
        from flask import has_app_context
        from database import AppSetting
        if not has_app_context():
            return default
        row = AppSetting.query.get(key)
        if not row or row.value_json is None:
            return default
        import json
        return json.loads(row.value_json)
    except Exception:
        return default


def _env_int(name, default, minimum=1):
    try:
        return max(minimum, int(os.environ.get(name, '') or default))
    except (TypeError, ValueError):
        return default


def interval_seconds():
    """Sampling interval, in seconds (``docker.history_interval`` or env)."""
    value = _setting('docker.history_interval', None)
    if isinstance(value, (int, float)) and value >= 1:
        return int(value)
    return _env_int('AILOG_DOCKER_POLL_SECONDS', DEFAULT_INTERVAL)


def window_minutes():
    value = _setting('docker.history_minutes', None)
    if isinstance(value, (int, float)) and value >= 1:
        return int(value)
    return _env_int('AILOG_DOCKER_HISTORY_MINUTES', DEFAULT_MINUTES)


def _points():
    """How many samples fit in the configured window."""
    seconds = interval_seconds()
    return max(12, int(window_minutes() * 60 / max(seconds, 1)))


# --------------------------------------------------------------------------
# buffers
# --------------------------------------------------------------------------

def capacity():
    """How many samples a ring buffer holds (used by the swarm sparklines)."""
    return _points()


def _series_for(host_key):
    series = _hosts.get(host_key)
    if series is None:
        series = {key: deque(maxlen=_points()) for key in HOST_KEYS}
        _hosts[host_key] = series
        _ts[host_key] = deque(maxlen=_points())
        _revision[host_key] = 0
    return series


def record(host_key, stats, containers=None, ts=None):
    """Append one sample for ``host_key`` and its per-app series."""
    if not stats:
        return
    ts = float(ts if ts is not None else stats.get('ts') or time.time())
    values = {
        'cpu': stats.get('cpu_percent'),
        'mem_pct': stats.get('mem_percent'),
        'mem_used': stats.get('mem_used'),
        'mem_total': stats.get('mem_total'),
        'disk_pct': stats.get('disk_percent'),
        'disk_used': stats.get('disk_used'),
        'disk_total': stats.get('disk_total'),
        'net_rx': stats.get('net_rx_bps'),
        'net_tx': stats.get('net_tx_bps'),
        'containers_running': stats.get('containers_running'),
        'containers_total': stats.get('containers_total'),
    }

    with _lock:
        series = _series_for(host_key)
        for key, value in values.items():
            # keep the series aligned: a missing metric holds the last value
            if value is None:
                value = series[key][-1] if series[key] else None
            series[key].append(value)
        _ts[host_key].append(ts)
        _revision[host_key] = _revision.get(host_key, 0) + 1

        if containers is not None:
            apps = aggregate_apps(containers)
            app_series = _apps.setdefault(host_key, {})
            misses = _app_miss.setdefault(host_key, {})
            for name, app in apps.items():
                target = app_series.setdefault(
                    name, {key: deque(maxlen=_points()) for key in APP_KEYS})
                target['cpu'].append(app.get('cpu_pct') or 0.0)
                target['mem_used'].append(app.get('mem_used') or 0.0)
                target['net_rx'].append(app.get('net_rx') or 0.0)
                target['net_tx'].append(app.get('net_tx') or 0.0)
                misses[name] = 0
            for name in list(app_series):
                if name in apps:
                    continue
                misses[name] = misses.get(name, 0) + 1
                if misses[name] >= APP_GRACE:
                    app_series.pop(name, None)
                    misses.pop(name, None)


def series(host_key, limit=MAX_SERIES_POINTS):
    """Downsampled host series plus the timestamps they line up with."""
    with _lock:
        if host_key not in _hosts:
            return {'series': {}, 'timestamps': [], 'points': 0}
        host = _hosts[host_key]
        stamps = list(_ts.get(host_key) or [])
        out = {key: downsample([v for v in host[key]], limit)
               for key in HOST_KEYS}
    points = max((len(v) for v in out.values()), default=0)
    if stamps and points and len(stamps) > points:
        start = stamps[-points:]
    else:
        start = stamps
    return {'series': out, 'timestamps': start, 'points': points}


def app_series(host_key, limit=MAX_SERIES_POINTS):
    with _lock:
        apps = _apps.get(host_key) or {}
        return {
            name: {key: downsample(list(buffers[key]), limit)
                   for key in APP_KEYS}
            for name, buffers in apps.items()
        }


def revision(host_key):
    with _lock:
        return _revision.get(host_key, 0)


def payload(host_key):
    """Everything the page needs to draw history for one host."""
    data = series(host_key)
    return {
        'host_key': host_key,
        'interval': interval_seconds(),
        'window_minutes': window_minutes(),
        'revision': revision(host_key),
        'points': data['points'],
        'timestamps': data['timestamps'],
        'series': data['series'],
        'apps': app_series(host_key),
    }


def clear(host_key=None):
    with _lock:
        keys = [host_key] if host_key else list(_hosts)
        for key in keys:
            _hosts.pop(key, None)
            _apps.pop(key, None)
            _app_miss.pop(key, None)
            _ts.pop(key, None)
            _revision.pop(key, None)


def summary():
    with _lock:
        return {
            'hosts': len(_hosts),
            'interval': interval_seconds(),
            'window_minutes': window_minutes(),
            'points': _points(),
            'sampled': {key: len(_ts.get(key) or []) for key in _hosts},
        }


# --------------------------------------------------------------------------
# background sampler
# --------------------------------------------------------------------------

def _targets():
    """Hosts with a reachable Docker endpoint (i.e. discovery has seen them)."""
    try:
        from database import DockerEndpoint
        rows = DockerEndpoint.query.all()
    except Exception:
        return []
    return [row.host_key for row in rows if getattr(row, 'is_reachable', False)]


def _sample(app, host_key):
    """One collection, inside the captured app's context."""
    with app.app_context():
        from . import routes
        return routes.host_snapshot(host_key)


def _loop(app, interval=None):
    while not _stop.is_set():
        started = time.time()
        # Re-read every cycle so a settings change takes effect without a restart.
        wait = interval or interval_seconds()
        try:
            with app.app_context():
                keys = _targets()
            if keys:
                with ThreadPoolExecutor(max_workers=SAMPLER_WORKERS) as pool:
                    futures = {pool.submit(_sample, app, key): key
                               for key in keys}
                    for future, key in futures.items():
                        try:
                            snap = future.result()
                        except Exception as exc:  # a dead host is not fatal
                            log.debug('[dockermon] sample failed for %s: %s',
                                      key, exc)
                            continue
                        record(key, snap.get('stats'),
                               snap.get('containers'), snap.get('ts'))
                        # Every sample is also an alert evaluation - this is
                        # where a threshold becomes a notification.
                        try:
                            from alerting import engine as alerts
                            alerts.evaluate_host(key, snap.get('stats') or {},
                                                 now=snap.get('ts'))
                        except Exception as exc:
                            log.debug('[dockermon] alert evaluation failed: %s', exc)
        except Exception as exc:
            log.warning('[dockermon] history sampler error: %s', exc)
        # Waiting on the event (not sleep) lets shutdown interrupt the pause.
        _stop.wait(max(1.0, wait - (time.time() - started)))


def start_sampler(app=None, interval=None):
    """Start the background sampler once (idempotent)."""
    global _started, _thread
    with _start_lock:
        if _started:
            return False
        if app is None:
            try:
                from flask import current_app
                app = current_app._get_current_object()
            except Exception:
                return False
        _started = True
        _stop.clear()
        _thread = threading.Thread(
            target=_loop, args=(app, interval or None), daemon=True,
            name='docker-history')
        _thread.start()
        return True


def stop_sampler():
    """Stop the sampler (used at shutdown and by tests)."""
    global _started
    with _start_lock:
        _started = False
        _stop.set()
