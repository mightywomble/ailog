"""Flask blueprint for ailog's Docker monitoring subsystem.

Routes
------
GET  /docker/<host_key>                     standalone Docker page
GET  /api/docker/endpoints                  known endpoints + reachability
POST /api/docker/discover                   scan every configured host
GET  /api/docker/discover/stream            same scan, SSE progress
POST /api/docker/hosts/<host_key>/probe     re-probe a single host
GET  /api/docker/hosts/<host_key>           engine / swarm info
GET  /api/docker/hosts/<host_key>/stats     live CPU / RAM / network
GET  /api/docker/hosts/<host_key>/containers
GET  /api/docker/hosts/<host_key>/containers/<container_id>
GET  /api/docker/hosts/<host_key>/nodes      swarm cluster-wide nodes
GET  /api/docker/hosts/<host_key>/history    rolling in-memory host series
GET  /api/docker/hosts/<host_key>/history/stream  same, pushed over SSE
GET  /api/docker/hosts/<host_key>/swarm      cluster view grouped per app
GET  /api/docker/hosts/<host_key>/fleet      docker usage as a share of the host
GET  /api/docker/hosts/<host_key>/updates    containers whose image moved
POST /api/docker/hosts/<host_key>/updates/refresh   queue a fresh scan
GET  /api/docker/overview                    sidebar badges: ok / attention
GET  /api/docker/hosts/<host_key>/update/plan  how this container gets its update
POST /api/docker/hosts/<host_key>/update       do it, for that container only
GET  /api/docker/update/jobs/<job_id>          the dialog's live progress
"""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import (Blueprint, Response, current_app, jsonify, render_template,
                   request, stream_with_context)

from . import endpoints as ep
from . import history as dhistory
from . import sshstats
from . import stats as dstats
from . import swarm as dswarm
from . import updates as dupdates
from . import updateflow as duflow
from core.timeutil import utcnow
from database import release_session

docker_bp = Blueprint('docker', __name__)

SCAN_WORKERS = 8


# --------------------------------------------------------------------------
# persistence helpers
# --------------------------------------------------------------------------

def _endpoint_model():
    try:
        from database import DockerEndpoint
        return DockerEndpoint
    except Exception:
        return None


def _save_endpoint(host_key: str, result: dict):
    """Upsert discovery results for a host (best effort)."""
    model = _endpoint_model()
    if model is None:
        return
    try:
        from database import db
        row = model.query.filter_by(host_key=host_key).first()
        if row is None:
            row = model(host_key=host_key)
            db.session.add(row)
        row.friendly_name = result.get('friendly_name') or host_key
        row.ip_address = result.get('ip')
        row.mode = result.get('mode')
        row.port = result.get('port')
        row.server_version = result.get('server_version')
        row.is_reachable = bool(result.get('reachable'))
        row.last_error = result.get('error')
        row.last_checked_at = utcnow()
        db.session.commit()
        _forget_endpoint_cache()
    except Exception:
        try:
            from database import db
            db.session.rollback()
        except Exception:
            pass


ENDPOINT_TTL = 3.0
_endpoint_cache = {'ts': 0.0, 'rows': {}}
_endpoint_cache_lock = threading.Lock()


def _forget_endpoint_cache() -> None:
    with _endpoint_cache_lock:
        _endpoint_cache['ts'] = 0.0
        _endpoint_cache['rows'] = {}


def _known_endpoints() -> dict:
    """Discovery results for every host, shared for a few seconds.

    Every stats poll and every background scan resolves a transport, and each
    of those used to be a separate query against the (NFS-backed) database. The
    rows only change when something is discovered, so a 3 second cache costs
    nothing in accuracy and removes most of the database traffic.
    """
    now = time.time()
    with _endpoint_cache_lock:
        # ts == 0 means "never read", so an empty table is still cached (and a
        # discovery result invalidates it explicitly).
        if _endpoint_cache['ts'] and (now - _endpoint_cache['ts']) < ENDPOINT_TTL:
            return _endpoint_cache['rows']
    model = _endpoint_model()
    if model is None:
        return {}
    try:
        rows = {row.host_key: row.to_dict() for row in model.query.all()}
    except Exception:
        return {}
    with _endpoint_cache_lock:
        _endpoint_cache['ts'] = now
        _endpoint_cache['rows'] = rows
    return rows


# --------------------------------------------------------------------------
# client helpers
# --------------------------------------------------------------------------

class DockerRequestError(Exception):
    pass


def _transport_for(host_key: str):
    """Resolve a host and return (host_info, transport, client).

    ``transport`` is either ``'sdk'`` (a DockerClient speaking to a TCP / TLS
    Engine API endpoint) or ``'ssh'`` (no remote API: statistics are gathered
    by running the docker CLI over SSH, see ``sshstats``).
    """
    info = ep.resolve_host(host_key)
    if not info:
        raise DockerRequestError(f"Unknown host '{host_key}'")

    row = _known_endpoints().get(host_key) or {}
    mode = row.get('mode')

    # Everything below leaves the database behind (an SSH probe, a Docker SDK
    # client); holding this thread's connection through it is what starved the
    # pool. See database.release_session.
    release_session()

    if not mode:
        found = ep.discover_host(host_key)
        _save_endpoint(host_key, found)
        release_session()              # discovery does SSH; do not pin a connection
        if not found.get('reachable'):
            raise DockerRequestError(found.get('error') or 'Docker API unreachable')
        mode = found.get('mode')
        row.update(found)

    if mode == 'socket':
        # Host only exposes the unix socket -> use the SSH-CLI transport.
        return info, 'ssh', None

    try:
        client = ep.build_client(mode, info.get('ip'), port=row.get('port'))
    except Exception as exc:
        raise DockerRequestError(str(exc))
    return info, 'sdk', client


def _ssh_args(info: dict):
    """Keyword arguments for the sshstats collectors."""
    return {
        'user': info.get('user') or 'root',
        'ip': info.get('ip') or '127.0.0.1',
        'ssh_key_id': info.get('ssh_key_id'),
    }


# The page polls /stats every 2s and /containers every 5s; each SSH snapshot
# runs `docker stats --no-stream` for every container. A very short TTL cache
# collapses the concurrent bursts (initial page load fires nodes + stats +
# containers at once) without making the numbers stale.
SNAPSHOT_TTL = 1.5
_snapshot_lock = threading.Lock()
_snapshot_cache: dict[str, tuple[float, dict]] = {}


def _snapshot_ssh(host_key: str, info: dict, max_age: float = SNAPSHOT_TTL):
    now = time.time()
    with _snapshot_lock:
        hit = _snapshot_cache.get(host_key)
        if hit and (now - hit[0]) < max_age:
            return hit[1]
    try:
        snap = sshstats.snapshot(host_key, **_ssh_args(info))
    except Exception as exc:
        raise DockerRequestError(f'Docker over SSH failed: {exc}') from exc
    with _snapshot_lock:
        _snapshot_cache[host_key] = (time.time(), snap)
        # Keep the cache from growing if hosts are removed over time.
        if len(_snapshot_cache) > 64:
            for key in [k for k, v in _snapshot_cache.items() if now - v[0] > 60]:
                _snapshot_cache.pop(key, None)
    return snap


def _error(message, status=502):
    return jsonify({'success': False, 'error': str(message)}), status


def host_snapshot(host_key: str) -> dict:
    """One collection for ``host_key``, whatever the transport.

    Returns ``{'stats', 'containers', 'nodes', 'ts'}``. The stats endpoints,
    the history sampler and the swarm view all go through here so they cannot
    disagree about what a host is currently doing.
    """
    info, transport, client = _transport_for(host_key)
    if transport == 'ssh':
        snap = _snapshot_ssh(host_key, info)
        stats = snap.get('stats') or {}
        return {
            'stats': stats,
            'containers': snap.get('containers') or [],
            'nodes': snap.get('nodes') or [],
            'ts': stats.get('ts') or time.time(),
        }
    containers = dstats.collect_containers(client)
    totals = dstats.collect_totals(client, containers)
    return {
        'stats': totals,
        'containers': containers,
        'nodes': dstats.swarm_nodes(client),
        'ts': totals.get('ts') or time.time(),
    }


def _ensure_sampler():
    """Start the history sampler on first use (idempotent)."""
    try:
        dhistory.start_sampler(current_app._get_current_object())
    except Exception:
        pass


# --------------------------------------------------------------------------
# page
# --------------------------------------------------------------------------

@docker_bp.route('/docker/<path:host_key>')
def docker_page(host_key):
    info = ep.resolve_host(host_key) or {'key': host_key, 'friendly_name': host_key}
    endpoint = _known_endpoints().get(host_key) or {}
    _ensure_sampler()
    return render_template('docker.html', host_key=host_key, host=info,
                           endpoint=endpoint,
                           history_interval=dhistory.interval_seconds(),
                           history_minutes=dhistory.window_minutes())


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------

@docker_bp.route('/api/docker/endpoints')
def api_endpoints():
    known = _known_endpoints()
    out = []
    for key in ep.all_host_keys():
        info = ep.resolve_host(key) or {'key': key, 'friendly_name': key}
        row = known.get(key, {})
        out.append({
            'host_key': key,
            'friendly_name': info.get('friendly_name'),
            'ip': info.get('ip'),
            'reachable': bool(row.get('is_reachable')),
            'mode': row.get('mode'),
            'port': row.get('port'),
            'server_version': row.get('server_version'),
            'error': row.get('last_error'),
        })
    return jsonify({'success': True, 'endpoints': out})


def _scan_one(host_key: str, app=None) -> dict:
    """Probe one host and persist the result.

    Worker threads do not inherit the caller's Flask app context, so
    ``Host.query`` inside resolve_host() and ``db.session`` in
    _save_endpoint() raise unless a context is pushed inside the thread.
    Callers that fan out to a ThreadPoolExecutor must therefore pass the
    app object explicitly (grabbed while still in a request context).
    """
    if app is None:
        try:
            app = current_app._get_current_object()
        except RuntimeError:
            app = None
    if app is None:
        return _scan_one_body(host_key)
    with app.app_context():
        return _scan_one_body(host_key)


def _scan_one_body(host_key: str) -> dict:
    try:
        result = ep.discover_host(host_key)
    except Exception as exc:
        result = {'host_key': host_key, 'reachable': False, 'error': str(exc)}
    _save_endpoint(host_key, result)
    return result


@docker_bp.route('/api/docker/discover', methods=['POST'])
def api_discover():
    keys = ep.all_host_keys()
    app = current_app._get_current_object()
    results = []
    with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
        futures = {pool.submit(_scan_one, k, app): k for k in keys}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as exc:
                results.append({'host_key': futures[fut], 'reachable': False, 'error': str(exc)})
    ok = [r for r in results if r.get('reachable')]
    return jsonify({'success': True, 'scanned': len(results), 'found': len(ok),
                    'results': results, 'endpoints': _known_endpoints()})


@docker_bp.route('/api/docker/discover/stream')
def api_discover_stream():
    keys = ep.all_host_keys()
    app = current_app._get_current_object()

    def generate():
        yield 'data: ' + json.dumps({'type': 'start', 'total': len(keys)}) + '\n\n'
        done = 0
        found = 0
        with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
            futures = {pool.submit(_scan_one, k, app): k for k in keys}
            for fut in as_completed(futures):
                try:
                    result = fut.result()
                except Exception as exc:
                    result = {'host_key': futures[fut], 'reachable': False, 'error': str(exc)}
                done += 1
                if result.get('reachable'):
                    found += 1
                payload = {'type': 'result', 'done': done, 'total': len(keys),
                           'found': found, 'result': result}
                yield 'data: ' + json.dumps(payload) + '\n\n'
        yield 'data: ' + json.dumps({'type': 'done', 'total': len(keys), 'found': found}) + '\n\n'

    return Response(stream_with_context(generate()), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@docker_bp.route('/api/docker/hosts/<path:host_key>/probe', methods=['POST'])
def api_probe(host_key):
    result = _scan_one(host_key)
    return jsonify({'success': bool(result.get('reachable')), 'result': result})


# --------------------------------------------------------------------------
# read APIs
# --------------------------------------------------------------------------

@docker_bp.route('/api/docker/hosts/<path:host_key>')
def api_host(host_key):
    try:
        info, transport, client = _transport_for(host_key)
    except DockerRequestError as exc:
        return _error(exc)
    if transport == 'ssh':
        try:
            data = sshstats.node_info(host_key, snap=_snapshot_ssh(host_key, info),
                                      **_ssh_args(info))
        except Exception as exc:
            return _error(exc)
    else:
        data = dstats.node_info(client)
    data.update({'host_key': host_key, 'friendly_name': info.get('friendly_name'),
                 'ip': info.get('ip')})
    return jsonify({'success': True, 'data': data})


@docker_bp.route('/api/docker/hosts/<path:host_key>/stats')
def api_stats(host_key):
    try:
        info, transport, client = _transport_for(host_key)
    except DockerRequestError as exc:
        return _error(exc)
    if transport == 'ssh':
        try:
            totals = _snapshot_ssh(host_key, info)['stats']
        except DockerRequestError as exc:
            return _error(exc)
    else:
        containers = dstats.collect_containers(client)
        totals = dstats.collect_totals(client, containers)
    totals['host_key'] = host_key
    totals['friendly_name'] = info.get('friendly_name')
    return jsonify({'success': True, 'stats': totals})


_ctr_net_lock = threading.Lock()
# host_key -> (when, {container id: (rx_total, tx_total)}) so a container's
# cumulative counters can be turned into a rate the way the host's are.
_ctr_net_cache: dict[str, tuple[float, dict[str, tuple[int, int]]]] = {}


def _container_net_rates(host_key: str, rows: list[dict]) -> None:
    """Give every container ``net_rx_bps``/``net_tx_bps``, on any transport.

    Over SSH the snapshot has already done this (and left the cumulative
    figures in ``net_rx_total``); the Engine API reports counters only, so the
    two transports disagreed about what ``net_rx`` meant - 11 MB a second for a
    container that had been idle for hours. Both now answer the same question,
    and nothing has to know which transport answered it.
    """
    now = time.time()
    with _ctr_net_lock:
        prev = _ctr_net_cache.get(host_key)
    counters: dict[str, tuple[int, int]] = {}
    for row in rows:
        if 'net_rx_bps' in row:
            continue
        cid = row.get('id') or ''
        if not cid:
            continue
        rx = int(row.get('net_rx_total', row.get('net_rx')) or 0)
        tx = int(row.get('net_tx_total', row.get('net_tx')) or 0)
        counters[cid] = (rx, tx)
        row['net_rx_total'] = rx
        row['net_tx_total'] = tx
        before = (prev[1].get(cid) if prev else None)
        if not before:
            row['net_rx_bps'] = 0.0
            row['net_tx_bps'] = 0.0
            continue
        elapsed = max(now - prev[0], 0.001)
        row['net_rx_bps'] = round(max(0, rx - before[0]) / elapsed, 2)
        row['net_tx_bps'] = round(max(0, tx - before[1]) / elapsed, 2)
    with _ctr_net_lock:
        _ctr_net_cache[host_key] = (now, counters)
        if len(_ctr_net_cache) > 64:
            for key in [k for k, v in _ctr_net_cache.items() if now - v[0] > 300]:
                _ctr_net_cache.pop(key, None)


@docker_bp.route('/api/docker/hosts/<path:host_key>/containers')
def api_containers(host_key):
    try:
        info, transport, client = _transport_for(host_key)
    except DockerRequestError as exc:
        return _error(exc)
    if transport == 'ssh':
        try:
            rows = _snapshot_ssh(host_key, info)['containers']
        except DockerRequestError as exc:
            return _error(exc)
    else:
        rows = dstats.collect_containers(client)
    _container_net_rates(host_key, rows)
    node_filter = request.args.get('node_id')
    if node_filter:
        rows = [r for r in rows if r.get('node_id') == node_filter]
    return jsonify({'success': True, 'containers': rows, 'count': len(rows)})


# --------------------------------------------------------------------------
# fleet usage, image updates and the sidebar badge
#
# Three questions the Docker Information page asks about one host:
#   * what is the whole docker fleet using, as a share of the host itself?
#   * which containers are running an image the registry has moved on from?
#   * does anything on this host need looking at at all?
# --------------------------------------------------------------------------

# Container network counters in `docker ps`/`docker stats` are cumulative, so a
# share of host traffic only exists once there are two samples. Kept per host
# and only used by /fleet: the container rows keep their own semantics.
_fleet_rate_lock = threading.Lock()
_fleet_rate_cache: dict[str, tuple[float, int, int]] = {}


def _fleet_payload(host_key: str, snap: dict, docker_df: dict | None = None) -> dict:
    stats = snap.get('stats') or {}
    containers = snap.get('containers') or []
    running = [c for c in containers
               if (c.get('state') or '').lower() == 'running']

    cores = float(stats.get('cpu_cores') or 1) or 1.0
    # `docker stats` reports CPU against a single core, so 3 containers at 100%
    # on an 8 core box is 37.5% of the host, not 300%.
    cpu_docker = round(sum(float(c.get('cpu_percent') or 0) for c in running) / cores, 2)

    mem_docker = sum(int(c.get('mem_used') or 0) for c in running)
    mem_total = int(stats.get('mem_total') or 0)

    rx_cum = sum(int(c.get('net_rx') or 0) for c in running)
    tx_cum = sum(int(c.get('net_tx') or 0) for c in running)
    now = time.time()
    with _fleet_rate_lock:
        prev = _fleet_rate_cache.get(host_key)
        _fleet_rate_cache[host_key] = (now, rx_cum, tx_cum)
    if prev and now > prev[0]:
        elapsed = max(now - prev[0], 0.001)
        rx_bps = max(0.0, (rx_cum - prev[1])) / elapsed
        tx_bps = max(0.0, (tx_cum - prev[2])) / elapsed
    else:
        rx_bps = tx_bps = 0.0

    # Storage: `docker system df` totals (images + containers + volumes + build
    # cache). Summing SizeRw per container would ignore images and volumes;
    # summing SizeRootfs would count every shared layer once per container.
    docker_df = docker_df if docker_df is not None else (stats.get('docker_df') or {})
    if docker_df:
        disk_docker = sum(float((row or {}).get('size') or 0) for row in docker_df.values())
    else:
        disk_docker = float(sum(int(c.get('size_rw') or 0) for c in containers))
    disk_total = float(stats.get('disk_total') or 0)

    host_rx = float(stats.get('net_rx_bps') or 0)
    host_tx = float(stats.get('net_tx_bps') or 0)
    net_docker = rx_bps + tx_bps
    net_host = host_rx + host_tx

    def share(part, whole, cap=100.0):
        if not whole:
            return None
        return round(min(cap, max(0.0, 100.0 * part / whole)), 1)

    return {
        'host_key': host_key,
        'host': {
            'cpu_percent': stats.get('cpu_percent'),
            'cpu_cores': stats.get('cpu_cores'),
            'mem_used': stats.get('mem_used'),
            'mem_total': mem_total,
            'net_rx_bps': host_rx,
            'net_tx_bps': host_tx,
            'disk_used': stats.get('disk_used'),
            'disk_total': disk_total,
        },
        'docker': {
            'cpu_percent': cpu_docker,
            'mem_used': mem_docker,
            'net_rx_bps': round(rx_bps, 1),
            'net_tx_bps': round(tx_bps, 1),
            'disk_used': round(disk_docker),
            'containers': len(containers),
            'running': len(running),
            'df': docker_df,
        },
        'pct': {
            'cpu': share(cpu_docker, 100.0),
            'ram': share(mem_docker, mem_total),
            'net': share(net_docker, net_host) if net_host else 0.0,
            'storage': share(disk_docker, disk_total),
        },
        'basis': {
            'cpu': 'share of all host cores',
            'ram': 'share of host RAM',
            'net': 'share of host network traffic',
            'storage': 'share of host disk (docker system df)',
        },
        'ts': now,
    }


# `docker system df` walks every image layer, so it is the one command that
# must not ride along with the 2s stats poll. The fleet pane only needs a
# minute-accurate number, so it is cached separately.
DF_TTL = 60
_df_lock = threading.Lock()
_df_cache: dict[str, tuple[float, dict]] = {}


def _docker_df(host_key: str, info: dict, transport: str, client) -> dict:
    now = time.time()
    with _df_lock:
        hit = _df_cache.get(host_key)
    if hit and (now - hit[0]) < DF_TTL:
        return hit[1]
    try:
        if transport == 'ssh':
            df = sshstats.disk_usage(**_ssh_args(info))
        else:
            df = dstats._df_totals(client)
    except Exception:
        df = {}
    with _df_lock:
        _df_cache[host_key] = (now, df)
        if len(_df_cache) > 64:
            for key in [k for k, v in _df_cache.items() if now - v[0] > DF_TTL * 4]:
                _df_cache.pop(key, None)
    return df


def _updates_runner(info: dict):
    return dupdates.runner_for(info)


@docker_bp.route('/api/docker/hosts/<path:host_key>/fleet')
def api_fleet(host_key):
    """Docker fleet CPU/RAM/NET/disk as a percentage of the host itself."""
    if not ep.resolve_host(host_key):
        return _error(f"Unknown host '{host_key}'", status=404)
    try:
        info, transport, client = _transport_for(host_key)
        snap = host_snapshot(host_key)
    except DockerRequestError as exc:
        return _error(exc)
    df = _docker_df(host_key, info, transport, client)
    return jsonify({'success': True, **_fleet_payload(host_key, snap, df)})


@docker_bp.route('/api/docker/hosts/<path:host_key>/updates')
def api_updates(host_key):
    """Containers whose image the registry has moved on from."""
    refresh = (request.args.get('refresh') or '').lower() in ('1', 'true', 'yes')
    if not ep.resolve_host(host_key):
        return _error(f"Unknown host '{host_key}'", status=404)
    try:
        info, _transport, _client = _transport_for(host_key)
        snap = host_snapshot(host_key)
    except DockerRequestError as exc:
        return _error(exc)
    try:
        result = dupdates.updates_for(host_key, snap.get('containers') or [],
                                      _updates_runner(info), refresh=refresh)
    except Exception as exc:                    # noqa: BLE001 - report, never 500 the page
        return _error(exc)
    dupdates._store(host_key, result)
    return jsonify({'success': True, **result})


@docker_bp.route('/api/docker/hosts/<path:host_key>/updates/refresh', methods=['POST'])
def api_updates_refresh(host_key):
    """Queue a fresh scan (the answer comes back from /updates or /overview)."""
    if not ep.resolve_host(host_key):
        return _error(f"Unknown host '{host_key}'", status=404)
    app = current_app._get_current_object()
    if not dupdates.stale(host_key, max_age=1):
        return jsonify({'success': True, 'pending': host_key})
    # Through scan_async, not a thread of its own: one queue keeps the scan
    # concurrency (and therefore the connections it can pin) bounded, and it is
    # what the activity strip reads its progress from.
    started = dupdates.scan_async(app, [host_key])
    return jsonify({'success': True, 'started': started[0] if started else None})


@docker_bp.route('/api/docker/updates/refresh', methods=['POST'])
def api_updates_refresh_all():
    """Queue a fresh scan for every host that could run Docker.

    The dashboard card's "check all hosts": one button, one queue, and the
    answers arrive through the normal poll as each scan lands. Bounded by the
    scan coordinator, so pressing it twice does not open 17 SSH rounds twice.
    """
    app = current_app._get_current_object()
    started = dupdates.scan_async(app, ep.all_host_keys(), force=True)
    # The dashboard's "updates" are two answers now: which tags moved, and which
    # pins are behind. A person pressing this is doubting both.
    try:
        from estate import drift
        reswept = drift.refresh_async(app, force=True)
    except Exception:                     # noqa: BLE001 - a sweep must not break the button
        reswept = False
    return jsonify({'success': True, 'started': started, 'estate': reswept,
                    'progress': dupdates.activity()})


@docker_bp.route('/api/docker/hosts/<path:host_key>/update/plan')
def api_update_plan(host_key):
    """How *this* container would be updated: the kind, the target, the commands.

    Reading only — the dialog shows this before anything runs, so the user sees
    "compose project gitea on casaos, two commands" rather than a black box.
    """
    if not ep.resolve_host(host_key):
        return _error(f"Unknown host '{host_key}'", status=404)
    image = (request.args.get('image') or '').strip()
    container = (request.args.get('container') or '').strip()
    if not image and not container:
        return _error('an image or a container name is required', status=400)
    try:
        return jsonify({'success': True, 'plan': duflow.plan(host_key, image, container)})
    except Exception as exc:                      # noqa: BLE001 - surfaced in the dialog
        return jsonify({'success': False, 'error': str(exc) or exc.__class__.__name__}), 502


@docker_bp.route('/api/docker/hosts/<path:host_key>/update', methods=['POST'])
def api_update_run(host_key):
    """Start the update for the containers a pane row refers to.

    Scoped by design: the body carries the image (or one container name) the row
    was about, so the same endpoint cannot be pointed at a whole host.
    """
    if not ep.resolve_host(host_key):
        return _error(f"Unknown host '{host_key}'", status=404)
    body = request.get_json(silent=True) or {}
    image = str(body.get('image') or '').strip()
    container = str(body.get('container') or '').strip()
    if not image and not container:
        return _error('an image or a container name is required', status=400)
    if not body.get('confirm'):
        return _error('confirmation is required: the dialog must show the commands first',
                      status=400)
    if duflow.mode() == 'off':
        return _error('updates are disabled on this server (AILOG_ALLOW_UPDATES=off)',
                      status=403)
    app = current_app._get_current_object()
    started = duflow.start(app, host_key, image, container)
    return jsonify({'success': True, 'job': started})


@docker_bp.route('/api/docker/update/jobs/<job_id>')
def api_update_job(job_id):
    """Live progress for one update: the step, the command, the output tail."""
    found = duflow.job(job_id)
    if not found:
        return _error(f"Unknown update job '{job_id}'", status=404)
    return jsonify({'success': True, 'job': found})


def _says_no_docker(message: str) -> bool:
    """True only when the error means Docker is genuinely absent.

    "permission denied while trying to connect to the Docker daemon socket" is a
    Docker *presence* with an access problem - the sidebar must not hide the
    square and pretend the host has no containers.
    """
    text = (message or '').lower()
    if not text:
        return False
    return any(marker in text for marker in (
        'docker_not_installed', 'command not found', 'no such file or directory',
        'docker: not found', 'is not installed',
    ))


@docker_bp.route('/api/docker/overview')
def api_overview():
    """Every host that runs Docker, and whether it needs attention.

    The sidebar badge is polled every ~20s, so this must never do a live SSH
    snapshot per host. Docker presence comes from the metrics snapshot the rest
    of the sidebar already reads (cached, stale-while-revalidate); the update
    verdict comes from the last background scan, and a stale one is queued here
    rather than answered inline.
    """
    known = _known_endpoints()
    cached = dupdates.all_state()
    app = current_app._get_current_object()

    # Which hosts run Docker at all. This endpoint is polled from the sidebar,
    # so it may only read the metrics cache -- calling servers_payload() here
    # would block the badge behind a cold SSH round for every host. An empty
    # cache simply means "ask again on the next poll".
    metrics_hosts = {}
    try:
        from metrics.routes import cached_servers_payload
        payload = cached_servers_payload() or {}
        for row in payload.get('servers') or []:
            metrics_hosts[row.get('host_key')] = row
    except Exception:
        metrics_hosts = {}

    hosts = {}
    to_scan = []
    # Every configured host is considered, so a host that has Docker but has
    # never been scanned still appears (as "unknown") instead of vanishing.
    keys = set(ep.all_host_keys()) | set(metrics_hosts) | set(known) | set(cached)
    for host_key in keys:
        info = ep.resolve_host(host_key) or {}
        endpoint = known.get(host_key) or {}
        metric = metrics_hosts.get(host_key) or {}
        docker_facts = metric.get('docker') or {}
        state_row = cached.get(host_key)
        state_error = (state_row or {}).get('error') or ''

        if state_row is not None:
            # A scan ran, so the only thing that can say "no docker here" is the
            # error itself. A permission or timeout error means Docker *is*
            # installed and we could not read it - that is attention, not absence.
            has_docker = not _says_no_docker(state_error)
        else:
            has_docker = bool(docker_facts.get('installed')
                              or docker_facts.get('reachable')
                              or endpoint.get('is_reachable'))
        if not has_docker:
            hosts[host_key] = {
                'host_key': host_key,
                'friendly_name': info.get('friendly_name') or metric.get('friendly_name') or host_key,
                'docker': None,
                'status': 'none',
                'updates': 0,
                'attention': 0,
                'containers': None,
                'error': state_error or None,
            }
            continue
        if not state_row:
            to_scan.append(host_key)

        updates_count = len((state_row or {}).get('updates') or [])
        attention = len((state_row or {}).get('attention_only') or [])
        containers = (state_row or {}).get('containers_checked')

        if state_row is None:
            status = 'unknown'
        elif state_row.get('error'):
            status = 'unknown'
        elif updates_count or attention:
            status = 'attention'
        else:
            status = 'ok'

        hosts[host_key] = {
            'host_key': host_key,
            'friendly_name': info.get('friendly_name') or metric.get('friendly_name') or host_key,
            'docker': True,
            'status': status,
            'updates': updates_count,
            'attention': attention,
            'containers': containers if containers is not None else docker_facts.get('running'),
            'running': docker_facts.get('running'),
            'reported_containers': docker_facts.get('total'),
            'scanned_at': (state_row or {}).get('ts'),
            'took': (state_row or {}).get('took'),
            'error': (state_row or {}).get('error'),
        }

    started = dupdates.scan_async(app, to_scan) if to_scan else []
    for key in started:
        if key in hosts:
            hosts[key]['pending'] = True

    return jsonify({'success': True, 'hosts': hosts,
                    'scanned': [k for k in hosts if cached.get(k)],
                    'pending': started})


@docker_bp.route('/api/docker/hosts/<path:host_key>/containers/<container_id>')
def api_container(host_key, container_id):
    try:
        info, transport, client = _transport_for(host_key)
    except DockerRequestError as exc:
        return _error(exc)
    if transport == 'ssh':
        try:
            data = sshstats.container_detail(
                host_key, container_id=container_id, **_ssh_args(info))
        except Exception as exc:
            return _error(exc)
        data['host_key'] = host_key
        data['friendly_name'] = info.get('friendly_name')
        return jsonify({'success': True, 'container': data})
    try:
        attrs = client.api.inspect_container(container_id, size=True)
    except Exception as exc:
        return _error(exc)
    config = attrs.get('Config') or {}
    state = attrs.get('State') or {}
    image_id = config.get('Image') or attrs.get('Image')
    image = {}
    try:
        img = client.images.get(image_id)
        iattrs = img.attrs or {}
        image = {
            'id': img.id,
            'tags': list(img.tags or []),
            'repo_tags': list(iattrs.get('RepoTags') or []),
            'repo_digests': list(iattrs.get('RepoDigests') or []),
            'size': iattrs.get('Size'),
            'created': iattrs.get('Created'),
            'labels': iattrs.get('Config', {}).get('Labels') or {},
        }
    except Exception:
        image = {'id': image_id}
    ports = []
    for container_port, bindings in ((attrs.get('NetworkSettings') or {}).get('Ports') or {}).items():
        for b in bindings or []:
            ports.append(f"{b.get('HostIp') or '0.0.0.0'}:{b.get('HostPort')}->{container_port}")
    mounts = [{'source': m.get('Source'), 'destination': m.get('Destination'),
               'type': m.get('Type'), 'mode': m.get('Mode')} for m in (attrs.get('Mounts') or [])]
    data = {
        'id': attrs.get('Id'),
        'name': (attrs.get('Name') or '').lstrip('/'),
        'created': attrs.get('Created'),
        'restart_count': attrs.get('RestartCount'),
        'platform': attrs.get('Platform'),
        'state': {
            'status': state.get('Status'),
            'running': state.get('Running'),
            'started_at': state.get('StartedAt'),
            'finished_at': state.get('FinishedAt'),
            'exit_code': state.get('ExitCode'),
            'error': state.get('Error'),
            'health': (state.get('Health') or {}).get('Status'),
            'restarting': state.get('Restarting'),
            'oom_killed': state.get('OOMKilled'),
        },
        'size_rw': attrs.get('SizeRw'),
        'size_rootfs': attrs.get('SizeRootFs'),
        'image': image,
        'image_name': config.get('Image'),
        'ports': ports,
        'mounts': mounts,
        'labels': config.get('Labels') or {},
        'env_count': len(config.get('Env') or []),
    }
    return jsonify({'success': True, 'container': data})


def _normalize_nodes(rows):
    """Normalise SSH-CLI node rows to the same shape as dockermon.stats.swarm_nodes.

    sshstats/parse_node_line yields {id, hostname, status, availability, manager};
    SDK swarm_nodes yields {id, hostname, role, state, availability, addr, ...}.
    """
    out = []
    for row in rows or []:
        node = dict(row)
        manager = (node.get('manager') or '').strip().lower()
        if not node.get('role'):
            node['role'] = 'manager' if manager.startswith('leader') or manager.startswith('reachable') else 'worker'
        if not node.get('state'):
            node['state'] = node.get('status') or ('ready' if manager else 'unknown')
        node['addr'] = node.get('addr') or ''
        node['version'] = node.get('version') or ''
        node['engine_version'] = node.get('engine_version') or ''
        out.append(node)
    return out


@docker_bp.route('/api/docker/hosts/<path:host_key>/nodes')
def api_nodes(host_key):
    try:
        info, transport, client = _transport_for(host_key)
    except DockerRequestError as exc:
        return _error(exc)
    if transport == 'ssh':
        try:
            nodes = _snapshot_ssh(host_key, info).get('nodes') or []
        except DockerRequestError as exc:
            return _error(exc)
    else:
        nodes = dstats.swarm_nodes(client)
    nodes = _normalize_nodes(nodes)
    return jsonify({'success': True, 'nodes': nodes, 'count': len(nodes)})


# --------------------------------------------------------------------------
# history (rolling in-memory series)
# --------------------------------------------------------------------------

@docker_bp.route('/api/docker/hosts/<path:host_key>/history')
def api_history(host_key):
    _ensure_sampler()
    payload = dhistory.payload(host_key)
    return jsonify({'success': True, **payload})


@docker_bp.route('/api/docker/hosts/<path:host_key>/history/stream')
def api_history_stream(host_key):
    """Push the series whenever the sampler records a new point."""
    _ensure_sampler()
    interval = dhistory.interval_seconds()

    def generate():
        yield ': connected\n\n'
        yield 'retry: 5000\n\n'
        last = None
        # Bounded so an abandoned browser tab cannot pin a worker forever.
        for _ in range(int(3600 / max(interval, 1))):
            payload = dhistory.payload(host_key)
            if payload['revision'] != last:
                last = payload['revision']
                yield 'data: ' + json.dumps(payload) + '\n\n'
            else:
                yield ': keepalive\n\n'
            time.sleep(max(1, interval))

    return Response(stream_with_context(generate()),
                    mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache, no-transform',
                             'X-Accel-Buffering': 'no',
                             'Connection': 'keep-alive'})


# --------------------------------------------------------------------------
# swarm cluster (master -> nodes, grouped per app)
# --------------------------------------------------------------------------

@docker_bp.route('/api/docker/hosts/<path:host_key>/swarm')
def api_swarm(host_key):
    try:
        info, transport, client = _transport_for(host_key)
    except DockerRequestError as exc:
        return _error(exc)
    try:
        snap = host_snapshot(host_key)
    except DockerRequestError as exc:
        return _error(exc)
    is_swarm = bool((snap.get('stats') or {}).get('swarm'))
    try:
        if is_swarm:
            view = dswarm.cluster(host_key, info, master_snap=snap,
                                  transport=transport, client=client)
        else:
            view = dswarm.single_host(host_key, info, snap)
    except Exception as exc:
        return _error(exc)
    view['success'] = True
    return jsonify(view)


@docker_bp.route('/api/docker/hosts/<path:host_key>/swarm/refresh', methods=['POST'])
def api_swarm_refresh(host_key):
    dswarm.clear(host_key)
    return api_swarm(host_key)


# --------------------------------------------------------------------------
# stack updates (swarm: the stack is the unit, the version is the choice)
# --------------------------------------------------------------------------

@docker_bp.route('/api/docker/hosts/<path:host_key>/swarm/stacks')
def api_swarm_stacks(host_key):
    """Every stack on the cluster, with the services that have moved on.

    Read from the manager, because a worker cannot see the cluster - and
    because a service's deployed image is a fact about the *service*, not about
    whichever container happens to be on the node being clicked.
    """
    if not ep.resolve_host(host_key):
        return _error(f"Unknown host '{host_key}'", status=404)
    refresh = (request.args.get('refresh') or '').lower() in ('1', 'true', 'yes')
    try:
        from . import swarmstack
        return jsonify({'success': True, **swarmstack.scan(host_key, refresh=refresh)})
    except Exception as exc:                    # noqa: BLE001 - report, never 500 the page
        return _error(exc)


@docker_bp.route('/api/docker/hosts/<path:host_key>/swarm/stacks/<stack>/services/<service>/versions')
def api_swarm_versions(host_key, stack, service):
    """What this service could be moved to, and what it is on now."""
    if not ep.resolve_host(host_key):
        return _error(f"Unknown host '{host_key}'", status=404)
    try:
        from . import swarmstack
        return jsonify({'success': True, **swarmstack.versions(host_key, stack, service)})
    except Exception as exc:                    # noqa: BLE001 - surfaced in the dialog
        return jsonify({'success': False, 'error': str(exc) or exc.__class__.__name__}), 502


@docker_bp.route('/api/docker/hosts/<path:host_key>/swarm/stacks/<stack>/services/<service>/update',
                 methods=['POST'])
def api_swarm_update(host_key, stack, service):
    """Move one service of one stack to a version the person chose."""
    if not ep.resolve_host(host_key):
        return _error(f"Unknown host '{host_key}'", status=404)
    body = request.get_json(silent=True) or {}
    version = str(body.get('version') or '').strip()
    if not version:
        return _error('a version is required: the dialog asks which one', status=400)
    if not body.get('confirm'):
        return _error('confirmation is required: the dialog shows the milestones first',
                      status=400)
    if duflow.mode() == 'off':
        return _error('updates are disabled on this server (AILOG_ALLOW_UPDATES=off)',
                      status=403)
    app = current_app._get_current_object()
    started = duflow.start_stack(app, host_key, stack, service, version,
                                 prune=bool(body.get('prune', True)))
    return jsonify({'success': True, 'job': started})


@docker_bp.route('/api/docker/registry/images')
def api_registry_images():
    """Every zot repository, what keeps each tag alive, and what could go."""
    try:
        from . import registrygc
        return jsonify({'success': True, **registrygc.describe()})
    except Exception as exc:                    # noqa: BLE001
        return jsonify({'success': False, 'error': str(exc) or exc.__class__.__name__}), 502


@docker_bp.route('/api/docker/registry/prune', methods=['POST'])
def api_registry_prune():
    """Delete the zot manifests nothing uses, keeping the newest N per repo."""
    body = request.get_json(silent=True) or {}
    if not body.get('confirm'):
        return _error('confirmation is required: show the plan first', status=400)
    try:
        from . import registrygc
        result = registrygc.prune(dry_run=bool(body.get('dry_run')))
    except Exception as exc:                    # noqa: BLE001
        return jsonify({'success': False, 'error': str(exc) or exc.__class__.__name__}), 502
    return jsonify({'success': True, **result})


@docker_bp.route('/api/docker/history/clear', methods=['POST'])
def api_history_clear():
    host_key = (request.args.get('host_key') or '').strip() or None
    dhistory.clear(host_key)
    dswarm.clear(host_key)
    return jsonify({'success': True, 'cleared': host_key or 'all'})
