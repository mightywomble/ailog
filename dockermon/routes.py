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
        row.last_checked_at = __import__('datetime').datetime.utcnow()
        db.session.commit()
    except Exception:
        try:
            from database import db
            db.session.rollback()
        except Exception:
            pass


def _known_endpoints() -> dict:
    model = _endpoint_model()
    if model is None:
        return {}
    try:
        return {row.host_key: row.to_dict() for row in model.query.all()}
    except Exception:
        return {}


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

    if not mode:
        found = ep.discover_host(host_key)
        _save_endpoint(host_key, found)
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
    node_filter = request.args.get('node_id')
    if node_filter:
        rows = [r for r in rows if r.get('node_id') == node_filter]
    return jsonify({'success': True, 'containers': rows, 'count': len(rows)})


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


@docker_bp.route('/api/docker/history/clear', methods=['POST'])
def api_history_clear():
    host_key = (request.args.get('host_key') or '').strip() or None
    dhistory.clear(host_key)
    dswarm.clear(host_key)
    return jsonify({'success': True, 'cleared': host_key or 'all'})
