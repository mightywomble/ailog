"""One request for the whole dashboard.

The Overview used to fire three polls every six seconds (fleet metrics,
alerts, reports).  This aggregates them server-side, returns a strong ETag, and
answers ``If-None-Match`` with 304 so an idle dashboard costs a header round
trip instead of three JSON bodies.

Each section is collected independently: a broken subsystem degrades one card
(``{"error": ...}``) instead of blanking the page.  The individual endpoints
stay in place for the pages that use them.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any, Dict

from flask import Blueprint, Response, jsonify, request

logger = logging.getLogger(__name__)

overview_bp = Blueprint('overview', __name__)

REPORT_LIMIT = 5
EVENT_LIMIT = 8
UPDATE_ROW_LIMIT = 12


def _fleet() -> Dict[str, Any]:
    from metrics.routes import servers_payload
    return servers_payload(force=False)


def _alerts() -> Dict[str, Any]:
    from alerting import engine
    return {
        'active': engine.active_events(),
        'events': engine.recent_events(limit=EVENT_LIMIT),
    }


def _reports() -> Dict[str, Any]:
    from database import LogReport
    reports = (LogReport.query
               .order_by(LogReport.created_at.desc())
               .limit(REPORT_LIMIT)
               .all())
    return {'reports': [r.to_dict() for r in reports]}


def _docker_updates() -> Dict[str, Any]:
    """Containers the registry has moved on from, across every scanned host.

    The dashboard asks this every six seconds, so it reads the background scan
    cache and nothing else - one SSH round per host here would make the whole
    page wait on the slowest machine in the estate. A host that has never been
    scanned is *queued* and answered on a later poll, which is why the card can
    be empty for a moment at boot.

    ``self_managed`` rows are left out on purpose: a container whose own compose
    project recreates it (Nextcloud AIO) would otherwise fill the card with
    fifteen entries that nobody should press.

    Two different questions are answered here, because both look like "needs an
    update" to the person reading the card. The scan says a tag's digest moved.
    The estate says a *pin* is behind its upstream release - anchor on 0.9.1
    while 0.17.2 is published, which no digest on the host can ever report
    because :0.9.1 does not move. Estate rows come first: a whole release behind
    is a bigger statement than a rebuilt tag.
    """
    from flask import current_app
    from dockermon import endpoints as dep
    from dockermon import updates as dupdates
    from estate import drift

    cached = dupdates.all_state()
    rows = []
    # Where each image actually runs, so an estate row can be clicked through to
    # the host that carries it: repo name -> (host_key, friendly name, container).
    running: Dict[str, Dict[str, Any]] = {}
    for host_key, state in cached.items():
        info = dep.resolve_host(host_key) or {}
        name = info.get('friendly_name') or host_key
        for row in (state or {}).get('containers') or []:
            ref = str(row.get('image') or '').split('@', 1)[0].rsplit('/', 1)[-1]
            repo = ref.split(':', 1)[0].lower()
            if repo and repo not in running:
                running[repo] = {'host_key': host_key, 'host': name,
                                 'container': row.get('name') or ''}

    # A sweep per fifteen minutes, started on the first poll after it expires;
    # the card fills in on a later poll rather than waiting on nineteen
    # registries inside a six-second request.
    try:
        drift.refresh_async(current_app._get_current_object())
    except Exception:                     # noqa: BLE001 - a sweep must not break the card
        pass
    estate_state = drift.state()
    for row in estate_state.get('rows') or []:
        where = running.get(str(row.get('repo') or '').lower()) or {}
        rows.append({
            'host_key': where.get('host_key') or '',
            'host': where.get('host') or 'estate',
            'container': where.get('container') or row.get('service') or row.get('name') or '',
            'service': row.get('name') or '',
            'image': row.get('image') or '',
            'from': f"v{row['current']}" if row.get('current') else '',
            'to': f"v{row['target']}" if row.get('target') else '',
            'containers': 1,
            'kind': 'estate',
        })
    estate_count = len(rows)

    for host_key, state in cached.items():
        info = dep.resolve_host(host_key) or {}
        name = info.get('friendly_name') or host_key
        for row in (state or {}).get('updates') or []:
            if row.get('self_managed'):
                continue
            rows.append({
                'host_key': host_key,
                'host': name,
                'container': row.get('name') or '',
                'image': row.get('image') or '',
                'from': row.get('local_digest') or '',
                'to': row.get('remote_digest') or '',
                'containers': row.get('containers') or 1,
                'kind': 'digest',
            })

    estate_rows = rows[:estate_count]
    digest_rows = rows[estate_count:]
    digest_rows.sort(key=lambda r: (r['host'].lower(), r['container'].lower()))

    # Twelve alphabetical rows is not a summary of the estate: the noisiest host
    # (nine `:latest` containers on one box) fills the card and everything else
    # ends up behind "and N more". Take one row per host at a time instead, so
    # every host that has something to update is visible before any host gets a
    # second row.
    buckets: Dict[str, list] = {}
    for row in digest_rows:
        buckets.setdefault(row['host'].lower(), []).append(row)
    spread = []
    while buckets and len(spread) < UPDATE_ROW_LIMIT:
        for key in list(buckets):
            spread.append(buckets[key].pop(0))
            if not buckets[key]:
                del buckets[key]
            if len(spread) >= UPDATE_ROW_LIMIT:
                break

    # A release behind beats a rebuilt tag, so the estate's rows go first.
    shown = (estate_rows + spread)[:UPDATE_ROW_LIMIT]

    # The card fills itself: anything never scanned is queued, once.
    to_scan = [key for key in dep.all_host_keys() if key not in cached]
    try:
        started = dupdates.scan_async(current_app._get_current_object(), to_scan) if to_scan else []
    except Exception:                     # noqa: BLE001 - a scan must not break the card
        started = []

    return {
        'count': len(rows),
        'hosts': len({r['host_key'] for r in rows if r['host_key']}),
        'estate': len(estate_rows),
        'rows': shown,
        'more': max(0, len(rows) - len(shown)),
        'pending': sorted(started),
    }


def _safe(fn) -> Any:
    try:
        return fn()
    except Exception as exc:  # pragma: no cover - depends on live hosts
        logger.warning('overview: %s failed: %s', fn.__name__, exc)
        return {'error': str(exc)}


def build_overview() -> Dict[str, Any]:
    return {
        'ts': time.time(),
        'servers': _safe(_fleet),
        'alerts': _safe(_alerts),
        'reports': _safe(_reports),
        'docker_updates': _safe(_docker_updates),
    }


# Keys that report the progress of a scan rather than what the dashboard says.
# A scan *landing* must refresh the card; "a host is being scanned" must not,
# or an idle dashboard would repaint every time a round starts and stops.
VOLATILE = {('docker_updates', 'pending')}


def _etag_for(payload: Dict[str, Any]) -> str:
    # ``ts`` must not defeat the ETag, otherwise every poll looks changed.
    stable = {k: v for k, v in payload.items() if k != 'ts'}
    for section, key in VOLATILE:
        block = stable.get(section)
        if isinstance(block, dict) and key in block:
            stable[section] = {k: v for k, v in block.items() if k != key}
    body = json.dumps(stable, sort_keys=True, default=str)
    return hashlib.sha256(body.encode('utf-8')).hexdigest()[:32]


@overview_bp.get('/api/overview')
def api_overview():
    payload = build_overview()
    etag = _etag_for(payload)

    if_none_match = (request.headers.get('If-None-Match') or '').strip().strip('"')
    if if_none_match and if_none_match == etag:
        resp = Response(status=304)
        resp.set_etag(etag)
        return resp

    body = json.dumps(payload, default=str)
    resp = Response(body, mimetype='application/json')
    resp.set_etag(etag)
    resp.headers['Cache-Control'] = 'private, max-age=0, must-revalidate'
    return resp


@overview_bp.get('/api/overview/summary')
def api_overview_summary():
    """Cheap counts only (used by the mobile tab bar badge)."""
    payload = build_overview()
    servers = payload.get('servers') or {}
    alerts = payload.get('alerts') or {}
    return jsonify({
        'servers': len(servers.get('servers') or servers.get('hosts') or []),
        'active_alerts': len(alerts.get('active') or []),
        'ts': payload['ts'],
    })
