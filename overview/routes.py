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
    }


def _etag_for(payload: Dict[str, Any]) -> str:
    # ``ts`` must not defeat the ETag, otherwise every poll looks changed.
    stable = {k: v for k, v in payload.items() if k != 'ts'}
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
