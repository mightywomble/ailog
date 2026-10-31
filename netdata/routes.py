"""Netdata API surface for the UI.

Everything here is read-only except ``/api/netdata/config`` (URL + token) and
``/api/netdata/ingest`` (pull alert transitions into ailog's own timeline).
The token is write-only from the browser's point of view: GET returns whether
it is set, never its value.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict

from flask import Blueprint, jsonify, render_template, request

from . import client, evidence

log = logging.getLogger(__name__)

netdata_bp = Blueprint('netdata', __name__)

HISTORY_CONTEXTS = ('system.cpu', 'system.ram', 'disk.space', 'system.load',
                    client.ANOMALY_CONTEXT)


def _error(message: str, status: int = 502):
    return jsonify({'success': False, 'error': message}), status


@netdata_bp.get('/netdata')
def netdata_page():
    return render_template('netdata.html',
                           embedded=request.args.get('embed') == '1')


@netdata_bp.get('/api/netdata/health')
def api_health():
    return jsonify({'success': True, **client.health()})


@netdata_bp.get('/api/netdata/fleet')
def api_fleet():
    try:
        window = max(1, min(request.args.get('window', type=int) or 120, 3600))
        points = max(2, min(request.args.get('points', type=int) or 30, 240))
        fleet = client.fleet_cards(after=-window, points=points)
    except client.NetdataError as exc:
        return _error(str(exc), exc.status or 502)
    try:
        reconciliation = client.reconcile()
    except client.NetdataError:
        reconciliation = {'available': False}
    # The node label map is useful server-side for matching, but shipping every
    # OS/hardware label for every node dominates the payload and the browser
    # only needs the card facts.
    nodes_out = [{k: v for k, v in node.items() if k != 'labels'}
                 for node in fleet.get('nodes') or []]
    return jsonify({'success': True, **{**fleet, 'nodes': nodes_out},
                    'reconcile': reconciliation,
                    'quality': client.streaming_health()})


@netdata_bp.get('/api/netdata/history')
def api_history():
    host = (request.args.get('host') or '').strip()
    if not host:
        return _error('host is required', 400)
    contexts = [c for c in (request.args.get('contexts') or ','.join(HISTORY_CONTEXTS)).split(',') if c]
    minutes = max(1, min(request.args.get('window', type=int) or 60, 24 * 60))
    points = max(2, min(request.args.get('points', type=int) or 120, 600))
    tier = request.args.get('tier', type=int)
    if tier is None and minutes > 360:
        tier = 1
    try:
        node_list = client.nodes(ttl=10.0)
        node = next((n for n in node_list
                     if host in (n.get('guid'), n.get('name'), n.get('hostname'))), None)
        if not node:
            return _error('unknown Netdata node', 404)
        series: Dict[str, Any] = {}
        for context in contexts:
            parsed = client.fetch_data([context], nodes=[node.get('name')],
                                       after=-minutes * 60, points=points, tier=tier,
                                       group_by='node,context,instance,dimension')
            dims = evidence._series(parsed, node.get('guid'), context)
            if context == 'system.cpu':
                values = client._cpu_percent(dims)
            elif context == 'system.ram':
                values = client._ram_percent(dims)
            elif context == 'disk.space':
                values = client._disk_percent(dims)
            elif context == 'system.load':
                values = (dims.get('load1') or {}).get('value') or []
            else:
                values = (dims.get('anomaly_rate') or dims.get('value') or {}).get('value') or []
            series[context] = [round(v, 3) if v is not None else None for v in values]
        return jsonify({'success': True, 'host': node.get('name'), 'guid': node.get('guid'),
                        'window_minutes': minutes, 'points': points, 'tier': tier,
                        'series': series, 'ts': time.time()})
    except client.NetdataError as exc:
        return _error(str(exc), exc.status or 502)


@netdata_bp.get('/api/netdata/alerts')
def api_alerts():
    try:
        data = client.alerts()
        transitions = client.alert_transitions(
            after=request.args.get('after', type=int) or -86400,
            limit=request.args.get('limit', type=int) or 100)
    except client.NetdataError as exc:
        return _error(str(exc), exc.status or 502)
    # Rank the live instances by severity then anomaly-ish value, so the UI can
    # show an anomaly-first triage list without another request.
    rank = {'CRITICAL': 0, 'WARNING': 1, 'CLEAR': 2}
    alerts = sorted(data.get('alerts') or [],
                    key=lambda a: (rank.get(str(a.get('status')).upper(), 3),
                                   -(a.get('value') or 0)))
    return jsonify({'success': True, 'alerts': alerts,
                    'transitions': transitions.get('transitions') or [],
                    'facets': transitions.get('facets') or {}})


@netdata_bp.get('/api/netdata/transitions')
def api_transitions():
    try:
        data = client.alert_transitions(
            after=request.args.get('after', type=int) or -86400,
            limit=request.args.get('limit', type=int) or 200)
    except client.NetdataError as exc:
        return _error(str(exc), exc.status or 502)
    return jsonify({'success': True, **data})


@netdata_bp.get('/api/netdata/reconcile')
def api_reconcile():
    try:
        return jsonify({'success': True, **client.reconcile()})
    except client.NetdataError as exc:
        return _error(str(exc), exc.status or 502)


@netdata_bp.get('/api/netdata/capacity')
def api_capacity():
    try:
        hours = request.args.get('hours', type=int) or 24
        return jsonify({'success': True, **client.capacity(hours=hours)})
    except client.NetdataError as exc:
        return _error(str(exc), exc.status or 502)


@netdata_bp.get('/api/netdata/diagnostics')
def api_diagnostics():
    return jsonify({'success': True, **client.diagnostics_probe()})


@netdata_bp.route('/api/netdata/config', methods=['GET', 'POST'])
def api_config():
    if request.method == 'GET':
        return jsonify({'success': True, 'url': client.base_url(),
                        'token_set': bool(client.token()),
                        'configured': client.configured()})
    body = request.get_json(silent=True) or {}
    url = str(body.get('url') or '')
    # An absent/blank token means "keep the one already stored"; an explicit
    # ``clear_token`` is the only way to remove it.
    tok = body.get('token')
    if tok is not None and not str(tok).strip():
        tok = None
    if body.get('clear_token'):
        tok = ''
    try:
        saved = client.save_config(url, tok)
    except Exception as exc:
        return _error(f'could not save settings: {exc}', 400)
    return jsonify({'success': True, **saved, 'health': client.health()})


@netdata_bp.post('/api/netdata/ingest')
def api_ingest():
    from alerting import engine
    try:
        result = engine.poll_netdata_alerts(meta=True)
    except Exception as exc:
        log.warning('[netdata] ingest failed: %s', exc)
        return _error(f'ingest failed: {exc}', 502)
    return jsonify({'success': True, **result})


@netdata_bp.get('/api/netdata/evidence')
def api_evidence():
    """Debug/explain endpoint: exactly what the AI report would be shown."""
    host = (request.args.get('host') or '').strip()
    minutes = request.args.get('window', type=int) or 60
    data = evidence.for_host(host, host, minutes)
    return jsonify({'success': True, 'evidence': data,
                    'rendered': evidence.render(data)})


@netdata_bp.get('/api/netdata/quality')
def api_quality():
    try:
        return jsonify({'success': True, **client.streaming_health()})
    except client.NetdataError as exc:
        return _error(str(exc), exc.status or 502)
