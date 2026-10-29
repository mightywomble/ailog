"""Alerting routes: rules CRUD, active/history events, test delivery."""

from __future__ import annotations


from flask import (Blueprint, jsonify, render_template, request)

from . import engine

alerts_bp = Blueprint('alerts', __name__)


def _json_body():
    return request.get_json(silent=True) or {}


@alerts_bp.route('/alerts')
def alerts_page():
    engine.seed_defaults()
    return render_template('alerts.html',
                           metrics=engine.METRICS,
                           ops=engine.OPS)


@alerts_bp.route('/api/alerts/rules', methods=['GET', 'POST'])
def api_rules():
    if request.method == 'GET':
        engine.seed_defaults()
        return jsonify({'success': True, 'rules': engine.all_rules(),
                        'metrics': {k: list(v) for k, v in engine.METRICS.items()},
                        'ops': list(engine.OPS)})
    try:
        rule = engine.create_rule(_json_body())
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400
    return jsonify({'success': True, 'rule': rule})


@alerts_bp.route('/api/alerts/rules/<int:rule_id>', methods=['PUT', 'DELETE'])
def api_rule(rule_id):
    if request.method == 'DELETE':
        ok = engine.delete_rule(rule_id)
        if not ok:
            return jsonify({'success': False, 'error': 'rule not found'}), 404
        return jsonify({'success': True})
    rule = engine.update_rule(rule_id, _json_body())
    if not rule:
        return jsonify({'success': False, 'error': 'rule not found'}), 404
    return jsonify({'success': True, 'rule': rule})


@alerts_bp.route('/api/alerts/events')
def api_events():
    limit = request.args.get('limit', type=int) or 50
    host = (request.args.get('host') or '').strip() or None
    return jsonify({
        'success': True,
        'active': engine.active_events(),
        'events': engine.recent_events(limit=min(max(limit, 1), 500), host_key=host),
    })


@alerts_bp.route('/api/alerts/state')
def api_state():
    return jsonify({'success': True, 'state': engine.state_snapshot()})


@alerts_bp.route('/api/alerts/test', methods=['POST'])
def api_test():
    ok, error = engine.send_test()
    return jsonify({'success': bool(ok), 'error': error}), (200 if ok else 502)


@alerts_bp.route('/api/alerts/evaluate', methods=['POST'])
def api_evaluate():
    """Manual evaluation from a JSON payload (used by tests and debugging)."""
    body = _json_body()
    host = body.get('host') or 'local'
    values = body.get('values') or {}
    fired = engine.evaluate(host, values)
    return jsonify({'success': True, 'fired': fired})
