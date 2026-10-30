"""HTTP surface for remediation: cards, plans, runs, policy pages."""

from __future__ import annotations

import json
import logging

from flask import Blueprint, Response, current_app, g, jsonify, render_template, request, stream_with_context

from remediation import catalog, policy, progress, runner, service

log = logging.getLogger(__name__)
remediation_bp = Blueprint('remediation', __name__)
STREAM_HEADERS = {'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}


def _models():
    import database
    return database


def _db():
    from database import db
    return db


def _actor():
    return getattr(g, 'auth_user', None) or 'anonymous'


def _disabled():
    return jsonify({'error': 'Remediation is disabled. Set AILOG_ALLOW_REMEDIATION=dry_run or on.'}), 403


def _mode_payload():
    return {
        'mode': policy.mode(),
        'enabled': policy.enabled(),
        'forced_dry_run': policy.forced_dry_run(),
        'max_hosts': policy.max_hosts(),
        'idea_channel': policy.idea_channel_enabled(),
        'runner_available': runner.available(),
    }


@remediation_bp.route('/api/reports/<int:report_id>/remediations')
def api_report_cards(report_id: int):
    models = _models()
    report = models.LogReport.query.get(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    cards = (models.RemediationMatch.query
             .filter_by(report_id=report_id)
             .order_by(models.RemediationMatch.source.desc(),
                       models.RemediationMatch.confidence.desc())
             .all())
    return jsonify({'report_id': report_id, 'host_key': report.host_key,
                    'policy': _mode_payload(),
                    'cards': [card.to_dict() for card in cards]})


@remediation_bp.route('/api/reports/<int:report_id>/remediations/refresh', methods=['POST'])
def api_refresh_cards(report_id: int):
    models, db = _models(), _db()
    report = models.LogReport.query.get(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    from remediation import matcher
    summary = matcher.match_report(report, models, db, with_ideas=False)
    return jsonify({'ok': True, 'summary': summary})


@remediation_bp.route('/api/remediation-matches/<int:match_id>/dismiss', methods=['POST'])
def api_dismiss(match_id: int):
    models, db = _models(), _db()
    card = models.RemediationMatch.query.get(match_id)
    if not card:
        return jsonify({'error': 'Card not found'}), 404
    data = request.get_json(silent=True) or {}
    reason = str(data.get('reason') or 'other')
    if reason not in policy.REASONS:
        reason = 'other'
    card.state = 'dismissed'
    card.dismissed_reason = reason
    db.session.commit()
    service.audit(db, models, _actor(), 'remediation.dismiss', 'remediation_match', card.id,
                  {'reason': reason, 'slug': card.slug})
    return jsonify({'ok': True})


@remediation_bp.route('/api/remediations/<slug>/plan', methods=['POST'])
def api_plan(slug: str):
    if not policy.enabled():
        return _disabled()
    models = _models()
    data = request.get_json(silent=True) or {}
    dry_run = bool(data.get('dry_run', True)) or policy.forced_dry_run()
    payload, error, code = service.plan(
        models, slug, data.get('scope') or 'host', data.get('host_key'),
        data.get('group_id'), dry_run, data.get('match_id'),
    )
    if error:
        return jsonify({'error': error}), code
    return jsonify(payload)


@remediation_bp.route('/api/remediations/<slug>/apply', methods=['POST'])
def api_apply(slug: str):
    if not policy.enabled():
        return _disabled()
    if not runner.available():
        return jsonify({'error': 'ansible-runner is not installed in this image.'}), 503
    models, db = _models(), _db()
    data = request.get_json(silent=True) or {}
    dry_run = bool(data.get('dry_run', True)) or policy.forced_dry_run()
    run, error, code = service.start_run(
        current_app._get_current_object(), models, db, slug,
        str(data.get('token') or ''), data.get('scope') or 'host',
        data.get('host_key'), data.get('group_id'), dry_run,
        data.get('match_id'), _actor(),
    )
    if error:
        return jsonify({'error': error}), code
    return jsonify({'ok': True, 'uuid': run.uuid, 'state': run.state}), 202


@remediation_bp.route('/api/remediation-runs/<run_uuid>')
def api_run(run_uuid: str):
    models = _models()
    run = models.RemediationRun.query.filter_by(uuid=run_uuid).first()
    if not run:
        return jsonify({'error': 'Run not found'}), 404
    return jsonify(run.to_dict())


@remediation_bp.route('/api/remediation-runs/<run_uuid>/stream')
def api_run_stream(run_uuid: str):
    def generate():
        yield ': connected\n\n'
        yield 'retry: 3000\n\n'
        if not progress.is_done(run_uuid) and not progress.snapshot(run_uuid):
            models = _models()
            run = models.RemediationRun.query.filter_by(uuid=run_uuid).first()
            if not run:
                yield 'data: ' + json.dumps({'type': 'error', 'message': 'Run not found'}) + '\n\n'
                return
            yield 'data: ' + json.dumps({'type': 'result', 'state': run.state,
                                          'summary': run.to_dict().get('summary', {})}) + '\n\n'
            return
        for event in progress.stream(run_uuid):
            yield 'data: ' + json.dumps(event, default=str) + '\n\n'

    return Response(stream_with_context(generate()), mimetype='text/event-stream', headers=STREAM_HEADERS)


@remediation_bp.route('/api/remediation-runs/<run_uuid>/cancel', methods=['POST'])
def api_cancel(run_uuid: str):
    ok = progress.cancel(run_uuid)
    return jsonify({'ok': ok})


@remediation_bp.route('/api/remediation-runs/<run_uuid>/rollback', methods=['POST'])
def api_rollback(run_uuid: str):
    if not policy.enabled():
        return _disabled()
    models, db = _models(), _db()
    run = models.RemediationRun.query.filter_by(uuid=run_uuid).first()
    if not run:
        return jsonify({'error': 'Run not found'}), 404
    entry = catalog.get(run.slug or '')
    if not entry or not entry.get('rollback'):
        return jsonify({'error': 'This remediation has no rollback playbook.'}), 400
    done = []
    for target in run.targets:
        if target.state not in ('failed', 'healed') or target.rollback_state == 'rolled_back':
            continue
        try:
            host = models.Host.query.get(int(target.host_key.split('-', 1)[1]))
        except (ValueError, TypeError):
            continue
        if not host:
            continue
        try:
            from remediation import inventory
            result = runner.run_playbook(
                entry['rollback'], inventory.build([host]), [target.host_key],
                {'remediation_target': ''}, False,
                policy.artifact_root() / f'manual-rollback-{run_uuid}',
                timeout=policy.run_timeout(),
            )
            target.rollback_state = 'rolled_back' if result['rc'] == 0 else 'rollback_failed'
        except Exception as exc:
            target.rollback_state = f'rollback_failed: {exc}'[:64]
        done.append(target.host_key)
    db.session.commit()
    service.audit(db, models, _actor(), 'remediation.rollback', 'remediation_run', run_uuid,
                  {'hosts': done})
    return jsonify({'ok': True, 'hosts': done})


@remediation_bp.route('/api/remediation-runs')
def api_runs():
    models = _models()
    limit = min(int(request.args.get('limit') or 50), 200)
    runs = (models.RemediationRun.query
            .order_by(models.RemediationRun.started_at.desc()).limit(limit).all())
    return jsonify({'runs': [run.to_dict() for run in runs]})


@remediation_bp.route('/api/remediation/settings')
def api_settings():
    return jsonify({'policy': _mode_payload(),
                    'catalog': [entry for entry in (row.to_dict() for row in _models().Remediation.query.all())]})


@remediation_bp.route('/api/remediation/windows', methods=['GET', 'POST'])
def api_windows():
    models, db = _models(), _db()
    if request.method == 'GET':
        rows = models.RemediationWindow.query.order_by(models.RemediationWindow.name).all()
        return jsonify({'windows': [row.to_dict() for row in rows]})
    data = request.get_json(silent=True) or {}
    window = models.RemediationWindow(
        name=str(data.get('name') or 'Window')[:128],
        group_id=data.get('group_id') or None,
        tag_id=data.get('tag_id') or None,
        days=str(data.get('days') or '1,2,3,4,5,6,7'),
        start_time=str(data.get('start_time') or '22:00'),
        end_time=str(data.get('end_time') or '02:00'),
        timezone=str(data.get('timezone') or 'UTC'),
        mode='block' if data.get('mode') != 'warn' else 'warn',
    )
    db.session.add(window)
    db.session.commit()
    service.audit(db, models, _actor(), 'remediation.window.create', 'remediation_window', window.id,
                  window.to_dict())
    return jsonify({'ok': True, 'window': window.to_dict()}), 201


@remediation_bp.route('/api/remediation/windows/<int:window_id>', methods=['DELETE'])
def api_window_delete(window_id: int):
    models, db = _models(), _db()
    window = models.RemediationWindow.query.get(window_id)
    if not window:
        return jsonify({'error': 'Window not found'}), 404
    db.session.delete(window)
    db.session.commit()
    service.audit(db, models, _actor(), 'remediation.window.delete', 'remediation_window', window_id)
    return jsonify({'ok': True})


@remediation_bp.route('/api/remediation/hosts/<host_key>/protect', methods=['POST'])
def api_protect(host_key: str):
    models, db = _models(), _db()
    try:
        host = models.Host.query.get(int(host_key.split('-', 1)[1]))
    except (ValueError, TypeError):
        host = None
    if not host:
        return jsonify({'error': 'Host not found'}), 404
    data = request.get_json(silent=True) or {}
    host.do_not_remediate = bool(data.get('protected'))
    db.session.commit()
    service.audit(db, models, _actor(), 'remediation.protect', 'host', host_key,
                  {'protected': host.do_not_remediate})
    return jsonify({'ok': True, 'protected': host.do_not_remediate})


@remediation_bp.route('/remediation')
def page():
    models = _models()
    try:
        catalog.sync(_db(), models.Remediation)
    except Exception:
        log.exception('catalog sync failed')
    runs = (models.RemediationRun.query
            .order_by(models.RemediationRun.started_at.desc()).limit(30).all())
    return render_template(
        'remediation.html',
        policy=_mode_payload(),
        remediation_catalog=models.Remediation.query.order_by(models.Remediation.risk, models.Remediation.title).all(),
        windows=models.RemediationWindow.query.order_by(models.RemediationWindow.name).all(),
        groups=models.Group.query.order_by(models.Group.name).all(),
        runs=runs,
        hosts=models.Host.query.order_by(models.Host.hostname).all(),
    )


@remediation_bp.route('/remediation/runs/<run_uuid>')
def run_page(run_uuid: str):
    models = _models()
    run = models.RemediationRun.query.filter_by(uuid=run_uuid).first()
    if not run:
        return Response('Run not found', status=404)
    return render_template('remediation_run.html', run=run, policy=_mode_payload())