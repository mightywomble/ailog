"""HTTP surface for remediation: cards, plans, runs, policy pages."""

from __future__ import annotations

import datetime
import json
import logging
import re
import uuid
from pathlib import Path

from flask import Blueprint, Response, current_app, g, jsonify, render_template, request, stream_with_context

from remediation import catalog, inventory, policy, progress, runner, service

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


@remediation_bp.route('/api/reports/<int:report_id>/ideas', methods=['POST'])
def api_generate_ideas(report_id: int):
    """Ask the model for Ansible playbooks the catalog did not cover.

    This is the button on the "no catalog remedy matches" state: it never
    executes anything, it only adds unverified cards.
    """
    models, db = _models(), _db()
    report = models.LogReport.query.get(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    if not policy.idea_channel_enabled():
        return jsonify({'error': 'The AI suggestion channel is disabled '
                                 '(AILOG_REMEDIATION_IDEAS=off).'}), 403
    from remediation import matcher
    existing = (models.RemediationMatch.query
                .filter_by(report_id=report_id, source='llm').all())
    if existing:
        return jsonify({'ok': True, 'ideas': len(existing), 'already': True})
    summary = matcher.match_report(report, models, db, with_ideas=True)
    return jsonify({'ok': True, 'ideas': summary.get('ideas', 0),
                    'suppressed': summary.get('suppressed') or ''})


def _host_for(models, host_key):
    if not host_key:
        return None
    try:
        return models.Host.query.get(int(str(host_key).split('-', 1)[1]))
    except (ValueError, TypeError, IndexError):
        return None


def _idea_paths(run_dir: Path, match_id: int):
    playbooks = run_dir / 'project' / 'remediations' / 'playbooks'
    playbooks.mkdir(parents=True, exist_ok=True)
    return playbooks, Path('playbooks') / f'idea-{match_id}.yml'


def _write_idea_playbook(run_dir: Path, match_id: int, text: str) -> str:
    playbooks, relative = _idea_paths(run_dir, match_id)
    (playbooks / relative.name).write_text(text if text.endswith('\n') else text + '\n',
                                           encoding='utf-8')
    return str(relative)


@remediation_bp.route('/api/remediation-matches/<int:match_id>/test', methods=['POST'])
def api_test_idea(match_id: int):
    """Run an AI playbook with `--check --diff` on its host. Read-only.

    Check mode connects, gathers and reports what *would* change; it cannot
    apply anything, so an untrusted suggestion can be exercised safely before
    a human decides to run it for real.
    """
    models, db = _models(), _db()
    card = models.RemediationMatch.query.get(match_id)
    if not card or card.source != 'llm':
        return jsonify({'error': 'Only AI suggestions can be tested here.'}), 404
    if not policy.enabled():
        return _disabled()
    if not runner.available():
        return jsonify({'error': 'ansible-runner is not installed in this image.'}), 503
    host = _host_for(models, card.host_key)
    if not host:
        return jsonify({'error': f'No host for {card.host_key!r}.'}), 404
    if getattr(host, 'do_not_remediate', False):
        return jsonify({'error': 'This host is protected from remediation.'}), 403
    text = (card.code_text or '').strip()
    if not text:
        return jsonify({'error': 'This suggestion has no playbook.'}), 400

    run_uuid = uuid.uuid4().hex
    run_dir = Path(policy.artifact_root()) / 'ideas' / run_uuid
    try:
        runner.ensure_project(run_dir)
        playbook = _write_idea_playbook(run_dir, match_id, text)
        started = datetime.datetime.utcnow()
        result = runner.run_playbook(
            playbook, inventory.build([host]), [inventory.host_key(host)], {},
            True, run_dir, timeout=min(180, policy.run_timeout()),
        )
    except Exception as exc:  # noqa: BLE001 - shown to the user
        log.exception('idea test failed')
        return jsonify({'error': f'The check could not run: {exc}'}), 500

    key = inventory.host_key(host)
    detail = (result.get('hosts') or {}).get(key) or {}
    ok = bool(detail.get('ok')) and int(result.get('rc') or 0) == 0
    service.audit(db, models, _actor(), 'remediation.idea_test', 'remediation_match', match_id,
                  {'host': card.host_key, 'rc': result.get('rc'), 'ok': ok,
                   'seconds': (datetime.datetime.utcnow() - started).total_seconds()})
    return jsonify({
        'ok': ok,
        'check_only': True,
        'rc': result.get('rc'),
        'status': result.get('status'),
        'changed': result.get('changed'),
        'output': (detail.get('output') or '')[-12000:],
        'artifact_dir': result.get('artifact_dir'),
    })


def _slugify(text: str) -> str:
    slug = re.sub(r'[^a-z0-9]+', '-', (text or '').lower()).strip('-')
    return (slug[:70] or 'learned-remedy')


@remediation_bp.route('/api/remediation-matches/<int:match_id>/confirm', methods=['POST'])
def api_confirm_idea(match_id: int):
    """Record the human verdict on an AI suggestion.

    worked=true promotes the playbook into the learned library (visible on
    /remediation, offered back to the idea channel). worked=false marks the
    card as rejected so it stops asking.
    """
    models, db = _models(), _db()
    card = models.RemediationMatch.query.get(match_id)
    if not card or card.source != 'llm':
        return jsonify({'error': 'Only AI suggestions can be confirmed here.'}), 404
    data = request.get_json(silent=True) or {}
    worked = bool(data.get('worked'))
    notes = str(data.get('notes') or '').strip()[:1000]

    if not worked:
        card.state = 'rejected'
        card.dismissed_reason = 'tried_failed'
        db.session.commit()
        service.audit(db, models, _actor(), 'remediation.idea_rejected',
                      'remediation_match', match_id, {'notes': notes})
        return jsonify({'ok': True, 'learned': None})

    title = str(data.get('title') or '').strip()[:200] or card.title
    base = 'learned-' + _slugify(title)
    slug, suffix = base, 2
    while models.RemediationLearned.query.filter_by(slug=slug).first():
        slug = f'{base}-{suffix}'
        suffix += 1

    row = models.RemediationLearned(
        slug=slug, title=title, summary=(card.rationale or card.summary or '')[:2000],
        risk=card.risk or 'medium', yaml_text=card.code_text or '',
        verify_text=card.verify_text, rollback_text=card.rollback_text,
        source_report_id=card.report_id, source_match_id=card.id,
        host_key=card.host_key, confirmed_by=_actor(),
    )
    db.session.add(row)
    card.state = 'confirmed'
    db.session.commit()
    service.audit(db, models, _actor(), 'remediation.idea_promoted', 'remediation_learned',
                  row.id, {'slug': slug, 'match_id': match_id, 'notes': notes})
    return jsonify({'ok': True, 'learned': row.to_dict()})


@remediation_bp.route('/api/remediation/learned')
def api_learned():
    models = _models()
    rows = (models.RemediationLearned.query
            .order_by(models.RemediationLearned.confirmed_at.desc()).all())
    return jsonify({'learned': [row.to_dict() for row in rows]})


@remediation_bp.route('/api/remediation/learned/<int:row_id>', methods=['DELETE'])
def api_learned_delete(row_id: int):
    models, db = _models(), _db()
    row = models.RemediationLearned.query.get(row_id)
    if not row:
        return jsonify({'error': 'Not found'}), 404
    slug = row.slug
    db.session.delete(row)
    db.session.commit()
    service.audit(db, models, _actor(), 'remediation.learned_deleted',
                  'remediation_learned', row_id, {'slug': slug})
    return jsonify({'ok': True})


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
        data.get('match_id'), _actor(), run_at=data.get('run_at'),
    )
    if error:
        return jsonify({'error': error}), code
    return jsonify({'ok': True, 'uuid': run.uuid, 'state': run.state,
                    'scheduled_for': run.to_dict(False).get('scheduled_for')}), 202


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
    """Cancel a running wave, or unschedule a run that is waiting."""
    models, db = _models(), _db()
    run = models.RemediationRun.query.filter_by(uuid=run_uuid).first()
    if run and run.state == 'scheduled':
        run.state = 'cancelled'
        run.finished_at = datetime.datetime.utcnow()
        for target in run.targets:
            if target.state == 'pending':
                target.state = 'skipped'
        db.session.commit()
        _drop_scheduled_job(current_app._get_current_object(), run_uuid)
        progress.emit(run_uuid, {'type': 'stage', 'stage': 'cancelled',
                                 'message': 'Scheduled run cancelled before it started.'})
        progress.finish(run_uuid, 'cancelled')
        service.audit(db, models, _actor(), 'remediation.cancel', 'remediation_run', run_uuid,
                      {'was': 'scheduled'})
        return jsonify({'ok': True, 'cancelled': 'scheduled'})
    ok = progress.cancel(run_uuid)
    return jsonify({'ok': ok, 'cancelled': 'running' if ok else 'none'})


def _drop_scheduled_job(app, run_uuid: str):
    scheduler = getattr(app, 'scheduler', None)
    if scheduler is None:
        return
    try:
        scheduler.remove_job(f'remediation-{run_uuid}')
    except Exception:
        pass


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
        learned=models.RemediationLearned.query.order_by(
            models.RemediationLearned.confirmed_at.desc()).all(),
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