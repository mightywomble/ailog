"""Orchestration: plan -> apply -> waves -> verify -> audit.

The runner does the work; this module owns the state machine and the
safety interlocks (scope caps, windows, halt thresholds, cancellation,
rollback, retention). It runs inside a worker thread with the Flask app
context, exactly like the report pipeline.
"""

from __future__ import annotations

import datetime
import json
import logging
import math
import threading
import time
import traceback
import uuid as uuid_lib
from pathlib import Path

from remediation import catalog, inventory, planner, policy, progress, runner, verify

log = logging.getLogger(__name__)

_semaphore = threading.BoundedSemaphore(4)
# A run may wait for a maintenance slot, but not forever: reject anything
# further out than this so a typo cannot park a job for years.
MAX_SCHEDULE_DAYS = 30
HEARTBEAT_SECONDS = 5


def parse_run_at(raw):
    """Parse an ISO-8601 timestamp from the wizard. Returns (when, error)."""
    if not raw:
        return None, ''
    text = str(raw).strip().replace('Z', '+00:00')
    try:
        when = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None, 'That start time could not be understood.'
    if when.tzinfo is not None:
        when = when.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    now = datetime.datetime.utcnow()
    if when <= now + datetime.timedelta(seconds=30):
        return None, 'Pick a start time at least a minute in the future.'
    if when > now + datetime.timedelta(days=MAX_SCHEDULE_DAYS):
        return None, f'Runs can be scheduled at most {MAX_SCHEDULE_DAYS} days ahead.'
    return when, ''


def waves_for(risk: str, keys: list[str]) -> list[list[str]]:
    keys = list(keys)
    if not keys:
        return []
    if risk == 'low':
        size = max(1, math.ceil(len(keys) / 4))
    else:
        size = 1
    return [keys[i:i + size] for i in range(0, len(keys), size)]


def audit(db, models, actor, action, object_type, object_id, detail=None):
    try:
        db.session.add(models.AuditEvent(
            actor=actor or 'anonymous', action=action, object_type=object_type,
            object_id=str(object_id), detail_json=json.dumps(detail or {}),
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()
        log.exception('audit write failed')


def plan(models, slug: str, scope: str, host_key: str | None, group_id,
         dry_run: bool, match_id=None) -> tuple[dict | None, str, int]:
    entry = catalog.get(slug)
    if not entry:
        return None, 'Unknown remediation.', 404
    targets = planner.resolve(models, slug, scope, host_key, group_id)
    eligible = [t for t in targets if t['eligible']]
    if not eligible:
        reason = targets[0]['why'] if targets else 'No hosts matched this scope.'
        return None, reason, 400
    cap = policy.max_hosts()
    if len(eligible) > cap:
        return None, f'This would touch {len(eligible)} hosts; the cap is {cap}. Narrow the scope.', 400
    if (scope or '').lower() == 'fleet' and entry['risk'] != 'low':
        return None, 'Only low-risk remediations can run against the fleet.', 400

    keys = [t['host_key'] for t in eligible]
    token, fingerprint = planner.make_token(slug, keys, bool(dry_run))
    waves = waves_for(entry['risk'], keys)
    return {
        'slug': slug,
        'title': entry['title'],
        'risk': entry['risk'],
        'scope': scope,
        'dry_run': bool(dry_run),
        'token': token,
        'fingerprint': fingerprint,
        'expires_in': planner.TOKEN_TTL,
        'entry': {k: entry[k] for k in ('title', 'summary', 'risk', 'est_seconds',
                                        'changes', 'does_not', 'requires')},
        'code': entry['playbook_text'],
        'verify': entry['verify_text'],
        'rollback': entry['rollback_text'],
        'targets': [{'host_key': t['host_key'], 'label': t['label'],
                     'eligible': t['eligible'], 'why': t['why']} for t in targets],
        'eligible_keys': keys,
        'waves': waves,
    }, '', 200


def start_run(app, models, db, slug: str, token: str, scope: str,
              host_key: str | None, group_id, dry_run: bool, match_id, actor: str,
              run_at=None):
    entry = catalog.get(slug)
    if not entry:
        return None, 'Unknown remediation.', 404
    targets = planner.resolve(models, slug, scope, host_key, group_id)
    eligible = [t for t in targets if t['eligible']]
    if not eligible:
        reason = targets[0]['why'] if targets else 'No hosts matched this scope.'
        return None, reason, 400
    if len(eligible) > policy.max_hosts():
        return None, f'Too many hosts (cap {policy.max_hosts()}).', 400
    keys = [t['host_key'] for t in eligible]

    ok, message = planner.check_token(token, slug, keys, bool(dry_run))
    if not ok:
        return None, message, 400

    when, when_error = parse_run_at(run_at)
    if when_error:
        return None, when_error, 400

    capped = [t for t in eligible if not policy.run_rate_limited(db, models, t['host_key'], slug)]
    if not capped:
        return None, 'This host already ran this remedy in the last 10 minutes.', 429

    run = models.RemediationRun(
        uuid=str(uuid_lib.uuid4()), slug=slug, match_id=match_id,
        dry_run=bool(dry_run), scope=scope or 'host', requested_by=actor,
        confirm_fingerprint=planner.fingerprint(slug, keys, bool(dry_run)),
        state='scheduled' if when else 'queued',
        scheduled_for=when,
    )
    db.session.add(run)
    db.session.flush()
    for target in capped:
        db.session.add(models.RemediationTarget(
            run_id=run.id, host_key=target['host_key'], host_label=target['label'], state='pending'))
    db.session.commit()

    progress.start(run.uuid)
    if when:
        progress.emit(run.uuid, {'type': 'stage', 'stage': 'scheduled',
                                 'message': f"Scheduled {entry['title']} for {when.isoformat()}Z."})
        audit(db, models, actor, 'remediation.schedule', 'remediation_run', run.uuid,
              {'slug': slug, 'hosts': keys, 'dry_run': bool(dry_run),
               'scope': scope, 'run_at': when.isoformat()})
        _schedule_run(app, run.uuid, when)
        return run, '', 202

    progress.emit(run.uuid, {'type': 'stage', 'stage': 'queued',
                             'message': f"Queued {entry['title']} for {len(capped)} host(s)."})
    audit(db, models, actor, 'remediation.apply', 'remediation_run', run.uuid,
          {'slug': slug, 'hosts': keys, 'dry_run': bool(dry_run), 'scope': scope})

    thread = threading.Thread(target=_execute, args=(app, run.uuid), daemon=True)
    thread.start()
    return run, '', 202


def _schedule_run(app, run_uuid: str, when: datetime.datetime):
    """Fire _execute at `when` using the app's APScheduler, else a timer."""
    scheduler = getattr(app, 'scheduler', None)
    args = (app, run_uuid)
    if scheduler is not None:
        try:
            scheduler.add_job(func=_scheduled_start, trigger='date', run_date=when,
                              args=args, id=f'remediation-{run_uuid}',
                              replace_existing=True, misfire_grace_time=3600)
            return
        except Exception:
            log.exception('could not register the scheduled run; falling back to a timer')
    delay = max(1.0, (when - datetime.datetime.utcnow()).total_seconds())
    timer = threading.Timer(delay, _scheduled_start, args=args)
    timer.daemon = True
    timer.start()


def _scheduled_start(app, run_uuid: str):
    """Promote a scheduled run to queued, unless it was cancelled meanwhile."""
    with app.app_context():
        from database import db
        import database as models
        run = models.RemediationRun.query.filter_by(uuid=run_uuid).first()
        if not run or run.state != 'scheduled':
            return
        run.state = 'queued'
        run.started_at = datetime.datetime.utcnow()
        db.session.commit()
        progress.emit(run_uuid, {'type': 'stage', 'stage': 'queued',
                                 'message': 'Maintenance slot reached: starting the run.'})
        threading.Thread(target=_execute, args=(app, run_uuid), daemon=True).start()


def _execute(app, run_uuid: str):
    with app.app_context():
        from database import db
        import database as models
        run = models.RemediationRun.query.filter_by(uuid=run_uuid).first()
        if not run:
            return
        acquired = _semaphore.acquire(timeout=900)
        if not acquired:
            _fail(db, models, run, 'Timed out waiting for a free execution slot.', run_uuid)
            return
        try:
            _execute_inner(app, db, models, run, run_uuid)
        except Exception as exc:
            log.error('remediation run %s crashed: %s', run_uuid, traceback.format_exc())
            _fail(db, models, run, f'{exc}', run_uuid)
        finally:
            _semaphore.release()
            try:
                policy.prune_artifacts()
            except Exception:
                pass


def _fail(db, models, run, message, run_uuid):
    try:
        run.state = 'failed'
        run.error = str(message)[:2000]
        run.finished_at = datetime.datetime.utcnow()
        for target in run.targets:
            if target.state in ('pending', 'running'):
                target.state = 'failed'
        db.session.commit()
    except Exception:
        db.session.rollback()
    progress.emit(run_uuid, {'type': 'error', 'message': str(message)[:1000]})
    progress.finish(run_uuid, 'failed')


def _execute_inner(app, db, models, run, run_uuid):
    entry = catalog.get(run.slug)
    if not entry:
        return _fail(db, models, run, 'The catalog entry disappeared.', run_uuid)

    run.state = 'checking' if run.dry_run else 'applying'
    db.session.commit()
    progress.emit(run_uuid, {'type': 'stage', 'stage': run.state,
                             'message': ('Dry run: --check --diff' if run.dry_run else 'Applying changes')})

    targets = list(run.targets)
    hosts = {}
    for target in targets:
        try:
            hosts[target.host_key] = models.Host.query.get(int(target.host_key.split('-', 1)[1]))
        except (ValueError, TypeError):
            hosts[target.host_key] = None

    # before-probe (independent of ansible)
    for target in targets:
        host = hosts.get(target.host_key)
        if not host:
            target.state = 'skipped'
            continue
        progress.emit(run_uuid, {'type': 'target', 'host_key': target.host_key,
                                 'label': target.host_label, 'state': 'probing'})
        result = verify.run_probe(host, entry['verify'])
        target.before_json = json.dumps(result)
    db.session.commit()

    keys = [t.host_key for t in targets if t.state != 'skipped']
    risk = entry['risk']
    failed_total = 0
    consecutive = 0
    halted = False
    run_dir = Path(policy.artifact_root()) / run_uuid
    run.artifact_dir = str(run_dir)
    db.session.commit()

    for index, wave in enumerate(waves_for(risk, keys), start=1):
        if progress.cancelled(run_uuid):
            halted = True
            progress.emit(run_uuid, {'type': 'stage', 'stage': 'cancelled', 'message': 'Cancelled by user.'})
            break
        wave_hosts = [hosts[k] for k in wave if hosts.get(k)]
        if not wave_hosts:
            continue
        progress.emit(run_uuid, {'type': 'stage', 'stage': 'wave',
                                 'message': f'Wave {index}: {len(wave_hosts)} host(s)'})
        labels = ', '.join(h.friendly_name or h.hostname or inventory.host_key(h) for h in wave_hosts)
        for key in wave:
            progress.emit(run_uuid, {'type': 'target', 'host_key': key, 'state': 'connecting'})
        progress.emit(run_uuid, {'type': 'stage', 'stage': 'connecting',
                                 'message': f'Connecting to {labels} over SSH…'})

        # A wave can take minutes (SSH, sudo, apt-less playbooks). Emit a
        # heartbeat so the console shows elapsed time instead of looking hung.
        beat_stop = threading.Event()
        beat_started = time.time()

        def _beat():
            while not beat_stop.wait(HEARTBEAT_SECONDS):
                progress.emit(run_uuid, {'type': 'heartbeat', 'stage': 'running',
                                         'elapsed': int(time.time() - beat_started)})

        seen_connected = set()

        def _on_event(event):
            host = event.get('host')
            kind = str(event.get('event') or '')
            if host and host not in seen_connected and kind.startswith('runner_on_'):
                seen_connected.add(host)
                progress.emit(run_uuid, {'type': 'stage', 'stage': 'connected',
                                         'host': host,
                                         'message': f'{host}: connected, running tasks'})
            progress.emit(run_uuid, event)

        beater = threading.Thread(target=_beat, daemon=True)
        beater.start()
        try:
            result = runner.run_playbook(
                entry['playbook'], inventory.build(wave_hosts),
                [inventory.host_key(h) for h in wave_hosts],
                {'remediation_target': ''}, bool(run.dry_run),
                run_dir / f'wave-{index}', timeout=policy.run_timeout(),
                on_event=_on_event,
            )
            rc, host_results = result['rc'], result['hosts']
        except Exception as exc:
            log.warning('wave %s failed to start: %s', index, exc)
            rc, host_results = 1, {}
            for key in wave:
                host_results[key] = {'ok': False, 'changed': 0, 'failed': True, 'output': str(exc)}
        finally:
            beat_stop.set()
        progress.emit(run_uuid, {'type': 'stage', 'stage': 'finished-wave',
                                 'message': f'Wave {index} finished in {int(time.time() - beat_started)}s.'})

        for key in wave:
            target = next((t for t in targets if t.host_key == key), None)
            if not target:
                continue
            info = host_results.get(key) or {'ok': rc == 0, 'changed': 0, 'failed': rc != 0, 'output': ''}
            target.exit_code = rc
            target.changed_tasks = int(info.get('changed') or 0)
            target.output = (info.get('output') or '')[-20000:]
            if run.dry_run:
                target.state = 'checked' if info.get('ok') else 'failed'
            elif not info.get('ok'):
                target.state = 'failed'
                failed_total += 1
                consecutive += 1
            else:
                target.state = 'verifying'
                consecutive = 0
            progress.emit(run_uuid, {'type': 'target', 'host_key': key,
                                     'state': target.state, 'changed': target.changed_tasks})
        db.session.commit()

        if not run.dry_run:
            _verify_wave(db, models, run, run_uuid, entry, targets, hosts, wave)
            failed_total = sum(1 for t in targets if t.state == 'failed')
            if failed_total > max(1, math.ceil(len(keys) * 0.2)) or consecutive >= 2:
                halted = True
                progress.emit(run_uuid, {'type': 'stage', 'stage': 'halt',
                                         'message': f'Stopping after {failed_total} failure(s).'})
                break

    if halted:
        for target in targets:
            if target.state in ('pending', 'verifying'):
                target.state = 'skipped'

    if not run.dry_run:
        _rollback_failed(db, models, run, run_uuid, entry, hosts)

    summary = {}
    for target in targets:
        summary[target.state] = summary.get(target.state, 0) + 1
    run.summary_json = json.dumps(summary)
    run.finished_at = datetime.datetime.utcnow()
    if progress.cancelled(run_uuid):
        run.state = 'cancelled'
    elif halted and summary.get('failed'):
        run.state = 'failed'
    elif summary.get('failed'):
        run.state = 'failed'
    elif run.dry_run:
        run.state = 'checked'
    elif summary.get('healed'):
        run.state = 'healed' if not summary.get('applied') else 'applied_unverified'
    else:
        run.state = 'applied_unverified'
    db.session.commit()

    audit(db, models, run.requested_by, 'remediation.finished', 'remediation_run', run_uuid,
          {'state': run.state, 'summary': summary})
    progress.emit(run_uuid, {'type': 'result', 'state': run.state, 'summary': summary})
    progress.finish(run_uuid, run.state)

    healed_hosts = [t.host_key for t in targets if t.state == 'healed']
    if healed_hosts and policy.closure_enabled():
        _schedule_closure(app, healed_hosts)


def _verify_wave(db, models, run, run_uuid, entry, targets, hosts, wave):
    verify.settle(entry['verify'].get('settle_seconds', 30), policy.settle_cap(),
                  cancelled=lambda: progress.cancelled(run_uuid))
    for key in wave:
        target = next((t for t in targets if t.host_key == key), None)
        if not target or target.state in ('failed', 'skipped'):
            continue
        host = hosts.get(key)
        if not host:
            target.state = 'skipped'
            continue
        result = verify.run_probe(host, entry['verify'])
        target.after_json = json.dumps(result)
        target.state = 'healed' if result.get('ok') else 'failed'
        progress.emit(run_uuid, {'type': 'verify', 'host_key': key,
                                 'state': target.state, 'detail': result.get('detail')})
    db.session.commit()


def _rollback_failed(db, models, run, run_uuid, entry, hosts):
    if not entry.get('rollback'):
        return
    failures = [t for t in run.targets if t.state == 'failed' and t.host_key in hosts]
    if not failures:
        return
    progress.emit(run_uuid, {'type': 'stage', 'stage': 'rollback',
                             'message': f'Rolling back {len(failures)} host(s)...'})
    for target in failures:
        host = hosts.get(target.host_key)
        try:
            result = runner.run_playbook(
                entry['rollback'], inventory.build([host]), [target.host_key],
                {'remediation_target': ''}, False,
                Path(run.artifact_dir or policy.artifact_root()) / f'rollback-{target.host_key}',
                timeout=policy.run_timeout())
            target.rollback_state = 'rolled_back' if result['rc'] == 0 else 'rollback_failed'
        except Exception as exc:
            log.warning('rollback failed for %s: %s', target.host_key, exc)
            target.rollback_state = 'rollback_failed'
    db.session.commit()


def _schedule_closure(app, host_keys):
    try:
        scheduler = getattr(app, 'scheduler', None)
        if scheduler is None:
            return
        for host_key in host_keys:
            scheduler.add_job(
                func=run_closure_report,
                trigger='date',
                run_date=datetime.datetime.now() + datetime.timedelta(minutes=15),
                args=[app, host_key],
                id=f'remediation-closure-{host_key}',
                replace_existing=True,
            )
    except Exception:
        log.exception('could not schedule closure report')


def run_closure_report(app, host_key: str):
    """Re-run the report 15 minutes after a heal so the fix can be proven."""
    with app.app_context():
        try:
            from serverreport.routes import run_pipeline
            config = app.load_config()
            provider = config.get('analysis_provider', 'openai')
            run_pipeline(host_key, host_key, 120, provider, None, config, use_cache=False)
        except Exception:
            log.exception('closure report failed for %s', host_key)