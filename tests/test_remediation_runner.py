"""The execution state machine, driven by a fake Ansible.

No real host is touched: ``remediation.runner`` is replaced with a stub that
returns scripted per-host results. What is asserted here is the safety
behaviour around it - wave sizing, halting, verification, rollback,
cancellation - not Ansible itself.
"""

from __future__ import annotations

import json

import pytest

from remediation import progress, runner, service, verify


@pytest.fixture()
def models():
    import database
    return database


@pytest.fixture(autouse=True)
def clean_state(monkeypatch):
    # Verification waits for a settle window before probing; tests must not.
    monkeypatch.setattr(verify, 'settle', lambda *a, **kw: None)
    for key in list(getattr(progress, '_streams', {}).keys()):
        progress.finish(key, 'done')
    yield


@pytest.fixture()
def db(ctx):
    from database import (RemediationMatch, RemediationRun, RemediationTarget,
                          RemediationWindow, db)
    RemediationWindow.query.delete()
    RemediationMatch.query.delete()
    RemediationTarget.query.delete()
    RemediationRun.query.delete()
    db.session.commit()
    return db


@pytest.fixture()
def allow_on(monkeypatch):
    monkeypatch.setenv('AILOG_ALLOW_REMEDIATION', 'on')


# --- wave sizing -----------------------------------------------------------


def test_low_risk_runs_in_quarters():
    # ceil(n/4) hosts per wave: 4 hosts -> one at a time, 8 -> two at a time.
    assert service.waves_for('low', ['a', 'b', 'c', 'd']) == [['a'], ['b'], ['c'], ['d']]
    waves = service.waves_for('low', [str(i) for i in range(8)])
    assert [len(w) for w in waves] == [2, 2, 2, 2]
    assert [len(w) for w in service.waves_for('low', [str(i) for i in range(12)])] == [3, 3, 3, 3]


def test_medium_and_high_risk_run_serially():
    for risk in ('medium', 'high'):
        assert [len(w) for w in service.waves_for(risk, ['a', 'b', 'c'])] == [1, 1, 1]


def test_no_hosts_means_no_waves():
    assert service.waves_for('low', []) == []


# --- plan ------------------------------------------------------------------


def test_plan_returns_targets_waves_and_a_token(models, db, host):
    payload, error, code = service.plan(models, 'restart-failed-units', 'host', host, None, True)
    assert error == '' and code == 200
    assert payload['eligible_keys'] == [host]
    assert payload['waves'] == [[host]]
    assert payload['token'] and payload['fingerprint']
    assert payload['risk'] == 'low'
    assert payload['code'], 'the dialog must show what will run'
    assert payload['verify'], 'the dialog must show how it will be tested'


def test_plan_rejects_an_unknown_slug(models, db, host):
    _, error, code = service.plan(models, 'no-such-remedy', 'host', host, None, True)
    assert code == 404
    assert error


def test_plan_refuses_the_fleet_for_medium_risk(models, db, host):
    from database import RemediationMatch
    db.session.add(RemediationMatch(report_id=1, host_key=host, slug='reload-nginx-config',
                                    source='catalog', executable=True, state='open', risk='medium',
                                    title='t', summary='s'))
    db.session.commit()
    _, error, code = service.plan(models, 'reload-nginx-config', 'fleet', None, None, True)
    assert code == 400
    assert 'low-risk' in error


def test_plan_enforces_the_host_cap(models, db, host, monkeypatch):
    monkeypatch.setenv('AILOG_REMEDIATION_MAX_HOSTS', '1')
    from database import RemediationMatch
    second = _extra_host(db)
    for key in (host, second):
        db.session.add(RemediationMatch(report_id=1, host_key=key, slug='restart-failed-units',
                                        source='catalog', executable=True, state='open', risk='low',
                                        title='t', summary='s'))
    db.session.commit()
    _, error, code = service.plan(models, 'restart-failed-units', 'fleet', None, None, True)
    assert code == 400
    assert 'cap' in error


def test_plan_refuses_a_protected_host(models, db, host):
    from database import Host
    row = Host.query.get(int(host.split('-')[1]))
    row.do_not_remediate = True
    db.session.commit()
    _, error, code = service.plan(models, 'restart-failed-units', 'host', host, None, True)
    assert code == 400
    assert 'do-not-remediate' in error


# --- apply contracts -------------------------------------------------------


def test_apply_refuses_a_token_for_a_different_host_set(models, db, host):
    payload, _, _ = service.plan(models, 'restart-failed-units', 'host', host, None, True)
    other = _extra_host(db)
    run, error, code = service.start_run(None, models, db, 'restart-failed-units',
                                         payload['token'], 'host', other, None, True, None, 'tester')
    assert run is None
    assert code == 400
    assert 'no longer matches' in error


def test_apply_refuses_an_expired_token(models, db, host):
    from remediation import planner
    token, _ = planner.make_token('restart-failed-units', [host], True, ttl=-1)
    run, error, code = service.start_run(None, models, db, 'restart-failed-units',
                                         token, 'host', host, None, True, None, 'tester')
    assert run is None and code == 400
    assert 'expired' in error.lower()


def test_a_second_run_of_the_same_remedy_is_rate_limited(models, db, host):
    from database import RemediationRun, RemediationTarget
    run = RemediationRun(uuid='rl-1', slug='restart-failed-units', dry_run=True, scope='host',
                         requested_by='tester', state='checked')
    db.session.add(run)
    db.session.flush()
    db.session.add(RemediationTarget(run_id=run.id, host_key=host, state='checked'))
    db.session.commit()
    from remediation import planner
    token, _ = planner.make_token('restart-failed-units', [host], True)
    result, error, code = service.start_run(None, models, db, 'restart-failed-units',
                                            token, 'host', host, None, True, None, 'tester')
    assert result is None and code == 429


# --- the state machine -----------------------------------------------------


def _run_with_host(flask_app, models, db, host, slug='restart-failed-units', dry_run=False):
    from remediation import planner
    token, _ = planner.make_token(slug, [host], dry_run)
    run, error, code = service.start_run(flask_app, models, db, slug, token, 'host',
                                         host, None, dry_run, None, 'tester')
    assert code == 202, error
    return run


def _wait(models, run_uuid, timeout=15):
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        db_session = models.db.session
        db_session.expire_all()
        run = models.RemediationRun.query.filter_by(uuid=run_uuid).first()
        if run and run.state not in ('queued', 'checking', 'applying'):
            return run
        time.sleep(0.05)
        models.db.session.remove()
    raise AssertionError('run did not finish')


def test_a_successful_apply_heals_and_verifies(flask_app, models, db, host, allow_on, monkeypatch):
    monkeypatch.setattr(runner, 'run_playbook', lambda *a, **kw: {
        'rc': 0, 'status': 'successful',
        'hosts': {host: {'ok': True, 'changed': 1, 'failed': False, 'output': 'ok'}},
        'changed': 1, 'artifact_dir': '/tmp/x', 'stats': {}})
    monkeypatch.setattr(verify, 'run_probe', lambda *a, **kw: {
        'ok': True, 'detail': 'looks good', 'command': 'true', 'stdout': '0', 'stderr': '', 'rc': 0})
    run = _run_with_host(flask_app, models, db, host)
    done = _wait(models, run.uuid)
    assert done.state == 'healed'
    target = done.targets[0]
    assert target.state == 'healed'
    assert json.loads(target.after_json)['ok'] is True
    assert json.loads(done.summary_json) == {'healed': 1}


def test_a_failing_playbook_marks_the_target_failed(flask_app, models, db, host, allow_on, monkeypatch):
    monkeypatch.setattr(runner, 'run_playbook', lambda *a, **kw: {
        'rc': 1, 'status': 'failed',
        'hosts': {host: {'ok': False, 'changed': 0, 'failed': True, 'output': 'boom'}},
        'changed': 0, 'artifact_dir': '/tmp/x', 'stats': {}})
    monkeypatch.setattr(verify, 'run_probe', lambda *a, **kw: {
        'ok': False, 'detail': 'still broken', 'command': 'true', 'stdout': '', 'stderr': '', 'rc': 1})
    run = _run_with_host(flask_app, models, db, host)
    done = _wait(models, run.uuid)
    assert done.state == 'failed'
    assert done.targets[0].state == 'failed'


def test_a_playbook_that_does_not_actually_fix_it_is_not_called_healed(
        flask_app, models, db, host, allow_on, monkeypatch):
    """Ansible says ok; the independent probe says otherwise. The probe wins."""
    monkeypatch.setattr(runner, 'run_playbook', lambda *a, **kw: {
        'rc': 0, 'status': 'successful',
        'hosts': {host: {'ok': True, 'changed': 1, 'failed': False, 'output': 'ok'}},
        'changed': 1, 'artifact_dir': '/tmp/x', 'stats': {}})
    monkeypatch.setattr(verify, 'run_probe', lambda *a, **kw: {
        'ok': False, 'detail': 'command still failing', 'command': 'true',
        'stdout': '1', 'stderr': '', 'rc': 0})
    run = _run_with_host(flask_app, models, db, host)
    done = _wait(models, run.uuid)
    assert done.targets[0].state != 'healed'
    assert done.state in ('failed', 'applied_unverified')


def test_a_dry_run_never_verifies_or_rolls_back(flask_app, models, db, host, monkeypatch):
    monkeypatch.setenv('AILOG_ALLOW_REMEDIATION', 'on')
    calls = {'probes': 0}

    def counting_probe(*a, **kw):
        calls['probes'] += 1
        return {'ok': True, 'detail': '', 'command': 'true', 'stdout': '', 'stderr': '', 'rc': 0}
    monkeypatch.setattr(verify, 'run_probe', counting_probe)
    monkeypatch.setattr(runner, 'run_playbook', lambda *a, **kw: {
        'rc': 0, 'status': 'successful',
        'hosts': {host: {'ok': True, 'changed': 0, 'failed': False, 'output': 'would change'}},
        'changed': 0, 'artifact_dir': '/tmp/x', 'stats': {}})
    run = _run_with_host(flask_app, models, db, host, dry_run=True)
    done = _wait(models, run.uuid)
    assert done.state == 'checked'
    assert done.targets[0].state == 'checked'
    assert done.targets[0].rollback_state in (None, '')
    # The pre-flight probe runs; the post-apply verification must not.
    assert calls['probes'] == 1


def test_an_exception_in_a_wave_fails_the_run_cleanly(flask_app, models, db, host, allow_on, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError('ansible-runner exploded')
    monkeypatch.setattr(runner, 'run_playbook', boom)
    monkeypatch.setattr(verify, 'run_probe', lambda *a, **kw: {
        'ok': False, 'detail': '', 'command': 'true', 'stdout': '', 'stderr': '', 'rc': 1})
    run = _run_with_host(flask_app, models, db, host)
    done = _wait(models, run.uuid)
    assert done.state == 'failed'
    assert done.targets[0].state == 'failed'


def test_a_run_records_before_and_after_evidence(flask_app, models, db, host, allow_on, monkeypatch):
    probes = iter([
        {'ok': False, 'detail': 'before', 'command': 'true', 'stdout': '3', 'stderr': '', 'rc': 0},
        {'ok': True, 'detail': 'after', 'command': 'true', 'stdout': '0', 'stderr': '', 'rc': 0},
    ])
    monkeypatch.setattr(verify, 'run_probe', lambda *a, **kw: next(probes))
    monkeypatch.setattr(runner, 'run_playbook', lambda *a, **kw: {
        'rc': 0, 'status': 'successful',
        'hosts': {host: {'ok': True, 'changed': 1, 'failed': False, 'output': 'ok'}},
        'changed': 1, 'artifact_dir': '/tmp/x', 'stats': {}})
    run = _run_with_host(flask_app, models, db, host)
    done = _wait(models, run.uuid)
    target = done.targets[0]
    assert json.loads(target.before_json)['stdout'] == '3'
    assert json.loads(target.after_json)['stdout'] == '0'


def test_cancelling_before_the_wave_stops_the_run(flask_app, models, db, host, allow_on, monkeypatch):
    run_holder = {}

    def slow_playbook(*a, **kw):
        return {'rc': 0, 'status': 'successful',
                'hosts': {host: {'ok': True, 'changed': 1, 'failed': False, 'output': ''}},
                'changed': 1, 'artifact_dir': '/tmp/x', 'stats': {}}
    monkeypatch.setattr(runner, 'run_playbook', slow_playbook)
    monkeypatch.setattr(verify, 'run_probe', lambda *a, **kw: {
        'ok': True, 'detail': '', 'command': 'true', 'stdout': '', 'stderr': '', 'rc': 0})
    # Cancel immediately after queueing, before the worker reaches the wave loop.
    original_start = service.progress.start

    def start(uuid):
        original_start(uuid)
        run_holder['uuid'] = uuid
        service.progress.cancel(uuid)
    monkeypatch.setattr(service.progress, 'start', start)
    run = _run_with_host(flask_app, models, db, host)
    done = _wait(models, run.uuid)
    assert done.state == 'cancelled'


def test_progress_events_include_stages_and_targets(flask_app, models, db, host, allow_on, monkeypatch):
    monkeypatch.setattr(runner, 'run_playbook', lambda *a, **kw: {
        'rc': 0, 'status': 'successful',
        'hosts': {host: {'ok': True, 'changed': 1, 'failed': False, 'output': ''}},
        'changed': 1, 'artifact_dir': '/tmp/x', 'stats': {}})
    monkeypatch.setattr(verify, 'run_probe', lambda *a, **kw: {
        'ok': True, 'detail': '', 'command': 'true', 'stdout': '', 'stderr': '', 'rc': 0})
    run = _run_with_host(flask_app, models, db, host)
    _wait(models, run.uuid)
    events = list(progress.snapshot(run.uuid) or [])
    types = {e.get('type') for e in events}
    assert 'stage' in types
    assert 'target' in types


# --- audit -----------------------------------------------------------------


def test_apply_and_finish_are_audited(flask_app, models, db, host, allow_on, monkeypatch):
    from database import AuditEvent
    monkeypatch.setattr(runner, 'run_playbook', lambda *a, **kw: {
        'rc': 0, 'status': 'successful',
        'hosts': {host: {'ok': True, 'changed': 1, 'failed': False, 'output': ''}},
        'changed': 1, 'artifact_dir': '/tmp/x', 'stats': {}})
    monkeypatch.setattr(verify, 'run_probe', lambda *a, **kw: {
        'ok': True, 'detail': '', 'command': 'true', 'stdout': '', 'stderr': '', 'rc': 0})
    run = _run_with_host(flask_app, models, db, host)
    _wait(models, run.uuid)
    actions = {row.action for row in AuditEvent.query.filter_by(object_id=run.uuid).all()}
    assert 'remediation.apply' in actions
    assert 'remediation.finished' in actions


def _extra_host(db):
    from database import Host
    n = Host.query.count() + 700
    row = Host(hostname=f'extra-{n}', friendly_name=f'extra-{n}',
               ip_address=f'10.7.0.{n % 250 + 1}', ssh_user='tester')
    db.session.add(row)
    db.session.commit()
    return f'db-{row.id}'


# --- runner integration (fake ansible-runner, real codepath) ---------------


def test_the_project_copy_places_roles_beside_the_playbooks(tmp_path):
    """Playbooks are in playbooks/, roles in roles/ - Ansible needs telling."""
    from remediation import runner as runner_mod
    project = runner_mod.ensure_project(tmp_path)
    catalog_root = project / 'remediations'
    assert (catalog_root / 'playbooks').is_dir()
    assert (catalog_root / 'roles').is_dir()
    assert not list(catalog_root.rglob('molecule')), 'molecule scaffolding must not be shipped'


def test_run_playbook_points_ansible_at_the_copied_roles(tmp_path, monkeypatch):
    """Regression: without ANSIBLE_ROLES_PATH every playbook fails with
    "the role '<slug>' was not found"."""
    import sys
    import types

    captured = {}

    class _Result:
        rc = 0
        status = 'successful'
        artifact_dir = str(tmp_path / 'artifact')

    def fake_run(**kwargs):
        captured.update(kwargs)
        return _Result()

    fake = types.ModuleType('ansible_runner')
    fake.run = fake_run
    monkeypatch.setitem(sys.modules, 'ansible_runner', fake)
    monkeypatch.setattr(runner, 'available', lambda: True)

    runner.run_playbook('playbooks/free-disk-journal.yml',
                        {'all': {'hosts': {}}}, ['h1'], {}, True, tmp_path, timeout=10)
    roles_path = captured['envvars']['ANSIBLE_ROLES_PATH']
    assert roles_path.endswith('remediations/roles')
    assert str(tmp_path) in roles_path


def test_a_host_whose_tasks_are_all_skipped_is_healthy(tmp_path, monkeypatch):
    """Already-in-desired-state emits no runner_on_ok; a clean exit is success."""
    import sys
    import types

    class _Result:
        rc = 0
        status = 'successful'
        artifact_dir = str(tmp_path / 'artifact')

    def fake_run(playbook=None, event_handler=None, **kwargs):
        event_handler({'event': 'runner_on_skipped',
                       'event_data': {'host': 'h1', 'task': 'Vacuum journal'}})
        return _Result()

    fake = types.ModuleType('ansible_runner')
    fake.run = fake_run
    monkeypatch.setitem(sys.modules, 'ansible_runner', fake)
    monkeypatch.setattr(runner, 'available', lambda: True)

    result = runner.run_playbook('playbooks/free-disk-journal.yml',
                                 {'all': {'hosts': {}}}, ['h1'], {}, True, tmp_path)
    assert result['hosts']['h1']['ok'] is True
    assert result['hosts']['h1']['failed'] is False


def test_a_failed_task_is_never_ok(tmp_path, monkeypatch):
    import sys
    import types

    class _Result:
        rc = 2
        status = 'failed'
        artifact_dir = str(tmp_path / 'artifact')

    def fake_run(playbook=None, event_handler=None, **kwargs):
        event_handler({'event': 'runner_on_ok', 'event_data': {'host': 'h1', 'task': 'a'}})
        event_handler({'event': 'runner_on_failed',
                       'event_data': {'host': 'h1', 'task': 'b', 'res': {'msg': 'boom'}}})
        return _Result()

    fake = types.ModuleType('ansible_runner')
    fake.run = fake_run
    monkeypatch.setitem(sys.modules, 'ansible_runner', fake)
    monkeypatch.setattr(runner, 'available', lambda: True)

    result = runner.run_playbook('playbooks/restart-failed-units.yml',
                                 {'all': {'hosts': {}}}, ['h1'], {}, False, tmp_path)
    assert result['hosts']['h1']['ok'] is False
    assert result['hosts']['h1']['failed'] is True
    assert 'boom' in result['hosts']['h1']['output']
