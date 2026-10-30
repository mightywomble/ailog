"""A run that waits for a maintenance slot, and a run that looks alive.

Two properties matter here:

* a scheduled run is queued and visible, does nothing now, re-checks policy
  when its slot arrives, and can be cancelled while it waits;
* a run in progress emits heartbeats, so the console can prove the app is
  still connected instead of looking hung.
"""

from __future__ import annotations

import datetime
import time

import pytest

from remediation import progress, runner, service, verify


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


@pytest.fixture(autouse=True)
def no_settle(monkeypatch):
    monkeypatch.setattr(verify, 'settle', lambda *a, **kw: None)
    for key in list(getattr(progress, '_streams', {}).keys()):
        progress.finish(key, 'done')
    yield


def _enable_on(monkeypatch):
    monkeypatch.setenv('AILOG_ALLOW_REMEDIATION', 'on')


def _plan(client, host, dry_run=True):
    return client.post('/api/remediations/restart-failed-units/plan',
                       json={'scope': 'host', 'host_key': host,
                             'dry_run': dry_run}).get_json()


# --- parse_run_at ---------------------------------------------------------

def test_a_past_start_time_is_refused():
    when, error = service.parse_run_at(
        (datetime.datetime.utcnow() - datetime.timedelta(minutes=5)).isoformat())
    assert when is None
    assert 'at least a minute in the future' in error


def test_a_time_inside_the_next_minute_is_refused():
    when, error = service.parse_run_at(
        (datetime.datetime.utcnow() + datetime.timedelta(seconds=5)).isoformat())
    assert when is None
    assert 'at least a minute' in error


def test_a_start_time_beyond_the_cap_is_refused():
    when, error = service.parse_run_at(
        (datetime.datetime.utcnow() + datetime.timedelta(days=service.MAX_SCHEDULE_DAYS + 1)).isoformat())
    assert when is None
    assert str(service.MAX_SCHEDULE_DAYS) in error


def test_a_start_time_near_the_cap_is_accepted():
    wanted = datetime.datetime.utcnow() + datetime.timedelta(days=3, hours=1)
    when, error = service.parse_run_at(wanted.isoformat())
    assert error == ''
    assert when is not None


def test_a_zulu_suffix_is_understood_and_normalised_to_naive_utc():
    wanted = datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    when, error = service.parse_run_at(wanted.strftime('%Y-%m-%dT%H:%M:%SZ'))
    assert error == ''
    assert when.tzinfo is None
    assert abs((when - wanted).total_seconds()) < 90


def test_an_offset_time_is_converted_to_utc():
    local = datetime.datetime.now().astimezone() + datetime.timedelta(hours=2)
    when, error = service.parse_run_at(local.isoformat())
    assert error == ''
    utcnow = datetime.datetime.utcnow()
    assert abs((when - utcnow).total_seconds() - 7200) < 120


def test_nonsense_is_reported_in_english():
    when, error = service.parse_run_at('next tuesday-ish')
    assert when is None
    assert 'could not be understood' in error


def test_an_empty_value_means_run_now():
    when, error = service.parse_run_at(None)
    assert (when, error) == (None, '')


# --- a scheduled run ------------------------------------------------------

def test_a_scheduled_run_is_queued_not_started(client, monkeypatch, host):
    _enable_on(monkeypatch)
    monkeypatch.setattr(runner, 'available', lambda: True)

    def explode(*args, **kwargs):
        raise AssertionError('a scheduled run must not touch ansible yet')

    monkeypatch.setattr(runner, 'run_playbook', explode)
    registered = []
    monkeypatch.setattr(service, '_schedule_run',
                        lambda app, run_uuid, when: registered.append((run_uuid, when)))

    plan = _plan(client, host)
    resp = client.post('/api/remediations/restart-failed-units/apply',
                       json={'scope': 'host', 'host_key': host, 'dry_run': True,
                             'token': plan['token'],
                             'run_at': (datetime.datetime.utcnow() + datetime.timedelta(hours=2)).isoformat()})
    assert resp.status_code == 202
    body = resp.get_json()
    assert body['state'] == 'scheduled'
    assert body['scheduled_for']
    assert registered and registered[0][0] == body['uuid']

    from database import RemediationRun
    run = RemediationRun.query.filter_by(uuid=body['uuid']).first()
    assert run.state == 'scheduled'
    assert run.scheduled_for is not None

    detail = client.get(f'/api/remediation-runs/{body["uuid"]}').get_json()
    assert detail['scheduled_for']
    assert detail['targets'][0]['state'] == 'pending'


def test_a_run_at_that_is_in_the_past_is_a_400(client, monkeypatch, host):
    _enable_on(monkeypatch)
    monkeypatch.setattr(runner, 'available', lambda: True)
    plan = _plan(client, host)
    resp = client.post('/api/remediations/restart-failed-units/apply',
                       json={'scope': 'host', 'host_key': host, 'dry_run': True,
                             'token': plan['token'],
                             'run_at': (datetime.datetime.utcnow() - datetime.timedelta(hours=1)).isoformat()})
    assert resp.status_code == 400
    assert 'future' in resp.get_json()['error']


def test_cancelling_a_scheduled_run_unschedules_it(client, monkeypatch, host, db):
    _enable_on(monkeypatch)
    monkeypatch.setattr(runner, 'available', lambda: True)
    monkeypatch.setattr(service, '_schedule_run', lambda app, run_uuid, when: None)
    dropped = []
    monkeypatch.setattr(service, '_drop_scheduled_job', lambda app, run_uuid: dropped.append(run_uuid),
                        raising=False)

    plan = _plan(client, host)
    body = client.post('/api/remediations/restart-failed-units/apply',
                       json={'scope': 'host', 'host_key': host, 'dry_run': True,
                             'token': plan['token'],
                             'run_at': (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).isoformat()}).get_json()

    resp = client.post(f'/api/remediation-runs/{body["uuid"]}/cancel')
    assert resp.status_code == 200
    assert resp.get_json()['cancelled'] == 'scheduled'

    from database import RemediationRun, RemediationTarget
    run = RemediationRun.query.filter_by(uuid=body['uuid']).first()
    assert run.state == 'cancelled'
    assert run.finished_at is not None
    targets = RemediationTarget.query.filter_by(run_id=run.id).all()
    assert [t.state for t in targets] == ['skipped']


def test_the_slot_arriving_promotes_the_run(client, monkeypatch, host, flask_app):
    _enable_on(monkeypatch)
    monkeypatch.setattr(runner, 'available', lambda: True)
    monkeypatch.setattr(service, '_schedule_run', lambda app, run_uuid, when: None)
    monkeypatch.setattr(runner, 'run_playbook', lambda *a, **kw: {
        'rc': 0, 'status': 'successful',
        'hosts': {host: {'ok': True, 'changed': 0, 'failed': False, 'output': ''}},
        'changed': 0, 'artifact_dir': '/tmp/none', 'stats': {}})
    monkeypatch.setattr(verify, 'run_probe', lambda *a, **kw: {
        'ok': True, 'detail': '', 'command': 'true', 'stdout': '', 'stderr': '', 'rc': 0})

    plan = _plan(client, host)
    body = client.post('/api/remediations/restart-failed-units/apply',
                       json={'scope': 'host', 'host_key': host, 'dry_run': True,
                             'token': plan['token'],
                             'run_at': (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).isoformat()}).get_json()

    # The scheduler fires later; simulate the slot arriving.
    service._scheduled_start(flask_app, body['uuid'])

    from database import RemediationRun, db
    deadline = time.time() + 15
    run = None
    while time.time() < deadline:
        db.session.expire_all()
        run = RemediationRun.query.filter_by(uuid=body['uuid']).first()
        if run and run.state not in ('scheduled', 'queued', 'checking', 'applying'):
            break
        time.sleep(0.05)
    assert run.state in ('checked', 'healed')


def test_the_slot_arriving_does_nothing_for_a_cancelled_run(client, monkeypatch, host, flask_app):
    _enable_on(monkeypatch)
    monkeypatch.setattr(runner, 'available', lambda: True)
    monkeypatch.setattr(service, '_schedule_run', lambda app, run_uuid, when: None)
    monkeypatch.setattr(runner, 'run_playbook', lambda *a, **kw: (_ for _ in ()).throw(
        AssertionError('a cancelled run must not execute')))

    plan = _plan(client, host)
    body = client.post('/api/remediations/restart-failed-units/apply',
                       json={'scope': 'host', 'host_key': host, 'dry_run': True,
                             'token': plan['token'],
                             'run_at': (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).isoformat()}).get_json()
    client.post(f'/api/remediation-runs/{body["uuid"]}/cancel')
    service._scheduled_start(flask_app, body['uuid'])

    from database import RemediationRun, db
    db.session.expire_all()
    assert RemediationRun.query.filter_by(uuid=body['uuid']).first().state == 'cancelled'


# --- liveness -------------------------------------------------------------

def test_a_run_in_progress_emits_heartbeats(client, monkeypatch, host, flask_app):
    _enable_on(monkeypatch)
    monkeypatch.setattr(runner, 'available', lambda: True)
    monkeypatch.setattr(service, 'HEARTBEAT_SECONDS', 0.05)
    started = {'seen': False}

    def slow_run(*args, **kwargs):
        # Long enough for at least one heartbeat while ansible "works".
        time.sleep(0.3)
        started['seen'] = True
        return {'rc': 0, 'status': 'successful',
                'hosts': {host: {'ok': True, 'changed': 0, 'failed': False, 'output': ''}},
                'changed': 0, 'artifact_dir': '/tmp/none', 'stats': {}}

    monkeypatch.setattr(runner, 'run_playbook', slow_run)
    monkeypatch.setattr(verify, 'run_probe', lambda *a, **kw: {
        'ok': True, 'detail': '', 'command': 'true', 'stdout': '', 'stderr': '', 'rc': 0})

    plan = _plan(client, host)
    body = client.post('/api/remediations/restart-failed-units/apply',
                       json={'scope': 'host', 'host_key': host, 'dry_run': True,
                             'token': plan['token']}).get_json()

    deadline = time.time() + 15
    while time.time() < deadline and not started['seen']:
        time.sleep(0.02)
    snapshot = progress.snapshot(body['uuid'])
    kinds = [event.get('type') for event in snapshot]
    assert 'heartbeat' in kinds, kinds
    assert 'stage' in kinds


def test_a_scheduled_run_announces_itself_on_the_stream(client, monkeypatch, host):
    """The console connects immediately, so the first thing it sees is the slot."""
    _enable_on(monkeypatch)
    monkeypatch.setattr(runner, 'available', lambda: True)
    monkeypatch.setattr(service, '_schedule_run', lambda app, run_uuid, when: None)
    plan = _plan(client, host)
    body = client.post('/api/remediations/restart-failed-units/apply',
                       json={'scope': 'host', 'host_key': host, 'dry_run': True,
                             'token': plan['token'],
                             'run_at': (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).isoformat()}).get_json()

    events = progress.snapshot(body['uuid'])
    stages = [e.get('stage') for e in events if e.get('type') == 'stage']
    assert 'scheduled' in stages, events
    message = next(e['message'] for e in events if e.get('stage') == 'scheduled')
    assert 'Scheduled' in message
