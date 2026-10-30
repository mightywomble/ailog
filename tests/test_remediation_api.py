"""HTTP surface: the flag gate, the plan/apply contract, dismissal, audit.

The most important test in this file is that a disabled deployment cannot
start a run, and that the refusal explains how to enable it.
"""

from __future__ import annotations

import json

import pytest

from remediation import progress, runner, verify


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


@pytest.fixture()
def report_id(db, host):
    from database import LogReport
    row = LogReport(host_key=host, host_label=host, verdict='degraded',
                    clusters_json=json.dumps([{'sig': 'Failed to start nginx.service',
                                               'count': 5, 'src': 'syslog', 'sev': 'error'}]))
    db.session.add(row)
    db.session.commit()
    return row.id


def _disable(monkeypatch):
    monkeypatch.setenv('AILOG_ALLOW_REMEDIATION', 'off')


def _enable_dry(monkeypatch):
    monkeypatch.setenv('AILOG_ALLOW_REMEDIATION', 'dry_run')


def _enable_on(monkeypatch):
    monkeypatch.setenv('AILOG_ALLOW_REMEDIATION', 'on')


# --- pages ----------------------------------------------------------------


def test_the_admin_page_renders(client):
    resp = client.get('/remediation')
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'remediation-page.css' in body
    assert 'window-form' in body


def test_an_unknown_run_page_is_a_404(client):
    assert client.get('/remediation/runs/does-not-exist').status_code == 404


# --- settings -------------------------------------------------------------


def test_settings_reports_the_mode(client, monkeypatch):
    _enable_dry(monkeypatch)
    payload = client.get('/api/remediation/settings').get_json()
    policy = payload['policy']
    assert policy['mode'] == 'dry_run'
    assert policy['enabled'] is True
    assert policy['forced_dry_run'] is True
    assert policy['max_hosts'] >= 1
    assert 'runner_available' in policy
    assert isinstance(payload['catalog'], list) and payload['catalog']


def test_settings_reports_off(client, monkeypatch):
    _disable(monkeypatch)
    payload = client.get('/api/remediation/settings').get_json()
    assert payload['policy']['mode'] == 'off'
    assert payload['policy']['enabled'] is False


# --- the flag gate --------------------------------------------------------


def test_plan_is_refused_when_disabled(client, monkeypatch, host):
    _disable(monkeypatch)
    resp = client.post('/api/remediations/restart-failed-units/plan',
                       json={'scope': 'host', 'host_key': host})
    assert resp.status_code == 403
    assert 'AILOG_ALLOW_REMEDIATION' in resp.get_json()['error']


def test_apply_is_refused_when_disabled(client, monkeypatch, host):
    _disable(monkeypatch)
    resp = client.post('/api/remediations/restart-failed-units/apply',
                       json={'scope': 'host', 'host_key': host, 'token': 'x'})
    assert resp.status_code == 403


def test_apply_is_503_when_ansible_runner_is_absent(client, monkeypatch, host):
    _enable_on(monkeypatch)
    monkeypatch.setattr(runner, 'available', lambda: False)
    resp = client.post('/api/remediations/restart-failed-units/apply',
                       json={'scope': 'host', 'host_key': host, 'token': 'x'})
    assert resp.status_code == 503
    assert 'ansible-runner' in resp.get_json()['error']


def test_cards_are_visible_even_when_disabled(client, monkeypatch, report_id):
    _disable(monkeypatch)
    resp = client.get(f'/api/reports/{report_id}/remediations')
    assert resp.status_code == 200
    assert resp.get_json()['policy']['enabled'] is False


# --- cards ----------------------------------------------------------------


def test_cards_endpoint_returns_matched_remedies(client, monkeypatch, report_id, host):
    _enable_dry(monkeypatch)
    client.post(f'/api/reports/{report_id}/remediations/refresh')
    payload = client.get(f'/api/reports/{report_id}/remediations').get_json()
    slugs = [card['slug'] for card in payload['cards']]
    assert 'restart-failed-units' in slugs
    card = next(c for c in payload['cards'] if c['slug'] == 'restart-failed-units')
    assert card['executable'] is True
    assert card['code']
    assert card['verify']
    assert card['changes'] and card['does_not']


def test_cards_for_an_unknown_report_are_a_404(client):
    assert client.get('/api/reports/999999/remediations').status_code == 404


# --- dismissal ------------------------------------------------------------


def test_dismissing_a_card_records_the_reason(client, monkeypatch, report_id, db):
    _enable_dry(monkeypatch)
    client.post(f'/api/reports/{report_id}/remediations/refresh')
    cards = client.get(f'/api/reports/{report_id}/remediations').get_json()['cards']
    card = next(c for c in cards if c['executable'])
    resp = client.post(f'/api/remediation-matches/{card["id"]}/dismiss',
                       json={'reason': 'not_now'})
    assert resp.status_code == 200
    from database import AuditEvent, RemediationMatch
    row = RemediationMatch.query.get(card['id'])
    assert row.state == 'dismissed'
    assert row.dismissed_reason == 'not_now'
    assert AuditEvent.query.filter_by(action='remediation.dismiss').count() >= 1


def test_an_unknown_dismissal_reason_becomes_other(client, monkeypatch, report_id, db):
    _enable_dry(monkeypatch)
    client.post(f'/api/reports/{report_id}/remediations/refresh')
    card = next(c for c in client.get(f'/api/reports/{report_id}/remediations').get_json()['cards']
                if c['executable'])
    client.post(f'/api/remediation-matches/{card["id"]}/dismiss', json={'reason': 'nonsense'})
    from database import RemediationMatch
    assert RemediationMatch.query.get(card['id']).dismissed_reason == 'other'


def test_dismissing_an_unknown_card_is_a_404(client):
    assert client.post('/api/remediation-matches/999999/dismiss', json={}).status_code == 404


# --- plan / apply contract ------------------------------------------------


def test_plan_returns_a_usable_token(client, monkeypatch, host):
    _enable_dry(monkeypatch)
    resp = client.post('/api/remediations/restart-failed-units/plan',
                       json={'scope': 'host', 'host_key': host, 'dry_run': True})
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload['token']
    assert payload['eligible_keys'] == [host]
    assert payload['expires_in'] > 0


def test_plan_for_an_unknown_slug_is_a_404(client, monkeypatch, host):
    _enable_dry(monkeypatch)
    resp = client.post('/api/remediations/nope/plan', json={'scope': 'host', 'host_key': host})
    assert resp.status_code == 404


def test_apply_without_a_token_is_refused(client, monkeypatch, host):
    _enable_on(monkeypatch)
    monkeypatch.setattr(runner, 'available', lambda: True)
    resp = client.post('/api/remediations/restart-failed-units/apply',
                       json={'scope': 'host', 'host_key': host})
    assert resp.status_code == 400


def test_a_full_plan_then_apply_round_trip(client, monkeypatch, host):
    _enable_on(monkeypatch)
    monkeypatch.setattr(runner, 'available', lambda: True)
    monkeypatch.setattr(runner, 'run_playbook', lambda *a, **kw: {
        'rc': 0, 'status': 'successful',
        'hosts': {host: {'ok': True, 'changed': 1, 'failed': False, 'output': ''}},
        'changed': 1, 'artifact_dir': '/tmp/x', 'stats': {}})
    monkeypatch.setattr(verify, 'run_probe', lambda *a, **kw: {
        'ok': True, 'detail': '', 'command': 'true', 'stdout': '', 'stderr': '', 'rc': 0})

    plan = client.post('/api/remediations/restart-failed-units/plan',
                       json={'scope': 'host', 'host_key': host, 'dry_run': False}).get_json()
    resp = client.post('/api/remediations/restart-failed-units/apply',
                       json={'scope': 'host', 'host_key': host, 'dry_run': False,
                             'token': plan['token']})
    assert resp.status_code == 202
    body = resp.get_json()
    assert body['ok'] is True
    assert body['uuid']

    import time
    from database import RemediationRun, db
    deadline = time.time() + 15
    while time.time() < deadline:
        db.session.expire_all()
        run = RemediationRun.query.filter_by(uuid=body['uuid']).first()
        if run and run.state not in ('queued', 'checking', 'applying'):
            break
        time.sleep(0.05)
    assert run.state == 'healed'
    detail = client.get(f'/api/remediation-runs/{body["uuid"]}').get_json()
    assert detail['state'] == 'healed'
    assert client.get(f'/remediation/runs/{body["uuid"]}').status_code == 200


def test_a_tampered_token_cannot_widen_the_scope(client, monkeypatch, host, db):
    _enable_on(monkeypatch)
    monkeypatch.setattr(runner, 'available', lambda: True)
    from database import Host
    n = Host.query.count() + 900
    other = Host(hostname='widen', friendly_name='widen', ip_address=f'10.6.0.{n % 250 + 1}',
                 ssh_user='tester')
    db.session.add(other)
    db.session.commit()
    plan = client.post('/api/remediations/restart-failed-units/plan',
                       json={'scope': 'host', 'host_key': host, 'dry_run': True}).get_json()
    resp = client.post('/api/remediations/restart-failed-units/apply',
                       json={'scope': 'host', 'host_key': f'db-{other.id}',
                             'dry_run': True, 'token': plan['token']})
    assert resp.status_code == 400
    assert 'no longer matches' in resp.get_json()['error']


# --- runs -----------------------------------------------------------------


def test_an_unknown_run_is_a_404(client):
    assert client.get('/api/remediation-runs/missing').status_code == 404


def test_the_run_list_is_paginated_json(client):
    payload = client.get('/api/remediation-runs').get_json()
    assert 'runs' in payload


def test_stream_falls_back_to_a_result_for_a_finished_run(client, monkeypatch, host, db):
    from database import RemediationRun
    run = RemediationRun(uuid='stream-1', slug='restart-failed-units', dry_run=True,
                         scope='host', requested_by='tester', state='checked')
    db.session.add(run)
    db.session.commit()
    resp = client.get('/api/remediation-runs/stream-1/stream')
    assert resp.status_code == 200
    assert resp.headers['Content-Type'].startswith('text/event-stream')
    body = resp.get_data(as_text=True)
    assert '"type": "result"' in body


def test_stream_for_an_unknown_run_reports_an_error_event(client):
    body = client.get('/api/remediation-runs/nope/stream').get_data(as_text=True)
    assert 'Run not found' in body


def test_cancelling_a_run_sets_the_flag(client):
    progress.start('cancel-me')
    assert client.post('/api/remediation-runs/cancel-me/cancel').get_json()['ok'] is True
    assert progress.cancelled('cancel-me') is True


def test_rollback_is_refused_for_a_remedy_without_one(client, monkeypatch, host, db):
    _enable_on(monkeypatch)
    from database import RemediationRun
    run = RemediationRun(uuid='rb-1', slug='restart-failed-units', dry_run=False,
                         scope='host', requested_by='tester', state='healed')
    db.session.add(run)
    db.session.commit()
    assert client.post('/api/remediation-runs/rb-1/rollback').status_code == 400


def test_rollback_is_refused_when_disabled(client, monkeypatch, db):
    _disable(monkeypatch)
    from database import RemediationRun
    run = RemediationRun(uuid='rb-2', slug='reload-nginx-config', dry_run=False,
                         scope='host', requested_by='tester', state='healed')
    db.session.add(run)
    db.session.commit()
    assert client.post('/api/remediation-runs/rb-2/rollback').status_code == 403


# --- admin: windows and protection ---------------------------------------


def test_a_window_can_be_created_listed_and_deleted(client, monkeypatch):
    _enable_dry(monkeypatch)
    created = client.post('/api/remediation/windows', json={
        'name': 'nightly', 'days': [1, 2, 3], 'start_time': '22:00',
        'end_time': '02:00', 'timezone': 'UTC', 'mode': 'block', 'enabled': True})
    assert created.status_code in (200, 201)
    windows = client.get('/api/remediation/windows').get_json()
    items = windows['windows'] if isinstance(windows, dict) else windows
    assert any(w['name'] == 'nightly' for w in items)
    window_id = next(w['id'] for w in items if w['name'] == 'nightly')
    assert client.delete(f'/api/remediation/windows/{window_id}').status_code == 200
    remaining = client.get('/api/remediation/windows').get_json()
    remaining = remaining['windows'] if isinstance(remaining, dict) else remaining
    assert all(w['id'] != window_id for w in remaining)


def test_a_window_without_a_name_gets_a_placeholder(client, monkeypatch):
    _enable_dry(monkeypatch)
    resp = client.post('/api/remediation/windows', json={'start_time': '22:00'})
    assert resp.status_code == 201
    assert resp.get_json()['window']['name'] == 'Window'


def test_a_window_mode_is_normalised(client, monkeypatch):
    _enable_dry(monkeypatch)
    resp = client.post('/api/remediation/windows', json={'name': 'w', 'mode': 'nonsense'})
    assert resp.get_json()['window']['mode'] == 'block'


def test_a_host_can_be_protected_and_unprotected(client, monkeypatch, host, db):
    _enable_dry(monkeypatch)
    resp = client.post(f'/api/remediation/hosts/{host}/protect', json={'protected': True})
    assert resp.status_code == 200
    from database import Host
    assert Host.query.get(int(host.split('-')[1])).do_not_remediate is True
    client.post(f'/api/remediation/hosts/{host}/protect', json={'protected': False})
    db.session.expire_all()
    assert Host.query.get(int(host.split('-')[1])).do_not_remediate is False


def test_protecting_an_unknown_host_is_a_404(client, monkeypatch):
    _enable_dry(monkeypatch)
    assert client.post('/api/remediation/hosts/db-999999/protect',
                       json={'protected': True}).status_code == 404
