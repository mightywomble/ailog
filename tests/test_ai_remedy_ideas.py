"""The untested-AI-remedy loop.

Reports whose findings are informational have no catalog match, so the empty
state offers a model-written **Ansible playbook**. It must stay untested and
non-executable until a human runs it: the test endpoint is `--check` only, and
promotion to the library happens only on an explicit "it worked".
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from remediation import runner, suggestions


@pytest.fixture()
def db(ctx):
    from database import (RemediationLearned, RemediationMatch, RemediationRun,
                          RemediationTarget, db)
    RemediationMatch.query.delete()
    RemediationTarget.query.delete()
    RemediationRun.query.delete()
    RemediationLearned.query.delete()
    db.session.commit()
    return db


@pytest.fixture()
def report_id(db, host):
    from database import LogReport
    row = LogReport(host_key=host, host_label=host, verdict='healthy',
                    clusters_json=json.dumps([{'sig': 'session opened for user david',
                                               'count': 12, 'src': 'syslog', 'sev': 'info'}]))
    db.session.add(row)
    db.session.commit()
    return row.id


PLAYBOOK = """- hosts: all
  become: true
  tasks:
    - name: Ensure the service is enabled
      ansible.builtin.systemd:
        name: cron
        enabled: true
        state: started
"""

ITEM = {
    'title': 'Keep cron enabled',
    'rationale': 'The timer never fires because the unit is disabled.',
    'risk_guess': 'low',
    'playbook': PLAYBOOK,
    'verify': 'systemctl is-enabled cron',
    'rollback': '',
}


def _idea_card(db, report_id, host):
    from database import RemediationMatch
    card = RemediationMatch(
        report_id=report_id, host_key=host, source='llm', executable=False,
        title=ITEM['title'], summary=ITEM['rationale'], rationale=ITEM['rationale'],
        risk='low', est_seconds=0, confidence=0.35,
        code_text=ITEM['playbook'], verify_text=ITEM['verify'], rollback_text='',
        evidence_json='[]', changes_json='[]', does_not_json='[]', requires_json='[]',
    )
    db.session.add(card)
    db.session.commit()
    return card


# --- the model's output ----------------------------------------------------

def test_the_idea_channel_asks_for_an_ansible_playbook():
    prompt = suggestions.SYSTEM_PROMPT.lower()
    assert 'ansible' in prompt
    assert 'playbook' in prompt
    assert '--check' in prompt or 'test' in prompt
    assert 'idempotent' in prompt


def test_a_valid_playbook_survives_validation():
    cleaned = suggestions._clean(ITEM)
    assert cleaned is not None
    assert cleaned['code'].startswith('- hosts: all')
    assert cleaned['kind'] == 'ansible'


@pytest.mark.parametrize('bad', [
    {'title': 'nope', 'verify': 'true', 'playbook': 'rm -rf /'},                     # not YAML
    {'title': 'nope', 'verify': 'true', 'playbook': 'hosts: all\ntasks: []'},        # mapping, no list
    {'title': 'nope', 'verify': 'true',
     'playbook': '- hosts: db\n  tasks:\n    - ansible.builtin.ping:\n'},            # wrong host scope
    {'title': 'nope', 'verify': 'true',
     'playbook': '- hosts: all\n  tasks: []\n'},                                     # no tasks
    {'title': 'nope', 'verify': 'true', 'playbook': PLAYBOOK + '    - shell: reboot\n'},
])
def test_a_playbook_that_breaks_the_rules_is_dropped(bad):
    assert suggestions._clean(bad) is None


def test_confirming_needs_a_model_card(client, db, report_id, host):
    resp = client.post('/api/remediation-matches/999999/confirm', json={'worked': True})
    assert resp.status_code == 404


# --- asking the model ------------------------------------------------------

def test_the_empty_state_can_ask_the_model(client, db, report_id, host, monkeypatch):
    from remediation import matcher
    monkeypatch.setattr(suggestions, 'propose', lambda *a, **k: [suggestions._clean(ITEM)])
    monkeypatch.setenv('AILOG_ALLOW_REMEDIATION', 'dry_run')

    body = client.post(f'/api/reports/{report_id}/ideas').get_json()
    assert body['ok'] is True
    assert body['ideas'] == 1

    cards = client.get(f'/api/reports/{report_id}/remediations').get_json()['cards']
    idea = [c for c in cards if c['source'] == 'llm'][0]
    assert idea['executable'] is False
    assert idea['code'].startswith('- hosts: all')

    # Asking twice does not stack duplicate cards.
    again = client.post(f'/api/reports/{report_id}/ideas').get_json()
    assert again['already'] is True
    assert matcher is not None


def test_the_idea_channel_can_be_turned_off(client, db, report_id, host, monkeypatch):
    monkeypatch.setenv('AILOG_REMEDIATION_ALLOW_IDEA_CHANNEL', 'off')
    resp = client.post(f'/api/reports/{report_id}/ideas')
    assert resp.status_code == 403


# --- testing it ------------------------------------------------------------

def test_test_runs_check_mode_only(client, db, report_id, host, monkeypatch):
    monkeypatch.setenv('AILOG_ALLOW_REMEDIATION', 'dry_run')
    monkeypatch.setattr(runner, 'available', lambda: True)
    card = _idea_card(db, report_id, host)

    seen = {}

    def fake_run(playbook, inventory, limit, extravars, dry_run, run_dir, timeout=300, on_event=None):
        seen.update(playbook=playbook, dry_run=dry_run, run_dir=Path(run_dir), limit=limit)
        path = Path(run_dir) / 'project' / 'remediations' / playbook
        seen['written'] = path.read_text()
        return {'rc': 0, 'status': 'successful', 'changed': 1,
                'hosts': {host: {'ok': True, 'changed': 1, 'output': 'ok: [host] task'}}}

    monkeypatch.setattr(runner, 'run_playbook', fake_run)
    monkeypatch.setattr(runner, 'ensure_project', lambda run_dir: Path(run_dir).mkdir(parents=True, exist_ok=True))

    body = client.post(f'/api/remediation-matches/{card.id}/test').get_json()
    assert body['ok'] is True
    assert body['check_only'] is True
    assert seen['dry_run'] is True, 'the test endpoint must never apply'
    assert seen['written'].startswith('- hosts: all')
    assert 'ok: [host]' in body['output']


def test_a_failed_check_is_reported_not_hidden(client, db, report_id, host, monkeypatch):
    monkeypatch.setenv('AILOG_ALLOW_REMEDIATION', 'dry_run')
    monkeypatch.setattr(runner, 'available', lambda: True)
    monkeypatch.setattr(runner, 'ensure_project', lambda run_dir: Path(run_dir).mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr(runner, 'run_playbook', lambda *a, **k: {
        'rc': 2, 'status': 'failed', 'changed': 0,
        'hosts': {host: {'ok': False, 'changed': 0, 'output': 'FAILED: syntax error'}}})
    card = _idea_card(db, report_id, host)

    body = client.post(f'/api/remediation-matches/{card.id}/test').get_json()
    assert body['ok'] is False
    assert body['rc'] == 2
    assert 'FAILED' in body['output']


def test_testing_is_refused_when_execution_is_off(client, db, report_id, host, monkeypatch):
    monkeypatch.setenv('AILOG_ALLOW_REMEDIATION', 'off')
    card = _idea_card(db, report_id, host)
    assert client.post(f'/api/remediation-matches/{card.id}/test').status_code == 403


# --- confirming it ---------------------------------------------------------

def test_a_confirmed_playbook_joins_the_library(client, db, report_id, host):
    from database import RemediationLearned
    card = _idea_card(db, report_id, host)

    body = client.post(f'/api/remediation-matches/{card.id}/confirm',
                       json={'worked': True}).get_json()
    assert body['ok'] is True
    learned = body['learned']
    assert learned['yaml'].startswith('- hosts: all')
    assert learned['slug'].startswith('learned-')

    rows = RemediationLearned.query.all()
    assert len(rows) == 1
    assert RemediationLearned.query.get(1) is not None

    # It shows up on the library page and the API.
    assert len(client.get('/api/remediation/learned').get_json()['learned']) == 1
    page = client.get('/remediation').get_data(as_text=True)
    assert 'Learned remedies' in page
    assert 'Keep cron enabled' in page


def test_two_confirmed_fixes_with_the_same_title_stay_distinct(client, db, report_id, host):
    first = _idea_card(db, report_id, host)
    second = _idea_card(db, report_id, host)
    a = client.post(f'/api/remediation-matches/{first.id}/confirm', json={'worked': True}).get_json()
    b = client.post(f'/api/remediation-matches/{second.id}/confirm', json={'worked': True}).get_json()
    assert a['learned']['slug'] != b['learned']['slug']


def test_a_failed_fix_is_never_added_and_stops_asking(client, db, report_id, host):
    from database import RemediationLearned, RemediationMatch
    card = _idea_card(db, report_id, host)
    body = client.post(f'/api/remediation-matches/{card.id}/confirm',
                       json={'worked': False, 'notes': 'broke sudo'}).get_json()
    assert body['learned'] is None
    assert RemediationLearned.query.count() == 0
    assert RemediationMatch.query.get(card.id).state == 'rejected'


def test_the_library_entry_can_be_deleted(client, db, report_id, host):
    from database import RemediationLearned
    card = _idea_card(db, report_id, host)
    learned = client.post(f'/api/remediation-matches/{card.id}/confirm',
                          json={'worked': True}).get_json()['learned']
    assert client.delete(f"/api/remediation/learned/{learned['id']}").status_code == 200
    assert RemediationLearned.query.count() == 0


# --- the page --------------------------------------------------------------

def test_the_empty_state_offers_the_ai_and_says_it_is_untested():
    js = (Path(__file__).resolve().parent.parent / 'static' / 'js' / 'remediation.js').read_text()
    assert 'Ask AI for a suggested fix' in js
    assert 'Untested AI playbook' in js
    assert "data-test=" in js
    assert "data-worked=" in js
    assert 'Test with --check' in js
    assert 'I ran it — it worked' in js
    assert '/confirm' in js
