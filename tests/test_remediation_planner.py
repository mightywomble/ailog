"""Planning is a promise the browser cannot widen.

The token binds slug + host set + dry_run + expiry, so a tampered or stale
plan is refused before anything reaches a host.
"""

from __future__ import annotations

import pytest

from remediation import planner


@pytest.fixture()
def models():
    import database
    return database


@pytest.fixture()
def db(ctx):
    from database import RemediationMatch, RemediationWindow, db
    # Windows and cards are global; leftovers from another test must not leak.
    RemediationWindow.query.delete()
    RemediationMatch.query.delete()
    db.session.commit()
    return db


def _card(db, host_key, slug='restart-failed-units', state='open', report_id=1):
    from database import RemediationMatch
    row = RemediationMatch(report_id=report_id, host_key=host_key, slug=slug,
                           source='catalog', executable=True, state=state,
                           title='t', summary='s', risk='low')
    db.session.add(row)
    db.session.commit()
    return row


# --- tokens ---------------------------------------------------------------


def test_a_fresh_token_verifies():
    token, fingerprint = planner.make_token('restart-failed-units', ['db-1', 'db-2'], True)
    ok, message = planner.check_token(token, 'restart-failed-units', ['db-2', 'db-1'], True)
    assert ok, message
    assert fingerprint == planner.fingerprint('restart-failed-units', ['db-1', 'db-2'], True)


def test_host_order_does_not_matter_but_membership_does():
    token, _ = planner.make_token('s', ['db-1', 'db-2'], True)
    assert planner.check_token(token, 's', ['db-1'], True)[0] is False
    assert planner.check_token(token, 's', ['db-1', 'db-2', 'db-3'], True)[0] is False


def test_a_different_slug_is_refused():
    token, _ = planner.make_token('s', ['db-1'], True)
    ok, message = planner.check_token(token, 'other', ['db-1'], True)
    assert ok is False and 'no longer matches' in message


def test_dry_run_is_part_of_the_contract():
    token, _ = planner.make_token('s', ['db-1'], True)
    assert planner.check_token(token, 's', ['db-1'], False)[0] is False


def test_an_expired_token_is_refused():
    token, _ = planner.make_token('s', ['db-1'], True, ttl=-10)
    ok, message = planner.check_token(token, 's', ['db-1'], True)
    assert ok is False and 'expired' in message.lower()


def test_a_malformed_token_is_refused():
    for bad in ('', 'nonsense', 'a.b.c', None):
        ok, _ = planner.check_token(bad, 's', ['db-1'], True)
        assert ok is False


def test_a_tampered_signature_is_refused():
    token, _ = planner.make_token('s', ['db-1'], True)
    sig, exp = token.split('.')
    forged = ('0' * len(sig)) + '.' + exp
    assert planner.check_token(forged, 's', ['db-1'], True)[0] is False


# --- scope resolution -----------------------------------------------------


def test_host_scope_resolves_exactly_one_host(models, db, host):
    rows = planner.resolve(models, 'restart-failed-units', 'host', host, None)
    assert [r['host_key'] for r in rows] == [host]
    assert rows[0]['eligible'] is True
    assert rows[0]['why'] == ''


def test_an_unknown_host_key_resolves_to_nothing(models, db):
    assert planner.resolve(models, 's', 'host', 'db-999999', None) == []
    assert planner.resolve(models, 's', 'host', 'not-a-key', None) == []


def test_fleet_scope_only_returns_hosts_with_an_open_card(models, db, host):
    other = _make_host(db, 'fleet-other')
    _card(db, host, report_id=10)
    _card(db, other, report_id=11, state='dismissed')
    rows = planner.resolve(models, 'restart-failed-units', 'fleet', None, None)
    keys = [r['host_key'] for r in rows]
    assert host in keys
    assert other not in keys, 'a dismissed card must never re-enter the fleet scope'


def test_fleet_scope_lists_a_host_once(models, db, host):
    _card(db, host, report_id=5)
    _card(db, host, report_id=9)
    rows = planner.resolve(models, 'restart-failed-units', 'fleet', None, None)
    assert [r['host_key'] for r in rows] == [host]


def test_a_host_whose_cards_are_all_resolved_leaves_the_fleet_scope(models, db, host):
    _card(db, host, report_id=5, state='applied')
    _card(db, host, report_id=9, state='healed')
    rows = planner.resolve(models, 'restart-failed-units', 'fleet', None, None)
    assert rows == []


def test_a_protected_host_is_never_eligible(models, db, host):
    from database import Host, db as db_handle
    row = Host.query.get(int(host.split('-')[1]))
    row.do_not_remediate = True
    db_handle.session.commit()
    rows = planner.resolve(models, 's', 'host', host, None)
    assert rows[0]['eligible'] is False
    assert 'do-not-remediate' in rows[0]['why']


def test_an_offline_host_is_never_eligible(models, db, host):
    from database import Host, db as db_handle
    row = Host.query.get(int(host.split('-')[1]))
    row.status = 'offline'
    db_handle.session.commit()
    rows = planner.resolve(models, 's', 'host', host, None)
    assert rows[0]['eligible'] is False
    assert 'offline' in rows[0]['why'].lower()


def test_a_block_window_makes_the_host_ineligible(models, db, host):
    from database import RemediationWindow, db as db_handle
    db_handle.session.add(RemediationWindow(
        name='nightly', days='1,2,3,4,5,6,7', start_time='00:00',
        end_time='23:59', timezone='UTC', mode='block', enabled=True))
    db_handle.session.commit()
    rows = planner.resolve(models, 's', 'host', host, None)
    assert rows[0]['eligible'] is False
    assert 'maintenance window' in rows[0]['why']


def test_a_warn_window_leaves_the_host_eligible(models, db, host):
    from database import RemediationWindow, db as db_handle
    db_handle.session.add(RemediationWindow(
        name='soft', days='1,2,3,4,5,6,7', start_time='00:00',
        end_time='23:59', timezone='UTC', mode='warn', enabled=True))
    db_handle.session.commit()
    rows = planner.resolve(models, 's', 'host', host, None)
    assert rows[0]['eligible'] is True


def test_an_empty_scope_resolves_to_nothing(models, db):
    assert planner.resolve(models, 's', 'group', None, None) == []
    assert planner.resolve(models, 's', 'nonsense', None, None) == []


def _make_host(db, name):
    from database import Host
    n = Host.query.count() + 500
    row = Host(hostname=name, friendly_name=name, ip_address=f'10.9.0.{n % 250 + 1}', ssh_user='tester')
    db.session.add(row)
    db.session.commit()
    return f'db-{row.id}'
