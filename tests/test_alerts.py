"""Alert engine + routes."""
import pytest


@pytest.fixture()
def engine(ctx):
    from alerting import engine
    from database import AlertEvent, AlertRule, db
    # a clean rule set for every test
    AlertEvent.query.delete()
    AlertRule.query.delete()
    db.session.commit()
    engine.reset_state()
    engine.invalidate()
    yield engine
    AlertEvent.query.delete()
    AlertRule.query.delete()
    db.session.commit()
    engine.reset_state()
    engine.invalidate()


def make_rule(engine, **kw):
    payload = {'name': 'test rule', 'metric': 'mem_percent', 'op': '>=',
               'threshold': 90, 'for_seconds': 0, 'cooldown_seconds': 0,
               'severity': 'warning', 'enabled': True}
    payload.update(kw)
    return engine.create_rule(payload)


# ---------------------------------------------------------------- comparisons

@pytest.mark.parametrize('value,op,threshold,expected', [
    (95, '>=', 90, True), (90, '>=', 90, True), (89, '>=', 90, False),
    (95, '>', 95, False), (10, '<', 20, True), (20, '<=', 20, True),
    (5, '==', 5, True), (5, '!=', 5, False), (2, 'at_least', 1, True),
    (None, '>=', 1, False),
])
def test_comparisons(engine, value, op, threshold, expected):
    assert engine._compare(value, op, threshold) is expected


# -------------------------------------------------------------------- firing

def test_rule_fires_once_and_stays_firing(engine):
    make_rule(engine, for_seconds=0)
    first = engine.evaluate('local', {'mem_percent': 95.0}, now=1000)
    assert len(first) == 1
    assert first[0]['state'] == 'firing'
    assert first[0]['host_key'] == 'local'

    again = engine.evaluate('local', {'mem_percent': 96.0}, now=1010)
    assert again == []  # no second notification for the same episode


def test_rule_needs_to_hold_for_its_duration(engine):
    make_rule(engine, for_seconds=300)
    assert engine.evaluate('local', {'mem_percent': 95.0}, now=1000) == []
    # still inside the "for" window
    assert engine.evaluate('local', {'mem_percent': 95.0}, now=1100) == []
    fired = engine.evaluate('local', {'mem_percent': 95.0}, now=1300)
    assert len(fired) == 1


def test_rule_resets_when_condition_clears_before_firing(engine):
    make_rule(engine, for_seconds=300)
    engine.evaluate('local', {'mem_percent': 95.0}, now=1000)
    engine.evaluate('local', {'mem_percent': 10.0}, now=1100)   # back to normal
    # the timer restarts, so 250s after the new breach is not enough
    assert engine.evaluate('local', {'mem_percent': 95.0}, now=1200) == []
    assert engine.evaluate('local', {'mem_percent': 95.0}, now=1501) != []


def test_recovery_resolves_the_event(engine, ctx):
    from database import AlertEvent
    make_rule(engine)
    engine.evaluate('local', {'mem_percent': 95.0}, now=1000)
    event = AlertEvent.query.filter_by(state='firing').one()
    engine.evaluate('local', {'mem_percent': 10.0}, now=1010)

    resolved = AlertEvent.query.get(event.id)
    assert resolved.state == 'resolved'
    assert resolved.resolved_at is not None
    assert resolved.resolved_value == 10.0
    assert engine.active_events() == []


def test_disabled_rule_never_fires(engine):
    make_rule(engine, enabled=False)
    assert engine.evaluate('local', {'mem_percent': 99.0}, now=1) == []


def test_metric_missing_from_sample_is_ignored(engine):
    make_rule(engine, metric='disk_percent')
    assert engine.evaluate('local', {'mem_percent': 99.0}, now=1) == []


def test_evaluate_host_reads_stats_dict(engine):
    make_rule(engine, metric='mem_percent')
    fired = engine.evaluate_host('db-1', {'mem_percent': 97.5, 'ts': 10}, now=10)
    assert len(fired) == 1
    assert 'db-1' in fired[0]['message']


def test_verdict_rule(engine):
    make_rule(engine, name='not healthy', metric='verdict_level', op='at_least',
              threshold=1, for_seconds=0)
    assert engine.record_verdict('db-1', 'healthy') == []
    fired = engine.record_verdict('db-1', 'failing')
    assert len(fired) == 1
    assert 'failing' in fired[0]['message']


def test_unknown_verdict_is_ignored(engine):
    make_rule(engine, metric='verdict_level', op='at_least', threshold=1,
              for_seconds=0)
    assert engine.record_verdict('db-1', 'banana') == []


def test_notification_is_attempted_and_recorded(engine, ctx, monkeypatch):
    from database import AlertEvent
    sent = {}

    def fake_post(url, json=None, timeout=None):
        sent['url'] = url
        sent['json'] = json
        class R:
            status_code = 204
        return R()

    monkeypatch.setattr(engine, '_webhook_url', lambda: 'https://example/hook')
    monkeypatch.setattr(engine.requests, 'post', fake_post)

    make_rule(engine)
    engine.evaluate('local', {'mem_percent': 95.0}, now=1)

    assert sent['url'] == 'https://example/hook'
    assert 'embeds' in sent['json']
    event = AlertEvent.query.one()
    assert event.notified is True


def test_notification_failure_is_stored_not_raised(engine, ctx, monkeypatch):
    from database import AlertEvent

    def boom(*a, **kw):
        raise RuntimeError('discord down')

    monkeypatch.setattr(engine, '_webhook_url', lambda: 'https://example/hook')
    monkeypatch.setattr(engine.requests, 'post', boom)

    make_rule(engine)
    engine.evaluate('local', {'mem_percent': 95.0}, now=1)
    event = AlertEvent.query.one()
    assert event.notified is False
    assert 'discord down' in (event.notify_error or '')


def test_no_webhook_means_no_delivery(engine, ctx, monkeypatch):
    monkeypatch.setattr(engine, '_webhook_url', lambda: '')
    make_rule(engine)
    fired = engine.evaluate('local', {'mem_percent': 95.0}, now=1)
    assert len(fired) == 1  # still recorded


# --------------------------------------------------------------------- rules

def test_default_rules_are_seeded_once(engine, ctx):
    from database import AlertRule
    AlertRule.query.delete()
    engine.invalidate()
    engine._rules_cache = (0.0, [])
    created = engine.seed_defaults()
    assert created == len(engine.DEFAULT_RULES)
    assert engine.seed_defaults() == 0  # idempotent


def test_invalid_rule_input_is_coerced(engine):
    rule = engine.create_rule({'name': '', 'metric': 'nonsense', 'op': '??',
                               'threshold': 'abc', 'for_seconds': '-5'})
    assert rule['metric'] == 'mem_percent'
    assert rule['op'] == '>='
    assert rule['threshold'] == 0.0
    assert rule['for_seconds'] == 0


def test_update_and_delete_rule(engine):
    rule = make_rule(engine)
    updated = engine.update_rule(rule['id'], {'threshold': 42, 'enabled': False})
    assert updated['threshold'] == 42
    assert updated['enabled'] is False
    assert engine.delete_rule(rule['id']) is True
    assert engine.delete_rule(rule['id']) is False


def test_state_keyed_per_host(engine):
    make_rule(engine)
    a = engine.evaluate('host-a', {'mem_percent': 95.0}, now=1)
    b = engine.evaluate('host-b', {'mem_percent': 95.0}, now=1)
    assert len(a) == 1 and len(b) == 1


def test_snapshot_exposes_state(engine):
    make_rule(engine)
    engine.evaluate('local', {'mem_percent': 95.0}, now=5)
    snap = engine.state_snapshot()
    assert any(key.startswith('local:') for key in snap)


# -------------------------------------------------------------------- routes

def test_rules_api_crud(client, ctx):
    import alerting.engine as engine
    engine.seed_defaults()

    r = client.get('/api/alerts/rules')
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert len(body['rules']) >= 1
    assert 'mem_percent' in body['metrics']

    created = client.post('/api/alerts/rules', json={
        'name': 'api rule', 'metric': 'cpu_percent', 'op': '>', 'threshold': 80
    }).get_json()['rule']
    assert created['name'] == 'api rule'

    updated = client.put(f"/api/alerts/rules/{created['id']}",
                         json={'threshold': 85}).get_json()['rule']
    assert updated['threshold'] == 85

    assert client.delete(f"/api/alerts/rules/{created['id']}").status_code == 200
    assert client.delete(f"/api/alerts/rules/{created['id']}").status_code == 404


def test_events_api_reports_active_and_history(client, ctx):
    import alerting.engine as engine
    engine.create_rule({'name': 'api fire', 'metric': 'mem_percent',
                        'op': '>=', 'threshold': 90, 'for_seconds': 0})
    engine.evaluate('local', {'mem_percent': 95.0})

    body = client.get('/api/alerts/events').get_json()
    assert body['success'] is True
    assert len(body['active']) == 1
    assert body['events'][0]['rule_name'] == 'api fire'


def test_evaluate_endpoint(client, ctx):
    import alerting.engine as engine
    engine.create_rule({'name': 'manual', 'metric': 'disk_percent',
                        'op': '>=', 'threshold': 80, 'for_seconds': 0})
    body = client.post('/api/alerts/evaluate',
                       json={'host': 'x', 'values': {'disk_percent': 90}}).get_json()
    assert len(body['fired']) == 1


def test_alerts_page_renders(client, ctx):
    r = client.get('/alerts')
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert 'id="rules-body"' in html
    assert '/static/js/alerts.js' in html
