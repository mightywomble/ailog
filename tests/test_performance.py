"""Phase 6: dashboard aggregate, ETag/304, adaptive polling, bounded caches."""

from __future__ import annotations

import os


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_overview_aggregate_shape(client):
    r = client.get('/api/overview')
    assert r.status_code == 200
    payload = r.get_json()
    for key in ('ts', 'servers', 'alerts', 'reports'):
        assert key in payload


def test_overview_returns_etag_and_304(client):
    first = client.get('/api/overview')
    etag = first.headers.get('ETag')
    assert etag

    second = client.get('/api/overview', headers={'If-None-Match': etag})
    assert second.status_code == 304
    assert second.data == b''


def test_overview_etag_ignores_timestamp(client):
    from overview.routes import _etag_for

    a = {'ts': 1, 'servers': {'x': 1}, 'alerts': {}, 'reports': {}}
    b = {'ts': 2, 'servers': {'x': 1}, 'alerts': {}, 'reports': {}}
    assert _etag_for(a) == _etag_for(b)
    b['servers'] = {'x': 2}
    assert _etag_for(a) != _etag_for(b)


def test_overview_survives_a_broken_subsystem(client, monkeypatch):
    import overview.routes as routes

    monkeypatch.setattr(routes, '_fleet', lambda: (_ for _ in ()).throw(RuntimeError('no ssh')))
    payload = client.get('/api/overview').get_json()
    assert payload['servers']['error'] == 'no ssh'
    assert 'reports' in payload


def test_overview_summary(client):
    data = client.get('/api/overview/summary').get_json()
    assert set(data) >= {'servers', 'active_alerts', 'ts'}


def test_sqlite_engine_options_and_pragmas(flask_app):
    from database import db

    options = flask_app.config.get('SQLALCHEMY_ENGINE_OPTIONS') or {}
    if flask_app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        assert options['connect_args']['timeout'] == 30
        with flask_app.app_context():
            assert db.session.execute(db.text('PRAGMA journal_mode')).fetchone()[0] == 'wal'


def test_caches_are_bounded():
    body = open(os.path.join(ROOT, 'app.py')).read()
    assert '_HOST_SOURCES_CACHE_MAX = 64' in body
    assert '_SURICATA_KEY_CACHE_MAX = 16' in body
    assert 'def _cache_host_sources(' in body

    bundles = open(os.path.join(ROOT, 'serverreport', 'routes.py')).read()
    assert 'BUNDLE_MAX_ENTRIES = 32' in bundles


def test_scheduler_can_be_disabled_for_web_replicas():
    body = open(os.path.join(ROOT, 'core', 'bootstrap.py')).read()
    assert 'AILOG_RUN_SCHEDULER' in body


def test_overview_js_uses_the_aggregate_and_conditional_requests():
    body = open(os.path.join(ROOT, 'static', 'js', 'overview.js')).read()
    assert "'/api/overview'" in body
    assert 'If-None-Match' in body
    assert '304' in body
    assert 'Math.pow(1.6' in body          # exponential backoff
    assert '60000' in body                 # capped at a minute
    assert '/api/metrics/servers' not in body


def test_metrics_page_has_adaptive_interval():
    body = open(os.path.join(ROOT, 'static', 'js', 'metrics-page.js')).read()
    assert 'function effectiveInterval()' in body
    assert 'state.failures' in body
    assert 'setTimeout' in body
