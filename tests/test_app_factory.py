"""Phase 3: app factory + bootstrap structure."""

from __future__ import annotations

import os
import tempfile

import pytest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture()
def built_app():
    import app as app_module

    fd, path = tempfile.mkstemp(suffix='.db', prefix='ailog-factory-')
    os.close(fd)
    application = app_module.create_app({'SQLALCHEMY_DATABASE_URI': f'sqlite:///{path}'})
    application.config.update(TESTING=True)
    yield application
    try:
        os.unlink(path)
    except OSError:
        pass


def test_create_app_builds_a_working_app(built_app):
    client = built_app.test_client()
    assert client.get('/healthz').status_code == 200
    rules = {r.rule for r in built_app.url_map.iter_rules()}
    assert '/search' in rules
    assert '/hosts' in rules
    assert '/ssh/websocket' in rules
    assert '/api/schedules' in rules
    assert '/admin/db/backup' in rules


def test_create_app_applies_config(built_app):
    assert built_app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite:///')
    assert built_app.config['AILOG_AUTH_MODE'] in ('none', 'proxy', 'local')


def test_create_app_registers_security_hooks(built_app):
    names = {fn.__name__ for fn in built_app.before_request_funcs.get(None, [])}
    assert '_auth_gate' in names
    after = {fn.__name__ for fn in built_app.after_request_funcs.get(None, [])}
    assert '_headers' in after


def test_bootstrap_module_has_no_import_side_effects():
    import core.bootstrap as bootstrap

    assert callable(bootstrap.main)
    assert callable(bootstrap.start_background_services)


def test_app_module_is_three_line_entrypoint():
    body = open(os.path.join(ROOT, 'app.py')).read()
    tail = body[body.index("if __name__ == '__main__':"):]
    assert 'core.bootstrap' in tail
    assert 'app.run(' not in tail
    assert len(tail.strip().splitlines()) <= 6


def test_route_module_uses_blueprint():
    body = open(os.path.join(ROOT, 'app.py')).read()
    assert "core_routes = Blueprint('core_ui', __name__)" in body
    assert body.count('@core_routes.route(') >= 70
