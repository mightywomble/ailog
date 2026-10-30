"""Shared pytest fixtures.

The app module creates its database at import time, so ``DATABASE_URL`` has to
be set *before* ``import app``. That is why this conftest sets the environment
at module scope and builds a single app per test session against a temporary
SQLite file.
"""
import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

_DB_FD, _DB_PATH = tempfile.mkstemp(suffix='.db', prefix='ailog-test-')
os.close(_DB_FD)
# Always own the database. A DATABASE_URL inherited from the shell or from CI
# would otherwise point every run at the same file; rows from the previous run
# survive and the deterministic fixture IPs collide on hosts.ip_address.
os.environ['DATABASE_URL'] = f'sqlite:///{_DB_PATH}'
os.environ['AILOG_TESTING'] = '1'
# DB admin routes are opt-in; the suite exercises them, so switch them on here.
os.environ['AILOG_ALLOW_DB_ADMIN'] = '1'


@pytest.fixture(scope='session', autouse=True)
def _throwaway_database():
    """Delete the per-session SQLite file (and its WAL sidecars) when done."""
    yield
    for suffix in ('', '-wal', '-shm'):
        try:
            os.unlink(_DB_PATH + suffix)
        except OSError:
            pass


@pytest.fixture(scope='session')
def app_module():
    import app as app_module
    app_module.app.config.update(TESTING=True)
    return app_module


@pytest.fixture(scope='session')
def flask_app(app_module):
    return app_module.app


@pytest.fixture()
def ctx(flask_app):
    with flask_app.app_context():
        yield


@pytest.fixture()
def client(flask_app):
    with flask_app.test_client() as client:
        yield client


@pytest.fixture()
def db_session(ctx, app_module):
    from database import db
    yield db.session
    db.session.rollback()


_host_counter = {'n': 0}


@pytest.fixture()
def host(ctx):
    """A configured host row; returns its ``db-<id>`` key.

    Each call gets a fresh row (and IP) because ``hosts.ip_address`` is unique.
    """
    from database import Host, db
    # hosts.ip_address is unique; skip any address already present so the
    # fixture cannot fail just because the database carried earlier rows.
    while True:
        _host_counter['n'] += 1
        n = _host_counter['n']
        ip = f'10.0.{n // 250}.{n % 250 + 1}'
        if Host.query.filter_by(ip_address=ip).first() is None:
            break
    row = Host(hostname=f'test-host-{n}', friendly_name=f'test-host-{n}',
               ip_address=ip, ssh_user='tester')
    db.session.add(row)
    db.session.commit()
    return f'db-{row.id}'


@pytest.fixture(autouse=True)
def clean_alert_state():
    """Alert state is process-wide; never leak it between tests."""
    try:
        from alerting import engine
        engine.reset_state()
        engine.invalidate()
    except Exception:
        pass
    yield
    try:
        from alerting import engine
        engine.reset_state()
    except Exception:
        pass
