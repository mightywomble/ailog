"""Phase 1 security baseline tests: auth gate, headers, upload limits, pins."""

from __future__ import annotations

import base64
import hashlib
import os
import re

import pytest

from core import hostkeys
from core.security import SecurityConfig, websocket_origin_allowed


@pytest.fixture()
def security_cfg(flask_app):
    return flask_app.config['AILOG_SECURITY']


def _basic(user: str, password: str) -> dict:
    token = base64.b64encode(f'{user}:{password}'.encode()).decode()
    return {'Authorization': f'Basic {token}'}


# --- authentication -------------------------------------------------------


def test_healthz_is_public_and_reports_mode(client):
    r = client.get('/healthz')
    assert r.status_code == 200
    assert r.get_json()['auth_mode'] in ('none', 'proxy', 'local')


def test_default_mode_allows_anonymous(client):
    assert client.get('/hosts').status_code in (200, 404, 500)


def test_local_mode_requires_credentials(client, security_cfg, monkeypatch):
    monkeypatch.setattr(security_cfg, 'auth_mode', 'local')
    monkeypatch.setattr(security_cfg, 'auth_user', 'admin')
    monkeypatch.setattr(security_cfg, 'auth_password', 's3cret')
    monkeypatch.setattr(security_cfg, 'auth_password_hash', '')

    assert client.get('/hosts').status_code == 401
    unauth = client.get('/hosts')
    assert 'Basic realm=' in unauth.headers['WWW-Authenticate']

    assert client.get('/hosts', headers=_basic('admin', 'wrong')).status_code == 401
    assert client.get('/hosts', headers=_basic('nobody', 's3cret')).status_code == 401
    assert client.get('/hosts', headers=_basic('admin', 's3cret')).status_code != 401


def test_local_mode_hashed_password(client, security_cfg, monkeypatch):
    from werkzeug.security import generate_password_hash

    monkeypatch.setattr(security_cfg, 'auth_mode', 'local')
    monkeypatch.setattr(security_cfg, 'auth_user', 'admin')
    monkeypatch.setattr(security_cfg, 'auth_password', '')
    monkeypatch.setattr(security_cfg, 'auth_password_hash', generate_password_hash('hunter2'))

    assert client.get('/hosts').status_code == 401
    assert client.get('/hosts', headers=_basic('admin', 'hunter2')).status_code != 401
    assert client.get('/hosts', headers=_basic('admin', 'hunter3')).status_code == 401


def test_proxy_mode_uses_header(client, security_cfg, monkeypatch):
    monkeypatch.setattr(security_cfg, 'auth_mode', 'proxy')
    monkeypatch.setattr(security_cfg, 'proxy_header', 'X-Forwarded-User')
    assert client.get('/hosts').status_code == 401
    assert client.get('/hosts', headers={'X-Forwarded-User': 'david'}).status_code != 401


def test_static_is_public_in_local_mode(client, security_cfg, monkeypatch):
    monkeypatch.setattr(security_cfg, 'auth_mode', 'local')
    monkeypatch.setattr(security_cfg, 'auth_password', 's3cret')
    assert client.get('/static/css/style.css').status_code == 200


# --- headers --------------------------------------------------------------


def test_security_headers_present(client):
    r = client.get('/healthz')
    for header in (
        'X-Content-Type-Options',
        'Referrer-Policy',
        'X-Frame-Options',
        'Permissions-Policy',
        'Content-Security-Policy',
    ):
        assert header in r.headers
    assert r.headers['X-Content-Type-Options'] == 'nosniff'
    assert r.headers['X-Frame-Options'] == 'SAMEORIGIN'
    csp = r.headers['Content-Security-Policy']
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'self'" in csp
    assert "object-src 'none'" in csp


def test_hsts_only_when_enabled(client, security_cfg, monkeypatch):
    monkeypatch.setattr(security_cfg, 'hsts', False)
    assert 'Strict-Transport-Security' not in client.get('/healthz').headers
    monkeypatch.setattr(security_cfg, 'hsts', True)
    assert 'Strict-Transport-Security' in client.get('/healthz').headers


def test_csp_can_be_disabled(client, security_cfg, monkeypatch):
    monkeypatch.setattr(security_cfg, 'csp', '')
    assert 'Content-Security-Policy' not in client.get('/healthz').headers


# --- config parsing -------------------------------------------------------


def test_config_defaults(monkeypatch):
    for name in ('AILOG_AUTH_MODE', 'AILOG_ALLOW_DB_ADMIN', 'AILOG_HSTS', 'AILOG_MAX_UPLOAD_MB'):
        monkeypatch.delenv(name, raising=False)
    cfg = SecurityConfig.from_env()
    assert cfg.auth_mode == 'none'
    assert cfg.allow_db_admin is False
    assert cfg.hsts is False
    assert cfg.max_upload_bytes == 32 * 1024 * 1024


def test_config_rejects_unknown_auth_mode(monkeypatch):
    monkeypatch.setenv('AILOG_AUTH_MODE', 'magic')
    with pytest.raises(ValueError):
        SecurityConfig.from_env()


def test_upload_cap_is_applied(flask_app, monkeypatch):
    monkeypatch.setenv('AILOG_MAX_UPLOAD_MB', '7')
    cfg = SecurityConfig.from_env()
    assert cfg.max_upload_bytes == 7 * 1024 * 1024
    assert flask_app.config['MAX_CONTENT_LENGTH'] > 0


def test_trusted_proxies_parse(monkeypatch):
    monkeypatch.setenv('AILOG_TRUSTED_PROXIES', '10.0.0.0/8, 192.168.1.5, nope')
    cfg = SecurityConfig.from_env()
    assert len(cfg.trusted_proxies) == 2


# --- db admin gate --------------------------------------------------------


def test_db_admin_disabled_by_default(client, flask_app, monkeypatch):
    monkeypatch.setitem(flask_app.config, 'AILOG_ALLOW_DB_ADMIN', False)
    assert client.get('/admin/db/backup').status_code == 403


def test_db_admin_requires_auth_in_local_mode(client, flask_app, security_cfg, monkeypatch):
    monkeypatch.setattr(security_cfg, 'auth_mode', 'local')
    monkeypatch.setattr(security_cfg, 'auth_user', 'admin')
    monkeypatch.setattr(security_cfg, 'auth_password', 's3cret')
    assert client.get('/admin/db/backup').status_code == 401


# --- websocket origin -----------------------------------------------------


def test_websocket_origin_must_match_host(flask_app):
    with flask_app.test_request_context('/', headers={'Origin': 'http://localhost'}):
        assert websocket_origin_allowed() is True
    with flask_app.test_request_context('/', headers={'Origin': 'http://evil.example'}):
        assert websocket_origin_allowed() is False
    with flask_app.test_request_context('/'):
        assert websocket_origin_allowed() is False


def test_websocket_origin_can_be_relaxed(flask_app, monkeypatch):
    monkeypatch.setenv('AILOG_WS_ALLOW_NO_ORIGIN', '1')
    with flask_app.test_request_context('/'):
        assert websocket_origin_allowed() is True


# --- host keys ------------------------------------------------------------


def test_host_key_policy_defaults_to_accept_new(monkeypatch):
    monkeypatch.delenv('AILOG_SSH_HOST_KEY_POLICY', raising=False)
    assert hostkeys.policy() == 'accept-new'
    opts = hostkeys.ssh_cli_options()
    assert 'StrictHostKeyChecking=accept-new' in opts
    assert 'UserKnownHostsFile=/dev/null' not in opts


def test_host_key_strict_mode(monkeypatch):
    monkeypatch.setenv('AILOG_SSH_HOST_KEY_POLICY', 'strict')
    assert 'StrictHostKeyChecking=yes' in hostkeys.ssh_cli_options()
    assert hostkeys.paramiko_policy().__class__.__name__ == 'RejectPolicy'


def test_host_key_off_is_legacy_escape_hatch(monkeypatch):
    monkeypatch.setenv('AILOG_SSH_HOST_KEY_POLICY', 'off')
    assert 'StrictHostKeyChecking=no' in hostkeys.ssh_cli_options()
    assert 'UserKnownHostsFile=/dev/null' in hostkeys.ssh_cli_options()


def test_exported_config_does_not_disable_host_checking():
    block = hostkeys.ssh_config_block()
    assert 'StrictHostKeyChecking accept-new' in block
    assert '/dev/null' not in block


# --- vendored front-end assets -------------------------------------------


VENDOR_HASHES = {
    'tailwindcss-3.4.16.js': 'sha384-',
    'chart-4.4.1.umd.min.js': 'sha384-',
    'marked-12.0.2.min.js': 'sha384-',
    'dompurify-3.1.6.min.js': 'sha384-',
}

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.mark.parametrize('filename', sorted(VENDOR_HASHES))
def test_vendored_asset_exists(filename):
    path = os.path.join(ROOT, 'static', 'vendor', filename)
    assert os.path.getsize(path) > 1000


@pytest.mark.parametrize('filename', sorted(VENDOR_HASHES))
def test_template_integrity_matches_vendored_file(filename):
    path = os.path.join(ROOT, 'static', 'vendor', filename)
    digest = base64.b64encode(hashlib.sha384(open(path, 'rb').read()).digest()).decode()
    expected = f'integrity="sha384-{digest}"'

    templates_dir = os.path.join(ROOT, 'templates')
    found = False
    for name in os.listdir(templates_dir):
        if not name.endswith('.html'):
            continue
        html = open(os.path.join(templates_dir, name)).read()
        for tag in re.findall(r'<script[^>]*>', html):
            if f'/static/vendor/{filename}' in tag:
                found = True
                assert expected in tag, f'{name}: SRI hash mismatch for {filename}'
    assert found, f'no template references {filename}'


def test_no_cdn_script_tags_remain():
    templates_dir = os.path.join(ROOT, 'templates')
    offenders = []
    for name in os.listdir(templates_dir):
        if not name.endswith('.html'):
            continue
        html = open(os.path.join(templates_dir, name)).read()
        for tag in re.findall(r'<script[^>]+src="([^"]+)"', html):
            if tag.startswith('http'):
                offenders.append((name, tag))
    assert offenders == []
