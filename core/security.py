"""Security baseline: authentication gate, security headers, upload limits.

Everything here is driven by environment variables so a deployment can be
hardened without touching code:

    AILOG_AUTH_MODE          none | proxy | local          (default: none)
    AILOG_AUTH_USER          username for local mode       (default: admin)
    AILOG_AUTH_PASSWORD      plaintext password for local mode
    AILOG_AUTH_PASSWORD_HASH werkzeug pbkdf2/scrypt hash   (wins over password)
    AILOG_AUTH_PROXY_HEADER  header carrying the user      (default: X-Forwarded-User)
    AILOG_TRUSTED_PROXIES    comma separated CIDR/IPs allowed to set that header
    AILOG_ALLOW_DB_ADMIN     1 to expose /admin/db/*       (default: 0)
    AILOG_MAX_UPLOAD_MB      request body cap in MB        (default: 32)
    AILOG_HSTS               1 to send Strict-Transport-Security
    AILOG_CSP                override the Content-Security-Policy, or 'off'
    AILOG_WS_ALLOW_NO_ORIGIN 1 to accept websocket upgrades without Origin
    AILOG_WS_ALLOWED_ORIGINS comma separated extra origins/patterns for the
                           SSH terminal websocket (e.g. https://*.home.arpa)
    AILOG_WS_ALLOWED_ORIGINS comma separated extra origins/patterns for the
                           SSH terminal websocket (e.g. https://*.home.arpa)

The module deliberately has no import-time side effects: ``install_security``
is called once from ``app.py`` (and later from the app factory).
"""

from __future__ import annotations

import fnmatch
import hmac
import ipaddress
import os
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from flask import current_app, g, has_app_context, jsonify, request
from werkzeug.security import check_password_hash

AUTH_MODES = ('none', 'proxy', 'local')

# Paths that never require authentication.
PUBLIC_PREFIXES = ('/static/',)
PUBLIC_PATHS = ('/healthz', '/favicon.ico')

DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com data:; "
    "img-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "frame-src 'self'; "
    "frame-ancestors 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


def _env(name: str, default: str = '') -> str:
    return (os.getenv(name) or default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ('1', 'true', 'yes', 'on')


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except (TypeError, ValueError):
        return default


@dataclass
class SecurityConfig:
    auth_mode: str = 'none'
    auth_user: str = 'admin'
    auth_password: str = ''
    auth_password_hash: str = ''
    proxy_header: str = 'X-Forwarded-User'
    trusted_proxies: tuple[ipaddress._BaseNetwork, ...] = field(default_factory=tuple)
    allow_db_admin: bool = False
    max_upload_bytes: int = 32 * 1024 * 1024
    hsts: bool = False
    csp: str = DEFAULT_CSP
    ws_allow_no_origin: bool = False

    @classmethod
    def from_env(cls) -> 'SecurityConfig':
        mode = _env('AILOG_AUTH_MODE', 'none').lower()
        if mode not in AUTH_MODES:
            raise ValueError(f'AILOG_AUTH_MODE must be one of {AUTH_MODES}, got {mode!r}')

        proxies = []
        for raw in _env('AILOG_TRUSTED_PROXIES').split(','):
            raw = raw.strip()
            if not raw:
                continue
            try:
                proxies.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                continue

        csp = _env('AILOG_CSP', DEFAULT_CSP)
        if csp.lower() == 'off':
            csp = ''

        return cls(
            auth_mode=mode,
            auth_user=_env('AILOG_AUTH_USER', 'admin') or 'admin',
            auth_password=_env('AILOG_AUTH_PASSWORD'),
            auth_password_hash=_env('AILOG_AUTH_PASSWORD_HASH'),
            proxy_header=_env('AILOG_AUTH_PROXY_HEADER', 'X-Forwarded-User') or 'X-Forwarded-User',
            trusted_proxies=tuple(proxies),
            allow_db_admin=_env_bool('AILOG_ALLOW_DB_ADMIN'),
            max_upload_bytes=max(1, _env_int('AILOG_MAX_UPLOAD_MB', 32)) * 1024 * 1024,
            hsts=_env_bool('AILOG_HSTS'),
            csp=csp,
            ws_allow_no_origin=_env_bool('AILOG_WS_ALLOW_NO_ORIGIN'),
        )


def _client_ip_allowed(cfg: SecurityConfig) -> bool:
    if not cfg.trusted_proxies:
        return True
    addr = request.remote_addr or ''
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in cfg.trusted_proxies)


def _wants_json() -> bool:
    if request.path.startswith('/api/') or request.path.startswith(('/admin/db', '/ssh-keys', '/monitoring', '/docker', '/reports', '/alerts', '/inventory')):
        return True
    return request.accept_mimetypes.best == 'application/json'


def _unauthorized(message: str = 'Authentication required'):
    if _wants_json():
        resp = jsonify({'error': message})
    else:
        resp = jsonify({'error': message})
    resp.status_code = 401
    resp.headers['WWW-Authenticate'] = 'Basic realm="Homelab Manager", charset="UTF-8"'
    return resp


def authenticate(cfg: SecurityConfig):
    """Return the authenticated user name, or None when access is denied."""
    if cfg.auth_mode == 'none':
        return 'anonymous'

    if cfg.auth_mode == 'proxy':
        if not _client_ip_allowed(cfg):
            return None
        user = (request.headers.get(cfg.proxy_header) or '').strip()
        if not user:
            user = (request.headers.get('X-Forwarded-Email') or '').strip()
        return user or None

    # local mode: HTTP Basic against env credentials
    auth = request.authorization
    if not auth or not auth.username:
        return None
    if not hmac.compare_digest(auth.username, cfg.auth_user):
        return None
    secret = auth.password or ''
    if cfg.auth_password_hash:
        try:
            if check_password_hash(cfg.auth_password_hash, secret):
                return auth.username
        except Exception:
            return None
        return None
    if cfg.auth_password and hmac.compare_digest(secret, cfg.auth_password):
        return auth.username
    return None


def _is_public(path: str) -> bool:
    if path in PUBLIC_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in PUBLIC_PREFIXES)


def install_security(app) -> SecurityConfig:
    """Attach the auth gate, security headers and health probe to *app*."""
    cfg = SecurityConfig.from_env()
    app.config['AILOG_AUTH_MODE'] = cfg.auth_mode
    app.config['AILOG_ALLOW_DB_ADMIN'] = cfg.allow_db_admin
    app.config['AILOG_SECURITY'] = cfg
    app.config['MAX_CONTENT_LENGTH'] = cfg.max_upload_bytes

    @app.before_request
    def _auth_gate():
        if request.method == 'OPTIONS' or _is_public(request.path):
            return None
        user = authenticate(cfg)
        if user is None:
            return _unauthorized()
        g.auth_user = user
        return None

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
        resp.headers.setdefault('Referrer-Policy', 'same-origin')
        resp.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
        resp.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
        if cfg.csp:
            resp.headers.setdefault('Content-Security-Policy', cfg.csp)
        if cfg.hsts or request.is_secure:
            resp.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        # HTML is the shell that references versioned assets; never let a page
        # (or the module URLs inside it) linger in a browser cache after a
        # deploy. Static files keep their ETag but must revalidate.
        if resp.mimetype == 'text/html':
            resp.headers['Cache-Control'] = 'no-store, must-revalidate'
        elif request.path.startswith('/static/'):
            resp.headers.setdefault('Cache-Control', 'no-cache')
        return resp

    @app.errorhandler(413)
    def _too_large(_err):
        return jsonify({'error': f'Upload too large (limit {cfg.max_upload_bytes // (1024 * 1024)} MB)'}), 413

    @app.route('/healthz')
    def healthz():
        return jsonify({'status': 'ok', 'auth_mode': cfg.auth_mode})

    app.logger.info(
        'security: auth_mode=%s db_admin=%s max_upload=%dMB hsts=%s',
        cfg.auth_mode, cfg.allow_db_admin, cfg.max_upload_bytes // (1024 * 1024), cfg.hsts,
    )
    return cfg


def _split_host(value: str) -> tuple[str, int | None]:
    """Return (lowercase hostname, explicit port) for a Host or Origin value."""
    value = (value or '').strip()
    if not value:
        return '', None
    parts = urlsplit(value if '://' in value else '//' + value)
    try:
        port = parts.port
    except ValueError:
        port = None
    return (parts.hostname or '').lower(), port


def _allowed_origin_patterns() -> list[str]:
    raw = _env('AILOG_WS_ALLOWED_ORIGINS')
    return [p.strip().lower().rstrip('/') for p in raw.split(',') if p.strip()]


def websocket_origin_allowed() -> bool:
    """Validate the Origin header of a WebSocket upgrade request.

    The first version compared Origin against request.host_url exactly, so
    every deployment reached through a reverse proxy or a different hostname
    (https in the browser, plain http to Flask) had its SSH terminal rejected.
    We now compare the host the request was addressed to - including the
    X-Forwarded-Host that a proxy adds and a browser cannot forge - and allow
    extra origins via AILOG_WS_ALLOWED_ORIGINS.
    """
    origin = request.headers.get('Origin')
    if not origin:
        return _env_bool('AILOG_WS_ALLOW_NO_ORIGIN')

    origin = origin.strip()
    normalised = origin.lower().rstrip('/')

    for pattern in _allowed_origin_patterns():
        if fnmatch.fnmatchcase(normalised, pattern):
            return True

    origin_host, origin_port = _split_host(origin)
    if not origin_host:
        return False

    candidates = {request.host or ''}
    forwarded = request.headers.get('X-Forwarded-Host') or ''
    for value in forwarded.split(','):
        if value.strip():
            candidates.add(value.strip())

    for candidate in candidates:
        host, port = _split_host(candidate)
        if host != origin_host:
            continue
        # Proxies usually rewrite the port; only enforce it when both sides
        # spell one out (otherwise https://host vs host:5001 never matches).
        if port is None or origin_port is None or port == origin_port:
            return True

    if has_app_context():
        current_app.logger.warning(
            'websocket origin rejected: origin=%s host=%s x-forwarded-host=%s '
            '(set AILOG_WS_ALLOWED_ORIGINS to allow it)',
            origin, request.host, forwarded or '-',
        )
    return False
