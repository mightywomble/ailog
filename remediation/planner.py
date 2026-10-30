"""Target resolution and confirmation tokens.

A plan is a promise: the exact host set, the wave order and the eligible
rows are computed first, signed into a short-lived token, and re-checked on
apply. The browser therefore cannot widen the scope between the dialog the
user read and the run that happens.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import logging
import os

from remediation import inventory, policy

log = logging.getLogger(__name__)
TOKEN_TTL = 300


def _secret() -> bytes:
    raw = os.getenv('AILOG_SECRET_KEY') or os.getenv('SECRET_KEY') or 'ailog-remediation-dev'
    return raw.encode()


def fingerprint(slug: str, host_keys, dry_run: bool) -> str:
    payload = json.dumps({'slug': slug, 'hosts': sorted(host_keys), 'dry': bool(dry_run)}, sort_keys=True)
    return hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()


def make_token(slug: str, host_keys, dry_run: bool, ttl: int = TOKEN_TTL) -> tuple[str, str]:
    expires = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + int(ttl)
    payload = json.dumps({'slug': slug, 'hosts': sorted(host_keys), 'dry': bool(dry_run), 'exp': expires}, sort_keys=True)
    sig = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return f'{sig}.{expires}', fingerprint(slug, host_keys, dry_run)


def check_token(token: str, slug: str, host_keys, dry_run: bool) -> tuple[bool, str]:
    try:
        sig, expires = str(token or '').split('.', 1)
        expires = int(expires)
    except (ValueError, AttributeError):
        return False, 'Malformed confirmation token.'
    if expires < int(datetime.datetime.now(datetime.timezone.utc).timestamp()):
        return False, 'This plan expired; reopen the dialog and try again.'
    payload = json.dumps({'slug': slug, 'hosts': sorted(host_keys), 'dry': bool(dry_run), 'exp': expires}, sort_keys=True)
    expected = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False, 'The plan no longer matches the requested targets.'
    return True, ''


def latest_match_hosts(models, slug: str) -> list[str]:
    """Hosts whose newest stored card for this slug is still open."""
    rows = (models.RemediationMatch.query
            .filter(models.RemediationMatch.slug == slug,
                    models.RemediationMatch.state == 'open')
            .order_by(models.RemediationMatch.report_id.desc()).all())
    seen, hosts = set(), []
    for row in rows:
        if row.host_key in seen:
            continue
        seen.add(row.host_key)
        hosts.append(row.host_key)
    return hosts[:200]


def _host_from_key(models, key: str):
    if not key or not key.startswith('db-'):
        return None
    try:
        return models.Host.query.get(int(key.split('-', 1)[1]))
    except (ValueError, TypeError):
        return None


def resolve(models, slug: str, scope: str, host_key: str | None, group_id=None) -> list[dict]:
    """Return [{host, host_key, label, eligible, why}] for the requested scope."""
    scope = (scope or 'host').lower()
    rows = []
    if scope == 'host':
        host = _host_from_key(models, host_key or '')
        if host:
            rows = [host]
    elif scope == 'group' and group_id:
        rows = (models.Host.query.join(models.Host.groups)
                .filter(models.Group.id == int(group_id)).all())
    elif scope == 'fleet':
        keys = latest_match_hosts(models, slug)
        rows = [h for h in (_host_from_key(models, key) for key in keys) if h]
    else:
        rows = []

    windows = models.RemediationWindow.query.filter_by(enabled=True).all()
    result, seen = [], set()
    for host in rows:
        key = inventory.host_key(host)
        if key in seen:
            continue
        seen.add(key)
        label = host.friendly_name or host.hostname or key
        eligible, why = True, ''
        if policy.host_protected(host):
            eligible, why = False, 'Marked do-not-remediate'
        elif (host.status or '').lower() == 'offline':
            eligible, why = False, 'Host is offline'
        else:
            allowed, reason = policy.check_windows(host, windows)
            if not allowed:
                eligible, why = False, reason
        result.append({'host': host, 'host_key': key, 'label': label,
                       'eligible': eligible, 'why': why})
    return result