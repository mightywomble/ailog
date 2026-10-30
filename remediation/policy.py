"""Remediation policy: execution mode, protection, windows, limits.

Everything here is environment-driven so a deployment can stay read-only
by default.  Modes:

    AILOG_ALLOW_REMEDIATION=off      cards are visible, apply is 403
    AILOG_ALLOW_REMEDIATION=dry_run  apply runs --check --diff only
    AILOG_ALLOW_REMEDIATION=on       apply really runs
"""

from __future__ import annotations

import datetime
import logging
import os
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

log = logging.getLogger(__name__)

MODES = ('off', 'dry_run', 'on')
REASONS = ('false_positive', 'already_fixed', 'not_now', 'too_risky', 'other')


def _env(name: str, default: str = '') -> str:
    return (os.getenv(name) or default).strip()


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ('1', 'true', 'yes', 'on')


def mode() -> str:
    value = _env('AILOG_ALLOW_REMEDIATION', 'off').lower()
    return value if value in MODES else 'off'


def enabled() -> bool:
    return mode() != 'off'


def forced_dry_run() -> bool:
    return mode() == 'dry_run'


def idea_channel_enabled() -> bool:
    return _env_bool('AILOG_REMEDIATION_ALLOW_IDEA_CHANNEL', True)


def closure_enabled() -> bool:
    return _env_bool('AILOG_REMEDIATION_CLOSURE', False)


def max_hosts() -> int:
    return max(1, _env_int('AILOG_REMEDIATION_MAX_HOSTS', 10))


def max_concurrent() -> int:
    return max(1, _env_int('AILOG_REMEDIATION_MAX_CONCURRENT', 2))


def retention_days() -> int:
    return max(1, _env_int('AILOG_REMEDIATION_RETENTION_DAYS', 30))


def artifact_root() -> Path:
    raw = _env('AILOG_REMEDIATION_ARTIFACT_DIR')
    if raw:
        path = Path(raw)
    else:
        path = Path(os.getenv('AILOG_DATA_DIR') or '/tmp/ailog-remediation')
    path.mkdir(parents=True, exist_ok=True)
    return path


def settle_cap() -> int:
    return max(0, _env_int('AILOG_REMEDIATION_SETTLE_CAP', 60))


def run_timeout() -> int:
    return max(30, _env_int('AILOG_REMEDIATION_TIMEOUT', 300))


def host_protected(host) -> bool:
    return bool(getattr(host, 'do_not_remediate', False))


def _window_matches(window, now: datetime.datetime, host) -> bool:
    if not window.enabled:
        return False
    if window.group_id and not any(g.id == window.group_id for g in getattr(host, 'groups', []) or []):
        return False
    if window.tag_id and not any(t.id == window.tag_id for t in getattr(host, 'tags', []) or []):
        return False
    try:
        tz = ZoneInfo(window.timezone or 'UTC')
    except (ZoneInfoNotFoundError, ValueError):
        tz = datetime.timezone.utc
    local = now.astimezone(tz)
    days = {int(d) for d in (window.days or '').split(',') if d.strip().isdigit()}
    if days and local.isoweekday() not in days:
        return False
    try:
        start_h, start_m = [int(x) for x in (window.start_time or '00:00').split(':')]
        end_h, end_m = [int(x) for x in (window.end_time or '23:59').split(':')]
    except ValueError:
        return False
    minute = local.hour * 60 + local.minute
    start, end = start_h * 60 + start_m, end_h * 60 + end_m
    if start == end:
        return True
    if start < end:
        return start <= minute < end
    return minute >= start or minute < end


def check_windows(host, windows, now: datetime.datetime | None = None) -> tuple[bool, str]:
    """Return (allowed, reason). A matching block window forbids the run."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    for window in windows or []:
        if not _window_matches(window, now, host):
            continue
        if (window.mode or 'block') == 'warn':
            return True, f'Inside window {window.name!r} (warn only)'
        return False, f'Blocked by maintenance window {window.name!r}'
    return True, ''


def run_rate_limited(db, models, host_key: str, slug: str, minutes: int = 10) -> bool:
    """True when this host already had a run of this remedy recently."""
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(minutes=minutes)
    query = (db.session.query(models.RemediationTarget.id)
             .join(models.RemediationRun, models.RemediationTarget.run_id == models.RemediationRun.id)
             .filter(models.RemediationTarget.host_key == host_key,
                     models.RemediationRun.slug == slug,
                     models.RemediationRun.started_at >= cutoff))
    return query.first() is not None


def prune_artifacts(root: Path | None = None, days: int | None = None) -> int:
    root = root or artifact_root()
    cutoff = datetime.datetime.now().timestamp() - (days or retention_days()) * 86400
    removed = 0
    for child in root.iterdir() if root.exists() else []:
        try:
            if child.is_dir() and child.stat().st_mtime < cutoff:
                import shutil
                shutil.rmtree(child, ignore_errors=True)
                removed += 1
        except OSError:
            continue
    return removed