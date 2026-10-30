"""Policy: the deployment decides whether remediation may touch anything.

Every switch here is environment-driven, defaults to the safe value, and is
re-read on each call so a running process can be tightened without a restart.
"""

from __future__ import annotations

import datetime

from remediation import policy


def test_off_is_the_default_mode(monkeypatch):
    monkeypatch.delenv('AILOG_ALLOW_REMEDIATION', raising=False)
    assert policy.mode() == 'off'
    assert policy.enabled() is False
    assert policy.forced_dry_run() is False


def test_an_unknown_mode_falls_back_to_off(monkeypatch):
    monkeypatch.setenv('AILOG_ALLOW_REMEDIATION', 'yes-please')
    assert policy.mode() == 'off'
    assert policy.enabled() is False


def test_dry_run_is_enabled_but_forced_dry(monkeypatch):
    monkeypatch.setenv('AILOG_ALLOW_REMEDIATION', 'dry_run')
    assert policy.enabled() is True
    assert policy.forced_dry_run() is True


def test_on_allows_real_runs(monkeypatch):
    monkeypatch.setenv('AILOG_ALLOW_REMEDIATION', 'ON')
    assert policy.mode() == 'on'
    assert policy.enabled() is True
    assert policy.forced_dry_run() is False


def test_caps_have_safe_defaults(monkeypatch):
    for name in ('AILOG_REMEDIATION_MAX_HOSTS', 'AILOG_REMEDIATION_MAX_CONCURRENT',
                 'AILOG_REMEDIATION_RETENTION_DAYS', 'AILOG_REMEDIATION_SETTLE_CAP',
                 'AILOG_REMEDIATION_TIMEOUT'):
        monkeypatch.delenv(name, raising=False)
    assert policy.max_hosts() == 10
    assert policy.max_concurrent() == 2
    assert policy.retention_days() == 30
    assert policy.settle_cap() == 60
    assert policy.run_timeout() == 300


def test_nonsense_numbers_do_not_break_policy(monkeypatch):
    monkeypatch.setenv('AILOG_REMEDIATION_MAX_HOSTS', 'many')
    monkeypatch.setenv('AILOG_REMEDIATION_RETENTION_DAYS', '-5')
    monkeypatch.setenv('AILOG_REMEDIATION_TIMEOUT', '1')
    assert policy.max_hosts() == 10          # unparsable -> default
    assert policy.retention_days() == 1      # clamped to at least one day
    assert policy.run_timeout() == 30        # clamped to a usable timeout


def test_the_idea_channel_defaults_on_and_can_be_closed(monkeypatch):
    monkeypatch.delenv('AILOG_REMEDIATION_ALLOW_IDEA_CHANNEL', raising=False)
    assert policy.idea_channel_enabled() is True
    monkeypatch.setenv('AILOG_REMEDIATION_ALLOW_IDEA_CHANNEL', '0')
    assert policy.idea_channel_enabled() is False


def test_the_closure_reporter_is_off_by_default(monkeypatch):
    monkeypatch.delenv('AILOG_REMEDIATION_CLOSURE', raising=False)
    assert policy.closure_enabled() is False


def test_a_protected_host_is_recognised():
    class H:
        do_not_remediate = True

    class Bare:
        pass

    assert policy.host_protected(H()) is True
    assert policy.host_protected(Bare()) is False


def test_artifact_root_is_created_and_configurable(tmp_path, monkeypatch):
    monkeypatch.setenv('AILOG_REMEDIATION_ARTIFACT_DIR', str(tmp_path / 'arts'))
    root = policy.artifact_root()
    assert root.is_dir()
    assert str(root).startswith(str(tmp_path))


# --- maintenance windows ---------------------------------------------------


class _Window:
    def __init__(self, **kw):
        self.enabled = kw.get('enabled', True)
        self.group_id = kw.get('group_id')
        self.tag_id = kw.get('tag_id')
        self.timezone = kw.get('timezone', 'UTC')
        self.days = kw.get('days', '1,2,3,4,5,6,7')
        self.start_time = kw.get('start_time', '22:00')
        self.end_time = kw.get('end_time', '02:00')
        self.mode = kw.get('mode', 'block')
        self.name = kw.get('name', 'window')


class _Host:
    groups = []
    tags = []


def _at(iso):
    return datetime.datetime.fromisoformat(iso)


def test_a_window_that_wraps_midnight_blocks_both_sides():
    window = _Window(start_time='22:00', end_time='02:00')
    assert policy.check_windows(_Host(), [window], _at('2026-10-30T23:30:00+00:00'))[0] is False
    assert policy.check_windows(_Host(), [window], _at('2026-10-30T01:00:00+00:00'))[0] is False
    assert policy.check_windows(_Host(), [window], _at('2026-10-30T12:00:00+00:00'))[0] is True


def test_a_daytime_window_blocks_only_inside_its_hours():
    window = _Window(start_time='09:00', end_time='17:00')
    assert policy.check_windows(_Host(), [window], _at('2026-10-30T09:00:00+00:00'))[0] is False
    assert policy.check_windows(_Host(), [window], _at('2026-10-30T16:59:00+00:00'))[0] is False
    assert policy.check_windows(_Host(), [window], _at('2026-10-30T17:00:00+00:00'))[0] is True


def test_the_weekday_list_is_honoured():
    # 2026-10-31 is a Saturday (isoweekday 6).
    window = _Window(days='1,2,3,4,5', start_time='00:00', end_time='23:59')
    assert policy.check_windows(_Host(), [window], _at('2026-10-31T12:00:00+00:00'))[0] is True
    assert policy.check_windows(_Host(), [window], _at('2026-10-30T12:00:00+00:00'))[0] is False


def test_a_disabled_window_never_matches():
    window = _Window(enabled=False, start_time='00:00', end_time='23:59')
    assert policy.check_windows(_Host(), [window], _at('2026-10-30T12:00:00+00:00'))[0] is True


def test_a_warn_window_allows_the_run_but_says_why():
    window = _Window(mode='warn', start_time='00:00', end_time='23:59')
    allowed, reason = policy.check_windows(_Host(), [window], _at('2026-10-30T12:00:00+00:00'))
    assert allowed is True
    assert 'warn only' in reason


def test_the_window_timezone_is_applied():
    # 22:15 UTC is 09:15 the next day in Sydney (UTC+11 in October).
    window = _Window(start_time='08:30', end_time='09:30', timezone='Australia/Sydney')
    assert policy.check_windows(_Host(), [window], _at('2026-10-30T22:15:00+00:00'))[0] is False
    # ...and 12:00 UTC is 23:00 there, outside the window.
    assert policy.check_windows(_Host(), [window], _at('2026-10-30T12:00:00+00:00'))[0] is True


def test_an_unknown_timezone_falls_back_to_utc():
    window = _Window(start_time='00:00', end_time='23:59', timezone='Mars/Olympus')
    assert policy.check_windows(_Host(), [window], _at('2026-10-30T12:00:00+00:00'))[0] is False


def test_a_host_outside_a_window_group_is_not_blocked():
    window = _Window(group_id=42, start_time='00:00', end_time='23:59')
    assert policy.check_windows(_Host(), [window], _at('2026-10-30T12:00:00+00:00'))[0] is True


def test_no_windows_means_always_allowed():
    assert policy.check_windows(_Host(), [], _at('2026-10-30T12:00:00+00:00')) == (True, '')


# --- retention -------------------------------------------------------------


def test_prune_artifacts_removes_only_old_directories(tmp_path):
    import os
    import time
    old = tmp_path / 'old-run'
    new = tmp_path / 'new-run'
    old.mkdir()
    new.mkdir()
    stale = time.time() - 40 * 86400
    os.utime(old, (stale, stale))
    removed = policy.prune_artifacts(root=tmp_path, days=30)
    assert removed == 1
    assert not old.exists()
    assert new.exists()
