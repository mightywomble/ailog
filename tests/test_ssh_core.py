"""Phase 2: every remote-exec path goes through core.ssh."""

from __future__ import annotations

import os
import re
import subprocess

import pytest

from core import ssh


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_ssh_argv_has_safe_defaults(monkeypatch):
    monkeypatch.setenv('AILOG_SSH_HOST_KEY_POLICY', 'accept-new')
    argv = ssh.ssh_argv('root', '10.0.0.5')
    assert argv[0] == 'ssh'
    assert 'StrictHostKeyChecking=accept-new' in argv
    assert 'BatchMode=yes' in argv
    assert 'IdentitiesOnly=yes' in argv
    assert any(a.startswith('ConnectTimeout=') for a in argv)
    assert argv[-1] == 'root@10.0.0.5'


def test_ssh_argv_adds_identity_file():
    argv = ssh.ssh_argv('tester', 'host.example', identity_file='/tmp/key')
    assert argv[argv.index('-i') + 1] == '/tmp/key'


def test_run_host_uses_shell_for_local(monkeypatch):
    monkeypatch.setattr(ssh.subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(
        a[0], 0, stdout='hello\n', stderr=''))
    ok, out = ssh.run_host({'key': 'local'}, 'echo hello')
    assert ok is True
    assert out == 'hello\n'


def test_run_host_remote_passes_command(monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen['argv'] = argv
        return subprocess.CompletedProcess(argv, 0, stdout='remote-ok', stderr='')

    monkeypatch.setattr(ssh.subprocess, 'run', fake_run)
    ok, out = ssh.run_host({'key': 'db-1', 'user': 'root', 'ip': '10.0.0.9'}, 'uptime', timeout=3)
    assert (ok, out) == (True, 'remote-ok')
    assert seen['argv'][-2:] == ['root@10.0.0.9', 'uptime']


def test_run_remote_returns_stderr_on_failure(monkeypatch):
    monkeypatch.setattr(ssh.subprocess, 'run', lambda argv, **k: subprocess.CompletedProcess(
        argv, 255, stdout='', stderr='Permission denied'))
    ok, out = ssh.run_remote('root', '10.0.0.9', 'true')
    assert ok is False
    assert 'Permission denied' in out


def test_run_remote_handles_timeout(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired('ssh', 5)

    monkeypatch.setattr(ssh.subprocess, 'run', boom)
    ok, out = ssh.run_remote('root', '10.0.0.9', 'sleep 60', timeout=5)
    assert ok is False
    assert 'timed out' in out.lower()


def test_fanout_keys_by_host_and_captures_errors():
    hosts = [{'key': 'a'}, {'key': 'b'}]

    def fn(host):
        if host['key'] == 'b':
            raise RuntimeError('unreachable')
        return 'ok'

    results = ssh.fanout(hosts, fn)
    assert results['a'] == 'ok'
    assert results['b'] == {'error': 'unreachable'}


def test_no_module_builds_its_own_ssh_command():
    """The point of phase 2: one transport, not five copies."""
    offenders = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in {'venv', '.git', 'node_modules', 'tests', '__pycache__', 'static'}]
        for name in filenames:
            if not name.endswith('.py'):
                continue
            path = os.path.join(dirpath, name)
            if path.endswith(os.path.join('core', 'ssh.py')):
                continue
            body = open(path).read()
            if re.search(r'["\']ssh["\'],\s*["\']-o["\'],\s*["\']ConnectTimeout', body):
                offenders.append(os.path.relpath(path, ROOT))
    assert offenders == []


def test_wizard_helpers_delegates_to_core_ssh():
    body = open(os.path.join(ROOT, 'wizard_helpers.py')).read()
    assert 'from core.ssh import run_remote' in body
    assert 'StrictHostKeyChecking' not in body


def test_metrics_collect_uses_run_host():
    body = open(os.path.join(ROOT, 'metrics', 'collect.py')).read()
    assert 'from core.ssh import run_host' in body
    assert 'subprocess' not in body


def test_dockermon_endpoints_uses_core_ssh():
    body = open(os.path.join(ROOT, 'dockermon', 'endpoints.py')).read()
    assert 'from core.ssh import run_remote as ssh_run_remote' in body


def test_app_ssh_prefix_uses_core_ssh():
    body = open(os.path.join(ROOT, 'app.py')).read()
    assert 'from core.ssh import ssh_argv' in body
    assert 'StrictHostKeyChecking=no' not in body


@pytest.mark.parametrize('module', ['wizard_helpers', 'dockermon.sshstats', 'dockermon.endpoints', 'metrics.collect', 'core.ssh'])
def test_modules_import(module):
    __import__(module)
