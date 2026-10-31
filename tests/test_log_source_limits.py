"""Log-source discovery must stay bounded.

The matrix server reported 46,592 "sources": 46,533 of them were transient
``.scope`` systemd units (one per container/systemd-run invocation). Streaming
that many ``source`` events is what locked the browser up mid-pull, and
``docker ps --size`` made the daemon measure every writable layer first.
"""

from __future__ import annotations

import json
import re

import app as app_module


class _Res:
    def __init__(self, stdout='', returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def _events(gen):
    out = []
    for chunk in gen:
        line = chunk.strip()
        if line.startswith('data: '):
            out.append(json.loads(line[6:]))
    return out


# ------------------------------------------------------------------- journal

def test_transient_scopes_are_not_log_sources(monkeypatch):
    seen = {}

    def fake_exec(hostname, command, timeout=20):
        if 'journalctl' in command:
            seen['cmd'] = command
            return _Res('sshd.service\nnginx.service\n')
        return _Res('')

    monkeypatch.setattr(app_module, 'execute_command', fake_exec)
    events = _events(app_module.get_log_sources_from_host_stream('db-1'))
    cmd = seen['cmd']
    # transient units left behind by every container run are excluded on the host
    assert "grep -v '\\.scope$'" in cmd
    assert 'sort -u' in cmd
    assert f'head -n {app_module.JOURNAL_UNIT_LIMIT}' in cmd
    units = [e['data']['name'] for e in events if e.get('status') == 'source']
    assert units == ['sshd.service', 'nginx.service']


def test_a_pathological_unit_list_is_capped_and_says_so(monkeypatch):
    many = '\n'.join(f'unit{i}.service' for i in range(app_module.JOURNAL_UNIT_LIMIT + 500))

    def fake_exec(hostname, command, timeout=20):
        if 'journalctl' in command:
            return _Res(many)
        return _Res('')

    monkeypatch.setattr(app_module, 'execute_command', fake_exec)
    events = _events(app_module.get_log_sources_from_host_stream('db-1'))
    units = [e for e in events if e.get('status') == 'source']
    assert len(units) <= app_module.JOURNAL_UNIT_LIMIT
    messages = [e.get('message', '') for e in events if e.get('status') == 'progress']
    assert any('first' in m and 'journal units' in m for m in messages), messages


# -------------------------------------------------------------------- docker

def test_the_container_listing_does_not_measure_every_layer():
    """``--size`` runs a `du` per container; on a busy host that stalls the pull."""
    import inspect
    src = inspect.getsource(app_module._docker_log_sources)
    assert '--size' not in src.split('command = (')[1].split(')')[0]
    assert 'ps -a --no-trunc' in src


def test_docker_sources_are_capped(monkeypatch):
    rows = '\n'.join(
        f'{"a" * 64}\tcontainer{i}\tnginx:latest\trunning\tUp 2 hours\t0B'
        for i in range(app_module.DOCKER_SOURCE_LIMIT + 50)
    )
    monkeypatch.setattr(app_module, 'execute_command', lambda *a, **k: _Res(rows))
    sources = app_module._docker_log_sources('db-1')
    assert len(sources) == app_module.DOCKER_SOURCE_LIMIT
    assert sources[0]['type'] == 'docker'
    assert sources[0]['name'] == 'container0'


def test_a_host_without_docker_is_simply_empty(monkeypatch):
    monkeypatch.setattr(app_module, 'execute_command', lambda *a, **k: _Res(''))
    assert app_module._docker_log_sources('db-1') == []


# --------------------------------------------------------------------- files

def test_the_file_listing_is_capped_before_it_is_stat_ed(monkeypatch):
    names = '\n'.join(f'f{i}.log' for i in range(app_module.FILE_SOURCE_LIMIT + 200))
    calls = {'stat': 0}

    def fake_exec(hostname, command, timeout=20):
        if command.startswith('sudo ls'):
            return _Res(names)
        if 'stat -c' in command:
            calls['stat'] += 1
            return _Res('10 1700000000')
        return _Res('')

    monkeypatch.setattr(app_module, 'execute_command', fake_exec)
    events = _events(app_module.get_log_sources_from_host_stream('db-1'))
    assert calls['stat'] == app_module.FILE_SOURCE_LIMIT
    files = [e for e in events if e.get('status') == 'source' and e['data']['type'] == 'file']
    assert len(files) == app_module.FILE_SOURCE_LIMIT


def test_the_limits_are_configurable():
    assert re.match(r'^\d+$', str(app_module.JOURNAL_UNIT_LIMIT))
    assert app_module.JOURNAL_UNIT_LIMIT <= 1000
    assert app_module.DOCKER_SOURCE_LIMIT <= 1000
    assert app_module.FILE_SOURCE_LIMIT <= 5000
