"""Independent verification probes.

The playbook that changed the host must not be the thing that grades the
result, so probes run over our own SSH transport (core.ssh), not through
ansible. Two probes with a settle window separate "it returned 0" from
"it is actually well".
"""

from __future__ import annotations

import logging
import re
import time

from core import ssh as ssh_core

log = logging.getLogger(__name__)


def host_dict(host) -> dict:
    return {
        'key': f'db-{host.id}',
        'user': host.ssh_user or 'root',
        'ip': host.ip_address,
        'ssh_key_id': host.ssh_key_id,
    }


def evaluate(expect: dict, rc: int, stdout: str, stderr: str) -> tuple[bool, str]:
    if 'exit_code' in expect:
        wanted = int(expect['exit_code'])
        if rc != wanted:
            return False, f'exit code {rc}, expected {wanted}'
    if 'stdout_matches' in expect:
        if not re.search(str(expect['stdout_matches']), stdout or '', re.MULTILINE):
            return False, f'stdout did not match {expect["stdout_matches"]!r}'
    if 'stdout_contains' in expect:
        if str(expect['stdout_contains']) not in (stdout or ''):
            return False, f'stdout did not contain {expect["stdout_contains"]!r}'
    if 'stdout_max' in expect or 'stdout_min' in expect:
        match = re.search(r'-?\d+', stdout or '')
        if not match:
            return False, 'stdout had no number to compare'
        value = int(match.group(0))
        if 'stdout_max' in expect and value > float(expect['stdout_max']):
            return False, f'{value} > {expect["stdout_max"]}'
        if 'stdout_min' in expect and value < float(expect['stdout_min']):
            return False, f'{value} < {expect["stdout_min"]}'
    return True, 'ok'


def run_probe(host, spec: dict, timeout: int = 20) -> dict:
    command = (spec or {}).get('command') or ''
    expect = (spec or {}).get('expect') or {}
    if not command:
        return {'ok': False, 'detail': 'no verify command', 'command': '', 'stdout': '', 'stderr': '', 'rc': None}
    ok, text = ssh_core.run_host(host_dict(host), command, timeout=timeout)
    stdout, stderr = (text, '') if ok else ('', text)
    passed, detail = evaluate(expect, 0 if ok else 1, stdout, stderr)
    return {'ok': passed, 'detail': detail, 'command': command,
            'stdout': stdout[-4000:], 'stderr': stderr[-2000:],
            'rc': 0 if ok else 1}


def settle(seconds: int, cap: int, cancelled=None) -> None:
    budget = min(max(0, int(seconds or 0)), max(0, int(cap)))
    for _ in range(budget):
        if cancelled and cancelled():
            return
        time.sleep(1)