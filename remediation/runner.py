"""ansible-runner wrapper: one playbook, one wave, one artifact dir.

ansible-runner is imported lazily so the app (and the unit tests) run
without it; the Docker image installs it. When it is missing, apply
returns a clear error instead of an ImportError traceback.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import shutil
from pathlib import Path

from remediation import catalog

log = logging.getLogger(__name__)


def available() -> bool:
    return importlib.util.find_spec('ansible_runner') is not None


def ensure_project(run_dir: Path) -> Path:
    """Copy the playbooks and roles into the run dir ansible-runner expects."""
    project = run_dir / 'project'
    project.mkdir(parents=True, exist_ok=True)
    target = project / 'remediations'
    if not target.exists():
        shutil.copytree(catalog.CATALOG_DIR, target,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', 'molecule'))
    return project


class _Collector:
    def __init__(self, on_event=None):
        self.hosts = {}
        self.lines = []
        self.on_event = on_event

    def _host(self, name):
        return self.hosts.setdefault(name, {'ok': False, 'failed': False,
                                            'unreachable': False, 'changed': 0,
                                            'output': []})

    def __call__(self, event):
        kind = event.get('event') or ''
        data = event.get('event_data') or {}
        host = data.get('host')
        task = data.get('task')
        if host and kind.startswith('runner_on_'):
            entry = self._host(host)
            result = data.get('res') or {}
            if kind == 'runner_on_ok':
                entry['ok'] = True
                if result.get('changed'):
                    entry['changed'] += 1
                entry['output'].append(f"ok: [{host}] {task}")
            elif kind == 'runner_on_failed':
                entry['failed'] = True
                entry['ok'] = False
                entry['output'].append(f"FAILED: [{host}] {task}: {result.get('msg') or result.get('stderr') or ''}"[:800])
            elif kind == 'runner_on_unreachable':
                entry['unreachable'] = True
                entry['ok'] = False
                entry['output'].append(f"UNREACHABLE: [{host}] {result.get('msg') or ''}"[:400])
            elif kind == 'runner_on_skipped':
                entry['output'].append(f"skipped: [{host}] {task}")
            entry['output'] = entry['output'][-120:]
        if kind in ('playbook_on_start', 'playbook_on_stats'):
            self.lines.append(kind)
        if self.on_event:
            try:
                self.on_event({'type': 'task', 'event': kind, 'host': host, 'task': task,
                               'changed': bool((data.get('res') or {}).get('changed'))})
            except Exception:
                pass


def run_playbook(playbook: str, inventory: dict, limit, extravars: dict,
                 dry_run: bool, run_dir: Path, timeout: int = 300,
                 on_event=None) -> dict:
    """Run one playbook against one wave. Returns per-host results."""
    if not available():
        raise RuntimeError('ansible-runner is not installed in this image. '
                           'Set AILOG_ALLOW_REMEDIATION=off or rebuild with the Ansible extras.')
    import ansible_runner

    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    ensure_project(run_dir)

    collector = _Collector(on_event=on_event)
    envvars = {
        'ANSIBLE_HOST_KEY_CHECKING': 'False',
        'ANSIBLE_RETRY_FILES_ENABLED': 'False',
        'ANSIBLE_NOCOLOR': '1',
        'ANSIBLE_STDOUT_CALLBACK': 'default',
        'ANSIBLE_GATHERING': 'smart',
        'ANSIBLE_DEPRECATION_WARNINGS': 'False',
        # Playbooks live in remediations/playbooks/, roles in remediations/roles/,
        # so Ansible's default (playbook-relative roles/) does not find them.
        'ANSIBLE_ROLES_PATH': str((run_dir / 'project' / 'remediations' / 'roles').resolve()),
    }
    cmdline = '--check --diff' if dry_run else None

    result = ansible_runner.run(
        private_data_dir=str(run_dir),
        playbook=f'remediations/{playbook}',
        inventory=inventory,
        limit=','.join(limit) if limit else None,
        extravars=dict(extravars or {}),
        cmdline=cmdline,
        envvars=envvars,
        settings={'job_timeout': int(timeout), 'pexpect_timeout': 30, 'idle_timeout': int(timeout)},
        quiet=True,
        event_handler=collector,
    )

    try:
        rc = int(getattr(result, 'rc', 1))
    except (TypeError, ValueError):
        rc = 1

    hosts = {}
    for name, entry in collector.hosts.items():
        bad = bool(entry['failed'] or entry['unreachable'])
        # A host whose tasks were all skipped (already in the desired state)
        # emits no runner_on_ok, so a clean exit is what makes it healthy.
        hosts[name] = {
            'ok': (not bad) and (entry['ok'] or rc == 0),
            'changed': int(entry['changed']),
            'failed': bad,
            'output': '\n'.join(entry['output'])[-20000:],
        }

    stats_path = Path(str(getattr(result, 'artifact_dir', ''))) / 'stats' / 'playbook_stats.json' if getattr(result, 'artifact_dir', None) else None
    changed_total = sum(h['changed'] for h in hosts.values())
    return {
        'rc': rc,
        'status': getattr(result, 'status', 'unknown'),
        'hosts': hosts,
        'changed': changed_total,
        'artifact_dir': str(getattr(result, 'artifact_dir', run_dir) or run_dir),
        'stats': json.loads(stats_path.read_text()) if stats_path and stats_path.exists() else {},
    }