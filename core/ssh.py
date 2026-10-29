"""One SSH transport for the whole application.

Before this module there were five near-identical remote-exec paths
(``app.get_ssh_prefix_args``, ``wizard_helpers.execute_remote_command``,
``dockermon.endpoints.ssh_run``, ``metrics.collect._run`` and
``dockermon.sshstats.run``), each with their own timeout, quoting and -- until
phase 1 -- their own host-key policy.  They now all funnel through here, so a
change to host-key handling or logging happens in exactly one place.

The API is deliberately tiny:

    run_remote(user, ip, command, ssh_key_path=None, timeout=10) -> (ok, text)
    run_host(host, command, timeout=...)        # host dict, supports 'local'
    ssh_argv(user, ip, identity_file=None)      # argv prefix, for callers
                                                # that need to append a script
    fanout(hosts, fn, max_workers=8)            # concurrent per-host calls

``ok`` means "exit status 0".  On failure the returned text is stderr (that is
what the log viewer and the docker probes already expect); on success it is
stdout.
"""

from __future__ import annotations

import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, Iterable

from core.hostkeys import ssh_cli_options

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10
CONNECT_TIMEOUT = 5


def ssh_argv(user: str, ip: str, identity_file: str | None = None) -> list[str]:
    """argv prefix ending with ``user@ip``; append the remote command after it."""
    argv = ['ssh', '-o', f'ConnectTimeout={CONNECT_TIMEOUT}']
    argv += ssh_cli_options()
    argv += ['-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes']
    if identity_file:
        argv += ['-i', identity_file]
    argv.append(f'{user}@{ip}')
    return argv


def run_remote(user: str, ip: str, command: str, ssh_key_path: str | None = None,
               timeout: int = DEFAULT_TIMEOUT) -> tuple[bool, str]:
    """Execute ``command`` on ``user@ip`` over SSH. Returns ``(ok, stdout|stderr)``."""
    argv = ssh_argv(user, ip, identity_file=ssh_key_path) + [command]
    return _run_argv(argv, timeout)


def run_host(host: Dict[str, Any], command: str, timeout: int = DEFAULT_TIMEOUT) -> tuple[bool, str]:
    """Execute on a host descriptor: ``{'key': 'local'}` or user/ip/ssh_key_id."""
    if not host or host.get('key') == 'local':
        return run_local(command, timeout=timeout)

    user = host.get('user') or 'root'
    ip = host.get('ip') or host.get('ip_address')
    key_path = None
    ssh_key_id = host.get('ssh_key_id')
    if ssh_key_id:
        try:
            from monitoring.sshkeys import materialize_ssh_key_path
            key_path = materialize_ssh_key_path(ssh_key_id)
        except Exception as exc:  # a missing key must not take the caller down
            logger.warning('ssh: could not materialize key %s: %s', ssh_key_id, exc)
    return run_remote(user, ip, command, ssh_key_path=key_path, timeout=timeout)


def run_local(command: str, timeout: int = DEFAULT_TIMEOUT) -> tuple[bool, str]:
    """Execute locally through bash (no sudo escalation of its own)."""
    try:
        proc = subprocess.run(['bash', '-lc', command], capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, 'Command timed out'
    except Exception as exc:
        return False, str(exc)
    return proc.returncode == 0, (proc.stdout or '') + (proc.stderr or '')


def _run_argv(argv: list[str], timeout: int) -> tuple[bool, str]:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning('ssh: timeout after %ss (%s)', timeout, argv[-2] if len(argv) > 1 else argv[-1])
        return False, 'Command timed out'
    except FileNotFoundError:
        return False, 'ssh binary not found'
    except Exception as exc:
        logger.warning('ssh: %s', exc)
        return False, str(exc)

    if result.returncode == 0:
        return True, result.stdout
    logger.debug('ssh: exit %s: %s', result.returncode, (result.stderr or '').strip()[:200])
    return False, result.stderr or result.stdout or ''


def fanout(hosts: Iterable[Dict[str, Any]], fn: Callable[[Dict[str, Any]], Any],
           max_workers: int = 8) -> Dict[str, Any]:
    """Call ``fn(host)`` for every host concurrently.

    ``fn`` must return a JSON-serialisable value; exceptions are captured as
    ``{'error': str(exc)}`` so one unreachable box cannot fail the fleet view.
    The dict is keyed by ``host['key']``.
    """
    hosts = list(hosts)
    results: Dict[str, Any] = {}
    if not hosts:
        return results
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(hosts)))) as pool:
        futures = {pool.submit(fn, host): host for host in hosts}
        for future in as_completed(futures):
            host = futures[future]
            key = host.get('key') or host.get('ip') or '?'
            try:
                results[key] = future.result()
            except Exception as exc:
                logger.warning('ssh: fanout failed for %s: %s', key, exc)
                results[key] = {'error': str(exc)}
    return results
