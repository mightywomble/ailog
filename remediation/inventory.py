"""Build an ansible inventory from Host rows.

Keys are materialised through the same module the rest of the app uses, so
remediation inherits the encrypted-at-rest handling and the shared host-key
policy instead of inventing its own SSH path.
"""

from __future__ import annotations

import logging

from core.hostkeys import ssh_cli_options

log = logging.getLogger(__name__)


def host_key(host) -> str:
    return f'db-{host.id}'


def _key_path(host) -> str | None:
    if not getattr(host, 'ssh_key_id', None):
        return None
    try:
        from monitoring.sshkeys import materialize_ssh_key_path
        return materialize_ssh_key_path(host.ssh_key_id)
    except Exception as exc:
        log.warning('could not materialise key for %s: %s', host_key(host), exc)
        return None


def host_vars(host, become: bool = True) -> dict:
    data = {
        'ansible_host': host.ip_address,
        'ansible_user': host.ssh_user or 'root',
        'ansible_ssh_common_args': ' '.join(ssh_cli_options()),
        'ansible_python_interpreter': 'auto_silent',
        'ansible_connect_timeout': 5,
    }
    key = _key_path(host)
    if key:
        data['ansible_ssh_private_key_file'] = key
    if become:
        data['ansible_become'] = True
        data['ansible_become_method'] = 'sudo'
        data['ansible_become_flags'] = '-n'
    return data


def build(hosts, become: bool = True) -> dict:
    """Return an ansible inventory dict keyed by db-<id>."""
    return {
        'all': {
            'hosts': {host_key(host): host_vars(host, become=become) for host in hosts},
            'vars': {'ansible_gathering': 'explicit' if False else 'smart'},
        }
    }