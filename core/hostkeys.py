"""SSH host-key verification policy.

Previously every SSH path in the codebase passed ``StrictHostKeyChecking=no``
(and paramiko used ``AutoAddPolicy``), which makes the whole app trivially
MITM-able.  The policy is now explicit and centralised so phase 2 can swap the
five remote-exec paths over without changing behaviour twice.

    AILOG_SSH_HOST_KEY_POLICY   accept-new | strict | off   (default: accept-new)
    AILOG_KNOWN_HOSTS           path to the known_hosts file to use/add to

``accept-new`` pins the key on first contact and refuses later changes, which
is what you want for a homelab box that talks to machines it has never seen.
``strict`` requires the key to be present already.  ``off`` is the old
behaviour and is only kept as an escape hatch for throwaway test rigs.
"""

from __future__ import annotations

import os
from pathlib import Path

POLICIES = ('accept-new', 'strict', 'off')

_DEFAULT_KNOWN_HOSTS = '/data/known_hosts'


def policy() -> str:
    raw = (os.getenv('AILOG_SSH_HOST_KEY_POLICY') or 'accept-new').strip().lower()
    if raw in ('yes', 'on', 'auto', 'autoadd'):
        return 'accept-new'
    if raw not in POLICIES:
        return 'accept-new'
    return raw


def known_hosts_path() -> str:
    """Path used for both reading and writing host keys."""
    explicit = (os.getenv('AILOG_KNOWN_HOSTS') or '').strip()
    if explicit:
        return explicit
    try:
        Path('/data').mkdir(parents=True, exist_ok=True)
        probe = Path(_DEFAULT_KNOWN_HOSTS)
        # Only use /data when this process can actually write there.
        with open(probe, 'a'):
            pass
        return str(probe)
    except OSError:
        fallback = Path.home() / '.ssh' / 'known_hosts'
        fallback.parent.mkdir(parents=True, exist_ok=True)
        fallback.touch(exist_ok=True)
        return str(fallback)


def ssh_cli_options() -> list[str]:
    """``-o`` options for the openssh CLI, in the order they should be passed."""
    mode = policy()
    if mode == 'off':
        return ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null']
    value = 'accept-new' if mode == 'accept-new' else 'yes'
    return ['-o', f'StrictHostKeyChecking={value}', '-o', f'UserKnownHostsFile={known_hosts_path()}']


def paramiko_policy():
    """MissingHostKeyPolicy matching :func:`policy`."""
    import paramiko

    mode = policy()
    if mode == 'strict':
        return paramiko.RejectPolicy()
    # accept-new and off both auto-add; 'off' just skips the known_hosts file
    return paramiko.AutoAddPolicy()


def load_known_hosts(client) -> None:
    """Load pinned keys into a paramiko client (best effort)."""
    if policy() == 'off':
        return
    path = known_hosts_path()
    try:
        if os.path.exists(path):
            client.load_host_keys(path)
    except Exception:
        pass


def save_known_hosts(client) -> None:
    """Persist newly accepted host keys (best effort)."""
    if policy() != 'accept-new':
        return
    try:
        client.save_host_keys(known_hosts_path())
    except Exception:
        pass


def ssh_config_block(indent: str = '    ') -> str:
    """The equivalent block for an exported ~/.ssh/config Host section."""
    if policy() == 'off':
        return f'{indent}StrictHostKeyChecking no{indent}UserKnownHostsFile /dev/null\n'
    value = 'accept-new' if policy() == 'accept-new' else 'yes'
    return f'{indent}StrictHostKeyChecking {value}\n'
