"""Reading a credential from a Docker secret, falling back to the environment.

A value in a stack file is a value in git and a value in ``docker service
inspect``. Swarm mounts secrets at ``/run/secrets/<name>``, which is where these
belong - so the stack file can name a secret instead of carrying the value.

The environment stays as the last resort on purpose: the test suite, a container
started by hand, and ``AILOG_*`` settings that were never secrets at all keep
working, and a missing file is never fatal.
"""

from __future__ import annotations

import os

# Swarm mounts secrets here. Overridable so a test (or a chart that mounts
# elsewhere) does not need to write to /run.
SECRETS_DIR = os.environ.get('AILOG_SECRETS_DIR', '/run/secrets')


def secret(name: str, env: str = '') -> str:
    """``<SECRETS_DIR>/<name>`` if it exists and has content, else ``$env``."""
    try:
        with open(os.path.join(SECRETS_DIR, name), encoding='utf-8') as handle:
            text = handle.read().strip()
        if text:
            return text
    except OSError:
        pass
    return (os.environ.get(env or name.upper()) or '').strip()


def configured(name: str, env: str = '') -> bool:
    """Whether :func:`secret` would return anything."""
    return bool(secret(name, env))
