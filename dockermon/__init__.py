"""Docker monitoring subsystem for ailog.

Discovers Docker Engine endpoints on configured hosts (SSH/unix-socket and
plain or TLS TCP) and serves live container/node statistics.

Bolt-on blueprint, mirroring the ``monitoring/`` package layout.
"""
from .routes import docker_bp  # noqa: F401

__all__ = ["docker_bp"]
