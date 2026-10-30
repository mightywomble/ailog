"""Self-healing remediation: catalog, matcher, planner, runner, routes.

The trust boundary is simple: only a validated catalog entry can reach
ansible-runner. Model output (the idea channel) is stored on a card with
executable=False and is never executed.
"""

from remediation.routes import remediation_bp  # noqa: F401

__all__ = ['remediation_bp']