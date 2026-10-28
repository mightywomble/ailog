"""Server-wide correlated log reporting (bolt-on blueprint)."""
from .routes import reports_bp  # noqa: F401

__all__ = ["reports_bp"]
