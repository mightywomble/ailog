"""Netdata integration: read-only fleet metrics, alerts and report evidence."""

from .routes import netdata_bp

__all__ = ['netdata_bp']
