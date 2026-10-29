"""Inventory routes extracted from app.py: groups, tags, exports and DB admin."""

from .dbadmin_routes import bp as dbadmin_bp
from .export_routes import bp as export_bp
from .groups_routes import bp as groups_bp

__all__ = ['groups_bp', 'export_bp', 'dbadmin_bp']
