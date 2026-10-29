"""Time helpers.

``datetime.utcnow()`` is deprecated (and emits a DeprecationWarning on every
call - 468 of them in a test run). These helpers keep the naive-UTC values the
database columns already store, without the deprecated call.
"""

from __future__ import annotations

import datetime as _dt


def utcnow() -> _dt.datetime:
    """Naive UTC 'now', equivalent to the old ``datetime.utcnow()``."""
    return _dt.datetime.now(_dt.UTC).replace(tzinfo=None)


def utcnow_iso() -> str:
    return utcnow().isoformat()
