"""In-process wizard session registry used by the SSE endpoints.

Historically these three names lived in ``app.py`` and were then copied into
``inventory/dbadmin_routes.py``; the copies in app.py were deleted when the
inventory package was extracted, leaving ``/wizard/session/*`` with undefined
names. One module now owns them.
"""

from __future__ import annotations

import datetime
import threading
import uuid

wizard_sessions: dict[str, dict] = {}
sessions_lock = threading.Lock()


def create_session() -> str:
    session_id = str(uuid.uuid4())
    with sessions_lock:
        wizard_sessions[session_id] = {
            'created_at': datetime.datetime.now(datetime.UTC),
            'status': 'active',
        }
    return session_id


def get_session(session_id: str):
    with sessions_lock:
        return wizard_sessions.get(session_id)


def drop_session(session_id: str) -> None:
    with sessions_lock:
        wizard_sessions.pop(session_id, None)
