"""Which estate services are behind their upstream *version*.

The per-host scan answers "has this tag moved?" and it is the right question
for a compose project that runs ``image:latest``.  It cannot answer the other
one: anchor sits on ``:0.9.1`` while ``:0.17.2`` exists upstream, and no digest
on the host will ever say so, because ``:0.9.1`` never moves.  That comparison
- wizard.yaml's pin against the newest tag its source publishes - is what this
module keeps, and it is why a container eight versions behind can be invisible
in a list of digest differences.

A registry round per service costs seconds, so this is never done inline: the
sweep runs in a background thread and the answer is cached for a quarter of an
hour.  A stale cache still answers (with its age), because "these were the
newest tags ten minutes ago" is more useful than an empty card.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List

from . import render, settings, tags
from .git import GitError, Repo

logger = logging.getLogger(__name__)

TTL = 15 * 60

_lock = threading.Lock()
_state: Dict[str, Any] = {
    'ts': 0.0,          # when the sweep last finished
    'rows': [],         # services whose pin is behind their upstream
    'checked': 0,       # services the sweep could resolve a version for
    'error': '',
    'running': False,
}


def state() -> Dict[str, Any]:
    with _lock:
        row = dict(_state)
    row['rows'] = [dict(r) for r in row.get('rows') or []]
    row['age'] = round(time.time() - float(row.get('ts') or 0), 1) if row.get('ts') else None
    return row


def stale(max_age: float = TTL) -> bool:
    with _lock:
        if _state['running']:
            return False
        return (time.time() - float(_state['ts'] or 0)) > max_age


def clear() -> None:
    with _lock:
        _state.update(ts=0.0, rows=[], checked=0, error='', running=False)


def oldest(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Behind first, then by name: the card is a to-do list, not an index."""
    return sorted(rows, key=lambda r: (r.get('name') or '').lower())


def _image_repo(entry: dict) -> str:
    """``zot.safehomelan.com/anchor:0.9.1`` -> ``anchor``."""
    ref = str(render.image_ref(entry, settings.registry()) or '')
    ref = ref.split('@', 1)[0].rsplit('/', 1)[-1]
    return ref.split(':', 1)[0]


def sweep(app=None) -> List[Dict[str, Any]]:
    """Ask every service's source for its newest tag. Blocking: background only."""
    repo = Repo()
    if not repo.exists():
        with _lock:
            _state.update(rows=[], checked=0, ts=time.time(),
                          error='no estate checkout yet (the first update clones it)')
        return []
    try:
        repo.fresh()
        doc = render.load_intent(repo.read('wizard.yaml'))
    except (OSError, GitError) as exc:
        with _lock:
            _state.update(rows=[], error=str(exc), ts=time.time())
        return []

    rows: List[Dict[str, Any]] = []
    checked = 0
    problems: List[str] = []
    for entry in doc.get('services') or []:
        name = str(entry.get('name') or '')
        kind = entry.get('kind') or ''
        # A build app has no version to resolve; its tag is a CI run number and
        # the estate page offers a rebuild instead.
        if not name or kind == 'build' or not entry.get('source'):
            continue
        current = str(entry.get('version') or '')
        try:
            newest = tags.newest_tag(entry['source'])
        except Exception as exc:              # noqa: BLE001 - one bad source must not blank the card
            problems.append(f'{name}: {exc}')
            continue
        checked += 1
        if newest.get('up_to_date') or not newest.get('best'):
            continue
        rows.append({
            'name': name,
            'kind': kind,
            'service': render.service_of(entry),
            'current': current,
            'target': str(newest['best']),
            'image': render.image_ref(entry, settings.registry()),
            'repo': _image_repo(entry),
            'source': entry.get('source') or '',
        })

    with _lock:
        _state.update(rows=oldest(rows), checked=checked, ts=time.time(),
                      error='; '.join(problems[:3]))
    return rows


def refresh_async(app) -> bool:
    """Start a sweep if the cache is stale. Returns True when one was started."""
    with _lock:
        if _state['running']:
            return False
        if (time.time() - float(_state['ts'] or 0)) <= TTL:
            return False
        _state['running'] = True

    def run():
        try:
            with app.app_context():
                sweep(app)
        except Exception as exc:              # noqa: BLE001 - a sweep must never kill the app
            logger.warning('estate drift sweep failed: %s', exc)
            with _lock:
                _state.update(error=str(exc), ts=time.time())
        finally:
            with _lock:
                _state['running'] = False

    threading.Thread(target=run, name='estate-drift', daemon=True).start()
    return True
