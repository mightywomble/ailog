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

import yaml

from . import render, settings, tags
from .git import GitError, Repo

logger = logging.getLogger(__name__)

TTL = 15 * 60

_lock = threading.Lock()
_state: Dict[str, Any] = {
    'ts': 0.0,          # when the sweep last finished
    'services': [],     # every mirror/image service: pin, deployed tag, newest
    'checked': 0,       # services the sweep could resolve a version for
    'error': '',
    'running': False,
}


def state() -> Dict[str, Any]:
    with _lock:
        row = dict(_state)
    row['services'] = [dict(r) for r in row.get('services') or []]
    row['rows'] = [r for r in row['services'] if r.get('behind')]
    row['age'] = round(time.time() - float(row.get('ts') or 0), 1) if row.get('ts') else None
    return row


def stale(max_age: float = TTL) -> bool:
    with _lock:
        if _state['running']:
            return False
        return (time.time() - float(_state['ts'] or 0)) > max_age


def clear() -> None:
    with _lock:
        _state.update(ts=0.0, services=[], checked=0, error='', running=False)


def oldest(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Behind first, then by name: the card is a to-do list, not an index."""
    return sorted(rows, key=lambda r: (r.get('name') or '').lower())


def _image_repo(entry: dict) -> str:
    """``zot.safehomelan.com/anchor:0.9.1`` -> ``anchor``."""
    ref = str(render.image_ref(entry, settings.registry()) or '')
    ref = ref.split('@', 1)[0].rsplit('/', 1)[-1]
    return ref.split(':', 1)[0]


def _deployed_tag(stack_text: str, service: str) -> str:
    """The tag CI would deploy for this service, read from its stack file."""
    try:
        doc = yaml.safe_load(stack_text) or {}
    except yaml.YAMLError:
        return ''
    image = str(((doc.get('services') or {}).get(service) or {}).get('image') or '')
    ref = image.split('@', 1)[0]
    tail = ref.rsplit('/', 1)[-1]
    return tail.rsplit(':', 1)[-1] if ':' in tail else ('latest' if tail else '')


def sweep(app=None) -> List[Dict[str, Any]]:
    """What every service pins, deploys, runs towards and could move to.

    Blocking: background only (one registry round per service). Every service is
    reported, not just the ones that are behind, because the card has a second
    question to ask of each of them: does the host run what the stack file says?
    A service half-moved - anchor on `:latest` while the stack still pins 0.9.1 -
    is invisible in any list filtered down to "behind upstream", and it is the
    one a redeploy would quietly roll backwards.
    """
    repo = Repo()
    if not repo.exists():
        with _lock:
            _state.update(services=[], checked=0, ts=time.time(),
                          error='no estate checkout yet (the first update clones it)')
        return []
    try:
        repo.fresh()
        doc = render.load_intent(repo.read('wizard.yaml'))
    except (OSError, GitError) as exc:
        with _lock:
            _state.update(services=[], error=str(exc), ts=time.time())
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
        service = render.service_of(entry)
        try:
            deployed = _deployed_tag(repo.read(f'stacks/{name}/stack.yml'), service)
        except OSError:
            deployed = ''
        row = {
            'name': name,
            'kind': kind,
            'service': service,
            'current': str(entry.get('version') or ''),
            'deployed': deployed,
            'target': '',
            'behind': False,
            'image': render.image_ref(entry, settings.registry()),
            'repo': _image_repo(entry),
            'source': entry.get('source') or '',
        }
        try:
            newest = tags.newest_tag(entry['source'])
        except Exception as exc:              # noqa: BLE001 - one bad source must not blank the card
            problems.append(f'{name}: {exc}')
            rows.append(row)
            continue
        checked += 1
        if not newest.get('up_to_date') and newest.get('best'):
            row['target'] = str(newest['best'])
            row['behind'] = True
        rows.append(row)

    with _lock:
        _state.update(services=oldest(rows), checked=checked, ts=time.time(),
                      error='; '.join(problems[:3]))
    return rows


def refresh_async(app, force: bool = False) -> bool:
    """Start a sweep if the cache is stale. Returns True when one was started.

    ``force`` is what a person pressing "check now" means: they are asking
    precisely because the cached answer is the one they doubt.
    """
    with _lock:
        if _state['running']:
            return False
        if not force and (time.time() - float(_state['ts'] or 0)) <= TTL:
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
