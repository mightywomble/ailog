"""In-process progress registry for remediation runs (SSE).

Same shape as the report stream: a queue fed by the worker thread and
drained by a streaming response. Runs are bounded (the registry is pruned
after 2 hours) and never hold more than the last 400 events.
"""

from __future__ import annotations

import datetime
import queue
import threading

MAX_EVENTS = 400
TTL_SECONDS = 7200

_lock = threading.Lock()
_runs: dict[str, dict] = {}


def start(run_uuid: str) -> None:
    with _lock:
        _prune()
        _runs[run_uuid] = {'queue': queue.Queue(), 'events': [], 'done': False,
                           'state': 'queued', 'cancelled': False,
                           'started': datetime.datetime.now(datetime.timezone.utc)}


def emit(run_uuid: str, payload: dict) -> None:
    with _lock:
        entry = _runs.get(run_uuid)
        if not entry:
            return
        entry['events'].append(payload)
        if len(entry['events']) > MAX_EVENTS:
            entry['events'] = entry['events'][-MAX_EVENTS:]
        q = entry['queue']
    q.put(payload)


def finish(run_uuid: str, state: str) -> None:
    with _lock:
        entry = _runs.get(run_uuid)
        if not entry:
            return
        entry['done'] = True
        entry['state'] = state
        entry['finished'] = datetime.datetime.now(datetime.timezone.utc)
        payload = {'type': 'done', 'state': state}
        # Keep 'done' in the replay buffer too, so a subscriber that arrives
        # after the run finished is replayed the whole run *and* the terminator.
        entry['events'].append(payload)
        if len(entry['events']) > MAX_EVENTS:
            entry['events'] = entry['events'][-MAX_EVENTS:]
        q = entry['queue']
    q.put(payload)


def cancel(run_uuid: str) -> bool:
    with _lock:
        entry = _runs.get(run_uuid)
        if not entry or entry['done']:
            return False
        entry['cancelled'] = True
    emit(run_uuid, {'type': 'log', 'message': 'Cancellation requested...'})
    return True


def cancelled(run_uuid: str) -> bool:
    with _lock:
        entry = _runs.get(run_uuid)
        return bool(entry and entry['cancelled'])


def snapshot(run_uuid: str) -> list[dict]:
    with _lock:
        entry = _runs.get(run_uuid)
        return list(entry['events']) if entry else []


def is_done(run_uuid: str) -> bool:
    with _lock:
        entry = _runs.get(run_uuid)
        return bool(entry and entry['done'])


def stream(run_uuid: str):
    """Yield events for an SSE response; replays what already happened."""
    with _lock:
        entry = _runs.get(run_uuid)
        if not entry:
            return
        pending = list(entry['events'])
        q = entry['queue']
    for event in pending:
        yield event
        if event.get('type') == 'done':
            return
    # Everything emitted so far is in 'pending' *and* in the queue; drain the
    # queue before switching to live, or the client sees each event twice.
    while True:
        try:
            q.get_nowait()
        except queue.Empty:
            break
    while True:
        try:
            event = q.get(timeout=10)
        except queue.Empty:
            yield {'type': 'ping'}
            continue
        yield event
        if event.get('type') == 'done':
            return


def _prune() -> None:
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=TTL_SECONDS)
    for key, entry in list(_runs.items()):
        if entry.get('started') and entry['started'] < cutoff:
            _runs.pop(key, None)