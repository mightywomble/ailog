"""Time-windowed log collection for the server-wide report.

The log viewer's ``tail -n 500`` is fine for reading one file, but it is useless
for correlation: 500 lines of syslog may span three hours while 500 lines of a
busy nginx access log span ninety seconds. Everything here is therefore bounded
by **wall-clock window** first and by line count second, so every source
contributes the same slice of time.

Hosts are only ever accessed through ``app.execute_command`` (SSH for remote
hosts, ``shell=True`` for ``local``) so the report reuses the same sudoers and
transport assumptions as the rest of the app.
"""
import datetime
import os
import shlex
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import severity

# --- limits -----------------------------------------------------------------
DEFAULT_WINDOW_MINUTES = 120
ALLOWED_WINDOWS = (15, 30, 60, 120, 360, 1440)

# The cap is a fairness knob, not a "first 60 things we saw" knob: see
# ``select_sources``. 120 keeps a busy host's journal and containers in the
# report instead of letting 60 log files consume the whole budget.
MAX_SOURCES = int(os.environ.get('AILOG_REPORT_MAX_SOURCES', '120') or 120)

# Share of the cap each kind may claim before overflow. Without this, a host
# with many log files (db-11: 200+) spent the whole budget on files and never
# collected a single journal unit or container.
KIND_SHARES = {'file': 0.45, 'journal': 0.30, 'docker': 0.25}
MAX_BYTES = int(os.environ.get('AILOG_REPORT_MAX_BYTES', str(24 * 1024 * 1024)) or 24 * 1024 * 1024)
MAX_JOURNAL_UNITS = 60

# Units that can never carry a useful report and only ever produce noise. The
# report's own `sudo journalctl -u emergency.service` command is logged by sudo
# into auth.log, and the word "emergency" then classifies as CRIT — the filter
# would be reporting on itself.
JOURNAL_UNIT_DENY = frozenset({'emergency.service', 'rescue.service'})
FILE_LINE_CAP = 4000
JOURNAL_LINE_CAP = 5000
DOCKER_LINE_CAP = 5000
COLLECT_WORKERS = 6
SOURCE_TIMEOUT = 45

# Severity filtering runs at the source, so a filtered run can afford to scan a
# much wider tail: the bytes that survive the grep are only the matches. Without
# this, selecting "errors only" on a quiet log would return the last 4000 lines
# *of which* maybe none are errors, instead of the last 4000 errors.
FILE_SCAN_CAP = int(os.environ.get('AILOG_REPORT_FILE_SCAN_CAP', '12000') or 12000)
JOURNAL_SCAN_CAP = int(os.environ.get('AILOG_REPORT_JOURNAL_SCAN_CAP', '20000') or 20000)
DOCKER_SCAN_CAP = int(os.environ.get('AILOG_REPORT_DOCKER_SCAN_CAP', '20000') or 20000)

# Lines of trailing context kept after a severity match: the line *after* a
# Python traceback header or a systemd "failed" line is where the cause lives.
SEVERITY_CONTEXT_LINES = int(os.environ.get('AILOG_REPORT_SEVERITY_CONTEXT', '3') or 3)

# One report run per host at a time: a double click must not stack 50 SSH
# sessions across the same box.
_run_locks = {}
_run_locks_guard = threading.Lock()


def _app():
    """Import the Flask app module lazily (avoids an import cycle)."""
    import app as app_module
    return app_module


def host_lock(host_key):
    with _run_locks_guard:
        lock = _run_locks.get(host_key)
        if lock is None:
            lock = threading.Lock()
            _run_locks[host_key] = lock
        return lock


def clamp_window(minutes):
    try:
        minutes = int(minutes)
    except (TypeError, ValueError):
        return DEFAULT_WINDOW_MINUTES
    if minutes <= 0:
        return DEFAULT_WINDOW_MINUTES
    return max(1, min(minutes, 1440))


def window_bounds(minutes, now=None):
    """Return (start, end) as timezone-aware UTC datetimes."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return now - datetime.timedelta(minutes=minutes), now


def _rfc3339(dt):
    return dt.astimezone(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# ---------------------------------------------------------------------------
# source discovery
# ---------------------------------------------------------------------------

def _discover_files(host_key):
    """List /var/log files with size + mtime in a single round trip.

    ``find -printf`` replaces a per-file ``stat`` loop, which used to mean one
    SSH command per log file.
    """
    app = _app()
    directory = app.LOG_DIRECTORY
    cmd = (
        f"sudo find {shlex.quote(directory)} -maxdepth 1 -type f "
        "-printf '%f\\t%s\\t%T@\\n' 2>/dev/null"
    )
    try:
        res = app.execute_command(host_key, cmd, timeout=20)
    except Exception as exc:
        print(f'[report] file discovery failed on {host_key}: {exc}')
        return [], str(exc)

    entries = []
    for line in (res.stdout or '').splitlines():
        parts = line.split('\t')
        if len(parts) != 3:
            continue
        name, size, mtime = parts
        try:
            entries.append({'name': name, 'size': int(float(size)), 'mtime': float(mtime)})
        except ValueError:
            continue
    return entries, None


def _usable_units(stdout):
    """Parse a unit listing and drop units that cannot inform a report."""
    units = []
    for raw in (stdout or '').splitlines():
        unit = raw.strip()
        if not unit or unit in JOURNAL_UNIT_DENY:
            continue
        units.append(unit)
    return units[:MAX_JOURNAL_UNITS]


def _discover_journal_units(host_key):
    """List systemd units, cheaply.

    ``journalctl --field _SYSTEMD_UNIT`` scans the entire journal before ``head``
    can stop it (db-11 alone takes >15s), so systemd's own unit list is used
    first and the journal scan is only a fallback with a longer timeout.
    """
    app = _app()

    systemctl_cmd = (
        'sudo systemctl list-units --type=service --all --no-pager --no-legend --plain '
        f"2>/dev/null | awk '{{print $1}}' | grep -E '\\.service$' | sort -u "
        f'| head -n {MAX_JOURNAL_UNITS}'
    )
    try:
        res = app.execute_command(host_key, systemctl_cmd, timeout=15)
        units = _usable_units(res.stdout)
        if units:
            return units, None
    except Exception as exc:
        print(f'[report] systemctl unit listing failed on {host_key}: {exc}')

    # Fallback: ask journald directly, with a longer timeout for busy hosts.
    field_cmd = (
        f'sudo journalctl --field _SYSTEMD_UNIT 2>/dev/null '
        f'| sort -u | head -n {MAX_JOURNAL_UNITS}'
    )
    try:
        res = app.execute_command(host_key, field_cmd, timeout=40)
    except Exception as exc:
        print(f'[report] journal discovery failed on {host_key}: {exc}')
        return [], str(exc)

    return _usable_units(res.stdout), None


def _discover_docker(host_key):
    app = _app()
    try:
        return app._docker_log_sources(host_key), None
    except Exception as exc:
        print(f'[report] docker discovery failed on {host_key}: {exc}')
        return [], str(exc)


def list_sources(host_key, include_files=True, include_journal=True, include_docker=True,
                 include_stopped=False, window_start=None, progress=None):
    """Enumerate candidate sources for a host.

    Returns ``(sources, errors)`` where each source is a dict with a stable
    ``key`` used for de-duplication and report references.
    """
    sources = []
    errors = []

    def note(msg):
        if progress:
            try:
                progress(msg)
            except Exception:
                pass

    if include_files:
        note('Listing log files...')
        entries, err = _discover_files(host_key)
        if err:
            errors.append({'kind': 'file', 'error': err})
        skipped = 0
        for entry in sorted(entries, key=lambda e: e['mtime'], reverse=True):
            # A file not written during the window cannot contribute events.
            if window_start is not None and entry['mtime'] < window_start.timestamp():
                skipped += 1
                continue
            if entry['size'] <= 0:
                skipped += 1
                continue
            sources.append({
                'key': f"file:{entry['name']}",
                'kind': 'file',
                'name': entry['name'],
                'label': entry['name'],
                'path': os.path.join(_app().LOG_DIRECTORY, entry['name']),
                'size_bytes': entry['size'],
                'mtime': entry['mtime'],
            })
        if skipped:
            note(f'Skipped {skipped} log file(s) not written in the window')

    if include_journal:
        note('Listing journald units...')
        units, err = _discover_journal_units(host_key)
        if err:
            errors.append({'kind': 'journal', 'error': err})
        # Most active units first: a chatty unit is where the events are. One
        # extra command ranks them; alphabetical order is otherwise arbitrary.
        activity = _journal_activity(host_key, window_start)
        units = sorted(units, key=lambda u: (-activity.get(u, 0), u))
        for unit in units:
            sources.append({
                'key': f'journal:{unit}',
                'kind': 'journal',
                'name': unit,
                'label': f'journal:{unit}',
                'unit': unit,
                'size_bytes': 0,
                'mtime': 0,
                'activity': activity.get(unit, 0),
            })

    if include_docker:
        note('Looking for Docker containers...')
        containers, err = _discover_docker(host_key)
        if err:
            errors.append({'kind': 'docker', 'error': err})
        for c in containers:
            state = (c.get('state') or '').lower()
            if state != 'running' and not include_stopped:
                continue
            sources.append({
                'key': f"docker:{c.get('name')}",
                'kind': 'docker',
                'name': c.get('name'),
                'label': f"docker:{c.get('name')}",
                'container_id': c.get('container_id'),
                'image': c.get('image'),
                'state': state or 'unknown',
                'status': c.get('status') or '',
                'size_bytes': c.get('size_bytes') or 0,
                'mtime': 0,
            })

    return sources, errors


# ---------------------------------------------------------------------------
# per-source fetch
# ---------------------------------------------------------------------------

def _prefilter_for(levels):
    """What the source-side filter actually did, for the report coverage."""
    levels = frozenset(levels or ())
    if not levels:
        return {}
    priority, exact = severity.journal_priority(levels)
    return {
        'journal': 'journalctl --priority=' + str(priority) + ('' if exact else ' + grep'),
        'file': f'grep -iE + tail -n {FILE_SCAN_CAP}',
        'docker': 'grep -iE (container logs have no severity metadata)',
    }


def _grep_filter(levels):
    """The shared ``| grep`` tail that keeps only the selected severities.

    ``-a`` because /var/log files can contain a stray NUL and grep would
    otherwise call the whole file binary and print nothing. Context lines
    (``-A``) keep the body of a traceback or a multi-line failure, and the final
    ``tail`` keeps the *newest* matches when there are more than the cap.
    """
    pattern = severity.grep_pattern(levels)
    if not pattern:
        return ''
    # --no-group-separator: grep's own "--" lines between context groups would
    # otherwise reach the normaliser as timestamp-less junk events.
    # -i is not optional: classify_severity matches case-insensitively, so a
    # case-sensitive grep here would silently drop "ERROR:"/"Failed" lines that
    # the authoritative filter would have kept.
    return (f" | grep -aiE -A {SEVERITY_CONTEXT_LINES} --no-group-separator "
            f"{shlex.quote(pattern)} | tail -n {{cap}}")


def build_command(source, window_start, window_end, sev_levels=None):
    """Build the shell command that fetches one source inside the window.

    ``sev_levels`` is a frozenset from ``severity.parse`` (empty = no filter).
    Filtering happens here, on the host, so filtered-out lines never cross the
    SSH channel — that is the whole point of the feature. ``normalize`` applies
    the same filter again authoritatively, because a grep over raw text is a
    heuristic and the classifier is not.
    """
    since = _rfc3339(window_start)
    kind = source['kind']
    levels = frozenset(sev_levels or ())
    filtering = bool(levels)

    if kind == 'file':
        path = shlex.quote(source['path'])
        cap = FILE_LINE_CAP
        scan = FILE_SCAN_CAP if filtering else FILE_LINE_CAP
        if str(source['name']).endswith('.gz'):
            head = f'sudo zcat {path} 2>/dev/null | tail -n {scan}'
        else:
            head = f'sudo tail -n {scan} {path} 2>/dev/null'
        if not filtering:
            return head
        return head + _grep_filter(levels).format(cap=cap)

    if kind == 'journal':
        unit = shlex.quote(source['unit'])
        cap = JOURNAL_LINE_CAP
        scan = JOURNAL_SCAN_CAP if filtering else JOURNAL_LINE_CAP
        priority, exact = severity.journal_priority(levels)
        priority_arg = f' --priority={priority}' if filtering and priority is not None else ''
        base = (
            f'sudo journalctl -u {unit} --since {shlex.quote(since)} '
            f'-n {scan} --no-pager -o short-iso{priority_arg} 2>/dev/null'
        )
        if not filtering:
            return base
        # --priority=N is native and free: the journal does the filtering on the
        # host, so no filtered line ever reaches the pipe. It is only exact when
        # the selection is "N and above", so the inexact cases get a grep too.
        if exact:
            return base
        return base + _grep_filter(levels).format(cap=cap)

    if kind == 'docker':
        container = shlex.quote(source['name'])
        label = '\'{{index .Config.Labels "com.docker.swarm.service.name"}}\''
        cap = DOCKER_LINE_CAP
        scan = DOCKER_SCAN_CAP if filtering else DOCKER_LINE_CAP
        # On a swarm manager `docker logs` only sees local tasks, so resolve the
        # service label first and prefer `docker service logs`. Container logs
        # carry no severity metadata, so only grep can filter them.
        body = (
            'if sudo -n docker version >/dev/null 2>&1; then D="sudo -n docker"; '
            'else D="docker"; fi; '
            f'SVC=$($D inspect -f {label} {container} 2>/dev/null); '
            f'if [ -n "$SVC" ]; then $D service logs --since {shlex.quote(since)} '
            f'--timestamps --tail {scan} "$SVC" 2>&1; '
            f'else $D logs --since {shlex.quote(since)} --timestamps '
            f'--tail {scan} {container} 2>&1; fi'
        )
        if not filtering:
            return body
        # The docker branch is a compound `if`; group it so one pipe applies.
        return '{ ' + body + '; }' + _grep_filter(levels).format(cap=cap)

    raise ValueError(f'unknown source kind: {kind}')


def collect_one(host_key, source, window_start, window_end, budget=None, sev_levels=None):
    """Fetch a single source. Never raises: failures are recorded in the result."""
    app = _app()
    cmd = build_command(source, window_start, window_end, sev_levels=sev_levels)
    timeout = SOURCE_TIMEOUT
    if source['kind'] == 'docker':
        timeout = SOURCE_TIMEOUT + 20

    started = datetime.datetime.now(datetime.timezone.utc)
    try:
        res = app.execute_command(host_key, cmd, timeout=timeout)
        text = res.stdout or ''
    except Exception as exc:
        return {
            'source': source,
            'ok': False,
            'status': 'error',
            'text': '',
            'lines': 0,
            'bytes': 0,
            'error': str(exc),
            'duration_ms': int((datetime.datetime.now(datetime.timezone.utc) - started).total_seconds() * 1000),
        }

    if budget is not None:
        text = budget.consume(text)

    has_text = bool(text.strip())
    return {
        'source': source,
        'ok': has_text,
        # 'empty' is NOT a failure: a quiet container or an idle log simply had
        # nothing to say in the window. Conflating the two makes the report
        # claim "logging failures" that never happened.
        'status': 'ok' if has_text else 'empty',
        'text': text,
        'lines': text.count('\n') + (1 if text and not text.endswith('\n') else 0),
        'bytes': len(text.encode('utf-8', 'ignore')),
        'error': None,
        'duration_ms': int((datetime.datetime.now(datetime.timezone.utc) - started).total_seconds() * 1000),
    }


class _ByteBudget:
    """Shared byte budget across a run so one noisy host cannot blow the tab."""

    def __init__(self, limit=MAX_BYTES):
        self.limit = limit
        self.used = 0
        self.lock = threading.Lock()

    def consume(self, text):
        raw = text.encode('utf-8', 'ignore')
        with self.lock:
            remaining = self.limit - self.used
            if remaining <= 0:
                return ''
            if len(raw) <= remaining:
                self.used += len(raw)
                return text
            # Keep the newest part: the tail is what correlates with "now".
            clipped = raw[-remaining:]
            self.used += len(clipped)
            return '[--- truncated to fit report budget ---]\n' + clipped.decode('utf-8', 'ignore')


def _journal_activity(host_key, window_start, limit=8000):
    """Count recent journal lines per unit, in one round trip.

    Used to rank units so the cap is spent on the units that actually wrote
    something during the window rather than the first 30 alphabetically.
    Best effort: an empty dict means "keep the discovery order".
    """
    app = _app()
    since = ''
    if window_start is not None:
        try:
            since = f'--since @{int(window_start.timestamp())} '
        except Exception:
            since = ''
    cmd = (
        f'sudo journalctl {since}-n {int(limit)} -o json '
        f'--output-fields=_SYSTEMD_UNIT --no-pager 2>/dev/null '
        + '''| grep -o '\"_SYSTEMD_UNIT\":\"[^\"]*\"' '''
        + '| sort | uniq -c | sort -rn | head -n 120'
    )
    try:
        res = app.execute_command(host_key, cmd, timeout=25)
    except Exception:
        return {}
    counts = {}
    for line in (res.stdout or '').splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        try:
            count = int(parts[0])
        except ValueError:
            continue
        # " 77 _SYSTEMD_UNIT=\"ssh.service\"" -> ssh.service
        unit = parts[1].rsplit('="', 1)[-1].rstrip('"')
        if unit:
            counts[unit] = count
    return counts


def select_sources(sources, max_sources, shares=None):
    """Trim the candidate list to ``max_sources`` without starving a kind.

    Files are already ordered newest-first, journal units by activity and
    containers running-first, so each kind's list is a priority order. The cap
    is divided by kind, then any unused allowance overflows to the kinds that
    still have candidates.

    Returns ``(selected, dropped)`` where ``dropped`` maps kind -> count.
    """
    shares = shares or KIND_SHARES
    if max_sources <= 0 or len(sources) <= max_sources:
        return list(sources), {}

    by_kind = {}
    for source in sources:
        by_kind.setdefault(source.get('kind') or 'other', []).append(source)

    chosen = {}
    for kind, items in by_kind.items():
        quota = max(1, int(round(max_sources * shares.get(kind, 0.2))))
        chosen[kind] = items[:quota]

    total = sum(len(items) for items in chosen.values())
    while total > max_sources:
        kind = max(chosen, key=lambda k: len(chosen[k]) - max_sources * shares.get(k, 0.2))
        if not chosen[kind]:
            break
        chosen[kind].pop()
        total -= 1

    while total < max_sources:
        backlog = [k for k in by_kind if len(chosen[k]) < len(by_kind[k])]
        if not backlog:
            break
        kind = max(backlog, key=lambda k: len(by_kind[k]) - len(chosen[k]))
        chosen[kind] = by_kind[kind][:len(chosen[kind]) + 1]
        total += 1

    keep = {id(item) for items in chosen.values() for item in items}
    selected = [s for s in sources if id(s) in keep]
    dropped = {kind: len(items) - len(chosen.get(kind, []))
               for kind, items in by_kind.items()}
    return selected, {k: v for k, v in dropped.items() if v}


def collect_host_logs(host_key, host_label=None, window_minutes=DEFAULT_WINDOW_MINUTES,
                      include_files=True, include_journal=True, include_docker=True,
                      include_stopped=False, max_sources=None, progress=None, app=None,
                      lock=None, severities=None):
    """Collect every in-scope source for one host inside the time window.

    ``progress`` is called with dict payloads so the SSE route can stream them.
    ``app`` must be the real Flask app object (``current_app._get_current_object()``)
    because worker threads do not inherit a request context.

    ``severities`` is any value ``severity.parse`` understands (list of names,
    comma string, or ``None``/``'all'`` for no filter). Filtering happens on the
    host, so filtered-out lines cost no bandwidth and no byte budget.
    """
    minutes = clamp_window(window_minutes)
    sev_levels = severity.parse(severities)
    window_start, window_end = window_bounds(minutes)
    max_sources = max_sources or MAX_SOURCES

    def emit(payload):
        if progress:
            try:
                progress(payload)
            except Exception:
                pass

    result = {
        'host_key': host_key,
        'host_label': host_label or host_key,
        'window_minutes': minutes,
        'window_start': window_start,
        'window_end': window_end,
        'sources': [],
        'errors': [],
        'skipped': [],
        'truncated': False,
        'duration_ms': 0,
        'severity_filter': severity.summary(sev_levels, prefilter=_prefilter_for(sev_levels)),
    }

    started = datetime.datetime.now(datetime.timezone.utc)

    emit({'phase': 'discover', 'message': 'Enumerating log sources...'})
    sources, errors = list_sources(
        host_key,
        include_files=include_files,
        include_journal=include_journal,
        include_docker=include_docker,
        include_stopped=include_stopped,
        window_start=window_start,
        progress=lambda msg: emit({'phase': 'discover', 'message': msg}),
    )
    result['errors'].extend(errors)

    if sev_levels:
        emit({'phase': 'discover',
              'message': f"Severity filter: {severity.describe(sev_levels)} only "
                         f"(applied on the host before transfer)."})

    if len(sources) > max_sources:
        sources, dropped = select_sources(sources, max_sources)
        result['truncated'] = True
        result['dropped'] = dropped
        detail = ', '.join(f'{n} {kind}' for kind, n in sorted(dropped.items()) if n)
        result['skipped'].append(
            f'source cap reached (MAX_SOURCES={max_sources}): '
            f'collected {len(sources)}, skipped {detail}')

    if not sources:
        result['duration_ms'] = int((datetime.datetime.now(datetime.timezone.utc) - started).total_seconds() * 1000)
        return result

    emit({'phase': 'collect', 'message': f'Fetching {len(sources)} source(s) from the last {minutes} minutes...',
          'sources_total': len(sources)})

    budget = _ByteBudget()
    collected = []
    total = len(sources)
    held = lock or host_lock(host_key)
    already = held.acquire(blocking=False) if lock is None else True
    if lock is None and not already:
        raise RuntimeError('A report run is already in progress for this host.')

    try:
        with ThreadPoolExecutor(max_workers=COLLECT_WORKERS) as pool:
            futures = {
                pool.submit(_collect_in_context, app, host_key, src, window_start,
                            window_end, budget, sev_levels): src
                for src in sources
            }
            done = 0
            for fut in as_completed(futures):
                src = futures[fut]
                done += 1
                try:
                    item = fut.result()
                except Exception as exc:  # pragma: no cover - defensive
                    item = {'source': src, 'ok': False, 'status': 'error', 'text': '',
                            'lines': 0, 'bytes': 0, 'error': str(exc), 'duration_ms': 0}
                collected.append(item)
                state = item.get('status') or ('ok' if item['ok'] else 'error')
                if state == 'empty':
                    state = 'no output'
                emit({
                    'phase': 'collect',
                    'message': f"[{done}/{total}] {src['label']}: {state}"
                               + (f" ({item['lines']} lines)" if item['ok'] else ''),
                    'sources_done': done,
                    'sources_total': total,
                })
    finally:
        if lock is None and already:
            held.release()

    result['sources'] = collected
    result['duration_ms'] = int((datetime.datetime.now(datetime.timezone.utc) - started).total_seconds() * 1000)
    return result


def _collect_in_context(app, host_key, source, window_start, window_end, budget,
                        sev_levels=None):
    """Run ``collect_one`` with an application context pushed.

    ``app`` may be None when called from a script/test harness.
    """
    if app is None:
        return collect_one(host_key, source, window_start, window_end, budget, sev_levels)
    with app.app_context():
        return collect_one(host_key, source, window_start, window_end, budget, sev_levels)


# ---------------------------------------------------------------------------
# container state snapshot
# ---------------------------------------------------------------------------

def container_states(host_key, sources, timeout=20):
    """Best-effort container state for every docker source.

    Exit codes, restart counts and OOM kills are the strongest correlation
    anchors available, so they are collected even when the logs themselves are
    thin.
    """
    app = _app()
    ids = [s['container_id'] for s in sources if s['kind'] == 'docker' and s.get('container_id')]
    if not ids:
        return []

    fmt = '{{.Id}}|{{.Name}}|{{.Config.Image}}|{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}|{{.State.OOMKilled}}|{{.State.StartedAt}}'
    states = []
    # Batch in small groups to stay under the command timeout.
    for chunk_start in range(0, len(ids), 8):
        chunk = ids[chunk_start:chunk_start + 8]
        quoted = ' '.join(shlex.quote(c) for c in chunk)
        cmd = (
            'if sudo -n docker version >/dev/null 2>&1; then D="sudo -n docker"; '
            'else D="docker"; fi; '
            f'for c in {quoted}; do $D inspect -f {shlex.quote(fmt)} "$c" 2>/dev/null; done'
        )
        try:
            res = app.execute_command(host_key, cmd, timeout=timeout)
        except Exception as exc:
            print(f'[report] container inspect failed on {host_key}: {exc}')
            continue
        for line in (res.stdout or '').splitlines():
            parts = line.split('|')
            if len(parts) != 8:
                continue
            states.append({
                'id': parts[0][:12],
                'name': parts[1].lstrip('/'),
                'image': parts[2],
                'status': parts[3],
                'exit_code': _to_int(parts[4]),
                'restarts': _to_int(parts[5]),
                'oom_killed': parts[6].strip().lower() == 'true',
                'started_at': parts[7],
            })
    return states


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
