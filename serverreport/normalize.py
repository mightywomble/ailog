"""Turn raw log text into timestamped, de-duplicated events.

Two jobs, both essential to making "all logs" tractable:

1. **Timestamp extraction** - every line gets a real UTC timestamp so events from
   different sources can be compared on one clock.
2. **Signature clustering** - near-identical lines collapse into one cluster
   with a count. On real hosts this is a 50-200x reduction, which is what keeps
   the model prompt inside its context window.

Nothing here talks to the network or the database; it is pure text processing so
it can be unit tested against fixtures.
"""
import datetime
import re
from collections import defaultdict

# ---------------------------------------------------------------------------
# timestamps
# ---------------------------------------------------------------------------

_MONTHS = {m: i for i, m in enumerate(
    ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'], start=1)}

_RFC3339_RE = re.compile(
    r'(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?'
)
_SYSLOG_RE = re.compile(r'^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+([ 0-9]\d)\s+(\d{2}:\d{2}:\d{2})')
_BRACKET_RE = re.compile(r'^\[(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})\]')


def _tz_from(text):
    if not text or text == 'Z':
        return datetime.timezone.utc
    sign = 1 if text[0] == '+' else -1
    body = text[1:].replace(':', '')
    try:
        hours, minutes = int(body[:2]), int(body[2:4])
    except (ValueError, IndexError):
        return datetime.timezone.utc
    return datetime.timezone(datetime.timedelta(minutes=sign * (hours * 60 + minutes)))


def parse_timestamp(line, reference=None):
    """Return an aware UTC datetime for the line, or None.

    Handles RFC3339 (docker ``--timestamps``, journal ``short-iso``), syslog
    ``Mon DD HH:MM:SS`` (year inferred) and ``[YYYY-MM-DD HH:MM:SS]`` brackets.
    """
    if not line:
        return None
    reference = reference or datetime.datetime.now(datetime.timezone.utc)
    head = line[:64]

    mt = _RFC3339_RE.search(head)
    if mt:
        date_s, time_s, frac, tz_s = mt.groups()
        try:
            base = datetime.datetime.strptime(f'{date_s} {time_s}', '%Y-%m-%d %H:%M:%S')
        except ValueError:
            base = None
        if base is not None:
            if frac:
                micro = int((frac + '000000')[:6])
                base = base.replace(microsecond=micro)
            return base.replace(tzinfo=_tz_from(tz_s)).astimezone(datetime.timezone.utc)

    mt = _BRACKET_RE.search(head)
    if mt:
        try:
            base = datetime.datetime.strptime(f'{mt.group(1)} {mt.group(2)}', '%Y-%m-%d %H:%M:%S')
            return base.replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            pass

    mt = _SYSLOG_RE.match(line)
    if mt:
        month, day, hms = _MONTHS.get(mt.group(1)), int(mt.group(2)), mt.group(3)
        if month:
            year = reference.year
            try:
                cand = datetime.datetime.strptime(
                    f'{year}-{month:02d}-{day:02d} {hms}', '%Y-%m-%d %H:%M:%S'
                ).replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                return None
            # Syslog carries no year; a December line read in January belongs to
            # the previous year, not eleven months in the future.
            if cand - reference > datetime.timedelta(days=1):
                try:
                    cand = cand.replace(year=year - 1)
                except ValueError:
                    pass
            return cand

    return None


# ---------------------------------------------------------------------------
# severity
# ---------------------------------------------------------------------------

SEV_CRIT, SEV_ERROR, SEV_WARN, SEV_INFO = 4, 3, 2, 1

# Keyword tables as *data*, so the source-side pre-filter in collect.py can
# build a grep pattern from exactly the same words this classifier uses
# (serverreport/severity.py). Divergence here would mean the report silently
# misses lines that a "filtered" grep run never shipped.
SEVERITY_WORDS = {
    SEV_CRIT: (
        r'emerg|emergency|alert|crit|critical|panic|kernel\s+panic|segfault|'
        r'oom[- ]?kill|out\s+of\s+memory|hard\s+lockup|machine\s+check'
    ),
    SEV_ERROR: (
        r'error|err|fail(?:ed|ure|ing)?|fatal|exception|traceback|refused|denied|'
        r'timeout|timed\s+out|unreachable|corrupt(?:ed)?|abort(?:ed)?|'
        r'cannot|can\'t|unable\s+to|no\s+space\s+left|killed|exited\s+with|'
        r'exited\s+on\s+signal|signal\s+\d+|exit\s+code\s+[1-9]|'
        r'segmentation\s+fault|broken\s+pipe'
    ),
    SEV_WARN: (
        r'warn|warning|deprecat(?:ed|ion)|retry|retrying|slow|degraded|'
        r'throttl(?:ed|ing)|high\s+load|stale'
    ),
}

_SEV_LEVELS = tuple(
    (level, re.compile(r'\b(?:' + words + r')\b', re.I))
    for level, words in SEVERITY_WORDS.items()
)


def classify_severity(text):
    for level, pattern in _SEV_LEVELS:
        if pattern.search(text):
            return level
    return SEV_INFO


SEV_NAMES = {SEV_CRIT: 'crit', SEV_ERROR: 'error', SEV_WARN: 'warn', SEV_INFO: 'info'}
SEV_BY_NAME = {name: level for level, name in SEV_NAMES.items()}


def sev_level_set(values):
    """Coerce a severity selection into a set of ``SEV_*`` constants.

    Accepts either the constants themselves or their names, because both reach
    this function from different callers (routes map names -> constants, tests
    and stored configs sometimes do not). A name that is not understood is
    dropped rather than guessed; an *empty* result means "no filter", so a typo
    can never silently empty every report.
    """
    levels = set()
    for value in values or ():
        if isinstance(value, str):
            name = value.strip().lower()
            if name in SEV_BY_NAME:
                levels.add(SEV_BY_NAME[name])
            continue
        try:
            ivalue = int(value)
        except (TypeError, ValueError):
            continue
        if ivalue in SEV_NAMES:
            levels.add(ivalue)
    return frozenset(levels)


# ---------------------------------------------------------------------------
# signatures
# ---------------------------------------------------------------------------

_SIG_SUBS = (
    (_RFC3339_RE, '<ts>'),
    (_SYSLOG_RE, '<ts>'),
    (_BRACKET_RE, '<ts>'),
    (re.compile(r'\b[0-9a-fA-F]{12,64}\b'), '<id>'),
    (re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'), '<uuid>'),
    (re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b'), '<ip>'),
    (re.compile(r'\b\d+(?:\.\d+)?\s?(?:ms|us|ns|s|sec|secs|seconds|m|min|mins|h|hours|B|KB|MB|GB|%)\b'), '<n>'),
    (re.compile(r'\b\d+(?:\.\d+)?\b'), '<n>'),
    (re.compile(r'\s+'), ' '),
)

_CONTINUATION_RE = re.compile(
    r'^(\s+|at\s+\S|Caused by:|Traceback\b|File\s+"|\.\.\.|\}' r'|\))'
)

MAX_SAMPLE_LINES = 6


def signature(text):
    """Reduce a log line to a stable template with volatile values removed."""
    sig = text or ''
    for pattern, repl in _SIG_SUBS:
        sig = pattern.sub(repl, sig)
    return sig.strip()[:400]


# ---------------------------------------------------------------------------
# normalisation
# ---------------------------------------------------------------------------

def _blank_event(ts, source, sev, message):
    return {
        'ts': ts,
        'src': source['key'],
        'label': source['label'],
        'kind': source['kind'],
        'sev': sev,
        'msg': message[:500],
        'sig': signature(message),
        'lines': 1,
    }


def normalize_source(source, raw_text, window_start, window_end, reference=None,
                     sev_levels=None):
    """Parse one collected source into events.

    Lines with no parseable timestamp inherit the previous timestamp, which is
    how multi-line stack traces stay attached to their parent event.

    ``sev_levels`` is a set of ``SEV_*`` constants (empty/None = keep all). This
    is the authoritative severity filter: collect.py already cut bytes on the
    host, but a grep over raw text is a heuristic and this classifier is not, so
    anything the pre-filter let through is dropped here. Dropping a line also
    detaches ``previous`` so a stack trace can never attach to an unrelated
    event that survived the filter.
    """
    levels = sev_level_set(sev_levels)
    events = []
    stats = {
        'key': source['key'],
        'label': source['label'],
        'kind': source['kind'],
        'lines': 0,
        'kept': 0,
        'out_of_window': 0,
        'no_timestamp': 0,
        'filtered_out': 0,
    }
    if not raw_text:
        return events, stats

    ref = reference or window_end
    last_dt = None
    previous = None

    for raw in raw_text.splitlines():
        if not raw.strip():
            continue
        stats['lines'] += 1

        dt = parse_timestamp(raw, reference=ref)
        is_continuation = bool(_CONTINUATION_RE.match(raw)) and previous is not None and dt is None

        if dt is None:
            stats['no_timestamp'] += 1
            if is_continuation:
                # Attach to the parent event instead of inventing a new cluster.
                if len(previous['msg'].splitlines()) < MAX_SAMPLE_LINES:
                    previous['msg'] = previous['msg'] + '\n' + raw.strip()[:200]
                previous['lines'] += 1
                continue
            dt = last_dt
            if dt is None:
                # No clock yet for this source: assume the window start so the
                # event still participates (flagged, not silently dropped).
                dt = window_start
        last_dt = dt

        if dt < window_start or dt > window_end:
            stats['out_of_window'] += 1
            continue

        sev = classify_severity(raw)
        if levels and sev not in levels:
            stats['filtered_out'] += 1
            previous = None       # never let a later continuation attach here
            continue
        # Events carry epoch seconds: every consumer compares/subtracts them.
        event = _blank_event(dt.timestamp(), source, sev, raw.strip())
        events.append(event)
        previous = event
        stats['kept'] += 1

    return events, stats


def _cluster_key(event):
    return (event['sig'], event['src'])


def build_clusters(events):
    """Group events by (signature, source) and keep representative samples."""
    buckets = defaultdict(list)
    for ev in events:
        buckets[_cluster_key(ev)].append(ev)

    clusters = []
    for (_sig, _src), group in buckets.items():
        group.sort(key=lambda e: e['ts'])
        first, last = group[0], group[-1]
        samples = []
        # Prefer distinct raw messages so the model sees variation, not repeats.
        seen = set()
        for ev in group:
            probe = re.sub(r'\s+', ' ', ev['msg'])[:200]
            if probe in seen:
                continue
            seen.add(probe)
            samples.append(ev['msg'][:300])
            if len(samples) >= 3:
                break
        clusters.append({
            'sig': _sig,
            'src': first['src'],
            'label': first['label'],
            'kind': first['kind'],
            'sev': max(e['sev'] for e in group),
            'count': len(group),
            'first_ts': first['ts'],
            'last_ts': last['ts'],
            'samples': samples,
        })

    clusters.sort(key=lambda c: (-c['sev'], -c['count']))
    return clusters


def normalize_all(collected, window_start, window_end, sev_levels=None):
    """Normalise every collected source.

    ``collected`` is the ``sources`` list from ``collect.collect_host_logs``.
    ``sev_levels`` is the severity selection (``SEV_*`` constants); see
    ``normalize_source``.
    """
    levels = sev_level_set(sev_levels)
    all_events = []
    source_stats = []
    filtered_out = 0
    for item in collected:
        if not item.get('ok'):
            source_stats.append({
                'key': item['source']['key'],
                'label': item['source']['label'],
                'kind': item['source']['kind'],
                'lines': 0, 'kept': 0, 'out_of_window': 0, 'no_timestamp': 0,
                'filtered_out': 0,
                'status': item.get('status') or ('ok' if item.get('ok') else 'error'),
                'error': item.get('error') if item.get('status') == 'error' else None,
            })
            continue
        events, stats = normalize_source(
            item['source'], item['text'], window_start, window_end, reference=window_end,
            sev_levels=levels,
        )
        all_events.extend(events)
        filtered_out += stats.get('filtered_out') or 0
        stats['status'] = 'ok'
        source_stats.append(stats)

    all_events.sort(key=lambda e: e['ts'])
    clusters = build_clusters(all_events)

    severity_counts = {name: 0 for name in SEV_NAMES.values()}
    for ev in all_events:
        severity_counts[SEV_NAMES[ev['sev']]] += 1

    return {
        'events': all_events,
        'clusters': clusters,
        'source_stats': source_stats,
        'severity_counts': severity_counts,
        'severity_filter': {
            'levels': sorted(SEV_NAMES[lvl] for lvl in levels),
            'active': bool(levels),
            'events_kept': len(all_events),
            'events_filtered': filtered_out,
            'lines_kept': sum(s.get('kept') or 0 for s in source_stats),
        },
    }
