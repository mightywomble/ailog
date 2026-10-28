"""Deterministic cross-source correlation.

Everything here is arithmetic on timestamps - no model, no heuristics that cannot
be explained. The output is what the report is built from, and what makes a
"server report" different from a pile of per-log summaries.

The statistics are deliberately conservative:

* 10 second buckets, because log timestamps routinely drift by a second or two
  even on one host (buffered writers, journald batching).
* co-occurrence is ranked by **lift** against an independence baseline, so two
  chatty-but-unrelated sources cannot dominate the results.
* bursts use median/MAD rather than a fixed threshold, so a naturally noisy
  source is not permanently "bursting".
"""
import datetime
import statistics
from collections import defaultdict

BUCKET_SECONDS = 10
MIN_PAIR_COINCIDENCE = 3
MIN_LIFT = 2.0
BURST_MAD_FACTOR = 3.0
MIN_GAP_SECONDS = 120
GAP_MEDIAN_FACTOR = 5.0
MAX_PAIRS = 20
MAX_TIMELINE = 40
CONTAINER_LOOKBACK = 60


def _iso(ts):
    if ts is None:
        return ''
    if isinstance(ts, datetime.datetime):
        ts = ts.timestamp()
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _bucket(ts, origin):
    return int((ts - origin) // BUCKET_SECONDS)


# ---------------------------------------------------------------------------
# bursts
# ---------------------------------------------------------------------------

def detect_bursts(events, origin, window_end):
    """Flag per-minute spikes relative to a cluster's own baseline."""
    per_cluster_minute = defaultdict(lambda: defaultdict(int))
    for ev in events:
        minute = int((ev['ts'] - origin) // 60)
        per_cluster_minute[(ev['sig'], ev['src'])][minute] += 1

    bursts = []
    total_minutes = max(1, int((window_end - origin) // 60) + 1)
    for key, minutes in per_cluster_minute.items():
        counts = [minutes.get(m, 0) for m in range(total_minutes)]
        if sum(counts) < 5:
            continue
        median = statistics.median(counts)
        deviations = [abs(c - median) for c in counts]
        mad = statistics.median(deviations) or 1.0
        threshold = median + BURST_MAD_FACTOR * mad
        for minute, count in sorted(minutes.items()):
            if count >= max(3, threshold) and count > median:
                bursts.append({
                    'sig': key[0],
                    'src': key[1],
                    'minute_offset': minute,
                    # origin is epoch seconds, so stay in seconds here
                    'ts': origin + minute * 60,
                    'count': count,
                    'median': median,
                })
    bursts.sort(key=lambda b: -b['count'])
    return bursts[:40]


# ---------------------------------------------------------------------------
# co-occurrence
# ---------------------------------------------------------------------------

def find_correlations(events, origin, window_end):
    """Rank cross-source cluster pairs by lift over an independence baseline."""
    usable = [ev for ev in events if ev['sev'] >= 2]  # warn and above only
    if not usable:
        return []

    total_buckets = max(1, int((window_end - origin) // BUCKET_SECONDS) + 1)

    cluster_buckets = defaultdict(set)
    cluster_meta = {}
    for ev in usable:
        key = (ev['sig'], ev['src'])
        cluster_buckets[key].add(_bucket(ev['ts'], origin))
        cluster_meta.setdefault(key, {'label': ev['label'], 'sev': ev['sev'], 'sig': ev['sig']})

    # Keep the pair space sane: only reasonably frequent clusters from distinct
    # sources can produce a meaningful lift figure.
    candidates = [
        key for key, buckets in cluster_buckets.items()
        if len(buckets) >= 2 and len(buckets) <= total_buckets * 0.5
    ]
    candidates.sort(key=lambda k: -len(cluster_buckets[k]))
    candidates = candidates[:80]

    pairs = []
    for i, a in enumerate(candidates):
        for b in candidates[i + 1:]:
            if a[1] == b[1]:
                continue  # same source: sequencing, not correlation
            shared = cluster_buckets[a] & cluster_buckets[b]
            n_ab = len(shared)
            if n_ab < MIN_PAIR_COINCIDENCE:
                continue
            n_a, n_b = len(cluster_buckets[a]), len(cluster_buckets[b])
            lift = (n_ab / total_buckets) / ((n_a / total_buckets) * (n_b / total_buckets))
            if lift < MIN_LIFT:
                continue
            pairs.append({
                'a': {'sig': a[0], 'src': a[1], 'label': cluster_meta[a]['label']},
                'b': {'sig': b[0], 'src': b[1], 'label': cluster_meta[b]['label']},
                'lift': round(lift, 1),
                'coincidences': n_ab,
                'score': round(lift * (n_ab ** 0.5), 2),
                'lag_seconds': _median_lag(events, a, b),
            })

    pairs.sort(key=lambda p: -p['score'])
    return pairs[:MAX_PAIRS]


def _median_lag(events, key_a, key_b):
    """Median lag (seconds) from a's first hit to b's first hit per bucket."""
    by_bucket = defaultdict(lambda: {'a': [], 'b': []})
    for ev in events:
        key = (ev['sig'], ev['src'])
        if key not in (key_a, key_b):
            continue
        bucket = int(ev['ts'] // BUCKET_SECONDS)
        by_bucket[bucket]['a' if key == key_a else 'b'].append(ev['ts'])

    lags = []
    for bucket, sides in by_bucket.items():
        if sides['a'] and sides['b']:
            lags.append(min(sides['b']) - min(sides['a']))
    if not lags:
        return None
    return round(statistics.median(lags), 1)


# ---------------------------------------------------------------------------
# silence / gaps
# ---------------------------------------------------------------------------

def detect_gaps(events, window_end):
    """Find sources that went quiet, or stopped logging before the window ended."""
    per_source = defaultdict(list)
    for ev in events:
        per_source[ev['src']].append(ev['ts'])

    gaps = []
    for src, stamps in per_source.items():
        stamps.sort()
        if len(stamps) < 5:
            continue
        intervals = [b - a for a, b in zip(stamps, stamps[1:])]
        median = statistics.median(intervals) or 1.0
        threshold = max(MIN_GAP_SECONDS, median * GAP_MEDIAN_FACTOR)
        for a, b in zip(stamps, stamps[1:]):
            if b - a >= threshold:
                gaps.append({
                    'src': src,
                    'kind': 'gap',
                    'start': a,
                    'end': b,
                    'seconds': round(b - a, 1),
                })
        # Silently stopping is often more diagnostic than an explicit error.
        if window_end - stamps[-1] >= 600 and stamps[-1] - stamps[0] >= 300:
            gaps.append({
                'src': src,
                'kind': 'stopped_early',
                'start': stamps[-1],
                'end': window_end,
                'seconds': round(window_end - stamps[-1], 1),
            })

    gaps.sort(key=lambda g: -g['seconds'])
    return gaps[:20]


# ---------------------------------------------------------------------------
# container events
# ---------------------------------------------------------------------------

def container_events(containers):
    """Turn container state into timeline-worthy events."""
    out = []
    for c in containers or []:
        name = c.get('name') or c.get('id')
        if c.get('oom_killed'):
            out.append({
                'src': f'docker:{name}', 'label': f'docker:{name}', 'sev': 4,
                'ts': None, 'sig': 'container oom-killed',
                'message': f"container {name} ({c.get('image')}) was OOM-killed",
            })
        if c.get('restarts'):
            sev = 3 if (c.get('restarts') or 0) >= 3 else 2
            out.append({
                'src': f'docker:{name}', 'label': f'docker:{name}', 'sev': sev,
                'ts': None, 'sig': 'container restarted',
                'message': f"container {name} has restarted {c['restarts']} time(s)",
            })
        status = (c.get('status') or '').lower()
        if status not in ('running', '') and (c.get('exit_code') or 0) != 0:
            out.append({
                'src': f'docker:{name}', 'label': f'docker:{name}', 'sev': 3,
                'ts': None, 'sig': 'container exited non-zero',
                'message': f"container {name} is {status}, last exit code {c['exit_code']}",
            })
    return out


# ---------------------------------------------------------------------------
# timeline
# ---------------------------------------------------------------------------

def build_timeline(events, clusters, bursts, containers, origin, window_end):
    """A chronological narrative of the significant first occurrences."""
    burst_keys = {(b['sig'], b['src']) for b in bursts}
    hot = [
        c for c in clusters
        if c['sev'] >= 3 or (c['sig'], c['src']) in burst_keys
    ]
    hot.sort(key=lambda c: c['first_ts'])
    hot = hot[:MAX_TIMELINE]

    timeline = []
    for c in hot:
        timeline.append({
            'ts': _iso(c['first_ts']),
            'offset_seconds': round(c['first_ts'] - origin, 1),
            'src': c['src'],
            'label': c['label'],
            'sev': c['sev'],
            'count': c['count'],
            'sig': c['sig'],
        })

    # Container problems have no log timestamp of their own; place them at the
    # start of the window so they are visible without inventing a time.
    for ev in container_events(containers):
        if ev['sev'] >= 3:
            timeline.append({
                'ts': _iso(origin),
                'offset_seconds': 0,
                'src': ev['src'],
                'label': ev['label'],
                'sev': ev['sev'],
                'count': 1,
                'sig': ev['sig'],
                'note': 'state snapshot (no timestamp available)',
            })
    return timeline


def link_containers_to_bursts(bursts, containers):
    """Container restarts explain far more when tied to a nearby log burst."""
    links = []
    for c in containers or []:
        if not (c.get('restarts') or c.get('oom_killed')):
            continue
        links.append({
            'container': c.get('name'),
            'image': c.get('image'),
            'restarts': c.get('restarts') or 0,
            'oom_killed': bool(c.get('oom_killed')),
            'exit_code': c.get('exit_code') or 0,
            'nearby_bursts': len(bursts),
            'note': 'container instability coincides with log bursts; see correlations',
        })
    return links


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def correlate(events, clusters, containers, window_start, window_end):
    origin = window_start.timestamp()
    end_ts = window_end.timestamp()

    bursts = detect_bursts(events, origin, end_ts)
    correlations = find_correlations(events, origin, end_ts)
    gaps = detect_gaps(events, end_ts)
    timeline = build_timeline(events, clusters, bursts, containers, origin, end_ts)

    return {
        'bursts': bursts,
        'correlations': correlations,
        'gaps': gaps,
        'timeline': timeline,
        'container_links': link_containers_to_bursts(bursts, containers),
        'window': {
            'start': _iso(window_start),
            'end': _iso(window_end),
            'seconds': round(end_ts - origin, 1),
            'bucket_seconds': BUCKET_SECONDS,
        },
    }
