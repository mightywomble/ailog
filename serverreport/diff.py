"""Diff two stored reports for the same host.

A daily report is only useful if you can see what *changed*: the verdict moved,
new signature clusters appeared, an old one stopped. Reading yesterday's and
today's reports side by side is not something anyone does, so the report page
gets a "Since last report" panel built here.

Everything works off the stored JSON columns, so it costs two rows and no
recollection of the host.
"""

from __future__ import annotations

import json

MAX_ITEMS = 8


def _loads(value, fallback):
    if value is None:
        return fallback
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return fallback


def report_payload(report):
    """The subset of a LogReport that diffing needs."""
    if report is None:
        return None
    return {
        'id': report.id,
        'created_at': report.created_at.isoformat() if report.created_at else None,
        'verdict': (report.verdict or 'unknown').lower(),
        'window_minutes': report.window_minutes,
        'events_total': report.events_total or 0,
        'clusters_total': report.clusters_total or 0,
        'sources_ok': report.sources_ok or 0,
        'sources_failed': report.sources_failed or 0,
        'severity': _loads(report.severity_json, {}),
        'clusters': _loads(getattr(report, 'clusters_json', None), []),
        'correlations': _loads(report.correlations_json, []),
    }


def _cluster_index(clusters):
    """sig+src -> cluster. The signature alone can appear on several sources."""
    out = {}
    for cluster in clusters or []:
        sig = cluster.get('sig')
        if not sig:
            continue
        out[(sig, cluster.get('src') or '')] = cluster
    return out


def _correlation_index(pairs):
    out = {}
    for pair in pairs or []:
        a = (pair.get('a') or {}).get('sig')
        b = (pair.get('b') or {}).get('sig')
        if not a or not b:
            continue
        out[tuple(sorted((a, b)))] = pair
    return out


def _label(cluster):
    return (cluster or {}).get('label') or (cluster or {}).get('sig') or '?'


def _slim(cluster):
    return {
        'sig': cluster.get('sig'),
        'label': _label(cluster),
        'src': cluster.get('src'),
        'sev': cluster.get('sev'),
        'count': cluster.get('count') or 0,
    }


def _delta(before, after):
    try:
        before = float(before or 0)
        after = float(after or 0)
    except (TypeError, ValueError):
        return {'before': before, 'after': after, 'delta': None, 'pct': None}
    change = after - before
    pct = round(100.0 * change / before, 1) if before else None
    return {'before': before, 'after': after, 'delta': change, 'pct': pct}


def compare(previous, current):
    """Compare ``previous`` against ``current`` (both from report_payload).

    Returns ``{'has_previous': False}`` when there is nothing to compare with,
    so callers can render nothing at all.
    """
    if not previous or not current:
        return {'has_previous': False}

    prev_clusters = _cluster_index(previous.get('clusters'))
    cur_clusters = _cluster_index(current.get('clusters'))

    new_keys = [k for k in cur_clusters if k not in prev_clusters]
    gone_keys = [k for k in prev_clusters if k not in cur_clusters]
    # A cluster that got dramatically noisier is as interesting as a new one.
    louder = []
    for key, cluster in cur_clusters.items():
        before = prev_clusters.get(key)
        if not before:
            continue
        before_count = before.get('count') or 0
        after_count = cluster.get('count') or 0
        if before_count and after_count >= before_count * 3 and after_count - before_count >= 20:
            louder.append(cluster)

    new_clusters = sorted((cur_clusters[k] for k in new_keys),
                          key=lambda c: -(c.get('count') or 0))
    gone_clusters = sorted((prev_clusters[k] for k in gone_keys),
                           key=lambda c: -(c.get('count') or 0))
    louder.sort(key=lambda c: -(c.get('count') or 0))

    prev_corr = _correlation_index(previous.get('correlations'))
    cur_corr = _correlation_index(current.get('correlations'))
    new_corr = [cur_corr[k] for k in cur_corr if k not in prev_corr]
    gone_corr = [prev_corr[k] for k in prev_corr if k not in cur_corr]
    new_corr.sort(key=lambda p: -(p.get('score') or 0))
    gone_corr.sort(key=lambda p: -(p.get('score') or 0))

    severity_before = previous.get('severity') or {}
    severity_after = current.get('severity') or {}
    severity_change = {}
    for key in set(severity_before) | set(severity_after):
        try:
            before = int(severity_before.get(key) or 0)
            after = int(severity_after.get(key) or 0)
        except (TypeError, ValueError):
            continue
        if before != after:
            severity_change[key] = {'before': before, 'after': after, 'delta': after - before}

    events = _delta(previous.get('events_total'), current.get('events_total'))
    verdict_changed = previous.get('verdict') != current.get('verdict')

    summary = _summary(previous, current, len(new_clusters), len(gone_clusters),
                       verdict_changed, events)

    return {
        'has_previous': True,
        'previous_id': previous.get('id'),
        'previous_created_at': previous.get('created_at'),
        'previous_verdict': previous.get('verdict'),
        'verdict_changed': verdict_changed,
        'verdict': {'from': previous.get('verdict'), 'to': current.get('verdict')},
        'events': events,
        'severity': severity_change,
        'clusters': {
            'common': len(cur_clusters) - len(new_clusters),
            'new': len(new_clusters),
            'gone': len(gone_clusters),
        },
        'new_clusters': [_slim(c) for c in new_clusters[:MAX_ITEMS]],
        'gone_clusters': [_slim(c) for c in gone_clusters[:MAX_ITEMS]],
        'louder_clusters': [_slim(c) for c in louder[:MAX_ITEMS]],
        'correlations': {
            'new': len(new_corr),
            'gone': len(gone_corr),
            'new_pairs': new_corr[:MAX_ITEMS],
            'gone_pairs': gone_corr[:MAX_ITEMS],
        },
        'sources': {
            'ok_before': previous.get('sources_ok'),
            'ok_now': current.get('sources_ok'),
            'failed_before': previous.get('sources_failed'),
            'failed_now': current.get('sources_failed'),
        },
        'summary': summary,
    }


def _summary(previous, current, new_count, gone_count, verdict_changed, events):
    parts = []
    if verdict_changed:
        parts.append(f'verdict {previous.get("verdict")} -> {current.get("verdict")}')
    if new_count or gone_count:
        parts.append(f'{new_count} new signature(s), {gone_count} gone')
    if events.get('delta'):
        pct = events.get('pct')
        change = f'{events["delta"]:+,.0f} events'
        if pct is not None:
            change += f' ({pct:+.0f}%)'
        parts.append(change)
    if not parts:
        parts.append('no material change')
    return '; '.join(parts)
