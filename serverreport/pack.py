"""Assemble the evidence pack that is actually sent to the model.

The pack is deliberately compact plain text rather than JSON: it is roughly 30%
cheaper in tokens and models read log-shaped text more reliably than nested
structures. Everything in here has already been reduced by ``normalize`` and
``correlate``, so the pack size is bounded by the number of *clusters*, not by
the number of log lines.
"""
import os

from . import severity

MAX_PACK_TOKENS = int(os.environ.get('AILOG_REPORT_MAX_TOKENS', '12000') or 12000)
MAX_CLUSTERS = 45
MAX_BURSTS = 12
MAX_GAPS = 8
MAX_CORRELATIONS = 15
SAMPLE_CHARS = 180

# How much of the tail each depth includes. Depth has to change what is *sent*,
# not just the budget: a bigger budget with a 45-cluster cap sends nothing more.
PACK_LIMITS = {
    1: {'clusters': 15, 'bursts': 5, 'gaps': 4, 'correlations': 6, 'samples': 0, 'coverage': 12},
    2: {'clusters': 28, 'bursts': 8, 'gaps': 6, 'correlations': 10, 'samples': 1, 'coverage': 20},
    3: {'clusters': 45, 'bursts': 12, 'gaps': 8, 'correlations': 15, 'samples': 1, 'coverage': 25},
    4: {'clusters': 90, 'bursts': 18, 'gaps': 12, 'correlations': 20, 'samples': 2, 'coverage': 35},
    5: {'clusters': 180, 'bursts': 30, 'gaps': 16, 'correlations': 30, 'samples': 2, 'coverage': 50},
}


def limits_for(depth):
    try:
        depth = int(depth)
    except (TypeError, ValueError):
        depth = 3
    return PACK_LIMITS.get(depth, PACK_LIMITS[3])

SEV_LABEL = {4: 'CRIT', 3: 'ERROR', 2: 'WARN', 1: 'INFO'}


def estimate_tokens(text):
    """Cheap token estimate (~4 chars/token for English + log noise)."""
    return max(1, len(text or '') // 4)


def _trim(text, limit=SAMPLE_CHARS):
    text = (text or '').replace('\n', ' ⏎ ')
    return text[:limit] + ('…' if len(text) > limit else '')


def _coverage(norm):
    """One line per source, so the model knows what it is *not* seeing.

    Empty and failed are deliberately distinct: a quiet container is not a
    logging fault and must not be reported as one.
    """
    ok, failed, quiet = [], [], []
    for stat in norm.get('source_stats') or []:
        label = stat.get('label') or stat.get('key')
        if stat.get('status') == 'error' or stat.get('error'):
            failed.append(f"{label} ({stat.get('error')})")
        elif not stat.get('kept'):
            quiet.append(label)
        else:
            ok.append(f"{label}:{stat['kept']}")
    return ok, failed, quiet


def build_pack(host_label, norm, corr, collect_meta, containers, depth=None):
    """Render the evidence pack text."""
    limits = limits_for(depth)
    max_clusters = limits['clusters']
    max_bursts = limits['bursts']
    max_gaps = limits['gaps']
    max_correlations = limits['correlations']
    sample_count = limits['samples']
    coverage_limit = limits['coverage']

    window = corr.get('window') or {}
    lines = []

    lines.append('=== SERVER LOG EVIDENCE PACK ===')
    lines.append(
        f"HOST: {host_label} | WINDOW: {window.get('start')} .. {window.get('end')} "
        f"({collect_meta.get('window_minutes')}m)"
    )

    sources = collect_meta.get('sources') or []
    ok_count = sum(1 for s in sources if s.get('ok'))
    lines.append(
        f"SOURCES: {len(sources)} in scope, {ok_count} returned data, "
        f"{len(sources) - ok_count} empty/failed"
    )
    if collect_meta.get('truncated'):
        lines.append('TRUNCATED: source cap or byte budget reached — this is a partial view.')
    if depth:
        lines.append(
            f'DEPTH: level {int(depth)} — showing up to {max_clusters} clusters, '
            f'{max_correlations} correlations, {max_bursts} bursts.'
        )

    counts = norm.get('severity_counts') or {}
    lines.append(
        f"EVENTS: {sum(counts.values())} in window | "
        f"crit {counts.get('crit', 0)} error {counts.get('error', 0)} "
        f"warn {counts.get('warn', 0)} info {counts.get('info', 0)}"
    )

    # The model must know the view is filtered, or it will read the missing
    # INFO lines as "nothing else happened" and invent a coverage gap.
    filt = norm.get('severity_filter') or {}
    if filt.get('active'):
        levels = filt.get('levels') or []
        detail = []
        if filt.get('events_kept') is not None:
            detail.append(f"{filt['events_kept']:,} relevant events kept")
        if filt.get('events_filtered'):
            detail.append(f"{filt['events_filtered']:,} context lines dropped")
        suffix = f" ({', '.join(detail)})" if detail else ''
        lines.append(f"FILTER: severity = {severity.describe(levels)} only{suffix}")
        pre = filt.get('source_prefilter') or {}
        if pre:
            lines.append('FILTER AT SOURCE: ' + '; '.join(
                f'{kind} {how}' for kind, how in sorted(pre.items())))
        lines.append(
            'FILTER NOTE: the operator asked for this severity subset. Lines outside it were '
            'discarded before analysis; their absence is NOT evidence that a source is healthy, '
            'and correlation baselines are computed on the filtered subset only.'
        )

    # --- containers ---------------------------------------------------------
    if containers:
        lines.append('')
        lines.append('--- CONTAINERS ---')
        for c in containers[:25]:
            flags = []
            if c.get('restarts'):
                flags.append(f"restarts={c['restarts']}")
            if c.get('oom_killed'):
                flags.append('OOMKilled')
            if (c.get('exit_code') or 0) and (c.get('status') or '').lower() != 'running':
                flags.append(f"exit={c['exit_code']}")
            suffix = (' | ' + ' '.join(flags)) if flags else ''
            lines.append(f"{c.get('name')} | {c.get('image')} | {c.get('status')}{suffix}")

    # --- clusters -----------------------------------------------------------
    clusters = norm.get('clusters') or []
    if clusters:
        lines.append('')
        lines.append('--- TOP CLUSTERS (severity, frequency) ---')
        lines.append('source | sev | count | first_seen | signature')
        for c in clusters[:max_clusters]:
            first = _iso(c.get('first_ts'))
            lines.append(
                f"{c['label']} | {SEV_LABEL.get(c['sev'], 'INFO')} | {c['count']} | "
                f"{first} | {_trim(c['sig'], 160)}"
            )
            for sample in (c.get('samples') or [])[:sample_count]:
                lines.append(f"    e.g. {_trim(sample)}")

    # --- correlations -------------------------------------------------------
    correlations = corr.get('correlations') or []
    if correlations:
        lines.append('')
        lines.append('--- CROSS-SOURCE CORRELATIONS (lift over chance) ---')
        for p in correlations[:max_correlations]:
            lag = p.get('lag_seconds')
            lag_txt = f"{lag:+.1f}s" if isinstance(lag, (int, float)) else 'n/a'
            lines.append(
                f"lift {p['lift']} x{p['coincidences']} lag {lag_txt} | "
                f"{p['a']['label']}: {_trim(p['a']['sig'], 90)}"
            )
            lines.append(f"    <-> {p['b']['label']}: {_trim(p['b']['sig'], 90)}")

    # --- bursts -------------------------------------------------------------
    bursts = corr.get('bursts') or []
    if bursts:
        lines.append('')
        lines.append('--- BURSTS (above each source\'s own baseline) ---')
        for b in bursts[:max_bursts]:
            lines.append(
                f"{_iso(b['ts'])} | {b['src'].split(':', 1)[-1]} | "
                f"{b['count']} hits in one minute (baseline {b['median']:g}) | "
                f"{_trim(b['sig'], 110)}"
            )

    # --- gaps ---------------------------------------------------------------
    gaps = corr.get('gaps') or []
    if gaps:
        lines.append('')
        lines.append('--- SILENCE / GAPS ---')
        for g in gaps[:max_gaps]:
            if g['kind'] == 'stopped_early':
                lines.append(
                    f"{g['src']} stopped logging {int(g['seconds'] // 60)}m before the window ended"
                )
            else:
                lines.append(
                    f"{g['src']} silent for {int(g['seconds'])}s "
                    f"from {_iso(g['start'])} to {_iso(g['end'])}"
                )

    # --- coverage -----------------------------------------------------------
    ok, failed, quiet = _coverage(norm)
    lines.append('')
    lines.append('--- COVERAGE ---')
    if ok:
        lines.append('with events: ' + ', '.join(ok[:coverage_limit]))
    if quiet:
        lines.append('no events in window: ' + ', '.join(quiet[:coverage_limit]))
    if failed:
        lines.append('collection errors: ' + ', '.join(failed[:15]))
    lines.append('note: sources under "no events in window" produced no output; this is not a fault.')

    lines.append('=== END EVIDENCE PACK ===')
    return '\n'.join(lines)


def _iso(ts):
    import datetime
    if ts is None:
        return 'n/a'
    if isinstance(ts, datetime.datetime):
        ts = ts.timestamp()
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def fit_pack(text, max_tokens=MAX_PACK_TOKENS):
    """Trim a pack to budget, marking clearly that it was trimmed.

    Blind truncation is only used as a last resort; ``correlate`` has already
    dropped the long tail, so hitting this path means the host is extreme.
    """
    if estimate_tokens(text) <= max_tokens:
        return text, False
    keep_chars = max_tokens * 4
    head = text[: int(keep_chars * 0.25)]
    tail = text[-int(keep_chars * 0.75):]
    trimmed = (
        head
        + '\n\n[--- EVIDENCE PACK TRUNCATED TO FIT MODEL CONTEXT ---]\n\n'
        + tail
    )
    return trimmed, True


# ---------------------------------------------------------------------------
# chunking (map/reduce for packs larger than the model can hold)
# ---------------------------------------------------------------------------

def split_pack(text, chunks):
    """Split a pack into roughly equal chunks.

    The header block (host, window, counts) is repeated in every chunk so each
    pass knows what it is looking at. Split points are placed by cumulative
    size and then snapped to a nearby blank line / section marker so a cluster
    entry is not cut in half (snapping is best-effort - a pack with no
    boundaries at all still gets even chunks).
    """
    import bisect

    chunks = max(1, int(chunks or 1))
    if chunks == 1 or not text:
        return [text or '']

    lines = text.splitlines()
    header_end = next((i for i, l in enumerate(lines) if l.startswith('--- ')), min(len(lines), 12))
    header_text = '\n'.join(lines[:header_end]).rstrip()
    body = lines[header_end:]
    if not body:
        return [text]

    def is_boundary(line):
        return (not line.strip()) or line.startswith('--- ') or line.startswith('===')

    cumulative = []
    total = 0
    for line in body:
        total += len(line) + 1
        cumulative.append(total)

    cuts = []
    for k in range(1, chunks):
        goal = total * k / chunks
        idx = min(len(body) - 1, bisect.bisect_left(cumulative, goal))
        snapped = None
        # Only snap within a few lines: hunting further afield collapses several
        # cut points onto the same boundary and produces lopsided chunks.
        for delta in range(0, 4):
            for cand in (idx + delta, idx - delta):
                if 0 < cand < len(body) and is_boundary(body[cand]):
                    snapped = cand
                    break
            if snapped is not None:
                break
        cuts.append(snapped if snapped is not None else idx)

    # Even chunks matter more than clean boundaries: drop duplicate cuts.
    cuts = sorted(set(c for c in cuts if 0 < c < len(body)))
    if not cuts:
        return [text]

    parts, prev = [], 0
    for cut in cuts + [len(body)]:
        segment = body[prev:cut]
        if segment:
            parts.append(segment)
        prev = cut

    out = []
    for idx, part in enumerate(parts, start=1):
        body_text = '\n'.join(part).strip()
        out.append(
            f'{header_text}\n\n[--- PART {idx} of {len(parts)} ---]\n\n'
            f'{body_text}\n=== END EVIDENCE PACK ==='
        )
    return out


def build_reduced_pack(host_label, digests, corr):
    """Assemble the merged pack after per-chunk summarisation."""
    window = (corr or {}).get('window') or {}
    lines = [
        '=== SERVER LOG EVIDENCE PACK (MERGED FROM CHUNK SUMMARIES) ===',
        f"HOST: {host_label} | WINDOW: {window.get('start')} .. {window.get('end')}",
        '',
        'Each PART below is an extracted summary of one slice of the same window.',
        'The slices were cut for context size only - they describe one server,',
        'not separate servers, and events may be mentioned in more than one part.',
        '',
    ]
    total = len(digests or [])
    for idx, digest in enumerate(digests or [], start=1):
        lines.append(f'--- PART {idx} of {total} ---')
        lines.append((digest or '').strip())
        lines.append('')
    lines.append('=== END EVIDENCE PACK ===')
    return '\n'.join(lines)
