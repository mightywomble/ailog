"""Assemble the evidence pack that is actually sent to the model.

The pack is deliberately compact plain text rather than JSON: it is roughly 30%
cheaper in tokens and models read log-shaped text more reliably than nested
structures. Everything in here has already been reduced by ``normalize`` and
``correlate``, so the pack size is bounded by the number of *clusters*, not by
the number of log lines.
"""
import os

MAX_PACK_TOKENS = int(os.environ.get('AILOG_REPORT_MAX_TOKENS', '12000') or 12000)
MAX_CLUSTERS = 45
MAX_BURSTS = 12
MAX_GAPS = 8
MAX_CORRELATIONS = 15
SAMPLE_CHARS = 180

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


def build_pack(host_label, norm, corr, collect_meta, containers):
    """Render the evidence pack text."""
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

    counts = norm.get('severity_counts') or {}
    lines.append(
        f"EVENTS: {sum(counts.values())} in window | "
        f"crit {counts.get('crit', 0)} error {counts.get('error', 0)} "
        f"warn {counts.get('warn', 0)} info {counts.get('info', 0)}"
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
        for c in clusters[:MAX_CLUSTERS]:
            first = _iso(c.get('first_ts'))
            lines.append(
                f"{c['label']} | {SEV_LABEL.get(c['sev'], 'INFO')} | {c['count']} | "
                f"{first} | {_trim(c['sig'], 160)}"
            )
            for sample in (c.get('samples') or [])[:1]:
                lines.append(f"    e.g. {_trim(sample)}")

    # --- correlations -------------------------------------------------------
    correlations = corr.get('correlations') or []
    if correlations:
        lines.append('')
        lines.append('--- CROSS-SOURCE CORRELATIONS (lift over chance) ---')
        for p in correlations[:MAX_CORRELATIONS]:
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
        for b in bursts[:MAX_BURSTS]:
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
        for g in gaps[:MAX_GAPS]:
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
        lines.append('with events: ' + ', '.join(ok[:25]))
    if quiet:
        lines.append('no events in window: ' + ', '.join(quiet[:20]))
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
