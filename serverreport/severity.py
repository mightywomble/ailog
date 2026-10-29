"""Severity selection for server reports.

Why this exists
---------------
A server report on a busy host is dominated by INFO noise: an nginx access log
or a syslog full of "session opened" lines can be 99% of the collected bytes and
almost none of the signal. Selecting *which* severities to analyse is therefore
the cheapest way to shrink the evidence pack — done at the source it also cuts
the bytes that ever cross the SSH channel.

Two filters, deliberately
------------------------
1. **At the source** (`collect.py`), so the saving is real:
   - journald: `journalctl --priority=N` — native, exact when the selection is a
     contiguous "N and above" set, and byte-free when it is not (we then add a
     `grep` to make it exact).
   - files and containers: a single `grep -aE` with the keyword pattern below,
     applied to a *wider* tail than the unfiltered path uses, so sparse errors
     are still found (`tail -n 8000 | grep | tail -n 2000`).
2. **At normalisation** (`normalize.py`), authoritatively. Source-side grep is a
   heuristic over raw text; `classify_severity` is the real classifier. Anything
   the pre-filter let through is dropped here, so the report can never claim a
   severity it was not asked for.

The keyword tables are shared with `normalize.classify_severity` — one source of
truth, so grep and the classifier cannot drift apart.
"""

from __future__ import annotations

# Ordered most severe first: the UI renders them in this order.
LEVELS = ('crit', 'error', 'warn')

LEVEL_LABELS = {'crit': 'Critical', 'error': 'Errors', 'warn': 'Warnings'}

# Accepted spellings (request bodies come from several places: the dialog, the
# schedule scope blob, older clients, and hand-written curl).
_ALIASES = {
    'crit': 'crit', 'critical': 'crit', 'criticial': 'crit', 'criticals': 'crit',
    'emerg': 'crit', 'emergency': 'crit', 'alert': 'crit', 'fatal': 'crit',
    'error': 'error', 'errors': 'error', 'err': 'error',
    'warn': 'warn', 'warning': 'warn', 'warnings': 'warn',
}

# syslog / journald priorities (0 is most severe).
PRIORITY = {'crit': 2, 'error': 3, 'warn': 4}


def parse(selection):
    """Normalise a request value into a frozenset of levels.

    Returns an **empty frozenset** to mean "no filter" (all severities), which
    is both the default and what ``'all'`` maps to. Unknown tokens are ignored
    rather than rejected: an old client sending ``['debug']`` should degrade to
    "no filter", not break the run.
    """
    if selection is None:
        return frozenset()
    if isinstance(selection, str):
        selection = [p for p in selection.replace(';', ',').split(',')]
    if not isinstance(selection, (list, tuple, set, frozenset)):
        return frozenset()

    levels = set()
    for raw in selection:
        token = str(raw or '').strip().lower()
        if not token:
            continue
        if token in ('all', 'any', '*'):
            return frozenset()
        mapped = _ALIASES.get(token)
        if mapped:
            levels.add(mapped)
    # Selecting every level is the same as no filter: keep the run identical to
    # the pre-filter behaviour (and the bundle cache key stable).
    if levels >= set(LEVELS):
        return frozenset()
    return frozenset(levels)


def describe(levels):
    """Human-readable label, e.g. ``'Errors + Critical'`` or ``'all severities'``."""
    levels = frozenset(levels or ())
    if not levels:
        return 'all severities'
    return ' + '.join(LEVEL_LABELS[lvl] for lvl in LEVELS if lvl in levels)


def journal_priority(levels):
    """Return ``(priority, exact)`` for ``journalctl --priority``.

    ``--priority=N`` means "N **and above**", so it is only exact when the
    selection is contiguous from the most severe level down to ``warn``:

    ==================  =========  ======
    selection           priority   exact
    ==================  =========  ======
    crit                2          yes
    crit + error        3          yes
    crit + error + warn *no filter* —
    error               3          no (also returns crit)
    warn                4          no (also returns crit + error)
    error + warn        4          no (also returns crit)
    crit + warn         2          no (returns everything)
    ==================  =========  ======

    In the inexact cases the caller appends a ``grep`` so the transfer is still
    cut down; ``normalize`` then drops the leftovers.
    """
    levels = frozenset(levels or ())
    if not levels:
        return None, True
    # --priority=N keeps priority <= N, i.e. "N and above". The least severe
    # selected level decides N; it is exact only if nothing between the most
    # severe level and N was left out of the selection.
    level = max(PRIORITY[lvl] for lvl in levels)
    exact = all(lvl in levels for lvl in LEVELS if PRIORITY[lvl] <= level)
    return level, exact


def grep_pattern(levels):
    """A GNU/POSIX-ERE pattern matching the selected severities.

    Built from the same keyword tables ``normalize.classify_severity`` uses, so
    the pre-filter and the authority cannot disagree. ``\\s`` is translated to
    ``[[:space:]]`` to stay portable to any POSIX ERE implementation.
    """
    from .normalize import SEVERITY_WORDS, SEV_CRIT, SEV_ERROR, SEV_WARN

    by_level = {SEV_CRIT: 'crit', SEV_ERROR: 'error', SEV_WARN: 'warn'}
    wanted = frozenset(levels or ())
    if not wanted:
        return None

    words = []
    for sev, name in by_level.items():
        if name in wanted:
            words.append(SEVERITY_WORDS[sev])
    if not words:
        return None
    # Plain capturing groups only: GNU grep's ERE parser does not understand
    # ``(?:`` and warns "? at start of expression", silently changing the
    # meaning of the pattern (the ``(?:ed|ure|ing)`` alternations break).
    pattern = r'\b(' + '|'.join(words).replace('(?:', '(') + r')\b'
    return pattern.replace(r'\s', '[[:space:]]')


def summary(levels, lines_kept=None, events_kept=None, events_filtered=None,
            prefilter=None):
    """The dict stored in the report coverage and returned by preflight."""
    levels = frozenset(levels or ())
    data = {
        'active': bool(levels),
        'levels': [lvl for lvl in LEVELS if lvl in levels],
        'label': describe(levels),
        'description': describe(levels),
    }
    if lines_kept is not None:
        data['lines_kept'] = int(lines_kept)
    if events_kept is not None:
        data['events_kept'] = int(events_kept)
    if events_filtered is not None:
        data['events_filtered'] = int(events_filtered)
    if prefilter:
        data['source_prefilter'] = prefilter
    return data
