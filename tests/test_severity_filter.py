"""Tests for the severity filter on server reports.

The feature has two halves and both are tested here:

* the **source-side** pre-filter (`collect.build_command`) — journald's native
  ``--priority`` where it is exact, and a shared ``grep`` everywhere else;
* the **authoritative** filter (`normalize.normalize_source`), which is what
  actually decides what reaches the model.

The regex tables are shared, so a test asserts the grep pattern really matches
the same lines the classifier would label.
"""
import datetime
import re

import pytest

from serverreport import collect, normalize, severity


NOW = datetime.datetime(2026, 10, 29, 12, 0, tzinfo=datetime.timezone.utc)

FILE_SRC = {'key': 'file:/var/log/syslog', 'kind': 'file', 'name': 'syslog',
            'label': 'syslog', 'path': '/var/log/syslog'}
GZ_SRC = {'key': 'file:/var/log/syslog.1.gz', 'kind': 'file', 'name': 'syslog.1.gz',
          'label': 'syslog.1.gz', 'path': '/var/log/syslog.1.gz'}
JOURNAL_SRC = {'key': 'journal:ssh.service', 'kind': 'journal', 'name': 'ssh.service',
               'label': 'ssh.service', 'unit': 'ssh.service'}
DOCKER_SRC = {'key': 'docker:web.1', 'kind': 'docker', 'name': 'web.1',
              'label': 'web.1'}


# ---------------------------------------------------------------------------
# selection parsing
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('raw', [None, '', [], (), set(), 'all', ['all'], ['ALL'],
                                 ['crit', 'error', 'warn'], 'debug'])
def test_everything_else_means_no_filter(raw):
    assert severity.parse(raw) == frozenset()


@pytest.mark.parametrize('raw,expected', [
    ('crit', {'crit'}),
    ('Critical', {'crit'}),
    ('critical,errors', {'crit', 'error'}),
    (['warning'], {'warn'}),
    (['err', 'WARN'], {'error', 'warn'}),
    ('crit;warn', {'crit', 'warn'}),
])
def test_parse_aliases(raw, expected):
    assert severity.parse(raw) == frozenset(expected)


def test_parse_ignores_unknown_tokens():
    assert severity.parse(['error', 'nonsense']) == frozenset({'error'})


def test_describe_is_ordered_most_severe_first():
    assert severity.describe({'warn', 'crit'}) == 'Critical + Warnings'
    assert severity.describe(set()) == 'all severities'


@pytest.mark.parametrize('levels,expected', [
    (frozenset({'crit'}), (2, True)),                 # --priority=2 is exactly crit+
    (frozenset({'crit', 'error'}), (3, True)),        # 3 and above == crit+error
    (frozenset({'error', 'warn'}), (4, True)),        # 4 and above == crit+error+warn? no
    (frozenset({'error'}), (3, False)),               # also returns crit
    (frozenset({'warn'}), (4, False)),                # also returns crit+error
    (frozenset({'crit', 'warn'}), (4, False)),        # everything
    (frozenset(), (None, True)),
])
def test_journal_priority_exactness(levels, expected):
    # NOTE: error+warn selects {3,4}; --priority=4 also admits crit, so the
    # "exact" answer there is False and is asserted separately below.
    if levels == frozenset({'error', 'warn'}):
        expected = (4, False)
    assert severity.journal_priority(levels) == expected


def test_grep_pattern_has_no_non_capturing_groups():
    """GNU grep's ERE parser rejects ``(?:``: it warns "? at start of
    expression" and silently changes the meaning of the pattern (the
    ``(?:ed|ure|ing)`` alternations stop grouping). The emitted pattern must use
    plain groups only."""
    pattern = severity.grep_pattern({'crit', 'error', 'warn'})
    assert '(?:' not in pattern
    assert '(?i)' not in pattern and '\\d{' not in pattern
    compiled = re.compile(pattern.replace('[[:space:]]', r'\s'), re.I)
    assert compiled.search('ERROR: broken pipe')
    assert compiled.search('Failed to start nginx')


@pytest.mark.parametrize('line,level', [
    ('kernel panic - not syncing', 'crit'),
    ('Out of memory: Killed process 42', 'crit'),
    ('error: connection refused', 'error'),
    ('Failed to start nginx.service', 'error'),
    ('Traceback (most recent call last):', 'error'),
    ('warning: deprecated option', 'warn'),
    ('session opened for user david', None),
])
def test_grep_pattern_agrees_with_the_classifier(line, level):
    """The pre-filter must not be stricter than the authoritative classifier."""
    import serverreport.normalize as n

    if level is None:
        return
    pattern = severity.grep_pattern({level})
    assert re.search(pattern.replace('[[:space:]]', r'\s'), line, re.I), line
    assert n.classify_severity(line) == {'crit': n.SEV_CRIT, 'error': n.SEV_ERROR,
                                        'warn': n.SEV_WARN}[level]


# ---------------------------------------------------------------------------
# source-side commands
# ---------------------------------------------------------------------------

def test_unfiltered_commands_are_unchanged():
    assert collect.build_command(FILE_SRC, NOW, NOW, set()) == \
        f'sudo tail -n {collect.FILE_LINE_CAP} /var/log/syslog 2>/dev/null'
    assert collect.build_command(JOURNAL_SRC, NOW, NOW, set()).count('--priority') == 0
    assert collect.build_command(DOCKER_SRC, NOW, NOW, set()).startswith('if sudo -n docker')


def test_gz_files_still_use_zcat_when_filtered():
    cmd = collect.build_command(GZ_SRC, NOW, NOW, {'error'})
    assert cmd.startswith('sudo zcat /var/log/syslog.1.gz 2>/dev/null | tail -n')
    assert 'grep -aiE' in cmd


def test_file_filter_widens_the_scanned_tail_and_keeps_the_newest_matches():
    cmd = collect.build_command(FILE_SRC, NOW, NOW, {'error'})
    assert f'tail -n {collect.FILE_SCAN_CAP}' in cmd        # scan wide...
    assert f'| tail -n {collect.FILE_LINE_CAP}' in cmd      # ...keep the newest
    assert 'grep -aiE' in cmd and '--no-group-separator' in cmd


def test_journal_uses_native_priority_when_exact():
    cmd = collect.build_command(JOURNAL_SRC, NOW, NOW, {'crit', 'error'})
    assert '--priority=3' in cmd
    assert 'grep' not in cmd


def test_journal_adds_grep_when_priority_would_over_fetch():
    cmd = collect.build_command(JOURNAL_SRC, NOW, NOW, {'warn'})
    assert '--priority=4' in cmd
    assert 'grep -aiE' in cmd


def test_journal_scan_cap_is_wider_when_filtered():
    unfiltered = collect.build_command(JOURNAL_SRC, NOW, NOW, set())
    filtered = collect.build_command(JOURNAL_SRC, NOW, NOW, {'crit'})
    assert f'-n {collect.JOURNAL_LINE_CAP}' in unfiltered
    assert f'-n {collect.JOURNAL_SCAN_CAP}' in filtered


def test_docker_filter_groups_the_compound_if_before_piping():
    cmd = collect.build_command(DOCKER_SRC, NOW, NOW, {'error'})
    assert cmd.startswith('{ if sudo -n docker')
    assert '; } | grep -aiE' in cmd


def test_build_command_rejects_unknown_kind():
    with pytest.raises(ValueError):
        collect.build_command({'kind': 'snmp'}, NOW, NOW, {'error'})


# ---------------------------------------------------------------------------
# authoritative filtering in the normaliser
# ---------------------------------------------------------------------------

SYSLOG = '\n'.join([
    '2026-10-29T11:00:00+00:00 host app[1]: session opened for user david',
    '2026-10-29T11:01:00+00:00 host app[1]: ERROR: upstream connection refused',
    '  File "/srv/app/x.py", line 12, in run',
    '2026-10-29T11:02:00+00:00 host app[1]: warning: deprecated option ignored',
    '2026-10-29T11:03:00+00:00 host app[1]: kernel panic - not syncing',
    '2026-10-29T11:04:00+00:00 host app[1]: GET /health 200',
])


@pytest.mark.parametrize('levels,expected_msgs,filtered', [
    (None, 5, 0),                     # 6 lines, one is a continuation
    (frozenset({'error'}), 1, 4),     # the traceback rides along with the error
    # With a crit-only filter the error line is dropped, so the traceback has no
    # parent to attach to and is counted as filtered-out text (5 of 6 lines).
    (frozenset({'crit'}), 1, 5),
    (frozenset({'warn'}), 1, 5),
    (frozenset({'crit', 'error'}), 2, 3),
])
def test_normalize_source_keeps_only_selected_severities(levels, expected_msgs, filtered):
    events, stats = normalize.normalize_source(
        FILE_SRC, SYSLOG, NOW - datetime.timedelta(hours=2), NOW, sev_levels=levels)
    assert len(events) == expected_msgs, [e['msg'] for e in events]
    assert stats['filtered_out'] == filtered


def test_continuations_of_dropped_lines_do_not_attach_to_kept_events():
    text = '\n'.join([
        '2026-10-29T11:00:00+00:00 h a[1]: error: first failure',
        '2026-10-29T11:00:01+00:00 h a[1]: session opened for user root',
        '  File "trace.py", line 3, in boom',
    ])
    events, _ = normalize.normalize_source(
        FILE_SRC, text, NOW - datetime.timedelta(hours=2), NOW, sev_levels=frozenset({'error'}))
    assert len(events) == 1
    # The traceback line belonged to the *dropped* info line: it must not have
    # been glued onto the surviving error event.
    assert 'trace.py' not in events[0]['msg']


def test_normalize_all_reports_what_was_filtered():
    collected = [{'source': FILE_SRC, 'ok': True, 'status': 'ok', 'text': SYSLOG}]
    norm = normalize.normalize_all(collected, NOW - datetime.timedelta(hours=2), NOW,
                                   sev_levels=frozenset({normalize.SEV_ERROR}))
    assert norm['severity_filter']['active'] is True
    assert norm['severity_filter']['levels'] == ['error']
    assert norm['severity_filter']['events_kept'] == 1
    assert norm['severity_filter']['events_filtered'] == 4
    assert norm['severity_filter']['lines_kept'] == 1


def test_normalize_all_without_filter_is_untouched():
    collected = [{'source': FILE_SRC, 'ok': True, 'status': 'ok', 'text': SYSLOG}]
    norm = normalize.normalize_all(collected, NOW - datetime.timedelta(hours=2), NOW)
    assert norm['severity_filter']['active'] is False
    assert norm['severity_filter']['events_filtered'] == 0
    assert len(norm['events']) == 5


# ---------------------------------------------------------------------------
# collection plumbing
# ---------------------------------------------------------------------------

def test_collect_host_logs_parses_severities_from_strings(ctx, monkeypatch):
    """The route hands over whatever the client sent; collect parses it."""
    seen = {}

    def fake_collect_one(host_key, source, ws, we, budget=None, sev_levels=None):
        seen['levels'] = sev_levels
        return {'source': source, 'ok': True, 'status': 'ok', 'text': '', 'lines': 0,
                'bytes': 0, 'error': None, 'duration_ms': 0}

    monkeypatch.setattr(collect, 'collect_one', fake_collect_one)
    monkeypatch.setattr(collect, 'list_sources',
                        lambda *a, **k: ([dict(FILE_SRC)], []))
    result = collect.collect_host_logs('host', severities=['Critical', 'errors'],
                                       include_journal=False, include_docker=False)
    assert seen['levels'] == frozenset({'crit', 'error'})
    assert result['severity_filter']['active'] is True
    assert result['severity_filter']['levels'] == ['crit', 'error']
    # The pre-filter actually used is recorded for the report coverage.
    assert result['severity_filter']['source_prefilter']['journal'].startswith(
        'journalctl --priority=3')


def test_collect_host_logs_without_filter_reports_inactive(ctx, monkeypatch):
    monkeypatch.setattr(collect, 'collect_one',
                        lambda *a, **k: {'source': FILE_SRC, 'ok': True, 'status': 'ok',
                                         'text': '', 'lines': 0, 'bytes': 0,
                                         'error': None, 'duration_ms': 0})
    monkeypatch.setattr(collect, 'list_sources', lambda *a, **k: ([dict(FILE_SRC)], []))
    result = collect.collect_host_logs('host', include_journal=False, include_docker=False)
    assert result['severity_filter']['active'] is False
    assert result['severity_filter']['levels'] == []


# ---------------------------------------------------------------------------
# route helpers
# ---------------------------------------------------------------------------

def test_bundle_cache_key_does_not_mix_filters(ctx):
    from serverreport import routes as rr

    base = ('host', 120, True, True, True, False)
    assert rr._bundle_key(*base) != rr._bundle_key(*base, frozenset({'error'}))
    assert rr._bundle_key(*base, frozenset({'error'})) != \
        rr._bundle_key(*base, frozenset({'crit'}))
    # Order of the selection must not matter.
    assert rr._bundle_key(*base, frozenset({'crit', 'error'})) == \
        rr._bundle_key(*base, frozenset({'error', 'crit'}))
    # "all" is the same as unfiltered.
    assert rr._bundle_key(*base, frozenset()) == rr._bundle_key(*base)


def test_scope_note_states_the_filter(ctx):
    from serverreport import routes as rr

    assert rr._scope_note(True, True, True, False).endswith('running only')
    note = rr._scope_note(True, True, True, False, frozenset({'error', 'crit'}))
    assert 'severity filter: Critical + Errors only' in note


def test_sev_level_mapping_round_trips(ctx):
    from serverreport import routes as rr

    names = frozenset({'crit', 'warn'})
    assert rr.sev_names_for(rr.sev_levels_for(names)) == names
    assert rr.sev_levels_for(['nonsense']) == frozenset()


def test_stored_filter_merges_collector_and_normalizer(ctx):
    from serverreport import routes as rr

    collected = {'severity_filter': {'source_prefilter': {'journal': 'journalctl --priority=3'}}}
    norm = {'severity_filter': {'active': True, 'levels': ['crit', 'error'],
                                'events_kept': 10, 'events_filtered': 2}}
    block = rr._stored_filter(collected, norm)
    assert block['label'] == 'Critical + Errors'
    assert block['source_prefilter']['journal'].endswith('--priority=3')


def test_stored_filter_is_inactive_by_default(ctx):
    from serverreport import routes as rr

    block = rr._stored_filter({}, {'severity_filter': {'active': False, 'levels': []}})
    assert block['active'] is False
    assert block['label'] == 'all severities'


def test_preflight_accepts_a_severity_selection(client, monkeypatch):
    """The endpoints must not 500 on the new field, and must pass it through."""
    captured = {}

    def fake_prepare(host_key, host_label, window, i_f, i_j, i_d, i_s, **kwargs):
        captured['severities'] = kwargs.get('severities')
        norm = {'events': [], 'clusters': [],
                'severity_counts': {'crit': 0, 'error': 0, 'warn': 0, 'info': 0},
                'source_stats': [],
                'severity_filter': {'active': True, 'levels': ['error'],
                                    'events_kept': 0, 'events_filtered': 0}}
        return {'collected': {'sources': [], 'severity_filter': {}}, 'norm': norm,
                'corr': {'correlations': [], 'timeline': [], 'gaps': [], 'bursts': [],
                         'window': {'start': None, 'end': None}},
                'containers': [], 'ok_sources': [], 'empty_sources': [],
                'failed_sources': [], 'window_start': NOW, 'window_end': NOW,
                'severities': kwargs.get('severities')}

    from serverreport import routes as rr
    monkeypatch.setattr(rr, 'prepare_bundle', fake_prepare)

    res = client.post('/serverreport/preflight',
                      json={'host_key': 'db-1', 'severities': ['error', 'critical']})
    assert res.status_code == 200, res.data
    body = res.get_json()
    assert captured['severities'] == frozenset({'crit', 'error'})
    assert body['filter']['active'] is True
    assert 'severity filter' in body['scope_note']


# ---------------------------------------------------------------------------
# self-observation guards
# ---------------------------------------------------------------------------

def test_journal_unit_denylist_drops_the_units_the_filter_would_report_on():
    """``sudo journalctl -u emergency.service`` is logged by sudo into auth.log
    and the word "emergency" classifies as CRIT, so collecting that unit makes
    the report report on itself."""
    stdout = '\n'.join(['ssh.service', 'emergency.service', 'cron.service',
                        'rescue.service', ''])
    assert collect._usable_units(stdout) == ['ssh.service', 'cron.service']


def test_usable_units_is_capped():
    stdout = '\n'.join(f'unit{i}.service' for i in range(200))
    assert len(collect._usable_units(stdout)) == collect.MAX_JOURNAL_UNITS


def test_grep_prefilter_is_case_insensitive():
    """classify_severity is case-insensitive; a case-sensitive grep would drop
    "ERROR:"/"Failed" lines before the classifier ever saw them."""
    cmd = collect.build_command(FILE_SRC, NOW, NOW, {'error'})
    assert 'grep -aiE' in cmd
