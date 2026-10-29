"""Source discovery, ranking and the per-kind cap."""
import pytest

from serverreport import collect


def src(kind, name, **kw):
    base = {'kind': kind, 'name': name, 'key': f'{kind}:{name}', 'label': name}
    base.update(kw)
    return base


# ----------------------------------------------------------------- the cap --

def test_under_the_cap_keeps_everything():
    sources = [src('file', f'f{i}') for i in range(5)]
    selected, dropped = collect.select_sources(sources, 10)
    assert len(selected) == 5
    assert dropped == {}


def test_files_cannot_starve_journal_and_docker():
    """The old behaviour took the first N, which on db-11 meant files only."""
    sources = ([src('file', f'f{i}') for i in range(300)] +
               [src('journal', f'j{i}.service') for i in range(60)] +
               [src('docker', f'd{i}') for i in range(40)])
    selected, dropped = collect.select_sources(sources, 120)

    kinds = {}
    for source in selected:
        kinds[source['kind']] = kinds.get(source['kind'], 0) + 1

    assert len(selected) == 120
    assert kinds['file'] > 0 and kinds['journal'] > 0 and kinds['docker'] > 0
    assert kinds['journal'] >= 20      # its reserved share (30%)
    assert kinds['docker'] >= 20
    assert dropped['file'] == 300 - kinds['file']


def test_cap_is_exact_when_there_is_plenty_to_choose_from():
    sources = ([src('file', f'f{i}') for i in range(100)] +
               [src('journal', f'j{i}') for i in range(100)])
    selected, _ = collect.select_sources(sources, 50)
    assert len(selected) == 50


def test_unused_share_overflows_to_other_kinds():
    sources = ([src('file', f'f{i}') for i in range(200)] +
               [src('docker', f'd{i}') for i in range(5)])
    selected, _ = collect.select_sources(sources, 40)
    kinds = [s['kind'] for s in selected]
    assert kinds.count('docker') == 5      # all of them fit
    assert kinds.count('file') == 35       # the rest goes to files


def test_single_kind_still_fills_the_cap():
    sources = [src('file', f'f{i}') for i in range(10)]
    selected, dropped = collect.select_sources(sources, 3)
    assert len(selected) == 3
    assert dropped == {'file': 7}


def test_discovery_order_is_preserved():
    sources = [src('journal', 'j1'), src('file', 'f1'), src('journal', 'j2')]
    selected, _ = collect.select_sources(sources, 2)
    assert [s['name'] for s in selected] == [s['name'] for s in sources if s in selected]
    # the highest priority of each kind wins: j1 and f1
    assert {s['name'] for s in selected} == {'j1', 'f1'}


def test_zero_cap_means_no_reduction():
    sources = [src('file', 'a'), src('file', 'b')]
    selected, dropped = collect.select_sources(sources, 0)
    assert len(selected) == 2
    assert dropped == {}


def test_default_cap_is_raised_from_60():
    assert collect.MAX_SOURCES >= 100


# ------------------------------------------------------------ journal rank --

def test_journal_activity_ranks_units(monkeypatch, ctx):
    class Res:
        stdout = ('   77 _SYSTEMD_UNIT="systemd-logind.service"\n'
                  '   65 _SYSTEMD_UNIT="ssh.service"\n'
                  '    2 _SYSTEMD_UNIT="cron.service"\n'
                  'garbage line\n')

    class FakeApp:
        def execute_command(self, host_key, cmd, timeout=None):
            assert 'journalctl' in cmd
            assert '_SYSTEMD_UNIT' in cmd
            return Res()

    monkeypatch.setattr(collect, '_app', lambda: FakeApp())
    counts = collect._journal_activity('local', None)
    assert counts['systemd-logind.service'] == 77
    assert counts['ssh.service'] == 65
    assert len(counts) == 3


def test_journal_activity_failure_is_silent(monkeypatch, ctx):
    class FakeApp:
        def execute_command(self, *a, **kw):
            raise RuntimeError('ssh down')

    monkeypatch.setattr(collect, '_app', lambda: FakeApp())
    assert collect._journal_activity('local', None) == {}


def test_journal_activity_includes_the_window(monkeypatch, ctx):
    seen = {}

    class Res:
        stdout = ''

    class FakeApp:
        def execute_command(self, host_key, cmd, timeout=None):
            seen['cmd'] = cmd
            return Res()

    monkeypatch.setattr(collect, '_app', lambda: FakeApp())
    import datetime
    start = datetime.datetime(2026, 10, 29, 10, 0, tzinfo=datetime.timezone.utc)
    collect._journal_activity('local', start)
    assert '--since @' in seen['cmd']


# ------------------------------------------------------------- window clamp --

@pytest.mark.parametrize('asked,expected', [
    (15, 15), (120, 120), (1440, 1440), (7, 7), (99999, 1440), (0, 120),
])
def test_window_clamping(asked, expected):
    assert collect.clamp_window(asked) == expected
