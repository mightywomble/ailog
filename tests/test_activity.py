"""The activity strip: what the app is doing, and that it says so.

Two jobs are slow enough to look like a hang -- collecting metrics from every
host on a cold start, and rescanning every image on a host against its registry
-- so both report progress. These tests pin the endpoint's shape, the maths the
strip draws, and the promise that polling it is free (no SSH, no database).
"""

import os
import re


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, 'static')
TEMPLATES = os.path.join(ROOT, 'templates')


def _read(*parts):
    with open(os.path.join(*parts), encoding='utf-8') as handle:
        return handle.read()


# ------------------------------------------------------------------ backend --


def test_activity_endpoint_is_cheap_and_empty_when_idle(client):
    body = client.get('/api/activity').get_json()
    assert body['success'] is True
    assert body['metrics'] is None
    assert body['docker'] is None
    assert 'ts' in body


def test_metrics_collection_reports_host_by_host_progress():
    from metrics import routes as metrics

    metrics._progress_begin(4)
    metrics._progress_step('swarm-worker1')
    metrics._progress_step(finished=True)
    metrics._progress_step('casaos')

    row = metrics.activity()
    assert row['active'] is True
    assert (row['done'], row['total']) == (1, 4)
    assert row['current'] == 'casaos'
    assert row['elapsed'] >= 0

    metrics._progress_end()
    assert metrics.activity() is None


def test_the_collection_round_wraps_every_host():
    """No host may finish without incrementing, or the bar lies."""
    source = _read(os.path.join(ROOT, 'metrics', 'routes.py'))
    round_block = source[source.index('def collect_servers'):]
    round_block = round_block[:round_block.index('results.extend(extra)')]
    assert '_progress_begin(len(hosts))' in round_block
    assert "finally:" in round_block
    assert '_progress_step("", finished=True)' in round_block.replace("'", '"')
    assert '_progress_end()' in round_block


def test_the_docker_scan_reports_progress_and_bounds_itself(monkeypatch):
    import types
    import dockermon.updates as dupdates

    # The coordinator must not actually run: this asserts the state it reports
    # while the round is in flight, and a real thread would finish first.
    monkeypatch.setattr(dupdates, 'stale', lambda key, max_age=0: True)
    monkeypatch.setattr(dupdates.threading, 'Thread',
                        lambda *a, **k: types.SimpleNamespace(start=lambda: None))
    dupdates.clear()
    queued = dupdates.scan_async(None, ['db-1', 'db-2', 'db-3', 'db-4'])
    assert queued == ['db-1', 'db-2', 'db-3', 'db-4']
    assert dupdates.SCAN_THREADS == 3          # three at a time, not one per host
    row = dupdates.activity()
    assert row['active'] is True
    assert row['total'] == 4
    assert row['host'] == 'db-1'
    dupdates.clear()
    assert dupdates.activity() is None


def test_the_strip_endpoint_never_touches_a_host_or_the_database():
    source = _read(os.path.join(ROOT, 'metrics', 'routes.py'))
    block = source[source.index("def api_activity"):]
    block = block[:block.index('@metrics_bp.get')]
    body = block.split(chr(34) * 3, 2)[-1]        # skip the docstring
    assert 'ssh' not in body.lower()
    assert 'query' not in body.lower()
    assert 'servers_payload' not in body


# ------------------------------------------------------------------ frontend --


def _strip_js():
    return _read(STATIC, 'js', 'activity.js')


def _strip_css():
    css = _read(STATIC, 'css', 'ui.css')
    return css[css.index('.activity-strip {'):]


def test_the_strip_says_what_and_how_far():
    js = _strip_js()
    assert "fetch('/api/activity'" in js
    # both jobs are named, not just a spinner
    assert 'Collecting host metrics' in _read(TEMPLATES, 'partials', 'activity-strip.html')
    assert 'Scanning containers for updates' in _read(TEMPLATES, 'partials', 'activity-strip.html')
    # done / total drives the bar, and the host being contacted is shown
    assert 'of ${total} hosts' in js
    assert 'contacting' in js and 'checking' in js


def test_the_strip_hides_when_idle_and_backs_off():
    js = _strip_js()
    assert "classList.toggle('hidden', !active)" in js
    assert 'ACTIVE_POLL_MS = 1500' in js
    assert 'IDLE_POLL_MS = 8000' in js
    # a hidden tab must not poll while a round is running
    assert 'document.hidden' in js


def test_the_bar_is_an_indeterminate_sweep_until_it_has_a_total():
    js = _strip_js()
    assert "fill.dataset.indeterminate = '1'" in js
    assert "delete fill.dataset.indeterminate" in js
    css = _strip_css()
    assert '.activity-fill[data-indeterminate]' in css
    # no hard-coded colours: the strip follows the theme tokens
    assert not re.search(r'#[0-9a-fA-F]{3,8}\b', css)


def test_the_strip_is_on_the_page():
    html = _read(TEMPLATES, 'index.html')
    assert 'partials/activity-strip.html' in html
    assert 'activity.js' in _read(STATIC, 'js', 'main.js')
