"""The re-check button, and the bar that was supposed to answer it.

Three separate reasons the progress bar "was gone" from the Docker pane, and
what each one now does instead:

* the per-host re-check tested staleness at 1s and the queue tested it at 30
  minutes, so a press answered ``started: null`` and scanned nothing;
* a manager's re-check goes to the stack list, which reported no progress at
  all - two or three silent seconds behind a placeholder;
* the pane drew its own re-check and the stack panel drew a second one under it.

The lock in `dockermon.updates` is here too: it was non-reentrant, `scan_host`
re-acquired it through `state()`, and the whole process wedged - which is what
the build server saw as a job frozen at 42% until it was killed.
"""

from __future__ import annotations

import re
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / 'static' / 'js'
TEMPLATES = ROOT / 'templates'
WORKFLOWS = ROOT / '.gitea' / 'workflows'


def _read(*parts):
    return Path(*parts).read_text(encoding='utf-8')


# --------------------------------------------------------------- the queue --


def test_the_re_check_forces_a_scan_instead_of_answering_nothing():
    """`started: null` with no scan queued is the bug, in one assertion.

    The route skipped only when the cache was younger than a second; the queue
    skipped when it was younger than its 30-minute TTL. A host the pane had
    just scanned therefore passed the first test and failed the second, and the
    button did nothing at all.
    """
    source = _read(ROOT, 'dockermon', 'routes.py')
    block = source[source.index('def api_updates_refresh'):]
    block = block[:block.index('def api_updates_refresh_all')]
    assert 'scan_async(app, [host_key], force=True)' in block


def test_the_scan_state_lock_can_be_taken_twice_by_the_same_thread():
    from dockermon import updates

    assert updates._state_lock.acquire(blocking=False)
    try:
        # re-enters the lock; with a plain Lock this line never returns
        assert updates.state('no-such-host') is None
    finally:
        updates._state_lock.release()


def test_a_host_already_being_scanned_answers_from_the_cache(monkeypatch):
    """The exact call that self-deadlocked: drilled through `state()`."""
    from dockermon import updates

    updates.clear()
    updates._store('db-9', {'host_key': 'db-9', 'ts': 1})
    monkeypatch.setattr(updates, '_inflight', {'db-9'})
    try:
        assert updates.scan_host(None, 'db-9')['host_key'] == 'db-9'
    finally:
        updates.clear()


def test_ci_gives_a_deadlock_a_deadline():
    """A hang must fail in two minutes, not eat a twenty-minute job slot."""
    ci = _read(WORKFLOWS, 'ci.yml')
    job = ci[ci.index('  python:'):ci.index('  remediation-catalog:')]
    runs = [line for line in job.splitlines() if re.search(r'-q .*pytest|pytest -q', line)]
    assert runs, 'the python job must still run the suite'
    for line in runs:
        assert '--timeout=120' in line, line
    assert 'pytest-timeout' in job               # and the plugin is installed


# ------------------------------------------------------- the stack scan --


def _service(repo='postgres', tag='16-alpine', digest='', stack='metamcp'):
    return {'stack': stack, 'short': stack, 'service': f'{stack}_{repo}',
            'image': f'zot.safehomelan.com/{repo}:{tag}', 'host': 'zot.safehomelan.com',
            'repo': repo, 'tag': tag, 'digest': digest, 'mode': 'replicated',
            'replicas': '1/1'}


@pytest.fixture()
def swarm_ready(monkeypatch):
    from dockermon import swarmstack

    swarmstack.clear()
    monkeypatch.setattr(swarmstack, '_zot_host', lambda: 'zot.safehomelan.com')
    monkeypatch.setattr(swarmstack, '_runner', lambda key: ({}, lambda cmd, timeout=0: (True, '')))
    monkeypatch.setattr(swarmstack, 'is_manager', lambda run: True)
    yield swarmstack
    swarmstack.clear()


def test_the_stack_scan_reports_its_stage_then_its_comparisons(swarm_ready, monkeypatch):
    swarmstack = swarm_ready
    seen = []

    def fake_compare(rows, refresh, on_step=None):
        seen.append(swarmstack.activity())
        if on_step:
            on_step('postgres:16-alpine')
        seen.append(swarmstack.activity())
        return []

    monkeypatch.setattr(swarmstack, 'read_services', lambda run: [_service()])
    monkeypatch.setattr(swarmstack, '_compare', fake_compare)

    swarmstack.scan('db-11', refresh=True)

    reading, comparing = seen
    assert reading['active'] is True
    assert reading['stage'] == 'comparing tags'
    assert reading['total'] == 1                 # one registry question per tag
    assert reading['host'] == 'db-11'
    assert comparing['done'] == 1
    assert swarmstack.activity() is None         # and it clears when it lands


def test_the_stack_scan_clears_the_strip_when_the_cluster_cannot_be_read(swarm_ready, monkeypatch):
    swarmstack = swarm_ready

    def boom(key):
        raise RuntimeError('docker service inspect failed: manager unreachable')

    monkeypatch.setattr(swarmstack, '_runner', boom)
    with pytest.raises(RuntimeError):
        swarmstack.scan('db-11', refresh=True)
    assert swarmstack.activity() is None


def test_each_registry_lookup_is_one_step(swarm_ready, monkeypatch):
    swarmstack = swarm_ready
    monkeypatch.setattr(swarmstack.reg, 'remote_digest',
                        lambda ref, refresh=False: {'digest': 'sha256:' + 'b' * 64})
    rows = [
        _service(digest='sha256:' + 'a' * 64),
        _service(digest='sha256:' + 'a' * 64),           # same tag: no second question
        {'stack': 'other', 'short': 'other', 'service': 'other_portainer',
         'image': 'docker.io/portainer/portainer-ce:lts', 'host': 'docker.io',
         'repo': 'portainer-ce', 'tag': 'lts', 'digest': 'sha256:' + 'c' * 64,
         'mode': 'replicated', 'replicas': '1/1'},
    ]
    steps = []
    swarmstack._compare(rows, False, on_step=steps.append)

    assert steps == ['postgres:16-alpine']
    assert rows[0]['update_available'] is True
    assert rows[2]['from_zot'] is False


def test_the_activity_endpoint_carries_the_stack_scan(client):
    body = client.get('/api/activity').get_json()
    assert body['swarm'] is None


# ------------------------------------------------------------- the strip --


def test_the_strip_has_a_row_for_the_stack_scan():
    partial = _read(TEMPLATES, 'partials', 'activity-strip.html')
    assert 'data-activity="swarm"' in partial
    assert 'Reading the stack list' in partial


def test_the_strip_renders_it_and_keeps_the_bar_up_for_it():
    js = _read(JS, 'activity.js')
    assert "render('swarm', data.swarm" in js
    assert 'data.swarm?.active' in js
    # the counter counts the thing the row is counting
    assert "unitFor" in js and "'tags' : 'hosts'" in js


# ------------------------------------------------------- one button, not two --


def test_the_pane_draws_one_re_check_button():
    """The pane's own button, and the stack panel under it, both said re-check."""
    core = _read(JS, 'app-core.js')
    assert core.count('recheck: false') >= 2      # the panel never draws its own here
    panel = _read(JS, 'swarm-update.js')
    assert "opts.recheck === false ? '' :" in panel
    assert 'data-swarm-recheck' in panel          # still there for the docker page


def test_the_docker_page_keeps_the_panels_own_button():
    page = _read(TEMPLATES, 'docker.html')
    assert 'renderSwarmUpdates' in page
    assert 'recheck: false' not in page


def test_the_manager_branch_wakes_the_strip_before_the_blocking_read():
    core = _read(JS, 'app-core.js')
    block = core[core.index("document.getElementById('docker-updates-refresh')"):]
    block = block[:block.index("document.getElementById('docker-log-select')")]
    manager = block[:block.index("await fetch(`/api/docker/hosts/${encodeURIComponent(hostId)}/updates/refresh`")]
    assert "new CustomEvent('ailog:activity')" in manager
    assert manager.index("CustomEvent('ailog:activity')") < manager.index('recheckSwarmUpdates(')


# ------------------------------------------------------------------ sweep --


def test_a_full_sweep_still_reports_hosts_not_tags(client):
    """The stack row must not take over the container sweep's wording."""
    js = _read(JS, 'activity.js')
    label = js[js.index('const hostLabel'):js.index('const unitFor')]
    assert "name === 'swarm'" in label
    assert "comparing image tags on" in label
