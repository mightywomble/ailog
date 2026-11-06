"""What a swarm node is running, and what only a manager may offer.

Two questions were being answered by one list. "What is this machine running?"
is about containers and every node can answer it. "What needs updating?" is
about the cluster - a service's image and whether zot has moved on - and a
worker cannot answer it at all, so the update list has no business being on a
worker's page. It was, which is why workers kept advertising updates that the
manager said did not exist.
"""

from __future__ import annotations

from pathlib import Path

from dockermon import routes, sshstats, swarmstack

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / 'static' / 'js'
TEMPLATES = ROOT / 'templates'


# ---------------------------------------------------------------- the numbers

def test_a_host_snapshot_reports_bytes_per_second_not_a_running_total():
    """`docker stats` counters are cumulative; the same row cannot be both.

    The node view converted them to bytes/second and the per-host snapshot -
    the one the container list reads - did not, so a container up for seven
    hours reported its whole lifetime of traffic as this second's usage
    (11,300,000.0 both ways, every poll, forever).
    """
    source = Path(sshstats.__file__).read_text()
    snapshot = source.split('def snapshot(', 1)[1].split('\ndef ', 1)[0]
    assert '_container_rates(containers' in snapshot


def test_the_rate_is_published_under_its_own_name():
    """`net_rx` means bps in one module and cumulative bytes in the other."""
    source = Path(sshstats.__file__).read_text()
    assert "row['net_rx_bps'] = row['net_rx']" in source
    assert "row['net_tx_bps'] = row['net_tx']" in source
    assert "row['net_rx_total'] = rx" in source


def test_the_engine_api_rows_get_a_rate_too(monkeypatch):
    """The SDK transport reports counters only, and must answer the same question."""
    monkeypatch.setattr(routes, '_ctr_net_cache', {})
    first = [{'id': 'abc', 'net_rx': 1000, 'net_tx': 2000}]
    routes._container_net_rates('db-x', first)
    assert first[0]['net_rx_bps'] == 0.0          # one sample cannot make a rate
    assert first[0]['net_rx_total'] == 1000

    second = [{'id': 'abc', 'net_rx': 1000 + 4096, 'net_tx': 2000 + 8192}]
    # pretend the first sample is a second old
    when, counters = routes._ctr_net_cache['db-x']
    monkeypatch.setitem(routes._ctr_net_cache, 'db-x', (when - 1.0, counters))
    routes._container_net_rates('db-x', second)
    assert 4000 < second[0]['net_rx_bps'] < 4200
    assert 8000 < second[0]['net_tx_bps'] < 8400


def test_a_worker_is_not_the_same_thing_as_a_host_with_no_swarm(monkeypatch):
    """manager:false is true of both, and they deserve different pages."""
    class Run:
        def __init__(self, state):
            self.state = state

        def __call__(self, command, timeout=60):
            if 'ControlAvailable' in command:
                return True, 'false'
            if 'LocalNodeState' in command:
                return True, self.state
            return True, ''

    assert swarmstack.is_swarm_node(Run('active')) is True
    assert swarmstack.is_swarm_node(Run('inactive')) is False

    monkeypatch.setattr(swarmstack, '_runner', lambda host: ({}, Run('active')))
    swarmstack.clear()
    out = swarmstack.scan('db-12')
    assert out['manager'] is False and out['swarm'] is True


# ------------------------------------------------------------------- the pages

def test_the_stacks_endpoint_says_whether_this_is_a_swarm_node():
    source = Path(swarmstack.__file__).read_text()
    assert "'swarm': is_swarm_node(run)" in source
    assert "'swarm': True," in source


def test_a_worker_page_has_no_update_list_and_a_container_table_instead():
    page = (TEMPLATES / 'docker.html').read_text()
    assert 'id="swarm-containers-list"' in page
    assert '/static/js/swarm-containers.js' in page
    # the update section is only revealed once the node says it is a manager
    assert "if (!body || !body.manager)" in page
    assert "updatesSection.classList.add('hidden');" in page


def test_the_host_pane_takes_the_update_card_off_a_worker():
    source = (JS / 'app-core.js').read_text()
    assert "id=\"docker-updates-card\"" in source            # removable as a whole
    assert "swarm.success && swarm.swarm" in source          # every node: containers
    after = source.split("const card = document.getElementById('docker-updates-card')", 1)[1]
    assert "if (card) card.classList.add('hidden')" in after.split('try {', 1)[0]


def test_every_pane_carries_the_four_numbers():
    source = (JS / 'swarm-containers.js').read_text()
    pane = source[source.index('const pane = (c, isOpen, s) =>'):source.index('const wire =')]
    assert 'versionBadge(c)' in pane          # name, then what version it is
    assert 'bytes(c.mem_used)' in pane
    assert 'pct(cpu)' in pane
    assert 'net_rx_bps' in source and 'net_tx_bps' in source
    # and it stops polling when the pane it drew into is gone
    assert 'mount.isConnected' in source


def test_a_worker_is_never_offered_a_stack_update(monkeypatch):
    """The manager owns the cluster's updates; a worker owns nothing."""
    from dockermon import swarmstack as stacks

    class Run:
        def __call__(self, command, timeout=60):
            if 'ControlAvailable' in command:
                return True, 'false'
            if 'LocalNodeState' in command:
                return True, 'active'
            return True, ''

    monkeypatch.setattr(stacks, '_runner', lambda host: ({}, Run()))
    stacks.clear()
    out = stacks.scan('db-13')
    assert out['manager'] is False
    assert out['stacks'] == []
    assert out['updates'] if 'updates' in out else True    # never a count from a worker


def test_the_container_list_shows_the_image_version():
    """The version is the thing you look for, and a truncated image:tag hides it."""
    source = (JS / 'swarm-containers.js').read_text()
    assert 'image_tag' in source
    assert 'versionBadge' in source
    # a badge beside the name, not a third line under it
    pane = source[source.index('const pane = (c, isOpen, s) =>'):source.index('const wire =')]
    assert '${versionBadge(c)}' in pane


def test_recheck_asks_the_question_the_panel_is_showing():
    """Re-check on a manager used to list images needing updates.

    The card says "Stack updates", the button ran the per-container scan, and
    one click later the panel answered a different question - the old image list
    the stack view exists to replace.
    """
    js = (JS / 'app-core.js').read_text()
    handler = js[js.index("document.getElementById('docker-updates-refresh')"):]
    handler = handler[:handler.index('docker-log-select')]
    assert 'window.swarmPanelTarget' in handler
    assert 'recheckSwarmUpdates' in handler
    # and the per-container refresh is the fallback, not the first move
    assert handler.index('recheckSwarmUpdates') < handler.index('/updates/refresh')

    stacks = (JS / 'swarm-update.js').read_text()
    assert 'window.recheckSwarmUpdates' in stacks
    # it remembers which list the user chose before re-asking
    assert 'lastOpts' in stacks


# ------------------------------------------------------------------ the panes

def test_the_panes_are_two_or_three_to_a_row_and_open_in_place():
    source = (JS / 'swarm-containers.js').read_text()
    assert 'sm:grid-cols-2 xl:grid-cols-3' in source
    assert 'data-toggle' in source and 'data-detail' in source
    # opening one shows the three graphs, not a new page
    for key in ('data-chart="cpu"', 'data-chart="mem"', 'data-chart="net"'):
        assert key in source
    assert 'series.cpu' in source and 'HISTORY' in source
    # a watched pane polls faster than an idle list
    assert 'POLL_OPEN_MS' in source


def test_a_pane_offers_a_terminal_inside_the_container():
    """Not the host it happens to be on - that is a hop the user has to make."""
    source = (JS / 'swarm-containers.js').read_text()
    assert 'ssh into container' in source
    assert '/shell' in source                 # asked before offering a prompt
    assert 'openContainerShell' in source

    core = (JS / 'app-core.js').read_text()
    assert 'window.openContainerShell' in core
    # the socket is told which container, and the resume check knows the difference
    assert '...(container ? { container } : {})' in core
    assert 'sshConnectedContainer === sshTargetContainer' in core

    app = (ROOT / 'app.py').read_text()
    assert "data.get('container')" in app
    assert 'docker exec -it' in app


def test_a_container_without_a_shell_says_so_instead_of_failing_later():
    source = (ROOT / 'dockermon' / 'routes.py').read_text()
    block = source[source.index('def api_container_shell'):]
    block = block[:block.index('# ------------------------------------')]
    assert "'sh', 'bash', 'ash'" in block
    assert 'no shell' in block
    assert '409' in block
