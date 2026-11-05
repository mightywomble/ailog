"""The dashboard's "Docker updates" card.

The estate is seventeen hosts wide, so "what can I update?" was a question you
had to ask one host at a time - pick the host, press its Docker square, read its
list - and the answer ("anchor is eight versions behind") could sit on a host
nobody thought to open. The card collects every out-of-date image in one place
and each row is a link to that container's own host.

Three things are worth pinning down:

* the aggregate reads the *cache* (the dashboard polls it every six seconds, so
  it must never block on an SSH round) and queues hosts that have not been
  scanned yet instead of waiting for them;
* rows a container's own compose project owns are left out, otherwise fifteen
  Nextcloud AIO siblings fill the card with entries nobody should press;
* a row click lands on that host's Docker list, which means it needs the two
  helpers app-core only exposes for this.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from dockermon import updates as dupdates
from overview import routes as overview_routes

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / 'static' / 'js' / 'overview.js'
CORE_JS = ROOT / 'static' / 'js' / 'app-core.js'
CSS = ROOT / 'static' / 'css' / 'ui.css'


@pytest.fixture()
def scan(monkeypatch):
    """Stand in for the scan cache and the scan queue."""
    state = {}
    queued = []

    def scan_async(app, host_keys, force=False):
        queued.extend(host_keys)
        return list(host_keys)

    monkeypatch.setattr(dupdates, 'all_state', lambda: {k: dict(v) for k, v in state.items()})
    monkeypatch.setattr(dupdates, 'scan_async', scan_async)
    monkeypatch.setattr('dockermon.endpoints.all_host_keys', lambda: list(state) + ['db-99'])
    monkeypatch.setattr('dockermon.endpoints.resolve_host',
                        lambda key: {'friendly_name': f'friendly-{key}'})
    return state, queued


def _row(name, image='zot.safehomelan.com/anchor:0.9.1', local='aaa', remote='bbb',
         self_managed=None, containers=1):
    return {
        'name': name, 'image': image, 'local_digest': local, 'remote_digest': remote,
        'self_managed': self_managed, 'containers': containers, 'update_available': True,
    }


def _host_state(*rows):
    return {'ts': 0, 'updates': list(rows), 'attention_only': []}


def test_every_out_of_date_container_is_listed_with_its_host(ctx, scan):
    state, _queued = scan
    state['db-3'] = _host_state(_row('anchor'))
    state['db-8'] = _host_state(_row('immich_server', image='ghcr.io/immich:1.0'))

    out = overview_routes._docker_updates()

    assert out['count'] == 2
    assert out['hosts'] == 2
    assert {(r['host_key'], r['container']) for r in out['rows']} == {
        ('db-3', 'anchor'), ('db-8', 'immich_server')}
    # the friendly name is what a person recognises
    assert out['rows'][0]['host'].startswith('friendly-db-')


def test_the_card_reads_the_cache_and_never_probes_a_host(ctx, scan, monkeypatch):
    """An SSH round here would make the whole dashboard wait on the slowest box."""
    state, _queued = scan
    state['db-3'] = _host_state(_row('anchor'))

    def boom(*_a, **_kw):
        raise AssertionError('/api/overview must not open a connection')

    monkeypatch.setattr('dockermon.routes._transport_for', boom)
    monkeypatch.setattr('dockermon.sshstats.list_containers', boom)
    assert overview_routes._docker_updates()['count'] == 1


def test_a_host_that_was_never_scanned_is_queued_instead_of_blocking(ctx, scan):
    state, queued = scan
    state['db-3'] = _host_state()

    out = overview_routes._docker_updates()

    assert out['pending'] == ['db-99']
    assert 'db-3' not in queued            # already answered
    assert 'db-99' not in [r['host_key'] for r in out['rows']]


def test_a_scan_that_cannot_be_queued_must_not_break_the_card(ctx, scan, monkeypatch):
    state, _queued = scan
    state['db-3'] = _host_state(_row('anchor'))

    def boom(*_a, **_kw):
        raise RuntimeError('queue full')

    monkeypatch.setattr(dupdates, 'scan_async', boom)
    out = overview_routes._docker_updates()
    assert out['count'] == 1
    assert out['pending'] == []


def test_containers_their_own_project_owns_are_not_updates(ctx, scan):
    """Nextcloud AIO recreates its own siblings; fifteen rows nobody should press."""
    state, _queued = scan
    state['db-3'] = {
        'ts': 0,
        'updates': [_row('anchor')],
        'self_managed': {'nextcloud-aio': 15},
    }
    state['db-3']['updates'] += [_row(f'aio-{n}', self_managed='nextcloud-aio') for n in range(15)]

    out = overview_routes._docker_updates()
    assert out['count'] == 1
    assert [r['container'] for r in out['rows']] == ['anchor']


def test_the_list_is_capped_and_says_how_much_it_is_hiding(ctx, scan):
    state, _queued = scan
    state['db-3'] = _host_state(*[_row(f'c{n:02d}') for n in range(20)])

    out = overview_routes._docker_updates()
    assert out['count'] == 20
    assert len(out['rows']) == overview_routes.UPDATE_ROW_LIMIT == 12
    assert out['more'] == 8
    assert out['rows'] == sorted(out['rows'], key=lambda r: (r['host'].lower(), r['container'].lower()))


def test_rows_carry_what_the_card_shows(ctx, scan):
    state, _queued = scan
    state['db-3'] = _host_state(_row('anchor', local='aaaa1111', remote='bbbb2222', containers=2))

    row = overview_routes._docker_updates()['rows'][0]
    assert row['image'].endswith('anchor:0.9.1')
    assert (row['from'], row['to']) == ('aaaa1111', 'bbbb2222')
    assert row['containers'] == 2


# ---------------------------------------------------------------- the endpoint

def test_overview_serves_the_section_and_its_etag(client, scan):
    state, _queued = scan
    state['db-3'] = _host_state(_row('anchor'))

    first = client.get('/api/overview')
    assert first.status_code == 200
    payload = first.get_json()
    assert payload['docker_updates']['count'] == 1

    etag = first.headers['ETag']
    again = client.get('/api/overview', headers={'If-None-Match': etag})
    assert again.status_code == 304

    # A new update on a host changes the answer, so the ETag must change too.
    state['db-3'] = _host_state(_row('anchor'), _row('vikunja', image='zot.safehomelan.com/vikunja:2.7.1'))
    changed = client.get('/api/overview', headers={'If-None-Match': etag})
    assert changed.status_code == 200
    assert changed.get_json()['docker_updates']['count'] == 2
    assert changed.headers['ETag'] != etag


def test_scan_progress_alone_does_not_invalidate_the_etag():
    """Otherwise an idle dashboard repaints every time a scan round starts."""
    from overview.routes import _etag_for

    base = {'ts': 1, 'docker_updates': {'count': 0, 'rows': [], 'pending': ['db-3']}}
    later = {'ts': 2, 'docker_updates': {'count': 0, 'rows': [], 'pending': []}}
    assert _etag_for(base) == _etag_for(later)

    landed = {'ts': 3, 'docker_updates': {'count': 1, 'rows': [{'container': 'anchor'}], 'pending': []}}
    assert _etag_for(landed) != _etag_for(base)


def test_a_broken_section_degrades_one_card_only(client, monkeypatch):
    def boom():
        raise RuntimeError('scan cache gone')

    monkeypatch.setattr(overview_routes, '_docker_updates', boom)
    payload = client.get('/api/overview').get_json()
    assert 'scan cache gone' in str(payload['docker_updates'])
    assert 'servers' in payload and 'alerts' in payload


def test_check_all_queues_every_host_and_ignores_the_ttl(client, host, monkeypatch):
    """"Check now" means now: the cached answer is exactly what they doubt."""
    seen = {}

    def scan_async(app, keys, force=False):
        seen['keys'], seen['force'] = list(keys), force
        return list(keys)

    monkeypatch.setattr(dupdates, 'scan_async', scan_async)
    res = client.post('/api/docker/updates/refresh')

    assert res.status_code == 200
    assert res.get_json()['success'] is True
    assert seen['force'] is True
    assert host in seen['keys']


def test_force_bypasses_the_scan_ttl(monkeypatch):
    def no_thread(*_a, **_kw):                  # never run the scan in a test
        return type('T', (), {'start': lambda self: None})()

    monkeypatch.setattr(dupdates.threading, 'Thread', no_thread)
    monkeypatch.setattr(dupdates, 'stale', lambda key, max_age=None: False)
    dupdates.clear()

    assert dupdates.scan_async(app=None, host_keys=['db-3'], force=False) == []
    assert dupdates.scan_async(app=None, host_keys=['db-3'], force=True) == ['db-3']
    dupdates.clear()


# -------------------------------------------------------------------- the card

def test_the_card_lists_updates_and_links_each_row():
    js = JS.read_text()
    assert 'function renderDockerUpdates(section)' in js
    assert '<h3>Docker updates</h3>' in js
    assert 'cards.push(renderDockerUpdates(result.docker_updates))' in js
    assert 'data-ov-update="${esc(row.host_key)}"' in js
    assert 'data-ov-update-container="${esc(row.container)}"' in js
    # "update available" is a count, not a secret
    assert 'update${count === 1' in js or 'update${count === 1 ?' in js
    assert 'more`' in js or 'more on other hosts' in js


def test_a_row_click_opens_that_hosts_docker_pane():
    js = JS.read_text()
    block = js[js.index("mount.querySelectorAll('[data-ov-update]')"):]
    block = block[:block.index("mount.querySelector('[data-ov-check-all]')")]
    assert 'window.selectHost(hostKey)' in block
    assert 'window.showDockerInfoMain()' in block
    # and if this page has no app-core (a bare /reports render), do not dead-end
    assert 'window.location.href = `/docker/' in block


def test_the_host_pane_flashes_the_container_you_came_from():
    core = CORE_JS.read_text()
    assert 'window.__ovFocusContainer' in core
    assert 'data-docker-row=' in core
    assert 'scrollIntoView' in core
    # a stale hint must not flash a stranger's row minutes later
    assert '__ovFocusAt' in core
    assert 'window.selectHost = selectHost' in core


def test_the_card_can_ask_for_a_fresh_scan():
    js = JS.read_text()
    assert 'data-ov-check-all' in js
    assert "'/api/docker/updates/refresh'" in js
    # the poll is ETag-driven: a new answer would otherwise be a 304
    assert re.search(r'etag = null;', js)


def test_update_rows_escape_what_the_registry_reports():
    js = JS.read_text()
    block = js[js.index('function renderDockerUpdates'):js.index('function renderNetdata')]
    for value in ('row.host_key', 'row.container', 'row.host', 'row.image', 'row.from', 'row.to'):
        assert f'esc({value}' in block, value


def test_the_row_link_looks_like_text_until_hovered():
    css = CSS.read_text()
    block = css[css.index('button.ov-row-link {'):css.index('.ov-row-meta {')]
    assert 'background: none' in block
    assert 'cursor: pointer' in block
    assert ':focus-visible' in block
    assert not re.search(r'#[0-9a-fA-F]{3,8}\b', block), 'a literal hex colour would break the theme switcher'
