"""The other reason a container looks out of date: its *version* is behind.

The per-host scan compares a tag's digest with the digest the registry reports
for the same tag, which is the right question for `image:latest` and useless
for a pin. anchor runs `:0.9.1` while the source publishes `:0.17.2`; that tag
never moved, so no digest on any host will ever say so, and the container you
cannot find stays invisible.

`estate/drift.py` keeps that comparison - wizard.yaml's pin against the newest
tag its source publishes - in the background, cached for fifteen minutes,
because it costs one registry round per service.
"""

from __future__ import annotations

from estate import drift


class FakeRepo:
    dir = '/tmp/estate'
    text = 'services: []'          # tests set this on the class before sweeping
    present = True

    def __init__(self, *_a, **_kw):
        self._text = self.text

    def exists(self):
        return self.present

    def fresh(self):
        return 'deadbee'

    def read(self, rel):
        if rel == 'wizard.yaml':
            return self._text
        return ''

    def head(self):
        return 'deadbee'


WIZARD = """
services:
  - name: anchor
    kind: mirror
    source: ghcr.io/anchor/anchor
    version: 0.9.1
    service: anchor
  - name: dozzle
    kind: mirror
    source: amir20/dozzle
    version: 9.0.0
    service: dozzle
  - name: ailog-mcp
    kind: build
    repo: ailog-mcp
    release: auto
    version: build-191
  - name: vikunja
    kind: mirror
    source: vikunja/vikunja
    version: 2.7.1
    service: vikunja
"""


def test_only_the_services_that_are_behind_are_reported(monkeypatch):
    calls = {}

    def newest_tag(image, limit=100):
        calls[image] = calls.get(image, 0) + 1
        if image == 'ghcr.io/anchor/anchor':
            return {'best': '0.17.2', 'current': '0.9.1', 'up_to_date': False}
        if image == 'amir20/dozzle':
            return {'best': '9.0.0', 'current': '9.0.0', 'up_to_date': True}
        raise RuntimeError('registry said 502')

    FakeRepo.text = WIZARD
    monkeypatch.setattr(drift, 'Repo', FakeRepo)
    monkeypatch.setattr(drift.tags, 'newest_tag', newest_tag)

    rows = drift.sweep()

    assert [r['name'] for r in rows] == ['anchor']
    assert (rows[0]['current'], rows[0]['target']) == ('0.9.1', '0.17.2')
    assert rows[0]['repo'] == 'anchor'
    # a build app has no version to resolve - it is a rebuild, not a bump
    assert calls and not any('mcp' in str(k) for k in calls)


def test_one_unreadable_source_does_not_blank_the_card(monkeypatch):
    def newest_tag(image, limit=100):
        if image == 'ghcr.io/anchor/anchor':
            return {'best': '0.17.2', 'up_to_date': False}
        raise RuntimeError('timed out')

    FakeRepo.text = WIZARD
    monkeypatch.setattr(drift, 'Repo', FakeRepo)
    monkeypatch.setattr(drift.tags, 'newest_tag', newest_tag)
    drift.clear()

    rows = drift.sweep()

    assert [r['name'] for r in rows] == ['anchor']
    assert 'timed out' in drift.state()['error']


def test_no_checkout_is_an_answer_not_an_exception(monkeypatch):
    FakeRepo.present = False
    monkeypatch.setattr(drift, 'Repo', FakeRepo)
    drift.clear()
    assert drift.sweep() == []
    assert 'checkout' in drift.state()['error']


def test_the_sweep_is_cached_until_it_expires(monkeypatch):
    started = []
    monkeypatch.setattr(drift.threading, 'Thread',
                        lambda **kw: type('T', (), {'start': lambda self: started.append(kw)})())
    drift.clear()

    assert drift.refresh_async(app=None) is True          # cold: sweep
    with drift._lock:
        drift._state.update(ts=__import__('time').time(), running=False)
    assert drift.refresh_async(app=None) is False         # warm: nothing to do

    with drift._lock:
        drift._state['ts'] = 0.0
        drift._state['running'] = True
    assert drift.refresh_async(app=None) is False         # already running
    with drift._lock:
        drift._state['running'] = False
    drift.clear()


def test_the_card_puts_estate_drift_first_and_resolves_its_host(ctx, monkeypatch):
    from dockermon import updates as dupdates
    from overview import routes as overview_routes

    monkeypatch.setattr(dupdates, 'all_state', lambda: {
        'db-15': {'ts': 0, 'updates': [{'name': 'portainer_agent.x', 'image': 'portainer/agent:lts',
                                        'local_digest': 'aaa', 'remote_digest': 'bbb'}],
                  'containers': [{'name': 'anchor_anchor.1.abcdef', 'image': 'zot.safehomelan.com/anchor:0.9.1'}]},
    })
    monkeypatch.setattr('dockermon.endpoints.all_host_keys', lambda: ['db-15'])
    monkeypatch.setattr('dockermon.endpoints.resolve_host',
                        lambda key: {'friendly_name': 'swarm-worker4'} if key == 'db-15' else None)
    monkeypatch.setattr(drift, 'refresh_async', lambda app: False)
    monkeypatch.setattr(drift, 'state', lambda: {'rows': [{
        'name': 'anchor', 'service': 'anchor', 'current': '0.9.1', 'target': '0.17.2',
        'image': 'zot.safehomelan.com/anchor:0.9.1', 'repo': 'anchor'}], 'checked': 14, 'error': ''})

    out = overview_routes._docker_updates()

    assert out['estate'] == 1
    first = out['rows'][0]
    assert first['kind'] == 'estate'
    assert first['service'] == 'anchor'
    assert (first['from'], first['to']) == ('v0.9.1', 'v0.17.2')
    # the row is clickable because we know which host carries that image
    assert first['host_key'] == 'db-15'
    assert first['host'] == 'swarm-worker4'
    assert first['container'] == 'anchor_anchor.1.abcdef'
    # and the digest row is still there, second
    assert out['rows'][1]['kind'] == 'digest'


def test_a_running_container_wins_over_a_shutdown_one_on_another_node(ctx, monkeypatch):
    """A swarm task leaves shutdown siblings behind; the row must point at the live one."""
    from dockermon import updates as dupdates
    from overview import routes as overview_routes

    monkeypatch.setattr(dupdates, 'all_state', lambda: {
        'db-14': {'ts': 0, 'updates': [], 'containers': [
            {'name': 'anchor_anchor.1.old', 'image': 'zot.safehomelan.com/anchor:0.9.1', 'state': 'shutdown'}]},
        'db-15': {'ts': 0, 'updates': [], 'containers': [
            {'name': 'anchor_anchor.1.new', 'image': 'zot.safehomelan.com/anchor:0.9.1', 'state': 'running'}]},
    })
    monkeypatch.setattr('dockermon.endpoints.all_host_keys', lambda: [])
    monkeypatch.setattr('dockermon.endpoints.resolve_host', lambda key: {'friendly_name': key})
    monkeypatch.setattr(drift, 'refresh_async', lambda app: False)
    monkeypatch.setattr(drift, 'state', lambda: {'rows': [{
        'name': 'anchor', 'service': 'anchor', 'current': '0.9.1', 'target': '0.18.0',
        'image': 'zot.safehomelan.com/anchor:0.9.1', 'repo': 'anchor'}], 'error': ''})

    row = overview_routes._docker_updates()['rows'][0]
    assert row['host_key'] == 'db-15'
    assert row['container'] == 'anchor_anchor.1.new'


def test_a_version_that_already_says_v_does_not_say_vv(ctx, monkeypatch):
    from dockermon import updates as dupdates
    from overview import routes as overview_routes

    monkeypatch.setattr(dupdates, 'all_state', lambda: {})
    monkeypatch.setattr('dockermon.endpoints.all_host_keys', lambda: [])
    monkeypatch.setattr(drift, 'refresh_async', lambda app: False)
    monkeypatch.setattr(drift, 'state', lambda: {'rows': [{
        'name': 'dozzle', 'service': 'dozzle', 'current': 'v11.4.0', 'target': 'v11.4.1',
        'image': 'zot.safehomelan.com/dozzle:v11.4.1', 'repo': 'dozzle'}], 'error': ''})

    row = overview_routes._docker_updates()['rows'][0]
    assert row['from'] == 'v11.4.0'
    assert row['to'] == 'v11.4.1'


def test_an_estate_service_running_nowhere_still_appears(ctx, monkeypatch):
    from dockermon import updates as dupdates
    from overview import routes as overview_routes

    monkeypatch.setattr(dupdates, 'all_state', lambda: {})
    monkeypatch.setattr('dockermon.endpoints.all_host_keys', lambda: [])
    monkeypatch.setattr(drift, 'refresh_async', lambda app: False)
    monkeypatch.setattr(drift, 'state', lambda: {'rows': [{
        'name': 'vikunja', 'service': 'vikunja', 'current': '2.7.1', 'target': '3.0.0',
        'image': 'zot.safehomelan.com/vikunja:2.7.1', 'repo': 'vikunja'}], 'error': ''})

    row = overview_routes._docker_updates()['rows'][0]
    assert row['host_key'] == ''           # the card sends this one to /estate
    assert row['host'] == 'estate'
    assert row['container'] == 'vikunja'


def test_the_card_labels_the_two_kinds_of_update():
    from pathlib import Path
    js = (Path(__file__).resolve().parents[1] / 'static' / 'js' / 'overview.js').read_text()
    assert "row.kind === 'estate'" in js
    assert 'row.service || row.container' in js
    assert 'estate</span>' in js            # the chip
    assert "window.location.href = '/estate'" in js   # a row with no host
