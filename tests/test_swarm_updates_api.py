"""The stack-update endpoints, and the two pages that have to draw them."""

from __future__ import annotations

from pathlib import Path

import pytest

from dockermon import routes as docker_routes

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / 'static' / 'js'
TEMPLATES = ROOT / 'templates'


@pytest.fixture()
def host(monkeypatch):
    monkeypatch.setattr(docker_routes.ep, 'resolve_host',
                        lambda key: {'friendly_name': key, 'ip': '127.0.0.1', 'user': 'x'})


def test_the_stack_list_comes_from_the_manager(client, host, monkeypatch):
    from dockermon import swarmstack
    monkeypatch.setattr(swarmstack, 'scan', lambda host_key, refresh=False: {
        'host_key': host_key, 'manager': True, 'updates': 1, 'services': 3,
        'stacks': [{'name': 'metamcp', 'updates': 1, 'services': []}], 'ts': 0,
    })

    body = client.get('/api/docker/hosts/db-11/swarm/stacks').get_json()

    assert body['success'] is True
    assert body['manager'] is True
    assert body['stacks'][0]['name'] == 'metamcp'


def test_a_worker_answers_that_it_is_not_a_manager(client, host, monkeypatch):
    from dockermon import swarmstack
    monkeypatch.setattr(swarmstack, 'scan', lambda host_key, refresh=False: {
        'host_key': host_key, 'manager': False, 'stacks': [], 'ts': 0,
        'note': 'this node is not a swarm manager, so it cannot see the cluster',
    })

    body = client.get('/api/docker/hosts/db-15/swarm/stacks').get_json()

    assert body['manager'] is False
    assert 'not a swarm manager' in body['note']


def test_an_update_must_name_a_version_and_be_confirmed(client, host):
    url = '/api/docker/hosts/db-11/swarm/stacks/metamcp/services/postgres/update'

    assert client.post(url, json={'confirm': True}).status_code == 400
    body = client.post(url, json={'version': '16.4-alpine'})
    assert body.status_code == 400
    assert 'confirmation' in body.get_json()['error']


def test_an_update_starts_a_job_the_dialog_can_poll(client, host, monkeypatch):
    from dockermon import updateflow
    monkeypatch.setattr(updateflow, 'start_stack',
                        lambda app, host_key, stack, service, version, prune=True: {
                            'id': 'abc123', 'status': 'running', 'steps': [], 'progress': 0})
    monkeypatch.setattr(updateflow, 'mode', lambda: 'on')

    body = client.post('/api/docker/hosts/db-11/swarm/stacks/metamcp/services/postgres/update',
                       json={'version': '16.4-alpine', 'confirm': True}).get_json()

    assert body['success'] is True
    assert body['job']['id'] == 'abc123'


def test_the_version_list_is_served_for_the_picker(client, host, monkeypatch):
    from dockermon import swarmstack
    monkeypatch.setattr(swarmstack, 'versions', lambda h, s, svc: {
        'stack': s, 'service': svc,
        'current': {'tag': '16-alpine', 'digest': 'sha256:' + 'a' * 64},
        'candidates': [{'tag': '16.4-alpine', 'in_zot': True}], 'warnings': [],
    })

    body = client.get('/api/docker/hosts/db-11/swarm/stacks/metamcp/services/postgres/versions'
                      ).get_json()

    assert body['success'] is True
    assert body['current']['tag'] == '16-alpine'
    assert body['candidates'][0]['tag'] == '16.4-alpine'


def test_pruning_needs_a_confirmation(client):
    assert client.post('/api/docker/registry/prune', json={}).status_code == 400


def test_the_manager_pane_asks_for_stacks_not_containers():
    source = (JS / 'app-core.js').read_text()
    assert '/swarm/stacks' in source
    assert 'Stack updates' in source
    # and the phantom-row fix it is there for: the container list is still read,
    # but only for the log picker
    assert 'renderDockerLogPicker(data.containers' in source


def test_the_docker_page_shows_the_same_list_and_the_modal():
    page = (TEMPLATES / 'docker.html').read_text()
    assert 'id="swarm-updates-list"' in page
    assert 'partials/swarm-update-modal.html' in page
    assert '/static/js/swarm-update.js' in page


def test_the_dialog_offers_versions_and_milestones():
    source = (JS / 'swarm-update.js').read_text()
    assert 'swarmUpdateVersion' in source          # the picker
    assert '/versions' in source                   # current + candidates
    assert '/update' in source                     # the pipeline
    assert '/api/docker/update/jobs/' in source    # the milestones it follows
    assert 'prune' in source                       # and the cleanup


def test_the_milestones_are_the_pipeline_in_order():
    """The steps a person sees must be the work that actually happens."""
    from dockermon import updateflow
    source = Path(updateflow.__file__).read_text()
    order = [source.index(marker) for marker in (
        "'read the cluster'", "'resolve version'", "'verify running'", "'prune zot'")]
    assert order == sorted(order)


def test_a_hidden_overlay_is_actually_hidden():
    """`hidden` the attribute loses to `flex` the class, and the page said so.

    The overlay covers the viewport with `fixed inset-0 ... flex`. The browser's
    own `[hidden] { display: none }` is a UA rule, so a utility class that sets
    display beats it: the attribute-hidden dialog sat over the page on every
    load, empty, titled "Stack update", with a close button that closed nothing
    interesting. It hides with the utility class instead, and the script toggles
    that class rather than the attribute.
    """
    partial = (TEMPLATES / 'partials' / 'swarm-update-modal.html').read_text()
    tag = partial.split('<div id="swarmUpdateModal"', 1)[1].split('>', 1)[0]
    classes = tag.split('class="', 1)[1].split('"', 1)[0]
    assert 'hidden' in classes                 # the utility class does the hiding
    assert 'hidden' not in tag.replace(classes, '')   # and not the attribute beside it

    source = (JS / 'swarm-update.js').read_text()
    assert '.hidden = ' not in source                     # no attribute toggling
    assert "classList.toggle('hidden'" in source


def test_the_picker_is_reachable_when_nothing_is_behind():
    """A clean cluster still has to be able to move a service.

    The panel listed only stacks with an update, and only a row that was behind
    got a button - so on a cluster where everything is current (the normal
    state, and the state the phantom fix produced) there was no way to reach the
    version picker at all. "every service" shows them all, and a service that is
    current gets "change version", which opens the same picker.
    """
    source = (JS / 'swarm-update.js').read_text()
    assert 'data-swarm-all' in source
    assert "'only updates' : 'every service'" in source
    assert 'change version' in source
    # the button is only offered for something that can be moved: zot, not upstream
    lines = source.splitlines()
    at = next(i for i, l in enumerate(lines) if 'change version' in l)
    window = '\n'.join(lines[max(0, at - 2):at + 1])
    assert 'from_zot' in window        # offered only for something zot can serve
