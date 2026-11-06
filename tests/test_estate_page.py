"""The estate page: the view that makes the pipeline legible before you use it.

The endpoints existed for a release with no page in front of them, which meant the
only way to see what git pins - or to move a service - was the API. These tests
are about the page being real, self-contained, and honest about what it does not
do (it does not deploy; it asks for a plan and watches a CI run).
"""

from __future__ import annotations

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, 'static', 'js')
TEMPLATES = os.path.join(ROOT, 'templates')


def test_the_estate_page_is_served(client):
    body = client.get('/estate').data.decode()
    assert 'The estate' in body
    # the parts the page is useless without
    for element_id in ('estate-rows', 'estate-count-services', 'estate-run',
                       'estate-run-bar', 'estate-run-steps', 'estate-run-log'):
        assert f'id="{element_id}"' in body, element_id
    assert '/static/js/estate.js' in body


def test_the_estate_page_is_embeddable_like_the_docker_view(client):
    embedded = client.get('/estate?embed=1').data.decode()
    assert '/static/js/estate.js' in embedded
    assert 'min-h-screen' not in embedded.split('<body')[-1][:120]


def test_the_page_module_refuses_to_pretend_it_deploys():
    source = open(os.path.join(STATIC, 'estate.js')).read()
    # it plans, confirms, then follows a job - nothing here runs docker
    assert "fetch('/api/estate/services'" in source
    assert '?check=1' in source
    assert "fetch('/api/estate/update'" in source
    assert 'confirm: true' in source
    assert '/api/estate/jobs/' in source
    assert 'docker service update' not in source
    assert 'docker stack deploy' not in source


def test_the_page_shows_progress_steps_and_the_run_log():
    source = open(os.path.join(STATIC, 'estate.js')).read()
    for wire in ('estate-run-fill', 'estate-run-steps', 'estate-run-log',
                 'estate-run-state', 'estate-mode'):
        assert wire in source, wire
    assert 'setTimeout(() => poll(jobId), 900)' in source


def test_the_docker_pane_opens_the_estate():
    index = open(os.path.join(TEMPLATES, 'index.html')).read()
    partial = open(os.path.join(TEMPLATES, 'partials', 'estate-modal.html')).read()
    assert '{% include "partials/estate-modal.html" %}' in index
    assert 'id="estateModalFrame"' in partial

    core = open(os.path.join(STATIC, 'app-core.js')).read()
    assert 'docker-estate-btn' in core
    assert 'window.openEstateModal' in core

    modals = open(os.path.join(STATIC, 'iframe-modals.js')).read()
    assert "openFrame('estateModal', 'estateModalFrame'" in modals
    # closing must unload the frame, or the page keeps polling behind the dialog
    assert "estateModal: 'estateModalFrame'" in modals


def test_the_page_lists_build_apps_as_rebuilds(client):
    """A build app is not 'n/a': the estate can rebuild it from source."""
    source = open(os.path.join(STATIC, 'estate.js')).read()
    assert "row.action === 'rebuild'" in source
    assert 'rebuild' in source


def test_a_refused_merge_is_readable_in_the_page():
    """The reason a merge was refused is a sentence, and must not be clipped.

    The 405 came back as one long line in a one-line span, so the only place
    the real reason survived was the branch's job log. Both the run state and
    the step detail now wrap, and a failed step is coloured as a failure.
    """
    source = open(os.path.join(STATIC, 'estate.js')).read()
    assert 'whitespace-pre-wrap' in source
    assert 'break-words' in source
    assert "step.ok === false ? 'text-red-300'" in source
