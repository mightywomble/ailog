"""Phase 5: index.html is a shell; dialogs live in templates/partials/."""

from __future__ import annotations

import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = os.path.join(ROOT, 'templates')
PARTIALS = os.path.join(TEMPLATES, 'partials')

EXPECTED_PARTIALS = ('settings.html', 'host.html', 'log-selection.html',
                     'ai-analysis.html', 'ssh-terminal.html')


@pytest.mark.parametrize('name', EXPECTED_PARTIALS)
def test_partial_exists_and_is_included(name):
    assert os.path.exists(os.path.join(PARTIALS, name))
    index = open(os.path.join(TEMPLATES, 'index.html')).read()
    assert f'{{% include "partials/{name}" %}}' in index


def test_index_html_is_now_a_shell():
    lines = sum(1 for _ in open(os.path.join(TEMPLATES, 'index.html')))
    assert lines < 800, f'index.html is {lines} lines; extract another dialog'


def test_rendered_page_still_contains_every_dialog(flask_app):
    body = flask_app.test_client().get('/').data.decode()
    for element_id in (
        'settings-modal', 'host-modal', 'log-selection-modal',
        'ai-analysis-modal', 'ssh-terminal-overlay', 'mobile-tabbar',
        'dashboard-view', 'ssh-terminal-body',
    ):
        assert f'id="{element_id}"' in body, element_id
    assert 'settings-layout' in body


def test_wizard_javascript_is_external():
    html = open(os.path.join(TEMPLATES, 'wizard.html')).read()
    assert '<script src="/static/js/wizard.js" defer></script>' in html
    assert '// New Wizard Implementation' not in html
    js = open(os.path.join(ROOT, 'static', 'js', 'wizard.js')).read()
    assert 'wizardNext' in js
    assert 'esc(' in js


def test_no_inline_script_bodies_left_in_partials():
    """Partials are markup only; behaviour belongs in static/js."""
    for name in EXPECTED_PARTIALS:
        body = open(os.path.join(PARTIALS, name)).read()
        assert '<script' not in body, name
