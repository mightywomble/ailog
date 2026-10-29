"""Interfaces: a layout axis independent of colour.

Three looks — classic, glass, console — selected in Settings → Appearance,
persisted in `ui.interface`, and applied as `data-ui` on <html> so every colour
theme keeps working with each one.
"""

from __future__ import annotations

import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = os.path.join(ROOT, 'templates')
CSS = os.path.join(ROOT, 'static', 'css')
JS = os.path.join(ROOT, 'static', 'js')


@pytest.fixture(scope='module')
def interfaces_css():
    return open(os.path.join(CSS, 'interfaces.css')).read()


@pytest.fixture(scope='module')
def theme_js():
    return open(os.path.join(JS, 'theme.js')).read()


def test_both_interfaces_are_defined(interfaces_css):
    assert '[data-ui="glass"]' in interfaces_css
    assert '[data-ui="console"]' in interfaces_css


def test_classic_is_the_unstyled_baseline(interfaces_css):
    # classic must not need overrides: the app's own styles are the classic look
    assert '[data-ui="classic"]' not in interfaces_css


def test_glass_reskins_surfaces_and_layout(interfaces_css):
    glass = interfaces_css[interfaces_css.index('[data-ui="glass"]'):interfaces_css.index('[data-ui="console"]')]
    assert 'backdrop-filter' in glass
    assert 'border-radius: 999px' in glass          # pill header / controls
    assert 'grid-template-columns: repeat(3' in glass  # bento overview
    assert 'radial-gradient' in glass               # ambient glow


def test_console_is_dense_and_uppercased(interfaces_css):
    console = interfaces_css[interfaces_css.index('[data-ui="console"]'):]
    assert 'text-transform: uppercase' in console
    assert 'letter-spacing' in console
    assert '--radius: 8px' in console
    assert '--chart-1' in console                    # accent-topped cards


def test_interfaces_use_semantic_tokens_only(interfaces_css):
    hexes = re.findall(r'#[0-9a-fA-F]{3,8}\b', interfaces_css)
    assert hexes == [], f'hard-coded colours in interfaces.css: {hexes}'
    assert 'var(--accent)' in interfaces_css
    assert 'var(--surface' in interfaces_css


def test_no_important_flags(interfaces_css):
    assert '!important' not in interfaces_css


def test_phone_layout_guards(interfaces_css):
    assert 'flex-shrink: 0' in interfaces_css
    assert '@media (max-width: 720px)' in interfaces_css


# --- controller -----------------------------------------------------------


def test_interfaces_are_registered(theme_js):
    assert 'export const INTERFACES' in theme_js
    for value in ('classic', 'glass', 'console'):
        assert f"id: '{value}'" in theme_js


def test_interface_is_persisted_and_applied(theme_js):
    assert "ui: 'ui.interface'" in theme_js
    assert 'root.dataset.ui = state.ui' in theme_js
    assert 'export function setInterface(' in theme_js
    assert "pick('ui'" in theme_js                      # ?ui=glass override


def test_reset_returns_to_classic(theme_js):
    reset = theme_js[theme_js.index('export function resetAppearance'):]
    assert "state.ui = 'classic'" in reset
    assert 'write(KEY.ui, state.ui)' in reset


def test_panel_builds_interface_choices(theme_js):
    assert 'data-ui-choice' in theme_js
    assert 'ui-preview' in theme_js
    assert 'Colour themes apply to every interface' in theme_js


def test_public_api_exposes_interfaces(theme_js):
    assert 'INTERFACES, state, setTheme, setInterface' in theme_js


def test_palette_can_switch_interface():
    palette = open(os.path.join(JS, 'command-palette.js')).read()
    assert 'INTERFACES' in palette
    assert 'Interface: ' in palette
    assert 'setInterface' in palette


# --- templates ------------------------------------------------------------


@pytest.mark.parametrize('name', sorted(
    n for n in os.listdir(TEMPLATES) if n.endswith('.html') and n != 'wizard.html'
))
def test_each_page_links_the_stylesheet_and_sets_the_attribute(name):
    html = open(os.path.join(TEMPLATES, name)).read()
    assert '/static/css/interfaces.css' in html, name
    assert "r.dataset.ui = localStorage.getItem('ui.interface') || 'classic';" in html, name


def test_stylesheet_loads_after_the_theme_stack():
    html = open(os.path.join(TEMPLATES, 'index.html')).read()
    order = [html.index('/static/css/theme.css'),
             html.index('/static/css/shell.css'),
             html.index('/static/css/ui.css'),
             html.index('/static/css/interfaces.css')]
    assert order == sorted(order)


def test_settings_panel_mentions_interfaces():
    panel = open(os.path.join(TEMPLATES, 'partials', 'settings.html')).read()
    assert 'Interface, theme, light/dark mode' in panel
    assert 'data-appearance-panel' in panel


def test_rendered_page_ships_the_look(flask_app):
    body = flask_app.test_client().get('/').data.decode()
    assert '/static/css/interfaces.css' in body
    assert 'data-appearance-panel' in body


def test_assets_are_versioned_so_a_deploy_cannot_be_masked_by_cache():
    """A stale theme.js is exactly how the Interface picker went missing."""
    html = open(os.path.join(TEMPLATES, 'index.html')).read()
    assert '/static/css/interfaces.css?v={{ app_version }}' in html
    assert '/static/js/theme.js?v={{ app_version }}' in html
    assert '/static/js/main.js?v={{ app_version }}' in html


def test_html_is_never_cached_and_static_assets_revalidate(flask_app):
    client = flask_app.test_client()
    page = client.get('/')
    assert 'no-store' in page.headers.get('Cache-Control', '')
    asset = client.get('/static/js/theme.js')
    assert asset.status_code == 200
    assert 'no-cache' in asset.headers.get('Cache-Control', '')


def test_settings_footer_shows_the_version(flask_app):
    body = flask_app.test_client().get('/').data.decode()
    assert 'data-app-version' in body
    assert 'v3.1.1' in body
