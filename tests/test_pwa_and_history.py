"""Installable app (PWA) and browser Back that stays inside the app."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(*parts):
    return ROOT.joinpath(*parts).read_text()


def _js():
    return _read('static', 'js', 'app-core.js')


# ----------------------------------------------------------------- manifest

def test_the_manifest_is_a_valid_web_app_manifest():
    manifest = json.loads(_read('static', 'manifest.webmanifest'))
    assert manifest['name'] == 'Homelab Manager'
    assert manifest['short_name']
    assert manifest['start_url'] == '/?source=pwa'
    assert manifest['scope'] == '/'
    assert manifest['display'] == 'standalone'
    assert manifest['theme_color'] and manifest['background_color']
    sizes = {i['sizes'] for i in manifest['icons']}
    assert '192x192' in sizes and '512x512' in sizes
    purposes = {i.get('purpose') for i in manifest['icons']}
    assert 'maskable' in purposes
    assert manifest.get('shortcuts')


def test_the_icons_exist_as_real_pngs():
    icons = ROOT / 'static' / 'icons'
    for name in ('icon-192.png', 'icon-512.png', 'icon-maskable-512.png', 'apple-touch-icon.png'):
        data = (icons / name).read_bytes()
        assert data[:8] == b'\x89PNG\r\n\x1a\n', name
        assert len(data) > 2000, name


def test_the_page_declares_the_app():
    html = _read('templates', 'index.html')
    assert '<link rel="manifest" href="/static/manifest.webmanifest">' in html
    assert 'name="theme-color"' in html
    assert 'rel="apple-touch-icon"' in html
    assert 'apple-mobile-web-app-capable' in html
    assert 'viewport-fit=cover' in html
    assert 'id="install-app-btn"' in html
    assert "import './pwa.js'" in _read('static', 'js', 'main.js')


# ------------------------------------------------------------ service worker

def test_the_worker_is_registered_from_the_root():
    pwa = _read('static', 'js', 'pwa.js')
    assert "navigator.serviceWorker.register('/sw.js', { scope: '/' })" in pwa
    assert "'serviceWorker' in navigator" in pwa
    # the install button only appears when the browser says it can install
    assert "addEventListener('beforeinstallprompt'" in pwa
    assert 'deferredPrompt.prompt()' in pwa


def test_the_worker_never_touches_streams_or_live_data():
    sw = _read('static', 'sw.js')
    assert 'const PASS_THROUGH' in sw
    for path in (r'/^\/sources/', r'/^\/ssh/', r'/^\/api\//'):
        assert path in sw, path
    assert 'if (!isCacheable(url, request)) return;' in sw


def test_the_worker_prefers_the_network_and_ships_an_offline_page():
    sw = _read('static', 'sw.js')
    assert "request.mode === 'navigate' ? { cache: 'no-store' } : {}" in sw
    assert 'caches.match(request' in sw
    assert 'const OFFLINE_URL' in sw
    assert (ROOT / 'static' / 'offline.html').exists()
    assert 'skipWaiting' in sw


def test_flask_serves_the_worker_at_the_root_with_the_right_headers():
    source = _read('app.py')
    block = source[source.index("def service_worker():"):source.index("def web_manifest():")]
    assert "send_from_directory(" in block
    assert "'sw.js'" in block
    assert "response.headers['Service-Worker-Allowed'] = '/'" in block
    assert "response.headers['Cache-Control'] = 'no-cache'" in block
    manifest = source[source.index("def web_manifest():"):][:400]
    assert 'application/manifest+json' in manifest


# ------------------------------------------------------------------ history

def test_every_screen_is_a_history_entry():
    js = _js()
    for view in ('dashboard', 'hosts', 'logs'):
        assert f"navSetView('{view}')" in js, view
    assert 'const navPush = (state) => {' in js
    assert "history.pushState({ ailog: state }" in js


def test_back_closes_the_layer_on_screen():
    js = _js()
    assert 'const navOpenLayers = () => {' in js
    assert "addEventListener('popstate'" in js
    # the screen, not the (already updated) history entry, decides what closes
    assert 'const open = navOpenLayers();' in js
    assert "if (name === 'ssh') contractSshTerminal();" in js
    assert "else if (name === 'sheet') closeMobileHostSheet();" in js


def test_opening_a_layer_pushes_and_closing_rewrites():
    js = _js()
    assert "navOpenLayer('ssh');" in js
    assert "navCloseLayer('ssh');" in js
    assert "navOpenLayer('sheet');" in js
    assert "navCloseLayer('sheet');" in js
    close = js[js.index('const navCloseLayer = (name) => {'):]
    close = close[:close.index('const navApplyView')]
    assert 'navReplace(' in close          # never history.back(): no async fights
    assert 'history.back' not in close


def test_dialogs_get_their_own_history_entry():
    modals = _read('static', 'js', 'modals.js')
    assert "history.pushState({ ...state, ailogModal: modal.id }" in modals
    assert "history.replaceState({ ...state, ailogModal: null }" in modals
    assert "window.addEventListener('popstate'" in modals
    assert 'window.closeAppModal(top);' in modals
    # app-core must leave dialog entries alone, and vice versa
    assert 'if (state.ailogModal) return;' in _js()
    assert 'if (state.ailogModal) return;' in modals


def test_a_view_change_does_not_fight_with_back():
    js = _js()
    assert 'let navApplying = false;' in js
    assert 'if (navApplying) return;' in js
    assert 'if (history.state.ailog.view === view && !history.state.ailog.layers.length) return;' in js
