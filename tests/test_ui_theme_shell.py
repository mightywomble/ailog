"""Theming + responsive shell + command palette contract tests.

These are cheap structural guards for the Option-A rework: the palette, the
responsive shell, and the three-layer theme system. They do not need a running
browser — the JS/CSS contracts are checked at the source level, which is enough
to catch a rename or a dropped link.
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
TEMPLATES = ROOT / "templates"


@pytest.fixture(scope="module")
def index_html():
    return (TEMPLATES / "index.html").read_text()


@pytest.fixture(scope="module")
def theme_css():
    return (STATIC / "css" / "theme.css").read_text()


@pytest.fixture(scope="module")
def shell_css():
    return (STATIC / "css" / "shell.css").read_text()


@pytest.fixture(scope="module")
def ui_css():
    return (STATIC / "css" / "ui.css").read_text()


# ------------------------------------------------------------------ themes

THEME_IDS = ["midnight", "slate", "nord", "solarized", "terminal", "contrast"]
SEMANTIC_TOKENS = [
    "--bg", "--surface", "--surface-2", "--surface-3", "--border", "--text",
    "--muted", "--accent", "--accent-hover", "--on-accent", "--ok", "--warn",
    "--bad", "--chart-1", "--chart-6", "--term-bg",
]


@pytest.mark.parametrize("theme", THEME_IDS)
def test_every_theme_has_a_dark_and_a_light_palette(theme_css, theme):
    dark = f'[data-theme="{theme}"][data-mode="dark"]'
    light = f'[data-theme="{theme}"][data-mode="light"]'
    assert dark in theme_css, f"{theme} has no dark palette"
    assert light in theme_css, f"{theme} has no light palette"


@pytest.mark.parametrize("token", SEMANTIC_TOKENS)
def test_semantic_tokens_are_declared(theme_css, token):
    assert token + ":" in theme_css


def test_theme_css_has_the_four_ui_switches(theme_css):
    for attr in ("data-density", "data-motion", "theme-switching"):
        assert attr in theme_css


def test_light_mode_retargets_legacy_tailwind_text_utilities(theme_css):
    # the app still has ~1500 lines of slate/gray utilities; light mode must not
    # leave them white-on-white
    assert '[data-mode="light"] .text-slate-100' in theme_css
    assert '[data-mode="light"] .text-amber-200' in theme_css


def test_theme_controller_exposes_the_six_themes_and_persistence_keys():
    js = (STATIC / "js" / "theme.js").read_text()
    for theme in THEME_IDS:
        assert theme in js
    for key in ("ui.theme", "ui.mode", "ui.density", "ui.motion"):
        assert key in js
    assert "ailogTheme" in js
    assert "themeColors" in js
    assert "--chart-1" in js


def test_theme_controller_supports_url_and_system_overrides():
    js = (STATIC / "js" / "theme.js").read_text()
    assert "URLSearchParams" in js
    assert "prefers-color-scheme" in js
    assert "toggleMode" in js


def test_every_page_gets_the_prepaint_boot_script_and_theme_css():
    pages = ["index.html", "metrics.html", "reports.html", "report.html",
             "alerts.html", "monitoring.html", "monitoring_wizard.html", "docker.html"]
    for page in pages:
        html = (TEMPLATES / page).read_text()
        assert "/static/css/theme.css" in html, f"{page} is missing theme.css"
        assert "ui.theme" in html, f"{page} is missing the pre-paint boot script"
        assert "/static/js/theme.js" in html, f"{page} is missing theme.js"


# ------------------------------------------------------------------ shell

def test_index_links_the_new_shell_stylesheets(index_html):
    for sheet in ("theme.css", "shell.css", "ui.css"):
        assert f"/static/css/{sheet}" in index_html


def test_header_owns_palette_theme_toggle_and_settings(index_html):
    for element_id in ("mobile-menu-btn", "command-palette-btn", "theme-toggle-btn", "settings-btn"):
        assert f'id="{element_id}"' in index_html


def test_theme_toggle_swaps_sun_and_moon_icons(shell_css):
    assert '[data-mode="dark"] .theme-icon-light' in shell_css
    assert '[data-mode="light"] .theme-icon-dark' in shell_css


def test_shell_has_three_breakpoints(shell_css):
    assert "max-width: 1024px) and (min-width: 641px" in shell_css   # tablet rail
    assert "max-width: 640px" in shell_css                           # phone sheet
    assert "grid-template-columns: 264px minmax(0, 1fr)" in shell_css


def test_phone_sidebar_is_a_slide_over_with_a_backdrop(shell_css):
    assert "translateX(-105%)" in shell_css
    assert "body.sidebar-open #hosts-sidebar" in shell_css
    assert "body.sidebar-open::after" in shell_css


def test_phone_tab_bar_has_five_destinations(index_html):
    nav = index_html[index_html.index('id="mobile-tabbar"'):
                     index_html.index('id="mobile-tabbar"') + 2000]
    for tab in ("overview", "logs", "hosts", "monitor", "alerts"):
        assert f'data-tab="{tab}"' in nav


def test_mobile_targets_are_at_least_44px(shell_css):
    assert "min-height: 44px" in shell_css
    assert "env(safe-area-inset-bottom)" in shell_css


def test_overview_cards_are_the_first_thing_on_the_dashboard(index_html):
    dashboard = index_html.index('id="dashboard-view"')
    overview = index_html.index('id="overview-cards"')
    toolbar = index_html.index('id="dashboard-toolbar"')
    assert dashboard < toolbar < overview
    # and not buried inside the toolbar
    assert index_html[dashboard:overview].count("<div") >= 1


def test_dashboard_uses_token_quick_access_buttons(index_html):
    dashboard = index_html[index_html.index('id="dashboard-toolbar"'):index_html.index('id="overview-cards"')]
    assert "qa-btn qa-btn-primary" in dashboard
    assert "bg-emerald-600" not in dashboard
    assert "bg-amber-500" not in dashboard


def test_big_fleets_do_not_stretch_the_overview_row(ui_css):
    block = re.search(r'\.ov-card\[data-ov="hosts"\] \{(.*?)\}', ui_css, re.S).group(1)
    assert "max-height" in block
    assert "overflow-y: auto" in ui_css


def test_sidebar_drag_grip_is_visible(ui_css):
    block = re.search(r"\.hosts-grab-handle svg \{(.*?)\}", ui_css, re.S).group(1)
    assert "stroke-width" in block


# ------------------------------------------------------------- interactions

def test_command_palette_contract():
    js = (STATIC / "js" / "command-palette.js").read_text()
    for marker in ("cmdk-overlay", "cmdk-panel", "cmdk-input", "cmdk-list"):
        assert marker in js
    assert "window.ailogPalette" in js
    assert "metaKey" in js and "ctrlKey" in js
    assert "ailogHostActions" in js
    assert "subsequence" in js.lower() or "for (const ch of haystack)" in js


def test_shell_js_wires_drawer_and_tab_bar():
    js = (STATIC / "js" / "shell.js").read_text()
    assert "sidebar-open" in js
    assert "aria-current" in js
    assert "window.ailogShell" in js


def test_overview_polls_the_three_summary_endpoints():
    js = (STATIC / "js" / "overview.js").read_text()
    for endpoint in ("/api/metrics/servers", "/api/alerts/events", "/api/reports"):
        assert endpoint in js
    assert "POLL_MS" in js
    assert "document.hidden" in js
    # cards must not wait for the slowest endpoint, and must not hang forever
    assert "AbortController" in js
    assert "skeletonCard" in js


def test_offline_count_copy_matches_the_number():
    js = (STATIC / "js" / "overview.js").read_text()
    # 6 offline hosts must not be described as "all reachable"
    assert "unreachable" in js
    assert "servers.length === online.length ? 'all reachable'" in js


def test_app_core_exposes_the_navigation_hooks():
    js = (STATIC / "js" / "app-core.js").read_text()
    assert "window.ailogOpenHost" in js
    assert "window.ailogHostActions" in js
    assert "window.showLogs" in js


def test_main_imports_the_new_modules(index_html):
    assert "/static/js/main.js" in index_html
    main = (STATIC / "js" / "main.js").read_text()
    # theme.js is loaded by the templates (it must run before first paint)
    for module in ("shell.js", "command-palette.js", "overview.js"):
        assert f"./{module}" in main


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_all_frontend_modules_parse():
    for path in sorted((STATIC / "js").rglob("*.js")):
        result = subprocess.run(["node", "--check", str(path)],
                                capture_output=True, text=True)
        assert result.returncode == 0, f"{path.name}: {result.stderr.strip()[:400]}"


def test_modal_chrome_is_token_driven_and_sits_above_the_tab_bar():
    css = (STATIC / "css" / "style.css").read_text()
    panel = re.search(r"\.app-modal-panel \{(.*?)\}", css, re.S).group(1)
    assert "var(--surface)" in panel
    assert "var(--border)" in panel
    modal = re.search(r"\.app-modal \{(.*?)\}", css, re.S).group(1)
    z = int(re.search(r"z-index:\s*(\d+)", modal).group(1))
    assert z >= 80, "dialogs must paint above the phone tab bar (75)"
