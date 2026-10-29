"""Every dialog in the app shares one chrome.

The look and feel (dark panel, title bar, Close button) lives in
``static/css/style.css`` under ``.app-modal*`` and the behaviour (Escape,
backdrop click, unloading of iframes) in ``static/js/modals.js``. These tests
exist because "apply it to all modals" is exactly the kind of thing that rots:
one new dialog gets added with the old markup and nobody notices.
"""
import re

import pytest

#: id -> a phrase that must appear in its title bar
MODALS = {
    'ai-analysis-modal': 'AI Analysis Result',
    'server-report-modal': 'Analyse All Logs',
    'settings-modal': 'Settings',
    'host-modal': 'New Host',            # title is rewritten at runtime
    'log-selection-modal': 'Select Logs to Monitor',
    'monitoringWizardModal': 'Monitoring Wizard',
    'dockerModal': 'Docker',
    'reportsModal': 'Reports',
    'metricsModal': 'Monitoring',
}


@pytest.fixture(scope='module')
def index_html(flask_app):
    with flask_app.test_client() as client:
        return client.get('/').data.decode()


def _modal_block(html, modal_id):
    """Return the markup from the modal's opening div to its matching close."""
    start = html.index(f'id="{modal_id}"')
    depth = 0
    for m in re.finditer(r'<div\b|</div>', html[start:]):
        depth += 1 if m.group(0) == '<div' else -1
        if depth == 0:
            return html[start:start + m.end()]
    raise AssertionError(f'{modal_id} never closes')


@pytest.mark.parametrize('modal_id,title', sorted(MODALS.items()))
def test_every_modal_uses_the_shared_chrome(index_html, modal_id, title):
    block = _modal_block(index_html, modal_id)
    assert 'class="app-modal hidden"' in block or 'class="app-modal hidden"' in index_html[index_html.index(f'id="{modal_id}"') - 40:index_html.index(f'id="{modal_id}"')]
    assert 'app-modal-panel' in block
    assert 'app-modal-head' in block
    assert 'app-modal-title' in block
    assert 'app-modal-close' in block
    assert title in block


@pytest.mark.parametrize('modal_id', sorted(MODALS))
def test_every_modal_close_button_is_shared_and_textual(index_html, modal_id):
    """The old dialogs used a bare '&times;' glyph; the shared chrome uses a
    labelled Close button so it is keyboard- and screen-reader-friendly."""
    block = _modal_block(index_html, modal_id)
    close_buttons = re.findall(r'<button[^>]*app-modal-close[^>]*>(.*?)</button>', block, re.S)
    assert close_buttons, f'{modal_id} has no .app-modal-close button'
    assert any('Close' in b for b in close_buttons)
    assert '&times;' not in block.split('app-modal-head', 1)[1].split('</div>')[0]


@pytest.mark.parametrize('modal_id', sorted(MODALS))
def test_no_modal_keeps_the_old_glass_or_inline_style(index_html, modal_id):
    block = _modal_block(index_html, modal_id)
    assert 'glass-container' not in block
    assert 'bg-black bg-opacity-75' not in block
    assert 'style="display: none"' not in block


def test_iframe_modals_load_with_embed_and_blank_start(index_html):
    for frame_id in ('dockerModalFrame', 'reportsModalFrame', 'monitoringWizardFrame'):
        tag = re.search(r'<iframe[^>]*id="%s"[^>]*>' % frame_id, index_html)
        assert tag, frame_id
        assert 'src="about:blank"' in tag.group(0)


def test_shared_modal_module_is_loaded_first(index_html, flask_app):
    main = flask_app.test_client().get('/static/js/main.js').data.decode()
    assert "import './modals.js'" in main
    # it must be imported before the feature modules that use it
    assert main.index("./modals.js") < main.index("'./app-core.js'")
    assert flask_app.test_client().get('/static/js/modals.js').status_code == 200


def test_shared_modal_css_is_present(flask_app):
    css = flask_app.test_client().get('/static/css/style.css').data.decode()
    for rule in ('.app-modal', '.app-modal-panel', '.app-modal-head',
                 '.app-modal-title', '.app-modal-close', '.app-modal-body'):
        assert rule in css, rule
    # `.hidden` must lose against the modal's own display:flex
    assert '.app-modal.hidden' in css


def test_reports_page_supports_embed_mode(flask_app):
    client = flask_app.test_client()
    assert '>Back<' in client.get('/reports').data.decode()
    embedded = client.get('/reports?embed=1').data.decode()
    assert '>Back<' not in embedded
    assert 'px-3 py-2.5' in embedded


def test_reports_links_open_outside_the_dialog_when_embedded(flask_app, ctx, db_session):
    """Navigating the iframe to /reports/<id> would replace the list inside the
    dialog, and that page's own Back link would load the SPA in a frame."""
    from database import LogReport
    import datetime

    db_session.add(LogReport(host_key='db-modal-test', host_label='modal-test',
                             window_minutes=60, verdict='healthy',
                             events_total=1, clusters_total=1,
                             created_at=datetime.datetime.utcnow()))
    db_session.commit()

    client = flask_app.test_client()
    plain = client.get('/reports?host=db-modal-test').data.decode()
    embedded = client.get('/reports?embed=1&host=db-modal-test').data.decode()
    assert '/reports/' in plain and '/reports/' in embedded
    assert 'target="_blank"' not in plain
    assert 'target="_blank"' in embedded


def test_reports_button_is_a_button_not_a_link(index_html):
    """It used to be <a target="_blank">; it now opens the dialog."""
    tag = re.search(r'<[^>]*id="logs-action-reports"[^>]*>', index_html)
    assert tag
    assert tag.group(0).startswith('<button')
    assert 'target="_blank"' not in tag.group(0)


def test_no_dialog_uses_flex_class_juggling():
    """`hidden` and `flex` are both Tailwind display utilities; toggling them
    made the winner depend on stylesheet order. .app-modal is flex via CSS and
    .app-modal.hidden wins, so nothing should add/remove `flex` any more."""
    import pathlib
    js_dir = pathlib.Path(__file__).resolve().parents[1] / 'static' / 'js'
    offenders = []
    for path in js_dir.rglob('*.js'):
        text = path.read_text()
        for token in ("classList.add('flex')", 'classList.add("flex")',
                      "classList.remove('flex')", 'classList.remove("flex")'):
            if token in text:
                offenders.append(f'{path.name}: {token}')
    assert offenders == []


def test_every_dialog_route_goes_through_the_shared_helpers():
    """Legacy call sites used to toggle `hidden` directly, which bypassed the
    open-order stack (Escape could close the wrong dialog)."""
    import pathlib
    js_dir = pathlib.Path(__file__).resolve().parents[1] / 'static' / 'js'
    core = (js_dir / 'app-core.js').read_text()
    assert 'window.openAppModal' in core and 'window.closeAppModal' in core
    assert 'openModal(settingsModal)' in core
    assert 'openModal(hostModal)' in core
    assert 'openModal(logSelectionModal)' in core
    assert 'openModal(aiAnalysisModal)' in core
    assert 'openModal(serverReportModal)' in core

    wizard = (pathlib.Path(__file__).resolve().parents[1] / 'templates' / 'wizard.html').read_text()
    assert "window.openAppModal('wizardModal')" in wizard
    assert "window.closeAppModal('wizardModal')" in wizard

    alerts_js = (js_dir / 'alerts.js').read_text()
    assert "window.openAppModal('rule-modal')" in alerts_js
    assert "window.closeAppModal('rule-modal')" in alerts_js


def test_rule_editor_uses_shared_chrome(flask_app):
    body = flask_app.test_client().get('/alerts').data.decode()
    assert 'id="rule-modal" class="app-modal hidden"' in body
    assert 'app-modal-panel' in body and 'app-modal-close' in body
    assert 'modals.js' in body


def test_panels_are_tall_by_default():
    """The Docker dialog looked right because its iframe filled a tall panel.
    A max-height alone lets the panel shrink to its content, so every panel
    now carries a height and short forms opt out with .app-modal-fit."""
    import pathlib
    css = (pathlib.Path(__file__).resolve().parents[1] / 'static' / 'css' / 'style.css').read_text()
    panel = re.search(r'\.app-modal-panel \{[^}]*\}', css).group(0)
    assert 'height: 92vh' in panel
    assert 'max-height: 92vh' in panel
    assert '.app-modal-panel.app-modal-fit' in css
    fit = re.search(r'\.app-modal-panel\.app-modal-fit \{[^}]*\}', css).group(0)
    assert 'height: auto' in fit
    # phone layout fills the screen in both axes
    mobile = re.search(r'@media \(max-width: 640px\) \{.*?\n\}', css, re.S).group(0)
    assert 'height: 100vh' in mobile


def test_short_forms_use_the_fit_modifier(index_html):
    """Add/Edit Host, Edit Monitor and the alert rule editor are short forms;
    they should not stretch to 92vh with empty space under the fields."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    assert index_html.count('app-modal-fit') == 1   # host (monitor edit was removed)
    alerts = (root / 'templates' / 'alerts.html').read_text()
    assert 'app-modal-panel app-modal-md app-modal-fit' in alerts
    # rich dialogs stay tall
    for modal_id in ('dockerModal', 'reportsModal', 'ai-analysis-modal', 'server-report-modal'):
        block = _modal_block(index_html, modal_id)
        assert 'app-modal-fit' not in block, modal_id
