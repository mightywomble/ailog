"""Phone log screen: log sources as cards, one log in a full-screen reader.

The phone is card-first. A host's sources are a single scrolling list of cards
(Pull logs / AI analyse host in the header), and tapping a card opens the log
full screen with AI analyse and share in the dialog header.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(*parts):
    return ROOT.joinpath(*parts).read_text()


def _js():
    return _read('static', 'js', 'app-core.js')


def _css():
    return _read('static', 'css', 'ui.css')


def _phone_logs_js():
    js = _js()
    return js[js.index('// ------------------------------------------------- phone log screen'):
              js.index("        mhSheetClose?.addEventListener('click', closeMobileHostSheet);")]


# ------------------------------------------------------------------ markup

def test_the_phone_log_screen_has_pull_and_analyse_host_buttons():
    html = _read('templates', 'index.html')
    view = html[html.index('id="mobile-logs-view"'):html.index('id="logs-view"')]
    assert 'id="mobile-logs-pull"' in view
    assert 'Pull logs' in view
    assert 'id="mobile-logs-analyse"' in view
    assert 'AI analyse host' in view
    assert 'id="mobile-log-cards"' in view
    assert 'id="mobile-logs-back"' in view
    assert 'id="mobile-logs-sub"' in view


def test_a_log_opens_in_a_full_screen_dialog_with_analyse_and_share():
    html = _read('templates', 'index.html') + _read('templates', 'partials', 'mobile-sheets.html')
    modal = html[html.index('id="mobile-log-modal"'):]
    modal = modal[:modal.index('id="mobile-host-sheet"')]
    assert 'class="app-modal hidden"' in modal
    assert 'data-modal-close' in modal                 # the one owner closes it
    assert 'id="mlog-name"' in modal and 'id="mlog-sub"' in modal
    assert 'id="mlog-analyse"' in modal
    assert 'id="mlog-share"' in modal
    assert 'id="mlog-pre"' in modal
    assert 'app-modal-body' in modal                   # scrolls


def test_the_sheet_sends_you_to_the_log_cards():
    html = _read('templates', 'partials', 'mobile-sheets.html')
    assert 'Logs &amp; analyse' in html


# ------------------------------------------------------------------ behaviour

def test_the_phone_logs_screen_is_a_scroll_container_too():
    css = _read('static', 'css', 'shell.css')
    scroll = css[css.index('/* the view container keeps its own scroll */'):]
    scroll = scroll[:scroll.index('/* ---------------------------------------------------------------- header')]
    assert '#mobile-logs-view' in scroll
    placement = css[css.index('.app-body > #dashboard-view,'):]
    placement = placement[:placement.index('/* the view container keeps')]
    assert '#mobile-logs-view' in placement
    phone = css[css.index('/* the sidebar is fixed here, so the view owns the whole single column */'):]
    assert '.app-body > #mobile-logs-view { grid-column: 1 / -1; grid-row: 1; }' in phone[:260]


def test_the_lines_route_through_the_phone_screen():
    js = _js()
    show_logs = js[js.index('const showLogs = () => {'):js.index('if (logsActionPull)')]
    assert 'if (isMobileLayout()) {' in show_logs
    assert 'showMobileLogs();' in show_logs
    # selectHost()'s default action must not paint the desktop info pane over it
    select = js[js.index('const selectHost = (hostId) => {'):js.index('const showHostInfoMain = async')]
    assert 'if (isMobileLayout()) showMobileLogs();' in select
    assert 'else showHostInfoMain();' in select


def test_the_cards_are_built_from_the_same_stream_as_the_desktop_list():
    js = _js()
    append = js[js.index('const appendSourceToList = (source) => {'):js.index('// Show/hide pulled sources')]
    assert 'mobileLogCards.appendChild(createMobileLogCard(source));' in append
    assert 'mobileLogsPulling' in append
    block = _phone_logs_js()
    assert 'function createMobileLogCard(source)' in block
    assert "card.className = 'ml-card';" in block
    assert "card.setAttribute('role', 'listitem');" in block
    assert 'openMobileLogModal(source)' in block


def test_the_tally_says_it_is_still_running():
    block = _phone_logs_js()
    assert 'so far' in block
    assert 'tap one to read it' in block


def test_the_pull_rearms_and_explains_an_empty_or_failed_pull():
    block = _phone_logs_js()
    assert 'function startMobilePull()' in block
    assert 'mobileLogsPull.disabled = true;' in block
    assert 'function finishMobilePull(' in block
    assert 'mobileLogsPull.disabled = false;' in block
    assert 'ml-empty' in block
    js = _js()
    assert 'finishMobilePull();' in js            # complete
    assert 'finishMobilePull(data.message' in js  # error carries the reason


def test_a_second_showlogs_does_not_start_a_second_stream():
    block = _phone_logs_js()
    assert 'if (changed) startMobilePull();' in block
    assert "else if (!mobileLogsPulling && !mobileLogCards?.querySelector('.ml-card')) startMobilePull();" in block


def test_the_log_body_is_text_only():
    block = _phone_logs_js()
    modal_fn = block[block.index('const openMobileLogModal'):block.index("mobileLogsBack?.addEventListener")]
    assert 'mlogPre.textContent = mobileLogText' in modal_fn
    assert 'mlogPre.textContent' in modal_fn
    assert '.innerHTML' not in modal_fn
    assert 'data.will_be_truncated' in modal_fn


def test_analyse_in_the_dialog_runs_the_same_pipeline():
    js = _js()
    assert 'const runAiAnalysis = async ({ logName, content, button = null } = {}) => {' in js
    assert 'aiAnalyseBtn.addEventListener(\'click\', () => runAiAnalysis({' in js
    block = _phone_logs_js()
    assert "mlogAnalyse?.addEventListener('click', () => runAiAnalysis({" in block
    assert 'content: mobileLogText,' in block
    # the desktop pipeline is now provider-agnostic about which button it drives
    assert "button.querySelector('span')" in js


def test_share_prefers_the_android_share_sheet_then_the_clipboard():
    js = _js()
    block = js[js.index('const shareText = async'):js.index('// One analysis pipeline for both surfaces')]
    assert 'navigator.share({ title, text: body })' in block
    assert "err.name === 'AbortError'" in block
    assert 'navigator.clipboard.writeText(body)' in block
    assert 'copyTextFallback' in block
    # wired both to the log itself and to the finished analysis
    b = _phone_logs_js()
    assert "mlogShare?.addEventListener('click', () => shareText(" in b
    assert "aiAnalysisShare?.addEventListener('click', () => shareText(" in b
    assert 'lastAnalysisText = result.analysis' in js


def test_the_analysis_dialog_has_a_share_button():
    html = _read('templates', 'partials', 'ai-analysis.html')
    assert 'id="ai-analysis-share"' in html
    assert 'ai-analysis-content' in html


def test_the_ssh_expand_button_is_gone_on_a_phone():
    css = _css()
    phone = css[css.index('@media (max-width: 640px) {\n  .ssh-modal-panel'):]
    assert '#ssh-terminal-expand-btn' in phone[:600]
    assert '#ssh-terminal-contract-btn' in phone[:600]
    assert 'display: none' in phone[:600]


# --------------------------------------------------------------------- style

def test_the_log_cards_are_thumb_sized_and_tokenized():
    css = _css()
    block = css[css.index("/* ------------------------------------------------ phone: a host's log files"):]
    assert not re.search(r'#[0-9a-fA-F]{3,8}\b', block)
    card = block[block.index('.ml-card {'):block.index('.ml-glyph {')]
    assert 'min-height: 68px' in card
    assert 'var(--surface-2)' in card
    buttons = block[block.index('.mlv-btn {'):block.index('.mlv-btn[disabled]')]
    assert 'min-height: 48px' in buttons
    panel = block[block.index('.ml-panel {'):][:220]
    assert '100dvh' in panel and 'border-radius: 0' in panel
    assert 'env(safe-area-inset-bottom' in block


def test_the_logs_tab_knows_the_phone_screen():
    shell = _read('static', 'js', 'shell.js')
    assert "'mobile-logs-view'" in shell
    assert "view === 'mobile-logs-view'" in shell


# ------------------------------------------------------- the soft keyboard

def test_the_ssh_dialog_uses_the_visual_viewport():
    """A fixed dialog is sized to the layout viewport, which the keyboard does
    not shrink: the prompt ended up behind it."""
    js = _js()
    assert 'const syncVisualViewport = () => {' in js
    assert "window.visualViewport.addEventListener('resize'" in js
    assert "window.visualViewport.addEventListener('scroll'" in js
    assert "root.style.setProperty('--vv-h'" in js
    assert "root.style.setProperty('--vv-top'" in js
    # xterm has to re-measure after the box changes height
    assert 'if (!sshMaximized) return;' in js
    assert 'sshTerm?.scrollToBottom();' in js

    css = _css()
    phone = css[css.index('#ssh-terminal-overlay {\n    top: var(--vv-top, 0);'):]
    assert 'height: var(--vv-h, 100dvh)' in phone[:400]
    assert 'height: calc(var(--vv-h, 100dvh) - 6px)' in phone[:800]
    assert 'env(safe-area-inset-bottom' in phone[:1200]
