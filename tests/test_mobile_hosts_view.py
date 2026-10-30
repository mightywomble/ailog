"""Phone card-first hosts view.

On a touch device the first screen is a grid of host tiles: the green ``>_``
opens the SSH terminal full screen, the tile body opens a slim detail sheet.
Desktop keeps the sidebar + dashboard untouched.
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


def _sheet_js():
    js = _js()
    return js[js.index('function closeMobileHostSheet'):js.index('const applyHostStatus')]


# ------------------------------------------------------------------ markup

def test_the_phone_grid_view_exists_and_starts_hidden():
    html = _read('templates', 'index.html')
    assert 'id="mobile-hosts-view"' in html
    assert 'class="mobile-hosts hidden"' in html
    assert 'id="mobile-host-cards"' in html
    assert 'id="mobile-hosts-sub"' in html
    assert 'id="mobile-hosts-refresh"' in html


def test_the_detail_sheet_exists_with_two_actions():
    html = _read('templates', 'index.html')
    assert 'id="mobile-host-sheet"' in html
    assert 'role="dialog"' in html and 'aria-modal="true"' in html
    assert 'id="mh-sheet-title"' in html and 'id="mh-sheet-facts"' in html
    assert 'id="mh-sheet-ssh"' in html and 'id="mh-sheet-logs"' in html
    assert 'id="mh-sheet-close"' in html


# ------------------------------------------------------------------ layout

def test_the_grid_is_gated_on_touch_viewports_only():
    css = _css()
    block = css[css.index('.mobile-hosts { display: none; }'):]
    head = block[:block.index('/* ------------------------------------------------ slim host detail sheet')]
    assert '@media (max-width: 640px), (max-width: 900px) and (pointer: coarse)' in head
    # and the js uses the same queries so the first view is chosen consistently
    js = _js()
    assert "window.matchMedia('(max-width: 640px)')" in js
    assert "window.matchMedia('(max-width: 900px) and (pointer: coarse)')" in js
    assert 'PHONE_QUERY.matches || TOUCH_QUERY.matches' in js


def test_two_columns_on_a_phone_and_three_when_unfolded():
    css = _css()
    block = css[css.index('.mh-grid {'):]
    block = block[:block.index('/* Tiles reuse')]
    assert 'grid-template-columns: repeat(2, minmax(0, 1fr))' in block
    assert 'grid-template-columns: repeat(3, minmax(0, 1fr))' in block


def test_the_tiles_are_thumb_sized():
    css = _css()
    block = css[css.index('#mobile-host-cards .host-card {'):]
    block = block[:block.index('/* ------------------------------------------------ slim host detail sheet')]
    assert 'min-height: 116px' in block
    ssh = block[block.index('.hc-ssh {'):]
    ssh = ssh[:ssh.index('}')]
    assert 'width: 44px' in ssh and 'height: 44px' in ssh
    assert 'touch-action: manipulation' in ssh


def test_the_sheet_actions_are_touch_sized_and_carry_the_safe_area():
    css = _css()
    assert '.mh-sheet-close {' in css and 'width: 44px' in css[css.index('.mh-sheet-close {'):][:400]
    action = css[css.index('.mh-action {'):]
    action = action[:action.index('.mh-action-primary')]
    assert 'min-height: 48px' in action
    panel = css[css.index('.mh-sheet-panel {'):][:500]
    assert 'env(safe-area-inset-bottom' in panel


def test_the_mobile_styles_use_semantic_tokens():
    css = _css()
    block = css[css.index('.mobile-hosts { display: none; }'):]
    assert not re.search(r'#[0-9a-fA-F]{3,8}\b', block)
    assert 'var(--ok)' in block and 'var(--bad)' in block


# ------------------------------------------------------------------- wiring

def test_both_mounts_use_the_same_card_factory():
    js = _js()
    populate = js[js.index('const populateHostCards = async ()'):js.index('window.refreshHostsSidebar')]
    assert 'createHostCard(id, host)' in populate
    assert "createHostCard(id, host, 'mobile')" in populate
    assert "createHostCard('local', {" in populate
    # the same localhost tile, with the mobile variant
    assert populate.count("'mobile')") >= 2


def test_the_first_screen_depends_on_the_pointer():
    js = _js()
    populate = js[js.index('const populateHostCards = async ()'):js.index('window.refreshHostsSidebar')]
    init = populate[populate.index('Showing the initial view'):]
    assert 'if (isMobileLayout()) showMobileHosts();' in init
    assert 'else window.showDashboard();' in init


def test_the_desktop_view_is_unchanged_by_the_phone_grid():
    js = _js()
    show = js[js.index('const showDashboard = () => {'):js.index('// --------------------------------------------------------- phone grid')]
    assert 'dashboardView.classList.remove' in show
    assert 'mobileHostsView?.classList.add' in show
    css = _css()
    # the sidebar tiles keep their own, separate rules
    assert '#hosts-sidebar .host-card {' in css
    assert 'min-height: 88px' in css[css.index('#hosts-sidebar .host-card {'):][:300]


def test_the_hosts_tab_opens_the_grid_not_the_drawer():
    shell = _read('static', 'js', 'shell.js')
    assert "'mobile-hosts-view'" in shell
    tab = shell[shell.index("tab === 'hosts'"):]
    tab = tab[:tab.index("tab === 'monitor'")]
    assert 'window.showMobileHosts()' in tab
    assert 'setOpen(true)' in tab.split('showMobileHosts')[0] or 'setOpen(true)' not in tab
    assert "tab === 'hosts' && view === 'mobile-hosts-view'" in shell
    js = _js()
    assert 'window.showMobileHosts = showMobileHosts;' in js


def test_the_sheet_writes_text_only():
    block = _sheet_js()
    assert 'innerHTML' not in block
    for writer in ('mhSheetTitle.textContent', 'mhSheetSub.textContent',
                   'mhSheetStatus.textContent', 'mhSheetFacts.textContent'):
        assert writer in block, writer
    assert 'document.createElement' in block      # facts are built node by node


def test_the_sheet_hides_ssh_for_the_local_machine():
    block = _sheet_js()
    assert "mhSheetSsh.classList.toggle('hidden', hostId === 'local')" in block


def test_the_ssh_button_expands_the_terminal_on_a_phone():
    js = _js()
    block = js[js.index('const sshIntoHost'):js.index('mhSheetClose?.addEventListener')]
    assert block.index('selectHost(hostId)') < block.index('await openSshTerminal()')
    assert 'if (isMobileLayout()) window.ailogSsh?.expand();' in block

    tile = js[js.index("card.querySelector('[data-hc-ssh]')"):]
    tile = tile[:tile.index('// Drag/drop reordering')]
    assert 'closeMobileHostSheet();' in tile
    assert tile.index('closeMobileHostSheet();') < tile.index('sshIntoHost(hostId)')


def test_tapping_the_tile_body_opens_the_sheet_on_a_phone():
    js = _js()
    handler = js[js.index('card.addEventListener(\'click\''):]
    handler = handler[:handler.index("card.querySelector('[data-hc-ssh]')")]
    assert 'if (isMobileCard) openMobileHostSheet(hostId);' in handler
    assert 'else selectHost(hostId);' in handler


def test_the_poll_decorates_both_mounts():
    js = _js()
    poll = js[js.index('const syncHostStatuses = async'):js.index('window.refreshHostStatuses')]
    assert '[hostListContainer, mobileHostCards].forEach' in poll
    assert 'applyHostStatus(card, byKey.get(card.dataset.hostId))' in poll
    assert 'mobileHostsSub.textContent' in poll
    # a phone grid alone must not be blocked by an empty sidebar
    assert 'mobileHostCards && mobileHostCards.children.length' in poll


def test_the_layout_listeners_swap_views_without_a_reload():
    js = _js()
    block = js[js.index('const onLayoutChange = () => {'):js.index('const showLogs = () => {')]
    assert 'if (isMobileLayout()) {' in block
    assert 'showMobileHosts()' in block
    assert 'showDashboard()' in block
    assert "PHONE_QUERY.addEventListener?.('change', onLayoutChange);" in js
    assert "TOUCH_QUERY.addEventListener?.('change', onLayoutChange);" in js


def test_the_grid_is_the_scroll_container_on_a_phone():
    """Bug: the grid was not part of the shell's view rules, so the last rows
    were clipped by the fixed-height shell with no way to reach them."""
    css = _read('static', 'css', 'shell.css')
    scroll = css[css.index('/* the view container keeps its own scroll */'):]
    scroll = scroll[:scroll.index('/* ---------------------------------------------------------------- header')]
    assert '#mobile-hosts-view' in scroll
    assert 'overflow: auto' in scroll
    placement = css[css.index('.app-body > #dashboard-view,'):]
    placement = placement[:placement.index('/* the view container keeps')]
    assert '#mobile-hosts-view' in placement
    assert 'grid-column: 2' in placement
    # the sidebar is a fixed overlay on a phone: one full-width column
    phone = css[css.index('  /* the sidebar is fixed here, so the view owns the whole single column */'):]
    assert '.app-body > #mobile-hosts-view { grid-column: 1 / -1; grid-row: 1; }' in phone[:200]
