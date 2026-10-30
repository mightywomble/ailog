"""Homescreen changes: brand = home, uniform host tiles, honest reachability.

Three things are pinned here:

* the metrics command always exits 0, so a host without Docker is not called
  offline (that was the bug behind six "offline" hosts that answered SSH);
* a reachable host with no ``/proc`` is online-without-metrics rather than down;
* the sidebar cards carry a status dot, an OS glyph, a Docker mark and an SSH
  prompt, all fed by the metrics poll rather than a hard-coded green dot.
"""

from __future__ import annotations

import re
from pathlib import Path

from metrics import collect

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / 'static' / 'js'
CSS = ROOT / 'static' / 'css'
TEMPLATES = ROOT / 'templates'


def _read(*parts):
    return ROOT.joinpath(*parts).read_text()


# ---------------------------------------------------------------- collector

def test_the_metrics_command_cannot_fail_on_a_host_without_docker():
    """``ok`` means exit 0; the last section is a probe, not a requirement."""
    assert collect.build_command().rstrip().endswith('; true')


def test_the_command_asks_for_the_os():
    cmd = collect.build_command()
    assert 'uname -s' in cmd
    assert '/etc/os-release' in cmd
    assert 'os' in collect.SECTIONS


def test_os_families_are_recognised():
    assert collect._os_family('Linux\nID=ubuntu\nPRETTY_NAME="Ubuntu 24.04"') == {
        'family': 'linux', 'id': 'ubuntu', 'name': 'Ubuntu 24.04'}
    assert collect._os_family('Darwin')['family'] == 'darwin'
    assert collect._os_family('FreeBSD')['family'] == 'bsd'
    assert collect._os_family('')['family'] == 'unknown'


def test_a_snapshot_carries_the_os_family(monkeypatch):
    from tests.test_metrics import sample_output

    monkeypatch.setattr(collect, '_run', lambda host, cmd, timeout=20: (True, sample_output()))
    snap = collect.system_snapshot({'key': 'os1', 'name': 'web', 'ip': '10.0.0.9'})
    assert 'os' in snap


# ---------------------------------------------------------------- the sidebar

def test_the_logo_is_a_link_home():
    html = _read('templates', 'index.html')
    assert 'class="brand-home"' in html
    assert 'data-brand-home' in html
    assert 'href="/"' in html
    js = _read('static', 'js', 'app-core.js')
    assert "querySelectorAll('[data-brand-home]')" in js
    assert 'showDashboard();' in js
    # a click must not reload the page; the href is only the no-JS fallback
    assert 'event.preventDefault();' in js


def test_host_cards_are_uniform_tiles_with_the_four_corners():
    js = _read('static', 'js', 'app-core.js')
    for part in ('hc-corner', 'hc-dot', 'hc-os', 'hc-main', 'hc-docker', 'hc-ssh'):
        assert f'class="{part}' in js, part
    assert 'host-card-name' in js
    # one fixed shape, not a card that grows with the text
    css = _read('static', 'css', 'ui.css')
    block = css[css.index('#hosts-sidebar .host-card {'):css.index('#hosts-sidebar .host-card .hc-main')]
    assert 'min-height: 88px' in block
    assert 'justify-content: center' in block


def test_the_card_name_is_centred_and_the_meta_is_small():
    css = _read('static', 'css', 'ui.css')
    block = css[css.index('#hosts-sidebar .host-card {'):css.index('/* top-left')]
    assert 'text-align: center' in block
    assert 'hc-sub' in block


def test_the_ssh_prompt_opens_the_existing_terminal():
    js = _read('static', 'js', 'app-core.js')
    assert 'data-hc-ssh' in js
    assert "querySelector('[data-hc-ssh]')" in js
    block = js[js.index("card.querySelector('[data-hc-ssh]')"):]
    block = block[:block.index('// Drag/drop reordering')]
    assert 'selectHost(hostId);' in block
    assert 'openSshTerminal();' in block
    assert 'event.stopPropagation();' in block          # pressing it must not select twice
    # there is no SSH session to open on the app's own machine
    assert "hostId === 'local' ? ''" in js
    assert 'is-green' not in js


def test_the_dot_reflects_the_poll_not_a_constant():
    js = _read('static', 'js', 'app-core.js')
    assert 'const syncHostStatuses' in js
    assert "'/api/metrics/servers'" in js
    assert "dot.dataset.state = up ? 'up' : 'down'" in js
    assert 'snapshot.os?.family' in js
    assert 'snapshot.docker && snapshot.docker.installed' in js
    assert 'HOST_STATUS_POLL_MS' in js
    assert 'document.hidden' in js
    # the old hard-coded indicator is gone
    assert 'connection-indicator' not in js
    assert 'bg-green-500 animate-pulse' not in js


def test_status_decorates_cards_without_re_rendering_them():
    """A refresh must not destroy drag order, focus or selection."""
    js = _read('static', 'js', 'app-core.js')
    block = js[js.index('const applyHostStatus'):js.index('window.refreshHostStatuses')]
    assert 'card.querySelector' in block
    assert 'card.innerHTML' not in block          # the tile itself is never rebuilt
    # only the badge node is redrawn, from a constant, never from server text
    assert 'os.innerHTML = badge.html' in block
    assert 'os.textContent = badge.text' in block


def test_the_rail_keeps_only_the_dot_and_the_name():
    css = _read('static', 'css', 'ui.css')
    rail = css[css.index('/* Icon rail (tablet)'):]
    for hidden in ('.hc-os', '.hc-docker', '.hc-ssh', '.hc-sub'):
        assert hidden in rail
    # the removed monogram must not linger
    assert 'host-monogram' not in css


def test_the_new_host_styles_use_tokens():
    css = _read('static', 'css', 'ui.css')
    block = css[css.index('#hosts-sidebar .host-card {'):css.index('/* Icon rail (tablet)')]
    assert not re.search(r'#[0-9a-fA-F]{3,8}\b', block)
    assert 'var(--ok)' in block and 'var(--bad)' in block


def test_each_socket_owns_its_handlers():
    """The wrong-server bug: a replaced socket's close/error tore down the new one."""
    js = _read('static', 'js', 'app-core.js')
    block = js[js.index('const connectSshSocket'):js.index('const openSshTerminal')]
    assert 'const sock = new WebSocket(wsUrl);' in block
    assert 'const isCurrent = () => sshSocket === sock;' in block
    for handler in ('sock.onopen', 'sock.onmessage', 'sock.onclose', 'sock.onerror'):
        assert handler in block, handler
    assert block.count('if (!isCurrent()) return;') >= 4
    # and the connection is opened on the captured socket, not the shared one
    assert 'sock.send(JSON.stringify({' in block
    assert 'sshSocket.send(JSON.stringify({' not in block

    close = js[js.index('const closeSshSocket'):js.index('const connectSshSocket')]
    for detach in ('sock.onopen = null', 'sock.onmessage = null',
                   'sock.onerror = null', 'sock.onclose = null'):
        assert detach in close, detach


def test_the_ssh_button_opens_the_host_on_the_card():
    js = _read('static', 'js', 'app-core.js')
    block = js[js.index("card.querySelector('[data-hc-ssh]')"):]
    block = block[:block.index('// Drag/drop reordering')]
    # select then open, in that order, with the same id
    assert block.index('selectHost(hostId)') < block.index('openSshTerminal()')
    # and the reopen path closes the old socket cleanly before dialling
    assert 'closeSshSocket();\n\n            // Everything below closes over' in js


def test_ubuntu_hosts_get_the_ubuntu_mark():
    js = _read('static', 'js', 'app-core.js')
    assert 'const OS_BADGES' in js
    assert 'ubuntu:' in js
    assert '<circle cx="12" cy="12" r="8.4"/>' in js       # circle of friends
    assert 'const osBadge = (os)' in js
    assert "String(os?.id || '').toLowerCase()" in js
    assert 'osBadge(snapshot.os)' in js
    # a distro we have a mark for wins over the generic penguin
    block = js[js.index('const osBadge = (os)'):js.index('const applyHostStatus')]
    assert 'OS_BADGES[distro]' in block


def test_the_badges_are_a_little_bigger():
    css = _read('static', 'css', 'ui.css')
    block = css[css.index('#hosts-sidebar .host-card .hc-os {'):css.index('/* bottom-left: Docker mark')]
    assert 'font-size: 1.1rem' in block
    assert 'width: 18px; height: 18px' in block
    assert '.hc-dot' in css[css.index('#hosts-sidebar .host-card .hc-dot {'):][:200]
    assert 'width: 9px' in css[css.index('#hosts-sidebar .host-card .hc-dot {'):][:200]
