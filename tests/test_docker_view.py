"""The Docker Information view, as the frontend promises it.

These are the same kind of source assertions the rest of the UI suite uses: the
view is a few hundred lines of template string, so the cheap way to keep its
contract honest is to assert the wiring that the request is about - the square's
position and state, the docker-only analysis scope, the fleet pane, and the
hand-off to the wizard.
"""

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), 'r', encoding='utf-8') as handle:
        return handle.read()


def _docker_view():
    js = _read('static', 'js', 'app-core.js')
    start = js.index('// --------------------------------------------------------- Docker view')
    end = js.index('window.showDockerInfoMain = showDockerInfoMain')
    return js[start:end]


def test_the_docker_square_sits_above_the_ssh_prompt():
    js = _read('static', 'js', 'app-core.js')
    card = js[js.index('card.innerHTML = `'):js.index('// Desktop: clicking the card selects the host')]
    # both actions live in one column, Docker first
    assert 'hc-actions' in card
    assert card.index('data-hc-docker') < card.index('data-hc-ssh')
    css = _read('static', 'css', 'ui.css')
    actions = css[css.index('#hosts-sidebar .host-card .hc-actions {'):]
    actions = actions[:actions.index('}')]
    assert 'flex-direction: column' in actions


def test_the_square_is_green_when_idle_and_red_when_something_needs_doing():
    css = _read('static', 'css', 'ui.css')
    assert '.hc-docker[data-state="ok"]' in css
    assert '.hc-docker[data-state="attention"]' in css
    js = _read('static', 'js', 'app-core.js')
    block = js[js.index('const applyDockerBadge'):js.index('const refreshDockerBadges')]
    assert "button.dataset.state = row.status || 'unknown'" in block
    assert 'row.updates' in block and 'row.attention' in block


def test_the_badge_polls_the_overview_endpoint_not_a_live_snapshot():
    js = _read('static', 'js', 'app-core.js')
    block = js[js.index('const refreshDockerBadges'):js.index('const applyHostStatus')]
    assert "'/api/docker/overview'" in block
    assert 'DOCKER_BADGE_POLL_MS' in js
    # a stale answer is better than blocking the sidebar
    assert 'dockerOverviewInFlight' in block


def test_clicking_the_square_swaps_the_pane_not_the_host():
    js = _read('static', 'js', 'app-core.js')
    handler = js[js.index("card.querySelector('[data-hc-docker]')"):]
    handler = handler[:handler.index("card.querySelector('[data-hc-ssh]')")]
    assert 'selectHost(hostId)' in handler
    assert 'showDockerInfoMain' in handler
    assert 'event.stopPropagation()' in handler


def test_the_view_reuses_the_host_banner():
    view = _docker_view()
    assert 'Docker Information:' in view
    assert 'docker-banner-os' in view
    assert 'docker-banner-engine' in view
    assert 'docker-banner-node' in view
    # wizard-onboarded hosts also get the distro and the last update
    assert "/hosts/db/${dbId}/info" in view
    assert 'docker-banner-update' in view


def test_analyse_is_scoped_to_container_logs_only():
    view = _docker_view()
    button = view[view.index("document.getElementById('docker-analyse-btn')"):]
    button = button[:button.index('docker-add-btn')]
    # files and journal are switched off, docker and stopped are switched on
    assert "files.checked = false" in button
    assert "journal.checked = false" in button
    assert "docker.checked = true" in button
    assert 'openServerReportModal()' in button


def test_the_fleet_pane_is_next_to_the_analyse_button():
    view = _docker_view()
    assert 'id="docker-analyse-btn"' in view
    assert 'id="docker-fleet"' in view
    # the pane is in the same row, and covers all four measures
    row = view[view.index('xl:grid-cols-3'):view.index('<!-- What upstream has moved on from -->')]
    assert 'docker-analyse-btn' in row
    assert 'docker-fleet' in row
    for label in ('CPU', 'RAM', 'NET', 'STORAGE'):
        assert f"fleetCard('{label}'" in view, label
    assert 'id="docker-fleet"' in view


def test_the_updates_pane_offers_the_wizard_for_a_moving_image():
    view = _docker_view()
    assert 'id="docker-updates-list"' in view
    assert 'id="docker-updates-count"' in view
    assert 'id="docker-updates-refresh"' in view
    block = view[view.index('const linkFor = (row)'):view.index('const renderDockerLog =')]
    # wizard.yaml is keyed on the stack, so that is what the deep link carries
    assert 'row.stack || row.service || row.name' in block
    assert "wizardLink('update'" in block
    # a container that is not in wizard.yaml still has to open on itself: the
    # wizard falls back to the image, then to prefilling the add-a-service form
    assert 'image: row.image' in block
    assert 'container: row.name' in block
    # the row's action opens the dialog, in place - not a blank tab that drops
    # the user on the wizard's whole service list
    assert 'data-wizard-open="${escapeHtml(linkFor(row))}"' in block
    assert 'target="_blank"' not in block
    assert "document.getElementById('docker-updates-list')?.addEventListener('click'" in view


def test_the_log_pane_tails_follows_and_filters():
    view = _docker_view()
    assert 'id="docker-log-select"' in view
    assert 'id="docker-log-follow"' in view
    assert 'id="docker-log-filter"' in view
    assert 'id="docker-log-output"' in view
    assert '/api/docker/log/' in view
    # follow is a repeating tail, and it stops when the view changes
    assert 'setInterval' in view
    assert "logsMainMode !== 'docker'" in view


def test_leaving_the_view_stops_its_timers():
    js = _read('static', 'js', 'app-core.js')
    assert 'const stopDockerView' in js
    host_info = js[js.index("logsMainMode = 'info';", js.index('const showHostInfoMain')):]
    host_info = host_info[:host_info.index('const topPane')]
    assert 'stopDockerView()' in host_info
    pull = js[js.index("logsMainMode = 'pull';", js.index('const pullLogsForSelectedHost')):]
    pull = pull[:pull.index('const topPane')]
    assert 'stopDockerView()' in pull


def test_adding_a_container_goes_to_the_wizard():
    view = _docker_view()
    assert "WIZARD_URL" in view
    assert 'wizard.safehomelan.com' in view
    add = view[view.index("document.getElementById('docker-add-btn')"):]
    add = add[:add.index('docker-updates-refresh')]
    assert "wizardLink('new'" in add


def test_the_wizard_opens_in_the_dialog_not_a_new_tab():
    view = _docker_view()
    # both hand-offs go through the frame helper, which is what keeps the user
    # in the app (and what carries the Exit button)
    assert 'window.openWizardModal' in view
    assert "openWizard(wizardLink('new'" in view
    assert "window.open(wizardLink('new'" not in view
    # and a deploy the wizard finished refreshes what the pane shows
    assert 'window.onWizardDeployed = refreshAfterWizard' in view
    assert 'window.onWizardClosed = refreshAfterWizard' in view


def test_the_full_monitor_opens_in_the_docker_dialog():
    view = _docker_view()
    block = view[view.index('id="docker-full-monitor-btn"'):]
    block = block[:block.index('</button>')]
    assert 'full monitor' in block
    assert 'href=' not in block                      # a button, not a link
    assert "window.openDockerModal(hostId, hostName)" in view
    assert 'href="/docker/${encodeURIComponent(hostId)}" target="_blank"' not in view
