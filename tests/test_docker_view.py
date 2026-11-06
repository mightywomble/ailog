"""The Docker Information view, as the frontend promises it.

These are the same kind of source assertions the rest of the UI suite uses: the
view is a few hundred lines of template string, so the cheap way to keep its
contract honest is to assert the wiring that the request is about - the square's
position and state, the docker-only analysis scope, the fleet pane, the in-app
update dialog, and the wizard hand-off for *new* services only.
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


def test_the_square_is_docker_blue_and_not_a_traffic_light():
    """A button that changes colour to report status is a status in a button.

    The Docker square used to be green when nothing needed doing and red when
    an image had moved on - on every host, including the four workers that
    cannot see the cluster and so could not answer the question at all. It
    identifies Docker now, in Docker blue, in every theme.
    """
    css = _read('static', 'css', 'ui.css')
    assert '.hc-docker[data-state="ok"]' not in css
    assert '.hc-docker[data-state="attention"]' not in css
    # the colour rule (the second block for this selector, after the sizing one)
    at = css.index('#hosts-sidebar .host-card .hc-docker {', css.index('#hosts-sidebar .host-card .hc-docker {' ) + 1)
    block = css[at:]
    block = block[:block.index('}')]
    assert 'var(--docker)' in block
    assert 'var(--ok)' not in block and 'var(--bad)' not in block

    theme = _read('static', 'css', 'theme.css')
    assert '--docker: #2496ed' in theme            # one brand colour, every theme

    js = _read('static', 'js', 'app-core.js')
    block = js[js.index('const applyDockerBadge'):js.index('const refreshDockerBadges')]
    # the tooltip says what the host runs, not what is wrong with it
    assert 'row.updates' not in block
    assert 'container${row.containers === 1' in block


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
    row = view[view.index('xl:grid-cols-3'):view.index('id="docker-updates-card"')]
    assert 'docker-analyse-btn' in row
    assert 'docker-fleet' in row
    for label in ('CPU', 'RAM', 'NET', 'STORAGE'):
        assert f"fleetCard('{label}'" in view, label
    assert 'id="docker-fleet"' in view


def test_the_updates_pane_updates_the_container_you_clicked():
    view = _docker_view()
    assert 'id="docker-updates-list"' in view
    assert 'id="docker-updates-count"' in view
    assert 'id="docker-updates-refresh"' in view
    block = view[view.index('const targetFor = (row)'):view.index('const renderDockerLog =')]
    # the row carries the image and the container it is about, so the update is
    # addressed at those and nothing else on the host
    assert 'image: row.image' in block
    assert 'container: row.name' in block
    # the action opens ailog's own dialog, in place
    assert 'data-update-image="${escapeHtml(row.image' in block
    assert 'data-update-container="${escapeHtml(row.name' in block
    assert 'data-wizard-open' not in block
    assert 'wizardLink(' not in block
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
    # the remaining hand-off (a new service) goes through the frame helper,
    # which is what keeps the user in the app and carries the Exit button;
    # updates no longer go to the wizard at all
    assert 'window.openWizardModal' in view
    assert "openWizard(wizardLink('new'" in view
    assert "window.open(wizardLink('new'" not in view
    assert "wizardLink('update'" not in view
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
