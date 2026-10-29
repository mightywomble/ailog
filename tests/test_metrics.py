"""Tests for the live monitoring page (metrics/) and its wiring.

The collectors are exercised against captured ``/proc`` output and a fake
``_run`` so no SSH is needed; the routes are exercised through Flask's test
client with ``collect.system_snapshot`` monkeypatched.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from metrics import collect, routes as metrics_routes


@pytest.fixture(scope='module')
def index_html():
    return (Path(__file__).resolve().parents[1] / 'templates' / 'index.html').read_text()

ROOT = Path(__file__).resolve().parents[1]

PROC_STAT = """cpu  1000 0 500 8000 500 0 0 0 0 0
cpu0 500 0 250 4000 250 0 0 0 0 0
cpu1 500 0 250 4000 250 0 0 0 0 0
"""

PROC_MEMINFO = """MemTotal:       16384000 kB
MemFree:         2048000 kB
MemAvailable:    4096000 kB
SwapTotal:       2048000 kB
SwapFree:        2048000 kB
"""

PROC_NETDEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  500000    1000    0    0    0     0          0         0   500000    1000    0    0    0     0       0          0
  eth0: 2000000    3000    0    0    0     0          0         0  1000000    2000    0    0    0     0       0          0
"""

DF = """Filesystem     1024-blocks      Used Available Capacity Mounted on
/dev/sda1         100000000  40000000  60000000      40% /
"""


def sample_output(stat=PROC_STAT, mem=PROC_MEMINFO, net=PROC_NETDEV, df=DF,
                  load='0.50 0.40 0.30 2/100 1234', up='86400.00 700000.00',
                  host='web-01', docker='yes',
                  dstate='running\nrunning\nexited\nAILOG_DOCKER_OK'):
    parts = []
    for name, value in (('stat', stat), ('mem', mem), ('net', net), ('df', df),
                        ('load', load), ('up', up), ('host', host),
                        ('docker', docker), ('dstate', dstate)):
        parts.append(f'{collect.MARK}:{name}\n{value.strip()}')
    return '\n'.join(parts)


# --------------------------------------------------------------- command

def test_command_carries_every_section_marker():
    cmd = collect.build_command()
    for name in collect.SECTIONS:
        assert f'{collect.MARK}:{name}' in cmd
    assert 'cat /proc/stat' in cmd and 'df -kP /' in cmd
    # docker presence is probed without needing the daemon
    assert 'command -v docker' in cmd


def test_parse_system_reads_counters_and_meta():
    raw = collect.parse_system(sample_output())
    assert raw['cpu_total'] == 10000 and raw['cpu_idle'] == 8500
    assert raw['mem_total'] == 16384000 * 1024
    assert raw['mem_used'] == (16384000 - 4096000) * 1024
    assert raw['swap_used'] == 0 and raw['swap_total'] == 2048000 * 1024
    # loopback is excluded from the totals
    assert raw['rx'] == 2000000 and raw['tx'] == 1000000
    assert raw['disk_total'] == 100000000 * 1024
    assert raw['disk_used'] == 40000000 * 1024
    assert raw['load1'] == 0.5 and raw['load15'] == 0.3
    assert raw['uptime'] == 86400.0
    assert raw['hostname'] == 'web-01'
    assert raw['docker_installed'] is True
    assert raw['docker_reachable'] is True
    assert raw['docker_running'] == 2 and raw['docker_total'] == 3


def test_parse_system_reports_docker_daemon_failures():
    raw = collect.parse_system(sample_output(dstate=''))
    assert raw['docker_installed'] is True
    assert raw['docker_reachable'] is False
    assert raw['docker_total'] == 0


def test_parse_system_tolerates_missing_sections():
    raw = collect.parse_system(f'{collect.MARK}:host\nbox\n')
    assert raw['cpu_total'] == 0 and raw['mem_total'] == 0
    assert raw['docker_installed'] is False
    assert raw['hostname'] == 'box'


# ------------------------------------------------------------ snapshots

@pytest.fixture(autouse=True)
def _clean():
    collect.reset_caches()
    metrics_routes._cache.update({'ts': 0.0, 'payload': None})
    yield
    collect.reset_caches()


def test_system_snapshot_first_sample_has_no_rates(monkeypatch):
    monkeypatch.setattr(collect, '_run', lambda host, cmd, timeout=20: (True, sample_output()))
    snap = collect.system_snapshot({'key': 'h1', 'friendly_name': 'web', 'ip': '10.0.0.5'})
    assert snap['online'] is True
    assert snap['cpu']['percent'] is None          # counter, needs a delta
    assert snap['net']['rx_bps'] is None
    assert snap['cpu']['cores'] == 2               # aggregate line excluded
    assert snap['mem']['percent'] == pytest.approx(75.0, abs=0.1)
    assert snap['disk']['percent'] == pytest.approx(40.0)
    assert snap['docker_installed'] is True


def test_system_snapshot_second_sample_computes_percent_and_rates(monkeypatch):
    clock = {'t': 1000.0}
    monkeypatch.setattr(collect.time, 'time', lambda: clock['t'])
    monkeypatch.setattr(collect, '_run', lambda host, cmd, timeout=20: (True, sample_output()))
    collect.system_snapshot({'key': 'h2', 'name': 'web', 'ip': '10.0.0.6'})

    clock['t'] = 1010.0
    second = sample_output(
        stat='cpu  1200 0 500 8800 500 0 0 0 0 0\ncpu0 600 0 250 4400 250 0 0 0 0 0\ncpu1 600 0 250 4400 250 0 0 0 0 0\n',
        net=PROC_NETDEV.replace('2000000    3000', '4000000    6000')
                          .replace('1000000    2000', '2000000    4000'),
    )
    monkeypatch.setattr(collect, '_run', lambda host, cmd, timeout=20: (True, second))
    snap = collect.system_snapshot({'key': 'h2', 'name': 'web', 'ip': '10.0.0.6'})

    # total ticks +1000, idle +800 -> 200/1000 busy = 20%
    assert snap['cpu']['percent'] == pytest.approx(20.0, abs=0.01)
    # 2,000,000 bytes over 10s
    assert snap['net']['rx_bps'] == pytest.approx(200000.0, rel=1e-3)
    assert snap['net']['tx_bps'] == pytest.approx(100000.0, rel=1e-3)


def test_system_snapshot_offline_on_command_failure(monkeypatch):
    monkeypatch.setattr(collect, '_run', lambda host, cmd, timeout=20: (False, 'Permission denied'))
    snap = collect.system_snapshot({'key': 'h3', 'friendly_name': 'dead', 'ip': '10.0.0.7'})
    assert snap['online'] is False
    assert 'Permission denied' in snap['error']
    assert snap['host_key'] == 'h3'


def test_system_snapshot_offline_when_no_proc_data(monkeypatch):
    monkeypatch.setattr(collect, '_run', lambda host, cmd, timeout=20: (True, ''))
    snap = collect.system_snapshot({'key': 'h4', 'name': 'weird', 'ip': '10.0.0.8'})
    assert snap['online'] is False
    assert 'no /proc data' in snap['error']


# ----------------------------------------------------------- containers

def _fake_docker_snapshot(containers):
    return {'stats': {'engine_version': '27.0.0'}, 'containers': containers, 'ts': 0}


def test_container_snapshot_shapes_rows_and_rates(monkeypatch):
    from dockermon import routes as docker_routes
    containers = [
        {'id': 'b' * 64, 'name': 'idle', 'state': 'exited', 'cpu_percent': 0,
         'mem_used': 0, 'mem_limit': 0, 'net_rx': 0, 'net_tx': 0},
        {'id': 'a' * 64, 'name': 'api', 'state': 'running', 'cpu_percent': 12.5,
         'mem_used': 50 * 1024 * 1024, 'mem_limit': 200 * 1024 * 1024,
         'net_rx': 1000, 'net_tx': 0, 'size_rw': 2048,
         'stack': 'web', 'service': 'web_api'},
    ]
    monkeypatch.setattr(docker_routes, 'host_snapshot', lambda key: _fake_docker_snapshot(containers))

    clock = {'t': 500.0}
    monkeypatch.setattr(collect.time, 'time', lambda: clock['t'])
    first = collect.container_snapshot('db-1')
    assert first['reachable'] is True
    assert [c['name'] for c in first['containers']] == ['api', 'idle']   # running first
    api = first['containers'][0]
    assert api['mem_percent'] == pytest.approx(25.0)
    assert api['disk_used'] == 2048
    assert api['net_rx_bps'] is None        # first sample seeds the cache

    clock['t'] = 502.0
    containers[1]['net_rx'] = 5000
    second = collect.container_snapshot('db-1')
    api2 = second['containers'][0]
    assert api2['net_rx_bps'] == pytest.approx(2000.0)


def test_container_snapshot_reports_unreachable_engine(monkeypatch):
    from dockermon import routes as docker_routes

    def boom(key):
        raise RuntimeError('Docker over SSH failed: timeout')

    monkeypatch.setattr(docker_routes, 'host_snapshot', boom)
    data = collect.container_snapshot('db-2')
    assert data['reachable'] is False
    assert 'timeout' in data['error']
    assert data['containers'] == []


# --------------------------------------------------------------- routes

def test_metrics_page_and_embed_mode(flask_app):
    client = flask_app.test_client()
    plain = client.get('/metrics')
    embedded = client.get('/metrics?embed=1')
    assert plain.status_code == 200 and embedded.status_code == 200
    assert 'btn-back' in plain.data.decode()
    assert 'btn-back' not in embedded.data.decode()
    assert '/static/js/metrics-page.js' in plain.data.decode()
    assert '/static/css/metrics.css' in plain.data.decode()


def test_api_servers_reports_stats_and_docker_block(flask_app, monkeypatch):
    seen = []

    def fake_snapshot(host):
        seen.append(host['key'])
        return {
            'host_key': host['key'], 'name': host['friendly_name'], 'ip': host['ip'],
            'ts': 1.0, 'online': True, 'error': None, 'uptime': 3600,
            'docker_installed': True,
            'cpu': {'percent': 12.0, 'cores': 4, 'load1': 0.1, 'load5': 0.2, 'load15': 0.3},
            'mem': {'used': 1, 'total': 2, 'percent': 50.0, 'swap_used': 0, 'swap_total': 0},
            'disk': {'used': 1, 'total': 4, 'percent': 25.0, 'mount': '/'},
            'net': {'rx': 10, 'tx': 20, 'rx_bps': 1.0, 'tx_bps': 2.0},
        }

    monkeypatch.setattr(metrics_routes.collect, 'system_snapshot', fake_snapshot)
    client = flask_app.test_client()
    data = client.get('/api/metrics/servers').get_json()
    assert data['success'] is True
    assert data['servers'], 'expected at least the local host'
    server = data['servers'][0]
    for key in ('host_key', 'name', 'ip', 'online', 'cpu', 'mem', 'disk', 'net', 'docker'):
        assert key in server
    assert server['cpu']['percent'] == 12.0
    assert set(server['docker']) == {'installed', 'reachable', 'containers_running',
                                     'containers_total', 'engine_version'}
    assert server['docker']['installed'] is True
    assert server['docker']['reachable'] is False   # fake snapshot has no counts


def test_api_servers_is_cached_between_polls(flask_app, monkeypatch):
    calls = {'n': 0}

    def fake_snapshot(host):
        calls['n'] += 1
        return {'host_key': host['key'], 'name': host['friendly_name'], 'ip': host['ip'],
                'ts': 1.0, 'online': True, 'error': None, 'docker_installed': False,
                'cpu': {'percent': None, 'cores': 1}, 'mem': {}, 'disk': {}, 'net': {}}

    monkeypatch.setattr(metrics_routes.collect, 'system_snapshot', fake_snapshot)
    client = flask_app.test_client()
    client.get('/api/metrics/servers')
    first = calls['n']
    client.get('/api/metrics/servers')
    assert calls['n'] == first, 'second poll should be served from the cache'
    client.get('/api/metrics/servers?refresh=1')
    assert calls['n'] > first, 'refresh=1 must bypass the cache'


def test_api_containers_requires_a_host(flask_app):
    resp = flask_app.test_client().get('/api/metrics/containers')
    assert resp.status_code == 400
    assert 'host' in resp.get_json()['error']


def test_api_containers_returns_rows(flask_app, monkeypatch):
    monkeypatch.setattr(metrics_routes.collect, 'container_snapshot',
                        lambda key: {'reachable': True, 'error': None,
                                     'engine_version': '27.0.0',
                                     'containers': [{'id': 'x', 'name': 'api'}]})
    data = flask_app.test_client().get('/api/metrics/containers?host=db-1').get_json()
    assert data['success'] is True and data['host_key'] == 'db-1'
    assert data['containers'][0]['name'] == 'api'
    assert data['engine_version'] == '27.0.0'


def test_blueprint_is_registered(app_module):
    assert 'metrics' in app_module.app.blueprints
    rules = {r.rule for r in app_module.app.url_map.iter_rules()}
    assert {'/metrics', '/api/metrics/servers', '/api/metrics/containers'} <= rules


# ---------------------------------------------------------------- wiring

def test_monitoring_button_opens_the_metrics_dialog(index_html):
    block = re.search(r'<div id="metricsModal" class="app-modal hidden">.*?</div>\s*</div>', index_html, re.S)
    assert block, 'metricsModal markup missing'
    assert 'metricsModalFrame' in block.group(0)
    assert '/static/' not in block.group(0)          # src is set by JS, not markup
    assert 'about:blank' in block.group(0)
    assert 'app-modal-close' in block.group(0)

    button = re.search(r'<button[^>]*id="logs-action-monitor"[^>]*>(.*?)</button>', index_html, re.S)
    assert button and 'Monitoring' in button.group(1)


def test_old_monitoring_ui_is_gone(index_html):
    core = (ROOT / 'static' / 'js' / 'app-core.js').read_text()

    # the legacy monitor list/editor and its hand-rolled overlay
    assert 'showHostMonitoringMain' not in core
    assert 'selectedMonitorIds' not in core
    assert 'monitor-edit-modal' not in core
    assert 'monitoring-modal-overlay' not in index_html
    assert 'monitor-edit-modal' not in index_html

    # the button now opens the dialog, and it exists in the modal module
    assert 'openMetricsModal' in core
    modals = (ROOT / 'static' / 'js' / 'iframe-modals.js').read_text()
    assert "openFrame('metricsModal'" in modals
    assert '/metrics?embed=1' in modals
    assert 'metricsModalFrame' in modals


def test_metrics_page_polls_and_expands_docker_cards():
    js = (ROOT / 'static' / 'js' / 'metrics-page.js').read_text()
    assert '/api/metrics/servers' in js
    assert '/api/metrics/containers' in js
    assert 'HISTORY' in js
    # docker badge + expand behaviour
    assert 'is-docker' in js and 'is-expanded' in js
    assert 'dockerInstalled' in js
    # charts are plain canvas, no external chart library
    assert 'getContext' in js
    assert 'Chart' not in js.replace('m-ctable', '')
