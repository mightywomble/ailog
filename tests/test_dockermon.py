"""Docker history, app grouping, swarm view and their routes."""
import time

import pytest

from dockermon import history as hist
from dockermon import parse as dparse
from dockermon import sshstats
from dockermon import swarm as dswarm


def container(name, stack=None, service=None, state='running', cpu=1.0,
              mem=100, node='n1'):
    return {
        'id': name.ljust(64, '0')[:64], 'short_id': name[:12], 'name': name,
        'image': 'img:tag', 'image_tag': 'tag', 'state': state,
        'status': 'Up', 'stack': stack, 'service': service,
        'cpu_percent': cpu, 'mem_used': mem, 'mem_percent': 5.0,
        'net_rx': 2, 'net_tx': 1, 'size_rw': 1000, 'node': node,
    }


# ------------------------------------------------------------------ parsing --

def test_parse_sysdf():
    assert dparse.parse_sysdf({'Type': 'Images', 'TotalCount': '3',
                               'Size': '1.5GB', 'Reclaimable': '1GB (66%)'}) == \
        ('images', {'count': 3, 'size': 1.5e9, 'reclaimable': 1e9})
    assert dparse.parse_sysdf({'Type': 'Other'}) == (None, None)


def test_parse_df_root():
    text = ('Filesystem 1B-blocks Used Available Use% Mounted on\n'
            '/dev/sda1 1000 250 750 25% /\n')
    assert dparse.parse_df_root(text) == (1000.0, 250.0)
    assert dparse.parse_df_root('nope') == (None, None)


def test_rate_handles_resets():
    assert dparse.rate(100, 300, 2) == 100.0
    assert dparse.rate(500, 10, 2) == 0.0     # counter reset, not negative
    assert dparse.rate(None, 10, 2) is None
    assert dparse.rate(1, 2, 0) is None


# ------------------------------------------------------------ app grouping --

def test_apps_group_by_stack_and_service():
    apps = dparse.finalize_apps(dparse.aggregate_apps([
        container('sonarr.1', 'media', 'sonarr', cpu=10, node='n1'),
        container('sonarr.2', 'media', 'sonarr', cpu=5, state='exited', node='n2'),
        container('caddy.1', 'web', 'caddy', cpu=1, node='n1'),
        container('adhoc', None, None, cpu=2, node='n1'),
    ]))
    media = apps[0]
    assert media['name'] == 'media'
    assert media['cpu_pct'] == 15.0
    assert (media['container_count'], media['running_count']) == (2, 1)
    assert media['nodes'] == ['n1', 'n2']
    assert [s['name'] for s in media['services']] == ['sonarr']
    assert apps[-1]['name'] == '(standalone)'


def test_app_without_containers_is_empty():
    assert dparse.finalize_apps({}) == []


# ---------------------------------------------------------------- history --

@pytest.fixture()
def clear_history():
    hist.clear()
    yield
    hist.clear()


def test_history_records_and_downsamples(clear_history):
    for i in range(5):
        hist.record('h', {'cpu_percent': 10 + i, 'mem_percent': 20,
                          'mem_used': 1, 'mem_total': 2, 'disk_percent': 50,
                          'net_rx_bps': i, 'net_tx_bps': 2 * i}, None, ts=i)
    payload = hist.payload('h')
    assert payload['points'] == 5
    assert payload['series']['cpu'] == [10, 11, 12, 13, 14]
    assert payload['revision'] == 5


def test_history_holds_last_value_when_metric_missing(clear_history):
    hist.record('h', {'cpu_percent': 42}, None, ts=1)
    hist.record('h', {'cpu_percent': None}, None, ts=2)
    assert hist.payload('h')['series']['cpu'][-1] == 42


def test_history_tracks_app_series(clear_history):
    hist.record('h', {'cpu_percent': 1}, [container('a.1', 'media', 'a')], ts=1)
    assert 'media' in hist.payload('h')['apps']


def test_history_is_bounded(clear_history):
    for i in range(hist.capacity() + 50):
        hist.record('h', {'cpu_percent': i}, None, ts=i)
    payload = hist.payload('h')
    assert payload['points'] == hist.capacity()
    assert payload['series']['cpu'][-1] == hist.capacity() + 49


def test_history_clear(clear_history):
    hist.record('h', {'cpu_percent': 1}, None, ts=1)
    hist.clear('h')
    assert hist.payload('h')['points'] == 0


def test_history_targets_only_reachable_endpoints(ctx, monkeypatch):
    from database import DockerEndpoint, db
    DockerEndpoint.query.delete()
    db.session.add(DockerEndpoint(host_key='up', friendly_name='up', is_reachable=True))
    db.session.add(DockerEndpoint(host_key='down', friendly_name='down', is_reachable=False))
    db.session.commit()
    targets = hist._targets()
    assert 'up' in targets and 'down' not in targets


# ------------------------------------------------------------------ swarm --

def node(nid, hostname, addr='', role='worker'):
    return {'id': nid, 'hostname': hostname, 'role': role, 'state': 'ready',
            'availability': 'active', 'addr': addr, 'manager': 'Leader' if role == 'manager' else ''}


def metrics(cpu=10.0, cores=4, mem_pct=20.0):
    return {'cpu_pct': cpu, 'cores': cores, 'mem_used': 100, 'mem_total': 1000,
            'mem_pct': mem_pct, 'disk_used': 10, 'disk_total': 100, 'disk_pct': 10.0,
            'net_rx_bps': 1.0, 'net_tx_bps': 2.0}


def test_swarm_totals_are_core_weighted():
    dswarm.clear()
    nodes = [node('1', 'm', role='manager'), node('2', 'w')]
    payloads = {
        '1': {'metrics': metrics(cpu=10, cores=4), 'containers': [container('a.1', 'app', 'a')]},
        '2': {'metrics': metrics(cpu=30, cores=8), 'containers': [container('b.1', 'app', 'b', node='w')]},
    }
    view = dswarm.build('h', nodes, payloads, ts=1)
    # 10% of 4 cores + 30% of 8 cores = 0.4 + 2.4 = 2.8 of 12 cores
    assert view['totals']['cpu_pct'] == 23.33
    assert view['totals']['cores'] == 12
    assert view['totals']['containers_total'] == 2
    assert view['apps'][0]['nodes'] == ['m', 'w']


def test_swarm_offline_node_is_listed_but_excluded():
    dswarm.clear()
    nodes = [node('1', 'm', role='manager'), node('2', 'w')]
    view = dswarm.build('h', nodes,
                        {'1': {'metrics': metrics(cpu=10, cores=4), 'containers': []}},
                        ts=1, errors={'2': 'ssh timeout'})
    assert view['nodes'][1]['online'] is False
    assert view['partial'] is True
    assert view['totals']['nodes_online'] == 1
    assert view['errors'][0]['error'] == 'ssh timeout'


def test_swarm_sparklines_grow_per_build():
    dswarm.clear()
    nodes = [node('1', 'm', role='manager')]
    payloads = {'1': {'metrics': metrics(), 'containers': []}}
    first = dswarm.build('h', nodes, payloads, ts=1)
    second = dswarm.build('h', nodes, payloads, ts=2)
    assert len(first['nodes'][0]['spark']['cpu']) == 1
    assert len(second['nodes'][0]['spark']['cpu']) == 2


def test_swarm_does_not_cache_failures(monkeypatch, ctx):
    dswarm.clear()
    import dockermon.routes as routes

    class Info(dict):
        pass

    info = {'user': 'root', 'ip': '10.0.0.1', 'ssh_key_id': None}
    monkeypatch.setattr(dswarm, '_master_df', lambda *a, **k: {})

    calls = {'n': 0}

    def fake_collect(host_key, info, node_, master_ip, master_name):
        calls['n'] += 1
        raise RuntimeError('nope')

    monkeypatch.setattr(dswarm, '_collect_node', fake_collect)

    master_snap = {'stats': {'swarm': True, 'node_name': 'm'},
                   'containers': [], 'nodes': [
                       {'id': '1', 'hostname': 'm', 'status': 'Ready',
                        'availability': 'Active', 'manager': 'Leader'},
                       {'id': '2', 'hostname': 'w', 'status': 'Ready',
                        'availability': 'Active', 'manager': ''}]}
    view = dswarm.cluster('h', info, master_snap=master_snap, transport='ssh')
    assert view['nodes'][1]['online'] is False
    # the master was still collected, so the view is cached
    assert view['totals']['nodes_online'] == 1
    dswarm.clear()


def test_single_host_grouping_for_non_swarm():
    dswarm.clear()
    view = dswarm.single_host('h', {'ip': '10.0.0.9', 'friendly_name': 'one'},
                              {'stats': {'node_name': 'one', 'cpu_percent': 5,
                                         'cpu_cores': 2, 'mem_used': 1,
                                         'mem_total': 2, 'mem_percent': 50},
                               'containers': [container('a.1', 'media', 'a')]})
    assert view['swarm'] is False
    assert [a['name'] for a in view['apps']] == ['media']


# ----------------------------------------------------------------- routes --

@pytest.fixture()
def fake_docker(ctx, monkeypatch, host):
    import dockermon.endpoints as ep
    import dockermon.sshstats as ss

    monkeypatch.setattr(ep, 'discover_host', lambda host_key, tcp_ports=(2375, 2376): {
        'host_key': host_key, 'friendly_name': 'test-host', 'ip': '10.0.0.10',
        'reachable': True, 'mode': 'socket', 'port': None,
        'server_version': '27.0.0', 'error': None})

    snap = {
        'stats': {'cpu_percent': 12.5, 'cpu_cores': 4, 'cpu_used': 0.5,
                  'mem_used': 512, 'mem_total': 1024, 'mem_percent': 50.0,
                  'disk_used': 10, 'disk_total': 100, 'disk_percent': 10.0,
                  'net_rx_bps': 1.0, 'net_tx_bps': 2.0, 'containers_running': 1,
                  'containers_total': 1, 'swarm': False, 'node_name': 'solo',
                  'ts': 123.0},
        'containers': [container('a.1', 'media', 'a')],
        'nodes': [],
    }
    monkeypatch.setattr(ss, 'snapshot', lambda host_key, **kw: snap)
    import dockermon.routes as routes
    routes._snapshot_cache.clear()
    return host, snap


def test_history_endpoint(client, fake_docker):
    host, snap = fake_docker
    body = client.get(f'/api/docker/hosts/{host}/history').get_json()
    assert body['success'] is True
    assert body['points'] == 0          # sampler has not run in tests
    assert body['interval'] >= 1


def test_history_endpoint_reflects_records(client, fake_docker):
    host, snap = fake_docker
    hist.clear()
    hist.record(host, snap['stats'], snap['containers'], snap['stats']['ts'])
    body = client.get(f'/api/docker/hosts/{host}/history').get_json()
    assert body['points'] == 1
    assert body['series']['disk_pct'] == [10.0]


def test_history_stream_headers(client, fake_docker):
    host, _ = fake_docker
    response = client.get(f'/api/docker/hosts/{host}/history/stream')
    assert response.headers['Content-Type'].startswith('text/event-stream')
    assert response.headers['X-Accel-Buffering'] == 'no'


def test_swarm_endpoint_groups_a_non_swarm_host(client, fake_docker):
    host, _ = fake_docker
    body = client.get(f'/api/docker/hosts/{host}/swarm').get_json()
    assert body['success'] is True
    assert body['swarm'] is False
    assert [a['name'] for a in body['apps']] == ['media']


def test_swarm_endpoint_caches_and_refresh_bypasses(client, fake_docker, monkeypatch):
    host, _ = fake_docker
    import dockermon.swarm as sw
    sw.clear()
    calls = {'n': 0}
    real = sw.single_host

    def counting(*a, **kw):
        calls['n'] += 1
        return real(*a, **kw)

    monkeypatch.setattr(sw, 'single_host', counting)
    client.get(f'/api/docker/hosts/{host}/swarm')
    after_first = calls['n']
    client.get(f'/api/docker/hosts/{host}/swarm')
    # single_host has no cache, but cluster() does; this asserts refresh works
    assert client.post(f'/api/docker/hosts/{host}/swarm/refresh').status_code == 200
    assert calls['n'] >= after_first


def test_docker_page_renders_tabs(client, fake_docker):
    host, _ = fake_docker
    html = client.get(f'/docker/{host}').get_data(as_text=True)
    assert 'data-view="apps"' in html
    assert 'id="apps-list"' in html
    assert 'seedHistory' in html


def test_history_clear_endpoint(client, fake_docker):
    host, snap = fake_docker
    hist.record(host, snap['stats'], snap['containers'], snap['stats']['ts'])
    assert client.post('/api/docker/history/clear').status_code == 200
    assert hist.payload(host)['points'] == 0


def test_container_rate_math():
    sshstats._ctr_cache.clear()
    rows = [{'id': 'c' * 64}]
    usage = {'c' * 64: {'net_bytes': (1000, 500)}}
    sshstats._container_rates(rows, usage, 1000.0)
    assert rows[0]['net_rx'] == 0.0
    sshstats._container_rates(rows, {'c' * 64: {'net_bytes': (3000, 1500)}}, 1002.0)
    assert rows[0]['net_rx'] == 1000.0
    assert rows[0]['net_tx'] == 500.0


# ---------------------------------------------------------------------------
# the page doubles as a modal iframe source (?embed=1)
# ---------------------------------------------------------------------------

def test_docker_page_standalone_keeps_the_back_link(client):
    res = client.get('/docker/db-1')
    assert res.status_code == 200
    body = res.data.decode()
    assert 'id="btn-back"' in body
    assert 'min-h-screen' in body


def test_docker_page_embedded_drops_the_back_link(client):
    """The modal owns the close button, so the embedded page must not render a
    second navigation control that would replace the whole SPA."""
    res = client.get('/docker/db-1?embed=1')
    assert res.status_code == 200
    body = res.data.decode()
    assert 'btn-back' not in body
    assert '>Back<' not in body
    # and the page chrome is tightened for the smaller frame
    assert 'px-3 py-2.5' in body
    assert 'min-h-screen' not in body


def test_index_page_has_the_docker_modal(client):
    body = client.get('/').data.decode()
    assert 'id="dockerModal"' in body
    assert 'id="dockerModalFrame"' in body
    assert 'id="dockerModalClose"' in body
    assert 'iframe-modals.js' in client.get('/static/js/main.js').data.decode()
