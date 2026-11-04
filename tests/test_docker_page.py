"""The Docker Information page: sidebar status, fleet share, update check.

These all sit on top of the SSH/socket transports the rest of dockermon tests,
so every test fakes the snapshot and asserts the endpoint layer's contract.
"""

import time

import pytest

import dockermon.endpoints as ep
import dockermon.sshstats as ss
import dockermon.routes as routes


def container(name, state='running', cpu=1.0, mem=100, net_rx=0, net_tx=0,
              size_rw=1000, image='img:tag', stack=None, service=None):
    return {
        'id': name.ljust(64, '0')[:64], 'short_id': name[:12], 'name': name,
        'image': image, 'image_tag': 'tag', 'state': state, 'status': 'Up',
        'stack': stack, 'service': service,
        'cpu_percent': cpu, 'mem_used': mem, 'mem_percent': 5.0,
        'net_rx': net_rx, 'net_tx': net_tx, 'size_rw': size_rw,
        'node': 'n1',
    }


def _snap(**over):
    snap = {
        'stats': {
            'cpu_percent': 25.0, 'cpu_cores': 4,
            'mem_used': 512, 'mem_total': 1024,
            'disk_used': 10, 'disk_total': 100,
            'net_rx_bps': 10.0, 'net_tx_bps': 5.0,
            'containers_running': 2, 'containers_total': 2,
            'docker_df': {
                'images': {'count': 2, 'size': 40.0, 'reclaimable': 0.0},
                'containers': {'count': 2, 'size': 5.0, 'reclaimable': 0.0},
                'volumes': {'count': 1, 'size': 5.0, 'reclaimable': 0.0},
                'build_cache': {'count': 0, 'size': 0.0, 'reclaimable': 0.0},
            },
            'swarm': False, 'node_name': 'solo', 'ts': 123.0,
        },
        'containers': [
            container('a.1', cpu=10.0, mem=256, net_rx=1000, net_tx=500),
            container('b.1', cpu=10.0, mem=256, net_rx=2000, net_tx=1000),
        ],
        'nodes': [],
    }
    snap.update(over)
    return snap


@pytest.fixture()
def fake_host(ctx, monkeypatch, host):
    monkeypatch.setattr(ep, 'discover_host', lambda host_key, tcp_ports=(2375, 2376): {
        'host_key': host_key, 'friendly_name': 'test-host', 'ip': '10.0.0.10',
        'reachable': True, 'mode': 'socket', 'port': None,
        'server_version': '27.0.0', 'error': None})
    # The endpoint row a real discovery would have written.
    monkeypatch.setattr(routes, '_known_endpoints', lambda: {
        host: {'is_reachable': True, 'mode': 'socket', 'port': None}})
    snap = _snap()
    monkeypatch.setattr(ss, 'snapshot', lambda host_key, **kw: snap)
    monkeypatch.setattr(routes, '_snapshot_ssh', lambda host_key, info, max_age=None: snap)
    # `docker system df` has its own cached SSH call; the fake serves it.
    monkeypatch.setattr(routes, '_docker_df',
                        lambda host_key, info, transport, client: snap['stats'].get('docker_df') or {})
    routes._snapshot_cache.clear()
    routes._fleet_rate_cache.clear()
    return host, snap


# ---------------------------------------------------------------- overview --

def test_overview_lists_a_docker_host(client, fake_host):
    host, _ = fake_host
    body = client.get('/api/docker/overview').get_json()
    assert body['success'] is True
    assert host in body['hosts']
    row = body['hosts'][host]
    assert row['docker'] is True
    # no scan has run yet: status is unknown, not a false "ok"
    assert row['status'] in ('unknown', 'ok')


def test_overview_reflects_cached_update_scan(client, fake_host, monkeypatch):
    import dockermon.updates as dupdates
    host, _ = fake_host
    dupdates._store(host, {
        'host_key': host, 'containers_checked': 2, 'took': 1.2,
        'updates': [{'container': 'a.1', 'name': 'a', 'image': 'img:tag',
                     'update_available': True}],
        'attention': [], 'attention_only': [], 'error': None, 'ts': 123.0,
    })
    row = client.get('/api/docker/overview').get_json()['hosts'][host]
    assert row['status'] == 'attention'
    assert row['updates'] == 1
    assert row['containers'] == 2


def test_overview_unknown_scan_does_not_claim_ok(client, fake_host, monkeypatch):
    import dockermon.updates as dupdates
    host, _ = fake_host
    dupdates._store(host, {
        'host_key': host, 'containers_checked': 0, 'updates': [],
        'attention': [], 'attention_only': [], 'error': 'SSH timeout', 'ts': 1.0,
    })
    row = client.get('/api/docker/overview').get_json()['hosts'][host]
    assert row['status'] == 'unknown'
    assert row['error'] == 'SSH timeout'


# ------------------------------------------------------------------- fleet --

def test_fleet_reports_the_docker_share_of_the_host(client, fake_host):
    host, _ = fake_host
    body = client.get(f'/api/docker/hosts/{host}/fleet').get_json()
    assert body['success'] is True
    # 20% of 4 cores = 20%; 512 of 1024 bytes = 50%
    # docker stats is a percentage of one core: 20% on a 4 core host is 5% of
    # the machine, and that is the number the pane must show.
    assert body['docker']['cpu_percent'] == 5.0
    assert body['pct']['cpu'] == 5.0
    assert body['pct']['ram'] == 50.0
    # docker system df totals: 40 + 5 + 5 = 50 of a 100 disk
    assert body['docker']['disk_used'] == 50
    assert body['pct']['storage'] == 50.0
    assert body['docker']['containers'] == 2
    assert body['docker']['running'] == 2


def test_fleet_net_is_a_share_of_host_traffic(client, fake_host):
    host, snap = fake_host
    # Container counters are cumulative, so a rate only exists between two
    # samples. Seed the previous sample one second back with zero counters.
    snap['stats']['net_rx_bps'] = 9000.0
    snap['stats']['net_tx_bps'] = 4500.0
    routes._fleet_rate_cache[host] = (time.time() - 1.0, 0, 0)
    # 3000 rx + 1500 tx over ~1s = 4500 B/s of a 13500 B/s host = 33.3%
    body = client.get(f'/api/docker/hosts/{host}/fleet').get_json()
    assert body['pct']['net'] == pytest.approx(33.3, abs=1.0)
    assert body['docker']['net_rx_bps'] > 0


def test_fleet_with_no_containers_is_zero_not_null(client, fake_host):
    host, snap = fake_host
    snap['containers'] = []
    snap['stats']['docker_df'] = {}
    body = client.get(f'/api/docker/hosts/{host}/fleet').get_json()
    assert body['docker']['containers'] == 0
    assert body['pct']['cpu'] == 0.0
    assert body['pct']['storage'] == 0.0


def test_fleet_unknown_host_is_404(client):
    res = client.get('/api/docker/hosts/does-not-exist/fleet')
    assert res.status_code == 404
    assert res.get_json()['success'] is False


# ----------------------------------------------------------------- updates --

def test_updates_lists_containers_and_marks_moves(client, fake_host, monkeypatch):
    import dockermon.updates as dupdates
    host, _ = fake_host

    def fake_for(host_key, containers, run, refresh=False):
        return {
            'host_key': host_key, 'containers_checked': len(containers),
            'took': 0.5, 'error': None,
            'containers': [{'container': c['name'], 'name': c['name'],
                            'image': c['image'], 'update_available': c['name'] == 'a.1'}
                           for c in containers],
            'updates': [{'container': 'a.1', 'name': 'a.1', 'image': 'img:tag',
                         'update_available': True}],
            'attention': [], 'attention_only': [], 'ts': 123.0,
        }
    monkeypatch.setattr(dupdates, 'updates_for', fake_for)
    monkeypatch.setattr(dupdates, 'runner_for', lambda info: (lambda *a, **k: ''))

    body = client.get(f'/api/docker/hosts/{host}/updates').get_json()
    assert body['success'] is True
    assert body['containers_checked'] == 2
    assert len(body['updates']) == 1


def test_updates_refresh_queues_a_scan(client, fake_host, monkeypatch):
    import dockermon.updates as dupdates
    host, _ = fake_host
    seen = []
    monkeypatch.setattr(dupdates, 'stale', lambda key, max_age=0: True)
    monkeypatch.setattr(dupdates, 'scan_host', lambda app, key: seen.append(key))
    res = client.post(f'/api/docker/hosts/{host}/updates/refresh')
    assert res.status_code == 200
    assert res.get_json()['success'] is True
    assert seen == [host]


def test_updates_refresh_unknown_host_is_404(client):
    assert client.post('/api/docker/hosts/does-not-exist/updates/refresh').status_code == 404


# ------------------------------------------------------------- page render --

def test_docker_page_renders(client, fake_host):
    host, _ = fake_host
    html = client.get(f'/docker/{host}').get_data(as_text=True)
    assert 'Docker' in html
    # The three panes the Docker Information view needs.
    assert 'container-list' in html
    assert 'chart-cpu' in html
    assert 'chart-net' in html
