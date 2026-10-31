"""Netdata integration: parser, fleet cards, evidence, ingestion and wiring.

The live API is never called here. Payloads below are trimmed copies of real
``/api/v3/data`` and ``/api/v3/alert_transitions`` responses (v2.12 nightly),
so the parser is tested against the shapes that actually exist: the label order
changes with the ``group_by`` keys, and every cell is a 3-tuple.
"""

import json
import os

import pytest

from netdata import client as nd_client, evidence, snapshot


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture()
def http(flask_app):
    return flask_app.test_client()


def _js(name):
    return open(os.path.join(ROOT, 'static', 'js', name)).read()


def _labels_payload(labels, rows, nodes=None):
    return {
        'api': 3,
        'result': {'labels': labels, 'data': rows,
                   'after': 1793480000, 'before': 1793480300, 'update_every': 1},
        'summary': {'nodes': nodes or []},
    }


def _row(ts, *values):
    return [ts] + [[v, 0, 0] for v in values]


# --- parsing --------------------------------------------------------------

def test_group_by_node_context_labels_are_machine_guids():
    payload = _labels_payload(
        ['time', 'guid-a,system.cpu', 'guid-b,system.cpu'],
        [_row(1793480300, 12.5, 3.25)],
        [{'mg': 'guid-a', 'nm': 'build', 'nd': 'n1',
          'ds': {'qr': 3}, 'sts': {'min': 1, 'max': 20, 'avg': 9, 'arp': 1.5, 'con': 99}}],
    )
    parsed = nd_client.parse_payload(payload)
    assert parsed['labels'][0] == 'time'
    assert parsed['series']['guid-a,system.cpu']['value'] == [12.5]
    assert parsed['series']['guid-a,system.cpu']['arp'] == [0.0]
    assert parsed['timestamps'] == [1793480300]
    assert parsed['nodes']['guid-a']['name'] == 'build'
    assert parsed['nodes']['guid-a']['stats']['arp'] == 1.5


def test_dimension_labels_are_kept_and_ordered_oldest_first():
    payload = _labels_payload(
        ['time', 'user', 'system'],
        [_row(1793480300, 4.0, 2.0), _row(1793480299, 3.0, 1.0)],
    )
    parsed = nd_client.parse_payload(payload)
    assert parsed['timestamps'] == [1793480299, 1793480300]
    assert parsed['series']['user']['value'] == [3.0, 4.0]
    assert parsed['series']['system']['value'] == [1.0, 2.0]


def test_gap_sentinels_are_none_not_zero():
    parsed = nd_client.parse_payload(_labels_payload(
        ['time', 'used'], [[1793480300, [None, 0, 0]]]))
    assert parsed['series']['used']['value'] == [None]


def test_group_understands_dimension_first_and_instance_position():
    # Real v2.12 labels: ``dim,instance,guid,context`` for disk.space.
    parsed = {
        'series': {
            'used,disk_space./,guid-a,disk.space': {'value': [10.0], 'arp': [0]},
            'avail,disk_space./,guid-a,disk.space': {'value': [90.0], 'arp': [0]},
            'used,disk_space./run,guid-a,disk.space': {'value': [90.0], 'arp': [0]},
            'avail,disk_space./run,guid-a,disk.space': {'value': [10.0], 'arp': [0]},
        }
    }
    grouped = nd_client._group(parsed, ['disk.space'], ['guid-a'])
    root = nd_client._root_instance(grouped['guid-a']['disk.space'])
    assert set(root) == {'used', 'avail'}
    assert nd_client._disk_percent(root) == [10.0]


# --- fleet ----------------------------------------------------------------

CPU_PAYLOAD = {
    'series': {
        'user,guid-a,system.cpu': {'value': [10.0], 'arp': [0]},
        'system,guid-a,system.cpu': {'value': [5.0], 'arp': [0]},
        'iowait,guid-a,system.cpu': {'value': [5.0], 'arp': [0]},
    }
}
RAM_PAYLOAD = {
    'series': {
        'used,guid-a,system.ram': {'value': [2000.0], 'arp': [0]},
        'free,guid-a,system.ram': {'value': [1000.0], 'arp': [0]},
        'cached,guid-a,system.ram': {'value': [900.0], 'arp': [0]},
        'buffers,guid-a,system.ram': {'value': [100.0], 'arp': [0]},
    }
}
DISK_PAYLOAD = {
    'series': {
        'used,disk_space./,guid-a,disk.space': {'value': [40.0], 'arp': [0]},
        'avail,disk_space./,guid-a,disk.space': {'value': [60.0], 'arp': [0]},
    }
}
LOAD_PAYLOAD = {
    'series': {'load1,guid-a,system.load': {'value': [1.25], 'arp': [0]}}
}
ANOM_PAYLOAD = {
    'series': {
        'anomaly_rate,anomaly_detection.anomaly_rate_on_guid-a,guid-a,'
        'anomaly_detection.anomaly_rate': {'value': [7.5], 'arp': [0]},
        # The parent's copy comes first in the real response and is often 0;
        # the parser must pick the instance for *this* node.
        'anomaly_rate,anomaly_detection.anomaly_rate_on_parent,parent-guid,'
        'anomaly_detection.anomaly_rate': {'value': [0.0], 'arp': [0]},
    }
}


DOCKER_PAYLOAD = {
    'series': {
        'running,docker.containers.running,guid-a,docker.containers.running':
            {'value': [6.0], 'arp': [0]},
    }
}


def _fake_fetch(contexts, **kwargs):
    context = list(contexts)[0]
    return {
        'system.cpu': CPU_PAYLOAD, 'system.ram': RAM_PAYLOAD,
        'disk.space': DISK_PAYLOAD, 'system.load': LOAD_PAYLOAD,
        nd_client.DOCKER_CONTEXT: DOCKER_PAYLOAD,
        nd_client.ANOMALY_CONTEXT: ANOM_PAYLOAD,
    }.get(context, {'series': {}})


NODE_A = {
    'guid': 'guid-a', 'node_id': 'n1', 'name': 'build', 'hostname': 'build',
    'version': 'v2.12.2', 'state': 'reachable', 'online': True,
    'cores': 8, 'ram_total': 8 * 1024 ** 3, 'disk_space': 100 * 1024 ** 3,
    'os': 'Ubuntu', 'ip': '100.0.0.1', 'is_parent': False,
    'streams_to': '100.0.0.9:19999', 'unstable_connection': False,
    'alerts': {'critical': 0, 'warning': 1, 'clear': 10}, 'labels': {},
}


def test_fleet_card_calculates_saturation_and_node_anomaly(monkeypatch):
    monkeypatch.setattr(nd_client, 'nodes', lambda ttl=None: [dict(NODE_A)])
    monkeypatch.setattr(nd_client, 'fetch_data', _fake_fetch)
    fleet = nd_client.fleet_cards()
    node = fleet['nodes'][0]
    assert node['cpu_percent'] == 20.0          # 10 + 5 + 5 busy states
    assert node['mem_percent'] == 50.0          # 2000 / (2000+1000+900+100)
    assert node['disk_percent'] == 40.0
    assert node['load1'] == 1.25
    assert node['anomaly_rate'] == 7.5
    assert node['docker_installed'] is True       # context present => Docker here
    assert node['docker_running'] == 6          # not the parent instance's 0
    assert node['alerts']['warning'] == 1


# --- streaming quality / reconciliation -----------------------------------

def test_streaming_health_flags_unstable_and_missing_streams():
    quality = nd_client.streaming_health([
        {**NODE_A, 'is_parent': True, 'name': 'netdata', 'hostname': 'netdata',
         'streams_to': None},
        {**NODE_A, 'name': 'files', 'hostname': 'files', 'streams_to': None},
        {**NODE_A, 'name': 'photos', 'hostname': 'photos', 'unstable_connection': True},
        {**NODE_A, 'name': 'nfs', 'hostname': 'nfs', 'online': False},
    ])
    assert quality['parent'] == 'netdata'
    assert quality['not_streaming'] == ['files']
    assert quality['unstable'] == ['photos']
    assert quality['offline'] == ['nfs']
    assert quality['ok'] is False


def test_host_mapping_prefers_override_then_exact_name(monkeypatch):
    hosts = [{'key': 'db-1', 'name': 'swarm-manager', 'friendly_name': 'Swarm manager'},
             {'key': 'db-2', 'name': 'pve', 'friendly_name': 'Proxmox'},
             {'key': 'db-3', 'name': 'pve2', 'friendly_name': 'Proxmox 2'}]
    monkeypatch.setattr(nd_client, 'host_key_map', lambda: {})
    assert nd_client.resolve_host_key({'guid': 'g', 'name': 'pve', 'hostname': 'pve'}, hosts) == 'db-2'
    assert nd_client.resolve_host_key({'guid': 'g', 'name': 'unknown'}, hosts) is None
    monkeypatch.setattr(nd_client, 'host_key_map', lambda: {'g': 'db-3'})
    assert nd_client.resolve_host_key({'guid': 'g', 'name': 'unknown'}, hosts) == 'db-3'


def test_reconcile_lists_both_directions(monkeypatch):
    monkeypatch.setattr(nd_client, 'nodes', lambda ttl=None: [
        {**NODE_A, 'name': 'build', 'hostname': 'build'},
        {**NODE_A, 'name': 'spare', 'hostname': 'spare'},
    ])
    monkeypatch.setattr(nd_client, 'host_key_map', lambda: {})
    rec = nd_client.reconcile([{'key': 'db-1', 'name': 'build'}, {'key': 'db-2', 'name': 'old'}])
    assert rec['matched'][0]['host_key'] == 'db-1'
    assert [n['node'] for n in rec['netdata_only']] == ['spare']
    assert [h['host_key'] for h in rec['ailog_only']] == ['db-2']


# --- monitoring page adapter ---------------------------------------------

def test_snapshot_has_the_metrics_page_shape_without_ssh():
    snap = snapshot.as_snapshot({'key': 'db-7', 'friendly_name': 'Build'},
                                {**NODE_A, 'cpu_percent': 12.0, 'mem_percent': 50.0,
                                 'disk_percent': 25.0, 'load1': 0.5,
                                 'anomaly_rate': 3.0, 'series': {}})
    assert snap['host_key'] == 'db-7'
    assert snap['cpu']['percent'] == 12.0
    assert snap['mem']['used'] == NODE_A['ram_total'] // 2
    assert snap['disk']['percent'] == 25.0
    assert snap['docker_installed'] is False        # node reported no Docker
    assert snap['metrics_source'] == 'netdata'
    assert snap['anomaly_rate'] == 3.0


def test_monitoring_round_uses_netdata_and_skips_ssh(monkeypatch, ctx):
    from metrics import routes as metrics_routes
    hosts = [{'key': 'db-1', 'name': 'build', 'friendly_name': 'Build', 'ip': '10.0.0.1'}]
    monkeypatch.setattr(metrics_routes, '_host_list', lambda: hosts)
    monkeypatch.setattr(nd_client, 'configured', lambda: True)
    monkeypatch.setattr(nd_client, 'nodes', lambda ttl=None: [dict(NODE_A, name='build', hostname='build')])
    monkeypatch.setattr(nd_client, 'fetch_data', _fake_fetch)
    monkeypatch.setattr(nd_client, 'host_key_map', lambda: {})

    def must_not_ssh(host):
        raise AssertionError('SSH must not run for a Netdata-matched host')

    monkeypatch.setattr(metrics_routes.collect, 'system_snapshot', must_not_ssh)
    payload = metrics_routes.collect_servers()
    assert payload['source']['source'] == 'netdata'
    assert payload['servers'][0]['host_key'] == 'db-1'
    assert payload['servers'][0]['metrics_source'] == 'netdata'


def test_netdata_only_keys_are_explicitly_refused_by_container_api(monkeypatch, http):
    from netdata import snapshot as snap_mod
    assert snap_mod.is_netdata_key('nd:files')
    body = http.get('/api/metrics/containers?host=nd:files').get_json()
    assert body['reachable'] is False
    assert 'Netdata-only' in body['error']


# --- evidence and the pack ------------------------------------------------

def test_evidence_renders_metrics_alerts_and_quality(monkeypatch):
    monkeypatch.setattr(nd_client, 'configured', lambda: True)
    monkeypatch.setattr(nd_client, '_ailog_hosts', lambda: [{'key': 'db-1', 'name': 'build'}])
    monkeypatch.setattr(nd_client, 'nodes', lambda ttl=None: [dict(NODE_A, name='build', hostname='build')])
    monkeypatch.setattr(nd_client, 'fetch_data', _fake_fetch)
    monkeypatch.setattr(nd_client, 'alert_transitions', lambda **kw: {'transitions': [{
        'id': 't1', 'when': 1793480300, 'guid': 'guid-a', 'hostname': 'build',
        'alert': 'ram_usage', 'status': 'WARNING', 'value': 91.0, 'units': '%',
        'summary': 'RAM usage high', 'instance': 'system.ram', 'context': 'system.ram',
    }]})
    monkeypatch.setattr(nd_client, 'streaming_health', lambda nodes=None: {
        'nodes': 1, 'parent': 'netdata', 'offline': [], 'unstable': [],
        'not_streaming': [], 'ok': True})

    data = evidence.for_host('db-1', 'build', 60)
    assert data['available'] is True
    lines = '\\n'.join(evidence.render(data))
    assert '--- METRICS (Netdata' in lines
    assert 'CPU busy: avg 20.0% max 20.0% now 20.0%' in lines
    assert '--- NETDATA ALERTS IN WINDOW ---' in lines
    assert 'ram_usage' in lines
    assert '91%' in lines


def test_evidence_is_optional_when_netdata_is_down(monkeypatch):
    monkeypatch.setattr(nd_client, 'configured', lambda: False)
    data = evidence.for_host('db-1', 'build', 60)
    assert data['available'] is False
    assert evidence.render(data) == []


def test_pack_adds_the_metrics_section_without_changing_log_sections():
    from serverreport import pack
    metrics = {'available': True, 'node': 'build', 'window_minutes': 60,
               'metrics': {'system.cpu': {'avg': 10.0, 'max': 20.0, 'last': 12.0}},
               'contexts': {}, 'alerts': [], 'quality': {}}
    text = pack.build_pack('build', {'clusters': [], 'source_stats': []},
                           {'window': {}, 'correlations': [], 'bursts': [], 'gaps': []},
                           {}, [], depth=1, metrics=metrics)
    assert '--- METRICS (Netdata' in text
    assert '--- COVERAGE ---' in text
    assert text.index('--- METRICS') < text.index('--- COVERAGE')


# --- alert ingestion ------------------------------------------------------

def _transition(tid='t1', status='WARNING', when=1793480300):
    return {'id': tid, 'when': when, 'guid': 'guid-a', 'hostname': 'build',
            'alert': 'ram_usage', 'instance': 'system.ram', 'context': 'system.ram',
            'status': status, 'value': 91.0, 'units': '%',
            'summary': 'RAM usage high', 'info': 'info', 'classification': 'Errors',
            'component': 'Memory', 'type': 'System'}


def test_transition_ingestion_is_idempotent_and_maps_the_host(monkeypatch, ctx):
    from alerting import engine
    from database import AlertEvent, db
    monkeypatch.setattr(nd_client, '_ailog_hosts',
                        lambda: [{'key': 'db-1', 'name': 'build'}])
    added, skipped = engine.ingest_netdata_transitions([_transition()])
    assert len(added) == 1 and skipped == 0
    event = AlertEvent.query.filter_by(source='netdata', external_id='t1').one()
    assert event.host_key == 'db-1'
    assert event.state == 'firing'
    assert event.units == '%'
    added2, skipped2 = engine.ingest_netdata_transitions([_transition()])
    assert added2 == [] and skipped2 == 1
    assert AlertEvent.query.filter_by(source='netdata').count() == 1
    db.session.delete(event)
    db.session.commit()


def test_clear_transition_is_recorded_as_resolved(monkeypatch, ctx):
    from alerting import engine
    from database import AlertEvent, db
    monkeypatch.setattr(nd_client, '_ailog_hosts', lambda: [])
    added, _ = engine.ingest_netdata_transitions([_transition('clear-1', 'CLEAR')])
    event = AlertEvent.query.filter_by(external_id='clear-1').one()
    assert event.state == 'resolved'
    assert event.host_key == 'nd:build'
    assert event.resolved_at is not None
    db.session.delete(event)
    db.session.commit()


def test_poll_reports_an_error_instead_of_raising(monkeypatch, ctx):
    from alerting import engine
    monkeypatch.setattr(nd_client, 'configured', lambda: False)
    result = engine.poll_netdata_alerts(meta=True)
    assert result['added'] == 0
    assert 'not configured' in result['error']


# --- API ------------------------------------------------------------------

def _enable(monkeypatch):
    monkeypatch.setattr(nd_client, 'configured', lambda: True)
    monkeypatch.setattr(nd_client, 'base_url', lambda: 'https://netdata.example')
    monkeypatch.setattr(nd_client, 'token', lambda: 'secret-token')
    monkeypatch.setattr(nd_client, 'nodes', lambda ttl=None: [dict(NODE_A)])
    monkeypatch.setattr(nd_client, 'fetch_data', _fake_fetch)
    monkeypatch.setattr(nd_client, 'alert_transitions', lambda **kw: {'transitions': [], 'facets': {}})
    monkeypatch.setattr(nd_client, 'alerts', lambda ttl=None: {'alerts': [], 'nodes': []})
    monkeypatch.setattr(nd_client, 'host_key_map', lambda: {})
    monkeypatch.setattr(nd_client, '_ailog_hosts', lambda: [])


def test_health_endpoint(monkeypatch, http):
    _enable(monkeypatch)
    body = http.get('/api/netdata/health').get_json()
    assert body['reachable'] is True
    assert body['nodes'] == 1
    assert body['token_set'] is True
    assert 'secret-token' not in json.dumps(body)


def test_config_get_never_returns_the_token(monkeypatch, http):
    _enable(monkeypatch)
    body = http.get('/api/netdata/config').get_json()
    assert body['token_set'] is True
    assert 'token' not in body
    assert 'secret-token' not in json.dumps(body)


def test_fleet_endpoint_carries_reconciliation(monkeypatch, http):
    _enable(monkeypatch)
    body = http.get('/api/netdata/fleet?window=120&points=10').get_json()
    assert body['success'] is True
    assert body['nodes'][0]['name'] == 'build'
    assert 'reconcile' in body
    assert body['quality']['nodes'] == 1


def test_history_endpoint_returns_series(monkeypatch, http):
    _enable(monkeypatch)
    body = http.get('/api/netdata/history?host=build&window=60&points=10').get_json()
    assert body['success'] is True
    assert body['series']['system.cpu'] == [20.0]


def test_diagnostics_reports_sso_block_honestly(monkeypatch):
    def blocked(path, params=None, **kwargs):
        raise nd_client.NetdataError('Netdata HTTP 412: SSO', status=412)
    monkeypatch.setattr(nd_client, '_request', blocked)
    probe = nd_client.diagnostics_probe()
    assert probe['available'] is False
    assert probe['status'] == 412
    assert 'Cloud SSO' in probe['reason']


def test_metrics_page_marks_netdata_cards_and_can_drill_down():
    js = _js('metrics-page.js')
    assert 'server.anomaly_rate' in js
    assert 'ML ${anomaly.toFixed(1)}%' in js
    assert 'metrics_source' in js


# --- prompts and UI wiring ------------------------------------------------

def test_capacity_prompt_is_in_the_library_and_uses_metric_evidence():
    import aiprompts
    prompt = aiprompts.PROMPTS_BY_ID['capacity']
    assert prompt['title'] == 'Capacity & saturation forensics'
    assert 'METRICS' in prompt['prompt']
    assert 'NETDATA ALERTS' in prompt['prompt']
    assert 'sustained' in prompt['prompt'] and 'spiky' in prompt['prompt']
    postmortem = aiprompts.PROMPTS_BY_ID['postmortem']['prompt']
    assert 'NETDATA ALERTS' in postmortem


def test_netdata_page_is_anomaly_first_and_read_only():
    page = open(os.path.join(ROOT, 'templates', 'netdata.html')).read()
    js = _js('netdata-page.js')
    assert 'Anomaly-first' in page
    assert '/api/netdata/history' in js
    assert '.sort((a, b) => (b.anomaly_rate' in js
    assert '/api/netdata/ingest' in js
    assert 'probeDiagnostics' in js


def test_settings_exposes_url_and_write_only_token():
    html = open(os.path.join(ROOT, 'templates', 'partials', 'settings.html')).read()
    js = _js('netdata-settings.js')
    assert 'id="netdata-url"' in html
    assert 'id="netdata-token"' in html
    assert 'never sent to the browser' in html
    assert 'clear_token' in js
    assert 'leave blank to keep the stored token' in html


def test_netdata_blueprint_and_poller_are_registered():
    app_py = open(os.path.join(ROOT, 'app.py')).read()
    assert 'from netdata import netdata_bp' in app_py
    assert 'netdata_alert_poll' in app_py
    assert 'poll_netdata_alerts' in app_py


def test_dashboard_card_is_anomaly_first_and_links_to_the_fleet_page():
    js = _js('overview.js')
    css = open(os.path.join(ROOT, 'static', 'css', 'ui.css')).read()
    assert '/api/netdata/fleet?window=120&points=30' in js
    assert 'function renderNetdata()' in js
    assert 'sort((a, b) => (b.anomaly_rate || 0)' in js
    assert 'Not reachable' in js
    assert '/netdata' in js
    assert '.ov-nd-anom' in css
    # The dashboard must not turn a missing configuration into a red error box.
    assert '/not configured/i.test(message)' in js


def test_settings_has_a_netdata_navigation_entry_and_live_status():
    html = open(os.path.join(ROOT, 'templates', 'partials', 'settings.html')).read()
    assert 'data-section="netdata"' in html
    assert 'id="netdata-section"' in html
    assert 'id="netdata-status"' in html
    assert 'Parent URL' in html
    assert 'API token' in html


def test_netdata_os_string_becomes_the_shape_the_cards_read():
    """Netdata says "Ubuntu"; the SSH collector says {family, id, name}.

    The host card picks its OS mark from ``id``/``family``, so a bare string
    drew the "unknown OS" monitor glyph on every Netdata-matched host.
    """
    from netdata import snapshot

    ubuntu = snapshot.os_shape('Ubuntu 24.04.5 LTS')
    assert ubuntu['id'] == 'ubuntu' and ubuntu['family'] == 'linux'
    assert ubuntu['name'] == 'Ubuntu 24.04.5 LTS'

    assert snapshot.os_shape('Debian GNU/Linux 13 (trixie)')['id'] == 'debian'
    assert snapshot.os_shape('macOS 15.1')['family'] == 'darwin'
    assert snapshot.os_shape('FreeBSD 14')['family'] == 'bsd'
    assert snapshot.os_shape('Microsoft Windows Server 2022')['family'] == 'windows'

    # already-shaped input passes through untouched, as does nothing at all
    shaped = {'family': 'linux', 'id': 'arch', 'name': 'Arch'}
    assert snapshot.os_shape(shaped) is shaped
    assert snapshot.os_shape(None) is None


def test_docker_presence_comes_from_the_netdata_context():
    """The card's Docker badge must survive on Netdata-matched hosts.

    ``as_snapshot`` used to hard-code docker_installed=False because counting
    containers needs SSH -- which silently removed the badge from every node
    Netdata covered. The docker.containers.running context already answers
    "is Docker here?", so the badge is truthful and costs no SSH.
    """
    node = {**NODE_A, 'docker_installed': True, 'docker_running': 6}
    snap = snapshot.as_snapshot({'key': 'db-7', 'friendly_name': 'Build'}, node)
    assert snap['docker_installed'] is True
    assert snap['docker_reachable'] is True
    assert snap['docker_running'] == 6
    # per-container detail is still not invented
    assert snap['docker_total'] == 0
