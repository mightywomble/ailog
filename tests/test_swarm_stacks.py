"""Stack updates: the swarm's unit is the stack, and the version is chosen.

The list this replaces was built from ``docker ps -a`` on one host, which
cannot answer the question: a service's deployed image is a fact about the
*service*, and the previous task's container stays behind, exited, on whatever
node it ran on. The manager is the only node that knows, and it knows it as
``repo:tag@sha256:…`` because swarm resolves the tag at deploy time.
"""

from __future__ import annotations

import pytest

from dockermon import swarmstack


REPLICATED = '{"Replicated":{"Replicas":1}}'
GLOBAL = '{"Global":{}}'


class FakeRun:
    """Just enough transport: inspect answers the services, ls answers the counts."""

    def __init__(self, output: str, ok: bool = True, manager: bool = True,
                 counts: str = ''):
        self.output = output
        self.counts = counts
        self.ok = ok
        self.manager = manager
        self.commands: list[str] = []

    def __call__(self, command, timeout=60):
        self.commands.append(command)
        if 'ControlAvailable' in command:
            return True, 'true' if self.manager else 'false'
        if 'service inspect' in command:
            return self.ok, self.output
        if 'service ls' in command:
            return True, self.counts
        return self.ok, self.output


SERVICES = '\n'.join([
    'metamcp_postgres\tmetamcp\tzot.safehomelan.com/postgres16:16-alpine@sha256:' + 'a' * 64
    + '\t' + REPLICATED,
    'metamcp_app\tmetamcp\tzot.safehomelan.com/metamcp:build-348@sha256:' + 'b' * 64
    + '\t' + REPLICATED,
    'dozzle_dozzle\tdozzle\tzot.safehomelan.com/dozzle:v11.4.1@sha256:' + 'c' * 64
    + '\t' + GLOBAL,
])

COUNTS = '\n'.join([
    'metamcp_postgres\t1/1',
    'metamcp_app\t1/1',
    'dozzle_dozzle\t3/3',
])


def _patch_registry(monkeypatch, digests: dict[str, str]):
    def fake(image, timeout=12, refresh=False):
        tag = image.rsplit(':', 1)[-1]
        return {'digest': digests.get(tag, ''), 'error': None}
    monkeypatch.setattr(swarmstack.reg, 'remote_digest', fake)


def test_a_service_is_not_a_container():
    """The image spec carries the digest swarm resolved, and the parts we need."""
    ref = swarmstack.parse_ref('zot.safehomelan.com/postgres16:16-alpine@sha256:' + 'a' * 64)
    assert ref['repo'] == 'postgres16'
    assert ref['tag'] == '16-alpine'
    assert ref['digest'] == 'sha256:' + 'a' * 64


def test_the_scan_groups_services_into_stacks(monkeypatch):
    _patch_registry(monkeypatch, {'16-alpine': 'sha256:' + 'a' * 64,
                                  'build-348': 'sha256:' + 'b' * 64,
                                  'v11.4.1': 'sha256:' + 'z' * 64})
    run = FakeRun(SERVICES, counts=COUNTS)
    monkeypatch.setattr(swarmstack, '_runner', lambda host: ({}, run))
    swarmstack.clear()

    out = swarmstack.scan('db-11')

    assert out['manager'] is True
    names = [s['name'] for s in out['stacks']]
    assert names == ['dozzle', 'metamcp']          # updates first, then alphabetical
    metamcp = next(s for s in out['stacks'] if s['name'] == 'metamcp')
    assert [r['short'] for r in metamcp['services']] == ['app', 'postgres']
    assert out['updates'] == 1                     # dozzle moved, metamcp did not
    dozzle = next(s for s in out['stacks'] if s['name'] == 'dozzle')
    assert dozzle['services'][0]['update_available'] is True
    assert dozzle['services'][0]['mode'] == 'global'


def test_a_worker_says_it_cannot_see_the_cluster(monkeypatch):
    run = FakeRun('', manager=False)
    monkeypatch.setattr(swarmstack, '_runner', lambda host: ({}, run))
    swarmstack.clear()

    out = swarmstack.scan('db-15')

    assert out['manager'] is False
    assert out['stacks'] == []
    assert 'not a swarm manager' in out['note']


def test_a_database_major_bump_is_refused_with_the_reason():
    """16 -> 17 will not read the existing data directory, and no pipeline fixes that."""
    with pytest.raises(RuntimeError) as err:
        swarmstack.target_tag({'repo': 'postgres16', 'tag': '16-alpine'}, '17-alpine')
    assert 'dump and restore' in str(err.value) or 'data directory' in str(err.value)


def test_a_hedged_database_tag_is_not_a_bump():
    assert swarmstack.target_tag({'repo': 'postgres16', 'tag': '16-alpine'},
                                 '16.4-alpine') == '16.4-alpine'


def test_versions_offer_what_zot_holds_and_what_it_could_hold(monkeypatch):
    _patch_registry(monkeypatch, {'16-alpine': 'sha256:' + 'a' * 64,
                                  '16.4-alpine': 'sha256:' + 'd' * 64})
    run = FakeRun(SERVICES, counts=COUNTS)
    monkeypatch.setattr(swarmstack, '_runner', lambda host: ({}, run))
    monkeypatch.setattr(swarmstack, 'mirror_sources',
                        lambda: {'postgres16': 'docker.io/library/postgres:16-alpine'})
    monkeypatch.setattr(swarmstack, '_zot_candidates', lambda repo: [
        {'tag': '16-alpine', 'digest': 'sha256:' + 'a' * 64, 'in_zot': True, 'kind': 'version'},
        {'tag': '17-alpine', 'digest': 'sha256:' + 'e' * 64, 'in_zot': True, 'kind': 'version'},
    ])
    monkeypatch.setattr(swarmstack, '_upstream_candidates', lambda repo, sources: [
        {'tag': '16.5-alpine', 'in_zot': False, 'kind': 'version',
         'source': 'docker.io/library/postgres:16.5-alpine'},
    ])

    out = swarmstack.versions('db-11', 'metamcp', 'postgres')

    assert out['current']['tag'] == '16-alpine'
    tags = {c['tag']: c for c in out['candidates']}
    assert tags['16-alpine']['current'] is True
    assert tags['17-alpine']['blocked']            # the major bump is not offered
    assert tags['16.5-alpine']['in_zot'] is False
    assert any('database' in w for w in out['warnings'])


def test_the_template_asks_nothing_a_map_can_refuse():
    """`{{if .Spec.Mode.Global}}` and `{{.ServiceStatus.…}}` both fail in the field.

    Docker renders --format templates with missingkey=error: a global service
    has no `Replicated` key and a replicated one has no `Global`, so asking the
    obvious question kills the whole scan with "map has no entry for key Global"
    - which is exactly what the manager answered the first time this ran live.
    Global mode is read out of `json .Spec.Mode`, and the task counts come from
    `docker service ls`, which always has them.
    """
    assert '.Spec.Mode.Global}}' not in swarmstack.SWARM_INSPECT
    assert 'ServiceStatus' not in swarmstack.SWARM_INSPECT
    assert 'json .Spec.Mode' in swarmstack.SWARM_INSPECT
    assert 'Replicas' in swarmstack.SWARM_REPLICAS


def test_a_global_service_is_read_as_global_without_its_status(monkeypatch):
    """A service created seconds ago has no ServiceStatus at all - the scan still runs."""
    _patch_registry(monkeypatch, {'v11.4.1': 'sha256:' + 'z' * 64})
    fresh = 'dozzle_dozzle\tdozzle\tzot.safehomelan.com/dozzle:v11.4.1@sha256:' + 'c' * 64 + '\t' + GLOBAL
    run = FakeRun(fresh, counts='dozzle_dozzle\t3/3')
    monkeypatch.setattr(swarmstack, '_runner', lambda host: ({}, run))
    swarmstack.clear()

    out = swarmstack.scan('db-11')

    row = out['stacks'][0]['services'][0]
    assert row['mode'] == 'global'
    assert row['replicas'] == '3/3'
    assert row['update_available'] is True
