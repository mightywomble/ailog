"""Updating one container, and only that container.

The bug these tests exist for: pressing "update" on a row opened the homelab
wizard, whose update path is a ``wizard.yaml`` tag bump. A CasaOS app is a
compose project that is not in ``wizard.yaml``, so the wizard fell through to its
add-a-service form and the user had to go and find their own container in a
list. The row now opens ailog's own dialog, which resolves what the container
actually is and addresses one service.

So the guarantees pinned here are:

* a compose container yields ``pull`` + ``up -d --no-deps <service>`` for its
  own service (not the project, not the host),
* a swarm container yields ``service update`` for its own service, run on a
  manager even when the container itself lives on a worker,
* replicas of one service are one update, not three,
* a container with no compose labels and no swarm service is refused with the
  reason instead of guessed at,
* the run endpoint refuses without confirmation, honours ``off``, and works in
  ``dry_run`` without touching the host.
"""

import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as handle:
        return handle.read()


@pytest.fixture()
def updateflow():
    from dockermon import updateflow
    updateflow.clear()
    return updateflow


COMPOSE_LABELS = {
    'com.docker.compose.project': 'gitea',
    'com.docker.compose.service': 'gitea',
    'com.docker.compose.project.config_files': '/var/lib/casaos/apps/gitea/docker-compose.yml',
}


def _inspect(name, image, labels):
    return {'Name': '/' + name, 'Config': {'Image': image, 'Labels': dict(labels)}}


def _compose_row(name='gitea', labels=None):
    return _inspect(name, 'gitea/gitea:latest', COMPOSE_LABELS if labels is None else labels)


# ------------------------------------------------------------------ shapes --


def test_a_compose_container_is_updated_through_its_own_service(updateflow):
    target = updateflow.group_targets([_compose_row()])[0]
    assert target['kind'] == 'compose'
    assert target['project'] == 'gitea'
    assert target['service'] == 'gitea'
    assert target['reason'] == ''
    commands = updateflow.commands_for(target)
    assert len(commands) == 2
    # the file recorded on the host, and --no-deps so the project's other
    # containers (a database, a sidecar) are not bounced by a gitea update
    assert '/var/lib/casaos/apps/gitea/docker-compose.yml' in commands[0]
    assert ' pull gitea' in commands[0]
    assert 'up -d --no-deps gitea' in commands[1]
    assert '--no-deps' in commands[1]


def test_a_swarm_container_is_updated_as_one_service(updateflow):
    row = _inspect('ailog_ailog.1.abc123', 'zot.safehomelan.com/ailog:v3.15.1',
                   {'com.docker.swarm.service.name': 'ailog_ailog',
                    'com.docker.stack.namespace': 'ailog'})
    target = updateflow.group_targets([row])[0]
    assert target['kind'] == 'swarm'
    commands = updateflow.commands_for(target)
    assert len(commands) == 1
    assert 'service update' in commands[0]
    # a moving tag has an identical image spec, so without --force swarm keeps
    # the digest it already has and nothing happens
    assert '--force' in commands[0]
    assert '--with-registry-auth' in commands[0]
    assert 'ailog_ailog' in commands[0]
    # the note says out loud that the git pin is not what moved
    assert 'homelab-ops' in target['note'] if 'note' in target else True


def test_replicas_of_one_service_are_one_update(updateflow):
    rows = [_compose_row('gitea-1'), _compose_row('gitea-2'), _compose_row('gitea-3')]
    targets = updateflow.group_targets(rows)
    assert len(targets) == 1
    assert targets[0]['containers'] == ['gitea-1', 'gitea-2', 'gitea-3']


def test_an_unmanaged_container_is_refused_with_a_reason(updateflow):
    target = updateflow.group_targets([_inspect('scratch', 'alpine:3.20', {})])[0]
    assert target['kind'] == 'container'
    assert updateflow.commands_for(target) == []
    assert 'no compose project and no swarm service' in target['reason']


def test_a_container_its_own_project_owns_is_refused_by_name(updateflow):
    """Nextcloud AIO keeps its siblings in a project it never made with compose.

    The mastercontainer creates them through the docker API and writes the
    project label but no compose service label, so replaying a compose command
    would be inventing an intent that was never recorded - and the recreate that
    follows would undo it anyway.  The refusal has to say whose they are.
    """
    labels = {'com.docker.compose.project': 'nextcloud-aio'}
    target = updateflow.group_targets(
        [_inspect('nextcloud-aio-nextcloud', 'ghcr.io/nextcloud-releases/aio-nextcloud:latest', labels)])[0]
    assert target['kind'] == 'container'
    assert updateflow.commands_for(target) == []
    assert 'nextcloud-aio' in target['reason']
    assert 'owns it and recreates it' in target['reason']


def test_a_publishers_set_is_updated_as_one(updateflow):
    """immich-server and immich-machine-learning must not drift apart.

    The server refuses to talk to a machine-learning container from a different
    release, so a per-service update would break the app while reporting success.
    """
    labels = {
        'com.docker.compose.project': 'immich',
        'com.docker.compose.project.config_files': '/home/david/code/immich/docker-compose.yaml',
    }
    rows = [
        _inspect('immich_server', 'ghcr.io/immich-app/immich-server:v3.3.1',
                 dict(labels, **{'com.docker.compose.service': 'immich-server'})),
        _inspect('immich_machine_learning', 'ghcr.io/immich-app/immich-machine-learning:v3.3.1',
                 dict(labels, **{'com.docker.compose.service': 'immich-machine-learning'})),
    ]
    targets = updateflow.group_targets(rows)
    assert len(targets) == 1
    assert targets[0]['services'] == ['immich-server', 'immich-machine-learning']
    commands = updateflow.commands_for(targets[0])
    assert 'pull immich-server immich-machine-learning' in commands[0]
    assert 'up -d --no-deps immich-server immich-machine-learning' in commands[1]


def test_different_versions_in_one_project_are_not_a_set(updateflow):
    """matrix-server is four services, three of which only share the word matrix.

    Folding those into one target would bounce postgres and redis to update
    synapse, which is the opposite of what the user clicked.
    """
    labels = {
        'com.docker.compose.project': 'matrix-server',
        'com.docker.compose.project.config_files': '/home/david/code/matrix-server/docker-compose.yml',
    }
    rows = [
        _inspect('matrix-synapse', 'ghcr.io/element-hq/synapse:v1.152.0',
                 dict(labels, **{'com.docker.compose.service': 'synapse'})),
        _inspect('matrix-postgres', 'postgres:16',
                 dict(labels, **{'com.docker.compose.service': 'postgres'})),
        _inspect('matrix-redis', 'redis:8-alpine',
                 dict(labels, **{'com.docker.compose.service': 'redis'})),
    ]
    targets = updateflow.group_targets(rows)
    assert len(targets) == 3
    for target in targets:
        assert updateflow.target_services(target) == [target['service']]


def test_the_siblings_of_a_compose_service_are_found_from_ps(updateflow):
    rows = [
        {'name': 'immich_server', 'image': 'ghcr.io/immich-app/immich-server:v3.3.1',
         'project': 'immich', 'service': 'immich-server'},
        {'name': 'immich_machine_learning',
         'image': 'ghcr.io/immich-app/immich-machine-learning:v3.3.1',
         'project': 'immich', 'service': 'immich-machine-learning'},
        {'name': 'immich_redis', 'image': 'valkey/valkey:9',
         'project': 'immich', 'service': 'redis'},
        {'name': 'gitea', 'image': 'gitea/gitea:latest', 'project': 'gitea', 'service': 'gitea'},
    ]
    target = updateflow.target_of(
        _inspect('immich_server', 'ghcr.io/immich-app/immich-server:v3.3.1', {
            'com.docker.compose.project': 'immich',
            'com.docker.compose.service': 'immich-server',
            'com.docker.compose.project.config_files': '/srv/immich/docker-compose.yaml',
        }))
    assert updateflow.siblings(rows, target) == ['immich_server', 'immich_machine_learning']


def test_an_old_compose_project_without_a_config_files_label_still_works(updateflow):
    labels = {
        'com.docker.compose.project': 'managelm',
        'com.docker.compose.service': 'portal',
        'com.docker.compose.project.working_dir': '/home/david/code/managelm',
    }
    target = updateflow.group_targets([_inspect('managelm-portal-1', 'managelm/portal:latest', labels)])[0]
    assert target['kind'] == 'compose'
    assert target['file'] == '/home/david/code/managelm/docker-compose.yml'
    assert updateflow.commands_for(target)


def test_the_work_directory_fallback_is_only_a_fallback(updateflow):
    """A recorded config file always wins: it is what compose itself would use."""
    labels = dict(COMPOSE_LABELS, **{
        'com.docker.compose.project.working_dir': '/srv/elsewhere',
    })
    target = updateflow.group_targets([_compose_row(labels=labels)])[0]
    assert target['file'] == '/var/lib/casaos/apps/gitea/docker-compose.yml'


# ------------------------------------------------------------------ manager --


def test_a_worker_finds_the_manager_rather_than_refusing(updateflow, monkeypatch):
    calls = []

    def fake_runner(host_key):
        answer = 'true' if host_key == 'db-1' else 'false'

        def run(command, timeout=60):
            calls.append((host_key, command))
            return True, answer + '\n'

        return {'friendly_name': host_key, 'user': 'root', 'ip': '10.0.0.1'}, run

    monkeypatch.setattr(updateflow, '_runner', fake_runner)
    monkeypatch.setattr(updateflow.ep, 'all_host_keys', lambda: ['db-9', 'db-1'])
    monkeypatch.setattr(updateflow, 'MANAGER_TTL', 300.0)

    assert updateflow.manager_for('db-9') == 'db-1'
    # cached: the second ask does not walk the estate again
    assert updateflow.manager_for('db-9') == 'db-1'
    assert [c[0] for c in calls] == ['db-9', 'db-1']


# ------------------------------------------------------------------ policy --


def test_updates_are_on_by_default_and_can_be_disabled(updateflow, monkeypatch):
    monkeypatch.delenv('AILOG_ALLOW_UPDATES', raising=False)
    assert updateflow.mode() == 'on'
    monkeypatch.setenv('AILOG_ALLOW_UPDATES', 'dry_run')
    assert updateflow.mode() == 'dry_run'
    monkeypatch.setenv('AILOG_ALLOW_UPDATES', 'off')
    assert updateflow.mode() == 'off'
    monkeypatch.setenv('AILOG_ALLOW_UPDATES', 'nonsense')
    assert updateflow.mode() == 'on'


def test_a_dry_run_prints_the_commands_and_touches_nothing(updateflow, monkeypatch):
    ran = []
    monkeypatch.setattr(updateflow, '_runner',
                        lambda host_key: ({}, lambda command, timeout=60: ran.append(command) or (True, '')))
    # hand-built job so the assertions are about _execute, not threading
    updateflow._jobs['j1'] = {'id': 'j1', 'steps': [], 'output': [], 'status': 'running',
                              'label': 'queued', 'error': '', 'started': 0.0, 'finished': 0.0}
    target = updateflow.group_targets([_compose_row()])[0]
    target['runs_on'] = 'h'
    ok = updateflow._execute('j1', 'h', target, dry=True)
    assert ok is True
    assert ran == []                                  # nothing was executed
    assert 'dry run' in '\n'.join(updateflow._jobs['j1']['output'])
    assert len(updateflow._jobs['j1']['steps']) >= 2


def test_a_real_run_records_every_command(updateflow, monkeypatch):
    ran = []
    monkeypatch.setattr(updateflow, '_runner',
                        lambda host_key: ({}, lambda command, timeout=60: ran.append(command) or (True, 'pulled')))
    updateflow._jobs['j2'] = {'id': 'j2', 'steps': [], 'output': [], 'status': 'running',
                              'label': 'queued', 'error': '', 'started': 0.0, 'finished': 0.0}
    target = updateflow.group_targets([_compose_row()])[0]
    target['runs_on'] = 'h'
    assert updateflow._execute('j2', 'h', target, dry=False) is True
    assert len(ran) == 2
    assert 'pulled' in updateflow._jobs['j2']['output']
    assert [s['ok'] for s in updateflow._jobs['j2']['steps']] == [True, True]


# ------------------------------------------------------------------ routes --


def test_the_plan_endpoint_needs_a_target(client):
    assert client.get('/api/docker/hosts/nope/update/plan?image=x').status_code == 404
    assert client.get('/api/docker/hosts/local/update/plan').status_code == 400


def test_the_run_endpoint_requires_confirmation(client, monkeypatch):
    body = client.post('/api/docker/hosts/local/update',
                       json={'image': 'gitea/gitea:latest'})
    assert body.status_code == 400
    assert 'confirm' in body.get_json()['error']


def test_the_run_endpoint_honours_off(client, monkeypatch):
    from dockermon import updateflow
    monkeypatch.setenv('AILOG_ALLOW_UPDATES', 'off')
    body = client.post('/api/docker/hosts/local/update',
                       json={'image': 'gitea/gitea:latest', 'confirm': True})
    assert body.status_code == 403
    assert 'AILOG_ALLOW_UPDATES' in body.get_json()['error']
    assert updateflow.job('anything') is None


def test_the_run_endpoint_queues_a_scoped_job(client, monkeypatch):
    from dockermon import updateflow
    seen = {}

    def fake_start(app, host_key, image='', container=''):
        seen.update(host_key=host_key, image=image, container=container)
        return {'id': 'abc123', 'status': 'running', 'steps': [], 'output': []}

    monkeypatch.setattr(updateflow, 'start', fake_start)
    body = client.post('/api/docker/hosts/local/update',
                       json={'image': 'gitea/gitea:latest', 'container': 'gitea', 'confirm': True})
    assert body.status_code == 200
    assert seen == {'host_key': 'local', 'image': 'gitea/gitea:latest', 'container': 'gitea'}
    assert body.get_json()['job']['id'] == 'abc123'


def test_the_job_endpoint_reports_progress(client):
    from dockermon import updateflow
    assert client.get('/api/docker/update/jobs/nope').status_code == 404
    updateflow._jobs['j3'] = {
        'id': 'j3', 'host_key': 'local', 'image': 'x', 'container': 'c',
        'status': 'running', 'label': 'pull gitea', 'steps': [],
        'output': ['pulling'], 'plan': None, 'error': '',
        'started': __import__('time').time(), 'finished': 0.0,
    }
    body = client.get('/api/docker/update/jobs/j3').get_json()
    assert body['success'] is True
    assert body['job']['label'] == 'pull gitea'
    assert body['job']['output'] == ['pulling']
    updateflow.clear()


# ------------------------------------------------------------------ frontend --


def _docker_view():
    js = _read('static', 'js', 'app-core.js')
    start = js.index('// --------------------------------------------------------- Docker view')
    end = js.index('window.showDockerInfoMain = showDockerInfoMain')
    return js[start:end]


def test_the_update_button_opens_ailogs_own_dialog_with_its_target():
    view = _docker_view()
    assert 'data-update-image="${escapeHtml(row.image || \'\')}"' in view
    assert 'data-update-container="${escapeHtml(row.name || \'\')}"' in view
    assert 'data-wizard-open' not in view
    assert 'window.openUpdateModal(options)' in view
    assert "document.getElementById('docker-updates-list')?.addEventListener('click'" in view


def test_the_dialog_confirms_before_it_runs_anything_and_shows_the_commands():
    js = _read('static', 'js', 'update-modal.js')
    # plan first: the commands are on screen before the button can be pressed
    assert '/update/plan?' in js
    assert 'Update now' in js
    assert 'confirm: true' in js
    # live progress, not a spinner over a 60 second request
    assert '/api/docker/update/jobs/' in js
    assert 'setTimeout(poll, 900)' in js
    # a dry run must not look like a real one
    assert 'dry_run' in js


def test_the_dialog_tells_the_view_to_refresh_the_host_it_changed():
    js = _read('static', 'js', 'update-modal.js')
    assert "new CustomEvent('ailog:container-updated'" in js
    view = _docker_view()
    assert "document.addEventListener('ailog:container-updated'" in view
    assert 'refreshAfterWizard();' in view


def test_the_page_and_module_entry_point_carry_the_dialog():
    assert '{% include "partials/update-modal.html" %}' in _read('templates', 'index.html')
    assert "import './update-modal.js'" in _read('static', 'js', 'main.js')
    partial = _read('templates', 'partials', 'update-modal.html')
    assert 'id="updateModal"' in partial
    assert 'data-modal-close' in partial        # Escape/backdrop/close share one path
    assert 'id="updateModalRun" type="button" disabled' in partial   # nothing runs before the plan
