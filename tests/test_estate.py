"""The estate: reading intent, moving one version, and letting CI deploy it.

The migration these tests are about is the point of the whole module: AILog used
to run `docker service update --force` on a swarm service, which rolls the
running image onto whatever the registry serves for the tag - and quietly drifts
away from the tag git pins.  Now a swarm service the estate owns goes through
`wizard.yaml` -> stack file -> mirror entry -> dev -> PR -> main -> ship.yml, so
what is running is what is committed.

The tests are deliberately about the decisions, not the plumbing: which tag wins,
which lines move, what a build-kind service does (nothing), and that the whole
run is refused when the pipeline is off.
"""

import json
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

WIZARD = """# wizard.yaml - hand-written preamble that must survive a bump.
version: 1
defaults:
  registry: zot.safehomelan.com
services:
- name: dozzle
  kind: mirror
  service: dozzle
  image: zot.safehomelan.com/dozzle:v11.4.0
  repo: dozzle
  version: v11.4.0
  source: docker.io/amir20/dozzle:v11.4.0
  ports:
  - host: 8080
- name: ingest
  kind: build
  service: ingest
  repo: ingest
  version: build-120
  source: ''
"""

STACK = """# dozzle - rendered from wizard.yaml by homelab-wizard.
# This comment explains why the volume is bind-mounted; a re-render would eat it.
version: "3.8"
services:
  dozzle:
    image: zot.safehomelan.com/dozzle:v11.4.0
    ports:
    - "8080:8080"
    volumes:
    - type: bind
      source: /opt/docker/data/dozzle
      target: /data
"""

MIRRORS = '{"mirrors": [{"name": "dozzle", "source": "docker.io/amir20/dozzle:v11.4.0"}]}'


# ---------------------------------------------------------------- rendering --

def test_image_ref_matches_what_ship_yml_assumes():
    from estate import render
    mirror = {'name': 'dozzle', 'kind': 'mirror', 'repo': 'dozzle', 'version': 'v11.5.0'}
    build = {'name': 'ingest', 'kind': 'build', 'repo': 'ingest', 'version': 'build-120'}
    assert render.image_ref(mirror) == 'zot.safehomelan.com/dozzle:v11.5.0'
    # a build app's tag comes from the run, and falls back to the pin
    assert render.image_ref(build) == 'zot.safehomelan.com/ingest:${IMAGE_TAG:-build-120}'


def test_a_manually_released_build_app_keeps_a_literal_pin():
    """ship.yml exports one IMAGE_TAG per stack, so two build images cannot both
    use the placeholder unless CI built both - the one that is pushed by hand
    keeps a literal tag, and render must agree with it or it would report drift."""
    from estate import render
    entry = {'name': 'ailog', 'kind': 'build', 'repo': 'ailog', 'version': 'v3.17.0',
             'release': 'manual'}
    assert render.image_ref(entry) == 'zot.safehomelan.com/ailog:v3.17.0'


def test_a_version_bump_moves_one_line_and_keeps_the_comments():
    from estate import render
    text, changed = render.bump_image(STACK, 'dozzle', 'zot.safehomelan.com/dozzle:v11.5.0')
    assert changed is True
    assert 'image: zot.safehomelan.com/dozzle:v11.5.0' in text
    # the reason the bind mount exists survives: this is why bump_image exists
    # instead of a full re-render through yaml.safe_dump
    assert 'a re-render would eat it' in text
    assert 'source: /opt/docker/data/dozzle' in text


def test_bumping_the_intent_moves_the_version_and_the_mirror_source():
    from estate import render
    text, entry = render.bump_intent(WIZARD, 'dozzle', 'v11.5.0')
    assert entry['version'] == 'v11.5.0'
    # the mirror list is keyed on the source ref, so a version that did not move
    # the source tag looked like "nothing changed" to mirror.yml
    assert entry['source'] == 'docker.io/amir20/dozzle:v11.5.0'
    assert 'hand-written preamble' in render.header_of(text)
    assert render.load_intent(text)['services'][0]['version'] == 'v11.5.0'
    assert render.load_intent(text)['services'][1]['version'] == 'build-120'


def test_with_tag_and_mirror_entry():
    from estate import render
    assert render.with_tag('ghcr.io/a/b:1.2.3', '1.2.4') == 'ghcr.io/a/b:1.2.4'
    assert render.with_tag('docker.io/library/postgres:16', '16.4') == 'docker.io/library/postgres:16.4'
    assert render.with_tag('ghcr.io/a/b@sha256:abc', '1.2.4') == 'ghcr.io/a/b@sha256:abc'
    entry = {'name': 'dozzle', 'kind': 'mirror', 'repo': 'dozzle',
             'version': 'v11.5.0', 'source': 'docker.io/amir20/dozzle:v11.5.0'}
    assert render.mirror_entry(entry) == {'name': 'dozzle',
                                          'source': 'docker.io/amir20/dozzle:v11.5.0'}
    assert render.mirror_entry({'name': 'ingest', 'kind': 'build'}) is None


def test_drift_names_both_sides():
    from estate import render
    entry = {'name': 'dozzle', 'kind': 'mirror', 'repo': 'dozzle', 'version': 'v11.5.0'}
    assert render.drift(entry, STACK) == ('zot.safehomelan.com/dozzle:v11.4.0 '
                                          '(intent: zot.safehomelan.com/dozzle:v11.5.0)')
    same = STACK.replace('v11.4.0', 'v11.5.0')
    assert render.drift(entry, same) == ''


# --------------------------------------------------------------------- tags --

def _listed(tags, current):
    return {'host': 'docker.io', 'repo': 'amir20/dozzle', 'current': current,
            'count': len(tags), 'tags': tags}


def test_the_newest_tag_is_numeric_not_alphabetical(monkeypatch):
    from estate import tags
    monkeypatch.setattr(tags, 'list_tags', lambda image, limit=80: _listed(
        ['v11.9.0', 'v11.10.0', 'latest', 'pr-5576', 'v11.2.0'], 'v11.9.0'))
    out = tags.newest_tag('docker.io/amir20/dozzle:v11.9.0')
    # 11.10 is above 11.9, and 'latest'/'pr-5576' are not versions
    assert out['best'] == 'v11.10.0'
    assert out['up_to_date'] is False


def test_a_version_update_does_not_jump_major(monkeypatch):
    from estate import tags
    monkeypatch.setattr(tags, 'list_tags', lambda image, limit=80: _listed(
        ['16-alpine', '17-alpine', '18.0', '14.5'], '16-alpine'))
    out = tags.newest_tag('docker.io/library/postgres:16-alpine')
    # "update postgres" must not silently move it to 18
    assert out['best'] == '16-alpine'


def test_the_packaging_already_in_use_wins_a_tie(monkeypatch):
    from estate import tags
    monkeypatch.setattr(tags, 'list_tags', lambda image, limit=80: _listed(
        ['11.5.0', '11.5.0-alpine'], '11.4.0-alpine'))
    out = tags.newest_tag('docker.io/amir20/dozzle:11.4.0-alpine')
    assert out['best'] == '11.5.0-alpine'


def test_a_service_on_its_newest_tag_says_so(monkeypatch):
    from estate import tags
    monkeypatch.setattr(tags, 'list_tags', lambda image, limit=80: _listed(
        ['v11.4.0', 'v11.3.0'], 'v11.4.0'))
    out = tags.newest_tag('docker.io/amir20/dozzle:v11.4.0')
    assert out['up_to_date'] is True and out['tag'] == 'v11.4.0'


def test_a_repo_with_no_version_tags_is_an_error_not_a_guess(monkeypatch):
    from estate import tags
    monkeypatch.setattr(tags, 'list_tags', lambda image, limit=80: _listed(
        ['latest', 'main', 'pr-1'], 'latest'))
    with pytest.raises(tags.TagError):
        tags.newest_tag('docker.io/mightywomble/ailog:latest')


def test_image_references_split_the_way_the_registries_do():
    from estate import tags
    assert tags.split('docker.io/amir20/dozzle:latest') == ('docker.io', 'amir20/dozzle', 'latest')
    assert tags.split('nginx:1.27') == ('docker.io', 'library/nginx', '1.27')
    assert tags.split('ghcr.io/zhfahim/anchor:0.9.1') == ('ghcr.io', 'zhfahim/anchor', '0.9.1')
    assert tags.split('zot.safehomelan.com/ailog:v3.16.1') == ('zot.safehomelan.com', 'ailog', 'v3.16.1')


# -------------------------------------------------------------------- forge --

def test_runs_are_matched_by_workflow_file_not_by_repo_path():
    """Gitea reports `path` as 'ship.yml@refs/heads/main', not the repo path.

    Comparing it with '.gitea/workflows/ship.yml' meant no run ever matched, so
    every estate update ended with "ship.yml did not start" even when it had.
    """
    from estate import forge

    class FakeSession:
        def __init__(self, payload):
            self.payload = payload
            self.headers = {}

        def get(self, url, **kwargs):
            class R:
                status_code = 200

                def __init__(self, body):
                    self.body = body

                def json(self):
                    return self.body

            if url.endswith('/actions/runs'):
                return R(self.payload)
            return R({})

    runs = [{'id': 9, 'path': 'ship.yml@refs/heads/main', 'head_sha': 'abc'},
            {'id': 8, 'path': 'mirror.yml@refs/heads/dev', 'head_sha': 'def'}]
    f = forge.Forge(session=FakeSession({'workflow_runs': runs}))
    assert forge.Forge.workflow_of(runs[0]) == 'ship.yml'
    found = f.find_run('ship.yml', sha='abc', timeout=1)
    assert found and found['id'] == 9
    assert f.find_run('.gitea/workflows/mirror.yml', timeout=1)['id'] == 8


# ---------------------------------------------------------------------- git --

def test_a_lost_race_regenerates_the_edit_instead_of_merging(monkeypatch):
    """Push rejected -> reset, run the same edit again on the new tree."""
    from estate import git as estate_git
    attempts = []

    class Repo(estate_git.Repo):
        def sync(self):
            return 'sha'

        def commit(self, message, paths):
            return list(paths)

        def push(self):
            attempts.append(len(attempts) + 1)
            if len(attempts) < 3:
                raise estate_git.Conflict('rejected: non-fast-forward')

        def head(self):
            return 'sha'

    def edit(repo):
        return {'name': 'dozzle'}, ['wizard.yaml']

    result = Repo(directory='/tmp/does-not-matter').apply(edit, 'msg')
    assert len(attempts) == 3
    assert result['attempts'] == 3
    assert result['changed'] == ['wizard.yaml']


def test_a_branch_that_keeps_moving_fails_with_a_readable_reason(monkeypatch):
    from estate import git as estate_git

    class Repo(estate_git.Repo):
        def sync(self):
            return 'sha'

        def commit(self, message, paths):
            return list(paths)

        def push(self):
            raise estate_git.Conflict('rejected: fetch first')

        def head(self):
            return 'sha'

    with pytest.raises(estate_git.Conflict) as excinfo:
        Repo(directory='/tmp/x').apply(lambda repo: ({}, ['wizard.yaml']), 'msg', attempts=2)
    assert 'kept moving' in str(excinfo.value)


# ------------------------------------------------------------------- update --

@pytest.fixture()
def frozen(monkeypatch, tmp_path):
    """The estate with its I/O replaced: a tree, a forge and a run that succeeds."""
    from estate import settings, update

    monkeypatch.setenv('AILOG_ALLOW_ESTATE', 'on')
    monkeypatch.setenv('AILOG_ESTATE_DIR', str(tmp_path))
    monkeypatch.setenv('AILOG_ESTATE_WORK_BRANCH', 'dev')

    tree = {'wizard.yaml': WIZARD, 'stacks/dozzle/stack.yml': STACK,
            'mirror-images.json': MIRRORS}

    class FakeRepo:
        dir = str(tmp_path)

        def sync(self):
            return 'head1'

        def read(self, relpath, default=''):
            return tree.get(relpath, default)

        def write(self, relpath, text):
            tree[relpath] = text

        def head(self):
            return 'head1'

        def apply(self, edit, message, attempts=4):
            entry, files = edit(self)
            return {'changed': files, 'head': 'head1', 'attempts': 1, 'entry': entry}

    class FakeForge:
        def __init__(self, *args, **kwargs):
            self.created = []
            self.merged = []

        def find_run(self, workflow, sha='', newer_than=0, timeout=120, cancel=None):
            return {'id': 4242, 'path': workflow, 'run_number': 141}

        def create_pr(self, title, head, base='', body=''):
            self.created.append({'title': title, 'head': head, 'base': base, 'body': body})
            return {'number': 7, 'title': title}

        def merge_pr(self, index, attempts=8):
            self.merged.append(index)
            return {'merged': True, 'sha': 'merge-sha'}

    forge = FakeForge()
    monkeypatch.setattr(update, 'Repo', FakeRepo)
    monkeypatch.setattr(update.forge_mod, 'Forge', lambda *a, **k: forge)
    monkeypatch.setattr(update, '_watch_run', lambda *a, **k: (True, 'success'))
    monkeypatch.setattr(update.tags, 'newest_tag', lambda image, limit=100: {
        'best': 'v11.5.0', 'current': 'v11.4.0', 'up_to_date': False,
        'host': 'docker.io', 'repo': 'amir20/dozzle', 'candidates': ['v11.5.0']})
    return {'update': update, 'tree': tree, 'forge': forge, 'settings': settings}


class RecordingSink:
    def __init__(self):
        self.steps, self.lines, self.progress_values = [], [], []

    def step(self, label, ok=None, detail=''):
        self.steps.append((label, ok, detail))

    def log(self, text):
        self.lines.append(text)

    def progress(self, pct):
        self.progress_values.append(pct)


def test_the_bump_moves_all_three_files_and_then_goes_through_ci(frozen):
    sink = RecordingSink()
    result = frozen['update'].perform('dozzle', sink)

    tree = frozen['tree']
    intent = frozen['update'].render.load_intent(tree['wizard.yaml'])
    assert frozen['update'].render.find_service(intent, 'dozzle')['version'] == 'v11.5.0'
    assert 'zot.safehomelan.com/dozzle:v11.5.0' in tree['stacks/dozzle/stack.yml']
    # the mirror entry moved with it, or mirror.yml would copy nothing into zot
    mirrors = json.loads(tree['mirror-images.json'])
    assert mirrors['mirrors'][0]['source'] == 'docker.io/amir20/dozzle:v11.5.0'
    # and the deploy is CI's, addressed at this one stack
    assert frozen['forge'].merged == [7]
    assert result['target'] == 'v11.5.0' and result['run'] == 4242
    assert result['sha'] == 'merge-sha'
    # the dialog gets a bar to follow
    assert sink.progress_values and max(sink.progress_values) == 100


def test_the_pr_is_scoped_to_the_one_service(frozen):
    sink = RecordingSink()
    frozen['update'].perform('dozzle', sink)
    pr = frozen['forge'].created[0]
    assert pr['head'] == 'dev' and pr['base'] == 'main'
    assert pr['title'].startswith('dozzle: v11.4.0 -> v11.5.0')
    assert 'only the `dozzle` stack' in pr['body']


def test_a_build_app_with_nothing_to_build_is_refused(frozen):
    """apps/ingest is not in this fake tree, so there is no source to compile."""
    sink = RecordingSink()
    with pytest.raises(frozen['update'].EstateError) as excinfo:
        frozen['update'].perform('ingest', sink)
    assert 'nothing the estate knows how to build' in str(excinfo.value)
    # nothing was written, and nothing was pushed
    assert frozen['tree']['wizard.yaml'] == WIZARD


def test_a_manually_released_build_app_is_still_refused(frozen):
    """A hand-pushed version tag has no source-to-build mapping to follow."""
    from estate import render
    doc = render.load_intent(frozen['tree']['wizard.yaml'])
    entry = render.find_service(doc, 'ingest')
    entry['release'] = 'manual'
    frozen['tree']['wizard.yaml'] = render.dump_intent(doc)
    with pytest.raises(frozen['update'].EstateError) as excinfo:
        frozen['update'].perform('ingest', RecordingSink())
    assert 'release: manual' in str(excinfo.value)


def test_a_build_app_is_rebuilt_through_ci_and_then_pinned(frozen):
    """Phase 2: the app is rebuilt from source, smoke tested on dev, deployed by
    ship.yml, and the tag that run produced is pinned afterwards so a later stack
    deploy cannot fall back to the previous build."""
    tree = frozen['tree']
    tree['apps/ingest/Dockerfile'] = 'FROM python:3.12-slim\n'
    tree['stacks/ingest/stack.yml'] = (
        'services:\n  ingest:\n    image: zot.safehomelan.com/ingest:'
        '${IMAGE_TAG:-build-120}\n')
    sink = RecordingSink()
    result = frozen['update'].perform('ingest', sink)

    # a request, not a version bump: the app directory is what CI watches
    request = json.loads(tree['apps/ingest/BUILD_REQUEST.json'])
    assert request['app'] == 'ingest' and request['requested_at']
    assert request['replaces'] == 'build-120'
    # it went to dev first: build.yml is the gate, and merging is what deploys
    assert frozen['forge'].created[0]['head'] == 'dev'
    assert frozen['forge'].created[0]['base'] == 'main'
    assert 'rebuild from source' in frozen['forge'].created[0]['title']
    assert frozen['forge'].merged[0] == 7
    # the tag ship.yml reported is now what git pins
    entry = frozen['update'].render.find_service(
        frozen['update'].render.load_intent(tree['wizard.yaml']), 'ingest')
    assert entry['version'] == 'build-141'
    assert '${IMAGE_TAG:-build-141}' in tree['stacks/ingest/stack.yml']
    assert result['tag'] == 'build-141' and result['pinned'] is True
    # a second PR carries the pin
    assert [pr['title'] for pr in frozen['forge'].created][1].startswith('ingest: pin build-141')
    # and the bar runs to the end
    assert max(sink.progress_values) == 100


def test_a_build_plan_says_rebuild_and_names_the_source(frozen):
    frozen['tree']['apps/ingest/Dockerfile'] = 'FROM python:3.12-slim\n'
    plan = frozen['update'].plan('ingest')
    assert plan['action'] == 'rebuild' and plan['supported'] is True
    assert 'apps/ingest' in plan['upstream'] or 'ingest' in plan['upstream']
    assert any('build.yml' in step for step in plan['steps'])
    assert any('pin' in step for step in plan['steps'])


def test_the_build_path_is_dry_run_safe(frozen, monkeypatch):
    frozen['tree']['apps/ingest/Dockerfile'] = 'FROM python:3.12-slim\n'
    monkeypatch.setenv('AILOG_ALLOW_ESTATE', 'plan')
    sink = RecordingSink()
    result = frozen['update'].perform('ingest', sink)
    assert result['dry_run'] is True
    assert 'apps/ingest/BUILD_REQUEST.json' not in frozen['tree']
    assert frozen['forge'].created == []


def test_a_build_app_whose_branch_build_fails_is_not_merged(frozen, monkeypatch):
    frozen['tree']['apps/ingest/Dockerfile'] = 'FROM python:3.12-slim\n'
    monkeypatch.setattr(frozen['update'], '_watch_run', lambda *a, **k: (False, 'failure'))
    with pytest.raises(frozen['update'].EstateError) as excinfo:
        frozen['update'].perform('ingest', RecordingSink())
    assert 'nothing was merged' in str(excinfo.value)
    assert frozen['forge'].merged == []


def test_an_up_to_date_service_stops_before_touching_git(frozen, monkeypatch):
    monkeypatch.setattr(frozen['update'].tags, 'newest_tag', lambda image, limit=100: {
        'best': 'v11.4.0', 'current': 'v11.4.0', 'up_to_date': True})
    sink = RecordingSink()
    result = frozen['update'].perform('dozzle', sink)
    assert result['up_to_date'] is True
    assert frozen['forge'].created == []
    assert frozen['tree']['wizard.yaml'] == WIZARD


def test_the_pipeline_off_means_no_commit_at_all(frozen, monkeypatch):
    monkeypatch.setenv('AILOG_ALLOW_ESTATE', 'off')
    with pytest.raises(frozen['update'].EstateError) as excinfo:
        frozen['update'].perform('dozzle', RecordingSink())
    assert 'AILOG_ALLOW_ESTATE=off' in str(excinfo.value)


def test_a_dry_run_shows_the_plan_and_writes_nothing(frozen, monkeypatch):
    monkeypatch.setenv('AILOG_ALLOW_ESTATE', 'plan')
    sink = RecordingSink()
    result = frozen['update'].perform('dozzle', sink)
    assert result['dry_run'] is True
    assert frozen['tree']['wizard.yaml'] == WIZARD
    assert any('would bump dozzle' in line for line in sink.lines)


def test_somebody_elses_bump_wins(frozen, monkeypatch):
    """The retry sees a newer version on the branch and stops instead of stomping."""
    update = frozen['update']
    tree = frozen['tree']

    class MovingRepo(type(update.Repo)):
        pass

    moving_tree = dict(tree)
    moving_tree['wizard.yaml'] = WIZARD.replace('version: v11.4.0', 'version: v11.6.0', 1)

    reads = {'wizard.yaml': 0}

    class Repo:
        dir = '/tmp'

        def sync(self):
            return 'h'

        def read(self, relpath, default=''):
            # the first read is the plan's; the branch moves before the edit runs
            if relpath == 'wizard.yaml':
                reads['wizard.yaml'] += 1
                if reads['wizard.yaml'] <= 1:
                    return tree.get(relpath, default)
            return moving_tree.get(relpath, default)

        def write(self, relpath, text):
            raise AssertionError('a conflicting edit must not be written')

        def apply(self, edit, message, attempts=4):
            entry, files = edit(self)          # raises Conflict inside
            return {'changed': files, 'head': 'h', 'attempts': 1, 'entry': entry}

    monkeypatch.setattr(update, 'Repo', Repo)
    with pytest.raises(update.Conflict) as excinfo:
        update.perform('dozzle', RecordingSink())
    assert 'moved to v11.6.0' in str(excinfo.value)


# ---------------------------------------------------------------- docker tie --

def _swarm_row(name='dozzle_dozzle.1.abc', image='zot.safehomelan.com/dozzle:v11.4.0'):
    return {'Name': '/' + name,
            'Config': {'Image': image, 'Labels': {
                'com.docker.swarm.service.name': 'dozzle_dozzle',
                'com.docker.stack.namespace': 'dozzle'}}}


def test_a_swarm_row_the_estate_owns_updates_through_ci(monkeypatch):
    from dockermon import updateflow
    from estate import update as estate_update

    monkeypatch.setattr(estate_update, 'plan', lambda name, version='': {
        'name': name, 'kind': 'mirror', 'service': name, 'current': 'v11.4.0',
        'target': 'v11.5.0', 'upstream': 'docker.io/amir20/dozzle:v11.4.0',
        'supported': True, 'reason': '', 'steps': ['bump', 'push', 'pr', 'deploy'],
        'files': [], 'drift': '', 'mode': 'on', 'image': ''})
    monkeypatch.setenv('AILOG_ALLOW_ESTATE', 'on')

    target = updateflow.group_targets([_swarm_row()])[0]
    assert target['kind'] == 'swarm'
    updateflow.estate_target(target)
    assert target['kind'] == 'estate'
    assert target['estate']['target'] == 'v11.5.0'
    assert target['commands'] == []            # CI does the work, not a shell
    assert target['runs_on'] == 'CI'


def test_a_swarm_row_the_estate_cannot_plan_still_updates_directly(monkeypatch):
    from dockermon import updateflow
    from estate import update as estate_update

    monkeypatch.setattr(estate_update, 'plan', lambda name, version='': {
        'name': name, 'kind': 'build', 'supported': False,
        'reason': 'built from source in this repo', 'current': 'build-1', 'target': ''})
    monkeypatch.setenv('AILOG_ALLOW_ESTATE', 'on')

    target = updateflow.group_targets([_swarm_row()])[0]
    updateflow.estate_target(target)
    # falls back rather than leaving the button dead
    assert target['kind'] == 'swarm'
    assert target['reason'] == ''
    assert 'built from source' in target['note']


def test_the_estate_is_skipped_entirely_when_it_is_off(monkeypatch):
    from dockermon import updateflow
    monkeypatch.setenv('AILOG_ALLOW_ESTATE', 'off')
    target = updateflow.group_targets([_swarm_row()])[0]
    updateflow.estate_target(target)
    assert target['kind'] == 'swarm'
    assert 'AILOG_ALLOW_ESTATE=off' in target['note']


def test_an_estate_target_counts_as_supported():
    from dockermon import updateflow
    target = {'kind': 'estate', 'service': 'dozzle', 'commands': [], 'reason': '',
              'containers': ['x'], 'file': '', 'project': '', 'image': ''}
    assert updateflow.commands_for(target) == []
    assert updateflow.unsupported_reason(target) == ''


# ------------------------------------------------------------------- routes --

def test_the_estate_status_endpoint_is_honest_about_mode_and_checkout(client, monkeypatch, tmp_path):
    monkeypatch.setenv('AILOG_ALLOW_ESTATE', 'plan')
    monkeypatch.setenv('AILOG_ESTATE_DIR', str(tmp_path / 'nope'))
    body = client.get('/api/estate/status').get_json()
    assert body['success'] is True
    assert body['mode'] == 'plan'
    assert body['enabled'] is True
    assert body['checkout'] is False


def test_the_services_endpoint_says_so_instead_of_failing_without_a_checkout(client, monkeypatch, tmp_path):
    monkeypatch.setenv('AILOG_ESTATE_DIR', str(tmp_path / 'missing'))
    body = client.get('/api/estate/services').get_json()
    assert body['services'] == []
    assert 'no estate checkout' in body['error']


def test_an_update_needs_confirmation_and_permission(client, monkeypatch):
    monkeypatch.setenv('AILOG_ALLOW_ESTATE', 'on')
    assert client.post('/api/estate/update', json={'name': 'dozzle'}).status_code == 400
    monkeypatch.setenv('AILOG_ALLOW_ESTATE', 'off')
    body = client.post('/api/estate/update', json={'name': 'dozzle', 'confirm': True})
    assert body.status_code == 403
    assert 'AILOG_ALLOW_ESTATE=off' in body.get_json()['error']


def test_the_estate_job_endpoint_reports_progress(client):
    from estate import update as estate_update
    estate_update.clear()
    assert client.get('/api/estate/jobs/nope').status_code == 404
    estate_update._jobs['e1'] = {
        'id': 'e1', 'kind': 'estate', 'name': 'dozzle', 'status': 'running',
        'label': 'commit', 'progress': 30.0, 'steps': [], 'output': ['…'],
        'result': None, 'error': '', 'started': __import__('time').time(), 'finished': 0.0,
    }
    body = client.get('/api/estate/jobs/e1').get_json()['job']
    assert body['progress'] == 30.0 and body['kind'] == 'estate'
    estate_update.clear()


def test_the_read_routes_refresh_the_checkout_before_reading_it(client, monkeypatch, tmp_path):
    """A view that lags the last release is a lie: reads fetch first, then report."""
    from estate import routes as estroutes

    calls = []

    class FakeRepo:
        dir = str(tmp_path)
        def exists(self):
            return True
        def fresh(self, max_age=60):
            calls.append('fresh')
            return 'a' * 40
        def head(self):
            return 'a' * 40
        def read(self, relpath, default=''):
            if relpath == 'wizard.yaml':
                return 'services:\n- name: dozzle\n  kind: mirror\n  version: v11.4.0\n'
            return ''

    monkeypatch.setattr(estroutes, 'Repo', FakeRepo)
    body = client.get('/api/estate/services').get_json()
    assert body['head'] == 'a' * 40
    assert body['services'][0]['name'] == 'dozzle'
    assert calls == ['fresh']


def test_a_variant_tag_is_not_mistaken_for_a_version():
    """wordpress publishes `php8.5-fpm`; read as 8.5 it beats every real release."""
    from estate import tags
    assert tags.is_version_tag('php8.5-fpm') is False
    assert tags.is_version_tag('7.1.4-php8.5-fpm-alpine') is True
    assert tags.is_version_tag('v11.4.0') is True
    assert tags.newest_tag.__doc__ is not None


def test_packaging_numbers_do_not_count_as_version_numbers(monkeypatch):
    """wordpress:7.1.4 was the right answer; 7.1.4-php8.5-fpm only looks newer."""
    from estate import tags

    listed = {'host': 'docker.io', 'repo': 'library/wordpress', 'current': '7.1.3',
              'count': 6, 'tags': ['7.1.4-php8.5-fpm-alpine', '7.1.4-php8.5-fpm',
                                   '7.1.4-php8.5', '7.1.4', '7.1.3', 'php8.5-fpm']}
    monkeypatch.setattr(tags, 'list_tags', lambda image, limit=100: listed)
    newest = tags.newest_tag('docker.io/library/wordpress:7.1.3')
    assert newest['best'] == '7.1.4'
    assert newest['up_to_date'] is False
    assert tags._ver('7.1.4-php8.5-fpm') == (7, 1, 4) == tags._ver('7.1.4')


def test_the_hub_listing_walks_more_than_one_page(monkeypatch):
    from estate import tags

    pages = {1: ['7.1.4-alpine'] * 100, 2: ['7.1.4'] + ['7.1.3'] * 99}
    asked = []

    class Resp:
        def __init__(self, names):
            self.status_code = 200
            self._names = names
        def raise_for_status(self):
            return None
        def json(self):
            return {'results': [{'name': n} for n in self._names]}

    def fake_get(url, params=None, timeout=None):
        asked.append(params['page'])
        return Resp(pages.get(params['page'], []))

    monkeypatch.setattr(tags.requests, 'get', fake_get)
    got = tags._hub_tags('library/wordpress', 80, 20)
    assert '7.1.4' in got and asked[:2] == [1, 2]


def test_a_merge_that_answers_with_no_body_still_counts(monkeypatch):
    """Gitea merged wordpress and answered empty; the run died on json() after
    the deploy had already happened."""
    from estate import forge as forge_mod

    class Resp:
        status_code = 200
        text = ''
        def json(self):
            raise ValueError('Expecting value: line 1 column 1 (char 0)')

    class F(forge_mod.Forge):
        def __init__(self):
            self.api, self.path = 'https://gitea.example/api/v1/repos/o/n', ''
        def pr(self, index):
            return {'merged': True, 'merge_commit_sha': 'b' * 40}

    f = F()
    monkeypatch.setattr(f, 'http', type('H', (), {'post': staticmethod(lambda *a, **k: Resp())})(), raising=False)
    out = f.merge_pr(9)
    assert out['merged'] is True and out['sha'] == 'b' * 40


def test_a_refused_merge_that_actually_happened_is_not_an_error(monkeypatch):
    from estate import forge as forge_mod

    class Resp:
        status_code = 405
        text = 'Please try again later'
        def json(self):
            return {}

    class F(forge_mod.Forge):
        def __init__(self):
            self.api, self.path = 'https://gitea.example/api/v1/repos/o/n', ''
        def pr(self, index):
            return {'merged': True, 'merge_commit_sha': 'c' * 40}

    f = F()
    monkeypatch.setattr(f, 'http', type('H', (), {'post': staticmethod(lambda *a, **k: Resp())})(), raising=False)
    assert f.merge_pr(10)['sha'] == 'c' * 40
