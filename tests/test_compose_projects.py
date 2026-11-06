"""Settings -> Docker reads the tree, and says what is wrong with it.

The section is deliberately read-only: the deploy is a commit, and the last time
this estate had two writers a service ran eight releases behind its own pin. So
everything it can be wrong about is a property of the files - an image that does
not come from zot, a project with no health check, an .env.example that has
drifted from the keys the project actually needs.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from composecfg import projects


class FakeRepo:
    """Just the two things the reader uses: a directory and the estate root."""

    def __init__(self, directory: Path, root: str = 'deploy'):
        self.dir = str(directory)
        self._root = root

    def root(self) -> str:
        return self._root


def _project(base: Path, name: str, meta: dict, compose: str, env_example: str = '') -> None:
    directory = base / 'deploy' / 'compose' / name
    directory.mkdir(parents=True)
    (directory / 'project.json').write_text(json.dumps(meta))
    (directory / 'compose.yml').write_text(compose)
    if env_example:
        (directory / '.env.example').write_text(env_example)


GOOD_META = {
    'name': 'immich',
    'description': 'Photo library',
    'host': 'photos',
    'ssh': 'david@100.64.49.47',
    'dir': '/home/david/code/immich',
    'compose_file': 'docker-compose.yml',
    'env_file': '.env',
    'env_keys': ['IMMICH_VERSION', 'DB_PASSWORD'],
    'health': {'service': 'immich-server', 'url': 'http://127.0.0.1:2283/api/server/ping'},
}

GOOD_COMPOSE = """services:
  server:
    image: zot.safehomelan.com/immich-server:${IMMICH_VERSION:-v3.3.6}
  db:
    image: zot.safehomelan.com/immich-postgres:14-vectorchord0.4.3
"""

GOOD_ENV = 'IMMICH_VERSION=v3.3.6\nDB_PASSWORD=change-me\n'


@pytest.fixture()
def tree(tmp_path):
    _project(tmp_path, 'immich', GOOD_META, GOOD_COMPOSE, GOOD_ENV)
    return tmp_path


def test_it_lists_the_project_with_where_it_runs_and_what_it_pins(tree):
    rows = projects(FakeRepo(tree))

    assert [r['name'] for r in rows] == ['immich']
    row = rows[0]
    assert (row['host'], row['dir'], row['compose_file']) == (
        'photos', '/home/david/code/immich', 'docker-compose.yml')
    assert [(i['image'], i['pin'], i['from_zot']) for i in row['images']] == [
        ('zot.safehomelan.com/immich-server', 'v3.3.6', True),
        ('zot.safehomelan.com/immich-postgres', '14-vectorchord0.4.3', True),
    ]
    assert row['problems'] == []


def test_an_image_that_does_not_come_from_zot_is_a_problem(tree):
    _project(tree, 'bad', dict(GOOD_META, name='bad'), 'services:\n  a:\n'
             '    image: ghcr.io/immich-app/immich-server:release\n', GOOD_ENV)

    rows = {r['name']: r for r in projects(FakeRepo(tree))}
    assert rows['immich']['problems'] == []
    assert rows['bad']['images'][0]['from_zot'] is False
    assert rows['bad']['problems'] == [
        'ghcr.io/immich-app/immich-server:release does not come from zot']


def test_a_project_with_no_health_check_cannot_be_rolled_back(tree):
    meta = dict(GOOD_META, health={})
    _project(tree, 'nohealth', meta, GOOD_COMPOSE, GOOD_ENV)

    row = next(r for r in projects(FakeRepo(tree)) if r['name'] == 'immich' and 'health' in str(r['problems']))
    assert any('no health check' in p for p in row['problems'])


def test_an_env_example_that_has_drifted_is_a_problem(tree):
    _project(tree, 'drifted', GOOD_META, GOOD_COMPOSE, 'IMMICH_VERSION=v3.3.6\n')

    row = next(r for r in projects(FakeRepo(tree)) if any('.env.example' in p for p in r['problems']))
    assert row['problems'] == ['.env.example does not list every key in project.json']


def test_a_broken_project_json_costs_one_row_not_the_section(tmp_path):
    _project(tmp_path, 'immich', GOOD_META, GOOD_COMPOSE, GOOD_ENV)
    broken = tmp_path / 'deploy' / 'compose' / 'broken'
    broken.mkdir(parents=True)
    (broken / 'project.json').write_text('{not json')

    rows = projects(FakeRepo(tmp_path))

    assert len(rows) == 2
    assert rows[0]['name'] == 'broken' and 'project.json' in rows[0]['error']
    assert rows[1]['name'] == 'immich' and 'error' not in rows[1]


def test_no_compose_directory_is_an_empty_list(tmp_path):
    (tmp_path / 'deploy').mkdir()
    assert projects(FakeRepo(tmp_path)) == []


def test_it_reads_the_estate_wherever_it_lives(tmp_path):
    """The prefix is the estate's, not a constant: a pre-merge checkout has the
    projects at the root."""
    root = tmp_path / 'deploy'
    root.mkdir()
    _project(tmp_path, 'immich', GOOD_META, GOOD_COMPOSE, GOOD_ENV)
    (tmp_path / 'deploy' / 'compose').rename(tmp_path / 'compose')

    rows = projects(FakeRepo(tmp_path, root=''))

    assert [r['name'] for r in rows] == ['immich']


def test_the_env_checklist_is_actually_in_the_repository():
    """`.env.example` is the project's checklist, and .gitignore ate it.

    The pattern ``.env.*`` kept every ``.env.example`` out of the tree while
    ``git add -A`` reported a clean repository - so the file the reader
    verifies against existed only on the machine that wrote it, and the live
    section reported the project as missing its own checklist.
    """
    import subprocess

    root = Path(__file__).resolve().parents[1]
    examples = sorted((root / 'deploy' / 'compose').glob('*/.env.example'))
    assert examples, 'the immich import should have brought one'

    for path in examples:
        relative = path.relative_to(root).as_posix()
        ignored = subprocess.run(['git', '-C', str(root), 'check-ignore', '-q', relative],
                                 capture_output=True)
        assert ignored.returncode != 0, f'{relative} is ignored by .gitignore'
        tracked = subprocess.run(['git', '-C', str(root), 'ls-files', '--error-unmatch', relative],
                                 capture_output=True)
        assert tracked.returncode == 0, f'{relative} is not committed'
