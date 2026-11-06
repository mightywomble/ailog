"""One repo: the estate lives in AILog's own tree, under ``deploy/``.

It used to be two repositories - the app, and the repo that deploys the app and
builds its images. Two repos meant two merges to ship a fix, a pin that could
only be updated by hand after a build (which is how a dozen services got rolled
backwards), and an app that had to hold a clone of a second repo to answer "what
does git say this should be running".

Everything below is the price of that merge, and it is small: every path the
estate reads or commits goes through one prefix, and the prefix is resolved
against the tree so a checkout made before the merge still works.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from estate import settings
from estate.git import Repo

ROOT = Path(__file__).resolve().parents[1]

WIZARD = 'services:\n  - name: anchor\n    kind: mirror\n    version: 0.9.1\n'


@pytest.fixture()
def checkout(tmp_path):
    def build(prefix: str):
        directory = tmp_path / 'repo'
        (directory / '.git').mkdir(parents=True)
        target = directory / prefix / 'wizard.yaml' if prefix else directory / 'wizard.yaml'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(WIZARD)
        if prefix:
            stack = directory / prefix / 'stacks' / 'anchor' / 'stack.yml'
            stack.parent.mkdir(parents=True)
            stack.write_text('services:\n  anchor:\n    image: zot.safehomelan.com/anchor:0.9.1\n')
        return directory

    return build


def test_the_estate_is_read_from_deploy_in_the_merged_layout(checkout, monkeypatch):
    monkeypatch.delenv('AILOG_ESTATE_ROOT', raising=False)
    repo = Repo(directory=str(checkout('deploy')))

    assert repo.root() == 'deploy'
    assert repo.path('wizard.yaml').endswith('deploy/wizard.yaml')
    assert repo.read('wizard.yaml') == WIZARD
    assert 'deploy/stacks/anchor' in repo.path('stacks/anchor/stack.yml')


def test_a_checkout_from_before_the_merge_still_reads(checkout, monkeypatch):
    """The estate was its own repo: wizard.yaml at the root. Report that, don't
    pretend the tree has no services."""
    monkeypatch.delenv('AILOG_ESTATE_ROOT', raising=False)
    repo = Repo(directory=str(checkout('')))

    assert repo.root() == ''
    assert repo.path('wizard.yaml') == os.path.join(repo.dir, 'wizard.yaml')
    assert repo.read('wizard.yaml') == WIZARD


def test_the_root_can_be_pointed_somewhere_else(checkout, monkeypatch):
    monkeypatch.setenv('AILOG_ESTATE_ROOT', 'infra/')
    repo = Repo(directory=str(checkout('infra')))
    assert repo.root() == 'infra'
    assert repo.path('wizard.yaml').endswith('infra/wizard.yaml')


def test_commits_are_staged_under_the_root(tmp_path, monkeypatch):
    """`git add` must name the prefixed path, or the commit is empty."""
    monkeypatch.delenv('AILOG_ESTATE_ROOT', raising=False)
    directory = tmp_path / 'repo'
    (directory / '.git').mkdir(parents=True)
    (directory / 'deploy' / 'stacks' / 'anchor').mkdir(parents=True)
    (directory / 'deploy' / 'wizard.yaml').write_text(WIZARD)
    repo = Repo(directory=str(directory))

    seen = []

    def fake_git(*args, **kwargs):
        seen.append(args)
        if args[0] == 'status':
            return True, ' M deploy/wizard.yaml\n'
        return True, ''

    monkeypatch.setattr(repo, 'git', fake_git)
    staged = repo.commit('bump', ['wizard.yaml'])

    assert ('add', '--', 'deploy/wizard.yaml') in seen
    # what comes back is repo-relative, the way the rest of the code thinks
    assert staged == ['wizard.yaml']


def test_the_defaults_point_at_this_repository():
    assert settings.name() == 'ailog'
    assert settings.owner() == 'david'
    assert settings.repo_url().endswith('/david/ailog.git')
    # the tree the app ships is the tree the estate lives in
    assert (ROOT / 'deploy' / 'wizard.yaml').is_file()
    assert (ROOT / 'deploy' / 'stacks' / 'ailog' / 'stack.yml').is_file()
    assert (ROOT / 'deploy' / 'mirror-images.json').is_file()


def test_one_repo_builds_and_deploys_from_the_same_tree():
    """The workflows used to live in the other repo; every path they touch is
    under deploy/ now, and nothing still points at the old layout."""
    ship = (ROOT / '.gitea' / 'workflows' / 'ship.yml').read_text()
    build = (ROOT / '.gitea' / 'workflows' / 'build.yml').read_text()
    mirror = (ROOT / '.gitea' / 'workflows' / 'mirror.yml').read_text()

    for text in (ship, build):
        assert 'deploy/apps/' in text
    assert 'deploy/stacks/' in ship
    assert 'deploy/mirror-images.json' in mirror
    # the old repo's copies are gone, so nothing can run from the stale layout
    assert not (ROOT / 'deploy' / '.gitea').exists()

    # builds run on the build server's runner, deploys on the swarm manager
    assert 'runs-on: ubuntu-latest' in ship and 'runs-on: deploy' in ship
    assert 'runs-on: ubuntu-latest' in build and 'runs-on: ubuntu-latest' in mirror


def test_no_workflow_pushes_or_clones_the_old_repo():
    """It is fine to mention the old repo in a comment explaining the merge."""
    import re

    for path in (ROOT / '.gitea' / 'workflows').glob('*.yml'):
        for line in path.read_text().splitlines():
            if line.lstrip().startswith('#'):
                continue
            assert 'homelab-ops' not in line, f'{path.name}: {line.strip()}'


def test_the_stack_tells_the_app_which_repo_is_the_estate():
    stack = (ROOT / 'deploy' / 'stacks' / 'ailog' / 'stack.yml').read_text()
    assert 'AILOG_ESTATE_REPO' in stack
    assert '/david/ailog.git' in stack or 'david/ailog' in stack
    assert 'AILOG_ESTATE_ROOT' in stack
