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


def test_wizard_yaml_and_the_stack_file_pin_the_same_tag():
    """One pin, written twice, on purpose: the record and the thing deployed.

    They drifted once - ``status`` said build-150 in wizard.yaml and build-128
    in its stack - and because ``${IMAGE_TAG:-<pin>}`` falls back to the pin on
    any deploy that did not rebuild the app, the wrong one is what ships.
    """
    import re

    import yaml

    wizard = yaml.safe_load((ROOT / 'deploy' / 'wizard.yaml').read_text()) or {}
    problems = []
    for svc in wizard.get('services') or []:
        name = svc.get('name')
        image, version = str(svc.get('image') or ''), str(svc.get('version') or '')
        default = re.search(r'\$\{IMAGE_TAG:-([^}]*)\}', image)
        if default and version and default.group(1) != version:
            problems.append(f'{name}: wizard.yaml image pins {default.group(1)}, '
                            f'version says {version}')
        stack = ROOT / 'deploy' / 'stacks' / str(name) / 'stack.yml'
        if not stack.is_file() or not default:
            continue
        # every ${IMAGE_TAG:-<pin>} in the stack, not just the one whose image
        # is named after the service ("homelab-wizard" deploys as "wizard")
        for found in re.findall(r'\$\{IMAGE_TAG:-([^}]*)\}', stack.read_text()):
            if found != default.group(1):
                problems.append(f'{name}: stack pins {found}, '
                                f'wizard.yaml pins {default.group(1)}')
    assert problems == [], problems


def test_the_wizard_writes_under_the_estate_root():
    """It renders wizard.yaml and the stacks, so it needs the same prefix."""
    import importlib.util

    # Loaded by path: AILog has its own ``core`` package, and this file is the
    # wizard's, not that one.
    spec = importlib.util.spec_from_file_location(
        'wizard_core', ROOT / 'deploy' / 'apps' / 'homelab-wizard' / 'core.py')
    core = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(core)
    settings_ = {'repo_dir': '/data/repo', 'estate_root': 'deploy'}
    assert core.rel('wizard.yaml', settings_) == 'deploy/wizard.yaml'
    assert core.path('stacks/x/stack.yml', settings_) == '/data/repo/deploy/stacks/x/stack.yml'
    assert core.estate_dir(settings_) == '/data/repo/deploy'
    # an estate at the repo root is still expressible, for a pre-merge checkout
    bare = {'repo_dir': '/data/repo', 'estate_root': ''}
    assert core.rel('wizard.yaml', bare) == 'wizard.yaml'
    assert core.path('wizard.yaml', bare) == '/data/repo/wizard.yaml'


def test_a_stack_absent_from_the_swarm_is_not_created_by_a_push():
    """deploy/stacks keeps records for services that are not deployed.

    The merge that first brought the whole tree in listed every stack as
    changed, so without this guard CI would have created them.
    """
    ship = (ROOT / '.gitea' / 'workflows' / 'ship.yml').read_text()
    assert 'docker stack ls' in ship
    assert 'CREATE_STACKS' in ship
    assert 'create_stacks' in ship      # the dispatch input that opts in


def test_the_push_workflows_compare_against_a_real_base():
    """Both build and mirror once "did nothing" and reported success.

    build.yml fetched main with --depth=1, so `git diff main...HEAD` had no
    merge base, failed, and `|| true` turned that into "No changed apps". A dev
    push therefore never built anything before its PR was opened. mirror.yml
    read its previous state from main, which does not carry the file until the
    first merge - an empty base means every entry looks new, so it re-mirrored
    the whole estate on the branch that introduced it.
    """
    build = (ROOT / '.gitea' / 'workflows' / 'build.yml').read_text()
    assert 'fetch origin main --depth' not in build
    mirror = (ROOT / '.gitea' / 'workflows' / 'mirror.yml').read_text()
    assert 'HEAD^:deploy/mirror-images.json' in mirror


def test_an_existing_checkout_is_repointed_at_the_configured_repository(tmp_path, monkeypatch):
    """A checkout outlives the setting that named it.

    The estate used to be its own repo, so every checkout made before the merge
    had ``origin`` pointing there. ensure() only set the remote when it cloned,
    so AILOG_ESTATE_REPO could not take effect - the sync kept succeeding
    against a repository nobody writes to, and answered every question with
    last month's pins.
    """
    import subprocess

    from estate import git as egit

    directory = tmp_path / 'estate'
    directory.mkdir()

    def run(*args):
        return subprocess.run(['git', *args], cwd=directory, check=True,
                              capture_output=True, text=True).stdout.strip()

    run('init', '-q')
    run('remote', 'add', 'origin', 'https://example.invalid/old.git')
    monkeypatch.setattr(egit.settings, 'authed_url',
                        lambda: 'https://example.invalid/new.git')

    egit.Repo(directory=str(directory)).ensure()

    assert run('remote', 'get-url', 'origin') == 'https://example.invalid/new.git'


def test_ci_writes_the_tag_it_deployed_back_into_the_pins():
    """The one thing two repositories could never do.

    A build tag exists only after the build, so the pin can only be written
    after the deploy. ship.yml therefore has a third job - after release and
    deploy - that pins what it built and pushes it to the working branch.
    """
    import yaml

    ship = yaml.safe_load((ROOT / '.gitea' / 'workflows' / 'ship.yml').read_text())
    jobs = ship['jobs']
    assert 'pin' in jobs
    assert set(jobs['pin']['needs']) == {'release', 'deploy'}
    body = (ROOT / '.gitea' / 'workflows' / 'ship.yml').read_text()
    assert 'deploy/tools/pin_build_tag.py' in body
    assert (ROOT / 'deploy' / 'tools' / 'pin_build_tag.py').is_file()
