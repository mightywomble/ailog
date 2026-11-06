"""The pin has to be written by the run that knows the tag.

A build tag does not exist until the image is built, so no pull request can
name it: that is why the pin was always one release behind in the two-repo
setup, and why ``ingest`` ran build-182 with build-120 written in its stack
file. One repository can close the loop after the deploy - these are the tests
that say the writer agrees with itself, in both places the pin is written.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope='module')
def tool():
    spec = importlib.util.spec_from_file_location(
        'pin_build_tag', ROOT / 'deploy' / 'tools' / 'pin_build_tag.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def estate(tmp_path):
    """A miniature estate: one build app, one mirror, one unrelated stack."""
    (tmp_path / 'stacks' / 'ingest').mkdir(parents=True)
    (tmp_path / 'stacks' / 'ingest' / 'stack.yml').write_text(
        'services:\n'
        '  ingest:\n'
        '    image: zot.safehomelan.com/ingest:${IMAGE_TAG:-build-120}\n')
    (tmp_path / 'stacks' / 'dozzle').mkdir(parents=True)
    (tmp_path / 'stacks' / 'dozzle' / 'stack.yml').write_text(
        'services:\n'
        '  dozzle:\n'
        '    image: zot.safehomelan.com/dozzle:v11.4.1\n')
    (tmp_path / 'wizard.yaml').write_text(
        'version: 1\n'
        'services:\n'
        '- name: ingest\n'
        '  kind: build\n'
        '  service: ingest\n'
        '  image: zot.safehomelan.com/ingest:${IMAGE_TAG:-build-120}\n'
        '  repo: ingest\n'
        '  version: build-120\n'
        '- name: dozzle\n'
        '  kind: mirror\n'
        '  service: dozzle\n'
        '  image: zot.safehomelan.com/dozzle:v11.4.1\n'
        '  version: v11.4.1\n')
    return tmp_path


def test_it_points_the_stack_file_at_the_tag_that_was_just_built(tool, estate):
    touched = tool.pin('build-256', ['ingest'], root=estate)

    assert touched == ['stacks/ingest/stack.yml', 'wizard.yaml']
    stack = (estate / 'stacks' / 'ingest' / 'stack.yml').read_text()
    assert '${IMAGE_TAG:-build-256}' in stack
    assert 'build-120' not in stack


def test_it_moves_the_record_beside_the_image_in_wizard_yaml(tool, estate):
    tool.pin('build-256', ['ingest'], root=estate)

    wizard = yaml.safe_load((estate / 'wizard.yaml').read_text())
    entry = next(s for s in wizard['services'] if s['name'] == 'ingest')
    assert entry['version'] == 'build-256'
    assert entry['image'].endswith('${IMAGE_TAG:-build-256}')


def test_two_pins_for_one_service_never_disagree(tool, estate):
    """wizard.yaml ships the pin twice - the image and the version - and they
    drifted apart once. Whoever writes one writes the other."""
    tool.pin('build-256', ['ingest'], root=estate)

    wizard = yaml.safe_load((estate / 'wizard.yaml').read_text())
    entry = next(s for s in wizard['services'] if s['name'] == 'ingest')
    stack = (estate / 'stacks' / 'ingest' / 'stack.yml').read_text()
    in_image = entry['image'].split(':-', 1)[1].rstrip('}')
    assert in_image == entry['version'] == 'build-256'
    assert f'${{IMAGE_TAG:-{in_image}}}' in stack


def test_a_mirror_is_left_alone(tool, estate):
    """Mirrored images carry a literal tag; there is no build to record."""
    tool.pin('build-256', ['ingest'], root=estate)

    assert 'v11.4.1' in (estate / 'stacks' / 'dozzle' / 'stack.yml').read_text()
    wizard = yaml.safe_load((estate / 'wizard.yaml').read_text())
    assert next(s for s in wizard['services'] if s['name'] == 'dozzle')['version'] == 'v11.4.1'


def test_a_second_run_is_a_no_op(tool, estate):
    """The loop converges: the pin job opening a commit every run would be a
    commit every release for nothing."""
    tool.pin('build-256', ['ingest'], root=estate)
    assert tool.pin('build-256', ['ingest'], root=estate) == []


def test_an_empty_tag_is_not_written(tool, estate):
    assert tool.pin('', ['ingest'], root=estate) == []


def test_it_only_touches_the_app_it_was_given(tool, estate):
    (estate / 'stacks' / 'status').mkdir()
    (estate / 'stacks' / 'status' / 'stack.yml').write_text(
        'services:\n  status:\n'
        '    image: zot.safehomelan.com/status:${IMAGE_TAG:-build-150}\n')

    tool.pin('build-256', ['ingest'], root=estate)

    assert 'build-150' in (estate / 'stacks' / 'status' / 'stack.yml').read_text()


def test_the_real_estate_is_consistent_after_pinning_itself(tool, tmp_path):
    """Run against a copy of the real tree: every pin the tool writes still
    satisfies the rule test_repo_layout asserts (image default == version)."""
    import shutil

    copy = tmp_path / 'deploy'
    shutil.copytree(ROOT / 'deploy', copy, ignore=shutil.ignore_patterns('apps', 'docs'))
    apps = ['ingest', 'status', 'metamcp', 'goodbye', 'homelab-wizard']

    tool.pin('build-256', apps, root=copy)

    wizard = yaml.safe_load((copy / 'wizard.yaml').read_text())
    for svc in wizard['services']:
        image = str(svc.get('image') or '')
        if '${IMAGE_TAG:-' not in image:
            continue
        assert image.split(':-', 1)[1].rstrip('}') == str(svc['version']), svc['name']
        stack = (copy / 'stacks' / svc['name'] / 'stack.yml').read_text()
        for found in __import__('re').findall(r'\$\{IMAGE_TAG:-([^}]*)\}', stack):
            assert found == str(svc['version']), svc['name']
