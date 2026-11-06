"""Moving one service of one stack, without dragging the rest of it along.

``estate.update.perform`` moves the service ``wizard.yaml`` knows by name — the
app's own image. A companion (``metamcp``'s postgres, ``wordpress``'s mysql)
lives only in the stack file, so an update to it has to be written there. These
tests pin the two things that makes true: the image line moves and nothing else
does, and a build app's ``${IMAGE_TAG:-…}`` placeholder survives.
"""

from __future__ import annotations

import pytest

from estate import stackservice

STACK = """\
services:
  app:
    image: zot.safehomelan.com/metamcp:${IMAGE_TAG:-build-348}
    environment:
      POSTGRES_HOST: "postgres"
  postgres:
    image: zot.safehomelan.com/postgres16:16-alpine
    volumes:
      - data:/var/lib/postgresql/data
volumes:
  data:
"""


def test_one_services_image_moves_and_the_rest_of_the_file_does_not():
    text, changed = stackservice.set_image_version(
        STACK, 'postgres', 'zot.safehomelan.com/postgres16', '16.4-alpine')

    assert changed is True
    assert 'image: zot.safehomelan.com/postgres16:16.4-alpine' in text
    assert 'image: zot.safehomelan.com/metamcp:${IMAGE_TAG:-build-348}' in text
    # comments and the rest of the file are untouched: a version bump is one line
    assert 'POSTGRES_HOST: "postgres"' in text
    assert 'volumes:\n  data:' in text


def test_a_build_apps_placeholder_is_preserved():
    """ship.yml exports the tag it built; a literal would disable that."""
    text, changed = stackservice.set_image_version(
        STACK, 'app', 'zot.safehomelan.com/metamcp', 'build-400')

    assert changed is True
    assert '${IMAGE_TAG:-build-400}' in text
    assert 'build-348' not in text


def test_asking_for_the_version_it_already_has_changes_nothing():
    text, changed = stackservice.set_image_version(
        STACK, 'postgres', 'zot.safehomelan.com/postgres16', '16-alpine')

    assert changed is False
    assert text == STACK


def test_an_unknown_service_is_not_silently_ignored_at_commit_time():
    text, changed = stackservice.set_image_version(STACK, 'redis', 'zot/redis', '7')
    assert changed is False


def test_the_current_tag_is_read_from_the_placeholder():
    assert stackservice._current_tag('zot.safehomelan.com/a:${IMAGE_TAG:-build-9}') == 'build-9'
    assert stackservice._current_tag('zot.safehomelan.com/postgres16:16-alpine') == '16-alpine'
    assert stackservice._current_tag('zot.safehomelan.com/a@sha256:' + 'a' * 64) == ''


@pytest.mark.parametrize('source,version,want', [
    ('docker.io/library/postgres:16-alpine', '16.4-alpine',
     'docker.io/library/postgres:16.4-alpine'),
    ('ghcr.io/metatool-ai/metamcp:2.4.22', '2.4.23',
     'ghcr.io/metatool-ai/metamcp:2.4.23'),
    ('docker.io/library/redis', '7-alpine', 'docker.io/library/redis:7-alpine'),
])
def test_the_upstream_reference_is_retagged_not_concatenated(source, version, want):
    assert stackservice._retag(source, version) == want


def test_the_real_stack_files_still_round_trip():
    """Whatever the estate holds now, a bump of its own tag must parse back."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / 'deploy' / 'stacks'
    for path in sorted(root.glob('*/stack.yml')):
        text = path.read_text()
        import yaml
        doc = yaml.safe_load(text) or {}
        for service in (doc.get('services') or {}):
            image = stackservice.service_image(text, service)
            if not image:
                continue
            current = stackservice._current_tag(image)
            if not current:
                continue
            bumped, changed = stackservice.set_image_version(text, service, image, current)
            assert not changed, f'{path.name}: {service} reported a change to its own tag'
            assert bumped == text
