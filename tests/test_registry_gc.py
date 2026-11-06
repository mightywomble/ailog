"""Pruning zot: keep what is used and the newest two, delete the rest.

Either half alone is dangerous. Deleting only the "old" tags breaks the
rollback that was the whole point of keeping a pin; deleting nothing is what
the registry has been doing since it was built (eight ``ailog-mcp`` build tags,
two ``postgres16`` digests, 120 old tags in total).
"""

from __future__ import annotations

import pytest

from dockermon import registrygc as gc


@pytest.fixture()
def zot(monkeypatch):
    """A registry with a known set of tags and a known set of users."""
    repo_tags = {
        'ailog': ['v3.24.0', 'v3.25.0', 'v3.25.1', 'v3.25.2', 'latest',
                  'a80d338', 'sha-2ea1a207542c'],
        'ailog-mcp': ['build-7', 'build-114', 'build-191', 'build-256', 'latest'],
        'metamcp': ['2.4.22', 'build-317', 'build-348', 'latest'],
    }
    digests = {}
    counter = [0]

    def fake_tags(repo):
        return list(repo_tags.get(repo, []))

    def fake_digest(repo, tag):
        key = f'{repo}:{tag}'
        if key not in digests:
            counter[0] += 1
            digests[key] = 'sha256:' + (f'{counter[0]:064x}')
        return digests[key]

    monkeypatch.setattr(gc, 'catalog', lambda limit=500: list(repo_tags))
    monkeypatch.setattr(gc, 'tags', fake_tags)
    monkeypatch.setattr(gc, '_digest', fake_digest)
    monkeypatch.setattr(gc, 'referenced', lambda: {
        'tags': {('ailog', 'v3.25.2'), ('ailog-mcp', 'build-256')},
        'digests': set(),
    })
    return repo_tags, digests


def test_the_newest_two_are_kept(zot):
    planned = gc.plan(repos=['ailog'], keep=2)
    deleted = set(planned['repos'][0]['delete'])

    assert 'v3.25.2' not in deleted          # in use
    assert 'v3.25.1' not in deleted          # newest two
    assert 'v3.25.0' in deleted
    assert 'v3.24.0' in deleted
    assert 'latest' not in deleted


def test_a_commit_sha_is_not_a_version(zot):
    """``a80d338`` parses as "version 80" - it must not outrank a release."""
    planned = gc.plan(repos=['ailog'], keep=2)
    assert 'a80d338' in set(planned['repos'][0]['delete'])


def test_build_tags_are_compared_as_numbers(zot):
    planned = gc.plan(repos=['ailog-mcp'], keep=2)
    deleted = set(planned['repos'][0]['delete'])

    assert 'build-256' not in deleted        # in use
    assert 'build-191' not in deleted        # second newest
    assert {'build-7', 'build-114'} == deleted


def test_what_git_or_a_container_names_is_never_deleted(zot):
    """A pin that is not deployed yet is still a rollback waiting to happen."""
    planned = gc.plan(repos=['ailog'], keep=1)
    deleted = set(planned['repos'][0]['delete'])
    assert 'v3.25.2' not in deleted


def test_a_manifest_is_only_deleted_when_none_of_its_tags_is_kept(monkeypatch):
    """Two tags can share one digest; deleting it would take the kept one too."""
    monkeypatch.setattr(gc, 'catalog', lambda limit=500: ['app'])
    monkeypatch.setattr(gc, 'tags', lambda repo: ['1.0', '1.1', '1.2'])
    monkeypatch.setattr(gc, '_digest', lambda repo, tag: {
        '1.0': 'sha256:' + 'a' * 64,
        '1.1': 'sha256:' + 'a' * 64,     # same manifest as 1.0
        '1.2': 'sha256:' + 'b' * 64,
    }[tag])
    monkeypatch.setattr(gc, 'referenced', lambda: {'tags': set(), 'digests': set()})

    planned = gc.plan(repos=['app'], keep=2)

    # 1.2 and 1.1 are the newest two, so the sha 1.0 shares with 1.1 is kept
    assert planned['repos'] == []


def test_nothing_is_deleted_while_it_is_running(monkeypatch):
    monkeypatch.setattr(gc, 'catalog', lambda limit=500: ['postgres16'])
    monkeypatch.setattr(gc, 'tags', lambda repo: ['15-alpine', '16-alpine'])
    monkeypatch.setattr(gc, '_digest', lambda repo, tag: 'sha256:' + tag[0:1] * 64)
    monkeypatch.setattr(gc, 'referenced', lambda: {
        'tags': {('postgres16', '15-alpine')}, 'digests': set(),
    })

    planned = gc.plan(repos=['postgres16'], keep=1)

    assert planned['repos'] == []


def test_a_dry_run_deletes_nothing(monkeypatch):
    monkeypatch.setattr(gc, 'catalog', lambda limit=500: ['app'])
    monkeypatch.setattr(gc, 'tags', lambda repo: ['1.0', '1.1', '1.2'])
    monkeypatch.setattr(gc, '_digest', lambda repo, tag: 'sha256:' + tag[-1] * 64)
    monkeypatch.setattr(gc, 'referenced', lambda: {'tags': set(), 'digests': set()})
    calls = []
    monkeypatch.setattr(gc, '_call', lambda path, method='GET', timeout=20: calls.append(path))

    out = gc.prune(repos=['app'], keep=2, dry_run=True)

    assert calls == []
    assert [row['tag'] for row in out['deleted']] == ['1.0']
    assert out['dry_run'] is True


def test_a_delete_that_the_registry_refuses_is_reported(monkeypatch):
    monkeypatch.setattr(gc, 'catalog', lambda limit=500: ['app'])
    monkeypatch.setattr(gc, 'tags', lambda repo: ['1.0', '1.1', '1.2'])
    monkeypatch.setattr(gc, '_digest', lambda repo, tag: 'sha256:' + tag[-1] * 64)
    monkeypatch.setattr(gc, 'referenced', lambda: {'tags': set(), 'digests': set()})
    monkeypatch.setattr(gc, '_call', lambda path, method='GET', timeout=20: (403, {}, b'denied'))

    out = gc.prune(repos=['app'], keep=2)

    assert out['deleted'] == []
    assert out['failed'][0]['status'] == 403
