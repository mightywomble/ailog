"""The catalog is the trust boundary: if it validates, it may run.

These tests fail in CI when someone adds a remedy that is dangerous,
unverifiable or unfalsifiable - not halfway through a fleet run.
"""

from __future__ import annotations

import json

import pytest

from remediation import catalog

REQUIRED = ('slug', 'version', 'title', 'summary', 'risk', 'est_seconds',
            'match', 'playbook', 'verify', 'changes', 'does_not')
CATALOG_NAMES = sorted(p.stem for p in catalog.CATALOG_DIR.glob('*.yml'))


@pytest.fixture(scope='module')
def entries():
    return catalog.load_all(force=True)


def test_the_catalog_directory_has_entries():
    assert CATALOG_NAMES, 'remediations/ must contain at least one remedy'


def test_every_entry_validates(entries):
    # load_all raises CatalogError, so simply getting here is the assertion.
    assert len(entries) == len(CATALOG_NAMES)


def test_slugs_are_unique_and_match_their_filenames(entries):
    slugs = [entry['slug'] for entry in entries]
    assert len(slugs) == len(set(slugs))
    assert sorted(slugs) == CATALOG_NAMES


def test_every_entry_carries_the_required_keys(entries):
    for entry in entries:
        for key in REQUIRED:
            assert key in entry, f'{entry["slug"]} is missing {key}'
        assert entry['title'].strip()
        assert entry['summary'].strip()
        assert entry['est_seconds'] >= 0


def test_risk_values_are_known(entries):
    for entry in entries:
        assert entry['risk'] in catalog.RISKS, entry['slug']


def test_rollback_is_mandatory_above_low_risk(entries):
    """A medium/high remedy without a way back is not allowed to exist."""
    for entry in entries:
        if entry['risk'] != 'low':
            assert entry.get('rollback'), f'{entry["slug"]} must ship a rollback'
            assert entry.get('rollback_text'), f'{entry["slug"]} rollback is unreadable'


def test_playbooks_and_rollbacks_exist_inside_the_catalog(entries):
    for entry in entries:
        playbook = (catalog.CATALOG_DIR / entry['playbook']).resolve()
        assert playbook.is_file(), entry['slug']
        assert catalog.CATALOG_DIR in playbook.parents, entry['slug']
        if entry.get('rollback'):
            rollback = (catalog.CATALOG_DIR / entry['rollback']).resolve()
            assert rollback.is_file(), entry['slug']
            assert catalog.CATALOG_DIR in rollback.parents, entry['slug']


def test_every_entry_has_a_verifiable_outcome(entries):
    allowlist = ('stdout_matches', 'stdout_contains', 'stdout_min', 'stdout_max', 'exit_code')
    for entry in entries:
        verify = entry['verify']
        assert verify.get('command'), entry['slug']
        assert verify.get('expect'), entry['slug']
        # At least one expectation must be something we can actually evaluate.
        assert any(key in allowlist for key in verify['expect']), entry['slug']


def test_match_rules_compile_and_are_specific(entries):
    import re
    for entry in entries:
        rules = entry['match']['any']
        assert rules, entry['slug']
        for rule in rules:
            assert rule.get('signature_regex'), entry['slug']
            re.compile(rule['signature_regex'])          # must not raise
            assert int(rule.get('min_count', 1)) >= 1, entry['slug']


def test_every_entry_declares_its_blast_radius(entries):
    for entry in entries:
        changes = entry.get('changes') or []
        does_not = entry.get('does_not') or []
        assert changes, f'{entry["slug"]} must say what it changes'
        assert does_not, f'{entry["slug"]} must say what it will not touch'


def test_an_unknown_slug_returns_none():
    assert catalog.get('this-remedy-does-not-exist') is None


def test_get_returns_a_validated_entry(entries):
    sample = entries[0]['slug']
    assert catalog.get(sample)['slug'] == sample


def test_the_cache_reuses_entries_until_forced():
    catalog.load_all(force=True)
    first = catalog.load_all()
    second = catalog.load_all()
    assert first is second


def _write_catalog(tmp_path, name, body):
    (tmp_path / name).write_text(body)
    return tmp_path


def test_a_bad_slug_fails_validation(tmp_path):
    _write_catalog(tmp_path, 'MixedCase.yml', 'slug: MixedCase\n')
    with pytest.raises(catalog.CatalogError):
        catalog.load_all(tmp_path, force=True)


def test_a_mismatched_slug_fails_validation(tmp_path):
    body = '\n'.join([
        'slug: other-name', 'version: 1', 'title: T', 'summary: S',
        'risk: low', 'est_seconds: 5', 'match:', '  any:',
        '    - signature_regex: x', 'playbook: p.yml', 'verify:',
        '  command: true', '  expect:', '    exit_code: 0',
        'blast_radius:', '  changes: [a]', '  does_not: [b]',
    ])
    _write_catalog(tmp_path, 'real-name.yml', body)
    with pytest.raises(catalog.CatalogError):
        catalog.load_all(tmp_path, force=True)


def test_a_medium_risk_entry_without_rollback_fails(tmp_path):
    (tmp_path / 'playbooks').mkdir()
    (tmp_path / 'playbooks' / 'risky.yml').write_text('- hosts: all\n')
    body = '\n'.join([
        'slug: risky', 'version: 1', 'title: T', 'summary: S',
        'risk: medium', 'est_seconds: 5', 'match:', '  any:',
        '    - signature_regex: x', 'playbook: playbooks/risky.yml', 'verify:',
        '  command: true', '  expect:', '    exit_code: 0',
        'blast_radius:', '  changes: [a]', '  does_not: [b]',
    ])
    (tmp_path / 'risky.yml').write_text(body)
    with pytest.raises(catalog.CatalogError, match='rollback'):
        catalog.load_all(tmp_path, force=True)


def test_playbooks_outside_the_catalog_are_rejected(tmp_path):
    outside = tmp_path / 'outside.yml'
    outside.write_text('[]\n')
    root = tmp_path / 'catalog'
    root.mkdir()
    body = '\n'.join([
        'slug: escape', 'version: 1', 'title: T', 'summary: S',
        'risk: low', 'est_seconds: 5', 'match:', '  any:',
        '    - signature_regex: x', 'playbook: ../outside.yml', 'verify:',
        '  command: true', '  expect:', '    exit_code: 0',
        'blast_radius:', '  changes: [a]', '  does_not: [b]',
    ])
    (root / 'escape.yml').write_text(body)
    with pytest.raises(catalog.CatalogError):
        catalog.load_all(root, force=True)


def test_sync_mirrors_the_catalog_into_the_table(ctx, entries):
    from database import Remediation, db
    catalog.sync(db, Remediation)
    rows = {row.slug: row for row in Remediation.query.all()}
    for entry in entries:
        assert entry['slug'] in rows, entry['slug']
        assert rows[entry['slug']].risk == entry['risk']
        assert rows[entry['slug']].executable is True
        assert json.loads(rows[entry['slug']].yaml_json)['playbook'] == entry['playbook']
