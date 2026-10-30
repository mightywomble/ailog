"""Validate and load the remediation catalog.

The YAML files in remediations/ are the source of truth.  Validation is
strict on purpose: a malformed catalog entry must fail in CI, not halfway
through a fleet run.  Every entry that survives validation is, by
definition, executable - model output never passes through here.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

CATALOG_DIR = Path(__file__).resolve().parent.parent / 'remediations'
SLUG_RE = re.compile(r'^[a-z0-9][a-z0-9-]{1,95}$')
RISKS = ('low', 'medium', 'high')
REQUIRE_TYPES = ('command_exists', 'path_exists', 'unit_active', 'container_exists')

REQUIRED_KEYS = ('slug', 'version', 'title', 'summary', 'risk', 'match', 'playbook', 'verify')

_cache: dict = {'key': None, 'entries': []}


class CatalogError(ValueError):
    """A catalog entry is invalid."""


def _fail(path: Path, message: str):
    raise CatalogError(f'{path.name}: {message}')


def _check_str(entry: dict, key: str, path: Path, allow_empty: bool = False) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        _fail(path, f'{key} must be a non-empty string')
    return value.strip()


def _check_list(entry: dict, key: str, path: Path, required: bool = True) -> list:
    value = entry.get(key)
    if value is None:
        if required:
            _fail(path, f'{key} is required')
        return []
    if not isinstance(value, list):
        _fail(path, f'{key} must be a list')
    return value


def _validate(entry: dict, path: Path, root: Path | None = None) -> dict:
    root = (root or CATALOG_DIR).resolve()
    if not isinstance(entry, dict):
        _fail(path, 'top level must be a mapping')
    for key in REQUIRED_KEYS:
        if key not in entry:
            _fail(path, f'missing key {key!r}')

    slug = _check_str(entry, 'slug', path)
    if not SLUG_RE.match(slug):
        _fail(path, 'slug must be lowercase letters, digits and dashes')
    if slug != path.stem:
        _fail(path, f'slug {slug!r} must match the filename')

    risk = _check_str(entry, 'risk', path).lower()
    if risk not in RISKS:
        _fail(path, f'risk must be one of {RISKS}')

    playbook = _check_str(entry, 'playbook', path)
    playbook_path = (path.parent / playbook.lstrip('/')).resolve()
    if not playbook_path.is_file():
        _fail(path, f'playbook {playbook!r} does not exist')
    if root not in playbook_path.parents:
        _fail(path, 'playbook must live inside remediations/')

    rollback = entry.get('rollback')
    if rollback:
        rollback_path = (path.parent / str(rollback).lstrip('/')).resolve()
        if not rollback_path.is_file():
            _fail(path, f'rollback {rollback!r} does not exist')
        if root not in rollback_path.parents:
            _fail(path, 'rollback must live inside the catalog directory')
    elif risk != 'low':
        _fail(path, 'rollback is mandatory for risk != low')

    verify = entry.get('verify')
    if not isinstance(verify, dict) or not isinstance(verify.get('command'), str) or not verify['command'].strip():
        _fail(path, 'verify.command is required')
    if not isinstance(verify.get('expect'), dict) or not verify['expect']:
        _fail(path, 'verify.expect must be a non-empty mapping')
    allowed_expect = ('stdout_matches', 'stdout_contains', 'stdout_min', 'stdout_max', 'exit_code')
    if not any(k in verify['expect'] for k in allowed_expect):
        _fail(path, f'verify.expect needs one of {allowed_expect}')

    match_value = entry.get('match')
    if isinstance(match_value, dict):
        rules = match_value.get('any') or []
    elif isinstance(match_value, list):
        rules = match_value
    else:
        _fail(path, 'match must be a list of rules or a mapping with any[]')
    if not rules:
        _fail(path, 'match must contain at least one rule')
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get('signature_regex'), str):
            _fail(path, 'each match rule needs a signature_regex string')
        try:
            re.compile(rule['signature_regex'], re.IGNORECASE)
        except re.error as exc:
            _fail(path, f'invalid regex {rule["signature_regex"]!r}: {exc}')
        count = rule.get('min_count', 1)
        if not isinstance(count, int) or count < 1:
            _fail(path, 'min_count must be a positive integer')

    for req in _check_list(entry, 'requires', path, required=False):
        if not isinstance(req, dict) or len(req) != 1:
            _fail(path, 'requires entries must be single-key mappings')
        if next(iter(req)) not in REQUIRE_TYPES:
            _fail(path, f'unsupported requirement {next(iter(req))!r}')

    blast = entry.get('blast_radius') or {}
    if not isinstance(blast, dict):
        _fail(path, 'blast_radius must be a mapping')
    changes = [str(x) for x in (blast.get('changes') or [])]
    does_not = [str(x) for x in (blast.get('does_not') or [])]
    if not changes or not does_not:
        _fail(path, 'blast_radius.changes and blast_radius.does_not are mandatory')

    try:
        version = int(entry['version'])
    except (TypeError, ValueError):
        _fail(path, 'version must be an integer')

    playbook_text = playbook_path.read_text()
    expect = verify['expect']
    verify_text = verify['command'].strip()
    if 'stdout_matches' in expect:
        verify_text += f"  # expect stdout matching {expect['stdout_matches']}"
    elif 'stdout_max' in expect:
        verify_text += f"  # expect numeric stdout <= {expect['stdout_max']}"
    elif 'stdout_min' in expect:
        verify_text += f"  # expect numeric stdout >= {expect['stdout_min']}"
    elif 'stdout_contains' in expect:
        verify_text += f"  # expect stdout containing {expect['stdout_contains']}"
    elif 'exit_code' in expect:
        verify_text += f"  # expect exit code {expect['exit_code']}"

    rollback_text = ''
    if rollback:
        rollback_text = (path.parent / str(rollback)).read_text()

    return {
        'slug': slug,
        'version': version,
        'title': _check_str(entry, 'title', path),
        'summary': _check_str(entry, 'summary', path),
        'risk': risk,
        'est_seconds': int(entry.get('est_seconds') or 30),
        'idempotent': bool(entry.get('idempotent', True)),
        'os': [str(x).lower() for x in (entry.get('os') or [])],
        'requires': entry.get('requires') or [],
        'match': {'any': rules},
        'changes': changes,
        'does_not': does_not,
        'playbook': str(playbook_path.relative_to(root)),
        'playbook_text': playbook_text,
        'verify': verify,
        'verify_text': verify_text,
        'rollback': (str((path.parent / str(rollback)).resolve().relative_to(root)) if rollback else None),
        'rollback_text': rollback_text,
        'fleet_safe': bool(entry.get('fleet_safe', False)),
        'executable': True,
        'path': str(path),
    }


def load_all(directory: Path | None = None, force: bool = False) -> list[dict]:
    """Load every *.yml in remediations/, validating each one."""
    directory = Path(directory or CATALOG_DIR).resolve()
    files = sorted(directory.glob('*.yml')) + sorted(directory.glob('*.yaml'))
    key = tuple((str(f), f.stat().st_mtime_ns) for f in files)
    if not force and _cache['key'] == key:
        return _cache['entries']

    entries, seen = [], set()
    for path in files:
        try:
            raw = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            raise CatalogError(f'{path.name}: invalid YAML: {exc}') from exc
        entry = _validate(raw, path, directory)
        if entry['slug'] in seen:
            raise CatalogError(f'{path.name}: duplicate slug {entry["slug"]!r}')
        seen.add(entry['slug'])
        entries.append(entry)

    _cache['key'] = key
    _cache['entries'] = entries
    return entries


def get(slug: str) -> dict | None:
    for entry in load_all():
        if entry['slug'] == slug:
            return entry
    return None


def sync(db, model) -> list[str]:
    """Upsert the catalog mirror table. Returns the slugs seen."""
    entries = load_all()
    existing = {row.slug: row for row in model.query.all()}
    for entry in entries:
        row = existing.pop(entry['slug'], None) or model(slug=entry['slug'])
        row.version = entry['version']
        row.title = entry['title']
        row.summary = entry['summary']
        row.risk = entry['risk']
        row.est_seconds = entry['est_seconds']
        row.executable = True
        row.fleet_safe = entry['fleet_safe']
        row.requires_json = json.dumps(entry['requires'])
        row.changes_json = json.dumps(entry['changes'])
        row.does_not_json = json.dumps(entry['does_not'])
        row.yaml_json = json.dumps({k: v for k, v in entry.items() if k != 'playbook_text'})
        if row.id is None:
            row.enabled = True
            db.session.add(row)
    db.session.commit()
    return [e['slug'] for e in entries]