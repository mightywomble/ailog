"""composecfg: the standalone-docker half of the estate.

Swarm services are described by ``deploy/stacks/<name>/stack.yml`` and shipped by
ship.yml. Hosts that run plain ``docker compose`` - photos (immich) today, more
later - are described by ``deploy/compose/<name>/`` and shipped by compose.yml.
This module is only the reading half: what projects exist, where they run, what
they pin, and whether the .env on each host has the keys the project needs.

It reads the same checkout the estate reads, so the section cannot describe a
tree that CI is not about to deploy.
"""

from __future__ import annotations

import json
import os
import re

from flask import Blueprint, jsonify

from estate.git import GitError, Repo

compose_bp = Blueprint('composecfg', __name__)

COMPOSE_DIR = 'compose'
IMAGE = re.compile(r'image:\s*(\S+)')


def _projects_dir(repo: Repo) -> str:
    return os.path.join(repo.dir, repo.root(), COMPOSE_DIR)


def _read(path: str) -> str:
    try:
        with open(path) as fh:
            return fh.read()
    except OSError:
        return ''


def _images(compose_text: str) -> list[dict]:
    """Every image in a compose file, with the pin and whether it comes from zot."""
    rows = []
    for raw in IMAGE.findall(compose_text):
        default = re.search(r'\$\{[A-Z_]*:-([^}]*)\}', raw)
        variable = re.search(r'\$\{([A-Z_]+)', raw)
        registry = raw.split('/', 1)[0]
        rows.append({
            'ref': raw,
            'image': raw.split(':', 1)[0] if '://' not in raw else raw,
            'pin': default.group(1) if default else raw.rsplit(':', 1)[-1],
            'variable': variable.group(1) if variable else '',
            'from_zot': registry == 'zot.safehomelan.com',
        })
    return rows


def projects(repo: Repo | None = None) -> list[dict]:
    """Every compose project in the tree, as it is written down."""
    repo = repo or Repo()
    base = _projects_dir(repo)
    if not os.path.isdir(base):
        return []

    out = []
    for name in sorted(os.listdir(base)):
        directory = os.path.join(base, name)
        project_file = os.path.join(directory, 'project.json')
        if not os.path.isfile(project_file):
            continue
        try:
            with open(project_file) as fh:
                meta = json.load(fh)
        except (OSError, ValueError) as exc:
            out.append({'name': name, 'error': f'project.json is not readable: {str(exc)[:160]}'})
            continue

        compose_name = str(meta.get('compose_file') or 'compose.yml')
        compose_text = _read(os.path.join(directory, 'compose.yml')) or _read(
            os.path.join(directory, compose_name))

        images = _images(compose_text)
        out.append({
            'name': str(meta.get('name') or name),
            'description': str(meta.get('description') or ''),
            'host': str(meta.get('host') or ''),
            'ssh': str(meta.get('ssh') or ''),
            'dir': str(meta.get('dir') or ''),
            'compose_file': compose_name,
            'env_file': str(meta.get('env_file') or '.env'),
            'env_keys': list(meta.get('env_keys') or []),
            'health': meta.get('health') or {},
            'images': images,
            # Not "is it up to date" - that is a question for the host, and the
            # host is not asked here. These are the things a person can fix by
            # reading the tree: an image that does not come from zot, a project
            # with no recorded health check, an .env example that has drifted
            # from the keys the project needs.
            'problems': (
                [f'{i["ref"]} does not come from zot' for i in images if not i['from_zot']]
                + ([] if (meta.get('health') or {}).get('url')
                   or (meta.get('health') or {}).get('service')
                   else ['no health check recorded - a failed deploy cannot be detected'])
                + ([] if _env_example_covers(directory, meta) else
                   ['.env.example does not list every key in project.json'])
            ),
        })
    return out


def _env_example_covers(directory: str, meta: dict) -> bool:
    """Is .env.example a usable checklist for the keys the project needs?"""
    text = _read(os.path.join(directory, '.env.example'))
    if not text:
        return not (meta.get('env_keys') or [])
    declared = {line.split('=', 1)[0].strip() for line in text.splitlines()
                if '=' in line and not line.lstrip().startswith('#')}
    return set(meta.get('env_keys') or []) <= declared


@compose_bp.get('/api/compose/projects')
def api_projects():
    repo = Repo()
    out = {'success': True, 'projects': [], 'error': '', 'dir': repo.dir}
    if not repo.exists():
        out['error'] = 'no estate checkout - the projects are read from the deployed tree'
        return jsonify(out)
    try:
        # A project list from a stale checkout is worse than none: it names a pin
        # that nobody will deploy.
        repo.fresh()
        out['head'] = repo.head()
        out['projects'] = projects(repo)
    except (GitError, OSError) as exc:
        out['success'] = False
        out['error'] = str(exc)[:300]
    return jsonify(out)
