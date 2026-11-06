"""Render Settings -> Docker for real, in node, with a payload.

Same reason as the dashboard cards: the section builds its HTML in one go, so a
throw halfway leaves the previous markup on screen and nothing in the console.
The two ways it can be wrong are a broken payload (a project with an error, no
projects at all) and a project whose files are wrong - and both have to paint
rather than fail.

Skipped when node is not installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / 'static' / 'js' / 'compose-section.js'

pytestmark = pytest.mark.skipif(shutil.which('node') is None, reason='node is not installed')

DRIVER = r'''
import fs from 'fs';

const payload = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const errors = [];
process.on('unhandledRejection', (e) => errors.push(String((e && e.message) || e)));

const els = {};
const mkEl = (id) => ({
  id, innerHTML: '', textContent: '',
  classList: { add() {}, remove() {}, contains: () => false },
  querySelectorAll: () => [], querySelector: () => null,
  addEventListener() {}, closest: () => null,
});
const mount = () => (els['docker-compose-projects'] ||= mkEl('docker-compose-projects'));
const head = () => (els['docker-compose-head'] ||= mkEl('docker-compose-head'));

global.document = {
  getElementById: (id) => (id === 'docker-compose-projects' ? mount() : head()),
  addEventListener() {},
};
global.window = { addEventListener() {} };
global.fetch = async () => ({ json: async () => payload });

const module = await import(process.argv[3]);
await module.loadComposeProjects();

console.log(JSON.stringify({
  errors,
  html: mount().innerHTML,
  head: head().textContent,
}));
'''

PAYLOAD = {
    'success': True,
    'head': '6b89b66d5f0e4a1c9a3e',
    'error': '',
    'projects': [
        {
            'name': 'immich',
            'description': 'Photo and video library (Immich)',
            'host': 'photos',
            'dir': '/home/david/code/immich',
            'compose_file': 'docker-compose.yml',
            'env_file': '.env',
            'env_keys': ['UPLOAD_LOCATION', 'DB_PASSWORD'],
            'images': [
                {'ref': 'zot.safehomelan.com/immich-server:v3.3.6',
                 'image': 'zot.safehomelan.com/immich-server',
                 'pin': 'v3.3.6', 'variable': '', 'from_zot': True},
                {'ref': 'ghcr.io/immich-app/immich-server:release',
                 'image': 'ghcr.io/immich-app/immich-server',
                 'pin': 'release', 'variable': '', 'from_zot': False},
            ],
            'problems': ['ghcr.io/immich-app/immich-server:release does not come from zot'],
        },
        {'name': 'broken', 'error': 'project.json is not readable: Expecting value'},
    ],
}


def _render(tmp_path: Path, payload: dict) -> dict:
    payload_file = tmp_path / 'payload.json'
    payload_file.write_text(json.dumps(payload))
    driver = tmp_path / 'driver.mjs'
    driver.write_text(DRIVER)
    result = subprocess.run(['node', str(driver), str(payload_file), str(JS)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr[-2000:]
    return json.loads(result.stdout)


def test_a_project_paints_with_its_pins_and_its_problems(tmp_path):
    out = _render(tmp_path, PAYLOAD)

    assert out['errors'] == [], out['errors']
    html = out['html']
    assert 'data-compose-project="immich"' in html
    assert 'v3.3.6' in html and 'release' in html
    assert 'photos' in html and '/home/david/code/immich' in html
    assert 'does not come from zot' in html
    assert 'UPLOAD_LOCATION' in html and 'DB_PASSWORD' in html
    # a broken project costs its own card, not the section
    assert 'project.json is not readable' in html
    assert out['head'] == 'deployed tree 6b89b66d'


def test_an_empty_estate_says_what_a_project_is(tmp_path):
    out = _render(tmp_path, {'success': True, 'head': '', 'error': '', 'projects': []})

    assert out['errors'] == []
    assert 'deploy/compose/' in out['html']


def test_an_unreadable_checkout_says_so_instead_of_painting_nothing(tmp_path):
    out = _render(tmp_path, {'success': False,
                             'error': 'no estate checkout - the projects are read from the deployed tree',
                             'projects': []})

    assert out['errors'] == []
    assert 'no estate checkout' in out['html']
