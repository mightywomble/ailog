"""Render the dashboard's cards for real, in node, with a payload.

The card module is a closure over `fetch` and a mount point, which makes it
easy to prove that it *paints*: feed it the shape `/api/overview` returns and
look at the HTML it produces.  That matters because a card that throws while
painting does not fail loudly - `mount.innerHTML` is set at the end of
`paint()`, so one exception leaves the previous (skeleton) cards on screen and
an empty console.  That is exactly how v3.22.0 shipped with four cards stuck on
"updating" while Netdata, which repaints on its own, kept working.

Skipped when node is not installed (the CI frontend job has it; a bare python
environment may not).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / 'static' / 'js' / 'overview.js'

pytestmark = pytest.mark.skipif(shutil.which('node') is None, reason='node is not installed')

DRIVER = r'''
import fs from 'fs';

const payload = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const errors = [];

const mkEl = (id) => ({
  id, innerHTML: '', dataset: {}, disabled: false, textContent: '', offsetWidth: 0,
  classList: { contains: () => false, add() {}, remove() {} },
  querySelectorAll: () => [], querySelector: () => null,
  addEventListener() {}, focus() {}, scrollIntoView() {},
});
const els = {};
global.document = {
  getElementById: (id) => (els[id] ||= mkEl(id)),
  addEventListener() {},
  hidden: false,
};
global.window = { addEventListener() {}, location: {}, showToast() {} };
process.on('unhandledRejection', (e) => errors.push(String(e && e.message || e)));

global.fetch = async (url) => {
  if (String(url).includes('/api/overview')) {
    return { status: 200, ok: true, headers: { get: () => 'etag-1' }, json: async () => payload };
  }
  // /api/netdata/fleet - deliberately "not configured", so this test is about
  // the aggregate cards only.
  return { ok: true, status: 200, json: async () => ({ success: false, error: 'not configured' }) };
};

const src = fs.readFileSync(process.argv[3], 'utf8');
try {
  eval(src);
} catch (error) {
  errors.push('sync: ' + error.message);
}
await new Promise((resolve) => setTimeout(resolve, 300));

const html = els['overview-cards'].innerHTML || '';
console.log(JSON.stringify({
  errors,
  length: html.length,
  skeleton: html.includes('data-ov-skeleton'),
  cards: ['fleet', 'offline', 'alerts', 'docker-updates', 'reports']
    .filter((name) => html.includes(`data-ov="${name}"`)),
  updateRows: (html.match(/data-ov-update=/g) || []).length,
  onclickWired: src.includes("mount.querySelectorAll('[data-ov-update]')"),
}));
process.exit(0);
'''


def _payload():
    return {
        'ts': 1793900000.0,
        'servers': {'servers': [
            {'host_key': 'db-15', 'name': 'swarm-worker4', 'ip': '100.106.96.24',
             'online': True, 'cpu': {'percent': 12.5}, 'mem': {'percent': 40.0},
             'docker': {'installed': True, 'containers_running': 6}},
            {'host_key': 'db-12', 'name': 'swarm-worker1', 'ip': '100.79.1.2',
             'online': False, 'error': 'timed out', 'last_seen': '2026-11-05T09:00:00'},
        ]},
        'alerts': {'active': [], 'events': [
            {'severity': 'warning', 'rule_name': 'disk filling', 'host_label': 'casaos'}]},
        'reports': {'reports': [
            {'id': 7, 'host_key': 'db-15', 'host_label': 'swarm-worker4',
             'verdict': 'healthy', 'created_at': '2026-11-05T09:30:00'}]},
        'docker_updates': {
            'count': 3, 'hosts': 2, 'estate': 1, 'drift': 1, 'more': 0, 'pending': [],
            'rows': [
                {'host_key': 'db-15', 'host': 'swarm-worker4', 'container': 'anchor_anchor.1.x',
                 'service': 'anchor', 'image': 'zot.safehomelan.com/anchor:0.9.1',
                 'from': 'v0.9.1', 'to': 'v0.18.0', 'containers': 1, 'kind': 'estate'},
                {'host_key': 'db-16', 'host': 'casaos', 'container': 'gitea',
                 'image': 'gitea/gitea:latest', 'from': '87a67ee09d3a', 'to': '8967bf9deaf3',
                 'containers': 1, 'kind': 'digest'},
                {'host_key': '', 'host': 'swarm-worker4', 'container': 'vikunja_vikunja.1.y',
                 'service': 'vikunja', 'image': 'zot.safehomelan.com/vikunja:latest@sha256:d2',
                 'from': 'latest', 'to': '2.7.1', 'note': 'running, git pins',
                 'containers': 1, 'kind': 'drift'},
            ],
        },
    }


def _render(tmp_path, payload):
    script = tmp_path / 'driver.mjs'
    script.write_text(DRIVER)
    data = tmp_path / 'payload.json'
    data.write_text(json.dumps(payload))
    out = subprocess.run(['node', str(script), str(data), str(JS)],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_every_card_paints_when_the_payload_arrives(tmp_path):
    result = _render(tmp_path, _payload())

    assert result['errors'] == [], result['errors']
    assert not result['skeleton'], 'a card was left on its skeleton'
    assert result['length'] > 2000
    # fleet, offline, alerts, docker updates, reports - the cards that come
    # from the aggregate. Netdata paints from its own poll.
    assert result['cards'] == ['fleet', 'offline', 'alerts', 'docker-updates', 'reports']


def test_the_docker_card_renders_one_row_per_update(tmp_path):
    result = _render(tmp_path, _payload())
    assert result['updateRows'] == 3


def test_the_docker_card_survives_an_empty_answer(tmp_path):
    payload = _payload()
    payload['docker_updates'] = {'count': 0, 'hosts': 0, 'estate': 0, 'more': 0,
                                 'pending': ['db-3'], 'rows': []}
    result = _render(tmp_path, payload)
    assert result['errors'] == []
    assert not result['skeleton']
    assert 'docker-updates' in result['cards']
    assert result['updateRows'] == 0


def test_the_docker_card_survives_an_error_section(tmp_path):
    payload = _payload()
    payload['docker_updates'] = {'error': 'scan cache gone'}
    result = _render(tmp_path, payload)
    assert result['errors'] == []
    assert not result['skeleton']
    assert 'fleet' in result['cards']      # one broken card does not blank the page


def test_the_docker_card_survives_a_partial_row(tmp_path):
    """The server is not obliged to send every field; a missing one is not a crash."""
    payload = _payload()
    payload['docker_updates']['rows'] = [{'host_key': 'db-15'}]
    result = _render(tmp_path, payload)
    assert result['errors'] == []
    assert not result['skeleton']
    assert result['updateRows'] == 1
