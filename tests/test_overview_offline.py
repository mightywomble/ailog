"""The fleet card's "10/16 online" is a question: which ones, and since when?

Two halves are covered here:

* the collector ships ``last_seen`` with every snapshot and refreshes it when a
  host actually answers (throttled, so a 2s poll cannot hammer the database);
* the dashboard chips away the raw count into a clickable chip plus an
  "Offline devices" card that says when each device was last seen.
"""

from __future__ import annotations

import re
from pathlib import Path

from metrics import routes as metrics_routes

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / 'static' / 'js' / 'overview.js'
CSS = ROOT / 'static' / 'css'


def _snap(key, online, name=None, ip='10.9.9.9', error=None):
    return {
        'host_key': key,
        'name': name or key,
        'ip': ip,
        'online': online,
        'error': error,
    }


def _wire(monkeypatch, snaps):
    """Serve these snapshots instead of touching SSH."""
    by_key = {s['host_key']: s for s in snaps}
    monkeypatch.setattr(metrics_routes, '_host_list', lambda: [{'key': key} for key in by_key])
    monkeypatch.setattr(metrics_routes.collect, 'system_snapshot', lambda row: dict(by_key[row['key']]))
    monkeypatch.setattr(metrics_routes, '_docker_block', lambda snap: {'installed': False})


def _host_id(key):
    return int(key.split('-', 1)[1])


def _clear_throttle():
    metrics_routes._seen_written.clear()


# ------------------------------------------------------------------ collector

def test_snapshots_carry_the_stored_last_seen(monkeypatch, ctx, host):
    from database import Host, db
    from core.timeutil import utcnow

    row = Host.query.get(_host_id(host))
    row.last_seen = utcnow()
    db.session.commit()
    stamp = row.last_seen

    _clear_throttle()
    _wire(monkeypatch, [_snap(host, online=False, name='nas')])
    payload = metrics_routes.collect_servers()

    snap = payload['servers'][0]
    assert snap['online'] is False
    assert snap['last_seen'] == stamp.isoformat()
    assert 'last_seen' in snap


def test_a_host_with_no_record_gets_no_invented_time(monkeypatch, ctx, host):
    _clear_throttle()
    _wire(monkeypatch, [_snap(host, online=False)])
    payload = metrics_routes.collect_servers()
    assert payload['servers'][0]['last_seen'] is None


def test_an_answering_host_records_last_seen(monkeypatch, ctx, host):
    from database import Host

    _clear_throttle()
    _wire(monkeypatch, [_snap(host, online=True)])
    metrics_routes.collect_servers()

    assert Host.query.get(_host_id(host)).last_seen is not None


def test_an_offline_host_keeps_the_previous_time(monkeypatch, ctx, host):
    from database import Host, db
    from core.timeutil import utcnow

    row = Host.query.get(_host_id(host))
    row.last_seen = utcnow()
    db.session.commit()
    before = row.last_seen

    _clear_throttle()
    _wire(monkeypatch, [_snap(host, online=False, error='timed out')])
    metrics_routes.collect_servers()

    assert Host.query.get(_host_id(host)).last_seen == before


def test_writes_are_throttled_to_once_a_minute(monkeypatch, ctx, host):
    from database import Host, db

    _clear_throttle()
    _wire(monkeypatch, [_snap(host, online=True)])
    metrics_routes.collect_servers()

    row = Host.query.get(_host_id(host))
    row.last_seen = None
    db.session.commit()

    # Second round inside the interval: the badge was already refreshed.
    metrics_routes.collect_servers()
    assert Host.query.get(_host_id(host)).last_seen is None

    assert host in metrics_routes._seen_written


# ----------------------------------------------------------------- dashboard

def test_the_online_chip_is_a_clickable_control():
    js = JS.read_text()
    assert 'data-ov-offline-jump' in js
    assert 'aria-controls="ov-card-offline"' in js
    assert 'see offline' in js
    assert 'scrollIntoView' in js
    assert 'is-flash' in js
    # a chip that is not a button is not reachable by keyboard
    assert '<button type="button"\n                      class="ov-chip' in js


def test_offline_devices_get_their_own_card():
    js = JS.read_text()
    assert 'data-ov="offline"' in js
    assert 'id="ov-card-offline"' in js
    assert 'function renderOffline(servers)' in js
    assert '<h3>Offline devices</h3>' in js
    assert 'cards.push(renderOffline(list))' in js


def test_the_offline_card_says_when_each_device_was_last_seen():
    js = JS.read_text()
    assert 'last online ' in js
    assert 'const fmtWhen' in js
    assert 'ov-when' in js
    assert 'no record' in js
    # an offline row must not look like a healthy one
    assert 'ov-sev is-critical' in js


def test_server_timestamps_are_read_as_utc():
    """Naive "2026-10-30T21:12:00" is UTC, not the viewer's local clock."""
    js = JS.read_text()
    assert 'const parseServerTime' in js
    assert '${text}Z' in js
    assert 'toLocaleString' in js


def test_offline_rows_escape_server_strings():
    js = JS.read_text()
    block = js[js.index('function renderOffline'):js.index('function renderAlerts')]
    for value in ('s.name', 's.host_key', 's.ip', 's.error'):
        assert f'esc({value}' in block, value


def test_the_card_styles_use_semantic_tokens_only():
    css = (CSS / 'ui.css').read_text()
    block = css[css.index('.ov-chip {'):css.index('.ov-metrics {')]
    assert not re.search(r'#[0-9a-fA-F]{3,8}\b', block), 'a literal hex colour would break the theme switcher'
    assert 'var(--faint)' in block
    assert 'cursor: pointer' in block          # the chip reads as clickable
    assert '@keyframes ov-flash' in block


def test_the_glass_bento_still_fills_its_rows():
    """Four cards, three tracks: 2 + 1, then 1 + 2 — no ragged gap."""
    css = (CSS / 'interfaces.css').read_text()
    glass = css[css.index('[data-ui="glass"] #overview-cards {'):css.index('[data-ui="glass"] .app-modal-panel')]
    assert 'grid-template-columns: repeat(3' in glass
    assert '[data-ui="glass"] #overview-cards > .ov-card:first-child { grid-column: span 2; }' in glass
    assert '[data-ui="glass"] #overview-cards > .ov-card:nth-child(4) { grid-column: span 2; }' in glass
