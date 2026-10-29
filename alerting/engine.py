"""Threshold alerting on the metrics ailog already collects.

ailog measures a lot and tells you nothing: the Docker sampler records CPU,
memory, disk and container counts every 15 s, and the report pipeline decides
whether a host is healthy, but you only find out by looking at the page.

This package turns those measurements into notifications:

* a **rule** is a metric + comparison + duration + cooldown
* the **evaluator** runs on every sampler tick (and on every stored report)
* a rule that stays true for its ``for_seconds`` moves ``ok -> firing``
* when the condition stops holding it moves ``firing -> resolved``
* transitions are stored in ``alert_events`` and pushed to Discord/webhooks

Design notes
------------
* State is kept in memory for the "has it been true long enough?" question and
  mirrored to the database on transitions, so a restart does not re-fire every
  alert (events still firing are reloaded from the table).
* Delivery is best-effort and never raises into the sampler.
* Only *transitions* notify. Without that, a 15 s sampler would send 240
  messages an hour for the same full disk.
"""

from __future__ import annotations

import json
import logging
import threading
import time

import requests
from core.timeutil import utcnow

log = logging.getLogger(__name__)

VERDICT_LEVELS = {'healthy': 0, 'ok': 0, 'unknown': -1,
                  'degraded': 1, 'failing': 2, 'critical': 2}

# metric -> (label, unit, default comparison direction)
METRICS = {
    'cpu_percent': ('CPU', '%', 'above'),
    'mem_percent': ('Memory', '%', 'above'),
    'disk_percent': ('Disk', '%', 'above'),
    'containers_running': ('Running containers', '', 'below'),
    'node_offline': ('Node offline', '', 'above'),
    'verdict_level': ('Report verdict', '', 'at_least'),
}

OPS = ('>', '>=', '<', '<=', '==', '!=', 'at_least')

DEFAULT_RULES = (
    {'name': 'Memory over 90% for 5m', 'metric': 'mem_percent', 'op': '>=',
     'threshold': 90, 'for_seconds': 300, 'cooldown_seconds': 1800,
     'severity': 'warning'},
    {'name': 'Disk over 85%', 'metric': 'disk_percent', 'op': '>=',
     'threshold': 85, 'for_seconds': 300, 'cooldown_seconds': 3600,
     'severity': 'warning'},
    {'name': 'CPU pegged for 10m', 'metric': 'cpu_percent', 'op': '>=',
     'threshold': 95, 'for_seconds': 600, 'cooldown_seconds': 1800,
     'severity': 'warning'},
    {'name': 'No containers running', 'metric': 'containers_running', 'op': '<=',
     'threshold': 0, 'for_seconds': 120, 'cooldown_seconds': 1800,
     'severity': 'critical'},
    {'name': 'Report is not healthy', 'metric': 'verdict_level', 'op': 'at_least',
     'threshold': 1, 'for_seconds': 0, 'cooldown_seconds': 3600,
     'severity': 'warning'},
)

_lock = threading.Lock()
# (host_key, rule_id) -> {'since': ts, 'firing': bool, 'event_id': int|None,
#                          'notified_at': ts|None}
_state: dict[tuple[str, int], dict] = {}
_rules_cache: tuple[float, list] = (0.0, [])
_RULES_TTL = 5.0


# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------

def _models():
    from database import AlertEvent, AlertRule, db
    return AlertRule, AlertEvent, db


def seed_defaults():
    """Create the default rule set once (idempotent)."""
    AlertRule, _, db = _models()
    try:
        if AlertRule.query.count() > 0:
            return 0
        for spec in DEFAULT_RULES:
            db.session.add(AlertRule(**spec))
        db.session.commit()
        invalidate()
        return len(DEFAULT_RULES)
    except Exception as exc:
        try:
            db.session.rollback()
        except Exception:
            pass
        log.warning('[alerts] could not seed default rules: %s', exc)
        return 0


def invalidate():
    global _rules_cache
    _rules_cache = (0.0, [])


def rules(force=False):
    """Enabled rules, cached for a few seconds (called on every sample)."""
    global _rules_cache
    stamp, cached = _rules_cache
    if not force and cached and (time.time() - stamp) < _RULES_TTL:
        return cached
    AlertRule, _, _ = _models()
    try:
        rows = AlertRule.query.filter_by(enabled=True).all()
    except Exception:
        return cached or []
    out = [row.to_dict() for row in rows]
    _rules_cache = (time.time(), out)
    return out


def all_rules():
    AlertRule, _, _ = _models()
    return [row.to_dict() for row in AlertRule.query.order_by(AlertRule.id).all()]


def create_rule(data):
    AlertRule, _, db = _models()
    rule = AlertRule(**_clean_rule(data))
    db.session.add(rule)
    db.session.commit()
    invalidate()
    return rule.to_dict()


def update_rule(rule_id, data):
    AlertRule, _, db = _models()
    rule = AlertRule.query.get(rule_id)
    if not rule:
        return None
    for key, value in _clean_rule(data, partial=True).items():
        setattr(rule, key, value)
    db.session.commit()
    invalidate()
    return rule.to_dict()


def delete_rule(rule_id):
    AlertRule, _, db = _models()
    rule = AlertRule.query.get(rule_id)
    if not rule:
        return False
    db.session.delete(rule)
    db.session.commit()
    invalidate()
    with _lock:
        for key in [k for k in _state if k[1] == rule_id]:
            _state.pop(key, None)
    return True


def _clean_rule(data, partial=False):
    data = data or {}
    out = {}
    if 'name' in data or not partial:
        out['name'] = str(data.get('name') or 'Rule')[:120]
    if 'metric' in data or not partial:
        metric = str(data.get('metric') or 'mem_percent')
        out['metric'] = metric if metric in METRICS else 'mem_percent'
    if 'op' in data or not partial:
        op = str(data.get('op') or '>=')
        out['op'] = op if op in OPS else '>='
    if 'threshold' in data or not partial:
        try:
            out['threshold'] = float(data.get('threshold'))
        except (TypeError, ValueError):
            out['threshold'] = 0.0
    if 'for_seconds' in data or not partial:
        try:
            out['for_seconds'] = max(0, int(data.get('for_seconds') or 0))
        except (TypeError, ValueError):
            out['for_seconds'] = 0
    if 'cooldown_seconds' in data or not partial:
        try:
            out['cooldown_seconds'] = max(0, int(data.get('cooldown_seconds') or 900))
        except (TypeError, ValueError):
            out['cooldown_seconds'] = 900
    if 'severity' in data or not partial:
        severity = str(data.get('severity') or 'warning').lower()
        out['severity'] = severity if severity in ('info', 'warning', 'critical') else 'warning'
    if 'enabled' in data or not partial:
        out['enabled'] = bool(data.get('enabled', True))
    return out


# --------------------------------------------------------------------------
# comparison
# --------------------------------------------------------------------------

def _compare(value, op, threshold):
    if value is None:
        return False
    try:
        value = float(value)
    except (TypeError, ValueError):
        return False
    if op == '>':
        return value > threshold
    if op == '>=':
        return value >= threshold
    if op == '<':
        return value < threshold
    if op == '<=':
        return value <= threshold
    if op == '==':
        return value == threshold
    if op == '!=':
        return value != threshold
    if op == 'at_least':
        return value >= threshold
    return False


def metric_value(stats, metric):
    """Pull a metric out of a stats dict (the shape ``host_snapshot`` returns)."""
    if not stats:
        return None
    if metric == 'node_offline':
        return 1.0 if stats.get('online') is False else 0.0
    if metric == 'verdict_level':
        return stats.get('verdict_level')
    return stats.get(metric)


# --------------------------------------------------------------------------
# evaluation
# --------------------------------------------------------------------------

def evaluate_host(host_key, stats, now=None):
    """Evaluate every rule against one host's stats. Returns fired events."""
    values = {}
    for metric in METRICS:
        value = metric_value(stats, metric)
        if value is not None:
            values[metric] = value
    if not values:
        return []
    return evaluate(host_key, values, now=now)


def evaluate(host_key, values, now=None):
    """Compare ``values`` (metric -> number) against the rules.

    Returns the events that moved ``ok -> firing`` on this call (i.e. the ones
    worth notifying). Recovery is recorded but returns ``resolved`` entries via
    :func:`recent_events`.
    """
    now = time.time() if now is None else float(now)
    fired = []
    for rule in rules():
        metric = rule['metric']
        if metric not in values:
            continue
        value = values[metric]
        if value is None:
            continue
        key = (str(host_key), int(rule['id']))
        hit = _compare(value, rule['op'], rule['threshold'])
        with _lock:
            state = _state.setdefault(key, {'since': None, 'firing': False,
                                            'event_id': None, 'notified_at': None})
            if hit:
                if state['since'] is None:
                    state['since'] = now
                held = now - state['since']
                if state['firing'] or held + 0.001 < float(rule['for_seconds'] or 0):
                    continue
                state['firing'] = True
                state['fired_at'] = now
            else:
                if not state['firing']:
                    state['since'] = None
                    continue
                state['firing'] = False
                state['since'] = None
                event_id = state['event_id']
                state['event_id'] = None
                _resolve(event_id, value)
                continue

        event = _fire(host_key, rule, value, now)
        if event:
            fired.append(event)
            with _lock:
                _state[key]['event_id'] = event['id']
                _state[key]['notified_at'] = now
    return fired


def _fire(host_key, rule, value, now):
    _, AlertEvent, db = _models()
    message = _describe(rule, host_key, value)
    try:
        event = AlertEvent(
            rule_id=rule['id'], rule_name=rule['name'], host_key=str(host_key),
            metric=rule['metric'], value=float(value),
            threshold=float(rule['threshold']), op=rule['op'],
            severity=rule['severity'], state='firing', message=message,
            started_at=utcnow(),
        )
        db.session.add(event)
        db.session.commit()
        payload = event.to_dict()
    except Exception as exc:
        try:
            db.session.rollback()
        except Exception:
            pass
        log.warning('[alerts] could not store event: %s', exc)
        return None

    ok, error = notify(payload)
    try:
        event.notified = bool(ok)
        event.notify_error = error
        db.session.commit()
    except Exception:
        db.session.rollback()
    return payload


def _resolve(event_id, value):
    if not event_id:
        return
    _, AlertEvent, db = _models()
    try:
        event = AlertEvent.query.get(event_id)
        if not event or event.state != 'firing':
            return
        event.state = 'resolved'
        event.resolved_at = utcnow()
        event.resolved_value = float(value) if value is not None else None
        db.session.commit()
        notify(event.to_dict())
    except Exception as exc:
        try:
            db.session.rollback()
        except Exception:
            pass
        log.debug('[alerts] could not resolve event %s: %s', event_id, exc)


def _describe(rule, host_key, value):
    label, unit, _ = METRICS.get(rule['metric'], (rule['metric'], '', 'above'))
    if rule['metric'] == 'verdict_level':
        names = {0: 'healthy', 1: 'degraded', 2: 'failing'}
        level = names.get(int(value), str(value))
        return f'{host_key}: report verdict is {level}'
    if rule['metric'] == 'node_offline':
        return f'{host_key}: node is offline'
    shown = f'{value:.1f}{unit}' if isinstance(value, float) else f'{value}{unit}'
    return f'{host_key}: {label} {rule["op"]} {rule["threshold"]:g}{unit} (now {shown})'


def record_verdict(host_key, verdict, report_id=None):
    """Feed a stored report's verdict into the rules as ``verdict_level``."""
    level = VERDICT_LEVELS.get(str(verdict or '').lower(), -1)
    if level < 0:
        return []
    return evaluate(str(host_key), {'verdict_level': float(level)})


# --------------------------------------------------------------------------
# delivery
# --------------------------------------------------------------------------

def _webhook_url():
    try:
        from database import AppSetting
        row = AppSetting.query.get('discord_webhook_url')
        if not row or not row.value_json:
            return ''
        return json.loads(row.value_json) or ''
    except Exception:
        return ''


def _colour(severity):
    return {'critical': 15158332, 'warning': 16776960}.get(severity, 3447003)


def notify(event):
    """Post one event to the configured Discord webhook. Never raises."""
    url = _webhook_url()
    if not url:
        return False, None
    resolved = event.get('state') == 'resolved'
    title = ('Resolved: ' if resolved else 'Alert: ') + (event.get('rule_name') or 'rule')
    body = event.get('message') or ''
    if resolved:
        body += ' (recovered)'
    embed = {
        'title': title[:240],
        'description': body[:1900],
        'color': 3066993 if resolved else _colour(event.get('severity')),
        'footer': {'text': 'ailog alerts'},
        'timestamp': utcnow().isoformat() + 'Z',
    }
    try:
        resp = requests.post(url, json={'embeds': [embed]}, timeout=8)
        if resp.status_code >= 400:
            return False, f'webhook HTTP {resp.status_code}'
        return True, None
    except Exception as exc:
        return False, str(exc)


def send_test():
    """Send a test embed so the Settings button can prove the wiring."""
    return notify({
        'rule_name': 'Test alert', 'message': 'If you can read this, alerting works.',
        'severity': 'info', 'state': 'firing',
    })


# --------------------------------------------------------------------------
# read side (page + API)
# --------------------------------------------------------------------------

def active_events():
    _, AlertEvent, _ = _models()
    rows = (AlertEvent.query.filter_by(state='firing')
            .order_by(AlertEvent.started_at.desc()).all())
    return [row.to_dict() for row in rows]


def recent_events(limit=50, host_key=None):
    _, AlertEvent, _ = _models()
    query = AlertEvent.query
    if host_key:
        query = query.filter(AlertEvent.host_key == str(host_key))
    rows = query.order_by(AlertEvent.started_at.desc()).limit(limit).all()
    return [row.to_dict() for row in rows]


def state_snapshot():
    with _lock:
        return {f'{k[0]}:{k[1]}': dict(v) for k, v in _state.items()}


def reset_state():
    """Test/helper: forget the in-memory state machine."""
    with _lock:
        _state.clear()
