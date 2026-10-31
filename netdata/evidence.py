"""Metric and alert evidence for an AI report.

Netdata owns thresholds; ailog's job is to explain what the logs say in the
context of what the machine was doing. This module turns a Netdata window into
a few compact, deterministic lines that go inside the same evidence pack as the
log clusters — so the model cannot write "the host was idle" without being
shown the actual CPU/memory/disk saturation and the alerts that fired.

The output is deliberately small (a handful of lines per context) and always
states the data-quality caveat when streaming is unhealthy: a log gap on a node
that is not streaming is a telemetry problem, not a silent service.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from . import client

log = logging.getLogger(__name__)

CONTEXTS = ('system.cpu', 'system.ram', 'disk.space', 'system.load',
            client.ANOMALY_CONTEXT)
MAX_ALERTS = 8
MAX_SERIES_POINTS = 60


def _fmt(value: Optional[float], unit: str = '') -> str:
    if value is None:
        return 'n/a'
    return f'{value:.1f}{unit}'


def _resolve(host_label: Optional[str] = None,
             host_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Find the Netdata node for an ailog host, without guessing."""
    hosts = client._ailog_hosts()
    node_list = client.nodes(ttl=15.0)
    for node in node_list:
        key = client.resolve_host_key(node, hosts)
        if host_key and key == host_key:
            return node
        if host_key and key is None:
            # A report for a netdata-only card uses ``nd:<name>``.
            if str(host_key) == f"nd:{node.get('name')}":
                return node
    if host_label:
        label = str(host_label).strip().lower()
        for node in node_list:
            if label in (str(node.get('name')).lower(), str(node.get('hostname')).lower()):
                return node
    return None


def _series(parsed: Dict[str, Any], guid: str, context: str) -> Dict[str, Any]:
    grouped = client._group(parsed, [context], [guid])
    instances = ((grouped.get(guid) or {}).get(context) or {})
    return next((v for k, v in instances.items() if k.endswith(guid)), {}) \
        or client._root_instance(instances)


def for_host(host_key: Optional[str], host_label: Optional[str],
             window_minutes: int = 60) -> Dict[str, Any]:
    """Collect one window of metric evidence for a host.

    Returns ``{'available': False, ...}`` rather than raising: a report must
    still run when Netdata is down.
    """
    if not client.configured():
        return {'available': False, 'reason': 'Netdata is not configured'}
    node = _resolve(host_label, host_key)
    if not node:
        return {'available': False, 'reason': 'host is not monitored by Netdata'}

    window_minutes = max(5, min(int(window_minutes or 60), 24 * 60))
    after = -window_minutes * 60
    points = min(MAX_SERIES_POINTS, max(12, window_minutes))
    tier = 1 if window_minutes > 360 else None
    guid = node.get('guid')
    out: Dict[str, Any] = {
        'available': True,
        'node': node.get('name'),
        'guid': guid,
        'window_minutes': window_minutes,
        'metrics': {},
        'alerts': [],
        'quality': {},
        'contexts': {},
    }

    for context in CONTEXTS:
        try:
            parsed = client.fetch_data([context], nodes=[node.get('name')],
                                       after=after, points=points, tier=tier,
                                       group_by='node,context,instance,dimension')
        except client.NetdataError as exc:
            log.debug('netdata evidence %s failed for %s: %s', context, node.get('name'), exc)
            continue
        dims = _series(parsed, guid, context)
        if context == 'system.cpu':
            values = client._cpu_percent(dims)
        elif context == 'system.ram':
            values = client._ram_percent(dims)
        elif context == 'disk.space':
            values = client._disk_percent(dims)
        elif context == 'system.load':
            values = [v for v in (dims.get('load1') or {}).get('value', []) if v is not None]
        else:
            values = [v for v in (dims.get('anomaly_rate') or {}).get('value', []) if v is not None]
        values = [v for v in values if v is not None]
        if not values:
            continue
        out['metrics'][context] = {
            'avg': round(sum(values) / len(values), 2),
            'max': round(max(values), 2),
            'last': round(values[-1], 2),
            'samples': len(values),
        }
        out['contexts'][context] = [round(v, 2) for v in values]

    try:
        transitions = client.alert_transitions(after=after, limit=200, ttl=10.0)
        out['alerts'] = [t for t in transitions.get('transitions') or []
                         if t.get('guid') == guid][-MAX_ALERTS:]
    except client.NetdataError as exc:
        log.debug('netdata evidence alerts failed: %s', exc)

    try:
        out['quality'] = client.streaming_health(client.nodes(ttl=15.0))
        out['quality']['node'] = node.get('name')
        out['quality']['node_unstable'] = bool(node.get('unstable_connection'))
        out['quality']['node_streams_to'] = node.get('streams_to')
    except client.NetdataError:
        out['quality'] = {}
    return out


def render(evidence: Optional[Dict[str, Any]]) -> List[str]:
    """Render evidence as the compact text block used inside the pack."""
    if not evidence or not evidence.get('available'):
        return []
    lines = ['', '--- METRICS (Netdata, thresholds owned by Netdata) ---']
    lines.append(
        f"node: {evidence.get('node')} | window: {evidence.get('window_minutes')}m | "
        f"source: {'Netdata parent'}"
    )
    m = evidence.get('metrics') or {}
    labels = {
        'system.cpu': ('CPU', '%', 'busy'),
        'system.ram': ('RAM', '%', 'used'),
        'disk.space': ('Disk', '%', 'used'),
        'system.load': ('Load1', '', ''),
        client.ANOMALY_CONTEXT: ('ML anomaly rate', '%', ''),
    }
    for context in CONTEXTS:
        row = m.get(context)
        if not row:
            continue
        name, unit, what = labels.get(context, (context, '', ''))
        suffix = f' {what}' if what else ''
        lines.append(
            f"{name}{suffix}: avg {_fmt(row.get('avg'), unit)} "
            f"max {_fmt(row.get('max'), unit)} now {_fmt(row.get('last'), unit)}"
        )
    # A very short tail makes a saturation *spike* legible without shipping a
    # time-series database to the model.
    for context in ('system.cpu', 'system.ram', 'disk.space'):
        values = (evidence.get('contexts') or {}).get(context) or []
        if len(values) >= 4:
            step = max(1, len(values) // 12)
            sampled = values[::step][-12:]
            lines.append(f"{context} sampled: " + ' '.join(f'{v:g}' for v in sampled))

    alerts = evidence.get('alerts') or []
    if alerts:
        lines.append('')
        lines.append('--- NETDATA ALERTS IN WINDOW ---')
        for alert in alerts:
            when = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(int(alert.get('when') or 0)))
            value = alert.get('value')
            unit = alert.get('units') or ''
            value_txt = f' = {value:g}{unit}' if isinstance(value, (int, float)) else ''
            lines.append(
                f"{when} | {alert.get('status')} | {alert.get('alert')}"
                f"{value_txt} | {alert.get('summary') or alert.get('info') or ''}"
            )

    quality = evidence.get('quality') or {}
    if quality:
        flags = []
        if quality.get('node_unstable') or (evidence.get('node') in (quality.get('unstable') or [])):
            flags.append('streaming connection is unstable')
        if not quality.get('node_streams_to') and evidence.get('node') != quality.get('parent'):
            flags.append('node has no stream target (may not be streaming to the parent)')
        if quality.get('offline'):
            flags.append('offline: ' + ', '.join(quality['offline']))
        if flags:
            lines.append('')
            lines.append('--- DATA QUALITY ---')
            lines.append(
                'streaming caveat: ' + '; '.join(flags)
                + '. A log gap on this node is more likely telemetry loss than a quiet service.'
            )
    return lines


def fleet_quality_text() -> List[str]:
    """One-line fleet health for reports that are not host-specific."""
    if not client.configured():
        return []
    try:
        quality = client.streaming_health()
    except client.NetdataError:
        return []
    if quality.get('ok'):
        return []
    return ['', '--- NETDATA DATA QUALITY ---',
            'streaming issues: ' + '; '.join(
                f"{label}: {', '.join(quality.get(key) or [])}"
                for label, key in (('unstable', 'unstable'),
                                   ('not streaming', 'not_streaming'),
                                   ('offline', 'offline'))
                if quality.get(key))]
