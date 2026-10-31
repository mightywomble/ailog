"""Read-only Netdata client.

ailog does not own thresholds and does not mirror time-series into SQLite.
Netdata is the source of truth for *what the fleet is doing right now* and for
*what it already alerted on*; this module is the one place that speaks to it.

Design rules (deliberate, see docs/netdata.md):

* **pull, never push.** The dashboard already polls ``/api/v3/data`` about once
  a second; there is no generic metric-push webhook. We poll the same API and
  reuse Netdata's own ML anomaly rate (``arp``).
* **read-only.** Only ``GET`` requests, only ``/api/v3/data``, ``/nodes``,
  ``/contexts``, ``/alerts``, ``/alert_transitions`` and a capability probe of
  ``/function`` (which is expected to be blocked without Cloud SSO).
* **the token stays server-side.** It is read from ``AILOG_NETDATA_TOKEN`` or
  the ``netdata.token`` AppSetting and never returned by an API or embedded in
  a template.
* **cheap by default.** Every response is cached for a second or two and the
  cache is capped, so N open dashboards cost one round of queries.

The parser understands both response layouts Netdata returns:

``group_by=node,context``
    ``result.labels = ['time', '<machine_guid>,<context>', ...]``

no ``group_by``
    ``result.labels = ['time', '<dimension>', ...]``

Each cell is ``[value, anomaly_rate, ...]`` (the extra elements are ignored).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 6.0
DEFAULT_TTL = 2.0
MAX_CACHE_ENTRIES = 256
UA = 'ailog-netdata/1.0'

# The contexts we need for a fleet card. Kept as a tuple so the order is
# stable in tests and in the query cache key.
FLEET_CONTEXTS = ('system.cpu', 'system.ram', 'system.load', 'disk.space')
DISK_CONTEXT = 'disk.space'
ANOMALY_CONTEXT = 'anomaly_detection.anomaly_rate'

_cache: Dict[str, Tuple[float, Any]] = {}
_cache_lock = threading.Lock()


class NetdataError(RuntimeError):
    """Any failure to talk to Netdata, with the HTTP status when there was one."""

    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------

def _env(name: str) -> str:
    return (os.getenv(name) or '').strip()


def _setting(key: str) -> str:
    """Read an AppSetting without requiring an app context.

    Settings are the normal place for the URL and token because they survive a
    container recreate; the environment variables are a deployment override.
    """
    try:
        from database import AppSetting
        row = AppSetting.query.get(key)
        if row and row.value_json:
            value = json.loads(row.value_json)
            if isinstance(value, str):
                return value.strip()
    except Exception:
        pass
    return ''


def base_url() -> str:
    url = _env('AILOG_NETDATA_URL') or _setting('netdata.url')
    if not url:
        return ''
    url = url.strip().rstrip('/')
    if '://' not in url:
        url = 'https://' + url
    return url


def token() -> str:
    return _env('AILOG_NETDATA_TOKEN') or _setting('netdata.token')


def configured() -> bool:
    return bool(base_url())


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _request(path: str, params: Optional[Iterable[Tuple[str, Any]]] = None,
             timeout: float = DEFAULT_TIMEOUT, ttl: Optional[float] = DEFAULT_TTL,
             allow_404: bool = False) -> Any:
    """GET a Netdata API path and return parsed JSON (cached)."""
    url = base_url()
    if not url:
        raise NetdataError('Netdata URL is not configured')

    pairs = [(k, v) for k, v in (params or []) if v is not None]
    key = path + '?' + '&'.join(f'{k}={v}' for k, v in sorted(pairs))
    now = time.time()
    if ttl is not None and ttl > 0:
        with _cache_lock:
            hit = _cache.get(key)
            if hit and (now - hit[0]) < ttl:
                return hit[1]

    headers = {'Accept': 'application/json', 'User-Agent': UA}
    tok = token()
    if tok:
        headers['Authorization'] = f'Bearer {tok}'

    cert = _env('AILOG_NETDATA_VERIFY').lower()
    verify: Any = True
    if cert in ('0', 'false', 'no', 'off'):
        verify = False
    elif cert:
        verify = cert

    try:
        resp = requests.get(url + path, params=pairs, headers=headers,
                            timeout=timeout, verify=verify)
    except Exception as exc:
        raise NetdataError(f'cannot reach Netdata: {exc}') from exc

    if resp.status_code >= 400:
        if allow_404 and resp.status_code == 404:
            return None
        detail = ''
        try:
            body = resp.json()
            detail = body.get('error') or body.get('message') or ''
        except Exception:
            detail = (resp.text or '').strip()[:200]
        raise NetdataError(
            f'Netdata HTTP {resp.status_code}' + (f': {detail}' if detail else ''),
            status=resp.status_code,
        )
    try:
        payload = resp.json()
    except Exception as exc:
        raise NetdataError(f'Netdata returned non-JSON: {exc}') from exc

    if ttl is not None and ttl > 0:
        with _cache_lock:
            if len(_cache) >= MAX_CACHE_ENTRIES:
                newest = sorted(_cache.items(), key=lambda kv: kv[1][0], reverse=True)
                _cache.clear()
                _cache.update(dict(newest[: MAX_CACHE_ENTRIES // 2]))
            _cache[key] = (time.time(), payload)
    return payload


def _data_params(contexts: Iterable[str], nodes: Optional[Iterable[str]] = None,
                 after: int = -300, before: int = 0, points: int = 60,
                 tier: Optional[int] = None, time_group: str = 'avg',
                 group_by: Optional[str] = None) -> List[Tuple[str, Any]]:
    ctx = [c for c in contexts if c]
    params: List[Tuple[str, Any]] = [
        ('scope_contexts', ','.join(ctx)),
        ('after', int(after)),
        ('before', int(before)),
        ('points', int(points)),
        ('format', 'json2'),
        ('options', 'jsonwrap|minify'),
        ('time_group', time_group),
        ('cardinality_limit', 20000),
        ('timeout', 5000),
    ]
    node_list = [n for n in (nodes or []) if n]
    if node_list:
        params.append(('scope_nodes', ','.join(node_list)))
    if tier is not None:
        params.append(('tier', int(tier)))
    if group_by:
        params.append(('group_by', group_by))
    return params


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------

def parse_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a ``/api/v3/data`` response.

    Returns ``{'start': ts, 'step': seconds, 'labels': [...], 'series': {label:
    {'value': [...], 'arp': [...]}}, 'timestamps': [...], 'nodes': {guid:
    summary}, 'raw': payload}``. Series are ordered oldest -> newest.
    """
    payload = payload or {}
    result = payload.get('result') or {}
    labels = list(result.get('labels') or [])
    rows = list(result.get('data') or [])
    rows.sort(key=lambda r: r[0] if r else 0)

    timestamps: List[int] = []
    series: Dict[str, Dict[str, List[Optional[float]]]] = {}
    for label in labels[1:]:
        series[label] = {'value': [], 'arp': []}

    for row in rows:
        if not row:
            continue
        timestamps.append(int(row[0]))
        for idx, label in enumerate(labels[1:]):
            cell = row[idx + 1] if idx + 1 < len(row) else None
            if isinstance(cell, (list, tuple)):
                value = cell[0] if cell else None
                arp = cell[1] if len(cell) > 1 else None
            else:
                value, arp = cell, None
            series[label]['value'].append(_number_or_none(value))
            series[label]['arp'].append(_number_or_none(arp))

    nodes: Dict[str, Dict[str, Any]] = {}
    summary = payload.get('summary') or {}
    for node in summary.get('nodes') or []:
        guid = node.get('mg')
        if not guid:
            continue
        sts = node.get('sts') or {}
        nodes[guid] = {
            'guid': guid,
            'node_id': node.get('nd'),
            'name': node.get('nm'),
            'points': ((node.get('ds') or {}).get('qr')),
            'stats': {'min': sts.get('min'), 'max': sts.get('max'),
                      'avg': sts.get('avg'), 'arp': sts.get('arp'),
                      'con': sts.get('con')},
        }

    step = int(result.get('update_every') or 0)
    if not step and len(timestamps) > 1:
        step = max(1, int((timestamps[-1] - timestamps[0]) / (len(timestamps) - 1)))
    return {
        'start': result.get('after'),
        'end': result.get('before'),
        'step': step,
        'labels': labels,
        'series': series,
        'timestamps': timestamps,
        'nodes': nodes,
        'raw': payload,
    }


def _number_or_none(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    # Netdata uses null-ish sentinels for gaps.
    if number != number:  # NaN
        return None
    return number


def fetch_data(contexts: Iterable[str], nodes: Optional[Iterable[str]] = None,
               after: int = -300, before: int = 0, points: int = 60,
               tier: Optional[int] = None, time_group: str = 'avg',
               group_by: Optional[str] = None, ttl: Optional[float] = DEFAULT_TTL) -> Dict[str, Any]:
    payload = _request('/api/v3/data',
                       _data_params(contexts, nodes, after, before, points, tier,
                                    time_group, group_by), ttl=ttl)
    return parse_payload(payload)


def _last_values(values: List[Optional[float]]) -> Optional[float]:
    for value in reversed(values or []):
        if value is not None:
            return value
    return None


def _last(series: Dict[str, List[Optional[float]]]) -> Optional[float]:
    for value in reversed(series.get('value') or []):
        if value is not None:
            return value
    return None


def _max(values: Iterable[Optional[float]]) -> Optional[float]:
    usable = [v for v in values if v is not None]
    return max(usable) if usable else None


def _avg(values: Iterable[Optional[float]]) -> Optional[float]:
    usable = [v for v in values if v is not None]
    return sum(usable) / len(usable) if usable else None


def _sum_at(series: Dict[str, Dict[str, List[Optional[float]]]], keys: Iterable[str],
            index: int) -> Optional[float]:
    total = 0.0
    seen = False
    for key in keys:
        values = (series.get(key) or {}).get('value') or []
        if index < len(values) and values[index] is not None:
            total += values[index]
            seen = True
    return total if seen else None


# ---------------------------------------------------------------------------
# nodes / alerts / contexts
# ---------------------------------------------------------------------------

def nodes(ttl: Optional[float] = 10.0) -> List[Dict[str, Any]]:
    payload = _request('/api/v3/nodes', [('options', 'minify')], ttl=ttl)
    out = []
    for node in (payload or {}).get('nodes') or []:
        labels = node.get('labels') or {}
        health = node.get('health') or {}
        alerts = health.get('alerts') or {}
        state = (node.get('state') or '').lower()
        out.append({
            'guid': node.get('mg'),
            'node_id': node.get('nd'),
            'name': node.get('nm'),
            'version': node.get('v'),
            'state': node.get('state'),
            'online': state in ('reachable', 'online', ''),
            'hostname': labels.get('_hostname') or node.get('nm'),
            'os': (node.get('os') or {}).get('nm') or labels.get('_os_name'),
            'os_version': (node.get('os') or {}).get('v') or labels.get('_os_version'),
            'kernel': ((node.get('os') or {}).get('kernel') or {}).get('v')
                      or labels.get('_kernel_version'),
            'cores': _int(labels.get('_system_cores')),
            'ram_total': _int(labels.get('_system_ram_total')),
            'disk_space': _int(labels.get('_system_disk_space')),
            'ip': labels.get('_net_default_iface_ip'),
            'timezone': labels.get('_timezone'),
            'virtualization': labels.get('_virtualization'),
            'is_parent': str(labels.get('_is_parent')).lower() == 'true',
            'streams_to': labels.get('_streams_to') or None,
            'unstable_connection': str(labels.get('_has_unstable_connection')).lower() == 'true',
            'alerts': {
                'critical': _int(alerts.get('critical')) or 0,
                'warning': _int(alerts.get('warning')) or 0,
                'clear': _int(alerts.get('clear')) or 0,
            },
            'labels': labels,
        })
    return out


def _int(value: Any) -> Optional[int]:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def alerts(ttl: Optional[float] = 5.0) -> Dict[str, Any]:
    """Current alert instances, flattened to ``{'alerts': [...], 'nodes': [...]}``."""
    payload = _request('/api/v3/alerts', [('options', 'instances|minify')], ttl=ttl)
    payload = payload or {}
    nodes_by_index = {i: n for i, n in enumerate(payload.get('nodes') or [])}
    out = []
    for item in payload.get('alert_instances') or []:
        node = nodes_by_index.get(item.get('ni')) or {}
        out.append({
            'guid': node.get('mg'),
            'node': node.get('nm'),
            'alert': item.get('nm'),
            'instance': item.get('instance') or item.get('ch_n'),
            'context': item.get('ctx'),
            'status': item.get('st'),
            'value': item.get('tr_v'),
            'units': item.get('units'),
            'when': item.get('tr_t'),
            'summary': item.get('sum'),
            'info': item.get('info'),
            'config': item.get('cfg'),
            'source': item.get('src'),
        })
    return {'alerts': out, 'nodes': list(nodes_by_index.values())}


def alert_transitions(after: int = -86400, before: int = 0, limit: int = 200,
                      ttl: Optional[float] = 5.0) -> Dict[str, Any]:
    """Alert transitions (what actually happened), newest last."""
    payload = _request('/api/v3/alert_transitions', [
        ('after', int(after)), ('before', int(before)),
        ('options', 'jsonwrap|minify'),
        ('limit', max(1, min(int(limit), 1000))),
    ], ttl=ttl) or {}
    out = []
    for item in payload.get('transitions') or []:
        new = item.get('new') or {}
        old = item.get('old') or {}
        out.append({
            'id': item.get('transition_id'),
            'when': item.get('when'),
            'guid': item.get('machine_guid'),
            'node_id': item.get('node_id'),
            'hostname': item.get('hostname'),
            'alert': item.get('alert'),
            'instance': item.get('instance'),
            'context': item.get('context'),
            'component': item.get('component'),
            'classification': item.get('classification'),
            'type': item.get('type'),
            'status': new.get('status'),
            'value': new.get('value'),
            'old_status': old.get('status'),
            'old_value': old.get('old_value') if 'old_value' in old else old.get('value'),
            'units': item.get('units'),
            'info': item.get('info'),
            'summary': item.get('summary'),
        })
    out.sort(key=lambda t: int(t.get('when') or 0))
    facets = {}
    for facet in payload.get('facets') or []:
        facets[facet.get('id')] = [
            {'id': opt.get('id'), 'name': opt.get('name'), 'count': opt.get('count')}
            for opt in facet.get('options') or []
        ]
    return {'transitions': out, 'facets': facets}


def contexts(ttl: Optional[float] = 30.0) -> Dict[str, Any]:
    return _request('/api/v3/contexts', [('options', 'minify')], ttl=ttl) or {}


# ---------------------------------------------------------------------------
# fleet cards
# ---------------------------------------------------------------------------

def _cpu_percent(series: Dict[str, Dict[str, List[Optional[float]]]]) -> List[Optional[float]]:
    """Sum of the per-state CPU dimensions is total utilisation.

    Netdata does not expose ``idle`` as a dimension on ``system.cpu``; the
    dimensions are the busy states, so their sum is the busy percentage.
    """
    keys = [k for k in series if k not in ('time',)]
    length = max((len(series[k]['value']) for k in keys), default=0)
    return [_sum_at(series, keys, i) for i in range(length)]


def _ram_percent(series: Dict[str, Dict[str, List[Optional[float]]]]) -> List[Optional[float]]:
    keys = [k for k in series if k not in ('time',)]
    length = max((len(series[k]['value']) for k in keys), default=0)
    out = []
    for i in range(length):
        used = _sum_at(series, [k for k in keys if k in ('used',)], i)
        if used is None:
            continue
        total = 0.0
        seen = False
        for key in ('used', 'free', 'cached', 'buffers'):
            if key not in series:
                continue
            values = series[key]['value']
            if i < len(values) and values[i] is not None:
                total += values[i]
                seen = True
        if seen and total > 0:
            out.append(100.0 * used / total)
    return out


def _disk_percent(series: Dict[str, Dict[str, List[Optional[float]]]]) -> List[Optional[float]]:
    keys = [k for k in series if k not in ('time',)]
    length = max((len(series[k]['value']) for k in keys), default=0)
    out = []
    for i in range(length):
        used = _sum_at(series, [k for k in keys if k == 'used'], i)
        avail = _sum_at(series, [k for k in keys if k in ('avail', 'available')], i)
        if used is None or not avail:
            continue
        out.append(100.0 * used / (used + avail))
    return out


def _group(parsed, contexts, guids):
    """Split ``group_by=...,dimension`` labels into guid/context/instance.

    Netdata puts the dimension first but the remaining order depends on which
    group_by keys exist (``guid,context`` or ``instance,guid,context``), so the
    label is identified by membership rather than by position.
    """
    contexts, guids = set(contexts), set(guids)
    out: Dict[str, Dict[str, Dict[str, Dict[str, Any]]]] = {}
    for label, series in (parsed.get('series') or {}).items():
        parts = str(label).split(',')
        if len(parts) < 2:
            continue
        dim = parts[0]
        ctx = next((p for p in parts[1:] if p in contexts), None)
        guid = next((p for p in parts[1:] if p in guids), None)
        if not ctx or not guid:
            continue
        rest = [p for p in parts[1:] if p not in (ctx, guid)]
        instance = ','.join(rest)
        out.setdefault(guid, {}).setdefault(ctx, {}).setdefault(instance, {})[dim] = series
    return out


def _root_instance(instances):
    """Pick the root filesystem from the per-mount disk instances."""
    if not instances:
        return {}
    for name in instances:
        tail = name.rsplit('/', 1)[-1]
        if tail in ('', '_', '.', 'root') or name in ('disk_space./', '/'):
            return instances[name]
    # Fall back to the mount with the fewest path separators.
    return instances[min(instances, key=lambda n: n.count('/'))]


def fleet_cards(after: int = -120, points: int = 30, ttl: Optional[float] = 2.0) -> Dict[str, Any]:
    """One query round for every node, shaped for the Monitoring page.

    This is the "metrics without SSH" path: a handful of requests cover the
    whole fleet instead of one SSH session per host every two seconds.
    """
    node_list = nodes(ttl=10.0)
    by_guid = {n['guid']: n for n in node_list if n.get('guid')}
    out: Dict[str, Dict[str, Any]] = {}
    if not by_guid:
        return {'available': True, 'nodes': [], 'ts': time.time()}

    guids = list(by_guid)

    def query(ctxs: Iterable[str]) -> Dict[str, Any]:
        try:
            return fetch_data(ctxs, after=after, points=points,
                              group_by='node,context,instance,dimension', ttl=ttl)
        except NetdataError as exc:
            log.debug('netdata fleet query failed: %s', exc)
            return {'series': {}, 'timestamps': [], 'nodes': {}}

    cpu = _group(query(['system.cpu']), ['system.cpu'], guids)
    ram = _group(query(['system.ram']), ['system.ram'], guids)
    disk = _group(query([DISK_CONTEXT]), [DISK_CONTEXT], guids)
    load = _group(query(['system.load']), ['system.load'], guids)
    anomaly = _group(query([ANOMALY_CONTEXT]), [ANOMALY_CONTEXT], guids)

    def dims(group, guid, context):
        return _root_instance(((group.get(guid) or {}).get(context) or {}))

    for guid, node in by_guid.items():
        cpu_values = _cpu_percent(dims(cpu, guid, 'system.cpu'))
        ram_dims = dims(ram, guid, 'system.ram')
        ram_values = _ram_percent(ram_dims)
        disk_values = _disk_percent(dims(disk, guid, DISK_CONTEXT))
        load_dims = dims(load, guid, 'system.load')
        ar_instances = ((anomaly.get(guid) or {}).get(ANOMALY_CONTEXT) or {})
        ar_dims = next((v for k, v in ar_instances.items() if k.endswith(guid)), {}) \
            or _root_instance(ar_instances)
        ar_values = (ar_dims.get('anomaly_rate') or ar_dims.get('value') or {}).get('value') or []

        out[guid] = {
            **node,
            'cpu_percent': _last_values(cpu_values),
            'cpu_max': _max(cpu_values),
            'cpu_avg': _avg(cpu_values),
            'mem_percent': _last_values(ram_values),
            'mem_used': _last_values((ram_dims.get('used') or {}).get('value') or []),
            'mem_total': node.get('ram_total'),
            'disk_percent': _last_values(disk_values),
            'load1': _last_values((load_dims.get('load1') or {}).get('value') or []),
            'anomaly_rate': _last_values(ar_values),
            'anomaly_max': _max(ar_values),
            'stats': {},
            'series': {
                'cpu': cpu_values[-60:],
                'mem': ram_values[-60:],
                'disk': disk_values[-60:],
                'anomaly': ar_values[-60:],
                'load1': ((load_dims.get('load1') or {}).get('value') or [])[-60:],
            },
        }
    return {'available': True, 'ts': time.time(), 'nodes': list(out.values())}


# ---------------------------------------------------------------------------
# capacity / streaming quality
# ---------------------------------------------------------------------------

def _percentile(values: List[float], pct: float) -> Optional[float]:
    usable = sorted(v for v in values if v is not None)
    if not usable:
        return None
    idx = min(len(usable) - 1, max(0, int(round((pct / 100.0) * (len(usable) - 1)))))
    return usable[idx]


def capacity(hours: int = 24, ttl: Optional[float] = 60.0) -> Dict[str, Any]:
    """Average / peak / p95 saturation per node from Netdata's minute tier.

    Downsampling happens in Netdata (``tier=1`` + ``points``), so a 24 hour
    window costs the same as a 5 minute one and nothing is stored in ailog.
    """
    hours = max(1, min(int(hours or 24), 24 * 14))
    points = min(2000, hours * 60)
    after = -hours * 3600
    node_list = nodes(ttl=30.0)
    guids = [n['guid'] for n in node_list if n.get('guid')]

    def one(context: str, transform) -> Dict[str, Any]:
        try:
            parsed = fetch_data([context], after=after, points=points, tier=1,
                                group_by='node,context,instance,dimension', ttl=ttl)
        except NetdataError as exc:
            log.debug('netdata capacity query failed: %s', exc)
            return {}
        grouped = _group(parsed, [context], guids)
        out = {}
        for guid in guids:
            instances = ((grouped.get(guid) or {}).get(context) or {})
            dimseries = next((v for k, v in instances.items() if k.endswith(guid)), {}) \
                or _root_instance(instances)
            values = transform(dimseries) if transform else [
                v for v in (dimseries.get('value') or {}).get('value', []) if v is not None
            ]
            values = [v for v in values if v is not None]
            out[guid] = {
                'avg': round(sum(values) / len(values), 2) if values else None,
                'max': round(max(values), 2) if values else None,
                'p95': round(_percentile(values, 95), 2) if values else None,
                'samples': len(values),
            }
        return out

    cpu = one('system.cpu', _cpu_percent)
    ram = one('system.ram', _ram_percent)
    disk = one(DISK_CONTEXT, _disk_percent)

    nodes_out = []
    for node in node_list:
        guid = node.get('guid')
        if not guid:
            continue
        c = cpu.get(guid) or {}
        r = ram.get(guid) or {}
        d = disk.get(guid) or {}
        peak = max([v for v in (c.get('p95'), r.get('p95'), d.get('p95')) if v is not None],
                   default=None)
        status = 'ok'
        if peak is not None and peak >= 90:
            status = 'critical'
        elif peak is not None and peak >= 80:
            status = 'warning'
        nodes_out.append({
            **{k: node.get(k) for k in ('guid', 'name', 'hostname', 'online', 'os')},
            'cpu': c, 'mem': r, 'disk': d,
            'peak_p95': peak,
            'status': status,
            'headroom_percent': round(100.0 - peak, 2) if peak is not None else None,
        })
    nodes_out.sort(key=lambda n: -(n.get('peak_p95') or -1))
    return {'available': True, 'window_hours': hours, 'tier': 1,
            'nodes': nodes_out, 'ts': time.time()}


def streaming_health(node_list: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Turn Netdata's own streaming state into a data-quality signal.

    If a node is not streaming to the parent, or its connection is marked
    unstable, then a *log* gap on that host is much more likely to be a
    telemetry problem than a service problem. The report pack has to say that
    out loud, otherwise the model reads silence as health.
    """
    node_list = node_list if node_list is not None else nodes(ttl=15.0)
    unstable, not_streaming, offline = [], [], []
    parent = None
    for node in node_list:
        if node.get('is_parent'):
            parent = node
            continue
        if not node.get('online'):
            offline.append(node.get('name'))
        if node.get('unstable_connection'):
            unstable.append(node.get('name'))
        if not node.get('streams_to'):
            # The parent itself has no stream target; everything else should.
            not_streaming.append(node.get('name'))
    return {
        'nodes': len(node_list),
        'parent': (parent or {}).get('name'),
        'offline': sorted(n for n in offline if n),
        'unstable': sorted(n for n in unstable if n),
        'not_streaming': sorted(n for n in not_streaming if n),
        'ok': not (unstable or not_streaming or offline),
    }


# ---------------------------------------------------------------------------
# host reconciliation
# ---------------------------------------------------------------------------

def host_key_map() -> Dict[str, str]:
    """Operator overrides: ``{'<machine_guid>': 'db-12'}`` from AppSetting."""
    raw = _setting('netdata.host_map')
    if not raw:
        return {}
    try:
        value = json.loads(raw)
        if isinstance(value, dict):
            return {str(k): str(v) for k, v in value.items()}
    except Exception:
        pass
    return {}


def resolve_host_key(node: Dict[str, Any], hosts: List[Dict[str, Any]]) -> Optional[str]:
    """Match a Netdata node to an ailog host key.

    Order: explicit override -> exact hostname -> friendly name -> case-insensitive
    hostname. Ambiguous matches return ``None`` rather than guessing, because a
    wrong match would put one server's metrics on another's card.
    """
    guid = str(node.get('guid') or '')
    mapped = host_key_map().get(guid)
    if mapped:
        return mapped

    candidates = {str(n or '').strip().lower() for n in (node.get('name'), node.get('hostname'))}
    candidates.discard('')
    matches = []
    for host in hosts or []:
        key = str(host.get('key') or '')
        names = {str(host.get('name') or '').strip().lower(),
                 str(host.get('friendly_name') or '').strip().lower(),
                 str(host.get('hostname') or '').strip().lower()}
        names.discard('')
        if names & candidates:
            matches.append(key)
    matches = [m for m in matches if m]
    if len(matches) == 1:
        return matches[0]
    if matches:
        return None

    # Second pass: normalise punctuation/case so "Swarm Manager" matches
    # "swarm-manager". Ambiguity still loses, because guessing is worse than
    # leaving the host in the reconciliation list for a human to map.
    norm_candidates = {_slug(c) for c in candidates}
    norm_candidates.discard('')
    norm_matches = []
    for host in hosts or []:
        names = {_slug(host.get('name')), _slug(host.get('friendly_name')),
                 _slug(host.get('hostname'))}
        names.discard('')
        if names & norm_candidates:
            norm_matches.append(str(host.get('key') or ''))
    norm_matches = [m for m in norm_matches if m]
    return norm_matches[0] if len(norm_matches) == 1 else None


def _slug(value: Any) -> str:
    return ''.join(ch for ch in str(value or '').lower() if ch.isalnum())


def reconcile(hosts: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Compare the Host inventory with the nodes Netdata knows about."""
    if hosts is None:
        hosts = _ailog_hosts()
    nodes_now = nodes(ttl=15.0)
    matched, unmatched_nodes = [], []
    used = set()
    for node in nodes_now:
        key = resolve_host_key(node, hosts)
        if key:
            used.add(key)
            matched.append({'host_key': key, 'node': node.get('name'),
                            'guid': node.get('guid'), 'online': node.get('online'),
                            'streams_to': node.get('streams_to')})
        else:
            unmatched_nodes.append({'node': node.get('name'), 'guid': node.get('guid'),
                                    'hostname': node.get('hostname'),
                                    'online': node.get('online')})
    unmonitored = [
        {'host_key': h.get('key'), 'name': h.get('name') or h.get('key')}
        for h in hosts if h.get('key') not in used
    ]
    return {
        'available': True,
        'matched': matched,
        'netdata_only': unmatched_nodes,
        'ailog_only': unmonitored,
        'coverage': f'{len(matched)}/{len(hosts)} ailog hosts seen by Netdata',
    }


def _ailog_hosts() -> List[Dict[str, Any]]:
    try:
        from dockermon import endpoints as ep
        out = []
        for key in ep.all_host_keys():
            host = ep.resolve_host(key)
            if host:
                out.append(host)
        return out
    except Exception:
        return []


# ---------------------------------------------------------------------------
# diagnostics (functions) — expected to need Cloud SSO
# ---------------------------------------------------------------------------

def diagnostics_probe() -> Dict[str, Any]:
    """Probe the functions API without pretending we can run a function.

    Netdata only allows ``/api/v3/function`` for a node claimed to Netdata
    Cloud (SSO). The probe reports that honestly so the UI can explain why the
    button is unavailable instead of showing a generic failure.
    """
    try:
        node_list = nodes(ttl=0)
        node = (node_list[0].get('name') if node_list else None) or 'netdata'
        _request('/api/v3/function',
                 [('function', 'systemd-journal'), ('node', node)], ttl=0)
        return {'available': True, 'status': 200,
                'reason': 'functions API answered', 'detail': None}
    except NetdataError as exc:
        status = exc.status
        reason = 'requires Netdata Cloud SSO (claim the parent and agents)'
        if status not in (412, 451, 403):
            reason = str(exc)
        return {'available': False, 'status': status, 'reason': reason,
                'detail': str(exc)}


def health() -> Dict[str, Any]:
    """Cheap status for Settings and the dashboard."""
    if not configured():
        return {'configured': False, 'reachable': False,
                'error': 'Set the Netdata URL in Settings → Netdata'}
    started = time.time()
    try:
        node_list = nodes(ttl=0)
    except NetdataError as exc:
        return {'configured': True, 'reachable': False, 'error': str(exc),
                'status': exc.status}
    elapsed = int((time.time() - started) * 1000)
    online = sum(1 for n in node_list if n.get('online'))
    return {
        'configured': True,
        'reachable': True,
        'url': base_url(),
        'token_set': bool(token()),
        'nodes': len(node_list),
        'online': online,
        'version': next((n.get('version') for n in node_list if n.get('version')), None),
        'ms': elapsed,
        'quality': streaming_health(node_list),
    }


# ---------------------------------------------------------------------------
# settings (written by the Settings UI)
# ---------------------------------------------------------------------------

def save_config(url: str, tok: Optional[str] = None, keep_token: bool = True) -> Dict[str, Any]:
    from database import AppSetting, db
    url = (url or '').strip().rstrip('/')
    if url and '://' not in url:
        url = 'https://' + url
    for key, value in (('netdata.url', url),
                       ('netdata.token', tok if tok is not None else
                        (token() if keep_token else ''))):
        row = AppSetting.query.get(key)
        if row:
            row.value_json = json.dumps(value)
        else:
            db.session.add(AppSetting(key=key, value_json=json.dumps(value)))
    db.session.commit()
    clear_cache()
    return {'url': url, 'token_set': bool(token())}
