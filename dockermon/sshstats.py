"""Socket-mode (SSH CLI) collectors for ailog's Docker monitoring page.

Some hosts do not expose the Docker Engine API on TCP at all - they only have
the local unix socket.  For those hosts we shell out over SSH and parse the
CLI output instead.  The public helpers return exactly the same dictionaries
as :mod:`dockermon.stats` so the routes and the browser template do not need
to care which transport produced the data.

A single marker delimited remote command is executed per poll; that keeps the
SSH round trips (and therefore the latency) to a minimum.
"""

from __future__ import annotations

import json
import re
import shlex
import threading
import time

from . import endpoints as ep
from .parse import (
    parse_df_root,
    parse_kv_json_lines,
    parse_meminfo,
    parse_netdev,
    parse_node_line,
    parse_proc_stat,
    parse_ps_line,
    parse_stats_line,
    parse_sysdf,
    rate,
)

# host_key -> (timestamp, monotonic-ish wall clock, rx, tx, cpu_total, cpu_idle)
_rate_lock = threading.Lock()
_rate_cache: dict[str, tuple[float, float, int, int, int, int]] = {}

M_INFO = '===AILOG_INFO==='
M_PS = '===AILOG_PS==='
M_STATS = '===AILOG_STATS==='
M_NODES = '===AILOG_NODES==='
M_STAT = '===AILOG_STAT==='
M_MEM = '===AILOG_MEM==='
M_NET = '===AILOG_NET==='
M_DF = '===AILOG_DF==='
M_SYSDF = '===AILOG_SYSDF==='

PS_FORMAT = (
    '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.Size}}\t'
    '{{.Label "com.docker.stack.namespace"}}\t'
    '{{.Label "com.docker.swarm.service.name"}}\t'
    '{{.Label "com.docker.swarm.task.id"}}\t'
    '{{.Label "com.docker.swarm.node.id"}}'
)

NODE_FORMAT = (
    '{{.ID}}\t{{.Hostname}}\t{{.Status}}\t{{.Availability}}\t{{.ManagerStatus}}'
)

_SNAPSHOT_CMD = '; '.join([
    'echo ' + M_INFO,
    "docker_cmd info --format '{{json .}}'",
    'echo ' + M_PS,
    "docker_cmd ps -a --size --no-trunc --format '" + PS_FORMAT + "'",
    'echo ' + M_STATS,
    "docker_cmd stats --no-stream --no-trunc --format '{{json .}}'",
    'echo ' + M_NODES,
    "docker_cmd node ls --format '" + NODE_FORMAT + "'",
    'echo ' + M_STAT,
    'cat /proc/stat',
    'echo ' + M_MEM,
    'cat /proc/meminfo',
    'echo ' + M_NET,
    'cat /proc/net/dev',
    'echo ' + M_DF,
    'df -B1 /',
])


def _wrap(command: str) -> str:
    """Wrap a command list so ``docker`` works with or without sudo."""
    prefix = 'docker_cmd() { sudo -n docker "$@" 2>/dev/null || docker "$@"; }; '
    return prefix + command + ' 2>/dev/null'


def run(user, ip, ssh_key_id=None, command: str = '', timeout: int = 25):
    """Execute ``command`` over SSH, returning ``(ok, stdout_or_stderr)``."""
    return ep.ssh_run(user, ip, _wrap(command), ssh_key_id=ssh_key_id, timeout=timeout)


def _split(output: str) -> dict[str, str]:
    """Split combined stdout on our marker lines."""
    markers = {M_INFO: 'info', M_PS: 'ps', M_STATS: 'stats',
               M_NODES: 'nodes', M_STAT: 'stat', M_MEM: 'mem', M_NET: 'net',
               M_DF: 'df', M_SYSDF: 'sysdf'}
    blocks: dict[str, list[str]] = {v: [] for v in markers.values()}
    current = None
    for line in output.splitlines():
        stripped = line.strip()
        if stripped in markers:
            current = markers[stripped]
            continue
        if current:
            blocks[current].append(line)
    return {k: '\n'.join(v) for k, v in blocks.items()}


def _as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _load_info(text: str) -> dict:
    for line in (text or '').splitlines():
        line = line.strip()
        if line.startswith('{'):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return {}


def _ram_pct(used, total):
    if not total:
        return 0.0
    return round(100.0 * used / total, 2)


def _host_rates(host_key, rx, tx, cpu_total, cpu_idle):
    """Return (rx_bps, tx_bps, cpu_percent) from the previous poll."""
    now = time.time()
    with _rate_lock:
        prev = _rate_cache.get(host_key)
        _rate_cache[host_key] = (now, now, rx, tx, cpu_total, cpu_idle)
    if not prev:
        return 0.0, 0.0, 0.0
    elapsed = max(now - prev[0], 0.001)
    rx_bps = max(0, rx - prev[2]) / elapsed
    tx_bps = max(0, tx - prev[3]) / elapsed
    total_delta = cpu_total - prev[4]
    idle_delta = cpu_idle - prev[5]
    cpu_pct = 0.0
    if total_delta > 0:
        cpu_pct = round(100.0 * (total_delta - idle_delta) / total_delta, 2)
    return round(rx_bps, 2), round(tx_bps, 2), cpu_pct


PS_LIST_FORMAT = (
    '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.Size}}'
)


def parse_container_rows(text: str) -> list[dict]:
    """Parse ``docker ps`` TSV output into container dicts."""
    rows = []
    for line in (text or '').splitlines():
        if not line.strip():
            continue
        parsed = parse_ps_line(line)
        if parsed.get('id'):
            rows.append(parsed)
    return rows


def list_containers(user, ip, ssh_key_id=None, timeout: int = 15) -> list[dict]:
    """List containers on a host (no stats) - one cheap SSH round trip."""
    command = "docker_cmd ps -a --no-trunc --size --format '" + PS_LIST_FORMAT + "'"
    ok, out = run(user, ip, ssh_key_id, command, timeout=timeout)
    if not ok:
        return []
    return parse_container_rows(out)


def _container_row(parsed: dict, usage: dict) -> dict:
    image = parsed.get('image') or ''
    tag = 'latest'
    if '@' in image:
        image, tag = image.split('@', 1)
    elif ':' in image.rsplit('/', 1)[-1]:
        image, tag = image.rsplit(':', 1)
    size_rw, size_virtual = parsed.get('size'), parsed.get('size_virtual')
    row = {
        'id': parsed.get('id'),
        'short_id': (parsed.get('id') or '')[:12],
        'name': parsed.get('name'),
        'image': parsed.get('image'),
        'image_name': image,
        'image_tag': tag,
        'image_tags': [image + ':' + tag] if image else [],
        'state': parsed.get('state'),
        'status': parsed.get('status'),
        'stack': parsed.get('stack') or None,
        'service': parsed.get('service') or None,
        'task_id': parsed.get('task') or None,
        'node_id': parsed.get('node_id') or None,
        'size_rw': size_rw,
        'size_rootfs': size_virtual,
        'created': None,
    }
    if usage:
        # parse_stats_line() gives NetIO as an (rx, tx) pair; older code put the
        # whole tuple into net_rx, which surfaced as "(123, 456)" wherever a
        # caller expected a number.
        net = usage.get('net_bytes') or (0, 0)
        if isinstance(net, (tuple, list)):
            net_rx, net_tx = (list(net) + [0, 0])[:2]
        else:
            net_rx, net_tx = net, 0
        row.update({
            'cpu_percent': usage.get('cpu_pct') or 0.0,
            'mem_used': usage.get('mem_used') or 0,
            'mem_limit': usage.get('mem_limit') or 0,
            'mem_percent': usage.get('mem_pct') or 0.0,
            'net_rx': net_rx or 0,
            'net_tx': net_tx or 0,
            'pids': usage.get('pids') or 0,
        })
    return row


def snapshot(host_key, user, ip, ssh_key_id=None, timeout: int = 25):
    """Collect one live snapshot: engine info, containers, totals and nodes."""
    ok, out = run(user, ip, ssh_key_id, _SNAPSHOT_CMD, timeout=timeout)
    if not ok:
        raise RuntimeError(out or 'SSH command failed')

    blocks = _split(out)
    info = _load_info(blocks.get('info', ''))

    usage_by_id = {}
    for obj in parse_kv_json_lines(blocks.get('stats', '')):
        parsed = parse_stats_line(obj)
        if parsed.get('id'):
            usage_by_id[parsed['id'][:12]] = parsed
            usage_by_id[parsed['id']] = parsed

    containers = []
    for line in (blocks.get('ps') or '').splitlines():
        if not line.strip():
            continue
        parsed = parse_ps_line(line)
        if not parsed.get('id'):
            continue
        usage = usage_by_id.get(parsed['id'][:12]) or usage_by_id.get(parsed['id'])
        containers.append(_container_row(parsed, usage))

    proc = parse_proc_stat(blocks.get('stat', ''))
    mem = parse_meminfo(blocks.get('mem', ''))
    netdev = parse_netdev(blocks.get('net', ''))
    disk_total, disk_used = parse_df_root(blocks.get('df', ''))

    rx_bps, tx_bps, cpu_pct = _host_rates(
        host_key, netdev.get('rx') or 0, netdev.get('tx') or 0,
        proc.get('total') or 0, proc.get('idle') or 0,
    )

    cores = _as_int(info.get('NCPU'), 0) or 1
    mem_total = mem.get('total') or 0
    mem_used = mem.get('used') or 0

    running = [c for c in containers if (c.get('state') or '').lower() == 'running']
    images = info.get('Images')
    swarm = info.get('Swarm') or {}
    if isinstance(swarm, str):
        swarm = {}

    stats = {
        'cpu_percent': cpu_pct,
        'cpu_cores': cores,
        'cpu_cores_used': round(cpu_pct * cores / 100.0, 2),
        'mem_used': mem_used,
        'mem_total': mem_total,
        'mem_percent': _ram_pct(mem_used, mem_total),
        'net_rx': netdev.get('rx') or 0,
        'net_tx': netdev.get('tx') or 0,
        'net_rx_bps': rx_bps,
        'net_tx_bps': tx_bps,
        'disk_used': disk_used,
        'disk_total': disk_total,
        'disk_percent': (round(100.0 * disk_used / disk_total, 2)
                         if disk_total else None),
        'containers_total': len(containers),
        'containers_running': len(running),
        'swarm': bool(swarm.get('LocalNodeState') == 'active'),
        'engine_version': info.get('ServerVersion'),
        'node_name': info.get('Name'),
        'images': _as_int(images, 0),
        'ts': time.time(),
    }

    nodes = []
    for line in (blocks.get('nodes') or '').splitlines():
        if not line.strip():
            continue
        node = parse_node_line(line)
        if node.get('id'):
            nodes.append(node)

    return {'stats': stats, 'containers': containers, 'nodes': nodes, 'info': info}


def node_info(host_key, user, ip, ssh_key_id=None, timeout: int = 25, snap=None):
    snap = snap or snapshot(host_key, user, ip, ssh_key_id, timeout=timeout)
    info = snap.get('info') or {}
    swarm = info.get('Swarm') or {}
    if isinstance(swarm, str):
        swarm = {}
    out = {
        'engine': {
            'name': info.get('Name'),
            'server_version': info.get('ServerVersion'),
            'os': ((info.get('OperatingSystem') or '') + ' ' +
                   (info.get('OSType') or '')).strip() or None,
            'kernel': info.get('KernelVersion'),
            'arch': info.get('Architecture'),
            'cpus': _as_int(info.get('NCPU'), 0),
            'memory': _as_int(info.get('MemTotal'), 0),
            'containers': _as_int(info.get('Containers'), 0),
            'containers_running': _as_int(info.get('ContainersRunning'), 0),
            'images': _as_int(info.get('Images'), 0),
            'driver': info.get('Driver'),
        },
        'swarm': None,
    }
    if swarm.get('LocalNodeState') == 'active':
        out['swarm'] = {
            'local_node_state': swarm.get('LocalNodeState'),
            'control_available': bool(swarm.get('ControlAvailable')),
            'node_id': (swarm.get('NodeID') or ''),
            'nodes': swarm.get('Nodes') or len(snap.get('nodes') or []),
            'managers': swarm.get('Managers'),
            'cluster': ((swarm.get('Cluster') or {}).get('ID') if isinstance(swarm.get('Cluster'), dict) else None),
        }
    return out


def container_detail(host_key, user, ip, container_id, ssh_key_id=None, timeout: int = 25):
    """Inspect one container (with sizes) plus its image, over SSH."""
    cid = shlex.quote(str(container_id))
    command = '; '.join([
        'echo ' + M_INFO,
        'docker_cmd inspect --type container --size ' + cid,
        'echo ' + M_MEM,
        'docker_cmd image inspect "$(docker_cmd inspect -f "{{.Image}}" ' + cid + ')"',
    ])
    ok, out = run(user, ip, ssh_key_id, command, timeout=timeout)
    if not ok:
        raise RuntimeError(out or 'SSH command failed')
    blocks = _split(out)

    def _first_json(text):
        text = (text or '').strip()
        if not text:
            return {}
        try:
            data = json.loads(text)
        except ValueError:
            return {}
        if isinstance(data, list):
            return data[0] if data else {}
        return data or {}

    attrs = _first_json(blocks.get('info'))
    image_attrs = _first_json(blocks.get('mem'))
    if not attrs:
        raise RuntimeError('container not found')

    config = attrs.get('Config') or {}
    state = attrs.get('State') or {}
    health = (state.get('Health') or {}).get('Status')
    image_id = config.get('Image') or attrs.get('Image')
    image_ref = attrs.get('Config', {}).get('Image') or ''

    ports = []
    for container_port, bindings in (attrs.get('NetworkSettings', {}).get('Ports') or {}).items():
        for binding in bindings or []:
            ports.append('%s:%s->%s' % (
                binding.get('HostIp') or '0.0.0.0',
                binding.get('HostPort') or '',
                container_port,
            ))

    mounts = []
    for mount in attrs.get('Mounts') or []:
        mounts.append({
            'source': mount.get('Source'),
            'destination': mount.get('Destination'),
            'type': mount.get('Type'),
            'mode': mount.get('Mode'),
        })

    return {
        'id': attrs.get('Id'),
        'name': (attrs.get('Name') or '').lstrip('/'),
        'created': attrs.get('Created'),
        'restart_count': attrs.get('RestartCount'),
        'platform': attrs.get('Platform'),
        'state': {
            'status': state.get('Status'),
            'running': bool(state.get('Running')),
            'started_at': state.get('StartedAt'),
            'finished_at': state.get('FinishedAt'),
            'exit_code': state.get('ExitCode'),
            'error': state.get('Error'),
            'health': health,
            'restarting': bool(state.get('Restarting')),
            'oom_killed': bool(state.get('OOMKilled')),
        },
        'size_rw': attrs.get('SizeRw'),
        'size_rootfs': attrs.get('SizeRootFs'),
        'image': {
            'id': image_id,
            'tags': image_attrs.get('RepoTags') or [],
            'repo_tags': image_attrs.get('RepoTags') or [],
            'repo_digests': image_attrs.get('RepoDigests') or [],
            'size': image_attrs.get('Size'),
            'created': image_attrs.get('Created'),
            'labels': image_attrs.get('Config', {}).get('Labels') or {},
        },
        'image_name': image_ref,
        'ports': ports,
        'mounts': mounts,
        'labels': config.get('Labels') or {},
        'env_count': len(config.get('Env') or []),
    }


# --------------------------------------------------------------------------
# swarm: per-node collection + node address resolution
# --------------------------------------------------------------------------

_NODE_SWARM_CMD = '; '.join([
    'echo ' + M_PS,
    "docker_cmd ps -a --size --no-trunc --format '" + PS_FORMAT + "'",
    'echo ' + M_STATS,
    "docker_cmd stats --no-stream --no-trunc --format '{{json .}}'",
    'echo ' + M_SYSDF,
    "docker_cmd system df --format '{{json .}}'",
    'echo ' + M_DF,
    'df -B1 /',
    'echo ' + M_STAT,
    'cat /proc/stat',
    'echo ' + M_MEM,
    'cat /proc/meminfo',
    'echo ' + M_NET,
    'cat /proc/net/dev',
])

_NODE_ADDR_CMD = "docker_cmd node inspect --format '{{.Status.Addr}}' "


def _cpu_cores(proc_stat_text: str) -> int:
    return sum(1 for line in (proc_stat_text or '').splitlines()
               if re.match(r'^cpu\d+\s', line)) or 0


_ctr_lock = threading.Lock()
# container_id -> (timestamp, net_rx, net_tx) cumulative counters
_ctr_cache: dict[str, tuple[float, int, int]] = {}


def _container_rates(rows, usage_by_id, now):
    """Rewrite ``net_rx``/``net_tx`` on each row as bytes/second.

    ``docker stats`` reports cumulative counters, so the first poll for a
    container has no rate and reports 0. Counters for containers that have
    gone away are pruned so the cache cannot grow without bound.
    """
    live = set()
    updates = {}
    with _ctr_lock:
        for row in rows:
            cid = row.get('id') or ''
            if not cid:
                continue
            live.add(cid)
            usage = usage_by_id.get(cid[:12]) or usage_by_id.get(cid)
            net = (usage or {}).get('net_bytes') or (None, None)
            rx, tx = net
            if rx is None or tx is None:
                continue
            prev = _ctr_cache.get(cid)
            if prev:
                elapsed = now - prev[0]
                row['net_rx'] = rate(prev[1], rx, elapsed) or 0.0
                row['net_tx'] = rate(prev[2], tx, elapsed) or 0.0
            else:
                row['net_rx'] = 0.0
                row['net_tx'] = 0.0
            row['net_rx_total'] = rx
            row['net_tx_total'] = tx
            updates[cid] = (now, rx, tx)
        _ctr_cache.update(updates)
        if len(_ctr_cache) > max(200, 3 * len(live)):
            for cid in [c for c in _ctr_cache if c not in live]:
                _ctr_cache.pop(cid, None)
    return rows


_SYSDF_CMD = "docker_cmd system df --format '{{json .}}'"


def disk_usage(user, ip, ssh_key_id=None, timeout: int = 15):
    """`docker system df` on one host -> {images/containers/volumes/build_cache}."""
    ok, out = run(user, ip, ssh_key_id, _SYSDF_CMD, timeout=timeout)
    if not ok:
        return {}
    from .parse import parse_kv_json_lines
    out_df = {}
    for obj in parse_kv_json_lines(out):
        key, value = parse_sysdf(obj)
        if key:
            out_df[key] = value
    return out_df


def node_addr(user, ip, ssh_key_id=None, node_id='', timeout: int = 10):
    """Ask the manager for a node's advertised address (``Status.Addr``)."""
    if not node_id:
        return ''
    ok, out = run(user, ip, ssh_key_id,
                  _NODE_ADDR_CMD + shlex.quote(str(node_id)), timeout=timeout)
    if not ok:
        return ''
    lines = [line.strip() for line in (out or '').splitlines() if line.strip()]
    return lines[-1] if lines else ''


def swarm_node_snapshot(host_key, hostname, user, ip, ssh_key_id=None,
                        timeout: int = 25):
    """Collect one swarm node: containers + usage + disk + host counters.

    ``host_key``/``hostname`` only key the rate cache, so the same node keeps
    its previous counters across polls.
    """
    ok, out = run(user, ip, ssh_key_id, _NODE_SWARM_CMD, timeout=timeout)
    if not ok:
        raise RuntimeError(out or 'SSH command failed')

    blocks = _split(out)

    usage_by_id = {}
    for obj in parse_kv_json_lines(blocks.get('stats', '')):
        parsed = parse_stats_line(obj)
        if parsed.get('id'):
            usage_by_id[parsed['id'][:12]] = parsed
            usage_by_id[parsed['id']] = parsed

    containers = []
    for line in (blocks.get('ps') or '').splitlines():
        if not line.strip():
            continue
        parsed = parse_ps_line(line)
        if not parsed.get('id'):
            continue
        usage = usage_by_id.get(parsed['id'][:12]) or usage_by_id.get(parsed['id'])
        row = _container_row(parsed, usage)
        row['node'] = hostname
        containers.append(row)
    _container_rates(containers, usage_by_id, time.time())

    sysdf = {}
    for obj in parse_kv_json_lines(blocks.get('sysdf', '')):
        key, value = parse_sysdf(obj)
        if key:
            sysdf[key] = value

    proc = parse_proc_stat(blocks.get('stat', ''))
    mem = parse_meminfo(blocks.get('mem', ''))
    netdev = parse_netdev(blocks.get('net', ''))
    disk_total, disk_used = parse_df_root(blocks.get('df', ''))

    rate_key = '%s/%s' % (host_key, hostname or ip)
    rx_bps, tx_bps, cpu_pct = _host_rates(
        rate_key, netdev.get('rx') or 0, netdev.get('tx') or 0,
        proc.get('total') or 0, proc.get('idle') or 0,
    )

    mem_total = mem.get('total') or 0
    mem_used = mem.get('used') or 0
    running = [c for c in containers
               if (c.get('state') or '').lower() == 'running']

    return {
        'containers': containers,
        'docker_df': sysdf,
        'metrics': {
            'cpu_pct': cpu_pct,
            'cores': _cpu_cores(blocks.get('stat', '')),
            'mem_used': mem_used,
            'mem_total': mem_total,
            'mem_pct': _ram_pct(mem_used, mem_total),
            'disk_used': disk_used,
            'disk_total': disk_total,
            'disk_pct': (round(100.0 * disk_used / disk_total, 2)
                         if disk_total else None),
            'net_rx_bps': rx_bps,
            'net_tx_bps': tx_bps,
            'containers_total': len(containers),
            'containers_running': len(running),
        },
        'ts': time.time(),
    }
