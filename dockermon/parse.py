"""Pure parsing/math helpers for Docker inventory (SSH CLI output + /proc)."""

from __future__ import annotations

import re

_SIZE_RE = re.compile(r"^([\d.]+)\s*([A-Za-z]*)$")
_UNIT_BYTES = {
    "": 1, "b": 1,
    "k": 10 ** 3, "kb": 10 ** 3, "kib": 2 ** 10,
    "m": 10 ** 6, "mb": 10 ** 6, "mib": 2 ** 20,
    "g": 10 ** 9, "gb": 10 ** 9, "gib": 2 ** 30,
    "t": 10 ** 12, "tb": 10 ** 12, "tib": 2 ** 40,
}


def parse_size(text):
    if text is None:
        return None
    s = str(text).strip()
    if not s or s in {"--", "N/A", "NaN"}:
        return None
    m = _SIZE_RE.match(s)
    if not m:
        return None
    mult = _UNIT_BYTES.get(m.group(2).lower())
    if mult is None:
        return None
    try:
        return float(m.group(1)) * mult
    except ValueError:
        return None


def parse_pct(text):
    if text is None:
        return None
    s = str(text).strip().rstrip("%").strip()
    if not s or s.lower() in {"--", "n/a", "nan"}:
        return None
    try:
        return float(s)
    except ValueError:
        return None


_PAIR_RE = re.compile(r"^\s*(.+?)\s*/\s*(.+?)\s*$")


def parse_pair(text):
    if text is None:
        return (None, None)
    m = _PAIR_RE.match(str(text))
    if not m:
        return (None, None)
    return (parse_size(m.group(1)), parse_size(m.group(2)))


def parse_ps_size(text):
    """'1.09kB (virtual 9.44MB)' -> (rw, virtual)."""
    if not text:
        return (None, None)
    s = str(text).strip()
    m = re.match(r"^(.*?)\s*\(virtual\s+(.*?)\)\s*$", s)
    if not m:
        return (parse_size(s), None)
    return (parse_size(m.group(1)), parse_size(m.group(2)))


def _int(v, default=0):
    try:
        return int(str(v).strip() or default)
    except (TypeError, ValueError):
        return default


def parse_stats_line(obj):
    net = parse_pair(obj.get("NetIO"))
    blk = parse_pair(obj.get("BlockIO"))
    mem_used, mem_limit = parse_pair(obj.get("MemUsage"))
    return {
        "id": str(obj.get("ID", "")),
        "name": str(obj.get("Name", "")),
        "cpu_pct": parse_pct(obj.get("CPUPerc")),
        "mem_used": mem_used,
        "mem_limit": mem_limit,
        "mem_pct": parse_pct(obj.get("MemPerc")),
        "net_bytes": net,
        "blk_bytes": blk,
        "pids": _int(obj.get("PIDs")),
    }


PS_FIELDS = 10


def parse_ps_line(line):
    """TSV row from `docker ps --size --no-trunc --format ...`.

    id, name, image, state, status, size, stack, service, task, node
    """
    f = line.split("\t")
    while len(f) < PS_FIELDS:
        f.append("")
    size, size_virtual = parse_ps_size(f[5])
    return {
        "id": f[0].strip(),
        "name": f[1].strip(),
        "image": f[2].strip(),
        "state": f[3].strip(),
        "status": f[4].strip(),
        "size": size,
        "size_virtual": size_virtual,
        "stack": f[6].strip() or None,
        "service": f[7].strip() or None,
        "task_id": f[8].strip() or None,
        "node_id": f[9].strip() or None,
    }


def parse_node_line(text):
    """One line of `docker node ls --format '{{.ID}}\t{{.Hostname}}\t...'`."""
    f = (text or "").split("\t")
    while len(f) < 5:
        f.append("")
    return {
        "id": f[0].strip(),
        "hostname": f[1].strip(),
        "status": f[2].strip(),
        "availability": f[3].strip(),
        "manager": f[4].strip() or None,
    }


def parse_proc_stat(text):
    for line in (text or "").splitlines():
        if line.startswith("cpu "):
            parts = [int(x) for x in line.split()[1:]]
            total = sum(parts)
            idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
            return {"total": total, "idle": idle, "busy": total - idle}
    return None


def parse_meminfo(text):
    out = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        num = v.strip().split()
        if not num:
            continue
        try:
            out[k.strip()] = int(num[0]) * 1024  # kB -> bytes
        except ValueError:
            continue
    total = out.get("MemTotal") or 0
    avail = out.get("MemAvailable") or out.get("MemFree") or 0
    return {"total": total, "used": max(0, total - avail), "available": avail}


def parse_netdev(text):
    rx = tx = 0
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        if name.strip() == "lo":
            continue
        f = rest.split()
        if len(f) < 9:
            continue
        try:
            rx += int(f[0])
            tx += int(f[8])
        except ValueError:
            continue
    return {"rx": rx, "tx": tx}


def parse_kv_json_lines(text):
    import json
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def downsample(values, limit):
    if not values or len(values) <= limit:
        return list(values)
    step = len(values) / float(limit)
    return [values[int(i * step)] for i in range(limit)]
