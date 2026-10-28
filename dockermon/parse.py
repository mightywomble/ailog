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


# --------------------------------------------------------------------------
# docker system df / filesystem
# --------------------------------------------------------------------------

_SYSDF_TYPES = {
    "Images": "images",
    "Local Volumes": "volumes",
    "Containers": "containers",
    "Build Cache": "build_cache",
}


def parse_sysdf(obj):
    """One ``{{json .}}`` row from `docker system df` -> (key, counts).

    Returns ``(None, None)`` for row types we do not track.
    """
    key = _SYSDF_TYPES.get((obj or {}).get("Type"))
    if key is None:
        return None, None

    def _reclaimable(value):
        if not value:
            return 0.0
        m = re.match(r"^([\d.]+\s*[A-Za-z]*)", str(value).strip())
        return parse_size(m.group(1)) if m else 0.0

    return key, {
        "count": _int(obj.get("TotalCount")),
        "size": parse_size(obj.get("Size")) or 0.0,
        "reclaimable": _reclaimable(obj.get("Reclaimable")),
    }


def parse_df_root(text):
    """Parse `df -B1 /` output -> (total_bytes, used_bytes)."""
    for line in (text or "").splitlines():
        fields = line.split()
        if len(fields) >= 6 and fields[5] == "/" and fields[4].endswith("%"):
            try:
                return float(fields[1]), float(fields[2])
            except ValueError:
                continue
    return (None, None)


def rate(prev, cur, dt):
    """Counter delta over ``dt`` seconds -> per-second rate.

    Returns ``None`` when unknown and ``0.0`` on a counter reset (reboot, or a
    network interface that was recreated) rather than a negative spike.
    """
    if prev is None or cur is None or not dt or dt <= 0:
        return None
    delta = cur - prev
    if delta < 0:
        return 0.0
    return delta / float(dt)


# --------------------------------------------------------------------------
# app (swarm stack) grouping
# --------------------------------------------------------------------------

APP_TOTALS = ("cpu_pct", "mem_used", "net_rx", "net_tx")


def _c_num(container, *names):
    for name in names:
        value = container.get(name)
        if value is None:
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return 0.0


def aggregate_apps(containers):
    """Group containers by stack (app) -> service, summing resource usage.

    ``containers`` may come from either transport, so both the SSH rows
    (``cpu_percent``/``mem_percent``) and the SDK rows use the same field
    names; anything missing counts as zero.
    """
    apps = {}
    for container in containers or []:
        app_name = container.get("stack") or "(standalone)"
        app = apps.setdefault(app_name, {
            "name": app_name, "cpu_pct": 0.0, "mem_used": 0.0,
            "net_rx": 0.0, "net_tx": 0.0, "size": 0.0,
            "container_count": 0, "running_count": 0,
            "nodes": set(), "services": {},
        })
        service_name = (container.get("service")
                        or (container.get("name") or "").split(".")[0]
                        or "(none)")
        service = app["services"].setdefault(service_name, {
            "name": service_name, "cpu_pct": 0.0, "mem_used": 0.0,
            "net_rx": 0.0, "net_tx": 0.0,
            "container_count": 0, "running_count": 0, "containers": [],
        })

        cpu = _c_num(container, "cpu_percent", "cpu_pct")
        mem = _c_num(container, "mem_used")
        rx = _c_num(container, "net_rx")
        tx = _c_num(container, "net_tx")
        size = _c_num(container, "size_rw", "size")
        running = (container.get("state") or "").lower() == "running"

        for scope in (app, service):
            scope["container_count"] += 1
            if running:
                scope["running_count"] += 1
            scope["cpu_pct"] += cpu
            scope["mem_used"] += mem
            scope["net_rx"] += rx
            scope["net_tx"] += tx

        app["size"] += size
        if container.get("node"):
            app["nodes"].add(container["node"])

        service["containers"].append({
            "id": container.get("id"),
            "short_id": container.get("short_id") or (container.get("id") or "")[:12],
            "name": container.get("name"),
            "image": container.get("image"),
            "image_tag": container.get("image_tag"),
            "state": container.get("state"),
            "status": container.get("status"),
            "node": container.get("node"),
            "cpu_pct": round(cpu, 2),
            "mem_used": mem,
            "mem_percent": _c_num(container, "mem_percent", "mem_pct"),
        })
    return apps


def finalize_apps(apps):
    """``aggregate_apps`` output -> sorted, JSON-ready list."""
    out = []
    for app in apps.values():
        services = sorted(app["services"].values(), key=lambda s: s["name"])
        for service in services:
            service["containers"] = sorted(
                service["containers"], key=lambda c: c.get("name") or "")
            for key in ("cpu_pct", "mem_used", "net_rx", "net_tx"):
                service[key] = round(service[key], 2)
        out.append({
            "name": app["name"],
            "cpu_pct": round(app["cpu_pct"], 2),
            "mem_used": round(app["mem_used"], 1),
            "net_rx": round(app["net_rx"], 1),
            "net_tx": round(app["net_tx"], 1),
            "size": round(app["size"], 1),
            "container_count": app["container_count"],
            "running_count": app["running_count"],
            "nodes": sorted(app["nodes"]),
            "services": services,
        })
    # Busiest first, but keep the un-stacked leftovers at the bottom.
    out.sort(key=lambda a: (a["name"] == "(standalone)",
                            -(a["cpu_pct"] or 0), a["name"]))
    return out
