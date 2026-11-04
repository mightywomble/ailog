"""status — one page, zero-day view of the homelab.

PVE nodes -> guests -> docker runtimes -> swarm services -> public applications,
built from the MCP servers that already know the estate (managelm, ailog,
netdata, patchmon) plus the Proxmox API and HTTP probes.

Routes
  GET  /                      dashboard (light + dark)
  GET  /api/snapshot          last poll (fast, served from memory)
  GET  /api/history?hours=12  incidents / uptime buckets for the last N hours
  GET  /api/node/{id}         drill-down: live stats, facts and logs
  GET  /api/node/{id}/history per-node status + metric series
  POST /api/refresh           force a poll now
  GET  /healthz
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import collect
import store

HERE = os.path.dirname(os.path.abspath(__file__))


def load_apps() -> list[dict]:
    path = os.environ.get("STATUS_APPS_FILE", os.path.join(HERE, "apps.json"))
    try:
        with open(path) as fh:
            return json.load(fh).get("apps", [])
    except Exception:
        return []


CFG = {
    "pve_url": os.environ.get("PVE_URL", "https://pve:8006"),
    "pve_token": os.environ.get("PVE_TOKEN", ""),
    "mcp_url": os.environ.get("METAMCP_URL", ""),
    "mcp_key": os.environ.get("METAMCP_API_KEY", ""),
    "apps": load_apps(),
}
POLL_SECONDS = int(os.environ.get("STATUS_POLL_SECONDS", "60"))
HISTORY_HOURS = int(os.environ.get("STATUS_HISTORY_HOURS", "12"))

app = FastAPI(title="homelab status", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=os.path.join(HERE, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(HERE, "templates"))

_lock = threading.Lock()
_cache: dict[str, Any] = {"snapshot": None, "error": None, "ts": 0}
_polling = threading.Event()


def log(*a: Any) -> None:
    print(*a, flush=True)


def poll_once() -> dict:
    t0 = time.time()
    try:
        snap = collect.build(CFG, log)
        store.save_snapshot(snap)
        with _lock:
            _cache["snapshot"] = snap
            _cache["ts"] = int(time.time() * 1000)
            _cache["error"] = None
        log(f"poll ok in {int((time.time() - t0) * 1000)}ms")
        return snap
    except Exception as e:  # noqa: BLE001
        log("poll failed:", e)
        with _lock:
            _cache["error"] = str(e)[:300]
        return {}


def poller() -> None:
    store.init()
    while True:
        poll_once()
        _polling.wait(POLL_SECONDS)
        _polling.clear()


@app.on_event("startup")
def startup() -> None:
    store.init()
    threading.Thread(target=poller, daemon=True).start()


# ---------------------------------------------------------------------------
# pages / api
# ---------------------------------------------------------------------------
@app.get("/healthz")
def healthz() -> dict:
    snap = _cache.get("snapshot")
    return {"ok": True, "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "snapshot_age_s": int(time.time() - snap["ts"]) if snap else None,
            "error": _cache.get("error")}


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/snapshot")
def api_snapshot() -> JSONResponse:
    with _lock:
        snap = _cache.get("snapshot")
        ts = _cache["ts"]
        err = _cache["error"]
    if not snap:
        snap = store.latest_snapshot()
    if not snap:
        return JSONResponse({"nodes": [], "pending": True, "error": err}, status_code=200)
    return JSONResponse({**snap, "served_ts": ts, "error": err})


@app.get("/api/history")
def api_history(hours: int = HISTORY_HOURS) -> dict:
    hours = max(1, min(hours, 24 * 7))
    return {"hours": hours, "episodes": store.episodes(hours),
            "buckets": store.uptime_buckets(hours, 24 if hours <= 12 else 48)}


@app.post("/api/refresh")
def api_refresh() -> dict:
    _polling.set()
    threading.Thread(target=poll_once, daemon=True).start()
    return {"ok": True, "started": int(time.time())}


@app.get("/api/node/{node_id:path}")
def api_node(node_id: str) -> dict:
    with _lock:
        snap = _cache.get("snapshot") or store.latest_snapshot() or {}
    node = next((n for n in snap.get("nodes", []) if n["id"] == node_id), None)
    if not node:
        raise HTTPException(404, "unknown node")

    detail: dict[str, Any] = {"sections": [], "facts": {}}
    layer = node["layer"]
    extra = node.get("extra") or {}

    def section(title: str, kind: str, body: Any) -> None:
        detail["sections"].append({"title": title, "kind": kind, "body": body})

    detail["facts"] = {
        "layer": layer,
        "status": node["status"],
        "parent": node.get("parent"),
        "subtitle": node.get("subtitle"),
    }

    if layer == "hypervisor":
        pve = collect.Pve(CFG["pve_url"], CFG["pve_token"])
        try:
            st = pve.get(f"/nodes/{node['name']}/status")
            facts = {
                "cpu": f"{collect.pct(st.get('cpu'))}% of {st.get('cpuinfo', {}).get('cpus')} cores",
                "memory": f"{st.get('memory', {}).get('used', 0) // 2**30} GiB / "
                          f"{st.get('memory', {}).get('total', 0) // 2**30} GiB",
                "uptime": collect.uptime_str(st.get("uptime")),
                "load": ", ".join(str(round(float(x), 2)) for x in st.get("loadavg") or []),
                "pve": st.get("pveversion"),
                "kernel": st.get("kversion"),
            }
            detail["facts"].update(facts)
            section("Storage", "kv", [
                {"k": f"{s.get('storage')} ({s.get('type')})",
                 "v": f"{s.get('used', 0) / 2**30:.0f} / {s.get('total', 0) / 2**30:.0f} GiB"
                      f" · {100 * (s.get('used') or 0) / max(1, s.get('total') or 1):.0f}%"}
                for s in (pve.get(f"/nodes/{node['name']}/storage") or [])
            ])
        except Exception as e:  # noqa: BLE001
            section("PVE status", "text", f"unavailable: {e}")
        _journal(section, node["name"])

    elif layer == "vm":
        vmid, pnode = extra.get("vmid"), extra.get("node")
        pve = collect.Pve(CFG["pve_url"], CFG["pve_token"])
        try:
            st = pve.get(f"/nodes/{pnode}/qemu/{vmid}/status/current")
            cfg = pve.get(f"/nodes/{pnode}/qemu/{vmid}/config")
            detail["facts"].update({
                "cpu": f"{collect.pct(st.get('cpu'))}% of {st.get('cpus')} vCPU",
                "memory": f"{(st.get('mem') or 0) / 2**30:.1f} / {(st.get('maxmem') or 0) / 2**30:.1f} GiB",
                "uptime": collect.uptime_str(st.get("uptime")),
                "net in/out": f"{(st.get('netin') or 0) / 2**30:.1f} / {(st.get('netout') or 0) / 2**30:.1f} GiB",
                "agent": "enabled" if cfg.get("agent") else "not enabled",
                "ostype": cfg.get("ostype"),
                "cores": cfg.get("cores"),
                "balloon": cfg.get("balloon"),
            })
            disks = []
            for k, d in cfg.items():
                if not k.startswith(("scsi", "virtio", "ide", "sata", "efidisk", "tpmstate")):
                    continue
                if isinstance(d, dict):
                    disks.append({"k": k, "v": f"{d.get('file') or d.get('volume') or ''} "
                                                  f"{('size=' + str(d['size'])) if d.get('size') else ''}".strip()})
                elif isinstance(d, str):
                    disks.append({"k": k, "v": d.replace(",", " · ")})
            section("Disks", "kv", disks)
        except Exception as e:  # noqa: BLE001
            section("PVE status", "text", f"unavailable: {e}")
        host = _agent_facts(node["name"], section, detail)
        _docker_section(section, host)
        _journal(section, node["name"])

    elif layer == "docker":
        conts = extra.get("containers") or []
        section("Containers", "table", {
            "columns": ["name", "state", "status", "image"],
            "rows": [[c["name"], c["state"], c["status"], c["image"]] for c in conts],
        })
        _agent_facts(node["name"], section, detail)
        bad = [c["name"] for c in conts if "unhealthy" in c["status"] or c["state"] != "running"]
        for cname in bad[:2]:
            _container_logs(section, node["name"], cname)

    elif layer == "service":
        detail["facts"].update({"image": extra.get("image"), "ports": extra.get("ports"),
                                "stack": extra.get("stack"),
                                "replicas": f"{(node.get('metrics') or {}).get('running')}/"
                                            f"{(node.get('metrics') or {}).get('desired')}"})
        section("Where it runs", "text",
                "Replica and task detail comes from the swarm rollup; open the "
                "docker runtime on the node for the containers themselves.")

    elif layer == "app":
        url = extra.get("url")
        t0 = time.time()
        try:
            r = httpx.get(url, timeout=10.0, verify=False, follow_redirects=False)
            body = r.text[:600]
            section("HTTP response", "kv", [
                {"k": "status", "v": f"{r.status_code} {r.reason_phrase}"},
                {"k": "server", "v": r.headers.get("server", "—")},
                {"k": "content-type", "v": r.headers.get("content-type", "—")},
                {"k": "location", "v": r.headers.get("location", "—")},
                {"k": "latency", "v": f"{int((time.time() - t0) * 1000)} ms"},
                {"k": "body", "v": body.replace("\n", " ")[:200]},
            ])
        except Exception as e:  # noqa: BLE001
            section("HTTP response", "text", f"{type(e).__name__}: {e}")
        detail["facts"].update({"url": url, "group": extra.get("group"),
                                "forwarded to": extra.get("forward")})

    detail["history"] = store.history(node_id, HISTORY_HOURS)
    return {"node": node, "detail": detail}


@app.get("/api/node/{node_id:path}/history")
def api_node_history(node_id: str, hours: int = HISTORY_HOURS) -> dict:
    return {"node_id": node_id, "points": store.history(node_id, max(1, min(hours, 168)))}


# ---------------------------------------------------------------------------
# helpers used by the drill-down
# ---------------------------------------------------------------------------
def _mcp_call(tool: str, args: dict) -> Any:
    try:
        mcp = collect.Mcp(CFG["mcp_url"], CFG["mcp_key"], "status-detail")
        return mcp.call(tool, args)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)[:200]}


def _ailog_key(snap: dict, name: str) -> str | None:
    for h in (snap.get("ailog") or {}).get("hosts", []):
        if h.get("name") == name:
            return h.get("key")
    return None


def _agent_facts(name: str, section, detail: dict) -> str | None:
    res = _mcp_call("managelm__search_agents", {"query": name})
    agents = collect.parse_json_text(res) if not isinstance(res, dict) else res
    if isinstance(agents, list):
        a = next((x for x in agents if x.get("hostname") == name), None)
        if a:
            hm = a.get("health_metrics") or {}
            detail["facts"].update({
                "os": a.get("os_info"),
                "ip": a.get("ip_address"),
                "host agent": a.get("agent_version"),
                "last seen": a.get("last_seen_at"),
            })
            section("Agent metrics", "kv", [
                {"k": "cpu", "v": f"{hm.get('cpu_percent')}%"},
                {"k": "memory", "v": f"{hm.get('memory_percent')}%"},
                {"k": "disk", "v": f"{hm.get('disk_percent')}%"},
                {"k": "load", "v": str(hm.get("load_avg"))},
            ])
    return name


def _docker_section(section, name: str, key: str | None = None) -> None:
    if not key:
        res = _mcp_call("ailog__list_hosts", {})
        parsed = collect.parse_json_text(res)
        for h in (parsed.get("hosts", []) if isinstance(parsed, dict) else []):
            if h.get("name") == name:
                key = h.get("key")
    if not key:
        return
    r = _mcp_call("ailog__list_containers", {"host": key})
    if isinstance(r, dict) and not r.get("error"):
        rows = [[c.get("name"), c.get("state"), c.get("status"), c.get("image")]
                for c in r.get("containers", [])]
        section("Containers on this host", "table",
                {"columns": ["name", "state", "status", "image"], "rows": rows})


def _container_logs(section, host: str, container: str) -> None:
    key = None
    res = _mcp_call("ailog__list_hosts", {})
    parsed = collect.parse_json_text(res)
    for h in (parsed.get("hosts", []) if isinstance(parsed, dict) else []):
        if h.get("name") == host:
            key = h.get("key")
    if not key:
        return
    r = _mcp_call("ailog__read_docker_logs", {"host": key, "container": container, "lines": 40})
    body = r.get("logs", r.get("output", r)) if isinstance(r, dict) else r
    section(f"Logs · {container}", "pre", str(body)[:4000])


def _journal(section, host: str) -> None:
    key = None
    res = _mcp_call("ailog__list_hosts", {})
    parsed = collect.parse_json_text(res)
    for h in (parsed.get("hosts", []) if isinstance(parsed, dict) else []):
        if h.get("name") == host:
            key = h.get("key")
    if not key:
        return
    r = _mcp_call("ailog__read_journal", {"host": key, "lines": 40, "priority": "warning"})
    body = r.get("output", r) if isinstance(r, dict) else r
    section("Journal (warnings+)", "pre", str(body)[:4000])
