"""Collectors: PVE, MetaMCP (managelm / ailog / netdata / patchmon) and HTTP.

Everything the dashboard knows comes from here. Each poll builds one snapshot
of the whole estate as a flat list of nodes; the layer + parent fields give the
drill-down tree the UI draws.

  hypervisor  Proxmox VE nodes                    (PVE API)
  vm          QEMU/LXC guests                     (PVE API + managelm)
  docker      Docker runtimes on those guests     (AILog run_command)
  service     Docker Swarm services               (AILog run_command)
  app         Public applications via NPM         (HTTP probe)
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import threading
import time
from typing import Any

import httpx

SEV = {"up": 0, "unknown": 1, "degraded": 2, "down": 3}


class ToolError(RuntimeError):
    """The MCP server understood the call and refused it - do not retry."""


# ---------------------------------------------------------------------------
# MetaMCP client (one long-lived session, serialised calls)
# ---------------------------------------------------------------------------
class Mcp:
    def __init__(self, url: str, key: str, name: str = "status") -> None:
        self.url = url
        self.key = key
        self.name = name
        self.sid: str | None = None
        self.lock = threading.RLock()
        self.c = httpx.Client(timeout=90.0, verify=False)

    def _post(self, payload: dict) -> list[dict]:
        headers = {"content-type": "application/json",
                   "accept": "application/json, text/event-stream",
                   "x-api-key": self.key}
        if self.sid:
            headers["mcp-session-id"] = self.sid
        r = self.c.post(self.url, json=payload, headers=headers)
        r.raise_for_status()
        sid = r.headers.get("mcp-session-id")
        if sid:
            self.sid = sid
        out = []
        for chunk in r.text.split("\n\n"):
            for line in chunk.splitlines():
                if line.startswith("data: "):
                    out.append(json.loads(line[6:]))
        return out

    def init(self) -> None:
        with self.lock:
            self.sid = None
            self._post({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                   "clientInfo": {"name": self.name, "version": "1"}}})
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def call(self, tool: str, args: dict | None = None) -> Any:
        """One retry, but only for transport/session failures.

        A tool that legitimately fails (unreachable host, bad argument) must not
        trigger a re-initialise: that costs a full MetaMCP handshake per call
        and turned a 15-host sweep into minutes.
        """
        with self.lock:
            if not self.sid:
                self.init()
            try:
                return self._call(tool, args)
            except ToolError:
                raise
            except Exception:
                self.init()
                return self._call(tool, args)

    def _call(self, tool: str, args: dict | None) -> Any:
        res = self._post({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                          "params": {"name": tool, "arguments": args or {}}})
        if not res:
            raise RuntimeError("empty MCP response")
        if "error" in res[0]:
            raise ToolError(str(res[0]["error"].get("message"))[:200])
        result = res[0].get("result", {})
        if result.get("isError"):
            raise ToolError(str(result.get("content"))[:200])
        if "structuredContent" in result:
            return result["structuredContent"]
        text = (result.get("content") or [{}])[0].get("text", "")
        try:
            return json.loads(text)
        except Exception:
            return text


def retry(fn, attempts: int = 3, delay: float = 1.0) -> Any:
    """Retry the flaky-but-transient MCP failures (stale host cache)."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001
            last = e
            if "unknown host" not in str(e).lower():
                raise
            time.sleep(delay * (i + 1))
    raise last  # type: ignore[misc]


def parse_json_text(v: Any) -> Any:
    """managelm returns prose + JSON; pull the JSON body out of it."""
    if not isinstance(v, str):
        return v
    for pat in (r"\[.*\]", r"\{.*\}"):
        m = re.search(pat, v, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                continue
    return v


# ---------------------------------------------------------------------------
# Proxmox VE
# ---------------------------------------------------------------------------
class Pve:
    def __init__(self, url: str, token: str) -> None:
        self.url = url.rstrip("/")
        self.token = token
        self.c = httpx.Client(timeout=25.0, verify=False,
                              headers={"Authorization": f"PVEAPIToken={token}"})

    def get(self, path: str) -> Any:
        r = self.c.get(f"{self.url}/api2/json{path}")
        r.raise_for_status()
        return r.json().get("data")

    def snapshot(self) -> dict:
        res = self.get("/cluster/resources") or []
        nodes, vms, storage = [], [], []
        for r in res:
            t = r.get("type")
            if t == "node":
                nodes.append(r)
            elif t in ("qemu", "lxc"):
                vms.append(r)
            elif t == "storage":
                storage.append(r)
        return {"nodes": nodes, "vms": vms, "storage": storage}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def pct(v: Any) -> float | None:
    try:
        return round(float(v) * 100, 1)
    except Exception:
        return None


def uptime_str(seconds: Any) -> str:
    try:
        s = int(seconds)
    except Exception:
        return "—"
    d, rem = divmod(s, 86400)
    h = rem // 3600
    return f"{d}d {h}h" if d else f"{h}h"


def issue(level: str, text: str) -> dict:
    return {"level": level, "text": text}


def worst(statuses: list[str]) -> str:
    if not statuses:
        return "unknown"
    return max(statuses, key=lambda s: SEV.get(s, 1))


def docker_hosts(mcp: Mcp, ailog_hosts: list[dict], timeout: int = 30) -> dict:
    """Containers per host through the ailog MCP (backed by the app's docker API)."""
    out: dict[str, dict] = {}

    def one(h: dict) -> tuple[str, dict]:
        try:
            res = retry(lambda: mcp.call("ailog__list_containers", {"host": h["key"]}))
            if not isinstance(res, dict) or res.get("error"):
                return h["name"], {"reachable": False, "containers": [],
                                   "error": str((res or {}).get("error", ""))[:120]}
            rows = [{"name": c.get("name"), "state": c.get("state"),
                     "status": c.get("status"), "image": c.get("image")}
                    for c in res.get("containers", [])]
            # no daemon here (hypervisor, NAS, laptop): docker API answers with 0
            # rows and a successful call, which is different from "unreachable"
            return h["name"], {"reachable": bool(rows), "containers": rows,
                               "empty": not rows}
        except Exception as e:  # noqa: BLE001
            return h["name"], {"reachable": False, "containers": [], "error": str(e)[:120]}

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for name, info in ex.map(one, ailog_hosts):
            out[name] = info
    return out


def swarm_info(mcp: Mcp, host_key: str) -> dict:
    """Swarm services + members through the ailog MCP."""
    try:
        res = retry(lambda: mcp.call("ailog__list_swarm_services", {"manager": host_key}))
        if not isinstance(res, dict) or res.get("error"):
            return {"ok": False, "services": [], "members": [],
                    "error": str((res or {}).get("error", ""))[:120]}
        services = [{"name": x["name"], "stack": x.get("stack"),
                     "running": x.get("running", 0), "desired": x.get("desired", 0),
                     "replicas": f"{x.get('running', 0)}/{x.get('desired', 0)}",
                     "image": x.get("image") or "", "ports": ""}
                    for x in res.get("services", [])]
        return {"ok": bool(services), "services": services,
                "members": [], "error": None}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "services": [], "members": [], "error": str(e)[:120]}


def probe_apps(apps: list[dict], timeout: float = 6.0) -> list[dict]:
    out: list[dict] = []

    def one(a: dict) -> dict:
        t0 = time.time()
        try:
            r = httpx.get(a["url"], timeout=timeout, verify=False,
                          follow_redirects=False,
                          headers={"user-agent": "homelab-status/1.0"})
            ms = int((time.time() - t0) * 1000)
            code = r.status_code
            if code >= 500:
                status, note = "down", f"HTTP {code}"
            elif code in (401, 403):
                status, note = "up", f"HTTP {code} (auth)"
            elif code >= 400:
                status, note = "up", f"HTTP {code}"
            else:
                status, note = "up", f"HTTP {code}"
            return {**a, "status": status, "code": code, "latency_ms": ms, "note": note,
                    "server": r.headers.get("server", "")}
        except Exception as e:  # noqa: BLE001
            ms = int((time.time() - t0) * 1000)
            return {**a, "status": "down", "code": None, "latency_ms": ms,
                    "note": type(e).__name__ + ": " + str(e)[:80]}

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        out = list(ex.map(one, apps))
    return out


# ---------------------------------------------------------------------------
# main snapshot
# ---------------------------------------------------------------------------
def build(cfg: dict, log=lambda *a: None) -> dict:
    started = time.time()
    ts = int(started)
    nodes: list[dict] = []
    sources: dict[str, dict] = {}

    def note(src: str, ok: bool, detail: str = "") -> None:
        sources[src] = {"ok": ok, "detail": detail, "ts": int(time.time())}

    # ---- Proxmox -----------------------------------------------------------
    pve_raw: dict = {"nodes": [], "vms": [], "storage": []}
    try:
        pve_raw = Pve(cfg["pve_url"], cfg["pve_token"]).snapshot()
        note("pve", True, f"{len(pve_raw['nodes'])} nodes, {len(pve_raw['vms'])} guests")
    except Exception as e:  # noqa: BLE001
        note("pve", False, str(e)[:160])

    health_by_host: dict[str, dict] = {}
    mcp: Mcp | None = None
    try:
        mcp = Mcp(cfg["mcp_url"], cfg["mcp_key"], "status")
        agents = parse_json_text(mcp.call("managelm__search_agents", {"query": ""}))
        if isinstance(agents, list):
            for a in agents:
                health_by_host[a.get("hostname", "")] = a
        note("managelm", bool(agents), f"{len(health_by_host)} agents")
    except Exception as e:  # noqa: BLE001
        note("managelm", False, str(e)[:160])
        mcp = Mcp(cfg["mcp_url"], cfg["mcp_key"], "status")

    gitea = {}
    try:
        ailog_hosts = parse_json_text(mcp.call("ailog__list_hosts", {"include_status": True}))
        if isinstance(ailog_hosts, dict):
            ailog_hosts = ailog_hosts.get("hosts", [])
        note("ailog", bool(ailog_hosts), f"{len(ailog_hosts)} hosts")
    except Exception as e:  # noqa: BLE001
        ailog_hosts = []
        note("ailog", False, str(e)[:160])

    try:
        patches = parse_json_text(mcp.call("patchmon__list_hosts", {}))
        patch_by_host = {h.get("hostname", ""): h for h in (patches or {}).get("hosts", [])}
        note("patchmon", True, f"{len(patch_by_host)} hosts")
    except Exception as e:  # noqa: BLE001
        patch_by_host = {}
        note("patchmon", False, str(e)[:160])

    alerts: list[dict] = []
    try:
        nd = parse_json_text(mcp.call("netdata__list_raised_alerts", {}))
        hdr = nd.get("alert_instances_header", []) if isinstance(nd, dict) else []
        idx = {name: i for i, name in enumerate(hdr)}
        for row in (nd.get("alert_instances") or []) if isinstance(nd, dict) else []:
            alerts.append({
                "name": row[idx["Alert Name"]],
                "host": row[idx["Hostname"]],
                "status": row[idx["Status"]],
                "summary": row[idx["Summary"]] or row[idx["Alert Name"]],
                "ts": row[idx["Last Transition Timestamp"]],
                "context": row[idx["Context"]],
            })
        note("netdata", True, f"{len(alerts)} alerts")
    except Exception as e:  # noqa: BLE001
        note("netdata", False, str(e)[:160])

    docker = docker_hosts(mcp, ailog_hosts) if ailog_hosts else {}
    note("docker", bool(docker), f"{sum(1 for v in docker.values() if v.get('reachable'))} docker hosts")

    swarm_host = next((h for h in ailog_hosts if h["name"] == "swarm-manager"), None)
    swarm = swarm_info(mcp, swarm_host["key"]) if swarm_host else {"ok": False, "services": [], "members": []}
    note("swarm", swarm.get("ok", False), f"{len(swarm.get('services', []))} services")

    # ---- hypervisor layer --------------------------------------------------
    vm_by_name: dict[str, dict] = {}
    for vm in pve_raw["vms"]:
        vm_by_name[vm.get("name", "")] = vm

    for n in pve_raw["nodes"]:
        name = n.get("node")
        st = "up" if n.get("status") == "online" else "down"
        mem_p = pct((n.get("mem") or 0) / (n.get("maxmem") or 1))
        disk_p = pct((n.get("disk") or 0) / (n.get("maxdisk") or 1))
        issues = []
        if st != "up":
            issues.append(issue("crit", "node offline"))
        if mem_p and mem_p > 92:
            issues.append(issue("warn", f"memory {mem_p}%"))
        if disk_p and disk_p > 90:
            issues.append(issue("warn", f"root disk {disk_p}%"))
        nodes.append({"id": f"pve:{name}", "layer": "hypervisor", "name": name,
                      "parent": None, "status": st,
                      "subtitle": f"PVE {n.get('pveversion', '').split('/')[-1] if n.get('pveversion') else ''} · {uptime_str(n.get('uptime'))} up",
                      "metrics": {"cpu": pct(n.get("cpu") / (n.get("maxcpu") or 1)),
                                  "mem": mem_p, "disk": disk_p,
                                  "uptime": uptime_str(n.get("uptime"))},
                      "issues": issues, "extra": {"maxcpu": n.get("maxcpu"),
                                                   "maxmem": n.get("maxmem")}})

    # ---- vm layer ----------------------------------------------------------
    for vm in pve_raw["vms"]:
        name = vm.get("name") or str(vm.get("vmid"))
        running = vm.get("status") == "running"
        st = "up" if running else "degraded"
        mem_p = pct((vm.get("mem") or 0) / (vm.get("maxmem") or 1))
        cpu_p = pct(vm.get("cpu"))
        issues = []
        if not running:
            issues.append(issue("warn", "guest stopped"))
        if vm.get("status") == "running" and (vm.get("uptime") or 1) < 300:
            issues.append(issue("warn", "recently restarted"))
        for a in alerts:
            if a["host"] == name:
                lvl = "crit" if a["status"].upper() == "CRITICAL" else "warn"
                issues.append(issue(lvl, a["summary"][:90]))
        p = patch_by_host.get(name)
        if p and p.get("needs_reboot"):
            issues.append(issue("warn", "reboot required (patching)"))
        nodes.append({
            "id": f"vm:{vm.get('vmid')}", "layer": "vm", "name": name,
            "parent": f"pve:{vm.get('node')}", "status": st,
            "subtitle": f"VM {vm.get('vmid')} · {vm.get('node')}",
            "metrics": {"cpu": cpu_p, "mem": mem_p,
                        "disk": pct((vm.get("maxdisk") or 0) and (vm.get("disk") or 0) / (vm.get("maxdisk") or 1)),
                        "uptime": uptime_str(vm.get("uptime"))},
            "issues": issues,
            "extra": {"vmid": vm.get("vmid"), "node": vm.get("node"),
                      "type": vm.get("type"), "maxmem": vm.get("maxmem"),
                      "maxcpu": vm.get("maxcpu"), "updates": (p or {}).get("updates_count")},
        })

    # ---- docker layer ------------------------------------------------------
    ip_to_host: dict[str, str] = {}
    for h in ailog_hosts:
        ip_to_host[h["ip"]] = h["name"]
    for name, info in docker.items():
        if not info.get("containers"):
            continue  # no docker daemon on this host (hypervisor, NAS, laptop)
        parent = None
        for vm in pve_raw["vms"]:
            if vm.get("name") == name:
                parent = f"vm:{vm.get('vmid')}"
                break
        conts = info.get("containers", [])
        running = [c for c in conts if c["state"] == "running"]
        unhealthy = [c for c in conts if "unhealthy" in c["status"]]
        # exited containers are ignored on purpose: swapping a swarm task leaves
        # Exited (137) rows on every node and they are not an outage
        exited = [c for c in conts if c["state"] == "restarting"]
        if not info.get("reachable"):
            st = "down"
            issues = [issue("crit", "docker unreachable: " + (info.get("error") or "")[:60])]
        elif unhealthy or exited:
            st = "degraded"
            issues = [issue("warn", f"{c['name']} {c['status']}") for c in (unhealthy + exited)[:4]]
        else:
            st = "up"
            issues = []
        nodes.append({"id": f"docker:{name}", "layer": "docker", "name": name,
                      "parent": parent, "status": st,
                      "subtitle": f"{len(running)}/{len(conts)} containers running",
                      "metrics": {"containers": len(conts), "running": len(running),
                                  "unhealthy": len(unhealthy)},
                      "issues": issues,
                      "extra": {"host_ip": next((h["ip"] for h in ailog_hosts if h["name"] == name), ""),
                                "containers": conts}})

    # ---- swarm services ----------------------------------------------------
    for s in swarm.get("services", []):
        st = "up" if s["desired"] and s["running"] >= s["desired"] else (
            "down" if s["running"] == 0 else "degraded")
        issues = [] if st == "up" else [issue("crit" if st == "down" else "warn",
                                             f"replicas {s['replicas']}")]
        stack = s.get("stack") or s["name"].split("_")[0]
        image = (s.get("image") or "").split("@")[0]
        nodes.append({"id": f"svc:{s['name']}", "layer": "service", "name": s["name"],
                      "parent": "docker:swarm-manager", "status": st,
                      "subtitle": f"{s['replicas']} · {image.split('/')[-1]}",
                      "metrics": {"running": s["running"], "desired": s["desired"]},
                      "issues": issues,
                      "extra": {"image": image, "ports": s["ports"], "stack": stack}})

    # ---- apps --------------------------------------------------------------
    apps = probe_apps(cfg["apps"])
    for a in apps:
        host_ip = a.get("forward_host", "")
        parent = f"docker:{ip_to_host[host_ip]}" if host_ip in ip_to_host else None
        st = a["status"]
        issues = [] if st == "up" else [issue("crit", a.get("note", "unreachable"))]
        nodes.append({"id": f"app:{a['host']}", "layer": "app", "name": a["host"],
                      "parent": parent, "status": st,
                      "subtitle": a.get("group", "") + (f" · {a['latency_ms']}ms" if a.get("latency_ms") else ""),
                      "latency_ms": a.get("latency_ms"),
                      "metrics": {"code": a.get("code") or 0},
                      "issues": issues,
                      "extra": {"url": a["url"], "note": a.get("note"), "group": a.get("group"),
                                "forward": f"{host_ip}:{a.get('forward_port')}" if host_ip else ""}})

    snap = {
        "ts": ts,
        "generated_ms": int((time.time() - started) * 1000),
        "nodes": nodes,
        "sources": sources,
        "swarm": {"members": swarm.get("members", []),
                  "services": len(swarm.get("services", []))},
        "alerts": alerts,
        "patch": {k: {"updates": v.get("updates_count"), "security": v.get("security_updates_count"),
                      "reboot": v.get("needs_reboot"), "state": v.get("update_state"),
                      "last_update": v.get("last_update")}
                  for k, v in patch_by_host.items()},
        "ailog": {"hosts": ailog_hosts},
        "counts": {},
        "status": "up",
        "poll_seconds": int(os.environ.get("STATUS_POLL_SECONDS", "60")),
    }
    counts: dict[str, int] = {}
    for n in nodes:
        counts[n["status"]] = counts.get(n["status"], 0) + 1
    snap["counts"] = counts
    # an app being down is a degraded estate, not a platform outage: only the
    # hypervisor/vm/docker/service layers can make the whole page "down"
    core = [n["status"] for n in nodes if n["layer"] != "app"]
    apps_bad = any(n["status"] == "down" for n in nodes if n["layer"] == "app")
    snap["status"] = worst(core)
    if snap["status"] == "up" and apps_bad:
        snap["status"] = "degraded"
    log("snapshot: %s in %dms" % (counts, snap["generated_ms"]))
    return snap
