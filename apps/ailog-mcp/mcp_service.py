"""MCP server for the AIOps platform (AILog).

Exposes the fleet the way an agent needs it:

    list_hosts           which servers exist (config + DB hosts)
    list_log_sources     log files / journald units / containers on a host
    read_log             tail (or grep) a log file, incl. .gz rotation
    search_logs          grep across a host's logs, or one file
    read_journal         journalctl for a unit
    read_docker_logs     docker logs / docker service logs
    host_facts           OS, kernel, uptime, cpu, mem, disk, docker, services
    run_command          guarded read-only command execution ("interrogate the server")
    fleet_summary        overview counters (servers / active alerts)
    list_reports         AI server reports (verdict, severity)
    get_report           one report's findings

It runs in the AILog image, next to the web app: the SSH transport, host list and
key materialisation are imported from the app itself so there is exactly one
definition of "how we reach a host". Read-only JSON endpoints (overview, reports)
are fetched over HTTP from the sibling Flask process.

Auth: a bearer token (or x-api-key) must match AILOG_MCP_TOKEN. /healthz is open.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import time
from typing import Any

import httpx
from fastmcp import FastMCP

# ---------------------------------------------------------------------------
# ailog internals — same image, same DB, same SSH keys
# ---------------------------------------------------------------------------
import app as ailog  # noqa: E402  (import after env is set; creates the Flask app)

_app_ctx = ailog.app.app_context()
_app_ctx.push()

execute_command = ailog.execute_command
load_hosts = ailog.load_hosts
Host = ailog.Host
try:  # clears the scoped SQLAlchemy session before each call (see _session())
    db = ailog.db
except Exception:  # pragma: no cover
    db = None

AILOG_URL = os.environ.get("AILOG_URL", "http://127.0.0.1:5001").rstrip("/")
# The bearer token this endpoint demands. Read from the swarm secret first so
# the stack file (which is in git) carries a secret name instead of the value.
try:
    from utils.secretfiles import secret as _secret
    TOKEN = _secret("ailog_mcp_token", "AILOG_MCP_TOKEN")
except Exception:                                    # older image layout
    TOKEN = os.environ.get("AILOG_MCP_TOKEN", "")
LOG_DIR = os.environ.get("AILOG_LOG_DIR", "/var/log")
ALLOW_RAW = os.environ.get("AILOG_MCP_ALLOW_RAW", "0") == "1"
MAX_OUTPUT = int(os.environ.get("AILOG_MCP_MAX_OUTPUT", "200000"))  # chars

mcp = FastMCP("ailog")

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

# Read-only interrogation allow-list. Anything else needs AILOG_MCP_ALLOW_RAW=1.
_ALLOWED = {
    "ls", "cat", "grep", "zgrep", "tail", "head", "wc", "stat", "df", "du", "free",
    "uptime", "uname", "hostname", "hostnamectl", "nproc", "ps", "top", "who", "w",
    "last", "ss", "ip", "lscpu", "lsblk", "lsof", "systemctl", "journalctl",
    "docker", "zcat", "awk", "sed", "sort", "uniq", "cut", "tr", "uptime_",
}
_SUDO_ALLOWED = {
    "ls", "cat", "grep", "zgrep", "tail", "head", "wc", "stat", "du", "lsof",
    "systemctl", "journalctl", "docker", "zcat", "ss", "last",
}


def _check_command(cmd: str) -> None:
    if ALLOW_RAW:
        return
    # first word may be an env assignment or sudo
    tokens = cmd.strip().split()
    if not tokens:
        raise ValueError("empty command")
    first = tokens[0]
    if first in ("env", "time", "nice", "ionice"):
        tokens = tokens[1:]
        if not tokens:
            raise ValueError("empty command")
        first = tokens[0]
    if first == "sudo":
        rest = [t for t in tokens[1:] if not t.startswith("-")]
        # tolerate `sudo -n cmd ...`
        if len(tokens) > 1 and tokens[1].startswith("-"):
            rest = tokens[2:]
        if not rest or rest[0] not in _SUDO_ALLOWED:
            raise ValueError(
                f"sudo subcommand not allow-listed: {rest[0] if rest else '(none)'}. "
                "Set AILOG_MCP_ALLOW_RAW=1 to permit it."
            )
        return
    if first not in _ALLOWED:
        raise ValueError(
            f"command not allow-listed: {first!r} (read-only interrogation only). "
            "Set AILOG_MCP_ALLOW_RAW=1 to permit it."
        )
    for bad in (";", "&&", "||", "|", ">", "<", "`", "$("):
        if bad in cmd:
            raise ValueError(
                f"shell chaining/redirection {bad!r} is not allowed in a single command"
            )


def _trim(text: str) -> str:
    if len(text) <= MAX_OUTPUT:
        return text
    return text[:MAX_OUTPUT] + f"\n...[truncated {len(text) - MAX_OUTPUT} chars]"


def _session() -> None:
    """Drop the scoped SQLAlchemy session.

    This process is long-lived; a session opened hours ago can still be holding
    a WAL snapshot from before the app wrote a row. Removing it forces the next
    query onto a fresh connection, which is what stopped `unknown host` errors
    appearing after ~20h of uptime.
    """
    try:
        if db is not None:
            db.session.remove()
    except Exception:
        pass


def _hosts_from_api() -> dict[str, dict]:
    """The app's own /hosts endpoint.

    Preferred over querying SQLite directly: this process is long-lived, and a
    stale SQLAlchemy view of the WAL-mode db on NFS silently returns no rows
    after a checkpoint (observed after ~20h uptime), which made every host
    "unknown" until the container was restarted.
    """
    out: dict[str, dict] = {}
    try:
        data = httpx.get(f"{AILOG_URL}/hosts", timeout=10).json()
        for key, val in (data or {}).items():
            out[key] = {
                "key": key,
                "name": val.get("friendly_name") or val.get("name") or key,
                "ip": val.get("ip"),
                "user": val.get("user") or "root",
                "description": val.get("description"),
                "source": "db",
                "groups": val.get("group_names") or [],
            }
    except Exception:
        pass
    return out


def _hosts_merged() -> dict[str, dict]:
    """Config hosts (hosts.json) + wizard/DB hosts, keyed by the id callers pass."""
    _session()
    hosts: dict[str, dict] = _hosts_from_api()
    try:
        for key, val in (load_hosts() or {}).items():
            hosts[key] = {
                "key": key,
                "name": val.get("friendly_name") or val.get("name") or key,
                "ip": val.get("ip"),
                "user": val.get("user") or "root",
                "description": val.get("description"),
                "source": "config",
            }
    except Exception:
        pass
    try:
        for h in Host.query.all():
            key = f"db-{h.id}"
            hosts.setdefault(key, {
                "key": key,
                "name": h.friendly_name or h.hostname or h.ip_address,
                "ip": h.ip_address,
                "user": h.ssh_user or "root",
                "description": h.description,
                "source": "db",
                "groups": [g.name for g in (h.groups or [])],
            })
    except Exception:
        pass
    return hosts


def _resolve(host: str) -> dict:
    if host in ("local", "localhost"):
        # the AILog container itself (no sudo inside it, so /var/log is limited)
        return {"key": "local", "name": "Localhost", "ip": "127.0.0.1",
                "user": "local", "source": "builtin"}
    hosts = _hosts_merged()
    if host not in hosts:
        raise ValueError(
            f"unknown host {host!r}; call list_hosts() for valid keys "
            f"(e.g. {', '.join(list(hosts)[:5])})"
        )
    return hosts[host]


def _run(host: str, cmd: str, timeout: int = 20) -> dict:
    """Execute on a host. Callers own the command they build; user input goes
    through run_command(), which applies the allow-list first."""
    started = time.time()
    _session()
    try:
        res = execute_command(host, cmd, timeout=timeout)
        out = res.stdout or ""
        err = getattr(res, "stderr", "") or ""
        rc = getattr(res, "returncode", None)
    except Exception as exc:  # connection refused, timeout, host key, ...
        return {"host": host, "command": cmd, "ok": False, "error": str(exc)}
    return {
        "host": host,
        "command": cmd,
        "ok": rc == 0,
        "returncode": rc,
        "duration_ms": int((time.time() - started) * 1000),
        "output": _trim(out),
        "stderr": _trim(err) if err else "",
    }


async def _json(path: str, params: dict | None = None) -> Any:
    async with httpx.AsyncClient(timeout=60.0, base_url=AILOG_URL) as c:
        r = await c.get(path, params=params)
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# tools — inventory
# ---------------------------------------------------------------------------

@mcp.tool
def list_hosts(include_status: bool = False) -> dict:
    """List the servers AILog knows about.

    Args:
        include_status: also return the fleet overview counters (servers, active alerts).
    """
    hosts = sorted(_hosts_merged().values(), key=lambda h: h["name"].lower())
    out: dict[str, Any] = {"count": len(hosts), "hosts": hosts}
    if include_status:
        try:
            out["fleet"] = httpx.get(f"{AILOG_URL}/api/overview/summary", timeout=30).json()
        except Exception as exc:
            out["fleet_error"] = str(exc)
    return out


@mcp.tool
def fleet_summary() -> dict:
    """Fleet counters (server count, active alerts) from the AILog overview API."""
    try:
        return httpx.get(f"{AILOG_URL}/api/overview/summary", timeout=30).json()
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# tools — log discovery
# ---------------------------------------------------------------------------

@mcp.tool
def list_containers(host: str, all: bool = True) -> dict:
    """Containers on a host, straight from the app's docker API.

    Uses HTTP rather than `docker ps` over SSH so it keeps working on nodes
    that cannot read the SQLite host table (see _session) and so callers get
    structured rows instead of parsing a format string.

    host: a host key from list_hosts() (e.g. "db-11")
    """
    h = _resolve(host)
    try:
        data = httpx.get(f"{AILOG_URL}/api/docker/hosts/{h['key']}/containers",
                         params={"all": "1" if all else "0"}, timeout=60).json()
    except Exception as e:  # noqa: BLE001
        return {"host": h["name"], "error": str(e)[:200], "containers": []}
    rows = []
    for c in data.get("containers") or []:
        rows.append({
            "name": c.get("name"),
            "state": c.get("state"),
            "status": c.get("status"),
            "image": c.get("image_name") or c.get("image"),
            "id": (c.get("id") or "")[:12],
            "cpu_percent": c.get("cpu_percent"),
            "mem_percent": c.get("mem_percent"),
        })
    return {"host": h["name"], "count": len(rows), "containers": rows}


@mcp.tool
def list_swarm_services(manager: str = "swarm-manager") -> dict:
    """Swarm services with running/desired replica counts.

    Backed by the app's /api/docker/hosts/<key>/swarm rollup. Desired replicas
    come from the highest task slot number seen for the service (docker names
    tasks <stack>_<service>.<slot>.<id>), which survives old exited tasks.
    """
    h = _resolve(manager)
    try:
        data = httpx.get(f"{AILOG_URL}/api/docker/hosts/{h['key']}/swarm", timeout=90).json()
    except Exception as e:  # noqa: BLE001
        return {"manager": h["name"], "error": str(e)[:200], "services": []}
    out = []
    for app in data.get("apps") or []:
        for svc in app.get("services") or []:
            names = [c.get("name") or "" for c in (svc.get("containers") or [])]
            slots = [int(n.split(".")[1]) for n in names
                     if n.count(".") >= 2 and n.split(".")[1].isdigit()]
            image = next((c.get("image") or c.get("image_name") for c in (svc.get("containers") or [])
                          if c.get("state") == "running"), None)
            running = int(svc.get("running_count") or 0)
            out.append({
                "name": svc.get("name"),
                "stack": app.get("name"),
                "running": running,
                "desired": max(slots) if slots else running,
                "image": image or "",
                "tasks": len(names),
            })
    out.sort(key=lambda x: x["name"] or "")
    return {"manager": h["name"], "count": len(out), "services": out}


@mcp.tool
def list_log_sources(host: str, include_docker: bool = True,
                     include_journal: bool = False, limit: int = 60) -> dict:
    """List what can be read on a host: files in /var/log, docker containers, journald units.

    Args:
        host: host key from list_hosts() ("local" for the AILog container itself).
        include_docker: include docker containers (readable via read_docker_logs).
        include_journal: include journald units (readable via read_journal).
        limit: cap the number of returned entries per category.
    """
    _resolve(host)
    files: list[dict] = []
    res = _run(host, f"sudo ls -p {shlex.quote(LOG_DIR)}", timeout=15)
    if res.get("ok"):
        names = [n for n in res["output"].splitlines() if n and not n.endswith("/")]
        # one stat call for the whole set keeps this to 2 round-trips
        if names:
            quoted = " ".join(shlex.quote(os.path.join(LOG_DIR, n)) for n in names[:limit])
            st = _run(host, f"sudo stat -c '%n|%s|%Y' {quoted}", timeout=25)
            for line in (st.get("output") or "").splitlines():
                parts = line.rsplit("|", 2)
                if len(parts) != 3:
                    continue
                path, size, mtime = parts
                files.append({
                    "name": os.path.basename(path),
                    "size_bytes": int(size) if size.isdigit() else None,
                    "modified": int(mtime) if mtime.isdigit() else None,
                    "compressed": path.endswith(".gz"),
                })
    out: dict[str, Any] = {"host": host, "files": files[:limit], "files_error": None if res.get("ok") else res.get("error") or res.get("stderr")}

    if include_journal:
        units: list[str] = []
        jr = _run(host, "sudo journalctl --field _SYSTEMD_UNIT 2>/dev/null | sort -u | head -40", timeout=20)
        if jr.get("ok"):
            units = [u for u in jr["output"].splitlines() if u]
        out["journal_units"] = units

    if include_docker:
        containers: list[dict] = []
        dr = _run(host, "docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>/dev/null", timeout=20)
        if dr.get("ok"):
            for line in dr["output"].splitlines():
                parts = line.split("|")
                if len(parts) == 3:
                    containers.append({"name": parts[0], "image": parts[1], "status": parts[2]})
        out["containers"] = containers

    return out


# ---------------------------------------------------------------------------
# tools — reading logs
# ---------------------------------------------------------------------------

@mcp.tool
def read_log(host: str, filename: str, lines: int = 200,
             pattern: str | None = None, case_sensitive: bool = False) -> dict:
    """Read a log file on a host.

    Args:
        host: host key from list_hosts().
        filename: file name inside /var/log (e.g. "syslog", "auth.log.2.gz") or an absolute path.
        lines: how many trailing lines to return (1-2000).
        pattern: optional grep pattern; returns matching lines instead of a plain tail.
        case_sensitive: grep case sensitivity (ignored without pattern).
    """
    _resolve(host)
    lines = max(1, min(int(lines), 2000))
    path = filename if filename.startswith("/") else os.path.join(LOG_DIR, filename)
    if not re.fullmatch(r"[\w./@+-]+", path):
        raise ValueError("unsafe log path")
    q = shlex.quote(path)
    compressed = path.endswith(".gz")
    if pattern:
        flags = "" if case_sensitive else "-i"
        reader = f"sudo zcat {q} 2>/dev/null" if compressed else f"sudo cat {q}"
        cmd = f"{reader} | grep {flags} -n {shlex.quote(pattern)} | tail -n {lines}"
    else:
        cmd = (f"sudo zcat {q} 2>/dev/null | tail -n {lines}" if compressed
               else f"sudo tail -n {lines} {q}")
    res = _run(host, cmd, timeout=30)
    res["path"] = path
    res["lines"] = len((res.get("output") or "").splitlines())
    return res


@mcp.tool
def search_logs(host: str, pattern: str, filename: str | None = None,
                max_matches: int = 100, case_sensitive: bool = False) -> dict:
    """Grep a host's logs for a pattern.

    Args:
        host: host key from list_hosts().
        pattern: grep pattern (extended regex, use egrep semantics).
        filename: restrict to one file in /var/log; omit to search all readable logs there.
        max_matches: stop after this many matching lines.
        case_sensitive: disable -i.
    """
    _resolve(host)
    max_matches = max(1, min(int(max_matches), 500))
    flags = "" if case_sensitive else "-i"
    if filename:
        path = filename if filename.startswith("/") else os.path.join(LOG_DIR, filename)
        if not re.fullmatch(r"[\w./@+-]+", path):
            raise ValueError("unsafe log path")
        target = shlex.quote(path)
    else:
        target = f"{shlex.quote(LOG_DIR)}/*"
    cmd = (f"sudo grep {flags} -H -n -I -E {shlex.quote(pattern)} {target} 2>/dev/null "
           f"| head -n {max_matches}")
    res = _run(host, cmd, timeout=45)
    matches = []
    for line in (res.get("output") or "").splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3:
            matches.append({"file": os.path.basename(parts[0]), "line": parts[1], "text": parts[2]})
        elif len(parts) == 2:
            matches.append({"file": os.path.basename(filename or ""), "line": parts[0], "text": parts[1]})
    return {"host": host, "pattern": pattern, "count": len(matches), "matches": matches,
            "ok": res.get("ok"), "error": res.get("error")}


@mcp.tool
def read_journal(host: str, unit: str, lines: int = 200, since: str | None = None) -> dict:
    """Read systemd journal entries for a unit.

    Args:
        host: host key from list_hosts().
        unit: systemd unit name, e.g. "ssh.service" or "docker".
        lines: trailing line count (1-2000).
        since: optional journalctl --since value, e.g. "2 hours ago" or "2026-11-01 10:00".
    """
    _resolve(host)
    lines = max(1, min(int(lines), 2000))
    cmd = f"sudo journalctl -u {shlex.quote(unit)} -n {lines} --no-pager"
    if since:
        cmd += f" --since {shlex.quote(since)}"
    return _run(host, cmd, timeout=30)


@mcp.tool
def read_docker_logs(host: str, container: str, lines: int = 200) -> dict:
    """Read docker logs for a container (uses `docker service logs` when the container is a swarm task).

    Args:
        host: host key from list_hosts().
        container: container name or id (exact match as shown by docker ps).
        lines: trailing line count (1-2000).
    """
    _resolve(host)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", container):
        raise ValueError("invalid container identifier")
    lines = max(1, min(int(lines), 2000))
    q = shlex.quote(container)
    label = "'{{index .Config.Labels \"com.docker.swarm.service.name\"}}'"
    cmd = ("if sudo -n docker version >/dev/null 2>&1; then D=\"sudo -n docker\"; "
           "else D=\"docker\"; fi; "
           f"SVC=$($D inspect -f {label} {q} 2>/dev/null); "
           f"if [ -n \"$SVC\" ] && $D service logs --tail {lines} --timestamps \"$SVC\" 2>&1; "
           f"then exit 0; fi; $D logs --tail {lines} --timestamps {q} 2>&1")
    return _run(host, cmd, timeout=40)


# ---------------------------------------------------------------------------
# tools — interrogating the server
# ---------------------------------------------------------------------------

@mcp.tool
def host_facts(host: str) -> dict:
    """Server facts: kernel/OS, uptime, cpu, memory, disk, docker, failed units, listening ports."""
    _resolve(host)
    probes = {
        "identity": "hostname; uname -srm; cat /etc/os-release 2>/dev/null | head -4",
        "uptime": "uptime; nproc",
        "memory": "free -m",
        "disk": "df -h / /var /opt 2>/dev/null",
        "failed_units": "systemctl list-units --state=failed --no-legend --no-pager 2>/dev/null | head -20",
        "docker": "docker ps -q 2>/dev/null | wc -l; docker version --format '{{.Server.Version}}' 2>/dev/null",
    }
    out: dict[str, Any] = {"host": host}
    for name, cmd in probes.items():
        res = _run(host, cmd, timeout=20)
        out[name] = res.get("output", "").strip() if res.get("ok") else (res.get("error") or res.get("stderr"))
    return out


@mcp.tool
def run_command(host: str, command: str, timeout: int = 30) -> dict:
    """Run a read-only command on a host (allow-listed tools: ls, cat, grep, tail, journalctl,
    systemctl status, docker ps/logs/inspect, df, free, ps, ss, ...).

    Use this to interrogate a server when the log-specific tools are not enough.
    Chain operators (; && || > < $()) are rejected. Set AILOG_MCP_ALLOW_RAW=1 on the
    service to lift the allow-list.

    Args:
        host: host key from list_hosts().
        command: the command line to run.
        timeout: seconds (5-120).
    """
    _resolve(host)
    timeout = max(5, min(int(timeout), 120))
    try:
        _check_command(command)
        return _run(host, command, timeout=timeout)
    except ValueError as exc:
        return {"host": host, "command": command, "ok": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# tools — AI reports
# ---------------------------------------------------------------------------

@mcp.tool
def list_reports(limit: int = 10, host: str | None = None) -> dict:
    """List AI server reports (newest first) with host, window, verdict and severity counts.

    Args:
        limit: number of reports (1-50).
        host: optional host key to filter by.
    """
    limit = max(1, min(int(limit), 50))
    try:
        data = httpx.get(f"{AILOG_URL}/api/reports", params={"limit": limit}, timeout=60).json()
    except Exception as exc:
        return {"error": str(exc)}
    rows = []
    for r in data.get("reports", [])[:limit]:
        if host and r.get("host_key") != host:
            continue
        rows.append({
            "id": r.get("id"), "host": r.get("host_label"), "host_key": r.get("host_key"),
            "verdict": r.get("verdict"), "severity": r.get("severity"),
            "events_total": r.get("events_total"), "clusters_total": r.get("clusters_total"),
            "window_start": r.get("window_start"), "window_minutes": r.get("window_minutes"),
            "created_at": r.get("created_at"), "error": r.get("error"),
        })
    return {"count": len(rows), "reports": rows}


@mcp.tool
def get_report(report_id: int, include_timeline: bool = False) -> dict:
    """Get one AI server report: verdict, severity, correlations and top clusters.

    Args:
        report_id: id from list_reports().
        include_timeline: also return the per-source timeline (can be large).
    """
    try:
        r = httpx.get(f"{AILOG_URL}/api/reports/{int(report_id)}", timeout=60).json()
    except Exception as exc:
        return {"error": str(exc)}
    rep = r.get("report", r) if isinstance(r, dict) else {}
    out = {
        "id": rep.get("id"), "host": rep.get("host_label"), "verdict": rep.get("verdict"),
        "severity": rep.get("severity"), "window_start": rep.get("window_start"),
        "window_end": rep.get("window_end"), "window_minutes": rep.get("window_minutes"),
        "events_total": rep.get("events_total"), "sources_ok": rep.get("sources_ok"),
        "sources_failed": rep.get("sources_failed"),
        "correlations": (rep.get("correlations") or [])[:10],
        "clusters": (rep.get("clusters") or [])[:10],
        "coverage": rep.get("coverage"),
    }
    if include_timeline:
        out["timeline"] = rep.get("timeline")
    return out


# ---------------------------------------------------------------------------
# ASGI plumbing: bearer-token gate + /healthz
# ---------------------------------------------------------------------------

class TokenAuth:
    """Minimal ASGI middleware: requires the shared secret on every request."""

    def __init__(self, app, token: str):
        self.app = app
        self.token = token

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        if path == "/healthz":
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": b'{"ok":true}'})
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        supplied = headers.get("authorization", "")
        if supplied.lower().startswith("bearer "):
            supplied = supplied[7:]
        supplied = supplied or headers.get("x-api-key", "")
        if not self.token or supplied != self.token:
            await send({"type": "http.response.start", "status": 401,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body",
                        "body": b'{"error":"unauthorized"}'})
            return
        return await self.app(scope, receive, send)


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("AILOG_MCP_PORT", "5002"))
    host = os.environ.get("AILOG_MCP_BIND", "0.0.0.0")
    if not TOKEN:
        print("WARNING: AILOG_MCP_TOKEN is empty - the endpoint is unauthenticated", flush=True)
    asgi = mcp.http_app(path="/mcp")
    uvicorn.run(TokenAuth(asgi, TOKEN), host=host, port=port, log_level="info")
