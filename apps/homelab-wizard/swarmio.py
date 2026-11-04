"""swarmio: ssh to the cluster, the port registry, image pulls, probes."""
import os
import re
import shlex
import subprocess
import threading
import time

import core

KEY = os.environ.get("WIZ_SSH_KEY", "/data/ssh/id_ed25519")
USER = os.environ.get("WIZ_SSH_USER", "david")


class SwarmError(RuntimeError):
    pass


def _ssh(host):
    return ["ssh", "-i", KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR", f"{USER}@{host}"]


def run(host, command, timeout=120):
    if not os.path.exists(KEY):
        raise SwarmError(f"no ssh key at {KEY} - mount it under /data/ssh")
    proc = subprocess.run(_ssh(host) + [command], capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise SwarmError(f"{host}: {(proc.stderr or proc.stdout).strip()[:300]}")
    return proc.stdout


def stream(host, command, timeout=1800):
    proc = subprocess.Popen(_ssh(host) + [command], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1)
    try:
        for line in proc.stdout:
            yield line.rstrip("\n")
    finally:
        proc.wait(timeout=timeout)
        if proc.returncode != 0:
            raise SwarmError(f"{host}: command failed (rc={proc.returncode})")


# ---------------------------------------------------------------- registry

def published_ports(settings):
    out = run(settings["manager"], "docker service ls --format '{{.Name}}\t{{.Ports}}'", timeout=30)
    rows = {}
    for line in out.splitlines():
        if "\t" not in line:
            continue
        name, ports = line.split("\t", 1)
        for m in re.finditer(r"\*?:(\d+)->(\d+)/tcp", ports):
            rows.setdefault(int(m.group(1)), []).append(name)
    return rows


def listening_ports(settings, node):
    try:
        out = run(node, "ss -tlnH | awk '{print $4}' | sed 's/.*://' | sort -un", timeout=30)
    except Exception:
        return {}
    return {int(p): [f"{node} (host)"] for p in out.split() if p.isdigit()}


def npm_ports(settings):
    script = (
        "sudo python3 - <<'PY'\n"
        "import sqlite3, json\n"
        f"db=sqlite3.connect('{settings['npm_db']}')\n"
        "for d,p in db.execute('select domain_names, forward_port from proxy_host where enabled=1'):\n"
        "    try: doms=json.loads(d)\n"
        "    except Exception: doms=[d]\n"
        "    print(p, ','.join(doms))\n"
        "PY")
    try:
        out = run(settings["casaos_ip"], script, timeout=60)
    except Exception:
        return {}
    rows = {}
    for line in out.splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[0].isdigit():
            rows.setdefault(int(parts[0]), []).extend(parts[1].split(","))
    return rows


def _parallel(fn, items, workers=5):
    out, lock = {}, threading.Lock()

    def wrap(item):
        try:
            res = fn(item)
        except Exception:
            return
        with lock:
            out.update(res)

    threads = [threading.Thread(target=wrap, args=(i,)) for i in items]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=45)
    return out


def registry(settings, wizard):
    """Every port in use, from four independent sources."""
    declared = {}
    for svc in wizard.get("services") or []:
        for p in svc.get("ports") or []:
            if p.get("host"):
                declared.setdefault(int(p["host"]), []).append(f"{svc['name']} (wizard.yaml)")
    warnings = []
    try:
        published = published_ports(settings)
    except Exception as exc:
        published = {}
        warnings.append(f"swarm: {str(exc)[:120]}")
    listen = _parallel(lambda n: listening_ports(settings, n), settings["nodes"])
    if not listen:
        warnings.append("no node answered over ssh (is the key mounted?)")
    try:
        npm = npm_ports(settings)
    except Exception as exc:
        npm = {}
        warnings.append(f"npm: {str(exc)[:120]}")

    ports = {}
    for src in (declared, published, listen, npm):
        for port, owners in src.items():
            row = ports.setdefault(int(port), {"port": int(port), "owners": [], "sources": []})
            for o in owners:
                if o not in row["owners"]:
                    row["owners"].append(o)
            if src is declared:
                row["sources"].append("declared")
            elif src is published:
                row["sources"].append("swarm")
            elif src is listen:
                row["sources"].append("listen")
            else:
                row["sources"].append("npm")

    for port, why in (wizard.get("reserved_ports") or {}).items():
        row = ports.setdefault(int(port), {"port": int(port), "owners": [], "sources": []})
        row["owners"].append(f"reserved: {why}")
        row["sources"].append("reserved")

    band = (wizard.get("defaults") or {}).get("port_bands") or {}
    ordered = sorted(ports.values(), key=lambda r: r["port"])
    for r in ordered:
        r["band"] = next((k for k, (lo, hi) in band.items() if lo <= r["port"] <= hi), "")

    used = {r["port"] for r in ordered}
    lo, hi = (band.get("web") or [8000, 8199])
    # suggest free ports nearest the middle of what is already in the band, so a
    # new app lands next to its neighbours instead of in a hole left by a
    # retired service (8089) or beside an outlier (8199 = langlearn)
    in_band = sorted(p for p in used if int(lo) <= p <= int(hi))
    mid = in_band[len(in_band) // 2] if in_band else int(lo)
    free = [p for p in range(int(lo), int(hi) + 1) if p not in used]
    suggestions = sorted(sorted(free, key=lambda p: (abs(p - mid), p))[:12])

    return {"ports": ordered, "suggestions": suggestions, "bands": band, "warnings": warnings,
            "sources": {"swarm": len(published), "listen": sum(len(v) for v in listen.values()),
                        "npm": len(npm), "declared": len(declared)}}


# ---------------------------------------------------------------- lifecycle

def service_ps(settings, stack):
    out = run(settings["manager"], f"docker stack ps {shlex.quote(stack)} --no-trunc "
              "--format '{{.Name}}\t{{.Node}}\t{{.CurrentState}}\t{{.Error}}'", timeout=30)
    rows = []
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) >= 3:
            rows.append({"task": p[0], "node": p[1], "state": p[2], "error": p[3] if len(p) > 3 else ""})
    return rows


def service_replicas(settings, stack):
    out = run(settings["manager"], f"docker stack services {shlex.quote(stack)} "
              "--format '{{.Name}}\t{{.Replicas}}\t{{.Image}}\t{{.Ports}}'", timeout=30)
    rows = []
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) >= 2:
            rows.append({"service": p[0], "replicas": p[1],
                         "image": p[2] if len(p) > 2 else "", "ports": p[3] if len(p) > 3 else ""})
    return rows


def curl_check(url, timeout=20):
    try:
        out = subprocess.run(["curl", "-sS", "-o", "/dev/null", "-w",
                              "%{http_code} %{time_total} %{ssl_verify_result}",
                              "-m", str(timeout), url], capture_output=True, text=True,
                             timeout=timeout + 5)
        code, total, sslv = (out.stdout.strip().split() + ["", "", ""])[:3]
        return {"url": url, "http": int(code or 0), "seconds": float(total or 0),
                "tls_ok": sslv in ("", "0")}
    except Exception as exc:
        return {"url": url, "http": 0, "seconds": 0, "tls_ok": False, "error": str(exc)[:200]}


# ---------------------------------------------------------------- image pull

_LAYER = re.compile(r"^([0-9a-f]{12}): ")
_PCT = re.compile(r"(\d+(?:\.\d+)?)%")


def pull(settings, image, host=None, on_line=None, on_progress=None):
    """docker pull over ssh, parsed into per-layer progress.

    Non-tty output is line oriented: 'Pulling fs layer', 'Downloading [==> ] 41%
    12MB/29MB', 'Extracting', 'Pull complete'. That is enough to drive a real
    progress bar without a pty and without guessing from timings.
    """
    host = host or settings["manager"]
    started = time.time()
    layers, digest = {}, ""
    for line in stream(host, f"DOCKER_CLI_HINTS=false docker pull {shlex.quote(image)}"):
        if on_line:
            on_line(line)
        m = _LAYER.match(line.strip())
        if m:
            layer = layers.setdefault(m.group(1), {"state": "pulling", "pct": 0.0})
            body = line.split(": ", 1)[1]
            if "Pull complete" in body or "Already exists" in body:
                layer.update(state="done", pct=100.0)
            elif "Retrying" in body or "error" in body.lower():
                layer["state"] = "error"
            else:
                pct = _PCT.search(body)
                if pct:
                    layer["pct"] = float(pct.group(1))
            if on_progress:
                on_progress({"layers": len(layers),
                             "done": sum(1 for l in layers.values() if l["state"] == "done"),
                             "percent": round(sum(l["pct"] for l in layers.values()) / max(1, len(layers)), 1),
                             "state": "pulling"})
        elif line.startswith("Digest:"):
            digest = line.split(":", 1)[1].strip()
        elif "not found" in line or "unauthorized" in line or "denied" in line:
            raise SwarmError(line.strip()[:300])
    if on_progress:
        on_progress({"layers": len(layers), "done": len(layers), "percent": 100.0, "state": "done"})
    return {"ok": True, "digest": digest, "layers": len(layers),
            "seconds": round(time.time() - started, 1), "host": host}
