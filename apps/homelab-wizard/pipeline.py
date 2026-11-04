"""pipeline: wizard.yaml edits, the build/ship chain, pulls and tests."""
import json
import os
import re
import shutil
import time

import core
import forge
import swarmio

BUILD_WF = "build.yml"
SHIP_WF = "ship.yml"


# ------------------------------------------------------------------ wizard

def load_wizard():
    return core.read_yaml("wizard.yaml")


def wizard_services():
    return load_wizard().get("services") or []


def find_service(name):
    return next((s for s in wizard_services() if s.get("name") == name), None)


def summarise(svc):
    return {"name": svc.get("name"), "kind": svc.get("kind"),
            "service": svc.get("service") or svc.get("name"),
            "repo": svc.get("repo"), "image": svc.get("image"),
            "version": svc.get("version"), "source": svc.get("source"),
            "url": svc.get("url"), "ports": svc.get("ports") or [],
            "replicas": svc.get("replicas"),
            "env_count": len(svc.get("env") or {}),
            "companions": svc.get("companions") or []}


def _render_service(entry):
    """Write stacks/<name>/stack.yml and, for mirrors, the mirror list entry."""
    registry = (load_wizard().get("defaults") or {}).get("registry", "zot.safehomelan.com")
    path = f"stacks/{entry['name']}/stack.yml"
    existing = core.read_yaml(path) or None
    core.write_text(path, core.render_stack(entry, existing, registry))
    files = [path]

    mirror = core.mirror_entry(entry)
    if mirror:
        mirrors = core.read_yaml("mirror-images.json") or {"mirrors": []}
        mirrors.setdefault("mirrors", [])
        for i, m in enumerate(mirrors["mirrors"]):
            if m.get("name") == mirror["name"]:
                mirrors["mirrors"][i] = mirror
                break
        else:
            mirrors["mirrors"].append(mirror)
        core.write_text("mirror-images.json", json.dumps(mirrors, indent=2) + "\n")
        files.append("mirror-images.json")
    return files


def save_service(entry):
    problems = core.validate(entry)
    if problems:
        return {"ok": False, "problems": problems, "files": []}
    wiz = load_wizard()
    services = wiz.setdefault("services", [])
    for i, svc in enumerate(services):
        if svc.get("name") == entry["name"]:
            entry = services[i] = {**svc, **entry}
            break
    else:
        services.append(entry)

    header = ""
    yaml_path = os.path.join(core.repo_dir(), "wizard.yaml")
    if os.path.exists(yaml_path):
        header = open(yaml_path).read().split("\nversion:", 1)[0] + "\n"
    core.write_yaml("wizard.yaml", wiz, header)
    return {"ok": True, "problems": [], "files": sorted(set(["wizard.yaml"] + _render_service(entry))),
            "entry": entry}


def delete_service(name):
    wiz = load_wizard()
    before = len(wiz.get("services") or [])
    wiz["services"] = [s for s in (wiz.get("services") or []) if s.get("name") != name]
    if len(wiz["services"]) == before:
        return {"ok": False, "problems": [f"{name} is not in wizard.yaml"]}
    core.write_yaml("wizard.yaml", wiz)
    files = ["wizard.yaml", f"stacks/{name}"]
    full = os.path.join(core.repo_dir(), "stacks", name)
    if os.path.isdir(full):
        shutil.rmtree(full)
    mirrors = core.read_yaml("mirror-images.json") or {}
    entries = mirrors.get("mirrors") or []
    kept = [m for m in entries if m.get("name") != name]
    if len(kept) != len(entries):
        mirrors["mirrors"] = kept
        core.write_text("mirror-images.json", json.dumps(mirrors, indent=2) + "\n")
        files.append("mirror-images.json")
    return {"ok": True, "files": files}


# ------------------------------------------------------------------ run logs

def _tail_run(job, gh, run_id, label=""):
    """Follow a run's job logs, emitting only what is new."""
    offsets, seen = {}, set()
    deadline = time.time() + 1800
    while time.time() < deadline:
        for wjob in gh.jobs(run_id):
            jid = wjob.get("id")
            text = gh.job_log(jid) or ""
            prev = offsets.get(jid, 0)
            if len(text) > prev:
                for line in text[prev:].splitlines():
                    if line.strip():
                        job.log(line)
                offsets[jid] = len(text)
            key = (jid, wjob.get("status"))
            if key not in seen:
                seen.add(key)
                job.step(f"{label}{wjob.get('name') or 'job'}", wjob.get("status") or "running")
        run = gh.run(run_id)
        job.tick(run=run_id, workflow=run.get("status"))
        if run.get("status") == "completed" or run.get("conclusion"):
            break
        time.sleep(2)
    conclusion = (gh.run(run_id).get("conclusion") or "").lower()
    if conclusion not in ("success", ""):
        raise RuntimeError(f"run {run_id} {conclusion}\n" + "\n".join(job.lines[-15:]))
    return conclusion


def _wait_run(job, gh, workflow, sha=None, after=0, timeout=180):
    job.step(f"waiting for {workflow}", "running")
    deadline = time.time() + timeout
    while time.time() < deadline:
        run = gh.find_run(workflow, sha=sha, newer_than=after, timeout=1)
        if run:
            job.log(f"{workflow}: run {run['id']} for {str(run.get('head_sha'))[:8]}")
            return run
        time.sleep(3)
    raise RuntimeError(f"{workflow} did not start in {timeout}s - is the runner online?")


# ------------------------------------------------------------------ build/ship

def build(job, message=None):
    settings = core.load()
    core.ensure(settings)
    gh = forge.Gitea(settings)
    job.step("commit", "running")
    res = core.commit_and_push(message or "wizard: update services")
    if not res.get("committed"):
        job.log("no local changes - building the branch head")
        res["sha"] = core._git(core.repo_dir(), "rev-parse", "HEAD").strip()
    job.step("commit", "ok", (res.get("sha") or "")[:8])
    run = _wait_run(job, gh, BUILD_WF, sha=res["sha"])
    job.step(BUILD_WF, "running")
    _tail_run(job, gh, run["id"], "build: ")
    job.step(BUILD_WF, "ok")
    return {"run": run["id"], "sha": res["sha"], "branch": res.get("branch")}


def ship(job, title=None):
    settings = core.load()
    gh = forge.Gitea(settings)
    branch = settings.get("work_branch", "dev")
    before = max([r.get("id", 0) for r in gh.runs(limit=10)] or [0])

    job.step("pull request", "running")
    pr = gh.create_pr(title or "homelab: wizard change", head=branch, base="main",
                      body="Opened by homelab-wizard after a green smoke build.")
    job.log(f"PR #{pr['number']}: {pr.get('html_url', '')}")
    job.step("pull request", "ok", f"#{pr['number']}")
    job.step("merge", "running")
    gh.merge_pr(pr["number"])
    job.step("merge", "ok")

    run = _wait_run(job, gh, SHIP_WF, after=before)
    job.step(SHIP_WF, "running")
    _tail_run(job, gh, run["id"], "ship: ")
    job.step(SHIP_WF, "ok")
    return {"pr": pr["number"], "run": run["id"]}


def pull_image(job, image, node=None):
    settings = core.load()
    job.step("pull", "running", image)
    res = swarmio.pull(settings, image, node, on_line=job.log, on_progress=lambda p: job.tick(**p))
    job.step("pull", "ok", f"{res['layers']} layers in {res['seconds']}s")
    job.log(f"digest {res.get('digest') or 'n/a'}")
    return res


# ------------------------------------------------------------------ tests

def _dig(domain):
    import subprocess
    try:
        return subprocess.run(["python3", "-c",
                               f"import socket;print(socket.gethostbyname('{domain}'))"],
                              capture_output=True, text=True, timeout=10).stdout.strip() or "unresolved"
    except Exception as exc:
        return f"unresolved ({exc})"


def test_stack(job, stack, domain=None, port=None, creds=None):
    settings = core.load()
    checks = []

    def add(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": str(detail)[:300]})
        job.log(("PASS " if ok else "FAIL ") + name + (f" - {detail}" if detail else ""))
        job.step(name, "ok" if ok else "failed", str(detail)[:80])

    replicas = swarmio.service_replicas(settings, stack)
    running = desired = 0
    for r in replicas:
        try:
            run, want = r["replicas"].split("/")
            running += int(run)
            desired += int(want)
        except Exception:
            pass
    add("replicas", desired > 0 and running == desired,
        f"{running}/{desired} over {len(replicas)} service(s)")

    if port:
        res = swarmio.curl_check(f"http://{settings['ingress_ip']}:{port}/")
        add(f"ingress :{port}", 0 < res.get("http", 0) < 500, f"HTTP {res.get('http')} {res.get('seconds')}s")

    if domain:
        ip = _dig(domain)
        add(f"dns {domain}", bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", ip or "")), ip)
        res = swarmio.curl_check(f"https://{domain}/")
        add(f"https://{domain}", 0 < res.get("http", 0) < 500,
            f"HTTP {res.get('http')} in {res.get('seconds')}s")
        add("tls", res.get("tls_ok", False), "certificate verified")

    if creds and creds.get("username"):
        import httpx
        target = f"https://{domain}/" if domain else f"http://{settings['ingress_ip']}:{port}/"
        try:
            r = httpx.get(target, auth=(creds["username"], creds.get("password", "")),
                          timeout=20, verify=False, follow_redirects=True)
            add("credentials", r.status_code < 400, f"HTTP {r.status_code} as {creds['username']}")
        except Exception as exc:
            add("credentials", False, str(exc)[:150])

    url = (f"https://{domain}" if domain else
           (f"http://{settings['ingress_ip']}:{port}" if port else ""))
    job.tick(checks=checks, url=url)
    return {"ok": all(c["ok"] for c in checks), "url": url, "checks": checks, "creds": creds or {}}
