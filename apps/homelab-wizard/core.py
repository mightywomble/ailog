"""core: settings, git plumbing and the wizard.yaml <-> stack.yml renderer."""
import copy
import json
import os
import re
import subprocess
import threading

import yaml

SETTINGS_PATH = os.environ.get("WIZ_SETTINGS", "/data/settings.json")
DEFAULT_MODEL = "anthropic/claude-sonnet-4.5"

DEFAULTS = {
    "gitea_url": "https://git.safehomelan.com",
    "gitea_owner": "david",
    "gitea_repo": "homelab-ops",
    "gitea_token": "",
    "zot_url": "https://zot.safehomelan.com",
    "zot_user": "",
    "zot_password": "",
    "openrouter_key": "",
    "openrouter_model": DEFAULT_MODEL,
    "domain_suffix": "safehomelan.com",
    "cert": "npm-1",
    "manager": "swarm1",
    "nodes": ["swarm1", "worker1", "worker2", "worker3", "worker4"],
    "ingress_ip": "100.79.189.118",
    "casaos_ip": "100.122.246.45",
    "pihole_ip": "100.122.246.45",
    "npm_db": "/DATA/AppData/nginxproxymanager/data/database.sqlite",
    "npm_conf_dir": "/DATA/AppData/nginxproxymanager/data/nginx/proxy_host",
    "repo_dir": "/data/repo",
    "work_branch": "dev",
}
SECRETS = {"gitea_token", "zot_password", "openrouter_key"}
_lock = threading.RLock()


def _seed():
    data = dict(DEFAULTS)
    data.update({
        "gitea_token": os.environ.get("GIT_API_KEY", ""),
        "zot_user": os.environ.get("ZOT_USER", ""),
        "zot_password": os.environ.get("ZOT_PASSWORD", ""),
        "openrouter_key": os.environ.get("OPENROUTER_API_KEY", ""),
        "openrouter_model": os.environ.get("OPENROUTER_MODEL", DEFAULT_MODEL),
    })
    return data


def load():
    with _lock:
        data = _seed()
        if os.path.exists(SETTINGS_PATH):
            try:
                data.update(json.load(open(SETTINGS_PATH)))
            except Exception:
                pass
        return data


def save(patch):
    with _lock:
        data = load()
        data.update({k: v for k, v in patch.items() if k in DEFAULTS or k in SECRETS})
        os.makedirs(os.path.dirname(SETTINGS_PATH) or ".", exist_ok=True)
        tmp = SETTINGS_PATH + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(data, fh, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, SETTINGS_PATH)
        return data


def public(data=None):
    data = data or load()
    out = dict(data)
    for k in SECRETS:
        out[k] = "••••••" if data.get(k) else ""
        out[k + "_set"] = bool(data.get(k))
    return out


def require(data, *keys):
    missing = [k for k in keys if not data.get(k)]
    if missing:
        raise ValueError("missing settings: " + ", ".join(missing))


# ------------------------------------------------------------------ git

class GitError(RuntimeError):
    pass


def _git(cwd, *args, timeout=120):
    proc = subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise GitError(f"git {' '.join(args)}: {(proc.stderr or proc.stdout).strip()[:400]}")
    return proc.stdout


def repo_dir(settings=None):
    return (settings or load())["repo_dir"]


def _clone_url(settings):
    return settings["gitea_url"].rstrip("/").replace(
        "https://", f"https://oauth2:{settings['gitea_token']}@")


def ensure(settings=None):
    """Clone or hard-sync the worktree to origin/<work_branch>."""
    settings = settings or load()
    require(settings, "gitea_token")
    path, branch = settings["repo_dir"], settings.get("work_branch", "dev")
    url = f"{_clone_url(settings)}/{settings['gitea_owner']}/{settings['gitea_repo']}.git"
    if not os.path.isdir(os.path.join(path, ".git")):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        subprocess.run(["git", "clone", "--quiet", url, path], check=True, capture_output=True, text=True)
    _git(path, "remote", "set-url", "origin", url)
    _git(path, "fetch", "--quiet", "--prune", "origin")
    target = f"origin/{branch}"
    try:
        _git(path, "rev-parse", "--verify", "--quiet", f"refs/remotes/{target}")
    except GitError:
        target = "origin/main"
    _git(path, "config", "user.email", "wizard@safehomelan.com")
    _git(path, "config", "user.name", "homelab wizard")
    _git(path, "checkout", "--quiet", "-B", branch, target)
    _git(path, "reset", "--quiet", "--hard", target)
    return path


_last_sync = [0.0]


def sync_if_stale(settings=None, min_interval=60):
    """Fetch + reset at most once a minute, so the UI reflects merges made
    elsewhere (a PR merged in Gitea, another browser's commit) without paying
    for a git round trip on every request."""
    import time
    settings = settings or load()
    if time.time() - _last_sync[0] < min_interval:
        return False
    try:
        if changed_files():        # never reset away an unsaved edit
            return False
    except Exception:
        pass
    _last_sync[0] = time.time()
    try:
        ensure(settings)
        return True
    except Exception:
        return False


def read_yaml(name, settings=None):
    path = os.path.join(repo_dir(settings), name)
    return (yaml.safe_load(open(path)) or {}) if os.path.exists(path) else {}


def write_yaml(name, data, header=""):
    path = os.path.join(repo_dir(), name)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as fh:
        fh.write(header or "")
        fh.write(yaml.safe_dump(data, sort_keys=False, width=100))
    return path


def write_text(relpath, text):
    path = os.path.join(repo_dir(), relpath)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    open(path, "w").write(text)
    return path


def head():
    return _git(repo_dir(), "log", "-1", "--pretty=%h %s").strip()


def changed_files():
    out = _git(repo_dir(), "status", "--porcelain")
    return [line[3:] for line in out.splitlines() if line.strip()]


def commit_and_push(message, files=None):
    path = repo_dir()
    branch = load().get("work_branch", "dev")
    files = files if files is not None else changed_files()
    if not files:
        return {"committed": False, "branch": branch, "files": []}
    for f in files:
        _git(path, "add", "-A", "--", f)
    _git(path, "-c", "user.email=wizard@safehomelan.com", "-c", "user.name=homelab wizard",
         "commit", "--quiet", "-m", message)
    _git(path, "push", "--quiet", "origin", f"HEAD:refs/heads/{branch}")
    return {"committed": True, "branch": branch, "sha": _git(path, "rev-parse", "HEAD").strip(),
            "files": files, "message": message}


# ------------------------------------------------------------------ render

HEADER = """# {name} - rendered from wizard.yaml by homelab-wizard.
# Owned by the wizard: image tag, published ports, replicas, volumes.
# Everything else here is hand-maintained and survives a re-render.
"""


def image_ref(entry, registry="zot.safehomelan.com"):
    repo = entry.get("repo") or entry["name"]
    version = str(entry.get("version") or "latest")
    base = f"{registry}/{repo}"
    return f"{base}:${{IMAGE_TAG:-{version}}}" if entry.get("kind") == "build" else f"{base}:{version}"


def render_stack(entry, existing=None, registry="zot.safehomelan.com"):
    name = entry["name"]
    doc = copy.deepcopy(existing) if existing else {"version": "3.8", "services": {}}
    services = doc.setdefault("services", {})
    svc = services.setdefault(entry.get("service") or name, {})
    svc["image"] = image_ref(entry, registry)

    if entry.get("ports") is not None:
        ports = []
        for p in entry["ports"]:
            if not p.get("host"):
                continue
            cont = p.get("container") or p["host"]
            if p.get("mode") == "host":
                ports.append({"target": int(cont), "published": int(p["host"]), "mode": "host"})
            else:
                ports.append(f"{p['host']}:{cont}" if str(cont) != str(p["host"]) else f"{p['host']}")
        if ports:
            svc["ports"] = ports

    if entry.get("replicas"):
        svc.setdefault("deploy", {})["replicas"] = int(entry["replicas"])

    if entry.get("volumes"):
        vols = [{"type": "bind", "source": v["host"], "target": v.get("container") or "/data"}
                for v in entry["volumes"] if v.get("host")]
        if vols:
            svc["volumes"] = vols

    if entry.get("env"):
        env = svc.get("environment") if isinstance(svc.get("environment"), dict) else {}
        env.update({str(k): str(v) for k, v in entry["env"].items()})
        svc["environment"] = env

    if entry.get("healthcheck"):
        hc = entry["healthcheck"]
        svc["healthcheck"] = hc if isinstance(hc, dict) else {
            "test": ["CMD-SHELL", str(hc)], "interval": "30s", "timeout": "5s",
            "retries": 3, "start_period": "40s"}

    return HEADER.format(name=name) + yaml.safe_dump(doc, sort_keys=False, width=100)


def mirror_entry(entry):
    if entry.get("kind") != "mirror" or not entry.get("source"):
        return None
    return {"name": entry.get("repo") or entry["name"], "source": entry["source"]}


def validate(entry):
    problems = []
    name = entry.get("name") or ""
    if not re.match(r"^[a-z0-9][a-z0-9-]{1,30}$", name):
        problems.append("name must be lowercase alphanumeric/hyphen (2-31 chars)")
    if entry.get("kind") not in ("build", "mirror", "image"):
        problems.append("kind must be build, mirror or image")
    if entry.get("kind") == "mirror" and not entry.get("source"):
        problems.append("mirror services need an upstream source (registry/repo:tag)")
    try:
        yaml.safe_load(render_stack(entry))
    except Exception as exc:
        problems.append(f"rendered stack.yml is invalid: {exc}")
    return problems
