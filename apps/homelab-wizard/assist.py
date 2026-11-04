"""assist: docker-compose auditing, stack validation, and the OpenRouter
conversion. The model proposes; validate_stack() decides."""
import json
import re

import httpx
import yaml

import core

SWARM_KEYS = {"image", "command", "entrypoint", "environment", "networks", "ports",
              "volumes", "deploy", "healthcheck", "logging", "configs", "secrets",
              "hostname", "user", "working_dir", "stop_grace_period", "labels",
              "cap_add", "cap_drop", "dns", "extra_hosts", "sysctls", "ulimits",
              "read_only", "init", "tty", "stdin_open", "expose", "tmpfs"}
COMPOSE_ONLY = {"build", "depends_on", "env_file", "network_mode", "mem_limit",
                "cpus", "restart", "container_name", "links", "volumes_from",
                "extends", "profiles", "cpu_shares", "shm_size", "ports_range"}

RULES = [
    ("placement at service level", lambda s: "placement" in s,
     "move `placement` under `deploy:` - at service level it is a schema error"),
    ("env_file", lambda s: "env_file" in s,
     "`docker stack deploy` ignores env_file - inline the variables under environment"),
    ("network_mode: service:*", lambda s: str(s.get("network_mode", "")).startswith("service:"),
     "shared netns is unsupported in swarm - put the companion on the overlay network"),
    ("network_mode: host", lambda s: s.get("network_mode") == "host",
     "host netns needs `ports: [{target, published, mode: host}]` and pins the task to a node"),
    ("depends_on", lambda s: "depends_on" in s,
     "swarm ignores depends_on - make the app retry, or gate on a healthcheck"),
    ("container_name", lambda s: "container_name" in s,
     "swarm names tasks itself; container_name breaks scaling"),
    ("restart:", lambda s: "restart" in s, "use deploy.restart_policy instead of restart:"),
    ("mem_limit / cpus", lambda s: "mem_limit" in s or "cpus" in s,
     "use deploy.resources.limits instead of mem_limit/cpus"),
    ("build:", lambda s: "build" in s,
     "swarm deploys images - build it in apps/ and reference the zot image"),
    ("links", lambda s: "links" in s, "use overlay networks and service names, not links"),
]


def parse(text):
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"not valid yaml: {exc}")
    services = doc.get("services") or {}
    if not isinstance(services, dict) or not services:
        raise ValueError("no `services:` mapping found")
    return doc, services


def audit_compose(text):
    doc, services = parse(text)
    notes = []
    for name, spec in services.items():
        if not isinstance(spec, dict):
            continue
        for label, test, fix in RULES:
            try:
                if test(spec):
                    notes.append({"service": name, "issue": label, "fix": fix})
            except Exception:
                continue
        for p in spec.get("ports") or []:
            if str(p).startswith(("127.0.0.1", "localhost")):
                notes.append({"service": name, "issue": f"loopback bind {p}",
                              "fix": "ingress cannot bind loopback - publish the port instead"})
    return {"services": list(services), "notes": notes,
            "volumes": list((doc.get("volumes") or {}).keys()),
            "networks": list((doc.get("networks") or {}).keys())}


def validate_stack(text):
    problems, warnings, seen = [], [], {}
    try:
        _, services = parse(text)
    except ValueError as exc:
        return {"ok": False, "problems": [str(exc)], "warnings": [], "services": [], "ports": []}
    for name, spec in services.items():
        if not isinstance(spec, dict):
            problems.append(f"{name}: not a mapping")
            continue
        for key in spec:
            if key in COMPOSE_ONLY:
                problems.append(f"{name}: `{key}` is compose-only")
            elif key not in SWARM_KEYS:
                warnings.append(f"{name}: unusual key `{key}`")
        if "image" not in spec:
            problems.append(f"{name}: no image")
        if "placement" in spec:
            problems.append(f"{name}: placement must be under deploy:")
        if not isinstance(spec.get("deploy") or {}, dict):
            problems.append(f"{name}: deploy must be a mapping")
        for p in spec.get("ports") or []:
            mode = p.get("mode", "ingress") if isinstance(p, dict) else "ingress"
            published = p.get("published") if isinstance(p, dict) else str(p).split(":")[0]
            try:
                published = int(str(published).split("/")[0])
            except Exception:
                warnings.append(f"{name}: unparsed port `{p}`")
                continue
            if mode != "host":
                if published in seen:
                    problems.append(f"port {published} published twice "
                                    f"({seen[published]} and {name})")
                seen[published] = name
        hc = spec.get("healthcheck")
        if hc and not (isinstance(hc, dict) and hc.get("test")):
            warnings.append(f"{name}: healthcheck without a test")
    return {"ok": not problems, "problems": problems, "warnings": warnings,
            "services": list(services), "ports": sorted(seen)}


# ------------------------------------------------------------------ openrouter

SYSTEM = """You convert docker-compose files into Docker Swarm stack files.

Return ONLY JSON: {"stack": "<yaml>", "changes": [{"what":"","why":""}],
"warnings": [""], "url": "<subdomain or empty>", "port": <host port or 0>,
"env_required": [""]}

Hard rules (each one breaks `docker stack deploy` if ignored):
- top level `version: "3.8"` and `services:`
- `placement` goes under `deploy:`, never at service level
- nothing compose-only: no depends_on, env_file, container_name, links, build,
  restart:, mem_limit, cpus, network_mode: service:*
- replicas, limits and restart_policy live under `deploy:`
- swarm does not read .env files: inline every variable under environment and
  keep the values from the source file
- healthcheck: {"test": ["CMD-SHELL", "..."], "interval": "30s",
  "timeout": "5s", "retries": 3, "start_period": "40s"}
- ports as "host:container" strings unless the source used host mode
- bind mounts as {"type": "bind", "source": "...", "target": "..."} with host
  paths under /opt/docker/data/<stack>/
- keep image references exactly as given, tags included
- drop profiles, x- extensions and watch entries
"""


def _json(text):
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n", "", text)
        text = re.sub(r"\n```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            raise
        return json.loads(m.group(0))


def models(timeout=25):
    try:
        r = httpx.get("https://openrouter.ai/api/v1/models", timeout=timeout)
        r.raise_for_status()
        out = [{"id": m.get("id"), "name": m.get("name"), "context": m.get("context_length"),
                "prompt_price": (m.get("pricing") or {}).get("prompt")}
               for m in r.json().get("data", [])]
        return sorted(out, key=lambda m: (m["name"] or "").lower())
    except Exception as exc:
        return [{"id": core.DEFAULT_MODEL, "name": f"(list unavailable: {exc})"}]


def _chat(settings, messages, timeout=180):
    core.require(settings, "openrouter_key")
    r = httpx.post("https://openrouter.ai/api/v1/chat/completions",
                   headers={"Authorization": f"Bearer {settings['openrouter_key']}",
                            "X-Title": "homelab-wizard"},
                   json={"model": settings.get("openrouter_model") or core.DEFAULT_MODEL,
                         "messages": messages, "temperature": 0.1,
                         "response_format": {"type": "json_object"}},
                   timeout=timeout)
    if r.status_code >= 400:
        raise RuntimeError(f"openrouter HTTP {r.status_code}: {r.text[:300]}")
    data = r.json()
    if not data.get("choices"):
        raise RuntimeError(f"openrouter returned no choices: {str(data)[:300]}")
    return data["choices"][0]["message"]["content"], data.get("usage") or {}


def convert(settings, compose_text, stack_name, hint=""):
    audit = audit_compose(compose_text)
    user = ("Stack name: " + stack_name
            + "\nContext: " + (hint or "none")
            + "\nStatic audit: " + json.dumps(audit["notes"])
            + "\n\ndocker-compose.yml:\n" + compose_text)
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": user}]
    raw, usage = _chat(settings, messages)
    proposal = _json(raw)
    result = validate_stack(proposal.get("stack") or "")
    if not result["ok"]:
        messages += [{"role": "assistant", "content": json.dumps(proposal)},
                     {"role": "user", "content": "This fails validation:\n"
                                                 + "\n".join(result["problems"])
                                                 + "\nReturn corrected JSON only."}]
        raw, usage2 = _chat(settings, messages)
        proposal = _json(raw)
        result = validate_stack(proposal.get("stack") or "")
        usage = {**usage, **usage2}
    return {"ok": result["ok"], "stack": proposal.get("stack") or "",
            "changes": proposal.get("changes") or [],
            "warnings": list(proposal.get("warnings") or []) + result["warnings"],
            "problems": result["problems"],
            "detected": {"port": proposal.get("port") or 0,
                         "url": proposal.get("url") or "",
                         "env_required": proposal.get("env_required") or [],
                         "services": result["services"], "ports": result["ports"]},
            "audit": audit, "model": settings.get("openrouter_model"), "usage": usage}
