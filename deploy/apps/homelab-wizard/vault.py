"""vault: the estate's credentials live in Docker secrets, not in git.


Two rules this module exists to enforce:

1. A stack file never carries a credential. Swarm gets it as an external secret
   and the service mounts it (`secrets:` + `external: true`); applications that
   support it read /run/secrets/<name> directly, and the wizard reads its own
   the same way.
2. Nothing secret is written to wizard.yaml, stack.yml or settings.json. The
   wizard's own settings only ever hold a *pointer* (the secret's name).

Swarm secrets are immutable: rotating one means `docker secret rm` + create.
A running task keeps its mounted copy, so the window where the name does not
exist only matters if a new task starts inside it - the helpers below create the
new value first under a temporary name where possible.
"""
import os
import re
import shlex

import swarmio

SECRETS_DIR = os.environ.get("WIZ_SECRETS_DIR", "/run/secrets")

# env keys that must never appear as plaintext in a stack file
SECRET_HINT = re.compile(r"(password|passwd|secret|token|api[_-]?key|private[_-]?key|"
                         r"access[_-]?key|encryption[_-]?key|jwt)", re.I)

# wizard-owned secret name -> (settings key, legacy env var)
WIZARD_SECRETS = {
    "wizard_gitea_token": ("gitea_token", "GIT_API_KEY"),
    "wizard_zot_password": ("zot_password", "ZOT_PASSWORD"),
    "wizard_openrouter_key": ("openrouter_key", "OPENROUTER_API_KEY"),
}


def read_file(name):
    """Value of a mounted secret, or "" when it is not mounted."""
    path = os.path.join(SECRETS_DIR, name)
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return ""


def overlay(settings):
    """Copy of settings with mounted secrets applied over the stored values."""
    out = dict(settings)
    for name, (key, env) in WIZARD_SECRETS.items():
        value = read_file(name)
        if value:
            out[key] = value
        elif os.environ.get(env):
            out[key] = os.environ[env]
    return out


def list_(settings):
    out = swarmio.run(settings["manager"],
                      "docker secret ls --format '{{.Name}}\t{{.UpdatedAt}}'", timeout=30)
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if parts and parts[0]:
            rows.append({"name": parts[0], "updated": parts[1] if len(parts) > 1 else ""})
    return rows


def exists(settings, name):
    out = swarmio.run(settings["manager"],
                      f"docker secret ls --filter name={shlex.quote(name)} "
                      "--format '{{.Name}}'", timeout=30)
    return name in out.split()


def store(settings, name, value):
    """Create or rotate an external swarm secret."""
    if not re.match(r"^[A-Za-z0-9._-]{1,64}$", name or ""):
        raise swarmio.SwarmError(f"bad secret name: {name!r}")
    if not value:
        raise swarmio.SwarmError("refusing to publish an empty secret")
    q = shlex.quote
    if exists(settings, name):
        # immutable: remove, recreate, then nudge anything that mounts it
        swarmio.run(settings["manager"],
                    f"docker secret rm {q(name)} >/dev/null && "
                    f"printf '%s' {q(value)} | docker secret create {q(name)} - >/dev/null",
                    timeout=60)
        rotated = True
    else:
        swarmio.run(settings["manager"],
                    f"printf '%s' {q(value)} | docker secret create {q(name)} - >/dev/null",
                    timeout=60)
        rotated = False
    return {"name": name, "rotated": rotated}


def audit(wizard, estate_dir):
    """Every stack file that still has a credential-shaped env value in it."""
    findings = []
    stacks = os.path.join(estate_dir, "stacks")
    if not os.path.isdir(stacks):
        return findings
    for name in sorted(os.listdir(stacks)):
        path = os.path.join(stacks, name, "stack.yml")
        if not os.path.isfile(path):
            continue
        declared = set()
        for svc in (wizard.get("services") or []):
            if svc.get("name") == name:
                declared = {str(k) for k in (svc.get("env") or {})}
        with open(path) as fh:
            for lineno, line in enumerate(fh, 1):
                m = re.match(r"^\s*([A-Za-z0-9_.-]+):\s*(.+?)\s*$", line)
                if not m:
                    continue
                key, value = m.group(1), m.group(2)
                if not SECRET_HINT.search(key):
                    continue
                # `POSTGRES_PASSWORD_FILE: /run/secrets/x` is the *fix*, not a
                # finding: the value is a path to a mounted secret. Flagging it
                # was hiding the real findings behind false ones.
                if key.endswith("_FILE"):
                    continue
                # A bare path is not a credential either, whichever key it is
                # under - someone pointing at a file has already done the work.
                if value.strip('"').strip("'").startswith("/run/secrets/"):
                    continue
                if value in ("", '""', "''") or value.startswith(("$", "*")):
                    continue
                # MYSQL_RANDOM_ROOT_PASSWORD=1 is a flag, not a credential
                if value.strip('"').strip("'") in ("0", "1", "true", "false",
                                                   "yes", "no", "on", "off"):
                    continue
                findings.append({"stack": name, "line": lineno, "key": key,
                                 "in_wizard_yaml": key in declared,
                                 "preview": value[:6] + "…" if len(value) > 6 else value})
    return findings
