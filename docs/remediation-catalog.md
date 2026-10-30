# The remediation catalog

`remediations/` is the allowlist. If an entry validates, it may run; if it does
not, the app refuses to boot the catalog (and CI fails).

```
remediations/
  restart-failed-units.yml          # the entry (metadata + matching + verify)
  playbooks/
    restart-failed-units.yml        # the playbook ansible-runner executes
    <slug>-rollback.yml             # required for medium/high risk
  roles/
    <slug>/
      tasks/main.yml
      defaults/main.yml
      meta/main.yml
      molecule/default/{molecule.yml,converge.yml,verify.yml}
```

## Anatomy of an entry

```yaml
slug: restart-failed-units            # must equal the filename stem
version: 1
title: Restart failed systemd units
summary: Restarts units in a failed state, once, and re-checks them.
risk: low                             # low | medium | high
est_seconds: 45
idempotent: true
os: [linux]
requires:
  - command_exists: systemctl

match:
  any:
    - signature_regex: "Failed to start|entered failed state|Main process exited, code=exited"
      source: syslog                  # optional: restrict to one log source
      min_count: 2                    # occurrences in the report window

blast_radius:
  changes:  ["restarts units that are already failed"]
  does_not: ["enables disabled units", "touches running services"]

playbook: playbooks/restart-failed-units.yml
rollback: playbooks/restart-failed-units-rollback.yml   # mandatory if risk != low

verify:
  command: "systemctl --failed --no-legend | wc -l"
  expect:
    stdout_max: 0
  settle_seconds: 10

fleet_safe: true                      # only low risk may be true
```

## What validation enforces

| Rule | Why |
|---|---|
| `slug` matches the filename | prevents copy-paste drift between card and file |
| `risk` ∈ `low`, `medium`, `high` | drives wave size and fleet eligibility |
| `rollback` present when `risk != low` | no one-way doors |
| `playbook`/`rollback` exist **inside** the catalog directory | the trust boundary cannot be escaped with `../` |
| `verify.command` + at least one `verify.expect` key | an unfalsifiable fix is not a fix |
| `match.any` non-empty, every regex compiles | a malformed regex must fail here, not mid-fleet |
| `blast_radius.changes` and `.does_not` non-empty | the dialog must state the blast radius |
| every `requires` type in the allowlist | unknown preconditions cannot be silently ignored |

## Matching and confidence

Cards are produced by `remediation/matcher.py` from the *stored* clusters of a
report — no model. Confidence is deterministic:

```
0.55 base
+0.10 occurrences >= 10      +0.05 occurrences >= 100
+0.10 report verdict degraded/failing
+0.10 cluster severity crit/error
capped at 0.95
```

If the report verdict is `unknown`, or its coverage was truncated, **no cards
are produced**: the evidence is not good enough to act on.

## Adding an entry

1. Copy an existing entry and its playbook; rename the slug.
2. Write the playbook as a thin play that delegates to a role in `roles/<slug>/`,
   so the logic is unit-testable with molecule.
3. Add a `verify` command whose success is unambiguous and cheap.
4. Add the rollback if risk is medium or high.
5. `python -c "from remediation import catalog; print(len(catalog.load_all(force=True)))"`
   — it must load without raising.
6. `pytest tests/test_remediation_catalog.py`.
7. Update `remediations/README.md` if the entry has an operational gotcha.

## Catalog entries shipped today

| slug | risk | what it does |
|---|---|---|
| `restart-failed-units` | low | restarts units in `failed` state |
| `enable-failed-service` | low | re-enables a unit that was disabled by a failure |
| `restart-crashloop-container` | low | restarts a container stuck in a restart loop |
| `remove-stale-container` | low | deletes exited containers older than 7 days |
| `docker-prune-dangling` | low | prunes untagged image layers |
| `free-disk-journal` | low | vacuums the journal to 200 MB |
| `rotate-logs-logrotate` | low | runs logrotate for a given config |
| `fix-time-sync` | low | re-enables NTP and steps the clock |
| `reload-nginx-config` | medium | `nginx -t`, backs up, reloads |
| `sysctl-conntrack` | medium | raises `nf_conntrack_max` via a drop-in |
| `restart-docker-service` | medium | restarts dockerd (brief container blip) |
| `restart-suricata` | low | restarts the Suricata service |
