# Self-healing remediation

Remediation turns a stored log report into a **plan you approve**, executes it
with Ansible, and then proves the fix with an independent probe.

Two rules shape the whole feature:

1. **Only catalog entries can run.** A YAML file in `remediations/` is the sole
   source of truth. Nothing else — no model output, no free text from the
   browser — can reach `ansible-runner`.
2. **The playbook does not grade its own homework.** Verification is a plain
   SSH command run *after* Ansible finishes, with its own expected value.

Auto-heal does not exist: nothing runs without a plan, a confirmation token and
a human click (plus a typed `RUN` when more than one host is involved).

---

## The three modes

| `AILOG_ALLOW_REMEDIATION` | Cards | Plan | Apply |
|---|---|---|---|
| `off` *(default)* | visible | 403 | 403 |
| `dry_run` | visible | yes | `ansible-playbook --check --diff` only |
| `on` | visible | yes | real changes |

Cards are always readable so operators can see what *would* be fixed. The
refusal message names the variable to set, so a read-only deployment is not a
dead end.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AILOG_ALLOW_REMEDIATION` | `off` | `off` \| `dry_run` \| `on` |
| `AILOG_REMEDIATION_MAX_HOSTS` | `10` | refuse plans wider than this |
| `AILOG_REMEDIATION_MAX_CONCURRENT` | `2` | concurrent runs per process |
| `AILOG_REMEDIATION_RETENTION_DAYS` | `30` | artifact directories kept |
| `AILOG_REMEDIATION_TIMEOUT` | `300` | per-wave job timeout (min 30) |
| `AILOG_REMEDIATION_SETTLE_CAP` | `60` | max wait before post-apply probing |
| `AILOG_REMEDIATION_ARTIFACT_DIR` | `$AILOG_DATA_DIR` or `/tmp/ailog-remediation` | where run output lands |
| `AILOG_REMEDIATION_ALLOW_IDEA_CHANNEL` | `1` | allow model *suggestion* cards |
| `AILOG_REMEDIATION_CLOSURE` | `0` | schedule a follow-up report after a fix |
| `AILOG_SECRET_KEY` | dev fallback | signs confirmation tokens — **set this in production** |

Remediation runs as the host's `ssh_user` with `sudo -n` (NOPASSWD). See the
sudoers example in the README.

## The lifecycle of one remedy

```
report saved
   │  matcher: deterministic regex over stored clusters
   ▼
card on /reports/<id>  ── dismiss (reason recorded) ──▶ stays dismissed
   │  "Plan" -> POST /api/remediations/<slug>/plan
   ▼
plan dialog: scope, hosts, waves, playbook, verify command, rollback
   │  click (1 host) or type RUN (2+ hosts) -> POST .../apply
   ▼
run (worker thread, SSE progress) -> per-wave ansible-runner
   │  after each wave: independent verify probe
   ▼
healed | applied_unverified | failed   (+ rollback for failed targets)
```

### Confirmation tokens

`plan` returns an HMAC-SHA256 token over `slug | sorted(hosts) | dry_run | exp`
(TTL 300 s). `apply` recomputes it from the *requested* scope. If the browser
tries to add a host between the dialog and the run, the token no longer matches
and the request is refused. This is what makes "the plan you read" the same as
"the plan that runs".

### Waves and halting

| Risk | Hosts per wave |
|---|---|
| `low` | `ceil(n / 4)` |
| `medium` / `high` | `1` (serial) |

The run stops early when failures exceed 20% of the eligible set or two
consecutive targets fail. Unstarted targets are marked `skipped`, never left
`pending`.

Fleet scope means *hosts whose newest open card for this remedy exists* — not
every host in the database. Only low-risk entries may be planned for a fleet.

## Verification

Each catalog entry declares:

```yaml
verify:
  command: "systemctl --failed --no-legend | wc -l"
  expect:
    stdout_max: 0
  settle_seconds: 10
```

Supported expectations: `exit_code`, `stdout_matches` (regex),
`stdout_contains`, `stdout_min`, `stdout_max` (numeric, first integer found).

A host is only `healed` when the probe passes. If Ansible reports success and
the probe does not, the target is **not** healed — the probe wins.

## Rollback

Medium and high risk entries must ship a `rollback` playbook; the catalog
loader refuses them otherwise. Failed targets are rolled back automatically at
the end of a run, and `/remediation/runs/<uuid>` offers a manual rollback for
`failed`/`healed` targets. Every rollback is audited.

## Maintenance windows and protected hosts

Windows live in the app (`RemediationWindow`), not in an external scheduler:

- days as ISO weekday numbers, `start_time`/`end_time` (wrapping midnight is fine)
- a timezone per window (zoneinfo; unknown zones fall back to UTC)
- optional `group_id` / `tag_id` scope
- mode `block` (refuse) or `warn` (allow, but say why)

A host can also be marked **do not remediate**; the planner and the runner both
refuse it. Use this for anything you never want automated.

## Audit

`audit_events` records `remediation.apply`, `remediation.finished`,
`remediation.dismiss`, `remediation.rollback`, `remediation.window.create`,
`remediation.window.delete` and `remediation.protect`, with the actor and the
relevant detail.

## Retention

Each run writes `ansible-runner` artifacts under
`<artifact_root>/<run-uuid>/wave-N`. Directories older than
`AILOG_REMEDIATION_RETENTION_DAYS` are pruned after every run.

## What this deliberately does not do

- no auto-heal on report arrival
- no execution of model output (see [promoting-a-suggestion.md](promoting-a-suggestion.md))
- no package upgrades, reboots or firewall flushes, in any catalog entry
