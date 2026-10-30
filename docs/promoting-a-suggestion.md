# Promoting a model suggestion into a real remedy

Every catalog match is deterministic: a regex over stored clusters, with a
documented confidence score. That is what lets you say "this card is safe to
run" and be right.

A model has no such guarantee. So model output lands in a different kind of
card:

> **Unverified suggestion — copy and run yourself**

That card has no **Plan** and no **Apply** button. It exists to shorten the
distance between "something looks odd" and "here is a thing to try". It is
prose plus a code block you can copy into a shell you already trust.

## The rule

> **The model can suggest. Only a reviewed pull request can make something
> executable.**

There are no exceptions, no config flag, and no admin bypass. A suggestion
becomes a remedy by adding files to this repository, not by clicking harder.

## Promotion checklist

1. **Reproduce the symptom** on a host where the recommendation applies. If you
   cannot trigger it, you cannot test the fix.
2. **Write the role**, not just a command. A single `shell:` line is not a
   remedy: it has no idempotence, no preconditions and no rollback.
   ```
   remediations/roles/<slug>/{tasks,defaults,meta}/main.yml
   ```
   Guard every task with `when:` and prefer modules over `shell`/`command`.
3. **Write the playbook** that applies the role:
   ```yaml
   - name: <title>
     hosts: all
     become: true
     gather_facts: false
     roles: [<slug>]
   ```
4. **Decide the risk honestly.** If it can lose data, drop a connection, or
   restart something someone depends on, it is `medium` or `high` — and then a
   rollback playbook is mandatory.
5. **Write a `verify` probe that would fail before the fix.** Run it on a broken
   host and on a healthy one. If it passes in both states, it proves nothing.
6. **Add the catalog entry** following
   [remediation-catalog.md](remediation-catalog.md), with `match.any` rules
   specific enough not to fire on unrelated noise.
7. **Add a molecule scenario** so the role is exercised in CI
   (`remediations/roles/<slug>/molecule/default/`).
8. **Update `docs/remediation-catalog.md`** with a one-line description.
9. **Open the PR.** It is reviewed like any other change to the sudo path,
   because that is exactly what it is.

## What must never be promoted

These were blocked in the idea channel for a reason, and a PR does not launder
them:

- `rm -rf` of anything, `mkfs`, `dd if=`, writes to block devices
- reboots, shutdowns, `systemctl isolate`
- firewall flushes (`iptables -F`, `nft flush`)
- piping a download into a shell (`curl … | sh`)
- `chmod -R 777 /`, deleting users, changing passwords
- `apt upgrade` / `dist-upgrade` (a package upgrade is a change window, not a
  remedy)
- dropping database tables

If a fix genuinely needs one of these, it needs a maintenance window and a
human, not a self-healing button.

## Why the extra friction is the point

The catalog is small on purpose. Twelve reviewed remedies that each prove
themselves are worth more than a hundred plausible commands executed with
`become: true`. The idea channel keeps the long tail visible without putting it
in the sudo path.
