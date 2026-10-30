# Remediation catalog

This directory **is** the allowlist for self-healing. Every `*.yml` here is
validated at boot and in CI; anything that fails validation is not loadable and
therefore cannot be executed.

- One file per remedy, named after its `slug`.
- Playbooks live in `playbooks/`, roles in `roles/`, molecule scenarios in
  `roles/<slug>/molecule/default/`.
- Medium and high risk entries **must** have a `rollback` playbook.
- `verify.command` + `verify.expect` are mandatory and must be falsifiable.

Read [../docs/remediation-catalog.md](../docs/remediation-catalog.md) before
adding an entry, and [../docs/promoting-a-suggestion.md](../docs/promoting-a-suggestion.md)
if you are turning a model suggestion into a reviewed remedy.

Quick check:

```bash
python -c "from remediation import catalog; print(len(catalog.load_all(force=True)), 'entries')"
pytest -q tests/test_remediation_catalog.py
```
