"""The idea channel: the model may propose, never execute.

Output is validated twice: structurally (JSON, required fields) and
against a blocklist of destructive patterns.  Whatever survives becomes a
card with source=llm and executable=False; the apply endpoint refuses
anything without a catalog slug, so the model can never reach sudo.
"""

from __future__ import annotations

import json
import logging
import re

from serverreport import llm

log = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    'You are a Linux operations engineer. The report below is about ONE host and '
    'the reviewed catalog matched nothing useful.\n\n'
    'Propose at most 3 remediation steps as **Ansible playbooks** that a careful '
    'operator can test with --check before running.\n\n'
    'Reply with ONLY a JSON array, no prose, no markdown fence. Each item:\n'
    '{"title": str, "rationale": str, "risk_guess": "low"|"medium"|"high", '
    '"playbook": str, "verify": str, "rollback": str}.\n\n'
    'playbook must be complete YAML for `ansible-playbook` (max 40 lines): a list '
    'with `hosts: all`, `become: true`, and `tasks:` using real modules (ansible.builtin.*). '
    'It must be idempotent and safe to run twice, must not touch other hosts, must not '
    'upgrade packages, reboot, format disks, delete data, or open the firewall. Prefer '
    'declarative modules over `shell:`; a `shell:` task must use `changed_when`/`creates`.\n'
    'verify must be ONE shell command whose output proves the fix worked. '
    'rollback must be an Ansible playbook that undoes the change, or an empty string.\n'
    'If the report shows nothing fixable, return an empty array [].'
)

BLOCKED = (
    r'\brm\s+-[a-z]*r[a-z]*f', r'\brm\s+-[a-z]*f[a-z]*r', r'\bmkfs\b', r'\bdd\s+if=',
    r'\bshutdown\b', r'\breboot\b', r'\bpoweroff\b', r'\biptables\s+-F\b',
    r'\bnft\s+flush\b', r'curl[^|]*\|\s*(ba)?sh', r'wget[^|]*\|\s*(ba)?sh',
    r'\bchmod\s+-R\s+777\s+/', r'\buserdel\b', r'\bpasswd\b', r'\bdrop\s+table\b',
    r'>\s*/dev/sd', r'\bapt(-get)?\s+(upgrade|dist-upgrade|full-upgrade)\b',
)


def _blocked(text: str) -> str | None:
    for pattern in BLOCKED:
        if re.search(pattern, text or '', re.IGNORECASE):
            return pattern
    return None


def _looks_like_playbook(text: str) -> bool:
    """Cheap structural gate before the YAML parser sees model output."""
    if not text.lstrip().startswith('- '):
        return False
    if 'tasks:' not in text or 'hosts:' not in text:
        return False
    try:
        import yaml
        parsed = yaml.safe_load(text)
    except Exception:
        return False
    if not isinstance(parsed, list) or not parsed:
        return False
    for play in parsed:
        if not isinstance(play, dict):
            return False
        if not isinstance(play.get('tasks'), list) or not play.get('tasks'):
            return False
        if play.get('hosts') not in ('all', ['all']):
            return False
        for task in play['tasks']:
            if not isinstance(task, dict):
                return False
    return True


def _clean(item) -> dict | None:
    if not isinstance(item, dict):
        return None
    title = str(item.get('title') or '').strip()[:200]
    code = str(item.get('playbook') or item.get('code') or '').strip()[:6000]
    verify = str(item.get('verify') or '').strip()[:500]
    rationale = str(item.get('rationale') or '').strip()[:1200]
    rollback = str(item.get('rollback') or '').strip()[:4000]
    if not title or not code or not verify:
        return None
    if _blocked(code) or _blocked(verify) or _blocked(rollback):
        log.warning('idea channel: dropped %r (blocked pattern)', title)
        return None
    if not _looks_like_playbook(code):
        log.info('idea channel: dropped %r (not a valid playbook)', title)
        return None
    risk = str(item.get('risk_guess') or 'unknown').lower()
    if risk not in ('low', 'medium', 'high'):
        risk = 'unknown'
    return {'title': title, 'rationale': rationale, 'risk': risk,
            'code': code, 'verify': verify, 'rollback': rollback,
            'kind': 'ansible'}


def _extract_array(text: str):
    start = text.find('[')
    end = text.rfind(']')
    if start < 0 or end <= start:
        return []
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return []


def available(app_module) -> bool:
    try:
        config = app_module.load_config()
        provider = config.get('analysis_provider', 'openai')
        if provider == 'openai':
            return bool(config.get('openai_api_key'))
        if provider == 'ollama':
            return bool(config.get('ollama_url') and config.get('ollama_model'))
        if provider == 'openrouter':
            return bool(config.get('openrouter_api_key') and config.get('openrouter_model'))
    except Exception:
        return False
    return False


def propose(app_module, report, clusters, matched_slugs) -> list[dict]:
    """Ask the model for idea-channel cards. Never raises."""
    if not available(app_module):
        return []
    config = app_module.load_config()
    provider = config.get('analysis_provider', 'openai')

    lines = [f'Host: {report.host_label or report.host_key}', f'Verdict: {report.verdict}',
             f'Already covered by the catalog: {", ".join(sorted(matched_slugs)) or "none"}',
             'Top clusters:']
    for cluster in (clusters or [])[:25]:
        lines.append(f"- [{cluster.get('sev')}] {cluster.get('count')}x {cluster.get('label') or cluster.get('sig')} ({cluster.get('src')})")
    # Prior art: playbooks a human already ran and confirmed on this fleet.
    # Reusing one is better than inventing a near-duplicate.
    try:
        import database
        learned = (database.RemediationLearned.query
                   .order_by(database.RemediationLearned.confirmed_at.desc()).limit(3).all())
        if learned:
            lines.append('Operator-confirmed playbooks already in the library '
                         '(reuse or adapt instead of inventing a duplicate):')
            for row in learned:
                body = (row.yaml_text or '').strip().splitlines()[:12]
                lines.append(f'- {row.title} ({row.slug}):')
                lines.extend('    ' + line for line in body)
    except Exception:
        pass

    user_prompt = '\n'.join(lines)[:8000]

    try:
        cfg = app_module._analysis_config(provider, config)
        text, _meta = llm.call_model(provider, cfg, SYSTEM_PROMPT, user_prompt, max_tokens=1200, timeout=120)
        items = [_clean(item) for item in _extract_array(text)]
        return [item for item in items if item][:3]
    except Exception as exc:
        log.info('idea channel unavailable: %s', exc)
        return []