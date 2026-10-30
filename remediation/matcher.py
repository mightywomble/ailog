"""Deterministic report -> remedy card matching.

No model is involved: a card appears because a catalog regex matched a
cluster that the correlation stage already produced, with a documented
confidence formula. That is what makes the executable path auditable.
"""

from __future__ import annotations

import json
import logging
import re

from remediation import catalog, policy, suggestions

log = logging.getLogger(__name__)


def _clusters(report) -> list[dict]:
    try:
        return report.clusters() or []
    except Exception:
        return []


def _rule_match(rule: dict, clusters: list[dict]) -> dict | None:
    pattern = re.compile(rule['signature_regex'], re.IGNORECASE)
    wanted_src = (rule.get('source') or '').strip().lower()
    best = None
    for cluster in clusters:
        if wanted_src and str(cluster.get('src') or '').lower() != wanted_src:
            continue
        haystack = ' '.join(str(cluster.get(k) or '') for k in ('sig', 'label'))
        if not pattern.search(haystack):
            continue
        count = int(cluster.get('count') or 0)
        if count < int(rule.get('min_count', 1)):
            continue
        if best is None or count > int(best.get('count') or 0):
            best = {'sig': cluster.get('sig'), 'label': cluster.get('label'),
                    'src': cluster.get('src'), 'sev': cluster.get('sev'), 'count': count}
    return best


def _confidence(entry: dict, hit: dict, report) -> float:
    score = 0.55
    count = int(hit.get('count') or 0)
    if count >= 10:
        score += 0.1
    if count >= 100:
        score += 0.05
    if (report.verdict or '') in ('failing', 'degraded'):
        score += 0.1
    if str(hit.get('sev') or '').lower() in ('crit', 'critical', 'error'):
        score += 0.1
    return round(min(0.95, score), 2)


def match_report(report, models, db, entries=None, with_ideas=True) -> dict:
    """Create/refresh the cards for one report. Returns a summary dict."""
    entries = entries if entries is not None else catalog.load_all()
    clusters = _clusters(report)
    coverage = report.coverage() if hasattr(report, 'coverage') else {}

    suppressed = ''
    if (report.verdict or '') == 'unknown':
        suppressed = 'verdict unknown'
    elif (coverage or {}).get('truncated'):
        suppressed = 'evidence truncated'

    by_slug = {row.slug: row for row in models.RemediationMatch.query.filter_by(report_id=report.id).all() if row.slug}
    matched_slugs, created = set(), 0

    if not suppressed:
        for entry in entries:
            hit = None
            for rule in entry['match']['any']:
                hit = _rule_match(rule, clusters)
                if hit:
                    break
            if not hit:
                continue
            matched_slugs.add(entry['slug'])
            row = by_slug.get(entry['slug'])
            if row is None:
                row = models.RemediationMatch(report_id=report.id, slug=entry['slug'])
                db.session.add(row)
                created += 1
            if row.state == 'dismissed':
                continue
            row.host_key = report.host_key
            row.source = 'catalog'
            row.executable = True
            row.title = entry['title']
            row.summary = entry['summary']
            row.risk = entry['risk']
            row.est_seconds = entry['est_seconds']
            row.confidence = _confidence(entry, hit, report)
            row.evidence_json = json.dumps([hit])
            row.rationale = f"Matched {hit.get('count')} x {hit.get('sig')} in {hit.get('src')}"
            row.code_text = entry['playbook_text']
            row.verify_text = entry['verify_text']
            row.rollback_text = entry['rollback_text']
            row.changes_json = json.dumps(entry['changes'])
            row.does_not_json = json.dumps(entry['does_not'])
            row.requires_json = json.dumps(entry['requires'])

    # Catalog rows that no longer match are removed (unless dismissed).
    for slug, row in list(by_slug.items()):
        if slug not in matched_slugs and row.state != 'dismissed':
            db.session.delete(row)

    ideas = 0
    existing_ideas = [row for row in models.RemediationMatch.query.filter_by(report_id=report.id, source='llm').all()]
    if with_ideas and not suppressed and not existing_ideas and policy.idea_channel_enabled():
        for item in suggestions.propose(_app_module(), report, clusters, matched_slugs):
            db.session.add(models.RemediationMatch(
                report_id=report.id, host_key=report.host_key, slug=None, source='llm',
                executable=False, title=item['title'], summary=item['rationale'],
                risk=item['risk'], est_seconds=0, confidence=0.35,
                evidence_json='[]', rationale=item['rationale'],
                code_text=item['code'], verify_text=item['verify'],
                rollback_text=item['rollback'], changes_json='[]',
                does_not_json='[]', requires_json='[]',
            ))
            ideas += 1

    db.session.commit()
    return {'matched': sorted(matched_slugs), 'created': created, 'ideas': ideas, 'suppressed': suppressed}


def _app_module():
    from flask import current_app
    return current_app._get_current_object()