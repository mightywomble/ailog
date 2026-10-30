"""Matching is deterministic and conservative.

A card may only appear because a catalog regex hit a stored cluster, and a
model suggestion may never be executable. These are the two properties that
keep the sudo path auditable.
"""

from __future__ import annotations

import json

import pytest

from remediation import matcher


def _report(db, host_key, clusters, verdict='degraded', truncated=False):
    from database import LogReport
    row = LogReport(host_key=host_key, host_label=host_key, verdict=verdict,
                    clusters_json=json.dumps(clusters),
                    coverage_json=json.dumps({'truncated': truncated}))
    db.session.add(row)
    db.session.commit()
    return row


def _cluster(sig, count=5, src='file:syslog', sev=3, label=None):
    """A cluster shaped exactly like serverreport/normalize.py emits.

    src is a qualified key ("file:syslog", "journal:nginx.service",
    "docker:web.1.abc") and sev is an int (2 warn, 3 error, 4 crit) - not the
    bare family names and severity strings an earlier fixture invented.
    """
    return {'sig': sig, 'count': count, 'src': src, 'sev': sev, 'label': label or sig}


@pytest.fixture()
def models():
    import database
    return database


@pytest.fixture()
def db(ctx):
    from database import db
    return db


def test_failed_unit_cluster_produces_the_restart_card(models, db, host):
    report = _report(db, host, [_cluster('Failed to start nginx.service', count=3)])
    summary = matcher.match_report(report, models, db, with_ideas=False)
    assert 'restart-failed-units' in summary['matched']
    card = models.RemediationMatch.query.filter_by(report_id=report.id, slug='restart-failed-units').first()
    assert card is not None
    assert card.executable is True
    assert card.source == 'catalog'
    assert card.code_text and card.verify_text and card.risk


def test_a_healthy_unrelated_cluster_matches_nothing(models, db, host):
    report = _report(db, host, [_cluster('Started Session 42 of user root', count=900, src='journal')])
    summary = matcher.match_report(report, models, db, with_ideas=False)
    assert summary['matched'] == []
    assert models.RemediationMatch.query.filter_by(report_id=report.id).count() == 0


def test_min_count_is_respected(models, db, host):
    # restart-failed-units needs at least 2 occurrences.
    report = _report(db, host, [_cluster('Failed to start thing.service', count=1)])
    summary = matcher.match_report(report, models, db, with_ideas=False)
    assert 'restart-failed-units' not in summary['matched']


def test_source_filter_is_respected(models, db, host):
    entries = [e for e in matcher.catalog.load_all() if e['slug'] == 'restart-failed-units']
    report = _report(db, host, [_cluster('Failed to start thing.service', count=9, src='docker:web.1.abc')])
    summary = matcher.match_report(report, models, db, entries=entries, with_ideas=False)
    assert summary['matched'] == []


def test_a_file_qualified_source_matches_the_rule_family(models, db, host):
    """Regression: `source: syslog` must match the real `file:syslog` key.

    Before this was fixed every rule was skipped, so no report could ever
    produce a card - the feature was invisible in production."""
    from remediation import matcher as m
    assert m._source_matches('file:syslog', {'syslog'}) is True
    assert m._source_matches('journal:nginx.service', {'journal'}) is True
    assert m._source_matches('docker:web.1.abc', {'docker'}) is True
    assert m._source_matches('file:auth.log', {'syslog'}) is False
    assert m._source_matches('file:syslog', set()) is True


def test_a_journal_cluster_can_match_a_systemd_remedy(models, db, host):
    report = _report(db, host, [_cluster('Failed to start nginx.service',
                                         count=3, src='journal:nginx.service')])
    summary = matcher.match_report(report, models, db, with_ideas=False)
    assert 'restart-failed-units' in summary['matched']


def test_a_rule_can_accept_several_source_families():
    from remediation import matcher as m
    rule = {'signature_regex': 'x', 'source': ['syslog', 'journal']}
    assert m._wanted_sources(rule) == {'syslog', 'journal'}
    assert m._wanted_sources({'source': 'docker'}) == {'docker'}
    assert m._wanted_sources({}) == set()


def test_unknown_verdict_suppresses_every_card(models, db, host):
    report = _report(db, host, [_cluster('Failed to start nginx.service', count=5)], verdict='unknown')
    summary = matcher.match_report(report, models, db, with_ideas=False)
    assert summary['suppressed'] == 'verdict unknown'
    assert summary['matched'] == []
    assert models.RemediationMatch.query.filter_by(report_id=report.id).count() == 0


def test_truncated_evidence_suppresses_every_card(models, db, host):
    report = _report(db, host, [_cluster('Failed to start nginx.service', count=5)], truncated=True)
    summary = matcher.match_report(report, models, db, with_ideas=False)
    assert summary['suppressed'] == 'evidence truncated'
    assert summary['matched'] == []


def test_confidence_is_higher_with_more_evidence(models, db, host):
    low = _report(db, host, [_cluster('Failed to start a.service', count=2)])
    high = _report(db, host, [_cluster('Failed to start a.service', count=200, sev=4)], verdict='failing')
    matcher.match_report(low, models, db, with_ideas=False)
    matcher.match_report(high, models, db, with_ideas=False)
    low_card = models.RemediationMatch.query.filter_by(report_id=low.id, slug='restart-failed-units').first()
    high_card = models.RemediationMatch.query.filter_by(report_id=high.id, slug='restart-failed-units').first()
    assert high_card.confidence > low_card.confidence
    assert 0.5 <= low_card.confidence <= 0.95
    assert high_card.confidence <= 0.95


def test_refresh_is_idempotent(models, db, host):
    report = _report(db, host, [_cluster('Failed to start nginx.service', count=4)])
    first = matcher.match_report(report, models, db, with_ideas=False)
    second = matcher.match_report(report, models, db, with_ideas=False)
    assert first['matched'] == second['matched']
    assert second['created'] == 0
    assert models.RemediationMatch.query.filter_by(
        report_id=report.id, slug='restart-failed-units').count() == 1
    assert len(first['matched']) == models.RemediationMatch.query.filter_by(report_id=report.id).count()


def test_a_card_whose_cluster_disappears_is_withdrawn(models, db, host):
    report = _report(db, host, [_cluster('Failed to start nginx.service', count=4)])
    matcher.match_report(report, models, db, with_ideas=False)
    assert models.RemediationMatch.query.filter_by(report_id=report.id).count() >= 1
    report.clusters_json = json.dumps([])
    db.session.commit()
    matcher.match_report(report, models, db, with_ideas=False)
    assert models.RemediationMatch.query.filter_by(report_id=report.id).count() == 0


def test_a_dismissed_card_survives_a_refresh(models, db, host):
    report = _report(db, host, [_cluster('Failed to start nginx.service', count=4)])
    matcher.match_report(report, models, db, with_ideas=False)
    card = models.RemediationMatch.query.filter_by(report_id=report.id).first()
    card.state = 'dismissed'
    db.session.commit()
    matcher.match_report(report, models, db, with_ideas=False)
    assert models.RemediationMatch.query.get(card.id) is not None
    assert models.RemediationMatch.query.get(card.id).state == 'dismissed'


def test_model_suggestions_are_never_executable(models, db, host, monkeypatch):
    monkeypatch.setattr(matcher.suggestions, 'propose', lambda *a, **kw: [{
        'title': 'Investigate the thing', 'rationale': 'Something looks odd',
        'risk': 'low', 'code': 'grep -c thing /var/log/syslog', 'verify': 'tail -5 /var/log/syslog',
        'rollback': 'nothing changed',
    }])
    monkeypatch.setattr(matcher.policy, 'idea_channel_enabled', lambda: True)
    report = _report(db, host, [_cluster('Started Session 7', count=3)])
    summary = matcher.match_report(report, models, db, with_ideas=True)
    assert summary['ideas'] == 1
    idea = models.RemediationMatch.query.filter_by(report_id=report.id, source='llm').first()
    assert idea is not None
    assert idea.executable is False
    assert idea.slug is None
    assert idea.code_text


def test_the_idea_channel_can_be_turned_off(models, db, host, monkeypatch):
    monkeypatch.setattr(matcher.suggestions, 'propose', lambda *a, **kw: [{
        'title': 't', 'rationale': 'r', 'risk': 'low', 'code': 'true', 'verify': 'true', 'rollback': ''}])
    monkeypatch.setattr(matcher.policy, 'idea_channel_enabled', lambda: False)
    report = _report(db, host, [_cluster('Started Session 7', count=3)])
    summary = matcher.match_report(report, models, db, with_ideas=True)
    assert summary['ideas'] == 0


def test_at_most_one_idea_pass_per_report(models, db, host, monkeypatch):
    calls = {'n': 0}

    def propose(*a, **kw):
        calls['n'] += 1
        return [{'title': 't', 'rationale': 'r', 'risk': 'low',
                 'code': 'true', 'verify': 'true', 'rollback': ''}]
    monkeypatch.setattr(matcher.suggestions, 'propose', propose)
    monkeypatch.setattr(matcher.policy, 'idea_channel_enabled', lambda: True)
    report = _report(db, host, [_cluster('Started Session 7', count=3)])
    matcher.match_report(report, models, db, with_ideas=True)
    matcher.match_report(report, models, db, with_ideas=True)
    assert calls['n'] == 1
