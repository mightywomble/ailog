"""Report-to-report diffing."""
import json

import pytest

from serverreport import diff


def payload(**kw):
    base = {
        'id': 1, 'created_at': '2026-10-29T10:00:00', 'verdict': 'healthy',
        'window_minutes': 120, 'events_total': 100, 'clusters_total': 3,
        'sources_ok': 10, 'sources_failed': 0,
        'severity': {'crit': 0, 'error': 1, 'warn': 2, 'info': 97},
        'clusters': [
            {'sig': 'a', 'src': 'syslog', 'label': 'alpha', 'sev': 2, 'count': 10},
            {'sig': 'b', 'src': 'syslog', 'label': 'beta', 'sev': 1, 'count': 5},
        ],
        'correlations': [
            {'a': {'sig': 'a'}, 'b': {'sig': 'b'}, 'lift': 5, 'score': 12},
        ],
    }
    base.update(kw)
    return base


def test_no_previous_means_no_diff():
    assert diff.compare(None, payload()) == {'has_previous': False}
    assert diff.compare(payload(), None) == {'has_previous': False}


def test_identical_reports_report_no_material_change():
    result = diff.compare(payload(), payload(id=2))
    assert result['has_previous'] is True
    assert result['verdict_changed'] is False
    assert result['clusters'] == {'common': 2, 'new': 0, 'gone': 0}
    assert result['summary'] == 'no material change'


def test_new_and_gone_clusters():
    previous = payload()
    current = payload(id=2, clusters=[
        {'sig': 'a', 'src': 'syslog', 'label': 'alpha', 'sev': 2, 'count': 10},
        {'sig': 'c', 'src': 'dockerd', 'label': 'gamma', 'sev': 3, 'count': 40},
    ])
    result = diff.compare(previous, current)
    assert result['clusters'] == {'common': 1, 'new': 1, 'gone': 1}
    assert [c['sig'] for c in result['new_clusters']] == ['c']
    assert [c['sig'] for c in result['gone_clusters']] == ['b']
    assert '1 new signature(s), 1 gone' in result['summary']


def test_cluster_identity_includes_source():
    """The same signature on a different source is a different cluster."""
    previous = payload(clusters=[{'sig': 'a', 'src': 'syslog', 'count': 1}])
    current = payload(id=2, clusters=[{'sig': 'a', 'src': 'dockerd', 'count': 1}])
    result = diff.compare(previous, current)
    assert result['clusters'] == {'common': 0, 'new': 1, 'gone': 1}


def test_noisier_cluster_is_flagged():
    previous = payload(clusters=[{'sig': 'a', 'src': 's', 'count': 10}])
    current = payload(id=2, clusters=[{'sig': 'a', 'src': 's', 'count': 60}])
    result = diff.compare(previous, current)
    assert result['clusters']['new'] == 0
    assert [c['sig'] for c in result['louder_clusters']] == ['a']


def test_small_increase_is_not_noise_flagged():
    previous = payload(clusters=[{'sig': 'a', 'src': 's', 'count': 10}])
    current = payload(id=2, clusters=[{'sig': 'a', 'src': 's', 'count': 12}])
    assert diff.compare(previous, current)['louder_clusters'] == []


def test_verdict_change_is_reported():
    result = diff.compare(payload(verdict='healthy'),
                          payload(id=2, verdict='degraded'))
    assert result['verdict_changed'] is True
    assert result['verdict'] == {'from': 'healthy', 'to': 'degraded'}
    assert result['summary'].startswith('verdict healthy -> degraded')


def test_event_delta_and_percentage():
    result = diff.compare(payload(events_total=100), payload(id=2, events_total=250))
    assert result['events']['delta'] == 150
    assert result['events']['pct'] == 150.0
    result = diff.compare(payload(events_total=0), payload(id=2, events_total=5))
    assert result['events']['pct'] is None  # no division by zero


def test_severity_delta_only_lists_changes():
    result = diff.compare(payload(severity={'crit': 0, 'error': 5}),
                          payload(id=2, severity={'crit': 3, 'error': 5}))
    assert list(result['severity']) == ['crit']
    assert result['severity']['crit'] == {'before': 0, 'after': 3, 'delta': 3}


def test_correlation_sets():
    previous = payload(correlations=[{'a': {'sig': 'a'}, 'b': {'sig': 'b'}, 'score': 1}])
    current = payload(id=2, correlations=[{'a': {'sig': 'x'}, 'b': {'sig': 'y'}, 'score': 9}])
    result = diff.compare(previous, current)
    assert result['correlations']['new'] == 1
    assert result['correlations']['gone'] == 1


def test_correlation_identity_is_order_independent():
    previous = payload(correlations=[{'a': {'sig': 'a'}, 'b': {'sig': 'b'}, 'score': 1}])
    current = payload(id=2, correlations=[{'a': {'sig': 'b'}, 'b': {'sig': 'a'}, 'score': 1}])
    result = diff.compare(previous, current)
    assert result['correlations']['new'] == 0


def test_items_are_capped_for_display():
    many = [{'sig': f's{i}', 'src': 'x', 'count': i} for i in range(50)]
    result = diff.compare(payload(clusters=[]), payload(id=2, clusters=many))
    assert len(result['new_clusters']) == diff.MAX_ITEMS
    assert result['clusters']['new'] == 50


def test_report_payload_reads_stored_json(ctx):
    from database import LogReport, db
    row = LogReport(
        host_key='db-1', host_label='one', window_minutes=60, verdict='Degraded',
        events_total=10, clusters_total=2, sources_ok=3, sources_failed=1,
        severity_json=json.dumps({'error': 3}),
        clusters_json=json.dumps([{'sig': 'a', 'src': 's', 'count': 4}]),
        correlations_json=json.dumps([]),
    )
    db.session.add(row)
    db.session.commit()
    data = diff.report_payload(row)
    assert data['verdict'] == 'degraded'
    assert data['severity'] == {'error': 3}
    assert data['clusters'][0]['sig'] == 'a'
    assert data['sources_failed'] == 1


def test_report_payload_tolerates_bad_json(ctx):
    from database import LogReport, db
    row = LogReport(host_key='db-2', clusters_json='not json',
                    severity_json='{', correlations_json=None)
    db.session.add(row)
    db.session.commit()
    data = diff.report_payload(row)
    assert data['clusters'] == []
    assert data['severity'] == {}
