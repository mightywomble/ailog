"""Scheduled report runs (Schedule.kind == 'report')."""
import json

import pytest


@pytest.fixture()
def clean_schedules(ctx):
    from database import Schedule, ScheduleHost, ScheduleSource, db
    ScheduleSource.query.delete()
    ScheduleHost.query.delete()
    Schedule.query.delete()
    db.session.commit()
    yield
    ScheduleSource.query.delete()
    ScheduleHost.query.delete()
    Schedule.query.delete()
    db.session.commit()


def test_schedule_defaults_to_log_kind(client, ctx, clean_schedules):
    body = client.post('/api/schedules', json={'name': 's1', 'enabled': False}).get_json()
    assert body['kind'] == 'log'
    assert body['report_scope'] == {}


def test_schedule_accepts_report_fields(client, ctx, clean_schedules):
    body = client.post('/api/schedules', json={
        'name': 'nightly report', 'enabled': False, 'interval_hours': 24,
        'kind': 'report', 'hosts': ['db-1'],
        'report_window_minutes': 1440, 'report_depth': 4,
        'report_model': 'openai/gpt-4o-mini',
        'report_scope': {'files': True, 'journal': False,
                         'docker': True, 'stopped': False},
    }).get_json()

    assert body['kind'] == 'report'
    assert body['report_window_minutes'] == 1440
    assert body['report_depth'] == 4
    assert body['report_model'] == 'openai/gpt-4o-mini'
    assert body['report_scope']['journal'] is False


def test_unknown_kind_falls_back_to_log(client, ctx, clean_schedules):
    body = client.post('/api/schedules',
                       json={'name': 'x', 'kind': 'banana'}).get_json()
    assert body['kind'] == 'log'


def test_update_switches_kind_and_keeps_fields(client, ctx, clean_schedules):
    created = client.post('/api/schedules', json={'name': 'y'}).get_json()
    updated = client.put(f"/api/schedules/{created['id']}",
                         json={'kind': 'report', 'report_window_minutes': 30}).get_json()
    assert updated['kind'] == 'report'
    assert updated['report_window_minutes'] == 30


def test_bad_report_window_is_ignored(client, ctx, clean_schedules):
    created = client.post('/api/schedules', json={'name': 'z'}).get_json()
    updated = client.put(f"/api/schedules/{created['id']}",
                         json={'report_window_minutes': 'soon'}).get_json()
    assert updated['report_window_minutes'] is None


def test_report_schedule_runs_pipeline_per_host(app_module, ctx, clean_schedules,
                                                monkeypatch, host):
    from database import Schedule, ScheduleHost, db
    from serverreport import routes as report_routes

    schedule = Schedule(name='report run', enabled=True, interval_hours=24,
                        kind='report', report_window_minutes=60,
                        report_depth=3,
                        report_scope_json=json.dumps({'files': True,
                                                      'journal': False,
                                                      'docker': True}))
    db.session.add(schedule)
    db.session.flush()
    db.session.add(ScheduleHost(schedule_id=schedule.id, host_id=host))
    db.session.add(ScheduleHost(schedule_id=schedule.id, host_id='local'))
    db.session.commit()

    calls = []

    def fake_run(host_key, host_label, window, provider, model, data, **kw):
        calls.append({'host': host_key, 'window': window, 'depth': kw.get('depth'),
                      'files': kw.get('include_files'), 'journal': kw.get('include_journal'),
                      'docker': kw.get('include_docker'), 'model': model})
        return {'id': 99 + len(calls), 'verdict': 'degraded'}

    monkeypatch.setattr(report_routes, 'run_pipeline', fake_run)

    emitted = []
    app_module._run_schedule(schedule, emit=lambda payload: emitted.append(payload))

    assert len(calls) == 2
    assert calls[0]['window'] == 60
    assert calls[0]['depth'] == 3
    assert calls[0]['journal'] is False
    assert calls[0]['docker'] is True

    db.session.refresh(schedule)
    assert schedule.last_run_at is not None
    status = json.loads(schedule.last_status)
    assert [entry['report_id'] for entry in status] == [100, 101]
    assert any('report(s) stored' in (p.get('message') or '') for p in emitted)


def test_report_schedule_records_per_host_failure(app_module, ctx, clean_schedules,
                                                  monkeypatch):
    from database import Schedule, ScheduleHost, db
    from serverreport import routes as report_routes

    schedule = Schedule(name='failing', enabled=True, interval_hours=24,
                        kind='report')
    db.session.add(schedule)
    db.session.flush()
    db.session.add(ScheduleHost(schedule_id=schedule.id, host_id='db-404'))
    db.session.commit()

    def boom(*a, **kw):
        raise RuntimeError('collection failed')

    monkeypatch.setattr(report_routes, 'run_pipeline', boom)
    app_module._run_schedule(schedule, emit=lambda payload: None)

    db.session.refresh(schedule)
    status = json.loads(schedule.last_status)
    assert 'collection failed' in status[0]['error']


def test_log_schedule_still_uses_the_analysis_path(app_module, ctx, clean_schedules,
                                                   monkeypatch):
    """kind='log' must not accidentally run reports."""
    from database import Schedule, db

    schedule = Schedule(name='logs', enabled=True, interval_hours=6, kind='log')
    db.session.add(schedule)
    db.session.commit()

    called = {}
    monkeypatch.setattr(app_module, '_do_analysis_task',
                        lambda emit=None: called.setdefault('analysis', True))
    monkeypatch.setattr(app_module, '_run_report_schedule',
                        lambda *a, **kw: called.setdefault('report', True))

    app_module._run_schedule(schedule, emit=lambda payload: None)
    assert called == {'analysis': True}


def test_scheduler_registers_one_job_per_enabled_schedule(app_module, ctx,
                                                          clean_schedules):
    from database import Schedule, db
    db.session.add(Schedule(name='a', enabled=True, interval_hours=3))
    db.session.add(Schedule(name='b', enabled=False, interval_hours=3))
    db.session.commit()

    app_module._sync_scheduler_jobs_from_db()
    jobs = [job.id for job in app_module.scheduler.get_jobs()
            if job.id.startswith('schedule_')]
    assert len(jobs) == 1
