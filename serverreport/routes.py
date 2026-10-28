"""HTTP surface for server-wide correlated log reports.

``POST /serverreport/stream`` drives the whole pipeline and streams staged
progress over SSE, because a 2 hour window across ~40 sources takes tens of
seconds and a frozen browser is indistinguishable from a hang.

The pipeline is:

    collect (time-windowed) -> normalise (clusters) -> correlate (lift/bursts/gaps)
    -> pack (compact evidence) -> model (one call) -> store -> /reports/<id>
"""
import datetime
import json
import queue
import threading
import time

from flask import (Blueprint, Response, current_app, jsonify, redirect,
                   render_template, request, stream_with_context, url_for)

from database import LogReport, db
from . import collect, correlate, llm, normalize, pack

reports_bp = Blueprint('serverreport', __name__)

STREAM_HEADERS = {
    'Cache-Control': 'no-cache, no-transform',
    'X-Accel-Buffering': 'no',
    'Connection': 'keep-alive',
}

DEFAULT_MODEL = 'gpt-3.5-turbo'
PROVIDER_LABELS = {'openai': 'OpenAI', 'ollama': 'Ollama', 'openrouter': 'OpenRouter'}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _app():
    import app as app_module
    return app_module


def _host_label(host_key):
    app = _app()
    try:
        for host_id, name in app._get_all_host_choices():
            if host_id == host_key:
                return name
    except Exception:
        pass
    return host_key


def _configured_provider():
    """The provider configured in Settings (the one the rest of the app uses)."""
    try:
        return _app().load_config().get('analysis_provider') or 'openai'
    except Exception:
        return 'openai'


def _defaults():
    """Dialog defaults.

    The model default must follow the *configured provider*: sending
    ``gpt-3.5-turbo`` to OpenRouter (or Ollama) is an unknown-model 404, so the
    provider's own configured model wins for anything other than OpenAI.
    """
    app = _app()
    try:
        window = int(app._setting_get('report.window_minutes', collect.DEFAULT_WINDOW_MINUTES)
                     or collect.DEFAULT_WINDOW_MINUTES)
    except Exception:
        window = collect.DEFAULT_WINDOW_MINUTES
    if window not in collect.ALLOWED_WINDOWS:
        window = collect.DEFAULT_WINDOW_MINUTES

    provider = _configured_provider()
    model = None
    try:
        config = app.load_config()
        if provider == 'ollama':
            model = config.get('ollama_model')
        elif provider == 'openrouter':
            model = config.get('openrouter_model')
        else:
            model = app._setting_get('report.default_model', DEFAULT_MODEL) or DEFAULT_MODEL
    except Exception:
        model = DEFAULT_MODEL if provider == 'openai' else None

    return {'window_minutes': window, 'model': model, 'provider': provider}


def _naive_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return dt


def _scope_note(include_files, include_journal, include_docker, include_stopped):
    parts = []
    if include_files:
        parts.append('files')
    if include_journal:
        parts.append('journald')
    if include_docker:
        parts.append('docker container logs' + ('' if include_stopped else ', running only'))
    return ', '.join(parts) or 'nothing selected'


# ---------------------------------------------------------------------------
# pipeline
# ---------------------------------------------------------------------------

def run_pipeline(host_key, host_label, window_minutes, provider, model, data,
                 include_files=True, include_journal=True, include_docker=True,
                 include_stopped=False, emit=None, app=None):
    """Run the full report pipeline and persist the result.

    Returns the saved ``LogReport``. ``emit`` receives progress dicts.
    """
    app_module = _app()

    def note(stage, message, **extra):
        if emit:
            payload = {'type': 'stage', 'stage': stage, 'message': message}
            payload.update(extra)
            try:
                emit(payload)
            except Exception:
                pass

    started = time.time()

    note('collect', f'Enumerating and fetching sources for the last {window_minutes} minutes...')
    collected = collect.collect_host_logs(
        host_key,
        host_label=host_label,
        window_minutes=window_minutes,
        include_files=include_files,
        include_journal=include_journal,
        include_docker=include_docker,
        include_stopped=include_stopped,
        app=app,
        progress=lambda p: emit({'type': 'stage', 'stage': 'collect',
                                 'message': p.get('message', ''), **{
                                     k: v for k, v in p.items()
                                     if k in ('sources_done', 'sources_total')
                                 }}) if emit else None,
    )

    window_start, window_end = collected['window_start'], collected['window_end']
    sources = collected['sources']

    def _status(item):
        # Older/simpler collectors may only set ``ok``; treat a missing status
        # as ok-or-error rather than silently dropping the source.
        return item.get('status') or ('ok' if item.get('ok') else 'error')

    ok_sources = [s for s in sources if _status(s) == 'ok']
    empty_sources = [s for s in sources if _status(s) == 'empty']
    failed_sources = [s for s in sources if _status(s) == 'error']

    if not ok_sources:
        detail = ''
        if failed_sources:
            detail = f" {len(failed_sources)} source(s) errored, e.g. {failed_sources[0].get('error')}."
        raise RuntimeError(
            'No log data could be collected for this window.'
            + detail
            + ' Check SSH/sudo access and that logs were written during the window.'
        )

    note('normalise', f'Normalising {len(ok_sources)} source(s)...')
    norm = normalize.normalize_all(sources, window_start, window_end)
    events, clusters = norm['events'], norm['clusters']
    note('normalise', f'{len(events):,} events reduced to {len(clusters):,} distinct signatures.',
         clusters_total=len(clusters))

    note('correlate', 'Checking cross-source correlations...')
    containers = []
    if include_docker:
        docker_sources = [s['source'] for s in sources if s['source']['kind'] == 'docker']
        containers = collect.container_states(host_key, docker_sources)
    corr = correlate.correlate(events, clusters, containers, window_start, window_end)
    note('correlate',
         f"{len(corr['correlations'])} correlation(s), {len(corr['bursts'])} burst(s), "
         f"{len(corr['gaps'])} gap(s) found.",
         correlations=len(corr['correlations']))

    note('summarise', 'Building evidence pack...')
    evidence = pack.build_pack(host_label, norm, corr, collected, containers)
    evidence, fitted = pack.fit_pack(evidence)
    tokens_in = pack.estimate_tokens(evidence)

    note('summarise', f'Contacting {PROVIDER_LABELS.get(provider, provider)} '
                      f'({model}) with ~{tokens_in:,} tokens of evidence...')

    cfg = app_module._analysis_config(provider, data, model=model)
    scope_note = _scope_note(include_files, include_journal, include_docker, include_stopped)

    def _generate(evidence_text, max_tokens):
        return llm.generate_report(
            provider, cfg, host_label, evidence_text, window_minutes,
            scope_note, max_tokens=max_tokens,
        )

    try:
        markdown, meta = _generate(evidence, 2500)
    except llm.EmptyReportError as first_exc:
        # Reasoning-heavy models can spend the whole completion budget on
        # reasoning and return nothing. Retry once with a smaller pack and a
        # larger cap rather than failing the run outright.
        note('summarise', 'Model returned no content; retrying with a trimmed evidence pack...')
        trimmed, _ = pack.fit_pack(evidence, max_tokens=max(1000, int(pack.MAX_PACK_TOKENS * 0.55)))
        tokens_in = pack.estimate_tokens(trimmed)
        evidence = trimmed
        try:
            markdown, meta = _generate(evidence, 4000)
        except Exception as exc:
            raise RuntimeError(f'Model call failed: {first_exc}; retry also failed: {exc}')
    except Exception as exc:
        raise RuntimeError(f'Model call failed: {exc}')

    note('report', 'Saving report...')

    report = LogReport(
        host_key=host_key,
        host_label=host_label,
        window_minutes=window_minutes,
        window_start=_naive_utc(window_start),
        window_end=_naive_utc(window_end),
        provider=meta.get('provider') or provider,
        model=meta.get('model') or model,
        verdict=meta.get('verdict') or 'unknown',
        sources_total=len(sources),
        sources_ok=len(ok_sources),
        sources_failed=len(failed_sources),
        events_total=len(events),
        clusters_total=len(clusters),
        severity_json=json.dumps(norm['severity_counts']),
        timeline_json=json.dumps(corr['timeline']),
        correlations_json=json.dumps(corr['correlations']),
        containers_json=json.dumps(containers),
        coverage_json=json.dumps({
            'source_stats': norm['source_stats'],
            'errors': collected.get('errors') or [],
            'sources_empty': len(empty_sources),
            'sources_failed': len(failed_sources),
            'gaps': corr['gaps'],
            'bursts': corr['bursts'],
            'truncated': bool(collected.get('truncated')),
            'pack_fitted': fitted,
            'missing_headings': meta.get('missing_headings') or [],
        }),
        evidence_text=evidence,
        tokens_in=meta.get('tokens_in') or tokens_in,
        tokens_out=meta.get('tokens_out'),
        duration_ms=int((time.time() - started) * 1000),
        report_markdown=markdown,
    )
    db.session.add(report)
    db.session.commit()
    # The pipeline runs in its own thread with its own session, so hand back a
    # plain dict: the ORM instance is detached (and expired) by the time the
    # SSE generator touches it.
    payload = report.to_dict()
    payload['id'] = report.id
    return payload


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------

@reports_bp.route('/api/serverreport/defaults', methods=['GET'])
def api_defaults():
    """Dialog defaults + whether a provider is configured at all."""
    app_module = _app()
    config = app_module.load_config()
    provider = config.get('analysis_provider', 'openai')
    ready = False
    if provider == 'openai':
        ready = bool(config.get('openai_api_key'))
    elif provider == 'ollama':
        ready = bool(config.get('ollama_url') and config.get('ollama_model'))
    elif provider == 'openrouter':
        ready = bool(config.get('openrouter_api_key') and config.get('openrouter_model'))
    defaults = _defaults()
    defaults.update({
        'provider': provider,
        'provider_label': PROVIDER_LABELS.get(provider, provider),
        'provider_configured': ready,
        'windows': list(collect.ALLOWED_WINDOWS),
        'max_sources': collect.MAX_SOURCES,
        'max_tokens': pack.MAX_PACK_TOKENS,
    })
    return jsonify(defaults)


@reports_bp.route('/serverreport/stream', methods=['POST'])
def stream_report():
    data = request.get_json(silent=True) or {}
    host_key = (data.get('host_key') or '').strip()
    if not host_key:
        return jsonify({'error': 'Missing host_key.'}), 400

    window_minutes = collect.clamp_window(data.get('window_minutes', _defaults()['window_minutes']))
    provider = (data.get('provider') or '').strip() or _configured_provider()
    if provider not in PROVIDER_LABELS:
        return jsonify({'error': f'Unknown provider: {provider}'}), 400
    requested_model = (data.get('model') or '').strip()
    defaults = _defaults()
    if requested_model:
        model = requested_model
    elif provider == defaults['provider']:
        model = defaults['model']
    else:
        # Different provider than the configured one: let the provider's own
        # configured model apply rather than guessing another provider's name.
        model = None

    try:
        app_module = _app()
        # Fail fast on missing credentials so the browser does not watch a
        # "contacting..." spinner for a request that cannot succeed.
        app_module._analysis_config(provider, data, model=model or None)
    except Exception as exc:
        return jsonify({'error': str(exc)}), 400

    host_label = _host_label(host_key)
    include_files = bool(data.get('include_files', True))
    include_journal = bool(data.get('include_journal', True))
    include_docker = bool(data.get('include_docker', True))
    include_stopped = bool(data.get('include_stopped', False))

    def generate():
        def ev(payload):
            return 'data: ' + json.dumps(payload, default=str) + '\n\n'

        started = time.time()

        def elapsed():
            return round(time.time() - started, 1)

        yield ': connected\n\n'
        yield 'retry: 5000\n\n'
        yield ev({'type': 'stage', 'stage': 'prepare', 'elapsed': 0,
                  'message': f'Preparing report for {host_label} '
                             f'({_scope_note(include_files, include_journal, include_docker, include_stopped)})...'})

        box = queue.Queue()

        try:
            worker_app = current_app._get_current_object()
        except RuntimeError:
            worker_app = None

        def work():
            def run():
                return run_pipeline(
                    host_key, host_label, window_minutes, provider, model, data,
                    include_files=include_files,
                    include_journal=include_journal,
                    include_docker=include_docker,
                    include_stopped=include_stopped,
                    emit=lambda p: box.put(('progress', p)),
                    app=worker_app,
                )

            try:
                if worker_app is not None:
                    with worker_app.app_context():
                        report = run()
                else:
                    report = run()
                box.put(('ok', report))
            except Exception as exc:  # noqa: BLE001 - surfaced to the browser
                box.put(('error', str(exc)))

        threading.Thread(target=work, daemon=True).start()

        while True:
            try:
                kind, payload = box.get(timeout=2.5)
            except queue.Empty:
                secs = int(time.time() - started)
                yield ev({'type': 'stage', 'stage': 'waiting', 'elapsed': secs,
                          'message': f'Still working... {secs}s'})
                continue

            if kind == 'progress':
                payload.setdefault('elapsed', elapsed())
                yield ev(payload)
                continue

            if kind == 'error':
                yield ev({'type': 'error', 'message': payload, 'elapsed': elapsed()})
                return

            report = payload
            yield ev({'type': 'result',
                      'report_id': report['id'],
                      'url': url_for('serverreport.view_report', report_id=report['id']),
                      'verdict': report.get('verdict'),
                      'provider': report.get('provider'),
                      'model': report.get('model'),
                      'tokens_in': report.get('tokens_in'),
                      'tokens_out': report.get('tokens_out'),
                      'duration_ms': report.get('duration_ms'),
                      'sources_ok': report.get('sources_ok'),
                      'sources_failed': report.get('sources_failed'),
                      'elapsed': elapsed()})
            return

    return Response(stream_with_context(generate()), mimetype='text/event-stream',
                    headers=STREAM_HEADERS)


@reports_bp.route('/reports')
def list_reports():
    host = (request.args.get('host') or '').strip()
    query = LogReport.query
    if host:
        query = query.filter(LogReport.host_key == host)
    reports = query.order_by(LogReport.created_at.desc()).limit(100).all()
    return render_template('reports.html', reports=reports, host_filter=host)


@reports_bp.route('/reports/<int:report_id>')
def view_report(report_id):
    report = LogReport.query.get(report_id)
    if not report:
        return render_template('report.html', report=None, report_id=report_id), 404
    return render_template('report.html', report=report, report_id=report_id)


@reports_bp.route('/reports/<int:report_id>/markdown')
def download_markdown(report_id):
    report = LogReport.query.get(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    filename = f"ailog-report-{report.host_key.replace('/', '_')}-{report.id}.md"
    body = report.report_markdown or report.error or ''
    return Response(body, mimetype='text/markdown',
                    headers={'Content-Disposition': f'attachment; filename="{filename}"'})


@reports_bp.route('/reports/<int:report_id>/discord', methods=['POST'])
def send_to_discord(report_id):
    """Explicit, on-request only: nothing posts to Discord automatically."""
    report = LogReport.query.get(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404

    app_module = _app()
    data = request.get_json(silent=True) or {}
    webhook_url = (data.get('webhook_url') or app_module.load_config().get('webhook_url') or '').strip()
    if not webhook_url:
        return jsonify({'error': 'No Discord webhook configured.'}), 400
    if not report.report_markdown:
        return jsonify({'error': 'This report has no content to send.'}), 400

    try:
        summary = report.report_markdown
        if len(summary) > 1800:
            summary = summary[:1800].rstrip() + '\n\n…(truncated, see the full report)'
        title = f"Server report: {report.host_label} ({report.window_minutes}m)"
        app_module.send_discord_status(
            webhook_url,
            f'{title}\nVerdict: {str(report.verdict or "unknown").upper()}',
            report.host_key,
            summary,
        )
        return jsonify({'success': True})
    except Exception as exc:
        return jsonify({'error': f'Discord send failed: {exc}'}), 500


@reports_bp.route('/api/reports')
def api_reports():
    host = (request.args.get('host') or '').strip()
    limit = min(int(request.args.get('limit', 50) or 50), 200)
    query = LogReport.query
    if host:
        query = query.filter(LogReport.host_key == host)
    reports = query.order_by(LogReport.created_at.desc()).limit(limit).all()
    return jsonify({'reports': [r.to_dict() for r in reports]})


@reports_bp.route('/api/reports/<int:report_id>', methods=['GET', 'DELETE'])
def api_report(report_id):
    report = LogReport.query.get(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    if request.method == 'DELETE':
        db.session.delete(report)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify(report.to_dict(include_markdown=True))
