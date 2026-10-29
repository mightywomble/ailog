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
import math
import queue
import threading
import time

from flask import (Blueprint, Response, current_app, jsonify, redirect,
                   render_template, request, stream_with_context, url_for)

from database import LogReport, db
from . import diff as rdiff
from . import collect, correlate, llm, normalize, pack, severity, sizing

reports_bp = Blueprint('serverreport', __name__)

STREAM_HEADERS = {
    'Cache-Control': 'no-cache, no-transform',
    'X-Accel-Buffering': 'no',
    'Connection': 'keep-alive',
}

DEFAULT_MODEL = 'openai/gpt-4o-mini'
PROVIDER_LABELS = {'openai': 'OpenAI', 'ollama': 'Ollama', 'openrouter': 'OpenRouter'}

# A size check and the run that follows it should not collect the host twice.
# Bundles are single-use and short-lived.
BUNDLE_TTL_SECONDS = 300
_bundle_lock = threading.Lock()
_bundles = {}


def _bundle_key(host_key, window_minutes, include_files, include_journal, include_docker,
                include_stopped, sev_levels=None):
    # The severity selection is part of the identity: reusing a cached
    # "errors only" snapshot for an unfiltered run (or vice versa) would make
    # the report describe data the user did not ask for.
    return (host_key, int(window_minutes), bool(include_files), bool(include_journal),
            bool(include_docker), bool(include_stopped),
            tuple(sorted(sev_levels or ())))


def _bundle_put(key, payload):
    with _bundle_lock:
        now = time.time()
        for stale in [k for k, v in _bundles.items() if now - v[0] > BUNDLE_TTL_SECONDS]:
            _bundles.pop(stale, None)
        _bundles[key] = (now, payload)


def _bundle_take(key):
    with _bundle_lock:
        hit = _bundles.pop(key, None)
    if not hit:
        return None
    age = time.time() - hit[0]
    if age > BUNDLE_TTL_SECONDS:
        return None
    return hit[1]


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
            # Ollama only has whatever is pulled locally.
            model = config.get('ollama_model')
        else:
            # Reports default to a large-context, low-cost model. The
            # provider-level model setting still drives per-log analysis;
            # settings key: report.default_model.
            model = app._setting_get('report.default_model', DEFAULT_MODEL) or DEFAULT_MODEL
    except Exception:
        model = DEFAULT_MODEL if provider == 'openai' else None

    try:
        # 0 = Auto: let the sizing engine choose from the evidence itself.
        depth = int(app._setting_get('report.depth', sizing.AUTO_DEPTH) or 0)
    except Exception:
        depth = sizing.DEFAULT_DEPTH
    if depth not in (0,) and depth not in sizing.DEPTHS:
        depth = sizing.DEFAULT_DEPTH

    return {
        'window_minutes': window,
        'model': model,
        'provider': provider,
        'depth': depth,
        'depths': [
            {'depth': d, 'key': p['key'], 'label': p['label'],
             'description': p['description'], 'max_output_tokens': p['max_output_tokens']}
            for d, p in sorted(sizing.DEPTHS.items())
        ],
    }


def _naive_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return dt


def pack_limits_label(depth):
    try:
        return sizing.DEPTHS[int(depth)]['label']
    except Exception:
        return str(depth)


def _scope_note(include_files, include_journal, include_docker, include_stopped,
                sev_levels=None):
    parts = []
    if include_files:
        parts.append('files')
    if include_journal:
        parts.append('journald')
    if include_docker:
        parts.append('docker container logs' + ('' if include_stopped else ', running only'))
    note = ', '.join(parts) or 'nothing selected'
    levels = frozenset(sev_levels or ())
    if levels:
        note += f" · severity filter: {severity.describe(levels)} only"
    return note


def sev_levels_for(values):
    """Map ``severity.parse`` names onto the normaliser's ``SEV_*`` constants."""
    from .normalize import SEV_CRIT, SEV_ERROR, SEV_WARN
    mapping = {'crit': SEV_CRIT, 'error': SEV_ERROR, 'warn': SEV_WARN}
    return frozenset(mapping[name] for name in (values or ()) if name in mapping)


def _stored_filter(collected, norm):
    """The severity-filter block persisted in ``coverage_json``.

    Merges what the collector did on the host (journal priority / grep) with
    what the normaliser actually dropped, so a stored report can always explain
    why its event counts look the way they do.
    """
    block = dict((norm or {}).get('severity_filter') or {})
    src = (collected or {}).get('severity_filter') or {}
    if src.get('source_prefilter'):
        block['source_prefilter'] = src['source_prefilter']
    levels = block.get('levels') or []
    block.setdefault('active', bool(levels))
    block.setdefault('levels', [])
    block['label'] = severity.describe(levels)
    return block


def sev_names_for(levels):
    """Inverse of :func:`sev_levels_for`: ``SEV_*`` constants -> names."""
    from .normalize import SEV_CRIT, SEV_ERROR, SEV_WARN
    mapping = {SEV_CRIT: 'crit', SEV_ERROR: 'error', SEV_WARN: 'warn'}
    return frozenset(mapping[lvl] for lvl in (levels or ()) if lvl in mapping)


# ---------------------------------------------------------------------------
# pipeline
# ---------------------------------------------------------------------------

def _status_of(item):
    """Older/simpler collectors may only set ``ok``; treat a missing status as
    ok-or-error rather than silently dropping the source."""
    return item.get('status') or ('ok' if item.get('ok') else 'error')


def prepare_bundle(host_key, host_label, window_minutes, include_files, include_journal,
                   include_docker, include_stopped, emit=None, app=None, note=None,
                   use_cache=True, severities=None):
    """Collect, normalise and correlate. Model-free and reusable.

    Shared by the size check and the report run so the host is only ever
    collected once per user action. ``severities`` is a ``severity.parse``
    result; it is applied on the host *and* at normalisation.
    """
    sel = frozenset(severities or ())
    sev_levels = sev_levels_for(sel)
    key = _bundle_key(host_key, window_minutes, include_files, include_journal,
                      include_docker, include_stopped, sel)
    if use_cache:
        cached = _bundle_take(key)
        if cached is not None:
            if note:
                note('collect', 'Reusing the size-check snapshot (no second collection).')
            return cached

    def _note(stage, message, **extra):
        if note:
            note(stage, message, **extra)

    collected = collect.collect_host_logs(
        host_key,
        host_label=host_label,
        window_minutes=window_minutes,
        include_files=include_files,
        include_journal=include_journal,
        include_docker=include_docker,
        include_stopped=include_stopped,
        severities=sel,
        app=app,
        progress=lambda p: emit({'type': 'stage', 'stage': 'collect',
                                 'message': p.get('message', ''), **{
                                     k: v for k, v in p.items()
                                     if k in ('sources_done', 'sources_total')
                                 }}) if emit else None,
    )

    window_start, window_end = collected['window_start'], collected['window_end']
    sources = collected['sources']
    ok_sources = [s for s in sources if _status_of(s) == 'ok']
    empty_sources = [s for s in sources if _status_of(s) == 'empty']
    failed_sources = [s for s in sources if _status_of(s) == 'error']

    if not ok_sources:
        detail = ''
        if failed_sources:
            detail = f" {len(failed_sources)} source(s) errored, e.g. {failed_sources[0].get('error')}."
        raise RuntimeError(
            'No log data could be collected for this window.'
            + detail
            + ' Check SSH/sudo access and that logs were written during the window.'
        )

    _note('normalise', f'Normalising {len(ok_sources)} source(s)...')
    norm = normalize.normalize_all(sources, window_start, window_end, sev_levels=sev_levels)
    events, clusters = norm['events'], norm['clusters']
    if sel:
        _note('normalise',
              f"Severity filter ({severity.describe(sel)}): "
              f"{norm['severity_filter']['events_kept']:,} relevant events, "
              f"{norm['severity_filter']['events_filtered']:,} dropped from context lines.")
    _note('normalise', f'{len(events):,} events reduced to {len(clusters):,} distinct signatures.',
          clusters_total=len(clusters))

    _note('correlate', 'Checking cross-source correlations...')
    containers = []
    if include_docker:
        docker_sources = [s['source'] for s in sources if s['source']['kind'] == 'docker']
        containers = collect.container_states(host_key, docker_sources)
    corr = correlate.correlate(events, clusters, containers, window_start, window_end)
    _note('correlate',
          f"{len(corr['correlations'])} correlation(s), {len(corr['bursts'])} burst(s), "
          f"{len(corr['gaps'])} gap(s) found.",
          correlations=len(corr['correlations']))

    return {
        'severities': sel,
        'collected': collected,
        'norm': norm,
        'corr': corr,
        'containers': containers,
        'window_start': window_start,
        'window_end': window_end,
        'ok_sources': ok_sources,
        'empty_sources': empty_sources,
        'failed_sources': failed_sources,
    }


def run_pipeline(host_key, host_label, window_minutes, provider, model, data,
                 include_files=True, include_journal=True, include_docker=True,
                 include_stopped=False, depth=None, emit=None, app=None, use_cache=True,
                 severities=None):
    """Run the full report pipeline and persist the result.

    Flow: prepare (collect/normalise/correlate) -> build evidence -> size it ->
    optionally chunk (map/reduce) -> one or more model calls -> store.

    Returns a plain dict (the ORM instance is detached once the worker thread
    finishes, so it must not escape).
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

    bundle = prepare_bundle(
        host_key, host_label, window_minutes, include_files, include_journal,
        include_docker, include_stopped, emit=emit, app=app, note=note, use_cache=use_cache,
        severities=severities,
    )

    collected = bundle['collected']
    norm = bundle['norm']
    corr = bundle['corr']
    containers = bundle['containers']
    window_start, window_end = bundle['window_start'], bundle['window_end']
    ok_sources = bundle['ok_sources']
    empty_sources = bundle['empty_sources']
    failed_sources = bundle['failed_sources']
    sources = collected['sources']
    events, clusters = norm['events'], norm['clusters']

    # --- size it before spending anything on the model --------------------
    note('summarise', 'Building evidence pack...')
    # Size the host from the *standard* view (depth 3): measuring the deepest
    # pack would always recommend maximum depth, which defeats the purpose.
    baseline_pack = pack.build_pack(host_label, norm, corr, collected, containers, depth=3)
    baseline_tokens = pack.estimate_tokens(baseline_pack)
    max_pack = pack.build_pack(host_label, norm, corr, collected, containers, depth=5)
    max_tokens = pack.estimate_tokens(max_pack)

    recommendation = sizing.recommend({
        'pack_tokens': baseline_tokens,
        'events': len(events),
        'clusters': len(clusters),
        'sources': len(ok_sources),
        'correlations': len(corr['correlations']),
        'severity': norm['severity_counts'],
        'model_filtered': model or 'the selected model',
    }, model, requested_depth=depth or None)

    profile = recommendation['profile']
    chosen_depth = recommendation['depth']

    # Depth decides what is *sent*, so build the pack at the chosen level.
    evidence = pack.build_pack(host_label, norm, corr, collected, containers, depth=chosen_depth)
    tokens = pack.estimate_tokens(evidence)

    chunks_needed = 1
    if tokens > profile['chunk_at']:
        chunks_needed = max(2, int(math.ceil(tokens / max(1, profile['evidence_tokens']))))

    note('summarise',
         f"Evidence is ~{baseline_tokens:,} tokens at standard depth "
         f"(up to ~{max_tokens:,} at maximum). Suggested: "
         f"{recommendation['depth_label']} depth"
         + (f", {chunks_needed} chunk pass(es)" if chunks_needed > 1 else '')
         + (f", model {recommendation['suggested_model']}" if recommendation['suggest_model'] else '')
         + '.',
         recommendation={
             'depth': chosen_depth,
             'depth_label': recommendation['depth_label'],
             'chunks': chunks_needed,
             'pack_tokens': tokens,
             'suggested_model': recommendation['suggested_model'],
             'suggest_model': recommendation['suggest_model'],
             'rationale': recommendation['rationale'],
         })

    chunks_used = 1
    fitted = False

    if chunks_needed > 1:
        # Map: summarise each slice. Reduce: merge notes into one pack.
        parts = pack.split_pack(evidence, chunks_needed)
        chunks_used = len(parts)
        note('summarise',
             f'Pack is ~{tokens:,} tokens, beyond the {profile["label"]} budget; summarising '
             f'in {chunks_used} passes then merging.')
        digests = []
        for idx, part in enumerate(parts, start=1):
            note('summarise', f'Chunk {idx}/{chunks_used}: extracting findings...',
                 chunk_index=idx, chunk_total=chunks_used)
            digest, _meta = llm.summarise_chunk(
                provider, app_module._analysis_config(provider, data, model=model),
                host_label, part, idx, chunks_used,
            )
            digests.append(digest)
        merged_notes = llm.merge_notes(digests)
        evidence = pack.build_reduced_pack(host_label, [merged_notes], corr)
    elif tokens > profile['evidence_tokens']:
        evidence, fitted = pack.fit_pack(evidence, profile['evidence_tokens'])

    tokens_in = pack.estimate_tokens(evidence)

    note('summarise', f'Contacting {PROVIDER_LABELS.get(provider, provider)} '
                      f'({model}) with ~{tokens_in:,} tokens of evidence...')

    cfg = app_module._analysis_config(provider, data, model=model)
    scope_note = _scope_note(include_files, include_journal, include_docker,
                             include_stopped, bundle.get('severities'))
    max_out = profile['max_output_tokens']

    def _generate(evidence_text, max_tokens):
        return llm.generate_report(
            provider, cfg, host_label, evidence_text, window_minutes,
            scope_note, max_tokens=max_tokens,
        )

    try:
        markdown, meta = _generate(evidence, max_out)
    except llm.EmptyReportError as first_exc:
        # Reasoning-heavy models can spend the whole completion budget on
        # reasoning and return nothing. Retry once with a smaller pack and a
        # larger cap rather than failing the run outright.
        note('summarise', 'Model returned no content; retrying with a trimmed evidence pack...')
        trimmed, _ = pack.fit_pack(evidence, max_tokens=max(1000, int(profile['evidence_tokens'] * 0.55)))
        tokens_in = pack.estimate_tokens(trimmed)
        evidence = trimmed
        try:
            markdown, meta = _generate(evidence, min(8000, int(max_out * 1.6) + 500))
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
        # Kept so two reports can be compared without recollecting the host.
        clusters_json=json.dumps([
            {'sig': c['sig'], 'label': c['label'], 'src': c['src'],
             'sev': c['sev'], 'count': c['count']}
            for c in sorted(clusters, key=lambda c: -(c.get('count') or 0))[:250]
        ]),
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
            'severity_filter': _stored_filter(collected, norm),
            'pack_fitted': fitted,
            'missing_headings': meta.get('missing_headings') or [],
            'depth': recommendation['depth'],
            'depth_label': recommendation['depth_label'],
            'depth_requested': depth or 0,
            'chunks': chunks_used,
            'pack_tokens': max_tokens,
            'evidence_tokens': tokens_in,
            'max_output_tokens': max_out,
            'recommendation': {
                'depth_label': recommendation['depth_label'],
                'suggested_model': recommendation['suggested_model'],
                'suggest_model': recommendation['suggest_model'],
                'rationale': recommendation['rationale'],
            },
        }),
        evidence_text=evidence,
        tokens_in=meta.get('tokens_in') or tokens_in,
        tokens_out=meta.get('tokens_out'),
        duration_ms=int((time.time() - started) * 1000),
        report_markdown=markdown,
    )
    db.session.add(report)
    db.session.commit()

    # A stored verdict is itself a metric: "not healthy" can be a rule.
    try:
        from alerting import engine as alerts
        alerts.record_verdict(host_key, report.verdict, report_id=report.id)
    except Exception:
        pass

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


@reports_bp.route('/serverreport/preflight', methods=['POST'])
def preflight():
    """Size a run without calling the model.

    Collects + normalises + correlates, builds the evidence pack, and returns
    what it would cost and which depth/model we would choose. The collected
    bundle is cached so pressing "Start" straight afterwards does not collect
    the host a second time.
    """
    data = request.get_json(silent=True) or {}
    host_key = (data.get('host_key') or '').strip()
    if not host_key:
        return jsonify({'error': 'Missing host_key.'}), 400

    window_minutes = collect.clamp_window(data.get('window_minutes', _defaults()['window_minutes']))
    provider = (data.get('provider') or '').strip() or _configured_provider()
    defaults = _defaults()
    if provider != defaults['provider']:
        model = (data.get('model') or '').strip() or None
    else:
        model = (data.get('model') or '').strip() or defaults['model']
    depth = data.get('depth', defaults['depth'])
    try:
        depth = int(depth or 0)
    except (TypeError, ValueError):
        depth = 0

    include_files = bool(data.get('include_files', True))
    include_journal = bool(data.get('include_journal', True))
    include_docker = bool(data.get('include_docker', True))
    include_stopped = bool(data.get('include_stopped', False))
    sev_sel = severity.parse(data.get('severities'))

    host_label = _host_label(host_key)
    # Collection fans out into worker threads, which do not inherit this
    # request's app context - hand them the real app object.
    try:
        worker_app = current_app._get_current_object()
    except RuntimeError:
        worker_app = None

    try:
        bundle = prepare_bundle(
            host_key, host_label, window_minutes, include_files, include_journal,
            include_docker, include_stopped, app=worker_app, use_cache=True,
            severities=sev_sel,
        )
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500

    norm = bundle['norm']
    depth_costs = [
        {'depth': d,
         'label': pack_limits_label(d),
         'tokens': pack.estimate_tokens(
             pack.build_pack(host_label, norm, bundle['corr'], bundle['collected'],
                             bundle['containers'], depth=d))}
        for d in sorted(pack.PACK_LIMITS)
    ]
    cost_by_depth = {c['depth']: c['tokens'] for c in depth_costs}
    baseline_tokens = cost_by_depth.get(3) or 0
    full_tokens = cost_by_depth.get(5) or baseline_tokens
    rec = sizing.recommend({
        'pack_tokens': baseline_tokens,
        'events': len(norm['events']),
        'clusters': len(norm['clusters']),
        'sources': len(bundle['ok_sources']),
        'correlations': len(bundle['corr']['correlations']),
        'severity': norm['severity_counts'],
        'model_filtered': model or 'the selected model',
    }, model, requested_depth=depth or None)

    # Chunk count must reflect the depth actually chosen, not the baseline.
    chosen_tokens = cost_by_depth.get(rec['depth'], baseline_tokens)
    profile = rec['profile']
    chunks = 1
    if chosen_tokens > profile['chunk_at']:
        chunks = max(2, int(math.ceil(chosen_tokens / max(1, profile['evidence_tokens']))))

    _bundle_put(_bundle_key(host_key, window_minutes, include_files, include_journal,
                            include_docker, include_stopped, sev_sel), bundle)

    return jsonify({
        'host_key': host_key,
        'host_label': host_label,
        'sources_total': len(bundle['collected']['sources']),
        'sources_ok': len(bundle['ok_sources']),
        'sources_empty': len(bundle['empty_sources']),
        'sources_failed': len(bundle['failed_sources']),
        'events': len(norm['events']),
        'clusters': len(norm['clusters']),
        'correlations': len(bundle['corr']['correlations']),
        'severity': norm['severity_counts'],
        'filter': _stored_filter(bundle['collected'], norm),
        'scope_note': _scope_note(include_files, include_journal, include_docker,
                                  include_stopped, sev_sel),
        'pack_tokens': baseline_tokens,
        'pack_tokens_max_depth': full_tokens,
        'depth_costs': depth_costs,
        'recommendation': {
            'depth': rec['depth'],
            'depth_label': rec['depth_label'],
            'depth_description': rec['depth_description'],
            'chunks': chunks,
            'chosen_tokens': chosen_tokens,
            'model': rec['model'],
            'model_context': rec['model_context'],
            'usable_input_tokens': rec['usable_input_tokens'],
            'suggested_model': rec['suggested_model'],
            'suggest_model': rec['suggest_model'],
            'rationale': rec['rationale'],
        },
    })


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

    depth = data.get('depth', _defaults()['depth'])
    try:
        depth = int(depth or 0)
    except (TypeError, ValueError):
        depth = 0

    sev_sel = severity.parse(data.get('severities'))
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
                             f'({_scope_note(include_files, include_journal, include_docker, include_stopped, sev_sel)})...'})

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
                    depth=depth,
                    emit=lambda p: box.put(('progress', p)),
                    app=worker_app,
                    use_cache=True,
                    severities=sev_sel,
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
        return render_template('report.html', report=None, report_id=report_id,
                               diff=None), 404

    # "What changed since last time?" - compare against the previous report for
    # the same host. Reports are read far more often than they are written, and
    # this costs one extra row lookup.
    previous = (LogReport.query
                .filter(LogReport.host_key == report.host_key, LogReport.id < report.id)
                .order_by(LogReport.id.desc()).first())
    diff = None
    if previous:
        try:
            diff = rdiff.compare(rdiff.report_payload(previous),
                                 rdiff.report_payload(report))
        except Exception:
            diff = None
    return render_template('report.html', report=report, report_id=report_id,
                           diff=diff)


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
