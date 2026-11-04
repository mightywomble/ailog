"""HTTP surface for the estate: what git says, and the one-click update.

Read endpoints are cheap (one clone read, no network) so the UI can render them
on demand.  Anything that writes is a job, because the interesting part is CI and
a request must not sit on a build for ten minutes:

    GET  /api/estate/status                mode, checkout, head
    GET  /api/estate/services              intent + drift per service
    GET  /api/estate/services/<name>       one service, with ?check=1 for upstream
    POST /api/estate/update                start the bump (needs confirm)
    GET  /api/estate/jobs/<id>             steps, progress, log
"""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from . import render, settings
from . import update as estupdate
from .git import GitError, Repo

estate_bp = Blueprint('estate', __name__)


def _fail(exc, status: int = 502):
    return jsonify({'success': False, 'error': settings.redact(str(exc))}), status


@estate_bp.get('/api/estate/status')
def api_status():
    repo = Repo()
    out = {
        'success': True,
        'mode': settings.mode(),
        'enabled': settings.enabled(),
        'repo': f'{settings.owner()}/{settings.name()}',
        'branch': settings.work_branch(),
        'base': settings.base_branch(),
        'dir': repo.dir,
        'checkout': repo.exists(),
        'head': '',
        'error': '',
    }
    if repo.exists():
        try:
            out['head'] = repo.fresh()
        except GitError as exc:
            out['error'] = str(exc)
    return jsonify(out)


@estate_bp.get('/api/estate/services')
def api_services():
    repo = Repo()
    if not repo.exists():
        return jsonify({'success': False,
                        'error': 'no estate checkout yet (the first update clones it)',
                        'services': []}), 200
    try:
        repo.fresh()                     # the view must not lag the last release
        text = repo.read('wizard.yaml')
    except (OSError, GitError) as exc:
        return _fail(exc)
    doc = render.load_intent(text)
    rows = []
    for entry in doc.get('services') or []:
        stack_rel = f'stacks/{entry.get("name")}/stack.yml'
        rows.append({
            'name': entry.get('name'),
            'kind': entry.get('kind'),
            'version': entry.get('version'),
            'source': entry.get('source') or '',
            'image': render.image_ref(entry, settings.registry()),
            'url': entry.get('url') or '',
            'drift': render.drift(entry, repo.read(stack_rel)),
            'supported': (entry.get('kind') in ('mirror', 'image') and bool(entry.get('source'))),
        })
    return jsonify({'success': True, 'services': rows, 'head': repo.head(),
                    'mode': settings.mode()})


@estate_bp.get('/api/estate/services/<name>')
def api_service(name):
    try:
        check = (request.args.get('check') or '').lower() in ('1', 'true', 'yes')
        if check:
            return jsonify({'success': True, 'plan': estupdate.plan(name)})
        repo = Repo()
        if not repo.exists():
            return _fail('no estate checkout yet', 404)
        repo.fresh()
        entry = render.find_service(render.load_intent(repo.read('wizard.yaml')), name)
        if entry is None:
            return _fail(f'{name} is not in wizard.yaml', 404)
        return jsonify({'success': True, 'service': entry})
    except Exception as exc:                      # noqa: BLE001 - shown in the UI
        return _fail(exc)


@estate_bp.post('/api/estate/update')
def api_update():
    body = request.get_json(silent=True) or {}
    name = str(body.get('name') or '').strip()
    version = str(body.get('version') or '').strip()
    if not name:
        return _fail('a service name is required', 400)
    if not body.get('confirm'):
        return _fail('confirmation is required: the dialog must show the plan first', 400)
    if not settings.enabled():
        return _fail('the estate pipeline is disabled on this server (AILOG_ALLOW_ESTATE=off)', 403)
    try:
        started = estupdate.start(current_app._get_current_object(), name, version)
    except Exception as exc:                      # noqa: BLE001 - shown in the UI
        return _fail(exc)
    return jsonify({'success': True, 'job': started})


@estate_bp.get('/api/estate/jobs/<job_id>')
def api_job(job_id):
    found = estupdate.job(job_id)
    if not found:
        return _fail(f'unknown estate job {job_id}', 404)
    return jsonify({'success': True, 'job': found})
