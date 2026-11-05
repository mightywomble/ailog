"""Moving one swarm service forward, through the pipeline that already ships it.

The update is four small commits' worth of work - actually one commit touching
three files - and then a wait:

    bump wizard.yaml (version, and the mirror's source tag)
    bump stacks/<name>/stack.yml (one image: line, comments untouched)
    bump mirror-images.json (so mirror.yml copies the new image into zot)
        -> push dev -> wait for mirror.yml (zot has the image)
        -> PR dev -> main -> merge -> wait for ship.yml (build + stack deploy)

Everything the estate needs to stay coherent happens in CI, on the runners that
hold the zot credentials and the manager socket.  AILog's contribution is the
judgement (which tag, which files) and the visibility (steps, progress, the
run's own log).

Build-kind services are refused on purpose: their tag comes from a CI build of
`apps/<name>`, so a version bump with no source change would point the stack at
an image that does not exist - the failure mode that once took a whole stack
down with `build-37: not found`.
"""

from __future__ import annotations

import json
import threading
import time
import uuid

from . import forge as forge_mod
from . import render, settings, tags
from .git import Conflict, GitError, Repo

# Matched against the run's workflow file name (estate.forge.Forge.workflow_of).
MIRROR_WF = 'mirror.yml'
SHIP_WF = 'ship.yml'
BUILD_WF = 'build.yml'

PULL_TIMEOUT = 180
JOB_TTL = 3600


class EstateError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# progress sinks
# --------------------------------------------------------------------------

class Sink:
    """Where a run's progress goes: the dialog's own job, or a caller's."""

    def step(self, label: str, ok=None, detail: str = '') -> None: ...
    def log(self, text: str) -> None: ...
    def progress(self, pct: float) -> None: ...


class LinkedSink(Sink):
    """Forwards to plain callables, so updateflow can reuse its own job dict."""

    def __init__(self, step=None, log=None, progress=None):
        self._step = step
        self._log = log
        self._progress = progress

    def step(self, label, ok=None, detail=''):
        if self._step:
            self._step(label, ok, detail)

    def log(self, text):
        if self._log:
            self._log(text)

    def progress(self, pct):
        if self._progress:
            self._progress(pct)


_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


class JobSink(Sink):
    def __init__(self, job_id: str):
        self.job_id = job_id

    def _patch(self, **changes):
        with _jobs_lock:
            job = _jobs.get(self.job_id)
            if job:
                job.update(changes)

    def step(self, label, ok=None, detail=''):
        with _jobs_lock:
            job = _jobs.get(self.job_id)
            if not job:
                return
            last = job['steps'][-1] if job['steps'] else None
            if last and last['label'] == label:
                if detail:
                    last['detail'] = settings.redact(detail)
                if ok is not None:
                    last['ok'] = ok
                job['label'] = label
                return
            job['steps'].append({'label': label, 'ok': ok, 'detail': settings.redact(detail)})
            job['label'] = label

    def log(self, text):
        with _jobs_lock:
            job = _jobs.get(self.job_id)
            if job is None:
                return
            lines = job['output']
            lines.extend(settings.redact(text).splitlines())
            del lines[:-400]                 # keep the tail, not the transcript

    def progress(self, pct):
        self._patch(progress=max(0.0, min(100.0, round(float(pct), 1))))


def job(job_id: str) -> dict | None:
    with _jobs_lock:
        found = _jobs.get(job_id)
        if not found:
            return None
        snapshot = dict(found)
        snapshot['steps'] = [dict(step) for step in found['steps']]
        snapshot['output'] = list(found['output'])
    snapshot['elapsed'] = round(time.time() - snapshot['started'], 1)
    return snapshot


def clear() -> None:
    with _jobs_lock:
        _jobs.clear()


def _prune() -> None:
    cutoff = time.time() - JOB_TTL
    with _jobs_lock:
        for key in [k for k, v in _jobs.items() if v.get('finished') and v['finished'] < cutoff]:
            _jobs.pop(key, None)


# --------------------------------------------------------------------------
# planning (read-only, safe to call from a page render)
# --------------------------------------------------------------------------

def plan(name: str, version: str = '') -> dict:
    """What an update of ``name`` would do, without touching anything."""
    repo = Repo()
    repo.sync()
    text = repo.read('wizard.yaml')
    doc = render.load_intent(text)
    entry = render.find_service(doc, name)
    if entry is None:
        raise EstateError(f'{name} is not in wizard.yaml')

    stack_rel = f'stacks/{name}/stack.yml'
    stack_text = repo.read(stack_rel)
    current = str(entry.get('version') or '')
    kind = entry.get('kind') or ''
    out = {
        'name': name,
        'kind': kind,
        'service': render.service_of(entry),
        'current': current,
        'image': render.image_ref(entry, settings.registry()),
        'upstream': entry.get('source') or '',
        'stack': stack_rel,
        'drift': render.drift(entry, stack_text),
        'mode': settings.mode(),
        'supported': kind in ('mirror', 'image') and bool(entry.get('source')),
        'reason': '',
        'target': '',
        'files': ['wizard.yaml', stack_rel],
        'steps': [],
    }
    if not out['supported']:
        if kind == 'build' and entry.get('release') == 'manual':
            out['reason'] = (f'{name} is built from source and pinned by hand under a version tag '
                             f'(release: manual) - bump it deliberately rather than by a tag scan')
        elif kind == 'build':
            out['reason'] = (f'built from source in this repo: its tag comes from a CI build of '
                             f'apps/{name}, so the estate path leaves it alone')
        else:
            out['reason'] = 'a mirrored service needs an upstream source in wizard.yaml'
        return out

    if version:
        out['target'] = version
    else:
        try:
            newest = tags.newest_tag(entry['source'])
            out['target'] = newest['best']
            out['up_to_date'] = bool(newest['up_to_date'])
            out['candidates'] = newest['candidates']
        except Exception as exc:              # noqa: BLE001 - shown in the dialog
            out['target'] = ''
            out['error'] = f'could not read upstream tags: {exc}'

    # "supported" has to mean "there is a version to move to", not just "this
    # kind is handled": a mirror that tracks `latest` upstream has no version tag
    # to pin, and offering one is how a moving tag gets frozen at a commit sha.
    if not out['target']:
        out['supported'] = False
        out['reason'] = out.get('error') or 'no newer version tag could be resolved'
    if entry.get('kind') == 'mirror' and render.mirror_entry(entry):
        out['files'].append('mirror-images.json')
    out['steps'] = [
        f'git reset --hard origin/{settings.work_branch()} in {repo.dir}',
        f'wizard.yaml: version {current} -> {out["target"] or "?"}',
        f'{stack_rel}: image -> {render.image_ref(dict(entry, version=out["target"] or current), settings.registry())}',
        'git commit + push origin ' + settings.work_branch(),
        f'wait for {MIRROR_WF.split("/")[-1]} to copy the image into {settings.registry()}',
        f'open PR {settings.work_branch()} -> {settings.base_branch()} and merge it',
        f'wait for {SHIP_WF.split("/")[-1]} to deploy the stack (docker stack deploy)',
    ]
    return out


# --------------------------------------------------------------------------
# the run
# --------------------------------------------------------------------------

def _watch_run(forge, run: dict, sink: Sink, base: float, span: float,
               cancel=None) -> tuple[bool, str]:
    """Follow one workflow run to its end, tailing the jobs' logs.

    Gitea's run status is coarse (queued/running/success/failure) and the log is
    the only way to say *what* is happening, so both are polled: the log drives
    the text, the job count drives the bar.
    """
    run_id = run.get('id')
    deadline = time.time() + settings.run_wait()
    seen_jobs: dict[int, int] = {}          # job id -> lines already shown
    total_jobs = max(1, len(forge.jobs(run_id)))
    last_status = ''
    while time.time() < deadline:
        if cancel and cancel():
            return False, 'cancelled'
        try:
            current = forge.run(run_id)
        except Exception as exc:              # noqa: BLE001 - a blip is not a failure
            sink.log(f'(could not read run {run_id}: {exc})')
            time.sleep(5)
            continue
        status = (current.get('conclusion') or current.get('status') or '').lower()
        jobs = forge.jobs(run_id)
        total_jobs = max(total_jobs, len(jobs))
        done = sum(1 for j in jobs if (j.get('conclusion') or '').lower() in ('success', 'failure', 'cancelled', 'skipped'))
        for meta in jobs:
            job_id = meta.get('id')
            if not job_id:
                continue
            text = forge.job_log(job_id)
            lines = settings.redact(text).splitlines()
            at = seen_jobs.get(job_id, 0)
            if len(lines) > at:
                for line in lines[at:]:
                    if line.strip():
                        sink.log(line)
                seen_jobs[job_id] = len(lines)
        sink.progress(base + span * min(1.0, done / max(1, total_jobs)))
        if status != last_status:
            last_status = status
            sink.step(f'run {run_id}', detail=status or 'running')
        if status in ('success', 'failure', 'cancelled', 'skipped', 'error'):
            ok = status == 'success'
            sink.step(f'run {run_id}', ok=ok, detail=status)
            return ok, status
        time.sleep(5)
    return False, f'timed out after {settings.run_wait()}s'


def perform(name: str, sink: Sink, version: str = '') -> dict:
    """Do the update. Raises :class:`EstateError` with a reason a person can act on."""
    if not settings.enabled():
        raise EstateError('the estate pipeline is disabled on this server '
                          '(AILOG_ALLOW_ESTATE=off)')

    repo = Repo()
    sink.progress(2)
    sink.step('sync estate repo', detail=f'{settings.owner()}/{settings.name()} @ {settings.work_branch()}')
    head = repo.sync()
    sink.step('sync estate repo', ok=True, detail=f'{(head or "")[:8]}')
    text = repo.read('wizard.yaml')
    entry = render.find_service(render.load_intent(text), name)
    if entry is None:
        raise EstateError(f'{name} is not in wizard.yaml')
    problems = render.validate(entry)
    if problems:
        raise EstateError('; '.join(problems))
    if entry.get('kind') == 'build':
        raise EstateError(
            f'{name} is built from source and pinned under a version tag by hand '
            f'(release: manual): a tag scan cannot know which build to move to.'
            if entry.get('release') == 'manual' else
            f'{name} is built from source in this repo: its tag comes from a CI build of '
            f'apps/{name}, so a version bump would point the stack at an image that does '
            f'not exist. Release it by merging the app change.')
    source = entry.get('source') or ''
    if not source:
        raise EstateError(f'{name} has no upstream source in wizard.yaml')

    current = str(entry.get('version') or '')
    sink.progress(8)
    if version:
        target = version
        sink.step('tag pinned by the caller', detail=target)
    else:
        sink.step('newest upstream tag', detail=f'listing {source}')
        newest = tags.newest_tag(source)
        target = newest['best']
        if newest['up_to_date']:
            sink.step('newest upstream tag', ok=True,
                      detail=f'{current} is the newest {newest.get("repo") or source} tag')
            sink.step('already newest', ok=True, detail=current)
            sink.progress(100)
            return {'up_to_date': True, 'current': current, 'name': name}
        sink.step('newest upstream tag', ok=True, detail=f'{current} -> {target}')
    sink.progress(15)

    if settings.dry_run():
        sink.log('(dry run - AILOG_ALLOW_ESTATE is not "on")')
        sink.log(f'would bump {name}: {current} -> {target}')
        sink.log(f'would commit wizard.yaml, stacks/{name}/stack.yml, mirror-images.json')
        sink.log(f'would push {settings.work_branch()}, open a PR to {settings.base_branch()} and merge it')
        sink.progress(100)
        return {'dry_run': True, 'current': current, 'target': target, 'name': name}

    def edit(repo: Repo):
        """Regenerated on every attempt: it is a function of the tree + target."""
        live_text = repo.read('wizard.yaml')
        live_entry = render.find_service(render.load_intent(live_text), name)
        live_version = str((live_entry or {}).get('version') or '')
        if live_version and live_version != current:
            raise Conflict(f'{name} moved to {live_version} on the branch while this update was '
                           f'being prepared (was {current}) - re-plan it')
        if live_version and tags._version_key(live_version) >= tags._version_key(target):
            raise Conflict(f'{name} is already on {live_version} on the branch, which is not '
                           f'behind {target} - re-plan it')
        new_text, new_entry = render.bump_intent(live_text, name, target)
        files = {'wizard.yaml': new_text}

        stack_rel = f'stacks/{name}/stack.yml'
        stack_text = repo.read(stack_rel)
        if stack_text:
            image = render.image_ref(new_entry, settings.registry())
            bumped, changed = render.bump_image(stack_text, render.service_of(new_entry), image)
            if changed:
                files[stack_rel] = bumped
        mirror = render.mirror_entry(new_entry)
        if mirror:
            try:
                doc = json.loads(repo.read('mirror-images.json', '{"mirrors": []}') or '{}')
            except ValueError:
                doc = {'mirrors': []}
            rows = doc.setdefault('mirrors', [])
            for index, row in enumerate(rows):
                if row.get('name') == mirror['name']:
                    rows[index] = mirror
                    break
            else:
                rows.append(mirror)
            files['mirror-images.json'] = json.dumps(doc, indent=2) + '\n'
        for relpath, body in files.items():
            repo.write(relpath, body)
        return new_entry, list(files)

    message = (f'{name}: {current} -> {target}\n\n'
               f'Moved by ailog from the Docker view, for {name!r} only. '
               f'wizard.yaml, the stack image and the mirror entry in one commit so '
               f'mirror.yml and ship.yml see the same version.')
    # One bullet per thing that happened: the step is opened with what it is
    # about and closed with what it did, rather than leaving a dangling line.
    sink.step(f'commit {name} {current} -> {target}')
    result = repo.apply(edit, message)
    if not result['changed']:
        sink.step('nothing to commit', ok=True, detail='the estate already matches')
        sink.progress(100)
        return {'changed': [], 'name': name, 'target': target}
    sink.step(f'commit {name} {current} -> {target}', ok=True,
              detail=', '.join(result['changed']))
    sink.progress(30)

    forge = forge_mod.Forge()
    sha = result['head']

    if 'mirror-images.json' in result['changed']:
        sink.step('mirror into zot', detail=f'waiting for {MIRROR_WF.split("/")[-1]}')
        run = forge.find_run(MIRROR_WF, sha=sha, timeout=PULL_TIMEOUT)
        if run is None:
            raise EstateError(f'{MIRROR_WF.split("/")[-1]} did not start for {sha[:8]} - '
                              f'the push to {settings.work_branch()} may not have triggered CI')
        ok, status = _watch_run(forge, run, sink, base=30, span=25)
        if not ok:
            raise EstateError(f'the mirror run failed ({status}) - zot does not have the image, '
                              f'so the stack would not deploy')
        sink.progress(58)

    title = f'{name}: {current} -> {target}' if target else f'{name}: estate update'
    body = (f'Opened by ailog after an update was requested for `{name}` in the Docker view.\n\n'
            f'- wizard.yaml: `{current}` -> `{target}`\n'
            f'- stacks/{name}/stack.yml: image pinned to the new version\n'
            + ('- mirror-images.json: new image copied into zot by mirror.yml\n'
               if 'mirror-images.json' in result['changed'] else '')
            + f'\nMerging this deploys only the `{name}` stack (ship.yml diffs the merge).')
    pr = forge.create_pr(title, head=settings.work_branch(),
                         base=settings.base_branch(), body=body)
    sink.step('pull request', ok=True, detail=f'#{pr.get("number")} {summary_title(pr)}')
    sink.progress(62)

    merged = forge.merge_pr(pr['number'])
    sink.step('merged', ok=True, detail=f'PR #{pr["number"]}')
    sink.progress(68)

    run = forge.find_run(SHIP_WF, sha=merged.get('sha') or '', timeout=PULL_TIMEOUT)
    if run is None:
        raise EstateError(f'the merge landed but {SHIP_WF.split("/")[-1]} did not start for '
                          f'{(merged.get("sha") or "")[:8]} - check the run list in Gitea')
    ok, status = _watch_run(forge, run, sink, base=68, span=32)
    if not ok:
        raise EstateError(f'the deploy run failed ({status}) - see the log above')
    sink.progress(100)
    return {'name': name, 'current': current, 'target': target, 'pr': pr['number'],
            'run': run.get('id'), 'sha': merged.get('sha') or ''}


def summary_title(pr: dict) -> str:
    return str(pr.get('title') or pr.get('html_url') or '')[:120]


# --------------------------------------------------------------------------
# background jobs (the dialog polls these)
# --------------------------------------------------------------------------

def _worker(app, job_id: str, name: str, version: str) -> None:
    sink = JobSink(job_id)
    try:
        if app is not None:
            with app.app_context():
                result = perform(name, sink, version)
        else:
            result = perform(name, sink, version)
        with _jobs_lock:
            job = _jobs.get(job_id)
            if job is not None:
                job['result'] = result
                job['status'] = 'done'
                job['error'] = '' if result.get('up_to_date') is not True else 'already newest'
    except Exception as exc:                      # noqa: BLE001 - shown in the dialog
        with _jobs_lock:
            job = _jobs.get(job_id)
            if job is not None:
                job['status'] = 'error'
                job['error'] = settings.redact(str(exc) or exc.__class__.__name__)
    finally:
        with _jobs_lock:
            job = _jobs.get(job_id)
            if job is not None:
                job['finished'] = time.time()
                job['label'] = job.get('label') or 'finished'


def start(app, name: str, version: str = '') -> dict:
    if not settings.enabled():
        raise EstateError('the estate pipeline is disabled on this server '
                          '(AILOG_ALLOW_ESTATE=off)')
    _prune()
    job_id = uuid.uuid4().hex[:12]
    with _jobs_lock:
        _jobs[job_id] = {
            'id': job_id,
            'kind': 'estate',
            'name': name,
            'status': 'running',
            'label': 'queued',
            'progress': 0.0,
            'steps': [],
            'output': [],
            'result': None,
            'error': '',
            'started': time.time(),
            'finished': 0.0,
        }
    threading.Thread(target=_worker, args=(app, job_id, name, version),
                     name=f'estate-{job_id}', daemon=True).start()
    return job(job_id)


__all__ = ['EstateError', 'Conflict', 'GitError', 'LinkedSink', 'JobSink', 'Sink',
           'perform', 'plan', 'start', 'job', 'clear', 'MIRROR_WF', 'SHIP_WF']
