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

Build-kind services take a different road to the same place.  Their tag is not a
version anyone can look up - it is `build-<run>`, produced by the release job - so
there is nothing to resolve and nothing to mirror.  What "update" means for them
is "rebuild `apps/<name>` from its source and roll the service onto that build",
so the pipeline writes a build request into the app directory (which is what makes
`build.yml` and `ship.yml` see the app as changed), waits for `build.yml` to build
and smoke test it on `dev`, merges the PR, and lets `ship.yml` build, push and
deploy.  Only afterwards, when the new tag exists, is the pinned `build-<n>` in
wizard.yaml and the stack corrected to it - a stale pin is how a later, unrelated
`docker stack deploy` quietly rolls a service back to an old build.

`release: manual` services are still refused: a hand-pushed version tag has no
source-to-build mapping the estate could follow.
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

# Written into apps/<name>/ so the estate's own CI treats the app as changed.
BUILD_MARKER = 'BUILD_REQUEST.json'


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
# build-kind apps (apps/<name> in the estate repo, built by CI)
# --------------------------------------------------------------------------

def app_dir(name: str) -> str:
    return f'apps/{name}'


def build_spec(repo: Repo, name: str) -> dict:
    """apps/<name>/build.json when the app builds external source, else {}."""
    raw = repo.read(f'{app_dir(name)}/build.json', '')
    if not raw:
        return {}
    try:
        return json.loads(raw) or {}
    except ValueError:
        return {}


def can_rebuild(repo: Repo, name: str) -> bool:
    return bool(build_spec(repo, name) or repo.read(f'{app_dir(name)}/Dockerfile', ''))


def build_source(repo: Repo, name: str) -> str:
    """What a rebuild would compile: an external clone, or apps/<name> itself."""
    spec = build_spec(repo, name)
    if spec.get('source'):
        return f'{spec["source"]}@{spec.get("ref") or "main"}'
    return f'apps/{name} in {settings.owner()}/{settings.name()}'


def build_image(entry: dict) -> str:
    """The image the stack resolves to, with the CI tag left as a placeholder."""
    return render.image_ref(entry, settings.registry())


# --------------------------------------------------------------------------
# planning (read-only, safe to call from a page render)
# --------------------------------------------------------------------------

def _plan_build(repo: Repo, entry: dict, out: dict) -> dict:
    """A build app has no version to resolve: the update is a rebuild."""
    name = entry.get('name') or out['name']
    stack_rel = out['stack']
    out['action'] = 'rebuild'
    out['upstream'] = build_source(repo, name)
    out['supported'] = can_rebuild(repo, name)
    out['target'] = 'the current source'
    out['files'] = [f'{app_dir(name)}/{BUILD_MARKER}', 'wizard.yaml', stack_rel]
    # A build app is always "behind": its image is a snapshot of the source, and
    # the source may have moved since.  Saying up_to_date would be a guess.
    out['up_to_date'] = False
    out['steps'] = [
        f'git reset --hard origin/{settings.work_branch()} in {repo.dir}',
        f'{app_dir(name)}/{BUILD_MARKER}: ask CI to rebuild {out["upstream"]}',
        'git commit + push origin ' + settings.work_branch(),
        f'wait for {BUILD_WF.split("/")[-1]} to build and smoke test the image',
        f'open PR {settings.work_branch()} -> {settings.base_branch()} and merge it',
        f'wait for {SHIP_WF.split("/")[-1]} to build, push and deploy the stack',
        'pin the new build tag in wizard.yaml and the stack',
    ]
    if not out['supported']:
        out['reason'] = (f'{name} has no apps/{name}/Dockerfile or build.json, so there is '
                         f'nothing the estate knows how to build')
    return out


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
    if kind == 'build' and entry.get('release') != 'manual':
        return _plan_build(repo, entry, out)

    if not out['supported']:
        if kind == 'build':
            out['reason'] = (f'{name} is built from source and pinned by hand under a version tag '
                             f'(release: manual) - bump it deliberately rather than by a tag scan')
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
        if entry.get('release') == 'manual':
            raise EstateError(
                f'{name} is built from source and pinned under a version tag by hand '
                f'(release: manual): a tag scan cannot know which build to move to.')
        return _perform_build(repo, entry, name, sink)
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


def _perform_build(repo: Repo, entry: dict, name: str, sink: Sink, version: str = '') -> dict:
    """Rebuild apps/<name> through CI, then pin the tag CI produced.

    Three CI runs' worth of work, and every one of them is a gate: `build.yml`
    compiles and smoke tests on the branch, `ship.yml` builds, pushes and deploys
    the stack, and the pin commit afterwards makes the estate's recorded version
    agree with what is actually running.
    """
    app = app_dir(name)
    if not can_rebuild(repo, name):
        raise EstateError(f'{name} has no {app}/Dockerfile or build.json, so there is nothing '
                          f'the estate knows how to build')
    spec = build_spec(repo, name)
    current = str(entry.get('version') or '')
    source = build_source(repo, name)
    sink.progress(8)
    sink.step('rebuild from source', detail=source)

    if settings.dry_run():
        sink.step('rebuild from source', ok=True, detail='(dry run)')
        sink.log('(dry run - AILOG_ALLOW_ESTATE is not "on")')
        sink.log(f'would write {app}/{BUILD_MARKER} asking CI to rebuild {source}')
        sink.log(f'would push {settings.work_branch()}, wait for {BUILD_WF}, open a PR to '
                 f'{settings.base_branch()}, merge it and wait for {SHIP_WF}')
        sink.log('would then pin the build tag CI produced in wizard.yaml and the stack')
        sink.progress(100)
        return {'dry_run': True, 'name': name, 'action': 'rebuild', 'current': current}

    requested = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    payload = {
        'requested_at': requested,
        'requested_by': 'ailog (update from the Docker view)',
        'app': name,
        'source': spec.get('source') or f'apps/{name}',
        'ref': spec.get('ref') or '',
        'replaces': current or '',
    }

    def edit(repo: Repo):
        """Regenerated on every lost race: same request, current tree."""
        live_entry = render.find_service(render.load_intent(repo.read('wizard.yaml')), name)
        if live_entry is None:
            raise Conflict(f'{name} is no longer in wizard.yaml - re-plan it')
        relpath = f'{app}/{BUILD_MARKER}'
        body = json.dumps(payload, indent=2) + chr(10)
        repo.write(relpath, body)
        return live_entry, [relpath]

    message = (f'{name}: rebuild from source\n\n'
               f'Requested by ailog from the Docker view. {BUILD_WF} builds and smoke tests it '
               f'on this branch; merging builds, pushes and deploys it.')
    sink.step(f'rebuild {name}')
    result = repo.apply(edit, message)
    if not result['changed']:
        sink.step(f'rebuild {name}', ok=True, detail='a request was already on the branch')
    else:
        sink.step(f'rebuild {name}', ok=True, detail=', '.join(result['changed']))
    sink.progress(18)

    forge = forge_mod.Forge()
    sha = result['head']

    # The gate: if it does not compile and pass its smoke test on the branch,
    # merging it would deploy an image nobody has run.
    sink.step(f'wait for {BUILD_WF}')
    run = forge.find_run(BUILD_WF, sha=sha, timeout=PULL_TIMEOUT)
    if run is None:
        raise EstateError(f'{BUILD_WF} did not start for {sha[:8]} - the push to '
                          f'{settings.work_branch()} may not have triggered CI')
    ok, status = _watch_run(forge, run, sink, base=18, span=30)
    if not ok:
        raise EstateError(f'the build failed on {settings.work_branch()} ({status}) - nothing was '
                          f'merged, so the running service is untouched')
    sink.progress(50)

    title = f'{name}: rebuild from source'
    body = (f'Opened by ailog after an update was requested for `{name}` in the Docker view.\n\n'
            f'- {app}/{BUILD_MARKER}: rebuild request\n'
            f'- source: `{source}`\n'
            f'- built and smoke tested by {BUILD_WF} on {settings.work_branch()}\n\n'
            f'Merging this makes {SHIP_WF} build the image, push it to the registry and deploy '
            f'only the `{name}` stack with the tag it just built.')
    pr = forge.create_pr(title, head=settings.work_branch(),
                         base=settings.base_branch(), body=body)
    sink.step('pull request', ok=True, detail=f'#{pr.get("number")} {summary_title(pr)}')
    sink.progress(54)

    merged = forge.merge_pr(pr['number'])
    sink.step('merged', ok=True, detail=f'PR #{pr["number"]}')
    sink.progress(58)

    ship = forge.find_run(SHIP_WF, sha=merged.get('sha') or '', timeout=PULL_TIMEOUT)
    if ship is None:
        raise EstateError(f'the merge landed but {SHIP_WF} did not start for '
                          f'{(merged.get("sha") or "")[:8]} - check the run list in Gitea')
    ok, status = _watch_run(forge, ship, sink, base=58, span=30)
    if not ok:
        raise EstateError(f'the release run failed ({status}) - see the log above')

    # The deploy used the tag this run produced.  The pin in git still names the
    # previous build, and a pin is what any later stack deploy falls back to, so
    # leaving it would make the next unrelated deploy roll this service back.
    tag = f'build-{ship.get("run_number") or ""}'.rstrip('-')
    result_out = {'name': name, 'action': 'rebuild', 'current': current,
                  'pr': pr.get('number'), 'run': ship.get('id'),
                  'sha': merged.get('sha') or '', 'tag': tag}
    if not ship.get('run_number'):
        sink.step('pin the build tag', ok=False, detail='the run did not report its number')
        sink.progress(100)
        return result_out
    pinned = _pin_build(repo, name, tag, sink)
    result_out['pinned'] = pinned
    sink.progress(100)
    return result_out


def _pin_build(repo: Repo, name: str, tag: str, sink: Sink) -> bool:
    """Point wizard.yaml and the stack at the build that just shipped."""
    sink.step('pin the build tag', detail=tag)

    def edit(repo: Repo):
        live_text = repo.read('wizard.yaml')
        live_entry = render.find_service(render.load_intent(live_text), name)
        if live_entry is None:
            raise Conflict(f'{name} is no longer in wizard.yaml')
        live_version = str(live_entry.get('version') or '')
        if live_version == tag:
            return live_entry, {}
        new_text, new_entry = render.bump_intent(live_text, name, tag)
        files = {'wizard.yaml': new_text}
        stack_rel = f'stacks/{name}/stack.yml'
        stack_text = repo.read(stack_rel)
        if stack_text:
            image = build_image(new_entry)
            bumped, changed = render.bump_image(stack_text, render.service_of(new_entry), image)
            if changed:
                files[stack_rel] = bumped
        for relpath, text in files.items():
            repo.write(relpath, text)
        return new_entry, list(files)

    try:
        result = repo.apply(edit, f'{name}: pin {tag}\n\n'
                                 f'The tag {SHIP_WF} built and deployed, recorded in git so a '
                                 f'later stack deploy does not fall back to the previous build.')
        if not result['changed']:
            sink.step('pin the build tag', ok=True, detail=f'{tag} was already pinned')
            return True
        sink.step('pin the build tag', ok=True, detail=', '.join(result['changed']))
    except (Conflict, GitError) as exc:
        # The service is already updated; a stale pin is a follow-up, not a
        # failure of the update the person asked for.
        sink.step('pin the build tag', ok=False, detail=str(exc)[:200])
        return False

    forge = forge_mod.Forge()
    pr = forge.create_pr(f'{name}: pin {tag}', head=settings.work_branch(),
                         base=settings.base_branch(),
                         body=f'The build tag {SHIP_WF} produced for `{name}`, pinned in '
                              f'wizard.yaml and the stack so a later deploy cannot fall back '
                              f'to the previous build.')
    sink.step('pin pull request', ok=True, detail=f'#{pr.get("number")} {summary_title(pr)}')
    merged = forge.merge_pr(pr['number'])
    sink.step('pin merged', ok=True, detail=f'PR #{pr["number"]}')
    run = forge.find_run(SHIP_WF, sha=merged.get('sha') or '', timeout=PULL_TIMEOUT)
    if run is not None:
        ok, status = _watch_run(forge, run, sink, base=94, span=6)
        if not ok:
            sink.step('pin deploy', ok=False, detail=status)
    return True


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
