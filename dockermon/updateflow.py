"""Updating exactly one container, from the container itself.

:mod:`dockermon.updates` answers "has this image moved upstream?".  This module
answers the next question - "so how does *this* container get the new bits?" -
and then does it, on the host it is running on, touching nothing else.

Three shapes exist in this estate and they need different commands:

``compose``
    a docker-compose project (the CasaOS apps: gitea, pihole, nginxproxymanager,
    managelm).  ``docker compose -f <file> pull <service>`` then
    ``up -d --no-deps <service>``.  ``--no-deps`` is the whole point: updating
    gitea must not bounce its database or a sidecar that shares the project.

``estate``
    a service in a stack the estate owns (``wizard.yaml``).  The running image
    has to stay the image git says it is, so this does not touch docker at all:
    it bumps the version in ``wizard.yaml`` + the stack file + the mirror entry,
    pushes ``dev``, opens the PR to ``main`` and lets ``ship.yml`` deploy.  See
    :mod:`estate`.

``swarm``
    a stack service the estate does not know about.  ``docker service update
    --image <ref> --force --with-registry-auth`` on a manager, for when there is
    no pin to move.  Still one service, never the stack.

``container``
    ``docker run`` with no compose labels and no swarm service.  There is no
    recorded intent to replay (ports, mounts, env, restart policy), so this is
    refused with the reason rather than guessed at.  A container that sits in a
    compose project *without* a compose service label was created by another
    program working inside that project - Nextcloud AIO's mastercontainer is the
    case that exists here - and the refusal says so, because "update it and let
    its owner recreate it five minutes later" is not an update.

One compose target may cover several services.  Publishers that ship a set
(``immich-server`` + ``immich-machine-learning``, same release, same version)
break if the set is split, so the services a project publishes at one version
are pulled and recreated together.

The old hand-off framed the whole homelab wizard for any of these, and the
wizard's update path is a ``wizard.yaml`` tag bump - which a CasaOS compose
project is not in, so the click landed on the add-a-service journey.  Doing the
update here means "gitea, on casaos" is a two-command change with a log, not a
release pipeline.
"""

from __future__ import annotations

import shlex
import threading
import time
import uuid

from database import release_session
from . import endpoints as ep

COMPOSE_PROJECT = 'com.docker.compose.project'
COMPOSE_SERVICE = 'com.docker.compose.service'
COMPOSE_FILES = 'com.docker.compose.project.config_files'
COMPOSE_WORKDIR = 'com.docker.compose.project.working_dir'
SWARM_SERVICE = 'com.docker.swarm.service.name'

# One shell prelude per SSH call: sudo only if it actually works, and the
# compose plugin only if this host has it.  Both answers are per invocation
# because each call is a fresh shell; the alternative (assume sudo, assume
# v2 compose) fails on exactly the Hosts that matter (CasaOS runs compose v1
# in some apps and v2 in others).
PRELUDE = (
    'if sudo -n docker info >/dev/null 2>&1; then DK="sudo -n docker"; else DK="docker"; fi; '
    'if $DK compose version >/dev/null 2>&1; then DC="$DK compose"; else DC="docker-compose"; fi; '
)

MODES = ('off', 'dry_run', 'on')


def _env(name: str, default: str = '') -> str:
    import os
    return (os.getenv(name) or default).strip()


def mode() -> str:
    """``AILOG_ALLOW_UPDATES``: off (plan only) / dry_run (print) / on (do it).

    On by default because this is the one action in ailog that exists to be
    pressed; the confirmation, the visible command and the job log are what make
    it safe, not a default that silently does nothing.
    """
    value = _env('AILOG_ALLOW_UPDATES', 'on').lower()
    return value if value in MODES else 'on'


def _int_env(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


PULL_TIMEOUT = _int_env('AILOG_UPDATE_PULL_TIMEOUT', 900)
RUN_TIMEOUT = _int_env('AILOG_UPDATE_RUN_TIMEOUT', 180)


# --------------------------------------------------------------------------
# pure helpers (the part worth testing without a host)
# --------------------------------------------------------------------------

def target_of(inspect_row: dict) -> dict:
    """Turn one ``docker inspect`` row into the thing we can act on.

    The labels are the whole story: a container belongs to a compose service, a
    swarm service, or neither.  Falls back to the compose file's directory when
    the config-files label was written by an older compose (it is absent on
    projects created before compose 1.25-ish), because guessing the file from
    the working directory is still better than refusing.
    """
    labels = ((inspect_row.get('Config') or {}).get('Labels') or {}) or {}
    name = str(inspect_row.get('Name') or '').lstrip('/')
    image = str((inspect_row.get('Config') or {}).get('Image') or '')

    swarm = (labels.get(SWARM_SERVICE) or '').strip()
    if swarm:
        return {
            'kind': 'swarm',
            'service': swarm,
            'image': image,
            'containers': [name],
            'project': labels.get('com.docker.stack.namespace') or '',
            'file': '',
        }

    project = (labels.get(COMPOSE_PROJECT) or '').strip()
    service = (labels.get(COMPOSE_SERVICE) or '').strip()
    if service:
        files = [part.strip() for part in (labels.get(COMPOSE_FILES) or '').split(',') if part.strip()]
        workdir = (labels.get(COMPOSE_WORKDIR) or '').strip()
        if not files and workdir:
            files = [workdir.rstrip('/') + '/docker-compose.yml']
        return {
            'kind': 'compose',
            'service': service,
            'image': image,
            'containers': [name],
            'project': project,
            'file': files[0] if files else '',
            'files': files,
        }

    return {
        'kind': 'container',
        'service': '',
        'image': image,
        'containers': [name],
        # A project with no service is the fingerprint of "someone else created
        # this inside that project": AIO's mastercontainer keeps its siblings in
        # ``nextcloud-aio`` but never writes a compose service label.
        'project': project,
        'file': '',
    }


def image_family(image: str) -> str:
    """The name a publisher uses for a set: ``immich-machine-learning`` -> immich."""
    ref = (image or '').split('@', 1)[0]
    name = ref.rsplit('/', 1)[-1].split(':', 1)[0]
    return name.split('-', 1)[0].lower()


def group_targets(rows) -> list[dict]:
    """One target per service, not per container.

    A row in the updates pane is aggregated by image, so three replicas of the
    same image arrive as three containers of one service; running the same
    ``service update`` three times would restart the service three times.
    """
    out: list[dict] = []
    seen: dict[tuple, dict] = {}
    for row in rows or []:
        target = target_of(row)
        key = (target['kind'], target['service'] or target['containers'][0])
        if key in seen:
            seen[key]['containers'].extend(target['containers'])
            continue
        seen[key] = target
        out.append(target)
    for target in out:
        target['reason'] = unsupported_reason(target)
        target['commands'] = commands_for(target)
    return coalesce(out)


def siblings(rows, target: dict) -> list[str]:
    """The rest of a publisher's set, as container names, from ``ps`` alone."""
    if target['kind'] != 'compose' or not target.get('project'):
        return []
    tag = (target.get('image') or '').rsplit(':', 1)[-1] if ':' in (target.get('image') or '') else ''
    family = image_family(target.get('image') or '')
    names = []
    for row in rows or []:
        if row.get('project') != target['project'] or not row.get('image'):
            continue
        row_tag = row['image'].rsplit(':', 1)[-1] if ':' in row['image'] else ''
        if image_family(row['image']) != family or row_tag != tag:
            continue
        if row['name'] not in names:
            names.append(row['name'])
    return names


def unsupported_reason(target: dict) -> str:
    if target['kind'] == 'estate':
        return ''
    if target['kind'] == 'container' and target.get('project'):
        return (f'it was created inside compose project {target["project"]} without a compose '
                f'service label, so something in that project owns it and recreates it - '
                f'updating it here would be undone the next time its owner restarts it')
    if target['kind'] == 'container':
        return ('no compose project and no swarm service: docker has no record of '
                'how this container was created, so it cannot be recreated safely')
    if target['kind'] == 'compose' and not target.get('files'):
        return 'the compose project has no config file recorded on this host'
    if target['kind'] == 'swarm' and not target.get('service'):
        return 'the container has no swarm service label'
    return ''


def target_services(target: dict) -> list[str]:
    """Every compose service this target moves, primary first."""
    services = [s for s in (target.get('services') or []) if s]
    if not services and target.get('service'):
        services = [target['service']]
    return services


def compose_commands(target: dict) -> list[str]:
    files = target.get('files') or ([target['file']] if target.get('file') else [])
    services = target_services(target)
    if not files or not services:
        return []
    flags = ' '.join(f'-f {shlex.quote(path)}' for path in files)
    wanted = ' '.join(shlex.quote(name) for name in services)
    return [
        PRELUDE + f'$DC {flags} pull {wanted}',
        PRELUDE + f'$DC {flags} up -d --no-deps {wanted}',
    ]


def coalesce(targets: list[dict]) -> list[dict]:
    """Fold a publisher's set back into one target.

    ``immich-server`` and ``immich-machine-learning`` are the same product at the
    same version - the server refuses to run against a machine-learning
    container from a different release - so they are pulled and recreated in one
    go.  The test for "one set" is deliberately narrow: same compose project,
    same image family, *and* the identical tag.  matrix-server has four services
    whose names start with ``matrix``, and folding those together would bounce
    postgres and redis to update synapse.
    """
    out: list[dict] = []
    sets: dict[tuple, dict] = {}
    for target in targets:
        if target['kind'] != 'compose' or target.get('reason'):
            out.append(target)
            continue
        tag = (target.get('image') or '').rsplit(':', 1)[-1] if ':' in (target.get('image') or '') else ''
        key = (target.get('project') or '', image_family(target.get('image') or ''), tag)
        held = sets.get(key)
        if held is None:
            target['services'] = [target['service']]
            sets[key] = target
            out.append(target)
            continue
        if target['service'] and target['service'] not in held['services']:
            held['services'].append(target['service'])
        for name in target['containers']:
            if name not in held['containers']:
                held['containers'].append(name)
    for target in out:
        if target['kind'] == 'compose':
            target['reason'] = unsupported_reason(target)
            target['commands'] = commands_for(target)
    return out


def swarm_commands(target: dict) -> list[str]:
    """Roll one swarm service onto the image the registry currently serves.

    ``--force`` because a moving tag (``:latest``) has an identical image spec,
    and without it swarm considers the update a no-op and keeps the old digest.
    ``--with-registry-auth`` because zot needs the credentials the manager
    already holds from the last deploy.
    """
    if not target.get('service'):
        return []
    return [
        PRELUDE + ('$DK service update --image {image} --with-registry-auth --force {service}'
                   .format(image=shlex.quote(target['image']),
                           service=shlex.quote(target['service']))),
    ]


def commands_for(target: dict) -> list[str]:
    if target['kind'] == 'compose':
        return compose_commands(target)
    if target['kind'] == 'swarm':
        return swarm_commands(target)
    # estate: the work happens in CI, so there is no command to show - the
    # dialog shows the plan's steps instead (target['estate']['steps']).
    return []


# --------------------------------------------------------------------------
# host reads
# --------------------------------------------------------------------------

def _runner(host_key: str):
    """(info, run) for one host; ``run`` keeps stderr so failures are readable."""
    info = ep.resolve_host(host_key)
    if not info:
        raise RuntimeError(f"Unknown host '{host_key}'")
    user = info.get('user') or 'root'
    ip = info.get('ip') or '127.0.0.1'
    key_id = info.get('ssh_key_id')

    def run(command: str, timeout: int = 60):
        return ep.ssh_run(user, ip, command, ssh_key_id=key_id, timeout=timeout)

    return info, run


def _ps_rows(run) -> list[dict]:
    """Every container on the host, with the labels that say who owns it.

    The project/service labels come from ``ps`` rather than ``inspect`` so that
    finding the rest of a compose project - the siblings that must move with the
    service someone clicked - costs no extra round trip.
    """
    ok, out = run(PRELUDE + 'docker ps -a --format '
                  '\'{{.Names}}\t{{.Image}}\t{{.Label "com.docker.compose.project"}}'
                  '\t{{.Label "com.docker.compose.service"}}\'', timeout=25)
    if not ok:
        raise RuntimeError((out or 'docker ps failed').strip()[:300])
    rows = []
    for line in (out or '').splitlines():
        parts = line.split('\t')
        if not parts[0].strip():
            continue
        rows.append({
            'name': parts[0].strip(),
            'image': (parts[1] if len(parts) > 1 else '').strip(),
            'project': (parts[2] if len(parts) > 2 else '').strip(),
            'service': (parts[3] if len(parts) > 3 else '').strip(),
        })
    return rows


def _inspect(run, names) -> list[dict]:
    if not names:
        return []
    import json
    quoted = ' '.join(shlex.quote(name) for name in names)
    ok, out = run(PRELUDE + f"$DK inspect --format '{{{{json .}}}}' {quoted}", timeout=30)
    if not ok:
        raise RuntimeError((out or 'docker inspect failed').strip()[:300])
    rows = []
    for line in (out or '').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows


def _is_manager(run) -> bool:
    ok, out = run(PRELUDE + '$DK info --format "{{.Swarm.ControlAvailable}}"', timeout=20)
    return bool(ok and (out or '').strip().lower() == 'true')


_manager_cache = {'ts': 0.0, 'key': '', 'for': ''}
_manager_lock = threading.Lock()
MANAGER_TTL = 300.0


def manager_for(host_key: str, run=None) -> str:
    """A host that can run ``docker service update``.

    A worker refuses swarm commands, so a stack's containers on a worker would
    otherwise be un-updatable from the node they happen to live on.  The answer
    is cached per asked-for host for five minutes, because finding it costs an
    SSH round trip per configured host.
    """
    now = time.time()
    with _manager_lock:
        if (_manager_cache['key'] and _manager_cache['for'] == host_key
                and (now - _manager_cache['ts']) < MANAGER_TTL):
            return _manager_cache['key']

    if run is None:
        _info, run = _runner(host_key)
    if _is_manager(run):
        with _manager_lock:
            _manager_cache.update(ts=time.time(), key=host_key, **{'for': host_key})
        return host_key

    for other in ep.all_host_keys():
        if other == host_key:
            continue
        try:
            release_session()
            _other_info, other_run = _runner(other)
            if _is_manager(other_run):
                with _manager_lock:
                    _manager_cache.update(ts=time.time(), key=other, **{'for': host_key})
                return other
        except Exception:
            continue
    return ''


def estate_target(target: dict) -> dict:
    """Turn a swarm target into an estate update when the stack is managed there.

    The stack a container belongs to is the estate's service name (both are the
    ``com.docker.stack.namespace`` label), so a row's swarm service resolves to a
    ``wizard.yaml`` entry without any guessing.  Falls back to the direct
    ``service update`` when the estate is off, unknown, or says the service is
    build-kind - a monitoring app must not be the reason an update cannot happen.
    """
    stack = (target.get('project') or '').strip()
    if not stack:
        return target
    try:
        from estate import settings as estatesettings
        from estate import update as estupdate
        if not estatesettings.enabled():
            target['note'] = (target.get('note') or '') + \
                ' (the estate pipeline is off: AILOG_ALLOW_ESTATE=off)'
            return target
        estate_plan = estupdate.plan(stack)
    except Exception as exc:                       # noqa: BLE001 - shown as a note
        target['note'] = f'estate: could not plan {stack} ({exc}) - using a direct service update'
        return target

    target['estate'] = estate_plan
    if not estate_plan.get('supported'):
        target['note'] = estate_plan.get('reason') or 'the estate does not manage this service'
        return target
    target['kind'] = 'estate'
    target['service'] = estate_plan.get('name') or stack
    target['estate_service'] = estate_plan.get('name') or stack
    target['commands'] = []
    target['runs_on'] = 'CI'
    if estate_plan.get('action') == 'rebuild':
        target['note'] = (f'rebuilds {estate_plan.get("name")} from its source and lets CI '
                          f'build, push and deploy it, so the running image is a build of '
                          f'the committed source rather than whatever the tag points at')
    else:
        target['note'] = (f'moves the image in git ({estate_plan.get("current")} -> '
                          f'{estate_plan.get("target")}) and lets CI deploy it, so the '
                          f'running image stays the one the estate pins')
    return target


def plan(host_key: str, image: str = '', container: str = '') -> dict:
    """What would be run, for the containers a pane row refers to."""
    image = (image or '').strip()
    container = (container or '').strip()
    if not image and not container:
        raise RuntimeError('an image or a container name is required')

    info, run = _runner(host_key)
    release_session()
    rows = _ps_rows(run)
    wanted = [r['name'] for r in rows
              if (container and r['name'] == container)
              or (image and r['image'] == image)]
    if not wanted and container:
        wanted = [container]
    release_session()
    inspected = _inspect(run, wanted)

    # A clicked row is one container, but the thing that has to move may be the
    # publisher's whole set (immich-server + immich-machine-learning).  Add the
    # siblings from the same project before planning, so the plan that gets
    # shown is the plan that runs.
    if inspected:
        extra = set()
        for probe in group_targets(inspected):
            extra.update(siblings(rows, probe))
        extra.difference_update(wanted)
        if extra:
            inspected = inspected + _inspect(run, sorted(extra))
    targets = group_targets(inspected)

    # The estate decides before the manager probe: an estate update never runs
    # `docker service update`, so paying an SSH round trip per host to find a
    # manager it will not use would be a slow lie.
    for target in targets:
        if target['kind'] == 'swarm':
            estate_target(target)

    manager = ''
    if any(t['kind'] == 'swarm' and not t['reason'] for t in targets):
        manager = manager_for(host_key, run)

    for target in targets:
        if target['kind'] == 'swarm':
            target['runs_on'] = manager or host_key
            target['note'] = (f'rolls this service onto whatever the registry serves for '
                              f'{target["image"]} now; the tag pinned in homelab-ops is unchanged'
                              + (f'. {target["note"]}' if target.get('note') else ''))
        elif target['kind'] == 'estate':
            target['runs_on'] = 'CI'
        elif target['kind'] == 'compose':
            target['runs_on'] = host_key
            services = target_services(target)
            if len(services) > 1:
                target['note'] = (f'recreates {", ".join(services)} together — they are '
                                  f'published as one version, so moving only one of them would '
                                  f'leave project {target["project"] or "?"} on two releases')
            else:
                target['note'] = (f'recreates only the {target["service"]} service of project '
                                  f'{target["project"] or "?"} — no other container in it is touched')
        else:
            target['runs_on'] = host_key
            target['note'] = ''

    return {
        'host_key': host_key,
        'host_name': info.get('friendly_name') or info.get('name') or host_key,
        'image': image,
        'container': container,
        'targets': targets,
        'supported': bool(targets) and all(
            (t['kind'] == 'estate') or bool(t['commands']) for t in targets),
        'mode': mode(),
        'ts': time.time(),
    }


# --------------------------------------------------------------------------
# running it
# --------------------------------------------------------------------------

_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()
JOB_TTL = 3600


def _job_update(job_id: str, **patch) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job:
            job.update(patch)


def _job_step(job_id: str, label: str, ok=None, detail: str = '') -> None:
    """Record a step, and resolve the same step in place when it finishes.

    A step is opened when its command starts (``ok=None``, so the dialog can show
    what is running) and closed with the exit status; appending twice would show
    every command as two lines, one of them permanently unresolved.
    """
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return
        last = job['steps'][-1] if job['steps'] else None
        if last and last['label'] == label:
            if detail:
                last['detail'] = detail
            if ok is not None:
                last['ok'] = ok
            job['label'] = label
            return
        job['steps'].append({'label': label, 'ok': ok, 'detail': detail})
        job['label'] = label


def _job_progress(job_id: str, pct: float) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is not None:
            job['progress'] = max(0.0, min(100.0, round(float(pct), 1)))


def _job_log(job_id: str, text: str) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is not None:
            job['output'].append(text)
            job['output'] = job['output'][-200:]


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


def _execute_estate(job_id: str, target: dict) -> bool:
    """Hand the update to the estate pipeline and mirror its progress here.

    Same job dict, so the dialog does not care that the work moved from a shell
    command to a commit, a PR and two CI runs.
    """
    from estate import update as estupdate

    estate_plan = target.get('estate') or {}
    name = target.get('estate_service') or estate_plan.get('name') or target.get('service')
    sink = estupdate.LinkedSink(
        step=lambda label, ok=None, detail='': _job_step(job_id, label, ok=ok, detail=detail),
        log=lambda text: _job_log(job_id, text),
        progress=lambda pct: _job_progress(job_id, pct),
    )
    try:
        result = estupdate.perform(name, sink)
    except Exception as exc:                      # noqa: BLE001 - shown in the dialog
        _job_step(job_id, 'estate update', ok=False, detail=str(exc)[:300])
        _job_update(job_id, error=str(exc))
        return False
    if result.get('up_to_date'):
        _job_step(job_id, 'already newest', ok=True, detail=str(result.get('current')))
        # A distinct note, because "done" here means "nothing to deploy" and the
        # dialog should not claim the host is being re-read for a change.
        _job_update(job_id, note='already newest')
        return True
    if result.get('dry_run'):
        return True
    _job_step(job_id, 'deployed by CI', ok=True,
              detail=f"PR #{result.get('pr')} · run {result.get('run')}")
    return True


def _execute(job_id: str, host_key: str, target: dict, dry: bool) -> bool:
    """Run one target's commands. Returns True when everything exited 0."""
    if target.get('kind') == 'estate':
        return _execute_estate(job_id, target)
    runs_on = target.get('runs_on') or host_key
    _info, run = _runner(runs_on)
    release_session()
    every_ok = True
    for command in target.get('commands') or []:
        label = 'pull' if ' pull ' in command else ('recreate' if ' up ' in command else 'service update')
        _job_step(job_id, f"{label} {target['service']}", detail=command)
        if dry:
            _job_log(job_id, f"$ {command}\n(dry run — not executed)")
            _job_step(job_id, f"{label} {target['service']}", ok=True, detail='dry run')
            continue
        started = time.time()
        ok, out = run(command, timeout=PULL_TIMEOUT if label == 'pull' else RUN_TIMEOUT)
        release_session()
        for line in (out or '').strip().splitlines():
            _job_log(job_id, line)
        _job_step(job_id, f"{label} {target['service']}", ok=ok,
                  detail=f"{round(time.time() - started, 1)}s")
        if not ok:
            every_ok = False
            break
    return every_ok


def _worker(app, job_id: str, host_key: str, image: str, container: str) -> None:
    with app.app_context():
        try:
            _job_step(job_id, 'reading the host', detail=f'{host_key}')
            current = plan(host_key, image, container)
            _job_update(job_id, plan=current)
            targets = len(current['targets'])
            _job_step(job_id, 'reading the host', ok=True,
                      detail=f"{targets} target{'' if targets == 1 else 's'}")
            if not current['supported']:
                reasons = '; '.join(t['reason'] for t in current['targets'] if t['reason'])
                _job_update(job_id, status='blocked',
                            error=reasons or 'nothing on this host matches that image')
                return
            dry = current['mode'] != 'on'
            if dry:
                _job_step(job_id, 'dry run', detail='AILOG_ALLOW_UPDATES is not "on"')
            every_ok = True
            for target in current['targets']:
                every_ok = _execute(job_id, host_key, target, dry) and every_ok
            _job_update(job_id, status='done' if every_ok else 'error',
                        error='' if every_ok else 'one or more commands failed — see the log')
        except Exception as exc:                      # noqa: BLE001 - shown in the dialog
            _job_update(job_id, status='error', error=str(exc) or exc.__class__.__name__)
        finally:
            _job_update(job_id, finished=time.time())
            release_session()


def start(app, host_key: str, image: str = '', container: str = '') -> dict:
    """Queue the update and return the job the dialog polls."""
    _prune()
    job_id = uuid.uuid4().hex[:12]
    with _jobs_lock:
        _jobs[job_id] = {
            'id': job_id,
            'host_key': host_key,
            'image': image,
            'container': container,
            'status': 'running',
            'label': 'queued',
            'progress': 0.0,
            'steps': [],
            'output': [],
            'plan': None,
            'error': '',
            'started': time.time(),
            'finished': 0.0,
        }
    threading.Thread(target=_worker, args=(app, job_id, host_key, image, container),
                     name=f'docker-update-{job_id}', daemon=True).start()
    return job(job_id)


# --------------------------------------------------------------------------
# stack updates: the swarm way
# --------------------------------------------------------------------------

def _stack_worker(app, job_id: str, host_key: str, stack: str, service: str,
                  version: str, prune: bool) -> None:
    """One service of one stack, moved to a chosen version and proved running."""
    from estate import stackservice, update as estupdate
    from estate import render, settings as estatesettings
    from estate.update import LinkedSink
    from . import registrygc, swarmstack

    with app.app_context():
        try:
            _job_step(job_id, 'read the cluster', detail=f'{stack}/{service}')
            plan = swarmstack.versions(host_key, stack, service)
            current = plan['current']
            _job_step(job_id, 'read the cluster', ok=True,
                      detail=f"{current['tag']} @ {(current['digest'] or '?')[:19]}")

            chosen = next((c for c in plan['candidates'] if c['tag'] == version), None)
            if chosen and chosen.get('blocked'):
                _job_update(job_id, status='blocked', error=chosen['blocked'])
                _job_step(job_id, 'resolve version', ok=False, detail=chosen['blocked'])
                return
            if version != current['tag'] and not chosen:
                raise RuntimeError(f'{version} is not a version zot holds or upstream publishes '
                                   f'for {plan["target_repo"]}')
            mirror_source = ''
            if chosen and not chosen.get('in_zot'):
                mirror_source = chosen.get('source') or ''
            _job_step(job_id, 'resolve version', ok=True,
                      detail=f"{current['tag']} -> {version}"
                             + (' (mirror into zot first)' if mirror_source else
                                ('' if version != current['tag'] else ' (same tag, newer digest)')))

            # Same tag, different digest: nothing in git changes, so the honest
            # move is to roll the service onto the digest zot serves now.
            if version == current['tag']:
                _job_step(job_id, 'roll the service onto the new digest')
                _info, run = _runner(host_key)
                command = ('$DK service update --image {image} --with-registry-auth --force {svc}'
                           .format(image=shlex.quote(current['image']),
                                   svc=shlex.quote(f'{stack}_{service}')))
                ok, out = run(PRELUDE + command, timeout=RUN_TIMEOUT)
                for line in (out or '').strip().splitlines():
                    _job_log(job_id, line)
                _job_step(job_id, 'roll the service onto the new digest', ok=ok,
                          detail='' if ok else (out or '').strip()[:200])
                if not ok:
                    raise RuntimeError('docker service update failed - see the log')
                _job_progress(job_id, 70)
            else:
                sink = LinkedSink(
                    step=lambda label, ok=None, detail='': _job_step(job_id, label, ok=ok, detail=detail),
                    log=lambda text: _job_log(job_id, text),
                    progress=lambda pct: _job_progress(job_id, pct),
                )
                entry = None
                try:
                    from estate.git import Repo
                    entry = render.find_service(
                        render.load_intent(Repo().read('wizard.yaml')), stack)
                except Exception:                 # noqa: BLE001 - a missing tree is not fatal
                    entry = None
                wizard_service = (render.service_of(entry) if entry else '') or ''
                if (entry and wizard_service == service and entry.get('kind') != 'build'
                        and estatesettings.enabled()):
                    # The estate's own service: let the estate move its pin,
                    # its mirror entry and its wizard.yaml version together.
                    estupdate.perform(stack, sink, version=version)
                else:
                    stackservice.perform(stack, service, version, sink,
                                         mirror_source=mirror_source)
                _job_progress(job_id, 90)

            _job_step(job_id, 'verify running', detail=f'{stack}/{service} on {version}')
            stackservice.wait_for_service(host_key, stack, service, version,
                                          LinkedSink(
                                              step=lambda label, ok=None, detail='':
                                              _job_step(job_id, label, ok=ok, detail=detail),
                                              log=lambda text: _job_log(job_id, text),
                                              progress=lambda pct: None,
                                          ))
            _job_progress(job_id, 96)

            if prune:
                _job_step(job_id, 'prune zot', detail=f'keeping the last {registrygc.keep_default()}')
                try:
                    result = registrygc.prune(repos=[plan['target_repo']])
                    count = len(result.get('deleted') or [])
                    _job_step(job_id, 'prune zot', ok=True,
                              detail=f'{count} old tag(s) removed from {plan["target_repo"]}'
                                     if count else 'nothing to remove')
                except Exception as exc:          # noqa: BLE001 - never fail an update on this
                    _job_step(job_id, 'prune zot', ok=False, detail=str(exc)[:200])
            _job_progress(job_id, 100)
            _job_update(job_id, status='done', note='deployed by CI and verified running')
        except Exception as exc:                  # noqa: BLE001 - shown in the dialog
            _job_update(job_id, status='error', error=str(exc) or exc.__class__.__name__)
            _job_log(job_id, f'!! {exc}')
        finally:
            _job_update(job_id, finished=time.time())
            release_session()


def start_stack(app, host_key: str, stack: str, service: str, version: str,
                prune: bool = True) -> dict:
    """Queue a stack-service update; the dialog polls it like any other job."""
    _prune()
    job_id = uuid.uuid4().hex[:12]
    with _jobs_lock:
        _jobs[job_id] = {
            'id': job_id,
            'host_key': host_key,
            'image': '',
            'container': f'{stack}_{service}',
            'stack': stack,
            'service': service,
            'version': version,
            'status': 'running',
            'label': 'queued',
            'progress': 0.0,
            'steps': [],
            'output': [],
            'plan': None,
            'error': '',
            'started': time.time(),
            'finished': 0.0,
        }
    threading.Thread(target=_stack_worker,
                     args=(app, job_id, host_key, stack, service, version, prune),
                     name=f'swarm-update-{job_id}', daemon=True).start()
    return job(job_id)
