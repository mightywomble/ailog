"""One service inside a stack, moved to a version someone chose.

:func:`estate.update.perform` moves a *service the estate knows by name*: it
bumps ``wizard.yaml``'s version, which is the app's own image. That is the right
thing for ``metamcp``'s ``app`` and the wrong thing for ``metamcp``'s
``postgres`` — the database is a companion, recorded in ``wizard.yaml`` as a
name and nowhere else, so an update to it has to be written where it lives: the
stack file's ``image:`` line and (when the version is new to us) the mirror list.

Everything after the commit is the same pipeline as any other estate update,
because it must be: a merge to the working branch, a pull request to ``main``
whose required checks decide whether it may merge, and ``ship.yml`` deploying
the stack with the runner on the build server. The one thing this adds is the
last word — that the version asked for is the version running.
"""

from __future__ import annotations

import json
import re
import time

from . import forge as forge_mod
from . import render, settings
from . import update as upd
from .git import Conflict, Repo

TAG_PLACEHOLDER = re.compile(r'\$\{IMAGE_TAG:-([^}]*)\}')


def set_image_version(text: str, service: str, image: str, tag: str) -> tuple[str, bool]:
    """Rewrite one service's image, keeping the deploy placeholder if it has one.

    A build app's image is ``${IMAGE_TAG:-build-347}``: ``ship.yml`` exports the
    tag it just built and the placeholder lets one stack carry two built apps.
    Writing a literal tag there would silently disable that. So the placeholder
    is preserved and only its default moves; a plain image gets ``repo:tag``.
    """
    lines = text.splitlines(keepends=True)
    head = None
    indent = 0
    for i, line in enumerate(lines):
        m = re.match(r'^(\s*)([A-Za-z0-9._-]+):\s*(#.*)?$', line)
        if m and m.group(2) == service and (head is None or len(m.group(1)) <= indent):
            head, indent = i, len(m.group(1))
            continue
        if head is None:
            continue
        stripped = line.strip()
        if stripped and not stripped.startswith('#') and (len(line) - len(line.lstrip())) <= indent:
            break
        m2 = re.match(r'^(\s*)image:\s*(.+?)\s*$', line)
        if not m2:
            continue
        current = m2.group(2).strip('"\'')
        if TAG_PLACEHOLDER.search(current):
            new = TAG_PLACEHOLDER.sub(lambda _m: '${IMAGE_TAG:-' + tag + '}', current, count=1)
        else:
            base = current.split('@', 1)[0]
            base = base.rsplit(':', 1)[0] if ':' in base.rsplit('/', 1)[-1] else base
            new = f'{base}:{tag}'
        if new == current:
            return text, False
        quote = '"' if m2.group(2)[:1] == '"' else ''
        lines[i] = f'{m2.group(1)}image: {quote}{new}{quote}\n'
        return ''.join(lines), True
    return text, False


def service_image(stack_text: str, service: str) -> str:
    """The image line a stack file currently carries for one service."""
    import yaml
    try:
        doc = yaml.safe_load(stack_text) or {}
    except yaml.YAMLError:
        return ''
    return str(((doc.get('services') or {}).get(service) or {}).get('image') or '')


def _current_tag(image: str) -> str:
    ref = (image or '').split('@', 1)[0]
    match = TAG_PLACEHOLDER.search(ref)
    if match:
        return match.group(1).strip()
    tail = ref.rsplit('/', 1)[-1]
    return tail.rsplit(':', 1)[-1] if ':' in tail else ''


def perform(stack: str, service: str, version: str, sink: upd.Sink,
            mirror_source: str = '', prune: bool = True) -> dict:
    """Move one service in one stack to ``version``, through CI, and prove it."""
    if not settings.enabled():
        raise upd.EstateError('the estate pipeline is disabled on this server '
                              '(AILOG_ALLOW_ESTATE=off)')
    version = (version or '').strip()
    if not version:
        raise upd.EstateError('no version was chosen')

    repo = Repo()
    sink.progress(3)
    sink.step('sync estate repo', detail=f'{settings.owner()}/{settings.name()} @ '
                                         f'{settings.work_branch()}')
    head = repo.sync()
    sink.step('sync estate repo', ok=True, detail=f'{(head or "")[:8]}')

    stack_rel = f'stacks/{stack}/stack.yml'
    stack_text = repo.read(stack_rel)
    if not stack_text:
        raise upd.EstateError(f'{stack_rel} does not exist, so {stack} is not a stack '
                              f'the estate deploys')
    image = service_image(stack_text, service)
    if not image:
        raise upd.EstateError(f'{stack} has no service called {service}')
    current = _current_tag(image)
    if current == version:
        sink.step('already on this version', ok=True, detail=f'{service} runs {version}')
        sink.progress(100)
        return {'up_to_date': True, 'stack': stack, 'service': service, 'target': version}
    sink.step('read the cluster', ok=True,
              detail=f'{stack}/{service}: {current or "?"} -> {version}')
    sink.progress(10)

    entry = render.find_service(render.load_intent(repo.read('wizard.yaml')), stack)
    wizard_service = (render.service_of(entry) if entry else '') or ''

    if settings.dry_run():
        sink.log('(dry run - AILOG_ALLOW_ESTATE is not "on")')
        sink.log(f'would set {stack_rel} {service} to {version}')
        if mirror_source:
            sink.log(f'would mirror {mirror_source} into {settings.registry()} first')
        sink.log(f'would push {settings.work_branch()}, open a PR to '
                 f'{settings.base_branch()}, merge it and wait for {upd.SHIP_WF}')
        sink.progress(100)
        return {'dry_run': True, 'stack': stack, 'service': service,
                'current': current, 'target': version}

    def edit(repo: Repo):
        text = repo.read(stack_rel)
        live = _current_tag(service_image(text, service))
        if live and live != current:
            raise Conflict(f'{stack}/{service} moved to {live} on the branch while this '
                           f'update was being prepared (was {current}) - re-plan it')
        new_text, changed = set_image_version(text, service, image, version)
        if not changed:
            raise Conflict(f'{stack_rel} already names {version} for {service}')
        files = {stack_rel: new_text}

        # The estate's own record, when this is the service it knows about: the
        # page reads wizard.yaml, and a stack/version pair that disagrees with
        # it is exactly the drift v3.23.1 was written about.
        if entry and wizard_service == service:
            bumped, new_entry = render.bump_intent(repo.read('wizard.yaml'), stack, version)
            files['wizard.yaml'] = bumped
            full = render.image_ref(new_entry, settings.registry())
            image_text, image_changed = set_image_version(files[stack_rel], service, image, version)
            if image_changed:
                files[stack_rel] = image_text
            sink.log(f'wizard.yaml: {stack} version -> {version} ({full})')

        if mirror_source and ':' in mirror_source.rsplit('/', 1)[-1]:
            doc = _mirror_doc(repo)
            rows = doc.setdefault('mirrors', [])
            name = image.split('@', 1)[0].rsplit('/', 1)[-1].rsplit(':', 1)[0]
            target_source = _retag(mirror_source, version)
            for index, row in enumerate(rows):
                if row.get('name') == name:
                    rows[index] = {'name': name, 'source': target_source}
                    break
            else:
                rows.append({'name': name, 'source': target_source})
            files['mirror-images.json'] = json.dumps(doc, indent=2) + '\n'
        for relpath, body in files.items():
            repo.write(relpath, body)
        return entry or {'name': stack}, list(files)

    message = (f'{stack}/{service}: {current or "?"} -> {version}\n\n'
               f'Moved by ailog from the Docker view. Only this service of this stack '
               f'moves; the rest of {stack} is deployed unchanged.')
    sink.step(f'pin {stack}/{service} {current or "?"} -> {version}')
    result = repo.apply(edit, message)
    sink.step(f'pin {stack}/{service} {current or "?"} -> {version}', ok=True,
              detail=', '.join(result['changed']) or 'nothing changed')
    sink.progress(25)

    forge = forge_mod.Forge()
    sha = result['head']

    # Pulling the image into zot is a CI job, not an app one: mirror.yml holds
    # the zot credentials, runs on the build server and is the same mechanism
    # every other mirrored image uses. The gate is that the digest zot serves
    # afterwards is the one we asked for.
    if 'mirror-images.json' in (result.get('changed') or []):
        sink.step('pull into zot', detail=f'waiting for {upd.MIRROR_WF.split("/")[-1]}')
        run = forge.find_run(upd.MIRROR_WF, sha=sha, timeout=upd.PULL_TIMEOUT)
        if run is None:
            raise upd.EstateError(f'{upd.MIRROR_WF.split("/")[-1]} did not start for '
                                  f'{sha[:8]} - the push may not have triggered CI')
        ok, status = upd._watch_run(forge, run, sink, base=25, span=25)
        if not ok:
            raise upd.EstateError(f'the mirror run failed ({status}) - zot does not have '
                                  f'{version}, so the stack would not deploy')
        sink.step('pull into zot', ok=True, detail=f'{version} is in zot')

    title = f'{stack}/{service}: {current or "?"} -> {version}'
    body = (f'Opened by ailog after `{stack}/{service}` was updated to `{version}` in the '
            f'Docker view.\n\n'
            f'- `{stack_rel}`: `{service}` image pinned to `{version}`\n'
            + ('- `mirror-images.json`: the new tag copied into zot first\n'
               if 'mirror-images.json' in (result.get('changed') or []) else '')
            + f'\nMerging deploys only the `{stack}` stack.')
    pr = forge.create_pr(title, head=settings.work_branch(),
                         base=settings.base_branch(), body=body)
    sink.step('pull request', ok=True, detail=f'#{pr.get("number")} {upd.summary_title(pr)}')
    sink.progress(55)

    merged = upd._merge(forge, sink, pr)
    sink.step('merged', ok=True, detail=f'PR #{pr["number"]}')
    sink.progress(62)

    run = forge.find_run(upd.SHIP_WF, sha=merged.get('sha') or '', timeout=upd.PULL_TIMEOUT)
    if run is None:
        raise upd.EstateError(f'the merge landed but {upd.SHIP_WF.split("/")[-1]} did not '
                              f'start for {(merged.get("sha") or "")[:8]}')
    ok, status = upd._watch_run(forge, run, sink, base=62, span=25)
    if not ok:
        raise upd.EstateError(f'the deploy run failed ({status}) - see the log above')
    sink.progress(88)
    return {'stack': stack, 'service': service, 'current': current, 'target': version,
            'pr': pr['number'], 'run': run.get('id'), 'sha': merged.get('sha') or '',
            'mirrored': 'mirror-images.json' in (result.get('changed') or [])}


def _mirror_doc(repo: Repo) -> dict:
    try:
        doc = json.loads(repo.read('mirror-images.json', '{"mirrors": []}') or '{}')
    except ValueError:
        doc = {'mirrors': []}
    doc.setdefault('mirrors', [])
    return doc


def _retag(source: str, version: str) -> str:
    """``docker.io/library/postgres:16-alpine`` + ``16.4-alpine`` -> the new ref."""
    ref = (source or '').split('@', 1)[0]
    tail = ref.rsplit('/', 1)[-1]
    if ':' in tail:
        return ref.rsplit(':', 1)[0] + ':' + version
    return ref + ':' + version


def wait_for_service(host_key: str, stack: str, service: str, version: str,
                     sink: upd.Sink, timeout: float = 240.0, poll: float = 6.0) -> bool:
    """Did the cluster actually end up running ``version``?

    The missing last word in every update this estate has ever done: "deployed"
    meant "the run was green", and a stack that stayed on the old image while
    the run passed looks identical from the outside. Reads the service spec the
    manager holds — the same value the scan compares — and waits for the tasks
    to be running before answering.
    """
    from dockermon import swarmstack

    deadline = time.time() + timeout
    last = ''
    while time.time() < deadline:
        try:
            _info, run = swarmstack._runner(host_key)
            rows = [r for r in swarmstack.read_services(run)
                    if r['stack'] == stack and r['short'] == service]
        except Exception as exc:                  # noqa: BLE001 - a blip is not a failure
            sink.log(f'(could not read {stack}/{service}: {exc})')
            time.sleep(poll)
            continue
        if not rows:
            raise upd.EstateError(f'{stack}/{service} is not on the cluster any more')
        row = rows[0]
        running, _, desired = row['replicas'].partition('/')
        detail = f"{row['tag']} {running}/{desired or '?'}"
        if row['tag'] == version and running and running == desired:
            sink.step('verify running', ok=True, detail=detail)
            return True
        if detail != last:
            last = detail
            sink.step('verify running', detail=detail)
        time.sleep(poll)
    raise upd.EstateError(f'{stack}/{service} never came up on {version} '
                          f'(last seen: {last or "nothing"}) - the deploy ran, the '
                          f'cluster did not take it')
