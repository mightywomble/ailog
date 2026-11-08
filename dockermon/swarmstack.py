"""Swarm updates are *stack* updates, and they are chosen, not guessed.

The per-host container scan answers "has this image tag moved?" — the right
question for a box running ``image:latest``. It is the wrong question for a
swarm, for three reasons that all showed up on the same day:

* a service is not a container. ``metamcp`` is ``app`` and ``postgres``; nobody
  wanting to move the database wants to be shown a task revision called
  ``metamcp_postgres.1.x865qef475upe4508azofd5is``;
* a deploy leaves the previous task's container behind, exited, on the node it
  ran on. Judged container by container that is indistinguishable from an
  out-of-date image — which is why the manager kept offering an update for a
  database that had already moved;
* a digest is not a version. "newer image upstream" cannot say *what* to move
  to, so there is nothing to choose and nothing to write down.

So this module reads the cluster the way swarm describes it — ``docker service
inspect`` on a manager — and answers three questions:

``scan(host_key)``
    every stack, every service, the image it is deployed with, the digest swarm
    resolved that tag to, and whether the registry now serves a different
    digest for it.

``versions(host_key, stack, service)``
    what that service could be moved *to*: the tags zot already holds (with
    their digests, so "in zot" is a fact rather than a hope), the tags upstream
    publishes that would have to be mirrored in first, and — for an app the
    estate builds from source — a rebuild.

The service's deployed image spec is ``repo:tag@sha256:…`` because swarm
resolves the tag at deploy time. That makes the comparison exact: it is what
the cluster is running, not what some container on some node happens to be.
"""

from __future__ import annotations

import json
import re
import threading
import time

from estate import tags as reftags

from . import updates as reg

TTL = 60.0

_lock = threading.Lock()
_cache: dict[str, tuple[float, dict]] = {}

# What a stack scan is doing right now, in the same shape as the per-host scan
# in `updates` -- the activity strip reads both, and a manager's re-check is as
# slow as the per-container one (a registry lookup per service) but used to say
# nothing at all: only a silent "Reading the cluster…" placeholder for two or
# three seconds.
_progress: dict = {'active': False, 'stage': '', 'host': '', 'done': 0,
                   'total': 0, 'started': 0.0}
_progress_lock = threading.Lock()


def _progress_begin(host_key: str, stage: str, total: int = 0) -> None:
    with _progress_lock:
        _progress.update(active=True, stage=stage, host=host_key, done=0,
                         total=int(total or 0), started=time.time())


def _progress_step(_key: str = '') -> None:
    with _progress_lock:
        if _progress['active']:
            _progress['done'] += 1


def _progress_end() -> None:
    with _progress_lock:
        _progress.update(active=False, stage='', host='', done=0, total=0,
                         started=0.0)


def activity() -> dict | None:
    """The stack scan in flight, or None. No SSH, no registry, no work."""
    with _progress_lock:
        if not _progress['active']:
            return None
        row = dict(_progress)
    row['elapsed'] = round(time.time() - row['started'], 1)
    return row

# The images that cannot survive a major bump on the same data directory.
DATABASES = ('postgres', 'postgres16', 'mysql', 'mariadb', 'mongo', 'redis',
             'valkey', 'clickhouse', 'timescale', 'couchdb')

# ``{{if .Spec.Mode.Global}}`` is the obvious way to ask "is this global?" and
# it is a trap: docker renders templates with missingkey=error, so the map that
# describes a *global* service has no ``Replicated`` key and the one that
# describes a replicated service has no ``Global`` key - either question fails
# on half the cluster with "map has no entry for key". ``json .Spec.Mode`` asks
# nothing and cannot fail. The task counts are just as conditional (a service
# created seconds ago has no ServiceStatus at all), so they come from
# ``docker service ls``, which always has them.
SWARM_INSPECT = (
    "{{.Spec.Name}}\t{{index .Spec.Labels \"com.docker.stack.namespace\"}}\t"
    "{{.Spec.TaskTemplate.ContainerSpec.Image}}\t{{json .Spec.Mode}}"
)

SWARM_REPLICAS = '{{.Name}}\t{{.Replicas}}'


def parse_ref(image: str) -> dict:
    """``zot.safehomelan.com/postgres16:16-alpine@sha256:ac83`` -> its parts."""
    text = (image or '').strip()
    digest = ''
    if '@' in text:
        text, digest = text.split('@', 1)
    try:
        host, repo, tag = reg.split_image(text)
    except ValueError:
        return {'image': image, 'host': '', 'repo': '', 'tag': '', 'digest': digest}
    return {'image': image, 'host': host, 'repo': repo, 'tag': tag,
            'digest': digest, 'ref': text}


def _runner(host_key: str):
    from . import updateflow
    return updateflow._runner(host_key)


def is_manager(run) -> bool:
    from .updateflow import PRELUDE
    ok, out = run(PRELUDE + '$DK info --format "{{.Swarm.ControlAvailable}}"', timeout=20)
    return bool(ok and (out or '').strip().lower() == 'true')


def is_swarm_node(run) -> bool:
    """A worker and a host that never joined a swarm both say manager: false.

    They are not the same page: a worker belongs to the cluster and must not be
    offered container updates (the manager owns them), while a plain host has
    nothing *but* its own containers to update. ``LocalNodeState`` is what
    tells them apart - ``active`` on any node in a swarm, ``inactive`` outside.
    """
    from .updateflow import PRELUDE
    ok, out = run(PRELUDE + '$DK info --format "{{.Swarm.LocalNodeState}}"', timeout=20)
    return bool(ok and (out or '').strip().lower() == 'active')


def read_services(run) -> list[dict]:
    """Every service on the cluster, straight from the manager (one round trip)."""
    from .updateflow import PRELUDE
    inspect = '$DK service inspect --format \'' + SWARM_INSPECT + '\' $($DK service ls -q)'
    ok, out = run(PRELUDE + inspect, timeout=45)
    if not ok:
        raise RuntimeError((out or 'docker service inspect failed').strip()[:300])
    counts = {}
    ok_r, out_r = run(PRELUDE + '$DK service ls --format \'' + SWARM_REPLICAS + '\'', timeout=30)
    if ok_r:
        for line in (out_r or '').splitlines():
            bits = line.split('\t')
            if len(bits) >= 2:
                counts[bits[0].strip()] = bits[1].strip()
    rows = []
    for line in (out or '').splitlines():
        parts = line.split('\t')
        if len(parts) < 4 or not parts[0].strip():
            continue
        name, stack, image, mode_json = [p.strip() for p in parts[:4]]
        mode = 'global' if 'Global' in mode_json else 'replicated'
        replicas = counts.get(name, '')
        ref = parse_ref(image)
        rows.append({
            'service': name,
            'stack': stack or name.rsplit('_', 1)[0],
            'short': name.rsplit('_', 1)[-1],
            'image': image,
            'host': ref['host'],
            'repo': ref['repo'],
            'tag': ref['tag'],
            'digest': ref['digest'],
            'mode': mode,
            'replicas': replicas,
        })
    return rows


# --------------------------------------------------------------------------
# the mirror mapping: zot repo -> the upstream reference it is copied from
# --------------------------------------------------------------------------

def mirror_sources() -> dict[str, str]:
    """``{'postgres16': 'docker.io/library/postgres:16-alpine'}`` from the tree.

    The estate records what each zot repository is a copy of, which is the only
    way "what could this become?" can ask the right publisher.  A missing tree
    is not an error: the answer is then just "what zot already holds".
    """
    try:
        from estate import settings as estatesettings
        from estate.git import Repo
        repo = Repo()
        text = ''
        if repo.exists():
            text = repo.read('mirror-images.json', '{"mirrors": []}') or '{}'
        if not text.strip('{} \n'):
            # No checkout yet (a fresh install, or this app in development):
            # the tree beside the app is the same file, one release older at
            # worst. Better than an empty picker.
            import os
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            path = os.path.join(base, estatesettings.root(), 'mirror-images.json')
            with open(path, 'r') as handle:
                text = handle.read() or '{}'
        doc = json.loads(text)
    except Exception:                     # noqa: BLE001 - a picker must not fail on this
        return {}
    out = {}
    for row in doc.get('mirrors') or []:
        name = str(row.get('name') or '').strip()
        source = str(row.get('source') or '').strip()
        if name and source:
            out[name] = source
    return out


def _zot_host() -> str:
    from estate import settings as estatesettings
    return estatesettings.registry()


def _zot_digest(repo: str, tag: str) -> str:
    info = reg.remote_digest(f'{_zot_host()}/{repo}:{tag}')
    return info.get('digest') or ''


# --------------------------------------------------------------------------
# the scan
# --------------------------------------------------------------------------

def _tag_keys(rows: list[dict]) -> list[str]:
    """The distinct zot tags this scan will ask the registry about.

    The bar counts *these*, because these are the round trips: a cluster with
    40 services can still be 12 registry questions, and it is the questions
    that take the time.
    """
    zot_host = _zot_host()
    seen: list[str] = []
    for row in rows:
        if row.get('host') != zot_host:
            continue
        key = f'{row["repo"]}:{row["tag"]}'
        if key not in seen:
            seen.append(key)
    return seen


def _compare(rows: list[dict], refresh: bool, on_step=None) -> list[dict]:
    """Attach the registry's current digest for each service's tag.

    Only for images zot actually serves.  ``portainer_portainer`` runs
    ``portainer/portainer-ce:lts`` straight from Docker Hub; zot happens to hold
    a repository of the same name, and comparing against it manufactured an
    update for an image the cluster never pulls from there.  A service outside
    zot is not behind - it is somewhere else, and the honest thing to say is so.
    """
    zot_host = _zot_host()
    by_tag: dict[str, str] = {}
    for row in rows:
        key = f'{row["repo"]}:{row["tag"]}'
        if key in by_tag or row.get('host') != zot_host:
            continue
        info = reg.remote_digest(f'{zot_host}/{row["repo"]}:{row["tag"]}', refresh=refresh)
        by_tag[key] = info.get('digest') or ''
        if on_step:
            on_step(key)
    for row in rows:
        row['from_zot'] = row.get('host') == zot_host
        if not row['from_zot']:
            row['available'] = ''
            row['update_available'] = False
            row['note'] = (f'runs {row.get("host") or "docker.io"}/{row["repo"]}:{row["tag"]} '
                           'straight from upstream - not from zot')
            continue
        current = by_tag.get(f'{row["repo"]}:{row["tag"]}', '')
        row['available'] = current
        # A retired tag (deleted upstream, or one we never mirrored) answers
        # nothing; that is not "an update is available", it is "cannot say".
        row['update_available'] = bool(current and row['digest'] and current != row['digest'])
    return rows


def scan(host_key: str, refresh: bool = False) -> dict:
    """Every stack on the cluster, with what needs moving and what to."""
    now = time.time()
    with _lock:
        hit = _cache.get(host_key)
    if hit and not refresh and (now - hit[0]) < TTL:
        return dict(hit[1])

    # Two stages, because they fail and stall differently: reading the cluster
    # is one SSH round trip, comparing tags is one registry round trip per
    # distinct image. The strip shows the stage and, once the service list is
    # known, how many comparisons are left.
    _progress_begin(host_key, 'reading the cluster')
    try:
        _info, run = _runner(host_key)
        if not is_manager(run):
            out = {'host_key': host_key, 'manager': False, 'swarm': is_swarm_node(run),
                   'stacks': [], 'ts': now,
                   'note': 'this node is not a swarm manager, so it cannot see the cluster'}
            with _lock:
                _cache[host_key] = (now, dict(out))
            return out

        services = read_services(run)
        _progress_begin(host_key, 'comparing tags', total=len(_tag_keys(services)))
        rows = _compare(services, refresh, on_step=_progress_step)
        stacks: dict[str, dict] = {}
        for row in rows:
            stack = stacks.setdefault(row['stack'], {
                'name': row['stack'], 'services': [], 'updates': 0,
            })
            stack['services'].append(row)
            if row['update_available']:
                stack['updates'] += 1
        for stack in stacks.values():
            stack['services'].sort(key=lambda r: r['short'])
        out = {
            'host_key': host_key,
            'manager': True,
            'swarm': True,
            'stacks': sorted(stacks.values(),
                             key=lambda s: (-s['updates'], s['name'].lower())),
            'services': len(rows),
            'updates': sum(1 for r in rows if r['update_available']),
            'ts': now,
        }
        with _lock:
            _cache[host_key] = (now, dict(out))
            if len(_cache) > 32:
                for stale in [k for k, v in _cache.items() if now - v[0] > TTL * 10]:
                    _cache.pop(stale, None)
        return out
    finally:
        # A failed scan must not leave the strip saying it is still reading.
        _progress_end()


def clear(host_key: str = '') -> None:
    with _lock:
        if host_key:
            _cache.pop(host_key, None)
        else:
            _cache.clear()


# --------------------------------------------------------------------------
# what could this become?
# --------------------------------------------------------------------------

BUILD_TAG = re.compile(r'^build-\d+$')


def _major(tag: str) -> str:
    match = re.search(r'\d+', tag or '')
    return match.group(0) if match else ''


def _is_database(repo: str) -> bool:
    base = (repo or '').rsplit('/', 1)[-1].lower()
    return any(base == db or base.startswith(db) for db in DATABASES)


def _zot_candidates(repo: str) -> list[dict]:
    """Tags zot already holds for this repository, newest first, with digests."""
    try:
        listed = reftags.list_tags(f'{_zot_host()}/{repo}', limit=60)
    except Exception:                    # noqa: BLE001 - an empty list is a fair answer
        return []
    tags = [t for t in listed.get('tags') or []]
    builds = sorted([t for t in tags if BUILD_TAG.match(t)],
                    key=lambda t: int(t.split('-', 1)[1]), reverse=True)
    versions = [t for t in tags if not BUILD_TAG.match(t)]
    versions.sort(key=reftags._version_key, reverse=True)
    out = []
    for tag in (builds[:8] + versions[:12]):
        out.append({
            'tag': tag,
            'digest': _zot_digest(repo, tag),
            'in_zot': True,
            'kind': 'build' if BUILD_TAG.match(tag) else 'version',
        })
    return out


def _upstream_candidates(repo: str, sources: dict[str, str], current: str = '') -> list[dict]:
    """Tags the publisher offers that zot does not hold yet (by name).

    The publisher answers with everything it has ever published and only a dozen
    are shown, so the order is the whole feature: sorting purely by version put
    ``19rc1`` first and hid ``16.4-alpine`` - the one upgrade a postgres 16
    actually wants - behind the releases it must not take. Tags sharing the
    current major version come first, newest of those first, and only then the
    rest: the blocked ones are still listed (and explained) but never first.
    """
    source = sources.get(repo) or ''
    if not source:
        return []
    try:
        listed = reftags.list_tags(source, limit=60)
    except Exception:                    # noqa: BLE001 - same
        return []
    host = listed.get('host') or ''
    upstream_repo = listed.get('repo') or ''
    major = _major(current)

    def rank(tag: str):
        same = bool(major) and _major(tag) == major
        return (0 if same else 1, _descending(tag))

    tags = sorted(listed.get('tags') or [], key=rank)
    return [{'tag': tag, 'in_zot': False, 'kind': 'version',
             'source': f'{host}/{upstream_repo}:{tag}'}
            for tag in tags[:12]]


def _descending(tag: str):
    """A sort key that puts the newest tag first, without reversing the list."""
    key = reftags._version_key(tag)
    return tuple(-part if isinstance(part, int) else _invert(part) for part in key)


def _invert(text: str) -> str:
    return ''.join(chr(0x10FFFF - ord(ch)) for ch in str(text))


def versions(host_key: str, stack: str, service: str) -> dict:
    """The current version of one service, and everything it could move to."""
    _info, run = _runner(host_key)
    rows = [r for r in _compare(read_services(run), False)
            if r['stack'] == stack and r['short'] == service]
    if not rows:
        raise RuntimeError(f'{stack}/{service} is not a service on this cluster')
    row = rows[0]
    sources = mirror_sources()
    zot = _zot_candidates(row['repo'])
    upstream = _upstream_candidates(row['repo'], sources, row['tag'])
    known = {c['tag'] for c in zot}
    upstream = [c for c in upstream if c['tag'] not in known]

    from_zot = (row['repo'] and reg.split_image(row['image'])[0] == _zot_host())
    warnings = []
    if not from_zot:
        warnings.append(f'{row["image"]} does not come from {_zot_host()}: '
                        f'updating it here would mirror it in first')
    if _is_database(row['repo']):
        warnings.append('this is a database: a major version bump cannot read the '
                        'existing data directory, so only tags sharing its major '
                        'version are offered')

    candidates = []
    for row_tag in zot + upstream:
        tag = row_tag['tag']
        blocked = ''
        if _is_database(row['repo']) and _major(tag) and _major(tag) != _major(row['tag']):
            blocked = (f'a database major bump ({_major(row["tag"])} -> {_major(tag)}) needs '
                       f'a dump and restore, not an update')
        candidates.append({**row_tag, 'blocked': blocked, 'current': tag == row['tag']})

    return {
        'host_key': host_key,
        'stack': stack,
        'service': service,
        'current': {
            'image': row['image'],
            'repo': row['repo'],
            'tag': row['tag'],
            'digest': row['digest'],
            'available': row['available'],
            'behind': row['update_available'],
            'replicas': row['replicas'],
            'mode': row['mode'],
            'from_zot': from_zot,
        },
        'target_repo': row['repo'],
        'renamed': not from_zot,
        'sources': {row['repo']: sources.get(row['repo'], '')},
        'candidates': candidates,
        'warnings': warnings,
        'ts': time.time(),
    }


def target_tag(row: dict, wanted: str) -> str:
    """The version a chosen candidate means, refusing something impossible."""
    wanted = (wanted or '').strip()
    if not wanted:
        raise RuntimeError('a version is required')
    if _is_database(row.get('repo', '')) and _major(wanted) != _major(row.get('tag', '')):
        raise RuntimeError(
            f'{row.get("repo")} {wanted} is a major version change from {row.get("tag")} - '
            f'the data directory would not be readable. Do that one by hand '
            f'(dump, bump, restore), not from here.')
    return wanted
