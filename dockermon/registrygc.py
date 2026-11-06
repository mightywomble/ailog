"""Deleting the images nothing runs any more, keeping the last few.

Picking a version means old versions pile up: ``ailog-mcp`` had eight build tags
and ``postgres16`` two digests under one tag, and zot only reclaims blobs for
manifests that are *gone*. Nothing in this estate ever deleted one, so the
registry only ever grew.

The rule is deliberately two-sided, because either half alone is dangerous:

* **what is in use is never deleted** — every image the estate pins in git, every
  image a swarm service is deployed with, and every image a running container on
  any host is using. A tag that is only *pinned* still counts: a rollback is
  deploying an older pin, and deleting it is how a rollback fails at the worst
  possible moment;
* **what is left keeps the newest N tags per repository** (``AILOG_REGISTRY_KEEP``,
  two by default) plus ``latest``.

Deletion is by *manifest*, which is the only unit a registry offers: a manifest
can carry several tags, so a digest is only removed when none of its tags is
kept. zot reclaims the blobs on its own schedule (``gcInterval``, 6h here), so
the answer says what was removed and when the space comes back.
"""

from __future__ import annotations

import base64
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import updates as reg

KEEP_DEFAULT = 2
MANIFEST_ACCEPT = reg.MANIFEST_ACCEPT
_PLACEHOLDER = re.compile(r'\$\{IMAGE_TAG:-([^}]*)\}')
BUILD_TAG = re.compile(r'^build-(\d+)$')

_lock = threading.Lock()


def keep_default() -> int:
    try:
        return max(1, int(os.getenv('AILOG_REGISTRY_KEEP', str(KEEP_DEFAULT))))
    except ValueError:
        return KEEP_DEFAULT


def registry_host() -> str:
    from estate import settings as estatesettings
    return estatesettings.registry()


def _auth_header() -> dict:
    host = registry_host()
    creds = reg._registry_credentials(host)
    if not creds:
        return {}
    token = base64.b64encode(f'{creds[0]}:{creds[1]}'.encode()).decode()
    return {'Authorization': 'Basic ' + token}


def _call(path: str, method: str = 'GET', timeout: int = 20) -> tuple[int, dict, bytes]:
    url = f'https://{registry_host()}{path}'
    headers = {**_auth_header(), 'Accept': MANIFEST_ACCEPT, 'User-Agent': 'ailog-dockermon'}
    request = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), b'' if method == 'DELETE' else resp.read()
    except urllib.error.HTTPError as exc:
        body = b''
        try:
            body = exc.read()
        except Exception:                 # noqa: BLE001 - a body is a bonus, not a need
            body = b''
        return exc.code, dict(exc.headers or {}), body
    except Exception as exc:              # noqa: BLE001 - surfaced to the caller
        raise RuntimeError(f'{registry_host()} unreachable: {exc}')


def catalog(limit: int = 500) -> list[str]:
    status, _headers, body = _call(f'/v2/_catalog?n={limit}')
    if status >= 400:
        raise RuntimeError(f'{registry_host()} answered HTTP {status} for the catalog')
    return [str(r) for r in (json.loads(body or b'{}').get('repositories') or [])]


def tags(repo: str) -> list[str]:
    status, _headers, body = _call(f'/v2/{repo}/tags/list?n=1000')
    if status == 404:
        return []
    if status >= 400:
        raise RuntimeError(f'{registry_host()} answered HTTP {status} for {repo}/tags/list')
    return [str(t) for t in (json.loads(body or b'{}').get('tags') or [])]


def _digest(repo: str, tag: str) -> str:
    info = reg.remote_digest(f'{registry_host()}/{repo}:{tag}')
    if info.get('error'):
        return ''
    return info.get('digest') or ''


# --------------------------------------------------------------------------
# what is in use
# --------------------------------------------------------------------------

def _estate_refs() -> list[str]:
    """Every image the estate's own files name, as ``repo:tag`` strings.

    Read from the checkout when there is one, and from the tree beside the app
    otherwise, so a fresh install still protects what it is about to deploy.
    """
    from estate import settings as estatesettings
    refs: list[str] = []

    def read(relpath: str) -> str:
        try:
            from estate.git import Repo
            repo = Repo()
            if repo.exists():
                return repo.read(relpath, '') or ''
        except Exception:                 # noqa: BLE001 - fall through to the tree
            pass
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(base, estatesettings.root(), relpath)
        try:
            with open(path, 'r') as handle:
                return handle.read()
        except OSError:
            return ''

    refs.extend(_images_in(read('wizard.yaml')))

    for name in _dirs(read, 'stacks') + _dirs(read, 'compose'):
        refs.extend(_images_in(read(f'stacks/{name}/stack.yml')))
        refs.extend(_images_in(read(f'compose/{name}/compose.yml')))
    return refs


def _dirs(read, kind: str) -> list[str]:
    """The stack (or compose) names in the estate, checkout first, tree second."""
    from estate import settings as estatesettings
    candidates = []
    try:
        from estate.git import Repo
        repo = Repo()
        if repo.exists():
            candidates.append(os.path.join(repo.dir, repo.root(), kind))
    except Exception:                     # noqa: BLE001 - the tree is the fallback
        pass
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates.append(os.path.join(base, estatesettings.root(), kind))
    for path in candidates:
        try:
            return sorted(n for n in os.listdir(path)
                          if os.path.isdir(os.path.join(path, n)))
        except OSError:
            continue
    return []


def _images_in(text: str) -> list[str]:
    """Every ``image: repo:tag`` in a file, placeholders resolved to their default."""
    out = []
    for line in (text or '').splitlines():
        match = re.match(r'^\s*"?image"?\s*:\s*(.+?)\s*$', line)
        if not match:
            continue
        value = match.group(1).strip().strip('"\'')
        value = _PLACEHOLDER.sub(lambda m: m.group(1), value)
        value = value.split('@', 1)[0]
        if '/' in value and ':' in value.rsplit('/', 1)[-1]:
            out.append(value)
    return out


def _running_refs() -> list[str]:
    """Image references in use right now, from the cached scan of every host."""
    from . import updates as dupdates
    refs = []
    for state in dupdates.all_state().values():
        for row in (state or {}).get('containers') or []:
            image = str(row.get('image') or '')
            if image:
                refs.append(image)
    return refs


def _swarm_refs() -> list[str]:
    """What the cluster is deployed with, from the last stack scan (digests included).

    ``payload['services']`` is a *count* — "28 services on this cluster" — and
    the deployed images are one level down, in ``stacks[].services[]``. Walking
    the count raised "'int' object is not iterable" for the whole registry
    endpoint, but only when a scan had already run in this process: a fresh
    process had an empty cache and answered fine, which is why it looked like a
    front-end bug from the outside and passed in a shell.
    """
    from . import swarmstack
    refs = []
    with swarmstack._lock:
        caches = list(swarmstack._cache.values())
    for _ts, payload in caches:
        for stack in (payload or {}).get('stacks') or []:
            for row in (stack or {}).get('services') or []:
                image = str(row.get('image') or '')
                if image:
                    refs.append(image)
    return refs


def mirror_refs() -> list[tuple[str, str]]:
    """``(zot repo, tag)`` pairs the mirror list exists to keep copies of.

    A mirror entry is an instruction, not a record of something running:
    ``{"name": "postgres16", "source": "docker.io/library/postgres:16-alpine"}``
    means "zot should hold ``postgres16:16-alpine``". Deleting that copy only
    makes the next mirror run pull it again, so it is not a candidate.
    """
    from estate import settings as estatesettings
    out = []
    try:
        from estate.git import Repo
        repo = Repo()
        text = repo.read('mirror-images.json', '') if repo.exists() else ''
    except Exception:                     # noqa: BLE001 - the tree is the fallback
        text = ''
    if not text:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        try:
            with open(os.path.join(base, estatesettings.root(), 'mirror-images.json')) as fh:
                text = fh.read()
        except OSError:
            return []
    try:
        doc = json.loads(text or '{}')
    except ValueError:
        return []
    for row in doc.get('mirrors') or []:
        name = str(row.get('name') or '').strip()
        source = str(row.get('source') or '').strip().split('@', 1)[0]
        if not name or not source:
            continue
        tail = source.rsplit('/', 1)[-1]
        tag = tail.rsplit(':', 1)[-1] if ':' in tail else 'latest'
        out.append((name, tag))
    return out


def referenced() -> dict:
    """``{'tags': {(repo, tag)}, 'digests': {digest}}`` for everything in use."""
    tags: set[tuple[str, str]] = {pair for pair in mirror_refs()}
    digests: set[str] = set()
    host = registry_host()
    for ref in _estate_refs() + _running_refs() + _swarm_refs():
        text = (ref or '').strip()
        digest = ''
        if '@' in text:
            text, digest = text.split('@', 1)
            digests.add(digest)
        try:
            ref_host, repo, tag = reg.split_image(text)
        except ValueError:
            continue
        if ref_host != host:
            continue                  # an upstream reference is not a zot tag
        tags.add((repo, tag))
    return {'tags': tags, 'digests': digests}


# --------------------------------------------------------------------------
# the plan
# --------------------------------------------------------------------------

def _rank(tag: str):
    """Newest first, and only real versions count as "newest".

    A commit sha is not a version. ``a80d338`` parses as "version 80" and would
    outrank ``v3.25.2``, so keeping "the newest two" would keep two shas and
    delete every release. Channel and sha tags rank below every version and are
    kept only when something actually uses them.
    """
    from estate import tags as reftags
    build = BUILD_TAG.match(tag)
    if build:
        return (3, int(build.group(1)), '')
    if reftags.is_version_tag(tag):
        return (2, reftags.version_of(tag), tag)
    if tag == 'latest':
        return (1, (), tag)
    return (0, (), tag)


def _is_newest(tag: str, tags_list: list[str], keep: int) -> bool:
    ranked = [t for t in sorted(tags_list, key=_rank, reverse=True) if _rank(t)[0] >= 2]
    return tag in ranked[:keep]


def plan(repos: list[str] | None = None, keep: int | None = None) -> dict:
    """What would be deleted, and why everything else is kept."""
    keep = keep if keep is not None else keep_default()
    in_use = referenced()
    wanted = repos or catalog()
    rows = []
    total = 0
    for repo in wanted:
        try:
            names = tags(repo)
        except RuntimeError as exc:
            rows.append({'repo': repo, 'error': str(exc), 'tags': [], 'delete': []})
            continue
        if not names:
            continue
        by_digest: dict[str, list[str]] = {}
        described = []
        for tag in names:
            digest = _digest(repo, tag)
            by_digest.setdefault(digest or f'?{tag}', []).append(tag)
            why = ''
            if (repo, tag) in in_use['tags']:
                why = 'in use'
            elif digest and digest in in_use['digests']:
                why = 'running somewhere'
            elif tag == 'latest':
                why = 'latest'
            elif _is_newest(tag, names, keep):
                why = f'newest {min(keep, len(names))}'
            described.append({'tag': tag, 'digest': digest, 'keep': bool(why), 'why': why})
        delete = []
        for digest, digest_tags in by_digest.items():
            if not digest.startswith('sha256:'):
                continue
            if any(row['keep'] for row in described if row['tag'] in digest_tags):
                continue
            delete.extend(digest_tags)
        if delete:
            total += len(delete)
        rows.append({
            'repo': repo,
            'tags': described,
            'delete': delete,
            'keep': keep,
        })
    return {
        'host': registry_host(),
        'keep': keep,
        'repos': [r for r in rows if r.get('delete')],
        'checked': len(rows),
        'deletable': total,
        'referenced_tags': len(in_use['tags']),
        'ts': time.time(),
    }


def prune(repos: list[str] | None = None, keep: int | None = None,
          dry_run: bool = False) -> dict:
    """Delete the manifests the plan named. Never touches anything in use."""
    planned = plan(repos=repos, keep=keep)
    deleted = []
    failed = []
    for row in planned['repos']:
        repo = row['repo']
        wanted = set(row['delete'])
        seen = set()
        for tag in row['tags']:
            if tag['tag'] not in wanted or not tag['digest'] or tag['digest'] in seen:
                continue
            seen.add(tag['digest'])
            if dry_run:
                deleted.append({'repo': repo, 'tag': tag['tag'], 'digest': tag['digest'],
                                'dry_run': True})
                continue
            status, _headers, body = _call(f'/v2/{repo}/manifests/{tag["digest"]}',
                                           method='DELETE')
            if status in (200, 202):
                deleted.append({'repo': repo, 'tag': tag['tag'], 'digest': tag['digest']})
            else:
                failed.append({'repo': repo, 'tag': tag['tag'], 'status': status,
                               'detail': (body or b'')[:120].decode('utf-8', 'replace')})
    return {
        'host': planned['host'],
        'keep': planned['keep'],
        'deleted': deleted,
        'failed': failed,
        'dry_run': dry_run,
        'note': ('zot reclaims the blobs on its next garbage collection '
                 '(gcInterval in /opt/apps/zot/config.json)'),
    }


def describe(keep: int | None = None) -> dict:
    """Every repository with its tags and what keeps each one alive."""
    planned = plan(keep=keep)
    by_repo = {row['repo']: row for row in planned['repos']}
    out = []
    for repo in catalog():
        row = by_repo.get(repo)
        if row:
            out.append({**row, 'deletable': len(row['delete'])})
            continue
        try:
            names = tags(repo)
        except RuntimeError:
            names = []
        out.append({'repo': repo, 'tags': [{'tag': t, 'keep': True, 'why': 'in use'}
                                           for t in names],
                    'delete': [], 'deletable': 0})
    return {'host': planned['host'], 'keep': planned['keep'], 'repos': out,
            'deletable': planned['deletable'], 'ts': time.time()}
