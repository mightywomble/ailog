"""Which tag is actually newer - asked of the registry that serves the image.

``dockermon.updates`` answers a different question: "has the tag I am running
moved?" (local manifest digest vs the registry's).  This answers "what should I
move to?", which needs the tag list and a ranking that does not fall for
`1.10 < 1.9`, for `alpine` flavour churn, or for `pr-5576`.

Ported from the wizard's ``registry.py``; the HTTP client is ``requests``
because this app already ships it, and the zot credentials come from the same
secret the update checker uses.
"""

from __future__ import annotations

import base64
import re
import threading
import time

import requests

from dockermon import updates as drunter          # registry credentials + digest logic

DOCKER_HOSTS = {'docker.io', 'index.docker.io', 'registry-1.docker.io'}
_TTL = 1800.0          # tags move on the order of days; Hub rate-limits per IP
_cache: dict[tuple, tuple] = {}
_lock = threading.Lock()

# Channels and CI artefacts are not versions. "update me" must never pick
# pr-5576-alpine, main, or a nightly.
_CHANNEL = {'latest', 'main', 'master', 'edge', 'nightly', 'dev', 'develop',
            'test', 'unstable', 'beta', 'alpha', 'rc', 'snapshot'}
_NOISE = re.compile(r'(^pr-|^sha256-|^ci-|^build-|^dind|test|nightly|SNAPSHOT)', re.I)


class TagError(RuntimeError):
    pass


def split(image: str) -> tuple[str, str, str]:
    """'docker.io/amir20/dozzle:latest' -> ('docker.io', 'amir20/dozzle', 'latest').

    A bare 'user/repo' is Docker Hub, not a hostname with a namespace - getting
    that wrong is why an older parser asked docker.io about a repo called
    'amir20'.
    """
    ref = re.sub(r'^https?://', '', (image or '').strip())
    tag = ''
    if '@' in ref:
        ref, tag = ref.split('@', 1)
    elif ':' in ref.split('/')[-1]:
        ref, _, tag = ref.rpartition(':')
    parts = ref.split('/')
    if len(parts) > 1 and ('.' in parts[0] or ':' in parts[0] or parts[0] == 'localhost'):
        host, repo = parts[0].lower(), '/'.join(parts[1:])
    else:
        host, repo = 'docker.io', '/'.join(parts)
    if host in DOCKER_HOSTS and '/' not in repo:
        repo = 'library/' + repo
    return host, repo, tag


def _bearer(repo: str, realm: str, service: str, timeout: int = 20) -> str:
    """An anonymous pull token, asked for the way each registry asks for it."""
    try:
        return drunter._bearer_token({'scheme': 'bearer', 'realm': realm, 'service': service,
                                      'scope': f'repository:{repo}:pull'}, repo, timeout) or ''
    except Exception:
        return ''


def _hub_tags(repo: str, limit: int, timeout: int) -> list[str]:
    """Docker Hub has a tag API sorted by last_updated; /v2/tags/list is
    lexicographic, so 'nginx' would come back at 1.11.x.

    One page is not enough: `wordpress:7.1.4` was pushed before the 7.1.4
    packaging variants that fill the next 100 rows by last_updated, so the plain
    tag - the one this estate actually runs - was invisible and the newest
    flavour won by default.  Walk a few pages instead.
    """
    want = max(limit, 300)
    tags: list[str] = []
    for page in range(1, 5):
        r = requests.get(f'https://hub.docker.com/v2/repositories/{repo}/tags',
                         params={'page_size': 100, 'page': page, 'ordering': 'last_updated'},
                         timeout=timeout)
        if r.status_code == 404:
            raise TagError(f'{repo} is not in docker.io')
        r.raise_for_status()
        results = (r.json() or {}).get('results') or []
        tags += [t['name'] for t in results
                 if t.get('name') and not t['name'].startswith('sha256-')]
        if len(results) < 100 or len(tags) >= want:
            break
    return tags[:want]


def list_tags(image: str, limit: int = 80, timeout: int = 25) -> dict:
    host, repo, wanted = split(image)
    key = (host, repo, limit)
    now = time.time()
    with _lock:
        hit = _cache.get(key)
    if hit and (now - hit[0]) < _TTL:
        return dict(hit[1])

    if host in DOCKER_HOSTS:
        try:
            tags = _hub_tags(repo, limit, timeout)
            out = {'host': 'docker.io', 'repo': repo, 'current': wanted,
                   'count': len(tags), 'tags': tags, 'source': 'hub.docker.com'}
            with _lock:
                _cache[key] = (now, dict(out))
            return out
        except TagError:
            raise
        except Exception:
            pass                        # Hub API down or rate limited: use /v2

    api_host = 'registry-1.docker.io' if host in DOCKER_HOSTS else host
    base = api_host if api_host.startswith('http') else 'https://' + api_host
    headers: dict[str, str] = {}
    if host in DOCKER_HOSTS:
        headers['Authorization'] = 'Bearer ' + _bearer(repo, 'https://auth.docker.io/token',
                                                        'registry.docker.io', timeout)
    elif host == 'ghcr.io':
        headers['Authorization'] = 'Bearer ' + _bearer(repo, 'https://ghcr.io/token', 'ghcr.io', timeout)

    # registries answer lexicographically, so asking for `limit` returns the
    # alphabetically first tags rather than the newest
    page = max(limit, 500)
    r = requests.get(f'{base}/v2/{repo}/tags/list', params={'n': page},
                     headers=headers, timeout=timeout)

    if r.status_code == 401:
        challenge = drunter._challenge(r.headers)
        if challenge.get('scheme') == 'bearer':
            token = drunter._bearer_token(challenge, repo, timeout)
            if token:
                headers['Authorization'] = 'Bearer ' + token
                r = requests.get(f'{base}/v2/{repo}/tags/list', params={'n': page},
                                 headers=headers, timeout=timeout)

    if r.status_code in (401, 403):
        creds = drunter._registry_credentials(host)
        if creds:
            basic = base64.b64encode(f'{creds[0]}:{creds[1]}'.encode()).decode()
            r = requests.get(f'{base}/v2/{repo}/tags/list', params={'n': page},
                             headers={'Authorization': 'Basic ' + basic}, timeout=timeout)

    if r.status_code == 404:
        raise TagError(f'{repo} is not in {host}')
    if r.status_code in (401, 403):
        raise TagError(f'{repo} is private, or does not exist in {host} '
                       f'(HTTP {r.status_code} - check the registry credentials)')
    if r.status_code >= 400:
        raise TagError(f'{host} answered HTTP {r.status_code} for {repo}/tags/list')

    tags = [t for t in (r.json() or {}).get('tags') or [] if not t.startswith('sha256-')]
    tags = sorted(tags, key=lambda t: [_num(p) for p in re.split(r'([0-9]+)', t)],
                  reverse=True)[:limit]
    out = {'host': host, 'repo': repo, 'current': wanted, 'count': len(tags), 'tags': tags}
    with _lock:
        _cache[key] = (now, dict(out))
        if len(_cache) > 512:
            for stale in [k for k, v in _cache.items() if now - v[0] > _TTL]:
                _cache.pop(stale, None)
    return out


def _num(part: str):
    return (1, int(part), '') if part.isdigit() else (0, 0, part)


def is_version_tag(tag: str) -> bool:
    t = (tag or '').strip()
    if not t or t.lower() in _CHANNEL or _NOISE.search(t):
        return False
    # a commit sha is not a version: registries carry 7-40 char hex tags, and
    # "update to a80d338" is how a mirror of a moving tag goes wrong
    if re.fullmatch(r'[0-9a-f]{7,40}', t) and re.search(r'[a-f]', t):
        return False
    if re.search(r'(rc|beta|alpha|pre|nightly)', t, re.I):
        return False        # a stable service should not be offered an rc
    # A version starts the tag.  Without this, wordpress' `php8.5-fpm` reads as
    # 8.5 and outranks `7.1.4-php8.5-fpm-alpine` - a variant, not a version.
    if not re.match(r'^v?\d', t):
        return False
    return bool(re.search(r'\d', t))


def _version_key(tag: str):
    """Sort key that puts 1.10 above 1.9 instead of below it."""
    out = []
    for part in re.split(r'(\d+)', tag.lower()):
        if part:
            out.append((1, int(part), '') if part.isdigit() else (0, 0, part))
    return out


def _ver(tag: str) -> tuple:
    """The leading version as comparable numbers: '7.1.4-php8.5-fpm' -> (7, 1, 4).

    Everything after it is packaging, and packaging numbers must not count as
    version numbers - '7.1.4-php8.5-fpm' is not newer than '7.1.4'.
    """
    m = re.match(r'^[^\d]*(\d+(?:[._]\d+)*)', tag or '')
    if not m:
        return ()
    return tuple(int(n) for n in re.split(r'[._]', m.group(1)))


def version_of(tag: str) -> tuple:
    """The leading version of a tag as comparable numbers; ``()`` if it has none.

    Public form of :func:`_ver`, for the callers that need to ask "is what is
    running older than what is published?" rather than "what is the newest tag?".
    """
    return _ver(tag)


def _major(tag: str) -> str:
    m = re.search(r'\d+', tag or '')
    return m.group(0) if m else ''


def _variant(tag: str) -> str:
    """What follows the leading version: 'v11.4.0-alpine' -> '-alpine'.

    Prefer the packaging the service already runs: someone on '11.4.0' wants
    '11.5.0', not '11.5.0-alpine'.

    The wizard's version of this regex was lazy, so '11.4.0-alpine' produced
    '.4.0-alpine' and never matched anything - the tie-break silently did
    nothing.  Matching the version once, greedily, and keeping what is left is
    both simpler and correct.
    """
    m = re.match(r'^[^\d]*\d+(?:[._]\d+)*(.*)$', tag or '')
    return (m.group(1) if m else '').lower()


def newest_tag(image: str, limit: int = 100) -> dict:
    """The version to move an existing service to.

    Registries hand tags back in their own order (Hub by last_updated, everyone
    else alphabetically), so neither order answers "what is newest".  Channel and
    CI tags are dropped, then version-shaped ones are compared numerically, and
    the major version is held: "update postgres" must not silently jump 16 -> 18.
    """
    listed = list_tags(image, limit=limit)
    current = listed.get('current') or ''
    tagged = [t for t in listed['tags'] if is_version_tag(t)]
    if not tagged:
        raise TagError(f'no version-like tags for {listed["repo"]} in {listed["host"]} '
                       f'({len(listed["tags"])} tags seen: {", ".join(listed["tags"][:5])})')

    major = _major(current)
    majors = [t for t in tagged if _major(t) == major]
    pool = majors if (current and is_version_tag(current) and majors) else tagged

    def rank(t):
        # highest version wins; on a tie prefer the packaging already in use,
        # then the plainest tag ("1.31.8" over "1.31.8-trixie-perl").  Only the
        # leading version counts: "1.31.8-alpine3.24" is 1.31.8.
        return (_ver(t), 1 if _variant(t) == _variant(current) else 0, -len(t))

    pool.sort(key=rank, reverse=True)
    best = pool[0]
    up_to_date = bool(current) and is_version_tag(current) and _ver(current) >= _ver(best)
    return {'tag': current if up_to_date else best,
            'best': best, 'current': current, 'up_to_date': up_to_date,
            'host': listed['host'], 'repo': listed['repo'],
            'candidates': pool[:10]}
