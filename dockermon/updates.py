"""Is there a newer image than the one this container is running?

A container update is not "the tag looks old" - it is "the registry's current
manifest for the tag I am running differs from the manifest digest stored on
the host".  That test works for pinned tags too: ``postgres:16`` stays
``16`` while upstream republishes the image, and ``latest`` moves daily.

Nothing here needs the Docker Engine API on the host: the local digests come
from one ``docker image inspect`` over SSH and the remote digest from the
registry's own ``/v2`` API.  Registry calls are cached because Docker Hub rate
limits anonymous pulls per IP and the sidebar asks about every host.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import sshstats

DOCKER_HOSTS = {
    'docker.io', 'index.docker.io', 'registry-1.docker.io', 'hub.docker.com',
    'registry.hub.docker.com',
}

# How long one (repo, tag) answer is trusted. Upstream images move on the order
# of days, and the sidebar polls every 20s - asking the registry each time
# would get us rate limited within an hour.
DIGEST_TTL = 30 * 60

# How long a whole host scan is trusted before the sidebar asks for another.
SCAN_TTL = 30 * 60

MANIFEST_ACCEPT = ', '.join((
    'application/vnd.oci.image.index.v1+json',
    'application/vnd.docker.distribution.manifest.list.v2+json',
    'application/vnd.oci.image.manifest.v1+json',
    'application/vnd.docker.distribution.manifest.v2+json',
))

_digest_cache: dict[tuple[str, str, str], tuple[float, dict]] = {}
_cache_lock = threading.Lock()

_state: dict[str, dict] = {}
_state_lock = threading.Lock()
_inflight: set[str] = set()


# --------------------------------------------------------------------------
# image references
# --------------------------------------------------------------------------

def split_image(ref: str) -> tuple[str, str, str]:
    """``zot.safehomelan.com/app:1.2`` -> ``(host, repo, tag)``.

    A bare ``user/repo`` is Docker Hub, not a hostname with a namespace -
    treating ``amir20/dozzle`` as a registry called ``amir20`` is the classic
    way to end up asking the wrong server about a repo called ``dozzle``.
    """
    text = (ref or '').strip()
    if '@' in text:                      # strip a pinned digest: the tag is what we compare
        text = text.split('@', 1)[0]
    if not text:
        raise ValueError('empty image reference')

    head, _, last = text.rpartition('/')
    if ':' in last:
        repo_part, _, tag = last.partition(':')
        text = (head + '/' + repo_part) if head else repo_part
    else:
        tag = 'latest'

    first, sep, rest = text.partition('/')
    if sep and ('.' in first or ':' in first or first == 'localhost'):
        host, repo = first, rest
    else:
        host, repo = 'docker.io', text

    if host in DOCKER_HOSTS and '/' not in repo:
        repo = 'library/' + repo         # nginx -> library/nginx
    return host, repo, tag or 'latest'


def _parse_digest(value: str) -> str:
    text = (value or '').strip()
    if text.startswith('sha256:') and len(text) == 71:
        return text
    return ''


# --------------------------------------------------------------------------
# registry HTTP
# --------------------------------------------------------------------------

def _http(url: str, headers: dict | None = None, timeout: int = 12, method: str = 'GET'):
    request = urllib.request.Request(url, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            body = resp.read() if method != 'HEAD' else b''
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as exc:
        body = b''
        try:
            body = exc.read()
        except Exception:
            pass
        return exc.code, dict(exc.headers or {}), body


def _challenge(headers: dict) -> dict:
    """Parse a WWW-Authenticate header into {'scheme': 'bearer', ...}."""
    raw = ''
    for key, value in headers.items():
        if key.lower() == 'www-authenticate':
            raw = value
            break
    if not raw:
        return {}
    scheme, _, rest = raw.partition(' ')
    out = {'scheme': scheme.strip().lower()}
    for match in re.finditer(r'(\w+)="([^"]*)"', rest):
        out[match.group(1).lower()] = match.group(2)
    return out


def _secret(name: str) -> str:
    """An env value, an env ``*_FILE`` pointer, or a mounted Docker secret.

    The estate keeps credentials in swarm secrets (``/run/secrets/<name>``), so
    reading only the environment would mean the one registry that hosts most of
    our images can never be checked.
    """
    value = os.environ.get(name)
    if value:
        return value
    candidates = [os.environ.get(name + '_FILE')]
    candidates.append(os.path.join('/run/secrets', name.lower()))
    candidates.append(os.path.join('/run/secrets', name.lower().replace('ailog_registry_', '')))
    for path in candidates:
        if not path:
            continue
        try:
            with open(path, 'r') as handle:
                text = handle.read().strip()
            if text:
                return text
        except OSError:
            continue
    return ''


def _registry_credentials(host: str) -> tuple[str, str] | None:
    """Basic credentials for a private registry.

    zot answers ``Basic realm="zot"``: without credentials every query looks
    like "image does not exist" (HTTP 401), and most of this estate's images
    live in zot.
    """
    user = (_secret('AILOG_REGISTRY_USER') or _secret('ZOT_USER'))
    pwd = (_secret('AILOG_REGISTRY_PASSWORD') or _secret('ZOT_PASSWORD'))
    if user and pwd:
        return user, pwd
    return None


def _bearer_token(challenge: dict, repo: str, timeout: int) -> str:
    realm = challenge.get('realm') or ''
    if not realm:
        return ''
    if not realm.startswith('http'):
        realm = 'https://' + realm.lstrip('/')
    query = {'scope': challenge.get('scope') or f'repository:{repo}:pull'}
    if challenge.get('service'):
        query['service'] = challenge['service']
    url = realm + ('&' if '?' in realm else '?') + urllib.parse.urlencode(query)
    status, _, body = _http(url, timeout=timeout)
    if status >= 400:
        raise RuntimeError(f'token endpoint {realm} returned {status}')
    try:
        payload = json.loads(body or b'{}')
    except ValueError:
        raise RuntimeError(f'token endpoint {realm} did not return JSON')
    # Docker Hub answers {"token": ...}, ghcr.io answers {"access_token": ...}
    return payload.get('token') or payload.get('access_token') or ''


def remote_digest(image: str, timeout: int = 12, refresh: bool = False) -> dict:
    """Manifest digest the registry currently serves for ``image``'s tag."""
    host, repo, tag = split_image(image)
    key = (host, repo, tag)
    now = time.time()

    with _cache_lock:
        hit = _digest_cache.get(key)
    if hit and not refresh and (now - hit[0]) < DIGEST_TTL:
        return dict(hit[1])

    result = {'image': image, 'host': host, 'repo': repo, 'tag': tag,
              'digest': '', 'error': None, 'ts': now}

    api_host = 'registry-1.docker.io' if host in DOCKER_HOSTS else host
    base = api_host if api_host.startswith('http') else 'https://' + api_host
    path = f'{base}/v2/{repo}/manifests/{urllib.parse.quote(tag, safe="")}'

    try:
        headers = {'Accept': MANIFEST_ACCEPT, 'User-Agent': 'ailog-dockermon'}
        creds = _registry_credentials(host)
        if creds:
            token = base64.b64encode(f'{creds[0]}:{creds[1]}'.encode()).decode()
            headers['Authorization'] = f'Basic {token}'

        status, resp_headers, body = _http(path, headers, timeout=timeout, method='HEAD')
        if status in (401, 403):
            challenge = _challenge(resp_headers)
            if challenge.get('scheme') == 'bearer':
                token = _bearer_token(challenge, repo, timeout)
                if token:
                    headers['Authorization'] = f'Bearer {token}'
                    status, resp_headers, body = _http(path, headers, timeout=timeout, method='HEAD')
        if status == 405:                      # registry rejects HEAD: ask with GET
            status, resp_headers, body = _http(path, headers, timeout=timeout)
        if status >= 400:
            detail = ''
            try:
                detail = (json.loads(body or b'{}').get('errors') or [{}])[0].get('message') or ''
            except Exception:
                detail = (body or b'')[:120].decode('utf-8', 'replace')
            raise RuntimeError(f'{host} answered HTTP {status}'
                               + (f': {detail}' if detail else ''))

        digest = ''
        for key_name, value in resp_headers.items():
            if key_name.lower() == 'docker-content-digest':
                digest = _parse_digest(value)
                break
        if not digest and body:
            # A registry that omits the header still gives us the bytes.
            digest = 'sha256:' + hashlib.sha256(body).hexdigest()
        if not digest:
            raise RuntimeError(f'{host} returned no manifest digest for {repo}:{tag}')
        result['digest'] = digest
    except Exception as exc:                   # noqa: BLE001 - surfaced to the UI
        result['error'] = str(exc) or exc.__class__.__name__

    with _cache_lock:
        _digest_cache[key] = (now, dict(result))
        if len(_digest_cache) > 2048:
            for stale in [k for k, v in _digest_cache.items() if now - v[0] > DIGEST_TTL]:
                _digest_cache.pop(stale, None)
    return result


# --------------------------------------------------------------------------
# per-host comparison
# --------------------------------------------------------------------------

def _local_digests(run, images) -> dict:
    """``{image_ref: 'sha256:…'}`` for the images present on the host."""
    try:
        return sshstats.image_digests_using(run, images)
    except Exception:
        return {}


def updates_for(host_key: str, containers, run, refresh: bool = False) -> dict:
    """Compare each running container's image against the registry.

    ``run(command) -> (ok, output)`` is the SSH transport, injected so this is
    testable without a host.  ``containers`` is the list from
    :func:`sshstats.snapshot` (or the SDK collector).
    """
    rows = [c for c in (containers or []) if c.get('image')]
    images = sorted({str(c['image']) for c in rows if c.get('image')})
    local = _local_digests(run, images)

    remote: dict[str, dict] = {}
    for image in images:
        remote[image] = remote_digest(image, refresh=refresh)

    attention, unknown = [], []
    seen_containers = []
    for container in rows:
        image = str(container['image'])
        info = remote.get(image) or {}
        local_digest = _parse_digest(local.get(image)) or ''
        remote_digest_value = _parse_digest(info.get('digest')) or ''

        entry = {
            'name': container.get('name'),
            'id': container.get('short_id') or (container.get('id') or '')[:12],
            'image': image,
            'image_name': container.get('image_name'),
            'tag': container.get('image_tag'),
            'stack': container.get('stack'),
            'service': container.get('service'),
            'state': container.get('state'),
            'status': container.get('status'),
            'cpu_percent': container.get('cpu_percent'),
            'mem_used': container.get('mem_used'),
            'local_digest': local_digest[7:19] if local_digest else None,
            'remote_digest': remote_digest_value[7:19] if remote_digest_value else None,
            'update_available': False,
            'reasons': [],
            'error': info.get('error'),
        }

        state = (container.get('state') or '').lower()
        status_text = (container.get('status') or '').lower()
        if state and state != 'running':
            entry['reasons'].append(f'not running ({state})')
        elif 'unhealthy' in status_text:
            entry['reasons'].append('unhealthy')

        if info.get('error'):
            unknown.append(entry)
        elif local_digest and remote_digest_value:
            if local_digest != remote_digest_value:
                entry['update_available'] = True
                entry['reasons'].insert(0, 'newer image upstream')
        elif remote_digest_value and not local_digest:
            # No local RepoDigest (image removed, or tagged by ID): we cannot
            # tell whether this is new, so say so rather than guess.
            entry['error'] = 'local image digest unavailable'

        if entry['reasons']:
            attention.append(entry)
        seen_containers.append(entry)

    # One row per distinct image is what "container updates" reads best as: a
    # stack with 3 replicas is one update, not three.
    by_image: dict[str, dict] = {}
    for entry in seen_containers:
        key = entry['image']
        if key not in by_image:
            by_image[key] = dict(entry, containers=1)
        else:
            by_image[key]['containers'] += 1
            if entry['update_available']:
                by_image[key]['update_available'] = True
            for reason in entry['reasons']:
                if reason not in by_image[key]['reasons']:
                    by_image[key]['reasons'].append(reason)

    # "attention" is split out because the badge has two very different
    # meanings: a pending update (do it when convenient) and something broken
    # (look now). Only the second should turn the square red on its own.
    attention_only = [e for e in attention
                      if any(r != 'newer image upstream' for r in e['reasons'])]

    rows_out = sorted(by_image.values(),
                      key=lambda r: (not r['update_available'], r['name'] or ''))
    return {
        'host_key': host_key,
        'containers_checked': len(seen_containers),
        'images_checked': len(images),
        'updates': [r for r in rows_out if r['update_available']],
        'attention': attention,
        'attention_only': attention_only,
        'unknown': unknown,
        'containers': rows_out,
        'ts': time.time(),
    }


# --------------------------------------------------------------------------
# background scanning (what the sidebar badges read)
# --------------------------------------------------------------------------

def state(host_key: str) -> dict | None:
    with _state_lock:
        row = _state.get(host_key)
        return dict(row) if row else None


def all_state() -> dict[str, dict]:
    with _state_lock:
        return {k: dict(v) for k, v in _state.items()}


def stale(host_key: str, max_age: float = SCAN_TTL) -> bool:
    row = state(host_key)
    return not row or (time.time() - float(row.get('ts') or 0)) > max_age


def _store(host_key: str, result: dict) -> None:
    with _state_lock:
        _state[host_key] = result


def scan_host(app, host_key: str) -> dict:
    """Scan one host in the background. Returns the stored result."""
    with _state_lock:
        if host_key in _inflight:
            return state(host_key) or {'host_key': host_key, 'pending': True}
        _inflight.add(host_key)
    started = time.time()
    try:
        # Late import: routes imports this module, so importing it back at
        # module scope would be a cycle.
        from . import routes as droutes
        with app.app_context():
            info, _transport, _client = droutes._transport_for(host_key)
            snap = droutes.host_snapshot(host_key)
            containers = snap.get('containers') or []
            result = updates_for(host_key, containers,
                                 runner_for(info), refresh=False)
        result['ts'] = time.time()
        result['took'] = round(result['ts'] - started, 1)
        _store(host_key, result)
        return result
    except Exception as exc:                   # noqa: BLE001 - a scan must never take the app down
        result = {'host_key': host_key, 'error': str(exc), 'ts': time.time(),
                  'updates': [], 'attention': [], 'containers': [],
                  'containers_checked': 0, 'images_checked': 0,
                  'took': round(time.time() - started, 1)}
        _store(host_key, result)
        return result
    finally:
        with _state_lock:
            _inflight.discard(host_key)


def runner_for(info: dict):
    """SSH runner for one resolved host (matches ``sshstats.run``)."""
    user = info.get('user') or 'root'
    ip = info.get('ip') or '127.0.0.1'
    key_id = info.get('ssh_key_id')

    def run(command: str, timeout: int = 20):
        return sshstats.run(user, ip, key_id, command, timeout=timeout)

    return run


def scan_async(app, host_keys) -> list[str]:
    """Kick a scan for each stale host; returns the keys that were started."""
    started = []
    for host_key in host_keys or []:
        if host_key in started or not stale(host_key):
            continue
        thread = threading.Thread(target=scan_host, args=(app, host_key),
                                  name=f'docker-scan-{host_key}', daemon=True)
        thread.start()
        started.append(host_key)
    return started


def clear(host_key: str | None = None) -> None:
    with _state_lock:
        if host_key:
            _state.pop(host_key, None)
        else:
            _state.clear()
    with _cache_lock:
        if host_key:
            for key in [k for k in _digest_cache if host_key in k]:
                _digest_cache.pop(key, None)
        else:
            _digest_cache.clear()
