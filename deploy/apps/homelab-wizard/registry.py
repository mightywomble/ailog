"""registry: list the tags an image actually has.

Why this lives on the server: the browser used to call auth.docker.io and
registry-1.docker.io directly, and Docker Hub sends no CORS headers, so the
button could only ever fail with "NetworkError when attempting to fetch
resource." The wizard container has working egress, so the fetch happens here.

Handles the registry APIs that matter to this estate:
  * docker.io (token from auth.docker.io)
  * ghcr.io (token from ghcr.io/token)
  * quay.io, lscr.io, registry.k8s.io ... (plain /v2/tags/list, or a token
    obtained from the WWW-Authenticate challenge)
  * zot.safehomelan.com (needs the estate's credentials)
"""
import base64
import re

import httpx

import core

DOCKER_HOSTS = {"docker.io", "index.docker.io", "registry-1.docker.io"}
_OFFICIAL = re.compile(r"^(?:docker\.io/|index\.docker\.io/)?[a-z0-9_.-]+$")


def split(image):
    """'docker.io/amir20/dozzle:latest' -> ('docker.io', 'amir20/dozzle', 'latest')

    A bare 'user/repo' is Docker Hub, not a hostname with a namespace - getting
    that wrong is why the old parser asked docker.io about a repo called 'amir20'.
    """
    ref = (image or "").strip()
    ref = re.sub(r"^https?://", "", ref)
    tag = ""
    if "@" in ref:
        ref, tag = ref.split("@", 1)
    elif ":" in ref.split("/")[-1]:
        ref, _, tag = ref.rpartition(":")
    parts = ref.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        host, repo = parts[0].lower(), "/".join(parts[1:])
    else:
        host, repo = "docker.io", "/".join(parts)
    if host in DOCKER_HOSTS and "/" not in repo:
        repo = "library/" + repo          # nginx -> library/nginx
    return host, repo, tag


def _docker_token(repo, timeout=20):
    r = httpx.get("https://auth.docker.io/token",
                  params={"service": "registry.docker.io",
                          "scope": f"repository:{repo}:pull"}, timeout=timeout)
    r.raise_for_status()
    return r.json().get("token")


def _ghcr_token(repo, timeout=20):
    r = httpx.get("https://ghcr.io/token",
                  params={"service": "ghcr.io", "scope": f"repository:{repo}:pull"},
                  timeout=timeout)
    r.raise_for_status()
    return r.json().get("token")


def _challenge_token(resp, timeout=20):
    """Fall back to whatever the registry's 401 challenge asks for."""
    head = resp.headers.get("www-authenticate", "")
    # zot answers Basic realm="zot" - treating "zot" as a realm URL is how you
    # get "TLSV1_UNRECOGNIZED_NAME: tlsv1 unrecognized name"
    if "realm=" not in head or "bearer" not in head.lower():
        return None
    realm = re.search(r'realm="([^"]+)"', head)
    service = re.search(r'service="([^"]+)"', head)
    scope = re.search(r'scope="([^"]+)"', head)
    if not realm:
        return None
    params = {}
    if service:
        params["service"] = service.group(1)
    if scope:
        params["scope"] = scope.group(1)
    target = realm.group(1)
    if not target.startswith("http"):
        target = "https://" + target.lstrip("/")   # zot answers with a bare path
    r = httpx.get(target, params=params, timeout=timeout)
    if r.status_code >= 400:
        return None
    body = r.json()
    return body.get("token") or body.get("access_token")


def _hub_tags(repo, limit, timeout):
    """Docker Hub has a proper tag API sorted by last_updated; the registry's
    /v2/tags/list is lexicographic, so 'nginx' would come back at 1.11.x."""
    r = httpx.get(f"https://hub.docker.com/v2/repositories/{repo}/tags",
                  params={"page_size": min(limit, 100), "ordering": "last_updated"},
                  timeout=timeout)
    if r.status_code == 404:
        raise RuntimeError(f"{repo} is not in docker.io")
    r.raise_for_status()
    return [t["name"] for t in (r.json() or {}).get("results", [])
            if t.get("name") and not t["name"].startswith("sha256-")]


def list_tags(image, limit=80, timeout=25):
    host, repo, wanted = split(image)
    settings = core.load()
    host_part = "registry-1.docker.io" if host in DOCKER_HOSTS else host
    base = host_part if host_part.startswith("http") else "https://" + host_part
    headers = {}

    if host in DOCKER_HOSTS:
        headers["Authorization"] = "Bearer " + (_docker_token(repo, timeout) or "")
    elif host == "ghcr.io":
        headers["Authorization"] = "Bearer " + (_ghcr_token(repo, timeout) or "")

    if host in DOCKER_HOSTS:
        try:
            tags = _hub_tags(repo, limit, timeout)
            return {"host": "docker.io", "repo": repo, "current": wanted,
                    "count": len(tags), "tags": tags, "source": "hub.docker.com"}
        except RuntimeError:
            raise
        except Exception:
            pass        # Hub API down or rate limited: use the registry instead

    url = f"{base}/v2/{repo}/tags/list"
    # registries answer lexicographically, so asking for `limit` would return the
    # alphabetically first tags (nginx "1.11.13") rather than the newest
    page = max(limit, 500)
    r = httpx.get(url, params={"n": page}, headers=headers, timeout=timeout)

    if r.status_code == 401:
        # anonymous token from the challenge, e.g. quay.io / registry.k8s.io
        fresh = _challenge_token(r, timeout)
        if fresh:
            headers["Authorization"] = "Bearer " + fresh
            r = httpx.get(url, params={"n": page}, headers=headers, timeout=timeout)

    if r.status_code in (401, 403) and (host.endswith("safehomelan.com")
                                        or "basic" in r.headers.get("www-authenticate", "").lower()):
        # our own zot wants the estate credentials; they are in the settings
        user, pwd = settings.get("zot_user"), settings.get("zot_password")
        if user and pwd:
            basic = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            r = httpx.get(url, params={"n": page},
                          headers={"Authorization": "Basic " + basic}, timeout=timeout)

    if r.status_code == 404:
        raise RuntimeError(f"{repo} is not in {host}")
    if r.status_code in (401, 403):
        raise RuntimeError(f"{repo} is private, or does not exist in {host} "
                           f"(HTTP {r.status_code} - check the credentials for that registry)")
    if r.status_code >= 400:
        raise RuntimeError(f"{host} answered HTTP {r.status_code} for {repo}/tags/list")

    tags = [t for t in (r.json() or {}).get("tags") or [] if not t.startswith("sha256-")]
    tags = sorted(tags, key=lambda t: [_num(p) for p in re.split(r"([0-9]+)", t)],
                  reverse=True)[:limit]
    return {"host": host, "repo": repo, "current": wanted, "count": len(tags), "tags": tags}


def _num(part):
    if part.isdigit():
        return (1, int(part), "")
    return (0, 0, part)


# Tags that are channels or CI artefacts rather than versions. "update me to the
# latest version" must never pick pr-5576-alpine or main.
_CHANNEL = {"latest", "main", "master", "edge", "nightly", "dev", "develop",
            "test", "unstable", "beta", "alpha", "rc", "snapshot"}
_NOISE = re.compile(r"(^pr-|^sha256-|^ci-|^build-|^dind|test|nightly|SNAPSHOT)", re.I)


def is_version_tag(tag):
    t = (tag or "").strip()
    if not t or t.lower() in _CHANNEL or _NOISE.search(t):
        return False
    if re.search(r"(rc|beta|alpha|pre|nightly)", t, re.I):
        return False          # a stable service should not be offered an rc
    return bool(re.search(r"\d", t))


def _version_key(tag):
    """Sort key that puts 1.10 above 1.9 instead of below it."""
    out = []
    for part in re.split(r"(\d+)", tag.lower()):
        if not part:
            continue
        out.append((1, int(part), "") if part.isdigit() else (0, 0, part))
    return out


def _major(tag):
    m = re.search(r"\d+", tag or "")
    return m.group(0) if m else ""


def _variant(tag):
    """What follows the last number: 'v11.4.0-alpine' -> '-alpine'.

    Prefer the packaging the service already runs: someone on '11.4.0' wants
    '11.5.0', not '11.5.0-alpine'.
    """
    m = re.match(r"^(?:[^\d]*\d[\w.]*?)((?:[-_.][\w.]+)*)$", tag)
    return (m.group(1) if m else "").lower()


def newest_tag(image, limit=100):
    """The version to move an existing service to.

    Registries hand back tags in their own order (Docker Hub by last_updated,
    everyone else alphabetically), so neither order answers "what is newest".
    Channel and CI tags are dropped, then the version-shaped ones are compared
    numerically.
    """
    listed = list_tags(image, limit=limit)
    current = listed.get("current") or ""
    tagged = [t for t in listed["tags"] if is_version_tag(t)]
    if not tagged:
        raise RuntimeError(f"no version-like tags for {listed['repo']} in {listed['host']} "
                           f"({len(listed['tags'])} tags seen: {', '.join(listed['tags'][:5])})")

    # Same major only: "update postgres" must not silently jump 16 -> 18.
    majors = [t for t in tagged if _major(t) == _major(current)]
    pool = majors if (current and is_version_tag(current) and majors) else tagged

    def rank(t):
        # highest *version* wins; on a tie prefer the packaging already in use,
        # then the plainest tag ("1.31.8" over "1.31.8-trixie-perl").
        # Only the leading version counts: "1.31.8-alpine3.24" is 1.31.8, not
        # 1.31.8.3.24, or alpine would always outrank the plain tag.
        m = re.match(r"^[^\d]*(\d+(?:[._]\d+)*)", t)
        ver = tuple(int(n) for n in re.split(r"[._]", m.group(1))) if m else ()
        return (ver, 1 if _variant(t) == _variant(current) else 0, -len(t))

    pool.sort(key=rank, reverse=True)
    candidates = pool
    best = candidates[0]
    up_to_date = bool(current) and is_version_tag(current) and _version_key(current) >= _version_key(best)
    return {"tag": current if up_to_date else best,
            "best": best, "current": current, "up_to_date": up_to_date,
            "host": listed["host"], "repo": listed["repo"],
            "candidates": candidates[:10]}
