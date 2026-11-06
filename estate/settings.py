"""Where the estate checkout lives, who we push as, and what we are allowed to do.

Everything is environment-driven so the app can ship with the feature present but
inert (`AILOG_ALLOW_ESTATE=off`), and so the credentials can arrive as Docker
secrets without a rebuild.

Since v3.24 the estate lives *in AILog's own repo* under ``deploy/`` (it was
`homelab-ops`), so the default here is the app's own repository. What used to be
two repos - the app, and the thing that deploys the app - is one tree, one merge
and one chain: `deploy/stacks` deploys to the swarm, `deploy/compose` to the
standalone hosts, and CI is the only thing that ever runs `docker` against
either.
"""

from __future__ import annotations

import os
from pathlib import Path

MODES = ('off', 'plan', 'on')

DEFAULT_REPO = 'https://git.safehomelan.com/david/ailog.git'
DEFAULT_OWNER = 'david'
DEFAULT_NAME = 'ailog'


def _env(name: str, default: str = '') -> str:
    return (os.getenv(name) or default).strip()


def _secret(name: str) -> str:
    """A Docker secret, mounted or inline.

    ``/run/secrets/<name>`` is preferred: it is how the rest of this app reads
    credentials, and it means the value is never in the compose file.
    """
    path = Path('/run/secrets') / name
    try:
        if path.is_file():
            return path.read_text().strip()
    except OSError:
        pass
    return _env(name.upper(), '')


def mode() -> str:
    value = _env('AILOG_ALLOW_ESTATE', 'off').lower()
    return value if value in MODES else 'off'


def enabled() -> bool:
    return mode() != 'off'


def dry_run() -> bool:
    return mode() != 'on'


def root() -> str:
    """The directory the estate's files live in, inside the repo.

    The estate used to be its own repo, so wizard.yaml sat at the root. It is
    part of AILog's repo now and lives under ``deploy/``. ``AILOG_ESTATE_ROOT``
    overrides it, and an empty value means "the repo's own root" - which is what
    a checkout made before the merge still is.
    """
    raw = os.getenv('AILOG_ESTATE_ROOT')
    if raw is None:
        return 'deploy'
    return raw.strip('/')


def repo_dir() -> Path:
    """A checkout that survives a redeploy, next to the app's database."""
    raw = _env('AILOG_ESTATE_DIR')
    path = Path(raw) if raw else Path(_env('AILOG_DATA_DIR', '/var/lib/ailog')) / 'estate'
    return path


def repo_url() -> str:
    return _env('AILOG_ESTATE_REPO', DEFAULT_REPO)


def owner() -> str:
    return _env('AILOG_ESTATE_OWNER', DEFAULT_OWNER)


def name() -> str:
    return _env('AILOG_ESTATE_NAME', DEFAULT_NAME)


def token() -> str:
    """A Gitea token with push on the estate repo (and read on app sources).

    Kept out of the URL the rest of the app logs: every place this value is used
    goes through :func:`authed_url` or the API client's headers.
    """
    return (_secret('estate_git_token') or _secret('gitea_token')
            or _env('AILOG_ESTATE_TOKEN'))


def authed_url() -> str:
    """The clone URL with the token inline.

    Git needs it in the URL (or a credential helper); ``git`` also writes it to
    ``.git/config``.  That is inside the app's own volume, and every job log line
    is passed through :func:`redact` before it is shown.
    """
    url = repo_url()
    token_value = token()
    if not token_value or '@' in url.split('//', 1)[-1]:
        return url
    scheme, _, rest = url.partition('://')
    return f'{scheme}://oauth2:{token_value}@{rest}'


def redact(text: str) -> str:
    """Strip the token out of anything user-visible."""
    value = token()
    if not value:
        return text
    return (text or '').replace(value, '***').replace(f'oauth2:{value}', 'oauth2:***')


def work_branch() -> str:
    return _env('AILOG_ESTATE_BRANCH', 'dev')


def base_branch() -> str:
    return _env('AILOG_ESTATE_BASE', 'main')


def registry() -> str:
    return _env('AILOG_ESTATE_REGISTRY', 'zot.safehomelan.com')


def commit_name() -> str:
    return _env('AILOG_ESTATE_AUTHOR_NAME', 'ailog')


def commit_email() -> str:
    return _env('AILOG_ESTATE_AUTHOR_EMAIL', 'ailog@safehomelan.com')


def git_timeout() -> int:
    try:
        return int(_env('AILOG_ESTATE_GIT_TIMEOUT', '180'))
    except ValueError:
        return 180


def check_wait() -> int:
    """How long a merge may wait for the branch's required status checks.

    A protected branch refuses a merge until its required checks have finished,
    and those checks take as long as a build takes.  This is a *wait*, not a
    retry budget: the merge is attempted once the checks are green, and the
    estate job is a background job precisely so it can sit here.
    """
    try:
        return int(_env('AILOG_ESTATE_CHECK_TIMEOUT', '1800'))
    except ValueError:
        return 1800


def run_wait() -> int:
    """How long a CI job may take before we stop watching it.

    ship.yml builds every changed app and then deploys; a cold build of this
    repo is minutes, not seconds.  Giving up early would report a failure that
    is really just a slow runner, so the wait is generous and the UI says it is
    still watching.
    """
    try:
        return int(_env('AILOG_ESTATE_RUN_TIMEOUT', '1800'))
    except ValueError:
        return 1800
