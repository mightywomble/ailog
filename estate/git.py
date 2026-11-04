"""The estate checkout, and commits that survive somebody else's push.

AILog holds a clone of the estate repo in its own volume.  It is the only way to
answer "what does git say this service should be running" without asking CI, and
it is where a version bump is written before it is pushed.

The conflict rule, from day one: **regenerate, never merge.**  An edit here is a
pure function of the tree plus a version number, so when a push is rejected
because `dev` moved, the fix is to reset and run the same edit again - not to
rebase a half-applied change over somebody else's work.  If the service moved on
without us (someone else bumped the same tag), the retry notices and stops
instead of stomping on it.
"""

from __future__ import annotations

import os
import subprocess
import time

from . import settings

# When the read endpoints last fetched, so polling the UI does not spawn a git
# fetch per request.
_last_sync = [0.0]


class GitError(RuntimeError):
    pass


class Conflict(GitError):
    """The estate moved while we were editing it."""


def _run(args, cwd: str, timeout: int | None = None):
    env = dict(os.environ)
    # Never prompt: this runs in a container with no tty and no askpass.
    # Never prompt: this runs in a container with no tty and no askpass helper.
    # No GIT_ASKPASS either - pointing it at a binary that does not exist on the
    # host made git fail before it read the URL.
    env.update({'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_NOSYSTEM': '1'})
    try:
        proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                              timeout=timeout or settings.git_timeout(), env=env)
    except subprocess.TimeoutExpired:
        raise GitError(f'git {args[1]} timed out')
    out = settings.redact((proc.stdout or '') + (proc.stderr or '')).strip()
    return proc.returncode == 0, out


class Repo:
    def __init__(self, directory: str | None = None, branch: str | None = None):
        self.dir = str(directory or settings.repo_dir())
        self.branch = branch or settings.work_branch()

    # ---------------------------------------------------------------- clone --
    def git(self, *args, timeout=None):
        return _run(['git', '-c', f'user.name={settings.commit_name()}',
                     '-c', f'user.email={settings.commit_email()}',
                     '-c', 'advice.detachedHead=false', *args],
                    cwd=self.dir, timeout=timeout)

    def exists(self) -> bool:
        return os.path.isdir(os.path.join(self.dir, '.git'))

    def ensure(self) -> None:
        if self.exists():
            return
        parent = os.path.dirname(self.dir)
        if parent:
            os.makedirs(parent, exist_ok=True)
        ok, out = _run(['git', 'clone', '--branch', self.branch, settings.authed_url(), self.dir],
                       cwd=parent or '.')
        if not ok:
            raise GitError(f'clone failed: {out[:300]}')

    def sync(self) -> str:
        """Fetch and hard-reset to the branch tip. Returns the new head sha.

        A dirty tree is thrown away on purpose: the only writes here are edits we
        are about to regenerate from the fresh tree.
        """
        self.ensure()
        ok, out = self.git('fetch', '--prune', 'origin', self.branch)
        if not ok:
            raise GitError(f'fetch failed: {out[:300]}')
        ok, out = self.git('reset', '--hard', f'origin/{self.branch}')
        if not ok:
            raise GitError(f'reset failed: {out[:300]}')
        ok, out = self.git('clean', '-fd', '-q')
        return self.head()

    def head(self) -> str:
        ok, out = self.git('rev-parse', 'HEAD')
        return out.strip() if ok else ''

    def fresh(self, max_age: int = 60) -> str:
        """The branch tip, fetching at most once per ``max_age`` seconds.

        Reads use this so the estate view cannot show a tree from before the last
        release.  A failed fetch is not a failed read: the checkout is still a
        true, if older, answer, and monitoring must keep working offline.
        """
        now = time.time()
        if now - _last_sync[0] >= max_age:
            try:
                self.sync()
            except GitError:
                pass
            _last_sync[0] = now
        return self.head()

    # ---------------------------------------------------------------- files --
    def path(self, relpath: str) -> str:
        return os.path.join(self.dir, relpath)

    def read(self, relpath: str, default: str = '') -> str:
        try:
            with open(self.path(relpath), encoding='utf-8') as handle:
                return handle.read()
        except OSError:
            return default

    def write(self, relpath: str, text: str) -> None:
        path = self.path(relpath)
        os.makedirs(os.path.dirname(path) or self.dir, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(text)

    def changed(self) -> list[str]:
        ok, out = self.git('status', '--porcelain')
        if not ok:
            return []
        return [line[3:].strip() for line in out.splitlines() if line.strip()]

    # --------------------------------------------------------------- commit --
    def commit(self, message: str, paths) -> list[str]:
        files = [p for p in paths if p]
        if files:
            ok, out = self.git('add', '--', *files)
            if not ok:
                raise GitError(f'add failed: {out[:300]}')
        staged = self.changed()
        if not staged:
            return []
        ok, out = self.git('commit', '-m', message)
        if not ok:
            raise GitError(f'commit failed: {out[:300]}')
        return staged

    def push(self) -> None:
        ok, out = self.git('push', 'origin', f'HEAD:{self.branch}', timeout=settings.git_timeout())
        if not ok:
            lowered = out.lower()
            if 'rejected' in lowered or 'non-fast-forward' in lowered or 'fetch first' in lowered:
                raise Conflict(out[:300])
            raise GitError(f'push failed: {out[:300]}')

    # ---------------------------------------------------------- edit + push --
    def apply(self, edit, message: str, attempts: int = 4) -> dict:
        """Reset, run ``edit`` against the fresh tree, commit, push.

        ``edit(repo, entry)`` must be idempotent: it is called again after every
        lost race, and on the retry it sees the tree somebody else just pushed.
        """
        last = ''
        for attempt in range(1, attempts + 1):
            self.sync()
            entry, files = edit(self)
            if not files:
                return {'changed': [], 'head': self.head(), 'attempts': attempt, 'entry': entry}
            staged = self.commit(message, [f for f in files])
            try:
                self.push()
                return {'changed': staged, 'head': self.head(), 'attempts': attempt, 'entry': entry}
            except Conflict as exc:
                last = str(exc)
                continue
        raise Conflict(f'the estate branch {self.branch} kept moving; gave up after '
                       f'{attempts} attempts: {last[:200]}')
