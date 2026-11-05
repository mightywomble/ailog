"""The estate's CI, read and driven through Gitea's API.

AILog does not build or deploy anything itself: `ship.yml` builds changed apps,
pushes them into zot and `docker stack deploy`s the changed stacks on a runner
that sits on the manager.  What this app adds is the part the pipeline is bad at:
a PR that takes one click, and a live view of the run instead of a browser tab.

Ported from the wizard's ``forge.Gitea`` (runs / find_run / job_log / create_pr /
merge_pr), with two fixes that came out of using it:

* a merge 405 is retried only while it is the lock, and reported as a conflict
  when `mergeable` is false - the wizard's version could burn eight attempts on
  something no retry can fix;
* log fetching returns whatever the job has so far, so a run in progress still
  shows output.
"""

from __future__ import annotations

import time

import requests

from . import settings


class ForgeError(RuntimeError):
    pass


class Forge:
    def __init__(self, session=None):
        self.api = self._api_root()
        self.path = f'/repos/{settings.owner()}/{settings.name()}'
        self.http = session or requests.Session()
        token = settings.token()
        if token:
            self.http.headers.update({'Authorization': f'token {token}'})
        self.http.headers.update({'Accept': 'application/json'})

    @staticmethod
    def _api_root() -> str:
        url = settings.repo_url()
        base = url
        for suffix in ('.git',):
            if base.endswith(suffix):
                base = base[: -len(suffix)]
        scheme, _, rest = base.partition('://')
        host = rest.split('/', 1)[0]
        return f'{scheme}://{host}/api/v1'

    # ----------------------------------------------------------------- runs --
    def runs(self, limit: int = 20) -> list[dict]:
        r = self.http.get(f'{self.api}{self.path}/actions/runs', params={'limit': limit}, timeout=30)
        if r.status_code == 200:
            return r.json().get('workflow_runs') or []
        # older Gitea only exposed /actions/tasks
        r = self.http.get(f'{self.api}{self.path}/actions/tasks', params={'limit': limit}, timeout=30)
        if r.status_code != 200:
            raise ForgeError(f'list runs -> {r.status_code} {r.text[:160]}')
        return r.json().get('workflow_runs') or []

    @staticmethod
    def workflow_of(run: dict) -> str:
        """The workflow a run belongs to.

        Gitea's ``path`` is ``<file>.yml@<ref>`` - just the *file name*, not the
        repo path - so comparing it with ``.gitea/workflows/ship.yml`` never
        matched and every estate update ended with "ship.yml did not start".
        """
        raw = str(run.get('path') or '')
        return raw.split('@', 1)[0].rsplit('/', 1)[-1]

    def find_run(self, workflow: str, sha: str = '', newer_than: int = 0,
                 timeout: int = 120, cancel=None) -> dict | None:
        """The run of ``workflow`` for ``sha``, or the newest one after ``newer_than``.

        Gitea registers the run a second or two after the push lands, so this is
        a poll rather than a read.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            if cancel and cancel():
                return None
            for run in self.runs(limit=30):
                if self.workflow_of(run) != self.workflow_of({'path': workflow}):
                    continue
                if sha and run.get('head_sha') and run.get('head_sha') != sha:
                    continue
                if newer_than and run.get('id', 0) <= newer_than:
                    continue
                return run
            time.sleep(3)
        return None

    def run(self, run_id: int) -> dict:
        r = self.http.get(f'{self.api}{self.path}/actions/runs/{run_id}', timeout=30)
        if r.status_code != 200:
            raise ForgeError(f'run {run_id} -> {r.status_code}')
        return r.json()

    def jobs(self, run_id: int) -> list[dict]:
        r = self.http.get(f'{self.api}{self.path}/actions/runs/{run_id}/jobs', timeout=30)
        return (r.json().get('jobs') or []) if r.status_code == 200 else []

    def job_log(self, job_id: int) -> str:
        r = self.http.get(f'{self.api}{self.path}/actions/jobs/{job_id}/logs', timeout=60)
        return '' if r.status_code == 404 else (r.text or '')

    # ------------------------------------------------------------- pull reqs --
    def create_pr(self, title: str, head: str, base: str = '', body: str = '') -> dict:
        r = self.http.post(f'{self.api}{self.path}/pulls',
                           json={'title': title, 'head': head,
                                 'base': base or settings.base_branch(), 'body': body},
                           timeout=30)
        if r.status_code == 409:               # a PR for this branch is already open
            for pr in self.open_prs():
                if (pr.get('head') or {}).get('ref') == head:
                    return pr
        if r.status_code >= 400:
            raise ForgeError(f'create PR -> {r.status_code} {r.text[:200]}')
        return r.json()

    def open_prs(self) -> list[dict]:
        r = self.http.get(f'{self.api}{self.path}/pulls', params={'state': 'open'}, timeout=30)
        return r.json() if r.status_code == 200 else []

    def pr(self, index: int) -> dict:
        r = self.http.get(f'{self.api}{self.path}/pulls/{index}', timeout=30)
        return r.json() if r.status_code == 200 else {}

    def merge_pr(self, index: int, attempts: int = 8) -> dict:
        """Merge, and say why when it will not.

        Two different 405s used to look identical: "please try again later"
        while another merge holds the lock (retry, it clears) and ``mergeable:
        false``, which no retry can fix and which the UI must show as a conflict.
        """
        last = ''
        delay = 1.0
        for attempt in range(attempts):
            r = self.http.post(f'{self.api}{self.path}/pulls/{index}/merge',
                               json={'Do': 'merge', 'delete_branch_after_merge': False},
                               timeout=60)
            if r.status_code in (200, 201, 204):
                # Gitea answers a merge with an empty body often enough that
                # reading it as JSON raised after the merge had already landed -
                # the run died on a successful deploy.  Ask the PR when the body
                # says nothing.
                body: dict = {}
                try:
                    body = r.json() or {}
                except ValueError:
                    body = {}
                sha = str(body.get('merge_commit_sha') or '')
                if not sha:
                    sha = str(self.pr(index).get('merge_commit_sha') or '')
                return {'merged': True, 'attempts': attempt + 1, 'sha': sha}
            last = f'{r.status_code} {r.text[:160]}'
            # A merge that Gitea reports as refused may still have happened
            # (a retry, or a second caller): look before deciding it failed.
            pr = self.pr(index)
            if pr.get('merged'):
                return {'merged': True, 'attempts': attempt + 1,
                        'sha': str(pr.get('merge_commit_sha') or '')}
            if attempt >= 1 and pr.get('mergeable') is False:
                raise ForgeError(f'PR #{index} conflicts with {settings.base_branch()} '
                                 f'- resolve it on {settings.work_branch()} and run again')
            time.sleep(delay)
            delay = min(delay * 2, 8.0)
        raise ForgeError(f'merge PR #{index} after {attempts} attempts: {last}')
