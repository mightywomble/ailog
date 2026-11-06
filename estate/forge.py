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

    # ------------------------------------------------------- required checks --
    def branch_protection(self, branch: str) -> dict:
        """The rule that decides whether a merge is allowed at all."""
        r = self.http.get(f'{self.api}{self.path}/branch_protections', timeout=30)
        if r.status_code != 200:
            return {}
        for rule in r.json() or []:
            if str(rule.get('branch_name') or '') == branch:
                return rule
        return {}

    def required_checks(self, branch: str) -> list[str]:
        """The status contexts a merge into ``branch`` must wait for.

        Asked of the protection rule rather than hard-coded: the rule is the
        thing that refuses the merge, so it is the thing that knows.  An
        unprotected branch answers [] and merges as it always did.
        """
        rule = self.branch_protection(branch)
        if not rule:
            return []
        return [str(c) for c in (rule.get('status_check_contexts') or [])]

    def commit_status(self, sha: str) -> dict:
        r = self.http.get(f'{self.api}{self.path}/commits/{sha}/status', timeout=30)
        return r.json() if r.status_code == 200 else {}

    def check_report(self, sha: str, required: list[str]) -> tuple[list, list, list]:
        """``(green, pending, failed)`` for the contexts this branch requires.

        ``failed`` is built for a person: a context name alone does not say what
        went wrong, and the description Gitea stores ("Waiting to run",
        "Process completed with exit code 1") does.
        """
        seen = {str(s.get('context') or ''): s
                for s in (self.commit_status(sha).get('statuses') or [])}
        green: list[str] = []
        pending: list[str] = []
        failed: list[str] = []
        for context in required:
            row = seen.get(context) or {}
            state = str(row.get('status') or '').lower()
            if not row or state in ('pending', 'running', 'queued', 'waiting'):
                pending.append(context)
            elif state == 'success':
                green.append(context)
            else:
                detail = str(row.get('description') or '').strip()
                failed.append(f'{context}: {state}' + (f' - {detail}' if detail else ''))
        return green, pending, failed

    def merge_when_ready(self, index: int, report=None, runs=None,
                         timeout: float | None = None, poll: float = 10.0) -> dict:
        """Merge once the branch's required checks are green - or say what is not.

        A protected branch answers a merge with
        ``405 Not all required status checks successful`` until CI has finished,
        and CI takes as long as a build takes.  Twelve attempts of exponential
        backoff is about eighty seconds, so every one-click estate update ended
        "after 12 attempts: 405" on a pull request that was perfectly fine.

        ``report`` is called as ``report(label, detail, ok=None)`` while waiting
        so the job log says which check is still running instead of going quiet
        for ten minutes.  ``runs`` may return one line about the workflow runs
        for the head - that is what tells a slow runner from a wedged one.
        """
        pr = self.pr(index)
        base = str((pr.get('base') or {}).get('branch') or settings.base_branch())
        sha = str((pr.get('head') or {}).get('sha') or '')
        required = self.required_checks(base)
        if not required:
            return self.merge_pr(index)

        if report:
            report('required checks', f'waiting on {len(required)} check(s): '
                                      + ', '.join(required))

        deadline = time.time() + (timeout if timeout is not None else settings.check_wait())
        last = ''
        while True:
            green, pending, failed = self.check_report(sha, required)
            if failed:
                raise ForgeError(f'PR #{index} cannot merge - required checks failed: '
                                 + '; '.join(failed))
            detail = f'{len(green)}/{len(required)} green'
            if pending:
                detail += ' - waiting on ' + ', '.join(pending)
            note = runs(sha) if runs else ''
            if note:
                detail += f' | {note}'
            if detail != last:
                last = detail
                if report:
                    report('required checks', detail)
            if not pending:
                if report:
                    report('required checks', f'all {len(required)} green', ok=True)
                return self.merge_pr(index)
            if time.time() >= deadline:
                fresh = runs(sha) if runs else ''
                raise ForgeError(
                    f'PR #{index} is mergeable but its required checks never finished: '
                    f'{len(green)}/{len(required)} green, still waiting on '
                    f'{", ".join(pending)}' + (f' ({fresh})' if fresh else '')
                    + '. If the run has been in progress with no new output, the build '
                      'runner is wedged - restart act-runner on the build host and re-run')
            time.sleep(poll)

    def merge_pr(self, index: int, attempts: int = 12, conflict_after: float = 25.0) -> dict:
        """Merge, and say why when it will not.

        Three different refusals look alike from the merge endpoint: the lock
        ("please try again later"), ``mergeable: false`` because Gitea has not
        *computed* mergeability yet, and a real conflict.  Only the last one is
        worth waking a person for, and the only way to tell it from the second is
        time - so a conflict is reported only after the flag has stayed false for
        ``conflict_after`` seconds.  Treating the transient false as a conflict is
        how the status rebuild's pin PR (57) was abandoned while it was, in fact,
        mergeable: the run failed on the last step of a successful deploy.
        """
        last = ''
        delay = 1.0
        false_since = 0.0
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
            if pr.get('mergeable') is False:
                false_since = false_since or time.time()
                if time.time() - false_since >= conflict_after:
                    raise ForgeError(f'PR #{index} conflicts with {settings.base_branch()} '
                                     f'(still unmergeable after {int(conflict_after)}s) '
                                     f'- resolve it on {settings.work_branch()} and run again')
            else:
                false_since = 0.0        # it was only being computed
            time.sleep(delay)
            delay = min(delay * 2, 8.0)
        raise ForgeError(f'merge PR #{index} after {attempts} attempts: {last}')
