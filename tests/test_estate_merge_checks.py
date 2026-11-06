"""A merge into a protected branch is a wait, not a retry.

Once ``main`` required CI, every one-click estate update ended the same way:

    405 {"message":"Not all required status checks successful"}

after twelve attempts. The retry budget was twelve attempts of exponential
backoff - about eighty seconds - and the checks take as long as a build takes.
Nothing was wrong with the pull request, or the update, or the pipeline; the
merge was simply being asked before CI had finished, twelve times, and then
reported as a failure.

These tests pin the replacement: ask the branch's protection rule which checks
it requires, wait for those, and when they do not arrive say which one is still
running and whether the runner has gone quiet.
"""

from __future__ import annotations

import pytest

from estate import forge as forge_mod
from estate import update as update_mod


class FakeHTTP:
    """Just enough of requests.Session: GET by URL, POST recorded."""

    def __init__(self, get_routes: dict):
        self.get_routes = get_routes
        self.posts: list[dict] = []

    class Resp:
        def __init__(self, status_code, payload=None):
            self.status_code = status_code
            self._payload = payload if payload is not None else {}
            self.text = ''

        def json(self):
            return self._payload

    def get(self, url, params=None, timeout=None):
        for suffix, (code, payload) in self.get_routes.items():
            if url.endswith(suffix):
                return self.Resp(code, payload)
        return self.Resp(404)

    def post(self, url, json=None, timeout=None):
        self.posts.append(json or {})
        return self.Resp(200, {'merge_commit_sha': 'd' * 40})


def _forge(get_routes) -> forge_mod.Forge:
    f = forge_mod.Forge()
    f.api, f.path = 'https://gitea.example/api/v1/repos/o/n', ''
    f.http = FakeHTTP(get_routes)
    return f


PROTECTED = {
    '/branch_protections': (200, [{
        'branch_name': 'main',
        'enable_status_check': True,
        'status_check_contexts': ['CI / python (pull_request)',
                                  'CI / frontend-syntax (pull_request)'],
    }]),
    '/pulls/7': (200, {'number': 7, 'base': {'branch': 'main'},
                       'head': {'sha': 'a' * 40}}),
}


def test_it_asks_the_protection_rule_which_checks_are_required():
    f = _forge(PROTECTED)
    assert f.required_checks('main') == ['CI / python (pull_request)',
                                         'CI / frontend-syntax (pull_request)']


def test_an_unprotected_branch_requires_nothing():
    f = _forge({'/branch_protections': (200, [])})
    assert f.required_checks('main') == []


def test_a_repository_without_protections_merges_as_it_always_did():
    f = _forge({'/branch_protections': (404, {})})
    # no protection, so no wait: merge_pr is reached immediately
    f.http.post = lambda *a, **k: FakeHTTP.Resp(200, {'merge_commit_sha': 'e' * 40})
    assert f.merge_when_ready(7)['sha'] == 'e' * 40


def test_a_failed_check_is_reported_at_once_with_its_description():
    """Retrying cannot fix a failed check, and a name alone does not say why."""
    f = _forge({**PROTECTED,
                '/commits/' + 'a' * 40 + '/status': (200, {'statuses': [
                    {'context': 'CI / python (pull_request)', 'status': 'failure',
                     'description': 'Process completed with exit code 1'},
                    {'context': 'CI / frontend-syntax (pull_request)',
                     'status': 'pending'}]})})

    with pytest.raises(forge_mod.ForgeError) as err:
        f.merge_when_ready(7, poll=0)

    message = str(err.value)
    assert 'required checks failed' in message
    assert 'CI / python (pull_request): failure - Process completed with exit code 1' in message
    assert f.http.posts == []            # it did not try to merge at all


def test_pending_checks_are_waited_for_and_then_the_merge_happens(monkeypatch):
    """The whole point: a merge that used to 405 now waits and succeeds."""
    states = iter([
        (['CI / python (pull_request)'], ['CI / frontend-syntax (pull_request)'], []),
        (['CI / python (pull_request)', 'CI / frontend-syntax (pull_request)'], [], []),
    ])
    f = _forge({**PROTECTED, '/commits/' + 'a' * 40 + '/status': (200, {})})
    monkeypatch.setattr(f, 'check_report', lambda sha, required: next(states))
    monkeypatch.setattr(forge_mod.time, 'sleep', lambda s: None)

    seen = []
    out = f.merge_when_ready(7, report=lambda label, detail, ok=None: seen.append(detail))

    assert out['merged'] is True
    assert any('waiting on CI / frontend-syntax (pull_request)' in d for d in seen), seen
    assert any('all 2 green' in d for d in seen), seen


def test_a_wait_that_never_ends_names_what_is_still_running(monkeypatch):
    f = _forge({**PROTECTED, '/commits/' + 'a' * 40 + '/status': (200, {})})
    monkeypatch.setattr(f, 'check_report',
                        lambda sha, required: (['CI / python (pull_request)'],
                                               ['CI / frontend-syntax (pull_request)'], []))
    monkeypatch.setattr(forge_mod.time, 'sleep', lambda s: None)

    with pytest.raises(forge_mod.ForgeError) as err:
        f.merge_when_ready(7, timeout=0, runs=lambda sha: 'ci.yml in_progress for 22m')

    message = str(err.value)
    assert 'still waiting on CI / frontend-syntax (pull_request)' in message
    assert 'ci.yml in_progress for 22m' in message          # the evidence
    assert 'wedged' in message and 'act-runner' in message  # and what to do about it


def test_the_wait_says_what_the_runs_are_doing():
    """A wedged runner and a slow build are both 'pending'; only the age differs."""
    class F(forge_mod.Forge):
        def __init__(self):
            pass
        def workflow_of(self, run):
            return str(run.get('path') or '').split('@')[0]

    f = F()
    now = '2099-01-01T00:00:00Z'
    runs = [
        {'path': 'ci.yml@refs/pull/7/head', 'head_sha': 'a' * 40,
         'status': 'in_progress', 'started_at': '2026-11-06T10:00:00Z'},
        {'path': 'build.yml@refs/heads/dev', 'head_sha': 'a' * 40,
         'status': 'completed', 'conclusion': 'success', 'started_at': now},
        {'path': 'mirror.yml@refs/heads/dev', 'head_sha': 'b' * 40,
         'status': 'queued', 'started_at': '1970-01-01T00:00:00Z'},
    ]
    f.runs = lambda limit=30: runs

    note = update_mod._runs_note(f, 'a' * 40)

    assert note.startswith('ci.yml in_progress for ')
    assert 'build.yml' not in note        # finished runs say nothing
    assert 'mirror.yml' not in note       # another commit's runs are not this wait


class RecordingSink(update_mod.Sink):
    def __init__(self):
        self.steps: list[tuple[str, object, str]] = []
        self.logs: list[str] = []

    def step(self, label, ok=None, detail=''):
        self.steps.append((label, ok, detail))

    def log(self, text):
        self.logs.append(text)

    def progress(self, pct):
        pass


def test_a_refused_merge_is_marked_on_the_step_list():
    """The job's error is one message; the steps are what a person reads first."""
    class Refuses:
        def merge_when_ready(self, index, report=None, runs=None, **kwargs):
            if report:
                report('required checks', '1/2 green - waiting on CI / python (pull_request)')
            raise forge_mod.ForgeError('PR #7 cannot merge - required checks failed: '
                                       'CI / python (pull_request): failure - exit code 1')

    sink = RecordingSink()
    with pytest.raises(forge_mod.ForgeError):
        update_mod._merge(Refuses(), sink, {'number': 7})

    labels = [label for label, _ok, _detail in sink.steps]
    assert 'required checks' in labels
    failed = [step for step in sink.steps if step[1] is False]
    assert failed, 'the merge step must be marked failed, not left blank'
    assert 'exit code 1' in failed[-1][2]
    assert any('merge refused' in line for line in sink.logs)


def test_the_wait_is_reported_while_it_waits():
    """Ten quiet minutes followed by a 405 is what made this unfixable by reading."""
    class Waits:
        def merge_when_ready(self, index, report=None, runs=None, **kwargs):
            report('required checks', '0/1 green - waiting on CI / python (pull_request)')
            report('required checks', '1/1 green', ok=True)
            return {'merged': True, 'sha': 'a' * 40}

    sink = RecordingSink()
    update_mod._merge(Waits(), sink, {'number': 7})

    details = [detail for label, _ok, detail in sink.steps if label == 'required checks']
    assert details == ['0/1 green - waiting on CI / python (pull_request)', '1/1 green']
    green = [ok for label, ok, _d in sink.steps if label == 'required checks']
    assert green[-1] is True
