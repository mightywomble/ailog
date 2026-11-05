"""Credentials come from Docker secrets, with the environment as a fallback.

A value in a stack file is a value in git, and it is also what
``docker service inspect`` prints back for anyone with a shell on a manager.
These tests pin the three properties that make the migration safe:

* the file wins when it exists, so the stack file can stop carrying the value,
* the environment still works, so a hand-started container and the test suite
  keep running,
* a missing or empty file is not an error - it falls through, it does not raise.
  The alternative (a container that refuses to boot because a secret is not
  mounted) turns a credential change into an outage.
"""

import os

import pytest

from utils import secretfiles


@pytest.fixture()
def secrets_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(secretfiles, 'SECRETS_DIR', str(tmp_path))
    return tmp_path


def test_the_secret_file_wins_over_the_environment(secrets_dir, monkeypatch):
    (secrets_dir / 'ailog_mcp_token').write_text('from-the-file\n')
    monkeypatch.setenv('AILOG_MCP_TOKEN', 'from-the-env')
    assert secretfiles.secret('ailog_mcp_token', 'AILOG_MCP_TOKEN') == 'from-the-file'


def test_the_environment_still_works_when_no_secret_is_mounted(secrets_dir, monkeypatch):
    monkeypatch.setenv('AILOG_SECRET_KEY', 'only-in-env')
    assert secretfiles.secret('ailog_secret_key', 'AILOG_SECRET_KEY') == 'only-in-env'


def test_an_empty_secret_file_falls_through_instead_of_blanking_the_credential(
        secrets_dir, monkeypatch):
    # An empty file is what a mis-created secret looks like. Returning '' would
    # silently disable the feature it protects; falling through is visible.
    (secrets_dir / 'ailog_mcp_token').write_text('   \n')
    monkeypatch.setenv('AILOG_MCP_TOKEN', 'from-the-env')
    assert secretfiles.secret('ailog_mcp_token', 'AILOG_MCP_TOKEN') == 'from-the-env'


def test_nothing_configured_is_an_empty_string_not_an_exception(secrets_dir, monkeypatch):
    monkeypatch.delenv('AILOG_MCP_TOKEN', raising=False)
    assert secretfiles.secret('ailog_mcp_token', 'AILOG_MCP_TOKEN') == ''
    assert secretfiles.configured('ailog_mcp_token', 'AILOG_MCP_TOKEN') is False


def test_the_default_directory_is_where_swarm_mounts_secrets():
    # Guard the constant, not just the behaviour: a typo here would make every
    # credential silently fall back to an environment that is about to be empty.
    assert secretfiles.SECRETS_DIR == os.environ.get('AILOG_SECRETS_DIR', '/run/secrets')
    assert '/run/secrets' in secretfiles.SECRETS_DIR or os.environ.get('AILOG_SECRETS_DIR')
