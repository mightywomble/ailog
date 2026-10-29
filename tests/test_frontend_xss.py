"""Phase 4: no server-provided text goes into innerHTML unescaped."""

from __future__ import annotations

import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JS_DIR = os.path.join(ROOT, 'static', 'js')

# Fields that come from the API/user input and must never be interpolated raw.
RISKY_FIELDS = (
    'friendly_name', 'host_name', 'description', 'hostname',
    'error', 'message', 'filename', 'log.name', 'key_name',
)


def _js_files():
    for name in sorted(os.listdir(JS_DIR)):
        if name.endswith('.js'):
            yield name, open(os.path.join(JS_DIR, name)).read()


def _templates():
    for name in sorted(os.listdir(os.path.join(ROOT, 'templates'))):
        if name.endswith('.html'):
            yield name, open(os.path.join(ROOT, 'templates', name)).read()


def _html_literal_interpolations(body):
    """Yield (line, expression) for ``${...}`` inside template literals containing markup.

    A template literal that already contains ``<`` is building HTML, so every
    interpolation in it needs escaping. Toast/log strings (no markup) do not.
    """
    out = []
    stack = []
    i = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if ch == '\\':
            i += 2
            continue
        if ch == '`':
            if stack:
                stack.pop()
            else:
                stack.append(i)
            i += 1
            continue
        if stack and body.startswith('${', i):
            depth = 1
            j = i + 2
            while j < n and depth:
                if body[j] == '{':
                    depth += 1
                elif body[j] == '}':
                    depth -= 1
                j += 1
            expr = body[i + 2:j - 1]
            literal = body[stack[-1]:i]
            if '<' in literal:
                out.append((body[:i].count('\n') + 1, expr.strip()))
            i = j
            continue
        i += 1
    return out


@pytest.mark.parametrize('filename,body', list(_js_files()))
def test_no_raw_interpolation_of_server_text(filename, body):
    """``${host.friendly_name}`` inside an HTML template literal is an XSS bug."""
    risky = re.compile(r'\.(' + '|'.join(re.escape(f.split('.')[-1]) for f in RISKY_FIELDS) + r')\b')
    offenders = []
    for line, expr in _html_literal_interpolations(body):
        if any(tok in expr for tok in ('escapeHtml', 'esc(', 'String(', 'JSON.stringify', 'encodeURIComponent')):
            continue
        if risky.search(expr):
            offenders.append((line, expr[:60]))
    assert offenders == [], f'{filename}: unescaped interpolation at {offenders}'


def test_escape_helper_is_exported_for_legacy_scripts():
    body = open(os.path.join(JS_DIR, 'app-core.js')).read()
    assert 'window.escapeHtml = escapeHtml' in body


def test_host_card_and_failure_lists_escape():
    body = open(os.path.join(JS_DIR, 'app-core.js')).read()
    assert '${escapeHtml(host.friendly_name)}' in body
    assert '${escapeHtml(hostData.friendly_name)}' in body
    assert '${escapeHtml(h.host_name)}: ${escapeHtml(h.error)}' in body
    assert '${escapeHtml(log.name)}' in body


def test_groups_panel_escapes_names_and_attributes():
    body = open(os.path.join(JS_DIR, 'groups.js')).read()
    assert 'const esc =' in body
    assert '${esc(g.name)}' in body
    assert 'data-name="${esc(g.name)}"' in body


def test_templates_do_not_build_host_markup_with_jinja_raw_fields():
    """Jinja output is escaped by default; this guards against ``|safe`` slips."""
    offenders = []
    for name, body in _templates():
        for match in re.finditer(r'\{\{[^}]*\|\s*safe[^}]*\}\}', body):
            if 'render' in match.group(0) or 'json' in match.group(0):
                continue
            offenders.append((name, match.group(0)[:60]))
    assert offenders == []
