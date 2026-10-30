"""The remediation UI obeys the house rules: tokens, order, escaping.

Cards render playbook code and model prose, so escaping is a security
property here, not a style preference.
"""

from __future__ import annotations

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSS = os.path.join(ROOT, 'static', 'css')
JS = os.path.join(ROOT, 'static', 'js')
TEMPLATES = os.path.join(ROOT, 'templates')


def _read(*parts):
    return open(os.path.join(*parts)).read()


def test_remediation_css_uses_semantic_tokens_only():
    for name in ('remediation.css', 'remediation-page.css'):
        body = _read(CSS, name)
        hexes = re.findall(r'#[0-9a-fA-F]{3,8}\b', body)
        assert hexes == [], f'{name} has hard-coded colours: {hexes}'
        assert 'var(--' in body, f'{name} must build on the token layer'


def test_the_report_page_loads_remediation_css_after_the_theme_stack():
    body = _read(TEMPLATES, 'report.html')
    order = [body.index('/static/css/theme.css'),
             body.index('/static/css/interfaces.css'),
             body.index('/static/css/remediation.css')]
    assert order == sorted(order)


def test_the_remediation_pages_load_the_page_shell_after_the_theme_stack():
    for name in ('remediation.html', 'remediation_run.html'):
        body = _read(TEMPLATES, name)
        order = [body.index('/static/css/theme.css'),
                 body.index('/static/css/interfaces.css'),
                 body.index('/static/css/remediation.css'),
                 body.index('/static/css/remediation-page.css')]
        assert order == sorted(order), name


def test_every_rem_page_template_has_a_mount_point_and_a_script():
    body = _read(TEMPLATES, 'report.html')
    assert 'id="report-remediations"' in body
    assert 'data-report-id="{{ report.id }}"' in body
    assert '/static/js/remediation.js' in body


def test_the_card_renderer_escapes_server_prose():
    body = _read(JS, 'remediation.js')
    fields = ('title', 'summary', 'rationale', 'code', 'verify', 'rollback', 'risk')
    for field in fields:
        raw = '${card.%s}' % field
        assert raw not in body, raw + ' is interpolated without esc()'
        if field == 'risk':
            # Rendered through riskBadge(), which escapes internally.
            assert 'riskBadge(card.risk)' in body
            continue
        if field in ('code', 'verify', 'rollback'):
            # Rendered through codeBlock(), which escapes the text in a <pre>.
            lines = [ln for ln in body.splitlines() if 'codeBlock(' in ln and 'card.' + field in ln]
            assert lines, field + ' is never passed to codeBlock()'
            continue
        assert re.search(r'esc\([^)]*card\.' + field + r'\b', body), field + ' is never escaped'

def test_the_card_helpers_escape_their_inputs():
    body = _read(JS, 'remediation.js')
    for helper in ('riskBadge', 'listHtml', 'codeBlock'):
        block = body[body.index('function ' + helper) if ('function ' + helper) in body
                     else body.index('const ' + helper):]
        assert 'esc(' in block[:600], f'{helper} must escape its input'


def test_the_renderer_defines_a_local_esc_helper():
    body = _read(JS, 'remediation.js')
    assert 'const esc = ' in body
    assert "'&': '&amp;'" in body and "'<': '&lt;'" in body


def test_model_cards_are_labelled_and_have_no_apply_affordance():
    body = _read(JS, 'remediation.js')
    assert 'Unverified suggestion — copy and run yourself' in body
    # The apply path must be gated on executable, never on source alone.
    assert 'executable' in body
    assert re.search(r'if\s*\([^)]*!?card\.executable', body) or \
           'card.executable' in body


def test_approval_requires_typing_run():
    body = _read(JS, 'remediation.js')
    assert 'RUN' in body
    assert re.search(r"toUpperCase\(\)\s*!==\s*'RUN'", body)


def test_the_run_stream_handles_the_documented_event_types():
    body = _read(JS, 'remediation.js')
    for kind in ('stage', 'target', 'result', 'error', 'log', 'done'):
        assert kind in body, f'the renderer ignores {kind} events'


def test_the_admin_page_never_builds_html_from_data():
    """It only talks to the API and reloads; nothing is interpolated into markup."""
    body = _read(JS, 'remediation-admin.js')
    assert 'innerHTML' not in body
    assert 'insertAdjacentHTML' not in body


def test_the_palette_offers_the_remediation_entry_points():
    body = _read(JS, 'command-palette.js')
    assert 'Open Remediation' in body
    assert 'Open last remediation run' in body
    assert 'Remediation settings' in body


def test_the_shell_links_to_the_remediation_page():
    body = _read(TEMPLATES, 'index.html')
    assert 'href="/remediation"' in body


def test_the_admin_page_explains_how_to_enable_execution():
    body = _read(TEMPLATES, 'remediation.html')
    assert 'AILOG_ALLOW_REMEDIATION' in body
