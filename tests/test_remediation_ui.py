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
    body = _read(JS, 'remediation-wizard.js')
    assert 'RUN' in body
    assert re.search(r"toUpperCase\(\)\s*!==\s*'RUN'", body)
    # ...and only for a multi-host apply, where a click is not enough.
    assert re.search(r"eligible\s*>\s*1\s*&&\s*!state\.dryRun", body)


def test_the_run_stream_handles_the_documented_event_types():
    body = _read(JS, 'remediation-wizard.js')
    for kind in ('heartbeat', 'stage', 'target', 'verify', 'task', 'result', 'error', 'log', 'done'):
        assert "'" + kind + "'" in body, f'the renderer ignores {kind} events'


def test_the_console_proves_the_run_is_alive_and_not_hung():
    """A quiet Ansible run must still look alive: heartbeat, stage, ticker."""
    body = _read(JS, 'remediation-wizard.js')
    assert 'Still running… (waiting for the host)' in body
    assert 'setInterval' in body and 'data-run-elapsed' in body
    # The server sends a heartbeat every few seconds; the client shows elapsed time.
    assert 'type === \'heartbeat\'' in body
    # Per-host rows, so a fleet run shows which host is being worked on.
    assert 'rem-target-name' in body and 'rem-target-task' in body


def test_the_wizard_offers_dry_run_now_or_scheduled():
    body = _read(JS, 'remediation-wizard.js')
    assert 'value="dry"' in body and 'value="apply"' in body
    assert 'forced_dry_run' in body, 'policy must be able to force a dry run'
    assert 'value="now"' in body and 'value="later"' in body
    assert 'type="datetime-local"' in body
    assert 'run_at' in body, 'a scheduled run must send its start time'
    # A local wall-clock time must be sent with a zone, not as a bare string.
    assert 'new Date(state.runAt)' in body and '.toISOString()' in body


def test_the_wizard_escapes_every_server_string_it_interpolates():
    body = _read(JS, 'remediation-wizard.js')
    assert 'const esc = ' in body
    assert "'&': '&amp;'" in body and "'<': '&lt;'" in body
    for field in ('plan.title', 'plan.scope', 't.label', 't.why'):
        assert 'esc(' + field in body, f'{field} is interpolated unescaped'
    # Code blocks go through block(), which escapes the text inside a <pre>.
    for field in ('plan.code', 'plan.verify', 'plan.rollback'):
        assert "block('" in body and field in body, f'{field} is never rendered through block()'
    assert "${esc(text)}" in body
    # Risk goes through riskBadge(), which escapes internally.
    assert 'riskBadge(plan.risk)' in body
    # The live log is text, never markup.
    assert 'row.textContent = line' in body


def test_report_and_admin_pages_load_the_wizard_before_their_own_script():
    for name, own in (('report.html', '/static/js/remediation.js'),
                      ('remediation.html', '/static/js/remediation-admin.js')):
        body = _read(TEMPLATES, name)
        assert '/static/js/remediation-wizard.js' in body, name
        assert body.index('/static/js/remediation-wizard.js') < body.index(own), name


def test_both_entry_points_use_the_shared_wizard():
    for name, call in (('remediation.js', 'window.ailogRemediation.open'),
                       ('remediation-admin.js', 'window.ailogRemediation.open')):
        body = _read(JS, name)
        assert call in body, f'{name} must open the wizard'
        # No second implementation of apply/stream may survive.
        assert 'new EventSource(' not in body, f'{name} still streams its own run'
        assert '/apply' not in body, f'{name} still applies on its own'


def test_the_palette_offers_the_remediation_entry_points():
    body = _read(JS, 'command-palette.js')
    assert 'Open Remediation' in body
    assert 'Open last remediation run' in body
    assert 'Remediation settings' in body


def test_the_shell_links_to_the_remediation_page():
    body = _read(TEMPLATES, 'index.html')
    # A green header link to the page. The dialog belongs to reports, not here.
    assert 'href="/remediation"' in body
    assert 'icon-btn is-go' in body
    assert 'remediationModalFrame' not in body


def test_the_remediation_header_button_is_green():
    shell = _read(CSS, 'shell.css')
    body = _read(TEMPLATES, 'index.html')
    assert 'icon-btn is-go' in body
    assert '.icon-btn.is-go' in shell
    # Green comes from the token layer, never a literal colour.
    assert 'var(--ok)' in shell.split('.icon-btn.is-go')[1][:400]


def test_a_report_opens_in_the_reports_dialog():
    body = _read(JS, 'iframe-modals.js')
    assert 'window.openReportModal' in body
    assert '/reports/${encodeURIComponent(reportId)}?embed=1' in body
    # The reports frame is unloaded on close, like every other embedded page.
    assert "reportsModal: 'reportsModalFrame'" in body
    # The dialog title follows whichever document the frame is showing.
    assert 'contentDocument' in body and 'reportsModalTitle' in body


def test_a_report_has_an_embedded_form_whose_links_stay_in_the_dialog():
    body = _read(TEMPLATES, 'report.html')
    assert "request.args.get('embed') == '1'" in body
    assert 'is-embedded' not in body  # this page uses utilities, not a page shell
    # Every internal link carries the flag, so navigation stays in the frame.
    assert 'href="/reports{{ q }}"' in body
    assert 'href="/remediation{{ q }}"' in body
    assert "{{ diff.get('previous_id') }}{{ q }}" in body
    # ...and the standalone-only Back link is dropped inside the dialog.
    assert '{% if not embedded %}' in body


def test_the_report_list_links_stay_inside_the_dialog():
    body = _read(TEMPLATES, 'reports.html')
    assert 'href="/reports/{{ r.id }}{% if embedded %}?embed=1{% endif %}"' in body
    # No target=_blank for report links when embedded: that would escape the dialog.
    assert 'target="_blank"' not in body.split('{% for r in reports %}')[1]


def test_the_dashboard_and_the_analyser_open_the_report_dialog():
    overview = _read(JS, 'overview.js')
    assert 'window.openReportModal(link.dataset.ovReport)' in overview
    assert 'data-ov-report=' in overview

    core = _read(JS, 'app-core.js')
    assert 'window.openReportModal(id)' in core
    assert '?embed=1' in core, 'the analyser link must point at the embedded report'
    # A finished analysis opens its report in the dialog without another click.
    assert "if (evt.report_id && typeof window.openReportModal === 'function')" in core


def test_catalog_cards_take_the_width_and_model_ideas_sit_beside_them():
    body = _read(JS, 'remediation.js')
    assert 'function cardsHtml()' in body
    # Catalog (executable) cards are one column; ideas only appear when there are any.
    assert "card.source === 'llm'" in body
    assert 'rem-layout has-ideas' in body
    css = _read(CSS, 'remediation.css')
    assert '.rem-layout.has-ideas' in css
    # The old half-width two-up grid is gone.
    assert '.rem-grid' not in body and '.rem-grid' not in css


def test_the_admin_page_explains_how_to_enable_execution():
    body = _read(TEMPLATES, 'remediation.html')
    assert 'AILOG_ALLOW_REMEDIATION' in body
