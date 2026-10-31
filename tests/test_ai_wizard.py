"""The shared AI analysis wizard.

Every AI analysis entry point must run the same two steps before it talks to a
model: (1) what to analyse, (2) which prompt - curated library, saved prompt or
free text. Choosing nothing must keep the classic default analysis.
"""
import os
import re

import aiprompts

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = os.path.join(ROOT, 'templates')


def _js(name):
    with open(os.path.join(ROOT, 'static', 'js', name), encoding='utf-8') as fh:
        return fh.read()


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _wizard_js():
    return _js('ai-wizard.js')


def _app_js():
    return _js('app-core.js')


# --- the library itself ----------------------------------------------------

def test_the_library_ships_the_ten_sysadmin_prompts():
    assert len(aiprompts.PROMPTS) == 10
    titles = [p['title'] for p in aiprompts.PROMPTS]
    assert titles == [
        'Timeline reconstruction',
        'Cross-source correlation',
        'Anomaly / baseline deviation',
        'Security and auth forensics',
        'Container crashloop forensics',
        'Resource exhaustion and OOM',
        'Error clustering and dedup',
        'Log noise and alert-fatigue audit',
        'Boot, unit-ordering and timer health',
        'Postmortem / handoff writer',
    ]
    ids = [p['id'] for p in aiprompts.PROMPTS]
    assert len(ids) == len(set(ids))


def test_every_prompt_is_a_brief_not_a_chat_opener():
    for prompt in aiprompts.PROMPTS:
        body = prompt['prompt']
        assert len(body.split()) > 60, prompt['id']
        assert prompt['summary'].endswith('.'), prompt['id']
        # Output instructions, not just "analyse this"
        assert re.search(r'Output|Report|Produce|End with|Rank|Return|For each|give:|Find|'
                         r'Recommend|Reconstruct|Review|Determine|Identify|Establish|Collapse', body), prompt['id']


def test_placeholders_are_known_and_have_labels():
    for prompt in aiprompts.PROMPTS:
        for token in aiprompts.prompt_tokens(prompt['prompt']):
            assert token in aiprompts.PLACEHOLDER_LABELS, f'{prompt["id"]}: {token}'


def test_filling_leaves_no_braces_and_marks_blanks():
    filled = aiprompts.fill_prompt('Host {{HOST}} at {{START}} about {{SYMPTOM}}',
                                   {'HOST': 'matrix', 'START': '2026-10-31T10:00:00Z'})
    assert '{{' not in filled and '}}' not in filled
    assert 'matrix' in filled
    assert '[SYMPTOM]' in filled          # unanswered blanks are explicit


def test_the_default_prompt_is_the_historical_analysis():
    assert aiprompts.DEFAULT_ANALYSIS_PROMPT.format(log_name='syslog') == (
        'Analyse this log for syslog for errors, create a summary report, '
        'and give troubleshooting tips.'
    )


# --- server endpoints ------------------------------------------------------

def test_the_library_is_served_with_saved_prompts(flask_app):
    payload = flask_app.test_client().get('/ai/prompts').get_json()
    assert payload['success'] is True
    assert len(payload['prompts']) == 10
    assert payload['saved'] == []
    assert payload['placeholder_labels']['HOST'] == 'Host name'
    assert payload['prompts'][0]['placeholders']


def test_a_prompt_can_be_saved_reused_and_deleted(flask_app):
    client = flask_app.test_client()
    saved = client.post('/ai/prompts/save', json={
        'title': 'Backup check', 'prompt': 'Check the backup job for {{HOST}}.',
    }).get_json()
    assert saved['success'] is True
    assert saved['saved'][0]['title'] == 'Backup check'

    again = client.get('/ai/prompts').get_json()
    assert again['saved'][0]['prompt'] == 'Check the backup job for {{HOST}}.'

    # Saving the same text twice must not create a duplicate.
    client.post('/ai/prompts/save', json={'prompt': 'Check the backup job for {{HOST}}.'})
    assert len(client.get('/ai/prompts').get_json()['saved']) == 1

    prompt_id = client.get('/ai/prompts').get_json()['saved'][0]['id']
    removed = client.post('/ai/prompts/delete', json={'id': prompt_id}).get_json()
    assert removed['saved'] == []


def test_an_empty_prompt_is_refused(flask_app):
    response = flask_app.test_client().post('/ai/prompts/save', json={'prompt': '   '})
    assert response.status_code == 400


def test_the_prompt_reaches_the_model_call(flask_app, monkeypatch):
    import app as app_module

    seen = {}

    def fake_ollama(log_content, log_name, url, model, prompt=None):
        seen['prompt'] = prompt
        return 'ok'

    monkeypatch.setattr(app_module, 'analyse_with_ollama', fake_ollama)
    monkeypatch.setattr(app_module, '_analysis_config',
                        lambda provider, data, model=None: {'url': 'http://ollama:11434',
                                                            'model': 'llama3'})

    client = flask_app.test_client()
    response = client.post('/analyse', json={
        'log_content': '2026-10-31T10:00:00Z host systemd[1]: started\n',
        'log_name': 'syslog',
        'provider': 'ollama',
        'host': 'matrix',
        'prompt': 'Timeline for {{HOST}} from {{START}} to {{END}} about {{SYMPTOM}}',
        'prompt_values': {'SYMPTOM': 'the reboot'},
    })
    assert response.status_code == 200
    assert response.get_json()['prompt_used'] is True
    assert 'matrix' in seen['prompt']
    assert 'the reboot' in seen['prompt']
    assert '{{' not in seen['prompt']
    assert '2026-10-31T10:00:00' in seen['prompt']      # inferred from the log


def test_no_prompt_keeps_the_classic_analysis(flask_app, monkeypatch):
    import app as app_module

    seen = {}

    def fake_ollama(log_content, log_name, url, model, prompt=None):
        seen['prompt'] = prompt
        return 'ok'

    monkeypatch.setattr(app_module, 'analyse_with_ollama', fake_ollama)
    monkeypatch.setattr(app_module, '_analysis_config',
                        lambda provider, data, model=None: {'url': 'http://ollama:11434',
                                                            'model': 'llama3'})

    response = flask_app.test_client().post('/analyse', json={
        'log_content': 'line\n', 'log_name': 'syslog', 'provider': 'ollama',
    })
    assert response.status_code == 200
    assert response.get_json()['prompt_used'] is False
    assert seen['prompt'] is None


def test_a_library_id_resolves_without_sending_the_text(flask_app, monkeypatch):
    import app as app_module

    seen = {}

    def fake_ollama(log_content, log_name, url, model, prompt=None):
        seen['prompt'] = prompt
        return 'ok'

    monkeypatch.setattr(app_module, 'analyse_with_ollama', fake_ollama)
    monkeypatch.setattr(app_module, '_analysis_config',
                        lambda provider, data, model=None: {'url': 'http://x', 'model': 'm'})

    response = flask_app.test_client().post('/analyse', json={
        'log_content': 'line\n', 'log_name': 'syslog', 'provider': 'ollama',
        'prompt_id': 'postmortem',
    })
    assert response.status_code == 200
    assert 'postmortem' in seen['prompt'] and 'on-call handoff' in seen['prompt']


def test_the_system_message_warns_that_logs_are_untrusted():
    import app as app_module

    messages = app_module._analysis_messages('syslog', 'body', 'do the thing')
    assert messages[0]['role'] == 'system'
    assert 'untrusted data' in messages[0]['content']
    assert messages[1]['content'].startswith('do the thing')

    default = app_module._analysis_messages('syslog', 'body', None)
    assert 'untrusted data' not in default[0]['content']
    assert default[1]['content'].startswith('Analyse this log for syslog')


# --- the browser side ------------------------------------------------------

def test_the_wizard_dialog_has_both_steps():
    html = _read('templates', 'partials', 'ai-wizard.html')
    assert 'id="ai-wizard-modal"' in html
    assert 'Step 1 of 2 · What to analyse' in html
    assert 'id="aw-step-pip-2"' in html
    assert 'id="aw-body"' in html
    assert 'id="aw-next"' in html


def test_the_wizard_is_loaded_before_the_code_that_uses_it():
    entry = _js('main.js')
    assert "import './ai-wizard.js';" in entry
    assert entry.index("import './ai-wizard.js';") < entry.index("import './app-core.js';")
    page = _read('templates', 'partials', 'ai-wizard.html')
    assert 'partials/ai-wizard.html' or 'ai-wizard-modal' in page


def test_the_wizard_offers_library_saved_and_free_text():
    js = _wizard_js()
    assert "fetch('/ai/prompts'" in js
    assert "fetch('/ai/prompts/save'" in js
    assert "fetch('/ai/prompts/delete'" in js
    assert "id = 'aw-custom'" in js or "custom.id = 'aw-custom'" in js
    assert 'Save this prompt for later' in js
    # The default stays available and is the fallback selection
    assert "promptChoice: 'default'" in js
    assert "'Default analysis'" in js


def test_the_wizard_renders_prompt_text_as_text_only():
    js = _wizard_js()
    assert '.innerHTML' not in js
    assert 'textContent' in js


def test_every_ai_entry_point_runs_the_wizard():
    js = _app_js()
    start = js.index('const runAiAnalysis = async')
    end = js.index('aiAnalyseBtn.addEventListener', start)
    block = js[start:end]
    assert 'window.ailogAiWizard.choose({' in block
    assert 'if (!chosen) return;' in block
    assert 'requestBody.prompt = brief.prompt;' in block
    assert 'requestBody.prompt_values = brief.promptValues || {};' in block

    # Both surfaces call the same pipeline
    assert 'aiAnalyseBtn.addEventListener(\'click\', () => runAiAnalysis({' in js
    assert "mlogAnalyse?.addEventListener('click', () => runAiAnalysis({" in js


def test_the_host_wide_report_reuses_the_same_prompt_picker():
    js = _app_js()
    assert 'window.ailogAiWizard.mountPicker(' in js
    assert 'serverReportPicker.getPrompt()' in js
    assert 'requestBody.prompt = serverPrompt;' in js
    html = _read('templates', 'partials', 'ai-analysis.html')
    assert 'id="server-report-prompt"' in html


def test_the_report_brief_is_additive_and_keeps_the_report_shape():
    llm = _read('serverreport', 'llm.py')
    assert 'ANALYST_BRIEF_HEADER' in llm
    assert 'ANALYST BRIEF' in llm and 'untrusted-data rule' in llm
    routes = _read('serverreport', 'routes.py')
    assert "brief=(data or {}).get('prompt')," in routes


def test_the_wizard_scope_only_changes_what_is_sent():
    js = _wizard_js()
    assert "const applyScope = (content, scope) => {" in js
    assert "if (scope === 'last500') return lines.slice(-500).join('\\n');" in js
    assert "if (scope === 'errors') {" in js
    assert 'Narrowing the scope only changes what is sent to the model' in js


def test_the_wizard_closes_the_dialog_when_back_or_close_is_used():
    js = _wizard_js()
    assert "modal.addEventListener('appmodal:close'" in js
    assert 'current.resolve(null);' in js


def test_the_wizard_is_thumb_sized_and_tokenised():
    css = _read('static', 'css', 'ui.css')
    block = css[css.index('/* --- AI analysis wizard'):]
    assert '.aw-btn' in block and 'min-height: 42px' in block
    assert 'min-height: 46px' in block            # phone targets
    assert 'var(--accent)' in block
    assert not re.search(r'#[0-9a-fA-F]{3,8}\b', block), 'no raw hex in the wizard CSS'
