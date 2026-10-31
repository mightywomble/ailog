// The shared AI analysis wizard.
//
// Every AI analysis entry point runs the same two steps before it talks to a
// model: (1) what to analyse, (2) which prompt. Step 2 offers the curated
// sysadmin library, the user's saved prompts, and a free-text field that can be
// saved for reuse. Choosing nothing keeps the historical default analysis.
//
// Exposed as window.ailogAiWizard:
//   choose({logName, content, host, sourceLabel}) -> Promise<{prompt, promptTitle, content, promptValues}|null>
//   mountPicker(containerEl, {host}) -> {getPrompt, refresh}
//
// Rendering is textContent-only: prompt titles and log text are user/host data.
(function () {
    'use strict';

    const TOKEN_RE = /\{\{([A-Za-z0-9_/][A-Za-z0-9_/ ]*)\}\}/g;
    const SCOPE_LABELS = {
        all: 'The whole log',
        last500: 'The last 500 lines',
        last200: 'The last 200 lines',
        errors: 'Errors and warnings only',
    };
    // Lines that carry operational weight; used by the "errors only" scope.
    const ERROR_RE = /\b(error|err|fail(?:ed|ure)?|fatal|critical|crit|panic|exception|denied|refused|timeout|timed out|oom|killed|segfault|unable)\b/i;

    let library = null;
    let libraryPromise = null;
    let session = null;

    const el = (id) => document.getElementById(id);

    const fetchLibrary = (force) => {
        if (library && !force) return Promise.resolve(library);
        if (libraryPromise && !force) return libraryPromise;
        libraryPromise = fetch('/ai/prompts', { headers: { Accept: 'application/json' } })
            .then((r) => r.json())
            .then((data) => {
                if (!data || !data.success) throw new Error(data && data.error ? data.error : 'Could not load the prompt library.');
                library = data;
                return library;
            })
            .finally(() => { libraryPromise = null; });
        return libraryPromise;
    };

    const tokensIn = (text) => {
        const found = [];
        let match;
        TOKEN_RE.lastIndex = 0;
        while ((match = TOKEN_RE.exec(text || '')) !== null) {
            if (!found.includes(match[1])) found.push(match[1]);
        }
        return found;
    };

    const fillTokens = (text, values) => (text || '').replace(TOKEN_RE, (whole, name) => {
        const value = values && values[name];
        return value ? String(value) : '';
    });

    const tokenLabel = (name) => {
        const labels = (library && library.placeholder_labels) || {};
        return labels[name] || name;
    };

    const lineCount = (text) => (text ? text.split('\n').length : 0);
    const kb = (text) => ((text || '').length / 1024);

    const applyScope = (content, scope) => {
        if (!content) return '';
        const lines = content.split('\n');
        if (scope === 'last500') return lines.slice(-500).join('\n');
        if (scope === 'last200') return lines.slice(-200).join('\n');
        if (scope === 'errors') {
            const hits = lines.filter((line) => ERROR_RE.test(line));
            return hits.join('\n');
        }
        return content;
    };

    // ---------------------------------------------------------------- wizard

    const scaffold = () => {
        const body = el('aw-body');
        if (body) body.textContent = '';
        return body;
    };

    const renderStep1 = () => {
        const body = scaffold();
        if (!body || !session) return;
        const opts = session.opts;
        const content = session.opts.content || '';

        el('aw-sub').textContent = 'Step 1 of 2 · What to analyse';
        el('aw-step-pip-1').classList.add('is-active');
        el('aw-step-pip-2').classList.remove('is-active');
        el('aw-back').classList.add('hidden');
        el('aw-next').textContent = 'Next';

        const card = document.createElement('div');
        card.className = 'aw-target';

        const row = (label, value) => {
            const line = document.createElement('div');
            line.className = 'aw-target-row';
            const k = document.createElement('span');
            k.className = 'aw-target-key';
            k.textContent = label;
            const v = document.createElement('span');
            v.className = 'aw-target-value';
            v.textContent = value;
            line.append(k, v);
            card.appendChild(line);
        };

        row('What', opts.sourceLabel || opts.logName || 'Log data');
        if (opts.host) row('Host', opts.host);
        const stats = document.createElement('span');
        stats.className = 'aw-target-value';
        stats.id = 'aw-stat';
        const statLine = document.createElement('div');
        statLine.className = 'aw-target-row';
        const statKey = document.createElement('span');
        statKey.className = 'aw-target-key';
        statKey.textContent = 'Size';
        statLine.append(statKey, stats);
        card.appendChild(statLine);
        body.appendChild(card);

        const updateStats = () => {
            const scoped = applyScope(content, session.scope);
            stats.textContent = `${lineCount(scoped).toLocaleString()} lines · ${kb(scoped).toFixed(1)} KB of evidence`;
            const note = el('aw-scope-note');
            if (note) {
                if (session.scope === 'errors' && !scoped) {
                    note.textContent = 'No errors or warnings matched — pick a wider scope.';
                    note.classList.remove('hidden');
                } else if (session.scope === 'errors') {
                    note.textContent = `${lineCount(scoped).toLocaleString()} matching lines kept.`;
                    note.classList.remove('hidden');
                } else {
                    note.classList.add('hidden');
                }
            }
            el('aw-next').disabled = !scoped;
        };

        const label = document.createElement('p');
        label.className = 'aw-label';
        label.textContent = 'Which part of it?';
        body.appendChild(label);

        const group = document.createElement('div');
        group.className = 'aw-scopes';
        const scopes = opts.canScope === false ? ['all'] : ['all', 'last500', 'last200', 'errors'];
        scopes.forEach((scope) => {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'aw-scope' + (session.scope === scope ? ' is-selected' : '');
            button.dataset.scope = scope;
            button.textContent = SCOPE_LABELS[scope];
            button.addEventListener('click', () => {
                session.scope = scope;
                group.querySelectorAll('.aw-scope').forEach((b) => b.classList.toggle('is-selected', b === button));
                updateStats();
            });
            group.appendChild(button);
        });
        body.appendChild(group);

        const note = document.createElement('p');
        note.id = 'aw-scope-note';
        note.className = 'aw-note hidden';
        body.appendChild(note);

        const hint = document.createElement('p');
        hint.className = 'aw-note';
        hint.textContent = 'Narrowing the scope only changes what is sent to the model; the log itself is untouched.';
        body.appendChild(hint);

        updateStats();
    };

    const renderPromptRow = (container, { id, title, summary, text, deletable }) => {
        const row = document.createElement('div');
        row.className = 'aw-prompt' + (session.promptChoice === id ? ' is-selected' : '');
        row.dataset.promptId = id;

        const pick = document.createElement('button');
        pick.type = 'button';
        pick.className = 'aw-prompt-main';
        const t = document.createElement('span');
        t.className = 'aw-prompt-title';
        t.textContent = title;
        const s = document.createElement('span');
        s.className = 'aw-prompt-summary';
        s.textContent = summary || text.split('\n')[0];
        pick.append(t, s);
        pick.addEventListener('click', () => selectPrompt(promptCandidate(id, text), container));
        row.appendChild(pick);

        if (deletable) {
            const del = document.createElement('button');
            del.type = 'button';
            del.className = 'aw-prompt-del';
            del.title = 'Delete this saved prompt';
            del.setAttribute('aria-label', `Delete saved prompt ${title}`);
            del.textContent = '×';
            del.addEventListener('click', async (event) => {
                event.stopPropagation();
                await fetch('/ai/prompts/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id: id.replace(/^saved:/, '') }),
                }).catch(() => {});
                await fetchLibrary(true).catch(() => {});
                if (session) renderStep2();
            });
            row.appendChild(del);
        }
        container.appendChild(row);
    };

    const promptCandidate = (id, text) => ({ id, text });

    const selectPrompt = (candidate, container) => {
        session.promptChoice = candidate.id;
        session.promptText = candidate.id === 'default' ? '' : candidate.text;
        if (container) container.querySelectorAll('.aw-prompt').forEach((row) => {
            row.classList.toggle('is-selected', row.dataset.promptId === candidate.id);
        });
        if (candidate.id !== 'custom') {
            const custom = el('aw-custom');
            if (custom) custom.value = candidate.id === 'default' ? '' : candidate.text;
        }
        renderValues();
        renderSaveBox();
    };

    const renderValues = () => {
        const host = el('aw-values');
        if (!host) return;
        host.textContent = '';
        const tokens = tokensIn(session.promptText);
        if (!tokens.length) {
            host.classList.add('hidden');
            return;
        }
        host.classList.remove('hidden');
        const title = document.createElement('p');
        title.className = 'aw-label';
        title.textContent = 'Fill in the blanks';
        host.appendChild(title);

        const sub = document.createElement('p');
        sub.className = 'aw-note';
        sub.textContent = 'Leave a field empty to let the server infer it from the log where it can.';
        host.appendChild(sub);

        const grid = document.createElement('div');
        grid.className = 'aw-values-grid';
        tokens.forEach((name) => {
            const field = document.createElement('label');
            field.className = 'aw-value';
            const span = document.createElement('span');
            span.className = 'aw-value-label';
            span.textContent = tokenLabel(name);
            const input = document.createElement('input');
            input.type = 'text';
            input.className = 'aw-input';
            input.dataset.token = name;
            input.placeholder = name;
            const known = session.opts.values && session.opts.values[name];
            if (known) input.value = known;
            field.append(span, input);
            grid.appendChild(field);
        });
        host.appendChild(grid);
    };

    const renderSaveBox = () => {
        const box = el('aw-save-box');
        if (!box) return;
        box.classList.toggle('hidden', session.promptChoice === 'default');
    };

    const renderStep2 = () => {
        const body = scaffold();
        if (!body || !session) return;

        el('aw-sub').textContent = 'Step 2 of 2 · Prompt';
        el('aw-step-pip-1').classList.remove('is-active');
        el('aw-step-pip-2').classList.add('is-active');
        el('aw-back').classList.remove('hidden');
        el('aw-next').textContent = 'Start analysis';
        el('aw-next').disabled = false;

        if (!session.promptChoice) session.promptChoice = 'default';
        if (session.promptText === undefined) session.promptText = '';

        const list = document.createElement('div');
        list.className = 'aw-prompts';

        renderPromptRow(list, {
            id: 'default',
            title: 'Default analysis',
            summary: 'Summary report, errors found and troubleshooting tips. This is the classic AI Analyse.',
            text: '',
        });
        (library.prompts || []).forEach((p) => {
            renderPromptRow(list, { id: p.id, title: p.title, summary: p.summary, text: p.prompt });
        });

        body.appendChild(list);

        // --- saved prompts
        const saved = library.saved || [];
        if (saved.length) {
            const heading = document.createElement('p');
            heading.className = 'aw-label';
            heading.textContent = 'Saved prompts';
            body.appendChild(heading);
            const savedList = document.createElement('div');
            savedList.className = 'aw-prompts';
            saved.forEach((p) => {
                renderPromptRow(savedList, {
                    id: `saved:${p.id}`,
                    title: p.title,
                    summary: p.prompt.split('\n')[0],
                    text: p.prompt,
                    deletable: true,
                });
            });
            body.appendChild(savedList);
        }

        // --- free text
        const label = document.createElement('p');
        label.className = 'aw-label';
        label.textContent = 'Or write your own';
        body.appendChild(label);

        const custom = document.createElement('textarea');
        custom.id = 'aw-custom';
        custom.className = 'aw-textarea';
        custom.rows = 5;
        custom.placeholder = 'Ask the model anything about this log. Use {{HOST}}, {{START}}, {{SYMPTOM}} and friends if you want the context filled in.';
        custom.value = session.promptChoice === 'custom' ? session.promptText : '';
        custom.addEventListener('input', () => {
            session.promptChoice = custom.value.trim() ? 'custom' : 'default';
            session.promptText = custom.value;
            list.querySelectorAll('.aw-prompt').forEach((row) => row.classList.toggle('is-selected', row.dataset.promptId === 'default' && !custom.value.trim()));
            renderValues();
            renderSaveBox();
        });
        body.appendChild(custom);

        // --- save for later
        const saveBox = document.createElement('div');
        saveBox.id = 'aw-save-box';
        saveBox.className = 'aw-save-box';
        const saveLabel = document.createElement('label');
        saveLabel.className = 'aw-check';
        const saveCheck = document.createElement('input');
        saveCheck.type = 'checkbox';
        saveCheck.id = 'aw-save';
        const saveText = document.createElement('span');
        saveText.textContent = 'Save this prompt for later';
        saveLabel.append(saveCheck, saveText);
        saveBox.appendChild(saveLabel);

        const titleInput = document.createElement('input');
        titleInput.type = 'text';
        titleInput.id = 'aw-save-title';
        titleInput.className = 'aw-input aw-save-title hidden';
        titleInput.placeholder = 'Name it (e.g. "Nightly backup check")';
        saveBox.appendChild(titleInput);
        saveCheck.addEventListener('change', () => titleInput.classList.toggle('hidden', !saveCheck.checked));
        body.appendChild(saveBox);

        const values = document.createElement('div');
        values.id = 'aw-values';
        values.className = 'aw-values hidden';
        body.appendChild(values);

        renderValues();
        renderSaveBox();
    };

    const step = (target) => {
        if (!session) return;
        session.step = target;
        if (target === 1) renderStep1();
        else renderStep2();
    };

    const finish = async () => {
        if (!session) return;
        const current = session;
        const prompt = (current.promptText || '').trim();
        const values = {};
        document.querySelectorAll('#aw-values input[data-token]').forEach((input) => {
            const value = input.value.trim();
            if (value) values[input.dataset.token] = value;
        });

        // Save first: the user asked for it, and a failed save must not block
        // the analysis.
        const saveCheck = el('aw-save');
        if (saveCheck && saveCheck.checked && prompt) {
            const title = (el('aw-save-title') && el('aw-save-title').value.trim()) || '';
            try {
                await fetch('/ai/prompts/save', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ title, prompt }),
                });
                await fetchLibrary(true);
                window.showToast && window.showToast('Prompt saved for later.', 'success');
            } catch (_) {
                window.showToast && window.showToast('Could not save that prompt.', 'error');
            }
        }

        const content = applyScope(current.opts.content, current.scope);
        const promptTitle = prompt
            ? (current.promptChoice === 'custom'
                ? 'Custom prompt'
                : ((library.prompts || []).find((p) => p.id === current.promptChoice) || {}).title
                  || ((library.saved || []).find((p) => `saved:${p.id}` === current.promptChoice) || {}).title
                  || 'Saved prompt')
            : 'Default analysis';

        session = null;
        if (window.closeAppModal) window.closeAppModal(el('ai-wizard-modal'));
        current.resolve({ prompt, promptTitle, content, promptValues: values });
    };

    const cancel = () => {
        if (!session) return;
        const current = session;
        session = null;
        if (window.closeAppModal) window.closeAppModal(el('ai-wizard-modal'));
        current.resolve(null);
    };

    const choose = (opts) => new Promise((resolve) => {
        const modal = el('ai-wizard-modal');
        if (!modal) {
            resolve({ prompt: '', promptTitle: 'Default analysis', content: opts.content || '', promptValues: {} });
            return;
        }
        session = {
            opts: opts || {},
            step: 1,
            scope: 'all',
            promptChoice: 'default',
            promptText: '',
            resolve,
        };
        // Open first so the dialog animates in, then fill it (the library may
        // still be loading; step 2 re-renders when it lands).
        if (window.openAppModal) window.openAppModal(modal);
        renderStep1();
        fetchLibrary()
            .catch((err) => window.showToast && window.showToast(err.message, 'error'));
    });

    // ---------------------------------------------------------- inline picker
    //
    // The server report dialog already has its own step 1 (window, sources,
    // severity), so it gets step 2 only - rendered here so it is literally the
    // same prompt list, saved prompts and free-text field.
    const mountPicker = (container, opts) => {
        if (!container) return { getPrompt: () => '' };
        const options = opts || {};
        container.textContent = '';
        const select = document.createElement('select');
        select.className = 'aw-input';
        const custom = document.createElement('textarea');
        custom.className = 'aw-textarea';
        custom.rows = 4;
        custom.placeholder = 'Optional: your own instruction for this server report.';
        const saveBox = document.createElement('label');
        saveBox.className = 'aw-check';
        const saveCheck = document.createElement('input');
        saveCheck.type = 'checkbox';
        const saveText = document.createElement('span');
        saveText.textContent = 'Save this prompt for later';
        saveBox.append(saveCheck, saveText);

        const titleInput = document.createElement('input');
        titleInput.type = 'text';
        titleInput.className = 'aw-input aw-save-title hidden';
        titleInput.placeholder = 'Name it';

        const render = () => {
            select.textContent = '';
            const none = document.createElement('option');
            none.value = '';
            none.textContent = 'Default report (no extra brief)';
            select.appendChild(none);
            (library.prompts || []).forEach((p) => {
                const option = document.createElement('option');
                option.value = p.prompt;
                option.textContent = p.title;
                select.appendChild(option);
            });
            (library.saved || []).forEach((p) => {
                const option = document.createElement('option');
                option.value = p.prompt;
                option.textContent = `Saved: ${p.title}`;
                select.appendChild(option);
            });
        };

        const label = document.createElement('p');
        label.className = 'aw-label';
        label.textContent = 'Prompt for this report';
        container.append(label, select, custom, saveBox, titleInput);
        select.addEventListener('change', () => {
            custom.value = select.value;
        });
        custom.addEventListener('input', () => {
            if (custom.value.trim()) select.value = '';
        });
        saveCheck.addEventListener('change', () => titleInput.classList.toggle('hidden', !saveCheck.checked));

        fetchLibrary().then(render).catch((err) => {
            if (options.onError) options.onError(err);
        });

        return {
            refresh: () => fetchLibrary(true).then(render).catch(() => {}),
            getPrompt: async () => {
                const text = (custom.value || select.value || '').trim();
                if (saveCheck.checked && text) {
                    try {
                        await fetch('/ai/prompts/save', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ title: titleInput.value.trim(), prompt: text }),
                        });
                        await fetchLibrary(true);
                    } catch (_) { /* an unsaved prompt must not block the report */ }
                }
                return text;
            },
        };
    };

    const onReady = () => {
        const modal = el('ai-wizard-modal');
        if (modal) {
            el('aw-next')?.addEventListener('click', () => {
                if (!session) return;
                if (session.step === 1) step(2);
                else finish();
            });
            el('aw-back')?.addEventListener('click', () => step(1));
            el('aw-cancel')?.addEventListener('click', cancel);
            el('aw-close')?.addEventListener('click', cancel);
            // Escape/backdrop close runs through modals.js, which only hides the
            // dialog; resolve the pending promise so callers never hang.
            modal.addEventListener('appmodal:close', () => {
                if (session) cancel();
            });
        }
        window.ailogAiWizard = { choose, mountPicker, fetchLibrary };
    };

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', onReady);
    else onReady();
})();
