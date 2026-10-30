/* The remediation wizard: review -> options -> confirm -> live console.
 *
 * Shared by the report cards and the /remediation "Start a run" form so there
 * is exactly one path from "I want to fix this" to "Ansible is doing it", and
 * one place that renders progress. Nothing here decides policy: the server
 * signs the plan, re-checks the token on apply, and only the server can widen
 * what will happen.
 *
 *   window.ailogRemediation.open({ slug, hostKey, matchId, scope, title })
 */

(function initRemediationWizard() {
    const W = {};

    const esc = (value) => String(value == null ? '' : value).replace(/[&<>"']/g, (c) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));

    const state = {
        slug: '',
        hostKey: '',
        matchId: null,
        scope: 'host',
        step: 1,
        plan: null,
        dryRun: true,
        when: 'now',
        runAt: '',
        source: null,
        uuid: '',
        startedAt: 0,
        ticker: null,
        lastBeat: 0,
    };

    async function api(url, options) {
        const response = await fetch(url, Object.assign(
            { headers: { 'Content-Type': 'application/json' } }, options || {}));
        let body = {};
        try { body = await response.json(); } catch (error) { body = {}; }
        if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
        return body;
    }

    /* ------------------------------------------------------------- shell */

    function panel() { return document.getElementById('rem-wizard'); }

    function close() {
        stopTicker();
        if (state.source) { state.source.close(); state.source = null; }
        const node = panel();
        if (node) node.remove();
        document.removeEventListener('keydown', onKey);
    }

    function onKey(event) { if (event.key === 'Escape') close(); }

    function ensurePanel() {
        let node = panel();
        if (!node) {
            node = document.createElement('div');
            node.id = 'rem-wizard';
            node.className = 'rem-modal';
            node.setAttribute('role', 'dialog');
            node.setAttribute('aria-modal', 'true');
            node.setAttribute('aria-label', 'Remediation wizard');
            document.body.appendChild(node);
            document.addEventListener('keydown', onKey);
        }
        return node;
    }

    const STEPS = ['Review', 'Options', 'Confirm', 'Run'];

    function stepsHtml() {
        return `<ol class="rem-steps">${STEPS.map((label, index) => {
            const n = index + 1;
            const cls = n === state.step ? 'is-current' : n < state.step ? 'is-done' : '';
            return `<li class="${cls}"><span class="rem-step-n">${n < state.step ? '✓' : n}</span>${esc(label)}</li>`;
        }).join('')}</ol>`;
    }

    function riskBadge(risk) {
        const level = ['low', 'medium', 'high'].includes(risk) ? risk : 'high';
        return `<span class="rem-badge risk-${level}">${esc(risk || 'unknown')} risk</span>`;
    }

    function block(label, text, open) {
        if (!text) return '';
        return `<details ${open ? 'open' : ''}><summary class="rem-muted">${esc(label)}</summary>` +
            `<div class="rem-code-head"><span class="rem-muted">${esc(label)}</span>` +
            `<button type="button" class="rem-btn" data-copy-block>Copy</button></div>` +
            `<pre class="rem-pre">${esc(text)}</pre></details>`;
    }

    function targetsTable(plan) {
        return `<table class="rem-table"><thead><tr><th>Host</th><th>Eligible</th><th>Why</th></tr></thead><tbody>
            ${plan.targets.map((t) => `<tr><td>${esc(t.label)}</td>
              <td class="${t.eligible ? 'rem-ok' : 'rem-bad'}">${t.eligible ? 'yes' : 'no'}</td>
              <td>${esc(t.why || '')}</td></tr>`).join('')}
        </tbody></table>`;
    }

    /* -------------------------------------------------------- steps 1-3 */

    function renderReview(plan) {
        return `
          <div class="rem-panel-body">
            <div class="rem-card-top">
              ${riskBadge(plan.risk)}
              <span class="rem-badge">${esc(plan.scope)}</span>
              <span class="rem-meta">${plan.eligible_keys.length} host(s), ${plan.waves.length} wave(s)</span>
            </div>
            <p class="rem-muted">${esc(plan.entry && plan.entry.summary || '')}</p>
            ${targetsTable(plan)}
            ${block('Playbook (what will run)', plan.code, true)}
            ${block('How it is verified afterwards', plan.verify)}
            ${block('Rollback', plan.rollback)}
            <div class="rem-muted rem-hint">Nothing has run yet.</div>
          </div>
          <div class="rem-panel-foot">
            <button type="button" class="rem-btn" data-wizard-close>Cancel</button>
            <button type="button" class="rem-btn primary" data-wizard-next>Continue</button>
          </div>`;
    }

    function renderOptions(plan, policy) {
        const forced = Boolean(policy && policy.forced_dry_run);
        const canApply = Boolean(policy && policy.enabled);
        return `
          <div class="rem-panel-body">
            <fieldset class="rem-fieldset">
              <legend>Execution</legend>
              <label class="rem-radio">
                <input type="radio" name="rem-mode" value="dry" ${state.dryRun ? 'checked' : ''} ${forced ? 'disabled' : ''}>
                <span><strong>Dry run</strong> — run the playbook with <code>--check --diff</code>.
                  Reports what would change; changes nothing.</span>
              </label>
              <label class="rem-radio">
                <input type="radio" name="rem-mode" value="apply" ${state.dryRun ? '' : 'checked'} ${forced || !canApply ? 'disabled' : ''}>
                <span><strong>Apply</strong> — make the change for real.
                  ${forced ? '<em>Forced to dry run by policy.</em>' : ''}</span>
              </label>
            </fieldset>

            <fieldset class="rem-fieldset">
              <legend>When</legend>
              <label class="rem-radio">
                <input type="radio" name="rem-when" value="now" ${state.when === 'now' ? 'checked' : ''}>
                <span><strong>Run now</strong> — start as soon as you confirm.</span>
              </label>
              <label class="rem-radio">
                <input type="radio" name="rem-when" value="later" ${state.when === 'later' ? 'checked' : ''}>
                <span><strong>Schedule for maintenance</strong> — queue it and start later.</span>
              </label>
              <div class="rem-schedule ${state.when === 'later' ? '' : 'hidden'}" data-schedule-box>
                <label>Start at
                  <input type="datetime-local" id="rem-run-at" value="${esc(state.runAt)}">
                </label>
                <div class="rem-muted rem-hint" data-window-hint></div>
              </div>
            </fieldset>
            <div class="rem-muted rem-hint">Blocking maintenance windows are checked by the server when the run starts.</div>
          </div>
          <div class="rem-panel-foot">
            <button type="button" class="rem-btn" data-wizard-back>Back</button>
            <button type="button" class="rem-btn primary" data-wizard-next>Continue</button>
          </div>`;
    }

    function renderConfirm(plan) {
        const eligible = plan.eligible_keys.length;
        const needsTyping = eligible > 1 && !state.dryRun;
        const mode = state.dryRun ? 'dry run (no changes)' : 'APPLY — changes will be made';
        const when = state.when === 'later' && state.runAt
            ? `scheduled for ${esc(state.runAt.replace('T', ' '))}`
            : 'starts immediately';
        return `
          <div class="rem-panel-body">
            <div class="rem-summary">
              <div><span class="rem-block-label">Remedy</span><div>${esc(plan.title)}</div></div>
              <div><span class="rem-block-label">Mode</span><div class="${state.dryRun ? '' : 'rem-bad'}">${esc(mode)}</div></div>
              <div><span class="rem-block-label">When</span><div>${when}</div></div>
              <div><span class="rem-block-label">Targets</span><div>${eligible} host(s): ${esc(plan.eligible_keys.join(', '))}</div></div>
            </div>
            ${needsTyping
                ? `<label class="rem-confirm">Type <strong>RUN</strong> to approve ${eligible} hosts:
                     <input class="rem-input" data-confirm-input autocomplete="off"></label>`
                : '<div class="rem-muted">Ready to start.</div>'}
            <div class="rem-empty rem-bad hidden" data-wizard-error></div>
          </div>
          <div class="rem-panel-foot">
            <button type="button" class="rem-btn" data-wizard-back>Back</button>
            <button type="button" class="rem-btn primary" data-wizard-start ${needsTyping ? 'disabled' : ''}>
              ${state.dryRun ? 'Start dry run' : 'Start applying'}
            </button>
          </div>`;
    }

    /* ------------------------------------------------------ step 4: live */

    function renderConsole(plan) {
        return `
          <div class="rem-panel-body">
            <div class="rem-console-head">
              <span class="rem-spinner" data-run-spinner aria-hidden="true"></span>
              <strong data-run-stage>Starting…</strong>
              <span class="rem-meta" data-run-elapsed>0s</span>
              <span class="rem-badge" data-run-state>queued</span>
            </div>
            <div class="rem-targets" data-run-targets></div>
            <div class="rem-log" data-run-log aria-live="polite"></div>
          </div>
          <div class="rem-panel-foot">
            <span class="rem-muted" data-run-note>${state.dryRun ? 'Dry run: nothing is changed.' : ''}</span>
            <button type="button" class="rem-btn" data-run-cancel>Cancel</button>
            <button type="button" class="rem-btn" data-run-rollback hidden>Rollback</button>
            <button type="button" class="rem-btn" data-wizard-close>Close</button>
          </div>`;
    }

    function log(line) {
        const box = document.querySelector('#rem-wizard [data-run-log]');
        if (!box) return;
        const row = document.createElement('div');
        row.textContent = line;
        box.appendChild(row);
        while (box.childElementCount > 400) box.removeChild(box.firstChild);
        box.scrollTop = box.scrollHeight;
    }

    function setStage(text) {
        const node = document.querySelector('#rem-wizard [data-run-stage]');
        if (node) node.textContent = text;
    }

    function setRunState(value) {
        const node = document.querySelector('#rem-wizard [data-run-state]');
        if (node) node.textContent = value;
    }

    function targetRow(key, label, status) {
        const box = document.querySelector('#rem-wizard [data-run-targets]');
        if (!box) return;
        let row = box.querySelector(`[data-target="${key}"]`);
        if (!row) {
            row = document.createElement('div');
            row.className = 'rem-target';
            row.dataset.target = key;
            row.innerHTML = `<span class="rem-target-name">${esc(label || key)}</span>` +
                '<span class="rem-target-task rem-muted">waiting</span>' +
                '<span class="rem-target-state rem-muted">queued</span>';
            box.appendChild(row);
        }
        if (status) {
            const stateNode = row.querySelector('.rem-target-state');
            stateNode.textContent = status;
            stateNode.className = 'rem-target-state ' + (
                ['healed', 'checked'].includes(status) ? 'rem-ok'
                    : ['failed', 'rollback_failed', 'unreachable'].includes(status) ? 'rem-bad' : 'rem-muted');
            if (label) row.querySelector('.rem-target-name').textContent = label;
        }
    }

    function targetTask(key, task) {
        const row = document.querySelector(`#rem-wizard [data-target="${key}"]`);
        if (!row || !task) return;
        const node = row.querySelector('.rem-target-task');
        node.textContent = task;
        node.classList.remove('rem-muted');
    }

    function startTicker() {
        stopTicker();
        state.startedAt = state.startedAt || Date.now();
        state.ticker = setInterval(() => {
            const node = document.querySelector('#rem-wizard [data-run-elapsed]');
            if (!node) return;
            const seconds = Math.floor((Date.now() - state.startedAt) / 1000);
            node.textContent = `${seconds}s`;
            // No server event for a while: say so rather than look frozen.
            if (state.lastBeat && Date.now() - state.lastBeat > 15000) {
                setStage('Still running… (waiting for the host)');
            }
        }, 1000);
    }

    function stopTicker() {
        if (state.ticker) clearInterval(state.ticker);
        state.ticker = null;
    }

    function streamRun(uuid) {
        if (state.source) state.source.close();
        const source = new EventSource(`/api/remediation-runs/${uuid}/stream`);
        state.source = source;
        state.lastBeat = Date.now();
        source.onmessage = (event) => {
            let payload = {};
            try { payload = JSON.parse(event.data); } catch (error) { return; }
            state.lastBeat = Date.now();
            const type = payload.type;
            if (type === 'heartbeat') {
                setStage(`Running… ${payload.elapsed}s elapsed`);
            } else if (type === 'stage') {
                setStage(payload.message || payload.stage || 'working');
                log(`· ${payload.message || payload.stage}`);
            } else if (type === 'target') {
                targetRow(payload.host_key, payload.label, payload.state);
                if (payload.state === 'connecting') {
                    targetTask(payload.host_key, 'connecting over SSH…');
                }
            } else if (type === 'verify') {
                targetRow(payload.host_key, '', payload.state);
                log(`· verify ${payload.host_key}: ${payload.detail || payload.state}`);
            } else if (type === 'task') {
                if (payload.task) {
                    targetTask(payload.host, payload.task + (payload.changed ? ' (changed)' : ''));
                    log(`${payload.host || ''} ${payload.task}${payload.changed ? '  [changed]' : ''}`);
                }
            } else if (type === 'log') {
                log(payload.message);
            } else if (type === 'error') {
                setStage('Failed');
                log(`ERROR: ${payload.message}`);
            } else if (type === 'result') {
                setRunState(payload.state);
                setStage(`Finished: ${payload.state}`);
                stopTicker();
                const spinner = document.querySelector('#rem-wizard [data-run-spinner]');
                if (spinner) spinner.classList.add('is-done');
                log(`Finished: ${payload.state} ${JSON.stringify(payload.summary || {})}`);
                const rollback = document.querySelector('#rem-wizard [data-run-rollback]');
                if (rollback && ['failed', 'applied_unverified'].includes(payload.state)) rollback.hidden = false;
                const cancel = document.querySelector('#rem-wizard [data-run-cancel]');
                if (cancel) cancel.hidden = true;
            } else if (type === 'done') {
                source.close();
                state.source = null;
                stopTicker();
                const spinner = document.querySelector('#rem-wizard [data-run-spinner]');
                if (spinner) spinner.classList.add('is-done');
                document.dispatchEvent(new CustomEvent('ailog:remediation-finished', { detail: { uuid } }));
            }
        };
        source.onerror = () => {
            // EventSource retries on its own; only stop when the stream is closed.
            if (source.readyState === EventSource.CLOSED) {
                source.close();
                state.source = null;
                stopTicker();
            }
        };
    }

    /* ------------------------------------------------------------ render */

    function render(policy) {
        const node = ensurePanel();
        const plan = state.plan;
        const body = state.step === 1 ? renderReview(plan)
            : state.step === 2 ? renderOptions(plan, policy || {})
                : state.step === 3 ? renderConfirm(plan)
                    : renderConsole(plan);
        node.innerHTML = `
          <div class="rem-panel rem-panel-wizard" role="document">
            <div class="rem-panel-head">
              <div>
                <div class="rem-panel-title">${esc(plan ? plan.title : 'Remediation')}</div>
                ${state.step < 3 ? stepsHtml() : ''}
              </div>
              <button type="button" class="rem-btn" data-wizard-close>Close</button>
            </div>
            ${body}
          </div>`;
        bindStep(policy);
    }

    function bindStep(policy) {
        const node = panel();
        if (!node) return;

        node.querySelectorAll('[data-wizard-close]').forEach((button) => {
            button.addEventListener('click', close);
        });

        node.querySelectorAll('[data-copy-block]').forEach((button) => {
            button.addEventListener('click', async () => {
                const pre = button.closest('details').querySelector('.rem-pre');
                try { await navigator.clipboard.writeText(pre.textContent); button.textContent = 'Copied'; } catch (error) { }
                setTimeout(() => { button.textContent = 'Copy'; }, 1200);
            });
        });

        const back = node.querySelector('[data-wizard-back]');
        if (back) back.addEventListener('click', () => { state.step = Math.max(1, state.step - 1); render(policy); });

        const next = node.querySelector('[data-wizard-next]');
        if (next) next.addEventListener('click', async () => {
            if (state.step === 1) { state.step = 2; render(policy); return; }
            // step 2 -> 3: options changed, so re-sign the plan first.
            state.step = 3;
            await replan(policy);
        });

        node.querySelectorAll('input[name="rem-mode"]').forEach((input) => {
            input.addEventListener('change', () => { state.dryRun = input.value === 'dry'; });
        });

        node.querySelectorAll('input[name="rem-when"]').forEach((input) => {
            input.addEventListener('change', () => {
                state.when = input.value;
                const box = node.querySelector('[data-schedule-box]');
                if (box) box.classList.toggle('hidden', state.when !== 'later');
                if (state.when === 'later') suggestSlot();
            });
        });

        const at = node.querySelector('#rem-run-at');
        if (at) at.addEventListener('change', () => { state.runAt = at.value; });

        const confirmInput = node.querySelector('[data-confirm-input]');
        const startBtn = node.querySelector('[data-wizard-start]');
        if (confirmInput && startBtn) {
            confirmInput.addEventListener('input', () => {
                startBtn.disabled = confirmInput.value.trim().toUpperCase() !== 'RUN';
            });
        }
        if (startBtn) startBtn.addEventListener('click', () => startRun(policy));

        const cancel = node.querySelector('[data-run-cancel]');
        if (cancel) cancel.addEventListener('click', async () => {
            try {
                const body = await api(`/api/remediation-runs/${state.uuid}/cancel`, { method: 'POST' });
                log(body.cancelled === 'scheduled' ? 'Scheduled run cancelled.' : 'Cancel requested.');
            } catch (error) { log(error.message); }
        });

        const rollback = node.querySelector('[data-run-rollback]');
        if (rollback) rollback.addEventListener('click', async () => {
            rollback.disabled = true;
            try {
                const body = await api(`/api/remediation-runs/${state.uuid}/rollback`, { method: 'POST' });
                log(`Rolled back: ${(body.hosts || []).join(', ') || 'nothing to do'}`);
            } catch (error) { log(error.message); }
        });
    }

    /* Suggest the next maintenance slot: tomorrow 02:00 local, or the window. */
    function suggestSlot() {
        const at = document.querySelector('#rem-wizard #rem-run-at');
        if (!at) return;
        if (!state.runAt) {
            const when = new Date();
            when.setDate(when.getDate() + 1);
            when.setHours(2, 0, 0, 0);
            const pad = (n) => String(n).padStart(2, '0');
            const local = `${when.getFullYear()}-${pad(when.getMonth() + 1)}-${pad(when.getDate())}T${pad(when.getHours())}:${pad(when.getMinutes())}`;
            state.runAt = local;
            at.value = local;
        }
        const hint = document.querySelector('#rem-wizard [data-window-hint]');
        if (hint && !hint.textContent) {
            hint.textContent = 'The run is queued now and starts at this time. Blocking maintenance windows are re-checked then.';
        }
    }

    async function replan(policy) {
        try {
            const plan = await api(`/api/remediations/${encodeURIComponent(state.slug)}/plan`, {
                method: 'POST',
                body: JSON.stringify({
                    scope: state.scope,
                    host_key: state.hostKey,
                    dry_run: state.dryRun,
                    match_id: state.matchId,
                }),
            });
            state.plan = plan;
            render(policy);
        } catch (error) {
            state.step = 2;
            render(policy);
            const node = panel();
            if (node) {
                const box = document.createElement('div');
                box.className = 'rem-empty rem-bad';
                box.textContent = error.message;
                node.querySelector('.rem-panel-body').appendChild(box);
            }
        }
    }

    async function startRun(policy) {
        const errorBox = document.querySelector('#rem-wizard [data-wizard-error]');
        if (errorBox) errorBox.classList.add('hidden');
        const payload = {
            token: state.plan.token,
            scope: state.plan.scope,
            host_key: state.hostKey,
            dry_run: state.dryRun,
            match_id: state.matchId,
        };
        if (state.when === 'later') {
            if (!state.runAt) {
                if (errorBox) { errorBox.textContent = 'Pick a start time.'; errorBox.classList.remove('hidden'); }
                return;
            }
            payload.run_at = state.runAt.length === 16 ? `${state.runAt}:00` : state.runAt;
        }
        try {
            const body = await api(`/api/remediations/${encodeURIComponent(state.slug)}/apply`, {
                method: 'POST',
                body: JSON.stringify(payload),
            });
            state.uuid = body.uuid;
            state.step = 4;
            state.startedAt = Date.now();
            render(policy);
            log(`Run ${body.uuid.slice(0, 8)} created (${body.state}).`);
            startTicker();
            streamRun(body.uuid);
        } catch (error) {
            if (errorBox) { errorBox.textContent = error.message; errorBox.classList.remove('hidden'); }
        }
    }

    /* -------------------------------------------------------------- open */

    W.open = async function open(options) {
        state.slug = options.slug;
        state.hostKey = options.hostKey || '';
        state.matchId = options.matchId || null;
        state.scope = options.scope || 'host';
        state.step = 1;
        state.dryRun = options.dryRun !== false;
        state.when = 'now';
        state.runAt = '';
        state.uuid = '';
        state.startedAt = 0;
        try {
            const [plan, settings] = await Promise.all([
                api(`/api/remediations/${encodeURIComponent(state.slug)}/plan`, {
                    method: 'POST',
                    body: JSON.stringify({
                        scope: state.scope, host_key: state.hostKey,
                        dry_run: state.dryRun, match_id: state.matchId,
                    }),
                }),
                api('/api/remediation/settings'),
            ]);
            state.plan = plan;
            render(settings.policy || {});
        } catch (error) {
            const node = ensurePanel();
            node.innerHTML = `
              <div class="rem-panel" role="document">
                <div class="rem-panel-head">
                  <div class="rem-panel-title">Cannot plan this run</div>
                  <button type="button" class="rem-btn" data-wizard-close>Close</button>
                </div>
                <div class="rem-panel-body"><div class="rem-empty rem-bad">${esc(error.message)}</div></div>
              </div>`;
            node.querySelector('[data-wizard-close]').addEventListener('click', close);
        }
    };

    W.close = close;
    window.ailogRemediation = W;
})();
