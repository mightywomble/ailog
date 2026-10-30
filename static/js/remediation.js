/* Self-healing remediation cards for the report page.
   Catalog cards can be planned/applied; idea-channel cards are copy-only. */

const esc = (value) => String(value == null ? '' : value).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

const state = { reportId: 0, hostKey: '', policy: null, cards: [], plan: null, card: null, run: null, source: null };

function root() { return document.getElementById('report-remediations'); }

async function api(url, options) {
    const response = await fetch(url, Object.assign({ headers: { 'Content-Type': 'application/json' } }, options || {}));
    let body = {};
    try { body = await response.json(); } catch (error) { body = {}; }
    if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
    return body;
}

function riskBadge(risk) {
    const level = ['low', 'medium', 'high'].includes(risk) ? risk : 'high';
    return `<span class="rem-badge risk-${level}">${esc(risk || 'unknown')} risk</span>`;
}

function modeBadge() {
    const policy = state.policy || {};
    const mode = policy.mode || 'off';
    const label = mode === 'on' ? 'apply enabled' : mode === 'dry_run' ? 'dry run only' : 'apply disabled';
    return `<span class="rem-badge mode-${esc(mode)}">${esc(label)}</span>`;
}

function evidenceHtml(card) {
    const items = (card.evidence || []).filter(Boolean);
    if (!items.length) return '';
    return `<div class="rem-evidence">${items.map((hit) => (
        `<span class="rem-chip">${esc(hit.count)}x ${esc(hit.sig || hit.label || 'match')} · ${esc(hit.src || '?')}</span>`
    )).join('')}</div>`;
}

function listHtml(title, items) {
    if (!items || !items.length) return '';
    return `<div><div class="rem-block-label">${esc(title)}</div><ul class="rem-list">${items.map((item) => `<li>${esc(item)}</li>`).join('')}</ul></div>`;
}

function codeBlock(label, text, extraClass) {
    if (!text) return '';
    return `<details ${extraClass === 'open' ? 'open' : ''}><summary class="rem-muted">${esc(label)}</summary>` +
        `<div class="rem-code-head"><span class="rem-muted">${esc(label)}</span>` +
        `<button type="button" class="rem-btn" data-copy="${esc(label)}">Copy</button></div>` +
        `<pre class="rem-pre" data-copy-text>${esc(text)}</pre></details>`;
}

function cardHtml(card) {
    const idea = card.source === 'llm';
    const canApply = card.executable && !idea && state.policy && state.policy.enabled;
    const dismissed = card.state === 'dismissed';
    const reasons = ['false_positive', 'already_fixed', 'not_now', 'too_risky', 'other'];
    return `<article class="rem-card ${idea ? 'is-idea' : ''} ${dismissed ? 'is-dismissed' : ''}" data-card-id="${card.id}">
        <div class="rem-card-top">
            ${riskBadge(card.risk)}
            ${idea ? '<span class="rem-badge idea">Unverified suggestion</span>' : `<span class="rem-badge">${Math.round((card.confidence || 0) * 100)}% confidence</span>`}
            ${card.est_seconds ? `<span class="rem-meta">~${esc(card.est_seconds)}s</span>` : ''}
            <span class="rem-meta" style="margin-left:auto">${esc(card.source === 'llm' ? 'model' : 'catalog')}</span>
        </div>
        <h3 class="rem-title">${esc(card.title)}</h3>
        <p class="rem-muted">${esc(card.rationale || card.summary || '')}</p>
        ${evidenceHtml(card)}
        ${listHtml('What it does', card.changes)}
        ${listHtml('Will NOT do', card.does_not)}
        ${idea ? '<div class="rem-badge idea">Unverified suggestion — copy and run yourself</div>' : ''}
        ${codeBlock(idea ? 'Suggested commands' : 'Playbook (what will run)', card.code, 'open')}
        ${codeBlock('How to test', card.verify)}
        ${card.rollback ? codeBlock('Rollback', card.rollback) : ''}
        <div class="rem-actions">
            ${canApply && !dismissed ? `<label class="rem-confirm"><input type="checkbox" data-dry-run checked> dry run first</label>` : ''}
            ${canApply && !dismissed ? `<button type="button" class="rem-btn primary" data-apply="${card.id}">Yes, apply</button>` : ''}
            ${!dismissed ? `<select class="rem-select" data-reason="${card.id}" aria-label="Dismiss reason">${reasons.map((r) => `<option value="${r}">${esc(r.replace('_', ' '))}</option>`).join('')}</select>` : ''}
            ${!dismissed ? `<button type="button" class="rem-btn" data-dismiss="${card.id}">No, dismiss</button>` : `<span class="rem-badge">dismissed: ${esc(card.dismissed_reason || '')}</span>`}
        </div>
    </article>`;
}

function render() {
    const host = root();
    if (!host) return;
    const cards = state.cards || [];
    host.innerHTML = `
        <div class="rem-head">
            <h2>Self-healing</h2>
            ${modeBadge()}
            <span class="rem-sub">${cards.length} suggestion(s) from the catalog${state.policy && state.policy.idea_channel ? ' and the model' : ''}</span>
            <button type="button" class="rem-btn" data-refresh style="margin-left:auto">Re-match</button>
        </div>
        ${state.policy && !state.policy.enabled ? '<div class="rem-empty">Remediation is in read-only mode. Cards are visible (and copyable); applying requires <code>AILOG_ALLOW_REMEDIATION=dry_run</code> or <code>on</code>.</div>' : ''}
        ${cards.length ? `<div class="rem-grid">${cards.map(cardHtml).join('')}</div>` : `<div class="rem-empty">
            No catalog remedy matches this report's evidence.
            <div class="rem-empty-sub">
                That is normal when the findings are informational (sessions, accepted logins,
                routine container stats) rather than a fixable fault. A remedy appears only when a
                reviewed catalog entry's signature matches a cluster in this report.
            </div>
            <div class="rem-actions" style="margin-top:.6rem">
                <a class="rem-btn" href="/remediation">Browse the reviewed remedies</a>
                <button type="button" class="rem-btn" data-refresh>Re-match this report</button>
            </div>
        </div>`}
    `;
}

async function load() {
    const host = root();
    if (!host) return;
    state.reportId = Number(host.dataset.reportId || 0);
    state.hostKey = host.dataset.hostKey || '';
    try {
        const body = await api(`/api/reports/${state.reportId}/remediations`);
        state.cards = body.cards || [];
        state.policy = body.policy || {};
        state.hostKey = body.host_key || state.hostKey;
    } catch (error) {
        host.innerHTML = `<div class="rem-empty">Could not load remediation suggestions: ${esc(error.message)}</div>`;
        return;
    }
    render();
}

function modal(html) {
    let node = document.getElementById('rem-modal');
    if (node) node.remove();
    node = document.createElement('div');
    node.id = 'rem-modal';
    node.className = 'rem-modal';
    node.innerHTML = html;
    document.body.appendChild(node);
    return node;
}

function closeModal() {
    const node = document.getElementById('rem-modal');
    if (node) node.remove();
    if (state.source) { state.source.close(); state.source = null; }
}

async function openPlan(card, scope, dryRun) {
    try {
        const plan = await api(`/api/remediations/${encodeURIComponent(card.slug)}/plan`, {
            method: 'POST',
            body: JSON.stringify({ scope, host_key: state.hostKey, dry_run: dryRun, match_id: card.id }),
        });
        state.plan = plan;
        state.card = card;
        const eligible = plan.targets.filter((target) => target.eligible);
        const needsTyping = eligible.length > 1;
        const node = modal(`
            <div class="rem-panel" role="dialog" aria-modal="true">
                <div class="rem-panel-head">
                    <div class="rem-panel-title">${esc(plan.title)}</div>
                    <button type="button" class="rem-btn" data-close>Close</button>
                </div>
                <div class="rem-panel-body">
                    <div class="rem-card-top">${riskBadge(plan.risk)}<span class="rem-badge">${esc(scope)}</span><span class="rem-badge">${dryRun ? 'dry run' : 'will apply'}</span><span class="rem-meta">${eligible.length} host(s), ${plan.waves.length} wave(s)</span></div>
                    <table class="rem-table"><thead><tr><th>Host</th><th>Eligible</th><th>Why</th></tr></thead><tbody>
                    ${plan.targets.map((target) => `<tr><td>${esc(target.label)}</td><td class="${target.eligible ? 'rem-ok' : 'rem-bad'}">${target.eligible ? 'yes' : 'no'}</td><td>${esc(target.why || '')}</td></tr>`).join('')}
                    </tbody></table>
                    ${codeBlock('Playbook (what will run)', plan.code, 'open')}
                    ${codeBlock('How it is verified afterwards', plan.verify)}
                    ${needsTyping ? `<label class="rem-confirm">Type <strong>RUN</strong> to approve ${eligible.length} hosts: <input class="rem-input" data-confirm-input autocomplete="off"></label>` : '<div class="rem-muted">One host: click Apply to confirm.</div>'}
                </div>
                <div class="rem-panel-foot">
                    <span class="rem-muted" data-modal-error></span>
                    <button type="button" class="rem-btn" data-close>Cancel</button>
                    <button type="button" class="rem-btn primary" data-confirm ${needsTyping ? 'disabled' : ''}>Yes, ${dryRun ? 'check' : 'apply'}</button>
                </div>
            </div>`);
        const input = node.querySelector('[data-confirm-input]');
        const confirmBtn = node.querySelector('[data-confirm]');
        if (input) {
            input.addEventListener('input', () => {
                confirmBtn.disabled = input.value.trim().toUpperCase() !== 'RUN';
            });
        }
        confirmBtn.addEventListener('click', () => applyPlan());
    } catch (error) {
        modal(`<div class="rem-panel"><div class="rem-panel-head"><div class="rem-panel-title">Cannot plan this run</div><button type="button" class="rem-btn" data-close>Close</button></div><div class="rem-panel-body"><div class="rem-empty">${esc(error.message)}</div></div></div>`);
    }
}

async function applyPlan() {
    const plan = state.plan;
    if (!plan) return;
    const errorNode = document.querySelector('#rem-modal [data-modal-error]');
    try {
        const body = await api(`/api/remediations/${encodeURIComponent(plan.slug)}/apply`, {
            method: 'POST',
            body: JSON.stringify({ token: plan.token, scope: plan.scope, host_key: state.hostKey, dry_run: plan.dry_run, match_id: state.card && state.card.id }),
        });
        openRun(body.uuid);
    } catch (error) {
        if (errorNode) errorNode.textContent = error.message;
    }
}

function openRun(uuid) {
    state.run = uuid;
    const node = modal(`
        <div class="rem-panel" role="dialog" aria-modal="true">
            <div class="rem-panel-head">
                <div class="rem-panel-title">Remediation run</div>
                <span class="rem-badge" data-run-state>running</span>
            </div>
            <div class="rem-panel-body">
                <div class="rem-targets" data-run-targets></div>
                <div class="rem-log" data-run-log></div>
            </div>
            <div class="rem-panel-foot">
                <button type="button" class="rem-btn" data-cancel>Cancel run</button>
                <button type="button" class="rem-btn" data-rollback hidden>Rollback</button>
                <button type="button" class="rem-btn" data-close>Close</button>
            </div>
        </div>`);
    node.querySelector('[data-cancel]').addEventListener('click', async () => {
        try { await api(`/api/remediation-runs/${uuid}/cancel`, { method: 'POST' }); } catch (error) { }
    });
    node.querySelector('[data-rollback]').addEventListener('click', async () => {
        const button = node.querySelector('[data-rollback]');
        button.disabled = true;
        try {
            const body = await api(`/api/remediation-runs/${uuid}/rollback`, { method: 'POST' });
            log(`Rolled back: ${(body.hosts || []).join(', ') || 'nothing to do'}`);
        } catch (error) { log(error.message); }
    });
    streamRun(uuid);
}

function log(line) {
    const box = document.querySelector('#rem-modal [data-run-log]');
    if (!box) return;
    box.textContent += (box.textContent ? '\n' : '') + line;
    box.scrollTop = box.scrollHeight;
}

function targetRow(key, label, status) {
    const box = document.querySelector('#rem-modal [data-run-targets]');
    if (!box) return;
    let row = box.querySelector(`[data-target="${key}"]`);
    if (!row) {
        row = document.createElement('div');
        row.className = 'rem-target';
        row.dataset.target = key;
        row.innerHTML = `<span>${esc(label || key)}</span><span class="rem-muted"></span>`;
        box.appendChild(row);
    }
    const statusNode = row.lastElementChild;
    statusNode.textContent = status;
    statusNode.className = ['healed', 'checked'].includes(status) ? 'rem-ok' : ['failed', 'rollback_failed'].includes(status) ? 'rem-bad' : 'rem-muted';
}

function streamRun(uuid) {
    if (state.source) state.source.close();
    const source = new EventSource(`/api/remediation-runs/${uuid}/stream`);
    state.source = source;
    source.onmessage = (event) => {
        let payload = {};
        try { payload = JSON.parse(event.data); } catch (error) { return; }
        if (payload.type === 'task' && payload.task) { log(`${payload.host || ''} ${payload.task}${payload.changed ? ' (changed)' : ''}`); }
        else if (payload.type === 'target') { targetRow(payload.host_key, payload.label, payload.state); }
        else if (payload.type === 'verify') { targetRow(payload.host_key, '', payload.state); log(`verify ${payload.host_key}: ${payload.detail}`); }
        else if (payload.type === 'stage') { log(payload.message || payload.stage); }
        else if (payload.type === 'log') { log(payload.message); }
        else if (payload.type === 'error') { log(`ERROR: ${payload.message}`); }
        else if (payload.type === 'result') {
            const badge = document.querySelector('#rem-modal [data-run-state]');
            if (badge) badge.textContent = payload.state;
            log(`Finished: ${payload.state} ${JSON.stringify(payload.summary || {})}`);
            const rollback = document.querySelector('#rem-modal [data-rollback]');
            if (rollback && ['failed', 'applied_unverified'].includes(payload.state)) rollback.hidden = false;
        } else if (payload.type === 'done') {
            source.close();
            state.source = null;
            load();
        }
    };
    source.onerror = () => {
        source.close();
        state.source = null;
    };
}

async function dismiss(cardId, reason) {
    try {
        await api(`/api/remediation-matches/${cardId}/dismiss`, { method: 'POST', body: JSON.stringify({ reason }) });
        await load();
    } catch (error) {
        window.alert(error.message);
    }
}

function bind() {
    const host = root();
    if (!host) return;
    host.addEventListener('click', async (event) => {
        const target = event.target.closest('button, [data-close]');
        if (!target) return;
        if (target.matches('[data-close]')) { closeModal(); return; }
        if (target.matches('[data-refresh]')) {
            target.disabled = true;
            try { await api(`/api/reports/${state.reportId}/remediations/refresh`, { method: 'POST' }); } catch (error) { }
            target.disabled = false;
            await load();
            return;
        }
        const applyId = target.getAttribute('data-apply');
        if (applyId) {
            const card = state.cards.find((item) => String(item.id) === applyId);
            if (!card) return;
            const dryRun = host.querySelector(`[data-card-id="${applyId}"] [data-dry-run]`);
            await openPlan(card, 'host', dryRun ? dryRun.checked : true);
            return;
        }
        const dismissId = target.getAttribute('data-dismiss');
        if (dismissId) {
            const select = host.querySelector(`[data-reason="${dismissId}"]`);
            await dismiss(Number(dismissId), select ? select.value : 'other');
            return;
        }
        const copy = target.getAttribute('data-copy');
        if (copy) {
            const block = target.closest('details').querySelector('[data-copy-text]');
            try { await navigator.clipboard.writeText(block.textContent); target.textContent = 'Copied'; } catch (error) { }
            setTimeout(() => { target.textContent = 'Copy'; }, 1200);
        }
    });
    document.addEventListener('click', (event) => {
        const node = document.getElementById('rem-modal');
        if (node && event.target === node) closeModal();
    });
    document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closeModal(); });
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { bind(); load(); });
} else {
    bind();
    load();
}

window.addEventListener('themechange', () => { });