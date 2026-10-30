/* Self-healing remediation cards for the report page.
   Catalog cards can be planned/applied; idea-channel cards are copy-only. */

const esc = (value) => String(value == null ? '' : value).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

const state = { reportId: 0, hostKey: '', policy: null, cards: [] };

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
            ${canApply && !dismissed ? `<button type="button" class="rem-btn primary" data-plan="${card.id}">Review &amp; fix…</button>` : ''}
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

/* Opening a card hands over to the shared wizard (remediation-wizard.js):
   review -> options (dry run? now or a maintenance slot?) -> confirm -> live
   console. This file must never run a playbook itself; it only picks the
   remedy and the host. */
function openWizard(card) {
    if (!window.ailogRemediation) {
        window.alert('The remediation wizard did not load. Reload the page.');
        return;
    }
    window.ailogRemediation.open({
        slug: card.slug,
        hostKey: state.hostKey,
        matchId: card.id,
        scope: 'host',
        title: card.title,
    });
}

document.addEventListener('ailog:remediation-finished', () => { load(); });

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
        if (target.matches('[data-refresh]')) {
            target.disabled = true;
            try { await api(`/api/reports/${state.reportId}/remediations/refresh`, { method: 'POST' }); } catch (error) { }
            target.disabled = false;
            await load();
            return;
        }
        const planId = target.getAttribute('data-plan');
        if (planId) {
            const card = state.cards.find((item) => String(item.id) === planId);
            if (!card) return;
            openWizard(card);
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
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { bind(); load(); });
} else {
    bind();
    load();
}

window.addEventListener('themechange', () => { });