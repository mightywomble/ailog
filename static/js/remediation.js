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
    // The primary block stays open with one label and a Copy button; the
    // secondary ones collapse behind their own label.
    if (extraClass === 'open') {
        return `<div class="rem-blockdoc">` +
            `<div class="rem-code-head"><span class="rem-block-label">${esc(label)}</span>` +
            `<button type="button" class="rem-btn" data-copy="${esc(label)}">Copy</button></div>` +
            `<pre class="rem-pre" data-copy-text>${esc(text)}</pre></div>`;
    }
    return `<details class="rem-blockdoc"><summary class="rem-muted">${esc(label)}</summary>` +
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
            ${idea ? '<span class="rem-badge idea">AI suggestion · untested</span>' : `<span class="rem-badge">${Math.round((card.confidence || 0) * 100)}% confidence</span>`}
            ${card.est_seconds ? `<span class="rem-meta">~${esc(card.est_seconds)}s</span>` : ''}
            <span class="rem-meta" style="margin-left:auto">${esc(card.source === 'llm' ? 'model' : 'catalog')}</span>
        </div>
        <h3 class="rem-title">${esc(card.title)}</h3>
        <p class="rem-muted">${esc(card.rationale || card.summary || '')}</p>
        ${evidenceHtml(card)}
        ${listHtml('What it does', card.changes)}
        ${listHtml('Will NOT do', card.does_not)}
        ${idea ? `<div class="rem-badge idea">Untested AI playbook — test with --check, then run it yourself</div>` : ''}
        ${codeBlock(idea ? 'Ansible playbook (AI-generated, untested)' : 'Playbook (what will run)', card.code, 'open')}
        ${codeBlock('How to test', card.verify)}
        ${card.rollback ? codeBlock('Rollback', card.rollback) : ''}
        ${idea ? `<pre class="rem-pre hidden" data-test-output="${card.id}"></pre>` : ''}
        <div class="rem-actions">
            ${canApply && !dismissed ? `<button type="button" class="rem-btn primary" data-plan="${card.id}">Review &amp; fix…</button>` : ''}
            ${idea && !dismissed ? `<button type="button" class="rem-btn" data-test="${card.id}">Test with --check</button>` : ''}
            ${idea && !dismissed ? `<button type="button" class="rem-btn" data-worked="${card.id}">I ran it — it worked</button>` : ''}
            ${idea && !dismissed ? `<button type="button" class="rem-btn" data-failed="${card.id}">Tried — didn't work</button>` : ''}
            ${!idea && !dismissed ? `<select class="rem-select" data-reason="${card.id}" aria-label="Dismiss reason">${reasons.map((r) => `<option value="${r}">${esc(r.replace('_', ' '))}</option>`).join('')}</select>` : ''}
            ${!idea && !dismissed ? `<button type="button" class="rem-btn" data-dismiss="${card.id}">No, dismiss</button>` : ''}
            ${!idea && dismissed ? `<span class="rem-badge">dismissed: ${esc(card.dismissed_reason || '')}</span>` : ''}
            ${idea && card.state === 'confirmed' ? '<span class="rem-badge">added to your library</span>' : ''}
            ${idea && card.state === 'rejected' ? '<span class="rem-badge">marked as not working</span>' : ''}
        </div>
    </article>`;
}

/* Say where the cards came from, and only claim what is actually there. */
function summaryLabel(cards) {
    const ideas = cards.filter((card) => card.source === 'llm').length;
    const catalog = cards.length - ideas;
    const parts = [];
    if (catalog) parts.push(`${catalog} from the reviewed catalog`);
    if (ideas) parts.push(`${ideas} untested AI playbook${ideas === 1 ? '' : 's'}`);
    if (!parts.length) return 'nothing to fix in this report';
    return parts.join(' \u00b7 ');
}

/* Catalog remedies are the executable ones, so they get the page width. Model
   suggestions are unverified and never executed: they sit in a column beside
   them, visibly dashed and labelled, and only when there are any. */
function cardsHtml() {
    const ideas = state.cards.filter((card) => card.source === 'llm');
    const catalog = state.cards.filter((card) => card.source !== 'llm');
    if (!ideas.length) return `<div class="rem-layout"><div class="rem-col">${catalog.map(cardHtml).join('')}</div></div>`;
    if (!catalog.length) return `<div class="rem-layout"><div class="rem-col is-ideas">${ideas.map(cardHtml).join('')}</div></div>`;
    return `<div class="rem-layout has-ideas">
        <div class="rem-col">${catalog.map(cardHtml).join('')}</div>
        <div class="rem-col is-ideas">
            <div class="rem-col-head">
                Unverified suggestions
                <span>from the model &mdash; copy and run yourself</span>
            </div>
            ${ideas.map(cardHtml).join('')}
        </div>
    </div>`;
}

function render() {
    const host = root();
    if (!host) return;
    const cards = state.cards || [];
    host.innerHTML = `
        <div class="rem-head">
            <h2>Self-healing</h2>
            ${modeBadge()}
            <span class="rem-sub">${summaryLabel(cards)}</span>
            <button type="button" class="rem-btn" data-refresh style="margin-left:auto">Re-match</button>
        </div>
        ${state.policy && !state.policy.enabled ? '<div class="rem-empty">Remediation is in read-only mode. Cards are visible (and copyable); applying requires <code>AILOG_ALLOW_REMEDIATION=dry_run</code> or <code>on</code>.</div>' : ''}
        ${cards.length ? cardsHtml() : `<div class="rem-empty">
            No catalog remedy matches this report's evidence.
            <div class="rem-empty-sub">
                That is normal when the findings are informational (sessions, accepted logins,
                routine container stats) rather than a fixable fault. A remedy appears only when a
                reviewed catalog entry's signature matches a cluster in this report.
            </div>
            <div class="rem-actions" style="margin-top:.6rem">
                <button type="button" class="rem-btn primary" data-ideas>Ask AI for a suggested fix&hellip;</button>
                <a class="rem-btn" href="/remediation">Browse the reviewed remedies</a>
                <button type="button" class="rem-btn" data-refresh>Re-match this report</button>
            </div>
            <div class="rem-empty-sub">
                The AI writes an Ansible playbook, clearly marked untested. You test it with
                <code>--check</code> (nothing is applied), run it yourself if it looks right, and
                tell the app whether it worked &mdash; confirmed fixes are added to your library.
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
        if (target.matches('[data-ideas]')) {
            target.disabled = true;
            target.textContent = 'Asking the model…';
            try {
                const body = await api(`/api/reports/${state.reportId}/ideas`, { method: 'POST' });
                if (body.already) window.alert('This report already has AI suggestions.');
                else if (!body.ideas) window.alert(body.suppressed
                    ? `The model was not asked: ${body.suppressed}.`
                    : 'The model did not propose anything safe to run for this report.');
                await load();
            } catch (error) {
                window.alert(error.message);
                target.disabled = false;
                target.textContent = 'Ask AI for a suggested fix…';
            }
            return;
        }

        const testId = target.getAttribute('data-test');
        if (testId) {
            const output = host.querySelector(`[data-test-output="${testId}"]`);
            target.disabled = true;
            const original = target.textContent;
            target.textContent = 'Checking…';
            try {
                const body = await api(`/api/remediation-matches/${testId}/test`, { method: 'POST' });
                if (output) {
                    output.textContent = (body.ok ? 'CHECK PASSED (rc=0)' : `CHECK FAILED (rc=${body.rc})`)
                        + ` — ${body.changed || 0} change(s) would be made\n\n` + (body.output || '(no output)');
                    output.classList.remove('hidden');
                }
                window.alert(body.ok
                    ? 'Check mode passed: the playbook parses and would run. Now run it yourself, then confirm.'
                    : 'Check mode reported a problem. Read the output; do not run this yet.');
            } catch (error) {
                window.alert(error.message);
            } finally {
                target.disabled = false;
                target.textContent = original;
            }
            return;
        }

        const workedId = target.getAttribute('data-worked');
        if (workedId) {
            if (!window.confirm('Add this playbook to your library as a remedy that works?')) return;
            try {
                await api(`/api/remediation-matches/${workedId}/confirm`,
                    { method: 'POST', body: JSON.stringify({ worked: true }) });
                await load();
            } catch (error) { window.alert(error.message); }
            return;
        }

        const failedId = target.getAttribute('data-failed');
        if (failedId) {
            try {
                await api(`/api/remediation-matches/${failedId}/confirm`,
                    { method: 'POST', body: JSON.stringify({ worked: false }) });
                await load();
            } catch (error) { window.alert(error.message); }
            return;
        }

        const copy = target.getAttribute('data-copy');
        if (copy) {
            const block = target.closest('.rem-blockdoc')?.querySelector('[data-copy-text]');
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