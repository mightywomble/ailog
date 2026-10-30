/* Admin page: windows + protected hosts. Everything else is server-rendered. */

async function api(url, options) {
    const response = await fetch(url, Object.assign({ headers: { 'Content-Type': 'application/json' } }, options || {}));
    let body = {};
    try { body = await response.json(); } catch (error) { body = {}; }
    if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
    return body;
}

document.getElementById('window-form')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = Object.fromEntries(new FormData(form).entries());
    data.group_id = data.group_id ? Number(data.group_id) : null;
    try {
        await api('/api/remediation/windows', { method: 'POST', body: JSON.stringify(data) });
        window.location.reload();
    } catch (error) {
        window.alert(error.message);
    }
});

document.querySelectorAll('[data-delete-window]').forEach((button) => {
    button.addEventListener('click', async () => {
        if (!window.confirm('Delete this maintenance window?')) return;
        try {
            await api(`/api/remediation/windows/${button.dataset.deleteWindow}`, { method: 'DELETE' });
            window.location.reload();
        } catch (error) { window.alert(error.message); }
    });
});

document.querySelectorAll('[data-protect]').forEach((checkbox) => {
    checkbox.addEventListener('change', async () => {
        try {
            await api(`/api/remediation/hosts/db-${checkbox.dataset.protect}/protect`, {
                method: 'POST', body: JSON.stringify({ protected: checkbox.checked }),
            });
        } catch (error) {
            checkbox.checked = !checkbox.checked;
            window.alert(error.message);
        }
    });
});
/* ------------------------------------------------------------------ plan
 * A remedy can be planned from this page, not only from a report card.
 * The plan is reviewed first (playbook + verify + rollback), then applied
 * with the token the server signed for exactly this host set.
 */

const esc = (value) => String(value == null ? '' : value).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

const planPanel = document.getElementById('plan-panel');
let currentPlan = null;

function closePlan() {
    if (!planPanel) return;
    planPanel.classList.add('hidden');
    planPanel.innerHTML = '';
    currentPlan = null;
}

function block(label, text) {
    if (!text) return '';
    return `<details><summary class="rem-muted">${esc(label)}</summary><pre class="rem-pre">${esc(text)}</pre></details>`;
}

function renderPlan(plan, dryRun) {
    currentPlan = { plan, dryRun };
    planPanel.innerHTML = `
      <div class="rem-panel" role="document">
        <div class="rem-panel-head">
          <div>
            <div class="rem-panel-title">${esc(plan.title)}</div>
            <div class="rem-muted">
              <span class="rem-badge risk-${esc(plan.risk)}">${esc(plan.risk)} risk</span>
              <span class="rem-badge">${esc(plan.scope)}</span>
              <span class="rem-badge">${dryRun ? 'dry run' : 'will apply'}</span>
              <span class="rem-meta">${plan.eligible_keys.length} host(s), ${plan.waves.length} wave(s)</span>
            </div>
          </div>
          <button type="button" class="rem-btn" data-close-plan>Close</button>
        </div>
        <div class="rem-panel-body">
          <table class="rem-table">
            <thead><tr><th>Host</th><th>Eligible</th><th>Why</th></tr></thead>
            <tbody>
              ${plan.targets.map((t) => `<tr><td>${esc(t.label)}</td>
                 <td class="${t.eligible ? 'rem-ok' : 'rem-bad'}">${t.eligible ? 'yes' : 'no'}</td>
                 <td>${esc(t.why || '')}</td></tr>`).join('')}
            </tbody>
          </table>
          ${block('Playbook (what will run)', plan.code)}
          ${block('How it is verified afterwards', plan.verify)}
          ${block('Rollback', plan.rollback)}
          <div class="rem-actions">
            <label class="rem-inline"><input type="checkbox" id="plan-dry" ${dryRun ? 'checked' : ''}> dry run first</label>
            <button type="button" class="rem-btn primary" id="plan-apply">
              ${dryRun ? 'Apply (dry run)' : 'Apply'}
            </button>
          </div>
          <div id="plan-error" class="rem-empty rem-bad hidden"></div>
        </div>
      </div>`;
    planPanel.classList.remove('hidden');

    planPanel.querySelector('[data-close-plan]').addEventListener('click', closePlan);
    planPanel.querySelector('#plan-dry').addEventListener('change', (event) => {
        // Toggling changes the contract, so re-plan rather than reuse the token.
        const dry = event.currentTarget.checked;
        requestPlan(plan.slug, plan.eligible_keys[0], dry);
    });
    planPanel.querySelector('#plan-apply').addEventListener('click', applyPlan);
}

async function requestPlan(slug, hostKey, dryRun) {
    try {
        const plan = await api(`/api/remediations/${encodeURIComponent(slug)}/plan`, {
            method: 'POST',
            body: JSON.stringify({ scope: 'host', host_key: hostKey, dry_run: dryRun }),
        });
        plan.slug = plan.slug || slug;
        renderPlan(plan, dryRun);
    } catch (error) {
        closePlan();
        const box = document.getElementById('start-error');
        if (box) { box.textContent = error.message; box.classList.remove('hidden'); }
    }
}

async function applyPlan() {
    if (!currentPlan) return;
    const dryRun = planPanel.querySelector('#plan-dry').checked;
    const errorBox = planPanel.querySelector('#plan-error');
    errorBox.classList.add('hidden');
    try {
        const body = await api(`/api/remediations/${encodeURIComponent(currentPlan.plan.slug)}/apply`, {
            method: 'POST',
            body: JSON.stringify({
                scope: 'host',
                host_key: currentPlan.plan.eligible_keys[0],
                dry_run: dryRun,
                token: currentPlan.plan.token,
            }),
        });
        window.location.href = `/remediation/runs/${body.uuid}`;
    } catch (error) {
        errorBox.textContent = error.message;
        errorBox.classList.remove('hidden');
    }
}

document.getElementById('start-form')?.addEventListener('submit', (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const slug = form.querySelector('#start-slug').value;
    const hostKey = form.querySelector('#start-host').value;
    const dryRun = form.querySelector('#start-dry').checked;
    const box = document.getElementById('start-error');
    if (box) box.classList.add('hidden');
    requestPlan(slug, hostKey, dryRun);
});
