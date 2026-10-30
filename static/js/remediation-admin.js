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
 * The wizard (remediation-wizard.js) owns the whole conversation: review the
 * plan, choose dry run or apply, run now or in a maintenance slot, then watch
 * the run. This page only decides which remedy and which host.
 */

document.getElementById('start-form')?.addEventListener('submit', (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const slug = form.querySelector('#start-slug').value;
    const hostKey = form.querySelector('#start-host').value;
    const dryRun = form.querySelector('#start-dry').checked;
    const box = document.getElementById('start-error');
    if (box) box.classList.add('hidden');
    if (!window.ailogRemediation) {
        if (box) { box.textContent = 'The remediation wizard did not load. Reload the page.'; box.classList.remove('hidden'); }
        return;
    }
    window.ailogRemediation.open({ slug, hostKey, scope: 'host', dryRun });
});

/* The run detail page is the durable record; the wizard's console is the live
   view. Do not reload on finish: that would throw the console away mid-read. */
