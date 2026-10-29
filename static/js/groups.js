// Groups settings UI (moved verbatim from templates/index.html).
// Exports the two entry points used by the core settings panel.

// --- GROUPS SETTINGS ---
async function loadGroupsSettings() {
    const list = document.getElementById('groups-list');
    if (!list) return;
    list.innerHTML = '<div class="text-xs termix-muted">Loading groups...</div>';

    try {
        const groups = await window.fetchApi('/groups');
        if (!Array.isArray(groups) || !groups.length) {
            list.innerHTML = '<div class="text-xs termix-muted">No groups yet.</div>';
            return;
        }

        list.innerHTML = '';
        for (const g of groups) {
            const wrapper = document.createElement('div');
            wrapper.className = 'p-3 rounded-lg bg-white/5 border border-white/10';
            wrapper.innerHTML = `
                <div class="flex items-start justify-between gap-3">
                    <div class="min-w-0">
                        <div class="font-medium text-white truncate">${g.name}</div>
                        <div class="text-xs termix-muted mt-1">${(g.description || '').replace(/</g,'&lt;')}</div>
                        <div class="text-xs termix-muted mt-2" id="group-hosts-${g.id}">Loading hosts...</div>
                    </div>
                    <div class="flex items-center gap-2 shrink-0">
                        <button class="groups-edit-btn bg-white/10 hover:bg-white/20 text-white text-xs px-2 py-1 rounded" data-id="${g.id}" data-name="${g.name}" data-desc="${g.description || ''}">Edit</button>
                        <button class="groups-del-btn bg-red-600/80 hover:bg-red-600 text-white text-xs px-2 py-1 rounded" data-id="${g.id}">Delete</button>
                    </div>
                </div>
            `;
            list.appendChild(wrapper);

            // load hosts for the group
            try {
                const resp = await window.fetchApi(`/groups/${g.id}/hosts`);
                const hostLine = document.getElementById(`group-hosts-${g.id}`);
                const hosts = (resp && resp.hosts) ? resp.hosts : [];
                if (hostLine) {
                    hostLine.textContent = hosts.length ? `Hosts: ${hosts.map(h => h.friendly_name || h.hostname || h.ip_address).join(', ')}` : 'Hosts: (none)';
                }
            } catch (_) {
                const hostLine = document.getElementById(`group-hosts-${g.id}`);
                if (hostLine) hostLine.textContent = 'Hosts: (failed to load)';
            }
        }

        // wire up edit/delete
        list.querySelectorAll('.groups-del-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const id = btn.getAttribute('data-id');
                if (!confirm('Delete this group?')) return;
                try {
                    const res = await fetch(`/groups/${id}`, { method: 'DELETE' });
                    const data = await res.json();
                    if (!res.ok) throw new Error(data.error || 'Delete failed');
                    window.showToast('Group deleted', 'success');
                    loadGroupsSettings();
                } catch (e) {
                    window.showToast(e.message, 'error');
                }
            });
        });

        list.querySelectorAll('.groups-edit-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const id = btn.getAttribute('data-id');
                const curName = btn.getAttribute('data-name') || '';
                const curDesc = btn.getAttribute('data-desc') || '';
                const name = prompt('Group name:', curName);
                if (name === null) return;
                const desc = prompt('Description (optional):', curDesc);
                if (desc === null) return;
                try {
                    const res = await fetch(`/groups/${id}`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ name, description: desc })
                    });
                    const data = await res.json();
                    if (!res.ok) throw new Error(data.error || 'Update failed');
                    window.showToast('Group updated', 'success');
                    loadGroupsSettings();
                } catch (e) {
                    window.showToast(e.message, 'error');
                }
            });
        });

    } catch (e) {
        list.innerHTML = `<div class="text-xs text-red-400">Failed to load groups: ${e.message}</div>`;
    }
}

function wireGroupsSettingsUi() {
    const createBtn = document.getElementById('groups-create-btn');
    const refreshBtn = document.getElementById('groups-refresh-btn');
    const status = document.getElementById('groups-create-status');

    if (refreshBtn) refreshBtn.addEventListener('click', () => loadGroupsSettings());

    if (createBtn) createBtn.addEventListener('click', async () => {
        const nameEl = document.getElementById('groups-new-name');
        const descEl = document.getElementById('groups-new-desc');
        const name = (nameEl && nameEl.value || '').trim();
        const description = (descEl && descEl.value || '').trim();

        if (!name) {
            if (status) status.textContent = 'Name is required.';
            return;
        }

        if (status) status.textContent = 'Creating...';
        try {
            const res = await fetch('/groups', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, description })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Create failed');

            if (nameEl) nameEl.value = '';
            if (descEl) descEl.value = '';
            if (status) status.textContent = '';
            window.showToast('Group created', 'success');
            loadGroupsSettings();
        } catch (e) {
            if (status) status.textContent = e.message;
            window.showToast(e.message, 'error');
        }
    });
}

export { loadGroupsSettings, wireGroupsSettingsUi };
