// Stack updates: the swarm's unit is the stack, so that is what is listed and
// what is updated.
//
// A container list cannot answer the question a swarm asks. `metamcp` is two
// services; a deploy leaves the previous task's container behind on whichever
// node it ran, so a node-by-node list offers updates for images that are
// already current. This module lists *stacks* (from the manager, which is the
// only node that can see the cluster), shows the service's current version and
// the versions it could move to, and then follows the pipeline as milestones:
// read the cluster → resolve → pull into zot → verify → pin → PR → checks →
// merge → deploy → verify running → prune.
//
// The dialog is its own overlay because both the host pane and the full docker
// page want it, and neither should have to own a modal template to get it.

(function () {
    const el = (id) => document.getElementById(id);
    const esc = (value) => String(value == null ? '' : value)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');

    const stackRows = async (hostKey, options) => {
        const res = await fetch(`/api/docker/hosts/${encodeURIComponent(hostKey)}/swarm/stacks`
            + (options && options.refresh ? '?refresh=1' : ''),
        { headers: { Accept: 'application/json' } });
        const body = await res.json();
        if (!res.ok || !body.success) throw new Error(body.error || `HTTP ${res.status}`);
        return body;
    };

    const serviceLine = (row) => {
        const behind = row.update_available
            ? '<span class="text-amber-300">update available</span>'
            : '<span class="text-emerald-300">current</span>';
        return `${esc(row.short)} <span class="font-mono">${esc(row.tag)}</span> `
            + `<span class="termix-muted">${esc(row.replicas)}</span> ${behind}`;
    };

    // ---------------------------------------------------------------- listing --

    window.renderSwarmUpdates = async function (mount, hostKey, options) {
        if (!mount) return;
        const opts = options || {};
        mount.innerHTML = '<div class="text-xs termix-muted py-2">Reading the cluster…</div>';
        let data;
        try {
            data = await stackRows(hostKey, opts);
        } catch (err) {
            mount.innerHTML = `<div class="text-xs text-red-400">Could not read the cluster (${esc(err.message)}).</div>`;
            return;
        }
        if (!data.manager) {
            mount.innerHTML = `<div class="text-xs termix-muted py-2">${esc(data.note
                || 'This node is not a swarm manager: updates are handled on the manager.')}</div>`;
            return;
        }
        const stacks = (data.stacks || []).filter((s) => opts.all || s.updates);
        const head = `<div class="flex items-center justify-between gap-2 text-xs termix-muted mb-2">
                <span>${data.updates} service${data.updates === 1 ? '' : 's'} behind on ${data.services} services</span>
                <span class="flex items-center gap-2">
                    <button type="button" data-swarm-prune class="px-2 py-1 rounded bg-white/10 hover:bg-white/20">prune zot</button>
                    <button type="button" data-swarm-recheck class="px-2 py-1 rounded bg-white/10 hover:bg-white/20">re-check</button>
                </span>
            </div>`;
        if (!stacks.length) {
            mount.innerHTML = head + `<div class="text-xs text-emerald-300 py-2">Every stack is on the version the registry serves.</div>`;
        } else {
            mount.innerHTML = head + stacks.map((stack) => `
                <div class="rounded-lg border border-white/10 bg-white/5 p-2 mb-2">
                    <div class="flex items-center justify-between gap-2">
                        <div class="text-sm termix-text font-medium">${esc(stack.name)}</div>
                        <span class="text-[11px] ${stack.updates ? 'text-amber-300' : 'termix-muted'}">
                            ${stack.updates ? `${stack.updates} to update` : 'current'}
                        </span>
                    </div>
                    <div class="mt-1 space-y-0.5">
                        ${stack.services.map((row) => `
                            <div class="flex items-center justify-between gap-2 text-xs">
                                <span class="truncate">${serviceLine(row)}</span>
                                ${row.update_available
                                    ? `<button type="button" class="text-[11px] px-2 py-0.5 rounded bg-amber-600/80 hover:bg-amber-500 text-black font-medium"
                                        data-swarm-service="${esc(row.short)}" data-swarm-stack="${esc(stack.name)}">update</button>`
                                    : '<span class="text-[11px] termix-muted">—</span>'}
                            </div>`).join('')}
                    </div>
                </div>`).join('');
        }
        mount.querySelectorAll('[data-swarm-service]').forEach((button) => {
            button.addEventListener('click', () => window.openSwarmUpdate(
                hostKey, button.dataset.swarmStack, button.dataset.swarmService));
        });
        mount.querySelectorAll('[data-swarm-recheck]').forEach((button) => {
            button.addEventListener('click', () => window.renderSwarmUpdates(mount, hostKey, { refresh: true, all: opts.all }));
        });
        mount.querySelectorAll('[data-swarm-prune]').forEach((button) => {
            button.addEventListener('click', () => openPrune(mount, hostKey, opts));
        });
    };

    // ------------------------------------------------------------------ prune --

    const openPrune = async (mount, hostKey, opts) => {
        showModal('Prune zot', 'older images nothing uses', `
            <div class="text-xs termix-muted">Reading the registry…</div>`);
        let data;
        try {
            const res = await fetch('/api/docker/registry/images', { headers: { Accept: 'application/json' } });
            data = await res.json();
            if (!res.ok || !data.success) throw new Error(data.error || `HTTP ${res.status}`);
        } catch (err) {
            body().innerHTML = `<div class="text-xs text-red-400">${esc(err.message)}</div>`;
            return;
        }
        const repos = (data.repos || []).filter((r) => r.deletable);
        body().innerHTML = `
            <div class="text-xs termix-muted mb-2">
                Keeps the newest ${data.keep} of every repository plus anything running or pinned in git.
                ${data.deletable} tag${data.deletable === 1 ? '' : 's'} can go.
            </div>
            <div class="max-h-64 overflow-auto space-y-1">
                ${repos.map((r) => `<div class="text-xs">
                    <span class="font-mono termix-text">${esc(r.repo)}</span>
                    <span class="termix-muted">${esc((r.delete || []).join(', '))}</span>
                </div>`).join('') || '<div class="text-xs text-emerald-300">Nothing to delete.</div>'}
            </div>
            <div class="mt-3 flex justify-end gap-2">
                <button type="button" data-close class="px-3 py-1.5 rounded bg-white/10 hover:bg-white/20 text-xs">close</button>
                <button type="button" data-prune class="px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 text-white text-xs font-medium"
                    ${data.deletable ? '' : 'disabled'}>Delete ${data.deletable} tag(s)</button>
            </div>`;
        body().querySelector('[data-close]').addEventListener('click', hideModal);
        body().querySelector('[data-prune]').addEventListener('click', async (event) => {
            event.target.disabled = true;
            event.target.textContent = 'deleting…';
            try {
                const res = await fetch('/api/docker/registry/prune', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ confirm: true }),
                });
                const out = await res.json();
                if (!res.ok || !out.success) throw new Error(out.error || `HTTP ${res.status}`);
                event.target.textContent = `${(out.deleted || []).length} deleted`;
                if (mount) window.renderSwarmUpdates(mount, hostKey, opts);
            } catch (err) {
                event.target.disabled = false;
                event.target.textContent = 'failed - see console';
                console.error(err);
            }
        });
    };

    // ------------------------------------------------------------------ modal --

    const body = () => el('swarmUpdateBody');
    const state = { timer: null, jobId: null, hostKey: '', stack: '', service: '' };

    const showModal = (title, sub, html) => {
        const wrap = el('swarmUpdateModal');
        if (!wrap) return;
        wrap.hidden = false;
        el('swarmUpdateTitle').textContent = title;
        el('swarmUpdateSub').textContent = sub || '';
        body().innerHTML = html;
        el('swarmUpdateBar').hidden = true;
    };
    const hideModal = () => {
        if (state.timer) clearTimeout(state.timer);
        state.timer = null;
        const wrap = el('swarmUpdateModal');
        if (wrap) wrap.hidden = true;
    };
    window.closeSwarmUpdate = hideModal;

    const setProgress = (pct) => {
        const wrap = el('swarmUpdateBar');
        const fill = el('swarmUpdateFill');
        if (!wrap || !fill) return;
        if (pct === null || pct === undefined) { wrap.hidden = true; return; }
        wrap.hidden = false;
        wrap.setAttribute('aria-valuenow', String(Math.round(pct)));
        fill.style.width = `${Math.max(0, Math.min(100, Number(pct) || 0))}%`;
    };

    const renderJob = (job) => {
        const steps = el('swarmUpdateSteps');
        const log = el('swarmUpdateLog');
        if (steps) {
            steps.innerHTML = (job.steps || []).map((step) => {
                const mark = step.ok === true ? '✓' : step.ok === false ? '✕' : '•';
                const tone = step.ok === true ? 'text-emerald-300'
                    : step.ok === false ? 'text-red-400' : 'termix-muted';
                return `<div class="text-xs ${tone} flex gap-2 items-start">
                    <span class="shrink-0">${mark}</span>
                    <div class="min-w-0"><span>${esc(step.label)}</span>
                    ${step.detail ? `<span class="ml-1 termix-muted font-mono text-[11px] break-words">${esc(step.detail)}</span>` : ''}
                    </div></div>`;
            }).join('');
        }
        if (log) {
            const text = (job.output || []).slice(-40).join('\n');
            log.hidden = !text;
            log.textContent = text;
            log.scrollTop = log.scrollHeight;
        }
        setProgress(job.status === 'running' ? job.progress : (job.status === 'done' ? 100 : null));
    };

    const poll = async () => {
        try {
            const res = await fetch(`/api/docker/update/jobs/${encodeURIComponent(state.jobId)}`,
                { headers: { Accept: 'application/json' } });
            const data = await res.json();
            if (!res.ok || !data.success) throw new Error(data.error || `HTTP ${res.status}`);
            renderJob(data.job);
            if (data.job.status === 'running') {
                state.timer = setTimeout(poll, 1000);
                return;
            }
            const state_ = el('swarmUpdateState');
            if (state_) {
                state_.textContent = data.job.status === 'done'
                    ? 'done — the new version is running'
                    : (data.job.error || 'the update failed');
                state_.className = `text-xs ${data.job.status === 'done' ? 'text-emerald-300' : 'text-red-400 whitespace-pre-wrap break-words'}`;
            }
            document.dispatchEvent(new CustomEvent('ailog:swarm-updated',
                { detail: { hostKey: state.hostKey, stack: state.stack, service: state.service } }));
        } catch (err) {
            const node = el('swarmUpdateState');
            if (node) node.textContent = `lost track of the job: ${err.message}`;
        }
    };

    window.openSwarmUpdate = async function (hostKey, stack, service) {
        state.hostKey = hostKey;
        state.stack = stack;
        state.service = service;
        state.jobId = null;
        showModal(`${stack} / ${service}`, 'choosing a version',
            '<div class="text-xs termix-muted">Reading what this service is on, and what it could be…</div>');
        let plan;
        try {
            const res = await fetch(`/api/docker/hosts/${encodeURIComponent(hostKey)}/swarm/stacks/`
                + `${encodeURIComponent(stack)}/services/${encodeURIComponent(service)}/versions`,
            { headers: { Accept: 'application/json' } });
            plan = await res.json();
            if (!res.ok || !plan.success) throw new Error(plan.error || `HTTP ${res.status}`);
        } catch (err) {
            body().innerHTML = `<div class="text-xs text-red-400">${esc(err.message)}</div>`;
            return;
        }
        const current = plan.current || {};
        const candidates = plan.candidates || [];
        const option = (row) => {
            const notes = [];
            if (row.current) notes.push('running now');
            if (row.in_zot) notes.push('in zot');
            else notes.push('will be mirrored into zot');
            if (row.kind === 'build') notes.push('build tag');
            if (row.blocked) notes.push(row.blocked);
            return `<option value="${esc(row.tag)}" ${row.blocked ? 'disabled' : ''}>
                ${esc(row.tag)} — ${esc(notes.join(', '))}</option>`;
        };
        const usable = candidates.filter((c) => !c.blocked && !c.current);
        body().innerHTML = `
            <div class="text-xs mb-2">
                <span class="termix-muted">now:</span>
                <span class="font-mono termix-text">${esc(current.tag)}</span>
                <span class="termix-muted font-mono text-[11px]">${esc((current.digest || '').slice(0, 19))} · ${esc(current.replicas)}</span>
                ${current.behind ? '<span class="text-amber-300 ml-1">registry serves something else for this tag</span>' : ''}
            </div>
            ${(plan.warnings || []).map((w) => `<div class="text-[11px] text-amber-300 mb-1">${esc(w)}</div>`).join('')}
            <label class="block text-xs termix-muted mt-2 mb-1">Upgrade to</label>
            <select id="swarmUpdateVersion" class="w-full text-xs bg-black/20 border border-white/10 rounded-lg px-2 py-1.5 termix-text">
                ${current.behind ? `<option value="${esc(current.tag)}">${esc(current.tag)} — re-pull the newer digest</option>` : ''}
                ${usable.map(option).join('')}
            </select>
            ${usable.length || current.behind ? '' : '<div class="text-xs text-amber-300 mt-2">Nothing newer is available to move to.</div>'}
            <div id="swarmUpdateState" class="text-xs termix-muted mt-2">${esc(usable.length || current.behind ? 'ready' : '')}</div>
            <div id="swarmUpdateSteps" class="mt-3 space-y-0.5"></div>
            <pre id="swarmUpdateLog" hidden class="text-[11px] font-mono whitespace-pre-wrap break-words max-h-40 overflow-auto mt-2 p-2 rounded bg-black/40 border border-white/10 termix-text"></pre>
            <div class="mt-3 flex items-center justify-end gap-2">
                <button type="button" data-close class="px-3 py-1.5 rounded bg-white/10 hover:bg-white/20 text-xs">cancel</button>
                <button type="button" data-go class="px-3 py-1.5 rounded bg-amber-600 hover:bg-amber-500 text-black text-xs font-medium"
                    ${usable.length || current.behind ? '' : 'disabled'}>Update via CI</button>
            </div>`;
        body().querySelector('[data-close]').addEventListener('click', hideModal);
        body().querySelector('[data-go]').addEventListener('click', async (event) => {
            const select = el('swarmUpdateVersion');
            const version = select ? select.value : '';
            event.target.disabled = true;
            event.target.textContent = 'starting…';
            try {
                const res = await fetch(`/api/docker/hosts/${encodeURIComponent(hostKey)}/swarm/stacks/`
                    + `${encodeURIComponent(stack)}/services/${encodeURIComponent(service)}/update`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ version, confirm: true, prune: true }),
                });
                const out = await res.json();
                if (!res.ok || !out.success) throw new Error(out.error || `HTTP ${res.status}`);
                state.jobId = out.job.id;
                event.target.textContent = 'running…';
                poll();
            } catch (err) {
                event.target.disabled = false;
                event.target.textContent = 'Update via CI';
                const node = el('swarmUpdateState');
                if (node) {
                    node.textContent = err.message;
                    node.className = 'text-xs text-red-400 whitespace-pre-wrap break-words';
                }
            }
        });
    };
})();
