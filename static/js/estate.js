// The estate page: what wizard.yaml says each swarm service should run, and the
// one click that moves a service forward through the pipeline that ships it.
//
// Deliberately read-mostly. Nothing here writes to git; it asks the server for a
// plan (`?check=1` resolves the newest upstream tag or, for a build app, says
// what source a rebuild would compile), shows the steps, and only then starts a
// job whose progress it follows. The deploy itself belongs to CI - this page
// watches a run, it does not docker.

(function () {
    const el = (id) => document.getElementById(id);
    const esc = (value) => String(value == null ? '' : value)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');

    const state = {
        services: [],
        plans: {},          // name -> plan from ?check=1
        running: null,      // {name, jobId, timer}
    };

    const setStatus = (text) => {
        const node = el('estate-status');
        if (node) node.textContent = text || '';
    };

    const setRunState = (text, tone) => {
        const node = el('estate-run-state');
        if (!node) return;
        node.textContent = text || '';
        node.className = `text-xs ${tone === 'error' ? 'text-red-400' : tone === 'ok' ? 'text-emerald-300' : 'termix-muted'}`;
    };

    const setProgress = (pct) => {
        const wrap = el('estate-run-bar');
        const fill = el('estate-run-fill');
        if (!wrap || !fill) return;
        if (pct === null || pct === undefined) {
            wrap.hidden = true;
            return;
        }
        const value = Math.max(0, Math.min(100, Number(pct) || 0));
        wrap.hidden = false;
        wrap.setAttribute('aria-valuenow', String(Math.round(value)));
        fill.style.width = `${value}%`;
    };

    const renderSteps = (steps) => {
        const node = el('estate-run-steps');
        if (!node) return;
        node.innerHTML = (steps || []).map((step) => {
            const mark = step.ok === true ? '<span class="text-emerald-400">✓</span>'
                : step.ok === false ? '<span class="text-red-400">✗</span>'
                    : '<span class="text-amber-300">•</span>';
            const detail = step.detail ? ` <span class="termix-muted">${esc(step.detail)}</span>` : '';
            return `<div class="flex gap-2">${mark}<span>${esc(step.label)}</span>${detail}</div>`;
        }).join('');
    };

    const renderLog = (lines) => {
        const node = el('estate-run-log');
        if (!node) return;
        if (!lines || !lines.length) {
            node.hidden = true;
            return;
        }
        node.hidden = false;
        node.textContent = lines.slice(-200).join('\n');
        node.scrollTop = node.scrollHeight;
    };

    // ---------------------------------------------------------------- listing --

    const rowHtml = (row) => {
        const plan = state.plans[row.name] || null;
        const drift = row.drift ? `<span class="text-amber-300">${esc(row.drift)}</span>` : '<span class="termix-muted">in sync</span>';
        const target = plan
            ? (plan.up_to_date ? '<span class="text-emerald-300">newest</span>'
                : `<span class="text-amber-300">${esc(plan.target || '?')}</span>`)
            : '<span class="termix-muted">—</span>';
        let action = '<span class="termix-muted text-[11px]">n/a</span>';
        if (row.action === 'rebuild') {
            action = row.supported
                ? `<button type="button" class="text-[11px] px-2 py-1 rounded bg-amber-600/80 hover:bg-amber-500 text-black font-medium" data-estate-update="${esc(row.name)}">rebuild</button>`
                : '<span class="termix-muted text-[11px]">nothing to build</span>';
        } else if (row.kind === 'build' && row.release === 'manual') {
            action = '<span class="termix-muted text-[11px]">pinned by hand</span>';
        } else if (row.supported) {
            action = plan
                ? (plan.up_to_date
                    ? `<button type="button" class="text-[11px] px-2 py-1 rounded bg-white/10 hover:bg-white/20" data-estate-update="${esc(row.name)}">re-apply</button>`
                    : `<button type="button" class="text-[11px] px-2 py-1 rounded bg-amber-600/80 hover:bg-amber-500 text-black font-medium" data-estate-update="${esc(row.name)}">update</button>`)
                : `<button type="button" class="text-[11px] px-2 py-1 rounded bg-white/10 hover:bg-white/20" data-estate-check="${esc(row.name)}">check</button>`;
        }
        return `
            <tr class="row-hover border-b border-white/5" data-estate-row="${esc(row.name)}">
                <td class="py-2 px-3">
                    <div class="font-medium">${esc(row.name)}</div>
                    <div class="text-[11px] termix-muted font-mono">${esc(row.image || '')}</div>
                </td>
                <td class="py-2 px-3 text-[11px] termix-muted">${esc(row.kind)}${row.release ? ` · ${esc(row.release)}` : ''}</td>
                <td class="py-2 px-3 font-mono text-xs">${esc(row.version || '')}</td>
                <td class="py-2 px-3 text-[11px] termix-muted font-mono truncate" style="max-width:22rem">${esc(row.source || '')}</td>
                <td class="py-2 px-3 text-xs space-y-0.5"><div>${drift}</div><div>${target}</div></td>
                <td class="py-2 px-3 text-right">${action}</td>
            </tr>`;
    };

    const render = () => {
        const body = el('estate-rows');
        if (!body) return;
        if (!state.services.length) {
            body.innerHTML = '<tr><td colspan="6" class="px-3 py-4 text-xs termix-muted">The estate has no services (or no checkout yet).</td></tr>';
            return;
        }
        body.innerHTML = state.services.map(rowHtml).join('');

        const mirror = state.services.filter((r) => r.kind === 'mirror' || r.kind === 'image').length;
        const build = state.services.filter((r) => r.kind === 'build').length;
        const drift = state.services.filter((r) => r.drift).length;
        el('estate-count-services').textContent = String(state.services.length);
        el('estate-count-mirror').textContent = String(mirror);
        el('estate-count-build').textContent = String(build);
        el('estate-count-drift').textContent = String(drift);
        el('estate-count-drift').className = drift ? 'text-xl font-semibold text-amber-300' : 'text-xl font-semibold';
        focusFromLink();
    };

    // ?service=anchor - the dashboard's Docker updates card clicks through to the
    // row it named, instead of dropping the reader at the top of the list.
    let focused = false;
    const focusFromLink = () => {
        const wanted = new URLSearchParams(window.location.search).get('service');
        if (!wanted || focused) return;
        const row = document.querySelector(`[data-estate-row="${wanted.replace(/"/g, '')}"]`);
        if (!row) return;
        focused = true;
        row.scrollIntoView({ behavior: 'smooth', block: 'center' });
        row.classList.add('bg-amber-400/10', 'ring-2', 'ring-amber-400/60');
        setTimeout(() => row.classList.remove('bg-amber-400/10', 'ring-2', 'ring-amber-400/60'), 2600);
    };

    const load = async () => {
        setStatus('reading…');
        try {
            const res = await fetch('/api/estate/services', { headers: { Accept: 'application/json' } });
            const body = await res.json();
            if (!body.success) {
                el('estate-banner').textContent = body.error || 'the estate is not readable right now';
                setStatus('');
                return;
            }
            state.services = body.services || [];
            el('estate-head').textContent = body.head ? body.head.slice(0, 8) : '';
            el('estate-banner').textContent = body.services && body.services.length
                ? `Read from ${body.head ? body.head.slice(0, 8) : 'the checkout'} - ${body.services.length} services. Nothing here deploys directly: every change is a commit that CI turns into a deploy.`
                : 'Another checkout with no services in wizard.yaml.';
            setStatus('');
            render();
        } catch (err) {
            el('estate-banner').textContent = `Could not read the estate (${err}).`;
            setStatus('');
        }
    };

    const loadMode = async () => {
        try {
            const res = await fetch('/api/estate/status', { headers: { Accept: 'application/json' } });
            const body = await res.json();
            const mode = body.mode || 'off';
            const node = el('estate-mode');
            node.textContent = `mode: ${mode}`;
            node.className = `text-xs px-2 py-1 rounded-lg ${mode === 'on'
                ? 'bg-emerald-600/20 text-emerald-300 border border-emerald-500/30'
                : mode === 'plan' ? 'bg-amber-600/20 text-amber-300 border border-amber-500/30'
                    : 'bg-red-600/20 text-red-300 border border-red-500/30'}`;
            if (body.mode === 'off') {
                el('estate-banner').textContent = 'The estate pipeline is off on this server (AILOG_ALLOW_ESTATE=off): this page is read-only.';
            }
        } catch (err) {
            el('estate-mode').textContent = 'mode: unknown';
        }
    };

    const check = async (name) => {
        setStatus(`checking ${name}…`);
        try {
            const res = await fetch(`/api/estate/services/${encodeURIComponent(name)}?check=1`,
                { headers: { Accept: 'application/json' } });
            const body = await res.json();
            if (body.success && body.plan) {
                state.plans[name] = body.plan;
            } else {
                state.plans[name] = { error: body.error || 'could not plan', supported: false };
            }
        } catch (err) {
            state.plans[name] = { error: String(err), supported: false };
        }
        setStatus('');
        render();
    };

    const checkAll = async () => {
        const names = state.services.filter((r) => r.supported).map((r) => r.name);
        for (const [index, name] of names.entries()) {
            setStatus(`checking ${index + 1}/${names.length}: ${name}…`);
            await check(name);
        }
        setStatus('');
    };

    // ----------------------------------------------------------------- update --

    const openRun = async (name) => {
        const plan = state.plans[name] || null;
        el('estate-run').hidden = false;
        el('estate-run-title').textContent = `${name} - ${plan && plan.action === 'rebuild' ? 'rebuild from source' : 'update'}`;
        renderLog([]);
        setProgress(null);
        setRunState('');
        if (!plan) {
            await check(name);
        }
        const fresh = state.plans[name] || {};
        const isRebuild = (fresh.action === 'rebuild');
        el('estate-run-sub').innerHTML = isRebuild
            ? `rebuilds <span class="font-mono">${esc(fresh.upstream || name)}</span> through CI, then pins the build tag it produced`
            : `${esc(fresh.current || '?')} → <span class="text-amber-300 font-mono">${esc(fresh.target || '?')}</span>`;
        renderSteps((fresh.steps || []).map((label) => ({ label, ok: null, detail: '' })));
        const runBtn = el('estate-run-run');
        runBtn.hidden = false;
        runBtn.disabled = !fresh.supported;
        runBtn.textContent = fresh.mode === 'plan' ? 'Show the plan (dry run)' : (isRebuild ? 'Rebuild via CI' : 'Update via CI');
        if (!fresh.supported) setRunState(fresh.reason || 'this service cannot be updated from here', 'error');
        el('estate-run').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    };

    const stopPolling = () => {
        if (state.running && state.running.timer) clearTimeout(state.running.timer);
        if (state.running) state.running.timer = null;
    };

    const poll = async (jobId) => {
        if (!state.running || state.running.jobId !== jobId) return;
        let job = null;
        try {
            const res = await fetch(`/api/estate/jobs/${encodeURIComponent(jobId)}`, { headers: { Accept: 'application/json' } });
            job = (await res.json()).job || null;
        } catch (err) {
            state.running.timer = setTimeout(() => poll(jobId), 2000);
            return;
        }
        if (!job) {
            setRunState('the job has gone (it expires after an hour)', 'error');
            return;
        }
        renderSteps(job.steps || []);
        renderLog(job.output || []);
        setProgress(job.progress);
        if (job.status === 'running') {
            setRunState(job.label ? `${job.label}… ${Math.round(job.progress || 0)}%` : `${Math.round(job.progress || 0)}%`);
            state.running.timer = setTimeout(() => poll(jobId), 900);
            return;
        }
        if (job.status === 'error') {
            setRunState(job.error || 'the update failed', 'error');
            setProgress(job.progress);
        } else if (job.note === 'already newest') {
            setRunState('already newest - nothing to deploy', 'ok');
        } else {
            const result = job.result || {};
            const bits = [];
            if (result.target) bits.push(`now ${result.target}`);
            if (result.tag) bits.push(`built ${result.tag}`);
            if (result.pr) bits.push(`PR #${result.pr}`);
            setRunState(`done${bits.length ? ` - ${bits.join(', ')}` : ''}`, 'ok');
        }
        state.running = null;
        el('estate-run-run').hidden = true;
        state.plans = {};
        load();
    };

    const run = async () => {
        const title = el('estate-run-title').textContent || '';
        const name = title.split(' - ')[0];
        const plan = state.plans[name] || {};
        stopPolling();
        setRunState('starting…');
        el('estate-run-run').disabled = true;
        try {
            const res = await fetch('/api/estate/update', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, confirm: true, version: plan.action === 'rebuild' ? '' : (plan.target || '') }),
            });
            const body = await res.json();
            if (!body.success) {
                setRunState(body.error || 'the update was refused', 'error');
                el('estate-run-run').disabled = false;
                return;
            }
            const job = body.job || {};
            state.running = { name, jobId: job.id, timer: null };
            renderSteps(job.steps || []);
            setProgress(job.progress || 0);
            poll(job.id);
        } catch (err) {
            setRunState(String(err), 'error');
            el('estate-run-run').disabled = false;
        }
    };

    // ----------------------------------------------------------------- wiring --

    el('estate-refresh')?.addEventListener('click', () => { state.plans = {}; load(); loadMode(); });
    el('estate-check-all')?.addEventListener('click', checkAll);
    el('estate-run-run')?.addEventListener('click', run);
    el('estate-run-close')?.addEventListener('click', () => {
        stopPolling();
        el('estate-run').hidden = true;
    });

    document.getElementById('estate-rows')?.addEventListener('click', (event) => {
        const checkBtn = event.target.closest('[data-estate-check]');
        if (checkBtn) { check(checkBtn.dataset.estateCheck); return; }
        const updateBtn = event.target.closest('[data-estate-update]');
        if (updateBtn) openRun(updateBtn.dataset.estateUpdate);
    });

    loadMode();
    load();
})();
