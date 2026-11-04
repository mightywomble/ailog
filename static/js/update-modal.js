// Updating one container, in place.
//
// The Container-updates pane used to hand a row to the homelab wizard and hope.
// The wizard's update path is a wizard.yaml tag bump, which a CasaOS compose
// project is not in, so the user landed on the add-a-service journey and had to
// find their own container in a list. This dialog asks the server how *this*
// container gets its image (POST-free plan: compose service / swarm service),
// shows the exact commands, and then runs them with live output.
//
// Scope is visible in the dialog, not just implied: the target line names the
// compose service and project (or the swarm service) that will be touched.

(function () {
    const el = (id) => document.getElementById(id);
    const esc = (value) => (window.escapeHtml || String)(value == null ? '' : value);

    const state = {
        hostKey: null,
        image: '',
        container: '',
        label: '',
        plan: null,
        job: null,
        timer: null,
    };

    const KIND_LABEL = {
        compose: 'compose project',
        swarm: 'swarm service',
        estate: 'swarm · via CI',
        container: 'standalone container',
    };

    const stopPolling = () => {
        if (state.timer) {
            clearTimeout(state.timer);
            state.timer = null;
        }
    };

    // The bar only appears once a job is running: a plan is instant, an update
    // is not, and a bar that fills on the plan would be a lie about progress.
    const setProgress = (pct) => {
        const wrap = el('updateModalBar');
        const fill = el('updateModalFill');
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

    const setState = (text, tone) => {
        const node = el('updateModalState');
        if (!node) return;
        node.textContent = text || '';
        node.className = `text-xs ${tone === 'error' ? 'text-red-400' : tone === 'ok' ? 'text-emerald-300' : 'termix-muted'}`;
    };

    const renderTarget = (target) => {
        const kind = KIND_LABEL[target.kind] || target.kind;
        const estate = target.estate || null;
        const where = target.kind === 'compose'
            ? `project ${target.project || '?'}${target.file ? ` · ${target.file}` : ''}`
            : (target.kind === 'estate'
                ? `wizard.yaml · ${estate && estate.kind ? estate.kind : 'service'}${estate && estate.upstream ? ` · ${estate.upstream}` : ''}`
                : (target.kind === 'swarm' ? `runs on ${target.runs_on || '?'}` : ''));
        const commands = (target.commands || []).map((c) => `$ ${esc(c)}`).join('\n');
        // The estate path is a pipeline, not a command: show the steps it will
        // take, and the version it is moving to.
        const estateSteps = target.kind === 'estate' && estate
            ? `<div class="text-xs termix-text mt-2">${esc(estate.current || '?')} → <span class="text-amber-300 font-mono">${esc(estate.target || '?')}</span></div>
               <ol class="text-[11px] termix-muted mt-1 ml-4 list-decimal space-y-0.5">${(estate.steps || []).map((step) => `<li>${esc(step)}</li>`).join('')}</ol>`
            : `<pre class="text-[11px] leading-relaxed font-mono whitespace-pre-wrap break-words mt-2 p-2 rounded bg-black/40 border border-white/10 termix-text">${commands}</pre>`;
        return `
            <div class="p-3 rounded-lg bg-white/5 border border-white/10">
                <div class="flex items-center justify-between gap-2 flex-wrap">
                    <div class="text-sm termix-text font-medium truncate">${esc(target.service || target.containers[0] || '')}</div>
                    <span class="px-2 py-0.5 rounded-full text-[11px] font-semibold ${target.reason ? 'bg-red-500/20 text-red-200 border border-red-500/30' : 'bg-emerald-500/20 text-emerald-200 border border-emerald-500/30'}">${esc(kind)}</span>
                </div>
                ${where ? `<div class="text-[11px] termix-muted font-mono truncate mt-1" title="${esc(where)}">${esc(where)}</div>` : ''}
                ${target.reason
                    ? `<div class="text-xs text-red-300 mt-2">${esc(target.reason)}</div>`
                    : `<div class="text-[11px] termix-muted mt-2">${esc(target.note || '')}</div>${estateSteps}`}
                ${target.containers && target.containers.length
                    ? `<div class="text-[11px] termix-muted mt-1 truncate" title="${esc(target.containers.join(', '))}">containers: ${esc(target.containers.join(', '))}</div>`
                    : ''}
            </div>
        `;
    };

    const renderPlan = (plan) => {
        state.plan = plan;
        const summary = el('updateModalSummary');
        const targets = el('updateModalTargets');
        const run = el('updateModalRun');
        if (!plan) {
            if (summary) summary.textContent = 'Could not read the plan for this container.';
            if (targets) targets.innerHTML = '';
            if (run) run.disabled = true;
            return;
        }
        if (summary) {
            summary.innerHTML = `<span class="font-mono">${esc(plan.image || plan.container || '')}</span> on <span class="termix-text">${esc(plan.host_name || plan.host_key)}</span>`;
        }
        if (targets) targets.innerHTML = (plan.targets || []).map(renderTarget).join('')
            || '<div class="text-xs text-red-400">nothing on this host matches that image</div>';
        if (run) {
            const viaEstate = (plan.targets || []).some((t) => t.kind === 'estate');
            run.disabled = !plan.supported;
            run.textContent = plan.mode === 'dry_run'
                ? 'Show the plan (dry run)'
                : (viaEstate ? 'Commit + deploy via CI' : 'Update now');
            run.title = plan.supported
                ? 'Pull the newer image and recreate only this service'
                : 'This container cannot be updated safely from here';
        }
        setState(plan.supported
            ? (plan.mode === 'dry_run' ? 'dry run: the commands are shown, not executed' : 'ready')
            : 'not updatable from ailog', plan.supported ? '' : 'error');
    };

    const renderSteps = (job) => {
        const box = el('updateModalSteps');
        if (!box) return;
        box.innerHTML = (job.steps || []).map((step) => {
            const mark = step.ok === true ? '✓' : step.ok === false ? '✕' : '•';
            const tone = step.ok === true ? 'text-emerald-300' : step.ok === false ? 'text-red-400' : 'termix-muted';
            return `<div class="text-xs ${tone}"><span class="inline-block w-4">${mark}</span>${esc(step.label)}${step.detail ? ` <span class="termix-muted font-mono text-[11px]">${esc(step.detail)}</span>` : ''}</div>`;
        }).join('');
        const pre = el('updateModalLog');
        const text = (job.output || []).join('\n');
        if (pre) {
            pre.hidden = !text;
            pre.textContent = text;
            pre.scrollTop = pre.scrollHeight;
        }
    };

    const renderJob = (job) => {
        state.job = job;
        if (!job) return;
        renderSteps(job);
        if (job.status === 'running') {
            setProgress(job.progress);
            setState(`${job.label || 'working'} · ${job.elapsed}s`);
            return;
        }
        const finished = ['done', 'error', 'blocked'].includes(job.status);
        if (!finished) return;
        const run = el('updateModalRun');
        const again = el('updateModalAgain');
        if (run) run.disabled = true;
        if (again) again.hidden = false;
        if (job.status === 'done') {
            setProgress(100);
            setState(job.note === 'already newest'
                ? 'already newest — nothing to deploy'
                : 'updated — the pane is re-reading this host',
            job.note === 'already newest' ? '' : 'ok');
            document.dispatchEvent(new CustomEvent('ailog:container-updated', {
                detail: { hostKey: job.host_key, image: job.image, container: job.container },
            }));
        } else {
            setProgress(null);
            setState(job.error || 'the update failed — see the log', 'error');
        }
    };

    const poll = async () => {
        if (!state.job || !state.job.id) return;
        try {
            const res = await fetch(`/api/docker/update/jobs/${encodeURIComponent(state.job.id)}`, {
                headers: { Accept: 'application/json' },
            });
            const data = await res.json();
            if (!res.ok || !data.success) throw new Error(data.error || `HTTP ${res.status}`);
            renderJob(data.job);
            if (data.job.status !== 'running') { stopPolling(); return; }
        } catch (err) {
            setState(`lost track of the job: ${err.message}`, 'error');
            stopPolling();
            return;
        }
        state.timer = setTimeout(poll, 900);
    };

    const loadPlan = async () => {
        const run = el('updateModalRun');
        const summary = el('updateModalSummary');
        const targets = el('updateModalTargets');
        if (run) run.disabled = true;
        if (targets) targets.innerHTML = '';
        setProgress(null);
        if (summary) summary.textContent = `Reading ${state.label || state.hostKey}…`;
        const params = new URLSearchParams();
        if (state.image) params.set('image', state.image);
        if (state.container) params.set('container', state.container);
        try {
            const res = await fetch(`/api/docker/hosts/${encodeURIComponent(state.hostKey)}/update/plan?${params}`, {
                headers: { Accept: 'application/json' },
            });
            const data = await res.json();
            if (!res.ok || !data.success) throw new Error(data.error || `HTTP ${res.status}`);
            renderPlan(data.plan);
        } catch (err) {
            renderPlan(null);
            setState(`could not plan this update: ${err.message}`, 'error');
        }
    };

    window.openUpdateModal = function (opts) {
        const options = opts || {};
        if (!options.hostKey) return;
        stopPolling();
        state.hostKey = options.hostKey;
        state.image = options.image || '';
        state.container = options.container || '';
        state.label = options.label || state.image || state.container;
        state.job = null;

        const title = el('updateModalTitle');
        if (title) title.textContent = `Update ${options.label || 'container'}`;
        const sub = el('updateModalSub');
        if (sub) sub.textContent = options.hostName ? `· ${options.hostName}` : '';
        if (el('updateModalSteps')) el('updateModalSteps').innerHTML = '';
        if (el('updateModalLog')) { el('updateModalLog').hidden = true; el('updateModalLog').textContent = ''; }
        if (el('updateModalAgain')) el('updateModalAgain').hidden = true;

        if (typeof window.openAppModal === 'function') window.openAppModal('updateModal');
        else el('updateModal')?.classList.remove('hidden');
        loadPlan();
    };

    window.closeUpdateModal = function () {
        stopPolling();
        if (typeof window.closeAppModal === 'function') window.closeAppModal('updateModal');
        else el('updateModal')?.classList.add('hidden');
    };

    const start = async () => {
        const run = el('updateModalRun');
        if (run) run.disabled = true;
        setProgress(1);
        setState('starting…');
        try {
            const res = await fetch(`/api/docker/hosts/${encodeURIComponent(state.hostKey)}/update`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                body: JSON.stringify({
                    image: state.image,
                    container: state.container,
                    confirm: true,
                }),
            });
            const data = await res.json();
            if (!res.ok || !data.success) throw new Error(data.error || `HTTP ${res.status}`);
            renderJob(data.job);
            if (data.job && data.job.status === 'running') state.timer = setTimeout(poll, 700);
        } catch (err) {
            setState(`could not start: ${err.message}`, 'error');
            if (run) run.disabled = false;
        }
    };

    document.addEventListener('DOMContentLoaded', () => {
        el('updateModalRun')?.addEventListener('click', start);
        el('updateModalAgain')?.addEventListener('click', () => {
            if (el('updateModalAgain')) el('updateModalAgain').hidden = true;
            if (el('updateModalSteps')) el('updateModalSteps').innerHTML = '';
            if (el('updateModalLog')) { el('updateModalLog').hidden = true; el('updateModalLog').textContent = ''; }
            loadPlan();
        });
        // Escape, the backdrop and the Close button all end in closeAppModal, so
        // one listener here stops the poll however the dialog was dismissed. The
        // server-side job keeps running; the pane re-reads when it is done.
        el('updateModal')?.addEventListener('appmodal:close', stopPolling);
    });
})();
