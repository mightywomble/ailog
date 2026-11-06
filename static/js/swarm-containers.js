/* What is actually running on this node, as panes you can open.

   A swarm node's page has two different questions on it and they were being
   answered by one list. "What needs updating?" is a question about the
   *cluster* - a service's image, its tag, whether zot has moved on - and only a
   manager can answer it. "What is this machine doing?" is a question about
   *containers* - name, version, RAM, CPU, network - and every node can answer
   it, workers included.

   So the workers lost the update list (they never had the truth to put in it)
   and every node gained this: a pane per running container, two or three to a
   row. Clicking a pane opens it: three live graphs, the image version, and a
   terminal *inside* the container - not on the host it happens to be running
   on, which is the thing you would otherwise have to work out and type.
*/

(function () {
    const POLL_MS = 5000;
    const POLL_OPEN_MS = 2000;      // an open pane is being watched: keep it live
    const HISTORY = 60;             // samples kept per container, ~2 min at 2s

    const esc = (value) => String(value == null ? '' : value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');

    const bytes = (value) => {
        const n = Number(value) || 0;
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let i = 0;
        let v = Math.abs(n);
        while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
        return (n < 0 ? '-' : '') + (i === 0 ? v.toFixed(0) : v.toFixed(1)) + ' ' + units[i];
    };

    const rate = (value) => {
        const n = Number(value) || 0;
        if (n < 1024) return n.toFixed(0) + ' B/s';
        const units = ['KB/s', 'MB/s', 'GB/s'];
        let v = n / 1024;
        let i = 0;
        while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
        return v.toFixed(v >= 10 ? 0 : 1) + ' ' + units[i];
    };

    const pct = (value) => (value == null || value === '' ? '\u2013' : Number(value).toFixed(1) + '%');

    // Per mount: the timers, the open panes and the samples, so a re-render
    // never leaves a timer behind and an open pane keeps its history.
    const mounts = new WeakMap();
    const state = (mount) => {
        let s = mounts.get(mount);
        if (!s) {
            s = { timer: null, open: new Set(), series: new Map() };
            mounts.set(mount, s);
        }
        return s;
    };

    const stop = (mount) => {
        if (!mount) return;
        const s = mounts.get(mount);
        if (s && s.timer) clearTimeout(s.timer);
        if (s) s.timer = null;
    };
    window.stopSwarmContainers = stop;

    const push = (s, id, cpu, mem, netIn, netOut) => {
        let series = s.series.get(id);
        if (!series) {
            series = { cpu: [], mem: [], net: [] };
            s.series.set(id, series);
        }
        series.cpu.push(Number(cpu) || 0);
        series.mem.push(Number(mem) || 0);
        series.net.push((Number(netIn) || 0) + (Number(netOut) || 0));
        ['cpu', 'mem', 'net'].forEach((key) => {
            while (series[key].length > HISTORY) series[key].shift();
        });
    };

    // A sparkline, drawn by hand: three of them per open pane, and a chart
    // library for sixty points of two numbers is a dependency nobody needs.
    const draw = (canvas, values, colour, kind) => {
        if (!canvas) return;
        const dpr = window.devicePixelRatio || 1;
        const width = canvas.clientWidth || 220;
        const height = canvas.clientHeight || 48;
        if (canvas.width !== Math.round(width * dpr) || canvas.height !== Math.round(height * dpr)) {
            canvas.width = Math.round(width * dpr);
            canvas.height = Math.round(height * dpr);
        }
        const ctx = canvas.getContext('2d');
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, width, height);
        if (!values.length) return;

        const max = kind === 'pct' ? 100 : Math.max(...values, 1);
        const stepX = values.length > 1 ? width / (values.length - 1) : width;
        const y = (v) => height - 2 - (Math.min(v, max) / max) * (height - 4);

        ctx.beginPath();
        values.forEach((v, i) => {
            const x = i * stepX;
            if (i === 0) ctx.moveTo(x, y(v));
            else ctx.lineTo(x, y(v));
        });
        ctx.strokeStyle = colour;
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // a soft fill under the line, so a flat idle graph still reads as a graph
        ctx.lineTo(width, height);
        ctx.lineTo(0, height);
        ctx.closePath();
        ctx.fillStyle = colour.replace('rgb', 'rgba').replace(')', ', 0.15)');
        ctx.fill();
    };

    const versionBadge = (c) => {
        const tag = c.image_tag || (c.image || '').split(':').pop() || '';
        if (!tag || tag === c.image) return '';
        return `<span class="shrink-0 text-[10px] px-1.5 py-0.5 rounded bg-white/10 border border-white/15 font-mono termix-text"
                      title="${esc((c.image || '') + ':' + tag)}">${esc(tag)}</span>`;
    };

    const charts = (c, s) => {
        const series = s.series.get(c.id) || { cpu: [], mem: [], net: [] };
        const boxes = [
            ['CPU', 'cpu', 'rgb(56, 189, 248)', pct(c.cpu_percent)],
            ['RAM', 'mem', 'rgb(167, 139, 250)', bytes(c.mem_used)],
            ['NET', 'net', 'rgb(52, 211, 153)', `${rate(Number(c.net_rx_bps || 0) + Number(c.net_tx_bps || 0))}`],
        ];
        return `<div class="grid grid-cols-3 gap-2 mt-2">
            ${boxes.map(([label, key, colour, now]) => `
                <div class="rounded bg-black/30 border border-white/10 p-1.5">
                    <div class="flex items-baseline justify-between">
                        <span class="text-[10px] uppercase tracking-wide termix-muted">${label}</span>
                        <span class="text-[10px] tabular-nums termix-text">${esc(now)}</span>
                    </div>
                    <canvas class="w-full h-12 block" data-chart="${key}" data-colour="${colour}"
                            style="height:48px"></canvas>
                </div>`).join('')}
        </div>`;
    };

    const pane = (c, isOpen, s) => {
        const name = c.name || c.short_id || '?';
        const service = c.service || c.stack || '';
        const cpu = Number(c.cpu_percent || 0);
        const netIn = Number(c.net_rx_bps || 0);
        const netOut = Number(c.net_tx_bps || 0);
        return `<div class="rounded-lg border border-white/10 bg-white/5 ${isOpen ? 'sm:col-span-2 xl:col-span-3' : ''}"
                     data-pane="${esc(c.id)}">
            <button type="button" class="w-full text-left p-2" data-toggle="${esc(c.id)}">
                <div class="flex items-start justify-between gap-2">
                    <div class="min-w-0">
                        <div class="flex items-center gap-1.5 min-w-0">
                            <span class="truncate text-xs termix-text font-medium" title="${esc(name)}">${esc(name)}</span>
                            ${versionBadge(c)}
                            ${service ? `<span class="shrink-0 text-[10px] px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/25">${esc(service)}</span>` : ''}
                        </div>
                        <div class="text-[10px] termix-muted truncate">${esc(c.image_name || c.image || '')}</div>
                    </div>
                    <svg class="w-3.5 h-3.5 shrink-0 termix-muted transition-transform ${isOpen ? 'rotate-90' : ''}"
                         fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" aria-hidden="true">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7"/>
                    </svg>
                </div>
                <div class="mt-1 grid grid-cols-3 gap-1 text-[10px] tabular-nums">
                    <span class="termix-text">${bytes(c.mem_used)}<span class="termix-muted"> ram</span></span>
                    <span class="${cpu >= 80 ? 'text-amber-300' : 'termix-text'}">${pct(cpu)}<span class="termix-muted"> cpu</span></span>
                    <span class="termix-text truncate"><span class="text-emerald-300">\u2193${rate(netIn)}</span>
                        <span class="text-amber-300">\u2191${rate(netOut)}</span></span>
                </div>
            </button>
            <div class="px-2 pb-2 ${isOpen ? '' : 'hidden'}" data-detail="${esc(c.id)}">
                ${isOpen ? charts(c, s) : ''}
                <div class="flex items-center justify-between gap-2 mt-2">
                    <span class="text-[10px] termix-muted truncate" title="${esc(c.image || '')}">
                        ${esc(c.image || '')}${c.image_tag ? ':' + esc(c.image_tag) : ''}
                    </span>
                    ${typeof window.openContainerShell === 'function' ? `
                    <button type="button" data-shell="${esc(c.id)}"
                            class="shrink-0 text-[11px] px-2 py-1 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-medium">
                        ssh into container
                    </button>` : ''}
                </div>
                <div class="text-[10px] text-red-400 mt-1 hidden" data-shell-error></div>
            </div>
        </div>`;
    };

    const wire = (mount, hostKey, containers, options) => {
        const s = state(mount);
        mount.querySelectorAll('[data-toggle]').forEach((button) => {
            button.addEventListener('click', () => {
                const id = button.dataset.toggle;
                if (s.open.has(id)) s.open.delete(id);
                else s.open.add(id);
                render(mount, hostKey, containers, options);
            });
        });
        mount.querySelectorAll('[data-shell]').forEach((button) => {
            button.addEventListener('click', async (event) => {
                event.stopPropagation();
                const id = button.dataset.shell;
                const errorBox = button.closest('[data-detail]')?.querySelector('[data-shell-error]');
                button.disabled = true;
                const label = button.textContent;
                button.textContent = 'checking\u2026';
                try {
                    const res = await fetch(`/api/docker/hosts/${encodeURIComponent(hostKey)}`
                        + `/containers/${encodeURIComponent(id)}/shell`, { headers: { Accept: 'application/json' } });
                    const data = await res.json();
                    if (!res.ok || data.success === false) throw new Error(data.error || `HTTP ${res.status}`);
                    if (typeof window.openContainerShell !== 'function') {
                        throw new Error('the terminal is not available on this page');
                    }
                    await window.openContainerShell(hostKey, id, data.shell);
                    button.textContent = 'open';
                } catch (err) {
                    if (errorBox) {
                        errorBox.textContent = err.message;
                        errorBox.classList.remove('hidden');
                    }
                    button.textContent = label;
                } finally {
                    button.disabled = false;
                }
            });
        });
    };

    const render = (mount, hostKey, containers, options) => {
        const s = state(mount);
        mount.innerHTML = `<div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-2">
            ${containers.map((c) => pane(c, s.open.has(c.id), s)).join('')}
        </div>`;
        wire(mount, hostKey, containers, options);
        // redraw only what is open: a closed pane has no canvas
        s.open.forEach((id) => {
            const row = containers.find((c) => c.id === id);
            const series = s.series.get(id);
            if (!row || !series) return;
            const detail = mount.querySelector(`[data-detail="${CSS.escape(id)}"]`);
            if (!detail) return;
            draw(detail.querySelector('[data-chart="cpu"]'), series.cpu, 'rgb(56, 189, 248)', 'pct');
            draw(detail.querySelector('[data-chart="mem"]'), series.mem, 'rgb(167, 139, 250)', 'mem');
            draw(detail.querySelector('[data-chart="net"]'), series.net, 'rgb(52, 211, 153)', 'net');
        });
    };

    window.renderSwarmContainers = function (mount, hostKey, options) {
        if (!mount) return;
        stop(mount);
        const opts = options || {};
        const s = state(mount);
        mount.innerHTML = '<div class="text-xs termix-muted py-2">Reading this node\u2019s containers\u2026</div>';

        const load = async () => {
            let data;
            try {
                const res = await fetch(`/api/docker/hosts/${encodeURIComponent(hostKey)}/containers`,
                    { headers: { Accept: 'application/json' } });
                data = await res.json();
                if (!res.ok || data.success === false) throw new Error(data.error || `HTTP ${res.status}`);
            } catch (err) {
                mount.innerHTML = `<div class="text-xs text-red-400 py-2">Could not read this node's containers (${esc(err.message)}).</div>`;
                return;
            }
            const running = (data.containers || [])
                .filter((c) => String(c.state || '').toLowerCase() === 'running')
                .sort((a, b) => Number(b.mem_used || 0) - Number(a.mem_used || 0));
            running.forEach((c) => push(s, c.id, c.cpu_percent, c.mem_used, c.net_rx_bps, c.net_tx_bps));

            const count = document.getElementById(mount.dataset.count || '');
            if (count) {
                count.textContent = `${running.length} running`
                    + (running.length ? ` \u00b7 ${bytes(running.reduce((sum, c) => sum + Number(c.mem_used || 0), 0))} in use` : '');
            }
            if (!running.length) {
                mount.innerHTML = '<div class="text-xs termix-muted py-2">No containers are running on this node.</div>';
            } else {
                render(mount, hostKey, running, opts);
            }

            // Poll only while the element is still in the document: a pane that
            // has been replaced must not keep asking the node for stats forever.
            const wait = s.open.size ? POLL_OPEN_MS : (opts.pollMs || POLL_MS);
            if (opts.poll !== false && mount.isConnected) {
                s.timer = setTimeout(() => {
                    if (!mount.isConnected) { s.timer = null; return; }
                    load();
                }, wait);
            }
        };
        load();
    };
})();
