/* What is actually running on this node, in four columns.

   A swarm node's page has two different questions on it and they were being
   answered by one list. "What needs updating?" is a question about the
   *cluster* - a service's image, its tag, whether zot has moved on - and only a
   manager can answer it. "What is this machine doing?" is a question about
   *containers* - name, RAM, CPU, network - and every node can answer it,
   workers included.

   So the workers lost the update list (they never had the truth to put in it)
   and every node gained this: one row per running container, four panes.
   Reads /api/docker/hosts/<key>/containers, which reports net_rx_bps /
   net_tx_bps per container on both transports, and polls while it is on screen.
*/

(function () {
    const POLL_MS = 5000;

    const el = (id) => document.getElementById(id);

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

    // One poller per mount, so re-rendering the pane does not leave timers
    // behind - and a timer that outlives its element is how a page gets slower
    // the longer it is open.
    const timers = new WeakMap();

    const stop = (mount) => {
        const timer = timers.get(mount);
        if (timer) clearTimeout(timer);
        timers.delete(mount);
    };
    window.stopSwarmContainers = stop;

    // The version the container is actually running, which is the thing you
    // look for and the thing a truncated `image:tag` line hides. `build-348`,
    // `v3.27.0`, `16-alpine` - whatever the tag is, next to the name.
    const versionBadge = (c) => {
        const tag = c.image_tag || (c.image || '').split(':').pop() || '';
        if (!tag || tag === c.image) return '';
        return `<span class="shrink-0 text-[10px] px-1.5 py-0.5 rounded bg-white/10 border border-white/15 font-mono termix-text"
                      title="${esc((c.image || '') + ':' + tag)}">${esc(tag)}</span>`;
    };

    const row = (c) => {
        const name = c.name || c.short_id || '?';
        const service = c.service || c.stack || '';
        const cpu = Number(c.cpu_percent || 0);
        const mem = Number(c.mem_used || 0);
        const memPct = c.mem_percent == null ? null : Number(c.mem_percent);
        const netIn = Number(c.net_rx_bps || 0);
        const netOut = Number(c.net_tx_bps || 0);
        return `<tr class="border-t border-white/5">
            <td class="py-1.5 pr-3 min-w-0">
                <div class="flex items-center gap-2 min-w-0">
                    <span class="truncate text-xs termix-text font-medium" title="${esc(name)}">${esc(name)}</span>
                    ${versionBadge(c)}
                    ${service ? `<span class="shrink-0 text-[10px] px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/25">${esc(service)}</span>` : ''}
                </div>
                <div class="text-[10px] termix-muted truncate">${esc(c.image_name || c.image || '')}</div>
            </td>
            <td class="py-1.5 pr-3 text-right text-xs tabular-nums termix-text whitespace-nowrap">
                ${bytes(mem)}${memPct == null ? '' : ` <span class="termix-muted text-[10px]">${memPct.toFixed(0)}%</span>`}
            </td>
            <td class="py-1.5 pr-3 text-right text-xs tabular-nums whitespace-nowrap ${cpu >= 80 ? 'text-amber-300' : 'termix-text'}">
                ${pct(cpu)}
            </td>
            <td class="py-1.5 text-right text-xs tabular-nums whitespace-nowrap">
                <span class="text-emerald-300">&darr; ${rate(netIn)}</span>
                <span class="text-amber-300 ml-2">&uarr; ${rate(netOut)}</span>
            </td>
        </tr>`;
    };

    const table = (rows) => `
        <table class="w-full table-fixed">
            <thead>
                <tr class="text-[10px] uppercase tracking-wide termix-muted">
                    <th class="text-left font-medium pb-1 w-[46%]">Container</th>
                    <th class="text-right font-medium pb-1 w-[16%]">RAM</th>
                    <th class="text-right font-medium pb-1 w-[12%]">CPU</th>
                    <th class="text-right font-medium pb-1 w-[26%]">Network</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>`;

    const load = async (mount, hostKey, options) => {
        const opts = options || {};
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
        const count = el(mount.dataset.count || '');
        if (count) {
            count.textContent = `${running.length} running`
                + (running.length ? ` \u00b7 ${bytes(running.reduce((sum, c) => sum + Number(c.mem_used || 0), 0))} in use` : '');
        }
        mount.innerHTML = running.length
            ? table(running.map(row).join(''))
            : '<div class="text-xs termix-muted py-2">No containers are running on this node.</div>';

        stop(mount);
        // Poll only while the element is still in the document: a pane that has
        // been replaced must not keep asking the node for stats forever.
        if (opts.poll !== false && mount.isConnected) {
            timers.set(mount, setTimeout(() => {
                if (!mount.isConnected) { timers.delete(mount); return; }
                load(mount, hostKey, opts);
            }, opts.pollMs || POLL_MS));
        }
    };

    window.renderSwarmContainers = function (mount, hostKey, options) {
        if (!mount) return;
        stop(mount);
        mount.innerHTML = '<div class="text-xs termix-muted py-2">Reading this node\u2019s containers\u2026</div>';
        load(mount, hostKey, options);
    };
})();
