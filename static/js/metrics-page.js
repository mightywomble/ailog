/* Monitoring page — live cards, one per server.
 *
 * Data: GET /api/metrics/servers every couple of seconds (the endpoint caches
 * a snapshot for ~1.5s, so several open views cost one collection round).
 * Containers: GET /api/metrics/containers?host=<key>, only while a Docker card
 * is expanded.
 *
 * The chart history lives here in the browser (a rolling window per host and
 * per container), so the server keeps no per-view state.
 */

const HISTORY = 90;                       // samples (~3 minutes at 2s)
// Series colours come from the active theme's --chart-* tokens, so switching
// theme re-colours the charts instead of leaving them on the old palette.
const series = () => {
    const tokens = window.themeColors ? window.themeColors() : null;
    const list = tokens?.series || ['#38bdf8', '#a78bfa', '#f59e0b', '#22d3ee', '#fb7185'];
    return { cpu: list[0], mem: list[1], disk: list[2], rx: list[3], tx: list[4] };
};
const SERIES_COLORS = { get cpu() { return series().cpu; }, get mem() { return series().mem; },
    get disk() { return series().disk; }, get rx() { return series().rx; }, get tx() { return series().tx; } };
const DOCKER_SVG = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M22.7 9.3c-.6-.4-1.9-.6-2.9-.4-.1-.9-.6-1.7-1.4-2.4l-.5-.4-.4.5c-.5.7-.7 1.8-.6 2.7.1.5.2 1 .5 1.4-.3.2-.9.4-1.1.4H1.4c-.2 1.6.3 3.6 1.7 5 1.4 1.4 3.4 2.1 6 2.1 6.5 0 11.2-3 13.4-8.4.9 0 2.4 0 3.2-1.6l.2-.4-.6-.4c-.5-.3-1.2-.5-1.6-.4zM3.2 10.7h1.9v1.9H3.2v-1.9zm2.6 0h1.9v1.9H5.8v-1.9zm2.7 0h1.9v1.9H8.5v-1.9zm2.6 0h1.9v1.9h-1.9v-1.9zm-7.9-2.6h1.9v1.9H3.2V8.1zm2.6 0h1.9v1.9H5.8V8.1zm2.7 0h1.9v1.9H8.5V8.1zm2.6 0h1.9v1.9h-1.9V8.1zm2.6 0h1.9v1.9h-1.9V8.1z"/></svg>';

const state = {
    hosts: new Map(),          // host_key -> {card, series, containers, expanded}
    interval: 2000,
    timer: null,
    paused: false,
    inFlight: false,
    lastOk: 0,
};

const grid = document.getElementById('m-grid');
const summary = document.getElementById('m-summary');
const liveBadge = document.getElementById('m-live');
const pauseBtn = document.getElementById('m-pause');
const intervalSelect = document.getElementById('m-interval');
const emptyEl = document.getElementById('m-empty');

/* --------------------------------------------------------------- helpers */

const fmtBytes = (n) => {
    if (n === null || n === undefined || Number.isNaN(Number(n))) return '–';
    const v = Number(n);
    if (v === 0) return '0 B';
    const units = ['B', 'kB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.min(Math.floor(Math.log(Math.abs(v)) / Math.log(1000)), units.length - 1);
    const scaled = v / Math.pow(1000, i);
    return `${scaled.toFixed(scaled >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
};

const fmtRate = (bps) => {
    if (bps === null || bps === undefined) return '–';
    return `${fmtBytes(bps)}/s`;
};

const fmtPct = (v) => (v === null || v === undefined ? '–' : `${Number(v).toFixed(1)}%`);

const fmtUptime = (seconds) => {
    if (!seconds) return '–';
    const s = Math.floor(seconds);
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d) return `${d}d ${h}h`;
    if (h) return `${h}h ${m}m`;
    return `${m}m`;
};

const pushCapped = (arr, value) => {
    arr.push(value);
    if (arr.length > HISTORY) arr.shift();
};

/* ------------------------------------------------------------- sparklines */

function drawSpark(canvas, seriesList, opts = {}) {
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const cssW = canvas.clientWidth || 160;
    const cssH = canvas.clientHeight || 40;
    if (canvas.width !== Math.round(cssW * dpr) || canvas.height !== Math.round(cssH * dpr)) {
        canvas.width = Math.round(cssW * dpr);
        canvas.height = Math.round(cssH * dpr);
    }
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssW, cssH);

    const usable = seriesList.filter(s => Array.isArray(s.values) && s.values.some(v => v !== null && v !== undefined));
    if (!usable.length) return;

    let max = opts.max;
    if (!max) {
        max = 0;
        usable.forEach(s => s.values.forEach(v => { if (v !== null && v !== undefined) max = Math.max(max, Number(v)); }));
        max = max > 0 ? max * 1.15 : 1;
    }
    const min = opts.min || 0;
    const pad = 1.5;
    const h = cssH - pad * 2;
    const toY = (v) => pad + h - ((Math.max(min, Math.min(max, Number(v))) - min) / (max - min || 1)) * h;

    usable.forEach((s) => {
        const values = s.values;
        const stepX = cssW / Math.max(HISTORY - 1, 1);
        const offset = cssW - (values.length - 1) * stepX;
        const pts = [];
        values.forEach((v, i) => {
            if (v === null || v === undefined) return;
            pts.push([offset + i * stepX, toY(v)]);
        });
        if (!pts.length) return;

        if (s.fill !== false) {
            const grad = ctx.createLinearGradient(0, 0, 0, cssH);
            grad.addColorStop(0, `${s.color}55`);
            grad.addColorStop(1, `${s.color}00`);
            ctx.beginPath();
            ctx.moveTo(pts[0][0], cssH);
            pts.forEach(([x, y]) => ctx.lineTo(x, y));
            ctx.lineTo(pts[pts.length - 1][0], cssH);
            ctx.closePath();
            ctx.fillStyle = grad;
            ctx.fill();
        }

        ctx.beginPath();
        pts.forEach(([x, y], i) => (i ? ctx.lineTo(x, y) : ctx.moveTo(x, y)));
        ctx.strokeStyle = s.color;
        ctx.lineWidth = s.width || 1.4;
        ctx.lineJoin = 'round';
        ctx.stroke();

        if (opts.marker !== false) {
            const [lx, ly] = pts[pts.length - 1];
            ctx.beginPath();
            ctx.arc(lx, ly, 1.9, 0, Math.PI * 2);
            ctx.fillStyle = s.color;
            ctx.fill();
        }
    });
}

/* ------------------------------------------------------------------ cards */

function buildCard(server) {
    const card = document.createElement('article');
    card.className = 'm-card';
    card.dataset.host = server.host_key;

    card.innerHTML = `
      <header class="m-card-head">
        <div class="m-card-id">
          <span class="m-dot"></span>
          <span class="m-name"></span>
          <span class="m-ip"></span>
        </div>
        <div class="m-card-flags">
          <span class="m-docker hidden" title="Docker installed">${DOCKER_SVG}<span class="m-docker-count"></span></span>
          <span class="m-chev hidden">▾</span>
        </div>
      </header>
      <div class="m-metrics">
        <div class="m-metric" data-metric="cpu">
          <div class="m-metric-top"><span>CPU</span><span class="m-metric-val">–</span></div>
          <canvas class="m-spark"></canvas>
          <div class="m-metric-foot"></div>
        </div>
        <div class="m-metric" data-metric="mem">
          <div class="m-metric-top"><span>RAM</span><span class="m-metric-val">–</span></div>
          <canvas class="m-spark"></canvas>
          <div class="m-metric-foot"></div>
        </div>
        <div class="m-metric" data-metric="disk">
          <div class="m-metric-top"><span>Disk</span><span class="m-metric-val">–</span></div>
          <canvas class="m-spark"></canvas>
          <div class="m-metric-foot"></div>
        </div>
        <div class="m-metric m-metric-net" data-metric="net">
          <div class="m-metric-top"><span>Network</span><span class="m-metric-val">–</span></div>
          <canvas class="m-spark"></canvas>
          <div class="m-metric-foot"></div>
        </div>
      </div>
      <div class="m-card-error hidden"></div>
      <section class="m-containers hidden">
        <div class="m-containers-head">
          <span>Containers</span>
          <span class="m-containers-note"></span>
        </div>
        <div class="m-containers-body"></div>
      </section>
    `;

    card.querySelector('.m-name').textContent = server.name || server.host_key;
    card.querySelector('.m-ip').textContent = server.ip || '';
    card.addEventListener('click', () => toggleExpand(server.host_key));
    return card;
}

function cardRefs(card) {
    return {
        card,
        dot: card.querySelector('.m-dot'),
        name: card.querySelector('.m-name'),
        ip: card.querySelector('.m-ip'),
        docker: card.querySelector('.m-docker'),
        dockerCount: card.querySelector('.m-docker-count'),
        chev: card.querySelector('.m-chev'),
        error: card.querySelector('.m-card-error'),
        containers: card.querySelector('.m-containers'),
        containersBody: card.querySelector('.m-containers-body'),
        containersNote: card.querySelector('.m-containers-note'),
        metrics: {
            cpu: card.querySelector('[data-metric="cpu"]'),
            mem: card.querySelector('[data-metric="mem"]'),
            disk: card.querySelector('[data-metric="disk"]'),
            net: card.querySelector('[data-metric="net"]'),
        },
    };
}

/* ------------------------------------------------------------- data flow */

async function fetchJson(url) {
    const res = await fetch(url, { headers: { Accept: 'application/json' } });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
}

function renderSampleError(box, raw) {
    const text = String(raw || 'Host unreachable').trim();
    const lines = text.split(/\r?\n/);
    box.textContent = '';
    const head = document.createElement('strong');
    head.textContent = lines[0] || 'Host unreachable';
    box.appendChild(head);
    if (lines.length > 1) {
        const details = document.createElement('details');
        const summary = document.createElement('summary');
        summary.textContent = 'Command output';
        const pre = document.createElement('pre');
        pre.textContent = lines.slice(1).join('\n');
        details.append(summary, pre);
        box.appendChild(details);
    }
}

function setLive(kind) {
    if (!liveBadge) return;
    liveBadge.classList.toggle('m-paused', kind === 'paused');
    liveBadge.classList.toggle('m-error', kind === 'error');
    const label = liveBadge.querySelector('#m-live-label');
    if (label) label.textContent = kind === 'paused' ? 'paused' : (kind === 'error' ? 'disconnected' : 'live');
}

function renderServer(server) {
    const key = String(server.host_key);
    let entry = state.hosts.get(key);

    if (!entry) {
        const card = buildCard(server);
        grid.appendChild(card);
        entry = {
            refs: cardRefs(card),
            series: { cpu: [], mem: [], disk: [], rx: [], tx: [] },
            containers: new Map(),
            expanded: false,
            dockerInstalled: false,
            server,
        };
        state.hosts.set(key, entry);
    }

    entry.server = server;
    const { refs, series } = entry;

    refs.name.textContent = server.name || key;
    refs.ip.textContent = server.ip || '';
    refs.card.classList.toggle('is-offline', server.online === false);

    const online = server.online !== false;
    refs.dot.classList.toggle('up', online);
    refs.dot.classList.toggle('down', !online);

    const docker = server.docker || {};
    entry.dockerInstalled = !!docker.installed;
    refs.docker.classList.toggle('hidden', !entry.dockerInstalled);
    refs.chev.classList.toggle('hidden', !entry.dockerInstalled);
    refs.card.classList.toggle('is-docker', entry.dockerInstalled);
    if (entry.dockerInstalled) {
        const total = docker.containers_total || 0;
        const running = docker.containers_running || 0;
        refs.dockerCount.textContent = total ? `${running}/${total}` : '';
        refs.docker.title = docker.reachable === false
            ? 'Docker installed — engine not reachable from ailog'
            : 'Docker installed — click to expand containers';
    }
    if (!entry.dockerInstalled) {
        refs.dockerCount.textContent = '';
    }

    if (!online) {
        entry.series = { cpu: [], mem: [], disk: [], rx: [], tx: [] };
        refs.error.classList.remove('hidden');
        renderSampleError(refs.error, server.error);
        refs.containers.classList.add('hidden');
        ['cpu', 'mem', 'disk', 'net'].forEach((name) => {
            const box = refs.metrics[name];
            box.querySelector('.m-metric-val').textContent = '–';
            box.querySelector('.m-metric-foot').textContent = '';
            drawSpark(box.querySelector('.m-spark'), []);
        });
        return;
    }

    refs.error.classList.add('hidden');

    const cpu = server.cpu || {};
    const mem = server.mem || {};
    const disk = server.disk || {};
    const net = server.net || {};

    pushCapped(series.cpu, cpu.percent === null || cpu.percent === undefined ? null : cpu.percent);
    pushCapped(series.mem, mem.percent ?? null);
    pushCapped(series.disk, disk.percent ?? null);
    pushCapped(series.rx, net.rx_bps ?? null);
    pushCapped(series.tx, net.tx_bps ?? null);

    const cpuBox = refs.metrics.cpu;
    cpuBox.querySelector('.m-metric-val').textContent = fmtPct(cpu.percent);
    cpuBox.querySelector('.m-metric-foot').textContent =
        `${cpu.cores || '?'} cores · load ${cpu.load1 ?? '–'} ${cpu.load5 ?? '–'} ${cpu.load15 ?? '–'}`;
    drawSpark(cpuBox.querySelector('.m-spark'),
        [{ values: series.cpu, color: SERIES_COLORS.cpu }], { max: 100 });

    const memBox = refs.metrics.mem;
    memBox.querySelector('.m-metric-val').textContent = fmtPct(mem.percent);
    memBox.querySelector('.m-metric-foot').textContent =
        `${fmtBytes(mem.used)} / ${fmtBytes(mem.total)}${mem.swap_total ? ` · swap ${fmtBytes(mem.swap_used)}` : ''}`;
    drawSpark(memBox.querySelector('.m-spark'),
        [{ values: series.mem, color: SERIES_COLORS.mem }], { max: 100 });

    const diskBox = refs.metrics.disk;
    diskBox.querySelector('.m-metric-val').textContent = fmtPct(disk.percent);
    diskBox.querySelector('.m-metric-foot').textContent =
        `${fmtBytes(disk.used)} / ${fmtBytes(disk.total)} · ${disk.mount || '/'}`;
    drawSpark(diskBox.querySelector('.m-spark'),
        [{ values: series.disk, color: SERIES_COLORS.disk }], { max: 100 });

    const netBox = refs.metrics.net;
    netBox.querySelector('.m-metric-val').textContent =
        `↓${fmtRate(net.rx_bps)} ↑${fmtRate(net.tx_bps)}`;
    netBox.querySelector('.m-metric-foot').textContent = `up ${fmtUptime(server.uptime)}`;
    drawSpark(netBox.querySelector('.m-spark'), [
        { values: series.rx, color: SERIES_COLORS.rx },
        { values: series.tx, color: SERIES_COLORS.tx, fill: false },
    ]);

    if (entry.expanded) loadContainers(key);
}

/* ------------------------------------------------------------- containers */

function containerRow(refs, container, hostKey) {
    const key = `${hostKey}|${container.id}`;
    let entry = state.hosts.get(hostKey);
    let series = entry.containers.get(key);
    if (!series) {
        series = { cpu: [], mem: [], rx: [], tx: [] };
        entry.containers.set(key, series);
    }
    pushCapped(series.cpu, container.cpu_percent ?? null);
    pushCapped(series.mem, container.mem_percent ?? null);
    pushCapped(series.rx, container.net_rx_bps ?? null);
    pushCapped(series.tx, container.net_tx_bps ?? null);

    const row = document.createElement('tr');
    const stateLabel = (container.state || 'unknown').toLowerCase();
    row.innerHTML = `
      <td>
        <div class="m-cname">
          <span class="m-dot ${stateLabel === 'running' ? 'up' : ''}"></span>
          <span class="m-cname-text"></span>
          <span class="m-cstack"></span>
        </div>
      </td>
      <td><span class="m-cstate ${stateLabel === 'running' ? 'running' : (stateLabel === 'exited' ? 'exited' : '')}"></span></td>
      <td><div class="m-cell"><span class="m-cell-num"></span><div class="m-bar"><i></i></div></div></td>
      <td><div class="m-cell"><span class="m-cell-num"></span><div class="m-bar"><i></i></div></div></td>
      <td><div class="m-cell"><span class="m-cell-num"></span></div></td>
      <td><div class="m-cell"><span class="m-cell-num"></span><canvas class="m-mini"></canvas></div></td>
    `;
    row.querySelector('.m-cname-text').textContent = container.name || container.id;
    row.querySelector('.m-cname-text').title = container.image || '';
    row.querySelector('.m-cstack').textContent = container.service || container.stack || '';
    row.querySelector('.m-cstate').textContent = container.state || '–';

    const cpus = row.querySelectorAll('.m-cell-num');
    cpus[0].textContent = fmtPct(container.cpu_percent);
    cpus[1].textContent = fmtPct(container.mem_percent);
    cpus[2].textContent = `${fmtBytes(container.mem_used)} / ${fmtBytes(container.mem_limit)}`;
    cpus[3].textContent = `↓${fmtRate(container.net_rx_bps)} ↑${fmtRate(container.net_tx_bps)}`;

    const bars = row.querySelectorAll('.m-bar > i');
    bars[0].style.width = `${Math.max(0, Math.min(100, container.cpu_percent || 0))}%`;
    bars[0].parentElement.title = 'CPU';
    bars[1].style.width = `${Math.max(0, Math.min(100, container.mem_percent || 0))}%`;
    bars[1].style.background = SERIES_COLORS.mem;

    drawSpark(row.querySelector('.m-mini'), [
        { values: series.rx, color: SERIES_COLORS.rx, width: 1.1 },
        { values: series.tx, color: SERIES_COLORS.tx, width: 1.1, fill: false },
    ], { marker: false });

    return row;
}

function renderContainers(hostKey, data) {
    const entry = state.hosts.get(hostKey);
    if (!entry || !entry.expanded) return;
    const { refs } = entry;

    if (!data.reachable) {
        refs.containersBody.innerHTML = '';
        refs.containersNote.textContent = data.error || 'Docker engine not reachable';
        return;
    }

    const containers = data.containers || [];
    const running = containers.filter(c => (c.state || '').toLowerCase() === 'running').length;
    refs.containersNote.textContent =
        `${running} running · ${containers.length} total${data.engine_version ? ` · engine ${data.engine_version}` : ''}`;

    if (!containers.length) {
        refs.containersBody.innerHTML =
            '<div class="m-containers-note">No containers on this host.</div>';
        return;
    }

    let body = refs.containersBody.querySelector('tbody');
    if (!body) {
        refs.containersBody.innerHTML = `
          <table class="m-ctable">
            <thead>
              <tr>
                <th>Container</th><th>State</th><th>CPU</th><th>RAM %</th>
                <th>RAM</th><th>Net (rx/tx)</th>
              </tr>
            </thead>
            <tbody></tbody>
          </table>
        `;
        body = refs.containersBody.querySelector('tbody');
    }

    // Rebuild rows: container set changes as services scale.
    body.innerHTML = '';
    containers.forEach((c) => body.appendChild(containerRow(refs, c, hostKey)));

    // Drop history for containers that no longer exist.
    const ids = new Set(containers.map(c => `${hostKey}|${c.id}`));
    Array.from(entry.containers.keys()).forEach((k) => {
        if (!ids.has(k)) entry.containers.delete(k);
    });
}

async function loadContainers(hostKey) {
    const entry = state.hosts.get(hostKey);
    if (!entry || !entry.expanded) return;
    try {
        const data = await fetchJson(`/api/metrics/containers?host=${encodeURIComponent(hostKey)}`);
        renderContainers(hostKey, data);
    } catch (err) {
        if (entry.refs) entry.refs.containersNote.textContent = `containers: ${err.message}`;
    }
}

function toggleExpand(hostKey) {
    const entry = state.hosts.get(hostKey);
    if (!entry || !entry.dockerInstalled) return;
    entry.expanded = !entry.expanded;
    entry.refs.card.classList.toggle('is-expanded', entry.expanded);
    entry.refs.containers.classList.toggle('hidden', !entry.expanded);
    if (entry.expanded) {
        entry.refs.containersNote.textContent = 'loading…';
        loadContainers(hostKey);
    }
}

/* ------------------------------------------------------------------- loop */

async function refresh() {
    if (state.paused || state.inFlight) return;
    state.inFlight = true;
    try {
        const data = await fetchJson(`/api/metrics/servers?ts=${Date.now()}`);
        const servers = data.servers || [];
        emptyEl.classList.toggle('hidden', servers.length > 0);

        const seen = new Set();
        servers.forEach((s) => {
            seen.add(String(s.host_key));
            renderServer(s);
        });

        // Hosts that disappeared from config.
        Array.from(state.hosts.keys()).forEach((key) => {
            if (!seen.has(key)) {
                const entry = state.hosts.get(key);
                entry.refs.card.remove();
                state.hosts.delete(key);
            }
        });

        const online = servers.filter(s => s.online !== false).length;
        const docker = servers.filter(s => (s.docker || {}).installed).length;
        summary.textContent =
            `${online}/${servers.length} servers reachable · ${docker} with Docker`;
        state.lastOk = Date.now();
        setLive(state.paused ? 'paused' : 'live');
    } catch (err) {
        setLive('error');
        summary.textContent = `Last update failed: ${err.message}`;
    } finally {
        state.inFlight = false;
    }
}

function schedule() {
    clearInterval(state.timer);
    state.timer = setInterval(() => {
        if (document.hidden) return;
        refresh();
    }, state.interval);
}

const togglePause = () => {
    state.paused = !state.paused;
    pauseBtn.textContent = state.paused ? 'Resume' : 'Pause';
    setLive(state.paused ? 'paused' : 'live');
    if (!state.paused) refresh();
};

pauseBtn?.addEventListener('click', togglePause);
intervalSelect?.addEventListener('change', () => {
    state.interval = Number(intervalSelect.value) || 2000;
    schedule();
});
document.addEventListener('visibilitychange', () => {
    if (!document.hidden && !state.paused) refresh();
});
window.addEventListener('resize', () => {
    // Re-draw with the new device pixel ratio / card width.
    state.hosts.forEach((entry) => {
        if (!entry.server || entry.server.online === false) return;
        const { series, refs } = entry;
        drawSpark(refs.metrics.cpu.querySelector('.m-spark'), [{ values: series.cpu, color: SERIES_COLORS.cpu }], { max: 100 });
        drawSpark(refs.metrics.mem.querySelector('.m-spark'), [{ values: series.mem, color: SERIES_COLORS.mem }], { max: 100 });
        drawSpark(refs.metrics.disk.querySelector('.m-spark'), [{ values: series.disk, color: SERIES_COLORS.disk }], { max: 100 });
        drawSpark(refs.metrics.net.querySelector('.m-spark'), [
            { values: series.rx, color: SERIES_COLORS.rx },
            { values: series.tx, color: SERIES_COLORS.tx, fill: false },
        ]);
    });
});

window.addEventListener('themechange', () => {
    // Repaint every sparkline in the new palette.
    state.hosts.forEach((entry) => {
        if (entry.expanded) loadContainers(entry.server?.host_key);
    });
    refresh();
});

refresh();
schedule();
