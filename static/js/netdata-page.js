/* Netdata fleet page.
 *
 * Data: /api/netdata/fleet (live cards + reconciliation + quality),
 *       /api/netdata/capacity (p95 over a window from Netdata's minute tier),
 *       /api/netdata/alerts (live instances + transitions),
 *       /api/netdata/history (drill-down; one request per open modal).
 *
 * The page is anomaly-first: cards are ordered by Netdata's own ML anomaly
 * rate, then by CPU, so the machine that is behaving unusually is the one you
 * see first. Nothing here writes to Netdata.
 */

const $ = (sel) => document.querySelector(sel);
const esc = (value) => String(value ?? '');

const state = { fleet: null, cards: [], timer: null, historyHost: null, historyTimer: null };

const fmtPct = (v) => (v === null || v === undefined || Number.isNaN(Number(v)) ? '–' : `${Number(v).toFixed(1)}%`);

function level(pct) {
    if (pct === null || pct === undefined) return '';
    if (pct >= 90) return 'crit';
    if (pct >= 75) return 'warn';
    return '';
}

async function getJson(url) {
    const res = await fetch(url, { headers: { Accept: 'application/json' } });
    const body = await res.json().catch(() => ({}));
    if (!res.ok || body.success === false) throw new Error(body.error || `${res.status} ${res.statusText}`);
    return body;
}

function drawChart(canvas, values, colour) {
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth || 260;
    const h = canvas.clientHeight || 90;
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    const usable = (values || []).filter((v) => v !== null && v !== undefined && !Number.isNaN(Number(v)));
    if (!usable.length) {
        ctx.fillStyle = 'rgba(148,163,184,.5)';
        ctx.font = '11px system-ui, sans-serif';
        ctx.fillText('no samples in this window', 8, h / 2);
        return;
    }
    const max = Math.max(1, ...usable.map(Number)) * 1.1;
    const step = w / Math.max(usable.length - 1, 1);
    const points = usable.map((v, i) => [i * step, h - (Number(v) / max) * (h - 6) - 3]);
    ctx.beginPath();
    points.forEach(([x, y], i) => (i ? ctx.lineTo(x, y) : ctx.moveTo(x, y)));
    ctx.strokeStyle = colour || '#38bdf8';
    ctx.lineWidth = 1.6;
    ctx.lineJoin = 'round';
    ctx.stroke();
    ctx.lineTo(points[points.length - 1][0], h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = `${colour || '#38bdf8'}22`;
    ctx.fill();
}

function renderBanner(fleet) {
    const banner = $('#nd-banner');
    const quality = fleet.quality || {};
    if (!quality.nodes) {
        banner.classList.add('hidden');
        return;
    }
    const issues = [];
    if ((quality.unstable || []).length) issues.push(`unstable streaming: ${quality.unstable.join(', ')}`);
    if ((quality.not_streaming || []).length) issues.push(`not streaming to parent: ${quality.not_streaming.join(', ')}`);
    if ((quality.offline || []).length) issues.push(`offline: ${quality.offline.join(', ')}`);
    if (!issues.length) {
        banner.classList.add('hidden');
        return;
    }
    banner.textContent = `Data quality: ${issues.join(' · ')}. A log gap on these nodes is more likely telemetry loss than a silent service.`;
    banner.classList.remove('hidden');
    banner.classList.add('warn');
}

function renderCards(nodes) {
    const grid = $('#nd-cards');
    grid.textContent = '';
    const sorted = [...nodes].sort((a, b) => (b.anomaly_rate || 0) - (a.anomaly_rate || 0)
        || (b.cpu_percent || 0) - (a.cpu_percent || 0));
    for (const node of sorted) {
        const card = document.createElement('button');
        card.type = 'button';
        card.className = 'nd-card' + (node.online === false ? ' offline' : '');
        card.dataset.guid = node.guid || '';
        card.dataset.name = node.name || '';

        const head = document.createElement('div');
        head.className = 'nd-card-head';
        const name = document.createElement('span');
        name.className = 'nd-name';
        name.textContent = node.name || node.hostname || 'unknown';
        const badges = document.createElement('span');
        badges.className = 'nd-badges';
        const ar = Number(node.anomaly_rate || 0);
        if (ar > 0) {
            const b = document.createElement('span');
            b.className = 'nd-badge ar';
            b.textContent = `anomaly ${ar.toFixed(2)}%`;
            b.title = 'Netdata ML anomaly rate (rolling 1 minute)';
            badges.appendChild(b);
        }
        const alerts = node.alerts || {};
        if (alerts.critical) {
            const b = document.createElement('span');
            b.className = 'nd-badge crit';
            b.textContent = `${alerts.critical} crit`;
            badges.appendChild(b);
        }
        if (alerts.warning) {
            const b = document.createElement('span');
            b.className = 'nd-badge warn';
            b.textContent = `${alerts.warning} warn`;
            badges.appendChild(b);
        }
        if (node.online === false) {
            const b = document.createElement('span');
            b.className = 'nd-badge crit';
            b.textContent = 'offline';
            badges.appendChild(b);
        }
        head.append(name, badges);
        card.appendChild(head);

        const metrics = document.createElement('div');
        metrics.className = 'nd-metrics';
        [['CPU', node.cpu_percent], ['RAM', node.mem_percent], ['Disk', node.disk_percent],
         ['Load1', node.load1]].forEach(([label, value]) => {
            const box = document.createElement('div');
            box.className = 'nd-metric';
            const strong = document.createElement('strong');
            strong.textContent = label === 'Load1'
                ? (value === null || value === undefined ? '–' : Number(value).toFixed(2))
                : fmtPct(value);
            box.append(`${label}`, strong);
            if (label !== 'Load1') {
                const bar = document.createElement('div');
                bar.className = 'nd-bar';
                const fill = document.createElement('i');
                fill.style.width = `${Math.max(0, Math.min(100, Number(value) || 0))}%`;
                fill.className = level(value);
                bar.appendChild(fill);
                box.appendChild(bar);
            }
            metrics.appendChild(box);
        });
        card.appendChild(metrics);
        card.addEventListener('click', () => openHistory(node));
        grid.appendChild(card);
    }
}

function renderReconcile(rec) {
    const box = $('#nd-reconcile');
    box.textContent = '';
    if (!rec || rec.available === false) {
        box.textContent = 'Reconciliation unavailable.';
        return;
    }
    $('#nd-reconcile-note').textContent = rec.coverage || '';
    const group = (title, items, render) => {
        const section = document.createElement('div');
        const h = document.createElement('h3');
        h.textContent = `${title} (${items.length})`;
        section.appendChild(h);
        const ul = document.createElement('ul');
        if (!items.length) {
            const li = document.createElement('li');
            li.className = 'nd-muted';
            li.textContent = 'none';
            ul.appendChild(li);
        }
        items.forEach((item) => {
            const li = document.createElement('li');
            li.textContent = render(item);
            ul.appendChild(li);
        });
        section.appendChild(ul);
        box.appendChild(section);
    };
    group('Matched', rec.matched || [], (m) => `${m.host_key} → ${m.node}${m.online === false ? ' (offline)' : ''}`);
    group('In Netdata, not in ailog', rec.netdata_only || [], (m) => `${m.node}${m.hostname && m.hostname !== m.node ? ` (${m.hostname})` : ''}`);
    group('In ailog, not in Netdata', rec.ailog_only || [], (m) => `${m.name} (${m.host_key})`);
}

async function loadFleet() {
    try {
        const fleet = await getJson('/api/netdata/fleet?window=120&points=30');
        state.fleet = fleet;
        state.cards = fleet.nodes || [];
        renderBanner(fleet);
        renderCards(state.cards);
        renderReconcile(fleet.reconcile);
        const online = state.cards.filter((n) => n.online !== false).length;
        const ar = state.cards.reduce((sum, n) => sum + (n.anomaly_rate || 0), 0);
        $('#nd-sub').textContent = `${state.cards.length} nodes · ${online} reachable · anomaly ${ar.toFixed(1)}% · source Netdata`;
    } catch (err) {
        $('#nd-sub').textContent = `Netdata unavailable: ${err.message}`;
    }
}

async function loadCapacity() {
    const hours = Number($('#nd-window').value) / 60;
    const tbody = $('#nd-capacity');
    try {
        const data = await getJson(`/api/netdata/capacity?hours=${Math.max(1, Math.round(hours))}`);
        tbody.textContent = '';
        for (const node of data.nodes || []) {
            const tr = document.createElement('tr');
            const cells = [
                node.name,
                fmtPct(node.cpu?.p95),
                fmtPct(node.mem?.p95),
                fmtPct(node.disk?.p95),
                fmtPct(node.headroom_percent),
            ];
            cells.forEach((text) => {
                const td = document.createElement('td');
                td.textContent = text;
                tr.appendChild(td);
            });
            const stateTd = document.createElement('td');
            const badge = document.createElement('span');
            badge.className = `nd-state ${node.status || 'ok'}`;
            badge.textContent = node.status || 'ok';
            stateTd.appendChild(badge);
            tr.appendChild(stateTd);
            tbody.appendChild(tr);
        }
        if (!(data.nodes || []).length) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 6;
            td.className = 'nd-muted';
            td.textContent = 'No capacity samples in this window.';
            tr.appendChild(td);
            tbody.appendChild(tr);
        }
    } catch (err) {
        tbody.textContent = '';
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 6;
        td.className = 'nd-muted';
        td.textContent = `Capacity unavailable: ${err.message}`;
        tr.appendChild(td);
        tbody.appendChild(tr);
    }
}

function alertRow(alert, isTransition) {
    const row = document.createElement('div');
    row.className = 'nd-alert';
    const when = document.createElement('time');
    const ts = Number(alert.when || 0) * 1000;
    when.textContent = ts ? new Date(ts).toLocaleString() : '–';
    const st = document.createElement('span');
    st.className = `st ${esc(alert.status || '').toUpperCase()}`;
    st.textContent = alert.status || '–';
    const text = document.createElement('span');
    text.textContent = isTransition
        ? `${alert.hostname || ''}: ${alert.alert}${alert.summary ? ` — ${alert.summary}` : ''}`
        : `${alert.node || ''}: ${alert.alert}${alert.instance ? ` (${alert.instance})` : ''}`;
    row.append(when, st, text);
    return row;
}

async function loadAlerts() {
    const box = $('#nd-alerts');
    try {
        const data = await getJson('/api/netdata/alerts?limit=80');
        box.textContent = '';
        const live = (data.alerts || []).filter((a) => ['WARNING', 'CRITICAL'].includes(String(a.status).toUpperCase()));
        live.slice(0, 12).forEach((a) => box.appendChild(alertRow(a, false)));
        const transitions = (data.transitions || []).slice(-20).reverse();
        transitions.forEach((t) => box.appendChild(alertRow(t, true)));
        if (!box.children.length) {
            const p = document.createElement('p');
            p.className = 'nd-muted';
            p.textContent = 'No active warnings and no transitions in the last 24 hours.';
            box.appendChild(p);
        }
    } catch (err) {
        box.textContent = '';
        const p = document.createElement('p');
        p.className = 'nd-muted';
        p.textContent = `Alerts unavailable: ${err.message}`;
        box.appendChild(p);
    }
}

async function loadHistory() {
    if (!state.historyHost) return;
    const minutes = Number($('#nd-modal-window').value);
    const host = state.historyHost;
    $('#nd-modal-sub').textContent = `${host.name} · last ${minutes >= 60 ? `${minutes / 60} h` : `${minutes} m`} · Netdata`;
    try {
        const data = await getJson(`/api/netdata/history?host=${encodeURIComponent(host.guid || host.name)}&window=${minutes}&points=160`);
        const series = data.series || {};
        const last = (arr) => {
            for (let i = (arr || []).length - 1; i >= 0; i -= 1) {
                if (arr[i] !== null && arr[i] !== undefined) return arr[i];
            }
            return null;
        };
        drawChart($('#nd-chart-cpu'), series['system.cpu'], '#38bdf8');
        drawChart($('#nd-chart-mem'), series['system.ram'], '#a78bfa');
        drawChart($('#nd-chart-disk'), series['disk.space'], '#f59e0b');
        drawChart($('#nd-chart-anom'), series['anomaly_detection.anomaly_rate'], '#fb7185');
        $('#nd-cpu-now').textContent = fmtPct(last(series['system.cpu']));
        $('#nd-mem-now').textContent = fmtPct(last(series['system.ram']));
        $('#nd-disk-now').textContent = fmtPct(last(series['disk.space']));
        const anom = last(series['anomaly_detection.anomaly_rate']);
        $('#nd-anom-now').textContent = anom === null ? '–' : `${Number(anom).toFixed(2)}%`;
    } catch (err) {
        $('#nd-modal-sub').textContent = `${host.name} · ${err.message}`;
    }
}

function openHistory(node) {
    state.historyHost = node;
    $('#nd-modal-title').textContent = `${node.name || node.hostname} history`;
    $('#nd-modal').classList.remove('hidden');
    loadHistory();
}

function closeHistory() {
    state.historyHost = null;
    $('#nd-modal').classList.add('hidden');
}

async function probeDiagnostics() {
    const out = $('#nd-diag-output');
    const btn = $('#nd-diag');
    btn.disabled = true;
    out.classList.remove('hidden');
    out.textContent = 'Probing…';
    try {
        const data = await getJson('/api/netdata/diagnostics');
        out.textContent = data.available
            ? `available (HTTP ${data.status})\n${data.reason}`
            : `not available (HTTP ${data.status || '—'})\n${data.reason}`;
    } catch (err) {
        out.textContent = `probe failed: ${err.message}`;
    } finally {
        btn.disabled = false;
    }
}

async function ingestAlerts() {
    const note = $('#nd-ingest-note');
    note.textContent = 'Pulling…';
    try {
        const data = await getJson('/api/netdata/ingest');
        note.textContent = `${data.added} new, ${data.skipped} already known`;
        loadAlerts();
    } catch (err) {
        note.textContent = err.message;
    }
}

/* ------------------------------------------------------------------ boot */

$('#nd-refresh').addEventListener('click', () => { loadFleet(); loadCapacity(); loadAlerts(); });
$('#nd-window').addEventListener('change', loadCapacity);
$('#nd-modal-close').addEventListener('click', closeHistory);
$('#nd-modal').addEventListener('click', (event) => { if (event.target.id === 'nd-modal') closeHistory(); });
$('#nd-modal-window').addEventListener('change', loadHistory);
$('#nd-diag').addEventListener('click', probeDiagnostics);
$('#nd-ingest').addEventListener('click', ingestAlerts);
document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closeHistory(); });

loadFleet();
loadCapacity();
loadAlerts();
state.timer = window.setInterval(() => {
    if (!document.hidden) loadFleet();
}, 5000);
state.historyTimer = window.setInterval(() => {
    if (!document.hidden && state.historyHost) loadHistory();
}, 10000);
