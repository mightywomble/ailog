// Suricata UI, tabs and stats dashboards, moved verbatim from templates/index.html.
// The three exports are the functions the core module calls.

// -----------------------------
// Suricata UI
// -----------------------------
let suricataAlertsChart = null;
let suricataCountersChart = null;
let suricataCategoryChart = null;
let currentSuricataSensorId = null;

function _suricataRangeKeyFromSlider(v) {
    const map = ['1h','6h','24h','7d'];
    return map[Math.max(0, Math.min(3, Number(v)||0))];
}

function _suricataSetRangeLabel(key) {
    const el = document.getElementById('suricata-range-label');
    if (el) el.textContent = key;
}

function setSuricataStatsButtonVisible(isVisible) {
    const btn = document.getElementById('suricata-stats-btn');
    if (!btn) return;
    btn.classList.toggle('hidden', !isVisible);
}

async function refreshSuricataConfiguredState() {
    try {
        const sensors = await window.fetchApi('/suricata/config');
        const ok = Array.isArray(sensors) && sensors.length > 0 && (sensors[0].host || sensors[0].user);
        setSuricataStatsButtonVisible(!!ok);
    } catch (e) {
        setSuricataStatsButtonVisible(false);
    }
}

function showSuricataStats() {
    const dashboardView = document.getElementById('dashboard-view');
    const logsView = document.getElementById('logs-view');
    const suriView = document.getElementById('suricata-stats-view');
    if (dashboardView) dashboardView.classList.add('hidden');
    if (logsView) logsView.classList.add('hidden');
    if (suriView) suriView.classList.remove('hidden');

    refreshSuricataStats();
}

async function loadSuricataConfigIntoForm() {
    const statusEl = document.getElementById('suricata-settings-status');
    if (statusEl) statusEl.textContent = 'Loading...';
    try {
        const sensors = await window.fetchApi('/suricata/config');
        const keys = await window.fetchApi('/ssh-keys');

        const keySel = document.getElementById('suricata-ssh-key');
        if (keySel) {
            keySel.innerHTML = '<option value="">(default)</option>';
            (keys||[]).forEach(k => {
                const opt = document.createElement('option');
                opt.value = String(k.id);
                opt.textContent = k.key_name;
                keySel.appendChild(opt);
            });
        }

        const sensor = (sensors && sensors.length) ? sensors[0] : null;
        currentSuricataSensorId = sensor ? sensor.id : null;

        document.getElementById('suricata-sensor-name').value = sensor?.name || 'Home Sniffer';
        document.getElementById('suricata-host').value = sensor?.host || 'sniffer.netbird.cloud';
        document.getElementById('suricata-user').value = sensor?.user || 'david';
        document.getElementById('suricata-log-dir').value = sensor?.log_dir || '/var/log/suricata';
        document.getElementById('suricata-sensor-enabled').checked = sensor ? !!sensor.enabled : true;
        document.getElementById('suricata-ingest-interval').value = sensor?.ingest_interval_seconds || 30;
        if (keySel) keySel.value = sensor?.ssh_key_id ? String(sensor.ssh_key_id) : '';

        if (statusEl) statusEl.textContent = sensor ? `Loaded sensor #${sensor.id}` : 'No sensor saved yet.';
    } catch (e) {
        if (statusEl) statusEl.textContent = 'Failed to load Suricata config';
    }
}

async function saveSuricataConfigFromForm() {
    const statusEl = document.getElementById('suricata-settings-status');
    if (statusEl) statusEl.textContent = 'Saving...';

    const payload = {
        id: currentSuricataSensorId,
        name: document.getElementById('suricata-sensor-name').value,
        host: document.getElementById('suricata-host').value,
        user: document.getElementById('suricata-user').value,
        log_dir: document.getElementById('suricata-log-dir').value,
        enabled: document.getElementById('suricata-sensor-enabled').checked,
        ingest_interval_seconds: Number(document.getElementById('suricata-ingest-interval').value || 30),
        ssh_key_id: document.getElementById('suricata-ssh-key').value || null,
    };

    try {
        const res = await window.fetchApi('/suricata/config', { method: 'POST', body: JSON.stringify(payload) });
        currentSuricataSensorId = res?.id || currentSuricataSensorId;
        if (statusEl) statusEl.textContent = `Saved sensor #${currentSuricataSensorId}`;
        window.showToast('Suricata settings saved', 'success');
        refreshSuricataConfiguredState();
    } catch (e) {
        if (statusEl) statusEl.textContent = 'Save failed';
    }
}

async function testSuricataConnection() {
    const out = document.getElementById('suricata-test-results');
    out.textContent = 'Testing...';
    const payload = {
        host: document.getElementById('suricata-host').value,
        user: document.getElementById('suricata-user').value,
        log_dir: document.getElementById('suricata-log-dir').value,
        ssh_key_id: document.getElementById('suricata-ssh-key').value || null,
    };
    try {
        const res = await window.fetchApi('/suricata/test', { method: 'POST', body: JSON.stringify(payload) });
        out.textContent = JSON.stringify(res, null, 2);
        window.showToast(res.ok ? 'Suricata test OK' : 'Suricata test failed', res.ok ? 'success' : 'error');
    } catch (e) {
        out.textContent = 'Test failed.';
    }
}

// Renamed from runSuricataIngestOnce: this earlier declaration was shadowed by
// the later one (the same name appears twice in the original script block, and
// a module cannot have duplicate top-level declarations). The later definition
// keeps the original name and remains the one used by the UI.
async function runSuricataIngestOnce_legacy() {
    const statusEl = document.getElementById('suricata-settings-status');
    if (statusEl) statusEl.textContent = 'Ingesting...';
    try {
        const res = await window.fetchApi('/suricata/ingest/run_once', { method: 'POST', body: JSON.stringify({ sensor_id: currentSuricataSensorId }) });
        if (statusEl) statusEl.textContent = 'Ingest complete';
        window.showToast('Suricata ingest complete', 'success');
        // Refresh charts if open
        refreshSuricataStats();
        // Show results in test pane for convenience
        const out = document.getElementById('suricata-test-results');
        if (out) out.textContent = JSON.stringify(res, null, 2);
    } catch (e) {
        if (statusEl) statusEl.textContent = 'Ingest failed';
    }
}

function _ensureSuricataCharts() {
    const alertsCtx = document.getElementById('suricata-alerts-chart');
    const countersCtx = document.getElementById('suricata-counters-chart');
    const catCtx = document.getElementById('suricata-category-chart');

    if (alertsCtx && !suricataAlertsChart) {
        suricataAlertsChart = new Chart(alertsCtx, {
            type: 'line',
            data: { labels: [], datasets: [{ label: 'Alerts', data: [], borderColor: '#a855f7', backgroundColor: 'rgba(168,85,247,0.2)', tension: 0.2 }] },
            options: { responsive: true, maintainAspectRatio: false, scales: { x: { ticks: { color: '#9ca3af' } }, y: { ticks: { color: '#9ca3af' } } }, plugins: { legend: { labels: { color: '#d1d5db' } } } }
        });
    }

    if (countersCtx && !suricataCountersChart) {
        suricataCountersChart = new Chart(countersCtx, {
            type: 'line',
            data: { labels: [], datasets: [
                { label: 'decoder.pkts', data: [], borderColor: '#60a5fa', tension: 0.2 },
                { label: 'capture.kernel_drops', data: [], borderColor: '#f59e0b', tension: 0.2 },
                { label: 'tcp.reassembly_gap', data: [], borderColor: '#22c55e', tension: 0.2 },
            ]},
            options: { responsive: true, maintainAspectRatio: false, scales: { x: { ticks: { color: '#9ca3af' } }, y: { ticks: { color: '#9ca3af' } } }, plugins: { legend: { labels: { color: '#d1d5db' } } } }
        });
    }

    if (catCtx && !suricataCategoryChart) {
        suricataCategoryChart = new Chart(catCtx, {
            type: 'doughnut',
            data: { labels: [], datasets: [{ data: [], backgroundColor: ['#a855f7','#60a5fa','#22c55e','#f59e0b','#ef4444','#14b8a6','#e879f9','#94a3b8'] }] },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: '#d1d5db' } } } }
        });
    }
}

async function refreshSuricataStats() {
    _ensureSuricataCharts();
    const slider = document.getElementById('suricata-range-slider');
    const key = _suricataRangeKeyFromSlider(slider ? slider.value : 2);
    _suricataSetRangeLabel(key);

    try {
        const url = `/suricata/stats?range=${encodeURIComponent(key)}${currentSuricataSensorId ? `&sensor_id=${currentSuricataSensorId}` : ''}`;
        const data = await window.fetchApi(url);

        // KPIs
        document.getElementById('suricata-kpi-total-alerts').textContent = data?.kpis?.total_alerts ?? '-';
        document.getElementById('suricata-kpi-alerts-per-hour').textContent = data?.kpis?.alerts_per_hour ? data.kpis.alerts_per_hour.toFixed(1) : '-';
        document.getElementById('suricata-kpi-sensor').textContent = data?.sensor?.name || data?.sensor?.host || '-';

        // Attempt to show some counters as KPIs if present
        const dropsSeries = data?.counter_series?.['capture.kernel_drops'] || [];
        const gapSeries = data?.counter_series?.['tcp.reassembly_gap'] || [];
        document.getElementById('suricata-kpi-kernel-drops').textContent = dropsSeries.length ? dropsSeries[dropsSeries.length-1].value : '-';
        document.getElementById('suricata-kpi-tcp-gaps').textContent = gapSeries.length ? gapSeries[gapSeries.length-1].value : '-';

        // Alerts chart
        if (suricataAlertsChart) {
            const labels = (data.alerts_timeseries || []).map(p => new Date(p.ts*1000).toLocaleString());
            const vals = (data.alerts_timeseries || []).map(p => p.alerts);
            suricataAlertsChart.data.labels = labels;
            suricataAlertsChart.data.datasets[0].data = vals;
            suricataAlertsChart.update();
        }

        // Counters chart (decoder.pkts, kernel_drops, tcp.gap)
        if (suricataCountersChart) {
            const base = data.counter_series || {};
            const pick = (name) => (base[name]||[]);
            const seriesA = pick('decoder.pkts');
            const labels = seriesA.map(p => new Date(p.ts*1000).toLocaleString());
            suricataCountersChart.data.labels = labels;
            const ds = suricataCountersChart.data.datasets;
            ds[0].data = seriesA.map(p => p.value);
            ds[1].data = pick('capture.kernel_drops').map(p => p.value);
            ds[2].data = pick('tcp.reassembly_gap').map(p => p.value);
            suricataCountersChart.update();
        }

        // Category chart
        if (suricataCategoryChart) {
            const labels = (data.pie_categories || []).map(p => p.category);
            const vals = (data.pie_categories || []).map(p => p.count);
            suricataCategoryChart.data.labels = labels;
            suricataCategoryChart.data.datasets[0].data = vals;
            suricataCategoryChart.update();
        }

        // Top signatures table
        const tbody = document.getElementById('suricata-top-signatures');
        if (tbody) {
            tbody.innerHTML = '';
            (data.top_signatures || []).forEach(row => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td class="py-2 pr-3">${row.signature}</td><td class="py-2 text-right">${row.count}</td>`;
                tbody.appendChild(tr);
            });
        }

    } catch (e) {
        // ignore
    }
}

// Wire events
(function initSuricataUI(){
    const btn = document.getElementById('suricata-stats-btn');
    if (btn) btn.addEventListener('click', showSuricataStats);

    const back = document.getElementById('back-to-dashboard-from-suricata');
    if (back) back.addEventListener('click', () => { window.showDashboard(); });

    const slider = document.getElementById('suricata-range-slider');
    if (slider) slider.addEventListener('input', () => { refreshSuricataStats(); });

    const testBtn = document.getElementById('suricata-test-btn');
    if (testBtn) testBtn.addEventListener('click', testSuricataConnection);

    const saveBtn = document.getElementById('suricata-save-btn');
    if (saveBtn) saveBtn.addEventListener('click', saveSuricataConfigFromForm);

    const ingestBtn = document.getElementById('suricata-ingest-once-btn');
    if (ingestBtn) ingestBtn.addEventListener('click', runSuricataIngestOnce);
})();



// -----------------------------
// Suricata tabs + richer feedback
// -----------------------------
function suricataSelectTab(tab) {
    const tabs = document.querySelectorAll('#suricata-tabs .suricata-tab');
    const panels = document.querySelectorAll('#suricata-data-section .suricata-tab-panel');
    tabs.forEach(b => {
        const active = b.dataset.tab === tab;
        b.classList.toggle('bg-purple-700', active);
        b.classList.toggle('text-white', active);
    });
    panels.forEach(p => {
        const active = p.dataset.tabPanel === tab;
        p.classList.toggle('hidden', !active);
    });
}

function _suricataLog(msg) {
    const log = document.getElementById('suricata-ingest-log');
    if (!log) return;
    const ts = new Date().toLocaleTimeString();
    log.textContent += `[${ts}] ${msg}\n`;
    log.scrollTop = log.scrollHeight;
}

async function runSuricataIngestOnce() {
    const statusEl = document.getElementById('suricata-settings-status');
    const progWrap = document.getElementById('suricata-ingest-progress');
    const progBar = document.getElementById('suricata-ingest-progress-bar');
    const btn = document.getElementById('suricata-ingest-once-btn');

    if (btn) btn.disabled = true;
    if (statusEl) statusEl.textContent = 'Ingesting...';
    if (progWrap) progWrap.classList.remove('hidden');
    if (progBar) progBar.style.width = '5%';

    _suricataLog('Starting ingest...');

    try {
        if (progBar) progBar.style.width = '15%';
        _suricataLog('Calling /suricata/ingest/run_once');

        const res = await window.fetchApi('/suricata/ingest/run_once', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sensor_id: currentSuricataSensorId })
        });

        if (progBar) progBar.style.width = '85%';
        _suricataLog('Ingest complete.');

        // Show results in test pane for convenience
        const out = document.getElementById('suricata-test-results');
        if (out) out.textContent = JSON.stringify(res, null, 2);

        // Refresh charts if open
        refreshSuricataStats();

        if (progBar) progBar.style.width = '100%';
        if (statusEl) statusEl.textContent = 'Ingest complete';
        window.showToast('Suricata ingest complete', 'success');

        setTimeout(() => {
            if (progWrap) progWrap.classList.add('hidden');
            if (progBar) progBar.style.width = '0%';
            const log = document.getElementById('suricata-ingest-log');
            if (log) log.textContent = '';
        }, 1500);

    } catch (e) {
        _suricataLog('Ingest failed: ' + (e?.message || String(e)));
        if (progBar) progBar.style.width = '100%';
        if (statusEl) statusEl.textContent = 'Ingest failed';
        window.showToast(e?.message || 'Ingest failed', 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function refreshSuricataEndpoints() {
    const statusEl = document.getElementById('suricata-endpoints-status');
    const tbody = document.getElementById('suricata-endpoints-table');
    const filterEl = document.getElementById('suricata-endpoints-search');
    if (!tbody) return;

    if (statusEl) statusEl.textContent = 'Loading...';
    tbody.innerHTML = '';

    const slider = document.getElementById('suricata-range-slider');
    const range = _suricataRangeKeyFromSlider(slider ? slider.value : 2);

    try {
        const url = `/suricata/endpoints?range=${encodeURIComponent(range)}${currentSuricataSensorId ? `&sensor_id=${currentSuricataSensorId}` : ''}`;
        const data = await window.fetchApi(url);
        const q = (filterEl?.value || '').trim().toLowerCase();
        const rows = (data.endpoints || []).filter(r => !q || String(r.endpoint||'').toLowerCase().includes(q));

        rows.forEach(r => {
            const tr = document.createElement('tr');
            const protos = (r.top_protocols||[]).map(p => `${String(p.name||'')}:${p.count}`).join(', ');
            const srcs = (r.top_sources||[]).map(p => `${p.ip}:${p.count}`).join(', ');
            tr.innerHTML = `
                <td class="py-2 px-3">${String(r.endpoint||'')}</td>
                <td class="py-2 px-3 text-right">${r.alerts}</td>
                <td class="py-2 px-3">${protos}</td>
                <td class="py-2 px-3">${srcs}</td>
            `;
            tbody.appendChild(tr);
        });

        if (statusEl) statusEl.textContent = `Loaded ${rows.length} endpoints`;
    } catch (e) {
        if (statusEl) statusEl.textContent = 'Failed to load endpoints';
    }
}

async function refreshSuricataRaw() {
    const out = document.getElementById('suricata-raw-output');
    const statusEl = document.getElementById('suricata-raw-status');
    if (!out) return;

    out.textContent = 'Loading...';
    if (statusEl) statusEl.textContent = '';

    const payload = {
        sensor_id: currentSuricataSensorId,
        filename: document.getElementById('suricata-raw-file')?.value,
        query: document.getElementById('suricata-raw-query')?.value,
        max_lines: Number(document.getElementById('suricata-raw-lines')?.value || 500),
    };

    try {
        const res = await window.fetchApi('/suricata/raw', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        out.textContent = res.content || '';
        if (statusEl) statusEl.textContent = `${res.filename} loaded`;
    } catch (e) {
        out.textContent = '(failed to load raw)';
        if (statusEl) statusEl.textContent = 'Failed';
    }
}

// Extra wiring for Suricata tabs
(function initSuricataTabs(){
    const tabBtns = document.querySelectorAll('#suricata-tabs .suricata-tab');
    tabBtns.forEach(b => b.addEventListener('click', () => {
        suricataSelectTab(b.dataset.tab);
        if (b.dataset.tab === 'endpoints') refreshSuricataEndpoints();
    }));

    document.getElementById('suricata-endpoints-refresh-btn')?.addEventListener('click', refreshSuricataEndpoints);
    document.getElementById('suricata-endpoints-search')?.addEventListener('input', refreshSuricataEndpoints);

    document.getElementById('suricata-raw-refresh-btn')?.addEventListener('click', refreshSuricataRaw);

    // default tab
    suricataSelectTab('server');
})();


async function loadSuricataPromptSettings() {
    const ta = document.getElementById('suricata-ai-prompt');
    const st = document.getElementById('suricata-prompt-save-status');
    if (!ta) return;
    try {
        const data = await window.fetchApi('/suricata/prompt');
        ta.value = data.prompt || '';
        if (st) st.textContent = '';
    } catch (e) { if (st) st.textContent = 'Failed to load'; }
}
async function saveSuricataPromptSettings() {
    const ta = document.getElementById('suricata-ai-prompt');
    const st = document.getElementById('suricata-prompt-save-status');
    if (!ta) return;
    if (st) st.textContent = 'Saving...';
    try {
        const data = await window.fetchApi('/suricata/prompt', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({prompt: ta.value})
        });
        ta.value = data.prompt || ta.value;
        if (st) st.textContent = 'Saved.';
        window.showToast('Suricata prompt saved', 'success');
    } catch (e) { if (st) st.textContent = 'Save failed.'; }
}
document.getElementById('save-suricata-prompt-btn')?.addEventListener('click', saveSuricataPromptSettings);


function suricataStatsSelectTab(tab) {
    document.querySelectorAll('#suricata-stats-tabs .suricata-stats-tab').forEach(b => {
        const active = b.dataset.suriTab === tab;
        b.classList.toggle('bg-purple-700', active);
        b.classList.toggle('text-white', active);
    });
    document.querySelectorAll('#suricata-stats-view .suricata-stats-panel').forEach(panel => {
        panel.classList.toggle('hidden', panel.dataset.suriPanel !== tab);
    });
}

async function refreshSuricataEndpoints2() {
    const statusEl = document.getElementById('suricata-endpoints-status2');
    const tbody = document.getElementById('suricata-endpoints-table2');
    const sourcesTbody = document.getElementById('suricata-top-sources-table');
    const filterEl = document.getElementById('suricata-endpoints-search2');
    const kTotal = document.getElementById('suricata-endpoints-kpi-total');
    const kAlerts = document.getElementById('suricata-endpoints-kpi-alerts');
    const kTopPort = document.getElementById('suricata-endpoints-kpi-top-port');
    const kTopEndpoint = document.getElementById('suricata-endpoints-kpi-top-endpoint');

    if (!tbody) return;
    if (statusEl) statusEl.textContent = 'Loading...';
    tbody.innerHTML = '';
    if (sourcesTbody) sourcesTbody.innerHTML = '';

    const slider = document.getElementById('suricata-range-slider');
    const range = _suricataRangeKeyFromSlider(slider ? slider.value : 2);
    const url = '/suricata/endpoint_stats?range=' + encodeURIComponent(range) + (currentSuricataSensorId ? '&sensor_id=' + currentSuricataSensorId : '');

    try {
        const data = await window.fetchApi(url);
        const eps = data.alerts_by_endpoint || [];
        const ports = data.alerts_by_port || [];
        const matrix = data.endpoint_port_matrix || [];
        const topSources = data.top_sources || [];

        const q = (filterEl ? filterEl.value : '').trim().toLowerCase();
        const epsFiltered = eps.filter(r => !q || String(r.endpoint || '').toLowerCase().includes(q));

        epsFiltered.forEach(r => {
            const tr = document.createElement('tr');
            tr.innerHTML = '<td class="py-2 px-3">' + (r.endpoint || '') + '</td><td class="py-2 px-3 text-right">' + (r.alerts || 0) + '</td>';
            tbody.appendChild(tr);
        });

        // KPIs
        if (kTotal) kTotal.textContent = String((data.total_endpoints !== undefined) ? data.total_endpoints : (eps.length || '-'));
        const totalAlerts = eps.reduce((acc, r) => acc + (Number(r.alerts) || 0), 0);
        if (kAlerts) kAlerts.textContent = String(totalAlerts);
        if (kTopPort) kTopPort.textContent = ports.length ? (String(ports[0].port) + ' (' + ports[0].alerts + ')') : '-';
        if (kTopEndpoint) kTopEndpoint.textContent = eps.length ? (String(eps[0].endpoint) + ' (' + eps[0].alerts + ')') : '-';

        // Top sources table
        if (sourcesTbody) {
            topSources.forEach(row => {
                const srcs = (row.sources || []).map(s => (s.ip + ':' + s.count)).join(', ');
                const tr = document.createElement('tr');
                tr.innerHTML = '<td class="py-2 px-3">' + (row.endpoint || '') + '</td><td class="py-2 px-3">' + srcs + '</td>';
                sourcesTbody.appendChild(tr);
            });
        }

        const pieCanvas = document.getElementById('suricata-endpoints-pie');
        const portCanvas = document.getElementById('suricata-ports-bar');
        const stackedCanvas = document.getElementById('suricata-endpoint-ports-stacked');

        const palette = [
            'rgba(168, 85, 247, 0.55)',
            'rgba(59, 130, 246, 0.55)',
            'rgba(16, 185, 129, 0.55)',
            'rgba(245, 158, 11, 0.55)',
            'rgba(239, 68, 68, 0.55)',
            'rgba(236, 72, 153, 0.55)',
            'rgba(34, 197, 94, 0.55)',
            'rgba(14, 165, 233, 0.55)'
        ];

        // Pie: top 10 endpoints + Other
        if (pieCanvas && window.Chart) {
            const top = eps.slice(0, 10);
            const other = eps.slice(10).reduce((acc, r) => acc + (Number(r.alerts) || 0), 0);
            const labels = top.map(x => x.endpoint);
            const values = top.map(x => x.alerts);
            const colors = top.map((_, i) => palette[i % palette.length]);
            if (other > 0) { labels.push('Other'); values.push(other); colors.push('rgba(148, 163, 184, 0.5)'); }

            const ctx = pieCanvas.getContext('2d');
            if (window.suricataEndpointsPieChart) window.suricataEndpointsPieChart.destroy();
            window.suricataEndpointsPieChart = new Chart(ctx, {
                type: 'doughnut',
                data: { labels, datasets: [{ data: values, backgroundColor: colors }] },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } }
            });
        }

        // Bar: ports top 12
        if (portCanvas && window.Chart) {
            const topP = ports.slice(0, 12);
            const labels = topP.map(x => String(x.port));
            const values = topP.map(x => x.alerts);

            const ctx = portCanvas.getContext('2d');
            if (window.suricataPortsBarChart) window.suricataPortsBarChart.destroy();
            window.suricataPortsBarChart = new Chart(ctx, {
                type: 'bar',
                data: { labels, datasets: [{ label: 'Alerts', data: values, backgroundColor: 'rgba(168, 85, 247, 0.6)' }] },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
            });
        }

        // Stacked: top endpoints x top ports
        if (stackedCanvas && window.Chart) {
            const epsTop = eps.slice(0, 10).map(x => x.endpoint);
            const portsTop = ports.slice(0, 6).map(x => x.port);
            const byKey = {};
            matrix.forEach(r => { byKey[String(r.endpoint) + '|' + String(r.port)] = r.alerts; });

            const datasets = portsTop.map((port, idx) => ({
                label: 'Port ' + port,
                data: epsTop.map(ep => byKey[String(ep) + '|' + String(port)] || 0),
                backgroundColor: palette[idx % palette.length]
            }));

            const ctx = stackedCanvas.getContext('2d');
            if (window.suricataEndpointPortStacked) window.suricataEndpointPortStacked.destroy();
            window.suricataEndpointPortStacked = new Chart(ctx, {
                type: 'bar',
                data: { labels: epsTop, datasets },
                options: { responsive: true, maintainAspectRatio: false, scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } }, plugins: { legend: { position: 'bottom' } } }
            });
        }

        if (statusEl) statusEl.textContent = 'Loaded ' + epsFiltered.length + ' endpoints';
    } catch (e) {
        if (statusEl) statusEl.textContent = 'Failed';
    }
}

let _suricataRawContent2 = '';

async function refreshSuricataRaw2() {
    const statusEl = document.getElementById('suricata-raw-status2');
    const tbody = document.getElementById('suricata-raw-table2');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (statusEl) statusEl.textContent = 'Loading...';
    const fileEl = document.getElementById('suricata-raw-file2');
    const queryEl = document.getElementById('suricata-raw-query2');
    const linesEl = document.getElementById('suricata-raw-lines2');
    try {
        const res = await window.fetchApi('/suricata/raw', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({
                sensor_id: currentSuricataSensorId,
                filename: fileEl ? fileEl.value : 'suricata.log',
                query: queryEl ? queryEl.value : '',
                max_lines: Number(linesEl ? linesEl.value : 500)
            })
        });
        _suricataRawContent2 = res.content || '';
        const lines = _suricataRawContent2.split('\n');
        lines.forEach((line, i) => {
            const tr = document.createElement('tr');
            tr.innerHTML = '<td class="py-1 px-3 text-right termix-muted">' + (i+1) + '</td><td class="py-1 px-3 whitespace-pre-wrap">' + (line || '') + '</td>';
            tbody.appendChild(tr);
        });
        if (statusEl) statusEl.textContent = (res.filename || '') + ' loaded (' + lines.length + ' lines)';
    } catch(e) { if (statusEl) statusEl.textContent = 'Failed'; }
}

async function analyseSuricataRaw2() {
    const btn = document.getElementById('suricata-raw-ai-btn2');
    if (!_suricataRawContent2) { window.showToast('Load raw data first.', 'error'); return; }
    const provider = localStorage.getItem('analysis_provider') || 'openai';
    if (provider === 'ollama') {
        if (!localStorage.getItem('ollama_url') || !localStorage.getItem('ollama_model')) {
            window.showToast('Ollama not configured.', 'error'); return;
        }
    } else {
        if (!localStorage.getItem('openai_api_key')) {
            window.showToast('OpenAI API Key missing.', 'error'); return;
        }
    }
    if (btn) { btn.textContent = 'Analysing...'; btn.disabled = true; }
    const modal = document.getElementById('ai-analysis-modal');
    const content = document.getElementById('ai-analysis-content');
    modal.classList.remove('hidden');
    const fileEl = document.getElementById('suricata-raw-file2');
    const providerLabel = ({ openai: 'OpenAI', ollama: 'Ollama', openrouter: 'OpenRouter' })[provider] || provider;
    if (window.renderAiAnalysisProgress) window.renderAiAnalysisProgress(content, providerLabel);
    if (window.setAiAnalysisStage) window.setAiAnalysisStage('prepare', 'Preparing Suricata data...', 0);

    const startedAt = Date.now();
    const timer = setInterval(() => {
        if (window.setAiAnalysisStage) {
            window.setAiAnalysisStage('waiting', 'Waiting for model response...', Math.round((Date.now() - startedAt) / 1000));
        }
    }, 1000);

    try {
        const body = {
            log_content: _suricataRawContent2,
            log_name: 'Suricata ' + (fileEl ? fileEl.value : 'raw'),
            provider: provider
        };
        if (provider === 'openai') body.api_key = localStorage.getItem('openai_api_key');
        if (window.setAiAnalysisStage) window.setAiAnalysisStage('contact', `Contacting ${providerLabel}...`, 0);
        const data = await window.fetchApi('/suricata/analyse', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify(body)
        });
        clearInterval(timer);
        if (window.setAiAnalysisStage) window.setAiAnalysisStage('format', 'Formatting result...', Math.round((Date.now() - startedAt) / 1000));
        if (window.renderMarkdownInto) window.renderMarkdownInto(content, data.analysis);
        else content.textContent = data.analysis || '';
        window.showToast('Analysis complete using ' + provider.toUpperCase());
    } catch(e) {
        clearInterval(timer);
        content.innerHTML = '<p class="text-red-400"><strong>Failed:</strong><br>' + (window.escapeHtml ? window.escapeHtml(e.message) : e.message) + '</p>';
    } finally {
        clearInterval(timer);
        if (btn) { btn.textContent = 'AI Analyse'; btn.disabled = false; }
    }
}

(function initSuricataStatsDashboards() {
    document.querySelectorAll('#suricata-stats-tabs .suricata-stats-tab').forEach(b => {
        b.addEventListener('click', () => {
            const tab = b.dataset.suriTab;
            suricataStatsSelectTab(tab);
            if (tab === 'endpoints') refreshSuricataEndpoints2();
        });
    });
    document.getElementById('suricata-endpoints-refresh-btn2') && document.getElementById('suricata-endpoints-refresh-btn2').addEventListener('click', refreshSuricataEndpoints2);
    document.getElementById('suricata-endpoints-search2') && document.getElementById('suricata-endpoints-search2').addEventListener('input', refreshSuricataEndpoints2);
    document.getElementById('suricata-raw-refresh-btn2') && document.getElementById('suricata-raw-refresh-btn2').addEventListener('click', refreshSuricataRaw2);
    document.getElementById('suricata-raw-ai-btn2') && document.getElementById('suricata-raw-ai-btn2').addEventListener('click', analyseSuricataRaw2);
    suricataStatsSelectTab('overview');
})();

export { loadSuricataConfigIntoForm, loadSuricataPromptSettings, refreshSuricataConfiguredState };
