/* Overview cards — the dashboard's card vocabulary (Option C).
 *
 * One read-only aggregate feeds all three cards:
 *   GET /api/overview   fleet live stats + active/recent alerts + recent reports
 *
 * The server tags the response with an ETag, so an unchanged dashboard is a
 * 304 with no body; failures back off exponentially up to a minute.
 *
 * It adds no state of its own: refresh replaces the card contents, and the
 * whole block is skipped while the dashboard is not the visible view.
 */

(function initOverview() {
    const mount = document.getElementById('overview-cards');
    if (!mount) return;

    const POLL_MS = 6000;
    let timer = null;
    let busy = false;

    const fmtBytes = (n) => {
        if (n === null || n === undefined || Number.isNaN(Number(n))) return '–';
        const v = Number(n);
        const units = ['B', 'kB', 'MB', 'GB', 'TB', 'PB'];
        if (!v) return '0 B';
        const i = Math.min(Math.floor(Math.log(Math.abs(v)) / Math.log(1000)), units.length - 1);
        const scaled = v / 1000 ** i;
        return `${scaled.toFixed(scaled >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
    };

    const fmtPct = (v) => (v === null || v === undefined ? '–' : `${Number(v).toFixed(0)}%`);

    const timeAgo = (value) => {
        if (!value) return '';
        const then = new Date(value).getTime();
        if (Number.isNaN(then)) return '';
        const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
        if (secs < 60) return `${secs}s ago`;
        if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
        if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
        return `${Math.round(secs / 86400)}d ago`;
    };

    const esc = (value) => String(value ?? '')
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

    const getJson = async (url) => {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        let res;
        try {
            res = await fetch(url, { headers: { Accept: 'application/json' }, signal: controller.signal });
        } finally {
            clearTimeout(timeout);
        }
        if (!res.ok) throw new Error(`${res.status}`);
        return res.json();
    };

    const dashboardVisible = () => {
        const view = document.getElementById('dashboard-view');
        return !!view && !view.classList.contains('hidden') && !document.hidden;
    };

    /* ------------------------------------------------------------- render */

    function renderFleet(servers) {
        const online = servers.filter((s) => s.online !== false);
        const cpu = online.map((s) => s.cpu?.percent).filter((v) => v !== null && v !== undefined);
        const mem = online.map((s) => s.mem?.percent).filter((v) => v !== null && v !== undefined);
        const avg = (arr) => (arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : null);
        const docker = servers.filter((s) => s.docker?.installed).length;
        const running = servers.reduce((sum, s) => sum + (s.docker?.containers_running || 0), 0);

        return `
          <div class="ov-card" data-ov="fleet">
            <div class="ov-card-head">
              <h3>Fleet</h3>
              <span class="ov-chip ${online.length === servers.length && servers.length ? 'is-ok' : 'is-warn'}">
                ${online.length}/${servers.length} online
              </span>
            </div>
            <div class="ov-metrics">
              <div class="ov-metric"><span>CPU</span><strong>${fmtPct(avg(cpu))}</strong>
                <div class="ov-bar"><i style="width:${Math.min(100, avg(cpu) || 0)}%;background:var(--chart-1)"></i></div></div>
              <div class="ov-metric"><span>RAM</span><strong>${fmtPct(avg(mem))}</strong>
                <div class="ov-bar"><i style="width:${Math.min(100, avg(mem) || 0)}%;background:var(--chart-2)"></i></div></div>
              <div class="ov-metric"><span>Docker hosts</span><strong>${docker}</strong>
                <div class="ov-sub">${running} containers running</div></div>
              <div class="ov-metric"><span>Offline</span>
                <strong class="${servers.length - online.length ? 'ov-bad' : ''}">${servers.length - online.length}</strong>
                <div class="ov-sub">${!servers.length ? 'no hosts configured'
                    : (servers.length === online.length ? 'all reachable' : `${servers.length - online.length} unreachable`)}</div></div>
            </div>
          </div>`;
    }

    function renderAlerts(data) {
        const active = data?.active || [];
        const events = (data?.events || []).slice(0, 4);
        const rows = (active.length ? active : events).slice(0, 4).map((e) => {
            const sev = (e.severity || 'warning').toLowerCase();
            const label = e.rule_name || e.message || e.metric || 'alert';
            return `<li class="ov-row">
                <span class="ov-sev is-${esc(sev)}"></span>
                <span class="ov-row-main">${esc(label)}</span>
                <span class="ov-row-meta">${esc(e.host_label || e.host_key || '')}</span>
              </li>`;
        }).join('');

        return `
          <div class="ov-card" data-ov="alerts">
            <div class="ov-card-head">
              <h3>Alerts</h3>
              <a href="/alerts" class="ov-link">Open</a>
            </div>
            ${active.length
                ? `<div class="ov-big-number ov-bad">${active.length}<span>active</span></div>`
                : '<div class="ov-big-number ov-good">0<span>active</span></div>'}
            <ul class="ov-rows">${rows || '<li class="ov-row"><span class="ov-row-main ov-sub">Nothing firing.</span></li>'}</ul>
          </div>`;
    }

    function renderReports(data) {
        const reports = (data?.reports || []).slice(0, 4);
        const rows = reports.map((r) => {
            const verdict = (r.verdict || 'unknown').toLowerCase();
            return `<li class="ov-row">
                <span class="ov-verdict is-${esc(verdict)}">${esc(verdict)}</span>
                <a class="ov-row-main" href="/reports/${esc(r.id)}?embed=1" data-ov-report="${esc(r.id)}">${esc(r.host_label || r.host_key)}</a>
                <span class="ov-row-meta">${esc(timeAgo(r.created_at))}</span>
              </li>`;
        }).join('');

        return `
          <div class="ov-card" data-ov="reports">
            <div class="ov-card-head">
              <h3>Recent reports</h3>
              <button type="button" class="ov-link" data-ov-open-reports>Open</button>
            </div>
            <ul class="ov-rows">${rows || '<li class="ov-row"><span class="ov-row-main ov-sub">No server reports yet.</span></li>'}</ul>
          </div>`;
    }

    function renderError(what, err) {
        return `
          <div class="ov-card" data-ov="error">
            <div class="ov-card-head"><h3>${esc(what)}</h3></div>
            <p class="ov-sub">Could not load: ${esc(err.message || err)}</p>
          </div>`;
    }

    /* --------------------------------------------------------------- poll */

    // The server aggregates all three cards into /api/overview and returns an
    // ETag, so an unchanged dashboard answers 304 and costs no payload.
    const result = { servers: null, alerts: null, reports: null };
    let painted = false;
    let etag = null;
    let failures = 0;
    let nextDelay = POLL_MS;

    function skeletonCard(title) {
        return `
          <div class="ov-card" data-ov-skeleton>
            <div class="ov-card-head"><h3>${esc(title)}</h3></div>
            <div class="ov-skeleton-line"></div>
            <div class="ov-skeleton-line short"></div>
          </div>`;
    }

    function paint() {
        const cards = [];
        if (result.servers === null) {
            cards.push(skeletonCard('Fleet'));
        } else if (result.servers.error) {
            cards.push(renderError('Fleet', result.servers.error));
        } else {
            const list = result.servers.data?.servers || [];
            cards.push(renderFleet(list));
        }

        if (result.alerts === null) cards.push(skeletonCard('Alerts'));
        else cards.push(result.alerts.error ? renderError('Alerts', result.alerts.error) : renderAlerts(result.alerts.data));

        if (result.reports === null) cards.push(skeletonCard('Recent reports'));
        else cards.push(result.reports.error ? renderError('Reports', result.reports.error) : renderReports(result.reports.data));

        mount.innerHTML = cards.join('');
        mount.dataset.updated = new Date().toISOString();
        painted = true;

        // A report is read next to the fleet it came from: open it in the dialog.
        mount.querySelectorAll('[data-ov-report]').forEach((link) => {
            link.addEventListener('click', (event) => {
                if (typeof window.openReportModal !== 'function') return;   // href still works
                event.preventDefault();
                window.openReportModal(link.dataset.ovReport);
            });
        });

        mount.querySelector('[data-ov-open-reports]')?.addEventListener('click', () => {
            if (typeof window.openReportsModal === 'function') window.openReportsModal(null, '');
            else window.open('/reports', '_blank', 'noopener');
        });
    }

    /* Fetch the aggregate. Returns false when the server said "not modified". */
    async function loadOverview() {
        const headers = { Accept: 'application/json' };
        if (etag) headers['If-None-Match'] = etag;

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 6000);
        let res;
        try {
            res = await fetch('/api/overview', { headers, signal: controller.signal });
        } finally {
            clearTimeout(timeout);
        }

        if (res.status === 304) return false;
        if (!res.ok) throw new Error(`overview ${res.status}`);

        etag = res.headers.get('ETag') || etag;
        const payload = await res.json();
        const section = (value) => (value && value.error ? { error: value } : { data: value });
        result.servers = section(payload.servers);
        result.alerts = section(payload.alerts);
        result.reports = section(payload.reports);
        return true;
    }

    async function refresh() {
        if (busy || !dashboardVisible()) return;
        busy = true;

        try {
            if (!painted) {
                result.servers = result.alerts = result.reports = null;
                paint();
            }
            const changed = await loadOverview();
            if (changed) {
                failures = 0;
                nextDelay = POLL_MS;
                if (dashboardVisible()) paint();
            }
        } catch (error) {
            // Back off instead of hammering a box that is already struggling.
            failures += 1;
            nextDelay = Math.min(Math.round(POLL_MS * Math.pow(1.6, failures)), 60000);
            if (!painted) {
                result.servers = result.alerts = result.reports = { error };
                paint();
            }
        } finally {
            busy = false;
        }
    }

    function schedule() {
        clearTimeout(timer);
        timer = setTimeout(async () => {
            if (dashboardVisible()) await refresh();
            schedule();
        }, nextDelay);
    }

    document.addEventListener('visibilitychange', () => {
        if (!document.hidden && dashboardVisible()) {
            nextDelay = POLL_MS;
            refresh();
        }
    });
    window.addEventListener('themechange', () => refresh());

    window.refreshOverview = refresh;
    window.overviewPollState = () => ({ delay: nextDelay, failures, etag });
    refresh();
    schedule();
})();
