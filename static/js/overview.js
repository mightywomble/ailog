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

    // The API sends naive UTC timestamps ("2026-10-30T21:12:00"), which a
    // browser would read as local time — eleven hours out in Australia. Treat
    // a stamp without a zone as UTC.
    const parseServerTime = (value) => {
        if (!value) return null;
        const text = String(value).trim();
        if (!text) return null;
        const zoned = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(text) ? text : `${text}Z`;
        const then = new Date(zoned).getTime();
        return Number.isNaN(then) ? null : then;
    };

    const timeAgo = (value) => {
        const then = parseServerTime(value);
        if (then === null) return '';
        const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
        if (secs < 60) return `${secs}s ago`;
        if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
        if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
        return `${Math.round(secs / 86400)}d ago`;
    };

    // "30 Oct, 21:12" in the viewer's own timezone, for people who need the
    // actual moment rather than "3h ago".
    const fmtWhen = (value) => {
        const then = parseServerTime(value);
        if (then === null) return '';
        try {
            return new Date(then).toLocaleString(undefined, {
                day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit',
            });
        } catch (error) {
            return new Date(then).toISOString().slice(0, 16).replace('T', ' ');
        }
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
        const down = servers.length - online.length;
        const allUp = !!servers.length && down === 0;

        return `
          <div class="ov-card" data-ov="fleet">
            <div class="ov-card-head">
              <h3>Fleet</h3>
              <button type="button"
                      class="ov-chip ${allUp ? 'is-ok' : 'is-warn'}"
                      data-ov-offline-jump
                      aria-controls="ov-card-offline"
                      title="${down ? 'Show the devices that are offline' : 'Every device answered the last probe'}">
                ${online.length}/${servers.length} online${down ? ' &middot; see offline' : ''}
              </button>
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

    /* Its own card: "which ones, and since when?" is a different question from
     * "how is the fleet doing", so it gets a square of its own instead of being
     * squeezed into the fleet metrics. */
    function renderOffline(servers) {
        const down = servers.filter((s) => s.online === false);
        const rows = down.map((s) => {
            const when = fmtWhen(s.last_seen);
            const ago = timeAgo(s.last_seen);
            return `<li class="ov-row" title="${esc(s.error || '')}">
                <span class="ov-sev is-critical"></span>
                <span class="ov-row-stack">
                  <span class="ov-row-main">${esc(s.name || s.host_key || 'unknown host')}</span>
                  <span class="ov-row-sub">${esc(s.ip || '')}${s.host_key ? ` &middot; ${esc(s.host_key)}` : ''}</span>
                </span>
                <span class="ov-when">
                  ${ago ? `<strong>${esc(ago)}</strong>` : '<strong class="ov-sub">no record</strong>'}
                  <span>${when ? `last online ${esc(when)}` : 'last online unknown'}</span>
                </span>
              </li>`;
        }).join('');

        return `
          <div class="ov-card" id="ov-card-offline" data-ov="offline" tabindex="-1">
            <div class="ov-card-head">
              <h3>Offline devices</h3>
              <a href="/metrics" class="ov-link">Monitor</a>
            </div>
            ${down.length
                ? `<div class="ov-big-number ov-bad">${down.length}<span>offline</span></div>
                   <ul class="ov-rows" tabindex="0" aria-label="Offline devices and when they were last online">${rows}</ul>`
                : `<div class="ov-big-number ov-good">0<span>offline</span></div>
                   <p class="ov-sub">${servers.length ? 'Every configured device answered the last probe.' : 'No hosts configured yet.'}</p>`}
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

    /* Docker updates: "what can I actually update right now?".
     *
     * The estate has seventeen hosts and the answer used to live three clicks
     * down - pick the host, press its Docker square, read its list. This card
     * puts every container the registry has moved on from in one place, and a
     * row is a link to that container's home: the host's Docker pane.
     *
     * The section comes from the background scan cache (see overview/routes.py),
     * so it can lag by one scan. That is the right trade: the dashboard polls
     * every six seconds and must never wait on the slowest SSH round. */
    function renderDockerUpdates(section) {
        if (!section) return skeletonCard('Docker updates');
        if (section.error) {
            const err = section.error;
            return renderError('Docker updates', err.message || err.error || err);
        }
        const data = section.data || {};
        const rows = data.rows || [];
        const count = Number(data.count || 0);
        const hosts = Number(data.hosts || 0);
        const pending = (data.pending || []).length;

        const chips = [
            `<span class="ov-chip ${count ? 'is-warn' : 'is-ok'}">${count
                ? `${count} update${count === 1 ? '' : 's'} available`
                : 'all images current'}</span>`,
            count && hosts ? `<span class="ov-chip">${hosts} host${hosts === 1 ? '' : 's'}</span>` : '',
            estate ? `<span class="ov-chip is-warn" title="Pinned in wizard.yaml behind the newest upstream release - updated through the estate, not on the host">${estate} estate</span>` : '',
            pending ? `<span class="ov-chip" title="A background scan is filling these in">checking ${pending}…</span>` : '',
        ].filter(Boolean).join(' ');

        const estate = Number(data.estate || 0);

        const items = rows.map((row) => {
            // Two kinds of "needs an update": a pin that is behind its upstream
            // release (``estate``, 0.9.1 → 0.17.2) and a tag whose digest moved
            // (``digest``, aabb → ccdd). The label says which, because they are
            // updated in different places.
            const label = row.kind === 'estate' ? (row.service || row.container) : row.container;
            const move = (row.from && row.to)
                ? `<span class="ov-row-meta font-mono" title="${esc(row.from)} → ${esc(row.to)}">${esc(String(row.from).slice(0, 12))} → ${esc(String(row.to).slice(0, 12))}</span>`
                : '';
            return `<li class="ov-row">
                <span class="ov-sev is-warning"></span>
                <button type="button" class="ov-row-main ov-row-link"
                        data-ov-update="${esc(row.host_key)}"
                        data-ov-update-container="${esc(row.container)}"
                        title="Open ${esc(row.host)}'s Docker list and update ${esc(label || 'this container')}">
                  ${esc(label || row.image || 'container')}${row.containers > 1 ? ` <span class="ov-sub">×${esc(row.containers)}</span>` : ''}
                </button>
                <span class="ov-row-stack ov-row-host">
                  <span class="ov-row-main">${esc(row.host)}</span>
                  <span class="ov-row-sub">${esc(row.image || '')}</span>
                </span>
                ${move}
              </li>`;
        }).join('');

        return `
          <div class="ov-card" data-ov="docker-updates">
            <div class="ov-card-head">
              <h3>Docker updates</h3>
              <button type="button" class="ov-link" data-ov-check-all
                      title="Scan every host now instead of waiting for the next round">Check all hosts</button>
            </div>
            <div class="ov-nd-head">${chips}</div>
            ${rows.length
                ? `<ul class="ov-rows" aria-label="Containers with a newer image">${items}</ul>`
                : `<p class="ov-sub">${count
                    ? `…and ${count} more on other hosts.`
                    : (pending
                        ? 'Scanning the estate for the first time — this fills in as hosts answer.'
                        : 'Nothing to update: every scanned container is on its current image.')}</p>`}
            ${data.more ? `<p class="ov-sub">…and ${data.more} more on other hosts.</p>` : ''}
          </div>`;
    }

    /* Netdata fleet card: the same numbers as /netdata, compressed to the
     * question a dashboard asks — "which machine is behaving unusually?".
     * Cards are already anomaly-first; here we show the top few and let the
     * full page carry the drill-down. */
    function renderNetdata() {
        const nd = window.__ovNetdata;
        if (!nd) return '';
        if (nd.error) {
            return `
              <div class="ov-card" data-ov="netdata">
                <div class="ov-card-head">
                  <h3>Netdata</h3>
                  <a href="/netdata" class="ov-link">Open</a>
                </div>
                <p class="ov-sub">Not reachable: ${esc(nd.error)}</p>
                <p class="ov-sub"><a class="ov-link" href="/">Check Settings → Netdata</a></p>
              </div>`;
        }
        const nodes = nd.nodes || [];
        const online = nodes.filter((n) => n.online !== false);
        // Netdata's ML anomaly rate is a percentage of metrics behaving unusually;
        // a few hundredths is normal background noise. At or above half a percent
        // is worth putting on the dashboard.
        const anomalies = nodes.filter((n) => Number(n.anomaly_rate || 0) >= 0.5);
        const alerts = nodes.reduce((sum, n) => sum + (n.alerts?.warning || 0) + (n.alerts?.critical || 0), 0);
        const quality = nd.quality || {};
        const streamingIssues = (quality.unstable || []).length + (quality.not_streaming || []).length;
        const top = [...nodes]
            .sort((a, b) => (b.anomaly_rate || 0) - (a.anomaly_rate || 0)
                || (b.cpu_percent || 0) - (a.cpu_percent || 0))
            .slice(0, 4);
        const rows = top.map((n) => {
            const ar = Number(n.anomaly_rate || 0);
            const cpu = Number(n.cpu_percent || 0);
            const mem = Number(n.mem_percent || 0);
            const cls = cpu >= 90 ? 'is-bad' : (cpu >= 75 ? 'is-warn' : '');
            return `
              <li class="ov-row ov-nd-row">
                <span class="ov-sev ${ar > 0 ? 'is-warning' : ''}" title="${ar > 0 ? `ML anomaly ${ar.toFixed(2)}%` : 'No anomaly'}"></span>
                <a class="ov-row-main" href="/netdata">${esc(n.name || n.hostname || 'node')}</a>
                <span class="ov-nd-metrics ${cls}">
                  <span title="CPU">CPU ${fmtPct(cpu)}</span>
                  <span title="RAM">RAM ${fmtPct(mem)}</span>
                  ${ar > 0 ? `<span class="ov-nd-anom" title="Netdata ML anomaly rate">ML ${ar.toFixed(2)}%</span>` : ''}
                </span>
              </li>`;
        }).join('');

        return `
          <div class="ov-card" data-ov="netdata">
            <div class="ov-card-head">
              <h3>Netdata</h3>
              <a href="/netdata" class="ov-link">Open fleet</a>
            </div>
            <div class="ov-nd-head">
              <span class="ov-chip ${online.length === nodes.length ? 'is-ok' : 'is-warn'}">${online.length}/${nodes.length} online</span>
              <span class="ov-chip ${anomalies.length ? 'is-warn' : 'is-ok'}">${anomalies.length} anomalous</span>
              <span class="ov-chip ${alerts ? 'is-warn' : 'is-ok'}">${alerts} alert${alerts === 1 ? '' : 's'}</span>
              <span class="ov-chip ${streamingIssues ? 'is-warn' : 'is-ok'}">${streamingIssues ? `${streamingIssues} streaming issue${streamingIssues === 1 ? '' : 's'}` : 'streaming ok'}</span>
            </div>
            <ul class="ov-rows ov-nd-rows">${rows || '<li class="ov-row"><span class="ov-row-main ov-sub">No nodes reported.</span></li>'}</ul>
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
    const result = { servers: null, alerts: null, reports: null, docker_updates: null };
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
            cards.push(renderOffline(list));
        }

        if (result.alerts === null) cards.push(skeletonCard('Alerts'));
        else cards.push(result.alerts.error ? renderError('Alerts', result.alerts.error) : renderAlerts(result.alerts.data));

        cards.push(renderDockerUpdates(result.docker_updates));

        if (result.reports === null) cards.push(skeletonCard('Recent reports'));
        else cards.push(result.reports.error ? renderError('Reports', result.reports.error) : renderReports(result.reports.data));

        const netdataCard = renderNetdata();
        if (netdataCard) cards.push(netdataCard);

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

        // "10/16 online" is a question, so the chip is a button: it takes you to
        // the card that answers it and flashes it, without moving the layout.
        mount.querySelector('[data-ov-offline-jump]')?.addEventListener('click', () => {
            const card = document.getElementById('ov-card-offline');
            if (!card) return;
            card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            card.classList.remove('is-flash');
            void card.offsetWidth;               // restart the highlight
            card.classList.add('is-flash');
            card.focus({ preventScroll: true });
            setTimeout(() => card.classList.remove('is-flash'), 1600);
        });

        // A row is the whole point of the card: it takes you to that host's
        // Docker pane, with the container you clicked already flashing so the
        // update button is under your cursor rather than one hunt away.
        mount.querySelectorAll('[data-ov-update]').forEach((button) => {
            button.addEventListener('click', () => {
                const hostKey = button.dataset.ovUpdate;
                const container = button.dataset.ovUpdateContainer || '';
                if (!hostKey) {
                    window.location.href = '/estate';
                    return;
                }
                if (typeof window.selectHost !== 'function' || typeof window.showDockerInfoMain !== 'function') {
                    window.location.href = `/docker/${encodeURIComponent(hostKey)}`;
                    return;
                }
                window.__ovFocusContainer = container || null;
                window.__ovFocusAt = Date.now();
                window.selectHost(hostKey);
                window.showDockerInfoMain();
            });
        });

        mount.querySelector('[data-ov-check-all]')?.addEventListener('click', async (event) => {
            const button = event.currentTarget;
            button.disabled = true;
            const was = button.textContent;
            button.textContent = 'checking…';
            try {
                await fetch('/api/docker/updates/refresh', {
                    method: 'POST', headers: { Accept: 'application/json' },
                });
                // The scans land over the next few seconds; drop the ETag so the
                // next poll is a full read rather than a 304 of the old answer.
                etag = null;
                await refresh();
            } catch (error) {
                window.showToast?.('Could not queue a scan', 'error');
            } finally {
                button.disabled = false;
                button.textContent = was;
            }
        });

        mount.querySelector('[data-ov-open-reports]')?.addEventListener('click', () => {
            if (typeof window.openReportsModal === 'function') window.openReportsModal(null, '');
            else window.open('/reports', '_blank', 'noopener');
        });
    }

    /* Netdata poll is slower than the overview: Netdata itself updates its ML
     * anomaly rate on a one-minute roll, so five seconds would just re-render
     * the same number. */
    let netdataAt = 0;
    const NETDATA_MS = 15000;

    async function loadNetdata() {
        if (Date.now() - netdataAt < NETDATA_MS) return false;
        netdataAt = Date.now();
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 5000);
            let res;
            try {
                res = await fetch('/api/netdata/fleet?window=120&points=30',
                    { headers: { Accept: 'application/json' }, signal: controller.signal });
            } finally {
                clearTimeout(timeout);
            }
            const body = await res.json().catch(() => ({}));
            if (!res.ok || body.success === false) {
                const message = String(body.error || `${res.status}`);
                // "not configured" is a deliberate state, not a dashboard error.
                window.__ovNetdata = /not configured/i.test(message) ? null : { error: message };
            } else {
                window.__ovNetdata = {
                    nodes: body.nodes || [],
                    quality: body.quality || {},
                };
            }
        } catch (error) {
            window.__ovNetdata = { error: error.message || 'request failed' };
        }
        return true;
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
        result.docker_updates = section(payload.docker_updates);
        return true;
    }

    async function refresh() {
        if (busy || !dashboardVisible()) return;
        busy = true;

        try {
            if (!painted) {
                result.servers = result.alerts = result.reports = result.docker_updates = null;
                paint();
            }
            // Netdata is decoration on this page: never let a slow parent delay
            // the fleet/alerts/report cards. Its result repaints on its own.
            loadNetdata().then((netdataChanged) => {
                if (netdataChanged && dashboardVisible()) paint();
            });
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
                result.servers = result.alerts = result.reports = result.docker_updates = { error };
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
