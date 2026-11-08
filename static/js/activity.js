// Activity strip: what the app is doing, and how far through it is.
//
// Two long jobs happen behind the interface and neither used to say a word:
// a cold start collects metrics from every host over SSH (seconds per host),
// and the Docker panes rescan each host's images against their registries
// (a manifest lookup per image, three hosts at a time). Both are reported by
// /api/activity, which only reads progress dicts -- so polling it every couple
// of seconds costs nothing and can never queue behind the work it describes.
//
// The strip is a full-width bar along the bottom, the same shape as the other
// progress bars in the app, and its detail line names the work in progress:
// which hosts are being contacted, which images are being compared, how long
// it has been running and how far along it is.
//
// Polling backs off when idle, pauses entirely while the tab is hidden, and can
// be kicked immediately by whoever starts a job (`ailog:activity` on document).

(function () {
    const ACTIVE_POLL_MS = 1500;
    const IDLE_POLL_MS = 8000;
    // How long a finished job stays on screen. A single-host scan can beat the
    // poll interval, and a bar that appears and vanishes unseen is the same as
    // no bar at all.
    const MIN_VISIBLE_MS = 2500;

    const strip = () => document.getElementById('activity-strip');
    const rowFor = (name) => strip()?.querySelector(`[data-activity="${name}"]`);

    let timer = null;
    let busy = false;
    const lastPaint = {};

    // "checking b, c" beats "checking a" when three hosts run at once: the bar
    // counts host *batches*, so the names are what make it legible. A stack
    // scan has no batches and no host list -- it has a stage and a service
    // count -- so it says those instead.
    const hostLabel = (name, data, done, total) => {
        const hosts = Array.isArray(data.hosts) ? data.hosts.filter(Boolean) : [];
        if (hosts.length) {
            const verb = name === 'docker' ? 'comparing image tags on' : 'contacting';
            const shown = hosts.slice(0, 3).join(', ');
            return hosts.length > 3 ? `${verb} ${shown} +${hosts.length - 3}` : `${verb} ${shown}`;
        }
        const one = data.current || data.host;
        if (name === 'swarm') {
            const where = one ? ` on ${one}` : '';
            return `${data.stage || 'reading the cluster'}${where}`;
        }
        if (one) return `${name === 'docker' ? 'checking' : 'contacting'} ${one}`;
        // Between batches there is no host in flight yet - say where we are
        // rather than leaving the last name on screen.
        const left = total ? Math.max(0, total - done) : 0;
        if (left) return `${left} host${left === 1 ? '' : 's'} to go`;
        return '';
    };

    // What the counter counts: hosts for a host sweep, tags for a stack scan.
    const unitFor = (name) => (name === 'swarm' ? 'tags' : 'hosts');

    const paint = (row, name, data, idleLabel) => {
        const total = Number(data.total) || 0;
        const done = Number(data.done) || 0;
        const pct = total ? Math.min(100, Math.round((100 * done) / total)) : null;

        const count = row.querySelector('[data-count]');
        if (count) count.textContent = total ? `${done} of ${total} ${unitFor(name)}` : '';

        const fill = row.querySelector('[data-fill]');
        if (fill) {
            if (pct === null) {
                fill.style.width = '100%';
                fill.dataset.indeterminate = '1';
            } else {
                fill.style.width = `${pct}%`;
                delete fill.dataset.indeterminate;
            }
        }

        const detail = row.querySelector('[data-detail]');
        if (detail) {
            const parts = [];
            const what = hostLabel(name, data, done, total);
            if (what) parts.push(what);
            if (data.elapsed !== undefined) parts.push(`${Math.round(data.elapsed)}s`);
            if (pct !== null) parts.push(`${pct}%`);
            detail.textContent = parts.length ? parts.join(' \u00b7 ') : idleLabel;
        }
    };

    // Returns true when the row is on screen, so the caller knows whether to
    // keep polling fast.
    const render = (name, data, idleLabel) => {
        const row = rowFor(name);
        if (!row) return false;
        if (data && data.active) {
            lastPaint[name] = { at: Date.now(), data };
            row.hidden = false;
            paint(row, name, data, idleLabel);
            return true;
        }
        // Gone - but it may only just have gone. One host against a warm digest
        // cache finishes inside a single poll, so an honest bar appeared and
        // vanished between two frames and the person who pressed the button saw
        // nothing at all. Hold the finished frame briefly: a click deserves an
        // answer, even a short one.
        const last = lastPaint[name];
        if (last && Date.now() - last.at < MIN_VISIBLE_MS) {
            row.hidden = false;
            paint(row, name, { ...last.data, done: last.data.total || last.data.done },
                  idleLabel);
            return true;
        }
        row.hidden = true;
        return false;
    };

    const tick = async () => {
        if (busy) return;
        if (document.hidden) {
            schedule(IDLE_POLL_MS);
            return;
        }
        busy = true;
        let active = false;
        try {
            const res = await fetch('/api/activity', { headers: { Accept: 'application/json' } });
            const data = await res.json();
            active = [
                render('metrics', data.metrics, 'collecting'),
                render('docker', data.docker, 'scanning'),
                render('swarm', data.swarm, 'reading the cluster'),
            ].some(Boolean);
            const host = strip();
            if (host) host.classList.toggle('hidden', !active);
        } catch (err) {
            // A failed poll is not worth a banner: keep whatever is on screen
            // and try again, slower.
            active = false;
        } finally {
            busy = false;
        }
        schedule(active ? ACTIVE_POLL_MS : IDLE_POLL_MS);
    };

    const schedule = (ms) => {
        if (timer) clearTimeout(timer);
        timer = setTimeout(tick, ms);
    };

    document.addEventListener('DOMContentLoaded', () => {
        if (!strip()) return;
        tick();
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) tick();
        });
        // A job that has just been queued should appear now, not on the next
        // idle poll eight seconds later.
        document.addEventListener('ailog:activity', () => {
            if (timer) clearTimeout(timer);
            tick();
        });
    });
})();
