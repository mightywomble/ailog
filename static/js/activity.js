// Activity strip: what the app is doing, and how far through it is.
//
// Two long jobs happen behind the interface and neither used to say a word:
// a cold start collects metrics from every host over SSH (seconds per host),
// and the Docker panes rescan each host's images against their registries
// (a manifest lookup per image, three hosts at a time). Both are reported by
// /api/activity, which only reads progress dicts -- so polling it every couple
// of seconds costs nothing and can never queue behind the work it describes.
//
// Polling backs off when idle, and pauses entirely while the tab is hidden.

(function () {
    const ACTIVE_POLL_MS = 1500;
    const IDLE_POLL_MS = 8000;

    const strip = () => document.getElementById('activity-strip');
    const rowFor = (name) => strip()?.querySelector(`[data-activity="${name}"]`);

    let timer = null;
    let busy = false;

    const render = (name, data, idleLabel) => {
        const row = rowFor(name);
        if (!row) return;
        if (!data || !data.active) {
            row.hidden = true;
            return;
        }
        row.hidden = false;
        const total = Number(data.total) || 0;
        const done = Number(data.done) || 0;
        const pct = total ? Math.min(100, Math.round((100 * done) / total)) : null;

        const count = row.querySelector('[data-count]');
        if (count) count.textContent = total ? `${done} of ${total} hosts` : '';

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
            if (data.host) parts.push(`${name === 'docker' ? 'checking' : 'contacting'} ${data.host}`);
            if (data.elapsed !== undefined) parts.push(`${Math.round(data.elapsed)}s`);
            if (pct !== null) parts.push(`${pct}%`);
            detail.textContent = parts.length ? parts.join(' · ') : idleLabel;
        }
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
            render('metrics', data.metrics, 'collecting');
            render('docker', data.docker, 'scanning');
            active = !!(data.metrics?.active || data.docker?.active);
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
    });
})();
