/* Settings → Netdata.
 *
 * The token is write-only from the browser's perspective: GET /api/netdata/config
 * returns ``token_set`` but never the value, and a blank field means "keep the
 * stored token". Saving is explicit so a half-typed URL cannot break the
 * Monitoring page's fallback.
 */

const API = '/api/netdata/config';

function byId(id) {
    return document.getElementById(id);
}

async function getJson(url, options) {
    const res = await fetch(url, { headers: { Accept: 'application/json' }, ...options });
    const body = await res.json().catch(() => ({}));
    if (!res.ok || body.success === false) throw new Error(body.error || `${res.status} ${res.statusText}`);
    return body;
}

async function refreshConfig() {
    const url = byId('netdata-url');
    const tokenState = byId('netdata-token-state');
    const status = byId('netdata-status');
    try {
        const cfg = await getJson(API);
        if (url) url.value = cfg.url || '';
        if (tokenState) tokenState.textContent = cfg.token_set ? '(stored)' : '(not set)';
        if (status) status.textContent = cfg.configured ? 'configured' : 'not configured';
    } catch (err) {
        if (status) status.textContent = `could not load: ${err.message}`;
    }
}

async function saveConfig(clearToken = false) {
    const status = byId('netdata-status');
    const url = byId('netdata-url');
    const token = byId('netdata-token');
    if (status) status.textContent = 'Saving…';
    try {
        const body = { url: url ? url.value.trim() : '', clear_token: clearToken };
        if (!clearToken && token && token.value.trim()) body.token = token.value.trim();
        const data = await getJson(API, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify(body),
        });
        if (token) token.value = '';
        if (status) {
            status.textContent = data.health?.reachable
                ? `saved · ${data.health.nodes} nodes reachable`
                : `saved · ${data.health?.error || 'not reachable yet'}`;
        }
        refreshConfig();
    } catch (err) {
        if (status) status.textContent = err.message;
    }
}

async function testConfig() {
    const status = byId('netdata-status');
    if (status) status.textContent = 'Testing…';
    try {
        const data = await getJson('/api/netdata/health');
        if (status) {
            status.textContent = data.reachable
                ? `${data.online}/${data.nodes} nodes online · ${data.version || ''} · ${data.ms} ms`
                : (data.error || 'not reachable');
        }
    } catch (err) {
        if (status) status.textContent = err.message;
    }
}

function wire() {
    const save = byId('netdata-save');
    const test = byId('netdata-test');
    const clear = byId('netdata-clear-token');
    if (!save) return;
    save.addEventListener('click', () => saveConfig(false));
    if (test) test.addEventListener('click', testConfig);
    if (clear) clear.addEventListener('click', () => {
        if (window.confirm('Remove the stored Netdata API token?')) saveConfig(true);
    });
    document.querySelectorAll('[data-section="netdata"]').forEach((button) => {
        button.addEventListener('click', refreshConfig);
    });
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wire);
} else {
    wire();
}
