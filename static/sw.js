/* Homelab Manager service worker.
 *
 * Two jobs, and nothing else:
 *   1. make the app installable (a manifest + a fetch handler is the minimum
 *      Chrome asks for);
 *   2. keep the *shell* usable when the network is gone.
 *
 * Rules that matter for this app:
 *   - network first, always. Releases are cache-proofed (v3.1.1) and a stale
 *     HTML shell pointing at new JS is worse than a slow load;
 *   - never touch /sources (Server-Sent Events), /ssh (WebSocket) or /api/*
 *     (live data). EventSource and WebSocket requests go through this handler,
 *     and buffering them would break streaming;
 *   - only cache same-origin GETs that we actually want offline: navigations
 *     and /static/ assets.
 */

const CACHE = 'ailog-shell-v1';
const OFFLINE_URL = '/static/offline.html';
const PASS_THROUGH = [/^\/sources/, /^\/ssh/, /^\/api\//, /^\/healthz/];

self.addEventListener('install', (event) => {
    event.waitUntil((async () => {
        const cache = await caches.open(CACHE);
        try { await cache.add(new Request(OFFLINE_URL, { cache: 'reload' })); } catch (_) {}
        await self.skipWaiting();
    })());
});

self.addEventListener('activate', (event) => {
    event.waitUntil((async () => {
        const keys = await caches.keys();
        await Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)));
        await self.clients.claim();
    })());
});

self.addEventListener('message', (event) => {
    if (event.data === 'skip-waiting') self.skipWaiting();
});

const isCacheable = (url, request) => {
    if (url.origin !== self.location.origin) return false;
    if (PASS_THROUGH.some((re) => re.test(url.pathname))) return false;
    if (request.mode === 'navigate') return true;
    return url.pathname.startsWith('/static/');
};

self.addEventListener('fetch', (event) => {
    const request = event.request;
    if (request.method !== 'GET') return;

    let url;
    try { url = new URL(request.url); } catch (_) { return; }
    if (!isCacheable(url, request)) return;   // let the browser own streams and live data

    event.respondWith((async () => {
        try {
            // Navigations bypass the HTTP cache so a new release is seen at once.
            const fresh = await fetch(request, request.mode === 'navigate' ? { cache: 'no-store' } : {});
            if (fresh && fresh.ok) {
                const copy = fresh.clone();
                event.waitUntil((async () => {
                    try { (await caches.open(CACHE)).put(request, copy); } catch (_) {}
                })());
            }
            return fresh;
        } catch (err) {
            const cached = await caches.match(request, { ignoreSearch: request.mode === 'navigate' });
            if (cached) return cached;
            if (request.mode === 'navigate') {
                const offline = await caches.match(OFFLINE_URL);
                if (offline) return offline;
            }
            throw err;
        }
    })());
});
