// Progressive-web-app plumbing: the service worker and the install button.
//
// The worker (static/sw.js) is registered from '/' so its scope covers the
// whole app; Flask serves it at /sw.js with the Service-Worker-Allowed
// header for exactly that reason.
//
// The install button stays hidden unless the browser says the app is
// installable (`beforeinstallprompt`), so there is never a dead control in a
// browser that cannot install it (iOS Safari, desktop Firefox).

(function initPwa() {
    const btn = document.getElementById('install-app-btn');

    const canInstall = () => 'serviceWorker' in navigator && window.isSecureContext;

    if (canInstall()) {
        window.addEventListener('load', () => {
            navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch((err) => {
                console.warn('[pwa] service worker registration failed:', err);
            });
        });
    }

    let deferredPrompt = null;

    const showButton = (show) => {
        if (!btn) return;
        btn.classList.toggle('hidden', !show);
        btn.hidden = !show;
    };

    window.addEventListener('beforeinstallprompt', (event) => {
        // Chrome shows its own mini-infobar unless we take over.
        event.preventDefault();
        deferredPrompt = event;
        showButton(true);
    });

    btn?.addEventListener('click', async () => {
        if (!deferredPrompt) return;
        btn.disabled = true;
        try {
            deferredPrompt.prompt();
            const choice = await deferredPrompt.userChoice;
            if (choice && choice.outcome === 'accepted') {
                window.showToast?.('Installing Homelab Manager…', 'success');
            }
        } catch (_) {
            // the prompt can only be used once; ignore a second attempt
        } finally {
            deferredPrompt = null;
            btn.disabled = false;
            showButton(false);
        }
    });

    window.addEventListener('appinstalled', () => {
        deferredPrompt = null;
        showButton(false);
        window.showToast?.('Homelab Manager installed.', 'success');
    });
})();
