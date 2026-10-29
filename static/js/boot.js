// Boot globals (moved verbatim from templates/index.html).
// Kept as the first import so window.__appReady / window.__waitForXterm exist
// before any app module runs.

// Wrap all initialization to ensure xterm.js has loaded
window.__appReady = false;
window.__waitForXterm = async () => {
    let retries = 0;
    while ((!window.Terminal || !window.FitAddon) && retries < 50) {
        await new Promise(r => setTimeout(r, 100));
        retries++;
    }
    return !!(window.Terminal && window.FitAddon);
};
