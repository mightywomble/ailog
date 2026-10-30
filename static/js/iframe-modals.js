// Iframe-backed dialogs: Docker monitoring, live monitoring (metrics) and the
// server report history.
//
// Both are full documents (`/docker/<host>`, `/reports`) with Chart.js
// instances, polling loops and their own tables, so they are embedded rather
// than inlined — inlining would duplicate ~1000 lines of DOM and every element
// id. They load with `?embed=1`, which drops the page's own Back link (the
// dialog owns closing) and tightens the page chrome.
//
// Opening/closing goes through the shared modal helpers (static/js/modals.js),
// so Escape, backdrop click, focus and the Close button all behave exactly like
// every other dialog in the app. Closing unloads the frame (about:blank), which
// tears down the embedded document's timers and EventSource instead of leaving
// them sampling in a hidden frame.

(function () {
    const openFrame = (modalId, frameId, titleId, src, label, fallbackTitle) => {
        const frame = document.getElementById(frameId);
        if (!frame) return;
        const title = document.getElementById(titleId);
        if (title) title.textContent = label ? `${fallbackTitle} — ${label}` : fallbackTitle;
        frame.src = src;
        if (typeof window.openAppModal === 'function') {
            window.openAppModal(modalId);
        } else {
            document.getElementById(modalId)?.classList.remove('hidden');
        }
    };

    const closeFrame = (modalId, frameId) => {
        const frame = document.getElementById(frameId);
        if (frame) frame.src = 'about:blank';   // unload: stops charts, SSE, polls
        if (typeof window.closeAppModal === 'function') {
            window.closeAppModal(modalId);
        } else {
            document.getElementById(modalId)?.classList.add('hidden');
        }
    };

    window.openDockerModal = function (hostKey, label) {
        if (!hostKey) return;
        openFrame('dockerModal', 'dockerModalFrame', 'dockerModalTitle',
                  `/docker/${encodeURIComponent(hostKey)}?embed=1`, label, 'Docker');
    };
    window.closeDockerModal = function () {
        closeFrame('dockerModal', 'dockerModalFrame');
    };
    window.dockerModalIsOpen = function () {
        return typeof window.isAppModalOpen === 'function'
            ? window.isAppModalOpen('dockerModal')
            : false;
    };

    window.openReportsModal = function (hostKey, label, query) {
        // hostKey is optional: the modal can show the global report list.
        const params = new URLSearchParams({ embed: '1' });
        if (hostKey) params.set('host', hostKey);
        if (query) {
            Object.entries(query).forEach(([k, v]) => {
                if (v !== undefined && v !== null && v !== '') params.set(k, v);
            });
        }
        openFrame('reportsModal', 'reportsModalFrame', 'reportsModalTitle',
                  `/reports?${params.toString()}`, label, 'Reports');
    };
    window.closeReportsModal = function () {
        closeFrame('reportsModal', 'reportsModalFrame');
    };

    // Remediation: catalog, "start a run", maintenance windows and the run
    // list. Embedded so the wizard opens with the dashboard still behind it;
    // the header link keeps its href, so a middle-click still gets the page.
    window.openRemediationModal = function () {
        openFrame('remediationModal', 'remediationModalFrame', 'remediationModalTitle',
                  '/remediation?embed=1', '', 'Remediation');
    };
    window.closeRemediationModal = function () {
        closeFrame('remediationModal', 'remediationModalFrame');
    };
    window.remediationModalIsOpen = function () {
        return typeof window.isAppModalOpen === 'function'
            ? window.isAppModalOpen('remediationModal')
            : false;
    };

    // Live monitoring: the netdata-style card grid. It polls every 2s, so the
    // frame is blanked on close rather than left running hidden.
    window.openMetricsModal = function (label) {
        openFrame('metricsModal', 'metricsModalFrame', 'metricsModalTitle',
                  '/metrics?embed=1', label, 'Monitoring');
    };
    window.closeMetricsModal = function () {
        closeFrame('metricsModal', 'metricsModalFrame');
    };
    window.metricsModalIsOpen = function () {
        return typeof window.isAppModalOpen === 'function'
            ? window.isAppModalOpen('metricsModal')
            : false;
    };

    document.addEventListener('DOMContentLoaded', () => {
        // Belt and braces: the shared data-modal-close handler covers these,
        // but the explicit listeners keep each page's close behaviour local
        // (and clear the iframe even if the shared module is unavailable).
        document.getElementById('dockerModalClose')
            ?.addEventListener('click', window.closeDockerModal);
        document.getElementById('reportsModalClose')
            ?.addEventListener('click', window.closeReportsModal);
        document.getElementById('metricsModalClose')
            ?.addEventListener('click', window.closeMetricsModal);
        document.getElementById('remediationModalClose')
            ?.addEventListener('click', window.closeRemediationModal);

        // The modal's own close (Escape / backdrop / shared handler) must also
        // unload the frame, which only these listeners know how to do.
        const FRAMES = {
            dockerModal: 'dockerModalFrame',
            reportsModal: 'reportsModalFrame',
            metricsModal: 'metricsModalFrame',
            remediationModal: 'remediationModalFrame',
        };
        Object.keys(FRAMES).forEach((id) => {
            document.getElementById(id)?.addEventListener('appmodal:close', () => {
                const frame = document.getElementById(FRAMES[id]);
                if (frame && frame.getAttribute('src') !== 'about:blank') {
                    frame.setAttribute('src', 'about:blank');
                }
            });
        });
    });

    // The header button opens the dialog; the anchor still navigates if this
    // module never loads (or if the user middle-clicks / uses a keyboard shortcut).
    document.addEventListener('click', (event) => {
        const link = event.target.closest('#remediation-link');
        if (!link) return;
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.button === 1) return;
        if (typeof window.openRemediationModal !== 'function') return;
        event.preventDefault();
        window.openRemediationModal();
    });
})();
