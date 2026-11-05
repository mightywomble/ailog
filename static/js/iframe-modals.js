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

    // The estate: what wizard.yaml says, and the update that goes through CI.
    // A page, not a dialog form - it lists services and follows a run.
    // ``service`` deep-links the page at that row, so a click on the dashboard's
    // Docker updates card lands on the thing it named rather than on the top of
    // a nineteen-service list.
    window.openEstateModal = function (service) {
        const href = '/estate?embed=1'
            + (service ? `&service=${encodeURIComponent(service)}` : '');
        openFrame('estateModal', 'estateModalFrame', 'estateModalTitle',
                  href, '', 'The estate');
    };
    window.closeEstateModal = function () {
        closeFrame('estateModal', 'estateModalFrame');
    };

    // The homelab wizard is a foreign document (wizard.safehomelan.com), so it
    // is framed rather than merged, and the CSP's frame-src names its origin
    // (core/security.py, from AILOG_WIZARD_URL). A deep link tells the wizard
    // which service row to open, so "update" lands on that app instead of the
    // service list.
    window.openWizardModal = function (href, label) {
        if (!href) return;
        // The wizard cannot see this app's location, so the only way back is
        // the Exit button here; the header keeps a plain link for anyone who
        // wants the wizard's own full window.
        const external = document.getElementById('wizardModalExtern');
        if (external) external.setAttribute('href', href);
        openFrame('wizardModal', 'wizardModalFrame', 'wizardModalTitle',
                  href, label, 'Homelab wizard');
    };
    window.closeWizardModal = function () {
        // closeFrame -> closeAppModal dispatches appmodal:close, and the
        // listener below turns that into the Docker view's refresh, so closing
        // by button, Escape or backdrop all behave the same.
        closeFrame('wizardModal', 'wizardModalFrame');
    };

    // The wizard posts after a successful deploy/test (it cannot touch this
    // document). Only its own origin is trusted.
    window.addEventListener('message', (event) => {
        const wizardOrigin = (window.AILOG_WIZARD_URL || 'https://wizard.safehomelan.com/');
        let allowed = '';
        try { allowed = new URL(wizardOrigin).origin; } catch (err) { allowed = ''; }
        if (!allowed || event.origin !== allowed) return;
        const data = event.data || {};
        if (data.source !== 'homelab-wizard') return;
        if (data.type === 'deployed' && typeof window.onWizardDeployed === 'function') {
            window.onWizardDeployed(data);
        }
        // The wizard's own red X: it cannot reach out of its frame, so it asks
        // here and the dialog closes exactly as if Exit had been pressed.
        if (data.type === 'close') window.closeWizardModal();
    });

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

    // One report opens in the same dialog as the list: the frame navigates to
    // /reports/<id>?embed=1, whose own links stay inside the dialog. Reports
    // are read while looking at a host's logs, so they belong in a frame.
    window.openReportModal = function (reportId, label) {
        if (reportId === undefined || reportId === null || reportId === '') {
            window.openReportsModal(null, '');
            return;
        }
        openFrame('reportsModal', 'reportsModalFrame', 'reportsModalTitle',
                  `/reports/${encodeURIComponent(reportId)}?embed=1`, label, 'Report');
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
        document.getElementById('wizardModalClose')
            ?.addEventListener('click', window.closeWizardModal);
        document.getElementById('estateModalClose')
            ?.addEventListener('click', window.closeEstateModal);

        // The modal's own close (Escape / backdrop / shared handler) must also
        // unload the frame, which only these listeners know how to do.
        const FRAMES = {
            dockerModal: 'dockerModalFrame',
            reportsModal: 'reportsModalFrame',
            metricsModal: 'metricsModalFrame',
            wizardModal: 'wizardModalFrame',
            estateModal: 'estateModalFrame',
        };
        Object.keys(FRAMES).forEach((id) => {
            document.getElementById(id)?.addEventListener('appmodal:close', () => {
                const frame = document.getElementById(FRAMES[id]);
                if (frame && frame.getAttribute('src') !== 'about:blank') {
                    frame.setAttribute('src', 'about:blank');
                }
                // Escape / backdrop closes bypass closeWizardModal, so the
                // "a deploy just finished" refresh has to fire here too.
                if (id === 'wizardModal' && typeof window.onWizardClosed === 'function') {
                    window.onWizardClosed();
                }
            });
        });

        // The reports frame moves between the list and a single report, so the
        // dialog title follows the document it is showing (same origin).
        const reportsFrame = document.getElementById('reportsModalFrame');
        reportsFrame?.addEventListener('load', () => {
            try {
                const doc = reportsFrame.contentDocument;
                if (!doc || doc.location.href === 'about:blank') return;
                const title = (doc.title || '').trim();
                const node = document.getElementById('reportsModalTitle');
                if (node && title) node.textContent = title;
            } catch (error) {
                // Cross-origin document: keep the title we were given.
            }
        });
    });
})();
