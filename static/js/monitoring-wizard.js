// Monitoring wizard modal bridge (window.openMonitoringWizard /
// window.closeMonitoringWizard + DOMContentLoaded wiring), moved verbatim.

    window.openMonitoringWizard = function (hostDbId) {
        const modal = document.getElementById('monitoringWizardModal');
        const frame = document.getElementById('monitoringWizardFrame');
        if (!modal || !frame) return;
        const qs = hostDbId ? `?host_id=${encodeURIComponent(hostDbId)}` : '';
        frame.src = `/monitoring/wizard${qs}`;
        if (typeof window.openAppModal === 'function') window.openAppModal(modal);
        else modal.classList.remove('hidden');
    };

    window.closeMonitoringWizard = function () {
        const modal = document.getElementById('monitoringWizardModal');
        const frame = document.getElementById('monitoringWizardFrame');
        if (frame) frame.src = 'about:blank';
        if (!modal) return;
        if (typeof window.closeAppModal === 'function') window.closeAppModal(modal);
        else modal.classList.add('hidden');
    };

    document.addEventListener('DOMContentLoaded', () => {
        const btn = document.getElementById('monitoringWizardClose');
        if (btn) btn.addEventListener('click', window.closeMonitoringWizard);

        // Escape is handled globally by modals.js (it also unloads the frame
        // through the appmodal:close listener below).
        document.getElementById('monitoringWizardModal')
            ?.addEventListener('appmodal:close', () => {
                const frame = document.getElementById('monitoringWizardFrame');
                if (frame && frame.getAttribute('src') !== 'about:blank') {
                    frame.setAttribute('src', 'about:blank');
                }
            });
    });
