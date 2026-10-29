// Monitoring wizard modal bridge (window.openMonitoringWizard /
// window.closeMonitoringWizard + DOMContentLoaded wiring), moved verbatim.

    window.openMonitoringWizard = function (hostDbId) {
        const modal = document.getElementById('monitoringWizardModal');
        const frame = document.getElementById('monitoringWizardFrame');
        if (!modal || !frame) return;
        const qs = hostDbId ? `?host_id=${encodeURIComponent(hostDbId)}` : '';
        frame.src = `/monitoring/wizard${qs}`;
        modal.classList.remove('hidden');
        modal.classList.add('flex');
    };

    window.closeMonitoringWizard = function () {
        const modal = document.getElementById('monitoringWizardModal');
        const frame = document.getElementById('monitoringWizardFrame');
        if (frame) frame.src = 'about:blank';
        if (modal) {
            modal.classList.add('hidden');
            modal.classList.remove('flex');
        }
    };

    document.addEventListener('DOMContentLoaded', () => {
        const btn = document.getElementById('monitoringWizardClose');
        if (btn) btn.addEventListener('click', window.closeMonitoringWizard);

        // Allow escape key to close
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                const modal = document.getElementById('monitoringWizardModal');
                if (modal && !modal.classList.contains('hidden')) window.closeMonitoringWizard();
            }
        });

        // Wire dashboard button/link
        const dash = document.getElementById('dashboard-open-monitoring-wizard');
        if (dash) {
            dash.addEventListener('click', (e) => {
                e.preventDefault();
                window.openMonitoringWizard(null);
            });
        }
    });
