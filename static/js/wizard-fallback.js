// Fallback definitions for window.openWizard / window.closeWizard, moved verbatim.

    // Fallback: if wizard script fails to parse, at least open the modal and log an error.
    window.__AILOG_WIZARD_FALLBACK__ = true;
    if (typeof window.openWizard !== 'function') {
        window.openWizard = function () {
            console.error('[wizard] openWizard not defined (wizard script failed to load).');
            const modal = document.getElementById('wizardModal');
            if (modal) modal.classList.remove('hidden');
        };
    }
    if (typeof window.closeWizard !== 'function') {
        window.closeWizard = function () {
            const modal = document.getElementById('wizardModal');
            if (modal) modal.classList.add('hidden');
        };
    }
