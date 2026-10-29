// Docker monitoring modal bridge.
//
// The Docker page is a full standalone document (/docker/<host_key>): it owns
// Chart.js instances, an EventSource for live history and its own polling
// loops. Re-implementing it inside index.html would duplicate ~1000 lines of
// DOM and every element id, so it is embedded in a modal iframe instead.
//
// Two details matter:
//  * the page is loaded with ?embed=1, which drops its "Back" link (the modal
//    owns the close button) and tightens the page chrome;
//  * closing sets src back to about:blank, which unloads the document and so
//    tears down its chart timers and its /history/stream EventSource instead of
//    leaving them sampling in a hidden frame.

(function () {
    const MODAL_ID = 'dockerModal';
    const FRAME_ID = 'dockerModalFrame';
    const TITLE_ID = 'dockerModalTitle';

    const modal = () => document.getElementById(MODAL_ID);
    const frame = () => document.getElementById(FRAME_ID);

    window.openDockerModal = function (hostKey, label) {
        const box = modal();
        const f = frame();
        if (!box || !f || !hostKey) return;

        const title = document.getElementById(TITLE_ID);
        if (title) {
            title.textContent = label ? `Docker — ${label}` : 'Docker';
        }

        const qs = new URLSearchParams({ embed: '1' });
        f.src = `/docker/${encodeURIComponent(hostKey)}?${qs.toString()}`;

        // Inline style, not a utility class: `hidden` and `flex` are both
        // display utilities and which one wins depends on stylesheet order.
        box.style.display = 'flex';
    };

    window.closeDockerModal = function () {
        const f = frame();
        if (f) f.src = 'about:blank';   // unload: stops charts, SSE and polls
        const box = modal();
        if (box) box.style.display = 'none';
    };

    window.dockerModalIsOpen = function () {
        const box = modal();
        return !!box && box.style.display !== 'none';
    };

    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('dockerModalClose')
            ?.addEventListener('click', window.closeDockerModal);

        // Click on the backdrop (but not inside the panel) closes, like the
        // other modals on the page.
        modal()?.addEventListener('mousedown', (event) => {
            if (event.target === modal()) window.closeDockerModal();
        });

        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && window.dockerModalIsOpen()) {
                window.closeDockerModal();
            }
        });
    });
})();
