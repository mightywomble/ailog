// One owner for every dialog in the app.
//
// Markup contract (see static/css/style.css and templates/index.html):
//
//   <div id="fooModal" class="app-modal hidden">
//     <div class="app-modal-panel app-modal-md">
//       <div class="app-modal-head">
//         <div class="app-modal-title">[icon] Title</div>
//         <button class="app-modal-close" data-modal-close>Close</button>
//       </div>
//       <div class="app-modal-body">...</div>
//     </div>
//   </div>
//
// State is the `hidden` class, which is what the rest of the app already
// toggles, so call sites keep working. What this module adds on top is the
// behaviour every dialog should have anyway: Escape closes the topmost one,
// clicking the backdrop closes it, `[data-modal-close]` closes its own dialog,
// and a dialog's iframes are unloaded on close so they stop polling.
//
// Page-specific open functions (Docker, monitoring wizard, reports) still own
// their own title/iframe wiring; they just call openAppModal/closeAppModal.

(function () {
    // Open order, so Escape closes the dialog the user is actually looking at
    // rather than whichever one happens to be first in the DOM.
    const stack = [];

    const el = (id) => (typeof id === 'string' ? document.getElementById(id) : id);
    const modalOf = (node) => (node && node.closest ? node.closest('.app-modal') : null);

    const unloadFrames = (modal) => {
        modal.querySelectorAll('iframe').forEach((f) => {
            // about:blank unloads the document: chart timers, EventSource and
            // polling loops inside it are torn down with it.
            if (f.getAttribute('src') !== 'about:blank') f.setAttribute('src', 'about:blank');
        });
    };

    window.openAppModal = function (idOrEl) {
        const modal = el(idOrEl);
        if (!modal) return null;
        modal.classList.remove('hidden');
        const at = stack.indexOf(modal);
        if (at !== -1) stack.splice(at, 1);
        stack.push(modal);
        // Focus the close button so keyboard users land inside the dialog.
        const focusable = modal.querySelector('.app-modal-close') || modal.querySelector('button');
        if (focusable) setTimeout(() => focusable.focus({ preventScroll: true }), 0);
        modal.dispatchEvent(new CustomEvent('appmodal:open', { bubbles: false }));
        // One history entry per dialog, so Back closes it instead of leaving
        // the app. The entry keeps the current view state (app-core's `ailog`)
        // and adds the dialog id on top of it.
        const state = history.state || {};
        if (state.ailogModal !== modal.id) {
            history.pushState({ ...state, ailogModal: modal.id }, '', location.href);
        }
        return modal;
    };

    window.closeAppModal = function (idOrEl) {
        const modal = el(idOrEl);
        if (!modal) return null;
        unloadFrames(modal);
        modal.classList.add('hidden');
        const at = stack.indexOf(modal);
        if (at !== -1) stack.splice(at, 1);
        // Drop our entry by rewriting it (not history.back()), so a close that
        // happens as part of a view change cannot fight with the Back button.
        const state = history.state;
        if (state && state.ailogModal === modal.id) {
            history.replaceState({ ...state, ailogModal: null }, '', location.href);
        }
        modal.dispatchEvent(new CustomEvent('appmodal:close', { bubbles: false }));
        return modal;
    };

    window.isAppModalOpen = function (idOrEl) {
        const modal = el(idOrEl);
        return !!modal && !modal.classList.contains('hidden');
    };

    window.toggleAppModal = function (idOrEl) {
        return window.isAppModalOpen(idOrEl) ? window.closeAppModal(idOrEl)
                                            : window.openAppModal(idOrEl);
    };

    document.addEventListener('DOMContentLoaded', () => {
        // Explicit close buttons anywhere inside a dialog.
        document.addEventListener('click', (event) => {
            const btn = event.target.closest && event.target.closest('[data-modal-close]');
            if (btn) {
                const modal = modalOf(btn);
                if (modal) {
                    event.preventDefault();
                    window.closeAppModal(modal);
                }
            }
        });

        // Backdrop click. mousedown (not click) so that a drag that starts
        // inside the panel and ends on the backdrop does not close it.
        document.addEventListener('mousedown', (event) => {
            if (event.target.classList && event.target.classList.contains('app-modal')) {
                window.closeAppModal(event.target);
            }
        });

        // Escape closes the topmost open dialog. Dialogs opened by older code
        // (which just removes the `hidden` class) are not in the stack, so fall
        // back to the last visible .app-modal in document order — they get
        // Escape for free.
        const topmost = () => {
            while (stack.length && stack[stack.length - 1].classList.contains('hidden')) {
                stack.pop();
            }
            if (stack.length) return stack[stack.length - 1];
            const visible = Array.from(document.querySelectorAll('.app-modal'))
                .filter((m) => !m.classList.contains('hidden'));
            return visible.length ? visible[visible.length - 1] : null;
        };

        // Back: if the entry we returned to is not a dialog but one is open,
        // close it. (View/screen entries are owned by app-core.)
        window.addEventListener('popstate', (event) => {
            const state = event.state || {};
            if (state.ailogModal) return;      // still inside another dialog
            const top = topmost();
            if (!top) return;
            window.closeAppModal(top);
        });

        document.addEventListener('keydown', (event) => {
            if (event.key !== 'Escape') return;
            const top = topmost();
            if (!top) return;
            event.stopPropagation();
            window.closeAppModal(top);
        });
    });
})();
