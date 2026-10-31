/* App shell behaviour: mobile drawer, bottom tab bar, view state.
 *
 * The shell is CSS (static/css/shell.css). This module only adds what CSS
 * cannot: opening/closing the host drawer, keeping the tab bar's aria-current
 * in sync with the visible view, and leaving the drawer with Escape.
 */

(function initShell() {
    const body = document.body;
    const sidebar = document.getElementById('hosts-sidebar');
    const openBtn = document.getElementById('mobile-menu-btn');
    const tabbar = document.getElementById('mobile-tabbar');
    const views = ['dashboard-view', 'mobile-hosts-view', 'mobile-logs-view', 'logs-view', 'suricata-stats-view'];

    const isOpen = () => body.classList.contains('sidebar-open');

    const setOpen = (open) => {
        body.classList.toggle('sidebar-open', open);
        if (openBtn) openBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
        if (open && sidebar) {
            const first = sidebar.querySelector('button, a, input, select');
            if (first) first.focus({ preventScroll: true });
        }
    };

    openBtn?.addEventListener('click', (event) => {
        event.stopPropagation();
        setOpen(!isOpen());
    });

    // Clicking a host inside the drawer closes it (the host view is underneath).
    sidebar?.addEventListener('click', (event) => {
        if (!isOpen()) return;
        if (event.target.closest('.termix-host, #host-list-container button')) setOpen(false);
    });

    // Anywhere outside closes it (the ::after backdrop is a pseudo element, so
    // a document-level listener is what actually catches the tap).
    document.addEventListener('click', (event) => {
        if (!isOpen()) return;
        if (event.target.closest('#hosts-sidebar') || event.target.closest('#mobile-menu-btn')) return;
        setOpen(false);
    });

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && isOpen()) setOpen(false);
    });

    /* ------------------------------------------------------------ tab bar */
    const visibleView = () => {
        for (const id of views) {
            const el = document.getElementById(id);
            if (el && !el.classList.contains('hidden')) return id;
        }
        return 'dashboard-view';
    };

    const syncTabs = () => {
        if (!tabbar) return;
        const view = visibleView();
        tabbar.querySelectorAll('[data-tab]').forEach((btn) => {
            const tab = btn.dataset.tab;
            const current = (tab === 'overview' && view === 'dashboard-view')
                || (tab === 'hosts' && view === 'mobile-hosts-view')
                || (tab === 'logs' && (view === 'logs-view' || view === 'mobile-logs-view'));
            if (current) btn.setAttribute('aria-current', 'page');
            else btn.removeAttribute('aria-current');
        });
    };

    tabbar?.addEventListener('click', (event) => {
        const btn = event.target.closest('[data-tab]');
        if (!btn) return;
        const tab = btn.dataset.tab;
        if (tab === 'overview') {
            window.showDashboard?.();
            document.getElementById('dashboard-view')?.scrollTo({ top: 0 });
        } else if (tab === 'logs') {
            if (typeof window.showLogs === 'function') window.showLogs();
            else document.getElementById('hosts-sidebar') && setOpen(true);
        } else if (tab === 'hosts') {
            // The grid, not the drawer: hosts are the first screen on a phone.
            if (typeof window.showMobileHosts === 'function') window.showMobileHosts();
            else setOpen(true);
        } else if (tab === 'monitor') {
            if (typeof window.openMetricsModal === 'function') window.openMetricsModal('');
            else window.open('/metrics', '_blank', 'noopener');
        } else if (tab === 'reports') {
            if (typeof window.openReportsModal === 'function') window.openReportsModal(null, '');
            else window.open('/reports', '_blank', 'noopener');
        } else if (tab === 'alerts') {
            window.location.href = '/alerts';
        }
    });

    // Views are shown/hidden by toggling `hidden` in app-core.js; observe that.
    const observer = new MutationObserver(syncTabs);
    views.forEach((id) => {
        const el = document.getElementById(id);
        if (el) observer.observe(el, { attributes: true, attributeFilter: ['class'] });
    });
    syncTabs();

    // Exported for the command palette: jump to a specific view.
    window.ailogShell = { showView: (name) => {
        if (name === 'dashboard') window.showDashboard?.();
        else if (name === 'hosts') window.showMobileHosts?.();
        else if (name === 'mobile-logs') window.showMobileLogs?.();
        else if (name === 'logs') window.showLogs?.();
        else if (name === 'suricata') document.getElementById('suricata-stats-btn')?.click();
        syncTabs();
    } };
})();
