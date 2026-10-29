// Toolbar "More" menu and hosts-sidebar collapse, moved verbatim from
// templates/index.html (two self-contained IIFEs).

// -----------------------------
// Toolbar "More" menu + Hosts sidebar collapse
// -----------------------------
(function initToolbarMoreMenu() {
    const btn = document.getElementById('toolbar-more-btn');
    const menu = document.getElementById('toolbar-more-menu');
    if (!btn || !menu) return;

    const close = () => {
        menu.classList.add('hidden');
        btn.setAttribute('aria-expanded', 'false');
    };
    const open = () => {
        menu.classList.remove('hidden');
        btn.setAttribute('aria-expanded', 'true');
    };

    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = !menu.classList.contains('hidden');
        if (isOpen) close(); else open();
    });

    document.addEventListener('click', (e) => {
        if (e.target.closest('#toolbar-more-menu') || e.target.closest('#toolbar-more-btn')) return;
        close();
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') close();
    });
})();

(function initHostsSidebarCollapse() {
    const sidebar = document.getElementById('hosts-sidebar');
    const btn = document.getElementById('hosts-collapse-btn');
    const icon = document.getElementById('hosts-collapse-icon');
    if (!sidebar || !btn) return;

    const key = 'ui.hosts_sidebar_collapsed';

    const apply = (collapsed) => {
        sidebar.classList.toggle('collapsed', !!collapsed);
        if (icon) icon.textContent = collapsed ? '⟩' : '⟨';
    };

    // initial
    apply(localStorage.getItem(key) === '1');

    btn.addEventListener('click', () => {
        const next = !sidebar.classList.contains('collapsed');
        localStorage.setItem(key, next ? '1' : '0');
        apply(next);
    });
})();
