/* Command palette (⌘K / Ctrl+K).
 *
 * The fast path over the page-based navigation: type once, jump to a host, a
 * view, a dialog or a theme. Actions are plain objects:
 *     { id, title, hint, group, icon, keywords, run() }
 * Static actions live here; hosts are injected by app-core.js through
 * window.ailogHostActions() so the palette does not need to know about the
 * hosts map.
 */

(function initCommandPalette() {
    const state = { open: false, items: [], filtered: [], index: 0 };

    const ICONS = {
        host: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2"/>',
        view: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h7"/>',
        action: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>',
        theme: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v2m0 14v2M5.6 5.6l1.4 1.4m10 10l1.4 1.4M3 12h2m14 0h2M5.6 18.4L7 17m10-10l1.4-1.4"/><circle cx="12" cy="12" r="4"/>',
    };

    /* ------------------------------------------------------------- actions */

    const staticActions = () => {
        const actions = [
            {
                id: 'view-overview', title: 'Go to Overview', group: 'Views', icon: 'view',
                keywords: 'dashboard home cards fleet',
                run: () => window.ailogShell?.showView('dashboard'),
            },
            {
                id: 'view-logs', title: 'Go to Logs', group: 'Views', icon: 'view',
                keywords: 'logs viewer pull',
                run: () => window.ailogShell?.showView('logs'),
            },
            {
                id: 'monitoring', title: 'Open Monitoring', hint: 'live CPU / RAM / disk / network',
                group: 'Actions', icon: 'action', keywords: 'metrics netdata graphs',
                run: () => window.openMetricsModal ? window.openMetricsModal('') : window.open('/metrics', '_blank', 'noopener'),
            },
            {
                id: 'reports', title: 'Open Reports', hint: 'server-wide AI reports',
                group: 'Actions', icon: 'action', keywords: 'analysis ai report history',
                run: () => window.openReportsModal ? window.openReportsModal(null, '') : window.open('/reports', '_blank', 'noopener'),
            },
            {
                id: 'alerts', title: 'Open Alerts', hint: 'threshold rules and events',
                group: 'Actions', icon: 'action', keywords: 'alert rules threshold discord',
                run: () => { window.location.href = '/alerts'; },
            },
            {
                id: 'settings', title: 'Open Settings', group: 'Actions', icon: 'action',
                keywords: 'ai provider discord hosts backup restore settings',
                run: () => document.getElementById('settings-btn')?.click(),
            },
            {
                id: 'appearance', title: 'Appearance & themes', hint: 'interface, theme, light/dark, density',
                group: 'Actions', icon: 'theme', keywords: 'interface look feel layout theme dark light mode colours colors density',
                run: () => {
                    document.getElementById('settings-btn')?.click();
                    setTimeout(() => document.querySelector('.settings-nav-btn[data-section="appearance"]')?.click(), 60);
                },
            },
            {
                id: 'add-devices', title: 'Add Devices', hint: 'onboarding wizard',
                group: 'Actions', icon: 'action', keywords: 'wizard ssh key onboard host',
                run: () => (window.openWizard ? window.openWizard() : window.location.assign('/monitoring/wizard')),
            },
            {
                id: 'monitoring-wizard', title: 'Monitoring Wizard', hint: 'discover ports and services',
                group: 'Actions', icon: 'action', keywords: 'wizard discover ports services',
                run: () => window.openMonitoringWizard ? window.openMonitoringWizard(null) : window.location.assign('/monitoring/wizard'),
            },
            {
                id: 'rescan', title: 'Rescan All Hosts', group: 'Actions', icon: 'action',
                keywords: 'refresh scan docker endpoints',
                run: () => document.getElementById('rescan-all-btn')?.click(),
            },
            {
                id: 'theme-toggle', title: 'Toggle light / dark', group: 'Appearance', icon: 'theme',
                keywords: 'theme mode switch dark light',
                run: () => window.ailogTheme?.toggleMode(),
            },
        ];

        (window.ailogTheme?.INTERFACES || []).forEach((ui) => {
            actions.push({
                id: `ui-${ui.id}`, title: `Interface: ${ui.label}`, hint: ui.hint,
                group: 'Appearance', icon: 'theme', keywords: `interface layout look feel ${ui.id} ui`,
                run: () => window.ailogTheme?.setInterface(ui.id),
            });
        });

        (window.ailogTheme?.THEMES || []).forEach((theme) => {
            actions.push({
                id: `theme-${theme.id}`, title: `Theme: ${theme.label}`, hint: theme.hint,
                group: 'Appearance', icon: 'theme', keywords: `theme ${theme.id} palette`,
                run: () => window.ailogTheme?.setTheme(theme.id),
            });
        });

        return actions;
    };

    const hostActions = () => {
        const hosts = (typeof window.ailogHostActions === 'function') ? window.ailogHostActions() : [];
        return hosts.map((host) => ({
            id: `host-${host.id}`,
            title: host.name || host.id,
            hint: [host.ip, host.group].filter(Boolean).join(' · '),
            group: 'Hosts',
            icon: 'host',
            keywords: `${host.id} ${host.name || ''} ${host.ip || ''} ${host.group || ''}`.toLowerCase(),
            run: () => window.ailogOpenHost?.(host.id),
        }));
    };

    /* ------------------------------------------------------------------ UI */

    const overlay = document.createElement('div');
    overlay.id = 'command-palette';
    overlay.className = 'cmdk-overlay hidden';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', 'Command palette');
    overlay.innerHTML = `
      <div class="cmdk-panel" role="document">
        <div class="cmdk-input-row">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" aria-hidden="true">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
          </svg>
          <input id="cmdk-input" type="text" autocomplete="off" spellcheck="false"
                 placeholder="Search hosts, views, actions…" aria-controls="cmdk-list" aria-autocomplete="list">
          <kbd>esc</kbd>
        </div>
        <div id="cmdk-list" class="cmdk-list" role="listbox" aria-label="Results"></div>
        <div class="cmdk-foot">
          <span><kbd>↑</kbd><kbd>↓</kbd> navigate</span>
          <span><kbd>↵</kbd> run</span>
          <span><kbd>⌘K</kbd> toggle</span>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    const input = overlay.querySelector('#cmdk-input');
    const list = overlay.querySelector('#cmdk-list');

    const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

    const score = (item, query) => {
        if (!query) return 1;
        const haystack = `${item.title} ${item.hint || ''} ${item.keywords || ''}`.toLowerCase();
        if (haystack.includes(query)) return 100 - haystack.indexOf(query);
        // subsequence match ("mn" -> "Monitoring")
        let i = 0;
        for (const ch of haystack) if (ch === query[i]) i += 1;
        return i === query.length ? 10 : 0;
    };

    const render = () => {
        const query = input.value.trim().toLowerCase();
        state.filtered = state.items
            .map((item) => ({ item, s: score(item, query) }))
            .filter((row) => row.s > 0)
            .sort((a, b) => b.s - a.s)
            .map((row) => row.item)
            .slice(0, 40);

        if (state.index >= state.filtered.length) state.index = 0;

        if (!state.filtered.length) {
            list.innerHTML = '<div class="cmdk-empty">No matches</div>';
            return;
        }

        let lastGroup = null;
        list.innerHTML = state.filtered.map((item, i) => {
            const header = item.group !== lastGroup ? `<div class="cmdk-group">${item.group}</div>` : '';
            lastGroup = item.group;
            return `${header}
              <button type="button" class="cmdk-item${i === state.index ? ' is-active' : ''}"
                      role="option" aria-selected="${i === state.index}" data-index="${i}">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" aria-hidden="true">${ICONS[item.icon] || ICONS.action}</svg>
                <span class="cmdk-title">${escapeHtml(item.title)}</span>
                ${item.hint ? `<span class="cmdk-hint">${escapeHtml(item.hint)}</span>` : ''}
              </button>`;
        }).join('');
    };

    const escapeHtml = (value) => String(value ?? '')
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

    const open = () => {
        state.items = [...staticActions(), ...hostActions()];
        state.index = 0;
        input.value = '';
        overlay.classList.remove('hidden');
        state.open = true;
        render();
        // Defer so the browser does not scroll the page while focusing.
        requestAnimationFrame(() => input.focus({ preventScroll: true }));
    };

    const close = () => {
        overlay.classList.add('hidden');
        state.open = false;
        input.blur();
    };

    const run = (index) => {
        const item = state.filtered[index ?? state.index];
        if (!item) return;
        close();
        try { item.run(); } catch (err) { console.error('[palette]', err); }
    };

    input.addEventListener('input', () => { state.index = 0; render(); });

    input.addEventListener('keydown', (event) => {
        if (event.key === 'ArrowDown') {
            event.preventDefault();
            state.index = Math.min(state.index + 1, state.filtered.length - 1);
            render();
            list.querySelector('.cmdk-item.is-active')?.scrollIntoView({ block: 'nearest' });
        } else if (event.key === 'ArrowUp') {
            event.preventDefault();
            state.index = Math.max(state.index - 1, 0);
            render();
            list.querySelector('.cmdk-item.is-active')?.scrollIntoView({ block: 'nearest' });
        } else if (event.key === 'Enter') {
            event.preventDefault();
            run();
        } else if (event.key === 'Escape') {
            event.preventDefault();
            close();
        }
    });

    overlay.addEventListener('click', (event) => {
        if (event.target === overlay) close();
        const item = event.target.closest('.cmdk-item');
        if (item) run(Number(item.dataset.index));
    });

    overlay.addEventListener('mousemove', (event) => {
        const item = event.target.closest('.cmdk-item');
        if (!item) return;
        const index = Number(item.dataset.index);
        if (index === state.index) return;
        state.index = index;
        list.querySelectorAll('.cmdk-item').forEach((el, i) => {
            el.classList.toggle('is-active', i === index);
            el.setAttribute('aria-selected', i === index ? 'true' : 'false');
        });
    });

    document.addEventListener('keydown', (event) => {
        const isPaletteKey = (event.key === 'k' || event.key === 'K') && (isMac ? event.metaKey : event.ctrlKey);
        if (isPaletteKey) {
            event.preventDefault();
            state.open ? close() : open();
            return;
        }
        if (event.key === 'Escape' && state.open) close();
    });

    document.querySelectorAll('[data-command-palette]').forEach((btn) => {
        btn.addEventListener('click', open);
    });

    // Hint text depends on the platform.
    document.querySelectorAll('[data-palette-hint]').forEach((el) => {
        el.textContent = isMac ? '⌘K' : 'Ctrl K';
    });

    window.ailogPalette = { open, close, isOpen: () => state.open };
})();
