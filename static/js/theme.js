/* Theme controller.
 *
 * Owns the four appearance axes stored on <html>:
 *   data-theme    midnight | slate | nord | solarized | terminal | contrast
 *   data-ui       classic | glass | console   ("look and feel", theme-independent)
 *   data-mode     dark | light        (the sun/moon button flips this)
 *   data-density  comfortable | compact
 *   data-motion   full | reduced
 *
 * Persisted in localStorage so every page — including the standalone docker /
 * metrics / reports pages and the iframes that embed them — agrees. Any canvas
 * chart should ask window.themeColors() for its series colours instead of
 * hard-coding hex, which is what makes charts follow the theme.
 */

export const THEMES = [
    { id: 'midnight', label: 'Midnight', hint: 'The original Homelab Manager look', swatch: ['#0b0f14', '#6d28d9', '#22c55e'] },
    { id: 'slate', label: 'Slate', hint: 'Neutral, low tint', swatch: ['#0b1120', '#2563eb', '#94a3b8'] },
    { id: 'nord', label: 'Nord', hint: 'Cool arctic blues', swatch: ['#2e3440', '#88c0d0', '#a3be8c'] },
    { id: 'solarized', label: 'Solarized', hint: 'Designed as a light/dark pair', swatch: ['#002b36', '#268bd2', '#b58900'] },
    { id: 'terminal', label: 'Terminal', hint: 'Green on black', swatch: ['#000000', '#22c55e', '#c9f7d9'] },
    { id: 'contrast', label: 'High contrast', hint: 'Maximum legibility', swatch: ['#000000', '#ffd400', '#ffffff'] },
];

export const INTERFACES = [
    { id: 'classic', label: 'Classic', hint: 'Current shell: sidebar, cards, quiet chrome' },
    { id: 'glass', label: 'Glass', hint: 'Bento cards, pill nav, blurred translucent panels' },
    { id: 'console', label: 'Console', hint: 'Dense instrument grid, accent-topped cards' },
];

const KEY = {
    theme: 'ui.theme',
    ui: 'ui.interface',
    mode: 'ui.mode',        // 'dark' | 'light' | 'system'
    density: 'ui.density',
    motion: 'ui.motion',
};
const LEGACY_THEME = 'ui.theme';
const DEFAULT_THEME = 'midnight';

const root = document.documentElement;

const read = (key, fallback) => {
    try {
        const value = localStorage.getItem(key);
        return value === null ? fallback : value;
    } catch (_) {
        return fallback;
    }
};
const write = (key, value) => {
    try { localStorage.setItem(key, value); } catch (_) { /* private mode */ }
};

const prefersDark = () => {
    try { return window.matchMedia('(prefers-color-scheme: dark)').matches; }
    catch (_) { return true; }
};

// ?theme=nord&mode=light&density=compact overrides the saved values for this
// view only (handy for sharing a screenshot or previewing a theme).
const params = new URLSearchParams(window.location.search);
const pick = (name, allowed, fallback) => {
    const value = params.get(name);
    return value && allowed.includes(value) ? value : fallback;
};

export const state = {
    theme: pick('theme', THEMES.map((t) => t.id), read(KEY.theme, DEFAULT_THEME)),
    ui: pick('ui', INTERFACES.map((i) => i.id), read(KEY.ui, 'classic')),
    mode: pick('mode', ['dark', 'light', 'system'], read(KEY.mode, 'system')),   // what the user chose
    density: pick('density', ['comfortable', 'compact'], read(KEY.density, 'comfortable')),
    motion: pick('motion', ['full', 'reduced'], read(KEY.motion, 'full')),
};

export const resolvedMode = () => (state.mode === 'system' ? (prefersDark() ? 'dark' : 'light') : state.mode);

export function isKnownTheme(id) {
    return THEMES.some((t) => t.id === id);
}

export function isKnownInterface(id) {
    return INTERFACES.some((i) => i.id === id);
}

function apply({ animate = false } = {}) {
    const mode = resolvedMode();
    if (!isKnownTheme(state.theme)) state.theme = DEFAULT_THEME;
    if (!isKnownInterface(state.ui)) state.ui = 'classic';

    if (animate) {
        root.classList.add('theme-switching');
        window.setTimeout(() => root.classList.remove('theme-switching'), 220);
    }

    root.dataset.theme = state.theme;
    root.dataset.ui = state.ui;
    root.dataset.mode = mode;
    root.dataset.density = state.density;
    root.dataset.motion = state.motion;
    // Makes native widgets (scrollbars, date pickers, form controls) match.
    root.style.colorScheme = mode;

    syncControls();
    window.dispatchEvent(new CustomEvent('themechange', {
        detail: { theme: state.theme, ui: state.ui, mode, choice: state.mode, colors: themeColors() },
    }));
}

export function setTheme(id, { animate = true } = {}) {
    if (!isKnownTheme(id)) return;
    state.theme = id;
    write(KEY.theme, id);
    apply({ animate });
}

export function setInterface(id) {
    if (!isKnownInterface(id)) return;
    state.ui = id;
    write(KEY.ui, id);
    apply({ animate: true });
}

export function setMode(mode, { animate = true } = {}) {
    if (!['dark', 'light', 'system'].includes(mode)) return;
    state.mode = mode;
    write(KEY.mode, mode);
    apply({ animate });
}

export function toggleMode() {
    // A light switch, not a theme picker: flip to the opposite of what is on
    // screen right now, even when the current choice is "system".
    setMode(resolvedMode() === 'dark' ? 'light' : 'dark');
}

export function setDensity(value) {
    if (!['comfortable', 'compact'].includes(value)) return;
    state.density = value;
    write(KEY.density, value);
    apply();
}

export function setMotion(value) {
    if (!['full', 'reduced'].includes(value)) return;
    state.motion = value;
    write(KEY.motion, value);
    apply();
}

export function resetAppearance() {
    state.theme = DEFAULT_THEME;
    state.ui = 'classic';
    state.mode = 'system';
    state.density = 'comfortable';
    state.motion = 'full';
    write(KEY.theme, state.theme);
    write(KEY.ui, state.ui);
    write(KEY.mode, state.mode);
    write(KEY.density, state.density);
    write(KEY.motion, state.motion);
    apply({ animate: true });
}

/** Semantic colours for canvas charts (sparklines, Chart.js datasets). */
export function themeColors() {
    const css = getComputedStyle(root);
    const v = (name, fallback) => (css.getPropertyValue(name) || fallback).trim();
    return {
        text: v('--text', '#e5e7eb'),
        muted: v('--muted', '#94a3b8'),
        faint: v('--faint', '#64748b'),
        surface: v('--surface', '#0f1520'),
        surface2: v('--surface-2', '#111a28'),
        border: v('--border', 'rgba(255,255,255,.08)'),
        accent: v('--accent', '#6d28d9'),
        ok: v('--ok', '#22c55e'),
        warn: v('--warn', '#f59e0b'),
        bad: v('--bad', '#ef4444'),
        info: v('--info', '#38bdf8'),
        series: [
            v('--chart-1', '#38bdf8'),
            v('--chart-2', '#a78bfa'),
            v('--chart-3', '#f59e0b'),
            v('--chart-4', '#22d3ee'),
            v('--chart-5', '#fb7185'),
            v('--chart-6', '#4ade80'),
        ],
    };
}

/* ----------------------------------------------------------- UI bindings */

function syncControls() {
    const mode = resolvedMode();
    document.querySelectorAll('[data-theme-toggle]').forEach((btn) => {
        btn.setAttribute('aria-pressed', mode === 'light' ? 'true' : 'false');
        const label = mode === 'light' ? 'Switch to dark theme' : 'Switch to light theme';
        btn.setAttribute('aria-label', label);
        btn.setAttribute('title', label);
    });

    document.querySelectorAll('[data-theme-choice]').forEach((btn) => {
        const active = btn.dataset.themeChoice === state.theme;
        btn.setAttribute('aria-pressed', active ? 'true' : 'false');
        btn.classList.toggle('is-active', active);
    });

    document.querySelectorAll('[data-ui-choice]').forEach((btn) => {
        const active = btn.dataset.uiChoice === state.ui;
        btn.setAttribute('aria-pressed', active ? 'true' : 'false');
        btn.classList.toggle('is-active', active);
    });

    document.querySelectorAll('[data-mode-choice]').forEach((btn) => {
        const active = btn.dataset.modeChoice === state.mode;
        btn.setAttribute('aria-pressed', active ? 'true' : 'false');
        btn.classList.toggle('is-active', active);
    });

    document.querySelectorAll('[data-density-choice]').forEach((btn) => {
        const active = btn.dataset.densityChoice === state.density;
        btn.setAttribute('aria-pressed', active ? 'true' : 'false');
        btn.classList.toggle('is-active', active);
    });

    document.querySelectorAll('[data-motion-choice]').forEach((btn) => {
        const active = btn.dataset.motionChoice === state.motion;
        btn.setAttribute('aria-pressed', active ? 'true' : 'false');
        btn.classList.toggle('is-active', active);
    });
}

function buildAppearancePanel(container) {
    const modeButtons = [['system', 'System'], ['dark', 'Dark'], ['light', 'Light']];
    container.innerHTML = `
      <div class="appearance-block">
        <div class="appearance-label">Interface</div>
        <div class="ui-grid" role="group" aria-label="Interface">
          ${INTERFACES.map((i) => `
            <button type="button" class="ui-card" data-ui-choice="${i.id}"
                    aria-pressed="false" title="${i.hint}">
              <span class="ui-preview ui-preview-${i.id}" aria-hidden="true">
                <i></i><i></i><i></i><i></i><i></i>
              </span>
              <span class="ui-name">${i.label}</span>
              <span class="ui-hint">${i.hint}</span>
            </button>`).join('')}
        </div>
        <p class="appearance-help">Layout and card treatment. Colour themes apply to every interface.</p>
      </div>

      <div class="appearance-block">
        <div class="appearance-label">Theme</div>
        <div class="theme-grid" role="group" aria-label="Theme">
          ${THEMES.map((t) => `
            <button type="button" class="theme-card" data-theme-choice="${t.id}"
                    aria-pressed="false" title="${t.hint}">
              <span class="theme-swatch" style="background:linear-gradient(135deg, ${t.swatch[0]} 0 55%, ${t.swatch[1]} 55% 80%, ${t.swatch[2]} 80%)"></span>
              <span class="theme-name">${t.label}</span>
              <span class="theme-hint">${t.hint}</span>
            </button>`).join('')}
        </div>
      </div>

      <div class="appearance-block">
        <div class="appearance-label">Mode</div>
        <div class="segmented" role="group" aria-label="Mode">
          ${modeButtons.map(([id, label]) => `
            <button type="button" data-mode-choice="${id}" aria-pressed="false">${label}</button>`).join('')}
        </div>
        <p class="appearance-help">The button next to Settings flips between this theme’s dark and light
          variant. “System” follows your operating system.</p>
      </div>

      <div class="appearance-block">
        <div class="appearance-label">Density</div>
        <div class="segmented" role="group" aria-label="Density">
          <button type="button" data-density-choice="comfortable" aria-pressed="false">Comfortable</button>
          <button type="button" data-density-choice="compact" aria-pressed="false">Compact</button>
        </div>
      </div>

      <div class="appearance-block">
        <div class="appearance-label">Motion</div>
        <div class="segmented" role="group" aria-label="Motion">
          <button type="button" data-motion-choice="full" aria-pressed="false">Full</button>
          <button type="button" data-motion-choice="reduced" aria-pressed="false">Reduced</button>
        </div>
      </div>

      <div class="appearance-block">
        <button type="button" class="termix-btn" id="appearance-reset">Reset to default</button>
      </div>
    `;
    syncControls();
}

function wireAppearancePanel(container) {
    if (container.dataset.wired === '1') return;
    container.dataset.wired = '1';
    container.addEventListener('click', (event) => {
        const target = event.target.closest('button');
        if (!target) return;
        const d = target.dataset;
        if (d.uiChoice) setInterface(d.uiChoice);
        else if (d.themeChoice) setTheme(d.themeChoice);
        else if (d.modeChoice) setMode(d.modeChoice);
        else if (d.densityChoice) setDensity(d.densityChoice);
        else if (d.motionChoice) setMotion(d.motionChoice);
        else if (target.id === 'appearance-reset') resetAppearance();
    });
}

function mount() {
    document.querySelectorAll('[data-theme-toggle]').forEach((btn) => {
        if (btn.dataset.wired === '1') return;
        btn.dataset.wired = '1';
        btn.addEventListener('click', () => toggleMode());
    });

    const panel = document.querySelector('[data-appearance-panel]');
    if (panel) {
        buildAppearancePanel(panel);
        wireAppearancePanel(panel);
    }

    syncControls();

    // Follow the OS live while the choice is "system".
    try {
        window.matchMedia('(prefers-color-scheme: dark)')
            .addEventListener('change', () => { if (state.mode === 'system') apply(); });
    } catch (_) { /* older browsers: ignore */ }
}

/* Public surface, also on window for the non-module pages (docker, metrics…). */
Object.assign(window, {
    ailogTheme: { THEMES, INTERFACES, state, setTheme, setInterface, setMode, toggleMode, setDensity, setMotion, resetAppearance, themeColors, resolvedMode },
    themeColors,
    toggleThemeMode: toggleMode,
});

// Apply immediately: a module still runs before first paint on a fresh parse,
// and the inline <head> snippet has already set the attributes on later loads.
apply();
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mount);
} else {
    mount();
}
