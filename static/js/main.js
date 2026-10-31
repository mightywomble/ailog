// Single ES-module entry point for templates/index.html.
//
// The order of these imports mirrors the order of the original inline
// <script> blocks so that DOMContentLoaded listeners are registered in the
// same relative order as before. Do not reorder without re-checking the page.
import './boot.js';
import './modals.js';              // shared dialog chrome: Escape, backdrop, close
import './ai-wizard.js';           // shared AI analysis wizard: what to analyse, then prompt
import './groups.js';
import './app-core.js';           // imports ./suricata.js and ./sshkeys.js
import './toolbar.js';
import './monitoring-wizard.js';
import './wizard-fallback.js';
import './iframe-modals.js';     // docker + reports dialogs (iframes)
import './shell.js';              // responsive shell: drawer, tab bar, view state
import './command-palette.js';    // ⌘K fast path over views/hosts/actions
import './overview.js';           // dashboard overview cards
import './pwa.js';                // installable app: service worker + install button
