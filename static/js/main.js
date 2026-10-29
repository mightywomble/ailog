// Single ES-module entry point for templates/index.html.
//
// The order of these imports mirrors the order of the original inline
// <script> blocks so that DOMContentLoaded listeners are registered in the
// same relative order as before. Do not reorder without re-checking the page.
import './boot.js';
import './groups.js';
import './app-core.js';           // imports ./suricata.js and ./sshkeys.js
import './toolbar.js';
import './monitoring-wizard.js';
import './wizard-fallback.js';
import './docker-modal.js';
