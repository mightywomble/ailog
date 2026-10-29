// Core application logic (the former giant DOMContentLoaded closure), moved
// verbatim from templates/index.html. The original closure body is preserved
// as-is inside init() so all closure-scoped state and function hoisting keep
// working exactly as before.
import { loadGroupsSettings, wireGroupsSettingsUi } from './groups.js';
import { loadSshKeys } from './sshkeys.js';
import { loadSuricataConfigIntoForm, loadSuricataPromptSettings, refreshSuricataConfiguredState } from './suricata.js';

// Shared dialog chrome lives in ./modals.js. These wrappers keep the older
// call sites working while making sure every dialog registers on the same
// open-order stack (so Escape and the backdrop close the topmost one).
const openModal = (el) => {
    if (typeof window.openAppModal === 'function') window.openAppModal(el);
    else if (el) el.classList.remove('hidden');
};
const closeModal = (el) => {
    if (typeof window.closeAppModal === 'function') window.closeAppModal(el);
    else if (el) el.classList.add('hidden');
};

export function init() {

        // --- ELEMENT SELECTORS ---
        const sourceListContainer = document.getElementById('log-table-container');
        const logTitle = document.getElementById('log-table-title');
        const logContent = document.getElementById('log-content-container');
        const aiAnalyseBtn = document.getElementById('ai-analyse-btn');
        const truncationWarning = document.getElementById('truncation-warning');
        // Removed non-existent elements: searchBox, sortControls, filterControls
        
        const aiContentWrapper = document.getElementById('ai-content-wrapper');
        const aiViewPanel = document.getElementById('ai-view-panel');
        const resizeHandle = document.getElementById('resize-handle');
        const logViewPanel = document.getElementById('log-view-panel');

        // Termix-style dashboard/logs views
        // HTML-escape anything that came from a host (file names, container
        // names, image refs) before it goes near innerHTML.
        const escapeHtml = (value) => String(value == null ? '' : value).replace(
            /[&<>"']/g,
            (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
        );

        // ---- AI output rendering -------------------------------------------------
        // Markdown -> sanitised HTML. AI responses are influenced by log content,
        // so never trust the model output as HTML.
        const renderMarkdownInto = (el, text) => {
            if (!el) return;
            const src = String(text == null ? '' : text);
            let html = null;
            if (window.marked && window.DOMPurify) {
                try {
                    const parsed = window.marked.parse(src, { gfm: true, breaks: true });
                    html = window.DOMPurify.sanitize(parsed, { USE_PROFILES: { html: true } });
                } catch (_) {
                    html = null;
                }
            }
            if (html === null) {
                // Fallback: plain text, still safe.
                el.innerHTML = '<pre class="whitespace-pre-wrap text-sm"></pre>';
                el.querySelector('pre').textContent = src || 'No content.';
                return;
            }
            el.innerHTML = '<div class="ai-markdown">' + html + '</div>';
        };

        // ---- AI analysis staged progress -----------------------------------------
        const AI_STAGE_ORDER = ['prepare', 'contact', 'waiting', 'format'];
        const AI_STAGE_LABELS = {
            prepare: 'Preparing log excerpt',
            contact: 'Contacting AI provider',
            waiting: 'Analysing logs',
            format: 'Formatting result'
        };

        const renderAiAnalysisProgress = (container, providerLabel) => {
            if (!container) return;
            container.innerHTML = `
                <div class="flex items-center gap-3 mb-3">
                    <span class="top-progress-spinner" aria-hidden="true"></span>
                    <span id="ai-progress-message" class="text-sm termix-text">Contacting ${escapeHtml(providerLabel || 'AI assistant')}...</span>
                    <span id="ai-progress-elapsed" class="text-xs termix-muted ml-auto">0s</span>
                </div>
                <div class="w-full bg-white/10 rounded-full h-1.5 overflow-hidden mb-4">
                    <div id="ai-progress-bar" class="bg-indigo-500 h-1.5 rounded-full transition-all duration-500" style="width: 6%"></div>
                </div>
                <ul class="space-y-1.5 text-xs termix-muted">
                    ${AI_STAGE_ORDER.map((stage) => `
                        <li data-ai-step="${stage}" class="ai-step">
                            <span class="ai-step-icon">\u25cb</span><span>${AI_STAGE_LABELS[stage]}</span>
                        </li>`).join('')}
                </ul>`;
        };

        const setAiAnalysisStage = (stage, message, elapsed) => {
            const msg = document.getElementById('ai-progress-message');
            const bar = document.getElementById('ai-progress-bar');
            const clock = document.getElementById('ai-progress-elapsed');
            const secs = Math.max(0, Math.round(Number(elapsed) || 0));
            if (msg && message) msg.textContent = message;
            if (clock) clock.textContent = `${secs}s`;

            const idx = AI_STAGE_ORDER.indexOf(stage);
            document.querySelectorAll('#ai-analysis-content [data-ai-step]').forEach((li) => {
                const i = AI_STAGE_ORDER.indexOf(li.dataset.aiStep);
                const done = idx >= 0 && i < idx;
                const active = i === idx;
                li.classList.toggle('ai-step-done', done);
                li.classList.toggle('ai-step-active', active);
                const icon = li.querySelector('.ai-step-icon');
                if (icon) icon.textContent = done ? '\u2713' : (active ? '\u25cf' : '\u25cb');
            });

            if (bar) {
                let pct = 10;
                if (stage === 'prepare') pct = 18;
                else if (stage === 'contact') pct = 38;
                else if (stage === 'waiting') pct = Math.min(90, 55 + secs * 1.2);
                else if (stage === 'format') pct = 95;
                bar.style.width = pct + '%';
            }
        };

        // Consume a `text/event-stream` response produced by a POST request.
        const streamJsonEvents = async (url, body, onEvent) => {
            const res = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Accept': 'text/event-stream' },
                body: JSON.stringify(body)
            });
            if (!res.ok) {
                let msg = `Request failed (${res.status})`;
                try {
                    const data = await res.json();
                    if (data && data.error) msg = data.error;
                } catch (_) {}
                throw new Error(msg);
            }
            if (!res.body || typeof res.body.getReader !== 'function') {
                throw new Error('Streaming is not supported by this browser.');
            }
            const reader = res.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';
            for (;;) {
                const { value, done } = await reader.read();
                if (done) break;
                buffer += decoder.decode(value, { stream: true });
                let sep;
                while ((sep = buffer.indexOf('\n\n')) >= 0) {
                    const chunk = buffer.slice(0, sep);
                    buffer = buffer.slice(sep + 2);
                    const payload = chunk.split('\n')
                        .filter((line) => line.startsWith('data:'))
                        .map((line) => line.slice(5).trim())
                        .join('\n');
                    if (!payload) continue;   // comment / keepalive
                    try {
                        onEvent(JSON.parse(payload));
                    } catch (_) {
                        // Ignore malformed frames rather than aborting the analysis.
                    }
                }
            }
        };

        // Expose to the page-level scripts (Suricata raw analysis reuses these).
        window.escapeHtml = escapeHtml;
        window.renderMarkdownInto = renderMarkdownInto;
        window.renderAiAnalysisProgress = renderAiAnalysisProgress;
        window.setAiAnalysisStage = setAiAnalysisStage;

        const dashboardView = document.getElementById('dashboard-view');
        const logsView = document.getElementById('logs-view');
        const backToDashboardBtn = document.getElementById('back-to-dashboard-btn');
        const logsSelectedHostTitle = document.getElementById('logs-selected-host-title');
        const logsActionPull = document.getElementById('logs-action-pull');
        const logsActionInfo = document.getElementById('logs-action-info');
        const logsActionMonitor = document.getElementById('logs-action-monitor');
        const logsActionSsh = document.getElementById('logs-action-ssh');
        const logsActionDocker = document.getElementById('logs-action-docker');
        const sshTerminalContainer = document.getElementById('ssh-terminal-container');
        const sshTerminalBody = document.getElementById('ssh-terminal-body');
        const sshTerminalStatus = document.getElementById('ssh-terminal-status');

        const dashboardSelectedHostEl = document.getElementById('dashboard-selected-host');
        const dashboardTotalHostsEl = document.getElementById('dashboard-total-hosts');
        const dashboardTotalSchedulesEl = document.getElementById('dashboard-total-schedules');
        const dashboardDbStatusEl = document.getElementById('dashboard-db-status');
        const dashboardOpenSettingsBtn = document.getElementById('dashboard-open-settings');
        const dashboardRescanBtn = document.getElementById('dashboard-rescan');
        const dashboardAddDevicesBtn = document.getElementById('dashboard-add-devices');
        const dashboardExportSshBtn = document.getElementById('dashboard-export-ssh');
        
        const hostListContainer = document.getElementById('host-list-container');
        const settingsBtn = document.getElementById('settings-btn');
        const createAnsibleInventoryBtn = document.getElementById('create-ansible-inventory-btn');
        const createSshConfigBtn = document.getElementById('create-ssh-config-btn');
        const rescanAllBtn = document.getElementById('rescan-all-btn');
        const closeSettingsBtn = document.getElementById('close-settings-btn');
        const downloadDbBackupBtn = document.getElementById('download-db-backup-btn');
        const restoreDbFileInput = document.getElementById('restore-db-file');
        const restoreDbBtn = document.getElementById('restore-db-btn');
        const settingsModal = document.getElementById('settings-modal');
        const hostListDiv = document.getElementById('host-list');
        const addNewHostBtn = document.getElementById('add-new-host-btn');
        
        const hostModal = document.getElementById('host-modal');
        const hostModalTitle = document.getElementById('host-modal-title');
        const hostForm = document.getElementById('host-form');
        const hostIdInput = document.getElementById('host-id-input');
        const hostFriendlyNameInput = document.getElementById('host-friendly-name-input');
        const hostIpInput = document.getElementById('host-ip-input');
        const hostUserInput = document.getElementById('host-user-input');
        const hostDescriptionInput = document.getElementById('host-description-input');
        const hostTestStatus = document.getElementById('host-test-status');
        const hostTestBtn = document.getElementById('host-test-btn');
        const hostSaveBtn = document.getElementById('host-save-btn');
        const hostModalCancelBtn = document.getElementById('host-modal-cancel-btn');
        const hostModalXBtn = document.getElementById('host-modal-x');
        
        const progressContainer = document.getElementById('progress-container');
        const progressBar = document.getElementById('progress-bar');
        const progressMessage = document.getElementById('progress-message');
        const progressLogs = document.getElementById('progress-logs');
        const progressMinimizeBtn = document.getElementById('progress-minimize-btn');
        const progressCloseBtn = document.getElementById('progress-close-btn');
        const journalLoadingIndicator = document.getElementById('journal-loading-indicator');
        
        const apiKeyInput = document.getElementById('api-key-input');
        const discordWebhookInput = document.getElementById('discord-webhook-input');
        const testDiscordBtn = document.getElementById('test-discord-btn');
        const discordWebhookStatusDot = document.getElementById('discord-webhook-status');
        const providerLabel = document.getElementById('provider-label');

        // AI Search (prompt + alert keywords)
        const aiSearchPromptTextarea = document.getElementById('ai-search-prompt');
        const saveAiSearchBtn = document.getElementById('save-ai-search-btn');
        const aiSearchSaveStatus = document.getElementById('ai-search-save-status');
        const alertKeywordsList = document.getElementById('alert-keywords-list');
        const addAlertKeywordBtn = document.getElementById('add-alert-keyword-btn');
        const saveAlertKeywordsBtn = document.getElementById('save-alert-keywords-btn');
        const alertKeywordsSaveStatus = document.getElementById('alert-keywords-save-status');
        
        // AI Provider Selection Elements (NEW UNIFIED WORKFLOW)
        const providerDropdown = document.getElementById('provider-dropdown');
        const openaiConfigPanel = document.getElementById('openai-config-panel');
        const ollamaConfigPanel = document.getElementById('ollama-config-panel');
        const openaiApiKeyInput = document.getElementById('openai-api-key');
        const testOpenaiBtn = document.getElementById('test-openai-btn');
        const openaiTestStatus = document.getElementById('openai-test-status');
        const openaiKeyStatusDot = document.getElementById('openai-key-status');
        const ollamaApiUrlInput = document.getElementById('ollama-api-url');
        const testOllamaUrlBtn = document.getElementById('test-ollama-url-btn');
        const ollamaUrlTestStatus = document.getElementById('ollama-url-test-status');
        const ollamaModelsPanel = document.getElementById('ollama-models-panel');
        const getModelsBtn = document.getElementById('get-models-btn');
        const ollamaModelSelectDropdown = document.getElementById('ollama-model-select');
        const testOllamaModelBtn = document.getElementById('test-ollama-model-btn');
        const ollamaModelTestStatus = document.getElementById('ollama-model-test-status');
        const currentConfigStatus = document.getElementById('current-config-status');
        const activeProviderName = document.getElementById('active-provider-name');
        
        // Legacy elements (for compatibility) - note: apiKeyInput already declared above
        const ollamaUrlInput = document.getElementById('ollama-url-input');
        const testOllamaBtn = document.getElementById('test-ollama-btn');
        const ollamaTestStatus = document.getElementById('ollama-test-status');
        const ollamaModelSection = document.getElementById('ollama-model-section');
        const listModelsBtn = document.getElementById('list-models-btn');
        const addOllamaBtn = document.getElementById('add-ollama-btn');
        const ollamaConfigStatus = document.getElementById('ollama-config-status');
        const ollamaModelSelect = document.getElementById('ollama-model-select');
        
        const schedulerStatusDiv = document.getElementById('scheduler-status');
        const scheduleIntervalInput = document.getElementById('schedule-interval-input');
        const startScheduleBtn = document.getElementById('start-schedule-btn');
        const stopScheduleBtn = document.getElementById('stop-schedule-btn');
        const runNowBtn = document.getElementById('run-now-btn');
        const selectLogsBtn = document.getElementById('select-logs-btn');
        const selectedLogCountSpan = document.getElementById('selected-log-count');

        const logSelectionModal = document.getElementById('log-selection-modal');
        const logSelectionTitle = document.getElementById('log-selection-title');
        const logSelectionList = document.getElementById('log-selection-list');
        const logSelectionProgress = document.getElementById('log-selection-progress');
        const logSelectionProgressBar = document.getElementById('log-selection-progress-bar');
        const logSelectionProgressPercent = document.getElementById('log-selection-progress-percent');
        const logSelectionProgressDetails = document.getElementById('log-selection-progress-details');
        const saveLogSelectionBtn = document.getElementById('save-log-selection-btn');
        const cancelLogSelectionBtn = document.getElementById('cancel-log-selection-btn');
        
        // Removed non-existent view mode buttons: listViewBtn, tableViewBtn
        
        const toast = document.getElementById('toast-notification');
        
        let currentLogName = "";
        let currentLogContent = "";
        let scheduledSources = [];
        let scheduleHostsDirty = false;
        const setPickLogsButtonState = (ready) => {
            if (!selectLogsBtn) return;
            selectLogsBtn.disabled = !ready;
            selectLogsBtn.classList.remove('bg-red-600','hover:bg-red-500','bg-green-600','hover:bg-green-500');
            selectLogsBtn.classList.add(ready ? 'bg-green-600' : 'bg-red-600');
            if (ready) selectLogsBtn.classList.add('hover:bg-green-500');
            else selectLogsBtn.classList.add('hover:bg-red-500');
            selectLogsBtn.title = ready ? '' : 'Click Save first to persist host selection.';
        };

        let currentEventSource = null;
        let currentViewMode = 'list';
        let tableData = null;
        let selectedHostId = 'local';
        let hosts = {};

        // Hosts list sorting / manual ordering
        const hostsSortSelect = document.getElementById('hosts-sort-select');
        const hostsResetOrderBtn = document.getElementById('hosts-reset-order-btn');
        const HOSTS_SORT_KEY = 'ui.hosts_sort';
        const HOSTS_MANUAL_ORDER_KEY = 'ui.hosts_manual_order';

        const getHostsSortMode = () => {
            const v = (localStorage.getItem(HOSTS_SORT_KEY) || 'manual').trim();
            return v || 'manual';
        };

        const setHostsSortMode = (mode) => {
            localStorage.setItem(HOSTS_SORT_KEY, mode);
            if (hostsSortSelect) hostsSortSelect.value = mode;
        };

        const getManualOrder = () => {
            try {
                const raw = localStorage.getItem(HOSTS_MANUAL_ORDER_KEY);
                const arr = raw ? JSON.parse(raw) : [];
                return Array.isArray(arr) ? arr.filter(x => typeof x === 'string') : [];
            } catch (_) {
                return [];
            }
        };

        const setManualOrder = (orderArr) => {
            try {
                localStorage.setItem(HOSTS_MANUAL_ORDER_KEY, JSON.stringify(orderArr || []));
            } catch (_) {}
        };

        const ipToSortable = (ip) => {
            // Returns an array of ints for IPv4; otherwise null (for hostnames, 'localhost', IPv6, etc)
            const s = (ip || '').trim();
            const m = /^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\s*$/.exec(s);
            if (!m) return null;
            const parts = m.slice(1).map(n => Number(n));
            if (parts.some(n => !Number.isFinite(n) || n < 0 || n > 255)) return null;
            return parts;
        };

        const compareIp = (aIp, bIp) => {
            const aa = ipToSortable(aIp);
            const bb = ipToSortable(bIp);
            if (!aa && !bb) return String(aIp || '').localeCompare(String(bIp || ''), undefined, { numeric: true, sensitivity: 'base' });
            if (!aa) return 1;
            if (!bb) return -1;
            for (let i = 0; i < 4; i++) {
                if (aa[i] !== bb[i]) return aa[i] - bb[i];
            }
            return 0;
        };

        const hostDisplayName = (host) => {
            return (host && (host.friendly_name || host.hostname || host.ip || host.ip_address)) ? String(host.friendly_name || host.hostname || host.ip || host.ip_address) : '';
        };

        const getOrderedHostEntries = (hostsObj) => {
            const entries = Object.entries(hostsObj || {});
            const mode = getHostsSortMode();

            if (mode === 'manual') {
                const manual = getManualOrder();
                const idx = new Map(manual.map((id, i) => [id, i]));
                entries.sort((a, b) => {
                    const ai = idx.has(a[0]) ? idx.get(a[0]) : Number.POSITIVE_INFINITY;
                    const bi = idx.has(b[0]) ? idx.get(b[0]) : Number.POSITIVE_INFINITY;
                    if (ai !== bi) return ai - bi;
                    // Stable fallback for hosts not yet in manual list
                    return hostDisplayName(a[1]).localeCompare(hostDisplayName(b[1]), undefined, { numeric: true, sensitivity: 'base' });
                });
                return entries;
            }

            if (mode === 'ip_asc' || mode === 'ip_desc') {
                entries.sort((a, b) => {
                    const c = compareIp(a[1]?.ip, b[1]?.ip);
                    return mode === 'ip_desc' ? -c : c;
                });
                return entries;
            }

            if (mode === 'name_asc' || mode === 'name_desc') {
                entries.sort((a, b) => {
                    const an = hostDisplayName(a[1]).toLowerCase();
                    const bn = hostDisplayName(b[1]).toLowerCase();
                    const c = an.localeCompare(bn, undefined, { numeric: true, sensitivity: 'base' });
                    return mode === 'name_desc' ? -c : c;
                });
                return entries;
            }

            return entries;
        };
        let currentLogType = null;
        let currentHostId = null;

        // Main-panel mode guard: prevents async Host Info loads from overwriting Pull Logs / SSH views.
        let logsMainMode = 'info'; // 'info' | 'pull' | 'ssh' | 'monitor'
        let logsMainViewToken = 0;

        // Search elements
        const searchInput = document.getElementById('search-input');
        const searchBtn = document.getElementById('search-btn');
        const caseSensitiveCheckbox = document.getElementById('case-sensitive-checkbox');
        const searchScope = document.getElementById('search-scope');
        const searchResultsContainer = document.getElementById('search-results-container');
        const searchResultsList = document.getElementById('search-results-list');
        const closeSearchResults = document.getElementById('close-search-results');

        // --- UTILITY FUNCTIONS ---
        const showToast = (message, type = 'success') => {
            toast.textContent = message;
            toast.className = 'fixed bottom-5 right-5 text-white py-2 px-4 rounded-lg shadow-lg';
            if (type === 'error') toast.classList.add('bg-red-500');
            else if (type === 'info') toast.classList.add('bg-sky-500');
            else toast.classList.add('bg-green-500');
            toast.classList.remove('hidden');
            setTimeout(() => toast.classList.add('hidden'), 4000);
        };



        const showDashboard = () => {
            if (dashboardView) dashboardView.classList.remove('hidden');
            if (logsView) logsView.classList.add('hidden');
        };

        const showLogs = () => {
            if (dashboardView) dashboardView.classList.add('hidden');
            if (logsView) logsView.classList.remove('hidden');
        };


        if (logsActionPull) logsActionPull.addEventListener('click', () => pullLogsForSelectedHost());
        if (logsActionInfo) logsActionInfo.addEventListener('click', () => showHostInfoMain());
        if (logsActionMonitor) logsActionMonitor.addEventListener('click', () => showHostMonitoringMain());
        if (logsActionSsh) logsActionSsh.addEventListener('click', () => openSshTerminal());

        // ---- Docker monitoring gating -------------------------------------------------
        // The Docker button is only shown for hosts with a reachable Docker endpoint
        // (unix socket over SSH, plain TCP 2375 or TLS 2376).
        let dockerReachableHosts = new Set();
        let dockerHostLabels = {};
        let dockerEndpointsAt = 0;
        let dockerEndpointsPromise = null;

        const loadDockerEndpoints = (force = false) => {
            const fresh = (Date.now() - dockerEndpointsAt) < 60000;
            if (dockerEndpointsPromise && fresh && !force) return dockerEndpointsPromise;
            dockerEndpointsPromise = (async () => {
                try {
                    const data = await window.fetchApi('/api/docker/endpoints');
                    const next = new Set();
                    const labels = {};
                    (data?.endpoints || []).forEach(ep => {
                        if (!ep) return;
                        if (ep.reachable) next.add(String(ep.host_key));
                        if (ep.friendly_name) labels[String(ep.host_key)] = ep.friendly_name;
                    });
                    dockerReachableHosts = next;
                    dockerHostLabels = labels;
                    dockerEndpointsAt = Date.now();
                } catch (err) {
                    // Keep whatever we had; the button simply stays hidden.
                }
                return dockerReachableHosts;
            })();
            return dockerEndpointsPromise;
        };

        const refreshDockerButton = async (hostId) => {
            if (!logsActionDocker) return;
            logsActionDocker.classList.add('hidden');
            if (!hostId) return;
            const requested = String(hostId);
            const reachable = await loadDockerEndpoints();
            if (String(selectedHostId) !== requested) return;
            if (reachable && reachable.has(requested)) {
                logsActionDocker.classList.remove('hidden');
            }
        };

        // Report history for the selected host, in a dialog like Docker (the
        // page itself stays put so the log view is not lost).
        const logsActionReports = document.getElementById('logs-action-reports');
        if (logsActionReports) logsActionReports.addEventListener('click', () => {
            const label = dockerHostLabels[String(selectedHostId || '')]
                || document.getElementById('logs-selected-host-title')?.textContent?.trim()
                || '';
            const host = selectedHostId ? String(selectedHostId) : '';
            if (typeof window.openReportsModal === 'function') {
                window.openReportsModal(host, label);
            } else {
                window.open(host ? `/reports?host=${encodeURIComponent(host)}` : '/reports', '_blank');
            }
        });

        if (logsActionDocker) logsActionDocker.addEventListener('click', () => {
            if (!selectedHostId) return;
            // A modal, not a navigation: the Docker page is chart-heavy and
            // users flip back and forth between it and the logs. The label
            // comes from the endpoint scan so the title reads "Docker — swarm1".
            const label = dockerHostLabels[String(selectedHostId)]
                || document.getElementById('logs-selected-host-title')?.textContent?.trim()
                || '';
            if (typeof window.openDockerModal === 'function') {
                window.openDockerModal(selectedHostId, label);
            } else {
                // Fallback if the module failed to load: keep the old behaviour.
                window.location.href = '/docker/' + encodeURIComponent(selectedHostId);
            }
        });

        // --- SERVER-WIDE CORRELATED REPORT -----------------------------------
        // Runs one analysis over *every* log source on the host and writes a
        // server report (see /reports). Stages come from the SSE pipeline.
        const REPORT_STAGES = ['prepare', 'collect', 'normalise', 'correlate', 'summarise', 'report'];
        const REPORT_STAGE_LABELS = {
            prepare: 'Preparing scope',
            collect: 'Collecting logs',
            normalise: 'Normalising events',
            correlate: 'Correlating sources',
            summarise: 'Asking the model',
            report: 'Saving report'
        };

        const analyseAllLogsBtn = document.getElementById('analyse-all-logs-btn');
        const serverReportModal = document.getElementById('server-report-modal');
        const serverReportForm = document.getElementById('server-report-form');
        const serverReportProgress = document.getElementById('server-report-progress');
        const serverReportResult = document.getElementById('server-report-result');
        const serverReportLog = document.getElementById('server-report-log');
        const serverReportError = document.getElementById('server-report-error');
        const serverReportStart = document.getElementById('server-report-start');
        const serverReportSubtitle = document.getElementById('server-report-subtitle');
        const serverReportEstimate = document.getElementById('server-report-estimate');
        const serverReportSteps = document.getElementById('server-report-steps');
        const serverReportOpen = document.getElementById('server-report-open');
        const serverReportDepth = document.getElementById('server-report-depth');
        const serverReportAutoDepth = document.getElementById('server-report-auto-depth');
        const serverReportDepthHint = document.getElementById('server-report-depth-hint');
        const serverReportSizeCheck = document.getElementById('server-report-size-check');
        const serverReportSizeStatus = document.getElementById('server-report-size-status');
        const serverReportRecommendation = document.getElementById('server-report-recommendation');
        const serverReportSevAll = document.getElementById('server-report-sev-all');
        const serverReportSevCrit = document.getElementById('server-report-sev-crit');
        const serverReportSevError = document.getElementById('server-report-sev-error');
        const serverReportSevWarn = document.getElementById('server-report-sev-warn');
        const serverReportSevHint = document.getElementById('server-report-sev-hint');
        let serverReportDefaults = null;
        let serverReportRunning = false;
        let serverReportLastRecommendation = null;
        let serverReportDepthCosts = null;

        const DEPTH_LABELS = { 1: 'Lite', 2: 'Standard', 3: 'Detailed', 4: 'Deep', 5: 'Maximum' };

        const syncDepthControls = () => {
            if (!serverReportDepth || !serverReportAutoDepth) return;
            const auto = serverReportAutoDepth.checked;
            serverReportDepth.disabled = auto;
            serverReportDepth.classList.toggle('opacity-40', auto);
            if (serverReportDepthHint) {
                const level = String(serverReportDepth.value);
                const meta = (serverReportDefaults?.depths || []).find((d) => String(d.depth) === level);
                const desc = meta?.description || '';
                const cost = (serverReportDepthCosts || []).find((d) => String(d.depth) === level);
                const costText = cost ? ` (${Number(cost.tokens).toLocaleString()} evidence tokens)` : '';
                serverReportDepthHint.textContent = auto
                    ? 'Depth is chosen from the evidence size before the model is called.'
                    : `${DEPTH_LABELS[level]}: ${desc}${costText}`;
            }
        };

        const selectedDepth = () => {
            if (serverReportAutoDepth?.checked) return 0;
            return Number(serverReportDepth?.value) || 3;
        };

        const refreshAnalyseAllLogsButton = async (hostId) => {
            if (!analyseAllLogsBtn) return;
            analyseAllLogsBtn.classList.add('hidden');
            if (!hostId) return;
            try {
                const cfg = await window.fetchApi('/ai/config');
                if (selectedHostId !== hostId) return;
                if (cfg && cfg.provider) analyseAllLogsBtn.classList.remove('hidden');
            } catch (err) {
                // No AI provider configured: button stays hidden.
            }
        };

        const SEVERITY_INPUTS = () => [
            ['crit', serverReportSevCrit],
            ['error', serverReportSevError],
            ['warn', serverReportSevWarn]
        ];

        // "All" is exclusive: it is the classic unfiltered report. Unticking it
        // with nothing else selected would mean "nothing", so we fall back to
        // All rather than silently producing an empty report.
        const selectedSeverities = () => {
            const levels = SEVERITY_INPUTS()
                .filter(([, el]) => el && el.checked && !(serverReportSevAll && serverReportSevAll.checked))
                .map(([name]) => name);
            return levels;
        };

        const syncSeverityControls = (changed) => {
            if (!serverReportSevAll) return;
            if (changed === 'all') {
                if (serverReportSevAll.checked) {
                    SEVERITY_INPUTS().forEach(([, el]) => { if (el) el.checked = false; });
                } else if (!SEVERITY_INPUTS().some(([, el]) => el && el.checked)) {
                    serverReportSevAll.checked = true;
                }
            } else {
                if (SEVERITY_INPUTS().some(([, el]) => el && el.checked)) {
                    serverReportSevAll.checked = false;
                } else {
                    serverReportSevAll.checked = true;
                }
            }
            const levels = selectedSeverities();
            const labels = { crit: 'Critical', error: 'Errors', warn: 'Warnings' };
            if (serverReportSevHint) {
                serverReportSevHint.textContent = levels.length
                    ? levels.map((l) => labels[l]).join(' + ') + ' only'
                    : 'All severities';
                serverReportSevHint.classList.toggle('text-indigo-300', levels.length > 0);
            }
        };

        const wireSeverityControls = () => {
            serverReportSevAll?.addEventListener('change', () => syncSeverityControls('all'));
            SEVERITY_INPUTS().forEach(([, el]) => el?.addEventListener('change', () => syncSeverityControls('level')));
            syncSeverityControls('level');
        };

        const loadServerReportDefaults = async () => {
            if (serverReportDefaults) return serverReportDefaults;
            try {
                const res = await fetch('/api/serverreport/defaults');
                serverReportDefaults = await res.json();
            } catch (err) {
                serverReportDefaults = { window_minutes: 120, model: 'gpt-3.5-turbo', provider_configured: false };
            }
            const windowEl = document.getElementById('server-report-window');
            const modelEl = document.getElementById('server-report-model');
            if (windowEl && serverReportDefaults.window_minutes) {
                windowEl.value = String(serverReportDefaults.window_minutes);
            }
            if (modelEl) {
                // Empty means "use the provider's configured model" - pre-filling
                // another provider's model name would 404 at the API.
                modelEl.value = serverReportDefaults.model || '';
                modelEl.placeholder = serverReportDefaults.model
                    ? serverReportDefaults.model
                    : `${serverReportDefaults.provider_label || 'provider'} default model`;
            }
            if (serverReportDepth && serverReportDefaults.depth) {
                serverReportDepth.value = String(serverReportDefaults.depth);
            }
            syncDepthControls();
            if (serverReportEstimate && serverReportDefaults.provider_configured === false) {
                serverReportEstimate.textContent = 'No AI provider is configured - set one up in Settings first.';
                serverReportEstimate.classList.add('text-red-400');
            } else if (serverReportEstimate) {
                serverReportEstimate.textContent =
                    `Up to ${serverReportDefaults.max_sources || 60} sources, ` +
                    `~${((serverReportDefaults.max_tokens || 12000) / 1000).toFixed(0)}k token budget.`;
            }
            return serverReportDefaults;
        };

        const renderServerReportSteps = () => {
            if (!serverReportSteps) return;
            serverReportSteps.innerHTML = REPORT_STAGES.map((stage) => `
                <li data-report-step="${stage}" class="ai-step">
                    <span class="ai-step-icon">\u25cb</span><span>${REPORT_STAGE_LABELS[stage]}</span>
                </li>`).join('');
        };

        const setServerReportStage = (stage, message, elapsed, extra) => {
            const msgEl = document.getElementById('server-report-progress-message');
            const clockEl = document.getElementById('server-report-progress-elapsed');
            const barEl = document.getElementById('server-report-progress-bar');
            const secs = Math.max(0, Math.round(Number(elapsed) || 0));
            if (msgEl && message) msgEl.textContent = message;
            if (clockEl) clockEl.textContent = `${secs}s`;

            const idx = REPORT_STAGES.indexOf(stage);
            serverReportSteps?.querySelectorAll('[data-report-step]').forEach((li) => {
                const i = REPORT_STAGES.indexOf(li.dataset.reportStep);
                const done = idx >= 0 && i < idx;
                const active = i === idx;
                li.classList.toggle('ai-step-done', done);
                li.classList.toggle('ai-step-active', active);
                const icon = li.querySelector('.ai-step-icon');
                if (icon) icon.textContent = done ? '\u2713' : (active ? '\u25cf' : '\u25cb');
            });

            if (barEl) {
                let pct = 8;
                if (stage === 'prepare') pct = 12;
                else if (stage === 'collect') {
                    const done = Number(extra?.sources_done) || 0;
                    const total = Number(extra?.sources_total) || 0;
                    pct = total ? 15 + Math.round((done / total) * 35) : 22;
                } else if (stage === 'normalise') pct = 55;
                else if (stage === 'correlate') pct = 65;
                else if (stage === 'summarise') pct = Math.min(92, 72 + secs * 0.5);
                else if (stage === 'report') pct = 96;
                barEl.style.width = pct + '%';
            }
        };

        const appendServerReportLog = (text) => {
            if (!serverReportLog || !text) return;
            const line = document.createElement('div');
            line.textContent = text;
            serverReportLog.appendChild(line);
            while (serverReportLog.childElementCount > 200) {
                serverReportLog.removeChild(serverReportLog.firstChild);
            }
            serverReportLog.scrollTop = serverReportLog.scrollHeight;
        };

        const resetServerReportModal = () => {
            serverReportError?.classList.add('hidden');
            if (serverReportError) serverReportError.textContent = '';
            if (serverReportLog) serverReportLog.innerHTML = '';
            serverReportProgress?.classList.add('hidden');
            serverReportResult?.classList.add('hidden');
            serverReportForm?.classList.remove('hidden');
            serverReportRecommendation?.classList.add('hidden');
            if (serverReportSizeStatus) serverReportSizeStatus.textContent = '';
            serverReportLastRecommendation = null;
            serverReportDepthCosts = null;
            renderServerReportSteps();
            serverReportRunning = false;
            if (serverReportStart) {
                serverReportStart.disabled = false;
                serverReportStart.textContent = 'Start analysis';
            }
        };

        const openServerReportModal = async () => {
            if (!serverReportModal || !selectedHostId) return;
            resetServerReportModal();
            const hostName = hosts[selectedHostId]?.friendly_name || selectedHostId;
            if (serverReportSubtitle) {
                serverReportSubtitle.textContent =
                    `Correlate every log source on ${hostName} into one report.`;
            }
            openModal(serverReportModal);
            await loadServerReportDefaults();
        };

        if (analyseAllLogsBtn) {
            analyseAllLogsBtn.addEventListener('click', () => { openServerReportModal(); });
        }
        document.getElementById('close-server-report-btn')?.addEventListener('click', () => {
            if (serverReportRunning) return;  // don't orphan a running pipeline view
            closeModal(serverReportModal);
        });
        document.getElementById('server-report-cancel')?.addEventListener('click', () => {
            closeModal(serverReportModal);
        });
        document.getElementById('server-report-close-2')?.addEventListener('click', () => {
            closeModal(serverReportModal);
        });

        serverReportAutoDepth?.addEventListener('change', syncDepthControls);
        serverReportDepth?.addEventListener('input', syncDepthControls);
        wireSeverityControls();

        const currentScopeBody = () => ({
            host_key: selectedHostId,
            window_minutes: Number(document.getElementById('server-report-window')?.value) || 120,
            model: (document.getElementById('server-report-model')?.value || '').trim() || undefined,
            depth: selectedDepth(),
            include_files: !!document.getElementById('server-report-files')?.checked,
            include_journal: !!document.getElementById('server-report-journal')?.checked,
            include_docker: !!document.getElementById('server-report-docker')?.checked,
            include_stopped: !!document.getElementById('server-report-stopped')?.checked,
            // Omitted when "All" is selected so the request stays byte-identical
            // to the pre-filter behaviour (and hits the same bundle cache key).
            severities: selectedSeverities()
        });

        const renderRecommendation = (payload) => {
            if (!serverReportRecommendation) return;
            const rec = payload.recommendation || {};
            const lines = [
                `<strong>Suggested: ${escapeHtml(rec.depth_label || 'Standard')} depth</strong>` +
                ` &middot; ~${Number(rec.pack_tokens || payload.pack_tokens || 0).toLocaleString()} evidence tokens` +
                (rec.chunks > 1 ? ` &middot; ${rec.chunks} chunk passes` : ' &middot; single pass'),
                `${escapeHtml(String(payload.events || 0))} events &rarr; ${escapeHtml(String(payload.clusters || 0))} signatures, ` +
                `${escapeHtml(String(payload.sources_ok || 0))}/${escapeHtml(String(payload.sources_total || 0))} sources with data`,
            ];
            const filt = payload.filter || {};
            if (filt.active) {
                lines.push(`<span class="text-indigo-300">Severity filter: ${escapeHtml(filt.label || '')}</span>` +
                    ` &middot; ${escapeHtml(String(filt.events_kept || 0))} relevant events` +
                    (filt.events_filtered ? ` &middot; ${escapeHtml(String(filt.events_filtered))} context lines dropped` : '') +
                    ' &middot; filtered on the host before transfer');
            }
            (rec.rationale || []).forEach((line) => lines.push(escapeHtml(line)));
            if (rec.suggest_model) {
                lines.push(`<span class="text-amber-300">Model ${escapeHtml(rec.model || '')} may be too small for this pack ` +
                           `(${escapeHtml(String(rec.usable_input_tokens || 0))} usable input tokens). ` +
                           `Consider <button type="button" id="server-report-apply-model" class="underline">` +
                           `${escapeHtml(rec.suggested_model || '')}</button>.</span>`);
            }
            serverReportRecommendation.innerHTML = lines.map((l) => `<div class="mt-0.5">${l}</div>`).join('');
            serverReportRecommendation.classList.remove('hidden');

            const applyModel = document.getElementById('server-report-apply-model');
            if (applyModel) {
                applyModel.addEventListener('click', () => {
                    const modelEl = document.getElementById('server-report-model');
                    if (modelEl) modelEl.value = rec.suggested_model || '';
                    applyModel.outerHTML = `<span class="text-emerald-300">${escapeHtml(rec.suggested_model || '')} applied</span>`;
                });
            }
        };

        serverReportSizeCheck?.addEventListener('click', async () => {
            if (!selectedHostId || serverReportRunning) return;
            const body = currentScopeBody();
            if (!body.include_files && !body.include_journal && !body.include_docker) {
                if (serverReportSizeStatus) serverReportSizeStatus.textContent = 'Select at least one source type.';
                return;
            }
            serverReportSizeCheck.disabled = true;
            if (serverReportSizeStatus) serverReportSizeStatus.textContent = 'Collecting and sizing (no model call)...';
            try {
                const res = await fetch('/serverreport/preflight', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                const payload = await res.json().catch(() => ({}));
                if (!res.ok) throw new Error(payload.error || `Request failed (${res.status})`);
                serverReportLastRecommendation = payload.recommendation || null;
                serverReportDepthCosts = payload.depth_costs || null;
                syncDepthControls();
                if (serverReportSizeStatus) {
                    serverReportSizeStatus.textContent = 'Size check complete - the next run reuses this collection.';
                }
                renderRecommendation(payload);
            } catch (err) {
                if (serverReportSizeStatus) serverReportSizeStatus.textContent = err.message || 'Size check failed.';
            } finally {
                serverReportSizeCheck.disabled = false;
            }
        });

        if (serverReportStart) {
            serverReportStart.addEventListener('click', async () => {
                if (!selectedHostId || serverReportRunning) return;
                serverReportRunning = true;
                serverReportStart.disabled = true;
                serverReportStart.textContent = 'Analysing...';
                serverReportError?.classList.add('hidden');

                const requestBody = currentScopeBody();

                if (!requestBody.include_files && !requestBody.include_journal && !requestBody.include_docker) {
                    serverReportError.textContent = 'Select at least one log source type.';
                    serverReportError.classList.remove('hidden');
                    serverReportRunning = false;
                    serverReportStart.disabled = false;
                    serverReportStart.textContent = 'Start analysis';
                    return;
                }

                serverReportForm.classList.add('hidden');
                serverReportResult?.classList.add('hidden');
                serverReportProgress.classList.remove('hidden');
                appendServerReportLog('Starting...');
                setServerReportStage('prepare', 'Preparing...', 0);

                try {
                    await streamJsonEvents('/serverreport/stream', requestBody, (evt) => {
                        if (!evt || !evt.type) return;
                        if (evt.type === 'stage') {
                            setServerReportStage(evt.stage, evt.message, evt.elapsed, evt);
                            if (evt.message) appendServerReportLog(evt.message);
                            if (evt.recommendation) renderRecommendation({
                                recommendation: evt.recommendation,
                                events: 0, clusters: 0, sources_ok: 0, sources_total: 0
                            });
                            return;
                        }
                        if (evt.type === 'error') {
                            serverReportRunning = false;
                            serverReportProgress.classList.add('hidden');
                            serverReportForm.classList.remove('hidden');
                            serverReportStart.disabled = false;
                            serverReportStart.textContent = 'Start analysis';
                            serverReportError.textContent = evt.message || 'The analysis failed.';
                            serverReportError.classList.remove('hidden');
                            return;
                        }
                        if (evt.type === 'result') {
                            serverReportRunning = false;
                            serverReportProgress.classList.add('hidden');
                            serverReportResult.classList.remove('hidden');
                            serverReportStart.disabled = false;
                            serverReportStart.textContent = 'Start analysis';
                            const verdict = String(evt.verdict || 'unknown').toUpperCase();
                            const summary = document.getElementById('server-report-result-summary');
                            if (summary) {
                                summary.innerHTML = `
                                    <div class="flex items-center gap-2">
                                        <span class="text-xs px-2 py-0.5 rounded border border-white/15 bg-white/10">${escapeHtml(verdict)}</span>
                                        <span class="termix-muted text-xs">report #${escapeHtml(String(evt.report_id))}</span>
                                    </div>
                                    <div class="mt-2 termix-muted text-xs">
                                        ${escapeHtml(String(evt.sources_ok))}/${escapeHtml(String(evt.sources_ok + evt.sources_failed))} sources with data &middot;
                                        ${escapeHtml(evt.provider || '')}/${escapeHtml(evt.model || '')} &middot;
                                        ${Number(evt.duration_ms || 0) / 1000}s
                                        ${evt.tokens_in ? ' &middot; ~' + escapeHtml(String(evt.tokens_in)) + ' tokens in' : ''}
                                    </div>`;
                            }
                            if (serverReportOpen && evt.url) serverReportOpen.href = evt.url;
                        }
                    });
                } catch (err) {
                    serverReportRunning = false;
                    serverReportProgress.classList.add('hidden');
                    serverReportForm.classList.remove('hidden');
                    serverReportStart.disabled = false;
                    serverReportStart.textContent = 'Start analysis';
                    serverReportError.textContent = err.message || 'The analysis failed.';
                    serverReportError.classList.remove('hidden');
                }
            });
        }

        window.refreshAnalyseAllLogsButton = refreshAnalyseAllLogsButton;

        // Cluster-wide "Scan Docker" action: probes every configured host for a
        // Docker API endpoint, then refreshes the per-host button gating.
        const dockerScanBtn = document.getElementById('docker-scan-btn');
        if (dockerScanBtn) {
            const scanLabel = dockerScanBtn.textContent;
            const restoreScanLabel = (text, delay = 4000) => {
                if (text) dockerScanBtn.textContent = text;
                setTimeout(() => { dockerScanBtn.textContent = scanLabel; }, delay);
            };
            dockerScanBtn.addEventListener('click', async () => {
                if (dockerScanBtn.disabled) return;
                dockerScanBtn.disabled = true;
                dockerScanBtn.textContent = 'Scanning…';
                try {
                    const res = await fetch('/api/docker/discover', {
                        method: 'POST',
                        headers: { 'Accept': 'application/json' }
                    });
                    const data = await res.json();
                    dockerEndpointsAt = 0;
                    dockerEndpointsPromise = null;
                    await loadDockerEndpoints(true);
                    if (selectedHostId) refreshDockerButton(selectedHostId);
                    restoreScanLabel(`Found ${(data && data.found) || 0}`);
                } catch (err) {
                    console.error('Docker scan failed', err);
                    restoreScanLabel('Scan failed');
                } finally {
                    dockerScanBtn.disabled = false;
                }
            });
        }

        const setStatusDot = (el, ok) => {
            if (!el) return;
            el.classList.remove('bg-green-500', 'bg-red-500');
            el.classList.add(ok ? 'bg-green-500' : 'bg-red-500');
        };

        let sshTerm = null;
        let sshFit = null;
        let sshSocket = null;
        let sshConnectedHost = null;

        // SSH session state
        let sshSessionActive = false;           // Socket/session currently connected
        let sshSessionEnded = false;            // Session ended intentionally (via `exit`)
        let sshExpectingExit = false;           // User typed `exit` and we expect disconnect
        let sshInputLineBuffer = '';            // Track typed command line to detect `exit` reliably

        const sshTabsBar = document.getElementById('ssh-tabs-bar');

        // SSH-only "tabs" for open SSH sessions. (We still only render one terminal view.)
        let sshTabs = []; // [{ hostId, hostName }]

        const sshTabsFooter = document.getElementById('ssh-tabs-footer');

        const renderSshTabs = () => {
            if (!sshTabsBar) return;

            if (!sshTabs.length) {
                sshTabsBar.classList.add('hidden');
                sshTabsBar.innerHTML = '';
                if (sshTabsFooter) sshTabsFooter.classList.add('hidden');
                return;
            }

            if (sshTabsFooter) sshTabsFooter.classList.remove('hidden');
            sshTabsBar.classList.remove('hidden');
            sshTabsBar.className = 'flex flex-wrap items-center gap-2';

            const pills = sshTabs.map(t => {
                const isActive = (sshConnectedHost === t.hostId) && (sshSocket && sshSocket.readyState === WebSocket.OPEN);
                const activeCls = isActive ? 'bg-green-600 text-white' : 'bg-white/10 text-gray-200 hover:bg-white/20';
                return `
                    <div class="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-white/10 ${activeCls}" data-ssh-tab="${t.hostId}">
                        <button class="text-xs font-medium" data-ssh-tab-open="${t.hostId}" type="button">SSH: ${t.hostName}</button>
                        <button class="text-xs px-2 py-0.5 rounded-full bg-black/20 hover:bg-black/30" data-ssh-tab-close="${t.hostId}" type="button" title="Close SSH session">×</button>
                    </div>
                `;
            }).join('');

            sshTabsBar.innerHTML = pills;

            sshTabsBar.querySelectorAll('button[data-ssh-tab-open]').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const hostId = btn.getAttribute('data-ssh-tab-open');
                    if (!hostId) return;
                    // Switch selected host and open SSH
                    selectHost(hostId);
                    await openSshTerminal();
                });
            });

            sshTabsBar.querySelectorAll('button[data-ssh-tab-close]').forEach(btn => {
                btn.addEventListener('click', () => {
                    const hostId = btn.getAttribute('data-ssh-tab-close');
                    if (!hostId) return;
                    closeSshSessionForHost(hostId);
                });
            });
        };

        const upsertSshTab = (hostId) => {
            if (!hostId || hostId === 'local') return;
            const hostName = hosts?.[hostId]?.friendly_name || hostId;
            const existing = sshTabs.find(t => t.hostId === hostId);
            if (existing) {
                existing.hostName = hostName;
            } else {
                sshTabs.push({ hostId, hostName });
            }
            renderSshTabs();
        };

        const handleSshUiClose = (hostId) => {
            // User explicitly closed the session via the X button.
            // Best-effort tell backend to disconnect cleanly.
            try {
                if (sshSocket && sshSocket.readyState === WebSocket.OPEN) {
                    sshSocket.send(JSON.stringify({ type: 'disconnect' }));
                }
            } catch (_) {}

            // Reset local session state so next SSH click starts a fresh session.
            sshSessionActive = false;
            sshSessionEnded = true;
            sshExpectingExit = false;
            sshInputLineBuffer = '';

            sshConnectedHost = null;

            try {
                if (sshSocket) sshSocket.close();
            } catch (_) {}
            sshSocket = null;

            // Hide the SSH view and return to host info.
            // (Do this after state reset to avoid accidental resume.)
            setTimeout(() => showHostInfoMain(), 50);
        };

        const closeSshSessionForHost = (hostId) => {
            // If this is the currently connected session, close it.
            if (sshConnectedHost === hostId) {
                handleSshUiClose(hostId);
            }

            // Remove the tab regardless.
            sshTabs = sshTabs.filter(t => t.hostId !== hostId);
            renderSshTabs();
        };

        const setSshStatus = (text, tone = 'muted') => {
            if (!sshTerminalStatus) return;
            sshTerminalStatus.textContent = text;
            sshTerminalStatus.className = `text-xs ${tone === 'error' ? 'text-red-400' : tone === 'ok' ? 'text-green-400' : 'termix-muted'}`;
        };

        const handleSshExitEnded = () => {
            // Mark session as intentionally ended (exit), close ws, and return to host info.
            sshSessionActive = false;
            sshSessionEnded = true;
            sshExpectingExit = false;
            sshInputLineBuffer = '';

            const endedHost = sshConnectedHost;

            // Ensure we don't try to "resume" a dead session
            sshConnectedHost = null;

            // Close websocket so next SSH click starts a fresh session
            try {
                if (sshSocket && sshSocket.readyState === WebSocket.OPEN) sshSocket.close();
            } catch (_) {}
            sshSocket = null;

            // Remove the tab if it was explicitly ended
            if (endedHost) {
                sshTabs = sshTabs.filter(t => t.hostId !== endedHost);
                renderSshTabs();
            }

            // Navigate away from the SSH terminal view
            setTimeout(() => showHostInfoMain(), 50);
        };

        const ensureSshTerminal = async () => {
            if (!sshTerminalBody) return false;
            // Wait for xterm.js to load
            let retries = 0;
            while ((!window.Terminal || !window.FitAddon) && retries < 50) {
                await new Promise(resolve => setTimeout(resolve, 100));
                retries++;
            }
            if (!window.Terminal || !window.FitAddon) {
                showToast('SSH terminal dependencies failed to load.', 'error');
                return false;
            }
            if (!sshTerm) {
                sshTerm = new Terminal({
                    cursorBlink: true,
                    fontFamily: '"JetBrains Mono", monospace',
                    fontSize: 12,
                    theme: { background: '#0b0f17' }
                });
                sshFit = new FitAddon.FitAddon();
                sshTerm.loadAddon(sshFit);
                sshTerm.open(sshTerminalBody);
                sshFit.fit();
                sshTerm.onData((data) => {
                    // Track input locally so we can distinguish an intentional `exit` from other disconnects.
                    // xterm delivers keystrokes; we reconstruct the current line until Enter.
                    for (const ch of data) {
                        if (ch === '\r' || ch === '\n') {
                            const line = sshInputLineBuffer.trim();
                            if (line === 'exit') {
                                sshExpectingExit = true;
                            }
                            sshInputLineBuffer = '';
                        } else if (ch === '\u007f') {
                            // backspace
                            sshInputLineBuffer = sshInputLineBuffer.slice(0, -1);
                        } else if (ch >= ' ' && ch !== '\u001b') {
                            // printable (ignore ESC sequences)
                            sshInputLineBuffer += ch;
                        }
                    }

                    if (sshSocket && sshSocket.readyState === WebSocket.OPEN) {
                        sshSocket.send(JSON.stringify({ type: 'input', data }));
                    }
                });
                window.addEventListener('resize', () => {
                    setTimeout(() => resizeSshTerminal(), 50);
                });
            }
            return true;
        };

        const resizeSshTerminal = () => {
            if (!sshTerm || !sshFit) return;
            sshFit.fit();
            if (sshSocket && sshSocket.readyState === WebSocket.OPEN) {
                sshSocket.send(JSON.stringify({
                    type: 'resize',
                    data: { cols: sshTerm.cols, rows: sshTerm.rows }
                }));
            }
        };

        const closeSshSocket = () => {
            if (sshSocket) {
                try { sshSocket.close(); } catch (_) {}
                sshSocket = null;
            }
        };

        const connectSshSocket = (hostId) => {
            if (!sshTerm) return;
            const wsProto = window.location.protocol === 'https:' ? 'wss' : 'ws';
            const wsUrl = `${wsProto}://${window.location.host}/ssh/websocket`;
            setSshStatus('Connecting...', 'muted');
            closeSshSocket();

            sshSocket = new WebSocket(wsUrl);
            sshSocket.onopen = () => {
                sshConnectedHost = hostId;
                sshSessionActive = true;
                sshSessionEnded = false;
                sshExpectingExit = false;
                sshInputLineBuffer = '';

                upsertSshTab(hostId);
                setSshStatus('Connected', 'ok');
                sshSocket.send(JSON.stringify({
                    type: 'connectToHost',
                    data: { hostId, cols: sshTerm.cols, rows: sshTerm.rows }
                }));
            };
            sshSocket.onmessage = (event) => {
                try {
                    const msg = JSON.parse(event.data);
                    if (msg.type === 'data' && msg.data) {
                        sshTerm.write(msg.data);

                        // Many shells print "logout" when exiting; if the user typed `exit`, treat this as session end.
                        if (sshExpectingExit && /\blogout\b/i.test(msg.data)) {
                            handleSshExitEnded();
                            return;
                        }
                    } else if (msg.type === 'connected') {
                        sshTerm.write('\r\n');
                        sshSessionActive = true;
                        sshSessionEnded = false;
                        sshExpectingExit = false;
                    } else if (msg.type === 'error') {
                        setSshStatus('Error', 'error');
                        const errMsg = msg.data?.message || 'Unknown error';
                        sshTerm.write(`\r\n[error] ${errMsg}\r\n`);

                        // If we were expecting an exit, and the backend now says the channel/socket is closed,
                        // treat it as a successful end-of-session and reset UI state.
                        if (sshExpectingExit && /socket is closed/i.test(errMsg)) {
                            handleSshExitEnded();
                            return;
                        }

                        sshSessionActive = false;
                        sshSessionEnded = false;
                        sshExpectingExit = false;
                    } else if (msg.type === 'disconnected') {
                        setSshStatus('Disconnected', 'muted');
                        sshTerm.write(`\r\n[disconnected] ${msg.data?.message || ''}\r\n`);

                        const endedByExit = !!sshExpectingExit;
                        sshSessionActive = false;
                        sshSessionEnded = endedByExit;
                        sshExpectingExit = false;
                        sshInputLineBuffer = '';

                        // Only auto-navigate when the user intentionally ended the session via `exit`.
                        if (endedByExit) {
                            handleSshExitEnded();
                            return;
                        }
                    }
                } catch (_) {
                    sshTerm.write(event.data);
                }
            };
            sshSocket.onclose = () => {
                setSshStatus('Disconnected', 'muted');

                // If the socket closes without an explicit 'disconnected' message,
                // treat it as ended-by-exit only if we were expecting exit.
                const endedByExit = !!sshExpectingExit;
                sshSessionEnded = endedByExit;
                sshExpectingExit = false;
                sshSessionActive = false;
                sshInputLineBuffer = '';

                // Reset socket reference so a new connection can be made
                sshSocket = null;

                if (endedByExit) {
                    handleSshExitEnded();
                }
            };
            sshSocket.onerror = (error) => {
                setSshStatus('Connection error', 'error');
                // Close socket to allow reconnection
                closeSshSocket();
            };
        };

        const openSshTerminal = async () => {
            const viewToken = ++logsMainViewToken;
            logsMainMode = 'ssh';

            if (!selectedHostId || selectedHostId === 'local') {
                showToast('Select a remote host for SSH.', 'error');
                return;
            }

            const topPane = document.getElementById('logs-top-pane');
            const bottomPane = document.getElementById('logs-bottom-pane');
            const topHeader = document.getElementById('logs-top-header');
            const logTableContainer = document.getElementById('log-table-container');

            // Hide the log panes and show SSH terminal to fill the entire space
            if (topPane) {
                topPane.classList.add('hidden');
                topPane.style.height = '40%';
            }
            if (bottomPane) {
                bottomPane.classList.add('hidden');
                bottomPane.style.height = '50%';
            }

            if (topHeader) topHeader.classList.add('hidden');
            if (logTableContainer) logTableContainer.classList.add('hidden');
            if (sshTerminalContainer) {
                sshTerminalContainer.classList.remove('hidden');
                // Keep sizing consistent with the rest of the logs view (no fixed positioning/overlays)
                sshTerminalContainer.style.position = '';
                sshTerminalContainer.style.top = '';
                sshTerminalContainer.style.left = '';
                sshTerminalContainer.style.right = '';
                sshTerminalContainer.style.bottom = '';
                sshTerminalContainer.style.zIndex = '';
            }

            // Ensure dependencies are loaded
            if (!(await ensureSshTerminal())) return;

            // If we still have a live socket for this host AND the session hasn't been ended via `exit`,
            // just resume the existing session.
            if (!sshSessionEnded && sshSocket && sshSocket.readyState === WebSocket.OPEN && sshConnectedHost === selectedHostId) {
                setSshStatus('Connected', 'ok');
                sshSessionActive = true;
                resizeSshTerminal();
                return;
            }

            // If the socket is not open, drop it so we can reconnect cleanly.
            if (sshSocket && sshSocket.readyState !== WebSocket.OPEN) {
                sshSocket = null;
            }

            // Start a fresh session when the previous one ended via `exit`, or if switching hosts.
            if (sshSessionEnded || sshConnectedHost !== selectedHostId) {
                sshTerm.clear();
            }

            resizeSshTerminal();
            connectSshSocket(selectedHostId);
        };


        const toggleOpenaiKeyVisibilityBtn = document.getElementById('toggle-openai-key-visibility');
        const toggleDiscordWebhookVisibilityBtn = document.getElementById('toggle-discord-webhook-visibility');

        const wireVisibilityToggle = (btn, input) => {
            if (!btn || !input) return;
            btn.addEventListener('click', () => {
                const show = input.type === 'password';
                input.type = show ? 'text' : 'password';
                btn.textContent = show ? 'Hide' : 'Show';
            });
        };

        wireVisibilityToggle(toggleOpenaiKeyVisibilityBtn, openaiApiKeyInput);
        wireVisibilityToggle(toggleDiscordWebhookVisibilityBtn, discordWebhookInput);

        const downloadFromPost = async (url, fallbackFilename) => {
            const resp = await fetch(url, { method: 'POST' });
            if (!resp.ok) {
                let msg = `Request failed (${resp.status})`;
                try {
                    const data = await resp.json();
                    if (data && data.error) msg = data.error;
                } catch (_) {}
                throw new Error(msg);
            }

            const blob = await resp.blob();

            // Try to honor Content-Disposition filename
            let filename = fallbackFilename;
            const cd = resp.headers.get('Content-Disposition') || resp.headers.get('content-disposition');
            if (cd) {
                const m = /filename\s*=\s*([^;]+)/i.exec(cd);
                if (m && m[1]) {
                    filename = m[1].trim().replace(/^"|"$/g, '');
                }
            }

            const blobUrl = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = blobUrl;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(() => URL.revokeObjectURL(blobUrl), 2000);
        };


        const fetchApi = async (endpoint, options = {}) => {
            // Set default timeout of 60 seconds for API calls
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 60000);
            
            try {
                const response = await fetch(endpoint, {
                    ...options,
                    signal: controller.signal
                });
                clearTimeout(timeoutId);
                
                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({error: 'An unknown server error occurred.'}));
                    throw new Error(errorData.error);
                }
                return response.json();
            } catch (error) {
                clearTimeout(timeoutId);
                if (error.name === 'AbortError') {
                    console.error("Request timed out:", endpoint);
                    window.showToast('Request timed out. Please try again.', 'error');
                    throw new Error('Request timed out');
                } else {
                    console.error("API Error:", error);
                    window.showToast(error.message, 'error');
                    throw error;
                }
            }
        };
        
        // runSortAndFilter function removed - not needed for current UI

        // --- TABLE VIEW FUNCTIONS ---
        const fetchTableView = async () => {
            sourceListContainer.innerHTML = '';
            logTitle.textContent = 'Loading logs from all hosts...';
            logContent.innerHTML = '';
            aiAnalyseBtn.classList.add('hidden');
            truncationWarning.classList.add('hidden');
            progressContainer.classList.remove('hidden');
            progressBar.style.width = '0%';
            progressMessage.textContent = 'Fetching logs from all hosts...';
            progressLogs.innerHTML = '';

            try {
                const data = await window.fetchApi('/sources/table');
                tableData = data;
                renderTableView(data);
                
                progressBar.style.width = '100%';
                progressMessage.textContent = 'Table view loaded!';
                logTitle.textContent = `Table View - ${data.logs.length} logs across ${data.successful_hosts} hosts`;
                
                setTimeout(() => progressContainer.classList.add('hidden'), 1500);
            } catch (error) {
                sourceListContainer.innerHTML = `<li class="p-4 text-red-400">Failed to load table view: ${escapeHtml(error.message)}</li>`;
                progressContainer.classList.add('hidden');
            }
        };

        const renderTableView = (data) => {
            sourceListContainer.innerHTML = '';
            
            if (data.failed_hosts && data.failed_hosts.length > 0) {
                const warningLi = document.createElement('li');
                warningLi.className = 'mb-2 p-2 bg-yellow-900/30 border border-yellow-600 rounded text-yellow-200 text-xs';
                warningLi.innerHTML = `⚠️ ${data.failed_hosts.length} host(s) failed to connect`;
                sourceListContainer.appendChild(warningLi);
            }
            
            if (data.logs.length === 0) {
                const noLogsLi = document.createElement('li');
                noLogsLi.className = 'p-4 text-center termix-muted';
                noLogsLi.textContent = 'No logs found on any accessible hosts.';
                sourceListContainer.appendChild(noLogsLi);
                return;
            }
            
            data.logs.forEach(log => {
                const li = document.createElement('li');
                li.className = 'log-table-item mb-2 bg-white/5 rounded-lg p-3 border border-white/10';
                
                const logHeader = document.createElement('div');
                logHeader.className = 'flex items-center justify-between mb-2';
                
                const logTitle = document.createElement('span');
                logTitle.className = 'font-medium text-white truncate flex-grow';
                logTitle.textContent = log.name;
                
                const logType = document.createElement('span');
                logType.className = `text-xs px-2 py-1 rounded ${
                    log.type === 'file' ? 'bg-blue-600 text-blue-100' : 'bg-purple-600 text-purple-100'
                }`;
                logType.textContent = log.type;
                
                logHeader.appendChild(logTitle);
                logHeader.appendChild(logType);
                
                const hostsContainer = document.createElement('div');
                hostsContainer.className = 'flex flex-wrap gap-1';
                
                data.hosts.forEach(host => {
                    const hostBadge = document.createElement('button');
                    const hasLog = log.hosts[host.host_id];
                    
                    if (hasLog) {
                        hostBadge.className = 'px-2 py-1 text-xs rounded bg-green-600 hover:bg-green-500 text-white transition-colors cursor-pointer';
                        hostBadge.title = `${hasLog.size_formatted} - ${hasLog.modified_formatted}`;
                        hostBadge.textContent = host.host_name;
                        
                        hostBadge.onclick = () => {
                            loadLogContent(log.name, log.type, host.host_id, host.host_name);
                        };
                    } else {
                        hostBadge.className = 'px-2 py-1 text-xs rounded bg-white/10 termix-muted cursor-not-allowed';
                        hostBadge.textContent = host.host_name;
                        hostBadge.disabled = true;
                    }
                    
                    hostsContainer.appendChild(hostBadge);
                });
                
                li.appendChild(logHeader);
                li.appendChild(hostsContainer);
                sourceListContainer.appendChild(li);
            });
        };

        // Single function to update AI Analyse button visibility based on /ai/config endpoint
        const updateAiAnalyseBtnVisibility = async (hasContent = true, willBeTruncated = false) => {
            aiAnalyseBtn.classList.add('hidden');
            truncationWarning.classList.add('hidden');
            
            if (!hasContent) return;
            
            try {
                const aiConfig = await window.fetchApi('/ai/config');
                if (aiConfig && aiConfig.provider) {
                    aiAnalyseBtn.classList.remove('hidden');
                    if (willBeTruncated) truncationWarning.classList.remove('hidden');
                }
            } catch (err) {
                // Silently fail - button stays hidden if config can't be fetched
            }
        };

        const loadLogContent = async (logName, logType, hostId, hostName) => {
            currentLogName = logName;
            logTitle.textContent = `Loading: ${logName} from ${hostName}...`;
            logContent.innerHTML = '<div class="text-center termix-muted mt-16">Fetching log data...</div>';
            await updateAiAnalyseBtnVisibility(false);

            const hostParam = hostId === 'local' ? '' : `?host=${hostId}`;
            const url = logType === 'file'
                ? `/log/${encodeURIComponent(logName)}${hostParam}`
                : (logType === 'docker'
                    ? `/api/docker/log/${encodeURIComponent(logName)}${hostParam}`
                    : `/journal/${encodeURIComponent(logName)}${hostParam}`);

            try {
                const response = await fetch(url);
                const data = await response.json();
                if (!response.ok) throw new Error(data.error);
                
                currentLogContent = data.content;
                logTitle.textContent = `${logName} on ${hostName}`;
                // Log lines are untrusted host output - use textContent, never innerHTML.
                logContent.innerHTML = '<pre class="text-sm termix-text font-mono whitespace-pre-wrap"></pre>';
                logContent.querySelector('pre').textContent = data.content || 'Log source is empty.';
                
                // Update button visibility based on content and AI config
                await updateAiAnalyseBtnVisibility(!!data.content, data.will_be_truncated);
            } catch (error) {
                logTitle.textContent = `Error loading ${logName}`;
                logContent.innerHTML = `<div class="text-center text-red-400 mt-16">${escapeHtml(error.message)}</div>`;
                window.showToast(error.message, 'error');
            }
        };

        // switchViewMode function removed - view mode buttons don't exist in current UI

        // --- HOST CARD FUNCTIONS ---

        const updateDashboardStats = async () => {
            try {
                const totalHosts = 1 + (hosts ? Object.keys(hosts).length : 0);
                if (dashboardTotalHostsEl) dashboardTotalHostsEl.textContent = String(totalHosts);

                // Schedules count
                try {
                    const sched = await window.fetchApi('/api/schedules');
                    if (dashboardTotalSchedulesEl) dashboardTotalSchedulesEl.textContent = String((sched || []).length);
                    if (dashboardDbStatusEl) {
                        dashboardDbStatusEl.textContent = 'Database: Healthy';
                        dashboardDbStatusEl.classList.add('termix-chip-ok');
                    }
                } catch (_) {
                    if (dashboardDbStatusEl) dashboardDbStatusEl.textContent = 'Database: Unknown';
                }
            } catch (_) {}
        };

        const populateHostCards = async () => {
            console.log('[DEBUG] Starting populateHostCards()');
            try {
                console.log('[DEBUG] Fetching hosts from /hosts endpoint...');
                const hostsData = await window.fetchApi('/hosts');
                console.log('[DEBUG] Received hosts data:', hostsData);
                hosts = hostsData;

                // Ensure controls reflect persisted state
                if (hostsSortSelect) hostsSortSelect.value = getHostsSortMode();

                hostListContainer.innerHTML = '';

                // Add localhost card (always pinned to top)
                console.log('[DEBUG] Creating localhost card...');
                const localhostCard = createHostCard('local', {
                    friendly_name: 'Localhost',
                    ip: 'localhost',
                    user: 'local',
                    description: 'Local machine'
                });
                hostListContainer.appendChild(localhostCard);

                // Add remote host cards in desired order
                const ordered = getOrderedHostEntries(hosts);
                console.log(`[DEBUG] Creating ${ordered.length} remote host cards...`);
                for (const [id, host] of ordered) {
                    console.log(`[DEBUG] Creating card for host: ${host.friendly_name} (${id})`);
                    const hostCard = createHostCard(id, host);
                    hostListContainer.appendChild(hostCard);
                }

                // In manual mode, keep manual order list up to date with newly seen hosts
                if (getHostsSortMode() === 'manual') {
                    const manual = getManualOrder();
                    const seen = new Set(manual);
                    let changed = false;
                    for (const [id] of ordered) {
                        if (!seen.has(id)) { manual.push(id); seen.add(id); changed = true; }
                    }
                    // Also drop any IDs that no longer exist
                    const existing = new Set(Object.keys(hosts || {}));
                    const filtered = manual.filter(id => existing.has(id));
                    if (filtered.length !== manual.length) changed = true;
                    if (changed) setManualOrder(filtered);
                }

                // Select localhost by default
                console.log('[DEBUG] Selecting localhost by default...');
                window.showDashboard();
                updateDashboardStats();
                // Do not auto-open logs on load; default to dashboard
                // selectHost('local');
                console.log('[DEBUG] populateHostCards() completed successfully');
            } catch (error) {
                console.error('[DEBUG] Error in populateHostCards():', error);
                hostListContainer.innerHTML = '<div class="p-4 text-red-400">Failed to load hosts.</div>';
            }
        };
        

        // Expose a refresh hook for the Add Devices wizard to update the sidebar without a full page reload
        window.refreshHostsSidebar = populateHostCards;
        const createHostCard = (hostId, hostData) => {
            const card = document.createElement('div');
            card.className = 'host-card termix-host';
            card.dataset.hostId = hostId;

            const isManualMode = (getHostsSortMode() === 'manual');
            const isReorderable = isManualMode && hostId !== 'local';
            if (isReorderable) {
                // We keep the card draggable, but only allow drag when the user grabs the handle.
                card.draggable = true;
                card.title = 'Drag the handle to reorder';
            }

            const grabHandleHtml = isReorderable ? `
                <div class="hosts-grab-handle shrink-0 mr-3 px-2 py-2 rounded bg-white/5 border border-white/10 text-gray-300"
                     title="Drag to reorder" aria-label="Drag handle" role="button" tabindex="0">
                    <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 6h.01M8 12h.01M8 18h.01M12 6h.01M12 12h.01M12 18h.01M16 6h.01M16 12h.01M16 18h.01" />
                    </svg>
                </div>
            ` : '';

            card.innerHTML = `
                <div class="flex items-center justify-between">
                    <div class="flex items-center min-w-0 flex-1">
                        ${grabHandleHtml}
                        <div class="min-w-0 flex-1">
                            <h3 class="font-bold termix-text truncate">${hostData.friendly_name}</h3>
                            <p class="text-sm termix-muted truncate">Group: ${(hostData.group_names && hostData.group_names.length) ? hostData.group_names.join(', ') : 'none'}</p>
                            <p class="text-xs termix-muted font-mono truncate">${hostData.user}@${hostData.ip}</p>
                        </div>
                    </div>
                    <div class="flex items-center space-x-3 shrink-0">
                        <div class="connection-indicator w-3 h-3 rounded-full bg-green-500 animate-pulse"></div>
                    </div>
                </div>
            `;

            // Clicking the card selects a host but does NOT automatically pull logs
            card.addEventListener('click', (e) => {
                // Avoid click-select while dragging
                if (card.dataset.dragging === '1') return;
                selectHost(hostId);
            });

            // Drag/drop reordering (manual mode only)
            if (isReorderable) {
                const handle = card.querySelector('.hosts-grab-handle');
                const armDrag = () => { card.dataset.allowDrag = '1'; };
                const disarmDrag = () => { card.dataset.allowDrag = '0'; };

                if (handle) {
                    handle.classList.add('cursor-grab');
                    handle.addEventListener('mousedown', armDrag);
                    handle.addEventListener('mouseup', disarmDrag);
                    handle.addEventListener('mouseleave', disarmDrag);
                    handle.addEventListener('keydown', (e) => {
                        // Allow keyboard users to start drag with Enter/Space (still uses mouse for drop)
                        if (e.key === 'Enter' || e.key === ' ') {
                            armDrag();
                        }
                    });
                }

                card.addEventListener('dragstart', (e) => {
                    // Only start drag if the user grabbed the handle.
                    if (card.dataset.allowDrag !== '1') {
                        e.preventDefault();
                        return;
                    }

                    card.dataset.dragging = '1';
                    try { e.dataTransfer.setData('text/plain', hostId); } catch (_) {}
                    e.dataTransfer.effectAllowed = 'move';
                    card.classList.add('opacity-60');
                    card.classList.add('hosts-dragging');
                });

                card.addEventListener('dragend', () => {
                    card.classList.remove('opacity-60');
                    card.classList.remove('hosts-dragging');
                    card.classList.remove('hosts-drag-over');
                    card.dataset.dragging = '0';
                    disarmDrag();
                });

                card.addEventListener('dragenter', (e) => {
                    e.preventDefault();
                    if (card.dataset.dragging === '1') return;
                    card.classList.add('hosts-drag-over');
                });

                card.addEventListener('dragleave', (e) => {
                    // Only remove highlight if leaving the card entirely
                    if (!card.contains(e.relatedTarget)) {
                        card.classList.remove('hosts-drag-over');
                    }
                });

                card.addEventListener('dragover', (e) => {
                    // Allow drop
                    e.preventDefault();
                    e.dataTransfer.dropEffect = 'move';
                });

                card.addEventListener('drop', (e) => {
                    e.preventDefault();
                    card.classList.remove('hosts-drag-over');

                    const draggedId = (e.dataTransfer && e.dataTransfer.getData('text/plain')) || '';
                    if (!draggedId || draggedId === hostId) return;
                    if (getHostsSortMode() !== 'manual') return;

                    const draggedEl = hostListContainer.querySelector(`.host-card[data-host-id="${CSS.escape(draggedId)}"]`);
                    if (!draggedEl) return;

                    // Insert dragged before drop target
                    hostListContainer.insertBefore(draggedEl, card);

                    // Persist manual order based on current DOM (excluding localhost)
                    const ids = Array.from(hostListContainer.querySelectorAll('.host-card'))
                        .map(el => el.dataset.hostId)
                        .filter(id => id && id !== 'local');
                    setManualOrder(ids);
                });
            }

            return card;
        };
        


        const showHostInfo = async (hostId, hostData) => {
            const existing = document.getElementById('host-info-overlay');
            if (existing) existing.remove();

            const overlay = document.createElement('div');
            overlay.id = 'host-info-overlay';
            overlay.className = 'fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-[9999]';

            const card = document.createElement('div');
            card.className = 'termix-panel max-w-xl w-full p-6 relative border border-white/10';

            const baseHeader = `
                <div class="flex items-center justify-between mb-4">
                    <div class="min-w-0">
                        <h2 class="text-xl font-bold termix-text truncate" title="${hostData.friendly_name}">${hostData.friendly_name}</h2>
                        <p class="text-sm termix-muted truncate" title="${hostData.description || 'No description'}">${hostData.description || 'No description'}</p>
                    </div>
                    <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold bg-indigo-50 text-indigo-700">
                        ${hostId === 'local' ? 'Local' : 'Remote'}
                    </span>
                </div>
            `;

            card.innerHTML = baseHeader + `
                <div class="space-y-3 text-sm termix-text" id="host-info-body">
                    <p class="text-xs termix-muted">Loading host details...</p>
                </div>
                <div class="mt-4 flex justify-between items-center">
                    <button id="host-info-rescan" class="px-4 py-2 text-sm font-medium bg-amber-500 hover:bg-amber-400 text-black rounded-lg">
                        Rescan
                    </button>
                    <button id="host-info-close" class="px-4 py-2 text-sm font-medium bg-gray-800 text-white rounded-lg hover:bg-white/5">
                        Close
                    </button>
                </div>
            `;

            overlay.appendChild(card);
            document.body.appendChild(overlay);

            const close = () => overlay.remove();
            overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
            card.querySelector('#host-info-close').addEventListener('click', close);

            const bodyEl = card.querySelector('#host-info-body');

            // Localhost or non-DB hosts: only basic info
            if (hostId === 'local' || !hostId.startsWith('db-')) {
                bodyEl.innerHTML = `
                    <div class="flex items-center">
                        <span class="w-6 h-6 mr-2 text-blue-500">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7h18M3 12h18M3 17h18"></path>
                            </svg>
                        </span>
                        <span class="font-mono">${hostData.user}@${hostData.ip}</span>
                    </div>
                    <p class="text-xs termix-muted mt-2">Detailed system info is only available for hosts onboarded via the wizard.</p>
                `;
                return;
            }

            try {
                const dbId = parseInt(hostId.split('-')[1], 10);
                const rescanBtn = card.querySelector('#host-info-rescan');

                const renderHostInfo = (info) => {
                    const si = info.system_info || {};
                    const svcSummary = info.services_summary || { total: 0, running: 0, stopped: 0 };

                    const fmtBytes = (v) => {
                        if (!v && v !== 0) return 'N/A';
                        const gb = v / (1024 ** 3);
                        return `${gb.toFixed(1)} GB`;
                    };

                    bodyEl.innerHTML = `

                    <div class="flex items-center justify-between">
                        <span class="font-mono truncate" title="${info.ssh_user || hostData.user}@${info.ip_address || hostData.ip}">
                            ${(info.ssh_user || hostData.user)}@${info.ip_address || hostData.ip}
                        </span>
                    </div>
                    <div class="grid grid-cols-2 gap-3 mb-3">
                        <div class="p-3 rounded-lg bg-white/5 space-y-1">
                            <p class="text-xs font-semibold termix-muted">OS / Hostname</p>
                            <p class="text-xs termix-text break-all">${si.os_version || 'Unknown OS'}</p>
                            <p class="text-xs termix-muted">Hostname: ${si.hostname || 'N/A'}</p>
                            <p class="text-xs termix-muted">Last update: ${si.last_update || 'N/A'}</p>
                        </div>
                        <div class="p-3 rounded-lg bg-white/5 space-y-1">
                            <p class="text-xs font-semibold termix-muted">Resources</p>
                            <p class="text-xs termix-text">RAM: ${fmtBytes(si.ram_total)} total, ${fmtBytes(si.ram_used)} used</p>
                            <p class="text-xs termix-text">Disk: ${fmtBytes(si.disk_total)} total, ${fmtBytes(si.disk_used)} used</p>
                            <p class="text-xs termix-text">CPU: ${si.cpu_type || 'Unknown'}, cores: ${si.cpu_cores || 'N/A'}</p>
                        </div>
                    </div>
                    <div class="grid grid-cols-2 gap-3 mb-3">
                        <div class="p-3 rounded-lg bg-white/5 space-y-1">
                            <p class="text-xs font-semibold termix-muted">Network</p>
                            <p class="text-xs termix-text">Main IP: ${si.main_ip || 'N/A'}</p>
                            <p class="text-xs termix-text">Netbird IP: ${si.netbird_ip || 'N/A'}</p>
                        </div>
                        <div class="p-3 rounded-lg bg-white/5 space-y-1">
                            <p class="text-xs font-semibold termix-muted">Services</p>
                            <p class="text-xs termix-text">Total: ${svcSummary.total}</p>
                            <p class="text-xs text-green-700">Running: ${svcSummary.running}</p>
                            <p class="text-xs text-red-700">Stopped: ${svcSummary.stopped}</p>
                        </div>
                    </div>
                `;
                };

                const loadInfo = async () => {
                    const resp = await fetch(`/hosts/db/${dbId}/info`);
                    const info = await resp.json();
                    if (info.error) {
                        bodyEl.innerHTML = `<p class="text-xs text-red-600">Error loading host info: ${info.error}</p>`;
                        return null;
                    }
                    renderHostInfo(info);
                    return info;
                };

                // Initial load
                await loadInfo();

                if (rescanBtn) {
                    rescanBtn.addEventListener('click', async () => {
                        rescanBtn.disabled = true;
                        rescanBtn.textContent = 'Rescanning...';
                        try {
                            const resp = await fetch(`/hosts/db/${dbId}/rescan`, { method: 'POST' });
                            const info = await resp.json();
                            if (!resp.ok || info.error) {
                                throw new Error(info.error || `Rescan failed (${resp.status})`);
                            }
                            renderHostInfo(info);
                            window.showToast('Rescan complete.', 'success');
                        } catch (err) {
                            window.showToast(err.message || 'Rescan failed.', 'error');
                        } finally {
                            rescanBtn.disabled = false;
                            rescanBtn.textContent = 'Rescan';
                        }
                    });
                }

            } catch (err) {
                console.error('Error loading host info', err);
                bodyEl.innerHTML = `<p class="text-xs text-red-600">Error loading host info: ${err.message}</p>`;
            }
        };

        const selectHost = (hostId) => {
            selectedHostId = hostId;

            // Switch into logs view
            showLogs();
            const hostName = hostId === 'local' ? 'Localhost' : (hosts[hostId]?.friendly_name || hostId);
            if (logsSelectedHostTitle) logsSelectedHostTitle.textContent = `Host: ${hostName}`;
            if (dashboardSelectedHostEl) dashboardSelectedHostEl.textContent = hostName;

            // Update card selection visuals
            hostListContainer.querySelectorAll('.host-card').forEach(card => {
                if (card.dataset.hostId === hostId) {
                    card.classList.add('termix-host-selected');
                    card.classList.remove('termix-host');
                } else {
                    card.classList.add('termix-host');
                    card.classList.remove('termix-host-selected');
                }
            });

            // Show the Docker button only when this host has a reachable endpoint
            refreshDockerButton(hostId);
            // "Analyse All Logs" needs a configured AI provider (window lookup
            // avoids a temporal-dead-zone hit if this runs before the block below).
            if (window.refreshAnalyseAllLogsButton) window.refreshAnalyseAllLogsButton(hostId);

            // Default view: show host info in the main panel
            showHostInfoMain();
        };


        

        let selectedMonitorIds = new Set();

        const showHostMonitoringMain = async () => {
            const hostId = selectedHostId;
            const viewToken = ++logsMainViewToken;
            logsMainMode = 'monitor';

            if (!hostId || hostId === 'local') {
                window.location.href = '/monitoring/wizard';
                return;
            }

            let dbId = null;
            if (String(hostId).startsWith('db-')) {
                const raw = String(hostId).split('-', 2)[1];
                const n = parseInt(raw, 10);
                if (!Number.isNaN(n)) dbId = n;
            }

            if (!dbId) {
                window.location.href = '/monitoring/wizard';
                return;
            }

            const fmtMonTs = (ts) => {
                if (!ts) return '-';
                try {
                    const d = new Date(ts);
                    if (Number.isNaN(d.getTime())) return ts;
                    const pad = (n) => String(n).padStart(2, '0');
                    return `${d.getFullYear()}/${pad(d.getMonth()+1)}/${pad(d.getDate())} - ${pad(d.getHours())}:${pad(d.getMinutes())}`;
                } catch (_) {
                    return ts;
                }
            };

            // Popup-style monitoring modal (similar UX to the Add Devices wizard)
            const ensureMonitoringModal = () => {
                let overlay = document.getElementById('monitoring-modal-overlay');
                if (overlay) return overlay;

                overlay = document.createElement('div');
                overlay.id = 'monitoring-modal-overlay';
                overlay.className = 'fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-[9999]';

                overlay.innerHTML = `
                    <div class="termix-panel w-full max-w-6xl h-[85vh] p-0 border border-white/10 rounded-xl overflow-hidden flex flex-col">
                        <div class="px-6 py-4 border-b border-white/10 flex items-center justify-between gap-3">
                            <div class="min-w-0">
                                <div class="termix-text text-lg font-semibold truncate" id="monitoring-modal-title">Monitoring</div>
                                <div class="text-xs termix-muted truncate" id="monitoring-modal-subtitle">Loading...</div>
                            </div>
                            <div class="flex items-center gap-2">
                                <button id="monitoring-modal-refresh" class="bg-white/10 hover:bg-white/20 text-white text-sm px-3 py-2 rounded-lg" type="button">Refresh</button>
                                <button id="monitoring-modal-close" class="bg-white/10 hover:bg-white/20 text-white text-sm px-3 py-2 rounded-lg" type="button">Close</button>
                            </div>
                        </div>
                        <div class="flex-1 overflow-auto" id="monitoring-modal-body">
                            <div class="p-6 text-sm termix-muted">Loading monitoring data...</div>
                        </div>
                    </div>
                `;

                overlay.addEventListener('click', (e) => {
                    if (e.target === overlay) overlay.remove();
                });

                document.body.appendChild(overlay);
                return overlay;
            };

            const overlay = ensureMonitoringModal();
            const body = overlay.querySelector('#monitoring-modal-body');
            const titleEl = overlay.querySelector('#monitoring-modal-title');
            const subtitleEl = overlay.querySelector('#monitoring-modal-subtitle');
            const closeBtn = overlay.querySelector('#monitoring-modal-close');
            const refreshBtn = overlay.querySelector('#monitoring-modal-refresh');

            if (closeBtn) closeBtn.onclick = () => overlay.remove();
            if (refreshBtn) refreshBtn.onclick = () => showHostMonitoringMain();

            const hostName = hosts[hostId]?.friendly_name || hostId;
            if (titleEl) titleEl.textContent = `Monitoring: ${hostName}`;
            if (subtitleEl) subtitleEl.textContent = 'Fetching monitors...';
            if (body) body.innerHTML = `<div class="p-6 text-sm termix-muted">Loading monitoring data...</div>`;

            try {
                const data = await window.fetchApi(`/api/hosts/${dbId}/monitoring`);
                if (data && data.error) throw new Error(data.error);

                // If user navigated away while loading, avoid clobbering other views.
                if (viewToken !== logsMainViewToken || logsMainMode !== 'monitor') return;

                const monitors = data.monitors || [];
                const dockerSnap = data.docker_snapshot;

                if (!monitors.length) {
                    // No monitors exist yet for this host; open the wizard in a modal (not a full-page redirect).
                    try {
                        if (overlay) overlay.remove();
                    } catch (_) {}
                    if (typeof window.openMonitoringWizard === 'function') {
                        window.openMonitoringWizard(dbId);
                    } else {
                        window.location.href = `/monitoring/wizard?host_id=${dbId}`;
                    }
                    return;
                }

                const rows = monitors.map(m => {
                    const cfg = m.config || {};
                    let target = '-';
                    if (m.type === 'http') target = cfg.url || '-';
                    else if (m.type === 'tcp') target = `${cfg.hostname || ''}:${cfg.port || ''}`;
                    else if (m.type === 'docker_container') target = cfg.container_name || '-';
                    else if (m.type === 'udp_listen') target = `:${cfg.port || ''}/udp`;

                    const status = m.last_status || 'never';
                    const statusClass = status === 'up' ? 'text-green-400' : (status === 'down' ? 'text-amber-400' : (status === 'error' ? 'text-red-400' : 'text-slate-400'));
                    const err = m.last_error_message ? `<div class="text-xs text-slate-400 max-w-xl truncate">${m.last_error_message}</div>` : '';
                    const rtt = (m.last_response_time_ms !== null && m.last_response_time_ms !== undefined) ? `${m.last_response_time_ms}ms` : '-';

                    const checked = selectedMonitorIds.has(m.id) ? 'checked' : '';

                    const iconBtn = (title, cls, svg) => `
                      <button class="${cls} bg-white/10 hover:bg-white/20 px-2 py-1 rounded" title="${title}" aria-label="${title}" type="button">${svg}</button>
                    `;

                    const svgPlay = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5v14l11-7z"/></svg>';
                    const svgEdit = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 20h9"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg>';
                    const svgTrash = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 6h18"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 6V4h8v2"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg>';

                    return `
                      <tr class="border-b border-white/5" data-mid="${m.id}">
                        <td class="py-2 pr-3"><input class="mon-cb" type="checkbox" data-mid="${m.id}" ${checked} /></td>
                        <td class="py-2 pr-4">${m.name}</td>
                        <td class="py-2 pr-4">${m.type}</td>
                        <td class="py-2 pr-4">${target}</td>
                        <td class="py-2 pr-4"><span class="${statusClass}">${status}</span>${err}</td>
                        <td class="py-2 pr-4">${fmtMonTs(m.last_checked_at)}</td>
                        <td class="py-2 pr-4">${rtt}</td>
                        <td class="py-2 pr-2">
                          <div class="flex gap-2">
                            ${iconBtn('Test now', 'mon-test', svgPlay)}
                            ${iconBtn('Edit', 'mon-edit', svgEdit)}
                            ${iconBtn('Delete', 'mon-del', svgTrash)}
                          </div>
                        </td>
                      </tr>
                    `;
                }).join('');

                let dockerHtml = '';
                if (dockerSnap && dockerSnap.inventory) {
                    const inv = dockerSnap.inventory;
                    const dockerInstalled = !!inv.docker;
                    const containers = inv.containers || [];
                    if (!dockerInstalled) {
                        dockerHtml = `<div class="text-sm termix-muted">Docker: not detected</div>`;
                    } else {
                        const contRows = containers.map(c => `
                          <tr class="border-b border-white/5">
                            <td class="py-2 pr-4">${c.Names || ''}</td>
                            <td class="py-2 pr-4">${c.Image || ''}</td>
                            <td class="py-2 pr-4">${c.Status || ''}</td>
                            <td class="py-2 pr-4 text-xs text-slate-300">${c.Ports || ''}</td>
                          </tr>
                        `).join('');
                        dockerHtml = `
                          <div class="text-sm termix-muted">Docker inventory (latest) — captured at ${dockerSnap.captured_at || ''}</div>
                          <div class="mt-2 overflow-x-auto">
                            <table class="min-w-full text-sm">
                              <thead>
                                <tr class="text-left text-slate-300 border-b border-white/10">
                                  <th class="py-2 pr-4">Name</th>
                                  <th class="py-2 pr-4">Image</th>
                                  <th class="py-2 pr-4">Status</th>
                                  <th class="py-2 pr-4">Ports</th>
                                </tr>
                              </thead>
                              <tbody>${contRows || ''}</tbody>
                            </table>
                          </div>
                        `;
                    }
                }

                const avatarLetter = String(data.host?.friendly_name || hosts[hostId]?.friendly_name || hostId || '?').trim().charAt(0).toUpperCase();
                const upCount = monitors.filter(m => m.last_status === 'up').length;
                const downCount = monitors.filter(m => m.last_status === 'down').length;
                const errCount = monitors.filter(m => m.last_status === 'error').length;

                if (subtitleEl) subtitleEl.textContent = `${monitors.length} monitor(s)`;

                body.innerHTML = `
                  <div class="p-6">
                    <div class="bg-gradient-to-br from-purple-700/20 via-white/5 to-green-600/20 border border-white/10 rounded-xl p-4">
                      <div class="flex items-start justify-between gap-4">
                        <div class="flex items-center gap-4">
                          <div class="w-12 h-12 rounded-full bg-white/10 flex items-center justify-center font-bold">${avatarLetter}</div>
                          <div>
                            <div class="flex items-center gap-2">
                              <div class="text-xl font-semibold">${data.host?.friendly_name || hosts[hostId]?.friendly_name || hostId}</div>
                              <span class="text-xs px-2 py-1 rounded-full bg-white/10 border border-white/10">Monitoring</span>
                            </div>
                            <div class="text-xs text-slate-300 font-mono">${data.host?.ssh_user || hosts[hostId]?.user || ''}@${data.host?.ip_address || hosts[hostId]?.ip || ''}</div>
                          </div>
                        </div>
                        <div class="flex items-center gap-2">
                          <button class="bg-sky-600 hover:bg-sky-700 text-white text-sm px-3 py-2 rounded-lg" type="button" onclick="window.openMonitoringWizard(${dbId})">Monitoring Wizard</button>
                        </div>
                      </div>
                    </div>

                    <div class="mt-4 grid grid-cols-1 md:grid-cols-4 gap-3">
                      <div class="bg-white/5 border border-white/10 rounded-xl p-3"><div class="text-xs text-slate-300">Total</div><div class="text-2xl font-semibold">${monitors.length}</div></div>
                      <div class="bg-white/5 border border-white/10 rounded-xl p-3"><div class="text-xs text-slate-300">Up</div><div class="text-2xl font-semibold text-green-400">${upCount}</div></div>
                      <div class="bg-white/5 border border-white/10 rounded-xl p-3"><div class="text-xs text-slate-300">Down</div><div class="text-2xl font-semibold text-amber-400">${downCount}</div></div>
                      <div class="bg-white/5 border border-white/10 rounded-xl p-3"><div class="text-xs text-slate-300">Error</div><div class="text-2xl font-semibold text-red-400">${errCount}</div></div>
                    </div>

                    <div class="mt-4 bg-white/5 border border-white/10 rounded-xl p-4">
                      <div class="flex items-center justify-between">
                        <div class="font-medium">Monitors</div>
                        <div class="text-xs text-slate-400">Checks run in the background — refresh to update</div>
                      </div>

                      <div class="mt-3 flex items-center justify-between gap-2">
                        <div class="text-xs text-slate-300" data-mon-selected-count>0 selected</div>
                        <div class="flex gap-2">
                          <button data-mon-bulk-test class="bg-white/10 hover:bg-white/20 px-3 py-2 rounded" type="button">Test selected</button>
                          <button data-mon-bulk-delete class="bg-white/10 hover:bg-white/20 px-3 py-2 rounded" type="button">Delete selected</button>
                        </div>
                      </div>

                      <div class="mt-3 overflow-x-auto">
                        <table class="min-w-full text-sm">
                          <thead>
                            <tr class="text-left text-slate-300 border-b border-white/10">
                              <th class="py-2 pr-3"></th>
                              <th class="py-2 pr-4">Name</th>
                              <th class="py-2 pr-4">Type</th>
                              <th class="py-2 pr-4">Target</th>
                              <th class="py-2 pr-4">Status</th>
                              <th class="py-2 pr-4">Last check</th>
                              <th class="py-2 pr-4">RTT</th>
                              <th class="py-2 pr-2">Actions</th>
                            </tr>
                          </thead>
                          <tbody>${rows}</tbody>
                        </table>
                      </div>
                    </div>

                    ${dockerHtml ? `<div class="mt-4 bg-white/5 border border-white/10 rounded-xl p-4">${dockerHtml}</div>` : ''}
                  </div>
                `;

                const wireMonitoringRowActions = (rootEl, monitors) => {
                    const selCountEl = rootEl.querySelector('[data-mon-selected-count]');
                    const updateSelCount = () => {
                        if (selCountEl) selCountEl.textContent = `${selectedMonitorIds.size} selected`;
                    };

                    rootEl.querySelectorAll('.mon-cb').forEach(cb => {
                        cb.addEventListener('change', () => {
                            const mid = parseInt(cb.dataset.mid, 10);
                            if (cb.checked) selectedMonitorIds.add(mid);
                            else selectedMonitorIds.delete(mid);
                            updateSelCount();
                        });
                    });

                    const callBulk = async (action) => {
                        const ids = Array.from(selectedMonitorIds);
                        if (!ids.length) return;
                        await window.fetchApi('/api/monitors/bulk', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action, ids })
                        });
                        await showHostMonitoringMain();
                    };

                    const bulkTest = rootEl.querySelector('[data-mon-bulk-test]');
                    const bulkDel = rootEl.querySelector('[data-mon-bulk-delete]');
                    if (bulkTest) bulkTest.addEventListener('click', () => callBulk('test'));
                    if (bulkDel) bulkDel.addEventListener('click', () => callBulk('delete'));

                    const openEdit = (m) => {
                        const modal = document.getElementById('monitor-edit-modal');
                        const body = document.getElementById('monitor-edit-body');
                        const status = document.getElementById('monitor-edit-status');
                        const btnClose = document.getElementById('monitor-edit-close');
                        const btnSave = document.getElementById('monitor-edit-save');
                        const btnTest = document.getElementById('monitor-edit-test');

                        if (!modal || !body || !btnClose || !btnSave || !btnTest) return;

                        const cfg = m.config || {};
                        const accepted = Array.isArray(cfg.acceptedStatusCodes) ? cfg.acceptedStatusCodes.join(',') : (cfg.acceptedStatusCodes || '200');

                        body.innerHTML = `
                          <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <div>
                              <label class="text-xs text-slate-300">Name</label>
                              <input id="edit-name" class="mt-1 w-full bg-slate-950 border border-white/10 rounded px-2 py-2 text-sm" value="${m.name || ''}" />
                            </div>
                            <div>
                              <label class="text-xs text-slate-300">Enabled</label>
                              <select id="edit-enabled" class="mt-1 w-full bg-slate-950 border border-white/10 rounded px-2 py-2 text-sm">
                                <option value="true" ${m.enabled ? 'selected' : ''}>true</option>
                                <option value="false" ${!m.enabled ? 'selected' : ''}>false</option>
                              </select>
                            </div>
                            <div>
                              <label class="text-xs text-slate-300">Interval (s)</label>
                              <input id="edit-interval" type="number" class="mt-1 w-full bg-slate-950 border border-white/10 rounded px-2 py-2 text-sm" value="${m.interval_seconds || 60}" />
                            </div>
                            <div>
                              <label class="text-xs text-slate-300">Timeout (s)</label>
                              <input id="edit-timeout" type="number" class="mt-1 w-full bg-slate-950 border border-white/10 rounded px-2 py-2 text-sm" value="${m.timeout_seconds || 10}" />
                            </div>
                          </div>

                          ${m.type === 'http' ? `
                          <div class="mt-4">
                            <label class="text-xs text-slate-300">Accepted status codes (comma separated)</label>
                            <div class="mt-1 flex gap-2">
                              <input id="edit-accepted" class="flex-1 bg-slate-950 border border-white/10 rounded px-2 py-2 text-sm" value="${accepted}" />
                              ${m.last_status_code ? `<button id="edit-add-last" class="bg-white/10 hover:bg-white/20 px-3 py-2 rounded text-sm" type="button">Add ${m.last_status_code}</button>` : ''}
                            </div>
                            <div class="mt-1 text-xs text-slate-400">Last status code: ${m.last_status_code || '-'} ${m.last_error_message ? `— ${m.last_error_message}` : ''}</div>
                          </div>
                          ` : ''}
                        `;

                        const close = () => {
                            if (typeof window.closeAppModal === 'function') window.closeAppModal(modal);
                            else modal.classList.add('hidden');
                        };
                        btnClose.onclick = close;

                        if (typeof window.openAppModal === 'function') window.openAppModal(modal);
                        else modal.classList.remove('hidden');
                        if (status) status.textContent = '';

                        const addLast = document.getElementById('edit-add-last');
                        if (addLast) {
                            addLast.addEventListener('click', () => {
                                const inp = document.getElementById('edit-accepted');
                                if (!inp) return;
                                const set = new Set(String(inp.value||'').split(',').map(x => x.trim()).filter(Boolean));
                                set.add(String(m.last_status_code));
                                inp.value = Array.from(set).join(',');
                            });
                        }

                        btnTest.onclick = async () => {
                            if (status) status.textContent = 'Testing...';
                            await window.fetchApi(`/api/monitors/${m.id}/test`, { method: 'POST' });
                            await showHostMonitoringMain();
                            close();
                        };

                        btnSave.onclick = async () => {
                            if (status) status.textContent = 'Saving...';
                            const payload = {
                                name: document.getElementById('edit-name')?.value,
                                enabled: document.getElementById('edit-enabled')?.value === 'true',
                                interval_seconds: parseInt(document.getElementById('edit-interval')?.value || '60', 10),
                                timeout_seconds: parseInt(document.getElementById('edit-timeout')?.value || '10', 10),
                                config: cfg,
                            };
                            if (m.type === 'http') {
                                payload.config = { ...cfg, acceptedStatusCodes: document.getElementById('edit-accepted')?.value || accepted };
                            }
                            await window.fetchApi(`/api/monitors/${m.id}`, {
                                method: 'PATCH',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify(payload)
                            });
                            await showHostMonitoringMain();
                            close();
                        };
                    };

                    rootEl.querySelectorAll('tr[data-mid]').forEach(tr => {
                        const mid = parseInt(tr.dataset.mid, 10);
                        const m = monitors.find(x => x.id === mid);
                        if (!m) return;

                        tr.querySelectorAll('button.mon-test').forEach(btn => btn.addEventListener('click', async () => {
                            await window.fetchApi(`/api/monitors/${mid}/test`, { method: 'POST' });
                            await showHostMonitoringMain();
                        }));
                        tr.querySelectorAll('button.mon-edit').forEach(btn => btn.addEventListener('click', () => openEdit(m)));
                        tr.querySelectorAll('button.mon-del').forEach(btn => btn.addEventListener('click', async () => {
                            if (!confirm('Delete this monitor?')) return;
                            await window.fetchApi(`/api/monitors/${mid}`, { method: 'DELETE' });
                            selectedMonitorIds.delete(mid);
                            await showHostMonitoringMain();
                        }));
                    });

                    updateSelCount();
                };

                wireMonitoringRowActions(body, monitors);

            } catch (err) {
                console.error('Error loading monitoring', err);
                if (subtitleEl) subtitleEl.textContent = 'Error';
                if (body) body.innerHTML = `<div class="p-6 text-sm text-red-400">Error loading monitoring: ${err.message || err}</div>`;
            }
        };

const showHostInfoMain = async () => {
            const hostId = selectedHostId;
            const hostName = hostId === 'local' ? 'Localhost' : (hosts[hostId]?.friendly_name || hostId);

            const viewToken = ++logsMainViewToken;
            logsMainMode = 'info';
            const topPane = document.getElementById('logs-top-pane');
            const bottomPane = document.getElementById('logs-bottom-pane');
            const logsContentPanel = document.getElementById('logs-content-panel');
            const logTableTitle = document.getElementById('log-table-title');
            const topHeader = document.getElementById('logs-top-header');
            const container = document.getElementById('log-table-container');
            const logTableContainer = document.getElementById('log-table-container');
            const logContent = document.getElementById('log-content-container');

            // Full-pane host info mode
            if (topPane) {
                topPane.classList.remove('hidden');
                topPane.style.height = 'calc(100% - 0px)';
            }
            if (bottomPane) {
                bottomPane.classList.add('hidden');
                bottomPane.style.height = '50%';
            }
            if (topHeader) topHeader.classList.remove('hidden');
            if (logTableContainer) logTableContainer.classList.remove('hidden');
            if (sshTerminalContainer) {
                sshTerminalContainer.classList.add('hidden');
                // Clear any SSH overlay styling so panes remain consistent sizes
                sshTerminalContainer.style.position = '';
                sshTerminalContainer.style.top = '';
                sshTerminalContainer.style.left = '';
                sshTerminalContainer.style.right = '';
                sshTerminalContainer.style.bottom = '';
                sshTerminalContainer.style.zIndex = '';
            }
            if (logsContentPanel) logsContentPanel.classList.remove('hidden');
            if (logTableTitle) logTableTitle.textContent = `Host information: ${hostName}`;
            if (container) container.innerHTML = '<div class="text-sm termix-muted">Loading host info...</div>';
            if (logContent) {
                logContent.innerHTML = '<div class="text-center termix-muted mt-16"><p class="text-lg">Select a log file to view its content</p></div>';
            }

            // If the user switched views while we were entering Host Info, stop here.
            if (viewToken !== logsMainViewToken || logsMainMode !== 'info' || selectedHostId !== hostId) return;

            // Localhost or config-based hosts: only basic info
            const hostData = (hostId === 'local') ? { friendly_name: 'Localhost', ip: 'localhost', user: 'local' } : (hosts[hostId] || { ip: hostId, user: 'root' });
            if (hostId === 'local' || !String(hostId).startsWith('db-')) {
                const groups = (hostData.group_names && hostData.group_names.length) ? hostData.group_names.join(', ') : 'none';
                if (container) {
                    container.innerHTML = `
                        <div class="termix-panel p-4 rounded-lg border border-white/10">
                            <div class="termix-text font-semibold text-lg">${hostData.friendly_name || hostName}</div>
                            <div class="text-sm termix-muted mt-1">Group: ${groups}</div>
                            <div class="text-xs termix-muted font-mono mt-3">${hostData.user || 'root'}@${hostData.ip || hostId}</div>
                            <div class="text-xs termix-muted mt-3">Detailed system info is available for wizard-onboarded (db-*) hosts.</div>
                        </div>
                    `;
                }
                return;
            }

            try {
                const dbId = parseInt(String(hostId).split('-')[1], 10);
                const resp = await fetch(`/hosts/db/${dbId}/info`);
                const info = await resp.json();
                if (!resp.ok || info.error) throw new Error(info.error || `Failed to load host info (${resp.status})`);

                // If the user switched views while we were loading host info, don't overwrite the Pull Logs list.
                if (viewToken !== logsMainViewToken || logsMainMode !== 'info' || selectedHostId !== hostId) return;

                const si = info.system_info || {};
                const svc = info.services_summary || { total: 0, running: 0, stopped: 0 };
                const groups = (hostData.group_names && hostData.group_names.length) ? hostData.group_names.join(', ') : 'none';
                const fmtBytes = (v) => {
                    if (v === null || v === undefined) return 'N/A';
                    const gb = v / (1024 ** 3);
                    return `${gb.toFixed(1)} GB`;
                };

                const pct = (used, total) => {
                    if (used === null || used === undefined) return 0;
                    if (!total) return 0;
                    const v = Math.round((used / total) * 100);
                    return Math.max(0, Math.min(100, v));
                };
                const ramPct = pct(si.ram_used, si.ram_total);
                const diskPct = pct(si.disk_used, si.disk_total);
                const osLower = String(si.os_version || '').toLowerCase();
                const osLabel = osLower.includes('ubuntu') ? 'Ubuntu' : osLower.includes('debian') ? 'Debian' : osLower.includes('arch') ? 'Arch' : osLower.includes('centos') ? 'CentOS' : osLower.includes('red hat') || osLower.includes('rhel') ? 'RHEL' : osLower.includes('fedora') ? 'Fedora' : osLower.includes('linux') ? 'Linux' : 'Unknown';
                const osColor = osLabel === 'Ubuntu' ? 'bg-orange-500/20 text-orange-200 border-orange-500/30'
                    : osLabel === 'Debian' ? 'bg-red-500/20 text-red-200 border-red-500/30'
                    : osLabel === 'Arch' ? 'bg-sky-500/20 text-sky-200 border-sky-500/30'
                    : 'bg-white/5 text-gray-200 border-white/10';

                const avatarLetter = String(info.friendly_name || hostName || '?').trim().charAt(0).toUpperCase();

                if (container) {
                    container.innerHTML = `
                        <div class="termix-panel p-4 rounded-lg border border-white/10 space-y-4">
                            <div class="relative overflow-hidden rounded-lg border border-white/10 bg-gradient-to-br from-purple-700/20 via-white/5 to-green-600/20 p-4">
                                <div class="flex items-center gap-4">
                                    <div class="w-12 h-12 rounded-full bg-white/10 border border-white/10 flex items-center justify-center text-xl font-bold termix-text">
                                        ${avatarLetter}
                                    </div>
                                    <div class="min-w-0">
                                        <div class="flex items-center gap-2 flex-wrap">
                                            <div class="termix-text font-semibold text-lg truncate">${info.friendly_name || hostName}</div>
                                            <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold border ${osColor}">${osLabel}</span>
                                            <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold border bg-white/5 text-gray-200 border-white/10">Group: ${groups}</span>
                                        </div>
                                        <div class="text-xs termix-muted font-mono mt-2">${(info.ssh_user || hostData.user || 'root')}@${(info.ip_address || hostData.ip || hostId)}</div>
                                        <div class="text-xs termix-muted mt-1">Hostname: ${si.hostname || 'N/A'} • Last update: ${si.last_update || 'N/A'}</div>
                                    </div>
                                </div>
                            </div>

                            <div class="grid grid-cols-1 lg:grid-cols-3 gap-3">
                                <div class="p-3 rounded-lg bg-white/5 border border-white/10">
                                    <div class="flex items-center justify-between">
                                        <div class="text-xs font-semibold termix-muted">RAM</div>
                                        <div class="text-xs termix-muted">${ramPct}%</div>
                                    </div>
                                    <div class="w-full bg-white/10 rounded-full h-2 mt-2">
                                        <div class="bg-purple-700 h-2 rounded-full" style="width: ${ramPct}%"></div>
                                    </div>
                                    <div class="text-xs termix-text mt-2">${fmtBytes(si.ram_used)} used / ${fmtBytes(si.ram_total)} total</div>
                                </div>

                                <div class="p-3 rounded-lg bg-white/5 border border-white/10">
                                    <div class="flex items-center justify-between">
                                        <div class="text-xs font-semibold termix-muted">Disk</div>
                                        <div class="text-xs termix-muted">${diskPct}%</div>
                                    </div>
                                    <div class="w-full bg-white/10 rounded-full h-2 mt-2">
                                        <div class="bg-green-600 h-2 rounded-full" style="width: ${diskPct}%"></div>
                                    </div>
                                    <div class="text-xs termix-text mt-2">${fmtBytes(si.disk_used)} used / ${fmtBytes(si.disk_total)} total</div>
                                </div>

                                <div class="p-3 rounded-lg bg-white/5 border border-white/10">
                                    <div class="text-xs font-semibold termix-muted">CPU</div>
                                    <div class="text-xs termix-text mt-2 break-all">${si.cpu_type || 'Unknown'}</div>
                                    <div class="text-xs termix-muted mt-1">Cores: ${si.cpu_cores || 'N/A'}</div>
                                </div>
                            </div>

                            <div class="p-3 rounded-lg bg-white/5 border border-white/10">
                                <div class="flex items-center justify-between">
                                    <div class="text-xs font-semibold termix-muted">Services</div>
                                    <div class="text-xs termix-muted">Total: ${svc.total || 0}</div>
                                </div>
                                <div class="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <div class="rounded-lg border border-green-500/20 bg-green-500/5 p-3">
                                        <div class="flex items-center justify-between">
                                            <div class="text-xs font-semibold text-green-200">Running</div>
                                            <div class="text-xs text-green-200">${svc.running || 0}</div>
                                        </div>
                                        <div class="mt-2 max-h-40 overflow-auto space-y-1">
                                            ${(Array.isArray(info.services) ? info.services.filter(s => (s.status === 'active') || s.is_running) : []).slice(0, 200).map(s => `<div class=\"text-xs font-mono text-green-100/90\">• ${s.service_name || '(unknown)'}${s.status ? ` <span class=\"termix-muted\">(${s.status})</span>` : ''}</div>`).join('') || '<div class="text-xs termix-muted">(none)</div>'}
                                        </div>
                                    </div>
                                    <div class="rounded-lg border border-red-500/20 bg-red-500/5 p-3">
                                        <div class="flex items-center justify-between">
                                            <div class="text-xs font-semibold text-red-200">Stopped</div>
                                            <div class="text-xs text-red-200">${svc.stopped || 0}</div>
                                        </div>
                                        <div class="mt-2 max-h-40 overflow-auto space-y-1">
                                            ${(Array.isArray(info.services) ? info.services.filter(s => !((s.status === 'active') || s.is_running)) : []).slice(0, 200).map(s => `<div class=\"text-xs font-mono text-red-100/90\">• ${s.service_name || '(unknown)'}${s.status ? ` <span class=\"termix-muted\">(${s.status})</span>` : ''}</div>`).join('') || '<div class="text-xs termix-muted">(none)</div>'}
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="flex items-center gap-2">
                                <button id="host-info-main-rescan" class="bg-amber-500 hover:bg-amber-400 text-black text-sm px-4 py-2 rounded-lg font-medium transition-colors" type="button">Rescan</button>
                            </div>
                        </div>
                    `;
                }

                const rescanBtn = document.getElementById('host-info-main-rescan');
                if (rescanBtn) {
                    rescanBtn.addEventListener('click', async () => {
                        rescanBtn.disabled = true;
                        const old = rescanBtn.textContent;
                        rescanBtn.textContent = 'Rescanning...';
                        try {
                            const r = await fetch(`/hosts/db/${dbId}/rescan`, { method: 'POST' });
                            const data = await r.json();
                            if (!r.ok || data.error) throw new Error(data.error || `Rescan failed (${r.status})`);
                            if (typeof window.showToast === 'function') window.showToast('Rescan complete.', 'success');
                            await showHostInfoMain();
                        } catch (e) {
                            if (typeof window.showToast === 'function') window.showToast(e.message, 'error');
                        } finally {
                            rescanBtn.disabled = false;
                            rescanBtn.textContent = old;
                        }
                    });
                }

            } catch (e) {
                if (container) container.innerHTML = `<div class="text-sm text-red-400">Failed to load host info: ${e.message}</div>`;
            }
        };

        const pullLogsForSelectedHost = () => {
            if (!selectedHostId) return;

            const viewToken = ++logsMainViewToken;
            logsMainMode = 'pull';

            const topPane = document.getElementById('logs-top-pane');
            const bottomPane = document.getElementById('logs-bottom-pane');
            const topHeader = document.getElementById('logs-top-header');
            const logTableContainer = document.getElementById('log-table-container');
            const logsContentPanel = document.getElementById('logs-content-panel');
            const logTableTitle = document.getElementById('log-table-title');

            // Normal split-pane logs mode
            if (topPane) {
                topPane.classList.remove('hidden');
                topPane.style.height = '40%';
            }
            if (bottomPane) {
                bottomPane.classList.remove('hidden');
                bottomPane.style.height = '50%';
            }

            if (topHeader) topHeader.classList.remove('hidden');
            if (logTableContainer) {
                logTableContainer.classList.remove('hidden');
                logTableContainer.innerHTML = '<div class="text-sm termix-muted">Loading logs...</div>';
            }
            if (logTableTitle) logTableTitle.textContent = 'Fetching logs...';
            if (sshTerminalContainer) {
                sshTerminalContainer.classList.add('hidden');
                // Clear any SSH overlay styling so panes remain consistent sizes
                sshTerminalContainer.style.position = '';
                sshTerminalContainer.style.top = '';
                sshTerminalContainer.style.left = '';
                sshTerminalContainer.style.right = '';
                sshTerminalContainer.style.bottom = '';
                sshTerminalContainer.style.zIndex = '';
            }
            if (logsContentPanel) logsContentPanel.classList.remove('hidden');

            fetchSourcesForHost(viewToken);
        };


        // --- TOP PROGRESS BAR (connect feedback) -------------------------------
        // While the sources stream is connecting there is nothing to measure, so
        // the bar sweeps (indeterminate) and the label carries an elapsed clock.
        // That makes slow SSH connections / proxy latency look like work in
        // progress instead of a frozen "Initializing connection...".
        let sourcesProgressTimer = null;
        let sourcesProgressStartedAt = 0;
        let sourcesProgressLabel = 'Initializing connection...';

        const sourcesProgressEls = () => ({
            container: document.getElementById('top-progress-container'),
            bar: document.getElementById('top-progress-bar'),
            message: document.getElementById('top-progress-message'),
            spinner: document.getElementById('top-progress-spinner'),
        });

        const sourcesProgressTick = () => {
            const { message } = sourcesProgressEls();
            if (!message || !sourcesProgressStartedAt) return;
            const elapsed = Math.max(0, Math.floor((Date.now() - sourcesProgressStartedAt) / 1000));
            let label = sourcesProgressLabel;
            // Escalate the wording while still waiting for the first event.
            if (label === 'Initializing connection...') {
                if (elapsed >= 8) label = 'Slow to respond - still trying...';
                else if (elapsed >= 3) label = 'Waiting for host to respond...';
            }
            message.textContent = elapsed >= 1 ? `${label} \u00b7 ${elapsed}s` : label;
        };

        const stopSourcesProgressClock = () => {
            if (sourcesProgressTimer) {
                clearInterval(sourcesProgressTimer);
                sourcesProgressTimer = null;
            }
        };

        const startSourcesProgress = () => {
            stopSourcesProgressClock();
            const { container, bar, message, spinner } = sourcesProgressEls();
            if (container) container.classList.remove('hidden');
            if (bar) {
                bar.classList.add('progress-indeterminate');
                bar.style.width = '0%';
            }
            if (spinner) spinner.classList.remove('hidden');
            sourcesProgressStartedAt = Date.now();
            sourcesProgressLabel = 'Initializing connection...';
            if (message) message.textContent = sourcesProgressLabel;
            sourcesProgressTimer = setInterval(sourcesProgressTick, 1000);
        };

        const noteSourcesProgress = (label) => {
            if (label) sourcesProgressLabel = label;
            sourcesProgressTick();
        };

        const finishSourcesProgress = () => {
            stopSourcesProgressClock();
            sourcesProgressStartedAt = 0;
            const { bar, spinner } = sourcesProgressEls();
            if (bar) bar.classList.remove('progress-indeterminate');
            if (spinner) spinner.classList.add('hidden');
        };

        // --- CORE APP LOGIC ---
        const fetchSourcesForHost = (viewToken) => {
            const url = selectedHostId === 'local' ? '/sources/local' : `/sources/remote/${selectedHostId}`;
            const hostName = selectedHostId === 'local' ? 'Localhost' : (hosts[selectedHostId]?.friendly_name || selectedHostId);

            if (currentEventSource) {
                currentEventSource.close();
            }

            const sourceListContainer = document.getElementById('log-table-container');
            sourceListContainer.innerHTML = '';
            const logTableTitle = document.getElementById('log-table-title');
            logTableTitle.textContent = `Fetching logs from ${hostName}...`;
            aiAnalyseBtn.classList.add('hidden');
            truncationWarning.classList.add('hidden');
            
            // Top progress bar with indeterminate sweep + elapsed clock while connecting
            startSourcesProgress();
            const topProgressContainer = document.getElementById('top-progress-container');
            const topProgressBar = document.getElementById('top-progress-bar');
            const topProgressMessage = document.getElementById('top-progress-message');

            let journalItems = [];
            let sourceCount = 0;
            let sawFirstEvent = false;

            currentEventSource = new EventSource(url);

            currentEventSource.onmessage = (event) => {
                // If user navigated away (Host Info / SSH / Monitoring), ignore streamed updates.
                if (viewToken !== logsMainViewToken || logsMainMode !== 'pull') {
                    finishSourcesProgress();
                    if (topProgressContainer) topProgressContainer.classList.add('hidden');
                    try { currentEventSource.close(); } catch (_) {}
                    return;
                }

                const data = JSON.parse(event.data);

                if (!sawFirstEvent) {
                    // First real message: stop sweeping, switch to measured progress.
                    sawFirstEvent = true;
                    if (topProgressBar) topProgressBar.classList.remove('progress-indeterminate');
                }

                switch(data.status) {
                    case 'progress':
                        if (topProgressBar) topProgressBar.style.width = `${data.progress}%`;
                        noteSourcesProgress(data.message);
                        break;
                    case 'source':
                        sourceCount += 1;
                        if (data.data.type === 'file') appendSourceToList(data.data);
                        else journalItems.push(data.data);
                        // Journal units can arrive in the thousands - don't repaint
                        // the label for every one of them.
                        if (data.data.type !== 'journal') {
                            noteSourcesProgress(`Found ${sourceCount} log sources...`);
                        }
                        break;
                    case 'complete':
                        journalItems.forEach(appendSourceToList);
                        finishSourcesProgress();
                        if (topProgressBar) topProgressBar.style.width = `100%`;
                        if (topProgressMessage) topProgressMessage.textContent = 'Done!';
                        if (journalLoadingIndicator) journalLoadingIndicator.classList.add('hidden');

                        if (sourceListContainer.children.length === 0) {
                            sourceListContainer.innerHTML = '<li class="p-4 text-center termix-muted">No log sources found on host.</li>';
                            logTableTitle.textContent = `No logs found on ${hostName}.`;
                        } else {
                            logTableTitle.textContent = `All logs pulled from ${hostName}. Select a log to view.`;
                        }
                        
                        setTimeout(() => topProgressContainer.classList.add('hidden'), 1500);
                        currentEventSource.close();
                        break;
                    case 'error':
                        finishSourcesProgress();
                        window.showToast(data.message, 'error');
                        topProgressContainer.classList.add('hidden');
                        if (journalLoadingIndicator) journalLoadingIndicator.classList.add('hidden');
                        sourceListContainer.innerHTML = `<li class="p-4 text-red-400">${escapeHtml(data.message)}</li>`;
                        currentEventSource.close();
                        break;
                }
            };

            currentEventSource.onerror = (err) => {
                console.error("EventSource failed:", err);
                finishSourcesProgress();
                window.showToast('Connection to server failed. Check if the backend is running.', 'error');
                topProgressContainer.classList.add('hidden');
                if (journalLoadingIndicator) journalLoadingIndicator.classList.add('hidden');
                if (currentEventSource) currentEventSource.close();
            };
        };

        const appendSourceToList = (source) => {
            const li = document.createElement('li');
            li.className = 'source-item';
            li.dataset.name = source.name;
            li.dataset.type = source.type;
            li.dataset.size = source.size_bytes;
            li.dataset.modified = source.modified_epoch;
            
            // Docker container logs are never treated as "empty" - running
            // containers legitimately report 0B of writable layer.
            const isEmptyLog = source.type !== 'docker' && source.size_bytes === 0;
            const isDocker = source.type === 'docker';
            if (isDocker) li.dataset.containerId = source.container_id || '';

            const icon = source.type === 'file'
                ? `<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 termix-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>`
                : (isDocker
                    ? `<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-sky-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 13V7a2 2 0 00-2-2h-3V3H9v2H6a2 2 0 00-2 2v6m16 0l-2 6H6l-2-6m16 0H4" /></svg>`
                    : `<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 termix-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h7" /></svg>`);

            li.innerHTML = `
                <a href="#" class="log-link flex items-center w-full text-left p-3 rounded-lg border border-transparent hover:bg-white/5/70 focus:bg-indigo-600 focus:text-white transition-all">
                    <div class="flex-shrink-0 mr-3">${icon}</div>
                    <div class="flex-grow overflow-hidden">
                        <span class="font-medium truncate block">${escapeHtml(source.name)}${isDocker ? ' <span class="text-[10px] uppercase tracking-wide text-sky-400/80 ml-1">docker</span>' : ''}</span>
                        <span class="text-xs termix-muted">${escapeHtml(source.modified_formatted)}</span>
                    </div>
                    <span class="text-xs font-mono termix-muted ml-2 flex-shrink-0">${escapeHtml(source.size_formatted)}</span>
                </a>
            `;

            sourceListContainer.appendChild(li);
            applySourceFilters();
        };
        
        // Show/hide pulled sources based on the "0-byte" and "Docker only" toggles.
        const applySourceFilters = () => {
            const showEmptyEl = document.getElementById('show-empty-logs');
            const dockerOnlyEl = document.getElementById('docker-only-logs');
            const showEmptyLogs = showEmptyEl ? showEmptyEl.checked : true;
            const dockerOnly = !!(dockerOnlyEl && dockerOnlyEl.checked);

            sourceListContainer.querySelectorAll('.source-item').forEach(item => {
                const isDocker = item.dataset.type === 'docker';
                const sizeBytes = parseInt(item.dataset.size || '0', 10);
                const isEmptyLog = !isDocker && sizeBytes === 0;
                const hide = (isEmptyLog && !showEmptyLogs) || (dockerOnly && !isDocker);
                item.style.display = hide ? 'none' : '';
            });
        };
        const filterLogsBySize = applySourceFilters;
        
        // --- SETTINGS MANAGEMENT ---
        const updateProviderIndicator = () => {
            const provider = localStorage.getItem('analysis_provider') || 'openai';
            const ollamaModel = localStorage.getItem('ollama_model');
            const openrouterModel = localStorage.getItem('openrouter_model');
            
            if (provider === 'ollama' && ollamaModel) {
                providerLabel.textContent = `🤖 Ollama (${ollamaModel})`;
            } else if (provider === 'openrouter' && openrouterModel) {
                providerLabel.textContent = `🚀 OpenRouter (${openrouterModel})`;
            } else if (provider === 'openai') {
                providerLabel.textContent = '🔑 OpenAI';
            } else {
                providerLabel.textContent = 'No Provider';
            }
        };
        
        const loadSettingsFromBackend = async () => {
            try {
                // Load AI config from backend
                const aiConfig = await window.fetchApi('/ai/config');
                const provider = aiConfig.provider || 'openai';
                
                // Update localStorage with config from backend
                localStorage.setItem('analysis_provider', provider);

                // Status dots
                setStatusDot(openaiKeyStatusDot, !!aiConfig.openai_configured);
                try {
                    const dc = await window.fetchApi('/discord/config', { method: 'GET' });
                    setStatusDot(discordWebhookStatusDot, !!dc.configured);
                    if (dc.webhook_url && discordWebhookInput) discordWebhookInput.value = dc.webhook_url;
                } catch (_) {
                    setStatusDot(discordWebhookStatusDot, false);
                }

                
                if (provider === 'openai' && aiConfig.openai_configured) {
                    // OpenAI is configured
                    console.log('OpenAI is configured on backend');
                } else if (provider === 'ollama' && aiConfig.ollama_configured) {
                    // Ollama is configured
                    const ollamaConfig = await window.fetchApi('/ollama/config', { method: 'GET' });
                    if (ollamaConfig.ollama_url) {
                        localStorage.setItem('ollama_url', ollamaConfig.ollama_url);
                    }
                    if (ollamaConfig.ollama_model) {
                        localStorage.setItem('ollama_model', ollamaConfig.ollama_model);
                    }
                    console.log(`Ollama is configured on backend with model: ${aiConfig.ollama_model}`);
                } else if (provider === 'openrouter' && aiConfig.openrouter_configured) {
                    // OpenRouter is configured
                    const openrouterConfig = await window.fetchApi('/openrouter/config', { method: 'GET' });
                    if (openrouterConfig.openrouter_model) {
                        localStorage.setItem('openrouter_model', openrouterConfig.openrouter_model);
                    }
                    console.log(`OpenRouter is configured on backend with model: ${openrouterConfig.openrouter_model}`);
                }
                
                updateProviderIndicator();
            } catch (error) {
                console.log('Could not load AI config from backend, using localStorage');
                updateProviderIndicator();
            }
        };
        
        // Initialize provider indicator on page load - async load from backend
        loadSettingsFromBackend();

        const renderAlertKeywords = (keywords) => {
            if (!alertKeywordsList) return;
            alertKeywordsList.innerHTML = '';
            (keywords || []).forEach((kw, idx) => {
                const li = document.createElement('li');
                li.className = 'flex items-center gap-2';

                const input = document.createElement('input');
                input.type = 'text';
                input.value = kw;
                input.className = 'flex-1 bg-white/10 border border-white/20 rounded-md px-3 py-2 text-white text-sm';

                const del = document.createElement('button');
                del.type = 'button';
                del.textContent = 'Delete';
                del.className = 'bg-red-600 hover:bg-red-500 text-white px-3 py-2 text-xs rounded-md font-medium transition-colors';
                del.addEventListener('click', () => {
                    li.remove();
                });

                li.appendChild(input);
                li.appendChild(del);
                alertKeywordsList.appendChild(li);
            });
        };

        const collectAlertKeywords = () => {
            if (!alertKeywordsList) return [];
            const inputs = Array.from(alertKeywordsList.querySelectorAll('input'));
            return inputs.map(i => i.value.trim()).filter(Boolean);
        };

        const loadAiSearchSettings = async () => {
            try {
                const cfg = await window.fetchApi('/ai/search-config', { method: 'GET' });
                if (aiSearchPromptTextarea && cfg.search_prompt) aiSearchPromptTextarea.value = cfg.search_prompt;
                renderAlertKeywords(cfg.alert_keywords || []);
            } catch (e) {
                // ignore
            }
        };

        const saveAiSearchSettings = async () => {
            const payload = {
                search_prompt: aiSearchPromptTextarea ? aiSearchPromptTextarea.value.trim() : '',
                alert_keywords: collectAlertKeywords(),
            };
            const resp = await window.fetchApi('/ai/search-config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            return resp;
        };

        if (saveAiSearchBtn) {
            saveAiSearchBtn.addEventListener('click', async () => {
                try {
                    saveAiSearchBtn.disabled = true;
                    if (aiSearchSaveStatus) aiSearchSaveStatus.textContent = 'Saving...';
                    await saveAiSearchSettings();
                    if (aiSearchSaveStatus) aiSearchSaveStatus.textContent = 'Saved.';
                    window.showToast('AI Search settings saved.', 'success');
                } catch (e) {
                    if (aiSearchSaveStatus) aiSearchSaveStatus.textContent = 'Save failed.';
                } finally {
                    saveAiSearchBtn.disabled = false;
                    setTimeout(() => { if (aiSearchSaveStatus) aiSearchSaveStatus.textContent = ''; }, 2000);
                }
            });
        }

        if (saveAlertKeywordsBtn) {
            saveAlertKeywordsBtn.addEventListener('click', async () => {
                try {
                    saveAlertKeywordsBtn.disabled = true;
                    if (alertKeywordsSaveStatus) alertKeywordsSaveStatus.textContent = 'Saving...';
                    await saveAiSearchSettings();
                    if (alertKeywordsSaveStatus) alertKeywordsSaveStatus.textContent = 'Saved.';
                    window.showToast('Alert keywords saved.', 'success');
                } catch (e) {
                    if (alertKeywordsSaveStatus) alertKeywordsSaveStatus.textContent = 'Save failed.';
                } finally {
                    saveAlertKeywordsBtn.disabled = false;
                    setTimeout(() => { if (alertKeywordsSaveStatus) alertKeywordsSaveStatus.textContent = ''; }, 2000);
                }
            });
        }

        if (addAlertKeywordBtn) {
            addAlertKeywordBtn.addEventListener('click', () => {
                const kws = collectAlertKeywords();
                kws.push('');
                renderAlertKeywords(kws);
                const last = alertKeywordsList?.querySelector('li:last-child input');
                if (last) last.focus();
            });
        }

        // --- UNIFIED AI PROVIDER SELECTION WORKFLOW ---
        
        // Load current provider config when settings open
        const loadCurrentProviderConfig = async () => {
            try {
                const aiConfig = await window.fetchApi('/ai/config');
                providerDropdown.value = aiConfig.provider;
                showProviderConfigPanel(aiConfig.provider, aiConfig);
            } catch (error) {
                console.log('Could not load AI config from backend');
                providerDropdown.value = localStorage.getItem('analysis_provider') || 'openai';
                showProviderConfigPanel(providerDropdown.value);
            }
        };
        
        // Show/hide config panels based on dropdown selection (MUST be declared before use)
        const showProviderConfigPanel = (provider, config = null) => {
            // Hide all panels first
            openaiConfigPanel.classList.add('hidden');
            ollamaConfigPanel.classList.add('hidden');
            openrouterConfigPanel.classList.add('hidden');
            currentConfigStatus.classList.add('hidden');
            
            if (provider === 'openai') {
                openaiConfigPanel.classList.remove('hidden');
                // Load from backend
                if (config && config.openai_configured) {
                    activeProviderName.textContent = 'OpenAI (GPT-3.5)';
                    currentConfigStatus.classList.remove('hidden');
                }

                // Populate field from backend (plaintext as requested)
                window.fetchApi('/openai/config', { method: 'GET' })
                    .then(cfg => { if (cfg.api_key) openaiApiKeyInput.value = cfg.api_key; })
                    .catch(() => {});
            } else if (provider === 'ollama') {
                ollamaConfigPanel.classList.remove('hidden');
                // Load from localStorage or backend
                const savedUrl = localStorage.getItem('ollama_url') || '';
                const savedModel = localStorage.getItem('ollama_model') || '';
                ollamaApiUrlInput.value = savedUrl;
                if (savedUrl && savedModel) {
                    ollamaModelsPanel.classList.remove('hidden');
                    // Set the radio button to the saved model
                    const savedModelRadio = document.querySelector(`input[name="ollama-model"][value="${savedModel}"]`);
                    if (savedModelRadio) {
                        savedModelRadio.checked = true;
                    }
                    activeProviderName.textContent = `Ollama (${savedModel})`;
                    currentConfigStatus.classList.remove('hidden');
                }
            } else if (provider === 'openrouter') {
                openrouterConfigPanel.classList.remove('hidden');
                window.fetchApi('/openrouter/config', { method: 'GET' })
                    .then(cfg => { 
                        if (cfg.api_key) openrouterApiKeyInput.value = cfg.api_key;
                        if (cfg.openrouter_model) {
                            localStorage.setItem('openrouter_model', cfg.openrouter_model);
                            const savedModelRadio = document.querySelector(`input[name="openrouter-model"][value="${cfg.openrouter_model}"]`);
                            if (savedModelRadio) {
                                savedModelRadio.checked = true;
                            }
                            activeProviderName.textContent = `OpenRouter (${cfg.openrouter_model})`;
                            currentConfigStatus.classList.remove('hidden');
                        }
                        setStatusDot(openrouterKeyStatusDot, !!cfg.api_key);
                    })
                    .catch(() => {});
            }
        };
        
        providerDropdown.addEventListener('change', (e) => {
            showProviderConfigPanel(e.target.value);
        });
        
        // --- OPENAI CONFIGURATION WORKFLOW ---
        testOpenaiBtn.addEventListener('click', async () => {
            const apiKey = openaiApiKeyInput.value.trim();
            if (!apiKey) {
                // No key entered: test saved key in DB
                testOpenaiBtn.disabled = true;
                testOpenaiBtn.textContent = 'Testing...';
                openaiTestStatus.textContent = 'Testing saved API key...';
                openaiTestStatus.className = 'text-xs text-yellow-600 mt-2';
                try {
                    await window.fetchApi('/openai/test-saved', { method: 'GET' });
                    openaiTestStatus.textContent = '✅ Saved API key is valid!';
                    openaiTestStatus.className = 'text-xs text-green-600 mt-2';
                    setStatusDot(openaiKeyStatusDot, true);
                } catch (error) {
                    openaiTestStatus.textContent = `❌ ${error.message}`;
                    openaiTestStatus.className = 'text-xs text-red-600 mt-2';
                    setStatusDot(openaiKeyStatusDot, false);
                } finally {
                    testOpenaiBtn.disabled = false;
                    testOpenaiBtn.textContent = 'Test';
                }
                return;
            }
            
            testOpenaiBtn.disabled = true;
            testOpenaiBtn.textContent = 'Testing...';
            openaiTestStatus.textContent = 'Testing API key...';
            openaiTestStatus.className = 'text-xs text-yellow-600 mt-2';
            
            try {
                // Try a simple API call to test the key (using /ai/config endpoint which validates)
                const client = new (function() {
                    this.testKey = async function(key) {
                        // We'll test by trying to save the config
                        const res = await window.fetchApi('/openai/config', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ api_key: key })
                        });
                        return res;
                    };
                })();
                
                const res = await client.testKey(apiKey);
                
                openaiTestStatus.textContent = '✅ API key is valid!';
                openaiTestStatus.className = 'text-xs text-green-600 mt-2';
                testOpenaiBtn.className = 'bg-green-600 hover:bg-green-500 text-white px-4 py-2 text-sm rounded-md font-medium transition-colors';
                testOpenaiBtn.textContent = 'Verified';
                testOpenaiBtn.disabled = true;
                
                // Save to localStorage
                // persisted on backend (DB-backed settings); do not store secrets in localStorage
                // localStorage.setItem('openai_api_key', apiKey);
                localStorage.setItem('analysis_provider', 'openai');
                
                // Update indicator
                activeProviderName.textContent = 'OpenAI (GPT-3.5)';
                currentConfigStatus.classList.remove('hidden');
                updateProviderIndicator();
                
                window.showToast('OpenAI configured as default AI provider');
            } catch (error) {
                openaiTestStatus.textContent = `❌ ${error.message}`;
                openaiTestStatus.className = 'text-xs text-red-600 mt-2';
                testOpenaiBtn.disabled = false;
                testOpenaiBtn.textContent = 'Retry Test';
            }
        });
        
        // --- OPENROUTER CONFIGURATION WORKFLOW ---
        const openrouterConfigPanel = document.getElementById('openrouter-config-panel');
        const openrouterApiKeyInput = document.getElementById('openrouter-api-key');
        const testOpenrouterBtn = document.getElementById('test-openrouter-btn');
        const openrouterTestStatus = document.getElementById('openrouter-test-status');
        const openrouterKeyStatusDot = document.getElementById('openrouter-key-status');
        const openrouterModelsPanel = document.getElementById('openrouter-models-panel');
        const openrouterGetModelsBtn = document.getElementById('openrouter-get-models-btn');
        const testOpenrouterModelBtn = document.getElementById('test-openrouter-model-btn');
        const openrouterModelTestStatus = document.getElementById('openrouter-model-test-status');
        const toggleOpenrouterKeyVisibilityBtn = document.getElementById('toggle-openrouter-key-visibility');
        
        // Wire OpenRouter visibility toggle
        wireVisibilityToggle(toggleOpenrouterKeyVisibilityBtn, openrouterApiKeyInput);
        
        // Test OpenRouter API Key
        testOpenrouterBtn.addEventListener('click', async () => {
            const apiKey = openrouterApiKeyInput.value.trim();
            if (!apiKey) {
                // No key entered: test saved key in DB
                testOpenrouterBtn.disabled = true;
                testOpenrouterBtn.textContent = 'Testing...';
                openrouterTestStatus.textContent = 'Testing saved API key...';
                openrouterTestStatus.className = 'text-xs text-yellow-600 mt-2';
                try {
                    await window.fetchApi('/openrouter/test-saved', { method: 'GET' });
                    openrouterTestStatus.textContent = '✅ Saved API key is valid!';
                    openrouterTestStatus.className = 'text-xs text-green-600 mt-2';
                    setStatusDot(openrouterKeyStatusDot, true);
                } catch (error) {
                    openrouterTestStatus.textContent = `❌ ${error.message}`;
                    openrouterTestStatus.className = 'text-xs text-red-600 mt-2';
                    setStatusDot(openrouterKeyStatusDot, false);
                } finally {
                    testOpenrouterBtn.disabled = false;
                    testOpenrouterBtn.textContent = 'Test';
                }
                return;
            }
            
            testOpenrouterBtn.disabled = true;
            testOpenrouterBtn.textContent = 'Testing...';
            openrouterTestStatus.textContent = 'Testing API key...';
            openrouterTestStatus.className = 'text-xs text-yellow-600 mt-2';
            
            try {
                const res = await window.fetchApi('/openrouter/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ api_key: apiKey })
                });
                
                openrouterTestStatus.textContent = '✅ API key is valid!';
                openrouterTestStatus.className = 'text-xs text-green-600 mt-2';
                testOpenrouterBtn.className = 'bg-green-600 hover:bg-green-500 text-white px-4 py-2 text-sm rounded-md font-medium transition-colors';
                testOpenrouterBtn.textContent = 'Verified';
                testOpenrouterBtn.disabled = true;
                
                // Show models panel and auto-load models
                openrouterModelsPanel.classList.remove('hidden');
                await loadOpenrouterModels(apiKey);
                
                localStorage.setItem('analysis_provider', 'openrouter');
                activeProviderName.textContent = 'OpenRouter';
                currentConfigStatus.classList.remove('hidden');
                updateProviderIndicator();
                
                window.showToast('OpenRouter configured as default AI provider');
            } catch (error) {
                openrouterTestStatus.textContent = `❌ ${error.message}`;
                openrouterTestStatus.className = 'text-xs text-red-600 mt-2';
                testOpenrouterBtn.disabled = false;
                testOpenrouterBtn.textContent = 'Retry Test';
            }
        });
        
        // Get Models button for OpenRouter
        openrouterGetModelsBtn.addEventListener('click', async () => {
            const apiKey = openrouterApiKeyInput.value.trim();
            if (!apiKey) {
                window.showToast('Please test the OpenRouter API key first', 'error');
                return;
            }
            await loadOpenrouterModels(apiKey);
        });
        
        // Load OpenRouter models with search filtering
        let openrouterModelsCache = [];
        const loadOpenrouterModels = async (apiKey) => {
            openrouterGetModelsBtn.disabled = true;
            openrouterGetModelsBtn.textContent = 'Loading...';
            const modelsList = document.getElementById('openrouter-models-list');
            const searchInput = document.getElementById('openrouter-models-search');
            modelsList.innerHTML = '<div class="col-span-1 text-sm termix-muted">Loading models...</div>';
            
            try {
                const data = await window.fetchApi('/openrouter/models', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ api_key: apiKey })
                });
                
                openrouterModelsCache = data.models || [];
                
                if (openrouterModelsCache.length === 0) {
                    modelsList.innerHTML = '<div class="col-span-1 text-sm termix-muted">No models available</div>';
                    return;
                }
                
                // Wire search filtering
                const renderFilteredModels = () => {
                    const query = (searchInput?.value || '').toLowerCase();
                    const filtered = openrouterModelsCache.filter(modelObj => {
                        const modelName = modelObj.id || modelObj;
                        const modelDisplay = modelObj.name || modelName;
                        const fullText = `${modelName} ${modelDisplay}`.toLowerCase();
                        return fullText.includes(query);
                    });
                    
                    modelsList.innerHTML = '';
                    if (filtered.length === 0) {
                        modelsList.innerHTML = '<div class="col-span-1 text-sm termix-muted">No models match your search</div>';
                        return;
                    }
                    
                    filtered.forEach((modelObj, index) => {
                        const modelName = modelObj.id || modelObj;
                        const modelDisplay = modelObj.name || modelName;
                        const radioId = `openrouter-model-${modelName.replace(/[^a-zA-Z0-9_-]/g, '_')}`;
                        const label = document.createElement('label');
                        label.className = 'flex items-center space-x-3 p-2 rounded-md border border-white/10 hover:bg-white/5 cursor-pointer transition-colors';
                        label.innerHTML = `
                            <input type="radio" id="${radioId}" name="openrouter-model" value="${modelName}" class="w-4 h-4 cursor-pointer">
                            <span class="text-sm text-gray-200 flex-1">${modelDisplay}</span>
                        `;
                        
                        const input = label.querySelector('input[type="radio"]');
                        input.addEventListener('change', () => {
                            testOpenrouterModelBtn.disabled = false;
                        });
                        
                        modelsList.appendChild(label);
                    });
                };
                
                // Initial render
                renderFilteredModels();
                
                // Wire search input
                if (searchInput) {
                    searchInput.addEventListener('input', renderFilteredModels);
                }
                
                window.showToast(`Found ${openrouterModelsCache.length} model(s)`);
            } catch (error) {
                modelsList.innerHTML = `<div class="col-span-1 text-sm text-red-400">Error: ${error.message}</div>`;
                window.showToast(`Error loading models: ${error.message}`, 'error');
            } finally {
                openrouterGetModelsBtn.disabled = false;
                openrouterGetModelsBtn.textContent = 'Get Models';
            }
        };
        
        // Test OpenRouter Model button
        testOpenrouterModelBtn.addEventListener('click', async () => {
            const selectedRadio = document.querySelector('input[name="openrouter-model"]:checked');
            const model = selectedRadio ? selectedRadio.value : '';
            const apiKey = openrouterApiKeyInput.value.trim();
            
            if (!model) {
                openrouterModelTestStatus.textContent = '❌ Please select a model';
                openrouterModelTestStatus.className = 'text-xs text-red-600 mt-2';
                return;
            }
            
            testOpenrouterModelBtn.disabled = true;
            testOpenrouterModelBtn.textContent = 'Testing...';
            openrouterModelTestStatus.textContent = 'Testing model...';
            openrouterModelTestStatus.className = 'text-xs text-yellow-600 mt-2';
            
            try {
                const res = await window.fetchApi('/openrouter/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ api_key: apiKey, model: model })
                });
                
                openrouterModelTestStatus.textContent = '✅ Model is configured and working!';
                openrouterModelTestStatus.className = 'text-xs text-green-600 mt-2';
                testOpenrouterModelBtn.className = 'bg-green-600 hover:bg-green-500 text-white px-4 py-2 text-sm rounded-md font-medium transition-colors';
                testOpenrouterModelBtn.textContent = 'Verified';
                testOpenrouterModelBtn.disabled = true;
                
                localStorage.setItem('analysis_provider', 'openrouter');
                localStorage.setItem('openrouter_model', model);
                
                activeProviderName.textContent = `OpenRouter (${model})`;
                currentConfigStatus.classList.remove('hidden');
                updateProviderIndicator();
                
                window.showToast('OpenRouter configured as default AI provider');
            } catch (error) {
                openrouterModelTestStatus.textContent = `❌ ${error.message}`;
                openrouterModelTestStatus.className = 'text-xs text-red-600 mt-2';
                testOpenrouterModelBtn.disabled = false;
                testOpenrouterModelBtn.textContent = 'Retry Test';
            }
        });
        
        // --- OLLAMA CONFIGURATION WORKFLOW ---
        testOllamaUrlBtn.addEventListener('click', async () => {
            const url = ollamaApiUrlInput.value.trim();
            if (!url) {
                ollamaUrlTestStatus.textContent = '❌ Ollama URL cannot be empty';
                ollamaUrlTestStatus.className = 'text-xs text-red-600 mt-2';
                return;
            }
            
            testOllamaUrlBtn.disabled = true;
            testOllamaUrlBtn.textContent = 'Testing...';
            ollamaUrlTestStatus.textContent = 'Testing connection...';
            ollamaUrlTestStatus.className = 'text-xs text-yellow-600 mt-2';
            
            try {
                const res = await window.fetchApi('/ollama/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ollama_url: url })
                });
                
                if (res.success) {
                    ollamaUrlTestStatus.textContent = `✅ Connection successful! Found ${res.models?.length || 0} model(s)`;
                    ollamaUrlTestStatus.className = 'text-xs text-green-600 mt-2';
                    testOllamaUrlBtn.className = 'bg-green-600 hover:bg-green-500 text-white px-4 py-2 text-sm rounded-md font-medium transition-colors';
                    testOllamaUrlBtn.textContent = 'Connected';
                    
                    // Show models panel and auto-load models
                    localStorage.setItem('ollama_url', url);
                    ollamaModelsPanel.classList.remove('hidden');
                    
                    // Auto-load models
                    await loadOllamaModels(url);
                } else {
                    throw new Error(res.error);
                }
            } catch (error) {
                ollamaUrlTestStatus.textContent = `❌ ${error.message}`;
                ollamaUrlTestStatus.className = 'text-xs text-red-600 mt-2';
                testOllamaUrlBtn.disabled = false;
                testOllamaUrlBtn.textContent = 'Retry Test';
            }
        });
        
        // Get Models button
        getModelsBtn.addEventListener('click', async () => {
            const url = ollamaApiUrlInput.value.trim();
            if (!url) {
                window.showToast('Please test the Ollama connection first', 'error');
                return;
            }
            await loadOllamaModels(url);
        });
        
        // Load Ollama models with search filtering
        let ollamaModelsCache = [];
        const loadOllamaModels = async (url) => {
            getModelsBtn.disabled = true;
            getModelsBtn.textContent = 'Loading...';
            const modelsList = document.getElementById('ollama-models-list');
            const searchInput = document.getElementById('ollama-models-search');
            modelsList.innerHTML = '<div class="col-span-2 text-sm termix-muted">Loading models...</div>';
            
            try {
                const data = await window.fetchApi('/ollama/models', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ollama_url: url })
                });
                
                ollamaModelsCache = data.models || [];
                
                if (ollamaModelsCache.length === 0) {
                    modelsList.innerHTML = '<div class="col-span-2 text-sm termix-muted">No models available</div>';
                    return;
                }
                
                // Wire search filtering
                const renderFilteredModels = () => {
                    const query = (searchInput?.value || '').toLowerCase();
                    const filtered = ollamaModelsCache.filter(modelName => {
                        return modelName.toLowerCase().includes(query);
                    });
                    
                    modelsList.innerHTML = '';
                    if (filtered.length === 0) {
                        modelsList.innerHTML = '<div class="col-span-2 text-sm termix-muted">No models match your search</div>';
                        return;
                    }
                    
                    filtered.forEach((modelName, index) => {
                        const radioId = `ollama-model-${modelName.replace(/[^a-zA-Z0-9_-]/g, '_')}`;
                        const label = document.createElement('label');
                        label.className = 'flex items-center space-x-3 p-3 rounded-md border border-white/10 hover:bg-white/5 cursor-pointer transition-colors';
                        label.innerHTML = `
                            <input type="radio" id="${radioId}" name="ollama-model" value="${modelName}" class="w-4 h-4 cursor-pointer">
                            <span class="text-sm text-gray-200 flex-1">${modelName}</span>
                        `;
                        
                        const input = label.querySelector('input[type="radio"]');
                        input.addEventListener('change', () => {
                            testOllamaModelBtn.disabled = false;
                        });
                        
                        modelsList.appendChild(label);
                    });
                };
                
                // Initial render
                renderFilteredModels();
                
                // Wire search input
                if (searchInput) {
                    searchInput.addEventListener('input', renderFilteredModels);
                }
                
                window.showToast(`Found ${ollamaModelsCache.length} model(s)`);
            } catch (error) {
                modelsList.innerHTML = `<div class="col-span-2 text-sm text-red-400">Error: ${error.message}</div>`;
                window.showToast(`Error loading models: ${error.message}`, 'error');
            } finally {
                getModelsBtn.disabled = false;
                getModelsBtn.textContent = 'Get Models';
            }
        };
        
        // Test Ollama Model button
        testOllamaModelBtn.addEventListener('click', async () => {
            const selectedRadio = document.querySelector('input[name="ollama-model"]:checked');
            const model = selectedRadio ? selectedRadio.value : '';
            const url = ollamaApiUrlInput.value.trim();
            
            if (!model) {
                ollamaModelTestStatus.textContent = '❌ Please select a model';
                ollamaModelTestStatus.className = 'text-xs text-red-600 mt-2';
                return;
            }
            
            testOllamaModelBtn.disabled = true;
            testOllamaModelBtn.textContent = 'Testing...';
            ollamaModelTestStatus.textContent = 'Testing model availability...';
            ollamaModelTestStatus.className = 'text-xs text-yellow-600 mt-2';
            
            try {
                const res = await window.fetchApi('/ollama/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ollama_url: url, model: model })
                });
                
                if (res.success) {
                    ollamaModelTestStatus.textContent = '✅ Model is available and working!';
                    ollamaModelTestStatus.className = 'text-xs text-green-600 mt-2';
                    testOllamaModelBtn.className = 'bg-green-600 hover:bg-green-500 text-white px-4 py-2 text-sm rounded-md font-medium transition-colors';
                    testOllamaModelBtn.textContent = 'Verified';
                    testOllamaModelBtn.disabled = true;
                    
                    // Save to backend and localStorage
                    localStorage.setItem('ollama_url', url);
                    localStorage.setItem('ollama_model', model);
                    localStorage.setItem('analysis_provider', 'ollama');
                    
                    try {
                        await window.fetchApi('/ollama/config', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ ollama_url: url, ollama_model: model })
                        });
                    } catch (e) {
                        console.log('Config saved to localStorage, backend sync may have failed');
                    }
                    
                    // Update indicator
                    activeProviderName.textContent = `Ollama (${model})`;
                    currentConfigStatus.classList.remove('hidden');
                    updateProviderIndicator();
                    
                    window.showToast('Ollama configured as default AI provider');
                } else {
                    throw new Error(res.error);
                }
            } catch (error) {
                ollamaModelTestStatus.textContent = `❌ ${error.message}`;
                ollamaModelTestStatus.className = 'text-xs text-red-600 mt-2';
                testOllamaModelBtn.disabled = false;
                testOllamaModelBtn.textContent = 'Retry Test';
            }
        });
        
        // --- HOST MANAGEMENT ---
        const openHostModal = (host = null) => {
            hostForm.reset();
            hostTestStatus.classList.add('hidden');
            hostSaveBtn.classList.add('hidden');
            hostTestBtn.classList.remove('hidden');
            hostTestBtn.disabled = false;
            hostTestBtn.textContent = 'Test Connection';

            if (host) { // Edit mode
                hostModalTitle.textContent = 'Edit Host';
                hostIdInput.value = host.id;
                hostFriendlyNameInput.value = host.friendly_name;
                hostIpInput.value = host.ip;
                hostUserInput.value = host.user;
                hostDescriptionInput.value = host.description;
                hostSaveBtn.textContent = 'Save Changes';
            } else { // Add mode
                hostModalTitle.textContent = 'Add New Host';
                hostIdInput.value = '';
                hostSaveBtn.textContent = 'Add Host';
            }
            closeModal(settingsModal);
            openModal(hostModal);
        };

        // Remote Hosts sub-navigation (Import / Delete)
        const remoteHostsTabs = document.querySelectorAll('.remote-hosts-tab');
        const remoteHostsPanels = document.querySelectorAll('.remote-hosts-panel');
        const hostImportFile = document.getElementById('host-import-file');
        const hostImportMode = document.getElementById('host-import-mode');
        const importHostsBtn = document.getElementById('import-hosts-btn');
        const hostImportStatus = document.getElementById('host-import-status');
        const downloadHostImportTemplateBtn = document.getElementById('download-host-import-template-btn');

        const switchRemoteHostsPanel = (panel) => {
            remoteHostsPanels.forEach(p => p.classList.add('hidden'));
            remoteHostsTabs.forEach(t => {
                t.classList.remove('bg-indigo-600', 'text-white');
            });

            const target = document.querySelector(`.remote-hosts-panel[data-remote-hosts-panel="${panel}"]`);
            if (target) target.classList.remove('hidden');

            const activeTab = document.querySelector(`.remote-hosts-tab[data-remote-hosts-tab="${panel}"]`);
            if (activeTab) activeTab.classList.add('bg-indigo-600', 'text-white');

            if (panel === 'delete') {
                populateHostList();
            }
        };

        if (remoteHostsTabs && remoteHostsTabs.length) {
            remoteHostsTabs.forEach(btn => {
                btn.addEventListener('click', () => {
                    switchRemoteHostsPanel(btn.dataset.remoteHostsTab);
                });
            });
        }

        if (hostImportFile && importHostsBtn) {
            const updateImportEnabled = () => {
                importHostsBtn.disabled = !(hostImportFile.files && hostImportFile.files.length);
            };
            hostImportFile.addEventListener('change', updateImportEnabled);
            updateImportEnabled();
        }

        if (downloadHostImportTemplateBtn) {
            downloadHostImportTemplateBtn.addEventListener('click', async () => {
                try {
                    const resp = await fetch('/hosts/import/template', { method: 'GET' });
                    if (!resp.ok) throw new Error(`Template download failed (${resp.status})`);

                    const blob = await resp.blob();
                    let filename = 'ailog-host-import-template.json';
                    const cd = resp.headers.get('Content-Disposition') || resp.headers.get('content-disposition');
                    if (cd) {
                        const m = /filename\s*=\s*([^;]+)/i.exec(cd);
                        if (m && m[1]) filename = m[1].trim().replace(/^"|"$/g, '');
                    }

                    const blobUrl = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = blobUrl;
                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    setTimeout(() => URL.revokeObjectURL(blobUrl), 2000);

                    window.showToast('Template downloaded.', 'success');
                } catch (e) {
                    window.showToast(e.message || 'Template download failed.', 'error');
                }
            });
        }

        if (importHostsBtn && hostImportFile && hostImportMode) {
            importHostsBtn.addEventListener('click', async () => {
                if (!(hostImportFile.files && hostImportFile.files.length)) return;

                const mode = hostImportMode.value || 'merge';
                if (mode === 'replace') {
                    const ok = confirm('Replace mode will delete ALL database-backed hosts (wizard/imported). Continue?');
                    if (!ok) return;
                }

                importHostsBtn.disabled = true;
                const originalText = importHostsBtn.textContent;
                importHostsBtn.textContent = 'Importing...';
                if (hostImportStatus) hostImportStatus.textContent = '';

                try {
                    // We send a file; backend reads mode from JSON. If the JSON doesn't include mode,
                    // the backend defaults to merge.
                    // For convenience, we also patch mode into the payload if it is a wrapped object.
                    const file = hostImportFile.files[0];
                    const text = await file.text();
                    let parsed = null;
                    try { parsed = JSON.parse(text); } catch (_) {}

                    let blobToSend = file;
                    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
                        parsed.mode = mode;
                        const patched = new Blob([JSON.stringify(parsed, null, 2)], { type: 'application/json' });
                        blobToSend = new File([patched], file.name, { type: 'application/json' });
                    }

                    const fd = new FormData();
                    fd.append('file', blobToSend);

                    const resp = await fetch('/hosts/import', { method: 'POST', body: fd });
                    const data = await resp.json().catch(() => ({}));
                    if (!resp.ok || data.error) {
                        throw new Error(data.error || `Import failed (${resp.status})`);
                    }

                    const msg = `Imported: ${data.total} (created ${data.created}, updated ${data.updated})`;
                    if (hostImportStatus) hostImportStatus.textContent = msg;
                    window.showToast(msg, 'success');

                    // Refresh UI
                    await populateHostCards();
                    await populateHostList();

                    // Move user to Delete tab so they can verify list immediately
                    switchRemoteHostsPanel('delete');
                } catch (e) {
                    window.showToast(e.message || 'Import failed.', 'error');
                } finally {
                    importHostsBtn.textContent = originalText;
                    importHostsBtn.disabled = false;
                }
            });
        }

        const populateHostList = async () => {
            try {
                const hosts = await window.fetchApi('/hosts');
                hostListDiv.innerHTML = '';
                if (Object.keys(hosts).length === 0) {
                     hostListDiv.innerHTML = `<p class="text-sm termix-muted text-center">No remote hosts configured.</p>`;
                }
                for (const [id, host] of Object.entries(hosts)) {
                    const div = document.createElement('div');
                    div.className = 'glass-container p-3 rounded-lg';
                    div.innerHTML = `
                        <div class="flex justify-between items-center">
                            <span class="font-bold text-white">${host.friendly_name}</span>
                            <div class="flex space-x-2">
                                <button class="edit-host-btn p-1 rounded hover:bg-white/5" data-host-id="${id}" title="Edit"><svg class="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.5L14.732 3.732z"></path></svg></button>
                                <button class="delete-host-btn p-1 rounded hover:bg-white/5" data-host-id="${id}" title="Delete"><svg class="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg></button>
                            </div>
                        </div>
                        <p class="text-sm termix-muted mt-1">${host.description || 'No description'}</p>
                        <p class="text-xs termix-muted font-mono mt-2">${host.user}@${host.ip}</p>
                    `;
                    hostListDiv.appendChild(div);
                }
            } catch (error) {
                 hostListDiv.innerHTML = `<p class="text-red-400">Could not load hosts.</p>`;
            }
        };
        

        // --- EVENT LISTENERS ---

        // --- SETTINGS MODAL SIDEBAR NAVIGATION ---
        const settingsNavBtns = document.querySelectorAll('.settings-nav-btn');
        const settingsSections = document.querySelectorAll('.settings-section');
        
        const switchSettingsSection = (sectionId) => {
            // Hide all sections
            settingsSections.forEach(section => section.classList.add('hidden'));
            
            // Remove active state from all buttons
            settingsNavBtns.forEach(btn => {
                btn.classList.remove('active', 'bg-white/20', 'border-l-indigo-400');
                btn.classList.add('border-l-transparent');
            });
            
            // Show selected section
            const selectedSection = document.getElementById(`${sectionId}-section`);
            if (selectedSection) {
                selectedSection.classList.remove('hidden');
            }
            if (sectionId === 'prompts') {
                loadAiSearchSettings();
            }
            if (sectionId === 'groups') {
                loadGroupsSettings();
            }
            if (sectionId === 'suricata') {
                loadSuricataConfigIntoForm();
                loadSuricataPromptSettings();
            }
            
            // Mark button as active
            const activeBtn = document.querySelector(`.settings-nav-btn[data-section="${sectionId}"]`);
            if (activeBtn) {
                activeBtn.classList.add('active', 'bg-white/20', 'border-l-indigo-400');
                activeBtn.classList.remove('border-l-transparent');
            }
        };
        
        // Add click listeners to sidebar buttons
        settingsNavBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const section = btn.dataset.section;
                switchSettingsSection(section);
            });
        });
        
        // Dashboard quick actions
        if (dashboardOpenSettingsBtn) dashboardOpenSettingsBtn.addEventListener('click', () => settingsBtn.click());
        if (dashboardRescanBtn && rescanAllBtn) dashboardRescanBtn.addEventListener('click', () => rescanAllBtn.click());
        if (dashboardAddDevicesBtn) dashboardAddDevicesBtn.addEventListener('click', () => {
            const addDevicesBtn = document.getElementById('add-devices-btn');
            if (addDevicesBtn) addDevicesBtn.click();
        });
        if (dashboardExportSshBtn && createSshConfigBtn) dashboardExportSshBtn.addEventListener('click', () => createSshConfigBtn.click());

        if (backToDashboardBtn) backToDashboardBtn.addEventListener('click', () => {
            window.showDashboard();
        });

        settingsBtn.addEventListener('click', () => {
             openModal(settingsModal);
             populateHostList();
             updateSchedulerStatus();
             loadCurrentProviderConfig();
             loadSettingsFromBackend();
             loadAiSearchSettings();
             loadSshKeys();
             wireGroupsSettingsUi();
             // Ensure AI Provider section is shown by default
             switchSettingsSection('ai-provider');
        });

        if (createAnsibleInventoryBtn) {
            createAnsibleInventoryBtn.addEventListener('click', async () => {
                try {
                    await downloadFromPost('/export/ansible-inventory', 'inventory.yaml');
                    window.showToast('Downloaded Ansible inventory.', 'success');
                } catch (err) {
                    window.showToast(err.message || 'Failed to create inventory.', 'error');
                }
            });
        }

        if (createSshConfigBtn) {
            createSshConfigBtn.addEventListener('click', async () => {
                try {
                    await downloadFromPost('/export/ssh-config', 'ssh_config');
                    window.showToast('Downloaded SSH config.', 'success');
                } catch (err) {
                    window.showToast(err.message || 'Failed to create SSH config.', 'error');
                }
            });
        }

        if (rescanAllBtn) {
            rescanAllBtn.addEventListener('click', async () => {
                rescanAllBtn.disabled = true;

                const originalHtml = rescanAllBtn.innerHTML;
                const originalClass = rescanAllBtn.className;

                // Turn button into an indeterminate red progress bar
                rescanAllBtn.className = 'relative overflow-hidden bg-red-600 text-white text-sm px-4 py-2 rounded-lg font-medium';
                rescanAllBtn.innerHTML = `
                    <span class="relative z-10">Rescanning...</span>
                    <div class="absolute inset-0 bg-red-700 opacity-40"></div>
                    <div id="rescan-all-progress" class="absolute left-0 top-0 h-full bg-red-400 opacity-70" style="width: 30%;"></div>
                `;

                const bar = rescanAllBtn.querySelector('#rescan-all-progress');
                let pos = 0;
                let dir = 1;
                const timer = setInterval(() => {
                    if (!bar) return;
                    pos += dir * 8;
                    if (pos >= 70) { pos = 70; dir = -1; }
                    if (pos <= 0) { pos = 0; dir = 1; }
                    bar.style.transform = `translateX(${pos}%)`;
                }, 120);

                try {
                    const resp = await fetch('/hosts/db/rescan-all', { method: 'POST' });
                    const data = await resp.json();
                    if (!resp.ok || data.error) {
                        throw new Error(data.error || `Rescan all failed (${resp.status})`);
                    }
                    window.showToast(`Rescan complete: ${data.successful}/${data.total} successful`, 'success');
                    await populateHostCards();
                } catch (err) {
                    window.showToast(err.message || 'Rescan all failed.', 'error');
                } finally {
                    clearInterval(timer);
                    rescanAllBtn.disabled = false;
                    rescanAllBtn.className = originalClass;
                    rescanAllBtn.innerHTML = originalHtml;
                }
            });
        }


        if (downloadDbBackupBtn) {
            downloadDbBackupBtn.addEventListener('click', async () => {
                try {
                    const resp = await fetch('/admin/db/backup', { method: 'GET' });
                    if (!resp.ok) {
                        let msg = `Backup failed (${resp.status})`;
                        try {
                            const data = await resp.json();
                            if (data && data.error) msg = data.error;
                        } catch (_) {}
                        throw new Error(msg);
                    }

                    const blob = await resp.blob();
                    let filename = 'ailog-backup.db';
                    const cd = resp.headers.get('Content-Disposition') || resp.headers.get('content-disposition');
                    if (cd) {
                        const m = /filename\s*=\s*([^;]+)/i.exec(cd);
                        if (m && m[1]) filename = m[1].trim().replace(/^"|"$/g, '');
                    }

                    const blobUrl = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = blobUrl;
                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    setTimeout(() => URL.revokeObjectURL(blobUrl), 2000);

                    window.showToast('Database backup downloaded.', 'success');
                } catch (err) {
                    window.showToast(err.message || 'Backup failed.', 'error');
                }
            });
        }

        if (restoreDbFileInput && restoreDbBtn) {
            const updateRestoreEnabled = () => {
                restoreDbBtn.disabled = !(restoreDbFileInput.files && restoreDbFileInput.files.length);
            };
            restoreDbFileInput.addEventListener('change', updateRestoreEnabled);
            updateRestoreEnabled();

            restoreDbBtn.addEventListener('click', async () => {
                if (!(restoreDbFileInput.files && restoreDbFileInput.files.length)) return;

                if (!confirm('Restore database from the selected file? This will overwrite the current database.')) {
                    return;
                }

                restoreDbBtn.disabled = true;
                const originalText = restoreDbBtn.textContent;
                restoreDbBtn.textContent = 'Restoring...';

                try {
                    const fd = new FormData();
                    fd.append('file', restoreDbFileInput.files[0]);

                    fd.append('restore_ai', document.getElementById('restore-ai')?.checked ? '1' : '0');
                    fd.append('restore_discord', document.getElementById('restore-discord')?.checked ? '1' : '0');
                    fd.append('restore_hosts', document.getElementById('restore-hosts')?.checked ? '1' : '0');
                    fd.append('restore_schedule', document.getElementById('restore-schedule')?.checked ? '1' : '0');
                    fd.append('restore_ai_search', document.getElementById('restore-ai-search')?.checked ? '1' : '0');
                    fd.append('restore_suricata', document.getElementById('restore-suricata')?.checked ? '1' : '0');

                    const resp = await fetch('/admin/db/restore-selective', { method: 'POST', body: fd });
                    const data = await resp.json().catch(() => ({}));
                    if (!resp.ok || data.error) {
                        throw new Error(data.error || `Restore failed (${resp.status})`);
                    }

                    window.showToast('Database restored. Refreshing host list...', 'success');
                    await populateHostCards();
                } catch (err) {
                    window.showToast(err.message || 'Restore failed.', 'error');
                } finally {
                    restoreDbBtn.textContent = originalText;
                    restoreDbBtn.disabled = false;
                }
            });
        }


        // SSH key encryption status
        const sshEncStatus = document.getElementById('sshkey-encryption-status');
        const sshEncGenOut = document.getElementById('sshkey-encryption-generated');
        const sshEncRefreshBtn = document.getElementById('sshkey-encryption-refresh');
        const sshEncGenBtn = document.getElementById('sshkey-encryption-generate');
        const sshEncToggle = document.getElementById('sshkey-encryption-toggle');
        const sshEncToggleStatus = document.getElementById('sshkey-encryption-toggle-status');

        async function refreshSshEncStatus() {
            try {
                const data = await window.fetchApi('/settings/sshkey-encryption/status');
                if (sshEncToggle) sshEncToggle.checked = !!data.enabled;
                if (sshEncToggleStatus) {
                    if (!data.enabled) {
                        sshEncToggleStatus.textContent = 'Disabled (keys stored unencrypted)';
                        sshEncToggleStatus.className = 'text-xs text-yellow-300';
                    } else if (data.ready) {
                        sshEncToggleStatus.textContent = 'Enabled ✅ (master key set)';
                        sshEncToggleStatus.className = 'text-xs text-green-400';
                    } else {
                        sshEncToggleStatus.textContent = 'Enabled, but not configured (set AILOG_SSHKEY_MASTER_KEY)';
                        sshEncToggleStatus.className = 'text-xs text-red-400';
                    }
                }
                if (sshEncStatus) {
                    sshEncStatus.textContent = data.configured ? 'Master key configured ✅' : 'Master key not configured';
                    sshEncStatus.className = data.configured ? 'text-sm text-green-400' : 'text-sm text-red-400';
                }
            } catch (e) {
                if (sshEncStatus) {
                    sshEncStatus.textContent = 'Failed to load status';
                    sshEncStatus.className = 'text-sm text-red-400';
                }
                if (sshEncToggleStatus) {
                    sshEncToggleStatus.textContent = 'Failed to load toggle';
                    sshEncToggleStatus.className = 'text-xs text-red-400';
                }
            }
        }

        if (sshEncRefreshBtn) sshEncRefreshBtn.addEventListener('click', refreshSshEncStatus);
        if (sshEncToggle) {
            sshEncToggle.addEventListener('change', async () => {
                try {
                    await window.fetchApi('/settings/sshkey-encryption/config', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ enabled: !!sshEncToggle.checked })
                    });
                    await refreshSshEncStatus();
                } catch (e) {
                    window.showToast(e.message || 'Failed to update encryption toggle', 'error');
                    await refreshSshEncStatus();
                }
            });
        }

        if (sshEncGenBtn) {
            sshEncGenBtn.addEventListener('click', async () => {
                try {
                    const resp = await fetch('/settings/sshkey-encryption/generate', { method: 'POST' });
                    const data = await resp.json().catch(() => ({}));
                    if (!resp.ok || data.error) throw new Error(data.error || `Generate failed (${resp.status})`);
                    if (sshEncGenOut) {
                        sshEncGenOut.textContent = `export ${data.env_var}='${data.master_key}'
# Then restart the ailog service`;
                    }
                    await refreshSshEncStatus();
                } catch (e) {
                    if (sshEncGenOut) sshEncGenOut.textContent = e.message;
                }
            });
        }

        // best-effort refresh once on load
        refreshSshEncStatus();

        if (closeSettingsBtn) {
            closeSettingsBtn.addEventListener('click', () => closeModal(settingsModal));
        }
        // Host modal controls are optional (legacy manual host management)
        if (typeof addNewHostBtn !== 'undefined' && addNewHostBtn) {
            addNewHostBtn.addEventListener('click', () => openHostModal());
        }
        if (typeof hostModalCancelBtn !== 'undefined' && hostModalCancelBtn) {
            hostModalCancelBtn.addEventListener('click', () => {
                closeModal(hostModal);
                openModal(settingsModal);
            });
        if (typeof hostModalXBtn !== 'undefined' && hostModalXBtn) {
            hostModalXBtn.addEventListener('click', () => hostModalCancelBtn.click());
        }
        }
        
        hostListDiv.addEventListener('click', async (e) => {
            const button = e.target.closest('button');
            if (!button) return;
            const hostId = button.dataset.hostId;
            if (button.classList.contains('edit-host-btn')) {
                const hosts = await window.fetchApi('/hosts');
                const hostData = hosts[hostId];
                if (hostData) openHostModal({ id: hostId, ...hostData });
            }
            if (button.classList.contains('delete-host-btn')) {
                if (confirm('Are you sure you want to delete this host?')) {
                    await window.fetchApi(`/hosts/delete/${hostId}`, { method: 'DELETE' });
                    window.showToast('Host deleted.');
                    populateHostList();
                    populateHostCards();
                }
            }
        });

        hostTestBtn.addEventListener('click', async () => {
            hostTestStatus.classList.remove('hidden');
            hostTestStatus.textContent = 'Testing...';
            hostTestStatus.className = 'text-sm p-2 rounded-md bg-white/5 text-yellow-400';
            hostSaveBtn.classList.add('hidden');
            hostTestBtn.disabled = true;
            try {
                const res = await window.fetchApi('/hosts/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: hostIpInput.value, user: hostUserInput.value })
                });
                if (res.success) {
                    hostTestStatus.textContent = res.message;
                    hostTestStatus.className = 'text-sm p-2 rounded-md bg-green-800 text-green-300';
                    hostSaveBtn.classList.remove('hidden');
                    hostTestBtn.classList.add('hidden');
                } else {
                     throw new Error(res.error);
                }
            } catch (error) {
                hostTestStatus.textContent = `Test Failed: ${error.message}`;
                hostTestStatus.className = 'text-sm p-2 rounded-md bg-red-800 text-red-300';
                hostTestBtn.disabled = false;
                hostTestBtn.textContent = 'Retry Test';
            }
        });

        hostForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const hostId = hostIdInput.value;
            const hostData = {
                friendly_name: hostFriendlyNameInput.value,
                ip: hostIpInput.value,
                user: hostUserInput.value,
                description: hostDescriptionInput.value,
            };
            const url = hostId ? `/hosts/update/${hostId}` : '/hosts/add';
            const method = hostId ? 'PUT' : 'POST';
            try {
                await window.fetchApi(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(hostData) });
                window.showToast(`Host ${hostId ? 'updated' : 'added'} successfully.`);
                closeModal(hostModal);
                openModal(settingsModal);
                populateHostList();
                populateHostCards();
            } catch(error) {}
        });
        

        
        // Ollama test button (legacy - only if element exists)
        if (testOllamaBtn) {
        testOllamaBtn.addEventListener('click', async () => {
            const url = ollamaUrlInput.value.trim();
            if (!url) {
                ollamaTestStatus.textContent = 'Please enter an Ollama URL';
                ollamaTestStatus.className = 'text-xs text-red-600 mt-2';
                ollamaTestStatus.classList.remove('hidden');
                return;
            }
            
            testOllamaBtn.disabled = true;
            testOllamaBtn.textContent = 'Testing...';
            ollamaTestStatus.textContent = 'Testing connection...';
            ollamaTestStatus.className = 'text-xs text-yellow-600 mt-2';
            ollamaTestStatus.classList.remove('hidden');
            
            try {
                const res = await window.fetchApi('/ollama/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ollama_url: url })
                });
                
                if (res.success) {
                    ollamaTestStatus.textContent = `✅ ${res.message}`;
                    ollamaTestStatus.className = 'text-xs text-green-600 mt-2';
                    testOllamaBtn.className = 'bg-green-600 hover:bg-green-500 text-white px-4 py-2 text-sm rounded-md font-medium transition-colors disabled:opacity-50';
                    testOllamaBtn.textContent = 'Connected';
                    
                    // Show model selection section
                    ollamaModelSection.classList.remove('hidden');
                    
                    // Auto-load models
                    await loadOllamaModels(url);
                } else {
                    throw new Error(res.error);
                }
            } catch (error) {
                ollamaTestStatus.textContent = `❌ ${error.message}`;
                ollamaTestStatus.className = 'text-xs text-red-600 mt-2';
                testOllamaBtn.disabled = false;
                testOllamaBtn.textContent = 'Retry';
            }
        });
        }

        sourceListContainer.addEventListener('click', async (event) => {
            const link = event.target.closest('.log-link');
            if (!link) return;
            event.preventDefault();

            const sourceItem = link.closest('.source-item');
            currentLogName = sourceItem.dataset.name;
            const type = sourceItem.dataset.type;
            const selectedHost = selectedHostId;
            const selectedHostName = hosts[selectedHost]?.friendly_name || 'Localhost';

            // Update the log content area elements
            const logContentTitle = document.getElementById('log-content-title');
            const logContentContainer = document.getElementById('log-content-container');
            if (sshTerminalContainer) sshTerminalContainer.classList.add('hidden');
            if (logContentContainer) logContentContainer.classList.remove('hidden');
            
            logContentTitle.textContent = `Loading: ${currentLogName}...`;
            logContentContainer.innerHTML = '<div class="text-center termix-muted mt-16">Fetching log data...</div>';
            await updateAiAnalyseBtnVisibility(false);

            const hostParam = selectedHost === 'local' ? '' : `?host=${selectedHost}`;
            const url = type === 'file'
                ? `/log/${encodeURIComponent(currentLogName)}${hostParam}`
                : (type === 'docker'
                    ? `/api/docker/log/${encodeURIComponent(currentLogName)}${hostParam}`
                    : `/journal/${encodeURIComponent(currentLogName)}${hostParam}`);

            try {
                const response = await fetch(url);
                const data = await response.json();
                if (!response.ok) throw new Error(data.error);
                
                currentLogContent = data.content;
                logContentTitle.textContent = `${currentLogName} on ${selectedHostName}`;
                // Log lines are untrusted host output - use textContent, never innerHTML.
                logContentContainer.innerHTML = '<pre class="text-sm termix-text font-mono whitespace-pre-wrap"></pre>';
                logContentContainer.querySelector('pre').textContent = data.content || 'Log source is empty.';
                
                // Update button visibility based on content and AI config
                await updateAiAnalyseBtnVisibility(!!data.content, data.will_be_truncated);
            } catch (error) {
                logContentTitle.textContent = `Error loading ${currentLogName}`;
                logContentContainer.innerHTML = `<div class="text-center text-red-400 mt-16">${escapeHtml(error.message)}</div>`;
                window.showToast(error.message, 'error');
            }
        });

// Single close handler for the AI modal (previously re-attached per analysis)
(() => {
    const modal = document.getElementById('ai-analysis-modal');
    const closeBtn = document.getElementById('close-ai-modal-btn');
    if (modal && closeBtn) closeBtn.addEventListener('click', () => closeModal(modal));
})();

aiAnalyseBtn.addEventListener('click', async () => {
            if (!currentLogContent) {
                window.showToast('No log content to analyse.', 'error');
                return;
            }
            
            // Get provider configuration from backend
            let provider;
            try {
                const aiConfig = await window.fetchApi('/ai/config');
                provider = aiConfig.provider;
                if (!provider) {
                    window.showToast('No AI provider configured. Please set one up in Settings.', 'error');
                    return;
                }
            } catch (err) {
                window.showToast('Failed to load AI provider configuration: ' + err.message, 'error');
                return;
            }

            aiAnalyseBtn.textContent = 'Analysing...';
            aiAnalyseBtn.disabled = true;
            
            // Show staged progress in the modal
            const aiAnalysisModal = document.getElementById('ai-analysis-modal');
            const aiAnalysisContent = document.getElementById('ai-analysis-content');
            const providerLabels = { openai: 'OpenAI', ollama: 'Ollama', openrouter: 'OpenRouter' };
            const providerLabel = providerLabels[provider] || provider;

            renderAiAnalysisProgress(aiAnalysisContent, providerLabel);
            openModal(aiAnalysisModal);

            try {
                const requestBody = {
                    log_content: currentLogContent,
                    log_name: currentLogName,
                    webhook_url: localStorage.getItem('discord_webhook_url'),
                    provider: provider
                };
                
                // Add provider-specific auth
                if (provider === 'openai') {
                    requestBody.api_key = localStorage.getItem('openai_api_key');
                }

                let result = null;
                let streamError = null;

                await streamJsonEvents('/analyse/stream', requestBody, (evt) => {
                    if (!evt || !evt.type) return;
                    if (evt.type === 'stage') {
                        setAiAnalysisStage(evt.stage, evt.message, evt.elapsed);
                    } else if (evt.type === 'result') {
                        result = evt;
                    } else if (evt.type === 'error') {
                        streamError = new Error(evt.message || 'Analysis failed.');
                    }
                });

                if (streamError) throw streamError;
                if (!result) throw new Error('No analysis was returned by the server.');

                if (result.discord_sent) window.showToast('Issue detected! Alert sent to Discord.', 'info');

                renderMarkdownInto(aiAnalysisContent, result.analysis);
                const metaBits = [];
                if (result.provider) metaBits.push(String(result.provider).toUpperCase());
                if (result.model) metaBits.push(result.model);
                if (result.elapsed) metaBits.push(`${result.elapsed}s`);
                if (metaBits.length) {
                    aiAnalysisContent.insertAdjacentHTML('afterbegin',
                        `<div class="text-[11px] termix-muted mb-3">Analysed with ${escapeHtml(metaBits.join(' \u00b7 '))}</div>`);
                }
                window.showToast(`Analysis complete using ${(result.provider || provider).toUpperCase()}`);
            } catch (error) {
                aiAnalysisContent.innerHTML = `<p class="text-red-400"><strong>Analysis Failed:</strong><br>${escapeHtml(error.message)}</p>`;
            } finally {
                aiAnalyseBtn.textContent = 'AI Analyse';
                aiAnalyseBtn.disabled = false;
            }
        });
        
        // --- Multi-schedule UI (DB-backed schedules) ---
        let schedules = [];
        let activeScheduleId = null;

        const scheduleSelect = document.getElementById('schedule-select');
        const addScheduleBtn = document.getElementById('add-schedule-btn');
        const deleteScheduleBtn = document.getElementById('delete-schedule-btn');
        const saveScheduleBtn = document.getElementById('save-schedule-btn');
        const scheduleEnabledInput = document.getElementById('schedule-enabled-input');
        const scheduleHostsList = document.getElementById('schedule-hosts-list');

        const apiScheduleUrl = (id) => `/api/schedules/${id}`;

        const normalizeScheduleSourcesForUi = (sources) => {
            if (!Array.isArray(sources)) return [];
            return sources.map(s => ({
                host: s.host || s.host_id || 'local',
                type: s.type || s.source_type,
                name: s.name || s.source_name,
            })).filter(s => s.type && s.name);
        };

        const getSelectedHostIds = () => {
            const checked = Array.from(scheduleHostsList.querySelectorAll('input[type=checkbox]:checked'));
            const ids = checked.map(cb => cb.value).filter(Boolean);
            return ids.length ? ids : ['local'];
        };

        const renderHostsChecklist = (hostTuples, selectedIds) => {
            scheduleHostsList.innerHTML = '';
            hostTuples.forEach(([host_id, host_name]) => {
                const id = `sched-host-${host_id}`.replace(/[^a-zA-Z0-9_-]/g, '_');
                const wrapper = document.createElement('label');
                wrapper.className = 'flex items-center gap-2';
                wrapper.innerHTML = `
                    <input id="${id}" type="checkbox" class="h-4 w-4 rounded bg-white/10 border-gray-500 text-indigo-600 focus:ring-indigo-500" value="${host_id}">
                    <span>${host_name}</span>
                `;
                scheduleHostsList.appendChild(wrapper);
                const cb = wrapper.querySelector('input');
                cb.checked = selectedIds.includes(host_id);
            });
        };

        const setActiveSchedule = (scheduleId) => {
            activeScheduleId = scheduleId;
            const s = schedules.find(x => x.id === scheduleId);
            if (!s) return;

            scheduledSources = normalizeScheduleSourcesForUi(s.sources);
            selectedLogCountSpan.textContent = `${scheduledSources.length} logs selected`;

            scheduleIntervalInput.value = s.interval_hours || 6;
            scheduleEnabledInput.checked = !!s.enabled;

            const selectedHostIds = (s.hosts || []).map(h => h.host_id).filter(Boolean);
            // Render host checklist from known hosts (local + remote)
            const hostsJson = window.__hostsChoices || [['local','Localhost']];
            renderHostsChecklist(hostsJson, selectedHostIds.length ? selectedHostIds : ['local']);

            scheduleHostsDirty = false;
            setPickLogsButtonState(true);
            schedulerStatusDiv.innerHTML = `
                <p class="${s.enabled ? 'text-green-400' : 'text-yellow-400'} font-semibold">Status: ${s.enabled ? 'Enabled' : 'Disabled'}</p>
                <p>Interval: every ${s.interval_hours || 6} hour(s)</p>
                <p>Hosts: ${(s.hosts || []).length || 0} &nbsp; Logs: ${(s.sources || []).length || 0}</p>
            `;
        };

        const loadHostChoices = async () => {
            // Derive from existing /hosts endpoint output (already used elsewhere)
            try {
                const hostsData = await window.fetchApi('/hosts');
                const tuples = [['local','Localhost']];
                Object.entries(hostsData || {}).forEach(([hid, h]) => {
                    tuples.push([hid, (h && h.friendly_name) ? h.friendly_name : hid]);
                });
                window.__hostsChoices = tuples;
            } catch (_) {
                window.__hostsChoices = [['local','Localhost']];
            }
        };

        const loadSchedules = async () => {
            await loadHostChoices();
            schedules = await window.fetchApi('/api/schedules');
            if (!Array.isArray(schedules)) schedules = [];

            scheduleSelect.innerHTML = '';
            schedules.forEach(s => {
                const opt = document.createElement('option');
                opt.value = String(s.id);
                opt.textContent = s.name || `Schedule ${s.id}`;
                scheduleSelect.appendChild(opt);
            });

            if (!schedules.length) {
                schedulerStatusDiv.innerHTML = '<p class="text-yellow-400 font-semibold">No schedules found.</p>';
                return;
            }

            const desired = activeScheduleId || schedules[0].id;
            scheduleSelect.value = String(desired);
            setActiveSchedule(desired);
            setPickLogsButtonState(true);
        };

        scheduleSelect?.addEventListener('change', () => {
            const sid = parseInt(scheduleSelect.value, 10);
            if (!Number.isFinite(sid)) return;
            setActiveSchedule(sid);
        });

        addScheduleBtn?.addEventListener('click', async () => {
            const name = (prompt('Schedule name?', 'New Schedule') || '').trim() || 'New Schedule';
            try {
                const created = await window.fetchApi('/api/schedules', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, enabled: false, interval_hours: 6, hosts: ['local'], sources: [] })
                });
                window.showToast('Schedule created', 'success');
                activeScheduleId = created.id;
                await loadSchedules();
            } catch (_) {}
        });

        deleteScheduleBtn?.addEventListener('click', async () => {
            if (!activeScheduleId) return;
            if (!confirm('Delete this schedule?')) return;
            try {
                await window.fetchApi(apiScheduleUrl(activeScheduleId), { method: 'DELETE' });
                window.showToast('Schedule deleted', 'success');
                activeScheduleId = null;
                await loadSchedules();
            } catch (_) {}
        });

        const saveActiveSchedule = async (patch) => {
            if (!activeScheduleId) return;
            const data = await window.fetchApi(apiScheduleUrl(activeScheduleId), {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(patch)
            });
            // Update local cache
            const idx = schedules.findIndex(s => s.id === activeScheduleId);
            if (idx >= 0) schedules[idx] = data;
            setActiveSchedule(activeScheduleId);
            return data;
        };

        scheduleHostsList?.addEventListener('change', () => {
            scheduleHostsDirty = true;
            setPickLogsButtonState(false);
            if (schedulerStatusDiv) {
                schedulerStatusDiv.innerHTML = '<p class="text-yellow-400 font-semibold">Host selection changed.</p><p class="text-xs termix-muted">Click Save before picking logs.</p>';
            }
        });

        saveScheduleBtn?.addEventListener('click', async () => {
            const interval_hours = Math.max(1, parseInt(scheduleIntervalInput.value || '6', 10));
            const enabled = !!scheduleEnabledInput.checked;
            const hosts = getSelectedHostIds();
            try {
                await saveActiveSchedule({ interval_hours, enabled, hosts });
                scheduleHostsDirty = false;
                setPickLogsButtonState(true);
                window.showToast('Schedule saved', 'success');
            } catch (_) {}
        });

        const updateSchedulerStatus = async () => {
            try {
                await loadSchedules();
            } catch (e) {
                schedulerStatusDiv.innerHTML = `<p class="text-red-400 font-semibold">Error loading schedules.</p>`;
            }
        };

        const updateLogSelectionProgress = (message, progress = 0) => {
            logSelectionProgressDetails.innerHTML += `<div>${new Date().toLocaleTimeString()}: ${message}</div>`;
            logSelectionProgressDetails.scrollTop = logSelectionProgressDetails.scrollHeight;
            logSelectionProgressBar.style.width = `${progress}%`;
            logSelectionProgressPercent.textContent = `${progress}%`;
        };

        const getSourcesStreamUrl = () => {
            if (!activeScheduleId) return '/sources/table/stream';
            const hosts = getSelectedHostIds();
            const qp = encodeURIComponent(hosts.join(','));
            return `/api/schedules/${activeScheduleId}/sources/table/stream?hosts=${qp}`;
        };

        const showRetrySection = (failedHosts) => {
            // Transform progress section into a retry section
            const progressContainer = logSelectionProgress;
            progressContainer.innerHTML = `
                <div class="flex items-center justify-between mb-2">
                    <span class="text-sm font-medium text-yellow-300">⚠️ Some hosts failed to connect</span>
                    <button id="retry-failed-hosts-btn" class="px-3 py-1 text-xs bg-yellow-600 hover:bg-yellow-500 text-white rounded transition-colors">Retry Failed Hosts</button>
                </div>
                <div class="max-h-20 overflow-y-auto bg-gray-900 rounded-md p-2 text-xs">
                    ${failedHosts.map(host => `<div class="text-red-400">❌ ${host.host_name}: ${host.error}</div>`).join('')}
                </div>
            `;
            
            // Add retry functionality
            const retryBtn = document.getElementById('retry-failed-hosts-btn');
            retryBtn.addEventListener('click', async () => {
                retryBtn.disabled = true;
                retryBtn.textContent = 'Retrying...';
                
                // Reset progress section for retry
                progressContainer.innerHTML = `
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-sm font-medium termix-muted">Retrying failed hosts...</span>
                        <span id="retry-progress-percent" class="text-sm termix-muted">0%</span>
                    </div>
                    <div class="w-full bg-white/5 rounded-full h-2 mb-2">
                        <div id="retry-progress-bar" class="bg-yellow-600 h-2 rounded-full transition-all duration-300" style="width: 0%"></div>
                    </div>
                    <div id="retry-progress-details" class="max-h-20 overflow-y-auto bg-gray-900 rounded-md p-2 text-xs font-mono termix-muted">
                        <div>Retrying failed host connections...</div>
                    </div>
                `;
                
                const retryProgressBar = document.getElementById('retry-progress-bar');
                const retryProgressPercent = document.getElementById('retry-progress-percent');
                const retryProgressDetails = document.getElementById('retry-progress-details');
                
                const updateRetryProgress = (message, progress = 0) => {
                    retryProgressDetails.innerHTML += `<div>${new Date().toLocaleTimeString()}: ${message}</div>`;
                    retryProgressDetails.scrollTop = retryProgressDetails.scrollHeight;
                    retryProgressBar.style.width = `${progress}%`;
                    retryProgressPercent.textContent = `${progress}%`;
                };
                
                try {
                    // Use streaming endpoint again for retry
                    const eventSource = new EventSource(getSourcesStreamUrl());
                    let newData = null;
                    
                    const retryPromise = new Promise((resolve, reject) => {
                        eventSource.onmessage = function(event) {
                            try {
                                const data = JSON.parse(event.data);
                                
                                if (data.status === 'progress') {
                                    updateRetryProgress(data.message, data.progress || 0);
                                } else if (data.status === 'complete') {
                                    newData = data.data;
                                    eventSource.close();
                                    resolve(newData);
                                } else if (data.status === 'error') {
                                    eventSource.close();
                                    reject(new Error(data.message));
                                }
                            } catch (e) {
                                console.error('Error parsing retry SSE data:', e);
                            }
                        };
                        
                        eventSource.onerror = function(event) {
                            eventSource.close();
                            reject(new Error('Connection error during retry'));
                        };
                        
                        setTimeout(() => {
                            if (eventSource.readyState !== EventSource.CLOSED) {
                                eventSource.close();
                                reject(new Error('Retry timeout'));
                            }
                        }, 60000);
                    });
                    
                    const retryData = await retryPromise;
                    
                    // Update the existing table with new data
                    updateLogSelectionTable(retryData);
                    
                    updateRetryProgress(`✅ Retry complete: ${retryData.successful_hosts}/${retryData.total_hosts} hosts connected`, 100);
                    
                    // Handle remaining failed hosts
                    if (retryData.failed_hosts && retryData.failed_hosts.length > 0) {
                        setTimeout(() => {
                            showRetrySection(retryData.failed_hosts);
                        }, 1000);
                    } else {
                        setTimeout(() => {
                            progressContainer.classList.add('hidden');
                            window.showToast('All hosts connected successfully!', 'success');
                        }, 2000);
                    }
                    
                } catch (error) {
                    updateRetryProgress(`❌ Retry failed: ${error.message}`, 0);
                    setTimeout(() => {
                        showRetrySection(failedHosts); // Show original failed hosts again
                    }, 2000);
                }
            });
        };

        const updateLogSelectionTable = (newData) => {
            // Find existing table and update it with new data
            const existingTable = logSelectionList.querySelector('table');
            if (!existingTable) {
                // If no existing table, create a new one
                buildLogSelectionTable(newData);
                return;
            }
            
            // Update the existing table with merged data
            const existingData = getCurrentTableData();
            const mergedData = mergeTableData(existingData, newData);
            
            // Rebuild the table content
            const contentContainer = logSelectionList.querySelector('div');
            if (contentContainer) {
                logSelectionList.removeChild(contentContainer);
            }
            buildLogSelectionTable(mergedData);
        };

        const getCurrentTableData = () => {
            // Extract current table data (this is a simplified version)
            // In a real implementation, you'd want to preserve the current state
            return { logs: [], hosts: [], failed_hosts: [], successful_hosts: 0, total_hosts: 0 };
        };

        const mergeTableData = (existingData, newData) => {
            // Merge the data, preferring new data but keeping successful connections from existing
            return newData; // Simplified - just use new data for now
        };

        const buildLogSelectionTable = (data) => {
            // Extract the table building logic into a separate function
            const contentContainer = document.createElement('div');
            contentContainer.className = 'h-full flex flex-col';
            
            // Add summary information at the top
            if (data.failed_hosts && data.failed_hosts.length > 0) {
                const warningDiv = document.createElement('div');
                warningDiv.className = 'mb-4 p-3 bg-yellow-900/30 border border-yellow-600 rounded-md text-yellow-200 flex-shrink-0';
                warningDiv.innerHTML = `
                    <h4 class="font-semibold mb-2">⚠️ Host Connection Issues</h4>
                    <p class="text-sm mb-2">Successfully connected to ${data.successful_hosts}/${data.total_hosts} hosts.</p>
                    <details class="text-xs">
                        <summary class="cursor-pointer hover:text-yellow-100">Show failed hosts...</summary>
                        <ul class="mt-2 ml-4 list-disc">
                            ${data.failed_hosts.map(h => `<li>${h.host_name}: ${h.error}</li>`).join('')}
                        </ul>
                    </details>
                `;
                contentContainer.appendChild(warningDiv);
            }

            const tableContainer = document.createElement('div');
            tableContainer.className = 'flex-1 overflow-auto border border-white/10 rounded-md';

            const table = document.createElement('table');
            table.className = 'min-w-full divide-y divide-gray-700';

            const thead = document.createElement('thead');
            thead.className = 'bg-white/5 sticky top-0 z-10';
            const headerRow = document.createElement('tr');
            
            // Header: Log Name + Host Names
            let headerHTML = '<th class="px-6 py-3 text-left text-xs font-medium termix-muted uppercase tracking-wider bg-white/5">Log Name</th>';
            data.hosts.forEach(host => {
                headerHTML += `<th class="px-6 py-3 text-left text-xs font-medium termix-muted uppercase tracking-wider bg-white/5">${host.host_name}</th>`;
            });
            headerRow.innerHTML = headerHTML;
            thead.appendChild(headerRow);
            
            const tbody = document.createElement('tbody');
            tbody.className = 'bg-gray-800 divide-y divide-gray-700';

            // Process the logs data
            data.logs.forEach(log => {
                const row = document.createElement('tr');
                
                let rowHTML = `<td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-white">${log.name}</td>`;
                
                data.hosts.forEach(host => {
                    const hostData = log.hosts[host.host_id];
                    if (hostData) {
                        const checked = scheduledSources.some(s => s.name === log.name && s.type === log.type && s.host === host.host_id) ? 'checked' : '';
                        rowHTML += `<td class="px-6 py-4 whitespace-nowrap text-sm termix-muted"><input type="checkbox" class="h-4 w-4 rounded bg-white/10 border-gray-500 text-indigo-600 focus:ring-indigo-500" value='${JSON.stringify({ name: log.name, type: log.type, host: host.host_id })}' ${checked}/></td>`;
                    } else {
                        rowHTML += '<td class="px-6 py-4 whitespace-nowrap text-sm termix-muted">-</td>';
                    }
                });
                row.innerHTML = rowHTML;
                tbody.appendChild(row);
            });

            table.appendChild(thead);
            table.appendChild(tbody);
            tableContainer.appendChild(table);
            contentContainer.appendChild(tableContainer);
            logSelectionList.appendChild(contentContainer);
        };

        selectLogsBtn.addEventListener('click', async () => {
            if (scheduleHostsDirty) { window.showToast('Please click Save first (hosts changed).', 'error'); return; }
            logSelectionTitle.textContent = 'Select Logs to Monitor from All Hosts';
            logSelectionList.innerHTML = '';
            openModal(logSelectionModal);
            
            // Show progress section
            logSelectionProgress.classList.remove('hidden');
            logSelectionProgressDetails.innerHTML = '';
            updateLogSelectionProgress('Initializing scan of all configured hosts...', 5);
            
            console.log('Starting log selection modal - connecting to /sources/table/stream');
            
            let collectedData = null;
            let hasError = false;
            
            try {
                updateLogSelectionProgress('Fetching logs from selected hosts... Please wait, this may take a while.', 10);
                
                // Use Server-Sent Events for streaming progress
                const eventSource = new EventSource(getSourcesStreamUrl());
                console.log('EventSource created, connection state:', eventSource.readyState);
                
                const streamPromise = new Promise((resolve, reject) => {
                    let messageCount = 0;
                    let partialSources = [];
                    let partialHosts = [];
                    let partialFailedHosts = [];
                    let totalHosts = 0;
                    
                    eventSource.onopen = function(event) {
                        console.log('EventSource connection opened');
                    };
                    
                    eventSource.onmessage = function(event) {
                        messageCount++;
                        console.log(`SSE Message #${messageCount}:`, event.data);
                        
                        try {
                            const data = JSON.parse(event.data);
                            
                            if (data.status === 'progress') {
                                updateLogSelectionProgress(data.message, data.progress || 0);
                                
                                // Extract host information from progress messages
                                if (data.message.includes('Found') && data.message.includes('hosts to scan')) {
                                    const match = data.message.match(/Found (\d+) hosts/);
                                    if (match) totalHosts = parseInt(match[1]);
                                }
                                
                                // Track successful host connections
                                if (data.message.includes('✅') && data.message.includes('Found') && data.message.includes('log sources')) {
                                    const hostMatch = data.message.match(/✅ ([^:]+): Found (\d+) log sources/);
                                    if (hostMatch) {
                                        const hostName = hostMatch[1];
                                        const sourceCount = parseInt(hostMatch[2]);
                                        console.log(`Tracked successful host: ${hostName} with ${sourceCount} sources`);
                                        
                                        // Add to partial hosts list if not already there
                                        if (!partialHosts.find(h => h.host_name === hostName)) {
                                            partialHosts.push({
                                                host_id: hostName === 'Localhost' ? 'local' : hostName.toLowerCase(),
                                                host_name: hostName
                                            });
                                        }
                                    }
                                }
                                
                                // Track failed hosts
                                if (data.message.includes('❌')) {
                                    const failMatch = data.message.match(/❌ ([^:]+): (.+)/);
                                    if (failMatch) {
                                        const hostName = failMatch[1];
                                        const error = failMatch[2];
                                        partialFailedHosts.push({
                                            host_id: hostName === 'Localhost' ? 'local' : hostName.toLowerCase(),
                                            host_name: hostName,
                                            error: error
                                        });
                                    }
                                }
                            } else if (data.status === 'complete') {
                                console.log('SSE Complete - final data:', data.data);
                                collectedData = data.data;
                                eventSource.close();
                                resolve(data.data);
                            } else if (data.status === 'error') {
                                console.error('SSE Error status received:', data.message);
                                eventSource.close();
                                hasError = true;
                                // Don't reject immediately - we might have partial data
                                if (collectedData) {
                                    resolve(collectedData);
                                } else {
                                    reject(new Error(data.message));
                                }
                            }
                        } catch (e) {
                            console.error('Error parsing SSE data:', e, 'Raw data:', event.data);
                        }
                    };
                    
                    eventSource.onerror = function(event) {
                        console.error('EventSource error:', event);
                        console.log('EventSource readyState:', eventSource.readyState);
                        eventSource.close();
                        
                        // If we have partial data, use it
                        if (collectedData) {
                            console.log('Using partial data despite connection error:', collectedData);
                            resolve(collectedData);
                        } else if (partialHosts.length > 0) {
                            console.log('Creating partial data from collected progress info');
                            const partialData = {
                                logs: [], // We don't have detailed log info, but we have host info
                                hosts: partialHosts,
                                failed_hosts: partialFailedHosts,
                                total_hosts: totalHosts || partialHosts.length + partialFailedHosts.length,
                                successful_hosts: partialHosts.length
                            };
                            resolve(partialData);
                        } else {
                            reject(new Error('Connection error while fetching logs'));
                        }
                    };
                    
                    // Timeout after 60 seconds
                    setTimeout(() => {
                        if (eventSource.readyState !== EventSource.CLOSED) {
                            console.log('SSE timeout reached, current state:', eventSource.readyState);
                            console.log('Partial hosts collected:', partialHosts);
                            console.log('Failed hosts:', partialFailedHosts);
                            eventSource.close();
                            
                            // If we have partial data, use it
                            if (collectedData) {
                                console.log('Using partial data due to timeout:', collectedData);
                                resolve(collectedData);
                            } else if (partialHosts.length > 0) {
                                console.log('Creating partial data from timeout with collected progress info');
                                // Add the host that was being processed when timeout occurred to failed hosts
                                const lastMessage = logSelectionProgressDetails.lastElementChild?.textContent || '';
                                if (lastMessage.includes('Connecting to')) {
                                    const connectingMatch = lastMessage.match(/Connecting to ([^.]+)/);
                                    if (connectingMatch) {
                                        const timedOutHost = connectingMatch[1];
                                        if (!partialFailedHosts.find(h => h.host_name === timedOutHost)) {
                                            partialFailedHosts.push({
                                                host_id: timedOutHost === 'Localhost' ? 'local' : timedOutHost.toLowerCase(),
                                                host_name: timedOutHost,
                                                error: 'Connection timed out'
                                            });
                                        }
                                    }
                                }
                                
                                const partialData = {
                                    logs: [], // We don't have detailed log info, but we have host info
                                    hosts: partialHosts,
                                    failed_hosts: partialFailedHosts,
                                    total_hosts: totalHosts || partialHosts.length + partialFailedHosts.length,
                                    successful_hosts: partialHosts.length
                                };
                                resolve(partialData);
                            } else {
                                reject(new Error('Timeout while fetching logs'));
                            }
                        }
                    }, 60000);
                });
                
                const data = await streamPromise;
                console.log('Stream promise resolved with data:', data);
                updateLogSelectionProgress(`Successfully connected to ${data.successful_hosts}/${data.total_hosts} hosts`, 95);
                
                if (data.failed_hosts && data.failed_hosts.length > 0) {
                    data.failed_hosts.forEach(host => {
                        updateLogSelectionProgress(`⚠️ Failed to connect to ${host.host_name}: ${host.error}`, 50);
                    });
                }
                
                updateLogSelectionProgress(`Found ${data.logs.length} unique logs across all hosts`, 70);
                
                if (data.logs.length === 0) {
                    logSelectionList.innerHTML = '<div class="text-center p-4 termix-muted">No logs found on any accessible hosts.</div>';
                    logSelectionProgress.classList.add('hidden');
                    return;
                }
                
                updateLogSelectionProgress('Building log selection table...', 80);

                // Create container with summary info
                const contentContainer = document.createElement('div');
                contentContainer.className = 'h-full flex flex-col';
                
                // Add summary information at the top
                if (data.failed_hosts && data.failed_hosts.length > 0) {
                    const warningDiv = document.createElement('div');
                    warningDiv.className = 'mb-4 p-3 bg-yellow-900/30 border border-yellow-600 rounded-md text-yellow-200 flex-shrink-0';
                    warningDiv.innerHTML = `
                        <h4 class="font-semibold mb-2">⚠️ Host Connection Issues</h4>
                        <p class="text-sm mb-2">Successfully connected to ${data.successful_hosts}/${data.total_hosts} hosts.</p>
                        <details class="text-xs">
                            <summary class="cursor-pointer hover:text-yellow-100">Show failed hosts...</summary>
                            <ul class="mt-2 ml-4 list-disc">
                                ${data.failed_hosts.map(h => `<li>${h.host_name}: ${h.error}</li>`).join('')}
                            </ul>
                        </details>
                    `;
                    contentContainer.appendChild(warningDiv);
                }

                const tableContainer = document.createElement('div');
                tableContainer.className = 'flex-1 overflow-auto border border-white/10 rounded-md';

                const table = document.createElement('table');
                table.className = 'min-w-full divide-y divide-gray-700';

                const thead = document.createElement('thead');
                thead.className = 'bg-white/5 sticky top-0 z-10';
                const headerRow = document.createElement('tr');
                
                // Header: Log Name + Host Names
                let headerHTML = '<th class="px-6 py-3 text-left text-xs font-medium termix-muted uppercase tracking-wider bg-white/5">Log Name</th>';
                data.hosts.forEach(host => {
                    headerHTML += `<th class="px-6 py-3 text-left text-xs font-medium termix-muted uppercase tracking-wider bg-white/5">${host.host_name}</th>`;
                });
                headerRow.innerHTML = headerHTML;
                thead.appendChild(headerRow);
                
                const tbody = document.createElement('tbody');
                tbody.className = 'bg-gray-800 divide-y divide-gray-700';

                // Process the logs data (which is already in the correct format from /sources/table)
                data.logs.forEach(log => {
                    const row = document.createElement('tr');
                    
                    let rowHTML = `<td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-white">${log.name}</td>`;
                    
                    data.hosts.forEach(host => {
                        const hostData = log.hosts[host.host_id];
                        if (hostData) {
                            const checked = scheduledSources.some(s => s.name === log.name && s.type === log.type && s.host === host.host_id) ? 'checked' : '';
                            rowHTML += `<td class="px-6 py-4 whitespace-nowrap text-sm termix-muted"><input type="checkbox" class="h-4 w-4 rounded bg-white/10 border-gray-500 text-indigo-600 focus:ring-indigo-500" value='${JSON.stringify({ name: log.name, type: log.type, host: host.host_id })}' ${checked}/></td>`;
                        } else {
                            rowHTML += '<td class="px-6 py-4 whitespace-nowrap text-sm termix-muted">-</td>';
                        }
                    });
                    row.innerHTML = rowHTML;
                    tbody.appendChild(row);
                });

                table.appendChild(thead);
                table.appendChild(tbody);
                tableContainer.appendChild(table);
                contentContainer.appendChild(tableContainer);
                logSelectionList.appendChild(contentContainer);
                
                updateLogSelectionProgress(`✅ Table ready with ${data.logs.length} logs from ${data.successful_hosts} hosts`, 100);
                
                // Hide progress after a short delay, but keep it visible if there are failed hosts
                if (data.failed_hosts && data.failed_hosts.length > 0) {
                    // Show retry section instead of hiding progress
                    setTimeout(() => {
                        showRetrySection(data.failed_hosts);
                    }, 1000);
                } else {
                    setTimeout(() => {
                        logSelectionProgress.classList.add('hidden');
                    }, 2000);
                }
            } catch (error) {
                updateLogSelectionProgress(`❌ Error: ${error.message}`, 0);
                logSelectionList.innerHTML = '<div class="text-center p-4 text-red-400">Failed to load logs from hosts.</div>';
                setTimeout(() => {
                    logSelectionProgress.classList.add('hidden');
                }, 3000);
            }
        });

        saveLogSelectionBtn.addEventListener('click', async () => {
            const selectedLogs = Array.from(logSelectionList.querySelectorAll('input:checked')).map(cb => JSON.parse(cb.value));
            scheduledSources = selectedLogs;
            selectedLogCountSpan.textContent = `${scheduledSources.length} logs selected`;

            // Persist to the active schedule
            if (activeScheduleId) {
                try {
                    await saveActiveSchedule({ sources: scheduledSources });
                    window.showToast('Log selection saved to schedule', 'success');
                } catch (_) {}
            }

            closeModal(logSelectionModal);
        });

        cancelLogSelectionBtn.addEventListener('click', () => closeModal(logSelectionModal));

        startScheduleBtn.addEventListener('click', async () => {
            if (!activeScheduleId) { window.showToast('No schedule selected.', 'error'); return; }

            const interval_hours = Math.max(1, parseInt(scheduleIntervalInput.value || '6', 10));
            const webhookUrl = discordWebhookInput.value.trim();
            const provider = localStorage.getItem('analysis_provider') || 'openai';

            if (scheduledSources.length === 0) { window.showToast('Select at least one log for this schedule.', 'error'); return; }
            if (!webhookUrl) { window.showToast('Discord webhook is required.', 'error'); return; }

            // Provider-specific requirements
            if (provider === 'ollama') {
                const ollamaUrl = localStorage.getItem('ollama_url');
                const ollamaModel = localStorage.getItem('ollama_model');
                if (!ollamaUrl || !ollamaModel) { window.showToast('Ollama is not configured. Please set it up first.', 'error'); return; }
            } else {
                const openaiKeyEl = openaiApiKeyInput || apiKeyInput;
                const apiKey = openaiKeyEl ? openaiKeyEl.value.trim() : '';
                if (!apiKey) { window.showToast('OpenAI API key is required.', 'error'); return; }
            }

            try {
                // Persist schedule config: enable + interval + hosts + sources
                const hosts = getSelectedHostIds();
                await saveActiveSchedule({ enabled: true, interval_hours, hosts, sources: scheduledSources });
                window.showToast('Schedule started (enabled).', 'success');
                updateSchedulerStatus();
            } catch (error) {}
        });

        stopScheduleBtn.addEventListener('click', async () => {
            if (!activeScheduleId) { window.showToast('No schedule selected.', 'error'); return; }
            try {
                await saveActiveSchedule({ enabled: false });
                window.showToast('Schedule stopped (disabled).', 'success');
                updateSchedulerStatus();
            } catch (error) {}
        });

        // Run Now: stream progress in sidebar progress panel
        let runNowEventSource = null;
        const appendProgressLog = (msg) => {
            if (!progressLogs) return;
            const line = document.createElement('div');
            line.textContent = msg;
            progressLogs.appendChild(line);
            progressLogs.scrollTop = progressLogs.scrollHeight;
        };


        let progressMinimized = false;

        const resetRunNowUi = () => {
            runNowBtn.disabled = false;
            runNowBtn.textContent = 'Run Now';
        };

        if (progressMinimizeBtn) {
            progressMinimizeBtn.addEventListener('click', () => {
                progressMinimized = !progressMinimized;
                if (progressLogs) progressLogs.classList.toggle('hidden', progressMinimized);
                progressMinimizeBtn.textContent = progressMinimized ? '+' : '_';
            });
        }

        if (progressCloseBtn) {
            progressCloseBtn.addEventListener('click', () => {
                if (runNowEventSource) {
                    try { runNowEventSource.close(); } catch (_) {}
                    runNowEventSource = null;
                }
                if (progressContainer) progressContainer.classList.add('hidden');
                if (progressBar) progressBar.style.width = '0%';
                if (progressMessage) progressMessage.textContent = '';
                if (progressLogs) progressLogs.innerHTML = '';
                resetRunNowUi();
            });
        }

        const formatRunNowLogMessage = (msg) => {
            if (!msg) return msg;
            if (msg.includes('insufficient_quota') || msg.includes('You exceeded your current quota')) {
                return '\u26a0\ufe0f OpenAI: quota exceeded \u2014 check your billing at platform.openai.com';
            }
            if (msg.includes('invalid_api_key') || msg.includes('Incorrect API key') || msg.includes('No API key provided')) {
                return '\u274c OpenAI: invalid or missing API key.';
            }
            if (msg.includes('rate_limit_exceeded') || (msg.includes('429') && msg.includes('rate'))) {
                return '\u23f3 OpenAI: rate limited \u2014 too many requests. Try again shortly.';
            }
            if ((msg.startsWith('Error analyzing') || msg.startsWith('Error code:')) && msg.length > 220) {
                const shortMsg = msg.slice(0, 220).replace(/{.*$/s, '').trim();
                return (shortMsg || msg.slice(0, 220)) + '\u2026';
            }
            return msg;
        };

        runNowBtn.addEventListener('click', async () => {
            if (scheduledSources.length === 0) { window.showToast('Please select logs for the schedule first.', 'error'); return; }

            // Reset + show progress UI
            if (runNowEventSource) {
                try { runNowEventSource.close(); } catch (_) {}
                runNowEventSource = null;
            }
            if (progressContainer) progressContainer.classList.remove('hidden');
            if (progressBar) progressBar.style.width = '0%';
            if (progressMessage) progressMessage.textContent = 'Starting Run Now...';
            if (progressLogs) progressLogs.innerHTML = '';
            appendProgressLog('Starting...');

            runNowBtn.disabled = true;
            runNowBtn.textContent = 'Running...';

            if (!activeScheduleId) { window.showToast('No schedule selected.', 'error'); resetRunNowUi(); return; }
            runNowEventSource = new EventSource(`/api/schedules/${activeScheduleId}/run_now/stream`);

            runNowEventSource.onmessage = (event) => {
                let data;
                try { data = JSON.parse(event.data); } catch (_) { return; }

                if (data.status === 'progress') {
                    if (progressBar && typeof data.progress === 'number') progressBar.style.width = `${data.progress}%`;
                    if (progressMessage && data.message) progressMessage.textContent = data.message;
                    if (data.message) appendProgressLog(formatRunNowLogMessage(data.message));
                } else if (data.status === 'log') {
                    if (data.message) appendProgressLog(formatRunNowLogMessage(data.message));
                } else if (data.status === 'error') {
                    if (data.message) window.showToast(data.message, 'error');
                    if (progressMessage && data.message) progressMessage.textContent = data.message;
                    if (progressBar) progressBar.style.width = '100%';
                    appendProgressLog('Error.');
                    try { runNowEventSource.close(); } catch (_) {}
                    runNowEventSource = null;
                    runNowBtn.disabled = false;
                    runNowBtn.textContent = 'Run Now';
                } else if (data.status === 'complete') {
                    if (progressBar) progressBar.style.width = '100%';
                    if (progressMessage) progressMessage.textContent = data.message || 'Done';
                    appendProgressLog(data.message || 'Done');
                    try { runNowEventSource.close(); } catch (_) {}
                    runNowEventSource = null;
                    runNowBtn.disabled = false;
                    runNowBtn.textContent = 'Run Now';
                }
            };

            runNowEventSource.onerror = (err) => {
                console.error('Run Now EventSource failed:', err);
                window.showToast('Run Now stream connection failed.', 'error');
                try { runNowEventSource.close(); } catch (_) {}
                runNowEventSource = null;
                runNowBtn.disabled = false;
                runNowBtn.textContent = 'Run Now';
            };
        });

        testDiscordBtn.addEventListener('click', async () => {
            const webhookUrl = discordWebhookInput.value.trim();

            testDiscordBtn.disabled = true;
            const original = testDiscordBtn.textContent;
            testDiscordBtn.textContent = 'Testing...';

            try {
                // If field is empty, backend will test saved webhook
                await window.fetchApi('/discord/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ webhook_url: webhookUrl })
                });
                window.showToast('Discord webhook test sent.', 'success');
                setStatusDot(discordWebhookStatusDot, true);
            } catch (error) {
                window.showToast(error.message || 'Discord test failed.', 'error');
                setStatusDot(discordWebhookStatusDot, false);
            } finally {
                testDiscordBtn.disabled = false;
                testDiscordBtn.textContent = original;
            }
        });

        // Event listeners for search/filter/sort removed - not needed for current UI

        // --- VIEW MODE LISTENERS ---
        // View mode listeners removed - buttons don't exist in current UI

        // --- SEARCH FUNCTIONALITY ---
        const performSearch = async () => {
            const query = searchInput.value.trim();
            if (!query) {
                window.showToast('Please enter a search query', 'error');
                return;
            }

            searchBtn.disabled = true;
            searchBtn.textContent = 'Searching...';
            searchResultsList.innerHTML = '';

            try {
                const scope = searchScope.value === 'selected' && currentLogName ? 
                    (currentLogType === 'file'
                        ? `file:${currentLogName}`
                        : (currentLogType === 'docker' ? 'all' : `journal:${currentLogName}`)) : 'all';
                
                const hostFilter = searchScope.value === 'selected' && currentHostId ? [currentHostId] : [];

                const searchData = {
                    query: query,
                    scope: scope,
                    host_filter: hostFilter,
                    case_sensitive: caseSensitiveCheckbox.checked
                };

                const results = await window.fetchApi('/search', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(searchData)
                });

                displaySearchResults(results, query);
            } catch (error) {
                searchResultsList.innerHTML = `
                    <div class="p-4 text-red-400 text-center">
                        <p>Search failed: ${error.message}</p>
                    </div>
                `;
                searchResultsContainer.classList.remove('hidden');
            } finally {
                searchBtn.disabled = false;
                searchBtn.textContent = 'Search';
            }
        };

        const displaySearchResults = (results, query) => {
            searchResultsList.innerHTML = '';
            
            if (results.failed_hosts && results.failed_hosts.length > 0) {
                const failedDiv = document.createElement('div');
                failedDiv.className = 'mb-3 p-2 bg-yellow-100 border border-yellow-300 rounded text-yellow-800 text-xs';
                failedDiv.innerHTML = `⚠️ Could not search ${results.failed_hosts.length} host(s): ${results.failed_hosts.map(h => h.host_name).join(', ')}`;
                searchResultsList.appendChild(failedDiv);
            }

            if (results.total_matches === 0) {
                const noResultsDiv = document.createElement('div');
                noResultsDiv.className = 'p-4 termix-muted text-center';
                noResultsDiv.innerHTML = `No matches found for "${query}"`;
                searchResultsList.appendChild(noResultsDiv);
            } else {
                const headerDiv = document.createElement('div');
                headerDiv.className = 'mb-3 text-sm termix-muted';
                headerDiv.innerHTML = `Found ${results.total_matches} match${results.total_matches !== 1 ? 'es' : ''} for "${query}"`;
                searchResultsList.appendChild(headerDiv);

                results.results.forEach(result => {
                    const resultDiv = document.createElement('div');
                    resultDiv.className = 'mb-2 p-3 bg-white border border-white/10 rounded-lg hover:bg-white/5 cursor-pointer transition-colors';
                    
                    // Highlight the search term in the content
                    const highlightedContent = result.content.replace(
                        new RegExp(`(${escapeRegExp(query)})`, caseSensitiveCheckbox.checked ? 'g' : 'gi'),
                        '<mark class="bg-yellow-200">$1</mark>'
                    );
                    
                    resultDiv.innerHTML = `
                        <div class="flex items-start justify-between mb-2">
                            <div class="flex-1">
                                <div class="flex items-center space-x-2 mb-1">
                                    <span class="font-medium termix-text">${result.log_name}</span>
                                    <span class="text-xs px-2 py-1 rounded ${
                                        result.log_type === 'file' ? 'bg-blue-100 text-blue-800' : 'bg-purple-100 text-purple-800'
                                    }">${result.log_type}</span>
                                    <span class="text-xs termix-muted">on ${result.host_name}</span>
                                </div>
                                <div class="text-sm termix-muted font-mono termix-panel p-2 rounded">
                                    ${result.line_number ? `Line ${result.line_number}: ` : ''}${highlightedContent}
                                </div>
                            </div>
                        </div>
                    `;
                    
                    resultDiv.addEventListener('click', () => {
                        loadLogContent(result.log_name, result.log_type, result.host_id, result.host_name);
                        // Update current log info for "selected log only" searches
                        currentLogName = result.log_name;
                        currentLogType = result.log_type;
                        currentHostId = result.host_id;
                        // Close search results
                        searchResultsContainer.classList.add('hidden');
                    });
                    
                    searchResultsList.appendChild(resultDiv);
                });
            }
            
            searchResultsContainer.classList.remove('hidden');
        };

        const escapeRegExp = (string) => {
            return string.replace(/[.*+?^${}()|[\[\]\\]/g, '\\$&');

        };

        // Search event listeners
        searchBtn.addEventListener('click', performSearch);
        
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                performSearch();
            }
        });
        
        closeSearchResults.addEventListener('click', () => {
            searchResultsContainer.classList.add('hidden');
        });

        // Update search scope when log is selected
        const originalLoadLogContent = loadLogContent;
        const enhancedLoadLogContent = async (logName, logType, hostId, hostName) => {
            await originalLoadLogContent(logName, logType, hostId, hostName);
            // Update current log info for search
            currentLogName = logName;
            currentLogType = logType;
            currentHostId = hostId;
        };
        
        // Replace the original function
        window.loadLogContent = enhancedLoadLogContent;

        // Add event listeners for the pulled-log filters
        const showEmptyLogsCheckbox = document.getElementById('show-empty-logs');
        if (showEmptyLogsCheckbox) showEmptyLogsCheckbox.addEventListener('change', applySourceFilters);
        const dockerOnlyLogsCheckbox = document.getElementById('docker-only-logs');
        if (dockerOnlyLogsCheckbox) dockerOnlyLogsCheckbox.addEventListener('change', applySourceFilters);

        // expose key helpers for other scripts
        window.fetchApi = fetchApi;
        window.showToast = showToast;
        window.showDashboard = showDashboard;

        // Toggle Suricata Stats button based on whether Suricata is configured
        refreshSuricataConfiguredState();

        // Hosts sort/reset wiring
        if (hostsSortSelect) {
            // initial from storage
            hostsSortSelect.value = getHostsSortMode();
            hostsSortSelect.addEventListener('change', async () => {
                const mode = hostsSortSelect.value || 'manual';
                setHostsSortMode(mode);
                await populateHostCards();
            });
        }

        if (hostsResetOrderBtn) {
            hostsResetOrderBtn.addEventListener('click', async () => {
                setManualOrder([]);
                setHostsSortMode('manual');
                await populateHostCards();
                window.showToast('Host order reset', 'success');
            });
        }

        // --- INITIALIZATION ---
        populateHostCards();

}

document.addEventListener('DOMContentLoaded', init);
