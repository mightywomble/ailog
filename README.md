# Homelab Manager - Multi-Host Log Analysis Platform

A comprehensive, modern web application for viewing and analyzing system logs from `/var/log`, `journalctl` and **Docker containers** across both **local** and **remote** servers, with live Docker/Swarm monitoring. This advanced platform combines real-time log viewing, powerful search capabilities, AI-powered analysis, and proactive alerting in a sleek, responsive interface designed for developers and system administrators.

## 📋 Version History

| Date | Version | Major Changes | Status |
|------|---------|---------------|--------|
| 2026-10-29 | v3.1.1 | **Cache-proof releases.** Every stylesheet and module is linked with a version query string; HTML is served with Cache-Control no-store and static files must revalidate. Settings shows the running version in its footer, so a deployed build can be identified at a glance. | ✅ Complete |
| 2026-10-29 | v3.1.0 | **Interface (look and feel) as a fourth appearance axis.** Settings → Appearance now offers three layouts — **Classic** (the existing shell), **Glass** (bento cards, pill navigation, blurred translucent panels, ambient glow) and **Console** (dense instrument grid, accent-topped cards, uppercase micro-labels, tabular numerals). Colour themes, light/dark, density and motion all apply on top of every interface; the choice is stored in `ui.interface`, applied as `data-ui` before first paint, exposed as `?ui=glass`, and switchable from ⌘K | ✅ Complete |
| 2026-10-29 | v3.0.0 | **Audit phases 0–6 implemented.** Dead code removed and `ruff`/coverage CI added; security baseline (opt-in auth gate, loopback bind, DB-admin gate + integrity-checked restores, CSP/nosniff/HSTS headers, vendored Tailwind/Chart.js/marked/DOMPurify with SRI, WebSocket origin check, pinned SSH host keys); one SSH transport (`core/ssh.py`); `create_app()` factory plus `core/bootstrap.py`; every HTML sink escaped and `index.html` split into `templates/partials/` (1,542 → 737 lines) with the wizard JS extracted; and performance work (`/api/overview` aggregate with ETag/304, adaptive polling, bounded caches, SQLite WAL). Four real `ruff` bugs fixed on the way (undefined `emit`, `tf_name`, `_ssh_key_file_cache`, wizard `sessions_lock`) | ✅ Complete |
| 2026-10-29 | v2.19.1 | **SSH terminal can expand into a window.** An icon in the terminal header promotes it to a 92 vh dialog and a contract icon (or backdrop click) returns it to its slot. The same xterm instance is moved rather than re-created, so the session, scrollback and running commands are untouched | ✅ Complete |
| 2026-10-29 | v2.19.0 | **Renamed to Homelab Manager**, and the Overview is now three cards: **Fleet**, **Alerts** and **Recent reports**. The per-host Hosts card is gone — host browsing lives in the sidebar, the ⌘K palette and the Logs workspace, so the dashboard stays a fleet summary. Page titles, the SSH-config header, backup/import filenames and the Discord test message follow the new name | ✅ Complete |
| 2026-10-29 | v2.18.2 | Fix: the Fleet card reported **"all reachable"** next to a non-zero Offline count; it now says `N unreachable` (and still says nothing configured when the fleet is empty) | ✅ Complete |
| 2026-10-29 | v2.18.1 | Polish for the new Overview: the **Hosts card is capped at 372 px with internal scroll**, so a 16-host fleet no longer stretches the whole card row, and the sidebar drag-grip dots are visible again (`stroke-width` was computing to 1 px) | ✅ Complete |
| 2026-10-29 | v2.18.0 | **Interface rework (Option A): fleet-first pages + a host workspace**, with a ⌘K command palette and a card-based Overview grid. Adds a responsive shell (desktop sidebar → tablet icon rail → phone drawer + bottom tab bar + bottom-sheet dialogs), a three-layer theme system with **6 themes × dark/light**, and Settings → **Appearance** (theme, mode, density, motion). Charts follow the theme; legacy Tailwind utilities are retargeted in light mode instead of rewriting 1,500 lines of markup | ✅ Complete |
| 2026-10-29 | v2.17.0 | **Monitoring moved to a dashboard toolbar.** Monitoring is server-wide, not per host, so the button left the host toolbar and now sits in a new Quick access bar on the dashboard alongside **Add Devices** and **More** (which moved out of the global header, keeping its Ansible / SSH config / Rescan entries). The header keeps only Settings, Suricata Stats and the sudo chip. README now documents the three toolbars and which scope each control belongs to | ✅ Complete |
| 2026-10-29 | v2.16.2 | Fix: container network counters crashed the expanded card (`TypeError: int() ... not 'tuple'`) because the SSH collector stored the whole `NetIO` pair in `net_rx`; the pair is now split into rx/tx and the metrics collector coerces counters defensively | ✅ Complete |
| 2026-10-29 | v2.16.1 | Monitoring cards read Docker container counts from the same SSH round trip (`docker ps -a --format {{.State}}`) instead of a Docker discovery row, so the whale badge shows `running/total` and "engine not reachable" is accurate rather than stale | ✅ Complete |
| 2026-10-29 | v2.16.0 | **Monitoring is a live netdata-style page in a dialog.** The Monitoring button no longer opens the old host-monitor list (that UI, its overlay and the monitor editor are deleted); it loads `/metrics?embed=1` in the shared modal chrome. One card per server with CPU %, RAM %, disk % and network rates drawn as canvas sparklines, refreshed every 2s, with a rolling 3-minute window kept in the browser. Hosts with Docker installed get a whale badge, and clicking such a card expands it to the same datapoints per container (CPU, RAM, writable disk, net rx/tx) | ✅ Complete |
| 2026-10-29 | v2.15.1 | **Dialogs are tall again**: panels carry a `height` (92vh, 100vh on phones) instead of only a `max-height`, so they no longer collapse to the height of their content — the body and iframes fill the panel the way the Docker dialog always did. The three short forms (Add/Edit Host, Edit Monitor, alert rule editor) opt out with `.app-modal-fit` so they stay snug | ✅ Complete |
| 2026-10-29 | v2.15.0 | **Every dialog shares one chrome.** A single `.app-modal` stylesheet block plus `static/js/modals.js` now own all popups (AI analysis, server report, settings, host, log selection, monitor edit, monitoring wizard, Docker, Reports and the alert rule editor): same head/title/close/body markup, an open-order stack so **Escape** closes the topmost dialog, backdrop-click close, and iframes unloaded (`about:blank`) on close so their timers and EventSource stop. The **Reports** button next to a server now opens the report history in a modal instead of a new tab (`/reports?embed=1`, links still open in a new tab) | ✅ Complete |
| 2026-10-29 | v2.14.1 | **Docker monitoring opens in a modal** instead of navigating away: the Docker button now loads `/docker/<host>?embed=1` in a large iframe dialog with its own close button (no page-level Back link), so flipping between the logs view and the Docker dashboard no longer loses your place. The standalone `/docker/<host>` page still works for deep links | ✅ Complete |
| 2026-10-29 | v2.14.0 | **Severity filter for server reports**: analyse only Critical / Errors / Warnings (multi-select, or All for the classic behaviour). Filtering happens **on the host** — `journalctl --priority` where it is exact, one shared `grep -iE` everywhere else — and again authoritatively in the normaliser, so a busy host sends 70–99% fewer bytes and the model never sees INFO noise. The evidence pack states the filter so the model cannot read filtered-out lines as a healthy source | ✅ Complete |
| 2026-10-29 | v2.13.1 | **Threshold alerting** (`alerting/`) evaluated on the metrics the samplers already collect, with debounce, cooldown, transitions-only Discord delivery and an `/alerts` page; **report-to-report diffs** ("Since last report" panel) computed from stored JSON; **scheduled reports** (`Schedule.kind = 'report'`); fairer source caps (`MAX_SOURCES` 60 → 120, per-kind shares, journal units ranked by activity); first **pytest suite** (108 tests); `app.py` split (`app_schema.py`, `inventory/`) and `index.html` split into ES modules | ✅ Complete |
| 2026-10-28 | v2.13.0 | Docker monitoring grows up: a rolling **in-memory history** sampler so `/docker/<host_key>` charts survive a reload (plus a disk card), an **Apps** view that groups containers per stack/service across the cluster, a **Cluster** view with swarm-wide totals, per-node cards with sparklines and `docker system df`, all rendered as tabs on the existing Docker page | ✅ Complete |
| 2026-10-28 | v2.12.1 | Docs: server-report usage walkthrough with depth guidance, report tuning settings/env table, endpoint reference, report-specific sudoers entries, blueprint and report-pipeline architecture notes | ✅ Complete |
| 2026-10-28 | v2.12.0 | Report tuning: default model `openai/gpt-4o-mini`; **Executive Summary** and **How to Resolve** closing sections; a depth slider (Lite → Maximum) plus Auto; a sizing engine that measures the evidence pack and recommends depth, chunking and model; map-reduce chunking for packs too large for one request; "Check size & suggest" pre-flight that does not call the model | ✅ Complete |
| 2026-10-28 | v2.11.0 | Server-wide correlated log reports: **Analyse All Logs** collects every file / journald / container source on a host into a uniform time window, normalises lines into signature clusters, correlates sources statistically (lift, bursts, silence gaps, container state), sends one compact evidence pack to the model and stores a report at `/reports/<id>` with a history list | ✅ Complete |
| 2026-10-28 | v2.10.1 | AI analysis UX: live staged progress in the modal (preparing → contacting → analysing with elapsed clock → formatting) streamed from the new `/analyse/stream` SSE endpoint; results rendered as sanitised Markdown (marked + DOMPurify) in the AI and Suricata analyse modals | ✅ Complete |
| 2026-10-28 | v2.10.0 | Docker monitoring: host-wide Docker API discovery (unix socket over SSH / TCP 2375 / TLS 2376), standalone `/docker/<host_key>` page (live CPU/RAM/network charts, containers with size + image tag, swarm cluster/node drill-down); Pull Logs now lists per-container logs with a **Docker logs only** filter; faster connect feedback (proxy-safe SSE, indeterminate progress bar, elapsed clock); security hardening (log path traversal blocked, log output XSS-escaped, Docker SDK pinned) | ✅ Complete |
| 2026-06-24 | v2.9.17 | Hosts sidebar: sort by IP/name + manual drag reorder with grab handle + clearer drop target highlight; Rescan reliability: DB hosts without explicit ssh_key_id now fall back to default SSH key (matches SSH terminal/log pulls) | ✅ Complete |
| 2026-05-25 | v2.9.16 | AI provider persistence: load from database on page init (survives hard refresh/pod restart); OpenRouter + Ollama model search filtering (real-time substring match on model list) | ✅ Complete |
| 2026-05-25 | v2.9.15 | OpenRouter AI provider integration: API key test → model discovery → selection workflow; fixed /openrouter/config to allow saving key before model; UI auto-loads models after key validation | ✅ Complete |
| 2026-05-25 | v2.9.14 | UI polish: SSH tabs/footer layout + main-pane sizing consistency; Pull Logs async clobber fix; Monitoring/Wizard now opens as modal (no full-page redirect) | ✅ Complete |
| 2026-05-24 | v2.9.13 | Termix-style SSH terminal (WebSocket + Paramiko) in Logs view | ✅ Complete |
| 2026-05-23 | v2.9.12 | Added in-repo Helm chart copy and Kubernetes/Helm deployment docs | ✅ Complete |
| 2026-05-23 | v2.9.11 | SSH key encryption toggle + status; container adds cryptography + openssh-client; Helm adds Tailscale egress sidecar for tailnet SSH | ✅ Complete |
| 2026-04-29 | v2.9.10 | Monitoring: stop creating TCP/53 monitors; add UDP listen monitor (e.g. DNS/Pi-hole on 53/udp) via SSH ss checks | ✅ Complete |
| 2026-04-29 | v2.9.9 | Monitoring UX: wizard has Done button and clearer Docker visibility; adds Docker container running monitors; monitoring renders inline in main host panel | ✅ Complete |
| 2026-04-29 | v2.9.8 | Monitoring UX: Monitoring button now works with db-<id> hosts and redirects to Monitoring Wizard when host has no monitors; wizard supports preselect + auto-discover | ✅ Complete |
| 2026-04-29 | v2.9.7 | Add modular monitoring subsystem: monitoring wizard (SSH discovery + HTTP probe), per-host monitoring pages, persisted Docker inventory snapshots | ✅ Complete |
| 2026-04-28 | v2.9.6 | Fix SSH key persistence + encryption metadata (enc_version), improve SSH error surfacing, repair DB URL mismatch and rescan/system-info collection to use decrypted key materialization | ✅ Complete |
| 2026-04-24 | v2.9.5 | Host selection workflow: select host → host info → pull logs; Groups management in Settings (CRUD + list members); Host Info UI enhancements (full-pane view, action buttons w/icons, resource/service visuals, running/stopped service lists) | ✅ Complete |
| 2026-04-24 | v2.9.4 | SSH key management: encryption-at-rest + checksum integrity verification; Add Devices wizard stability fixes (SSE parsing, logging, Step 4→5 completion/close flow) | ✅ Complete |
| 2026-04-06 | v2.9.3 | Wizard UX fixes (step indicators, verify failure reasons, progress counts, duplicate/skip reporting) + Remote Hosts Edit modal restyled to termix theme | ✅ Complete |
| 2026-04-06 | v2.9.2 | Homepage: removed Top Noisy Servers + Recommendations and replaced with a large tech-themed logo panel matching the termix theme | ✅ Complete |
| 2026-04-06 | v2.9.1 | UI polish: collapsible Hosts sidebar, cleaner toolbar (More menu), Suricata button shown only when configured, wizard restyled to match termix theme | ✅ Complete |
| 2026-04-06 | v2.9.0 | Suricata integration: remote sensor config + incremental ingest, Suricata Stats dashboards (Overview/Endpoint Stats/Raw), persistence + selective restore | ✅ Complete |
| 2026-04-04 | v2.8.0 | Discord alert hostname resolution - use actual server hostname instead of db-<id> identifier | ✅ Complete |
| 2026-04-02 | v2.6.0 | Termix-style dark dashboard (default view), logs view on host click, global dark theme consistency pass | ✅ Complete |
| 2026-04-02 | v2.5.0 | Multi-schedule system (DB schedules), host-first selection per schedule, queued serial execution, schedule-scoped Run Now SSE + log picker | ✅ Complete |
| 2026-04-02 | v2.4.0 | DB-backed Settings + Backup/Selective Restore, AI Search prompt/keywords, Run Now SSE progress, Export improvements, Rescan/Netbird enhancements | ✅ Complete |
| 2026-01-27 | v2.3.0 | Settings Modal Redesign, Sidebar Navigation, Radio Button Models, Dark Theme, Bug Fixes | ✅ Complete |
| 2026-01-27 | v2.2.0 | Unified AI Provider Settings, DOM Element Fixes, Host Card Styling, Multi-Model Support | ✅ Complete |
| 2026-01-15 | v2.1.0 | Global Search, Multi-Host Enhancements, Progress Tracking | ✅ Complete |
| 2025-12-01 | v2.0.0 | Multi-Host Architecture, SSH Integration, Concurrent Processing | ✅ Complete |
| 2025-10-15 | v1.0.0 | Initial Release, Log Viewing, AI Analysis, Discord Alerts | ✅ Complete |

### ⚠️ Security Warning

This application is designed for use on a trusted, internal development network only. It runs commands with `sudo` on local and remote machines and provides access to potentially sensitive log data.

**DO NOT expose this application to the public internet.** Doing so would create a significant security risk. You must ensure that passwordless SSH key-based authentication is set up correctly and that the principle of least privilege is followed.

## 🚀 Key Features

### 🧭 **Navigation (fleet first, then host)**
There is one rule: **server-wide things live on pages, per-host things live in the host workspace.**

* **Overview (fleet)** — the landing page: three live cards — **Fleet** (online hosts, average
  CPU/RAM, Docker host and container counts, offline count), **Alerts** and **Recent reports**.
  They poll `/api/metrics/servers`, `/api/alerts/events` and `/api/reports` every 6 s and stop
  while the tab is hidden. Per-host browsing stays in the sidebar / ⌘K, not on the dashboard.
* **Logs (host workspace)** — pick a host in the sidebar (or a tile in the Overview) and the Logs
  view opens for it, with the host toolbar: SSH, Pull Logs, Host Info, Docker.
* **Back** returns to the fleet without reloading.
* **⌘K / Ctrl+K** jumps anywhere — views, actions, every host and every theme (see below).
* **Phone:** the sidebar becomes a slide-over drawer (hamburger), and a five-slot bottom tab bar
  (Overview, Logs, Hosts, Monitor, Alerts) carries the primary navigation.

### 🧰 **Toolbars — what lives where**
There are three toolbars and the split is deliberate: a control sits in the one whose scope it matches.

| Toolbar | Scope | Controls |
|---|---|---|
| **Header** (always visible) | This ailog instance | **Settings** (AI provider, Discord, hosts, themes), **Suricata Stats** (only when Suricata is configured), AI-provider badge, `SUDO MODE` chip |
| **Dashboard → Quick access** (dashboard only) | All servers at once | **Monitoring** (live metrics dialog), **Add Devices** (onboarding wizard), **More ▾** (Create Ansible Inventory, Create SSH Config, Rescan All) |
| **Host toolbar** (Logs view) | The selected host | **SSH**, **Pull Logs**, **Host Info**, **Docker** (only for hosts with a reachable engine) |

Monitoring and Add Devices are server-wide, so they moved out of the header/host bar onto the dashboard: you should not have to select a host to look at the whole fleet.

### 📊 **Unified Log Management**
* **Multi-Source Access:** View traditional syslog files from `/var/log`, systemd journal entries **and Docker container logs** in a unified interface
* **Cross-Platform Compatibility:** Works seamlessly across Linux distributions with systemd support
* **Automatic Decompression:** Handles `.gz` compressed log archives transparently
* **Docker logs in the Pull Logs list:** if the selected host runs containers, each container is listed as a log source (`docker` badge). Selecting one tails the last 500 lines with timestamps; on a Swarm manager AILog resolves the service label and uses `docker service logs`, so containers scheduled on other nodes still work.
* **List filters:** “Docker logs only” shows just container sources, “Show 0-byte logs” hides empty files — the two combine.

### 🌐 **Multi-Host Architecture**
* **Host Management Dashboard:** Intuitive interface for managing local and remote servers
* **Hosts sidebar ordering:** Sort hosts by **IP** or **Name**, or use **Manual order** (drag via grab handle). Ordering preferences are stored in browser localStorage.
* **SSH Connection Testing:** Built-in validation ensures proper SSH key setup and sudo permissions before adding hosts
* **Dynamic Host Switching:** Seamlessly switch between configured servers with real-time log loading
* **Connection Status Monitoring:** Visual indicators show host connectivity status
* **SSH Terminal:** Click the green **SSH** button to open an interactive terminal to the selected host (UI inspired by the Termix project on GitHub).
  An **expand icon** in the terminal header pops the same session into a window (92 vh, the shared dialog
  chrome) for full-screen work; the contract icon — or a click on the backdrop — puts it back in place.
  The xterm instance and the WebSocket session are reused, so scrollback and any running command survive
  the transition; leaving the Logs view or ending the session contracts it automatically.

### 📡 **Live Monitoring** (`metrics/`)

The **Monitoring** button on the dashboard's **Quick access** bar opens `/metrics?embed=1` in the shared dialog — the same chrome as Docker and Reports. There is no agent and no time-series database: one SSH command per host per poll, and the chart history lives in the browser.

| Endpoint | Purpose |
|---|---|
| `GET /metrics` | The page (`?embed=1` drops the Back link for the dialog) |
| `GET /api/metrics/servers` | Every host in parallel: CPU %, cores/load, RAM + swap, root-fs disk, network rx/tx rates, uptime, Docker presence and container counts. Cached ~1.5s so many views cost one collection round (`?refresh=1` bypasses it) |
| `GET /api/metrics/containers?host=<key>` | Containers on one host with the same datapoints plus mem used/limit and writable-layer size |

**How it collects.** A single marker-delimited command (`cat /proc/stat`, `/proc/meminfo`, `/proc/net/dev`, `df -kP /`, `/proc/loadavg`, `/proc/uptime`, `hostname`, `command -v docker`, `docker ps -a --format '{{.State}}'`) is run per host — `local` through a shell, everything else over SSH. CPU and network are counters, so the *first* sample of a host has no percentage and no rate: it seeds a per-host delta cache and the card shows `–` for one interval. `df -kP` rather than `-B1` because the app also runs on macOS in development.

Container numbers come from the existing Docker collectors (`dockermon.routes.host_snapshot`), so there is one definition of "what is this container doing"; their network counters are cumulative and are turned into bytes/second by a per-container delta cache.

**In the page.** Cards are a CSS grid, charts are hand-drawn `<canvas>` sparklines (no Chart.js, no CDN, no build step) with a 90-sample window — about 3 minutes at the 2s default. Polling pauses while the tab is hidden, stops entirely when the dialog closes (the iframe is blanked, which unloads the document), and the interval is selectable 2s/5s/10s. Hosts that have Docker installed get a whale badge with a `running/total` count; clicking such a card expands it full-width and lists its containers, each with CPU %, RAM % (bar), RAM used/limit, and a net rx/tx sparkline. Hosts where the Docker *binary* exists but the engine is not reachable still show the badge — the expansion then explains why it is empty.

### 🐳 **Docker Monitoring**
* **Automatic discovery:** every configured host is probed for a Docker Engine endpoint — unix socket over SSH (preferred, no exposed port needed), plain TCP `2375`, or TLS `2376`. Hosts without Docker are skipped cleanly.
* **Docker button:** appears in the Logs toolbar only for hosts with a reachable endpoint; opens `/docker/<host_key>?embed=1` in the shared dialog chrome (v2.14.1). The standalone page still works for deep links, and the **Close** button unloads the iframe so its charts and pollers stop.
* **Live charts:** CPU, RAM, network (rx/tx bytes per second) and root-filesystem usage, polled every 2 s. The cards **seed from a rolling in-memory history** (one sample every 15 s for 60 minutes by default) so a refresh no longer throws the graph away. History lives in process memory only — it is gone on restart by design, and nothing is written to the database.
* **Containers:** name, state/health, stack/service, writable + rootfs size, image reference and version tag, ports and mounts. Click a container to expand its details.
* **Swarm view:** cluster nodes with role/state, plus per-node drill-down that filters the container list.
* **Apps tab:** containers grouped by stack (compose project / swarm stack) → service → container, with per-app CPU/RAM totals, node spread, live sparklines and an expandable container list. Works on a plain host too — unstacked containers fall into one `(standalone)` group.
* **Cluster tab (swarm only):** swarm-wide CPU/RAM/disk/network totals and per-node cards with role, address, container count, utilisation bars, CPU sparklines and `docker system df` (images / containers / volumes / build cache, with reclaimable space). Nodes that cannot be reached are shown as offline with the SSH error instead of being silently dropped from the totals.
* **Cost model:** one combined SSH command per node (`docker ps --size` + `docker stats --no-stream` + `docker system df` + `/proc` + `df -B1 /`), fanned out across nodes in parallel and cached for 10 s, so a 5-node cluster refresh is ~6 round trips rather than ~24.
* **Refresh cadence:** background re-probe every `AILOG_DOCKER_REFRESH_SECONDS` (default `300`, minimum `30`) or on demand with the **Scan Docker** button in the hosts sidebar.
* **Docker on the target host:** the `docker` CLI must be installed; AILog runs `sudo -n docker …` and falls back to `docker …` (docker group membership also works).

### 🔍 **Advanced Search Capabilities**
* **Global Search:** Search across all logs from all configured hosts simultaneously
* **Scoped Search:** Target specific log files or journal units for precise results
* **Case-Sensitive Options:** Fine-tune search behavior with case sensitivity controls
* **Real-Time Results:** Instant search results with highlighted matches and line numbers
* **Cross-Host Discovery:** Find log entries across your entire infrastructure from a single search

### 🤖 **AI-Powered Analysis**
* **Provider Support:** OpenAI, Ollama, and OpenRouter
* **AI Search Settings:** Configurable analysis prompt + alert keyword/phrase list (DB-backed) used by manual analysis, Run Now, and scheduled runs
* **On-Demand Analysis:** Manual log analysis with provider-specific validation and status indicators
* **Live analysis progress:** the modal shows real stages — *preparing log excerpt → contacting provider → analysing (with a seconds clock) → formatting result* — streamed over SSE from `POST /analyse/stream`, so long model calls never look frozen
* **Markdown results:** analyses are rendered as formatted Markdown (headings, lists, tables, code blocks) and sanitised with DOMPurify, with a safe plain-text fallback if the renderer is unavailable
* **Scheduled Monitoring (Multi-Schedule):** Create multiple schedules, each with its own hosts, logs, and interval
* **Queued Execution:** Scheduled runs and Run Now requests are queued and execute serially (no skipping)
* **Run Now with Live Progress:** Server-Sent Events (SSE) streaming progress + heartbeat while the model is working
* **Smart Alerting:** Discord notifications when alert keywords are detected; otherwise a summary message can be sent

### 🧠 **Server-Wide Correlated Reports** (`serverreport/`)
* **Analyse All Logs:** a button in the Pull Logs toolbar runs one analysis across *every* log source on the selected host — log files, journald units and Docker container logs — and reports on the **server**, not on individual files
* **Time-aligned collection:** sources are bounded by wall-clock window (default 2 hours) rather than `tail -n 500`, so a busy nginx log and a quiet syslog cover the same slice of time and can legitimately be compared
* **Deterministic correlation first, model second:** lines become signature clusters (typically a 50–200× reduction), then a correlation engine computes cross-source co-occurrence **lift** over an independence baseline, per-source **bursts** against median/MAD, **silence gaps**, and container restarts / exit codes / OOM kills
* **One bounded model call:** the model receives a compact evidence pack (clusters + correlations + timeline + coverage), never the raw logs, so a 40-source run stays at one call and a predictable token budget
* **Stored reports:** every run is saved (`log_reports`) and viewable at `/reports/<id>` with verdict banner, severity counts, incident timeline, correlation table, source coverage and a `.md` download; `/reports` lists history by host
* **Model override:** per-run model selection (default `gpt-3.5-turbo`); the evidence pack is retained so a report can be re-summarised later without re-collecting
* **On request only:** nothing is posted to Discord automatically — the report page has an explicit **Send to Discord** button
* **Sized to fit:** a **depth slider** (Lite → Maximum) controls the evidence budget and output budget, with an **Auto** mode where the sizing engine measures the built evidence pack and picks the depth, decides whether chunking is needed, and warns when the chosen model's context is too small (offering a bigger one). The dialog can run a **Check size & suggest** pre-flight that collects and sizes the logs *without* calling the model, and the run that follows reuses that collection
* **Chunked for big hosts:** packs larger than the model can hold are split on section boundaries, summarised pass-by-pass (map) and merged into one reduced pack (reduce), with progress and the pass count shown
* **Closing sections:** every report ends with an **Executive Summary** (plain-English, non-specialist) and **How to Resolve** (numbered remediation steps marked immediate / soon / preventive, with verification)
* **Honest about blind spots:** truncation, source caps, failed sources and logging gaps are all stated in the report
* **Severity filter (new):** choose **Critical**, **Errors** and/or **Warnings** — or **All** for the
  unfiltered classic report. This is the cheapest way to shrink a run, and it is applied twice:
  - **on the host, before transfer** — `journalctl --priority=N` for journald (native, so the journal
    discards the lines itself; exact when the selection is a contiguous "N and above" set, with a
    `grep` added when it is not), and one `grep -iE` from the *same keyword tables the classifier
    uses* for log files and container logs. Filtered runs also scan a wider tail
    (`tail -n 12000 | grep | tail -n 4000`) so a sparse error is still found rather than the last
    4000 lines merely *containing* no errors
  - **authoritatively in the normaliser** — `classify_severity` is the real decision; anything the
    pre-filter let through is dropped, and a dropped line takes its stack trace with it
  Measured on a 63-source host over a 60-minute window: **1.05 MB → 296 KB** of transferred log text
  for errors+critical and **2.3 KB** for critical-only, with 8,046 events reduced to 229. Because
  INFO provides the correlation baseline, the evidence pack says so explicitly and tells the model
  that the absence of a severity is not evidence of health
* **Since last report:** each report page diffs itself against the previous report for the same host — verdict transition, event delta (with %), new / gone / louder signature clusters ("louder" = ≥3× and ≥20 more events), new / gone cross-source correlations and per-source coverage change. The diff is computed from the stored `clusters_json` / `severity_json` / `correlations_json` of both rows, so opening a report never re-collects the host
* **Scheduled reports:** a schedule can now be `kind = 'report'` instead of `'log'`. It stores its own window, depth, model and source scope, and each run produces one `/reports/<id>` per host in the schedule; the per-host outcome is recorded in `last_status` / `last_run_at` on the schedule

Tuning, in **Settings** (DB-backed) or as environment variables:

| Setting | Env var | Default | Purpose |
|---|---|---|---|
| `report.default_model` | – | `openai/gpt-4o-mini` | model used when no per-run override is given |
| `report.window_minutes` | – | `120` | default time window |
| `report.depth` | – | `0` (Auto) | `0` = size the run automatically, `1`-`5` = pinned depth |
| – | `AILOG_REPORT_MAX_SOURCES` | `120` | hard cap on sources per run (split fairly per kind, see below) |
| – | `AILOG_REPORT_MAX_BYTES` | `25165824` (24 MB) | total log text collected per run |
| – | `AILOG_REPORT_MAX_TOKENS` | `12000` | ceiling for the `fit_pack` trim path |
| – | `AILOG_REPORT_FILE_SCAN_CAP` | `12000` | lines tailed before the severity `grep` on log files |
| – | `AILOG_REPORT_JOURNAL_SCAN_CAP` | `20000` | journal lines fetched when a severity filter is active |
| – | `AILOG_REPORT_DOCKER_SCAN_CAP` | `20000` | container lines fetched when a severity filter is active |
| – | `AILOG_REPORT_SEVERITY_CONTEXT` | `3` | lines of context kept after a severity match (tracebacks) |
| – | `AILOG_DOCKER_REFRESH_SECONDS` | `300` | Docker endpoint re-discovery cadence |
| `docker.history_interval` | `AILOG_DOCKER_POLL_SECONDS` | `15` | seconds between history samples per Docker host |
| `docker.history_minutes` | `AILOG_DOCKER_HISTORY_MINUTES` | `60` | rolling history window kept in memory |
| – | `AILOG_DOCKER_SWARM_TTL` | `10` | seconds a swarm cluster view is cached |
| – | `AILOG_DOCKER_NODE_TIMEOUT` | `25` | SSH timeout per swarm node |

**Source caps are per kind, not first-come.** With a flat cap, one host with 200 files in
`/var/log` would consume the entire budget and no journald unit or container would ever be
collected. `collect.select_sources()` reserves `KIND_SHARES = {'file': 0.45, 'journal': 0.30,
'docker': 0.25}`, hands unused allowance to the kinds that need it, keeps discovery order
inside each kind, and ranks journald units by recent activity first (one `journalctl -o json`
round trip) so the busiest units are the ones that survive the cut. On db-11 the same request
(300 sources, cap 120) now collects 54 file / 36 journal / 30 docker instead of 120 / 0 / 0, and
the skip message states the cap, what was collected and what was left out.

Docker monitoring endpoints: `GET /docker/<host_key>`, `GET /api/docker/endpoints`,
`POST /api/docker/discover`, `GET /api/docker/hosts/<k>/{,stats,containers,nodes,history,swarm}`,
`GET /api/docker/hosts/<k>/history/stream` (SSE), `POST /api/docker/hosts/<k>/swarm/refresh`,
`POST /api/docker/history/clear`.

Endpoints: `POST /serverreport/stream` (SSE), `POST /serverreport/preflight`,
`GET /api/serverreport/defaults`, `GET /reports`, `GET /reports/<id>`,
`GET /reports/<id>/markdown`, `POST /reports/<id>/discord`, `GET /api/reports`,
`GET|DELETE /api/reports/<id>`.

### 🚨 **Threshold Alerts** (`alerting/`)

Alerting is evaluated on metrics that are *already being collected* — the Docker history
sampler's per-host series and the verdict of every server report — so there is no second
collection path to keep in sync.

* **Rules:** `name`, `metric`, `op`, `threshold`, `for_seconds`, `cooldown_seconds`, `severity`, `enabled`.
  Metrics: `cpu_percent`, `mem_percent`, `disk_percent`, `containers_running`, `node_offline`
  and `verdict_level` (healthy 0 / degraded 1 / failing 2, fed by report verdicts).
  Operators: `>`, `>=`, `<`, `<=`, `==`, `!=`, `at_least`. Five sensible rules are seeded on first boot.
* **Debounced state machine:** `ok → pending → firing → resolved`. A rule enters `pending` on the
  first breach and only fires once it has held for `for_seconds`; a recovery before that returns
  silently to `ok`. `cooldown_seconds` suppresses repeat notifications for the same rule/host.
* **Notifications only on transitions**, not on every sample. The sampler ticks every 15 s, so
  notifying per evaluation would be 240 identical Discord messages an hour. A resolution message
  is sent too (green embed) when a firing rule recovers.
* **Never breaks the sampler:** delivery is best-effort and every failure is caught, recorded on
  the event row (`notified`, `notify_error`) and logged — a broken webhook cannot stop metric
  collection.
* **State where it belongs:** the live state machine is in memory (a restart does not re-fire old
  alerts) while every transition is mirrored to `alert_events`, so history and "what is firing
  right now" are both queryable.
* **Page:** `/alerts` shows active alerts, the rule table with an inline editor, and recent events
  (30 s auto-refresh). API: `GET|POST /api/alerts/rules`, `PUT|DELETE /api/alerts/rules/<id>`,
  `GET /api/alerts/events`, `GET /api/alerts/state`, `POST /api/alerts/test`,
  `POST /api/alerts/evaluate`.

### 📈 **Real-Time Progress Tracking**
* **Instant connect feedback:** SSE responses for log discovery disable proxy buffering (`X-Accel-Buffering: no`) and send an immediate `: connected` heartbeat, so the first update lands in tens of milliseconds instead of after an nginx buffer flush
* **Indeterminate bar + spinner:** while no measurable progress exists the bar sweeps and a spinner is shown, switching to a normal percentage bar on the first event
* **Elapsed clock:** the label ticks seconds and escalates (“Initializing connection…” → “Waiting for host to respond…” → “Slow to respond - still trying…”), then tracks real progress (“Listing log files…”, “Found N log sources…”)

### 🎨 **Appearance: interface, themes, light/dark, density**
Appearance has two independent choices: **interface** (how the page is laid out) and **theme**
(what colours it uses). Any interface works with any theme, in dark or light.

#### Interfaces (`static/css/interfaces.css`)

Pick one in **Settings → Appearance → Interface**, or from ⌘K (`Interface: …`).

| Interface | Character |
|---|---|
| **Classic** | The default shell: sidebar, flat cards, quiet chrome. No overrides — this is the app's own CSS |
| **Glass** | Bento overview grid, floating pill header, pill controls, blurred translucent panels, ambient accent glow, large radii |
| **Console** | Dense instrument panel: 8 px radii, accent-topped cards with **uppercase micro-labels**, tabular numerals, faint blueprint grid, squared compact controls |

Only semantic tokens are used, so a theme change re-colours every interface. The axis is
`data-ui` on `<html>`, persisted as `ui.interface`, previewable with `?ui=console`, and it never
changes navigation or which controls exist.

#### Themes
Six theme families, each with a dark and a light variant. Pick one in **Settings → Appearance**
(or type `theme` in ⌘K); the **sun/moon button next to Settings** flips dark ↔ light instantly.

| Theme | Character |
|---|---|
| **Midnight** | The original ailog look — deep navy, violet accent |
| **Slate** | Neutral grey, low tint, blue accent |
| **Nord** | Cool arctic blues |
| **Solarized** | Designed as a light/dark pair, warm paper in light mode |
| **Terminal** | Green on black, phosphor accent |
| **High contrast** | Maximum legibility, hard borders, no tint |

How it works — three layers, and only the middle one may be used by components:

1. **Palettes** (`static/css/theme.css`) define raw colours per `[data-theme][data-mode]`.
2. **Semantic tokens** are the only names markup/CSS may reference: `--bg`, `--surface`,
   `--surface-2/3`, `--surface-sunken`, `--border`, `--border-strong`, `--text`, `--muted`,
   `--faint`, `--overlay`, `--accent`, `--accent-hover`, `--accent-soft`, `--on-accent`, `--ok`,
   `--warn`, `--bad`, `--info`, `--chart-1…6`, `--shadow-1/2`, `--focus`, `--radius`, `--radius-sm`,
   `--term-bg`, `--term-fg`, `--bg-glow-1/2`.
3. **Components** (`style.css`, `shell.css`, `ui.css`, `metrics.css`) style themselves from those
   tokens, so a new theme is ~20 lines instead of a search-and-replace across five files.
   **Interfaces** (`interfaces.css`) sit on top of components and only re-shape radii, spacing,
   surfaces and typography — never colours.

* **No flash:** every template has a tiny inline boot script in `<head>` that reads localStorage and
  sets `data-ui` / `data-theme` / `data-mode` / `data-density` / `data-motion` plus `color-scheme`
  before first paint; `static/js/theme.js` then owns all later changes and fires `themechange` events.
* **Persistence:** `ui.interface`, `ui.theme`, `ui.mode` (`dark` | `light` | `system`),
  `ui.density`, `ui.motion`.
  `system` follows `prefers-color-scheme` live.
* **Shareable previews:** `?ui=glass&theme=nord&mode=light&density=compact&motion=reduced` overrides the saved
  values for that page load (validated against the allowed lists).
* **Charts follow the theme:** `window.themeColors()` returns the semantic colours including a
  `series[]` array; the metrics sparklines read it at draw time and `docker.html` recolours its
  Chart.js instances on `themechange`.
* **Density & motion:** Comfortable/Compact changes radii and paddings; Reduced disables the
  shimmer/pulse animations and smooth scrolling (also honoured via `prefers-reduced-motion`).

### ⌘K **Command palette**
`⌘K` on macOS, `Ctrl+K` elsewhere (there is also a magnifier button in the header).

* Fuzzy subsequence search over **Views**, **Actions**, **Hosts** and **Appearance** (one entry per
  interface and per theme, plus toggle light/dark).
* ↑/↓ to move, Enter to run, Esc to dismiss; results are grouped and the platform-correct shortcut
  is shown in the footer and the header hint.
* Host entries go through the same `selectHost()` path as a sidebar click, so the palette, the
  Overview tiles and the sidebar can never disagree.

### 📱 **Responsive layout**
| Width | Shell |
|---|---|
| **≥1025 px** | Fixed 264 px sidebar beside the content; header shows labelled buttons |
| **641–1024 px** | Sidebar collapses to a **76 px icon rail** (host cards become monogram tiles with a status dot, full name in the tooltip); cards reflow to two columns |
| **≤640 px** | Sidebar becomes a **slide-over drawer** behind a backdrop, a **bottom tab bar** (5 slots, `env(safe-area-inset-bottom)`) carries navigation, dialogs become **bottom sheets**, tables scroll horizontally, touch targets are ≥40 px |

The shell is a flex column of `100dvh` with an internal scroll region, so the header and tab bar stay
put on mobile browsers with collapsing toolbars.

### 🪟 **Unified Modal Dialogues**
Every popup in the app is the same component, built from one stylesheet block and one small module — no framework, no build step.

| Piece | Where | What it does |
|---|---|---|
| `.app-modal` / `-panel` / `-head` / `-title` / `-close` / `-body` | `static/css/style.css` | Fixed backdrop, centred panel, size presets (`-sm` `-md` `-lg` `-xl`), header with a text Close button, scrollable body, full-screen on phones |
| `openAppModal()` / `closeAppModal()` | `static/js/modals.js` | Only owner of dialog state. Tracks an **open-order stack**, closes the topmost on `Escape`, closes on backdrop `mousedown`, wires every `[data-modal-close]` button, dispatches `appmodal:open` / `appmodal:close`, and blanks iframes on close |
| `openDockerModal()` / `openReportsModal()` | `static/js/iframe-modals.js` | Full-document dialogs (Docker dashboard, report history) loaded in an iframe with `?embed=1` so the embedded page drops its own Back link |
| `openModal()` / `closeModal()` | `static/js/app-core.js` | Thin wrappers so the older call sites (settings, host, log selection, AI analysis, server report, monitor edit) join the same stack |

Two details that matter:

* **Panels are 92vh tall by default** (`100vh` on phones), not just capped at `max-height`. A max-height alone lets a flex panel shrink to its content, which made the dialogs feel short and squat; the body and iframes now fill the panel. Short forms pass `.app-modal-fit` to stay content-sized.
* **`.app-modal` is `display:flex` and `.app-modal.hidden` is `display:none !important`.** Tailwind's `hidden` and `flex` are both display utilities, so toggling `flex` by hand made the outcome depend on stylesheet order. Only the `hidden` class is ever toggled now.
* **Closing an iframe dialog sets `src="about:blank"`.** That unloads the document, which tears down its Chart.js timers, `EventSource` connections and polling loops instead of leaving them running in an invisible frame.

Behaviour that applies to all of them: `Escape` closes only the topmost dialog, clicking the dimmed backdrop closes it, the Close button is always the same text button in the header, and every dialog is focus-moved on open so keyboard users land inside it.

**Adding a new dialog** — copy this shape, do not hand-roll classes:

```html
<div id="myModal" class="app-modal hidden">
  <div class="app-modal-panel app-modal-lg">      <!-- -sm | -md | -lg | -xl -->
    <div class="app-modal-head">
      <div class="app-modal-title">
        <svg ...></svg>
        <span>My dialog
          <span class="app-modal-sub">optional second line</span>
        </span>
      </div>
      <button type="button" class="app-modal-close" data-modal-close>Close</button>
    </div>
    <div class="app-modal-body app-modal-body-flush">…</div>
    <div class="app-modal-foot">…</div>            <!-- optional -->
  </div>
</div>
```

```js
openAppModal('myModal');    // or openAppModal(element)
closeAppModal('myModal');
```

`data-modal-close` on any element closes it, so no per-dialog click handler is needed. Use
`app-modal-fit` on the panel for a short form (it will otherwise be 92vh tall) and
`app-modal-body-flush` when the body is an iframe or a single scroll container that should
provide its own padding. Listen for `appmodal:close` if the dialog owns something that must be
torn down (an iframe, a poller, a chart).

### 💾 **Database Backup & Restore**
* **One-Click Backup Download:** Download the sqlite database bundle
* **Selective Restore:** Restore only selected categories (AI provider/key, Discord webhook, AI Search prompt/keywords, Hosts (replace all), legacy schedule interval/is_running)
  - Note: Full schedules (multi-schedule tables) are included in a full DB restore, but are not currently part of the selective restore toggle.

### 🔒 **Security & Privacy**
* **DB-Backed Credential Storage:** API keys/webhooks and settings are stored in the application database (plaintext, by choice) and persist across restarts
* **Backup Awareness:** Database backups include settings/secrets; keep backups protected
* **SSH Key Authentication:** Passwordless SSH access with proper key-based security
* **Granular Sudo Permissions:** Minimal required permissions for enhanced security
* **Network Isolation:** Designed for trusted internal networks only
* **Log output is rendered as text:** `/var/log` and container log contents are inserted with `textContent`, so a log line containing HTML/JS cannot execute in the browser
* **Path traversal blocked:** `/log/<file>` rejects absolute paths and any `..` segment, so the endpoint can only read below `/var/log`
* **Container identifiers validated:** `/api/docker/log/<container>` only accepts Docker-legal name characters (and is `shlex`-quoted) before reaching the remote shell
* **Authentication is opt-in, not absent:** `AILOG_AUTH_MODE` (default `none`) can be set to `proxy` (trust an upstream identity header) or `local` (HTTP Basic against env credentials). In `none` mode every endpoint still inherits the trusted-network model — keep the app off the public internet and restrict access at the proxy.
* **Security headers on every response:** CSP (`default-src 'self'`, `frame-ancestors 'self'`, `object-src 'none'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `X-Frame-Options: SAMEORIGIN` and a `Permissions-Policy` that disables camera/mic/geolocation. HSTS is sent when `AILOG_HSTS=1` or the request is already TLS.
* **Front-end assets are vendored, not remote:** Tailwind, Chart.js, marked and DOMPurify are served from `static/vendor/` with `integrity="sha384-…"` SRI hashes, so a compromised CDN cannot inject script into the UI.
* **Host keys are pinned:** SSH uses `StrictHostKeyChecking=accept-new` against a real `known_hosts` file (`AILOG_SSH_HOST_KEY_POLICY=strict|accept-new|off`), and paramiko loads/saves the same file. The exported `~/.ssh/config` no longer disables host checking.
* **Uploads are capped and validated:** `AILOG_MAX_UPLOAD_MB` (default 32) is enforced by Flask; a DB restore must pass an SQLite header check, `PRAGMA integrity_check`, and a required-tables check, and the live DB is copied to `<db>.pre-restore-<timestamp>` first.
* **Destructive endpoints are opt-in:** `/admin/db/*` returns 403 unless `AILOG_ALLOW_DB_ADMIN=1`, and requires authentication when an auth mode is enabled.
* **WebSocket origin checked:** `/ssh/websocket` rejects upgrades whose `Origin` is not the app's own host (cross-site WebSocket hijacking defence).
* **TLS Docker endpoints:** discovery accepts self-signed certificates (`verify=False` unless a CA is supplied). Only enable TLS endpoints you trust on the network path.
* **Dependency pinning:** the Docker SDK is pinned (`docker>=7.1.0,<8.0`) to avoid surprise breaking/major-version changes on image rebuild.
* **Server reports treat logs as hostile input:** log content is attacker-controlled, so the evidence pack is fenced with `<<<EVIDENCE … EVIDENCE>>>` and the system prompt states it is untrusted data that must never be followed as instructions (prompt-injection defence). Report Markdown is rendered through DOMPurify.
* **Model names validated:** per-run model overrides must match `[A-Za-z0-9][A-Za-z0-9._:/@-]*` (max 128 chars) before reaching a provider request.
* **Report fan-out is bounded:** all file paths still go through `_safe_log_path`, container names through the existing identifier regex, and each run is capped by source count, byte budget, worker count and a per-host lock.
* **No automatic Discord posts:** reports only reach Discord when a user presses **Send to Discord** on `/reports/<id>`.

#### Authentication and hardening environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `AILOG_AUTH_MODE` | `none` | `none`, `proxy` (header from your reverse proxy) or `local` (HTTP Basic) |
| `AILOG_AUTH_USER` / `AILOG_AUTH_PASSWORD` | `admin` / – | Credentials for `local` mode |
| `AILOG_AUTH_PASSWORD_HASH` | – | werkzeug hash; wins over the plaintext password |
| `AILOG_AUTH_PROXY_HEADER` | `X-Forwarded-User` | Header carrying the authenticated user in `proxy` mode |
| `AILOG_TRUSTED_PROXIES` | – | Comma-separated IPs/CIDRs allowed to set that header |
| `AILOG_ALLOW_DB_ADMIN` | `0` | Exposes `/admin/db/backup|restore*` |
| `AILOG_MAX_UPLOAD_MB` | `32` | Request body limit |
| `AILOG_HSTS` | `0` | Send `Strict-Transport-Security` |
| `AILOG_CSP` | built-in policy | Override the CSP, or `off` |
| `AILOG_BIND` / `AILOG_PORT` | `127.0.0.1` / `5001` | Dev listen address (the container sets `0.0.0.0`) |
| `AILOG_SSH_HOST_KEY_POLICY` | `accept-new` | `accept-new`, `strict` or `off` |
| `AILOG_KNOWN_HOSTS` | `/data/known_hosts` (fallback `~/.ssh/known_hosts`) | Pinned host keys |
| `AILOG_WS_ALLOW_NO_ORIGIN` | `0` | Accept websocket upgrades without an `Origin` header (only for old clients) |
| `AILOG_RUN_SCHEDULER` | `1` | Set `0` on web replicas so only one process owns APScheduler |

Health probe: `GET /healthz` is unauthenticated and reports the active auth mode.

### ⚡ Performance notes

* **One dashboard request:** the Overview polls `GET /api/overview`, which aggregates fleet metrics, alerts and recent reports server-side and answers `If-None-Match` with `304 Not Modified`. An idle dashboard therefore costs a header round trip. The per-subsystem endpoints remain for the pages that use them.
* **Adaptive polling:** the Overview backs off exponentially (to 60 s) on failures and resumes on visibility change; the Monitoring page slows its interval when many hosts are open and no card is expanded, and backs off when a poll fails.
* **Bounded caches:** host source listings (64), Suricata key paths (16) and report bundles (32) are size-capped, not just TTL-capped, so a long-lived process cannot grow without bound.
* **SQLite WAL:** `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=30s` and `foreign_keys=ON` are applied on connect, and the engine uses a 30 s connect timeout — samplers and requests no longer fail with `database is locked`.
* **Scheduler placement:** `AILOG_RUN_SCHEDULER=0` lets you run a dedicated worker so replicas do not each execute every schedule.

### 🔌 Tailscale egress for SSH (Kubernetes deployments)
If your target hosts are only reachable over Tailscale, the AILog pod needs tailnet routing to connect to `100.x` addresses. The Helm chart now supports an optional Tailscale **egress sidecar** (tun mode) that provides outbound tailnet/subnet access from the pod. See the Helm chart README for configuration details.


### 🕵️ Secret scanning (gitleaks)
This repository is protected by a server-side `gitleaks` hook that rejects pushes if it detects secrets (or secret-like strings) anywhere in the commit history.

Tips
- Do not commit backup copies of templates or scratch files (for example `*.backup` or `templates/*_old.html`).
- Avoid including real key material in the repo. If you need examples, use generic wording like “PEM format” rather than pasting literal key headers.
- Run a local scan before pushing:
  - `gitleaks detect --source . --redact`

If a push is rejected
- Run `gitleaks detect --source . --redact --verbose` to see which file/line is triggering.
- Remove the secret from the working tree. If the finding is in history, you must rewrite history (for example using `git filter-repo`) and then force-push the branch.

### 🟣 Suricata (Remote Sensor)
- Configure a Suricata sensor under **Settings → Suricata Data** (host/user/log directory/SSH key)
- Test SSH + sudo access and confirm the sensor can see `eve.json`, `fast.log`, `stats.log`, `suricata.log`
- Incremental ingest into SQLite with rotation/truncation handling
- **Suricata Stats** (toolbar button) dashboards:
  - **Suricata Stats:** KPIs, alerts-over-time, engine counters, category breakdown, top signatures
  - **Endpoint Data (Endpoint Stats):** total endpoints, alerts per endpoint, alerts per destination port, endpoint×port stacked chart, top sources to endpoints
  - **Raw Data:** tail and search raw logs + AI Analyse using a dedicated Suricata prompt
- Backup/restore: Suricata settings/prompt included in DB backup; selective restore includes a Suricata checkbox


## 🛠 Installation & Setup

### System Requirements
* **Operating System:** Ubuntu 20.04+ / Debian 11+ / CentOS 8+ (systemd-based distributions)
* **Python:** 3.8 or higher
* **Memory:** 512MB+ RAM (1GB+ recommended for multiple hosts)
* **Network:** Internal network access to monitored hosts
* **SSH:** Key-based authentication configured for remote hosts

### Prerequisites

* A Linux server to host the Homelab Manager application
* Non-root user with sudo privileges (we'll use `david` in examples - replace with your username)
* SSH key-based authentication configured for remote host access
* OpenAI API key for AI analysis features (optional but recommended)
* Discord webhook URL for notifications (optional)

### Kubernetes + Helm deployment
Helm is the **preferred and supported** way to deploy/upgrade AILog in Kubernetes. The repo ships a working chart in `helm/` and that should be treated as the source of truth.

#### Kubeconfig Setup
Before deploying with Helm, ensure your kubeconfig points at the target cluster:

```bash
# Export your kubeconfig (required for all helm commands)
export KUBECONFIG=~/.kube/config

# Verify you're connected to the correct cluster
kubectl config current-context
kubectl cluster-info
```

**IMPORTANT:** Without setting `KUBECONFIG`, the `helm` command will not be able to reach your Kubernetes cluster and the deployment will hang or fail silently.

#### Build + push the Docker image
The Helm chart deploys an image from a registry. Typical workflow is:

```bash
# dev image tag (for a dev namespace)
docker build -t mightywomble/ailog:dev -f docker/Dockerfile .
docker push mightywomble/ailog:dev

# production-ish tag (example)
docker build -t mightywomble/ailog:ailog -f docker/Dockerfile .
docker push mightywomble/ailog:ailog
```

#### Helm chart location
The working chart is included in this repo at `helm/`.

#### Deploy/upgrade (preferred)
```bash
helm upgrade --install ailog ./helm -n ailog
```

#### Deploy with explicit image overrides
```bash
helm upgrade --install ailog ./helm -n ailog \
  --set image.repository=mightywomble/ailog \
  --set image.tag=ailog
```

#### Deploy to a dev namespace
To run a separate dev instance, use a unique namespace and Tailscale hostname:
```bash
helm upgrade --install ailog-dev ./helm -n ailog-dev --create-namespace \
  --set tailscale.hostname=ailog-dev \
  --set image.repository=mightywomble/ailog \
  --set image.tag=dev
```

#### Values files
The chart uses `values.yaml` for defaults. You can override settings by:
- Editing `helm/values.yaml`, or
- Passing `-f` with your own values file, or
- Using `--set` flags for one-off changes.

Common overrides:
- `image.repository`, `image.tag`, `image.pullPolicy`
- `env.databaseUrl`
- `tailscale.enabled` (ingress)
- `tailscale.egress.enabled` / `tailscale.egress.mode` (egress sidecar)

Example:
```bash
helm upgrade --install ailog ./helm -n ailog \
  --set tailscale.enabled=true \
  --set tailscale.egress.enabled=true \
  --set tailscale.egress.mode=tun \
  --set tailscale.egress.acceptRoutes=false
```

#### Optional: kubectl-based rollout procedure (not the primary method)
If you deployed via Helm and just need to force a restart (for example after pushing a mutable tag like `:dev`), you can do:

```bash
# restart pods for the deployment
kubectl -n ailog rollout restart deploy/ailog

# watch the rollout
kubectl -n ailog rollout status deploy/ailog --timeout=300s

# see what is running
kubectl -n ailog get pods -o wide
```

##### Optional workaround: PVC Multi-Attach (ReadWriteOnce)
If the rollout hangs with errors like **Multi-Attach** (RWO volume still attached to the old pod), the quickest fix is usually:

```bash
kubectl -n ailog scale deploy/ailog --replicas=0

# wait for the old pod to terminate so the PVC detaches
kubectl -n ailog get pods

kubectl -n ailog scale deploy/ailog --replicas=1
kubectl -n ailog rollout status deploy/ailog --timeout=300s
```

#### Step 1: Install System Dependencies

Update your package list and install Python, pip, and the virtual environment module.
```bash
sudo apt update
sudo apt install python3-pip python3.12-venv -y
```

#### Step 2: Set Up Project Directory and Clone Repo

Create a directory for the application and clone the project repository into it.
```bash
mkdir -p ~/code
cd ~/code
git clone [https://github.com/your-username/your-repo-name.git](https://github.com/your-username/your-repo-name.git)
cd your-repo-name
```

#### Step 3: Create Python Virtual Environment & Install Requirements

It's best practice to run a Python application in a virtual environment.
```bash
python3 -m venv venv
source venv/bin/activate
```
The project includes a `requirements.txt` file with all necessary dependencies:

**requirements.txt**
```
Flask==3.0.0
Werkzeug==3.0.1
openai==1.3.7
requests==2.31.0
APScheduler==3.10.4
SQLAlchemy==2.0.23
Flask-SQLAlchemy==3.1.1
cryptography==42.0.8
# Note: openai==1.3.7 requires httpx<0.28 (pinned in the deployed venv)
```

Install the dependencies:
```bash
pip install -r requirements.txt
```

#### Step 4: Configure Passwordless `sudo` Access

For the application to read logs, the user running it needs passwordless `sudo` access **for the specific commands required**.

**This** configuration must be applied to every machine **the Log Viewer will access (including `localhost` and all remote servers).**

1.  On each server, open the sudoers file for editing using `visudo`. This is the safest way to edit this file.

    ```bash
    sudo visudo
    ```

2.  Scroll to the bottom of the file and add the following line. Remember to replace `david` with the username that will be used for SSH/local access on that specific machine.

    ```
    # Allow the 'david' user to run specific log-reading commands without a password
    david ALL=(ALL) NOPASSWD: /usr/bin/ls -p /var/log, /usr/bin/stat -c %s %Y /var/log/*, /usr/bin/tail -n 500 /var/log/*, /usr/bin/zcat /var/log/*.gz, /usr/bin/journalctl --field _SYSTEMD_UNIT, /usr/bin/journalctl -u * -n 500 --no-pager
    ```

    For the Docker monitoring/container-log features (optional, only on hosts that run Docker), also allow the read-only Docker commands — or add the user to the `docker` group instead:

    ```
    david ALL=(ALL) NOPASSWD: /usr/bin/docker version --format *, /usr/bin/docker info --format *, /usr/bin/docker ps -a --no-trunc --size --format *, /usr/bin/docker stats --no-stream --no-trunc --format *, /usr/bin/docker node ls --format *, /usr/bin/docker node inspect *, /usr/bin/docker system df --format *, /usr/bin/docker inspect *, /usr/bin/docker logs --tail 500 *, /usr/bin/docker service logs --tail 500 *, /usr/bin/docker image inspect *
    ```

    `docker node inspect` and `docker system df` are what the Docker page's **Cluster** tab uses to
    find each node's address and to report per-node disk usage. `df -B1 /` is read without sudo.

    **Server reports** (Analyse All Logs) need a few wider read-only commands than the log viewer
    uses, because it reads a time window rather than the last 500 lines:

    ```
    david ALL=(ALL) NOPASSWD: /usr/bin/find /var/log -maxdepth 1 -type f -printf *, /usr/bin/tail -n 4000 /var/log/*, /usr/bin/journalctl -u * --since * -n 5000 --no-pager -o short-iso, /usr/bin/systemctl list-units --type=service --all --no-pager --no-legend --plain, /usr/bin/docker logs --since * --timestamps --tail 5000 *, /usr/bin/docker service logs --since * --timestamps --tail 5000 *
    ```

    Without these the report still runs, but affected sources are skipped and listed under
    "collection errors" / "sources with no output" on the report page.

3.  Save and exit the editor (`Ctrl+X`, then `Y`, then `Enter`).

#### Step 5: Set Up the Systemd Service

Create a `systemd` service on the main Log Viewer server to ensure the application runs automatically on boot.

1.  Create a new service file:

    ```bash
    sudo nano /etc/systemd/system/ailog.service
    ```

2.  Paste the following configuration into the file. Crucially, replace `david` with your username and `your-repo-name` with your project's directory name.

    ```ini
    [Unit]
    Description=Flask Log Viewer Application
    After=network.target

    [Service]
    User=david
    Group=www-data
    WorkingDirectory=/home/david/code/your-repo-name
    # Use 'debug=False' for production stability with the scheduler
    ExecStart=/home/david/code/your-repo-name/venv/bin/python3 /home/david/code/your-repo-name/app.py
    Restart=always
    # Persist DB outside the repo (recommended)
    Environment=DATABASE_URL=sqlite:////var/lib/ailog/ailog.db

    [Install]
    WantedBy=multi-user.target
    ```

3.  Save and close the file.

#### Step 6: Start and Enable the Service

Reload the `systemd` daemon, then start and enable the service.
```bash
sudo systemctl daemon-reload
sudo systemctl start ailog
sudo systemctl enable ailog
```

#### Step 7: Verify the Service is Running

Check the status of the service to ensure it's active.
```bash
sudo systemctl status ailog
```
You should see output indicating that the service is `active (running)`.

### Docker Swarm deployment (homelab)

AILog also runs on the homelab Docker Swarm (manager: swarm1) via the
[homelab_docker_build](https://git.safehomelan.com/david/homelab_docker_build) +
[homelab_docker_deploy](https://git.safehomelan.com/david/homelab_docker_deploy)
pipelines: the published image `docker.io/mightywomble/ailog:latest` is mirrored
into the private zot registry (`zot.safehomelan.com/ailog:latest`) and deployed
by the `stacks/ailog/stack.yml` stack file.

- **URL:** `http://<any swarm node LAN or Tailscale IP>:5001` (swarm routing
  mesh), e.g. `http://100.79.189.118:5001`
- **Login:** none — the app is unauthenticated by design; trusted internal
  network only (see the security warning above)
- **Data:** the SQLite db persists on the shared NFS
  (`/opt/docker/data/ailog` → `/var/lib/ailog`) so the service can reschedule
  to any node; `DATABASE_URL=sqlite:////var/lib/ailog/ailog.db`
- SSH keys for monitored hosts are uploaded in the app UI and stored in its db;
  outbound SSH to LAN/tailnet hosts works via node networking

**Current production image** (as of 2026-10-29): `zot.safehomelan.com/ailog:v2.15.1`
(`:latest` points at the same manifest), digest
`sha256:c0c8a5a5bb691b36dd74b10c16b0521bc72941ac8c267199f71da2c68df69cd2`, running as
`ailog_ailog.1` on `swarm-worker1`. Redeploy after a push with:

```bash
docker service update --with-registry-auth --force ailog_ailog
```

Build the image with `--provenance=false --sbom=false`, otherwise BuildKit emits a manifest
list and the digest running in the swarm will not match the one you tagged:

```bash
docker build --provenance=false --sbom=false -f docker/Dockerfile \
  -t zot.safehomelan.com/ailog:v2.15.1 -t zot.safehomelan.com/ailog:latest .
```

Plain Docker host equivalent:

```bash
docker run -d --name ailog -p 5001:5001 \
  -v ailog-data:/var/lib/ailog \
  -e DATABASE_URL=sqlite:////var/lib/ailog/ailog.db \
  mightywomble/ailog:latest
```

## 🧭 Device Onboarding Wizard & Host Info

### Device Onboarding Wizard (Add Devices)

The **Add Devices** wizard lets you onboard one or more remote Linux hosts in a few guided steps. It will:

- Validate SSH connectivity with your chosen user + key
- Collect system information (OS, host name, RAM, disk, CPU, IPs)
- Enumerate systemd services
- Store everything in the database and expose hosts in the main UI

#### Requirements

- Passwordless sudo for the SSH user on the target hosts for commands used to read logs and systemd state.
- SSH key-based login from the Homelab Manager host to the remote hosts.

#### Wizard Stages

1. **Device entry**
   - Click the green **Add Devices** button on the dashboard's **Quick access** bar.
   - Paste one or more hostnames or IPs (one per line).
   - Enter the SSH username you want the app to use (for example `david`).
   - Either:
     - Upload a PRIVATE SSH key file, or
     - Select a previously saved key, or
     - Paste key content.

2. **Verify SSH connectivity**
   - The app attempts SSH connections to each host using the provided user/key.
   - Status icons:
     - **✓** – connection successful
     - **⚠** – authentication or sudo warning
     - **✗** – connection failed
   - Only successfully validated hosts continue to collection.

3. **Collect system information**
   - For each validated host the app collects:
     - OS version
     - Hostname
     - RAM total / used
     - Disk total / used
     - CPU type and core count
     - Main IP and Netbird IP (if available)
     - Full list of systemd services and running state
   - This data is stored in the `Host`, `SystemInfo` and `Service` tables in the database.

4. **Add devices**
   - The collected data is written to the database.
   - New hosts appear in the **Hosts** sidebar on the left.

### Hosts Sidebar: Info vs Logs

The **Hosts** column on the left shows all available hosts (local + wizard onboarded):

Ordering controls:
- **Sort:** Manual / IP (asc/desc) / Name (A–Z / Z–A)
- **Manual order:** drag-and-drop hosts using the grab handle (Localhost is pinned to the top)

Each host card shows:

- Friendly name
- Short description
- `user@host` line (truncated with full value on hover)
- A green connection indicator
- Two action buttons:
  - **Info** (blue circle icon) – open the host information card
  - **Logs** (document icon) – load logs for that host (existing behaviour)

#### Host Info card

- Click the **Info** button for a wizard-onboarded host (labelled *Remote*).
- The app calls `GET /hosts/db/<id>/info` and displays:
  - OS version and host name
  - RAM and disk usage (GB)
  - CPU type and cores
  - Main IP and Netbird IP
  - Service counts (total, running, stopped)
- Click **Rescan** to refresh system info + service snapshot.
  - Note: for database-backed hosts created by import/wizard that do not have an explicit `ssh_key_id`, the rescan path falls back to the most recently added SSH key (same behavior as SSH terminal/log pulls).
- Local or non-database hosts show a basic `user@host` line and a note that detailed info is only available for wizard-managed hosts.

## 📖 Usage Guide

### Getting Started

Access the application at: `http://<your-server-ip>:5001`

The interface features a clean, modern design with:
- **Host sidebar** for server selection
- **Log list panel** showing available logs
- **Content viewer** for log analysis
- **Global search bar** for cross-host searches

### 🔧 Initial Setup

1. **Configure AI Provider**:
   - Click the **Settings** ⚙️ icon in the header
   - Navigate to **AI Provider** section (default view)
   - Select your provider:
     - **OpenAI**: Enter your API key and click **Test**
     - **Ollama**: Enter API URL, test connection, get models, select model
     - **OpenRouter**: Enter your API key and click **Test**, then click **Get Models** to load available models from OpenRouter. Select a model via radio button, then click **Save** to persist both key and model.
   - Provider configuration is saved automatically when tested

2. **Configure Notifications** (Optional):
   - In Settings → **Notifications**
   - Enter your **Discord Webhook URL**
   - Click **Test** to verify the connection

3. **Add Remote Hosts**:
   - In Settings → **Remote Hosts** → **Add New**
   - Fill in host details:
     - **Friendly Name**: "Production Server", "Database Host", etc.
     - **IP Address**: Server IP or hostname
     - **SSH User**: Username for SSH access
     - **Description**: Optional host description
   - Click **Test Connection** to verify SSH and sudo access
   - On success (green indicator), click **Save Host**

4. **Close Settings**:
   - Click **Save & Close** to return to the main interface

### 🔍 Search Functionality

#### Global Search
1. Enter search terms in the top search bar
2. Select search scope:
   - **All logs**: Search across all hosts and log files
   - **Selected log only**: Search within currently viewed log
3. Toggle **Case sensitive** if needed
4. Click **Search** or press Enter

#### Search Features
- **Cross-host results**: Find logs from any configured server
- **Highlighted matches**: Search terms highlighted in results
- **Line numbers**: Exact line location for each match
- **Quick navigation**: Click results to jump to specific logs
- **Failed host handling**: Clear indicators for unreachable servers

### 📊 Log Management

#### Viewing Logs
1. **Select Host**: Choose from the host sidebar (localhost always available)
2. **Browse Logs**: Real-time loading with progress indicators
3. **View Content**: Click any log file or journal unit
4. **AI Analysis**: Use **AI Analyse** button for automated insights

#### Log Types
- **📄 File logs**: Traditional syslog files from `/var/log`
- **🔧 Journal entries**: systemd journal units via `journalctl`
- **📦 Compressed logs**: Automatic `.gz` decompression

#### Docker Page (Overview / Apps / Cluster)
The **Docker** button in the host toolbar opens `/docker/<host_key>` (in the dialog, or as a
standalone page) for hosts with a reachable Docker endpoint. The page has three tabs:

| Tab | Shows | Use it for |
|---|---|---|
| **Overview** | CPU / RAM / Network / Disk cards seeded from the history window, the container list, swarm node chips | "is this host busy right now, and how has the last hour looked?" |
| **Apps** | Containers grouped per stack (compose project or swarm stack) → service → container, with CPU/RAM totals, node spread and sparklines | "how much is the *media* stack using, and where is it running?" |
| **Cluster** | Swarm-wide totals, per-node cards with utilisation bars and CPU sparklines, and a `docker system df` table per node | "which node is the hot one, and what is eating disk?" |

Notes:

- The **Cluster** tab only appears when the selected host is a swarm manager. The **Apps** tab
  works everywhere; containers without a stack label are grouped into one `(standalone)` entry.
- Overview charts start from the server's rolling history (one sample every 15 s, 60 minutes by
  default) and then extend live every 2 s, so reloading the page does not blank the graph. App and
  node sparklines accumulate per cluster refresh (every 10 s while a tab showing them is open).
- History is **in-process only**. It is lost on restart and nothing is written to the database —
  if you need something that survives a restart, use **Analyse All Logs** (a report is stored).
- Tune it with `docker.history_interval` / `AILOG_DOCKER_POLL_SECONDS` and
  `docker.history_minutes` / `AILOG_DOCKER_HISTORY_MINUTES`; `POST /api/docker/history/clear`
  drops the buffers.
- On a large swarm, opening the Cluster tab costs one SSH round trip per node (parallel, cached
  10 s). A node that cannot be reached stays in the list marked **offline** with its error and is
  excluded from the cluster totals, so the summary never pretends a dead node is idle.

### 🤖 AI Analysis & Monitoring

#### Manual Analysis
1. Load any log file or journal unit
2. Click **AI Analyse** (requires OpenAI API key)
3. View detailed analysis in popup modal
4. Automatic Discord alerts for detected issues

#### Server Reports (Analyse All Logs)
Reports answer "what happened on this server?" instead of "what does this file say?".

1. Select a host in the sidebar, then click **Pull Logs**
2. In the log-list toolbar click **Analyse All Logs** (only shown when an AI provider is configured)
3. Choose a **time window** (default 2 hours) and which source types to include — log files,
   journald units, Docker container logs, optionally stopped containers
4. Optional: click **Check size & suggest** to size the run *without* calling the model. It
   collects the logs, reports events/clusters/token estimates per depth level, and recommends a
   depth and model. Pressing **Start analysis** afterwards reuses that collection
5. Set **Report size / depth** — leave **Auto** on, or drag the slider from *Lite* to *Maximum*
6. Press **Start analysis** and watch the stepper: *preparing → collecting → normalising →
   correlating → asking the model → saving*
7. The report opens at `/reports/<id>`; **Reports** next to the log list opens the history dialog

Choosing a depth:

| Depth | Evidence tokens (db-11, 2h) | Use when |
|---|---|---|
| Lite | ~1.7k | quick "is anything on fire?" check |
| Standard | ~4.2k | routine check |
| Detailed | ~6.5k | suspected issue, want the timeline |
| Deep | ~13.4k | investigating a specific incident |
| Maximum | ~22.9k | post-incident write-up |

A report contains a verdict (healthy / degraded / failing), incident timeline, ranked root-cause
candidates, the correlation table, subsystem health, what was checked and found clean, ordered
recommended actions, and two closing sections: an **Executive Summary** for non-specialists and
**How to Resolve** with commands and verification steps.

Reports state their own limits: if a source cap was hit, the evidence pack was trimmed, a source
failed, or the model stopped before finishing a section, the report page says so.

#### Scheduled Monitoring
1. **Settings** → **Select Logs for Schedule...**
2. **Cross-host selection**: Choose logs from multiple servers
3. **Set interval**: Configure analysis frequency (hours)
4. **Start monitoring**: Enable automated analysis
5. **Run Now**: Trigger immediate analysis of all monitored logs

### 📈 Advanced Features

#### Multi-Host Operations
- **Concurrent processing**: Parallel operations across multiple hosts
- **Retry mechanisms**: Automatic retry for failed connections
- **Progress tracking**: Real-time status for all operations
- **Error recovery**: Graceful handling of network issues

#### Performance Optimization
- **Streaming data**: Server-Sent Events for real-time updates
- **Caching**: Intelligent caching of host data
- **Timeout handling**: Configurable timeouts for reliability
- **Resource management**: Efficient memory usage for large logs

### 🚨 Troubleshooting

#### Common Issues
1. **Host connection failures**:
   - Verify SSH key authentication
   - Check sudo permissions (see sudoers configuration)
   - Ensure network connectivity

2. **Search not working**:
   - Check host connectivity in sidebar
   - Verify log file permissions
   - Look for timeout errors in browser console

3. **AI analysis errors**:
   - Validate OpenAI API key in Settings
   - Check API quota and billing
   - Ensure log content is not empty

#### Debug Information
The application provides detailed startup logs showing:
- Number of configured hosts loaded
- Host connection details
- Scheduler status and configuration
- Service startup confirmation

## 🏗️ Technical Architecture

### Backend (Flask)
- **Framework**: Flask with APScheduler for background tasks
- **APIs**: RESTful endpoints for log access, search, and host management
- **Streaming**: Server-Sent Events (SSE) for real-time progress updates
- **Concurrency**: ThreadPoolExecutor for parallel host operations
- **Security**: SSH key-based authentication with minimal sudo permissions
- **Blueprints** (modular bolt-ons registered in `app.py`):
  - `monitoring/` – host monitors, checks and alerting
  - `dockermon/` – Docker endpoint discovery, live stats, swarm view
  - `serverreport/` – server-wide correlated reports:
    `collect` → `normalize` → `correlate` → `pack` → `sizing` → `llm` → `routes`,
    plus `diff.py` (report-to-report comparison from stored JSON) and `severity.py`
    (severity selection: the shared keyword tables, journal priority mapping and grep pattern)
  - `alerting/` – threshold rules, evaluation state machine, `alert_events`, Discord delivery
  - `inventory/` – groups and tags, Ansible/SSH-config exports, SQLite backup and restore
    (split out of `app.py` so the core module only holds logs, search, AI, schedules and hosts)
- **Schema:** `database.py` holds the models and `db.create_all()` adds new *tables*; there is no
  Alembic, so additive **columns** on existing tables go through `app_schema.add_missing_columns()`,
  the single place that knows the `ALTER TABLE` list (`suricata_*`, `ssh_keys`, `log_reports`,
  `schedules`). Two copy-pasted column helpers used to exist; both now delegate to it.

### Frontend (Vanilla JavaScript, no build step)
- **UI Framework**: Tailwind CSS for responsive design
- **Real-time Updates**: EventSource API for SSE communication
- **State Management**: Local storage for credentials and preferences
- **Progressive Enhancement**: Graceful degradation for network issues
- **ES modules:** `templates/index.html` is markup only (≈1,400 lines) and loads a single entry
  point, `<script type="module" src="/static/js/main.js">`. `main.js` imports the feature modules
  in the same order the old inline `<script>` blocks ran, so `DOMContentLoaded` listeners register
  in the same relative order:
  - `boot.js` – `window.__appReady`, xterm readiness helper
  - `modals.js` – the only owner of dialog state (`openAppModal` / `closeAppModal`, Escape stack,
    backdrop close, `appmodal:*` events); imported early because everything else calls it
  - `groups.js` – group settings UI
  - `app-core.js` – the main UI closure (hosts, logs, search, AI modals, schedules); imports
    `suricata.js` and `sshkeys.js`
  - `toolbar.js`, `monitoring-wizard.js`, `wizard-fallback.js`
  - `iframe-modals.js` – the Docker and Reports dialogs (iframe-backed full documents)
  - `shell.js` – mobile drawer, bottom tab bar and view/aria-current syncing
  - `command-palette.js` – the ⌘K palette (views, actions, hosts, themes)
  - `overview.js` – the dashboard cards (fleet, hosts, alerts, reports, 6 s polling)
  - `theme.js` is loaded directly by every template (it must run before first paint) and owns the
    four `data-*` attributes, localStorage, the Appearance panel and `themeColors()`
  - stylesheets, in order: `style.css` (base + shared dialogs), `theme.css` (palettes + tokens),
    `shell.css` (responsive shell), `ui.css` (palette, appearance, overview cards), plus
    `metrics.css` for the monitoring page
  - per-page modules: `alerts.js` (loaded by `alerts.html`)
  Everything the markup uses from `onclick` handlers stays on `window`. No bundler, no transpiler —
  the files are served as-is, which keeps deployment identical to before.

### Data Flow
1. **Host Configuration**: JSON-based host storage with validation
2. **Log Discovery**: Parallel scanning across configured hosts
3. **Search Processing**: Distributed grep operations with result aggregation
4. **AI Analysis**: OpenAI API integration with Discord webhook notifications
5. **Scheduling**: APScheduler for automated monitoring tasks
6. **Server Reports**: per-host collection is bounded by a wall-clock window, lines are reduced
   to signature clusters, clusters are correlated across sources (co-occurrence lift, bursts,
   silence gaps, container state), the result is rendered as a compact evidence pack, sized
   against the model's context, chunked if necessary, and stored as a `log_reports` row

### Report Pipeline (detail)
1. **Collect** (`serverreport/collect.py`) – one `find -printf` round trip for file discovery,
   `journalctl --since`, `docker logs --since` / `service logs --since`, per-source timeouts,
   source/byte/worker caps, one run per host at a time
2. **Normalise** (`normalize.py`) – timestamp parsing (RFC3339, syslog with year rollover,
   journal short-iso, bracketed), multi-line stack-trace joining, severity tiers, signature
   clustering (volatile values replaced) which typically shrinks volume by 50-200x
3. **Correlate** (`correlate.py`) – 10s buckets, lift vs an independence baseline, median lag,
   median/MAD bursts, silence/early-stop gaps, container state
4. **Pack** (`pack.py`) – plain-text evidence pack; `PACK_LIMITS` scales with depth, section
   boundaries are the split points when chunking
5. **Size** (`sizing.py`) – recommends depth, chunk count and model from the pack, with model
   context awareness
6. **Model** (`llm.py`) – fenced untrusted evidence, required sections, one call (or
   map/reduce passes), verdict parsed
7. **Store** (`routes.py`) – `log_reports` row; page renders through marked + DOMPurify

## 📝 Recent Updates

### v3.1.0 - Interfaces: Classic, Glass and Console
- 🧩 **A new appearance axis, independent of colour.** Settings → Appearance → **Interface** offers three
  layouts; themes, light/dark, density and motion apply on top of all of them
- 🫧 **Glass** — bento overview (fleet wide, reports across the bottom), floating pill header, pill buttons
  and search, blurred translucent panels with a top sheen, and an ambient accent glow that follows the theme
- 🖥️ **Console** — dense instrument grid: accent-topped cards, uppercase micro-labels, tabular numerals,
  squared compact controls, 8 px radii and a faint blueprint grid behind the page
- 🎛️ Each option is a tiny live preview in the picker; the active one is highlighted
- ⌨️ **⌘K** gained `Interface: …` entries, so you can flip layouts without opening Settings
- 💾 Persisted as `ui.interface`, applied before first paint (`data-ui`), shared with the embedded
  Monitoring / Docker / Reports pages, and previewable with `?ui=glass`
- 🧪 Tests: `tests/test_ui_interfaces.py` (tokens only, no `!important`, boot script on every page,
  stylesheet ordering, controller API, palette, phone guards)

### v3.0.0 - Audit implementation: security baseline, one SSH path, split module tree, faster dashboard
This release is the six-phase audit implemented end to end. There are behaviour changes worth reading
before upgrading — they are all in the *Security and hardening* and *Performance* sections above.

- 🔐 **Opt-in authentication** (`AILOG_AUTH_MODE=none|proxy|local`) with a single `before_request` gate, plus
  `/healthz`. `none` keeps today's trusted-network behaviour, so nothing breaks by default
- 🛡️ **Security headers everywhere** — CSP, `nosniff`, `Referrer-Policy`, `SAMEORIGIN`, `Permissions-Policy`,
  optional HSTS — and the app now binds **127.0.0.1** unless `AILOG_BIND` says otherwise (the image sets it)
- 📦 **Front-end assets are vendored** in `static/vendor/` with **SRI hashes**; a CDN compromise can no longer
  inject script into the UI. `GET /` no longer touches the internet
- 🔑 **SSH host keys are pinned** (`StrictHostKeyChecking=accept-new` + a real `known_hosts`); the exported
  `~/.ssh/config` no longer disables host checking either
- 🗄️ **DB backup/restore is opt-in** (`AILOG_ALLOW_DB_ADMIN=1`) and restores are validated
  (`PRAGMA integrity_check`, required tables, size cap) with a `<db>.pre-restore-<ts>` copy kept
- 🚪 **WebSocket origin check** on `/ssh/websocket` (cross-site hijacking)
- 🧵 **One SSH transport** — `core/ssh.py` replaces five near-duplicate remote-exec paths; `core/hostkeys.py`
  owns the policy
- 🏗️ **`create_app()` factory** and `core/bootstrap.py`; app routes live on the `core_ui` blueprint. Routes and
  URLs are unchanged
- 🧼 **Every HTML sink is escaped** (host names, descriptions, errors, log/container names, group attributes)
  and a test walks all JS to keep it that way; `index.html` is 737 lines with dialogs in `templates/partials/`,
  and the wizard's inline script is `static/js/wizard.js`
- ⚡ **`/api/overview`** aggregates the dashboard into one ETag'd request (`304` when nothing changed), polling
  backs off on failure, caches are size-capped, and SQLite runs in WAL with a busy timeout
- 🐛 **Four latent crashes fixed** (found by `ruff`): undefined `emit` in `get_ollama_models`, undefined
  `tf_name` in the Suricata SSH read, undefined `_ssh_key_file_cache` on key delete, and undefined
  `sessions_lock` in `/wizard/session/create` — plus a `/ssh-keys/verify-integrity` route that never
  registered because `app.run()` sat above it
- 🧪 **CI**: `ruff --select F,E9`, `pytest` with a coverage floor, and `node --check` on every JS module

### v2.19.1 - Expandable SSH terminal
- ⤢ **Expand / contract** icon in the SSH terminal header: the session pops out to a 92 vh window using the
  same dialog chrome as Docker, Reports and Monitoring
- 🔁 **The session is moved, not recreated** — the xterm node is re-parented and re-fitted, so scrollback,
  the WebSocket connection and any running command survive both directions
- ⎋ Contract via the header icon or a backdrop click (Escape is deliberately left to the terminal, so `vim`
  and `htop` keep working)
- 🧹 Contracting is automatic when the session ends or you leave the Logs view
- 📱 Below 640 px the window becomes a full-width sheet, like every other dialog

### v2.19.0 - Homelab Manager, and a leaner Overview
- 🏷️ **Renamed to Homelab Manager** everywhere it is visible: header and brand mark, browser titles on
  every page, the SSH-config header, the generated backup / host-import filenames, the Discord test
  notification. Service, image and repository names are unchanged (`ailog_ailog`)
- 🧹 **The Hosts card is gone from the Overview** — the dashboard is now Fleet + Alerts + Recent
  reports in one row. Selecting a host is still the sidebar, a ⌘K entry, or the Logs workspace
- 📱 The longer name fits the phone header (the brand mark yields its space below 430 px)

### v2.18.0 - Fleet-first UI, ⌘K and six themes
- 🧭 **Option A navigation** — the dashboard is now a genuine fleet Overview
  (Fleet / Hosts / Alerts / Recent reports cards) and every per-host tool stays in the host workspace;
  nothing was removed, everything was re-homed
- ⌨️ **⌘K command palette** — subsequence search across views, actions, hosts and themes, with
  ↑/↓/Enter/Esc and platform-aware shortcut hints
- 🎨 **Six theme families × dark/light** with a sun/moon toggle next to Settings, Settings →
  Appearance (theme, mode, density, motion), pre-paint boot script (no flash), `?theme=` overrides
  for screenshots/links, and theme-aware charts
- 📱 **Responsive shell** — 264 px sidebar → 76 px icon rail → phone drawer + bottom tab bar, with
  bottom-sheet dialogs and horizontally scrolling tables
- 🧱 **Tokenised dialog chrome** — every modal (Docker, Reports, Monitoring, Settings, host forms) now
  paints from `--surface` / `--border` / `--shadow-2`, so light mode is legible everywhere
- 🧪 43 new structural tests (theme palettes, boot script in every template, breakpoints, palette
  contract, overview polling) — suite at 274 passing

### v2.14.1 - Docker Monitoring in a Modal
- 🪟 **The Docker button opens a dialog, not a new page** — a 95vw × 92vh panel with the
  Docker dashboard inside an iframe, titled `Docker — <host>`, with a **Close** button (also
  Escape and backdrop click). The logs view stays mounted underneath, so you no longer lose your
  filter/scroll position by checking containers
- 🔗 **One page, two modes** — `/docker/<host>` is unchanged for deep links and bookmarks; the modal
  loads `/docker/<host>?embed=1`, which drops the page's own **Back** link (the dialog owns closing)
  and tightens the chrome for the smaller frame
- 🧹 **Nothing keeps sampling in a hidden frame** — closing the modal resets the iframe to
  `about:blank`, which unloads the document and so tears down its chart timers and polling (the page
  already hooked `beforeunload` / `visibilitychange` for this)
- ↩️ Falls back to the old navigation if the modal module fails to load

### v2.14.0 - Severity Filters for Server Reports
- 🎯 **Multi-select severity filter** in the *Analyse All Logs* dialog: **Critical / Errors / Warnings**
  (any combination) or **All** (default, byte-identical to the previous behaviour). The selection
  travels with the request, the size check, the bundle cache key, the stored report and the
  scheduled-report scope
- ⚡ **Filtered on the host, so the saving is real**
  - journald: `journalctl --priority=N` — the journal drops the lines itself, nothing enters the pipe.
    Exact for the contiguous "N and above" selections (crit, crit+error), with a `grep` appended for
    the rest (warn-only, error-only, error+warn, crit+warn)
  - files / `.gz` / container logs: `grep -aiE` from the **same keyword tables**
    (`normalize.SEVERITY_WORDS`) that `classify_severity` uses, so the pre-filter can never be
    stricter than the classifier. `-i` matters: the classifier is case-insensitive, so a
    case-sensitive grep would silently drop `ERROR:` lines. `-A 3` keeps traceback bodies and
    `--no-group-separator` avoids grep's `--` junk lines
  - filtered runs widen the scanned tail (`FILE_SCAN_CAP` 12000 / `JOURNAL_SCAN_CAP` 20000) because
    only the matches are transferred: "the last 4000 errors" instead of "the last 4000 lines"
- 🧪 **Two-stage filtering**: `normalize` re-applies the selection authoritatively and drops whatever
  the grep heuristic let through. Dropping a line detaches it from `previous`, so a stack trace can
  never attach to an unrelated event that survived
- 📉 **Measured** on a 63-source host, 60-minute window: 1.05 MB → 296 KB (errors+critical) →
  2.3 KB (critical only) of transferred text; 8,046 → 229 events. On hosts where the pack exceeds the
  model context the fewer signatures also mean fewer chunk passes
- 🛡 **Honest evidence:** the pack header gains `FILTER` / `FILTER NOTE` lines stating the subset and
  that missing severities are *not* evidence of health, since correlation baselines are computed on
  the filtered subset. The report page shows the filter next to the header, and the size check
  reports events kept / context lines dropped
- 🧹 `emergency.service` and `rescue.service` are no longer collected: the report's own
  `sudo journalctl -u emergency.service` shows up in auth.log and the word "emergency" classifies as
  CRIT, i.e. the filter was reporting on itself

### v2.13.1 - Alerts, Report Diffs, Scheduled Reports and a Smaller app.py
- 🚨 **`alerting/` blueprint** - threshold rules over metrics that are already collected
  - `AlertRule` / `AlertEvent` models; five rules seeded on first boot; `/alerts` page with active
    alerts, an inline rule editor and recent events (30 s refresh)
  - `ok → pending → firing → resolved` state machine with `for_seconds` debounce and per-rule
    `cooldown_seconds`; only transitions notify (a 15 s sampler would otherwise emit 240 identical
    Discord messages an hour), and recoveries send a green "resolved" embed
  - Evaluated from `dockermon/history.py` on every sample and from `serverreport/routes.py` when a
    report's verdict is stored (`verdict_level` rule), wrapped so a delivery failure can never
    break the sampler; live state is in memory, every transition is mirrored to `alert_events`
- 🔁 **Report diffs** (`serverreport/diff.py`) - the report page now has a **Since last report**
  panel: verdict transition, event delta and %, new / gone / louder signature clusters,
  new / gone correlations, per-source coverage. Identity is `(signature, source)` for clusters and
  an order-independent pair for correlations, and everything is read from the stored JSON columns,
  so no host is re-collected
- 🗓 **Scheduled reports** - `Schedule.kind` is now `'log'` (default) or `'report'`, with
  `report_window_minutes`, `report_depth`, `report_model` and `report_scope_json`. A report
  schedule reuses the existing pipeline unchanged: one report per host per run, per-host results
  recorded in `last_status` / `last_run_at`
- ⚖️ **Fairer source caps** - `AILOG_REPORT_MAX_SOURCES` 60 → 120, allocated by kind
  (45 % file / 30 % journal / 25 % docker) with unused allowance overflow and journald units
  ranked by activity, so a file-heavy host cannot starve journald or container sources
- 🧱 **`app.py` split** - additive-column migrations moved to `app_schema.add_missing_columns()`
  (replacing two duplicated helpers), and the groups / tags / export / DB-admin routes moved to
  the new `inventory/` package. URLs and handlers are byte-for-byte the extracted code
- 🧩 **`templates/index.html` split into ES modules** - 8,257 → ~1,399 lines of markup with one
  `<script type="module" src="/static/js/main.js">` entry point and per-feature modules
  (`app-core.js`, `suricata.js`, `sshkeys.js`, `groups.js`, `toolbar.js`, wizards, `alerts.js`).
  Import order mirrors the old script-block order so `DOMContentLoaded` wiring is unchanged
- 🧪 **First test suite** - `tests/` with 108 pytest tests over alerts, diffs, scheduled reports,
  source caps, dockermon and inventory (see *Testing*)

### v2.13.0 - Docker History, Apps and Cluster Views
- 🕘 **Rolling history** (`dockermon/history.py`) - a background sampler records one point per
  Docker host every 15 s into a 60-minute ring buffer
  - Charts seed from `/api/docker/hosts/<k>/history` on load, so a refresh keeps the graph
  - `GET …/history/stream` pushes new points over SSE; `POST /api/docker/history/clear` drops them
  - In memory only, and therefore lost on restart: this is a "what has it been doing?" window,
    not a metrics database. Anything that needs to outlive the process belongs in a report
  - A metric that a sample does not report holds its previous value instead of punching a hole
- 🗂 **Apps view** (`dockermon/parse.py: aggregate_apps/finalize_apps`) - containers grouped by
  `com.docker.stack.namespace` → service → container, summed CPU/RAM/network and disk footprint
  - Across a swarm the groups span nodes, so "how much is the media stack using?" is one number
  - Falls back to a single `(standalone)` group on hosts without stack labels
- 🖧 **Cluster view** (`dockermon/swarm.py`) - manager → node tree built from `docker node ls`
  plus `docker node inspect` for each node's address
  - One combined SSH command per node collects containers, `docker stats`, `docker system df`,
    `/proc/stat`, `/proc/meminfo`, `/proc/net/dev` and `df -B1 /`
  - Nodes are collected in parallel (6 workers) and the whole view is cached for 10 s
  - The manager serving the request reuses its own live snapshot instead of SSHing to itself,
    which also makes a single-node swarm cost one extra `docker system df`
  - Unreachable nodes stay in the list marked offline with their error, and are excluded from
    the cluster totals rather than quietly zeroing them
  - Per-container network rates come from counter deltas (`sshstats._container_rates`), with
    counter resets reported as 0 rather than a negative spike
- 🧭 **UI** - the Docker page is now tabbed: **Overview** (charts + containers + node chips),
  **Apps**, and **Cluster** (hidden unless the host is a swarm manager). Everything is rendered
  with the page's existing Tailwind/Chart.js stack - no new front-end dependencies.

### v2.12.1 - Documentation for Server Reports
- 📖 Usage walkthrough for **Analyse All Logs**: window/scope selection, size check, depth
  guidance with real token costs per level, where reports live
- ⚙️ Report tuning table: `report.default_model`, `report.window_minutes`, `report.depth` and the
  `AILOG_REPORT_MAX_SOURCES` / `MAX_BYTES` / `MAX_TOKENS` environment variables
- 🔗 Endpoint reference for `/serverreport/*`, `/reports*` and `/api/reports*`
- 🔑 Sudoers entries the report collection needs (windowed `journalctl`, `tail -n 4000`,
  `find -printf`, `systemctl list-units`, `docker logs --since`) plus what degrades without them
- 🏗 Architecture notes: blueprint layout and the seven-stage report pipeline

### v2.12.0 - Report Sizing, Chunking and Closing Sections
- 🧮 **`serverreport/sizing.py`** - measures the evidence pack and recommends a run profile
  - Depth levels 1-5 (Lite / Standard / Detailed / Deep / Maximum) controlling the evidence
    budget, the output budget and the chunking threshold
  - Depth changes what is actually **sent** (`pack.PACK_LIMITS`): 15 / 28 / 45 / 90 / 180
    clusters, 6-30 correlations, extra sample lines at depth 4+, wider coverage lists. On
    db-11 the same window costs 1.7k tokens at Lite and 22.9k at Maximum
  - An explicit depth always wins over Auto; Auto only fills the gap, and the rationale says
    what it would have picked instead
  - Auto mode sizes the host from the **standard (depth 3)** view plus cluster/event counts,
    weighted up for noisy hosts and high correlation counts. (Measuring the deepest pack
    would always recommend maximum depth, which defeats the purpose.)
  - Model context awareness (`MODEL_CONTEXTS`, 75% safety margin) - if the pack exceeds the
    model's window it suggests a model that can hold it
  - Human-readable rationale returned to the UI, e.g. *"Evidence pack is ~90,000 tokens;
    the model holds ~49,152 input tokens. That fits in 3 chunks..."*
- 🧩 **Map/reduce chunking** (`pack.split_pack`, `llm.summarise_chunk`, `llm.merge_notes`)
  - Splits are balanced by size and snapped to blank-line/section boundaries; the header
    block is repeated in every part so each pass knows the host and window
  - Each pass extracts `FINDINGS / CORRELATIONS / CONTAINERS / GAPS / NOTES`; the notes are
    de-duplicated and merged into one pack for the final report call
- 🎚 **Depth slider + pre-flight** in the Analyse All Logs dialog
  - Auto (default) or manual 1-5, with a description of what each level includes
  - **Check size & suggest** collects, normalises and correlates *without* calling the model,
    returns source/event/cluster counts, the token estimate and a recommendation, and caches
    the bundle so pressing Start does not collect the host twice
  - Surfaces the recommendation (and any model suggestion, one click to apply) both before
    and during a run
- 📄 **Two new closing sections**
  - `## Executive Summary` - final section, two or three plain-English sentences for a
    non-specialist: what happened, how bad, whether to act now
  - `## How to Resolve` - numbered remediation plan with concrete steps, the command or
    config change where confident, and how to verify, tagged immediate / soon / preventive
- ⚙️ **Default model** for reports is now `openai/gpt-4o-mini` (settings key
  `report.default_model`); per-run override still supported
- 🗄 Depth, chunk count, pack size and the recommendation are stored in the report's
  coverage blob, so a report records how it was produced

### v2.11.0 - Server-Wide Correlated Log Reports
- 🧠 **New `serverreport/` blueprint:** `collect` → `normalize` → `correlate` → `pack` → `llm` → `routes`
- 🪟 **Time-windowed collection** (`collect.py`)
  - Default window is 2 hours; every source is fetched with `--since`/`tail` bounded by that
    window, so sources share a clock
  - One `find -printf` round trip for file discovery instead of a `stat` per file; files not
    written in the window are skipped
  - journald unit listing capped (`head -n 60`) — an uncapped `--field _SYSTEMD_UNIT` emits
    ~118k lines on db-11 and times out
  - Caps: `AILOG_REPORT_MAX_SOURCES` (120, shared per kind), `AILOG_REPORT_MAX_BYTES` (24 MB), 6 workers,
    per-host lock so two clicks cannot stack SSH sessions, failures isolated per source
- 🧩 **Normalisation** (`normalize.py`): timestamps parsed from RFC3339, syslog (with year
  rollover), journal `short-iso` and bracketed formats; multi-line stack traces attach to
  their parent event; severity tiers; volatile values (PIDs, IPs, UUIDs, hex, numbers) are
  replaced so similar lines collapse into one signature
- 📐 **Correlation** (`correlate.py`): co-occurrence lift within 10 s buckets across
  *different* sources (ranked by lift × √hits, with median lag), median/MAD burst detection,
  silence/early-stop detection, container state, and a chronological first-occurrence timeline
- 📦 **Evidence pack** (`pack.py`): plain-text, token-estimated, trimmed to
  `AILOG_REPORT_MAX_TOKENS` when necessary
- 🛡 **Prompt-injection guard** (`llm.py`): evidence is fenced and the system prompt marks it
  as untrusted data; required section headings keep output parseable; verdict parsed to
  healthy / degraded / failing
- 📄 **Routes & UI:** `POST /serverreport/stream` (SSE stages), `/reports`, `/reports/<id>`,
  `/reports/<id>/markdown`, `POST /reports/<id>/discord`, `/api/reports*`; toolbar button,
  scope dialog (window / sources / model) and a stepper showing collect → normalise →
  correlate → summarise → save
- 🗄 **`log_reports` table** (additive, created by `db.create_all()`) storing severity,
  timeline, correlations, container state, coverage and the evidence pack itself

### v2.10.1 - AI Analysis Progress & Markdown Output
- ⏱ **Staged progress in the AI modal** (replaces the static "Contacting AI assistant...")
  - New `POST /analyse/stream` SSE endpoint: the blocking provider call runs in a worker
    thread (with its own app context) while the response emits stage events and a
    heartbeat every 2 s
  - Stages: *Preparing log excerpt → Contacting provider → Analysing logs (elapsed clock)
    → Formatting result*, shown as a stepper (○ / ● / ✓) with a progress bar
  - Configuration errors (missing key / unconfigured Ollama or OpenRouter) fail before
    "contacting" and surface immediately
  - Shared `_analysis_config()` / `_run_analysis()` / `_notify_if_alerting()` helpers;
    `POST /analyse` keeps its original contract
- 📝 **Markdown-rendered results**
  - marked@12 + DOMPurify@3 (pinned CDN, sanitised) with a plain-text fallback
  - Theme-aware styling for headings, lists, tables, code fences, blockquotes and links
  - Provenance line: provider · model · elapsed seconds
  - Applied to both the AI Analyse and Suricata Raw analyse modals; modal close handler
    now bound once

### v2.10.0 - Docker Monitoring & Container Logs
- 🐳 **Docker monitoring subsystem** (`dockermon/` blueprint)
  - Discovery over three transports: unix socket via SSH (default), TCP `2375`, TLS `2376`
  - Standalone page `/docker/<host_key>` with live CPU / RAM / network charts (2 s, 60-point window)
  - Container list with state/health, writable + rootfs size, image reference and version tag, ports, mounts
  - Swarm cluster node list with per-node drill-down
  - Background re-probe job (`AILOG_DOCKER_REFRESH_SECONDS`, default 300 s) plus a **Scan Docker** button
  - Persisted endpoint state in the additive `docker_endpoints` table
- 🧾 **Container logs in Pull Logs**
  - Each container is listed as a log source with a `docker` badge and `state · image:tag` subtitle
  - Opens the last 500 lines with timestamps; Swarm managers resolve the service label and use `docker service logs` so cross-node tasks work
  - New **Docker logs only** filter, combining with the existing 0-byte filter
- ⏱ **Faster connect feedback**
  - SSE routes disable proxy buffering and emit an immediate `: connected` heartbeat (first byte in ~40 ms through nginx)
  - Indeterminate sweeping bar + spinner until the first measurable event
  - Elapsed clock with escalating copy while connecting
- 🔒 **Security hardening**
  - `/log/<path>` now rejects absolute paths and `..` segments (was able to read files outside `/var/log` as root)
  - Log output is inserted with `textContent` instead of `innerHTML` (log-injection XSS)
  - Host-derived strings (file/container names, image refs) are HTML-escaped before rendering
  - `/api/docker/log/<container>` validates the identifier against Docker's name grammar
  - Docker SDK pinned to `>=7.1.0,<8.0`
- 🧪 Verified live against 16 hosts (10 with Docker): discovery, stats, containers, container detail, swarm nodes, and container logs over both SSH-CLI and Swarm-service paths

### v2.3.0 - Settings Modal Redesign & UX Improvements
- 🎨 **Sidebar Navigation**: Redesigned settings modal with intuitive sidebar menu
  - Five menu sections: AI Provider, AI Prompts, Notifications, Scheduled Analysis, Remote Hosts
  - Clean separation of concerns with content panels
  - Active state indicators with indigo borders
- 🎯 **Dark Theme Support**: Updated settings modal to match main application dark theme
  - Dark semi-transparent glass-effect backgrounds
  - White/light gray text for better readability
  - Dark input fields with white borders
  - Consistent styling with overall application aesthetic
- 📻 **Model Selection Redesign**: Ollama model selection improved
  - Changed from dropdown to 2-column radio button grid
  - Larger clickable areas with hover effects
  - Better visual hierarchy and user experience
- 🔧 **AI Prompts Placeholder**: New section for future custom prompt configuration
  - Coming Soon interface ready for prompt customization feature
- 🐛 **Bug Fixes**: Fixed critical issues with settings modal
  - Resolved "Save & Close" button TypeError
  - Removed dependencies on non-existent DOM elements
  - Simplified credentials handling workflow

### v2.2.0 - Unified AI Provider Settings & UI Improvements
- 🔧 **Unified AI Provider Selection**: Single dropdown to select between OpenAI and Ollama
- 🤖 **Ollama Integration**: Full support for local Ollama models with:
  - API URL configuration with connection testing
  - Dynamic model discovery and selection
  - Model availability verification
  - Persistent configuration saved to config.json
- 🔑 **OpenAI Configuration**: Simplified API key management with validation
- 🎨 **Host Card Styling**: Improved visibility with better contrast and animations
  - White/opaque backgrounds for better readability
  - Animated green connection indicators
  - Enhanced selected and hover states
  - Better shadow and border styling
- 🐛 **DOM Element Fixes**: Fixed null reference errors preventing host card display
  - Corrected logTitle and logContent element references
  - Added null checks for legacy elements
  - Fixed testOllamaBtn conditional initialization
- 📱 **Provider Indicator**: Toolbar badge showing active AI provider and model
- 💾 **Configuration Persistence**: AI provider settings persisted across app restarts
- ✅ **Status Validation**: Real-time configuration status display in Settings modal

### v2.1.0 - Advanced Search & Multi-Host Enhancements
- ✨ **Global Search**: Search across all logs from all hosts simultaneously
- 🎯 **Scoped Search**: Target specific logs or journal units
- 🔍 **Search Highlighting**: Visual highlighting of search terms in results
- 📊 **Progress Tracking**: Real-time progress for all operations
- 🔄 **Retry Mechanisms**: Automatic retry for failed host connections
- 🐛 **Bug Fixes**: Resolved const redeclaration issues and improved error handling
- 🎨 **UI Improvements**: Enhanced visual feedback and user experience

### v2.0.0 - Multi-Host Architecture
- 🌐 **Multi-Host Support**: Manage multiple remote servers from single interface
- 🔒 **SSH Integration**: Secure passwordless authentication
- ⚡ **Concurrent Processing**: Parallel operations across hosts
- 📈 **Streaming Updates**: Real-time progress with Server-Sent Events
- 🤖 **Cross-Host AI Monitoring**: Schedule analysis across multiple servers

### v1.0.0 - Initial Release
- 📄 **Log Viewing**: Basic syslog and journal viewing
- 🤖 **AI Analysis**: OpenAI-powered log analysis
- 🔔 **Discord Alerts**: Webhook notifications
- 📅 **Scheduling**: Automated monitoring capabilities

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests for any improvements.

### Development Setup
```bash
# Clone repository
git clone <your-repo-url>
cd ailog

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run development server
python3 app.py
```

### Testing

There is a real pytest suite under `tests/` (108 tests, no network or SSH required):

```bash
pip install -r requirements-dev.txt      # pytest
python -m pytest tests/ -q
```

`tests/conftest.py` points `DATABASE_URL` at a temporary SQLite file *before* importing `app`
(the app builds its schema at import time), then provides `client`, `ctx`, `db_session` and a
`host` fixture that returns a fresh `db-<id>` key. Alert state is process-wide, so an autouse
fixture resets it between tests.

| File | Covers |
|---|---|
| `test_alerts.py` | operators, debounce/`for_seconds`, recovery resolves, cooldown, disabled rules, missing metrics, verdict rules, notification success/failure, seeding, rule CRUD + API, events/state/evaluate endpoints, page render |
| `test_report_diff.py` | identical reports, new/gone clusters, source as part of cluster identity, "louder" rule, verdict transitions, event delta and % (with a zero baseline), correlation identity order-independence, item caps, bad JSON tolerance |
| `test_schedule_reports.py` | `kind` defaulting and switching, report field coercion, per-host pipeline runs and failures, log schedules keeping the old path, one APScheduler job per enabled schedule |
| `test_collect_sources.py` | the source cap: no kind can starve another, unused shares overflow, discovery order preserved, journal units ranked by activity, window clamping |
| `test_dockermon.py` | `docker system df` / `df` parsing, app grouping, history buffer (hold-last, bounded, clear), core-weighted swarm totals, offline nodes, container rate deltas, history/swarm routes |
| `test_severity_filter.py` | selection parsing/aliases, `--priority` exactness, the grep pattern agreeing with the classifier (and containing no `(?:` that GNU grep rejects), case-insensitive pre-filter, per-source commands for files/gz/journal/docker, normaliser filtering incl. traceback handling and continuation detach, collect plumbing, bundle-cache keying, preflight passthrough |
| `test_inventory.py` | groups/tags CRUD and assignment, Ansible and SSH-config exports, SQLite backup/restore validation, blueprint registration of the extracted routes |

Manual checks still matter for the parts that touch real hosts: SSH key auth, passwordless sudo,
and search across different log types.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

**Security Notice**: This application is intended for use in trusted, internal networks only. It requires elevated permissions and SSH access to monitored systems. Ensure proper network isolation and access controls are in place.

**AI Analysis**: AI-powered analysis requires an OpenAI API key and usage may incur costs based on your OpenAI plan.

## 📞 Support

For issues, feature requests, or questions:
1. Check the troubleshooting section above
2. Review application logs for detailed error information
3. Open an issue on the project repository
4. Include system information and error logs for faster resolution

## Suricata Quick Start
1. Open **Settings → Suricata Data** and enter host/user/log dir (default `/var/log/suricata`) and optional SSH key.
2. Click **Test Connection** to verify SSH + sudo + log visibility.
3. Click **Run Ingest Once** to populate the local SQLite cache (the scheduler also ingests periodically).
4. Click **Suricata Stats** in the toolbar and use:
   - The range slider (1h / 6h / 24h / 7d)
   - Tabs: **Suricata Stats**, **Endpoint Data**, **Raw Data**

### Suricata Raw Data AI Analyse
- Configure the Suricata prompt in **Settings → AI Search → Suricata AI Prompt**
- Use **Suricata Stats → Raw Data → AI Analyse** to analyze the currently loaded raw log tail

