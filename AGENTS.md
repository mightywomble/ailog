# AGENTS.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Common commands

- Create venv and install deps
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
  ```
- Run the app (binds 0.0.0.0:5001, debug=False)
  ```bash
  python3 app.py
  ```
- Lint/format
  - None configured in this repo (no ruff/flake8/black configs). Skip or add explicitly if needed.
- Tests
  - No test suite or test framework is present as of 2026-01-26.

Notes
- Many backend operations require passwordless sudo for specific commands on the target hosts (including localhost). See README’s sudoers example. Without this, log discovery/search/journal access will fail.

## High-level architecture

Backend (Flask, single module: `app.py`)
- Responsibilities
  - Local and remote command execution for log discovery and retrieval under `/var/log` and via `journalctl`.
  - REST endpoints for: search (`POST /search`), log/journal content (`GET /log/<file>` and `GET /journal/<unit>`), host CRUD (`/hosts*`), and analysis/scheduling (`/analyse`, `/schedule/*`).
  - Server-Sent Events (SSE) streams for progressive UI updates: `/sources/local`, `/sources/remote/<host>`, `/sources/table/stream`.
  - Concurrent host operations using `ThreadPoolExecutor`; simple in-process caching for aggregated source views.
  - AI analysis via OpenAI client; optional Discord notifications when certain keywords are detected.
- Remote execution model
  - For remote hosts, commands are executed over SSH with `BatchMode` and a short connect timeout; for local execution `shell=True` is used.
  - The app expects passwordless sudo for: `ls`, `stat`, `tail`, `zcat`, selected `journalctl` invocations.
- Configuration/state files (created at runtime in repo root)
  - `hosts.json`: map of configured hosts (id → {friendly_name, ip, user, description}).
  - `scheduler_config.json`: persisted scheduler settings (API key, webhook, selected sources, interval, is_running).
- Runtime
  - Starts Flask on `0.0.0.0:5001` and an APScheduler background scheduler in the same process.

Frontend (vanilla JS + Tailwind via CDN)
- Primary template: `templates/index.html` with inline logic for UI state, SSE wiring, host/log selection, search, and analysis flows.
- Static assets: `static/js/main.js` (component loader stub), `static/css/style.css`, favicon. Credentials (OpenAI API key, Discord webhook) are stored in browser `localStorage` and sent per action.
- UX pattern relies on SSE progress messages and simple JSON APIs rather than a front-end framework.

## Useful local API calls (for debugging and automation)

- List aggregated sources (cached)
  ```bash
  curl -sS http://localhost:5001/sources/all | jq '.successful_hosts, (.logs | length)'
  ```
- Search across logs (set case sensitivity and scope)
  ```bash
  curl -sS -X POST http://localhost:5001/search \
    -H 'Content-Type: application/json' \
    -d '{"query":"error","scope":"all","case_sensitive":false}' | jq '.total_matches'
  ```
- Clear source caches
  ```bash
  curl -sS -X POST http://localhost:5001/sources/clear-cache
  ```
- Trigger one-off AI analysis (placeholders for secrets)
  ```bash
  curl -sS -X POST http://localhost:5001/analyse \
    -H 'Content-Type: application/json' \
    -d '{"log_content":"...last 500 lines here...","log_name":"syslog","api_key":"{{OPENAI_API_KEY}}","webhook_url":"{{DISCORD_WEBHOOK}}"}'
  ```
- Scheduler controls
  ```bash
  # start recurring analysis (hours)
  curl -sS -X POST http://localhost:5001/schedule/start \
    -H 'Content-Type: application/json' \
    -d '{"interval":12,"api_key":"{{OPENAI_API_KEY}}","webhook_url":"{{DISCORD_WEBHOOK}}","sources":[{"name":"syslog","type":"file","host":"local"}]}'

  # stop
  curl -sS -X POST http://localhost:5001/schedule/stop

  # status
  curl -sS http://localhost:5001/schedule/status | jq
  ```
- Discord webhook test
  ```bash
  curl -sS -X POST http://localhost:5001/test_discord \
    -H 'Content-Type: application/json' \
    -d '{"webhook_url":"{{DISCORD_WEBHOOK}}"}'
  ```
