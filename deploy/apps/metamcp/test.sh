#!/usr/bin/env bash
# Smoke test for the MetaMCP image ($1 = candidate tag).
# The full app needs postgres, so this checks the runtime pieces instead:
# the upstream entrypoint/health paths exist and the tools MetaMCP shells out to
# for stdio MCP servers are present.
set -euo pipefail
IMG="$1"

docker run --rm --entrypoint sh "$IMG" -eu -c '
  test -x /usr/local/bin/pihole-mcp          || { echo "missing pihole-mcp"; exit 1; }
  pihole-mcp --version                        || { echo "pihole-mcp does not run"; exit 1; }
  command -v node >/dev/null                  || { echo "missing node"; exit 1; }
  command -v npx >/dev/null                   || { echo "missing npx"; exit 1; }
  command -v uvx >/dev/null                   || { echo "missing uvx"; exit 1; }
  test -x /usr/local/bin/patchmon-mcp         || { echo "missing patchmon-mcp"; exit 1; }
  PYTHONPATH=/opt/patchmon python3 -c "import patchmon_mcp.server" || { echo "patchmon_mcp import failed"; exit 1; }
  # get_host_packages must filter pending_only itself: PatchMon ignores
  # ?update=true, and the unfiltered 950-row reply is ~1.27 MB, which the MCP
  # gateway in front of MetaMCP rejects at 1,000,000 bytes per response.
  grep -q "p.get(\"needs_update\")" /opt/patchmon/patchmon_mcp/server.py \
    || { echo "patchmon_mcp does not filter pending_only"; exit 1; }
  test -f /app/docker-entrypoint.sh           || { echo "missing entrypoint"; exit 1; }
  # the session/process lifecycle patch (RECON.md in the source branch) must be
  # in the bundle this image actually runs, not just in the git patch
  grep -q METAMCP_MAX_SESSIONS_PER_SERVER /app/apps/backend/dist/index.js \
    || { echo "patched backend missing (no METAMCP_MAX_SESSIONS_PER_SERVER)"; exit 1; }
  grep -q METAMCP_SESSION_LIFETIME_MS /app/apps/backend/dist/index.js \
    || { echo "patched backend missing (no METAMCP_SESSION_LIFETIME_MS)"; exit 1; }
  grep -q METAMCP_SHARED_STDIO_PROCESSES /app/apps/backend/dist/index.js \
    || { echo "patched backend missing (no METAMCP_SHARED_STDIO_PROCESSES)"; exit 1; }
  grep -q 'health/pool' /app/apps/backend/dist/index.js \
    || { echo "patched backend missing (/health/pool)"; exit 1; }
  echo "node: $(node --version)"; echo "uvx: $(uvx --version)"
'

echo "smoke test passed for metamcp (entrypoint, stdio servers, patched backend)"
