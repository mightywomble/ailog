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
  test -f /app/docker-entrypoint.sh           || { echo "missing entrypoint"; exit 1; }
  echo "node: $(node --version)"; echo "uvx: $(uvx --version)"
'

echo "smoke test passed for metamcp (entrypoint + pihole-mcp + node/npx + uvx present)"
