#!/usr/bin/env bash
# Smoke test for the ailog-mcp image ($1 = candidate tag).
#
# The image is the AILog app + mcp_service.py. The full app needs a database,
# so this boots mcp_service.py against a throwaway SQLite file and checks:
#   - /healthz answers without a token
#   - an unauthenticated POST /mcp is rejected (401)
#   - an authenticated MCP initialize + tools/list works and exposes list_hosts
set -euo pipefail
IMG="$1"
NAME="smoke-ailog-mcp"
PORT=15902
TOKEN="smoke-token-$$"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker rm -f "$NAME" >/dev/null 2>&1 || true
mkdir -p /tmp/ailog-mcp-smoke

docker run -d --name "$NAME" \
  -e DATABASE_URL="sqlite:////var/lib/ailog/ailog.db" \
  -e AILOG_MCP_TOKEN="$TOKEN" \
  -e AILOG_URL="http://127.0.0.1:5001" \
  -v /tmp/ailog-mcp-smoke:/var/lib/ailog \
  -p "$PORT:5002" \
  "$IMG" sh -c 'python3 mcp_service.py' >/dev/null

for i in $(seq 1 30); do
  if curl -sf -m 2 "http://localhost:$PORT/healthz" >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "healthz: $(curl -s -m 3 "http://localhost:$PORT/healthz")"

UNAUTH=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X POST "http://localhost:$PORT/mcp" \
  -H 'content-type: application/json' -d '{}')
[ "$UNAUTH" = "401" ] || { echo "FAIL: unauthenticated request returned $UNAUTH"; docker logs "$NAME" | tail -30; exit 1; }
echo "auth gate: 401 without token OK"

OUT=$(docker exec -i "$NAME" python3 - "$TOKEN" <<'PY'
import json, sys, urllib.request

token = sys.argv[1]
url = "http://127.0.0.1:5002/mcp"
hdr = {"content-type": "application/json",
       "accept": "application/json, text/event-stream",
       "authorization": f"Bearer {token}"}

def post(payload, sid=None):
    h = dict(hdr)
    if sid:
        h["mcp-session-id"] = sid
    req = urllib.request.Request(url, json.dumps(payload).encode(), h)
    r = urllib.request.urlopen(req, timeout=30)
    sid_out = r.headers.get("mcp-session-id")
    body = r.read().decode()
    msgs = []
    for chunk in body.split("\n\n"):
        for line in chunk.splitlines():
            if line.startswith("data: "):
                msgs.append(json.loads(line[6:]))
    return msgs, sid_out

_, sid = post({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                          "clientInfo": {"name": "smoke", "version": "1"}}})
post({"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
msgs, _ = post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid)
tools = [t["name"] for t in msgs[0]["result"]["tools"]]
print(" ".join(tools))
PY
)

echo "tools: $OUT"
for want in list_hosts list_log_sources read_log search_logs read_journal read_docker_logs host_facts run_command list_reports get_report; do
  case " $OUT " in
    *" $want "*) ;;
    *) echo "FAIL: tool '$want' missing"; docker logs "$NAME" | tail -30; exit 1 ;;
  esac
done

echo "smoke test passed for ailog-mcp ($(echo "$OUT" | wc -w | tr -d ' ') tools)"
