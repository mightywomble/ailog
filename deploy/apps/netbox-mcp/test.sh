#!/usr/bin/env bash
# Smoke test for the NetBox MCP image ($1 = candidate tag).
#
# The server only talks to NetBox when a tool is called, so this proves the
# transport, the bearer auth and the tool table without a NetBox instance:
# NETBOX_URL points at a dead port and must not be touched at startup.
#
# Checked here: 401 without the token, a full MCP handshake, and a tools/list
# that has four tools and no write tool at all (that is what "read-only" means
# for this server - it ships no create/update/delete tool).
set -euo pipefail
IMG="${1:-netbox-mcp:candidate}"
NAME="smoke-netbox-mcp-$$"
PORT="${SMOKE_PORT:-18299}"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8000" \
  -e TRANSPORT=http -e HOST=0.0.0.0 -e PORT=8000 \
  -e NETBOX_URL=http://127.0.0.1:9/ -e NETBOX_TOKEN=not-a-real-token \
  -e MCP_AUTH_TOKEN=smoke-token "$IMG" >/dev/null

for _ in $(seq 60); do
  docker logs "$NAME" 2>&1 | grep -q "Starting HTTP transport" && break
  sleep 0.5
done
docker logs "$NAME" 2>&1 | grep -q "Starting HTTP transport" \
  || { echo "server did not start:"; docker logs "$NAME" 2>&1 | tail -20; exit 1; }

python3 - "$PORT" <<'PY'
import json
import sys
import urllib.error
import urllib.request

URL = "http://127.0.0.1:%s/mcp" % sys.argv[1]
BASE = {"Content-Type": "application/json",
        "Accept": "application/json, text/event-stream"}
AUTH = {"Authorization": "Bearer smoke-token"}


def sse(raw):
    body = None
    for line in raw.splitlines():
        if line.startswith("data: "):
            body = json.loads(line[len("data: "):])
    return body


def post(payload, headers=None, sid=None):
    head = dict(BASE)
    head.update(AUTH if headers is None else headers)
    if sid:
        head["mcp-session-id"] = sid
    req = urllib.request.Request(URL, data=json.dumps(payload).encode(),
                                 headers=head, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode()
            ctype = resp.headers.get("content-type", "")
            parsed = json.loads(raw) if "json" in ctype and raw.strip() else sse(raw)
            return resp.status, parsed, resp.headers
    except urllib.error.HTTPError as exc:
        return exc.code, None, exc.headers


# 1. the bearer token is actually enforced
code, _, _ = post({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}},
                  headers={})
assert code == 401, "expected 401 without a bearer token, got %s" % code

# 2. handshake
code, body, headers = post(
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "smoke", "version": "0"}}})
assert code == 200, "initialize: HTTP %s" % code
sid = headers.get("mcp-session-id")
assert sid, "initialize returned no mcp-session-id"
server = (body or {}).get("result", {}).get("serverInfo", {})
assert server.get("name"), "initialize returned no serverInfo: %r" % (body,)
print("serverInfo:", server.get("name"), server.get("version"))

post({"jsonrpc": "2.0", "method": "notifications/initialized"}, sid=sid)

# 3. the tool table
code, body, _ = post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid=sid)
assert code == 200, "tools/list: HTTP %s" % code
tools = sorted(tool["name"] for tool in body["result"]["tools"])
print("tools:", ", ".join(tools))
assert len(tools) == 4, "expected 4 tools, got %d" % len(tools)
writes = [t for t in tools if any(w in t for w in ("create", "update", "delete", "write"))]
assert not writes, "a write tool appeared: %s" % writes
PY

echo "smoke test passed for netbox-mcp (http transport, bearer auth, 4 read-only tools)"