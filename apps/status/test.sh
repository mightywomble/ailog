#!/usr/bin/env bash
# Smoke test: boot the image with every upstream unreachable and prove that
# the dashboard, the API and the poller all stay up. A status page that dies
# when a source dies is worse than useless.
set -euo pipefail
IMAGE="${1:-status:candidate}"
NAME="smoke-status-$$"
PORT=15911

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

cat > /tmp/status-apps-$$.json <<'JSON'
{"apps":[{"name":"self","host":"self","group":"test","url":"http://127.0.0.1:9/","forward_host":"127.0.0.1","forward_port":9}]}
JSON

docker run -d --name "$NAME" -p "$PORT:8080" \
  -e STATUS_DB=/tmp/status.db \
  -e STATUS_POLL_SECONDS=30 \
  -e STATUS_APPS_FILE=/tmp/apps.json \
  -e PVE_URL=http://127.0.0.1:9 \
  -e PVE_TOKEN=none \
  -e METAMCP_URL=http://127.0.0.1:9/mcp \
  -e METAMCP_API_KEY=none \
  -v /tmp/status-apps-$$.json:/tmp/apps.json:ro \
  "$IMAGE" >/dev/null

for i in $(seq 1 40); do
  if curl -sf -m 2 "http://localhost:$PORT/healthz" >/dev/null 2>&1; then break; fi
  sleep 1
done

echo -n "healthz: "; curl -sf -m 5 "http://localhost:$PORT/healthz" || { echo FAIL; docker logs "$NAME"; exit 1; }
echo

echo -n "snapshot: "; SNAP=$(curl -sf -m 20 "http://localhost:$PORT/api/snapshot") || { echo FAIL; docker logs "$NAME"; exit 1; }
case "$SNAP" in *'"nodes"'*) echo "ok ($(echo "$SNAP" | head -c 90)...)";; *) echo "FAIL: unexpected body"; exit 1;; esac

echo -n "history: "; HIST=$(curl -sf -m 10 "http://localhost:$PORT/api/history?hours=12") || { echo FAIL; exit 1; }
case "$HIST" in *'"episodes"'*) echo ok;; *) echo "FAIL: no episodes key"; exit 1;; esac

echo -n "dashboard: "; HTML=$(curl -sf -m 10 "http://localhost:$PORT/") || { echo FAIL; exit 1; }
for want in "Last 12 hours" "Virtual machines" "Swarm services" "Applications" "static/app.js" "static/style.css"; do
  case "$HTML" in *"$want"*) ;; *) echo "FAIL: dashboard missing '$want'"; exit 1;; esac
done
echo "renders OK"

echo -n "assets: "
for a in /static/app.js /static/style.css; do
  curl -sf -m 5 "http://localhost:$PORT$a" >/dev/null || { echo "FAIL: $a"; exit 1; }
done
echo ok

echo -n "unknown node: "; CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "http://localhost:$PORT/api/node/nope:nope")
[ "$CODE" = "404" ] || { echo "FAIL ($CODE)"; exit 1; }
echo "$CODE"

echo -n "still alive after a failed poll: "
sleep 12
curl -sf -m 5 "http://localhost:$PORT/healthz" >/dev/null || { echo FAIL; docker logs "$NAME"; exit 1; }
echo ok

echo "smoke test passed for status"
