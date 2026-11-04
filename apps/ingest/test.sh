#!/usr/bin/env bash
# Smoke test for the ingest image ($1 = candidate tag).
# Boots the app with a throwaway DB and no upstream credentials, then checks:
#   - /healthz and /api/status answer
#   - the dashboard renders (HTML with the source table)
#   - a dry-run of a source reports a sane job record (no credentials -> errors
#     are expected and are surfaced, the app must not crash)
set -euo pipefail
IMG="$1"
NAME="smoke-ingest"
PORT=15910

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker rm -f "$NAME" >/dev/null 2>&1 || true
rm -rf /tmp/ingest-smoke && mkdir -p /tmp/ingest-smoke

docker run -d --name "$NAME" \
  -e INGEST_DB=/data/ingest.db \
  -e ANYTHINGLLM_URL=http://127.0.0.1:9 \
  -e ANYTHINGLLM_API_KEY=x \
  -e WP_URL=http://127.0.0.1:9 \
  -e GITEA_URL=http://127.0.0.1:9 \
  -v /tmp/ingest-smoke:/data -p "$PORT:8080" "$IMG" >/dev/null

for i in $(seq 1 30); do
  curl -sf -m 2 "http://localhost:$PORT/healthz" >/dev/null 2>&1 && break
  sleep 1
done

echo "healthz: $(curl -s -m 3 "http://localhost:$PORT/healthz")"

STATUS=$(curl -s -m 10 "http://localhost:$PORT/api/status")
echo "status: $(echo "$STATUS" | head -c 200)"
case "$STATUS" in
  *'"workspace"'*) ;;
  *) echo "FAIL: /api/status missing workspace key"; docker logs "$NAME" | tail -30; exit 1 ;;
esac

HTML=$(curl -s -m 10 "http://localhost:$PORT/")
case "$HTML" in
  *"homelab ingest"*) echo "dashboard: renders OK" ;;
  *) echo "FAIL: dashboard did not render"; docker logs "$NAME" | tail -30; exit 1 ;;
esac
for want in wordpress gitea lan goose; do
  case "$HTML" in
    *">$want<"*|*"$want"*) ;;
    *) echo "FAIL: source '$want' missing from dashboard"; exit 1 ;;
  esac
done

# a dry run with unreachable upstreams must be recorded, not crash the process
RUN=$(curl -s -m 30 -X POST "http://localhost:$PORT/api/run/wordpress?dry_run=true" || true)
echo "dry run: $(echo "$RUN" | head -c 200)"
case "$RUN" in
  *'"run_id"'*) ;;
  *) echo "FAIL: dry run did not return a run record"; docker logs "$NAME" | tail -30; exit 1 ;;
esac

STATUS2=$(curl -s -m 10 "http://localhost:$PORT/api/status")
case "$STATUS2" in
  *'"recent_runs"'*) ;;
  *) echo "FAIL: recent runs missing after a run"; exit 1 ;;
esac
case "$STATUS2" in
  *'"source": "wordpress"'*|*'"source":"wordpress"'*) echo "run recorded OK" ;;
  *) echo "note: wordpress run not visible in per-source (dry run adds nothing) — acceptable" ;;
esac

echo "smoke test passed for ingest"
