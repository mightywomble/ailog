#!/bin/sh
# Custom test for the goodbye app. The build workflow calls this with the
# candidate image tag as $1 (instead of the default smoke test). It starts the
# container, waits for it to serve, checks the content, and cleans up.
set -e
IMG="$1"
NAME="goodbye-test"
PORT="18081"

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "starting $IMG on localhost:$PORT"
docker run -d --name "$NAME" -p "$PORT:8081" "$IMG" >/dev/null
sleep 3

CONTENT=$(curl -fsS "http://localhost:$PORT/") || { echo "curl failed - container not serving"; exit 1; }
echo "served content: $CONTENT"

case "$CONTENT" in
  *goodbye*)
    echo "custom test passed: goodbye app is serving the expected content"
    ;;
  *)
    echo "custom test FAILED: unexpected content served"
    exit 1
    ;;
esac
