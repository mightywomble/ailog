#!/usr/bin/env bash
# Boot with no token, no repo and no ssh key: still serve the UI, still answer
# in JSON, never 500.
set -u  # smoke test: boots with no credentials, no repo, no ssh key
IMG="${1:-homelab-wizard:candidate}"
PORT=15915; NAME="smoke-wizard-$$"; DATA=$(mktemp -d)
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1; rm -rf "$DATA"; }
trap cleanup EXIT
docker run -d --name "$NAME" -p "$PORT:8080" -e GIT_API_KEY= -v "$DATA:/data" "$IMG" >/dev/null
for i in $(seq 1 30); do curl -fsS "http://localhost:$PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
fail=0
check() { body=$(curl -sS -m 10 "http://localhost:$PORT$1" 2>/dev/null)
  case "$body" in *"$2"*) echo "ok   $3";; *) echo "FAIL $3 (got: $(printf '%s' "$body" | head -c 140))"; fail=1;; esac; }
code() { got=$(curl -sS -o /dev/null -w '%{http_code}' -m "${3:-10}" "http://localhost:$PORT$1")
  [ "$got" = "$2" ] && echo "ok   $1 -> $2" || { echo "FAIL $1 -> $got (wanted $2)"; fail=1; }; }
check /healthz '"ok"' healthz
code / 200
check / 'homelab wizard' "title"
code /static/app.js 200
code /static/style.css 200
check /static/app.js 'openJob' "job runner"
check /static/app.js 'pipeline' "pipeline"
code /api/state 200
check /api/state '"settings"' "settings key"
# no ssh key in the smoke container: keep this generous, the point is that it
# answers instead of hanging
code /api/ports 200 40
code /api/models 200
body=$(curl -sS -o /dev/null -w '%{http_code}' -m 15 -X PUT -H 'Content-Type: application/json' \
  -d '{"entry":{"name":"BAD NAME","kind":"mirror"}}' "http://localhost:$PORT/api/services/bad")
[ "$body" = "400" ] && echo "ok   invalid service -> 400" || { echo "FAIL invalid service -> $body"; fail=1; }
# tag listing is server-side because Docker Hub has no CORS headers. A live tag
# fetch would make the smoke test depend on the internet, so assert the shape
# (and the error path) instead: this is the endpoint that used to only be
# reachable from the browser.
code "/api/tags?image=" 400 20
out=$(curl -sS -m 20 "http://localhost:$PORT/api/tags?image=docker.io/amir20/dozzle:latest")
if echo "$out" | grep -q '"tags"'; then echo "ok   /api/tags -> live tags"
elif echo "$out" | grep -q '"error"'; then echo "ok   /api/tags -> offline ($(echo "$out" | head -c 60))"
else echo "FAIL /api/tags -> $out"; fail=1; fi
check /static/app.js '/api/tags' "tag fetcher is server-side"

docker logs "$NAME" 2>&1 | grep -qi traceback && { echo "FAIL traceback in logs"; fail=1; } || echo "ok   no traceback"
exit $fail
