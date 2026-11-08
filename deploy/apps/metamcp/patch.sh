#!/usr/bin/env bash
# Applied by the ailog ship/build workflow to the upstream clone
# ($1 = clone directory) before the image is built.
#
# MetaMCP is built from upstream v2.4.22 plus a source patch rather than from a
# fork: the patch is reviewed here, applies to a pinned tag, and the build is
# reproducible from upstream + this repo alone.
#
#   patches/0001-session-and-process-lifecycle.patch
#     source: david/metamcp @ fix/session-process-leaks (RECON.md, TESTS.md,
#     VERIFY.md, UPSTREAM.md). Fixes session/process leaks: #324 (sessions
#     never evicted, one process per session), #128 residuals (SIGTERM only, no
#     orphan reaping, no shutdown hook), failed-connect process leaks, plus a
#     per-server session cap, /health/pool and a shared-process flag.
set -euo pipefail

WORK="${1:?usage: patch.sh <clone-dir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"

cd "$WORK"

for p in "$HERE"/patches/*.patch; do
  echo "--- applying $(basename "$p")"
  git apply --verbose "$p"
done

# The homelab layer (Dockerfile + vendored patchmon-mcp) lives in this repo, not
# in upstream, so it is copied into the clone the workflow builds from.
cp "$HERE/Dockerfile.homelab" "$WORK/Dockerfile.homelab"
mkdir -p "$WORK/vendor"
cp -R "$HERE/vendor/." "$WORK/vendor/"

echo "--- patched tree ready:"
git status --short | head -30
