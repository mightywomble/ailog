#!/usr/bin/env bash
# Smoke test for the CI toolchain image ($1 = candidate tag).
# Every tool here is one the workflows call; a missing one turns a green run
# into a confusing failure three steps later.
set -euo pipefail
IMG="$1"

docker run --rm --entrypoint sh "$IMG" -eu -c '
  python3 -c "import sys; assert sys.version_info[:2] == (3, 12), sys.version" \
    || { echo "python is not 3.12"; exit 1; }
  node --version | grep -qE "^v20\." || { echo "node is not 20"; exit 1; }
  command -v git >/dev/null    || { echo "missing git (actions/checkout needs it)"; exit 1; }
  for t in pytest ruff yamllint ansible-lint ansible-playbook; do
    command -v "$t" >/dev/null || { echo "missing $t"; exit 1; }
  done
  python3 -c "import pytest_cov" || { echo "missing pytest-cov"; exit 1; }
  echo "python $(python3 --version), node $(node --version), pytest $(pytest --version | head -1)"
'

echo "smoke test passed for ci-python (python 3.12 + node 20 + git + linters)"
