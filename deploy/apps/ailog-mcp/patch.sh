#!/usr/bin/env bash
# Prepare an AILog source clone so the same image can also serve the MCP
# endpoint (mcp_service.py) next to the Flask app.
#
#   $1 = path to the ailog clone
#
# Two changes only:
#   1. drop mcp_service.py into the image root (docker/Dockerfile does COPY . /app)
#   2. add fastmcp/uvicorn/httpx and relax the openai pin, which otherwise
#      cannot co-resolve with fastmcp-slim (openai==1.3.7 caps httpx/pydantic;
#      AILog only uses openai.OpenAI(...) + chat.completions, stable across 1.x)
set -euo pipefail

WORK="${1:?usage: patch.sh <ailog-clone>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== ailog-mcp: installing mcp_service.py ==="
cp "$HERE/mcp_service.py" "$WORK/mcp_service.py"

echo "=== ailog-mcp: requirements ==="
REQ="$WORK/requirements.txt"
sed -i 's/^openai==1\.3\.7$/openai>=1.102,<3/' "$REQ"
grep -q '^fastmcp==' "$REQ" || cat >> "$REQ" <<'REQS'

# MCP endpoint (mcp_service.py) — AIOps tools for agents
fastmcp==3.4.7
uvicorn>=0.30
httpx>=0.27
REQS
grep -nE '^(openai|fastmcp|uvicorn|httpx)' "$REQ"
