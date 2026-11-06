# MetaMCP image used by the swarm stack.
#
# Thin layer over the upstream image (mirrored into zot as metamcp:2.4.22 —
# upstream already ships Node 20, pnpm and uv, so MetaMCP can run stdio MCP
# servers with npx/uvx at runtime). The additions are the stdio servers that
# cannot simply be fetched by npx/uvx:
#
#   pihole-mcp  — Go binary, only on GitHub releases
#   patchmon-mcp — locally written FastMCP wrapper around the PatchMon API, not
#                  published to PyPI (vendored under vendor/patchmon_mcp)
#
# Everything else is fetched at runtime by MetaMCP itself:
#   npx  gitea-mcp, @hexsleeves/tailscale-mcp-server
#   uvx  nextcloud-mcp-server, nginx-proxy-manager-mcp (pinned mcp==1.30.0)
# MetaMCP caches those on the NFS-backed /root/.npm and /root/.cache/uv.
#
# No apt here on purpose: the base image's NodeSource repo key is now rejected
# by Debian trixie's sqv policy ("SHA1 is not considered secure"), which makes
# any `apt-get update` fail. curl and tar ship with the base image.
FROM zot.safehomelan.com/metamcp:2.4.22

ARG PIHOLE_MCP_VERSION=0.9.0

USER root

# pihole-mcp (Go binary from GitHub releases)
RUN set -eu; \
    curl -fsSL -o /tmp/pihole-mcp.tar.gz \
      "https://github.com/hexamatic/pihole-mcp/releases/download/v${PIHOLE_MCP_VERSION}/pihole-mcp-slim_${PIHOLE_MCP_VERSION}_linux_amd64.tar.gz"; \
    mkdir -p /tmp/pihole-mcp-extract; \
    tar -xzf /tmp/pihole-mcp.tar.gz -C /tmp/pihole-mcp-extract; \
    BIN=$(find /tmp/pihole-mcp-extract -maxdepth 2 -type f -name 'pihole-mcp*' ! -name '*.tar.gz' | head -1); \
    test -n "$BIN"; \
    install -m 0755 "$BIN" /usr/local/bin/pihole-mcp; \
    rm -rf /tmp/pihole-mcp.tar.gz /tmp/pihole-mcp-extract; \
    /usr/local/bin/pihole-mcp --version

# patchmon-mcp (vendored python package) + a console-script-equivalent wrapper
COPY vendor/patchmon_mcp /opt/patchmon/patchmon_mcp
RUN set -eu; \
    uv pip install --system --break-system-packages "fastmcp==3.4.7" "httpx" "pydantic" "structlog"; \
    printf '%s\n' '#!/bin/sh' \
      'exec python3 -c "import sys; sys.path.insert(0, \"/opt/patchmon\"); from patchmon_mcp.server import main; main()" "$@"' \
      > /usr/local/bin/patchmon-mcp; \
    chmod 0755 /usr/local/bin/patchmon-mcp; \
    PYTHONPATH=/opt/patchmon python3 -c "import patchmon_mcp.server" && echo "patchmon_mcp import OK"

EXPOSE 12008
