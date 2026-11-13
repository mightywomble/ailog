#!/bin/bash
# netbox-mcp-tailnet-fw.sh - keep the NetBox MCP port on tailscale0 only.
#
# Swarm cannot bind a published port to a host IP (docker requires `published`
# to be an integer, and `host_ip` is ignored), so the stack publishes 8299 in
# host mode on the node that runs the MCP server and this script closes the port
# to every interface except the tailnet and loopback.
#
# Copy of stacks/netbox/tailnet-only.sh with PORT defaulted to 8299 and its own
# unit name, so the two stacks do not fight over the same systemd unit. Same
# reasoning applies, restated here:
#
# Two paths have to be covered, because docker can serve a published host-mode
# port either way:
#
#   * via DNAT into the container (FORWARD -> DOCKER-USER), matched on
#     --ctorigdstport because the destination has already been rewritten to the
#     container's 8000 by the time DOCKER-USER sees the packet;
#   * via docker-proxy listening on 0.0.0.0:8299 in the host netns, which is
#     plain INPUT traffic and never touches DOCKER-USER at all.
#
# The DOCKER-USER rules alone are therefore not enough: if docker leaves no NAT
# rule for the port (which is the normal case for `mode: host` publishing) the
# port is served by the proxy and the LAN could reach it. Both layers are
# installed here.
#
#   ./netbox-mcp-tailnet-fw.sh            apply now (idempotent)
#   ./netbox-mcp-tailnet-fw.sh --install  apply now + re-apply on every boot
set -euo pipefail

PORT="${NETBOX_MCP_PORT:-8299}"
SELF=/usr/local/sbin/netbox-mcp-tailnet-fw.sh
UNIT=/etc/systemd/system/netbox-mcp-tailnet-fw.service

apply() {
  # Docker publishes a swarm `mode: host` port by DNATing it to the task's
  # docker_gwbridge address. On this node that address (172.18.0.4) belongs to a
  # gateway sandbox whose container no longer exists, so every connection from
  # outside the host is DNAT'd into a black hole while docker-proxy on
  # 0.0.0.0:$PORT happily serves loopback. The stale address is re-applied on
  # every task create/update, so a one-off delete is not a fix: drop the rule
  # and let docker-proxy serve the port (it forwards to the task's live overlay
  # address, which is what makes http://localhost:$PORT work).
  while iptables -t nat -S DOCKER | grep -q -- "--dport $PORT -j DNAT"; do
    rule=$(iptables -t nat -S DOCKER | grep -- "--dport $PORT -j DNAT" | head -1 | sed 's/^-A DOCKER //')
    # shellcheck disable=SC2086
    iptables -t nat -D DOCKER $rule || break
  done

  # Belt and braces: even before the timer runs, make docker's bogus DNAT
  # unreachable by short-circuiting the port at the head of the DOCKER nat chain
  # and REDIRECTing it to the local docker-proxy socket. REDIRECT queues the
  # packet for local delivery, so the INPUT rules below still gate it to
  # tailscale0/lo, and docker's rule further down the chain is never evaluated.
  while iptables -t nat -C DOCKER -p tcp --dport "$PORT" -j REDIRECT --to-ports "$PORT" 2>/dev/null; do
    iptables -t nat -D DOCKER -p tcp --dport "$PORT" -j REDIRECT --to-ports "$PORT"
  done
  iptables -t nat -I DOCKER 1 -p tcp --dport "$PORT" -j REDIRECT --to-ports "$PORT"

  # drop our own rules first so a second run cannot stack duplicates
  while iptables -C DOCKER-USER -p tcp -m conntrack --ctorigdstport "$PORT" -j DROP 2>/dev/null; do
    iptables -D DOCKER-USER -p tcp -m conntrack --ctorigdstport "$PORT" -j DROP
  done
  while iptables -C DOCKER-USER -i tailscale0 -p tcp -m conntrack --ctorigdstport "$PORT" -j RETURN 2>/dev/null; do
    iptables -D DOCKER-USER -i tailscale0 -p tcp -m conntrack --ctorigdstport "$PORT" -j RETURN
  done
  while iptables -C DOCKER-USER -i lo -p tcp -m conntrack --ctorigdstport "$PORT" -j RETURN 2>/dev/null; do
    iptables -D DOCKER-USER -i lo -p tcp -m conntrack --ctorigdstport "$PORT" -j RETURN
  done

  # order matters: loopback, then the tailnet, then drop everything else
  iptables -I DOCKER-USER 1 -i lo -p tcp -m conntrack --ctorigdstport "$PORT" -j RETURN
  iptables -I DOCKER-USER 2 -i tailscale0 -p tcp -m conntrack --ctorigdstport "$PORT" -j RETURN
  iptables -I DOCKER-USER 3 -p tcp -m conntrack --ctorigdstport "$PORT" -j DROP

  # the docker-proxy path: host INPUT traffic on the published port
  while iptables -C INPUT -p tcp --dport "$PORT" -j DROP 2>/dev/null; do
    iptables -D INPUT -p tcp --dport "$PORT" -j DROP
  done
  while iptables -C INPUT -i tailscale0 -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null; do
    iptables -D INPUT -i tailscale0 -p tcp --dport "$PORT" -j ACCEPT
  done
  while iptables -C INPUT -i lo -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null; do
    iptables -D INPUT -i lo -p tcp --dport "$PORT" -j ACCEPT
  done

  iptables -I INPUT 1 -i lo -p tcp --dport "$PORT" -j ACCEPT
  iptables -I INPUT 2 -i tailscale0 -p tcp --dport "$PORT" -j ACCEPT
  iptables -I INPUT 3 -p tcp --dport "$PORT" -j DROP

  echo "netbox-mcp port ${PORT}: tailscale0 + lo allowed, everything else dropped"
  iptables -S DOCKER-USER | head -5
  iptables -S INPUT | head -5
}

case "${1:-}" in
  --install)
    install -m 0755 "$0" "$SELF"
    cat > "$UNIT" <<EOF
[Unit]
Description=Restrict the NetBox MCP published port to the tailnet
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$SELF

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now netbox-mcp-tailnet-fw.service

    # docker rewrites the published-port DNAT every time the task is recreated,
    # so re-assert both the NAT cleanup and the firewall on a short timer
    cat > "${UNIT%.service}.timer" <<EOF
[Unit]
Description=Re-assert the netbox-mcp tailnet-only port rules

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
Unit=netbox-mcp-tailnet-fw.service

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now netbox-mcp-tailnet-fw.timer
    apply
    ;;
  *)
    apply
    ;;
esac
