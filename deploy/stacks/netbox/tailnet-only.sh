#!/bin/bash
# netbox-tailnet-fw.sh - keep NetBox's published port on tailscale0 only.
#
# Swarm cannot bind a published port to a host IP (docker requires `published`
# to be an integer, and `host_ip` is ignored), so the stack publishes 8096 in
# host mode on the node that runs netbox and this script closes the port to
# every interface except the tailnet and loopback.
#
# The match is --ctorigdstport (the port before docker's DNAT) because by the
# time DOCKER-USER sees the packet the destination has already been rewritten
# to the container's 8080.
#
#   ./netbox-tailnet-fw.sh            apply now (idempotent)
#   ./netbox-tailnet-fw.sh --install  apply now + re-apply on every boot
set -euo pipefail

PORT="${NETBOX_PORT:-8096}"
SELF=/usr/local/sbin/netbox-tailnet-fw.sh
UNIT=/etc/systemd/system/netbox-tailnet-fw.service

apply() {
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
  echo "netbox port ${PORT}: tailscale0 + lo allowed, everything else dropped"
  iptables -S DOCKER-USER | head -5
}

case "${1:-}" in
  --install)
    install -m 0755 "$0" "$SELF"
    cat > "$UNIT" <<EOF
[Unit]
Description=Restrict the NetBox published port to the tailnet
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
    systemctl enable --now netbox-tailnet-fw.service
    apply
    ;;
  *)
    apply
    ;;
esac
