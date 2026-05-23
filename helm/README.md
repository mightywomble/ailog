# ailog Helm chart

## Exec summary
This chart deploys AILog and publishes it on your Tailscale network (ingress). It also supports an optional Tailscale egress sidecar so the AILog pod can reach tailnet IPs (and subnet routes) for SSH-based log collection.

## What this chart deploys
- A `Deployment` running the AILog container.
- A `Service` (`ClusterIP`) on port 5001.
- A Tailscale `LoadBalancer` Service (ingress) when `tailscale.enabled=true`.
- Optional: a Tailscale **egress sidecar** container in the same pod for outbound tailnet/subnet access.
- Optional: a PVC when persistence is enabled.
- Optional: Tailscale state `Secret` + RBAC for the egress sidecar.

## Networking
### Ingress (access AILog from tailnet)
Controlled by `tailscale.enabled`. When enabled, the chart creates a Service with:
- `type: LoadBalancer`
- `loadBalancerClass: tailscale`

This exposes a `100.x` VIP and a `*.ts.net` hostname.

### Egress (SSH/outbound to tailnet and subnet routes)
Controlled by `tailscale.egress.enabled`. When enabled, the chart injects a `tailscale-egress` sidecar into the AILog pod.

Modes:
1) `userspace`
- No `/dev/net/tun` or privileged access.
- Provides a local SOCKS5 proxy (`tailscale.egress.socks5Server`).
- Your app must use the proxy explicitly.

2) `tun`
- Uses `/dev/net/tun` and privileged mode.
- Installs routing so the pod can reach `100.x` tailnet IPs directly.

Important: keep `tailscale.egress.acceptRoutes=false` if your tailnet advertises the cluster pod CIDR, otherwise Kubernetes probe/service routing can break.

## Required secrets
For egress, you need a Tailscale auth key secret in the namespace:
- `secret/tailscale-auth` with key `authkey`

The sidecar stores state in a `secret/tailscale` which the chart creates when egress is enabled.

## Example values (egress + tun)
```yaml
tailscale:
  enabled: true
  hostname: ailog

  egress:
    enabled: true
    mode: tun
    acceptRoutes: false
    authSecretName: tailscale-auth
    authSecretKey: authkey
```

## How it works
AILog uses SSH to reach remote hosts for log discovery and retrieval. When those targets are only reachable over Tailscale, the egress sidecar provides tailnet routing so the AILog pod can connect to `100.x` addresses and subnet routes.
