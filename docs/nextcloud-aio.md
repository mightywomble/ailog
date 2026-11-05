# Nextcloud AIO on `files` (outside the swarm)

Nextcloud here is **not** an estate stack. It is Nextcloud All-in-One (AIO) running
as plain containers on the `files` host (`100.68.173.37`, david), with an
Nginx-Proxy-Manager ingress on `casaos` (`100.122.246.45`) in front of it.

    browser ──TLS──► NPM on casaos :443 ──plain HTTP──► AIO apache on files :11000
                              (files.safehomelan.com)              │
                                                                   └─► nextcloud, talk,
                                                                       collabora, clamav, …

## Why it is shaped this way

`files.safehomelan.com` is a **tailnet-only** name — it resolves to CasaOS's
Tailscale address, not to a public IP. AIO's default mode puts Caddy on :443 and
asks Let's Encrypt for a certificate, which cannot ever succeed for a name that
does not resolve publicly:

    {"logger":"http.acme_client","msg":"challenge failed",
     "problem":{"detail":"no valid A records found for files.safehomelan.com"}}

Caddy then has no certificate to present, so it aborts the handshake and NPM —
which does hold a valid edge certificate — reports

    SSL_do_handshake() failed (SSL: ... tlsv1 alert internal error) while SSL
    handshaking to upstream, upstream: "https://100.68.173.37:443/"
    -> 502 to the browser

So AIO runs in its **documented reverse-proxy mode**: TLS terminates at the edge
(NPM), and the AIO apache speaks plain HTTP on a private port. This is the same
shape as every estate service behind NPM.

AIO decides this from `APACHE_PORT` alone (`/start.sh` in the apache image):

```sh
if [ "$APACHE_PORT" != '443' ]; then
    export PROTOCOL="http"; export NC_DOMAIN=""     # plain http, any Host
    auto_https off                                   # no ACME at all
    TRUSTED_PROXIES="trusted_proxies static private_ranges 100.64.0.0/10"  # tailnet
```

`100.64.0.0/10` is the tailnet range, so a proxy on CasaOS is a trusted proxy and
the real client IP / `X-Forwarded-Proto: https` reach Nextcloud intact.

## The two long-lived settings

**1. The mastercontainer carries the mode.** It recreates every other AIO
container, so the flag lives on it:

```sh
docker run -d --name nextcloud-aio-mastercontainer --restart always \
  --network nextcloud-aio -p 80:80 -p 8080:8080 -p 8443:8443 \
  -e APACHE_PORT=11000 \
  -v nextcloud_aio_mastercontainer:/mnt/docker-aio-config \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  ghcr.io/nextcloud-releases/all-in-one:latest
```

If this container is ever recreated **without** `-e APACHE_PORT=11000`, the next
"Start containers" in the AIO interface puts Caddy back on :443 with ACME and the
502 returns. That env var is the whole configuration.

**2. The apache container follows it** (`-p 11000:11000`, `APACHE_PORT=11000`).
It holds only Caddy's own storage (`nextcloud_aio_apache`) plus a read-only mount
of the web root (`nextcloud_aio_nextcloud`); recreating it touches no user data.

## NPM side

Proxy host `files.safehomelan.com` (id 53, `proxy_host/53.conf`):

    forward_scheme  http
    forward_host    100.68.173.37
    forward_port    11000
    Force SSL       on   (so X-Forwarded-Proto: https)

Recorded in NPM's `database.sqlite` **and** in the generated `53.conf`; editing
only the `.conf` works until the next save in the NPM UI, which regenerates it
from the database.

## Checks

```sh
# from any tailnet host
curl -s https://files.safehomelan.com/status.php        # {"installed":true,...}
curl -s -o /dev/null -w '%{http_code}\n' -X PROPFIND https://files.safehomelan.com/remote.php/dav/files/   # 401
curl -s -o /dev/null -w '%{http_code}\n' https://files.safehomelan.com/hosting/discovery                  # 200

# on files: the apache is plain HTTP on 11000 and never talks ACME
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:11000/status.php
docker logs --tail 20 nextcloud-aio-apache | grep -i acme    # nothing
```

Diagnosing a 502 from NPM is one command — it names the upstream it could not
talk to:

```sh
docker exec nginxproxymanager tail -5 /data/logs/proxy-host-53_error.log
```

## Unchanged by this setup

`overwriteprotocol=https`, `overwritehost=files.safehomelan.com` and
`overwrite.cli.url` stay as AIO sets them, so Nextcloud still emits https URLs.
The AIO management interface is still reached directly on
`https://files.safehomelan.com:8443` (or `:8080`), not through NPM.
