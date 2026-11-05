# The fleet, and who owns each container

AILog can update a container only when it can name the thing that created it.
This page is the inventory of the four shapes that exist here and which hosts
are in which, so "the update button is greyed out on that host" is a documented
answer rather than a bug report.

## The four shapes

| shape | what owns it | how an update runs |
|-------|--------------|--------------------|
| `estate` | `wizard.yaml` + the stack file, deployed by `ship.yml` | AILog commits the bump, CI builds/mirrors and deploys. Never `docker` on the host. |
| `compose` | a docker-compose project on that host | `docker compose -f <files> pull <svc…>` then `up -d --no-deps <svc…>` |
| `swarm` | a swarm service the estate does not pin | `docker service update --image … --force --with-registry-auth` on a manager |
| `container` | nothing docker recorded | refused, with the reason |

There is exactly one writer to `wizard.yaml`: the estate, in AILog. The
homelab-wizard used to roll images forward itself with its own tag resolution,
its own commit and its own wait for CI, which meant two programs could answer
"what is pinned" differently and whoever ran second won. That path is retired -
the wizard's `update` now refuses and says where the button went - and it keeps
only the jobs that create: the new-service and compose-to-stack journeys.

A `compose` target can carry more than one service. When a publisher ships a set
at one version - `immich-server` and `immich-machine-learning` are the case
here - the services are pulled and recreated together, because the server
refuses to run against a machine-learning container from a different release.
The test for a set is narrow on purpose: same project, same image family, same
tag. `matrix-server` has four services whose names start with `matrix` and they
must *not* be treated as a set, because that would bounce postgres and redis to
update synapse.

## Hosts

### swarm (`estate`)

`swarm-manager` (db-11), `worker2` (db-13), `swarm-worker4` (db-15). Everything
in `wizard.yaml` is deployed from git by `ship.yml`; the estate page
(`/estate` in AILog) is the complete list and is the only correct place to move
one of them forward.

`swarm-worker1` (db-12) and `swarm-worker3` (db-14) are **Down**. They are still
cluster members, so the scheduler simply places no tasks there; nothing in this
repo needs to change until the machines come back.

### casaos (db-16) - compose

CasaOS apps, one compose project each, config under
`/var/lib/casaos/apps/<app>/docker-compose.yml`:

- `gitea` - `gitea/gitea:latest`
- `big-bear-pihole` - `pihole/pihole:latest`
- `nginxproxymanager` - `jc21/nginx-proxy-manager:latest`
- `managelm` - `managelm/portal:latest`, `postgres:16-alpine`, `redis:7-alpine`

Plus `portainer_agent`, a bare `docker run` container and therefore refused.

Because these pin `:latest`, drift is judged on the image digest rather than the
tag, which is exactly the case the tag comparison cannot answer.

### photos (db-8) - compose

`immich`, from `/home/david/code/immich/docker-compose.yaml`. Four services, two
of which are the versioned set described above; `immich-postgres` and
`immich_redis` carry their own pins and are updated only by a deliberate immich
upgrade.

### matrix (db-5) - compose

`matrix-server`, from `/home/david/code/matrix-server/docker-compose.yml` plus
its override file. Seventeen containers, of which several are built locally
(`matrix-infinigpt:local`, `matrix-mcp-server:local`) or pinned to `:latest` at
the publisher's discretion. Local images have no registry to compare against, so
they report no update rather than a false one.

### files (db-3) - managed by Nextcloud AIO

`nextcloud-aio`, fourteen containers plus the mastercontainer. AIO creates and
recreates its own containers, so AILog refuses them by name. Updates happen in
the AIO interface. See [nextcloud-aio.md](nextcloud-aio.md).

### No docker

`netdata` (db-6), `nfs` (db-7), `pve` (db-17), `pve2` (db-18) have no docker
engine, and `Davids-Mac-mini.local` (db-1) reports `docker_not_installed`. They
are reachable for logs and metrics and appear in the Docker view as such.

## Adding a host

1. add it in AILog's host list (friendly name + ssh address),
2. make sure passwordless sudo works for the docker commands if the user is not
   in the `docker` group - the runner uses `sudo -n` only when it succeeds,
3. that is all: the shape is discovered from the container labels, never
   configured.
