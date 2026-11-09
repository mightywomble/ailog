# homelab-ops

One repo for the swarm: app sources, stack files, mirror list and the pipeline
that ships them. Replaces `homelab_docker_build` + `homelab_docker_deploy`.

```
wizard.yaml              the source of truth: image, version, ports, url, replicas
apps/<app>/              Dockerfile or build.json (+ patch.sh, test.sh)
stacks/<app>/stack.yml   rendered from wizard.yaml, hand-editable
compose/<name>/          a project on a host that is NOT a swarm node
mirror-images.json       upstream images to cache into zot
tools/pin_build_tag.py   writes the tag a run deployed back into the pins
```

## Two kinds of host

| | descibed by | shipped by | rolled back by |
|---|---|---|---|
| swarm service | `stacks/<name>/stack.yml` | `ship.yml` → `docker stack deploy` | `ship.yml` refuses a stack whose images are absent from zot |
| plain docker host | `compose/<name>/{compose.yml, project.json}` | `compose.yml` → `pull`, `up -d --wait` | the previous file, if the health check does not answer |

A compose project is three files:

```
compose.yml     the deployable file - images point at zot, and the version is
                written literally (a variable in the host's .env outranks the
                default beside it, which is how immich kept pulling :v3 after
                the file said v3.3.6)
project.json    host, ssh target, directory, health check, .env keys
.env.example    the keys the host's .env must define - never the values
```

The `.env` stays on the host, in `/home/david/code/<project>`. The pipeline
logs the host in to zot (it does the pulling), refuses a project whose `.env` is
missing a key, and reads the deployed tree from `Settings → Docker`.

CasaOS hosts are out of scope by name: their compose projects belong to CasaOS.

## The shape of a change

```
edit wizard.yaml (or the wizard UI)
        │
   push dev ──► build.yml      build every changed app, smoke test, no push
        │
      PR dev → main ──► ship.yml
                          release: build changed apps → zot/<app>:build-<run> + :latest
                          deploy:  docker stack deploy changed stacks with
                                   IMAGE_TAG=build-<run>
```

`ship.yml` runs release and deploy **in one workflow**, so the stack that gets
deployed always references the image that was just built. There is no second
repo and no "bump the tag over there" commit. Stack files for locally built
apps use `image: zot.safehomelan.com/<app>:${IMAGE_TAG:-<pinned>}`; mirrored and
upstream images keep literal tags and ignore the variable.

## Services that are not stacks

Nextcloud AIO runs outside the swarm on the `files` host, behind the NPM ingress
on CasaOS. It needed its own shape (plain HTTP on a private port, TLS at the
edge) because its domain is tailnet-only and AIO's built-in ACME can never
succeed for it: see [docs/nextcloud-aio.md](docs/nextcloud-aio.md). Because the
mastercontainer recreates its own containers, AIO also owns its own updates -
AILog refuses them by name rather than undoing them.

## The rest of the fleet

`wizard.yaml` is not the whole homelab. The CasaOS apps on `casaos` and immich on
`photos` are plain compose projects; the swarm services AILog does not
pin are plain swarm services. Which shape each host uses, and why the button is
greyed out on the ones that are neither, is in
[docs/fleet.md](docs/fleet.md).

## Wizard

https://wizard.safehomelan.com — `apps/homelab-wizard`. Nine stages: source →
compose → stack file → ports → details → url → build → test. Every long action
(pull, build, ship, tests) is a job streamed over SSE.

- **ports** merges four sources: `wizard.yaml`, `docker service ls`, `ss -tln`
  on every node (catches host-mode binds), and the nginx proxy_host table.
- **AI convert** calls OpenRouter with the swarm rules that have bitten this
  cluster (placement under `deploy:`, no `env_file` / `depends_on` conditions /
  `network_mode: service:*`), then `compose_check.validate_stack` proves the
  result before it is offered.
- **url** writes the NPM proxy host (SQLite row + rendered conf + `nginx -t`)
  and the Pi-hole record.
- **test** reports replicas, ingress port, DNS, TLS, HTTP and an optional
  credentialed request, plus the URL to hand to a person.

## Runners

Both runners are instance-level: `build` (labels `ubuntu-latest`, `build`) and
`swarm-manager` (label `deploy`).

## Secrets

`ZOT_URL` `ZOT_USER` `ZOT_PASSWORD` `GIT_API_KEY` `GIT_SERVER_URL` `GIT_USER`
(Gitea refuses `GITHUB_`/`GITEA_` prefixes).

## Deploy rules the wizard relies on

`ship.yml` exports `IMAGE_TAG` for a stack **only if** that stack references an
app the same run pushed *and* that tag is actually in zot. Everything else
deploys with the pinned fallback in the stack file:

```yaml
image: zot.safehomelan.com/<app>:${IMAGE_TAG:-build-48}
```

That pin is what a stacks-only change falls back to, so it must stay real. After
a successful `ship`, the wizard scrapes the release job log for
`released <registry>/<app>:build-<n>`, bumps `version:` in `wizard.yaml`,
re-renders the stack and commits the pin. A stale pin is not a cosmetic problem:
on run 37 it made every task get rejected with
`build-37: not found`.

## AI compose conversion

`POST /api/ai/convert` needs a live OpenRouter key. `GET /api/models` returns the
catalogue with or without one (`/api/v1/models` is public), so
`GET /api/ai/health` makes a real call to `/api/v1/key` — the settings panel's
**test key** button uses it. `401 {"error":{"message":"User not found."}}` means
the key was revoked or deleted, not that the model is wrong.
