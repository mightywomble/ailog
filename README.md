# homelab-ops

One repo for the swarm: app sources, stack files, mirror list and the pipeline
that ships them. Replaces `homelab_docker_build` + `homelab_docker_deploy`.

```
wizard.yaml              the source of truth: image, version, ports, url, replicas
apps/<app>/              Dockerfile or build.json (+ patch.sh, test.sh)
stacks/<app>/stack.yml   rendered from wizard.yaml, hand-editable
mirror-images.json       upstream images to cache into zot
.gitea/workflows/        build.yml · mirror.yml · ship.yml
```

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
