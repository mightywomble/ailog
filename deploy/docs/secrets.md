# Credentials belong in Docker secrets

The stack files are in git. Every plaintext credential in them is published to
anyone who can read the repository, and a `docker service inspect` prints it
back for anyone with a shell on a manager. The convention, and the order the
remaining ones are being moved in, is below.

## The convention

1. create the secret once, on a manager:

   ```sh
   printf %s "$VALUE" | docker secret create status_pve_token -
   ```

2. mount it in the stack, and declare it at the bottom of the file:

   ```yaml
       secrets:
         - status_pve_token
   ...
   secrets:
     status_pve_token:
       external: true
   ```

3. the container reads `/run/secrets/status_pve_token`. An app that does not
   natively support `_FILE` variables gets a five-line reader:

   ```python
   def secret(name, env=""):
       for path in (f"/run/secrets/{name}",):
           try:
               with open(path, encoding="utf-8") as handle:
                   text = handle.read().strip()
               if text:
                   return text
           except OSError:
               pass
       return os.environ.get(env or name.upper(), "")
   ```

   The environment stays as the *last* fallback so a container started by hand -
   the smoke test, a debugging run - still works.

4. delete the line from the stack file in the same commit. Never leave both: a
   stack that still exports the value keeps leaking it, and it hides the fact
   that the secret is doing anything.

## Why this order

A credential is only as good as its consumers. Poisoning the well from the
outside in means each step is small, and each app is verified - a real request
that needs the credential, not just "the container is up" - before the next one
depends on it.

| # | stack | secrets | notes |
|---|-------|---------|-------|
| 1 | status | `status_pve_token`, `metamcp_api_key` | ✅ read-only PVE token; the MetaMCP key is shared with ingest, so it is one secret, not two |
| 2 | ingest | `anythingllm_api_key`, `wp_app_password`, `gitea_token`, `metamcp_api_key` | ✅ verified: AnythingLLM health 200 and 66 Gitea documents re-synced on the secret |
| 3 | langlearn | `langlearn_app_password`, `langlearn_secret_key` | ✅ mirrored image with no `_FILE` support, so the stack `command` exports both from `/run/secrets` and execs the image's own CMD |
| 4 | wordpress + mysql | `wordpress_db_password` | ✅ both images support `_FILE` natively - no wrapper. Verified with a live `mysqli` connect from the wordpress container |
| 5 | metamcp | `metamcp_postgres_password`, `metamcp_auth_secret`, `metamcp_bootstrap_password` | ✅ `DATABASE_URL` embeds the password, so the wrapper rebuilds it - leaving it in the file would have put the value straight back |
| 6 | ailog | `ailog_secret_key`, `ailog_mcp_token`, `ailog_sshkey_master_key` | ✅ `utils/secretfiles.py` in the app; moved in two stages so the master key was never briefly absent |
| 7 | patchmon | five secrets | ✅ server wrapper rebuilds `DATABASE_URL`; database uses `POSTGRES_PASSWORD_FILE`; redis gets `--requirepass` from the file, healthcheck included, so the password is not in argv |
| 8 | netbox-mcp | `netbox_mcp_token`, `netbox_mcp_auth_token` | ✅ upstream `netbox-mcp-server` reads `NETBOX_TOKEN` and `MCP_AUTH_TOKEN` from the environment only, so the stack `command` exports both from `/run/secrets` and execs the server. The NetBox token is a v2 (`nbt_...`) read-only token on `svc-netbox-mcp`; the auth token is the bearer the MCP itself demands (MetaMCP sends it as `bearerToken`) |
| — | vikunja | three | ❌ **blocked - see below** |

## The one that cannot be moved yet: vikunja

`zot.safehomelan.com/vikunja:2.7.1` is a mirrored upstream image built from
scratch. It has no `/bin/sh`:

```
docker run --rm --entrypoint /bin/sh .../vikunja:2.7.1 -c true
# exec: "/bin/sh": stat /bin/sh: no such file or directory
```

and Vikunja has no `_FILE` variant of `VIKUNJA_DATABASE_PASSWORD` or
`VIKUNJA_SERVICE_SECRET`. With no shell to read the file and no variable to
point at it, there is nothing to hook: the three values stay in the stack file
until one of these happens.

1. upstream adds `_FILE` support (ask, do not wait),
2. we build vikunja ourselves - an `apps/vikunja` with a `build.json` that pulls
   the upstream release, adds a shell and a `_FILE` reader - which is a real
   image to own and maintain,
3. it moves to a stack we control entirely.

Do not half-move it: switching only the postgres side to
`POSTGRES_PASSWORD_FILE` while vikunja still carries the same password in its
own environment gains nothing and hides the fact that the credential is still
published.

## Things that must not be rotated to do this

Moving a value into a secret is not the moment to change it. `POSTGRES_PASSWORD`
and the password already stored inside the database have to agree, so the secret
is created with the *current* value and the database keeps working. Rotating is a
separate job, done inside the application, with both containers coordinated.

`AILOG_SECRET_KEY` is worse: it signs sessions, so changing it logs everyone out.
Same rule - move it, do not change it.
