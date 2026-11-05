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
outside in means each step is small and each app is verified before the next one
depends on it.

| # | stack | secrets | notes |
|---|-------|---------|-------|
| 1 | status | `status_pve_token`, `metamcp_api_key` | ✅ done. Read-only PVE token; the MetaMCP key is shared with ingest, so it is one secret, not two. |
| 2 | ingest | `ANYTHINGLLM_API_KEY`, `WP_APP_PASSWORD`, `GITEA_TOKEN`, `metamcp_api_key` | metamcp_api_key is already created. |
| 3 | langlearn | `APP_PASSWORD`, `SECRET_KEY` | |
| 4 | wordpress + postgres | `*_FILE` | postgres natively supports `POSTGRES_PASSWORD_FILE`; this is the one case with no helper needed. |
| 5 | metamcp, vikunja, ailog | database and session secrets | |
| 6 | patchmon | six secrets, including `POSTGRES_PASSWORD` and `REDIS_PASSWORD` | last because it has the most moving parts (api, worker, postgres, redis). |

## Things that must not be rotated to do this

Moving a value into a secret is not the moment to change it. `POSTGRES_PASSWORD`
and the password already stored inside the database have to agree, so the secret
is created with the *current* value and the database keeps working. Rotating is a
separate job, done inside the application, with both containers coordinated.

`AILOG_SECRET_KEY` is worse: it signs sessions, so changing it logs everyone out.
Same rule - move it, do not change it.
