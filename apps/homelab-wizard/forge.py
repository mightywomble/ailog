"""forge: gitea actions + nginx proxy manager + pi-hole."""
import json
import time

import httpx

import core
import swarmio


class ForgeError(RuntimeError):
    pass


# ------------------------------------------------------------------ gitea

class Gitea:
    def __init__(self, settings=None):
        s = settings or core.load()
        core.require(s, "gitea_token")
        self.api = s["gitea_url"].rstrip("/") + "/api/v1"
        self.path = f"/repos/{s['gitea_owner']}/{s['gitea_repo']}"
        self.http = httpx.Client(timeout=30, headers={"Authorization": f"token {s['gitea_token']}"})

    def runs(self, limit=20):
        r = self.http.get(f"{self.api}{self.path}/actions/runs", params={"limit": limit})
        r.raise_for_status()
        return r.json().get("workflow_runs") or []

    def run(self, run_id):
        r = self.http.get(f"{self.api}{self.path}/actions/runs/{run_id}")
        r.raise_for_status()
        return r.json()

    def jobs(self, run_id):
        r = self.http.get(f"{self.api}{self.path}/actions/runs/{run_id}/jobs")
        return r.json().get("jobs") or [] if r.status_code == 200 else []

    def job_log(self, job_id):
        r = self.http.get(f"{self.api}{self.path}/actions/jobs/{job_id}/logs")
        return "" if r.status_code == 404 else r.text

    def find_run(self, workflow, sha=None, newer_than=0, timeout=150):
        deadline = time.time() + timeout
        while time.time() < deadline:
            for run in self.runs(limit=30):
                if (run.get("path") or "").split("@", 1)[0] != workflow:
                    continue
                if sha and run.get("head_sha") != sha:
                    continue
                if run.get("id", 0) <= newer_than:
                    continue
                return run
            time.sleep(3)
        return None

    def dispatch(self, workflow, ref="main"):
        """Start a workflow by hand.

        The mirror only runs on a push that changes mirror-images.json, which is
        no help when the file is already correct on the branch (or when the
        paths filter never fired) - so the pipeline can ring the bell itself.
        """
        r = self.http.post(f"{self.api}{self.path}/actions/workflows/{workflow}/dispatches",
                           json={"ref": ref})
        if r.status_code >= 400:
            raise ForgeError(f"dispatch {workflow} -> {r.status_code} {r.text[:200]}")
        return {"workflow": workflow, "ref": ref, "status": r.status_code}

    def create_pr(self, title, head, base="main", body=""):
        r = self.http.post(f"{self.api}{self.path}/pulls",
                           json={"title": title, "head": head, "base": base, "body": body})
        if r.status_code == 409:
            for pr in self.open_prs():
                if pr["head"]["ref"] == head:
                    return pr
        if r.status_code >= 400:
            raise ForgeError(f"create PR -> {r.status_code} {r.text[:200]}")
        return r.json()

    def open_prs(self):
        r = self.http.get(f"{self.api}{self.path}/pulls", params={"state": "open"})
        return r.json() if r.status_code == 200 else []

    def merge_pr(self, index, attempts=8):
        """Gitea answers 405 {"message":"Please try again later"} while another
        merge (or its own index update) is in flight. It is a lock, not a
        failure: back off and retry, then give up with the last response."""
        last = ""
        delay = 1.0
        for attempt in range(attempts):
            r = self.http.post(f"{self.api}{self.path}/pulls/{index}/merge",
                               json={"Do": "merge", "delete_branch_after_merge": False})
            if r.status_code in (200, 201):
                return {"merged": True, "attempts": attempt + 1}
            last = f"{r.status_code} {r.text[:160]}"
            time.sleep(delay)
            delay = min(delay * 2, 8.0)
        raise ForgeError(f"merge PR #{index} after {attempts} attempts: {last}")


# ------------------------------------------------------------------ nginx

def _remote(settings, script, timeout=90):
    return swarmio.run(settings["casaos_ip"], f"sudo python3 - <<'WIZEOF'\n{script}\nWIZEOF",
                       timeout=timeout)


def _json_list(value):
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else [parsed]
    except Exception:
        return [value] if value else []


def list_hosts(settings):
    out = _remote(settings, f"""
import json, sqlite3
con = sqlite3.connect({settings['npm_db']!r})
print(json.dumps(con.execute("select id, domain_names, forward_host, forward_port, certificate_id, enabled "
                             "from proxy_host where is_deleted=0 order by id").fetchall()))
""")
    rows = json.loads(out.strip().splitlines()[-1] or "[]")
    return [{"id": r[0], "domains": _json_list(r[1]), "forward_host": r[2],
             "forward_port": r[3], "certificate_id": r[4], "enabled": r[5]} for r in rows]


def certificates(settings):
    out = _remote(settings, f"""
import json, sqlite3
con = sqlite3.connect({settings['npm_db']!r})
print(json.dumps(con.execute("select id, nice_name, domain_names from certificate "
                             "where is_deleted=0").fetchall()))
""")
    rows = json.loads(out.strip().splitlines()[-1] or "[]")
    return [{"id": r[0], "nice_name": r[1], "domains": _json_list(r[2])} for r in rows]


def _conf(host_id, domain, forward_host, forward_port, cert_nice, advanced, scheme="http"):
    ssl = ""
    if cert_nice:
        ssl = ("  listen 443 ssl;\n  listen [::]:443 ssl;\n"
               "  include conf.d/include/ssl-cache.conf;\n"
               "  include conf.d/include/ssl-ciphers.conf;\n"
               f"  ssl_certificate /etc/letsencrypt/live/{cert_nice}/fullchain.pem;\n"
               f"  ssl_certificate_key /etc/letsencrypt/live/{cert_nice}/privkey.pem;\n"
               "  set $trust_forwarded_proto \"F\";\n"
               "  include conf.d/include/force-ssl.conf;\n")
    adv = f"  {advanced}\n" if advanced else ""
    return f"""# {domain} - created by homelab-wizard (proxy host {host_id})
server {{
  set $forward_scheme {scheme};
  set $server         "{forward_host}";
  set $port           {int(forward_port)};

  listen 80;
  listen [::]:80;
{ssl}
  server_name {domain};
  http2 off;

  include conf.d/include/letsencrypt-acme-challenge.conf;
{adv}
  access_log /data/logs/proxy-host-{host_id}_access.log proxy;
  error_log /data/logs/proxy-host-{host_id}_error.log warn;

  location / {{
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $http_connection;
    proxy_http_version 1.1;
    include conf.d/include/proxy.conf;
  }}

  include /data/nginx/custom/server_proxy[.]conf;
}}
"""


def _cert_nice(settings, cert_id):
    """NPM names the cert directory after the certificate id (certificate 1 ->
    /etc/letsencrypt/live/npm-1), NOT after nice_name, which is the domain."""
    return f"npm-{int(cert_id)}" if cert_id else None


def create_host(settings, domain, forward_host, forward_port, cert_id=None,
                advanced="", dry_run=False):
    clash = [h for h in list_hosts(settings) if domain in h["domains"]]
    if clash:
        raise ForgeError(f"{domain} already has a proxy host (id {clash[0]['id']})")
    if dry_run:
        return {"domain": domain, "forward": f"{forward_host}:{forward_port}", "dry_run": True,
                "sql": (f"insert into proxy_host(domain_names, forward_host, forward_port, "
                        f"certificate_id, enabled, created_on, modified_on) values "
                        f"('{json.dumps([domain])}', '{forward_host}', {forward_port}, "
                        f"{cert_id or 0}, 1, datetime('now'), datetime('now'));"),
                "conf": _conf("NEW", domain, forward_host, forward_port,
                              _cert_nice(settings, cert_id), advanced)}

    host_id = int(_remote(settings, f"""
import json, sqlite3
con = sqlite3.connect({settings['npm_db']!r})
cur = con.cursor()
owner = con.execute("select id from user order by id limit 1").fetchone()[0]
cur.execute("insert into proxy_host (owner_user_id, domain_names, forward_host, forward_port, "
            "forward_scheme, certificate_id, ssl_forced, http2_support, advanced_config, meta, "
            "enabled, is_deleted, created_on, modified_on) "
            "values (?,?,?,?,?,?,?,?,?,?,?,?, datetime('now'), datetime('now'))",
            (owner, json.dumps([{domain!r}]), {forward_host!r}, {int(forward_port)}, 'http',
             {int(cert_id or 0)}, {1 if cert_id else 0}, 0, {advanced!r},
             json.dumps({{"nginx_online": True}}), 1, 0))
host_id = cur.lastrowid
con.commit()
print(host_id)
""").strip().splitlines()[-1])

    conf = _conf(host_id, domain, forward_host, forward_port,
                 _cert_nice(settings, cert_id), advanced)
    _remote(settings, f"open({settings['npm_conf_dir']!r} + '/{host_id}.conf', 'w').write({conf!r})")
    out = swarmio.run(settings["casaos_ip"],
                      "docker exec nginxproxymanager nginx -t 2>&1 && "
                      "docker exec nginxproxymanager nginx -s reload && echo RELOADED", timeout=90)
    if "RELOADED" not in out:
        raise ForgeError(f"nginx reload failed: {out[-300:]}")
    return {"id": host_id, "domain": domain, "url": f"https://{domain}",
            "certificate": _cert_nice(settings, cert_id), "conf": conf}


def add_dns(settings, hostname, ip=None):
    """Pi-hole record so LAN clients resolve internally instead of hairpinning."""
    ip = ip or settings["ingress_ip"]
    try:
        out = _remote(settings, f"""
import json, urllib.request
body = json.dumps({{"ip": "{ip}", "hostname": "{hostname}", "restart": True}}).encode()
req = urllib.request.Request("http://{settings['pihole_ip']}/admin/api.php", body,
                             {{"Content-Type": "application/json"}})
try:
    print(urllib.request.urlopen(req, timeout=10).read().decode()[:200])
except Exception as exc:
    print("ERR", exc)
""", timeout=40)
        return {"hostname": hostname, "ip": ip, "ok": "ERR" not in out, "detail": out.strip()[:200]}
    except Exception as exc:
        return {"hostname": hostname, "ip": ip, "ok": False, "detail": str(exc)[:200]}
