"""ingest — move homelab knowledge into AnythingLLM and show what landed.

Sources
  wordpress   WordPress REST API -> markdown, one document per post
  gitea       Gitea REST API -> one document per repository README
  lan         MetaMCP tools -> one document per subsystem (ingress, dns, patching,
              monitoring, tailnet, fleet)
  goose       POST /api/goose with a run summary (used by the goose summariser)

Everything is written into the AnythingLLM workspace as a document in a per-source
folder, tagged through metadata (source / docSource / chunkSource), and recorded in
a local SQLite manifest so re-syncs are idempotent and the UI can show what was
moved, when, from where.

The app is read-mostly: the only mutations are "sync a source now" and "remove a
document". Dry-run is the default for the manual buttons.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------
ANY = os.environ.get("ANYTHINGLLM_URL", "http://anythingllm:3001").rstrip("/")
ANY_KEY = os.environ.get("ANYTHINGLLM_API_KEY", "")
WORKSPACE = os.environ.get("ANYTHINGLLM_WORKSPACE", "my-workspace")

WP_URL = os.environ.get("WP_URL", "https://www.daveknowstech.com").rstrip("/")
WP_USER = os.environ.get("WP_USER", "")
WP_APP_PASSWORD = os.environ.get("WP_APP_PASSWORD", "").replace(" ", "")

GITEA_URL = os.environ.get("GITEA_URL", "https://git.safehomelan.com").rstrip("/")
GITEA_TOKEN = os.environ.get("GITEA_TOKEN", "")
GITEA_OWNER = os.environ.get("GITEA_OWNER", "david")

MCP_URL = os.environ.get("METAMCP_URL", "").rstrip("/")
MCP_KEY = os.environ.get("METAMCP_API_KEY", "")

DB_PATH = os.environ.get("INGEST_DB", "/data/ingest.db")
MAX_DOC_BYTES = int(os.environ.get("INGEST_MAX_DOC_BYTES", "400000"))
GOOSE_FOLDER = os.environ.get("GOOSE_FOLDER", "goose-runs")

app = FastAPI(title="homelab ingest", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

FOLDERS = {"wordpress": "wordpress", "gitea": "gitea", "lan": "lan", "goose": GOOSE_FOLDER}
SOURCE_LABELS = {
    "wordpress": "WordPress posts",
    "gitea": "Gitea READMEs",
    "lan": "LAN inventory (MetaMCP)",
    "goose": "Goose run summaries",
}

# ---------------------------------------------------------------------------
# manifest
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS docs (
  source TEXT NOT NULL,
  source_key TEXT NOT NULL,
  title TEXT NOT NULL,
  folder TEXT NOT NULL,
  docpath TEXT,
  status TEXT NOT NULL DEFAULT 'new',
  sha TEXT,
  words INTEGER,
  source_updated TEXT,
  synced_at TEXT,
  last_error TEXT,
  PRIMARY KEY (source, source_key)
);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT, started_at TEXT, finished_at TEXT,
  dry_run INTEGER DEFAULT 0,
  added INTEGER DEFAULT 0, updated INTEGER DEFAULT 0, removed INTEGER DEFAULT 0,
  skipped INTEGER DEFAULT 0, errors INTEGER DEFAULT 0, detail TEXT
);
"""


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    with closing(db()) as c:
        c.executescript(SCHEMA)
        c.commit()


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# AnythingLLM client
# ---------------------------------------------------------------------------
class Anything:
    def __init__(self) -> None:
        self.c = httpx.Client(timeout=180.0, base_url=ANY,
                              headers={"Authorization": f"Bearer {ANY_KEY}"})

    def health(self) -> dict:
        try:
            r = self.c.get("/api/v1/auth")
            return {"ok": r.status_code == 200, "status": r.status_code}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def vector_count(self) -> int | None:
        try:
            return self.c.get("/api/v1/system/vector-count").json().get("vectorCount")
        except Exception:
            return None

    def workspace(self) -> dict:
        try:
            return self.c.get(f"/api/v1/workspace/{WORKSPACE}").json().get("workspace", [{}])[0]
        except Exception as exc:
            return {"error": str(exc)}

    def ensure_folder(self, folder: str) -> None:
        try:
            self.c.post("/api/v1/document/create-folder", json={"name": folder})
        except Exception:
            pass  # already exists is a 4xx we do not care about

    def upload(self, folder: str, filename: str, content: str, metadata: dict) -> dict:
        """Upload markdown into a folder and embed it into the workspace."""
        self.ensure_folder(folder)
        r = self.c.post(
            f"/api/v1/document/upload/{folder}",
            files={"file": (filename, content.encode("utf-8"), "text/markdown")},
            data={"addToWorkspaces": WORKSPACE,
                  "metadata": json.dumps(metadata)},
        )
        r.raise_for_status()
        docs = r.json().get("documents") or []
        if not docs:
            raise RuntimeError(f"upload returned no document: {r.text[:200]}")
        return docs[0]

    def remove(self, locations: list[str]) -> dict:
        if not locations:
            return {"success": True}
        r = self.c.request("DELETE", "/api/v1/system/remove-documents", json={"names": locations})
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# MetaMCP (streamable HTTP) client
# ---------------------------------------------------------------------------
class Mcp:
    def __init__(self) -> None:
        self.sid: str | None = None
        self.c = httpx.Client(timeout=180.0,
                              headers={"content-type": "application/json",
                                       "accept": "application/json, text/event-stream",
                                       "x-api-key": MCP_KEY})
        self._init()

    def _post(self, payload: dict) -> list[dict]:
        headers = {}
        if self.sid:
            headers["mcp-session-id"] = self.sid
        r = self.c.post(MCP_URL, json=payload, headers=headers)
        r.raise_for_status()
        sid = r.headers.get("mcp-session-id")
        if sid:
            self.sid = sid
        out = []
        for chunk in r.text.split("\n\n"):
            for line in chunk.splitlines():
                if line.startswith("data: "):
                    out.append(json.loads(line[6:]))
        return out

    def _init(self) -> None:
        self._post({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "ingest", "version": "1"}}})
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def call(self, tool: str, args: dict | None = None) -> Any:
        res = self._post({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                          "params": {"name": tool, "arguments": args or {}}})
        if not res:
            raise RuntimeError("empty MCP response")
        result = res[0].get("result", {})
        if result.get("isError"):
            raise RuntimeError(str(result.get("content"))[:300])
        if "structuredContent" in result:
            return result["structuredContent"]
        text = (result.get("content") or [{}])[0].get("text", "")
        try:
            return json.loads(text)
        except Exception:
            return text


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
TAG_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.S | re.I)
BLOCK_RE = re.compile(r"</(p|div|h[1-6]|li|tr|pre|blockquote)>", re.I)


def html_to_md(raw: str) -> str:
    """Small, dependency-free HTML -> markdown for post bodies."""
    s = TAG_RE.sub("", raw or "")
    # drop social/embed widgets that WordPress injects into content.rendered
    s = re.sub(r'<div[^>]*class="[^"]*(sharethis|sharedaddy|jp-relatedposts)[^"]*"[^>]*>.*?</div>',
               "", s, flags=re.S | re.I)
    s = re.sub(r"<figure[^>]*wp-block-embed[^>]*>.*?</figure>", "", s, flags=re.S | re.I)
    s = re.sub(r"<!--.*?-->", "", s, flags=re.S)
    s = re.sub(r"<pre[^>]*>(.*?)</pre>", lambda m: "\n```\n" + re.sub(r"<[^>]+>", "", m.group(1)).strip() + "\n```\n",
               s, flags=re.S | re.I)
    s = re.sub(r"<h([1-6])[^>]*>(.*?)</h\1>",
               lambda m: "\n" + "#" * int(m.group(1)) + " " + re.sub(r"<[^>]+>", "", m.group(2)).strip() + "\n",
               s, flags=re.S | re.I)
    s = re.sub(r"<li[^>]*>", "\n- ", s, flags=re.I)
    s = re.sub(r"<a[^>]*href=\"([^\"]+)\"[^>]*>(.*?)</a>",
               lambda m: f"[{re.sub(r'<[^>]+>', '', m.group(2)).strip()}]({m.group(1)})",
               s, flags=re.S | re.I)
    s = re.sub(r"<br\s*/?>", "\n", s, flags=re.I)
    s = re.sub(r"<(strong|b)[^>]*>(.*?)</\1>", r"**\2**", s, flags=re.S | re.I)
    s = re.sub(r"<(em|i)[^>]*>(.*?)</\1>", r"*\2*", s, flags=re.S | re.I)
    s = re.sub(r"<img[^>]*src=\"([^\"]+)\"[^>]*alt=\"([^\"]*)\"[^>]*>", r"![\2](\1)", s, flags=re.I)
    s = re.sub(r"<code[^>]*>(.*?)</code>", r"`\1`", s, flags=re.S | re.I)
    s = BLOCK_RE.sub("\n\n", s)
    s = re.sub(r"<[^>]+>", "", s)
    s = html.unescape(s)
    s = re.sub(r"[ \t]+\n", "\n", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def words(text: str) -> int:
    return len(re.findall(r"\S+", text))


def record(source: str, key: str, title: str, folder: str, body: str,
           source_updated: str | None, dry_run: bool, run: dict) -> None:
    """Create/update one document. Idempotent: unchanged docs are skipped."""
    digest = sha(body)
    with closing(db()) as c:
        row = c.execute("SELECT * FROM docs WHERE source=? AND source_key=?", (source, key)).fetchone()
        if row and row["sha"] == digest and row["status"] == "synced":
            run["skipped"] += 1
            return
        if dry_run:
            run["updated" if row else "added"] += 1
            return

        anything = Anything()
        # delete the previous copy first: raw uploads mint a new location each time
        if row and row["docpath"]:
            try:
                anything.remove([row["docpath"]])
            except Exception:
                pass
        meta = {
            "title": title,
            "docSource": source,
            "chunkSource": f"{folder}/{key}",
            "source": source,
            "source_key": key,
            "collected_at": now(),
        }
        if source_updated:
            meta["published"] = source_updated
        try:
            doc = anything.upload(folder, f"{key}.md", body, meta)
            location = doc.get("location") or doc.get("url")
            c.execute("""INSERT INTO docs (source, source_key, title, folder, docpath, status, sha, words, source_updated, synced_at, last_error)
                         VALUES (?,?,?,?,?,'synced',?,?,?,?,NULL)
                         ON CONFLICT(source, source_key) DO UPDATE SET
                           title=excluded.title, docpath=excluded.docpath, status='synced', sha=excluded.sha,
                           words=excluded.words, source_updated=excluded.source_updated, synced_at=excluded.synced_at,
                           last_error=NULL""",
                      (source, key, title, folder, location, digest, words(body), source_updated, now()))
            c.commit()
            run["updated" if row else "added"] += 1
        except Exception as exc:
            c.execute("""INSERT INTO docs (source, source_key, title, folder, status, sha, words, source_updated, last_error)
                         VALUES (?,?,?,?,'error',?,?,?,?)
                         ON CONFLICT(source, source_key) DO UPDATE SET status='error', last_error=excluded.last_error""",
                      (source, key, title, folder, digest, words(body), source_updated, str(exc)[:400]))
            c.commit()
            run["errors"] += 1


# ---------------------------------------------------------------------------
# collectors
# ---------------------------------------------------------------------------
def collect_wordpress(dry_run: bool, run: dict) -> None:
    auth = (WP_USER, WP_APP_PASSWORD) if (WP_USER and WP_APP_PASSWORD) else None
    fields = "id,date,modified_gmt,slug,link,title,content,excerpt"
    with httpx.Client(timeout=90.0, auth=auth) as c:
        page = 1
        while True:
            params = {"per_page": 100, "page": page, "_fields": fields, "status": "publish"}
            if auth:
                params.update({"context": "edit", "status": "publish,draft,private,future"})
            r = c.get(f"{WP_URL}/wp-json/wp/v2/posts", params=params)
            if r.status_code == 400 and page > 1:
                break  # past the last page
            r.raise_for_status()
            posts = r.json()
            if not posts:
                break
            for p in posts:
                title = html.unescape(re.sub(r"<[^>]+>", "", p["title"]["rendered"]))
                body = html_to_md(p["content"]["rendered"])
                front = (f"---\ntitle: {title}\nwp_id: {p['id']}\nslug: {p['slug']}\n"
                         f"date: {p['date']}\nurl: {p['link']}\n---\n\n# {title}\n\n")
                record("wordpress", f"post-{p['id']}", title, FOLDERS["wordpress"],
                       front + body + "\n", p.get("modified_gmt"), dry_run, run)
            page += 1


def collect_gitea(dry_run: bool, run: dict) -> None:
    h = {"Authorization": f"token {GITEA_TOKEN}"} if GITEA_TOKEN else {}
    with httpx.Client(timeout=90.0, headers=h) as c:
        page = 1
        while True:
            r = c.get(f"{GITEA_URL}/api/v1/repos/search",
                      params={"limit": 50, "page": page, "sort": "updated"})
            r.raise_for_status()
            repos = r.json().get("data", [])
            if not repos:
                break
            for repo in repos:
                if repo.get("archived") or repo.get("fork"):
                    run["skipped"] += 1
                    continue
                full = repo["full_name"]
                raw = c.get(f"{GITEA_URL}/api/v1/repos/{full}/raw/README.md")
                if raw.status_code != 200 or len(raw.content) < 200:
                    run["skipped"] += 1
                    continue
                text = raw.text[:MAX_DOC_BYTES]
                front = (f"---\ntitle: {full}\nrepo: {full}\nurl: {repo.get('html_url')}\n"
                         f"default_branch: {repo.get('default_branch')}\n"
                         f"updated: {repo.get('updated_at')}\n---\n\n# {full}\n\n")
                record("gitea", full.replace("/", "__"), full, FOLDERS["gitea"],
                       front + text, repo.get("updated_at"), dry_run, run)
            page += 1


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        out.append("| " + " | ".join("" if v is None else str(v).replace("|", "\\|") for v in row) + " |")
    return "\n".join(out)


LAN_DOCS = {
    "ingress": ("Ingress map (Nginx Proxy Manager)", "nginx-proxy-manager__list_proxy_hosts", {}),
    "dns": ("DNS records (Pi-hole)", "pihole__pihole_local_dns_list", {}),
    "patching": ("Fleet patching (PatchMon)", "patchmon__list_hosts", {}),
    "monitoring": ("Monitoring (Netdata)", "netdata__list_nodes", {}),
    "tailnet": ("Tailnet devices (Tailscale)", "tailscale__list_devices", {}),
    "fleet": ("Fleet inventory (ManageLM)", "managelm__search_agents", {}),
}


def _render_lan(name: str, title: str, data: Any) -> str:
    body: list[str] = [f"# {title}", "", f"_Collected {now()} via MetaMCP._", ""]
    if name == "ingress" and isinstance(data, list):
        rows = []
        for h in data:
            domains = ", ".join(h.get("domain_names") or [])
            rows.append([domains, f"{h.get('forward_scheme')}://{h.get('forward_host')}:{h.get('forward_port')}",
                         "yes" if h.get("enabled") else "no",
                         "yes" if h.get("ssl_forced") else "no",
                         "yes" if h.get("allow_websocket_upgrade") else "no",
                         h.get("id")])
        body.append(_table(["Domain", "Forwards to", "Enabled", "SSL", "Websocket", "NPM id"], rows))
    elif name == "dns":
        text = data if isinstance(data, str) else json.dumps(data, indent=1)
        body += [text.strip(), ""]
    elif name == "patching" and isinstance(data, dict):
        rows = []
        for h in data.get("hosts", []):
            rows.append([h.get("friendly_name"), h.get("os_type"), h.get("os_version"),
                         h.get("updates_count"), h.get("security_updates_count"),
                         "yes" if h.get("needs_reboot") else "no", h.get("update_state"),
                         h.get("last_update")])
        body.append(_table(["Host", "OS", "Version", "Updates", "Security", "Reboot", "State", "Last seen"], rows))
    elif name == "monitoring" and isinstance(data, dict):
        rows = [[n.get("hostname"), n.get("node_id"), n.get("relationship"), n.get("connected")]
                for n in data.get("nodes", [])]
        body.append(_table(["Node", "Node id", "Relationship", "Connected"], rows))
    elif name == "tailnet" and isinstance(data, dict):
        rows = [[d.get("hostname"), d.get("name"), d.get("os"), d.get("authorized"),
                 ", ".join(d.get("addresses") or []), d.get("lastSeen")]
                for d in data.get("devices", [])]
        body.append(_table(["Host", "Name", "OS", "Authorised", "Addresses", "Last seen"], rows))
    elif name == "fleet":
        agents = data.get("agents") if isinstance(data, dict) else None
        rows = [[a.get("hostname"), a.get("status"), a.get("os_info")] for a in (agents or [])]
        body.append(_table(["Agent", "Status", "OS"], rows))
    else:
        body.append("```json\n" + json.dumps(data, indent=1)[:20000] + "\n```")
    return "\n".join(body) + "\n"


def collect_lan(dry_run: bool, run: dict, only: str | None = None) -> None:
    mcp = Mcp()
    for name, (title, tool, args) in LAN_DOCS.items():
        if only and only != name:
            continue
        try:
            data = mcp.call(tool, args)
            body = _render_lan(name, title, data)
            record("lan", name, title, FOLDERS["lan"], body, None, dry_run, run)
        except Exception as exc:
            run["errors"] += 1
            run["detail"].append(f"lan:{name}: {exc}")


COLLECTORS = {"wordpress": collect_wordpress, "gitea": collect_gitea, "lan": collect_lan}


def start_run(source: str, dry_run: bool) -> int:
    with closing(db()) as c:
        cur = c.execute("INSERT INTO runs (source, started_at, dry_run) VALUES (?,?,?)",
                        (source, now(), 1 if dry_run else 0))
        c.commit()
        return int(cur.lastrowid)


def finish_run(run_id: int, run: dict, error: str | None = None) -> None:
    with closing(db()) as c:
        c.execute("""UPDATE runs SET finished_at=?, added=?, updated=?, removed=?, skipped=?,
                     errors=?, detail=? WHERE id=?""",
                  (now(), run["added"], run["updated"], run["removed"], run["skipped"],
                   run["errors"], json.dumps({"notes": run["detail"], "error": error})[:8000], run_id))
        c.commit()


def run_collector(source: str, dry_run: bool = True, only: str | None = None) -> dict:
    if source not in COLLECTORS:
        raise HTTPException(400, f"unknown source {source!r}")
    run = {"added": 0, "updated": 0, "removed": 0, "skipped": 0, "errors": 0, "detail": []}
    run_id = start_run(source, dry_run)
    started = time.time()
    try:
        if source == "lan":
            collect_lan(dry_run, run, only)
        else:
            COLLECTORS[source](dry_run, run)
        finish_run(run_id, run)
    except Exception as exc:
        # surface the failure in the job log instead of a bare 500: the UI and
        # the scheduler both want a run record even when a source is unreachable
        finish_run(run_id, run, str(exc))
        run["errors"] += 1
        run["error"] = str(exc)[:500]
    run["seconds"] = round(time.time() - started, 1)
    run["run_id"] = run_id
    run["dry_run"] = dry_run
    return run


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------
@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "ts": now()}


@app.get("/api/status")
def api_status() -> dict:
    anything = Anything()
    with closing(db()) as c:
        per_source = [dict(r) for r in c.execute(
            """SELECT source, COUNT(*) docs, SUM(words) words, MAX(synced_at) last_synced,
                      SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) errors
               FROM docs GROUP BY source ORDER BY source""")]
        recent = [dict(r) for r in c.execute(
            "SELECT * FROM runs ORDER BY id DESC LIMIT 20")]
        totals = dict(c.execute(
            "SELECT COUNT(*) docs, SUM(words) words FROM docs").fetchone() or {})
    ws = anything.workspace()
    return {
        "ts": now(),
        "anythingllm": {"url": ANY, "workspace": WORKSPACE, "health": anything.health(),
                        "vectors": anything.vector_count(),
                        "workspace_docs": len(ws.get("documents") or []),
                        "chat_mode": ws.get("chatMode")},
        "sources": {k: SOURCE_LABELS[k] for k in SOURCE_LABELS},
        "per_source": per_source,
        "totals": totals,
        "recent_runs": recent,
        "config": {"wordpress": WP_URL, "wordpress_auth": bool(WP_USER and WP_APP_PASSWORD),
                   "gitea": GITEA_URL, "metamcp": bool(MCP_URL and MCP_KEY)},
    }


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    status = api_status()
    with closing(db()) as c:
        docs = [dict(r) for r in c.execute(
            "SELECT * FROM docs ORDER BY synced_at DESC, title ASC LIMIT 500")]
    return templates.TemplateResponse("index.html", {
        "request": request, "status": status, "docs": docs,
        "labels": SOURCE_LABELS, "folders": FOLDERS,
    })


@app.post("/run/{source}")
def run_source(source: str, dry_run: str = Form("1"), only: str = Form("")):
    result = run_collector(source, dry_run in ("1", "true", "on", "yes"), only or None)
    return JSONResponse(result)


@app.post("/api/run/{source}")
def api_run(source: str, dry_run: bool = True, only: str | None = None):
    return JSONResponse(run_collector(source, dry_run, only))


@app.post("/api/goose")
async def api_goose(payload: dict):
    """Ingest a goose run summary. Called by the goose summariser."""
    title = payload.get("title") or f"Goose run {now()}"
    body = payload.get("markdown") or ""
    if not body.strip():
        raise HTTPException(400, "markdown is required")
    key = payload.get("session_id") or f"run-{int(time.time())}"
    run = {"added": 0, "updated": 0, "removed": 0, "skipped": 0, "errors": 0, "detail": []}
    run_id = start_run("goose", False)
    record("goose", str(key), title, FOLDERS["goose"], body, payload.get("started"), False, run)
    finish_run(run_id, run)
    return {"ok": True, "run_id": run_id, **run}


@app.post("/api/remove/{source}/{key}")
def api_remove(source: str, key: str):
    with closing(db()) as c:
        row = c.execute("SELECT docpath FROM docs WHERE source=? AND source_key=?",
                        (source, key)).fetchone()
        if not row:
            raise HTTPException(404, "not found")
        if row["docpath"]:
            Anything().remove([row["docpath"]])
        c.execute("DELETE FROM docs WHERE source=? AND source_key=?", (source, key))
        c.commit()
    return {"ok": True}
