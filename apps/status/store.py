"""SQLite persistence: one row per node per poll, plus the latest snapshot.

The checks table is the source of truth for the "last 12 hours" view: the
dashboard derives incidents by walking status changes per node, so no separate
event stream has to be maintained.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import closing

DB_PATH = os.environ.get("STATUS_DB", "/data/status.db")
RETENTION_HOURS = int(os.environ.get("STATUS_RETENTION_HOURS", "168"))

SCHEMA = """
create table if not exists checks(
  ts integer not null,
  node_id text not null,
  layer text not null,
  name text not null,
  status text not null,
  latency_ms integer,
  issues text,
  metrics text
);
create index if not exists checks_node_ts on checks(node_id, ts);
create index if not exists checks_ts on checks(ts);
create table if not exists snapshots(
  ts integer primary key,
  body text not null
);
create table if not exists meta(k text primary key, v text);
"""


def db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    return c


def init() -> None:
    with closing(db()) as c:
        c.executescript(SCHEMA)
        c.commit()


def save_snapshot(snap: dict) -> None:
    ts = int(snap["ts"])
    rows = [
        (ts, n["id"], n["layer"], n["name"], n["status"],
         n.get("latency_ms"), json.dumps(n.get("issues") or []),
         json.dumps(n.get("metrics") or {}))
        for n in snap.get("nodes", [])
    ]
    with closing(db()) as c:
        c.executemany(
            "insert or replace into checks(ts,node_id,layer,name,status,latency_ms,issues,metrics)"
            " values (?,?,?,?,?,?,?,?)", rows)
        c.execute("insert or replace into snapshots(ts, body) values (?,?)",
                  (ts, json.dumps(snap)))
        cutoff = int(time.time()) - RETENTION_HOURS * 3600
        c.execute("delete from checks where ts < ?", (cutoff,))
        c.execute("delete from snapshots where ts < ?", (cutoff,))
        c.commit()


def latest_snapshot() -> dict | None:
    with closing(db()) as c:
        row = c.execute("select body from snapshots order by ts desc limit 1").fetchone()
        return json.loads(row["body"]) if row else None


def set_meta(key: str, value: str) -> None:
    with closing(db()) as c:
        c.execute("insert or replace into meta(k,v) values (?,?)", (key, value))
        c.commit()


def get_meta(key: str) -> str | None:
    with closing(db()) as c:
        row = c.execute("select v from meta where k=?", (key,)).fetchone()
        return row["v"] if row else None


def history(node_id: str, hours: int = 12) -> list[dict]:
    since = int(time.time()) - hours * 3600
    with closing(db()) as c:
        rows = c.execute(
            "select ts,status,latency_ms,issues,metrics from checks"
            " where node_id=? and ts>=? order by ts", (node_id, since)).fetchall()
    return [{"ts": r["ts"], "status": r["status"], "latency_ms": r["latency_ms"],
             "issues": json.loads(r["issues"] or "[]"),
             "metrics": json.loads(r["metrics"] or "{}")} for r in rows]


def episodes(hours: int = 12) -> list[dict]:
    """Walk status history and return contiguous non-green episodes."""
    since = int(time.time()) - hours * 3600
    with closing(db()) as c:
        rows = c.execute(
            "select ts,node_id,layer,name,status,issues from checks"
            " where ts>=? order by node_id, ts", (since,)).fetchall()
    out: list[dict] = []
    cur: dict | None = None
    last_ts: dict[str, int] = {}
    for r in rows:
        bad = r["status"] in ("down", "degraded")
        if bad:
            issues = json.loads(r["issues"] or "[]")
            if cur and cur["node_id"] == r["node_id"] and cur["status"] == r["status"]:
                cur["end"] = r["ts"]
                cur["samples"] += 1
                for i in issues:
                    t = i.get("text", "")
                    if t and t not in cur["issues"]:
                        cur["issues"].append(t)
            else:
                if cur:
                    out.append(cur)
                cur = {"node_id": r["node_id"], "layer": r["layer"], "name": r["name"],
                       "status": r["status"], "start": r["ts"], "end": r["ts"],
                       "samples": 1, "issues": [i.get("text", "") for i in issues][:4]}
        elif cur and cur["node_id"] == r["node_id"]:
            out.append(cur)
            cur = None
        last_ts[r["node_id"]] = r["ts"]
    if cur:
        out.append(cur)
    now = int(time.time())
    for e in out:
        e["duration_s"] = max(0, e["end"] - e["start"])
        e["ongoing"] = (now - e["end"]) <= 180
        e["issues"] = [i for i in e["issues"] if i][:4]
    out.sort(key=lambda e: (not e["ongoing"], -e["end"]))
    return out


def uptime_buckets(hours: int = 12, buckets: int = 24) -> list[dict]:
    """Coarse availability per time bucket across the whole estate."""
    now = int(time.time())
    width = hours * 3600 // buckets
    start = now - hours * 3600
    out = []
    with closing(db()) as c:
        for i in range(buckets):
            lo, hi = start + i * width, start + (i + 1) * width
            row = c.execute(
                "select sum(case when status in ('down','degraded') then 1 else 0 end) bad,"
                " count(*) n from checks where ts>=? and ts<?", (lo, hi)).fetchone()
            out.append({"start": lo, "bad": row["bad"] or 0,
                        "degraded": round(100.0 * (row["bad"] or 0) / row["n"], 1) if row["n"] else None})
    return out
