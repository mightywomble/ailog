# Netdata integration

ailog reads from a Netdata **parent** over its read-only HTTP API. Netdata owns
thresholds, anomaly detection and the raw time series; ailog explains what those
numbers mean next to the logs.

- **Pull, never push.** Netdata has no generic metric-push webhook. ailog polls
  `/api/v3/data` and `/api/v3/alert_transitions`.
- **Read-only.** Only `GET` requests are made. The one capability probe
  (`/api/v3/function`) is expected to be blocked until the fleet is claimed to
  Netdata Cloud.
- **No time-series mirror.** Nothing is copied into SQLite. The only persisted
  facts are alert *transitions* (`alert_events`, source `netdata`), deduped on
  Netdata's transition id.
- **The token stays server-side.** Stored in `AppSetting` (`netdata.token`) or
  `AILOG_NETDATA_TOKEN`; `GET /api/netdata/config` returns only `token_set`.

## Configure

Settings → **Netdata**:

| Field | Meaning |
| --- | --- |
| Parent URL | e.g. `https://netdata.safehomelan.com` |
| API token | optional bearer token; blank keeps the stored one |

Environment overrides (useful for a container): `AILOG_NETDATA_URL`,
`AILOG_NETDATA_TOKEN`, `AILOG_NETDATA_VERIFY` (`0` disables TLS verification,
or a CA bundle path).

The parent currently answers anonymous data requests (`/api/v3/me` reports
`auth: none`, `anonymous-data`). Put a bearer token or an IP allowlist in front
of it before exposing it beyond the LAN.

## What it powers

| Item | Where |
| --- | --- |
| Metric evidence in AI reports | `netdata/evidence.py` → `serverreport/pack.py` `--- METRICS ---` and `--- NETDATA ALERTS IN WINDOW ---` |
| Fleet metrics without SSH | `netdata/snapshot.py`; `metrics/routes.py` uses one fleet query and falls back to SSH per unmatched host |
| Alert ingestion | `alerting/engine.py` `poll_netdata_alerts()` (60 s scheduler job, plus a manual **Pull into ailog** button) |
| Anomaly-first triage | `/netdata` orders cards by Netdata's ML anomaly rate (`arp`) |
| Live cards + drill-down | `/netdata` cards, click opens `/api/netdata/history` charts |
| Capacity / SLO | `/api/netdata/capacity` reads Netdata's minute tier (`tier=1`) with `points` downsampling |
| Host reconciliation | `/api/netdata/reconcile`, the panel on `/netdata` |
| Streaming health | `client.streaming_health()`; shown as a data-quality banner and written into report evidence |
| Capacity prompt | 11th prompt in the AI wizard, `aiprompts.PROMPTS_BY_ID['capacity']` |
| On-demand diagnostics | `/api/netdata/diagnostics` probes `/api/v3/function` and reports the SSO requirement honestly |

## API

All endpoints are `GET` unless stated.

| Endpoint | Returns |
| --- | --- |
| `/api/netdata/health` | configured / reachable / nodes / version / streaming quality |
| `/api/netdata/fleet?window=120&points=30` | per-node CPU, RAM, disk, load, anomaly rate, alert counts, series, reconciliation |
| `/api/netdata/history?host=<guid|name>&window=360&points=160` | one node's series for the drill-down |
| `/api/netdata/alerts?limit=80` | live alert instances + transitions + facets |
| `/api/netdata/transitions?after=-86400` | transitions and facets |
| `/api/netdata/reconcile` | matched / Netdata-only / ailog-only hosts |
| `/api/netdata/capacity?hours=24` | avg / max / p95 and headroom per node |
| `/api/netdata/diagnostics` | functions API availability (412 = Cloud SSO required) |
| `/api/netdata/evidence?host=<key>&window=60` | the exact text an AI report would receive |
| `/api/netdata/config` | `GET` status; `POST` saves URL/token |
| `POST /api/netdata/ingest` | pull transitions into `alert_events` now |

## Response shape notes

`/api/v3/data` with `group_by=node,context,dimension` returns labels whose order
depends on the group keys. Real v2.12 responses look like:

```
time, user,guid,system.cpu, ...                  (node + context + dimension)
time, used,disk_space./,guid,disk.space, ...     (dimension first, instance second)
```

The parser identifies the GUID and context by membership, not position
(`client._group`). Each cell is `[value, anomaly_rate, ...]`; a `None`/gap is
kept as `None`, never turned into zero.

Disk context changed from `disk_space.*` to `disk.space` in v2; the client uses
`disk.space` and picks the root instance.

## Diagnostics are blocked by design (for now)

```
GET /api/v3/function?function=systemd-journal&node=<node>
→ HTTP 412 "You need to be authenticated via Netdata Cloud Single-Sign-On (SSO)"
```

`/api/v3/functions` (the list of function definitions) works, but executing one
requires the node to be claimed to Netdata Cloud. The UI says so rather than
presenting a broken button. Claim the parent and agents to enable it; no ailog
change is then needed beyond removing the probe's caveat.

## Tests

`tests/test_netdata.py` covers the parser against trimmed real payloads, fleet
saturation maths, node anomaly selection (parent instance vs node instance),
streaming quality, host matching (exact, normalised, override, ambiguous),
the Monitoring-page adapter, evidence rendering, pack integration, idempotent
alert ingestion, every API route, and the UI/config wiring.
