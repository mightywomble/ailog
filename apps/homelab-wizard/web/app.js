/* homelab-wizard: one flow, nine touchpoints, every long action a job.
   Stages: source, compose, stack file, ports, details, url, review, build, test. */
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

const STAGES = [["source", "source"], ["compose", "compose"], ["stack", "stack file"],
  ["ports", "ports"], ["details", "details"], ["creds", "credentials"], ["url", "url"],
  ["review", "review"], ["run", "build"], ["test", "test"]];

const S = { settings: {}, services: [], ports: null, current: null, entry: {}, stage: "source",
  es: null, mode: "new", parts: ["source"], newest: null };

/* Adding a service and bumping one are different journeys. A new service needs
   every stage; an existing one only needs the stages you ticked, then review. */
function stages() {
  if (S.mode === "new") return STAGES;
  return STAGES.filter(([id]) => id === "source" || id === "review" || id === "run"
    || id === "test" || S.parts.includes(id));
}
function isExisting() { return !!S.current && S.services.some((s) => s.name === S.current); }

/* ------------------------------------------------------------------ plumbing */
async function api(path, opts = {}) {
  progress.start();
  try {
    const res = await fetch(path, {
      headers: { "Content-Type": "application/json" }, ...opts,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    const text = await res.text();
    let data; try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
    if (!res.ok) throw new Error(data.detail || (data.problems || []).join(", ") || `HTTP ${res.status}`);
    return data;
  } finally { progress.done(); }
}

const progress = (() => {
  const el = $("#topbar"), bar = el.querySelector("i");
  let active = 0, w = 0, timer = null;
  const paint = (v) => (bar.style.width = v + "%");
  return {
    start() {
      active++; el.classList.add("on"); el.classList.remove("fail");
      if (!timer) { w = 8; paint(w); timer = setInterval(() => { w = Math.min(88, w + (88 - w) * 0.06); paint(w); }, 200); }
    },
    done() {
      active = Math.max(0, active - 1); if (active) return;
      clearInterval(timer); timer = null; paint(100);
      setTimeout(() => { el.classList.remove("on"); paint(0); }, 350);
    },
  };
})();

/* ------------------------------------------------------------------ stages */
function renderStepper() {
  const list = stages();
  const idx = list.findIndex(([x]) => x === S.stage);
  $("#stepper").innerHTML = list.map(([id, label], i) => `<button class="step ${S.stage === id ? "active" : ""} ${i < idx ? "done" : ""}" data-go="${id}">
    <b>${i < idx ? "✓" : i + 1}</b>${label}</button>`).join("")
    + `<span class="chip mode">${S.mode === "new" ? "new service" : "updating " + esc(S.current || "")}</span>`;
}
function go(stage) {
  const list = stages().map(([id]) => id);
  if (!list.includes(stage)) stage = "review";
  S.stage = stage;
  try { window.history.replaceState(null, "", "#" + stage); } catch (e) {}
  $$(".stage").forEach((el) => el.classList.toggle("active", el.dataset.stage === stage));
  renderStepper();
  if (stage === "ports") loadPorts();
  if (stage === "review") renderReview();
  if (stage === "test") prefillTest();
  if (stage === "creds") renderCredNote();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function nextStage() {
  if (S.stage === "source" && isExisting()) return openUpdateModal();
  const list = stages().map(([id]) => id);
  const i = list.indexOf(S.stage);
  go(list[Math.min(i + 1, list.length - 1)]);
}
$$("[data-next]").forEach((b) => (b.onclick = nextStage));
$("#btnNextSource").onclick = nextStage;

/* ------------------------------------------------------------------ state */
async function boot() {
  try {
    const st = await api("/api/state");
    S.settings = st.settings || {};
    S.services = st.services || [];
    $("#repoChip").textContent = st.repo?.ok ? `${st.repo.branch} · ${st.repo.commit || "?"}` : "repo offline";
    $("#suffix").textContent = "." + (st.domain_suffix || "safehomelan.com");
    $("#f_forward").value = S.settings.ingress_ip || "100.79.189.118";
    renderList(); fillSettings(st.settings);
    if (S.services.length && !S.current) loadService(S.services[0].name);
  } catch (err) {
    $("#serviceList").innerHTML = `<li class="empty">${esc(err.message)}</li>`;
  }
  const h = (location.hash || "").slice(1);
  if (STAGES.some(([id]) => id === h)) S.stage = h;
  go(S.stage); loadExposeMeta();
}

function renderList() {
  const q = $("#filter").value.trim().toLowerCase();
  const rows = S.services.filter((s) => !q || s.name.includes(q) || (s.repo || "").includes(q));
  $("#serviceList").innerHTML = rows.length ? rows.map((s) => `<li class="svc kind-${s.kind} ${S.current === s.name ? "active" : ""}" data-name="${s.name}">
      <div class="name"><span>${esc(s.name)}</span><span class="chip">${esc(s.kind)}</span></div>
      <div class="meta">${esc(s.version || "")} · ${esc((s.ports[0] || {}).host || "—")}${s.url ? " · " + esc(s.url) : ""}</div>
    </li>`).join("") : `<li class="empty">no services</li>`;
}

async function refreshServices() {
  const st = await api("/api/state");
  S.services = st.services || [];
  renderList();
}

async function loadService(name) {
  S.current = name; S.mode = "update";
  S.parts = ["source"];            // ticks are chosen in the modal after source
  renderList();
  const d = await api(`/api/services/${encodeURIComponent(name)}`);
  const e = d.entry || {}; S.entry = e;
  $("#f_name").value = e.name || "";
  $("#f_kind").value = e.kind || "mirror";
  $("#f_source").value = e.source || "";
  $("#f_version").value = e.version || "";
  $("#f_repo").value = e.repo || "";
  $("#f_stack").value = d.stack || "";
  const p = (e.ports || [])[0] || {};
  $("#f_port").value = p.host || "";
  $("#f_container_port").value = p.container || "";
  $("#f_replicas").value = e.replicas || 1;
  $("#f_hostmode").checked = p.mode === "host";
  $("#f_volumes").value = (e.volumes || []).filter((v) => v.host).map((v) => `${v.host}:${v.container}`).join("\n");
  $("#f_env").value = Object.entries(e.env || {}).map(([k, v]) => `${k}=${v}`).join("\n");
  $("#f_health").value = typeof e.healthcheck === "string" ? e.healthcheck : (e.healthcheck?.test?.[1] || "");
  $("#f_subdomain").value = (e.url || "").replace(/\..*$/, "");
  $("#f_creduser").value = e.env?.[$("#f_creduserkey").value] || "";
  $("#f_credpass").value = e.env?.[$("#f_credpwkey").value] || "";
  $("#imagePreview").textContent = imageRef();
  renderReview(); renderPath(); previewNewest();
}

/* Update and Next are both offered here because they are different intents:
   one rolls the image forward, the other edits something specific. */
function renderPath() {
  const existing = isExisting();
  $("#btnUpdate").hidden = !existing || !$("#f_source").value.trim();
  $("#newestNote").textContent = existing ? "this service is already in wizard.yaml" : "";
  $("#f_name").readOnly = existing;
}

async function previewNewest() {
  const src = $("#f_source").value.trim();
  if (!isExisting() || !src) return;
  $("#newestNote").textContent = "checking upstream…";
  try {
    const d = await api("/api/newest?image=" + encodeURIComponent(src));
    S.newest = d;
    $("#newestNote").textContent = d.up_to_date
      ? `upstream ${d.host}/${d.repo}: ${d.tag} — already newest`
      : `upstream ${d.host}/${d.repo}: ${d.current || "?"} → ${d.best}`;
    $("#btnUpdate").textContent = d.up_to_date ? "already newest" : `update to ${d.best}`;
    $("#btnUpdate").disabled = !!d.up_to_date;
  } catch (err) {
    S.newest = null;
    $("#newestNote").textContent = "cannot read upstream tags: " + (err.message || err);
    $("#btnUpdate").textContent = "update to newest";
    $("#btnUpdate").disabled = true;
  }
}

function imageRef() {
  const kind = $("#f_kind").value;
  const repo = $("#f_repo").value || $("#f_name").value || "app";
  const version = $("#f_version").value || "latest";
  return kind === "build" ? `zot.safehomelan.com/${repo}:\${IMAGE_TAG:-${version}}`
                          : `zot.safehomelan.com/${repo}:${version}`;
}

function entryFromForm() {
  const port = Number($("#f_port").value) || 0;
  const cport = Number($("#f_container_port").value) || port;
  const volumes = $("#f_volumes").value.split("\n").map((l) => l.trim()).filter(Boolean)
    .map((l) => { const [host, container] = l.split(":"); return { host, container: container || "/data" }; });
  const env = {};
  $("#f_env").value.split("\n").map((l) => l.trim()).filter(Boolean).forEach((l) => {
    const i = l.indexOf("="); if (i > 0) env[l.slice(0, i)] = l.slice(i + 1);
  });
  const sub = $("#f_subdomain").value.trim();
  // credentials are just two env keys; clearing the fields removes them
  const cu = $("#f_creduser").value.trim(), cp = $("#f_credpass").value.trim();
  const cuk = $("#f_creduserkey").value.trim() || "ADMIN_USER";
  const cpk = $("#f_credpwkey").value.trim() || "ADMIN_PASSWORD";
  if (cu) env[cuk] = cu; else delete env[cuk];
  if (cp) env[cpk] = cp; else delete env[cpk];
  return {
    name: $("#f_name").value.trim(), kind: $("#f_kind").value,
    source: $("#f_source").value.trim(), version: $("#f_version").value.trim(),
    repo: $("#f_repo").value.trim(), replicas: Number($("#f_replicas").value) || 1,
    ports: port ? [{ host: port, container: cport, mode: $("#f_hostmode").checked ? "host" : "ingress" }] : [],
    volumes, env, healthcheck: $("#f_health").value.trim(),
    url: sub ? `${sub}.${S.settings.domain_suffix || "safehomelan.com"}` : "",
    service: S.entry.service || $("#f_name").value.trim(),
    companions: S.entry.companions || [],
  };
}

/* ------------------------------------------------------------------ review */
function renderReview() {
  const e = entryFromForm();
  if (!e.name) { $("#reviewOut").innerHTML = `<div class="note bad">name is required</div>`; return; }
  const rows = [["stack", e.name], ["kind", e.kind], ["image", imageRef()],
    ["upstream", e.source || "—"],
    ["ports", e.ports.map((p) => `${p.host} → ${p.container} (${p.mode})`).join(", ") || "none"],
    ["replicas", e.replicas], ["url", e.url || "—"],
    ["volumes", e.volumes.map((v) => v.host).join(", ") || "—"],
    ["env keys", Object.keys(e.env).join(", ") || "—"],
    ["credentials", (e.env[($("#f_creduserkey").value || "ADMIN_USER").trim()]
      ? `user via ${$("#f_creduserkey").value.trim()}` : "no username")
      + (e.env[($("#f_credpwkey").value || "ADMIN_PASSWORD").trim()] ? " · password set" : "")]];
  $("#reviewOut").innerHTML = rows.map(([k, v]) => `<div class="kv"><dt>${k}</dt><dd>${esc(v)}</dd></div>`).join("")
    + `<div class="note">writes <code>wizard.yaml</code> + <code>stacks/${esc(e.name)}/stack.yml</code>`
    + (e.kind === "mirror" ? " + the <code>mirror-images.json</code> entry" : "") + `</div>`
    + (S.mode === "update"
      ? `<div class="note">updating only: <b>${esc(S.parts.join(", ") || "nothing ticked")}</b></div>` : "");
}

async function saveDraft() {
  const e = entryFromForm();
  const res = await api(`/api/services/${encodeURIComponent(e.name)}`, { method: "PUT", body: { entry: e } });
  if (res.ok) {
    $("#f_stack").value = (await api(`/api/services/${encodeURIComponent(e.name)}`)).stack || "";
    await refreshServices();
    $("#reviewOut").insertAdjacentHTML("afterbegin", `<div class="note ok">saved to the worktree</div>`);
  } else {
    $("#reviewOut").insertAdjacentHTML("afterbegin", `<div class="note bad">${esc((res.problems || []).join(", "))}</div>`);
  }
  return res;
}

/* ------------------------------------------------------------------ jobs */
function openJob(id, title) {
  if (S.es) S.es.close();
  $("#runSteps").innerHTML = ""; $("#log").textContent = ""; setRun(0, "starting…");
  appendLog(`── ${title || "job " + id} ──`);
  const es = new EventSource(`/api/jobs/${id}/events`);
  S.es = es;
  es.onmessage = (evt) => {
    const e = JSON.parse(evt.data);
    if (e.type === "snapshot") { renderSteps(e.job.steps); (e.job.lines || []).forEach((l) => appendLog(l)); 
      if (e.job.progress) setProgressFrom(e.job.progress); return; }
    if (e.type === "log") appendLog(e.text);
    if (e.type === "steps") renderSteps(e.steps);
    if (e.type === "progress") setProgressFrom(e.progress);
    if (e.type === "status") {
      es.close(); S.es = null;
      setRun(e.status === "ok" ? 100 : 0, e.status === "ok" ? "done" : "failed");
      if (e.error) appendLog("ERROR " + e.error, true);
      $("#btnRunNext").hidden = false;
      $("#btnRunNext").textContent = e.status === "ok" ? "next: test" : "next: test anyway";
      if (e.result?.checks) renderTest(e.result);
      if (e.result?.tests) renderTest(e.result.tests);
      if (e.result?.expose) $("#exposeOut").textContent = `host ${e.result.expose.id}\n${e.result.expose.url}`;
      refreshServices().catch(() => {});
    }
  };
}

function appendLog(text, isErr) {
  const el = $("#log");
  const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 40;
  const line = document.createElement("div");
  if (isErr || /(^|\s)(FAILED|ERROR|error:|denied)/i.test(String(text))) line.className = "err";
  line.textContent = text;
  el.appendChild(line);
  while (el.childElementCount > 3000) el.removeChild(el.firstChild);
  if (atBottom) el.scrollTop = el.scrollHeight;
}

function renderSteps(steps) {
  $("#runSteps").innerHTML = (steps || []).map((s) => {
    const ok = ["completed", "ok", "success"].includes(s.status);
    return `<span class="s ${ok ? "ok" : s.status === "failed" ? "failed" : "run"}">${esc(s.name)}</span>`;
  }).join("");
}

function setRun(pct, label) {
  $("#runFill").style.width = Math.max(0, Math.min(100, pct)) + "%";
  $("#runPct").textContent = ["done", "failed"].includes(label) ? label : `${Math.round(pct)}%`;
}

function setProgressFrom(p) {
  if (!p) return;
  if (typeof p.percent === "number") {
    setRun(p.percent, p.state === "done" ? "done" : "pulling");
    if (p.layers) $("#runPct").textContent = `${Math.round(p.percent)}% · ${p.done}/${p.layers} layers`;
  } else if (p.workflow) {
    setRun(p.workflow === "completed" ? 100 : 45, p.workflow === "completed" ? "done" : "working");
  } else if (p.checks) {
    setRun(100, `${p.checks.filter((c) => c.ok).length}/${p.checks.length} checks`);
  }
}

function jobRoute(path, body, title) {
  return api(path, { method: "POST", body }).then((r) => { go("run"); openJob(r.job, title); return r.job; });
}

/* ------------------------------------------------------------------ actions */
/* ---------------------------------------------------------- update path */
function openUpdateModal() {
  $("#updateWho").innerHTML = `<b>${esc(S.current)}</b> — tick what this change touches. Stages you
    leave unticked keep their current values.`;
  $("#updateModal").hidden = false;
}
function chosenParts() {
  return $$("#updateModal [data-part]").filter((c) => c.checked).map((c) => c.dataset.part);
}
$("#btnPartsGo").onclick = () => {
  const parts = chosenParts();
  S.parts = ["source", ...parts.filter((p) => p !== "source")];
  // "stack file" is edited after details, so keep that order
  S.parts = STAGES.map(([id]) => id).filter((id) => S.parts.includes(id));
  $("#updateModal").hidden = true;
  const after = stages().filter(([id]) => id !== "source");
  go(after.length ? after[0][0] : "review");
};
$("#btnPartsReview").onclick = () => {
  S.parts = ["source", ...chosenParts()];
  $("#updateModal").hidden = true;
  go("review");
};

$("#btnUpdate").onclick = async () => {
  if (!S.current) return;
  // one click: newest upstream tag -> wizard.yaml -> mirror/build -> ship -> deploy -> test
  jobRoute("/api/update", { name: S.current, test: true }, `update ${S.current}`);
};

/* ------------------------------------------------------------ credentials */
function makePassword(len = 90) {
  const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@%^*-_=+";
  const buf = new Uint32Array(len);
  crypto.getRandomValues(buf);
  return [...buf].map((n) => alphabet[n % alphabet.length]).join("");
}
$("#btnGenPass").onclick = () => {
  $("#f_credpass").value = makePassword();
  $("#credNote").textContent = "generated — save it somewhere before you leave this stage";
  renderReview();
};
$("#btnUseCreds").onclick = () => {
  $("#f_testuser").value = $("#f_creduser").value.trim();
  $("#f_testpass").value = $("#f_credpass").value.trim();
  $("#credNote").textContent = "copied to the test form";
};
function renderCredNote() {
  const u = $("#f_creduser").value.trim(), p = $("#f_credpass").value.trim();
  $("#credNote").textContent = u || p
    ? `${$("#f_creduserkey").value || "ADMIN_USER"}=${u || "(empty)"} · ${$("#f_credpwkey").value || "ADMIN_PASSWORD"}=${p ? p.slice(0, 3) + "…" : "(empty)"}`
    : "no credentials set on this service";
}
["f_creduser", "f_credpass", "f_creduserkey", "f_credpwkey"].forEach((id) => {
  $("#" + id).oninput = () => { renderCredNote(); renderReview(); };
});

$("#btnRunNext").onclick = () => go("test");

$("#btnPull").onclick = () => {
  const img = imageRef().replace(/\$\{IMAGE_TAG:-([^}]*)\}/, "$1");
  jobRoute("/api/pull", { image: img }, "docker pull " + img);
};
$("#btnBuild").onclick = () => jobRoute("/api/build", {}, "build + smoke test");
$("#btnShip").onclick = () => jobRoute("/api/ship", {}, "PR → release → deploy");
$("#btnRunAll").onclick = async () => {
  await saveDraft();
  const e = entryFromForm();
  const port = (e.ports[0] || {}).host;
  const sub = $("#f_subdomain").value.trim();
  jobRoute("/api/pipeline", {
    message: `wizard: ${e.name} ${e.version || ""}`.trim(), deploy: true,
    expose: sub ? { domain: e.url, port, cert_id: Number($("#f_cert").value) || null } : null,
    test: { stack: e.name, domain: sub ? e.url : null, port,
            creds: { username: $("#f_testuser").value, password: $("#f_testpass").value } },
  }, "pipeline: " + e.name);
};

$("#btnStackState").onclick = async () => {
  const name = entryFromForm().name;
  const d = await api(`/api/stack/${encodeURIComponent(name)}`);
  $("#log").textContent = [...(d.replicas || []).map((r) => `${r.service}  ${r.replicas}  ${r.image}`),
    "", ...(d.tasks || []).map((t) => `${t.state.padEnd(28)} ${t.node}  ${t.error || ""}`)].join("\n");
  go("run");
};

$("#btnValidate").onclick = async () => {
  const res = await api("/api/compose/validate", { method: "POST", body: { compose: $("#f_stack").value } });
  $("#validateOut").innerHTML =
    (res.ok ? `<div class="note ok">valid — ${esc(res.services.join(", "))}</div>`
            : res.problems.map((p) => `<div class="note bad">${esc(p)}</div>`).join(""))
    + (res.warnings || []).map((w) => `<div class="note">${esc(w)}</div>`).join("");
};

const toggleTip = () => ($("#saveTip").hidden = !$("#saveTip").hidden);
$("#saveHelp").onclick = toggleTip;
$("#saveHelp").onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleTip(); } };

$("#btnRender").onclick = () => { renderReview(); $("#btnSaveDraft").click(); };

$("#btnConvert").onclick = async () => {
  const compose = $("#f_compose").value.trim();
  if (!compose) return;
  $("#convertOut").innerHTML = `<div class="note">asking ${esc(S.settings.openrouter_model || "the model")}…</div>`;
  const { job } = await api("/api/ai/convert", { method: "POST",
    body: { compose, name: $("#f_name").value.trim() || "newapp", hint: $("#f_hint").value } });
  const timer = setInterval(async () => {
    const j = await api(`/api/jobs/${job}`);
    if (!["ok", "failed"].includes(j.status)) return;
    clearInterval(timer);
    if (j.status === "failed") { $("#convertOut").innerHTML = `<div class="note bad">${esc(j.error)}</div>`; return; }
    renderConvert(j.result);
  }, 2500);
};

function renderConvert(res) {
  const bad = (res.problems || []).map((p) => `<div class="note bad">${esc(p)}</div>`).join("");
  const changes = (res.changes || []).map((c) => `<div class="note ok"><b>${esc(c.what)}</b> — ${esc(c.why)}</div>`).join("");
  const warn = (res.warnings || []).map((w) => `<div class="note">${esc(w)}</div>`).join("");
  $("#convertOut").innerHTML = `${bad}${changes}${warn}<pre class="mono">${esc(res.stack)}</pre>
    <div class="row"><button class="btn" id="btnAcceptStack">use this stack</button>
      <span class="hint">${esc(res.model || "")}${res.detected?.port ? " · port " + res.detected.port : ""}</span></div>`;
  $("#btnAcceptStack").onclick = () => {
    $("#f_stack").value = res.stack;
    if (res.detected?.port) { $("#f_port").value = res.detected.port; $("#f_container_port").value = res.detected.port; }
    if (res.detected?.url) $("#f_subdomain").value = res.detected.url.split(".")[0];
    if (res.detected?.services?.length && !$("#f_name").value) $("#f_name").value = res.detected.services[0];
    go("stack");
  };
}

$("#btnFetchTags").onclick = async () => {
  const src = $("#f_source").value.trim();
  if (!src) return;
  $("#tagList").innerHTML = `<span class="chip">fetching…</span>`;
  try {
    // the registry call is server-side: Docker Hub sends no CORS headers, so a
    // browser fetch can only fail with "NetworkError when attempting to fetch
    // resource." This also handles ghcr.io tokens and our own zot credentials.
    const d = await api("/api/tags?image=" + encodeURIComponent(src));
    const cur = d.current;
    $("#tagList").innerHTML = (d.tags || []).slice(0, 24).map((t) =>
      `<span class="chip ${t === cur ? "on" : ""}" data-tag="${esc(t)}">${esc(t)}</span>`).join("")
      || `<span class="chip">no tags listed</span>`;
    $("#tagNote").textContent = `${d.host}/${d.repo} · ${d.count} tags` + (cur ? ` · current ${cur}` : "");
    $$("#tagList .chip").forEach((c) => c.onclick = () => {
      if (!c.dataset.tag) return;
      $("#f_version").value = c.dataset.tag;
      $("#imagePreview").textContent = imageRef();
      $$("#tagList .chip").forEach((x) => x.classList.remove("on"));
      c.classList.add("on");
    });
  } catch (err) {
    $("#tagList").innerHTML = `<span class="chip">${esc(err.message || err)}</span>`;
  }
};

/* ------------------------------------------------------------------ ports */
async function loadPorts() { if (S.ports) { renderPorts(); return; } $("#portTable").innerHTML = `<tr><td class="empty shimmer">scanning nodes…</td></tr>`; await scanPorts(); }
async function scanPorts() {
  $("#portStats").textContent = "scanning…";
  try { S.ports = await api("/api/ports");
    $("#portStats").textContent = Object.entries(S.ports.sources || {}).map(([k, v]) => `${k}: ${v}`).join(" · ");
  } catch (err) { $("#portStats").textContent = err.message; }
  renderPorts();
}
function portTable(el) {
  const rows = (S.ports?.ports || []).map((p) => `<tr>
    <td class="portnum">${p.port}</td>
    <td>${(p.owners || []).map((o) => `<span class="pill ${/reserved/.test(o) ? "bad" : ""}">${esc(o)}</span>`).join("")}</td>
    <td>${(p.sources || []).map((s) => `<span class="pill">${esc(s)}</span>`).join("")}</td>
    <td>${esc(p.band || "")}</td>
    <td><button class="btn sm ghost" data-pick="${p.port}">use</button></td></tr>`).join("");
  el.innerHTML = `<thead><tr><th>port</th><th>owner</th><th>source</th><th>band</th><th></th></tr></thead><tbody>${rows}</tbody>`;
  el.querySelectorAll("[data-pick]").forEach((b) => b.onclick = () => { $("#f_port").value = b.dataset.pick; renderReview(); go("details"); });
}
function renderPorts() {
  portTable($("#portTable"));
  if (!$("#portsModal").hidden) portTable($("#portTableModal"));
  $("#suggestions").innerHTML = (S.ports?.suggestions || []).map((p) => `<span class="chip" data-pick2="${p}">${p}</span>`).join("");
  $$("#suggestions .chip").forEach((c) => c.onclick = () => { $("#f_port").value = c.dataset.pick2; renderReview(); go("details"); });
}
$("#btnScanPorts").onclick = scanPorts;
$("#btnPorts").onclick = () => { $("#portsModal").hidden = false; loadPorts(); };

/* ------------------------------------------------------------------ url */
async function loadExposeMeta() {
  try {
    const d = await api("/api/expose/hosts");
    $("#f_cert").innerHTML = `<option value="">no TLS</option>` + (d.certs || []).map((c) =>
      `<option value="${c.id}" ${c.nice_name === "npm-1" ? "selected" : ""}>${esc(c.nice_name)} (${esc((c.domains || []).join(", "))})</option>`).join("");
  } catch (err) { $("#f_cert").innerHTML = `<option value="">${esc(err.message)}</option>`; }
}
$("#btnExposePreview").onclick = async () => {
  try {
    const res = await api("/api/expose", { method: "POST", body: {
      domain: `${$("#f_subdomain").value.trim()}.${S.settings.domain_suffix}`,
      forward_host: $("#f_forward").value, forward_port: Number($("#f_port").value) || 1,
      cert_id: Number($("#f_cert").value) || null, advanced: $("#f_advanced").value, dry_run: true } });
    $("#exposeOut").textContent = `-- forward ${res.forward}\n-- sql\n${res.sql}\n\n${res.conf}`;
  } catch (err) { $("#exposeOut").textContent = err.message; }
};
$("#btnExpose").onclick = async () => {
  try {
    const res = await api("/api/expose", { method: "POST", body: {
      domain: `${$("#f_subdomain").value.trim()}.${S.settings.domain_suffix}`,
      forward_host: $("#f_forward").value, forward_port: Number($("#f_port").value) || 1,
      cert_id: Number($("#f_cert").value) || null, advanced: $("#f_advanced").value, dns: true } });
    $("#exposeOut").textContent = `created host ${res.id}\n${res.url}\ncert: ${res.certificate || "none"}\ndns: ${JSON.stringify(res.dns)}\n\n${res.conf}`;
  } catch (err) { $("#exposeOut").textContent = err.message; }
};

/* ------------------------------------------------------------------ test */
function prefillTest() {
  if (!$("#f_testuser").value) $("#f_testuser").value = $("#f_creduser").value.trim();
  if (!$("#f_testpass").value) $("#f_testpass").value = $("#f_credpass").value.trim();
  const e = entryFromForm();
  if (!$("#f_testurl").value) $("#f_testurl").value = e.url || "";
  if (!$("#f_testport").value) $("#f_testport").value = (e.ports[0] || {}).host || "";
}
$("#btnTest").onclick = () => {
  const body = { stack: entryFromForm().name, domain: $("#f_testurl").value.trim() || null,
    port: Number($("#f_testport").value) || null,
    creds: { username: $("#f_testuser").value, password: $("#f_testpass").value } };
  jobRoute("/api/tests", body, "tests: " + body.stack);
};

function renderTest(res) {
  const checks = (res.checks || []).map((c) => `<div class="note ${c.ok ? "ok" : "bad"}">
    <b>${c.ok ? "PASS" : "FAIL"}</b> ${esc(c.name)} ${c.detail ? "— " + esc(c.detail) : ""}</div>`).join("");
  const creds = res.creds?.username
    ? `<div class="kv"><dt>username</dt><dd>${esc(res.creds.username)}</dd></div>
       <div class="kv"><dt>password</dt><dd>${esc(res.creds.password || "(unchanged)")}</dd></div>` : "";
  $("#testOut").innerHTML = `<div class="kv"><dt>url</dt><dd><a href="${esc(res.url)}" target="_blank" rel="noreferrer">${esc(res.url)}</a></dd></div>
    ${creds}<div class="review" style="margin-top:12px">${checks}</div>`;
}

/* ------------------------------------------------------------------ settings */
function fillSettings(s) {
  $("#s_gitea_url").value = s.gitea_url || "";
  $("#s_gitea_repo").value = `${s.gitea_owner || ""}/${s.gitea_repo || ""}`;
  $("#s_zot_user").value = s.zot_user || "";
  $("#s_domain_suffix").value = s.domain_suffix || "";
  $("#s_model").innerHTML = `<option value="${esc(s.openrouter_model || "")}">${esc(s.openrouter_model || "—")}</option>`;
  $("#modelNote").textContent = s.openrouter_key_set ? "OpenRouter key configured" : "no OpenRouter key yet — add one to use the converter";
}
$("#btnSettings").onclick = async () => {
  $("#settingsModal").hidden = false;
  renderSecrets();
  const d = await api("/api/models");
  $("#s_model").innerHTML = (d.models || []).map((m) =>
    `<option value="${esc(m.id)}" ${m.id === d.current ? "selected" : ""}>${esc(m.name || m.id)}</option>`).join("");
};
$("#btnTestKey").onclick = async () => {
  // a valid key is the one thing the AI step cannot fake: /api/v1/models is
  // public, so only a real call proves the key works
  const out = $("#settingsOut");
  out.textContent = "checking…"; out.className = "hint";
  try {
    const r = await api("/api/ai/health");
    out.textContent = r.ok ? `key ok - ${r.label || "no label"}${r.limit ? ", limit $" + r.limit : ""}`
                           : `key rejected (${r.status}): ${r.error}`;
    out.className = "hint " + (r.ok ? "ok" : "bad");
  } catch (e) {
    out.textContent = "key rejected: " + (e.message || e);
    out.className = "hint bad";
  }
};

async function renderSecrets() {
  const el = $("#secretsOut");
  try {
    const d = await api("/api/secrets");
    const swarm = (d.swarm || []).map((x) => `<span class="chip">${esc(x.name)}</span>`).join("");
    const rows = (d.audit || []).map((a) =>
      `<div class="note bad"><b>${esc(a.stack)}</b> line ${a.line}: <code>${esc(a.key)}</code>
        still plaintext${a.in_wizard_yaml ? " (also in wizard.yaml)" : ""}</div>`).join("");
    el.innerHTML = `<div class="chips">${swarm || '<span class="chip">none</span>'}</div>`
      + `<p class="hint">${(d.mounted || []).length} wizard secret(s) mounted in this container.</p>`
      + (rows || `<div class="note ok">no plaintext credentials in any stack file</div>`);
  } catch (err) {
    el.innerHTML = `<div class="note bad">${esc(err.message || err)}</div>`;
  }
}

$("#btnSaveSettings").onclick = async () => {
  const [owner, repo] = ($("#s_gitea_repo").value || "/").split("/");
  const patch = { gitea_url: $("#s_gitea_url").value.trim(), gitea_owner: owner || "david",
    gitea_repo: repo || "homelab-ops", zot_user: $("#s_zot_user").value.trim(),
    openrouter_model: $("#s_model").value,
    domain_suffix: $("#s_domain_suffix").value.trim() || "safehomelan.com" };
  if ($("#s_gitea_token").value.trim()) patch.gitea_token = $("#s_gitea_token").value.trim();
  if ($("#s_zot_password").value.trim()) patch.zot_password = $("#s_zot_password").value.trim();
  if ($("#s_openrouter_key").value.trim()) patch.openrouter_key = $("#s_openrouter_key").value.trim();
  await api("/api/settings", { method: "PUT", body: { patch } });
  $("#settingsOut").textContent = "saved";
  $("#s_gitea_token").value = ""; $("#s_openrouter_key").value = ""; $("#s_zot_password").value = "";
  await boot();
};

/* ------------------------------------------------------------------ misc */
$$("[data-close]").forEach((b) => b.onclick = (e) => { e.target.closest(".modal").hidden = true; });
$$(".modal").forEach((m) => m.onclick = (e) => { if (e.target === m) m.hidden = true; });
$("#stepper").onclick = (e) => { const b = e.target.closest("[data-go]"); if (b) go(b.dataset.go); };
$("#serviceList").onclick = (e) => { const li = e.target.closest("[data-name]"); if (li) { loadService(li.dataset.name); go("source"); } };
$("#filter").oninput = renderList;
$("#btnNew").onclick = () => {
  S.current = null; S.entry = {}; S.mode = "new"; S.parts = []; S.newest = null;
  $("#f_name").readOnly = false; $("#btnUpdate").hidden = true;
  $("#f_creduser").value = ""; $("#f_credpass").value = ""; $("#newestNote").textContent = "";
  ["f_name", "f_source", "f_version", "f_repo", "f_port", "f_container_port", "f_health", "f_subdomain", "f_compose"]
    .forEach((id) => { $("#" + id).value = ""; });
  $("#f_replicas").value = 1; $("#f_volumes").value = ""; $("#f_env").value = "";
  $("#f_stack").value = ""; $("#imagePreview").textContent = "";
  renderList(); go("source"); $("#f_name").focus();
};
["f_port", "f_container_port", "f_subdomain", "f_version", "f_repo", "f_kind", "f_name"]
  .forEach((id) => { $("#" + id).oninput = () => { $("#imagePreview").textContent = imageRef(); renderPath(); }; });
$("#f_source").onchange = () => { $("#imagePreview").textContent = imageRef(); renderPath(); previewNewest(); };

$("#btnTheme").onclick = () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  localStorage.setItem("wiz-theme", next);
};
document.documentElement.dataset.theme = localStorage.getItem("wiz-theme") || "dark";

boot();
