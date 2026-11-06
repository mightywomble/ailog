/* status.safehomelan.com — front-end (no framework, no build step) */
(() => {
  const LAYERS = [
    { key: "hypervisor", label: "Hypervisors · Proxmox VE", short: "Hypervisors", ico: "🖧" },
    { key: "vm", label: "Virtual machines", short: "VMs", ico: "💻" },
    { key: "docker", label: "Docker runtimes", short: "Docker", ico: "🐳" },
    { key: "service", label: "Swarm services", short: "Services", ico: "🧩" },
    { key: "app", label: "Applications", short: "Apps", ico: "🌐" },
  ];
  const SEV = { down: 3, degraded: 2, unknown: 1, up: 0 };

  let snap = null;
  let history = { episodes: [], buckets: [] };
  let current = null;      // node id in drawer
  let currentNode = null;
  let tab = "overview";
  let timer = null;
  let hashOpened = false;
  let detailSeq = 0;

  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  /* ---------------- theme ---------------- */
  function setTheme(t) {
    document.documentElement.dataset.theme = t;
    localStorage.setItem("status-theme", t);
  }
  (function initTheme() {
    const q = new URLSearchParams(location.search).get("theme");
    if (q === "light" || q === "dark") { setTheme(q); return; }
    const saved = localStorage.getItem("status-theme");
    if (saved) setTheme(saved);
    else setTheme(matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  })();
  $("#theme").onclick = () =>
    setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");

  /* ---------------- progress bar ----------------
     A full sweep can take a few seconds on slow links. Everything that waits
     on the network drives this bar, so there is never a silent pause. */
  const progress = (() => {
    const el = $("#progress");
    const bar = el.querySelector("i");
    let timerA = null, timerB = null, active = 0;

    function clear() {
      clearInterval(timerA); clearTimeout(timerB);
      timerA = timerB = null;
    }
    return {
      start(weight = 1) {
        active += weight;
        clear();
        el.classList.remove("fail");
        el.classList.add("on");
        bar.style.width = "8%";
        let w = 8;
        timerA = setInterval(() => {
          // creep towards 85% while we wait, slowing down as it fills
          w += Math.max(0.4, (85 - w) * 0.04);
          bar.style.width = Math.min(85, w) + "%";
        }, 220);
      },
      done() {
        active = Math.max(0, active - 1);
        if (active) return;
        clear();
        bar.style.width = "100%";
        timerB = setTimeout(() => {
          el.classList.remove("on");
          setTimeout(() => { bar.style.width = "0%"; }, 260);
        }, 260);
      },
      fail() {
        active = Math.max(0, active - 1);
        if (active) return;
        clear();
        el.classList.add("fail");
        bar.style.width = "100%";
        timerB = setTimeout(() => {
          el.classList.remove("on", "fail");
          setTimeout(() => { bar.style.width = "0%"; }, 260);
        }, 900);
      },
    };
  })();

  function setBusy(btn, on, label) {
    if (!btn) return;
    btn.classList.toggle("loading", on);
    btn.disabled = on;
    const span = btn.querySelector("span:last-child");
    if (span && label) span.textContent = on ? "Polling…" : label;
  }

  /* ---------------- data ---------------- */
  async function load(force) {
    const btn = $("#refresh");
    if (!snap) renderSkeleton();
    progress.start();
    setBusy(btn, true);
    try {
      if (force) await fetch("/api/refresh", { method: "POST" });
      const [s, h] = await Promise.all([
        fetch("/api/snapshot").then((r) => r.json()),
        fetch("/api/history?hours=12").then((r) => r.json()),
      ]);
      snap = s;
      history = h;
      render();
      progress.done();
    } catch (e) {
      $("#overallText").textContent = "feed unavailable — retrying";
      $("#overallDot").className = "dot down";
      $("#overall").className = "overall down";
      progress.fail();
    } finally {
      setBusy(btn, false, "Refresh");
    }
  }

  $("#refresh").onclick = () => load(true);

  /* ---------------- skeleton ---------------- */
  function renderSkeleton() {
    $("#lanes").innerHTML = `<div class="skeleton">${LAYERS.map(() => `
      <section class="lane">
        <div class="sk-line"></div>
        <div class="sk-grid">${Array.from({ length: 7 }, () => `<div class="sk-card"></div>`).join("")}</div>
      </section>`).join("")}</div>`;
    $("#timeline").innerHTML = Array.from({ length: 24 }, () => `<div class="seg none"></div>`).join("");
    $("#issues").innerHTML = `<div class="empty shimmer">Loading history…</div>`;
    $("#ribbonSummary").textContent = "loading history…";
  }

  /* ---------------- render ---------------- */
  function render() {
    if (!snap || snap.pending) return;
    const nodes = snap.nodes || [];
    renderHeader(nodes);
    renderRibbon();
    renderLanes(nodes);
    renderIssues();
    renderSources();
    if (!hashOpened) {
      const m = location.hash.match(/#node=(.+)$/);
      if (m) {
        hashOpened = true;
        const id = decodeURIComponent(m[1]);
        if (nodes.some((n) => n.id === id)) openNode(id);
      }
    }
    if (current && currentNode) {
      const n = nodes.find((x) => x.id === current);
      if (n) { currentNode = n; renderDrawer(); }
    }
  }

  function renderHeader(nodes) {
    const c = { up: 0, degraded: 0, down: 0, unknown: 0 };
    nodes.forEach((n) => (c[n.status] = (c[n.status] || 0) + 1));
    const core = nodes.filter((n) => n.layer !== "app");
    const worstCore = core.reduce((a, n) => (SEV[n.status] > SEV[a] ? n.status : a), "up");
    const worstApp = nodes.filter((n) => n.layer === "app")
      .reduce((a, n) => (SEV[n.status] > SEV[a] ? n.status : a), "up");
    // one dead website is not "the estate is down": app-only failures are degraded
    const worst = worstCore === "down" ? "down" : (worstCore === "degraded" || worstApp !== "up") ? "degraded" : "up";
    $("#overallDot").className = "dot " + worst;
    $("#overall").className = "overall " + worst;
    $("#overallText").textContent =
      worst === "up" ? "All systems operational" :
      worst === "degraded" ? "Degraded — something needs a look" : "Outage in progress";
    $("#counts").innerHTML = [
      ["up", "operational"], ["degraded", "degraded"], ["down", "down"], ["unknown", "unknown"],
    ].map(([k, label]) =>
      `<span class="c"><span class="dot ${k}"></span><b class="${c[k] ? "" : "zero"}">${c[k] || 0}</b>${label}</span>`).join("");
    const ts = snap.ts ? new Date(snap.ts * 1000) : null;
    const age = ts ? Math.round((Date.now() - ts.getTime()) / 1000) : null;
    $("#updated").textContent = ts
      ? `polled ${age < 90 ? age + "s" : Math.round(age / 60) + "m"} ago · ${snap.generated_ms}ms`
      : "—";
  }

  function renderRibbon() {
    const b = history.buckets || [];
    $("#timeline").innerHTML = b.map((x, i) => {
      let cls = "none", title = "no data";
      if (x.degraded != null) {
        cls = x.degraded === 0 ? "" : x.degraded < 15 ? "warn" : "bad";
        title = `${x.degraded}% of checks not green`;
      }
      if (i === b.length - 1) cls += " now";
      return `<div class="seg ${cls}" title="${esc(title)} · ${new Date(x.start * 1000).toLocaleTimeString()}"></div>`;
    }).join("");
    const eps = history.episodes || [];
    const open = eps.filter((e) => e.ongoing).length;
    $("#ribbonSummary").textContent = eps.length
      ? `${eps.length} incident${eps.length === 1 ? "" : "s"}${open ? ` · ${open} ongoing` : ""}`
      : "green throughout";
  }

  function metricBars(n) {
    const m = n.metrics || {};
    const vm = n.layer === "vm";
    const bar = (v, label) => {
      if (v == null) return "";
      // KVM guests always look full: only flag real pressure
      const cls = vm && label === "mem" ? (v > 98 ? "bad" : v > 95 ? "warn" : "")
        : v > 90 ? "bad" : v > 75 ? "warn" : "";
      return `<span class="bar" title="${label} ${v}%"><i class="${cls}" style="width:${Math.min(100, v)}%"></i></span>`;
    };
    if (n.layer === "hypervisor" || n.layer === "vm") return bar(m.cpu, "cpu") + bar(m.mem, "mem");
    if (n.layer === "docker") {
      const p = m.containers ? (100 * (m.running || 0)) / m.containers : 100;
      return `<span class="bar" title="${m.running}/${m.containers} running"><i class="${p < 100 ? "warn" : ""}" style="width:${p}%"></i></span>`;
    }
    if (n.layer === "service") {
      const p = m.desired ? (100 * (m.running || 0)) / m.desired : 0;
      return `<span class="bar" title="${m.running}/${m.desired} replicas"><i class="${p < 100 ? "bad" : ""}" style="width:${Math.min(100, p || 4)}%"></i></span>`;
    }
    return "";
  }

  function card(n) {
    const bad = (n.issues || []).length;
    const code = n.layer === "app" && n.metrics && n.metrics.code ? `${n.metrics.code} · ` : "";
    return `<button class="card ${n.status}" data-id="${esc(n.id)}" title="${esc(n.name + " — " + (n.subtitle || ""))}">
      ${bad ? `<span class="badge">${bad}</span>` : ""}
      <div class="row1"><span class="dot ${n.status}"></span><span class="name">${esc(n.name)}</span></div>
      <div class="sub">${esc(code)}${esc(n.subtitle || "")}</div>
      <div class="bars">${metricBars(n)}</div>
    </button>`;
  }

  function renderLanes(nodes) {
    $("#lanes").innerHTML = LAYERS.map((L) => {
      const items = nodes.filter((n) => n.layer === L.key)
        .sort((a, b) => SEV[b.status] - SEV[a.status] || a.name.localeCompare(b.name));
      if (!items.length) return "";
      const counts = items.reduce((a, n) => ((a[n.status] = (a[n.status] || 0) + 1), a), {});
      const spark = items.slice(0, 40).map((n) =>
        `<i class="${n.status === "degraded" ? "warn" : n.status === "down" ? "bad" : n.status === "unknown" ? "unknown" : ""}"></i>`).join("");
      const bits = [`${items.length}`];
      bits.push(`${counts.up || 0} up`);
      if (counts.degraded) bits.push(`${counts.degraded} degraded`);
      if (counts.down) bits.push(`${counts.down} down`);
      if (counts.unknown) bits.push(`${counts.unknown} unknown`);
      return `<section class="lane" data-layer="${L.key}">
        <div class="lane-head">
          <span class="lane-ico">${L.ico}</span>
          <h3>${L.label}</h3>
          <span class="n">${bits.join(" · ")}</span>
          <span class="spark">${spark}</span>
        </div>
        <div class="cards">${items.map(card).join("")}</div>
      </section>`;
    }).join("");
    document.querySelectorAll(".card").forEach((el) => {
      el.onclick = () => openNode(el.dataset.id);
    });
  }

  function ago(ts) {
    const s = Math.max(0, Math.round((Date.now() / 1000) - ts));
    if (s < 90) return `${s}s ago`;
    if (s < 5400) return `${Math.round(s / 60)}m ago`;
    return `${Math.round(s / 3600)}h ago`;
  }
  function dur(s) {
    if (s < 120) return `${s}s`;
    if (s < 7200) return `${Math.round(s / 60)}m`;
    return `${(s / 3600).toFixed(1)}h`;
  }

  function renderIssues() {
    const eps = history.episodes || [];
    if (!eps.length) {
      $("#issues").innerHTML = `<div class="empty">Nothing has changed state in the last 12 hours.</div>`;
      return;
    }
    $("#issues").innerHTML = eps.slice(0, 40).map((e) => `
      <div class="issue ${e.status === "down" ? "bad" : ""} ${e.ongoing ? "ongoing" : ""}" data-id="${esc(e.node_id)}">
        <span class="who"><span class="dot ${e.status}"></span> ${esc(e.name)}</span>
        <span class="what">${esc((e.issues || []).join(" · ") || e.status)}</span>
        <span class="dur">${e.ongoing ? "ongoing" : dur(e.duration_s)}</span>
        <span class="when">${ago(e.end)}</span>
      </div>`).join("");
    document.querySelectorAll(".issue").forEach((el) => (el.onclick = () => openNode(el.dataset.id)));
  }

  function renderSources() {
    const s = snap.sources || {};
    $("#srcbar").innerHTML = Object.entries(s).map(([k, v]) =>
      `<span class="srcchip"><span class="dot ${v.ok ? "up" : "down"}"></span>${esc(k)}${v.detail ? ` · ${esc(v.detail)}` : ""}</span>`).join("")
      + `<span class="srcchip">poll every ${(snap.poll_seconds || 60)}s · ${(snap.nodes || []).length} objects</span>`;
  }

  /* ---------------- drawer ---------------- */
  function openNode(id) {
    current = id;
    try { window.history.replaceState(null, "", "#node=" + encodeURIComponent(id)); } catch (e) { /* sandboxed */ }
    tab = "overview";
    currentNode = (snap.nodes || []).find((n) => n.id === id) || null;
    $("#drawer").classList.add("on");
    $("#drawer").setAttribute("aria-hidden", "false");
    $("#scrim").classList.add("on");
    document.querySelectorAll("#dTabs button").forEach((b) =>
      b.classList.toggle("on", b.dataset.tab === tab));
    renderDrawer(true);
  }

  function closeDrawer() {
    try { if (current) window.history.replaceState(null, "", location.pathname); } catch (e) { /* sandboxed */ }
    current = null;
    currentNode = null;
    $("#drawer").classList.remove("on");
    $("#drawer").setAttribute("aria-hidden", "true");
    $("#scrim").classList.remove("on");
  }
  $("#dClose").onclick = closeDrawer;
  $("#scrim").onclick = closeDrawer;
  document.querySelectorAll("#dTabs button").forEach((b) => {
    b.onclick = () => {
      tab = b.dataset.tab;
      document.querySelectorAll("#dTabs button").forEach((x) =>
        x.classList.toggle("on", x === b));
      renderDrawer(false);
    };
  });

  let elapsedTimer = null;

  function renderDrawer(loading) {
    if (!currentNode) return;
    const n = currentNode;
    const seq = ++detailSeq;
    $("#dName").textContent = n.name;
    $("#dCrumb").textContent = (LAYERS.find((l) => l.key === n.layer) || {}).label || n.layer;
    $("#dPill").textContent = n.status;
    $("#dPill").className = "pill " + n.status;

    if (loading) {
      // live detail fans out to PVE + several MCP tools; say so, and count up
      const t0 = Date.now();
      $("#dBody").innerHTML = `
        <div class="loading-note"><span class="spinner"></span>
          <span>Fetching live detail… <b id="dElapsed">0s</b></span></div>
        <div class="dskeleton">
          <div class="sk-grid" style="grid-template-columns:1fr 1fr">
            ${Array.from({ length: 6 }, () => `<div class="sk-card"></div>`).join("")}
          </div>
          <div class="sk-line" style="width:60%"></div>
          <div class="sk-card" style="height:90px"></div>
        </div>`;
      progress.start();
      clearInterval(elapsedTimer);
      elapsedTimer = setInterval(() => {
        const el = $("#dElapsed");
        if (!el) return clearInterval(elapsedTimer);
        const s = Math.round((Date.now() - t0) / 1000);
        el.textContent = s === 0 ? "0s" : s < 60 ? s + "s" : Math.floor(s / 60) + "m " + (s % 60) + "s";
      }, 500);
    }

    fetch(`/api/node/${encodeURIComponent(current)}`)
      .then((r) => r.json())
      .then((d) => {
        if (seq !== detailSeq || current !== n.id) return;
        clearInterval(elapsedTimer);
        progress.done();
        const det = d.detail || {};
        if (typeof det === "string" || !det.facts) {
          $("#dBody").innerHTML = `<div class="empty">${esc(d.detail || "No detail available.")}</div>`;
          return;
        }
        const facts = det.facts || {};
        const sections = det.sections || [];
        const hist = det.history || [];
        const factHtml = Object.entries(facts)
          .filter(([, v]) => v != null && v !== "")
          .map(([k, v]) => `<div class="fact"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`)
          .join("");

        const statusline = hist.length
          ? `<div class="statusline">${hist.map((p) => `<i class="${p.status}" title="${new Date(p.ts * 1000).toLocaleTimeString()} · ${p.status}"></i>`).join("")}</div>`
          : "";

        const sec = (s) => {
          if (s.kind === "pre") return `<div class="sec"><h4>${esc(s.title)}</h4><pre class="log">${esc(s.body)}</pre></div>`;
          if (s.kind === "table") {
            const t = s.body || {};
            return `<div class="sec"><h4>${esc(s.title)}</h4><table><thead><tr>${(t.columns || [])
              .map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>${(t.rows || [])
              .map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
          }
          if (s.kind === "kv") {
            return `<div class="sec"><h4>${esc(s.title)}</h4><div class="kv">${(s.body || [])
              .map((r) => `<div class="r"><span>${esc(r.k)}</span><span>${esc(r.v)}</span></div>`).join("")}</div></div>`;
          }
          return `<div class="sec"><h4>${esc(s.title)}</h4><div class="muted">${esc(s.body)}</div></div>`;
        };

        let body = "";
        if (tab === "overview") {
          body = statusline + `<div class="facts">${factHtml}</div>` +
            sections.filter((s) => s.kind !== "pre").map(sec).join("");
        } else if (tab === "stats") {
          body = chart("CPU %", hist, "cpu") + chart("Memory %", hist, "mem") +
            (n.layer === "app" ? chart("Latency ms", hist, "latency_ms") : "") +
            `<div class="sec"><h4>status timeline</h4>${statusline || '<div class="muted">no samples yet</div>'}</div>` +
            `<div class="muted" style="margin-top:10px">${hist.length} samples in the last 12 hours.</div>`;
        } else {
          const pres = sections.filter((s) => s.kind === "pre");
          body = pres.length ? pres.map(sec).join("") : `<div class="empty">No log source for this object.</div>`;
        }
        $("#dBody").innerHTML = body;
      })
      .catch(() => {
        if (seq !== detailSeq) return;
        clearInterval(elapsedTimer);
        progress.fail();
        $("#dBody").innerHTML = `<div class="empty">Could not load detail — the source did not answer in time.</div>`;
      });
  }

  function chart(label, hist, key) {
    const pts = hist.map((p, i) => {
      const v = key === "latency_ms" ? p.latency_ms : (p.metrics || {})[key];
      return v == null || isNaN(v) ? null : { x: i, y: Number(v) };
    });
    const vals = pts.filter(Boolean);
    if (vals.length < 2) return "";
    const max = Math.max(...vals.map((p) => p.y), key === "latency_ms" ? 1 : 100);
    const W = 480, H = 90, pad = 4;
    const step = W / Math.max(1, pts.length - 1);
    let d = "";
    pts.forEach((p, i) => {
      if (!p) return;
      const x = pad + i * step;
      const y = H - pad - (p.y / max) * (H - pad * 2);
      d += (d ? " L" : "M") + x.toFixed(1) + " " + y.toFixed(1);
    });
    const last = vals[vals.length - 1].y;
    return `<div class="spark-wrap">
      <div class="lab"><span>${esc(label)}</span><span>${last.toFixed(1)} (max ${max.toFixed(0)})</span></div>
      <svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" preserveAspectRatio="none">
        <path d="${d}" fill="none" stroke="var(--accent)" stroke-width="2" vector-effect="non-scaling-stroke"/>
      </svg></div>`;
  }

  /* ---------------- keyboard + loop ---------------- */
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeDrawer();
    if (e.target.matches("input,textarea")) return;
    if (e.key === "r" || e.key === "R") $("#refresh").click();
    if (e.key === "t" || e.key === "T") $("#theme").click();
  });

  load();
  timer = setInterval(() => { if (!document.hidden) load(); }, 30000);
})();
