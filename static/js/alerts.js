// Alerts page: rule editor, active alerts, event history.
// Plain ES module - no build step, no dependencies.

const METRICS = {
  cpu_percent: ['CPU', '%'],
  mem_percent: ['Memory', '%'],
  disk_percent: ['Disk', '%'],
  containers_running: ['Running containers', ''],
  node_offline: ['Node offline', ''],
  verdict_level: ['Report verdict (healthy=0, degraded=1, failing=2)', ''],
};

const OPS = ['>', '>=', '<', '<=', '==', '!=', 'at_least'];

const $ = (id) => document.getElementById(id);

function esc(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

async function api(url, options = {}) {
  const res = await fetch(url, {
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    ...options,
  });
  let body = null;
  try { body = await res.json(); } catch { body = null; }
  if (!res.ok || !body || body.success === false) {
    throw new Error((body && body.error) || `HTTP ${res.status}`);
  }
  return body;
}

function banner(message, kind = 'error') {
  const el = $('banner');
  if (!message) { el.classList.add('hidden'); return; }
  el.className = 'mt-4 rounded-lg border px-4 py-3 text-sm ' + (
    kind === 'error'
      ? 'border-rose-500/40 bg-rose-500/10 text-rose-200'
      : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
  );
  el.textContent = message;
}

function seconds(value) {
  const n = Number(value || 0);
  if (!n) return 'immediately';
  if (n % 3600 === 0) return `${n / 3600}h`;
  if (n % 60 === 0) return `${n / 60}m`;
  return `${n}s`;
}

function severityClass(sev) {
  if (sev === 'critical') return 'border-rose-500/40 bg-rose-500/10 text-rose-200';
  if (sev === 'warning') return 'border-amber-500/40 bg-amber-500/10 text-amber-200';
  return 'border-sky-500/40 bg-sky-500/10 text-sky-200';
}

function since(iso) {
  if (!iso) return '-';
  const then = Date.parse(iso.endsWith('Z') ? iso : `${iso}Z`);
  if (!Number.isFinite(then)) return iso;
  const sec = Math.max(0, (Date.now() - then) / 1000);
  if (sec < 60) return `${Math.floor(sec)}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

// ------------------------------------------------------------------ render

function renderRules(rules) {
  const body = $('rules-body');
  body.innerHTML = '';
  if (!rules.length) {
    body.innerHTML = '<tr><td colspan="6" class="px-4 py-6 text-center text-slate-500">No rules yet.</td></tr>';
    return;
  }
  rules.forEach((rule) => {
    const [label, unit] = METRICS[rule.metric] || [rule.metric, ''];
    const tr = document.createElement('tr');
    tr.className = 'border-t border-white/5 row-hover';
    tr.innerHTML = `
      <td class="px-4 py-2 text-slate-200">${esc(rule.name)}
        ${rule.enabled ? '' : '<span class="ml-2 text-[10px] text-slate-500">disabled</span>'}</td>
      <td class="px-3 py-2 text-slate-300">${esc(label)} ${esc(rule.op)} ${rule.threshold}${esc(unit)}</td>
      <td class="px-3 py-2 text-right tabular-nums text-slate-400">${seconds(rule.for_seconds)}</td>
      <td class="px-3 py-2 text-right tabular-nums text-slate-400">${seconds(rule.cooldown_seconds)}</td>
      <td class="px-3 py-2"><span class="text-[10px] px-1.5 py-0.5 rounded border ${severityClass(rule.severity)}">${esc(rule.severity)}</span></td>
      <td class="px-4 py-2 text-right whitespace-nowrap">
        <button data-edit="${rule.id}" class="text-sky-300 hover:text-sky-200 mr-3">edit</button>
        <button data-toggle="${rule.id}" class="text-slate-300 hover:text-white mr-3">${rule.enabled ? 'disable' : 'enable'}</button>
        <button data-delete="${rule.id}" class="text-rose-300 hover:text-rose-200">delete</button>
      </td>`;
    body.appendChild(tr);
  });

  body.querySelectorAll('[data-edit]').forEach((btn) => btn.addEventListener('click', () => {
    const rule = rules.find((r) => String(r.id) === btn.dataset.edit);
    if (rule) openRule(rule);
  }));
  body.querySelectorAll('[data-toggle]').forEach((btn) => btn.addEventListener('click', async () => {
    const rule = rules.find((r) => String(r.id) === btn.dataset.toggle);
    if (!rule) return;
    try {
      await api(`/api/alerts/rules/${rule.id}`, {
        method: 'PUT',
        body: JSON.stringify({ enabled: !rule.enabled }),
      });
      await load();
    } catch (err) { banner(err.message); }
  }));
  body.querySelectorAll('[data-delete]').forEach((btn) => btn.addEventListener('click', async () => {
    if (!confirm('Delete this rule? Existing events are kept.')) return;
    try {
      await api(`/api/alerts/rules/${btn.dataset.delete}`, { method: 'DELETE' });
      await load();
    } catch (err) { banner(err.message); }
  }));
}

function renderActive(events) {
  const list = $('active-list');
  $('active-count').textContent = events.length ? `(${events.length})` : '';
  $('active-empty').classList.toggle('hidden', events.length > 0);
  list.innerHTML = '';
  events.forEach((event) => {
    const el = document.createElement('div');
    el.className = 'card rounded-xl px-4 py-3 border-l-2 ' + (
      event.severity === 'critical' ? 'border-l-rose-500' :
      event.severity === 'warning' ? 'border-l-amber-500' : 'border-l-sky-500');
    el.innerHTML = `
      <div class="flex flex-wrap items-center gap-2">
        <span class="text-[10px] px-1.5 py-0.5 rounded border ${severityClass(event.severity)}">${esc(event.severity)}</span>
        <span class="text-sm text-slate-100">${esc(event.rule_name)}</span>
        <span class="text-[11px] text-slate-500">${esc(event.host_key)} &middot; since ${since(event.started_at)}</span>
        ${event.notified ? '' : '<span class="text-[10px] text-amber-300">not delivered</span>'}
      </div>
      <div class="mt-1 text-xs text-slate-400">${esc(event.message)}</div>`;
    list.appendChild(el);
  });
}

function renderEvents(events) {
  const body = $('events-body');
  $('events-empty').classList.toggle('hidden', events.length > 0);
  body.innerHTML = '';
  events.forEach((event) => {
    const tr = document.createElement('tr');
    tr.className = 'border-t border-white/5 row-hover';
    tr.innerHTML = `
      <td class="px-4 py-2 text-slate-400 whitespace-nowrap" title="${esc(event.started_at || '')}">${since(event.started_at)}</td>
      <td class="px-3 py-2 text-slate-300">${esc(event.host_key)}</td>
      <td class="px-3 py-2 text-slate-300">${esc(event.rule_name)}</td>
      <td class="px-3 py-2 text-slate-400">${esc(event.message)}</td>
      <td class="px-3 py-2">
        <span class="text-[10px] px-1.5 py-0.5 rounded border ${
          event.state === 'firing'
            ? 'border-rose-500/40 bg-rose-500/10 text-rose-200'
            : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'}">${esc(event.state)}</span>
      </td>
      <td class="px-4 py-2 text-slate-400">${event.notified ? 'yes' : (esc(event.notify_error) || 'no')}</td>`;
    body.appendChild(tr);
  });
}

// ------------------------------------------------------------------ editor

let editingId = null;
let currentRules = [];

function fillSelects() {
  const metricSel = $('r-metric');
  metricSel.innerHTML = Object.entries(METRICS)
    .map(([key, [label]]) => `<option value="${key}">${esc(label)}</option>`).join('');
  const opSel = $('r-op');
  opSel.innerHTML = OPS.map((op) => `<option value="${op}">${op}</option>`).join('');
}

function openRule(rule) {
  editingId = rule ? rule.id : null;
  $('rule-modal-title').textContent = rule ? 'Edit rule' : 'New rule';
  $('r-name').value = rule ? rule.name : '';
  $('r-metric').value = rule ? rule.metric : 'mem_percent';
  $('r-op').value = rule ? rule.op : '>=';
  $('r-threshold').value = rule ? rule.threshold : 90;
  $('r-severity').value = rule ? rule.severity : 'warning';
  $('r-for').value = rule ? rule.for_seconds : 300;
  $('r-cooldown').value = rule ? rule.cooldown_seconds : 1800;
  $('r-enabled').checked = rule ? rule.enabled : true;
  $('rule-error').classList.add('hidden');
  // Shared dialog chrome (static/js/modals.js): .app-modal is flex via CSS,
  // so only the `hidden` class needs toggling and Escape/backdrop work for free.
  if (typeof window.openAppModal === 'function') window.openAppModal('rule-modal');
  else $('rule-modal').classList.remove('hidden');
}

function closeRule() {
  if (typeof window.closeAppModal === 'function') window.closeAppModal('rule-modal');
  else $('rule-modal').classList.add('hidden');
}

async function saveRule() {
  const payload = {
    name: $('r-name').value.trim() || 'Rule',
    metric: $('r-metric').value,
    op: $('r-op').value,
    threshold: Number($('r-threshold').value),
    severity: $('r-severity').value,
    for_seconds: Number($('r-for').value),
    cooldown_seconds: Number($('r-cooldown').value),
    enabled: $('r-enabled').checked,
  };
  try {
    if (editingId) {
      await api(`/api/alerts/rules/${editingId}`, { method: 'PUT', body: JSON.stringify(payload) });
    } else {
      await api('/api/alerts/rules', { method: 'POST', body: JSON.stringify(payload) });
    }
    closeRule();
    banner('Rule saved.', 'ok');
    setTimeout(() => banner(null), 2500);
    await load();
  } catch (err) {
    const box = $('rule-error');
    box.textContent = err.message;
    box.classList.remove('hidden');
  }
}

// ------------------------------------------------------------------ wiring

async function load() {
  try {
    const [rulesBody, eventsBody] = await Promise.all([
      api('/api/alerts/rules'),
      api('/api/alerts/events?limit=100'),
    ]);
    currentRules = rulesBody.rules || [];
    renderRules(currentRules);
    renderActive(eventsBody.active || []);
    renderEvents(eventsBody.events || []);
    banner(null);
  } catch (err) {
    banner(`Could not load alerts: ${err.message}`);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  fillSelects();
  $('btn-add').addEventListener('click', () => openRule(null));
  $('rule-close').addEventListener('click', closeRule);
  $('rule-cancel').addEventListener('click', closeRule);
  $('rule-save').addEventListener('click', saveRule);
  $('btn-refresh').addEventListener('click', load);
  $('btn-test').addEventListener('click', async () => {
    try {
      await api('/api/alerts/test', { method: 'POST' });
      banner('Test alert sent - check Discord.', 'ok');
    } catch (err) {
      banner(`Test failed: ${err.message}`);
    }
  });
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') closeRule();
  });
  load();
  setInterval(load, 30000);
});
