// BugHound webui — vanilla JS, no build step, no dependencies.
//
// Workspace list polls /api/workspaces every 5s. Selecting a workspace
// fetches its dashboard + findings and opens an EventSource on
// /api/workspaces/{id}/events for live job updates.

(() => {
  "use strict";

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  const STAGE_NAMES = {
    0: "Initialize", 1: "Enumerate", 2: "Discover",
    3: "Analyze", 4: "Test", 5: "Validate", 6: "Report",
  };

  let state = {
    selected: null,         // workspace_id
    eventSource: null,      // active EventSource
    pollTimer: null,        // workspace-list refresh timer
  };

  // ---------------------------------------------------------------------
  // health probe
  // ---------------------------------------------------------------------
  async function checkHealth() {
    try {
      const r = await fetch("/api/health");
      if (r.ok) {
        setConn("connected", "ok");
      } else {
        setConn(`http ${r.status}`, "err");
      }
    } catch (e) {
      setConn("offline", "err");
    }
  }

  function setConn(text, kind) {
    const el = $("#connStatus");
    el.textContent = text;
    el.className = "status " + (kind || "");
  }

  // ---------------------------------------------------------------------
  // workspace list
  // ---------------------------------------------------------------------
  async function refreshWorkspaces() {
    try {
      const r = await fetch("/api/workspaces");
      if (!r.ok) throw new Error(`status ${r.status}`);
      const data = await r.json();
      renderWorkspaceList(data.workspaces || []);
    } catch (e) {
      $("#wsList").innerHTML = `<li class="ws-empty">error: ${e.message}</li>`;
    }
  }

  function renderWorkspaceList(workspaces) {
    const ul = $("#wsList");
    if (!workspaces.length) {
      ul.innerHTML = `<li class="ws-empty">no workspaces</li>`;
      return;
    }
    ul.innerHTML = workspaces.map(w => {
      const cls = w.workspace_id === state.selected ? "active" : "";
      const stats = w.stats || {};
      const sub  = stats.subdomains_found || 0;
      const host = stats.live_hosts || 0;
      const url  = stats.urls_discovered || 0;
      return `
        <li class="${cls}" data-id="${w.workspace_id}">
          <div class="ws-target">${escapeHtml(w.target)}</div>
          <div class="ws-meta">${w.state} · subs:${sub} · hosts:${host} · urls:${url}</div>
        </li>`;
    }).join("");
    ul.querySelectorAll("li[data-id]").forEach(li => {
      li.addEventListener("click", () => selectWorkspace(li.dataset.id));
    });
  }

  // ---------------------------------------------------------------------
  // workspace detail
  // ---------------------------------------------------------------------
  async function selectWorkspace(wsId) {
    state.selected = wsId;
    refreshWorkspaces(); // re-render to highlight
    $("#empty").hidden = true;
    $("#detail").hidden = false;
    $("#dId").textContent = wsId;

    closeEventStream();

    await Promise.all([
      loadDashboard(wsId),
      loadFindings(wsId),
    ]);
    openEventStream(wsId);
  }

  async function loadDashboard(wsId) {
    try {
      const r = await fetch(`/api/workspaces/${encodeURIComponent(wsId)}/dashboard`);
      if (!r.ok) throw new Error(`status ${r.status}`);
      const dash = await r.json();
      renderDashboard(dash);
    } catch (e) {
      $("#dTarget").textContent = `error: ${e.message}`;
    }
  }

  function renderDashboard(dash) {
    $("#dTarget").textContent = dash.target;
    $("#dState").textContent = dash.state || "?";
    $("#dDepth").textContent = `stage ${dash.current_stage}`;

    // Stages list
    const completed = new Set(dash.stages_completed || []);
    const pending = new Set(dash.stages_pending || []);
    const allStages = [0, 1, 2, 3, 4, 5, 6];
    $("#stageList").innerHTML = allStages.map(s => {
      const name = STAGE_NAMES[s];
      let cls = "skip";
      if (completed.has(s)) cls = "done";
      else if (pending.has(s)) cls = "pending";
      return `<li class="${cls}">${s}. ${name}</li>`;
    }).join("");

    // Categories table
    const cats = (dash.categories || []).filter(c => c.count !== null && c.count > 0);
    if (!cats.length) {
      $("#catBody").innerHTML = `<tr class="empty"><td colspan="2">no data collected yet</td></tr>`;
    } else {
      $("#catBody").innerHTML = cats.map(c => `
        <tr>
          <td>${escapeHtml(c.name)}</td>
          <td class="num">${c.count}</td>
        </tr>`).join("");
    }
  }

  async function loadFindings(wsId) {
    try {
      const r = await fetch(`/api/workspaces/${encodeURIComponent(wsId)}/findings`);
      if (!r.ok) {
        $("#findingsEmpty").hidden = false;
        $("#findingsBody").innerHTML = "";
        return;
      }
      const result = await r.json();
      const items = result.items || [];
      renderFindings(items);
    } catch (e) {
      $("#findingsEmpty").hidden = false;
      $("#findingsEmpty").textContent = `error: ${e.message}`;
      $("#findingsBody").innerHTML = "";
    }
  }

  function renderFindings(items) {
    if (!items.length) {
      $("#findingsEmpty").hidden = false;
      $("#findingsBody").innerHTML = "";
      return;
    }
    $("#findingsEmpty").hidden = true;
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sorted = items.slice().sort((a, b) =>
      (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9)
    );
    $("#findingsBody").innerHTML = sorted.map(f => {
      const sev = (f.severity || "info").toLowerCase();
      const cls = f.vulnerability_class || f.template_id || "?";
      const ep = f.endpoint || f.host || "?";
      const status = f.validation_status || (f.needs_validation ? "pending" : "definitive");
      return `
        <tr>
          <td><span class="sev ${sev}">${sev.toUpperCase()}</span></td>
          <td>${escapeHtml(cls)}</td>
          <td>${escapeHtml(ep)}</td>
          <td>${escapeHtml(status)}</td>
        </tr>`;
    }).join("");
  }

  // ---------------------------------------------------------------------
  // SSE live event stream
  // ---------------------------------------------------------------------
  function openEventStream(wsId) {
    const url = `/api/workspaces/${encodeURIComponent(wsId)}/events`;
    const es = new EventSource(url);
    state.eventSource = es;

    setEvtStatus("connecting", false);

    es.addEventListener("ready", () => setEvtStatus("live", true));
    es.addEventListener("job", (e) => {
      try {
        const snapshot = JSON.parse(e.data);
        prependEvent(snapshot);
        // Refresh the workspace stats on each event — cheap and keeps the
        // sidebar/dashboard in sync without a full reload.
        refreshWorkspaces();
      } catch (err) {
        console.warn("bad SSE frame", err);
      }
    });
    es.onerror = () => setEvtStatus("disconnected", false);
  }

  function closeEventStream() {
    if (state.eventSource) {
      state.eventSource.close();
      state.eventSource = null;
    }
    setEvtStatus("disconnected", false);
    $("#evtList").innerHTML = "";
  }

  function setEvtStatus(text, live) {
    const el = $("#evtStatus");
    el.textContent = text;
    el.classList.toggle("live", !!live);
  }

  function prependEvent(snapshot) {
    const time = new Date().toLocaleTimeString();
    const status = (snapshot.status || "").toLowerCase();
    const cls = `evt-status-${status}`;
    const li = document.createElement("li");
    li.innerHTML = `
      <span class="evt-time">${escapeHtml(time)}</span>
      <span class="evt-id">${escapeHtml(snapshot.job_id || "?")}</span>
      <span class="evt-msg">
        <span class="${cls}">${escapeHtml(snapshot.status || "?")}</span>
        · ${snapshot.progress_pct ?? 0}%
        ${snapshot.message ? `· ${escapeHtml(snapshot.message)}` : ""}
      </span>`;
    const list = $("#evtList");
    list.insertBefore(li, list.firstChild);
    // Cap to 200 entries.
    while (list.children.length > 200) list.removeChild(list.lastChild);
  }

  // ---------------------------------------------------------------------
  // tab switching
  // ---------------------------------------------------------------------
  function wireTabs() {
    $$(".tab").forEach(btn => {
      btn.addEventListener("click", () => {
        const name = btn.dataset.tab;
        $$(".tab").forEach(b => b.classList.toggle("active", b === btn));
        $$(".tab-pane").forEach(p => p.hidden = p.dataset.pane !== name);
      });
    });
  }

  // ---------------------------------------------------------------------
  // utilities
  // ---------------------------------------------------------------------
  function escapeHtml(s) {
    if (s === null || s === undefined) return "";
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // ---------------------------------------------------------------------
  // boot
  // ---------------------------------------------------------------------
  function boot() {
    wireTabs();
    $("#refreshBtn").addEventListener("click", refreshWorkspaces);
    $("#evtClear").addEventListener("click", () => $("#evtList").innerHTML = "");

    checkHealth();
    refreshWorkspaces();

    // Poll the workspace list every 5s so newly-created workspaces appear.
    state.pollTimer = setInterval(refreshWorkspaces, 5000);
    // Health check every 30s.
    setInterval(checkHealth, 30000);
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
