const params = new URLSearchParams(window.location.search);
const tokenFromQuery = params.get("token");
if (tokenFromQuery) {
  localStorage.setItem("oracle_token", tokenFromQuery);
}

async function fetchJson(path, options = {}) {
  const token = localStorage.getItem("oracle_token") || "";
  const headers = { ...(options.headers || {}) };
  if (token) {
    headers["X-Oracle-Token"] = token;
  }
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    throw new Error(`${path} -> ${response.status}`);
  }
  return response.json();
}

function renderCards(targetId, items, renderItem) {
  const target = document.getElementById(targetId);
  target.innerHTML = "";
  if (!items.length) {
    target.innerHTML = '<div class="card"><small>No data yet.</small></div>';
    return;
  }
  items.forEach((item) => {
    const node = document.createElement("div");
    node.className = "card";
    node.innerHTML = renderItem(item);
    target.appendChild(node);
  });
}

function renderOverview(overview) {
  const target = document.getElementById("overview");
  const build = overview.build_identity || {};
  target.innerHTML = `
    <div class="card">
      <strong>${overview.name || "mission"}</strong>
      <small>${overview.objective || "No objective set."}</small>
      <div>scope: ${(overview.scope || []).join(", ") || "n/a"}</div>
      <div>timeline depth: ${overview.timeline_depth || 0}</div>
      <div>version: ${build.semantic_version || "unknown"} / ${build.git_hash || "unknown"} / ${build.schema_version || "unknown"}</div>
    </div>
    <div class="card">
      <strong>Recent Directives</strong>
      <div>${(overview.recent_directives || []).join("<br>") || "<small>No directives.</small>"}</div>
    </div>
  `;
}

function renderFindings(items) {
  renderCards("findings", items || [], (item) => `
    <div class="finding-row">
      <div class="finding-title">${item.title || "Untitled finding"}</div>
      <div class="finding-meta">
        <span class="severity severity-${(item.severity || "INFO").toLowerCase()}">${item.severity || "INFO"}</span>
        <span>${item.host || "unknown host"}${item.port ? `:${item.port}` : ""}</span>
        <span>confidence ${(item.confidence || 0).toFixed(2)}</span>
        <span>${item.plugin || "unknown plugin"}</span>
      </div>
      <div class="finding-meta">${(item.cves || []).join(", ") || "no CVEs"} </div>
      <div class="finding-meta">${(item.evidence_refs || []).join(", ") || "no evidence refs"} </div>
    </div>
  `);
}

function renderCouncil(council) {
  renderCards("council", [council || {}], (item) => `
    <strong>${item.mode || "deterministic"}</strong>
    <small>backend ${item.backend || "unknown"}${item.last_arbiter ? ` • arbiter ${item.last_arbiter}` : ""}</small>
    <div>recommendations: ${item.recommendations_seen || 0}</div>
    <div>accepted: ${item.accepted_count || 0} • fallbacks: ${item.fallback_count || 0}</div>
    <div>last outcome: ${item.last_decision_outcome || "n/a"}${item.last_gate_reason ? ` • ${item.last_gate_reason}` : ""}</div>
    <div>agreement: ${item.agreement_count || 0}/${item.eligible_votes || 0}${item.is_unanimous ? " unanimous" : item.is_split_vote ? " split" : ""}</div>
    <div>override streak: ${item.current_override_streak || 0} current • ${item.max_override_streak || 0} max</div>
    <div>drift: rec ${item.recommendation_drift_count || 0} • final ${item.final_action_drift_count || 0} • arbiter ${item.arbiter_drift_count || 0}</div>
    <div>alerts: ${(item.alerts || []).join(", ") || "none"}</div>
    <div>last recommendation: ${(item.last_recommended_tool || "n/a")}${item.last_recommended_target ? ` -> ${item.last_recommended_target}` : ""}</div>
    <div>last decision: ${(item.last_decision_tool || "n/a")}${item.last_decision_target ? ` -> ${item.last_decision_target}` : ""} (${item.last_decision_source || "unknown"})</div>
    <div>${(item.role_breakdown || []).map((role) => `${role.role}: ${role.tool || "no tool"}${role.target ? ` -> ${role.target}` : ""} @ ${(role.confidence || 0).toFixed(2)}${role.agrees_with_arbiter ? " [arbiter]" : ""}${role.stop_reason ? ` (${role.stop_reason})` : ""}`).join("<br>") || "No council role data yet."}</div>
    <div>${(item.recent_rounds || []).slice(0, 3).map((round) => `${round.phase || "phase"}: ${round.outcome} • ${round.tool || "n/a"}${round.target ? ` -> ${round.target}` : ""}`).join("<br>") || "No recent council rounds."}</div>
    <div>${item.last_drift && item.last_drift.kind ? `last drift: ${item.last_drift.kind} ${item.last_drift.from || "n/a"} -> ${item.last_drift.to || "n/a"}` : "last drift: none"}</div>
  `);
}

async function refreshDashboard() {
  const [overview, workers, approvals, liveStream, evidence, artifacts, chat] = await Promise.all([
    fetchJson("/api/dashboard/overview"),
    fetchJson("/api/dashboard/workers"),
    fetchJson("/api/dashboard/approvals"),
    fetchJson("/api/dashboard/live-stream"),
    fetchJson("/api/dashboard/evidence"),
    fetchJson("/api/dashboard/artifacts"),
    fetchJson("/api/dashboard/chat"),
  ]);

  document.getElementById("mission-phase").textContent = overview.phase || "INIT";
  document.getElementById("mission-status").textContent = overview.status || "unknown";
  document.getElementById("metric-hosts").textContent = `${overview.stats.hosts || 0} hosts`;
  document.getElementById("metric-findings").textContent = `${overview.stats.findings || 0} findings`;
  document.getElementById("metric-workers").textContent = `${workers.items.length} workers`;
  const build = overview.build_identity || {};
  document.getElementById("build-id").textContent = `${build.semantic_version || "unknown"} • ${build.git_hash || "unknown"} • ${build.schema_version || "unknown"}`;
  renderOverview(overview);
  renderFindings(overview.analyst_findings || []);
  renderCouncil(overview.council || {});

  renderCards("workers", workers.items, (worker) => `
    <strong>${worker.worker_id}</strong>
    <small>${worker.transport} • ${worker.role}</small>
    <div>health: ${worker.health_score}</div>
    <div>capabilities: ${(worker.capabilities || []).join(", ")}</div>
  `);

  renderCards("approvals", approvals.items || [], (item) => `
    <strong>${item.approval_id}</strong>
    <small>${item.status} • ${item.requested_by}</small>
    <div>${JSON.stringify(item.action)}</div>
  `);

  renderCards("timeline", liveStream.items || [], (item) => `
    <strong>${item.headline || item.event_type || "event"}</strong>
    <small>${item.channel || "system"} • ${item.priority || "info"} • ${item.created_at || ""}</small>
    <div>${item.summary || ""}</div>
    <div>${item.narrative || ""}</div>
    <div>${item.operator_action ? `<em>${item.operator_action}</em>` : ""}</div>
  `);

  renderCards("attack-graph", [overview.attack_graph || {}], (item) => `
    <strong>${item.nodes || 0} nodes / ${item.edges || 0} edges</strong>
    <small>Top correlated paths</small>
    <div>${(item.top_paths || []).slice(0, 3).map((path) => `${(path.path || []).join(" -> ")} (${(path.score || 0).toFixed ? path.score.toFixed(2) : path.score})`).join("<br>") || "No paths yet."}</div>
    <small>Highest risk nodes</small>
    <div>${(item.top_nodes || []).slice(0, 3).map((node) => `${node.label || node.id} [${node.kind || "node"}] risk ${(node.risk_score || 0).toFixed ? node.risk_score.toFixed(2) : node.risk_score}`).join("<br>") || "No weighted nodes yet."}</div>
  `);

  renderCards("replay", [overview.replay_summary || {}], (item) => `
    <strong>${item.count || 0} replay artifacts</strong>
    <small>latest replay ${item.latest_replay_id || "n/a"}</small>
    <div>phase: ${item.latest_phase || "n/a"}</div>
    <div class="artifact-path">${item.latest_artifact || "No replay artifact yet."}</div>
  `);

  renderCards("topology", [overview.topology || {}], (item) => `
    <strong>${(item.nodes || []).length} topology nodes</strong>
    <small>${(item.edges || []).length} topology edges</small>
    <div>${(item.nodes || []).slice(0, 6).map((node) => `${node.kind}: ${node.label}`).join("<br>") || "No topology yet."}</div>
  `);

  renderCards("artifacts", artifacts.items || [], (item) => `
    <strong>${item.name || item.path}</strong>
    <small>${item.artifact_type || item.content_type || "artifact"}</small>
    <div>${item.download_url ? `<a class="artifact-link" href="${item.download_url}">download</a>` : ""}</div>
  `);

  renderCards("chat", chat.messages || [], (item) => `
    <strong>${item.user || "operator"}</strong>
    <small>${item.ts || ""}</small>
    <div>${item.text || ""}</div>
  `);
}

document.getElementById("chat-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = document.getElementById("chat-input");
  const text = input.value.trim();
  if (!text) {
    return;
  }
  await fetchJson("/api/dashboard/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user: "operator", text }),
  });
  input.value = "";
  await refreshDashboard();
});

refreshDashboard().catch((error) => {
  document.getElementById("overview").innerHTML = `<div class="card">${error.message}</div>`;
});
setInterval(() => refreshDashboard().catch(() => null), 5000);
