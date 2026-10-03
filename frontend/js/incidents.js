/**
 * CYBERGUARD Incident Response, Playbook Execution & Preset Scenarios
 */

let activeIncidentForModal = null;

// Tab switcher for main navigation
function switchMainTab(tabId) {
  document.querySelectorAll(".nav-tab-btn").forEach(btn => btn.classList.remove("active"));
  document.querySelectorAll(".view-section").forEach(sec => sec.classList.remove("active"));

  const targetBtn = document.getElementById(`nav-btn-${tabId}`);
  const targetView = document.getElementById(`view-${tabId}`);
  if (targetBtn) targetBtn.classList.add("active");
  if (targetView) targetView.classList.add("active");

  if (tabId === "incidents") {
    loadIncidentsTable();
  } else if (tabId === "scenarios") {
    loadScenariosList();
  }
}

// Load Incidents Table
async function loadIncidentsTable() {
  const tbody = document.getElementById("incidents-tbody");
  if (!tbody) return;

  const statusFilter = document.getElementById("filter-incident-status")?.value || "";
  const levelFilter = document.getElementById("filter-incident-level")?.value || "";

  try {
    const incidents = await api.getIncidents({ status: statusFilter, level: levelFilter });
    tbody.innerHTML = "";

    if (!incidents || incidents.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:2rem; color:var(--text-dim);">No incidents match the selected filter.</td></tr>`;
      return;
    }

    incidents.forEach(inc => {
      const tr = document.createElement("tr");
      const levelClass = (inc.risk_level || "medium").toLowerCase();
      const isMitigated = inc.status && inc.status.startsWith("Mitigated");

      tr.innerHTML = `
        <td style="font-family:var(--font-mono); font-weight:700; color:var(--cyan-glow);">${escapeHtml(inc.id)}</td>
        <td style="font-size:0.8rem; color:var(--text-dim);">${escapeHtml(inc.timestamp)}</td>
        <td>
          <div style="font-weight:600; color:#ffffff;">${escapeHtml(inc.title)}</div>
          <div style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(inc.category)}</div>
        </td>
        <td style="font-family:var(--font-mono); font-size:0.8rem;">${escapeHtml(inc.source)}</td>
        <td>
          <span class="threat-badge ${levelClass}">${inc.risk_level} (${inc.risk_score})</span>
        </td>
        <td>
          <span style="font-weight:600; color:${isMitigated ? 'var(--safe-green)' : (inc.status === 'Open' ? 'var(--critical-red)' : 'var(--med-yellow)')};">
            ${escapeHtml(inc.status)}
          </span>
        </td>
        <td>
          <button class="btn-secondary" onclick="openMitigationModal('${inc.id}')" style="padding:0.35rem 0.75rem; font-size:0.75rem;">
            ${isMitigated ? 'Audit Logs' : '⚡ Mitigate'}
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Failed to load incidents:", err);
  }
}

// Open Mitigation Modal
async function openMitigationModal(incidentId) {
  try {
    const incidents = await api.getIncidents();
    const inc = incidents.find(i => i.id === incidentId);
    if (!inc) return;

    activeIncidentForModal = inc;
    const modal = document.getElementById("mitigation-modal");
    const titleEl = document.getElementById("modal-inc-title");
    const idEl = document.getElementById("modal-inc-id");
    const explanationEl = document.getElementById("modal-inc-explanation");
    const actionSelect = document.getElementById("modal-action-select");

    if (idEl) idEl.textContent = inc.id;
    if (titleEl) titleEl.textContent = inc.title;
    if (explanationEl) explanationEl.textContent = inc.explanation || "No automated explanation available.";

    // Select recommended action
    if (actionSelect && inc.recommended_action) {
      actionSelect.value = inc.recommended_action;
    }

    if (modal) modal.classList.add("active");
  } catch (err) {
    console.error("Failed to open modal:", err);
  }
}

function closeMitigationModal() {
  const modal = document.getElementById("mitigation-modal");
  if (modal) modal.classList.remove("active");
  activeIncidentForModal = null;
}

// Execute Mitigation from Modal
async function confirmExecuteMitigation() {
  if (!activeIncidentForModal) return;
  const actionCode = document.getElementById("modal-action-select").value;
  const analyst = document.getElementById("modal-analyst-name").value || "SecOps Analyst";

  showToast(`Deploying mitigation playbook '${actionCode}' for incident ${activeIncidentForModal.id}...`);

  try {
    const result = await api.executeIncidentAction(activeIncidentForModal.id, actionCode, analyst);
    showToast(`Mitigation complete! Playbook: ${result.playbook_execution?.playbook_name}`);
    closeMitigationModal();
    loadIncidentsTable();
    loadDashboardStats();
  } catch (err) {
    showToast(`Failed to execute mitigation: ${err.message}`, "error");
  }
}

// Reset Incidents
async function resetIncidentsToDefault() {
  if (!confirm("Reset all incident logs back to initial factory demo state?")) return;
  try {
    await api.resetIncidents();
    showToast("Incident ledger reset to default demonstration state.");
    loadIncidentsTable();
    loadDashboardStats();
  } catch (err) {
    showToast("Failed to reset incidents.", "error");
  }
}

// Load Preloaded Scenarios for 1-Click Testing
async function loadScenariosList() {
  const grid = document.getElementById("scenarios-grid");
  if (!grid) return;

  try {
    const scenarios = await api.getScenarios();
    grid.innerHTML = "";

    scenarios.forEach(sc => {
      const card = document.createElement("div");
      card.className = "scenario-card";
      card.innerHTML = `
        <div class="scenario-head">
          <div class="scenario-category">${escapeHtml(sc.category)}</div>
          <div class="scenario-title">${escapeHtml(sc.title)}</div>
          <div class="scenario-desc">${escapeHtml(sc.description)}</div>
        </div>
        <button class="btn-primary" onclick="loadAndRunScenario('${sc.id}')" style="align-self:flex-start;">
          🚀 Load &amp; Test Scenario
        </button>
      `;
      grid.appendChild(card);
    });
  } catch (err) {
    console.error("Failed to load scenarios:", err);
  }
}

// 1-Click Load & Run Scenario
async function loadAndRunScenario(scenarioId) {
  try {
    const scenarios = await api.getScenarios();
    const sc = scenarios.find(s => s.id === scenarioId);
    if (!sc) return;

    // Switch to analyzer tab
    switchMainTab("analyzer");

    if (sc.input_type === "phishing") {
      switchSubtab("phishing");
      document.getElementById("phish-sender").value = sc.payload.sender || "";
      document.getElementById("phish-subject").value = sc.payload.subject || "";
      document.getElementById("phish-text").value = sc.payload.text || "";
      document.getElementById("phish-type").value = sc.payload.message_type || "email";
      
      showToast(`Loaded "${sc.title}" - Running analysis...`);
      const result = await api.analyzeText(sc.payload);
      renderAnalysisResult(result);

    } else if (sc.input_type === "url") {
      switchSubtab("url");
      document.getElementById("url-input").value = sc.payload.url || "";
      
      showToast(`Loaded "${sc.title}" - Running analysis...`);
      const result = await api.analyzeUrl(sc.payload);
      renderAnalysisResult(result);

    } else if (sc.input_type === "impersonation") {
      switchSubtab("impersonation");
      document.getElementById("imp-mode-select").value = "text";
      document.getElementById("imp-identity").value = sc.payload.claimed_identity || "";
      document.getElementById("imp-role").value = sc.payload.claimed_role || "CEO";
      document.getElementById("imp-text").value = sc.payload.text || "";
      document.getElementById("imp-text-controls").style.display = "block";
      document.getElementById("imp-deepfake-controls").style.display = "none";

      showToast(`Loaded "${sc.title}" - Running analysis...`);
      const result = await api.analyzeImpersonation(sc.payload);
      renderAnalysisResult(result);

    } else if (sc.input_type === "deepfake") {
      switchSubtab("impersonation");
      document.getElementById("imp-mode-select").value = "deepfake";
      document.getElementById("imp-text-controls").style.display = "none";
      document.getElementById("imp-deepfake-controls").style.display = "block";
      document.getElementById("df-media-type").value = sc.payload.media_type || "audio";
      document.getElementById("df-filename").value = sc.payload.file_name || "";
      document.getElementById("df-spectral-flatness").value = sc.payload.spectral_flatness || 0.85;
      document.getElementById("df-breath-anomaly").checked = !!sc.payload.breath_pause_anomaly;
      document.getElementById("df-frequency-cutoff").value = sc.payload.audio_frequency_cutoff_khz || 8.0;
      switchDeepfakeMediaType(sc.payload.media_type || "audio");

      showToast(`Loaded "${sc.title}" - Running acoustic forensic inspection...`);
      const result = await api.analyzeImpersonation({
        mode: "deepfake",
        ...sc.payload
      });
      renderAnalysisResult(result);

    } else if (sc.input_type === "logs") {
      switchSubtab("logs");
      document.getElementById("log-user").value = sc.payload.user_id || "";
      document.getElementById("log-ip").value = sc.payload.source_ip || "";
      document.getElementById("log-location").value = sc.payload.location || "";
      document.getElementById("log-failed-attempts").value = sc.payload.failed_attempts || 0;
      document.getElementById("log-velocity").value = sc.payload.geo_velocity_kmh || 0;
      document.getElementById("log-egress-mb").value = sc.payload.bytes_transferred_mb || 0;
      document.getElementById("log-device-status").value = sc.payload.device_status || "Unknown";

      showToast(`Loaded "${sc.title}" - Running log anomaly analysis...`);
      const result = await api.analyzeLogs(sc.payload);
      renderAnalysisResult(result);
    }

  } catch (err) {
    showToast(`Error executing scenario: ${err.message}`, "error");
  }
}
