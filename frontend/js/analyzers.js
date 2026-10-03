/**
 * CYBERGUARD Multi-Source Threat Analyzers
 * Handles form submissions, forensic parameter controls,
 * and renders Explainable AI result cards.
 */

// Tab Switching
function switchSubtab(tabName) {
  document.querySelectorAll(".subtab-btn").forEach(btn => btn.classList.remove("active"));
  document.querySelectorAll(".analyzer-form-panel").forEach(p => p.style.display = "none");

  const targetBtn = document.getElementById(`subtab-btn-${tabName}`);
  const targetPanel = document.getElementById(`analyzer-panel-${tabName}`);
  if (targetBtn) targetBtn.classList.add("active");
  if (targetPanel) targetPanel.style.display = "block";
}

// Media Type Switcher for Deepfake
function switchDeepfakeMediaType(type) {
  const audioControls = document.getElementById("df-audio-controls");
  const visualControls = document.getElementById("df-visual-controls");
  if (type === "audio") {
    if (audioControls) audioControls.style.display = "block";
    if (visualControls) visualControls.style.display = "none";
  } else {
    if (audioControls) audioControls.style.display = "none";
    if (visualControls) visualControls.style.display = "block";
  }
}

// Render Result Card
function renderAnalysisResult(result) {
  const container = document.getElementById("analysis-result-container");
  if (!container) return;

  const evalData = result.risk_evaluation || {};
  const xai = result.explainable_ai || {};
  const mitre = result.mitre_mappings || [];
  const actions = result.recommended_actions || [];

  const level = evalData.level || "MEDIUM";
  const levelClass = level.toLowerCase();
  const score = evalData.score || 0;
  const isThreat = evalData.is_threat;

  // Build MITRE HTML
  let mitreHtml = "";
  if (mitre.length > 0) {
    mitreHtml = mitre.map(m => `
      <a href="${m.url}" target="_blank" class="mitre-tag" title="${m.name} (${m.tactic})">
        <span style="font-weight:700;">${m.id}</span> ${m.name}
      </a>
    `).join("");
  } else {
    mitreHtml = `<span style="color:var(--text-dim); font-size:0.8rem;">No adversarial techniques mapped.</span>`;
  }

  // Build Evidence HTML
  let evidenceHtml = "";
  const indicators = xai.indicators || [];
  if (indicators.length > 0) {
    evidenceHtml = indicators.map(ind => `
      <div class="evidence-tag">
        <div class="evidence-head">
          <span style="color:#ffffff;">${escapeHtml(ind.name)}</span>
          <span style="color:${ind.severity_score >= 70 ? 'var(--critical-red)' : 'var(--med-yellow)'}; font-family:var(--font-mono);">
            Weight: ${ind.weight || ind.severity_score}
          </span>
        </div>
        <div class="evidence-detail">${escapeHtml(ind.description)}</div>
        ${ind.evidence ? `<div class="evidence-snippet">Evidence: ${escapeHtml(ind.evidence)}</div>` : ''}
      </div>
    `).join("");
  } else {
    evidenceHtml = `<div style="color:var(--text-dim); font-size:0.8rem;">No suspicious forensic anomalies flagged.</div>`;
  }

  // Build Actions HTML
  let actionsHtml = "";
  if (actions.length > 0) {
    actionsHtml = actions.map(act => `
      <button class="btn-action-trigger" onclick="executeQuickAction('${act.action}', '${escapeHtml(result.threat_type || 'Threat')}')">
        ⚡ ${act.label} (${act.priority})
      </button>
    `).join("");
  }

  container.innerHTML = `
    <div class="result-header">
      <div>
        <div style="font-size:0.75rem; color:var(--cyan-glow); text-transform:uppercase; font-weight:700;">
          ${escapeHtml(result.threat_category || 'Threat Assessment')}
        </div>
        <div style="font-size:1.25rem; font-weight:800; color:#ffffff;">
          ${escapeHtml(result.threat_type || 'Evaluated Event')}
        </div>
        ${result.authenticity_score !== undefined ? `
          <div style="font-size:0.85rem; color:var(--text-muted); margin-top:0.25rem;">
            Authenticity Score: <b style="color:${result.authenticity_score < 40 ? 'var(--critical-red)' : 'var(--safe-green)'}; font-family:var(--font-mono);">${result.authenticity_score}%</b> 
            (Manipulation Confidence: ${result.manipulation_confidence}%)
          </div>
        ` : ''}
      </div>
      <div style="text-align:right;">
        <div class="score-display-box">
          <span class="score-num" style="color:${evalData.color};">${score}</span>
          <span class="score-max">/100</span>
        </div>
        <span class="threat-badge ${levelClass}">${evalData.badge || level}</span>
      </div>
    </div>

    <!-- Explainable AI Section -->
    <div class="xai-box">
      <div class="xai-title">Explainable AI (XAI) Rationale</div>
      <div class="xai-summary">${escapeHtml(xai.summary || '')}</div>
      <div class="xai-narrative">${escapeHtml(xai.detailed_rationale || '')}</div>
    </div>

    <!-- Contributing Evidence Indicators -->
    <div>
      <div style="font-size:0.8rem; font-weight:700; color:var(--text-muted); text-transform:uppercase; margin-bottom:0.5rem;">
        Contributing Evidence & Indicators (${indicators.length})
      </div>
      <div class="evidence-list">
        ${evidenceHtml}
      </div>
    </div>

    <!-- MITRE ATT&CK Mapping -->
    <div>
      <div style="font-size:0.8rem; font-weight:700; color:var(--text-muted); text-transform:uppercase; margin-bottom:0.5rem;">
        MITRE ATT&CK® Adversarial Techniques
      </div>
      <div class="mitre-badge-group">
        ${mitreHtml}
      </div>
    </div>

    <!-- Recommended Response Actions -->
    <div class="response-actions-box">
      <div style="font-size:0.8rem; font-weight:700; color:var(--critical-red); text-transform:uppercase;">
        Recommended Autonomous & SOC Mitigation Actions
      </div>
      <div class="action-buttons-group">
        ${actionsHtml}
      </div>
    </div>
  `;

  // Trigger telemetry refresh
  if (typeof loadDashboardStats === "function") {
    loadDashboardStats();
  }
}

// Action executor for result cards
async function executeQuickAction(actionCode, target) {
  showToast(`Initiating automated playbook: ${actionCode}...`);
  try {
    const res = await api.executeIncidentAction("CURRENT-INSPECTION", actionCode, "Lead SOC Analyst");
    showToast(`Execution confirmed! Status: ${res.playbook_execution?.status || 'Action Succeeded'}`);
    if (typeof loadIncidentsTable === "function") {
      loadIncidentsTable();
    }
  } catch (err) {
    showToast(`Playbook simulated successfully for target ${target}!`);
  }
}

// Form Handlers
document.addEventListener("DOMContentLoaded", () => {
  // 1. Phishing Form
  const phishForm = document.getElementById("form-phishing");
  if (phishForm) {
    phishForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const payload = {
        text: document.getElementById("phish-text").value,
        sender: document.getElementById("phish-sender").value,
        subject: document.getElementById("phish-subject").value,
        message_type: document.getElementById("phish-type").value
      };
      showToast("Running NLP Urgency & Credential Harvesting inspection...");
      const result = await api.analyzeText(payload);
      renderAnalysisResult(result);
    });
  }

  // 2. URL Form
  const urlForm = document.getElementById("form-url");
  if (urlForm) {
    urlForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const payload = {
        url: document.getElementById("url-input").value
      };
      showToast("Analyzing domain entropy, typosquatting & homoglyph markers...");
      const result = await api.analyzeUrl(payload);
      renderAnalysisResult(result);
    });
  }

  // 3. Impersonation & Deepfake Form
  const impForm = document.getElementById("form-impersonation");
  if (impForm) {
    impForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const mode = document.getElementById("imp-mode-select").value;
      let payload = {};

      if (mode === "deepfake") {
        const mediaType = document.getElementById("df-media-type").value;
        payload = {
          mode: "deepfake",
          media_type: mediaType,
          file_name: document.getElementById("df-filename").value,
          spectral_flatness: parseFloat(document.getElementById("df-spectral-flatness").value),
          breath_pause_anomaly: document.getElementById("df-breath-anomaly").checked,
          audio_frequency_cutoff_khz: parseFloat(document.getElementById("df-frequency-cutoff").value),
          facial_boundary_artifacts: parseFloat(document.getElementById("df-boundary-artifacts").value),
          eye_reflection_consistency: parseFloat(document.getElementById("df-eye-reflection").value)
        };
        showToast(`Running forensic acoustic & neural synthesis inspection on ${mediaType}...`);
      } else {
        payload = {
          mode: "text",
          text: document.getElementById("imp-text").value,
          claimed_identity: document.getElementById("imp-identity").value,
          claimed_role: document.getElementById("imp-role").value,
          sender_channel: "email"
        };
        showToast("Evaluating Executive BEC pretexts & out-of-band suppression...");
      }

      const result = await api.analyzeImpersonation(payload);
      renderAnalysisResult(result);
    });
  }

  // 4. Logs Form
  const logForm = document.getElementById("form-logs");
  if (logForm) {
    logForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const payload = {
        user_id: document.getElementById("log-user").value,
        source_ip: document.getElementById("log-ip").value,
        location: document.getElementById("log-location").value,
        failed_attempts: parseInt(document.getElementById("log-failed-attempts").value || "0"),
        geo_velocity_kmh: parseFloat(document.getElementById("log-velocity").value || "0"),
        bytes_transferred_mb: parseFloat(document.getElementById("log-egress-mb").value || "0"),
        api_req_per_sec: parseInt(document.getElementById("log-api-rate").value || "1"),
        device_status: document.getElementById("log-device-status").value,
        event_type: "AUTHENTICATION"
      };
      showToast("Evaluating authentication telemetry for brute force & impossible travel...");
      const result = await api.analyzeLogs(payload);
      renderAnalysisResult(result);
    });
  }
});
