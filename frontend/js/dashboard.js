/**
 * CYBERGUARD Dashboard Telemetry & Real-Time Visualization
 */

function initClock() {
  const clockEl = document.getElementById("soc-clock");
  if (!clockEl) return;
  function update() {
    const now = new Date();
    clockEl.textContent = now.toUTCString().replace("GMT", "UTC");
  }
  update();
  setInterval(update, 1000);
}

function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.innerHTML = `<span style="color:var(--cyan-glow); font-weight:700;">[CYBERGUARD]</span> ${message}`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(100%)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 4500);
}

async function loadDashboardStats() {
  try {
    const data = await api.getDashboardStats();
    if (!data) return;

    // 1. Update KPI Values
    const tel = data.telemetry || {};
    document.getElementById("kpi-total-events").textContent = (tel.total_events_analyzed || 0).toLocaleString();
    document.getElementById("kpi-threats-detected").textContent = (tel.threats_detected || 0).toLocaleString();
    document.getElementById("kpi-phishing").textContent = (tel.phishing_attempts || 0).toLocaleString();
    document.getElementById("kpi-impersonation").textContent = (tel.impersonation_attempts || 0).toLocaleString();
    document.getElementById("kpi-deepfakes").textContent = (tel.deepfakes_detected || 0).toLocaleString();
    document.getElementById("kpi-ato").textContent = (tel.account_takeover_attempts || 0).toLocaleString();

    // 2. Update Risk Meter Progress
    const dist = data.risk_distribution || {};
    const totalDist = Object.values(dist).reduce((a, b) => a + b, 0) || 1;

    ['critical', 'high', 'medium', 'low', 'safe'].forEach(tier => {
      const count = dist[tier.toUpperCase()] || 0;
      const pct = Math.round((count / totalDist) * 100);
      const fillEl = document.getElementById(`meter-fill-${tier}`);
      const countEl = document.getElementById(`meter-count-${tier}`);
      if (fillEl) fillEl.style.width = `${pct}%`;
      if (countEl) countEl.textContent = `${count} (${pct}%)`;
    });

    // 3. Update Live Timeline
    const timelineEl = document.getElementById("timeline-feed");
    if (timelineEl && data.recent_incidents) {
      timelineEl.innerHTML = "";
      data.recent_incidents.forEach(inc => {
        const item = document.createElement("div");
        item.className = "timeline-item";
        const levelClass = (inc.risk_level || "medium").toLowerCase();
        
        item.innerHTML = `
          <div class="timeline-meta">
            <span class="timeline-time">${inc.timestamp}</span>
            <span class="threat-badge ${levelClass}">${inc.risk_level} • Score ${inc.risk_score}</span>
          </div>
          <div class="timeline-title">${escapeHtml(inc.title)}</div>
          <div class="timeline-desc">${escapeHtml(inc.explanation || '')}</div>
          <div style="font-size:0.75rem; color:var(--text-dim); margin-top:0.25rem;">
            Target: <code style="color:var(--cyan-glow);">${escapeHtml(inc.target)}</code> | 
            Status: <span style="color:#ffffff; font-weight:600;">${escapeHtml(inc.status)}</span>
          </div>
        `;
        timelineEl.appendChild(item);
      });
    }

  } catch (err) {
    console.warn("Could not fetch dashboard telemetry:", err);
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

document.addEventListener("DOMContentLoaded", () => {
  initClock();
  loadDashboardStats();
  setInterval(loadDashboardStats, 12000);
});
