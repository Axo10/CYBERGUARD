/**
 * CYBERGUARD API Service Layer
 * Interacts with Flask backend endpoints
 */

const API_BASE = window.location.origin.includes("5000") 
  ? window.location.origin 
  : "http://127.0.0.1:5000";

const api = {
  async getHealth() {
    const res = await fetch(`${API_BASE}/api/health`);
    return res.json();
  },

  async getDashboardStats() {
    const res = await fetch(`${API_BASE}/api/dashboard/stats`);
    return res.json();
  },

  async getScenarios() {
    const res = await fetch(`${API_BASE}/api/scenarios`);
    return res.json();
  },

  async getIncidents(filters = {}) {
    const query = new URLSearchParams(filters).toString();
    const res = await fetch(`${API_BASE}/api/incidents?${query}`);
    return res.json();
  },

  async analyzeText(payload) {
    const res = await fetch(`${API_BASE}/api/analyze/text`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  async analyzeUrl(payload) {
    const res = await fetch(`${API_BASE}/api/analyze/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  async analyzeImpersonation(payload) {
    const res = await fetch(`${API_BASE}/api/analyze/impersonation`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  async analyzeLogs(payload) {
    const res = await fetch(`${API_BASE}/api/analyze/logs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  async executeIncidentAction(incidentId, actionCode, analyst = "SecOps Lead") {
    const res = await fetch(`${API_BASE}/api/incidents/${incidentId}/action`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: actionCode, analyst: analyst })
    });
    return res.json();
  },

  async resetIncidents() {
    const res = await fetch(`${API_BASE}/api/incidents/reset`, {
      method: "POST"
    });
    return res.json();
  }
};
