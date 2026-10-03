"""
CYBERGUARD - AI-Powered Cyber Threat, Phishing & Digital Impersonation Detection & Response System
Flask Backend REST API Server
"""
import os
import json
import uuid
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

from engine.risk_scorer import RiskScorer
from engine.explainable_ai import ExplainableAIEngine
from engine.mitre_mapper import MITREMapper
from analyzers.phishing_analyzer import PhishingAnalyzer
from analyzers.url_analyzer import URLAnalyzer
from analyzers.impersonation_deepfake import ImpersonationDeepfakeAnalyzer
from analyzers.log_anomaly_analyzer import LogAnomalyAnalyzer
from playbooks.response_engine import ResponseEngine
from data.demo_datasets import PRESET_SCENARIOS, SIMULATED_INITIAL_INCIDENTS

# Determine paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))
DATA_FILE = os.path.join(BASE_DIR, "data", "incidents_db.json")

app = Flask(__name__, static_folder=FRONTEND_DIR)
CORS(app)  # Enable Cross-Origin Resource Sharing for modern browser frontend

# State management
def load_incidents():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    # Save default if not exists
    save_incidents(SIMULATED_INITIAL_INCIDENTS)
    return list(SIMULATED_INITIAL_INCIDENTS)

def save_incidents(incidents):
    try:
        os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(incidents, f, indent=2)
    except Exception as e:
        print(f"Error saving incidents: {e}")

# Global telemetry counters
TELEMETRY = {
    "total_events_analyzed": 14920,
    "threats_detected": 148,
    "phishing_attempts": 62,
    "impersonation_attempts": 38,
    "deepfakes_detected": 19,
    "account_takeover_attempts": 29
}

# --- Serve Frontend (if accessed on same port) ---
@app.route("/")
def serve_index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/<path:path>")
def serve_static(path):
    if os.path.exists(os.path.join(FRONTEND_DIR, path)):
        return send_from_directory(FRONTEND_DIR, path)
    return send_from_directory(FRONTEND_DIR, "index.html")

# --- API Endpoints ---

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "system": "CYBERGUARD AI Cyber Threat Core",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })

@app.route("/api/scenarios", methods=["GET"])
def get_scenarios():
    return jsonify(PRESET_SCENARIOS)

@app.route("/api/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    incidents = load_incidents()
    
    # Calculate risk distribution
    risk_dist = {"SAFE": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    category_counts = {}
    
    for inc in incidents:
        level = inc.get("risk_level", "MEDIUM")
        risk_dist[level] = risk_dist.get(level, 0) + 1
        cat = inc.get("category", "General")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    active_critical = sum(1 for inc in incidents if inc.get("risk_level") in ["HIGH", "CRITICAL"] and not inc.get("status", "").startswith("Mitigated"))

    return jsonify({
        "telemetry": TELEMETRY,
        "risk_distribution": risk_dist,
        "category_breakdown": category_counts,
        "active_critical_incidents": active_critical,
        "total_active_incidents": len(incidents),
        "recent_incidents": incidents[:6]
    })

@app.route("/api/analyze/text", methods=["POST"])
def analyze_text():
    TELEMETRY["total_events_analyzed"] += 1
    data = request.get_json() or {}
    text = data.get("text", "")
    sender = data.get("sender", "")
    subject = data.get("subject", "")
    msg_type = data.get("message_type", "email")

    result = PhishingAnalyzer.analyze(
        text=text,
        sender=sender,
        subject=subject,
        message_type=msg_type
    )

    if result["risk_evaluation"]["is_threat"]:
        TELEMETRY["threats_detected"] += 1
        TELEMETRY["phishing_attempts"] += 1
        
        # Automatically register into incident ledger
        _auto_create_incident(
            category="Phishing & Social Engineering",
            title=f"{result['threat_type']}: {subject or 'Suspicious Message'}"[:60],
            target=sender or "Internal Email Recipient",
            source=sender or "External Gateway",
            risk_level=result["risk_evaluation"]["level"],
            risk_score=result["risk_evaluation"]["score"],
            mitre_id=result["mitre_mappings"][0]["id"] if result["mitre_mappings"] else "T1566",
            explanation=result["explainable_ai"]["summary"],
            action=result["recommended_actions"][0]["action"] if result["recommended_actions"] else "QUARANTINE_EMAIL"
        )

    return jsonify(result)

@app.route("/api/analyze/url", methods=["POST"])
def analyze_url():
    TELEMETRY["total_events_analyzed"] += 1
    data = request.get_json() or {}
    url = data.get("url", "")

    result = URLAnalyzer.analyze(raw_url=url)

    if result["risk_evaluation"]["is_threat"]:
        TELEMETRY["threats_detected"] += 1
        
        _auto_create_incident(
            category="Malicious URL & Infrastructure Spoofing",
            title=f"Deceptive URL: {result['parsed_domain']}"[:60],
            target="Enterprise Perimeter",
            source=url[:80],
            risk_level=result["risk_evaluation"]["level"],
            risk_score=result["risk_evaluation"]["score"],
            mitre_id=result["mitre_mappings"][0]["id"] if result["mitre_mappings"] else "T1583.001",
            explanation=result["explainable_ai"]["summary"],
            action=result["recommended_actions"][0]["action"] if result["recommended_actions"] else "BLOCK_URL_PROXY"
        )

    return jsonify(result)

@app.route("/api/analyze/impersonation", methods=["POST"])
def analyze_impersonation():
    TELEMETRY["total_events_analyzed"] += 1
    data = request.get_json() or {}
    mode = data.get("mode", "text")  # 'text' or 'deepfake'

    if mode == "deepfake":
        result = ImpersonationDeepfakeAnalyzer.analyze_deepfake_media(
            media_type=data.get("media_type", "audio"),
            file_name=data.get("file_name", "voice_memo.wav"),
            spectral_flatness=float(data.get("spectral_flatness", 0.85)),
            breath_pause_anomaly=bool(data.get("breath_pause_anomaly", True)),
            facial_boundary_artifacts=float(data.get("facial_boundary_artifacts", 0.85)),
            eye_reflection_consistency=float(data.get("eye_reflection_consistency", 0.20)),
            audio_frequency_cutoff_khz=float(data.get("audio_frequency_cutoff_khz", 8.0))
        )
        if result["risk_evaluation"]["is_threat"]:
            TELEMETRY["threats_detected"] += 1
            TELEMETRY["deepfakes_detected"] += 1
            _auto_create_incident(
                category="Deepfake & Synthetic Media Detection",
                title=f"Synthetic Deepfake ({result['media_type'].upper()}): {result['file_name']}"[:60],
                target="Internal Communications Channel",
                source=result["file_name"],
                risk_level=result["risk_evaluation"]["level"],
                risk_score=result["risk_evaluation"]["score"],
                mitre_id=result["mitre_mappings"][0]["id"] if result["mitre_mappings"] else "T1656",
                explanation=result["explainable_ai"]["summary"],
                action=result["recommended_actions"][0]["action"] if result["recommended_actions"] else "CHALLENGE_VOICE_MFA"
            )
    else:
        result = ImpersonationDeepfakeAnalyzer.analyze_impersonation(
            text=data.get("text", ""),
            claimed_identity=data.get("claimed_identity", ""),
            sender_channel=data.get("sender_channel", "email"),
            claimed_role=data.get("claimed_role", "CEO")
        )
        if result["risk_evaluation"]["is_threat"]:
            TELEMETRY["threats_detected"] += 1
            TELEMETRY["impersonation_attempts"] += 1
            _auto_create_incident(
                category="Digital Impersonation & Identity Fraud",
                title=f"Executive Spoofing: {result['claimed_identity']} ({result['claimed_role']})"[:60],
                target="Executive Communications",
                source=data.get("sender", "External Sender"),
                risk_level=result["risk_evaluation"]["level"],
                risk_score=result["risk_evaluation"]["score"],
                mitre_id=result["mitre_mappings"][0]["id"] if result["mitre_mappings"] else "T1656",
                explanation=result["explainable_ai"]["summary"],
                action=result["recommended_actions"][0]["action"] if result["recommended_actions"] else "HALT_FINANCIAL_RELEASE"
            )

    return jsonify(result)

@app.route("/api/analyze/logs", methods=["POST"])
def analyze_logs():
    TELEMETRY["total_events_analyzed"] += 1
    data = request.get_json() or {}
    
    result = LogAnomalyAnalyzer.analyze_event(
        user_id=data.get("user_id", "admin@enterprise.internal"),
        source_ip=data.get("source_ip", "192.168.1.1"),
        location=data.get("location", "Unknown"),
        failed_attempts=int(data.get("failed_attempts", 0)),
        event_type=data.get("event_type", "LOGIN"),
        device_status=data.get("device_status", "Known Device"),
        geo_velocity_kmh=float(data.get("geo_velocity_kmh", 0.0)),
        bytes_transferred_mb=float(data.get("bytes_transferred_mb", 0.0)),
        api_req_per_sec=int(data.get("api_req_per_sec", 1)),
        details=data.get("details", "")
    )

    if result["risk_evaluation"]["is_threat"]:
        TELEMETRY["threats_detected"] += 1
        TELEMETRY["account_takeover_attempts"] += 1
        _auto_create_incident(
            category="Credential Theft & Technical Threat",
            title=f"{result['threat_type']}: {result['user_id']}"[:60],
            target=result["user_id"],
            source=f"{result['source_ip']} ({result['location']})",
            risk_level=result["risk_evaluation"]["level"],
            risk_score=result["risk_evaluation"]["score"],
            mitre_id=result["mitre_mappings"][0]["id"] if result["mitre_mappings"] else "T1078",
            explanation=result["explainable_ai"]["summary"],
            action=result["recommended_actions"][0]["action"] if result["recommended_actions"] else "REVOKE_SESSION"
        )

    return jsonify(result)

@app.route("/api/incidents", methods=["GET"])
def get_incidents():
    incidents = load_incidents()
    status_filter = request.args.get("status")
    category_filter = request.args.get("category")
    level_filter = request.args.get("level")

    filtered = incidents
    if status_filter:
        filtered = [i for i in filtered if status_filter.lower() in i.get("status", "").lower()]
    if category_filter:
        filtered = [i for i in filtered if category_filter.lower() in i.get("category", "").lower()]
    if level_filter:
        filtered = [i for i in filtered if i.get("risk_level", "").upper() == level_filter.upper()]

    return jsonify(filtered)

@app.route("/api/incidents/<incident_id>/action", methods=["POST"])
def execute_incident_action(incident_id):
    data = request.get_json() or {}
    action_code = data.get("action", "QUARANTINE_EMAIL")
    user = data.get("analyst", "SOC Lead Analyst")

    incidents = load_incidents()
    target_inc = None
    for inc in incidents:
        if inc.get("id") == incident_id:
            target_inc = inc
            break

    if not target_inc:
        return jsonify({"error": f"Incident {incident_id} not found"}), 404

    # Execute playbook
    exec_result = ResponseEngine.execute_action(
        action_code=action_code,
        target=target_inc.get("target", "Target Asset"),
        initiated_by=user
    )

    # Update incident state
    target_inc["status"] = exec_result["status"]
    target_inc["mitigated_at"] = exec_result["executed_at"]
    target_inc["mitigation_details"] = exec_result

    save_incidents(incidents)

    return jsonify({
        "success": True,
        "incident": target_inc,
        "playbook_execution": exec_result
    })

@app.route("/api/incidents/reset", methods=["POST"])
def reset_incidents():
    save_incidents(SIMULATED_INITIAL_INCIDENTS)
    return jsonify({"success": True, "message": "Incident registry reset to default simulation set."})

def _auto_create_incident(category, title, target, source, risk_level, risk_score, mitre_id, explanation, action):
    incidents = load_incidents()
    new_inc = {
        "id": f"INC-{uuid.uuid4().hex[:6].upper()}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "category": category,
        "title": title,
        "target": target,
        "source": source,
        "risk_level": risk_level,
        "risk_score": float(risk_score),
        "mitre_id": mitre_id,
        "status": "Open",
        "explanation": explanation,
        "recommended_action": action
    }
    incidents.insert(0, new_inc)
    # Keep ledger manageable
    save_incidents(incidents[:40])

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting CYBERGUARD AI Defence Core on port {port}...")
    app.run(host="127.0.0.1", port=port, debug=True)
