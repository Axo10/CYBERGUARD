"""
CYBERGUARD Automated Verification Test Suite
Tests all REST API endpoints, forensic scoring, XAI narrative, and playbook executions.
"""
import urllib.request
import json
import sys

BASE_URL = "http://127.0.0.1:5000"

def post_json(endpoint, payload):
    url = f"{BASE_URL}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))

def get_json(endpoint):
    url = f"{BASE_URL}{endpoint}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))

def get_html(endpoint="/"):
    url = f"{BASE_URL}{endpoint}"
    with urllib.request.urlopen(url) as resp:
        return resp.status, resp.read().decode("utf-8")

def run_tests():
    print("=" * 60)
    print("  RUNNING CYBERGUARD END-TO-END VERIFICATION SUITE")
    print("=" * 60)

    # 1. Health check
    status, res = get_json("/api/health")
    assert status == 200, f"Health check failed: {status}"
    assert res["status"] == "online"
    print("[PASS] 1. Core Health Check:", res["status"])

    # 2. Frontend HTML check
    status, html = get_html("/")
    assert status == 200
    assert "CYBERGUARD" in html
    assert "Threat Inspector Workbench" in html
    print("[PASS] 2. Frontend Dashboard HTML Delivery:", len(html), "bytes")

    # 3. Scenarios Catalog
    status, scenarios = get_json("/api/scenarios")
    assert status == 200
    assert len(scenarios) >= 6
    print(f"[PASS] 3. Preloaded Scenarios Catalog ({len(scenarios)} scenarios available)")

    # 4. Phishing Analyzer
    phish_payload = {
        "text": "CRITICAL ALERT: Your corporate password will expire in 2 hours. Click here to verify credentials: https://micros0ft-portal-auth.xyz/login",
        "sender": "Security Admin <admin@micros0ft-portal-auth.xyz>",
        "subject": "Immediate Action Required: Password Verification",
        "message_type": "email"
    }
    status, phish_res = post_json("/api/analyze/text", phish_payload)
    assert status == 200
    assert phish_res["risk_evaluation"]["level"] in ["HIGH", "CRITICAL"]
    assert "Explainable AI" in phish_res["explainable_ai"]["summary"] or phish_res["risk_evaluation"]["is_threat"]
    print(f"[PASS] 4. Phishing Engine: Level={phish_res['risk_evaluation']['level']}, Score={phish_res['risk_evaluation']['score']}")
    print(f"       XAI Rationale: {phish_res['explainable_ai']['summary']}")

    # 5. Malicious URL Analyzer
    url_payload = {"url": "https://paypa1-security-alert.xyz/verify/login"}
    status, url_res = post_json("/api/analyze/url", url_payload)
    assert status == 200
    assert url_res["risk_evaluation"]["level"] in ["HIGH", "CRITICAL"]
    assert url_res["brand_impersonated"] == "PAYPAL"
    print(f"[PASS] 5. URL Radar: Brand Impersonated={url_res['brand_impersonated']}, Score={url_res['risk_evaluation']['score']}")

    # 6. Impersonation & BEC Analyzer
    bec_payload = {
        "mode": "text",
        "text": "I am in a confidential board meeting and cannot take calls. Wire $85,000 immediately to vendor escrow.",
        "claimed_identity": "CEO",
        "claimed_role": "CEO"
    }
    status, bec_res = post_json("/api/analyze/impersonation", bec_payload)
    assert status == 200
    assert bec_res["risk_evaluation"]["level"] in ["HIGH", "CRITICAL"]
    print(f"[PASS] 6. Executive Impersonation: Level={bec_res['risk_evaluation']['level']}, Threat={bec_res['threat_type']}")

    # 7. Deepfake Forensic Audio Analyzer
    df_payload = {
        "mode": "deepfake",
        "media_type": "audio",
        "file_name": "executive_voice_call.wav",
        "spectral_flatness": 0.91,
        "breath_pause_anomaly": True,
        "audio_frequency_cutoff_khz": 7.2
    }
    status, df_res = post_json("/api/analyze/impersonation", df_payload)
    assert status == 200
    assert df_res["risk_evaluation"]["level"] in ["HIGH", "CRITICAL"]
    assert df_res["authenticity_score"] < 30.0
    print(f"[PASS] 7. Deepfake Audio Lab: Authenticity={df_res['authenticity_score']}%, Manipulation Conf={df_res['manipulation_confidence']}%")

    # 8. Log Anomaly & Account Takeover Analyzer
    log_payload = {
        "user_id": "r.chen@enterprise.internal",
        "source_ip": "185.220.101.42",
        "location": "London, UK (Previous: Tokyo, Japan 15 min ago)",
        "failed_attempts": 18,
        "geo_velocity_kmh": 3600.0,
        "bytes_transferred_mb": 14.2,
        "device_status": "Untrusted Node"
    }
    status, log_res = post_json("/api/analyze/logs", log_payload)
    assert status == 200
    assert log_res["risk_evaluation"]["level"] in ["HIGH", "CRITICAL"]
    print(f"[PASS] 8. Log Anomaly Engine: Level={log_res['risk_evaluation']['level']}, Threat={log_res['threat_type']}")

    # 9. Incidents & Playbook Action Execution
    status, incidents = get_json("/api/incidents")
    assert status == 200
    assert len(incidents) > 0
    first_inc_id = incidents[0]["id"]
    
    # Execute mitigation
    status, play_res = post_json(f"/api/incidents/{first_inc_id}/action", {
        "action": "QUARANTINE_EMAIL",
        "analyst": "Automated Test Runner"
    })
    assert status == 200
    assert play_res["success"] is True
    assert "Mitigated" in play_res["incident"]["status"]
    print(f"[PASS] 9. Automated Mitigation Playbook on {first_inc_id}: Status={play_res['incident']['status']}")

    # 10. Dashboard Stats
    status, stats = get_json("/api/dashboard/stats")
    assert status == 200
    assert stats["telemetry"]["threats_detected"] > 0
    print(f"[PASS] 10. SOC Dashboard Telemetry: Total Analyzed={stats['telemetry']['total_events_analyzed']}, Threats={stats['telemetry']['threats_detected']}")

    print("=" * 60)
    print("  ALL 10 VERIFICATION TESTS PASSED SUCCESSFULLY! (100% PASS RATE)")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
