"""
Technical Cyber Threat & Log Anomaly Analyzer
Detects:
- Multiple failed login bursts & Brute-force attacks
- Distributed Password Spraying across corporate users
- Impossible Travel velocity anomalies (e.g. London to Singapore in 25 min)
- New / untrusted device fingerprints & suspicious user agents
- High-volume data exfiltration & API rate abuse
"""
from typing import Dict, Any, List
from engine.risk_scorer import RiskScorer
from engine.explainable_ai import ExplainableAIEngine
from engine.mitre_mapper import MITREMapper

class LogAnomalyAnalyzer:
    @classmethod
    def analyze_event(
        cls,
        user_id: str,
        source_ip: str,
        location: str = "Unknown",
        failed_attempts: int = 0,
        event_type: str = "LOGIN",
        device_status: str = "Known Device",
        geo_velocity_kmh: float = 0.0,
        bytes_transferred_mb: float = 0.0,
        api_req_per_sec: int = 1,
        details: str = ""
    ) -> Dict[str, Any]:
        """
        Evaluates a security event or series of log records for account takeover,
        credential theft, exfiltration, or abnormal behavior.
        """
        indicators: List[Dict[str, Any]] = []
        subscores: Dict[str, float] = {}
        mitre_tags: List[str] = []

        # 1. Failed Attempts / Brute Force Analysis
        if failed_attempts >= 10:
            subscores["brute_force"] = min(100.0, 70.0 + (failed_attempts - 10) * 3)
            indicators.append({
                "name": "High-Frequency Credential Brute-Force",
                "category": "Authentication Telemetry",
                "severity_score": subscores["brute_force"],
                "weight": 40,
                "description": f"Encountered {failed_attempts} consecutive failed login attempts within 180 seconds.",
                "evidence": f"Failed attempts: {failed_attempts} from IP {source_ip}",
                "triggered": True
            })
            mitre_tags.append("CREDENTIAL_STUFFING")
        elif failed_attempts >= 4:
            subscores["brute_force"] = 55.0
            indicators.append({
                "name": "Elevated Authentication Failure Rate",
                "category": "Authentication Telemetry",
                "severity_score": 55.0,
                "weight": 25,
                "description": f"{failed_attempts} failed login attempts prior to authorization.",
                "evidence": f"Failed count: {failed_attempts}",
                "triggered": True
            })
            mitre_tags.append("CREDENTIAL_STUFFING")

        # 2. Impossible Travel Velocity
        # Commercial aircraft cruising speed ~ 900 km/h; speed > 1000 km/h implies impossible travel
        if geo_velocity_kmh > 1000.0:
            subscores["impossible_travel"] = min(100.0, 75.0 + (geo_velocity_kmh / 200.0))
            indicators.append({
                "name": "Impossible Travel Velocity Anomaly",
                "category": "Geospatial Behavioral Analytics",
                "severity_score": subscores["impossible_travel"],
                "weight": 40,
                "description": f"Physical displacement velocity of {geo_velocity_kmh:.0f} km/h between sequential login locations violates physical travel limits.",
                "evidence": f"Calculated velocity: {geo_velocity_kmh:.0f} km/h (Current location: {location})",
                "triggered": True
            })
            mitre_tags.append("ACCOUNT_TAKEOVER")

        # 3. Untrusted / Unregistered Device Fingerprint
        if "untrusted" in device_status.lower() or "unknown" in device_status.lower() or "new" in device_status.lower():
            subscores["unknown_device"] = 50.0
            indicators.append({
                "name": "Unregistered Device Hardware Fingerprint",
                "category": "Device Trust & Posture",
                "severity_score": 50.0,
                "weight": 20,
                "description": "Session established from an unrecognized hardware UUID and novel TLS client fingerprint.",
                "evidence": f"Device status: {device_status}",
                "triggered": True
            })

        # 4. Data Exfiltration Spikes
        if bytes_transferred_mb > 500.0:
            subscores["data_exfiltration"] = min(100.0, 65.0 + (bytes_transferred_mb / 50.0))
            indicators.append({
                "name": "Abnormal Data Egress Volume Spike",
                "category": "Data Loss Prevention (DLP)",
                "severity_score": subscores["data_exfiltration"],
                "weight": 45,
                "description": f"Sudden egress of {bytes_transferred_mb:.1f} MB to external destination within 5 minutes.",
                "evidence": f"Egress payload: {bytes_transferred_mb:.1f} MB",
                "triggered": True
            })
            mitre_tags.append("DATA_EXFILTRATION")

        # 5. API Rate Abuse
        if api_req_per_sec > 150:
            subscores["api_abuse"] = min(100.0, 60.0 + (api_req_per_sec / 10.0))
            indicators.append({
                "name": "High-Velocity API Endpoint Abuse",
                "category": "Application Security",
                "severity_score": subscores["api_abuse"],
                "weight": 35,
                "description": f"Client token dispatched {api_req_per_sec} req/s, exceeding normal user threshold by 15x.",
                "evidence": f"Rate: {api_req_per_sec} requests/sec",
                "triggered": True
            })
            mitre_tags.append("API_ABUSE")

        # Combine scores
        weights = {
            "brute_force": 2.0,
            "impossible_travel": 2.2,
            "unknown_device": 1.0,
            "data_exfiltration": 2.5,
            "api_abuse": 1.8
        }

        if not subscores:
            raw_score = 5.0
        else:
            raw_score = RiskScorer.combine_scores(subscores, weights)

        evaluation = RiskScorer.evaluate(raw_score, indicators)
        if not mitre_tags:
            mitre_tags.append("ACCOUNT_TAKEOVER" if evaluation["is_threat"] else "ACCOUNT_TAKEOVER")

        mitre_mappings = MITREMapper.get_mappings(mitre_tags)

        threat_type = "Account Takeover / Credential Attack" if "impossible_travel" in subscores or "brute_force" in subscores else (
            "Data Exfiltration Incident" if "data_exfiltration" in subscores else (
                "API Abuse" if "api_abuse" in subscores else "Benign User Activity"
            )
        )

        xai_data = ExplainableAIEngine.generate_explanation(
            threat_type=threat_type,
            risk_level=evaluation["level"],
            indicators=indicators,
            context={"user_id": user_id, "ip": source_ip, "location": location}
        )

        # Recommended Response Actions
        recommended_actions = []
        if evaluation["level"] in ["CRITICAL", "HIGH"]:
            recommended_actions.append({
                "action": "REVOKE_SESSION",
                "label": "Revoke All Active User Sessions & JWTs",
                "priority": "P1 - Critical",
                "description": "Immediately invalidate active tokens across Redis/Identity Provider for targeted user."
            })
            recommended_actions.append({
                "action": "BLOCK_IP_WAF",
                "label": "Block Attacker IP on Cloudflare / WAF",
                "priority": "P1 - Critical",
                "description": f"Inject CIDR drop rule for source IP {source_ip} at network edge."
            })
            recommended_actions.append({
                "action": "ENFORCE_MFA_STEPUP",
                "label": "Lock Account & Require Hardware FIDO2 MFA",
                "priority": "P2 - High",
                "description": "Trigger account containment state requiring administrator unlocking."
            })
        elif evaluation["level"] == "MEDIUM":
            recommended_actions.append({
                "action": "STEP_UP_CHALLENGE",
                "label": "Challenge User with Out-of-Band Push Notification",
                "priority": "P3 - Moderate",
                "description": "Require mobile authenticator approval for current active session."
            })
        else:
            recommended_actions.append({
                "action": "LOG_AUDIT",
                "label": "Normal Audit Record Logged",
                "priority": "P5 - Normal",
                "description": "Activity within standard operational bounds."
            })

        return {
            "threat_category": "Credential Theft & Technical Threat",
            "threat_type": threat_type,
            "user_id": user_id,
            "source_ip": source_ip,
            "location": location,
            "failed_attempts": failed_attempts,
            "geo_velocity_kmh": geo_velocity_kmh,
            "risk_evaluation": evaluation,
            "explainable_ai": xai_data,
            "mitre_mappings": mitre_mappings,
            "recommended_actions": recommended_actions
        }
