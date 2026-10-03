"""
AI-Powered Phishing & Social Engineering Threat Analyzer
Evaluates Emails, SMS, Quishing (QR Phishing), and Direct Messages for:
- Psychological urgency & coercive tone
- Credential harvesting triggers
- Sender/Domain masquerading & mismatch
- Deceptive links & QR authentication traps
"""
import re
from typing import Dict, Any, List
from engine.risk_scorer import RiskScorer
from engine.explainable_ai import ExplainableAIEngine
from engine.mitre_mapper import MITREMapper

class PhishingAnalyzer:
    URGENCY_KEYWORDS = [
        r"\b(urgent|urgently|immediate|immediately|critical|action required|final warning|act now)\b",
        r"\b(within \d+ (hours?|minutes?|days?)|suspended|terminated|deactivated|locked out)\b",
        r"\b(breach|unauthorized access|security alert|fraud detected|penalty|legal action)\b"
    ]

    CREDENTIAL_KEYWORDS = [
        r"\b(verify (your )?account|confirm (your )?identity|update (your )?password|reset credentials)\b",
        r"\b(login to proceed|enter (your )?pin|bank details|credit card|cvv|one-time password|otp)\b",
        r"\b(validate credentials|sign in immediately|click here to verify|fill this form)\b"
    ]

    QUISHING_KEYWORDS = [
        r"\b(scan (the |this )?qr code|qr-code authentication|camera to scan|qr login)\b"
    ]

    BRAND_TARGETS = [
        "paypal", "microsoft", "google", "apple", "amazon", "netflix", 
        "chase", "wells fargo", "bank of america", "irs", "hr department", "it support"
    ]

    @classmethod
    def analyze(cls, text: str, sender: str = "", subject: str = "", message_type: str = "email") -> Dict[str, Any]:
        """
        Analyzes content and returns risk evaluation, evidence indicators, XAI explanations,
        and recommended response actions.
        """
        indicators: List[Dict[str, Any]] = []
        subscores: Dict[str, float] = {}
        combined_text = f"{subject} {text}".lower()
        sender_lower = sender.lower()

        # 1. Urgency & Coercive Psychological Pressure Analysis
        urgency_matches = []
        for pat in cls.URGENCY_KEYWORDS:
            found = re.findall(pat, combined_text, re.IGNORECASE)
            if found:
                for match in found:
                    urgency_matches.append(match[0] if isinstance(match, tuple) else match)

        urgency_score = min(100.0, len(urgency_matches) * 32.0)
        subscores["urgency"] = urgency_score
        if urgency_matches:
            indicators.append({
                "name": "Coercive Urgency & Threat Signals",
                "category": "NLP Behavioral Analysis",
                "severity_score": urgency_score,
                "weight": 25,
                "description": "High-urgency language designed to induce panic and bypass logical scrutiny.",
                "evidence": ", ".join(list(set(urgency_matches))[:4]),
                "triggered": True
            })

        # 2. Credential Harvesting & Sensitive Prompt Analysis
        cred_matches = []
        for pat in cls.CREDENTIAL_KEYWORDS:
            found = re.findall(pat, combined_text, re.IGNORECASE)
            if found:
                for match in found:
                    cred_matches.append(match[0] if isinstance(match, tuple) else match)

        cred_score = min(100.0, len(cred_matches) * 38.0)
        subscores["credentials"] = cred_score
        if cred_matches:
            indicators.append({
                "name": "Credential Solicitation / Sensitive Trap",
                "category": "Heuristic Threat Detection",
                "severity_score": cred_score,
                "weight": 35,
                "description": "Explicit prompt demanding credentials, authentication codes, or financial information.",
                "evidence": ", ".join(list(set(cred_matches))[:4]),
                "triggered": True
            })

        # 3. QR Code Phishing (Quishing)
        quishing_matches = []
        for pat in cls.QUISHING_KEYWORDS:
            found = re.findall(pat, combined_text, re.IGNORECASE)
            if found:
                quishing_matches.append(str(found[0]))

        if quishing_matches:
            subscores["quishing"] = 85.0
            indicators.append({
                "name": "Quishing Vector Detected",
                "category": "Multi-Modal Phishing",
                "severity_score": 85.0,
                "weight": 30,
                "description": "Advises scanning an external QR code, which circumvents email gateway URL inspection.",
                "evidence": quishing_matches[0],
                "triggered": True
            })

        # 4. Brand Masquerading & Sender Spoofing
        brand_targeted = None
        for brand in cls.BRAND_TARGETS:
            if brand in combined_text or (sender and brand in sender_lower):
                brand_targeted = brand
                break

        sender_anomaly = False
        if brand_targeted and sender:
            # Check if domain matches the legitimate brand
            clean_brand = brand_targeted.replace(" ", "")
            if clean_brand in sender_lower and not any(legit in sender_lower for legit in [f"@{clean_brand}.com", f".{clean_brand}.com"]):
                sender_anomaly = True
                subscores["sender_spoof"] = 90.0
                indicators.append({
                    "name": "Display-to-Domain Mismatch Spoofing",
                    "category": "Identity Verification",
                    "severity_score": 90.0,
                    "weight": 40,
                    "description": f"Sender masquerades as '{brand_targeted.title()}' but sends from an unauthorized external domain.",
                    "evidence": sender,
                    "triggered": True
                })

        # 5. Suspicious External Links in message
        links_found = re.findall(r"https?://[^\s<>\"']+", combined_text)
        suspicious_links = []
        for link in links_found:
            if any(tld in link for tld in [".xyz", ".top", ".tk", ".ru", ".cc", ".link", ".click", "-security", "-login", "-verify"]):
                suspicious_links.append(link)

        if suspicious_links:
            subscores["malicious_links"] = 88.0
            indicators.append({
                "name": "Suspicious External Links Identified",
                "category": "Network Threat Intelligence",
                "severity_score": 88.0,
                "weight": 35,
                "description": "Message embeds hyperlinks pointing to low-reputation or spoofed top-level domains.",
                "evidence": suspicious_links[0],
                "triggered": True
            })

        # Calculate composite score
        weights = {
            "urgency": 1.2,
            "credentials": 1.8,
            "quishing": 1.4,
            "sender_spoof": 2.0,
            "malicious_links": 1.6
        }
        
        if not subscores:
            raw_score = 5.0
        else:
            raw_score = RiskScorer.combine_scores(subscores, weights)

        evaluation = RiskScorer.evaluate(raw_score, indicators)
        
        # Determine MITRE Tags
        mitre_tags = ["PHISHING_EMAIL" if message_type == "email" else "PHISHING_SMS"]
        if suspicious_links:
            mitre_tags.append("PHISHING_LINK")
        if quishing_matches:
            mitre_tags.append("QUISHING")
        if sender_anomaly:
            mitre_tags.append("IMPERSONATION_VIP")

        mitre_mappings = MITREMapper.get_mappings(mitre_tags)

        # Explainable AI synthesis
        threat_label = "Quishing Attack" if quishing_matches else ("Phishing Attempt" if evaluation["is_threat"] else "Clean Communication")
        xai_data = ExplainableAIEngine.generate_explanation(
            threat_type=threat_label,
            risk_level=evaluation["level"],
            indicators=indicators,
            context={"sender": sender, "subject": subject, "type": message_type}
        )

        # Recommended Response Actions
        recommended_actions = cls._recommend_actions(evaluation["level"], indicators, links_found)

        return {
            "threat_category": "Phishing & Social Engineering",
            "threat_type": threat_label,
            "message_type": message_type,
            "sender": sender,
            "subject": subject,
            "extracted_urls": links_found,
            "risk_evaluation": evaluation,
            "explainable_ai": xai_data,
            "mitre_mappings": mitre_mappings,
            "recommended_actions": recommended_actions
        }

    @classmethod
    def _recommend_actions(cls, risk_level: str, indicators: List[Dict[str, Any]], urls: List[str]) -> List[Dict[str, str]]:
        actions = []
        if risk_level in ["CRITICAL", "HIGH"]:
            actions.append({
                "action": "QUARANTINE_EMAIL",
                "label": "Quarantine Message in Gateway",
                "priority": "P1 - Immediate",
                "description": "Purge from recipient inbox and hold in secure quarantine vault."
            })
            if urls:
                actions.append({
                    "action": "BLOCK_URL_PROXY",
                    "label": "Block Destination URLs at Web Proxy",
                    "priority": "P1 - Immediate",
                    "description": "Broadcast DNS sinkhole and proxy edge block for all embedded URLs."
                })
            actions.append({
                "action": "RESET_CREDENTIALS",
                "label": "Prompt Targeted User Password Reset",
                "priority": "P2 - High",
                "description": "Enforce immediate credential reset and invalidate current user session tokens."
            })
            actions.append({
                "action": "NOTIFY_SOC",
                "label": "Escalate to Incident Response SOC",
                "priority": "P2 - High",
                "description": "Dispatch high-severity alert ticket to SOC analysts."
            })
        elif risk_level == "MEDIUM":
            actions.append({
                "action": "WARN_BANNER",
                "label": "Insert Cautionary Header Banner",
                "priority": "P3 - Moderate",
                "description": "Append 'External Suspicious Email' banner with clickable report button."
            })
            actions.append({
                "action": "DISABLE_LINKS",
                "label": "Neutralize Embedded Hyperlinks",
                "priority": "P3 - Moderate",
                "description": "Wrap external URLs with security rewrite proxy sandbox."
            })
        else:
            actions.append({
                "action": "LOG_ACTIVITY",
                "label": "Allow & Log Normal Audit Telemetry",
                "priority": "P5 - Informational",
                "description": "Deliver message normally; retain audit metadata in security data lake."
            })
        return actions
