"""
MITRE ATT&CK Framework Mapping Engine for CYBERGUARD
Maps detected indicators and threat categories to MITRE ATT&CK Enterprise techniques.
"""
from typing import Dict, Any, List

class MITREMapper:
    TECHNIQUES = {
        "PHISHING_EMAIL": {
            "id": "T1566.001",
            "name": "Phishing: Spearphishing Attachment",
            "tactic": "Initial Access",
            "url": "https://attack.mitre.org/techniques/T1566/001/"
        },
        "PHISHING_LINK": {
            "id": "T1566.002",
            "name": "Phishing: Spearphishing Link",
            "tactic": "Initial Access",
            "url": "https://attack.mitre.org/techniques/T1566/002/"
        },
        "PHISHING_SMS": {
            "id": "T1566.003",
            "name": "Phishing: Spearphishing via Service (Smishing)",
            "tactic": "Initial Access",
            "url": "https://attack.mitre.org/techniques/T1566/003/"
        },
        "QUISHING": {
            "id": "T1566.004",
            "name": "Phishing: QR Code-based Phishing (Quishing)",
            "tactic": "Initial Access",
            "url": "https://attack.mitre.org/techniques/T1566/"
        },
        "IMPERSONATION_VIP": {
            "id": "T1656",
            "name": "Impersonation: Executive & Authority Masquerading",
            "tactic": "Defense Evasion / Initial Access",
            "url": "https://attack.mitre.org/techniques/T1656/"
        },
        "DEEPFAKE_AUDIO": {
            "id": "T1656.001",
            "name": "Impersonation: Synthetic Audio & Voice Cloning",
            "tactic": "Defense Evasion",
            "url": "https://attack.mitre.org/techniques/T1656/"
        },
        "DEEPFAKE_VIDEO": {
            "id": "T1656.002",
            "name": "Impersonation: Synthetic Video & Facial Manipulation",
            "tactic": "Defense Evasion",
            "url": "https://attack.mitre.org/techniques/T1656/"
        },
        "TYPOSQUATTING": {
            "id": "T1583.001",
            "name": "Acquire Infrastructure: Domains & Typosquatting",
            "tactic": "Resource Development",
            "url": "https://attack.mitre.org/techniques/T1583/001/"
        },
        "HOMOGLYPH_ATTACK": {
            "id": "T1583.008",
            "name": "Acquire Infrastructure: Punycode / IDN Homoglyphs",
            "tactic": "Resource Development",
            "url": "https://attack.mitre.org/techniques/T1583/"
        },
        "PASSWORD_SPRAYING": {
            "id": "T1110.003",
            "name": "Brute Force: Password Spraying",
            "tactic": "Credential Access",
            "url": "https://attack.mitre.org/techniques/T1110/003/"
        },
        "CREDENTIAL_STUFFING": {
            "id": "T1110.004",
            "name": "Brute Force: Credential Stuffing",
            "tactic": "Credential Access",
            "url": "https://attack.mitre.org/techniques/T1110/004/"
        },
        "ACCOUNT_TAKEOVER": {
            "id": "T1078.004",
            "name": "Valid Accounts: Cloud and Enterprise Accounts",
            "tactic": "Defense Evasion / Persistence",
            "url": "https://attack.mitre.org/techniques/T1078/004/"
        },
        "DATA_EXFILTRATION": {
            "id": "T1048",
            "name": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration",
            "url": "https://attack.mitre.org/techniques/T1048/"
        },
        "API_ABUSE": {
            "id": "T1190",
            "name": "Exploit Public-Facing Application & API Abuse",
            "tactic": "Initial Access",
            "url": "https://attack.mitre.org/techniques/T1190/"
        }
    }

    @classmethod
    def get_mappings(cls, tags: List[str]) -> List[Dict[str, Any]]:
        """
        Returns full MITRE details for the provided list of threat tag keys.
        """
        results = []
        for tag in tags:
            upper_tag = tag.upper().strip()
            if upper_tag in cls.TECHNIQUES:
                results.append(cls.TECHNIQUES[upper_tag])
            else:
                # Default generic fallback mapping
                results.append({
                    "id": "T1204",
                    "name": f"User Execution / Malicious Activity ({tag})",
                    "tactic": "Execution",
                    "url": "https://attack.mitre.org/techniques/T1204/"
                })
        return results
