"""
Simulated Cyber Datasets, Baseline Telemetry, and Preset Demonstration Scenarios
Used by CYBERGUARD for command dashboard telemetry and 1-click test evaluations.
"""

PRESET_SCENARIOS = [
    {
        "id": "scenario-phishing-m365",
        "title": "Scenario 1: Microsoft 365 Credential Phishing (Urgency & Spoofing)",
        "category": "Phishing & Social Engineering",
        "description": "Deceptive high-urgency message masquerading as IT Security demanding password verification within 24 hours.",
        "input_type": "phishing",
        "payload": {
            "text": "CRITICAL ALERT: Your Microsoft 365 enterprise password will expire within 24 hours. Failure to verify credentials immediately will result in complete account deactivation and loss of email access. Click here to confirm identity and update your password right now: https://micros0ft-portal-auth.xyz/verify-login",
            "sender": "Microsoft Security Alert <it-helpdesk@micros0ft-portal-auth.xyz>",
            "subject": "FINAL WARNING: Immediate Action Required - Password Expiry",
            "message_type": "email"
        }
    },
    {
        "id": "scenario-impersonation-ceo",
        "title": "Scenario 2: Executive Impersonation / CEO Wire Fraud (BEC)",
        "category": "Digital Impersonation & Identity Fraud",
        "description": "Targeted Business Email Compromise masquerading as the CEO demanding an urgent confidential wire transfer while suppressing out-of-band phone calls.",
        "input_type": "impersonation",
        "payload": {
            "text": "I am currently tied up in a strictly confidential executive board meeting and cannot take voice calls. We have an urgent confidential wire transfer of $84,500 that must be sent to vendor escrow before end of day. Process this right away and remit payment using updated routing details. Keep this strictly private until our acquisition announcement.",
            "claimed_identity": "Satya Nadella",
            "claimed_role": "CEO",
            "sender_channel": "email"
        }
    },
    {
        "id": "scenario-deepfake-audio",
        "title": "Scenario 3: Synthetic Voice-Clone / Deepfake Audio Call",
        "category": "Deepfake & Synthetic Media Detection",
        "description": "Forensic acoustic analysis of a synthetic phone recording impersonating the CFO with neural vocoder flatness and unnatural absence of breathing.",
        "input_type": "deepfake",
        "payload": {
            "media_type": "audio",
            "file_name": "cfo_urgent_wire_authorization_call.wav",
            "spectral_flatness": 0.89,
            "breath_pause_anomaly": True,
            "audio_frequency_cutoff_khz": 7.5,
            "facial_boundary_artifacts": 0.0,
            "eye_reflection_consistency": 1.0
        }
    },
    {
        "id": "scenario-log-ato",
        "title": "Scenario 4: Technical Threat: Password Spraying & Impossible Travel",
        "category": "Credential Theft & Technical Threat",
        "description": "Telemetry logs showing 19 consecutive failed logins followed by a successful login across 9,500 km within 15 minutes (Tokyo to London).",
        "input_type": "logs",
        "payload": {
            "user_id": "r.chen@enterprise.internal",
            "source_ip": "185.220.101.42",
            "location": "London, UK (Previous: Tokyo, Japan 15 min ago)",
            "failed_attempts": 19,
            "event_type": "AUTHENTICATION_ANOMALY",
            "device_status": "Untrusted / Unknown Linux Tor Node",
            "geo_velocity_kmh": 3840.0,
            "bytes_transferred_mb": 12.4,
            "api_req_per_sec": 42,
            "details": "Password spray pattern followed by geographic velocity violation"
        }
    },
    {
        "id": "scenario-url-typosquat",
        "title": "Scenario 5: Malicious Look-Alike Typosquatting Domain",
        "category": "Malicious URL & Infrastructure Spoofing",
        "description": "Deceptive financial login URL using brand typo, suspicious TLD, and high entropy to evade security filters.",
        "input_type": "url",
        "payload": {
            "url": "https://paypa1-security-verification.xyz/secure/login/auth-check"
        }
    },
    {
        "id": "scenario-benign-clean",
        "title": "Scenario 6: Clean Baseline: Authorized Internal IT Notification",
        "category": "Benign / Normal Baseline",
        "description": "Standard scheduled maintenance broadcast without urgency, credential solicitation, or external redirection.",
        "input_type": "phishing",
        "payload": {
            "text": "Hello Team, This is a reminder that scheduled datacenter maintenance will take place this Saturday between 02:00 AM and 04:00 AM EST. Internal wiki services will experience brief intermittent downtime. No action is required on your part.",
            "sender": "IT Infrastructure Team <sysadmin@enterprise.internal>",
            "subject": "Scheduled Weekend Maintenance Notice",
            "message_type": "email"
        }
    }
]

SIMULATED_INITIAL_INCIDENTS = [
    {
        "id": "INC-8942",
        "timestamp": "2026-10-03 09:12:44",
        "category": "Phishing & Social Engineering",
        "title": "Urgent Quishing Campaign - QR Code MFA Trap",
        "target": "Finance Dept (fin-all@enterprise.internal)",
        "source": "mailer@it-support-auth.link",
        "risk_level": "CRITICAL",
        "risk_score": 94.0,
        "mitre_id": "T1566.004",
        "status": "Open",
        "explanation": "Quishing Vector Detected: Advises scanning external QR code. High-urgency coercive prompt targeting finance credentials.",
        "recommended_action": "QUARANTINE_EMAIL"
    },
    {
        "id": "INC-8941",
        "timestamp": "2026-10-03 08:45:10",
        "category": "Digital Impersonation & Identity Fraud",
        "title": "Executive Impersonation (CEO Wire Transfer Pretext)",
        "target": "Accounts Payable (ap@enterprise.internal)",
        "source": "ceo.private.desk@external-mail.cc",
        "risk_level": "CRITICAL",
        "risk_score": 92.5,
        "mitre_id": "T1656",
        "status": "In Progress",
        "explanation": "Executive C-suite masquerading detected. Demands urgent wire transfer and explicitly suppresses out-of-band voice confirmation.",
        "recommended_action": "HALT_FINANCIAL_RELEASE"
    },
    {
        "id": "INC-8940",
        "timestamp": "2026-10-03 08:02:18",
        "category": "Credential Theft & Technical Threat",
        "title": "Impossible Travel & Password Spray Detected",
        "target": "User: d.smith@enterprise.internal",
        "source": "IP 194.26.29.112 (Bucharest, RO)",
        "risk_level": "HIGH",
        "risk_score": 88.0,
        "mitre_id": "T1110.003",
        "status": "Open",
        "explanation": "Physical displacement velocity of 4,200 km/h between sequential login locations. 14 consecutive failed attempts prior to token grant.",
        "recommended_action": "REVOKE_SESSION"
    },
    {
        "id": "INC-8939",
        "timestamp": "2026-10-03 07:29:55",
        "category": "Deepfake & Synthetic Media Detection",
        "title": "Synthetic Audio Voice-Clone on Support Line",
        "target": "Customer Operations Tier-2",
        "source": "SIP Trunk #8821",
        "risk_level": "HIGH",
        "risk_score": 86.0,
        "mitre_id": "T1656.001",
        "status": "Open",
        "explanation": "Acoustic flatness index 0.88 matches neural vocoder generation. Zero biological breath pauses detected across 45-second call.",
        "recommended_action": "CHALLENGE_VOICE_MFA"
    },
    {
        "id": "INC-8938",
        "timestamp": "2026-10-03 06:14:02",
        "category": "Malicious URL & Infrastructure Spoofing",
        "title": "Typosquatting Look-alike Domain Registered",
        "target": "Enterprise Perimeter DNS",
        "source": "https://chase-security-update.xyz/login",
        "risk_level": "HIGH",
        "risk_score": 84.5,
        "mitre_id": "T1583.001",
        "status": "Mitigated - Domain Sinkholed",
        "explanation": "Domain mimics authoritative brand 'CHASE' with suspicious .xyz TLD and credential harvesting path.",
        "recommended_action": "BLOCK_URL_PROXY"
    },
    {
        "id": "INC-8937",
        "timestamp": "2026-10-03 05:40:11",
        "category": "Credential Theft & Technical Threat",
        "title": "High-Volume Data Egress Spike to Cloud Bucket",
        "target": "Workstation: WS-DEV-092",
        "source": "10.0.4.88 -> 45.33.32.156",
        "risk_level": "CRITICAL",
        "risk_score": 91.0,
        "mitre_id": "T1048",
        "status": "Mitigated - IP Shunned at Edge",
        "explanation": "Sudden egress of 1,240 MB archive file over non-standard port during off-hours window.",
        "recommended_action": "BLOCK_IP_WAF"
    }
]
