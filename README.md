# CYBERGUARD: AI-Powered Cyber Threat, Phishing & Digital Impersonation Detection and Response System

**Domain**: Cybersecurity + Artificial Intelligence  
**Tech Stack**: Python (Flask REST API), Vanilla HTML5, High-Tech Cyber CSS3, Modular JavaScript  
**Architecture**: Fully decoupled `backend/` and `frontend/` folders

---

## 🌟 Executive Summary

**CYBERGUARD** is an intelligent, multi-layered cyber-defence platform engineered to analyze digital telemetry across multiple enterprise threat vectors in near real-time. Moving beyond legacy binary alerts, CYBERGUARD delivers **calibrated risk scoring (Safe -> Low -> Medium -> High -> Critical)**, transparent **Explainable AI (XAI)** reasoning, formal **MITRE ATT&CK** matrix mapping, and **automated 1-click incident response playbooks**.

---

## 🎯 Threat Scenarios Addressed

| Scenario # | Category | Threat Vector | Key Indicators & AI Forensic Logic | MITRE Technique |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **Phishing & Social Engineering** | M365 Credential Harvester (Email/SMS/Quishing) | NLP urgency extraction, credential solicitations, sender domain mismatches, QR authentication bypass traps | `T1566.001`, `T1566.002`, `T1566.004` |
| **2** | **Malicious Look-alike URLs** | Typosquatting & Deceptive Domains | Levenshtein distance matching against banking/cloud brands (`paypa1-security.xyz`), Punycode IDN homoglyphs (`xn--`), Shannon entropy | `T1583.001`, `T1583.008` |
| **3** | **Digital Impersonation** | Executive BEC / CEO Fraud | C-Suite authority pretexts, high-value wire transfers, out-of-band communication suppression ("in a closed meeting, do not call") | `T1656` |
| **4** | **Synthetic Media / Deepfake** | AI Voice Clone & Audio Forensics | Neural vocoder spectral flatness, biological breath cadence absence, steep high-frequency acoustic cutoffs | `T1656.001` |
| **5** | **Synthetic Media / Deepfake** | Facial & Video Deepfakes | Pixel gradient boundary warping along jawline/hairline, corneal reflection & lighting vector discrepancies | `T1656.002` |
| **6** | **Technical Cyber Threat** | Password Spraying & Impossible Travel | >15 failed logins followed by geographic velocity anomaly (>3,000 km/h between sequential logins), untrusted Tor/Linux nodes | `T1110.003`, `T1078.004` |
| **7** | **Data Exfiltration & API Abuse** | Egress Spikes & Rate Anomaly | Sudden off-hours multi-gigabyte egress to unknown IPs, anomalous API request bursts (>150 req/sec) | `T1048`, `T1190` |
| **8** | **Benign Baseline** | Authorized Internal Notifications | Routine IT maintenance notices with zero urgency or external redirection, scoring clean (Safe 0–19) | Baseline |

---

## 🏗️ System Architecture

```
cyberguard/
├── backend/
│   ├── app.py                      # Flask REST API server, CORS, state management
│   ├── run.py                      # Server runner script
│   ├── requirements.txt            # Python dependencies (Flask, flask-cors)
│   ├── engine/
│   │   ├── risk_scorer.py          # Calibrated 0–100 risk scoring & tier categorization
│   │   ├── explainable_ai.py       # XAI plain-English narrative & feature attribution generator
│   │   └── mitre_mapper.py         # Standard MITRE ATT&CK technique mapping
│   ├── analyzers/
│   │   ├── phishing_analyzer.py    # Email, SMS & Quishing NLP urgency & credential traps
│   │   ├── url_analyzer.py         # Levenshtein distance, IDN homoglyphs & entropy
│   │   ├── impersonation_deepfake.py # Executive BEC, voice-cloning & image deepfakes
│   │   └── log_anomaly_analyzer.py # Brute-force, impossible travel & egress spikes
│   ├── playbooks/
│   │   └── response_engine.py      # Automated mitigation playbook executor
│   └── data/
│       ├── demo_datasets.py        # Preloaded attack scenarios & benchmark incidents
│       └── incidents_db.json       # Incident state persistence
│
├── frontend/
│   ├── index.html                  # Cyber Defense Command Center HUD
│   ├── css/
│   │   └── style.css               # Futuristic dark mode styling, neon accents & responsive grids
│   └── js/
│       ├── api.js                  # Client service connecting to Flask backend
│       ├── dashboard.js            # KPI metrics, risk meters & live attack feed
│       ├── analyzers.js            # Multi-source threat analyzer workbench & XAI renderer
│       └── incidents.js            # Incident ledger, triage filters & playbook modal
│
├── start.bat                       # 1-Click Windows Batch launcher
├── start.ps1                       # 1-Click PowerShell launcher
└── README.md                       # Comprehensive documentation
```

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.11+ (Installed automatically via Windows Package Manager)
- Google Chrome, Edge, or any modern web browser

### 1. Launching via Script (Recommended)
Double click `start.bat` or run:
```powershell
.\start.ps1
```
This starts the Flask backend server on `http://127.0.0.1:5000` and automatically launches the Command Dashboard in your browser.

### 2. Manual Startup
```powershell
# In terminal 1: Start backend
cd C:\Users\Aryan Jena\.gemini\antigravity\scratch\cyberguard\backend
C:\Users\Aryan Jena\AppData\Local\Programs\Python\Python311\python.exe run.py

# In browser: Open dashboard
http://127.0.0.1:5000
```

---

## 🔬 How to Test the Prototype

### 1. Using 1-Click Preset Scenarios (Fastest Evaluation)
1. In the top navigation, click **"Demo Scenarios (1-Click Test)"**.
2. Select any of the preloaded scenarios:
   - **Scenario 1**: Microsoft 365 Credential Phishing
   - **Scenario 2**: Executive Impersonation / CEO Wire Fraud (BEC)
   - **Scenario 3**: Synthetic Voice-Clone / Deepfake Audio Call
   - **Scenario 4**: Password Spraying & Impossible Travel Anomaly
   - **Scenario 5**: Malicious Look-Alike Typosquatting Domain
   - **Scenario 6**: Clean Baseline (Authorized IT Notification)
3. Click **"Load & Test Scenario"**. The system instantly shifts to the **Threat Inspector Workbench**, extracts forensic signals, and displays the **Explainable AI (XAI)** card.

### 2. Testing Custom Threat Inputs
Navigate to **"Threat Inspector Workbench"** and test custom payloads across any of the 4 subtabs:
- **Phishing & Quishing**: Test emails or text messages containing urgency keywords and external links.
- **URL & Typosquatting**: Test look-alike domains like `https://paypa1-security.com/login` or bare IP hosts like `http://192.168.1.100/verify`.
- **Impersonation & Deepfake**: Switch between **Text Pretext** (CEO/CFO wire demands) or **Deepfake Forensic Lab** (adjust acoustic flatness, breathing cadence, or facial warping).
- **Technical Logs & ATO**: Simulate failed logins, impossible travel velocities (>1,000 km/h), and large egress payloads.

### 3. Executing Incident Containment Playbooks
1. Click **"Incident Triage & Playbooks"** in the top navigation.
2. Review active incidents with their status (`Open`, `In Progress`, `Mitigated`).
3. Click **"⚡ Mitigate"** on any open incident.
4. Select the appropriate automated playbook:
   - *Quarantine Message in Gateway*
   - *Block Destination URL & Sinkhole DNS*
   - *Revoke User JWT Sessions & Enforce Step-up MFA*
   - *Shun Attacker IP on Edge WAF / Firewall*
   - *Freeze ERP Financial Disbursement & Wire Batch*
   - *Biometric Step-Up Deepfake Challenge*
5. Click **"Execute Playbook"** — the incident immediately transitions to **Mitigated** with cryptographic audit timestamps.

---

## 📡 REST API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/health` | `GET` | Core health check & status indicator |
| `/api/dashboard/stats` | `GET` | Live telemetry, KPI counts & risk tier distributions |
| `/api/scenarios` | `GET` | Catalog of preloaded attack scenarios |
| `/api/analyze/text` | `POST` | Phishing, Smishing & Quishing NLP inspection |
| `/api/analyze/url` | `POST` | Typosquatting, Levenshtein & Shannon entropy analysis |
| `/api/analyze/impersonation` | `POST` | Executive BEC & Deepfake forensic media evaluation |
| `/api/analyze/logs` | `POST` | Authentication logs, brute-force & impossible travel |
| `/api/incidents` | `GET` | Filterable incident ledger |
| `/api/incidents/<id>/action` | `POST` | Execute automated mitigation playbook |
| `/api/incidents/reset` | `POST` | Reset incidents to default demo baseline |
