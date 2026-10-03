"""
Malicious URL & Typosquatting Analyzer
Performs:
- Brand look-alike & Levenshtein distance analysis
- Punycode / IDN homoglyph detection (Cyrillic/Greek spoofed glyphs)
- Shannon entropy measurement (Algorithmic Domain Generation - DGA)
- Suspicious Top-Level Domain (TLD) assessment
- Deceptive path & credential harvesting pattern detection
"""
import math
import re
from urllib.parse import urlparse
from typing import Dict, Any, List
from engine.risk_scorer import RiskScorer
from engine.explainable_ai import ExplainableAIEngine
from engine.mitre_mapper import MITREMapper

class URLAnalyzer:
    POPULAR_BRANDS = [
        "paypal", "google", "microsoft", "apple", "amazon", "facebook",
        "instagram", "netflix", "chase", "bankofamerica", "wellsfargo",
        "binance", "coinbase", "github", "dropbox", "linkedin", "twitter"
    ]

    SUSPICIOUS_TLDS = [
        ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".work",
        ".click", ".link", ".live", ".icu", ".casa", ".monster", ".rest"
    ]

    DECEPTIVE_PATH_KEYWORDS = [
        "login", "signin", "verify", "secure", "account", "banking", "update",
        "confirm", "recover", "authenticate", "wallet", "checkpoint", "validation"
    ]

    @classmethod
    def _levenshtein_distance(cls, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return cls._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    @classmethod
    def _shannon_entropy(cls, string: str) -> float:
        """Calculates Shannon entropy to detect DGA (Domain Generation Algorithms)"""
        if not string:
            return 0.0
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        return -sum(p * math.log(p) / math.log(2.0) for p in prob)

    @classmethod
    def analyze(cls, raw_url: str) -> Dict[str, Any]:
        """
        Analyzes a URL for deceptive patterns, typosquatting, and malicious indicators.
        """
        url = raw_url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()
            path = parsed.path.lower()
        except Exception:
            netloc = url.lower()
            path = ""

        indicators: List[Dict[str, Any]] = []
        subscores: Dict[str, float] = {}

        # 1. IP Address as Host Check
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$"
        if re.match(ip_pattern, netloc):
            subscores["ip_host"] = 85.0
            indicators.append({
                "name": "Direct IP Address Host",
                "category": "Evasion Technique",
                "severity_score": 85.0,
                "weight": 35,
                "description": "URL bypasses regular DNS hostnames and uses a bare IP address to evade reputation systems.",
                "evidence": netloc,
                "triggered": True
            })

        # Clean domain for brand comparison
        domain_parts = netloc.split(".")
        main_domain = domain_parts[-2] if len(domain_parts) >= 2 else netloc
        # Extract sub-tokens from hyphens and dots (e.g. paypa1-security-alert -> ['paypa1', 'security', 'alert'])
        domain_tokens = re.split(r"[-._]", netloc)

        # 2. Typosquatting & Brand Look-alike Matching
        matched_brand = None
        min_dist = 999

        # Common visual substitution mappings: 1->l, 0->o, 5->s, 3->e, vv->w
        def normalize_visual_substitutions(tok: str) -> str:
            t = tok.replace("1", "l").replace("0", "o").replace("5", "s").replace("3", "e").replace("vv", "w")
            return t

        for brand in cls.POPULAR_BRANDS:
            # Check exact or normalized visual token match
            for token in domain_tokens:
                if len(token) >= 3:
                    norm_token = normalize_visual_substitutions(token)
                    dist = cls._levenshtein_distance(norm_token, brand)
                    if dist <= 1 or norm_token == brand:
                        matched_brand = brand
                        min_dist = dist
                        break
            if matched_brand:
                break

            # Also check main domain directly
            norm_main = normalize_visual_substitutions(main_domain)
            dist_main = cls._levenshtein_distance(norm_main, brand)
            if dist_main <= 2 and abs(len(norm_main) - len(brand)) <= 2:
                matched_brand = brand
                min_dist = dist_main
                break

        if matched_brand:
            subscores["typosquatting"] = 94.0
            indicators.append({
                "name": "Targeted Brand Typosquatting / Impersonation",
                "category": "Infrastructure Spoofing",
                "severity_score": 94.0,
                "weight": 40,
                "description": f"Domain mimics authoritative brand '{matched_brand.upper()}' with intentional character manipulation or spoofed subdomains.",
                "evidence": f"Found look-alike token mimicking '{matched_brand}'",
                "triggered": True
            })

        # 3. Punycode / IDN Homoglyph Detection
        if "xn--" in netloc:
            subscores["punycode"] = 95.0
            indicators.append({
                "name": "Punycode IDN Homoglyph Attack",
                "category": "Visual Deception",
                "severity_score": 95.0,
                "weight": 40,
                "description": "Domain utilizes internationalized Unicode characters (IDN) to masquerade as an ASCII brand name.",
                "evidence": netloc,
                "triggered": True
            })

        # 4. Suspicious Low-Reputation TLD
        found_suspicious_tld = None
        for tld in cls.SUSPICIOUS_TLDS:
            if netloc.endswith(tld):
                found_suspicious_tld = tld
                break

        if found_suspicious_tld:
            subscores["tld"] = 75.0
            indicators.append({
                "name": "High-Risk Top-Level Domain (TLD)",
                "category": "Domain Reputation",
                "severity_score": 75.0,
                "weight": 25,
                "description": f"Domain registered under '{found_suspicious_tld}', a TLD heavily correlated with bulletproof hosting and disposable malware campaigns.",
                "evidence": found_suspicious_tld,
                "triggered": True
            })

        # 5. Shannon Entropy (DGA Detection)
        entropy = cls._shannon_entropy(main_domain)
        if entropy > 3.75 and len(main_domain) > 10:
            subscores["entropy"] = 80.0
            indicators.append({
                "name": "High Shannon Entropy (Potential DGA)",
                "category": "Algorithmic Analysis",
                "severity_score": 80.0,
                "weight": 30,
                "description": f"Domain displays high randomness (Shannon entropy {entropy:.2f}), indicative of automated Domain Generation Algorithms.",
                "evidence": f"Entropy: {entropy:.2f}",
                "triggered": True
            })

        # 6. Deceptive Path Keywords
        path_matches = [kw for kw in cls.DECEPTIVE_PATH_KEYWORDS if kw in path]
        if path_matches:
            subscores["deceptive_path"] = 60.0
            indicators.append({
                "name": "Credential Harvest Path Signature",
                "category": "Phishing Architecture",
                "severity_score": 60.0,
                "weight": 20,
                "description": "Path simulates a secure login checkpoint to induce visitors into revealing credentials.",
                "evidence": ", ".join(path_matches),
                "triggered": True
            })

        # Combine scores
        weights = {
            "ip_host": 1.4,
            "typosquatting": 2.2,
            "punycode": 2.2,
            "tld": 1.2,
            "entropy": 1.5,
            "deceptive_path": 1.0
        }
        
        if not subscores:
            raw_score = 4.0
        else:
            raw_score = RiskScorer.combine_scores(subscores, weights)

        evaluation = RiskScorer.evaluate(raw_score, indicators)
        
        # MITRE Mapping
        mitre_tags = ["PHISHING_LINK"]
        if matched_brand:
            mitre_tags.append("TYPOSQUATTING")
        if "xn--" in netloc:
            mitre_tags.append("HOMOGLYPH_ATTACK")

        mitre_mappings = MITREMapper.get_mappings(mitre_tags)

        # XAI Narrative
        threat_type = "Malicious Look-Alike Domain" if matched_brand else ("Deceptive URL" if evaluation["is_threat"] else "Legitimate URL")
        xai_data = ExplainableAIEngine.generate_explanation(
            threat_type=threat_type,
            risk_level=evaluation["level"],
            indicators=indicators,
            context={"url": raw_url, "domain": netloc}
        )

        # Action Recommendations
        recommended_actions = []
        if evaluation["level"] in ["CRITICAL", "HIGH"]:
            recommended_actions.append({
                "action": "BLOCK_DOMAIN_FIREWALL",
                "label": "Add Domain to Next-Gen Firewall Blacklist",
                "priority": "P1 - Immediate",
                "description": "Instantly propagate block rule across enterprise Palo Alto / Fortinet perimeters."
            })
            recommended_actions.append({
                "action": "SINKHOLE_DNS",
                "label": "Sinkhole Internal Recursive DNS Queries",
                "priority": "P1 - Immediate",
                "description": "Reroute all DNS requests for this hostname to internal telemetry honeypot."
            })
            recommended_actions.append({
                "action": "TAKEDOWN_REQUEST",
                "label": "Generate Registrar Domain Abuse Takedown",
                "priority": "P2 - High",
                "description": "Automatically draft RFC compliant abuse report to the authoritative registrar."
            })
        elif evaluation["level"] == "MEDIUM":
            recommended_actions.append({
                "action": "ISOLATE_BROWSER",
                "label": "Route Through Remote Browser Isolation (RBI)",
                "priority": "P3 - Moderate",
                "description": "Allow rendering only via disposable virtualized container without local execution."
            })
        else:
            recommended_actions.append({
                "action": "REPUTATION_MONITOR",
                "label": "Pass Through with Passive Telemetry Log",
                "priority": "P5 - Informational",
                "description": "No active block required; host reputation verified as benign."
            })

        return {
            "threat_category": "Malicious URL & Infrastructure Spoofing",
            "threat_type": threat_type,
            "target_url": raw_url,
            "parsed_domain": netloc,
            "brand_impersonated": matched_brand.upper() if matched_brand else None,
            "shannon_entropy": round(entropy, 2),
            "risk_evaluation": evaluation,
            "explainable_ai": xai_data,
            "mitre_mappings": mitre_mappings,
            "recommended_actions": recommended_actions
        }
