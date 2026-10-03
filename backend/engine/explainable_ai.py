"""
Explainable AI (XAI) Engine for CYBERGUARD
Generates human-readable explanations, feature attribution breakdowns,
and evidence markers for automated security decisions.
"""
from typing import List, Dict, Any

class ExplainableAIEngine:
    @classmethod
    def generate_explanation(
        cls,
        threat_type: str,
        risk_level: str,
        indicators: List[Dict[str, Any]],
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Synthesizes indicators into an Explainable AI dossier:
        - Plain English summary explanation
        - Key contributing indicators with severity
        - Feature attribution weights (for radar / bar charts)
        - Decision rationale
        """
        context = context or {}
        active_indicators = [ind for ind in indicators if ind.get("triggered", True)]
        
        # Build natural language narrative
        if not active_indicators or risk_level == "SAFE":
            summary = "Activity evaluated as normal. No suspicious behavioral patterns, anomalous indicators, or unauthorized impersonation signatures detected."
            detailed_rationale = (
                "The analysis did not uncover indicators of psychological coercion, deceptive domain structures, "
                "or abnormal authentication deviations. Content and telemetry match baseline corporate profiles."
            )
        else:
            indicator_descriptions = [ind.get("description", ind.get("name", "")) for ind in active_indicators]
            top_reasons = indicator_descriptions[:3]
            
            summary = f"{risk_level} Risk: {'. '.join(top_reasons)}."
            
            detailed_rationale = cls._build_detailed_narrative(
                threat_type=threat_type,
                risk_level=risk_level,
                indicators=active_indicators,
                context=context
            )

        # Feature attribution for UI charts
        feature_importance = []
        for ind in active_indicators:
            weight = ind.get("weight", ind.get("severity_score", 50))
            feature_importance.append({
                "feature": ind.get("name", "Unknown Feature"),
                "importance_score": weight,
                "category": ind.get("category", "Heuristic"),
                "evidence": ind.get("evidence", "Flagged by model inspection")
            })

        return {
            "summary": summary,
            "detailed_rationale": detailed_rationale,
            "evidence_count": len(active_indicators),
            "indicators": active_indicators,
            "feature_importance": feature_importance
        }

    @classmethod
    def _build_detailed_narrative(
        cls,
        threat_type: str,
        risk_level: str,
        indicators: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> str:
        parts = []
        parts.append(f"Model identified {len(indicators)} corroborating security signals pointing towards {threat_type}.")
        
        for idx, ind in enumerate(indicators[:4], 1):
            name = ind.get("name", "Signal")
            desc = ind.get("description", "")
            evidence = ind.get("evidence", "")
            detail = f"({idx}) {name}: {desc}"
            if evidence:
                detail += f" [Evidence: '{evidence}']"
            parts.append(detail)
            
        if risk_level in ["HIGH", "CRITICAL"]:
            parts.append(
                "These combined telemetry markers indicate active exploitation or targeted social engineering requiring immediate containment."
            )
        else:
            parts.append(
                "Telemetry demonstrates elevated risk exceeding normal baseline tolerances. Continuous monitoring and user caution recommended."
            )
            
        return " ".join(parts)
