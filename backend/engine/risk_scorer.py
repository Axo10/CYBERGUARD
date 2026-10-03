"""
Unified Threat Risk Scoring Engine
Calibrates composite risk scores on a 0-100 scale into standard threat levels:
Safe (0-19) -> Low (20-39) -> Medium (40-69) -> High (70-89) -> Critical (90-100)
"""
from typing import Dict, Any, List

class RiskScorer:
    LEVELS = {
        "SAFE": {"min": 0, "max": 19, "color": "#10b981", "badge": "Safe", "label": "SAFE"},
        "LOW": {"min": 20, "max": 39, "color": "#3b82f6", "badge": "Low Risk", "label": "LOW"},
        "MEDIUM": {"min": 40, "max": 69, "color": "#f59e0b", "badge": "Medium Risk", "label": "MEDIUM"},
        "HIGH": {"min": 70, "max": 89, "color": "#f97316", "badge": "High Risk", "label": "HIGH"},
        "CRITICAL": {"min": 90, "max": 100, "color": "#ef4444", "badge": "Critical Threat", "label": "CRITICAL"}
    }

    @classmethod
    def evaluate(cls, score: float, indicators: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Evaluates a raw score (0-100) and returns classification, risk level,
        color code, and contributing weight summary.
        """
        clamped_score = max(0.0, min(100.0, round(float(score), 1)))

        if clamped_score < 20:
            level_key = "SAFE"
        elif clamped_score < 40:
            level_key = "LOW"
        elif clamped_score < 70:
            level_key = "MEDIUM"
        elif clamped_score < 90:
            level_key = "HIGH"
        else:
            level_key = "CRITICAL"

        level_info = cls.LEVELS[level_key]

        return {
            "score": clamped_score,
            "level": level_info["label"],
            "badge": level_info["badge"],
            "color": level_info["color"],
            "is_threat": clamped_score >= 40,
            "requires_immediate_action": clamped_score >= 70,
            "confidence": round(min(0.99, max(0.70, clamped_score / 100.0 if clamped_score >= 50 else (100 - clamped_score) / 100.0)), 2)
        }

    @classmethod
    def combine_scores(cls, subscores: Dict[str, float], weights: Dict[str, float] = None) -> float:
        """
        Combines weighted subscores into a single normalized 0-100 score.
        """
        if not subscores:
            return 0.0

        if not weights:
            # Equal weighting
            return sum(subscores.values()) / len(subscores)

        total_weight = sum(weights.get(k, 1.0) for k in subscores.keys())
        if total_weight == 0:
            return 0.0

        weighted_sum = sum(score * weights.get(k, 1.0) for k, score in subscores.items())
        return min(100.0, max(0.0, weighted_sum / total_weight))
