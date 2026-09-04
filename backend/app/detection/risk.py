"""Risk engine boundary.

Phase 1: Transitional implementation.
Maps severity to a risk score as a placeholder.
Future phases will implement contextual risk scoring with:
- asset criticality
- privilege
- IOC reputation
- behavioral rarity
- ATT&CK technique
- recurrence
- corroboration
- blast radius
"""
from __future__ import annotations

from app.detection.contracts.core import DetectionResult, RiskAssessment

_SEVERITY_RISK_MAP = {
    "critical": 0.9,
    "high": 0.7,
    "medium": 0.5,
    "low": 0.3,
    "info": 0.1,
}


def assess_risk(result: DetectionResult) -> RiskAssessment:
    """Phase 1 placeholder: maps severity to a risk score.

    This is NOT a real risk engine. It is a transitional boundary
    that preserves the architectural separation between detection
    and risk assessment.
    """
    risk_score = _SEVERITY_RISK_MAP.get(result.severity, 0.5)
    return RiskAssessment(
        risk_score=risk_score,
        risk_factors={"severity": result.severity},
        risk_version="1.0-phase1-placeholder",
        explanation=f"Phase 1 placeholder: risk derived from severity={result.severity}",
    )
