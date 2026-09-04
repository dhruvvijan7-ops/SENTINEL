"""Authoritative heuristic scoring.

This is the SINGLE authoritative implementation of the deterministic
heuristic/rule score used by all detectors. The legacy engine and the Phase 1
detector modules previously shipped duplicate copies of this formula; those
duplicates are removed and everything routes through :func:`compute_heuristic_score`.

Score semantics (see also DOCS and backend/docs/DETECTION_PHASE2.md):

- ``heuristic_score``   deterministic, rule/evidence-based volume+diversity score.
                        NOT a probability, NOT a confidence percentage.
- ``anomaly_score``     statistical/ML anomaly measure (future, Phase 3).
- ``confidence``        calibrated confidence (future; none implemented today).
- ``risk_score``        contextual risk (future / transitional severity mapping).

Only ``heuristic_score`` is produced by the current detectors. Future fields
remain ``None`` until genuine sources exist (specification 100).
"""
from __future__ import annotations


def compute_heuristic_score(
    *,
    event_count: int,
    diversity: int,
    matched_rules: int = 1,
) -> int:
    """Compute the authoritative heuristic/rule score.

    The formula is preserved from the legacy ``_compute_confidence`` (and the
    Phase 1 host/network detector copies) so existing default severity/score
    behaviour is unchanged:

        base        = min(matched_rules * 15, 60)
        volume      = min(event_count / 100, 20)
        diversity   = min(diversity / 10, 20)
        score       = clamp(base + volume + diversity, 10, 99)

    Parameters
    ----------
    event_count
        Total events considered by the detector.
    diversity
        A diversity metric appropriate to the detector: host detectors pass
        unique syscall count; network detectors pass distinct port count.
    matched_rules
        Number of distinct rule matches (default 1).

    The result is an integer heuristic score, NOT a probability.
    """
    base = min(matched_rules * 15, 60)
    volume_bonus = min(event_count / 100, 20)
    diversity_bonus = min(diversity / 10, 20)
    raw = base + volume_bonus + diversity_bonus
    return min(max(int(raw), 10), 99)
