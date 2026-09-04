"""Persistence mapping layer.

Converts DetectionResult domain objects into SQLAlchemy ORM models.
Keeps persistence concerns separate from detection logic.
"""
from __future__ import annotations

from uuid import uuid4

from sqlalchemy.orm import Session

from app.detection.contracts.core import DetectionResult
from app.models.alert import Alert
from app.models.detection import Detection


def persist_detections(
    results: list[DetectionResult],
    *,
    db: Session,
    analysis_run_id: str | None = None,
) -> tuple[list[Detection], list[Alert]]:
    """Convert DetectionResults to ORM objects and persist them.

    Returns the created Detection and Alert ORM objects.
    """
    detections: list[Detection] = []
    alerts: list[Alert] = []

    for result in results:
        detection_id = str(uuid4())
        detection = Detection(
            id=detection_id,
            analysis_run_id=analysis_run_id,
            detector_id=result.detector_id,
            detector_version=result.detector_version,
            detection_type=result.detection_type,
            title=result.title,
            description=result.description,
            severity=result.severity,
            confidence=result.scores.heuristic_score or 0,
            source_ip=result.source_ip,
            destination_ip=result.destination_ip,
            protocol=result.protocol,
            evidence=result.evidence.to_dict(),
            source_events=result.source_events or None,
        )
        detections.append(detection)

        alert = Alert(
            id=str(uuid4()),
            detection_id=detection_id,
            severity=result.severity,
            status="new",
            title=result.title,
            description=result.description,
            source=f"detection-engine:{result.detector_id}",
        )
        alerts.append(alert)

    for d in detections:
        db.add(d)
    for a in alerts:
        db.add(a)

    if detections or alerts:
        db.flush()

    return detections, alerts
