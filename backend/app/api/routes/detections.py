from __future__ import annotations

import math

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.alert import Alert
from app.models.analysis_run import AnalysisRun
from app.models.detection import Detection
from app.models.user import User
from app.schemas.detections import (
    AlertSummary,
    AnalysisRunSummary,
    DetectionDetailResponse,
    DetectionListResponse,
    DetectionResponse,
    DetectionSeverity,
    DetectionUpdateRequest,
)
from app.services.audit import AuditService
from app.services.audit_enums import AuditAction, AuditResult

router = APIRouter(prefix="/detections", tags=["detections"])


@router.get("", response_model=DetectionListResponse)
def list_detections(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    severity: DetectionSeverity | None = Query(default=None),
    search: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> DetectionListResponse:
    statement = select(Detection)

    if severity is not None:
        statement = statement.where(Detection.severity == severity)

    if search:
        pattern = f"%{search}%"
        statement = statement.where(
            or_(
                Detection.title.ilike(pattern),
                Detection.description.ilike(pattern),
                Detection.detection_type.ilike(pattern),
                Detection.source_ip.ilike(pattern),
                Detection.destination_ip.ilike(pattern),
                Detection.protocol.ilike(pattern),
            )
        )

    count_statement = select(func.count()).select_from(statement.subquery())
    total = db.scalar(count_statement) or 0
    total_pages = max(1, math.ceil(total / page_size))

    statement = statement.order_by(Detection.created_at.desc())
    statement = statement.offset((page - 1) * page_size).limit(page_size)

    items = list(db.scalars(statement).all())

    return DetectionListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{detection_id}", response_model=DetectionDetailResponse)
def get_detection(
    detection_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> DetectionDetailResponse:
    detection = db.get(Detection, detection_id)
    if detection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection not found.",
        )

    audit = AuditService(db)
    audit.record(
        action=AuditAction.DETECTION_VIEWED,
        result=AuditResult.SUCCESS,
        actor_user_id=_current_user.id,
        actor_email=_current_user.email,
        resource_type="DETECTION",
        resource_id=detection.id,
        ip_address=_get_ip(request),
        user_agent=_get_ua(request),
    )
    db.commit()

    analysis_run = None
    other_detections_in_run = 0
    if detection.analysis_run_id:
        run = db.get(AnalysisRun, detection.analysis_run_id)
        if run is not None:
            analysis_run = run
            other_detections_in_run = (
                db.scalar(
                    select(func.count())
                    .select_from(Detection)
                    .where(
                        Detection.analysis_run_id == detection.analysis_run_id,
                        Detection.id != detection.id,
                    )
                )
                or 0
            )

    alerts = list(
        db.scalars(
            select(Alert)
            .where(Alert.detection_id == detection.id)
            .order_by(Alert.created_at.desc())
        ).all()
    )

    return DetectionDetailResponse(
        detection=detection,
        analysis_run=analysis_run,
        alerts=alerts,
        other_detections_in_run=other_detections_in_run,
    )


@router.patch("/{detection_id}", response_model=DetectionResponse)
def update_detection(
    detection_id: str,
    payload: DetectionUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> Detection:
    detection = db.get(Detection, detection_id)
    if detection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection not found.",
        )

    old_status = detection.status
    detection.status = payload.status

    audit = AuditService(db)
    audit.record(
        action=AuditAction.DETECTION_STATUS_CHANGED,
        result=AuditResult.SUCCESS,
        actor_user_id=_current_user.id,
        actor_email=_current_user.email,
        resource_type="DETECTION",
        resource_id=detection.id,
        ip_address=_get_ip(request),
        user_agent=_get_ua(request),
        metadata={
            "old_status": old_status,
            "new_status": payload.status,
            "detection_type": detection.detection_type,
            "severity": detection.severity,
        },
    )

    db.commit()
    db.refresh(detection)
    return detection


@router.get("/{detection_id}/alerts", response_model=list[AlertSummary])
def get_detection_alerts(
    detection_id: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> list[AlertSummary]:
    detection = db.get(Detection, detection_id)
    if detection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection not found.",
        )
    return list(
        db.scalars(
            select(Alert)
            .where(Alert.detection_id == detection.id)
            .order_by(Alert.created_at.desc())
        ).all()
    )


def _get_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _get_ua(request: Request) -> str | None:
    ua = request.headers.get("user-agent")
    return ua[:512] if ua else None
