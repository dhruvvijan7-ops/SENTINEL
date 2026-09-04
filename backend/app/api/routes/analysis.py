from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status
from sqlalchemy import func, literal, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.alert import Alert
from app.models.analysis_run import AnalysisRun
from app.models.detection import Detection
from app.models.network_event import NetworkEvent
from app.models.user import User
from app.schemas.analysis import AnalysisRunListResponse, AnalysisRunResponse
from app.schemas.detections import AlertSummary, DetectionListResponse, DetectionResponse
from app.schemas.monitoring import (
    MonitorRecordListResponse,
    MonitorRecordResponse,
    MonitoringRunDetail,
    MonitoringRunListResponse,
    SeverityCounts,
)
from app.detection.pipeline import analyse_network_events, analyse_trace
from app.services.audit import AuditService
from app.services.audit_enums import AuditAction, AuditResult
from app.services.host_trace import summarize_host_trace
from app.services.system_settings import get_system_settings

router = APIRouter(prefix="/analysis-runs", tags=["analysis-runs"])

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "normal")
_DETECTION_SEVERITIES = {"critical", "high", "medium", "low"}


def _severity_counts(rows: list[tuple[str, int]]) -> SeverityCounts:
    counts = {label: 0 for label in _SEVERITY_ORDER}
    for severity, count in rows:
        key = severity if severity in counts else "normal"
        counts[key] = count
    return SeverityCounts(**counts)


def _run_detection_counts(db: Session, run_ids: list[str]) -> dict[str, dict[str, int]]:
    """Return {run_id: {"total": n, "severity_rows": [(severity, count), ...]}}."""
    if not run_ids:
        return {}
    rows = db.execute(
        select(Detection.analysis_run_id, Detection.severity, func.count())
        .where(Detection.analysis_run_id.in_(run_ids))
        .group_by(Detection.analysis_run_id, Detection.severity)
    ).all()
    result: dict[str, dict[str, int]] = {}
    for run_id, severity, count in rows:
        entry = result.setdefault(run_id, {"total": 0, "severity_rows": []})
        entry["total"] += count
        entry["severity_rows"].append((severity, count))
    return result


def _run_alert_counts(db: Session, run_ids: list[str]) -> dict[str, int]:
    if not run_ids:
        return {}
    rows = db.execute(
        select(Detection.analysis_run_id, func.count(Alert.id))
        .join(Alert, Alert.detection_id == Detection.id)
        .where(
            Detection.analysis_run_id.in_(run_ids),
            Alert.detection_id.isnot(None),
        )
        .group_by(Detection.analysis_run_id)
    ).all()
    result = {run_id: 0 for run_id in run_ids}
    for run_id, count in rows:
        if run_id in result:
            result[run_id] = count
    return result


def _to_monitoring_detail(
    run: AnalysisRun,
    det_counts: dict[str, dict[str, int]],
    alert_counts: dict[str, int],
) -> MonitoringRunDetail:
    entry = det_counts.get(run.id, {"total": 0, "severity_rows": []})
    return MonitoringRunDetail(
        id=run.id,
        source_type=run.source_type,
        file_name=run.file_name,
        status=run.status,
        event_count=run.event_count,
        sequence_count=run.sequence_count,
        details=run.details,
        submitted_at=run.submitted_at,
        completed_at=run.completed_at,
        detection_count=entry["total"],
        alert_count=alert_counts.get(run.id, 0),
        severity_counts=_severity_counts(entry["severity_rows"]),
    )


def _load_run(db: Session, run_id: str) -> AnalysisRun:
    run = db.get(AnalysisRun, run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis run not found.",
        )
    return run


@router.get("", response_model=AnalysisRunListResponse)
def list_analysis_runs(
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> AnalysisRunListResponse:
    settings = get_system_settings(db)
    runs = db.scalars(select(AnalysisRun).order_by(AnalysisRun.submitted_at.desc()).limit(settings.analysis_history_limit)).all()
    return AnalysisRunListResponse(items=list(runs))


@router.get("/monitoring", response_model=MonitoringRunListResponse)
def list_monitoring_runs(
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> MonitoringRunListResponse:
    settings = get_system_settings(db)
    runs = db.scalars(
        select(AnalysisRun).order_by(AnalysisRun.submitted_at.desc()).limit(settings.analysis_history_limit)
    ).all()
    run_ids = [r.id for r in runs]
    det_counts = _run_detection_counts(db, run_ids)
    alert_counts = _run_alert_counts(db, run_ids)
    items = [_to_monitoring_detail(r, det_counts, alert_counts) for r in runs]
    return MonitoringRunListResponse(items=items)


@router.get("/{run_id}", response_model=AnalysisRunResponse)
def get_analysis_run(
    run_id: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> AnalysisRun:
    return _load_run(db, run_id)


@router.get("/{run_id}/detail", response_model=MonitoringRunDetail)
def get_analysis_run_detail(
    run_id: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> MonitoringRunDetail:
    run = _load_run(db, run_id)
    det_counts = _run_detection_counts(db, [run.id])
    alert_counts = _run_alert_counts(db, [run.id])
    return _to_monitoring_detail(run, det_counts, alert_counts)


@router.get("/{run_id}/alerts", response_model=list[AlertSummary])
def get_analysis_run_alerts(
    run_id: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> list[AlertSummary]:
    run = _load_run(db, run_id)
    alerts = db.scalars(
        select(Alert)
        .join(Detection, Detection.id == Alert.detection_id)
        .where(
            Detection.analysis_run_id == run.id,
            Alert.detection_id.isnot(None),
        )
        .order_by(Alert.created_at.desc())
    ).all()
    return list(alerts)


@router.get("/{run_id}/records", response_model=MonitorRecordListResponse)
def list_run_records(
    run_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    record_type: str | None = Query(default=None, alias="type"),
    severity: str | None = Query(default=None),
    search: str | None = Query(default=None),
    from_timestamp: str | None = Query(default=None, alias="from"),
    to_timestamp: str | None = Query(default=None, alias="to"),
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> MonitorRecordListResponse:
    run = _load_run(db, run_id)

    detection_cols = [
        Detection.id.label("id"),
        literal("detection").label("record_type"),
        Detection.severity.label("severity"),
        Detection.detection_type.label("kind"),
        Detection.title.label("title"),
        Detection.description.label("description"),
        Detection.created_at.label("timestamp"),
        Detection.source_ip.label("source_ip"),
        Detection.destination_ip.label("destination_ip"),
        Detection.protocol.label("protocol"),
        Detection.id.label("detection_id"),
    ]
    det_stmt = (
        select(*detection_cols)
        .where(Detection.analysis_run_id == run.id)
    )

    event_sev = func.coalesce(Detection.severity, literal("normal"))
    event_cols = [
        NetworkEvent.id.label("id"),
        literal("network_event").label("record_type"),
        event_sev.label("severity"),
        NetworkEvent.syscall_name.label("kind"),
        NetworkEvent.description.label("title"),
        NetworkEvent.description.label("description"),
        NetworkEvent.timestamp.label("timestamp"),
        NetworkEvent.source_ip.label("source_ip"),
        NetworkEvent.destination_ip.label("destination_ip"),
        NetworkEvent.protocol.label("protocol"),
        NetworkEvent.detection_id.label("detection_id"),
    ]
    event_stmt = (
        select(*event_cols)
        .outerjoin(Detection, Detection.id == NetworkEvent.detection_id)
        .where(NetworkEvent.analysis_run_id == run.id)
    )

    combined = det_stmt.union_all(event_stmt).subquery()

    stmt = select(combined)

    if record_type in ("detection", "network_event"):
        stmt = stmt.where(combined.c.record_type == record_type)

    if severity:
        stmt = stmt.where(combined.c.severity == severity)

    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(
            or_(
                combined.c.kind.ilike(pattern),
                combined.c.title.ilike(pattern),
                combined.c.description.ilike(pattern),
                combined.c.source_ip.ilike(pattern),
                combined.c.destination_ip.ilike(pattern),
                combined.c.protocol.ilike(pattern),
            )
        )

    if from_timestamp:
        dt = _parse_iso(from_timestamp)
        if dt:
            stmt = stmt.where(combined.c.timestamp >= dt)

    if to_timestamp:
        dt = _parse_iso(to_timestamp)
        if dt:
            stmt = stmt.where(combined.c.timestamp <= dt)

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = db.scalar(count_stmt) or 0
    total_pages = max((total + page_size - 1) // page_size, 1)

    rows = db.execute(
        stmt.order_by(combined.c.timestamp.desc().nullslast(), combined.c.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()

    items = [
        MonitorRecordResponse(
            id=row.id,
            record_type=row.record_type,
            severity=row.severity or "normal",
            kind=row.kind,
            title=row.title,
            description=row.description,
            timestamp=row.timestamp,
            source_ip=row.source_ip,
            destination_ip=row.destination_ip,
            protocol=row.protocol,
            detection_id=row.detection_id,
        )
        for row in rows
    ]

    return MonitorRecordListResponse(
        items=items, total=total, page=page, page_size=page_size, total_pages=total_pages,
    )


def _parse_iso(raw: str) -> datetime | None:
    try:
        s = raw.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


@router.get("/{run_id}/detections", response_model=DetectionListResponse)
def get_analysis_run_detections(
    run_id: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> DetectionListResponse:
    run = db.get(AnalysisRun, run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis run not found.",
        )

    statement = select(Detection).where(Detection.analysis_run_id == run_id)
    count_statement = select(func.count()).select_from(statement.subquery())
    total = db.scalar(count_statement) or 0

    items = list(
        db.scalars(statement.order_by(Detection.created_at.desc())).all()
    )

    return DetectionListResponse(
        items=items,
        total=total,
        page=1,
        page_size=total or 1,
        total_pages=1,
    )


@router.post("/host-traces", response_model=AnalysisRunResponse, status_code=201)
async def upload_host_trace(
    file: UploadFile = File(...),
    request: Request = None,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> AnalysisRun:
    settings = get_system_settings(db)

    audit = AuditService(db)
    ip = _get_ip(request)
    ua = _get_ua(request)

    is_json = file.filename and file.filename.endswith(".json")

    audit.record(
        action=AuditAction.VALIDATION_STARTED,
        result=AuditResult.SUCCESS,
        actor_user_id=_current_user.id,
        actor_email=_current_user.email,
        resource_type="ANALYSIS_RUN",
        ip_address=ip,
        user_agent=ua,
        metadata={"filename": file.filename, "file_type": "json" if is_json else "csv"},
    )

    try:
        content = await file.read()
        summary = summarize_host_trace(content, max_upload_mb=settings.max_upload_mb)
    except Exception as exc:
        upload_action = AuditAction.JSON_UPLOAD if is_json else AuditAction.CSV_UPLOAD
        audit.record(
            action=AuditAction.UPLOAD_REJECTED,
            result=AuditResult.FAILURE,
            actor_user_id=_current_user.id,
            actor_email=_current_user.email,
            resource_type="ANALYSIS_RUN",
            ip_address=ip,
            user_agent=ua,
            metadata={"filename": file.filename, "error": str(exc)},
        )
        audit.record(
            action=AuditAction.VALIDATION_FAILED,
            result=AuditResult.FAILURE,
            actor_user_id=_current_user.id,
            actor_email=_current_user.email,
            resource_type="ANALYSIS_RUN",
            ip_address=ip,
            user_agent=ua,
            metadata={"filename": file.filename, "error": str(exc)},
        )
        db.commit()
        raise

    upload_action = AuditAction.JSON_UPLOAD if is_json else AuditAction.CSV_UPLOAD
    audit.record(
        action=upload_action,
        result=AuditResult.SUCCESS,
        actor_user_id=_current_user.id,
        actor_email=_current_user.email,
        resource_type="ANALYSIS_RUN",
        ip_address=ip,
        user_agent=ua,
        metadata={
            "filename": file.filename,
            "event_count": summary.event_count,
            "sequence_count": summary.sequence_count,
        },
    )

    audit.record(
        action=AuditAction.VALIDATION_COMPLETED,
        result=AuditResult.SUCCESS,
        actor_user_id=_current_user.id,
        actor_email=_current_user.email,
        resource_type="ANALYSIS_RUN",
        ip_address=ip,
        user_agent=ua,
        metadata={
            "filename": file.filename,
            "event_count": summary.event_count,
            "sequence_count": summary.sequence_count,
            "unique_system_calls": summary.unique_system_calls,
        },
    )

    completed_at = datetime.now(timezone.utc)
    run = AnalysisRun(
        source_type="host_trace",
        file_name=file.filename or "host-trace.json",
        status="completed",
        event_count=summary.event_count,
        sequence_count=summary.sequence_count,
        details={
            "unique_system_calls": summary.unique_system_calls,
            "network_event_count": len(summary.network_events),
        },
        completed_at=completed_at,
    )
    db.add(run)
    db.flush()

    audit.record(
        action=AuditAction.ANALYSIS_STARTED,
        result=AuditResult.SUCCESS,
        actor_user_id=_current_user.id,
        actor_email=_current_user.email,
        resource_type="ANALYSIS_RUN",
        resource_id=run.id,
        ip_address=ip,
        user_agent=ua,
        metadata={
            "event_count": summary.event_count,
            "sequence_count": summary.sequence_count,
            "unique_system_calls": summary.unique_system_calls,
        },
    )

    try:
        detections, alerts = analyse_trace(
            event_count=summary.event_count,
            sequence_count=summary.sequence_count,
            unique_system_calls=summary.unique_system_calls,
            all_calls=summary.all_calls,
            db=db,
            analysis_run_id=run.id,
        )

        for detection in detections:
            audit.record(
                action=AuditAction.DETECTION_CREATED,
                result=AuditResult.SUCCESS,
                actor_user_id=_current_user.id,
                actor_email=_current_user.email,
                resource_type="DETECTION",
                resource_id=detection.id,
                ip_address=ip,
                user_agent=ua,
                metadata={
                    "detection_type": detection.detection_type,
                    "severity": detection.severity,
                    "confidence": detection.confidence,
                    "analysis_run_id": run.id,
                },
            )

        for alert in alerts:
            audit.record(
                action=AuditAction.ALERT_CREATED,
                result=AuditResult.SUCCESS,
                actor_user_id=_current_user.id,
                actor_email=_current_user.email,
                resource_type="ALERT",
                resource_id=alert.id,
                ip_address=ip,
                user_agent=ua,
                metadata={
                    "title": alert.title,
                    "severity": alert.severity,
                    "detection_id": alert.detection_id,
                },
            )

        saved_network_events: list[NetworkEvent] = []
        if summary.network_events:
            for ne in summary.network_events:
                net_event = NetworkEvent(
                    analysis_run_id=run.id,
                    timestamp=ne.timestamp,
                    source_ip=ne.source_ip,
                    destination_ip=ne.destination_ip,
                    source_port=ne.source_port,
                    destination_port=ne.destination_port,
                    protocol=ne.protocol,
                    connection_id=ne.connection_id,
                    syscall_name=ne.syscall_name,
                    sequence_index=ne.sequence_index,
                    event_index=ne.event_index,
                    description=ne.description,
                )
                db.add(net_event)
                saved_network_events.append(net_event)
            db.flush()

        net_detections, net_alerts = analyse_network_events(
            network_events=saved_network_events,
            analysis_run_id=run.id,
            db=db,
        )

        for detection in net_detections:
            audit.record(
                action=AuditAction.DETECTION_CREATED,
                result=AuditResult.SUCCESS,
                actor_user_id=_current_user.id,
                actor_email=_current_user.email,
                resource_type="DETECTION",
                resource_id=detection.id,
                ip_address=ip,
                user_agent=ua,
                metadata={
                    "detection_type": detection.detection_type,
                    "severity": detection.severity,
                    "confidence": detection.confidence,
                    "analysis_run_id": run.id,
                    "source": "network-detection-engine",
                },
            )

        for alert in net_alerts:
            audit.record(
                action=AuditAction.ALERT_CREATED,
                result=AuditResult.SUCCESS,
                actor_user_id=_current_user.id,
                actor_email=_current_user.email,
                resource_type="ALERT",
                resource_id=alert.id,
                ip_address=ip,
                user_agent=ua,
                metadata={
                    "title": alert.title,
                    "severity": alert.severity,
                    "detection_id": alert.detection_id,
                    "source": "network-detection-engine",
                },
            )

        all_detections = detections + net_detections
        all_alerts = alerts + net_alerts

        audit.record(
            action=AuditAction.ANALYSIS_COMPLETED,
            result=AuditResult.SUCCESS,
            actor_user_id=_current_user.id,
            actor_email=_current_user.email,
            resource_type="ANALYSIS_RUN",
            resource_id=run.id,
            ip_address=ip,
            user_agent=ua,
            metadata={
                "detections_count": len(all_detections),
                "alerts_count": len(all_alerts),
                "network_events_count": len(saved_network_events),
            },
        )
    except Exception as exc:
        run.status = "failed"
        db.add(run)
        audit.record(
            action=AuditAction.ANALYSIS_FAILED,
            result=AuditResult.FAILURE,
            actor_user_id=_current_user.id,
            actor_email=_current_user.email,
            resource_type="ANALYSIS_RUN",
            resource_id=run.id,
            ip_address=ip,
            user_agent=ua,
            metadata={
                "filename": file.filename,
                "error_type": exc.__class__.__name__,
            },
            description="Analysis failed while processing the uploaded trace.",
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis failed while processing the uploaded trace.",
        )

    db.commit()
    db.refresh(run)
    return run


def _get_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _get_ua(request: Request | None) -> str | None:
    if request is None:
        return None
    ua = request.headers.get("user-agent")
    return ua[:512] if ua else None
