from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.alert import Alert
from app.models.analysis_run import AnalysisRun
from app.models.detection import Detection
from app.models.system_settings import SystemSettings
from app.models.user import User
from app.schemas.system import DashboardSummaryResponse, SystemSettingsResponse, SystemSettingsUpdateRequest, SystemStatusResponse
from app.services.audit import AuditService
from app.services.audit_enums import AuditAction, AuditResult
from app.services.system_settings import get_system_settings

router = APIRouter(tags=["system"])


@router.get("/system/status", response_model=SystemStatusResponse)
def get_system_status(db: Session = Depends(get_db)) -> SystemStatusResponse:
    db.execute(text("SELECT 1"))
    return SystemStatusResponse(
        api_status="online",
        database_status="online",
        light_hids_status="not_configured",
        light_hids_message="Host traces are accepted; the LIGHT-HIDS model is not installed yet.",
    )


@router.get("/dashboard/summary", response_model=DashboardSummaryResponse)
def get_dashboard_summary(
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> DashboardSummaryResponse:
    analysis_runs = db.scalar(select(func.count()).select_from(AnalysisRun)) or 0
    analyzed_events = db.scalar(select(func.coalesce(func.sum(AnalysisRun.event_count), 0))) or 0
    return DashboardSummaryResponse(
        analysis_runs=analysis_runs,
        analyzed_events=analyzed_events,
        detections=db.scalar(select(func.count()).select_from(Detection)) or 0,
        open_alerts=db.scalar(select(func.count()).select_from(Alert).where(Alert.status != "resolved")) or 0,
    )


@router.get("/system/settings", response_model=SystemSettingsResponse)
def read_system_settings(
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> SystemSettings:
    return get_system_settings(db)


_admin = require_role("admin")


@router.patch("/system/settings", response_model=SystemSettingsResponse)
def update_system_settings(
    payload: SystemSettingsUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    _admin: User = Depends(_admin),
) -> SystemSettings:
    settings = get_system_settings(db)

    old_max_upload = settings.max_upload_mb
    old_history_limit = settings.analysis_history_limit

    settings.max_upload_mb = payload.max_upload_mb
    settings.analysis_history_limit = payload.analysis_history_limit

    audit = AuditService(db)
    ip = _get_ip(request)
    ua = _get_ua(request)
    metadata: dict[str, object] = {}
    if old_max_upload != payload.max_upload_mb:
        metadata["max_upload_mb"] = {"from": old_max_upload, "to": payload.max_upload_mb}
    if old_history_limit != payload.analysis_history_limit:
        metadata["analysis_history_limit"] = {"from": old_history_limit, "to": payload.analysis_history_limit}

    if metadata:
        audit.record(
            action=AuditAction.SYSTEM_SETTING_CHANGED,
            result=AuditResult.SUCCESS,
            actor_user_id=_admin.id,
            actor_email=_admin.email,
            resource_type="SYSTEM",
            ip_address=ip,
            user_agent=ua,
            metadata=metadata,
        )
        audit.record(
            action=AuditAction.SYSTEM_CONFIGURATION_CHANGED,
            result=AuditResult.SUCCESS,
            actor_user_id=_admin.id,
            actor_email=_admin.email,
            resource_type="SYSTEM",
            ip_address=ip,
            user_agent=ua,
            metadata={"changed_fields": list(metadata.keys())},
        )

    db.commit()
    db.refresh(settings)
    return settings


def _get_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _get_ua(request: Request) -> str | None:
    ua = request.headers.get("user-agent")
    return ua[:512] if ua else None
