from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.alert import Alert
from app.models.user import User
from app.schemas.alerts import AlertListResponse, AlertResponse, AlertStatus, AlertUpdateRequest
from app.services.audit import AuditService
from app.services.audit_enums import AuditAction, AuditResult

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=AlertListResponse)
def list_alerts(
    request: Request,
    status_filter: AlertStatus | None = Query(default=None, alias="status"),
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> AlertListResponse:
    audit = AuditService(db)
    audit.record(
        action=AuditAction.ALERT_VIEWED,
        result=AuditResult.SUCCESS,
        actor_user_id=_current_user.id,
        actor_email=_current_user.email,
        resource_type="ALERT",
        ip_address=_get_ip(request),
        user_agent=_get_ua(request),
    )
    db.commit()

    statement = select(Alert).order_by(Alert.created_at.desc())
    if status_filter is not None:
        statement = statement.where(Alert.status == status_filter)
    return AlertListResponse(items=list(db.scalars(statement).all()))


@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert(
    alert_id: str,
    payload: AlertUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found.")

    old_status = alert.status
    alert.status = payload.status

    if payload.status == "resolved" and old_status != "resolved":
        action = AuditAction.ALERT_RESOLVED
    elif payload.status == "new" and old_status == "resolved":
        action = AuditAction.ALERT_REOPENED
    else:
        action = AuditAction.ALERT_STATUS_CHANGED

    audit = AuditService(db)
    audit.record(
        action=action,
        result=AuditResult.SUCCESS,
        actor_user_id=_current_user.id,
        actor_email=_current_user.email,
        resource_type="ALERT",
        resource_id=alert.id,
        ip_address=_get_ip(request),
        user_agent=_get_ua(request),
        metadata={
            "old_status": old_status,
            "new_status": payload.status,
            "title": alert.title,
            "severity": alert.severity,
        },
    )

    db.commit()
    db.refresh(alert)
    return alert


def _get_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _get_ua(request: Request) -> str | None:
    ua = request.headers.get("user-agent")
    return ua[:512] if ua else None
