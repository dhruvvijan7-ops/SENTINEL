from __future__ import annotations

import csv
import io
import math
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.audit import AuditLogListResponse, AuditLogResponse

router = APIRouter(prefix="/audit-logs", tags=["audit-logs"])

_admin_or_analyst = require_role("admin", "analyst")


def _apply_filters(
    statement,
    category,
    action,
    actor_user_id,
    actor_email,
    resource_type,
    resource_id,
    result,
    severity,
    user_agent,
    ip_address,
    from_timestamp,
    to_timestamp,
    search,
):
    if category is not None:
        statement = statement.where(AuditLog.category == category)

    if action is not None:
        statement = statement.where(AuditLog.action == action)

    if actor_user_id is not None:
        statement = statement.where(AuditLog.actor_user_id == actor_user_id)

    if actor_email is not None:
        statement = statement.where(AuditLog.actor_email == actor_email)

    if resource_type is not None:
        statement = statement.where(AuditLog.resource_type == resource_type)

    if resource_id is not None:
        statement = statement.where(AuditLog.resource_id == resource_id)

    if result is not None:
        statement = statement.where(AuditLog.result == result)

    if severity is not None:
        statement = statement.where(AuditLog.severity == severity)

    if user_agent is not None:
        pattern = f"%{user_agent}%"
        statement = statement.where(AuditLog.user_agent.ilike(pattern))

    if ip_address is not None:
        statement = statement.where(AuditLog.ip_address == ip_address)

    if from_timestamp is not None:
        statement = statement.where(AuditLog.timestamp >= from_timestamp)

    if to_timestamp is not None:
        statement = statement.where(AuditLog.timestamp <= to_timestamp)

    if search:
        pattern = f"%{search}%"
        statement = statement.where(
            or_(
                AuditLog.actor_email.ilike(pattern),
                AuditLog.action.ilike(pattern),
                AuditLog.category.ilike(pattern),
                AuditLog.resource_type.ilike(pattern),
                AuditLog.resource_id.ilike(pattern),
                AuditLog.description.ilike(pattern),
                AuditLog.user_agent.ilike(pattern),
                AuditLog.ip_address.ilike(pattern),
            )
        )

    return statement


@router.get("", response_model=AuditLogListResponse)
def list_audit_logs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    category: str | None = Query(default=None),
    action: str | None = Query(default=None),
    actor_user_id: str | None = Query(default=None),
    actor_email: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    resource_id: str | None = Query(default=None),
    result: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    user_agent: str | None = Query(default=None),
    ip_address: str | None = Query(default=None),
    from_timestamp: datetime | None = Query(default=None),
    to_timestamp: datetime | None = Query(default=None),
    search: str | None = Query(default=None),
    sort_by: str = Query(default="timestamp"),
    sort_order: str = Query(default="desc"),
    db: Session = Depends(get_db),
    _admin: User = Depends(_admin_or_analyst),
) -> AuditLogListResponse:
    statement = select(AuditLog)

    statement = _apply_filters(
        statement,
        category=category,
        action=action,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        resource_type=resource_type,
        resource_id=resource_id,
        result=result,
        severity=severity,
        user_agent=user_agent,
        ip_address=ip_address,
        from_timestamp=from_timestamp,
        to_timestamp=to_timestamp,
        search=search,
    )

    count_statement = select(func.count()).select_from(statement.subquery())
    total = db.scalar(count_statement) or 0
    total_pages = max(1, math.ceil(total / page_size))

    sort_column = getattr(AuditLog, sort_by, AuditLog.timestamp)
    if sort_order == "asc":
        statement = statement.order_by(sort_column.asc())
    else:
        statement = statement.order_by(sort_column.desc())

    statement = statement.offset((page - 1) * page_size).limit(page_size)

    items = list(db.scalars(statement).all())

    return AuditLogListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/export")
def export_audit_logs(
    category: str | None = Query(default=None),
    action: str | None = Query(default=None),
    actor_user_id: str | None = Query(default=None),
    actor_email: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    resource_id: str | None = Query(default=None),
    result: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    user_agent: str | None = Query(default=None),
    ip_address: str | None = Query(default=None),
    from_timestamp: datetime | None = Query(default=None),
    to_timestamp: datetime | None = Query(default=None),
    search: str | None = Query(default=None),
    sort_by: str = Query(default="timestamp"),
    sort_order: str = Query(default="asc"),
    db: Session = Depends(get_db),
    _admin: User = Depends(_admin_or_analyst),
) -> StreamingResponse:
    statement = select(AuditLog)

    statement = _apply_filters(
        statement,
        category=category,
        action=action,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        resource_type=resource_type,
        resource_id=resource_id,
        result=result,
        severity=severity,
        user_agent=user_agent,
        ip_address=ip_address,
        from_timestamp=from_timestamp,
        to_timestamp=to_timestamp,
        search=search,
    )

    sort_column = getattr(AuditLog, sort_by, AuditLog.timestamp)
    if sort_order == "desc":
        statement = statement.order_by(sort_column.desc())
    else:
        statement = statement.order_by(sort_column.asc())

    items = list(db.scalars(statement).all())

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "id",
            "timestamp",
            "created_at",
            "actor_user_id",
            "actor_email",
            "actor_type",
            "category",
            "action",
            "result",
            "severity",
            "resource_type",
            "resource_id",
            "ip_address",
            "user_agent",
            "request_id",
            "description",
        ]
    )
    for entry in items:
        writer.writerow(
            [
                entry.id,
                entry.timestamp.isoformat() if entry.timestamp else "",
                entry.created_at.isoformat() if entry.created_at else "",
                entry.actor_user_id or "",
                entry.actor_email or "",
                entry.actor_type or "",
                entry.category or "",
                entry.action or "",
                entry.result or "",
                entry.severity or "",
                entry.resource_type or "",
                entry.resource_id or "",
                entry.ip_address or "",
                entry.user_agent or "",
                entry.request_id or "",
                entry.description or "",
            ]
        )

    buffer.seek(0)
    filename = f"audit-logs-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.csv"
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{log_id}", response_model=AuditLogResponse)
def get_audit_log(
    log_id: str,
    db: Session = Depends(get_db),
    _admin: User = Depends(_admin_or_analyst),
) -> AuditLog:
    entry = db.get(AuditLog, log_id)
    if entry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log not found.",
        )
    return entry
