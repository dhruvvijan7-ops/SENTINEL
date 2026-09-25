from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.services.audit_enums import (
    ACTION_CATEGORY_MAP,
    AuditAction,
    AuditResult,
)


_SYSTEM_ACTOR_ID = "__system__"
_SYSTEM_ACTOR_EMAIL = "system@sentinel.local"


def _default_severity(action: AuditAction, result: AuditResult) -> str:
    if action in (
        AuditAction.LOGIN_FAILED,
        AuditAction.REFRESH_TOKEN_REUSED,
        AuditAction.PASSWORD_RESET_FAILED,
        AuditAction.RATE_LIMIT_TRIGGERED,
        AuditAction.UPLOAD_REJECTED,
        AuditAction.VALIDATION_FAILED,
        AuditAction.ANALYSIS_FAILED,
    ):
        return "high"
    if action in (
        AuditAction.USER_DEACTIVATED,
        AuditAction.USER_ROLE_CHANGED,
        AuditAction.SYSTEM_SETTING_CHANGED,
        AuditAction.SYSTEM_CONFIGURATION_CHANGED,
        AuditAction.PASSWORD_RESET_REQUESTED,
        AuditAction.PASSWORD_RESET_COMPLETED,
        AuditAction.REFRESH_TOKEN_ROTATED,
        AuditAction.SESSION_REVOKED,
        AuditAction.DETECTION_CREATED,
        AuditAction.ALERT_CREATED,
    ):
        return "medium"
    if result == AuditResult.FAILURE:
        return "medium"
    return "info"


class AuditService:
    def __init__(self, db: Session) -> None:
        self._db = db

    def record(
        self,
        *,
        action: AuditAction,
        result: AuditResult = AuditResult.SUCCESS,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
        actor_type: str = "user",
        resource_type: str | None = None,
        resource_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        severity: str | None = None,
        metadata: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> AuditLog:
        category = ACTION_CATEGORY_MAP[action].value

        if actor_user_id is None and actor_email is None:
            actor_user_id = _SYSTEM_ACTOR_ID
            actor_email = _SYSTEM_ACTOR_EMAIL
            actor_type = "system"

        entry = AuditLog(
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            actor_type=actor_type,
            category=category,
            action=action.value,
            result=result.value,
            severity=severity or _default_severity(action, result),
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            metadata_json=metadata,
            description=description,
        )
        self._db.add(entry)
        return entry
