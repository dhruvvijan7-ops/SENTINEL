from __future__ import annotations

from typing import Any

from sentinel_core.config import Settings
from sentinel_core.db import tx
from sentinel_core.logging import get_logger
from sentinel_core.rls import set_rls
from sentinel_storage.repos_audit import insert_audit

from .auth import Principal

log = get_logger("api.audit")


def write_audit(
    settings: Settings,
    *,
    principal: Principal,
    action: str,
    outcome: str,
    object_kind: str | None = None,
    object_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Stage-6 §5.4: every mutating call and operator action lands in
    ``audit_log``, denied attempts included.  The row is always written in the
    principal's own workspace scope so the RLS policy matches; a denied call
    records the resource it asked for in ``detail``.

    Never raises: an audit failure must not convert a 403 into a 500, but it
    is logged loudly so the gap is visible.
    """
    try:
        with tx(settings.database_url) as conn:
            set_rls(conn, principal.tenant_id, principal.workspace_id)
            insert_audit(
                conn,
                tenant_id=principal.tenant_id,
                workspace_id=principal.workspace_id,
                principal=principal.principal_id,
                action=action,
                object_kind=object_kind,
                object_id=object_id,
                outcome=outcome,
                detail=detail or {},
            )
            conn.commit()
    except Exception as exc:
        log.error(
            "audit.write_failed",
            action=action,
            outcome=outcome,
            error=str(exc),
        )
