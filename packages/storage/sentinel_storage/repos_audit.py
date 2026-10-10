from __future__ import annotations

from typing import Any

import psycopg
from psycopg.types.json import Json


def insert_audit(
    conn: psycopg.Connection,
    *,
    tenant_id: str,
    workspace_id: str,
    principal: str | None,
    action: str,
    object_kind: str | None,
    object_id: str | None,
    outcome: str,
    detail: dict[str, Any],
) -> None:
    conn.execute(
        """
        INSERT INTO audit_log (tenant_id, workspace_id, principal, action,
                               object_kind, object_id, outcome, detail)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            tenant_id,
            workspace_id,
            principal,
            action,
            object_kind,
            object_id,
            outcome,
            Json(detail),
        ),
    )
