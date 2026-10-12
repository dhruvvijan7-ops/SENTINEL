from __future__ import annotations

from datetime import datetime
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


def list_audit(
    conn: psycopg.Connection,
    *,
    action: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    sql = (
        "SELECT audit_uid, at, principal, action, object_kind, object_id, "
        "outcome, detail FROM audit_log"
    )
    clauses: list[str] = []
    args: list[Any] = []
    if action:
        clauses.append("action = %s")
        args.append(action)
    if since:
        clauses.append("at >= %s")
        args.append(since)
    if until:
        clauses.append("at <= %s")
        args.append(until)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY at DESC, audit_uid DESC LIMIT %s"
    args.append(limit)
    rows = conn.execute(sql, args).fetchall()
    return [
        {
            "audit_uid": str(r[0]),
            "at": r[1].isoformat() if r[1] is not None else None,
            "principal": r[2],
            "action": r[3],
            "object_kind": r[4],
            "object_id": r[5],
            "outcome": r[6],
            "detail": dict(r[7] or {}),
        }
        for r in rows
    ]


def count_audit(
    conn: psycopg.Connection, *, action: str, outcome: str | None = None
) -> int:
    sql = "SELECT count(*) FROM audit_log WHERE action = %s"
    args: list[Any] = [action]
    if outcome:
        sql += " AND outcome = %s"
        args.append(outcome)
    row = conn.execute(sql, args).fetchone()
    return int(row[0]) if row else 0
