from __future__ import annotations

import uuid
from typing import Any

import psycopg
from psycopg.types.json import Json


def create_run(
    conn: psycopg.Connection,
    *,
    tenant_id: str,
    workspace_id: str,
    requested_by: str,
    scope: dict[str, Any],
    config_hash: bytes,
) -> uuid.UUID:
    row = conn.execute(
        """
        INSERT INTO detection_runs (tenant_id, workspace_id, requested_by, scope, status, config_hash)
        VALUES (%s, %s, %s, %s, 'queued', %s)
        RETURNING run_id
        """,
        (tenant_id, workspace_id, requested_by, Json(scope), config_hash),
    ).fetchone()
    assert row is not None
    return row[0]


def mark_running(conn: psycopg.Connection, run_id: uuid.UUID) -> None:
    conn.execute(
        "UPDATE detection_runs SET status = 'running', started_at = now() WHERE run_id = %s",
        (run_id,),
    )


def finish_run(
    conn: psycopg.Connection,
    run_id: uuid.UUID,
    *,
    status: str,
    summary: dict[str, Any],
) -> None:
    conn.execute(
        """
        UPDATE detection_runs
        SET status = %s, finished_at = now(), summary = %s
        WHERE run_id = %s
        """,
        (status, Json(summary), run_id),
    )


def get_run(conn: psycopg.Connection, run_id: uuid.UUID) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT run_id, status, scope, encode(config_hash, 'hex'),
               started_at, finished_at, summary, created_at, requested_by
        FROM detection_runs WHERE run_id = %s
        """,
        (run_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "run_id": str(row[0]),
        "status": row[1],
        "scope": row[2],
        "config_hash": row[3],
        "started_at": row[4],
        "finished_at": row[5],
        "summary": row[6],
        "created_at": row[7],
        "requested_by": row[8],
    }


def list_rule_runs(conn: psycopg.Connection, run_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT rule_id, outcome, findings, processed_events, rejected_events,
               detection_path, reason_codes, started_at, finished_at
        FROM rule_run WHERE run_id = %s
        ORDER BY started_at
        """,
        (run_id,),
    ).fetchall()
    return [
        {
            "run_id": str(run_id),
            "rule_id": str(r[0]),
            "outcome": r[1],
            "findings": r[2],
            "processed_events": r[3],
            "rejected_events": r[4],
            "detection_path": r[5],
            "reason_codes": list(r[6] or []),
            "started_at": r[7],
            "finished_at": r[8],
        }
        for r in rows
    ]


def count_rule_run(conn: psycopg.Connection, run_id: uuid.UUID) -> int:
    row = conn.execute(
        "SELECT count(*) FROM rule_run WHERE run_id = %s", (run_id,)
    ).fetchone()
    return int(row[0]) if row else 0


def count_findings_for_run(conn: psycopg.Connection, run_id: uuid.UUID) -> int:
    row = conn.execute(
        "SELECT count(*) FROM findings WHERE run_id = %s", (run_id,)
    ).fetchone()
    return int(row[0]) if row else 0


def list_runs(
    conn: psycopg.Connection, *, limit: int = 50
) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT run_id, status, created_at, finished_at
        FROM detection_runs ORDER BY created_at DESC LIMIT %s
        """,
        (limit,),
    ).fetchall()
    return [
        {
            "run_id": str(r[0]),
            "status": r[1],
            "created_at": r[2],
            "finished_at": r[3],
        }
        for r in rows
    ]
