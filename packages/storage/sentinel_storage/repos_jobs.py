from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

import psycopg
from psycopg.types.json import Json


@dataclass(frozen=True)
class JobRow:
    job_id: uuid.UUID
    job_type: str
    payload: dict[str, Any]
    tenant_id: str
    workspace_id: str
    attempts: int
    locked_by: str


def enqueue(
    conn: psycopg.Connection,
    *,
    tenant_id: str,
    workspace_id: str,
    job_type: str,
    payload: dict[str, Any],
    idempotency_key: str | None = None,
    priority: int = 100,
) -> uuid.UUID:
    row = conn.execute(
        """
        INSERT INTO jobs (tenant_id, workspace_id, job_type, payload, idempotency_key, priority)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (tenant_id, workspace_id, idempotency_key)
            WHERE idempotency_key IS NOT NULL
        DO UPDATE SET job_id = jobs.job_id
        RETURNING job_id
        """,
        (tenant_id, workspace_id, job_type, Json(payload), idempotency_key, priority),
    ).fetchone()
    assert row is not None
    return row[0]


def claim(
    conn: psycopg.Connection, *, worker_id: str, limit: int = 1
) -> list[JobRow]:
    """Claim up to `limit` queued jobs exactly once under concurrency
    (FOR UPDATE SKIP LOCKED — Stage-6 §2)."""
    rows = conn.execute(
        """
        UPDATE jobs SET
            status = 'running',
            locked_by = %s,
            locked_at = now(),
            heartbeat_at = now(),
            attempts = attempts + 1,
            updated_at = now()
        WHERE job_id IN (
            SELECT job_id FROM jobs
            WHERE status = 'queued' AND run_after <= now()
            ORDER BY priority, run_after
            FOR UPDATE SKIP LOCKED
            LIMIT %s
        )
        RETURNING job_id, job_type, payload, tenant_id, workspace_id, attempts, locked_by
        """,
        (worker_id, limit),
    ).fetchall()
    out: list[JobRow] = []
    for r in rows:
        conn.execute(
            """
            INSERT INTO job_attempts (job_id, attempt, worker)
            VALUES (%s, %s, %s)
            ON CONFLICT (job_id, attempt) DO NOTHING
            """,
            (r[0], r[5], worker_id),
        )
        out.append(
            JobRow(
                job_id=r[0],
                job_type=r[1],
                payload=dict(r[2] or {}),
                tenant_id=r[3],
                workspace_id=r[4],
                attempts=r[5],
                locked_by=r[6],
            )
        )
    return out


def finish(
    conn: psycopg.Connection,
    job: JobRow,
    *,
    success: bool,
    error: str | None = None,
) -> None:
    status = "succeeded" if success else "failed"
    conn.execute(
        """
        UPDATE jobs
        SET status = %s, last_error = %s, finished_at = now(), updated_at = now()
        WHERE job_id = %s AND locked_by = %s AND status = 'running'
        """,
        (status, error, job.job_id, job.locked_by),
    )
    conn.execute(
        """
        UPDATE job_attempts
        SET finished_at = now(), outcome = %s, error = %s
        WHERE job_id = %s AND attempt = %s
        """,
        ("succeeded" if success else "failed", error, job.job_id, job.attempts),
    )


def count_by_status(conn: psycopg.Connection) -> dict[str, int]:
    rows = conn.execute("SELECT status, count(*) FROM jobs GROUP BY status").fetchall()
    return {r[0]: int(r[1]) for r in rows}
