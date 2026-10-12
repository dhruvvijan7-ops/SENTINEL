from __future__ import annotations

import random
import uuid
from dataclasses import dataclass
from typing import Any, Sequence

import psycopg
from psycopg.types.json import Json

RETRYABLE_STATUSES = ("failed", "dead", "cancelled")


@dataclass(frozen=True)
class JobRow:
    job_id: uuid.UUID
    job_type: str
    payload: dict[str, Any]
    tenant_id: str
    workspace_id: str
    attempts: int
    max_attempts: int
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
    max_attempts: int | None = None,
) -> uuid.UUID:
    cols = "tenant_id, workspace_id, job_type, payload, idempotency_key, priority"
    vals = "%s, %s, %s, %s, %s, %s"
    args: list[Any] = [
        tenant_id,
        workspace_id,
        job_type,
        Json(payload),
        idempotency_key,
        priority,
    ]
    if max_attempts is not None:
        cols += ", max_attempts"
        vals += ", %s"
        args.append(max_attempts)
    row = conn.execute(
        f"""
        INSERT INTO jobs ({cols})
        VALUES ({vals})
        ON CONFLICT (tenant_id, workspace_id, idempotency_key)
            WHERE idempotency_key IS NOT NULL
        DO UPDATE SET job_id = jobs.job_id
        RETURNING job_id
        """,
        args,
    ).fetchone()
    assert row is not None
    return row[0]


def claim(
    conn: psycopg.Connection,
    *,
    worker_id: str,
    limit: int = 1,
    job_types: Sequence[str] | None = None,
) -> list[JobRow]:
    """Claim up to `limit` queued jobs exactly once under concurrency
    (FOR UPDATE SKIP LOCKED — Stage-6 §2).

    `job_types` narrows the claim to specific handlers, so a specialised
    worker never steals a job it cannot run.
    """
    type_clause = "AND job_type = ANY(%s)" if job_types else ""
    params: list[Any] = [worker_id]
    if job_types:
        params.append(list(job_types))
    params.append(limit)
    rows = conn.execute(
        f"""
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
            {type_clause}
            ORDER BY priority, run_after
            FOR UPDATE SKIP LOCKED
            LIMIT %s
        )
        RETURNING job_id, job_type, payload, tenant_id, workspace_id,
                  attempts, max_attempts, locked_by
        """,
        params,
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
                max_attempts=r[6],
                locked_by=r[7],
            )
        )
    return out


def heartbeat(
    conn: psycopg.Connection, *, worker_id: str, job_ids: Sequence[uuid.UUID]
) -> int:
    """Refresh the lease on live jobs so the reaper leaves them alone."""
    if not job_ids:
        return 0
    return conn.execute(
        """
        UPDATE jobs SET heartbeat_at = now(), updated_at = now()
        WHERE job_id = ANY(%s) AND locked_by = %s AND status = 'running'
        """,
        (list(job_ids), worker_id),
    ).rowcount


def backoff_seconds(
    attempt: int,
    *,
    base_seconds: int,
    cap_seconds: int,
    rng: Any | None = None,
) -> float:
    """Full-jitter exponential backoff (Stage-6 §6.5): uniform(0, min(cap,
    base * 2**(attempt-1))).  Every attempt draws independently, so two jobs
    failing at the same attempt do not retry in lockstep."""
    source = random if rng is None else rng
    ceiling = float(min(cap_seconds, base_seconds * (2 ** max(attempt - 1, 0))))
    return source.uniform(0.0, ceiling)


def reap_stale_locks(
    conn: psycopg.Connection,
    *,
    lease_seconds: int,
    backoff_base_seconds: int,
    backoff_cap_seconds: int,
    rng: Any | None = None,
) -> dict[str, int]:
    """Reclaim `running` jobs whose heartbeat outlived the lease.

    Each reclaimed attempt is closed out as `lost_lock`; the job is re-queued
    with fresh backoff, or dead-lettered once `max_attempts` is spent.
    """
    stale = conn.execute(
        """
        SELECT job_id, attempts, max_attempts
        FROM jobs
        WHERE status = 'running'
          AND COALESCE(heartbeat_at, locked_at)
                < now() - make_interval(secs => %s)
        FOR UPDATE SKIP LOCKED
        """,
        (lease_seconds,),
    ).fetchall()
    requeued = dead = 0
    for job_id, attempts, max_attempts in stale:
        conn.execute(
            """
            UPDATE job_attempts
            SET finished_at = now(), outcome = 'lost_lock'
            WHERE job_id = %s AND attempt = %s AND outcome IS NULL
            """,
            (job_id, attempts),
        )
        if attempts >= max_attempts:
            conn.execute(
                """
                UPDATE jobs
                SET status = 'dead',
                    last_error = COALESCE(last_error, 'lease expired before completion'),
                    finished_at = now(), locked_by = NULL, locked_at = NULL,
                    heartbeat_at = NULL, updated_at = now()
                WHERE job_id = %s
                """,
                (job_id,),
            )
            dead += 1
        else:
            delay = backoff_seconds(
                attempts,
                base_seconds=backoff_base_seconds,
                cap_seconds=backoff_cap_seconds,
                rng=rng,
            )
            conn.execute(
                """
                UPDATE jobs
                SET status = 'queued',
                    run_after = now() + make_interval(secs => %s),
                    locked_by = NULL, locked_at = NULL, heartbeat_at = NULL,
                    updated_at = now()
                WHERE job_id = %s
                """,
                (delay, job_id),
            )
            requeued += 1
    return {"requeued": requeued, "dead": dead}


def finish(
    conn: psycopg.Connection,
    job: JobRow,
    *,
    success: bool,
    error: str | None = None,
    backoff_base_seconds: int = 5,
    backoff_cap_seconds: int = 900,
    rng: Any | None = None,
) -> str:
    """Close out one attempt and set the job's next state.

    The UPDATE is guarded by (job_id, locked_by, status='running'); a rowcount
    of zero means the lease was already reclaimed, so this caller must not
    overwrite the reaper's decision.  Returns `succeeded`, `queued` (retry
    scheduled), `dead` (attempts exhausted) or `lost_lock`.
    """
    if success:
        new_status = "succeeded"
        row = conn.execute(
            """
            UPDATE jobs
            SET status = 'succeeded', last_error = NULL, finished_at = now(),
                locked_by = NULL, locked_at = NULL, heartbeat_at = NULL,
                updated_at = now()
            WHERE job_id = %s AND locked_by = %s AND status = 'running'
            """,
            (job.job_id, job.locked_by),
        )
    elif job.attempts >= job.max_attempts:
        new_status = "dead"
        row = conn.execute(
            """
            UPDATE jobs
            SET status = 'dead', last_error = %s, finished_at = now(),
                locked_by = NULL, locked_at = NULL, heartbeat_at = NULL,
                updated_at = now()
            WHERE job_id = %s AND locked_by = %s AND status = 'running'
            """,
            (error, job.job_id, job.locked_by),
        )
    else:
        new_status = "queued"
        delay = backoff_seconds(
            job.attempts,
            base_seconds=backoff_base_seconds,
            cap_seconds=backoff_cap_seconds,
            rng=rng,
        )
        row = conn.execute(
            """
            UPDATE jobs
            SET status = 'queued', last_error = %s,
                run_after = now() + make_interval(secs => %s),
                locked_by = NULL, locked_at = NULL, heartbeat_at = NULL,
                updated_at = now()
            WHERE job_id = %s AND locked_by = %s AND status = 'running'
            """,
            (error, delay, job.job_id, job.locked_by),
        )

    if row.rowcount == 0:
        conn.execute(
            """
            UPDATE job_attempts
            SET finished_at = now(), outcome = 'lost_lock', error = %s
            WHERE job_id = %s AND attempt = %s AND outcome IS NULL
            """,
            (error or "lease lost before finish", job.job_id, job.attempts),
        )
        return "lost_lock"

    conn.execute(
        """
        UPDATE job_attempts
        SET finished_at = now(), outcome = %s, error = %s
        WHERE job_id = %s AND attempt = %s
        """,
        ("succeeded" if success else "failed", error, job.job_id, job.attempts),
    )
    return new_status


def retry(
    conn: psycopg.Connection,
    *,
    job_id: uuid.UUID,
    backoff_base_seconds: int = 0,
    backoff_cap_seconds: int = 0,
    rng: Any | None = None,
) -> str | None:
    """Operator dead-letter retry (Stage-6 §6.5).  Re-queues a `failed`,
    `dead` or `cancelled` job with a fresh attempt budget; returns the new
    status, or None when the job does not exist, or `active` when it is not
    in a retryable state.
    """
    row = conn.execute(
        "SELECT status, max_attempts FROM jobs WHERE job_id = %s", (job_id,)
    ).fetchone()
    if row is None:
        return None
    if row[0] not in RETRYABLE_STATUSES:
        return "active"
    delay = backoff_seconds(
        1,
        base_seconds=backoff_base_seconds,
        cap_seconds=backoff_cap_seconds,
        rng=rng,
    )
    conn.execute(
        """
        UPDATE jobs
        SET status = 'queued', run_after = now() + make_interval(secs => %s),
            attempts = 0, finished_at = NULL, locked_by = NULL, locked_at = NULL,
            heartbeat_at = NULL, updated_at = now()
        WHERE job_id = %s
        """,
        (delay, job_id),
    )
    return "queued"


def count_by_status(conn: psycopg.Connection) -> dict[str, int]:
    rows = conn.execute("SELECT status, count(*) FROM jobs GROUP BY status").fetchall()
    return {r[0]: int(r[1]) for r in rows}


def oldest_queued_age_seconds(conn: psycopg.Connection) -> float | None:
    row = conn.execute(
        "SELECT EXTRACT(EPOCH FROM (now() - min(created_at))) "
        "FROM jobs WHERE status = 'queued'"
    ).fetchone()
    if row is None or row[0] is None:
        return None
    return float(row[0])


def queue_depth(conn: psycopg.Connection) -> dict[str, dict[str, int]]:
    rows = conn.execute(
        """
        SELECT job_type,
               count(*) FILTER (WHERE status = 'queued'),
               count(*) FILTER (WHERE status = 'running')
        FROM jobs GROUP BY job_type
        """
    ).fetchall()
    return {r[0]: {"queued": int(r[1]), "running": int(r[2])} for r in rows}
