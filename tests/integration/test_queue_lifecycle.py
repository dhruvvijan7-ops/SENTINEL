"""Stage-6 §6.5 queue lifecycle: heartbeat, stale-lock reaper, backoff,
dead-letter, idempotency under race, and operator retry audit."""
from __future__ import annotations

import threading
import uuid
from dataclasses import replace

import pytest

from sentinel_core.db import tx
from sentinel_storage import repos_jobs

PROBE_PREFIX = "m1-probe:"
PROBE_TYPE = "m1_probe"


@pytest.fixture
def probe_settings(migrated):
    # Zero backoff so retry scheduling never sleeps in a test.
    return replace(migrated, jobs_backoff_base_seconds=0)


@pytest.fixture
def clean_probes(migrated):
    yield
    with tx(migrated.database_worker_url) as conn:
        conn.execute(
            "DELETE FROM jobs WHERE idempotency_key LIKE %s", (PROBE_PREFIX + "%",)
        )
        conn.commit()


def _enqueue(
    conn, *, job_type: str = PROBE_TYPE, max_attempts: int | None = None
) -> uuid.UUID:
    return repos_jobs.enqueue(
        conn,
        tenant_id="default",
        workspace_id="default",
        job_type=job_type,
        payload={"probe": True},
        idempotency_key=PROBE_PREFIX + uuid.uuid4().hex,
        max_attempts=max_attempts,
    )


def _job_row(dsn, job_id) -> dict:
    with tx(dsn) as conn:
        row = conn.execute(
            """
            SELECT status, attempts, max_attempts, locked_by, locked_at,
                   heartbeat_at, run_after, finished_at, last_error
            FROM jobs WHERE job_id = %s
            """,
            (job_id,),
        ).fetchone()
    assert row is not None, f"job {job_id} disappeared"
    keys = (
        "status",
        "attempts",
        "max_attempts",
        "locked_by",
        "locked_at",
        "heartbeat_at",
        "run_after",
        "finished_at",
        "last_error",
    )
    return dict(zip(keys, row))


def _attempt_outcomes(dsn, job_id) -> list[str]:
    with tx(dsn) as conn:
        rows = conn.execute(
            "SELECT outcome FROM job_attempts WHERE job_id = %s ORDER BY attempt",
            (job_id,),
        ).fetchall()
    return [r[0] for r in rows]


def test_claim_takes_a_lease_and_records_the_attempt(migrated, clean_probes):
    dsn = migrated.database_worker_url
    with tx(dsn) as conn:
        job_id = _enqueue(conn)
        conn.commit()
    with tx(dsn) as conn:
        jobs = repos_jobs.claim(
            conn, worker_id="w-claim", limit=5, job_types=(PROBE_TYPE,)
        )
        conn.commit()
    assert [j.job_id for j in jobs] == [job_id]
    job = jobs[0]
    assert job.attempts == 1
    assert job.max_attempts == 5
    row = _job_row(dsn, job_id)
    assert row["status"] == "running"
    assert row["locked_by"] == "w-claim"
    assert row["heartbeat_at"] is not None
    assert _attempt_outcomes(dsn, job_id) == [None]


def test_heartbeat_refreshes_only_the_holders_lease(migrated, clean_probes):
    dsn = migrated.database_worker_url
    with tx(dsn) as conn:
        job_id = _enqueue(conn)
        conn.commit()
        jobs = repos_jobs.claim(conn, worker_id="w-hb", limit=1, job_types=(PROBE_TYPE,))
        conn.commit()
    with tx(dsn) as conn:
        conn.execute(
            "UPDATE jobs SET heartbeat_at = now() - interval '10 minutes' WHERE job_id = %s",
            (job_id,),
        )
        conn.commit()
    stale = _job_row(dsn, job_id)["heartbeat_at"]

    with tx(dsn) as conn:
        assert repos_jobs.heartbeat(conn, worker_id="w-other", job_ids=[job_id]) == 0
        assert repos_jobs.heartbeat(conn, worker_id="w-hb", job_ids=[]) == 0
        assert repos_jobs.heartbeat(conn, worker_id="w-hb", job_ids=[job_id]) == 1
        conn.commit()

    assert _job_row(dsn, job_id)["heartbeat_at"] > stale
    assert jobs[0].job_id == job_id


def test_stale_running_job_is_requeued_with_backoff(migrated, clean_probes):
    dsn = migrated.database_worker_url
    with tx(dsn) as conn:
        job_id = _enqueue(conn)
        conn.commit()
        repos_jobs.claim(conn, worker_id="w-dead", limit=1, job_types=(PROBE_TYPE,))
        conn.commit()
        conn.execute(
            """
            UPDATE jobs
            SET locked_at = now() - interval '1 hour',
                heartbeat_at = now() - interval '1 hour'
            WHERE job_id = %s
            """,
            (job_id,),
        )
        conn.commit()

    with tx(dsn) as conn:
        counts = repos_jobs.reap_stale_locks(
            conn,
            lease_seconds=60,
            backoff_base_seconds=5,
            backoff_cap_seconds=900,
        )
        conn.commit()
    assert counts == {"requeued": 1, "dead": 0}

    row = _job_row(dsn, job_id)
    assert row["status"] == "queued"
    assert row["locked_by"] is None
    assert row["locked_at"] is None
    assert row["heartbeat_at"] is None
    assert row["attempts"] == 1
    assert row["finished_at"] is None
    assert row["run_after"].timestamp() >= row["run_after"].timestamp() - 1
    assert _attempt_outcomes(dsn, job_id) == ["lost_lock"]


def test_stale_job_dead_letters_once_attempts_are_spent(migrated, clean_probes):
    dsn = migrated.database_worker_url
    with tx(dsn) as conn:
        job_id = _enqueue(conn, max_attempts=1)
        conn.commit()
        repos_jobs.claim(conn, worker_id="w-dead", limit=1, job_types=(PROBE_TYPE,))
        conn.commit()
        conn.execute(
            """
            UPDATE jobs
            SET locked_at = now() - interval '1 hour',
                heartbeat_at = now() - interval '1 hour'
            WHERE job_id = %s
            """,
            (job_id,),
        )
        conn.commit()

    with tx(dsn) as conn:
        counts = repos_jobs.reap_stale_locks(
            conn,
            lease_seconds=60,
            backoff_base_seconds=5,
            backoff_cap_seconds=900,
        )
        conn.commit()
    assert counts == {"requeued": 0, "dead": 1}

    row = _job_row(dsn, job_id)
    assert row["status"] == "dead"
    assert row["finished_at"] is not None
    assert row["last_error"]
    assert _attempt_outcomes(dsn, job_id) == ["lost_lock"]


def test_fresh_running_jobs_survive_the_reaper(migrated, clean_probes):
    dsn = migrated.database_worker_url
    with tx(dsn) as conn:
        job_id = _enqueue(conn)
        conn.commit()
        repos_jobs.claim(conn, worker_id="w-live", limit=1, job_types=(PROBE_TYPE,))
        conn.commit()
        counts = repos_jobs.reap_stale_locks(
            conn,
            lease_seconds=3600,
            backoff_base_seconds=5,
            backoff_cap_seconds=900,
        )
        conn.commit()
    assert counts == {"requeued": 0, "dead": 0}
    assert _job_row(dsn, job_id)["status"] == "running"


def test_unhandled_job_type_retries_then_dead_letters(probe_settings, clean_probes):
    from sentinel_worker.main import make_worker_id, process_batch

    dsn = probe_settings.database_worker_url
    with tx(dsn) as conn:
        job_id = _enqueue(conn, job_type="m1_probe_unhandled", max_attempts=2)
        conn.commit()

    worker = make_worker_id(probe_settings)
    assert (
        process_batch(
            probe_settings, worker, job_types=("m1_probe_unhandled",)
        )
        == 1
    )
    row = _job_row(dsn, job_id)
    assert row["status"] == "queued", "first failure must schedule a retry"
    assert row["attempts"] == 1
    assert row["last_error"] and "unknown job_type" in row["last_error"]
    assert row["finished_at"] is None
    assert _attempt_outcomes(dsn, job_id) == ["failed"]

    assert (
        process_batch(
            probe_settings, worker, job_types=("m1_probe_unhandled",)
        )
        == 1
    )
    row = _job_row(dsn, job_id)
    assert row["status"] == "dead"
    assert row["attempts"] == 2
    assert row["finished_at"] is not None
    assert _attempt_outcomes(dsn, job_id) == ["failed", "failed"]


def test_finish_never_overwrites_a_stolen_lease(migrated, clean_probes):
    dsn = migrated.database_worker_url
    with tx(dsn) as conn:
        job_id = _enqueue(conn)
        conn.commit()
        [job] = repos_jobs.claim(
            conn, worker_id="w-owner", limit=1, job_types=(PROBE_TYPE,)
        )
        conn.execute(
            "UPDATE jobs SET locked_by = 'w-thief' WHERE job_id = %s", (job_id,)
        )
        conn.commit()

    with tx(dsn) as conn:
        outcome = repos_jobs.finish(conn, job, success=True)
        conn.commit()
    assert outcome == "lost_lock"

    row = _job_row(dsn, job_id)
    assert row["status"] == "running"
    assert row["locked_by"] == "w-thief"
    assert _attempt_outcomes(dsn, job_id) == ["lost_lock"]


def test_enqueue_is_unique_under_concurrent_race(migrated, clean_probes):
    dsn = migrated.database_worker_url
    key = PROBE_PREFIX + "race:" + uuid.uuid4().hex
    threads: list[threading.Thread] = []
    results: list[str] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def worker() -> None:
        try:
            for _ in range(10):
                with tx(dsn) as conn:
                    jid = repos_jobs.enqueue(
                        conn,
                        tenant_id="default",
                        workspace_id="default",
                        job_type=PROBE_TYPE,
                        payload={},
                        idempotency_key=key,
                    )
                    conn.commit()
                with lock:
                    results.append(str(jid))
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
        assert not t.is_alive()

    assert not errors, f"enqueue race raised: {errors[:3]}"
    assert len(results) == 80
    assert len(set(results)) == 1, "idempotency_key must resolve to one job"


def test_operator_retry_requeues_a_dead_job_and_writes_audit(
    client, migrated, clean_probes
):
    from ..keys import KEY_A

    dsn = migrated.database_worker_url
    with tx(dsn) as conn:
        job_id = _enqueue(conn, max_attempts=1)
        conn.commit()
        [job] = repos_jobs.claim(
            conn, worker_id="w-op", limit=1, job_types=(PROBE_TYPE,)
        )
        conn.commit()
        repos_jobs.finish(conn, job, success=False, error="boom")
        conn.commit()
    assert _job_row(dsn, job_id)["status"] == "dead"

    r = client.post(
        f"/v1/workspaces/default/jobs/{job_id}",
        headers={"X-API-Key": KEY_A},
    )
    assert r.status_code == 202, r.text
    assert r.json() == {"job_id": str(job_id), "status": "queued"}

    row = _job_row(dsn, job_id)
    assert row["status"] == "queued"
    assert row["attempts"] == 0
    assert row["finished_at"] is None

    from sentinel_storage.repos_audit import count_audit

    with tx(migrated.database_url) as conn:
        from sentinel_core.rls import set_rls

        set_rls(conn, "default", "default")
        assert (
            count_audit(conn, action="job.retry", outcome="ok") >= 1
        ), "operator retry must leave an audit row"


def test_operator_retry_conflicts_while_the_job_is_active(
    client, migrated, clean_probes
):
    from ..keys import KEY_A

    dsn = migrated.database_worker_url
    with tx(dsn) as conn:
        job_id = _enqueue(conn)
        conn.commit()
        repos_jobs.claim(conn, worker_id="w-op", limit=1, job_types=(PROBE_TYPE,))
        conn.commit()

    r = client.post(
        f"/v1/workspaces/default/jobs/{job_id}",
        headers={"X-API-Key": KEY_A},
    )
    assert r.status_code == 409, r.text
    assert _job_row(dsn, job_id)["status"] == "running"


def test_operator_retry_unknown_job_is_404(client, migrated):
    from ..keys import KEY_A

    r = client.post(
        f"/v1/workspaces/default/jobs/{uuid.uuid4()}",
        headers={"X-API-Key": KEY_A},
    )
    assert r.status_code == 404, r.text
