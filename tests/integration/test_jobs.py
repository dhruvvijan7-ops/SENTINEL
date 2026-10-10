"""M1 exit ③: 10k jobs claimed exactly once under 8 concurrent workers."""
from __future__ import annotations

import threading
import uuid
from dataclasses import replace

import pytest

from sentinel_core.db import tx
from sentinel_storage import repos_jobs
from sentinel_worker.main import process_batch


@pytest.mark.slow
def test_10k_noop_jobs_exactly_once(migrated):
    total = 10_000
    tenant, ws = "default", "default"
    # Unique per invocation: a prior run's soak rows must not be recounted.
    run_token = uuid.uuid4().hex
    # Large claim batch: the M1 no-pool design opens a connection per tx();
    # a small batch would churn thousands of connections and exhaust
    # Windows ephemeral ports (observed as TIME_WAIT floods).
    settings = replace(migrated, worker_claim_batch=250)
    job_ids: list[str] = []

    with tx(settings.worker_url) as conn:
        for i in range(total):
            jid = repos_jobs.enqueue(
                conn,
                tenant_id=tenant,
                workspace_id=ws,
                job_type="noop",
                payload={"i": i},
                idempotency_key=f"exactly-once-test:{run_token}:{i}",
            )
            job_ids.append(str(jid))
        conn.commit()

    stop = threading.Event()
    errors: list[BaseException] = []

    def worker_loop(worker_no: int) -> None:
        wid = f"test-worker-{worker_no}"
        try:
            while not stop.is_set():
                n = process_batch(settings, wid)
                if n == 0:
                    with tx(settings.worker_url) as conn:
                        queued = conn.execute(
                            "SELECT count(*) FROM jobs WHERE status = 'queued'"
                        ).fetchone()
                    if int(queued[0]) == 0:
                        return
        except BaseException as exc:  # pragma: no cover - surfaced via pytest
            errors.append(exc)
            stop.set()

    threads = [threading.Thread(target=worker_loop, args=(i,), daemon=True) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=600)
        assert not t.is_alive(), "worker thread did not finish in time"

    assert not errors, f"worker errors: {errors[:3]}"

    with tx(migrated.worker_url) as conn:
        row = conn.execute(
            """
            SELECT count(*) AS jobs,
                   count(*) FILTER (WHERE status = 'succeeded') AS succeeded,
                   count(*) FILTER (WHERE status <> 'succeeded') AS not_ok
            FROM jobs WHERE job_type = 'noop' AND tenant_id = %s
              AND idempotency_key LIKE %s
            """,
            (tenant, f"exactly-once-test:{run_token}:%"),
        ).fetchone()
        jobs, succeeded, not_ok = int(row[0]), int(row[1]), int(row[2])
        assert jobs == total, f"expected {total} jobs, got {jobs}"
        assert not_ok == 0, f"{not_ok} jobs not succeeded"
        assert succeeded == total

        # exactly-once: no job has more than one attempt row
        dup = conn.execute(
            """
            SELECT count(*) FROM (
                SELECT ja.job_id FROM job_attempts ja
                JOIN jobs j ON j.job_id = ja.job_id
                WHERE j.job_type = 'noop' AND j.idempotency_key LIKE %s
                GROUP BY ja.job_id HAVING count(*) > 1
            ) d
            """,
            (f"exactly-once-test:{run_token}:%",),
        ).fetchone()
        assert int(dup[0]) == 0, "some jobs were attempted more than once"
