from __future__ import annotations

import argparse
import os
import socket
import threading
import time
import uuid
from typing import Any, Callable, Sequence

from sentinel_core.config import Settings, log_effective_config, load_settings
from sentinel_core.db import tx
from sentinel_core.logging import configure_logging, get_logger
from sentinel_ingest.worker_handlers import handle_detect_run, handle_ingest_file
from sentinel_storage import repos_jobs

log = get_logger("worker")

Handler = Callable[[Settings, repos_jobs.JobRow], dict[str, Any]]

PIPELINE_JOB_TYPES: tuple[str, ...] = ("ingest_file", "detect_run")


def _handle_noop(settings: Settings, job: repos_jobs.JobRow) -> dict[str, Any]:
    return {"noop": True}


HANDLERS: dict[str, Handler] = {
    "ingest_file": handle_ingest_file,
    "detect_run": handle_detect_run,
    "noop": _handle_noop,
}


def _dsn(settings: Settings) -> str:
    return settings.database_worker_url or settings.database_url


def make_worker_id(settings: Settings) -> str:
    if settings.jobs_worker_id:
        return settings.jobs_worker_id
    return f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"


def backoff_cap_seconds(settings: Settings) -> int:
    return settings.jobs_backoff_cap_minutes * 60


def _heartbeat_loop(
    settings: Settings,
    worker_id: str,
    job_ids: list[uuid.UUID],
    stop: threading.Event,
) -> None:
    interval = max(1.0, float(settings.jobs_heartbeat_seconds))
    while not stop.wait(interval):
        try:
            with tx(_dsn(settings)) as conn:
                repos_jobs.heartbeat(conn, worker_id=worker_id, job_ids=job_ids)
                conn.commit()
        except Exception as exc:  # a lost beat is recoverable; the reaper decides
            log.warning("job.heartbeat_failed", worker_id=worker_id, error=str(exc))


class Heartbeater:
    """Refreshes the lease of every in-flight job for the lifetime of a batch."""

    def __init__(
        self, settings: Settings, worker_id: str, job_ids: list[uuid.UUID]
    ) -> None:
        self._stop = threading.Event()
        self._job_ids = job_ids
        self._thread = threading.Thread(
            target=_heartbeat_loop,
            args=(settings, worker_id, job_ids, self._stop),
            daemon=True,
            name="sentinel-heartbeat",
        )

    def __enter__(self) -> Heartbeater:
        if self._job_ids:
            self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=5.0)


_reap_lock = threading.Lock()
_reap_last = 0.0


def reap_once(settings: Settings) -> dict[str, int]:
    """Run the stale-lock reaper immediately (Stage-6 §6.5)."""
    with tx(_dsn(settings)) as conn:
        counts = repos_jobs.reap_stale_locks(
            conn,
            lease_seconds=settings.jobs_lease_seconds,
            backoff_base_seconds=settings.jobs_backoff_base_seconds,
            backoff_cap_seconds=backoff_cap_seconds(settings),
        )
        conn.commit()
    return counts


def _maybe_reap(settings: Settings) -> None:
    """Rate-limited reaper: at most one pass per half-lease, one thread at a
    time, so a busy pool does not stampede the jobs table."""
    global _reap_last
    if not _reap_lock.acquire(blocking=False):
        return
    try:
        now = time.monotonic()
        if now - _reap_last < max(1.0, settings.jobs_lease_seconds / 2.0):
            return
        _reap_last = now
        counts = reap_once(settings)
        if counts["requeued"] or counts["dead"]:
            log.warning("queue.reaped", **counts)
    except Exception as exc:
        log.warning("queue.reap_failed", error=str(exc))
    finally:
        _reap_lock.release()


def process_batch(
    settings: Settings,
    worker_id: str,
    *,
    job_types: Sequence[str] | None = None,
) -> int:
    _maybe_reap(settings)
    with tx(_dsn(settings)) as conn:
        jobs = repos_jobs.claim(
            conn,
            worker_id=worker_id,
            limit=settings.jobs_claim_concurrency,
            job_types=job_types,
        )
        conn.commit()
    if not jobs:
        return 0
    # One connection for the whole batch's finish updates: the M1 no-pool
    # design opens a fresh connection per tx(); batching finishes keeps the
    # connection churn proportional to batches, not jobs (port exhaustion
    # under soak load on Windows).
    failures: list[tuple[repos_jobs.JobRow, str]] = []
    with Heartbeater(settings, worker_id, [job.job_id for job in jobs]):
        for job in jobs:
            handler = HANDLERS.get(job.job_type)
            try:
                if handler is None:
                    raise RuntimeError(f"unknown job_type {job.job_type!r}")
                handler(settings, job)
            except Exception as exc:
                log.error(
                    "job.failed",
                    job_id=str(job.job_id),
                    job_type=job.job_type,
                    error=str(exc),
                )
                failures.append((job, str(exc)))
    cap = backoff_cap_seconds(settings)
    with tx(_dsn(settings)) as conn:
        for job in jobs:
            err = next((e for j, e in failures if j.job_id == job.job_id), None)
            outcome = repos_jobs.finish(
                conn,
                job,
                success=err is None,
                error=err,
                backoff_base_seconds=settings.jobs_backoff_base_seconds,
                backoff_cap_seconds=cap,
            )
            if outcome in ("queued", "dead", "lost_lock"):
                log.warning(
                    "job.retry_scheduled" if outcome == "queued" else "job.dead_letter",
                    job_id=str(job.job_id),
                    job_type=job.job_type,
                    outcome=outcome,
                    attempts=job.attempts,
                    max_attempts=job.max_attempts,
                    error=err,
                )
        conn.commit()
    return len(jobs)


def run_forever(
    settings: Settings,
    *,
    stop: threading.Event | None = None,
    idle_exit_after_polls: int | None = None,
) -> None:
    worker_id = make_worker_id(settings)
    idle_polls = 0
    log.info("worker.start", worker_id=worker_id)
    while stop is None or not stop.is_set():
        n = process_batch(settings, worker_id)
        if n == 0:
            idle_polls += 1
            if idle_exit_after_polls is not None and idle_polls >= idle_exit_after_polls:
                log.info("worker.idle_exit", worker_id=worker_id)
                return
            time.sleep(settings.worker_poll_interval_ms / 1000.0)
        else:
            idle_polls = 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinel-worker")
    parser.add_argument("--once", action="store_true", help="process one batch and exit")
    args = parser.parse_args()
    settings = load_settings()
    configure_logging(
        settings.observability_log_format, settings.observability_log_level
    )
    log_effective_config(settings)
    if args.once:
        worker_id = make_worker_id(settings)
        n = process_batch(settings, worker_id)
        log.info("worker.once_done", claimed=n)
        return
    run_forever(settings)


if __name__ == "__main__":
    main()
