from __future__ import annotations

import argparse
import os
import socket
import threading
import time
import uuid
from typing import Any, Callable

from sentinel_core.config import Settings, load_settings
from sentinel_core.db import tx
from sentinel_core.logging import configure_logging, get_logger
from sentinel_ingest.worker_handlers import handle_detect_run, handle_ingest_file
from sentinel_storage import repos_jobs

log = get_logger("worker")

Handler = Callable[[Settings, repos_jobs.JobRow], dict[str, Any]]


def _handle_noop(settings: Settings, job: repos_jobs.JobRow) -> dict[str, Any]:
    return {"noop": True}


HANDLERS: dict[str, Handler] = {
    "ingest_file": handle_ingest_file,
    "detect_run": handle_detect_run,
    "noop": _handle_noop,
}


def _dsn(settings: Settings) -> str:
    return settings.worker_url or settings.database_url


def make_worker_id(settings: Settings) -> str:
    if settings.worker_id:
        return settings.worker_id
    return f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"


def process_batch(settings: Settings, worker_id: str) -> int:
    with tx(_dsn(settings)) as conn:
        jobs = repos_jobs.claim(
            conn, worker_id=worker_id, limit=settings.worker_claim_batch
        )
        conn.commit()
    if not jobs:
        return 0
    # One connection for the whole batch's finish updates: the M1 no-pool
    # design opens a fresh connection per tx(); batching finishes keeps the
    # connection churn proportional to batches, not jobs (port exhaustion
    # under soak load on Windows).
    failures: list[tuple[repos_jobs.JobRow, str]] = []
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
    with tx(_dsn(settings)) as conn:
        for job in jobs:
            err = next((e for j, e in failures if j.job_id == job.job_id), None)
            repos_jobs.finish(conn, job, success=err is None, error=err)
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
    configure_logging(settings.log_format)
    if args.once:
        worker_id = make_worker_id(settings)
        n = process_batch(settings, worker_id)
        log.info("worker.once_done", claimed=n)
        return
    run_forever(settings)


if __name__ == "__main__":
    main()
