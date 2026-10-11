"""Job handlers: ingest_file (EVTX → events) and detect_run (empty pack)."""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from sentinel_core.config import Settings
from sentinel_core.db import tx
from sentinel_core.logging import get_logger
from sentinel_core.rls import set_rls
from sentinel_detect.runner import run_detection
from sentinel_storage import repos_detect, repos_jobs, repos_uploads
from sentinel_storage.repos_events import bulk_insert

from .evtx_parser import ParseStats, iter_envelopes

log = get_logger("ingest.handlers")

_BATCH = 500


def _path_from_uri(uri: str) -> str:
    parsed = urlparse(uri)
    path = unquote(parsed.path)
    # Windows file:///C:/... → urlparse path is '/C:/...'; strip the leading
    # slash so open() sees a drive-letter path.
    if re.match(r"^/[A-Za-z]:[/\\]", path):
        path = path[1:]
    return path


def _event_row(
    envelope: dict[str, Any], *, tenant_id: str, workspace_id: str,
    artifact_id: uuid.UUID, harvest_run_id: str,
) -> dict[str, Any]:
    time_block = envelope["time"]
    event = envelope["event"]
    host = envelope.get("host") or {}
    user = envelope.get("user") or {}
    source = envelope["source"]
    record = source.get("record") or {}
    utc = time_block.get("utc")
    return {
        "tenant_id": tenant_id,
        "workspace_id": workspace_id,
        "run_id": harvest_run_id,
        "artifact_id": artifact_id,
        "event_time_utc": utc,
        "event_time_state": time_block.get("state", "unknown"),
        "event_category": event["category"],
        "event_type": event["type"],
        "event_action": event["action"] if isinstance(event["action"], str) else "unknown",
        "event_outcome": event["outcome"],
        "event_severity": event["severity"] if isinstance(event["severity"], str) else "informational",
        "event_derived_by": event["derived_by"],
        "classification": envelope.get("classification", "internal"),
        "host_hostname": host.get("hostname") if isinstance(host.get("hostname"), str) else None,
        "user_name": user.get("name") if isinstance(user.get("name"), str) else None,
        "user_sid": user.get("sid") if isinstance(user.get("sid"), str) else None,
        "source_format": source.get("format", "evtx"),
        "source_parser": source.get("parser", "evtx-canonical"),
        "source_channel": source.get("channel"),
        "source_provider": source.get("provider"),
        "source_event_id": str(source["event_id"]) if source.get("event_id") is not None else None,
        "source_record_type": record.get("type", "event_record"),
        "document": json.dumps(envelope),
    }


def _dsn(settings: Settings) -> str:
    # Workers run under the BYPASSRLS sentinel_worker role (platform
    # processor); handlers still set RLS vars explicitly for job scoping.
    return settings.database_worker_url or settings.database_url


def handle_ingest_file(settings: Settings, job: repos_jobs.JobRow) -> dict[str, Any]:
    artifact_id = uuid.UUID(str(job.payload["artifact_id"]))
    with tx(_dsn(settings)) as conn:
        set_rls(conn, job.tenant_id, job.workspace_id)
        meta = repos_uploads.get_upload_with_object(conn, artifact_id)
        if meta is None:
            raise RuntimeError(f"upload {artifact_id} not visible under RLS scope")
        path = _path_from_uri(meta["storage_uri"])
        harvest_run_id = meta["run_id"]
        repos_uploads.set_upload_triage_state(conn, artifact_id, "running")
        conn.commit()

    stats = ParseStats()
    batch: list[dict[str, Any]] = []
    inserted = 0
    for envelope in iter_envelopes(
        path,
        tenant_id=job.tenant_id,
        workspace_id=job.workspace_id,
        run_id=harvest_run_id,
        file_id=str(artifact_id),
        file_sha256=meta["sha256"],
        stats=stats,
    ):
        batch.append(
            _event_row(
                envelope,
                tenant_id=job.tenant_id,
                workspace_id=job.workspace_id,
                artifact_id=artifact_id,
                harvest_run_id=harvest_run_id,
            )
        )
        if len(batch) >= _BATCH:
            with tx(_dsn(settings)) as conn:
                set_rls(conn, job.tenant_id, job.workspace_id)
                inserted += bulk_insert(conn, batch)
            batch.clear()
    if batch:
        with tx(_dsn(settings)) as conn:
            set_rls(conn, job.tenant_id, job.workspace_id)
            inserted += bulk_insert(conn, batch)

    with tx(_dsn(settings)) as conn:
        set_rls(conn, job.tenant_id, job.workspace_id)
        repos_uploads.set_upload_triage_state(conn, artifact_id, "done")
        conn.commit()

    # M1 pipeline: ingest success auto-chains an empty-pack detect_run over the
    # same harvest run (documented chain; OpenAPI createRun covers manual runs).
    with tx(_dsn(settings)) as conn:
        set_rls(conn, job.tenant_id, job.workspace_id)
        requested_by = str(job.payload.get("requested_by") or "system:ingest")
        run_id = repos_detect.create_run(
            conn,
            tenant_id=job.tenant_id,
            workspace_id=job.workspace_id,
            requested_by=requested_by,
            scope={"harvest_run_id": harvest_run_id, "artifact_id": str(artifact_id)},
            config_hash=_empty_pack_config_hash(),
        )
        repos_jobs.enqueue(
            conn,
            tenant_id=job.tenant_id,
            workspace_id=job.workspace_id,
            job_type="detect_run",
            payload={"detection_run_id": str(run_id)},
            idempotency_key=f"detect:{run_id}",
        )
        conn.commit()

    summary = {
        "records_total": stats.records_total,
        "events_inserted": inserted,
        "unmapped_eid": stats.unmapped_eid,
        "parse_errors": stats.parse_errors,
        "detection_run_id": None,
    }
    if stats.events_mapped == 0:
        summary["warning"] = "NO_EVENTS_MAPPED"
    log.info("ingest_file.done", job_id=str(job.job_id), **summary)
    return summary


def _empty_pack_config_hash() -> bytes:
    from sentinel_detect.store import empty_pack_config_bytes

    import hashlib

    return hashlib.sha256(empty_pack_config_bytes()).digest()


def handle_detect_run(settings: Settings, job: repos_jobs.JobRow) -> dict[str, Any]:
    run_id = uuid.UUID(str(job.payload["detection_run_id"]))
    with tx(_dsn(settings)) as conn:
        set_rls(conn, job.tenant_id, job.workspace_id)
        row = repos_detect.get_run(conn, run_id)
        if row is None:
            raise RuntimeError(f"detection run {run_id} not visible")
        result = run_detection(
            conn,
            run_id=run_id,
            tenant_id=job.tenant_id,
            workspace_id=job.workspace_id,
            requested_by=row["requested_by"],
            scope=row["scope"] or {},
        )
        conn.commit()
    log.info("detect_run.done", job_id=str(job.job_id), **result)
    return result
