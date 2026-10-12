from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from sentinel_core.config import Settings
from sentinel_core.db import tx
from sentinel_core.errors import (
    GateError,
    GateTenantMismatch,
    NotFoundError,
)
from sentinel_core.rls import set_rls
from sentinel_storage import repos_uploads
from sentinel_storage.repos_events import list_events

from .auth import Principal, authenticate

router = APIRouter()


def _settings(request: Request) -> Settings:
    return request.app.state.settings


def require_principal(request: Request) -> Principal:
    settings = _settings(request)
    header = request.headers.get(settings.security_api_key_header)
    return authenticate(settings, header)


def _check_workspace(principal: Principal, workspace_id: str) -> None:
    if workspace_id != principal.workspace_id:
        raise GateTenantMismatch(
            "principal is not scoped to this workspace",
            details={"workspace_id": workspace_id},
        )


def require_workspace(request: Request, principal: Principal, workspace_id: str, *, action: str) -> None:
    """Workspace check for mutating endpoints: a denied attempt is itself an
    audit event (Stage-6 §5.4, denied attempts included)."""
    if workspace_id == principal.workspace_id:
        return
    from .audit import write_audit

    write_audit(
        _settings(request),
        principal=principal,
        action=action,
        outcome="denied",
        object_kind="workspace",
        object_id=workspace_id,
        detail={"code": "GATE_TENANT_MISMATCH", "requested_workspace": workspace_id},
    )
    raise GateTenantMismatch(
        "principal is not scoped to this workspace",
        details={"workspace_id": workspace_id},
    )


@router.post("/v1/workspaces/{workspaceId}/uploads", status_code=202)
async def create_upload(request: Request, workspaceId: str) -> JSONResponse:
    settings = _settings(request)
    principal = require_principal(request)
    require_workspace(request, principal, workspaceId, action="upload.reject")

    from sentinel_ingest.gate import PrincipalLimiter, check_storage_quota
    from sentinel_ingest.store import LocalObjectStore
    from sentinel_storage.repos_jobs import enqueue
    from .metrics import UPLOADS_ACCEPTED, UPLOADS_REJECTED

    limiter: PrincipalLimiter = request.app.state.limiter
    limiter.acquire(principal.principal_id)
    deadline = time.monotonic() + settings.ingest_gate_timeout_seconds
    try:
        form = await request.form()
        file_parts = [
            (key, value)
            for key, value in form.multi_items()
            if hasattr(value, "read")
        ]
        if not file_parts:
            from sentinel_core.errors import GateEmptyFile

            raise GateEmptyFile("multipart body must contain exactly one file part")
        if len(file_parts) > 1:
            from sentinel_core.errors import GateTooManyFiles

            raise GateTooManyFiles(
                "exactly one file part allowed", details={"files": len(file_parts)}
            )
        _field, upload = file_parts[0]
        fields: dict[str, str] = {}
        for key, value in form.multi_items():
            if hasattr(value, "read"):
                continue
            raw = str(value)
            if len(raw.encode()) > settings.ingest_max_field_bytes:
                from sentinel_core.errors import GateFieldTooLarge

                raise GateFieldTooLarge(
                    f"field {key} exceeds limit", details={"field": key}
                )
            fields[key] = raw

        def _check_deadline() -> None:
            if time.monotonic() > deadline:
                from sentinel_core.errors import GateTimeout

                raise GateTimeout("gate wall-clock timeout")

        _check_deadline()
        store = LocalObjectStore(settings.storage_root)
        sha256_hex, size, uri, sha1_hex, md5_hex = store.write_stream(
            upload.file, max_bytes=settings.ingest_max_file_bytes
        )
        _check_deadline()

        run_id = fields.get("run_id") or f"run-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{sha256_hex[:8]}"
        idem_key = request.headers.get("Idempotency-Key")

        from sentinel_storage.repos_idempotency import get_key, put_key

        with tx(settings.database_url) as conn:
            set_rls(conn, principal.tenant_id, principal.workspace_id)
            check_storage_quota(
                repos_uploads.workspace_stored_bytes(conn), settings.ingest_storage_quota_bytes
            )
            if idem_key:
                existing = get_key(conn, principal.principal_id, idem_key)
                if existing is not None:
                    if existing["request_hash"] == bytes.fromhex(sha256_hex):
                        return JSONResponse(
                            status_code=existing["response_code"],
                            content=existing["response_body"],
                        )
                    from sentinel_core.errors import GateIdempotencyMismatch

                    raise GateIdempotencyMismatch(
                        "Idempotency-Key reused with a different body"
                    )

            from datetime import datetime, timedelta, timezone

            retention_until = datetime.now(timezone.utc) + timedelta(
                days=settings.retention_raw_days
            )
            repos_uploads.insert_raw_object(
                conn,
                sha256_hex=sha256_hex,
                size=size,
                storage_uri=uri,
                retention_until=retention_until,
            )
            upload_row = repos_uploads.insert_upload(
                conn,
                tenant_id=principal.tenant_id,
                workspace_id=principal.workspace_id,
                run_id=run_id,
                sha256_hex=sha256_hex,
                sha1_hex=sha1_hex,
                md5_hex=md5_hex,
                size=size,
                original_filename=upload.filename or "upload",
                display_name=(upload.filename or "upload")[:255],
                agent_id=fields.get("agent_id"),
                collection_kind=fields.get("collection_kind"),
                source_path=fields.get("source_path"),
                motw_zone_id=int(fields["motw_zone_id"]) if fields.get("motw_zone_id") else None,
                motw_referrer_url=fields.get("motw_referrer_url"),
            )
            enqueue(
                conn,
                tenant_id=principal.tenant_id,
                workspace_id=principal.workspace_id,
                job_type="ingest_file",
                payload={
                    "artifact_id": upload_row["artifact_id"],
                    "requested_by": principal.principal_id,
                },
                idempotency_key=f"ingest:{upload_row['artifact_id']}",
            )
            from sentinel_storage.repos_audit import insert_audit

            insert_audit(
                conn,
                tenant_id=principal.tenant_id,
                workspace_id=principal.workspace_id,
                principal=principal.principal_id,
                action="upload.accept",
                object_kind="upload",
                object_id=upload_row["artifact_id"],
                outcome="ok",
                detail={"sha256": sha256_hex, "size": size},
            )
            body = _upload_response_body(upload_row)
            if idem_key:
                put_key(
                    conn,
                    principal_id=principal.principal_id,
                    key=idem_key,
                    request_hash=bytes.fromhex(sha256_hex),
                    response_code=202,
                    response_body=body,
                )
            conn.commit()
        UPLOADS_ACCEPTED.inc()
        return JSONResponse(status_code=202, content=body)
    except GateError as exc:
        from .audit import write_audit

        UPLOADS_REJECTED.labels(exc.code).inc()
        write_audit(
            settings,
            principal=principal,
            action="upload.reject",
            outcome="denied",
            object_kind="upload",
            detail={"code": exc.code, "message": exc.message},
        )
        headers = {}
        if exc.code == "GATE_RATE_LIMITED":
            headers = {
                "RateLimit-Limit": str(settings.ingest_upload_hourly_quota_per_principal),
                "RateLimit-Remaining": "0",
                "RateLimit-Reset": "3600",
            }
        return JSONResponse(status_code=exc.status, content=exc.body(), headers=headers)
    finally:
        limiter.release(principal.principal_id)


def _upload_response_body(row: dict) -> dict:
    from datetime import datetime

    received = row["received_at"]
    if isinstance(received, datetime):
        received = received.isoformat()
    return {
        "artifact_id": row["artifact_id"],
        "run_id": row["run_id"],
        "sha256": row["sha256"],
        "sha1": row["sha1"],
        "md5": row["md5"],
        "size": row["size"],
        "display_name": row["display_name"],
        "collection_kind": row.get("collection_kind"),
        "agent_id": row.get("agent_id"),
        "received_at": received,
        "gate_warnings": row.get("gate_warnings", []),
        "triage_state": row["triage_state"],
    }


@router.get("/v1/workspaces/{workspaceId}/uploads/{artifactId}")
def get_upload(workspaceId: str, artifactId: str, request: Request):
    settings = _settings(request)
    principal = require_principal(request)
    _check_workspace(principal, workspaceId)
    import uuid as _uuid

    try:
        aid = _uuid.UUID(artifactId)
    except ValueError:
        raise NotFoundError("upload not found")
    with tx(settings.database_url) as conn:
        set_rls(conn, principal.tenant_id, principal.workspace_id)
        row = repos_uploads.get_upload(conn, aid)
    if row is None:
        raise NotFoundError("upload not found")
    return _upload_response_body(row)


@router.get("/v1/workspaces/{workspaceId}/uploads")
def list_uploads(
    workspaceId: str,
    request: Request,
    run_id: str | None = None,
    limit: int = Query(50, ge=1, le=1000),
):
    settings = _settings(request)
    principal = require_principal(request)
    _check_workspace(principal, workspaceId)
    with tx(settings.database_url) as conn:
        set_rls(conn, principal.tenant_id, principal.workspace_id)
        sql = (
            "SELECT artifact_id, run_id, received_at, triage_state, display_name, "
            "size, sha256, sha1, md5, gate_warnings, agent_id, collection_kind "
            "FROM uploads"
        )
        args: list = []
        if run_id:
            sql += " WHERE run_id = %s"
            args.append(run_id)
        sql += " ORDER BY received_at DESC LIMIT %s"
        args.append(limit)
        rows = conn.execute(sql, args).fetchall()
    items = []
    for r in rows:
        items.append(
            _upload_response_body(
                {
                    "artifact_id": str(r[0]),
                    "run_id": r[1],
                    "received_at": r[2],
                    "triage_state": r[3],
                    "display_name": r[4],
                    "size": r[5],
                    "sha256": r[6].hex() if r[6] else None,
                    "sha1": r[7].hex() if r[7] else None,
                    "md5": r[8].hex() if r[8] else None,
                    "gate_warnings": list(r[9] or []),
                    "agent_id": r[10],
                    "collection_kind": r[11],
                }
            )
        )
    return {"items": items, "next": None}


@router.get("/v1/workspaces/{workspaceId}/events")
def list_events_route(
    workspaceId: str,
    request: Request,
    run_id: str | None = None,
    category: str | None = None,
    limit: int = Query(50, ge=1, le=1000),
):
    settings = _settings(request)
    principal = require_principal(request)
    _check_workspace(principal, workspaceId)
    with tx(settings.database_url) as conn:
        set_rls(conn, principal.tenant_id, principal.workspace_id)
        items = list_events(
            conn, harvest_run_id=run_id, category=category, limit=limit
        )
    return {"items": items, "next": None}
