from __future__ import annotations

import hashlib
import json
import time
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from sentinel_core.db import tx
from sentinel_core.errors import BadRequestError, GateIdempotencyMismatch, NotFoundError
from sentinel_core.rls import set_rls
from sentinel_detect.store import empty_pack_config_bytes
from sentinel_storage import repos_detect
from sentinel_storage.repos_idempotency import get_key, put_key
from sentinel_storage.repos_jobs import enqueue

from .auth import Principal, authenticate
from .routes_uploads import _check_workspace, _settings

router = APIRouter()


def _principal(request: Request) -> Principal:
    settings = _settings(request)
    return authenticate(settings, request.headers.get(settings.security_api_key_header))


def _run_body(row: dict) -> dict:
    from datetime import datetime

    def _iso(v):
        return v.isoformat() if isinstance(v, datetime) else v

    return {
        "run_id": row["run_id"],
        "status": row["status"],
        "scope": row.get("scope"),
        "config_hash": row.get("config_hash"),
        "started_at": _iso(row.get("started_at")),
        "finished_at": _iso(row.get("finished_at")),
        "summary": row.get("summary"),
        "created_at": _iso(row.get("created_at")),
    }


@router.post("/v1/workspaces/{workspaceId}/runs", status_code=202)
async def create_run(workspaceId: str, request: Request):
    settings = _settings(request)
    principal = _principal(request)
    _check_workspace(principal, workspaceId)
    body_bytes = await request.body()
    try:
        scope = json.loads(body_bytes) if body_bytes else {}
    except json.JSONDecodeError as exc:
        raise BadRequestError(f"invalid JSON body: {exc}")
    if not isinstance(scope, dict):
        raise BadRequestError("RunRequest must be a JSON object")
    idem_key = request.headers.get("Idempotency-Key")
    request_hash = hashlib.sha256(body_bytes).digest()
    config_hash = hashlib.sha256(empty_pack_config_bytes()).digest()

    with tx(settings.database_url) as conn:
        set_rls(conn, principal.tenant_id, principal.workspace_id)
        if idem_key:
            existing = get_key(conn, principal.principal_id, idem_key)
            if existing is not None:
                if existing["request_hash"] == request_hash:
                    return JSONResponse(
                        status_code=existing["response_code"],
                        content=existing["response_body"],
                    )
                raise GateIdempotencyMismatch(
                    "Idempotency-Key reused with a different body"
                )
        run_id = repos_detect.create_run(
            conn,
            tenant_id=principal.tenant_id,
            workspace_id=principal.workspace_id,
            requested_by=principal.principal_id,
            scope=scope,
            config_hash=config_hash,
        )
        enqueue(
            conn,
            tenant_id=principal.tenant_id,
            workspace_id=principal.workspace_id,
            job_type="detect_run",
            payload={"detection_run_id": str(run_id)},
            idempotency_key=f"detect:{run_id}",
        )
        row = repos_detect.get_run(conn, run_id)
        assert row is not None
        body = _run_body(row)
        if idem_key:
            put_key(
                conn,
                principal_id=principal.principal_id,
                key=idem_key,
                request_hash=request_hash,
                response_code=202,
                response_body=body,
            )
        conn.commit()
    return JSONResponse(status_code=202, content=body)


@router.get("/v1/workspaces/{workspaceId}/runs")
def list_runs(workspaceId: str, request: Request, limit: int = 50):
    settings = _settings(request)
    principal = _principal(request)
    _check_workspace(principal, workspaceId)
    with tx(settings.database_url) as conn:
        set_rls(conn, principal.tenant_id, principal.workspace_id)
        rows = repos_detect.list_runs(conn, limit=min(limit, 1000))
    return {"items": rows, "next": None}


@router.get("/v1/workspaces/{workspaceId}/runs/{runId}")
def get_run(workspaceId: str, runId: str, request: Request):
    settings = _settings(request)
    principal = _principal(request)
    _check_workspace(principal, workspaceId)
    try:
        rid = uuid.UUID(runId)
    except ValueError:
        raise NotFoundError("run not found")
    with tx(settings.database_url) as conn:
        set_rls(conn, principal.tenant_id, principal.workspace_id)
        row = repos_detect.get_run(conn, rid)
    if row is None:
        raise NotFoundError("run not found")
    return _run_body(row)


@router.get("/v1/workspaces/{workspaceId}/runs/{runId}/rule-runs")
def list_rule_runs(workspaceId: str, runId: str, request: Request):
    settings = _settings(request)
    principal = _principal(request)
    _check_workspace(principal, workspaceId)
    try:
        rid = uuid.UUID(runId)
    except ValueError:
        raise NotFoundError("run not found")
    with tx(settings.database_url) as conn:
        set_rls(conn, principal.tenant_id, principal.workspace_id)
        if repos_detect.get_run(conn, rid) is None:
            raise NotFoundError("run not found")
        items = repos_detect.list_rule_runs(conn, rid)
    return {"items": items, "next": None}
