from __future__ import annotations

import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from sentinel_core.db import tx
from sentinel_core.errors import NotFoundError
from sentinel_core.rls import set_rls
from sentinel_storage import repos_jobs
from sentinel_storage.repos_audit import insert_audit

from .auth import Principal, authenticate
from .routes_uploads import _settings, require_workspace

router = APIRouter()


def _principal(request: Request) -> Principal:
    settings = _settings(request)
    return authenticate(settings, request.headers.get(settings.security_api_key_header))


@router.post("/v1/workspaces/{workspaceId}/jobs/{jobId}", status_code=202)
def retry_job(workspaceId: str, jobId: str, request: Request):
    """Operator dead-letter retry (Stage-6 §6.5): re-queue a failed or dead
    job and record the action in ``audit_log``."""
    settings = _settings(request)
    principal = _principal(request)
    require_workspace(request, principal, workspaceId, action="job.retry")
    try:
        jid = uuid.UUID(jobId)
    except ValueError:
        raise NotFoundError("job not found")

    with tx(settings.database_url) as conn:
        set_rls(conn, principal.tenant_id, principal.workspace_id)
        previous = repos_jobs.retry(
            conn,
            job_id=jid,
            backoff_base_seconds=settings.jobs_backoff_base_seconds,
            backoff_cap_seconds=settings.jobs_backoff_cap_minutes * 60,
        )
        if previous is None:
            raise NotFoundError("job not found")
        if previous == "active":
            return JSONResponse(
                status_code=409,
                content={"message": "job is not in a retryable state"},
            )
        insert_audit(
            conn,
            tenant_id=principal.tenant_id,
            workspace_id=principal.workspace_id,
            principal=principal.principal_id,
            action="job.retry",
            object_kind="job",
            object_id=str(jid),
            outcome="ok",
            detail={"previous_status": previous, "requested_workspace": workspaceId},
        )
        conn.commit()
    return JSONResponse(
        status_code=202, content={"job_id": str(jid), "status": "queued"}
    )
