from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Query, Request

from sentinel_core.db import tx
from sentinel_core.errors import BadRequestError
from sentinel_core.rls import set_rls
from sentinel_storage.repos_audit import list_audit

from .auth import Principal, authenticate
from .routes_uploads import _check_workspace, _settings

router = APIRouter()


def _principal(request: Request) -> Principal:
    settings = _settings(request)
    return authenticate(settings, request.headers.get(settings.security_api_key_header))


def _iso(value: str | None, field: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise BadRequestError(f"{field} is not an ISO-8601 timestamp")


@router.get("/v1/workspaces/{workspaceId}/audit")
def list_audit_route(
    workspaceId: str,
    request: Request,
    action: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = Query(50, ge=1, le=1000),
    cursor: str | None = None,
):
    settings = _settings(request)
    principal = _principal(request)
    _check_workspace(principal, workspaceId)
    with tx(settings.database_url) as conn:
        set_rls(conn, principal.tenant_id, principal.workspace_id)
        items = list_audit(
            conn,
            action=action,
            since=_iso(since, "since"),
            until=_iso(until, "until"),
            limit=limit,
        )
    return {"items": items, "next": None}
