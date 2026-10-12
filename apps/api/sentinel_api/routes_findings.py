from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Query, Request

from sentinel_core.db import tx
from sentinel_core.errors import BadRequestError, NotFoundError
from sentinel_core.rls import set_rls
from sentinel_storage import repos_findings

from .audit import write_audit
from .routes_uploads import _check_workspace, _settings, require_principal, require_workspace

router = APIRouter()

_SEVERITIES = ("LOW", "MEDIUM", "HIGH")


def _iso(value: Any) -> Any:
    return value.isoformat() if isinstance(value, datetime) else value


def _finding_body(row: dict[str, Any]) -> dict[str, Any]:
    """`openapi.yaml` → `components.schemas.Finding`, field for field."""
    return {
        "finding_uid": row["finding_uid"],
        "run_id": str(row["run_id"]) if row.get("run_id") else None,
        "rule_id": str(row["rule_id"]),
        "rule_name": row["rule_name"],
        "author": row["author"],
        "kind": row["kind"],
        "severity": row["severity"],
        "level_original": row["level_original"],
        "time_utc": _iso(row["time_utc"]),
        "host_hostname": row["host_hostname"],
        "user_name": row["user_name"],
        "detection_path": row["detection_path"],
        "reason_codes": list(row["reason_codes"] or []),
        "fingerprint": row["fingerprint"],
        "event_uids": list(row["event_uids"] or []),
        "evidence_snapshot": row["evidence_snapshot"],
        "first_seen": _iso(row["first_seen"]),
        "last_seen": _iso(row["last_seen"]),
        "occurrence_count": int(row["occurrence_count"]),
        "triage_state": row["triage_state"],
    }


def _instant(value: str | None, name: str) -> str | None:
    if value is None:
        return None
    try:
        datetime.fromisoformat(value)
    except ValueError:
        raise BadRequestError(f"{name} must be an RFC 3339 date-time")
    return value


@router.get("/v1/workspaces/{workspaceId}/findings")
def list_findings_route(
    workspaceId: str,
    request: Request,
    severity: str | None = None,
    rule_id: str | None = None,
    triage_state: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = Query(50, ge=1, le=1000),
):
    settings = _settings(request)
    principal = require_principal(request)
    _check_workspace(principal, workspaceId)
    if severity is not None and severity not in _SEVERITIES:
        raise BadRequestError(f"severity must be one of {list(_SEVERITIES)}")
    if triage_state is not None and triage_state not in repos_findings.TRIAGE_STATES:
        raise BadRequestError(
            f"triage_state must be one of {list(repos_findings.TRIAGE_STATES)}"
        )
    if rule_id is not None:
        try:
            uuid.UUID(rule_id)
        except ValueError:
            raise BadRequestError("rule_id must be a UUID")
    with tx(settings.database_url) as conn:
        set_rls(conn, principal.tenant_id, principal.workspace_id)
        rows = repos_findings.list_findings(
            conn,
            tenant_id=principal.tenant_id,
            workspace_id=principal.workspace_id,
            since=_instant(since, "since"),
            until=_instant(until, "until"),
            severity=severity,
            rule_id=rule_id,
            triage_state=triage_state,
            limit=limit,
        )
    return {"items": [_finding_body(r) for r in rows], "next": None}


@router.get("/v1/workspaces/{workspaceId}/findings/{findingUid}")
def get_finding(workspaceId: str, findingUid: str, request: Request):
    settings = _settings(request)
    principal = require_principal(request)
    _check_workspace(principal, workspaceId)
    try:
        fid = uuid.UUID(findingUid)
    except ValueError:
        raise NotFoundError("finding not found")
    with tx(settings.database_url) as conn:
        set_rls(conn, principal.tenant_id, principal.workspace_id)
        row = repos_findings.get_finding(
            conn,
            tenant_id=principal.tenant_id,
            workspace_id=principal.workspace_id,
            finding_uid=fid,
        )
    if row is None:
        raise NotFoundError("finding not found")
    return _finding_body(row)


@router.patch("/v1/workspaces/{workspaceId}/findings/{findingUid}")
async def update_finding_triage(workspaceId: str, findingUid: str, request: Request):
    settings = _settings(request)
    principal = require_principal(request)
    require_workspace(request, principal, workspaceId, action="finding.triage")
    try:
        fid = uuid.UUID(findingUid)
    except ValueError:
        raise NotFoundError("finding not found")

    try:
        body = await request.json()
    except ValueError as exc:
        raise BadRequestError(f"invalid JSON body: {exc}")
    if not isinstance(body, dict):
        raise BadRequestError("triage update must be a JSON object")
    triage_state = body.get("triage_state")
    if triage_state not in repos_findings.TRIAGE_STATES:
        raise BadRequestError(
            f"triage_state must be one of {list(repos_findings.TRIAGE_STATES)}"
        )
    note = body.get("note")
    if note is not None and (not isinstance(note, str) or len(note) > 4096):
        raise BadRequestError("note must be a string of at most 4096 characters")

    with tx(settings.database_url) as conn:
        set_rls(conn, principal.tenant_id, principal.workspace_id)
        row = repos_findings.set_triage_state(
            conn,
            tenant_id=principal.tenant_id,
            workspace_id=principal.workspace_id,
            finding_uid=fid,
            triage_state=triage_state,
        )
        if row is None:
            raise NotFoundError("finding not found")
        body_out = _finding_body(row)

    write_audit(
        settings,
        principal=principal,
        action="finding.triage",
        outcome="ok",
        object_kind="finding",
        object_id=str(fid),
        detail={"triage_state": triage_state, **({"note": note} if note else {})},
    )
    return body_out


@router.get("/v1/workspaces/{workspaceId}/evidence/{findingUid}")
def get_finding_evidence(workspaceId: str, findingUid: str, request: Request):
    """Spec §1.5 / reject-condition R1: the snapshot is *always* returned —
    the raw object's fate only changes whether a ``raw_object`` block rides
    along with it."""
    settings = _settings(request)
    principal = require_principal(request)
    _check_workspace(principal, workspaceId)
    try:
        fid = uuid.UUID(findingUid)
    except ValueError:
        raise NotFoundError("finding not found")
    with tx(settings.database_url) as conn:
        set_rls(conn, principal.tenant_id, principal.workspace_id)
        row = repos_findings.get_finding(
            conn,
            tenant_id=principal.tenant_id,
            workspace_id=principal.workspace_id,
            finding_uid=fid,
        )
        if row is None:
            raise NotFoundError("finding not found")
        raw = repos_findings.raw_object_for_finding(
            conn,
            tenant_id=principal.tenant_id,
            workspace_id=principal.workspace_id,
            finding_uid=fid,
        )
    bundle: dict[str, Any] = {
        "finding_uid": row["finding_uid"],
        "evidence_snapshot": row["evidence_snapshot"],
    }
    if raw is not None:
        bundle["raw_state"] = raw["raw_state"]
        if raw["raw_state"] == "hot":
            bundle["raw_object"] = {"sha256": raw["sha256"], "size": raw["size"]}
    return bundle
