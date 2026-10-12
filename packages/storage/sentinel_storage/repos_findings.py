from __future__ import annotations

import uuid
from typing import Any, Mapping, Sequence

import psycopg
from psycopg.types.json import Json

_FINDING_COLUMNS = (
    "finding_uid, tenant_id, workspace_id, run_id, rule_id, rule_name, author, "
    "kind, severity, level_original, time_utc, host_hostname, user_name, "
    "detection_path, reason_codes, fingerprint, event_uids, evidence_snapshot, "
    "first_seen, last_seen, occurrence_count, triage_state"
)

_INSERT_SQL = f"""
    INSERT INTO findings (
        tenant_id, workspace_id, run_id, rule_id, rule_name, author, kind,
        severity, level_original, time_utc, host_hostname, user_name,
        detection_path, reason_codes, fingerprint, event_uids, evidence_snapshot
    ) VALUES (
        %(tenant_id)s, %(workspace_id)s, %(run_id)s, %(rule_id)s, %(rule_name)s,
        %(author)s, %(kind)s, %(severity)s, %(level_original)s, %(time_utc)s,
        %(host_hostname)s, %(user_name)s, %(detection_path)s, %(reason_codes)s,
        %(fingerprint)s, %(event_uids)s, %(evidence_snapshot)s
    )
    ON CONFLICT (tenant_id, workspace_id, rule_id, fingerprint, time_utc)
    DO NOTHING
    RETURNING finding_uid
"""

_SELECT_BY_KEY_SQL = f"""
    SELECT {_FINDING_COLUMNS} FROM findings
     WHERE tenant_id = %(tenant_id)s
       AND workspace_id = %(workspace_id)s
       AND rule_id = %(rule_id)s
       AND fingerprint = %(fingerprint)s
       AND time_utc = %(time_utc)s
"""

_BUMP_SQL = """
    UPDATE findings
       SET occurrence_count = occurrence_count + 1,
           last_seen = now(),
           run_id = %(run_id)s,
           event_uids = %(event_uids)s,
           evidence_snapshot = %(evidence_snapshot)s
     WHERE tenant_id = %(tenant_id)s
       AND workspace_id = %(workspace_id)s
       AND rule_id = %(rule_id)s
       AND fingerprint = %(fingerprint)s
       AND time_utc = %(time_utc)s
    RETURNING finding_uid
"""


def _row_to_dict(row: Sequence[Any]) -> dict[str, Any]:
    keys = _FINDING_COLUMNS.split(", ")
    out: dict[str, Any] = dict(zip(keys, row))
    out["finding_uid"] = str(out["finding_uid"])
    out["event_uids"] = [str(u) for u in (out["event_uids"] or [])]
    out["fingerprint"] = bytes(out["fingerprint"]).hex()
    return out


def upsert_finding(
    conn: psycopg.Connection,
    *,
    tenant_id: str,
    workspace_id: str,
    run_id: uuid.UUID,
    rule_id: uuid.UUID,
    rule_name: str,
    author: str,
    kind: str,
    severity: str,
    level_original: str | None,
    time_utc: Any,
    host_hostname: str | None,
    user_name: str | None,
    detection_path: str,
    reason_codes: Sequence[str],
    fingerprint: bytes,
    event_uids: Sequence[Any],
    evidence_snapshot: Mapping[str, Any],
) -> tuple[str, bool]:
    """Insert one finding.

    Returns ``(finding_uid, created)``.  Re-running ``finalize()`` for the same
    run is a no-op (idempotent under retry, spec §5); a *different* run
    re-asserting the same identity tuple bumps ``occurrence_count``.
    """
    params: dict[str, Any] = {
        "tenant_id": tenant_id,
        "workspace_id": workspace_id,
        "run_id": run_id,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "author": author,
        "kind": kind,
        "severity": severity,
        "level_original": level_original,
        "time_utc": time_utc,
        "host_hostname": host_hostname,
        "user_name": user_name,
        "detection_path": detection_path,
        "reason_codes": list(reason_codes),
        "fingerprint": fingerprint,
        "event_uids": list(event_uids),
        "evidence_snapshot": Json(dict(evidence_snapshot)),
    }
    row = conn.execute(_INSERT_SQL, params).fetchone()
    if row is not None:
        return str(row[0]), True

    key = {k: params[k] for k in ("tenant_id", "workspace_id", "rule_id", "fingerprint", "time_utc")}
    existing = conn.execute(_SELECT_BY_KEY_SQL, key).fetchone()
    if existing is None:
        # The conflicting row lives in a partition this statement did not see;
        # let the caller see the failure rather than silently dropping it.
        raise RuntimeError("findings conflict row not visible after ON CONFLICT DO NOTHING")

    existing_run = existing[3]
    if existing_run == run_id:
        return str(existing[0]), False

    bump = {
        "tenant_id": params["tenant_id"],
        "workspace_id": params["workspace_id"],
        "rule_id": params["rule_id"],
        "fingerprint": params["fingerprint"],
        "time_utc": params["time_utc"],
        "run_id": params["run_id"],
        "event_uids": params["event_uids"],
        "evidence_snapshot": params["evidence_snapshot"],
    }
    row = conn.execute(_BUMP_SQL, bump).fetchone()
    return (str(row[0]), False) if row else (str(existing[0]), False)


def get_finding(
    conn: psycopg.Connection,
    *,
    tenant_id: str,
    workspace_id: str,
    finding_uid: str | uuid.UUID,
) -> dict[str, Any] | None:
    row = conn.execute(
        f"SELECT {_FINDING_COLUMNS} FROM findings "
        "WHERE tenant_id = %s AND workspace_id = %s AND finding_uid = %s",
        (tenant_id, workspace_id, str(finding_uid)),
    ).fetchone()
    return _row_to_dict(row) if row else None


def list_findings(
    conn: psycopg.Connection,
    *,
    tenant_id: str,
    workspace_id: str,
    since: Any | None = None,
    until: Any | None = None,
    severity: str | None = None,
    rule_id: str | None = None,
    triage_state: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    sql = f"SELECT {_FINDING_COLUMNS} FROM findings WHERE tenant_id = %s AND workspace_id = %s"
    args: list[Any] = [tenant_id, workspace_id]
    if since is not None:
        sql += " AND time_utc >= %s"
        args.append(since)
    if until is not None:
        sql += " AND time_utc < %s"
        args.append(until)
    if severity:
        sql += " AND severity = %s"
        args.append(severity)
    if rule_id:
        sql += " AND rule_id = %s"
        args.append(rule_id)
    if triage_state:
        sql += " AND triage_state = %s"
        args.append(triage_state)
    sql += " ORDER BY time_utc DESC LIMIT %s OFFSET %s"
    args.extend([limit, offset])
    return [_row_to_dict(r) for r in conn.execute(sql, args).fetchall()]


def count_findings(
    conn: psycopg.Connection,
    *,
    tenant_id: str,
    workspace_id: str,
) -> int:
    row = conn.execute(
        "SELECT count(*) FROM findings WHERE tenant_id = %s AND workspace_id = %s",
        (tenant_id, workspace_id),
    ).fetchone()
    return int(row[0]) if row else 0


#: Frozen by ``openapi.yaml``'s ``Finding.triage_state`` enum.
TRIAGE_STATES: tuple[str, ...] = (
    "new",
    "acknowledged",
    "escalated",
    "resolved",
    "false_positive",
)


def set_triage_state(
    conn: psycopg.Connection,
    *,
    tenant_id: str,
    workspace_id: str,
    finding_uid: str | uuid.UUID,
    triage_state: str,
) -> dict[str, Any] | None:
    """Move a finding along the triage axis and return its new shape."""
    if triage_state not in TRIAGE_STATES:
        raise ValueError(f"unknown triage_state {triage_state!r}")
    row = conn.execute(
        f"UPDATE findings SET triage_state = %(triage_state)s "
        f" WHERE tenant_id = %(tenant_id)s"
        f"   AND workspace_id = %(workspace_id)s"
        f"   AND finding_uid = %(finding_uid)s"
        f" RETURNING {_FINDING_COLUMNS}",
        {
            "triage_state": triage_state,
            "tenant_id": tenant_id,
            "workspace_id": workspace_id,
            "finding_uid": str(finding_uid),
        },
    ).fetchone()
    return _row_to_dict(row) if row else None


def raw_object_for_finding(
    conn: psycopg.Connection,
    *,
    tenant_id: str,
    workspace_id: str,
    finding_uid: str | uuid.UUID,
) -> dict[str, Any] | None:
    """Backing CAS object of a finding's events, or ``None`` if unresolvable.

    ``None`` is the honest answer once the events themselves are gone: the
    snapshot in ``findings.evidence_snapshot`` is then the whole evidence of
    record (spec §1.5, reject-condition R1).
    """
    row = conn.execute(
        "SELECT DISTINCT ro.state, ro.sha256, ro.size "
        "  FROM findings f "
        "  JOIN events e ON e.tenant_id = f.tenant_id "
        "              AND e.workspace_id = f.workspace_id "
        "              AND e.event_uid = ANY (f.event_uids) "
        "  JOIN uploads u ON u.artifact_id = e.artifact_id "
        "  JOIN raw_objects ro ON ro.sha256 = u.sha256 "
        " WHERE f.tenant_id = %s AND f.workspace_id = %s AND f.finding_uid = %s",
        (tenant_id, workspace_id, str(finding_uid)),
    ).fetchone()
    if row is None:
        return None
    return {"raw_state": row[0], "sha256": bytes(row[1]).hex(), "size": int(row[2])}
