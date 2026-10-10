from __future__ import annotations

from typing import Any, Sequence

import psycopg

EVENT_INSERT_SQL = """
    INSERT INTO events (
        tenant_id, workspace_id, run_id, artifact_id,
        event_time_utc, event_time_state,
        event_category, event_type, event_action, event_outcome,
        event_severity, event_derived_by, classification,
        host_hostname, user_name, user_sid,
        source_format, source_parser, source_channel, source_provider,
        source_event_id, source_record_type, document
    ) VALUES (
        %(tenant_id)s, %(workspace_id)s, %(run_id)s, %(artifact_id)s,
        %(event_time_utc)s, %(event_time_state)s,
        %(event_category)s, %(event_type)s, %(event_action)s, %(event_outcome)s,
        %(event_severity)s, %(event_derived_by)s, %(classification)s,
        %(host_hostname)s, %(user_name)s, %(user_sid)s,
        %(source_format)s, %(source_parser)s, %(source_channel)s, %(source_provider)s,
        %(source_event_id)s, %(source_record_type)s, %(document)s
    )
"""

_CHUNK = 500


def bulk_insert(conn: psycopg.Connection, rows: Sequence[dict[str, Any]]) -> int:
    total = 0
    for start in range(0, len(rows), _CHUNK):
        chunk = rows[start : start + _CHUNK]
        with conn.cursor() as cur:
            cur.executemany(EVENT_INSERT_SQL, chunk)
            total += cur.rowcount if cur.rowcount and cur.rowcount > 0 else len(chunk)
    return total


def count_for_run(conn: psycopg.Connection, harvest_run_id: str) -> int:
    row = conn.execute(
        "SELECT count(*) FROM events WHERE run_id = %s", (harvest_run_id,)
    ).fetchone()
    return int(row[0]) if row else 0


def list_events(
    conn: psycopg.Connection,
    *,
    harvest_run_id: str | None = None,
    category: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    sql = "SELECT event_uid, ingest_time, document FROM events"
    conds: list[str] = []
    args: list[Any] = []
    if harvest_run_id:
        conds.append("run_id = %s")
        args.append(harvest_run_id)
    if category:
        conds.append("event_category = %s")
        args.append(category)
    if conds:
        sql += " WHERE " + " AND ".join(conds)
    sql += " ORDER BY ingest_time DESC LIMIT %s"
    args.append(limit)
    rows = conn.execute(sql, args).fetchall()
    return [
        {"event_uid": str(r[0]), "ingest_time": r[1], "document": r[2]} for r in rows
    ]
