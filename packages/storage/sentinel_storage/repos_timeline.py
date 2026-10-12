from __future__ import annotations

from datetime import datetime
from typing import Any, Sequence

import psycopg

#: §9 M2 exit ③: "findings ∪ events for a host over a time window".
#:
#: Two deliberate index choices:
#:
#: * the events side is a ``UNION ALL`` of two branches rather than one
#:   ``COALESCE(...)`` predicate, because ``events`` is partitioned by
#:   ``ingest_time`` and indexed on ``(tenant, ws, event_time_utc)`` — a
#:   ``COALESCE`` in the predicate defeats *both* of them.  Branch 1 range-scans
#:   ``event_time_utc`` (the normal case), branch 2 catches rows whose
#:   ``event_time_state`` left ``event_time_utc`` NULL and prunes on
#:   ``ingest_time`` instead.  They cannot double-count: branch 2 requires NULL.
#: * ``findings`` is partitioned by ``time_utc`` and indexed on
#:   ``(tenant, ws, time_utc DESC)``, so the window prunes partitions directly.
_TIMELINE_SQL = """
    SELECT at, kind, uid, label, category, severity, event_severity,
           host_hostname, user_name
      FROM (
          SELECT COALESCE(e.event_time_utc, e.ingest_time) AS at,
                 'event'::text AS kind,
                 e.event_uid::text AS uid,
                 e.event_type AS label,
                 e.event_category AS category,
                 NULL::text AS severity,
                 e.event_severity AS event_severity,
                 e.host_hostname AS host_hostname,
                 e.user_name AS user_name
            FROM events e
           WHERE e.tenant_id = %(tenant_id)s
             AND e.workspace_id = %(workspace_id)s
             AND e.host_hostname = %(host)s
             AND ( (e.event_time_utc >= %(since)s AND e.event_time_utc < %(until)s)
                OR ( e.event_time_utc IS NULL
                 AND e.ingest_time >= %(since)s AND e.ingest_time < %(until)s) )
          UNION ALL
          SELECT f.time_utc AS at,
                 'finding'::text AS kind,
                 f.finding_uid::text AS uid,
                 f.rule_name AS label,
                 NULL::text AS category,
                 f.severity AS severity,
                 NULL::text AS event_severity,
                 f.host_hostname AS host_hostname,
                 f.user_name AS user_name
            FROM findings f
           WHERE f.tenant_id = %(tenant_id)s
             AND f.workspace_id = %(workspace_id)s
             AND f.host_hostname = %(host)s
             AND f.time_utc >= %(since)s
             AND f.time_utc < %(until)s
      ) u
     ORDER BY at, kind, uid
     LIMIT %(limit)s OFFSET %(offset)s
"""


def _iso(value: Any) -> Any:
    return value.isoformat() if isinstance(value, datetime) else value


def query_timeline(
    conn: psycopg.Connection,
    *,
    tenant_id: str,
    workspace_id: str,
    host: str,
    since: Any,
    until: Any,
    limit: int = 500,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """One host, one half-open window ``[since, until)``, oldest first.

    ``kind`` separates the two halves of the union: ``event`` rows carry
    ``event_severity`` (the Stage-2 vocabulary), ``finding`` rows carry
    ``severity`` (LOW/MEDIUM/HIGH).  They are kept in separate columns so no
    consumer ever has to guess which axis a value belongs to.
    """
    rows: Sequence[Any] = conn.execute(
        _TIMELINE_SQL,
        {
            "tenant_id": tenant_id,
            "workspace_id": workspace_id,
            "host": host,
            "since": since,
            "until": until,
            "limit": limit,
            "offset": offset,
        },
    ).fetchall()
    return [
        {
            "at": _iso(r[0]),
            "kind": r[1],
            "uid": r[2],
            "label": r[3],
            "category": r[4],
            "severity": r[5],
            "event_severity": r[6],
            "host_hostname": r[7],
            "user_name": r[8],
        }
        for r in rows
    ]
