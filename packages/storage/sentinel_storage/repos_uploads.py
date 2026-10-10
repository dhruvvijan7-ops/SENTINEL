from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import psycopg


def insert_raw_object(
    conn: psycopg.Connection,
    *,
    sha256_hex: str,
    size: int,
    storage_uri: str,
    retention_until: datetime,
) -> None:
    conn.execute(
        """
        INSERT INTO raw_objects (sha256, size, storage_uri, retention_until)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (sha256) DO UPDATE SET
            refcount = raw_objects.refcount + 1,
            storage_uri = EXCLUDED.storage_uri,
            retention_until = GREATEST(raw_objects.retention_until, EXCLUDED.retention_until)
        """,
        (bytes.fromhex(sha256_hex), size, storage_uri, retention_until),
    )


def insert_upload(
    conn: psycopg.Connection,
    *,
    tenant_id: str,
    workspace_id: str,
    run_id: str,
    sha256_hex: str,
    sha1_hex: str | None,
    md5_hex: str | None,
    size: int,
    original_filename: str,
    display_name: str,
    agent_id: str | None,
    collection_kind: str | None,
    source_path: str | None,
    motw_zone_id: int | None = None,
    motw_referrer_url: str | None = None,
    gate_warnings: list[str] | None = None,
) -> dict[str, Any]:
    row = conn.execute(
        """
        INSERT INTO uploads (
            tenant_id, workspace_id, run_id, sha256, sha1, md5, size,
            original_filename, display_name, motw_zone_id, motw_referrer_url,
            agent_id, collection_kind, source_path, gate_warnings
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s, %s
        )
        RETURNING artifact_id, run_id, received_at, triage_state, display_name,
                  size, sha256, sha1, md5, gate_warnings, agent_id, collection_kind
        """,
        (
            tenant_id,
            workspace_id,
            run_id,
            bytes.fromhex(sha256_hex),
            bytes.fromhex(sha1_hex) if sha1_hex else None,
            bytes.fromhex(md5_hex) if md5_hex else None,
            size,
            original_filename,
            display_name,
            motw_zone_id,
            motw_referrer_url,
            agent_id,
            collection_kind,
            source_path,
            gate_warnings or [],
        ),
    ).fetchone()
    assert row is not None
    return {
        "artifact_id": str(row[0]),
        "run_id": row[1],
        "received_at": row[2],
        "triage_state": row[3],
        "display_name": row[4],
        "size": row[5],
        "sha256": row[6].hex() if row[6] else None,
        "sha1": row[7].hex() if row[7] else None,
        "md5": row[8].hex() if row[8] else None,
        "gate_warnings": list(row[9] or []),
        "agent_id": row[10],
        "collection_kind": row[11],
    }


def get_upload(conn: psycopg.Connection, artifact_id: uuid.UUID) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT artifact_id, run_id, received_at, triage_state, display_name,
               size, sha256, sha1, md5, gate_warnings, agent_id, collection_kind
        FROM uploads WHERE artifact_id = %s
        """,
        (artifact_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "artifact_id": str(row[0]),
        "run_id": row[1],
        "received_at": row[2],
        "triage_state": row[3],
        "display_name": row[4],
        "size": row[5],
        "sha256": row[6].hex() if row[6] else None,
        "sha1": row[7].hex() if row[7] else None,
        "md5": row[8].hex() if row[8] else None,
        "gate_warnings": list(row[9] or []),
        "agent_id": row[10],
        "collection_kind": row[11],
    }


def get_upload_with_object(
    conn: psycopg.Connection, artifact_id: uuid.UUID
) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT u.artifact_id, u.run_id, u.triage_state, u.size, u.sha256,
               r.storage_uri
        FROM uploads u JOIN raw_objects r ON r.sha256 = u.sha256
        WHERE u.artifact_id = %s
        """,
        (artifact_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "artifact_id": str(row[0]),
        "run_id": row[1],
        "triage_state": row[2],
        "size": row[3],
        "sha256": row[4].hex(),
        "storage_uri": row[5],
    }


def set_upload_triage_state(
    conn: psycopg.Connection, artifact_id: uuid.UUID, state: str
) -> None:
    conn.execute(
        "UPDATE uploads SET triage_state = %s WHERE artifact_id = %s",
        (state, artifact_id),
    )


def workspace_stored_bytes(conn: psycopg.Connection) -> int:
    row = conn.execute(
        """
        SELECT COALESCE(SUM(u.size), 0)
        FROM uploads u JOIN raw_objects r ON r.sha256 = u.sha256
        WHERE r.state <> 'purged'
        """
    ).fetchone()
    return int(row[0]) if row else 0
