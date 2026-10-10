from __future__ import annotations

import uuid
from typing import Any

import psycopg
from psycopg.types.json import Json


def get_key(
    conn: psycopg.Connection, principal_id: str, key: str
) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT request_hash, response_code, response_body, expires_at
        FROM idempotency_keys
        WHERE principal_id = %s AND key = %s AND expires_at > now()
        """,
        (uuid.UUID(principal_id), key),
    ).fetchone()
    if row is None:
        return None
    return {
        "request_hash": row[0],
        "response_code": row[1],
        "response_body": row[2],
        "expires_at": row[3],
    }


def put_key(
    conn: psycopg.Connection,
    *,
    principal_id: str,
    key: str,
    request_hash: bytes,
    response_code: int,
    response_body: dict[str, Any],
) -> None:
    conn.execute(
        """
        INSERT INTO idempotency_keys (key, principal_id, request_hash, response_code, response_body, expires_at)
        VALUES (%s, %s, %s, %s, %s, now() + interval '24 hours')
        ON CONFLICT (principal_id, key) DO UPDATE
        SET request_hash = EXCLUDED.request_hash,
            response_code = EXCLUDED.response_code,
            response_body = EXCLUDED.response_body,
            expires_at = EXCLUDED.expires_at
        """,
        (key, uuid.UUID(principal_id), request_hash, response_code, Json(response_body)),
    )
