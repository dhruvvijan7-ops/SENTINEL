from __future__ import annotations

import psycopg


def set_rls(conn: psycopg.Connection, tenant_id: str, workspace_id: str) -> None:
    """Scope the current transaction to one tenant+workspace (schema.sql §0).

    is_local=true ties both settings to the surrounding transaction, so every
    statement in the unit of work sees them and a later transaction on the
    same connection starts clean.
    """
    conn.execute("SELECT set_config('sentinel.tenant_id', %s, true)", (tenant_id,))
    conn.execute("SELECT set_config('sentinel.workspace_id', %s, true)", (workspace_id,))
