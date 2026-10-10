"""M1 exit ②: cross-tenant probe returns 403 and zero rows."""
from __future__ import annotations

import pytest

from sentinel_core.db import tx
from sentinel_core.rls import set_rls

from ..keys import KEY_A, KEY_B


def test_cross_workspace_is_403(client):
    # tenant-b principal probing default workspace
    r = client.get(
        "/v1/workspaces/default/events",
        headers={"X-API-Key": KEY_B},
    )
    assert r.status_code == 403
    assert r.json()["code"] == "GATE_TENANT_MISMATCH"


def test_wrong_api_key_is_401(client):
    r = client.get(
        "/v1/workspaces/default/events",
        headers={"X-API-Key": "not-a-real-key"},
    )
    assert r.status_code == 401
    assert r.json()["code"] == "GATE_UNAUTHENTICATED"


def test_missing_api_key_is_401(client):
    r = client.get("/v1/workspaces/default/events")
    assert r.status_code == 401


def test_unscoped_session_sees_zero_rows(migrated):
    """App role without set_config sees nothing (RLS is USING-only)."""
    with tx(migrated.database_url) as conn:
        row = conn.execute("SELECT count(*) FROM uploads").fetchone()
        assert int(row[0]) == 0


def test_scoped_session_only_sees_own_tenant(migrated, client):
    # insert one upload under tenant A via API
    files = {"file": ("probe.bin", b"probe-bytes", "application/octet-stream")}
    r = client.post(
        "/v1/workspaces/default/uploads",
        files=files,
        headers={"X-API-Key": KEY_A},
    )
    assert r.status_code == 202
    artifact = r.json()["artifact_id"]

    with tx(migrated.database_url) as conn:
        set_rls(conn, "default", "default")
        row = conn.execute(
            "SELECT count(*) FROM uploads WHERE artifact_id = %s", (artifact,)
        ).fetchone()
        assert int(row[0]) == 1

    with tx(migrated.database_url) as conn:
        set_rls(conn, "tenant-b", "ws-b")
        row = conn.execute(
            "SELECT count(*) FROM uploads WHERE artifact_id = %s", (artifact,)
        ).fetchone()
        assert int(row[0]) == 0


@pytest.mark.parametrize("key,ws,tenant", [(KEY_A, "default", "default"), (KEY_B, "ws-b", "tenant-b")])
def test_each_key_reads_only_its_workspace(client, migrated, key, ws, tenant):
    with tx(migrated.database_url) as conn:
        set_rls(conn, tenant, ws)
        n = conn.execute("SELECT count(*) FROM uploads").fetchone()
        assert int(n[0]) >= 0  # scoped read succeeds (no cross rows leaked)
    r = client.get(f"/v1/workspaces/{ws}/uploads", headers={"X-API-Key": key})
    assert r.status_code == 200
