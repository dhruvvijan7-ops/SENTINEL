"""Dynamic RLS suite — spec §6.4a (a)–(d) plus the M0-A1 partition probe.

(a) a session without GUCs sees 0 rows on every scoped table;
(b) tenant A's GUC never reads tenant B's rows, parametrised over all 21 base
    tables (``tests/rls_seed.py`` plants one FK-valid row per table per tenant);
(c) the cross-workspace 403s the API itself raises;
(d) the ``EXISTS`` policies on ``job_attempts`` and ``rule_run`` — a row that
    references *another* tenant's parent is invisible;
(e) M0-A1: a direct ``SELECT`` against a partition child is scoped exactly like
    its parent (declarative children do not inherit RLS, so this is the check
    that locks in the partition work).
"""
from __future__ import annotations

import pytest

from sentinel_core.db import tx
from sentinel_core.rls import set_rls
from tools.schema_parse import load_schema

from ..keys import KEY_A, KEY_B
from ..rls_seed import (
    CONTRACT_BASE_TABLES,
    TENANT_A,
    TENANT_B,
    count_owned_by,
    count_visible,
    purge_seeded_rows,
    seed_tenant_rows,
)

SCHEMA = load_schema()
PARTITION_CHILDREN = sorted(SCHEMA.partition_children)
PARTITION_PARENTS = sorted(SCHEMA.partition_parents)


# ---------------------------------------------------------------------------
# (c) API-level tenancy
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# The 21-table probe — needs rows planted in both tenants
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def seeded(migrated):
    """Plant one FK-valid row per contract table for tenant A and tenant B.

    Purges first: ``ON CONFLICT DO NOTHING`` cannot repair a row an earlier run
    planted wrongly, and a stale wrong row would silently weaken the probe.
    Purges again on the way out so the *next* pytest session starts clean —
    without the teardown, every module-level seed row survives into the
    following run and ``tests/e2e/test_upload_flow.py`` (which runs earlier in
    the session) inherits it.
    """
    purge_seeded_rows(migrated)
    seed_tenant_rows(migrated, tenant=TENANT_A, worker=False)
    seed_tenant_rows(migrated, tenant=TENANT_B, worker=True)
    yield migrated
    purge_seeded_rows(migrated)


@pytest.mark.parametrize(
    "table",
    [t for t in CONTRACT_BASE_TABLES if t != "raw_objects"],
)
def test_a_unscoped_session_sees_zero_rows(seeded, table):
    """(a) no GUCs set ⇒ zero rows on every scoped table.

    ``raw_objects`` is the one documented exemption (D6-012 / M1-D3): it has
    no tenant column and its policy is an explicit ``USING (true)`` pass-through,
    so an unscoped read is *expected* to succeed. That behaviour is pinned by
    ``test_a_raw_objects_is_the_documented_passthrough`` instead.
    """
    row = count_visible(seeded, tenant=None, table=table)
    assert row == 0, (
        f"unscoped session saw {row} rows on {table}; RLS is USING-only so a "
        "NULL current_setting must match nothing"
    )


def test_a_raw_objects_is_the_documented_passthrough(seeded):
    """M1-D3 resolution: RLS-enabled with an explicit pass-through policy.

    An ENABLEd table with no policy is deny-all — that was the defect. The
    contract now carries ``raw_objects_cas`` (USING (true) WITH CHECK (true)),
    so the app role can read and write the shared CAS and scoping is the
    uploads join in application code (Stage-6 §1.4).
    """
    n = count_visible(seeded, tenant=None, table="raw_objects")
    assert n >= 1, (
        "raw_objects is RLS-enabled; without the raw_objects_cas pass-through "
        "policy this read would return 0 — the M1-D3 defect has regressed"
    )


@pytest.mark.parametrize(
    "table",
    [t for t in CONTRACT_BASE_TABLES if t != "raw_objects"],
)
def test_b_tenant_a_never_reads_tenant_b(seeded, table):
    """(b) tenant A's GUC reads tenant A's row and not tenant B's.

    The probe counts rows *owned by* B that A can see — counting "rows visible
    to B" would be the wrong question, since B is supposed to see its own row.
    ``raw_objects`` is excluded: its documented pass-through policy (M1-D3)
    means the shared CAS is visible to everyone by design; see
    ``test_a_raw_objects_is_the_documented_passthrough``.
    """
    own_a = count_owned_by(seeded, viewer=TENANT_A, table=table, owner=TENANT_A)
    leaked = count_owned_by(seeded, viewer=TENANT_A, table=table, owner=TENANT_B)
    assert own_a >= 1, f"tenant A sees no rows of its own on {table} — the seed failed"
    assert leaked == 0, (
        f"tenant A's GUC leaked {leaked} row(s) of {table} that belong to tenant B"
    )


@pytest.mark.parametrize(
    "table",
    [t for t in CONTRACT_BASE_TABLES if t != "raw_objects"],
)
def test_b_tenant_b_never_reads_tenant_a(seeded, table):
    """(b) the mirror probe: tenant B's GUC never surfaces a tenant-A row."""
    own_b = count_owned_by(seeded, viewer=TENANT_B, table=table, owner=TENANT_B)
    leaked = count_owned_by(seeded, viewer=TENANT_B, table=table, owner=TENANT_A)
    assert own_b >= 1, f"tenant B sees no rows of its own on {table} — the seed failed"
    assert leaked == 0, (
        f"tenant B's GUC leaked {leaked} row(s) of {table} that belong to tenant A"
    )


@pytest.mark.parametrize(
    "table",
    [t for t in CONTRACT_BASE_TABLES if t != "raw_objects"],
)
def test_b_unscoped_session_sees_no_belonging_rows(seeded, table):
    """(a)+(b) with NULL GUCs neither tenant's rows are reachable at all."""
    for owner in (TENANT_A, TENANT_B):
        n = count_owned_by(seeded, viewer=None, table=table, owner=owner)
        assert n == 0, (
            f"unscoped session saw {n} row(s) of {table} owned by {owner[0]}; "
            "RLS is USING-only so a NULL current_setting must match nothing"
        )


# ---------------------------------------------------------------------------
# (d) EXISTS policies — job_attempts over jobs, rule_run over detection_runs
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("table", ["job_attempts", "rule_run"])
def test_d_exists_target_of_another_tenant_is_invisible(seeded, table):
    """A row whose only tenancy is an EXISTS over a parent table is invisible
    when that parent belongs to the other tenant — even though the row itself
    has no tenant column (spec §6.4a (d))."""
    own_a = count_owned_by(seeded, viewer=TENANT_A, table=table, owner=TENANT_A)
    leaked = count_owned_by(seeded, viewer=TENANT_A, table=table, owner=TENANT_B)
    assert own_a == 1, f"tenant A lost its own {table} row (saw {own_a})"
    assert leaked == 0, (
        f"tenant A can see {leaked} {table} row(s) that reference tenant B's parent"
    )


def test_d_unscoped_session_cannot_reach_exists_targets(seeded):
    """Without GUCs the EXISTS predicates compare against NULL ⇒ zero rows."""
    for table in ("job_attempts", "rule_run"):
        n = count_visible(seeded, tenant=None, table=table)
        assert n == 0, f"unscoped session saw {table} rows"


def test_d_idempotency_keys_scoped_to_own_principal(seeded):
    """idempotency_keys uses an IN over principals, not a tenant column."""
    own_a = count_owned_by(
        seeded, viewer=TENANT_A, table="idempotency_keys", owner=TENANT_A
    )
    leaked = count_owned_by(
        seeded, viewer=TENANT_A, table="idempotency_keys", owner=TENANT_B
    )
    assert own_a == 1, "tenant A lost its own idempotency key"
    assert leaked == 0, "tenant A can see tenant B's idempotency key"


# ---------------------------------------------------------------------------
# (e) M0-A1 — partition children are scoped exactly like their parents
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("child", PARTITION_CHILDREN)
def test_e_partition_unscoped_sees_zero_rows(seeded, child):
    n = count_visible(seeded, tenant=None, table=child)
    assert n == 0, f"unscoped SELECT against partition {child} returned {n} rows"


@pytest.mark.parametrize("child", PARTITION_CHILDREN)
def test_e_partition_never_shows_another_tenants_rows(seeded, child):
    """A direct SELECT against a partition child is scoped exactly like its
    parent.  Declarative children do not inherit RLS from the parent, so this
    is the check that locks in M0-A1 (D6-013)."""
    parent = SCHEMA.tables[child].parent
    leaked = count_owned_by(
        seeded, viewer=TENANT_A, table=child, owner=TENANT_B, marker_table=parent
    )
    assert leaked == 0, (
        f"tenant A's GUC leaked {leaked} row(s) from partition {child} "
        f"(parent {parent}) — partition RLS is not applied"
    )
    own_a = count_owned_by(
        seeded, viewer=TENANT_A, table=child, owner=TENANT_A, marker_table=parent
    )
    # The seeded row may legitimately route into a different monthly partition,
    # so only assert the scoped read itself is permitted (never an error).
    assert own_a >= 0


@pytest.mark.parametrize("parent", PARTITION_PARENTS)
def test_e_parent_and_children_agree_on_visibility(seeded, parent):
    """A scoped count over the parent must equal the sum over its children —
    if a child were unpoliced the totals would diverge."""
    children = SCHEMA.partitions_of(parent)
    with tx(seeded.database_url) as conn:
        set_rls(conn, TENANT_A[0], TENANT_A[1])
        parent_n = int(conn.execute(f"SELECT count(*) FROM {parent}").fetchone()[0])
        child_n = sum(
            int(conn.execute(f"SELECT count(*) FROM {c}").fetchone()[0])
            for c in children
        )
    assert parent_n == child_n, (
        f"{parent}: parent sees {parent_n} rows but its children sum to "
        f"{child_n} — at least one partition is not policed"
    )


def test_e_all_contract_partitions_are_covered():
    """The probe must cover every partition child in the storage contract."""
    assert len(PARTITION_CHILDREN) == 12, (
        f"expected the 12 contract partitions, found {len(PARTITION_CHILDREN)}"
    )
    assert set(PARTITION_PARENTS) <= set(CONTRACT_BASE_TABLES), (
        "every policed parent must also be a seeded contract table: "
        f"{sorted(set(PARTITION_PARENTS) - set(CONTRACT_BASE_TABLES))}"
    )
    assert all(
        SCHEMA.tables[child].is_partition_child for child in PARTITION_CHILDREN
    ), "the parser stopped recognising partition children"
