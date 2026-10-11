"""M0 exit criterion ④ (static half) — the schema-lint contract of spec §6.4a.

Spec §6.4a (research/SENTINEL_IMPLEMENTATION_SPEC.md:19665 area) requires that
"any new table without a policy fails CI (schema-lint script counts
`ENABLE ROW LEVEL SECURITY` vs tenant-column tables)".

This module is that check, run against the *text* of ``schema.sql`` so it works
with no database.  It is deliberately stronger than the Stage-7 invariant INV-7
(``_stage7_work/audit_invariants.py``), which only counted
``ENABLE ROW LEVEL SECURITY`` statements and therefore let a policy-less table
pass — exactly the M1-D3 defect that left ``raw_objects`` deny-all.

FROZEN_* constants below are the M0 contract. Changing any of them is a
spec §10 (rank-2) contract change and needs a matching amendment in
``research/DEVIATION_REGISTER.md`` first.
"""
from __future__ import annotations

import re
from pathlib import Path

from tools.schema_parse import Schema, load_schema

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = load_schema(ROOT / "schema.sql")

# ---------------------------------------------------------------------------
# Frozen M0 numbers (see research/DEVIATION_REGISTER.md)
# ---------------------------------------------------------------------------
FROZEN_BASE_TABLE_COUNT = 21
FROZEN_PARTITION_CHILD_COUNT = 11
FROZEN_PARTITION_PARENT_COUNT = 4
FROZEN_POLICY_COUNT = 32  # 20 base + 11 partition + 1 raw_objects_cas
FROZEN_RLS_ENABLED_COUNT = 32

# Spec §10.1 table index, verbatim (research/SENTINEL_IMPLEMENTATION_SPEC.md
# §10.1 "Table index (from schema.sql)"). Only *base* tables are listed there;
# partition children are a §1.4 implementation detail.
SPEC_10_1_TABLES = {
    "tenants",
    "workspaces",
    "principals",
    "raw_objects",
    "uploads",
    "events",
    "rules",
    "rule_source",
    "rule_baseline",
    "fim_baseline",
    "ioc_pack",
    "ioc_entry",
    "jobs",
    "job_attempts",
    "detection_runs",
    "rule_run",
    "findings",
    "artifact_facts",
    "idempotency_keys",
    "audit_log",
    "retention_policies",
}

# The one policy permitted not to reference the tenancy GUCs, with the reason.
# raw_objects is a shared content-addressed store: it has no tenant_id column
# by design (D6-012 / Stage-6 §1.4) and is scoped by an application-level join
# through `uploads`. RLS is still ENABLEd (so the table is not owner-only) and
# this pass-through policy is what keeps it from being deny-all (M1-D3).
POLICY_EXEMPTIONS = {
    "raw_objects_cas": (
        "shared CAS with no tenant column (D6-012); scoping is the uploads "
        "join in application code — see research/DEVIATION_REGISTER.md (M1-D3)"
    )
}

TENANT_GUC = "sentinel.tenant_id"
WORKSPACE_GUC = "sentinel.workspace_id"

# The `tenants` table has no workspace dimension: a row *is* a tenant, so its
# policy can only scope on the tenant GUC. Same class of exemption, different
# reason — kept separate so a future "we dropped workspace scoping" change
# cannot hide inside the raw_objects exemption.
TENANT_ONLY_POLICY_EXEMPTIONS = {
    "tenants_ws": (
        "the tenants table has no workspace_id column; a row is a tenant, so "
        "the predicate can only be id = current_setting('sentinel.tenant_id')"
    )
}


def _tables_with_column(schema: Schema, column: str) -> set[str]:
    return {n for n, t in schema.tables.items() if t.has_column(column)}


# ---------------------------------------------------------------------------
# 1. every tenant-column table (parents AND partition children) is RLS-enabled
# ---------------------------------------------------------------------------
def test_every_tenant_column_relation_is_rls_enabled():
    tenant_tables = _tables_with_column(SCHEMA, "tenant_id")
    missing = sorted(tenant_tables - SCHEMA.rls_enabled)
    assert not missing, (
        "relations carrying tenant_id without ENABLE ROW LEVEL SECURITY "
        f"(spec §6.4a): {missing}"
    )


def test_every_workspace_column_relation_is_rls_enabled():
    ws_tables = _tables_with_column(SCHEMA, "workspace_id")
    missing = sorted(ws_tables - SCHEMA.rls_enabled)
    assert not missing, (
        "relations carrying workspace_id without ENABLE ROW LEVEL SECURITY "
        f"(spec §6.4a): {missing}"
    )


def test_partition_children_are_rls_enabled():
    """Declarative children do not inherit ENABLE from the parent (M0-A1)."""
    missing = sorted(set(SCHEMA.partition_children) - SCHEMA.rls_enabled)
    assert not missing, (
        f"partition children without ENABLE ROW LEVEL SECURITY: {missing}"
    )


# ---------------------------------------------------------------------------
# 2. every ENABLEd table has at least one policy — the check that would have
#    caught the M1-D3 raw_objects defect
# ---------------------------------------------------------------------------
def test_every_enabled_table_has_a_policy():
    without = sorted(
        name
        for name in SCHEMA.rls_enabled
        if not SCHEMA.policies_on(name)
    )
    assert not without, (
        "RLS-enabled tables with zero CREATE POLICY (deny-all for non-owners; "
        f"this is the M1-D3 defect class): {without}"
    )


def test_every_policy_targets_an_existing_table():
    dangling = sorted(
        {p.table for p in SCHEMA.policies} - set(SCHEMA.tables)
    )
    assert not dangling, f"policies on tables that do not exist: {dangling}"


# ---------------------------------------------------------------------------
# 3. every policy references the tenancy GUCs, except the documented exemption
# ---------------------------------------------------------------------------
def test_every_policy_references_the_tenancy_gucs():
    exempt = set(POLICY_EXEMPTIONS) | set(TENANT_ONLY_POLICY_EXEMPTIONS)
    bad = []
    for policy in SCHEMA.policies:
        if policy.name in exempt:
            continue
        if not (policy.uses_setting(TENANT_GUC) and policy.uses_setting(WORKSPACE_GUC)):
            bad.append(policy.name)
    assert not bad, (
        f"policies that do not reference both {TENANT_GUC!r} and "
        f"{WORKSPACE_GUC!r}: {bad}. Either fix the predicate or add an entry to "
        "POLICY_EXEMPTIONS with a rationale."
    )


def test_tenant_only_exemptions_are_real_and_documented():
    names = {p.name for p in SCHEMA.policies}
    unknown = sorted(set(TENANT_ONLY_POLICY_EXEMPTIONS) - names)
    assert not unknown, (
        f"TENANT_ONLY_POLICY_EXEMPTIONS names policies that no longer exist: {unknown}"
    )
    for name, reason in TENANT_ONLY_POLICY_EXEMPTIONS.items():
        assert len(reason) > 40, f"exemption {name} needs a real rationale, got {reason!r}"
        policy = next(p for p in SCHEMA.policies if p.name == name)
        assert policy.uses_setting(TENANT_GUC), f"{name} does not scope on the tenant GUC"
        assert not policy.uses_setting(WORKSPACE_GUC), (
            f"{name} now scopes on the workspace GUC — remove the exemption and "
            "put it under the normal rule"
        )


def test_policy_exemptions_are_real_and_documented():
    names = {p.name for p in SCHEMA.policies}
    unknown = sorted(set(POLICY_EXEMPTIONS) - names)
    assert not unknown, (
        f"POLICY_EXEMPTIONS names policies that no longer exist: {unknown}"
    )
    for name, reason in POLICY_EXEMPTIONS.items():
        assert len(reason) > 40, f"exemption {name} needs a real rationale, got {reason!r}"


def test_exempted_policy_is_the_documented_passthrough():
    policy = next(p for p in SCHEMA.policies if p.name == "raw_objects_cas")
    assert policy.table == "raw_objects"
    assert policy.using.strip() == "true"
    assert (policy.with_check or "").strip() == "true"


# ---------------------------------------------------------------------------
# 4. frozen counts — a table/policy addition forces a conscious update
# ---------------------------------------------------------------------------
def test_base_table_count_is_frozen():
    assert len(SCHEMA.base_tables) == FROZEN_BASE_TABLE_COUNT, (
        f"schema.sql has {len(SCHEMA.base_tables)} base tables, the M0 contract "
        f"freezes it at {FROZEN_BASE_TABLE_COUNT}"
    )


def test_partition_child_count_is_frozen():
    assert len(SCHEMA.partition_children) == FROZEN_PARTITION_CHILD_COUNT, (
        f"schema.sql has {len(SCHEMA.partition_children)} partition children, "
        f"the M0 contract freezes it at {FROZEN_PARTITION_CHILD_COUNT}"
    )


def test_partition_parent_count_is_frozen():
    assert len(SCHEMA.partition_parents) == FROZEN_PARTITION_PARENT_COUNT


def test_policy_count_is_frozen():
    assert len(SCHEMA.policies) == FROZEN_POLICY_COUNT, (
        f"schema.sql has {len(SCHEMA.policies)} CREATE POLICY statements, the "
        f"M0 contract freezes it at {FROZEN_POLICY_COUNT} "
        f"({FROZEN_POLICY_COUNT - 1} tenant-scoped + 1 raw_objects_cas). "
        "Amend research/DEVIATION_REGISTER.md before adding or removing one."
    )


def test_rls_enabled_count_is_frozen():
    assert len(SCHEMA.rls_enabled) == FROZEN_RLS_ENABLED_COUNT, (
        f"schema.sql enables RLS on {len(SCHEMA.rls_enabled)} relations; the M0 "
        f"contract freezes it at {FROZEN_RLS_ENABLED_COUNT}"
    )


def test_policy_names_are_unique():
    names = [p.name for p in SCHEMA.policies]
    dupes = sorted({n for n in names if names.count(n) > 1})
    assert not dupes, f"duplicate policy names: {dupes}"


# ---------------------------------------------------------------------------
# 5. static CREATE TABLE set matches spec §10.1's 21-table index
# ---------------------------------------------------------------------------
def test_base_table_set_matches_spec_10_1():
    actual = set(SCHEMA.base_tables)
    assert actual == SPEC_10_1_TABLES, (
        f"base tables only in schema.sql: {sorted(actual - SPEC_10_1_TABLES)}; "
        f"only in spec §10.1: {sorted(SPEC_10_1_TABLES - actual)}"
    )


def test_partition_children_all_belong_to_a_known_parent():
    known_parents = set(SCHEMA.partition_parents)
    orphans = sorted(
        {t.parent for t in SCHEMA.partition_children.values()} - known_parents
    )
    assert not orphans, f"partitions of unknown parents: {orphans}"


# ---------------------------------------------------------------------------
# 6. every policy's USING is tenant/workspace scoped on partition children too
# ---------------------------------------------------------------------------
def test_partition_policies_match_their_parent_shape():
    for child, table in sorted(SCHEMA.partition_children.items()):
        child_policies = SCHEMA.policies_on(child)
        assert child_policies, f"partition {child} has no policy"
        parent_policies = SCHEMA.policies_on(table.parent)
        assert parent_policies, f"parent {table.parent} has no policy"
        for cp in child_policies:
            assert cp.uses_setting(TENANT_GUC) and cp.uses_setting(WORKSPACE_GUC), (
                f"partition policy {cp.name} on {child} is not workspace-scoped "
                f"like its parent's {parent_policies[0].name}"
            )


# ---------------------------------------------------------------------------
# 7. schema.sql header still documents the frozen numbers (drift guard)
# ---------------------------------------------------------------------------
def test_header_documents_the_frozen_counts():
    text = (ROOT / "schema.sql").read_text(encoding="utf-8")
    header = text.split("-- ====", 2)[1] if "-- ====" in text else text[:4000]
    for needle in (
        str(FROZEN_BASE_TABLE_COUNT),
        str(FROZEN_PARTITION_CHILD_COUNT),
        str(FROZEN_POLICY_COUNT),
    ):
        assert re.search(rf"\b{needle}\b", header), (
            f"schema.sql header no longer states the frozen count {needle}; the "
            "header is the human-facing copy of this contract."
        )
