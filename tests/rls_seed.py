"""Seeding helper for the dynamic RLS suite (spec §6.4a (a)–(d)).

Inserts exactly one FK-valid row per base table for **each** of two tenants, so
the parametrised probe can assert "tenant A sees 1, tenant B sees 0" on every
table rather than only on the handful the API happens to write during M1.

Two connection identities are used, mirroring the shipped topology
(``packaging/docker-init/00-roles.sql``):

  * ``settings.database_url``  — ``sentinel_app``, **no** BYPASSRLS.  Every
    tenant-A row goes in through this role with the tenancy GUCs set, so the
    insert itself is subject to the policy's implicit ``WITH CHECK``.  That is
    deliberate: it is how the partition-RLS work (M0-A1) proves an ordinary
    write still lands after children were policed.
  * ``settings.database_worker_url``    — ``sentinel_worker``, ``BYPASSRLS``.  Tenant-B
    rows are planted through this role because the worker is the only identity
    that legitimately writes cross-tenant (it is the platform processor).  It
    also keeps the probe honest: tenant B's rows exist in the database even
    though tenant A can never see them.

Every statement is idempotent (``ON CONFLICT DO NOTHING`` or a stable key), so
the module can be re-imported across a session without duplicating rows.

Timestamps are pinned into the 2026-10 partition window so rows land in the
monthly partitions that exist in ``schema.sql`` rather than erroring with "no
partition of relation found for row".
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass

TENANT_A = ("default", "default")
TENANT_B = ("tenant-b", "ws-b")

# Fixed UUIDs so the probe is re-runnable and failures are diffable.
UID = uuid.UUID("00000000-0000-7000-8000-0000000000aa")
UID_B = uuid.UUID("00000000-0000-7000-8000-0000000000bb")
SHA_A = bytes.fromhex("aa" * 32)
SHA_B = bytes.fromhex("bb" * 32)


@dataclass(frozen=True)
class SeededTable:
    """One base table under test."""

    name: str
    #: column whose value identifies the owning tenant on a plain SELECT;
    #: None for tables whose policy is an EXISTS over another table
    #: (job_attempts, rule_run) or that have no tenant column at all
    #: (raw_objects, idempotency_keys).  Those use ``marker_col`` instead.
    tenant_probe: str | None
    #: column used to tell "this row belongs to tenant X" apart from
    #: "this row is visible to tenant X".  For tenant-scoped tables this is the
    #: same as ``tenant_probe``; for EXISTS-scoped tables it is the parent FK.
    marker_col: str | None = None
    #: how ``marker_for`` computes the value: ``"tenant"`` (the tenant id),
    #: ``"workspace"`` (the workspace id) or ``"uuid"`` (UID for A / UID_B for B).
    marker_kind: str = "tenant"
    #: INSERT executed as sentinel_app with tenant-A GUCs (subject to WITH CHECK)
    seed_a: str | None = None
    #: INSERT executed as sentinel_worker (BYPASSRLS) for tenant B
    seed_b: str | None = None
    #: tables whose policy is the documented raw_objects_cas pass-through
    unscoped_visible: bool = False

    def marker_for(self, tenant: tuple[str, str]) -> object:
        """Value of ``marker_col`` that marks a row owned by ``tenant``."""
        if self.marker_kind == "uuid":
            return str(UID if tenant[0] == TENANT_A[0] else UID_B)
        if self.marker_kind == "workspace":
            return tenant[1]
        return tenant[0]

    @property
    def marker_column(self) -> str | None:
        """Column that identifies row ownership (``marker_col`` or the tenant probe)."""
        return self.marker_col or self.tenant_probe


# ---------------------------------------------------------------------------
# Seed statements — ordered so every FK target exists before its referrer.
# ---------------------------------------------------------------------------
def _seed_rows() -> list[SeededTable]:
    return [
        # ---- 1. tenancy & identity -------------------------------------
        SeededTable(
            "tenants",
            tenant_probe="id",
            seed_a=None,  # 'default' is inserted by schema.sql itself
            seed_b=None,  # 'tenant-b' is inserted by the conftest migrated fixture
        ),
        SeededTable(
            "workspaces",
            tenant_probe="id",
            marker_kind="workspace",
        ),
        SeededTable(
            "principals",
            tenant_probe="tenant_id",
            seed_a=(
                "INSERT INTO principals (id, tenant_id, workspace_id, kind, "
                "display_name, scopes) VALUES (%s, %s, %s, 'api_key', "
                "'rls-seed-a', '{}') ON CONFLICT DO NOTHING"
            ),
            seed_b=(
                "INSERT INTO principals (id, tenant_id, workspace_id, kind, "
                "display_name, scopes) VALUES (%s, %s, %s, 'api_key', "
                "'rls-seed-b', '{}') ON CONFLICT DO NOTHING"
            ),
        ),
        # ---- 2. CAS + accepted uploads ---------------------------------
        SeededTable(
            "raw_objects",
            tenant_probe=None,
            seed_a=(
                "INSERT INTO raw_objects (sha256, size, storage_uri, "
                "retention_until) VALUES (%s, 1, 'file:///rls-a', now() + "
                "interval '90 days') ON CONFLICT DO NOTHING"
            ),
            seed_b=(
                "INSERT INTO raw_objects (sha256, size, storage_uri, "
                "retention_until) VALUES (%s, 1, 'file:///rls-b', now() + "
                "interval '90 days') ON CONFLICT DO NOTHING"
            ),
            unscoped_visible=True,
        ),
        SeededTable(
            "uploads",
            tenant_probe="tenant_id",
            seed_a=(
                "INSERT INTO uploads (artifact_id, tenant_id, workspace_id, "
                "run_id, sha256, size, original_filename, display_name) "
                "VALUES (%s, %s, %s, 'rls-run', %s, 1, 'a.bin', 'a.bin') "
                "ON CONFLICT DO NOTHING"
            ),
            seed_b=(
                "INSERT INTO uploads (artifact_id, tenant_id, workspace_id, "
                "run_id, sha256, size, original_filename, display_name) "
                "VALUES (%s, %s, %s, 'rls-run', %s, 1, 'b.bin', 'b.bin') "
                "ON CONFLICT DO NOTHING"
            ),
        ),
        # ---- 3. events --------------------------------------------------
        SeededTable(
            "events",
            tenant_probe="tenant_id",
            seed_a=(
                "INSERT INTO events (event_uid, tenant_id, workspace_id, "
                "run_id, artifact_id, event_time_state, event_category, "
                "event_type, event_action, event_outcome, event_severity, "
                "event_derived_by, classification, source_format, "
                "source_parser, source_record_type, document) "
                "VALUES (%s, %s, %s, 'rls-run', %s, 'ok', 'process', "
                "'process_create', 'created', 'success', 'low', 'sentinel', "
                "'internal', 'evtx', 'sysmon', '1', '{}') "
                "ON CONFLICT DO NOTHING"
            ),
            seed_b=(
                "INSERT INTO events (event_uid, tenant_id, workspace_id, "
                "run_id, artifact_id, event_time_state, event_category, "
                "event_type, event_action, event_outcome, event_severity, "
                "event_derived_by, classification, source_format, "
                "source_parser, source_record_type, document) "
                "VALUES (%s, %s, %s, 'rls-run', %s, 'ok', 'process', "
                "'process_create', 'created', 'success', 'low', 'sentinel', "
                "'internal', 'evtx', 'sysmon', '1', '{}') "
                "ON CONFLICT DO NOTHING"
            ),
        ),
        # ---- 4. rules ---------------------------------------------------
        SeededTable(
            "rules",
            tenant_probe="tenant_id",
            # ``enabled = false``: these rows exist only so the policy has a
            # row to show/hide.  They carry an empty document (no ``detection``),
            # so if they were enabled the auto-chained detect_run in
            # ``tests/e2e/test_upload_flow.py`` would compile them and fail —
            # a seed row must never change an unrelated test's outcome.
            seed_a=(
                "INSERT INTO rules (rule_id, tenant_id, workspace_id, name, "
                "kind, source, license, author, title, status, severity, "
                "enabled, document) VALUES (%s, %s, %s, 'rls-a', 'sigma', "
                "'native', 'DRL-1.1', 'sentinel', 'RLS seed A', 'stable', "
                "'LOW', false, '{}') ON CONFLICT DO NOTHING"
            ),
            seed_b=(
                "INSERT INTO rules (rule_id, tenant_id, workspace_id, name, "
                "kind, source, license, author, title, status, severity, "
                "enabled, document) VALUES (%s, %s, %s, 'rls-b', 'sigma', "
                "'native', 'DRL-1.1', 'sentinel', 'RLS seed B', 'stable', "
                "'LOW', false, '{}') ON CONFLICT DO NOTHING"
            ),
        ),
        SeededTable(
            "rule_source",
            tenant_probe="tenant_id",
            seed_a=(
                "INSERT INTO rule_source (tenant_id, workspace_id, rule_id, "
                "text, sha256) VALUES (%s, %s, %s, 'title: a', %s) "
                "ON CONFLICT DO NOTHING"
            ),
            seed_b=(
                "INSERT INTO rule_source (tenant_id, workspace_id, rule_id, "
                "text, sha256) VALUES (%s, %s, %s, 'title: b', %s) "
                "ON CONFLICT DO NOTHING"
            ),
        ),
        SeededTable(
            "rule_baseline",
            tenant_probe="tenant_id",
            seed_a=(
                "INSERT INTO rule_baseline (tenant_id, workspace_id, rule_id, "
                "baseline_key, bucket_start, bucket_span, observations) "
                "VALUES (%s, %s, %s, 'host', '2026-10-01T00:00:00Z', "
                "interval '1 day', 0) ON CONFLICT DO NOTHING"
            ),
            seed_b=(
                "INSERT INTO rule_baseline (tenant_id, workspace_id, rule_id, "
                "baseline_key, bucket_start, bucket_span, observations) "
                "VALUES (%s, %s, %s, 'host', '2026-10-01T00:00:00Z', "
                "interval '1 day', 0) ON CONFLICT DO NOTHING"
            ),
        ),
        SeededTable(
            "fim_baseline",
            tenant_probe="tenant_id",
            seed_a=(
                "INSERT INTO fim_baseline (tenant_id, workspace_id, host_key, "
                "path) VALUES (%s, %s, 'host-a', 'C:/a') "
                "ON CONFLICT DO NOTHING"
            ),
            seed_b=(
                "INSERT INTO fim_baseline (tenant_id, workspace_id, host_key, "
                "path) VALUES (%s, %s, 'host-b', 'C:/b') "
                "ON CONFLICT DO NOTHING"
            ),
        ),
        # ---- 5. IOC -----------------------------------------------------
        SeededTable(
            "ioc_pack",
            tenant_probe="tenant_id",
            seed_a=(
                "INSERT INTO ioc_pack (pack_id, tenant_id, workspace_id, name, "
                "version, sha256) VALUES (%s, %s, %s, 'rls-a', '1', %s) "
                "ON CONFLICT DO NOTHING"
            ),
            seed_b=(
                "INSERT INTO ioc_pack (pack_id, tenant_id, workspace_id, name, "
                "version, sha256) VALUES (%s, %s, %s, 'rls-b', '1', %s) "
                "ON CONFLICT DO NOTHING"
            ),
        ),
        SeededTable(
            "ioc_entry",
            tenant_probe="tenant_id",
            seed_a=(
                "INSERT INTO ioc_entry (tenant_id, workspace_id, pack_id, "
                "kind, value_hash, value_norm) VALUES (%s, %s, %s, 'sha256', "
                "%s, 'aa') ON CONFLICT DO NOTHING"
            ),
            seed_b=(
                "INSERT INTO ioc_entry (tenant_id, workspace_id, pack_id, "
                "kind, value_hash, value_norm) VALUES (%s, %s, %s, 'sha256', "
                "%s, 'bb') ON CONFLICT DO NOTHING"
            ),
        ),
        # ---- 6. job queue ----------------------------------------------
        SeededTable(
            "jobs",
            tenant_probe="tenant_id",
            seed_a=(
                "INSERT INTO jobs (job_id, tenant_id, workspace_id, job_type) "
                "VALUES (%s, %s, %s, 'ingest_file') ON CONFLICT DO NOTHING"
            ),
            seed_b=(
                "INSERT INTO jobs (job_id, tenant_id, workspace_id, job_type) "
                "VALUES (%s, %s, %s, 'ingest_file') ON CONFLICT DO NOTHING"
            ),
        ),
        SeededTable(
            # EXISTS policy over jobs — no tenant column of its own.
            "job_attempts",
            tenant_probe=None,
            marker_col="job_id",
            marker_kind="uuid",
            seed_a=(
                "INSERT INTO job_attempts (job_id, attempt, worker) "
                "VALUES (%s, 1, 'rls-seed') ON CONFLICT DO NOTHING"
            ),
            seed_b=(
                "INSERT INTO job_attempts (job_id, attempt, worker) "
                "VALUES (%s, 1, 'rls-seed') ON CONFLICT DO NOTHING"
            ),
        ),
        # ---- 7. detection -----------------------------------------------
        SeededTable(
            "detection_runs",
            tenant_probe="tenant_id",
            seed_a=(
                "INSERT INTO detection_runs (run_id, tenant_id, workspace_id, "
                "requested_by, config_hash) VALUES (%s, %s, %s, 'rls', %s) "
                "ON CONFLICT DO NOTHING"
            ),
            seed_b=(
                "INSERT INTO detection_runs (run_id, tenant_id, workspace_id, "
                "requested_by, config_hash) VALUES (%s, %s, %s, 'rls', %s) "
                "ON CONFLICT DO NOTHING"
            ),
        ),
        SeededTable(
            # EXISTS policy over detection_runs — no tenant column of its own.
            "rule_run",
            tenant_probe=None,
            marker_col="run_id",
            marker_kind="uuid",
            seed_a=(
                "INSERT INTO rule_run (run_id, rule_id, outcome) VALUES (%s, "
                "%s, 'ok') ON CONFLICT DO NOTHING"
            ),
            seed_b=(
                "INSERT INTO rule_run (run_id, rule_id, outcome) VALUES (%s, "
                "%s, 'ok') ON CONFLICT DO NOTHING"
            ),
        ),
        SeededTable(
            "findings",
            tenant_probe="tenant_id",
            seed_a=(
                "INSERT INTO findings (finding_uid, tenant_id, workspace_id, "
                "run_id, rule_id, rule_name, author, kind, severity, time_utc, "
                "detection_path, fingerprint, evidence_snapshot) VALUES (%s, "
                "%s, %s, %s, %s, 'rls', 'sentinel', 'sigma', 'LOW', "
                "'2026-10-01T00:00:00Z', 'sql', %s, '{}') "
                "ON CONFLICT DO NOTHING"
            ),
            seed_b=(
                "INSERT INTO findings (finding_uid, tenant_id, workspace_id, "
                "run_id, rule_id, rule_name, author, kind, severity, time_utc, "
                "detection_path, fingerprint, evidence_snapshot) VALUES (%s, "
                "%s, %s, %s, %s, 'rls', 'sentinel', 'sigma', 'LOW', "
                "'2026-10-01T00:00:00Z', 'sql', %s, '{}') "
                "ON CONFLICT DO NOTHING"
            ),
        ),
        # ---- 8. artifact facts -----------------------------------------
        SeededTable(
            "artifact_facts",
            tenant_probe="tenant_id",
            seed_a=(
                "INSERT INTO artifact_facts (fact_uid, tenant_id, "
                "workspace_id, run_id, artifact_id, namespace, fact_name, "
                "fact_value) VALUES (%s, %s, %s, 'rls-run', %s, 'pe', "
                "'imphash', '{}') ON CONFLICT DO NOTHING"
            ),
            seed_b=(
                "INSERT INTO artifact_facts (fact_uid, tenant_id, "
                "workspace_id, run_id, artifact_id, namespace, fact_name, "
                "fact_value) VALUES (%s, %s, %s, 'rls-run', %s, 'pe', "
                "'imphash', '{}') ON CONFLICT DO NOTHING"
            ),
        ),
        # ---- 9. API plumbing -------------------------------------------
        SeededTable(
            # EXISTS/IN policy over principals — no tenant column of its own.
            "idempotency_keys",
            tenant_probe=None,
            marker_col="principal_id",
            marker_kind="uuid",
            seed_a=(
                "INSERT INTO idempotency_keys (key, principal_id, "
                "request_hash, response_code, expires_at) VALUES ('rls-a', %s, "
                "%s, 200, now() + interval '24 hours') ON CONFLICT DO NOTHING"
            ),
            seed_b=(
                "INSERT INTO idempotency_keys (key, principal_id, "
                "request_hash, response_code, expires_at) VALUES ('rls-b', %s, "
                "%s, 200, now() + interval '24 hours') ON CONFLICT DO NOTHING"
            ),
        ),
        SeededTable(
            "audit_log",
            tenant_probe="tenant_id",
            seed_a=(
                "INSERT INTO audit_log (audit_uid, tenant_id, workspace_id, "
                "action, outcome) VALUES (%s, %s, %s, 'rls.seed', 'ok') "
                "ON CONFLICT DO NOTHING"
            ),
            seed_b=(
                "INSERT INTO audit_log (audit_uid, tenant_id, workspace_id, "
                "action, outcome) VALUES (%s, %s, %s, 'rls.seed', 'ok') "
                "ON CONFLICT DO NOTHING"
            ),
        ),
        SeededTable(
            "retention_policies",
            tenant_probe="tenant_id",
            seed_a=None,  # seeded by schema.sql for ('default','default')
            seed_b=(
                "INSERT INTO retention_policies (tenant_id, workspace_id, "
                "scope_kind, retention_days) VALUES (%s, %s, 'event', 365) "
                "ON CONFLICT DO NOTHING"
            ),
        ),
    ]


SEEDED_TABLES: tuple[SeededTable, ...] = tuple(_seed_rows())
_TABLE_BY_NAME: dict[str, SeededTable] = {t.name: t for t in SEEDED_TABLES}

#: The 21 base tables of the storage contract (spec §10.1).  Kept explicit
#: rather than derived so a table addition cannot silently widen the probe.
CONTRACT_BASE_TABLES: tuple[str, ...] = tuple(t.name for t in SEEDED_TABLES)


def _params(table: SeededTable, tenant: tuple[str, str]) -> list | None:
    """Build the parameter tuple for a table's seed statements.

    Every uuid primary key is derived from the tenant being seeded, so tenant B
    gets a distinct ``UID_B`` rather than colliding with tenant A's ``UID`` and
    silently failing ``ON CONFLICT DO NOTHING``.
    """
    tenant_id, workspace_id = tenant
    a = tenant_id == TENANT_A[0]
    suffix = "a" if a else "b"
    uid = str(UID if a else UID_B)
    sha = SHA_A if a else SHA_B
    match table.name:
        case "tenants" if a:
            return None
        case "workspaces" if a:
            return None
        case "retention_policies" if a:
            return None
        case "tenants":
            return [tenant_id, f"RLS seed tenant {suffix}"]
        case "workspaces":
            return [workspace_id, tenant_id, f"RLS seed workspace {suffix}"]
        case "retention_policies":
            return [tenant_id, workspace_id]
        case "principals":
            return [uid, tenant_id, workspace_id]
        case "raw_objects":
            return [sha]
        case "uploads":
            return [uid, tenant_id, workspace_id, sha]
        case "events":
            return [uid, tenant_id, workspace_id, uid]
        case "rules":
            return [uid, tenant_id, workspace_id]
        case "rule_baseline":
            # column order is (tenant_id, workspace_id, rule_id, …)
            return [tenant_id, workspace_id, uid]
        case "fim_baseline":
            return [tenant_id, workspace_id]
        case "rule_source":
            return [tenant_id, workspace_id, uid, bytes.fromhex("cc" * 32)]
        case "ioc_pack":
            return [uid, tenant_id, workspace_id, bytes.fromhex("dd" * 32)]
        case "ioc_entry":
            return [tenant_id, workspace_id, uid, bytes.fromhex("ee" * 32)]
        case "jobs":
            return [uid, tenant_id, workspace_id]
        case "job_attempts":
            return [uid]
        case "detection_runs":
            return [uid, tenant_id, workspace_id, bytes.fromhex("11" * 32)]
        case "rule_run":
            return [uid, uid]
        case "findings":
            return [
                uid, tenant_id, workspace_id, uid, uid,
                bytes.fromhex("22" * 32),
            ]
        case "artifact_facts":
            return [uid, tenant_id, workspace_id, uid]
        case "idempotency_keys":
            return [uid, bytes.fromhex("33" * 32)]
        case "audit_log":
            return [uid, tenant_id, workspace_id]
        case _:
            raise NotImplementedError(f"no seed parameters for {table.name}")


#: DELETE statements run before seeding, in reverse FK order, so a row planted
#: by an earlier (possibly buggy) run cannot survive ``ON CONFLICT DO NOTHING``
#: and mask a real regression.  Executed as the BYPASSRLS worker role.
_PURGE_ORDER: tuple[tuple[str, str], ...] = (
    ("findings", "finding_uid IN (%s, %s)"),
    ("artifact_facts", "fact_uid IN (%s, %s)"),
    ("rule_run", "run_id IN (%s, %s)"),
    ("rule_baseline", "rule_id IN (%s, %s)"),
    ("rule_source", "rule_id IN (%s, %s)"),
    ("ioc_entry", "pack_id IN (%s, %s)"),
    ("job_attempts", "job_id IN (%s, %s)"),
    ("events", "event_uid IN (%s, %s)"),
    ("uploads", "artifact_id IN (%s, %s)"),
    ("rules", "rule_id IN (%s, %s)"),
    ("ioc_pack", "pack_id IN (%s, %s)"),
    ("jobs", "job_id IN (%s, %s)"),
    ("detection_runs", "run_id IN (%s, %s)"),
    ("idempotency_keys", "key IN ('rls-a', 'rls-b') OR principal_id IN (%s, %s)"),
    ("audit_log", "audit_uid IN (%s, %s)"),
    ("fim_baseline", "host_key IN ('host-a', 'host-b')"),
    ("retention_policies", "tenant_id = 'tenant-b' AND workspace_id = 'ws-b'"),
    ("principals", "id IN (%s, %s)"),
    ("raw_objects", "sha256 IN (%s, %s)"),
)


def purge_seeded_rows(settings) -> int:
    """Delete every row the seed could have planted (worker role, BYPASSRLS)."""
    from sentinel_core.db import tx

    removed = 0
    with tx(settings.database_worker_url) as conn:
        for table, predicate in _PURGE_ORDER:
            if "%s" in predicate:
                params = (SHA_A, SHA_B) if table == "raw_objects" else (UID, UID_B)
                n = conn.execute(
                    f"DELETE FROM {table} WHERE {predicate}", params
                ).rowcount
            else:
                n = conn.execute(f"DELETE FROM {table} WHERE {predicate}").rowcount
            removed += n
        conn.commit()
    return removed


def seed_tenant_rows(settings, tenant: tuple[str, str], *, worker: bool) -> int:
    """Insert one row per seedable table for ``tenant``.

    ``worker=False`` uses the app role with the tenancy GUCs set (so the insert
    is checked by the policy); ``worker=True`` uses the BYPASSRLS worker role
    (used for tenant B so its rows exist without needing app-role visibility).
    Returns the number of rows attempted.
    """
    from sentinel_core.db import tx
    from sentinel_core.rls import set_rls

    url = settings.database_worker_url if worker else settings.database_url
    written = 0
    with tx(url) as conn:
        if not worker:
            set_rls(conn, tenant[0], tenant[1])
        for table in SEEDED_TABLES:
            if table.seed_a is None and not worker:
                continue
            if table.seed_b is None and worker:
                continue
            stmt = table.seed_a if not worker else table.seed_b
            if stmt is None:
                continue
            params = _params(table, tenant)
            conn.execute(stmt, params)
            written += 1
        conn.commit()
    return written


def count_visible(settings, *, tenant: tuple[str, str] | None, table: str) -> int:
    """Count rows of ``table`` visible under the given tenancy (None = unscoped)."""
    from sentinel_core.db import tx
    from sentinel_core.rls import set_rls

    with tx(settings.database_url) as conn:
        if tenant is not None:
            set_rls(conn, tenant[0], tenant[1])
        row = conn.execute(f"SELECT count(*) FROM {table}").fetchone()
        return int(row[0])


def count_owned_by(
    settings,
    *,
    viewer: tuple[str, str] | None,
    table: str,
    owner: tuple[str, str],
    #: table whose SeededTable metadata supplies the ownership marker; defaults
    #: to ``table`` itself.  A partition child has no entry of its own, so pass
    #: the parent name here while querying the child.
    marker_table: str | None = None,
) -> int:
    """Count rows of ``table`` **owned by** ``owner`` that ``viewer`` can see.

    This is the honest cross-tenant probe: "rows visible to tenant B" and "rows
    of tenant B visible to tenant A" are different questions, and only the
    second one tests the policy.  ``viewer=None`` means an unscoped session
    (GUCs NULL), which must see zero foreign rows on every scoped table.
    """
    from sentinel_core.db import tx
    from sentinel_core.rls import set_rls

    meta = _TABLE_BY_NAME[marker_table or table]
    col = meta.marker_column
    if col is None:
        raise ValueError(
            f"{meta.name} has no ownership marker; it is exempt from the "
            "cross-tenant probe (see SeededTable.unscoped_visible)"
        )
    with tx(settings.database_url) as conn:
        if viewer is not None:
            set_rls(conn, viewer[0], viewer[1])
        row = conn.execute(
            f"SELECT count(*) FROM {table} WHERE {col} = %s",
            (meta.marker_for(owner),),
        ).fetchone()
        return int(row[0])
