"""Partition-level row-level security (M0-A1).

Declarative partition children do NOT inherit ``ENABLE ROW LEVEL SECURITY``
from their parent, and ``CREATE POLICY ... ON parent`` does not apply to
children either.  schema.sql (post-M0) therefore enables and polices all 11
partition children explicitly; this migration brings databases that were
created before that contract change — e.g. the live dev database, which is
already at 0003 — up to the same shape.

Idempotent by construction: ``ENABLE ROW LEVEL SECURITY`` is a no-op when
already enabled, and every ``CREATE POLICY`` is guarded by an
``IF NOT EXISTS (SELECT FROM pg_policies)`` check so re-running is safe.

Children and the USING expression they inherit from their parent:

  events         → events_2026_10 / _11 / _12
  findings       → findings_2026_10 / _11 / _12
  audit_log      → audit_log_2026_10 / _11 / _12
  rule_baseline  → rule_baseline_2026 / _2027

See research/DEVIATION_REGISTER.md (M0-A1) for the amendment record.
"""
from __future__ import annotations

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

# (child table, parent table) — the USING expression is the parent's.
PARTITIONS: tuple[tuple[str, str], ...] = (
    ("events_2026_10", "events"),
    ("events_2026_11", "events"),
    ("events_2026_12", "events"),
    ("findings_2026_10", "findings"),
    ("findings_2026_11", "findings"),
    ("findings_2026_12", "findings"),
    ("audit_log_2026_10", "audit_log"),
    ("audit_log_2026_11", "audit_log"),
    ("audit_log_2026_12", "audit_log"),
    ("rule_baseline_2026", "rule_baseline"),
    ("rule_baseline_2027", "rule_baseline"),
)

_TENANT_WORKSPACE_USING = """(
    tenant_id = current_setting('sentinel.tenant_id', true)
    AND workspace_id = current_setting('sentinel.workspace_id', true)
)"""


def upgrade() -> None:
    for child, _parent in PARTITIONS:
        op.execute(f"ALTER TABLE {child} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_policies
                    WHERE schemaname = 'public'
                      AND tablename  = '{child}'
                      AND policname  = '{child}_ws'
                ) THEN
                    CREATE POLICY {child}_ws ON {child}
                        USING {_TENANT_WORKSPACE_USING};
                END IF;
            END
            $$
            """
        )


def downgrade() -> None:
    # Forward-only (spec §7.2).  Dropping the policies would re-open the
    # cross-tenant read path this migration closes, so it is a no-op.
    pass
