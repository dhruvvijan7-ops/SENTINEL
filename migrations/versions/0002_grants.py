"""Grant DML to the app and worker roles.

schema.sql is contract text and contains no GRANTs (roles are infrastructure,
not schema).  Stage-6 §1: "the application role is a separate login with
GRANTed DML only — no BYPASSRLS, no ownership".  The worker role is the
platform processor (BYPASSRLS) but still gets explicit table grants so a
future non-bypass worker works unchanged.
"""
from __future__ import annotations

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

_TABLES = (
    "tenants workspaces principals raw_objects uploads events rules rule_source "
    "rule_baseline fim_baseline ioc_pack ioc_entry jobs job_attempts "
    "detection_runs rule_run findings artifact_facts idempotency_keys "
    "audit_log retention_policies"
)

# Partition children inherit privileges from the parent in PG (GRANT on the
# partitioned table does NOT cascade to existing partitions in older versions;
# PG 17+ does propagate.  Target engine is PG18 → parent grants suffice, but we
# grant on partitions too for safety when restoring logical dumps.)
_PARTITIONED = "events findings audit_log rule_baseline"


def upgrade() -> None:
    for role in ("sentinel_app", "sentinel_worker"):
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role}")
        op.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}")
        op.execute(
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {role}"
        )


def downgrade() -> None:
    for role in ("sentinel_app", "sentinel_worker"):
        op.execute(f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {role}")
        op.execute(f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {role}")
