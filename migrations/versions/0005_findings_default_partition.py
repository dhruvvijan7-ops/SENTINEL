"""Catch-all partition for ``findings`` (M2-A12).

``findings.time_utc`` is the *event* instant: the §6.6 timeline unions
findings with events by their own time, so a finding must be bucketed where
the event sits, not where the detection ran.  A capture imported today can
carry an event from any date in the past, and the three maintained monthly
partitions only cover the MVP window — without a default partition the first
historical EVTX dies with

    no partition of relation "findings" found for row

which takes the whole M2 vertical slice down with it.

Idempotent by construction (``IF NOT EXISTS`` for both the partition and its
policy) so re-running is safe; ``partition_maintain`` may later ATTACH a
tighter range by sweeping this child first.

See research/DEVIATION_REGISTER.md (M2-A12).
"""
from __future__ import annotations

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

_TENANT_WORKSPACE_USING = """(
    tenant_id = current_setting('sentinel.tenant_id', true)
    AND workspace_id = current_setting('sentinel.workspace_id', true)
)"""


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS findings_default PARTITION OF findings
        DEFAULT
        """
    )
    op.execute("ALTER TABLE findings_default ENABLE ROW LEVEL SECURITY")
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies
                WHERE schemaname = 'public'
                  AND tablename  = 'findings_default'
                  AND policyname  = 'findings_default_ws'
            ) THEN
                CREATE POLICY findings_default_ws ON findings_default
                    USING {_TENANT_WORKSPACE_USING};
            END IF;
        END
        $$
        """
    )


def downgrade() -> None:
    # Forward-only (spec §7.2).  Dropping the catch-all would re-open the
    # partition-routing failure this migration closes, so it is a no-op.
    pass
