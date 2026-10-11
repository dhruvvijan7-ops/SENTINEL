"""raw_objects access policy.

Historical defect (M1-D3, now resolved — see research/DEVIATION_REGISTER.md):
schema.sql §9 enabled RLS on raw_objects but created no policy (the table has
no tenant column — shared CAS by design; "access is mediated entirely through
uploads (app-level join) — see Stage 6 §1.4").  RLS-enabled + policy-less =
deny-all for non-owners, which blocks the app role from INSERTing accepted
objects.

The fix landed in two places:
  * M0: schema.sql now ships ``CREATE POLICY raw_objects_cas`` directly, so a
    database created from the contract text already has it.
  * this migration, kept and made idempotent for pre-M0 databases that were
    built by alembic alone.

The policy itself is the permissive one Stage-6 §1.4 implies: visibility of
raw_objects rows is unrestricted at the SQL layer and scoped by the uploads
join in application code (repos_uploads, get_upload_with_object).
"""
from __future__ import annotations

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Idempotent: a database built from post-M0 schema.sql already has this
    # policy, so re-running must no-op instead of failing with
    # "policy raw_objects_cas for relation raw_objects already exists".
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies
                WHERE schemaname = 'public'
                  AND tablename  = 'raw_objects'
                  AND policyname  = 'raw_objects_cas'
            ) THEN
                CREATE POLICY raw_objects_cas ON raw_objects
                    USING (true) WITH CHECK (true);
            END IF;
        END
        $$
        """
    )


def downgrade() -> None:
    # Intentional no-op.  Since M0 the policy is part of the schema.sql
    # contract, so dropping it here would re-open the M1-D3 deny-all defect on
    # every database that ever ran this migration.  Migrations are forward-only
    # in MVP (spec §7.2), so a no-op downgrade is the safe default.
    pass
