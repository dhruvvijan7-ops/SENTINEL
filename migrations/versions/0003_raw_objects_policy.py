"""raw_objects access policy.

schema.sql §9 enables RLS on raw_objects but creates no policy (the table has
no tenant column — shared CAS by design; "access is mediated entirely through
uploads (app-level join) — see Stage 6 §1.4").  RLS-enabled + policy-less =
deny-all for non-owners, which blocks the app role from INSERTing accepted
objects.  This migration adds the permissive policy that Stage-6 §1.4
implies: visibility of raw_objects rows is unrestricted at the SQL layer and
scoped by the uploads join in application code (repos_uploads,
get_upload_with_object).  Documented deviation register entry: M1-D3.
"""
from __future__ import annotations

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE POLICY raw_objects_cas ON raw_objects
            USING (true) WITH CHECK (true)
        """
    )


def downgrade() -> None:
    op.execute("DROP POLICY raw_objects_cas ON raw_objects")
