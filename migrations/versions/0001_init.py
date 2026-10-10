"""Baseline: execute schema.sql verbatim as the migrator (owner) role.

schema.sql is the DDL authority; this migration never rewrites it.  BEGIN /
COMMIT lines are stripped because Alembic already owns the transaction.
"""
from __future__ import annotations

import re
from pathlib import Path

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

_SCHEMA_SQL = Path(__file__).resolve().parents[2] / "schema.sql"


def upgrade() -> None:
    import sqlalchemy as sa

    sql = _SCHEMA_SQL.read_text(encoding="utf-8")
    sql = re.sub(r"^\s*BEGIN;\s*$", "", sql, flags=re.IGNORECASE | re.MULTILINE)
    sql = re.sub(r"^\s*COMMIT;\s*$", "", sql, flags=re.IGNORECASE | re.MULTILINE)
    op.get_bind().execute(sa.text(sql))


def downgrade() -> None:
    raise RuntimeError(
        "downgrade not supported: schema.sql is forward-only (Stage-6 §7); "
        "restore from backup instead"
    )
