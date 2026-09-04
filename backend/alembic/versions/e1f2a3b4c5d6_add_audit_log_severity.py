"""add severity to audit_logs

Revision ID: e1f2a3b4c5d6
Revises: d4e5f6a7b8c9
Create Date: 2026-08-26 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e1f2a3b4c5d6'
down_revision: Union[str, Sequence[str], None] = 'd4e5f6a7b8c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("audit_logs", sa.Column("severity", sa.String(16), nullable=False, server_default="info"))
    op.create_index("ix_audit_logs_severity", "audit_logs", ["severity"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_severity", table_name="audit_logs")
    op.drop_column("audit_logs", "severity")
