"""add detections table

Revision ID: a1b2c3d4e5f6
Revises: 6cf2881a4068
Create Date: 2026-08-21 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = '6cf2881a4068'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'detections',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('analysis_run_id', sa.String(36), nullable=True, index=True),
        sa.Column('detection_type', sa.String(64), nullable=False, index=True),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(16), nullable=False, index=True),
        sa.Column('confidence', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('source_ip', sa.String(45), nullable=True),
        sa.Column('destination_ip', sa.String(45), nullable=True),
        sa.Column('protocol', sa.String(16), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),
    )


def downgrade() -> None:
    op.drop_table('detections')
