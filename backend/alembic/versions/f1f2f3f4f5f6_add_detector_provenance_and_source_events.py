"""add detector provenance and source_events to detections

Revision ID: f1f2f3f4f5f6
Revises: e1f2a3b4c5d6
Create Date: 2026-09-04 12:00:00.000000

Adds structured detector provenance (detector_id, detector_version) and a
compact, JSON-serialized source_events reference list to the detections table,
per Phase 2 persistence requirements. Alert.source is preserved for
backward compatibility.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f1f2f3f4f5f6'
down_revision: Union[str, Sequence[str], None] = 'e1f2a3b4c5d6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("detections", sa.Column("detector_id", sa.String(64), nullable=True))
    op.add_column("detections", sa.Column("detector_version", sa.String(32), nullable=True))
    op.add_column("detections", sa.Column("source_events", sa.JSON(), nullable=True))
    op.create_index("ix_detections_detector_id", "detections", ["detector_id"])


def downgrade() -> None:
    op.drop_index("ix_detections_detector_id", table_name="detections")
    op.drop_column("detections", "source_events")
    op.drop_column("detections", "detector_version")
    op.drop_column("detections", "detector_id")
