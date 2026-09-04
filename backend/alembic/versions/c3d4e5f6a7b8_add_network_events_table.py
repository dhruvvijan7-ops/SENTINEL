"""add network_events table

Revision ID: c3d4e5f6a7b8
Revises: 418f2964dd27
Create Date: 2026-08-25 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, Sequence[str], None] = '418f2964dd27'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("DROP TABLE IF EXISTS network_events")

    op.create_table(
        "network_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("analysis_run_id", sa.String(36), nullable=True),
        sa.Column("detection_id", sa.String(36), nullable=True),
        sa.Column("alert_id", sa.String(36), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("destination_ip", sa.String(45), nullable=True),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(16), nullable=True),
        sa.Column("connection_id", sa.String(128), nullable=True),
        sa.Column("syscall_name", sa.String(64), nullable=True),
        sa.Column("sequence_index", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("event_index", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_index("ix_network_events_analysis_run_id", "network_events", ["analysis_run_id"])
    op.create_index("ix_network_events_detection_id", "network_events", ["detection_id"])
    op.create_index("ix_network_events_alert_id", "network_events", ["alert_id"])
    op.create_index("ix_network_events_timestamp", "network_events", ["timestamp"])
    op.create_index("ix_network_events_source_ip", "network_events", ["source_ip"])
    op.create_index("ix_network_events_destination_ip", "network_events", ["destination_ip"])
    op.create_index("ix_network_events_destination_port", "network_events", ["destination_port"])
    op.create_index("ix_network_events_protocol", "network_events", ["protocol"])
    op.create_index("ix_network_events_connection_id", "network_events", ["connection_id"])
    op.create_index("ix_network_events_created_at", "network_events", ["created_at"])
    op.create_index("ix_network_events_src_dst", "network_events", ["source_ip", "destination_ip"])
    op.create_index("ix_network_events_run_timestamp", "network_events", ["analysis_run_id", "timestamp"])


def downgrade() -> None:
    op.drop_table("network_events")
