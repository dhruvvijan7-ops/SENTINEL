from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class NetworkEvent(Base):
    __tablename__ = "network_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    analysis_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    detection_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    connection_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    syscall_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sequence_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    event_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    __table_args__ = (
        Index("ix_network_events_src_dst", "source_ip", "destination_ip"),
        Index("ix_network_events_run_timestamp", "analysis_run_id", "timestamp"),
    )
