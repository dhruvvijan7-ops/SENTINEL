from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    analysis_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    detector_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    detector_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    detection_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="new", index=True)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    evidence: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    source_events: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
