from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    normal: int = 0


class MonitoringRunDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    source_type: str
    file_name: str
    status: str
    event_count: int
    sequence_count: int
    details: dict[str, object]
    submitted_at: datetime
    completed_at: datetime | None
    detection_count: int = 0
    alert_count: int = 0
    severity_counts: SeverityCounts = SeverityCounts()


class MonitoringRunListResponse(BaseModel):
    items: list[MonitoringRunDetail]


class MonitorRecordResponse(BaseModel):
    id: str
    record_type: str  # "detection" | "network_event"
    severity: str  # critical/high/medium/low/info/normal
    kind: str | None  # detection_type or syscall_name
    title: str | None
    description: str | None
    timestamp: datetime | None
    source_ip: str | None
    destination_ip: str | None
    protocol: str | None
    detection_id: str | None


class MonitorRecordListResponse(BaseModel):
    items: list[MonitorRecordResponse]
    total: int
    page: int
    page_size: int
    total_pages: int