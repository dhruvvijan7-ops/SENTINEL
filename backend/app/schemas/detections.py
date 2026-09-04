from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

DetectionSeverity = Literal["critical", "high", "medium", "low"]
DetectionStatus = Literal["new", "investigating", "resolved"]


class DetectionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    analysis_run_id: str | None
    detector_id: str | None = None
    detector_version: str | None = None
    detection_type: str
    title: str
    description: str
    severity: DetectionSeverity
    status: DetectionStatus
    confidence: int
    source_ip: str | None
    destination_ip: str | None
    protocol: str | None
    evidence: dict[str, object]
    source_events: list[str] | None = None
    created_at: datetime


class DetectionListResponse(BaseModel):
    items: list[DetectionResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class DetectionUpdateRequest(BaseModel):
    status: DetectionStatus


class AnalysisRunSummary(BaseModel):
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


class AlertSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    detection_id: str | None
    severity: str
    status: str
    title: str
    description: str
    source: str
    created_at: datetime
    updated_at: datetime | None


class DetectionDetailResponse(BaseModel):
    detection: DetectionResponse
    analysis_run: AnalysisRunSummary | None
    alerts: list[AlertSummary]
    other_detections_in_run: int
