from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


class NetworkEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    analysis_run_id: str | None
    detection_id: str | None
    alert_id: str | None
    timestamp: datetime | None
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str | None
    connection_id: str | None
    syscall_name: str | None
    sequence_index: int
    event_index: int
    description: str | None
    created_at: datetime


class NetworkEventListResponse(BaseModel):
    items: list[NetworkEventResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class NetworkSummaryResponse(BaseModel):
    total_events: int
    unique_source_ips: int
    unique_destination_ips: int
    unique_ports: int
    protocols_observed: list[str]


class NetworkIPDetailResponse(BaseModel):
    ip_address: str
    first_seen: datetime | None
    last_seen: datetime | None
    total_events: int
    unique_destinations: int
    unique_sources: int
    unique_ports: int
    protocols: list[str]
    related_detections: int
    related_alerts: int


class NetworkPortResponse(BaseModel):
    port: int
    protocol: str | None
    event_count: int
    unique_sources: int
    unique_destinations: int
    first_seen: datetime | None
    last_seen: datetime | None


class NetworkPortListResponse(BaseModel):
    items: list[NetworkPortResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class NetworkProtocolResponse(BaseModel):
    protocol: str
    event_count: int
    percentage: float


class NetworkProtocolListResponse(BaseModel):
    items: list[NetworkProtocolResponse]


class NetworkTopTalkerResponse(BaseModel):
    ip_address: str
    connection_count: int
    unique_destinations: int
    unique_sources: int
    unique_ports: int
    direction: str


class NetworkTopTalkerListResponse(BaseModel):
    items: list[NetworkTopTalkerResponse]


class NetworkTimelinePoint(BaseModel):
    timestamp: datetime
    event_count: int


class NetworkTimelineResponse(BaseModel):
    items: list[NetworkTimelinePoint]
    interval: str


class NetworkEventDetailResponse(BaseModel):
    event: NetworkEventResponse
    related_detections: list[dict[str, object]]
    related_alerts: list[dict[str, object]]
