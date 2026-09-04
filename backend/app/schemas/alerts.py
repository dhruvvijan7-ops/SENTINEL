from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

AlertSeverity = Literal["critical", "high", "medium", "low"]
AlertStatus = Literal["new", "investigating", "resolved"]


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    detection_id: str | None
    severity: AlertSeverity
    status: AlertStatus
    title: str
    description: str
    source: str
    created_at: datetime
    updated_at: datetime | None


class AlertListResponse(BaseModel):
    items: list[AlertResponse]


class AlertUpdateRequest(BaseModel):
    status: AlertStatus
