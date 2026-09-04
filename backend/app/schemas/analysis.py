from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AnalysisRunResponse(BaseModel):
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


class AnalysisRunListResponse(BaseModel):
    items: list[AnalysisRunResponse]
