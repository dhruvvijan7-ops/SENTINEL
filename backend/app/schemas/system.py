from datetime import datetime

from pydantic import BaseModel, Field


class SystemStatusResponse(BaseModel):
    api_status: str
    database_status: str
    light_hids_status: str
    light_hids_message: str


class DashboardSummaryResponse(BaseModel):
    analysis_runs: int
    analyzed_events: int
    detections: int
    open_alerts: int


class SystemSettingsResponse(BaseModel):
    max_upload_mb: int
    analysis_history_limit: int
    updated_at: datetime | None


class SystemSettingsUpdateRequest(BaseModel):
    max_upload_mb: int = Field(ge=1, le=100)
    analysis_history_limit: int = Field(ge=10, le=500)
