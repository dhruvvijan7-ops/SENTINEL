from __future__ import annotations

import math
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    created_at: datetime
    actor_user_id: str | None
    actor_email: str | None
    actor_type: str
    category: str
    action: str
    result: str
    severity: str
    resource_type: str | None
    resource_id: str | None
    ip_address: str | None
    user_agent: str | None
    request_id: str | None
    metadata_json: dict[str, object] | None
    description: str | None


class AuditLogListResponse(BaseModel):
    items: list[AuditLogResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
