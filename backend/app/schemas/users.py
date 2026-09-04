from __future__ import annotations

import math
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    name: str
    role: str
    is_active: bool
    created_at: datetime
    updated_at: datetime | None


class UserListResponse(BaseModel):
    items: list[UserResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class UserUpdateRequest(BaseModel):
    role: str | None = Field(default=None, pattern=r"^(admin|analyst|viewer)$")
    is_active: bool | None = None


class UserCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: str
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(default="analyst", pattern=r"^(admin|analyst)$")

