from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    database_url: str
    frontend_origin: str
    jwt_secret_key: str
    jwt_algorithm: str
    access_token_expire_minutes: int


def get_settings() -> Settings:
    return Settings(
        database_url=os.getenv("DATABASE_URL", "sqlite:///./sentinelai.db"),
        frontend_origin=os.getenv("FRONTEND_ORIGIN", "http://localhost:5173"),
        jwt_secret_key=os.getenv("JWT_SECRET_KEY", "dev-secret-change-in-production"),
        jwt_algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
        access_token_expire_minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")),
    )


settings = get_settings()
