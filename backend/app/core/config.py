from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()

_DEFAULT_DEV_SECRET = "dev-secret-change-in-production"
_MIN_SECRET_BYTES = 32
_ALLOWED_ALGORITHMS = {"HS256"}

logger = logging.getLogger(__name__)


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_url: str
    frontend_origin: str

    env: str
    jwt_secret_key: str
    jwt_algorithm: str
    jwt_issuer: str
    jwt_audience: str
    access_token_expire_minutes: int
    refresh_token_expire_days: int
    reset_token_expire_minutes: int

    cookie_access_name: str
    cookie_refresh_name: str
    cookie_secure: bool
    cookie_samesite: str
    cookie_domain: str | None

    client_header_name: str
    client_header_value: str

    debug_reset_returns_token: bool


def _validate_or_fail(**values: object) -> None:
    """Fail fast on an insecure configuration in production and validate
    shared invariants across all environments."""
    env = str(values["env"])
    secret = str(values["jwt_secret_key"] or "")
    algorithm = str(values["jwt_algorithm"] or "")

    if len(secret) < _MIN_SECRET_BYTES:
        raise RuntimeError(
            "JWT_SECRET_KEY must be at least 32 bytes. Generate one with "
            "`python -c \"import secrets; print(secrets.token_urlsafe(48))\"`."
        )

    if algorithm not in _ALLOWED_ALGORITHMS:
        raise RuntimeError(f"JWT_ALGORITHM must be one of: {sorted(_ALLOWED_ALGORITHMS)}.")

    if int(values["access_token_expire_minutes"]) < 5:
        raise RuntimeError("ACCESS_TOKEN_EXPIRE_MINUTES must be at least 5.")

    if int(values["refresh_token_expire_days"]) < 1:
        raise RuntimeError("REFRESH_TOKEN_EXPIRE_DAYS must be at least 1.")

    if int(values["reset_token_expire_minutes"]) < 5:
        raise RuntimeError("RESET_TOKEN_EXPIRE_MINUTES must be at least 5.")

    if values["cookie_samesite"] not in {"lax", "strict", "none"}:
        raise RuntimeError("AUTH_COOKIE_SAMESITE must be one of: lax, strict, none.")

    if str(values["cookie_samesite"]) == "none" and not values["cookie_secure"]:
        raise RuntimeError("AUTH_COOKIE_SAMESITE=none requires AUTH_COOKIE_SECURE=true.")

    if env == "production":
        if secret == _DEFAULT_DEV_SECRET:
            raise RuntimeError(
                "Refusing to start in production with the default JWT_SECRET_KEY. "
                "Set a strong, unique JWT_SECRET_KEY."
            )
        if not values["frontend_origin"]:
            raise RuntimeError("FRONTEND_ORIGIN must be set in production.")
        if not values["cookie_secure"]:
            raise RuntimeError("AUTH_COOKIE_SECURE must be true in production.")
        if values["debug_reset_returns_token"]:
            raise RuntimeError("DEBUG_RESET_RETURNS_TOKEN must be disabled in production.")


def get_settings() -> Settings:
    env = os.getenv("SENTINEL_ENV", "development").strip().lower()
    if env not in {"development", "production", "test"}:
        raise RuntimeError(f"Unknown SENTINEL_ENV: {env!r}. Use development, production, or test.")

    algorithm = os.getenv("JWT_ALGORITHM", "HS256")

    secret = os.getenv("JWT_SECRET_KEY", "")
    if not secret:
        if env == "production":
            raise RuntimeError(
                "Missing JWT_SECRET_KEY. Set a strong, unique secret before starting in production."
            )
        secret = secrets.token_urlsafe(48)
        logger.warning(
            "JWT_SECRET_KEY was not set; generated an ephemeral secret "
            "(tokens will not survive a restart). Set JWT_SECRET_KEY for persistent sessions."
        )
    elif secret == _DEFAULT_DEV_SECRET and env != "production":
        logger.warning(
            "JWT_SECRET_KEY is still the well-known development default. "
            "Set a strong, unique secret before deploying."
        )

    samesite = os.getenv("AUTH_COOKIE_SAMESITE", "lax").strip().lower()
    cookie_secure_default = env == "production"
    debug_reset_default = env != "production"

    values: dict[str, object] = {
        "database_url": os.getenv("DATABASE_URL", "sqlite:///./sentinelai.db"),
        "frontend_origin": os.getenv("FRONTEND_ORIGIN", "http://localhost:5173"),
        "env": env,
        "jwt_secret_key": secret,
        "jwt_algorithm": algorithm,
        "jwt_issuer": os.getenv("JWT_ISSUER", "sentinel.api"),
        "jwt_audience": os.getenv("JWT_AUDIENCE", "sentinel.frontend"),
        "access_token_expire_minutes": int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15")),
        "refresh_token_expire_days": int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "14")),
        "reset_token_expire_minutes": int(os.getenv("RESET_TOKEN_EXPIRE_MINUTES", "30")),
        "cookie_access_name": os.getenv("AUTH_COOKIE_ACCESS_NAME", "sentinel_access"),
        "cookie_refresh_name": os.getenv("AUTH_COOKIE_REFRESH_NAME", "sentinel_refresh"),
        "cookie_secure": _as_bool(os.getenv("AUTH_COOKIE_SECURE"), cookie_secure_default),
        "cookie_samesite": samesite,
        "cookie_domain": os.getenv("AUTH_COOKIE_DOMAIN") or None,
        "client_header_name": os.getenv("AUTH_CLIENT_HEADER_NAME", "x-sentinel-client"),
        "client_header_value": os.getenv("AUTH_CLIENT_HEADER_VALUE", "sentinel"),
        "debug_reset_returns_token": _as_bool(
            os.getenv("DEBUG_RESET_RETURNS_TOKEN"),
            debug_reset_default,
        ),
    }

    _validate_or_fail(**values)

    return Settings(**values)


settings = get_settings()