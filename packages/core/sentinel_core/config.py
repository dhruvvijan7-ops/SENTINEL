from __future__ import annotations

import os
import tomllib
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path

CONFIG_PATH_ENV = "SENTINEL_CONFIG"
DEFAULT_CONFIG_CANDIDATES = (
    Path("configs/config.toml"),
    Path("configs/config.example.toml"),
)


@dataclass(frozen=True)
class DevKey:
    key: str
    tenant_id: str
    workspace_id: str
    principal_id: str
    display_name: str
    scopes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Settings:
    database_url: str
    migrator_url: str
    worker_url: str = ""
    api_bind_host: str = "127.0.0.1"
    api_bind_port: int = 8080
    worker_id: str = ""
    worker_poll_interval_ms: int = 200
    worker_claim_batch: int = 4
    storage_local_dir: str = ".sentinel-data/objects"
    retention_days_raw_object: int = 90
    max_request_bytes: int = 64 * 1024 * 1024
    max_file_bytes: int = 64 * 1024 * 1024
    max_field_bytes: int = 8192
    request_timeout_s: int = 30
    max_concurrent_uploads_per_principal: int = 4
    upload_hourly_quota_per_principal: int = 500
    storage_quota_bytes: int = 50 * 1024**3
    api_key_header: str = "X-API-Key"
    log_format: str = "json"
    dev_keys: tuple[DevKey, ...] = ()

    def dev_key(self, presented: str) -> DevKey | None:
        for dk in self.dev_keys:
            if dk.key == presented:
                return dk
        return None


def _coerce(value: str, current: object) -> object:
    if isinstance(current, bool):
        return value.lower() in ("1", "true", "yes", "on")
    if isinstance(current, int):
        return int(value)
    return value


def _from_toml(path: Path) -> dict[str, object]:
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    flat: dict[str, object] = {}
    db = data.get("database", {})
    flat["database_url"] = db.get("url")
    flat["migrator_url"] = db.get("migrator_url")
    flat["worker_url"] = db.get("worker_url")
    api = data.get("api", {})
    flat["api_bind_host"] = api.get("bind_host")
    flat["api_bind_port"] = api.get("bind_port")
    worker = data.get("worker", {})
    flat["worker_id"] = worker.get("id")
    flat["worker_poll_interval_ms"] = worker.get("poll_interval_ms")
    flat["worker_claim_batch"] = worker.get("claim_batch")
    storage = data.get("storage", {})
    flat["storage_local_dir"] = storage.get("local_dir")
    flat["retention_days_raw_object"] = storage.get("retention_days_raw_object")
    limits = data.get("limits", {})
    for key in (
        "max_request_bytes",
        "max_file_bytes",
        "max_field_bytes",
        "request_timeout_s",
        "max_concurrent_uploads_per_principal",
        "upload_hourly_quota_per_principal",
        "storage_quota_bytes",
    ):
        if key in limits:
            flat[key] = limits[key]
    security = data.get("security", {})
    if "api_key_header" in security:
        flat["api_key_header"] = security["api_key_header"]
    log = data.get("log", {})
    if "format" in log:
        flat["log_format"] = log["format"]
    keys = []
    for entry in data.get("auth", {}).get("dev_keys", []):
        keys.append(
            DevKey(
                key=entry["key"],
                tenant_id=entry["tenant_id"],
                workspace_id=entry["workspace_id"],
                principal_id=str(uuid.UUID(str(entry["principal_id"]))),
                display_name=entry.get("display_name", "dev"),
                scopes=tuple(entry.get("scopes", ())),
            )
        )
    if keys:
        flat["dev_keys"] = tuple(keys)
    return {k: v for k, v in flat.items() if v is not None}


def load_settings(path: str | Path | None = None) -> Settings:
    """Load Settings: TOML file (SENTINEL_CONFIG env, path arg, or default
    candidate) then SENTINEL_<FIELD> environment overrides."""
    cfg_path: Path | None = None
    if path is not None:
        cfg_path = Path(path)
    elif os.environ.get(CONFIG_PATH_ENV):
        cfg_path = Path(os.environ[CONFIG_PATH_ENV])
    else:
        for candidate in DEFAULT_CONFIG_CANDIDATES:
            if candidate.exists():
                cfg_path = candidate
                break

    base: dict[str, object] = {}
    if cfg_path is not None and cfg_path.exists():
        base = _from_toml(cfg_path)

    defaults = Settings(database_url="", migrator_url="")
    merged: dict[str, object] = {}
    for name in defaults.__dataclass_fields__:
        if name in base and base[name] is not None:
            merged[name] = base[name]
        else:
            merged[name] = getattr(defaults, name)

    for name in defaults.__dataclass_fields__:
        env_val = os.environ.get(f"SENTINEL_{name.upper()}")
        if env_val is not None:
            merged[name] = _coerce(env_val, merged[name])

    return Settings(**merged)
