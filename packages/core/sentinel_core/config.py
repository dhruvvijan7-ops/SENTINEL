"""Sentinel configuration — spec §4 is the contract.

Precedence (D6-010): **environment ``SENTINEL_*`` > ``sentinel.toml`` > built-in
default**. File format TOML; env names map ``section.key`` →
``SENTINEL_SECTION__KEY`` (double underscore = nesting), with the pre-M0 flat
form ``SENTINEL_<FIELD>`` still honoured so an existing deployment does not go
dark on upgrade.

``CONFIG_KEYS`` is the frozen key inventory: one entry per spec §4 table row
(``origin="spec §4"``) plus the keys the 3-role docker topology needs and §4
omitted (``origin="M0-A2"``, see ``research/DEVIATION_REGISTER.md``). A key
cannot appear on ``Settings`` without either a spec row or an M0-A2 entry —
``tests/contract/test_config_freeze.py`` enforces that in both directions.
"""
from __future__ import annotations

import hashlib
import json
import os
import tomllib
import uuid
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

CONFIG_PATH_ENV = "SENTINEL_CONFIG"
DEFAULT_CONFIG_CANDIDATES = (
    Path("configs/config.toml"),
    Path("configs/config.example.toml"),
)

#: Keys whose value is a credential and must never be logged or hashed in the
#: clear. The effective config is logged redacted and the redacted form is what
#: ``config_hash`` digests (spec §4).
SECRET_FIELDS: frozenset[str] = frozenset(
    {"database_url", "database_migrator_url", "database_worker_url", "auth_dev_keys"}
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
class Argon2Params:
    """OWASP 2024 baseline for ``security.argon2_params`` (spec §4)."""

    time_cost: int = 3
    memory_cost: int = 65536
    parallelism: int = 4
    hash_len: int = 32
    salt_len: int = 16


@dataclass(frozen=True)
class ConfigKey:
    """One row of the frozen configuration inventory."""

    field: str
    section: str
    key: str
    kind: str  # str | int | bool | opt_str | enum | table | dev_keys
    default: object
    origin: str  # "spec §4" or "M0-A2"
    note: str = ""


@dataclass(frozen=True)
class Settings:
    # --- spec §4: server ------------------------------------------------
    server_host: str = "127.0.0.1"
    server_port: int = 8000
    server_workers: int = 1

    # --- spec §4: database ----------------------------------------------
    database_url: str = ""
    database_pool_min: int = 5
    database_pool_max: int = 20
    # --- M0-A2: the two extra roles the 3-role topology logs in as -------
    database_migrator_url: str = ""
    database_worker_url: str = ""

    # --- spec §4: storage ------------------------------------------------
    storage_backend: str = "fs"
    storage_root: str = r"C:\ProgramData\Sentinel\data"
    storage_archive_uri: str | None = None

    # --- spec §4: jobs ---------------------------------------------------
    jobs_worker_id: str = ""
    jobs_claim_concurrency: int = 8
    jobs_heartbeat_seconds: int = 15
    jobs_lease_seconds: int = 60
    jobs_backoff_base_seconds: int = 5
    jobs_backoff_cap_minutes: int = 15
    jobs_max_attempts: int = 5
    # --- M0-A2: worker process tuning, not queue policy ------------------
    worker_poll_interval_ms: int = 200

    # --- spec §4: ingest (Stage-3 hostile-file gate, D8-05-fix) ----------
    ingest_max_request_bytes: int = 67108864
    ingest_max_file_bytes: int = 67108864
    ingest_max_field_bytes: int = 8192
    ingest_gate_timeout_seconds: int = 30
    # --- M0-A2: §3.2 admission controls expressed as configuration -------
    ingest_max_concurrent_uploads_per_principal: int = 4
    ingest_upload_hourly_quota_per_principal: int = 500
    ingest_storage_quota_bytes: int = 53687091200

    # --- spec §4: detection ----------------------------------------------
    detection_statement_timeout_ms: int = 60000
    detection_native_enabled: bool = True
    detection_cold_start_policy: str = "stage5-§4.8"

    # --- spec §4: retention ----------------------------------------------
    retention_raw_days: int = 90
    retention_event_days: int = 365
    retention_finding_days: int = 730
    retention_legal_hold_enabled: bool = True

    # --- spec §4: observability -------------------------------------------
    observability_log_level: str = "info"
    observability_log_format: str = "json"
    observability_metrics_enabled: bool = True
    observability_otel_endpoint: str | None = None

    # --- spec §4: security -------------------------------------------------
    security_api_key_header: str = "X-API-Key"
    security_argon2_params: Argon2Params = field(default_factory=Argon2Params)
    security_windows_dpapi: bool = True

    # --- M0-A2: dev-only API keys (Stage-6 auth replaces this stub) -------
    auth_dev_keys: tuple[DevKey, ...] = ()

    # -- helpers ----------------------------------------------------------
    def dev_key(self, presented: str) -> DevKey | None:
        for dk in self.auth_dev_keys:
            if dk.key == presented:
                return dk
        return None

    def as_dict(self) -> dict[str, object]:
        """Canonical mapping of every config field (used by hash + logging)."""
        out: dict[str, object] = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if isinstance(value, Argon2Params):
                value = asdict(value)
            elif isinstance(value, tuple):
                value = [
                    {**asdict(v), "scopes": list(v.scopes)}
                    if isinstance(v, DevKey)
                    else v
                    for v in value
                ]
            out[f.name] = value
        return out

    def redacted(self) -> dict[str, object]:
        """``as_dict`` with every credential replaced by ``***`` (spec §4)."""
        out = self.as_dict()
        for name in SECRET_FIELDS:
            if name not in out:
                continue
            out[name] = "***" if name != "auth_dev_keys" else [
                {**dk, "key": "***"} for dk in out[name]  # type: ignore[union-attr]
            ]
        return out


def config_hash(settings: Settings) -> str:
    """SHA-256 of the redacted effective config, lowercase hex (C-7-fix).

    ``detection_runs.config_hash`` stores the raw 32-byte digest; the wire form
    (OpenAPI ``^[0-9a-f]{64}$``) is exactly this string.
    """
    payload = json.dumps(
        settings.redacted(), sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


_logged_config_hash: str | None = None


def log_effective_config(settings: Settings) -> str:
    """Emit the loaded, redacted effective config once at startup (spec §4).

    Returns the run's ``config_hash``. Subsequent calls in the same process are
    no-ops unless the config actually changed, so an app factory invoked by a
    test suite does not spam one line per test.
    """
    global _logged_config_hash
    digest = config_hash(settings)
    if _logged_config_hash == digest:
        return digest
    _logged_config_hash = digest
    from sentinel_core.logging import get_logger

    get_logger("config").info(
        "config.loaded",
        config_hash=digest,
        config=settings.redacted(),
    )
    return digest


# ---------------------------------------------------------------------------
# The frozen inventory
# ---------------------------------------------------------------------------
_SPEC = "spec §4"
_A2 = "M0-A2"

CONFIG_KEYS: tuple[ConfigKey, ...] = (
    ConfigKey("server_host", "server", "host", "str", "127.0.0.1", _SPEC,
              "never bind 0.0.0.0 by default"),
    ConfigKey("server_port", "server", "port", "int", 8000, _SPEC,
              "config.example.toml keeps 8080 for M1 dev"),
    ConfigKey("server_workers", "server", "workers", "int", 1, _SPEC,
              "uvicorn workers; jobs run in the worker process"),
    ConfigKey("database_url", "database", "url", "str", "", _SPEC,
              "psycopg DSN for the app role; required in production"),
    ConfigKey("database_pool_min", "database", "pool_min", "int", 5, _SPEC, ""),
    ConfigKey("database_pool_max", "database", "pool_max", "int", 20, _SPEC,
              "hard cap; gate 503s when saturated"),
    ConfigKey("database_migrator_url", "database", "migrator_url", "str", "", _A2,
              "migration role DSN (schema owner)"),
    ConfigKey("database_worker_url", "database", "worker_url", "str", "", _A2,
              "BYPASSRLS worker role DSN"),
    ConfigKey("storage_backend", "storage", "backend", "enum", "fs", _SPEC,
              "fs | s3 (s3 = OQ-6-03, not MVP)"),
    ConfigKey("storage_root", "storage", "root", "str",
              r"C:\ProgramData\Sentinel\data", _SPEC,
              "content-addressed root (§1.2); ACL: service account only"),
    ConfigKey("storage_archive_uri", "storage", "archive_uri", "opt_str", None, _SPEC,
              "when set, purge archives before delete (§1.6)"),
    ConfigKey("jobs_worker_id", "jobs", "worker_id", "str", "", _SPEC,
              "appears in jobs.locked_by; default derives from hostname+pid"),
    ConfigKey("jobs_claim_concurrency", "jobs", "claim_concurrency", "int", 8, _SPEC,
              "PROPOSED"),
    ConfigKey("jobs_heartbeat_seconds", "jobs", "heartbeat_seconds", "int", 15, _SPEC,
              "PROPOSED"),
    ConfigKey("jobs_lease_seconds", "jobs", "lease_seconds", "int", 60, _SPEC,
              "PROPOSED; reaper threshold"),
    ConfigKey("jobs_backoff_base_seconds", "jobs", "backoff_base_seconds", "int", 5,
              _SPEC, "PROPOSED, full jitter"),
    ConfigKey("jobs_backoff_cap_minutes", "jobs", "cap_minutes", "int", 15, _SPEC,
              "PROPOSED, full jitter"),
    ConfigKey("jobs_max_attempts", "jobs", "max_attempts", "int", 5, _SPEC,
              "dead-letter after"),
    ConfigKey("worker_poll_interval_ms", "worker", "poll_interval_ms", "int", 200,
              _A2, "worker process idle poll, not queue policy"),
    ConfigKey("ingest_max_request_bytes", "ingest", "max_request_bytes", "int",
              67108864, _SPEC, "GATE_REQUEST_TOO_LARGE; 64 MiB"),
    ConfigKey("ingest_max_file_bytes", "ingest", "max_file_bytes", "int", 67108864,
              _SPEC, "GATE_FILE_TOO_LARGE; 64 MiB"),
    ConfigKey("ingest_max_field_bytes", "ingest", "max_field_bytes", "int", 8192,
              _SPEC, "GATE_FIELD_TOO_LARGE; 8 KiB"),
    ConfigKey("ingest_gate_timeout_seconds", "ingest", "gate_timeout_seconds", "int",
              30, _SPEC, "GATE_TIMEOUT; Stage-3 request wall-clock"),
    ConfigKey("ingest_max_concurrent_uploads_per_principal", "ingest",
              "max_concurrent_uploads_per_principal", "int", 4, _A2, ""),
    ConfigKey("ingest_upload_hourly_quota_per_principal", "ingest",
              "upload_hourly_quota_per_principal", "int", 500, _A2, ""),
    ConfigKey("ingest_storage_quota_bytes", "ingest", "storage_quota_bytes", "int",
              53687091200, _A2, "50 GiB per workspace"),
    ConfigKey("detection_statement_timeout_ms", "detection", "statement_timeout_ms",
              "int", 60000, _SPEC, "per-rule SQL budget (Stage 5)"),
    ConfigKey("detection_native_enabled", "detection", "native_enabled", "bool", True,
              _SPEC, "fallback evaluator"),
    ConfigKey("detection_cold_start_policy", "detection", "cold_start_policy", "str",
              "stage5-§4.8", _SPEC, "pointer to Stage 5 defaults"),
    ConfigKey("retention_raw_days", "retention", "raw_days", "int", 90, _SPEC,
              "seeds retention_policies"),
    ConfigKey("retention_event_days", "retention", "event_days", "int", 365, _SPEC,
              "seeds retention_policies"),
    ConfigKey("retention_finding_days", "retention", "finding_days", "int", 730,
              _SPEC, "seeds retention_policies"),
    ConfigKey("retention_legal_hold_enabled", "retention", "legal_hold_enabled",
              "bool", True, _SPEC, "operator flag honoured by purge"),
    ConfigKey("observability_log_level", "observability", "log_level", "enum", "info",
              _SPEC, ""),
    ConfigKey("observability_log_format", "observability", "log_format", "enum",
              "json", _SPEC, "structlog JSON"),
    ConfigKey("observability_metrics_enabled", "observability", "metrics_enabled",
              "bool", True, _SPEC, "/metrics on loopback"),
    ConfigKey("observability_otel_endpoint", "observability", "otel_endpoint",
              "opt_str", None, _SPEC, "traces off unless set"),
    ConfigKey("security_api_key_header", "security", "api_key_header", "str",
              "X-API-Key", _SPEC, ""),
    ConfigKey("security_argon2_params", "security", "argon2_params", "table",
              "OWASP-2024 baseline", _SPEC, ""),
    ConfigKey("security_windows_dpapi", "security", "windows.dpapi", "bool", True,
              _SPEC, "encrypt secrets at rest via DPAPI when not supplied via env"),
    ConfigKey("auth_dev_keys", "auth", "dev_keys", "dev_keys", (), _A2,
              "dev-only API keys; Stage-6 auth service replaces this stub"),
)

_SPEC_ORIGIN_KEYS = tuple(k for k in CONFIG_KEYS if k.origin == _SPEC)
_A2_ORIGIN_KEYS = tuple(k for k in CONFIG_KEYS if k.origin == _A2)


def _env_names(key: ConfigKey) -> tuple[str, ...]:
    """Spec form first (``SENTINEL_SECTION__KEY``), then the pre-M0 flat form.

    ``LEGACY_ENV_ALIASES`` adds a third candidate: the env name the pre-M0
    ``Settings`` field used, so an operator's existing systemd/WinSW unit file
    keeps taking effect across the rename.
    """
    spec = "SENTINEL_" + key.section.upper() + "__" + key.key.upper().replace(
        ".", "__"
    )
    flat = "SENTINEL_" + key.field.upper()
    names = [spec]
    if flat != spec:
        names.append(flat)
    for old_name, field_name in LEGACY_ENV_ALIASES.items():
        if field_name == key.field and old_name not in names:
            names.append(old_name)
    return tuple(names)


#: pre-M0 ``Settings`` field → env variable name that used to override it.
LEGACY_ENV_ALIASES: dict[str, str] = {
    "SENTINEL_API_BIND_HOST": "server_host",
    "SENTINEL_API_BIND_PORT": "server_port",
    "SENTINEL_MIGRATOR_URL": "database_migrator_url",
    "SENTINEL_WORKER_URL": "database_worker_url",
    "SENTINEL_WORKER_ID": "jobs_worker_id",
    "SENTINEL_WORKER_CLAIM_BATCH": "jobs_claim_concurrency",
    "SENTINEL_STORAGE_LOCAL_DIR": "storage_root",
    "SENTINEL_RETENTION_DAYS_RAW_OBJECT": "retention_raw_days",
    "SENTINEL_MAX_REQUEST_BYTES": "ingest_max_request_bytes",
    "SENTINEL_MAX_FILE_BYTES": "ingest_max_file_bytes",
    "SENTINEL_MAX_FIELD_BYTES": "ingest_max_field_bytes",
    "SENTINEL_REQUEST_TIMEOUT_S": "ingest_gate_timeout_seconds",
    "SENTINEL_MAX_CONCURRENT_UPLOADS_PER_PRINCIPAL":
        "ingest_max_concurrent_uploads_per_principal",
    "SENTINEL_UPLOAD_HOURLY_QUOTA_PER_PRINCIPAL":
        "ingest_upload_hourly_quota_per_principal",
    "SENTINEL_STORAGE_QUOTA_BYTES": "ingest_storage_quota_bytes",
    "SENTINEL_API_KEY_HEADER": "security_api_key_header",
    "SENTINEL_LOG_FORMAT": "observability_log_format",
}


def _coerce(value: str, kind: str, current: object) -> object:
    if kind == "bool":
        return value.strip().lower() in ("1", "true", "yes", "on")
    if kind == "int":
        return int(value)
    if kind == "opt_str":
        return None if value.strip() == "" else value
    return value


def _lookup(data: dict, key: ConfigKey) -> object:
    node: object = data
    for part in (key.section, *key.key.split(".")):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _from_toml(path: Path) -> dict[str, object]:
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    out: dict[str, object] = {}
    for key in CONFIG_KEYS:
        if key.kind == "dev_keys":
            raw = _lookup(data, key)
            if not raw:
                continue
            out[key.field] = tuple(
                DevKey(
                    key=entry["key"],
                    tenant_id=entry["tenant_id"],
                    workspace_id=entry["workspace_id"],
                    principal_id=str(uuid.UUID(str(entry["principal_id"]))),
                    display_name=entry.get("display_name", "dev"),
                    scopes=tuple(entry.get("scopes", ())),
                )
                for entry in raw
            )
            continue
        value = _lookup(data, key)
        if value is None:
            continue
        if key.kind == "table":
            value = Argon2Params(**value) if isinstance(value, dict) else value
        elif key.kind == "opt_str" and value == "":
            # an empty string in TOML is the file form of "unset"
            value = None
        out[key.field] = value
    return out


def load_settings(path: str | Path | None = None) -> Settings:
    """Load Settings: TOML file, then ``SENTINEL_*`` env overrides.

    Order (D6-010): env > file > built-in default. ``path`` wins over the
    ``SENTINEL_CONFIG`` env var, which wins over the default candidates.
    """
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

    defaults = Settings()
    merged: dict[str, object] = {
        f.name: base.get(f.name, getattr(defaults, f.name))
        for f in fields(Settings)
    }

    for key in CONFIG_KEYS:
        if key.kind in ("table", "dev_keys"):
            continue  # structured values are file-only; env cannot express them
        for env_name in _env_names(key):
            raw = os.environ.get(env_name)
            if raw is not None:
                merged[key.field] = _coerce(raw, key.kind, merged[key.field])
                break

    return Settings(**merged)
