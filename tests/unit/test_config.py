from __future__ import annotations

from sentinel_core.config import (
    CONFIG_KEYS,
    DevKey,
    Settings,
    config_hash,
    load_settings,
    log_effective_config,
)

EXAMPLE = "configs/config.example.toml"


def test_load_example_config():
    s = load_settings(EXAMPLE)
    assert isinstance(s, Settings)
    # spec §4 defaults that the example file deliberately overrides
    assert s.server_port == 8080
    assert s.ingest_max_file_bytes == 67108864
    assert s.ingest_max_field_bytes == 8192
    assert s.security_api_key_header == "X-API-Key"
    # spec §4 keys the example file does not touch keep their spec defaults
    assert s.server_host == "127.0.0.1"
    assert s.database_pool_min == 5 and s.database_pool_max == 20
    assert s.jobs_claim_concurrency == 8
    assert s.jobs_lease_seconds == 60
    assert s.detection_statement_timeout_ms == 60000
    assert s.retention_event_days == 365
    assert s.observability_log_level == "info"
    assert s.observability_metrics_enabled is True
    assert s.security_windows_dpapi is True
    assert s.security_argon2_params.memory_cost == 65536
    # M0-A2 extensions
    assert s.ingest_storage_quota_bytes == 53687091200
    assert s.worker_poll_interval_ms == 200
    assert len(s.auth_dev_keys) == 2
    assert s.auth_dev_keys[0].tenant_id == "default"
    assert s.auth_dev_keys[1].tenant_id == "tenant-b"


def test_spec_default_port_is_8000():
    """config.example.toml pins 8080 for M1 dev; the built-in default is 8000."""
    assert Settings().server_port == 8000


def test_env_override_spec_form(monkeypatch):
    monkeypatch.setenv("SENTINEL_SERVER__PORT", "9999")
    assert load_settings(EXAMPLE).server_port == 9999


def test_env_override_nested_spec_form(monkeypatch):
    monkeypatch.setenv("SENTINEL_SECURITY__WINDOWS__DPAPI", "false")
    assert load_settings(EXAMPLE).security_windows_dpapi is False


def test_env_override_flat_form(monkeypatch):
    """The pre-M0 flat spelling still works (SENTINEL_<FIELD>)."""
    monkeypatch.setenv("SENTINEL_SERVER_PORT", "7777")
    assert load_settings(EXAMPLE).server_port == 7777


def test_env_override_legacy_alias(monkeypatch):
    """The pre-M0 *field name* keeps working: SENTINEL_API_BIND_PORT."""
    monkeypatch.setenv("SENTINEL_API_BIND_PORT", "6666")
    assert load_settings(EXAMPLE).server_port == 6666


def test_spec_form_beats_legacy_alias(monkeypatch):
    monkeypatch.setenv("SENTINEL_SERVER__PORT", "9001")
    monkeypatch.setenv("SENTINEL_API_BIND_PORT", "6666")
    assert load_settings(EXAMPLE).server_port == 9001


def test_bool_and_int_coercion(monkeypatch):
    monkeypatch.setenv("SENTINEL_DETECTION__NATIVE_ENABLED", "off")
    monkeypatch.setenv("SENTINEL_JOBS__MAX_ATTEMPTS", "9")
    s = load_settings(EXAMPLE)
    assert s.detection_native_enabled is False
    assert s.jobs_max_attempts == 9


def test_opt_str_treats_empty_toml_string_as_unset():
    s = load_settings(EXAMPLE)
    assert s.storage_archive_uri is None
    assert s.observability_otel_endpoint is None


def test_dev_key_lookup():
    dk = DevKey(
        key="k", tenant_id="t", workspace_id="w", principal_id="p", display_name="d"
    )
    s = Settings(database_url="", auth_dev_keys=(dk,))
    assert s.dev_key("k") is dk
    assert s.dev_key("nope") is None


def test_every_field_is_in_the_frozen_inventory():
    """A key cannot exist on Settings without a spec §4 row or an M0-A2 entry."""
    from dataclasses import fields

    field_names = {f.name for f in fields(Settings)}
    key_names = {k.field for k in CONFIG_KEYS}
    assert field_names == key_names, (
        f"Settings-only: {sorted(field_names - key_names)}; "
        f"inventory-only: {sorted(key_names - field_names)}"
    )


def test_config_hash_is_stable_lowercase_hex():
    s = load_settings(EXAMPLE)
    digest = config_hash(s)
    assert len(digest) == 64
    assert digest == digest.lower()
    assert digest == config_hash(s)


def test_config_hash_ignores_secret_values():
    """config_hash digests the *redacted* config (spec §4), so rotating a
    password does not change the run's config_hash."""
    a = Settings(database_url="postgresql://user:aaaa@h/db")
    b = Settings(database_url="postgresql://user:bbbb@h/db")
    assert config_hash(a) == config_hash(b)
    assert a.redacted()["database_url"] == "***"


def test_config_hash_tracks_non_secret_changes():
    a = Settings(database_url="", server_port=8000)
    b = Settings(database_url="", server_port=8001)
    assert config_hash(a) != config_hash(b)


def test_redacted_hides_dev_keys():
    dk = DevKey(
        key="secret-key",
        tenant_id="t",
        workspace_id="w",
        principal_id="p",
        display_name="d",
    )
    s = Settings(database_url="", auth_dev_keys=(dk,))
    redacted = s.redacted()
    assert redacted["auth_dev_keys"][0]["key"] == "***"
    assert redacted["auth_dev_keys"][0]["tenant_id"] == "t"


def test_log_effective_config_emits_once():
    import sentinel_core.config as config_mod
    from structlog.testing import capture_logs

    config_mod._logged_config_hash = None  # reset the once-per-process guard
    s = load_settings(EXAMPLE)
    with capture_logs() as captured:
        first = log_effective_config(s)
        second = log_effective_config(s)
    assert first == second == config_hash(s)

    events = [e for e in captured if e["event"] == "config.loaded"]
    assert len(events) == 1, (
        "spec §4 requires the redacted effective config to be logged once at "
        f"startup; saw {len(events)} lines"
    )
    assert events[0]["config_hash"] == config_hash(s)
    # secrets are replaced by *** before the line is emitted
    assert events[0]["config"]["database_url"] == "***"
    assert events[0]["config"]["auth_dev_keys"][0]["key"] == "***"
