from __future__ import annotations

from sentinel_core.config import DevKey, Settings, load_settings


def test_load_example_config():
    s = load_settings("configs/config.example.toml")
    assert isinstance(s, Settings)
    assert s.max_file_bytes == 64 * 1024 * 1024
    assert s.max_field_bytes == 8192
    assert s.api_key_header == "X-API-Key"
    assert len(s.dev_keys) == 2
    assert s.dev_keys[0].tenant_id == "default"
    assert s.dev_keys[1].tenant_id == "tenant-b"


def test_env_override(monkeypatch):
    monkeypatch.setenv("SENTINEL_API_BIND_PORT", "9999")
    s = load_settings("configs/config.example.toml")
    assert s.api_bind_port == 9999


def test_dev_key_lookup():
    dk = DevKey(key="k", tenant_id="t", workspace_id="w", principal_id="p", display_name="d")
    s = Settings(database_url="", migrator_url="", dev_keys=(dk,))
    assert s.dev_key("k") is dk
    assert s.dev_key("nope") is None
