"""OpenAPI conformance: the app's route table matches openapi.yaml paths
and the normative gate/error enums."""
from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = yaml.safe_load((ROOT / "openapi.yaml").read_text(encoding="utf-8"))


def _app_route_keys():
    from sentinel_core.config import Settings
    from sentinel_api.app import create_app

    app = create_app(Settings(database_url="", migrator_url=""))
    keys = set()

    def walk(routes):
        for route in routes:
            inner = getattr(route, "original_router", None)
            if inner is not None:
                walk(inner.routes)
                continue
            methods = getattr(route, "methods", None)
            if not methods:
                continue
            path = route.path
            for m in methods:
                if m in ("HEAD", "OPTIONS"):
                    continue
                keys.add((m.upper(), path))

    walk(app.routes)
    return keys


def test_required_endpoints_present():
    required = {
        ("GET", "/health"),
        ("GET", "/ready"),
        ("GET", "/metrics"),
        ("POST", "/v1/workspaces/{workspaceId}/uploads"),
        ("GET", "/v1/workspaces/{workspaceId}/uploads"),
        ("GET", "/v1/workspaces/{workspaceId}/uploads/{artifactId}"),
        ("GET", "/v1/workspaces/{workspaceId}/events"),
        ("POST", "/v1/workspaces/{workspaceId}/runs"),
        ("GET", "/v1/workspaces/{workspaceId}/runs"),
        ("GET", "/v1/workspaces/{workspaceId}/runs/{runId}"),
        ("GET", "/v1/workspaces/{workspaceId}/runs/{runId}/rule-runs"),
    }
    app_keys = _app_route_keys()
    missing = required - app_keys
    assert not missing, f"missing routes: {missing}"


def test_spec_upload_schema_fields():
    upload = SPEC["components"]["schemas"]["Upload"]
    props = set(upload["properties"])
    expected = {
        "artifact_id", "run_id", "sha256", "sha1", "md5", "size",
        "display_name", "collection_kind", "agent_id", "received_at",
        "gate_warnings", "triage_state",
    }
    assert expected <= props, f"Upload missing: {expected - props}"


def test_spec_error_schema():
    err = SPEC["components"]["schemas"]["Error"]
    assert set(err["properties"]) == {"code", "message", "details"}
    assert err["required"] == ["code", "message"]


def test_spec_readiness_schema():
    r = SPEC["components"]["schemas"]["Readiness"]
    assert set(r["properties"]) == {"status", "checks"}
    assert r["properties"]["status"]["enum"] == ["ok", "degraded"]


def test_spec_detection_run_status_enum():
    run = SPEC["components"]["schemas"]["DetectionRun"]
    assert run["properties"]["status"]["enum"] == [
        "queued", "running", "completed", "completed_with_warnings",
        "failed", "cancelled",
    ]
    assert run["properties"]["config_hash"]["pattern"] == "^[0-9a-f]{64}$"


def test_spec_security_scheme_is_x_api_key():
    schemes = SPEC["components"]["securitySchemes"]
    assert "ApiKeyAuth" in schemes
    assert schemes["ApiKeyAuth"]["type"] == "apiKey"
    assert schemes["ApiKeyAuth"]["in"] == "header"
    assert schemes["ApiKeyAuth"]["name"] == "X-API-Key"


def test_spec_upload_enums():
    triage = SPEC["components"]["schemas"]["Upload"]["properties"]["triage_state"]
    assert triage["enum"] == ["queued", "running", "done", "failed", "rejected_by_policy"]
