"""OpenAPI conformance: the app's route table matches openapi.yaml paths
and the normative gate/error enums.

Also carries M0 exit criterion ②: ``openapi.yaml`` parses, every ``$ref``
(internal and external) resolves, no duplicate ``operationId``, every
operation carries an ``operationId``, the path count is frozen at 23, and
no undocumented (app-side-only) endpoint exists.

Refs/operationId logic ported from research/work/_stage7_work/audit_openapi_ddl.py
(L119-147); that script stays as authoring tooling, this module is the gate.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = yaml.safe_load((ROOT / "openapi.yaml").read_text(encoding="utf-8"))

# M0 frozen contract numbers (spec §9 / §9.1).
SPEC_PATH_COUNT = 23
SPEC_OPERATION_COUNT = 35

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")

# FastAPI framework-generated routes, not part of the product surface.
FRAMEWORK_PATHS = {"/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"}

# External $refs openapi.yaml is allowed to point at (spec §1.4 / §8).
ALLOWED_EXTERNAL_REF_FILES = {"canonical_event_v1.schema.json", "rule_schema.json"}


def _resolve_ref(ref: str, root: dict) -> object | None:
    """Resolve a local (#/...) or external (file.json[#/frag]) $ref."""
    if ref.startswith("#/"):
        node: object = root
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node
    if ".json" in ref and not ref.startswith(("http://", "https://")):
        file_part, _, frag = ref.partition("#")
        f = ROOT / file_part
        if not f.exists():
            return None
        node = json.loads(f.read_text(encoding="utf-8"))
        if frag.startswith("/"):
            for part in frag[1:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                if not isinstance(node, dict) or part not in node:
                    return None
                node = node[part]
        return node
    return None


def _walk_refs(node, path: str = ""):
    """Yield (json_pointer_path, ref_string) for every $ref in the document."""
    if isinstance(node, dict):
        if "$ref" in node and isinstance(node["$ref"], str):
            yield path, node["$ref"]
        for k, v in node.items():
            yield from _walk_refs(v, f"{path}/{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_refs(v, f"{path}/{i}")


def _operations() -> list[tuple[str, str, dict]]:
    """(method, path, operation) for every operation object in the spec."""
    out = []
    for path, item in SPEC.get("paths", {}).items():
        for method, op in item.items():
            if method in HTTP_METHODS:
                out.append((method.upper(), path, op))
    return out


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


# ---------------------------------------------------------------------------
# M0 exit criterion ② — structural conformance
# ---------------------------------------------------------------------------
def test_every_internal_ref_resolves():
    unresolved = [
        (path, ref)
        for path, ref in _walk_refs(SPEC)
        if ref.startswith("#/") and _resolve_ref(ref, SPEC) is None
    ]
    assert not unresolved, f"unresolved internal $refs: {unresolved}"


def test_every_external_ref_names_an_existing_file():
    bad = []
    seen_files = set()
    for path, ref in _walk_refs(SPEC):
        if ref.startswith("#/") or ref.startswith(("http://", "https://")):
            continue
        file_part = ref.partition("#")[0]
        seen_files.add(file_part)
        if not (ROOT / file_part).exists():
            bad.append((path, ref))
    assert not bad, f"external $refs pointing at missing files: {bad}"
    assert seen_files <= ALLOWED_EXTERNAL_REF_FILES, (
        f"openapi.yaml grew new external $ref targets {seen_files - ALLOWED_EXTERNAL_REF_FILES}; "
        f"the M0 contract allows only {sorted(ALLOWED_EXTERNAL_REF_FILES)}"
    )


def test_every_external_ref_fragment_resolves():
    unresolved = [
        (path, ref)
        for path, ref in _walk_refs(SPEC)
        if not ref.startswith("#/")
        and not ref.startswith(("http://", "https://"))
        and _resolve_ref(ref, SPEC) is None
    ]
    assert not unresolved, f"unresolvable external $refs: {unresolved}"


def test_no_duplicate_operation_ids():
    seen: dict[str, list[str]] = {}
    for method, path, op in _operations():
        oid = op.get("operationId")
        if oid:
            seen.setdefault(oid, []).append(f"{method} {path}")
    dups = {oid: where for oid, where in seen.items() if len(where) > 1}
    assert not dups, f"duplicate operationIds: {dups}"


def test_every_operation_has_an_operationId():
    missing = [f"{m} {p}" for m, p, op in _operations() if not op.get("operationId")]
    assert not missing, f"operations without operationId: {missing}"


def test_spec_path_count_is_frozen():
    paths = SPEC.get("paths", {})
    assert len(paths) == SPEC_PATH_COUNT, (
        f"openapi.yaml has {len(paths)} paths, the M0 contract freezes it at "
        f"{SPEC_PATH_COUNT} (spec §9.1). Amend the spec before adding endpoints."
    )


def test_spec_operation_count_is_frozen():
    ops = _operations()
    assert len(ops) == SPEC_OPERATION_COUNT, (
        f"openapi.yaml has {len(ops)} operations, the M0 contract freezes it at "
        f"{SPEC_OPERATION_COUNT} (spec §9.1 path index)."
    )


def test_app_routes_are_documented():
    """Reverse of test_required_endpoints_present: an endpoint the app serves
    but the spec omits is an undocumented surface and fails the M0 gate."""
    undocumented = {
        (m, p) for m, p in _app_route_keys() if p not in FRAMEWORK_PATHS
    } - {(m.upper(), p) for m, p, _ in _operations()}
    assert not undocumented, (
        f"app serves endpoints missing from openapi.yaml: {sorted(undocumented)}"
    )
