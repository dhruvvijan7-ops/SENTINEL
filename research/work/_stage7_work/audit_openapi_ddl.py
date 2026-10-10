#!/usr/bin/env python3
"""Stage-7 audit: OpenAPI 3.1 ↔ schema.sql ↔ canonical_event_v1.schema.json
cross-check.  Resolves every $ref, indexes tables/columns, and emits a
structured mismatch list to _stage7_work/openapi_ddl_audit.json."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "_stage7_work"

# --------------------------------------------------------------------------
# load
# --------------------------------------------------------------------------
spec = yaml.safe_load((ROOT / "openapi.yaml").read_text(encoding="utf-8"))
ddl_text = (ROOT / "schema.sql").read_text(encoding="utf-8")
canon = json.loads((ROOT / "canonical_event_v1.schema.json").read_text(encoding="utf-8"))

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def resolve_ref(ref: str, root: dict):
    if ref.startswith("#/"):
        node = root
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node
    # external file ref, optionally with a #/fragment (OpenAPI 3.1)
    # e.g. rule_schema.json or canonical_event_v1.schema.json#/$defs/host (C-9/C-10-fix)
    if ".json" in ref and not ref.startswith(("http://", "https://")):
        file_part, _, frag = ref.partition("#")
        f = ROOT / file_part
        if f.exists():
            node = json.loads(f.read_text(encoding="utf-8"))
            if frag.startswith("/"):
                for part in frag[1:].split("/"):
                    part = part.replace("~1", "/").replace("~0", "~")
                    if not isinstance(node, dict) or part not in node:
                        return None
                    node = node[part]
            return node
    return None


def deref(node, root, _depth=0):
    if _depth > 20:
        return node
    if isinstance(node, dict):
        if "$ref" in node:
            target = resolve_ref(node["$ref"], root)
            if target is not None:
                return deref(target, root, _depth + 1)
            return node
        return {k: deref(v, root, _depth + 1) for k, v in node.items()}
    if isinstance(node, list):
        return [deref(v, root, _depth + 1) for v in node]
    return node


def parse_ddl(text: str) -> dict[str, dict]:
    """Very small DDL parser: CREATE TABLE name ( cols ) — enough for audit."""
    tables: dict[str, dict] = {}
    # strip comments
    clean = re.sub(r"--[^\n]*", "", text)
    for m in re.finditer(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][\w]*)\s*\((.*?)\)\s*(?:PARTITION|;)",
        clean,
        re.S | re.I,
    ):
        name = m.group(1).lower()
        body = m.group(2)
        cols: dict[str, str] = {}
        for line in body.splitlines():
            line = line.strip().rstrip(",")
            if not line:
                continue
            # skip table-level constraints
            if re.match(
                r"(PRIMARY\s+KEY|UNIQUE|FOREIGN\s+KEY|CHECK\s*\(|CONSTRAINT|EXCLUDE|LIKE\b)",
                line,
                re.I,
            ):
                continue
            cm = re.match(r"([A-Za-z_][\w]*)\s+(.+)", line)
            if cm:
                cols[cm.group(1).lower()] = cm.group(2).strip()
        tables[name] = {"columns": cols, "raw": m.group(0)[:200]}
    return tables


tables = parse_ddl(ddl_text)
mismatches: list[dict] = []
resolved_notes: list[dict] = []  # documented Stage-8 resolutions (not open mismatches)


def add(kind: str, detail: str, **extra):
    mismatches.append({"kind": kind, "detail": detail, **extra})


def add_resolved(kind: str, detail: str, **extra):
    resolved_notes.append({"kind": kind, "detail": detail, **extra})


# --------------------------------------------------------------------------
# 1. every component schema resolves
# --------------------------------------------------------------------------
schemas = spec.get("components", {}).get("schemas", {})
unresolved = []


def walk_refs(node, path=""):
    if isinstance(node, dict):
        if "$ref" in node:
            if resolve_ref(node["$ref"], spec) is None:
                unresolved.append({"at": path, "ref": node["$ref"]})
        for k, v in node.items():
            walk_refs(v, f"{path}/{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            walk_refs(v, f"{path}/{i}")


walk_refs(spec)
for u in unresolved:
    add("openapi_unresolved_ref", f"{u['at']} -> {u['ref']}")

# --------------------------------------------------------------------------
# 2. duplicate operationIds
# --------------------------------------------------------------------------
ops: dict[str, list[str]] = {}
for path, item in spec.get("paths", {}).items():
    for method, op in item.items():
        if method in ("get", "post", "put", "patch", "delete", "head", "options"):
            oid = op.get("operationId")
            if oid:
                ops.setdefault(oid, []).append(f"{method.upper()} {path}")
for oid, where in ops.items():
    if len(where) > 1:
        add("duplicate_operationId", f"{oid}: {where}")

# --------------------------------------------------------------------------
# 3. OpenAPI ↔ DDL table coverage
# --------------------------------------------------------------------------
schema_to_table = {
    "CanonicalEvent": None,  # stored as events.document
    "Finding": "findings",
    "Rule": "rules",
    "RuleRun": "rule_run",
    "DetectionRun": "detection_runs",
    "Job": "jobs",
    "Upload": "uploads",
    "IocPack": "ioc_pack",
    "IocEntry": "ioc_entry",
    "Alert": None,
    "AnalysisRun": None,
}
for sname, tname in schema_to_table.items():
    if tname is None:
        continue
    if tname not in tables:
        add("ddl_missing_table", f"OpenAPI schema {sname} expects table {tname}")

# reverse: DDL tables with no OpenAPI counterpart (informational)
ddl_only = sorted(
    t
    for t in tables
    if t
    not in {
        "findings",
        "rules",
        "rule_run",
        "detection_runs",
        "jobs",
        "uploads",
        "ioc_pack",
        "ioc_entry",
        "tenants",
        "workspaces",
        "principals",
        "raw_objects",
        "rule_source",
        "rule_baseline",
        "fim_baseline",
        "job_attempts",
        "audit_log",
        "artifact_fact",
        "artifact_node",
        "artifact_edge",
    }
    and not t.startswith("events_")
    and not t.startswith("rule_baseline_")
)

# --------------------------------------------------------------------------
# 4. per-schema field presence: OpenAPI required vs DDL NOT NULL / existence
# --------------------------------------------------------------------------
def api_props(sname: str) -> dict:
    s = schemas.get(sname)
    if not s:
        return {}
    s = deref(s, spec)
    return s.get("properties", {})


def api_required(sname: str) -> set[str]:
    s = schemas.get(sname)
    if not s:
        return set()
    s = deref(s, spec)
    return set(s.get("required", []))


# 4a. Finding
finding_api = api_props("Finding")
finding_cols = tables.get("findings", {}).get("columns", {})
for req in sorted(api_required("Finding")):
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", req).lower()
    # already-snake fields pass through
    if req in finding_cols:
        snake = req
    if snake not in finding_cols and req not in finding_cols:
        add(
            "finding_required_not_in_ddl",
            f"OpenAPI Finding.required '{req}' has no DDL column (checked '{snake}')",
        )

# 4b. Rule
rule_api = api_props("Rule")
rule_cols = tables.get("rules", {}).get("columns", {})
ddl_rule_only = sorted(set(rule_cols) - set(rule_api))
api_rule_only = sorted(
    k for k in rule_api if re.sub(r"(?<!^)(?=[A-Z])", "_", k).lower() not in rule_cols and k not in rule_cols
)
for f in api_rule_only:
    add("rule_api_not_in_ddl", f"OpenAPI Rule.{f} has no DDL column in rules")
# DDL-only informational (path-scoped / soft-delete columns; not an open mismatch)
add_resolved(
    "rule_ddl_projection_gap",
    f"DDL rules columns absent from OpenAPI Rule schema: {ddl_rule_only} (tenant_id/workspace_id are path-scoped; schema_tag/source_ref/source_spec/description/provenance/deleted_at added by C-10-fix where exposed)",
)

# 4c. RuleRun
rulerun_api = api_props("RuleRun")
rulerun_cols = tables.get("rule_run", {}).get("columns", {})
for f in sorted(rulerun_api):
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", f).lower()
    if snake not in rulerun_cols and f not in rulerun_cols:
        add("rulerun_api_not_in_ddl", f"OpenAPI RuleRun.{f} has no DDL column")

# 4d. Uploads: createUpload request vs uploads DDL
create_upload = (
    spec.get("paths", {})
    .get("/v1/workspaces/{workspaceId}/uploads", {})
    .get("post", {})
)
if create_upload:
    body = (
        create_upload.get("requestBody", {})
        .get("content", {})
        .get("multipart/form-data", {})
        .get("schema", {})
    )
    body = deref(body, spec)
    upload_cols = tables.get("uploads", {}).get("columns", {})
    for prop, meta in (body.get("properties") or {}).items():
        snake = re.sub(r"(?<!^)(?=[A-Z])", "_", prop).lower()
        if snake not in upload_cols and prop not in upload_cols:
            if prop == "file":
                # C-4b-fix: multipart file lands in raw_objects CAS, not an uploads column
                add_resolved(
                    "upload_field_server_derived",
                    "createUpload.file has no uploads column by design — raw bytes go to raw_objects (CAS); uploads rows record metadata (C-4b-fix)",
                )
            else:
                add("upload_field_not_in_ddl", f"createUpload.{prop} has no DDL column")
    # DDL NOT NULL fields that the API does not require
    server_derived = {
        "tenant_id": "from authenticated principal (Stage-3 §1.1: principal resolves to one tenant/workspace)",
        "workspace_id": "from authenticated principal",
        "sha256": "computed server-side from the uploaded bytes",
        "size": "computed server-side from the uploaded bytes",
        "original_filename": "from the multipart file part's filename",
        "display_name": "from the multipart file part's filename",
    }
    for col, typ in upload_cols.items():
        if re.search(r"\bNOT NULL\b", typ, re.I) and "DEFAULT" not in typ.upper():
            if col not in body.get("properties", {}) and col not in body.get("required", []):
                # map snake back heuristically
                if col.replace("_", "") not in {p.replace("_", "") for p in body.get("properties", {})}:
                    if col in server_derived:
                        # C-4b-fix: server-populated, same class as run_id
                        add_resolved(
                            "upload_ddl_server_derived",
                            f"uploads.{col} NOT NULL is satisfied server-side ({server_derived[col]}) — C-4b-fix",
                        )
                    else:
                        add(
                            "upload_ddl_notnull_not_in_api",
                            f"uploads.{col} is NOT NULL without DEFAULT but createUpload does not require it",
                        )

# --------------------------------------------------------------------------
# 5. CanonicalEvent envelope vs OpenAPI CanonicalEvent vs DDL events
# --------------------------------------------------------------------------
canon_required = set(canon.get("required", []))
canon_props = set(canon.get("properties", {}).keys())
oa_ce = api_props("CanonicalEvent")
oa_ce_req = api_required("CanonicalEvent")
for r in sorted(canon_required - set(oa_ce)):
    add("canonical_required_missing_in_openapi", f"canonical-event/v1 requires '{r}' absent from OpenAPI CanonicalEvent")
for r in sorted(oa_ce_req - canon_required):
    add("openapi_canonical_required_extra", f"OpenAPI CanonicalEvent requires '{r}' not required by JSON Schema")

# source.format enum compare
def enum_of(node, dotted: str):
    cur = node
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        props = cur.get("properties") or cur
        cur = props.get(part) if part in props else None
        if cur is None:
            return None
        cur = deref(cur, spec) if isinstance(cur, dict) and "$ref" in cur else cur
    if isinstance(cur, dict):
        return cur.get("enum")
    return None


canon_src_fmt = (
    canon.get("properties", {}).get("source", {}).get("properties", {}).get("format", {})
)
canon_fmt_enum = canon_src_fmt.get("enum") if isinstance(canon_src_fmt, dict) else None
oa_fmt_enum = enum_of(schemas.get("CanonicalEvent", {}), "source.format")
if canon_fmt_enum and oa_fmt_enum:
    only_canon = sorted(set(canon_fmt_enum) - set(oa_fmt_enum))
    only_oa = sorted(set(oa_fmt_enum) - set(canon_fmt_enum))
    if only_canon or only_oa:
        add(
            "source_format_enum_mismatch",
            f"canonical={canon_fmt_enum} openapi={oa_fmt_enum} only_canonical={only_canon} only_openapi={only_oa}",
        )

# host shape (canonical host is a $ref to $defs/host — must deref)
canon_host = deref(canon.get("properties", {}).get("host", {}), canon)
canon_host_props = set((canon_host.get("properties") or {}).keys())
oa_host = (
    deref(schemas.get("CanonicalEvent", {}), spec)
    .get("properties", {})
    .get("host", {})
)
if isinstance(oa_host, dict):
    oa_host_props = set((oa_host.get("properties") or oa_host).keys() if "properties" in oa_host else oa_host.keys())
    # if host is a free-form object, note it
    if "properties" not in oa_host and oa_host.get("type") == "object":
        add(
            "openapi_host_freeform",
            "OpenAPI CanonicalEvent.host is a free-form object; canonical-event/v1 defines hostname/fqdn/ips/os/arch",
        )
    else:
        missing = sorted(canon_host_props - oa_host_props)
        extra = sorted(oa_host_props - canon_host_props)
        if missing or extra:
            add("host_shape_mismatch", f"only_canonical={missing} only_openapi={extra}")

# --------------------------------------------------------------------------
# 6. findings.evidence_snapshot obligation
# --------------------------------------------------------------------------
finding_cols_all = tables.get("findings", {}).get("columns", {})
if "evidence_snapshot" not in finding_cols_all:
    add("evidence_snapshot_missing", "schema.sql findings has no evidence_snapshot column (Stage-6 evidence model)")
if "author" not in finding_cols_all:
    add(
        "findings_author_missing",
        "schema.sql findings has no author column; Stage-1 DRL-1.1 obligation 'persist rule author on every alert row' is unfulfilled at the findings table (author lives only on rules)",
    )
if "level_original" not in finding_cols_all:
    add(
        "findings_level_original_missing",
        "schema.sql findings has no level_original column; Stage-1 §6 references alerts.level_original",
    )

# --------------------------------------------------------------------------
# 7. config_hash / fingerprint representation
# --------------------------------------------------------------------------
dr_cols = tables.get("detection_runs", {}).get("columns", {})
if "config_hash" in dr_cols and "bytea" in dr_cols["config_hash"]:
    oa_dr = api_props("DetectionRun")
    ch = oa_dr.get("configHash") or oa_dr.get("config_hash")
    if ch:
        ch = deref(ch, spec)
        pat = (ch.get("pattern") or "") if isinstance(ch, dict) else ""
        if "a-f0-9" in pat or "0-9a-f" in pat:
            # C-7-fix: bytea at rest, hex at the API edge — documented, not an open mismatch
            add_resolved(
                "config_hash_representation",
                "detection_runs.config_hash bytea (DDL) vs hex string (OpenAPI) — RESOLVED C-7-fix: encode(config_hash,'hex') at the API edge, documented in Stage-6 §4",
            )

# --------------------------------------------------------------------------
# 8. findings severity CHECK vs OpenAPI
# --------------------------------------------------------------------------
find_sev = finding_cols_all.get("severity", "")
if "LOW" in find_sev and "critical" not in find_sev.lower():
    oa_find = api_props("Finding")
    sev = oa_find.get("severity", {})
    sev = deref(sev, spec) if isinstance(sev, dict) else {}
    oa_enum = sev.get("enum") if isinstance(sev, dict) else None
    if oa_enum and "critical" in oa_enum:
        add(
            "finding_severity_enum_mismatch",
            f"DDL findings.severity CHECK is {find_sev!r} but OpenAPI Finding.severity enum includes {oa_enum}",
        )

# --------------------------------------------------------------------------
# 9. rule_run shape vs Stage-5 §4.3 (C-5-fix: job_id ≡ run_id mapping)
# --------------------------------------------------------------------------
s5_expected = {"job_id", "rule_id", "max_window_ms", "sql_ms", "native_ms"}
s5_actual = set(rulerun_cols)
# C-5-fix: Stage-5 'job_id' is the DDL 'run_id' (same concept — documented mapping)
if "run_id" in s5_actual:
    s5_expected.discard("job_id")
    if "job_id" not in s5_actual:
        add_resolved(
            "rule_run_job_id_mapped",
            "Stage-5 §4.3 'job_id' maps to DDL rule_run.run_id (C-5-fix) — no duplicate column",
        )
missing_s5 = sorted(s5_expected - s5_actual)
if missing_s5:
    add(
        "rule_run_stage5_mismatch",
        f"Stage-5 §4.3 rule_run shape expects {sorted(s5_expected)}; DDL has {sorted(s5_actual)}; missing={missing_s5}",
    )

# --------------------------------------------------------------------------
# write
# --------------------------------------------------------------------------
# de-duplicate identical details
seen = set()
uniq = []
for m in mismatches:
    key = (m["kind"], m["detail"])
    if key not in seen:
        seen.add(key)
        uniq.append(m)

out = {
    "tables_found": sorted(tables),
    "openapi_schemas": sorted(schemas),
    "unresolved_refs": unresolved,
    "duplicate_operation_ids": {k: v for k, v in ops.items() if len(v) > 1},
    "mismatch_count": len(uniq),
    "mismatches": uniq,
    "resolved_notes": resolved_notes,
}
path = OUT / "openapi_ddl_audit.json"
path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"wrote {path}")
print(f"tables={len(tables)} openapi_schemas={len(schemas)} mismatches={len(uniq)} resolved={len(resolved_notes)}")
for m in uniq:
    print(f"  [{m['kind']}] {m['detail'][:160]}")
for r in resolved_notes:
    print(f"  [resolved:{r['kind']}] {r['detail'][:140]}")
return_code = 0
sys.exit(return_code)
