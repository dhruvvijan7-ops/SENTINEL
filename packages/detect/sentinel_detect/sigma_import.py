"""Rule-pack import: the L0–L4 gate every rule document passes through.

L0  size/alias/depth-capped YAML parse (hostile input is rejected, never loaded)
L1  ``rule_schema.json`` structural validation of the normalized document
L2  condition parse + identifier resolution (``condition`` module)
L3  SQL/native compile (``compile`` module)
L4  upsert into ``rules`` / ``rule_source``

Nothing is ever skipped silently (invariant §1.10.4): every rule the pack names
comes back as ``imported``, ``disabled`` (loaded but not executable, with the
reason codes that made it so) or ``rejected`` (with the reason it never loaded).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml
from yaml.nodes import MappingNode, SequenceNode

from .compile import CompileError, compile_document
from .normalize import NormalizeError, normalize_rule
from .pipelines import PipelineRegistry, default_registry

MANIFEST_SCHEMA = "sentinel-rule-pack/v1"
MANIFEST_NAME = "rule_pack.json"

#: L0 hostile-YAML bounds.
MAX_RULE_BYTES = 1 << 20  # 1 MiB
MAX_YAML_NODES = 4096
MAX_YAML_DEPTH = 32


class RuleParseError(ValueError):
    """L0: the bytes are not a bounded, safe YAML rule document."""


class RuleValidationError(ValueError):
    """L1: the normalized document does not satisfy ``rule_schema.json``."""


# ---------------------------------------------------------------------------
# pack manifest
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PackManifest:
    pack_id: str
    pack_version: str
    source_repo: str
    source_commit: str
    source_spec: str
    rules: tuple[dict[str, Any], ...]
    pack_sha256: str

    @property
    def count(self) -> int:
        return len(self.rules)

    def paths(self) -> list[str]:
        return [str(r["path"]) for r in self.rules]


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def pack_digest(rules: Sequence[Mapping[str, Any]]) -> str:
    """Digest of the pack membership list — the pinning value."""
    blob = json.dumps(
        [[r["path"], r["sha256"]] for r in rules],
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(blob).hexdigest()


def build_pack_manifest(
    paths: Sequence[str | Path],
    *,
    repo_root: Path,
    source_repo: str,
    source_commit: str,
    pack_id: str,
    pack_version: str,
    source_spec: str = "sigma-spec/2.1.0",
) -> dict[str, Any]:
    """Build the committed manifest for a set of rule files (all deterministic)."""
    root = Path(repo_root)
    entries: list[dict[str, str]] = []
    for path in sorted(str(p) for p in paths):
        text = (root / path).read_text(encoding="utf-8")
        entries.append({"path": path, "sha256": _sha256_text(text)})
    return {
        "schema": MANIFEST_SCHEMA,
        "pack_id": pack_id,
        "pack_version": pack_version,
        "source": {
            "kind": "sigma",
            "repo": source_repo,
            "commit": source_commit,
            "spec": source_spec,
        },
        "count": len(entries),
        "pack_sha256": pack_digest(entries),
        "rules": entries,
    }


def load_pack_manifest(path: str | Path) -> PackManifest:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if raw.get("schema") != MANIFEST_SCHEMA:
        raise RuleParseError(f"manifest schema {raw.get('schema')!r} is not {MANIFEST_SCHEMA!r}")
    rules = raw.get("rules")
    if not isinstance(rules, list) or not rules:
        raise RuleParseError("manifest names no rules")
    entries = tuple(rules)
    if int(raw.get("count", -1)) != len(entries):
        raise RuleParseError("manifest count does not match its rule list")
    digest = raw.get("pack_sha256")
    if digest != pack_digest(entries):
        raise RuleParseError("manifest pack_sha256 does not match its rule list")
    source = raw.get("source") or {}
    return PackManifest(
        pack_id=str(raw["pack_id"]),
        pack_version=str(raw["pack_version"]),
        source_repo=str(source.get("repo", "")),
        source_commit=str(source.get("commit", "")),
        source_spec=str(source.get("spec", "")),
        rules=entries,
        pack_sha256=digest,
    )


def pack_config_bytes(manifest: PackManifest | None, engine_version: str) -> bytes:
    """Canonical engine-config blob hashed into ``detection_runs.config_hash``."""
    if manifest is None:
        body = {"engine_version": engine_version, "rule_pack": None, "mode": "empty"}
    else:
        body = {
            "engine_version": engine_version,
            "rule_pack": {
                "pack_id": manifest.pack_id,
                "pack_version": manifest.pack_version,
                "pack_sha256": manifest.pack_sha256,
                "source_commit": manifest.source_commit,
            },
            "mode": "pack",
        }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


_MANIFEST_CACHE: dict[str, PackManifest | None] = {}


def default_manifest() -> PackManifest | None:
    """The pinned pack the engine declares (``configs/rule_pack.json``).

    Located by walking ancestors for the repo markers rather than a Settings
    key (the config-key freeze), and ``None`` when the pack is unavailable —
    an installed package with no repo tree runs the empty pack.
    """
    if "default" not in _MANIFEST_CACHE:
        manifest: PackManifest | None = None
        try:
            path = _find_repo_root() / "configs" / MANIFEST_NAME
            if path.is_file():
                manifest = load_pack_manifest(path)
        except (RuleParseError, OSError, ValueError):
            manifest = None
        _MANIFEST_CACHE["default"] = manifest
    return _MANIFEST_CACHE["default"]


# ---------------------------------------------------------------------------
# L0
# ---------------------------------------------------------------------------


def parse_rule_text(text: str) -> dict[str, Any]:
    """L0: bounded, alias-free YAML → mapping."""
    if len(text.encode("utf-8")) > MAX_RULE_BYTES:
        raise RuleParseError("rule document exceeds the L0 size cap")
    if not text.strip():
        raise RuleParseError("rule document is empty")
    try:
        _check_anchors(text)
        node = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        raise RuleParseError(f"YAML is not parseable: {exc}") from exc
    if node is None:
        raise RuleParseError("rule document is empty")
    _check_nodes(node, 0)
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict):
        raise RuleParseError("rule document must be a YAML mapping")
    return doc


def _check_anchors(text: str) -> None:
    """Ban anchors/aliases outright — they are a pure amplification vector.

    Checked on the *event* stream (parsed, never constructed), so the check
    itself can never be the thing that expands.
    """
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if getattr(event, "anchor", None):
            raise RuleParseError("rule YAML may not use anchors or aliases")


def _check_nodes(node: Any, depth: int) -> int:
    if depth > MAX_YAML_DEPTH:
        raise RuleParseError("rule YAML nests deeper than the L0 depth cap")
    count = 1
    if isinstance(node, SequenceNode):
        for child in node.value:
            count += _check_nodes(child, depth + 1)
    elif isinstance(node, MappingNode):
        for key, value in node.value:
            count += _check_nodes(key, depth + 1)
            count += _check_nodes(value, depth + 1)
    if count > MAX_YAML_NODES:
        raise RuleParseError("rule YAML exceeds the L0 node cap")
    return count


# ---------------------------------------------------------------------------
# L1
# ---------------------------------------------------------------------------

_SCHEMA_CACHE: dict[str, Any] = {}


def rule_schema(repo_root: Path | str | None = None) -> dict[str, Any]:
    if "schema" not in _SCHEMA_CACHE:
        root = Path(repo_root) if repo_root else _find_repo_root()
        _SCHEMA_CACHE["schema"] = json.loads((root / "rule_schema.json").read_text(encoding="utf-8"))
    return _SCHEMA_CACHE["schema"]


def _find_repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in [here, *here.parents]:
        if (parent / "rule_schema.json").is_file():
            return parent
    raise RuleParseError("rule_schema.json not found in any parent directory")


def validate_document(document: Mapping[str, Any], repo_root: Path | None = None) -> None:
    """L1: structural validation.  Raises ``RuleValidationError`` with every error."""
    import jsonschema

    schema = rule_schema(repo_root)
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))
    if not errors:
        return
    lines = []
    for err in errors[:20]:
        where = "/".join(str(p) for p in err.absolute_path) or "<root>"
        lines.append(f"{where}: {err.message}")
    raise RuleValidationError("; ".join(lines))


# ---------------------------------------------------------------------------
# import result
# ---------------------------------------------------------------------------

IMPORTED = "imported"
DISABLED = "disabled"
REJECTED = "rejected"


@dataclass(frozen=True)
class CompiledRule:
    """One rule that passed L0–L3, ready for the L4 upsert."""

    document: dict[str, Any]
    compile_block: dict[str, Any]
    outcome: str
    reason_codes: tuple[str, ...]
    source_text: str
    source_sha256: str
    detail: str = ""

    @property
    def rule_id(self) -> str:
        return str(self.document["id"])

    @property
    def enabled(self) -> bool:
        return self.outcome == IMPORTED


@dataclass(frozen=True)
class RejectedRule:
    source_ref: str
    reason: str
    detail: str
    source_id: str | None = None


def compile_rule_text(
    text: str,
    *,
    source_ref: str,
    provenance: Mapping[str, Any] | None = None,
    registry: PipelineRegistry | None = None,
    repo_root: Path | None = None,
) -> CompiledRule:
    """Run L0–L3 over one rule document and return the L4 payload (or raise)."""
    raw = parse_rule_text(text)
    normalized = normalize_rule(raw, registry=registry, source_ref=source_ref)
    document = normalized.document

    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    prov = {
        "imported_at": now,
        "imported_by": "sentinel",
        "repo_commit": str((provenance or {}).get("repo_commit", "")),
        "pack_id": str((provenance or {}).get("pack_id", "")),
        "pack_version": str((provenance or {}).get("pack_version", "")),
        "rule_source_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }
    document["provenance"] = prov

    compile_block = compile_document(document, unsupported=normalized.unsupported)

    codes = tuple(sorted({c["code"] for c in compile_block.get("unsupported", [])}))
    fatal = bool(set(codes) - {"UNMAPPED_FIELD"})
    outcome = DISABLED if fatal else IMPORTED
    document["enabled"] = not fatal
    # The compile block travels inside the document (schema allows it) *and*
    # in the ``compile`` column, so a row read either way tells the same story.
    document["compile"] = compile_block

    validate_document(document, repo_root)

    return CompiledRule(
        document=document,
        compile_block=compile_block,
        outcome=outcome,
        reason_codes=codes,
        source_text=text,
        source_sha256=prov["rule_source_sha256"],
        detail="" if not fatal else "reason codes outside UNMAPPED_FIELD disable the rule",
    )


# ---------------------------------------------------------------------------
# L4
# ---------------------------------------------------------------------------

_RULE_UPSERT = """
INSERT INTO rules (
    tenant_id, workspace_id, rule_id, name, kind, schema_tag, source, source_id,
    source_ref, source_spec, license, author, title, description, status,
    level_original, severity, enabled, document, compile, provenance,
    imported_at, updated_at
) VALUES (
    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, now(), now()
)
ON CONFLICT (tenant_id, workspace_id, rule_id) DO UPDATE SET
    name         = EXCLUDED.name,
    kind         = EXCLUDED.kind,
    schema_tag   = EXCLUDED.schema_tag,
    source       = EXCLUDED.source,
    source_id    = EXCLUDED.source_id,
    source_ref   = EXCLUDED.source_ref,
    source_spec  = EXCLUDED.source_spec,
    license      = EXCLUDED.license,
    author       = EXCLUDED.author,
    title        = EXCLUDED.title,
    description  = EXCLUDED.description,
    status       = EXCLUDED.status,
    level_original = EXCLUDED.level_original,
    severity     = EXCLUDED.severity,
    enabled      = EXCLUDED.enabled,
    document     = EXCLUDED.document,
    compile      = EXCLUDED.compile,
    provenance   = EXCLUDED.provenance,
    updated_at   = now(),
    deleted_at   = NULL
"""

_SOURCE_UPSERT = """
INSERT INTO rule_source (tenant_id, workspace_id, rule_id, text, sha256, imported_at)
VALUES (%s,%s,%s,%s,%s::bytea, now())
ON CONFLICT DO NOTHING
"""


def insert_rule(conn: Any, tenant_id: str, workspace_id: str, rule: CompiledRule) -> None:
    doc = rule.document
    conn.execute(
        _RULE_UPSERT,
        (
            tenant_id,
            workspace_id,
            rule.rule_id,
            doc.get("name") or doc.get("title"),
            doc.get("kind", "sigma"),
            doc.get("schema", "sentinel-rule/v1"),
            doc.get("source", "sigma"),
            doc.get("source_id"),
            doc.get("source_ref"),
            doc.get("source_spec"),
            doc.get("license") or "DRL-1.1",
            doc.get("author") or "unknown",
            doc.get("title"),
            doc.get("description"),
            doc.get("status") or "experimental",
            doc.get("level_original"),
            doc.get("severity"),
            doc["enabled"],
            json.dumps(doc),
            json.dumps(rule.compile_block),
            json.dumps(doc.get("provenance")),
        ),
    )
    conn.execute(
        _SOURCE_UPSERT,
        (
            tenant_id,
            workspace_id,
            rule.rule_id,
            rule.source_text,
            bytes.fromhex(rule.source_sha256),
        ),
    )


# ---------------------------------------------------------------------------
# pack driver
# ---------------------------------------------------------------------------


@dataclass
class PackSummary:
    pack_id: str
    pack_version: str
    imported: list[str] = field(default_factory=list)
    disabled: list[CompiledRule] = field(default_factory=list)
    rejected: list[RejectedRule] = field(default_factory=list)
    retired: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        return {
            "imported": len(self.imported),
            "disabled": len(self.disabled),
            "rejected": len(self.rejected),
            "retired": len(self.retired),
        }

    def reason_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for rule in self.disabled:
            for code in rule.reason_codes:
                out[code] = out.get(code, 0) + 1
        for bad in self.rejected:
            out[bad.reason] = out.get(bad.reason, 0) + 1
        return dict(sorted(out.items()))


def import_pack(
    conn: Any,
    manifest: PackManifest,
    *,
    tenant_id: str,
    workspace_id: str,
    pack_root: Path,
    registry: PipelineRegistry | None = None,
    repo_root: Path | None = None,
    retire_missing: bool = True,
) -> PackSummary:
    """Load every rule the manifest pins, verify its digest, and upsert it."""
    registry = registry or default_registry()
    pack_root = Path(pack_root)
    summary = PackSummary(pack_id=manifest.pack_id, pack_version=manifest.pack_version)
    provenance = {
        "repo_commit": manifest.source_commit,
        "pack_id": manifest.pack_id,
        "pack_version": manifest.pack_version,
    }

    seen_rule_ids: list[str] = []
    for entry in manifest.rules:
        rel = str(entry["path"])
        expected = str(entry["sha256"])
        source_ref = f"{manifest.source_repo}@{manifest.source_commit}:{rel}"
        target = pack_root / rel
        try:
            text = target.read_text(encoding="utf-8")
        except OSError as exc:
            summary.rejected.append(
                RejectedRule(source_ref=source_ref, reason="RULE_FILE_MISSING", detail=str(exc))
            )
            continue
        actual = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if actual != expected:
            summary.rejected.append(
                RejectedRule(
                    source_ref=source_ref,
                    reason="RULE_DIGEST_MISMATCH",
                    detail=f"expected {expected}, got {actual}",
                )
            )
            continue
        try:
            rule = compile_rule_text(
                text,
                source_ref=source_ref,
                provenance=provenance,
                registry=registry,
                repo_root=repo_root,
            )
        except RuleParseError as exc:
            summary.rejected.append(
                RejectedRule(source_ref=source_ref, reason="RULE_PARSE_FAILED", detail=str(exc))
            )
            continue
        except NormalizeError as exc:
            summary.rejected.append(
                RejectedRule(source_ref=source_ref, reason="RULE_NORMALIZE_FAILED", detail=str(exc))
            )
            continue
        except RuleValidationError as exc:
            summary.rejected.append(
                RejectedRule(source_ref=source_ref, reason="SCHEMA_VALIDATION_FAILED", detail=str(exc))
            )
            continue
        except CompileError as exc:
            summary.rejected.append(
                RejectedRule(source_ref=source_ref, reason="UNSUPPORTED_CONDITION_FORM", detail=str(exc))
            )
            continue

        insert_rule(conn, tenant_id, workspace_id, rule)
        seen_rule_ids.append(rule.rule_id)
        if rule.outcome == IMPORTED:
            summary.imported.append(rule.rule_id)
        else:
            summary.disabled.append(rule)

    if retire_missing and seen_rule_ids:
        placeholders = ",".join(["%s"] * len(seen_rule_ids))
        cur = conn.execute(
            f"""
            UPDATE rules SET deleted_at = now(), enabled = false
            WHERE tenant_id = %s AND workspace_id = %s AND deleted_at IS NULL
              AND provenance ->> 'pack_id' = %s
              AND rule_id NOT IN ({placeholders})
            RETURNING rule_id
            """,
            (tenant_id, workspace_id, manifest.pack_id, *seen_rule_ids),
        )
        summary.retired = [str(row[0]) for row in cur.fetchall()]

    return summary
