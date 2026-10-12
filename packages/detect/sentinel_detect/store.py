"""Rule store — the L0–L4 validated pack loader.

``EmptyRuleStore`` stays (D6-015 invariant: zero rules ⇒ exactly zero
findings), ``DbRuleStore`` loads the validated pack from ``rules``.  The
interface is unchanged: ``load(tenant, workspace) -> list[dict]``.
"""
from __future__ import annotations

import json
from typing import Any

ENGINE_VERSION = "0.1.0"


class EmptyRuleStore:
    """Loads zero rule documents.  Zero rules ⇒ exactly zero findings."""

    def load(self, tenant_id: str, workspace_id: str) -> list[dict[str, Any]]:
        return []


def empty_pack_config_bytes() -> bytes:
    """Canonical engine-config blob whose sha256 becomes
    detection_runs.config_hash (NOT NULL bytea)."""
    return json.dumps(
        {"engine_version": ENGINE_VERSION, "rule_pack": None, "mode": "empty"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _as_dict(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    return None


_LOAD_SQL = """
    SELECT r.rule_id, r.document, r.compile, r.severity,
           s.sha256
      FROM rules r
      LEFT JOIN LATERAL (
           SELECT sha256 FROM rule_source rs
            WHERE rs.tenant_id = r.tenant_id
              AND rs.workspace_id = r.workspace_id
              AND rs.rule_id = r.rule_id
            ORDER BY rs.imported_at DESC
            LIMIT 1
      ) s ON true
     WHERE r.tenant_id = %s
       AND r.workspace_id = %s
       AND r.deleted_at IS NULL
       AND r.enabled
     ORDER BY r.rule_id
"""


class DbRuleStore:
    """Loads the validated pack from the ``rules`` table."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def load(self, tenant_id: str, workspace_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(_LOAD_SQL, (tenant_id, workspace_id)).fetchall()
        out: list[dict[str, Any]] = []
        for rule_id, document, compile_block, _severity, source_sha256 in rows:
            doc = document if isinstance(document, dict) else {}
            out.append(
                {
                    "rule_id": rule_id,
                    "document": doc,
                    "compile": _as_dict(compile_block) or _as_dict(doc.get("compile")),
                    "source_sha256": source_sha256.hex() if source_sha256 else None,
                    "kind": str(doc.get("kind") or "sigma"),
                    "severity": str(doc.get("severity") or "MEDIUM"),
                }
            )
        return out
