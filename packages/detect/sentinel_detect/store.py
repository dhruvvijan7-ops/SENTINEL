"""Rule store — M1 ships an EMPTY pack (D6-015; Stage-5 D5-014 invariant:
zero rules ⇒ exactly zero findings; no detection constants in engine code)."""
from __future__ import annotations

import json
from typing import Any

ENGINE_VERSION = "0.1.0"


class EmptyRuleStore:
    """Loads zero rule documents.  M2 replaces this with the L0–L4 validated
    pack loader; the interface stays: load(tenant, workspace) → list[dict]."""

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
