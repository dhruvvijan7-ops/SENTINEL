"""Finding identity (D6-013): the stable tuple a fingerprint is taken over.

Both detection paths must arrive at byte-identical fingerprints for the same
logical alert — that is what makes the §12.1 conformance oracle meaningful and
what makes ``finalize()`` retry-idempotent.  Nothing run-specific (no
``finding_uid``, no ``detection_path``, no wall clock) may enter the tuple.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Iterable, Mapping, Sequence

FINGERPRINT_SCHEMA = "sentinel-finding/fingerprint/v1"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _iso(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def finding_fingerprint(
    *,
    tenant_id: str,
    workspace_id: str,
    rule_id: str,
    time_utc: Any,
    event_uids: Sequence[Any],
    host_hostname: str | None = None,
    user_name: str | None = None,
) -> bytes:
    payload = {
        "schema": FINGERPRINT_SCHEMA,
        "tenant_id": tenant_id,
        "workspace_id": workspace_id,
        "rule_id": str(rule_id),
        "time_utc": _iso(time_utc),
        "event_uids": sorted(str(u) for u in event_uids),
        "host_hostname": host_hostname,
        "user_name": user_name,
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).digest()


def document_digest(document: Any) -> str:
    """sha256 of a document's canonical JSON (evidence event digests)."""
    return hashlib.sha256(canonical_json(document).encode("utf-8")).hexdigest()
