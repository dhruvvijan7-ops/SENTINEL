"""Evidence snapshot (spec §1.5, invariants 1 and 7).

``sentinel-finding/v1`` is the engine-internal emission shape; at ``flush()`` it
is persisted verbatim inside ``findings.evidence_snapshot`` together with the
rule document digest, the run's ``config_hash`` and the per-event document
digests.  The snapshot must survive purging of the raw object, so it never
references anything outside itself.
"""
from __future__ import annotations

import json
from datetime import date, datetime
from typing import Any, Mapping, Sequence

SENTINEL_FINDING = "sentinel-finding/v1"
SENTINEL_EVIDENCE = "sentinel-evidence/v1"

_EXCERPT_STRING_CHARS = 1024
_EXCERPT_TOTAL_BYTES = 8192
_ELLIPSIS = "…"


def _json_default(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_json_default
    )


def _truncate(value: Any, limit: int) -> Any:
    if isinstance(value, str):
        if len(value) <= limit:
            return value
        return value[:limit] + _ELLIPSIS
    if isinstance(value, dict):
        return {k: _truncate(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [_truncate(v, limit) for v in value]
    return value


def payload_excerpt(event_document: Mapping[str, Any]) -> dict[str, Any]:
    """A size-bounded copy of the event's triggering payload sub-object."""
    key = event_document.get("payload_key")
    if not isinstance(key, str):
        return {}
    payload = event_document.get(key)
    if payload is None:
        return {}
    excerpt = _truncate(payload, _EXCERPT_STRING_CHARS)
    if not isinstance(excerpt, dict):
        excerpt = {key: excerpt}
    if len(canonical_json(excerpt).encode("utf-8")) > _EXCERPT_TOTAL_BYTES:
        excerpt = {"truncated": True, "payload_key": key}
    return excerpt


def attck_refs(rule_document: Mapping[str, Any]) -> list[str]:
    tags = rule_document.get("tags") or []
    refs: list[str] = []
    for tag in tags:
        if not isinstance(tag, str):
            continue
        if tag.startswith("attack."):
            refs.append(tag)
    return refs


def falsepositives_note(rule_document: Mapping[str, Any]) -> str | None:
    fp = rule_document.get("falsepositives")
    if isinstance(fp, str):
        return fp
    if isinstance(fp, list) and fp:
        return "; ".join(str(item) for item in fp)
    return None


def build_finding(
    *,
    rule_id: str,
    rule_name: str,
    kind: str,
    severity: str,
    level_original: str | None,
    author: str | None,
    time_utc: Any,
    event_ids: Sequence[Any],
    host: Mapping[str, Any] | None,
    user: Mapping[str, Any] | None,
    detection_path: str,
    reason_codes: Sequence[str],
    payload_excerpt_value: Mapping[str, Any],
    attck_refs_value: Sequence[str],
    falsepositives_note_value: str | None,
    attestation: Any = None,
    score: int | None = None,
    fingerprint_hex: str | None = None,
) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "schema_version": SENTINEL_FINDING,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "kind": kind,
        "severity": severity,
        "level": level_original,
        "author": author,
        "time": time_utc.isoformat() if isinstance(time_utc, datetime) else str(time_utc),
        "event_ids": [str(e) for e in event_ids],
        "host": dict(host or {"agent_id": None, "instance_id": None, "name": None}),
        "user": dict(user or {"name": None, "domain": None}),
        "detection_path": detection_path,
        "reason_codes": list(reason_codes),
        "payload_excerpt": dict(payload_excerpt_value),
        "attck_refs": list(attck_refs_value),
        "falsepositives_note": falsepositives_note_value,
        "attestation": attestation,
    }
    if score is not None:
        finding["score"] = int(score)
    if fingerprint_hex is not None:
        finding["fingerprint"] = fingerprint_hex
    return finding


def build_snapshot(
    finding: Mapping[str, Any],
    *,
    rule_document: Mapping[str, Any],
    rule_source_sha256: str | None,
    run_id: Any,
    config_hash: str | None,
    events: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """The value stored verbatim in ``findings.evidence_snapshot``."""
    return {
        "schema_version": SENTINEL_EVIDENCE,
        "finding": dict(finding),
        "rule": {
            "rule_id": rule_document.get("id"),
            "name": rule_document.get("name"),
            "title": rule_document.get("title"),
            "source_ref": rule_document.get("source_ref"),
            "source_spec": rule_document.get("source_spec"),
            "status": rule_document.get("status"),
            "level": rule_document.get("level_original"),
            "document_sha256": _document_sha256(rule_document),
            "source_sha256": rule_source_sha256,
        },
        "run": {
            "run_id": str(run_id),
            "config_hash": config_hash,
        },
        "events": [
            {"event_uid": str(event.get("event_uid")), "sha256": _event_digest(event)}
            for event in events
        ],
    }


def _document_sha256(rule_document: Mapping[str, Any]) -> str:
    import hashlib

    return hashlib.sha256(canonical_json(rule_document).encode("utf-8")).hexdigest()


def _event_digest(event: Mapping[str, Any]) -> str | None:
    import hashlib

    document = event.get("document")
    if document is None:
        return None
    return hashlib.sha256(canonical_json(document).encode("utf-8")).hexdigest()
