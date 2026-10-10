"""canonical-event/v1 envelope construction (Stage-2 §1; fixtures §5).

Value-state model (D2-001): absent key = absent value; bare null forbidden
except time.utc under state unknown/invalid; derived values follow the VERIFIED
§5 fixtures (e.g. EX-SYSMON-3 direction = {$state:"inferred",$note:...} with no
enum value — the schema's oneOf picks the state-object arm).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "canonical-event/v1"
PARSER_NAME = "evtx-canonical"
PARSER_VERSION = "1.0.0"

_RFC3339 = re.compile(
    r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?$"
)
_SYSTIME = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[ ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$"
)


def state_null(raw: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"$state": "null"}
    if raw is not None:
        out["$raw"] = raw
    return out


def state_unknown(note: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"$state": "unknown"}
    if note:
        out["$note"] = note
    return out


def state_invalid(raw: str, note: str) -> dict[str, Any]:
    return {"$state": "invalid", "$note": note, "$raw": raw}


def state_inferred(note: str, raw: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"$state": "inferred", "$note": note}
    if raw is not None:
        out["$raw"] = raw
    return out


def parse_evtx_time(system_time: str | None) -> dict[str, Any]:
    """TimeCreated@SystemTime (UTC 'Z', up to 7 fractional digits).

    EX-SEC-4624 / EX-WIN-7045: keep the source string in time.original,
    truncate utc to microseconds, state ok, source_explicit.
    """
    if not system_time:
        return {"utc": None, "precision": "unknown", "state": "unknown", "timezone_source": "none"}
    m = _RFC3339.match(system_time)
    if not m or (m.group(4) not in (None, "Z")):
        return {
            "utc": None,
            "original": system_time,
            "precision": "unknown",
            "state": "invalid",
            "timezone_source": "none",
        }
    frac = m.group(3) or ""
    if frac:
        us = frac[:6].ljust(6, "0")
        utc = f"{m.group(1)}T{m.group(2)}.{us}Z"
        precision = "microsecond"
    else:
        utc = f"{m.group(1)}T{m.group(2)}Z"
        precision = "second"
    return {
        "utc": utc,
        "original": system_time,
        "original_timezone": "Z",
        "timezone_source": "source_explicit",
        "precision": precision,
        "state": "ok",
    }


def parse_sysmon_time(utc_time: str | None) -> dict[str, Any]:
    """Sysmon UtcTime ('YYYY-MM-DD HH:MM:SS.mmm'): documented UTC; conversion
    is Sentinel-derived → state inferred, source_documented_utc (EX-SYSMON-1)."""
    if not utc_time:
        return {"utc": None, "precision": "unknown", "state": "unknown", "timezone_source": "none"}
    m = _SYSTIME.match(utc_time)
    if not m:
        return {
            "utc": None,
            "original": utc_time,
            "precision": "unknown",
            "state": "invalid",
            "timezone_source": "none",
        }
    frac = m.group(7) or ""
    if frac == "mmm" or (frac and len(frac) <= 3):
        ms = frac.ljust(3, "0")[:3] if frac else ""
        utc = f"{m.group(1)}-{m.group(2)}-{m.group(3)}T{m.group(4)}:{m.group(5)}:{m.group(6)}"
        if ms:
            utc = f"{utc}.{ms}Z"
            precision = "millisecond"
        else:
            utc = f"{utc}Z"
            precision = "second"
    else:
        us = frac[:6].ljust(6, "0")
        utc = f"{m.group(1)}-{m.group(2)}-{m.group(3)}T{m.group(4)}:{m.group(5)}:{m.group(6)}.{us}Z"
        precision = "microsecond"
    return {
        "utc": utc,
        "original": utc_time,
        "original_timezone": "Z",
        "timezone_source": "source_documented_utc",
        "precision": precision,
        "state": "inferred",
    }


def hex_pid(raw: str) -> dict[str, Any]:
    """Security hex PID ('0x4c8') → inferred state object with $raw kept
    (EX-SEC-4624 process_pid shape; the int itself is not re-emitted)."""
    try:
        int(raw, 16)
    except ValueError:
        return state_invalid(raw, "hex PID not parsable")
    return state_inferred(f"hex {raw}→int", raw=raw)


def split_domain_user(value: str) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """'CORP\\jdoe' → ({domain, name}, unmapped-sid-case)."""
    if value.startswith("S-"):
        return {}, []
    if "\\" in value:
        domain, _, name = value.partition("\\")
        out: dict[str, str] = {}
        if domain:
            out["domain"] = domain
        if name:
            out["name"] = name
        return out, []
    return {"name": value}, []


def basename_windows(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


def is_sid(value: str) -> bool:
    return value.startswith("S-")


def split_hashes(raw: str) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Sysmon Hashes 'KEY=value,KEY=value' → (hashes, remainder→other)."""
    out: dict[str, str] = {}
    leftovers: list[str] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        key, sep, val = part.partition("=")
        if not sep or not val:
            leftovers.append(part)
            continue
        k = key.strip().lower()
        if k in ("md5", "sha1", "sha256", "imphash"):
            out[k] = val.strip()
        else:
            leftovers.append(part)
    if leftovers:
        out["other"] = ",".join(leftovers)
    return out, []


def null_or_string(raw: str | None, *, dash_is_null: bool = True) -> Any:
    """Windows renders absent as '' or '-'; per SEC-B convention emit
    {$state:null,$raw} when semantics are null, else the plain string."""
    if raw is None:
        return None
    if raw == "" or (dash_is_null and raw == "-"):
        return state_null(raw if raw else "")
    return raw


def parse_int_or_null(raw: str | None) -> Any:
    if raw is None:
        return None
    s = raw.strip()
    if s == "" or s == "-":
        return state_null(raw)
    try:
        return int(s)
    except ValueError:
        return state_invalid(raw, "not an integer")


def build_envelope(
    *,
    tenant_id: str,
    workspace_id: str,
    run_id: str,
    file_id: str,
    file_sha256: str | None,
    channel: str | None,
    provider: str | None,
    event_id: int | str | None,
    record_id: int | str | None,
    category: str,
    event_type: str,
    action: str,
    outcome: str,
    severity: str,
    derived_by: str,
    time_block: dict[str, Any],
    host: dict[str, Any],
    user: dict[str, Any],
    payload_key: str | None,
    payload: dict[str, Any] | None,
    raw: str,
    unmapped: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    source: dict[str, Any] = {
        "file_id": file_id,
        "format": "evtx",
        "parser": PARSER_NAME,
        "parser_version": PARSER_VERSION,
        "record": {"type": "event_record", "record_id": record_id},
    }
    if file_sha256:
        source["sha256"] = file_sha256
    if channel:
        source["channel"] = channel
    if provider:
        source["provider"] = provider
    if event_id is not None:
        source["event_id"] = event_id

    env: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "event": {
            "category": category,
            "type": event_type,
            "action": action,
            "outcome": outcome,
            "severity": severity,
            "derived_by": derived_by,
        },
        "tenant_id": tenant_id,
        "workspace_id": workspace_id,
        "run_id": run_id,
        "time": time_block,
        "host": host,
        "user": user,
        "source": source,
        "raw": raw,
    }
    if payload_key and payload:
        env[payload_key] = payload
    if unmapped:
        env["unmapped"] = unmapped
    return env
