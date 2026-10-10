"""System channel / Service Control Manager tables (Stage-2 §2 SEC-B):
7034, 7036, 7040, 7043, 7045 (+ System 104 config_check)."""
from __future__ import annotations

from typing import Any

from ..envelope import parse_evtx_time, state_invalid
from . import MappedEvent, RecordContext


def _decode_binary_utf16(hex_raw: str) -> str | None:
    """System event `Binary` carrier: UTF-16LE hex (D2-021)."""
    try:
        return bytes.fromhex(hex_raw).decode("utf-16-le")
    except (ValueError, UnicodeDecodeError):
        return None


def map_event(ctx: RecordContext, eid: int) -> MappedEvent | None:
    data = dict(ctx.eventdata)
    pos = dict(ctx.positional)
    time_block = parse_evtx_time(ctx.system_time)
    host: dict[str, Any] = {"hostname": ctx.computer} if ctx.computer else {}
    user: dict[str, Any] = {}
    if ctx.security_user_id:
        user["sid"] = ctx.security_user_id

    if eid == 7045:
        svc: dict[str, Any] = {}
        if data.get("ServiceName"):
            svc["name"] = data["ServiceName"]
        if data.get("ImagePath"):
            svc["image_path"] = data["ImagePath"]
        if data.get("ServiceType"):
            svc["service_type"] = data["ServiceType"]
        if data.get("StartType"):
            svc["start_type"] = data["StartType"]
        if data.get("AccountName"):
            svc["account_name"] = data["AccountName"]
        return MappedEvent(
            category="service", event_type="service_install", action="install",
            outcome="success", severity="medium", derived_by="source",
            time_block=time_block, host=host, user=user,
            payload_key="service", payload=svc, unmapped=[],
        )

    if eid == 7034:
        svc = {}
        if pos.get(1):
            svc["name"] = pos[1]
        unmapped = []
        if pos.get(2) is not None:
            unmapped.append({"name": "service.crash_count", "value": pos[2]})
        return MappedEvent(
            category="service", event_type="service_crash", action="terminate",
            outcome="success", severity="informational", derived_by="source",
            time_block=time_block, host=host, user=user,
            payload_key="service", payload=svc, unmapped=unmapped,
        )

    if eid == 7036:
        svc = {}
        if pos.get(1):
            svc["name"] = pos[1]
        if pos.get(2) is not None:
            svc["state"] = pos[2]
        unmapped = []
        if data.get("Binary") is not None:
            unmapped.append({"name": "Binary", "value": data["Binary"]})
        return MappedEvent(
            category="service", event_type="service_state_change",
            action="state_change", outcome="success", severity="informational",
            derived_by="source", time_block=time_block, host=host, user=user,
            payload_key="service", payload=svc, unmapped=unmapped,
        )

    if eid == 7040:
        svc = {}
        if pos.get(1):
            svc["name"] = pos[1]
        if pos.get(3):
            svc["start_type"] = pos[3]
        unmapped = []
        if pos.get(2) is not None:
            unmapped.append({"name": "service.old_start_type", "value": pos[2]})
        if pos.get(4) is not None:
            unmapped.append({"name": "service.caller", "value": pos[4]})
        return MappedEvent(
            category="service", event_type="service_start_type_change",
            action="change", outcome="success", severity="low", derived_by="source",
            time_block=time_block, host=host, user=user,
            payload_key="service", payload=svc, unmapped=unmapped,
        )

    if eid == 7043:
        svc = {}
        if pos.get(1):
            svc["name"] = pos[1]
        unmapped = []
        binary = data.get("Binary") or pos.get(2)
        if binary:
            decoded = _decode_binary_utf16(binary)
            if decoded is not None:
                svc["image_path"] = decoded
            else:
                unmapped.append({"name": "Binary", "value": binary})
        return MappedEvent(
            category="service", event_type="service_config_change",
            action="change", outcome="success", severity="low", derived_by="source",
            time_block=time_block, host=host, user=user,
            payload_key="service", payload=svc, unmapped=unmapped,
        )

    return None
