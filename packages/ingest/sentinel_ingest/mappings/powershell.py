"""PowerShell Operational mapping (Stage-2 §2.4): EID 4104 (M1 set)."""
from __future__ import annotations

from typing import Any

from ..envelope import parse_evtx_time, parse_int_or_null, state_null
from . import MappedEvent, RecordContext


def map_event(ctx: RecordContext, eid: int) -> MappedEvent | None:
    data = dict(ctx.eventdata)
    time_block = parse_evtx_time(ctx.system_time)
    host: dict[str, Any] = {"hostname": ctx.computer} if ctx.computer else {}

    if eid == 4104:
        ps: dict[str, Any] = {}
        if data.get("MessageNumber") is not None:
            ps["message_number"] = parse_int_or_null(data["MessageNumber"])
        if data.get("MessageTotal") is not None:
            ps["message_total"] = parse_int_or_null(data["MessageTotal"])
        if data.get("ScriptBlockText") is not None:
            ps["script_block_text"] = data["ScriptBlockText"]
        if data.get("ScriptBlockId"):
            ps["script_block_id"] = data["ScriptBlockId"]
        if data.get("Path") is not None:
            raw = data["Path"]
            ps["script_path"] = state_null(raw) if raw == "" else raw
        consumed = {"MessageNumber", "MessageTotal", "ScriptBlockText", "ScriptBlockId", "Path"}
        unmapped = [{"name": k, "value": v} for k, v in data.items() if k not in consumed]
        return MappedEvent(
            category="powershell", event_type="script_block_logging", action="log",
            outcome="success", severity="informational", derived_by="source",
            time_block=time_block, host=host, user={},
            payload_key="powershell", payload=ps, unmapped=unmapped,
        )

    return None
