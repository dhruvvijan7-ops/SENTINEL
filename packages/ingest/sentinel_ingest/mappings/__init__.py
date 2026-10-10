"""EVTX record → canonical-event classification (Stage-2 §2 tables).

One source record → exactly one canonical event with exactly one
`event.category` (Stage-2 classification invariant).  Unknown
(channel, provider, eid) triples return None — the caller counts them as
`unmapped_eid` and never invents fields (D2-017 discipline).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# NOTE: submodule imports live at the bottom of this module.  security.py etc.
# do `from . import MappedEvent, RecordContext`, so importing them at the top
# hits a partially initialized package (circular import).


@dataclass
class RecordContext:
    event_id: int | None
    channel: str | None
    provider: str | None
    computer: str | None
    security_user_id: str | None
    system_time: str | None
    record_id: int | None
    eventdata: dict[str, str] = field(default_factory=dict)
    positional: dict[int, str] = field(default_factory=dict)
    userdata: dict[str, str] = field(default_factory=dict)
    raw_xml: str = ""


@dataclass
class MappedEvent:
    category: str
    event_type: str
    action: str
    outcome: str
    severity: str
    derived_by: str
    time_block: dict[str, Any]
    host: dict[str, Any]
    user: dict[str, Any]
    payload_key: str | None
    payload: dict[str, Any] | None
    unmapped: list[dict[str, Any]]


def default_classification(channel: str | None, provider: str | None) -> str:
    """M1 per-source data-sensitivity default (spec-change request logged:
    the full per-source map is unspecified; schema example cites Windows
    Security EVTX => restricted)."""
    ch = (channel or "").lower()
    pr = (provider or "").lower()
    if ch == "security" or "defender" in pr or "powershell" in ch:
        return "restricted"
    return "internal"


def _is_sysmon(ctx: RecordContext) -> bool:
    return (ctx.provider or "") == "Microsoft-Windows-Sysmon" or "sysmon" in (
        ctx.channel or ""
    ).lower()


def _is_security(ctx: RecordContext) -> bool:
    return (ctx.provider or "") == "Microsoft-Windows-Security-Auditing" or (
        ctx.channel or ""
    ) == "Security"


def map_record(ctx: RecordContext) -> MappedEvent | None:
    from . import powershell, security, sysmon, system

    eid = ctx.event_id
    if eid is None:
        return None
    if _is_sysmon(ctx):
        return sysmon.map_event(ctx, eid)
    if _is_security(ctx):
        return security.map_event(ctx, eid)
    if (ctx.channel or "") == "System" and (
        (ctx.provider or "") == "Service Control Manager" or eid in (104,)
    ):
        return system.map_event(ctx, eid)
    if "powershell" in (ctx.provider or "").lower() or "powershell" in (
        ctx.channel or ""
    ).lower():
        return powershell.map_event(ctx, eid)
    return None
