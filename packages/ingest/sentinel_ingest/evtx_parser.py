"""EVTX → canonical-event/v1 via the PyPI `evtx` crate bindings (D3-001).

Binding API (verified locally, evtx 0.13.1):
    PyEvtxParser(path_or_file_like) — usable once
    .records() yields dicts {event_record_id, timestamp, data} where `data`
    is the crate-rendered XML string.
Fallback per D3-001: python-evtx (Apache-2.0) — not wired for M1 (crate
bindings install cleanly on the target; fallback noted as contingency).
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Iterator

from evtx import PyEvtxParser

from .envelope import build_envelope
from .mappings import MappedEvent, RecordContext, default_classification, map_record

_NS_EVENT = "{http://schemas.microsoft.com/win/2004/08/events/event}"


@dataclass
class ParseStats:
    records_total: int = 0
    events_mapped: int = 0
    unmapped_eid: int = 0
    parse_errors: int = 0


def _strip(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_record_xml(xml_text: str) -> RecordContext | None:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    event_id: int | None = None
    channel = provider = computer = security_uid = system_time = None
    record_id: int | None = None
    eventdata: dict[str, str] = {}
    positional: dict[int, str] = {}
    userdata: dict[str, str] = {}
    for el in root:
        kind = _strip(el.tag)
        if kind == "System":
            for child in el:
                name = _strip(child.tag)
                if name == "Provider":
                    provider = child.get("Name")
                elif name == "EventID":
                    try:
                        event_id = int((child.text or "").strip())
                    except ValueError:
                        event_id = None
                elif name == "TimeCreated":
                    system_time = child.get("SystemTime")
                elif name == "EventRecordID":
                    try:
                        record_id = int((child.text or "").strip())
                    except ValueError:
                        record_id = None
                elif name == "Channel":
                    channel = (child.text or "").strip()
                elif name == "Computer":
                    computer = (child.text or "").strip()
                elif name == "Security":
                    security_uid = child.get("UserID")
        elif kind == "EventData":
            unnamed = 0
            for child in el:
                if _strip(child.tag) != "Data":
                    continue
                text = child.text if child.text is not None else ""
                fname = child.get("Name")
                if fname:
                    eventdata[fname] = text
                else:
                    unnamed += 1
                    positional[unnamed] = text
        elif kind == "UserData":
            for child in el:
                for leaf in child:
                    userdata[_strip(leaf.tag)] = leaf.text if leaf.text is not None else ""
    return RecordContext(
        event_id=event_id,
        channel=channel,
        provider=provider,
        computer=computer,
        security_user_id=security_uid,
        system_time=system_time,
        record_id=record_id,
        eventdata=eventdata,
        positional=positional,
        userdata=userdata,
        raw_xml=xml_text,
    )


def iter_envelopes(
    path: str,
    *,
    tenant_id: str,
    workspace_id: str,
    run_id: str,
    file_id: str,
    file_sha256: str | None,
    stats: ParseStats,
) -> Iterator[dict[str, Any]]:
    parser = PyEvtxParser(path)
    for record in parser.records():
        stats.records_total += 1
        xml_text = record.get("data") or ""
        ctx = parse_record_xml(xml_text)
        if ctx is None:
            stats.parse_errors += 1
            continue
        mapped: MappedEvent | None = map_record(ctx)
        if mapped is None:
            stats.unmapped_eid += 1
            continue
        envelope = build_envelope(
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            run_id=run_id,
            file_id=file_id,
            file_sha256=file_sha256,
            channel=ctx.channel,
            provider=ctx.provider,
            event_id=ctx.event_id,
            record_id=ctx.record_id,
            category=mapped.category,
            event_type=mapped.event_type,
            action=mapped.action,
            outcome=mapped.outcome,
            severity=mapped.severity,
            derived_by=mapped.derived_by,
            time_block=mapped.time_block,
            host=mapped.host,
            user=mapped.user,
            payload_key=mapped.payload_key,
            payload=mapped.payload,
            raw=ctx.raw_xml,
            unmapped=mapped.unmapped,
        )
        envelope["classification"] = default_classification(ctx.channel, ctx.provider)
        stats.events_mapped += 1
        yield envelope
