"""Sysmon mapping tables (Stage-2 §2.1): EID 1, 3, 11, 22 (M1 set)."""
from __future__ import annotations

from typing import Any

from ..envelope import (
    basename_windows,
    is_sid,
    null_or_string,
    parse_int_or_null,
    parse_sysmon_time,
    split_domain_user,
    split_hashes,
    state_null,
)
from . import MappedEvent, RecordContext

_UNMAPPED_ALWAYS = ("RuleName",)


def _consume(
    data: dict[str, str], name: str, unmapped: list[dict[str, Any]]
) -> str | None:
    """Take field `name`; if absent return None; caller decides mapping.  Any
    field never consumed lands in unmapped[] via _sweep()."""
    return data.get(name)


def _sweep(data: dict[str, str], consumed: set[str], unmapped: list[dict[str, Any]]) -> None:
    for name, value in data.items():
        if name not in consumed:
            unmapped.append({"name": name, "value": value})


def _sysmon_user(data: dict[str, str]) -> tuple[str | None, dict[str, Any] | None]:
    raw = data.get("User")
    if raw is None or raw == "" or raw == "-":
        return None, None
    if is_sid(raw):
        return raw, {"sid": raw}
    parts = raw.split("\\")
    if len(parts) == 2:
        return parts[1], {"name": parts[1], "domain": parts[0]}
    return raw, {"name": raw}


def _process_payload(data: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if data.get("ProcessGuid"):
        out["guid"] = data["ProcessGuid"]
    pid = data.get("ProcessId")
    if pid is not None:
        out["pid"] = parse_int_or_null(pid) if pid not in ("", "-") else state_null(pid)
    if data.get("Image"):
        out["exe"] = data["Image"]
        out["name"] = basename_windows(data["Image"])
    owner, _ = _sysmon_user(data)
    if owner is not None:
        raw = data.get("User", "")
        if is_sid(raw):
            out["owner_sid"] = raw
        else:
            out["owner_name"] = owner
    return out


def map_event(ctx: RecordContext, eid: int) -> MappedEvent | None:
    data = dict(ctx.eventdata)
    unmapped: list[dict[str, Any]] = []
    consumed: set[str] = set()
    time_block = parse_sysmon_time(data.get("UtcTime"))
    consumed.add("UtcTime")
    host: dict[str, Any] = {"hostname": ctx.computer} if ctx.computer else {}
    user_obj: dict[str, Any] = {}
    owner, user_split = _sysmon_user(data)
    if user_split:
        user_obj = user_split

    if eid == 1:
        consumed |= {
            "ProcessGuid", "ProcessId", "Image", "OriginalFileName",
            "CommandLine", "CurrentDirectory", "User", "LogonGuid", "LogonId",
            "TerminalSessionId", "IntegrityLevel", "Hashes",
            "ParentProcessGuid", "ParentProcessId", "ParentImage",
            "ParentCommandLine", "ParentUser",
        }
        proc: dict[str, Any] = {}
        if data.get("ProcessGuid"):
            proc["guid"] = data["ProcessGuid"]
        if data.get("ProcessId") not in (None, "", "-"):
            proc["pid"] = parse_int_or_null(data["ProcessId"])
        if data.get("Image"):
            proc["exe"] = data["Image"]
            proc["name"] = basename_windows(data["Image"])
        if data.get("CommandLine") is not None:
            proc["command_line"] = null_or_string(data["CommandLine"], dash_is_null=False)
        if data.get("CurrentDirectory") is not None:
            proc["current_dir"] = data["CurrentDirectory"]
        if data.get("IntegrityLevel"):
            proc["integrity_level"] = data["IntegrityLevel"]
        if data.get("LogonGuid"):
            proc["logon_guid"] = data["LogonGuid"]
        if data.get("LogonId"):
            proc["logon_id"] = data["LogonId"]
        if data.get("TerminalSessionId") not in (None, "", "-"):
            proc["terminal_session_id"] = parse_int_or_null(data["TerminalSessionId"])
        if data.get("OriginalFileName"):
            proc["original_file_name"] = data["OriginalFileName"]
        if data.get("Hashes"):
            hashes, _ = split_hashes(data["Hashes"])
            if hashes:
                proc["hashes"] = hashes
        parent: dict[str, Any] = {}
        if data.get("ParentProcessGuid"):
            parent["guid"] = data["ParentProcessGuid"]
        if data.get("ParentProcessId") not in (None, "", "-"):
            parent["pid"] = parse_int_or_null(data["ParentProcessId"])
        if data.get("ParentImage"):
            parent["exe"] = data["ParentImage"]
            parent["name"] = basename_windows(data["ParentImage"])
        if data.get("ParentCommandLine"):
            parent["command_line"] = data["ParentCommandLine"]
        if data.get("ParentUser"):
            if is_sid(data["ParentUser"]):
                parent["owner_sid"] = data["ParentUser"]
            else:
                unmapped.append({"name": "ParentUser", "value": data["ParentUser"]})
        if parent:
            proc["parent"] = parent
        if owner is not None and user_obj.get("name"):
            proc["owner_name"] = user_obj["name"]
        elif owner is not None and user_obj.get("sid"):
            proc["owner_sid"] = user_obj["sid"]
        _sweep(data, consumed | _UNMAPPED_ALWAYS_SET(data), unmapped)
        return MappedEvent(
            category="process", event_type="process_create", action="create",
            outcome="success", severity="informational", derived_by="source",
            time_block=time_block, host=host, user=user_obj,
            payload_key="process", payload=proc, unmapped=unmapped,
        )

    if eid == 3:
        consumed |= {
            "ProcessGuid", "ProcessId", "Image", "User", "Protocol", "Initiated",
            "SourceIp", "SourcePort", "DestinationIp", "DestinationPort",
        }
        proc = _process_payload(data)
        net: dict[str, Any] = {}
        if data.get("Protocol"):
            net["protocol"] = data["Protocol"]
        if data.get("Initiated") is not None:
            direction = "outbound" if data["Initiated"].lower() == "true" else "inbound"
            net["direction"] = {
                "$state": "inferred",
                "$note": f"mapped from Initiated={data['Initiated'].lower()}",
            }
            _ = direction  # value intentionally not re-emitted (EX-SYSMON-3)
        if data.get("SourceIp"):
            net["src_ip"] = data["SourceIp"]
        if data.get("SourcePort") not in (None, "", "-"):
            net["src_port"] = parse_int_or_null(data["SourcePort"])
        if data.get("DestinationIp"):
            net["dst_ip"] = data["DestinationIp"]
        if data.get("DestinationPort") not in (None, "", "-"):
            net["dst_port"] = parse_int_or_null(data["DestinationPort"])
        if proc:
            net["process"] = proc
        _sweep(data, consumed | _UNMAPPED_ALWAYS_SET(data), unmapped)
        return MappedEvent(
            category="network", event_type="network_connection", action="connect",
            outcome="success", severity="informational", derived_by="source",
            time_block=time_block, host=host, user=user_obj,
            payload_key="network", payload=net, unmapped=unmapped,
        )

    if eid == 11:
        consumed |= {"ProcessGuid", "ProcessId", "Image", "User", "TargetFilename", "CreationUtcTime"}
        proc = _process_payload(data)
        file_payload: dict[str, Any] = {}
        if data.get("TargetFilename"):
            file_payload["path"] = data["TargetFilename"]
        if data.get("CreationUtcTime"):
            file_payload["created"] = data["CreationUtcTime"]
        payload: dict[str, Any] = dict(file_payload)
        if proc:
            payload["process"] = proc
        _sweep(data, consumed | _UNMAPPED_ALWAYS_SET(data), unmapped)
        return MappedEvent(
            category="file", event_type="file_create", action="create",
            outcome="success", severity="informational", derived_by="source",
            time_block=time_block, host=host, user=user_obj,
            payload_key="file", payload=payload, unmapped=unmapped,
        )

    if eid == 22:
        consumed |= {
            "ProcessGuid", "ProcessId", "QueryName", "QueryType", "QueryStatus",
            "QueryResults", "Image", "User",
        }
        outcome = "success"
        if data.get("QueryStatus") is not None:
            try:
                outcome = "success" if int(data["QueryStatus"]) == 0 else "failure"
            except ValueError:
                outcome = "unknown"
        dns: dict[str, Any] = {}
        if data.get("QueryName"):
            dns["query_name"] = data["QueryName"]
        if data.get("QueryType"):
            dns["query_type"] = data["QueryType"]
        if data.get("QueryStatus"):
            dns["query_status"] = data["QueryStatus"]
        if data.get("QueryResults") is not None:
            dns["answers"] = [data["QueryResults"]]
        proc = _process_payload(data)
        if proc:
            dns["process"] = proc
        _sweep(data, consumed | _UNMAPPED_ALWAYS_SET(data), unmapped)
        return MappedEvent(
            category="dns", event_type="dns_query", action="query",
            outcome=outcome, severity="informational", derived_by="source",
            time_block=time_block, host=host, user=user_obj,
            payload_key="dns", payload=dns, unmapped=unmapped,
        )

    return None


def _UNMAPPED_ALWAYS_SET(data: dict[str, str]) -> set[str]:
    return {n for n in _UNMAPPED_ALWAYS if n in data}
