"""Windows Security mapping tables (Stage-2 §2.2): 1102, 4624, 4625, 4688, 4720."""
from __future__ import annotations

from typing import Any

from ..envelope import (
    basename_windows,
    hex_pid,
    is_sid,
    null_or_string,
    parse_evtx_time,
    parse_int_or_null,
    state_invalid,
    state_null,
    state_unknown,
)
from . import MappedEvent, RecordContext


def _subject_user(data: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if data.get("SubjectUserSid"):
        out["sid"] = data["SubjectUserSid"]
    if data.get("SubjectUserName") and data["SubjectUserName"] not in ("-", ""):
        out["name"] = data["SubjectUserName"]
    if data.get("SubjectDomainName") and data["SubjectDomainName"] not in ("-", ""):
        out["domain"] = data["SubjectDomainName"]
    if data.get("SubjectLogonId") and data["SubjectLogonId"] not in ("-", ""):
        out["logon_id"] = data["SubjectLogonId"]
    return out


def _elev_token(raw: str | None) -> Any:
    if raw is None or raw == "":
        return None
    if raw in ("Yes", "true", "TRUE", "True"):
        return True
    if raw in ("No", "false", "FALSE", "False"):
        return False
    if raw.startswith("%%"):
        return state_invalid(
            raw, "%%nnnn message-table constant; expansion lives in message table, not EVTX"
        )
    return state_unknown("unrecognized ElevatedToken rendering")


def _dash_or_str(raw: str | None) -> Any:
    return null_or_string(raw, dash_is_null=True)


_UNMAPPED_4624 = (
    "LogonProcessName", "TransmittedServices", "LmPackageName", "IpPort",
    "ImpersonationLevel", "RestrictedAdminMode", "TargetOutboundUserName",
    "TargetOutboundDomainName", "VirtualAccount", "TargetLinkedLogonId",
)


def map_event(ctx: RecordContext, eid: int) -> MappedEvent | None:
    data = dict(ctx.eventdata)
    unmapped: list[dict[str, Any]] = []
    time_block = parse_evtx_time(ctx.system_time)
    host: dict[str, Any] = {"hostname": ctx.computer} if ctx.computer else {}
    user = _subject_user(data)
    consumed = set(data)  # default-consume; unmapped re-added per EID lists

    if eid == 1102:
        # UserData path: fields live under <LogFileCleared>, not EventData.
        ud = dict(ctx.userdata)
        user = {}
        if ud.get("SubjectUserSid"):
            user["sid"] = ud["SubjectUserSid"]
        if ud.get("SubjectUserName") and ud["SubjectUserName"] not in ("-", ""):
            user["name"] = ud["SubjectUserName"]
        if ud.get("SubjectDomainName") and ud["SubjectDomainName"] not in ("-", ""):
            user["domain"] = ud["SubjectDomainName"]
        if ud.get("SubjectLogonId") and ud["SubjectLogonId"] not in ("-", ""):
            user["logon_id"] = ud["SubjectLogonId"]
        return MappedEvent(
            category="fim", event_type="audit_log_cleared", action="clear",
            outcome="success", severity="informational", derived_by="sentinel",
            time_block=time_block, host=host, user=user,
            payload_key="fim", payload={"operation": "audit_log_cleared"},
            unmapped=[],
        )

    if eid == 4624:
        auth: dict[str, Any] = {}
        if data.get("LogonType") is not None:
            auth["logon_type"] = parse_int_or_null(data["LogonType"])
        if data.get("TargetLogonId") is not None:
            auth["logon_id"] = _dash_or_str(data["TargetLogonId"])
        if data.get("LogonGuid"):
            auth["logon_guid"] = data["LogonGuid"]
        if data.get("TargetUserSid"):
            auth["account_sid"] = data["TargetUserSid"]
        if data.get("TargetUserName"):
            auth["account_name"] = data["TargetUserName"]
        if data.get("TargetDomainName"):
            auth["account_domain"] = data["TargetDomainName"]
        if data.get("IpAddress") is not None:
            auth["source_ip"] = _dash_or_str(data["IpAddress"])
        if data.get("WorkstationName") is not None:
            auth["workstation"] = _dash_or_str(data["WorkstationName"])
        if data.get("AuthenticationPackageName") is not None:
            auth["auth_package"] = _dash_or_str(data["AuthenticationPackageName"])
        if data.get("KeyLength") is not None:
            auth["key_length"] = parse_int_or_null(data["KeyLength"])
        if data.get("ProcessId") is not None:
            auth["process_pid"] = hex_pid(data["ProcessId"])
        if data.get("ProcessName") is not None:
            auth["process_name"] = _dash_or_str(data["ProcessName"])
        elev = _elev_token(data.get("ElevatedToken"))
        if elev is not None:
            auth["elev_token"] = elev
        for name in _UNMAPPED_4624:
            if name in data:
                unmapped.append({"name": name, "value": data[name]})
        return MappedEvent(
            category="authentication", event_type="logon_success", action="logon",
            outcome="success", severity="informational", derived_by="source",
            time_block=time_block, host=host, user=user,
            payload_key="authentication", payload=auth, unmapped=unmapped,
        )

    if eid == 4625:
        auth = {}
        if data.get("LogonType") is not None:
            auth["logon_type"] = parse_int_or_null(data["LogonType"])
        if data.get("TargetLogonId") is not None:
            auth["logon_id"] = _dash_or_str(data["TargetLogonId"])
        if data.get("TargetUserSid"):
            auth["account_sid"] = data["TargetUserSid"]
        if data.get("TargetUserName"):
            auth["account_name"] = data["TargetUserName"]
        if data.get("TargetDomainName"):
            auth["account_domain"] = data["TargetDomainName"]
        if data.get("Status") is not None:
            auth["status"] = data["Status"]
        if data.get("FailureReason") is not None:
            auth["failure_reason"] = data["FailureReason"]
        if data.get("SubStatus") is not None:
            auth["sub_status"] = data["SubStatus"]
        if data.get("AuthenticationPackageName") is not None:
            auth["auth_package"] = _dash_or_str(data["AuthenticationPackageName"])
        if data.get("WorkstationName") is not None:
            auth["workstation"] = _dash_or_str(data["WorkstationName"])
        if data.get("KeyLength") is not None:
            auth["key_length"] = parse_int_or_null(data["KeyLength"])
        if data.get("ProcessId") is not None:
            auth["process_pid"] = hex_pid(data["ProcessId"])
        if data.get("ProcessName") is not None:
            auth["process_name"] = _dash_or_str(data["ProcessName"])
        if data.get("IpAddress") is not None:
            auth["source_ip"] = _dash_or_str(data["IpAddress"])
        for name in ("LogonProcessName", "TransmittedServices", "LmPackageName", "IpPort"):
            if name in data:
                unmapped.append({"name": name, "value": data[name]})
        return MappedEvent(
            category="authentication", event_type="logon_failure", action="logon",
            outcome="failure", severity="informational", derived_by="source",
            time_block=time_block, host=host, user=user,
            payload_key="authentication", payload=auth, unmapped=unmapped,
        )

    if eid == 4688:
        proc: dict[str, Any] = {}
        if data.get("NewProcessId") is not None:
            proc["pid"] = hex_pid(data["NewProcessId"])
        if data.get("NewProcessName"):
            proc["exe"] = data["NewProcessName"]
            proc["name"] = basename_windows(data["NewProcessName"])
        if data.get("CommandLine") is not None:
            proc["command_line"] = null_or_string(data["CommandLine"], dash_is_null=True)
        integrity = data.get("MandatoryLabel") or data.get("TokenElevationType")
        if integrity:
            proc["integrity_level"] = integrity
        parent: dict[str, Any] = {}
        if data.get("ProcessId") is not None:
            parent["pid"] = hex_pid(data["ProcessId"])
        if data.get("ParentProcessName"):
            parent["exe"] = data["ParentProcessName"]
            parent["name"] = basename_windows(data["ParentProcessName"])
        if parent:
            proc["parent"] = parent
        if data.get("TargetUserSid"):
            proc["owner_sid"] = data["TargetUserSid"]
        if data.get("TargetUserName"):
            proc["owner_name"] = data["TargetUserName"]
        for name in ("TargetDomainName", "TargetLogonId"):
            if name in data:
                unmapped.append({"name": name, "value": data[name]})
        return MappedEvent(
            category="process", event_type="process_create", action="create",
            outcome="success", severity="informational", derived_by="source",
            time_block=time_block, host=host, user=user,
            payload_key="process", payload=proc, unmapped=unmapped,
        )

    if eid == 4720:
        account: dict[str, Any] = {}
        if data.get("TargetUserName"):
            account["name"] = data["TargetUserName"]
        if data.get("TargetDomainName"):
            account["domain"] = data["TargetDomainName"]
        if data.get("TargetSid"):
            account["sid"] = data["TargetSid"]
        if data.get("SamAccountName") is not None:
            account["sam_account_name"] = _dash_or_str(data["SamAccountName"])
        if data.get("DisplayName") is not None:
            account["display_name"] = _dash_or_str(data["DisplayName"])
        if data.get("UserPrincipalName") is not None:
            account["upn"] = _dash_or_str(data["UserPrincipalName"])
        if data.get("SidHistory") is not None:
            account["sid_history"] = _dash_or_str(data["SidHistory"])
        for name in (
            "PrivilegeList", "HomeDirectory", "HomePath", "ScriptPath",
            "ProfilePath", "UserWorkstations", "PasswordLastSet", "AccountExpires",
            "PrimaryGroupId", "AllowedToDelegateTo", "OldUacValue", "NewUacValue",
            "UserAccountControl", "UserParameters", "LogonHours",
        ):
            if name in data:
                unmapped.append({"name": name, "value": data[name]})
        return MappedEvent(
            category="account", event_type="account_created", action="create",
            outcome="success", severity="informational", derived_by="source",
            time_block=time_block, host=host, user=user,
            payload_key="account", payload=account, unmapped=unmapped,
        )

    return None
