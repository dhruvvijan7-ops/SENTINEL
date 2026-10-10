"""Contract tests: every emitted envelope validates against
canonical_event_v1.schema.json (the schema outranks prose)."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from sentinel_ingest.evtx_parser import parse_record_xml
from sentinel_ingest.mappings import map_record, default_classification
from sentinel_ingest.envelope import build_envelope

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "canonical_event_v1.schema.json").read_text(encoding="utf-8"))

_SYSMON_1_XML = """<?xml version="1.0"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>1</EventID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>HOST-A</Computer>
    <EventRecordID>42</EventRecordID>
    <TimeCreated SystemTime="2026-01-02T03:04:05.1234567Z"/>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-01-02 03:04:05.123</Data>
    <Data Name="ProcessGuid">{11111111-2222-3333-4444-555555555555}</Data>
    <Data Name="ProcessId">0x4c8</Data>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="User">NT AUTHORITY\\SYSTEM</Data>
    <Data Name="Hashes">SHA256=AAAA,MD5=BBBB</Data>
    <Data Name="RuleName">-</Data>
  </EventData>
</Event>
"""

_SEC_4624_XML = """<?xml version="1.0"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <Channel>Security</Channel>
    <Computer>HOST-B</Computer>
    <EventRecordID>7</EventRecordID>
    <TimeCreated SystemTime="2026-01-02T03:04:05.1234567Z"/>
  </System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">10.0.0.9</Data>
    <Data Name="ProcessId">0x4c8</Data>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
  </EventData>
</Event>
"""

_WIN_7045_XML = """<?xml version="1.0"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Service Control Manager"/>
    <EventID>7045</EventID>
    <Channel>System</Channel>
    <Computer>HOST-C</Computer>
    <EventRecordID>9</EventRecordID>
    <TimeCreated SystemTime="2026-01-02T03:04:05.1234567Z"/>
  </System>
  <EventData>
    <Data Name="ServiceName">EvilSvc</Data>
    <Data Name="ImagePath">C:\\Temp\\evil.exe</Data>
    <Data Name="ServiceType">user mode service</Data>
    <Data Name="StartType">auto start</Data>
    <Data Name="AccountName">LocalSystem</Data>
  </EventData>
</Event>
"""


def _envelope_from_xml(xml: str) -> dict:
    ctx = parse_record_xml(xml)
    assert ctx is not None
    mapped = map_record(ctx)
    assert mapped is not None, "M1 fixture EIDs must be mapped"
    env = build_envelope(
        tenant_id="default",
        workspace_id="default",
        run_id="contract-test",
        file_id="00000000-0000-7000-8000-0000000000ff",
        file_sha256=None,
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
    env["classification"] = default_classification(ctx.channel, ctx.provider)
    return env


@pytest.mark.parametrize(
    "xml",
    [_SYSMON_1_XML, _SEC_4624_XML, _WIN_7045_XML],
    ids=["sysmon-1", "sec-4624", "win-7045"],
)
def test_emitted_envelope_validates(xml):
    env = _envelope_from_xml(xml)
    jsonschema.validate(env, SCHEMA)


def test_sysmon_direction_inferred_shape():
    """EX-SYSMON-3 direction: state object with no enum value re-emitted."""
    xml = _SYSMON_1_XML.replace("EventID>1<", "EventID>3<").replace(
        "<Data Name=\"UtcTime\">",
        "<Data Name=\"Initiated\">true</Data><Data Name=\"SourceIp\">10.1.1.1</Data>"
        "<Data Name=\"DestinationIp\">10.1.1.2</Data><Data Name=\"SourcePort\">1234</Data>"
        "<Data Name=\"DestinationPort\">443</Data><Data Name=\"Protocol\">tcp</Data>"
        "<Data Name=\"UtcTime\">",
    )
    env = _envelope_from_xml(xml)
    jsonschema.validate(env, SCHEMA)
    network = env.get("network") or {}
    direction = network.get("direction")
    if direction is not None:
        assert isinstance(direction, dict)
        assert direction.get("$state") in ("inferred", "unknown", "invalid", "null")


def test_classification_default_map():
    env = _envelope_from_xml(_SEC_4624_XML)
    assert env["classification"] == "restricted"
    env2 = _envelope_from_xml(_WIN_7045_XML)
    assert env2["classification"] == "internal"


def test_no_bare_null_except_time_utc():
    env = _envelope_from_xml(_SYSMON_1_XML)

    def _walk(node, path=""):
        if node is None:
            # only allowed under time.utc
            assert path.endswith(".utc") or path.endswith("['utc']"), f"bare null at {path}"
            return
        if isinstance(node, dict):
            for k, v in node.items():
                _walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                _walk(v, f"{path}[{i}]")

    _walk(env)
