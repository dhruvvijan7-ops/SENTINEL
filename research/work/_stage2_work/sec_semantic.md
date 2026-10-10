## 4. Semantic Classification Spec

**Three-level model (resolves Stage-1 OPEN-QUESTION Q1).** Every canonical
event is classifiable along three independent levels. Levels 1 and 2 live in
`source.format` and `source.record.type` (envelope); level 3 lives in
`event.category` + `event.type` (payload selection). Parsers set levels 1-2
mechanically; level 3 is set by the mapping tables in §2 (labelled
`event.derived_by`).

| Level | Question answered | Where it lives | Set by |
|---|---|---|---|
| **1. File format** | What is the physical container? | `source.format` (enum) | Parser, from sniffing/magic bytes/extension contract |
| **2. Semantic data type** | What logical record shape does this row/record have? | `source.record.type` + `source.channel`/`source.provider` (EVTX channel+EID; Zeek log name; EVE `event_type`; CSV header set) | Parser, from container metadata |
| **3. Security behaviour** | What security-relevant behaviour does the record describe? | `event.category` (26 values) + `event.type` (snake_case) + `event.action`/`outcome`, with `event.derived_by` marking source-vs-Sentinel authorship | Mapping table (§2); `derived_by: sentinel` when Sentinel authors the classification (snapshot exports, third-party alert typing, LSM semantics — D2-009/D2-010) |

**Worked examples.** Each example names a concrete source record and
classifies it at all three levels; the canonical example ids point into §5.

1. **Sysmon EID 1, `Image=C:\Windows\System32\cmd.exe`, `ProcessGuid={a6f…}`**
   - L1 `evtx` (channel `Microsoft-Windows-Sysmon/Operational`)
   - L2 `event_record` (EVTX record, `source.event_id=1`)
   - L3 `process` / `process_create`, action `create`, outcome `success`,
     `derived_by: source` (Sysmon's own event name "Process creation")
   - Canonical example: `EX-SYSMON-1`.

2. **Sysmon EID 13, `TargetObject=HKLM\...\Run\Updater`, `Details=C:\temp\x.exe`**
   - L1 `evtx`; L2 `event_record` (EID 13)
   - L3 `registry` / `registry_set`, action `set`, `derived_by: source`
   - Canonical example: `EX-SYSMON-13`.

3. **Sysmon EID 3, `Initiated=true`, `DestinationIp=203.0.113.5`**
   - L1 `evtx`; L2 `event_record` (EID 3)
   - L3 `network` / `network_connection`, action `connect`,
     `direction=outbound` (INFERRED from `Initiated` — value-level
     `inferred`; classification itself is `source`), `derived_by: source`
   - Canonical example: `EX-SYSMON-3`.

4. **Security 4624, `LogonType=3`, `IpAddress=10.0.0.5`**
   - L1 `evtx` (channel `Security`)
   - L2 `event_record` (EID 4624)
   - L3 `authentication` / `logon_success`, action `logon`, outcome
     `success`, `derived_by: source` (Security subcategory semantics)
   - Canonical example: `EX-SEC-4624`.

5. **Security 4625, `Status=0xC000006D`, `SubStatus=0xC0000064`**
   - L1 `evtx`; L2 `event_record` (EID 4625)
   - L3 `authentication` / `logon_failure`, action `logon`, outcome
     `failure`, `derived_by: source`
   - Canonical example: `EX-SEC-4625`.

6. **Security 5156, `Direction=%%14592`, `DestAddress=198.51.100.7`**
   - L1 `evtx`; L2 `event_record` (EID 5156)
   - L3 `network` / `packet_filtered` (WFP allow/deny), `derived_by: source`;
     the `%%`-code → `direction` enum mapping is INFERRED and flagged
     UNVERIFIED in SEC-A — parsers emit `$state: unknown` until the
     direction code table is corroborated
   - Canonical example: `EX-SEC-5156`.

7. **Windows Defender 1116, `Threat Name=HackTool:PowerShell/Mimikatz`,
   `Severity Name=High`** (real record from this host, 2026-10-08)
   - L1 `evtx` (channel `Microsoft-Windows-Windows Defender/Operational`)
   - L2 `event_record` (EID 1116) — 42 named elements incl. space-bearing
     names (`Threat Name`, `Product Name`)
   - L3 `third_party_alert` / `malware_detected`, action `detect`,
     outcome `success`, `derived_by: sentinel` (Defender does not publish a
     canonical event taxonomy; Sentinel types it as an alert)
   - Canonical example: `EX-WIN-1116`.

8. **PowerShell 4104, `ScriptBlockText='#!/usr/bin/env pwsh ...'`,
   `ScriptBlockId=d8bf42e3-…`** (real record from this host)
   - L1 `evtx` (channel `Microsoft-Windows-PowerShell/Operational`)
   - L2 `event_record` (EID 4104); `MessageNumber`/`MessageTotal` enable
     multi-part reassembly (level-2 property, not behaviour)
   - L3 `powershell` / `script_block`, action `execute`, `derived_by: source`
   - Canonical example: `EX-WIN-4104`.

9. **Zeek conn.log row `ts=1728234959.822772 uid=C12… id.orig_h=192.168.1.10
   id.resp_h=203.0.113.5 id.resp_p=443 proto=tcp conn_state=S1`**
   - L1 `tsv` (Zeek's tab-separated log with `#fields` header)
   - L2 `row` (one conn.log line; column set defined by the `#fields`
     header — parser must bind columns by header, never by position)
   - L3 `network` / `connection`, action `observe`, `derived_by: sentinel`
     (Zeek frames this as connection metadata, not a security verdict)
   - Canonical example: `EX-ZEEK-conn`.

10. **Suricata EVE `{"event_type":"alert","alert":{"signature":"ET
    TROJAN Cobalt Strike Beacon","signature_id":2031234,"severity":1}}`**
    - L1 `json` (one JSON object per line — EVE JSON)
    - L2 `row` (JSON line; `event_type` field selects the payload schema)
    - L3 `third_party_alert` / `alert`, `derived_by: sentinel` (Suricata's
      `alert` object is vendor-typed; Sentinel normalises to
      `third_party_alert` with `vendor: suricata`)
    - Canonical example: `EX-EVE-alert`.

11. **`netstat -ano` row `TCP 0.0.0.0:49664 0.0.0.0:0 LISTENING 1234`**
    - L1 `text` (console command output)
    - L2 `line` (fixed column layout per Microsoft docs; no timestamps)
    - L3 `network` / `connection_snapshot`, `derived_by: sentinel`
      (snapshot semantics: point-in-time state, not an event; `time.state:
      unknown` — netstat carries no timestamp; PID-only process linkage
      carries the documented PID-reuse failure mode)
    - Canonical example: `EX-NETSTAT-1`.

12. **`reg export HKLM\...\Run run.reg` output line
    `"Updater"="C:\\temp\\x.exe"`**
    - L1 `text` (`.reg` file format — documented header + quoted
      key/value lines)
    - L2 `row` (one value line inside an exported key block; key path
      inherited from the preceding `[...]` line)
    - L3 `registry` / `registry_set`, `derived_by: sentinel` (an export is
      a static snapshot; `event.type` is `registry_set` because the value
      exists as of export time — no create-vs-set distinction is
      recoverable; documented limitation)
    - Canonical example: `EX-REGEXPORT-1`.

13. **Autoruns CSV row `Autoruns Entry, Launch
    Point, Image Path, HKLM\...\Run, updater, C:\temp\x.exe`**
    - L1 `csv` (RFC-4180-ish comma-separated with header row)
    - L2 `row` (header-driven: the parser binds columns by header names at
      runtime; autorunsc column sets vary by version — headers are
      UNVERIFIED against Sysinternals docs, see NOT_VERIFIED)
    - L3 `config_check` / `autostart_entry`, `derived_by: sentinel`
      (Autoruns reports configuration, not behaviour; each row becomes a
      config observation)
    - Canonical example: `EX-AUTORUNS-1`.

**Classification invariants.**
- L1 and L2 are *descriptive*: two sources may share L3 while differing in
  L1/L2 (Sysmon EID 1 and Security 4688 both → `process`/`process_create`,
  but L1/L2 differ: different channels, different field inventories — that
  is why detectors must not assume source field names).
- L3 is *behavioural*: one source record produces exactly one canonical
  event with one `event.category`. Sources that blend behaviours (e.g.
  Suricata `alert` carrying an embedded `http` object) emit ONE event of
  the dominant category (`third_party_alert`) and keep the embedded payload
  fields in `unmapped` or a secondary event only if the mapping table says
  so (SEC-B EVE table is authoritative).
- `event.derived_by` never mixes within one classification decision: if any
  of category/type/action/outcome/severity was authored by Sentinel, the
  whole classification is `sentinel`.

---
