---
section_id: SEC-B
verification_log:
  - id: B-LOC-HARVEST
    source: "Local harvest — EVTX rendered to XML on this host (Windows 11 Home Single Language, build 26200, non-elevated, 2026-10-09). Produced by _stage2_work/harvest_local_events.ps1 + extract_fields.py into _stage2_work/local_eventfields.json. Authoritative for on-box <Data Name=...> element names and realistic value renderings. Present-and-found: System 7034/7036/7040/7043/7045; Windows PowerShell 400/403/600; PowerShell/Operational 4103/4104; Defender/Operational 1116/1117/5001/5007; WMI-Activity 5857/5858/5860; LSM 21/22/23/24/25/39. NOT found (channel disabled or no samples): System 104; TaskScheduler 106/140/141/200/201 (channel disabled); RCM 1149 (recordcount 0); AppLocker 8003/8004; PowerShell 4105/4106; classic PowerShell 800."
    url: "file:///C:/Users/dhruv/OneDrive/Desktop/College/Light%20HIDS/_stage2_work/local_eventfields.json"
    retrieved: 2026-10-09
    publisher: "local host (this machine)"
    version_or_commit: "harvest run 2026-10-09; Defender Engine Version 4.18.26080.4 / Product Version 4.18.26080.4; PowerShell Host Version 5.1.26100.9444"
    license: "n/a (locally generated)"
    method: "wevtutil query + render to XML on-box; Python regex over <Data Name=...>; label VERIFIED-LOCAL"
    label: VERIFIED
  - id: B-PS-MANIFEST
    source: "PowerShell instrumentation manifest — scripts/base/windows-powershell/src/powershell.man inside the PowerShell GitHub repo (publisher Microsoft-Windows-PowerShell). Contains per-event <data name=...> descriptors and message templates for 4103 (T_LOG_CONTEXT: ContextInfo, UserData, Payload), 4104 (T_ScriptBlock_Compiled: MessageNumber, MessageTotal, ScriptBlockText, ScriptBlockId, Path), 4105/4106 (T_ScriptBlock_Executed: ScriptBlockId, RunspaceId)."
    url: https://raw.githubusercontent.com/PowerShell/PowerShell/master/src/powershell-native/src/powershell.man
    retrieved: 2026-10-09
    publisher: Microsoft (via PowerShell/PowerShell repo)
    version_or_commit: master; saved copy s2workb/ps-instrumentation.man (221 KB)
    license: MIT (PowerShell repo license)
    method: HTTP GET (IWR) on 2026-10-09; local parse. Cross-verified against B-LOC-HARVEST 4103/4104 element names (identical). Applicability of these templates to the Microsoft-Windows-PowerShell publisher (vs PowerShellCore) is INFERRED.
    label: VERIFIED
  - id: B-SYS-ARCHIVE
    source: "Archived Microsoft Learn System event pages — Event ID 104 (EVENT_LOG_CLEARED, 'The %3 log file was cleared.', provider Microsoft-Windows-Eventlog), 7034 (EVENT_SERVICE_CRASH_NO_ACTION, 'The %1 service terminated unexpectedly. It has done this %2 time(s).' — param2 is occurrence COUNT, not exit code), 7036 ('The %1 service entered the %2 state.'), 7040 ('The start type of the %1 service was changed from %2 to %3.'), plus hub-basic-service.html table covering 7030/7035/7036/7037/7040."
    url: "pattern https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server/... (archived pages pg-104a/pg-104r2/pg-7034/pg-7036/pg-7040r2/hub-basic-service); 104 symbolic name per pg-104a; 7043/7045 have NO MS Learn page (HTTP 404)"
    retrieved: 2026-10-09
    publisher: Microsoft (archived Learn)
    version_or_commit: "per-page ms.date varies; archived Windows Server content"
    license: Microsoft Learn site terms
    method: "HTTP GET (IWR) archived pages on 2026-10-09; text extraction. Event 104 element names beyond param3 are UNVERIFIED (community candidates Channel/SubjectUserName/SubjectDomainName/SubjectUserSid/SubjectLogonId)."
    label: VERIFIED
  - id: B-DEFENDER-DOC
    source: "Microsoft Defender troubleshoot page — per-event symbolic names + message templates (1116 = MALWAREPROTECTION_STATE_MALWARE_DETECTED, 1117 = MALWAREPROTECTION_STATE_MALWARE_ACTION, 5001 = MALWAREPROTECTION_RTP_HAS_DISABLED_MANUALLY, 5007 = MALWAREPROTECTION_MPCFG_EXCLUSIONS_CHANGE, etc.). Confirms the 42-element detection/action shape seen locally."
    url: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus
    retrieved: 2026-10-09
    publisher: Microsoft (Microsoft Learn)
    version_or_commit: ms.date 2026 (page current at retrieval)
    license: Microsoft Learn site terms
    method: "HTTP GET (IWR) on 2026-10-09; text extraction of per-event template tables. Element names cross-verified against B-LOC-HARVEST (42 <Data> elements, identical set)."
    label: VERIFIED
  - id: B-APPLOCKER-DOC
    source: "Microsoft 'Using Event Viewer with AppLocker' page — message templates for 8000-8008/8020-8024 (8003/8004 audit-only allowed-vs-blocked; 8006/8007 with '<File name>' parameter). EventData element NAMES are not published on the page."
    url: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker
    retrieved: 2026-10-09
    publisher: Microsoft (Microsoft Learn)
    version_or_commit: ms.date 2025 (page current at retrieval)
    license: Microsoft Learn site terms
    method: "HTTP GET (IWR) on 2026-10-09; text extraction. EventData names UNVERIFIED (not enumerated by Microsoft)."
    label: VERIFIED
  - id: B-ZEEK-DOC
    source: "Zeek source clone — scripts/base/protocols/{conn,dns,http,ssl}/main.zeek and scripts/base/frameworks/{notice,files}/main.zeek + scripts/base/files/hash/main.zeek. Authoritative Info-record field lists with &log tags. No ja3/ja3s in base ssl/main.zeek (community package only). files.log uid = conn uid (no tx_uid exists in Zeek). conn_id record rendered as id.orig_h/id.orig_p/id.resp_h/id.resp_p/id.proto."
    url: file:///C:/Users/dhruv/AppData/Local/Temp/opencode/s2/zeek (local git clone; upstream github.com/zeek/zeek)
    retrieved: 2026-10-09
    publisher: "The Zeek Project / ISC"
    version_or_commit: "b5bf5e5e42e9015d78be5105d2fd1e41eb75361f (Thu Oct 8 2026), verified with git log -1"
    license: BSD 3-clause (Zeek license)
    method: "git log -1 for commit; Python parse of main.zeek records extracting field names with &log tag and type."
    label: VERIFIED
  - id: B-SURICATA-DOC
    source: "Suricata EVE JSON docs — docs.suricata.io/en/latest/output/eve/eve-json-format.html (per-event-type field reference: alert/dns/http/fileinfo/tls/ssh/... flow, src_ip/dest_ip/src_port/dest_port/proto/event_type/flow_id/timestamp common envelope) and en/latest/appendix/eve-index.html (event-type index listing alert,dns,http,fileinfo,tls,ssh,smtp,imap,pop,ftp,ftp_data,dhcp,rfb,rdp,sip,smb,dcerpc,nfs,tftp,ikev2,krb5,quic,mqtt,modbus,conn,netflow,stats,bittorrent,dnp3,enip,pgsql). Old readthedocs URL 404s."
    url: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
    retrieved: 2026-10-09
    publisher: "Open Information Security Foundation (OISF) / Suricata"
    version_or_commit: "en/latest at retrieval; saved copies s2workb/eve-format.html, s2workb/eve-index.html"
    license: GPL-2.0 (Suricata) / OISF docs license
    method: "HTTP GET (IWR) on 2026-10-09; text extraction of headings + field tokens + event-type index."
    label: VERIFIED
  - id: B-NMAP-DOC
    source: "Nmap XML DTD — local clone docs/nmap.dtd. Full ATTLIST extraction for nmaprun/scaninfo/host/status/address/hostname/ports/extraports/port/state/service/cpe/script/table/elem/os/portused/osmatch/osclass/distance/uptime/tcpsequence/ipidsequence/tcptssequence/trace/hop/times/output/runstats/finished/hosts. Authoritative for -oX output. nmap.org/book/data-elements.html returns 404; nmap-output.html (book/man-output) also saved."
    url: file:///C:/Users/dhruv/AppData/Local/Temp/opencode/s2/nmap/docs/nmap.dtd (local clone; upstream github.com/nmap/nmap)
    retrieved: 2026-10-09
    publisher: "Nmap Project / Gordon Lyon"
    version_or_commit: "Copyright 2001-2022 Nmap Software LLC (per DTD header); local clone"
    license: Nmap license / GPL-2.0 (nmap source)
    method: "Read local nmap.dtd; Python regex over <!ELEMENT>/< ATTLIST> declarations to enumerate every element and attribute."
    label: VERIFIED
  - id: B-WINSDOCS
    source: "WindowsServerDocs local clone — administration/windows-commands/{netstat,schtasks,schtasks-query,reg-export,sc-query,sc-config}.md. netstat column headers Proto/Local Address/Foreign Address/State/PID + state vocabulary (CLOSE_WAIT,CLOSED,ESTABLISHED,FIN_WAIT_1,FIN_WAIT_2,LAST_ACK,LISTEN,SYN_RECEIVED,SYN_SEND,TIMED_WAIT). sc-query output fields SERVICE_NAME/TYPE/STATE/WIN32_EXIT_CODE/SERVICE_EXIT_CODE/CHECKPOINT/WAIT_HINT. sc qc BINARY_PATH_NAME field: NO sc-qc.md exists in the clone and the learn.microsoft.com sc-qc URL returns 404 — brief's sc-qc field list is UNVERIFIED."
    url: file:///C:/Users/dhruv/AppData/Local/Temp/opencode/s2/WindowsServerDocs (local git clone; upstream github.com/MicrosoftDocs/WindowsServerDocs)
    retrieved: 2026-10-09
    publisher: "Microsoft (MicrosoftDocs)"
    version_or_commit: "b30da775fdeb9df0c446fda330fd0f101422edbe (Oct 6 2026), verified with git log -1"
    license: "Microsoft Docs license / CC BY 4.0 (docs content)"
    method: "git log -1 for commit; read netstat.md/schtasks.md/reg-export.md/sc-query.md; noted absence of sc-qc.md and BINARY_PATH_NAME anywhere in clone."
    label: VERIFIED
  - id: B-TOOLS-DOC
    source: "Sysinternals Autoruns/Autorunsc + Sigcheck pages, PowerShell Export-Csv page, reg.exe docs. autorunsc [-a *|bdeghiklmoprsw] [-c|-ct] [-h] [-m] [-s] [-u] [-vt] [[-z]|user]; -c CSV comma, -ct tab, -h hashes, -m hide Microsoft entries, -s verify signatures, -u show unsigned-only when VT enabled, -vt VirusTotal, -x XML, -z empty. Sigcheck [-a][-h][-i][-e][-l][-n][[-s]|[-c|-ct]|[-m]][-q][-r][-u][-vt][-v[r][s]] <file/dir>; -c CSV comma, -ct CSV tab, -u unsigned-only, -vt VirusTotal, -h hashes. Export-Csv: object property names → header row, -Delimiter/-UseCulture/-Encoding/-NoTypeInformation/-Append/-IncludeTypeInformation. reg export <keyname> <filename> [/y]."
    url: https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
    retrieved: 2026-10-09
    publisher: Microsoft (Sysinternals / Learn)
    version_or_commit: "Sigcheck v2.92 (page); Autoruns page current at retrieval"
    license: Microsoft Learn site terms / Sysinternals license
    method: "HTTP GET (IWR) on 2026-10-09; text extraction of usage syntax + parameter tables. Saved copies s2workb/{autoruns,sigcheck,export-csv,reg-export}.html."
    label: VERIFIED
  - id: B-COMMUNITY
    source: "Community-sourced Windows event title pages (wineventids.com) — used ONLY to supply display TITLES for events with no MS Learn page and no local sample: 106 'Task Registered', 140 'Task Registration Updated', 141 'Task Registration Deleted', 200 'Scheduled Task Executed', 201 'Scheduled Task Completed', 5859, 5861, 1149 'User Authentication via RemoteDesktop', 8003/8004/8006/8007 AppLocker. Site self-labels content 'Unconfirmed — community sourced'."
    url: "https://www.wineventids.com (per-id pages e.g. /ids/106, /ids/140, ...)"
    retrieved: 2026-10-09
    publisher: "wineventids.com (community, no affiliation with Microsoft)"
    version_or_commit: "n/a (live site)"
    license: "site terms (community content)"
    method: "HTTP GET on 2026-10-09; titles recorded; message-template ELEMENT NAMES from these pages are UNVERIFIED and marked as such below."
    label: UNVERIFIED
  - id: B-PRIOR
    source: "No external source — assertions in the task brief or prior Sentinel knowledge that could NOT be corroborated in any retrieved source. Examples: sc qc field list (BINARY_PATH_NAME etc.) because the MS sc-qc URL 404s; Event 104 element names beyond param3; AppLocker 8003/8004 EventData element names; TaskScheduler 106/140/141/200/201 EventData element names; RDP RCM 1149 element names; WMI 5859/5861 element names; classic PowerShell 800 element names."
    url: n/a
    retrieved: 2026-10-09
    publisher: n/a
    version_or_commit: n/a
    license: n/a
    method: "attempted corroboration against B-LOC-HARVEST / B-ARCHIVE / B-APPLOCKER-DOC / B-WINSDOCS / B-COMMUNITY — not found"
    label: UNVERIFIED
---

## Source Mapping Tables — Windows System/PowerShell/TaskScheduler/WMI/Defender/RDP/AppLocker + Network/Export Sources (Zeek, Suricata EVE, Nmap, netstat, sc, schtasks, reg, Export-Csv, Autoruns, Sigcheck)

Evidence basis: field names for on-box Windows events come from the local EVTX→XML harvest (B-LOC-HARVEST) where present, cross-checked against Microsoft's archived System-event message templates (B-SYS-ARCHIVE), the PowerShell instrumentation manifest (B-PS-MANIFEST), the Defender troubleshoot page (B-DEFENDER-DOC), and the AppLocker Event Viewer page (B-APPLOCKER-DOC). Events with NO local sample and NO Microsoft element-name page are marked UNVERIFIED and their parameter names are listed only as community/brief candidates — never asserted as present. Network/export-source field lists come from the primary sources in the verification log (Zeek source clone B-ZEEK-DOC, Suricata EVE docs B-SURICATA-DOC, Nmap DTD B-NMAP-DOC, WindowsServerDocs B-WINSDOCS, Sysinternals/PowerShell/reg docs B-TOOLS-DOC). Consequences you must respect: (1) element names shown as `param1`/`param2` in the System-event message templates are symbolic substitution slots, not `<Data Name=...>` keys — parsers must bind them positionally from the rendered message AND/OR from EventData when present; (2) anything labeled UNVERIFIED is a parser-tolerant optional field, never a required key; (3) for network sources the canonical `network.*`/`dns.*`/`http.*`/`tls.*` paths are stable, but source field names differ per tool and are mapped tool-by-tool below.

Section-wide conventions (apply to every table below unless a row says otherwise):

- Every source timestamp → `time.original` (raw) + derive `time.utc` (RFC 3339, `Z`) with `timezone_source` per source (Zeek `ts` = Unix epoch float → INFERRED conversion; Suricata `timestamp` = ISO 8601 with offset; Windows EVTX SystemTime = UTC ISO 8601) and `time.state: inferred` for the conversion — the DERIVED inference required by project rules.
- `event.derived_by` rule used here: `source` = Microsoft/Suricata/Zeek/Nmap explicitly names the category/type (e.g. service install, dns query, network connection) and the action is a direct transliteration; `sentinel` = Sentinel had to reinterpret the domain (e.g. Defender 1117 → file/quarantine outcome; AppLocker 8004 → config_check; an export tool row → artifact/config_check rather than a native event).
- `severity` is Sentinel-assigned in all cases (default `informational`; 1116/1117 → `high`/`medium` per Threat Severity ID; detectors override); the `derived_by` value on each line covers category/type/action/outcome.
- Anything under "Unmapped / traps" goes to top-level `unmapped[]` as `{name, value}` unless noted; absent canonical key = value absent in source, never bare null.
- `raw` carries the verbatim source record (rendered XML string for EVTX rows, full JSON object for Zeek/Suricata, full XML element tree for Nmap).

### Windows System — Service lifecycle (EID 7034 / 7036 / 7040 / 7043 / 7045)

**Classification (7034):** category: `service` · type: `service_crash` · action: `terminate` · outcome: `success` · severity: informational · derived_by: `source` (Microsoft names it "service terminated unexpectedly")
**Classification (7036):** category: `service` · type: `service_state_change` · action: `state_change` · outcome: `success` · severity: informational · derived_by: `source`
**Classification (7040):** category: `service` · type: `service_start_type_change` · action: `change` · outcome: `success` · severity: low · derived_by: `source`
**Classification (7043):** category: `service` · type: `service_config_change` · action: `change` · outcome: `success` · severity: low · derived_by: `source`
**Classification (7045):** category: `service` · type: `service_install` · action: `install` · outcome: `success` · severity: medium · derived_by: `source`
**Source names:** MS "The %1 service terminated unexpectedly" / "The %1 service entered the %2 state" / "The start type of the %1 service was changed from %2 to %3" (B-SYS-ARCHIVE); local harvest `<Data>` names (B-LOC-HARVEST).

| Event | Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|---|
| 7034 | param1 | service.name | VERIFIED B-LOC-HARVEST, B-SYS-ARCHIVE | service display/name that crashed (e.g. `Claude`) |
| 7034 | param2 | unmapped[] (`service.crash_count`) | VERIFIED B-SYS-ARCHIVE | occurrence COUNT ("done this %2 time(s)"), NOT exit code — brief's guidance wrong; schema has no service.crash_count (OPEN_QUESTIONS) |
| 7036 | `<Data>` [0] (unnamed) | service.name | VERIFIED B-LOC-HARVEST | provider `VfpExt`; first unnamed data = service name |
| 7036 | `<Data>` [1] (unnamed) | service.state | VERIFIED B-LOC-HARVEST | second unnamed data = new state (e.g. `running`/`stopped`) |
| 7036 | Binary | unmapped[] | VERIFIED B-LOC-HARVEST | non-name binary blob; no canonical home |
| 7040 | param1 | service.name | VERIFIED B-LOC-HARVEST, B-SYS-ARCHIVE | service whose start type changed (e.g. BITS) |
| 7040 | param2 | service.start_type | VERIFIED B-LOC-HARVEST, B-SYS-ARCHIVE | old start type (`auto start`) |
| 7040 | param3 | service.start_type | VERIFIED B-LOC-HARVEST, B-SYS-ARCHIVE | new start type (`demand start`); old+new both map to start_type — store new in start_type, old in unmapped[] or a from-state (INFERRED) |
| 7040 | param4 | unmapped[] | VERIFIED B-LOC-HARVEST | caller process (e.g. `BITS`) — extra param vs archived 3-slot template; no canonical home |
| 7043 | param1 | service.name | VERIFIED B-LOC-HARVEST | crashed service (e.g. `Windows Security Service`) |
| 7043 | Binary (UTF-16) | service.image_path | VERIFIED B-LOC-HARVEST | UTF-16LE hex decodes to binary path (e.g. `SecurityHealthService`) — carriers may differ, decode trap |
| 7045 | ServiceName | service.name | VERIFIED B-LOC-HARVEST | installed service (e.g. `ChatGPT`) |
| 7045 | ImagePath | service.image_path | VERIFIED B-LOC-HARVEST | full quoted path to service binary |
| 7045 | ServiceType | service.service_type | VERIFIED B-LOC-HARVEST | e.g. `user mode service` |
| 7045 | StartType | service.start_type | VERIFIED B-LOC-HARVEST | e.g. `auto start` |
| 7045 | AccountName | service.account_name | VERIFIED B-LOC-HARVEST | e.g. `LocalSystem` |

- **Unmapped / traps:** 7034 `param2` (crash count) → `unmapped[]` as `service.crash_count`; 7040 `param4` (caller) → `unmapped[]`; 7036 `Binary` blob → `unmapped[]`. Positional-`paramN` binding is the parser strategy (INFERRED): parse the rendered message and/or bind EventData positionally when `<Data>` elements are unnamed. 7043/7045 have NO Microsoft event page — element names are VERIFIED-LOCAL only (B-LOC-HARVEST), titles INFERRED.

### Windows System — Log clear (EID 104)

**Classification:** category: `config_check` (log hygiene) · type: `log_clear` · action: `clear` · outcome: `success` · severity: medium · derived_by: `sentinel` (log-clearing is a defensive-evasion signal; Microsoft files it under Eventlog, not a native object domain)
**Source names:** MS "The %3 log file was cleared." symbolic `EVENT_LOG_CLEARED`, provider `Microsoft-Windows-Eventlog` (B-SYS-ARCHIVE). No local sample (not found in harvest).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| param3 (message slot) | source.channel | VERIFIED B-SYS-ARCHIVE (template) | the log file / channel cleared — the only slot MS names in the message |
| Channel (candidate `<Data>`) | source.channel | UNVERIFIED B-COMMUNITY/B-PRIOR | community candidate element name; NOT observed locally — parser must accept param3 OR Channel |
| SubjectUserName (candidate) | user.name | UNVERIFIED B-COMMUNITY/B-PRIOR | who cleared it; community candidate, not on archived page |
| SubjectDomainName (candidate) | host.domain? / user.domain | UNVERIFIED B-COMMUNITY/B-PRIOR | domain; no dedicated user.domain key on the user payload — keep in user.name as DOMAIN\user (INFERRED) |
| SubjectUserSid (candidate) | user.sid (SID-form only) | UNVERIFIED B-COMMUNITY/B-PRIOR | store only when parses as `S-…` (INFERRED); else unmapped[] |
| SubjectLogonId (candidate) | unmapped[] | UNVERIFIED B-COMMUNITY/B-PRIOR | LUID hex; authentication.logon_id exists but 104 is not an auth event — keep unmapped |

- **Unmapped / traps:** everything except the channel is UNVERIFIED for 104 (no local sample, no element-name page). The VERIFIED fact is the message template + symbolic name only. Parser strategy: derive `source.channel` from param3 (VERIFIED) and treat the Subject* element names as optional (UNVERIFIED).

### Windows PowerShell (classic channel) — EID 400 / 403 / 600

**Classification (400/403):** category: `powershell` · type: `engine_state_change` · action: `state_change` · outcome: `success` · severity: informational · derived_by: `source`
**Classification (600):** category: `powershell` · type: `provider_state_change` / `command_start` · action: `state_change` / `start` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** local harvest (B-LOC-HARVEST) — 3 unnamed `<Data>`: [0] new state, [1] previous state, [2] detail blob. Classic 800 NOT found. Element names VERIFIED-LOCAL via PowerShell manifest blob keys (B-PS-MANIFEST cross-check).

| Event | Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|---|
| 400/403 | `<Data>` [0] | powershell.engine_state / powershell.new_provider_state | VERIFIED B-LOC-HARVEST, B-PS-MANIFEST | new engine state (e.g. `Started`) |
| 400/403 | `<Data>` [1] | powershell.previous_engine_state | VERIFIED B-LOC-HARVEST, B-PS-MANIFEST | previous engine state |
| 400/403 | `<Data>` [2] detail `NewEngineState` | powershell.engine_state | VERIFIED B-LOC-HARVEST | detail-blob key; overlaps [0] |
| 400/403 | detail `PreviousEngineState` | powershell.previous_engine_state | VERIFIED B-LOC-HARVEST | |
| 400/403 | detail `SequenceNumber` | unmapped[] | VERIFIED B-LOC-HARVEST | no canonical home |
| 400/403 | detail `HostName` | powershell.host_name | VERIFIED B-LOC-HARVEST | e.g. `ConsoleHost` |
| 400/403 | detail `HostVersion` | powershell.host_version | VERIFIED B-LOC-HARVEST | e.g. `5.1.26100.9444` |
| 400/403 | detail `HostId` | powershell.host_id | VERIFIED B-LOC-HARVEST | GUID |
| 400/403 | detail `HostApplication` | powershell.host_application | VERIFIED B-LOC-HARVEST | full launch command line |
| 400/403 | detail `EngineVersion` | powershell.engine_version | VERIFIED B-LOC-HARVEST | |
| 400/403 | detail `RunspaceId` | powershell.runspace_id | VERIFIED B-LOC-HARVEST | GUID |
| 400/403 | detail `PipelineId` | powershell.pipeline_id | VERIFIED B-LOC-HARVEST | |
| 400/403 | detail `CommandName`/`CommandType`/`ScriptName`/`CommandPath`/`CommandLine` | powershell.command_name / command_type / script_name / command_path / command_line | VERIFIED B-LOC-HARVEST | often empty in engine-state events |
| 600 | `<Data>` [0] | powershell.new_provider_state | VERIFIED B-LOC-HARVEST | new provider state (e.g. `Started`) |
| 600 | `<Data>` [1] | powershell.previous_engine_state | VERIFIED B-LOC-HARVEST | previous state |
| 600 | detail `ProviderName` | powershell.provider_name | VERIFIED B-LOC-HARVEST | e.g. `Variable` |
| 600 | detail `NewProviderState` | powershell.new_provider_state | VERIFIED B-LOC-HARVEST | |

- **Unmapped / traps:** unnamed-`<Data>` positional binding is the parser strategy (INFERRED). Detail-blob is `KEY=Value` lines inside `<Data>` [2] — parse then drop the blob (it also lands in `raw`). 400/403/600 detail keys come from B-LOC-HARVEST; 800 element names UNVERIFIED (not found locally, B-PRIOR).

### PowerShell Operational — EID 4103 / 4104 / 4105 / 4106

**Classification (4103):** category: `powershell` · type: `module_logging` · action: `log` · outcome: `success` · severity: informational · derived_by: `source`
**Classification (4104):** category: `powershell` · type: `script_block_logging` · action: `log` · outcome: `success` · severity: informational (raise to `medium` for obfuscated/encoded blocks) · derived_by: `source`
**Classification (4105/4106):** category: `powershell` · type: `pipeline_execution` · action: `start` / `stop` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** B-PS-MANIFEST (T_LOG_CONTEXT, T_ScriptBlock_Compiled, T_ScriptBlock_Executed) + local harvest (B-LOC-HARVEST).

| Event | Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|---|
| 4103 | ContextInfo | powershell.context_info | VERIFIED B-LOC-HARVEST, B-PS-MANIFEST | multi-line context (Severity, Host Name/Version/ID/Application, …) |
| 4103 | UserData | powershell.payload? / unmapped[] | VERIFIED B-LOC-HARVEST | usually empty; if populated → unmapped[] (no distinct UserData path; INFERRED) |
| 4103 | Payload | powershell.payload | VERIFIED B-LOC-HARVEST, B-PS-MANIFEST | CommandInvocation / ParameterBinding text |
| 4104 | MessageNumber | powershell.message_number | VERIFIED B-LOC-HARVEST, B-PS-MANIFEST | int; chunk index |
| 4104 | MessageTotal | powershell.message_total | VERIFIED B-LOC-HARVEST, B-PS-MANIFEST | int; total chunks — reassemble ScriptBlockText across MessageNumber≤MessageTotal (INFERRED) |
| 4104 | ScriptBlockText | powershell.script_block_text | VERIFIED B-LOC-HARVEST, B-PS-MANIFEST | the script block source |
| 4104 | ScriptBlockId | powershell.script_block_id | VERIFIED B-LOC-HARVEST, B-PS-MANIFEST | GUID; join key across 4104 chunks + 4105/4106 |
| 4104 | Path | powershell.script_path | VERIFIED B-LOC-HARVEST, B-PS-MANIFEST | source file path (e.g. npm.ps1) |
| 4105 | ScriptBlockId | powershell.script_block_id | VERIFIED B-PS-MANIFEST (template); NOT found locally (B-LOC-HARVEST) | pipeline start |
| 4105 | RunspaceId | powershell.runspace_id | VERIFIED B-PS-MANIFEST (template); NOT found locally | |
| 4106 | ScriptBlockId | powershell.script_block_id | VERIFIED B-PS-MANIFEST (template); NOT found locally | pipeline stop |
| 4106 | RunspaceId | powershell.runspace_id | VERIFIED B-PS-MANIFEST (template); NOT found locally | |

- **Unmapped / traps:** 4105/4106 have no local sample (channel exists but no events) — element names are VERIFIED-by-manifest only. `Path` empty string = interactive block (no file). Reassemble 4104 chunks by ScriptBlockId before storing `script_block_text` (INFERRED).

### WMI-Activity/Operational — EID 5857 / 5858 / 5860 (+ 5859/5861 UNVERIFIED)

**Classification (5857/5860):** category: `wmi` · type: `wmi_operation` · action: `connect` · outcome: `success` · severity: informational · derived_by: `source`
**Classification (5858):** category: `wmi` · type: `wmi_client_failure` · action: `connect` · outcome: `failure` · severity: low · derived_by: `source`
**Source names:** local harvest (B-LOC-HARVEST) via UserData child-element names.

| Event | Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|---|
| 5857 | UserData/ProviderName | wmi.provider_name | VERIFIED B-LOC-HARVEST | WMI provider that logged |
| 5857 | UserData/Code | wmi.result_code | VERIFIED B-LOC-HARVEST | operation status code |
| 5857 | UserData/HostProcess | unmapped[] (`wmi.host_process`) | VERIFIED B-LOC-HARVEST | host process image — no distinct wmi.host_process path; INFERRED→ keep raw, process payload absent on 5857 |
| 5857 | UserData/ProcessID | wmi.process.pid? / unmapped[] | VERIFIED B-LOC-HARVEST | uppercase-D `ProcessID`; maps to a process pid only if a process payload exists (it does not on 5857) → unmapped[] `wmi.process_id` (INFERRED); wmi.process exists but is a process_ref — not populated here |
| 5857 | UserData/ProviderPath | wmi.provider_path? / unmapped[] | VERIFIED B-LOC-HARVEST | provider DLL path; no wmi.provider_path in schema → unmapped[] (OPEN_QUESTIONS) |
| 5858 | UserData/Id | unmapped[] (`wmi.failure_id`) | VERIFIED B-LOC-HARVEST | failure identifier |
| 5858 | UserData/ClientMachine | wmi.client_machine | VERIFIED B-LOC-HARVEST | remote client machine |
| 5858 | UserData/User | wmi.client_user | VERIFIED B-LOC-HARVEST | client user |
| 5858 | UserData/ClientProcessId | wmi.client_process_id | VERIFIED B-LOC-HARVEST | uppercase-P `ClientProcessId` — int |
| 5858 | UserData/Component | unmapped[] (`wmi.component`) | VERIFIED B-LOC-HARVEST | failing component |
| 5858 | UserData/Operation | wmi.operation | VERIFIED B-LOC-HARVEST | operation name |
| 5858 | UserData/ResultCode | wmi.result_code | VERIFIED B-LOC-HARVEST | |
| 5858 | UserData/PossibleCause | unmapped[] (`wmi.possible_cause`) | VERIFIED B-LOC-HARVEST | free-text cause |
| 5860 | UserData/NamespaceName | wmi.namespace | VERIFIED B-LOC-HARVEST | WMI namespace |
| 5860 | UserData/Query | wmi.query | VERIFIED B-LOC-HARVEST | WQL query |
| 5860 | UserData/User | wmi.client_user | VERIFIED B-LOC-HARVEST | |
| 5860 | UserData/Processid | wmi.process.pid? / unmapped[] | VERIFIED B-LOC-HARVEST | lowercase-d `Processid` — casing trap vs 5857 `ProcessID`; same treatment (unmapped[] `wmi.process_id`, INFERRED) |
| 5860 | UserData/ClientMachine | wmi.client_machine | VERIFIED B-LOC-HARVEST | |
| 5860 | UserData/PossibleCause | unmapped[] | VERIFIED B-LOC-HARVEST | |
| 5859 / 5861 | (element names) | (n/a) | UNVERIFIED B-COMMUNITY/B-PRIOR | NOT found locally; no MS element-name page; titles only — do not map |

- **Unmapped / traps:** casing trap `ProcessID` (5857) vs `Processid` (5860) vs `ClientProcessId` (5858) — parsers must compare case-insensitively while emitting the harvest spelling. `wmi.process` (process_ref) is NOT populated because WMI-Activity events carry no process payload — the PIDs land in unmapped[] until a process record is joined (INFERRED). 5859/5861 fully UNVERIFIED.

### Windows Defender/Operational — EID 1116 / 1117 / 5001 / 5007

**Classification (1116):** category: `third_party_alert` (Defender is the "vendor" here) · type: `malware_detected` · action: `detect` · outcome: `success` · severity: high (or per Severity ID) · derived_by: `sentinel` (Microsoft files it under Defender, not a native object domain; the detection is an alert)
**Classification (1117):** category: `file` (quarantine/remediation touches the file) · type: `malware_action` · action: `quarantine`/`remove`/`allow` · outcome: per Action ID · severity: high · derived_by: `sentinel`
**Classification (5001):** category: `config_check` · type: `realtime_protection_disabled` · action: `disable` · outcome: `success` · severity: high · derived_by: `sentinel`
**Classification (5007):** category: `config_check` · type: `settings_change` · action: `change` · outcome: `success` · severity: low · derived_by: `source`
**Source names:** B-DEFENDER-DOC (symbolic names + templates) + local harvest 42-element set (B-LOC-HARVEST).

| Event | Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|---|
| 1116/1117 | Product Name | third_party_alert.product | VERIFIED B-LOC-HARVEST, B-DEFENDER-DOC | `Microsoft Defender Antivirus` |
| 1116/1117 | Product Version | unmapped[] (`defender.product_version`) | VERIFIED B-LOC-HARVEST | version string; no third_party_alert.product_version — unmapped[] (OPEN_QUESTIONS) |
| 1116/1117 | Detection ID | third_party_alert.rule_id? / unmapped[] | VERIFIED B-LOC-HARVEST | GUID; better as detection correlation id — no dedicated path → unmapped[] `defender.detection_id` (INFERRED) |
| 1116/1117 | Detection Time | time.original | VERIFIED B-LOC-HARVEST | detection timestamp (also has SystemTime) |
| 1116/1117 | Threat ID | unmapped[] (`defender.threat_id`) | VERIFIED B-LOC-HARVEST | numeric threat id |
| 1116/1117 | Threat Name | third_party_alert.rule_name? / description | VERIFIED B-LOC-HARVEST | threat family name (e.g. `Trojan:Win32/...`) → third_party_alert.rule_name (INFERRED) |
| 1116/1117 | Severity ID / Severity Name | third_party_alert.severity_raw | VERIFIED B-LOC-HARVEST | numeric + name; Sentinel maps to canonical severity |
| 1116/1117 | Category ID / Category Name | third_party_alert.category | VERIFIED B-LOC-HARVEST | e.g. `Trojan` |
| 1116/1117 | FWLink | unmapped[] | VERIFIED B-LOC-HARVEST | remediation URL |
| 1116/1117 | Status Code / Status Description | third_party_alert.description? / unmapped[] | VERIFIED B-LOC-HARVEST | status; map description → third_party_alert.description (INFERRED), status_code unmapped[] |
| 1116/1117 | State | unmapped[] (`defender.state`) | VERIFIED B-LOC-HARVEST | internal state |
| 1116/1117 | Source ID / Source Name | unmapped[] (`defender.source`) | VERIFIED B-LOC-HARVEST | detection source |
| 1116/1117 | Process Name | process.exe | VERIFIED B-LOC-HARVEST | process where malware seen |
| 1116/1117 | Detection User | process.owner_name? / user.name | VERIFIED B-LOC-HARVEST | user context of detection (INFERRED) |
| 1116/1117 | Path | file.path | VERIFIED B-LOC-HARVEST | file path of detection |
| 1116/1117 | Origin ID / Origin Name | unmapped[] (`defender.origin`) | VERIFIED B-LOC-HARVEST | detection origin |
| 1116/1117 | Execution ID / Execution Name | unmapped[] (`defender.execution`) | VERIFIED B-LOC-HARVEST | execution chain |
| 1116/1117 | Type ID / Type Name | unmapped[] (`defender.type`) | VERIFIED B-LOC-HARVEST | detection type |
| 1116/1117 | Pre Execution Status | unmapped[] | VERIFIED B-LOC-HARVEST | |
| 1116/1117 | Action ID / Action Name | file.action? / third_party_alert.mitigation | VERIFIED B-LOC-HARVEST | quarantine/remove/allow → file.action (INFERRED); Action Name → third_party_alert.mitigation |
| 1116/1117 | Error Code / Error Description | unmapped[] | VERIFIED B-LOC-HARVEST | remediation error |
| 1116/1117 | Post Clean Status | unmapped[] | VERIFIED B-LOC-HARVEST | |
| 1116/1117 | Additional Actions ID / Additional Actions String | unmapped[] | VERIFIED B-LOC-HARVEST | |
| 1116/1117 | Remediation User | user.name? / unmapped[] | VERIFIED B-LOC-HARVEST | who/what remediated (INFERRED) |
| 1116/1117 | Unused/Unused2..6 | (drop) | VERIFIED B-LOC-HARVEST | named `Unused*` — parser drops; not even unmapped[] |
| 1116/1117 | Security intelligence Version / Engine Version | unmapped[] | VERIFIED B-LOC-HARVEST | version strings |
| 5001 | Product Name / Product Version | third_party_alert.product / unmapped[] | VERIFIED B-LOC-HARVEST, B-DEFENDER-DOC | RTP disabled manually |
| 5007 | Product Name / Product Version | third_party_alert.product / unmapped[] | VERIFIED B-LOC-HARVEST, B-DEFENDER-DOC | settings change |
| 5007 | Old Value | config_check.observed? / unmapped[] | VERIFIED B-LOC-HARVEST | prior setting (registry path=value) |
| 5007 | New Value | config_check.observed | VERIFIED B-LOC-HARVEST | new setting → config_check.observed (INFERRED); Old Value → unmapped[] or config_check.expected |

- **Unmapped / traps:** the 42-element detection/action set is VERIFIED-LOCAL (B-LOC-HARVEST) and matches B-DEFENDER-DOC templates; but most elements have no canonical home and land in `unmapped[]` (product_version, detection_id, threat_id, state, source, origin, execution, type, error/post-clean/additional-actions, engine/intelligence versions). `file.path` and `process.exe` are the primary canonical homes on 1116/1117. Severity is Sentinel-assigned from Severity ID (INFERRED). 5001/5007 are config_check, not detections.

### TaskScheduler/Operational — EID 106 / 140 / 141 / 200 / 201 (all UNVERIFIED locally)

**Classification (106/140/141):** category: `scheduled_task` · type: `task_register`/`task_update`/`task_delete` · action: `register`/`change`/`delete` · outcome: `success` · severity: low · derived_by: `source` (INFERRED — titles community)
**Classification (200/201):** category: `scheduled_task` · type: `task_action_start`/`task_action_complete` · action: `start`/`complete` · outcome: `success` · severity: informational · derived_by: `source` (INFERRED — titles community)
**Source names:** community titles only (B-COMMUNITY: 106 "Task Registered", 140 "Task Registration Updated", 141 "Task Registration Deleted", 200 "Scheduled Task Executed", 201 "Scheduled Task Completed"). TaskScheduler channel DISABLED on-box (B-LOC-HARVEST), so NO local `<Data>` names. No Microsoft element-name page.

| Event | Source field (candidate) | Canonical path | Evidence | Notes |
|---|---|---|---|---|
| 106/140/141 | TaskName (candidate) | scheduled_task.name | UNVERIFIED B-COMMUNITY/B-PRIOR | parser must treat as optional |
| 106/140/141 | TaskPath (candidate) | scheduled_task.path | UNVERIFIED B-COMMUNITY/B-PRIOR | |
| 106/140/141 | UserContext / UserId (candidate) | scheduled_task.user_id | UNVERIFIED B-COMMUNITY/B-PRIOR | |
| 106/140/141 | Author (candidate) | scheduled_task.author | UNVERIFIED B-COMMUNITY/B-PRIOR | |
| 106/140/141 | TaskContent (candidate) | scheduled_task.task_xml | UNVERIFIED B-COMMUNITY/B-PRIOR | full task XML (brief mentions "Task Content") |
| 200 | TaskName (candidate) | scheduled_task.name | UNVERIFIED B-COMMUNITY/B-PRIOR | |
| 200 | ActionName (candidate) | scheduled_task.action? / command | UNVERIFIED B-COMMUNITY/B-PRIOR | brief mentions "Action Name"; map to scheduled_task.action (INFERRED) or command |
| 200 | Path (candidate) | scheduled_task.command | UNVERIFIED B-COMMUNITY/B-PRIOR | brief mentions "Task Path"; map to command (INFERRED) vs path |
| 201 | TaskName (candidate) | scheduled_task.name | UNVERIFIED B-COMMUNITY/B-PRIOR | |
| 201 | ActionName (candidate) | scheduled_task.action | UNVERIFIED B-COMMUNITY/B-PRIOR | |
| 201 | ResultCode (candidate) | scheduled_task.result_code | UNVERIFIED B-COMMUNITY/B-PRIOR | brief mentions "Result Code" |

- **Unmapped / traps:** EVERY element name is UNVERIFIED (channel disabled + no MS page). Parser strategy (brief's recommendation, INFERRED): render the message + parse `Key=Value` pairs, mark the mapping INFERRED, do not treat any as required. `scheduled_task.*` fields exist in schema and are ready to receive them once a sample is harvested (enable the channel to upgrade these to VERIFIED-LOCAL).

### RemoteDesktopServices-RdpCoreTS — EID 1149 (UNVERIFIED locally) + LSM EID 21/22/23/24/25/39

**Classification (1149):** category: `authentication` (RDP pre-auth) · type: `rdp_auth` · action: `connect` · outcome: `success` · severity: low · derived_by: `sentinel`
**Classification (LSM 21/22/24/25):** category: `authentication` · type: `session_logon`/`logoff`/`disconnect`/`reconnect` · action: `logon`/`logoff` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** local harvest LSM `<UserData>` child names (B-LOC-HARVEST: 21/22/24/25 → User, SessionID, Address; 23 → User, SessionID only; 39 → TargetSession, Source). RDP 1149: NOT found (recordcount 0), community title only (B-COMMUNITY).

| Event | Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|---|
| LSM 21/22/24/25 | UserData/User | user.name | VERIFIED B-LOC-HARVEST | logon/logoff/disconnect/reconnect user |
| LSM 21/22/24/25 | UserData/SessionID | unmapped[] (`session.id`) | VERIFIED B-LOC-HARVEST | session id; no session.* key — unmapped[] (OPEN_QUESTIONS) |
| LSM 21/22/24/25 | UserData/Address | network.src_ip | VERIFIED B-LOC-HARVEST | client IP |
| LSM 23 | UserData/User | user.name | VERIFIED B-LOC-HARVEST | logoff |
| LSM 23 | UserData/SessionID | unmapped[] (`session.id`) | VERIFIED B-LOC-HARVEST | no Address on 23 (trap) |
| LSM 39 | UserData/TargetSession | unmapped[] (`session.target`) | VERIFIED B-LOC-HARVEST | session-name change |
| LSM 39 | UserData/Source | unmapped[] (`session.source`) | VERIFIED B-LOC-HARVEST | |
| 1149 | (element names) | (n/a) | UNVERIFIED B-COMMUNITY/B-PRIOR | title "User Authentication via RemoteDesktop" only; no local sample, no MS element-name page |

- **Unmapped / traps:** LSM 23 has NO Address (only User + SessionID) — do not expect a src_ip on every session event. 39 has no User. `SessionID` has no canonical home → `unmapped[]`. RDP 1149 fully UNVERIFIED.

### AppLocker EXE/DLL — EID 8003 / 8004 / 8006 / 8007 (UNVERIFIED element names)

**Classification:** category: `config_check` (AppLocker policy enforcement) · type: `applocker_audit`/`applocker_block` · action: `allow`/`block` · outcome per audit/enforce · severity: low (audit) / medium (enforce-block) · derived_by: `sentinel`
**Source names:** B-APPLOCKER-DOC (message templates 8000-8008/8020-8024; 8003/8004 audit-only, 8006/8007 with `<File name>` param). Channel exists (11 records harvested) but 8003/8004 NOT found in the harvest event ids (B-LOC-HARVEST lists only 8003/8004 as the AppLocker ids present — confirm before asserting samples). EventData element NAMES not published by Microsoft.

| Event | Source field (candidate) | Canonical path | Evidence | Notes |
|---|---|---|---|---|
| 8003/8004 | FilePath / File name (candidate) | file.path | UNVERIFIED B-APPLOCKER-DOC (template) / B-PRIOR (names) | template names the file; element name UNVERIFIED |
| 8003/8004 | User (candidate) | user.name | UNVERIFIED B-PRIOR | |
| 8003/8004 | PolicyName / RuleName (candidate) | config_check.check? / unmapped[] | UNVERIFIED B-PRIOR | rule that matched |
| 8006/8007 | File name param (template-verified) | file.path | VERIFIED B-APPLOCKER-DOC (template) / UNVERIFIED (element name) | template `<File name>` is VERIFIED; its EventData spelling is UNVERIFIED |

- **Unmapped / traps:** AppLocker element names are UNVERIFIED (Microsoft publishes templates, not EventData names). Parser strategy (INFERRED): render message, extract the file path from the `<File name>` slot, bind element names optionally. 8003/8004 = audit (allow+block logged); 8006/8007 = enforce (allowed vs blocked).

### Zeek — conn.log / dns.log / http.log / ssl.log / notice.log / files.log (B-ZEEK-DOC)

**Classification (conn):** category: `network` · type: `network_connection` · action: `connect` · outcome per `conn_state` · severity: informational · derived_by: `source`
**Classification (dns):** category: `dns` · type: `dns_query` · action: `query`/`response` · outcome per `rcode_name` · severity: informational · derived_by: `source`
**Classification (http):** category: `http` · type: `http_request`/`http_response` · action: `request`/`response` · outcome per `status_code` · severity: informational · derived_by: `source`
**Classification (ssl):** category: `tls` · type: `tls_handshake` · action: `handshake` · outcome per `established` · severity: informational · derived_by: `source`
**Classification (notice):** category: `third_party_alert` · type: `zeek_notice` · action: `notice` · outcome: `success` · severity: per `note` · derived_by: `sentinel`
**Classification (files):** category: `file` · type: `file_seen` · action: `seen` · outcome: `success` · severity: informational · derived_by: `source`

| Log | Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|---|
| conn | ts | time.original (+time.utc) | VERIFIED B-ZEEK-DOC | Unix epoch float; INFERRED conversion |
| conn | uid | network.uid | VERIFIED B-ZEEK-DOC | connection uid; join key across logs |
| conn | id.orig_h | network.src_ip | VERIFIED B-ZEEK-DOC | originator addr |
| conn | id.orig_p | network.src_port | VERIFIED B-ZEEK-DOC | |
| conn | id.resp_h | network.dst_ip | VERIFIED B-ZEEK-DOC | responder addr |
| conn | id.resp_p | network.dst_port | VERIFIED B-ZEEK-DOC | |
| conn | id.proto | network.protocol | VERIFIED B-ZEEK-DOC | transport_proto (tcp/udp/icmp) |
| conn | proto (top-level) | network.protocol | VERIFIED B-ZEEK-DOC | ip_proto count (duplicated with id.proto — INFERRED, prefer id.proto) |
| conn | service | network.state? / unmapped[] | VERIFIED B-ZEEK-DOC | detected app protocol (e.g. DNS, SSL); no network.service — keep unmapped[] `zeek.service` (INFERRED) |
| conn | duration | network.duration | VERIFIED B-ZEEK-DOC | |
| conn | orig_bytes | network.bytes_sent | VERIFIED B-ZEEK-DOC | originator→responder |
| conn | resp_bytes | network.bytes_received | VERIFIED B-ZEEK-DOC | responder→originator |
| conn | conn_state | network.state | VERIFIED B-ZEEK-DOC | e.g. S1, REJ, RSTO |
| conn | orig_pkts/orig_ip_bytes/resp_pkts/resp_ip_bytes | network.bytes_sent/received (pkts unmapped) | VERIFIED B-ZEEK-DOC | byte counters map; packet counts → unmapped[] `zeek.orig_pkts` etc. |
| conn | history | unmapped[] (`zeek.history`) | VERIFIED B-ZEEK-DOC | flag history string; no canonical home |
| conn | local_orig/local_resp/missed_bytes/tunnel_parents | unmapped[] | VERIFIED B-ZEEK-DOC | |
| dns | ts/uid/id.* | time.original/network.uid/network.* | VERIFIED B-ZEEK-DOC | same as conn |
| dns | query | dns.query_name | VERIFIED B-ZEEK-DOC | queried name |
| dns | qtype_name | dns.query_type | VERIFIED B-ZEEK-DOC | e.g. A, AAAA, CNAME |
| dns | rcode_name | dns.response_code | VERIFIED B-ZEEK-DOC | e.g. NOERROR, NXDOMAIN |
| dns | answers | dns.answers | VERIFIED B-ZEEK-DOC | vector of strings |
| dns | trans_id/rtt/qclass_name/opcode_name/rejected/TTLs/AA/TC/RD/RA/Z/total_* /saw_* | unmapped[] | VERIFIED B-ZEEK-DOC | no canonical homes |
| http | method | http.method | VERIFIED B-ZEEK-DOC | GET/POST/… |
| http | host | http.host | VERIFIED B-ZEEK-DOC | |
| http | uri | http.uri | VERIFIED B-ZEEK-DOC | |
| http | user_agent | http.user_agent | VERIFIED B-ZEEK-DOC | |
| http | status_code | http.status_code | VERIFIED B-ZEEK-DOC | int |
| http | status_msg/referrer/version/origin/request_body_len/response_body_len/info_code/info_msg/tags/username/password/proxied/trans_depth | http.request_body_length / response_body_length (lens) + unmapped[] (rest) | VERIFIED B-ZEEK-DOC | body lengths map; others unmapped[] |
| ssl | server_name | tls.sni / tls.server_name | VERIFIED B-ZEEK-DOC | SNI — both tls.sni and tls.server_name exist; INFERRED, prefer tls.sni |
| ssl | version | tls.version | VERIFIED B-ZEEK-DOC | e.g. TLSv12 |
| ssl | cipher | tls.cipher | VERIFIED B-ZEEK-DOC | |
| ssl | curve/resumed/last_alert/next_protocol/established/ssl_history | tls.resumed (bool) + unmapped[] (rest) | VERIFIED B-ZEEK-DOC | resumed maps; others unmapped[] |
| ssl | ja3/ja3s | (n/a) | NOT in base Zeek (B-ZEEK-DOC) | community package only — if present, map to tls.ja3/tls.ja3s; base clone has NO ja3 (INFERRED) |
| notice | note/msg/sub | third_party_alert.rule_id? / description | VERIFIED B-ZEEK-DOC | note=enum (rule id), msg=text |
| notice | src/dst/p | network.src_ip/dst_ip/dst_port | VERIFIED B-ZEEK-DOC | |
| notice | fuid/file_mime_type/file_desc | file.path? / third_party_alert.observable | VERIFIED B-ZEEK-DOC | related file |
| notice | actions/email_dest/n/peer_descr | unmapped[] | VERIFIED B-ZEEK-DOC | |
| files | ts/fuid | time.original / file… (fuid unmapped[] `zeek.fuid`) | VERIFIED B-ZEEK-DOC | |
| files | uid | network.uid | VERIFIED B-ZEEK-DOC | files.log uid = conn uid (NO tx_uid in Zeek — brief wrong) |
| files | id.* | network.* | VERIFIED B-ZEEK-DOC | |
| files | source/mime_type/filename | file.path? / unmapped[] | VERIFIED B-ZEEK-DOC | source=log name, filename, mime_type |
| files | md5/sha1/sha256 (added by files/hash/main.zeek) | file.hashes (md5/sha1/sha256) | VERIFIED B-ZEEK-DOC | hash fields exist when hashing enabled |
| files | seen_bytes/total_bytes/missing_bytes/overflow_bytes/duration/local_orig/is_orig | network.bytes_*? / unmapped[] | VERIFIED B-ZEEK-DOC | byte counters → unmapped[] `zeek.*`; no file.byte homes for these |
| files | analyzers/depth/timedout/parent_fuid | unmapped[] | VERIFIED B-ZEEK-DOC | |

- **Unmapped / traps:** conn_id rendered as `id.orig_h`/`id.orig_p`/`id.resp_h`/`id.resp_p`/`id.proto` (bracket-free flat names in log output) — parsers match the flat form. `uid` is the cross-log join key (conn↔dns↔http↔ssl↔files). ja3/ja3s are NOT in base Zeek (community package) — do not require them. files.log `uid` is the conn uid, NOT a tx_uid (no tx_uid exists in Zeek). `service` (conn) has no canonical home → unmapped[] `zeek.service`.

### Suricata EVE JSON — common envelope + per-event-type (B-SURICATA-DOC)

**Classification:** varies per `event_type` (alert→third_party_alert, dns→dns, http→http, tls→tls, conn/netflow→network, fileinfo→file, …); category/type/action follow the event_type. derived_by: `source` (Suricata names the event_type explicitly). severity: alert.severity for alert events, else informational.

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| timestamp | time.original (+time.utc) | VERIFIED B-SURICATA-DOC | ISO 8601 with offset; timezone_source=source_offset |
| flow_id | network.uid? / unmapped[] | VERIFIED B-SURICATA-DOC | flow correlation id → network.uid (INFERRED) or unmapped[] |
| event_type | event.type | VERIFIED B-SURICATA-DOC | alert/dns/http/tls/… — drives classification |
| src_ip / dest_ip | network.src_ip / network.dst_ip | VERIFIED B-SURICATA-DOC | |
| src_port / dest_port | network.src_port / network.dst_port | VERIFIED B-SURICATA-DOC | |
| proto | network.protocol | VERIFIED B-SURICATA-DOC | TCP/UDP/ICMP |
| alert.signature / signature_id / category / severity / action / description | third_party_alert.rule_name / rule_id / category / severity_raw / description | VERIFIED B-SURICATA-DOC | alert event_type only |
| dns.rrname / rrtype / rdata / answers / flags / ttl | dns.query_name / query_type / answers (+unmapped[]) | VERIFIED B-SURICATA-DOC | dns event_type |
| http.hostname / url / http_user_agent / http_method / status / length | http.host / url / user_agent / method / status_code / request_body_length | VERIFIED B-SURICATA-DOC | http event_type |
| tls.sni / ja3 / ja3s / version / certificate / subject / issuer | tls.sni / ja3 / ja3s / version / subject / issuer | VERIFIED B-SURICATA-DOC | tls event_type |
| flow.bytes_toserver / bytes_toclient / pkts_toserver / pkts_toclient / start / end | network.bytes_sent / bytes_received (+unmapped[] pkts) | VERIFIED B-SURICATA-DOC | flow/netflow event_type |
| fileinfo.filename / magic / size / md5 / sha256 / state | file.path / hashes.md5 / hashes.sha256 | VERIFIED B-SURICATA-DOC | fileinfo event_type |

- **Unmapped / traps:** EVE is a single flat JSON stream where `event_type` selects the sub-object (`alert.*`, `dns.*`, `http.*`, `tls.*`, `flow.*`, `fileinfo.*`). Parse the common envelope first, then branch on `event_type`. `flow_id` → network.uid is INFERRED. Packet counts (pkts_*) have no canonical home → unmapped[]. Full record → `raw`.

### Nmap XML (-oX) — nmaprun/host/port/service/os (B-NMAP-DOC)

**Classification:** category: `config_check` (host/port inventory, not a runtime event) · type: `port_scan`/`service_detect`/`os_detect` · action: `scan` · outcome per `host@state`/`port/state@state` · severity: informational (inventory) · derived_by: `sentinel` (a scan result is a snapshot, not an event)

| Source element@attr (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| nmaprun@args / @version / @start / @startstr | unmapped[] (`nmap.args`/`nmap.version`) + time.original (startstr) | VERIFIED B-NMAP-DOC | scan command line + tool version; startstr→time.original (INFERRED) |
| host@starttime / @endtime | time.original (start) + unmapped[] (end) | VERIFIED B-NMAP-DOC | |
| status@state / @reason / @reason_ttl | network.state? / unmapped[] | VERIFIED B-NMAP-DOC | up/down; reason e.g. echo-reply |
| address@addr / @addrtype / @vendor | network.src_ip (or unmapped[] `nmap.addr`) + unmapped[] | VERIFIED B-NMAP-DOC | scanned host addr (ipv4/ipv6/mac); map to network.src_ip INFERRED (the scan source is nmap itself, not this addr — keep unmapped[] if ambiguous) |
| hostname@name / @type | unmapped[] (`nmap.hostname`) | VERIFIED B-NMAP-DOC | |
| port@protocol / @portid | network.protocol / network.dst_port | VERIFIED B-NMAP-DOC | the scanned port |
| state@state / @reason / @reason_ttl | network.state | VERIFIED B-NMAP-DOC | open/closed/filtered |
| service@name / @product / @version / @extrainfo / @tunnel / @method / @conf | unmapped[] (`nmap.service.*`) + network.state? | VERIFIED B-NMAP-DOC | service fingerprint; no canonical service.product home on network payload → unmapped[] (OPEN_QUESTIONS); @tunnel=ssl → tls hint (INFERRED) |
| cpe (#PCDATA) | unmapped[] (`nmap.cpe`) | VERIFIED B-NMAP-DOC | CPE product id |
| script@id / @output / table / elem | unmapped[] (`nmap.script.*`) | VERIFIED B-NMAP-DOC | NSE script results (nested table/elem) |
| osmatch@name / @accuracy + osclass@vendor/@type/@osfamily/@accuracy/@osgen | unmapped[] (`nmap.os.*`) | VERIFIED B-NMAP-DOC | OS detection |
| portused@state/@proto/@portid | unmapped[] | VERIFIED B-NMAP-DOC | |
| uptime@seconds / @lastboot | unmapped[] | VERIFIED B-NMAP-DOC | |
| distance@value / tcpsequence@…/ipidsequence@…/tcptssequence@… | unmapped[] | VERIFIED B-NMAP-DOC | sequence fingerprints |
| trace/proto/@port + hop@ttl/@rtt/@ipaddr/@host | unmapped[] (`nmap.trace.*`) | VERIFIED B-NMAP-DOC | traceroute |
| times@srtt/@rttvar/@to | unmapped[] | VERIFIED B-NMAP-DOC | |
| runstats/finished@time/@elapsed/@summary/@exit/@errormsg + hosts@up/@down/@total | unmapped[] (`nmap.runstats.*`) + time.original (finished@time) | VERIFIED B-NMAP-DOC | scan summary |
| extraports@state/@count + extrareasons@reason/@count/@proto/@ports | unmapped[] | VERIFIED B-NMAP-DOC | collapsed closed/filtered ports |

- **Unmapped / traps:** Nmap XML is an inventory snapshot, not a runtime event — almost everything has no canonical runtime home and lands in `unmapped[]` under `nmap.*`. The only near-canonical homes are `network.dst_port` (port@portid), `network.protocol`, and `network.state` (port state). `nmap.args` (the command line) is the highest-value detection field (shows scan technique/targets). Do not force address@addr into network.src_ip when it is the SCAN TARGET, not the scanner — prefer unmapped[] unless the host is the local scanner (INFERRED).

### netstat / sc / schtasks / reg export / Export-Csv / Autoruns / Sigcheck (B-WINSDOCS, B-TOOLS-DOC)

**Classification:** all are command-line collection/inventory tools, not runtime events → category: `config_check` (or `artifact` for exports) · derived_by: `sentinel`. Severity: informational (baseline), low (if a suspicious value is found by a detector).

| Tool | Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|---|
| netstat | Proto | network.protocol | VERIFIED B-WINSDOCS | TCP/UDP |
| netstat | Local Address | network.src_ip + network.src_port | VERIFIED B-WINSDOCS | `ip:port` — split (INFERRED) |
| netstat | Foreign Address | network.dst_ip + network.dst_port | VERIFIED B-WINSDOCS | split (INFERRED) |
| netstat | State | network.state | VERIFIED B-WINSDOCS | ESTABLISHED/LISTEN/CLOSE_WAIT/… |
| netstat | PID | process.pid (or unmapped[] `netstat.pid`) | VERIFIED B-WINSDOCS | owning process; maps to a process.pid only when joined to a process record (INFERRED) |
| sc query | SERVICE_NAME | service.name | VERIFIED B-WINSDOCS | registry subkey name |
| sc query | TYPE | service.service_type | VERIFIED B-WINSDOCS | |
| sc query | STATE | service.state | VERIFIED B-WINSDOCS | RUNNING/STOPPED/… |
| sc query | WIN32_EXIT_CODE / SERVICE_EXIT_CODE | service.exit_code | VERIFIED B-WINSDOCS | |
| sc query | CHECKPOINT / WAIT_HINT | service.checkpoint / service.wait_hint | VERIFIED B-WINSDOCS | |
| sc qc | BINARY_PATH_NAME | service.image_path | UNVERIFIED B-PRIOR | sc-qc URL 404s; no sc-qc.md in clone — brief's field list UNVERIFIED |
| schtasks | (query fields) | scheduled_task.name/path/command/arguments/user_id/… | VERIFIED B-WINSDOCS (schtasks.md/schtasks-query.md) | task name, next run time, mode, last run/result — map name→scheduled_task.name, command/args→scheduled_task.command/arguments (INFERRED for column spelling) |
| reg export | (registry key → .reg file) | registry.* / artifact | VERIFIED B-WINSDOCS (reg-export.md) | exports a key to .reg; the .reg content → registry payload (path/key/value/data) |
| Export-Csv | header row (object property names) | (structure only) | VERIFIED B-TOOLS-DOC | property names → CSV header; -NoTypeInformation removes #TYPE; -Delimiter/-UseCulture/-Encoding control format; -Append for row append |
| autorunsc | Entry Location | unmapped[] (`autoruns.location`) | VERIFIED B-TOOLS-DOC | e.g. Logon, Explorer, Services, Scheduled Task |
| autorunsc | Entry / Enabled / Hidden | unmapped[] | VERIFIED B-TOOLS-DOC | |
| autorunsc | Path / Launch String | service.image_path / process.exe / unmapped[] | VERIFIED B-TOOLS-DOC | autostart binary path; map to process.exe INFERRED |
| autorunsc | -h hashes | file.hashes | VERIFIED B-TOOLS-DOC | md5/sha1/sha256 when -h |
| autorunsc | -c CSV / -ct tab / -x XML | (structure only) | VERIFIED B-TOOLS-DOC | output format flags |
| sigcheck | -c CSV / -ct CSV tab | (structure only) | VERIFIED B-TOOLS-DOC | CSV output format |
| sigcheck | Path / Description / Version / Publisher | file.path / executable.product / executable.file_version / signer | VERIFIED B-TOOLS-DOC | file inventory + signature |
| sigcheck | -h hashes | file.hashes | VERIFIED B-TOOLS-DOC | |
| sigcheck | -u unsigned-only / -vt VirusTotal / -s catalog / -e | config_check / third_party_alert | VERIFIED B-TOOLS-DOC | VT detection → third_party_alert (INFERRED) |
| sigcheck | -a / -i / -n / -l / -q / -r / -nobanner | (flags) | VERIFIED B-TOOLS-DOC | scan scope/filtering flags |

- **Unmapped / traps:** these tools emit tabular/CSV/XML output whose column names are tool-specific and mostly land in `unmapped[]` under a per-tool namespace (`netstat.*`, `sc.*`, `nmap.*`, `autoruns.*`, `sigcheck.*`) rather than canonical runtime paths — the canonical homes (`network.*`, `service.*`, `file.*`, `process.*`) receive only the identity/connection columns (IPs, ports, PIDs, service names, file paths). `Export-Csv` defines the CSV *structure* (header = property names) but carries no schema of its own. `sc qc` BINARY_PATH_NAME is UNVERIFIED (dead MS URL). These are collection baselines (derived_by `sentinel`), not detections — detectors add severity on top.

- **Schema wish-list items surfaced by this section (OPEN_QUESTIONS for the schema owner):**
  - `service.crash_count` (7034 param2 occurrence count) — no home today.
  - `wmi.host_process`, `wmi.provider_path`, `wmi.process_id`, `wmi.failure_id`, `wmi.component`, `wmi.possible_cause` — WMI-Activity carries these but wmi.* lacks them (only operation/namespace/query/provider_name/result_code/client_*/process exist).
  - `session.id` / `session.target` / `session.source` (LSM SessionID/TargetSession/Source) — no session.* namespace.
  - `defender.product_version`, `defender.detection_id`, `defender.threat_id`, `defender.state`, `defender.source/origin/execution/type` — third_party_alert is too thin for the 42-element Defender payload.
  - `service.image_path` exists but `service.provider_path` (WMI) / `autoruns.location` / `sigcheck.publisher` do not.
  - Nmap `nmap.service.product` / `nmap.service.version` / `nmap.cpe` / `nmap.os.*` — inventory fields with no runtime home.
  - Zeek `zeek.service` (conn.service) / `zeek.history` / `zeek.fuid` — no canonical home; `network.uid` currently doubles as Zeek/Suricata flow_id.
  - classic PowerShell detail-blob `SequenceNumber`, and 7040 `param4` caller process — no home.

<!-- END SEC-B -->
