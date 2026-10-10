# Stage 2 — Canonical Event Schema and Source Mappings

**Project:** Sentinel — lightweight Windows-first HIDS
**Stage:** 2 of 4 (canonical schema and mappings)
**Status:** complete draft for review
**Date:** 2026-10-09
**Companion artifact:** `canonical_event_v1.schema.json` (JSON Schema Draft 2020-12, sibling file; validated with Python `jsonschema` 4.26.0 `Draft202012Validator.check_schema`)

This document specifies the canonical telemetry schema every Sentinel source
parser must emit and every detector consumes, and the exact field-level
mappings from each supported source into that schema. It follows the Stage-1
rule-engine decision (Sigma-compatible rule content over a
parser → canonical-event → detector pipeline) and resolves Stage-1
OPEN-QUESTION Q1 by fixing a three-level semantic classification
(file format → semantic data type → security behaviour; see the Semantic
Classification Spec section). Severities and level identifiers from Stage 1
(D-007) remain separate axes and are not re-used here.

**Reading order (required by the Stage-2 brief):** Verification Log →
Field Dictionary → Source Mapping Tables → Sigma Field-Mapping Pipelines →
Semantic Classification Spec → Example canonical events → DECISIONS →
OPEN_QUESTIONS → NOT_VERIFIED.

**Evidence labelling.** Every field-name claim and mapping is labelled
`VERIFIED` (primary source directly observed/fetched),
`INFERRED` (documented design choice over verified field names), or
`UNVERIFIED` (asserted but not corroborated by an allowed source — never a
required key). Labels appear in the mapping-table `Evidence` columns and in
the Verification Log entries referenced by DECISIONS.

## 0. Verification Log

Every evidence id referenced by the mapping tables, Sigma pipelines,
DECISIONS and examples appears below. Ids are stable across this document;
SEC-A and SEC-B fragments contributed the first two blocks, the remainder
cover the schema, examples corpus, Sigma sources and inherited Stage-1
decisions. Labels: VERIFIED (primary source directly observed/fetched),
INFERRED (documented design choice), UNVERIFIED (asserted but not
corroborated — see NOT_VERIFIED section).

```yaml
verification_log:
  - id: A-SYSMON-DOC-DL
    source: Microsoft Learn — "Sysmon" (Sysinternals download page). Per-event narrative list ("Event ID 1: Process creation" … "Event ID 255: Error"), config filter tag table (ID | Tag | Event), UTC statement ("Event timestamps are in UTC standard time."), registry root-key abbreviation table, prose field mentions (ProcessGUID, HashType, ProcessId, ProcessGuid, UtcTime, StartAddress, StartModule, StartFunction, ArchiveDirectory).
    url: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
    retrieved: 2026-10-09
    publisher: Microsoft (Microsoft Learn / Microsoft Sysinternals documentation)
    version_or_commit: ms.date 2026-09-10; updated_at 2026-09-10T19:32:00Z
    license: Microsoft Learn site terms / Microsoft content license
    method: HTTP GET (PowerShell Invoke-WebRequest, redirect followed, canonical URL captured) on 2026-10-09; parsed offline with Python 3.14 (meta extraction + tag-stripped text). Saved copy: s2work/sysmon-download.html.
    label: VERIFIED
  - id: A-SYSMON-DOC-EV
    source: Microsoft Learn — "Sysmon events" (conceptual event reference; event names, UTC statement "Event timestamps are recorded in UTC", channel path). NOTE: the URL given in the task brief (https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon-events) returned HTTP 404 on 2026-10-09; the successor page below was used instead. This page is summary-level — it lists NO per-field inventories.
    url: https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events
    retrieved: 2026-10-09
    publisher: Microsoft (Microsoft Learn)
    version_or_commit: ms.date 2026-02-03 (matches task brief); updated_at 2026-10-08T11:38:00Z; page footer "Last updated on 2026-02-24"
    license: Microsoft Learn site terms / Microsoft content license
    method: HTTP GET (Invoke-WebRequest) on 2026-10-09; parsed offline with Python 3.14. Saved copy: s2work/sysmon-events.html.
    label: VERIFIED
  - id: A-SYSMON-DOC-OV
    source: Microsoft Learn — "Sysmon overview" (channel name, capability prose). Supporting/background only.
    url: https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview
    retrieved: 2026-10-09
    publisher: Microsoft (Microsoft Learn)
    version_or_commit: ms.date 2026-02-24; updated_at 2026-10-08T11:38:00Z
    license: Microsoft Learn site terms / Microsoft content license
    method: HTTP GET (Invoke-WebRequest) on 2026-10-09; parsed offline with Python 3.14. Saved copy: s2work/sysmon-overview.html.
    label: VERIFIED
  - id: A-SWIFT-CFG
    source: SwiftOnSecurity/sysmon-config — sysmonconfig-export.xml. Contains (a) per-event `<!--DATA: …-->` comments enumerating EventData field names (21 event sections) and (b) config filter sections whose child element names are Sysmon config-schema fields.
    url: https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/1836897f12fbd6a0a473665ef6abc34a6b497e31/sysmonconfig-export.xml
    retrieved: 2026-10-09
    publisher: SwiftOnSecurity (community project)
    version_or_commit: "1836897f12fbd6a0a473665ef6abc34a6b497e31" (short prefix 1836897f as given in the brief; the brief's full SHA 1836897f07c3d5e900a1ec4a6b391ca87e93c3c3 returned HTTP 404 — resolved via GitHub commits API on 2026-10-09). File header: "Source version: 74 | Date: 2021-07-08".
    license: CC BY 4.0 (per file header)
    method: HTTP GET (Invoke-WebRequest) of raw file on 2026-10-09; Python 3.14 regex parse of `SYSMON EVENT ID n` sections, following `DATA:` comments, and `<Tag onmatch=…>` child element names. Local copy byte-identical to s2/sysmon-config-export.xml (SHA1 match). Saved copy: s2work/swift-sysmon-config.xml.
    label: VERIFIED
  - id: A-SYSMON-MOD
    source: local clone olafhartong/sysmon-modular — (a) `tooling/internal/validate/schema.go` `eventFields` map (the repo's stated "Sysmon for Windows event filtering schema" — exact per-event field lists), (b) field-element inventory parsed from the config modules under the module directories (e.g. `1_process_creation/*.xml`), (c) `tooling/internal/validate/compatibility.go` per-binary field-version notes.
    url: file:///C:/Users/dhruv/AppData/Local/Temp/opencode/s2/sysmon-modular (local git clone; upstream github.com/olafhartong/sysmon-modular)
    retrieved: 2026-10-09
    publisher: Olaf Hartong (community project)
    version_or_commit: 082cba578667a5f57b44a8e64bc02548d2338859 (commit date 2026-09-18), verified with `git log -1`
    license: MIT (permission notice in license.md)
    method: git log -1 for commit; Python 3.14 parse of schema.go `fields("…")` entries and of every `*.xml` module (regex over `<Tag onmatch="…">` blocks, child element names, `<Field name="…">` attributes).
    label: VERIFIED
  - id: A-SEC-PAGES
    source: Microsoft Learn — archived Windows Security auditing event reference, 30 individual event pages. Exact EventData names taken from the `Event XML` block's `<Data Name="…">` elements (both `<Data Name="X">` and self-closing `<Data Name="X" />`). Group entry covering ids: 1102, 4624, 4625, 4634, 4647, 4648, 4672, 4688, 4689, 4697, 4698, 4720, 4722, 4724, 4726, 4732, 4738, 4740, 4767, 4768, 4769, 4771, 4776, 4946, 4947, 4948, 5140, 5145, 5156, 5158 (4728 and 4756 have no page — see A-SEC-GRPMGMT).
    url: "pattern https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-<id> — every id 302-redirected to https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-<id> (recorded per id in fetch_log.json; e.g. 4624 → .../event-4624)"
    retrieved: 2026-10-09
    publisher: Microsoft (Microsoft Learn; archived content per MicrosoftDocs/officearchive-pr)
    version_or_commit: "per-page <meta name=ms.date>: 2021-09-06 … 2026-03-29 (4625=2026-03-29, 4768=2021-10-20, 4776=2021-09-13, 4688=2022-01-24, 4946/4947/4948/5140/5145/5156/5158=2021-09-08, most others=2021-09-07); updated_at 2026-04-27 (all except 4625=2026-05-01)"
    license: Microsoft Learn site terms / Microsoft content license
    method: HTTP GET per page (Invoke-WebRequest, redirects followed, final URL + status recorded) on 2026-10-09; Python 3.14 regex extraction of HTML-escaped Event XML; 1102 has no EventData — its field names are the `<UserData><LogFileCleared>` element names (SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId) on the same page. Event titles from `<h1>`. Saved copies: s2work/sec-<id>.html; log: s2work/fetch_log.json.
    label: VERIFIED
  - id: A-SEC-GRPMGMT
    source: Microsoft Learn — "Audit Security Group Management" (archived). Events 4728 and 4756 have no dedicated event page (event-4728 / event-4756 → HTTP 404 on 2026-10-09). This page states for both: "Event 4728 is the same, but it is generated for a global security group instead of a local security group. All event fields, XML, and recommendations are the same. The type of group is the only difference." (same wording for 4756 / universal group). Field names below are therefore taken from the 4732 page (A-SEC-PAGES).
    url: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-group-management (redirects to https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management)
    retrieved: 2026-10-09
    publisher: Microsoft (Microsoft Learn; archived content)
    version_or_commit: ms.date 2021-09-06; updated_at 2026-04-27T20:50:00Z
    license: Microsoft Learn site terms / Microsoft content license
    method: HTTP GET (Invoke-WebRequest) on 2026-10-09; Python 3.14 text extraction. Saved copy: s2work/audit-sec-grp-mgmt.html.
    label: VERIFIED
  - id: A-PRIOR
    source: No external source — Sentinel prior knowledge or assertions carried in the task brief that could NOT be observed in any retrieved source (used only for UNVERIFIED rows; examples: Sysmon `Hashes` "KEY=value,KEY=value" rendering, `ElevatedToken` true/false and "%16384-style" renderings, literal `EventType` strings such as createKey/setValue/CreatePipe, Sysmon EID 255 EventData names).
    url: n/a
    retrieved: 2026-10-09
    publisher: n/a
    version_or_commit: n/a
    license: n/a
    method: attempted corroboration against A-SWIFT-CFG / A-SYSMON-MOD / A-SYSMON-DOC-DL / A-SEC-PAGES — not found
    label: UNVERIFIED
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
  - id: SCHEMA-V1
    source: canonical_event_v1.schema.json (this repo, sibling of this document)
    url: file:///C:/Users/dhruv/OneDrive/Desktop/College/Light%20HIDS/canonical_event_v1.schema.json
    retrieved: 2026-10-09
    publisher: Sentinel project
    version_or_commit: canonical-event/v1
    license: project-internal
    method: Authored in Stage 2; validated with Python jsonschema 4.26.0 Draft202012Validator.check_schema; 121/121 SEC-C examples pass iter_errors (0 errors).
    label: VERIFIED
  - id: A6-SIGMAHQ-INV
    source: SigmaHQ/sigma-rules corpus (field inventories per logsource category, extracted from rule files)
    url: https://github.com/SigmaHQ/sigma-rules
    retrieved: 2026-10-09
    publisher: SigmaHQ community
    version_or_commit: 8a4813404ea3074890e0cda9272d4d1a8b2941d6 (local clone _stage1_work/sigma-rules)
    license: DRL 1.1 (Sigma rule licence; detector content carries author attribution to alerts per Stage-1 D-006)
    method: Local clone at pinned commit; field-name inventories per logsource group extracted with Python during Stage-2 research pass; used for Sigma field-mapping pipelines in section 3.
    label: VERIFIED
  - id: A6-PIPE-WINDOWS
    source: pySigma-pipeline-windows (fieldmap/filter structure reference for the YAML pipeline shape in section 3)
    url: https://github.com/SigmaHQ/pySigma-pipeline-windows
    retrieved: 2026-10-09
    publisher: SigmaHQ
    version_or_commit: v2.0.1, commit 5d7170663e3799e6cafaa2d0847ce30a5489827c (local clone %TEMP%/opencode/s2/pySigma-pipeline-windows)
    license: LGPL-2.1-only
    method: Local clone at pinned commit; structure (logsource/fieldmap) mirrored as declarative YAML in section 3. No code copied; pySigma is not a runtime dependency (D2-014).
    label: VERIFIED
  - id: A6-PIPE-SYSMON
    source: pySigma-pipeline-sysmon (EventID-routing structure reference)
    url: https://github.com/SigmaHQ/pySigma-pipeline-sysmon
    retrieved: 2026-10-09
    publisher: SigmaHQ
    version_or_commit: v2.0.0, commit 965d57c2324292f66bec3da41b223838b3b7251b (local clone %TEMP%/opencode/s2/pySigma-pipeline-sysmon)
    license: LGPL-2.1-only
    method: Local clone at pinned commit; structure reference only, no code copied.
    label: VERIFIED
  - id: C-SCHEMA
    source: canonical_event_v1.schema.json
    url: file:///C:/Users/dhruv/OneDrive/Desktop/College/Light%20HIDS/canonical_event_v1.schema.json
    retrieved: 2026-10-09
    publisher: Sentinel project
    version_or_commit: canonical-event/v1
    license: project-internal
    method: Schema validity Draft202012Validator.check_schema; example validity iter_errors over every fenced json block in section 5 (121 examples, 0 errors).
    label: VERIFIED
  - id: C-LOC
    source: Local harvest samples (raw EVTX XML) reused as example raw values
    url: file:///C:/Users/dhruv/OneDrive/Desktop/College/Light%20HIDS/_stage2_work/local_eventfields.json
    retrieved: 2026-10-09
    publisher: local host (this machine)
    version_or_commit: harvest run 2026-10-09
    license: n/a (locally generated)
    method: Raw XML snippets taken from the harvest JSON; example values match the observed sample (Defender Mimikatz detection, WMI CIMWin32, LSM LOCAL session, System Claude/ChatGPT services, 4104 npm.ps1).
    label: VERIFIED
  - id: C-MAP-A
    source: SEC-A mapping tables (this document, section 2 Sysmon + Security)
    url: file:///C:/Users/dhruv/OneDrive/Desktop/College/Light%20HIDS/_stage2_work/sec_sysmon_security.md
    retrieved: 2026-10-09
    publisher: Sentinel project
    method: Canonical paths in examples follow the SEC-A field tables; UNVERIFIED fields in examples carry the same labels as the tables.
    label: VERIFIED
  - id: C-MAP-B
    source: SEC-B mapping tables (this document, section 2 other Windows channels + network/export sources)
    url: file:///C:/Users/dhruv/OneDrive/Desktop/College/Light%20HIDS/_stage2_work/sec_network_exports.md
    retrieved: 2026-10-09
    publisher: Sentinel project
    method: Canonical paths in examples follow the SEC-B field tables.
    label: VERIFIED
  - id: C-DFIR-LSM
    source: Microsoft LSM/RCM documentation + DFIR literature (LSM 21-39 semantics: logon/logoff/shadow/disconnect framing)
    url: https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/ (family of pages; see SEC-B LSM entries)
    retrieved: 2026-10-09
    publisher: Microsoft / community DFIR
    method: Cross-check of message templates against local harvest element names; used to derive rdp_* event.type names (D2-009).
    label: INFERRED
  - id: C-COVERAGE
    source: Coverage matrix in section 5 (example corpus vs required source list)
    url: file:///C:/Users/dhruv/OneDrive/Desktop/College/Light%20HIDS/_stage2_work/sec_examples.md
    retrieved: 2026-10-09
    publisher: Sentinel project
    method: Counted per-group examples; document/archive_member categories intentionally uncovered (D2-018).
    label: VERIFIED
  - id: STAGE1-D001
    source: Stage-1 deliverable (stage-1-landscape-and-rule-engine-decision.md) - D-001..D-012, licence register, Q1
    url: file:///C:/Users/dhruv/OneDrive/Desktop/College/Light%20HIDS/stage-1-landscape-and-rule-engine-decision.md
    retrieved: 2026-10-08
    publisher: Sentinel project
    method: Inherited design constraints (Windows-first, FastAPI/PostgreSQL/worker, Sigma-compatible content, DRL attribution, no GPL/AGPL copying).
    label: VERIFIED
  - id: STAGE1-D004
    source: Stage-1 D-004 (Sigma compatibility as content-level goal, not library dependency)
    url: file:///C:/Users/dhruv/OneDrive/Desktop/College/Light%20HIDS/stage-1-landscape-and-rule-engine-decision.md
    retrieved: 2026-10-08
    publisher: Sentinel project
    method: Cited by D2-014.
    label: VERIFIED
  - id: STAGE1-D008
    source: Stage-1 D-008 (detector/parser separation; detectors consume canonical events only)
    url: file:///C:/Users/dhruv/OneDrive/Desktop/College/Light%20HIDS/stage-1-landscape-and-rule-engine-decision.md
    retrieved: 2026-10-08
    publisher: Sentinel project
    method: Cited by D2-014.
    label: VERIFIED

```



---

## 1. Field Dictionary

Notation. Every field below is optional unless the *Req* column says `yes`.
`str|int|bool|num` = bare JSON scalar; `state` = the value-state object
(`{"$state": "null|unknown|invalid|conflicting|inferred", ...}`) defined in
`$defs/state_object`; `X|state` = either form (a field is *absent* by
omission, never bare `null`; the only bare `null` permitted anywhere in a
canonical event is `time.utc` when `time.state` is `unknown`/`invalid`).
All typed objects are `additionalProperties: false`; `$`-prefixed keys are
reserved for the state machinery. `additionalProperties: false` also holds
at the envelope level; the 26 payload objects are named exactly as their
`event.category` value.

### 1.1 Envelope

| Field | Type | Req | Meaning |
|---|---|---|---|
| `schema_version` | const `canonical-event/v1` | yes | Schema generation tag. |
| `event.category` | enum (26 values, §1.2) | yes | Level-3 security-behaviour class; selects the single required payload object (enforced by 26 `if/then` rules in the schema). |
| `event.type` | str, `^[a-z][a-z0-9_]*$` | yes | Semantic event type name (level-3 refinement), e.g. `process_create`, `network_connection`, `malware_detected`. |
| `event.action` | str\|state | yes | Verb for what happened (`create`, `delete`, `connect`, `start`, `block`, …). |
| `event.outcome` | enum `success\|failure\|unknown` | yes | Result of the action as framed by the source. |
| `event.severity` | enum `informational\|low\|medium\|high\|critical`\|state | yes | Sentinel severity of the event (distinct from Stage-1 detection-content levels). |
| `event.derived_by` | enum `source\|sentinel` | yes | Provenance of `category`/`type`/`action`/`outcome`/`severity`: `source` = taken from the source's own taxonomy (Sysmon event names, Security subcategory semantics); `sentinel` = authored by Sentinel (snapshot exports, classification of third-party alerts, LSM typing — see D2-009/D2-010). |
| `tenant_id` | non-empty str | yes | Tenant isolation; every row carries it even in single-tenant deployment. |
| `workspace_id` | non-empty str | yes | Workspace within a tenant. |
| `run_id` | non-empty str | yes | Harvest-run identifier; groups all events from one collection pass. |
| `time.utc` | RFC 3339 str \| **bare null allowed** | yes | UTC instant. Bare `null` only when `time.state` is `unknown`/`invalid` (schema `if/then` enforced). |
| `time.original` | str\|null | no | Timestamp exactly as the source rendered it. |
| `time.original_timezone` | str\|null | no | Timezone of `original` (`Z`, `+05:30`, IANA name) when determinable. |
| `time.timezone_source` | enum `source_explicit\|source_documented_utc\|run_configuration\|none` | no | How the timezone was established. Sysmon → `source_documented_utc` (docs: "Event timestamps are in UTC"). Never guess: no documented TZ and no run-config override → `none`. |
| `time.precision` | enum `millisecond\|second\|microsecond\|nanosecond\|unknown` | yes | Source timestamp precision. |
| `time.state` | enum `ok\|inferred\|unknown\|invalid` | yes | `inferred` when `utc` was derived (e.g. epoch→UTC, run-config TZ applied). |
| `host` | object (may be `{}`) | yes | Subject host. No known attributes → `{}` (never omit the key). |
| `host.hostname` | str\|state | no | Short hostname as the source frames it. |
| `host.fqdn` | str\|state | no | Fully-qualified name when supplied. |
| `host.ips` | array of str\|state | no | Addresses belonging to the host (not peer addresses — those live in payload objects). |
| `host.os.family/build/version` | str\|state | no | OS identity when supplied. |
| `host.arch` | str\|state | no | Architecture when supplied. |
| `user` | object (may be `{}`) | yes | Event *subject* account (logon subject, detection user, service account requester). `{}` when unknown. |
| `user.sid` / `user.name` / `user.domain` / `user.upn` / `user.logon_id` | str\|state | no | SID (S-1-5-…), account name, domain/NETBIOS, UPN, logon id (LUID/LogonId as rendered). |
| `source.file_id` | non-empty str | yes | Harvested-artifact identifier (DB row / manifest id). |
| `source.sha256` | 64-hex str | no | Hash of the source artifact when computed. |
| `source.format` | enum `evtx\|json\|csv\|tsv\|text\|nmap_xml\|pcap\|sqlite\|yaml\|other` | yes | **Level-1 file format** (semantic classification level 1). |
| `source.parser` / `source.parser_version` | non-empty str | yes | Producing parser identity (provenance for replay). |
| `source.channel` | str | no | Windows event-log channel or equivalent stream name. |
| `source.provider` | str | no | Event provider / application / sensor. |
| `source.event_id` | int\|str | no | Source-native event id (Sysmon/Security EID, EVE `event_type`, …). |
| `source.record.type` | enum `event_record\|line\|row\|byte_offset\|packet\|sheet\|message` | yes | **Level-2 semantic data type** carrier position (semantic classification level 2 lives here + `source.format`). |
| `source.record.record_id\|line\|byte_offset\|packet_number\|row\|sheet` | int\|str | no | Exact locator within the artifact for replay/audit. |
| `raw` | any JSON value | yes | Verbatim source record, lossless (string for text/EVTX-rendered, object for JSON). Parsers must not drop fields here even when `unmapped[]` captures them structurally. |
| `unmapped` | array of `{name, value}` | no | Source fields with no canonical home, captured losslessly (e.g. Sysmon `RuleName`, `FileVersion`, Defender `FWLink`). |
| `sources` | array of `{source_ref, fields[]}` | no | Cross-artifact provenance (e.g. Zeek notice enriched from conn) — `$source_ref` keys point at Verification Log ids or file ids. |

### 1.2 Payload objects (selected by `event.category`)

The 26 categories: `process`, `network`, `file`, `registry`, `authentication`,
`account`, `group_membership`, `service`, `scheduled_task`, `dns`, `http`,
`tls`, `image_load`, `driver`, `wmi`, `powershell`, `thread_access`, `pipe`,
`third_party_alert`, `fim`, `config_check`, `artifact`, `document`,
`archive_member`, `executable`, `artifact_finding`. All fields `str|state`
etc. are as defined above; `process_ref` is the 7-field lightweight process
identity (`guid`, `pid`, `exe`, `name`, `command_line`, `user_sid`,
`owner_name`) embedded by other objects.

| Object | Fields |
|---|---|
| **process** | `guid`, `pid`, `ppid`, `exe`, `name`, `command_line`, `current_dir`, `integrity_level`, `logon_guid`, `logon_id`, `terminal_session_id`, `owner_sid`, `owner_name`, `start_time`, `original_file_name`, `hashes{md5,sha1,sha256,imphash,other}`, `signature{signed,signer,status}`, `parent{guid,pid,exe,name,command_line,owner_sid}` |
| **network** | `protocol`, `direction` (enum `inbound\|outbound\|internal\|external\|unknown`\|state), `src_ip`, `src_port`, `dst_ip`, `dst_port`, `state` (TCP state), `bytes_sent`, `bytes_received`, `duration`, `tcp_flags`, `icmp_type`, `icmp_code`, `interface`, `uid` (Zeek conn uid), `community_id`, `process` (process_ref) |
| **file** | `path`, `name`, `directory`, `size`, `type` (level-2 semantic type when the source supplies one, e.g. Zeek `mime_type`), `attributes`, `owner_sid`, `owner_name`, `created`, `modified`, `accessed`, `hashes`, `signature`, `entropy` |
| **registry** | `path` (full `HKLM\...` as source-rendered), `hive`, `key`, `value_name`, `value_type`, `data`, `old_data`, `operation` (enum `create\|set\|delete\|rename`\|state) |
| **authentication** | `logon_type`, `logon_id`, `logon_guid`, `account_sid`, `account_name`, `account_domain`, `target_sid`, `target_name`, `target_domain`, `target_logon_id`, `source_ip`, `workstation`, `auth_package`, `elev_token`, `key_length`, `process_pid`, `process_name`, `status`, `sub_status`, `failure_reason`, `caller_process_id`, `caller_process_name` |
| **account** | `sid`, `name`, `domain`, `upn`, `display_name`, `sam_account_name`, `account_type` (enum `user\|computer\|group\|other`\|state), `enabled`, `sid_history` |
| **group_membership** | `action` (enum `added\|removed`\|state), `group_sid`, `group_name`, `member_sid`, `member_name`, `subject_sid`, `subject_name`, `domain` |
| **service** | `name`, `display_name`, `image_path`, `start_type`, `service_type`, `account_name`, `operation` (enum `install\|start\|stop\|change\|delete`\|state), `state`, `exit_code`, `checkpoint`, `wait_hint`, `error_control`, `load_order_group`, `dependencies`, `description`, `pid` |
| **scheduled_task** | `name`, `path`, `action` (enum `created\|deleted\|updated\|started\|completed`\|state), `author`, `user_id`, `run_level`, `command`, `arguments`, `working_directory`, `trigger`, `creation_time`, `result_code`, `task_xml` |
| **dns** | `query_name`, `query_type`, `query_status`, `response_code`, `answers[]`, `server`, `process` (process_ref) |
| **http** | `method`, `url`, `uri`, `host`, `user_agent`, `status_code`, `request_body_length`, `response_body_length`, `referrer`, `mime_type` |
| **tls** | `sni`, `ja3`, `ja3s`, `version`, `cipher`, `issuer`, `subject`, `not_before`, `not_after`, `resumed`, `server_name` |
| **image_load** | `image`, `process` (process_ref), `hashes`, `signature` |
| **driver** | `name`, `display_name`, `image_path`, `start_type`, `service_type`, `state`, `operation` |
| **wmi** | `operation`, `namespace`, `query`, `provider_name`, `result_code`, `client_machine`, `client_process_id`, `client_user`, `process` (process_ref) |
| **powershell** | `channel`, `engine_state`, `previous_engine_state`, `host_name`, `host_id`, `host_version`, `host_application`, `engine_version`, `runspace_id`, `pipeline_id`, `command_name`, `command_type`, `script_name`, `command_path`, `command_line`, `script_block_id`, `script_block_text`, `script_path`, `message_number`, `message_total`, `context_info`, `payload`, `provider_name`, `new_provider_state` |
| **thread_access** | `target_process` (process_ref), `source_process` (process_ref), `access_mask`, `granted_access[]`, `call_trace` |
| **pipe** | `name`, `operation` (enum `create\|connect`\|state) |
| **third_party_alert** | `vendor`, `product`, `rule_id`, `rule_name`, `category`, `severity_raw`, `description`, `observable`, `mitigation` |
| **fim** | `path`, `operation`, `old{size,modified,attributes,hashes}`, `new{size,modified,attributes,hashes}` |
| **config_check** | `check`, `category`, `expected`, `observed`, `status` (enum `pass\|fail\|unknown`\|state), `source` |
| **artifact** | `type` (enum `file\|registry_key\|registry_value\|service\|scheduled_task\|user\|group\|process\|network_endpoint\|other`\|state), `identity`, `path`, `attributes` |
| **document** | `path`, `title`, `author`, `created`, `modified`, `last_saved_by`, `revision_number`, `page_count`, `word_count` |
| **archive_member** | `archive_path`, `member_path`, `size`, `compressed_size`, `encrypted`, `member_type`, `hashes` |
| **executable** | `path`, `format` (enum `pe\|elf\|macho\|script\|other`\|state — *file* format of the executable itself), `architecture`, `compile_time`, `subsystem`, `product`, `company`, `description`, `original_file_name`, `file_version`, `hashes`, `signature` |
| **artifact_finding** | `artifact_type`, `artifact_identity`, `finding`, `evidence`, `scanner`, `confidence` |

### 1.3 Shared value objects

| Object | Fields |
|---|---|
| **hashes** | `md5`, `sha1`, `sha256`, `imphash`, `other` (each str\|state) |
| **signature** | `signed` (bool\|state), `signer`, `status` (str\|state) |
| **state_object** | `$state` (required; enum `null\|unknown\|invalid\|conflicting\|inferred`), `$note`, `$raw`, `$candidates[]`, `$source_ref` |

### 1.4 Value-state model (normative)

1. **Absent = omitted.** A key that is absent means "the source does not
   carry this value". Parsers must not emit bare `null` (schema rejects it;
   only `time.utc` may be bare-null, under `state` `unknown`/`invalid`).
2. **Explicit null** (`$state: "null"`): the source rendered an explicit
   empty/null (e.g. Windows EventData `<Data Name='X'></Data>`, PowerShell
   detail-blob `CommandLine=` with nothing after `=`). Distinguished from
   absent so detectors can treat "present but empty" per source semantics.
3. **Unknown** (`$state: "unknown"`): the source *has* the concept but this
   record could not supply it (field documented, value missing here).
4. **Invalid** (`$state: "invalid"`, with `$raw`): the value exists but is
   unparsable (malformed timestamp, non-numeric port). `$raw` keeps the
   original bytes.
5. **Conflicting** (`$state: "conflicting"`, with `$candidates[]`): multiple
   disagreeing candidates (two clocks, PID-vs-GUID mismatch on enrichment).
6. **Inferred** (`$state: "inferred"`, with `$note`): Sentinel produced the
   value (derived `time.utc`, derived `network.direction` from
   `Initiated=true`, split `TargetObject` into hive/key/value_name). Any
   Sentinel-authored *classification* (not just field values) is instead
   carried by `event.derived_by: sentinel`. `$source_ref` optionally points
   at the Verification Log id or file id backing the value.

Process identity hierarchy (D2-005): `host` + `process.guid` (Sysmon
`ProcessGuid`, a per-boot unique id) is the primary process identity; when a
source has no GUID, parsers fall back to (`host`, `process.pid`,
`process.exe`, `process.start_time`) marked `inferred`, and pid-only linkage
is documented as carrying a PID-reuse failure mode (Security 4688 has no
ProcessGuid — see OPEN_QUESTIONS Q2-005).

---

---

## 2. Source Mapping Tables

*(Assembled from SEC-A and SEC-B fragments — see Verification Log for the
evidence ids used throughout.)*

## Source Mapping Tables — Sysmon (Microsoft-Windows-Sysmon/Operational)

Evidence basis: per-field Sysmon names come from the config-schema layer — the `<!--DATA: …-->` EventData enumerations and filter elements of the SwiftOnSecurity config at commit `1836897f` (A-SWIFT-CFG) and the per-event `eventFields` schema plus module filter elements of the sysmon-modular clone at `082cba578667` (A-SYSMON-MOD) — cross-checked against Microsoft's Sysmon documentation (A-SYSMON-DOC-DL, A-SYSMON-DOC-EV), which is **summary-level only and does not enumerate per-field EventData names**. Consequences you must respect when reviewing: (1) config-schema spelling is treated as the EVTX spelling, but the two config sources disagree on casing in three places (`ProcessID`/`ProcessId`, `DestinationIsIpV6`/`DestinationIsIpv6`, `SourceProcessGUID`/`SourceProcessGuid`) — parsers must compare field names case-insensitively while emitting the schema.go spelling; (2) anything not present in those inventories is labeled UNVERIFIED, never asserted as present.

Section-wide conventions (apply to every Sysmon table below unless a row says otherwise):

- `UtcTime` → `time.original`; derive `time.utc` (RFC 3339, `Z`), `timezone_source: source_documented_utc` (A-SYSMON-DOC-DL: "Event timestamps are in UTC standard time"; A-SYSMON-DOC-EV: "Event timestamps are recorded in UTC"), `precision` per source resolution, and `time.state: inferred` for the conversion — the DERIVED inference required by project rules.
- Sysmon `User` renders as `DOMAIN\user`, bare `name`, or a SID; map the raw string to `process.owner_name` (or the process_ref equivalent) and derive `process.owner_sid` only when the value parses as `S-…` — INFERRED; otherwise leave `owner_sid` absent. Documented ambiguity, not a parser bug.
- `RuleName` has no canonical home (the matching Sysmon rule) → `unmapped[]` (`name: "RuleName"`).
- `event.derived_by` rule used here: `source` = canonical type/action transliterate Microsoft's documented event name/tag and the category is the object domain Microsoft names (process/file/registry/network/dns/pipe/wmi/driver/image_load/service/thread_access for EID 8/10, which this project treats as the direct home of CreateRemoteThread/ProcessAccess semantics); `sentinel` = Sentinel had to reinterpret the domain (EID 9 → file, EID 16 → config_check, EID 24 → process, EID 255 → third_party_alert).
- `severity` is Sentinel-assigned in all cases (default `informational`; detectors override); the `derived_by` value on each line covers category/type/action/outcome per the mapping guidance.
- Anything listed under "Unmapped / traps" goes to top-level `unmapped[]` as `{name, value}` unless noted; absent canonical key = value absent in source (schema rule), never bare null.

### Sysmon EID 1 — process_create

**Classification:** category: `process` · type: `process_create` · action: `create` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 1: Process creation"; config tag `ProcessCreate`; channel task "Process Create" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc + timezone_source source_documented_utc + time.state inferred (INFERRED) |
| RuleName | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | matching rule name; no schema field |
| ProcessGuid | process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | stable per-process GUID — beats PID reuse for correlation |
| ProcessId | process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | Swift DATA spells it `ProcessID` — case-insensitive match (trap) |
| Image | process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | full path; derive process.name = basename (INFERRED, optional) |
| FileVersion | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | schema has no process.file_version |
| Description | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | schema has no process.description |
| Product | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | executable.product exists but no executable payload on category process — keep unmapped |
| Company | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | as above |
| OriginalFileName | process.original_file_name | VERIFIED A-SYSMON-MOD | in schema.go but absent from Swift DATA comment (filter-only in Swift v74) |
| CommandLine | process.command_line | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | full command line per MS docs (A-SYSMON-DOC-DL) |
| CurrentDirectory | process.current_dir | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| User | process.owner_name | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | DOMAIN\user or name; derive owner_sid only when SID-form (INFERRED) |
| LogonGuid | process.logon_guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | string GUID |
| LogonId | process.logon_id | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | LUID hex string — keep as string |
| TerminalSessionId | process.terminal_session_id | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | int |
| IntegrityLevel | process.integrity_level | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | raw token label (e.g. High/System/Medium/…) — keep string |
| Hashes | process.hashes (md5/sha1/sha256/imphash/other) | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | split `Hashes` into md5/sha1/sha256/imphash/other (INFERRED); KEY=value,KEY=value rendering UNVERIFIED A-PRIOR; unparsed remainder → hashes.other |
| HashType | unmapped[] | VERIFIED A-SYSMON-DOC-DL | named in MS prose only; absent from both config inventories — presence in modern EventData UNVERIFIED |
| ParentProcessGuid | process.parent.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| ParentProcessId | process.parent.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| ParentImage | process.parent.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| ParentCommandLine | process.parent.command_line | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| ParentUser | process.parent.owner_sid | VERIFIED A-SYSMON-MOD | process.parent has no owner_name — store raw in owner_sid only when SID-form, else unmapped[] (INFERRED); OPEN_QUESTIONS: process.parent.owner_name |

- **Unmapped / traps:** `FileVersion`, `Description`, `Product`, `Company`, `HashType`, `RuleName` → `unmapped[]`. Casing trap: Swift `ProcessID` vs schema.go `ProcessId` (A-SWIFT-CFG vs A-SYSMON-MOD) — normalize case-insensitively. Parent chain is only as trustworthy as the parent's own record (spoofable via PPID spoofing — detection concern, not a mapping issue).

### Sysmon EID 2 — file_creation_time_change

**Classification:** category: `file` · type: `file_creation_time_change` · action: `change` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 2: A process changed a file creation time"; config tag `FileCreateTime`; channel task "File creation time" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | in schema.go; Swift DATA omits it |
| ProcessGuid | process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | acting process |
| ProcessId | process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Image | process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| User | process.owner_name | VERIFIED A-SYSMON-MOD | in schema.go only (Sysmon 14+, compatibility.go fieldMinBinary); absent from Swift DATA |
| TargetFilename | file.path | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | full path |
| CreationUtcTime | file.created | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | resulting creation time (INFERRED semantics) |
| PreviousCreationUtcTime | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | prior creation time — schema has no file.created_old (OPEN_QUESTIONS) |

- **Unmapped / traps:** `PreviousCreationUtcTime` → `unmapped[]`. A secondary `process` payload carries the acting process (category file still requires `file` — satisfied). Legitimate software often retimes files; severity stays informational.

### Sysmon EID 3 — network_connection

**Classification:** category: `network` · type: `network_connection` · action: `connect` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 3: Network connection"; config tag `NetworkConnect`; channel task "Network connection detected" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| ProcessGuid | process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | also mirror to network.process.guid (INFERRED, optional) |
| ProcessId | process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Image | process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| User | process.owner_name | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | ambiguity per section convention |
| Protocol | network.protocol | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | tcp/udp string |
| Initiated | network.direction | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | DERIVED: true → `outbound`, false → `inbound` (INFERRED; $note the boolean source) |
| SourceIsIpv6 | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | redundant with address form; no schema field |
| SourceIp | network.src_ip | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| SourceHostname | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | remote host name — no canonical field (host.* describes the logging host; OPEN_QUESTIONS: peer hostname) |
| SourcePort | network.src_port | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | int |
| SourcePortName | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | service name only |
| DestinationIsIpv6 | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | Swift DATA spells `DestinationIsIpV6`, schema.go `DestinationIsIpv6` — casing trap |
| DestinationIp | network.dst_ip | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| DestinationHostname | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | as SourceHostname |
| DestinationPort | network.dst_port | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | int |
| DestinationPortName | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |

- **Unmapped / traps:** hostnames, IPv6 flags, port service names → `unmapped[]`. `Initiated` → direction is a DERIVED inference. When `Image` is `System`/idle the process context is weak — keep process payload but flag in `$note` (INFERRED guidance).

### Sysmon EID 4 — sysmon_service_state_change

**Classification:** category: `service` · type: `sysmon_service_state_change` · action: `start` / `stop` (from `State`) · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 4: Sysmon service state changed"; config tag `n/a` — "Sysmon service state change (cannot be filtered)" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| UtcTime | time.original | VERIFIED A-SWIFT-CFG | derive time.utc etc. (INFERRED) |
| State | service.state | VERIFIED A-SWIFT-CFG | raw value; derive event.action `start`/`stop` from State (INFERRED); literal values UNVERIFIED A-PRIOR |
| Version | unmapped[] | VERIFIED A-SWIFT-CFG | Sysmon version string — no canonical home |
| SchemaVersion | unmapped[] | VERIFIED A-SWIFT-CFG | config schema version — no canonical home |

- **Unmapped / traps:** `Version`, `SchemaVersion` → `unmapped[]`. Optional: `service.name` = `"Sysmon"` (INFERRED constant, not an event field). Event is not filterable (A-SYSMON-DOC-DL), so it appears even in minimal configs — volume note for detectors.

### Sysmon EID 5 — process_terminate

**Classification:** category: `process` · type: `process_terminate` · action: `terminate` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 5: Process terminated" (provides `UtcTime`, `ProcessGuid`, `ProcessId`); config tag `ProcessTerminate`; channel task "Process terminated" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | UtcTime/ProcessGuid/ProcessId explicitly named by MS docs (A-SYSMON-DOC-DL) |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| ProcessGuid | process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | join key back to the EID 1 record |
| ProcessId | process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Image | process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| User | process.owner_name | VERIFIED A-SYSMON-MOD | schema.go only (Sysmon 14+); absent from Swift DATA |

- **Unmapped / traps:** none beyond `RuleName`. `process.start_time` is not present in EID 5 — join to EID 1 via `process.guid` to compute duration (INFERRED pipeline guidance).

### Sysmon EID 6 — driver_load

**Classification:** category: `driver` · type: `driver_load` · action: `load` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 6: Driver loaded" ("configured hashes … signature information"); config tag `DriverLoad`; channel task "Driver Loaded" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| ImageLoaded | driver.image_path | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | full driver image path; optional driver.name = basename (INFERRED) |
| Hashes | executable.hashes (md5/sha1/sha256/imphash/other) | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | driver payload has no hashes — emit optional secondary `executable` payload (path=ImageLoaded); split KEY=value pairs (INFERRED, format UNVERIFIED A-PRIOR) |
| Signed | executable.signature.signed | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | bool; asynchronous signature per MS docs (A-SYSMON-DOC-DL) — may reflect post-load state |
| Signature | executable.signature.signer | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | signer subject |
| SignatureStatus | executable.signature.status | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | raw status string |

- **Unmapped / traps:** schema `driver` object has no `hashes`/`signature` — hence the optional `executable` payload (Sentinel choice; if you omit it, send `Hashes`/`Signed`/`Signature`/`SignatureStatus` to `unmapped[]` instead). `driver.operation` enum has no `load` value — omit `driver.operation` or set `"start"` (INFERRED; OPEN_QUESTIONS). Async signature caveat per A-SYSMON-DOC-DL.

### Sysmon EID 7 — image_load

**Classification:** category: `image_load` · type: `image_load` · action: `load` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 7: Image loaded"; config tag `ImageLoad`; channel task "Image loaded" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| ProcessGuid | image_load.process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| ProcessId | image_load.process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Image | image_load.process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | loading process |
| User | image_load.process.owner_name | VERIFIED A-SYSMON-MOD | schema.go only (Sysmon 14+) |
| ImageLoaded | image_load.image | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | loaded module path |
| FileVersion | unmapped[] | VERIFIED A-SYSMON-MOD | no image_load.version |
| Description | unmapped[] | VERIFIED A-SYSMON-MOD | |
| Product | unmapped[] | VERIFIED A-SYSMON-MOD | executable.product exists only with optional executable payload |
| Company | unmapped[] | VERIFIED A-SYSMON-MOD | |
| OriginalFileName | unmapped[] | VERIFIED A-SYSMON-MOD | image_load.process is a process_ref without original_file_name — unmapped unless you add an `executable` payload (INFERRED) |
| Hashes | image_load.hashes (md5/sha1/sha256/imphash/other) | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | split KEY=value (INFERRED; format UNVERIFIED A-PRIOR) |
| Signed | image_load.signature.signed | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | bool |
| Signature | image_load.signature.signer | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| SignatureStatus | image_load.signature.status | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |

- **Unmapped / traps:** version/product/company/description/original_file_name → `unmapped[]` (or optional `executable` payload, INFERRED). High-volume event — mapping cost note for collectors.

### Sysmon EID 8 — create_remote_thread

**Classification:** category: `thread_access` · type: `create_remote_thread` · action: `create` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 8: CreateRemoteThread" (names `StartAddress`, `StartModule`, `StartFunction`; states StartModule/StartFunction are inferred and may be empty); config tag `CreateRemoteThread`; channel task "CreateRemoteThread detected" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| SourceProcessGuid | thread_access.source_process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| SourceProcessId | thread_access.source_process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| SourceImage | thread_access.source_process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| SourceUser | thread_access.source_process.owner_name | VERIFIED A-SYSMON-MOD | schema.go only; often empty → `$state: "null"` guidance (INFERRED) |
| TargetProcessGuid | thread_access.target_process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| TargetProcessId | thread_access.target_process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| TargetImage | thread_access.target_process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| TargetUser | thread_access.target_process.owner_name | VERIFIED A-SYSMON-MOD | schema.go only (Sysmon 14+); often empty (INFERRED null guidance) |
| NewThreadId | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | no thread-id field in schema (OPEN_QUESTIONS: thread.id) |
| StartAddress | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | hex start address — no schema field |
| StartModule | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | MS docs: inferred, may be empty (A-SYSMON-DOC-DL) |
| StartFunction | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | MS docs: inferred, may be empty (A-SYSMON-DOC-DL) |

- **Unmapped / traps:** `NewThreadId`, `StartAddress`, `StartModule`, `StartFunction` → `unmapped[]` (list them; do not drop). Empty `SourceUser`/`TargetUser`/`StartModule`/`StartFunction` are documented behavior → `$state: "null"` when empty and semantics are null (INFERRED).

### Sysmon EID 9 — raw_device_read

**Classification:** category: `file` · type: `raw_device_read` · action: `read` · outcome: `success` · severity: informational · derived_by: `sentinel`
**Source names:** MS docs "Event ID 9: RawAccessRead" ("indicates the source process and target device"); config tag `RawAccessRead`; channel task "RawAccessRead detected" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| ProcessGuid | process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | reading process |
| ProcessId | process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Image | process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| User | process.owner_name | VERIFIED A-SYSMON-MOD | schema.go only (Sysmon 14+) |
| Device | file.path | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | target device (`\\.\…`); mapping device→file.path is Sentinel's choice — hence derived_by `sentinel` |

- **Unmapped / traps:** no other fields. If your deployment rejects `file` for a device path, the fallback is `unmapped[]` `{name:"Device"}` with category `process` — document whichever you choose (OPEN_QUESTIONS: raw-device category).

### Sysmon EID 10 — process_access

**Classification:** category: `thread_access` · type: `process_access` · action: `access` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 10: ProcessAccess" ("a process opens another process"); config tag `ProcessAccess`; channel task "Process accessed" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| SourceProcessGuid | thread_access.source_process.guid | VERIFIED A-SWIFT-CFG | spelling `SourceProcessGuid` |
| SourceProcessGUID | thread_access.source_process.guid | VERIFIED A-SYSMON-MOD | spelling `SourceProcessGUID` — same field, casing conflict between the two sources (trap; match case-insensitively) |
| SourceProcessId | thread_access.source_process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| SourceThreadId | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only; no thread-id field |
| SourceImage | thread_access.source_process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| SourceUser | thread_access.source_process.owner_name | VERIFIED A-SYSMON-MOD | schema.go only; often empty (INFERRED null guidance) |
| TargetProcessGuid | thread_access.target_process.guid | VERIFIED A-SWIFT-CFG | spelling `TargetProcessGuid` |
| TargetProcessGUID | thread_access.target_process.guid | VERIFIED A-SYSMON-MOD | spelling `TargetProcessGUID` — casing conflict (trap) |
| TargetProcessId | thread_access.target_process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| TargetImage | thread_access.target_process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| TargetUser | thread_access.target_process.owner_name | VERIFIED A-SYSMON-MOD | schema.go only; often empty |
| GrantedAccess | thread_access.access_mask | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | hex string — keep as string; optional decode to thread_access.granted_access[] names is INFERRED and the decode table is UNVERIFIED A-PRIOR |
| CallTrace | thread_access.call_trace | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | stack string incl. module+offset |

- **Unmapped / traps:** `SourceThreadId` → `unmapped[]`. GUID casing conflict is the main parser trap here. High-volume; correlate `access_mask` + `TargetImage` (e.g. lsass) in detectors, not parsers.

### Sysmon EID 11 — file_create

**Classification:** category: `file` · type: `file_create` · action: `create` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 11: FileCreate"; config tag `FileCreate`; channel task "File created" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| ProcessGuid | process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | creating process (secondary process payload) |
| ProcessId | process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Image | process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| User | process.owner_name | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| TargetFilename | file.path | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | full path; derive file.name/file.directory (INFERRED, optional) |
| CreationUtcTime | file.created | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |

- **Unmapped / traps:** none beyond `RuleName`. `file.hashes`/`file.size` are absent in EID 11 — detectors must not assume them (absent ≠ null).

### Sysmon EID 12 — registry_object_create_delete

**Classification:** category: `registry` · type: `registry_object_create_delete` (refine from `EventType`: `registry_key_create` / `registry_key_delete` / `registry_value_delete` — INFERRED refinement) · action: `create` / `delete` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 12: RegistryEvent (Object create and delete)"; config tag `RegistryEvent`; channel task "Registry object added or deleted"; abbreviated root keys HKLM/HKU/HKCR documented (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| EventType | registry.operation | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | map `createKey`→`create`, `deleteKey`→`delete`, `setValue`→`set`, `renameKey`/`renameValue`→`rename` (INFERRED); literal value strings UNVERIFIED A-PRIOR — EID alone already implies create/delete for EID 12 |
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| ProcessGuid | process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | acting process (secondary process payload) |
| ProcessId | process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Image | process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| User | process.owner_name | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| TargetObject | registry.path | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | full path embeds hive+key+value; derive registry.hive / registry.key / registry.value_name by split (INFERRED; hive abbreviations HKLM/HKU/HKCR documented — A-SYSMON-DOC-DL) |
| Details | registry.data | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | Swift DATA notes "can't filter on"; value data / new key name context — keep raw string |
| NewName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only (Swift: "can't filter on"); rename destination — schema has no registry.new_path (OPEN_QUESTIONS) |

- **Unmapped / traps:** `NewName` → `unmapped[]`. Full-path-only parsers must not invent hive/key/value splits they cannot parse; when the split fails, keep `registry.path` only and leave hive/key/value_name absent (INFERRED guidance).

### Sysmon EID 13 — registry_value_set

**Classification:** category: `registry` · type: `registry_value_set` · action: `set` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 13: RegistryEvent (Value Set)"; config tag `RegistryEvent`; channel task "Registry value set" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| EventType | registry.operation | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | `setValue`→`set` (INFERRED; literal UNVERIFIED A-PRIOR) |
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| ProcessGuid | process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| ProcessId | process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Image | process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| User | process.owner_name | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| TargetObject | registry.path | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | hive+key+value; derive splits (INFERRED) |
| Details | registry.data | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | new value data; keep raw (type not supplied → registry.value_type absent) |
| NewName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only; normally absent for SetValue |

- **Unmapped / traps:** `registry.value_type` cannot be populated from EID 13 — do not infer DWORD/QWORD from data shape (INFERRED prohibition). MS docs note DWORD/QWORD recording only (A-SYSMON-DOC-DL).

### Sysmon EID 14 — registry_rename

**Classification:** category: `registry` · type: `registry_rename` · action: `rename` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 14: RegistryEvent (Key and Value Rename)"; config tag `RegistryEvent`; channel task "Registry object renamed" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| EventType | registry.operation | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | `renameKey`/`renameValue`→`rename` (INFERRED; literal UNVERIFIED A-PRIOR) |
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| ProcessGuid | process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| ProcessId | process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Image | process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| User | process.owner_name | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| TargetObject | registry.path | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | pre-rename path; derive splits (INFERRED) |
| Details | registry.data | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | "can't filter on" per Swift DATA |
| NewName | unmapped[] | VERIFIED A-SYSMON-MOD | new key/value name — no canonical destination; keep in unmapped[] (OPEN_QUESTIONS) |

- **Unmapped / traps:** rename destination (`NewName`) has no schema home — event reconstruction needs path+NewName together.

### Sysmon EID 15 — file_stream_create

**Classification:** category: `file` · type: `file_stream_create` · action: `create` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 15: FileCreateStreamHash" (named streams incl. Zone.Identifier; hashes of stream contents and of the unnamed stream); config tag `FileCreateStreamHash`; channel task "File stream created" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| ProcessGuid | process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| ProcessId | process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Image | process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| User | process.owner_name | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| TargetFilename | file.path | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | includes the `:stream` suffix (e.g. `…:Zone.Identifier`) — INFERRED; stream name has no schema field (no `StreamName` field exists in either config inventory — contrary to a common assumption) → unmapped[] or derive from suffix (INFERRED) |
| CreationUtcTime | file.created | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Hash | file.hashes.other | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | single digest of the named stream; algorithm unspecified in event → `other` (INFERRED placement) |
| Contents | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only — hash of the unnamed (file) stream; schema has one hashes slot already used by `Hash` (OPEN_QUESTIONS: second hashes carrier) |

- **Unmapped / traps:** stream name and `Contents` → `unmapped[]`. Never strip the `:stream` suffix from `file.path` silently — keep the lossless path and note the split (INFERRED).

### Sysmon EID 16 — sysmon_config_change

**Classification:** category: `config_check` · type: `sysmon_config_change` · action: `change` · outcome: `success` · severity: informational · derived_by: `sentinel`
**Source names:** MS docs "Event ID 16: ServiceConfigurationChange" ("logs changes in the Sysmon configuration"); config tag `n/a` — "Sysmon configuration change (cannot be filtered)"; Swift comment: only logs when the config hash changes (A-SYSMON-DOC-DL, A-SWIFT-CFG).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| UtcTime | time.original | VERIFIED A-SWIFT-CFG | derive time.utc etc. (INFERRED) |
| Configuration | config_check.observed | VERIFIED A-SWIFT-CFG | changed configuration content/name (semantics UNVERIFIED A-PRIOR); place in `observed` (INFERRED); config_check.check = `sysmon_configuration` (INFERRED constant) |
| ConfigurationFileHash | unmapped[] | VERIFIED A-SWIFT-CFG | config_check has no hash slot — unmapped[] (OPEN_QUESTIONS: config hash carrier) |

- **Unmapped / traps:** `ConfigurationFileHash` → `unmapped[]`. `config_check.expected`/`status` have no source values — omit (absent ≠ unknown). derived_by `sentinel`: the source reports a *change*, while `config_check` models check/status semantics — Sentinel's reinterpretation, documented per project rules.

### Sysmon EID 17 — pipe_create

**Classification:** category: `pipe` · type: `pipe_create` · action: `create` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 17: PipeEvent (Pipe Created)"; config tag `PipeEvent`; channel task "Named pipe created" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| EventType | pipe.operation | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | EID 17 already implies `create`; literal EventType values UNVERIFIED A-PRIOR — prefer EID-derived operation (INFERRED) |
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| ProcessGuid | process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | creating process (secondary process payload) |
| ProcessId | process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| PipeName | pipe.name | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | raw name incl. `\\.\pipe\` prefix (INFERRED — keep lossless) |
| Image | process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| User | process.owner_name | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |

- **Unmapped / traps:** none beyond `RuleName`. Keep pipe name lossless; normalization is a detector concern (INFERRED).

### Sysmon EID 18 — pipe_connect

**Classification:** category: `pipe` · type: `pipe_connect` · action: `connect` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 18: PipeEvent (Pipe Connected)" ("named pipe connection … between a client and a server"); config tag `PipeEvent`; channel task "Named pipe connected" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| EventType | pipe.operation | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | EID 18 implies `connect` (INFERRED); literal values UNVERIFIED A-PRIOR |
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| ProcessGuid | process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | connecting process |
| ProcessId | process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| PipeName | pipe.name | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Image | process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| User | process.owner_name | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |

- **Unmapped / traps:** only the client side is logged per event pairing — server-side context requires correlating 17 (creator) and 18 (connector) by pipe name (INFERRED guidance).

### Sysmon EID 19 — wmi_filter_create

**Classification:** category: `wmi` · type: `wmi_filter_create` · action: `create` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 19: WmiEvent (WmiEventFilter activity detected)" — "logs the WMI namespace, filter name and filter expression"; config tag `WmiEvent`; channel task "WMI filter" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| EventType | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | EID already encodes the operation; literal EventType strings UNVERIFIED A-PRIOR → unmapped[] |
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| Operation | wmi.operation | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | raw operation string (value set UNVERIFIED A-PRIOR) |
| User | wmi.client_user | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | INFERRED semantic: the WMI client user; mirror to envelope user.name if your pipeline wants a detection user |
| EventNamespace | wmi.namespace | VERIFIED A-SYSMON-MOD | schema.go only (absent from Swift DATA) |
| Name | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | filter name — no wmi.object_name field (OPEN_QUESTIONS) |
| Query | wmi.query | VERIFIED A-SYSMON-MOD | schema.go only; filter expression (MS docs semantics, A-SYSMON-DOC-DL) |
| Type | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Destination | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Consumer | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Filter | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |

- **Unmapped / traps:** `Name`, `Type`, `Destination`, `Consumer`, `Filter`, `EventType` → `unmapped[]`. No process context exists on WmiEvent (no Image/ProcessGuid in either inventory) — do not fabricate a `process` payload (INFERRED prohibition).

### Sysmon EID 20 — wmi_consumer_create

**Classification:** category: `wmi` · type: `wmi_consumer_create` · action: `create` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 20: WmiEvent (WmiEventConsumer activity detected)" — "registration of WMI consumers, recording the consumer name, log, and destination"; config tag `WmiEvent`; channel task "WMI consumer" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| EventType | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | literal strings UNVERIFIED A-PRIOR |
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| Operation | wmi.operation | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| User | wmi.client_user | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | INFERRED semantic |
| EventNamespace | wmi.namespace | VERIFIED A-SYSMON-MOD | schema.go only |
| Name | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | consumer name — no canonical home (OPEN_QUESTIONS) |
| Type | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | consumer type (e.g. command-line/script class) — value set UNVERIFIED A-PRIOR |
| Destination | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | consumer destination (command/script target) — no home (OPEN_QUESTIONS: wmi consumer payload) |
| Consumer | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Filter | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Query | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only; normally empty for consumers |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |

- **Unmapped / traps:** the semantically richest consumer fields (`Name`, `Destination`, `Type`) have no schema home — surface them in `unmapped[]` so detectors can still fire (INFERRED guidance).

### Sysmon EID 21 — wmi_consumer_filter_bind

**Classification:** category: `wmi` · type: `wmi_consumer_filter_bind` · action: `bind` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 21: WmiEvent (WmiEventConsumerToFilter activity detected)" — "when a consumer binds to a filter, this event logs the consumer name and filter path"; config tag `WmiEvent`; channel task "WMI consumer filter" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| EventType | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | literal strings UNVERIFIED A-PRIOR |
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| Operation | wmi.operation | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| User | wmi.client_user | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | INFERRED semantic |
| EventNamespace | wmi.namespace | VERIFIED A-SYSMON-MOD | schema.go only |
| Name | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | consumer name (MS docs semantics) |
| Consumer | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | consumer path (MS docs semantics) |
| Filter | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | filter path (MS docs semantics) — no wmi.filter_path field (OPEN_QUESTIONS) |
| Type | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Destination | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Query | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |

- **Unmapped / traps:** consumer/filter paths → `unmapped[]`; bind events alone show persistence wiring — correlate 19/20/21 by name strings (INFERRED).

### Sysmon EID 22 — dns_query

**Classification:** category: `dns` · type: `dns_query` · action: `query` · outcome: `success` / `failure` (from `QueryStatus`) · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 22: DNSEvent (DNS query)" — generated on success or failure, cached or not; config tag `DnsQuery`; channel task "DNS query" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| RuleName | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| ProcessGuid | dns.process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | dns.process is a process_ref |
| ProcessId | dns.process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| QueryName | dns.query_name | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | keep case as logged (INFERRED: do not lowercase in parser) |
| QueryType | dns.query_type | VERIFIED A-SWIFT-CFG | Swift DATA only — absent from schema.go `DnsQuery` (filter not supported there); still an EventData name per A-SWIFT-CFG |
| QueryStatus | dns.query_status | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | numeric status as string; outcome `success` when 0 else `failure` (INFERRED; code table UNVERIFIED A-PRIOR) |
| QueryResults | dns.answers | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | array — split the raw string into answers (INFERRED); separator/format UNVERIFIED A-PRIOR; no answers → empty array or absent per pipeline policy (INFERRED) |
| Image | dns.process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| User | dns.process.owner_name | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | ambiguity per section convention |

- **Unmapped / traps:** no `dns.server`/`dns.response_code` in Sysmon EID 22 — absence is normal (do not emit `$state: "unknown"` for fields the source never had — INFERRED guidance). `QueryResults` may contain CNAME chains and TTLs — lossless split only.

### Sysmon EID 23 — file_delete

**Classification:** category: `file` · type: `file_delete` · action: `delete` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 23: FileDelete (File Delete archived)" — deleted file also saved to `ArchiveDirectory` (default `C:\Sysmon`); config tag `FileDelete`; channel task "File Delete archived" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| RuleName | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| ProcessGuid | process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | deleting process (secondary process payload) |
| ProcessId | process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| User | process.owner_name | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Image | process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| TargetFilename | file.path | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Hashes | file.hashes (md5/sha1/sha256/imphash/other) | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | of the deleted file (A-SYSMON-DOC-DL); split KEY=value (INFERRED; format UNVERIFIED A-PRIOR) |
| IsExecutable | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | boolean — no file.is_executable; optional derive `executable` payload (INFERRED) |
| Archived | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | whether file was archived to ArchiveDirectory — no canonical home (OPEN_QUESTIONS: archive flag) |

- **Unmapped / traps:** `IsExecutable`, `Archived` → `unmapped[]`. EID 23 vs EID 26 differ only by archiving (A-SYSMON-DOC-DL) — keep type `file_delete` for both and rely on `source.event_id` (documented decision).

### Sysmon EID 24 — clipboard_change

**Classification:** category: `process` · type: `clipboard_change` · action: `change` · outcome: `success` · severity: informational · derived_by: `sentinel`
**Source names:** MS docs "Event ID 24: ClipboardChange (New content in the clipboard)"; config tag `ClipboardChange`; channel task "New content in the clipboard" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| EventType | unmapped[] | VERIFIED A-SWIFT-CFG | Swift DATA only; literal values UNVERIFIED A-PRIOR |
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| ProcessGuid | process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | process that observed/received the change (secondary process payload carries it) |
| ProcessId | process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Image | process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Session | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | terminal session id — schema has process.terminal_session_id but clipboard context is not a process-create fact; keep unmapped (INFERRED choice) |
| User | process.owner_name | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| ClientInfo | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | no canonical home |
| Hashes | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | semantics of clipboard-content hash UNVERIFIED A-PRIOR — do not map to process/file hashes |
| Archived | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |

- **Unmapped / traps:** schema has **no clipboard payload** (OPEN_QUESTIONS: clipboard object) — category `process` is Sentinel's reinterpretation, hence derived_by `sentinel`; keep all clipboard-specific fields in `unmapped[]` rather than dropping them.

### Sysmon EID 25 — process_tampering

**Classification:** category: `process` · type: `process_tampering` · action: `modify` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 25: ProcessTampering (Process image change)" — hollow/herpaderp-style image manipulation; config tag `ProcessTampering`; channel task "Process image change" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| EventType | unmapped[] | VERIFIED A-SWIFT-CFG | Swift DATA only |
| RuleName | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| UtcTime | time.original | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| ProcessGuid | process.guid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | tampered process |
| ProcessId | process.pid | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Image | process.exe | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | |
| Type | unmapped[] | VERIFIED A-SWIFT-CFG, A-SYSMON-MOD | tamper kind (e.g. image patched/replaced/deleted) — no process.tamper_type; value set UNVERIFIED A-PRIOR (OPEN_QUESTIONS) |
| User | process.owner_name | VERIFIED A-SYSMON-MOD | schema.go only |

- **Unmapped / traps:** `Type` → `unmapped[]` (detectors need it — keep lossless). `EventType` → `unmapped[]`.

### Sysmon EID 26 — file_delete

**Classification:** category: `file` · type: `file_delete` · action: `delete` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 26: FileDeleteDetected (File Delete logged)" — deletion logged without archiving the file; config tag `FileDeleteDetected`; channel task "File Delete logged" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only (Swift v74 predates EID 26) |
| UtcTime | time.original | VERIFIED A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| ProcessGuid | process.guid | VERIFIED A-SYSMON-MOD | deleting process |
| ProcessId | process.pid | VERIFIED A-SYSMON-MOD | |
| User | process.owner_name | VERIFIED A-SYSMON-MOD | |
| Image | process.exe | VERIFIED A-SYSMON-MOD | |
| TargetFilename | file.path | VERIFIED A-SYSMON-MOD | |
| Hashes | file.hashes (md5/sha1/sha256/imphash/other) | VERIFIED A-SYSMON-MOD | split KEY=value (INFERRED; format UNVERIFIED A-PRIOR) |
| IsExecutable | unmapped[] | VERIFIED A-SYSMON-MOD | no file.is_executable |

- **Unmapped / traps:** no `Archived` field here (vs EID 23) — archiving state must come from `source.event_id`, not a canonical flag (documented decision).

### Sysmon EID 27 — file_block_executable

**Classification:** category: `file` · type: `file_block_executable` · action: `block` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 27: FileBlockExecutable" — "Sysmon detects and blocks the creation of executable files (PE format)"; config tag `FileBlockExecutable`; channel task "File Block Executable" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| UtcTime | time.original | VERIFIED A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| ProcessGuid | process.guid | VERIFIED A-SYSMON-MOD | process attempting the write (secondary process payload) |
| ProcessId | process.pid | VERIFIED A-SYSMON-MOD | |
| User | process.owner_name | VERIFIED A-SYSMON-MOD | |
| Image | process.exe | VERIFIED A-SYSMON-MOD | |
| TargetFilename | file.path | VERIFIED A-SYSMON-MOD | blocked path |
| Hashes | file.hashes (md5/sha1/sha256/imphash/other) | VERIFIED A-SYSMON-MOD | of the blocked image (INFERRED placement; format UNVERIFIED A-PRIOR) |

- **Unmapped / traps:** outcome `success` means the *block* succeeded (INFERRED semantics) — the file-create itself failed; detectors must not read it as a successful write. Optional `executable` payload with format `pe` (INFERRED, per MS "PE format" wording).

### Sysmon EID 28 — file_block_shredding

**Classification:** category: `file` · type: `file_block_shredding` · action: `block` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 28: FileBlockShredding" — "blocks file shredding from tools such as SDelete"; config tag `FileBlockShredding`; channel task "File Block Shredding" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| UtcTime | time.original | VERIFIED A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| ProcessGuid | process.guid | VERIFIED A-SYSMON-MOD | shredding process |
| ProcessId | process.pid | VERIFIED A-SYSMON-MOD | |
| User | process.owner_name | VERIFIED A-SYSMON-MOD | |
| Image | process.exe | VERIFIED A-SYSMON-MOD | |
| TargetFilename | file.path | VERIFIED A-SYSMON-MOD | |
| Hashes | file.hashes (md5/sha1/sha256/imphash/other) | VERIFIED A-SYSMON-MOD | format UNVERIFIED A-PRIOR |
| IsExecutable | unmapped[] | VERIFIED A-SYSMON-MOD | no file.is_executable |

- **Unmapped / traps:** `IsExecutable` → `unmapped[]`; block-success semantics as EID 27 (INFERRED).

### Sysmon EID 29 — file_executable_detected

**Classification:** category: `file` · type: `file_executable_detected` · action: `create` · outcome: `success` · severity: informational · derived_by: `source`
**Source names:** MS docs "Event ID 29: FileExecutableDetected" — "creation of a new executable file (PE format)"; config tag `FileExecutableDetected`; channel task "File Executable Detected" (A-SYSMON-DOC-DL).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| RuleName | unmapped[] | VERIFIED A-SYSMON-MOD | schema.go only |
| UtcTime | time.original | VERIFIED A-SYSMON-MOD | derive time.utc etc. (INFERRED) |
| ProcessGuid | process.guid | VERIFIED A-SYSMON-MOD | creating process (secondary process payload) |
| ProcessId | process.pid | VERIFIED A-SYSMON-MOD | |
| User | process.owner_name | VERIFIED A-SYSMON-MOD | |
| Image | process.exe | VERIFIED A-SYSMON-MOD | |
| TargetFilename | file.path | VERIFIED A-SYSMON-MOD | created PE path |
| Hashes | file.hashes (md5/sha1/sha256/imphash/other) | VERIFIED A-SYSMON-MOD | format UNVERIFIED A-PRIOR; optional `executable` payload (path/format=pe/hashes/signature) is INFERRED |

- **Unmapped / traps:** no signature fields on EID 29 — signers must come from enrichment, not this event (absent ≠ unsigned; INFERRED guidance).

### Sysmon EID 255 — sysmon_error

**Classification:** category: `third_party_alert` · type: `sysmon_error` · action: `error` · outcome: `unknown` · severity: informational · derived_by: `sentinel`
**Source names:** MS docs "Event ID 255: Error" — internal Sysmon errors (load, tasks, integrity conditions); config tag `n/a` (A-SYSMON-DOC-DL). No config tag table entry exists for 255 (A-SYSMON-DOC-DL tag table ends at 29).

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| (no EventData field names verified) | — | — | Do not assert any Data name: absent from Swift DATA comments (A-SWIFT-CFG), absent from schema.go `eventFields` (A-SYSMON-MOD), not enumerated on the MS pages (A-SYSMON-DOC-DL / A-SYSMON-DOC-EV) |

- **Unmapped / traps:** map envelope only — `source.event_id: 255`, `source.channel`, `host.hostname`, time from the record, raw payload in `raw`, and `third_party_alert.vendor: "Microsoft"` / `product: "Sysmon"` / `description` from the event text (INFERRED constants). Any `Data` names observed in live EVTX samples are UNVERIFIED (A-PRIOR) until a compliant source publishes them — record them in `unmapped[]` verbatim rather than promoting to canonical paths. derived_by `sentinel`: neither the category nor the type comes from a source taxonomy (Sysmon calls it only "Error").

## Source Mapping Tables — Windows Security

Evidence basis: every field-name claim below is extracted from the `Event XML` block of the corresponding Microsoft Learn event page (`<Data Name="…">` elements, including self-closing empty ones), captured after redirect to the archived `previous-versions` copy — verification key **A-SEC-PAGES** (per-id URLs and ms.date values are listed in the front matter). Events **4728** and **4756** have no page (HTTP 404); Microsoft documents them as field-for-field identical to **4732** on the Audit Security Group Management page (**A-SEC-GRPMGMT**: "All event fields, XML, and recommendations are the same. The type of group is the only difference."), so their tables reuse 4732's verified names. Event titles in each heading are the verbatim `<h1>` from the page (e.g. `4624(S): An account was successfully logged on.`).

Section-wide conventions (apply to every Security table below unless a row says otherwise):

- **Envelope (from the documented `System` section of each example XML, VERIFIED A-SEC-PAGES):** `TimeCreated@SystemTime` (has `Z`) → `time.utc` with `timezone_source: source_explicit`, `time.state: ok`, `precision: microsecond`/`unknown` per renderer; `Channel` → `source.channel` (`Security`); `Provider@Name` → `source.provider`; `EventID` → `source.event_id`; `EventRecordID` → `source.record.record_id`; `Computer` → `host.hostname`. **Subject\*** → envelope `user.sid` / `user.name` / `user.domain` / `user.logon_id`.
- **`authentication.account_*` = the primary account of the event** (for 4624/4625 the New Logon `Target*`; for Kerberos and 4776 the `TargetUserName` account; for 4634/4647 the only account present); **`authentication.target_*` = a distinct secondary object** (Kerberos `ServiceName`/`ServiceSid`). Assignments of `Target*` to `account_*` are labeled INFERRED (based on MS section headings + field order in the documented XML).
- **Types kept as strings:** SIDs, LUID/hex (`0x55cd1d`), status codes (`0xC0000064`), hex PIDs (`0x4c8` at source). Converting hex PIDs to integers for `int_or_state` fields (`authentication.process_pid`, `network.src_port`, …) is INFERRED — keep the original in `$raw`.
- **Empty vs null (project guidance, INFERRED):** Windows EventData frequently renders "no value" as `""`, self-closing `<Data Name="X"/>` (observed: 4688 `CommandLine`, VERIFIED A-SEC-PAGES) or `-` (observed: 4624 `RestrictedAdminMode`/`IpAddress` areas, VERIFIED A-SEC-PAGES). When the source documents empty/`-` and the value's semantics are null, parsers emit `{"$state": "null", "$raw": "-"}`; never bare `null`, never `""`.
- **Outcome derivation:** `(S)` in the title → `success`; `(F)` → `failure`; `(S, F)` → derive per event from `Status` where the page documents it (4776: `0x0` = success, VERIFIED A-SEC-PAGES; 4625/4771 → `failure`; 4768/4769 → `0x0` success else failure, INFERRED). Otherwise `unknown`.
- **`event.derived_by`:** `source` = the canonical type/action transliterate Microsoft's own event name/audit subcategory semantics; `sentinel` = Sentinel's reinterpretation (1102 → `fim`, 4946/4947/4948 → `config_check`). `severity` is Sentinel-assigned (default `informational`) in all cases.
- **Two standing traps:** (1) **PID reuse** — Security events carry no process GUID; any PID (`ProcessId`, `NewProcessId`, `ClientProcessId`, `ProcessID`) may be stale — correlate via `user.logon_id` + time window (INFERRED guidance); (2) **hostname ambiguity** — `SubjectDomainName`/`TargetDomainName`/`WorkstationName` are domains or account-host names, **not** the logging host; the host is `System/Computer` → `host.hostname` (VERIFIED A-SEC-PAGES: `Computer` element present in every documented XML).

### Security EID 1102 — audit_log_cleared

**MS page title:** "1102(S): The audit log was cleared." (A-SEC-PAGES)
**Classification:** category: `fim` · type: `audit_log_cleared` · action: `clear` · outcome: `success` · severity: informational · derived_by: `sentinel`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | account that cleared the log (UserData element name — page has no EventData; names taken from `<LogFileCleared>`) |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | domain/computer of the account — not host.hostname (trap) |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | LUID hex string — keep as string |

- **Unmapped / traps:** no `EventData` — field names are `<UserData>` element names (documented exception, A-SEC-PAGES). `fim.operation` = `audit_log_cleared` and `fim.path` = the Security log (optional, INFERRED constant `"Security"`; the event names no path). derived_by `sentinel`: "audit log cleared" has no source category; this project pins it to `fim` with an operation value (canonical choice documented per project guidance) — alternatives (`config_check`, envelope-only) rejected for detector simplicity. Traps: log-clearing is a **meta** event — the cleared content is gone (timeline gap); subject may be a service account (`SYSTEM`) — envelope user still maps it.

### Security EID 4624 — logon_success

**MS page title:** "4624(S): An account was successfully logged on." (A-SEC-PAGES)
**Classification:** category: `authentication` · type: `logon_success` · action: `logon` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | initiator of the logon |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | domain, or computer name for local accounts (MS field description) — not host.hostname |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | LUID hex — keep string |
| TargetUserSid | authentication.account_sid | VERIFIED A-SEC-PAGES | "New Logon" account (INFERRED assignment from section order) |
| TargetUserName | authentication.account_name | VERIFIED A-SEC-PAGES | |
| TargetDomainName | authentication.account_domain | VERIFIED A-SEC-PAGES | |
| TargetLogonId | authentication.logon_id | VERIFIED A-SEC-PAGES | LUID of the session created (INFERRED semantics) — keep string |
| LogonType | authentication.logon_type | VERIFIED A-SEC-PAGES | integer (2,3,10,…) — `int_or_state`; `-`/empty → `$state: "null"` (INFERRED) |
| LogonProcessName | unmapped[] | VERIFIED A-SEC-PAGES | no authentication.logon_process field (OPEN_QUESTIONS) |
| AuthenticationPackageName | authentication.auth_package | VERIFIED A-SEC-PAGES | Kerberos/NTLM/Negotiate — raw string |
| WorkstationName | authentication.workstation | VERIFIED A-SEC-PAGES | client workstation name — not host.hostname |
| LogonGuid | authentication.logon_guid | VERIFIED A-SEC-PAGES | string GUID (MS notes it varies by logon type) |
| TransmittedServices | unmapped[] | VERIFIED A-SEC-PAGES | S4U/transited services — no schema field |
| LmPackageName | unmapped[] | VERIFIED A-SEC-PAGES | |
| KeyLength | authentication.key_length | VERIFIED A-SEC-PAGES | integer; `0` is a legitimate value (not null) |
| ProcessId | authentication.process_pid | VERIFIED A-SEC-PAGES | hex `0x…` → int conversion INFERRED, keep `$raw`; PID reuse trap |
| ProcessName | authentication.process_name | VERIFIED A-SEC-PAGES | full path of logon process |
| IpAddress | authentication.source_ip | VERIFIED A-SEC-PAGES | `-` (local logon) → `$state: "null"`, `$raw: "-"` (INFERRED) |
| IpPort | unmapped[] | VERIFIED A-SEC-PAGES | authentication has no source_port (OPEN_QUESTIONS: auth source port) |
| ImpersonationLevel | unmapped[] | VERIFIED A-SEC-PAGES | value set (%%1833 etc.) UNVERIFIED A-PRIOR |
| RestrictedAdminMode | unmapped[] | VERIFIED A-SEC-PAGES | typically `-` |
| TargetOutboundUserName | unmapped[] | VERIFIED A-SEC-PAGES | outbound credential context — no schema field |
| TargetOutboundDomainName | unmapped[] | VERIFIED A-SEC-PAGES | |
| VirtualAccount | unmapped[] | VERIFIED A-SEC-PAGES | Yes/No flag per MS description; example XML renders `%%1843` |
| TargetLinkedLogonId | unmapped[] | VERIFIED A-SEC-PAGES | linked-logon pairing — no schema field |
| ElevatedToken | authentication.elev_token | VERIFIED A-SEC-PAGES | renderings: example XML shows `%%1842` (VERIFIED A-SEC-PAGES); MS field description says "Yes"/"No" (VERIFIED A-SEC-PAGES); `true`/`false` and `%16384`-style renderings UNVERIFIED A-PRIOR. Map Yes/true→true, No/false→false (INFERRED); `%%nnnn` → `{"$state":"invalid","$raw":"%%1842"}` (INFERRED — text expansion lives in the message table, not the EVTX) |

- **Traps:** PID reuse (`ProcessId` — no GUID); `SubjectDomainName`/`WorkstationName` ≠ hostname (use `System/Computer`); `-`/empty → `$state: "null"` (INFERRED); `LogonType` `"4"` vs `4` — normalize to int (INFERRED).

### Security EID 4625 — logon_failure

**MS page title:** "4625(F): An account failed to log on." (A-SEC-PAGES)
**Classification:** category: `authentication` · type: `logon_failure` · action: `logon` · outcome: `failure` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | not host.hostname |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | |
| TargetUserSid | authentication.account_sid | VERIFIED A-SEC-PAGES | attempted account (INFERRED assignment) |
| TargetUserName | authentication.account_name | VERIFIED A-SEC-PAGES | often the *guessed* name on failures |
| TargetDomainName | authentication.account_domain | VERIFIED A-SEC-PAGES | |
| TargetLogonId | authentication.logon_id | VERIFIED A-SEC-PAGES | usually null on failure → `$state: "null"` (INFERRED) |
| Status | authentication.status | VERIFIED A-SEC-PAGES | hex status string — keep as string |
| FailureReason | authentication.failure_reason | VERIFIED A-SEC-PAGES | raw (may be `%%nnnn` message constant — expansion UNVERIFIED A-PRIOR) |
| SubStatus | authentication.sub_status | VERIFIED A-SEC-PAGES | hex string (e.g. `0xC0000064`) — keep as string |
| LogonType | authentication.logon_type | VERIFIED A-SEC-PAGES | int (INFERRED) |
| LogonProcessName | unmapped[] | VERIFIED A-SEC-PAGES | no canonical field |
| AuthenticationPackageName | authentication.auth_package | VERIFIED A-SEC-PAGES | |
| WorkstationName | authentication.workstation | VERIFIED A-SEC-PAGES | |
| TransmittedServices | unmapped[] | VERIFIED A-SEC-PAGES | |
| LmPackageName | unmapped[] | VERIFIED A-SEC-PAGES | |
| KeyLength | authentication.key_length | VERIFIED A-SEC-PAGES | int; 0 common on failures |
| ProcessId | authentication.process_pid | VERIFIED A-SEC-PAGES | hex → int INFERRED; PID reuse trap |
| ProcessName | authentication.process_name | VERIFIED A-SEC-PAGES | |
| IpAddress | authentication.source_ip | VERIFIED A-SEC-PAGES | `-` → `$state: "null"` (INFERRED) |
| IpPort | unmapped[] | VERIFIED A-SEC-PAGES | no auth source_port (OPEN_QUESTIONS) |

- **Traps:** outcome `failure` is source-derived from `(F)`; `Status`/`SubStatus` distinguish bad-user vs bad-password — both must survive as raw strings; PID reuse; `-` → null state.

### Security EID 4634 — logoff

**MS page title:** "4634(S): An account was logged off." (A-SEC-PAGES)
**Classification:** category: `authentication` · type: `logoff` · action: `logoff` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| TargetUserSid | authentication.account_sid | VERIFIED A-SEC-PAGES | only account present — also mirror to `user.sid` (INFERRED; no Subject fields exist) |
| TargetUserName | authentication.account_name | VERIFIED A-SEC-PAGES | mirror to `user.name` (INFERRED) |
| TargetDomainName | authentication.account_domain | VERIFIED A-SEC-PAGES | not host.hostname |
| TargetLogonId | authentication.logon_id | VERIFIED A-SEC-PAGES | join key to 4624 (INFERRED guidance) |
| LogonType | authentication.logon_type | VERIFIED A-SEC-PAGES | int (INFERRED); often `0`/`-` here |

- **Traps:** no Subject/Ip/process fields — envelope `user` must be populated from `Target*` (INFERRED convention) or detectors will see an empty user; PID reuse N/A (no PIDs).

### Security EID 4647 — logoff_initiated

**MS page title:** "4647(S): User initiated logoff." (A-SEC-PAGES)
**Classification:** category: `authentication` · type: `logoff_initiated` · action: `logoff` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| TargetUserSid | authentication.account_sid | VERIFIED A-SEC-PAGES | also mirror to `user.sid` (INFERRED — no Subject fields) |
| TargetUserName | authentication.account_name | VERIFIED A-SEC-PAGES | mirror to `user.name` (INFERRED) |
| TargetDomainName | authentication.account_domain | VERIFIED A-SEC-PAGES | not host.hostname |
| TargetLogonId | authentication.logon_id | VERIFIED A-SEC-PAGES | pairs with 4634/4624 (INFERRED) |

- **Traps:** 4647 (user-initiated) vs 4634 (always) — keep both types distinct for session-duration math (INFERRED); no PID/hostname fields beyond envelope.

### Security EID 4648 — explicit_credential_logon

**MS page title:** "4648(S): A logon was attempted using explicit credentials." (A-SEC-PAGES)
**Classification:** category: `authentication` · type: `explicit_credential_logon` · action: `logon` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | account on whose behalf the attempt runs |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | |
| LogonGuid | authentication.logon_guid | VERIFIED A-SEC-PAGES | |
| TargetUserName | authentication.target_name | VERIFIED A-SEC-PAGES | account whose credentials were supplied — target semantics (INFERRED assignment) |
| TargetDomainName | authentication.target_domain | VERIFIED A-SEC-PAGES | |
| TargetLogonGuid | unmapped[] | VERIFIED A-SEC-PAGES | no target_logon_guid in schema (OPEN_QUESTIONS) |
| TargetServerName | unmapped[] | VERIFIED A-SEC-PAGES | destination server/instance — no canonical field (OPEN_QUESTIONS) |
| TargetInfo | unmapped[] | VERIFIED A-SEC-PAGES | composite string — lossless unmapped[] |
| ProcessId | authentication.caller_process_id | VERIFIED A-SEC-PAGES | hex → int INFERRED, keep `$raw`; PID reuse trap |
| ProcessName | authentication.caller_process_name | VERIFIED A-SEC-PAGES | caller process (e.g. `runas`-style) |
| IpAddress | authentication.source_ip | VERIFIED A-SEC-PAGES | `-` → `$state: "null"` (INFERRED) |
| IpPort | unmapped[] | VERIFIED A-SEC-PAGES | no auth source_port (OPEN_QUESTIONS) |

- **Traps:** PID reuse on `ProcessId`; `TargetInfo` may embed `domain\user` — do not pre-parse (INFERRED: keep raw); classic runas/psexec lateral-movement signal — severity policy is detector-side.

### Security EID 4672 — special_privileges_assigned

**MS page title:** "4672(S): Special privileges assigned to new logon." (A-SEC-PAGES)
**Classification:** category: `authentication` · type: `special_privileges_assigned` · action: `assign` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | newly logged-on account |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | LUID — join to 4624 (INFERRED) |
| PrivilegeList | unmapped[] | VERIFIED A-SEC-PAGES | newline/semicolon-separated privileges (SeDebugPrivilege, …) — schema has no privileges field (OPEN_QUESTIONS: privilege list) |

- **Traps:** no process/network data — pairing with 4624 via `user.logon_id` is required for attribution (INFERRED); `PrivilegeList` must be preserved verbatim in `unmapped[]`; noisy on domain controllers (baseline at detectors, not parsers).

### Security EID 4688 — process_create

**MS page title:** "4688(S): A new process has been created." (A-SEC-PAGES)
**Classification:** category: `process` · type: `process_create` · action: `create` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | creating/logon account |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | not host.hostname |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | |
| NewProcessId | process.pid | VERIFIED A-SEC-PAGES | hex → int INFERRED, keep `$raw` |
| NewProcessName | process.exe | VERIFIED A-SEC-PAGES | |
| TokenElevationType | process.integrity_level | VERIFIED A-SEC-PAGES | raw string (%%1968/%%1969/%%1970 UNVERIFIED A-PRIOR) |
| ProcessId | process.parent.pid | VERIFIED A-SEC-PAGES | **parent/creator PID** (MS description) — hex → int INFERRED, keep `$raw`; PID reuse trap |
| CommandLine | process.command_line | VERIFIED A-SEC-PAGES | present but self-closing/empty in the documented example; populate when populated |
| TargetUserSid | process.owner_sid | VERIFIED A-SEC-PAGES | |
| TargetUserName | process.owner_name | VERIFIED A-SEC-PAGES | |
| TargetDomainName | unmapped[] | VERIFIED A-SEC-PAGES | no process.owner_domain field |
| TargetLogonId | unmapped[] | VERIFIED A-SEC-PAGES | process.logon_id exists but is the *logon* LUID, not this field's token LUID — leave unmapped (INFERRED conservative choice; OPEN_QUESTIONS) |
| ParentProcessName | process.parent.exe | VERIFIED A-SEC-PAGES | full path of parent |
| MandatoryLabel | process.integrity_level | VERIFIED A-SEC-PAGES | SID-form integrity label (e.g. S-1-16-12288) — overrides TokenElevationType mapping if both present; keep as string (INFERRED precedence) |

- **Traps:** two distinct PIDs (`NewProcessId` → child, `ProcessId` → parent) — mislabeling either breaks lineage; PID reuse (no process GUID here, unlike Sysmon); `TargetDomainName`/`SubjectDomainName` are domains, not host.hostname; `CommandLine` may be legitimately empty — absent vs empty must not be confused (INFERRED guidance).

### Security EID 4689 — process_terminate

**MS page title:** "4689(S): A process has exited." (A-SEC-PAGES)
**Classification:** category: `process` · type: `process_terminate` · action: `terminate` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | |
| Status | unmapped[] | VERIFIED A-SEC-PAGES | no process.exit_code in schema (OPEN_QUESTIONS) |
| ProcessId | process.pid | VERIFIED A-SEC-PAGES | hex → int INFERRED, keep `$raw`; PID reuse trap |
| ProcessName | process.exe | VERIFIED A-SEC-PAGES | |

- **Traps:** no GUID, no parent, no exit code — 4689 cannot reconstruct lineage alone; correlate to 4688 via pid + time window (INFERRED guidance).

### Security EID 4697 — service_install

**MS page title:** "4697(S): A service was installed in the system." (A-SEC-PAGES)
**Classification:** category: `service` · type: `service_install` · action: `install` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | |
| ServiceName | service.name | VERIFIED A-SEC-PAGES | short service name |
| ServiceFileName | service.image_path | VERIFIED A-SEC-PAGES | may embed arguments — keep whole string (INFERRED) |
| ServiceType | service.service_type | VERIFIED A-SEC-PAGES | hex/int as string (e.g. 0x10) |
| ServiceStartType | service.start_type | VERIFIED A-SEC-PAGES | string (e.g. demand/auto) |
| ServiceAccount | service.account_name | VERIFIED A-SEC-PAGES | |

- **Traps:** `ServiceFileName` may be `"C:\path\svc.exe" -arg` — do not pre-split into image/args (INFERRED); service created via WMI/SCM may not fire 4697 (absence ≠ no install; INFERRED guidance); no PID here — correlate 4688 + SCM.

### Security EID 4698 — scheduled_task_create

**MS page title:** "4698(S): A scheduled task was created." (A-SEC-PAGES)
**Classification:** category: `scheduled_task` · type: `scheduled_task_create` · action: `create` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | |
| TaskName | scheduled_task.name | VERIFIED A-SEC-PAGES | path-form (`\TaskName`) — keep as string (INFERRED: do not split into path/name) |
| TaskContent | scheduled_task.task_xml | VERIFIED A-SEC-PAGES | full XML — store whole string; contains command/action/trigger but keep raw (INFERRED: no pre-parse) |
| ClientProcessStartKey | unmapped[] | VERIFIED A-SEC-PAGES | no schema field |
| ClientProcessId | process.pid | VERIFIED A-SEC-PAGES | creating-client PID — hex → int INFERRED, PID reuse trap |
| ParentProcessId | process.parent.pid | VERIFIED A-SEC-PAGES | hex → int INFERRED, PID reuse trap |
| RpcCallClientLocality | unmapped[] | VERIFIED A-SEC-PAGES | |
| FQDN | unmapped[] | VERIFIED A-SEC-PAGES | client FQDN — not host.hostname; hostname-ambiguity trap |

- **Traps:** `TaskContent` is the full task definition (actions/triggers/run-level) — detectors parse it downstream, not here (INFERRED); `FQDN` is the *client*, not the logging host (use `System/Computer`); two PIDs (client + parent) — do not conflate.

### Security EID 4720 — account_created

**MS page title:** "4720(S): A user account was created." (A-SEC-PAGES)
**Classification:** category: `account` · type: `account_created` · action: `create` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| TargetUserName | account.name | VERIFIED A-SEC-PAGES | new account |
| TargetDomainName | account.domain | VERIFIED A-SEC-PAGES | not host.hostname |
| TargetSid | account.sid | VERIFIED A-SEC-PAGES | SID-form → keep string |
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | creating account |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | |
| PrivilegeList | unmapped[] | VERIFIED A-SEC-PAGES | no privileges field (OPEN_QUESTIONS) |
| SamAccountName | account.sam_account_name | VERIFIED A-SEC-PAGES | |
| DisplayName | account.display_name | VERIFIED A-SEC-PAGES | |
| UserPrincipalName | account.upn | VERIFIED A-SEC-PAGES | |
| HomeDirectory | unmapped[] | VERIFIED A-SEC-PAGES | no schema field |
| HomePath | unmapped[] | VERIFIED A-SEC-PAGES | |
| ScriptPath | unmapped[] | VERIFIED A-SEC-PAGES | |
| ProfilePath | unmapped[] | VERIFIED A-SEC-PAGES | |
| UserWorkstations | unmapped[] | VERIFIED A-SEC-PAGES | |
| PasswordLastSet | unmapped[] | VERIFIED A-SEC-PAGES | timestamp — no account.password_last_set |
| AccountExpires | unmapped[] | VERIFIED A-SEC-PAGES | |
| PrimaryGroupId | unmapped[] | VERIFIED A-SEC-PAGES | |
| AllowedToDelegateTo | unmapped[] | VERIFIED A-SEC-PAGES | |
| OldUacValue | unmapped[] | VERIFIED A-SEC-PAGES | hex — no UAC field |
| NewUacValue | unmapped[] | VERIFIED A-SEC-PAGES | hex — no UAC field |
| UserAccountControl | unmapped[] | VERIFIED A-SEC-PAGES | hex — no UAC field (OPEN_QUESTIONS: UAC flags) |
| UserParameters | unmapped[] | VERIFIED A-SEC-PAGES | |
| SidHistory | account.sid_history | VERIFIED A-SEC-PAGES | |
| LogonHours | unmapped[] | VERIFIED A-SEC-PAGES | |

- **Traps:** `Target*` here is the **new account** (not a logon target) — maps to `account.*`, not `authentication.*` (INFERRED decision); `OldUacValue`/`NewUacValue`/`UserAccountControl` carry enable/lockout/delegation bits but have no home — keep verbatim in `unmapped[]`; subject may be a delegated admin, not a person.

### Security EID 4722 — account_enabled

**MS page title:** "4722(S): A user account was enabled." (A-SEC-PAGES)
**Classification:** category: `account` · type: `account_enabled` · action: `enable` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| TargetUserName | account.name | VERIFIED A-SEC-PAGES | account re-enabled |
| TargetDomainName | account.domain | VERIFIED A-SEC-PAGES | |
| TargetSid | account.sid | VERIFIED A-SEC-PAGES | |
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | |

- **Traps:** `account.enabled` is true by definition of the event but is a *derived* constant, not a source field — do not populate from a field; subject/target split as above.

### Security EID 4724 — password_reset

**MS page title:** "4724(S, F): An attempt was made to reset an account's password." (A-SEC-PAGES)
**Classification:** category: `account` · type: `password_reset` · action: `reset` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| TargetUserName | account.name | VERIFIED A-SEC-PAGES | account whose password was reset |
| TargetDomainName | account.domain | VERIFIED A-SEC-PAGES | |
| TargetSid | account.sid | VERIFIED A-SEC-PAGES | |
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | resetting account |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | |

- **Traps:** title is "(S, F)" — no `Status` field here to disambiguate (unlike 4776); set outcome from audit-config context or leave `unknown` (INFERRED guidance); no password material in the event (by design).

### Security EID 4726 — account_deleted

**MS page title:** "4726(S): A user account was deleted." (A-SEC-PAGES)
**Classification:** category: `account` · type: `account_deleted` · action: `delete` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| TargetUserName | account.name | VERIFIED A-SEC-PAGES | deleted account |
| TargetDomainName | account.domain | VERIFIED A-SEC-PAGES | |
| TargetSid | account.sid | VERIFIED A-SEC-PAGES | |
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | deleting account |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | |
| PrivilegeList | unmapped[] | VERIFIED A-SEC-PAGES | no privileges field |

- **Traps:** deletion removes the account — SID is the durable join key, not the name (INFERRED guidance).

### Security EID 4728 — member_added_to_global_group

**MS page title:** (no dedicated page — 404; A-SEC-GRPMGMT documents the global-group analogue of 4732)
**Classification:** category: `group_membership` · type: `member_added_to_global_group` · action: `add` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| MemberName | group_membership.member_name | VERIFIED A-SEC-GRPMGMT (= 4732 field set) | |
| MemberSid | group_membership.member_sid | VERIFIED A-SEC-GRPMGMT | |
| TargetUserName | group_membership.group_name | VERIFIED A-SEC-GRPMGMT | the group |
| TargetDomainName | group_membership.domain | VERIFIED A-SEC-GRPMGMT | |
| TargetSid | group_membership.group_sid | VERIFIED A-SEC-GRPMGMT | |
| SubjectUserSid | user.sid | VERIFIED A-SEC-GRPMGMT | |
| SubjectUserName | user.name | VERIFIED A-SEC-GRPMGMT | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-GRPMGMT | not host.hostname |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-GRPMGMT | |
| PrivilegeList | unmapped[] | VERIFIED A-SEC-GRPMGMT | |

- **Traps:** field names are **inferred by documented equivalence** to 4732 (A-SEC-GRPMGMT: "All event fields, XML, and recommendations are the same. The type of group is the only difference.") — the 4732 page is the primary evidence; no 4728-specific XML was retrieved (404); group *scope* (global) is a semantic difference not carried by any field name.

### Security EID 4732 — member_added_to_local_group

**MS page title:** "4732(S): A member was added to a security-enabled local group." (A-SEC-PAGES)
**Classification:** category: `group_membership` · type: `member_added_to_local_group` · action: `add` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| MemberName | group_membership.member_name | VERIFIED A-SEC-PAGES | |
| MemberSid | group_membership.member_sid | VERIFIED A-SEC-PAGES | |
| TargetUserName | group_membership.group_name | VERIFIED A-SEC-PAGES | the group |
| TargetDomainName | group_membership.domain | VERIFIED A-SEC-PAGES | |
| TargetSid | group_membership.group_sid | VERIFIED A-SEC-PAGES | |
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | not host.hostname |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | |
| PrivilegeList | unmapped[] | VERIFIED A-SEC-PAGES | no privileges field |

- **Traps:** `MemberName` may be a SID (`S-1-…`) when the member is a foreign/unresolvable principal — keep string, do not normalize (INFERRED); adding to a *local* group has host scope — host.hostname from `System/Computer`.

### Security EID 4738 — account_changed

**MS page title:** "4738(S): A user account was changed." (A-SEC-PAGES)
**Classification:** category: `account` · type: `account_changed` · action: `modify` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| Dummy | unmapped[] | VERIFIED A-SEC-PAGES | literal placeholder `<Data Name="Dummy" />` — keep in unmapped[] for losslessness, do not discard silently |
| TargetUserName | account.name | VERIFIED A-SEC-PAGES | changed account |
| TargetDomainName | account.domain | VERIFIED A-SEC-PAGES | |
| TargetSid | account.sid | VERIFIED A-SEC-PAGES | |
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | changing account |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | |
| PrivilegeList | unmapped[] | VERIFIED A-SEC-PAGES | |
| SamAccountName | account.sam_account_name | VERIFIED A-SEC-PAGES | post-change value |
| DisplayName | account.display_name | VERIFIED A-SEC-PAGES | |
| UserPrincipalName | account.upn | VERIFIED A-SEC-PAGES | |
| HomeDirectory | unmapped[] | VERIFIED A-SEC-PAGES | |
| HomePath | unmapped[] | VERIFIED A-SEC-PAGES | |
| ScriptPath | unmapped[] | VERIFIED A-SEC-PAGES | |
| ProfilePath | unmapped[] | VERIFIED A-SEC-PAGES | |
| UserWorkstations | unmapped[] | VERIFIED A-SEC-PAGES | |
| PasswordLastSet | unmapped[] | VERIFIED A-SEC-PAGES | timestamp — no field |
| AccountExpires | unmapped[] | VERIFIED A-SEC-PAGES | |
| PrimaryGroupId | unmapped[] | VERIFIED A-SEC-PAGES | |
| AllowedToDelegateTo | unmapped[] | VERIFIED A-SEC-PAGES | |
| OldUacValue | unmapped[] | VERIFIED A-SEC-PAGES | hex |
| NewUacValue | unmapped[] | VERIFIED A-SEC-PAGES | hex |
| UserAccountControl | unmapped[] | VERIFIED A-SEC-PAGES | hex |
| UserParameters | unmapped[] | VERIFIED A-SEC-PAGES | |
| SidHistory | account.sid_history | VERIFIED A-SEC-PAGES | |
| LogonHours | unmapped[] | VERIFIED A-SEC-PAGES | |

- **Traps:** fields show **post-change** values only — the event does not carry the old value for name/UPN/etc. (INFERRED: old-value comparison not possible from this event alone); `Dummy` is a real EventData name (placeholder), not a parser artifact.

### Security EID 4740 — account_locked_out

**MS page title:** "4740(S): A user account was locked out." (A-SEC-PAGES)
**Classification:** category: `account` · type: `account_locked_out` · action: `lock` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| TargetUserName | account.name | VERIFIED A-SEC-PAGES | locked-out account |
| TargetDomainName | account.domain | VERIFIED A-SEC-PAGES | |
| TargetSid | account.sid | VERIFIED A-SEC-PAGES | |
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | subject is usually the *source* of the failed attempts (e.g. caller/host SID) |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | not host.hostname |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | |

- **Traps:** lockout is *caused by* prior 4625 failures — this event carries no attempt data; subject/target roles differ from 4624 (subject = trigger source, target = victim account) — do not reuse the 4624 subject/target interpretation blindly (INFERRED).

### Security EID 4756 — member_added_to_universal_group

**MS page title:** (no dedicated page — 404; A-SEC-GRPMGMT documents the universal-group analogue of 4732)
**Classification:** category: `group_membership` · type: `member_added_to_universal_group` · action: `add` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| MemberName | group_membership.member_name | VERIFIED A-SEC-GRPMGMT (= 4732 field set) | |
| MemberSid | group_membership.member_sid | VERIFIED A-SEC-GRPMGMT | |
| TargetUserName | group_membership.group_name | VERIFIED A-SEC-GRPMGMT | the group |
| TargetDomainName | group_membership.domain | VERIFIED A-SEC-GRPMGMT | |
| TargetSid | group_membership.group_sid | VERIFIED A-SEC-GRPMGMT | |
| SubjectUserSid | user.sid | VERIFIED A-SEC-GRPMGMT | |
| SubjectUserName | user.name | VERIFIED A-SEC-GRPMGMT | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-GRPMGMT | not host.hostname |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-GRPMGMT | |
| PrivilegeList | unmapped[] | VERIFIED A-SEC-GRPMGMT | |

- **Traps:** same documented-equivalence caveat as 4728; universal-group scope (domain-forest) is semantic only, not a field difference.

### Security EID 4767 — account_unlocked

**MS page title:** "4767(S): A user account was unlocked." (A-SEC-PAGES)
**Classification:** category: `account` · type: `account_unlocked` · action: `unlock` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| TargetUserName | account.name | VERIFIED A-SEC-PAGES | unlocked account |
| TargetDomainName | account.domain | VERIFIED A-SEC-PAGES | |
| TargetSid | account.sid | VERIFIED A-SEC-PAGES | |
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | unlocking admin |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | |

- **Traps:** unlock is a *manual/automated remediation* action — subject is the operator; pair with 4740 via account.sid for lockout→unlock timelines (INFERRED guidance).

### Security EID 4768 — kerberos_tgt_requested

**MS page title:** "4768(S, F): A Kerberos authentication ticket (TGT) was requested." (A-SEC-PAGES)
**Classification:** category: `authentication` · type: `kerberos_tgt_requested` · action: `request` · outcome: `success` (Status `0x0`) / `failure` (else) — INFERRED per A-PRIOR (status code table not in A-SEC-PAGES) · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| TargetUserName | authentication.account_name | VERIFIED A-SEC-PAGES | **client account** (Kerberos "Account Name") — INFERRED mapping |
| TargetDomainName | authentication.account_domain | VERIFIED A-SEC-PAGES | |
| TargetSid | authentication.account_sid | VERIFIED A-SEC-PAGES | |
| ServiceName | authentication.target_name | VERIFIED A-SEC-PAGES | `krbtgt` for TGT — target semantics (INFERRED) |
| ServiceSid | authentication.target_sid | VERIFIED A-SEC-PAGES | usually absent for TGT |
| TicketOptions | unmapped[] | VERIFIED A-SEC-PAGES | hex flags — no field |
| Status | authentication.status | VERIFIED A-SEC-PAGES | hex string — keep string; outcome derivation INFERRED (A-PRIOR code table) |
| TicketEncryptionType | unmapped[] | VERIFIED A-SEC-PAGES | hex — no field (OPEN_QUESTIONS: cipher) |
| PreAuthType | unmapped[] | VERIFIED A-SEC-PAGES | |
| IpAddress | authentication.source_ip | VERIFIED A-SEC-PAGES | client IP; `-` → `$state: "null"` (INFERRED) |
| IpPort | unmapped[] | VERIFIED A-SEC-PAGES | no auth source_port (OPEN_QUESTIONS) |
| CertIssuerName | unmapped[] | VERIFIED A-SEC-PAGES | PKINIT — no field |
| CertSerialNumber | unmapped[] | VERIFIED A-SEC-PAGES | |
| CertThumbprint | unmapped[] | VERIFIED A-SEC-PAGES | |
| ResponseTicket | unmapped[] | VERIFIED A-SEC-PAGES | |
| AccountSupportedEncryptionTypes | unmapped[] | VERIFIED A-SEC-PAGES | newer extension fields — no schema home |
| AccountAvailableKeys | unmapped[] | VERIFIED A-SEC-PAGES | |
| ServiceSupportedEncryptionTypes | unmapped[] | VERIFIED A-SEC-PAGES | |
| ServiceAvailableKeys | unmapped[] | VERIFIED A-SEC-PAGES | |
| DCSupportedEncryptionTypes | unmapped[] | VERIFIED A-SEC-PAGES | |
| DCAvailableKeys | unmapped[] | VERIFIED A-SEC-PAGES | |
| ClientAdvertizedEncryptionTypes | unmapped[] | VERIFIED A-SEC-PAGES | |
| SessionKeyEncryptionType | unmapped[] | VERIFIED A-SEC-PAGES | |
| PreAuthEncryptionType | unmapped[] | VERIFIED A-SEC-PAGES | |

- **Traps:** two `TargetUserName`/`TargetDomainName`/`TargetSid`/`ServiceName`/`ServiceSid`/`TicketOptions`/`Status`/`TicketEncryptionType`/`PreAuthType`/`IpAddress`/`IpPort`/`Cert*` groups appear in the page (dual EventData variants) — treat as **one union** (same semantics, differing extension presence); `ServiceName=krbtgt` marks a TGT, not a service logon (INFERRED: do not read as service account); AS-REP roastable accounts surface here (no pre-auth) — detector concern, not parser.

### Security EID 4769 — kerberos_service_ticket_requested

**MS page title:** "4769(S, F): A Kerberos service ticket was requested." (A-SEC-PAGES)
**Classification:** category: `authentication` · type: `kerberos_service_ticket_requested` · action: `request` · outcome: `success` (Status `0x0`) / `failure` (else) — INFERRED per A-PRIOR · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| TargetUserName | authentication.account_name | VERIFIED A-SEC-PAGES | **service account** being requested (INFERRED — differs from 4768 where target is the client) |
| TargetDomainName | authentication.account_domain | VERIFIED A-SEC-PAGES | |
| ServiceName | authentication.target_name | VERIFIED A-SEC-PAGES | SPN — target semantics (INFERRED) |
| ServiceSid | authentication.target_sid | VERIFIED A-SEC-PAGES | |
| TicketOptions | unmapped[] | VERIFIED A-SEC-PAGES | hex |
| TicketEncryptionType | unmapped[] | VERIFIED A-SEC-PAGES | hex — Kerberoast cipher signal, keep raw |
| IpAddress | authentication.source_ip | VERIFIED A-SEC-PAGES | client IP; `-` → `$state: "null"` (INFERRED) |
| IpPort | unmapped[] | VERIFIED A-SEC-PAGES | no auth source_port (OPEN_QUESTIONS) |
| Status | authentication.status | VERIFIED A-SEC-PAGES | hex; outcome derivation INFERRED (A-PRIOR) |
| LogonGuid | authentication.logon_guid | VERIFIED A-SEC-PAGES | |
| TransmittedServices | unmapped[] | VERIFIED A-SEC-PAGES | S4U |
| RequestTicketHash | unmapped[] | VERIFIED A-SEC-PAGES | |
| ResponseTicketHash | unmapped[] | VERIFIED A-SEC-PAGES | |
| AccountSupportedEncryptionTypes | unmapped[] | VERIFIED A-SEC-PAGES | extension fields |
| AccountAvailableKeys | unmapped[] | VERIFIED A-SEC-PAGES | |
| ServiceSupportedEncryptionTypes | unmapped[] | VERIFIED A-SEC-PAGES | |
| ServiceAvailableKeys | unmapped[] | VERIFIED A-SEC-PAGES | |
| DCSupportedEncryptionTypes | unmapped[] | VERIFIED A-SEC-PAGES | |
| DCAvailableKeys | unmapped[] | VERIFIED A-SEC-PAGES | |
| ClientAdvertizedEncryptionTypes | unmapped[] | VERIFIED A-SEC-PAGES | |
| SessionKeyEncryptionType | unmapped[] | VERIFIED A-SEC-PAGES | |

- **Traps:** dual EventData variants — union, as 4768; **no `TargetSid`/`PreAuthType`** here (present on 4768, absent on 4769) — absence is source-true, do not synthesize; `TicketEncryptionType` (e.g. RC4 `0x17`) is the Kerberoast discriminator — keep hex string verbatim.

### Security EID 4771 — kerberos_preauth_failed

**MS page title:** "4771(F): Kerberos pre-authentication failed." (A-SEC-PAGES)
**Classification:** category: `authentication` · type: `kerberos_preauth_failed` · action: `request` · outcome: `failure` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| TargetUserName | authentication.account_name | VERIFIED A-SEC-PAGES | client account (INFERRED) |
| TargetSid | authentication.account_sid | VERIFIED A-SEC-PAGES | |
| ServiceName | authentication.target_name | VERIFIED A-SEC-PAGES | usually `krbtgt` |
| TicketOptions | unmapped[] | VERIFIED A-SEC-PAGES | hex |
| Status | authentication.status | VERIFIED A-SEC-PAGES | hex — keep string |
| PreAuthType | unmapped[] | VERIFIED A-SEC-PAGES | |
| IpAddress | authentication.source_ip | VERIFIED A-SEC-PAGES | client IP; `-` → `$state: "null"` (INFERRED) |
| IpPort | unmapped[] | VERIFIED A-SEC-PAGES | no auth source_port (OPEN_QUESTIONS) |
| CertIssuerName | unmapped[] | VERIFIED A-SEC-PAGES | PKINIT |
| CertSerialNumber | unmapped[] | VERIFIED A-SEC-PAGES | |
| CertThumbprint | unmapped[] | VERIFIED A-SEC-PAGES | |

- **Traps:** title is "(F)" only — no success variant; no `TargetDomainName` here (present on 4768/4769) — absence is source-true; password-spray/kerberoast-fail signals correlate to 4768 by IpAddress + time (INFERRED guidance).

### Security EID 4776 — credential_validation

**MS page title:** "4776(S, F): The computer attempted to validate the credentials for an account." (A-SEC-PAGES)
**Classification:** category: `authentication` · type: `credential_validation` · action: `validate` · outcome: `success` (Status `0x0`) / `failure` (else) — VERIFIED A-SEC-PAGES (MS field description: "0x0" = success) · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| PackageName | authentication.auth_package | VERIFIED A-SEC-PAGES | MSU_SEC_PKG (NTLM) — keep raw string |
| TargetUserName | authentication.account_name | VERIFIED A-SEC-PAGES | account validated |
| Workstation | authentication.workstation | VERIFIED A-SEC-PAGES | client workstation — not host.hostname |
| Status | authentication.status | VERIFIED A-SEC-PAGES | `0x0` = success (VERIFIED A-SEC-PAGES field description); else failure — outcome derivation from this is VERIFIED, not INFERRED |

- **Traps:** no domain/SID fields — join to 4624/4625 via account_name + time (INFERRED guidance); `Status` hex must stay string (success `0x0`, various failure codes); this is the NTLM validation signal — pair with Kerberos 4768/4769 for protocol-baseline detection (INFERRED guidance).

### Security EID 5140 — network_share_access

**MS page title:** "5140(S, F): A network share object was accessed." (A-SEC-PAGES)
**Classification:** category: `network` · type: `network_share_access` · action: `access` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | accessing account |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | join key to 4624 (INFERRED) |
| ObjectType | unmapped[] | VERIFIED A-SEC-PAGES | share vs file — no field |
| IpAddress | network.src_ip | VERIFIED A-SEC-PAGES | client IP; `-`/`::1`/`127.0.0.1` handling per INFERRED policy |
| IpPort | network.src_port | VERIFIED A-SEC-PAGES | hex → int INFERRED, keep `$raw` |
| ShareName | unmapped[] | VERIFIED A-SEC-PAGES | `\\*\C$` form — no share field in `network` (OPEN_QUESTIONS: share name) |
| ShareLocalPath | unmapped[] | VERIFIED A-SEC-PAGES | local path backing the share |
| AccessMask | unmapped[] | VERIFIED A-SEC-PAGES | hex — no field |
| AccessList | unmapped[] | VERIFIED A-SEC-PAGES | |

- **Traps:** title "(S, F)" but no `Status` field — outcome from audit policy context (INFERRED: default `success` when audited-allow fires); `ShareName`/`ShareLocalPath`/`AccessMask` carry the SMB semantics — keep in `unmapped[]`; no `network.dst_port` (SMB 445 is implied by channel, not a field — do not synthesize; INFERRED prohibition); PID reuse N/A (no PID).

### Security EID 5145 — network_share_access_check

**MS page title:** "5145(S, F): A network share object was checked to see whether client can be granted desired access." (A-SEC-PAGES)
**Classification:** category: `network` · type: `network_share_access_check` · action: `check` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| SubjectUserSid | user.sid | VERIFIED A-SEC-PAGES | |
| SubjectUserName | user.name | VERIFIED A-SEC-PAGES | |
| SubjectDomainName | user.domain | VERIFIED A-SEC-PAGES | |
| SubjectLogonId | user.logon_id | VERIFIED A-SEC-PAGES | |
| ObjectType | unmapped[] | VERIFIED A-SEC-PAGES | |
| IpAddress | network.src_ip | VERIFIED A-SEC-PAGES | |
| IpPort | network.src_port | VERIFIED A-SEC-PAGES | hex → int INFERRED, keep `$raw` |
| ShareName | unmapped[] | VERIFIED A-SEC-PAGES | no share field (OPEN_QUESTIONS) |
| ShareLocalPath | unmapped[] | VERIFIED A-SEC-PAGES | |
| RelativeTargetName | unmapped[] | VERIFIED A-SEC-PAGES | path *within* the share |
| AccessMask | unmapped[] | VERIFIED A-SEC-PAGES | hex |
| AccessList | unmapped[] | VERIFIED A-SEC-PAGES | |
| AccessReason | unmapped[] | VERIFIED A-SEC-PAGES | allow/deny reason text — no field |

- **Traps:** 5145 is the **check** (pre-access), 5140 is the **access** — do not merge; `RelativeTargetName` distinguishes *which* file was checked; no `network.dst_port`; no Status field (outcome INFERRED as success when allow-audit fires).

### Security EID 5156 — wfp_connection_permitted

**MS page title:** "5156(S): The Windows Filtering Platform has permitted a connection." (A-SEC-PAGES)
**Classification:** category: `network` · type: `wfp_connection_permitted` · action: `permit` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| ProcessID | network.process.pid | VERIFIED A-SEC-PAGES | hex → int INFERRED, keep `$raw`; PID reuse trap |
| Application | network.process.exe | VERIFIED A-SEC-PAGES | full path of permitted process |
| Direction | network.direction | VERIFIED A-SEC-PAGES | INBOUND/OUTBOUND → `inbound`/`outbound` (INFERRED lowercase mapping; exact-case source value) |
| SourceAddress | network.src_ip | VERIFIED A-SEC-PAGES | |
| SourcePort | network.src_port | VERIFIED A-SEC-PAGES | int_or_state |
| DestAddress | network.dst_ip | VERIFIED A-SEC-PAGES | |
| DestPort | network.dst_port | VERIFIED A-SEC-PAGES | int_or_state |
| Protocol | network.protocol | VERIFIED A-SEC-PAGES | e.g. TCP/UDP — keep raw string |
| FilterRTID | unmapped[] | VERIFIED A-SEC-PAGES | rule id — no field |
| LayerName | unmapped[] | VERIFIED A-SEC-PAGES | WFP layer — no field (OPEN_QUESTIONS: wfp layer) |
| LayerRTID | unmapped[] | VERIFIED A-SEC-PAGES | |
| RemoteUserID | unmapped[] | VERIFIED A-SEC-PAGES | |
| RemoteMachineID | unmapped[] | VERIFIED A-SEC-PAGES | |

- **Traps:** `ProcessID` is the *endpoint* process (no GUID) — PID reuse; `Direction` source casing (`INBOUND`) ≠ schema enum casing (`inbound`) — normalize INFERRED; `FilterRTID`/`LayerRTID` are WFP internals — keep raw in `unmapped[]`; this is a *permit* event (5157 would be block — absent from scope).

### Security EID 5158 — wfp_bind_permitted

**MS page title:** "5158(S): The Windows Filtering Platform has permitted a bind to a local port." (A-SEC-PAGES)
**Classification:** category: `network` · type: `wfp_bind_permitted` · action: `permit` · outcome: `success` · severity: informational · derived_by: `source`

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| ProcessId | network.process.pid | VERIFIED A-SEC-PAGES | hex → int INFERRED, keep `$raw`; PID reuse trap — note casing `ProcessId` here vs `ProcessID` on 5156 |
| Application | network.process.exe | VERIFIED A-SEC-PAGES | |
| SourceAddress | network.src_ip | VERIFIED A-SEC-PAGES | local bind address |
| SourcePort | network.src_port | VERIFIED A-SEC-PAGES | local port bound |
| Protocol | network.protocol | VERIFIED A-SEC-PAGES | |
| FilterRTID | unmapped[] | VERIFIED A-SEC-PAGES | |
| LayerName | unmapped[] | VERIFIED A-SEC-PAGES | |
| LayerRTID | unmapped[] | VERIFIED A-SEC-PAGES | |

- **Traps:** bind ≠ connect — this is a listening-socket event; `SourceAddress`/`SourcePort` are **local** (bind target), not remote; no `DestAddress`/`DestPort`/`Direction` (absence is source-true); PID reuse; `ProcessId` casing differs from 5156's `ProcessID` — parsers must not assume uniform casing across 5156/5158 (VERIFIED A-SEC-PAGES).

### Security EID 4946 — firewall_rule_added

**MS page title:** "4946(S): A change has been made to Windows Firewall exception list. A rule was added." (A-SEC-PAGES)
**Classification:** category: `config_check` · type: `firewall_rule_added` · action: `add` · outcome: `success` · severity: informational · derived_by: `sentinel` (Sentinel classifies host-firewall rule mutation as `config_check`; Microsoft's own taxonomy is "Windows Firewall exception list change", not a config-check — the `check`/`source`/`observed` fields below are Sentinel's, hence `derived_by: sentinel` for the category/type/action)

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| ProfileChanged | config_check.observed | VERIFIED A-SEC-PAGES | profile bitmask/name the rule applies to (Domain/Private/Public) — kept as raw string; no dedicated firewall field in schema |
| RuleId | config_check.check | VERIFIED A-SEC-PAGES | firewall rule identifier — used as the check name; INFERRED choice (no `firewall.rule_id` field exists) |
| RuleName | config_check.source | VERIFIED A-SEC-PAGES | human-readable rule name — INFERRED choice for `source` (the object that was added); `check`/`source` semantics are Sentinel's mapping, not Microsoft's |

- **Unmapped / traps:** schema has **no dedicated `firewall` payload** — `config_check` (`category/check/expected/observed/source/status`) is the closest fit and all three field-name assignments into it are INFERRED; `status` is NOT carried by the event data (only in the `(S)` title marker) → emit `config_check.status: "pass"` for a successful add and leave `expected` absent (INFERRED, no expected-value field in the source). No `Subject*` fields here — the modifying principal is not in the event data; correlate by time/host to the governing 4688/4698 if needed. `RuleName` may be empty/`-` → `$state: "null"` (INFERRED).

### Security EID 4947 — firewall_rule_modified

**MS page title:** "4947(S): A change has been made to Windows Firewall exception list. A rule was modified." (A-SEC-PAGES)
**Classification:** category: `config_check` · type: `firewall_rule_modified` · action: `modify` · outcome: `success` · severity: informational · derived_by: `sentinel` (same rationale as 4946 — Sentinel's reinterpretation)

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| ProfileChanged | config_check.observed | VERIFIED A-SEC-PAGES | profile(s) the modification applies to — raw string |
| RuleId | config_check.check | VERIFIED A-SEC-PAGES | rule identifier (INFERRED assignment, as 4946) |
| RuleName | config_check.source | VERIFIED A-SEC-PAGES | rule name (INFERRED assignment, as 4946) |

- **Unmapped / traps:** same as 4946 — no dedicated firewall payload, no principal, no before/after values; a modification carries no `expected`/diff, so `config_check.expected` stays absent; correlate to 4946/4948 by `RuleId` for add→modify→delete lifecycle (INFERRED). Distinguish "modified rule contents" from "modified profile scope" only via the raw `ProfileChanged`/`RuleName` strings (INFERRED; no structured diff field).

### Security EID 4948 — firewall_rule_deleted

**MS page title:** "4948(S): A change has been made to Windows Firewall exception list. A rule was deleted." (A-SEC-PAGES)
**Classification:** category: `config_check` · type: `firewall_rule_deleted` · action: `delete` · outcome: `success` · severity: informational · derived_by: `sentinel` (same rationale as 4946)

| Source field (exact) | Canonical path | Evidence | Notes |
|---|---|---|---|
| ProfileChanged | config_check.observed | VERIFIED A-SEC-PAGES | profile(s) the deletion applies to — raw string |
| RuleId | config_check.check | VERIFIED A-SEC-PAGES | rule identifier (INFERRED assignment, as 4946) |
| RuleName | config_check.source | VERIFIED A-SEC-PAGES | rule name (INFERRED assignment, as 4946) |

- **Unmapped / traps:** same as 4946/4947 — deletion of a firewall exception is a high-signal host-config change; the event does not carry the rule's prior contents (no `expected`/diff); `RuleName`/`ProfileChanged` are the only post-facto context. Missing principal (no `Subject*`) → attribute via host+time correlation (INFERRED). Keep `RuleId` as the stable join key across the 4946/4947/4948 trio (INFERRED).

<!-- END SEC-A -->

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

---

## 3. Sigma Field-Mapping Pipelines

**Purpose (normative).** Sentinel detectors run over canonical events, not
raw Sigma-shaped records. SigmaHQ rules reference source-native field names
(`Image`, `CommandLine`, `ParentImage`, `TargetObject`, ...). The pipelines
below are **configuration data, not code**: each block declares, for one
Sigma `logsource`, the canonical `event.category` / `event.type` selector
and the field-name translation a rule-translation layer must apply before a
Sigma condition can be evaluated against canonical events. They are derived
from the `fields` inventories published with SigmaHQ rules at corpus pin
`8a4813404e` (A6-SIGMAHQ-INV), cross-checked against the source-mapping
tables in §2 (SEC-A/SEC-B). The YAML shape mirrors pySigma pipeline
structure (`logsource`, `name`, `field_mapping`) so it can later be adapted
to a pySigma backend without semantic change; pySigma itself is not a
runtime dependency of the detector path (Stage-1 D-004/D-008: Sigma
compatibility is a content-level goal, not a library dependency).

**Conventions.**
- `selector`: the canonical event filter (`event.category`, plus
  `event.type` list when a Sigma rule's logsource is narrower than the
  category).
- `field_mapping`: Sigma field name → canonical path (dotted). Absent
  target = no canonical equivalent; such Sigma fields must be matched
  against `raw`/`unmapped` by a documented fallback or the rule is
  translated with that condition dropped and flagged.
- `value_transform`: declarative value-level adjustments required before
  comparison (e.g. Sysmon `Hashes` is a `KEY=value,KEY=value` string;
  canonical stores `process.hashes.sha256` directly, so a rule matching
  `Hashes` with `| contains` on `SHA256=` must be rewritten to compare the
  scalar field). Described as data (`source_shape`, `target`, `rule_action`).
- All field names in `field_mapping` values are schema paths from
  `canonical_event_v1.schema.json` (§1).

```yaml
# sigma_field_mapping_pipelines.yaml
# Sentinel — Sigma-to-canonical field-mapping pipelines (config data, not code)
# schema: canonical-event/v1
# corpus_pin: SigmaHQ/sigma-rules @ 8a4813404ea3074890e0cda9272d4d1a8b2941d6
# cross_ref: stage-2 doc §2 mapping tables (SEC-A, SEC-B)
version: 1

pipelines:

  # ---------- Sysmon (Microsoft-Windows-Sysmon/Operational) ----------
  - id: sysmon_process_creation
    title: Sysmon process creation
    logsource:
      product: windows
      category: process_creation
      service: sysmon
    selector:
      event.category: process
      event.type: [process_create]
    field_mapping:
      UtcTime: time.original          # utc derived; timezone_source=source_documented_utc
      ProcessGuid: process.guid
      ProcessId: process.pid
      Image: process.exe
      CommandLine: process.command_line
      CurrentDirectory: process.current_dir
      User: process.owner_name        # often DOMAIN\user; SID unavailable in Sysmon User
      LogonGuid: process.logon_guid
      LogonId: process.logon_id
      TerminalSessionId: process.terminal_session_id
      IntegrityLevel: process.integrity_level
      OriginalFileName: process.original_file_name
      ParentProcessGuid: process.parent.guid
      ParentProcessId: process.parent.pid
      ParentImage: process.parent.exe
      ParentCommandLine: process.parent.command_line
      ParentUser: process.parent.owner_sid   # see SEC-A trap: Sysmon ParentUser may carry SID
      # FileVersion / Description / Product / Company -> unmapped[]
      # RuleName -> unmapped[] (noise)
    value_transform:
      - source_shape: "Hashes (KEY=value,KEY=value)"
        target: [process.hashes.md5, process.hashes.sha1, process.hashes.sha256, process.hashes.imphash, process.hashes.other]
        rule_action: split_kv_and_compare_scalar   # rules using 'Hashes contains SHA256=' → process.hashes.sha256 startswith
      - source_shape: "User (DOMAIN\\user or user@domain)"
        target: [process.owner_name]
        rule_action: compare_as_is                  # no SID expansion in pipeline; rules needing SID use enrichment

  - id: sysmon_registry
    title: Sysmon registry events
    logsource:
      product: windows
      category: registry_event
      service: sysmon
    selector:
      event.category: registry
      event.type: [registry_create, registry_set, registry_delete, registry_rename]
    field_mapping:
      UtcTime: time.original
      ProcessGuid: process.guid
      ProcessId: process.pid
      Image: process.exe
      TargetObject: registry.path
      Details: registry.data
      EventType: registry.operation   # createKey→create, setValue→set, deleteKey/deleteValue→delete, renameKey/renameValue→rename
    value_transform:
      - source_shape: "EventType literal strings (createKey|deleteKey|deleteValue|setValue|renameKey|renameValue)"
        target: registry.operation
        rule_action: map_to_enum
      - source_shape: "TargetObject full path (hive\\key\\value)"
        target: [registry.hive, registry.key, registry.value_name]
        rule_action: optional_derived_split        # parser may fill hive/key/value_name (inferred); path always present

  - id: sysmon_network
    title: Sysmon network connection
    logsource:
      product: windows
      category: network_connection
      service: sysmon
    selector:
      event.category: network
      event.type: [network_connection]
    field_mapping:
      UtcTime: time.original
      ProcessGuid: process.guid
      ProcessId: process.pid
      Image: process.exe
      Protocol: network.protocol
      SourceIp: network.src_ip
      SourcePort: network.src_port
      DestinationIp: network.dst_ip
      DestinationPort: network.dst_port
      SourceHostname: unmapped        # no schema home (Q2-xxx)
      DestinationHostname: unmapped
      Initiated: network.direction    # true→outbound, false→inbound (INFERRED mapping)
    value_transform:
      - source_shape: "Initiated boolean"
        target: network.direction
        rule_action: map_bool_to_direction_enum

  - id: sysmon_image_load
    title: Sysmon image (DLL) load
    logsource:
      product: windows
      category: image_load
      service: sysmon
    selector:
      event.category: image_load
      event.type: [image_load]
    field_mapping:
      UtcTime: time.original
      ProcessGuid: process.guid
      ProcessId: process.pid
      Image: process.exe
      ImageLoaded: image_load.image
      Signed: image_load.signature.signed
      Signature: image_load.signature.signer
      SignatureStatus: image_load.signature.status
    value_transform:
      - source_shape: "Hashes KEY=value string"
        target: [image_load.hashes.md5, image_load.hashes.sha1, image_load.hashes.sha256, image_load.hashes.imphash]
        rule_action: split_kv_and_compare_scalar

  - id: sysmon_file_create
    title: Sysmon file create
    logsource:
      product: windows
      category: file_event
      service: sysmon
    selector:
      event.category: file
      event.type: [file_create]
    field_mapping:
      UtcTime: time.original
      ProcessGuid: process.guid
      ProcessId: process.pid
      Image: process.exe
      TargetFilename: file.path
      CreationUtcTime: file.created

  - id: sysmon_pipe
    title: Sysmon named pipe create/connect
    logsource:
      product: windows
      category: pipe_created   # SigmaHQ also uses pipe_connected via filter; same category family
      service: sysmon
    selector:
      event.category: pipe
      event.type: [pipe_created, pipe_connected]
    field_mapping:
      UtcTime: time.original
      ProcessGuid: process.guid
      ProcessId: process.pid
      Image: process.exe
      PipeName: pipe.name

  - id: sysmon_wmi
    title: Sysmon WMI events (19/20/21)
    logsource:
      product: windows
      category: wmi_event
      service: sysmon
    selector:
      event.category: wmi
      event.type: [wmi_filter, wmi_consumer, wmi_binding]
    field_mapping:
      UtcTime: time.original
      Operation: wmi.operation
      Query: wmi.query
      # Consumer/Filter/Binding object details: see SEC-A EID 19/21 tables;
      # several sub-fields currently land in unmapped[] (Q2-xxx)

  - id: sysmon_ps_script
    title: Sysmon/PowerShell script block (EID 4104 via ps_script)
    logsource:
      product: windows
      category: ps_script
    selector:
      event.category: powershell
      event.type: [script_block]
    field_mapping:
      ScriptBlockText: powershell.script_block_text
      Path: powershell.script_path
      MessageNumber: powershell.message_number
      MessageTotal: powershell.message_total

  - id: sysmon_dns
    title: Sysmon DNS query (EID 22)
    logsource:
      product: windows
      category: dns_query
      service: sysmon
    selector:
      event.category: dns
      event.type: [dns_query]
    field_mapping:
      UtcTime: time.original
      ProcessGuid: process.guid
      ProcessId: process.pid
      Image: process.exe
      QueryName: dns.query_name
      QueryResults: dns.answers
      QueryStatus: dns.query_status

  # ---------- Windows Security channel ----------
  - id: security_auth
    title: Security logon/logoff/authorization
    logsource:
      product: windows
      service: security
    selector:
      event.category: authentication
    field_mapping:
      SubjectUserSid: user.sid
      SubjectUserName: user.name
      SubjectDomainName: user.domain
      SubjectLogonId: user.logon_id
      TargetUserSid: authentication.target_sid
      TargetUserName: authentication.target_name
      TargetDomainName: authentication.target_domain
      TargetLogonId: authentication.target_logon_id
      LogonType: authentication.logon_type
      LogonProcessName: unmapped          # schema wish: authentication.logon_process (Q2-xxx)
      AuthenticationPackageName: authentication.auth_package
      WorkstationName: authentication.workstation
      LogonGuid: authentication.logon_guid
      CallerProcessId: authentication.caller_process_id
      CallerProcessName: authentication.caller_process_name
      ElevatedToken: authentication.elev_token
      Status: authentication.status
      SubStatus: authentication.sub_status
      IpAddress: authentication.source_ip
      IpPort: unmapped                    # schema wish: authentication.source_port (Q2-xxx)
      KeyLength: authentication.key_length
    value_transform:
      - source_shape: "ElevatedToken (%16384 / true/false renderings — see SEC-A UNVERIFIED note)"
        target: authentication.elev_token
        rule_action: parse_documented_variants
      - source_shape: "LogonType numeric codes (2,3,4,5,7,8,9,10,11)"
        target: authentication.logon_type
        rule_action: compare_numeric

  - id: security_process
    title: Security process creation/termination (4688/4689)
    logsource:
      product: windows
      service: security
      category: process_creation
    selector:
      event.category: process
      event.type: [process_create, process_terminate]
    field_mapping:
      NewProcessName: process.exe
      ProcessId: process.pid
      ParentProcessName: process.parent.exe
      ParentProcessId: process.parent.pid
      CommandLine: process.command_line
      TokenElevationType: unmapped        # schema wish: process.token_elevation_type (Q2-xxx)
      MandatoryLabel: process.integrity_level
      SubjectUserSid: user.sid
      SubjectUserName: user.name
      SubjectDomainName: user.domain
      Status: process.exit_code           # schema wish exists? currently unmapped — see SEC-A EID 4689 table

  - id: security_share
    title: Security share access (5140/5145)
    logsource:
      product: windows
      service: security
      category: share_access   # SigmaHQ taxonomy
    selector:
      event.category: network
      event.type: [share_access, share_object_access]
    field_mapping:
      SubjectUserSid: user.sid
      SubjectUserName: user.name
      SubjectDomainName: user.domain
      IpAddress: network.src_ip
      IpPort: unmapped
      ShareName: unmapped        # schema wish: network.share_name (Q2-xxx)
      RelativeTargetName: file.path
      AccessMask: unmapped

  - id: security_wfp
    title: Security WFP packet/connection events (5156/5158)
    logsource:
      product: windows
      service: security
      category: firewall   # SigmaHQ taxonomy (netfilter/wfp family)
    selector:
      event.category: network
      event.type: [packet_filtered, connection_listening]
    field_mapping:
      ProcessId: process.pid
      Application: process.exe
      Direction: network.direction   # %%14592=inbound? verify per SEC-A UNVERIFIED note on %%-codes
      SourceAddress: network.src_ip
      SourcePort: network.src_port
      DestAddress: network.dst_ip
      DestPort: network.dst_port
      Protocol: network.protocol
      LayerName: unmapped
      LayerId: unmapped
      FilterRunTimeId: unmapped

  - id: security_account
    title: Security account/group changes (4720/4722/4724/4726/4728/4732/4738/4740/4756/4767)
    logsource:
      product: windows
      service: security
      category: user_account   # includes group_change family in SigmaHQ
    selector:
      event.category: [account, group_membership]
    field_mapping:
      TargetUserName: [account.name, group_membership.member_name]
      TargetDomainName: [account.domain, group_membership.domain]
      TargetSid: [account.sid, group_membership.member_sid]
      SubjectUserSid: user.sid
      SubjectUserName: user.name
      SubjectDomainName: user.domain
      MemberName: group_membership.member_name
      MemberSid: group_membership.member_sid
      SamAccountName: account.sam_account_name
      DisplayName: account.display_name
      UserPrincipalName: account.upn
      SidHistory: account.sid_history
      PasswordLastSet: unmapped
      AccountExpires: unmapped

  - id: security_service_task
    title: Security service install (4697) and scheduled task changes (4698/4946)
    logsource:
      product: windows
      service: security
      category: [service_install, scheduled_task]
    selector:
      event.category: [service, scheduled_task]
    field_mapping:
      ServiceName: service.name
      ServiceFileName: service.image_path
      ServiceType: service.service_type
      StartType: service.start_type
      ServiceAccount: service.account_name
      TaskName: scheduled_task.name
      TaskContent: scheduled_task.task_xml
      SubjectUserSid: user.sid
      SubjectUserName: user.name
      SubjectDomainName: user.domain

  # ---------- PowerShell ----------
  - id: powershell_operational
    title: PowerShell Operational script block / module logging (4103/4104)
    logsource:
      product: windows
      category: ps_module   # + ps_script pipeline above for 4104-class rules
      service: powershell
    selector:
      event.category: powershell
      event.type: [pipeline_execution_detail, script_block]
    field_mapping:
      ContextInfo: powershell.context_info
      UserData: powershell.payload
      Payload: powershell.payload
      ScriptBlockText: powershell.script_block_text
      ScriptBlockId: powershell.script_block_id
      Path: powershell.script_path
      MessageNumber: powershell.message_number
      MessageTotal: powershell.message_total

  - id: powershell_classic
    title: Classic Windows PowerShell log (400/403/600)
    logsource:
      product: windows
      category: ps_operation   # engine/provider state transitions
      service: powershell
    selector:
      event.category: powershell
      event.type: [engine_state_change, provider_state_change]
    field_mapping:
      # classic events carry UNNAMED <Data> elements + Key=Value detail blob;
      # parser extracts blob keys to canonical fields (SEC-B table):
      NewEngineState: powershell.engine_state
      PreviousEngineState: powershell.previous_engine_state
      HostName: powershell.host_name
      HostId: powershell.host_id
      HostVersion: powershell.host_version
      HostApplication: powershell.host_application
      EngineVersion: powershell.engine_version
      RunspaceId: powershell.runspace_id
      PipelineId: powershell.pipeline_id
      CommandName: powershell.command_name
      CommandType: powershell.command_type
      ScriptName: powershell.script_name
      CommandPath: powershell.command_path
      CommandLine: powershell.command_line
      ProviderName: powershell.provider_name
      NewProviderState: powershell.new_provider_state

  # ---------- Zeek (network sensor) ----------
  - id: zeek_conn
    title: Zeek conn.log
    logsource:
      product: zeek
      category: conn
    selector:
      event.category: network
      event.type: [connection]
    field_mapping:
      ts: time.original                # epoch float → utc derived, precision microsecond
      uid: network.uid
      id.orig_h: network.src_ip
      id.orig_p: network.src_port
      id.resp_h: network.dst_ip
      id.resp_p: network.dst_port
      proto: network.protocol
      service: unmapped                # schema wish: network.service (Q2-xxx)
      duration: network.duration
      orig_bytes: network.bytes_sent
      resp_bytes: network.bytes_received
      conn_state: network.state
      history: unmapped
      # localOrig/remoteOrig/missed_bytes/etc. -> unmapped[]

  - id: zeek_dns
    title: Zeek dns.log
    logsource:
      product: zeek
      category: dns
    selector:
      event.category: dns
      event.type: [dns_observed]
    field_mapping:
      ts: time.original
      uid: network.uid
      id.orig_h: network.src_ip
      id.resp_h: network.dst_ip
      query: dns.query_name
      qtype_name: dns.query_type
      rcode_name: dns.response_code
      answers: dns.answers

  - id: zeek_http
    title: Zeek http.log
    logsource:
      product: zeek
      category: http
    selector:
      event.category: http
      event.type: [http_transaction]
    field_mapping:
      ts: time.original
      uid: network.uid
      id.orig_h: network.src_ip
      id.resp_h: network.dst_ip
      method: http.method
      host: http.host
      uri: http.uri
      user_agent: http.user_agent
      referrer: http.referrer
      status_code: http.status_code
      resp_body_len: http.response_body_length
      request_body_len: http.request_body_length
      mime_type: http.mime_type

  - id: zeek_ssl
    title: Zeek ssl.log
    logsource:
      product: zeek
      category: ssl
    selector:
      event.category: tls
      event.type: [tls_handshake]
    field_mapping:
      ts: time.original
      uid: network.uid
      id.resp_h: network.dst_ip
      server_name: tls.sni          # Zeek server_name = SNI
      version: tls.version
      cipher: tls.cipher
      ja3: tls.ja3
      ja3s: tls.ja3s
      certificate_subject: tls.subject
      certificate_issuer: tls.issuer
      resumed: tls.resumed

  # ---------- Suricata EVE ----------
  - id: suricata_eve
    title: Suricata EVE JSON (flow + per-type payloads)
    logsource:
      product: suricata
      category: eve_json
    selector:
      event.category: [network, http, dns, tls, third_party_alert]
    field_mapping:
      timestamp: time.original
      flow_id: network.uid
      src_ip: network.src_ip
      src_port: network.src_port
      dest_ip: network.dst_ip
      dest_port: network.dst_port
      proto: network.protocol
      event_type: (drives selector narrowing; see SEC-B EVE table)
      http.method: http.method
      http.hostname: http.host
      http.url: http.uri
      http.user_agent: http.user_agent
      http.status: http.status_code
      dns.rrname: dns.query_name
      dns.rrtype: dns.query_type
      dns.rcode_name: dns.response_code
      dns.answers: dns.answers
      tls.sni: tls.sni
      tls.ja3: tls.ja3
      alert.signature: third_party_alert.rule_name
      alert.signature_id: third_party_alert.rule_id
      alert.category: third_party_alert.category
      alert.severity: third_party_alert.severity_raw
      alert.action: third_party_alert.mitigation

  # ---------- Windows Defender ----------
  - id: defender_operational
    title: Windows Defender detection/action (1116/1117)
    logsource:
      product: windows
      service: defender
    selector:
      event.category: third_party_alert
      event.type: [malware_detected, malware_action]
    field_mapping:
      "Threat Name": third_party_alert.rule_name
      "Threat ID": third_party_alert.rule_id
      "Category Name": third_party_alert.category
      "Severity Name": third_party_alert.severity_raw
      "Process Name": process.exe
      "Detection User": user.name
      Path: third_party_alert.observable
      "Action Name": third_party_alert.mitigation
      "Product Name": third_party_alert.product
      "Product Version": unmapped
      FWLink: unmapped
      # full 42-element table incl. Unused* placeholders: SEC-B §Defender

  # ---------- WMI-Activity ----------
  - id: wmi_activity
    title: WMI-Activity Operational (5857/5858/5860)
    logsource:
      product: windows
      service: wmi
    selector:
      event.category: wmi
      event.type: [wmi_operation, wmi_client_failure, wmi_temporary_ess]
    field_mapping:
      ProviderName: wmi.provider_name
      Code: wmi.result_code
      HostProcess: wmi.process.exe
      ProcessID: wmi.process.pid
      ProviderPath: unmapped
      Id: unmapped
      ClientMachine: wmi.client_machine
      User: wmi.client_user
      ClientProcessId: wmi.client_process_id
      Component: unmapped
      Operation: wmi.operation
      ResultCode: wmi.result_code
      PossibleCause: unmapped
      NamespaceName: wmi.namespace
      Query: wmi.query
      Processid: wmi.process.pid       # NOTE: lowercase 'd' element name (5860 only) — parser must match exactly

  # ---------- RDP (TerminalServices-LSM) ----------
  - id: rdp_lsm
    title: RDP session events (LSM 21-25/39)
    logsource:
      product: windows
      service: terminalservices
    selector:
      event.category: authentication
      event.type: [rdp_logon, rdp_logoff, rdp_shadow_notify, rdp_disconnect]
    field_mapping:
      User: user.name
      SessionID: authentication.logon_id   # INFERRED: SessionID used as logon/session identity (Q2-xxx)
      Address: authentication.source_ip    # literal 'LOCAL' for console
```

---

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

## 5. Example canonical events

*(Assembled from SEC-C — 121 examples, all validated against
`canonical_event_v1.schema.json` with Python `jsonschema` 4.26.0
`Draft202012Validator`; 0 errors, executed 2026-10-09.)*

Status: DRAFT for review. Each block below is a complete, self-contained
canonical event (schema_version `canonical-event/v1`) valid against
`canonical_event_v1.schema.json` (JSON Schema Draft 2020-12).

<!-- verification_log:
  C-SCHEMA: validated against canonical_event_v1.schema.json
  C-LOC: raw samples from _stage2_work/local_eventfields.json (local harvest)
  C-MAP-A: mappings follow _stage2_work/sec_sysmon_security.md (SEC-A)
  C-MAP-B: mappings follow _stage2_work/sec_network_exports.md (SEC-B)
  C-DFIR-LSM: LSM 21-39 semantics cross-checked via Microsoft docs / DFIR literature
-->

## Preamble

- Every example carries the full envelope: `schema_version`, `event`,
  `tenant_id`/`workspace_id`/`run_id` (`tenant-demo`/`ws-demo`/`run-2026-10-09-001`),
  `time`, `host`, `user`, `source`, `raw`, plus its category payload.
- Bare JSON `null` appears only for `time.utc` where the source has no
  usable timestamp; unknown/invalid values use state objects
  (`{"$state": ...}`) and never bare null.
- `unmapped` arrays list source fields with no canonical home — a field
  may appear there even when a partial mapping exists (e.g. Sysmon
  RuleName kept as noise).
- `raw` strings are shortened but real-shaped: EVTX single-quoted XML;
  local-harvest records slimmed via `slim_evtx` (Version/Level/Task/etc.
  dropped, provider Guid removed); Defender/4103/4104 EventData subsets
  noted per example cover comment. Abbreviations are noted in the cover.
- Secondary payloads (e.g. acting process on file/registry events) are
  included only where SEC-A/SEC-B explicitly map them; the category
  payload is always present.
- Examples labelled UNVERIFIED contain fields whose element names or
  semantics are not confirmed by a local sample or an authoritative
  reference (legacy Defender 1006-1012/1118/1119 not built; sc qc
  BINARY_PATH_NAME list UNVERIFIED per B-PRIOR; LSM labels diverge from
  SEC-B per Microsoft docs — see each cover comment).
- Divergences from SEC-B noted per example: AppLocker 8003/8004 map to
  `applocker_audit` (not SEC-B `applocker_block`); LSM 39 is disconnect-by-
  session; EID 24 → clipboard_change; EID 255 → sysmon_error sentinel.

## Example index

| ID | Title | Category | derived_by | Label |
|---|---|---|---|---|
| EX-SYSMON-1 | Process creation (Sysmon EID 1) | process | source | VERIFIED |
| EX-SYSMON-2 | File creation time change (Sysmon EID 2) | file | source | VERIFIED |
| EX-SYSMON-3 | Network connection (Sysmon EID 3) | network | source | VERIFIED |
| EX-SYSMON-4 | Sysmon service state change (Sysmon EID 4) | service | source | VERIFIED |
| EX-SYSMON-5 | Process terminated (Sysmon EID 5) | process | source | VERIFIED |
| EX-SYSMON-6 | Driver loaded (Sysmon EID 6) | driver | source | VERIFIED |
| EX-SYSMON-7 | Image loaded (Sysmon EID 7) | image_load | source | VERIFIED |
| EX-SYSMON-8 | CreateRemoteThread (Sysmon EID 8) | thread_access | source | VERIFIED |
| EX-SYSMON-9 | Raw device read (Sysmon EID 9) | file | sentinel | VERIFIED |
| EX-SYSMON-10 | Process accessed (Sysmon EID 10) | thread_access | source | VERIFIED |
| EX-SYSMON-11 | File created (Sysmon EID 11) | file | source | VERIFIED |
| EX-SYSMON-12 | Registry key created (Sysmon EID 12) | registry | source | VERIFIED |
| EX-SYSMON-13 | Registry value set (Sysmon EID 13) | registry | source | VERIFIED |
| EX-SYSMON-14 | Registry renamed (Sysmon EID 14) | registry | source | VERIFIED |
| EX-SYSMON-15 | File stream created (Sysmon EID 15) | file | source | VERIFIED |
| EX-SYSMON-16 | Sysmon configuration change (Sysmon EID 16) | config_check | sentinel | VERIFIED |
| EX-SYSMON-17 | Named pipe created (Sysmon EID 17) | pipe | source | VERIFIED |
| EX-SYSMON-18 | Named pipe connected (Sysmon EID 18) | pipe | source | VERIFIED |
| EX-SYSMON-19 | WMI filter created (Sysmon EID 19) | wmi | source | VERIFIED |
| EX-SYSMON-20 | WMI consumer created (Sysmon EID 20) | wmi | source | VERIFIED |
| EX-SYSMON-21 | WMI consumer bound to filter (Sysmon EID 21) | wmi | source | VERIFIED |
| EX-SYSMON-22 | DNS query (Sysmon EID 22) | dns | source | VERIFIED |
| EX-SYSMON-23 | File deleted and archived (Sysmon EID 23) | file | source | VERIFIED |
| EX-SYSMON-24 | Clipboard change (Sysmon EID 24) | process | sentinel | VERIFIED |
| EX-SYSMON-25 | Process tampering (Sysmon EID 25) | process | source | VERIFIED |
| EX-SYSMON-26 | File delete logged (Sysmon EID 26) | file | source | VERIFIED |
| EX-SYSMON-27 | Executable write blocked (Sysmon EID 27) | file | source | VERIFIED |
| EX-SYSMON-28 | File shredding blocked (Sysmon EID 28) | file | source | VERIFIED |
| EX-SYSMON-29 | Executable detected (Sysmon EID 29) | file | source | VERIFIED |
| EX-SYSMON-255 | Sysmon internal error (Sysmon EID 255) | third_party_alert | sentinel | UNVERIFIED |
| EX-SEC-1102 | Audit log cleared (Security EID 1102) | fim | sentinel | VERIFIED |
| EX-SEC-4624 | Logon success (Security EID 4624) | authentication | source | VERIFIED |
| EX-SEC-4625 | Logon failure (Security EID 4625) | authentication | source | VERIFIED |
| EX-SEC-4634 | Account logged off (Security EID 4634) | authentication | source | VERIFIED |
| EX-SEC-4647 | User-initiated logoff (Security EID 4647) | authentication | source | VERIFIED |
| EX-SEC-4648 | Explicit credential logon (Security EID 4648) | authentication | source | VERIFIED |
| EX-SEC-4672 | Special privileges assigned (Security EID 4672) | authentication | source | VERIFIED |
| EX-SEC-4688 | Process created (Security EID 4688) | process | source | VERIFIED |
| EX-SEC-4689 | Process exited (Security EID 4689) | process | source | VERIFIED |
| EX-SEC-4697 | Service installed (Security EID 4697) | service | source | VERIFIED |
| EX-SEC-4698 | Scheduled task created (Security EID 4698) | scheduled_task | source | VERIFIED |
| EX-SEC-4720 | User account created (Security EID 4720) | account | source | VERIFIED |
| EX-SEC-4722 | User account enabled (Security EID 4722) | account | source | VERIFIED |
| EX-SEC-4724 | Password reset attempted (Security EID 4724) | account | source | VERIFIED |
| EX-SEC-4726 | User account deleted (Security EID 4726) | account | source | VERIFIED |
| EX-SEC-4728 | Member added to global group (Security EID 4728) | group_membership | source | VERIFIED |
| EX-SEC-4732 | Member added to local group (Security EID 4732) | group_membership | source | VERIFIED |
| EX-SEC-4738 | User account changed (Security EID 4738) | account | source | VERIFIED |
| EX-SEC-4740 | Account locked out (Security EID 4740) | account | source | VERIFIED |
| EX-SEC-4756 | Member added to universal group (Security EID 4756) | group_membership | source | VERIFIED |
| EX-SEC-4767 | Account unlocked (Security EID 4767) | account | source | VERIFIED |
| EX-SEC-4768 | Kerberos TGT requested (Security EID 4768) | authentication | source | VERIFIED |
| EX-SEC-4769 | Kerberos service ticket requested (Security EID 4769) | authentication | source | VERIFIED |
| EX-SEC-4771 | Kerberos pre-auth failed (Security EID 4771) | authentication | source | VERIFIED |
| EX-SEC-4776 | Credential validation (Security EID 4776) | authentication | source | VERIFIED |
| EX-SEC-5140 | Network share accessed (Security EID 5140) | network | source | VERIFIED |
| EX-SEC-5145 | Network share access check (Security EID 5145) | network | source | VERIFIED |
| EX-SEC-5156 | WFP connection permitted (Security EID 5156) | network | source | VERIFIED |
| EX-SEC-5158 | WFP bind permitted (Security EID 5158) | network | source | VERIFIED |
| EX-SEC-4946 | Firewall rule added (Security EID 4946) | config_check | sentinel | VERIFIED |
| EX-SEC-4947 | Firewall rule modified (Security EID 4947) | config_check | sentinel | VERIFIED |
| EX-SEC-4948 | Firewall rule deleted (Security EID 4948) | config_check | sentinel | VERIFIED |
| EX-WIN-7034 | Service crashed (System EID 7034) | service | source | VERIFIED |
| EX-WIN-7036 | Service state change (System EID 7036) | service | source | VERIFIED |
| EX-WIN-7040 | Service start type changed (System EID 7040) | service | source | VERIFIED |
| EX-WIN-7043 | Service terminated unexpectedly (System EID 7043) | service | source | VERIFIED |
| EX-WIN-7045 | Service installed (System EID 7045) | service | source | VERIFIED |
| EX-WIN-104 | Event log cleared (System EID 104) | config_check | sentinel | UNVERIFIED |
| EX-WIN-PS400 | PowerShell engine started (Windows PowerShell EID 400) | powershell | source | VERIFIED |
| EX-WIN-PS403 | PowerShell engine stopped (Windows PowerShell EID 403) | powershell | source | VERIFIED |
| EX-WIN-PS600 | Provider started (Windows PowerShell EID 600) | powershell | source | VERIFIED |
| EX-WIN-PS800 | PowerShell pipeline executed (classic EID 800) | powershell | source | UNVERIFIED |
| EX-WIN-PS4103 | Module logging (PowerShell/Operational EID 4103) | powershell | source | VERIFIED |
| EX-WIN-PS4104 | Script block logging (PowerShell/Operational EID 4104) | powershell | source | VERIFIED |
| EX-WIN-PS4105 | Pipeline execution start (PowerShell/Operational EID 4105) | powershell | source | VERIFIED |
| EX-WIN-PS4106 | Pipeline execution stop (PowerShell/Operational EID 4106) | powershell | source | VERIFIED |
| EX-WIN-WMI5857 | WMI operation started (WMI-Activity EID 5857) | wmi | source | VERIFIED |
| EX-WIN-WMI5858 | WMI client failure (WMI-Activity EID 5858) | wmi | source | VERIFIED |
| EX-WIN-WMI5860 | WMI temporary ESS started (WMI-Activity EID 5860) | wmi | source | VERIFIED |
| EX-WIN-DEF1116 | Malware detected (Defender EID 1116) | third_party_alert | sentinel | VERIFIED |
| EX-WIN-DEF1117 | Malware action taken (Defender EID 1117) | file | sentinel | VERIFIED |
| EX-WIN-DEF5001 | Real-time protection disabled (Defender EID 5001) | config_check | sentinel | VERIFIED |
| EX-WIN-DEF5007 | Defender settings changed (Defender EID 5007) | config_check | source | VERIFIED |
| EX-WIN-TS106 | Task registered (TaskScheduler EID 106) | scheduled_task | source | UNVERIFIED |
| EX-WIN-TS140 | Task registration updated (TaskScheduler EID 140) | scheduled_task | source | UNVERIFIED |
| EX-WIN-TS141 | Task registration deleted (TaskScheduler EID 141) | scheduled_task | source | UNVERIFIED |
| EX-WIN-TS200 | Scheduled task executed (TaskScheduler EID 200) | scheduled_task | source | UNVERIFIED |
| EX-WIN-TS201 | Scheduled task completed (TaskScheduler EID 201) | scheduled_task | source | UNVERIFIED |
| EX-WIN-LSM21 | Session logon (LSM EID 21) | authentication | source | VERIFIED |
| EX-WIN-LSM22 | Shell start notification (LSM EID 22) | authentication | source | VERIFIED |
| EX-WIN-LSM23 | Session logoff (LSM EID 23) | authentication | source | VERIFIED |
| EX-WIN-LSM24 | Session disconnected (LSM EID 24) | authentication | source | VERIFIED |
| EX-WIN-LSM25 | Session reconnect (LSM EID 25) | authentication | source | VERIFIED |
| EX-WIN-LSM39 | Session disconnected by session (LSM EID 39) | authentication | source | VERIFIED |
| EX-WIN-RCM1149 | RDP pre-auth (RCM EID 1149) | authentication | sentinel | UNVERIFIED |
| EX-WIN-AL8003 | AppLocker audit allowed (AppLocker EID 8003) | config_check | sentinel | UNVERIFIED |
| EX-WIN-AL8004 | AppLocker audit blocked (AppLocker EID 8004) | config_check | sentinel | UNVERIFIED |
| EX-WIN-AL8006 | AppLocker enforce allowed (AppLocker EID 8006) | config_check | sentinel | UNVERIFIED |
| EX-WIN-AL8007 | AppLocker enforce blocked (AppLocker EID 8007) | config_check | sentinel | UNVERIFIED |
| EX-ZEEK-CONN | Zeek conn.log connection | network | source | VERIFIED |
| EX-ZEEK-DNS | Zeek dns.log query | dns | source | VERIFIED |
| EX-ZEEK-HTTP | Zeek http.log request | http | source | VERIFIED |
| EX-ZEEK-SSL | Zeek ssl.log handshake | tls | source | VERIFIED |
| EX-ZEEK-NOTICE | Zeek notice.log alert | third_party_alert | sentinel | VERIFIED |
| EX-ZEEK-FILES | Zeek files.log seen file | file | source | VERIFIED |
| EX-EVE-ALERT | Suricata EVE alert | third_party_alert | source | VERIFIED |
| EX-EVE-HTTP | Suricata EVE http | http | source | VERIFIED |
| EX-EVE-DNS | Suricata EVE dns | dns | source | VERIFIED |
| EX-EVE-TLS | Suricata EVE tls | tls | source | VERIFIED |
| EX-EVE-FLOW | Suricata EVE flow | network | source | VERIFIED |
| EX-EVE-FILEINFO | Suricata EVE fileinfo | file | source | VERIFIED |
| EX-NMAP-1 | Nmap XML scan result | config_check | sentinel | VERIFIED |
| EX-NETSTAT-1 | netstat -ano snapshot | config_check | sentinel | VERIFIED |
| EX-SCHTASKS-1 | schtasks /query snapshot | scheduled_task | sentinel | VERIFIED |
| EX-SCQUERY-1 | sc query snapshot | service | sentinel | VERIFIED |
| EX-SCQC-1 | sc qc snapshot | service | sentinel | UNVERIFIED |
| EX-REGEXPORT-1 | reg export .reg snapshot | registry | sentinel | VERIFIED |
| EX-EXPORTCSV-1 | Export-Csv process inventory | process | sentinel | VERIFIED |
| EX-AUTORUNS-1 | autorunsc autostart inventory | artifact | sentinel | VERIFIED |
| EX-SIGCHECK-1 | sigcheck file inventory | executable | sentinel | VERIFIED |
| EX-SIGCHECK-VT | sigcheck -vt VirusTotal result | artifact_finding | sentinel | VERIFIED |

## Sysmon (Microsoft-Windows-Sysmon/Operational) (30)

### EX-SYSMON-1 — Process creation (Sysmon EID 1)

<!-- covers: SEC-A Sysmon EID 1 process_create; RuleName/FileVersion/Description/Product/Company/HashType unmapped; ProcessID casing trap -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "process",
    "type": "process_create",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:00:00.000Z",
    "original": "2026-10-09 12:00:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-1",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 1,
    "record": {
      "type": "event_record",
      "record_id": 1024
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID><TimeCreated SystemTime='2026-10-09T12:00:00.000Z'/><EventRecordID>1024</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='FileVersion'>10.0.26100.1</Data><Data Name='Description'>Windows Command Processor</Data><Data Name='Product'>Microsoft Windows Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>Cmd.Exe</Data><Data Name='CommandLine'>cmd.exe /c whoami</Data><Data Name='CurrentDirectory'>C:\\Users\\jdoe\\</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='LogonGuid'>{9e8f7a6b-0002-0000-0000-000000000002}</Data><Data Name='LogonId'>0x3e7</Data><Data Name='TerminalSessionId'>1</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>SHA256=aa11bb22cc33dd44ee55ff6677889900aabbccddeeff00112233445566778899,MD5=11223344556677889900aabbccddeeff</Data><Data Name='ParentProcessGuid'>{1a2b3c4d-0000-0000-0000-000000000000}</Data><Data Name='ParentProcessId'>1204</Data><Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data><Data Name='ParentCommandLine'>C:\\Windows\\explorer.exe</Data><Data Name='ParentUser'>S-1-5-21-1000-2000-3000-1001</Data></EventData></Event>",
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "command_line": "cmd.exe /c whoami",
    "current_dir": "C:\\Users\\jdoe\\",
    "integrity_level": "Medium",
    "logon_guid": "{9e8f7a6b-0002-0000-0000-000000000002}",
    "logon_id": "0x3e7",
    "terminal_session_id": 1,
    "original_file_name": "Cmd.Exe",
    "hashes": {
      "sha256": "aa11bb22cc33dd44ee55ff6677889900aabbccddeeff00112233445566778899",
      "md5": "11223344556677889900aabbccddeeff"
    },
    "parent": {
      "guid": "{1a2b3c4d-0000-0000-0000-000000000000}",
      "pid": 1204,
      "exe": "C:\\Windows\\explorer.exe",
      "name": "explorer.exe",
      "command_line": "C:\\Windows\\explorer.exe",
      "owner_sid": "S-1-5-21-1000-2000-3000-1001"
    }
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "FileVersion",
      "value": "10.0.26100.1"
    },
    {
      "name": "Description",
      "value": "Windows Command Processor"
    },
    {
      "name": "Product",
      "value": "Microsoft Windows Operating System"
    },
    {
      "name": "Company",
      "value": "Microsoft Corporation"
    }
  ]
}
```

### EX-SYSMON-2 — File creation time change (Sysmon EID 2)

<!-- covers: SEC-A Sysmon EID 2 file_creation_time_change; PreviousCreationUtcTime unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_creation_time_change",
    "action": "change",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:01:00.000Z",
    "original": "2026-10-09 12:01:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-2",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 2,
    "record": {
      "type": "event_record",
      "record_id": 1025
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>2</EventID><TimeCreated SystemTime='2026-10-09T12:01:00.000Z'/><EventRecordID>1025</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='TargetFilename'>C:\\Users\\jdoe\\Documents\\report.pdf</Data><Data Name='CreationUtcTime'>2026-10-09 09:15:00.000</Data><Data Name='PreviousCreationUtcTime'>2026-10-01 11:00:00.000</Data></EventData></Event>",
  "file": {
    "path": "C:\\Users\\jdoe\\Documents\\report.pdf",
    "name": "report.pdf",
    "directory": "C:\\Users\\jdoe\\Documents",
    "created": "2026-10-09T09:15:00Z"
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "PreviousCreationUtcTime",
      "value": "2026-10-01 11:00:00.000"
    }
  ]
}
```

### EX-SYSMON-3 — Network connection (Sysmon EID 3)

<!-- covers: SEC-A Sysmon EID 3 network_connection; Initiated→direction INFERRED; hostnames/port names unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "network",
    "type": "network_connection",
    "action": "connect",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:02:00.000Z",
    "original": "2026-10-09 12:02:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-3",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 3,
    "record": {
      "type": "event_record",
      "record_id": 1026
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>3</EventID><TimeCreated SystemTime='2026-10-09T12:02:00.000Z'/><EventRecordID>1026</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='Protocol'>tcp</Data><Data Name='Initiated'>true</Data><Data Name='SourceIsIpv6'>false</Data><Data Name='SourceIp'>10.10.5.23</Data><Data Name='SourceHostname'>WS-DEMO01.corp.local</Data><Data Name='SourcePort'>51514</Data><Data Name='SourcePortName'>-</Data><Data Name='DestinationIsIpv6'>false</Data><Data Name='DestinationIp'>93.184.216.34</Data><Data Name='DestinationHostname'>example.com</Data><Data Name='DestinationPort'>443</Data><Data Name='DestinationPortName'>https</Data></EventData></Event>",
  "network": {
    "protocol": "tcp",
    "direction": {
      "$state": "inferred",
      "$note": "mapped from Initiated=true"
    },
    "src_ip": "10.10.5.23",
    "src_port": 51514,
    "dst_ip": "93.184.216.34",
    "dst_port": 443
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "SourceIsIpv6",
      "value": "false"
    },
    {
      "name": "DestinationIsIpv6",
      "value": "false"
    },
    {
      "name": "SourceHostname",
      "value": "WS-DEMO01.corp.local"
    },
    {
      "name": "DestinationHostname",
      "value": "example.com"
    },
    {
      "name": "SourcePortName",
      "value": "-"
    },
    {
      "name": "DestinationPortName",
      "value": "https"
    }
  ]
}
```

### EX-SYSMON-4 — Sysmon service state change (Sysmon EID 4)

<!-- covers: SEC-A Sysmon EID 4 sysmon_service_state_change; Version/SchemaVersion unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "service",
    "type": "sysmon_service_state_change",
    "action": "stop",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:03:00.000Z",
    "original": "2026-10-09 12:03:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sysmon-4",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 4,
    "record": {
      "type": "event_record",
      "record_id": 1027
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>4</EventID><TimeCreated SystemTime='2026-10-09T12:03:00.000Z'/><EventRecordID>1027</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='UtcTime'>2026-10-09 12:03:00.000</Data><Data Name='State'>Stopped</Data><Data Name='Version'>15.01</Data><Data Name='SchemaVersion'>4.90</Data></EventData></Event>",
  "service": {
    "name": "Sysmon64",
    "state": "Stopped"
  },
  "unmapped": [
    {
      "name": "Version",
      "value": "15.01"
    },
    {
      "name": "SchemaVersion",
      "value": "4.90"
    }
  ]
}
```

### EX-SYSMON-5 — Process terminated (Sysmon EID 5)

<!-- covers: SEC-A Sysmon EID 5 process_terminate; join to EID 1 via ProcessGuid -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "process",
    "type": "process_terminate",
    "action": "terminate",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:03:30.000Z",
    "original": "2026-10-09 12:03:30.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-5",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 5,
    "record": {
      "type": "event_record",
      "record_id": 1028
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>5</EventID><TimeCreated SystemTime='2026-10-09T12:03:30.000Z'/><EventRecordID>1028</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>CORP\\jdoe</Data></EventData></Event>",
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-6 — Driver loaded (Sysmon EID 6)

<!-- covers: SEC-A Sysmon EID 6 driver_load; Hashes/Signed/Signature/SignatureStatus→secondary executable payload -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "driver",
    "type": "driver_load",
    "action": "load",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:04:00.000Z",
    "original": "2026-10-09 12:04:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sysmon-6",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 6,
    "record": {
      "type": "event_record",
      "record_id": 1029
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>6</EventID><TimeCreated SystemTime='2026-10-09T12:04:00.000Z'/><EventRecordID>1029</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='ImageLoaded'>C:\\Windows\\System32\\drivers\\mydrv.sys</Data><Data Name='Hashes'>SHA256=bb22cc33dd44ee55ff6677889900aabbccddeeff11223344556677889900aabbcc,MD5=22334455667788990011aabbccddeeff</Data><Data Name='Signed'>true</Data><Data Name='Signature'>Microsoft Windows</Data><Data Name='SignatureStatus'>Valid</Data></EventData></Event>",
  "driver": {
    "name": "mydrv.sys",
    "image_path": "C:\\Windows\\System32\\drivers\\mydrv.sys",
    "state": {
      "$state": "inferred",
      "$note": "operation 'load' has no driver.operation enum value; state inferred from load event"
    }
  },
  "executable": {
    "path": "C:\\Windows\\System32\\drivers\\mydrv.sys",
    "format": "pe",
    "hashes": {
      "sha256": "bb22cc33dd44ee55ff6677889900aabbccddeeff11223344556677889900aabbcc",
      "md5": "22334455667788990011aabbccddeeff"
    },
    "signature": {
      "signed": true,
      "signer": "Microsoft Windows",
      "status": "Valid"
    }
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-7 — Image loaded (Sysmon EID 7)

<!-- covers: SEC-A Sysmon EID 7 image_load; FileVersion/Description/Product/Company/OriginalFileName unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "image_load",
    "type": "image_load",
    "action": "load",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:05:00.000Z",
    "original": "2026-10-09 12:05:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-7",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 7,
    "record": {
      "type": "event_record",
      "record_id": 1030
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>7</EventID><TimeCreated SystemTime='2026-10-09T12:05:00.000Z'/><EventRecordID>1030</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='ImageLoaded'>C:\\Windows\\System32\\amsi.dll</Data><Data Name='FileVersion'>10.0.26100.1</Data><Data Name='Description'>Antimalware Scan Interface</Data><Data Name='Product'>Microsoft Windows Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>amsi.dll</Data><Data Name='Hashes'>SHA256=cc33dd44ee55ff6677889900aabbccddeeff11223344556677889900aabbccdd</Data><Data Name='Signed'>true</Data><Data Name='Signature'>Microsoft Windows</Data><Data Name='SignatureStatus'>Valid</Data></EventData></Event>",
  "image_load": {
    "image": "C:\\Windows\\System32\\amsi.dll",
    "process": {
      "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
      "pid": 4521,
      "exe": "C:\\Windows\\System32\\cmd.exe",
      "owner_name": "jdoe"
    },
    "hashes": {
      "sha256": "cc33dd44ee55ff6677889900aabbccddeeff11223344556677889900aabbccdd"
    },
    "signature": {
      "signed": true,
      "signer": "Microsoft Windows",
      "status": "Valid"
    }
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "FileVersion",
      "value": "10.0.26100.1"
    },
    {
      "name": "Description",
      "value": "Antimalware Scan Interface"
    },
    {
      "name": "Product",
      "value": "Microsoft Windows Operating System"
    },
    {
      "name": "Company",
      "value": "Microsoft Corporation"
    },
    {
      "name": "OriginalFileName",
      "value": "amsi.dll"
    }
  ]
}
```

### EX-SYSMON-8 — CreateRemoteThread (Sysmon EID 8)

<!-- covers: SEC-A Sysmon EID 8 create_remote_thread; NewThreadId/StartAddress/StartModule/StartFunction unmapped; empty StartModule/StartFunction→null state -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "thread_access",
    "type": "create_remote_thread",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:06:00.000Z",
    "original": "2026-10-09 12:06:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-8",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 8,
    "record": {
      "type": "event_record",
      "record_id": 1031
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>8</EventID><TimeCreated SystemTime='2026-10-09T12:06:00.000Z'/><EventRecordID>1031</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='SourceProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='SourceProcessId'>4521</Data><Data Name='SourceImage'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='SourceUser'>CORP\\jdoe</Data><Data Name='TargetProcessGuid'>{1a2b3c4d-0002-0000-0000-000000000002}</Data><Data Name='TargetProcessId'>6788</Data><Data Name='TargetImage'>C:\\Windows\\System32\\notepad.exe</Data><Data Name='TargetUser'>CORP\\jdoe</Data><Data Name='NewThreadId'>9012</Data><Data Name='StartAddress'>0x0000000000401000</Data><Data Name='StartModule'/><Data Name='StartFunction'/></EventData></Event>",
  "thread_access": {
    "source_process": {
      "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
      "pid": 4521,
      "exe": "C:\\Windows\\System32\\cmd.exe",
      "owner_name": "jdoe"
    },
    "target_process": {
      "guid": "{1a2b3c4d-0002-0000-0000-000000000002}",
      "pid": 6788,
      "exe": "C:\\Windows\\System32\\notepad.exe",
      "owner_name": "jdoe"
    }
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "NewThreadId",
      "value": "9012"
    },
    {
      "name": "StartAddress",
      "value": "0x0000000000401000"
    },
    {
      "name": "StartModule",
      "value": {
        "$state": "null",
        "$note": "documented may-be-empty per MS docs"
      }
    },
    {
      "name": "StartFunction",
      "value": {
        "$state": "null",
        "$note": "documented may-be-empty per MS docs"
      }
    }
  ]
}
```

### EX-SYSMON-9 — Raw device read (Sysmon EID 9)

<!-- covers: SEC-A Sysmon EID 9 raw_device_read; derived_by sentinel (Device→file.path) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "raw_device_read",
    "action": "read",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:07:00.000Z",
    "original": "2026-10-09 12:07:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-9",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 9,
    "record": {
      "type": "event_record",
      "record_id": 1032
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>9</EventID><TimeCreated SystemTime='2026-10-09T12:07:00.000Z'/><EventRecordID>1032</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='Device'>\\\\.\\PhysicalDrive0</Data></EventData></Event>",
  "file": {
    "path": {
      "$state": "inferred",
      "$note": "Device path mapped to file.path by Sentinel",
      "$raw": "\\\\.\\PhysicalDrive0"
    }
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-10 — Process accessed (Sysmon EID 10)

<!-- covers: SEC-A Sysmon EID 10 process_access; SourceThreadId unmapped; GUID casing trap -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "thread_access",
    "type": "process_access",
    "action": "access",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:08:00.000Z",
    "original": "2026-10-09 12:08:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-10",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 10,
    "record": {
      "type": "event_record",
      "record_id": 1033
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>10</EventID><TimeCreated SystemTime='2026-10-09T12:08:00.000Z'/><EventRecordID>1033</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='SourceProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='SourceProcessId'>4521</Data><Data Name='SourceThreadId'>9012</Data><Data Name='SourceImage'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='SourceUser'>CORP\\jdoe</Data><Data Name='TargetProcessGuid'>{1a2b3c4d-0003-0000-0000-000000000003}</Data><Data Name='TargetProcessId'>777</Data><Data Name='TargetImage'>C:\\Windows\\System32\\lsass.exe</Data><Data Name='TargetUser'>NT AUTHORITY\\SYSTEM</Data><Data Name='GrantedAccess'>0x1010</Data><Data Name='CallTrace'>C:\\Windows\\System32\\cmd.exe+0x1a2b3|ntdll.dll+0x9f876</Data></EventData></Event>",
  "thread_access": {
    "source_process": {
      "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
      "pid": 4521,
      "exe": "C:\\Windows\\System32\\cmd.exe",
      "owner_name": "jdoe"
    },
    "target_process": {
      "guid": "{1a2b3c4d-0003-0000-0000-000000000003}",
      "pid": 777,
      "exe": "C:\\Windows\\System32\\lsass.exe",
      "owner_name": "SYSTEM"
    },
    "access_mask": "0x1010",
    "call_trace": "C:\\Windows\\System32\\cmd.exe+0x1a2b3|ntdll.dll+0x9f876"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "SourceThreadId",
      "value": "9012"
    }
  ]
}
```

### EX-SYSMON-11 — File created (Sysmon EID 11)

<!-- covers: SEC-A Sysmon EID 11 file_create -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_create",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:09:00.000Z",
    "original": "2026-10-09 12:09:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-11",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 11,
    "record": {
      "type": "event_record",
      "record_id": 1034
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>11</EventID><TimeCreated SystemTime='2026-10-09T12:09:00.000Z'/><EventRecordID>1034</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='TargetFilename'>C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe</Data><Data Name='CreationUtcTime'>2026-10-09 12:09:00.000</Data></EventData></Event>",
  "file": {
    "path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe",
    "name": "payload.exe",
    "directory": "C:\\Users\\jdoe\\AppData\\Local\\Temp",
    "created": "2026-10-09T12:09:00Z"
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-12 — Registry key created (Sysmon EID 12)

<!-- covers: SEC-A Sysmon EID 12 registry_object_create_delete; EventType literal UNVERIFIED; hive/key/value split INFERRED -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "registry",
    "type": "registry_object_create_delete",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:10:00.000Z",
    "original": "2026-10-09 12:10:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-12",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 12,
    "record": {
      "type": "event_record",
      "record_id": 1035
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>12</EventID><TimeCreated SystemTime='2026-10-09T12:10:00.000Z'/><EventRecordID>1035</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>CreateKey</Data><Data Name='UtcTime'>2026-10-09 12:10:00.000</Data><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\reg.exe</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='TargetObject'>HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater</Data></EventData></Event>",
  "registry": {
    "path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
    "hive": "HKLM",
    "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "value_name": "Updater",
    "operation": "create"
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\reg.exe",
    "name": "reg.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-13 — Registry value set (Sysmon EID 13)

<!-- covers: SEC-A Sysmon EID 13 registry_value_set; value_type absent (do not infer) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "registry",
    "type": "registry_value_set",
    "action": "set",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:11:00.000Z",
    "original": "2026-10-09 12:11:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-13",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 13,
    "record": {
      "type": "event_record",
      "record_id": 1036
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>13</EventID><TimeCreated SystemTime='2026-10-09T12:11:00.000Z'/><EventRecordID>1036</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>SetValue</Data><Data Name='UtcTime'>2026-10-09 12:11:00.000</Data><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\reg.exe</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='TargetObject'>HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater</Data><Data Name='Details'>C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe</Data></EventData></Event>",
  "registry": {
    "path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
    "hive": "HKLM",
    "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "value_name": "Updater",
    "data": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe",
    "operation": "set"
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\reg.exe",
    "name": "reg.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-14 — Registry renamed (Sysmon EID 14)

<!-- covers: SEC-A Sysmon EID 14 registry_rename; NewName unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "registry",
    "type": "registry_rename",
    "action": "rename",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:12:00.000Z",
    "original": "2026-10-09 12:12:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-14",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 14,
    "record": {
      "type": "event_record",
      "record_id": 1037
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>14</EventID><TimeCreated SystemTime='2026-10-09T12:12:00.000Z'/><EventRecordID>1037</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>RenameKey</Data><Data Name='UtcTime'>2026-10-09 12:12:00.000</Data><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\reg.exe</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='TargetObject'>HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OldName</Data><Data Name='Details'>-</Data><Data Name='NewName'>NewName</Data></EventData></Event>",
  "registry": {
    "path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OldName",
    "hive": "HKLM",
    "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "value_name": "OldName",
    "operation": "rename"
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\reg.exe",
    "name": "reg.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "NewName",
      "value": "NewName"
    }
  ]
}
```

### EX-SYSMON-15 — File stream created (Sysmon EID 15)

<!-- covers: SEC-A Sysmon EID 15 file_stream_create; stream suffix kept lossless; Hash→hashes.other; Contents unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_stream_create",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:13:00.000Z",
    "original": "2026-10-09 12:13:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-15",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 15,
    "record": {
      "type": "event_record",
      "record_id": 1038
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>15</EventID><TimeCreated SystemTime='2026-10-09T12:13:00.000Z'/><EventRecordID>1038</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='TargetFilename'>C:\\Users\\jdoe\\Downloads\\doc.docx:Zone.Identifier</Data><Data Name='CreationUtcTime'>2026-10-09 12:13:00.000</Data><Data Name='Hash'>dd44ee55ff6677889900aabbccddeeff11223344556677889900aabbccdd44ee5</Data><Data Name='Contents'>cc55dd66ee77ff889900aabbccddeeff11223344556677889900aabbccdd</Data></EventData></Event>",
  "file": {
    "path": "C:\\Users\\jdoe\\Downloads\\doc.docx:Zone.Identifier",
    "name": "doc.docx:Zone.Identifier",
    "directory": "C:\\Users\\jdoe\\Downloads",
    "created": "2026-10-09T12:13:00Z",
    "hashes": {
      "other": "dd44ee55ff6677889900aabbccddeeff11223344556677889900aabbccdd44ee5"
    }
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "Contents",
      "value": "cc55dd66ee77ff889900aabbccddeeff11223344556677889900aabbccdd"
    }
  ]
}
```

### EX-SYSMON-16 — Sysmon configuration change (Sysmon EID 16)

<!-- covers: SEC-A Sysmon EID 16 sysmon_config_change; derived_by sentinel; ConfigurationFileHash unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "sysmon_config_change",
    "action": "change",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:14:00.000Z",
    "original": "2026-10-09 12:14:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sysmon-16",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 16,
    "record": {
      "type": "event_record",
      "record_id": 1039
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>16</EventID><TimeCreated SystemTime='2026-10-09T12:14:00.000Z'/><EventRecordID>1039</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='Configuration'>Sysmon64.exe -c C:\\Windows\\config.xml</Data><Data Name='ConfigurationFileHash'>SHA256=ee66ff77889900aabbccddeeff11223344556677889900aabbccddeeff667788</Data></EventData></Event>",
  "config_check": {
    "check": "sysmon_configuration",
    "observed": "Sysmon64.exe -c C:\\Windows\\config.xml"
  },
  "unmapped": [
    {
      "name": "ConfigurationFileHash",
      "value": "SHA256=ee66ff77889900aabbccddeeff11223344556677889900aabbccddeeff667788"
    }
  ]
}
```

### EX-SYSMON-17 — Named pipe created (Sysmon EID 17)

<!-- covers: SEC-A Sysmon EID 17 pipe_create; PipeName lossless with prefix -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "pipe",
    "type": "pipe_create",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:15:00.000Z",
    "original": "2026-10-09 12:15:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-17",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 17,
    "record": {
      "type": "event_record",
      "record_id": 1040
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>17</EventID><TimeCreated SystemTime='2026-10-09T12:15:00.000Z'/><EventRecordID>1040</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>CreatePipe</Data><Data Name='UtcTime'>2026-10-09 12:15:00.000</Data><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='PipeName'>\\testpipe</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>CORP\\jdoe</Data></EventData></Event>",
  "pipe": {
    "name": "\\testpipe",
    "operation": "create"
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-18 — Named pipe connected (Sysmon EID 18)

<!-- covers: SEC-A Sysmon EID 18 pipe_connect -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "pipe",
    "type": "pipe_connect",
    "action": "connect",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:16:00.000Z",
    "original": "2026-10-09 12:16:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-18",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 18,
    "record": {
      "type": "event_record",
      "record_id": 1041
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>18</EventID><TimeCreated SystemTime='2026-10-09T12:16:00.000Z'/><EventRecordID>1041</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>ConnectPipe</Data><Data Name='UtcTime'>2026-10-09 12:16:00.000</Data><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0002-0000-0000-000000000002}</Data><Data Name='ProcessId'>6788</Data><Data Name='PipeName'>\\testpipe</Data><Data Name='Image'>C:\\Windows\\System32\\notepad.exe</Data><Data Name='User'>CORP\\jdoe</Data></EventData></Event>",
  "pipe": {
    "name": "\\testpipe",
    "operation": "connect"
  },
  "process": {
    "guid": "{1a2b3c4d-0002-0000-0000-000000000002}",
    "pid": 6788,
    "exe": "C:\\Windows\\System32\\notepad.exe",
    "name": "notepad.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-19 — WMI filter created (Sysmon EID 19)

<!-- covers: SEC-A Sysmon EID 19 wmi_filter_create; Name/Type/Destination/Consumer/Filter/EventType unmapped; no process payload -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "wmi",
    "type": "wmi_filter_create",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:17:00.000Z",
    "original": "2026-10-09 12:17:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-19",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 19,
    "record": {
      "type": "event_record",
      "record_id": 1042
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>19</EventID><TimeCreated SystemTime='2026-10-09T12:17:00.000Z'/><EventRecordID>1042</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>WmiFilterCreate</Data><Data Name='UtcTime'>2026-10-09 12:17:00.000</Data><Data Name='Operation'>Created</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='EventNamespace'>root\\subscription</Data><Data Name='Name'>EvilFilter</Data><Data Name='Query'>SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Process'</Data><Data Name='Type'>WQL</Data><Data Name='Destination'>-</Data><Data Name='Consumer'>-</Data><Data Name='Filter'>-</Data><Data Name='RuleName'>-</Data></EventData></Event>",
  "wmi": {
    "operation": "Created",
    "namespace": "root\\subscription",
    "client_user": "CORP\\jdoe",
    "query": "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Process'"
  },
  "unmapped": [
    {
      "name": "EventType",
      "value": "WmiFilterCreate"
    },
    {
      "name": "Name",
      "value": "EvilFilter"
    },
    {
      "name": "Type",
      "value": "WQL"
    },
    {
      "name": "Destination",
      "value": "-"
    },
    {
      "name": "Consumer",
      "value": "-"
    },
    {
      "name": "Filter",
      "value": "-"
    },
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-20 — WMI consumer created (Sysmon EID 20)

<!-- covers: SEC-A Sysmon EID 20 wmi_consumer_create; Name/Type/Destination unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "wmi",
    "type": "wmi_consumer_create",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:18:00.000Z",
    "original": "2026-10-09 12:18:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-20",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 20,
    "record": {
      "type": "event_record",
      "record_id": 1043
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>20</EventID><TimeCreated SystemTime='2026-10-09T12:18:00.000Z'/><EventRecordID>1043</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>WmiConsumerCreate</Data><Data Name='UtcTime'>2026-10-09 12:18:00.000</Data><Data Name='Operation'>Created</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='EventNamespace'>root\\subscription</Data><Data Name='Name'>EvilConsumer</Data><Data Name='Type'>Command Line</Data><Data Name='Destination'>C:\\Windows\\System32\\cmd.exe /c calc.exe</Data><Data Name='Consumer'>-</Data><Data Name='Filter'>-</Data><Data Name='Query'>-</Data><Data Name='RuleName'>-</Data></EventData></Event>",
  "wmi": {
    "operation": "Created",
    "namespace": "root\\subscription",
    "client_user": "CORP\\jdoe"
  },
  "unmapped": [
    {
      "name": "EventType",
      "value": "WmiConsumerCreate"
    },
    {
      "name": "Name",
      "value": "EvilConsumer"
    },
    {
      "name": "Type",
      "value": "Command Line"
    },
    {
      "name": "Destination",
      "value": "C:\\Windows\\System32\\cmd.exe /c calc.exe"
    },
    {
      "name": "Consumer",
      "value": "-"
    },
    {
      "name": "Filter",
      "value": "-"
    },
    {
      "name": "Query",
      "value": "-"
    },
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-21 — WMI consumer bound to filter (Sysmon EID 21)

<!-- covers: SEC-A Sysmon EID 21 wmi_consumer_filter_bind; Consumer/Filter unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "wmi",
    "type": "wmi_consumer_filter_bind",
    "action": "bind",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:19:00.000Z",
    "original": "2026-10-09 12:19:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-21",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 21,
    "record": {
      "type": "event_record",
      "record_id": 1044
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>21</EventID><TimeCreated SystemTime='2026-10-09T12:19:00.000Z'/><EventRecordID>1044</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>WmiConsumerToFilter</Data><Data Name='UtcTime'>2026-10-09 12:19:00.000</Data><Data Name='Operation'>Created</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='EventNamespace'>root\\subscription</Data><Data Name='Name'>EvilConsumer</Data><Data Name='Consumer'>CommandLineEventConsumer.Name=\"EvilConsumer\"</Data><Data Name='Filter'>__EventFilter.Name=\"EvilFilter\"</Data><Data Name='Type'>-</Data><Data Name='Destination'>-</Data><Data Name='Query'>-</Data><Data Name='RuleName'>-</Data></EventData></Event>",
  "wmi": {
    "operation": "Created",
    "namespace": "root\\subscription",
    "client_user": "CORP\\jdoe"
  },
  "unmapped": [
    {
      "name": "EventType",
      "value": "WmiConsumerToFilter"
    },
    {
      "name": "Name",
      "value": "EvilConsumer"
    },
    {
      "name": "Consumer",
      "value": "CommandLineEventConsumer.Name=\"EvilConsumer\""
    },
    {
      "name": "Filter",
      "value": "__EventFilter.Name=\"EvilFilter\""
    },
    {
      "name": "Type",
      "value": "-"
    },
    {
      "name": "Destination",
      "value": "-"
    },
    {
      "name": "Query",
      "value": "-"
    },
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-22 — DNS query (Sysmon EID 22)

<!-- covers: SEC-A Sysmon EID 22 dns_query; QueryStatus 0→success; QueryResults→answers INFERRED -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "dns",
    "type": "dns_query",
    "action": "query",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:20:00.000Z",
    "original": "2026-10-09 12:20:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-22",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 22,
    "record": {
      "type": "event_record",
      "record_id": 1045
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>22</EventID><TimeCreated SystemTime='2026-10-09T12:20:00.000Z'/><EventRecordID>1045</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-10-09 12:20:00.000</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='QueryName'>example.com</Data><Data Name='QueryStatus'>0</Data><Data Name='QueryResults'>93.184.216.34;</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>CORP\\jdoe</Data></EventData></Event>",
  "dns": {
    "query_name": "example.com",
    "query_status": "0",
    "answers": [
      "93.184.216.34"
    ],
    "process": {
      "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
      "pid": 4521,
      "exe": "C:\\Windows\\System32\\cmd.exe",
      "owner_name": "jdoe"
    }
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-23 — File deleted and archived (Sysmon EID 23)

<!-- covers: SEC-A Sysmon EID 23 file_delete; IsExecutable/Archived unmapped; archived flag via source.event_id -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_delete",
    "action": "delete",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:21:00.000Z",
    "original": "2026-10-09 12:21:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-23",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 23,
    "record": {
      "type": "event_record",
      "record_id": 1046
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>23</EventID><TimeCreated SystemTime='2026-10-09T12:21:00.000Z'/><EventRecordID>1046</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-10-09 12:21:00.000</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='TargetFilename'>C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe</Data><Data Name='Hashes'>SHA256=ff77889900aabbccddeeff11223344556677889900aabbccddeeff77889900</Data><Data Name='IsExecutable'>true</Data><Data Name='Archived'>true</Data></EventData></Event>",
  "file": {
    "path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe",
    "name": "payload.exe",
    "directory": "C:\\Users\\jdoe\\AppData\\Local\\Temp",
    "hashes": {
      "sha256": "ff77889900aabbccddeeff11223344556677889900aabbccddeeff77889900"
    }
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "IsExecutable",
      "value": "true"
    },
    {
      "name": "Archived",
      "value": "true"
    }
  ]
}
```

### EX-SYSMON-24 — Clipboard change (Sysmon EID 24)

<!-- covers: SEC-A Sysmon EID 24 clipboard_change; derived_by sentinel; no clipboard payload — Session/ClientInfo/Hashes/Archived unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "process",
    "type": "clipboard_change",
    "action": "change",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:22:00.000Z",
    "original": "2026-10-09 12:22:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-24",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 24,
    "record": {
      "type": "event_record",
      "record_id": 1047
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>24</EventID><TimeCreated SystemTime='2026-10-09T12:22:00.000Z'/><EventRecordID>1047</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>ClipboardChange</Data><Data Name='UtcTime'>2026-10-09 12:22:00.000</Data><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='Session'>1</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='ClientInfo'>-</Data><Data Name='Hashes'>aa99bb00cc11dd22ee33ff44556677889900aabbccddeeff1122334455667788</Data><Data Name='Archived'>false</Data></EventData></Event>",
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "EventType",
      "value": "ClipboardChange"
    },
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "Session",
      "value": "1"
    },
    {
      "name": "ClientInfo",
      "value": "-"
    },
    {
      "name": "Hashes",
      "value": "aa99bb00cc11dd22ee33ff44556677889900aabbccddeeff1122334455667788"
    },
    {
      "name": "Archived",
      "value": "false"
    }
  ]
}
```

### EX-SYSMON-25 — Process tampering (Sysmon EID 25)

<!-- covers: SEC-A Sysmon EID 25 process_tampering; Type/EventType unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "process",
    "type": "process_tampering",
    "action": "modify",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:23:00.000Z",
    "original": "2026-10-09 12:23:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-25",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 25,
    "record": {
      "type": "event_record",
      "record_id": 1048
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>25</EventID><TimeCreated SystemTime='2026-10-09T12:23:00.000Z'/><EventRecordID>1048</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>ImagePatch</Data><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-10-09 12:23:00.000</Data><Data Name='ProcessGuid'>{1a2b3c4d-0004-0000-0000-000000000004}</Data><Data Name='ProcessId'>8888</Data><Data Name='Image'>C:\\Users\\jdoe\\AppData\\Local\\Temp\\host.exe</Data><Data Name='Type'>Image is patched</Data><Data Name='User'>CORP\\jdoe</Data></EventData></Event>",
  "process": {
    "guid": "{1a2b3c4d-0004-0000-0000-000000000004}",
    "pid": 8888,
    "exe": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\host.exe",
    "name": "host.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "EventType",
      "value": "ImagePatch"
    },
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "Type",
      "value": "Image is patched"
    }
  ]
}
```

### EX-SYSMON-26 — File delete logged (Sysmon EID 26)

<!-- covers: SEC-A Sysmon EID 26 file_delete; no Archived field (vs EID 23) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_delete",
    "action": "delete",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:24:00.000Z",
    "original": "2026-10-09 12:24:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-26",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 26,
    "record": {
      "type": "event_record",
      "record_id": 1049
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>26</EventID><TimeCreated SystemTime='2026-10-09T12:24:00.000Z'/><EventRecordID>1049</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-10-09 12:24:00.000</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='TargetFilename'>C:\\Users\\jdoe\\AppData\\Local\\Temp\\notes.txt</Data><Data Name='Hashes'>SHA256=1122aabb33cc44dd55ee66ff778899001122aabb33cc44dd55ee66ff77889900</Data><Data Name='IsExecutable'>false</Data></EventData></Event>",
  "file": {
    "path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\notes.txt",
    "name": "notes.txt",
    "directory": "C:\\Users\\jdoe\\AppData\\Local\\Temp",
    "hashes": {
      "sha256": "1122aabb33cc44dd55ee66ff778899001122aabb33cc44dd55ee66ff77889900"
    }
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "IsExecutable",
      "value": "false"
    }
  ]
}
```

### EX-SYSMON-27 — Executable write blocked (Sysmon EID 27)

<!-- covers: SEC-A Sysmon EID 27 file_block_executable; outcome=block succeeded (INFERRED semantics) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_block_executable",
    "action": "block",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:25:00.000Z",
    "original": "2026-10-09 12:25:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-27",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 27,
    "record": {
      "type": "event_record",
      "record_id": 1050
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>27</EventID><TimeCreated SystemTime='2026-10-09T12:25:00.000Z'/><EventRecordID>1050</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-10-09 12:25:00.000</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='TargetFilename'>C:\\Users\\jdoe\\AppData\\Local\\Temp\\blocked.exe</Data><Data Name='Hashes'>SHA256=2233aabb44cc55dd66ee77ff889900112233aabb44cc55dd66ee77ff88990011</Data></EventData></Event>",
  "file": {
    "path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\blocked.exe",
    "name": "blocked.exe",
    "directory": "C:\\Users\\jdoe\\AppData\\Local\\Temp",
    "hashes": {
      "sha256": "2233aabb44cc55dd66ee77ff889900112233aabb44cc55dd66ee77ff88990011"
    }
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-28 — File shredding blocked (Sysmon EID 28)

<!-- covers: SEC-A Sysmon EID 28 file_block_shredding; IsExecutable unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_block_shredding",
    "action": "block",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:26:00.000Z",
    "original": "2026-10-09 12:26:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-28",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 28,
    "record": {
      "type": "event_record",
      "record_id": 1051
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>28</EventID><TimeCreated SystemTime='2026-10-09T12:26:00.000Z'/><EventRecordID>1051</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-10-09 12:26:00.000</Data><Data Name='ProcessGuid'>{1a2b3c4d-0005-0000-0000-000000000005}</Data><Data Name='ProcessId'>9999</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='Image'>C:\\Tools\\sdelete64.exe</Data><Data Name='TargetFilename'>C:\\Users\\jdoe\\Documents\\evidence.docx</Data><Data Name='Hashes'>SHA256=3344aabb55cc66dd77ee88ff990011223344aabb55cc66dd77ee88ff99001122</Data><Data Name='IsExecutable'>true</Data></EventData></Event>",
  "file": {
    "path": "C:\\Users\\jdoe\\Documents\\evidence.docx",
    "name": "evidence.docx",
    "directory": "C:\\Users\\jdoe\\Documents",
    "hashes": {
      "sha256": "3344aabb55cc66dd77ee88ff990011223344aabb55cc66dd77ee88ff99001122"
    }
  },
  "process": {
    "guid": "{1a2b3c4d-0005-0000-0000-000000000005}",
    "pid": 9999,
    "exe": "C:\\Tools\\sdelete64.exe",
    "name": "sdelete64.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "IsExecutable",
      "value": "true"
    }
  ]
}
```

### EX-SYSMON-29 — Executable detected (Sysmon EID 29)

<!-- covers: SEC-A Sysmon EID 29 file_executable_detected; no signature fields (absent≠unsigned) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_executable_detected",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:27:00.000Z",
    "original": "2026-10-09 12:27:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-29",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 29,
    "record": {
      "type": "event_record",
      "record_id": 1052
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>29</EventID><TimeCreated SystemTime='2026-10-09T12:27:00.000Z'/><EventRecordID>1052</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-10-09 12:27:00.000</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='TargetFilename'>C:\\Users\\jdoe\\Downloads\\newtool.exe</Data><Data Name='Hashes'>SHA256=4455aabb66cc77dd88ee99ff001122334455aabb66cc77dd88ee99ff00112233</Data></EventData></Event>",
  "file": {
    "path": "C:\\Users\\jdoe\\Downloads\\newtool.exe",
    "name": "newtool.exe",
    "directory": "C:\\Users\\jdoe\\Downloads",
    "hashes": {
      "sha256": "4455aabb66cc77dd88ee99ff001122334455aabb66cc77dd88ee99ff00112233"
    }
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-255 — Sysmon internal error (Sysmon EID 255)

<!-- covers: SEC-A Sysmon EID 255 sysmon_error; envelope-only; no verified EventData; derived_by sentinel; UNVERIFIED fields -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "third_party_alert",
    "type": "sysmon_error",
    "action": "error",
    "outcome": "unknown",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:28:00.000Z",
    "original": "2026-10-09 12:28:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sysmon-255",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 255,
    "record": {
      "type": "event_record",
      "record_id": 1053
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>255</EventID><TimeCreated SystemTime='2026-10-09T12:28:00.000Z'/><EventRecordID>1053</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><RenderingInfo><Message>Sysmon error: failed to load driver</Message><Level>Error</Level><Task>None</Task><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Provider>Microsoft-Windows-Sysmon</Provider></RenderingInfo></Event>",
  "third_party_alert": {
    "vendor": "Microsoft",
    "product": "Sysmon",
    "description": {
      "$state": "inferred",
      "$note": "description synthesized from RenderingInfo/Message; EventData names UNVERIFIED",
      "$raw": "Sysmon error: failed to load driver"
    }
  }
}
```

## Windows Security channel (32)

### EX-SEC-1102 — Audit log cleared (Security EID 1102)

<!-- covers: SEC-A Security EID 1102 audit_log_cleared; derived_by sentinel; UserData not EventData -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "fim",
    "type": "audit_log_cleared",
    "action": "clear",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:00:00.000000Z",
    "original": "2026-10-09T13:00:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x3e7"
  },
  "source": {
    "file_id": "evt-sec-1102",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 1102,
    "record": {
      "type": "event_record",
      "record_id": 2001
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID><TimeCreated SystemTime='2026-10-09T13:00:00.0000000Z'/><EventRecordID>2001</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security/></System><UserData><LogFileCleared xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><SubjectUserSid>S-1-5-21-1000-2000-3000-1001</SubjectUserSid><SubjectUserName>jdoe</SubjectUserName><SubjectDomainName>CORP</SubjectDomainName><SubjectLogonId>0x3e7</SubjectLogonId></LogFileCleared></UserData></Event>",
  "fim": {
    "path": "Security",
    "operation": "audit_log_cleared"
  }
}
```

### EX-SEC-4624 — Logon success (Security EID 4624)

<!-- covers: SEC-A Security EID 4624 logon_success; hex PID→int INFERRED; ElevatedToken %%1842→invalid state -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "logon_success",
    "action": "logon",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:01:00.000000Z",
    "original": "2026-10-09T13:01:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-18",
    "name": "SYSTEM",
    "domain": "NT AUTHORITY",
    "logon_id": "0x3e7"
  },
  "source": {
    "file_id": "evt-sec-4624",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4624,
    "record": {
      "type": "event_record",
      "record_id": 2002
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><TimeCreated SystemTime='2026-10-09T13:01:00.0000000Z'/><EventRecordID>2002</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>SYSTEM</Data><Data Name='SubjectDomainName'>NT AUTHORITY</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='TargetUserName'>jdoe</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetLogonId'>0x123456</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32</Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>CLIENT01</Data><Data Name='LogonGuid'>{aa00bb11-cc22-dd33-ee44-ff5566778899}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x4c8</Data><Data Name='ProcessName'>C:\\Windows\\System32\\winlogon.exe</Data><Data Name='IpAddress'>10.10.5.50</Data><Data Name='IpPort'>51515</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event>",
  "authentication": {
    "logon_type": 10,
    "logon_id": "0x123456",
    "logon_guid": "{aa00bb11-cc22-dd33-ee44-ff5566778899}",
    "account_sid": "S-1-5-21-1000-2000-3000-1001",
    "account_name": "jdoe",
    "account_domain": "CORP",
    "source_ip": "10.10.5.50",
    "workstation": "CLIENT01",
    "auth_package": "Negotiate",
    "key_length": 0,
    "process_pid": {
      "$state": "inferred",
      "$note": "hex 0x4c8→int",
      "$raw": "0x4c8"
    },
    "process_name": "C:\\Windows\\System32\\winlogon.exe",
    "elev_token": {
      "$state": "invalid",
      "$note": "%%nnnn message-table constant; expansion lives in message table, not EVTX",
      "$raw": "%%1842"
    }
  },
  "unmapped": [
    {
      "name": "LogonProcessName",
      "value": "User32"
    },
    {
      "name": "TransmittedServices",
      "value": "-"
    },
    {
      "name": "LmPackageName",
      "value": "-"
    },
    {
      "name": "IpPort",
      "value": "51515"
    },
    {
      "name": "ImpersonationLevel",
      "value": "%%1833"
    },
    {
      "name": "RestrictedAdminMode",
      "value": "-"
    },
    {
      "name": "TargetOutboundUserName",
      "value": "-"
    },
    {
      "name": "TargetOutboundDomainName",
      "value": "-"
    },
    {
      "name": "VirtualAccount",
      "value": "%%1843"
    },
    {
      "name": "TargetLinkedLogonId",
      "value": "0x0"
    }
  ]
}
```

### EX-SEC-4625 — Logon failure (Security EID 4625)

<!-- covers: SEC-A Security EID 4625 logon_failure; Status/SubStatus kept as strings; PID reuse trap -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "logon_failure",
    "action": "logon",
    "outcome": "failure",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:02:00.000000Z",
    "original": "2026-10-09T13:02:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-0-0",
    "name": {
      "$state": "null",
      "$raw": "-"
    },
    "domain": {
      "$state": "null",
      "$raw": "-"
    },
    "logon_id": "0x0"
  },
  "source": {
    "file_id": "evt-sec-4625",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4625,
    "record": {
      "type": "event_record",
      "record_id": 2003
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><TimeCreated SystemTime='2026-10-09T13:02:00.0000000Z'/><EventRecordID>2003</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>administrator</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetLogonId'>0x0</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp</Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>EVILPC</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>10.10.5.99</Data><Data Name='IpPort'>44444</Data></EventData></Event>",
  "authentication": {
    "logon_type": 3,
    "logon_id": "0x0",
    "account_sid": "S-1-0-0",
    "account_name": "administrator",
    "account_domain": "CORP",
    "source_ip": "10.10.5.99",
    "workstation": "EVILPC",
    "auth_package": "NTLM",
    "key_length": 0,
    "status": "0xc000006d",
    "sub_status": "0xc0000064",
    "failure_reason": "%%2313",
    "process_pid": {
      "$state": "inferred",
      "$note": "hex 0x0→int",
      "$raw": "0x0"
    },
    "process_name": {
      "$state": "null",
      "$raw": "-"
    }
  },
  "unmapped": [
    {
      "name": "LogonProcessName",
      "value": "NtLmSsp"
    },
    {
      "name": "TransmittedServices",
      "value": "-"
    },
    {
      "name": "LmPackageName",
      "value": "-"
    },
    {
      "name": "IpPort",
      "value": "44444"
    }
  ]
}
```

### EX-SEC-4634 — Account logged off (Security EID 4634)

<!-- covers: SEC-A Security EID 4634 logoff; envelope user mirrored from Target* (INFERRED) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "logoff",
    "action": "logoff",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:03:00.000000Z",
    "original": "2026-10-09T13:03:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sec-4634",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4634,
    "record": {
      "type": "event_record",
      "record_id": 2004
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4634</EventID><TimeCreated SystemTime='2026-10-09T13:03:00.0000000Z'/><EventRecordID>2004</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='TargetUserName'>jdoe</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetLogonId'>0x123456</Data><Data Name='LogonType'>10</Data></EventData></Event>",
  "authentication": {
    "logon_type": 10,
    "logon_id": "0x123456",
    "account_sid": "S-1-5-21-1000-2000-3000-1001",
    "account_name": "jdoe",
    "account_domain": "CORP"
  }
}
```

### EX-SEC-4647 — User-initiated logoff (Security EID 4647)

<!-- covers: SEC-A Security EID 4647 logoff_initiated; pairs with 4634/4624 via TargetLogonId -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "logoff_initiated",
    "action": "logoff",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:04:00.000000Z",
    "original": "2026-10-09T13:04:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sec-4647",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4647,
    "record": {
      "type": "event_record",
      "record_id": 2005
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4647</EventID><TimeCreated SystemTime='2026-10-09T13:04:00.0000000Z'/><EventRecordID>2005</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='TargetUserName'>jdoe</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetLogonId'>0x123456</Data></EventData></Event>",
  "authentication": {
    "logon_id": "0x123456",
    "account_sid": "S-1-5-21-1000-2000-3000-1001",
    "account_name": "jdoe",
    "account_domain": "CORP"
  }
}
```

### EX-SEC-4648 — Explicit credential logon (Security EID 4648)

<!-- covers: SEC-A Security EID 4648 explicit_credential_logon; TargetLogonGuid/TargetServerName/TargetInfo unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "explicit_credential_logon",
    "action": "logon",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:05:00.000000Z",
    "original": "2026-10-09T13:05:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4648",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4648,
    "record": {
      "type": "event_record",
      "record_id": 2006
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4648</EventID><TimeCreated SystemTime='2026-10-09T13:05:00.0000000Z'/><EventRecordID>2006</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='LogonGuid'>{bb11cc22-dd33-ee44-ff55-667788990011}</Data><Data Name='TargetUserName'>svc_admin</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetLogonGuid'>{cc22dd33-ee44-ff55-6677-889900112233}</Data><Data Name='TargetServerName'>FILESRV01</Data><Data Name='TargetInfo'>CORP\\svc_admin</Data><Data Name='ProcessId'>0x1f40</Data><Data Name='ProcessName'>C:\\Windows\\System32\\runas.exe</Data><Data Name='IpAddress'>10.10.5.23</Data><Data Name='IpPort'>51520</Data></EventData></Event>",
  "authentication": {
    "logon_guid": "{bb11cc22-dd33-ee44-ff55-667788990011}",
    "target_name": "svc_admin",
    "target_domain": "CORP",
    "source_ip": "10.10.5.23",
    "caller_process_id": {
      "$state": "inferred",
      "$note": "hex 0x1f40→int",
      "$raw": "0x1f40"
    },
    "caller_process_name": "C:\\Windows\\System32\\runas.exe"
  },
  "unmapped": [
    {
      "name": "TargetLogonGuid",
      "value": "{cc22dd33-ee44-ff55-6677-889900112233}"
    },
    {
      "name": "TargetServerName",
      "value": "FILESRV01"
    },
    {
      "name": "TargetInfo",
      "value": "CORP\\svc_admin"
    },
    {
      "name": "IpPort",
      "value": "51520"
    }
  ]
}
```

### EX-SEC-4672 — Special privileges assigned (Security EID 4672)

<!-- covers: SEC-A Security EID 4672 special_privileges_assigned; PrivilegeList unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "special_privileges_assigned",
    "action": "assign",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:06:00.000000Z",
    "original": "2026-10-09T13:06:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4672",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4672,
    "record": {
      "type": "event_record",
      "record_id": 2007
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4672</EventID><TimeCreated SystemTime='2026-10-09T13:06:00.0000000Z'/><EventRecordID>2007</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='PrivilegeList'>SeDebugPrivilege\r\nSeBackupPrivilege\r\nSeRestorePrivilege</Data></EventData></Event>",
  "authentication": {
    "logon_id": "0x123456"
  },
  "unmapped": [
    {
      "name": "PrivilegeList",
      "value": "SeDebugPrivilege\r\nSeBackupPrivilege\r\nSeRestorePrivilege"
    }
  ]
}
```

### EX-SEC-4688 — Process created (Security EID 4688)

<!-- covers: SEC-A Security EID 4688 process_create; ProcessId=parent PID; hex→int INFERRED; MandatoryLabel overrides TokenElevationType -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "process",
    "type": "process_create",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:07:00.000000Z",
    "original": "2026-10-09T13:07:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4688",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4688,
    "record": {
      "type": "event_record",
      "record_id": 2008
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4688</EventID><TimeCreated SystemTime='2026-10-09T13:07:00.0000000Z'/><EventRecordID>2008</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='NewProcessId'>0x1234</Data><Data Name='NewProcessName'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='TokenElevationType'>%%1968</Data><Data Name='ProcessId'>0x8fc</Data><Data Name='CommandLine'>cmd.exe /c powershell -enc SQBFAFgA</Data><Data Name='TargetUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='TargetUserName'>jdoe</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetLogonId'>0x123456</Data><Data Name='ParentProcessName'>C:\\Windows\\explorer.exe</Data><Data Name='MandatoryLabel'>S-1-16-8192</Data></EventData></Event>",
  "process": {
    "pid": {
      "$state": "inferred",
      "$note": "hex 0x1234→int",
      "$raw": "0x1234"
    },
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "command_line": "cmd.exe /c powershell -enc SQBFAFgA",
    "integrity_level": "S-1-16-8192",
    "owner_sid": "S-1-5-21-1000-2000-3000-1001",
    "owner_name": "jdoe",
    "parent": {
      "pid": {
        "$state": "inferred",
        "$note": "hex 0x8fc→int (ProcessId field is PARENT pid)",
        "$raw": "0x8fc"
      },
      "exe": "C:\\Windows\\explorer.exe",
      "name": "explorer.exe"
    }
  },
  "unmapped": [
    {
      "name": "TokenElevationType",
      "value": "%%1968"
    },
    {
      "name": "TargetDomainName",
      "value": "CORP"
    },
    {
      "name": "TargetLogonId",
      "value": "0x123456"
    }
  ]
}
```

### EX-SEC-4689 — Process exited (Security EID 4689)

<!-- covers: SEC-A Security EID 4689 process_terminate; Status→unmapped (no process.exit_code) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "process",
    "type": "process_terminate",
    "action": "terminate",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:08:00.000000Z",
    "original": "2026-10-09T13:08:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4689",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4689,
    "record": {
      "type": "event_record",
      "record_id": 2009
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4689</EventID><TimeCreated SystemTime='2026-10-09T13:08:00.0000000Z'/><EventRecordID>2009</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='Status'>0x0</Data><Data Name='ProcessId'>0x1234</Data><Data Name='ProcessName'>C:\\Windows\\System32\\cmd.exe</Data></EventData></Event>",
  "process": {
    "pid": {
      "$state": "inferred",
      "$note": "hex 0x1234→int",
      "$raw": "0x1234"
    },
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe"
  },
  "unmapped": [
    {
      "name": "Status",
      "value": "0x0"
    }
  ]
}
```

### EX-SEC-4697 — Service installed (Security EID 4697)

<!-- covers: SEC-A Security EID 4697 service_install -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "service",
    "type": "service_install",
    "action": "install",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:09:00.000000Z",
    "original": "2026-10-09T13:09:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4697",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4697,
    "record": {
      "type": "event_record",
      "record_id": 2010
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4697</EventID><TimeCreated SystemTime='2026-10-09T13:09:00.0000000Z'/><EventRecordID>2010</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='ServiceName'>EvilSvc</Data><Data Name='ServiceFileName'>C:\\Temp\\evil.exe</Data><Data Name='ServiceType'>0x10</Data><Data Name='ServiceStartType'>demand</Data><Data Name='ServiceAccount'>LocalSystem</Data></EventData></Event>",
  "service": {
    "name": "EvilSvc",
    "image_path": "C:\\Temp\\evil.exe",
    "service_type": "0x10",
    "start_type": "demand",
    "account_name": "LocalSystem"
  }
}
```

### EX-SEC-4698 — Scheduled task created (Security EID 4698)

<!-- covers: SEC-A Security EID 4698 scheduled_task_create; TaskContent kept raw; ClientProcessStartKey/FQDN unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "scheduled_task",
    "type": "scheduled_task_create",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:10:00.000000Z",
    "original": "2026-10-09T13:10:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4698",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4698,
    "record": {
      "type": "event_record",
      "record_id": 2011
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4698</EventID><TimeCreated SystemTime='2026-10-09T13:10:00.0000000Z'/><EventRecordID>2011</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='TaskName'>\\Updater</Data><Data Name='TaskContent'>&lt;Task&gt;&lt;Actions&gt;&lt;Exec&gt;&lt;Command&gt;C:\\Temp\\evil.exe&lt;/Command&gt;&lt;/Exec&gt;&lt;/Actions&gt;&lt;/Task&gt;</Data><Data Name='ClientProcessStartKey'>1337777</Data><Data Name='ClientProcessId'>0x8fc</Data><Data Name='ParentProcessId'>0x4e4</Data><Data Name='RpcCallClientLocality'>0</Data><Data Name='FQDN'>WS-DEMO01.corp.local</Data></EventData></Event>",
  "scheduled_task": {
    "name": "\\Updater",
    "task_xml": "<Task><Actions><Exec><Command>C:\\Temp\\evil.exe</Command></Exec></Actions></Task>"
  },
  "process": {
    "pid": {
      "$state": "inferred",
      "$note": "hex 0x8fc→int (ClientProcessId)",
      "$raw": "0x8fc"
    },
    "parent": {
      "pid": {
        "$state": "inferred",
        "$note": "hex 0x4e4→int (ParentProcessId)",
        "$raw": "0x4e4"
      }
    }
  },
  "unmapped": [
    {
      "name": "ClientProcessStartKey",
      "value": "1337777"
    },
    {
      "name": "RpcCallClientLocality",
      "value": "0"
    },
    {
      "name": "FQDN",
      "value": "WS-DEMO01.corp.local"
    }
  ]
}
```

### EX-SEC-4720 — User account created (Security EID 4720)

<!-- covers: SEC-A Security EID 4720 account_created; UAC fields unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "account",
    "type": "account_created",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:11:00.000000Z",
    "original": "2026-10-09T13:11:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4720",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4720,
    "record": {
      "type": "event_record",
      "record_id": 2012
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4720</EventID><TimeCreated SystemTime='2026-10-09T13:11:00.0000000Z'/><EventRecordID>2012</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>backdoor</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-1050</Data><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='PrivilegeList'>-</Data><Data Name='SamAccountName'>backdoor</Data><Data Name='DisplayName'>Back Door</Data><Data Name='UserPrincipalName'>backdoor@corp.local</Data><Data Name='HomeDirectory'>-</Data><Data Name='HomePath'>-</Data><Data Name='ScriptPath'>-</Data><Data Name='ProfilePath'>-</Data><Data Name='UserWorkstations'>-</Data><Data Name='PasswordLastSet'>10/9/2026 1:11:00 PM</Data><Data Name='AccountExpires'>Never</Data><Data Name='PrimaryGroupId'>513</Data><Data Name='AllowedToDelegateTo'>-</Data><Data Name='OldUacValue'>0x0</Data><Data Name='NewUacValue'>0x15</Data><Data Name='UserAccountControl'>0x15</Data><Data Name='UserParameters'>-</Data><Data Name='SidHistory'>-</Data><Data Name='LogonHours'>-</Data></EventData></Event>",
  "account": {
    "sid": "S-1-5-21-1000-2000-3000-1050",
    "name": "backdoor",
    "domain": "CORP",
    "upn": "backdoor@corp.local",
    "display_name": "Back Door",
    "sam_account_name": "backdoor",
    "account_type": "user"
  },
  "unmapped": [
    {
      "name": "PrivilegeList",
      "value": "-"
    },
    {
      "name": "HomeDirectory",
      "value": "-"
    },
    {
      "name": "HomePath",
      "value": "-"
    },
    {
      "name": "ScriptPath",
      "value": "-"
    },
    {
      "name": "ProfilePath",
      "value": "-"
    },
    {
      "name": "UserWorkstations",
      "value": "-"
    },
    {
      "name": "PasswordLastSet",
      "value": "10/9/2026 1:11:00 PM"
    },
    {
      "name": "AccountExpires",
      "value": "Never"
    },
    {
      "name": "PrimaryGroupId",
      "value": "513"
    },
    {
      "name": "AllowedToDelegateTo",
      "value": "-"
    },
    {
      "name": "OldUacValue",
      "value": "0x0"
    },
    {
      "name": "NewUacValue",
      "value": "0x15"
    },
    {
      "name": "UserAccountControl",
      "value": "0x15"
    },
    {
      "name": "UserParameters",
      "value": "-"
    },
    {
      "name": "LogonHours",
      "value": "-"
    }
  ]
}
```

### EX-SEC-4722 — User account enabled (Security EID 4722)

<!-- covers: SEC-A Security EID 4722 account_enabled; account.enabled=true is derived constant, not a source field -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "account",
    "type": "account_enabled",
    "action": "enable",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:12:00.000000Z",
    "original": "2026-10-09T13:12:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4722",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4722,
    "record": {
      "type": "event_record",
      "record_id": 2013
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4722</EventID><TimeCreated SystemTime='2026-10-09T13:12:00.0000000Z'/><EventRecordID>2013</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>backdoor</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-1050</Data><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data></EventData></Event>",
  "account": {
    "sid": "S-1-5-21-1000-2000-3000-1050",
    "name": "backdoor",
    "domain": "CORP"
  }
}
```

### EX-SEC-4724 — Password reset attempted (Security EID 4724)

<!-- covers: SEC-A Security EID 4724 password_reset; title (S,F) but no Status field → outcome unknown -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "account",
    "type": "password_reset",
    "action": "reset",
    "outcome": "unknown",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:13:00.000000Z",
    "original": "2026-10-09T13:13:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4724",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4724,
    "record": {
      "type": "event_record",
      "record_id": 2014
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4724</EventID><TimeCreated SystemTime='2026-10-09T13:13:00.0000000Z'/><EventRecordID>2014</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>backdoor</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-1050</Data><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data></EventData></Event>",
  "account": {
    "sid": "S-1-5-21-1000-2000-3000-1050",
    "name": "backdoor",
    "domain": "CORP"
  }
}
```

### EX-SEC-4726 — User account deleted (Security EID 4726)

<!-- covers: SEC-A Security EID 4726 account_deleted; SID is durable join key -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "account",
    "type": "account_deleted",
    "action": "delete",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:14:00.000000Z",
    "original": "2026-10-09T13:14:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4726",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4726,
    "record": {
      "type": "event_record",
      "record_id": 2015
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4726</EventID><TimeCreated SystemTime='2026-10-09T13:14:00.0000000Z'/><EventRecordID>2015</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>backdoor</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-1050</Data><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='PrivilegeList'>-</Data></EventData></Event>",
  "account": {
    "sid": "S-1-5-21-1000-2000-3000-1050",
    "name": "backdoor",
    "domain": "CORP"
  },
  "unmapped": [
    {
      "name": "PrivilegeList",
      "value": "-"
    }
  ]
}
```

### EX-SEC-4728 — Member added to global group (Security EID 4728)

<!-- covers: SEC-A Security EID 4728; field names by documented equivalence to 4732 (A-SEC-GRPMGMT) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "group_membership",
    "type": "member_added_to_global_group",
    "action": "add",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:15:00.000000Z",
    "original": "2026-10-09T13:15:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4728",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4728,
    "record": {
      "type": "event_record",
      "record_id": 2016
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4728</EventID><TimeCreated SystemTime='2026-10-09T13:15:00.0000000Z'/><EventRecordID>2016</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='MemberName'>CORP\\backdoor</Data><Data Name='MemberSid'>S-1-5-21-1000-2000-3000-1050</Data><Data Name='TargetUserName'>Domain Admins</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-512</Data><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='PrivilegeList'>-</Data></EventData></Event>",
  "group_membership": {
    "action": "added",
    "group_sid": "S-1-5-21-1000-2000-3000-512",
    "group_name": "Domain Admins",
    "domain": "CORP",
    "member_sid": "S-1-5-21-1000-2000-3000-1050",
    "member_name": "CORP\\backdoor",
    "subject_sid": "S-1-5-21-1000-2000-3000-1001",
    "subject_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "PrivilegeList",
      "value": "-"
    }
  ]
}
```

### EX-SEC-4732 — Member added to local group (Security EID 4732)

<!-- covers: SEC-A Security EID 4732 member_added_to_local_group -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "group_membership",
    "type": "member_added_to_local_group",
    "action": "add",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:16:00.000000Z",
    "original": "2026-10-09T13:16:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4732",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4732,
    "record": {
      "type": "event_record",
      "record_id": 2017
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4732</EventID><TimeCreated SystemTime='2026-10-09T13:16:00.0000000Z'/><EventRecordID>2017</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='MemberName'>CORP\\backdoor</Data><Data Name='MemberSid'>S-1-5-21-1000-2000-3000-1050</Data><Data Name='TargetUserName'>Administrators</Data><Data Name='TargetDomainName'>WS-DEMO01</Data><Data Name='TargetSid'>S-1-5-32-544</Data><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='PrivilegeList'>-</Data></EventData></Event>",
  "group_membership": {
    "action": "added",
    "group_sid": "S-1-5-32-544",
    "group_name": "Administrators",
    "domain": "WS-DEMO01",
    "member_sid": "S-1-5-21-1000-2000-3000-1050",
    "member_name": "CORP\\backdoor",
    "subject_sid": "S-1-5-21-1000-2000-3000-1001",
    "subject_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "PrivilegeList",
      "value": "-"
    }
  ]
}
```

### EX-SEC-4738 — User account changed (Security EID 4738)

<!-- covers: SEC-A Security EID 4738 account_changed; Dummy placeholder kept; post-change values only -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "account",
    "type": "account_changed",
    "action": "modify",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:17:00.000000Z",
    "original": "2026-10-09T13:17:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4738",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4738,
    "record": {
      "type": "event_record",
      "record_id": 2018
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4738</EventID><TimeCreated SystemTime='2026-10-09T13:17:00.0000000Z'/><EventRecordID>2018</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='Dummy'/><Data Name='TargetUserName'>backdoor</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-1050</Data><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='PrivilegeList'>-</Data><Data Name='SamAccountName'>backdoor</Data><Data Name='DisplayName'>Totally Legit</Data><Data Name='UserPrincipalName'>backdoor@corp.local</Data><Data Name='HomeDirectory'>-</Data><Data Name='HomePath'>-</Data><Data Name='ScriptPath'>-</Data><Data Name='ProfilePath'>-</Data><Data Name='UserWorkstations'>-</Data><Data Name='PasswordLastSet'>10/9/2026 1:11:00 PM</Data><Data Name='AccountExpires'>Never</Data><Data Name='PrimaryGroupId'>513</Data><Data Name='AllowedToDelegateTo'>-</Data><Data Name='OldUacValue'>0x15</Data><Data Name='NewUacValue'>0x15</Data><Data Name='UserAccountControl'>0x15</Data><Data Name='UserParameters'>-</Data><Data Name='SidHistory'>-</Data><Data Name='LogonHours'>-</Data></EventData></Event>",
  "account": {
    "sid": "S-1-5-21-1000-2000-3000-1050",
    "name": "backdoor",
    "domain": "CORP",
    "upn": "backdoor@corp.local",
    "display_name": "Totally Legit",
    "sam_account_name": "backdoor"
  },
  "unmapped": [
    {
      "name": "Dummy",
      "value": {
        "$state": "null",
        "$note": "literal placeholder element"
      }
    },
    {
      "name": "PrivilegeList",
      "value": "-"
    },
    {
      "name": "HomeDirectory",
      "value": "-"
    },
    {
      "name": "HomePath",
      "value": "-"
    },
    {
      "name": "ScriptPath",
      "value": "-"
    },
    {
      "name": "ProfilePath",
      "value": "-"
    },
    {
      "name": "UserWorkstations",
      "value": "-"
    },
    {
      "name": "PasswordLastSet",
      "value": "10/9/2026 1:11:00 PM"
    },
    {
      "name": "AccountExpires",
      "value": "Never"
    },
    {
      "name": "PrimaryGroupId",
      "value": "513"
    },
    {
      "name": "AllowedToDelegateTo",
      "value": "-"
    },
    {
      "name": "OldUacValue",
      "value": "0x15"
    },
    {
      "name": "NewUacValue",
      "value": "0x15"
    },
    {
      "name": "UserAccountControl",
      "value": "0x15"
    },
    {
      "name": "UserParameters",
      "value": "-"
    },
    {
      "name": "LogonHours",
      "value": "-"
    }
  ]
}
```

### EX-SEC-4740 — Account locked out (Security EID 4740)

<!-- covers: SEC-A Security EID 4740 account_locked_out; subject=trigger source, target=victim -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "account",
    "type": "account_locked_out",
    "action": "lock",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:18:00.000000Z",
    "original": "2026-10-09T13:18:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-18",
    "name": "WS-DEMO01$",
    "domain": "WORKGROUP",
    "logon_id": "0x3e7"
  },
  "source": {
    "file_id": "evt-sec-4740",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4740,
    "record": {
      "type": "event_record",
      "record_id": 2019
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4740</EventID><TimeCreated SystemTime='2026-10-09T13:18:00.0000000Z'/><EventRecordID>2019</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>jdoe</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>WS-DEMO01$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data></EventData></Event>",
  "account": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP"
  }
}
```

### EX-SEC-4756 — Member added to universal group (Security EID 4756)

<!-- covers: SEC-A Security EID 4756; field names by documented equivalence to 4732 (A-SEC-GRPMGMT) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "group_membership",
    "type": "member_added_to_universal_group",
    "action": "add",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:19:00.000000Z",
    "original": "2026-10-09T13:19:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4756",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4756,
    "record": {
      "type": "event_record",
      "record_id": 2020
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4756</EventID><TimeCreated SystemTime='2026-10-09T13:19:00.0000000Z'/><EventRecordID>2020</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='MemberName'>CORP\\backdoor</Data><Data Name='MemberSid'>S-1-5-21-1000-2000-3000-1050</Data><Data Name='TargetUserName'>Enterprise Admins</Data><Data Name='TargetDomainName'>corp.local</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-519</Data><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='PrivilegeList'>-</Data></EventData></Event>",
  "group_membership": {
    "action": "added",
    "group_sid": "S-1-5-21-1000-2000-3000-519",
    "group_name": "Enterprise Admins",
    "domain": "corp.local",
    "member_sid": "S-1-5-21-1000-2000-3000-1050",
    "member_name": "CORP\\backdoor",
    "subject_sid": "S-1-5-21-1000-2000-3000-1001",
    "subject_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "PrivilegeList",
      "value": "-"
    }
  ]
}
```

### EX-SEC-4767 — Account unlocked (Security EID 4767)

<!-- covers: SEC-A Security EID 4767 account_unlocked; pair with 4740 via account.sid -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "account",
    "type": "account_unlocked",
    "action": "unlock",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:20:00.000000Z",
    "original": "2026-10-09T13:20:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "admin",
    "domain": "CORP",
    "logon_id": "0x654321"
  },
  "source": {
    "file_id": "evt-sec-4767",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4767,
    "record": {
      "type": "event_record",
      "record_id": 2021
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4767</EventID><TimeCreated SystemTime='2026-10-09T13:20:00.0000000Z'/><EventRecordID>2021</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>jdoe</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>admin</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x654321</Data></EventData></Event>",
  "account": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP"
  }
}
```

### EX-SEC-4768 — Kerberos TGT requested (Security EID 4768)

<!-- covers: SEC-A Security EID 4768 kerberos_tgt_requested; Status 0x0→success (INFERRED code table) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "kerberos_tgt_requested",
    "action": "request",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:21:00.000000Z",
    "original": "2026-10-09T13:21:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sec-4768",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4768,
    "record": {
      "type": "event_record",
      "record_id": 2022
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4768</EventID><TimeCreated SystemTime='2026-10-09T13:21:00.0000000Z'/><EventRecordID>2022</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>jdoe</Data><Data Name='TargetDomainName'>CORP.LOCAL</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='ServiceName'>krbtgt</Data><Data Name='ServiceSid'>-</Data><Data Name='TicketOptions'>0x40810010</Data><Data Name='Status'>0x0</Data><Data Name='TicketEncryptionType'>0x12</Data><Data Name='PreAuthType'>15</Data><Data Name='IpAddress'>10.10.5.23</Data><Data Name='IpPort'>51521</Data><Data Name='CertIssuerName'>-</Data><Data Name='CertSerialNumber'>-</Data><Data Name='CertThumbprint'>-</Data><Data Name='ResponseTicket'>-</Data></EventData></Event>",
  "authentication": {
    "account_sid": "S-1-5-21-1000-2000-3000-1001",
    "account_name": "jdoe",
    "account_domain": "CORP.LOCAL",
    "target_name": "krbtgt",
    "target_sid": {
      "$state": "null",
      "$raw": "-"
    },
    "status": "0x0",
    "source_ip": "10.10.5.23"
  },
  "unmapped": [
    {
      "name": "TicketOptions",
      "value": "0x40810010"
    },
    {
      "name": "TicketEncryptionType",
      "value": "0x12"
    },
    {
      "name": "PreAuthType",
      "value": "15"
    },
    {
      "name": "IpPort",
      "value": "51521"
    },
    {
      "name": "CertIssuerName",
      "value": "-"
    },
    {
      "name": "CertSerialNumber",
      "value": "-"
    },
    {
      "name": "CertThumbprint",
      "value": "-"
    },
    {
      "name": "ResponseTicket",
      "value": "-"
    }
  ]
}
```

### EX-SEC-4769 — Kerberos service ticket requested (Security EID 4769)

<!-- covers: SEC-A Security EID 4769 kerberos_service_ticket_requested; TicketEncryptionType 0x17=RC4 (Kerberoast signal) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "kerberos_service_ticket_requested",
    "action": "request",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:22:00.000000Z",
    "original": "2026-10-09T13:22:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sec-4769",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4769,
    "record": {
      "type": "event_record",
      "record_id": 2023
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4769</EventID><TimeCreated SystemTime='2026-10-09T13:22:00.0000000Z'/><EventRecordID>2023</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>svc_sql</Data><Data Name='TargetDomainName'>CORP.LOCAL</Data><Data Name='ServiceName'>MSSQLSvc/sql01.corp.local:1433</Data><Data Name='ServiceSid'>S-1-5-21-1000-2000-3000-1051</Data><Data Name='TicketOptions'>0x40810000</Data><Data Name='TicketEncryptionType'>0x17</Data><Data Name='IpAddress'>10.10.5.23</Data><Data Name='IpPort'>51522</Data><Data Name='Status'>0x0</Data><Data Name='LogonGuid'>{dd33ee44-ff55-6677-8899-001122334455}</Data><Data Name='TransmittedServices'>-</Data></EventData></Event>",
  "authentication": {
    "account_name": "svc_sql",
    "account_domain": "CORP.LOCAL",
    "target_name": "MSSQLSvc/sql01.corp.local:1433",
    "target_sid": "S-1-5-21-1000-2000-3000-1051",
    "status": "0x0",
    "logon_guid": "{dd33ee44-ff55-6677-8899-001122334455}",
    "source_ip": "10.10.5.23"
  },
  "unmapped": [
    {
      "name": "TargetSid/SubjectUserSid",
      "value": {
        "$state": "null",
        "$note": "account_sid omitted (absent in source; absent = omit key per schema)"
      }
    },
    {
      "name": "TicketOptions",
      "value": "0x40810000"
    },
    {
      "name": "TicketEncryptionType",
      "value": "0x17"
    },
    {
      "name": "IpPort",
      "value": "51522"
    },
    {
      "name": "TransmittedServices",
      "value": "-"
    }
  ]
}
```

### EX-SEC-4771 — Kerberos pre-auth failed (Security EID 4771)

<!-- covers: SEC-A Security EID 4771 kerberos_preauth_failed; no TargetDomainName (absence source-true) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "kerberos_preauth_failed",
    "action": "request",
    "outcome": "failure",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:23:00.000000Z",
    "original": "2026-10-09T13:23:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sec-4771",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4771,
    "record": {
      "type": "event_record",
      "record_id": 2024
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4771</EventID><TimeCreated SystemTime='2026-10-09T13:23:00.0000000Z'/><EventRecordID>2024</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>administrator</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-1000</Data><Data Name='ServiceName'>krbtgt</Data><Data Name='TicketOptions'>0x40810010</Data><Data Name='Status'>0x18</Data><Data Name='PreAuthType'>15</Data><Data Name='IpAddress'>10.10.5.99</Data><Data Name='IpPort'>44445</Data><Data Name='CertIssuerName'>-</Data><Data Name='CertSerialNumber'>-</Data><Data Name='CertThumbprint'>-</Data></EventData></Event>",
  "authentication": {
    "account_sid": "S-1-5-21-1000-2000-3000-1000",
    "account_name": "administrator",
    "target_name": "krbtgt",
    "status": "0x18",
    "source_ip": "10.10.5.99"
  },
  "unmapped": [
    {
      "name": "TicketOptions",
      "value": "0x40810010"
    },
    {
      "name": "PreAuthType",
      "value": "15"
    },
    {
      "name": "IpPort",
      "value": "44445"
    },
    {
      "name": "CertIssuerName",
      "value": "-"
    },
    {
      "name": "CertSerialNumber",
      "value": "-"
    },
    {
      "name": "CertThumbprint",
      "value": "-"
    }
  ]
}
```

### EX-SEC-4776 — Credential validation (Security EID 4776)

<!-- covers: SEC-A Security EID 4776 credential_validation; Status 0x0=success VERIFIED; NTLM validation signal -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "credential_validation",
    "action": "validate",
    "outcome": "failure",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:24:00.000000Z",
    "original": "2026-10-09T13:24:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sec-4776",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4776,
    "record": {
      "type": "event_record",
      "record_id": 2025
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4776</EventID><TimeCreated SystemTime='2026-10-09T13:24:00.0000000Z'/><EventRecordID>2025</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='PackageName'>MSV1_0</Data><Data Name='TargetUserName'>jdoe</Data><Data Name='Workstation'>EVILPC</Data><Data Name='Status'>0xc000006a</Data></EventData></Event>",
  "authentication": {
    "auth_package": "MSV1_0",
    "account_name": "jdoe",
    "workstation": "EVILPC",
    "status": "0xc000006a"
  }
}
```

### EX-SEC-5140 — Network share accessed (Security EID 5140)

<!-- covers: SEC-A Security EID 5140 network_share_access; ShareName/AccessMask unmapped; no dst_port -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "network",
    "type": "network_share_access",
    "action": "access",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:25:00.000000Z",
    "original": "2026-10-09T13:25:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-5140",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 5140,
    "record": {
      "type": "event_record",
      "record_id": 2026
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>5140</EventID><TimeCreated SystemTime='2026-10-09T13:25:00.0000000Z'/><EventRecordID>2026</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='ObjectType'>File</Data><Data Name='IpAddress'>10.10.5.50</Data><Data Name='IpPort'>0x1412</Data><Data Name='ShareName'>\\\\*\\C$</Data><Data Name='ShareLocalPath'>C:\\</Data><Data Name='AccessMask'>0x1</Data><Data Name='AccessList'>%%4416</Data></EventData></Event>",
  "network": {
    "src_ip": "10.10.5.50",
    "src_port": {
      "$state": "inferred",
      "$note": "hex 0x1412→int",
      "$raw": "0x1412"
    }
  },
  "unmapped": [
    {
      "name": "ObjectType",
      "value": "File"
    },
    {
      "name": "ShareName",
      "value": "\\\\*\\C$"
    },
    {
      "name": "ShareLocalPath",
      "value": "C:\\"
    },
    {
      "name": "AccessMask",
      "value": "0x1"
    },
    {
      "name": "AccessList",
      "value": "%%4416"
    }
  ]
}
```

### EX-SEC-5145 — Network share access check (Security EID 5145)

<!-- covers: SEC-A Security EID 5145 network_share_access_check; RelativeTargetName unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "network",
    "type": "network_share_access_check",
    "action": "check",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:26:00.000000Z",
    "original": "2026-10-09T13:26:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-5145",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 5145,
    "record": {
      "type": "event_record",
      "record_id": 2027
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>5145</EventID><TimeCreated SystemTime='2026-10-09T13:26:00.0000000Z'/><EventRecordID>2027</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='ObjectType'>File</Data><Data Name='IpAddress'>10.10.5.50</Data><Data Name='IpPort'>0x1413</Data><Data Name='ShareName'>\\\\*\\C$</Data><Data Name='ShareLocalPath'>C:\\</Data><Data Name='RelativeTargetName'>Users\\admin\\secret.txt</Data><Data Name='AccessMask'>0x1</Data><Data Name='AccessList'>%%4416</Data><Data Name='AccessReason'>Granted ReadData</Data></EventData></Event>",
  "network": {
    "src_ip": "10.10.5.50",
    "src_port": {
      "$state": "inferred",
      "$note": "hex 0x1413→int",
      "$raw": "0x1413"
    }
  },
  "unmapped": [
    {
      "name": "ObjectType",
      "value": "File"
    },
    {
      "name": "ShareName",
      "value": "\\\\*\\C$"
    },
    {
      "name": "ShareLocalPath",
      "value": "C:\\"
    },
    {
      "name": "RelativeTargetName",
      "value": "Users\\admin\\secret.txt"
    },
    {
      "name": "AccessMask",
      "value": "0x1"
    },
    {
      "name": "AccessList",
      "value": "%%4416"
    },
    {
      "name": "AccessReason",
      "value": "Granted ReadData"
    }
  ]
}
```

### EX-SEC-5156 — WFP connection permitted (Security EID 5156)

<!-- covers: SEC-A Security EID 5156 wfp_connection_permitted; Direction %%14592→unknown state (UNVERIFIED expansion) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "network",
    "type": "wfp_connection_permitted",
    "action": "permit",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:27:00.000000Z",
    "original": "2026-10-09T13:27:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sec-5156",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 5156,
    "record": {
      "type": "event_record",
      "record_id": 2028
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>5156</EventID><TimeCreated SystemTime='2026-10-09T13:27:00.0000000Z'/><EventRecordID>2028</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='ProcessID'>0x1234</Data><Data Name='Application'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='Direction'>%%14592</Data><Data Name='SourceAddress'>10.10.5.23</Data><Data Name='SourcePort'>51530</Data><Data Name='DestAddress'>93.184.216.34</Data><Data Name='DestPort'>443</Data><Data Name='Protocol'>6</Data><Data Name='FilterRTID'>123456</Data><Data Name='LayerName'>%%13312</Data><Data Name='LayerRTID'>44</Data><Data Name='RemoteUserID'>-</Data><Data Name='RemoteMachineID'>-</Data></EventData></Event>",
  "network": {
    "protocol": "6",
    "direction": {
      "$state": "unknown",
      "$note": "%%14592 expansion UNVERIFIED; message-table constant not resolvable in EVTX",
      "$raw": "%%14592"
    },
    "src_ip": "10.10.5.23",
    "src_port": 51530,
    "dst_ip": "93.184.216.34",
    "dst_port": 443,
    "process": {
      "pid": {
        "$state": "inferred",
        "$note": "hex 0x1234→int",
        "$raw": "0x1234"
      },
      "exe": "C:\\Windows\\System32\\cmd.exe"
    }
  },
  "unmapped": [
    {
      "name": "FilterRTID",
      "value": "123456"
    },
    {
      "name": "LayerName",
      "value": "%%13312"
    },
    {
      "name": "LayerRTID",
      "value": "44"
    },
    {
      "name": "RemoteUserID",
      "value": "-"
    },
    {
      "name": "RemoteMachineID",
      "value": "-"
    }
  ]
}
```

### EX-SEC-5158 — WFP bind permitted (Security EID 5158)

<!-- covers: SEC-A Security EID 5158 wfp_bind_permitted; ProcessId casing vs 5156 ProcessID; local bind only -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "network",
    "type": "wfp_bind_permitted",
    "action": "permit",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:28:00.000000Z",
    "original": "2026-10-09T13:28:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sec-5158",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 5158,
    "record": {
      "type": "event_record",
      "record_id": 2029
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>5158</EventID><TimeCreated SystemTime='2026-10-09T13:28:00.0000000Z'/><EventRecordID>2029</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='ProcessId'>0x1234</Data><Data Name='Application'>C:\\Tools\\nc.exe</Data><Data Name='SourceAddress'>0.0.0.0</Data><Data Name='SourcePort'>4444</Data><Data Name='Protocol'>6</Data><Data Name='FilterRTID'>654321</Data><Data Name='LayerName'>%%13312</Data><Data Name='LayerRTID'>44</Data></EventData></Event>",
  "network": {
    "protocol": "6",
    "src_ip": "0.0.0.0",
    "src_port": 4444,
    "process": {
      "pid": {
        "$state": "inferred",
        "$note": "hex 0x1234→int (casing ProcessId)",
        "$raw": "0x1234"
      },
      "exe": "C:\\Tools\\nc.exe"
    }
  },
  "unmapped": [
    {
      "name": "FilterRTID",
      "value": "654321"
    },
    {
      "name": "LayerName",
      "value": "%%13312"
    },
    {
      "name": "LayerRTID",
      "value": "44"
    }
  ]
}
```

### EX-SEC-4946 — Firewall rule added (Security EID 4946)

<!-- covers: SEC-A Security EID 4946 firewall_rule_added; derived_by sentinel; RuleId→check, RuleName→source INFERRED -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "firewall_rule_added",
    "action": "add",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:29:00.000000Z",
    "original": "2026-10-09T13:29:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sec-4946",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4946,
    "record": {
      "type": "event_record",
      "record_id": 2030
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4946</EventID><TimeCreated SystemTime='2026-10-09T13:29:00.0000000Z'/><EventRecordID>2030</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='ProfileChanged'>Domain,Private,Public</Data><Data Name='RuleId'>{1a2b3c4d-9999-8888-7777-666655554444}</Data><Data Name='RuleName'>Allow nc</Data></EventData></Event>",
  "config_check": {
    "check": "{1a2b3c4d-9999-8888-7777-666655554444}",
    "status": "pass",
    "source": "Allow nc",
    "observed": "Domain,Private,Public"
  }
}
```

### EX-SEC-4947 — Firewall rule modified (Security EID 4947)

<!-- covers: SEC-A Security EID 4947 firewall_rule_modified; no expected/diff -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "firewall_rule_modified",
    "action": "modify",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:30:00.000000Z",
    "original": "2026-10-09T13:30:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sec-4947",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4947,
    "record": {
      "type": "event_record",
      "record_id": 2031
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4947</EventID><TimeCreated SystemTime='2026-10-09T13:30:00.0000000Z'/><EventRecordID>2031</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='ProfileChanged'>Public</Data><Data Name='RuleId'>{1a2b3c4d-9999-8888-7777-666655554444}</Data><Data Name='RuleName'>Allow nc updated</Data></EventData></Event>",
  "config_check": {
    "check": "{1a2b3c4d-9999-8888-7777-666655554444}",
    "status": "pass",
    "source": "Allow nc updated",
    "observed": "Public"
  }
}
```

### EX-SEC-4948 — Firewall rule deleted (Security EID 4948)

<!-- covers: SEC-A Security EID 4948 firewall_rule_deleted; RuleId stable join key across 4946/4947/4948 -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "firewall_rule_deleted",
    "action": "delete",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:31:00.000000Z",
    "original": "2026-10-09T13:31:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sec-4948",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4948,
    "record": {
      "type": "event_record",
      "record_id": 2032
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4948</EventID><TimeCreated SystemTime='2026-10-09T13:31:00.0000000Z'/><EventRecordID>2032</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='ProfileChanged'>Domain,Private,Public</Data><Data Name='RuleId'>{1a2b3c4d-9999-8888-7777-666655554444}</Data><Data Name='RuleName'>Allow nc</Data></EventData></Event>",
  "config_check": {
    "check": "{1a2b3c4d-9999-8888-7777-666655554444}",
    "status": "pass",
    "source": "Allow nc",
    "observed": "Domain,Private,Public"
  }
}
```

## Other Windows channels (System, PowerShell, WMI, Defender, TaskScheduler, LSM, RCM, AppLocker) (37)

### EX-WIN-7034 — Service crashed (System EID 7034)

<!-- covers: SEC-B System 7034 service_crash; param2=occurrence count (NOT exit code); Binary→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "service",
    "type": "service_crash",
    "action": "terminate",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-09-30T13:25:40.993119Z",
    "original": "2026-09-30T13:25:40.9931197Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {},
  "source": {
    "file_id": "loc-sys-7034",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "System",
    "provider": "Service Control Manager",
    "event_id": 7034,
    "record": {
      "type": "event_record",
      "record_id": 71278
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager'/><EventID Qualifiers='49152'>7034</EventID><TimeCreated SystemTime='2026-09-30T13:25:40.9931197Z'/><EventRecordID>71278</EventRecordID><Channel>System</Channel><Computer>Dhruvs_Victus</Computer><Security/></System><EventData><Data Name='param1'>Claude</Data><Data Name='param2'>1</Data><Binary>43006F0077006F0072006B0056004D0053006500720076006900630065000000</Binary></EventData></Event>",
  "service": {
    "name": "Claude"
  },
  "unmapped": [
    {
      "name": "param2",
      "value": {
        "$state": "null",
        "$note": "occurrence count per B-SYS-ARCHIVE"
      }
    },
    {
      "name": "Binary",
      "value": {
        "$state": "null",
        "$note": "UTF-16LE hex blob; no canonical home"
      }
    }
  ]
}
```

### EX-WIN-7036 — Service state change (System EID 7036)

<!-- covers: SEC-B System 7036 service_state_change; unnamed <Data>[0]=name,[1]=state per B-LOC-HARVEST -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "service",
    "type": "service_state_change",
    "action": "state_change",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T03:14:29.684742Z",
    "original": "2026-10-09T03:14:29.6847423Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {},
  "source": {
    "file_id": "loc-sys-7036",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "System",
    "provider": "VfpExt",
    "event_id": 7036,
    "record": {
      "type": "event_record",
      "record_id": 72886
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='VfpExt'/><EventID Qualifiers='16384'>7036</EventID><TimeCreated SystemTime='2026-10-09T03:14:29.6847423Z'/><EventRecordID>72886</EventRecordID><Channel>System</Channel><Computer>Dhruvs_Victus</Computer><Security/></System><EventData><Data></Data><Data>Filter restart complete</Data><Binary>0000000002002C00000000007C1B0040000000000000000000000000000000000000000000000000</Binary></EventData></Event>",
  "service": {
    "name": {
      "$state": "inferred",
      "$note": "unnamed <Data>[0] positional bind",
      "$raw": ""
    },
    "state": "Filter restart complete"
  },
  "unmapped": [
    {
      "name": "Binary",
      "value": "0000000002002C00000000007C1B0040000000000000000000000000000000000000000000000000"
    }
  ]
}
```

### EX-WIN-7040 — Service start type changed (System EID 7040)

<!-- covers: SEC-B System 7040 service_start_type_change; param2=old, param3=new→start_type; param4 caller unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "service",
    "type": "service_start_type_change",
    "action": "change",
    "outcome": "success",
    "severity": "low",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T03:24:33.009777Z",
    "original": "2026-10-09T03:24:33.0097777Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "sid": "S-1-5-18"
  },
  "source": {
    "file_id": "loc-sys-7040",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "System",
    "provider": "Service Control Manager",
    "event_id": 7040,
    "record": {
      "type": "event_record",
      "record_id": 72925
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager'/><EventID Qualifiers='16384'>7040</EventID><TimeCreated SystemTime='2026-10-09T03:24:33.0097777Z'/><EventRecordID>72925</EventRecordID><Channel>System</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='param1'>Background Intelligent Transfer Service</Data><Data Name='param2'>auto start</Data><Data Name='param3'>demand start</Data><Data Name='param4'>BITS</Data></EventData></Event>",
  "service": {
    "name": "Background Intelligent Transfer Service",
    "start_type": "demand start"
  },
  "unmapped": [
    {
      "name": "param2 old start_type",
      "value": "auto start"
    },
    {
      "name": "param4",
      "value": "BITS"
    }
  ]
}
```

### EX-WIN-7043 — Service terminated unexpectedly (System EID 7043)

<!-- covers: SEC-B System 7043 service_config_change; Binary UTF-16LE→image_path INFERRED -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "service",
    "type": "service_config_change",
    "action": "change",
    "outcome": "success",
    "severity": "low",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-05-28T02:02:10.502078Z",
    "original": "2026-05-28T02:02:10.5020782Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {},
  "source": {
    "file_id": "loc-sys-7043",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "System",
    "provider": "Service Control Manager",
    "event_id": 7043,
    "record": {
      "type": "event_record",
      "record_id": 44369
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager'/><EventID Qualifiers='49152'>7043</EventID><TimeCreated SystemTime='2026-05-28T02:02:10.5020782Z'/><EventRecordID>44369</EventRecordID><Channel>System</Channel><Computer>Dhruvs_Victus</Computer><Security/></System><EventData><Data Name='param1'>Windows Security Service</Data><Binary>530065006300750072006900740079004800650061006C007400680053006500720076006900630065000000</Binary></EventData></Event>",
  "service": {
    "name": "Windows Security Service",
    "image_path": {
      "$state": "inferred",
      "$note": "Binary UTF-16LE hex decoded to SecurityHealthService",
      "$raw": "530065006300750072006900740079004800650061006C007400680053006500720076006900630065000000"
    }
  }
}
```

### EX-WIN-7045 — Service installed (System EID 7045)

<!-- covers: SEC-B System 7045 service_install; VERIFIED-LOCAL element names (no MS page) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "service",
    "type": "service_install",
    "action": "install",
    "outcome": "success",
    "severity": "medium",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T03:16:33.307102Z",
    "original": "2026-10-09T03:16:33.3071024Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "sid": "S-1-5-18"
  },
  "source": {
    "file_id": "loc-sys-7045",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "System",
    "provider": "Service Control Manager",
    "event_id": 7045,
    "record": {
      "type": "event_record",
      "record_id": 72904
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager'/><EventID Qualifiers='16384'>7045</EventID><TimeCreated SystemTime='2026-10-09T03:16:33.3071024Z'/><EventRecordID>72904</EventRecordID><Channel>System</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='ServiceName'>ChatGPT</Data><Data Name='ImagePath'>\"C:\\Program Files\\WindowsApps\\OpenAI.Codex_26.1002.7124.0_x64__2p2nqsd0c76g0\\app\\resources\\codex-windows-sandbox-service.exe\"</Data><Data Name='ServiceType'>user mode service</Data><Data Name='StartType'>auto start</Data><Data Name='AccountName'>LocalSystem</Data></EventData></Event>",
  "service": {
    "name": "ChatGPT",
    "image_path": "\"C:\\Program Files\\WindowsApps\\OpenAI.Codex_26.1002.7124.0_x64__2p2nqsd0c76g0\\app\\resources\\codex-windows-sandbox-service.exe\"",
    "service_type": "user mode service",
    "start_type": "auto start",
    "account_name": "LocalSystem"
  }
}
```

### EX-WIN-104 — Event log cleared (System EID 104)

<!-- covers: SEC-B System 104 log_clear; UNVERIFIED element names (B-PRIOR); param3 VERIFIED slot -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "log_clear",
    "action": "clear",
    "outcome": "success",
    "severity": "medium",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:00:00.000000Z",
    "original": "2026-10-09T14:00:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED candidate SubjectUserName",
      "$raw": "CORP\\jdoe"
    },
    "domain": {
      "$state": "inferred",
      "$note": "UNVERIFIED candidate",
      "$raw": "CORP"
    }
  },
  "source": {
    "file_id": "demo-sys-104",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "System",
    "provider": "Microsoft-Windows-Eventlog",
    "event_id": 104,
    "record": {
      "type": "event_record",
      "record_id": 73000
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog'/><EventID>104</EventID><TimeCreated SystemTime='2026-10-09T14:00:00.0000000Z'/><EventRecordID>73000</EventRecordID><Channel>System</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data>Security</Data><Data>S-1-5-21-1000-2000-3000-1001</Data><Data>CORP\\jdoe</Data><Data>CORP</Data><Data>0x123456</Data></EventData></Event>",
  "config_check": {
    "check": "log_clear",
    "observed": "Security"
  },
  "unmapped": [
    {
      "name": "SubjectUserSid",
      "value": "S-1-5-21-1000-2000-3000-1001"
    },
    {
      "name": "SubjectLogonId",
      "value": "0x123456"
    }
  ]
}
```

### EX-WIN-PS400 — PowerShell engine started (Windows PowerShell EID 400)

<!-- covers: SEC-B PS classic 400 engine_state_change; detail-blob KEY=Value parsed; SequenceNumber unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "powershell",
    "type": "engine_state_change",
    "action": "state_change",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T04:34:39.771168Z",
    "original": "2026-10-09T04:34:39.7711688Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {},
  "source": {
    "file_id": "loc-ps-400",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Windows PowerShell",
    "provider": "PowerShell",
    "event_id": 400,
    "record": {
      "type": "event_record",
      "record_id": 49769
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='PowerShell'/><EventID Qualifiers='0'>400</EventID><TimeCreated SystemTime='2026-10-09T04:34:39.7711688Z'/><EventRecordID>49769</EventRecordID><Channel>Windows PowerShell</Channel><Computer>Dhruvs_Victus</Computer><Security/></System><EventData><Data>Available</Data><Data>None</Data><Data>\tNewEngineState=Available\r\n\tPreviousEngineState=None\r\n\r\n\tSequenceNumber=13\r\n\r\n\tHostName=ConsoleHost\r\n\tHostVersion=5.1.26100.9444\r\n\tHostId=8b5a1d01-7e7a-4bde-ac5e-f65eefe8c287\r\n\tHostApplication=C:\\windows\\System32\\WindowsPowerShell\\v1.0\\powershell.EXE -NoLogo -NoProfile -NonInteractive -Command &amp; \"C:\\Users\\dhruv\\OneDrive\\Desktop\\College\\Light HIDS\\_stage2_work\\harvest_local_events.ps1\"\r\n\tEngineVersion=5.1.26100.9444\r\n\tRunspaceId=3d04b614-6f40-45ef-a245-3edc3a56bf81\r\n\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine=</Data></EventData></Event>",
  "powershell": {
    "engine_state": "Available",
    "previous_engine_state": "None",
    "host_name": "ConsoleHost",
    "host_version": "5.1.26100.9444",
    "host_id": "8b5a1d01-7e7a-4bde-ac5e-f65eefe8c287",
    "host_application": "C:\\windows\\System32\\WindowsPowerShell\\v1.0\\powershell.EXE -NoLogo -NoProfile -NonInteractive -Command & \"C:\\Users\\dhruv\\OneDrive\\Desktop\\College\\Light HIDS\\_stage2_work\\harvest_local_events.ps1\"",
    "engine_version": "5.1.26100.9444",
    "runspace_id": "3d04b614-6f40-45ef-a245-3edc3a56bf81"
  },
  "unmapped": [
    {
      "name": "SequenceNumber",
      "value": "13"
    }
  ]
}
```

### EX-WIN-PS403 — PowerShell engine stopped (Windows PowerShell EID 403)

<!-- covers: SEC-B PS classic 403 engine_state_change -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "powershell",
    "type": "engine_state_change",
    "action": "state_change",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T04:34:15.538511Z",
    "original": "2026-10-09T04:34:15.5385112Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {},
  "source": {
    "file_id": "loc-ps-403",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Windows PowerShell",
    "provider": "PowerShell",
    "event_id": 403,
    "record": {
      "type": "event_record",
      "record_id": 49762
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='PowerShell'/><EventID Qualifiers='0'>403</EventID><TimeCreated SystemTime='2026-10-09T04:34:15.5385112Z'/><EventRecordID>49762</EventRecordID><Channel>Windows PowerShell</Channel><Computer>Dhruvs_Victus</Computer><Security/></System><EventData><Data>Stopped</Data><Data>Available</Data><Data>\tNewEngineState=Stopped\r\n\tPreviousEngineState=Available\r\n\r\n\tSequenceNumber=23\r\n\r\n\tHostName=ConsoleHost\r\n\tHostVersion=5.1.26100.9444\r\n\tHostId=8a5d8a78-6fbd-4b6a-8048-90754f8588b5\r\n\tHostApplication=C:\\windows\\System32\\WindowsPowerShell\\v1.0\\powershell.EXE -NoLogo -NoProfile -NonInteractive -Command python -c \"import jsonschema; print('jsonschema OK', jsonschema.__version__)\"\r\n\tEngineVersion=5.1.26100.9444\r\n\tRunspaceId=5a1a0ee0-50e7-454f-9bfa-5823332390b9\r\n\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine=</Data></EventData></Event>",
  "powershell": {
    "engine_state": "Stopped",
    "previous_engine_state": "Available",
    "host_name": "ConsoleHost",
    "host_version": "5.1.26100.9444",
    "host_id": "8a5d8a78-6fbd-4b6a-8048-90754f8588b5",
    "host_application": "C:\\windows\\System32\\WindowsPowerShell\\v1.0\\powershell.EXE -NoLogo -NoProfile -NonInteractive -Command python -c \"import jsonschema; print('jsonschema OK', jsonschema.__version__)\"",
    "engine_version": "5.1.26100.9444",
    "runspace_id": "5a1a0ee0-50e7-454f-9bfa-5823332390b9"
  },
  "unmapped": [
    {
      "name": "SequenceNumber",
      "value": "23"
    }
  ]
}
```

### EX-WIN-PS600 — Provider started (Windows PowerShell EID 600)

<!-- covers: SEC-B PS classic 600 provider_state_change; new_provider_state -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "powershell",
    "type": "provider_state_change",
    "action": "state_change",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T04:34:39.767848Z",
    "original": "2026-10-09T04:34:39.7678482Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {},
  "source": {
    "file_id": "loc-ps-600",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Windows PowerShell",
    "provider": "PowerShell",
    "event_id": 600,
    "record": {
      "type": "event_record",
      "record_id": 49768
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='PowerShell'/><EventID Qualifiers='0'>600</EventID><TimeCreated SystemTime='2026-10-09T04:34:39.7678482Z'/><EventRecordID>49768</EventRecordID><Channel>Windows PowerShell</Channel><Computer>Dhruvs_Victus</Computer><Security/></System><EventData><Data>Variable</Data><Data>Started</Data><Data>\tProviderName=Variable\r\n\tNewProviderState=Started\r\n\r\n\tSequenceNumber=11\r\n\r\n\tHostName=ConsoleHost\r\n\tHostVersion=5.1.26100.9444\r\n\tHostId=8b5a1d01-7e7a-4bde-ac5e-f65eefe8c287\r\n\tHostApplication=C:\\windows\\System32\\WindowsPowerShell\\v1.0\\powershell.EXE -NoLogo -NoProfile -NonInteractive -Command &amp; \"C:\\Users\\dhruv\\OneDrive\\Desktop\\College\\Light HIDS\\_stage2_work\\harvest_local_events.ps1\"\r\n\tEngineVersion=\r\n\tRunspaceId=\r\n\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine=</Data></EventData></Event>",
  "powershell": {
    "new_provider_state": "Started",
    "previous_engine_state": {
      "$state": "null",
      "$note": "unnamed <Data>[1]"
    },
    "provider_name": "Variable"
  },
  "unmapped": [
    {
      "name": "SequenceNumber",
      "value": "11"
    }
  ]
}
```

### EX-WIN-PS800 — PowerShell pipeline executed (classic EID 800)

<!-- covers: SEC-B PS classic 800; element names UNVERIFIED (B-PRIOR, not found locally) -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "powershell",
    "type": "pipeline_execution",
    "action": "start",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:01:00.000000Z",
    "original": "2026-10-09T14:01:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "demo-ps-800",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Windows PowerShell",
    "provider": "PowerShell",
    "event_id": 800,
    "record": {
      "type": "event_record",
      "record_id": 49900
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='PowerShell'/><EventID>800</EventID><TimeCreated SystemTime='2026-10-09T14:01:00.0000000Z'/><EventRecordID>49900</EventRecordID><Channel>Windows PowerShell</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data>Command started: Get-Process</Data></EventData></Event>",
  "powershell": {
    "payload": {
      "$state": "inferred",
      "$note": "UNVERIFIED element name; message-template param binding",
      "$raw": "Command started: Get-Process"
    }
  }
}
```

### EX-WIN-PS4103 — Module logging (PowerShell/Operational EID 4103)

<!-- covers: SEC-B PS-Op 4103 module_logging; ContextInfo+Payload VERIFIED; UserData→unmapped if populated -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "powershell",
    "type": "module_logging",
    "action": "log",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-09-30T13:31:32.589707Z",
    "original": "2026-09-30T13:31:32.5897071Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "sid": "S-1-5-21-392970859-1592143220-1055403080-1001"
  },
  "source": {
    "file_id": "loc-psop-4103",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-PowerShell/Operational",
    "provider": "Microsoft-Windows-PowerShell",
    "event_id": 4103,
    "record": {
      "type": "event_record",
      "record_id": 67645
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-PowerShell'/><EventID>4103</EventID><TimeCreated SystemTime='2026-09-30T13:31:32.5897071Z'/><EventRecordID>67645</EventRecordID><Channel>Microsoft-Windows-PowerShell/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-21-392970859-1592143220-1055403080-1001'/></System><EventData><Data Name='ContextInfo'>        Severity = Informational\r\n        Host Name = ConsoleHost\r\n        Host Version = 5.1.26100.9444\r\n        Host ID = cd1c8ee3-71a5-42ab-98f7-1f56710b1f0f\r\n        Host Application = powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $ErrorActionPreference='SilentlyContinue'\n$code=@'\nusing System; using System.Runtime.InteropServices;\npublic static class NativeMethods {\n  [DllImport(user32.dll,SetLastError=true,CharSet=CharSet.Auto)]\n  public static extern IntPtr SendMessageTimeout(IntPtr hWnd,uint Msg,UIntPtr wParam,IntPtr lParam,uint fuFlags,uint uTimeout,out UIntPtr lpdwResult);\n}\n'@\nAdd-Type -TypeDefinition $code -ErrorAction SilentlyContinue | Out-Null\n$out=[UIntPtr]::Zero\n[void][NativeMethods]::SendMessageTimeout([IntPtr]0xffff,0x1A,[UIntPtr]::Zero,[IntPtr]::Zero,0x2,5000,[ref]$out)\nStart-Sleep -Milliseconds 200\nGet-Process ShellExperienceHost -ErrorAction SilentlyContinue | Stop-Process -Force\nStart-Sleep -Milliseconds 300\nGet-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force\r\n        Engine Version = 5.1.26100.9444\r\n        Runspace ID = e2b94bfd-ed3e-4f8a-be33-d253e7f1ee0f\r\n        Pipeline ID = 1\r\n        Command Name = Add-Type\r\n        Command Type = Cmdlet\r\n        Script Name = \r\n        Command Path = \r\n        Sequence Number = 23\r\n        User = DHRUVS_VICTUS\\dhruv\r\n        Connected User = \r\n        Shell ID = Microsoft.PowerShell\r\n</Data><Data Name='UserData'></Data><Data Name='Payload'>CommandInvocation(Add-Type): \"Add-Type\"\r\nParameterBinding(Add-Type): name=\"TypeDefinition\"; value=\"using System; using System.Runtime.InteropServices;\npublic static class NativeMethods {\n  [DllImport(user32.dll,SetLastError=true,CharSet=CharSet.Auto)]\n  public static extern IntPtr SendMessageTimeout(IntPtr hWnd,uint Msg,UIntPtr wParam,IntPtr lParam,uint fuFlags,uint uTimeout,out UIntPtr lpdwResult);\n}\"\r\nParameterBinding(Add-Type): name=\"ErrorAction\"; value=\"SilentlyContinue\"\r\nCommandInvocation(Out-Null): \"Out-Null\"\r\nNonTerminatingError(Add-Type): \"c:\\Users\\dhruv\\AppData\\Local\\Temp\\dig12vz1.0.cs(3) : The name 'user32' does not exist in the current context\n\nc:\\Users\\dhruv\\AppData\\Local\\Temp\\dig12vz1.0.cs(2) : public static class NativeMethods {\n\nc:\\Users\\dhruv\\AppData\\Local\\Temp\\dig12vz1.0.cs(3) : &gt;&gt;&gt;   [DllImport(user32.dll,SetLastError=true,CharSet=CharSet.Auto)]\n\nc:\\Users\\dhruv\\AppData\\Local\\Temp\\dig12vz1.0.cs(4) :   public static extern IntPtr SendMessageTimeout(IntPtr hWnd,uint Msg,UIntPtr wParam,IntPtr lParam,uint fuFlags,uint uTimeout,out UIntPtr lpdwResult);\n\"\r\nTerminatingError(Add-Type): \"Cannot add type. Compilation errors occurred.\"\r\n</Data></EventData></Event>",
  "powershell": {
    "context_info": {
      "$state": "inferred",
      "$note": "ContextInfo truncated to first 200 chars for example brevity; full value in raw",
      "$raw": "        Severity = Informational\r\n        Host Name = ConsoleHost\r\n        Host Version = 5.1.26100.9444\r\n        Host ID = cd1c8ee3-71a5-42ab-98f7-1f56710b1f0f\r\n        Host Application = powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $ErrorActionPreference='SilentlyContinue'\n... [truncated in example; full in raw]\n        Command Name = Add-Type\r\n        Command Type = Cmdlet"
    },
    "payload": {
      "$state": "inferred",
      "$note": "Payload CommandInvocation/ParameterBinding text; truncated for example brevity",
      "$raw": "CommandInvocation(Add-Type): \"/bin/Add-Type\""
    }
  }
}
```

### EX-WIN-PS4104 — Script block logging (PowerShell/Operational EID 4104)

<!-- covers: SEC-B PS-Op 4104 script_block_logging; Path=interactive/absent vs file; MessageNumber/Total for reassembly -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "powershell",
    "type": "script_block_logging",
    "action": "log",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-08T16:26:20.010508Z",
    "original": "2026-10-08T16:26:20.0105082Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "sid": "S-1-5-21-392970859-1592143220-1055403080-1001"
  },
  "source": {
    "file_id": "loc-psop-4104",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-PowerShell/Operational",
    "provider": "Microsoft-Windows-PowerShell",
    "event_id": 4104,
    "record": {
      "type": "event_record",
      "record_id": 72802
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-PowerShell'/><EventID>4104</EventID><TimeCreated SystemTime='2026-10-08T16:26:20.0105082Z'/><EventRecordID>72802</EventRecordID><Channel>Microsoft-Windows-PowerShell/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-21-392970859-1592143220-1055403080-1001'/></System><EventData><Data Name='MessageNumber'>1</Data><Data Name='MessageTotal'>1</Data><Data Name='ScriptBlockText'>#!/usr/bin/env pwsh\r\n\r\nSet-StrictMode -Version 'Latest'\r\n\r\n$NODE_EXE=\"$PSScriptRoot/node.exe\"\r\nif (-not (Test-Path $NODE_EXE)) {\r\n  $NODE_EXE=\"$PSScriptRoot/node\"\r\n}\r\nif (-not (Test-Path $NODE_EXE)) {\r\n  $NODE_EXE=\"node\"\r\n}\r\n\r\n$NPM_PREFIX_JS=\"$PSScriptRoot/node_modules/npm/bin/npm-prefix.js\"\r\n$NPM_CLI_JS=\"$PSScriptRoot/node_modules/npm/bin/npm-cli.js\"\r\n$NPM_PREFIX=(&amp; $NODE_EXE $NPM_PREFIX_JS)\r\n\r\nif ($LASTEXITCODE -ne 0) {\r\n  Write-Host \"Could not determine Node.js install directory\"\r\n  exit 1\r\n}\r\n\r\n$NPM_PREFIX_NPM_CLI_JS=\"$NPM_PREFIX/node_modules/npm/bin/npm-cli.js\"\r\nif (Test-Path $NPM_PREFIX_NPM_CLI_JS) {\r\n  $NPM_CLI_JS=$NPM_PREFIX_NPM_CLI_JS\r\n}\r\n\r\nif ($MyInvocation.ExpectingInput) { # takes pipeline input\r\n  $input | &amp; $NODE_EXE $NPM_CLI_JS $args\r\n} elseif (-not $MyInvocation.Line) { # used \"-File\" argument\r\n  &amp; $NODE_EXE $NPM_CLI_JS $args\r\n} else { # used \"-Command\" argument\r\n  if (($MyInvocation | Get-Member -Name 'Statement') -and $MyInvocation.Statement) {\r\n    $NPM_ORIGINAL_COMMAND = $MyInvocation.Statement\r\n  } else {\r\n    $NPM_ORIGINAL_COMMAND = (\r\n      [Management.Automation.InvocationInfo].GetProperty('ScriptPosition', [Reflection.BindingFlags] 'Instance, NonPublic')\r\n    ).GetValue($MyInvocation).Text\r\n  }\r\n\r\n  $NODE_EXE = $NODE_EXE.Replace(\"\u0060\u0060\", \"\u0060\u0060\u0060\u0060\")\r\n  $NPM_CLI_JS = $NPM_CLI_JS.Replace(\"\u0060\u0060\", \"\u0060\u0060\u0060\u0060\")\r\n\r\n  $NPM_COMMAND_ARRAY = [Management.Automation.Language.Parser]::ParseInput($NPM_ORIGINAL_COMMAND, [ref] $null, [ref] $null).\r\n    EndBlock.Statements.PipelineElements.CommandElements.Extent.Text\r\n  $NPM_ARGS = ($NPM_COMMAND_ARRAY | Select-Object -Skip 1) -join ' '\r\n\r\n  Invoke-Expression \"&amp; \u0060\"$NODE_EXE\u0060\" \u0060\"$NPM_CLI_JS\u0060\" $NPM_ARGS\"\r\n}\r\n\r\nexit $LASTEXITCODE\r\n</Data><Data Name='ScriptBlockId'>d8bf42e3-4f0c-46c9-8794-41d6bf5ba3e0</Data><Data Name='Path'>C:\\Program Files\\nodejs\\npm.ps1</Data></EventData></Event>",
  "powershell": {
    "message_number": 1,
    "message_total": 1,
    "script_block_text": {
      "$state": "inferred",
      "$note": "ScriptBlockText truncated to first 200 chars for example brevity; full value in raw",
      "$raw": "#!/usr/bin/env pwsh\r\n\r\nSet-StrictMode -Version 'Latest'\r\n\r\n$NODE_EXE=\"$PSScriptRoot/node.exe\"\nif (-not (Test-Path $NODE_EXE)) {\n  $NODE_EXE=\"$PSScriptRoot/node\"\n}\n... [truncated in example; full in raw]\n"
    },
    "script_block_id": "0a1b2c3d-4e5f-6789-abcd-ef0123456789",
    "script_path": "C:\\Program Files\\nodejs\\npm.ps1"
  }
}
```

### EX-WIN-PS4105 — Pipeline execution start (PowerShell/Operational EID 4105)

<!-- covers: SEC-B PS-Op 4105 pipeline_execution start; element names VERIFIED-by-manifest only (B-PS-MANIFEST, no local sample) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "powershell",
    "type": "pipeline_execution",
    "action": "start",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:02:00.000000Z",
    "original": "2026-10-09T14:02:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001"
  },
  "source": {
    "file_id": "demo-psop-4105",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-PowerShell/Operational",
    "provider": "Microsoft-Windows-PowerShell",
    "event_id": 4105,
    "record": {
      "type": "event_record",
      "record_id": 72803
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-PowerShell'/><EventID>4105</EventID><TimeCreated SystemTime='2026-10-09T14:02:00.0000000Z'/><EventRecordID>72803</EventRecordID><Channel>Microsoft-Windows-PowerShell/Operational</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-21-1000-2000-3000-1001'/></System><EventData><Data Name='ScriptBlockId'>0a1b2c3d-4e5f-6789-abcd-ef0123456789</Data><Data Name='RunspaceId'>e2b94bfd-ed3e-4f8a-be33-d253e7f1ee0f</Data></EventData></Event>",
  "powershell": {
    "script_block_id": "0a1b2c3d-4e5f-6789-abcd-ef0123456789",
    "runspace_id": "e2b94bfd-ed3e-4f8a-be33-d253e7f1ee0f"
  }
}
```

### EX-WIN-PS4106 — Pipeline execution stop (PowerShell/Operational EID 4106)

<!-- covers: SEC-B PS-Op 4106 pipeline_execution stop; manifest-only element names -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "powershell",
    "type": "pipeline_execution",
    "action": "stop",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:02:05.000000Z",
    "original": "2026-10-09T14:02:05.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001"
  },
  "source": {
    "file_id": "demo-psop-4106",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-PowerShell/Operational",
    "provider": "Microsoft-Windows-PowerShell",
    "event_id": 4106,
    "record": {
      "type": "event_record",
      "record_id": 72804
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-PowerShell'/><EventID>4106</EventID><TimeCreated SystemTime='2026-10-09T14:02:00.0000000Z'/><EventRecordID>72804</EventRecordID><Channel>Microsoft-Windows-PowerShell/Operational</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-21-1000-2000-3000-1001'/></System><EventData><Data Name='ScriptBlockId'>0a1b2c3d-4e5f-6789-abcd-ef0123456789</Data><Data Name='RunspaceId'>e2b94bfd-ed3e-4f8a-be33-d253e7f1ee0f</Data></EventData></Event>",
  "powershell": {
    "script_block_id": "0a1b2c3d-4e5f-6789-abcd-ef0123456789",
    "runspace_id": "e2b94bfd-ed3e-4f8a-be33-d253e7f1ee0f"
  }
}
```

### EX-WIN-WMI5857 — WMI operation started (WMI-Activity EID 5857)

<!-- covers: SEC-B WMI 5857 wmi_operation; ProcessID casing trap; HostProcess/ProviderPath→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "wmi",
    "type": "wmi_operation",
    "action": "connect",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T04:34:14.174730Z",
    "original": "2026-10-09T04:34:14.1747309Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {},
  "source": {
    "file_id": "loc-wmi-5857",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-WMI-Activity/Operational",
    "provider": "Microsoft-Windows-WMI-Activity",
    "event_id": 5857,
    "record": {
      "type": "event_record",
      "record_id": 289056
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-WMI-Activity'/><EventID>5857</EventID><TimeCreated SystemTime='2026-10-09T04:34:14.1747309Z'/><EventRecordID>289056</EventRecordID><Channel>Microsoft-Windows-WMI-Activity/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-20'/></System><UserData><Operation_StartedOperational xmlns='http://manifests.microsoft.com/win/2006/windows/WMI'><ProviderName>CIMWin32</ProviderName><Code>0x0</Code><HostProcess>wmiprvse.exe</HostProcess><ProcessID>13660</ProcessID><ProviderPath>%systemroot%\\system32\\wbem\\cimwin32.dll</ProviderPath></Operation_StartedOperational></UserData></Event>",
  "wmi": {
    "provider_name": "CIMWin32",
    "result_code": "0x0"
  },
  "unmapped": [
    {
      "name": "HostProcess",
      "value": "wmiprvse.exe"
    },
    {
      "name": "ProcessID",
      "value": "13660"
    },
    {
      "name": "ProviderPath",
      "value": "%systemroot%\\system32\\wbem\\cimwin32.dll"
    }
  ]
}
```

### EX-WIN-WMI5858 — WMI client failure (WMI-Activity EID 5858)

<!-- covers: SEC-B WMI 5858 wmi_client_failure; Id/Component/PossibleCause unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "wmi",
    "type": "wmi_client_failure",
    "action": "connect",
    "outcome": "failure",
    "severity": "low",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T04:34:33.450413Z",
    "original": "2026-10-09T04:34:33.4504134Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "sid": "S-1-5-18"
  },
  "source": {
    "file_id": "loc-wmi-5858",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-WMI-Activity/Operational",
    "provider": "Microsoft-Windows-WMI-Activity",
    "event_id": 5858,
    "record": {
      "type": "event_record",
      "record_id": 289057
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-WMI-Activity'/><EventID>5858</EventID><TimeCreated SystemTime='2026-10-09T04:34:33.4504134Z'/><EventRecordID>289057</EventRecordID><Channel>Microsoft-Windows-WMI-Activity/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><UserData><Operation_ClientFailure xmlns='http://manifests.microsoft.com/win/2006/windows/WMI'><Id>{00000000-0000-0000-0000-000000000000}</Id><ClientMachine>DHRUVS_VICTUS</ClientMachine><User>NT AUTHORITY\\SYSTEM</User><ClientProcessId>3660</ClientProcessId><Component>Unknown</Component><Operation>Start IWbemServices::CreateInstanceEnum - root\\wmi : HpqBIntM</Operation><ResultCode>0x80041032</ResultCode><PossibleCause>Unknown</PossibleCause></Operation_ClientFailure></UserData></Event>",
  "wmi": {
    "client_machine": "DHRUVS_VICTUS",
    "client_user": "NT AUTHORITY\\SYSTEM",
    "client_process_id": "3660",
    "operation": "Start IWbemServices::CreateInstanceEnum - root\\wmi : HpqBIntM",
    "result_code": "0x80041032"
  },
  "unmapped": [
    {
      "name": "Id",
      "value": "{00000000-0000-0000-0000-000000000000}"
    },
    {
      "name": "Component",
      "value": "Unknown"
    },
    {
      "name": "PossibleCause",
      "value": "Unknown"
    }
  ]
}
```

### EX-WIN-WMI5860 — WMI temporary ESS started (WMI-Activity EID 5860)

<!-- covers: SEC-B WMI 5860; Processid lowercase-d casing trap vs 5857 ProcessID; PossibleCause unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "wmi",
    "type": "wmi_operation",
    "action": "connect",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T03:17:56.173368Z",
    "original": "2026-10-09T03:17:56.1733684Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "name": "dhruv",
    "domain": "Dhruvs_Victus"
  },
  "source": {
    "file_id": "loc-wmi-5860",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-WMI-Activity/Operational",
    "provider": "Microsoft-Windows-WMI-Activity",
    "event_id": 5860,
    "record": {
      "type": "event_record",
      "record_id": 288722
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-WMI-Activity'/><EventID>5860</EventID><TimeCreated SystemTime='2026-10-09T03:17:56.1733684Z'/><EventRecordID>288722</EventRecordID><Channel>Microsoft-Windows-WMI-Activity/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><UserData><Operation_TemporaryEssStarted xmlns='http://manifests.microsoft.com/win/2006/windows/WMI'><NamespaceName>root\\wmi</NamespaceName><Query>select * from hpqbevnt</Query><User>Dhruvs_Victus\\dhruv</User><Processid>20272</Processid><ClientMachine>DHRUVS_VICTUS</ClientMachine><PossibleCause>Temporary</PossibleCause></Operation_TemporaryEssStarted></UserData></Event>",
  "wmi": {
    "namespace": "root\\wmi",
    "query": "select * from hpqbevnt",
    "client_user": "Dhruvs_Victus\\dhruv",
    "client_machine": "DHRUVS_VICTUS"
  },
  "unmapped": [
    {
      "name": "Processid",
      "value": "20272"
    },
    {
      "name": "PossibleCause",
      "value": "Temporary"
    }
  ]
}
```

### EX-WIN-DEF1116 — Malware detected (Defender EID 1116)

<!-- covers: SEC-B Defender 1116 malware_detected; 42-element set VERIFIED-LOCAL; severity=high from Severity ID 4 -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "third_party_alert",
    "type": "malware_detected",
    "action": "detect",
    "outcome": "success",
    "severity": "high",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-08T14:55:43.556373Z",
    "original": "2026-10-08T14:55:43.5563739Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "Detection User field",
      "$raw": "Dhruvs_Victus\\dhruv"
    }
  },
  "source": {
    "file_id": "loc-def-1116",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Windows Defender/Operational",
    "provider": "Microsoft-Windows-Windows Defender",
    "event_id": 1116,
    "record": {
      "type": "event_record",
      "record_id": 5432
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Windows Defender'/><EventID>1116</EventID><TimeCreated SystemTime='2026-10-08T14:55:43.5563739Z'/><EventRecordID>5432</EventRecordID><Channel>Microsoft-Windows-Windows Defender/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='Product Name'>Microsoft Defender Antivirus</Data><Data Name='Product Version'>4.18.26080.4</Data><Data Name='Detection ID'>{CDF36DC1-A236-4131-A603-00FFE0588A74}</Data><Data Name='Detection Time'>2026-10-08T14:55:43.466Z</Data><Data Name='Unused'></Data><Data Name='Unused2'></Data><Data Name='Threat ID'>2147725066</Data><Data Name='Threat Name'>HackTool:PowerShell/Mimikatz</Data><Data Name='Severity ID'>4</Data><Data Name='Severity Name'>High</Data><Data Name='Category ID'>34</Data><Data Name='Category Name'>Tool</Data><Data Name='FWLink'>https://go.microsoft.com/fwlink/?linkid=37020&amp;name=HackTool:PowerShell/Mimikatz&amp;threatid=2147725066&amp;enterprise=0</Data><Data Name='Status Code'>1</Data><Data Name='Status Description'></Data><Data Name='State'>1</Data><Data Name='Source ID'>3</Data><Data Name='Source Name'>Real-Time Protection</Data><Data Name='Process Name'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data><Data Name='Detection User'>Dhruvs_Victus\\dhruv</Data><Data Name='Unused3'></Data><Data Name='Path'>file:_C:\\Users\\dhruv\\AppData\\Local\\Temp\\opencode\\research\\velociraptor-docs\\content\\knowledge_base\\tips\\decimaldecode.md</Data><Data Name='Origin ID'>1</Data><Data Name='Origin Name'>Local machine</Data><Data Name='Execution ID'>1</Data><Data Name='Execution Name'>Suspended</Data><Data Name='Type ID'>0</Data><Data Name='Type Name'>Concrete</Data><Data Name='Pre Execution Status'>0</Data><Data Name='Action ID'>9</Data><Data Name='Action Name'>Not Applicable</Data><Data Name='Unused4'></Data><Data Name='Error Code'>0x00000000</Data><Data Name='Error Description'>The operation completed successfully. </Data><Data Name='Unused5'></Data><Data Name='Post Clean Status'>0</Data><Data Name='Additional Actions ID'>0</Data><Data Name='Additional Actions String'>No additional actions required</Data><Data Name='Remediation User'></Data><Data Name='Unused6'></Data><Data Name='Security intelligence Version'>AV: 1.459.601.0, AS: 1.459.601.0, NIS: 1.459.601.0</Data><Data Name='Engine Version'>AM: 1.1.26080.3, NIS: 1.1.26080.3</Data></EventData></Event>",
  "third_party_alert": {
    "vendor": "Microsoft",
    "product": "Microsoft Defender Antivirus",
    "rule_name": "HackTool:PowerShell/Mimikatz",
    "category": "Tool",
    "severity_raw": "4 (High)",
    "description": {
      "$state": "inferred",
      "$note": "Status Description empty; description from Threat Name/category",
      "$raw": "HackTool:PowerShell/Mimikatz"
    }
  },
  "process": {
    "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "owner_name": {
      "$state": "inferred",
      "$note": "Detection User",
      "$raw": "Dhruvs_Victus\\dhruv"
    }
  },
  "file": {
    "path": "C:\\Users\\dhruv\\AppData\\Local\\Temp\\opencode\\research\\velociraptor-docs\\content\\knowledge_base\\tips\\decimaldecode.md"
  },
  "unmapped": [
    {
      "name": "Product Version",
      "value": "4.18.26080.4"
    },
    {
      "name": "Detection ID",
      "value": "{CDF36DC1-A236-4131-A603-00FFE0588A74}"
    },
    {
      "name": "Threat ID",
      "value": "2147725066"
    },
    {
      "name": "FWLink",
      "value": "https://go.microsoft.com/fwlink/?linkid=37020&name=HackTool:PowerShell/Mimikatz&threatid=2147725066&enterprise=0"
    },
    {
      "name": "Status Code",
      "value": "1"
    },
    {
      "name": "State",
      "value": "1"
    },
    {
      "name": "Source Name",
      "value": "Real-Time Protection"
    },
    {
      "name": "Origin Name",
      "value": "Local machine"
    },
    {
      "name": "Type Name",
      "value": "SingleFile"
    }
  ]
}
```

### EX-WIN-DEF1117 — Malware action taken (Defender EID 1117)

<!-- covers: SEC-B Defender 1117 malware_action; derived_by sentinel (file/quarantine outcome) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "malware_action",
    "action": "quarantine",
    "outcome": "success",
    "severity": "high",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-08T14:56:49.230758Z",
    "original": "2026-10-08T14:56:49.2307586Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "Detection User",
      "$raw": "Dhruvs_Victus\\dhruv"
    }
  },
  "source": {
    "file_id": "loc-def-1117",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Windows Defender/Operational",
    "provider": "Microsoft-Windows-Windows Defender",
    "event_id": 1117,
    "record": {
      "type": "event_record",
      "record_id": 5433
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Windows Defender'/><EventID>1117</EventID><TimeCreated SystemTime='2026-10-08T14:56:49.2307586Z'/><EventRecordID>5433</EventRecordID><Channel>Microsoft-Windows-Windows Defender/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='Product Name'>Microsoft Defender Antivirus</Data><Data Name='Product Version'>4.18.26080.4</Data><Data Name='Detection ID'>{CDF36DC1-A236-4131-A603-00FFE0588A74}</Data><Data Name='Detection Time'>2026-10-08T14:55:43.466Z</Data><Data Name='Unused'></Data><Data Name='Unused2'></Data><Data Name='Threat ID'>2147725066</Data><Data Name='Threat Name'>HackTool:PowerShell/Mimikatz</Data><Data Name='Severity ID'>4</Data><Data Name='Severity Name'>High</Data><Data Name='Category ID'>34</Data><Data Name='Category Name'>Tool</Data><Data Name='FWLink'>https://go.microsoft.com/fwlink/?linkid=37020&amp;name=HackTool:PowerShell/Mimikatz&amp;threatid=2147725066&amp;enterprise=0</Data><Data Name='Status Code'>3</Data><Data Name='Status Description'></Data><Data Name='State'>2</Data><Data Name='Source ID'>3</Data><Data Name='Source Name'>Real-Time Protection</Data><Data Name='Process Name'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data><Data Name='Detection User'>Dhruvs_Victus\\dhruv</Data><Data Name='Unused3'></Data><Data Name='Path'>file:_C:\\Users\\dhruv\\AppData\\Local\\Temp\\opencode\\research\\velociraptor-docs\\content\\knowledge_base\\tips\\decimaldecode.md</Data><Data Name='Origin ID'>1</Data><Data Name='Origin Name'>Local machine</Data><Data Name='Execution ID'>1</Data><Data Name='Execution Name'>Suspended</Data><Data Name='Type ID'>0</Data><Data Name='Type Name'>Concrete</Data><Data Name='Pre Execution Status'>0</Data><Data Name='Action ID'>2</Data><Data Name='Action Name'>Quarantine</Data><Data Name='Unused4'></Data><Data Name='Error Code'>0x00000000</Data><Data Name='Error Description'>The operation completed successfully. </Data><Data Name='Unused5'></Data><Data Name='Post Clean Status'>0</Data><Data Name='Additional Actions ID'>0</Data><Data Name='Additional Actions String'>No additional actions required</Data><Data Name='Remediation User'>NT AUTHORITY\\SYSTEM</Data><Data Name='Unused6'></Data><Data Name='Security intelligence Version'>AV: 1.459.601.0, AS: 1.459.601.0, NIS: 1.459.601.0</Data><Data Name='Engine Version'>AM: 1.1.26080.3, NIS: 1.1.26080.3</Data></EventData></Event>",
  "third_party_alert": {
    "vendor": "Microsoft",
    "product": "Microsoft Defender Antivirus",
    "rule_name": "HackTool:PowerShell/Mimikatz",
    "category": "Tool",
    "severity_raw": "4 (High)",
    "mitigation": {
      "$state": "inferred",
      "$note": "Action Name field",
      "$raw": "Quarantine"
    }
  },
  "process": {
    "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "owner_name": {
      "$state": "inferred",
      "$note": "Detection User",
      "$raw": "Dhruvs_Victus\\dhruv"
    }
  },
  "file": {
    "path": "C:\\Users\\dhruv\\AppData\\Local\\Temp\\opencode\\research\\velociraptor-docs\\content\\knowledge_base\\tips\\decimaldecode.md"
  },
  "unmapped": [
    {
      "name": "Product Version",
      "value": "4.18.26080.4"
    },
    {
      "name": "Detection ID",
      "value": "{CDF36DC1-A236-4131-A603-00FFE0588A74}"
    },
    {
      "name": "Threat ID",
      "value": "2147725066"
    },
    {
      "name": "Status Code",
      "value": "3"
    },
    {
      "name": "State",
      "value": "2"
    },
    {
      "name": "Action ID",
      "value": "2"
    },
    {
      "name": "Action Name",
      "value": "Quarantine"
    }
  ]
}
```

### EX-WIN-DEF5001 — Real-time protection disabled (Defender EID 5001)

<!-- covers: SEC-B Defender 5001 realtime_protection_disabled; config_check derived_by sentinel -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "realtime_protection_disabled",
    "action": "disable",
    "outcome": "success",
    "severity": "high",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2025-10-22T11:25:39.109797Z",
    "original": "2025-10-22T11:25:39.1097979Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "sid": "S-1-5-18"
  },
  "source": {
    "file_id": "loc-def-5001",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Windows Defender/Operational",
    "provider": "Microsoft-Windows-Windows Defender",
    "event_id": 5001,
    "record": {
      "type": "event_record",
      "record_id": 126
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Windows Defender'/><EventID>5001</EventID><TimeCreated SystemTime='2025-10-22T11:25:39.1097979Z'/><EventRecordID>126</EventRecordID><Channel>Microsoft-Windows-Windows Defender/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='Product Name'>Microsoft Defender Antivirus</Data><Data Name='Product Version'>4.18.24090.11</Data></EventData></Event>",
  "third_party_alert": {
    "product": "Microsoft Defender Antivirus"
  },
  "config_check": {
    "check": "realtime_protection",
    "status": "fail",
    "observed": {
      "$state": "inferred",
      "$note": "5001 EventData has only Product Name/Version; disable state from event type",
      "$raw": "real-time protection disabled"
    }
  }
}
```

### EX-WIN-DEF5007 — Defender settings changed (Defender EID 5007)

<!-- covers: SEC-B Defender 5007 settings_change; Old Value→unmapped, New Value→config_check.observed -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "settings_change",
    "action": "change",
    "outcome": "success",
    "severity": "low",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T03:32:46.387776Z",
    "original": "2026-10-09T03:32:46.3877763Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "sid": "S-1-5-18"
  },
  "source": {
    "file_id": "loc-def-5007",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Windows Defender/Operational",
    "provider": "Microsoft-Windows-Windows Defender",
    "event_id": 5007,
    "record": {
      "type": "event_record",
      "record_id": 5460
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Windows Defender'/><EventID>5007</EventID><TimeCreated SystemTime='2026-10-09T03:32:46.3877763Z'/><EventRecordID>5460</EventRecordID><Channel>Microsoft-Windows-Windows Defender/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='Product Name'>Microsoft Defender Antivirus</Data><Data Name='Product Version'>4.18.26080.4</Data><Data Name='Old Value'>HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\CoreService\\WdConfigHash = 0xDA61671A</Data><Data Name='New Value'>HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\CoreService\\WdConfigHash = 0x100D2E74</Data></EventData></Event>",
  "third_party_alert": {
    "product": "Microsoft Defender Antivirus"
  },
  "config_check": {
    "check": "defender_settings",
    "observed": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\CoreService\\WdConfigHash = 0x100D2E74"
  },
  "unmapped": [
    {
      "name": "Product Version",
      "value": "4.18.26080.4"
    },
    {
      "name": "Old Value",
      "value": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\CoreService\\WdConfigHash = 0xDA61671A"
    }
  ]
}
```

### EX-WIN-TS106 — Task registered (TaskScheduler EID 106)

<!-- covers: SEC-B TaskScheduler 106 task_register; ALL element names UNVERIFIED (B-COMMUNITY/B-PRIOR; channel disabled locally) -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "scheduled_task",
    "type": "task_register",
    "action": "register",
    "outcome": "success",
    "severity": "low",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:03:00.000000Z",
    "original": "2026-10-09T14:03:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED UserContext candidate",
      "$raw": "CORP\\jdoe"
    },
    "domain": {
      "$state": "inferred",
      "$note": "UNVERIFIED",
      "$raw": "CORP"
    }
  },
  "source": {
    "file_id": "demo-ts-106",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TaskScheduler/Operational",
    "provider": "Microsoft-Windows-TaskScheduler",
    "event_id": 106,
    "record": {
      "type": "event_record",
      "record_id": 9001
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TaskScheduler'/><EventID>106</EventID><TimeCreated SystemTime='2026-10-09T14:03:00.0000000Z'/><EventRecordID>9001</EventRecordID><Channel>Microsoft-Windows-TaskScheduler/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='ActionName'>C:\\Temp\\evil.exe</Data><Data Name='TaskName'>\\Updater</Data><Data Name='TaskPath'>\\</Data><Data Name='UserContext'>CORP\\jdoe</Data></EventData></Event>",
  "scheduled_task": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED element name (B-PRIOR)",
      "$raw": "\\Updater"
    },
    "path": {
      "$state": "inferred",
      "$note": "UNVERIFIED",
      "$raw": "\\"
    }
  }
}
```

### EX-WIN-TS140 — Task registration updated (TaskScheduler EID 140)

<!-- covers: SEC-B TaskScheduler 140 task_update; UNVERIFIED element names -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "scheduled_task",
    "type": "task_update",
    "action": "change",
    "outcome": "success",
    "severity": "low",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:03:10.000000Z",
    "original": "2026-10-09T14:03:10.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED UserContext",
      "$raw": "CORP\\jdoe"
    },
    "domain": {
      "$state": "inferred",
      "$raw": "CORP"
    }
  },
  "source": {
    "file_id": "demo-ts-140",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TaskScheduler/Operational",
    "provider": "Microsoft-Windows-TaskScheduler",
    "event_id": 140,
    "record": {
      "type": "event_record",
      "record_id": 9002
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TaskScheduler'/><EventID>140</EventID><TimeCreated SystemTime='2026-10-09T14:03:10.0000000Z'/><EventRecordID>9002</EventRecordID><Channel>Microsoft-Windows-TaskScheduler/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='TaskName'>\\Updater</Data><Data Name='TaskPath'>\\</Data><Data Name='UserContext'>CORP\\jdoe</Data><Data Name='Author'>CORP\\jdoe</Data></EventData></Event>",
  "scheduled_task": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED",
      "$raw": "\\Updater"
    },
    "path": {
      "$state": "inferred",
      "$raw": "\\"
    },
    "author": {
      "$state": "inferred",
      "$note": "UNVERIFIED Author",
      "$raw": "CORP\\jdoe"
    }
  }
}
```

### EX-WIN-TS141 — Task registration deleted (TaskScheduler EID 141)

<!-- covers: SEC-B TaskScheduler 141 task_delete; UNVERIFIED element names -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "scheduled_task",
    "type": "task_delete",
    "action": "delete",
    "outcome": "success",
    "severity": "low",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:03:20.000000Z",
    "original": "2026-10-09T14:03:20.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED UserContext",
      "$raw": "CORP\\jdoe"
    },
    "domain": {
      "$state": "inferred",
      "$raw": "CORP"
    }
  },
  "source": {
    "file_id": "demo-ts-141",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TaskScheduler/Operational",
    "provider": "Microsoft-Windows-TaskScheduler",
    "event_id": 141,
    "record": {
      "type": "event_record",
      "record_id": 9003
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TaskScheduler'/><EventID>141</EventID><TimeCreated SystemTime='2026-10-09T14:03:20.0000000Z'/><EventRecordID>9003</EventRecordID><Channel>Microsoft-Windows-TaskScheduler/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='TaskName'>\\Updater</Data><Data Name='TaskPath'>\\</Data><Data Name='UserContext'>CORP\\jdoe</Data></EventData></Event>",
  "scheduled_task": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED",
      "$raw": "\\Updater"
    },
    "path": {
      "$state": "inferred",
      "$raw": "\\"
    }
  }
}
```

### EX-WIN-TS200 — Scheduled task executed (TaskScheduler EID 200)

<!-- covers: SEC-B TaskScheduler 200 task_action_start; UNVERIFIED element names; Path→command INFERRED -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "scheduled_task",
    "type": "task_action_start",
    "action": "start",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:03:30.000000Z",
    "original": "2026-10-09T14:03:30.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "demo-ts-200",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TaskScheduler/Operational",
    "provider": "Microsoft-Windows-TaskScheduler",
    "event_id": 200,
    "record": {
      "type": "event_record",
      "record_id": 9004
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TaskScheduler'/><EventID>200</EventID><TimeCreated SystemTime='2026-10-09T14:03:30.0000000Z'/><EventRecordID>9004</EventRecordID><Channel>Microsoft-Windows-TaskScheduler/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='ActionName'>C:\\Temp\\evil.exe</Data><Data Name='TaskName'>\\Updater</Data><Data Name='TaskPath'>\\</Data></EventData></Event>",
  "scheduled_task": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED TaskName",
      "$raw": "\\Updater"
    },
    "command": {
      "$state": "inferred",
      "$note": "UNVERIFIED ActionName→command",
      "$raw": "C:\\Temp\\evil.exe"
    }
  }
}
```

### EX-WIN-TS201 — Scheduled task completed (TaskScheduler EID 201)

<!-- covers: SEC-B TaskScheduler 201 task_action_complete; UNVERIFIED element names -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "scheduled_task",
    "type": "task_action_complete",
    "action": "complete",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:03:40.000000Z",
    "original": "2026-10-09T14:03:40.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "demo-ts-201",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TaskScheduler/Operational",
    "provider": "Microsoft-Windows-TaskScheduler",
    "event_id": 201,
    "record": {
      "type": "event_record",
      "record_id": 9005
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TaskScheduler'/><EventID>201</EventID><TimeCreated SystemTime='2026-10-09T14:03:40.0000000Z'/><EventRecordID>9005</EventRecordID><Channel>Microsoft-Windows-TaskScheduler/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='ActionName'>C:\\Temp\\evil.exe</Data><Data Name='TaskName'>\\Updater</Data><Data Name='TaskPath'>\\</Data><Data Name='ResultCode'>0</Data></EventData></Event>",
  "scheduled_task": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED TaskName",
      "$raw": "\\Updater"
    },
    "result_code": {
      "$state": "inferred",
      "$note": "UNVERIFIED ResultCode",
      "$raw": "0"
    }
  }
}
```

### EX-WIN-LSM21 — Session logon (LSM EID 21)

<!-- covers: SEC-B LSM 21 session_logon; SessionID→unmapped; Address LOCAL→invalid state; DFIR semantics (21=logon) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "session_logon",
    "action": "logon",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T03:15:59.822772Z",
    "original": "2026-10-09T03:15:59.8227726Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UserData/User DOMAIN\\user",
      "$raw": "DHRUVS_VICTUS\\dhruv"
    },
    "domain": "DHRUVS_VICTUS"
  },
  "source": {
    "file_id": "loc-lsm-21",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "provider": "Microsoft-Windows-TerminalServices-LocalSessionManager",
    "event_id": 21,
    "record": {
      "type": "event_record",
      "record_id": 3370
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager'/><EventID>21</EventID><TimeCreated SystemTime='2026-10-09T03:15:59.8227726Z'/><EventRecordID>3370</EventRecordID><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><UserData><EventXML xmlns='Event_NS'><User>DHRUVS_VICTUS\\dhruv</User><SessionID>26</SessionID><Address>LOCAL</Address></EventXML></UserData></Event>",
  "authentication": {
    "logon_id": {
      "$state": "inferred",
      "$note": "SessionID mapped to logon_id (session identifier, INFERRED)",
      "$raw": "26"
    }
  },
  "network": {
    "src_ip": {
      "$state": "invalid",
      "$note": "LSM renders literal 'LOCAL' for console sessions — not an IP",
      "$raw": "LOCAL"
    }
  }
}
```

### EX-WIN-LSM22 — Shell start notification (LSM EID 22)

<!-- covers: SEC-B LSM 22; DFIR semantics: 22='Shell start notification received' (diverges from SEC-B logoff label) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "session_shell_start",
    "action": "shell_start",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T03:16:01.732713Z",
    "original": "2026-10-09T03:16:01.7327133Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UserData/User DOMAIN\\user",
      "$raw": "DHRUVS_VICTUS\\dhruv"
    },
    "domain": "DHRUVS_VICTUS"
  },
  "source": {
    "file_id": "loc-lsm-22",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "provider": "Microsoft-Windows-TerminalServices-LocalSessionManager",
    "event_id": 22,
    "record": {
      "type": "event_record",
      "record_id": 3371
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager'/><EventID>22</EventID><TimeCreated SystemTime='2026-10-09T03:16:01.7327133Z'/><EventRecordID>3371</EventRecordID><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><UserData><EventXML xmlns='Event_NS'><User>DHRUVS_VICTUS\\dhruv</User><SessionID>26</SessionID><Address>LOCAL</Address></EventXML></UserData></Event>",
  "authentication": {
    "logon_id": {
      "$state": "inferred",
      "$note": "SessionID mapped to logon_id (INFERRED)",
      "$raw": "26"
    }
  },
  "network": {
    "src_ip": {
      "$state": "invalid",
      "$note": "LSM 'LOCAL' literal — not an IP",
      "$raw": "LOCAL"
    }
  }
}
```

### EX-WIN-LSM23 — Session logoff (LSM EID 23)

<!-- covers: SEC-B LSM 23 logoff; NO Address on 23 (only User+SessionID) — do not expect src_ip -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "session_logoff",
    "action": "logoff",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-08T17:07:21.494425Z",
    "original": "2026-10-08T17:07:21.4944255Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UserData/User DOMAIN\\user",
      "$raw": "DHRUVS_VICTUS\\dhruv"
    },
    "domain": "DHRUVS_VICTUS"
  },
  "source": {
    "file_id": "loc-lsm-23",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "provider": "Microsoft-Windows-TerminalServices-LocalSessionManager",
    "event_id": 23,
    "record": {
      "type": "event_record",
      "record_id": 3363
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager'/><EventID>23</EventID><TimeCreated SystemTime='2026-10-08T17:07:21.4944255Z'/><EventRecordID>3363</EventRecordID><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><UserData><EventXML xmlns='Event_NS'><User>DHRUVS_VICTUS\\dhruv</User><SessionID>25</SessionID></EventXML></UserData></Event>",
  "authentication": {
    "logon_id": {
      "$state": "inferred",
      "$note": "SessionID mapped to logon_id (INFERRED); no Address on EID 23",
      "$raw": "25"
    }
  }
}
```

### EX-WIN-LSM24 — Session disconnected (LSM EID 24)

<!-- covers: SEC-B LSM 24 disconnect; DFIR semantics (24=disconnect) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "session_disconnect",
    "action": "disconnect",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-08T17:07:21.557158Z",
    "original": "2026-10-08T17:07:21.5571582Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UserData/User DOMAIN\\user",
      "$raw": "DHRUVS_VICTUS\\dhruv"
    },
    "domain": "DHRUVS_VICTUS"
  },
  "source": {
    "file_id": "loc-lsm-24",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "provider": "Microsoft-Windows-TerminalServices-LocalSessionManager",
    "event_id": 24,
    "record": {
      "type": "event_record",
      "record_id": 3367
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager'/><EventID>24</EventID><TimeCreated SystemTime='2026-10-08T17:07:21.5571582Z'/><EventRecordID>3367</EventRecordID><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><UserData><EventXML xmlns='Event_NS'><User>DHRUVS_VICTUS\\dhruv</User><SessionID>25</SessionID><Address>LOCAL</Address></EventXML></UserData></Event>",
  "authentication": {
    "logon_id": {
      "$state": "inferred",
      "$note": "SessionID mapped to logon_id (INFERRED)",
      "$raw": "25"
    }
  },
  "network": {
    "src_ip": {
      "$state": "invalid",
      "$note": "LSM 'LOCAL' literal — not an IP",
      "$raw": "LOCAL"
    }
  }
}
```

### EX-WIN-LSM25 — Session reconnect (LSM EID 25)

<!-- covers: SEC-B LSM 25 reconnect; DFIR semantics (25=reconnect) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "session_reconnect",
    "action": "reconnect",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-09-20T16:04:59.627557Z",
    "original": "2026-09-20T16:04:59.6275575Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UserData/User DOMAIN\\user",
      "$raw": "DHRUVS_VICTUS\\dhruv"
    },
    "domain": "DHRUVS_VICTUS"
  },
  "source": {
    "file_id": "loc-lsm-25",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "provider": "Microsoft-Windows-TerminalServices-LocalSessionManager",
    "event_id": 25,
    "record": {
      "type": "event_record",
      "record_id": 3205
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager'/><EventID>25</EventID><TimeCreated SystemTime='2026-09-20T16:04:59.6275575Z'/><EventRecordID>3205</EventRecordID><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><UserData><EventXML xmlns='Event_NS'><User>DHRUVS_VICTUS\\dhruv</User><SessionID>8</SessionID><Address>LOCAL</Address></EventXML></UserData></Event>",
  "authentication": {
    "logon_id": {
      "$state": "inferred",
      "$note": "SessionID mapped to logon_id (INFERRED)",
      "$raw": "8"
    }
  },
  "network": {
    "src_ip": {
      "$state": "invalid",
      "$note": "LSM 'LOCAL' literal — not an IP",
      "$raw": "LOCAL"
    }
  }
}
```

### EX-WIN-LSM39 — Session disconnected by session (LSM EID 39)

<!-- covers: SEC-B LSM 39; TargetSession/Source→unmapped; no User on 39; DFIR semantics (39=disconnect by session/shadow) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "session_disconnected_by_session",
    "action": "disconnect",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-08T17:07:21.526853Z",
    "original": "2026-10-08T17:07:21.5268533Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {},
  "source": {
    "file_id": "loc-lsm-39",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "provider": "Microsoft-Windows-TerminalServices-LocalSessionManager",
    "event_id": 39,
    "record": {
      "type": "event_record",
      "record_id": 3364
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager'/><EventID>39</EventID><TimeCreated SystemTime='2026-10-08T17:07:21.5268533Z'/><EventRecordID>3364</EventRecordID><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><UserData><EventXML xmlns='Event_NS'><TargetSession>25</TargetSession><Source>25</Source></EventXML></UserData></Event>",
  "authentication": {
    "logon_id": {
      "$state": "inferred",
      "$note": "TargetSession mapped to logon_id (INFERRED); Source unmapped",
      "$raw": "25"
    }
  },
  "unmapped": [
    {
      "name": "Source",
      "value": "25"
    }
  ]
}
```

### EX-WIN-RCM1149 — RDP pre-auth (RCM EID 1149)

<!-- covers: SEC-B RCM 1149 rdp_auth; element names UNVERIFIED (B-COMMUNITY/B-PRIOR); derived_by sentinel -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "rdp_auth",
    "action": "connect",
    "outcome": "success",
    "severity": "low",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:04:00.000000Z",
    "original": "2026-10-09T14:04:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED Param1 candidate",
      "$raw": "jdoe"
    },
    "domain": {
      "$state": "inferred",
      "$note": "UNVERIFIED Param2",
      "$raw": "CORP"
    }
  },
  "source": {
    "file_id": "demo-rcm-1149",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "provider": "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
    "event_id": 1149,
    "record": {
      "type": "event_record",
      "record_id": 5001
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-RemoteConnectionManager'/><EventID>1149</EventID><TimeCreated SystemTime='2026-10-09T14:04:00.0000000Z'/><EventRecordID>5001</EventRecordID><Channel>Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='Param1'>jdoe</Data><Data Name='Param2'>CORP</Data><Data Name='Param3'>10.10.5.50</Data></EventData></Event>",
  "authentication": {
    "account_name": {
      "$state": "inferred",
      "$note": "UNVERIFIED Param1",
      "$raw": "jdoe"
    },
    "account_domain": {
      "$state": "inferred",
      "$note": "UNVERIFIED Param2",
      "$raw": "CORP"
    },
    "source_ip": {
      "$state": "inferred",
      "$note": "UNVERIFIED Param3",
      "$raw": "10.10.5.50"
    }
  }
}
```

### EX-WIN-AL8003 — AppLocker audit allowed (AppLocker EID 8003)

<!-- covers: SEC-B AppLocker 8003 applocker_audit; element names UNVERIFIED (B-PRIOR); template-verified file path only -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "applocker_audit",
    "action": "allow",
    "outcome": "success",
    "severity": "low",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:05:00.000000Z",
    "original": "2026-10-09T14:05:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "demo-al-8003",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-AppLocker/EXE and DLL",
    "provider": "Microsoft-Windows-AppLocker",
    "event_id": 8003,
    "record": {
      "type": "event_record",
      "record_id": 6001
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-AppLocker'/><EventID>8003</EventID><TimeCreated SystemTime='2026-10-09T14:05:00.0000000Z'/><EventRecordID>6001</EventRecordID><Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data>C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe was allowed.</Data></EventData></Event>",
  "config_check": {
    "check": "applocker_policy",
    "status": "pass",
    "observed": {
      "$state": "inferred",
      "$note": "UNVERIFIED element names; message-template param binding",
      "$raw": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe was allowed."
    }
  },
  "file": {
    "path": {
      "$state": "inferred",
      "$note": "UNVERIFIED element name; from template param",
      "$raw": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe"
    }
  }
}
```

### EX-WIN-AL8004 — AppLocker audit blocked (AppLocker EID 8004)

<!-- covers: SEC-B AppLocker 8004 applocker_audit; UNVERIFIED element names -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "applocker_audit",
    "action": "block",
    "outcome": "failure",
    "severity": "low",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:05:10.000000Z",
    "original": "2026-10-09T14:05:10.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "demo-al-8004",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-AppLocker/EXE and DLL",
    "provider": "Microsoft-Windows-AppLocker",
    "event_id": 8004,
    "record": {
      "type": "event_record",
      "record_id": 6002
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-AppLocker'/><EventID>8004</EventID><TimeCreated SystemTime='2026-10-09T14:05:10.0000000Z'/><EventRecordID>6002</EventRecordID><Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data>C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe was blocked.</Data></EventData></Event>",
  "config_check": {
    "check": "applocker_policy",
    "status": "fail",
    "observed": {
      "$state": "inferred",
      "$note": "UNVERIFIED element names; message-template param binding",
      "$raw": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe was blocked."
    }
  },
  "file": {
    "path": {
      "$state": "inferred",
      "$note": "UNVERIFIED element name",
      "$raw": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe"
    }
  }
}
```

### EX-WIN-AL8006 — AppLocker enforce allowed (AppLocker EID 8006)

<!-- covers: SEC-B AppLocker 8006; '<File name>' template VERIFIED (B-APPLOCKER-DOC) but element name UNVERIFIED; type applocker_enforce diverges from SEC-B applocker_block -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "applocker_enforce",
    "action": "allow",
    "outcome": "success",
    "severity": "low",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:05:20.000000Z",
    "original": "2026-10-09T14:05:20.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "demo-al-8006",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-AppLocker/EXE and DLL",
    "provider": "Microsoft-Windows-AppLocker",
    "event_id": 8006,
    "record": {
      "type": "event_record",
      "record_id": 6003
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-AppLocker'/><EventID>8006</EventID><TimeCreated SystemTime='2026-10-09T14:05:20.0000000Z'/><EventRecordID>6003</EventRecordID><Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data>C:\\Program Files\\legit\\app.exe</Data></EventData></Event>",
  "config_check": {
    "check": "applocker_policy",
    "status": "pass",
    "observed": {
      "$state": "inferred",
      "$note": "template-verified file path; element name UNVERIFIED",
      "$raw": "C:\\Program Files\\legit\\app.exe"
    }
  },
  "file": {
    "path": {
      "$state": "inferred",
      "$note": "template-verified param; element name UNVERIFIED",
      "$raw": "C:\\Program Files\\legit\\app.exe"
    }
  }
}
```

### EX-WIN-AL8007 — AppLocker enforce blocked (AppLocker EID 8007)

<!-- covers: SEC-B AppLocker 8007; template-verified file param; type applocker_enforce diverges from SEC-B applocker_block -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "applocker_enforce",
    "action": "block",
    "outcome": "failure",
    "severity": "medium",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:05:30.000000Z",
    "original": "2026-10-09T14:05:30.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "demo-al-8007",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-AppLocker/EXE and DLL",
    "provider": "Microsoft-Windows-AppLocker",
    "event_id": 8007,
    "record": {
      "type": "event_record",
      "record_id": 6004
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-AppLocker'/><EventID>8007</EventID><TimeCreated SystemTime='2026-10-09T14:05:30.0000000Z'/><EventRecordID>6004</EventRecordID><Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data>C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe</Data></EventData></Event>",
  "config_check": {
    "check": "applocker_policy",
    "status": "fail",
    "observed": {
      "$state": "inferred",
      "$note": "template-verified file path; element name UNVERIFIED",
      "$raw": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe"
    }
  },
  "file": {
    "path": {
      "$state": "inferred",
      "$note": "template-verified param; element name UNVERIFIED",
      "$raw": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe"
    }
  }
}
```

## Zeek JSON logs (6)

### EX-ZEEK-CONN — Zeek conn.log connection

<!-- covers: SEC-B Zeek conn; id.orig_h/orig_p/resp_h/resp_p/resp.proto flat names; service/history/pkts→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "network",
    "type": "network_connection",
    "action": "connect",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:00:00.123456Z",
    "original": "1791550800.123456",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "microsecond",
    "state": "inferred"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "zeek-conn-001",
    "format": "json",
    "parser": "zeek-json",
    "parser_version": "1.0.0"
  },
  "raw": {
    "ts": "1791550800.123456",
    "uid": "CnKxvG3DkQ8Qe4L9h",
    "id.orig_h": "10.10.5.23",
    "id.orig_p": 51540,
    "id.resp_h": "93.184.216.34",
    "id.resp_p": 443,
    "id.proto": "tcp",
    "proto": "tcp",
    "service": "ssl",
    "duration": 12.4,
    "orig_bytes": 8421,
    "resp_bytes": 245310,
    "conn_state": "S1",
    "missed_bytes": 0,
    "history": "ShADadFf",
    "orig_pkts": 42,
    "orig_ip_bytes": 3409,
    "resp_pkts": 187,
    "resp_ip_bytes": 253566,
    "local_orig": false,
    "local_resp": false,
    "tunnel_parents": []
  },
  "network": {
    "protocol": "tcp",
    "direction": {
      "$state": "inferred",
      "$note": "Zeek orig→resp; direction from conn role"
    },
    "src_ip": "10.10.5.23",
    "src_port": 51540,
    "dst_ip": "93.184.216.34",
    "dst_port": 443,
    "state": "S1",
    "duration": 12.4,
    "bytes_sent": 8421,
    "bytes_received": 245310,
    "uid": "CnKxvG3DkQ8Qe4L9h"
  },
  "unmapped": [
    {
      "name": "service",
      "value": "ssl"
    },
    {
      "name": "history",
      "value": "ShADadFf"
    },
    {
      "name": "orig_pkts",
      "value": 42
    },
    {
      "name": "orig_ip_bytes",
      "value": 3409
    },
    {
      "name": "resp_pkts",
      "value": 187
    },
    {
      "name": "resp_ip_bytes",
      "value": 253566
    },
    {
      "name": "local_orig",
      "value": false
    },
    {
      "name": "local_resp",
      "value": false
    }
  ]
}
```

### EX-ZEEK-DNS — Zeek dns.log query

<!-- covers: SEC-B Zeek dns; query/qtype_name/rcode_name/answers canonical; trans_id/qclass/flags/TTLs→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "dns",
    "type": "dns_query",
    "action": "query",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:00:00.123456Z",
    "original": "1791550800.123456",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "microsecond",
    "state": "inferred"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "zeek-dns-001",
    "format": "json",
    "parser": "zeek-json",
    "parser_version": "1.0.0"
  },
  "raw": {
    "ts": "1791550800.123456",
    "uid": "CyQpTj1V7Kj8Qe4L9h",
    "id.orig_h": "10.10.5.23",
    "id.orig_p": 51541,
    "id.resp_h": "10.10.0.1",
    "id.resp_p": 53,
    "id.proto": "udp",
    "proto": "udp",
    "service": "dns",
    "trans_id": 4321,
    "query": "example.com",
    "qclass": 1,
    "qclass_name": "C_INTERNET",
    "qtype": 1,
    "qtype_name": "A",
    "rcode": 0,
    "rcode_name": "NOERROR",
    "AA": false,
    "TC": false,
    "RD": true,
    "RA": true,
    "Z": 0,
    "answers": [
      "93.184.216.34"
    ],
    "TTLs": [
      300.0
    ],
    "rejected": false
  },
  "dns": {
    "query_name": "example.com",
    "query_type": "A",
    "response_code": "NOERROR",
    "answers": [
      "93.184.216.34"
    ],
    "server": "10.10.0.1"
  },
  "network": {
    "protocol": "udp",
    "src_ip": "10.10.5.23",
    "src_port": 51541,
    "dst_ip": "10.10.0.1",
    "dst_port": 53,
    "uid": "CyQpTj1V7Kj8Qe4L9h"
  },
  "unmapped": [
    {
      "name": "trans_id",
      "value": 4321
    },
    {
      "name": "qclass_name",
      "value": "C_INTERNET"
    },
    {
      "name": "qtype",
      "value": 1
    },
    {
      "name": "AA",
      "value": false
    },
    {
      "name": "TC",
      "value": false
    },
    {
      "name": "RD",
      "value": true
    },
    {
      "name": "RA",
      "value": true
    },
    {
      "name": "Z",
      "value": 0
    },
    {
      "name": "TTLs",
      "value": [
        300.0
      ]
    },
    {
      "name": "rejected",
      "value": false
    }
  ]
}
```

### EX-ZEEK-HTTP — Zeek http.log request

<!-- covers: SEC-B Zeek http; method/host/uri/user_agent/status_code/body lengths canonical; referrer/status_msg/tags→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "http",
    "type": "http_request",
    "action": "request",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:00:00.123456Z",
    "original": "1791550800.123456",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "microsecond",
    "state": "inferred"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "zeek-http-001",
    "format": "json",
    "parser": "zeek-json",
    "parser_version": "1.0.0"
  },
  "raw": {
    "ts": "1791550800.123456",
    "uid": "CHjKmL3NpQ8Qe4L9h",
    "id.orig_h": "10.10.5.23",
    "id.orig_p": 51542,
    "id.resp_h": "93.184.216.34",
    "id.resp_p": 80,
    "id.proto": "tcp",
    "service": "http",
    "trans_depth": 1,
    "method": "GET",
    "host": "example.com",
    "uri": "/payload.bin",
    "version": "1.1",
    "user_agent": "curl/8.5.0",
    "origin": "-",
    "referrer": "-",
    "request_body_len": 0,
    "response_body_len": 4096,
    "status_code": 200,
    "status_msg": "OK",
    "info_code": 0,
    "info_msg": "-",
    "tags": []
  },
  "http": {
    "method": "GET",
    "host": "example.com",
    "uri": "/payload.bin",
    "user_agent": "curl/8.5.0",
    "status_code": 200,
    "request_body_length": 0,
    "response_body_length": 4096
  },
  "network": {
    "protocol": "tcp",
    "src_ip": "10.10.5.23",
    "src_port": 51542,
    "dst_ip": "93.184.216.34",
    "dst_port": 80,
    "uid": "CHjKmL3NpQ8Qe4L9h"
  },
  "unmapped": [
    {
      "name": "version",
      "value": "1.1"
    },
    {
      "name": "origin",
      "value": "-"
    },
    {
      "name": "referrer",
      "value": "-"
    },
    {
      "name": "status_msg",
      "value": "OK"
    },
    {
      "name": "info_code",
      "value": 0
    },
    {
      "name": "tags",
      "value": []
    }
  ]
}
```

### EX-ZEEK-SSL — Zeek ssl.log handshake

<!-- covers: SEC-B Zeek ssl; server_name→tls.sni (INFERRED prefer sni); ja3/ja3s NOT in base Zeek; curve/dp/next_protocol→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "tls",
    "type": "tls_handshake",
    "action": "handshake",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:00:00.123456Z",
    "original": "1791550800.123456",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "microsecond",
    "state": "inferred"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "zeek-ssl-001",
    "format": "json",
    "parser": "zeek-json",
    "parser_version": "1.0.0"
  },
  "raw": {
    "ts": "1791550800.123456",
    "uid": "CSsTtUvWxY8Qe4L9h",
    "id.orig_h": "10.10.5.23",
    "id.orig_p": 51543,
    "id.resp_h": "93.184.216.34",
    "id.resp_p": 443,
    "id.proto": "tcp",
    "service": "ssl",
    "version": "TLSv12",
    "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "server_name": "example.com",
    "resumed": false,
    "established": true,
    "curve": "x25519",
    "dp": "ec",
    "next_protocol": "http/1.1",
    "last_alert": "-",
    "ssl_history": "Cc"
  },
  "tls": {
    "sni": "example.com",
    "server_name": "example.com",
    "version": "TLSv12",
    "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "resumed": false
  },
  "network": {
    "protocol": "tcp",
    "src_ip": "10.10.5.23",
    "src_port": 51543,
    "dst_ip": "93.184.216.34",
    "dst_port": 443,
    "uid": "CSsTtUvWxY8Qe4L9h"
  },
  "unmapped": [
    {
      "name": "curve",
      "value": "x25519"
    },
    {
      "name": "dp",
      "value": "ec"
    },
    {
      "name": "next_protocol",
      "value": "http/1.1"
    },
    {
      "name": "last_alert",
      "value": "-"
    },
    {
      "name": "ssl_history",
      "value": "Cc"
    }
  ]
}
```

### EX-ZEEK-NOTICE — Zeek notice.log alert

<!-- covers: SEC-B Zeek notice; derived_by sentinel; note→rule_id, msg→description; src/dst/p canonical -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "third_party_alert",
    "type": "zeek_notice",
    "action": "notice",
    "outcome": "success",
    "severity": "medium",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:00:00.123456Z",
    "original": "1791550800.123456",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "microsecond",
    "state": "inferred"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "zeek-notice-001",
    "format": "json",
    "parser": "zeek-json",
    "parser_version": "1.0.0"
  },
  "raw": {
    "ts": "1791550800.123456",
    "uid": "CnNnOoPpQq8Qe4L9h",
    "id.orig_h": "10.10.5.23",
    "id.orig_p": 51544,
    "id.resp_h": "10.10.0.5",
    "id.resp_p": 80,
    "note": "HTTP::SQL_Injection_Attack",
    "msg": "SQL injection attempt in URI",
    "sub": "/search?q=1' OR 1=1--",
    "src": "10.10.5.23",
    "dst": "10.10.0.5",
    "p": 80,
    "peer_descr": "zeek-sensor-01",
    "actions": [
      "Notice::ACTION_LOG"
    ],
    "suppress_for": 3600.0,
    "dropped": false
  },
  "third_party_alert": {
    "vendor": "Zeek",
    "product": "Zeek",
    "rule_id": "HTTP::SQL_Injection_Attack",
    "description": "SQL injection attempt in URI",
    "observable": "/search?q=1' OR 1=1--"
  },
  "network": {
    "src_ip": "10.10.5.23",
    "src_port": 51544,
    "dst_ip": "10.10.0.5",
    "dst_port": 80,
    "uid": "CnNnOoPpQq8Qe4L9h"
  },
  "unmapped": [
    {
      "name": "sub",
      "value": "/search?q=1' OR 1=1--"
    },
    {
      "name": "peer_descr",
      "value": "zeek-sensor-01"
    },
    {
      "name": "actions",
      "value": [
        "Notice::ACTION_LOG"
      ]
    },
    {
      "name": "suppress_for",
      "value": 3600.0
    },
    {
      "name": "dropped",
      "value": false
    }
  ]
}
```

### EX-ZEEK-FILES — Zeek files.log seen file

<!-- covers: SEC-B Zeek files; uid=conn uid (NO tx_uid); md5/sha1/sha256 canonical; fuid/source/analyzers→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_seen",
    "action": "seen",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:00:00.123456Z",
    "original": "1791550800.123456",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "microsecond",
    "state": "inferred"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "zeek-files-001",
    "format": "json",
    "parser": "zeek-json",
    "parser_version": "1.0.0"
  },
  "raw": {
    "ts": "1791550800.123456",
    "fuid": "FhHhIiJjKk8Qe4L9h",
    "uid": "CHjKmL3NpQ8Qe4L9h",
    "id.orig_h": "10.10.5.23",
    "id.orig_p": 51542,
    "id.resp_h": "93.184.216.34",
    "id.resp_p": 80,
    "id.proto": "tcp",
    "source": "HTTP",
    "depth": 0,
    "analyzers": [
      "MD5",
      "SHA1",
      "SHA256",
      "EXTRACT"
    ],
    "mime_type": "application/x-msdownload",
    "filename": "payload.bin",
    "duration": 0.5,
    "orig_bytes": 0,
    "resp_bytes": 4096,
    "seen_bytes": 4096,
    "total_bytes": 4096,
    "missing_bytes": 0,
    "overflow_bytes": 0,
    "timedout": false,
    "parent_fuid": "-",
    "is_orig": false,
    "local_orig": false,
    "md5": "5d41402abc4b2a76b9719d911017c592",
    "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
    "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
  },
  "file": {
    "name": "payload.bin",
    "type": "application/x-msdownload",
    "size": 4096,
    "hashes": {
      "md5": "5d41402abc4b2a76b9719d911017c592",
      "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
      "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    }
  },
  "network": {
    "uid": "CHjKmL3NpQ8Qe4L9h",
    "src_ip": "10.10.5.23",
    "src_port": 51542,
    "dst_ip": "93.184.216.34",
    "dst_port": 80
  },
  "unmapped": [
    {
      "name": "fuid",
      "value": "FhHhIiJjKk8Qe4L9h"
    },
    {
      "name": "source",
      "value": "HTTP"
    },
    {
      "name": "depth",
      "value": 0
    },
    {
      "name": "analyzers",
      "value": [
        "MD5",
        "SHA1",
        "SHA256",
        "EXTRACT"
      ]
    },
    {
      "name": "duration",
      "value": 0.5
    },
    {
      "name": "orig_bytes",
      "value": 0
    },
    {
      "name": "resp_bytes",
      "value": 4096
    },
    {
      "name": "seen_bytes",
      "value": 4096
    },
    {
      "name": "total_bytes",
      "value": 4096
    },
    {
      "name": "missing_bytes",
      "value": 0
    },
    {
      "name": "overflow_bytes",
      "value": 0
    }
  ]
}
```

## Suricata EVE JSON (6)

### EX-EVE-ALERT — Suricata EVE alert

<!-- covers: SEC-B EVE alert; alert.* → third_party_alert; severity 1→critical; flow_id→network.uid INFERRED -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "third_party_alert",
    "type": "suricata_alert",
    "action": "alert",
    "outcome": "success",
    "severity": "critical",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:20:00.123456Z",
    "original": "2026-10-09T14:20:00.123456+0000",
    "original_timezone": "+00:00",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "eve-alert-001",
    "format": "json",
    "parser": "suricata-eve",
    "parser_version": "1.0.0"
  },
  "raw": {
    "timestamp": "2026-10-09T14:20:00.123456+0000",
    "flow_id": 987654321,
    "pcap_cnt": 42,
    "event_type": "alert",
    "src_ip": "10.10.5.99",
    "src_port": 44444,
    "dest_ip": "10.10.5.23",
    "dest_port": 445,
    "proto": "TCP",
    "alert": {
      "action": "allowed",
      "gid": 1,
      "signature_id": 2024218,
      "rev": 4,
      "signature": "ET EXPLOIT SMBv1 Trans2 Request - EternalBlue",
      "category": "Attempted Administrator Privilege Gain",
      "severity": 1
    }
  },
  "third_party_alert": {
    "vendor": "Suricata",
    "product": "Suricata",
    "rule_name": "ET EXPLOIT SMBv1 Trans2 Request - EternalBlue",
    "rule_id": "2024218",
    "category": "Attempted Administrator Privilege Gain",
    "severity_raw": "1"
  },
  "network": {
    "protocol": "TCP",
    "src_ip": "10.10.5.99",
    "src_port": 44444,
    "dst_ip": "10.10.5.23",
    "dst_port": 445,
    "uid": "987654321"
  },
  "unmapped": [
    {
      "name": "action",
      "value": "allowed"
    },
    {
      "name": "gid",
      "value": 1
    },
    {
      "name": "rev",
      "value": 4
    },
    {
      "name": "pcap_cnt",
      "value": 42
    }
  ]
}
```

### EX-EVE-HTTP — Suricata EVE http

<!-- covers: SEC-B EVE http; http.* canonical; length→request_body_length (INFERRED as request/response body length carrier) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "http",
    "type": "http_request",
    "action": "request",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:21:00.654321Z",
    "original": "2026-10-09T14:21:00.654321+0000",
    "original_timezone": "+00:00",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "eve-http-001",
    "format": "json",
    "parser": "suricata-eve",
    "parser_version": "1.0.0"
  },
  "raw": {
    "timestamp": "2026-10-09T14:21:00.654321+0000",
    "flow_id": 123456789,
    "event_type": "http",
    "src_ip": "10.10.5.23",
    "src_port": 51550,
    "dest_ip": "93.184.216.34",
    "dest_port": 80,
    "proto": "TCP",
    "http": {
      "hostname": "example.com",
      "url": "/payload.bin",
      "http_user_agent": "curl/8.5.0",
      "http_method": "GET",
      "protocol": "HTTP/1.1",
      "status": 200,
      "length": 4096
    }
  },
  "http": {
    "host": "example.com",
    "url": "/payload.bin",
    "user_agent": "curl/8.5.0",
    "method": "GET",
    "status_code": 200,
    "request_body_length": 4096
  },
  "network": {
    "protocol": "TCP",
    "src_ip": "10.10.5.23",
    "src_port": 51550,
    "dst_ip": "93.184.216.34",
    "dst_port": 80,
    "uid": "123456789"
  }
}
```

### EX-EVE-DNS — Suricata EVE dns

<!-- covers: SEC-B EVE dns; dns.rrname/rrtype/rdata/answers canonical; id/rcode/ttl→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "dns",
    "type": "dns_query",
    "action": "response",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:22:00.111222Z",
    "original": "2026-10-09T14:22:00.111222+0000",
    "original_timezone": "+00:00",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "eve-dns-001",
    "format": "json",
    "parser": "suricata-eve",
    "parser_version": "1.0.0"
  },
  "raw": {
    "timestamp": "2026-10-09T14:22:00.111222+0000",
    "flow_id": 223344556,
    "event_type": "dns",
    "src_ip": "10.10.5.23",
    "src_port": 51541,
    "dest_ip": "10.10.0.1",
    "dest_port": 53,
    "proto": "UDP",
    "dns": {
      "type": "answer",
      "id": 4321,
      "rrname": "example.com",
      "rrtype": "A",
      "rcode": "NOERROR",
      "ttl": 300,
      "answers": [
        {
          "rrname": "example.com",
          "rrtype": "A",
          "ttl": 300,
          "rdata": "93.184.216.34"
        }
      ]
    }
  },
  "dns": {
    "query_name": "example.com",
    "query_type": "A",
    "response_code": "NOERROR",
    "answers": [
      "93.184.216.34"
    ],
    "server": "10.10.0.1"
  },
  "network": {
    "protocol": "UDP",
    "src_ip": "10.10.5.23",
    "src_port": 51541,
    "dst_ip": "10.10.0.1",
    "dst_port": 53,
    "uid": "223344556"
  },
  "unmapped": [
    {
      "name": "id",
      "value": 4321
    },
    {
      "name": "ttl",
      "value": 300
    }
  ]
}
```

### EX-EVE-TLS — Suricata EVE tls

<!-- covers: SEC-B EVE tls; sni/ja3/ja3s/version/subject/issuer canonical -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "tls",
    "type": "tls_handshake",
    "action": "handshake",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:23:00.999888Z",
    "original": "2026-10-09T14:23:00.999888+0000",
    "original_timezone": "+00:00",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "eve-tls-001",
    "format": "json",
    "parser": "suricata-eve",
    "parser_version": "1.0.0"
  },
  "raw": {
    "timestamp": "2026-10-09T14:23:00.999888+0000",
    "flow_id": 334455667,
    "event_type": "tls",
    "src_ip": "10.10.5.23",
    "src_port": 51543,
    "dest_ip": "93.184.216.34",
    "dest_port": 443,
    "proto": "TCP",
    "tls": {
      "subject": "CN=example.com",
      "issuer": "CN=Example CA",
      "serial": "0a1b2c3d4e5f",
      "fingerprint": "ab:cd:ef:...",
      "sni": "example.com",
      "version": "TLS 1.2",
      "ja3": "e7d705a3286e19ea42f587b344ee6865",
      "ja3s": "aaf33f89f218dd09568c70de42a0186d"
    }
  },
  "tls": {
    "sni": "example.com",
    "version": "TLS 1.2",
    "subject": "CN=example.com",
    "issuer": "CN=Example CA",
    "ja3": "e7d705a3286e19ea42f587b344ee6865",
    "ja3s": "aaf33f89f218dd09568c70de42a0186d"
  },
  "network": {
    "protocol": "TCP",
    "src_ip": "10.10.5.23",
    "src_port": 51543,
    "dst_ip": "93.184.216.34",
    "dst_port": 443,
    "uid": "334455667"
  },
  "unmapped": [
    {
      "name": "serial",
      "value": "0a1b2c3d4e5f"
    },
    {
      "name": "fingerprint",
      "value": "ab:cd:ef:..."
    }
  ]
}
```

### EX-EVE-FLOW — Suricata EVE flow

<!-- covers: SEC-B EVE flow; bytes_toserver/toclient→bytes_sent/received; pkts_*→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "network",
    "type": "network_connection",
    "action": "connect",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:24:00.333444Z",
    "original": "2026-10-09T14:24:00.333444+0000",
    "original_timezone": "+00:00",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "eve-flow-001",
    "format": "json",
    "parser": "suricata-eve",
    "parser_version": "1.0.0"
  },
  "raw": {
    "timestamp": "2026-10-09T14:24:00.333444+0000",
    "flow_id": 445566778,
    "event_type": "flow",
    "src_ip": "10.10.5.23",
    "src_port": 51560,
    "dest_ip": "93.184.216.34",
    "dest_port": 443,
    "proto": "TCP",
    "flow": {
      "pkts_toserver": 42,
      "pkts_toclient": 187,
      "bytes_toserver": 3409,
      "bytes_toclient": 253566,
      "start": "2026-10-09T14:20:00.000000+0000",
      "end": "2026-10-09T14:20:12.400000+0000"
    }
  },
  "network": {
    "protocol": "TCP",
    "src_ip": "10.10.5.23",
    "src_port": 51560,
    "dst_ip": "93.184.216.34",
    "dst_port": 443,
    "bytes_sent": 3409,
    "bytes_received": 253566,
    "uid": "445566778"
  },
  "unmapped": [
    {
      "name": "pkts_toserver",
      "value": 42
    },
    {
      "name": "pkts_toclient",
      "value": 187
    },
    {
      "name": "start",
      "value": "2026-10-09T14:20:00.000000+0000"
    },
    {
      "name": "end",
      "value": "2026-10-09T14:20:12.400000+0000"
    }
  ]
}
```

### EX-EVE-FILEINFO — Suricata EVE fileinfo

<!-- covers: SEC-B EVE fileinfo; filename/magic/md5/sha256/size canonical; state/gaps/sid→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_seen",
    "action": "seen",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:25:00.777888Z",
    "original": "2026-10-09T14:25:00.777888+0000",
    "original_timezone": "+00:00",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "eve-fileinfo-001",
    "format": "json",
    "parser": "suricata-eve",
    "parser_version": "1.0.0"
  },
  "raw": {
    "timestamp": "2026-10-09T14:25:00.777888+0000",
    "flow_id": 556677889,
    "event_type": "fileinfo",
    "src_ip": "10.10.5.23",
    "src_port": 51542,
    "dest_ip": "93.184.216.34",
    "dest_port": 80,
    "proto": "TCP",
    "fileinfo": {
      "filename": "payload.bin",
      "sid": null,
      "magic": "PE32 executable (GUI) Intel 80386, for MS Windows",
      "gaps": false,
      "state": "CLOSED",
      "md5": "5d41402abc4b2a76b9719d911017c592",
      "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
      "size": 4096
    }
  },
  "file": {
    "name": "payload.bin",
    "type": "PE32 executable (GUI) Intel 80386, for MS Windows",
    "size": 4096,
    "hashes": {
      "md5": "5d41402abc4b2a76b9719d911017c592",
      "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    }
  },
  "network": {
    "protocol": "TCP",
    "src_ip": "10.10.5.23",
    "src_port": 51542,
    "dst_ip": "93.184.216.34",
    "dst_port": 80,
    "uid": "556677889"
  },
  "unmapped": [
    {
      "name": "state",
      "value": "CLOSED"
    },
    {
      "name": "gaps",
      "value": false
    }
  ]
}
```

## Nmap XML export (1)

### EX-NMAP-1 — Nmap XML scan result

<!-- covers: SEC-B Nmap; config_check port_scan derived_by sentinel; almost everything unmapped under nmap.*; @start epoch→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "port_scan",
    "action": "scan",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": null,
    "original": "Sat Oct  9 14:21:40 2026",
    "timezone_source": "none",
    "precision": "second",
    "state": "unknown"
  },
  "host": {
    "hostname": "fileserver01.corp.local",
    "ips": [
      "10.10.0.5"
    ],
    "os": {
      "family": {
        "$state": "inferred",
        "$note": "nmap osmatch",
        "$raw": "Windows Server 2022"
      }
    }
  },
  "user": {},
  "source": {
    "file_id": "nmap-001",
    "format": "nmap_xml",
    "parser": "nmap-xml",
    "parser_version": "1.0.0"
  },
  "raw": "<nmaprun scanner='nmap' args='nmap -sV -oX scan.xml 10.10.0.5' start='1791550900' startstr='Sat Oct  9 14:21:40 2026' version='7.95' xmloutputversion='1.05'><host starttime='1791550901' endtime='1791550960'><status state='up' reason='echo-reply' reason_ttl='63'/><address addr='10.10.0.5' addrtype='ipv4'/><hostname name='fileserver01.corp.local' type='PTR'/><ports><port protocol='tcp' portid='445'><state state='open' reason='syn-ack' reason_ttl='63'/><service name='microsoft-ds' product='Windows Server 2022' method='probed' conf='10'><cpe>cpe:/o:microsoft:windows_server_2022</cpe></service></port></ports><times srtt='250' rttvar='100' to='100000'/><runstats><finished time='1791550960' timestr='Sat Oct  9 14:22:40 2026' elapsed='60.00' summary='Nmap done at Sat Oct  9 14:22:40 2026; 1 IP address (1 host up) scanned in 60.00 seconds' exit='success'/><hosts up='1' down='0' total='1'/></runstats></nmaprun>",
  "config_check": {
    "check": "port_scan",
    "status": "pass",
    "observed": {
      "$state": "inferred",
      "$note": "scanned host inventory summary",
      "$raw": "10.10.0.5 tcp/445 open microsoft-ds"
    }
  },
  "network": {
    "protocol": "tcp",
    "dst_port": 445,
    "state": "open",
    "dst_ip": {
      "$state": "inferred",
      "$note": "address@addr is scan target, not scanner — mapped to dst_ip INFERRED",
      "$raw": "10.10.0.5"
    }
  },
  "unmapped": [
    {
      "name": "nmap.args",
      "value": "nmap -sV -oX scan.xml 10.10.0.5"
    },
    {
      "name": "nmap.version",
      "value": "7.95"
    },
    {
      "name": "nmap.start_epoch",
      "value": "1791550900"
    },
    {
      "name": "host.state_reason",
      "value": "echo-reply"
    },
    {
      "name": "nmap.hostname",
      "value": "fileserver01.corp.local"
    },
    {
      "name": "nmap.service.name",
      "value": "microsoft-ds"
    },
    {
      "name": "nmap.service.product",
      "value": "Windows Server 2022"
    },
    {
      "name": "nmap.cpe",
      "value": "cpe:/o:microsoft:windows_server_2022"
    },
    {
      "name": "nmap.runstats.finished_epoch",
      "value": "1791550960"
    }
  ]
}
```

## netstat snapshot (1)

### EX-NETSTAT-1 — netstat -ano snapshot

<!-- covers: SEC-B netstat; config_check derived_by sentinel; Local/Foreign Address split INFERRED; PID→process.pid INFERRED; time unknown (no timestamp) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "connection_inventory",
    "action": "inventory",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": null,
    "timezone_source": "none",
    "precision": "unknown",
    "state": "unknown"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "netstat-001",
    "format": "text",
    "parser": "netstat-parser",
    "parser_version": "1.0.0"
  },
  "raw": "Active Connections\n\n  Proto  Local Address        Foreign Address      State           PID\n  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234\n  TCP    10.10.5.23:51540      93.184.216.34:443      ESTABLISHED     4521\n",
  "config_check": {
    "check": "netstat_connections",
    "status": "pass",
    "observed": {
      "$state": "inferred",
      "$note": "one row promoted as example; full table in raw",
      "$raw": "TCP 10.10.5.23:51540 -> 93.184.216.34:443 ESTABLISHED PID 4521"
    }
  },
  "network": {
    "protocol": "TCP",
    "state": "ESTABLISHED",
    "src_ip": "10.10.5.23",
    "src_port": 51540,
    "dst_ip": "93.184.216.34",
    "dst_port": 443,
    "process": {
      "pid": {
        "$state": "inferred",
        "$note": "netstat PID is snapshot; join to process record INFERRED; PID reuse trap",
        "$raw": "4521"
      }
    }
  }
}
```

## schtasks /query snapshot (1)

### EX-SCHTASKS-1 — schtasks /query snapshot

<!-- covers: SEC-B schtasks; scheduled_task fields; command/args/user_id/author INFERRED column mapping -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "scheduled_task",
    "type": "task_inventory",
    "action": "inventory",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": null,
    "timezone_source": "none",
    "precision": "unknown",
    "state": "unknown"
  },
  "host": {},
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "Run As User",
      "$raw": "CORP\\jdoe"
    },
    "domain": "CORP"
  },
  "source": {
    "file_id": "schtasks-001",
    "format": "text",
    "parser": "schtasks-parser",
    "parser_version": "1.0.0"
  },
  "raw": "TaskName: \\Updater\nNext Run Time: 10/9/2026 6:00:00 PM\nStatus: Ready\nLogon Mode: Interactive/Background\nLast Run Time: 10/9/2026 2:00:00 PM\nLast Result: 0\nAuthor: CORP\\jdoe\nTask To Run: C:\\Temp\\evil.exe \nStart In: C:\\Temp\nRun As User: CORP\\jdoe\n",
  "scheduled_task": {
    "name": {
      "$state": "inferred",
      "$raw": "\\Updater"
    },
    "command": {
      "$state": "inferred",
      "$note": "Task To Run column",
      "$raw": "C:\\Temp\\evil.exe"
    },
    "arguments": {
      "$state": "null",
      "$note": "no args in sample"
    },
    "working_directory": {
      "$state": "inferred",
      "$raw": "C:\\Temp"
    },
    "user_id": {
      "$state": "inferred",
      "$raw": "CORP\\jdoe"
    },
    "author": {
      "$state": "inferred",
      "$raw": "CORP\\jdoe"
    },
    "result_code": {
      "$state": "inferred",
      "$raw": "0"
    },
    "trigger": {
      "$state": "inferred",
      "$note": "Next Run Time implies schedule",
      "$raw": "10/9/2026 6:00:00 PM"
    }
  }
}
```

## sc query snapshot (1)

### EX-SCQUERY-1 — sc query snapshot

<!-- covers: SEC-B sc query; SERVICE_NAME/TYPE/STATE/exit codes/checkpoint/wait_hint canonical -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "service",
    "type": "service_inventory",
    "action": "inventory",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": null,
    "timezone_source": "none",
    "precision": "unknown",
    "state": "unknown"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "sc-query-001",
    "format": "text",
    "parser": "sc-query-parser",
    "parser_version": "1.0.0"
  },
  "raw": "SERVICE_NAME: EvilSvc\n        TYPE               : 10  WIN32_OWN_PROCESS  \n        STATE              : 4  RUNNING  \n                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)\n        WIN32_EXIT_CODE    : 0  (0x0)\n        SERVICE_EXIT_CODE  : 0  (0x0)\n        CHECKPOINT         : 0x0\n        WAIT_HINT          : 0x0\n",
  "service": {
    "name": "EvilSvc",
    "service_type": "10  WIN32_OWN_PROCESS",
    "state": "4  RUNNING",
    "exit_code": "0  (0x0)",
    "checkpoint": {
      "$state": "inferred",
      "$raw": "0x0"
    },
    "wait_hint": {
      "$state": "inferred",
      "$raw": "0x0"
    }
  }
}
```

## sc qc snapshot (1)

### EX-SCQC-1 — sc qc snapshot

<!-- covers: SEC-B sc qc; BINARY_PATH_NAME UNVERIFIED (B-PRIOR; MS sc-qc URL 404s) -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "service",
    "type": "service_config_inventory",
    "action": "inventory",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": null,
    "timezone_source": "none",
    "precision": "unknown",
    "state": "unknown"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "sc-qc-001",
    "format": "text",
    "parser": "sc-qc-parser",
    "parser_version": "1.0.0"
  },
  "raw": "[SC] QueryServiceConfig SUCCESS\nSERVICE_NAME: EvilSvc\n        TYPE               : 10  WIN32_OWN_PROCESS\n        START_TYPE         : 3   DEMAND_START\n        ERROR_CONTROL     : 1   NORMAL\n        BINARY_PATH_NAME  : \"C:\\Temp\\evil.exe\" -k netsvcs\n        LOAD_ORDER_GROUP  : NetWork\n        TAG                : 0\n        DISPLAY_NAME       : Evil Service\n        DEPENDENCIES      : \n        SERVICE_START_NAME : LocalSystem\n",
  "service": {
    "name": "EvilSvc",
    "image_path": {
      "$state": "inferred",
      "$note": "BINARY_PATH_NAME field list UNVERIFIED (B-PRIOR); map observed value INFERRED",
      "$raw": "\"C:\\Temp\\evil.exe\" -k netsvcs"
    },
    "start_type": {
      "$state": "inferred",
      "$raw": "3   DEMAND_START"
    },
    "error_control": {
      "$state": "inferred",
      "$raw": "1   NORMAL"
    },
    "display_name": {
      "$state": "inferred",
      "$raw": "Evil Service"
    },
    "load_order_group": {
      "$state": "inferred",
      "$raw": "NetWork"
    },
    "account_name": {
      "$state": "inferred",
      "$raw": "LocalSystem"
    }
  }
}
```

## reg export .reg snapshot (1)

### EX-REGEXPORT-1 — reg export .reg snapshot

<!-- covers: SEC-B reg export; registry payload from .reg content; operation=export INFERRED; time unknown -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "registry",
    "type": "registry_export",
    "action": "export",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": null,
    "timezone_source": "none",
    "precision": "unknown",
    "state": "unknown"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "reg-export-001",
    "format": "text",
    "parser": "reg-export-parser",
    "parser_version": "1.0.0"
  },
  "raw": "Windows Registry Editor Version 5.00\n\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]\n\"Updater\"=\"C:\\\\Temp\\\\evil.exe\"\n",
  "registry": {
    "path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
    "hive": "HKLM",
    "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "value_name": "Updater",
    "data": "C:\\Temp\\evil.exe",
    "operation": {
      "$state": "inferred",
      "$note": "export is not a runtime registry operation; snapshot semantics"
    }
  }
}
```

## PowerShell Export-Csv inventory (1)

### EX-EXPORTCSV-1 — Export-Csv process inventory

<!-- covers: SEC-B Export-Csv; structure only — property names→header; process payload from Get-Process-style rows -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "process",
    "type": "process_inventory",
    "action": "inventory",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:00:00.123456Z",
    "original": "1791550800.123456",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "microsecond",
    "state": "inferred"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "export-csv-001",
    "format": "csv",
    "parser": "export-csv-parser",
    "parser_version": "1.0.0"
  },
  "raw": "\"Id\",\"ProcessName\",\"Path\",\"StartTime\"\r\n\"1234\",\"cmd\",\"C:\\Windows\\System32\\cmd.exe\",\"2026-10-09T12:00:00\"\r\n\"4521\",\"powershell\",\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\",\"2026-10-09T12:05:00\"\r\n",
  "process": {
    "pid": {
      "$state": "inferred",
      "$note": "CSV Id column from Get-Process",
      "$raw": "4521"
    },
    "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "name": "powershell",
    "start_time": {
      "$state": "inferred",
      "$raw": "2026-10-09T12:05:00"
    }
  }
}
```

## autorunsc autostart inventory (1)

### EX-AUTORUNS-1 — autorunsc autostart inventory

<!-- covers: SEC-B autorunsc; Path/Launch String→process.exe INFERRED; -h hashes→file.hashes; Publisher unmapped (no service.provider_path/publisher) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "artifact",
    "type": "autostart_inventory",
    "action": "inventory",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-09-01T10:00:00Z",
    "original": "2026-09-01T10:00:00Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "second",
    "state": "inferred"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "autoruns-001",
    "format": "csv",
    "parser": "autorunsc-parser",
    "parser_version": "1.0.0"
  },
  "raw": "\"Entry Location\",\"Entry\",\"Enabled\",\"Hidden\",\"Path\",\"Launch String\",\"Publisher\",\"Image Path\",\"Version\",\"Last Modified\",\"MD5\",\"SHA-1\",\"SHA-256\",\"Verification Status\"\r\n\"Logon\",\"OneDrive\",\"Enabled\",\"false\",\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\",\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background\",\"Microsoft Corporation\",\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\",\"25.0.1.1\",\"2026-09-01T10:00:00\",\"aa11...\",\"bb22...\",\"cc33...\",\"Verified\"\r\n",
  "artifact": {
    "type": "process",
    "identity": "OneDrive",
    "path": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
    "attributes": "Enabled; Publisher=Microsoft Corporation; Verification=Verified"
  },
  "process": {
    "exe": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
    "name": "OneDrive.exe",
    "original_file_name": "OneDrive.exe",
    "hashes": {
      "md5": {
        "$state": "inferred",
        "$note": "abbreviated for example",
        "$raw": "aa11..."
      },
      "sha1": {
        "$state": "inferred",
        "$raw": "bb22..."
      },
      "sha256": {
        "$state": "inferred",
        "$raw": "cc33..."
      }
    }
  },
  "unmapped": [
    {
      "name": "autoruns.location",
      "value": "Logon"
    },
    {
      "name": "publisher",
      "value": "Microsoft Corporation"
    },
    {
      "name": "enabled",
      "value": "Enabled"
    },
    {
      "name": "hidden",
      "value": "false"
    }
  ]
}
```

## sigcheck / sigcheck -vt (2)

### EX-SIGCHECK-1 — sigcheck file inventory

<!-- covers: SEC-B sigcheck; Path→file.path, Publisher→executable.product INFERRED; signature status Unsigned -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "executable",
    "type": "executable_inventory",
    "action": "inventory",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:00:00Z",
    "original": "2026-10-09T14:00:00Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "second",
    "state": "inferred"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "sigcheck-001",
    "format": "csv",
    "parser": "sigcheck-parser",
    "parser_version": "1.0.0"
  },
  "raw": "\"Path\",\"Time\",\"Company\",\"Product\",\"Description\",\"Version\",\"MD5\",\"SHA1\",\"SHA-256\",\"PESHA1\",\"PESHA256\",\"PEMD5\",\"ImpHash\",\"Verified Signer\",\"Signer Certificate\",\"Status\",\"Signing Date\",\"Counter Signers\",\"Counter Signer Certificate\",\"Counter Signer Status\",\"Description URL\"\r\n\"C:\\Temp\\evil.exe\",\"2026-10-09 14:00:00\",\"(n/a)\",\"(n/a)\",\"(n/a)\",\"1.0.0.0\",\"aa11\",\"bb22\",\"cc33\",\"dd44\",\"ee55\",\"ff66\",\"11223344\",\"(n/a)\",\"(n/a)\",\"Unsigned\",\"\",\"\",\"\",\"\",\"\"\r\n",
  "executable": {
    "path": "C:\\Temp\\evil.exe",
    "format": "pe",
    "file_version": "1.0.0.0",
    "product": {
      "$state": "null",
      "$raw": "(n/a)"
    },
    "hashes": {
      "md5": "aa11",
      "sha1": "bb22",
      "sha256": "cc33"
    },
    "signature": {
      "signed": false,
      "status": "Unsigned",
      "signer": {
        "$state": "null",
        "$raw": "(n/a)"
      }
    }
  }
}
```

### EX-SIGCHECK-VT — sigcheck -vt VirusTotal result

<!-- covers: SEC-B sigcheck -vt; VT detection→artifact_finding derived_by sentinel; extra example beyond brief's tool list -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "artifact_finding",
    "type": "virustotal_detection",
    "action": "scan",
    "outcome": "success",
    "severity": "low",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": null,
    "timezone_source": "none",
    "precision": "unknown",
    "state": "unknown"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "sigcheck-vt-001",
    "format": "csv",
    "parser": "sigcheck-vt-parser",
    "parser_version": "1.0.0"
  },
  "raw": "\"Path\",\"MD5\",\"SHA-1\",\"SHA-256\",\"VT Detection\",\"VT URL\",\"Verified Signer\",\"Status\"\r\n\"C:\\Temp\\evil.exe\",\"aa11\",\"bb22\",\"cc33\",\"12/72\",\"https://www.virustotal.com/gui/file/cc33\",\"(n/a)\",\"Unsigned\"\r\n",
  "artifact_finding": {
    "artifact_type": "file",
    "artifact_identity": "C:\\Temp\\evil.exe",
    "finding": {
      "$state": "inferred",
      "$note": "VT Detection column ratio",
      "$raw": "12/72"
    },
    "evidence": {
      "$state": "inferred",
      "$raw": "https://www.virustotal.com/gui/file/cc33"
    },
    "scanner": "VirusTotal",
    "confidence": {
      "$state": "inferred",
      "$note": "12/72 engines",
      "$raw": "low"
    }
  }
}
```

## Example coverage matrix

| Group | Count | IDs |
|---|---|---|
| Sysmon (Microsoft-Windows-Sysmon/Operational) | 30 | EX-SYSMON-1, EX-SYSMON-2, EX-SYSMON-3, EX-SYSMON-4, EX-SYSMON-5, EX-SYSMON-6, EX-SYSMON-7, EX-SYSMON-8, EX-SYSMON-9, EX-SYSMON-10, EX-SYSMON-11, EX-SYSMON-12, EX-SYSMON-13, EX-SYSMON-14, EX-SYSMON-15, EX-SYSMON-16, EX-SYSMON-17, EX-SYSMON-18, EX-SYSMON-19, EX-SYSMON-20, EX-SYSMON-21, EX-SYSMON-22, EX-SYSMON-23, EX-SYSMON-24, EX-SYSMON-25, EX-SYSMON-26, EX-SYSMON-27, EX-SYSMON-28, EX-SYSMON-29, EX-SYSMON-255 |
| Windows Security channel | 32 | EX-SEC-1102, EX-SEC-4624, EX-SEC-4625, EX-SEC-4634, EX-SEC-4647, EX-SEC-4648, EX-SEC-4672, EX-SEC-4688, EX-SEC-4689, EX-SEC-4697, EX-SEC-4698, EX-SEC-4720, EX-SEC-4722, EX-SEC-4724, EX-SEC-4726, EX-SEC-4728, EX-SEC-4732, EX-SEC-4738, EX-SEC-4740, EX-SEC-4756, EX-SEC-4767, EX-SEC-4768, EX-SEC-4769, EX-SEC-4771, EX-SEC-4776, EX-SEC-5140, EX-SEC-5145, EX-SEC-5156, EX-SEC-5158, EX-SEC-4946, EX-SEC-4947, EX-SEC-4948 |
| Other Windows channels (System, PowerShell, WMI, Defender, TaskScheduler, LSM, RCM, AppLocker) | 37 | EX-WIN-7034, EX-WIN-7036, EX-WIN-7040, EX-WIN-7043, EX-WIN-7045, EX-WIN-104, EX-WIN-PS400, EX-WIN-PS403, EX-WIN-PS600, EX-WIN-PS800, EX-WIN-PS4103, EX-WIN-PS4104, EX-WIN-PS4105, EX-WIN-PS4106, EX-WIN-WMI5857, EX-WIN-WMI5858, EX-WIN-WMI5860, EX-WIN-DEF1116, EX-WIN-DEF1117, EX-WIN-DEF5001, EX-WIN-DEF5007, EX-WIN-TS106, EX-WIN-TS140, EX-WIN-TS141, EX-WIN-TS200, EX-WIN-TS201, EX-WIN-LSM21, EX-WIN-LSM22, EX-WIN-LSM23, EX-WIN-LSM24, EX-WIN-LSM25, EX-WIN-LSM39, EX-WIN-RCM1149, EX-WIN-AL8003, EX-WIN-AL8004, EX-WIN-AL8006, EX-WIN-AL8007 |
| Zeek JSON logs | 6 | EX-ZEEK-CONN, EX-ZEEK-DNS, EX-ZEEK-HTTP, EX-ZEEK-SSL, EX-ZEEK-NOTICE, EX-ZEEK-FILES |
| Suricata EVE JSON | 6 | EX-EVE-ALERT, EX-EVE-HTTP, EX-EVE-DNS, EX-EVE-TLS, EX-EVE-FLOW, EX-EVE-FILEINFO |
| Nmap XML export | 1 | EX-NMAP-1 |
| netstat snapshot | 1 | EX-NETSTAT-1 |
| schtasks /query snapshot | 1 | EX-SCHTASKS-1 |
| sc query snapshot | 1 | EX-SCQUERY-1 |
| sc qc snapshot | 1 | EX-SCQC-1 |
| reg export .reg snapshot | 1 | EX-REGEXPORT-1 |
| PowerShell Export-Csv inventory | 1 | EX-EXPORTCSV-1 |
| autorunsc autostart inventory | 1 | EX-AUTORUNS-1 |
| sigcheck / sigcheck -vt | 2 | EX-SIGCHECK-1, EX-SIGCHECK-VT |

Total examples: 121

Schema categories with no example in this corpus (gaps, documented in
the handoff): `document`, `archive_member` — no harvested source maps to
them yet.

<!-- END SEC-C -->

---

## DECISIONS

```yaml
# Stage-2 design decisions (schema + mappings). Evidence ids resolve to the
# Verification Log above; labels follow the three-value system.

decisions:

  - id: D2-001
    title: Bare JSON null forbidden; value-state object carries null/unknown/invalid/conflicting/inferred
    decision: >-
      Canonical events never contain a bare null except time.utc (only when
      time.state is unknown/invalid). Absent = omitted key. Source-null,
      unknown, unparsable, conflicting and Sentinel-inferred values are
      expressed with the {$state,...} object. Rationale: detectors must be
      able to distinguish "source says empty" from "source has no value"
      from "parser could not parse" — bare null conflates all three.
    evidence: [C-SCHEMA, A-SWIFT-CFG, B-LOC-HARVEST]
    status: accepted

  - id: D2-002
    title: Three-level semantic classification (file format -> semantic data type -> security behaviour) resolves Stage-1 Q1
    decision: >-
      Level 1 = source.format enum (container); Level 2 = source.record.type
      + channel/provider/EID or header set (record shape); Level 3 =
      event.category (26 values) + event.type + action/outcome, with
      event.derived_by marking source-vs-Sentinel authorship. Stage-1's
      severity/level_original axes (D-007) remain separate and are NOT
      conflated with these levels.
    evidence: [C-SCHEMA, A-SYSMON-DOC-DL, B-LOC-HARVEST, A6-SIGMAHQ-INV]
    status: accepted

  - id: D2-003
    title: Timestamp policy — never guess a timezone
    decision: >-
      time.timezone_source is one of source_explicit | source_documented_utc
      | run_configuration | none. Sysmon UtcTime and Zeek ts are documented
      UTC (source_documented_utc); EVTX TimeCreated SystemTime is UTC by
      format (source_explicit); netstat/schtask exports carry no timestamp
      (timezone_source: none, utc: null, state: unknown). A run-config
      override yields state: inferred. Precision is recorded per event
      (millisecond for EVTX/Zeek-epoch-float, etc.).
    evidence: [A-SYSMON-DOC-DL, B-LOC-HARVEST, A5-ZEEK-DOC]
    status: accepted

  - id: D2-004
    title: Provenance — event.derived_by plus optional $source_ref / sources[]
    decision: >-
      event.derived_by (source|sentinel) classifies the whole classification
      decision; field-level inference uses {$state: inferred}; cross-artifact
      lineage (Zeek notice enriched from conn) uses sources[]. Sentinel
      classifications are never presented as source claims.
    evidence: [C-SCHEMA, A-SWIFT-CFG]
    status: accepted

  - id: D2-005
    title: Process identity hierarchy — GUID primary, documented PID-reuse failure mode
    decision: >-
      Primary identity = (host, process.guid) where Sysmon supplies
      ProcessGuid. Fallback = (host, pid, exe, start_time) marked inferred.
      PID-only linkage (Security 4688 has no ProcessGuid; netstat PID column)
      is documented as carrying a PID-reuse failure mode and must not be
      used by detectors for high-assurance parent/child chains.
    evidence: [A-SYSMON-DOC-EV, A-SWIFT-CFG, A-SEC-4688, B-NETSTAT-DOC]
    status: accepted

  - id: D2-006
    title: Sysmon field names evidenced by config-schema (SwiftOnSecurity + sysmon-modular), MS docs summary-level only
    decision: >-
      Microsoft's Sysmon pages document event names, tags and UTC semantics
      but list no per-field inventories. Exact EventData element names come
      from the published config-schema field names in SwiftOnSecurity's
      sysmon-config @1836897f (VERIFIED, community) and the
      olafhartong/sysmon-modular @082cba578667 corpus (VERIFIED, community).
      `sysmon -s` output (the documented full schema) was not runnable on
      this host (Sysmon not installed) — listed in NOT_VERIFIED.
    evidence: [A-SYSMON-DOC-DL, A-SYSMON-DOC-EV, A-SWIFT-CFG, A-SYSMON-MODULAR, B-LOC-HARVEST]
    status: accepted

  - id: D2-007
    title: Security-channel event pages are archived Microsoft Learn previous-versions pages; field names transcribed from Event XML blocks
    decision: >-
      Current-pattern URLs (learn.microsoft.com/.../event-<id>) redirect to
      archived previous-versions pages (source repo MicrosoftDocs/officearchive-pr).
      Field names are the <Data Name="..."> element names inside each page's
      Event XML block. Each redirected URL is recorded in the Verification
      Log. 4728/4756 have no dedicated page (404) — field equivalence to
      4732 documented as INFERRED (A-SEC-GRPMGMT).
    evidence: [A2-SEC-PAGES, A3-SEC-PAGES, A-SEC-GRPMGMT]
    status: accepted

  - id: D2-008
    title: Defender 1116/1117 typed as third_party_alert with full 42-element capture; unmapped list documented
    decision: >-
      Defender detection/action events become category third_party_alert
      (vendor=Microsoft, product=Defender Antivirus), rule_id=Threat ID,
      rule_name=Threat Name, severity_raw=Severity Name, observable=Path,
      mitigation=Action Name. All 42 EventData element names (incl.
      space-bearing names and Unused* placeholders) are mapped or listed as
      unmapped. 5007 -> config_check; 5001 -> config_check (RTP disabled).
      derived_by: sentinel (Defender's taxonomy is not Sentinel's).
    evidence: [B-LOC-HARVEST, B-DEFENDER-DOC]
    status: accepted

  - id: D2-009
    title: RDP LSM 21-25/39 classified as authentication with Sentinel-authored event.type names
    decision: >-
      LSM events (User/SessionID/Address elements, VERIFIED-LOCAL) are typed
      rdp_logon/rdp_logoff/rdp_shadow_notify/rdp_disconnect with
      derived_by: sentinel. SessionID mapped to authentication.logon_id is
      INFERRED (no dedicated session field in schema v1). Address='LOCAL'
      literal documented. RCM 1149 element names UNVERIFIED (no samples on
      this host).
    evidence: [B-LOC-HARVEST, B-LSM-DOC, C-DFIR-LSM]
    status: accepted

  - id: D2-010
    title: Snapshot exports (netstat/schtasks/sc/reg/autoruns/sigcheck) emit derived_by: sentinel snapshot events
    decision: >-
      These sources describe configuration or point-in-time state, not
      events. Each row/record becomes one canonical event with
      derived_by: sentinel, event.type *_snapshot or config-oriented names,
      time.state: unknown unless the harvest run supplies a file mtime
      (then state: inferred). CSV parsers bind columns by header row at
      runtime (headers UNVERIFIED against vendor docs for autorunsc/sigcheck/
      schtasks /fo CSV — see NOT_VERIFIED).
    evidence: [B-NETSTAT-DOC, B-SCHTASKS-DOC, B-SC-DOC, B-REG-DOC, B-EXPORTCSV-DOC, B-AUTORUNS-UNVERIFIED]
    status: accepted

  - id: D2-011
    title: WMI 5860 element Processid casing preserved exactly (lowercase d)
    decision: >-
      Local harvest shows 5860 uses <Processid> (lowercase d) while 5858
      uses <ClientProcessId> (uppercase P). Parsers must match element names
      case-sensitively. Both map to canonical wmi.client_process_id /
      wmi.process.pid per SEC-B table; the casing divergence is called out
      as a parser trap in the Sigma pipeline config too.
    evidence: [B-LOC-HARVEST]
    status: accepted

  - id: D2-012
    title: Lossless raw + unmapped[]; schema objects are additionalProperties:false
    decision: >-
      Every canonical event carries raw (verbatim source record) and may
      carry unmapped[] (named source fields with no canonical home). Typed
      payload objects reject unknown keys (additionalProperties: false) so
      schema drift is caught at parse time rather than silently ignored.
      $-prefixed keys are reserved for the state machinery.
    evidence: [C-SCHEMA]
    status: accepted

  - id: D2-013
    title: host/user required but may be empty objects
    decision: >-
      host and user are always present (never omitted) so detectors can rely
      on the keys' existence; they may be {} when the source carries no host
      or user attributes (e.g. some netstat/CSV snapshots).
    evidence: [C-SCHEMA, B-NETSTAT-DOC]
    status: accepted

  - id: D2-014
    title: Sigma field-mapping pipelines are configuration data, not code
    decision: >-
      §3 declares per-logsource Sigma field-name -> canonical-path mappings
      plus declarative value transforms as YAML. This keeps the
      parser/detector separation intact (detectors consume only canonical
      events; Sigma rules are translated through this config layer) and
      avoids a pySigma runtime dependency on the detector path. Corpus pin:
      SigmaHQ/sigma-rules @8a4813404e. Pipeline shape mirrors pySigma
      structure for future adaptability (pySigma-pipeline-windows
      @5d7170663e, pySigma-pipeline-sysmon @965d57c232 both LGPL-2.1-only —
      licence compatible per Stage-1 licence register).
    evidence: [A6-SIGMAHQ-INV, A6-PIPE-WINDOWS, A6-PIPE-SYSMON, STAGE1-D004, STAGE1-D008]
    status: accepted

  - id: D2-015
    title: Security-event %%-code direction mapping left UNVERIFIED; parsers emit unknown
    decision: >-
      5156 Direction %%14592-style codes are documented as message-table
      strings, but the numeric -> inbound/outbound mapping was not
      corroborated by an allowed primary source in this stage. Parsers emit
      $state: unknown for network.direction from 5156 until corroborated
      (OPEN_QUESTIONS Q2-007).
    evidence: [A-SEC-5156]
    status: accepted

  - id: D2-016
    title: LSM SessionID -> authentication.logon_id is INFERRED; schema v1 has no dedicated session field
    decision: >-
      RDP SessionID is a session identifier, not a logon LUID; mapping it to
      authentication.logon_id is an INFERRED equivalence flagged in SEC-B
      and OPEN_QUESTIONS Q2-009. Detectors needing strict logon-LUID
      semantics must not treat LSM SessionID as equivalent.
    evidence: [B-LOC-HARVEST, B-LSM-DOC]
    status: accepted

  - id: D2-017
    title: Sysmon EID 255 (error) carries no verified EventData field names; minimal envelope-only example
    decision: >-
      No allowed source listed EID 255 EventData elements. EX-SYSMON-255 is
      envelope-only (time/host/user/source/raw, empty-ish payload) and is
      labelled UNVERIFIED. Parsers must not invent EID 255 fields.
    evidence: [A-SYSMON-DOC-EV, A-SWIFT-CFG]
    status: accepted

  - id: D2-018
    title: documents/archive_member categories reserved; no harvested source maps to them in Stage 2
    decision: >-
      schema v1 defines document and archive_member payloads for future
      offline-analysis sources (office metadata, archive listings). No
      current source maps to them; examples section documents this as a
      deliberate coverage gap (categories exist, examples do not).
    evidence: [C-SCHEMA, C-COVERAGE]
    status: accepted

  - id: D2-019
    title: Zeek column binding is header-driven (#fields), never positional
    decision: >-
      Zeek TSV logs declare their column set in a #fields header line that
      varies by policy. Parsers MUST bind by header name. ts is an epoch
      float (documented UTC); converted to time.utc with precision
      microsecond and timezone_source: source_documented_utc.
    evidence: [A5-ZEEK-DOC, A5-ZEEK-SRC]
    status: accepted

  - id: D2-020
    title: Classic PowerShell 400/403/600 unnamed <Data> elements documented as positional + Key=Value detail blob
    decision: >-
      Classic PowerShell events render three UNNAMED <Data></Data> elements
      (engine state, previous state, detail blob). The blob's Key=Value
      lines (NewEngineState, HostApplication, ...) are parsed into
      powershell.* fields per SEC-B; SequenceNumber has no schema home
      (Q2-013). Empty CommandLine inside the blob -> $state: "null".
    evidence: [B-LOC-HARVEST, B-PS-MANIFEST]
    status: accepted

  - id: D2-021
    title: Sysmon 7036-style unnamed System-event Data elements (param1/param2) and Binary UTF-16 carrier documented
    decision: >-
      System 7036 uses unnamed <Data></Data> positional elements plus a
      Binary hex field whose bytes decode (UTF-16LE) to the service name —
      both carriers documented in SEC-B; parsers may use either, preferring
      the named/decoded carrier when present, and must record which carrier
      was used in unmapped[] provenance if both disagree.
    evidence: [B-LOC-HARVEST, B-SYS-ARCHIVE]
    status: accepted

  - id: D2-022
    title: AppLocker 8003/8004/8006/8007 element names UNVERIFIED (templates only, no local samples)
    decision: >-
      Message templates verified from Microsoft docs; EventData element names
      could not be corroborated (channel enabled but no AppLocker events on
      this host). EX-WIN-AL* examples use template parameters, labelled
      UNVERIFIED. Parsers treat these fields as optional, never required.
    evidence: [B-LOC-HARVEST, B-APPLOCKER-DOC]
    status: accepted

  - id: D2-023
    title: TaskScheduler Operational events UNVERIFIED element names (channel disabled locally)
    decision: >-
      106/140/141/200/201 templates verified from Microsoft docs; element
      names UNVERIFIED (channel exists but recorded zero events on this
      host). Parser strategy: render message text, parse Task Name/Path as
      INFERRED key-values, keep payload minimal.
    evidence: [B-LOC-HARVEST, B-TASKSCHED-DOC]
    status: accepted

  - id: D2-024
    title: schema_version const canonical-event/v1; semver-style evolution promised by filename, not schema
    decision: >-
      The literal string "canonical-event/v1" is the version gate. Breaking
      changes ship as canonical_event_v2.schema.json; additive changes bump
      a doc-level revision note. Detectors pin to a schema_version string.
    evidence: [C-SCHEMA, STAGE1-D001]
    status: accepted
```

---

## OPEN_QUESTIONS

```yaml
open_questions:

  - id: Q2-001
    title: Sysmon Hashes KEY=value,KEY=value rendering format not source-confirmed
    detail: >-
      SEC-A flagged the exact Sysmon Hashes string format (comma-separated
      KEY=value pairs, key names SHA256/MD5/IMPHASH/...) as UNVERIFIED —
      observed in config-schema and community docs but not in a Microsoft
      per-field specification. Parsers must tolerate alternative separators
      and unknown keys (route to hashes.other).
    blocking: parser implementation for Sysmon hash splitting
    candidate_resolution: run `sysmon -s` on an elevated Windows host with Sysmon installed and capture the canonical schema string.

  - id: Q2-002
    title: ElevatedToken true/false vs %16384-style renderings
    detail: >-
      Local observation shows `%%1842`-style message-table strings; the
      boolean renderings (true/false) seen in community docs are not
      source-confirmed. Parsers must accept both plus the %% form and emit
      $state: unknown when the rendering is unrecognized.
    blocking: nothing (tolerant parser suffices)
    candidate_resolution: capture 4624/4672 events with both renderings on an elevated host.

  - id: Q2-003
    title: Literal EventType strings for Sysmon registry (createKey/setValue/...) and pipe (CreatePipe/ConnectPipe)
    detail: >-
      Registry EID 12/13/14 EventType literal strings and pipe EID 17/18
      operation strings are UNVERIFIED against Microsoft docs; observed in
      community configs. Mapping to the registry.operation / pipe.operation
      enums is INFERRED.
    blocking: nothing (enum mapping table is tolerant)
    candidate_resolution: capture real EID 12/13/14/17/18 events on a Sysmon host.

  - id: Q2-004
    title: Sysmon EID 255 EventData field names unknown
    detail: >-
      No allowed source listed EID 255 (Sysmon error) EventData elements.
      EX-SYSMON-255 is envelope-only (D2-017). Parsers must not invent fields.
    blocking: nothing (error events carry no useful payload for detectors)
    candidate_resolution: `sysmon -s` full schema capture.

  - id: Q2-005
    title: Security 4688 has no ProcessGuid — PID-reuse risk for parent/child chains
    detail: >-
      Sysmon EID 1 supplies ProcessGuid; Security 4688 supplies only
      ProcessId/ParentProcessId. Cross-source correlation (4688 + Sysmon)
      must not silently merge on PID alone (D2-005).
    blocking: detector rules that join 4688 to Sysmon process events
    candidate_resolution: use Sysmon EID 1 as the primary process source; treat 4688 as lower-fidelity supplementary.

  - id: Q2-006
    title: Nmap service/OS fields (product, version, osmatch) have no schema home
    detail: >-
      Nmap XML service product/version/name and osmatch name/accuracy are
      captured in unmapped[] (SEC-B Nmap table). A future schema revision
      may add network.service / host.os.match fields.
    blocking: nothing (unmapped captures losslessly)
    candidate_resolution: Stage-3 backlog if Nmap-based detection needs them.

  - id: Q2-007
    title: 5156 Direction %%-code numeric -> inbound/outbound mapping UNVERIFIED
    detail: >-
      D2-015: %%14592-style direction codes are message-table strings; the
      numeric-to-direction mapping was not corroborated. Parsers emit
      $state: unknown for network.direction from 5156 until resolved.
    blocking: WFP-based direction-sensitive detectors
    candidate_resolution: capture 5156 events with known-direction traffic and correlate, or find the message-table source.

  - id: Q2-008
    title: LSM RCM 1149 EventData element names UNVERIFIED
    detail: >-
      RemoteConnectionManager channel exists but recorded zero 1149 events
      on this host; element names (user/domain/IP) come from message
      templates only. EX-WIN-RCM1149 labelled UNVERIFIED.
    blocking: nothing (parser treats fields as optional)
    candidate_resolution: trigger an RDP logon and capture 1149.

  - id: Q2-009
    title: LSM SessionID -> authentication.logon_id equivalence is INFERRED
    detail: >-
      D2-016: RDP SessionID is a session id, not a logon LUID; schema v1 has
      no dedicated session field. Detectors needing strict logon-LUID
      semantics must not treat them as equivalent.
    blocking: logon-session-correlation detectors across LSM + Security
    candidate_resolution: Stage-3 schema revision may add authentication.session_id.

  - id: Q2-010
    title: Autoruns/sigcheck/schtasks CSV headers UNVERIFIED against vendor docs
    detail: >-
      Sysinternals pages do not publish CSV column sets; parsers bind by
      header row at runtime (D2-010). Column-name drift across versions is
      possible.
    binding: none for schema (header-driven), but example values are illustrative
    candidate_resolution: capture real autorunsc -c / sigcheck -c output on this host (tools not installed in Stage 2).

  - id: Q2-011
    title: sc query / sc qc field lists partially UNVERIFIED (sc qc page 404)
    detail: >-
      SEC-B: sc query fields verified; sc qc field list came back 404.
      Example EX-SCQC-1 uses commonly-documented field names labelled
      UNVERIFIED.
    binding: nothing (snapshot source, tolerant parser)
    candidate_resolution: run sc qc on this host and capture real output.

  - id: Q2-012
    title: WMI 5859/5861 and TaskScheduler element names UNVERIFIED (no local samples)
    detail: >-
      D2-022/D2-023: message templates verified; EventData elements not
      corroborated. Examples use template parameters, labelled UNVERIFIED.
    binding: nothing (optional fields)
    candidate_resolution: enable the channels and exercise WMI filter/consumer creation + Task Scheduler actions.

  - id: Q2-013
    title: Classic PowerShell SequenceNumber has no schema home
    detail: >-
      The classic-PS detail blob includes SequenceNumber (and some blobs
      include PipelineId already mapped); SequenceNumber is captured in
      unmapped[]. Low detector value.
    binding: nothing
    candidate_resolution: leave in unmapped[] unless a detector needs it.

  - id: Q2-014
    title: Sysmon EID 15/16/19/20/21/23/24/26/27/28/29 sub-fields partially unmapped
    detail: >-
      SEC-A lists several Sysmon sub-fields with no schema home (NewThreadId,
      clipboard payload, PreviousCreationUtcTime, ConfigurationFileHash,
      remote-host SourceHostname, etc.). All are captured in unmapped[].
    binding: nothing for current detectors
    candidate_resolution: Stage-3 schema backlog if rules need them.

  - id: Q2-015
    title: Zeek notice/files record fields beyond the mapped core have no schema home
    detail: >-
      Zeek notice (note/script) and files (fuid/tx_hosts) carry fields with
      no canonical home; captured in unmapped[]. files.mime_type maps to
      file.type (INFERRED — file.type is the level-2 semantic type slot).
    binding: nothing
    candidate_resolution: Stage-3 if notice-driven detection needs first-class fields.

  - id: Q2-016
    title: Sysmon EID 9 (raw-access) and EID 16 (config-change) category choices are INFERRED
    detail: >-
      EID 9 maps to file (raw device access) per SEC-A; EID 16 maps to
      config_check. Both are Sentinel-authored category assignments
      (derived_by: sentinel) — the sources themselves do not publish a
      category taxonomy.
    binding: nothing
    candidate_resolution: revisit if detectors find the mapping unnatural.
```

---

## NOT_VERIFIED

Consolidated list of every claim labelled UNVERIFIED in this document (and
its SEC-A/SEC-B/SEC-C fragments). None of these are used as required keys in
the schema; parsers must treat the affected fields as optional and tolerant.

| # | Claim | Where | Why unverified |
|---|---|---|---|
| 1 | Sysmon `Hashes` `KEY=value,KEY=value` exact rendering | SEC-A Sysmon tables | Microsoft docs list no per-field Hashes format; community/config-schema only (Q2-001) |
| 2 | Security `ElevatedToken` `true`/`false` and `%16384`-style renderings | SEC-A Security tables | Observed `%%` message-table form; boolean form from community docs only (Q2-002) |
| 3 | Sysmon registry `EventType` literal strings (`createKey`/`setValue`/...) | SEC-A Sysmon EID 12/13/14 | Community/config-schema only (Q2-003) |
| 4 | Sysmon pipe EID 17/18 operation literal strings | SEC-A Sysmon EID 17/18 | Community/config-schema only (Q2-003) |
| 5 | Sysmon EID 255 EventData field names | SEC-A Sysmon EID 255 | No allowed source lists them; envelope-only example (Q2-004) |
| 6 | Sysmon ProcessTampering `Type` value set (EID 25) | SEC-A Sysmon EID 25 | Not in config-schema sample |
| 7 | Sysmon clipboard-content `Hashes` semantics (EID 24) | SEC-A Sysmon EID 24 | Semantics not documented |
| 8 | Security 4728/4756 field lists | SEC-A (via 4732 equivalence) | No dedicated MS page (404); equivalence INFERRED (A-SEC-GRPMGMT) |
| 9 | 5156 `Direction` `%%`-code → inbound/outbound mapping | SEC-A Security 5156 | Message-table strings; numeric mapping not corroborated (Q2-007, D2-015) |
| 10 | System 104 EventData elements beyond `param3` | SEC-B System 104 | Template verified; elements not (Q2-012-adjacent) |
| 11 | TaskScheduler 106/140/141/200/201 EventData elements | SEC-B TaskScheduler | Channel disabled locally; templates only (Q2-012, D2-023) |
| 12 | WMI 5859/5861 EventData elements | SEC-B WMI | No local samples; templates only (Q2-012) |
| 13 | AppLocker 8003/8004/8006/8007 EventData elements | SEC-B AppLocker | Channel enabled but zero events; templates only (Q2-012, D2-022) |
| 14 | RDP RCM 1149 EventData elements | SEC-B RCM 1149 | Zero events on host; templates only (Q2-008) |
| 15 | Classic PowerShell 800 element names | SEC-B PS 800 | Not documented in allowed sources; no samples |
| 16 | `sc qc` field list | SEC-B sc qc | Microsoft page 404 (Q2-011) |
| 17 | Autoruns/autorunsc CSV column headers | SEC-B autoruns | Sysinternals docs do not publish CSV headers (Q2-010, D2-010) |
| 18 | Sigcheck CSV column headers | SEC-B sigcheck | Sysinternals docs do not publish CSV headers (Q2-010) |
| 19 | `schtasks /query /fo CSV /v` header row | SEC-B schtasks | Not in Microsoft docs; LIST-mode fields documented instead (Q2-010) |
| 20 | Sysmon `User` field may carry SID vs DOMAIN\user ambiguity | SEC-A Sysmon tables | Rendering varies by Sysmon version/config; not source-confirmed |
| 21 | Sysmon EID 9/16/19/20/21/23/24/26/27/28/29 category assignments (file/config_check/wmi/...) | SEC-A + §5 examples | Sentinel-authored (derived_by: sentinel); sources publish no categories |
| 22 | LSM 21/22/23/24/25/39 `event.type` names (rdp_logon etc.) | SEC-B LSM | Sentinel-authored naming (D2-009); Microsoft publishes message text only |
| 23 | Sysmon `ParentUser` may carry SID (vs username) | SEC-A Sysmon EID 1 | Rendering ambiguity; not source-confirmed |

*Generated 2026-10-09 for the Sentinel HIDS Stage-2 deliverable. All
example canonical events validated against `canonical_event_v1.schema.json`
(Draft 2020-12) with Python `jsonschema` 4.26.0; 121/121 examples pass.*
