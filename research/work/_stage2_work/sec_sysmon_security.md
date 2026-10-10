---
section_id: SEC-A
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
---

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
