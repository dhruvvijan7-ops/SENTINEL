## 5. Example canonical events

*(Assembled from SEC-C — 121 examples, all validated against
`canonical_event_v1.schema.json` with Python `jsonschema` 4.26.0
`Draft202012Validator`; 0 errors, executed 2026-10-09.)*

<!--ASSEMBLER:INSERT-SEC-C-->

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
