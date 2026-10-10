# Stage-2 implementation notes for Milestone 1 (M1)

Source of truth: `stage-2-canonical-event-and-mappings.md` (13,049 lines, dated 2026-10-09) + sibling `canonical_event_v1.schema.json` (JSON Schema Draft 2020-12, validated with jsonschema 4.26.0; 121/121 §5 examples pass). Line refs below are `stage-2-canonical-event-and-mappings.md:LINE`.

M1 goal per this file: an EVTX upload must be parsed into canonical-event/v1 rows that validate against `canonical_event_v1.schema.json`, with correct time handling, provenance, unmapped preservation, and classification backfill.

Doc-vs-schema discrepancies (verified by reading the schema directly; schema wins on validation):
- Top-level optional `classification` enum (`public|internal|restricted`) exists in the schema (added by SENTINEL_IMPLEMENTATION_SPEC conflict fix C-13 / D8-02-fix) but is NOT listed in §1.1 Envelope table.
- Schema `source.format` enum includes `xml`; the §1.1 doc list omits it. Schema enum: `evtx|json|csv|xml|tsv|text|nmap_xml|pcap|sqlite|yaml|other`.
- §4 worked examples cite ids `EX-WIN-1116`, `EX-WIN-4104`, `EX-ZEEK-conn`, `EX-EVE-alert`; the authoritative §5 index uses `EX-WIN-DEF1116`, `EX-WIN-PS4104`, `EX-ZEEK-CONN`, `EX-EVE-ALERT`.

---

## 1. §1 Field Dictionary — envelope of canonical-event/v1

Notation (§1.1, lines 335-344): every field is optional unless the Req column says `yes`. `str|int|bool|num` = bare JSON scalar; `state` = value-state object; `X|state` = either form. All typed objects are `additionalProperties: false`; `$`-prefixed keys are reserved for the state machinery; `additionalProperties: false` also at the envelope level. The 26 payload objects are named exactly as their `event.category` value.

### 1.1 Required vs optional (schema `required` verified: `["schema_version","event","tenant_id","workspace_id","run_id","time","host","user","source","raw"]`)

| Key | Req | Type / enum |
|---|---|---|
| `schema_version` | yes | const `"canonical-event/v1"` |
| `event` | yes | object, all six subkeys required (below) |
| `event.category` | yes | enum of 26 (§1.2 list, below) — selects the single required payload object via 26 schema `if/then` rules |
| `event.type` | yes | str `^[a-z][a-z0-9_]*$` (e.g. `process_create`, `network_connection`, `malware_detected`) |
| `event.action` | yes | str\|state (`create`, `delete`, `connect`, `start`, `block`, …) |
| `event.outcome` | yes | enum `success\|failure\|unknown` |
| `event.severity` | yes | enum `informational\|low\|medium\|high\|critical` \| state |
| `event.derived_by` | yes | enum `source\|sentinel` |
| `tenant_id` / `workspace_id` / `run_id` | yes | non-empty str; every row carries all three even single-tenant |
| `time` | yes | object (see §2 below) |
| `host` | yes | object, may be `{}` (never omit the key; D2-013) |
| `user` | yes | object, may be `{}` |
| `source` | yes | object (see §3 below) |
| `raw` | yes | any JSON value — verbatim source record, lossless (string for text/EVTX-rendered XML, object for JSON). Parsers must not drop fields here even when `unmapped[]` captures them structurally |
| `classification` | no | enum `public\|internal\|restricted` (schema top-level; §5 examples omit it; see §4 of these notes) |
| `unmapped` | no | array of `{name, value}` (both keys required, additionalProperties:false; `value` = any) |
| `sources` | no | array of `{source_ref, fields[]}` — cross-artifact provenance; `$source_ref`/`source_ref` point at Verification Log ids or file ids |
| `process`, `network`, `file`, `registry`, `authentication`, `account`, `group_membership`, `service`, `scheduled_task`, `dns`, `http`, `tls`, `image_load`, `driver`, `wmi`, `powershell`, `thread_access`, `pipe`, `third_party_alert`, `fim`, `config_check`, `artifact`, `document`, `archive_member`, `executable`, `artifact_finding` | exactly one required, selected by `event.category` (schema `allOf` if/then per category) | |

`host` fields (all optional inside): `hostname`, `fqdn`, `ips` (array), `os{family,build,version}`, `arch` — each str|state.
`user` fields (all optional): `sid`, `name`, `domain`, `upn`, `logon_id` — each str|state. `user` = event *subject* account.

### 1.2 The 26 `event.category` values (§1.2, lines 389-393 — closed enum, schema-confirmed)

`process`, `network`, `file`, `registry`, `authentication`, `account`, `group_membership`, `service`, `scheduled_task`, `dns`, `http`, `tls`, `image_load`, `driver`, `wmi`, `powershell`, `thread_access`, `pipe`, `third_party_alert`, `fim`, `config_check`, `artifact`, `document`, `archive_member`, `executable`, `artifact_finding`

Payload-object field lists: see §1.2 table (lines 398-425) — key ones for M1 (EVTX):
- `process`: `guid, pid, ppid, exe, name, command_line, current_dir, integrity_level, logon_guid, logon_id, terminal_session_id, owner_sid, owner_name, start_time, original_file_name, hashes{md5,sha1,sha256,imphash,other}, signature{signed,signer,status}, parent{guid,pid,exe,name,command_line,owner_sid}` (note: `process.parent` has NO `owner_name`).
- `authentication`: `logon_type, logon_id, logon_guid, account_sid, account_name, account_domain, target_sid, target_name, target_domain, target_logon_id, source_ip, workstation, auth_package, elev_token, key_length, process_pid, process_name, status, sub_status, failure_reason, caller_process_id, caller_process_name`.
- `service`: `name, display_name, image_path, start_type, service_type, account_name, operation(install|start|stop|change|delete|state), state, exit_code, checkpoint, wait_hint, error_control, load_order_group, dependencies, description, pid`.
- `powershell`: `channel, engine_state, previous_engine_state, host_name, host_id, host_version, host_application, engine_version, runspace_id, pipeline_id, command_name, command_type, script_name, command_path, command_line, script_block_id, script_block_text, script_path, message_number, message_total, context_info, payload, provider_name, new_provider_state`.
- `account`: `sid, name, domain, upn, display_name, sam_account_name, account_type(user|computer|group|other|state), enabled, sid_history`.
- Shared `process_ref` (embedded by other objects): `guid, pid, exe, name, command_line, user_sid, owner_name` (7 fields).
- Shared `hashes`: `md5, sha1, sha256, imphash, other` (each str|state); `signature`: `signed` (bool|state), `signer`, `status`.

### 1.3 Value-state model (§1.4, lines 435-463 — normative)

state_object (schema `$defs/state_object`): required `$state`; optional `$note` (str), `$raw` (str|null), `$candidates[]`, `$source_ref` (str). `$state` enum: `null | unknown | invalid | conflicting | inferred`.

1. **Absent = omitted.** A key absent means "the source does not carry this value". Parsers MUST NOT emit bare `null` anywhere — schema rejects it; the ONLY bare `null` permitted in a canonical event is `time.utc`, and only when `time.state` is `unknown`/`invalid` (schema if/then enforced).
2. **Explicit null** (`$state:"null"`): source rendered an explicit empty (Windows `<Data Name='X'></Data>`, PowerShell detail `CommandLine=` with nothing after `=`). Distinguished from absent. When Windows renders `-` or empty and semantics are null: emit `{"$state":"null","$raw":"-"}` — never `""`, never bare null (SEC-B convention, line 1093).
3. **Unknown** (`$state:"unknown"`): source has the concept but this record could not supply it.
4. **Invalid** (`$state:"invalid"`, WITH `$raw`): value exists but unparsable (malformed timestamp, non-numeric port). e.g. `ElevatedToken=%%1842` → `{"$state":"invalid","$note":"%%nnnn message-table constant; expansion lives in message table, not EVTX","$raw":"%%1842"}` (EX-SEC-4624).
5. **Conflicting** (`$state:"conflicting"`, WITH `$candidates[]`): multiple disagreeing candidates.
6. **Inferred** (`$state:"inferred"`, WITH `$note`): Sentinel produced the value (derived `time.utc`, derived `network.direction` from `Initiated=true`, hex PID→int keeping `$raw`). Sentinel-authored *classification* (not field values) is instead carried by `event.derived_by: sentinel`.

Process identity hierarchy (D2-005): `(host, process.guid)` (Sysmon `ProcessGuid`, per-boot unique) is primary; fallback `(host, pid, exe, start_time)` marked inferred; PID-only linkage (Security 4688 has no GUID) documented PID-reuse failure mode — must not be used for high-assurance parent/child chains.

### 1.4 `event_uid` / ids

- **Not in canonical-event/v1.** The wire schema has no `uid`/`id`/`event_uid` field (stage-2 doc never defines one — "not specified").
- DB side (`schema.sql:132-164`): `events.event_uid uuid NOT NULL DEFAULT uuidv7()`, plus `artifact_id uuid NOT NULL REFERENCES uploads(artifact_id)`, `ingest_time timestamptz NOT NULL DEFAULT now()`, `PK (event_uid, ingest_time)` (partition key included). `event_time_utc timestamptz` nullable "NULL allowed (time.state != ok)" citing D2-003; `event_time_state text NOT NULL CHECK IN ('ok','inferred','unknown','invalid')`; flattened indexed columns `event_category/event_type/event_action/event_outcome/event_severity/event_derived_by`, `host_hostname`, `user_name`, `user_sid`, `source_format/source_parser/source_channel/source_provider/source_event_id/source_record_type`; full envelope persisted losslessly in `document jsonb NOT NULL`; `classification text NOT NULL CHECK IN ('public','internal','restricted')`.
- Ingest idempotency (Stage-3, not Stage-2): `Idempotency-Key` header; same key + same content sha256 → 200 original artifact_id; same key + different sha256 → 409 `GATE_IDEMPOTENCY_MISMATCH`.

---

## 2. Time rules (§1.1 time block + D2-003, lines 360-365; 12613-12624)

`time` object (schema `$defs/time`): required = `utc`, `precision`, `state`; additionalProperties:false.

| Field | Req | Type/enum |
|---|---|---|
| `time.utc` | yes | RFC 3339 str (`format: date-time`) \| **bare null allowed only when `state` is `unknown`/`invalid`** (schema if/then: if utc is null then state ∈ {unknown,invalid}) |
| `time.original` | no | str\|null — timestamp exactly as the source rendered it |
| `time.original_timezone` | no | str\|null — `Z`, `+05:30`, IANA name, when determinable |
| `time.timezone_source` | no | enum `source_explicit\|source_documented_utc\|run_configuration\|none` |
| `time.precision` | yes | enum `millisecond\|second\|microsecond\|nanosecond\|unknown` |
| `time.state` | yes | enum `ok\|inferred\|unknown\|invalid` — `inferred` when utc was derived (epoch→UTC, run-config TZ applied) |

Rules (D2-003: "never guess a timezone"):
- **Sysmon** `UtcTime` → `time.original`; derive `time.utc` (RFC 3339, `Z`), `timezone_source: source_documented_utc` (docs: "Event timestamps are in UTC standard time"), `precision` per source resolution, and **`time.state: inferred`** for the conversion (SYSMON section convention, line 480).
- **Windows Security/System/PowerShell EVTX** `TimeCreated@SystemTime` (has `Z`) → `time.utc` directly with `timezone_source: source_explicit`, `time.state: ok`, `precision: microsecond` (or `unknown` per renderer) (line 1090).
- **Zeek** `ts` epoch float → documented UTC: `timezone_source: source_documented_utc`, precision microsecond, state `inferred` (D2-019).
- **No timestamp at all** (netstat/schtasks/sc/reg/CSV snapshots): `timezone_source: none`, `utc: null`, `state: unknown` (D2-003; EX-NETSTAT-1 pattern).
- Run-config TZ override → `state: inferred`.
- Unparsable source timestamp → `time.state: invalid` (utc null) with the original in `time.original` / state `$raw`.
- 7045-style example shows a quirk worth knowing: EVTX SystemTime `2026-10-09T03:16:33.3071024Z` (7 fractional digits) is rendered in `time.utc` truncated to microseconds `...307102Z` with `state: ok` (EX-WIN-7045).

---

## 3. Provenance requirements (§1.1 source block, lines 374-382)

`source` object (schema): required = `file_id`, `format`, `parser`, `parser_version`; additionalProperties:false.

| Field | Req | Type/enum |
|---|---|---|
| `source.file_id` | yes | non-empty str — harvested-artifact identifier (DB row / manifest id) |
| `source.sha256` | no | 64-lowercase-hex str `^[a-f0-9]{64}$` — hash of the source artifact when computed |
| `source.format` | yes | enum `evtx\|json\|csv\|xml\|tsv\|text\|nmap_xml\|pcap\|sqlite\|yaml\|other` (schema; doc omits `xml`) — **level-1 classification** |
| `source.parser` / `source.parser_version` | yes | non-empty str — producing parser identity (replay provenance). Examples use `"evtx-canonical"` / `"1.0.0"` |
| `source.channel` | no | Windows event-log channel or equivalent stream name |
| `source.provider` | no | Event provider / application / sensor |
| `source.event_id` | no | int\|str — source-native event id (Sysmon/Security EID) |
| `source.record.type` | yes | enum `event_record\|line\|row\|byte_offset\|packet\|sheet\|message` — **level-2 classification carrier position** |
| `source.record.record_id\|line\|byte_offset\|packet_number\|row\|sheet` | no | int\|str — exact locator for replay/audit. For EVTX: `record.record_id` = `EventRecordID` |

EVTX envelope extraction (Security section convention, line 1090, VERIFIED): `Channel`→`source.channel`, `Provider@Name`→`source.provider`, `EventID`→`source.event_id`, `EventRecordID`→`source.record.record_id`, `Computer`→`host.hostname`. `raw` = rendered XML string (single-quoted attribute style in examples).

Cross-artifact: `sources[]` optional `{source_ref, fields[]}` (D2-004); field-level inference uses `{$state:"inferred"}`; Sentinel classification never presented as source claim.

---

## 4. Classification

### 4.1 Three axes (§4 Semantic Classification Spec, lines 2787-2926; D2-002)

| Level | Question | Where it lives | Set by |
|---|---|---|---|
| 1. File format | physical container | `source.format` enum | Parser (sniffing/magic/extension contract) |
| 2. Semantic data type | logical record shape | `source.record.type` + `source.channel`/`source.provider` (EVTX channel+EID; Zeek log name; EVE `event_type`; CSV header set) | Parser, from container metadata |
| 3. Security behaviour | security-relevant behaviour | `event.category` (26 values) + `event.type` + `event.action`/`outcome`, with `event.derived_by` marking authorship | §2 mapping tables; `derived_by: sentinel` when Sentinel authors it |

Stage-1 severity/level axes (D-007) stay separate — NOT conflated with these levels. A fourth, orthogonal axis: data-sensitivity `classification` (`public|internal|restricted`) — see 4.4.

Classification invariants (lines 2913-2926): L1/L2 descriptive (Sysmon EID 1 and Security 4688 both → process/process_create but different channels/field inventories — detectors must not assume source field names); L3 behavioural — one source record → exactly ONE canonical event with ONE `event.category`; blended sources (Suricata alert with embedded http) emit the dominant category; `event.derived_by` never mixes: if any of category/type/action/outcome/severity was Sentinel-authored, the whole classification is `sentinel`.

`event.derived_by` semantics (§1.1): `source` = taken from the source's own taxonomy (Sysmon event names, Security subcategory semantics); `sentinel` = authored by Sentinel (snapshot exports, third-party alert typing, LSM typing — D2-009/D2-010; also Sysmon EID 9→file, EID 16→config_check, EID 24→process, EID 255→third_party_alert).

`severity` is Sentinel-assigned in ALL cases (default `informational`; detectors override). Mapping-table overrides: System 7040/7043 → low, 7045 → medium, 104 → medium, Defender 1116 → high (or per Severity ID), 1117 → high, 5001 → high, 5007 → low, PowerShell 4104 → medium for obfuscated/encoded blocks, WMI 5858 → low, RCM 1149 → low, AppLocker audit → low / enforce-block → medium.

### 4.2 Classification backfill — `events.classification` (C-13)

- Stage-2 doc itself never mentions it ("not specified" in the md body).
- `canonical_event_v1.schema.json` top-level optional property `classification`, enum `public|internal|restricted`, description (verbatim): "Data-sensitivity axis (Stage-1 §6.4): public | internal | restricted. Third of the three non-collapsible classification axes. Set by the parser per source (e.g. Windows Security EVTX => restricted); drives export/redaction policy. Optional on the wire (older parsers may omit); the ingest pipeline backfills a per-source default and schema.sql enforces NOT NULL at rest."
- SENTINEL_IMPLEMENTATION_SPEC.md C-13 resolution (D8-02-fix): "`classification` column added to `events` (NOT NULL, CHECK public/internal/restricted) and optional enum field added to canonical-event/v1 envelope (DB NOT NULL enforced at rest; wire field backfilled by ingest)."
- **A full per-source default table is NOT specified anywhere in the repo** — only the schema's example "Windows Security EVTX => restricted". M1 decision needed: define the per-source default map (suggest: Windows Security + Defender + PowerShell Operational ⇒ `restricted`; other EVTX channels ⇒ `internal`; exports ⇒ `internal` or per policy) and document it. §5 examples omit the field entirely — validation still passes (optional on the wire); DB ingest must backfill before INSERT.

### 4.3 Outcome derivation & derived_by rules per channel (SEC conventions)

- Security titles: `(S)` → outcome `success`; `(F)` → `failure`; `(S,F)` → per `Status` where documented (4776: `0x0`=success VERIFIED; 4625/4771 → failure; 4768/4769 → `0x0` success else failure INFERRED); otherwise `unknown` (line 1094).
- Security `derived_by: sentinel` cases: 1102→fim, 4946/4947/4948→config_check, RCM 1149, LSM event.type naming per D2-009 (note: §2 LSM classification line 1985 says `source` for LSM 21/22/24/25 with `session_*` type names while D2-009/§5 use `rdp_*` + `sentinel` — §5 preamble flags "LSM labels diverge from SEC-B per Microsoft docs — see each cover comment"; follow §5 examples for LSM).

---

## 5. §5 Example canonical events — format, index, fixtures

- §5 spans lines 2930-12577. Preamble (lines 2948-2973): every example carries the full envelope (`schema_version`, `event`, `tenant_id`/`workspace_id`/`run_id` = `tenant-demo`/`ws-demo`/`run-2026-10-09-001`, `time`, `host`, `user`, `source`, `raw`, plus its category payload). Bare null only for `time.utc` where no usable timestamp. `unmapped` lists fields with no canonical home (a field may appear there even when a partial mapping exists, e.g. Sysmon RuleName as noise). `raw` strings shortened but real-shaped (EVTX single-quoted XML; local-harvest slimmed via `slim_evtx`). Secondary payloads only where tables map them; category payload always present.
- **Fence format** (per example, e.g. lines 3103-3203): heading `### EX-<ID> — Title`, then HTML comments `<!-- covers: ... -->` and `<!-- labels: VERIFIED|UNVERIFIED -->`, then a single ```` ```json ```` fenced block containing one complete, schema-valid canonical event. All 121 fenced json blocks in §5 were validated against the schema (C-SCHEMA: 0 errors, 2026-10-09).
- **121 examples total** (coverage matrix lines 12552-12571): Sysmon 30 (`EX-SYSMON-1..29`, `EX-SYSMON-255`; lines 3101-5514), Windows Security 32 (`EX-SEC-1102`, `4624..4948`; lines 5515-8052), Other Windows 37 (`EX-WIN-7034..RCM1149`, `EX-WIN-AL8003..8007`; lines 8053-10677), Zeek 6 (10678-11358), Suricata EVE 6 (11359-11869), Nmap 1 (11870), netstat 1 (11979), schtasks 1 (12042), sc query 1 (12124), sc qc 1 (12177, UNVERIFIED), reg export 1 (12244), Export-Csv 1 (12294), autorunsc 1 (12348), sigcheck 2 (12433). Example index table: lines 2977-3099 (id → title → category → derived_by → label). Coverage gap: `document` and `archive_member` categories have no examples (D2-018).
- Ids for M1 EVTX fixtures: EX-SYSMON-1 (line 3103), EX-SEC-1102 (5517), EX-SEC-4624 (5578), EX-SEC-4625 (5700), EX-SEC-4688 (6082), EX-SEC-4720 (6400), EX-WIN-7045 (8320), EX-WIN-PS4104 (8785).

### 5.1 EX-SYSMON-1 — Process creation (Sysmon EID 1), verbatim (lines 3103-3203)

Covers comment: `SEC-A Sysmon EID 1 process_create; RuleName/FileVersion/Description/Product/Company/HashType unmapped; ProcessID casing trap`. Label VERIFIED.

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

Notes on this fixture: `time.state: inferred` + `timezone_source: source_documented_utc` (Sysmon conversion); `process.hashes` split from KEY=value string (INFERRED; format UNVERIFIED A-PRIOR, tolerate alternatives, unknown keys → `hashes.other`); `LogonId` kept string; `process.name` derived basename (INFERRED); `ParentUser` (SID-form) → `process.parent.owner_sid` (parent has no owner_name); RuleName/FileVersion/Description/Product/Company → `unmapped[]`.

### 5.2 EX-SEC-4624 — Logon success (Security EID 4624), verbatim (lines 5578-5698)

Covers comment: `SEC-A Security EID 4624 logon_success; hex PID→int INFERRED; ElevatedToken %%1842→invalid state`. Label VERIFIED.

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

Notes on this fixture: envelope `user.*` = Subject*; `authentication.account_*` = Target* (New Logon, INFERRED assignment); hex PID → state-object int with `$raw`; LUIDs/status hex kept as strings; `KeyLength` 0 is a legitimate value (not null); `-` values with no canonical home stay as raw `-` in unmapped[] (they are unmapped, so no $state null needed); `LogonType` normalized to int.

### 5.3 EX-WIN-7045 — Service installed (System EID 7045), verbatim (lines 8320-8379)

Covers comment: `SEC-B System 7045 service_install; VERIFIED-LOCAL element names (no MS page)`. Label VERIFIED.

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

Notes: envelope user from `<Security UserID='S-1-5-18'/>`; ImagePath kept whole incl. surrounding quotes (do not pre-split image/args); 7045 has NO Microsoft event page — element names VERIFIED-LOCAL only.

### 5.4 EX-AUTORUNS-1 — unmapped-heavy snapshot example (lines 12350-12431)

Included because it shows the snapshot/unmapped/state-object pattern M1 will meet for non-EVTX exports (and `host: {}`, `user: {}`, `time.state: inferred`, abbreviated hashes as `$state: inferred` with `$raw`). See stage-2 lines 12350-12431 for full JSON; key traits: category `artifact`, type `autostart_inventory`, action `inventory`, derived_by `sentinel`, `source.format: csv`, no channel/record block, `unmapped[]` with dotted names (`autoruns.location`, `publisher`, `enabled`, `hidden`), payload split across `artifact` + `process`.

---

## 6. Mapping tables (§2)

### 6.0 Section-wide parser traps

Sysmon (lines 476-485): field names evidenced from config-schema (SwiftOnSecurity @1836897f + sysmon-modular @082cba57), MS docs summary-only. Compare field names CASE-INSENSITIVELY, emit schema.go spelling. Known casing conflicts: `ProcessID`(Swift)/`ProcessId`(schema.go), `DestinationIsIpV6`/`DestinationIsIpv6`, `SourceProcessGUID`/`SourceProcessGuid`. `RuleName` → unmapped[]. Sysmon `User` = `DOMAIN\user` | name | SID → `process.owner_name`; derive `owner_sid` only when SID-form (INFERRED). `severity` default informational.

Security (lines 1088-1096): envelope from System section (see §3 above). **Types kept as strings**: SIDs, LUID/hex (`0x55cd1d`), status codes (`0xC0000064`); hex PIDs (`0x4c8`) → int conversion INFERRED, keep `$raw`. Empty/`-` → `{"$state":"null","$raw":"-"}` (INFERRED). Two standing traps: (1) PID reuse — no process GUID, correlate via `user.logon_id` + time window; (2) hostname ambiguity — `SubjectDomainName`/`TargetDomainName`/`WorkstationName` are NOT the logging host (host is `System/Computer`).

SEC-B (lines 1778-1786): System-event `paramN` are message-template slots, not `<Data Name>` keys — bind positionally from rendered message and/or EventData when present. UNVERIFIED fields = optional, never required. `raw` = rendered XML string for EVTX.

### 6.1 Sysmon EID 1 — process_create (lines 487-519) — FULL

Classification: category `process` · type `process_create` · action `create` · outcome `success` · severity informational · derived_by `source`.

| Source field | Canonical path | Notes |
|---|---|---|
| UtcTime | time.original | derive time.utc + timezone_source source_documented_utc + time.state inferred (INFERRED) |
| RuleName | unmapped[] | matching rule name; no schema field |
| ProcessGuid | process.guid | stable per-process GUID — beats PID reuse |
| ProcessId | process.pid | Swift DATA spells `ProcessID` — case-insensitive match (trap) |
| Image | process.exe | full path; derive process.name = basename (INFERRED, optional) |
| FileVersion | unmapped[] | no process.file_version |
| Description | unmapped[] | |
| Product | unmapped[] | executable.product exists but no executable payload on category process — keep unmapped |
| Company | unmapped[] | as above |
| OriginalFileName | process.original_file_name | in schema.go, absent from Swift DATA (filter-only in Swift v74) |
| CommandLine | process.command_line | |
| CurrentDirectory | process.current_dir | |
| User | process.owner_name | DOMAIN\user or name; derive owner_sid only when SID-form (INFERRED) |
| LogonGuid | process.logon_guid | string GUID |
| LogonId | process.logon_id | LUID hex string — keep as string |
| TerminalSessionId | process.terminal_session_id | int |
| IntegrityLevel | process.integrity_level | raw token label — keep string |
| Hashes | process.hashes (md5/sha1/sha256/imphash/other) | split KEY=value pairs (INFERRED); KEY=value rendering UNVERIFIED A-PRIOR; unparsed remainder → hashes.other |
| HashType | unmapped[] | MS prose only; presence in modern EventData UNVERIFIED |
| ParentProcessGuid | process.parent.guid | |
| ParentProcessId | process.parent.pid | |
| ParentImage | process.parent.exe | |
| ParentCommandLine | process.parent.command_line | |
| ParentUser | process.parent.owner_sid | process.parent has no owner_name — store raw in owner_sid only when SID-form, else unmapped[] (INFERRED); OPEN_QUESTIONS: process.parent.owner_name |

Unmapped/traps: `FileVersion`, `Description`, `Product`, `Company`, `HashType`, `RuleName` → unmapped[]. Parent chain spoofable via PPID spoofing (detection concern, not mapping).

### 6.2 Sysmon EID 3 — network_connection (lines 540-566)

Classification: `network` · `network_connection` · `connect` · success · informational · `source`.

| Source | Canonical | Notes |
|---|---|---|
| UtcTime | time.original | derive (INFERRED) |
| RuleName | unmapped[] | |
| ProcessGuid | process.guid | also mirror to network.process.guid (INFERRED, optional) |
| ProcessId | process.pid | |
| Image | process.exe | |
| User | process.owner_name | |
| Protocol | network.protocol | tcp/udp string |
| Initiated | network.direction | DERIVED: true→`outbound`, false→`inbound` (INFERRED; $note the boolean source) |
| SourceIsIpv6 | unmapped[] | |
| SourceIp | network.src_ip | |
| SourceHostname | unmapped[] | no canonical field (host.* = logging host) |
| SourcePort | network.src_port | int |
| SourcePortName | unmapped[] | |
| DestinationIsIpv6 | unmapped[] | casing trap `DestinationIsIpV6`/`DestinationIsIpv6` |
| DestinationIp | network.dst_ip | |
| DestinationHostname | unmapped[] | |
| DestinationPort | network.dst_port | int |
| DestinationPortName | unmapped[] | |

### 6.3 Sysmon EID 7 — image_load (lines 615-639)

Classification: `image_load` · `image_load` · `load` · success · informational · `source`.

| Source | Canonical | Notes |
|---|---|---|
| UtcTime | time.original | derive |
| RuleName | unmapped[] | |
| ProcessGuid | image_load.process.guid | process_ref |
| ProcessId | image_load.process.pid | |
| Image | image_load.process.exe | loading process |
| User | image_load.process.owner_name | schema.go only (Sysmon 14+) |
| ImageLoaded | image_load.image | loaded module path |
| FileVersion / Description / Product / Company | unmapped[] | (or optional executable payload, INFERRED) |
| OriginalFileName | unmapped[] | image_load.process is process_ref without original_file_name |
| Hashes | image_load.hashes (md5/sha1/sha256/imphash/other) | split KEY=value (INFERRED) |
| Signed | image_load.signature.signed | bool |
| Signature | image_load.signature.signer | |
| SignatureStatus | image_load.signature.status | |

High-volume — mapping cost note for collectors.

### 6.4 Sysmon EID 8 — create_remote_thread (lines 641-663)

Classification: `thread_access` · `create_remote_thread` · `create` · success · informational · `source`.

| Source | Canonical | Notes |
|---|---|---|
| UtcTime | time.original | derive |
| RuleName | unmapped[] | |
| SourceProcessGuid | thread_access.source_process.guid | |
| SourceProcessId | thread_access.source_process.pid | |
| SourceImage | thread_access.source_process.exe | |
| SourceUser | thread_access.source_process.owner_name | schema.go only; often empty → `$state:"null"` guidance (INFERRED) |
| TargetProcessGuid | thread_access.target_process.guid | |
| TargetProcessId | thread_access.target_process.pid | |
| TargetImage | thread_access.target_process.exe | |
| TargetUser | thread_access.target_process.owner_name | often empty |
| NewThreadId | unmapped[] | no thread-id field in schema |
| StartAddress | unmapped[] | hex start address |
| StartModule | unmapped[] | MS: inferred, may be empty |
| StartFunction | unmapped[] | MS: inferred, may be empty |

Empty SourceUser/TargetUser/StartModule/StartFunction are documented behavior → `$state:"null"` when empty (INFERRED).

### 6.5 Sysmon EID 11 — file_create (lines 707-723)

Classification: `file` · `file_create` · `create` · success · informational · `source`.

| Source | Canonical | Notes |
|---|---|---|
| UtcTime | time.original | derive |
| RuleName | unmapped[] | |
| ProcessGuid | process.guid | creating process (secondary process payload) |
| ProcessId | process.pid | |
| Image | process.exe | |
| User | process.owner_name | |
| TargetFilename | file.path | full path; derive file.name/file.directory (INFERRED, optional) |
| CreationUtcTime | file.created | |

file.hashes/file.size absent in EID 11 — detectors must not assume them (absent ≠ null).

### 6.6 Sysmon EID 22 — dns_query (lines 920-938)

Classification: `dns` · `dns_query` · `query` · outcome success/failure (from QueryStatus) · informational · `source`.

| Source | Canonical | Notes |
|---|---|---|
| RuleName | unmapped[] | |
| UtcTime | time.original | derive |
| ProcessGuid | dns.process.guid | process_ref |
| ProcessId | dns.process.pid | |
| QueryName | dns.query_name | keep case as logged (do not lowercase in parser) |
| QueryType | dns.query_type | Swift DATA only — absent from schema.go |
| QueryStatus | dns.query_status | numeric status as string; outcome `success` when 0 else `failure` (INFERRED) |
| QueryResults | dns.answers | array — split raw string (INFERRED); separator UNVERIFIED A-PRIOR; no answers → empty array or absent per pipeline policy |
| Image | dns.process.exe | |
| User | dns.process.owner_name | |

No dns.server/response_code in EID 22 — do NOT emit `$state:"unknown"` for fields the source never had.

### 6.7 Security EID 1102 — audit_log_cleared (lines 1098-1110) — FULL

MS title: "1102(S): The audit log was cleared." Classification: `fim` · `audit_log_cleared` · `clear` · success · informational · derived_by **`sentinel`**.

| Source | Canonical | Notes |
|---|---|---|
| SubjectUserSid | user.sid | account that cleared the log — UserData element name (page has no EventData; names from `<LogFileCleared>`) |
| SubjectUserName | user.name | |
| SubjectDomainName | user.domain | domain/computer of account — not host.hostname |
| SubjectLogonId | user.logon_id | LUID hex — keep string |

Traps: no EventData (documented exception); optional `fim.operation = "audit_log_cleared"`? — spec says fim.operation = audit_log_cleared and optional `fim.path` = "Security" (INFERRED constant). derived_by sentinel because "audit log cleared" has no source category; alternatives rejected for detector simplicity. Log-clearing is a meta event — cleared content gone (timeline gap).

### 6.8 Security EID 4624 — logon_success (lines 1112-1147) — FULL

Classification: `authentication` · `logon_success` · `logon` · success · informational · `source`. See fixture §5.2 for a worked event.

| Source | Canonical | Notes |
|---|---|---|
| SubjectUserSid / SubjectUserName / SubjectDomainName / SubjectLogonId | user.sid / user.name / user.domain / user.logon_id | initiator of the logon; LUID hex keep string; domain≠hostname |
| TargetUserSid / TargetUserName / TargetDomainName | authentication.account_sid / account_name / account_domain | "New Logon" account (INFERRED assignment from section order) |
| TargetLogonId | authentication.logon_id | LUID of session created (INFERRED semantics) — keep string |
| LogonType | authentication.logon_type | integer (2,3,10,…) `int_or_state`; `-`/empty → `$state:"null"` (INFERRED) |
| LogonProcessName | unmapped[] | no authentication.logon_process |
| AuthenticationPackageName | authentication.auth_package | Kerberos/NTLM/Negotiate raw string |
| WorkstationName | authentication.workstation | not host.hostname |
| LogonGuid | authentication.logon_guid | string GUID (varies by logon type per MS) |
| TransmittedServices | unmapped[] | |
| LmPackageName | unmapped[] | |
| KeyLength | authentication.key_length | int; `0` legitimate (not null) |
| ProcessId | authentication.process_pid | hex `0x…` → int INFERRED, keep `$raw`; PID reuse trap |
| ProcessName | authentication.process_name | full path of logon process |
| IpAddress | authentication.source_ip | `-` (local logon) → `$state:"null"`, `$raw:"-"` (INFERRED) |
| IpPort | unmapped[] | no auth source_port |
| ImpersonationLevel | unmapped[] | `%%1833` value set UNVERIFIED |
| RestrictedAdminMode | unmapped[] | typically `-` |
| TargetOutboundUserName / TargetOutboundDomainName | unmapped[] | |
| VirtualAccount | unmapped[] | example XML renders `%%1843` |
| TargetLinkedLogonId | unmapped[] | |
| ElevatedToken | authentication.elev_token | `%%1842` (VERIFIED) / Yes-No (VERIFIED) renderings; true/false & %16384 UNVERIFIED. Yes/true→true, No/false→false (INFERRED); `%%nnnn` → `{"$state":"invalid","$raw":"%%1842"}` (INFERRED) |

Traps: PID reuse; `-`/empty → `$state:"null"`; LogonType `"4"` vs `4` — normalize to int (INFERRED).

### 6.9 Security EID 4625 — logon_failure (lines 1149-1179) — FULL

Classification: `authentication` · `logon_failure` · `logon` · **failure** · informational · `source`.

| Source | Canonical | Notes |
|---|---|---|
| SubjectUserSid / SubjectUserName / SubjectDomainName / SubjectLogonId | user.sid / name / domain / logon_id | |
| TargetUserSid / TargetUserName / TargetDomainName | authentication.account_sid / account_name / account_domain | attempted account (INFERRED); name often the *guessed* name |
| TargetLogonId | authentication.logon_id | usually null on failure → `$state:"null"` (INFERRED) |
| Status | authentication.status | hex status string — keep as string |
| FailureReason | authentication.failure_reason | raw (may be `%%nnnn` — expansion UNVERIFIED) |
| SubStatus | authentication.sub_status | hex string (e.g. `0xC0000064`) — keep string |
| LogonType | authentication.logon_type | int (INFERRED) |
| LogonProcessName | unmapped[] | |
| AuthenticationPackageName | authentication.auth_package | |
| WorkstationName | authentication.workstation | |
| TransmittedServices / LmPackageName | unmapped[] | |
| KeyLength | authentication.key_length | int; 0 common on failures |
| ProcessId | authentication.process_pid | hex→int INFERRED; PID reuse trap |
| ProcessName | authentication.process_name | |
| IpAddress | authentication.source_ip | `-` → `$state:"null"` |
| IpPort | unmapped[] | |

Traps: outcome failure is source-derived from `(F)`; Status/SubStatus (bad-user vs bad-password) must both survive as raw strings.

### 6.10 Security EID 4688 — process_create (lines 1249-1272) — FULL

Classification: `process` · `process_create` · `create` · success · informational · `source`.

| Source | Canonical | Notes |
|---|---|---|
| SubjectUserSid / SubjectUserName / SubjectDomainName / SubjectLogonId | user.sid / name / domain / logon_id | |
| NewProcessId | process.pid | hex→int INFERRED, keep `$raw` |
| NewProcessName | process.exe | |
| TokenElevationType | process.integrity_level | raw string (%%1968/1969/1970 UNVERIFIED) |
| ProcessId | process.parent.pid | **parent/creator PID** (MS description) — hex→int INFERRED, keep `$raw`; PID reuse trap |
| CommandLine | process.command_line | may be self-closing/empty in documented example |
| TargetUserSid | process.owner_sid | |
| TargetUserName | process.owner_name | |
| TargetDomainName | unmapped[] | no process.owner_domain |
| TargetLogonId | unmapped[] | process.logon_id is the *logon* LUID, not token LUID — leave unmapped (INFERRED conservative; OPEN_QUESTIONS) |
| ParentProcessName | process.parent.exe | |
| MandatoryLabel | process.integrity_level | SID-form integrity label (e.g. S-1-16-12288) — OVERRIDES TokenElevationType if both present; keep string (INFERRED precedence) |

Traps: two PIDs (NewProcessId child / ProcessId parent); NO ProcessGuid (unlike Sysmon) — PID-reuse; domains ≠ hostname; CommandLine empty vs absent must not be confused. Security 4688 also has no `NewProcessId`-time correlation key — correlate to 4689 via pid+time window.

### 6.11 Security EID 4720 — account_created (lines 1331-1365) — FULL

Classification: `account` · `account_created` · `create` · success · informational · `source`.

| Source | Canonical | Notes |
|---|---|---|
| TargetUserName | account.name | new account |
| TargetDomainName | account.domain | not host.hostname |
| TargetSid | account.sid | keep string |
| SubjectUserSid / SubjectUserName / SubjectDomainName / SubjectLogonId | user.sid / name / domain / logon_id | creating account |
| PrivilegeList | unmapped[] | |
| SamAccountName | account.sam_account_name | |
| DisplayName | account.display_name | |
| UserPrincipalName | account.upn | |
| HomeDirectory / HomePath / ScriptPath / ProfilePath / UserWorkstations | unmapped[] | no schema fields |
| PasswordLastSet / AccountExpires | unmapped[] | timestamps — no account.password_last_set etc. |
| PrimaryGroupId / AllowedToDelegateTo | unmapped[] | |
| OldUacValue / NewUacValue / UserAccountControl | unmapped[] | hex UAC bits — no UAC field |
| UserParameters | unmapped[] | |
| SidHistory | account.sid_history | |
| LogonHours | unmapped[] | |

Traps: `Target*` here is the **new account** — maps to `account.*`, NOT `authentication.*`; UAC hex kept verbatim in unmapped[]; subject may be delegated admin.

### 6.12 System 7045 — service_install (lines 1788-1816, shared table with 7034/7036/7040/7043) — FULL

Classification (7045): `service` · `service_install` · `install` · success · **severity medium** · `source`. (Neighbors: 7034 service_crash/terminate/informational; 7036 service_state_change/state_change/informational; 7040 service_start_type_change/change/low; 7043 service_config_change/change/low.)

| Event | Source | Canonical | Notes |
|---|---|---|---|
| 7045 | ServiceName | service.name | e.g. `ChatGPT` |
| 7045 | ImagePath | service.image_path | full quoted path — keep whole string |
| 7045 | ServiceType | service.service_type | e.g. `user mode service` |
| 7045 | StartType | service.start_type | e.g. `auto start` |
| 7045 | AccountName | service.account_name | e.g. `LocalSystem` |

Neighbors worth implementing with the same parser: 7034 `param1`→service.name, `param2`→unmapped[] (`service.crash_count` — occurrence COUNT, not exit code); 7036 unnamed `<Data>`[0]→service.name, [1]→service.state, `Binary`→unmapped[]; 7040 `param1`→service.name, `param2`→old start_type (unmapped/from-state), `param3`→service.start_type (new), `param4`→unmapped[] (caller); 7043 `param1`→service.name, `Binary` (UTF-16LE hex)→service.image_path. 7043/7045 have NO Microsoft page — element names VERIFIED-LOCAL (B-LOC-HARVEST) only. Positional paramN binding is the parser strategy (INFERRED).

### 6.13 PowerShell Operational 4104 — script_block_logging (lines 1862-1884, shared table with 4103/4105/4106) — FULL

Classification (4104): `powershell` · `script_block_logging` · `log` · success · informational (**raise to `medium` for obfuscated/encoded blocks**) · `source`. (4103 module_logging/log; 4105/4106 pipeline_execution/start|stop. §4 worked-example 8 names L3 type `script_block` + action `execute` — the §2 table and §5 index use `script_block_logging`/`log`; the mapping table + EX-WIN-PS4104 fixture are authoritative.)

| Event | Source | Canonical | Notes |
|---|---|---|---|
| 4104 | MessageNumber | powershell.message_number | int; chunk index |
| 4104 | MessageTotal | powershell.message_total | int — reassemble ScriptBlockText across MessageNumber≤MessageTotal (INFERRED) |
| 4104 | ScriptBlockText | powershell.script_block_text | the script block source |
| 4104 | ScriptBlockId | powershell.script_block_id | GUID; join key across 4104 chunks + 4105/4106 |
| 4104 | Path | powershell.script_path | source file path (e.g. npm.ps1); empty string = interactive block |
| 4103 | ContextInfo | powershell.context_info | multi-line context blob |
| 4103 | UserData | unmapped[] | usually empty (INFERRED) |
| 4103 | Payload | powershell.payload | CommandInvocation/ParameterBinding text |
| 4105/4106 | ScriptBlockId / RunspaceId | powershell.script_block_id / runspace_id | VERIFIED-by-manifest only (no local samples) |

Traps: reassemble 4104 chunks by ScriptBlockId before storing script_block_text (INFERRED).

### 6.14 Other events — ids + classification lines only (skimmed)

Sysmon (derived_by `source`, severity informational, action per line; line numbers in parens):
- EID 2 file/file_creation_time_change/change (523); EID 4 service/sysmon_service_state_change/start|stop-from-State (570); EID 5 process/process_terminate/terminate (584); EID 6 driver/driver_load/load (600) — driver payload lacks hashes/signature → optional secondary `executable` payload or unmapped[]; EID 9 file/raw_device_read/read **sentinel** (667); EID 10 thread_access/process_access/access (684) — GrantedAccess hex string→thread_access.access_mask, CallTrace→thread_access.call_trace, GUID casing trap; EID 12 registry/registry_object_create_delete (refine to registry_key_create/key_delete/value_delete from EventType — INFERRED)/create|delete (727); EID 13 registry/registry_value_set/set (747) — registry.value_type must NOT be inferred from data shape; EID 14 registry/registry_rename/rename (767) — NewName→unmapped[]; EID 15 file/file_stream_create/create (787) — `Hash`→file.hashes.other, `Contents`→unmapped[], keep `:stream` suffix in file.path; EID 16 config_check/sysmon_config_change/change **sentinel** (807) — Configuration→config_check.observed, ConfigurationFileHash→unmapped[]; EID 17 pipe/pipe_create/create (820); EID 18 pipe/pipe_connect/connect (838); EID 19 wmi/wmi_filter_create/create (856) — no process context exists, do not fabricate; EID 20 wmi/wmi_consumer_create/create (878) — Name/Type/Destination→unmapped[]; EID 21 wmi/wmi_consumer_filter_bind/bind (900); EID 23 file/file_delete/delete (942) — ArchiveDirectory archived; EID 24 process/clipboard_change/change **sentinel** (962); EID 25 process/process_tampering/modify (983); EID 26 file/file_delete/delete (1001); EID 27 file/file_block_executable/block (1020); EID 28 file/file_block_shredding/block (1038); EID 29 file/file_executable_detected/create (1057); EID 255 third_party_alert/sysmon_error/error/unknown **sentinel** UNVERIFIED (1075) — envelope-only, never invent fields (D2-017).

Security (all severity informational):
- 4634 authentication/logoff/logoff/source (1184) — mirror Target*→envelope user (INFERRED, no Subject fields); 4647 logoff_initiated/logoff/source (1199); 4648 explicit_credential_logon/logon/source (1213) — TargetUserName→authentication.target_name, ProcessId→authentication.caller_process_id, TargetInfo→unmapped[] keep raw; 4672 special_privileges_assigned/assign/source (1237) — PrivilegeList→unmapped[] verbatim; 4689 process/process_terminate/terminate/source (1277) — Status→unmapped[] (no process.exit_code); 4697 service/service_install/install/source (1294) — ServiceFileName→service.image_path keep whole string; 4698 scheduled_task/scheduled_task_create/create/source (1313) — TaskName keep path-form, TaskContent→scheduled_task.task_xml whole string, FQDN is client not host; 4722 account/account_enabled/enable/source (1370); 4724 account/password_reset/reset/source (1387); 4726 account/account_delete/delete/source (1404); 4728/4732/4756 group_membership/member_added_to_{global,local,universal}_group/add/source (1422/1442/1516) — 4728/4756 field lists = 4732 equivalence INFERRED (A-SEC-GRPMGMT); 4738 account/account_changed/modify/source (1462); 4740 account/account_locked_out/lock/source (1499); 4767 account/account_unlocked/unlock/source (1536); 4768 authentication/kerberos_tgt_requested/request/ (1553) outcome per Status 0x0 (INFERRED); 4769 kerberos_service_ticket_requested/request/ (1587); 4771 kerberos_preauth_failed/request/failure (1618); 4776 credential_validation/validate/ (1639) Status 0x0=success VERIFIED; 5140 network/network_share_access/access (1653); 5145 network/network_share_access_check/check (1674); 5156 network/wfp_connection_permitted/permit (1697) — Direction %%-code → `$state:"unknown"` until corroborated (D2-015/Q2-007); 5158 network/wfp_bind_permitted/permit (1720); 4946/4947/4948 config_check/firewall_rule_{added,modified,deleted}/add|modify|delete **sentinel** (1738/1751/1764).

SEC-B: System 104 config_check/log_clear/clear/medium/sentinel (1820) — param3→source.channel VERIFIED, Subject* UNVERIFIED; classic PS 400/403 powershell/engine_state_change and 600 provider_state_change|command_start (1836-1837) — 3 unnamed `<Data>` positional + Key=Value detail blob (D2-020), SequenceNumber→unmapped[]; WMI 5857/5860 wmi/wmi_operation/connect, 5858 wmi_client_failure/connect/failure/low (1888-1889) — casing traps `ProcessID`(5857)/`ClientProcessId`(5858)/`Processid`(5860) → compare case-insensitively, D2-011 says 5860 lowercase-d match case-sensitively in that pipeline; PIDs → unmapped[] (`wmi.process_id`) because no process payload; Defender 1116 third_party_alert/malware_detected/detect/high/sentinel (1919), 1117 file/malware_action/quarantine|remove|allow/high/sentinel (1920), 5001 config_check/realtime_protection_disabled/disable/high/sentinel (1921), 5007 config_check/settings_change/change/low/source (1922) — space-bearing element names (`Threat Name`, `Product Name`); TaskScheduler 106/140/141 scheduled_task task_register/update/delete/low/source, 200/201 task_action_start/complete (1962-1963) UNVERIFIED element names (D2-023); RCM 1149 authentication/rdp_auth/connect/low/sentinel UNVERIFIED (1984); LSM 21/22/24/25 authentication session_logon/logoff/disconnect/reconnect (1985) per §2 vs `rdp_*` + sentinel per D2-009/§5 — follow §5; LSM 39 disconnect-by-session. AppLocker 8003/8004/8006/8007 config_check/applocker_audit|applocker_block/allow|block/sentinel UNVERIFIED (2003); §5 preamble: 8003/8004 → `applocker_audit` (not SEC-B `applocker_block`).

---

## 7. §3 Sigma field-mapping pipelines (lines 2168-2783) — NOT needed for M1

Purpose (normative): Sentinel detectors run over canonical events, not raw Sigma-shaped records. SigmaHQ rules reference source-native field names (`Image`, `CommandLine`, `ParentImage`, `TargetObject`, …). The pipelines are **configuration data, not code**: per Sigma `logsource`, they declare the canonical `event.category`/`event.type` selector and the field-name translation a rule-translation layer must apply before a Sigma condition can be evaluated against canonical events. Derived from SigmaHQ field inventories @ corpus pin `8a4813404e` (A6-SIGMAHQ-INV), cross-checked against §2. YAML shape mirrors pySigma pipeline structure; pySigma is NOT a runtime dependency (D2-014; Stage-1 D-004/D-008: Sigma compatibility is a content-level goal, detectors consume canonical events only).

Pipeline block shape: `id`, `title`, `logsource{product, category, service}`, `selector{event.category, event.type[]}`, `field_mapping{SigmaField: canonical.dotted.path}` (absent target = match against `raw`/`unmapped` via documented fallback or drop-and-flag), `value_transform[{source_shape, target, rule_action}]` (e.g. `split_kv_and_compare_scalar` for Hashes, `map_bool_to_direction_enum` for Initiated, `map_to_enum` for registry EventType, `optional_derived_split` for TargetObject, `parse_documented_variants` for ElevatedToken, `compare_numeric` for LogonType).

25 pipelines: `sysmon_process_creation`, `sysmon_registry`, `sysmon_network`, `sysmon_image_load`, `sysmon_file_create`, `sysmon_pipe`, `sysmon_wmi`, `sysmon_ps_script`, `sysmon_dns`, `security_auth`, `security_process`, `security_share`, `security_wfp`, `security_account`, `security_service_task`, `powershell_operational`, `powershell_classic`, `zeek_conn`, `zeek_dns`, `zeek_http`, `zeek_ssl`, `suricata_eve`, `defender_operational`, `wmi_activity`, `rdp_lsm`.

**M1 verdict:** not needed. They sit in the detector/rule-translation path (Stage-5 rule engine), downstream of M1's parser → canonical row persistence. M1 only needs §2 mapping tables (which the pipelines mirror). Revisit at M2+.

---

## 8. §4 Semantic Classification Spec — quick reference (lines 2787-2926)

- L1 file format → `source.format` (enum, incl. `xml` per schema).
- L2 semantic data type → `source.record.type` + `source.channel`/`source.provider` (EVTX channel+EID; Zeek log name; EVE `event_type`; CSV header set). Parser sets L1/L2 mechanically from container metadata.
- L3 security behaviour → `event.category` (26) + `event.type` (snake_case) + `event.action`/`event.outcome`, with `event.derived_by` marking source-vs-Sentinel authorship. §2 mapping tables set L3.
- Worked examples (13, lines 2802-2911): Sysmon EID 1→L1 evtx/L2 event_record/L3 process+process_create derived source (EX-SYSMON-1); Sysmon 13→registry/registry_set; Sysmon 3→network/network_connection, direction=outbound INFERRED value-level but classification `source`; Security 4624→authentication/logon_success; 4625→logon_failure; 5156→network/packet_filtered with direction `$state: unknown` until %%-code table corroborated; Defender 1116→third_party_alert/malware_detected derived **sentinel**; PowerShell 4104→powershell; Zeek conn→L1 tsv/L2 row (bind by #fields header, never positional)/L3 network/connection derived sentinel; Suricata alert→L1 json/L2 row/L3 third_party_alert sentinel; netstat→L1 text/L2 line/L3 network/connection_snapshot sentinel, `time.state: unknown`; reg export→registry/registry_set sentinel; autoruns CSV→config_check/autostart_entry sentinel (header-driven binding).
- Invariants: one record → one event, one category; `derived_by` all-or-nothing per classification decision; Stage-1 severity/level axes separate.

---

## 9. DECISIONS / OPEN_QUESTIONS / NOT_VERIFIED (compact)

### DECISIONS (lines 12581-12856) — D2-001..D2-024, all status accepted

- D2-001: bare JSON null forbidden except time.utc (state unknown/invalid); `{$state,...}` carries null/unknown/invalid/conflicting/inferred.
- D2-002: three-level classification L1 source.format / L2 source.record.type+channel / L3 event.category+type+action/outcome; Stage-1 D-007 axes stay separate.
- D2-003: timestamp policy — never guess a timezone; timezone_source enum; Sysmon/Zeek = source_documented_utc; EVTX TimeCreated = source_explicit; netstat/schtasks = none + utc null + state unknown; run-config override → state inferred.
- D2-004: provenance — event.derived_by + optional $source_ref/sources[]; field-level inference = {$state: inferred}; Sentinel classifications never presented as source claims.
- D2-005: process identity — (host, process.guid) primary; fallback (host, pid, exe, start_time) inferred; PID-only linkage carries documented PID-reuse failure mode.
- D2-006: Sysmon field names from config-schema (Swift+sysmon-modular); MS docs summary-level; `sysmon -s` not runnable here (NOT_VERIFIED).
- D2-007: Security pages = archived previous-versions Learn pages; names from Event XML `<Data Name>`; 4728/4756 = 4732 equivalence INFERRED.
- D2-008: Defender 1116/1117 → third_party_alert with full 42-element capture; 5001/5007 → config_check; derived_by sentinel.
- D2-009: LSM 21-25/39 → authentication with Sentinel-authored `rdp_*` event.type names; SessionID→logon_id INFERRED; RCM 1149 element names UNVERIFIED.
- D2-010: snapshot exports (netstat/schtasks/sc/reg/autoruns/sigcheck) → derived_by sentinel, `*_snapshot`/config-oriented types, time.state unknown unless file mtime (then inferred); CSV bind by header at runtime.
- D2-011: WMI 5860 `<Processid>` lowercase-d casing preserved; parsers match element names case-sensitively per this decision (vs case-insensitive compare guidance elsewhere — be tolerant on input, exact on known traps).
- D2-012: lossless raw + unmapped[]; typed objects additionalProperties:false; $-keys reserved for state machinery.
- D2-013: host/user always present, may be {}.
- D2-014: Sigma pipelines = config data, not code; no pySigma runtime dependency; corpus pin 8a4813404e.
- D2-015: Security 5156 %%-code direction mapping UNVERIFIED — parsers emit `$state: unknown` for network.direction (Q2-007).
- D2-016: LSM SessionID → authentication.logon_id is INFERRED; no dedicated session field in v1 (Q2-009).
- D2-017: Sysmon EID 255 has no verified EventData names — envelope-only example; never invent fields.
- D2-018: `document`/`archive_member` categories reserved; no harvested source maps to them (coverage gap documented).
- D2-019: Zeek column binding header-driven (#fields), never positional; ts epoch float → utc, precision microsecond, source_documented_utc.
- D2-020: classic PS 400/403/600 = 3 unnamed `<Data>` (state, prev state, Key=Value detail blob); empty CommandLine in blob → `$state: "null"`; SequenceNumber → unmapped[].
- D2-021: System unnamed Data (param1/param2) + Binary UTF-16 carrier documented; prefer named/decoded carrier; record carrier used in unmapped[] provenance if both disagree.
- D2-022: AppLocker element names UNVERIFIED — optional fields, never required.
- D2-023: TaskScheduler 106/140/141/200/201 element names UNVERIFIED — minimal payload, message-text key-values INFERRED.
- D2-024: schema_version const `canonical-event/v1` is the version gate; breaking → v2 file; detectors pin the string.

### OPEN_QUESTIONS (lines 12860-13011) — Q2-001..Q2-016

- Q2-001: Sysmon Hashes KEY=value rendering not source-confirmed — tolerate separators/unknown keys → hashes.other (blocking hash splitting).
- Q2-002: ElevatedToken true/false vs %%nnnn — accept all; unrecognized → `$state: unknown`.
- Q2-003: Sysmon registry/pipe EventType literal strings UNVERIFIED — enum mapping INFERRED, tolerant.
- Q2-004: Sysmon EID 255 EventData names unknown — do not invent.
- Q2-005: Security 4688 no ProcessGuid — PID-reuse risk; don't silently merge on PID (D2-005).
- Q2-006: Nmap service/OS fields no schema home — unmapped[].
- Q2-007: 5156 Direction %%-code numeric mapping UNVERIFIED — emit unknown (blocking WFP direction detectors).
- Q2-008: RCM 1149 element names UNVERIFIED.
- Q2-009: LSM SessionID→logon_id INFERRED (blocking LSM+Security session correlation).
- Q2-010: autoruns/sigcheck/schtasks CSV headers UNVERIFIED — bind by header row at runtime.
- Q2-011: sc qc field list UNVERIFIED (page 404).
- Q2-012: WMI 5859/5861 + TaskScheduler element names UNVERIFIED.
- Q2-013: classic PS SequenceNumber no schema home — unmapped[].
- Q2-014: Sysmon EID 15/16/19/20/21/23/24/26/27/28/29 sub-fields partially unmapped — all in unmapped[].
- Q2-015: Zeek notice/files extra fields no home; files.mime_type → file.type (INFERRED).
- Q2-016: Sysmon EID 9/16 category choices INFERRED sentinel.

### NOT_VERIFIED (lines 13015-13045) — 23 claims; none are required keys; parsers treat as optional/tolerant

1. Sysmon Hashes KEY=value rendering. 2. ElevatedToken true/false and %16384 renderings. 3. Sysmon registry EventType literals (createKey/setValue/…). 4. Sysmon pipe 17/18 operation literals. 5. Sysmon EID 255 EventData names. 6. ProcessTampering Type value set (EID 25). 7. Clipboard Hashes semantics (EID 24). 8. Security 4728/4756 field lists (via 4732 equivalence). 9. 5156 Direction %%-code → inbound/outbound. 10. System 104 elements beyond param3. 11. TaskScheduler 106/140/141/200/201 elements. 12. WMI 5859/5861 elements. 13. AppLocker 8003/8004/8006/8007 elements. 14. RDP RCM 1149 elements. 15. Classic PowerShell 800 element names. 16. sc qc field list. 17. Autoruns CSV headers. 18. Sigcheck CSV headers. 19. schtasks /fo CSV header row. 20. Sysmon User field SID-vs-DOMAIN\user ambiguity. 21. Sysmon EID 9/16/19/20/21/23/24/26/27/28/29 category assignments (sentinel-authored). 22. LSM event.type names rdp_* (sentinel-authored). 23. Sysmon ParentUser may carry SID.

---

## 10. M1 acceptance checklist distilled from the above

1. EVTX → one canonical-event/v1 row per record; validate every emitted JSON against `canonical_event_v1.schema.json` (Draft 2020-12).
2. Required keys always present: schema_version, event{category,type,action,outcome,severity,derived_by}, tenant_id, workspace_id, run_id, time{utc,precision,state}, host (may {}), user (may {}), source{file_id,format,parser,parser_version,record.type}, raw.
3. No bare null anywhere except time.utc under state unknown/invalid; empty-vs-absent via `$state:"null"` (+`$raw` for `-`); unparsable → `$state:"invalid"`+`$raw`; Sentinel-derived values → `$state:"inferred"`+`$note`; hex PID→int keeps `$raw`.
4. Times: Sysmon UtcTime → original + derived utc (Z, source_documented_utc, state inferred); EVTX TimeCreated SystemTime → utc directly (source_explicit, state ok, precision microsecond); missing → utc null, timezone_source none, state unknown.
5. Provenance on every row: source.file_id, sha256 (when computed, 64-hex), parser/parser_version, record.type=`event_record` + record.record_id, channel/provider/event_id; raw = verbatim rendered XML string.
6. Lossless: every source field either mapped to a canonical path or present in unmapped[] as {name, value}; raw never lossy. Respect casing traps (case-insensitive match, exact known-spelling emit).
7. Classification per §2 tables (see §6 classification lines); severity default informational with documented overrides; derived_by source/sentinel per table; one event per record, exactly one category payload.
8. Backfill optional wire `classification` (public|internal|restricted) per per-source default (schema suggests Windows Security EVTX ⇒ restricted; full map not specified — decide + document) before NOT NULL DB insert; persist full envelope in `events.document`, generate `event_uid` uuidv7 server-side.
9. Use §5 fenced examples (121, index lines 2977-3099) as golden fixtures — at minimum EX-SYSMON-1, EX-SEC-4624, EX-SEC-4625, EX-WIN-7045, EX-WIN-PS4104, EX-SEC-1102, EX-SEC-4720.
10. Sigma pipelines (§3) are out of scope for M1 (detector-path config, D2-014).
