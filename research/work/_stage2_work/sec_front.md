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

<!--VERIFICATION_LOG-->

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
