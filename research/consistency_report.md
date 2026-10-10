# Stage 7 — Consistency Report

Sentinel (Light HIDS) · generated 2026-10-10 from Stages 1–6 artifacts · work artifacts under `_stage7_work/`

This report cross-checks every named contract, decision, invariant, and number across the six stage documents plus the delivered schema/API files (`schema.sql`, `openapi.yaml`, `canonical_event_v1.schema.json`, `rule_schema.json`, `verification-log.yaml`, `VERIFICATION_LOG_2026-10-09.yaml`). It does **not** resolve conflicts silently; every conflict is listed with its competing versions and left for human input.

**Source artifacts audited (all present, no stage omitted):**

| File | Role | Lines |
|---|---|---|
| `stage-1-landscape-and-rule-engine-decision.md` | Engine decision, classification axes, MVP scope | 658 |
| `stage-2-canonical-event-and-mappings.md` | canonical-event/v1 + 121 source mappings | 13,049 |
| `stage-3-ingestion-and-artifact-triage.md` | Upload gate, parsers, triage, artifact graph | 3,892 |
| `stage-4-threat-model-and-windows-sandbox.md` | Threat model, sandbox tiers, D4 decisions | 308 |
| `stage-5-dynamic-rule-engine.md` | Rule contract, SQL/native paths, 25 examples | 1,743 |
| `stage-6-platform-storage-jobs-api-testing-release.md` | DDL narrative, jobs, API surface, tests, release | 475 |
| `schema.sql` | Stage-6 DDL (21 tables) | — |
| `openapi.yaml` | OpenAPI 3.1.0 (23 paths, 18 schemas) | — |
| `canonical_event_v1.schema.json` | Normative canonical-event/v1 JSON Schema | — |
| `rule_schema.json` | Normative sentinel-rule/v1 JSON Schema | — |
| `verification-log.yaml`, `VERIFICATION_LOG_2026-10-09.yaml` | Evidence registers | — |

**No `*_decisions.yaml` files exist in the workspace** (confirmed by recursive search: `decision_yaml_files=[]`). DECISIONS / OPEN_QUESTIONS / NOT_VERIFIED live as YAML blocks, markdown tables, or numbered prose inside each stage markdown. The consolidated machine-readable inventory is `_stage7_work/decision_inventory.json` (decisions=115, open_questions=75, not_verified=89, id-collisions=0).

---

## 1. Contract cross-check

Every named contract is listed below with (a) each competing version and its location, (b) whether the difference is a **conflict** (two versions, no documented precedence) or a **documented supersession** (later stage explicitly replaces earlier), and (c) the status left to the reader. Where a contract exists in only one place it is marked SINGLE-SOURCE (not a conflict, but flagged if it is load-bearing and unversioned).

### 1.1 Canonical event envelope

| Version | Location | Shape |
|---|---|---|
| V1 Stage-1 §6.1 sketch | `stage-1…md` §6.1 | flat: `event_id`, `tenant_id`, `upload_id`, `source_format`, `source_ref`, `event_time`, `ingest_time`, `channel`, `provider`, `event_id`, `record_id`, `computer`, `classification`, `fields{dotted keys}` |
| V2 canonical-event/v1 | `canonical_event_v1.schema.json` + Stage-2 §1 | nested: `schema_version`, `event{category,type,action,outcome,severity,derived_by}`, `tenant_id`, `workspace_id`, `run_id`, `time{utc,original,original_timezone,timezone_source,precision,state}`, `host{hostname,fqdn,ips,os,arch}`, `user`, `source{file_id,format,parser,parser_version,channel,provider,event_id,record,sha256}`, `raw`, `unmapped` |

**Conflict type:** V1 is an early sketch; V2 is normative (JSON Schema + 121 validated examples). Stage-2 never says "supersedes §6.1" by name; Stage-5 detectors and Stage-6 storage all speak V2 only. `events` DDL stores the V2 document as JSONB (`document` column) plus indexed envelope columns (`run_id`, `event_time_utc`, `host_hostname`, `user_name`, `event_category`, `source_event_id`, …).

**Status: RESOLVED (C-1-fix).** V2 is normative. Stage-1 §6.1 now carries a SUPERSEDED banner (C-1-fix, Stage-8 round 1) pointing to canonical-event/v1; file precedence made explicit.

**Specific field deltas:**

| Field | V1 | V2 | Note |
|---|---|---|---|
| provenance key | `upload_id` | `run_id` (+ `source.file_id`) | different names, no mapping table |
| data classification | `classification: public\|internal\|restricted` | absent | see §1.5 |
| flat taxonomy | `fields{"process.image":…}` | `unmapped{}` + structured `host`/`user`/`event` | Stage-2 §1.4 defines unmapped policy |
| raw access | `raw_ref` | `raw` object (stage-2) | |

### 1.2 Finding / alert object

| Version | Location | Name | Key fields |
|---|---|---|---|
| V1 Stage-1 §6.4 | `stage-1…md` | `alerts` | `alerts.severity`, `alerts.level_original`, `events.classification` inherited |
| V2 Stage-5 §4.1 | `stage-5…md` | `sentinel-finding/v1` | `{rule_id, rule_name, kind, severity, time, event_ids[], host{agent_id,instance_id,name}, user, detection_path, reason_codes[], payload_excerpt, attck_refs[], falsepositives_note, attestation}` |
| V3 OpenAPI Finding | `openapi.yaml` `#/components/schemas/Finding` | `Finding` | `{finding_uid, rule_id, rule_name, kind, severity, time_utc, host_hostname, user_name, detection_path, reason_codes, fingerprint, event_uids, first_seen, last_seen, occurrence_count, triage_state, evidence_snapshot, run_id}` |
| V4 DDL `findings` | `schema.sql` | table | V3 columns as SQL, plus `tenant_id`, `workspace_id`; **no** `author`, **no** `level_original`, **no** `classification` |

**Conflict type:** three live names (`alerts` / `sentinel-finding/v1` / `Finding`) + one DDL table. Stage-6 §evidence says the JSONB freeze contains "the full finding document (`sentinel-finding/v1` per Stage 5 §4)" — so V2 is the snapshot payload, V3/V4 are the API/storage projection. They do not currently agree:

| V2 field | V3/V4 counterpart | Delta |
|---|---|---|
| `time` | `time_utc` | rename |
| `event_ids[]` | `event_uids[]` | rename |
| `host{agent_id,instance_id,name}` | `host_hostname` (string) | structure collapse; agent/instance dropped |
| `user` | `user_name` | rename |
| `payload_excerpt` | — | missing in V3/V4 |
| `attck_refs[]` | — | missing in V3/V4 |
| `falsepositives_note` | — | missing in V3/V4 |
| `attestation` | — | missing in V3/V4 |
| — | `finding_uid`, `fingerprint`, `first_seen`, `last_seen`, `occurrence_count`, `triage_state`, `evidence_snapshot`, `run_id` | V3/V4-only |

`sentinel-finding/v1` appears **0 times** in `schema.sql` and `openapi.yaml` (only inside Stage-5 prose and the Stage-6 evidence-snapshot comment). `sentinel-alert` appears 0 times anywhere (no dangling name to resolve beyond the `alerts` vs `findings` split). `AnalysisRun` appears 0 times anywhere.

**Status: RESOLVED (C-2-fix).** Layered contract: DDL `findings` storage-normative; `sentinel-finding/v1` engine-internal (persisted verbatim in `evidence_snapshot`); OpenAPI `Finding` API projection (now with `author`, `level_original`). `payload_excerpt`/`attck_refs`/`falsepositives_note`/`attestation` live in the snapshot. `alerts` name superseded by `findings` (Stage-1 §6.4 banner).

### 1.3 Detection severity / level / classification axes

| Axis | Stage-1 §6.4 (binding) | OpenAPI | DDL | Stage-2 / canonical schema |
|---|---|---|---|---|
| detection severity | `LOW\|MEDIUM\|HIGH` on alerts | `Finding.severity` enum LOW/MEDIUM/HIGH | `findings.severity CHECK (… IN ('LOW','MEDIUM','HIGH'))` | `event.severity` enum informational/low/medium/high/critical (different scale — this is upstream fidelity, not product severity) |
| upstream level | `alerts.level_original` verbatim | **absent** on Finding (present on `Rule.level_original`) | **absent** on findings | n/a |
| data classification | `events.classification` = `public\|internal\|restricted` | header `DataClassification` = integer `1\|2\|3` (1 internal, 2 sensitive, 3 restricted) | **no** `events.classification` column | **no** classification field on canonical-event/v1 |

**Conflict type:** three spellings of data classification (Stage-1 §6.1 comment "LEVEL 1 of 3", Stage-1 §6.4 string enum, OpenAPI integer enum with a different value set — `restricted` vs `3`, `sensitive` appears only in OpenAPI). Severity/level split is intact in DDL for `rules.level_original` but dropped on `findings`.

**Status: RESOLVED (C-3-fix, C-3b-fix).** Single string vocabulary `public|internal|restricted` (DDL CHECK + canonical enum + OpenAPI header now string enum). `level_original` restored on `findings` (nullable) and OpenAPI `Finding`.

### 1.4 Upload / artifact API path

| Version | Location | Paths |
|---|---|---|
| V1 Stage-3 | `stage-3…md` | `POST /v1/artifacts`, `GET /v1/artifacts/{artifact_id}` |
| V2 OpenAPI | `openapi.yaml` | `POST /v1/workspaces/{workspaceId}/uploads` (`createUpload`), `GET /v1/workspaces/{workspaceId}/uploads/{artifactId}`, plus evidence under `/v1/workspaces/{workspaceId}/evidence/{findingUid}` |

**Conflict type:** resource rename (`artifacts` → `uploads`) and workspace-scoped prefix. Stage-6 §API narrative follows V2. Stage-3 body still uses V1 paths in gate/error tables.

**Status: RESOLVED (C-4-fix).** OpenAPI workspace-scoped paths adopted normative; Stage-3 §1.1 updated; Stage-3's HTTP 201 sketch superseded by the OpenAPI 202 `Upload` schema.

**Related:** `createUpload` multipart marks only `file` required; `run_id` is optional in the request schema. DDL `uploads.run_id` is `NOT NULL`. OpenAPI `Upload` response schema lists `run_id` required. Request/response/DDL disagree on whether the client must supply `run_id`.

**Status: RESOLVED (C-4b-fix).** Server-generated: client MAY supply `run_id` as a hint; absent → server generates (DDL NOT NULL satisfied server-side); Upload response always returns the effective run_id.

### 1.5 `rule_run` accounting shape

| Version | Location | Columns/fields |
|---|---|---|
| V1 Stage-5 §4.3 | `stage-5…md` | `rule_run(rule_id, job_id, outcome, findings, processed_events, rejected_events, max_group_size, max_window_ms, sql_ms, native_ms)` |
| V2 DDL | `schema.sql` | `run_id, rule_id, outcome, findings, processed_events, rejected_events, max_group_size, detection_path, reason_codes, started_at, finished_at` (+ tenant/workspace) |
| V3 OpenAPI `RuleRun` | `openapi.yaml` | `detection_path, findings, max_group_size, outcome, processed_events, reason_codes, rejected_events, rule_id` |

**Deltas:** `job_id`, `max_window_ms`, `sql_ms`, `native_ms` exist only in V1. `run_id`, `detection_path`, `reason_codes`, `started_at`, `finished_at` exist only in V2/V3. V3 omits all timing columns.

**Status: RESOLVED (C-5-fix).** Stage-5 `job_id` ≡ DDL `run_id` (mapped, no duplicate column). `max_window_ms`/`sql_ms`/`native_ms` added to DDL `rule_run` and OpenAPI `RuleRun`; timing split preserved for §10.6 shadow reports.

### 1.6 `config_hash` representation

| Version | Location | Type |
|---|---|---|
| V1 DDL | `schema.sql` `detection_runs.config_hash` | `bytea NOT NULL` |
| V2 OpenAPI | `DetectionRun.configHash` | `string` pattern `^[0-9a-f]{64}$` |

**Status: RESOLVED (C-7-fix).** bytea at rest; lowercase hex at the API edge via `encode(config_hash,'hex')`/`decode(<hex>,'hex')`, documented in Stage-6 §4 and the OpenAPI property description.

### 1.7 Canonical `source.format` enum

| Version | Values |
|---|---|
| canonical-event/v1 JSON Schema | `evtx, json, csv, xml, tsv, text, nmap_xml, pcap, sqlite, yaml, other` (**includes `xml`**) |
| OpenAPI `CanonicalEvent.source.format` | `evtx, json, csv, tsv, text, nmap_xml, pcap, sqlite, yaml, other` (**omits `xml`**) |

Stage-2 Stage-3 both ingest raw XML (OOXML, generic XML, AppLocker XML, etc.). An OpenAPI-validated client would reject `format: xml`.

**Status: RESOLVED (C-8-fix).** `xml` added to the OpenAPI enum (canonical normative). Adjacent defect fixed: OpenAPI `source.required` referenced non-existent `record_type`, now aligned to canonical `[file_id, format, parser, parser_version]`.

### 1.8 Canonical `host` shape

| Version | Shape |
|---|---|
| canonical-event/v1 | `{hostname, fqdn, ips[], os{family,build}, arch}` |
| OpenAPI `CanonicalEvent.host` | `{type: object, additionalProperties: true}` (free-form) |

OpenAPI is a looser superset; a free-form host would not validate against the JSON Schema. Which validator is authoritative for API-bound events is unstated.

**Status: RESOLVED (C-9-fix).** OpenAPI `CanonicalEvent.host` tightened from free-form to the structured canonical shape; JSON Schema remains authoritative for event validation. Stage-5 finding `host{agent_id,instance_id,name}` documented as a separate agent-identity concept.

### 1.9 `rules` table vs OpenAPI `Rule`

DDL columns absent from OpenAPI `Rule`: `tenant_id`, `workspace_id` (path-scoped — acceptable projection), `schema_tag`, `source_ref`, `source_spec`, `description`, `provenance`, `deleted_at`. OpenAPI adds nothing the DDL lacks. `RuleDocument` in OpenAPI is `additionalProperties: true` with a prose pointer to `rule_schema.json` (not a `$ref`) — the normative rule schema is therefore **not machine-linked** from the API.

**Status: RESOLVED (C-10-fix).** Provenance columns (`schema_tag`, `source_ref`, `source_spec`, `description`, `provenance`, `deleted_at`) added to OpenAPI `Rule`; `RuleDocument` now `allOf: [$ref "rule_schema.json"]` (OpenAPI 3.1 external ref), machine-linking the normative rule schema (closes S7-V8/D8-17).

### 1.10 `ioc_pack.status` default

| Version | Behaviour |
|---|---|
| DDL | `status text NOT NULL DEFAULT 'active' CHECK (status IN ('pending_verify','active','rejected','retired'))` |
| OpenAPI `IocPack.status` | enum same four values, no default |
| Stage-4 D4-003 / Stage-5 | signature verification flow implies packs arrive unverified |

A `DEFAULT 'active'` on insert would mark unsigned/unverified packs active, contradicting the verify-then-activate flow (signature column is nullable "NULL only in dev").

**Status: RESOLVED (C-11-fix).** DDL default changed `active` → `pending_verify`; packs flip to `active` only after Ed25519 verification per D4-003 (closes D8-18).

### 1.11 Evidence retrieval

| Version | Location | Contract |
|---|---|---|
| OpenAPI | `GET /v1/workspaces/{workspaceId}/evidence/{findingUid}` | `EvidenceBundle{finding_uid, evidence_snapshot, raw_object, raw_state}`; presigned raw URL TTL **PROPOSED: 15 min** |
| Stage-3 | triage/`finding`/`evidence` fields | fact-level `evidence` strings quoting source values — different meaning of the word "evidence" |
| Stage-6 | evidence snapshot | immutable JSONB freeze, does not reference raw bytes |

The triage "evidence" (fact quotes) and the finding "evidence" (bundle/snapshot) are distinct concepts that share a name. Presigned TTL 15 min is marked PROPOSED in OpenAPI only.

**Status: RESOLVED (C-12-fix).** No renames (would ripple 121 examples); the two meanings disambiguated in Stage-6 §1.5 (triage evidence = fact quotes; EvidenceBundle/evidence_snapshot = machine retrieval contract). TTL 15 min confirmed as the working default, retains PROPOSED-TO-BENCHMARK marker.

### 1.12 Other contract notes (SINGLE-SOURCE / informational)

| Contract | Where | Note |
|---|---|---|
| `sentinel-rule/v1` | `rule_schema.json` (normative); Stage-5 §3; OpenAPI `RuleDocument` prose-only | valid, machine-checkable; 25 Stage-5 examples + 5 Stage-3 AF rules validate OK |
| Jobs / `detection_runs` lifecycle | Stage-6 + OpenAPI `Job`/`DetectionRun` | consistent on status enums at audit time |
| Idempotency / audit_log | Stage-6 DDL + OpenAPI | consistent |
| Triage state machine | Stage-3 §5 + `uploads.triage_state` CHECK | consistent (`queued,running,done,failed,rejected_by_policy`) |
| Licence obligations | Stage-1 §2.3 + Stage-6 §licence table | Stage-6 repeats Stage-1 classifications with additions; no override detected |
| `findings.author` (DRL-1.1) | Stage-1 obligation "persist rule author on every alert row" | **RESOLVED (D8-03-fix):** `author text NOT NULL` added to `findings`; also added to OpenAPI `Finding`. INV-6 now PASS |

---

## 2. Decision conflicts

Machine extraction (`_stage7_work/extract_decisions.py` → `decision_inventory.json`): **114 decisions, 74 open questions, 88 not-verified items, 0 id collisions** (no two stages define the same decision id). Format varies by stage (YAML list, markdown table, numbered prose) — the inventory normalises them.

No two decisions with the same id disagree. The **cross-stage semantic tensions** are the contract conflicts in §1 (naming: alerts/findings; envelope: §6.1 vs canonical-event/v1; paths: artifacts vs uploads; severity/classification spellings; rule_run shape; config_hash encoding; ioc_pack default). Each is bound to decisions that predate the later artifact:

| Tension | Binding decisions | Later artifact that breaks the assumption |
|---|---|---|
| `alerts` table name | Stage-1 D-004 (Option C), §6.4 | Stage-6 DDL names the table `findings` |
| classification on events | Stage-1 D-012 / §6.1–6.4 | Stage-2 canonical-event/v1 and Stage-6 DDL both omit it |
| author on every alert | Stage-1 DRL-1.1 (licence gate) | `findings` has no `author` column |
| upload path | Stage-3 gate §1 | OpenAPI workspace-scoped `/uploads` |
| rule_run metrics | Stage-5 §4.3 | DDL `rule_run` lacks `job_id`/`max_window_ms`/`sql_ms`/`native_ms` |
| pack verify-then-activate | Stage-4 D4-003, Stage-5 ioc section | DDL `DEFAULT 'active'` |

These were recorded as open conflicts at Stage-7 time. **All are now RESOLVED (Stage-8 round 1, conflict-decision pass)** — see the §13 register in the spec and `stage-8-fix-log.md` for each decision's rationale. Decision-block YAML inside each stage remains verbatim in the merged spec; no historical decision text was rewritten — resolutions were added as documented new decisions.

---

## 3. Dangling references

IDs referenced in stage bodies that do not resolve to a definition, after feeding `audit_invariants.py` the full inventory from `extract_decisions.py` (which understands YAML lists, markdown tables, and Stage-1 numbered prose).

| Reference | Cited at | Expected definition | Status |
|---|---|---|---|
| `D-022` | Stage-5 §4 (streaming reconciliation, called "binding") | Stage-1 only defines D-001…D-012 | **RESOLVED (D8-13-fix):** citation corrected to "normative, see §4 modes table"; no D-022 decision exists or is needed. |
| `Q5-009` | Stage-5 §1 table (`scope` SUPPORTED_LATER, "deployment gating deferred to Stage-6 (Q5-009)") | Stage-5 OPEN_QUESTIONS defines Q5-001…Q5-008 only | **RESOLVED (D8-13-fix):** Q5-009 registered in Stage-5 OPEN_QUESTIONS (rule `scope` deployment-gating vocabulary). |
| `events.classification` | Stage-1 §6.4, §8 invariant text; Stage-5 §1.10 invariant 5 | Column does not exist in `schema.sql`; field does not exist in canonical-event/v1 | **RESOLVED (D8-02-fix):** `classification` column added to `events` (NOT NULL, CHECK) and optional enum field added to canonical-event/v1. INV-5 now PASS |
| `alerts.*` (table) | Stage-1 §6.1–6.4, MVP-6, detectors narrative | Table is named `findings` in Stage-6 DDL/OpenAPI | **RESOLVED (C-2-fix):** `alerts` superseded by `findings` (Stage-1 §6.4 naming banner); same semantics |
| Stage-3 `/v1/artifacts` paths | Stage-3 gate/error tables | OpenAPI defines `/v1/workspaces/{id}/uploads` | **RESOLVED (C-4-fix):** Stage-3 §1.1 updated to OpenAPI paths; supersession documented |

Stage-6 table-format decisions (D6-001…D6-016), Stage-4 YAML decisions (D4-001…D4-005), and Stage-4 markdown-table open questions (Q4-001…) all resolve correctly once the inventory is shared. **0 further dangling decision/question ids.**

Evidence-register ids (TL-*, ARC-*, DOC-*, PRIOR-*, FX-*, UP-*, ID-*, etc.) used throughout Stages 2–5 resolve against `verification-log.yaml` / `VERIFICATION_LOG_2026-10-09.yaml` / Stage-3 §0 as authored; a full id-by-id join was **not** executed (see NOT_VERIFIED).

---

## 4. Invariant audit

Invariants are the Stage-1 §5/§8 and Stage-5 §1.10 claims that must hold across every later artifact. Checks are in `_stage7_work/audit_invariants.py`; results `_stage7_work/invariants_numbers.json`.

| Id | Invariant | Check | Result |
|---|---|---|---|
| INV-1 | Engine with zero rules emits zero findings; no detection constants in engine code | Stage-5 engine design (SQL path is data-driven; native path has no baked detections) | **PASS** |
| INV-2 | Detectors consume only canonical-event/v1 objects | Stage-3 §3.4/§12 emit canonical-event/v1; Stage-5 §3.4 | **PASS** |
| INV-3 | Triage never emits a verdict; clean/safe/benign/malicious banned by name | Stage-3 triage matrix uses facts + finding-ids only | **PASS** |
| INV-4 | No rendering, no macro execution, no document interpreters in-process, no egress, no code-loading | Stage-3 sandbox/isolation posture + Stage-4 tiers | **PASS** |
| INV-5 | `events.classification` (public/internal/restricted) is a persisted column | `schema.sql` `events` has `classification` (NOT NULL CHECK); canonical-event/v1 has the optional enum field | **PASS** (D8-02-fix) |
| INV-6 | Rule author is persisted on every alert/finding row (DRL-1.1) | `findings` has `author text NOT NULL`; also on OpenAPI `Finding` | **PASS** (D8-03-fix) |
| INV-7 | Every tenant-scoped table has RLS ENABLEd (D-012 / Stage-6) | All 16 tenant-scoped tables have `ENABLE ROW LEVEL SECURITY` + policies (schema.sql:475–577) | **PASS** (initial regex missed aligned spacing; corrected) |
| INV-8 | `findings.evidence_snapshot` is an immutable JSONB freeze that does NOT reference raw bytes | DDL comment + Stage-6 §evidence + OpenAPI EvidenceBundle separates snapshot from `raw_object` | **PASS** |
| INV-9 | `severity` (LOW/MEDIUM/HIGH) and `level_original` (informational…critical) remain separate axes | Separate on `rules`; `level_original` dropped on `findings` (see §1.3) — separation holds where both exist | **PASS with gap** (level_original absent on findings) |
| INV-10 | Canonical events never contain a bare JSON null except `time.utc` under state unknown/invalid | `canonical_event/v1.schema.json` `$defs.time.allOf` guards null utc by state; `$defs.state_object` bans bare null | **PASS** |

**Invariant failures requiring human input:** none — INV-5 and INV-6 were the only failures and both now PASS (D8-02/D8-03 fixes). All 10 invariants hold.

---

## 5. Number audit

Counts claimed in stage bodies vs counts measured from the artifacts.

| Claim | Source | Measured | Status |
|---|---|---|---|
| Stage-2 example corpus | per-source headings `(30)+(32)+(37)+(6)+(6)+(1)×8+(2)` | 121 `### EX-*` blocks | **MATCH** |
| Stage-2 examples validate vs canonical-event/v1 | Stage-2 §5 | `_stage7_work/validate_examples.py`: **121/121 OK** | **MATCH** |
| Stage-5 "25 documents, schema-valid" | Stage-5 §11 heading | 25 rule documents; **25/25 OK** vs `rule_schema.json` | **MATCH** |
| Stage-3 AF rule examples | Stage-3 §12 | 5 AF rules; **5/5 OK** vs `rule_schema.json` | **MATCH** |
| Stage-6 verification rows `V-6-*` | Stage-6 table | 39 rows | **MATCH** (table self-consistent) |
| Stage-6 decisions `D6-*` | Stage-6 table | 16 rows | **MATCH** |
| Stage-6 open questions `OQ-6-*` | Stage-6 table | 9 rows | **MATCH** |
| Stage-4 decisions `D4-*` | Stage-4 §9 YAML | 5 (D4-001…D4-005) | **MATCH** |
| Stage-1 decisions `D-001`…`D-012` | Stage-1 §8.1 | 12 unique ids (13 mentions) | **MATCH** |
| Stage-1 open questions Q1–Q12 | Stage-1 §8.2 | 12 | **MATCH** |
| Consolidated totals | no single stage claims a total | inventory: 114 D / 74 Q / 88 NV | **informational** (corrected after D8-08 header-row fix; Q count rose 73→74 when Q5-009 was registered under D8-13) |
| OpenAPI paths | — | 23 paths | **informational** |
| DDL tables | Stage-6 narrative "21 tables" | 21 logical tables (32 `CREATE TABLE` incl. 11 monthly partitions) | **MATCH** |

RETRACTED (D8-16): the earlier claim "No numeric contradiction found inside the stage corpus" was false. The number audit's own tooling (`extract_decisions.py`) counted markdown table header rows as items, inflating the totals to 115 D / 75 Q / 89 NV; the true counts are 114 D / 74 Q / 88 NV (D8-08 fixed the counter; the Q count rose from 73 to 74 when Q5-009 was registered under D8-13). Additional numeric contradictions that were present but undisclosed at audit time: Stage-3 §0 summary said 61 entries / 59 VERIFIED while the log actually holds 75 / 73 (D8-09, fixed); Stage-6 §1.2 said "32 relations" while only 21 are logical tables (11 are monthly partitions — clarified; the 32 CREATE TABLE count is itself correct); gate budgets differed between Stage-3 §1.2 and Stage-6 §4 (D8-05, fixed — Stage-6 §4 now aligns to §1.2: 64 MiB/64 MiB/8 KiB/30 s, PROPOSED − TO BENCHMARK); PostgreSQL doc citations mixed 17.4 and 18 (D8-12, fixed — all re-pinned to 18). Numbers that are PROPOSED and not yet measured (presigned TTL 15 min, parser budgets, sandbox timeouts) are carried as-is into the spec with their PROPOSED markers intact.

---

## 6. What is NOT in conflict (explicitly verified)

- Triage state machine values match across Stage-3 and `uploads.triage_state` CHECK.
- Job/detection_run status enums match across Stage-6, OpenAPI `Job`/`DetectionRun`.
- `rule_schema.json` accepts all 30 example rule documents (25 + 5 AF).
- `canonical_event/v1.schema.json` accepts all 121 Stage-2 examples.
- RLS is enabled on every tenant-scoped table; policy set is complete.
- Licence tables in Stage-1 and Stage-6 agree (Stage-6 adds rows, does not override).
- No decision-id collisions across stages.
- Idempotency, audit_log, retention_policies DDL ↔ OpenAPI plumbing is consistent at audit time.

---

## 7. DECISIONS

No new product decisions are made by Stage 7. Stage 7 **records** the following process decisions (YAML, machine-readable):

```yaml
- id: S7-001
  decision: Assemble SENTINEL_IMPLEMENTATION_SPEC.md by full verbatim splice of stage bodies (no summarised sections); verification logs and decision blocks are hoisted into §2/§3/§14 with pointers left in place.
  status: accepted
  evidence: brief reject-conditions "no section that is a summary", "no omitted stage artifact"
  alternatives_rejected:
    - prose-only merge (violates lossless requirement)
- id: S7-002
  decision: Do not silently resolve any contract conflict; every conflict in §1 ships unresolved into the spec's "Open decisions requiring human input".
  status: accepted
  evidence: brief "no silent conflict resolution"
- id: S7-003
  decision: Treat canonical_event_v1.schema.json + rule_schema.json as the machine-normative contracts; stage prose that disagrees is listed as conflict, not rewritten.
  status: accepted
  evidence: both files validate the delivered example corpora (121/121, 25/25, 5/5)
- id: S7-004
  decision: Publish decision/question/not-verified inventory as _stage7_work/decision_inventory.json alongside the spec because no *_decisions.yaml files exist.
  status: accepted
  evidence: recursive search decision_yaml_files=[]
```

## 8. OPEN_QUESTIONS

1. **S7-Q1** — Mark Stage-1 §6.1 envelope as SUPERSEDED by canonical-event/v1, or keep both as living sketches?
2. **S7-Q2** — Which finding contract is normative: Stage-5 `sentinel-finding/v1`, OpenAPI `Finding`, or a reconciled schema? How do `payload_excerpt` / `attck_refs` / `falsepositives_note` / `attestation` land in storage?
3. **S7-Q3** — Rename `findings` back to `alerts`, update all Stage-1 references to `findings`, or introduce a view/alias?
4. **S7-Q4** — Restore `events.classification` (column + canonical field), drop the invariant, or move classification to `uploads`/`raw_objects`?
5. **S7-Q5** — Restore `findings.author` (and `level_original`) to satisfy DRL-1.1 and INV-9, or record an explicit licence-gate exception?
6. **S7-Q6** — Adopt OpenAPI workspace-scoped `/uploads` paths and renumber Stage-3 error tables, or keep `/v1/artifacts` as a compatibility alias?
7. **S7-Q7** — Is `run_id` on `createUpload` required-from-client, optional-with-server-generation, or rejected when absent?
8. **S7-Q8** — Reconcile `rule_run` metrics: add `job_id`/`max_window_ms`/`sql_ms`/`native_ms` to DDL, or drop them from Stage-5 §4.3?
9. **S7-Q9** — Specify `config_hash` edge encoding (hex string ↔ bytea) and where encode/decode happens.
10. **S7-Q10** — Add `xml` to OpenAPI `source.format`, or ban `xml` in canonical-event/v1?
11. **S7-Q11** — Tighten OpenAPI `CanonicalEvent.host` to `$ref` the canonical host object, or keep free-form and declare OpenAPI non-authoritative for events?
12. **S7-Q12** — Change `ioc_pack.status DEFAULT 'active'` to `'pending_verify'`?
13. **S7-Q13** — Resolve dangling `D-022` (Stage-5 streaming reconciliation) — record the decision or fix the citation?
14. **S7-Q14** — Resolve dangling `Q5-009` (deployment gating) — record the open question or fix the citation?
15. **S7-Q15** — Confirm presigned evidence TTL (15 min PROPOSED) and rename triage-level `evidence` strings to avoid collision with EvidenceBundle.
16. **S7-Q16** — Should OpenAPI `Rule` `$ref` `rule_schema.json` and expose `source_ref` / `source_spec` / `provenance` / `description`?

## 9. NOT_VERIFIED

1. **S7-V1** — Evidence-register id join (every TL-*/ARC-*/DOC-*/PRIOR-*/FX-*/UP-*/ID-* cited in Stages 2–5 ↔ `verification-log.yaml` + `VERIFICATION_LOG_2026-10-09.yaml` + Stage-3 §0) was **not** executed id-by-id; only spot-checked.
2. **S7-V2** — No Postgres instance was available; DDL was **not** executed. RLS policies, CHECK constraints, and PARTITION clauses are text-audited only.
3. **S7-V3** — `openapi.yaml` was **not** linted with a spectral/openapi-generator toolchain; only structural parse + schema/path cross-checks against DDL and stages.
4. **S7-V4** — Sandbox (.wsb / AppContainer / Job Object) behaviour (Stage-4) was **not** executed on a Windows Sandbox host in this stage.
5. **S7-V5** — Parser fixture corpora (Stage-3 FX-*) were **not** re-run; Stage-3 labels (VERIFIED/…) are carried as authored.
6. **S7-V6** — Engine performance budgets (Stage-5 §10) are PROPOSED; no load test was run.
7. **S7-V7** — Ed25519 signature verification for ioc_pack (D4-003) was **not** implemented or tested in Stage 7.
8. **S7-V8** — OpenAPI `RuleDocument.additionalProperties: true` means rule documents in API responses are **not** machine-validated against `rule_schema.json` at the API layer; only the file-based examples were validated.
9. **S7-V9** — Stage-2 tolerant-parser notes (unquoted colons in decision titles, backtick scalars) mean decision YAML blocks are informal; they were parsed by a tolerant extractor, not a strict YAML conformance suite.
10. **S7-V10** — Cross-stage licence obligation completeness (every DRL/CC/MIT clause → a concrete enforcement point in code paths) was **not** traced end-to-end.

---

*End of consistency_report.md. Machine-readable artifacts: `_stage7_work/decision_inventory.json`, `_stage7_work/example_validation.json`, `_stage7_work/openapi_ddl_audit.json`, `_stage7_work/invariants_numbers.json`.*
