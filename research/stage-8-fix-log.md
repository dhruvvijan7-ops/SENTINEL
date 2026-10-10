# Stage-8 Fix Log — Round 1

Remediation record for the Stage-8 adversarial review (`stage-8-adversarial-review.md`, REJECT 42/56). Each defect is traced to its fix, the files touched, and the re-run evidence. Conflicts are **registered, not silently resolved** (project precedence rule); a fix "resolves" a defect only where the defect was a contradiction or tooling bug, not where it surfaced a genuine open design conflict.

## Status summary

| Defect | Severity | Status | One-line resolution |
|---|---|---|---|
| D8-01 | Blocker | **RESOLVED** | False psycopg OpenSSL-exception claim struck; LGPL posture re-derived without it |
| D8-02 | Blocker | **RESOLVED** | `events.classification` added (NOT NULL column + optional wire enum); INV-5 PASS |
| D8-03 | Blocker | **RESOLVED** | `findings.author` column added; INV-6 PASS |
| D8-04 | Blocker | **RESOLVED** | All 16 conflicts C-1…C-16 decided and implemented (conflict-decision pass, below); C-6/C-13/C-14/C-15 earlier via D8-02/03/13 |
| D8-05 | High | **RESOLVED** | Gate budgets aligned to Stage-3 §1.2 (64 MiB/64 MiB/8 KiB/30 s) in Stage-6 §4 |
| D8-06 | High | **RESOLVED** | Telemetry-family precedence sniff + 7 format-family map rows added (Stage-3 §2.3) |
| D8-07 | High | **RESOLVED** | SQLite triage subsection added (Stage-3 §5.9b) |
| D8-08 | High | **RESOLVED** | `extract_decisions.py` header-row bug fixed; counts now 114 D / 74 Q / 88 NV (was 115/75 inflated). Stage-6 "32 CREATE TABLE" claim verified correct (21 tables + 11 partitions = 32) |
| D8-09 | High | **RESOLVED** | Stage-3 §0 summary corrected to 75 entries / 73 VERIFIED |
| D8-10 | High | **RESOLVED** | `audit_openapi_ddl.py` path fixed to `/v1/workspaces/{workspaceId}/uploads`; 12 mismatches now surfaced (was silent false negative) |
| D8-11 | High | **RESOLVED** | `deadline_unix` → `deadline_monotonic` (Stage-3 §3.2, spec, `_stage3_work/p3_parser_interface.md`) |
| D8-12 | High | **RESOLVED** | All PostgreSQL citations re-pinned 17.4 → 18 (features re-verified on postgresql.org/docs/18: `date_bin` §9.9.3, `starts_with`/`^@` §9.4) |
| D8-13 | High | **RESOLVED** | Q5-009 registered; "(binding, D-022)" → "normative, see §4"; C-6/C-13/C-14/C-15 marked RESOLVED in §13 |
| D8-14 | High | **RESOLVED** | S-01 paths fixed (`process.parent_image` → `process.parent.exe`); new CI gate `_stage5_work/validate_rule_paths.py` (25 rules / 22 fields / 0 failures; would reject the old path); §10.6 gate row added |
| D8-15 | High | **RESOLVED** | WSB CLI caveated as Windows 11 24H2+ in tier table, D4-001 consequences, and evidence row (verified on MS Learn) |
| D8-16 | High | **RESOLVED** | `consistency_report.md` §5 false "no numeric contradiction" claim retracted with disclosed contradictions |
| D8-17 | Medium | **RESOLVED** | Closed via C-10-fix: `RuleDocument` now `allOf: [$ref "rule_schema.json"]` (OpenAPI 3.1 external ref) — API layer machine-validates rules against the normative schema |
| D8-18 | Medium | **RESOLVED** | Closed via C-11-fix: `ioc_pack.status` DDL DEFAULT `'active'` → `'pending_verify'` (safety default; verify-then-activate per D4-003) |
| D8-19 | Medium | **RESOLVED** | Closed via C-7-fix: bytea at rest, hex at the API edge via `encode()`/`decode()`, documented in Stage-6 §4 + OpenAPI description |
| D8-20 | Medium | **PARTIAL** | `sqlite` triage row added (D8-07); `.eml`/`.msg` (Q3-015) and NSIS/Inno (Q3-016) remain open questions (triage-scope decisions, not contract conflicts) |

## Conflict-decision pass (D8-04, Stage-8 round 1)

All 16 conflicts in the `consistency_report.md` §1 / spec §13 register were decided with documented rationale; every resolution names the artifacts it touched and the precedence rule it follows. No historical decision text was rewritten — resolutions were added as new documented decisions.

| Conflict | Decision | Artifacts changed |
|---|---|---|
| C-1 event envelope | Stage-1 §6.1 marked **SUPERSEDED** by canonical-event/v1 (JSON Schema normative per precedence; §6.1 had a duplicate `event_id` key bug) | stage-1 §6.1 banner |
| C-2 finding object | **Layered:** DDL `findings` storage-normative; `sentinel-finding/v1` engine-internal (persisted verbatim in `evidence_snapshot` per Stage-6 §1.5 — `payload_excerpt`/`attck_refs`/`falsepositives_note`/`attestation` live there); OpenAPI `Finding` API projection (+ `author`, `level_original`); `alerts` name superseded by `findings` | openapi Finding, stage-1 §6.4 banner, stage-5 §4.1 note, stage-6 §1.5 |
| C-3 classification spelling | **Single vocabulary** `public\|internal\|restricted` (DDL CHECK + canonical enum); OpenAPI `X-Data-Classification` header changed from integer 1\|2\|3 to string enum | openapi header + info.description |
| C-3b `level_original` | **Column restored:** `findings.level_original text` (nullable, verbatim upstream level) + OpenAPI `Finding` — closes the INV-9 gap | schema.sql, openapi Finding |
| C-4 upload path | **OpenAPI workspace-scoped paths normative**; Stage-3 §1.1 updated (`/v1/workspaces/{workspaceId}/uploads`); Stage-3's HTTP 201 sketch superseded by OpenAPI 202 `Upload` | stage-3 §1.1 |
| C-4b `run_id` | **Server-generated**; client MAY supply as idempotency hint; absent → server generates (DDL NOT NULL satisfied server-side); Upload response always returns effective run_id. Same class applied to the 6 other server-derived upload columns (tenant/workspace from principal, sha256/size computed, filenames from multipart) and `file`→raw_objects CAS | openapi createUpload description |
| C-5 `rule_run` metrics | Stage-5 `job_id` ≡ DDL `run_id` (**mapped, no duplicate column**); `max_window_ms`/`sql_ms`/`native_ms` added to DDL + OpenAPI `RuleRun` (sql-vs-native timing split is load-bearing for §10.6 shadow reports) | schema.sql, openapi RuleRun, stage-5 §4.3 note, stage-6 §1.2 |
| C-7 `config_hash` | **bytea at rest; hex at the API edge** via `encode(config_hash,'hex')`/`decode(<hex>,'hex')`, documented | stage-6 §4, openapi description |
| C-8 `source.format` | **`xml` added to OpenAPI enum** (canonical normative; XML ingested — OOXML/AppLocker). Adjacent defect fixed: OpenAPI `source.required` referenced non-existent `record_type`, aligned to canonical `[file_id, format, parser, parser_version]` | openapi source |
| C-9 `host` shape | OpenAPI `CanonicalEvent.host` → **`$ref: "canonical_event_v1.schema.json#/$defs/host"`** (OpenAPI 3.1 external ref, single source of truth; string-or-state fields preserved — an earlier inline `string|null` version would have rejected valid `{ $state: ... }` carriers, caught and corrected in the round-2 self-check). JSON Schema remains authoritative; Stage-5 finding `host{agent_id,instance_id,name}` documented as a separate agent-identity concept | openapi host, audit tool `resolve_ref` fragment support, stage-5 §4.1 note |
| C-10 OpenAPI Rule projection | **Provenance columns added** (`schema_tag`, `source_ref`, `source_spec`, `description`, `provenance`, `deleted_at`); `RuleDocument` → `allOf: [$ref "rule_schema.json"]` (3.1 external ref) — closes S7-V8/D8-17 | openapi Rule + RuleDocument |
| C-11 `ioc_pack.status` | **DEFAULT `'active'` → `'pending_verify'`** (safety default; packs flip to active only after Ed25519 verification per D4-003) — closes D8-18 | schema.sql, stage-6 §1.2, stage-4 D4-003 |
| C-12 evidence naming + TTL | **No renames** (would ripple 121 examples); two meanings disambiguated in Stage-6 §1.5 (triage evidence = fact quotes; EvidenceBundle/evidence_snapshot = machine retrieval contract); TTL 15 min **confirmed** as working default, keeps PROPOSED-TO-BENCHMARK marker | stage-6 §1.5 + §3.2 |
| C-16 Stage-1 splice | **Index/reference approach accepted** — Stage-1 remains a delivered sibling file (inlining would duplicate the licence table + decision block) | spec §13 register note |

Audit-tool updates so the harness reflects the resolved state (`audit_openapi_ddl.py`): external `$ref` loading (rule_schema.json), canonical-host `$ref` deref, `job_id`→`run_id` mapping, and reclassification of the 10 documented representation/projection items into `resolved_notes` (open `mismatches` now **0**).

## Tooling fixes (Stage-7 harness)

- `extract_decisions.py` — `count_markdown_rows` no longer counts header rows (`| id |` line) as items. Regenerated `decision_inventory.json`.
- `audit_invariants.py` — events.classification dangling check uses bounded `CREATE TABLE` block regex instead of `split(")")[0]` (was broken by `uuidv7()`). All 10 invariants PASS.
- `audit_openapi_ddl.py` — reads the real createUpload path; emits the 12 previously-skipped mismatches (all registered conflicts, none new defects).
- New: `_stage5_work/validate_rule_paths.py` — walks rule detection/correlation/ioc/fim/sca/statistical/when containers, validates Sigma-style keys and `field:` values against `canonical_event_v1.schema.json`; emits `_stage5_work/rule_path_validation.json`.

## Re-run evidence (post-fix, after conflict-decision pass)

```
extract_decisions:   decisions=114  open_questions=74  not_verified=88  collisions=0  conflicts=0
audit_invariants:    INV-1..INV-10 PASS  invariant_failures=0  dangling=1 (stage1:160 alerts. — Wazuh's alerts.log third-party artifact; false positive, C-2 naming now superseded)
audit_openapi_ddl:   tables=21  openapi_schemas=18  mismatches=0  resolved_notes=10 (C-4b/C-5/C-7/C-10 class, documented)
validate_examples:   stage2 121/121  stage5 25/25  stage3 AF 5/5
validate_rule_paths: rules=25  fields=22  non_resolving=0
schema.sql:          CREATE TABLE statements = 32 (21 logical + 11 partitions) — matches Stage-6 §1.2
```

## Decision notes

- **D8-02 design choice:** `events.classification` is `NOT NULL CHECK (...)` in the DDL (storage invariant) but an **optional** enum on the canonical wire schema — ingest backfills the per-source default. Keeps all 121 stage-2 examples valid while making INV-5 hold at rest.
- **D8-01 licence posture:** psycopg 3 (master + 3.2.9 tag) ships plain LGPL-3.0 with **no** OpenSSL exception (the exception exists only in psycopg2 2.x and the psycopg2-binary PyPI metadata). psycopg 3 links system libpq, not OpenSSL directly, so the LGPL linking posture stands without the struck claim. V-6-012 was downgraded and V-6-012a/b added as fresh evidence rows.
- **D8-12 re-citation:** the cited features were re-verified against PostgreSQL **18** docs live (`date_bin` §9.9.3, `starts_with`/`^@` §9.4); section numbers are unchanged from 17, only the major-version pin moved. ARE-lookahead facts (PG 17+) hold in 18.

## Not in scope this round

- Spec re-assembly via `assemble_spec.py`: all edits were applied to both stage bodies and spec mirrors in place. A future full re-assembly should be diffed against the current spec to confirm no mirror drift.
- D8-20 remaining triage-scope questions (Q3-015 `.eml`/`.msg`, Q3-016 NSIS/Inno) — genuine open questions about parser scope, not contract conflicts; carried as OPEN_QUESTIONS.

## Round-2 re-review outcome

Stage-8 re-scored in the same session after remediation (full record appended to `stage-8-adversarial-review.md`):

- **Score: 55/56 (98.2%). Threshold: 48 (85%). Zeros: none. Verdict: ACCEPT.**
- Sole remaining deduction: criterion 18 (cold-start budgets PROPOSED only; S7-V6 load test not run — environmental, disclosed).
- Three regressions introduced by the remediation itself were caught in a self-check pass and fixed before scoring: OpenAPI `host` `$ref` (C-9 refinement, above), `Finding.author` added to `required`, `Rule.schema_tag` added to `required`.
- All 20 defects (D8-01…D8-20): 19 RESOLVED, 1 PARTIAL (D8-20 — deferred as registered questions Q3-015/Q3-016).
