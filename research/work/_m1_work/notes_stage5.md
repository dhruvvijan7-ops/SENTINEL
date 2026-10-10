# Stage 5 "Dynamic rule engine" — implementation notes for M1/M2

Source read **in full**: `stage-5-dynamic-rule-engine.md` (1753 lines, Status: Draft for review, Date 2026-10-10).
Companion read in full: `rule_schema.json` (534 lines, draft 2020-12).
Cross-references verified in-workspace (labelled **[DDL]** = `schema.sql`, **[OAS]** = `openapi.yaml`, **[S6]** = `stage-6-platform-storage-jobs-api-testing-release.md`). Anything marked **not specified** is absent from the Stage-5 spec; do not invent it.

Line numbers below are Stage-5 file lines.

---

## 0. M1 bottom line — a detect run with ZERO rules

- **Invariant (§1.10 #1, line 91):** "Empty rule pack ⇒ exactly zero findings on any input (Stage-1 MVP-2; CI test, §10.1). Engine code contains no detection constants." Repeated as reject-condition R1 (line 14) and **D5-014** (line 1529): "the engine with zero rules emits exactly zero findings on the golden corpus; no detection constants in engine code; all detections ship as data. CI-enforced (R1 reject condition)."
- **§10.1 CI test (line 617):** "boot the engine with an empty rule store against the golden corpus → **exactly 0 findings**, and assert the codebase contains no `sigma`/`ioc`/`fim`/`sca`/`statistical`/`artifact` rule documents outside `fixtures/` and `packs/` (a grep-based tripwire + a pack-free integration test)." §10.6 gate: "Empty-pack invariant (R1) — golden corpus run with empty store emits ≠ 0 findings" blocks merge.
- **Run status:** §4.3 (line 320) `job status ∈ {COMPLETED, COMPLETED_WITH_WARNINGS, FAILED}` (uppercase — this is the only status enum Stage 5 defines). A zero-rule run has **no** warning sources (all cold-start/cost codes are per-rule outcomes, §4.8/§3.1), so it finishes `COMPLETED` — this implication is **INFERRED**, Stage 5 never states the zero-rule status in words. The lowercase status `completed` is **[DDL]** `detection_runs.status CHECK (status IN ('queued','running','completed','completed_with_warnings','failed','cancelled'))` (schema.sql:336-337) = **[OAS]** openapi.yaml:1109 enum — a different artifact, same concept.
- **`rule_run` is one row PER RULE PER RUN, not per run.** Stage-5 §4.3 (line 323): per-rule accounting written to `rule_run(rule_id, job_id, outcome, findings, processed_events, rejected_events, max_group_size, max_window_ms, sql_ms, native_ms)`; §1.10 #4 (line 94): "Every rule is accounted for **per job**: loaded-and-ran, skipped-with-reason, or rejected-with-reason". With zero rules there are zero rules to account for ⇒ **`rule_run` empty**. **[DDL]** confirms: `PRIMARY KEY (run_id, rule_id)` (schema.sql:361).
- **M1 exit criteria are NOT stated in Stage 5.** They live in **[S6]** §9 (line 376): M1 "Skeleton + empty-pack run … ① e2e: upload 1 MiB EVTX → events rows > 0, `rule_run` empty, run status `completed`"; **[S6]** D6-015: "M1 = empty rule pack; M2 = first real vertical slice (EVTX/Sysmon + Sigma + evidence + timeline)".
- **Findings:** zero rows for zero rules (invariant). No `findings` insert should occur; no `detection_path` value is ever chosen (nothing fires).
- **Cold-start codes:** none — every code in §4.8 is attached to a rule outcome; zero rules ⇒ zero codes, job stays `COMPLETED` (never `COMPLETED_WITH_WARNINGS`).
- **Canary (§10.5, line 646):** one synthetic `kind: sigma` `canary: true` rule **per pack**; "a job with zero canary findings is flagged `PIPELINE_SILENT`" (PROPOSED warning). With an empty store there is **no pack and no canary rule**; behaviour of `PIPELINE_SILENT` for pack-free runs: **not specified**. D5-014 consequence: "an empty install is legitimately quiet; the canary rule is the pipeline liveness check."
- **What M1 must still do with zero rules:** run the L0–L1 gates vacuously (nothing to validate), write the `detection_runs` row with terminal status, write **no** `rule_run` rows, write **no** `findings` rows, pass the §10.1 empty-pack CI test + grep tripwire, and never contain detection literals (only budgets/limits, the reason-code enum, and schema/fixture paths are allowed literals in code — §10.1 line 616).

---

## 1. §1 Rule format

### 1.1 Document schema `sentinel-rule/v1`, storage (lines 37-39)
- **Additive-only guarantee:** every Stage-1 §6.2 field keeps name/type/meaning: `schema, id, source, source_id, source_ref, source_spec, license, author, title, description, status, level_original, severity, logsource, detection, correlation, enabled, provenance, compile`.
- **Stage 5 adds:** `kind, name, fields, falsepositives, references, date, modified, scope, ioc, fim, sca, statistical, when, emit, rationale, governance` and extends `compile`/`provenance`.
- **Storage split (D5-001):** `rules` table = normalized document (schema-validated, `additionalProperties: false`); verbatim upstream text in `rule_source(rule_id, text, sha256, imported_at)` referenced by `provenance.rule_source_sha256`. Unknown upstream attributes live in `rule_source`, never silently dropped; spec-known-but-unsupported attributes get an explicit reason code (§3.1).

### 1.2 The 7 kinds (§1.1 table, lines 27-35)
| `kind` | family | input |
|---|---|---|
| `sigma` | Sigma detection rules (spec 2.1.0) | `canonical-event/v1` |
| `correlation` | Sigma correlation rules (7 types) over matched event sets | windows over `canonical-event/v1` |
| `ioc` | watchlist membership from signed packs | `canonical-event/v1` + `ioc_entry` |
| `fim` | file-integrity predicates | `canonical-event/v1` (+ `fim_baseline`) |
| `sca` | configuration-assessment predicates | `canonical-event/v1` (`config_check`) |
| `statistical` | declarative baselines (rate / rare value / proportion) | `canonical-event/v1` + `rule_baseline` |
| `artifact` | Stage-3 fact→finding rules | `artifact_fact` → emits `artifact_finding` |

### 1.3 Status / lifecycle vocabularies (four distinct axes — do not conflate)
1. **Rule `status` (lifecycle metadata):** schema enum `["stable","test","experimental","deprecated","unsupported"]` — "verbatim upstream status for imported rules (never rewritten)". §3.2: `status` SUPPORTED, "verbatim, never rewritten".
2. **Feature support status (§3.1):** `SUPPORTED` (implemented on **both** SQL + native, conformance fixtures) | `SUPPORTED_LATER` (shipped after MVP/behind flag; "never silently enabled" → import `OK_PARTIAL` + flag) | `NOT_SUPPORTED` (`REJECTED` or condition-dropped per row). §3.7 additionally uses `REJECTED` and `NOT_APPLICABLE` as table values.
3. **Import outcome (§2 line 128):** `OK | OK_PARTIAL(reason codes) | REJECTED(reason code)` — Stage-1 §6.3 vocabulary reused for every kind; per-pack counts surfaced, "never a silent drop".
4. **Per-rule job outcome (§4.3 line 319):** `OK | OK_PARTIAL(codes) | REJECTED(codes) | QUARANTINED(codes)`. **[DDL]** `rule_run.outcome CHECK (outcome IN ('ok','ok_partial','rejected','skipped','error'))` — note DDL has `skipped`/`error` but **no** `quarantined`; mapping of `QUARANTINED`→DDL value: **not specified** (conflict, flag it).

### 1.4 Severity / level (§1.10 #5, schema)
- `severity` ∈ `LOW | MEDIUM | HIGH` (3-level product axis, Stage-1 §6.4).
- `level_original` ∈ `informational|low|medium|high|critical` (upstream 5-level, verbatim, never collapsed).
- `events.classification` (public/internal/restricted) is the third, separate axis. "Three classification axes stay separate … ≠" — violation = defect.
- Schema mapping note: `informational|low->LOW, medium->MEDIUM, high|critical->HIGH`.

### 1.5 `scope` (§3.2 line 181)
- `scope` = SUPPORTED_LATER: **stored, not evaluated**; deployment gating deferred to Stage-6 → **Q5-009**. Shape: array of strings (sigma-spec 4.15, e.g. `server`); schema `properties.scope: {type: array, items: {type: string}}`.

### 1.6 Empty rule pack — meaning
A rule store with zero documents. Consequences: exactly zero findings on any input (§1.10 #1 / D5-014), no detection constants in code (§10.1), CI gates in §10.6 apply vacuously, an empty install "is legitimately quiet" (D5-014). Storage-wise an empty pack is simply zero rows in `rules` (and zero packs); Stage 5 defines no special "empty pack" document.

### 1.7 Other §1 facts M1 needs
- §1.2: Sigma fields translated **once at import** through Stage-2 `sigma_field_mapping_pipelines.yaml` (D2-014) — the only aliasing layer. Operators: `contains|startswith|endswith|in|eq|neq|exists|lt|lte|gt|gte|re|cidr|all`. `EventID` never a stored predicate field — lives at `source.event_id`, mapping recorded in `compile.prefilter`.
- §1.3 correlation stored per `$defs/correlation`: `type` (7 values), `rules` (ids **or** unique names, name→id index built at load), optional `aliases`, mandatory `group-by` (ANDed), mandatory `timespan` (`^\d+[smhd]$`), `condition` (`gt|gte|lt|lte|eq|neq`, ranges = two ANDed keys, metric types require `condition.field`), optional `generate`. Cycles ⇒ load error `CORRELATION_CYCLE`.
- §1.9 value conventions: `''` matches present-but-empty string; `null` matches `{$state:"null"}`, never mixed into lists (lint rejects); absent key matches only via `exists: false`; lists = OR (`|all` → AND); maps = AND; list of maps = OR; list of strings = whole-event keyword search (SQL `raw::text` or native Aho–Corasick, "never silently skipped").
- §1.10 #7: compiled SQL stored per rule as `compile.sql`, never re-parsed into executable form at runtime.
- §1.10 #8: "Every alert carries `detection_path` (sql|native) plus reason codes when fallback fired".

---

## 2. §2 `rule_schema.json` contract (engine-read fields)

**Top-level `required` (schema line 7):** `["schema", "id", "kind", "source", "title", "severity", "enabled"]`; `additionalProperties: false`.
- `schema` = `const "sentinel-rule/v1"`; `id` pattern `^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$` (UUID for sigma/correlation, `AF-xxx` kept verbatim for artifact).
- `kind` enum = the 7 kinds. `source` enum = `sigma|falco|yara|suricata|wazuh|native`.
- **⚠ exactness note:** `author` property description says "REQUIRED for every rule (DRL 1.1 obligation…)" and §3.2 marks it "**required**", but `author` is **not** in the schema `required` array. Contract tests must decide which wins; the discrepancy is real — report, don't silently pick.

**Conditional requirements (`allOf`, schema lines 102-121):**
- `kind=sigma` ⇒ require `logsource`, `detection`.
- `kind=correlation` ⇒ `correlation`; `kind=ioc` ⇒ `ioc`; `kind=fim` ⇒ `fim`; `kind=sca` ⇒ `sca`; `kind=statistical` ⇒ `statistical`; `kind=artifact` ⇒ `when`, `emit`.
- `kind ∈ {ioc,fim,sca,statistical,artifact}` ⇒ `source` must be `const "native"`.
- `kind ≠ artifact` ⇒ must NOT carry `severity_hint`/`attribution`/`when`/`emit`.

**Kind blocks the engine reads:**
- `detection`: required `condition` (string, minLength 1), `minProperties: 2`, other keys = search identifiers (map = AND, list = OR of maps/strings). Grammar (and/or/not, parens, `1/all of them`, `n of pattern`, condition-as-list) is **lint**-validated, not schema (§2: "grammar-level checks … belong to the lint engine described in §3").
- `correlation`: required `type, rules, group-by, timespan`; `type` enum = `event_count, value_count, temporal, temporal_ordered, value_sum, value_avg, value_percentile`; `timespan` pattern `^\d+[smhd]$`; temporal types must NOT have `condition`; metric types MUST have `condition.field`; `condition` = exactly one comparator (`gt|gte|lt|lte|eq|neq`) or a 2-key range.
- `ioc`: required `packs` (each `pack, version, digest_sha256` `^[a-f0-9]{64}$`, optional `subset`), `match` (`fields`, `kinds` enum `sha256|sha1|md5|ipv4|ipv6|cidr|domain|url|email`, optional `normalize`); optional `confirm_exact`, `on_stale` enum `last_known_good|skip`, `emit_fields`. Indicator **values absent by construction**.
- `fim`: required `paths.include`; optional `exclude`, `operations` (enum `create|modify|delete|rename|attribute_change|audit_log_cleared`), `require` (`hash_changed|size_changed|attributes_any`), `baseline.source` enum `event_old_new|upload_pair|fim_baseline_table`, `match_event_fields`.
- `sca`: required `select.checks` (trailing-`*` wildcards); optional `select.categories`, `assert` (`field, op` enum `eq|neq|in|contains|regex|absent|present`, `regex` ⇒ `regex_engine: re2`), `fail_status_only` (default true), `benchmark` (`framework` enum `own|cis|nist|cis_controls|other`, `control_id`, `note`), `evidence`.
- `statistical`: required `kind, group_by, window, threshold`; `kind` enum `rate|rare_value|proportion`; `window` requires `bucket`+`span` (`^\d+[smhd]$`); `baseline` (`min_observations ≥1`, `warmup_action` enum `suppress|flag`, `estimator` enum `median_mad|ewma|none`, `alpha` ∈ (0,1), `k` > 0); `threshold` requires `op` enum `gt|gte|lt|lte` + `value`, optional `for_buckets ≥1`; optional `scope_filter`.
- `when`/`emit` (artifact): `when` = `all` and/or `any` arrays of predicates; predicate = `fact` + **exactly one** operator key from `exists|in|not_in|eq|neq|gt|gte|lt|lte|contains|regex|in_list_ref`; `emit` requires `artifact_type, finding, confidence, evidence_facts`, `confidence` enum `observed|derived|third_party`.

**`compile` block (engine-owned; schema lines 494-532):** `detection_path` enum `sql|native`; `sql` (string|null — evidence, never re-parsed); `fallback_reason` (string|null); `cost_class` enum `prefilter|standard|heavy|window`; `prefilter[]` items `{column, op: eq|in|range, values[]}`; `compiled_at`; `engine_version`; `unsupported[]` items `{code (required), detail, selector}` — "reason-code list is open (string) but codes are registered in §3.1".

**§2 `$defs` guard table (lines 108-118):** `logsource` exactly 4 keys `category/product/service/definition`, no extras; `detection` ≥1 search-identifier + mandatory condition, `null` never inside mixed lists; `correlation` as above; `ioc` packs pinned by sha256; `fim` include-globs mandatory, closed operation enum; `sca` check selectors, `regex` ⇒ `regex_engine: re2`; `statistical` window patterns, `alpha`∈(0,1), `min_observations` ≥1; `fact_when/fact_predicate/fact_emit` Stage-3 shape, exactly one operator key; `compile` engine-owned.

**Validation levels (§2 lines 120-126), all enforced in CI:**
- **L0 parse** — YAML safe loader, size cap `PROPOSED - TO BENCHMARK: 512 KiB/rule`, alias/anchor expansion cap (billion-laughs), no custom tags.
- **L1 schema** — `rule_schema.json` (draft 2020-12).
- **L2 lint** — §3 support matrix + condition grammar + RE2 subset + cost class + list refs + ATT&CK tag shape.
- **L3 compile** — SQL/native compile; conformance fixtures (sigma-specification `tests/` at `ba9251aa834b`, §12.1).
- **L4 pack** — Ed25519 signature (D4-003), manifest digests, NOTICE completeness.

---

## 3. §4 Streaming Detector Interface (EXACT)

### 4.1 Interface (verbatim, lines 277-291)

```python
class Detector(Protocol):
    kind: ClassVar[Literal["sigma","correlation","ioc","fim","sca","statistical","artifact"]]
    rule_id: UUID
    cost_class: ClassVar[Literal["prefilter","standard","heavy","window"]]
    prepared: list[PrefilterPredicate]          # pushed down to the event stream / SQL
    compile_status: Literal["OK","OK_PARTIAL","REJECTED"]
    unsupported: list[UnsupportedItem]          # reason codes (§3.1)

    def prepare(self, ctx: RuleContext) -> None: ...
    def process(self, ev: CanonicalEvent) -> list[Finding]: ...   # 0..n findings per event
    def finalize(self) -> list[Finding]: ...                     # windows/correlations/baselines
    def cost_report(self) -> CostReport: ...                      # per-rule budget telemetry
    def teardown(self) -> None: ...                               # release window state
```

The methods are **prepare / process / finalize / cost_report / teardown** (there is no `evaluate`). Types `PrefilterPredicate`, `RuleContext`, `CanonicalEvent`, `Finding`, `CostReport`, `UnsupportedItem` are referenced but their definitions are **not specified** in Stage 5.

Semantics (bullets, lines 293-296):
- `RuleContext` carries: resolved rule document, signed `ioc`/`list` material (D5-019), baseline handles, feature flags (SUPPORT_LATER gates), job-level budget handles, clock (`time.utc` only per Stage-2 D2-003), conformance-mode toggle (§12.1).
- `process()` is the only per-event entry point; must be **pure** w.r.t. time (timestamps from event envelope), allocation-bounded, free of I/O.
- `finalize()` is the only place windows/correlations/baselines/SCA rollups produce findings; **idempotent under retry**: "re-running `finalize` on the same collected state yields the same findings, deduplicated by `finding.fingerprint`".
- Detectors are **stateless across jobs**: cross-run state lives in `rule_baseline` / `fim_baseline` / `ioc_pack` tables read at `prepare()`.

### 4.2 Two residence modes (§4.2 table, lines 304-308)
| Mode | predicates run | `process()` | `finalize()` | used when |
|---|---|---|---|---|
| **db-resident (default)** | PostgreSQL over `events` rows filtered by `run_id` + pushed-down `prepared` prefilters | no-op | executes stored `compile.sql`, streams rows back as findings | events already ingested to Postgres (MVP path) |
| **stream** | native (RE2 + stdlib) on event bus | evaluate native plan per event, buffer window-relevant tuples | windows/correlations execute over job's buffered tuples | bus-native workloads, or rule with `cost_class: heavy` + stream-shaped prefilter |

- Streaming reconciliation rule (normative): "SQL detectors query events by `run_id` in `finalize()`; stream detectors buffer into the job workspace during `process()`." Both modes produce `prepared` from the same list (shared pushdown, Stage-1 §5.6.2).
- Kind defaults (line 311): `artifact` stream-shaped by construction; `correlation`/`statistical` window-shaped (`finalize()`); `sigma` may be either; `ioc`/`fim`/`sca` per-event (db-resident by default).
- Same rule document compiles for **both** modes; `detection_path` on every finding names which fired (line 302).

### 4.3 "SQL primary with native fallback" — operational meaning
- Stage-1 **D-004 Option C** makes SQL-over-events the primary engine; a native evaluator exists as fallback + conformance oracle (§4.2 line 302, §4.5, **D5-017**).
- Per-rule `compile.detection_path ∈ {sql, native}` (schema). `sql` = normal primary path; `native` = rule evaluated by native plan (e.g. S-03 has one `re` predicate — "regex check runs in the RE2 pass; SQL still applies the envelope/category prefilter", line 768).
- Fallback firing ⇒ every alert carries `detection_path` + reason code (§1.10 #8; D5-017).
- Timeout path: §5.4 — "SQL timeout in finalize → `SQL_TIMEOUT` → quarantined; native fallback attempted once (§12.2)".
- §12.2 fallback drill: force `detection_path: native` for every rule + 1 ms `statement_timeout` ⇒ job `COMPLETED_WITH_WARNINGS` with per-rule reason codes and **the same findings** as unforced run.
- Which rules choose which mode at compile: cost-class/`re`/keyword heuristics per §3.4/§4.4/§4.6; the exact decision function is lint's output, not a separately specified algorithm. Stage-1 §5.5 (referenced): a rule that fails SQL compile routes to native for the remainder of the job with `detection_path: native` + reason code (Stage-1 line 273) — Stage 5 inherits this via §4.5/D5-017.

### 4.4 SQL-path notes (§4.4, primary)
- Prefilters always index-usable envelope predicates (`time.utc` range, `host.agent_id`, `user.name` presence, `source.event_id`/`category`); Stage-1 §5.6.2 requires a `run_id` + time partial index; **"every compiled detector's SQL begins with the same envelope predicate set"** so the planner hits the index before any JSONB extraction.
- Payload predicates: `payload @> …` containment (GIN if present) or `(payload->>'process'->>'exe') ILIKE …` with ILIKE pattern-escaping (never embed raw user `*`/`?`).
- Keyword search-lists → `raw::text ILIKE ANY(ARRAY[...])`, cost class `heavy`; no other predicate ⇒ prefilter rejects at compile unless event count below configured bound (else `COST_BUDGET_EXCEEDED`, `OK_PARTIAL`).
- Window aggregation → `date_bin(interval, time.utc, origin)` buckets (PostgreSQL 18 §9.9.3), partitioned by group-by columns; `percentile_cont(fraction) WITHIN GROUP` for percentiles.
- **Statement timeouts mandatory on every engine-issued statement** (Stage-4 D4-004 → §4.7 L3). Numeric default: **not specified** in Stage 5 (the drill uses 1 ms; **[S6]** config `detection.statement_timeout_ms` default `60000` "per-rule SQL budget (Stage 5)" — Stage-6 config, not Stage-5 text).
- Compiled SQL **parameterized** (values bound, never string-interpolated) — non-negotiable of D-004 / §1.10 #7.

### 4.5 Native path (§4.5)
- Compile-time value lists (`base64*`, `windash`) materialized as literal sets; regex via `google-re2`; keyword sets via `pyahocorasick` above a threshold, plain sets below (`PROPOSED`: 32 keys).
- Native evaluator = **conformance oracle** for SQL (Stage-1 §5.5): golden corpus (sigma-specification `tests/` + 20 pinned SigmaHQ rules), both paths must emit **identical finding fingerprints**; divergence = defect (§10.6, §12.1).
- Same RE2 subset as SQL-path regex — "one regex engine everywhere is what makes the oracle meaningful".

### 4.6 Cost classes (§4.6, D5-012)
`prefilter` (envelope-only, no cap) | `standard` (≤2 ms/event p95 native, PROPOSED) | `heavy` (≤10 ms/event p95, PROPOSED) | `window` (≤200 000 buffered tuples/job/group `GROUP_CARDINALITY_CAP`; ≤512 MiB workspace). Exceeded → `COST_BUDGET_EXCEEDED`, rule quarantined for job. Lint assigns class; refuses unbounded worst-case (e.g. `re` variable-length repetition with no other predicate/prefilter). Two consecutive trips → quarantine (`REGEX_TIMEOUT_QUARANTINE`/`COST_BUDGET_EXCEEDED`), "never silently".

### 4.7 ReDoS 4 layers (§4.7, D5-004/D5-005) — reject condition R3
- **L1 grammar (import+CI):** `re` must parse against spec restricted flavor (only `.^$*+?{n,m}[]|()`, no backrefs/lookahead) **and** RE2's parser; else `REJECTED(UNSUPPORTED_REGEX_CONSTRUCT)` at lint.
- **L2 translation (compile):** regex never emitted as PostgreSQL `~` on hostile paths; either prefilter narrows rows then RE2 native pass, or engine-authored simple pattern → `ILIKE`/`starts_with()` (`^@`).
- **L3 runtime (run):** `statement_timeout` on every engine SQL; native regex wall-clock deadline per event (`PROPOSED`: 2 ms); timeouts increment cost report.
- **L4 circuit breaker (run):** two consecutive timeouts/quota trips → rule quarantined for the job, job `COMPLETED_WITH_WARNINGS`, reason code persisted; per-tenant quarantine alarm is Stage-6.
- User regex confined to RE2 with deadlines; wildcards never become regex (D5-005 → `ILIKE`/`starts_with` + literal expansion).

### 4.8 Per-rule accounting fields (§4.3 lines 323-324)
`rule_run(rule_id, job_id, outcome, findings, processed_events, rejected_events, max_group_size, max_window_ms, sql_ms, native_ms)` + **C-5-fix**: "`job_id` is the DDL `rule_run.run_id` (same concept — the `detection_runs.run_id` FK; no separate `job_id` column). The DDL also carries `detection_path`, `reason_codes`, `started_at`, `finished_at`, and now `max_window_ms`, `sql_ms`, `native_ms` … the sql-vs-native timing split is load-bearing for the §10.6 shadow-mode reports and Stage-6 risk scoring and must not be dropped."
**[DDL]** full column set (schema.sql:345-362): `run_id uuid FK`, `rule_id uuid`, `outcome` (enum above), `findings int default 0`, `processed_events bigint default 0`, `rejected_events bigint default 0`, `max_group_size int`, `max_window_ms bigint`, `sql_ms bigint`, `native_ms bigint`, `detection_path CHECK IN ('sql','native')`, `reason_codes text[] default '{}'`, `started_at timestamptz default now()`, `finished_at timestamptz`, `PRIMARY KEY (run_id, rule_id)`.

---

## 4b. Run lifecycle: detection_runs / rule_run / findings

### Job lifecycle pseudo-code (§4.3, verbatim lines 315-321)
```
job = RUN → per event: fanout to detectors' process() (or SQL execute at finalize)
          → finalize all window detectors (topological order for correlations-of-correlations)
          → flush findings, persist baselines/fingerprints
          → per-rule accounting: OK | OK_PARTIAL(codes) | REJECTED(codes) | QUARANTINED(codes)
          → job status ∈ {COMPLETED, COMPLETED_WITH_WARNINGS, FAILED}
```
"No detector may exit silently." (line 323)

### detection_runs
Stage 5 never writes a `detection_runs` DDL — **[DDL]** (schema.sql:330-343) is authoritative: `run_id uuid PK default uuidv7()`, `tenant_id`, `workspace_id`, `requested_by`, `scope jsonb default '{}'` (filters: time range, hosts, categories, rule selection), `status` enum `queued|running|completed|completed_with_warnings|failed|cancelled`, `config_hash bytea NOT NULL`, `started_at`, `finished_at`, `summary jsonb`, `created_at`. **[S6]**: `COMPLETED_WITH_WARNINGS` propagates — job handler finishes `succeeded` with `warnings[]`; run rollup becomes `completed_with_warnings`.

### Findings — `sentinel-finding/v1` (§4.1 line 297, verbatim field list)
`{rule_id, rule_name, kind, severity, time, event_ids[], host{agent_id,instance_id,name}, user, detection_path, reason_codes[], payload_excerpt, attck_refs[], falsepositives_note, attestation}` — severity `LOW/MEDIUM/HIGH` only; `detection_path ∈ {sql, native}`.
**Contract layering (C-2-fix, line 298):** `sentinel-finding/v1` is engine-**internal**, not storage/wire. At `flush()` the full object is persisted **verbatim inside `findings.evidence_snapshot`** (JSONB) — so `payload_excerpt`, `attck_refs[]`, `falsepositives_note`, `attestation` live in the snapshot, not dedicated columns. Indexed storage projection = DDL `findings`: `finding_uid, rule_id, rule_name, author, kind, severity, level_original, time_utc, host_hostname, user_name, detection_path, reason_codes, fingerprint, event_uids, …`. API projection = OpenAPI `Finding`. `host{agent_id,instance_id,name}` is the **agent-identity summary on a finding**, distinct from canonical-event `host{hostname,fqdn,ips,os,arch}`; maps to `findings.host_hostname` + agent context in `evidence_snapshot`.
**[DDL]** findings (schema.sql:364-396): + `tenant_id`, `workspace_id`, `run_id`, `author` (DRL 1.1), `evidence_snapshot jsonb NOT NULL` ("immutable freeze; never references raw bytes"), `first_seen/last_seen/occurrence_count`, `triage_state` enum `new|acknowledged|escalated|resolved|false_positive`; `PARTITION BY RANGE (time_utc)`; `PRIMARY KEY (finding_uid, time_utc)`; `UNIQUE (tenant_id, workspace_id, rule_id, fingerprint, time_utc)`.

### Fingerprint
- Stage 5 defines: dedup key `finding.fingerprint` (§4.1 finalize idempotency) and, for correlations (§5.1 line 391): **`fingerprint = rule_id + group_key + window_id + metric_value`**.
- General (non-correlation) fingerprint tuple/hash algorithm: **not specified** in Stage 5. **[DDL]** comment: `fingerprint bytea NOT NULL -- sha256 of stable identity tuple`.
- **D6-013 (not a Stage-5 id — Stage-6):** "Findings unique on `(tenant, workspace, rule_id, fingerprint, time_utc)` (partition key included per PG rule) for idempotent finalize within a run window" (**[S6]** D6-013; schema.sql:391-395 comment: "cross-month duplicates are impossible in practice because finalize() dedups against the run window (D6-013)"). Stage 5's own finalize contract = §4.1 idempotency sentence above.

### evidence_snapshot contents
- Stage-5 C-2-fix: full `sentinel-finding/v1` object persisted verbatim at `flush()`.
- **[S6]** §1.5 adds: rule document version + `rule_source.sha256`, run's `config_hash`, per-event `(event_uid, sha256_of_document)` digests — **not** copies of raw bytes, **not** pointers depending on `raw_objects.state`.
- Related: `rule_baseline(rule_id, group_key, span_start, span_end, metric, n, extras)` written at `finalize()` idempotent upsert keyed by bucket id (§9.3 line 602).

---

## 5. §4.8 Cold-start policy (D5-015; reject condition R4)

Definition: "a detector that needs state the system does not have yet" — "explicit, per subsystem, and **never degrades to a silent pass**".

| Subsystem | state | cold-start behaviour (exact codes) |
|---|---|---|
| `sigma` (per-event) | none | runs immediately, zero warm-up |
| `correlation` | none pre-stored | windows fill from first event; findings require ≥1 group member; `eq` on empty window emits nothing (correct) |
| `statistical` | ≥ `min_observations` buckets in `rule_baseline` | warm-up window (`PROPOSED`: 7 days of buckets or `min_observations`, whichever first). `warmup_action: suppress` (default) = no findings until baseline valid, rule accounted with **`BASELINE_WARMUP`**, job `COMPLETED_WITH_WARNINGS`. `warmup_action: flag` = LOW findings carrying `baseline.warmup=true` + the code |
| `ioc` | signed packs present | **`IOC_PACK_MISSING`** → rules of that pack `OK_PARTIAL`, job completes; stale pack (older than `PROPOSED - TO BENCHMARK`: 7 days) adds **`IOC_PACK_STALE`** and "LOW findings are suppressed, HIGH+ still fire" (⚠ §6.4 line 488 says "MEDIUM+ still fire" — internal inconsistency, flag) |
| `fim` (baseline modes) | `fim_baseline` rows or upload-pair | **`SNAPSHOT_MISSING`** → rules with `baseline.source: upload_pair/fim_baseline_table` inert for job with code; `baseline.source: event_old_new` runs normally |
| `sca` | none | runs immediately; check whose plugin hasn't reported → no events |
| `artifact` | none | runs immediately; replay of stored facts is first-class |
| compile cache | per-rule `compile` rows | absent → compile at job start (startup latency budget §4.6); failed compile cached as `REJECTED` with codes; invalidation on rule/source digest change (D4-003) |

Universal rule (line 378): "**warm-up/cold-start never fabricates a 'pass'** … all surface as `COMPLETED_WITH_WARNINGS` with per-rule codes, never as zero-finding silence."

**Registered cold-start codes (§3.1 line 161):** `BASELINE_WARMUP / BASELINE_MISSING / IOC_PACK_MISSING / IOC_PACK_STALE / SNAPSHOT_MISSING` ("cold-start outcomes (§4.8)"). ⚠ **`BASELINE_MISSING` appears ONLY in that registration row** — no §4.8/§9 body text ever emits it; emission condition **not specified**.
Other cold-start-adjacent codes: `NO_EVENTS_FROM_PLUGIN` (§8.3 — SCA job with zero `config_check` events but enabled SCA rules "surfaces `NO_EVENTS_FROM_PLUGIN` as a warning — never silence"), `UNSUPPORTED_COMBINATION` (§7.2/§7.4, FIM hash requirement with no old/new pair → `OK_PARTIAL`), `MEMBER_RULE_INACTIVE` / `MEMBER_RULE_SUPPRESSED` (§5.4), `PIPELINE_SILENT` (§10.5 canary).

**Empty-pack run:** zero rules ⇒ zero cold-start codes, zero warnings ⇒ `COMPLETED` (see §0). Cold-start is *per-rule*; there is no run-level cold-start code in Stage 5.

---

## 6. §10 Governance / safety (M1 enforcement subset)

- **§10.1 (R1, D5-014):** zero detection constants in engine code — allowed literals: budgets/limits (§4.6), reason-code enum, schema/fixture paths. Empty-store golden-corpus run = exactly 0 findings; grep tripwire: no rule documents outside `fixtures/` and `packs/`; pack-free integration test. AF rules imported as ordinary rules, never special-cased in code.
- **§10.2 packs/signing:** manifest `sentinel-pack/v1` = `{pack_id, version, created_utc, rules_digest, entries: [{rule_id, sha256}], attestation: {sig, key_id, sig_alg: ed25519}}`. **Load order: signature → digests → schema → lint → compile.** Any failure keeps **last-known-good** pack (Stage-4 T-06) + finding-severity alarm. **Deferred:** key rotation, revocation list, offline verification = "Stage-6/ops material" (key-id indirection reserved now as schema field, §2 L4). Signing is Ed25519 per Stage-4 D4-003 (not re-specified here).
- **§10.4 untrusted content (D5-018):** safe YAML loader only (no custom tags/object construction); doc size cap `PROPOSED: 512 KiB` + anchor-expansion cap; no template/placeholder expansion (`expand` rejected); no rule-triggered I/O (lists resolved at load, content-addressed, `PROPOSED: 10 MiB` per list — D5-019); expression caps `PROPOSED`: depth 32, identifiers 64, OR-arms 256; compiled SQL parameterized; native plan values are data.
- **§10.5:** `governance.mode: shadow` (findings tagged `shadow: true`, stored/visible, never page/incident; promotion to `active` needs second approver + audit); kill switch `rules.enabled=false` global/per rule/pack, disable as fast as enable, audited; audit log on pack load/signature failure/quarantine/shadow promotion/baseline reset/kill-switch flip (actor, UTC timestamp, pack digest, reason); canary rule per pack (`canary: true`), `PIPELINE_SILENT` PROPOSED warning.
- **§10.6 CI gates:** schema L0-L1; **canonical-path cross-validation (D8-14)** — every `detection` predicate `field` (and `fields[]` entry) must resolve to a property path in `canonical_event_v1.schema.json`; support-matrix lint; ReDoS lint (§4.7 L1); empty-pack invariant (R1); native/SQL conformance (fingerprint divergence); licence tripwire (DRL attribution path, ATT&CK copyright line, NOTICE); CIS text tripwire ("rejects any rule string longer than 64 chars that matches known CIS phrasing patterns (heuristic, `PROPOSED`)").
- **Rejection reason codes (§3.1 registered set):** `UNSUPPORTED_MODIFIER`, `UNSUPPORTED_CONDITION_FORM`, `UNSUPPORTED_CORRELATION_TYPE`, `UNSUPPORTED_PLACEHOLDER`, `UNSUPPORTED_TAXONOMY`, `UNSUPPORTED_AGGREGATION`, `UNSUPPORTED_REGEX_CONSTRUCT`, `UNSUPPORTED_ENCODING_TARGET`, `UNMAPPED_FIELD`, `SEMANTICS_REDUCED`, `NO_PIPELINE_MATCH`, `EMPTY_SELECTION`, `CORRELATION_CYCLE`, `LIST_REF_UNRESOLVED`, `LIST_REF_TOO_LARGE`, `COST_BUDGET_EXCEEDED`, `REGEX_TIMEOUT_QUARANTINE`, `SQL_TIMEOUT`, `GROUP_CARDINALITY_CAP`, `WINDOW_STATE_CAP`, `BASELINE_WARMUP`, `BASELINE_MISSING`, `IOC_PACK_MISSING`, `IOC_PACK_STALE`, `SNAPSHOT_MISSING`. Additional codes used elsewhere in the doc: `UNSUPPORTED_RULE_ATTRIBUTE` (§3.7), `UNSUPPORTED_TIMEZONE` (§3.4), `UNSUPPORTED_COMBINATION` (§7), `MEMBER_RULE_INACTIVE`, `MEMBER_RULE_SUPPRESSED` (§5.4), `NO_EVENTS_FROM_PLUGIN` (§8.3), `PIPELINE_SILENT` (§10.5).
- **M1 with zero rules must enforce:** §10.1 empty-pack CI test + grep tripwire; no detection literals in code; loader accepts zero-rule store without error (all gates vacuous); no signing step required when no pack is loaded (**not specified** otherwise — §10.2 pipeline applies "when a pack is loaded"); kill-switch/shadow machinery can exist but has no rows to act on.

---

## 7. §11 Worked examples (25 documents, contract-test targets)

All are stored-form `sentinel-rule/v1`; "CI validates all examples against `rule_schema.json` (§10.6, §12.3)". **VERIFIED (§15):** all 25 parse + validate under strict draft-2020-12 (jsonschema 4.26, `additionalProperties` enforced); validator retained at `_stage5_work/validate_examples.py` — "seed of the CI gate in 12.3".

| Section | Count | IDs | Notes |
|---|---|---|---|
| §11.1 `kind: sigma` | 5 | S-01…S-05 (UUIDs `7c1a9e40-…`, `3d5e7f80-…`, `9b8c7d6e-…`, `1e2f3a4b-…`, `0f9e8d7c-…`) | S-01 `detection_path: sql`, `cost_class: standard`, prefilter `source.channel in [security, sysmon]`; S-02 sql/prefilter, prefilter `source.event_id in [13,14]`; S-03 `detection_path: native` (has `\|re` + `\|cidr`), standard, prefilter `event.category eq [network]`; S-04 sql, `cost_class: heavy`; S-05 keyword list form, native, heavy |
| §11.2 `kind: correlation` | 4 | C-01…C-04 | C-01 `event_count`, `group-by: [authentication.account_name, host.agent_id]`, `timespan: 10m`, `condition: {gt: 5}`, `generate: true`; C-02 `temporal_ordered` (no condition), 30m; C-03 `value_count` `condition: {field: authentication.account_name, gte: 10}`, 15m; C-04 `value_sum` `condition: {field: network.bytes_sent, gt: 50000000}`, 1h. All `compile.cost_class: window` |
| §11.3 `kind: ioc` | 2 | I-01, I-02 | pack `acme-intel` `2026.10.0` `digest_sha256: "6b8e1f0c…c3d4"`; I-01 sha256 fields, `normalize: [hash_lower, trim]`, `subset: botnet-c2`; I-02 `kinds: [domain, ipv4, cidr]`, `normalize: [lowercase, strip_trailing_dot, ip_canonical]`; both `confirm_exact: true`, `on_stale: last_known_good`, `detection_path: sql`, prefilter class |
| §11.4 `kind: fim` | 2 | F-01, F-02 | F-01 `operations: [audit_log_cleared]`, `baseline.source: event_old_new`, prefilter `source.event_id eq [1102]`; F-02 `upload_pair` + `require.hash_changed: true` — description pins `SNAPSHOT_MISSING` + inert + `COMPLETED_WITH_WARNINGS` (§4.8) |
| §11.5 `kind: sca` | 2 | SC-01, SC-02 | `select.checks` wildcards, `fail_status_only: true`, `assert.op: neq`/`contains`, `benchmark.framework: cis`, `control_id: "18.9.1"` |
| §11.6 `kind: statistical` | 2 | ST-01, ST-02 | ST-01 `rate`, `warmup_action: suppress`, `estimator: median_mad`, `k: 6`, `for_buckets: 3`; ST-02 `rare_value`, `warmup_action: flag`, `estimator: none` |
| §11.7 `kind: artifact` | 8 | A-01…A-08 = AF-001…AF-008 (ids verbatim, non-UUID) | AF-001…AF-005 reproduce Stage-3 §12.4 keys verbatim; AF-006…AF-008 new (composite `all` predicates, `in_list_ref: lists/exec_apis.yaml`, `confidence: observed|derived`, `severity_hint` at rule level allowed for artifact only) |

Contract-test requirements: strict validator, `additionalProperties` everywhere, `if/then` evaluated (§12.3); negative corpus (null-in-list, unknown attributes, temporal+condition, missing group-by) must fail with expected error path (§12.3/T-A).

---

## 8. §12 Acceptance / verification plan

- **T-A schema:** `rule_schema.json` + the 25 §11 examples validate; negative corpus fails with expected error path.
- **T-B spec fixtures:** `_stage1_work/sigma-specification/tests/` @ `ba9251aa834b` (rules + correlation schema tests, conditions, modifiers) — L2 lint accepts exactly spec-valid cases; tokenizer matches pySigma's on shared fixtures.
- **T-C dual-path oracle (M2/M3 need):** golden corpus = **20 pinned SigmaHQ rules covering each §3.4 SUPPORTED modifier + the 7 correlation fixtures (§5.5)**; **SQL path and native path emit identical finding fingerprints** on replayed synthetic events; any divergence fails CI (§10.6). Correlation fixtures: `_stage1_work/sigma-specification/tests/schema/correlation/` — `event_count.yml`, `event_count_ecs.yml`, `value_count.yml`, `temporal.yml`, `temporal_ecs.yml`, `temporal_ordered.yml`, `value_sum.yml`, `value_avg.yml`, `value_percentile.yml` (§5.5), replayed through native path at CI; expectations from fixture `tests/cases` where present else hand-authored.
- **T-D Stage-1 PoC hooks:** T2 compile-rate ≥95% on 4063 active rules (PROPOSED); T3 streaming throughput; T4 baseline-cold-start latency (§4.8 windows).
- **T-E governance:** signed pack fixtures, expired-key fixture, CIS-phrasing canary strings, DRL/ATT&CK export templates — signature failures keep last-known-good; tripwires fire; alerts carry author + MITRE copyright line.
- **§12.2 fallback drill** (see §3.3 above). **§12.3** example validation = merge blocker. **§12.4:** no throughput/latency/compile-rate/TPR/FPR claims — all budgets PROPOSED - TO BENCHMARK.

---

## 9. DECISIONS / OPEN QUESTIONS / NOT_VERIFIED (compact)

### DECISIONS (§13, D5-001…D5-020 — 20 items, status `accepted`)
- **D5-001** One stored schema `sentinel-rule/v1` with 7-kind discriminator; upstream verbatim text in `rule_source`; unknown attrs → reason codes.
- **D5-002** Detector interface = prepare/process/finalize (+cost_report, teardown), two residence modes (db-resident default SQL-at-finalize; stream native+buffered); both compile from same doc; findings carry `detection_path`.
- **D5-003** Normative support matrix + registered reason codes; every import/job accounts for every rule; no silent semantic change.
- **D5-004** User regex = RE2-class only; 4-layer ReDoS defense; two consecutive trips quarantine for the job.
- **D5-005** Wildcards compile to ILIKE/starts_with + literal expansion, never regex.
- **D5-006** Default case-insensitive (ILIKE/casefold); `|cased` flips binary; encodings/case are compile-time value expansions.
- **D5-007** IOC values never in rules; signed packs + Bloom prefilter + exact confirm; staleness/missing → reason codes; last-known-good.
- **D5-008** FIM event-driven only + uploaded baselines; live-host FIM out of scope; missing baseline = `SNAPSHOT_MISSING` + inert + warnings.
- **D5-009** SCA = `config_check` events + own checks; control IDs cited factually, benchmark wording never shipped; `unknown` ≠ pass.
- **D5-010** Statistical = declarative (median+MAD/EWMA/raw), no ML; warm-up explicit and always accounted via `BASELINE_WARMUP`.
- **D5-011** Correlations over finding streams; tumbling `date_bin` windows at MVP (sliding SUPPORTED_LATER + `OK_PARTIAL`); cardinality/state hard-capped; member-rule state always reported.
- **D5-012** Cost classes assigned at lint, enforced at run; breaches quarantine + `COMPLETED_WITH_WARNINGS`; budgets PROPOSED.
- **D5-013** Governance = Ed25519 packs + DRL author on every alert + MITRE line in exports + NOTICE + shadow mode two-person promotion + audited kill switch + per-pack canary (`PIPELINE_SILENT`).
- **D5-014** Empty-pack invariant: zero rules ⇒ exactly zero findings on golden corpus; no detection constants; CI-enforced (R1).
- **D5-015** Cold-start policy per subsystem: never fabricate a pass; always reason code + `COMPLETED_WITH_WARNINGS`.
- **D5-016** Unmapped fields: drop condition + `UNMAPPED_FIELD` (`OK_PARTIAL`); semantic OR-arm loss also `SEMANTICS_REDUCED`; never silent.
- **D5-017** Native evaluator = streaming path + SQL conformance oracle; findings carry `detection_path` + fallback reason code; forced-fallback drill in §12.2.
- **D5-018** Rule/pack/baseline content untrusted: safe YAML, size/expansion caps, no templates/expand, no rule I/O, parameterized SQL, lint expression caps.
- **D5-019** `in_list_ref` lists resolved at load from signed pack, content-addressed, `PROPOSED 10 MiB` cap, never re-read at match time.
- **D5-020** Findings carry rule_id, kind, severity (3-level), `detection_path`, `reason_codes[]`, `related_finding_ids` (capped), shadow flag, DRL author; severity floors applied at emission; correlations only see post-floor findings (`MEMBER_RULE_SUPPRESSED`).

### OPEN QUESTIONS (§14, Q5-001…Q5-009 — 9 items present; §15 claims the YAML block parses "20/8/12", i.e. 8 — discrepancy, report it)
- **Q5-001** Promote SUPPORTED_LATER encodings (utf16/wide/base64) via byte-bearing declaration, or keep rejected?
- **Q5-002** Condition-as-list (0 corpus usage): keep SUPPORTED or demote?
- **Q5-003** Tumbling windows acceptable at MVP, or sliding before any correlation pack ships?
- **Q5-004** `UNMAPPED_FIELD` stay `OK_PARTIAL` or become `REJECTED` per-pack for compliance packs?
- **Q5-005** Bloom sizing + 7d staleness under real feed sizes (5M-entry cap)?
- **Q5-006** Canary `PIPELINE_SILENT` as warning vs failure for compliance?
- **Q5-007** pySigma 2.0 LGPL notice-availability acceptable for distribution, or reimplement oracle?
- **Q5-008** Which cost budgets (2/10 ms/event, 200k tuples) survive T3?
- **Q5-009** `scope` vocabulary/matching semantics Stage-6 needs (stored, not evaluated)?

### NOT_VERIFIED (§15, 12 items)
1. pySigma v2.0.0 release date/Python bounds/LGPL/RE2-default release-note wording (local pin `50708bae` verified; wording not re-read).
2. google-re2 1.1.20251105 wheel matrix + BSD-3 classifier (wheels not install-tested on target build).
3. pyahocorasick 2.3.1 wheel matrix (win_amd64 cp310-cp314 only; ARM64 fallback untested).
4. SigmaHQ/sigma release r2026-07-01 latest + published SHA-256 digests (digests not recomputed).
5. CIS Benchmark licensing summary (2028-08 page; terms not re-fetched 2026-10-10).
6. MITRE ATT&CK v19.2 current (licence text WAS re-read).
7. Corpus modifier/status counts (drift as corpus moves; scan params recorded, not frozen).
8. PostgreSQL 18 date_bin/percentile_cont/starts_with/ARE facts (docs read, not re-validated on live server).
9. Stage-2 canonical payload field names in examples (S-01 corrected `process.parent_image`→`process.parent.exe`; D8-14 CI gate added).
10. The 25 §11 examples validate — **VERIFIED 2026-10-10** (jsonschema 4.26; script `_stage5_work/validate_examples.py`); YAML blocks parse (20/8/12 items).
11. Bloom FPP ~1% / k=6 sizing — PROPOSED arithmetic only (Q5-005).
12. sigma-specification tag v2.1.0 vs HEAD `ba9251aa834b` spec docs identical (earlier diff, not re-done).

---

## 10. Explicit gaps (Stage-5 "not specified") — do not invent

- Numeric `statement_timeout` default (only "mandatory"; drill = 1 ms; 60000 ms is a Stage-6 config default).
- General finding fingerprint hash/tuple (only the correlation formula + DDL "sha256 of stable identity tuple").
- `D6-013` unique key itself is Stage-6/`schema.sql`, not a Stage-5 id.
- Lowercase `detection_runs` status enum is DDL/OpenAPI, not Stage-5 (Stage-5 uses uppercase job enum {COMPLETED, COMPLETED_WITH_WARNINGS, FAILED}).
- Zero-rule run status stated explicitly (only inferable as `COMPLETED`).
- `PIPELINE_SILENT` behaviour when no pack/canary exists (empty store).
- Mapping of Stage-5 `QUARANTINED` outcome to DDL `rule_run.outcome` enum (no `quarantined` value in DDL).
- `BASELINE_MISSING` emission point (registered only).
- Stale-IOC suppression floor: §4.8 says "HIGH+ still fire", §6.4 says "MEDIUM+ still fire" — conflict.
- `author` schema-required vs description-required mismatch (see §2 above).
- Stage-5 `rules` table DDL (only the concept "rules table stores the normalized document"; actual DDL not in Stage 5).
- Q5-count: doc body has 9, §15 validation claim says 8.
