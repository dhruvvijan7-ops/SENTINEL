# Stage 5: Dynamic Rule Engine

**Status:** Draft for review
**Date:** 2026-10-10
**Inherits:** Stage 1 (RED-001/D-004, §5.5–§5.8, §6.1–§6.5, §2.2–§2.3, MVP-2/MVP-6, D-007), Stage 2 (`canonical-event/v1`, D2-014 `sigma_field_mapping_pipelines.yaml`, SEC-A/SEC-B source tables, 26 `event.category` values), Stage 3 (D3-001…D3-037, §12 `artifact_finding_rules.yaml` AF-001…AF-005, artifact fact namespaces, ExternalProcessRunner D3-024), Stage 4 (D4-003 rule-pack signing, D4-004 non-backtracking regex, threats T-04 ReDoS / T-06 supply chain / T-12 rule content)
**Companion file:** [`rule_schema.json`](rule_schema.json) — JSON Schema draft 2020-12 for stored rule documents (`sentinel-rule/v1`)

**Claim labels (house rule, Stage-1 preamble):** `VERIFIED` = read from a named primary source this stage (local pin or URL+date); `INFERRED` = derived reasoning over verified facts; `UNVERIFIED` = believed but unchecked. Every quantitative threshold in this document is **PROPOSED - TO BENCHMARK** until the Stage-1 §5.7 PoC produces MEASURED numbers. Licence rows repeat Stage-1 §2 classifications with this stage's additions; nothing here overrides Stage-1 legal gates.

**Non-negotiables this stage must satisfy (reject conditions from the brief):**

| # | Reject condition | Where satisfied |
|---|---|---|
| R1 | No hardcoded detections anywhere in engine code | §10.1 (empty-pack invariant + CI test), D5-014 |
| R2 | No silent semantic change to Sigma or to upstream rules | §3.1 status vocabulary + reason codes; §1.10 invariants; every deviation is `OK_PARTIAL` or `REJECTED` with a code |
| R3 | A stated ReDoS strategy for untrusted rule content | §4.7 (four layers: grammar, SQL, runtime budget, circuit breaker), D5-004/D5-005 |
| R4 | A stated cold-start policy | §4.8 (per subsystem: windows, baselines, IOC packs, FIM baselines, SCA snapshots, compile cache), D5-015 |

---

## 1. Rule Format Specification

### 1.1 One document schema, seven kinds (additive extension of Stage-1 §6.2)

Stage 1 defined the canonical rule document (§6.2) for Sigma-shaped detections and left `correlation` as an optional block. Stage 3 defined a second, smaller rule shape for artifact fact→finding rules (§12.4) and asked (Q3-018) whether to build it or unify. Stage 5 resolves that question: **one stored schema, seven kinds, one governance pipeline** (D5-001).

| `kind` | Detector family | Input | Section |
|---|---|---|---|
| `sigma` | Sigma detection rules (spec 2.1.0) evaluated over canonical events | `canonical-event/v1` | §3, §4 |
| `correlation` | Sigma correlation rules (7 types) over matched event sets | windows over `canonical-event/v1` | §5 |
| `ioc` | Watchlist membership (hashes, IPs, domains, URLs) from signed packs | `canonical-event/v1` + `ioc_entry` | §6 |
| `fim` | File-integrity predicates over `fim`/`file` events + optional uploaded baselines | `canonical-event/v1` (+ `fim_baseline`) | §7 |
| `sca` | Configuration-assessment predicates over `config_check` events | `canonical-event/v1` | §8 |
| `statistical` | Declarative baselines (rate / rare value / proportion) | `canonical-event/v1` + `rule_baseline` | §9 |
| `artifact` | Stage-3 fact→finding rules over `artifact_fact`, emitting `artifact_finding` events | `artifact_fact` | §1.8, §11.7 |

Additive-only guarantee (no silent change): every Stage-1 §6.2 field keeps its name, type and meaning (`schema`, `id`, `source`, `source_id`, `source_ref`, `source_spec`, `license`, `author`, `title`, `description`, `status`, `level_original`, `severity`, `logsource`, `detection`, `correlation`, `enabled`, `provenance`, `compile`). Stage 5 **adds**: `kind`, `name`, `fields`, `falsepositives`, `references`, `date`, `modified`, `scope`, `ioc`, `fim`, `sca`, `statistical`, `when`, `emit`, `rationale`, `governance`, and extends `compile` and `provenance` (see `rule_schema.json`). The Stage-1 example rule (normalized `proc_creation_win_7zip_exfil_dmp_files.yml`) remains schema-valid with `kind: sigma` added.

**Storage split (D5-001):** the `rules` table stores the normalized document (schema-validated, `additionalProperties: false`); the verbatim upstream/imported text is stored separately in `rule_source(rule_id, text, sha256, imported_at)` and referenced by `provenance.rule_source_sha256`. Unknown upstream attributes are never silently dropped: they live in `rule_source`, and when they are spec-known-but-unsupported (`taxonomy`, legacy `aggregation`, `expand` placeholders…) the import result carries an explicit reason code (§3.1).

### 1.2 `kind: sigma` — normalized detection form

The `detection` block keeps Sigma's structure (search-identifiers + `condition`) but its values are already pipeline-resolved (Stage-2 D2-014):

* Sigma field names are translated **once**, at import, through `sigma_field_mapping_pipelines.yaml` — the only aliasing layer in the product (Stage-1 §6.1 rule of the house; Stage-2 §3 normative purpose: *"the field-name translation a rule-translation layer must apply before a Sigma condition can be evaluated against canonical events"*).
* Every mapped field in a stored rule is a **canonical path** from `canonical_event_v1.schema.json` (`process.exe`, `process.command_line`, `registry.path`, `network.dst_ip`, `dns.query_name`, `powershell.script_block_text`, `user.name`, `service.image_path`, …).
* Modifiers are resolved to canonical operators where possible (`op: contains|startswith|endswith|in|eq|neq|exists|lt|lte|gt|gte|re|cidr|all`) — Stage-1 §6.2 already showed this normalized shape; the full modifier→operator table is §3.4.
* Unmapped Sigma fields follow Stage-2 §3 exactly: *"Absent target = no canonical equivalent; such Sigma fields must be matched against `raw`/`unmapped` by a documented fallback or the rule is translated with that condition dropped and flagged."* Sentinel's documented fallback (D5-016): a dropped condition emits `compile.unsupported[] = {code: UNMAPPED_FIELD, selector, detail}` and downgrades the import outcome to `OK_PARTIAL`; if **all** predicates of a search-identifier are dropped, the identifier is removed and the condition is re-linted (removing an OR-arm changes semantics → `OK_PARTIAL` + `SEMANTICS_REDUCED` code; removing an AND-arm is safe but still flagged).

`EventID` is never a stored predicate field: the event id lives in the envelope as `source.event_id` (Stage-2 §1) and drives pipeline selection, not detection predicates. Sigma rules that key on `EventID` are translated to `source.event_id` predicates via the pipeline layer, with the mapping recorded in the rule's `compile.prefilter` so the SQL path can use the index.

### 1.3 `kind: correlation` — Sigma correlation rules as first-class documents

Stored exactly per `rule_schema.json` `$defs/correlation`: `type` (7 values), `rules` (ids **or** unique names — a name→id index is built at load, mandatory per spec: *"the tool must be able to manage the name-to-id translation automatically"*), optional `aliases`, mandatory `group-by` (ANDed), mandatory `timespan` (`^\d+[smhd]$`, e.g. `90m` for 1h30), `condition` (`gt|gte|lt|lte|eq|neq`, ranges as two ANDed keys, metric types additionally require `condition.field`), optional `generate`. Correlations may reference other correlations; compilation is topologically ordered and cycles are a load error (`CORRELATION_CYCLE`).

### 1.4 `kind: ioc`

Indicator **values never appear in rule documents** (D5-007). A rule names signed packs (`pack + version + sha256 digest`), the canonical fields to test, indicator kinds, and normalization steps. See §6 for the pack format, Bloom prefilter and exact confirm.

### 1.5 `kind: fim`

Path globs (case-insensitive on Windows, `\`/`/` equivalent), operations (`create|modify|delete|rename|attribute_change|audit_log_cleared`), optional change requirements (`hash_changed`, `size_changed`), baseline source (`event_old_new` when the source event carries old/new pairs, `upload_pair`/`fim_baseline_table` for cross-upload diffs), and an optional sigma-style `match_event_fields` predicate (e.g. `fim.operation: audit_log_cleared` for Security 1102, which Stage 2 pins to category `fim` with `derived_by: sentinel`). See §7.

### 1.6 `kind: sca`

Selects `config_check.check` ids (trailing-`*` wildcards allowed), optionally asserts over `config_check.observed`/`expected` with RE2-safe operators, defaults to firing only on `status: fail`, records factual framework references (`benchmark.framework/control_id`) with a mandatory note that wording is Sentinel's own. See §8.

### 1.7 `kind: statistical`

Declarative baseline rules: `kind` (`rate|rare_value|proportion`), `group_by`, `measure`, `window` (`bucket` + `span`), `baseline` (`min_observations`, `warmup_action`, `estimator: median_mad|ewma|none`, `k`, `alpha`), `threshold` (+ optional `for_buckets` consecutive violations), optional `scope_filter`. No ML (Stage-1 §4.3). See §9.

### 1.8 `kind: artifact` — Stage-3 AF rules, verbatim keys (resolves Q3-018)

The `when`/`emit` keys and their semantics are **unchanged** from Stage 3 §12.4 (operators `exists`, `in`, `gte`, `in_list_ref` kept; `not_in`, `eq`, `neq`, `lt`, `lte`, `contains`, `regex` added). Constraints inherited verbatim: rules are configuration data; ids are stable; `finding` is a rule id or config-defined name, never free text; `severity_hint` is UI-only (*"detectors own real severity"*); numbers are content (*"operator-configurable; the number is content, not code"*); replay on stored facts reproduces findings without re-triage; scanners may only speak through `artifact_finding` events (D3-031); the triage vocabulary bans `clean/safe/ok/benign/whitelisted/malicious/infected` (D3-029). The engine executes these rules by reading `artifact_fact` and writing `artifact_finding` canonical events (`artifact_type`, `artifact_identity`, `finding`, `evidence`, `scanner`, `confidence`) — the only path from a fact to a detector (Stage-3 §12.6).

### 1.9 Shared value conventions

| Construct | Meaning | Engine handling |
|---|---|---|
| `''` (empty string) | explicit empty value (sigma-spec rules §Special Field Values) | matches a present field whose string value is empty |
| `null` | explicit null-typed value (own type; never mixed into lists — lint rejects) | matches value-state `{$state: "null"}`; **not** the same as an absent key |
| absent key | value absent in source (Stage-2 invariant) | matches only via `exists: false` |
| value-state object `{$state: …}` | Stage-2 D2-001 null/unknown/invalid/conflicting/inferred | predicates match on `$state == "null"` for null; `unknown/invalid` never satisfy equality predicates (they are not values) |
| lists of values | OR (AND with `\|all`) | compiled to SQL `IN`/`OR` or native short-circuit |
| maps | AND across fields | compiled to SQL `AND` |
| list of maps | OR across items | compiled to SQL `OR` / union |
| list of strings | keyword search across the whole event | SQL: search over `raw::text` (see §4.4 cost note) or Aho–Corasick scan natively; never silently skipped |

### 1.10 Invariants (normative; violation = defect, not variance)

1. **Empty rule pack ⇒ exactly zero findings** on any input (Stage-1 MVP-2; CI test, §10.1). Engine code contains no detection constants.
2. **Detectors consume only canonical events** (`canonical-event/v1`) and, for `artifact` kind, only `artifact_fact` rows (Stage-2 D2-014, Stage-3 D3-031). No detector reads raw EVTX/XML/CSV.
3. **Rules are configuration, never code.** No template expansion, no placeholder substitution, no rule-triggered file/network access, no code paths selected by rule content. Lists referenced by `in_list_ref` are resolved from the signed pack at load time only, content-addressed and size-capped (D5-019).
4. **No silent skip.** Every rule is accounted for per job: loaded-and-ran, skipped-with-reason, or rejected-with-reason (Stage-1 §5.6.3; Stage-3 Zircolite precedent).
5. **Three classification axes stay separate** (Stage-1 §6.4): `severity` (LOW/MEDIUM/HIGH) ≠ `level_original` (upstream 5-level) ≠ `events.classification` (public/internal/restricted).
6. **DRL 1.1 attribution flows to every alert** (rule `author` persisted and exposed in API/exports) — Stage-1 §2.3 rule 2.
7. **Compiled SQL is stored per rule as evidence** (`compile.sql`) and is never re-parsed into executable form at runtime (Stage-1 §6.2 non-negotiable d).
8. **Every alert carries `detection_path` (sql|native)** plus reason codes when fallback fired (Stage-1 §5.5/§5.6).
9. **Parser/detector separation** (Stage-1 §5.6.5): no detection logic in parsers, no parsing logic in detectors.
10. **No verdict vocabulary in artifact findings** (Stage-3 D3-029) — and no numeric confidence anywhere (confidence is the 3-value enum `observed|derived|third_party`).

---

## 2. `rule_schema.json` — the stored-document contract

The companion JSON Schema is the **first gate** on every rule at load, pack publish and CI. It is deliberately structural: grammar-level checks (condition expressions, modifier legality, RE2 regex subset, timespan arithmetic, list-reference resolution) belong to the lint engine described in §3, because JSON Schema cannot express them.

| `$defs` | Guards |
|---|---|
| `logsource` | exactly the 4 spec keys (`category/product/service/definition`), no extras |
| `detection` | ≥1 search-identifier + mandatory `condition`; identifiers validated as map-or-list; field keys may carry `\|modifiers`; `null` never inside mixed lists |
| `correlation` | 7 types; `timespan` pattern; temporal types must **not** carry `condition`; metric types **must** carry `condition.field`; condition = one comparator or a 2-key range |
| `ioc` | packs pinned by sha256 digest; indicator values absent by construction |
| `fim` | include-globs mandatory; operations from a closed enum |
| `sca` | check selectors; `regex` assert implies `regex_engine: re2` |
| `statistical` | window patterns; `alpha`∈(0,1); `min_observations` ≥1 |
| `fact_when` / `fact_predicate` / `fact_emit` | Stage-3 shape preserved; exactly one operator key per predicate |
| `compile` | engine-owned; `detection_path` enum; reason-code list is open (string) but codes are registered in §3.1 |

Validation levels (all enforced in CI, §10.4):

1. **L0 parse** — YAML via safe loader, document size cap (`PROPOSED - TO BENCHMARK`: 512 KiB/rule), alias/anchor expansion cap (billion-laughs defence), no custom tags.
2. **L1 schema** — `rule_schema.json` (draft 2020-12).
3. **L2 lint** — §3 support matrix + condition grammar + RE2 subset + cost class + list refs + ATT&CK tag shape.
4. **L3 compile** — SQL/native compile; conformance fixtures (sigma-specification `tests/` at `ba9251aa834b`, §12.1).
5. **L4 pack** — Ed25519 signature (D4-003), manifest digests, NOTICE completeness (DRL authors, ATT&CK copyright line).

Import outcomes (Stage-1 §6.3 vocabulary, reused for every kind): `OK | OK_PARTIAL(reason codes) | REJECTED(reason code)` with per-pack counts surfaced — never a silent drop.

---

## 3. Sigma Feature Support Matrix (spec 2.1.0)

### 3.1 Status vocabulary and reason codes

| Status | Meaning | Engine behaviour |
|---|---|---|
| `SUPPORTED` | Spec construct implemented on **both** paths (SQL + native), covered by conformance fixtures | normal |
| `SUPPORTED_LATER` | Spec construct fully specified here, shipped after MVP or behind a flag; **never silently enabled** | import `OK_PARTIAL` with code + feature flag |
| `NOT_SUPPORTED` | Rejected at import with a reason code, or condition-dropped with flag per Stage-2 §3 | `REJECTED` or `OK_PARTIAL` as specified per row |

Reason codes (registered set; stored in `compile.unsupported[]` and in job accounting):

| Code | Raised when |
|---|---|
| `UNSUPPORTED_MODIFIER` | modifier outside §3.4 (Stage-1 §6.3 vocabulary, reused) |
| `UNSUPPORTED_CONDITION_FORM` | condition grammar form not implemented (§3.5) |
| `UNSUPPORTED_CORRELATION_TYPE` | correlation type rejected |
| `UNSUPPORTED_PLACEHOLDER` | `expand`/`%ph%` placeholders — spec: *"If the tool isn't able to handle placeholders, it must reject the rule"* |
| `UNSUPPORTED_TAXONOMY` | non-default `taxonomy:` attribute |
| `UNSUPPORTED_AGGREGATION` | legacy Sigma-1.x `aggregation:` attribute (not in spec 2.x) |
| `UNSUPPORTED_REGEX_CONSTRUCT` | `re` value outside the spec's restricted flavor or outside RE2 |
| `UNSUPPORTED_ENCODING_TARGET` | `utf16/wide` value whose target field is not declared byte-bearing |
| `UNMAPPED_FIELD` | Sigma field has no canonical target (Stage-2 §3 fallback) |
| `SEMANTICS_REDUCED` | condition re-linted after dropping an arm |
| `NO_PIPELINE_MATCH` | logsource selects no Stage-2 pipeline |
| `EMPTY_SELECTION` | condition references a search-identifier that matches none defined (incl. pattern globs) |
| `CORRELATION_CYCLE` | correlation reference cycle |
| `LIST_REF_UNRESOLVED` / `LIST_REF_TOO_LARGE` | `in_list_ref` problems |
| `COST_BUDGET_EXCEEDED` / `REGEX_TIMEOUT_QUARANTINE` / `SQL_TIMEOUT` / `GROUP_CARDINALITY_CAP` / `WINDOW_STATE_CAP` | runtime guards (§4.7), disable the rule for the remainder of the job and mark job `COMPLETED_WITH_WARNINGS` |
| `BASELINE_WARMUP` / `BASELINE_MISSING` / `IOC_PACK_MISSING` / `IOC_PACK_STALE` / `SNAPSHOT_MISSING` | cold-start outcomes (§4.8) |

Corpus priority (VERIFIED 2026-10-10 scan of the pinned corpus `SigmaHQ/sigma @ 8a4813404e`, 4537 YAML files under the whole tree; modifier counts are per-file occurrences of the key text `|mod:`): `contains` 3606, `endswith` 3687, `startswith` 612, `|all` 1232, `|re` 224 (+4 with submodifier), `|windash` 111, `|expand` 42 (almost all under `deprecated/cloud`; active `rules*` dirs ≈2), `|cidr` 40, `|fieldref` 5, `|base64offset` 9 (always chained `|base64offset|contains`), top-level `name:` 12; **zero** occurrences of `|base64`, `|utf16`, `|wide`, `|exists`, `|neq`, `|gt`, `|lt`, time modifiers, `|cased`, legacy `aggregation:`, `scope:`, `taxonomy:`; **zero** correlation rules and **zero** global filter files in the corpus (top-level `correlation:` = 0, top-level `filter:` = 0 across all 4537 files). Status counts in the five active rule dirs (3768 files): `test` 3328, `experimental` 336, `stable` 104.

### 3.2 Rule metadata & structure

| Spec component (sigma-spec rules spec, `ba9251aa834b`) | Status | Notes / code |
|---|---|---|
| `title` | SUPPORTED | required in stored form |
| `id` | SUPPORTED | becomes `provenance` link; Sentinel `id` is our UUID |
| `name` | SUPPORTED | correlation name→id index |
| `taxonomy` | NOT_SUPPORTED | only default `sigma` taxonomy; code `UNSUPPORTED_TAXONOMY` (0 corpus usage) |
| `status` | SUPPORTED | verbatim, never rewritten |
| `description`, `references`, `date`, `modified`, `falsepositives`, `fields` | SUPPORTED | recorded; `fields` is display-hint only |
| `license` | SUPPORTED | recorded; drives §10.3 obligations |
| `author` | SUPPORTED | **required**; flows to every alert (DRL 1.1) |
| `logsource.category/product/service/definition` | SUPPORTED | selects Stage-2 pipeline; `definition` recorded, not evaluated |
| `detection` (maps/lists/keywords) | SUPPORTED | §1.2 |
| `level` | SUPPORTED | verbatim `level_original` |
| `tags` | SUPPORTED | preserved; ATT&CK ids validated for shape (§10.3), not for existence (offline) |
| `scope` | SUPPORTED_LATER | stored; deployment gating deferred to Stage-6 (Q5-009) |
| global Sigma Filters (`mf_*` files: `filter.rules/selection/condition`) | SUPPORTED | applied at import as `AND NOT (filter.condition)` per referenced rule; the set of applied filter digests is recorded per rule for traceability (0 in corpus; spec-complete) |

### 3.3 Detection section

| Construct (spec section) | Status | Translation |
|---|---|---|
| search-identifier = map (AND) | SUPPORTED | SQL `AND` / native conjunction |
| search-identifier = list of maps (OR) | SUPPORTED | SQL `OR` / native disjunction |
| search-identifier = list of strings (keywords) | SUPPORTED | whole-event search: native Aho–Corasick over the serialized event; SQL over `raw::text` — cost class `heavy` |
| wildcards `*`, `?` in values | SUPPORTED | §3.4 row `startswith/endswith/contains` + literal wildcard expansion; escape rules (`\*`, `\?`, `\\`, `\\\*`, `\\\\`) implemented per spec §Escape Character |
| escape character rules | SUPPORTED | exact spec table |
| `''` empty value | SUPPORTED | §1.9 |
| `null` value | SUPPORTED | §1.9; mixing `null` into value lists = lint error (spec ban) |
| `exists` (field presence) | SUPPORTED | SQL: JSONB key presence on the payload object; native: key present (empty/null values still count, per spec) |
| case-insensitive default | SUPPORTED | `ILIKE`/lower() on SQL; casefold on native |
| condition forms (see §3.5) | SUPPORTED | — |
| `%ph%` placeholders with `\|expand` | NOT_SUPPORTED | code `UNSUPPORTED_PLACEHOLDER`; spec requires rejection; 42 corpus hits are deprecated cloud rules |
| nested/complex values beyond spec | NOT_SUPPORTED | lint rejects |

### 3.4 Modifiers (complete appendix list, v2.1.0)

| Modifier | Class | Status | SQL path | Native path | Corpus hits |
|---|---|---|---|---|---|
| `all` | generic | SUPPORTED | `&&` of per-value predicates | conjunction | 1232 |
| `startswith` | generic | SUPPORTED | `ILIKE 'v%'` (escaped) | prefix compare | 612 |
| `endswith` | generic | SUPPORTED | `ILIKE '%v'` | suffix compare | 3687 |
| `contains` | generic | SUPPORTED | `ILIKE '%v%'` | substring | 3606 |
| `exists` | generic | SUPPORTED | `jsonb_exists(payload, key)` | key presence | 0 |
| `cased` | generic | SUPPORTED | binary/`LIKE` on raw case | case-sensitive | 0 |
| `neq` | generic+numeric | SUPPORTED | `<>` with null-awareness (use `exists:false` filter for not-null, per spec example) | `!=` | 0 |
| `windash` | string | SUPPORTED | compile-time permutation expansion of `- / – — ―` (capped `PROPOSED`: 32 permutations, else `UNSUPPORTED_MODIFIER`) | same | 111 |
| `re` | string (type) | SUPPORTED | RE2-compiled predicate evaluated natively; **never** passed raw to PostgreSQL `~` (see §4.7) | RE2 (`google-re2`) | 224 |
| `re\|i`, `re\|m`, `re\|s` | sub-modifiers | SUPPORTED | inline `(?i)(?m)(?s)` prefixes (RE2 supports all three) | same | 4 |
| `base64` | encoding | SUPPORTED | compile-time value expansion (0 corpus usage; cheap) | same | 0 |
| `base64offset` | encoding | SUPPORTED | compile-time expansion of 3 offsets; combined with `contains` as in corpus (`\|base64offset\|contains`) | same | 9 |
| `utf16le` / `utf16be` / `utf16` / `wide` | encoding | SUPPORTED_LATER | byte-value expansion applied **only** to fields marked byte-bearing in the Stage-2 pipeline `value_transform` (e.g. base64 blobs, PE strings); otherwise `UNSUPPORTED_ENCODING_TARGET` + `OK_PARTIAL` | same | 0 (`wide` token 2 in docs) |
| `lt` `lte` `gt` `gte` (numeric) | numeric | SUPPORTED | `<` `<=` `>` `>=` (cast with type guard; non-numeric value-states never match) | same | 0 |
| `minute` `hour` `day` `week` `month` `year` | time | SUPPORTED | `EXTRACT(unit FROM time.utc)` — **UTC only** (Stage-2 D2-003: never guess a timezone); source-local extraction NOT_SUPPORTED unless `time.original_timezone` is present (then SUPPORTED_LATER, `UNSUPPORTED_TIMEZONE`) | same | 0 |
| `cidr` | ip | SUPPORTED | `host::inet << 'cidr'::inet` guarded by try/catch → invalid values never match | `ipaddress` stdlib | 40 |
| `expand` | specific | NOT_SUPPORTED | placeholders — `UNSUPPORTED_PLACEHOLDER` | — | 42 |
| `fieldref` (± `neq`) | specific | SUPPORTED | field-vs-field compare on the payload (`(p->>'a') = (p->>'b')` with type guards) | same | 5 |

Design notes: (a) every transformation modifier (`base64`, `base64offset`, `windash`, encodings) is resolved **at compile time into literal value sets** — runtime never computes encodings per event; (b) `re` is the only runtime regex class and it is RE2, which is exactly the spec's own restricted flavor minus constructs the spec already forbids (spec: metacharacters other than `.^$*+?{n,m}[]|()` are *"unsupported and can not be used"*) — see §4.7; (c) the absence of `utf16/wide/base64/exists/neq/gt/lt/time/cased` in the pinned corpus means SUPPORTED_LATER rows cost nothing at MVP compile-rate (T2) while remaining spec-honest.

### 3.5 Condition grammar

| Form (spec §Condition) | Status | Notes |
|---|---|---|
| bare identifier (`condition: selection`) | SUPPORTED | |
| `and` / `or` / `not`, parentheses | SUPPORTED | tokenizer treats `not/and/or` as keywords (`notsel` must not split — pySigma fixed this class of bug in 2.0, release notes VERIFIED) |
| `1 of them` / `all of them` | SUPPORTED | `them` excludes identifiers starting with `_` (spec; corpus: 1 hit, in `other/`) |
| `n of pattern` / `1 of pattern` / `all of pattern` | SUPPORTED | `*` wildcards in the identifier pattern; corpus: 3 hits (`1 of selection_generic_*`) |
| identifier globs matching zero identifiers | REJECTED | code `EMPTY_SELECTION` |
| condition as **list** (each item generates a query, logically OR) | SUPPORTED | documented OR semantics (spec wording reviewed; see Q5-002); 0 corpus usage |
| legacy Sigma-1.x `aggregation: ... count() > x timeframe` | NOT_SUPPORTED | not in spec 2.x; code `UNSUPPORTED_AGGREGATION`; aggregation belongs to `kind: correlation` (§5) |
| `near` (some vendor extension) | NOT_SUPPORTED | never part of the Sigma spec |

### 3.6 Correlation rules (spec correlation, v2.1.0)

| Type | Status | Implementation sketch (§5) | Conformance fixture (local `tests/schema/correlation/`) |
|---|---|---|---|
| `event_count` | SUPPORTED | `count(*)` per group in sliding/tumbling window vs comparator | `event_count.yml`, `event_count_ecs.yml` |
| `value_count` | SUPPORTED | `count(DISTINCT field)` per group | `value_count.yml` |
| `temporal` | SUPPORTED | set-cover over rule-match timestamps within timespan | `temporal.yml`, `temporal_ecs.yml` |
| `temporal_ordered` | SUPPORTED | ordered stage machine over rule-match timestamps | `temporal_ordered.yml` |
| `value_sum` | SUPPORTED | `sum(field)` per group | `value_sum.yml` |
| `value_avg` | SUPPORTED | `avg(field)` per group | `value_avg.yml` |
| `value_percentile` | SUPPORTED | `percentile_cont` per group vs comparator | `value_percentile.yml` |
| `group-by` (ANDed fields) | SUPPORTED | window partition keys | |
| `aliases` | SUPPORTED | compile-time field alias application before partitioning | |
| `timespan` `Xs/Xm/Xh/Xd` | SUPPORTED | interval arithmetic; `90m` accepted for 1h30 | |
| condition comparators + ranges | SUPPORTED | | |
| `generate` | SUPPORTED | `true` also compiles referred rules as standalone | |
| correlations-of-correlations | SUPPORTED | topological compile; cycles rejected | |
| spec defect noted | — | the spec's own allowed-values list for `type` (line 236) omits the three metric types added in 2.1.0 (History confirms); Sentinel accepts all 7 and records the inconsistency in NOT_VERIFIED | |

### 3.7 Constructs outside the spec

| Construct | Status | Reason |
|---|---|---|
| Elastic/`data_service`/custom top-level keys | REJECTED | unknown attributes kept in `rule_source`, code `UNSUPPORTED_RULE_ATTRIBUTE` |
| `fieldmappings:` block (rules spec §Field Usage example) | NOT_APPLICABLE | tool-side configuration; our equivalent is Stage-2 `sigma_field_mapping_pipelines.yaml` (D2-014) |
| pySigma processing-pipeline YAML as rule input | NOT_SUPPORTED | pipelines are configuration owned by Stage 2; never rule-supplied (also blocks the pySigma-2.0 `SigmaPolicy` attack surface: template vars, external sources — release notes VERIFIED) |

### 3.8 Compile-rate expectation (PROPOSED - TO BENCHMARK)

Against the Stage-1 PoC protocol T2 (≥95% of 4063 active rules compile to SQL without fallback): the only corpus-relevant non-SQL constructs are `re` (224 files, natively evaluated with RE2 prefiltered by SQL), `windash`/`base64offset` (compile-time expansion), and `fieldref` (5 files, native). Everything else in the matrix is either common (contains/endswith/startswith/all) or absent from the corpus. Expected fallback share: low single-digit percent — **INFERRED**, to be measured.

<!-- CONTINUED-PART-B -->
---

## 4. Streaming Detector Interface

### 4.1 Interface contract (Python-level signature, illustrative)

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

* `RuleContext` carries: resolved rule document, signed `ioc`/`list` material (`D5-019`), baseline handles, feature flags (SUPPORT_LATER gates), job-level budget handles, clock (`time.utc` only per Stage-2 D2-003), and the conformance-mode toggle (§12.1).
* `process()` is the only per-event entry point; it must be **pure** with respect to time (all timestamps come from the event envelope), allocation-bounded (no unbounded per-rule caches), and free of I/O.
* `finalize()` is the only place windows/correlations/baselines/SCA rollups produce findings; it must be idempotent under retry (re-running `finalize` on the same collected state yields the same findings, deduplicated by `finding.fingerprint`).
* Detectors are **stateless across jobs**: all cross-run state lives in `rule_baseline` / `fim_baseline` / `ioc_pack` tables read at `prepare()`.
* Findings (`sentinel-finding/v1`): `{rule_id, rule_name, kind, severity, time, event_ids[], host{agent_id,instance_id,name}, user, detection_path, reason_codes[], payload_excerpt, attck_refs[], falsepositives_note, attestation}` — severity is LOW/MEDIUM/HIGH only (Stage-1 §6.4); `detection_path ∈ {sql, native}`.
  * **Contract layering (C-2-fix, Stage-8 round 1):** `sentinel-finding/v1` is the engine-**internal** emission shape, not a storage or wire contract. At `flush()`, the full object is persisted verbatim inside `findings.evidence_snapshot` (JSONB, per Stage-6 §1.5) — so `payload_excerpt`, `attck_refs[]`, `falsepositives_note`, and `attestation` live in the snapshot, not in dedicated columns. The indexed storage projection is the DDL `findings` table (storage-normative: `finding_uid`, `rule_id`, `rule_name`, `author`, `kind`, `severity`, `level_original`, `time_utc`, `host_hostname`, `user_name`, `detection_path`, `reason_codes`, `fingerprint`, `event_uids`, …); the API projection is OpenAPI `Finding`. Note `host{agent_id,instance_id,name}` here is the **agent-identity summary on a finding**, not the canonical-event `host{hostname,fqdn,ips,os,arch}` object — different concepts, deliberately distinct shapes; it maps to `findings.host_hostname` plus agent context inside `evidence_snapshot`.

### 4.2 Two residence modes, one contract

Stage 1 D-004 Option C makes SQL-over-events the primary engine; Stage 3's `artifact_fact`/`config_check` pipeline and Stage 4's ReDoS posture (D4-004) require a native evaluator to exist as well. The same rule document compiles for both; `detection_path` on every finding names which one fired.

| Mode | Where predicates run | `process()` | `finalize()` | Used when |
|---|---|---|---|---|
| **db-resident (default)** | PostgreSQL, over `events` rows filtered by `run_id` + pushed-down `prepared` prefilters | no-op | executes the stored `compile.sql`, streams rows back as findings | events already ingested to Postgres (MVP path) |
| **stream** | native (RE2 + stdlib), on the event bus | evaluate the native plan per event, buffer window-relevant tuples | windows/correlations execute over the job's buffered tuples | bus-native workloads, or any rule whose `cost_class` is `heavy` with a stream-shaped prefilter |

The **streaming reconciliation rule** (normative, see §4 modes table above): SQL detectors query events by `run_id` in `finalize()`; stream detectors buffer into the job workspace during `process()`. Prefilters mean two different things per mode — index-usable envelope predicates for SQL, fast-reject predicates for native — and both are produced from the same `prepared` list, so the pushdown layer is shared (Stage-1 §5.6.2).

`artifact` kind detectors are stream-shaped by construction (facts arrive as events, findings are emitted immediately); `correlation`/`statistical` are window-shaped (`finalize()`); `sigma` may be either; `ioc`/`fim`/`sca` are per-event (db-resident by default).

### 4.3 Job lifecycle and accounting

```
job = RUN → per event: fanout to detectors' process() (or SQL execute at finalize)
          → finalize all window detectors (topological order for correlations-of-correlations)
          → flush findings, persist baselines/fingerprints
          → per-rule accounting: OK | OK_PARTIAL(codes) | REJECTED(codes) | QUARANTINED(codes)
          → job status ∈ {COMPLETED, COMPLETED_WITH_WARNINGS, FAILED}
```

No detector may exit silently. Per-rule accounting is written to `rule_run(rule_id, job_id, outcome, findings, processed_events, rejected_events, max_group_size, max_window_ms, sql_ms, native_ms)` — this is the audit trail that feeds Stage-6 risk scoring and the §10.6 shadow-mode reports.
**Column mapping (C-5-fix, Stage-8 round 1):** here `job_id` is the DDL `rule_run.run_id` (same concept — the `detection_runs.run_id` FK; no separate `job_id` column). The DDL also carries `detection_path`, `reason_codes`, `started_at`, `finished_at`, and now `max_window_ms`, `sql_ms`, `native_ms` (added to close this conflict); the sql-vs-native timing split is load-bearing for the §10.6 shadow-mode reports and Stage-6 risk scoring and must not be dropped.

### 4.4 SQL-path notes (primary, Option C)

* Prefilters are always expressible as index-usable predicates on envelope columns (`time.utc` range from correlation timespans, `host.agent_id`, `user.name` presence, `source.event_id`/`category`) — Stage-1 §5.6.2 requires a `run_id` + time partial index; this stage adds: **every compiled detector's SQL begins with the same envelope predicate set** so the planner hits the index before any JSONB extraction.
* Payload predicates compile to `payload @> …` containment (GIN, if present) or `(payload->>'process'->>'exe') ILIKE …` with `ILIKE` pattern-escaping (never embed raw user `*`/`?`).
* Keyword search-lists compile to a `raw::text ILIKE ANY(ARRAY[...])` — cost class `heavy`; if the rule has no other predicate, the prefilter layer rejects it at compile time unless the event count for the run is below a configured bound (else `COST_BUDGET_EXCEEDED`, `OK_PARTIAL`).
* Time-window aggregation (`correlation`, `statistical`) compiles to `date_bin(interval, time.utc, origin)` buckets (PostgreSQL 18 §9.9.3, VERIFIED) partitioned by the group-by columns; `percentile_cont(fraction) WITHIN GROUP` for percentiles (VERIFIED §9.7/9.9).
* Statement timeouts are mandatory on every engine-issued statement (Stage-4 D4-004 → §4.7 layer 3).
* Compiled SQL is stored as evidence per rule and is **parameterized** (values bound as parameters, never string-interpolated) — a non-negotiable of D-004 (§1.10 invariant 7).

### 4.5 Native-path notes (fallback + oracle)

* Value lists from compile-time transformations (`base64*`, `windash`) are materialized into the native plan as literal sets; regex predicates use `google-re2` (BSD, win_amd64 wheels cp310–cp314, VERIFIED PyPI); list membership uses `pyahocorasick` for large keyword sets (BSD-3/Public-Domain, win_amd64 cp310–cp314, VERIFIED) and plain sets below a threshold (`PROPOSED`: 32 keys).
* The native evaluator is also the **conformance oracle** for the SQL path (Stage-1 §5.5): on the golden corpus (sigma-specification `tests/`, plus 20 pinned SigmaHQ rules), both paths must emit identical finding fingerprints; any divergence is a defect, not a variance (§12.1).
* Same RE2 subset as SQL-path regex (§4.7) — one regex engine everywhere is what makes the oracle meaningful.

### 4.6 Cost classes and budgets (D5-012)

| Class | Definition | Budget (PROPOSED - TO BENCHMARK) | Exceeded → |
|---|---|---|---|
| `prefilter` | envelope-only predicates (category/source.event_id/host/time) | no per-rule cap | — |
| `standard` | payload field predicates, ≤N fields, no regex | ≤2 ms/event p95 native; SQL cost tracked via `EXPLAIN` estimate at compile | `COST_BUDGET_EXCEEDED`, rule quarantined for job |
| `heavy` | keyword-search over whole event, fieldref, large OR sets | ≤10 ms/event p95 native | same |
| `window` | correlation/statistical/finalize aggregations | ≤200 000 buffered tuples/job/group (`GROUP_CARDINALITY_CAP`); ≤512 MiB workspace | same + finding suppressed, never partial group |

Compile-time lint assigns the class (and refuses to compile a rule whose worst-case is unbounded, e.g. `re` with a variable-length repetition AND no other predicate, unless a prefilter exists). Runtime `cost_report()` feeds the job-level watchdog; a rule that trips its budget twice in a row is quarantined for the remainder of the job (`REGEX_TIMEOUT_QUARANTINE`/`COST_BUDGET_EXCEEDED`) — **never silently**.

### 4.7 ReDoS strategy (4 layers; D4-004 compliance, D5-004/D5-005)

| Layer | Mechanism | Scope |
|---|---|---|
| **L1 grammar** | `re` values must parse against the spec's own restricted flavor (only `.^$*+?{n,m}[]|()`, no backrefs/lookahead) **and** against RE2's parser; both must accept or the rule is `REJECTED(UNSUPPORTED_REGEX_CONSTRUCT)` at lint time | import + CI |
| **L2 translation** | regex predicates are never emitted as PostgreSQL `~` on hostile input paths: either (a) the prefilter narrows to a bounded set of rows and the remaining check runs in the RE2 native pass, or (b) a **generated** (engine-authored, not user-authored) simple pattern is translated to `ILIKE`/`starts_with()` (PostgreSQL 18 §9.7 notes `starts_with()`/`^@` as the index-friendly forms — VERIFIED) | compile |
| **L3 runtime** | `statement_timeout` on every engine SQL (D4-004 mandate); native regex runs carry a wall-clock deadline per event (`PROPOSED`: 2 ms); timeouts increment the rule's cost report | run |
| **L4 circuit breaker** | two consecutive timeouts/quota trips → rule quarantined for the job, `COMPLETED_WITH_WARNINGS`, reason code persisted (§3.1); a per-tenant quarantine rate alarm is Stage-6 material | run |

Hostile-regex caution (PostgreSQL docs §9.7, VERIFIED 2026-10-10) is the documented justification for L2/L3; RE2's non-backtracking guarantee (pySigma 2.0 release notes made RE2 the default engine for exactly this reason — VERIFIED) is the justification for routing user regex to RE2 rather than to any backtracking engine. User-supplied regex is the **only** place rule content can trigger a regex engine, and it is confined to RE2 with deadlines.

### 4.8 Cold-start policy (D5-015; reject condition R4)

"Cold start" = a detector that needs state the system does not have yet. The policy is **explicit, per subsystem, and never degrades to a silent pass**:

| Subsystem | State needed | Cold-start behaviour | Recovery |
|---|---|---|---|
| `sigma` (per-event) | none | runs immediately, zero warm-up | — |
| `correlation` | nothing pre-stored; windows fill from the first event | findings require ≥1 group member; `eq` comparators with empty windows emit nothing (correct) | window state per job only |
| `statistical` | ≥ `min_observations` buckets in `rule_baseline` | **warm-up window** (`PROPOSED`: 7 days of buckets or `min_observations`, whichever first). `warmup_action: suppress` (default) = no findings until the baseline is valid, but the rule is accounted with `BASELINE_WARMUP` in the job report and the job becomes `COMPLETED_WITH_WARNINGS` — never silent silence. `warmup_action: flag` = emit LOW findings carrying `baseline.warmup=true` and the code. | first stable median/MAD or EWMA seed; `alpha` seedable from a config constant |
| `ioc` | signed packs present | `IOC_PACK_MISSING` → rules of that pack are `OK_PARTIAL`; the job completes; a **stale** pack (older than `PROPOSED - TO BENCHMARK`: 7 days) adds `IOC_PACK_STALE` and LOW findings are suppressed, HIGH+ still fire | pack refresh (D4-003 signature verified on load) |
| `fim` (baseline modes) | `fim_baseline` rows or an upload-pair | `SNAPSHOT_MISSING` → rules with `baseline.source: upload_pair/fim_baseline_table` are inert for the job with the code; rules with `baseline.source: event_old_new` run normally (old/new pairs come from the event itself — Stage-2 `fim` mapping, VERIFIED) | baseline upload (§7.4) |
| `sca` | nothing pre-stored (checks evaluate per event) | runs immediately; a check whose source plugin has not reported yet simply produces no events | plugin heartbeats (Stage-3) |
| `artifact` | nothing pre-stored | runs immediately over incoming facts; replay of stored facts is a first-class path (Stage-3 §12.5) | — |
| compile cache | per-rule `compile` rows | absent → compile at job start (adds to job startup latency budget, §4.6); a failed compile is cached as `REJECTED` with its codes | invalidation on rule/source digest change (D4-003) |

Universal rule: **warm-up/cold-start never fabricates a "pass"**. A statistical rule in warm-up, a missing IOC pack, or a missing FIM baseline all surface as `COMPLETED_WITH_WARNINGS` with per-rule codes, never as zero-finding silence. This is the same epistemic rule as Stage-3 D3-029 (`unknown` ≠ pass) and Stage-2's unknown-handling invariant, applied to detector readiness.

---

## 5. Correlation Design (7 types, SQL primary + native fallback)

### 5.1 Data flow

```
per-event detectors (sigma/ioc/fim/sca) emit findings
        → match_stream (finding.rule_id, finding.time.utc, group_keys, payload scalars)
        → window buffer (in-memory per job; SQL: date_bin GROUP BY over findings view)
        → correlation detector (partition by group-by, evaluate comparator on metric)
        → correlated finding (fingerprint = rule_id + group_key + window_id + metric_value)
```

Correlations consume **findings**, not raw events (the spec's `rules:` field references rule ids/names, not fields). A correlation may reference another correlation; the dependency graph is topologically ordered at load (`CORRELATION_CYCLE` otherwise).

### 5.2 Metric implementations

| Type | Metric | SQL | Native fallback | Notes |
|---|---|---|---|---|
| `event_count` | `count(*)` per group per window | `count(*) FILTER (WHERE …)` over the findings view, bucketed by `date_bin` | in-memory `Counter` | sliding windows approximated by tumbling buckets of the timespan (documented approximation; Q5-003) |
| `value_count` | `count(DISTINCT field)` | `count(DISTINCT (payload->>'…'))` | `set` size | field resolved through the same pipeline alias map |
| `value_sum` | `sum(field)` | `sum((payload->>'…')::numeric)` with cast guard (non-numeric ⇒ row ignored + counter) | running sum | v2.1.0 addition; `neq` comparator allowed |
| `value_avg` | `avg(field)` | `avg(…::numeric)` guarded | running mean | |
| `value_percentile` | `percentile_cont(f) WITHIN GROUP (ORDER BY …)` | native: sorted sample, `PROPOSED` reservoir cap 10 000 | `PROPOSED - TO BENCHMARK` cap; exceed ⇒ `WINDOW_STATE_CAP` |
| `temporal` | all referenced rules fired within `timespan` for the group | set-cover over (rule_id, time) ordered by time | | emits one finding per qualifying group-window |
| `temporal_ordered` | stages fired in order within `timespan` | stage machine; each stage's window starts at the previous stage's match time | | strict ordering (`leq` per spec examples) |

### 5.3 Semantics decisions (normative)

1. **Group-by is mandatory** for every type (spec: `group-by` required); an empty group-by list is a lint error (not "global").
2. **Windows are tumbling** at MVP (`date_bin(timespan, …)`); sliding windows are SUPPORTED_LATER (`W5-001`) because they multiply state; both are documented as approximations of the spec's interval semantics — this is a **declared** deviation with a code (`OK_PARTIAL` on the rule if sliding is requested), never silent (invariant R2).
3. **Missing fields in group-by** (event lacks a group key): the event is excluded from grouping (matches the spec's "fields must exist" expectation) and counted in `rejected_events` for the correlation rule; excluded-group storms trip the cost watchdog.
4. **Comparators** `gt|gte|lt|lte|eq|neq`; ranges = two ANDed comparators on the same field; metric types require `condition.field` (schema-enforced).
5. **`generate`** compiles referred rules as standalone as well; the correlated finding links to member findings via `finding.related_finding_ids` (cap `PROPOSED`: 100).
6. **False-positive hints** on the correlation rule are advisory only (UI), same as Stage-1 §6.4.

### 5.4 Failure modes (all accounted, none silent)

| Condition | Code | Effect |
|---|---|---|
| group cardinality > cap | `GROUP_CARDINALITY_CAP` | correlation quarantined for job; prior groups' findings retained |
| window buffer > cap | `WINDOW_STATE_CAP` | same |
| member rule missing/disabled | `MEMBER_RULE_INACTIVE` | correlation inert + code (never "correlate over nothing") |
| member findings suppressed downstream (severity floor) | `MEMBER_RULE_SUPPRESSED` | `OK_PARTIAL`; correlations can only see what passed the floor (D5-020) |
| SQL timeout in finalize | `SQL_TIMEOUT` | quarantined; native fallback attempted once (§12.2) |

### 5.5 Conformance

Every local correlation fixture in `_stage1_work/sigma-specification/tests/schema/correlation/` (`event_count.yml`, `value_count.yml`, `temporal.yml`, `temporal_ordered.yml`, `value_sum.yml`, `value_avg.yml`, `value_percentile.yml`, plus ECS variants) is compiled and replayed through the native path at CI; expected findings come from the fixture's own `tests/cases` where present, else from hand-authored expectations checked into Sentinel's conformance suite (§12.1).

<!-- CONTINUED-PART-C -->
---

## 6. IOC Design (signed packs, two-stage membership, no values in rules)

### 6.1 Pack format (`ioc_pack/v1`)

Packs are **data**, signed with the Stage-4 D4-003 Ed25519 process (same pipeline as rule packs; Stage-1 §5.3.2 external-source flow). Values never enter rule documents (D5-007) — packs are swappable intelligence, rules are stable detection logic.

```yaml
schema: ioc_pack/v1
pack: {id: acme-intel, version: "2026.10.0", generated_utc: "2026-10-09T12:00:00Z",
       source: ACME-MISP, license: DRL-1.1-or-proprietary, contact: intel@acme.example,
       attestation: {sig: base64(ed25519), key_id: acme-intel-2026}}
entries:
  - {kind: sha256, value: 3f2a…, first_seen: 2026-09-01, tlp: amber, refs: ["https://…"], tags: [apt, loader]}
  - {kind: ipv4,   value: 203.0.113.7, cidr: false, …}
  - {kind: cidr,   value: 198.51.100.0/24, …}
  - {kind: domain, value: bad.example, match_subdomains: true, …}
  - {kind: url,    value: "https://bad.example/payload.exe", …}
counts: {sha256: 1, ipv4: 1, cidr: 1, domain: 1, url: 1}
digests: {entries_sha256: …, manifest_sha256: …}
```

Load path: signature verify (D4-003) → digest check → normalize (lowercase domains, strip trailing dot, canonical IPv6, reject invalid) → ingest into `ioc_entry(pack_id, kind, value, meta…)` with a unique index on `(kind, value)`.

### 6.2 Two-stage membership (D5-007)

| Stage | Structure | Purpose |
|---|---|---|
| **Stage A — Bloom prefilter** | in-house Bloom filter (`hashlib` blake2b/keccak, stdlib only; `PROPOSED - TO BENCHMARK`: k=6, m sized for pack size × 10 bits/entry, FPP ≈ 1%) built at pack load, per (pack, kind) | O(1) fast-reject of ~all negatives; no third-party dependency (Stage-1 §2.1); rebuild is incremental-friendly |
| **Stage B — exact confirm** | hash-set / `ILIKE`-guarded domain-suffix match / `inet <<` for CIDR | the only stage allowed to produce a finding; eliminates Bloom false positives entirely |

Domain matching is suffix-exact (`bad.example` and `*.bad.example` per `match_subdomains`), never a substring scan. URL matching is exact + optional prefix. IPv4/IPv6/CIDR use the same guards as the `cidr` modifier (§3.4). Hash indicators compare against `hashes.sha256` (and configured aliases `md5/sha1` where the pipeline materializes them); a pack entry of the wrong length/charset is rejected at load, not at match time.

### 6.3 Rule side (`kind: ioc`)

```yaml
kind: ioc
ioc:
  packs:
    - pack: acme-intel
      version: "2026.10.0"
      digest_sha256: "6b8e1f0c2d3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4"
  match:
    fields: [process.hashes.sha256, file.hashes.sha256]
    kinds: [sha256]
    normalize: [hash_lower, trim]
  confirm_exact: true
  on_stale: last_known_good
  emit_fields: [process.hashes.sha256, process.exe]
```

`match` maps indicator kind → canonical field paths (pipeline-resolved, same rule as §1.2). The compiled prefilter is "field present"; the Bloom pass is free per event; a positive Bloom triggers Stage-B confirm → finding.

### 6.4 Freshness, failure, governance

* Staleness gate (§4.8): packs older than `PROPOSED` 7 days mark `IOC_PACK_STALE`; LOW-severity IOC findings are suppressed, MEDIUM+ still fire; the pack is **never** silently dropped.
* Missing pack → rules referencing it are `OK_PARTIAL(IOC_PACK_MISSING)`; job continues.
* Pack update with broken signature → last-known-good pack retained (Stage-4 T-06 posture), alert raised, `IOC_PACK_STALE` escalates to alarm (Stage-6 dashboard).
* Pack provenance (source, license, TLP, refs) is persisted per entry and copied onto findings (§10.3 obligations for third-party feeds).
* Pack content is untrusted input: size caps (`PROPOSED`: 5 M entries / 256 MiB), no regex fields, no executable content (D5-018 applies to packs too).

---

## 7. FIM Design (event-driven only; live-host baselines out of scope)

### 7.1 Scope boundary (Stage-1 §4.2 binding)

Live-host file-integrity agents (OSSEC-style baselining of a running host) are **out of scope** for Sentinel MVP. FIM here means: (a) predicates over `fim`/`file` canonical events (Stage-2 §6 mapping: Security 4663/4656/4660/4698/4719, Sysmon 11/23, plus `audit_log_cleared` for Security 1102 — VERIFIED stage-2 lines 1095–1110, 3009), and (b) diffs against an **uploaded** baseline file (hash+size+attrs per path), never against a live host.

### 7.2 Rule shape (`kind: fim`)

```yaml
kind: fim
fim:
  paths:
    include: ["C:\\Windows\\System32\\**", "*.exe", "*.dll"]
    exclude: ["C:\\Windows\\System32\\*.log"]
  operations: [create, modify, attribute_change]     # or [audit_log_cleared]
  require: {hash_changed: true}                     # optional
  baseline: {source: event_old_new}                 # or upload_pair / fim_baseline_table
  match_event_fields: {fim.operation: audit_log_cleared}   # optional sigma-style predicate
```

Case-insensitivity and `\`/`/` equivalence are compiler behaviour on Windows (not rule keys — the schema has no `case_sensitive` flag; §7.2). Globs semantics: `**` crosses directories; `*`/`?` within a segment; the compiler emits an Aho–Corasick automaton of literal prefixes + a bounded matcher for `**` (no user regex anywhere — §4.7 applies unchanged). `require.hash_changed` is only satisfiable when the event carries old/new hash pairs (Stage-2 `fim.old/new` VERIFIED); otherwise the rule is `OK_PARTIAL(UNSUPPORTED_COMBINATION)`. For the audit-log-cleared rule of §1.5, `operations: [audit_log_cleared]` alone is sufficient (the `match_event_fields` predicate is redundant there and is shown to demonstrate the shape).

### 7.3 Baseline modes

| Mode | Source | Use |
|---|---|---|
| `event_old_new` | the `fim` event's own `old{size,modified,attributes,hashes}` vs `new{…}` (VERIFIED in `canonical_event_v1.schema.json` `$defs.fim`) | change detection without any stored state; **default**; cold-start-free |
| `upload_pair` | baseline CSV/JSON uploaded by the analyst (`fim_baseline` rows: path, size, mtime, sha256) + an inventory file from the same host at a later time | inventory-diff workflow (Stage-3 §9-style external input) |
| `fim_baseline_table` | prior inventory rows already stored for the host | cross-run drift |

### 7.4 Failure modes

| Condition | Code | Effect |
|---|---|---|
| baseline requested, none present | `SNAPSHOT_MISSING` | rule inert for job, accounted (§4.8) |
| event lacks old/new but rule requires hash comparison | `UNSUPPORTED_COMBINATION` | `OK_PARTIAL` |
| path outside any host's observed roots | — | not an error; zero matches |
| `audit_log_cleared` rule with no 1102-equivalent events in range | zero matches | normal (the event only exists when an admin clears it) |

Severity assignment follows Stage-1 §6.4 defaults with `audit_log_cleared` defaulting to HIGH (`PROPOSED`, overridable per rule).

---

## 8. SCA Design (own checks, no SCAP/OVAL/XCCDF, no copied benchmark text)

### 8.1 Scope boundary (Stage-1 §4.2 binding) and licence posture

No SCAP/OVAL/XCCDF engine; no CIS PDF text. CIS Benchmarks are free for non-commercial use (CC BY-NC-SA 4.0 for non-members) but **commercial redistribution/tailoring requires SecureSuite membership** (terms VERIFIED 2026-10-10). Sentinel's posture (D5-009): **write our own check definitions**, cite framework **control IDs** (`CIS Windows 11 §18.9.1`) as factual references, never copy benchmark wording, and mark every check `license: sentinel-own`. Where a check mirrors a public control, the `framework` field records the ID and the rule records `source_note: paraphrased` — a licence gate, not a cosmetic note (Stage-1 §2.2 rules 2–4: DRL attribution, MITRE copyright line, per-source licence class — all still apply to SCA packs).

### 8.2 Event source and rule shape

Checks emit `config_check` canonical events (VERIFIED `$defs.config_check`: `check`, `category`, `expected`, `observed`, `status ∈ {pass,fail,unknown}`, `source`). Rules are **selection + optional assertion**, never the check logic itself (checks live in Stage-3 plugins/ExternalProcessRunner, D3-024):

```yaml
kind: sca
sca:
  select:
    checks: ["sc.win.local_policy.*", "sc.win.autorun.*"]    # trailing-* wildcards
  fail_status_only: true                                      # default: fire only on status: fail
  assert:                                                     # optional; over the emitted event
    field: config_check.observed
    op: neq
    value: "2"                                                # re2-safe ops only
  benchmark:
    framework: cis
    control_id: "18.9.1"
    note: "Control ID cited factually; the check wording is Sentinel's own (CIS PDFs are CC BY-NC-SA 4.0 for non-commercial use; commercial tailoring needs SecureSuite)."
  evidence: [config_check.observed, config_check.expected, config_check.source]
```

`unknown` is never treated as `pass` (mirrors Stage-3 D3-029 and Stage-2 unknown-handling): `fail_status_only: false` fires on any status including `unknown`; a rule that fires on `unknown` must set top-level `severity: LOW` and the finding payload carries `status: unknown` (lint-enforced). Absent evidence (no `config_check` event at all) is neither pass nor fail — it is absence, and §8.3 surfaces it as a warning, never as a green result.

### 8.3 Aggregation and reporting

SCA findings are per-check-per-host with a `sca_rollup` view (pass/fail/unknown counts per benchmark family per host per run) for the Stage-6 dashboard. Rollup thresholds are Stage-6 material; this stage only guarantees the data shape and the accounting (a job with zero `config_check` events but enabled SCA rules surfaces `NO_EVENTS_FROM_PLUGIN` as a warning — never silence).

---

## 9. Statistical Design (declarative baselines, no ML, warm-up explicit)

### 9.1 Rule shape (`kind: statistical`)

```yaml
kind: statistical
statistical:
  kind: rate                       # rate | rare_value | proportion
  group_by: [host.agent_id]        # mandatory
  measure: {op: sum, field: network.bytes_sent}
  window: {bucket: 5m, span: 7d}   # bucket = date_bin width; span = trailing baseline window
  baseline: {min_observations: 84, warmup_action: flag, estimator: median_mad, k: 6, alpha: 0.3}
  threshold: {op: gt, value: 50000000, for_buckets: 3}   # comparator + optional consecutive buckets
  scope_filter: {event.category: [network]}              # optional sigma-style predicate
```

### 9.2 Estimators (all stdlib/SQL, no ML — Stage-1 §4.3)

| Estimator | Definition | SQL | Native |
|---|---|---|---|
| `median_mad` | median + k×MAD over baseline buckets | `percentile_cont(0.5)` over the bucket view + `percentile_cont(0.5)` of abs deviations | sorted sample, same caps as §5.2 |
| `ewma` | `s_t = α·x_t + (1−α)·s_{t−1}` | computed at finalize over the bucket series | running scalar |
| `none` | raw threshold only (`threshold` required, baseline ignored) | — | — |

`rare_value` uses `count(DISTINCT value)` + per-value historical frequency from `rule_baseline` (`PROPOSED`: flag buckets whose value is absent from the last 30 observed days of that value's set). `proportion` is `count(match)/count(*)` per group-bucket vs threshold.

### 9.3 Baselines, warm-up, cold start

* Buckets persist in `rule_baseline(rule_id, group_key, span_start, span_end, metric, n, extras)`; the baseline is written at `finalize()` of each job (idempotent upsert keyed by the bucket id).
* `min_observations` gates validity; until then `warmup_action`:
  * `suppress` (default): no findings until the baseline is valid, but the rule is accounted with `BASELINE_WARMUP` and the job is `COMPLETED_WITH_WARNINGS` (never silent);
  * `flag`: findings emitted at LOW carrying `baseline.warmup=true` and `BASELINE_WARMUP` — visible, not alarming.
* `k` default 6 (`PROPOSED - TO BENCHMARK`); `alpha` default 0.3 (`PROPOSED`); both config-overridable per rule.
* Baseline resets: rule digest change (D4-003) invalidates baselines; manual reset is an explicit admin action recorded in the audit log (Stage-3 D3-034 pattern).
* No ML, no autotuning, no anomaly models beyond median/MAD and EWMA — Stage-1 §4.3 out-of-scope is honoured by construction (the schema has no model fields).

---

## 10. Governance, Supply Chain, and Safety

### 10.1 No hardcoded detections (reject condition R1; D5-014)

* Engine code contains **zero** detection constants: no rule fragments, no indicator values, no "if hostname == 'DC01'" logic. The only literals allowed in code are budgets/limits (§4.6), the reason-code enum, and schema/fixture paths.
* CI invariant test: boot the engine with an empty rule store against the golden corpus → **exactly 0 findings**, and assert the codebase contains no `sigma`/`ioc`/`fim`/`sca`/`statistical`/`artifact` rule documents outside `fixtures/` and `packs/` (a grep-based tripwire + a pack-free integration test).
* All detections ship as data through the same signed-pack path (§10.2); `kind: artifact` AF rules from Stage-3 §12 are imported as ordinary rules, not special-cased in code.

### 10.2 Rule packs and signing (extends Stage-4 D4-003)

Pack manifest (`sentinel-pack/v1`): `{pack_id, version, created_utc, rules_digest, entries: [{rule_id, sha256}], attestation: {sig, key_id, sig_alg: ed25519}}`. Load order: signature → digests → schema → lint → compile. Any failure keeps the **last-known-good** pack (Stage-4 T-06 posture) and raises a finding-severity alarm. Key rotation, revocation list, and offline verification are Stage-6/ops material but the key-id indirection is reserved now (schema field, §2 L4).

### 10.3 Third-party content obligations (carried from Stage-1 §2.3)

| Source | SPDX/licence | Class | This stage's handling |
|---|---|---|---|
| SigmaHQ rules (DRL 1.1 — VERIFIED 2026-10-10 `LICENSE` at `8a4813404e`) | Detection-Rules-License-1.1 | EXTERNAL_PROCESS / REFERENCE | retain author + URI + licence reference per DRL §1–§3; `author` is copied onto **every alert** the rule produces (DRL §3 requirement, §1.10 invariant 6); commercial redistribution of rules is the Stage-1 §2.3 legal gate — pack publisher defaults to `private` |
| sigma-specification (public domain — VERIFIED LICENSE) | Unlicense-equivalent | REFERENCE | no constraint |
| MITRE ATT&CK (© 2016–2026 The MITRE Corporation; VERIFIED `attack-stix-data/LICENSE.txt` 2026-10-10: royalty-free incl. commercial, must reproduce the copyright designation) | Apache-style custom | REFERENCE | every exported artefact that includes ATT&CK ids carries the line `"© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."`; MITRE-derived data is facts (ids/names), not text dumps |
| CIS Benchmarks (PDF free for non-commercial use; commercial tailoring needs SecureSuite — VERIFIED 2026-08 CIS terms page) | CC BY-NC-SA 4.0 (non-commercial PDFs) | AVOID for text; REFERENCE for control IDs | SCA rules cite control IDs only (§8.1); CI tripwire rejects any rule string longer than 64 chars that matches known CIS phrasing patterns (heuristic, `PROPOSED`) |
| `google-re2` (BSD-3-Clause classifier, VERIFIED PyPI 2026-10-10) | BSD-3-Clause | DEPENDENCY | NOTICE entry |
| `pyahocorasick` (BSD-3-Clause + Public-Domain, VERIFIED PyPI) | BSD-3-Clause | DEPENDENCY | NOTICE entry |
| `pySigma` (LGPL-2.1-only, VERIFIED `pyproject.toml` @ `50708bae`) | LGPL-2.1-only | DEPENDENCY (conformance tooling only) | kept out of the runtime hot path (Stage-1 pin rationale); NOTICE + LGPL notice-availability obligation if linked |
| PostgreSQL 18 | PostgreSQL License | DEPENDENCY | NOTICE entry |

### 10.4 Content as untrusted input (D5-018; extends Stage-4 T-12)

Rules, packs, filters, baselines and IOC feeds are all **attacker-influenced-by-design** surfaces (they will be edited by humans and bots for years). Handling: safe YAML loader only (no custom tags, no object construction); document size cap (`PROPOSED`: 512 KiB) + anchor-expansion cap; no template/placeholder expansion (spec's `expand` rejected, §3.3); no rule-triggered I/O (lists resolved at load, content-addressed, size-capped `PROPOSED`: 10 MiB per list — D5-019); condition expression depth/size caps (`PROPOSED`: depth 32, identifiers 64, OR-arms 256) with lint rejection; compiled SQL parameterized (never string-concatenated) so rule values cannot become SQL text; native plan values are data, never code.

### 10.5 Shadow mode, kill switch, audit

* **Shadow mode** (extends Stage-2 `shadow_mode` job flag and Stage-3 §11): a rule or pack can be flagged `governance.mode: shadow`; it compiles, runs, produces findings tagged `shadow: true` that are stored + visible in dashboards but **never page anyone** and never open incidents. Promotion to `active` is an explicit action requiring a second approver (config, Stage-6 RBAC) and is recorded in the audit log with actor + pack digest.
* **Kill switch** (Stage-3 D3-033 precedent): `rules.enabled=false` globally or per rule/pack; the disable path must be as fast as the enable path (config flip, no recompile) and audited.
* **Audit log** (Stage-3 D3-034): every pack load, signature failure, quarantine, shadow promotion, baseline reset, and kill-switch flip is appended with actor, timestamp (UTC), pack digest, and reason — retained per Stage-3 retention policy.
* **Canary rule**: one synthetic rule (`kind: sigma`, matches nothing real, `canary: true`, governance-owned) per pack verifies end-to-end plumbing on every job; a job with zero canary findings is flagged `PIPELINE_SILENT` (`PROPOSED`: warning, not failure, because legitimate zero-match jobs exist — the canary matches a synthetic injected event, so zero means the path is broken).

### 10.6 CI gates (the reject conditions, automated)

| Gate | Blocks merge if |
|---|---|
| Schema (`rule_schema.json`) | any rule/pack fails L0–L1 |
| Canonical-path cross-validation (D8-14) | any rule's `detection` predicate `field` (and `fields[]` entry) does not resolve to a property path in `canonical_event_v1.schema.json` — prevents rules that compile + validate but silently match nothing (e.g. `process.parent_image` vs canonical `process.parent.exe`) |
| Support matrix lint | any `SUPPORTED` row's fixtures fail; any `SUPPORTED_LATER` rule slips in without its flag |
| ReDoS lint (§4.7 L1) | any `re` value outside the restricted RE2 subset |
| Empty-pack invariant (R1) | golden corpus run with empty store emits ≠ 0 findings |
| Native/SQL conformance (§12.1) | fingerprint divergence on the golden corpus |
| Licence tripwire | missing DRL attribution path, missing ATT&ACK copyright line in exports, missing NOTICE entries |
| CIS text tripwire (§10.3) | known-benchmark phrasing detected in rule bodies |

<!-- CONTINUED-PART-D -->
---

## 11. Worked Rule Examples (25 documents, schema-valid)

Every block below is a **stored-form** document (`sentinel-rule/v1`): the post-import shape the engine persists and executes. Sigma examples show pipeline-resolved canonical fields (Stage-2 D2-014 applied once at import; the verbatim upstream text lives in `rule_source` per D5-001). Thresholds are content, not code — operators edit them without redeploying the engine (Stage-3 §12.4 precedent). CI validates all examples against `rule_schema.json` (§10.6, §12.3).

### 11.1 `kind: sigma` (5)

```yaml
# S-01 — Encoded PowerShell launched from cmd.exe (process creation)
schema: sentinel-rule/v1
id: 7c1a9e40-2f6b-4d8a-9c3e-1b2d3e4f5a60
kind: sigma
source: sigma
source_id: 5f0d8b2a-9c4e-4a1f-8e7d-6b5a4c3d2e10
source_ref: "sigma-rules@8a4813404e:rules/windows/process_creation/example_s01.yml"
source_spec: sigma-spec/2.1.0
license: DRL-1.1
author: Example Sigma Author
title: Encoded PowerShell Launched From cmd.exe
name: win_process_encoded_ps_from_cmd
description: cmd.exe spawning PowerShell with an encoded command and execution-policy bypass.
status: test
severity: HIGH
level_original: high
logsource:
  product: windows
  category: process_creation
tags: [attack.t1059.001, attack.t1027]
falsepositives: [Software deployment tooling that encodes installer commands]
fields: [process.exe, process.command_line, process.parent.exe, user.name]
detection:
  selection:
    process.exe|endswith: ['\cmd.exe', '\powershell.exe', '\pwsh.exe']
    process.command_line|contains|all: ['-enc', 'bypass']
  filter_legit:
    process.parent.exe|endswith: '\services.exe'
  condition: selection and not filter_legit
enabled: true
compile:
  detection_path: sql
  cost_class: standard
  prefilter:
    - {column: source.channel, op: eq, values: [security, sysmon]}
```

```yaml
# S-02 — Suspicious registry persistence value written
schema: sentinel-rule/v1
id: 3d5e7f80-1a2b-4c6d-8e9f-0a1b2c3d4e51
kind: sigma
source: sigma
source_spec: sigma-spec/2.1.0
license: DRL-1.1
author: Example Sigma Author
title: Run Key Persistence Written Under Winlogon
name: win_registry_winlogon_shell_replace
description: A value named Shell under Winlogon is set to a non-standard interpreter.
status: test
severity: HIGH
level_original: high
logsource:
  product: windows
  category: registry_set
tags: [attack.t1547.001]
detection:
  selection:
    registry.path|endswith: '\CurrentVersion\Winlogon\Shell'
    registry.data|contains: ['.exe', '.vbs', '.js', '.hta', '.bat', '.cmd']
  condition: selection
enabled: true
compile:
  detection_path: sql
  cost_class: prefilter
  prefilter:
    - {column: source.event_id, op: in, values: [13, 14]}
```

```yaml
# S-03 — Outbound connection to a raw-IP destination on a high port
schema: sentinel-rule/v1
id: 9b8c7d6e-5f4a-4b3c-8d2e-1f0a9b8c7d62
kind: sigma
source: sigma
source_spec: sigma-spec/2.1.0
license: DRL-1.1
author: Example Sigma Author
title: Network Connection To Literal IP Address
name: win_network_literal_ip_high_port
description: Process opens a connection to a dotted-quad address on a non-standard port.
status: test
severity: MEDIUM
level_original: medium
logsource:
  product: windows
  category: network_connection
tags: [attack.t1071]
detection:
  selection:
    network.dst_ip|re: '^\d{1,3}(\.\d{1,3}){3}$'
    network.dst_port|gte: 1024
  filter_corp:
    network.dst_ip|cidr: [10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12]
  condition: selection and not filter_corp
enabled: true
compile:
  detection_path: native          # one `re` predicate: regex check runs in the RE2 pass; SQL still applies the envelope/category prefilter
  cost_class: standard
  prefilter:
    - {column: event.category, op: eq, values: [network]}
```

```yaml
# S-04 — Suspicious PowerShell script block content
schema: sentinel-rule/v1
id: 1e2f3a4b-5c6d-4e7f-8a9b-0c1d2e3f4a53
kind: sigma
source: sigma
source_spec: sigma-spec/2.1.0
license: DRL-1.1
author: Example Sigma Author
title: PowerShell Downloads And Invokes A Remote Bytecode Loader
name: win_ps_downloadstring_assembly
description: Script block combines DownloadString with Assembly Load — classic cradle pattern.
status: test
severity: HIGH
level_original: high
logsource:
  product: windows
  service: powershell
tags: [attack.t1059.001, attack.t1105]
detection:
  selection:
    powershell.script_block_text|contains|all: ['DownloadString', 'Assembly']
    powershell.script_block_text|contains: ['Load(', 'GetType']
  condition: selection
enabled: true
compile:
  detection_path: sql              # contains-predicates only: ILIKE over the payload, no regex
  cost_class: heavy                # long-text scan class
```

```yaml
# S-05 — Keyword search across the whole event (OR list, search-identifier list form)
schema: sentinel-rule/v1
id: 0f9e8d7c-6b5a-4c3d-2e1f-0a9b8c7d6e54
kind: sigma
source: sigma
source_spec: sigma-spec/2.1.0
license: DRL-1.1
author: Example Sigma Author
title: Mimikatz-Like Strings Anywhere In The Event
name: win_keyword_mimikatz_strings
description: Whole-event keyword search; condition is a list of items (OR across items per spec).
status: experimental
severity: MEDIUM
level_original: medium
logsource:
  product: windows
tags: [attack.t1003]
detection:
  keywords:
    - 'sekurlsa::logonpasswords'
    - 'privilege::debug'
    - 'lsadump::sam'
  condition: keywords
enabled: true
compile:
  detection_path: native
  cost_class: heavy
```

### 11.2 `kind: correlation` (4)

```yaml
# C-01 — Brute force: repeated failed logons per account per host
schema: sentinel-rule/v1
id: a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c55
kind: correlation
source: sigma
source_spec: sigma-spec/2.1.0
license: DRL-1.1
author: Sentinel content team
title: Repeated Failed Interactive Logons (Brute Force Candidate)
name: corr_bruteforce_failed_logons
description: >-
  More than 5 failed logon events for the same account on the same host within 10m.
  Referenced rules are ordinary kind:sigma rules resolved by name through the load-time name index;
  a missing/disabled member produces MEMBER_RULE_INACTIVE (never a silent no-op).
severity: HIGH
level_original: high
correlation:
  type: event_count
  rules: [win_auth_failure_4625, win_auth_failure_4768]
  group-by: [authentication.account_name, host.agent_id]
  timespan: 10m
  condition: {gt: 5}
  generate: true
enabled: true
compile:
  cost_class: window
```

```yaml
# C-02 — Ordered lateral movement: new service followed by remote logon
schema: sentinel-rule/v1
id: b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d66
kind: correlation
source: sigma
source_spec: sigma-spec/2.1.0
license: DRL-1.1
author: Sentinel content team
title: Remote Service Creation Followed By Interactive Logon
name: corr_service_then_logon
description: >-
  Stage-ordered correlation - service install, then logon, on the same host within 30m.
severity: HIGH
level_original: high
correlation:
  type: temporal_ordered
  rules: [win_service_install, win_auth_success_4624]
  group-by: [host.agent_id]
  timespan: 30m
enabled: true
compile:
  cost_class: window
```

```yaml
# C-03 — Password spray: many distinct accounts failed from one source IP
schema: sentinel-rule/v1
id: c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e77
kind: correlation
source: sigma
source_spec: sigma-spec/2.1.0
license: DRL-1.1
author: Sentinel content team
title: Many Distinct Failed Accounts From One Source (Password Spray Candidate)
name: corr_password_spray
description: 10+ distinct failing account names from the same source IP within 15m.
severity: HIGH
level_original: high
correlation:
  type: value_count
  rules: [win_auth_failure_4625]
  group-by: [authentication.source_ip]
  timespan: 15m
  condition: {field: authentication.account_name, gte: 10}
enabled: true
compile:
  cost_class: window
```

```yaml
# C-04 — Bulk data egress: summed bytes_sent far above the peer baseline
schema: sentinel-rule/v1
id: d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f88
kind: correlation
source: sigma
source_spec: sigma-spec/2.1.0
license: DRL-1.1
author: Sentinel content team
title: Sustained Outbound Byte Volume From One Host
name: corr_egress_byte_sum
description: Summed network.bytes_sent above 50 MB per host within 1h across network events.
severity: MEDIUM
level_original: medium
correlation:
  type: value_sum
  rules: [win_network_literal_ip_high_port]
  group-by: [host.agent_id]
  timespan: 1h
  condition: {field: network.bytes_sent, gt: 50000000}
enabled: true
compile:
  cost_class: window
```

### 11.3 `kind: ioc` (2)

```yaml
# I-01 — Known-bad SHA-256 in process or file hashes
schema: sentinel-rule/v1
id: e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8a99
kind: ioc
source: native
author: Sentinel content team
title: Process Hash Matches Signed Intelligence Pack
description: Bloom prefilter then exact confirm; indicator values live only in the pack (D5-007).
severity: HIGH
ioc:
  packs:
    - pack: acme-intel
      version: "2026.10.0"
      digest_sha256: "6b8e1f0c2d3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4"
      subset: botnet-c2
  match:
    fields: [process.hashes.sha256, file.hashes.sha256]
    kinds: [sha256]
    normalize: [hash_lower, trim]
  confirm_exact: true
  on_stale: last_known_good
  emit_fields: [process.hashes.sha256, process.exe]
enabled: true
compile:
  detection_path: sql
  cost_class: prefilter
```

```yaml
# I-02 — DNS query or connection destination matches domain/IP intelligence
schema: sentinel-rule/v1
id: f6a7b8c9-d0e1-4f2a-3b4c-5d6e7f8a9b0a
kind: ioc
source: native
author: Sentinel content team
title: DNS Or Connection Destination Matches Signed Intelligence Pack
description: Domain suffix-exact match plus IP/CIDR membership from the same signed pack.
severity: HIGH
ioc:
  packs:
    - pack: acme-intel
      version: "2026.10.0"
      digest_sha256: "6b8e1f0c2d3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4"
  match:
    fields: [dns.query_name, network.dst_ip]
    kinds: [domain, ipv4, cidr]
    normalize: [lowercase, strip_trailing_dot, ip_canonical]
  confirm_exact: true
  on_stale: last_known_good
  emit_fields: [dns.query_name, network.dst_ip, network.dst_port]
enabled: true
compile:
  detection_path: sql
  cost_class: prefilter
```

### 11.4 `kind: fim` (2)

```yaml
# F-01 — Security audit log cleared (Security 1102 -> category fim, VERIFIED Stage-2)
schema: sentinel-rule/v1
id: 1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c1b
kind: fim
source: native
author: Sentinel content team
title: Security Event Log Cleared
description: fim.operation = audit_log_cleared is produced by the Stage-2 pipeline from Security EID 1102.
severity: HIGH
fim:
  paths:
    include: ['**']
  operations: [audit_log_cleared]
  baseline: {source: event_old_new}
enabled: true
compile:
  detection_path: sql
  cost_class: prefilter
  prefilter:
    - {column: source.event_id, op: eq, values: [1102]}
```

```yaml
# F-02 — Critical system binary changed versus uploaded baseline inventory
schema: sentinel-rule/v1
id: 2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d2c
kind: fim
source: native
author: Sentinel content team
title: System32 Executable Hash Drift Against Uploaded Baseline
description: >-
  Requires an uploaded baseline pair (fim_baseline rows). Absent baseline = SNAPSHOT_MISSING,
  rule inert for the job, job COMPLETED_WITH_WARNINGS (cold-start policy 4.8) — never a silent pass.
severity: HIGH
fim:
  paths:
    include: ['C:\\Windows\\System32\\*.exe']
    exclude: ['C:\\Windows\\System32\\*.log']
  operations: [modify, attribute_change]
  require: {hash_changed: true}
  baseline: {source: upload_pair}
enabled: true
compile:
  cost_class: standard
```

### 11.5 `kind: sca` (2)

```yaml
# SC-01 — Local security policy check failed
schema: sentinel-rule/v1
id: 3c4d5e6f-7a8b-4c9d-0e1f-2a3b4c5d6e3d
kind: sca
source: native
author: Sentinel content team
title: Unsupported Security Provider Registered
description: Fires only on config_check.status = fail for the selected checks; wording is Sentinel's own.
severity: MEDIUM
sca:
  select:
    checks: ["sc.win.local_policy.*"]
  fail_status_only: true
  assert:
    field: config_check.observed
    op: neq
    value: "2"
  benchmark:
    framework: cis
    control_id: "18.9.1"
    note: "Control ID cited factually; check wording is Sentinel's own (no CIS benchmark text shipped)."
  evidence: [config_check.observed, config_check.expected, config_check.source]
enabled: true
compile:
  cost_class: prefilter
```

```yaml
# SC-02 — Autorun entry outside the organisation's allowlist
schema: sentinel-rule/v1
id: 4d5e6f7a-8b9c-4d0e-1f2a-3b4c5d6e7f4e
kind: sca
source: native
author: Sentinel content team
title: Autorun Entry Not In The Approved Allowlist
description: >-
  config_check plugins emit pass/fail/unknown events; unknown never counts as pass (D3-029 mirror).
severity: MEDIUM
sca:
  select:
    checks: ["sc.win.autorun.*"]
    categories: [persistence]
  fail_status_only: true
  assert:
    field: config_check.observed
    op: contains
    value: "\\Temp\\"
  evidence: [config_check.observed, config_check.source]
enabled: true
compile:
  cost_class: prefilter
```

### 11.6 `kind: statistical` (2)

```yaml
# ST-01 — Per-host byte-rate outlier versus its own trailing baseline
schema: sentinel-rule/v1
id: 5e6f7a8b-9c0d-4e1f-2a3b-4c5d6e7f8a5f
kind: statistical
source: native
author: Sentinel content team
title: Network Byte Rate Above Peer Baseline
description: >-
  median + k*MAD over 5m buckets spanning 7d; k and thresholds are content.
  Warm-up (suppress) accounts BASELINE_WARMUP — never silent silence (4.8).
severity: MEDIUM
statistical:
  kind: rate
  group_by: [host.agent_id]
  measure: {op: sum, field: network.bytes_sent}
  window: {bucket: 5m, span: 7d}
  baseline: {min_observations: 84, warmup_action: suppress, estimator: median_mad, k: 6}
  threshold: {op: gt, value: 50000000, for_buckets: 3}
  scope_filter: {event.category: [network]}
enabled: true
compile:
  cost_class: window
```

```yaml
# ST-02 — Rare authenticated user on a host
schema: sentinel-rule/v1
id: 6f7a8b9c-0d1e-4f2a-3b4c-5d6e7f8a9b6a
kind: statistical
source: native
author: Sentinel content team
title: First-Time Interactive User On Host
description: >-
  rare_value over authentication.account_name per host; a name absent from the 30d
  observed set is flagged. No ML (Stage-1 4.3): set-membership only.
severity: LOW
statistical:
  kind: rare_value
  group_by: [host.agent_id]
  measure: {op: distinct_count, field: authentication.account_name}
  window: {bucket: 1h, span: 30d}
  baseline: {min_observations: 24, warmup_action: flag, estimator: none}
  threshold: {op: gte, value: 1}
  scope_filter: {authentication.logon_type: [2, 10, 11]}
enabled: true
compile:
  cost_class: window
```

### 11.7 `kind: artifact` (8: AF-001…AF-005 verbatim + AF-006…AF-008 new)

Import wraps Stage-3 §12.4 rules: adds `schema`/`kind`/`source`/`severity`/`enabled`, keeps `id`/`title`/`when`/`emit`/`severity_hint`/`attribution` **verbatim** (D5-001; schema allows rule-level `severity_hint`/`attribution` for `kind: artifact` only). AF-001…AF-005 below reproduce the Stage-3 keys exactly; AF-006…AF-008 are new rules resolving Q3-018's "we want a few more" gap, using only Stage-3-verified fact names (`pe.authenticode.present` §5.5, `pe.import.name` §5.5, `motw.zone_id` §12.4, `pdf.action.open_action` §5.3, `pdf.javascript.count` §5.3, `lnk.target.is_unc`/`lnk.target.path` §5.6).

```yaml
# A-01 = AF-001
schema: sentinel-rule/v1
id: AF-001
kind: artifact
source: native
title: Office document declares an external relationship target
severity: LOW
when:
  all:
    - fact: ooxml.relationship.external_target
      exists: true
    - fact: identification.selected
      in: [ooxml]
emit:
  artifact_type: file
  finding: external_relationship_declared
  confidence: observed
  evidence_facts: [ooxml.relationship.external_target, ooxml.relationship.type]
severity_hint: informational
attribution: >-
  Rule authored for Sentinel (DRL-compatible content, Stage-1 D-004).
enabled: true
```

```yaml
# A-02 = AF-002
schema: sentinel-rule/v1
id: AF-002
kind: artifact
source: native
title: PDF declares an OpenAction
severity: LOW
when:
  all:
    - fact: pdf.action.open_action
      exists: true
emit:
  artifact_type: file
  finding: pdf_open_action_declared
  confidence: observed
  evidence_facts: [pdf.action.open_action]
enabled: true
```

```yaml
# A-03 = AF-003
schema: sentinel-rule/v1
id: AF-003
kind: artifact
source: native
title: Archive entry expansion ratio above the configured threshold
severity: MEDIUM
when:
  any:
    - fact: archive.entry.ratio
      gte: 100                     # operator-configurable; the number is content, not code
    - fact: ooxml.part.ratio
      gte: 100
emit:
  artifact_type: file
  finding: high_expansion_ratio
  confidence: derived
  evidence_facts: [archive.entry.ratio, ooxml.part.ratio]
enabled: true
```

```yaml
# A-04 = AF-004
schema: sentinel-rule/v1
id: AF-004
kind: artifact
source: native
title: PE imports a process-execution API
severity: MEDIUM
when:
  any:
    - fact: pe.import.name
      in_list_ref: lists/exec_apis.yaml     # WinExec, ShellExecuteA, CreateProcessW, ...
emit:
  artifact_type: file
  finding: imports_process_execution_api
  confidence: observed
  evidence_facts: [pe.import.name, pe.import.dll]
enabled: true
```

```yaml
# A-05 = AF-005
schema: sentinel-rule/v1
id: AF-005
kind: artifact
source: native
title: File carries the mark of the web
severity: LOW
when:
  all:
    - fact: motw.zone_id
      in: [3, 4]
emit:
  artifact_type: file
  finding: internet_zone_origin
  confidence: observed
  evidence_facts: [motw.zone_id, motw.referrer_url]
enabled: true
```

```yaml
# A-06 = AF-006 (new) — unsigned PE + exec API import + MotW, ANDed
schema: sentinel-rule/v1
id: AF-006
kind: artifact
source: native
title: Unsigned PE with process-execution import and Internet-zone origin
description: >-
  Composite of three Stage-3 facts. All three must hold; each fact alone is weak,
  the conjunction is the finding. confidence: derived because authenticity is inferred
  from presence flags, not from chain verification (offline, unverified_offline).
severity: MEDIUM
when:
  all:
    - fact: pe.authenticode.present
      eq: false
    - fact: pe.import.name
      in_list_ref: lists/exec_apis.yaml
    - fact: motw.zone_id
      in: [3, 4]
emit:
  artifact_type: file
  finding: unsigned_pe_exec_api_from_internet
  confidence: derived
  evidence_facts: [pe.authenticode.present, pe.import.name, motw.zone_id]
severity_hint: medium
enabled: true
```

```yaml
# A-07 = AF-007 (new) — PDF OpenAction combined with embedded JavaScript
schema: sentinel-rule/v1
id: AF-007
kind: artifact
source: native
title: PDF declares an OpenAction and embeds JavaScript
description: AF-002 alone is weak (many benign PDFs declare OpenAction); JavaScript raises the bar.
severity: MEDIUM
when:
  all:
    - fact: pdf.action.open_action
      exists: true
    - fact: pdf.javascript.count
      gte: 1
emit:
  artifact_type: file
  finding: pdf_open_action_with_javascript
  confidence: derived
  evidence_facts: [pdf.action.open_action, pdf.javascript.count, pdf.javascript.source]
severity_hint: medium
enabled: true
```

```yaml
# A-08 = AF-008 (new) — LNK pointing at a UNC path
schema: sentinel-rule/v1
id: AF-008
kind: artifact
source: native
title: LNK shortcut targets a UNC path
description: UNC LNK targets are the classic phishing-payload delivery shape; facts come from the in-house LNK parser (Stage-3 5.6).
severity: LOW
when:
  all:
    - fact: lnk.target.is_unc
      eq: true
emit:
  artifact_type: file
  finding: lnk_unc_target
  confidence: observed
  evidence_facts: [lnk.target.is_unc, lnk.target.path, lnk.target_hashes.sha256]
severity_hint: low
enabled: true
```

<!-- CONTINUED-PART-E -->
---

## 12. Acceptance and Verification Plan

### 12.1 Conformance tiers

| Tier | Corpus | Assertion |
|---|---|---|
| **T-A schema** | `rule_schema.json` + the 25 examples of §11 | every example validates; a corpus of negative rules (null-in-list, unknown attributes, temporal+condition, missing group-by) each fails with the expected error path |
| **T-B spec fixtures** | `_stage1_work/sigma-specification/tests/` at `ba9251aa834b` (rules + correlation schema tests, conditions, modifiers) | L2 lint accepts exactly the spec-valid cases; the engine's condition tokenizer matches pySigma's on the shared fixture set (the pySigma 2.0 `not/and/or` tokenizer fixes are already noted as regression targets) |
| **T-C dual-path oracle** | golden corpus: 20 pinned SigmaHQ rules covering each §3.4 SUPPORTED modifier + the 7 correlation fixtures (§5.5) | SQL path and native path emit **identical finding fingerprints** on replayed synthetic events; any divergence fails CI (§10.6) |
| **T-D Stage-1 PoC hooks** | PoC protocol T1–T7 (Stage-1 §5.8) | T2 compile-rate ≥95% on the 4063 active rules (PROPOSED, Stage-1); T3 streaming throughput; T4 baseline-cold-start latency (this stage's §4.8 windows) |
| **T-E governance** | signed pack fixtures, expired-key fixture, CIS-phrasing canary strings, DRL/ATT&ACK export templates | signature failures keep last-known-good; licence tripwires fire; alerts carry author + MITRE copyright line |

### 12.2 Fallback drill

On the golden corpus, force `detection_path: native` for every rule and force SQL timeouts via a 1 ms `statement_timeout`; the job must complete as `COMPLETED_WITH_WARNINGS` with per-rule reason codes and **the same findings** as the unforced run. This validates Stage-1 §5.5's fallback requirement and this stage's §4.7 layer-3/4 wiring.

### 12.3 Example validation

The 25 §11 documents are checked into the repo and validated in CI against `rule_schema.json` with a strict draft-2020-12 validator (`additionalProperties` enforced everywhere; `if/then` evaluated). A validation failure is a merge blocker (§10.6).

### 12.4 What this stage does **not** claim

No throughput, latency, or compile-rate numbers are claimed here — every budget in §4.6 and every window size in §4.8/§9 is **PROPOSED - TO BENCHMARK** against the Stage-1 PoC (T2/T3/T4). No detection efficacy (TPR/FPR) claims; that is measurement, not specification.

---

## 13. DECISIONS

```yaml
decisions:
  - id: D5-001
    decision: >-
      One stored document schema (sentinel-rule/v1, rule_schema.json) with a kind
      discriminator over seven families. Sigma/correlation keep their spec shape
      verbatim; artifact rules keep Stage-3 AF when/emit/severity_hint/attribution
      verbatim (non-UUID AF-xxx ids accepted). Unknown upstream attributes are never
      dropped silently: they live in rule_source and surface as reason codes.
    status: accepted
    evidence: [stage-1:6.2, stage-3:12.4, rule_schema.json]
    alternatives_rejected:
      - "Two schemas (sigma doc + artifact doc): doubles the governance pipeline, reopens Q3-018."
      - "Store verbatim upstream YAML only: no stable engine contract, no additive guarantee."
    consequences: [one lint gate, one pack format, one audit trail for all detections.]
    depends_on: [D-004, D2-014, D3-029]

  - id: D5-002
    decision: >-
      Detector interface = prepare/process/finalize (+cost_report, teardown) with two
      residence modes (db-resident default: SQL at finalize; stream: native process +
      buffered finalize). Both modes compile from the same document; findings carry
      detection_path.
    status: accepted
    evidence: [stage-1:5.5, stage-1:5.6.2, stage-1:6.2]
    alternatives_rejected:
      - "SQL-only: cannot serve bus-native workloads or serve as a conformance oracle."
      - "Native-only: contradicts D-004 Option C primary."
    consequences: [two execution paths to keep in lockstep; conformance tier T-C enforces it.]
    depends_on: [D-004]

  - id: D5-003
    decision: >-
      Normative support matrix (SUPPORTED/SUPPORTED_LATER/NOT_SUPPORTED) with a
      registered reason-code vocabulary; every import and every job accounts for every
      rule; NO silent semantic change - each deviation is OK_PARTIAL or REJECTED with a code.
    status: accepted
    evidence: [stage-1:6.3, stage-1:5.6.3]
    alternatives_rejected: ["Best-effort parsing with silent skips (Zircolite-style accounting is the floor, not the ceiling)."]
    consequences: [job reports always list non-OK rules; dashboards can alert on reason codes.]
    depends_on: [D5-001]

  - id: D5-004
    decision: >-
      User regex is RE2-class only (google-re2), matching the Sigma spec's own restricted
      flavor; four-layer ReDoS defense (grammar lint, no raw regex to PostgreSQL ~,
      statement_timeout + native deadlines, quarantine circuit breaker). Two consecutive
      trips quarantine the rule for the job.
    status: accepted
    evidence: [stage-4:D4-004, sigma-spec:rules, pysigma:2.0.0, postgres:18]
    alternatives_rejected:
      - "PostgreSQL POSIX ARE (~): backtracking engine on hostile input, explicitly cautioned by the docs."
      - "Reject all regex: breaks 224 corpus files for no security gain once RE2 is in place."
    consequences: [RE2 in the runtime dependency set (BSD-3); no lookahead/backrefs ever.]
    depends_on: [D4-004]

  - id: D5-005
    decision: Wildcards (*, ?) compile to ILIKE/starts_with + literal expansion, never to regex.
    status: accepted
    evidence: [sigma-spec:escape-rules, postgres:18]
    alternatives_rejected: ["Translate wildcards to regex: unnecessary engine exposure for a trivial translation."]
    consequences: [prefilter-friendly patterns; index usage preserved where possible.]
    depends_on: [D5-004]

  - id: D5-006
    decision: >-
      Case handling is default-insensitive (ILIKE / casefold) exactly as the spec
      requires; |cased flips to binary compare; encodings/case are compile-time
      value expansions, never per-event runtime transforms.
    status: accepted
    evidence: [sigma-spec:modifiers]
    alternatives_rejected: ["Per-event base64/utf16 expansion: cost blow-up, no semantic difference."]
    consequences: [compile output is literal value sets; conformance corpus must include |cased fixtures.]
    depends_on: []

  - id: D5-007
    decision: >-
      IOC values never live in rule documents. Signed packs (D4-003) feed a two-stage
      membership test: in-house Bloom prefilter (stdlib hashlib, no third-party BF lib)
      then exact confirm. Staleness and missing packs surface as reason codes; last-known-good retained.
    status: accepted
    evidence: [stage-1:5.3.2, stage-4:D4-003, stage-1:2.1]
    alternatives_rejected:
      - "Embed indicators in rules: rules become intelligence, defeats pack rotation and D4-003 signing."
      - "Third-party Bloom library: new supply-chain surface for a solved problem."
    consequences: [pack format + load path; Bloom rebuild cost at load (bounded by entry caps).]
    depends_on: [D4-003]

  - id: D5-008
    decision: >-
      FIM is event-driven only (fim/file canonical events, old/new pairs when present)
      plus optional uploaded-baseline diffs. Live-host FIM agents are out of scope
      (Stage-1 4.2). Cold start with a required-but-missing baseline = SNAPSHOT_MISSING + inert + warnings.
    status: accepted
    evidence: [stage-1:4.2, stage-2:fim-mapping]
    alternatives_rejected: ["Host-side baseline daemon: new agent surface, out of MVP scope."]
    consequences: [upload_pair workflow is analyst-driven; no silent green.]
    depends_on: [D2-014]

  - id: D5-009
    decision: >-
      SCA = config_check events + our own check packs. Benchmark control IDs may be
      cited factually; benchmark wording may never be shipped (CIS commercial terms).
      unknown status never counts as pass.
    status: accepted
    evidence: [stage-1:4.2, stage-1:2.3, cis-terms:2026, stage-3:D3-029]
    alternatives_rejected: ["Ship CIS/OVAL content: commercial licence breach risk for a distributed product."]
    consequences: [check coverage is self-owned; framework mapping is reference data only.]
    depends_on: []

  - id: D5-010
    decision: >-
      Statistical detectors are declarative (rate/rare_value/proportion) with
      median+MAD, EWMA, or raw thresholds. No ML (Stage-1 4.3). Warm-up is explicit
      (suppress/flag) and always accounted via BASELINE_WARMUP.
    status: accepted
    evidence: [stage-1:4.3, postgres:18]
    alternatives_rejected: ["Vendor ML baselines: unexplainable alerts, training-data governance burden, out of scope."]
    consequences: [baselines are rows in rule_baseline; resets are audited actions.]
    depends_on: []

  - id: D5-011
    decision: >-
      Correlations run over finding streams (not raw events), windows are tumbling
      date_bin buckets at MVP (sliding = SUPPORTED_LATER with an explicit OK_PARTIAL
      code), group cardinality and window state are hard-capped, member-rule state
      (inactive/suppressed) is always reported.
    status: accepted
    evidence: [sigma-spec:correlation, postgres:18]
    alternatives_rejected: ["Exact sliding windows at MVP: state cost unbounded, no corpus need (0 correlation rules in corpus)."]
    consequences: [declared approximation of interval semantics; Q5-003 tracks the exactness question.]
    depends_on: [D5-002]

  - id: D5-012
    decision: >-
      Cost classes (prefilter/standard/heavy/window) assigned at lint, enforced at run
      with per-rule budgets; breaches quarantine the rule for the job and mark the job
      COMPLETED_WITH_WARNINGS. Budgets are PROPOSED - TO BENCHMARK (T3/T4).
    status: accepted
    evidence: [stage-1:5.7, stage-4:T-04]
    alternatives_rejected: ["Unmetered evaluation: one pathological rule can starve the job (T-04)."]
    consequences: [cost_report() telemetry becomes Stage-6 dashboard input.]
    depends_on: [D5-004]

  - id: D5-013
    decision: >-
      Governance = Ed25519-signed packs (D4-003) + DRL author attribution to every
      alert + MITRE copyright line in exports + NOTICE entries + shadow mode with
      two-person promotion + audited kill switch + per-pack canary rule
      (PIPELINE_SILENT when the canary produces nothing).
    status: accepted
    evidence: [stage-1:2.3, stage-4:D4-003, drl:LICENSE, mitre:LICENSE.txt, stage-2:shadow_mode, stage-3:D3-033]
    alternatives_rejected: ["Unsigned local rules only: no tamper evidence for packs that will be edited by bots for years."]
    consequences: [pack publishing becomes a signed release step; key rotation is ops material (Stage-6).]
    depends_on: [D4-003]

  - id: D5-014
    decision: >-
      Empty-pack invariant: the engine with zero rules emits exactly zero findings on
      the golden corpus; no detection constants in engine code; all detections ship as
      data. CI-enforced (R1 reject condition).
    status: accepted
    evidence: [stage-1:MVP-2]
    alternatives_rejected: ["Built-in starter detections: would violate MVP-2 and make the product unauditable."]
    consequences: [an empty install is legitimately quiet; the canary rule is the pipeline liveness check.]
    depends_on: []

  - id: D5-015
    decision: >-
      Cold-start policy per subsystem (statistical warm-up, IOC pack freshness, FIM
      baseline presence, compile cache): never fabricate a pass; always surface a
      reason code and COMPLETED_WITH_WARNINGS. Universal invariant: missing state is
      reported, not absorbed.
    status: accepted
    evidence: [stage-1:5.6.3, stage-3:D3-029]
    alternatives_rejected: ["Silently disable until warm: hides months of blind spots (the classic cold-start failure mode)."]
    consequences: [ops must watch warning codes; Stage-6 risk scoring consumes them.]
    depends_on: [D5-003]

  - id: D5-016
    decision: >-
      Unmapped Sigma fields follow Stage-2 section 3 fallback: condition dropped AND
      flagged UNMAPPED_FIELD (OK_PARTIAL); dropping an OR-arm that changes semantics
      additionally records SEMANTICS_REDUCED. Never a silent keep-or-drop.
    status: accepted
    evidence: [stage-2:3]
    alternatives_rejected: ["Reject the whole rule on any unmapped field: too brittle for a 4000-rule corpus."]
    consequences:
      - "compile.unsupported[] becomes queryable; Q5-004 tracks the reject-instead option per-pack."
    depends_on: [D2-014]

  - id: D5-017
    decision: >-
      Native evaluator is both the streaming path and the SQL conformance oracle;
      every finding carries detection_path and, when fallback fired, the reason code.
      Forced-fallback drill is part of acceptance (12.2).
    status: accepted
    evidence: [stage-1:5.5]
    alternatives_rejected: ["Trust the SQL path alone: divergences would ship silently."]
    consequences: [dual maintenance cost, bounded by the shared plan format.]
    depends_on: [D5-002]

  - id: D5-018
    decision: >-
      Rule/pack/baseline content is untrusted input: safe YAML loader, size and
      expansion caps, no templates/placeholders/expand, no rule-triggered I/O,
      parameterized SQL only, expression depth/width caps at lint.
    status: accepted
    evidence: [stage-4:T-12, sigma-spec:expand]
    alternatives_rejected: ["Full spec fidelity including expand/placeholders: opens a template-injection class with no corpus benefit (42 deprecated hits)."]
    consequences: [rules can never become code; expand-using rules are rejected with UNSUPPORTED_PLACEHOLDER.]
    depends_on: [D5-003]

  - id: D5-019
    decision: >-
      in_list_ref lists are resolved at load from the signed pack, content-addressed by
      digest, size-capped (PROPOSED 10 MiB), and never re-read at match time.
    status: accepted
    evidence: [stage-3:12.4]
    alternatives_rejected: ["Runtime file reads from rules: I/O from untrusted paths, TOCTOU, and cold-start ambiguity."]
    consequences: [list edits require a pack re-sign; replay is deterministic.]
    depends_on: [D5-018]

  - id: D5-020
    decision: >-
      Finding contract extension: findings carry rule_id, kind, severity (3-level),
      detection_path, reason_codes[], related_finding_ids (capped), shadow flag, and
      DRL author attribution. Severity floors are applied at emission, and correlations
      only see findings that passed the floor (MEMBER_RULE_SUPPRESSED otherwise).
    status: accepted
    evidence: [stage-1:6.4, stage-2:shadow_mode, drl:LICENSE]
    alternatives_rejected: ["Correlate pre-floor: hidden alerts would silently drive HIGH findings."]
    consequences: [floor tuning changes correlation behaviour - documented, not silent.]
    depends_on: [D5-011]
```

---

## 14. OPEN QUESTIONS

```yaml
open_questions:
  - id: Q5-001
    question: >-
      Should SUPPORT_LATER encodings (utf16/wide/base64 as runtime modifiers for
      non-declared fields) be promoted to SUPPORTED via a per-rule byte-bearing
      declaration, or stay rejected for Sentinel's Windows-first corpus?
    needs: Corpus re-scan after the first 90 days of live imports; PoC T2 numbers.
  - id: Q5-002
    question: >-
      Condition-as-list (each item generates a query, logically OR) is accepted per the
      spec's wording but has 0 corpus usage - keep SUPPORTED, or demote to NOT_SUPPORTED
      until a real rule needs it?
    needs: Live-import telemetry.
  - id: Q5-003
    question: >-
      Are tumbling windows an acceptable approximation of the correlation spec's interval
      semantics at MVP, or must sliding windows land before any correlation pack ships?
    needs: T4 baseline/cold-start benchmarks; customer-shaped traffic replay.
  - id: Q5-004
    question: >-
      Should UNMAPPED_FIELD stay OK_PARTIAL (drop-and-flag) or become REJECTED per-pack
      for compliance packs (where a dropped OR-arm is a coverage claim)?
    needs: Compliance-pack requirements from Stage-6 scope definition.
  - id: Q5-005
    question: >-
      Bloom sizing and staleness window (7d PROPOSED) - does the false-positive budget
      and pack-refresh cadence hold under real feed sizes (up to the 5M-entry cap)?
    needs: T3 throughput runs with synthetic 1M/5M-entry packs.
  - id: Q5-006
    question: >-
      Canary PIPELINE_SILENT as warning vs failure: for compliance deployments, should a
      dead canary fail the job instead of merely warning?
    needs: Stage-6 compliance-profile input.
  - id: Q5-007
    question: >-
      pySigma 2.0 (LGPL-2.1-only) as a CI-only conformance oracle - is the LGPL
      notice-availability obligation acceptable for the distribution model, or must the
      oracle be reimplemented natively?
    needs: Distribution-model decision (binary vs source) from Stage-6 packaging.
  - id: Q5-008
    question: >-
      Cost budgets (2/10 ms/event, 200k window tuples) are PROPOSED - which numbers survive T3?
    needs: PoC T3/T4 results.
  - id: Q5-009
    question: >-
      Rule `scope` (deployment gating) is SUPPORTED_LATER (stored, not evaluated). What
      scope vocabulary and matching semantics does Stage-6 require before scope-gated
      rules can be enabled per-environment without hand-editing packs?
    needs: Stage-6 deployment/environment model; register under OQ-6-* once defined.
```

---

## 15. NOT VERIFIED

```yaml
not_verified:
  - claim: >-
      pySigma v2.0.0 release date (2026-10-04), requires_python >=3.11,<4.0, LGPL-2.1-only,
      and the RE2-default release-note wording.
    checked: >-
      2026-10-10 via GitHub API / PyPI JSON (client-challenge on raw pypi.org pages);
      local pin at 50708bae (v2.0.0 tag, pyproject.toml license field VERIFIED locally).
      The release-notes wording itself was not re-read this session beyond the Stage-1 pin.
  - claim: google-re2 1.1.20251105 win32/win_amd64 wheel matrix and BSD-3-Clause classifier.
    checked: 2026-10-10 PyPI JSON; wheel installability on the target Windows build not tested.
  - claim: pyahocorasick 2.3.1 wheel matrix (win_amd64 cp310-cp314 only; no win32/win_arm64).
    checked: 2026-10-10 PyPI JSON; ARM64 Windows fallback path not exercised.
  - claim: >-
      SigmaHQ/sigma release r2026-07-01 is the latest release and its package archives
      carry published SHA-256 digests.
    checked: 2026-10-10 GitHub API; digests not recomputed locally this session.
  - claim: >-
      CIS Benchmark licensing summary (PDFs free for non-commercial use; commercial
      tailoring requires SecureSuite membership).
    checked: 2026-08 CIS terms page (via earlier session); exact current terms not re-fetched 2026-10-10.
  - claim: MITRE ATT&CK v19.2 (2026-04-28) is the current ATT&CK version.
    checked: prior session; not re-checked 2026-10-10. The licence text WAS re-read 2026-10-10.
  - claim: >-
      Corpus modifier counts (contains 3606, endswith 3687, ... zero correlation rules)
      and status counts (test 3328/experimental 336/stable 104 in the five active dirs).
    checked: >-
      2026-10-10 scan of the pinned partial clone (blob:none). Counts are per-file
      occurrences of the key text across the whole tree unless noted; they will drift as
      the corpus moves - the scan parameters are recorded so the number is reproducible,
      not frozen.
  - claim: >-
      PostgreSQL 18 date_bin/percentile_cont/startswith^@/ARE-lookahead facts.
    checked: 2026-10-10 local docs read (18; date_bin §9.9.3 + starts_with/^@ §9.4 confirmed on postgresql.org/docs/18); not re-validated against a live server.
  - claim: Stage-2 canonical payload field names used in examples (process.parent.exe etc.).
    checked: >-
      Verified fields are cited inline where used (registry.*, fim.*, config_check.*,
      powershell.script_block_text, network.bytes_sent, authentication.*, dns.query_name,
      process.exe/command_line/hashes.sha256). S-01 previously used the Stage-1-shaped
      name process.parent_image; corrected to the canonical process.parent.exe (D8-14)
      and a CI gate (§10.6 canonical-path cross-validation) now blocks any rule whose
      predicate field does not resolve in canonical_event_v1.schema.json.
  - claim: >-
      The 25 §11 examples validate against rule_schema.json.
    checked: >-
      VERIFIED 2026-10-10 (this session): all 25 blocks parse and validate under a
      strict draft-2020-12 validator (jsonschema 4.26, additionalProperties enforced);
      the DECISIONS/OPEN QUESTIONS/NOT VERIFIED YAML blocks also parse
      (20/8/12 items). The validator script is retained at
      _stage5_work/validate_examples.py and is the seed of the CI gate in 12.3.
  - claim: Bloom FPP target (~1%) and k=6 sizing.
    checked: PROPOSED arithmetic only; not benchmarked (Q5-005).
  - claim: >-
      sigma-specification tag v2.1.0 vs HEAD ba9251aa834b: spec docs identical.
    checked: >-
      Earlier session diff (tag is not an ancestor of HEAD; only ISSUE_TEMPLATE and
      convention docs differ). Not re-diffed 2026-10-10.
```

---

## Verification Log

Every primary source consulted for this stage, with pin and retrieval method. Local paths are under the working directory unless noted.

| # | Source | Pin / version | URL or path | Retrieved | What was used |
|---|---|---|---|---|---|
| V1 | sigma-specification | commit `ba9251aa834b11a70dbf80836b453dba99c5159e` (spec v2.1.0, 2025-08-02; SPDX: public domain per LICENSE) | `_stage1_work/sigma-specification/` | read locally 2026-10-10 | rules spec (logsource, detection, wildcards, escapes, `''`/`null`, exists, condition grammar incl. condition-as-list, `1/all of them`, `n of ident`, `_` exclusion, metadata fields incl. taxonomy/scope/expand); filters spec (`mf_` prefix); correlation spec (7 types, aliases, group-by, timespan regex, generate, `neq`, History 2.1.0 additions, line-236 allowed-values inconsistency); modifiers appendix (full list); `tests/schema/correlation/` fixture inventory |
| V2 | SigmaHQ/sigma (sigma-rules corpus) | commit `8a4813404ea3074890e0cda9272d4d1a8b2941d6` (partial clone blob:none; no tags; LICENSE = spec/logo public domain + rules DRL 1.1) | `_stage1_work/sigma-rules/` | read locally + scan 2026-10-10 | corpus modifier/metadata/correlation/filters counts (§3.1); active-dir status counts; `Releases.md`; LICENSE text for §10.3 |
| V3 | Detection Rules License 1.1 | DRL 1.1 full text | `_stage1_work/drl/LICENSE.Detection.Rules.md` | read locally 2026-10-10 | attribution obligations (author + URI + licence reference on sharing; author on rule-triggered messages) |
| V4 | pySigma | v2.0.0 tag == commit `50708bae1fd24c75a5342187e34c126c13c69a18` (LGPL-2.1-only, requires_python >=3.11,<4.0) | `_stage1_work/pySigma/` + PyPI JSON 2026-10-10 | read locally 2026-10-10 | licence/version pins; conformance-oracle role; tokenizer regression note |
| V5 | pySigma 2.0.0 release notes | release 2026-10-04 | GitHub API 2026-10-10 | 2026-10-10 | SigmaPolicy security control, default RE2 engine (ReDoS rationale) |
| V6 | PostgreSQL 18 docs | 18 | postgresql.org/docs/18 (read 2026-10-10) | 2026-10-10 | §9.7 hostile-regex caution + statement_timeout + `^@`/starts_with(); POSIX ARE lookahead/backref facts; §9.9.3 date_bin; percentile_cont WITHIN GROUP |
| V7 | CIS licensing/terms | terms page snapshot | cisecurity.org (read 2026-08, earlier session) | 2026-08 | non-commercial PDF terms, CC BY-NC-SA 4.0, SecureSuite commercial requirement |
| V8 | MITRE ATT&CK licence | attack-stix-data `master` LICENSE.txt (© 2016-2026 The MITRE Corporation) | github.com/mitre-attack/attack-stix-data (read 2026-10-10) | 2026-10-10 | royalty-free commercial use; mandatory copyright-designation line |
| V9 | ATT&CK versions | v19.2 (April 28, 2026); mitre/cti = STIX 2.0 | attack.mitre.org + mitre-attack/attack-stix-data (prior session) | prior session | version claim (listed under NOT VERIFIED for this session) |
| V10 | google-re2 | 1.1.20251105 (BSD-3-Clause classifier, win32/win_amd64 cp310-cp314, win_arm64 cp311+) | PyPI JSON 2026-10-10 | 2026-10-10 | RE2 dependency row |
| V11 | pyahocorasick | 2.3.1 (BSD-3-Clause + Public-Domain, win_amd64 cp310-cp314) | PyPI JSON 2026-10-10 | 2026-10-10 | keyword-set fast path dependency row |
| V12 | SigmaHQ/sigma releases | r2026-07-01 (published 2026-07-09, package archives + SHA-256) | GitHub API 2026-10-10 | 2026-10-10 | latest-release fact |
| V13 | Stage 1 | stage-1-landscape-and-rule-engine-decision.md | local | re-read 2026-10-10 | D-004 (Option C + native fallback + oracle), RED-001, §5.5-§5.8 engine contract, §6.1-§6.5 canonical rule doc + severity/level split, §2.2-§2.3 licence rules, §4.2-§4.3 out-of-scope, MVP-2 invariant, pySigma pin |
| V14 | Stage 2 | stage-2-canonical-event-and-mappings.md (DECISIONS at line 12581; D2-001…D2-024) | local | re-read 2026-10-10 | D2-014 pipelines, §3 unmapped-field fallback, fim mapping (lines 1095-1110, 3009: Security 1102 → category fim, operation audit_log_cleared), shadow_mode flag, value-state semantics |
| V15 | canonical_event_v1.schema.json | local | `$defs` registry/authentication/service/powershell/fim/config_check/artifact/artifact_finding | read 2026-10-10 | example field paths for registry/fim/config_check/powershell/authentication/network/dns/proc |
| V16 | Stage 3 | stage-3-ingestion-and-artifact-triage.md §12 (lines 3055-3159) | local | read 2026-10-10 | AF-001…AF-005 verbatim; D3-024 runner; D3-029 finding vocabulary; D3-031 scanner confinement; fact namespaces (ooxml/pdf/pe/motw/lnk/signature); line 2019 LNK facts; line 2045 authenticode facts |
| V17 | Stage 4 | stage-4-threat-model-and-windows-sandbox.md | local | format + D4-003/D4-004 re-read (prior in-session) | decision/verification-log format; signing posture; ReDoS mandate; T-04/T-06/T-12 threat hooks |
| V18 | rule_schema.json | draft 2020-12, this stage | local companion file | written + JSON-parse-validated 2026-10-10 | normative stored-document contract; machine validation of §11 examples still pending (NOT VERIFIED) |
