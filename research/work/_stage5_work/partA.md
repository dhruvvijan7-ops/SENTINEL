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
