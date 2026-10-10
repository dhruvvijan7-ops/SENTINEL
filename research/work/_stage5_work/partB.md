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

### 4.2 Two residence modes, one contract

Stage 1 D-004 Option C makes SQL-over-events the primary engine; Stage 3's `artifact_fact`/`config_check` pipeline and Stage 4's ReDoS posture (D4-004) require a native evaluator to exist as well. The same rule document compiles for both; `detection_path` on every finding names which one fired.

| Mode | Where predicates run | `process()` | `finalize()` | Used when |
|---|---|---|---|---|
| **db-resident (default)** | PostgreSQL, over `events` rows filtered by `run_id` + pushed-down `prepared` prefilters | no-op | executes the stored `compile.sql`, streams rows back as findings | events already ingested to Postgres (MVP path) |
| **stream** | native (RE2 + stdlib), on the event bus | evaluate the native plan per event, buffer window-relevant tuples | windows/correlations execute over the job's buffered tuples | bus-native workloads, or any rule whose `cost_class` is `heavy` with a stream-shaped prefilter |

The **streaming reconciliation rule** (binding, D-022): SQL detectors query events by `run_id` in `finalize()`; stream detectors buffer into the job workspace during `process()`. Prefilters mean two different things per mode — index-usable envelope predicates for SQL, fast-reject predicates for native — and both are produced from the same `prepared` list, so the pushdown layer is shared (Stage-1 §5.6.2).

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
