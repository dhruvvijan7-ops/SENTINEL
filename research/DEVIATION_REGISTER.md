# Deviation Register

Every place the delivered tree diverges from the authored specification, with
the precedence rule that authorises it. Nothing here is a silent edit: spec
§1.1 makes `consistency_report.md` the conflict register, and this file is the
**amendment** register — it records changes *we* made to the contract at M0,
plus the one pre-M0 defect that was resolved rather than amended.

Precedence reminder (spec §1.1):

| Rank | Artifact | Role |
|---|---|---|
| 1 | `canonical_event_v1.schema.json`, `rule_schema.json` | machine-normative contracts |
| 2 | `schema.sql` | storage contract |
| 3 | `openapi.yaml` | HTTP surface contract |
| 4 | stage bodies (Stages 1–6, spliced into §4–§8) | design intent, rationale |
| 5 | `verification-log.yaml`, `VERIFICATION_LOG_2026-10-09.yaml` | evidence |

An amendment at rank 2 or 3 does **not** silently override rank 4 prose — it is
recorded here and, where the spec states a number that changed, the spec text is
amended with an `M0-A*` marker so a reader of the spec alone is never misled.

---

## History (resolved before M0)

### M1-D3 — `raw_objects` was RLS-enabled but policy-less

* **Defect.** `schema.sql` shipped `ALTER TABLE raw_objects ENABLE ROW LEVEL
  SECURITY` with **no** `CREATE POLICY` for that table. Under PostgreSQL RLS
  semantics, an enabled table with no policy denies everything to non-owners —
  so the application role (no `BYPASSRLS`, not the owner) could neither read
  nor insert accepted objects. The rationale comment ("access is mediated
  entirely through uploads (app-level join)") describes an *application-layer*
  scoping decision; it does not satisfy the *database-layer* requirement that
  an enabled table needs at least one policy.
* **Citation defect.** `migrations/versions/0003_raw_objects_policy.py:10`
  cited a decision id `M1-D3` that existed in no register — a dangling
  reference (same class of defect as C-14/C-15, which Stage 8 fixed).
* **Resolution (M0).** The policy `raw_objects_cas` (`USING (true) WITH CHECK
  (true)`) now lives **in `schema.sql`**, so a database created from the
  contract text has it by construction. Migration `0003` is retained for
  databases built before M0 and rewritten to be **idempotent**
  (`IF NOT EXISTS (SELECT FROM pg_policies …)`), so a fresh database no-ops.
  The dangling citation is replaced by a pointer to this register.
* **Classification.** Defect resolution, not an amendment: no spec-stated
  number or shape changed. `raw_objects` gains the one policy it was always
  required to have.
* **Gate.** `tests/contract/test_rls_lint.py` — "every ENABLEd table has ≥1
  `CREATE POLICY`". This is the check that would have caught the defect at
  authoring time.

---

## M0 amendments

### M0-A1 — partition-level RLS

* **Amended.** `schema.sql` §9 now enables RLS **and** creates a
  workspace-scoped policy on all **11** partition children:
  `events_2026_10/11/12`, `findings_2026_10/11/12`, `audit_log_2026_10/11/12`,
  `rule_baseline_2026/2027`.
* **Why.** Declarative partition children do **not** inherit
  `ENABLE ROW LEVEL SECURITY` from the parent, and `CREATE POLICY … ON parent`
  does not reach children. Without this, a `SELECT` aimed *directly* at a
  partition (a maintenance job, a partition swap, a `pg_dump` of a single
  partition, or a query the planner cannot route through the parent) bypassed
  the tenant check that spec §6.4a requires of "every scoped table".
* **Spec number amended.** Spec §6.4a (line 19565) said "all 20 policies".
  The true post-M0 count is **32**: 20 base-table policies + 11 partition
  policies + 1 `raw_objects_cas` exemption. *(The M0 plan text said 31; the
  arithmetic was off by one because there are 11 partition children, not 10 —
  events×3 + findings×3 + audit_log×3 + rule_baseline×2. The spec is amended to
  the true count, and the count is now machine-pinned rather than prose.)*
* **Precedence.** `schema.sql` is rank 2; §6.4a is rank 4. The DDL is the
  storage contract and wins; the prose is amended with this marker rather than
  left stale.
* **Migration.** `migrations/versions/0004_partition_rls.py`, idempotent, for
  databases already at 0003.
* **Gate.** `tests/contract/test_rls_lint.py` (static: policy count == 32, and
  every partition child is enabled + policed) and
  `tests/integration/test_rls.py` (dynamic: direct `SELECT` against a partition
  returns 0 rows unscoped / only own rows scoped).

### M0-A2 — configuration keys required by the 3-role docker topology and the running processes

* **Amended.** Spec §4 (the configuration reference) gains **seven** keys that
  the delivered implementation needs and the spec table omitted:

  | Key | Type | Default | Why |
  |---|---|---|---|
  | `database.migrator_url` | str | — | the migration role's DSN; a separate login because migrations need DDL rights the app role must not have |
  | `database.worker_url` | str | — | the BYPASSRLS worker role's DSN |
  | `worker.poll_interval_ms` | int | 200 | the worker process's idle poll interval; §4's `jobs.*` keys are queue *policy*, not process tuning |
  | `ingest.max_concurrent_uploads_per_principal` | int | 4 | upload concurrency cap (§3.2 rate-limit family) |
  | `ingest.upload_hourly_quota_per_principal` | int | 500 | upload quota |
  | `ingest.storage_quota_bytes` | int | 50 GiB | storage quota |
  | `auth.dev_keys` | array of tables | — | the Stage-6 auth service does not exist yet; M1 binds each dev API key to one principal/tenant/workspace |

  *(The register's first draft listed five; `worker.poll_interval_ms` and
  `auth.dev_keys` were discovered when `Settings` was rewritten field-by-field
  against the §4 table. Seven is the count that matches the delivered tree.)*

* **Why.** `docker-compose.yml` runs three roles (owner / app / worker) and the
  code needs a distinct DSN for the migrator and the worker; §4 only specified
  `database.url`. The three ingest keys are the §3.2 rate-limit/admission
  controls expressed as configuration rather than constants.
* **Precedence.** Spec §4 is rank 4 prose describing rank-2/3 artifacts; adding
  keys that the implementation requires does not contradict any higher-rank
  artifact. Recorded here so the omission is visible and the keys are frozen
  rather than discovered.
* **Gate.** `tests/contract/test_config_freeze.py` — every extension key must
  be listed in `configs/config_keys.json` with `origin: "M0-A2"` **and** named
  in this register (`test_a2_keys_are_declared_in_the_deviation_register`),
  otherwise the freeze test fails. A key cannot be added to `Settings` without
  either a spec table row or an `M0-A2` manifest entry.

### M0-A3 — contract files live at the repository root, not `schemas/`

* **Amended.** Spec §8's repository-layout tree shows
  `schemas/  # canonical_event_v1.schema.json, rule_schema.json, openapi.yaml`.
  In the delivered tree all three live at the **repository root**.
* **Why.** Root is what spec §1.4 ("Create the database from `schema.sql`…
  Serve `openapi.yaml`…") points implementers at, and — decisively —
  `openapi.yaml`'s two **external** `$ref`s are bare relative filenames
  (`canonical_event_v1.schema.json#/$defs/host`, `rule_schema.json`), which
  resolve only from the root. Moving the files into `schemas/` would break
  every external ref unless the spec AND the ref strings were changed together.
* **Precedence.** §8 is rank 4; `openapi.yaml` is rank 3. The rank-3 artifact
  wins; §8's tree is amended with this marker.
* **Gate.** `tests/contract/test_openapi.py::test_every_external_ref_names_an_existing_file`
  — the external refs must resolve from the root; relocating the files fails
  the gate immediately.

---

## M1 amendments

### M1-A1 — the operator-retry `409` carries a bare `message`, not an `Error` object

* **Amended.** `openapi.yaml` declares the `retryJob` `409` as
  `{ description: Job is not in a retryable state }` — **no content schema** —
  while every other error response in the document resolves to
  `components.schemas.Error` (`code` + `message` required). The delivered
  route returns `{"message": "job is not in a retryable state"}` for that case.
* **Why.** Two frozen contracts collide. Stage-3 §1.5 (and `sentinel_core/errors.py`)
  freezes the code vocabulary to the `GATE_*` set and forbids inventing codes;
  no member of that set means "job is not in a retryable state". Wrapping the
  409 in an `Error` object would therefore require either a new code (rank-4
  violation) or a code that lies about the failure. `openapi.yaml` (rank 3)
  imposes no body here, so the only shape that satisfies both constraints is a
  bare message.
* **Precedence.** `openapi.yaml` is rank 3 and says nothing about the body;
  §1.5 is rank 4 and forbids new codes. Neither is overridden — the gap between
  them is what this entry records.
* **Gate.** `tests/contract/test_openapi.py` (23 paths / 35 operations frozen,
  so no schema can be added at M1 without an explicit rank-3 amendment) and
  `tests/integration/test_queue_lifecycle.py::test_operator_retry_conflicts_while_the_job_is_active`
  (pins the `409` + body shape).

### M1-A2 — a `401` denial cannot be attributed in `audit_log`

* **Amended.** Spec §5.4 requires that "every mutating API call and operator
  action writes an `audit_log` row, **denied attempts included**". Delivered
  behaviour: denials that resolve to a principal are audited
  (`upload.reject`, `run.create`, `job.retry` with `outcome='denied'`);
  denials raised *before* a principal is resolved — `401
  GATE_UNAUTHENTICATED`, missing/garbage `X-API-Key` — are **not** audited.
* **Why.** `audit_log` is workspace-RLS-scoped (rank 2): the app role has no
  legal insertion point outside the caller's own `tenant_id`/`workspace_id`.
  A 401 caller has asserted no tenant and no workspace, so writing a row would
  mean either fabricating an identity (an unauthenticated caller choosing
  where evidence lands) or writing with the BYPASSRLS worker role (an
  unauthenticated input escalating to a platform role). Neither is acceptable;
  the HTTP surface's own access log carries the transport-level record instead.
* **Precedence.** §5.4 is rank 4 prose; `schema.sql`'s RLS policies are rank 2.
  The storage contract wins where the two cannot both be satisfied.
* **Gate.** `tests/integration/test_audit.py` — four denied-attribution tests
  prove principal-bearing denials *are* recorded, and
  `test_audit_reader_requires_authentication` pins the unauthenticated path to
  `401` without an audit row. When the Stage-6 auth service exists, this entry
  should be re-opened: a principal-less `auth.denied` action in a platform-owned
  audit partition is the intended fix.

---

## M2 amendments

### M2-A1 — the §4.6 budget is a statement-size cap that falls back, not an `EXPLAIN` estimate that quarantines

* **Amended.** §4.6 gives `standard`/`heavy` rules a compile-time budget read
  from an "`EXPLAIN` estimate at compile" and says an exceeded rule is
  "quarantined for job". Delivered: the budget is the generated statement's
  byte length against `MAX_SQL_BYTES` (64 KiB,
  `packages/detect/sentinel_detect/compile.py:59`), and exceeding it flips
  `detection_path` to `native` while registering `COST_BUDGET_EXCEEDED`
  (`compile.py:528-536`). The rule keeps running — on the other path — and is
  never quarantined.
* **Why.** What actually threatens the detect job at M2 is parsing and
  planning a very large statement at job start (the SQL is stored and never
  re-parsed — §1.10 invariant 7), not a row-count blow-up. An `EXPLAIN`
  estimate needs a representative statistics snapshot an M2 deployment does
  not guarantee, and quarantining would drop coverage for a rule that has a
  working fallback. The reason code is still emitted, so §4.6's real
  invariant — never silent — holds.
* **Precedence.** The budget column is explicitly `PROPOSED - TO BENCHMARK`
  (§4.6); the reason code and the never-silent rule are normative. Nothing
  is overridden — only the *measurement* behind the proposal differs.
* **Gate.** `tests/unit/test_evaluate_keywords.py` (asserts the SQL exceeds
  `MAX_SQL_BYTES`, flips to native and reports `COST_BUDGET_EXCEEDED`, and
  that a smaller statement stays on `sql`), plus
  `tests/integration/test_m2_exit.py::test_m2_exit_1_planted_finding_matches_the_manifest`,
  which pins the ordinary rule to `detection_path: sql`.

### M2-A2 — `/evidence/{findingUid}` never returns a presigned raw URL

* **Amended.** `openapi.yaml` documents the bundle as "snapshot plus optional
  presigned raw link" and `EvidenceBundle.raw_object` declares `presigned_url`
  and `expires_at` (`openapi.yaml:417-423`, `:1028-1036`). Delivered: while
  the object is `hot` the route returns `{sha256, size}` only
  (`apps/api/sentinel_api/routes_findings.py:197-210`); there is no URL
  minting anywhere in the API.
* **Why.** The fields are optional in the schema (only `finding_uid` and
  `evidence_snapshot` are required), and minting a signed URL needs a storage
  backend that can do it: `OQ-6-03` (S3-compatible backend) is still open, and
  the local `LocalObjectStore` serves files that the API never exposes
  directly. Returning `sha256`/`size` is the honest, verifiable locator that
  both backends can answer.
* **Precedence.** `openapi.yaml` is rank 3 and declares both fields optional;
  the rank-3 prose is the only text that outranks this entry, and it is
  amended here rather than silently contradicted.
* **Gate.** `tests/integration/test_m2_exit.py::test_m2_exit_2_evidence_outlives_the_raw_object`
  pins the hot/purged/`None` three-state behaviour and the R1 invariant that
  the snapshot is byte-identical across the purge.

### M2-A3 — `warmup_action: flag` is not implemented; every cold-start rule suppresses

* **Amended.** §4.8 offers `warmup_action: suppress` (default) *or* `flag`
  ("emit LOW findings carrying `baseline.warmup=true` and the code").
  Delivered: `_prepare()` only ever splits into (runnable, suppressed) — there
  is no third, flagging branch
  (`packages/detect/sentinel_detect/runner.py:104-110`); a rule whose document
  asks for `flag` behaves exactly like `suppress`.
* **Why.** `flag` needs the warm-up finding path (severity override,
  `baseline.warmup` in the evidence snapshot) that belongs with the
  statistical window engine, which M2 does not ship (M2-A4). Suppression is
  the safe half of the §4.8 contract: it can only under-report, and it always
  reports the code — "never silent silence" (§4.8) is preserved.
* **Precedence.** §4.8's universal rule ("warm-up never fabricates a pass")
  is honoured in full; only the optional *visible* variant is deferred to M3,
  which the §9 M3 row already scopes as "statistical baselines".
* **Gate.** `tests/integration/test_m2_exit.py::test_m2_exit_4_missing_baseline_is_reported`
  and `::test_m2_exit_4_warmup_baseline_is_reported` (suppressed + code +
  `completed_with_warnings`), `::test_m2_exit_4_a_valid_baseline_lifts_the_suppression`
  (the gate opens once `min_observations` is met).

### M2-A4 — `kind: statistical` has no execution engine at M2

* **Amended.** §9.1 specifies the statistical rule shape (rate / rare_value /
  proportion over `date_bin` buckets). Delivered at M2: the rule *content*
  parses and validates and is classified by the cold-start gate, but no bucket
  evaluator exists — `plan()` on a document with no Sigma `condition` raises
  `CompileError`, which the run loop reports as `outcome="error"` with
  `UNSUPPORTED_CONDITION_FORM` (`packages/detect/sentinel_detect/runner.py:248-259`),
  so a statistical rule that is *ready* runs into an accounted error rather
  than producing findings.
* **Why.** M2 is deliberately the narrowest vertical slice (§9 note under the
  milestone table): EVTX/Sysmon → Sigma → evidence → timeline. The window
  engine, the bucket table and the estimators are Stage-5 §9 work, and the §9
  M3 row already claims "statistical baselines" as its own content.
* **Precedence.** Nothing in §9.1 claims M2 execution; exit ④ asks only that
  the cold-start *codes* appear, which they do.
* **Gate.** `tests/integration/test_m2_exit.py` exit④ (three tests above) and
  `tests/contract/test_fixture_corpora.py`, which keeps the two committed
  statistical examples schema-valid.

### M2-A5 — RESOLVED: exit ⑤ (conformance oracle) now has a committed gate

* **Then (deferred).** §9 M2 ⑤ requires "the conformance oracle runs on the
  golden corpus with zero unexplained divergences". The oracle ran locally
  over the fetched corpus but neither it nor the corpus was committed: the
  corpus was gitignored under the original D6-009/§6.2 and CI fetches
  nothing. A gate that would pass vacuously was considered worse than none.
* **Now (gated).** The oracle is committed at `tools/conformance_oracle.py`,
  the golden corpus at `tests/conformance/rules/` (20 SigmaHQ rules pinned at
  `8a4813404ea3074890e0cda9272d4d1a8b2941d6` byte-identical to upstream, plus
  3 Sentinel-authored rules covering `gt/gte/lt/lte`, `neq` and `exists`,
  `cased`/`i`, which the pinned corpus does not use), and the gate at
  `tests/integration/test_conformance_oracle.py`. Spec §9b row ⑤ names that
  gate; `tests/contract/test_m2_exit_gates.py` fails if it is renamed,
  deferred again or dropped from CI.
* **Why committing it is allowed.** D6-009 was revised for test corpora:
  SigmaHQ rules are **DRL-1.1** (MIT-based; distribution and modification
  permitted with the copyright/licence notice and author attribution, which
  `tests/conformance/ATTRIBUTION.md` and each rule's untouched `author` field
  provide). The revision does **not** extend to datasets: raw captures stay
  out of the tree (§6.3), and the oracle's events are the project's own
  fixtures plus values synthesized deterministically from each rule's own
  selections.
* **What the gate asserts.** One rolled-back transaction; identical finding
  sets from the SQL compiler and the native evaluator for every comparable
  rule; native-only fallbacks confined to the registered reason codes
  (`REGEX_NATIVE_ONLY`, `FIELDREF_NATIVE_ONLY`, `KEYWORD_NATIVE_ONLY`,
  `NATIVE_BY_COMPILE`); `expected.json` (per-file sha256 + compiled
  classification + author) still matches the corpus; attribution present.
  Measured on the committed corpus: 23 rules, 19 comparable, 4 native-only,
  167 events, **0 divergences**, 16 of 19 comparable rules firing, 174
  matched pairs.
* **Defects the oracle found (all fixed here, each covered by the gate).**
  1. `compile._text_predicate` called `.match()` on `_NUMERIC_RE`, a plain
     string — every `lt/lte/gt/gte` rule crashed the compiler
     (`packages/detect/sentinel_detect/compile.py:49`).
  2. The native evaluator had no `neq` branch at all and silently evaluated
     `field|neq: v` as `field == v`, the exact opposite of the SQL path
     (`packages/detect/sentinel_detect/evaluate.py:_match_with_mode`).
  3. The SQL null predicate for `unmapped.<Field>` was missing the
     `t.el->>'name' = <field>` predicate, so a rule asking for a null/`-`
     value matched *any* unmapped entry carrying the dash sentinel — native
     is name-scoped, SQL was not
     (`packages/detect/sentinel_detect/compile.py:_leaf_sql`).
* **Gate.** `tests/integration/test_conformance_oracle.py` (5 tests) in CI's
  `integration` job, plus `tests/contract/test_m2_exit_gates.py` pinning §9b
  row ⑤ to it.

### M2-A6 - RESOLVED: exit ⑥ (UNSW-NB15) now has a committed gate

* **Then (deferred).** §9 M2 ⑥ asks that UNSW-NB15 flow rows parse to
  `network_connection` events with zero drops and that a scored run report F1
  and per-category recall. Delivered first: nothing — M2's ingest was
  EVTX/Sysmon only, the dataset was unfetched (OQ-6-04), and scoring needed
  the label/attack_cat corpus plumbing.
* **Now (gated).** The corpus is fetched out-of-tree by
  `tools/corpus_fetch.py` into `.corpus/unsw-nb15/` with sha256 + byte-size +
  row-count pins (`tools/evaluate_unsw_nb15.py:PINNED`) and a citation
  manifest (Moustafa & Slay, MilCIS 2015 — V-6-035; attribution is part of
  the gate, a manifest without it fails the run). The mapper is
  `packages/ingest/sentinel_ingest/unsw_nb15.py` driven by the
  `unsw_nb15_network_flow` pipeline (M2-A10); the gate is
  `tests/scoring/test_unsw_nb15_scoring.py` over fixtures in
  `tests/scoring/conftest.py` with the pack frozen at `tests/scoring/rules/`
  (6 rules, tuned on the training split, reported on the testing split). It
  asserts rows == pins, dropped == 0, schema-invalid documents == 0, all nine
  attack categories scored, and F1 / precision / recall / FPR plus minimum
  per-category recall at or above the frozen baseline on **both** splits —
  and it fails, never skips, when the corpus is absent.
* **Measured (2026-10-12, `bench/unsw_nb15_scoring.json`).** Train
  P .954 / R .885 / F1 .918 / FPR .092; test P .838 / R .939 / F1 .886 /
  FPR .223; per-category test recall .764–1.000; 257 673 rows, 0 dropped,
  0 invalid. Two engine defects surfaced by this corpus and fixed here:
  `_as_text` rendered floats as `1e-05` while SQL sees jsonb plain decimal
  `0.00001` (sub-1e-4 numeric comparisons diverged between paths), and
  non-finite floats would have produced invalid JSON for PostgreSQL.
* **Why the dataset is still out-of-tree.** D6-009 was revised for *rule*
  corpora only; UNSW-NB15's academic-use / no-commercial terms (V-6-035)
  keep the CSVs in `.corpus/`, with the fetch tool, the pins and the
  citation manifest as the reproducible path.
* **Precedence.** §6.3a is a method specification (rank 4); no rank 1–3
  contract is touched, and spec §9b row ⑥ now names the gate instead of the
  deferral.
* **Gate.** `tests/scoring/test_unsw_nb15_scoring.py` in CI's `scoring` job
  (`tools/corpus_fetch.py` → `pytest tests/scoring`), plus
  `tests/contract/test_m2_exit_gates.py` pinning §9b row ⑥ to it.

### M2-A7 — the time extractors are rejected (`UNSUPPORTED_MODIFIER`), not compiled

* **Amended.** §3.4's SUPPORTED row lists `minute`, `hour`, `day`, `week`,
  `month`, `year` (extract a component from a timestamp for comparison).
  Delivered: they are recognised but rejected at normalize time with
  `UNSUPPORTED_MODIFIER`
  (`packages/detect/sentinel_detect/normalize.py:76-78` and `:306-313`), so a
  rule using one fails to import rather than silently comparing the wrong
  thing.
* **Why.** A timestamp extractor needs a *guarded* cast
  (`t.el #>> '{}'::timestamptz` only when the element really is a timestamp)
  that plain SQL cannot express without risking a per-row error, and the
  pinned corpus uses them **zero** times — measured over all 3 152 rule files
  at `8a4813404ea3074890e0cda9272d4d1a8b2941d6`. Rejection is the never-silent
  half of §3.1; implementing them would be speculative code with no corpus to
  validate it against.
* **Precedence.** §3.4 marks them SUPPORTED (rank 3), but §3.1 also requires
  that an unimplemented construct must never be *silently* mis-evaluated. The
  rejection honours the stronger of the two and is recorded here rather than
  left as a gap.
* **Gate.** The corpus scan itself (0 usages) plus
  `tests/integration/test_conformance_oracle.py`, which fails if a corpus rule
  ever starts using a rejected modifier (the rule would stop compiling and its
  `fallback_reason` would leave the registered set).

### M2-A8 — `windows_process_creation` was added to the frozen mapping table

* **Amended.** §`(sigma_field_mapping_pipelines.yaml)` (spec lines 2708-2971)
  is transcribed verbatim as `configs/sigma_field_mapping_pipelines.yaml`.
  One pipeline was added: `windows_process_creation`
  (`configs/sigma_field_mapping_pipelines.yaml:59`), a two-key
  `logsource: {product: windows, category: process_creation}` pipeline.
* **Why.** SigmaHQ writes that two-key shape for the majority of process
  rules; without it neither `sysmon_process_creation` nor `security_process`
  (both requiring a `service:`) is eligible, so those rules would map no
  fields at all. Eligibility is `pipeline.logsource ⊆ rule.logsource` and the
  most specific eligible pipeline wins, so rules that do name
  `service: sysmon` still take the Sysmon pipeline — the addition cannot
  change the mapping of any rule that already mapped.
* **Precedence.** The spec table is rank 3 data, and this is an addition, not
  a change: no existing entry was edited, which is why it is recorded as an
  amendment instead of silently growing the file.
* **Gate.** `tests/contract/` mapping tests, the M2 planted-finding drill
  (`tests/integration/test_m2_exit.py`, exit ① — the planted rule is a plain
  `product: windows` / `category: process_creation` rule and only resolves
  through this pipeline), and the conformance corpus, which is dominated by
  that same logsource shape.

### M2-A9 — `re`, `fieldref` and `cidr` are native-only (no SQL predicate)

* **Amended.** §3.4 lists `re`/`fieldref`/`cidr` as SUPPORTED (i.e. the rule
  runs). Delivered: they are evaluated by the native evaluator only; the SQL
  compiler emits **no** predicate for a rule whose selector needs them and
  records `REGEX_NATIVE_ONLY` / `FIELDREF_NATIVE_ONLY` /
  `KEYWORD_NATIVE_ONLY` as the fallback reason
  (`packages/detect/sentinel_detect/normalize.py:61-65`, compiler fallback in
  `compile.py`).
* **Why.** RE2 syntax never crosses into PostgreSQL `~` (different regex
  dialect, different catastrophic-backtracking guarantees), `fieldref` needs a
  second projection of the same element, and `cidr` needs a guarded `inet`
  cast that plain SQL cannot express. Forcing any of them into SQL would
  either change match semantics between the two paths (the exact failure the
  conformance oracle exists to catch) or risk per-row errors.
* **Precedence.** §3.4 says the modifier is supported — and it is, on the
  native path, which is a first-class path at M2 (`detection_path: native` is
  an accounted outcome, §4.1). The reason codes keep the fallback visible
  (§4.6 never-silent), so no rank-2/3 invariant is contradicted.
* **Gate.** `tests/integration/test_conformance_oracle.py` asserts every
  native-only fallback carries one of the registered reasons (and that the
  corpus's 4 such rules stay classified that way in `expected.json`), plus the
  unit coverage for keyword evaluation.

### M2-A10 - `unsw_nb15_network_flow` was added to the frozen mapping table

* **Amended.** §`(sigma_field_mapping_pipelines.yaml)` (spec lines 2708-2971)
  is transcribed verbatim as `configs/sigma_field_mapping_pipelines.yaml`.
  One more pipeline was added: `unsw_nb15_network_flow`
  (`configs/sigma_field_mapping_pipelines.yaml:315`), keyed by
  `logsource: {product: unsw-nb15, category: network_connection}`.
* **Why.** UNSW-NB15 rows carry source-style column names (`sbytes`, `sttl`,
  `dttl`, `ct_state_ttl`, `service`, `dur`, …). Without a pipeline those keys
  would land in `unmapped` under a double prefix, so no detection could
  select them and exit ⑥ could not be scored at all. Eligibility is
  `pipeline.logsource ⊆ rule.logsource` and the most specific eligible
  pipeline wins; the product token `unsw-nb15` appears in no SigmaHQ
  `logsource`, so this pipeline can never become eligible for — and never
  changes the mapping of — any rule that already mapped.
* **Precedence.** Rank-3 data by addition, not by change: no existing entry
  was edited, which is why it is recorded here rather than silently growing
  the file (same posture as M2-A8).
* **Gate.** `tests/scoring/test_unsw_nb15_pack.py` (every detection field a
  rule selects must resolve through a pipeline; ground-truth keys are banned
  from `detection`) and `tests/scoring/test_unsw_nb15_mapping.py` (the
  pipeline-mapped document is what both validators and the harness score).

---

## Register shape

Entries are prose here (they are decisions, not data). The machine-readable
side of M0's verification surface lives in:

* `tests/fixtures/manifest.json` — fixture provenance
* `configs/config_keys.json` — frozen configuration keys + origins
* `research/verification/DEPENDENCY_LICENCES.yaml` — licence verification rows
* `tests/contract/test_rls_lint.py::FROZEN_POLICY_COUNT`,
  `::FROZEN_TABLE_COUNT`, `::FROZEN_PARTITION_COUNT` — frozen schema numbers

Any change to one of those constants without a matching entry above is a
contract regression, and the corresponding gate fails in CI.
