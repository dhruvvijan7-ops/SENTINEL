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
