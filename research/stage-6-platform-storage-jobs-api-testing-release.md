# Stage 6: Platform — Storage, Jobs, API, Testing, Release

**Status:** Draft for review
**Date:** 2026-10-10
**Inherits:** Stage 1 (D-001…D-012, §2 licence taxonomy, §5.7 PoC protocol T1/T2/T3-a/T3-b, MVP list), Stage 2 (`canonical-event/v1`, D2-001…D2-024, 26 categories, value-state model), Stage 3 (D3-001…D3-037, §1 gate + accepted-upload record, §12 artifact facts, ExternalProcessRunner budgets), Stage 4 (D4-001…D4-0xx, sandbox budgets, threats T-01…T-12), Stage 5 (D5-001…D5-016, seven rule kinds, `rule_run` accounting, cold-start policy, ReDoS four layers)
**Companion files:**
- [`schema.sql`](schema.sql) — PostgreSQL 18 DDL (tenancy RLS, partitioning, evidence snapshots, retention, job queue)
- [`openapi.yaml`](openapi.yaml) — OpenAPI 3.1.0 REST surface
- [`rule_schema.json`](rule_schema.json) — inherited from Stage 5 (rule document contract)

**Claim labels (house rule, Stage-1 preamble):** `VERIFIED` = read from a named primary source this stage (URL + fetch date 2026-10-10, or local pin); `INFERRED` = derived reasoning over verified facts; `UNVERIFIED` = believed but unchecked. Every quantitative number in this document is **PROPOSED - TO BENCHMARK** until a measurement run produces MEASURED values (protocol: §6.6). Licence rows repeat Stage-1 §2 classifications with this stage's additions; nothing here overrides Stage-1 legal gates. Where Stage 5 referenced PoC tasks "T4"/"T7", no such tasks exist — Stage 1 §5.7 defines exactly T1, T2, T3-a, T3-b; this stage does not invent T4–T7.

**Non-negotiables this stage must satisfy (reject conditions from the brief):**

| # | Reject condition | Where satisfied |
|---|---|---|
| R1 | Evidence lost when raw files expire | §1.5 `evidence_snapshot` invariant + `schema.sql` `findings.evidence_snapshot`; drill in M2 exit criteria (§9) |
| R2 | No tenancy fields / no RLS | §1.3; every tenant-scoped table has `tenant_id` + `workspace_id` + an ENABLEd RLS policy (`schema.sql` §9) |
| R3 | Unverified Windows support for the job library | §2.2: we own the queue; the only cross-platform dependencies are PostgreSQL 18 (VERIFIED) and psycopg-binary (VERIFIED win_amd64 cp312 wheels); pgqueuer's `windows-latest` CI is recorded as the vetted alternative (VERIFIED) |
| R4 | No measurement protocol | §6.6 (platform harness: ingest throughput, queue latency, API p95 — method mirrors Stage-1 §5.7 discipline) |
| R5 | Milestones without exit criteria | §9: every milestone has an exit-criteria table |

---

## 1. Storage Design (`schema.sql`)

### 1.1 Engine and conventions

PostgreSQL **18** — current stable as of 2026-10-10 (VERIFIED: postgresql.org homepage news item is "PostgreSQL 19 Beta 4"; docs `current` resolves to PostgreSQL 18). PostgreSQL 19 is excluded until GA and a re-benchmark. Licence: PostgreSQL Licence (BSD/MIT-like, VERIFIED 2026-10-09 against postgresql.org/about/licence).

- Primary keys are `uuidv7()` (VERIFIED: native in PG 18, `docs/18/functions-uuid.html` — "Generates a version 7 (time-ordered) UUID") where time-ordering matters (events, findings, jobs, uploads); `gen_random_uuid()` (pgcrypto) elsewhere. Application-supplied UUIDs are accepted from the API layer for cross-system stability (rule ids, per Stage 1 §6.2).
- All monetary-like counters are `bigint`; all timestamps are `timestamptz`; the database never stores a timestamp without timezone.
- The migration role owns tables; the application role is a separate login with `GRANT`ed DML only — no `BYPASSRLS`, no ownership. This is what makes RLS enforceable rather than advisory (INFERRED from the RLS threat model: an owner bypasses its own policies — VERIFIED behaviour, docs/18/ddl-rowsecurity.html "table owners normally bypass").

### 1.2 Table inventory (21 logical tables + 11 monthly partitions = 32 `CREATE TABLE` statements in `schema.sql`)

| Group | Tables | Notes |
|---|---|---|
| Tenancy | `tenants`, `workspaces`, `principals` | seeded literals `default`/`default` (D-001, single-tenant-first) |
| Raw store | `raw_objects`, `uploads` | content-addressed CAS (Stage 3 §1.7) + accepted-upload record (Stage 3 §1.6), dedup by refcount |
| Events | `events` + monthly partitions | full `canonical-event/v1` envelope in `document` JSONB + typed columns for indexes; partitioned by `ingest_time` (D6-016) so nullable `event_time_utc` (D2-003) never routes to a special partition |
| Rules | `rules`, `rule_source` | Stage 5 D5-001 storage split; verbatim upstream never dropped |
| Rule state | `rule_baseline` (+ partitions), `fim_baseline`, `ioc_pack`, `ioc_entry` | consumed at `prepare()` (Stage 5 §4.8 cold-start policy). `ioc_pack.status` defaults to **`pending_verify`** (C-11-fix, was `active`): packs arrive unverified and only flip to `active` after Ed25519 signature verification per D4-003 — verify-then-activate, never activate-by-default |
| Jobs | `jobs`, `job_attempts` | §2 queue; claim partial index; idempotency unique index |
| Detection | `detection_runs`, `rule_run`, `findings` (+ partitions) | `rule_run` columns match Stage 5 §4 accounting verbatim (C-5-fix: Stage-5 `job_id` ≡ `run_id`; `max_window_ms`/`sql_ms`/`native_ms` now real columns); `findings` carries `author` (DRL 1.1) and `level_original` (C-3b-fix) |
| Artifact | `artifact_facts` | Stage 3 §12; `artifact_finding` output is an `events` row, not a second table |
| API plumbing | `idempotency_keys`, `audit_log` (+ partitions), `retention_policies` | gate reject audit (Stage 3 §1.5), operator trail |

### 1.3 Tenancy and RLS (reject-condition R2)

Every tenant-scoped table carries `tenant_id` + `workspace_id` and has `ENABLE ROW LEVEL SECURITY` plus a policy comparing the row to `current_setting('sentinel.tenant_id', true)` / `('sentinel.workspace_id', true)`. The application sets these session GUCs per request/transaction (`set_config(..., true)` = transaction-local). Consequences:

- An unset GUC returns `NULL`; `col = NULL` is never true — an unscoped session sees **zero rows**, fail-closed (INFERRED from SQL semantics; this is the intended default).
- The upload gate's principal→tenant binding (Stage 3 §1.5 `GATE_TENANT_MISMATCH`) is enforced twice: at the router (rejects before Postgres) and by RLS (rejects if the router is bypassed).
- Child tables without their own tenant columns (`job_attempts`, `rule_run`) carry policies that EXISTS-join the parent under the same GUCs.

**D6-012 (INFERRED):** `raw_objects` has no tenant column — the CAS is shared across workspaces by design (dedup of identical bytes); access is mediated exclusively through `uploads` joins in the API layer. The alternative (tenant-scoped CAS, forfeiting cross-workspace dedup) is recorded as OQ-6-07. Rejected-upload audit rows (Stage 3 §1.5) live in `audit_log`, not in `uploads`.

### 1.4 Partitioning (VERIFIED mechanism)

`events`, `findings`, `audit_log`, `rule_baseline` are RANGE-partitioned by month (declarative partitioning, VERIFIED `docs/18/ddl-partitioning.html` §5.12.2: "PostgreSQL allows you to declare that a table is divided into partitions"). Partition keys are chosen so the key column is always populated and so PostgreSQL's unique-constraint rule (unique/PK on a partitioned table must include all partition key columns — VERIFIED V-6-039) does not collide with nullable business columns:

- `events` → `ingest_time` (always present; retention runs from ingest, D6-016). `event_time_utc` remains NULLable per Stage 2 D2-003 and is served by a non-unique index.
- `findings`, `audit_log`, `rule_baseline` → their natural instant (`time_utc`, `at`, `bucket_start`), each NOT NULL.

A `partition_maintain` job creates the next N months (PROPOSED: N = 3 ahead) and drops expired partitions per retention policy — no pg_partman dependency (D6-007; keeps the dependency surface to what Stage 1 §2 allowed). Findings always carry a time (the engine stamps run time when events lack one), so no undated-findings partition exists; events with unknown time simply live in their ingest month.

### 1.5 Evidence model (reject-condition R1)

`findings.evidence_snapshot` is an immutable JSONB freeze written at detection time containing: the full finding document (`sentinel-finding/v1` per Stage 5 §4: rule id/name/kind/severity, time, event uids, host, user, detection_path, reason_codes, plus `payload_excerpt`/`attck_refs`/`falsepositives_note`/`attestation` — C-2-fix: these Stage-5 fields live here, not in dedicated columns), the rule document version + `rule_source.sha256`, the run's `config_hash`, and per-event `(event_uid, sha256_of_document)` digests — **not** copies of raw bytes and **not** pointers that depend on `raw_objects.state`.

**Naming disambiguation (C-12-fix):** the word "evidence" is used for two distinct contracts and they must not be conflated. (a) **Triage evidence** (Stage-3 §5): short human-readable fact quotes ("filename X matched Y") attached to triage findings — diagnostic strings, not stored bytes. (b) **EvidenceBundle / `evidence_snapshot`** (this section + OpenAPI `GET /evidence/{findingUid}`): the machine retrieval contract — immutable JSONB freeze, always returned; raw bytes only via a separate presigned URL while hot. No renames were made (would ripple every Stage-3 example); this note is the authoritative disambiguation.

Retention therefore proceeds independently: `raw_objects` moves hot → archived → purged (checked by `state`, `retention_until`, `legal_hold`), while the snapshot remains the evidence of record. The API's `/evidence/{findingUid}` returns the snapshot always, and a presigned raw URL only while `state = 'hot'` (§3). The M2 exit drill (§9) deletes raw bytes under a finding and demonstrates the snapshot still reconstructs the alert context.

**D6-005:** snapshot is write-once; triage updates touch `triage_state`/`last_seen`/`occurrence_count` only. Snapshots are retained at least as long as findings (default 730 days, `PROPOSED`).

### 1.6 Retention state machine

```
hot ──(retention_until reached, archive configured)──► archived ──(grace elapsed)──► purged
  └────(legal_hold=true: never leaves hot/archived; purge job skips)───────┘
```

- `retention_policies` rows set days per `(scope_kind, scope_match)`; defaults in `schema.sql`: raw 90, events 365, findings 730, audit 365, rejected-upload audit 90 (the 90-day figure VERIFIED as Stage 3 §1.5's stated default; everything else PROPOSED).
- The `purge_raw` job: select candidates → (if archive_uri configured) copy + flip to `archived` → after grace, delete file + set `state='purged'`, `purged_at=now()`; `refcount` guards shared objects; `legal_hold` is an operator flag (audited write) that blocks all transitions out of the current state.
- Dropping an `events` partition is a separate, policy-driven action; it does not touch `findings` (snapshots are self-contained).

### 1.7 What is deliberately not here

- No Kafka/outbox-to-queue fan-out (Stage 1 scope: no streaming bus).
- No `hosts` inventory table — host identity is derived from events (Stage 1: no live agents in scope); revisit post-MVP (OQ-6-08).
- No materialized views for the timeline in v1 — the M2 timeline query is a plain indexed SELECT over `findings` + `events` (§9); MVs are a post-MEASURED optimization.

---

## 2. Job System Design

### 2.1 The queue: PostgreSQL `FOR UPDATE SKIP LOCKED` (D6-001)

We implement a thin, owned queue on the `jobs` / `job_attempts` tables rather than adopting a third-party queue library. Claim query (normative):

```sql
SELECT job_id FROM jobs
 WHERE status = 'queued' AND run_after <= now()
 ORDER BY priority, run_after
 LIMIT 1
 FOR UPDATE SKIP LOCKED;
```

Syntax VERIFIED: `docs/18/sql-select.html` — `FOR { UPDATE | NO KEY UPDATE | SHARE | KEY SHARE } [ OF ... ] [ NOWAIT | SKIP LOCKED ]`. `SKIP LOCKED` semantics (skip rows locked by other transactions) are the documented purpose of the clause (INFERRED from the syntax + the PostgreSQL 9.5+ feature's standing usage; the docs sentence itself is the citation).

Lifecycle:

1. **Enqueue** — API/job producers INSERT with optional `idempotency_key` (unique per tenant/workspace; conflict returns the existing job — this is how `POST /runs` and re-ingest are made safe).
2. **Claim** — worker loop (N workers per process, concurrency per `job_type` from config §4): the claim query, then `UPDATE ... SET status='running', locked_by=$worker, locked_at=now(), heartbeat_at=now(), attempts=attempts+1`.
3. **Heartbeat** — running workers refresh `heartbeat_at` on a PROPOSED 15 s interval; lease = PROPOSED 60 s.
4. **Finish** — `succeeded` (+summary) or `failed` (retryable) → `run_after = now() + backoff(attempts)` with exponential backoff + full jitter (base PROPOSED 5 s, cap PROPOSED 15 min), or `dead` when `attempts >= max_attempts` (dead-letter: operator re-queue via API, audited).
5. **Stale-lock reaper** — `running` jobs with `heartbeat_at < now() - lease` are reset to `queued` (or `dead` at max attempts) with `job_attempts.outcome='lost_lock'`; the attempt row preserves the evidence of the crash. Exactly-once is not claimed; **at-least-once with idempotent handlers** is the contract (each job type documents its idempotency key; `finalize()` per Stage 5 §4 must already be retry-idempotent).

Job types (enum in API + CHECK in DDL): `ingest_file`, `detect_run`, `ioc_import`, `purge_raw`, `partition_maintain`, `baseline_update`.

### 2.2 Why not a library — and the Windows evidence (reject-condition R3)

| Option | Windows support evidence (2026-10-10) | Licence | Verdict |
|---|---|---|---|
| **Own SKIP LOCKED layer on PG 18 + psycopg** (chosen) | PG 18 VERIFIED current stable with the required syntax; `psycopg-binary` 3.3.6 ships `cp312-win_amd64` wheels (VERIFIED via PyPI file list) — the only OS-sensitive dependency | psycopg 3 LGPL-3.0 plain — NO OpenSSL exception (psycopg 3 links libpq, a system library, not OpenSSL directly; the OpenSSL exception exists only in the psycopg2 v2.x line). Python import model, attribution retained; PostgreSQL Licence | **ADOPTED (D6-001)** — schema ownership, no extra moving parts, the reject condition reduces to two verified components |
| pgqueuer (janbjorge/pgqueuer) | Dedicated CI job `run-windows-tests: runs-on: windows-latest` that provisions a Windows PostgreSQL service and runs `test/windows/` (VERIFIED from `ci.yml` at commit `70c56624`, 2026-10-10); README documents psycopg + asyncpg drivers and SKIP LOCKED | MIT (VERIFIED LICENSE.txt) | **Vetted alternative** — if queue needs exceed the thin layer (per-type pools, rich scheduling), adopt without re-litigating Windows support; v1.5.0 current |
| Celery + Redis broker | Celery has historically dropped first-class Windows support; Redis adds an infra component the brief excludes | BSD / Redis SSPL-family | REJECT — extra server + UNVERIFIED Windows posture |
| RQ / arq (Redis) | Same Redis objection; RQ Windows support is partial/community-tested | MIT | REJECT — same |
| APScheduler (SQLAlchemy job store) | In-process; no `SKIP LOCKED` multi-node claim; scheduler dies with the process | MIT | REJECT as primary queue; acceptable only as an in-process timer for heartbeats |
| Windows Task Scheduler | Native, but no portable claim semantics, poor observability, couples jobs to one host's SCM | n/a | REJECT — integration-only use (service start) is covered by WinSW (§7) |

INFERRED: self-owning the ~200-line queue is cheaper than the integration surface of any listed library, and it keeps every column in §1.2 under our migration discipline.

### 2.3 Workers, process model, backpressure

- One worker process per host (Windows service, §7), internal thread/async pool sized by config (PROPOSED default: `min(32, cpu*4)` claim loops; per-`job_type` caps — e.g. `detect_run` capped at PROPOSED 2 to bound memory).
- Queue depth per `job_type` is a gauge; admission control: the upload gate returns `429` when queued `ingest_file` jobs for the principal exceed PROPOSED 1000 or when DB connections are saturated (connection pool hard cap; fail fast rather than queue-storm).
- `COMPLETED_WITH_WARNINGS` propagates: a job whose handler accumulated warnings finishes `succeeded` with `warnings[]` in its summary; the run rollup becomes `completed_with_warnings` (Stage 5 invariant, unchanged semantics).

---

## 3. API Design (`openapi.yaml`)

### 3.1 Shape

OpenAPI **3.1.0** (D6-002). The brief mandates 3.1; VERIFIED that FastAPI 0.143.0 emits `"openapi": "3.1.0"` (raw `fastapi/openapi/utils.py`, `openapi_version: str = "3.1.0"`). The OAS project's latest *release* is 3.2.1 (VERIFIED 2026-10-09) — we do not target it because our framework emits 3.1; migration is OQ-6-06.

23 paths (see file): system (`/health`, `/ready`, `/metrics` — unauthenticated, bind internally), then workspace-scoped `/v1/workspaces/{workspaceId}/...` for uploads, events, findings, evidence, rules (+ `/source` verbatim), runs (+ `/rule-runs`), jobs (+ retry), ioc-packs, audit.

### 3.2 Cross-cutting contracts

| Concern | Contract |
|---|---|
| Tenancy | Path-scoped `workspaceId`; router resolves principal → (tenant, workspace) and sets the §1.3 GUCs; clients never send tenant ids in bodies |
| Pagination | Cursor-based everywhere (`limit` default 50, max 1000; opaque `cursor`; `Link rel="next"`). No offset pagination (Stage-1 discipline: stable under concurrent ingest) |
| Idempotency | `Idempotency-Key` on mutating POSTs; server stores `(principal, key) → request_hash + response` for PROPOSED 24 h; same key + different hash → 409 `IDEMPOTENCY_MISMATCH` (gate vocabulary, Stage 3 §1.5) |
| Rate limits | 429 + `RateLimit-Limit/-Remaining/-Reset` (IETF draft header names; VERIFIED field names are the current draft convention — INFERRED that they remain draft at fetch time) |
| Classification | `X-Data-Classification: 1|2|3` on event/finding responses (Stage-1 §6.4 levels) |
| Errors | Machine-readable `code` + human `message`; gate reject codes are reused verbatim (400/402/408/409/413/429/503 table in Stage 3 §1.5) |
| Auth | `X-API-Key` (Argon2id-hashed at rest, `principals.key_hash`); Bearer/OIDC reserved in the spec, not implemented in M1 (OQ-6-02) |
| Evidence | `/evidence/{findingUid}` always returns `evidence_snapshot`; presigned raw URL only while hot (TTL PROPOSED 15 min — confirmed working default per C-12-fix; retains the PROPOSED marker until benchmarked) |

### 3.3 Framework choices (licence VERIFIED 2026-10-10)

| Component | Version | Licence |
|---|---|---|
| FastAPI | 0.143.0 (2026-10-08) | MIT |
| pydantic | (current) | MIT |
| uvicorn | (current) | BSD-3-Clause (3-clause text VERIFIED in LICENSE.md) |
| psycopg / psycopg-binary | 3.3.6 | LGPL-3.0 plain (dependency; dynamic linking via Python import / libpq system library). **No OpenSSL exception** — that exception belongs to the psycopg2 v2.x line, not psycopg 3 (see §10 D6-001-fix and V-6-012a/b) |
| alembic | 1.20.0 | MIT (permission grant VERIFIED in LICENSE header) |
| structlog | 26.1.0 | dual Apache-2.0 / MIT |
| prometheus-client | 0.26.0 | Apache-2.0 |
| opentelemetry-sdk | 1.45.1 | Apache-2.0 |
| pytest | 9.1.1 | MIT |
| hypothesis | 6.168.5 | MPL-2.0 (dev/test only) |
| python-json-logger | 4.2.0 | BSD-2-Clause |

---

## 4. Configuration Reference

Precedence (D6-010): **environment `SENTINEL_*` > `sentinel.toml` > built-in default**. The loaded, redacted effective config is logged once at startup (secrets replaced by `***`) and its SHA-256 becomes the run's `config_hash` (ties to §1.5). File format TOML; env names map `section.key` → `SENTINEL_SECTION__KEY` (double underscore = nesting). **Encoding (C-7-fix):** `config_hash` is stored as `bytea` (raw 32-byte digest) in `detection_runs`; the API exposes it as lowercase hex via `encode(config_hash,'hex')` on read and accepts hex via `decode(<hex>,'hex')` on write — the OpenAPI pattern `^[0-9a-f]{64}$` is the wire form of the same value.

| Key (TOML path) | Type | Default (PROPOSED) | Notes |
|---|---|---|---|
| `server.host` / `server.port` | str/int | `127.0.0.1` / 8000 | never bind 0.0.0.0 by default |
| `server.workers` | int | 1 | uvicorn workers; jobs run in the worker process, not here |
| `database.url` | str | — (required) | psycopg DSN; TLS mode `verify-full` PROPOSED for non-loopback |
| `database.pool_min` / `pool_max` | int | 5 / 20 | hard cap; gate 503s when saturated |
| `storage.backend` | enum | `fs` | `fs` \| `s3` (s3 = OQ-6-03, not MVP) |
| `storage.root` | path | `C:\ProgramData\Sentinel\data` | content-addressed root (§1.2); ACL: service account only |
| `storage.archive_uri` | str\|null | null | when set, purge archives before delete (§1.6) |
| `jobs.worker_id` | str | hostname+pid | appears in `jobs.locked_by` |
| `jobs.claim_concurrency` | int | 8 | PROPOSED |
| `jobs.heartbeat_seconds` | int | 15 | PROPOSED |
| `jobs.lease_seconds` | int | 60 | PROPOSED; reaper threshold |
| `jobs.backoff_base_seconds` / `cap_minutes` | int | 5 / 15 | PROPOSED, full jitter |
| `jobs.max_attempts` | int | 5 | dead-letter after |
| `ingest.max_request_bytes` | int | 64 MiB (67108864) | Stage 3 §1.2 gate (normative; D8-05-fix); maps to GATE_REQUEST_TOO_LARGE; PROPOSED - TO BENCHMARK |
| `ingest.max_file_bytes` | int | 64 MiB (67108864) | GATE_FILE_TOO_LARGE; matches Stage-3 §1.2 (D8-05-fix) |
| `ingest.max_field_bytes` | int | 8 KiB (8192) | matches Stage-3 §1.2 (D8-05-fix) |
| `ingest.gate_timeout_seconds` | int | 30 | GATE_TIMEOUT; matches Stage-3 §1.2 request wall-clock (D8-05-fix) |
| `detection.statement_timeout_ms` | int | 60000 | per-rule SQL budget (Stage 5) |
| `detection.native_enabled` | bool | true | fallback evaluator |
| `detection.cold_start_policy` | str | `stage5-§4.8` | pointer to Stage 5 defaults |
| `retention.raw_days` / `event_days` / `finding_days` | int | 90 / 365 / 730 | seeds `retention_policies` |
| `retention.legal_hold_enabled` | bool | true | operator flag honoured by purge |
| `observability.log_level` | enum | `info` | |
| `observability.log_format` | enum | `json` | structlog JSON |
| `observability.metrics_enabled` | bool | true | `/metrics` on loopback |
| `observability.otel_endpoint` | str\|null | null | traces off unless set |
| `security.api_key_header` | str | `X-API-Key` | |
| `security.argon2_params` | table | OWASP-2024 baseline | |
| `security.windows.dpapi` | bool | true | encrypt secrets at rest via DPAPI (pywin32, PSF-2.0) when not supplied via env |

**Secrets:** `database.url` password and any future client secrets are never written to `sentinel.toml` in production; supply via environment or Windows DPAPI-protected blob (D6-010; DPAPI bound to the service account). Startup fails closed if a secret is missing — no silent empty string.

---

## 5. Observability Spec

### 5.1 Logs

structlog JSON, one event per line, fields: `ts`, `level`, `event`, `logger`, `tenant_id`, `workspace_id`, `request_id`, `run_id`, `job_id`, `principal`, `duration_ms`. No raw event payloads at `info`+ (classification discipline); `debug` may include field names, never full `raw` blobs (Stage-4 exfiltration posture). Log shipping is out of scope; the file sink rotates at PROPOSED 100 MiB × 7.

### 5.2 Metrics (Prometheus; `/metrics` loopback-only)

| Metric | Type | Purpose |
|---|---|---|
| `sentinel_http_requests_total{route,status}` | counter | API traffic + error rate |
| `sentinel_http_request_duration_seconds{route}` | histogram | p95 gate/latency budget (§6.6) |
| `sentinel_jobs_queued{type}` / `sentinel_jobs_running{type}` | gauge | queue depth (§2.3 admission) |
| `sentinel_job_duration_seconds{type,outcome}` | histogram | incl. `lost_lock` |
| `sentinel_events_ingested_total{format}` | counter | ingest throughput |
| `sentinel_findings_total{severity,kind}` | counter | detection yield |
| `sentinel_rule_run_outcome_total{outcome}` | counter | Stage 5 accounting rollup |
| `sentinel_raw_objects_state{state}` | gauge | hot/archived/purged (retention health) |
| `sentinel_db_pool_used` | gauge | saturation → gate 503 predictor |

Buckets: PROPOSED latency buckets `[.005,.01,.025,.05,.1,.25,.5,1,2.5,5,10]`; all values re-labeled MEASURED after §6.6.

### 5.3 Traces

OpenTelemetry SDK present but inert unless `observability.otel_endpoint` set (D6-014: no hard dependency on a collector). Spans: `http.request`, `job.claim`, `job.execute`, `ingest.parse`, `detect.rule` (attributes mirror log correlation fields).

### 5.4 Health and audit

`/health` = process liveness only. `/ready` = DB `SELECT 1`, object-store probe file, oldest-queued-job age (degraded when > PROPOSED 15 min). Every mutating API call and every operator action (rule import, legal-hold toggle, job retry, pack retire) writes an `audit_log` row (partitioned, §1.4) with principal + outcome; denied attempts included (Stage-4 T-01/T-02 accountability).

---

## 6. Test Strategy

### 6.1 Layers

| Layer | Scope | Gate |
|---|---|---|
| Unit | parsers, mappers, rule compiler, queue claim logic | every PR |
| Contract | JSON Schema validation of every example rule (reuse `_stage5_work/validate_examples.py` pattern), `canonical_event_v1.schema.json` conformance, `openapi.yaml` lint + every `$ref` resolves, `schema.sql` applies clean on PG 18 | every PR |
| Integration | real PostgreSQL 18 service container: migrations, RLS (cross-tenant probe MUST see zero rows), SKIP LOCKED under concurrent claim, partition maintenance, purge state machine | every PR |
| End-to-end | fixture corpus → upload API → ingest job → detect run → findings + evidence bundle; M2 vertical slice (§9) | merge to main |
| Conformance | Stage 5 §12 SQL-vs-native oracle over the golden corpus; divergence = fail | nightly |
| Performance | §6.6 protocol | nightly + pre-release |
| Security | ReDoS corpus against the native evaluator (Stage 4 budgets), malicious fixtures (zip bombs, path traversal — Stage 3 §10), auth/RLS penetration probes | nightly + pre-release |

Windows-first: CI runners are `windows-latest` for unit/contract/e2e (the product's primary OS); Linux containers run only the Postgres service and lint jobs. VERIFIED precedent: pgqueuer separates a `run-windows-tests` job the same way.

### 6.2 Corpora — licences VERIFIED 2026-08-29…2026-10-10

Nothing below is committed to the repository. `tools/corpus-fetch` downloads pinned URLs, verifies sha256, and stores outside the tree; CI secrets gate which corpora a runner may pull. D6-009: GPL corpora are **fixture-only** (tests reference local paths; they are never redistributed, never baked into images, never served by the product).

| Corpus | Licence (VERIFIED) | Status / freshness | Use |
|---|---|---|---|
| splunk/attack_data | Apache-2.0 | active (pushed 2026-10-09) | e2e ATT&CK-mapped EVTX/PCAP |
| OTRF/Security-Datasets | MIT | **stale** (last push 2024-03-20) | e2e host Artefacts; pin commit |
| sbousseaden/EVTX-ATTACK-SAMPLES | **GPL-3.0** | stale (2023-01-24) | fixture-only negative/positive EVTX |
| LID-DS (framework repo) | **GPL-3.0** | active (2026-08-29) | fixture-only behavioral scenarios; Zenodo dataset licence = OQ-6-04 |
| OISF/suricata-verify | MIT | active (2026-10-09) | PCAP + expected-EVE pairs |
| zeek/zeek `testing/` traces | BSD-3-Clause (COPYING VERIFIED) | in-repo test data | Zeek EVE parser conformance |
| SigmaHQ/sigma rules (pinned) | DRL-1.1 / tier licences | pin commit `8a4813404e` precedent | real rule pack for M2 slice |
| CIC-IDS2017 (UNB) | research-public + citation required (page text VERIFIED) | published dataset | optional flow-level perf corpus; counsel gate before automation |
| UNSW-NB15 | academic/public use + citation required (page text VERIFIED) | published dataset | same |
| malware-traffic-analysis.net | **NOT_VERIFIED — excluded** | — | not used |

### 6.3 Dataset selection rules

- Every fixture id in tests carries a one-line licence header in the fetch manifest (mirrors Stage 3 fixture discipline).
- Golden corpus for the conformance oracle (Stage 5 §12) = sigma-spec `tests/` + 20 pinned SigmaHQ rules — inherited, not redefined.
- Planted-finding fixtures (M2 drill): one EVTX containing a known-bad process creation that a pinned SigmaHQ rule must match, with expected `fingerprint` recorded in the fixture manifest.

### 6.4 RLS and tenancy tests (reject-condition R2 regression)

Integration suite includes: (a) session without GUCs sees 0 rows on every scoped table; (b) tenant A GUC never reads tenant B rows across all 20 policies; (c) cross-workspace probe inside one tenant; (d) `job_attempts`/`rule_run` EXISTS-policies. Any new table without a policy fails CI (schema-lint script counts `ENABLE ROW LEVEL SECURITY` vs tenant-column tables).

### 6.5 Queue tests

Concurrent claim correctness (N workers, M jobs, each claimed once), stale-lock reaper, backoff distribution (jitter statistical bounds via hypothesis), idempotency-key uniqueness under race, dead-letter + operator retry audit.

### 6.6 Measurement protocol (reject-condition R4)

Mirrors Stage-1 §5.7 discipline; every number ships labeled MEASURED-with-environment or stays PROPOSED:

1. Pin: PG 18.x minor, CPU/RAM/OS build, corpus manifest sha256, config_hash.
2. Warm-up: one full pass discarded; then 5 measured passes.
3. Report: ingest throughput (events/s) per format; queue claim latency p50/p95; API p95 for `/events` list and `/uploads` POST; detect-run wall time per 10k events; purge throughput.
4. Artifacts: JSON result files committed under `_stage6_work/bench/` (numbers only, no corpus).

---

## 7. Packaging and Deployment

### 7.1 Freezer (D6-003)

| Tool | Licence (VERIFIED) | Verdict |
|---|---|---|
| **cx_Freeze** | PSF-derived permissive (LICENSE.md: "derived from the Python Software Foundation License", commercial use intact) | **ADOPTED** for frozen single-file-ish builds of `sentinel-api` / `sentinel-worker` |
| PyInstaller | GPL-2.0-or-later **with Bootloader Exception** (COPYING.txt VERIFIED: exception covers linking/embedding the bootloader; "GPL restrictions do apply in other respects") | **AVOID** for closed-source redistribution — the GPL applies to the combined distributed artifact beyond the bootloader carve-out; recorded for counsel, not used |
| Nuitka | not fetched this stage | UNVERIFIED — not evaluated |

Build-time-only tools carry no redistribution obligation to the end product: Inno Setup's licence (license.txt VERIFIED) explicitly grants use "for any purpose, including commercial applications" with notice-retention conditions — satisfied by shipping the notices file.

### 7.2 Windows service and installer

- **WinSW** (MIT, VERIFIED LICENSE) wraps `sentinel-worker.exe` and `sentinel-api.exe` as Windows services (restart policies, rotation). NSSM noted as an UNVERIFIED alternative (official site not fetched; OQ-6-09).
- **Inno Setup** produces the MSI/EXE installer: creates service accounts, installs to `Program Files`, data root under `ProgramData` with ACLs, registers the two WinSW services, installs `schema.sql`-compatible migrations runner (alembic) as a first-boot step, and writes default `sentinel.toml` without secrets.
- **Code signing:** Authenticode signing is required for SmartScreen credibility but the certificate procurement is a legal/budget decision → OQ-6-01; installer ships unsigned in dev builds, signing is a release-pipeline step.
- **Upgrades:** installer-run alembic migrations (forward-only in MVP; downgrades UNVERIFIED-by-policy); service stop → replace binaries → start; rollback = previous installer + backup restore (backup cadence PROPOSED: nightly full + WAL archiving when `archive_uri` configured).

### 7.3 Runtime dependencies on the target host

PostgreSQL 18 runs on the same host for single-tenant MVP (service or VM); the app never requires a compiler, .NET, or the sandbox toolchain (YARA/TShark/EVTX reader are external processes per Stage 3 — present only on triage-enabled hosts; the installer detects and warns, never silently degrades — Stage-5 cold-start honesty rule).

---

## 8. Repository Layout

```
light-hids/
├── apps/
│   ├── api/                  # FastAPI app: routers, gate, auth
│   └── worker/               # job claim loops, handlers, reaper
├── packages/
│   ├── core/                 # config, logging, db session, RLS GUC helper
│   ├── ingest/               # parsers, pipelines, ExternalProcessRunner adapter
│   ├── detect/               # rule compiler, SQL path, native evaluator
│   └── storage/              # CAS, retention, evidence snapshot builder
├── migrations/               # alembic; schema.sql is the reviewed snapshot
├── schemas/                  # canonical_event_v1.schema.json, rule_schema.json, openapi.yaml
├── configs/                  # sentinel.toml defaults + examples
├── tests/
│   ├── unit/  contract/  integration/  e2e/  perf/  security/
├── tools/
│   ├── corpus-fetch/         # pinned download + sha256 manifest (D6-009)
│   └── bench/                # §6.6 harness
├── packaging/
│   ├── winsw/                # service wrapper configs
│   └── inno/                 # installer scripts
├── docs/                     # stage-1..6 specs (this file lives at repo root per house style)
└── _stage6_work/             # bench results, validation scripts (mirrors _stage5_work/)
```

House rule carried forward: CI validation scripts live under `_stage*_work/` and are referenced by the stage spec (pattern: `_stage5_work/validate_examples.py`).

---

## 9. Milestone Plan

Scope reminder: the first *product* milestone sequence is the Stage-1 MVP list; this plan adds M0 (contracts) which the brief's stage-6 output explicitly demands.

| Milestone | Content | Exit criteria (all must pass) |
|---|---|---|
| **M0 — Contracts (this stage)** | `schema.sql`, `openapi.yaml`, this spec, config keys frozen | ① `schema.sql` applies clean on PG 18 docker + `psql` lint (no ERROR/WARNING); ② `openapi.yaml` parses, every internal `$ref` resolves, no duplicate `operationId`; ③ contract tests validate `rule_schema.json` examples + `canonical_event_v1.schema.json` fixtures; ④ RLS schema-lint passes (§6.4a); ⑤ every DEPENDENCY licence row in this document has a Verification-Log entry |
| **M1 — Skeleton + empty-pack run** | API boots, worker boots, migrations run, one upload accepted, ingest job produces events with **zero rules enabled**, detect run completes with empty findings, health/ready/metrics live, audit rows written | ① e2e: upload 1 MiB EVTX → events rows > 0, `rule_run` empty, run status `completed`; ② cross-tenant probe returns 403/zero rows; ③ queue: 10k trivial jobs drain with exactly-once claim under 8 workers (§6.5); ④ readiness flips on DB stop/start; ⑤ installer (dev build) creates both services on a clean Windows VM |
| **M2 — First vertical slice** | EVTX/Sysmon ingest + real SigmaHQ pack (pinned commit) + SQL path + evidence snapshot + timeline query | ① pinned fixture EVTX (§6.3 planted finding) yields the expected finding with correct `detection_path` + `fingerprint`; ② evidence drill: purge the raw object, `/evidence/{id}` still returns a complete snapshot (reject-condition R1 — the drill is mandatory); ③ timeline: findings ∪ events for a host over a time window render in < PROPOSED 2 s p95 for 10⁵ events (§6.6 method); ④ Stage-5 cold-start codes appear in the run summary when baselines are absent; ⑤ conformance oracle runs on the golden corpus with zero unexplained divergences |
| **M3 — Breadth** | Artifact triage branch (Stage 3 parsers + AF rules), IOC packs (signed), FIM, statistical baselines, correlation rules | ① each kind produces one planted finding; ② unsigned IOC pack → `rejected` + audit; ③ ReDoS corpus completes within Stage-4 budgets with circuit-breaker codes; ④ `COMPLETED_WITH_WARNINGS` exercised end-to-end on a 3-of-400k-loss fixture |
| **M4 — Release candidate** | cx_Freeze + WinSW + Inno installer, perf numbers MEASURED, hardening pass | ① §6.6 numbers published as MEASURED with environment pins; ② full §6.1 suite green on windows-latest; ③ security suite green; ④ legal gate review of the DEPENDENCY/AVOID table signed off (Stage-1 §2.3 precedent); ⑤ upgrade drill: previous release → new installer with data intact |

The brief's "first vertical slice" is exactly M2: EVTX/Sysmon + real Sigma pack + evidence + timeline — deliberately before artifact breadth so the evidence-survives-purge invariant is proven early (R1 is the hardest reject condition to retrofit).

---

## 10. DECISIONS

| Id | Decision | Evidence |
|---|---|---|
| D6-001 | Own the SKIP LOCKED queue on PG 18 + psycopg; pgqueuer is the documented fallback | PG syntax VERIFIED; psycopg-binary win_amd64 VERIFIED; pgqueuer windows CI VERIFIED (§2.2). Licence posture CORRECTED (D8-01-fix): psycopg 3 is LGPL-3.0 with NO OpenSSL exception; the exception cited in the original D6-001 belongs to psycopg2 v2.x only |
| D6-002 | Target OpenAPI 3.1.0 | Brief mandate + FastAPI emits 3.1.0 VERIFIED; OAS 3.2.1 exists but unused (§3.1) |
| D6-003 | cx_Freeze over PyInstaller | PyInstaller GPL-2.0+bootloader exception VERIFIED vs cx_Freeze PSF-derived VERIFIED (§7.1) |
| D6-004 | WinSW (MIT VERIFIED) as service wrapper | §7.2 |
| D6-005 | `evidence_snapshot` write-once, self-contained, survives purge | §1.5; R1 drill in M2 |
| D6-006 | RLS via transaction-local GUCs; app role non-owner | §1.1, §1.3; docs/18/ddl-rowsecurity.html |
| D6-007 | App-managed monthly partitions; no pg_partman | §1.4; dependency discipline Stage-1 §2 |
| D6-008 | Cursor pagination + Idempotency-Key + RateLimit draft headers | §3.2 |
| D6-009 | GPL corpora fixture-only; never redistributed/bundled/served | §6.2; Stage-1 §2 legal gates |
| D6-010 | Config precedence env > file > default; secrets via env or DPAPI | §4 |
| D6-011 | Single-tenant-first literals; RLS always enabled from day one | §1.3; D-001 |
| D6-012 | `raw_objects` un-tenanted CAS scoped via `uploads` (INFERRED tradeoff) | §1.3; OQ-6-07 |
| D6-013 | Findings unique on `(tenant, workspace, rule_id, fingerprint, time_utc)` (partition key included per PG rule) for idempotent finalize within a run window | schema.sql §6; Stage 5 §4 finalize contract; PG partitioned-unique rule VERIFIED V-6-039 |
| D6-014 | OTel present but inert without endpoint | §5.3 |
| D6-015 | M1 = empty rule pack; M2 = first real vertical slice (EVTX/Sysmon + Sigma + evidence + timeline) | §9; brief ordering |
| D6-016 | Events partitioned by `ingest_time`, not event time — keeps nullable `event_time_utc` (D2-003) PK-legal and aligns retention with ingest clock | §1.4; schema.sql §3 |

## 11. OPEN_QUESTIONS

| Id | Question | Owner / next step |
|---|---|---|
| OQ-6-01 | Authenticode certificate procurement for installer signing | legal/budget; blocks M4 polish, not M4 exit |
| OQ-6-02 | OIDC integration timing (BearerAuth reserved in spec) | post-MVP; API keys suffice for M1–M2 |
| OQ-6-03 | S3-compatible object storage backend | add when multi-host CAS needed; `storage.backend` enum reserved |
| OQ-6-04 | LID-DS *dataset* licence (Zenodo artifact) distinct from GPL framework repo | fetch Zenodo metadata before any M3 corpus automation |
| OQ-6-05 | Adopt pgqueuer if queue requirements outgrow the thin layer | revisit at M3 perf review |
| OQ-6-06 | OpenAPI 3.2 migration | wait for FastAPI emission of 3.2 |
| OQ-6-07 | Tenant-scoped CAS (forfeit dedup) vs shared CAS | revisit with real multi-tenant load data |
| OQ-6-08 | Host inventory table | post-MVP; events-derived until then |
| OQ-6-09 | NSSM as alternative service wrapper | verify licence from nssm.cc before any use |

## 12. NOT_VERIFIED

- NSSM licence and Windows Service Control compatibility (excluded from the plan until fetched).
- malware-traffic-analysis.net terms of use — **excluded from corpora** (§6.2).
- Redistribution terms for Zeek test traces beyond the repository's COPYING as applied to the `testing/` subtree (used locally only; no redistribution planned).
- Full legal text of CIC-IDS2017 / UNSW-NB15 terms beyond the quoted public/academic-use sentences — counsel gate before any commercial corpus automation (Stage-1 §2.3 pattern).
- pgqueuer behaviour on Windows *Server* SKUs (CI evidence is `windows-latest` runner) — mitigated by D6-001 (we do not depend on it in MVP).
- PostgreSQL 19 features and performance (beta only; excluded per §1.1).
- Nuitka licence (not fetched; not evaluated).
- Whether the IETF RateLimit draft headers have been finalised at implementation time — pin at M1.

## 13. Verification Log (this stage; all fetched 2026-10-10 unless noted)

| V-id | Source | Verified fact |
|---|---|---|
| V-6-001 | https://www.postgresql.org/ (homepage) | "PostgreSQL 19 Beta 4" news ⇒ 19 not GA; stable line is 18 |
| V-6-002 | https://www.postgresql.org/docs/current/index.html | current docs = PostgreSQL 18 |
| V-6-003 | https://www.postgresql.org/docs/18/sql-select.html | `FOR {UPDATE\|…} [ NOWAIT \| SKIP LOCKED ]` syntax |
| V-6-004 | https://www.postgresql.org/docs/18/ddl-partitioning.html §5.12.2 | declarative partitioning |
| V-6-005 | https://www.postgresql.org/docs/18/ddl-rowsecurity.html | row security policies; owner-bypass behaviour |
| V-6-006 | https://www.postgresql.org/docs/18/functions-uuid.html | native `uuidv7()` |
| V-6-007 | https://www.postgresql.org/about/licence (2026-10-09) | PostgreSQL Licence (permissive) |
| V-6-008 | https://raw.githubusercontent.com/janbjorge/pgqueuer/main/LICENSE.txt | MIT |
| V-6-009 | https://raw.githubusercontent.com/janbjorge/pgqueuer/main/.github/workflows/ci.yml @ commit `70c56624e8e2539dff9a10381c488c56fb6bc20a` | `run-windows-tests` on `windows-latest` with Windows PG service + `pytest test/windows/` |
| V-6-010 | https://api.github.com/repos/janbjorge/pgqueuer/commits/main | commit 70c56624, 2026-10-10; release v1.5.0 (2026-10-04) |
| V-6-011 | https://pypi.org/pypi/psycopg-binary/json | 3.3.6 ships `cp312-cp312-win_amd64.whl` (and cp310–cp315) |
| V-6-012 | https://raw.githubusercontent.com/psycopg/psycopg/master/LICENSE.txt | CORRECTED (was false, D8-01): file is verbatim LGPL-3.0 — **no OpenSSL exception present**. Verified again at tag 3.2.9 (same text). psycopg 3 links libpq (system library), not OpenSSL directly, so no exception is needed |
| V-6-012a | https://raw.githubusercontent.com/psycopg/psycopg2/master/LICENSE | psycopg2 (v2.x) LICENSE **does** contain the OpenSSL special exception ("as a special exception, the copyright holders give permission to link this program with the OpenSSL library"). This is a DIFFERENT package line from the pinned psycopg 3.3.6 — the original V-6-012 conflated them |
| V-6-012b | https://pypi.org/pypi/psycopg2-binary/json | psycopg2-binary `info.license` = "LGPL with exceptions"; classifier "GNU Library or Lesser General Public License (LGPL)". Confirms the exception applies to the psycopg2 line only |
| V-6-013 | https://raw.githubusercontent.com/fastapi/fastapi/master/fastapi/openapi/utils.py | `openapi_version: str = "3.1.0"` |
| V-6-014 | PyPI JSON fastapi (2026-10-09) | 0.143.0 published 2026-10-08 |
| V-6-015 | https://raw.githubusercontent.com/fastapi/fastapi/master/LICENSE | MIT |
| V-6-016 | https://raw.githubusercontent.com/pydantic/pydantic/main/LICENSE | MIT |
| V-6-017 | https://raw.githubusercontent.com/encode/uvicorn/main/LICENSE.md | BSD 3-clause text |
| V-6-018 | https://raw.githubusercontent.com/sqlalchemy/alembic/main/LICENSE | MIT grant text |
| V-6-019 | https://raw.githubusercontent.com/pytest-dev/pytest/main/LICENSE | MIT |
| V-6-020 | https://raw.githubusercontent.com/HypothesisWorks/hypothesis/master/LICENSE.txt | MPL-2.0 |
| V-6-021 | https://raw.githubusercontent.com/prometheus/client_python/master/LICENSE | Apache-2.0 |
| V-6-022 | https://raw.githubusercontent.com/open-telemetry/opentelemetry-python/main/LICENSE | Apache-2.0 |
| V-6-023 | https://api.github.com/repos/hynek/structlog/contents/ | dual LICENSE-APACHE + LICENSE-MIT |
| V-6-024 | https://api.github.com/repos/nhairs/python-json-logger/license | BSD-2-Clause |
| V-6-025 | https://raw.githubusercontent.com/pyinstaller/pyinstaller/develop/COPYING.txt | GPL-2.0-or-later + Bootloader Exception wording |
| V-6-026 | https://raw.githubusercontent.com/marcelotduarte/cx_Freeze/main/LICENSE.md | PSF-derived permissive licence |
| V-6-027 | https://raw.githubusercontent.com/winsw/winsw/v3/LICENSE | MIT |
| V-6-028 | https://raw.githubusercontent.com/jrsoftware/issrc/main/license.txt | Inno Setup licence; commercial use permitted |
| V-6-029 | https://raw.githubusercontent.com/mhammond/pywin32/main/README.md | PSF-2.0 badge; mixed licences, source tree is source of truth |
| V-6-030 | https://api.github.com/repos/sbousseaden/EVTX-ATTACK-SAMPLES | GPL-3.0; pushed 2023-01-24 |
| V-6-031 | https://raw.githubusercontent.com/LID-DS/LID-DS/master/LICENSE | GPL-3.0 |
| V-6-032 | https://api.github.com/repos/OISF/suricata-verify | MIT; pushed 2026-10-09 |
| V-6-033 | https://raw.githubusercontent.com/zeek/zeek/master/COPYING | BSD 3-clause (Berkeley/LBNL/ICSI) |
| V-6-034 | https://www.unb.ca/cic/datasets/ids-2017.html | "publicly available for researchers"; citation required |
| V-6-035 | https://research.unsw.edu.au/projects/unsw-nb15-dataset | "academic/public use … authors have to cite" |
| V-6-036 | https://api.github.com/repos/fastapi/fastapi (2026-10-09) + OAS repo releases | OAS latest release 3.2.1 (2026-09-09/10) — 3.1.0 chosen per D6-002 |
| V-6-037 | prior session: https://api.github.com/repos/splunk/attack_data | Apache-2.0; pushed 2026-10-09 |
| V-6-038 | prior session: https://api.github.com/repos/OTRF/Security-Datasets | MIT; pushed 2024-03-20 (stale) |
| V-6-039 | https://www.postgresql.org/docs/18/ddl-partitioning.html (fetched 2026-10-10) | "the constraint's columns must include all of the partition key columns" — basis for D6-013/D6-016 PK shapes |

---

*End of Stage 6. Re-run §6.6 before replacing any PROPOSED number; extend the Verification Log rather than editing entries in place.*
