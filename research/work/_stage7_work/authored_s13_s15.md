---
# §13 — Open decisions requiring human input

Every item below is a conflict or dangling reference that Stage 7 did **not** resolve. Implementers must not choose a side silently. Full analysis: `consistency_report.md` §1.

| # | Conflict | Competing versions | Human question |
|---|---|---|---|
| C-1 | Canonical event envelope | Stage-1 §6.1 flat sketch vs `canonical-event/v1` nested | Mark §6.1 SUPERSEDED, or keep both? |
| C-2 | Finding/alert object | `alerts` (Stage-1) / `sentinel-finding/v1` (Stage-5 §4.1) / OpenAPI `Finding` / DDL `findings` | Which is normative? Where do `payload_excerpt`, `attck_refs`, `falsepositives_note`, `attestation` land? |
| C-3 | Data classification spelling | `public\|internal\|restricted` strings vs header `DataClassification` 1\|2\|3 (`internal/sensitive/restricted`) vs Stage-1 "LEVEL 1 of 3" comment | One vocabulary? Which? |
| C-3b | `level_original` on findings | Stage-1 §6.4 requires it on alerts; DDL/OpenAPI Finding omit it | Restore column, or record exception? |
| C-4 | Upload API path | Stage-3 `POST /v1/artifacts` vs OpenAPI `POST /v1/workspaces/{workspaceId}/uploads` | Adopt OpenAPI paths and fix Stage-3 tables, or add alias? |
| C-4b | `createUpload` `run_id` | optional in multipart request vs `uploads.run_id NOT NULL` vs required on Upload response | Client-required, server-generated, or 400 when absent? |
| C-5 | `rule_run` metrics | Stage-5 §4.3 (`job_id`, `max_window_ms`, `sql_ms`, `native_ms`) vs DDL (`run_id`, `detection_path`, `reason_codes`, `started_at`, `finished_at`) vs OpenAPI (subset, no timings) | Add metrics columns to DDL, or drop from Stage-5? |
| C-6 | `findings.author` | Stage-1 DRL-1.1 "persist author on every alert row" vs missing column | Add `author`, or licence-gate exception? (Also INV-6.) |
| C-7 | `config_hash` encoding | DDL `bytea` vs OpenAPI hex `^[0-9a-f]{64}$` | Specify edge encode/decode. |
| C-8 | `source.format` enum | canonical-event/v1 includes `xml`; OpenAPI omits it | Add to OpenAPI, or ban `xml` in canonical? |
| C-9 | `host` shape | canonical structured `{hostname,fqdn,ips,os,arch}` vs OpenAPI free-form object | `$ref` canonical host in OpenAPI, or declare OpenAPI non-authoritative for events? |
| C-10 | OpenAPI `Rule` projection | missing `source_ref`/`source_spec`/`provenance`/`description`/`schema_tag`/`deleted_at`; `RuleDocument` is free-form not `$ref rule_schema.json` | Expose columns and machine-link the rule schema? |
| C-11 | `ioc_pack.status` default | DDL `DEFAULT 'active'` vs verify-then-activate flow (D4-003) | Change default to `pending_verify`? |
| C-12 | Evidence naming + TTL | triage `evidence` strings vs `EvidenceBundle`; presigned TTL 15 min PROPOSED | Rename triage evidence? Confirm TTL? |
| C-13 | `events.classification` | Stage-1 §6.4 + Stage-5 §1.10 invariant 5 cite a column that does not exist in DDL or canonical-event/v1 | Restore column + field, drop invariant, or rehome classification? (Also INV-5.) |
| C-14 | Dangling `D-022` | Stage-5 §4 calls streaming reconciliation "binding, D-022"; Stage-1 only defines D-001…D-012 | Record the decision, or fix the citation? |
| C-15 | Dangling `Q5-009` | Stage-5 §1 cites Q5-009; Stage-5 OPEN_QUESTIONS only defines Q5-001…Q5-008 | Record the open question, or fix the citation? |
| C-16 | Stage-1 splice | Stage 1 body is not inlined as its own § (see §1.2); its decision block and licence table live in the delivered file | Inline Stage 1 as an additional section, or accept the index/reference approach? |

**No decision above was implemented unilaterally.** S7-001…S7-004 (assembly process decisions) are in `consistency_report.md` §7.

---
# §14 — What I could not verify

Stage 7 did not execute code against a database, sandbox, or live API. The following remain unverified and are carried forward with their stage-authored labels:

| Id | Item | Why unverified |
|---|---|---|
| S7-V1 | Full evidence-id join (TL-*/ARC-*/DOC-*/PRIOR-*/FX-*/UP-*/ID-* ↔ YAML registers ↔ Stage-3 §0) | Only spot-checked; no automated join script completed for every id |
| S7-V2 | DDL execution | No Postgres instance available in this environment; RLS/CHECKs/PARTITIONs are text-audited only |
| S7-V3 | OpenAPI lint (spectral / openapi-generator) | Toolchain not run; only structural parse + cross-checks |
| S7-V4 | Windows Sandbox / AppContainer / Job Object behaviour | Stage-4 design not executed on a Sandbox host |
| S7-V5 | Parser fixture corpora re-run | Stage-3 FX-* labels carried as authored; fixtures not re-executed |
| S7-V6 | Engine performance budgets | Stage-5 §10 budgets are PROPOSED; no load test |
| S7-V7 | Ed25519 ioc_pack signature verification | D4-003 design not implemented/tested in Stage 7 |
| S7-V8 | API-layer rule document validation | OpenAPI `RuleDocument` is free-form; only file-based examples were validated against `rule_schema.json` |
| S7-V9 | Strict YAML conformance of decision blocks | Tolerant extractor used (unquoted colons, backtick scalars present) |
| S7-V10 | End-to-end licence-obligation trace | Every DRL/CC/MIT clause → concrete code path not traced |

Additionally, PROPOSED values inside stage bodies (presigned TTL 15 min, parser budgets, sandbox timeouts, statistical-rule defaults) are **not verified measurements**; they keep their PROPOSED markers.

---
# §15 — Artifact inventory and colophon

## 15.1 Delivered source artifacts (all present; none omitted from audit)

| File | Role in this spec |
|---|---|
| `stage-1-landscape-and-rule-engine-decision.md` | Engine decision, classification axes, MVP scope, licence obligations, D-001…D-012 — referenced via §2/§3; full text is a delivered sibling |
| `stage-2-canonical-event-and-mappings.md` | §5 body (verbatim) |
| `stage-3-ingestion-and-artifact-triage.md` | §6 body (verbatim) |
| `stage-4-threat-model-and-windows-sandbox.md` | §4 body (verbatim) |
| `stage-5-dynamic-rule-engine.md` | §7 body (verbatim) |
| `stage-6-platform-storage-jobs-api-testing-release.md` | §8 body (verbatim) |
| `schema.sql` | §10 contract file (21 tables) |
| `openapi.yaml` | §9 contract file (OpenAPI 3.1.0, 23 paths) |
| `canonical_event_v1.schema.json` | §11 contract file |
| `rule_schema.json` | §12 contract file |
| `verification-log.yaml` | Evidence register (indexed §2) |
| `VERIFICATION_LOG_2026-10-09.yaml` | Evidence register snapshot (indexed §2) |
| `consistency_report.md` | Conflict register (sibling; §13 restates open items) |

## 15.2 Stage-7 work artifacts

| File | Role |
|---|---|
| `_stage7_work/extract_decisions.py` | Decision/Q/NV inventory extractor |
| `_stage7_work/decision_inventory.json` | 115 decisions / 75 open questions / 89 not-verified |
| `_stage7_work/audit_openapi_ddl.py` | OpenAPI ↔ DDL cross-check |
| `_stage7_work/openapi_ddl_audit.json` | Mismatch list |
| `_stage7_work/validate_examples.py` | Example validator (canonical + rule) |
| `_stage7_work/example_validation.json` | 121/121, 25/25, 5/5 OK |
| `_stage7_work/audit_invariants.py` | INV-1…INV-10 + dangling-ref scanner |
| `_stage7_work/invariants_numbers.json` | INV results + dangling refs |
| `_stage7_work/assemble_spec.py` | This document's assembler |

## 15.3 Measured corpus counts (number audit)

| Corpus | Count | Validator |
|---|---|---|
| Stage-2 canonical examples | 121 | `canonical_event_v1.schema.json` — 121/121 OK |
| Stage-5 rule documents | 25 | `rule_schema.json` — 25/25 OK |
| Stage-3 AF rule documents | 5 | `rule_schema.json` — 5/5 OK |
| DDL tables | 21 | text count |
| OpenAPI paths | 23 | structural parse |
| Decisions (all stages) | 115 | inventory |
| Open questions (all stages) | 75 | inventory |
| Not-verified items (all stages) | 89 | inventory |
| V-6 verification rows | 39 | table count |
| Open conflicts left for human input | 16 (C-1…C-16) | consistency_report.md §1 |

## 15.4 Colophon

* Assembled: 2026-10-10
* Assembly method: full verbatim splice of stage bodies with one-level heading demotion; code fences preserved; no summarised stage sections
* Conflict handling: zero silent resolutions; all conflicts listed in §13
* Environment note: Python 3.14 with `pyyaml` + `jsonschema`; no Postgres; no Windows Sandbox; no OpenAPI linter
* Git note: workspace was an uncommitted git repo at audit time

**Open decisions requiring human input:** see §13 (C-1…C-16).
**What I could not verify:** see §14 (S7-V1…S7-V10).
