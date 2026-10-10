# §1 — How to read this specification

**Sentinel (Light HIDS) — Implementation Specification**
Generated 2026-10-10 from Stages 1–6. This document is the single merged specification for implementation. It is assembled by full verbatim splice of every stage artifact; nothing is summarised away, no decision is silently resolved.

## 1.1 Precedence order

When two parts of this specification disagree, the following precedence applies **only where a stage explicitly states supersession**. Where no supersession is stated, the disagreement is a **conflict** and is listed in `consistency_report.md` §1 and in §13 of this document — implementers must not pick a side silently.

| Rank | Artifact | Role |
|---|---|---|
| 1 | `canonical_event_v1.schema.json`, `rule_schema.json` | Machine-normative contracts (validate the delivered example corpora) |
| 2 | `schema.sql` | Storage contract (tables, columns, CHECKs, RLS) |
| 3 | `openapi.yaml` | HTTP surface contract (paths, request/response schemas) |
| 4 | Stage bodies (Stages 1–6, spliced in §4–§8) | Design intent, decision rationale, mappings, matrices |
| 5 | `verification-log.yaml`, `VERIFICATION_LOG_2026-10-09.yaml` | Evidence backing for VERIFIED labels |

`consistency_report.md` (sibling file) is the authoritative conflict register. Section §13 of this document restates every open conflict for implementers.

## 1.2 Section map

| § | Contents | Source |
|---|---|---|
| 1 | How to read this specification | authored (Stage 7) |
| 2 | Verification log and licence register (consolidated index) | authored, pointing at stage §0s and licence tables |
| 3 | Architecture, decision register, and cross-stage contracts | authored |
| 4 | Threat model, sandbox, isolation | Stage 4 verbatim |
| 5 | Canonical event and source mappings | Stage 2 verbatim |
| 6 | Ingestion, parser interface, and artifact triage | Stage 3 verbatim |
| 7 | Dynamic rule engine | Stage 5 verbatim |
| 8 | Platform: storage, jobs, evidence, release | Stage 6 verbatim |
| 9 | HTTP API contract | `openapi.yaml` (delivered file; path/schema index below) |
| 10 | Storage DDL contract | `schema.sql` (delivered file; table index below) |
| 11 | Canonical event JSON Schema | `canonical_event_v1.schema.json` (delivered file) |
| 12 | Rule JSON Schema | `rule_schema.json` (delivered file) |
| 13 | Open decisions requiring human input | authored |
| 14 | What I could not verify | authored |
| 15 | Artifact inventory and colophon | authored |

Stage 1 is not spliced as its own body section because its load-bearing outputs (engine decision D-004, classification axes §6, MVP scope, licence obligations, decision block) are referenced from §2/§3 and conflict-checked in `consistency_report.md`; the full Stage 1 text remains a delivered sibling file and is listed in §15. Every other stage body appears verbatim.

## 1.3 Conventions inside spliced stage bodies

* Headings are demoted one level (`##` → `###`) so each stage body nests under its §-heading. Numbering inside each body is preserved as authored (e.g. Stage 2 still has its own §1, §2, …).
* Code fences, YAML decision blocks, decision tables, and fixture matrices are preserved byte-for-byte.
* DECISIONS / OPEN_QUESTIONS / NOT_VERIFIED blocks at the end of each stage body are left in place (they are also indexed in §3.2).
* Where a stage cites `alerts` or `events.classification`, the citation is **not** rewritten; see §13 conflicts C-2 and C-5.

## 1.4 Quick start for implementers

1. Read §3 (architecture + decision register) and §13 (open conflicts) before writing code.
2. Treat `canonical_event/v1` (§11 + Stage 2 §5 examples) as the event wire format; 121/121 examples validate.
3. Treat `sentinel-rule/v1` (§12 + Stage 5 §11 examples) as the rule document format; 25/25 + 5/5 examples validate.
4. Create the database from `schema.sql` (§10) — 21 tables, RLS on all tenant-scoped tables.
5. Serve `openapi.yaml` (§9) as the API surface — 23 paths.
6. Implement detection as SQL-over-events primary with native fallback (Stage 1 D-004 Option C, Stage 5 §4).
7. Do not implement any conflict in §13 until a human resolves it; leave the conflicting surface behind a feature flag or stub.

---
# §2 — Verification log and licence register (consolidated index)

This section is an index, not a replacement. Full verification-log content remains inside Stage 2 §0 and Stage 3 §0 (spliced in §5 and §6) and in the delivered files `verification-log.yaml` and `VERIFICATION_LOG_2026-10-09.yaml`. Licence obligations remain in Stage 1 §2.3 and Stage 6 licence table.

## 2.1 Where verification evidence lives

| Register | Location | Role |
|---|---|---|
| Stage 2 §0 Verification Log | §5 of this document (Stage 2 body) | Tool/library evidence for parser stack (evtx, tshark, polars, etc.) |
| Stage 3 §0 Verification Log | §6 of this document (Stage 3 body) | Fixture/tool evidence for ingestion & triage labels (TL-*, ARC-*, DOC-*, UP-*, ID-*, FX-*) |
| Stage 4 evidence citations | §4 of this document | Microsoft Sandbox / AppContainer / Job Object citations in D4 decision blocks |
| Stage 5 §12.3 example validation | §7 of this document | Rule-example validation narrative |
| Stage 6 V-6-001…V-6-039 | §8 of this document | Platform verification table |
| `verification-log.yaml` | delivered file | Machine-readable register |
| `VERIFICATION_LOG_2026-10-09.yaml` | delivered file | Timestamped snapshot register |

**NOT_VERIFIED by Stage 7:** a full id-by-id join of every evidence id cited in Stages 2–5 against the YAML registers was not executed (see §14 S7-V1).

## 2.2 Label vocabulary

| Label | Meaning (as used in stage decision matrices) |
|---|---|
| `VERIFIED` | Claim confirmed against a primary source or executed tool/fixture cited in the register |
| `PROPOSED` | Design choice not yet measured or ratified |
| `INFERRED` | Derived by Sentinel, not stated by the source |
| `UNVERIFIED` | Carried forward without confirmation |

## 2.3 Licence obligation index (author-attribution and upstream licences)

| Obligation | Source stage | Enforcement point (as stated) | Status |
|---|---|---|---|
| DRL-1.1 — match outputs retain author identification | Stage 1 §2.3 / DRL-1.1 | Rule author flows to alerts/findings | **UNFULFILLED in DDL** — `findings` has no `author` column (conflict C-6, INV-6) |
| Sigma / upstream rule text preserved verbatim | Stage 1 §2.3, Stage 5 D5-001 | `rule_source` table (text + sha256); OpenAPI `getRuleSource` | implemented in DDL + API |
| MIT / Apache / GPL tool licences | Stage 1 §2.3 tool survey | Dependency manifest (not in this repo) | out of scope for spec |
| Stage-6 licence register additions | Stage 6 licence table (§8) | Documentation only | carried as authored |
| ioc_pack signature / provenance | Stage 4 D4-003 | `ioc_pack.signature`, `signing_key_id`, status flow | DDL has columns; verify-then-activate flow conflicts with `DEFAULT 'active'` (C-12) |

Full licence text tables: Stage 1 §2.3 (in decision body, referenced via §3) and Stage 6 licence section (in §8).

---
# §3 — Architecture, decision register, and cross-stage contracts

## 3.1 One-paragraph architecture

Sentinel is a Windows-first, multi-tenant-ready host agent + local platform that ingests forensic artifacts (EVTX, XML, CSV, JSON, archives, PCAP, live snapshots), normalises every source record into a versioned **canonical event** (`canonical-event/v1`), extracts **artifact facts** for structured files, evaluates **rules** (`sentinel-rule/v1`) primarily as SQL over the `events` table with a native evaluator fallback, and emits **findings** with immutable evidence snapshots. Storage is PostgreSQL (21 tables, RLS per tenant/workspace); the HTTP surface is OpenAPI 3.1 (`openapi.yaml`); jobs orchestrate parse → triage → detect → persist. Active content never executes in-process; detonation is sandboxed (Stage 4 tiers). The engine contains no baked detections; rules are data.

### 3.1.1 Control-flow summary (stage-backed)

```
upload (POST …/uploads) 
  → Stage-3 upload gate (magic, size, policy)
  → parse (Stage-3 parsers → canonical-event/v1 events + artifact_facts)
  → triage (Stage-3 matrices → facts only, no verdicts)
  → detection job (Stage-5: SQL path primary, native fallback; same rule document)
  → findings + evidence_snapshot (immutable JSONB)
  → API read paths (OpenAPI findings/evidence/events/rules/runs/jobs)
```

### 3.1.2 Binding cross-stage decisions (ids remain stage-scoped)

| Decision | Stage | Binding effect |
|---|---|---|
| D-004 Option C | Stage 1 | SQL-over-events is the primary engine; native evaluator exists for Stage-3/4 cases |
| D-001…D-012 | Stage 1 | multi-tenant columns from day 1; RLS; classification axes separate; etc. |
| D2-001…D2-0xx | Stage 2 | canonical-event/v1 shape; bare-null policy; unmapped preservation |
| D3-0xx | Stage 3 | upload gate order; parser interface; triage emits facts not verdicts |
| D4-001…D4-005 | Stage 4 | Windows Sandbox tiers; ReDoS posture; ioc signature (Ed25519) |
| D5-0xx | Stage 5 | two residence modes one contract; detection_path on every finding |
| D6-001…D6-016 | Stage 6 | table shapes; jobs; evidence freeze; API naming |

Full decision text: each stage body's DECISIONS block (§4–§8). Machine inventory: `_stage7_work/decision_inventory.json` (115 decisions, 75 open questions, 89 not-verified; 0 id collisions).

## 3.2 Decision / open-question / not-verified index

| Stage | Decisions | Open questions | Not verified | Block format |
|---|---|---|---|---|
| 1 | D-001…D-012 (§8.1) | Q1–Q12 (§8.2 numbered prose) | §8.3 prose | YAML list + prose |
| 2 | D2-* (§DECISIONS) | Q2-* (§OPEN_QUESTIONS) | table | YAML list |
| 3 | D3-* (§DECISIONS) | Q3-* (§OPEN_QUESTIONS) | table | YAML list |
| 4 | D4-001…D4-005 (§9) | Q4-* table | table | YAML list |
| 5 | D5-* (§DECISIONS) | Q5-001…Q5-008 | YAML | YAML list |
| 6 | D6-001…D6-016 table | OQ-6-01…OQ-6-09 table | V-6-001…V-6-039 table | markdown tables |

Stage-7 process decisions S7-001…S7-004 and questions S7-Q1…S7-Q16: `consistency_report.md` §7–§8.

**Dangling ids (real):** `D-022` cited in Stage 5 §4 (streaming reconciliation) has no definition; `Q5-009` cited in Stage 5 §1 has no definition. See §13 C-14/C-15.

## 3.3 Contract register (summary; full analysis in consistency_report.md)

| # | Contract | Versions found | Status |
|---|---|---|---|
| C-1 | Canonical event envelope | Stage-1 §6.1 sketch vs canonical-event/v1 | CONFLICT (V2 de-facto normative) |
| C-2 | Finding/alert object | alerts / sentinel-finding/v1 / Finding / findings DDL | CONFLICT |
| C-3 | Severity / level / classification axes | 3 classification spellings; level_original dropped on findings | CONFLICT |
| C-4 | Upload API path | /v1/artifacts vs /v1/workspaces/{id}/uploads | CONFLICT |
| C-4b | createUpload run_id | optional in request vs NOT NULL in DDL | CONFLICT |
| C-5 | rule_run metrics | Stage-5 §4.3 vs DDL vs OpenAPI | CONFLICT |
| C-6 | findings.author | DRL-1.1 obligation vs missing column | CONFLICT / INV-6 FAIL |
| C-7 | config_hash | bytea vs hex string | CONFLICT |
| C-8 | source.format enum | canonical includes xml; OpenAPI omits | CONFLICT |
| C-9 | host shape | structured vs free-form | CONFLICT |
| C-10 | OpenAPI Rule projection | missing provenance columns; RuleDocument not $ref'd | GAP |
| C-11 | ioc_pack.status default | DEFAULT 'active' vs verify-then-activate | CONFLICT |
| C-12 | Evidence naming + TTL | triage evidence vs EvidenceBundle; 15 min PROPOSED | NAMING + OPEN |
| C-13 | events.classification | invariant cites column that does not exist | INV-5 FAIL |
| C-14 | D-022 | cited, never defined | DANGLING |
| C-15 | Q5-009 | cited, never defined | DANGLING |

## 3.4 Normative file pointers

| File | Spec section | Machine-check |
|---|---|---|
| `canonical_event_v1.schema.json` | §11 | validates 121/121 Stage-2 examples |
| `rule_schema.json` | §12 | validates 25/25 Stage-5 + 5/5 Stage-3 AF examples |
| `schema.sql` | §10 | 21 tables; text-audited only (not executed — §14 S7-V2) |
| `openapi.yaml` | §9 | 23 paths; structural audit only (§14 S7-V3) |
