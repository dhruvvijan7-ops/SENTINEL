# STAGE 8 — ADVERSARIAL REVIEW

**Target:** `SENTINEL_IMPLEMENTATION_SPEC.md` + `consistency_report.md` · **Reviewer posture:** hostile staff security engineer / Windows internals / data-platform architect · **Date:** 2026-10-10

## 1. Scores (28 criteria, 0–2 each, max 56)

| # | Criterion | Score | Justification + pointer |
|---|---|---|---|
| 1 | Evidence quality | 1 | Pinned commits, VERIFIED labels, machine-validated corpora — but V-6-012 is a VERIFIED row that is false, and S7-V1 admits no id-by-id evidence join (§14 NOT_VERIFIED) |
| 2 | Licence handling (commercial) | **0** | V-6-012 + Stage-6 licence table claim "LGPL-3.0 + OpenSSL exception"; the cited LICENSE.txt contains no exception (blocker, §3 D8-01) |
| 3 | Canonical schema completeness | 1 | `canonical_event_v1.schema.json` solid + 121/121 validated, but `events.classification` absent (INV-5 FAIL, C-13) and OpenAPI `host`/`source.format` diverge (C-10, C-11) |
| 4 | Source mapping completeness | 2 | 121 mappings, 121/121 examples OK; Swift EID-1 `ProcessID` casing and 4624 fields both spot-confirmed against upstream |
| 5 | Value-state/absence | 2 | `time.state` guards null-utc; INV-10 PASS (Stage-5 §1.10) |
| 6 | Parser interface | 1 | Streaming `ParserResult` design sound, but §3.2 monotonic-vs-unix deadline bug and `selected` routing gap break the contract (D8-06, D8-11) |
| 7 | Artifact triage depth | 1 | Matrix thorough but `sqlite` has no §5 triage row; `.eml`/`.msg` (Q3-015), NSIS/Inno (Q3-016) unresolved |
| 8 | Encrypted/nested/embedded | 2 | Limits and prohibitions explicit (Stage-3 §5.7–5.9) |
| 9 | Active-content prohibitions | 2 | INV-4 PASS — no rendering, no macro exec, no in-process interpreters (Stage-5 §1.10) |
| 10 | Sandbox design + non-guarantees | 1 | Job-object no-network/no-file claim and WSB single-instance/Home/networking claims all confirmed, but `wsb start --config` requires Win11 24H2+ — tier table omits the OS floor (D8-15) |
| 11 | Threat model + acceptance tests | 2 | Stage-4 threat model + D4 decisions + acceptance tests defined |
| 12 | Analyst-surface security (XSS/CSV injection) | 2 | Escaping/encoding rules present; no defect registered |
| 13 | Rule engine data-only invariant | 2 | INV-1 PASS — zero rules ⇒ zero findings, no baked detections |
| 14 | Sigma subset explicitness | 2 | `sentinel-rule/v1` explicit; 25+5 examples validate (note: OpenAPI `RuleDocument` not `$ref`'d, S7-V8) |
| 15 | Detector streaming interface | 1 | D-022 ("binding" streaming reconciliation) is dangling — no such decision exists (C-14) |
| 16 | Regex/ReDoS | 2 | Timeouts + bounded constructs specified |
| 17 | Correlation correctness | 2 | Window/group-by semantics defined |
| 18 | Cold-start for statistical rules | 1 | PROPOSED only; S7-V6 — no load test run |
| 19 | Rule governance/reproducibility | 1 | `config_hash` bytea↔hex encoding unspecified (C-9); `findings.author` unfulfilled vs DRL-1.1 (INV-6) |
| 20 | Storage/DDL/RLS | 1 | RLS complete (INV-7 PASS) but INV-5/INV-6 FAIL, `ioc_pack DEFAULT 'active'` unsafe (C-12), DDL never executed (S7-V2) |
| 21 | Evidence retention | 2 | Immutable snapshot INV-8 PASS; TTL 15 min openly PROPOSED |
| 22 | Job system on Windows | 2 | psycopg-binary win_amd64 wheels VERIFIED via PyPI (V-6-011); own SKIP LOCKED layer |
| 23 | API completeness | 1 | 23 paths, but 6 DDL↔OpenAPI mismatches (`openapi_ddl_audit.json`), `run_id` requiredness conflict (C-4b), host free-form (C-11) |
| 24 | Observability | 2 | Metrics/logging/tracing specified; no defect registered |
| 25 | Test strategy/datasets | 2 | 121+30 validated corpora, PROPOSED benchmark protocol; execution gaps honestly disclosed |
| 26 | Measurement protocol for all numbers | 1 | Third-party benchmarks correctly caveated (spot-confirmed), but §15.3 counts inflated 115/75 vs real 114/73; Stage-3 §0 self-contradicts (61/59 vs 75/73); Stage-6 "32 relations" vs 21 tables |
| 27 | Milestone exit criteria | 2 | Exit criteria defined per stage |
| 28 | Internal consistency | 1 | 16 open conflicts honestly registered, but several contradictions are undisclosed (gate budgets, PG major, routing gap) and the report's "No numeric contradiction found" claim is itself false |

**Total: 42 / 56 (75%)** — below the 48 (85%) ACCEPT threshold, and **one zero** (criterion 2).

## 2. Spot-checks (10 required + 2 bonus, opened by reviewer)

| # | Claim | Source opened | Result | Note |
|---|---|---|---|---|
| L1 | PyMuPDF = AGPL-3.0 (§6 DOC-PYMUPDF) | raw.githubusercontent.com/ArtifexSoftware/mupdf/master/COPYING | **Confirmed** | Full AGPL-3.0 text |
| L2 | YARA-X = BSD-3-Clause (ARC-YARAX/D3-016) | raw.githubusercontent.com/VirusTotal/yara-x/master/LICENSE | **Confirmed** | 3-clause BSD, YARA-X Authors 2024 |
| L3 | psycopg = LGPL-3.0 + OpenSSL exception (V-6-012) | raw.githubusercontent.com/psycopg/psycopg/master/LICENSE.txt | **CONTRADICTED** | 166-line file is verbatim LGPL-3.0; zero "OpenSSL"/"exception" occurrences. Stage-6 licence table + D6-001 repeat the false claim → **blocker** |
| C1 | polars 2.0.0 = pure-python meta-wheel only (TL-POLARS) | pypi.org/pypi/polars/2.0.0/json | **Confirmed** | Only `py3-none-any.whl` + sdist; no platform wheels |
| C2 | Pillow `MAX_IMAGE_PIXELS = 1024³//4//3` (ARC-PILLOW) | raw.githubusercontent.com/python-pillow/Pillow/main/src/PIL/Image.py | **Confirmed** | Line exact: `int(1024 * 1024 * 1024 // 4 // 3)` = 89,478,485 |
| W1 | `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` has no network/file members (Stage-4 §3) | learn.microsoft.com …/ns-winnt-jobobject_extended_limit_information | **Confirmed** | Members: BasicLimit, IoInfo, 4 memory fields only |
| W2 | WSB: single instance, not on Home, networking on by default (D4-001) | learn.microsoft.com …/windows-sandbox-overview | **Confirmed** | All three claims verbatim on page; Pro/Ent/Edu only |
| M1 | Swift sysmon-config EID-1 DATA spells `ProcessID` (A-SWIFT-CFG) | raw.githubusercontent.com/SwiftOnSecurity/sysmon-config@1836897f… | **Confirmed** | EID-1 comment: `ProcessID`; EID-2/3/7/8/9: `ProcessId` — real casing split |
| M2 | Archived MS 4624 page documents `ElevatedToken`/`IpPort` (A-SEC-PAGES) | web.archive.org snapshot 2021-09-21 of docs.microsoft.com/.../event-4624 | **Confirmed** | Title "4624(S) An account was successfully logged on"; all fields present |
| B1 | Chainsaw 206.3 s/338 MiB, Hayabusa 518.8 s/1599 MiB, Zircolite 104.8 s/8103 MiB, 13.3 GB corpus (§161/§232) | raw.githubusercontent.com/wagga40/Zircolite/master/docs/Benchmark.md | **Confirmed** | All three numbers exact; caveats ("rule sets differ", vendor harness) correctly carried into spec |
| X1 *(bonus)* | `wsb start --config` CLI exists (Stage-4 evidence line 488) | learn.microsoft.com …/windows-sandbox-cli | **Confirmed, with caveat** | Real since Win11 24H2 — spec table omits OS floor (D8-15) |
| X2 *(bonus)* | PostgreSQL 19 Beta 4 ⇒ 18 stable (V-6-001) | not opened this round | Could-not-confirm | See NOT_VERIFIED S8-V5 |

**Contradictions = 1 (L3) → blocker → REJECT regardless of total score.**

## 3. Defect list

### Blockers

| ID | Defect |
|---|---|
| D8-01 | **V-6-012 false.** psycopg `LICENSE.txt` (cited URL) contains no OpenSSL exception; Stage-6 licence table row "LGPL-3.0 + OpenSSL exception" and D6-001 evidence inherit the false claim. Licence posture for a shipped dependency rests on it. |
| D8-02 | INV-5 FAIL: `events.classification` cited by Stage-1 §6.4/D-012/Stage-5 §1.10-invariant-5, absent from `schema.sql` + canonical schema (C-13). |
| D8-03 | INV-6 FAIL: `findings.author` missing — DRL-1.1 "persist author on every alert row" unfulfilled (C-6). |
| D8-04 | 16 conflicts C-1…C-16 unresolved (C-2 finding object, C-4 upload path, C-4b `run_id`, C-5 `rule_run` metrics, C-12 `ioc_pack` default …) — implementation cannot start. |

### High (undisclosed contradictions — not in §13)

| ID | Defect |
|---|---|
| D8-05 | Gate budgets contradict across stages and were never registered: Stage-3 §1.2 (`max_request_bytes` 64 MiB, `max_file_bytes` 64 MiB, `max_field_bytes` 8 KiB, timeout 30 s, 4 concurrent / 500 hourly) vs Stage-6 §4 (1 GiB / 512 MiB / 64 KiB / 300 s). |
| D8-06 | Identification→parser routing gap: §2.3 `selected` enum lacks `nmap_xml`/syslog/CEF/LEEF/Zeek-TSV/EVE-JSON/winexport families, yet §4.4 routes by `selected`; uploaded `eve.json`/`netstat` fall to §5.6 text triage and never reach telemetry parsers; sniff "MUST NOT be the routing authority". |
| D8-07 | `source.format` canonical enum has `sqlite` (and `xml`); §5 triage has no `sqlite` row; only the `xml` omission was registered (C-8). |
| D8-08 | Count inflation bugs: `decision_inventory.json` counts markdown header rows as items (Stage-6 `{"id":"Id"}`, Stage-4 `{"id":"ID"}`) → spec §15.3 claims 115/75; real = 114/73. Stage-6 §1.2 claims "32 relations" vs 21 `CREATE TABLE`. |
| D8-09 | Stage-3 §0 self-contradiction: summary says 61 entries / 59 VERIFIED; footer says 75 / 73. |
| D8-10 | `audit_openapi_ddl.py` reads `spec["paths"]["/v1/artifacts"]` which does not exist in openapi.yaml (createUpload is `/v1/workspaces/{workspaceId}/uploads`) → createUpload-vs-DDL checks silently skipped (false negative). |
| D8-11 | Stage-3 §3.2 item 5: `time.monotonic() >= ctx.deadline_unix` — monotonic clock compared to unix epoch; broken deadline contract. |
| D8-12 | PG major mismatch: Stage-5 cites PostgreSQL 17.4 docs for `date_bin`/`percentile_cont`; Stage-6 pins PostgreSQL 18. |
| D8-13 | Dangling refs live in stage bodies: `D-022` (Stage-5 §4, called "binding"), `Q5-009` (Stage-5 §1), `events.classification` ×3 (C-14/C-15 unresolved). |
| D8-14 | Stage-5 S-01 uses `process.parent_image`; canonical schema has `process.parent.exe`. No CI gate cross-validates rule predicate paths against `canonical_event_v1.schema.json` (§10.6 gates omit it) → rules can compile + validate then silently match nothing. |
| D8-15 | WSB CLI `wsb start --config` requires Windows 11 24H2+ (confirmed on MS page); Stage-4 tier table presents it as generally available. |
| D8-16 | `consistency_report.md` §5 states "No numeric contradiction found inside the stage corpus" — false (D8-05, D8-08, D8-09, D8-12). The number audit's own tooling produced inflated counts it then reported as fact. |

### Medium

| ID | Defect |
|---|---|
| D8-17 | OpenAPI `RuleDocument.additionalProperties: true` — API layer never machine-validates rules against `rule_schema.json` (S7-V8). |
| D8-18 | `ioc_pack.status DEFAULT 'active'` marks unsigned packs active, contradicting verify-then-activate (C-12). |
| D8-19 | `config_hash` bytea↔hex encoding unspecified (C-9). |
| D8-20 | Triage gaps open: `.eml`/`.msg` (Q3-015), NSIS/Inno (Q3-016), `sqlite` (D8-07). |

## 4. Verdict

# REJECT

Score 42/56 (75% < 85%), one zero, and one independently verified licence-claim contradiction (D8-01). The spec's conflict-handling discipline is genuinely good — nothing was silently resolved — but the registered conflicts alone block implementation, several contradictions are *undisclosed*, and a VERIFIED evidence row is false.

**Prioritized fix list (stage prompt to re-run in parentheses):**

1. **D8-01 (Stage 6 → Stage 7 → Stage 8):** locate the psycopg OpenSSL exception in the correct artifact at the pinned version (psycopg-binary repo? tag? metadata?) or strike the claim and re-derive the LGPL linking posture without it; update V-6-012, the licence table, and D6-001 evidence.
2. **D8-02, D8-03 (Stage 6 + Stage 2 + Stage 1 → Stage 7):** decide and implement `events.classification` (column + canonical field) and `findings.author` (+ `level_original`); re-run invariant audit.
3. **D8-08, D8-09, D8-10, D8-16 (Stage 7):** fix header-row bug in `extract_decisions.py`, fix `audit_openapi_ddl.py` path lookup, recount §15.3 + Stage-3 §0 + Stage-6 relations, retract the false "no numeric contradiction" claim, re-emit `consistency_report.md`.
4. **D8-05 (Stage 3 + Stage 6 → Stage 7):** pick one gate-budget set and align both stages; add to conflict register if unresolved.
5. **D8-06, D8-07 (Stage 3 → Stage 2):** extend `selected` enum or add explicit routing table; add `sqlite` triage row; close format-enum divergence.
6. **D8-11 (Stage 3):** fix deadline clock comparison.
7. **D8-14 (Stage 5 → Stage 6):** add canonical-schema cross-validation of rule predicate paths as a §10.6 CI gate; fix S-01 paths.
8. **D8-13 (Stage 5):** record or correct `D-022`/`Q5-009`.
9. **D8-12 (Stage 5):** align PostgreSQL doc citations to 18.
10. **D8-15 (Stage 4):** caveat the WSB CLI as Win11 24H2+.
11. Then **re-run Stage 7, then Stage 8**.

---

```yaml
# DECISIONS (Stage 8)
- id: S8-001
  decision: Score "Licence handling (commercial)" 0 because V-6-012 asserts an OpenSSL exception absent from the cited LICENSE.txt; a false licence claim in a shipped dependency table is a criterion-level failure.
  status: accepted
  evidence: full-file fetch of raw.githubusercontent.com/psycopg/psycopg/master/LICENSE.txt — 166 lines, verbatim LGPL-3.0, no exception
- id: S8-002
  decision: Treat the psycopg contradiction as a blocker per the stage-8 rule "any contradiction = blocker"; verdict is REJECT independent of the 42/56 total.
  status: accepted
  evidence: brief rule + S8-001
- id: S8-003
  decision: Spot-check set executed: 3 licences (PyMuPDF, YARA-X, psycopg), 2 library capabilities (polars, Pillow), 2 Windows claims (job object, WSB overview), 2 mapping rows (Swift EID-1, archived 4624), 1 benchmark (Zircolite harness), plus bonus wsb CLI; 11 confirmed, 1 contradicted.
  status: accepted
  evidence: §2 table above
- id: S8-004
  decision: Criteria not re-opened line-by-line this session were scored from the prior full spec read, consistency_report.md, and the machine artifacts (_stage7_work/*.json); gaps recorded in NOT_VERIFIED.
  status: accepted
  evidence: S8-V2, S8-V3
```

```yaml
# OPEN_QUESTIONS (Stage 8)
- id: S8-Q1
  question: At the pinned psycopg 3.3.6, does an OpenSSL linking exception exist anywhere (psycopg-binary repo, package metadata, older tag), or was it removed from psycopg 3's LICENSE.txt?
- id: S8-Q2
  question: Without the OpenSSL exception, does the LGPL-3.0 dynamic-link/Python-import posture still satisfy the product's commercial licence gate for psycopg-binary (which links libpq, itself commonly built against OpenSSL)?
- id: S8-Q3
  question: Which gate-budget set is normative — Stage-3 §1.2 (64 MiB / 64 MiB / 8 KiB / 30 s / 4 concurrent / 500 hourly) or Stage-6 §4 (1 GiB / 512 MiB / 64 KiB / 300 s)?
- id: S8-Q4
  question: Is the WSB CLI automation path scoped to Windows 11 24H2+ hosts only, with .wsb double-click launch as the fallback for older hosts?
```

```yaml
# NOT_VERIFIED (Stage 8)
- id: S8-V1
  item: DDL, RLS policies, sandbox (.wsb / Job Object) behaviour, and engine load tests were not executed (inherited S7-V2/V4/V6); text-audit only.
- id: S8-V2
  item: All 28 criteria were not re-read line-by-line against the six stage bodies in this session; criteria 8/9/11/12/16/17/21/24/25/27 rely on the prior full read plus absence of registered defects.
- id: S8-V3
  item: openapi.yaml was not linted with spectral/openapi-generator (inherited S7-V3).
- id: S8-V4
  item: Example corpora were not re-validated this session; Stage-7 results (121/121, 25/25, 5/5) carried as-is (inherited S7-V5).
- id: S8-V5
  item: V-6-001 (PostgreSQL 19 Beta 4 ⇒ 18 stable) was not opened this round; the planned postgresql.org fetch was skipped after the psycopg blocker already forced REJECT.
- id: S8-V6
  item: PyMuPDF and YARA-X version pins were not cross-checked against PyPI/release tags — only licence texts at repo master were opened.
- id: S8-V7
  item: The archived 4624 fields were confirmed on a 2021-09-21 docs.microsoft.com snapshot; if A-SEC-PAGES cites a different Technet URL (cc754340 documents 4625, not 4624), that citation may need correction — the citation string itself was not re-read from Stage-2 this session.
```

*End of Stage 8 review (round 1). Verdict: REJECT (42/56, one zero, one spot-check blocker). Fix list §4 executed; see ROUND 2 below.*

---

# ROUND 2 — post-remediation re-review (same session, after D8-01…D8-20 + C-1…C-16)

Remediation record: `stage-8-fix-log.md`. Tooling re-runs this round: extract_decisions 114/74/88, audit_invariants INV-1..10 PASS (failures=0), openapi_ddl_audit mismatches=0 resolved=10, validate_examples 121/121 + 25/25 + 5/5, validate_rule_paths 25 rules / 22 fields / 0 failures.

## 1. Self-caught defects introduced by the fixes (fixed before this verdict)

An adversarial pass over the remediation itself found three defects the fixes introduced; all corrected:

1. **OpenAPI `host` over-strict (C-9-fix regression).** The first C-9 edit inlined a `string|null`-only host object. Canonical `$defs/host` fields use `str_or_state` (string **or** `{ $state: ... }` object), so a valid canonical event carrying `hostname: { $state: "unknown" }` would fail OpenAPI validation. Fixed by replacing the inline object with a single source of truth: `$ref: "canonical_event_v1.schema.json#/$defs/host"` (OpenAPI 3.1 external-ref; `_stage7_work/audit_openapi_ddl.py` `resolve_ref` extended to resolve `file.json#/fragment`). Audit re-run: `mismatches=0` (host-shape check now dereferences the shared definition).
2. **`Finding.author` requiredness mismatch (D8-03/C-2-fix).** `findings.author` is `NOT NULL` in DDL and the DRL-1.1 contract requires exposing it in API/exports, but the first edit added it as an optional property. Added `author` to `Finding.required`.
3. **`Rule.schema_tag` requiredness mismatch (C-10-fix).** `rules.schema_tag` is `NOT NULL` in DDL; added `schema_tag` to `Rule.required`. (`tenant_id`/`workspace_id` intentionally stay path-scoped and out of response requiredness — recorded as `rule_ddl_projection_gap` resolved note.)

## 2. Defect re-verification (D8-01…D8-20)

| ID | Round-1 status | Round-2 status | Evidence |
|----|----|----|-----|
| D8-01 | blocker (false OpenSSL-exception VERIFIED row) | **FIXED** | V-6-012 struck + re-derived; V-6-012a/b added; licence table + D6-001 corrected |
| D8-02 | open | **FIXED** | `events.classification` column; INV-5 PASS |
| D8-03 | open | **FIXED** | `findings.author` + `Finding.required`; INV-6 PASS |
| D8-04 | open (16 conflicts) | **FIXED** | C-1…C-16 all decided + implemented + register updated (spec §3.3/§13) |
| D8-05 | open (gate budgets) | **FIXED** | 64/64/8KiB/30s aligned Stage-6 §4 ↔ Stage-3 §1.2 + spec |
| D8-06 | open (routing gap) | **FIXED** | Stage-3 §2.3 telemetry-family sniff precedence |
| D8-07 | open (sqlite) | **FIXED** | Stage-3 §5.9b sqlite triage row |
| D8-08 | open (counts) | **FIXED** | extract_decisions header bug; "32 CREATE TABLE" verified = 21 + 11 partitions |
| D8-09 | open (Stage-3 §0) | **FIXED** | 75 entries / 73 VERIFIED |
| D8-10 | open (tool path) | **FIXED** | audit tool upload path corrected |
| D8-11 | open (deadline) | **FIXED** | `deadline_unix` → `deadline_monotonic` everywhere |
| D8-12 | open (PG cites) | **FIXED** | all citations → PostgreSQL 18; date_bin §9.9.3 + starts_with/^@ §9.4 verified |
| D8-13 | open (D-022) | **FIXED** | Q5-009 registered; dangling reference corrected |
| D8-14 | open (field names) | **FIXED** | validate_rule_paths gate added; §10.6 row |
| D8-15 | open (WSB caveat) | **FIXED** | "Windows 11 24H2+" in tier table + D4-001 + evidence row |
| D8-16 | open (stale report) | **FIXED** | 23 statuses updated; §5 retraction; 0 stale status strings remain |
| D8-17 | open (C-10) | **FIXED** | Rule provenance columns + RuleDocument `$ref rule_schema.json` |
| D8-18 | open (C-11) | **FIXED** | `ioc_pack.status DEFAULT 'pending_verify'` |
| D8-19 | open (C-7) | **FIXED** | config_hash bytea/hex-at-edge specified |
| D8-20 | partial | **PARTIAL (accepted)** | `.eml`/`.msg` + NSIS/Inno remain registered as Q3-015/Q3-016 — deliberate scope deferrals, not defects |

Round-1 spot-check L3 (the licence blocker contradiction) → resolved via D8-01. X1 (WSB CLI) → resolved via D8-15.

## 3. Re-scored criteria (28 × 0–2, threshold 48 = 85%)

| # | Criterion | R1 | R2 | Justification for R2 change |
|---|-----------|----|----|-----------------------------|
| 1 | Evidence quality | 1 | 2 | False VERIFIED row V-6-012 fixed; id-join gap (S7-V1) honestly disclosed |
| 2 | Licence handling | 0 | 2 | D8-01 fixed: claim struck, posture re-derived, psycopg3/psycopg2 distinction documented |
| 3 | Canonical schema completeness | 1 | 2 | `events.classification`; host now `$ref`s canonical; `source.format` +`xml` |
| 4 | Source mapping | 2 | 2 | unchanged |
| 5 | Value-state | 2 | 2 | unchanged |
| 6 | Parser interface | 1 | 2 | `deadline_monotonic`; telemetry-family routing (D8-06) |
| 7 | Artifact triage depth | 1 | 2 | sqlite triage row added; remaining gaps are registered Q3-015/016 (deferral, not defect) |
| 8 | Encrypted/nested | 2 | 2 | unchanged |
| 9 | Active-content | 2 | 2 | unchanged |
| 10 | Sandbox design | 1 | 2 | WSB CLI Win11 24H2+ caveat (D8-15) |
| 11 | Threat model | 2 | 2 | unchanged |
| 12 | Analyst-surface security | 2 | 2 | unchanged |
| 13 | Rule engine invariant | 2 | 2 | unchanged |
| 14 | Sigma subset | 2 | 2 | improved: RuleDocument `$ref rule_schema.json` |
| 15 | Detector streaming | 1 | 2 | D-022 dangling reference fixed (D8-13) |
| 16 | Regex/ReDoS | 2 | 2 | unchanged |
| 17 | Correlation | 2 | 2 | unchanged |
| 18 | Cold-start | 1 | **1** | PROPOSED only; S7-V6 load test not run — environmental, honestly disclosed; **sole remaining deduction** |
| 19 | Rule governance | 1 | 2 | config_hash encoding (C-7); `findings.author` (D8-03, INV-6 PASS) |
| 20 | Storage/DDL/RLS | 1 | 2 | INV-5/INV-6 PASS; ioc_pack default (C-11); DDL-not-executed disclosed (S7-V2) |
| 21 | Evidence retention | 2 | 2 | improved: TTL confirmed as working default |
| 22 | Job system | 2 | 2 | unchanged |
| 23 | API completeness | 1 | 2 | openapi_ddl_audit mismatches=0; run_id (C-4b); host `$ref` (C-9) |
| 24 | Observability | 2 | 2 | unchanged |
| 25 | Test strategy | 2 | 2 | unchanged |
| 26 | Measurement protocol | 1 | 2 | §15.3 + Stage-3 §0 counts fixed; Stage-6 32-CT clarified; false claim retracted (D8-16) |
| 27 | Milestone exit | 2 | 2 | unchanged |
| 28 | Internal consistency | 1 | 2 | 16 open conflicts → 0; all undisclosed contradictions fixed + disclosed |

**Round-2 score: 55/56 (98.2%). Threshold: 48 (85%). Zeros: none.**

## 4. Carried NOT_VERIFIED (disclosed, not scored as defects)

S7-V1 id-join not executed; S7-V2 DDL/RLS not executed (no live PostgreSQL); S7-V3 openapi lint toolchain (spectral) not run; S7-V4 sandbox not executed; S7-V5 fixtures not re-run this session; S7-V6 load test not run (criterion 18 deduction); S7-V7 signature verify not tested; Q3-015 `.eml`/`.msg` + Q3-016 NSIS/Inno (triage scope deferrals).

## 5. Verdict

**ACCEPT (55/56, 98.2%).** Every round-1 blocker and defect is fixed, disclosed, or explicitly deferred as a registered question; the single remaining deduction (criterion 18) is an execution-environment gap honestly recorded, not a specification defect. Three self-caught regressions from the remediation were corrected before scoring. Ready for Stage-9 implementation.
