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
  - claim: Stage-2 canonical payload field names used in examples (process.parent_image etc.).
    checked: >-
      Verified fields are cited inline where used (registry.*, fim.*, config_check.*,
      powershell.script_block_text, network.bytes_sent, authentication.*, dns.query_name,
      process.exe/command_line/hashes.sha256). process.parent_image and file.hashes.sha256
      appear in examples as Stage-1/Stage-2-shaped names; exact canonical paths must be
      confirmed against canonical_event_v1.schema.json at implementation time.
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
