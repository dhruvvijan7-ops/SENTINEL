# M1 NOTES — Stage-1 decision record × Stage-7 consistency report

Audience: coding agent implementing Milestone 1 (M1). Sources read in full:
`stage-1-landscape-and-rule-engine-decision.md` (662 lines, compiled 2026-10-08) and `consistency_report.md` (345 lines, generated 2026-10-10).
Rules: ids/enums/licences verbatim. Where a fact is absent from these two files it says **not specified** (cross-file facts are explicitly attributed to the other file they were verified in).

**File precedence (Stage-1 §6.1 banner, C-1-fix):** `canonical_event_v1.schema.json` > `schema.sql` > `openapi.yaml` > stage bodies.
**Namespace warning:** Stage-1 §3 uses labels **M1–M4** for *matrix-derived facts* (product-fit gap etc.) — a different namespace from "Milestone 1". Stage-1 decisions are **D-001…D-012 only** (§3 of consistency_report: "Stage-1 only defines D-001…D-012").

---

## 1. Stage-1 DECISIONS D-001…D-012 (§8.1)

| Id | Decision (condensed, load-bearing details kept) | Status | Confidence / gate |
|---|---|---|---|
| D-001 | Stage-1 evidence base = 4 companion research files + verification metadata (34 repo rows + 12 non-repo sources) + 2 delegated reports (LIGHT-HIDS; Sysmon/Sysinternals); claims outside them labelled INFERRED or UNVERIFIED. | ACCEPTED | high; evidence §1, §1.2 |
| D-002 | Product-fit gap (matrix M1): no studied product combines offline file-upload analysis + Windows/EVTX depth + a modern Sigma engine inside a commercially usable licence envelope; Sentinel pursues exactly that gap. | ACCEPTED | high; evidence §3 C1/C2/C6, §2 |
| D-003 | MVP scope frozen as MVP-1..MVP-8 (EVTX ingest, Sigma pack, PCAP/TShark+Suricata, YARA scan, endpoint-export static analysis, evidence-preserving alerts, staged job lifecycle, benchmark harness). FIM, SCAP/SCA, live agents, LIGHT-HIDS ML explicitly out/deferred with triggers. | ACCEPTED | high; evidence §4.1, §4.2, §4.3 |
| D-004 | RED-001 rule engine: **Option C primary** — compile detections to SQL executed on canonical events in PostgreSQL, correlation as compiled plans; **mandatory native row-level evaluator** as fallback + conformance oracle; Option B (fully native) contingency if PoC thresholds T2/T3 fail; Option A rejected standalone (pays LGPL cost, buys no evaluation code); Option D (external hunter) dev-oracle only (product path violates canonical-events invariant + licence risk). | **RECOMMENDED_PENDING_POC** | medium-high; `poc_gate`: ENGINE_POC.md — T1 100 % conformance on implemented constructs; T2 ≥95 % SQL compile rate; T3 zero path divergences + ≥3× speedup at N1 |
| D-005 | Shipped runtime must **not embed LGPL/GPL/AGPL code**: converter tooling runs isolated (C1 acceptable **in PoC only**); standing preference **C2 = our own Sigma→PostgreSQL backend**, judged against public conformance suite. | ACCEPTED | high; `legal_gate`: counsel review of LGPL-3.0 (MED–HIGH flag) before dependency freeze |
| D-006 | Canonical event envelope + canonical rule document (`sentinel-rule/v1`) fixed as normative; aliasing lives in one import layer; compiled SQL stored per rule as evidence; **`tenant_id` on every row from day 1** (tenancy = multi-tenant-ready, single-tenant first). | ACCEPTED | high; evidence §6.1, §6.2, §5.6 |
| D-007 | **Three classification axes kept separate, never collapsed:** `alerts.severity` = LOW\|MEDIUM\|HIGH; `alerts.level_original` = upstream verbatim (Sigma five `informational…critical`, Falco priority, Wazuh 0–16); `events.classification` = `public\|internal\|restricted`. | ACCEPTED_INTERPRETATION (axis naming confirmed via OPEN_QUESTIONS Q1) | medium; evidence §6.4 |
| D-008 | v1 adapters: Sigma (primary, incl. correlation), Falco, YARA, Suricata, Wazuh-XML (**customer-owned rules only**), Sysmon config (telemetry profile, not detection). Every unsupported construct produces an explicit reason code; **silent skips forbidden**. | ACCEPTED | high; evidence §6.3, §7.1 item 3 |
| D-009 | Licence rules of engagement (§2.3) binding: no copying from Wazuh/Chainsaw/Hayabusa-code/Velociraptor/MISP/Elastic/ET-GPL-range/SwiftOnSecurity; allowed imports = SigmaHQ rules (DRL 1.1, author carried to alerts), sysmon-modular (MIT), Falco rules (Apache-2.0), ComplianceAsCode (BSD-3), Feodo (CC0); **HIGH legal flags need sign-off before dependency freeze**. | ACCEPTED | high; evidence §2.1, §2.2, §2.3 |
| D-010 | Performance truth policy: **no throughput/memory number ships unless produced by the MVP-8 harness** (protocol §5.7; targets §4.4). Public third-party numbers = directional context only, labelled `PROPOSED - TO BENCHMARK`. | ACCEPTED | high; evidence §4.4, §5.1, §7.2 avoid-3 |
| D-011 | Architecture lessons as named principles: one alias layer (Chainsaw); run-wide correlation + output profiles + FP knobs (Hayabusa); layered prefilter/unified workspace/CSV hardening (Zircolite); layered rule trees + self-benchmark stats (Wazuh); version gating + validation-first CLI + ordered override semantics (Falco). | ACCEPTED | high; evidence §7.1..§7.5 |
| D-012 | Job status semantics: any partial parse/convert/execute ⇒ **`COMPLETED_WITH_WARNINGS`** (never `SUCCESS`, never silent drop); **empty rule pack ⇒ exactly zero detections**; parse errors keep original bytes reachable via `raw_ref`. | ACCEPTED | high; evidence §4.4, §5.6 |

Stage-1 §8.2 also carries OPEN_QUESTIONS **Q1–Q12** (12, verified count in consistency_report §5) — key for M1: Q1 (three-axis meaning), Q2 (T1/T2/T3 thresholds), Q3 (C1 vs C2 counsel gate), Q7 (DRL attribution surface), Q11 (Sigma case-sensitivity must be pinned before C2 coding). Stage-1 ends: "Stage 2 may begin only with ENGINE_POC.md results (§5.7) resolving D-004's gate."

**RLS:** Stage-1 itself never mentions RLS — only `tenant_id` on every row (D-006). RLS appears in consistency_report INV-7 (see §6.4 below).

---

## 2. Stage-1 §4 MVP scope

### 2.1 In scope (MVP-1…MVP-8, §4.1)

| ID | Capability | Input | Detection path / notes |
|---|---|---|---|
| MVP-1 | EVTX ingestion → canonical events | `.evtx` (Windows Security, System, Application, PowerShell-Operational, Sysmon channels) | external Rust EVTX parser (`evtx_dump` process or our Rust helper on `evtx` crate, §2.1) → canonical events → detector; Sysmon channel `Microsoft-Windows-Sysmon/Operational`, export via `wevtutil epl` |
| MVP-2 | Sigma detection pack (**optional, default EMPTY**) | rule pack (SigmaHQ corpus DRL 1.1 or customer rules) | engine per §5 decision; zero hardcoded detections ⇒ empty pack yields zero detections (invariant, tested in CI) |
| MVP-3 | PCAP analysis | `.pcap`/`.pcapng` | external TShark (field extraction) + Suricata `-r` offline replay **only if customer-installed** (licence §2.1); EVE alert JSON ingested as canonical events |
| MVP-4 | File content scanning | any uploaded file | external YARA/YARA-X process; rules = our own + DRL/permissive packs |
| MVP-5 | Static analysis of endpoint exports | Autoruns CSV (`autorunsc -c`), Sigcheck CSV (`sigcheck -c -h`), Sysmon config XML | parsers → canonical events → detector; **static only** |
| MVP-6 | Evidence-preserving alerts | — | store full canonical event + rule provenance (`repo@commit:path`) + rule `author` (DRL §2.3) + original rule level **and** 3-level severity (never collapsed) + `COMPLETED_WITH_WARNINGS` partial status |
| MVP-7 | Batch job lifecycle | upload → parse → detect → report | background worker; per-stage timings (model: Zircolite `--performance-json`) |
| MVP-8 | Benchmark harness (**build in MVP, not optional**) | synthetic + sample corpora (§5 PoC) | measures throughput/memory/conformance from day 1 |

Explicit MVP non-goals: multi-tenant enablement (schema carries `tenant_id` day 1, UI/API single-tenant), ML detection, live agents, dashboards, SOAR.

### 2.2 Out of scope (whole product, §4.2)
Live agents · kernel drivers / eBPF / ETW subscription · active response or blocking · FIM baselines (needs live host) · SCAP/OVAL/XCCDF compliance scanning (OpenSCAP Windows support void since 2022-02-01; Wazuh SCA is its own YAML language) · Kafka/Kubernetes · SOAR · cross-source live correlation · **bundling GPL/AGPL engines** (§2.1).

### 2.3 Deferred with rationale (§4.3)
LIGHT-HIDS ML detector (paper needs integer-mapped syscall sequences; no code/weights/data released; never mentions Windows; trigger = Windows-compatible syscall collector or author release) · Wazuh XML/Falco YAML as first-class adapters beyond v1 (GPLv2 content; trigger = customer demand) · osquery/Tetragon data sources (live-only; trigger = agent phase) · Velociraptor-native artifact execution (AGPL — "**Never as code**; format study only").

### 2.4 Scale/status targets (§4.4, all `PROPOSED - TO BENCHMARK`)
10 M events run 1 / 50 M run 2; detection wall-clock ≤120 s (run 1, full SigmaHQ active pack) and ≤600 s (run 2) on stated 8-core/32 GB box; peak RSS ≤8 GB at 13.3 GB input class; any parse/rule failure ⇒ `COMPLETED_WITH_WARNINGS` never `SUCCESS` never silent skip; empty pack ⇒ exactly 0 detections.

---

## 3. Stage-1 §2 Licence Register (M1-constraining rows)

**Usage classes (§2):** `DEPENDENCY` = code/content shipped in or imported into Sentinel · `EXTERNAL_PROCESS` = separate binary executed at runtime, never linked · `REFERENCE_ONLY` = study only, no code/content copied · `AVOID` = do not redistribute, embed, or serve. Commercial/closed-source distribution assumed. "Legal flag" = LOW/MED/HIGH counsel-review recommendation.

### 3.1 §2.1 Code & engines (full register; M1-relevant rows bolded)

| Project | Code licence (SPDX, evidence) | Usage class | Commercial impact | Flag |
|---|---|---|---|---|
| **Rust `evtx` crate** | MIT OR Apache-2.0 (`Cargo.toml` dual LICENSE) | DEPENDENCY (our Rust parser helper) / EXTERNAL_PROCESS (`evtx_dump`) | Permissive; retain notices; no source obligation | LOW |
| **python-evtx** | Apache-2.0 | DEPENDENCY (fallback parser) | Apache patent grant + notice retention | LOW |
| **pySigma** | **LGPL-2.1-only** | DEPENDENCY **or** EXTERNAL_PROCESS (`sigma-cli`, also LGPL-2.1) | Closed-source OK if library unmodified + dynamically loadable + licence text + relink ability shipped; **modifications to pySigma force source release of the modified library** | MED |
| **pySigma pipelines `windows`/`sysmon`** | LGPL-2.1 | DEPENDENCY (import-time field mapping) | Same LGPL-2.1 obligations as pySigma | MED |
| **pySigma SQLite backend** | **LGPL-3.0-only** | DEPENDENCY / EXTERNAL_PROCESS; copying its code into our backend = creating a derivative | LGPL-3.0 obligations; **LGPL-3 vs LGPL-2.1 incompatibility must be checked** | MED–HIGH |
| SigmaHQ pipelines ossem/ocsf/rclinuxedr | not fetched | not assigned | UNVERIFIED — fetch before use | — |
| **YARA** | BSD-3-Clause | DEPENDENCY / EXTERNAL_PROCESS | Permissive; retain notice | LOW |
| **YARA-X** | BSD-3-Clause | DEPENDENCY (Rust) / EXTERNAL_PROCESS | Permissive; retain notice | LOW |
| **yara-python** | Apache-2.0 (bundles libyara BSD-3) | DEPENDENCY | Permissive; notice retention for both | LOW |
| DuckDB | MIT | DEPENDENCY (analytics/scratch, if needed) | Permissive | LOW |
| cti-python-stix2 | BSD-3-Clause | DEPENDENCY (STIX 2.1 import) | Permissive | LOW |
| misp-stix | BSD-3-Clause | DEPENDENCY (MISP↔STIX, if needed) | Permissive | LOW |
| osquery | Apache-2.0 **OR** GPL-2.0-only (no OpenSSL exception) | REFERENCE_ONLY in MVP; DEPENDENCY/EXTERNAL_PROCESS permissible by **electing Apache-2.0** | Election documented in our NOTICE; GPL branch avoided | LOW |
| Tetragon | Apache-2.0 | REFERENCE_ONLY (Linux live telemetry, out of scope) | None if not shipped | LOW |
| Falco engine + libs + plugins | Apache-2.0 | EXTERNAL_PROCESS (customer-installed) / REFERENCE_ONLY | Notice preservation; no source obligation | LOW |
| OpenSCAP | LGPL-2.1 | EXTERNAL_PROCESS (Linux-only customer install) / REFERENCE_ONLY | LGPL obligations only if we redistribute the binary | LOW–MED |
| ComplianceAsCode content | BSD-3-Clause | DEPENDENCY (optional SCAP content pack) | Permissive | LOW |
| **Suricata engine** | GPL-2.0 | **AVOID bundling**; EXTERNAL_PROCESS only if installed by customer under its own licence | Distributing binary inside closed-source product triggers GPLv2 source obligations | HIGH |
| AIDE | GPL-2.0 | REFERENCE_ONLY (FIM semantics); EXTERNAL_PROCESS if customer-run | Same bundling risk as Suricata | MED |
| **Wazuh manager/agent/ruleset** | GPL-2.0-only + OpenSSL exception (covers "decoders, rules and any other data file") | REFERENCE_ONLY; **AVOID** copying rules or code; EXTERNAL_PROCESS only customer-installed | GPLv2 explicitly covers Wazuh detection content — no rule copying into closed-source product | HIGH |
| Wazuh indexer/dashboard | Apache-2.0 | REFERENCE_ONLY (out of scope) | Permissive if ever used | LOW |
| OSSEC HIDS | GPL-2.0 | REFERENCE_ONLY | Same as Wazuh | MED |
| **Chainsaw** | GPL-3.0 (`Cargo.toml` `license = "GPL3"` non-SPDX; `LICENCE` GPLv3 text; no root LICENSE) | REFERENCE_ONLY (architecture lessons); EXTERNAL_PROCESS only if customer-run, unmodified, not bundled | GPLv3 patent + anti-tivoization; bundling in closed-source = AVOID | HIGH |
| **Hayabusa code** | **AGPL-3.0** | **AVOID** (dependency, bundling, modification); REFERENCE_ONLY for architecture | AGPL §13 can require releasing our service's modifications (Sentinel is a network service) | HIGH |
| **Hayabusa rule corpus (`hayabusa-rules`)** | **DRL 1.1** | DEPENDENCY (optional import pack) **with attribution obligations** (§2.3) | Alerts generated from these rules must retain `author` if supplied | MED |
| **Zircolite** | LGPL-3.0-or-later | REFERENCE_ONLY (do not copy code); EXTERNAL_PROCESS if run unmodified | Reimplementing ideas (SQL prefilter, auto-mode) is fine; copying code creates an LGPL-3.0 derivative | MED |
| **Velociraptor** | **AGPL-3.0** | **AVOID**; REFERENCE_ONLY | AGPL network clause; Rapid7-owned | HIGH |
| DeepBlueCLI | GPL-3.0 | REFERENCE_ONLY | Hard-coded heuristics not importable | MED |
| MISP core | AGPL-3.0 | **AVOID** (code); format study REFERENCE_ONLY via `misp-rfc` | AGPL + PHP service code not usable in our stack | HIGH |
| **elastic/detection-rules** | **Elastic License 2.0** — "You may not provide the software to third parties as a hosted or managed service, where the service provides users with access to any substantial set of the features or functionality of the software." | **AVOID** for shipping rules; REFERENCE_ONLY for format study | Sentinel is exactly a hosted/managed service — serving substantial Elastic content prohibited | HIGH |
| Sysmon / Autoruns / Sigcheck | Proprietary Microsoft freeware (no SPDX) | EXTERNAL_PROCESS (runs on customer machines; we do not redistribute) / REFERENCE_ONLY | Redistribution of MS tools not permitted; collection customer-side | MED |
| pySigma plugin directory JSON | repo licence UNVERIFIED | REFERENCE_ONLY until fetched | Data file used only for §5 counts | LOW |

### 3.2 §2.2 Detection content & data feeds

| Content | Licence | Usage class | Commercial impact | Flag |
|---|---|---|---|---|
| Sigma specification v2.1.0 | Public domain | DEPENDENCY (adopted as conformance spec) | None | LOW |
| **SigmaHQ rule corpus (4063 active rules)** | **DRL 1.1** | DEPENDENCY (default optional rule pack) | Free commercial use subject to: retain `author` on shared rules **and on match outputs** ⇒ **our alert records MUST carry rule `author` end-to-end**; retain licence notice/URI | MED (implementable) |
| Falco rule files | Apache-2.0 | DEPENDENCY (optional) | Notices only | LOW |
| Wazuh rules/decoders | GPLv2 incl. content | **AVOID** (copying); REFERENCE_ONLY | Rule text is explicitly licensed code-equivalent | HIGH |
| Chainsaw native rules + mappings | GPLv3 | **AVOID**; REFERENCE_ONLY | See code row | HIGH |
| ET Open ruleset (Suricata) | Mixed GPLv2/BSD/ETPRO sid ranges | **AVOID as a pack**; BSD-range sids only after per-sid audit (not done → UNVERIFIED) | GPLv2 sids cannot ship; ETPRO is commercial | HIGH |
| SwiftOnSecurity Sysmon config | CC-BY-4.0 claimed **only in XML header**; repo-level UNVERIFIED | REFERENCE_ONLY until verified | Attribution required if ever used | MED |
| **sysmon-modular configs** | MIT | DEPENDENCY (config modules we derive from) | Notices only | LOW |
| abuse.ch Feodo CSV | CC0 | DEPENDENCY (feed; currently empty) | None | LOW |
| abuse.ch URLhaus CSV | Custom ToS; Auth-Key for bulk | DEPENDENCY (subject to ToS) | ToS compliance + key handling | MED |
| Elastic detection rules | ELv2 | **AVOID** | Hosted-service prohibition | HIGH |
| LIGHT-HIDS paper | No code released | REFERENCE_ONLY | Academic citation only | LOW |

### 3.3 §2.3 Licence rules of engagement (binding for the coding agent — verbatim intent)
1. **Never** copy rule text, config text, or source from: Wazuh, Chainsaw, Hayabusa code, Velociraptor, MISP, elastic/detection-rules, ET Open (GPLv2/ETPRO ranges), SwiftOnSecurity (unverified).
2. **Allowed content imports with conditions**: SigmaHQ rules (DRL 1.1 → persist rule `author` on every alert row and expose it in API/exports), sysmon-modular (MIT → notice), Falco rules (Apache → notice), ComplianceAsCode (BSD → notice), Feodo (CC0).
3. **LGPL components** (pySigma, pipelines, SQLite backend): prefer EXTERNAL_PROCESS (`sigma-cli` subprocess) during PoC to defer obligations; if used as a library, ship full licence text + documented relink/replace procedure; never patch pySigma in place without releasing the modified library source.
4. Legal flags **HIGH** require counsel sign-off **before** the component enters `pyproject.toml` or a default rule pack.

### 3.4 Rows you might expect in Stage-1 §2 but are NOT there
- **PostgreSQL, FastAPI, pytest, uvicorn, psycopg, pgqueuer: no rows in Stage-1 §2 — not specified.** Stage-1 §8.3 (NOT_VERIFIED) says "PostgreSQL licence itself (not inspected this stage)".
- Cross-reference (verified in `stage-6-platform-storage-jobs-api-testing-release.md` §licence table, not in the two source files): FastAPI 0.143.0 = **MIT**; uvicorn = **BSD-3-Clause**; pytest 9.1.1 = **MIT**; psycopg/psycopg-binary 3.3.6 = **LGPL-3.0 plain, NO OpenSSL exception** (D8-01 correction — the OpenSSL exception belongs to psycopg2 2.x only); pgqueuer = **MIT** (vetted alternative); PostgreSQL = "PostgreSQL Licence".
- Stage-1 fixed stack (line 10): Python 3.12+/FastAPI/PostgreSQL/background worker; native tools (Rust EVTX parser, TShark, YARA) run as isolated external processes.

---

## 4. Stage-1 §6 canonical event — SUPERSESSION (C-1)

- **§6.1 said:** a flat JSON envelope for the `events` PostgreSQL table (one row per source record, `tenant_id` on every row, JSONB lossless payload): `event_id` (uuid-v7), `tenant_id`, `upload_id`, `source_format` (`evtx|autoruns_csv|sigcheck_csv|sysmon_xml|pcap_eve|json|xml|csv`), `source_ref`, `event_time`, `ingest_time`, `channel`, `provider`, `event_id` (Windows EID — **duplicate key bug**: two keys named `event_id`), `record_id`, `computer`, `classification` ("DATA CLASSIFICATION LEVEL 1 of 3"), `fields{dotted flat taxonomy}` incl. `raw{}`, `raw_ref`.
- **Status: SUPERSEDED (C-1-fix, Stage-8 round 1). Do NOT implement §6.1.** Banner: "retained for provenance only. The normative canonical-event envelope is `canonical_event_v1.schema.json` (`canonical-event/v1`), which supersedes this sketch in every detail — including the duplicate `event_id` key bug." File precedence: `canonical_event_v1.schema.json` > `schema.sql` > `openapi.yaml` > stage bodies.
- V2 shape (consistency_report §1.1): nested `schema_version`, `event{category,type,action,outcome,severity,derived_by}`, `tenant_id`, `workspace_id`, `run_id`, `time{utc,original,original_timezone,timezone_source,precision,state}`, `host{hostname,fqdn,ips,os,arch}`, `user`, `source{file_id,format,parser,parser_version,channel,provider,event_id,record,sha256}`, `raw`, `unmapped`. Key deltas vs V1: `upload_id`→`run_id` (+`source.file_id`); `classification` was absent until D8-02-fix (now optional enum field); flat `fields{}` → `unmapped{}` + structured objects; `raw_ref` → `raw`.
- **§6.4 also carries a C-2-fix banner:** `alerts.*` references (and "alert records" phrasing in MVP-6 / engine contract) realize as the **`findings`** table from Stage-6 `schema.sql` (D6-001 lineage); `alerts` is the superseded conceptual name; OpenAPI `Finding` is the API projection. Same semantics.
- **Not superseded:** §6.2 canonical rule document `sentinel-rule/v1` remains normative (D-006; machine-normative file = `rule_schema.json` per consistency_report S7-003). §6.3 import adapters and §6.4 three-axis table remain in force (§6.4 subject to Q1).
- Three axes (§6.4): severity mapping `informational|low→LOW`, `medium→MEDIUM`, `high|critical→HIGH`; `level_original` verbatim; `classification` set by parser per source (e.g. Security log EVTX ⇒ `restricted`), drives export/redaction policy. "These are three *different axes* and must never be collapsed into a single enum."

---

## 5. Stage-1 §5.7 PoC protocol (all thresholds `PROPOSED - TO BENCHMARK`; box: 8 cores / 32 GB / local PostgreSQL, Python 3.12)

Pins: SigmaHQ rules @`8a4813404e` (4063 active + 259 inactive stress set); `sigma-specification` @`ba9251aa834b` (`tests/`, `json-schema/`); `pysigma` resolved `<2.0`; `pysigma-backend-sqlite@0173066875` for reference runs.

| Verdict | Protocol | Threshold |
|---|---|---|
| **T1** (conformance) | Run the public `tests/` suite through the engine's **native evaluator first (oracle)**, then through the **SQL path**; record pass/fail/unsupported per case. | **100 % pass on implemented constructs**; unsupported constructs listed with reason codes — **zero silent skips**. |
| **T2** (compile rate) | Convert all 4063 active rules to SQL. | **≥ 95 % compile to SQL without fallback**; each failure classified (`modifier` \| `condition form` \| `correlation` \| `other`). |
| **T3-a** (cross-check correctness) | Run path C and fallback path B over N1 (10 M events) with the full pack; detection sets must be equal (rule id × event id). Any divergence = defect, not variance. | **Zero unexplained divergences.** |
| **T3-b** (performance) | 3 timed runs per path (cold cache + warm); report p50 wall-clock, peak RSS, SQL-time vs fallback-time split. | **C-primary ≥ 3× faster than B-only at N1** and meets §4.4 wall-clock targets. |

Supporting steps: corpora = synthetic canonical events seeded from documented Windows schemas (Security 4624/4625/4688/4720/1102; Sysmon 1/3/11/22) at N1 = 10 M and N2 = 50 M rows + real EVTX if supplied (record provenance + licence), plus an MVP-1 parse→detect round-trip; licence gate decides **C1 vs C2** by counsel acceptance of LGPL-3.0 (**C2 standing preference**); output = `ENGINE_POC.md` with every number labelled MEASURED, T1–T3 verdicts, fallback rate, final C1/C2 + C/B selection. **If T2 or T3(b) fail ⇒ §5.5 row 1: Option B becomes primary** (SQL only as coarse pre-filter; engine contract unchanged). Other §5.5 triggers: single rule fails to compile → route to native fallback for the rest of the job, record `detection_path: native` + reason code, job `COMPLETED_WITH_WARNINGS` if fallback share > 0; pySigma pin stays `<2.0` for converter, **never block runtime on pySigma**; SQLite→Postgres dialect gaps implemented by us, proven via conformance suite, **not by copying**.

---

## 6. consistency_report.md (Stage-7)

### 6.0 Framing
Cross-checks every named contract/decision/invariant/number across Stages 1–6 + delivered files (`schema.sql`, `openapi.yaml`, `canonical_event_v1.schema.json`, `rule_schema.json`, `verification-log.yaml`, `VERIFICATION_LOG_2026-10-09.yaml`). **"It does not resolve conflicts silently; every conflict is listed with its competing versions and left for human input."** All 6 stage files present, none omitted. No `*_decisions.yaml` files exist (search `decision_yaml_files=[]`); inventory = `_stage7_work/decision_inventory.json`.
**Count discrepancy (as-written):** report intro says `decisions=115, open_questions=75, not_verified=89, id-collisions=0`; §2 and §5 say **114 D / 74 Q / 88 NV / 0 collisions** (corrected after D8-08 header-row fix; Q rose 73→74 when Q5-009 registered under D8-13). §5 RETRACTED the old "no numeric contradiction" claim (D8-16). Use 114/74/88.

### 6.1 §1 contract cross-check — conflict register C-1..C-16

**All conflicts in the report are RESOLVED; none open.** §2: "These were recorded as open conflicts at Stage-7 time. **All are now RESOLVED (Stage-8 round 1, conflict-decision pass)** … resolutions were added as documented new decisions; no historical decision text was rewritten."
Note: the consistency_report prints C-numbers **C-1…C-12 (+C-3b, C-4b)** in §1; C-6/C-13/C-14/C-15 appear in §1.12/§3 by their fix ids without the C-label, and **C-16 does not appear in consistency_report at all** — C-id numbering cross-checked against `SENTINEL_IMPLEMENTATION_SPEC.md` §13 register (marked ⟨spec⟩ below).

| C-id | Conflict | Status + fix (what changed) |
|---|---|---|
| C-1 | Canonical event envelope: Stage-1 §6.1 sketch vs `canonical-event/v1` | **RESOLVED (C-1-fix)** — V2 normative; Stage-1 §6.1 SUPERSEDED banner added; file precedence made explicit |
| C-2 | Finding/alert object: `alerts` / `sentinel-finding/v1` / OpenAPI `Finding` / DDL `findings` | **RESOLVED (C-2-fix)** — layered contract: DDL `findings` storage-normative; `sentinel-finding/v1` engine-internal (persisted verbatim in `evidence_snapshot`; `payload_excerpt`/`attck_refs`/`falsepositives_note`/`attestation` live there); OpenAPI `Finding` API projection now with `author`, `level_original`; `alerts` name superseded (Stage-1 §6.4 banner) |
| C-3 | Data classification: 3 spellings (Stage-1 §6.1 "LEVEL 1 of 3" / §6.4 string enum / OpenAPI integer 1\|2\|3 with `sensitive`) | **RESOLVED (C-3-fix)** — single string vocabulary `public\|internal\|restricted` (DDL CHECK + canonical enum + OpenAPI header now string enum) |
| C-3b | `level_original` dropped on `findings` | **RESOLVED (C-3b-fix)** — `level_original` restored on `findings` (nullable) and OpenAPI `Finding` |
| C-4 | Upload path: Stage-3 `POST /v1/artifacts` vs OpenAPI `/v1/workspaces/{workspaceId}/uploads` | **RESOLVED (C-4-fix)** — OpenAPI workspace-scoped paths normative; Stage-3 §1.1 updated; Stage-3 HTTP 201 sketch superseded by OpenAPI 202 `Upload` |
| C-4b | `createUpload.run_id` optional in request vs `uploads.run_id NOT NULL` vs required on response | **RESOLVED (C-4b-fix)** — server-generated; client MAY supply as hint; absent → server generates; response always returns effective `run_id` |
| C-5 | `rule_run` accounting: Stage-5 §4.3 (`job_id`, `max_window_ms`, `sql_ms`, `native_ms`) vs DDL vs OpenAPI | **RESOLVED (C-5-fix)** — Stage-5 `job_id` ≡ DDL `run_id` (mapped, no duplicate column); `max_window_ms`/`sql_ms`/`native_ms` added to DDL + OpenAPI `RuleRun` (timing split preserved for §10.6 shadow reports) |
| C-6 | `findings.author` missing vs DRL-1.1 "persist rule author on every alert row" | **RESOLVED (D8-03-fix)** — `author text NOT NULL` added to `findings` + OpenAPI `Finding`; INV-6 now PASS ⟨C-id from spec §13⟩ |
| C-7 | `config_hash`: DDL `bytea NOT NULL` vs OpenAPI hex `^[0-9a-f]{64}$` | **RESOLVED (C-7-fix)** — bytea at rest; lowercase hex at API edge via `encode(config_hash,'hex')`/`decode(<hex>,'hex')` |
| C-8 | Canonical `source.format` enum missing `xml` in OpenAPI | **RESOLVED (C-8-fix)** — `xml` added (canonical normative); adjacent defect: `source.required` `record_type` → aligned to `[file_id, format, parser, parser_version]` |
| C-9 | `host` shape: canonical structured vs OpenAPI free-form | **RESOLVED (C-9-fix)** — OpenAPI `CanonicalEvent.host` tightened to structured canonical shape; JSON Schema authoritative for event validation; Stage-5 finding `host{agent_id,instance_id,name}` documented as separate agent-identity concept |
| C-10 | `rules` DDL vs OpenAPI `Rule`; `RuleDocument` not machine-linked | **RESOLVED (C-10-fix)** — provenance columns (`schema_tag`, `source_ref`, `source_spec`, `description`, `provenance`, `deleted_at`) added to OpenAPI `Rule`; `RuleDocument` now `allOf: [$ref "rule_schema.json"]` (closes S7-V8/D8-17) |
| C-11 | `ioc_pack.status DEFAULT 'active'` vs verify-then-activate (D4-003) | **RESOLVED (C-11-fix)** — default `active` → `pending_verify`; packs flip to `active` only after Ed25519 verification (closes D8-18) |
| C-12 | Evidence naming collision (triage `evidence` fact strings vs EvidenceBundle/evidence_snapshot) + presigned TTL 15 min PROPOSED | **RESOLVED (C-12-fix)** — no renames (would ripple 121 examples); disambiguated in Stage-6 §1.5; TTL 15 min confirmed as working default, retains PROPOSED-TO-BENCHMARK marker |
| C-13 | `events.classification` cited by Stage-1 §6.4/§8 invariant + Stage-5 §1.10 invariant 5, column absent from `schema.sql` and canonical-event/v1 | **RESOLVED (D8-02-fix)** — `classification` column added to `events` (NOT NULL, CHECK) + optional enum field on canonical-event/v1; INV-5 now PASS ⟨C-id from spec §13; content in report §3⟩ |
| C-14 | Dangling `D-022` (Stage-5 §4 streaming reconciliation, called "binding") | **RESOLVED (D8-13-fix)** — citation corrected to "normative, see §4 modes table"; no D-022 exists or is needed ⟨spec §13⟩ |
| C-15 | Dangling `Q5-009` (Stage-5 §1 deployment gating) | **RESOLVED (D8-13-fix)** — Q5-009 registered in Stage-5 OPEN_QUESTIONS (rule `scope` deployment-gating vocabulary) ⟨spec §13⟩ |
| C-16 | Stage-1 delivered as sibling file, not inlined in the spec | **not specified in consistency_report.md** ⟨spec §13: RESOLVED (C-16-fix) — index/reference approach accepted; Stage-1 remains a delivered sibling⟩ |

**Related single-source note (§1.12):** `sentinel-rule/v1` valid + machine-checkable (25 Stage-5 examples + 5 Stage-3 AF rules validate OK); jobs/`detection_runs` lifecycle, idempotency/audit_log, triage state machine (`queued,running,done,failed,rejected_by_policy`) all consistent; Stage-6 licence table repeats Stage-1 classifications with additions, **no override detected**.

### 6.2 §2 Decision conflicts (≤2 lines each)
Machine extraction: **114 decisions / 74 open questions / 88 not-verified / 0 id collisions** — "No two decisions with the same id disagree." The real conflicts are six cross-stage semantic tensions, each binding old decisions to later artifacts: (1) `alerts` table name ← Stage-1 D-004 (Option C) + §6.4, broken by Stage-6 DDL `findings`; (2) classification on events ← Stage-1 D-012 / §6.1–6.4 (as written in report; the classification decision is D-007 in Stage-1 §8.1), broken by Stage-2/Stage-6 omitting it; (3) author on every alert ← Stage-1 DRL-1.1 licence gate, `findings` lacked `author`; (4) upload path ← Stage-3 gate §1 vs OpenAPI `/uploads`; (5) `rule_run` metrics ← Stage-5 §4.3 vs DDL; (6) pack verify-then-activate ← Stage-4 D4-003 / Stage-5 vs DDL `DEFAULT 'active'`. **All six RESOLVED (Stage-8 round 1)** via documented new decisions (see §13 register in spec + `stage-8-fix-log.md`); historical decision blocks left verbatim.

### 6.3 §3 Dangling references (all RESOLVED; 0 further dangling)
`D-022` → RESOLVED (D8-13-fix, citation corrected); `Q5-009` → RESOLVED (D8-13-fix, registered); `events.classification` → RESOLVED (D8-02-fix, column + wire field added, INV-5 PASS); `alerts.*` → RESOLVED (C-2-fix, superseded by `findings`); Stage-3 `/v1/artifacts` → RESOLVED (C-4-fix, OpenAPI paths adopted). Stage-6 D6-001…016, Stage-4 D4-001…005, Q4-* all resolve; **0 further dangling ids**. Evidence-register id join (TL-*/ARC-*/DOC-*/…) **not executed id-by-id** (only spot-checked → S7-V1).

### 6.4 §4 Invariant audit (INV-1…INV-10)

| Id | Invariant (check) | Result |
|---|---|---|
| INV-1 | Engine with zero rules emits zero findings; no detection constants in engine code (Stage-5 SQL data-driven, native path no baked detections) | **PASS** |
| INV-2 | Detectors consume only canonical-event/v1 objects (Stage-3 §3.4/§12 emit; Stage-5 §3.4) | **PASS** |
| INV-3 | Triage never emits a verdict; `clean/safe/benign/malicious` banned by name (Stage-3 triage matrix = facts + finding-ids only) | **PASS** |
| INV-4 | No rendering, no macro execution, no document interpreters in-process, no egress, no code-loading (Stage-3 sandbox + Stage-4 tiers) | **PASS** |
| INV-5 | `events.classification` (`public/internal/restricted`) is a persisted column | **PASS** (D8-02-fix: DDL NOT NULL CHECK + canonical optional enum field) |
| INV-6 | Rule author persisted on every alert/finding row (DRL-1.1) | **PASS** (D8-03-fix: `findings.author text NOT NULL` + OpenAPI `Finding`) |
| INV-7 | Every tenant-scoped table has RLS ENABLEd (attributed "D-012 / Stage-6" in report) | **PASS** — "All 16 tenant-scoped tables have `ENABLE ROW LEVEL SECURITY` + policies (schema.sql:475–577)" (initial regex missed aligned spacing; corrected) |
| INV-8 | `findings.evidence_snapshot` immutable JSONB freeze that does NOT reference raw bytes | **PASS** |
| INV-9 | `severity` (LOW/MEDIUM/HIGH) and `level_original` (informational…critical) remain separate axes | **PASS with gap** — "Separate on `rules`; `level_original` dropped on `findings` (see §1.3) — separation holds where both exist" (§1.3 C-3b-fix says `level_original` was restored on `findings`; the INV-9 row note predates/contradicts that wording — both statements as written) |
| INV-10 | Canonical events never contain a bare JSON null except `time.utc` under state unknown/invalid | **PASS** (schema `$defs.time.allOf` guards null utc by state; `$defs.state_object` bans bare null) |

Verdict line: "**Invariant failures requiring human input: none** — INV-5 and INV-6 were the only failures and both now PASS (D8-02/D8-03 fixes). **All 10 invariants hold.**"

### 6.5 §5 Number audit (≤2 lines each)
- Stage-2 example corpus headings → **121 `### EX-*` blocks — MATCH**; **121/121 validate** vs canonical-event/v1 — MATCH.
- Stage-5 "25 documents, schema-valid" → 25, **25/25 OK** vs `rule_schema.json` — MATCH; Stage-3 AF rules 5, **5/5 OK** — MATCH.
- Stage-6 counts: `V-6-*` 39 rows, `D6-*` 16, `OQ-6-*` 9 — all MATCH; Stage-4 `D4-001…005` = 5 — MATCH.
- Stage-1 `D-001`…`D-012` = 12 unique ids (13 mentions) — MATCH; Stage-1 Q1–Q12 = 12 — MATCH.
- Consolidated totals: inventory **114 D / 74 Q / 88 NV — informational** (D8-08 counter fix; Q 73→74 with Q5-009); OpenAPI 23 paths — informational; DDL **21 logical tables** (32 `CREATE TABLE` incl. 11 monthly partitions) — MATCH.
- **RETRACTED (D8-16):** the earlier claim "No numeric contradiction found inside the stage corpus" was false. Counter counted markdown header rows → inflated 115/75/89. Also undisclosed at audit time: Stage-3 §0 said 61 entries / 59 VERIFIED vs actual **75 / 73** (D8-09, fixed); Stage-6 "32 relations" vs 21 logical tables (clarified — 32 CREATE TABLE is itself correct); gate budgets differed §1.2 vs Stage-6 §4 (D8-05 fixed → **64 MiB / 64 MiB / 8 KiB / 30 s, PROPOSED − TO BENCHMARK**); PostgreSQL doc citations mixed 17.4 and 18 (D8-12 fixed → all re-pinned to **18**). PROPOSED numbers (presigned TTL 15 min, parser budgets, sandbox timeouts) carry PROPOSED markers into the spec.

### 6.6 §6 What is NOT in conflict
Triage state machine values match; job/detection_run status enums match; `rule_schema.json` accepts all 30 rule docs (25+5); canonical schema accepts all 121 examples; RLS enabled on every tenant-scoped table with complete policy set; Stage-1 and Stage-6 licence tables agree (Stage-6 adds, does not override); no decision-id collisions; idempotency/audit_log/retention DDL↔OpenAPI consistent.

### 6.7 §7 DECISIONS (process decisions only; no new product decisions)
- **S7-001** (accepted): Assemble SENTINEL_IMPLEMENTATION_SPEC.md by full verbatim splice of stage bodies (no summarised sections); verification logs and decision blocks hoisted into §2/§3/§14 with pointers left in place. Rejected: prose-only merge (violates lossless requirement).
- **S7-002** (accepted): **Do not silently resolve any contract conflict**; every conflict in §1 ships unresolved into the spec's "Open decisions requiring human input". Evidence: brief "no silent conflict resolution".
- **S7-003** (accepted): Treat `canonical_event_v1.schema.json` + `rule_schema.json` as the machine-normative contracts; stage prose that disagrees is listed as conflict, not rewritten. Evidence: 121/121, 25/25, 5/5 validations.
- **S7-004** (accepted): Publish decision/question/not-verified inventory as `_stage7_work/decision_inventory.json` alongside the spec because no `*_decisions.yaml` files exist (search `decision_yaml_files=[]`).

### 6.8 §8 OPEN_QUESTIONS (S7-Q1…S7-Q16 — note: §1 fixes post-date these; each Q maps to a `*-fix` above)
Q1 §6.1 SUPERSEDED-banner vs both-living (→ C-1-fix) · Q2 which finding contract normative + where `payload_excerpt`/`attck_refs`/`falsepositives_note`/`attestation` land (→ C-2-fix) · Q3 rename `findings`↔`alerts`/alias (→ C-2-fix) · Q4 restore `events.classification` or drop invariant (→ D8-02-fix) · Q5 restore `findings.author`/`level_original` or licence exception (→ D8-03/C-3b-fix) · Q6 adopt workspace `/uploads` or keep `/v1/artifacts` alias (→ C-4-fix) · Q7 `run_id` required-from-client vs server-generated (→ C-4b-fix) · Q8 reconcile `rule_run` metrics (→ C-5-fix) · Q9 `config_hash` edge encoding (→ C-7-fix) · Q10 add `xml` to OpenAPI format or ban it (→ C-8-fix) · Q11 tighten `CanonicalEvent.host` or keep free-form (→ C-9-fix) · Q12 `ioc_pack.status` default → `pending_verify` (→ C-11-fix) · Q13 dangling `D-022` (→ D8-13-fix) · Q14 dangling `Q5-009` (→ D8-13-fix) · Q15 confirm presigned TTL 15 min + rename triage `evidence` (→ C-12-fix) · Q16 `Rule` `$ref` `rule_schema.json` + expose provenance fields (→ C-10-fix).

### 6.9 §9 NOT_VERIFIED (S7-V1…S7-V10 — do not assume these were checked)
V1 evidence-register id join not executed id-by-id (spot-checked only) · V2 **no Postgres instance; DDL not executed** — RLS/CHECKs/PARTITIONs text-audited only · V3 `openapi.yaml` not linted with spectral/generator (structural parse only) · V4 Windows Sandbox/.wsb/AppContainer/Job Object behaviour not executed · V5 Stage-3 parser fixtures (FX-*) not re-run · V6 engine performance budgets PROPOSED; no load test run · V7 Ed25519 ioc_pack verification (D4-003) not implemented/tested in Stage 7 · V8 API-layer `RuleDocument` not machine-validated against `rule_schema.json` (only file examples were; gap closed for API by C-10-fix per §1.9) · V9 Stage-2 decision YAML is informal (tolerant extractor, not strict YAML suite) · V10 cross-stage licence-obligation completeness (every DRL/CC/MIT clause → concrete code enforcement point) **not traced end-to-end**.

---

## 7. What an implementer must NOT do (both files)

1. **No silent conflict resolution.** Report intro: conflicts are listed with competing versions "and left for human input"; **S7-002**: every §1 conflict ships unresolved into "Open decisions requiring human input"; **S7-003**: disagreeing stage prose is listed as conflict, **not rewritten**; §2: "no historical decision text was rewritten — resolutions were added as documented new decisions."
2. **Unresolved surfaces stay behind a flag/stub:** `SENTINEL_IMPLEMENTATION_SPEC.md` (not one of the two source files) line 65: "Do not implement any conflict in §13 until a human resolves it; leave the conflicting surface behind a feature flag or stub." Related: Stage-5 `SUPPORTED_LATER` = "shipped after MVP or behind a flag; **never silently enabled**". Neither rule appears verbatim in the two source files — cross-referenced for completeness.
3. **Do not implement Stage-1 §6.1** — SUPERSEDED (C-1-fix); use `canonical_event_v1.schema.json`; obey the file precedence chain.
4. **No silent skips / silent exclusions:** D-008 "silent skips forbidden"; §5.6.3 zero silent skips (loaded/skipped-with-reason counts); §6.3 import outcome always `OK | OK_PARTIAL(fallback) | REJECTED(reason_code)` with counts; Chainsaw-style silent `timeframe` ignoring is the named anti-pattern.
5. **Never collapse the three axes** (D-007 / §6.4): `severity` (LOW|MEDIUM|HIGH), `level_original` (verbatim upstream), `classification` (`public|internal|restricted`) stay distinct in storage, API, exports.
6. **Never `SUCCESS` on partial work** (D-012): any partial parse/convert/execute ⇒ `COMPLETED_WITH_WARNINGS`; never silent drop; parse errors keep original bytes reachable via `raw_ref`.
7. **Empty pack ⇒ exactly 0 detections** (D-012, MVP-2 invariant, tested in CI); zero hardcoded detections; no detection logic in parsers, no parsing logic in detectors (§5.6.5); detectors consume only canonical events (Option D rejected as product path for bypassing this).
8. **Licence hard-stops:** never copy rule/config/source from Wazuh, Chainsaw, Hayabusa code, Velociraptor, MISP, elastic/detection-rules, ET Open GPLv2/ETPRO ranges, SwiftOnSecurity (§2.3.1); **shipped runtime must not embed LGPL/GPL/AGPL code** (D-005; C1/`pysigma-backend-sqlite` PoC-only); HIGH-flag components need counsel sign-off before entering `pyproject.toml` or a default rule pack (§2.3.4); never patch pySigma in place without releasing the modified library source (§2.3.3); Wazuh GPLv2 rule text never stored — adapter is customer-rules-only (§6.3); do not bundle GPL/AGPL engines (§4.2); Velociraptor artifacts "Never as code" (§4.3).
9. **No unsourced performance numbers** (D-010): throughput/memory ships only as MEASURED output of the MVP-8 harness (§5.7 step 6); everything else keeps `PROPOSED - TO BENCHMARK`.
10. **Do not block runtime on pySigma** (§5.5 row 3): converter pinned `<2.0`; runtime consumes compiled SQL / our own IR. Never copy SQLite dialect code — implement Postgres functions ourselves, prove via conformance suite (§5.5 row 4).
11. **Do not start Stage-2 before `ENGINE_POC.md`** resolves D-004's T1/T2/T3 gate (Stage-1 closing line).

---

## 8. Explicit "not specified" entries
- Postgres/FastAPI/pytest/uvicorn/psycopg licence rows in Stage-1 §2: **not specified** (Stage-1 §8.3: PostgreSQL licence "not inspected this stage").
- RLS in Stage-1: **not specified** (Stage-1 only mandates `tenant_id` on every row; RLS is INV-7/Stage-6).
- C-16 status inside `consistency_report.md`: **not specified**.
- The "feature flag or stub" rule: **not in the two source files** (it is in `SENTINEL_IMPLEMENTATION_SPEC.md` line 65; quoted above with attribution).
- Consistency-report inventory totals: intro says 115/75/89, §2/§5 say 114/74/88 (D8-08 fix) — both figures as-written; use 114/74/88.
