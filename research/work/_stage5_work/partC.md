---

## 6. IOC Design (signed packs, two-stage membership, no values in rules)

### 6.1 Pack format (`ioc_pack/v1`)

Packs are **data**, signed with the Stage-4 D4-003 Ed25519 process (same pipeline as rule packs; Stage-1 §5.3.2 external-source flow). Values never enter rule documents (D5-007) — packs are swappable intelligence, rules are stable detection logic.

```yaml
schema: ioc_pack/v1
pack: {id: acme-intel, version: "2026.10.0", generated_utc: "2026-10-09T12:00:00Z",
       source: ACME-MISP, license: DRL-1.1-or-proprietary, contact: intel@acme.example,
       attestation: {sig: base64(ed25519), key_id: acme-intel-2026}}
entries:
  - {kind: sha256, value: 3f2a…, first_seen: 2026-09-01, tlp: amber, refs: ["https://…"], tags: [apt, loader]}
  - {kind: ipv4,   value: 203.0.113.7, cidr: false, …}
  - {kind: cidr,   value: 198.51.100.0/24, …}
  - {kind: domain, value: bad.example, match_subdomains: true, …}
  - {kind: url,    value: "https://bad.example/payload.exe", …}
counts: {sha256: 1, ipv4: 1, cidr: 1, domain: 1, url: 1}
digests: {entries_sha256: …, manifest_sha256: …}
```

Load path: signature verify (D4-003) → digest check → normalize (lowercase domains, strip trailing dot, canonical IPv6, reject invalid) → ingest into `ioc_entry(pack_id, kind, value, meta…)` with a unique index on `(kind, value)`.

### 6.2 Two-stage membership (D5-007)

| Stage | Structure | Purpose |
|---|---|---|
| **Stage A — Bloom prefilter** | in-house Bloom filter (`hashlib` blake2b/keccak, stdlib only; `PROPOSED - TO BENCHMARK`: k=6, m sized for pack size × 10 bits/entry, FPP ≈ 1%) built at pack load, per (pack, kind) | O(1) fast-reject of ~all negatives; no third-party dependency (Stage-1 §2.1); rebuild is incremental-friendly |
| **Stage B — exact confirm** | hash-set / `ILIKE`-guarded domain-suffix match / `inet <<` for CIDR | the only stage allowed to produce a finding; eliminates Bloom false positives entirely |

Domain matching is suffix-exact (`bad.example` and `*.bad.example` per `match_subdomains`), never a substring scan. URL matching is exact + optional prefix. IPv4/IPv6/CIDR use the same guards as the `cidr` modifier (§3.4). Hash indicators compare against `hashes.sha256` (and configured aliases `md5/sha1` where the pipeline materializes them); a pack entry of the wrong length/charset is rejected at load, not at match time.

### 6.3 Rule side (`kind: ioc`)

```yaml
kind: ioc
ioc:
  packs:
    - pack: acme-intel
      version: "2026.10.0"
      digest_sha256: "6b8e1f0c2d3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4"
  match:
    fields: [process.hashes.sha256, file.hashes.sha256]
    kinds: [sha256]
    normalize: [hash_lower, trim]
  confirm_exact: true
  on_stale: last_known_good
  emit_fields: [process.hashes.sha256, process.exe]
```

`match` maps indicator kind → canonical field paths (pipeline-resolved, same rule as §1.2). The compiled prefilter is "field present"; the Bloom pass is free per event; a positive Bloom triggers Stage-B confirm → finding.

### 6.4 Freshness, failure, governance

* Staleness gate (§4.8): packs older than `PROPOSED` 7 days mark `IOC_PACK_STALE`; LOW-severity IOC findings are suppressed, MEDIUM+ still fire; the pack is **never** silently dropped.
* Missing pack → rules referencing it are `OK_PARTIAL(IOC_PACK_MISSING)`; job continues.
* Pack update with broken signature → last-known-good pack retained (Stage-4 T-06 posture), alert raised, `IOC_PACK_STALE` escalates to alarm (Stage-6 dashboard).
* Pack provenance (source, license, TLP, refs) is persisted per entry and copied onto findings (§10.3 obligations for third-party feeds).
* Pack content is untrusted input: size caps (`PROPOSED`: 5 M entries / 256 MiB), no regex fields, no executable content (D5-018 applies to packs too).

---

## 7. FIM Design (event-driven only; live-host baselines out of scope)

### 7.1 Scope boundary (Stage-1 §4.2 binding)

Live-host file-integrity agents (OSSEC-style baselining of a running host) are **out of scope** for Sentinel MVP. FIM here means: (a) predicates over `fim`/`file` canonical events (Stage-2 §6 mapping: Security 4663/4656/4660/4698/4719, Sysmon 11/23, plus `audit_log_cleared` for Security 1102 — VERIFIED stage-2 lines 1095–1110, 3009), and (b) diffs against an **uploaded** baseline file (hash+size+attrs per path), never against a live host.

### 7.2 Rule shape (`kind: fim`)

```yaml
kind: fim
fim:
  paths:
    include: ["C:\\Windows\\System32\\**", "*.exe", "*.dll"]
    exclude: ["C:\\Windows\\System32\\*.log"]
  operations: [create, modify, attribute_change]     # or [audit_log_cleared]
  require: {hash_changed: true}                     # optional
  baseline: {source: event_old_new}                 # or upload_pair / fim_baseline_table
  match_event_fields: {fim.operation: audit_log_cleared}   # optional sigma-style predicate
```

Case-insensitivity and `\`/`/` equivalence are compiler behaviour on Windows (not rule keys — the schema has no `case_sensitive` flag; §7.2). Globs semantics: `**` crosses directories; `*`/`?` within a segment; the compiler emits an Aho–Corasick automaton of literal prefixes + a bounded matcher for `**` (no user regex anywhere — §4.7 applies unchanged). `require.hash_changed` is only satisfiable when the event carries old/new hash pairs (Stage-2 `fim.old/new` VERIFIED); otherwise the rule is `OK_PARTIAL(UNSUPPORTED_COMBINATION)`. For the audit-log-cleared rule of §1.5, `operations: [audit_log_cleared]` alone is sufficient (the `match_event_fields` predicate is redundant there and is shown to demonstrate the shape).

### 7.3 Baseline modes

| Mode | Source | Use |
|---|---|---|
| `event_old_new` | the `fim` event's own `old{size,modified,attributes,hashes}` vs `new{…}` (VERIFIED in `canonical_event_v1.schema.json` `$defs.fim`) | change detection without any stored state; **default**; cold-start-free |
| `upload_pair` | baseline CSV/JSON uploaded by the analyst (`fim_baseline` rows: path, size, mtime, sha256) + an inventory file from the same host at a later time | inventory-diff workflow (Stage-3 §9-style external input) |
| `fim_baseline_table` | prior inventory rows already stored for the host | cross-run drift |

### 7.4 Failure modes

| Condition | Code | Effect |
|---|---|---|
| baseline requested, none present | `SNAPSHOT_MISSING` | rule inert for job, accounted (§4.8) |
| event lacks old/new but rule requires hash comparison | `UNSUPPORTED_COMBINATION` | `OK_PARTIAL` |
| path outside any host's observed roots | — | not an error; zero matches |
| `audit_log_cleared` rule with no 1102-equivalent events in range | zero matches | normal (the event only exists when an admin clears it) |

Severity assignment follows Stage-1 §6.4 defaults with `audit_log_cleared` defaulting to HIGH (`PROPOSED`, overridable per rule).

---

## 8. SCA Design (own checks, no SCAP/OVAL/XCCDF, no copied benchmark text)

### 8.1 Scope boundary (Stage-1 §4.2 binding) and licence posture

No SCAP/OVAL/XCCDF engine; no CIS PDF text. CIS Benchmarks are free for non-commercial use (CC BY-NC-SA 4.0 for non-members) but **commercial redistribution/tailoring requires SecureSuite membership** (terms VERIFIED 2026-10-10). Sentinel's posture (D5-009): **write our own check definitions**, cite framework **control IDs** (`CIS Windows 11 §18.9.1`) as factual references, never copy benchmark wording, and mark every check `license: sentinel-own`. Where a check mirrors a public control, the `framework` field records the ID and the rule records `source_note: paraphrased` — a licence gate, not a cosmetic note (Stage-1 §2.2 rules 2–4: DRL attribution, MITRE copyright line, per-source licence class — all still apply to SCA packs).

### 8.2 Event source and rule shape

Checks emit `config_check` canonical events (VERIFIED `$defs.config_check`: `check`, `category`, `expected`, `observed`, `status ∈ {pass,fail,unknown}`, `source`). Rules are **selection + optional assertion**, never the check logic itself (checks live in Stage-3 plugins/ExternalProcessRunner, D3-024):

```yaml
kind: sca
sca:
  select:
    checks: ["sc.win.local_policy.*", "sc.win.autorun.*"]    # trailing-* wildcards
  fail_status_only: true                                      # default: fire only on status: fail
  assert:                                                     # optional; over the emitted event
    field: config_check.observed
    op: neq
    value: "2"                                                # re2-safe ops only
  benchmark:
    framework: cis
    control_id: "18.9.1"
    note: "Control ID cited factually; the check wording is Sentinel's own (CIS PDFs are CC BY-NC-SA 4.0 for non-commercial use; commercial tailoring needs SecureSuite)."
  evidence: [config_check.observed, config_check.expected, config_check.source]
```

`unknown` is never treated as `pass` (mirrors Stage-3 D3-029 and Stage-2 unknown-handling): `fail_status_only: false` fires on any status including `unknown`; a rule that fires on `unknown` must set top-level `severity: LOW` and the finding payload carries `status: unknown` (lint-enforced). Absent evidence (no `config_check` event at all) is neither pass nor fail — it is absence, and §8.3 surfaces it as a warning, never as a green result.

### 8.3 Aggregation and reporting

SCA findings are per-check-per-host with a `sca_rollup` view (pass/fail/unknown counts per benchmark family per host per run) for the Stage-6 dashboard. Rollup thresholds are Stage-6 material; this stage only guarantees the data shape and the accounting (a job with zero `config_check` events but enabled SCA rules surfaces `NO_EVENTS_FROM_PLUGIN` as a warning — never silence).

---

## 9. Statistical Design (declarative baselines, no ML, warm-up explicit)

### 9.1 Rule shape (`kind: statistical`)

```yaml
kind: statistical
statistical:
  kind: rate                       # rate | rare_value | proportion
  group_by: [host.agent_id]        # mandatory
  measure: {op: sum, field: network.bytes_sent}
  window: {bucket: 5m, span: 7d}   # bucket = date_bin width; span = trailing baseline window
  baseline: {min_observations: 84, warmup_action: flag, estimator: median_mad, k: 6, alpha: 0.3}
  threshold: {op: gt, value: 50000000, for_buckets: 3}   # comparator + optional consecutive buckets
  scope_filter: {event.category: [network]}              # optional sigma-style predicate
```

### 9.2 Estimators (all stdlib/SQL, no ML — Stage-1 §4.3)

| Estimator | Definition | SQL | Native |
|---|---|---|---|
| `median_mad` | median + k×MAD over baseline buckets | `percentile_cont(0.5)` over the bucket view + `percentile_cont(0.5)` of abs deviations | sorted sample, same caps as §5.2 |
| `ewma` | `s_t = α·x_t + (1−α)·s_{t−1}` | computed at finalize over the bucket series | running scalar |
| `none` | raw threshold only (`threshold` required, baseline ignored) | — | — |

`rare_value` uses `count(DISTINCT value)` + per-value historical frequency from `rule_baseline` (`PROPOSED`: flag buckets whose value is absent from the last 30 observed days of that value's set). `proportion` is `count(match)/count(*)` per group-bucket vs threshold.

### 9.3 Baselines, warm-up, cold start

* Buckets persist in `rule_baseline(rule_id, group_key, span_start, span_end, metric, n, extras)`; the baseline is written at `finalize()` of each job (idempotent upsert keyed by the bucket id).
* `min_observations` gates validity; until then `warmup_action`:
  * `suppress` (default): no findings until the baseline is valid, but the rule is accounted with `BASELINE_WARMUP` and the job is `COMPLETED_WITH_WARNINGS` (never silent);
  * `flag`: findings emitted at LOW carrying `baseline.warmup=true` and `BASELINE_WARMUP` — visible, not alarming.
* `k` default 6 (`PROPOSED - TO BENCHMARK`); `alpha` default 0.3 (`PROPOSED`); both config-overridable per rule.
* Baseline resets: rule digest change (D4-003) invalidates baselines; manual reset is an explicit admin action recorded in the audit log (Stage-3 D3-034 pattern).
* No ML, no autotuning, no anomaly models beyond median/MAD and EWMA — Stage-1 §4.3 out-of-scope is honoured by construction (the schema has no model fields).

---

## 10. Governance, Supply Chain, and Safety

### 10.1 No hardcoded detections (reject condition R1; D5-014)

* Engine code contains **zero** detection constants: no rule fragments, no indicator values, no "if hostname == 'DC01'" logic. The only literals allowed in code are budgets/limits (§4.6), the reason-code enum, and schema/fixture paths.
* CI invariant test: boot the engine with an empty rule store against the golden corpus → **exactly 0 findings**, and assert the codebase contains no `sigma`/`ioc`/`fim`/`sca`/`statistical`/`artifact` rule documents outside `fixtures/` and `packs/` (a grep-based tripwire + a pack-free integration test).
* All detections ship as data through the same signed-pack path (§10.2); `kind: artifact` AF rules from Stage-3 §12 are imported as ordinary rules, not special-cased in code.

### 10.2 Rule packs and signing (extends Stage-4 D4-003)

Pack manifest (`sentinel-pack/v1`): `{pack_id, version, created_utc, rules_digest, entries: [{rule_id, sha256}], attestation: {sig, key_id, sig_alg: ed25519}}`. Load order: signature → digests → schema → lint → compile. Any failure keeps the **last-known-good** pack (Stage-4 T-06 posture) and raises a finding-severity alarm. Key rotation, revocation list, and offline verification are Stage-6/ops material but the key-id indirection is reserved now (schema field, §2 L4).

### 10.3 Third-party content obligations (carried from Stage-1 §2.3)

| Source | SPDX/licence | Class | This stage's handling |
|---|---|---|---|
| SigmaHQ rules (DRL 1.1 — VERIFIED 2026-10-10 `LICENSE` at `8a4813404e`) | Detection-Rules-License-1.1 | EXTERNAL_PROCESS / REFERENCE | retain author + URI + licence reference per DRL §1–§3; `author` is copied onto **every alert** the rule produces (DRL §3 requirement, §1.10 invariant 6); commercial redistribution of rules is the Stage-1 §2.3 legal gate — pack publisher defaults to `private` |
| sigma-specification (public domain — VERIFIED LICENSE) | Unlicense-equivalent | REFERENCE | no constraint |
| MITRE ATT&CK (© 2016–2026 The MITRE Corporation; VERIFIED `attack-stix-data/LICENSE.txt` 2026-10-10: royalty-free incl. commercial, must reproduce the copyright designation) | Apache-style custom | REFERENCE | every exported artefact that includes ATT&CK ids carries the line `"© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."`; MITRE-derived data is facts (ids/names), not text dumps |
| CIS Benchmarks (PDF free for non-commercial use; commercial tailoring needs SecureSuite — VERIFIED 2026-08 CIS terms page) | CC BY-NC-SA 4.0 (non-commercial PDFs) | AVOID for text; REFERENCE for control IDs | SCA rules cite control IDs only (§8.1); CI tripwire rejects any rule string longer than 64 chars that matches known CIS phrasing patterns (heuristic, `PROPOSED`) |
| `google-re2` (BSD-3-Clause classifier, VERIFIED PyPI 2026-10-10) | BSD-3-Clause | DEPENDENCY | NOTICE entry |
| `pyahocorasick` (BSD-3-Clause + Public-Domain, VERIFIED PyPI) | BSD-3-Clause | DEPENDENCY | NOTICE entry |
| `pySigma` (LGPL-2.1-only, VERIFIED `pyproject.toml` @ `50708bae`) | LGPL-2.1-only | DEPENDENCY (conformance tooling only) | kept out of the runtime hot path (Stage-1 pin rationale); NOTICE + LGPL notice-availability obligation if linked |
| PostgreSQL 18 | PostgreSQL License | DEPENDENCY | NOTICE entry |

### 10.4 Content as untrusted input (D5-018; extends Stage-4 T-12)

Rules, packs, filters, baselines and IOC feeds are all **attacker-influenced-by-design** surfaces (they will be edited by humans and bots for years). Handling: safe YAML loader only (no custom tags, no object construction); document size cap (`PROPOSED`: 512 KiB) + anchor-expansion cap; no template/placeholder expansion (spec's `expand` rejected, §3.3); no rule-triggered I/O (lists resolved at load, content-addressed, size-capped `PROPOSED`: 10 MiB per list — D5-019); condition expression depth/size caps (`PROPOSED`: depth 32, identifiers 64, OR-arms 256) with lint rejection; compiled SQL parameterized (never string-concatenated) so rule values cannot become SQL text; native plan values are data, never code.

### 10.5 Shadow mode, kill switch, audit

* **Shadow mode** (extends Stage-2 `shadow_mode` job flag and Stage-3 §11): a rule or pack can be flagged `governance.mode: shadow`; it compiles, runs, produces findings tagged `shadow: true` that are stored + visible in dashboards but **never page anyone** and never open incidents. Promotion to `active` is an explicit action requiring a second approver (config, Stage-6 RBAC) and is recorded in the audit log with actor + pack digest.
* **Kill switch** (Stage-3 D3-033 precedent): `rules.enabled=false` globally or per rule/pack; the disable path must be as fast as the enable path (config flip, no recompile) and audited.
* **Audit log** (Stage-3 D3-034): every pack load, signature failure, quarantine, shadow promotion, baseline reset, and kill-switch flip is appended with actor, timestamp (UTC), pack digest, and reason — retained per Stage-3 retention policy.
* **Canary rule**: one synthetic rule (`kind: sigma`, matches nothing real, `canary: true`, governance-owned) per pack verifies end-to-end plumbing on every job; a job with zero canary findings is flagged `PIPELINE_SILENT` (`PROPOSED`: warning, not failure, because legitimate zero-match jobs exist — the canary matches a synthetic injected event, so zero means the path is broken).

### 10.6 CI gates (the reject conditions, automated)

| Gate | Blocks merge if |
|---|---|
| Schema (`rule_schema.json`) | any rule/pack fails L0–L1 |
| Support matrix lint | any `SUPPORTED` row's fixtures fail; any `SUPPORTED_LATER` rule slips in without its flag |
| ReDoS lint (§4.7 L1) | any `re` value outside the restricted RE2 subset |
| Empty-pack invariant (R1) | golden corpus run with empty store emits ≠ 0 findings |
| Native/SQL conformance (§12.1) | fingerprint divergence on the golden corpus |
| Licence tripwire | missing DRL attribution path, missing ATT&ACK copyright line in exports, missing NOTICE entries |
| CIS text tripwire (§10.3) | known-benchmark phrasing detected in rule bodies |

<!-- CONTINUED-PART-D -->
