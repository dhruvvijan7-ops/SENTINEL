# SENTINELAI ARCHITECTURE AUDIT — COMPLETE REPORT

**Date:** September 2, 2026
**Scope:** Architecture document intake, repository audit, gap analysis, Phase 1 readiness assessment
**Document Audited:** SENTINELAI ANALYSIS ENGINE V2 PROMPT.docx (2,410 paragraphs, 48,916 characters, 181 sections)
**Repository Audited:** C:\Users\dhruv\SentinalAI

---

## 1. Document Successfully Located

The architecture document was found at:
```
C:\Users\dhruv\SentinalAI\DOCS\SENTINELAI ANALYSIS ENGINE V2 PROMPT.docx
```

## 2. Document Reading Confirmation

- **Total paragraphs:** 2,410
- **Total characters:** 48,916
- **Sections covered:** 181 (Sections 1–181)
- **Fully read:** Yes — all 2,409 lines from line 1 to line 2409

The document is a comprehensive architecture and engineering specification covering 10 implementation phases, 181 numbered sections, and the full target analytical pipeline from raw inputs through controlled response.

## 3. Executive Architecture Understanding

The document specifies a **multi-layered, modular cybersecurity detection platform** built on these core concepts:

**Target Pipeline:**
```
Raw Input → Input Adapter → Canonical Telemetry → Normalization → Entity Resolution → Feature Extraction → Detection Fabric (deterministic rules, signatures, IOC matching, threshold/rate, statistical anomaly, behavioral baselines, unsupervised ML, supervised ML, LIGHT-HIDS, temporal/correlation) → Evidence Aggregation → Enrichment (MITRE ATT&CK, asset/user/vulnerability context, TI) → Risk Engine → Severity → Deduplication → Suppression → Alert → Incident Correlation → Investigation → Analyst Recommendation → Future Controlled Response
```

**Key Architectural Principles:**
1. Modularity — each analytical capability independently replaceable
2. No detector-owned persistence — detectors return results, orchestration layer persists
3. Evidence-first — every detection must have structured evidence
4. Separation of concerns — adapters, detectors, persistence, risk, enrichment, correlation, UI all separate
5. Confidence ≠ Risk ≠ Anomaly Score ≠ Severity — these must never be collapsed into one number
6. Honest status reporting — no fake ML, no fabricated TI, no invented ATT&CK mappings

**Implementation is phased across 10 phases**, with Phase 1 (Detection Foundation) being the immediate implementation task.

## 4. Current Repository Understanding

### Backend Structure
```
backend/
  app/
    main.py              — FastAPI app, CORS, router registration
    api/
      deps.py            — JWT auth, RBAC (get_current_user, require_role)
      routes/
        auth.py          — register, login, logout, forgot/reset password
        analysis.py      — upload host traces, list/get analysis runs, monitoring
        detections.py    — list/get/update detections, detection alerts
        alerts.py        — list/update alerts
        network.py       — network events, summary, IP detail, ports, protocols, top talkers, timeline
        users.py         — admin CRUD users
        audit.py         — audit log viewing
        system.py        — system settings
    core/
      config.py          — Settings via env vars (database_url, JWT, etc.)
      database.py        — SQLAlchemy engine, session, Base
    models/
      user.py            — User model (id, email, hashed_password, name, role, is_active)
      analysis_run.py    — AnalysisRun model
      detection.py       — Detection model
      alert.py           — Alert model
      network_event.py   — NetworkEvent model
      audit_log.py       — AuditLog model
      system_settings.py — SystemSettings model
    schemas/
      analysis.py, detections.py, alerts.py, network.py, monitoring.py, users.py, audit.py, system.py
    services/
      detection_engine.py — The core detection engine (all rules)
      host_trace.py       — JSON/CSV parsing, syscall normalization
      auth.py             — JWT, password hashing
      audit.py            — AuditService
      audit_enums.py      — Audit actions/categories
      system_settings.py  — System settings service
  tests/                — pytest tests (conftest, test_detections, test_network, test_audit, test_rbac, test_monitoring)
  alembic/              — Alembic migrations
  sample-data/          — example-host-trace.json
```

### Frontend Structure
```
frontend/src/
  features/
    analysis/pages/     — Upload trace
    alerts/pages/       — Alert list
    monitoring/pages/   — MonitoringPage, InvestigationPage
    network/pages/      — NetworkPage
    dashboard/pages/    — Dashboard
    investigation/      — EMPTY directory
    ml/                 — EMPTY directory
    auth/, common/, settings/, users/, admin/, analytics/, reports/, landing/
  services/
    apiClient.ts, alertService.ts, analysisService.ts, detectionService.ts,
    networkService.ts, monitoringService.ts, auditService.ts, authService.ts,
    systemService.ts, userService.ts
  types/
    api.ts, auth.ts, detection.ts
  routes/paths.ts       — ROUTES constants
```

## 5. Current Detection Pipeline

**Implemented flow:**
```
Uploaded JSON/CSV File
    ↓
FastAPI upload_host_trace endpoint (analysis.py:337)
    ↓
summarize_host_trace() — parses JSON sequences or CSV rows (host_trace.py:300)
    ↓
TraceSummary — event_count, sequence_count, unique_system_calls, all_calls, network_events
    ↓
analyse_trace() — 6 hardcoded rules (detection_engine.py:25)
    ↓
Detection + Alert objects created directly in detection_engine.py (detector-owned persistence)
    ↓
NetworkEvents persisted (analysis.py:500-519)
    ↓
analyse_network_events() — 4 hardcoded rules (detection_engine.py:264)
    ↓
Detection + Alert objects persisted
    ↓
API returns AnalysisRun
```

**Missing stages (not implemented):**
- Canonical event abstraction
- Normalization layer
- Entity resolution
- Feature extraction
- Detection registry / orchestrator
- Structured evidence model
- Risk engine
- Deduplication / suppression
- Correlation
- Incidents
- Investigation workflow

## 6. Current Host Telemetry

| Capability | Status |
|---|---|
| Syscall ID mapping (236 Linux syscalls) | **IMPLEMENTED** |
| Syscall name resolution | **IMPLEMENTED** |
| Sequence extraction from JSON | **IMPLEMENTED** |
| Sequence extraction from CSV | **IMPLEMENTED** |
| Network event extraction from traces | **IMPLEMENTED** |
| Process creation/termination | **MISSING** |
| Process tree / parent-child | **MISSING** |
| Command lines | **MISSING** |
| File operations (only as syscall names, not as events) | **PARTIAL** |
| File hashes | **MISSING** |
| Services | **MISSING** |
| Scheduled tasks | **MISSING** |
| Registry activity | **MISSING** |
| Authentication/session events | **MISSING** |
| Privilege changes (detected via syscall names only) | **PARTIAL** |
| Memory telemetry | **MISSING** |
| Injection detection | **MISSING** |

## 7. Current Network Capability

| Capability | Status |
|---|---|
| Network events extracted from host traces | **IMPLEMENTED** |
| Source/destination IP, ports, protocol | **IMPLEMENTED** |
| Connection IDs | **IMPLEMENTED** |
| Network analytics (summary, top talkers, ports, protocols, timeline) | **IMPLEMENTED** |
| IP detail drill-down | **IMPLEMENTED** |
| Network event detail with related detections | **IMPLEMENTED** |
| PCAP parsing | **MISSING** |
| Live packet capture | **MISSING** |
| NetFlow / IPFIX | **MISSING** |
| Zeek logs | **MISSING** |
| Suricata EVE JSON | **MISSING** |
| Flow reconstruction | **MISSING** |
| Protocol parsing | **MISSING** |
| Streaming | **MISSING** |

Network capability is **limited to events extracted from uploaded host traces**. There is no independent network monitoring, no PCAP, no flow data ingestion.

## 8. Current ML / LIGHT-HIDS Status

| Component | Status |
|---|---|
| ML libraries (scikit-learn, torch, etc.) | **MISSING** — not in requirements.txt |
| Trained models | **MISSING** |
| Inference code | **MISSING** |
| Feature extraction (for ML) | **MISSING** |
| Anomaly detection (statistical or ML) | **MISSING** |
| Behavioral models | **MISSING** |
| Model registry | **MISSING** |
| Model versioning | **MISSING** |
| Model evaluation | **MISSING** |
| DeepSVDD | **MISSING** |
| LIGHT-HIDS | **MISSING** |
| Isolation Forest | **MISSING** |
| One-Class SVM | **MISSING** |
| LOF | **MISSING** |
| Autoencoders | **MISSING** |
| Frontend `features/ml/` | **EMPTY directory** |

There is **zero ML functionality**. No ML dependencies exist in `requirements.txt`. The `frontend/src/features/ml/` directory is empty. Any UI claiming ML status would be fabricated.

## 9. Current Database Architecture

**Tables (7 total):**

| Table | Model | Key Fields |
|---|---|---|
| `users` | user.py | id, email, hashed_password, name, role, is_active |
| `analysis_runs` | analysis_run.py | id, source_type, file_name, status, event_count, sequence_count, details(JSON), submitted_at, completed_at |
| `detections` | detection.py | id, analysis_run_id, detection_type, title, description, severity, status, confidence(int), source_ip, destination_ip, protocol, evidence(JSON), created_at |
| `alerts` | alert.py | id, detection_id, severity, status, title, description, source, created_at, updated_at |
| `network_events` | network_event.py | id, analysis_run_id, detection_id, alert_id, timestamp, src/dst IP, src/dst port, protocol, connection_id, syscall_name, sequence_index, event_index, description |
| `audit_logs` | audit_log.py | id, timestamp, actor_*, category, action, result, severity, resource_*, ip_address, user_agent, request_id, metadata_json |
| `system_settings` | system_settings.py | id, max_upload_mb, analysis_history_limit |

**Not implemented:**
- canonical_events
- entities
- detector_results
- evidence (separate table)
- risk_assessments
- incidents
- correlations
- baseline_profiles
- model_registry
- model_evaluations
- threat_intelligence
- tenant isolation (no tenant_id on any table)

## 10. Current Frontend Architecture

**Functional pages:**
- Dashboard — aggregate overview
- Monitoring — analysis run list with detection/alert counts
- Investigation — single detection detail viewer (NOT incident investigation)
- Analysis — host trace upload
- Alerts — alert list with status updates
- Network — network events, summary, top talkers, ports, protocols, timeline, IP detail
- Settings — system settings
- Admin — user management, audit logs
- Auth — login, register, forgot password

**Empty feature directories (placeholder only):**
- `features/investigation/` — empty
- `features/ml/` — empty

**Frontend consumes real backend API** through `services/` layer. No mocked data detected. The Investigation page (`InvestigationPage.tsx`) is a detection detail viewer — it loads a single detection by ID and shows its evidence, alerts, and analysis run context. It is NOT an incident investigation system.

## 11. Architecture vs Implementation Matrix

| # | Requirement | Architecture Says | Current Code Does | Status | Gap | Priority |
|---|---|---|---|---|---|---|
| 1 | Canonical Event Model | Abstraction over all telemetry types (process, network, file, auth, DNS, etc.) | No canonical model. Syscalls parsed directly into TraceSummary. Network events extracted as NetworkEventData dataclass. | **MISSING** | Complete gap | High |
| 2 | Input Adapter Architecture | Separate adapter per input type, adapters produce canonical events | `host_trace.py` parses JSON/CSV but is not structured as an adapter. No adapter interface. | **MISSING** | Needs refactoring into adapter pattern | High |
| 3 | Detector Interface | Protocol/ABC with detector_id, detector_version, supports(), detect() | No detector interface. Single `analyse_trace()` function with if/else rules. | **MISSING** | Complete gap | High |
| 4 | Detector Registry | Registration, lookup, enable/disable, metadata, configuration, versioning | No registry. Detectors are hard-coded function calls. | **MISSING** | Complete gap | High |
| 5 | DetectionResult | Structured result with detection_id, detector_id, scores (confidence, anomaly, model, TI, risk), severity_hint, mitre, enrichment, provenance | Detection model has confidence (int), severity (string), evidence (JSON dict). No structured score separation. | **PARTIALLY IMPLEMENTED** | Confidence/severity/risk collapsed; no anomaly_score, model_score, TI confidence | High |
| 6 | DetectionContext | Explicit context passed to detectors (tenant, analysis_run, canonical_events, entities, features, configuration, baseline_provider, model_provider, TI provider) | No context object. Detection engine receives raw parameters (event_count, sequence_count, etc.) | **MISSING** | Complete gap | High |
| 7 | Orchestrator | Central analysis orchestrator: adapter → canonical → features → detector selection → execution → evidence → enrichment → risk → severity → dedup → persistence → correlation → alerts → incidents | The API route `upload_host_trace` IS the orchestrator (analysis.py:337-608). It calls parser → detection engine → persistence inline. | **MISSING** (proper orchestrator) | Monolithic orchestration in API route | High |
| 8 | Evidence Model | Structured, machine-readable evidence (syscall sequence, event count, unusual syscall, network destination, IOC match, statistical deviation, etc.) | Evidence is a JSON dict with `rule`, counts, and lists. Example: `{"rule": "high_event_volume", "event_count": 1200, "threshold": 500}` | **PARTIALLY IMPLEMENTED** | Evidence exists but is unstructured and rule-specific | Medium |
| 9 | Risk Engine | Separate from detection confidence. Factors: asset criticality, privilege, IOC reputation, ATT&CK technique, rarity, recurrence, corroboration, blast radius | No risk engine. Severity is hard-coded per rule (e.g., "privilege_escalation" = "critical"). | **MISSING** | Complete gap | High |
| 10 | Confidence Semantics | Detection confidence, anomaly score, model score, TI confidence, contextual risk — all separate | Single `confidence` field (int). Computed by `_compute_confidence()` heuristic based on matched_rules, event_count, syscall_diversity. | **CONFLICTING** | Heuristic score presented as "confidence" | High |
| 11 | Severity Derivation | Should consider contextual risk, impact, asset importance, privilege, TI, corroboration | Hard-coded per rule: privilege_escalation="critical", suspicious_network_pattern="high", high_event_volume="medium", high_syscall_diversity="low" | **PARTIALLY IMPLEMENTED** | Hard-coded, not derived from context | Medium |
| 12 | Detector-owned Persistence | Detectors should NOT create database records. Persistence belongs to orchestration layer. | `detection_engine.py` creates Detection and Alert objects AND calls `db.add()` / `db.flush()` directly (lines 253-259, 448-454). | **CONFLICTING** | Violates architectural principle | High |
| 13 | Hard-coded Thresholds | Should move to validated configuration with type/range validation, defaults, versioning | All thresholds hard-coded in source: event_count > 500, sequence_count > 50, unique_syscalls > 30, network_used >= 3, src_ips with >= 10 unique_dsts, port with >= 5 sources, 50+ events per port, >= 20 unique destinations | **CONFLICTING** | No configuration system | Medium |
| 14 | Hard-coded Severity | Should be derived from risk context | Each rule hard-codes severity in the if-block | **CONFLICTING** | No dynamic severity | Medium |
| 15 | MITRE ATT&CK | Structured mappings (tactic, technique, sub-technique, version, mapping_confidence) — evidence-based | No ATT&CK mappings exist anywhere in the codebase | **MISSING** | Complete gap | Medium (not Phase 1) |
| 16 | Threat Intelligence | Separate subsystem for IOC matching (IP, domain, URL, hash, etc.) with TI confidence | No TI subsystem | **MISSING** | Complete gap | Medium (not Phase 1) |
| 17 | Behavioral Baselines | Entity-aware baselines with warmup, poisoning protection, drift, lifecycle states | No baselines | **MISSING** | Complete gap | Medium (not Phase 1) |
| 18 | Statistical Anomaly | z-score, MAD, EWMA, rolling statistics | No statistical methods | **MISSING** | Complete gap | Medium (Phase 6) |
| 19 | Unsupervised ML | Isolation Forest, One-Class SVM, LOF, autoencoders, DeepSVDD | No ML at all | **MISSING** | Complete gap | Low (Phase 7-8) |
| 20 | LIGHT-HIDS | Research-faithful DeepSVDD-based architecture with neural feature extraction | Not implemented | **MISSING** | Complete gap | Low (Phase 8) |
| 21 | Correlation | Temporal, entity grouping, cross-detector, attack-chain | No correlation | **MISSING** | Complete gap | Medium (Phase 4) |
| 22 | Deduplication | Prevent repeated identical detections, preserve evidence counts | No deduplication | **MISSING** | Complete gap | Medium (Phase 4) |
| 23 | Suppression | Temporary, detector-specific, entity-specific, with expiration/reason/audit | No suppression | **MISSING** | Complete gap | Medium (Phase 4) |
| 24 | Incident Model | First-class incident with lifecycle (OPEN → TRIAGED → INVESTIGATING → etc.) | No incident model | **MISSING** | Complete gap | Low (Phase 9) |
| 25 | Investigation | Incident-centric: overview, risk, evidence, timeline, entities, process tree, ATT&CK, analyst notes, hypotheses | Current InvestigationPage is a detection detail viewer for a single detection | **PLACEHOLDER** | Not incident investigation | Low (Phase 9) |
| 26 | JWT Authentication | JWT-based auth | **IMPLEMENTED** | — | — | — |
| 27 | RBAC | Role-based access control | **IMPLEMENTED** (admin, analyst roles via require_role) | — | — | — |
| 28 | Audit Logging | Comprehensive audit trail | **IMPLEMENTED** (AuditService with 30+ action types) | — | — | — |
| 29 | Host Trace Upload | JSON/CSV upload and parsing | **IMPLEMENTED** | — | — | — |
| 30 | Syscall Parsing | ID mapping, name resolution, sequence extraction | **IMPLEMENTED** (236 syscalls mapped) | — | — | — |
| 31 | Network Event Extraction | Extract network events from traces | **IMPLEMENTED** | — | — | — |
| 32 | Network Analytics | Summary, top talkers, ports, protocols, timeline, IP detail | **IMPLEMENTED** | — | — | — |
| 33 | Frontend API Integration | Real API calls | **IMPLEMENTED** | — | — | — |
| 34 | Automated Tests | Test suite | **IMPLEMENTED** (pytest with test_detections, test_network, test_audit, test_rbac, test_monitoring) | — | — | — |
| 35 | Modular Monolith | Keep backend modular, allow future extraction | Currently a monolith but no modular boundaries within detection | **PARTIALLY IMPLEMENTED** | Detection is monolithic | Medium |
| 36 | Backward Compatibility | Don't break existing APIs | N/A (no new APIs yet) | **N/A** | — | — |
| 37 | No Premature Microservices | Don't introduce Kafka, K8s, etc. | Correct — none exist | **CORRECT** | — | — |
| 38 | Multi-tenancy | Tenant-scoped objects, server-side isolation | No tenant_id on any model | **MISSING** | Complete gap | Low (not Phase 1) |
| 39 | Upload Security | Content validation, size limits, type validation, parser hardening | Size limit exists (max_upload_mb). Basic JSON/CSV validation. No content sanitization, no timeout, no memory limits. | **PARTIALLY IMPLEMENTED** | Security hardening needed | Medium |
| 40 | Sigma-compatible Design | Support metadata, detection logic, conditions, fields, ATT&CK mappings | No Sigma compatibility | **MISSING** | Not Phase 1 | Low |

## 12. Architectural Conflicts

### Conflict 1: Detector-Owned Persistence
- **Current:** `detection_engine.py` creates Detection and Alert objects AND writes to database directly (lines 253-259, 448-454)
- **Target:** Detectors return `DetectionResult` objects. Persistence handled by orchestrator.
- **Why it conflicts:** Tight coupling prevents independent testing, versioning, and replacement of detectors. Makes it impossible to swap persistence backends or add deduplication/suppression.
- **Migration:** Extract detection logic to pure functions returning dataclass/Pydantic results. Move DB writes to orchestrator.
- **Risk:** Medium — requires touching detection engine and API route simultaneously.

### Conflict 2: Confidence/Risk/Severity Conflation
- **Current:** Single `confidence` field (int 10-99) computed by heuristic formula `_compute_confidence()`. Severity is hard-coded per rule.
- **Target:** Separate fields: detection_confidence, anomaly_score, model_score, TI confidence, contextual_risk, final_risk, severity.
- **Why it conflicts:** The current "confidence" is actually a heuristic volume score, not probabilistic confidence. Calling it "confidence" is misleading and violates the architecture's semantic separation.
- **Migration:** Rename current field to `heuristic_score`. Add separate fields incrementally.
- **Risk:** Low — additive change, can preserve existing field during transition.

### Conflict 3: Monolithic Detection Function
- **Current:** Single `analyse_trace()` function with 6 if/else rules and `analyse_network_events()` with 4 if/else rules.
- **Target:** Independent detector classes registered in a detector registry, executed by an orchestrator.
- **Why it conflicts:** Cannot independently version, enable/disable, test, or replace individual rules. Adding a new rule requires modifying the monolithic function.
- **Migration:** Extract each rule into a detector class. Build registry. Build orchestrator.
- **Risk:** Medium — must preserve exact detection behavior during migration.

### Conflict 4: API Route as Orchestrator
- **Current:** `analysis.py:upload_host_trace` (lines 337-608) handles upload, parsing, detection, persistence, audit — all in one endpoint.
- **Target:** Dedicated orchestrator service. API routes should be thin.
- **Why it conflicts:** Business logic mixed with HTTP concerns. Cannot reuse orchestration for different input sources. Difficult to test detection pipeline independently.
- **Migration:** Extract orchestration logic into a service. Keep API route as thin wrapper.
- **Risk:** Medium — requires careful extraction.

### Conflict 5: Hard-coded Thresholds in Source Code
- **Current:** All detection thresholds are numeric literals in `detection_engine.py` (500, 50, 30, 3, 10, 5, 50, 20).
- **Target:** Validated configuration with type checking, range validation, defaults, versioning, auditability.
- **Why it conflicts:** Changing a threshold requires code change and redeployment. No auditability. No A/B testing capability.
- **Migration:** Move thresholds to configuration. First as simple config, then as database-backed configuration.
- **Risk:** Low — can initially pass config as constructor parameters.

### Conflict 6: Hard-coded Severity
- **Current:** Each rule block hard-codes severity: `"critical"`, `"high"`, `"medium"`, `"low"`.
- **Target:** Severity derived from contextual risk, asset importance, corroboration, TI.
- **Why it conflicts:** Same rule always produces same severity regardless of context. A privilege escalation on a dev box gets same severity as on a production domain controller.
- **Migration:** Keep hard-coded severity as initial default. Add contextual override mechanism later.
- **Risk:** Low — additive change.

## 13. Existing Functionality That Must Be Preserved

1. **FastAPI application** with CORS, router structure
2. **SQLAlchemy models** (7 tables) and database setup
3. **JWT authentication** (register, login, logout, forgot/reset password)
4. **RBAC** (admin, analyst roles)
5. **Audit logging** (30+ action types)
6. **Host trace upload** (JSON/CSV)
7. **Syscall parsing** (236 syscall ID mappings)
8. **Network event extraction** from traces
9. **6 host detections** (high_event_volume, excessive_sequences, suspicious_network_pattern, privilege_escalation, suspicious_file_operations, high_syscall_diversity)
10. **4 network detections** (excessive_connection_attempts, port_scan_detected, high_connection_frequency, repeated_connection_attempts)
11. **Detection persistence** and **alert persistence**
12. **Network analytics** (summary, top talkers, ports, protocols, timeline, IP detail)
13. **Frontend API service layer** (all services)
14. **Frontend pages** (dashboard, monitoring, investigation/detection-detail, analysis, alerts, network, settings, admin)
15. **Existing tests** (test_detections, test_network, test_audit, test_rbac, test_monitoring)
16. **Alembic migrations**
17. **System settings** (max_upload_mb, analysis_history_limit)

## 14. Technical Debt

1. **No detector interface** — rules are inline if/else blocks in a function
2. **Detector-owned database writes** — violates separation of concerns
3. **Heuristic confidence named "confidence"** — semantically misleading
4. **No structured evidence model** — evidence is untyped JSON dicts
5. **Hard-coded thresholds** — no configuration system
6. **API route contains business logic** — monolithic upload endpoint
7. **No canonical event model** — tightly coupled to syscall telemetry
8. **No tenant isolation** — all data is global
9. **SQLite in development** — no production DB testing
10. **Hardcoded JWT default secret** — `dev-secret-change-in-production` in config.py:24
11. **Password reset token logged** — auth.py:203-206 logs the reset token
12. **No rate limiting** on authentication endpoints
13. **No detector timeouts** — analysis can run indefinitely
14. **No streaming/chunking** — entire trace loaded into memory

## 15. Target Detection Architecture

The architecture specifies a **Detection Fabric** with 10+ layers:

1. **Deterministic Rules** — known suspicious patterns, syscall combinations, privilege behaviors (CURRENT: exists as monolithic function)
2. **Signatures** — pattern matching (MISSING)
3. **IOC / Threat Intelligence** — external intelligence matching (MISSING)
4. **Threshold / Rate** — event counts per window (PARTIAL — current rules use simple thresholds but no windowing)
5. **Statistical Anomaly** — z-score, MAD, EWMA (MISSING)
6. **Behavioral Baselines** — entity-aware baselines with warmup/lifecycle (MISSING)
7. **Unsupervised ML** — Isolation Forest, One-Class SVM, LOF, autoencoders (MISSING)
8. **Supervised ML** — conditional on reliable labels (MISSING)
9. **LIGHT-HIDS** — DeepSVDD-based neural feature extraction (MISSING)
10. **Temporal / Correlation** — sequence patterns, attack chains, entity grouping (MISSING)

**Phased evolution:**
- Phase 1-2: Foundation + rule migration
- Phase 3: Evidence and risk
- Phase 4: Correlation
- Phase 5: Enrichment (ATT&CK, TI)
- Phase 6: Statistical detection
- Phase 7: ML foundation
- Phase 8: LIGHT-HIDS
- Phase 9: Incidents
- Phase 10: Advanced telemetry (PCAP, Zeek, Suricata, NetFlow)

## 16. Canonical Event Architecture

The architecture requires a **canonical event abstraction** that is NOT Linux-syscall-specific. It must eventually support:
- Process events, network events, file events, authentication events, syscall events, DNS events, registry events, service events, scheduled-task events, module/library events, session events, host events, flow events, packet-derived events, security events, threat-intelligence observations

Conceptual fields: event_id, tenant_id, asset_id, event_type, source_type, event_timestamp, ingestion_timestamp, sequence_number, process_context, user_context, network_context, file_context, authentication_context, normalized_fields, raw_reference, labels, tags, provenance

**Why this matters:** The current system is tightly coupled to syscall telemetry. Different datasets (CICIDS2017, UNSW-NB15, Bot-IoT, TON_IoT, future PCAP/Zeek/Suricata) have fundamentally different schemas and cannot be forced into the syscall structure.

## 17. Detector Architecture

**Detector Contract:**
```python
class Detector(Protocol):
    detector_id: str
    detector_version: str
    def supports(self, context: DetectionContext) -> bool: ...
    def detect(self, context: DetectionContext) -> list[DetectionResult]: ...
```

**Detector Metadata:** id, name, description, version, category (RULE/SIGNATURE/IOC/THRESHOLD/STATISTICAL/BASELINE/UNSUPERVISED_ML/SUPERVISED_ML/LIGHT_HIDS/CORRELATION), scope (EVENT/PROCESS/USER/HOST/NETWORK_FLOW/ANALYSIS_RUN/INCIDENT), supported_event_types, requires_features, requires_baseline, requires_model, requires_TI, default_enabled, configuration_schema.

**DetectionResult:** detection_id, detector_id, detector_version, detection_type, title, description, evidence, source_events, affected_entities, scores (detection_confidence, anomaly_score, model_score, TI confidence, contextual_risk), severity_hint, mitre, enrichment, timestamps, provenance.

**Relationship:**
```
Detector → DetectionResult → Evidence → Risk → Severity → Alert / Incident
```

## 18. Evidence Architecture

Evidence must be **structured and machine-readable**, not just prose. Potential evidence types: syscall sequence, event count, unique syscall count, unusual syscall, network destination, port distribution, process ancestry, command line, file hash, IOC match, statistical deviation, baseline deviation, anomaly score, correlated detection, ATT&CK mapping, recurrence, rarity.

Current evidence: `{"rule": "high_event_volume", "event_count": 1200, "threshold": 500}` — partially structured but untyped and rule-specific.

## 19. Correlation Architecture

**Temporal correlation:** A followed by B; A then B within N seconds; A and B within a window; N occurrences; N unique values; grouping by entity; ordered sequences.

**Cross-source correlation:** combining signals from host, network, authentication to detect attack chains.

**Attack-chain reconstruction:** Initial Access → Execution → Privilege Escalation → Persistence → Discovery → C2 → Impact — with uncertainty representation.

**Why not just another if/else block:** Correlation requires state management, temporal ordering, entity grouping, and evidence aggregation. A flat if/else structure becomes unmaintainable and cannot handle the combinatorial complexity.

## 20. MITRE ATT&CK Architecture

**Required:** Structured mappings (tactic, technique, sub-technique, version, mapping_confidence, relationship). Must be evidence-based — do not assign ATT&CK techniques to make the UI appear complete.

**Current:** No ATT&CK mappings exist in the codebase.

## 21. Threat Intelligence Architecture

**Required:** Separate subsystem. IOC categories: IPv4, IPv6, domain, URL, file hash, certificate, email, malware family, threat actor, campaign. Support exact match, normalized match, expiration, confidence, source, freshness. Future providers: internal feeds, STIX/TAXII, public feeds, commercial feeds.

**Current:** No TI subsystem.

## 22. Behavioral Baseline Architecture

**Required:** Entity-aware baselines (host, user, process, service, network peer). Dimensions: syscall distribution, process activity, destination IPs, destination ports, protocols, connection frequency, process ancestry, file activity, authentication, DNS. Lifecycle: INITIALIZING → LEARNING → ACTIVE → DEGRADED → STALE → RETIRED. Poisoning protection: suspicious-event exclusion, bounded update rates, robust statistics, drift detection.

**Current:** No baselines.

## 23. ML Architecture

**Statistical (Phase 6):** z-score, robust z-score, MAD, rolling mean/std, percentile deviation, EWMA, robust quantiles.

**Unsupervised (Phase 7):** Isolation Forest (initial candidate for tabular anomaly), One-Class SVM, LOF, autoencoders. Each must declare model, version, feature schema, preprocessing, threshold, inference time.

**Supervised (Phase 7, conditional):** Random Forest, XGBoost, LightGBM, logistic regression — only with reliable labels, leakage-free evaluation, class imbalance handling.

**Current:** None of this exists.

## 24. LIGHT-HIDS Architecture

**Required research-faithful implementation:**
```
System Call Sequence → Feature Representation → Compressed Neural Feature Extractor → DeepSVDD → Compact Normal Representation → Novelty/Anomaly Score → DetectionResult
```

Must document: feature representation, preprocessing, network architecture, compression, DeepSVDD objective, training, inference, threshold selection, dataset, evaluation, computational cost.

**Current:** Not implemented. No ML libraries in requirements.txt. Must NOT claim LIGHT-HIDS support.

## 25. Risk Architecture

**Required separation:**
- Detection confidence — how strongly evidence supports the hypothesis
- Anomaly score — how unusual the behavior is (statistical/ML)
- Model score — raw/normalized score from a model
- TI confidence — confidence in external intelligence match
- Contextual risk — potential security/business impact given context
- Final risk — aggregated operational risk
- Severity — operational priority classification

**Risk factors:** asset criticality, privilege, external/internal origin, IOC reputation, ATT&CK technique, rarity, recurrence, persistence, corroboration, blast radius, exploitability, detection quality.

**Current:** Single `confidence` field (int) computed by heuristic formula. Severity hard-coded per rule. Risk and confidence conflated.

## 26. Alert Architecture

**Required:** Alert deduplication (by detector, entity, IOC, destination, time window, behavior signature). Suppression (temporary, detector-specific, entity-specific, with expiration, reason, actor, audit history). Alert fatigue metrics (alerts per host, per hour, duplicates, false positives, unresolved age).

**Current:** Every detection generates exactly one alert. No deduplication, no suppression. Alert has status (new/investigating/resolved) with audit trail.

## 27. Incident Architecture

**Required:** First-class incident model with lifecycle (OPEN → TRIAGED → INVESTIGATING → CONTAINMENT_RECOMMENDED → RESOLVED → CLOSED → FALSE_POSITIVE). Incident includes: title, summary, severity, risk_score, status, entities, detections, alerts, timeline, attack_chain, ATT&CK mapping, analyst_notes, assignments.

**Current:** No incident model. The Investigation page is a detection detail viewer.

## 28. Investigation Architecture

**Required (eventually):** Incident overview, risk, evidence, timeline, entities, process tree, network relationships, ATT&CK, related alerts, related detections, analyst notes, hypotheses, audit history.

**Current:** `InvestigationPage.tsx` displays a single detection's detail: severity, status, confidence, description, network details (source/dest IP, protocol), evidence JSON, related alerts, analysis run info, and status change buttons. This is a **detection detail viewer**, not an incident investigation system.

## 29. Implementation Phases

| Phase | Name | Key Deliverables |
|---|---|---|
| 1 | Detection Foundation | Canonical events, DetectionContext, DetectionResult, Detector interface, Detector registry, Orchestrator, Structured evidence, Risk-engine interface, Host trace normalization, Existing rule migration |
| 2 | Rule Migration | All host/network rules into independent detectors, remove detector-to-DB coupling |
| 3 | Evidence and Risk | Structured evidence, confidence semantics, anomaly-score fields, contextual risk, severity derivation |
| 4 | Correlation | Temporal correlation, detection correlation, entity grouping, deduplication, suppression |
| 5 | Enrichment | ATT&CK, asset context, IOC abstraction, TI abstraction |
| 6 | Statistical Detection | Rolling statistics, robust z-score, MAD, EWMA, configurable thresholds |
| 7 | ML Foundation | Feature schemas, model registry, model evaluation, model artifacts, Isolation Forest |
| 8 | LIGHT-HIDS | Research-faithful DeepSVDD-based architecture |
| 9 | Incidents | Incident model, correlation, timeline, analyst notes, attack chain, investigation workflow |
| 10 | Advanced Telemetry | Endpoint telemetry, PCAP, Zeek, Suricata, NetFlow/IPFIX, streaming |

## 30. Phase 1 Requirements

Phase 1 must implement:
1. Canonical event model (adapted for host trace input)
2. Host trace normalization (refactor existing parser into adapter)
3. DetectionContext dataclass
4. DetectionResult dataclass with structured scores
5. Detector interface (Protocol or ABC)
6. Detector registry (registration, lookup, enable/disable, metadata)
7. Analysis orchestrator (replaces API-route-as-orchestrator)
8. Structured evidence contract
9. Risk-engine interface (can be stub/heuristic initially)
10. Migration of 6 host rules + 4 network rules into independent detector classes
11. Regression tests proving equivalence

## 31. Phase 1 Non-Goals

**Do NOT implement in Phase 1:**
- Full ML (no scikit-learn, no PyTorch)
- Full LIGHT-HIDS (no DeepSVDD, no neural networks)
- PCAP parsing
- Zeek/Suricata/NetFlow adapters
- Streaming analysis
- Autonomous response
- Complete threat-intelligence feeds
- Full incident UI
- Massive frontend rewrite
- Microservices
- Kafka/Kubernetes/distributed infrastructure
- Complete MITRE ATT&CK mapping
- Behavioral baselines
- Statistical anomaly detection
- Correlation engine

## 32. Phase 1 Readiness

### **YES — SentinelAI is ready to begin Phase 1.**

**Reasons:**
1. The existing codebase is functional and has working end-to-end flow
2. Tests exist and provide regression safety
3. The detection engine, while monolithic, is well-understood and can be migrated rule-by-rule
4. No blocking technical debt prevents Phase 1
5. The database models can be extended incrementally
6. The frontend consumes APIs and can tolerate backend refactoring as long as API contracts are preserved
7. Sample data exists for regression testing
8. The architecture document provides clear guidance on what to build and what NOT to build

**What makes Phase 1 feasible now:**
- The current system is small enough to refactor safely
- There are only 10 detectors to migrate (6 host + 4 network)
- The parser (`host_trace.py`) is already separated from detection logic
- The test suite covers the critical API paths

## 33. Critical Risks

1. **Regression risk during migration** — if detection behavior changes even slightly, existing users lose trust. Mitigation: compatibility testing with sample-data/example-host-trace.json before and after.

2. **Over-engineering Phase 1** — temptation to build more than the foundation. Mitigation: strict adherence to Phase 1 non-goals.

3. **Frontend breakage** — if API response shapes change, frontend breaks. Mitigation: preserve API contracts or version them.

4. **Hard-coded confidence value** — the current confidence integer (10-99) is displayed in the frontend as a percentage. Changing semantics could confuse users. Mitigation: keep field name and range during Phase 1, clarify semantics in documentation.

5. **Detector-owned persistence extraction** — requires moving DB operations from detection_engine.py to the orchestrator. Risk of missed flush/commit. Mitigation: careful transaction management in orchestrator.

## 34. Ambiguities / Questions

1. **Canonical event depth for Phase 1:** The architecture specifies a rich canonical event model (process_context, user_context, file_context, etc.), but the current input is only syscalls + network events. How minimal can the Phase 1 canonical event be? *Recommendation: Start with a minimal canonical event that covers syscall events and network events only. Extend in later phases.*

2. **Risk engine in Phase 1:** The architecture says "risk-engine interface" for Phase 1. Is a stub that returns a fixed/default risk score sufficient? *Recommendation: Yes, a stub returning the current hard-coded severity as initial risk is acceptable.*

3. **Detector registry scope:** Should the registry support configuration (thresholds) in Phase 1, or just registration/lookup? *Recommendation: Registration/lookup with optional configuration dict. Full config validation can come in Phase 2-3.*

4. **Frontend changes in Phase 1:** The architecture says "APIs remain functional" and "existing frontend behavior must continue." Should any frontend changes be made in Phase 1? *Recommendation: No frontend changes in Phase 1 unless strictly necessary for API compatibility.*

5. **Alembic migrations:** Should Phase 1 create new tables (canonical_events, detector_results) or only extend existing models? *Recommendation: Extend existing Detection model with new fields. Add new tables only when needed.*

## 35. Recommended Next Step

**Begin Phase 1 implementation with this sequence:**

1. **Define data contracts** — Create `backend/app/core/detection.py` (or similar) with:
   - `CanonicalEvent` dataclass
   - `DetectionContext` dataclass
   - `DetectionResult` dataclass
   - `Detector` Protocol
   - `DetectorMetadata` dataclass

2. **Build detector registry** — Create `backend/app/services/detector_registry.py` with registration, lookup, enable/disable

3. **Extract host trace adapter** — Refactor `host_trace.py` into a class implementing an adapter interface that produces canonical events

4. **Migrate first detector** — Extract `high_event_volume` rule into `HighEventVolumeDetector` class

5. **Build orchestrator skeleton** — Create `backend/app/services/analysis_orchestrator.py` that replaces the inline logic in `analysis.py:upload_host_trace`

6. **Regression test** — Run existing tests, compare detection output with sample-data

7. **Migrate remaining 9 detectors** — One at a time, with regression tests

8. **Wire orchestrator into API** — Replace inline detection calls in `analysis.py`

9. **Documentation** — Update architecture docs, create ADRs

---

**End of Audit Report.**
