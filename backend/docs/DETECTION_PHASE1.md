# SentinelAI Detection Engine — Phase 1 (Modular Architecture)

This document describes the Phase 1 migration of the detection engine to the
modular architecture defined in `DOCS/SENTINELAI ANALYSIS ENGINE V2 PROMPT.docx`.

## Goal

Establish a truly modular detection foundation while preserving every existing
API behavior and all 10 detection rules exactly.

Canonical flow:

```
raw trace ──> TraceSummary ──> CanonicalEvent[] ──> DetectionContext
        ──> DetectionOrchestrator/Registry ──> DetectionResult[]
        ──> persist_detections ──> Detection + Alert (ORM)
```

## What was done

### 1. Fixed circular import (`app/detection/adapters/`)

`host_trace.py` (adapter) imported `TraceSummary` from `host_trace_parser.py`,
and `host_trace_parser.py` imported `trace_summary_to_canonical_events` from
`host_trace.py`. This raised
`ImportError: cannot import name 'trace_summary_to_canonical_events'` and broke
import of the entire application (and all tests).

Fix:
- `host_trace.py` now imports `TraceSummary` / `summarize_host_trace` directly
  from `app.services.host_trace` (the real parser / source of truth).
- `host_trace_parser.py` is now a thin **public facade** that re-exports the
  adapter surface from the two real sources; it no longer participates in a cycle.

### 2. Fixed unwired pipeline (`app/api/routes/analysis.py`)

The route imported the new detection components but still called the legacy
`analyse_trace` / `analyse_network_events`, which were never imported (a future
`NameError`).

Created `app/detection/pipeline.py`, which exposes `analyse_trace` and
`analyse_network_events` with the same names/signatures the route and the audit
failure tests rely on, but now backed by the modular pipeline:

- `analyse_trace` -> SYSTEM_CALL canonical events -> host-scoped detectors
- `analyse_network_events` -> NETWORK canonical events -> network-scoped detectors

The route's unused per-detector imports were replaced with a single import of
the two pipeline functions.

### 3. Added registry bootstrap (`app/detection/registry/bootstrap.py`)

`build_registry()` registers all 10 Phase 1 detectors (6 host + 4 network).
`build_orchestrator()` returns a reusable orchestrator backed by that registry.
No detector / route knows about any other component.

### 4. Orchestrator event-type scoping

Added an optional `event_types` filter to `DetectionOrchestrator.execute()` so
the application can scope a run to host detectors, network detectors, or all.
The orchestrator still:

- queries only enabled detectors,
- isolates per-detector failures (collects errors without crashing the run),
- knows nothing about individual detectors or DB persistence.

### 5. Test infrastructure hardening (`tests/conftest.py`)

`app.main` eagerly calls `Base.metadata.create_all(bind=engine)` at import time.
With `.env` pointing at Postgres and no running server, the entire suite could
not import. `config.py` calls `load_dotenv()`, which does not override existing
env vars, so conftest now sets a SQLite `DATABASE_URL` (and a test JWT secret)
before importing `app.main`. This is test-only and leaves application behavior
unchanged.

## Detection rules preserved (10)

Host (migrated from `analyse_trace`):

| detector_id | type | rule |
|---|---|---|
| `host.high_event_volume` | threshold | event_count > 500 |
| `host.excessive_sequences` | threshold | sequence_count > 50 |
| `host.suspicious_network_pattern` | rule | >= 3 distinct network syscalls |
| `host.privilege_escalation` | rule | any privilege syscall |
| `host.suspicious_file_operations` | rule | >= 2 sensitive file syscalls |
| `host.high_syscall_diversity` | threshold | unique_system_calls > 30 |

Network (migrated from `analyse_network_events`):

| detector_id | type | rule |
|---|---|---|
| `network.excessive_connection_attempts` | threshold | src -> >= 10 unique dst |
| `network.port_scan_detected` | threshold | port <- >= 5 unique src |
| `network.high_connection_frequency` | threshold | port with >= 50 events |
| `network.repeated_connection_attempts` | threshold | src -> >= 20 unique dst |

Severities, evidence, thresholds, alert generation, and network event
relationships are preserved. The heuristic score remains a heuristic in the
10–99 range.

## Notes / deviations

- The legacy `app/services/detection_engine.py` is intentionally retained as a
  compatibility module. `tests/test_network.py::TestNetworkDetectionEngine`
  still calls it directly, and it remains the migration reference. It is no
  longer the pipeline used by the upload route.
- Risk boundary (`app/detection/risk.py`) remains a transitional severity→score
  placeholder per the spec. It is not yet a "real" contextual risk engine.

## Verification

- Full suite: `python -m pytest -q` -> 196 passed (169 pre-existing + 27 new).
- New tests: `tests/test_detection_architecture.py` covers canonical adapters,
  registry bootstrap, orchestrator scoping, detector failure isolation, detector
  independence (no DB), and pipeline persistence.
- End-to-end upload of `backend/sample-data/example-host-trace.json` produces a
  completed run with `suspicious_network_pattern` detection (confidence 15) and
  one alert, matching legacy semantics.
