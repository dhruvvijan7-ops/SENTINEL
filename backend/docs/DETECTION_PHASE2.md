# SentinelAI Detection Engine — Phase 2 (Configurable Rules, Temporal & Sequence Detection, IOC Foundation)

This document describes the Phase 2 extension of the modular detection engine
defined by `DOCS/ANALYSIS ENGINE P2 MASTER BUILDER IMPLEMENTATION PROMPT.docx`
and `DOCS/SentinelAI Phase 2 Master Builder.pdf`. Phase 1 built the modular
architecture; Phase 2 adds **configurable rules**, **rate/window detection**,
**ordered sequence detection**, and the **IOC (indicator of compromise)
foundation** — all on top of the same architecture without redesigning it.

## Architecture

The canonical flow from Phase 1 is unchanged:

```
raw trace ──> TraceSummary ──> CanonicalEvent[] ──> DetectionContext
        ──> DetectionOrchestrator/Registry ──> DetectionResult[]
        ──> persist_detections ──> Detection + Alert (ORM)
```

New Phase 2 packages:

- `app/detection/configuration/` — schemas, defaults, validation, provider.
- `app/detection/temporal/` — sliding-window primitives (rate detection).
- `app/detection/sequence/` — declarative ordered-predicate matching.
- `app/detection/ioc/` — IOC model, normalization, matcher, provider.

### Configuration

Detector configuration is centralized and validated:

- `DETECTOR_CONFIG_SCHEMAS` — parameter types, ranges, defaults (single source of truth).
- `DEFAULT_CONFIG` — resolved defaults per detector.
- `DEFAULT_ENABLED` — default enabled state per detector.
- `DetectorConfigurationProvider` — read-only, validated in-memory provider
  (no database table, per spec 104) injectable into the orchestrator and pipeline.

Precedence for each detector (highest wins):

1. configuration injected into the `DetectionContext` by the orchestrator
   (per-detector, validated),
2. schema defaults.

Every detector resolves its effective config through `resolve_detector_config`,
so detectors work both standalone (tests/invocation) and through the pipeline.

### Orchestrator lifecycle

The pipeline builds a **fresh orchestrator per call** (`build_orchestrator`) —
the Phase 1 process-wide `_orchestrator_instance` singleton was removed. This
eliminates stale cross-run state. The orchestrator injects each detector's
validated config into an isolated per-detector `DetectionContext` copy via
`dataclasses.replace`.

## Detectors

All 10 Phase 1 detectors are preserved (`host.*` and `network.*`), now
config-driven with the **same thresholds by default**, plus 3 Phase 2 detectors:

| detector_id | category | rule | defaults |
|---|---|---|---|
| `network.event_rate_window` | rule | network events per dest port within a sliding time window | `window_seconds=60`, `event_threshold=50` |
| `host.syscall_sequence` | rule | ordered system-call pattern (A, B, C) | `sequence=("open","write","close")`, `window_seconds=None` |
| `network.ioc_match` | ioc | network IP telemetry matches a configured IOC | — |

### Rate / window detection

`EventRateWindowDetector` counts network events grouped by destination port
within a configurable sliding window (`grouped_max_in_window`, O(n log n)
two-pointer window) and fires when the windowed count reaches
`event_threshold`. It consumes **only NETWORK events**, which carry real
timestamps.

### Sequence detection

`SyscallSequenceDetector` finds an **ordered** predicate pattern over
system-call events. Matching is a single left-to-right greedy pass (O(n·k)),
non-overlapping. Because system-call events currently lack timestamps, matching
uses **event order** (`ordering_basis="event_index"`) and the matcher honestly
reports `temporal_constraint_applied=False` — it never fabricates elapsed time.

### IOC support

The IOC foundation (`app/detection/ioc/`) is dependency-inverted:

- `IOC`, `IOCType` — typed indicators with provenance (source, confidence).
- `normalize_ioc` — safe canonicalization (IPs via `ipaddress`, domains/URLs).
- `IOCMatcher` — O(1) index over `(type, normalized_value)`.
- `IOCProvider` — in-memory provider; an injectable abstraction so a future
  STIX/TAXII feed can replace it without touching the detector.

`IOCDetector` matches **real NETWORK IP telemetry** (`source_ip`,
`destination_ip`) against IP IOCs. The default provider is empty — **no IOC is
fabricated** — so with no configured IOCs the detector reports nothing. Tests
inject explicit test IOCs.

## Score semantics

Unified through a single `compute_heuristic_score(event_count, diversity,
matched_rules)`:

- host detectors pass `diversity = unique_system_calls`,
- network detectors pass `diversity = port_count`.

This preserves both Phase 1 formulas exactly. `heuristic_score` remains the
only score produced; `detection_confidence`, `anomaly_score`, `risk_score`,
etc. stay `None` until a genuine source exists. `heuristic_score` is a
heuristic, **not** a probability.

## Evidence

Phase 2 evidence is bounded and JSON-serializable (matched events are
truncated at a cap and flagged as truncated). IOC, sequence, and window
evidence each expose `rule`, `observed_values`, `matched_events`,
`matched_fields`, `description`. Evidence remains a JSON object persisted on
`Detection.evidence` (backward compatible with the Phase 1 frontend renderer).

## Persistence

Per the Master Builder persistence reality:

- Added `Detection.detector_id`, `Detection.detector_version`,
  `Detection.source_events` (compact JSON event references).
- `persist_detections` now writes these fields. `Alert.source` is preserved for
  backward compatibility.
- Alembic migration `f1f2f3f4f5f6_add_detector_provenance_and_source_events.py`
  (additive; upgrade/downgrade verified against SQLite; Postgres-compatible).
- `DetectionResponse` exposes the new fields additively; the frontend `Detection`
  type was updated additively with **no UI change**.

## Testing

- Full backend suite: `python -m pytest -q` → **225 passed** (196 Phase 1/2 +
  29 new Phase 2 tests).
- New: `tests/test_phase2_detectors.py` covers rate/window, sequence matching,
  IOC normalization/provider/matcher, and registry integration.
- The legacy `tests/test_network.py::TestNetworkDetectionEngine` import was
  migrated from `app.services.detection_engine` to `app.detection.pipeline`
  (same `(list[Detection], list[Alert])` contract). The legacy
  `app/services/detection_engine.py` is retained with an explicit deprecation
  marker.

## Timestamp / telemetry limitations

Documented facts, not design gaps:

1. **System-call events carry no timestamp** (`timestamp=None`); only NETWORK
   events carry real time. Rate/window and temporal processing therefore apply
   only to network telemetry. Sequence matching uses ordering.
2. **`file_hash`, `domain`, `url`** are schema-supported IOC fields but are not
   currently populated by host-trace telemetry. The IOC detector evaluates only
   values that actually exist (IPs); it never fabricates hashes/domains/URLs.
3. The IOC provider default is empty (no fabricated/threat-intelligence IOCs).

## Known limitations

- IOC sources are in-memory only; no external threat feed (per spec 191).
- System-call sequence time windows are not enforced (no timestamps).
- Configurable rules are validated and injectable but there is no runtime admin
  API to change them yet (in-memory provider).

## Phase 3 extension points

- Plug a real IOC source (STIX/TAXII) into `IOCProvider` behind the same interface.
- Enforce sequence time windows once system-call telemetry carries timestamps.
- Add a persistence-backed configuration provider and an admin configuration API.
- Replace the IOC detector's provider with external-threat-intelligence feeds.
