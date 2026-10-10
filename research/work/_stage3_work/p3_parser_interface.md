## 3. Parser Interface

Two parser families implement one contract. **Telemetry parsers** turn
harvested logs into `canonical-event/v1` events (this is the Stage-2 consumer
side). **Content extractors** turn artifact bytes into *facts* (§12), which a
separate mapper turns into canonical events in the reserved categories. They
share the streaming, error-taxonomy and never-raise-per-record rules; they
differ in their yield type.

The interface is written as a `typing.Protocol` plus a documented ABC for the
shared plumbing. Parsers are **not** required to inherit from the ABC, only
to satisfy the Protocol — this keeps third-party or optional parsers
(external-process ones in particular) implementable without a class hierarchy
commitment.

### 3.1 Types

```python
# sentinel/ingest/parser_api.py
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import BinaryIO, ClassVar, Iterator, Literal, Mapping, Protocol, runtime_checkable

Status = Literal["COMPLETED", "COMPLETED_WITH_WARNINGS", "FAILED"]

# Canonical event is the Stage-2 object. Typed here only as a Mapping so that
# this module does not need to import the JSON Schema; validation against
# canonical_event_v1.schema.json happens once, at the pipeline boundary.
CanonicalEvent = Mapping[str, object]


@dataclass(frozen=True, slots=True)
class ParseContext:
    """Everything a parser is allowed to know about the run. Immutable."""
    artifact_id: str
    tenant_id: str
    workspace_id: str
    run_id: str
    source_format: str                  # identification.selected (§2)
    source_path: str | None             # storage_key or harvest path; never opened by the parser itself
    declared_format: str | None         # agent/manifest hint (advisory)
    parser_config: Mapping[str, object] # parser-specific, from configuration data, never from the artifact
    deadline_monotonic: float            # monotonic-clock cutoff; pipeline sets
                                          # time.monotonic() + budget (never wall-clock,
                                          # per invariant 6 determinism)
    max_events: int                     # hard cap on emitted events
    max_bytes_read: int                 # hard cap on bytes consumed from the stream
    max_record_bytes: int               # hard cap on one record before it is split or failed
    emit_raw: bool                      # Stage-2 lossless `raw` inclusion (default true)
    emit_unmapped: bool                 # Stage-2 `unmapped[]` inclusion (default true)
    timezone_default: str | None        # run-config timezone; never guessed (Stage-2 D2-003)


class ParserErrorKind(str, Enum):       # noqa: E501 - see §3.3 for the taxonomy
    UNSUPPORTED_FORMAT = "unsupported_format"
    TRUNCATED_INPUT = "truncated_input"
    CORRUPT_RECORD = "corrupt_record"
    ENCODING = "encoding"
    RESOURCE_LIMIT = "resource_limit"
    DEPENDENCY_MISSING = "dependency_missing"
    SOURCE_CONTRACT = "source_contract"
    INTERNAL = "internal"


@dataclass(frozen=True, slots=True)
class ParserError:
    kind: ParserErrorKind
    locator: str | None       # record locator: line number, record id, byte offset, sheet name
    message: str               # operator-readable, never contains artifact bytes
    field: str | None = None
    detail: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ParserWarning:
    kind: str                  # e.g. "unmapped_field", "clock_assumed", "column_not_bound"
    locator: str | None
    message: str


@dataclass(slots=True)
class ParserResult:
    """Returned by finalize(). Always returned — even on total failure."""
    status: Status
    parser_id: str
    parser_version: str
    records_seen: int
    events_emitted: int
    records_failed: int
    bytes_read: int
    warnings: list[ParserWarning]
    errors: list[ParserError]
    coverage: Mapping[str, object]   # parser-specific, e.g. {"channels": {...}, "columns_unbound": [...]}

    @property
    def partial(self) -> bool:
        return self.status == "COMPLETED_WITH_WARNINGS"


@runtime_checkable
class TelemetryParser(Protocol):
    """Turns a harvested log byte stream into canonical-event/v1 events."""

    parser_id: ClassVar[str]          # e.g. "evtx.rust"   (stable id, appears in source.parser)
    parser_version: ClassVar[str]     # tool/library version, appears in source.parser_version
    accepted_formats: ClassVar[frozenset[str]]   # subset of identification.selected values

    def sniff(self, head: bytes, ctx: ParseContext) -> float:
        """Return 0.0..1.0 confidence that this parser handles the stream.
        MUST be cheap (no I/O beyond `head`), MUST NOT mutate state, and MUST
        NOT be the routing authority — routing uses identification (§2)."""
        ...

    def parse(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[CanonicalEvent]:
        """Lazily yield canonical events. Streaming, bounded, cancellable."""
        ...

    def finalize(self) -> ParserResult:
        """Idempotent. Returns COMPLETED, COMPLETED_WITH_WARNINGS or FAILED."""
        ...


@dataclass(frozen=True, slots=True)
class Fact:
    """A single extracted observation about an artifact (§12)."""
    namespace: str             # e.g. "pe", "ooxml", "pdf", "archive"
    name: str                  # e.g. "import", "relationship.external_target", "action.open_action"
    value: object              # JSON-serialisable; None is legal here (facts are not schema events)
    value_type: Literal["string", "int", "float", "bool", "timestamp", "enum",
                        "list", "bytes_hex", "state"]
    locator: str | None        # where in the artifact: "part:/word/document.xml", "section:.text", "obj:12 0 R"
    confidence: Literal["observed", "derived"] = "observed"


class ContentExtractor(Protocol):
    """Turns artifact bytes into Facts. NEVER into verdicts (§8)."""

    extractor_id: ClassVar[str]
    extractor_version: ClassVar[str]
    accepted_formats: ClassVar[frozenset[str]]

    def extract(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Fact]:
        ...

    def finalize(self) -> ParserResult:
        ...
```

### 3.2 Normative behaviour of `parse` / `extract`

1. **Streaming.** `parse` is a generator. A parser MUST NOT require the whole
   stream in memory. Where a third-party library materialises the whole
   object (OLE container directory, OOXML part table), the parser MUST
   materialise *the index*, not the payload bytes, and MUST stream payloads.
2. **Never raise per record.** A malformed record is caught inside the
   generator, recorded as a `ParserError` with a locator, counted in
   `records_failed`, and iteration continues. Exceptions escape only for
   programmer errors (a bug in the parser itself), which the pipeline
   converts to `status: FAILED` at the job level.
3. **Never return partial objects silently.** A record that could not be
   fully interpreted still yields an event if the envelope could be built —
   with the unavailable values expressed in the Stage-2 value-state form
   (`{"$state": "invalid", "$raw": ...}`), not omitted and not bare-null
   (Stage-2 D2-001).
4. **Losslessness.** `raw` carries the verbatim source record (string for
   text/EVTX-rendered, object for JSON) and `unmapped[]` carries named source
   fields with no canonical home. Both are on by default and a parser MUST
   NOT drop a source field that has no canonical destination — it goes to
   `unmapped[]` (Stage-2 D2-012).
5. **Cancellation.** Before each record a parser checks
   `time.monotonic() >= ctx.deadline_monotonic` and its own byte/event counters.
   On breach it stops cleanly and returns
   `status: COMPLETED_WITH_WARNINGS` with a `resource_limit` error entry that
   records the number of records it managed to emit.
6. **Determinism.** For the same bytes and the same configuration, two runs
   emit the same events in the same order. Parsers MUST NOT consult wall
   clock, randomness, network, environment variables, or locale.
7. **No side effects.** A parser writes nothing outside the pipeline's own
   output buffers. It does not create temp files, does not spawn processes
   (external-process parsers are driven by the *pipeline*, not by the parser
   object — §4), and does not open any path other than the `stream` it was
   given.
8. **Timezone honesty.** A parser never guesses a timezone
   (Stage-2 D2-003). No documented timezone and no `timezone_default` →
   `time.timezone_source: none`.
9. **Schema conformance is the pipeline's job, not the parser's.** The
   pipeline validates emitted events against `canonical_event_v1.schema.json`
   and records a `source_contract` error for any event that fails. Parsers
   SHOULD emit conforming events; they are not required to re-validate
   internally on every record (that would double the cost).

### 3.3 Error taxonomy

| Kind | Meaning | Typical locator | Effect on status |
|---|---|---|---|
| `unsupported_format` | the parser was handed a stream identification said it owns, but the stream is not that format | byte offset 0 | FAILED if it happens before the first record; otherwise a warning |
| `truncated_input` | the stream ends inside a record/container | byte offset / record id | warning; remaining records are skipped |
| `corrupt_record` | a record is structurally invalid (bad CRC, bad XML, bad length prefix) | record id / line | per-record; counts toward `records_failed` |
| `encoding` | a byte sequence could not be decoded in the declared encoding | record id / field | per-record; the raw bytes go into `$raw` with `$state: invalid` |
| `resource_limit` | deadline, `max_events`, `max_bytes_read`, `max_record_bytes`, or an external process's own limit | n/a | warning if anything was emitted; FAILED if nothing was |
| `dependency_missing` | an optional native library or external binary is not installed | n/a | FAILED, and the job is marked retryable-by-operator |
| `source_contract` | an emitted event failed schema validation, or the source violated a documented contract (e.g. a `#fields` header that does not match the line's column count) | record id | warning; the offending event is dropped and counted |
| `internal` | a bug in the parser | stack hash | FAILED |

`COMPLETED_WITH_WARNINGS` is mandatory, not optional (inherited invariant):
a harvest that lost 3 of 400,000 records is a *success with warnings*, and
the operator's dashboard must say so, rather than either lying with
`COMPLETED` or throwing away 399,997 good records with `FAILED`.

### 3.4 The pipeline around the interface

```
upload/harvest  →  gate (§1)  →  store  →  identify (§2)
                                              │
                    ┌─────────────────────────┴──────────────────────────┐
                    ▼ telemetry branch                                    ▼ artifact branch
            route by selected format                              route by selected format
                    │                                                      │
            TelemetryParser.parse(stream)                          ContentExtractor.extract(stream)
                    │                                                      │
            canonical-event/v1 events                               Facts
                    │                                                      │
            schema validation (fail → source_contract)            Fact mapper (§12)
                    │                                                      │
            batch insert + outbox                                     → document / archive_member /
            (events are immutable)                                      executable / artifact /
                                                                         artifact_finding events
                    │                                                      │
            Sigma-compatible detection (Stage 1)                   fact-to-finding rules (§12)
                                                                         │
                                                                   artifact_finding events
```

Two consequences worth stating because they are invariants, not
implementation detail:

- **Detectors still consume only canonical events.** The artifact branch's
  facts are *not* handed to detectors. They are (a) mapped into the reserved
  canonical categories and (b) evaluated by fact-to-finding rules whose
  *output* is `artifact_finding` canonical events. A detector never sees a
  `pe.import` fact object; it sees an `artifact_finding` event whose
  `finding`/`evidence` fields quote it.
- **External-process parsers are driven by the pipeline, not by the parser
  object.** A parser implementation for TShark or ClamAV is a thin adapter
  that reads the subprocess's stdout stream; the *subprocess spawn, its
  sandbox, its timeout and its resource caps* belong to the pipeline's
  `ExternalProcessRunner`, which is the component §4 and §9 govern. This
  keeps the "parsers have no side effects" rule true even for tools that are
  inherently processes.

---

## 4. Parser Decision Matrix

Columns: the format; what produces it in Sentinel; the candidates that were
actually opened and verified (§0); the decision; the fallback; the licence
class; the evidence; and the budget. Every budget is `PROPOSED - TO
BENCHMARK` with the fixture or method that Stage 4 must run.

Licence class values: `in-process` (linked/imported into the Sentinel
process, licence must be Stage-1-D-008 compatible), `external-process` (run
as a separate binary; copyleft is acceptable because nothing is linked, but
§9 prohibitions still bind it), `excluded` (not used at all).

### 4.1 Windows event logs

| Format | Candidate | Version / commit observed | SPDX | Class | Verdict |
|---|---|---|---|---|---|
| EVTX | `evtx` (PyPI binding of omerbenamram/evtx) | 0.13.1 (2026-09-22); head 7479d02 (2026-10-07) | MIT OR Apache-2.0 (crate); MIT (binding) | in-process | **chosen** |
| EVTX | python-evtx (williballenthin) | 0.8.1 (2025-05-02); head c000744 (2026-10-06) | Apache-2.0 | in-process | fallback when the native wheel is unavailable |
| EVTX | libevtx / pyevtx (libyal) | 20260705; no PyPI distribution exists | LGPL-3.0-or-later | excluded | see rationale |

**Decision (D3-001).** Primary EVTX parser is the `evtx` binding. Rationale:
(1) it is the only candidate that is both actively released in the current
quarter and licence-clean for commercial distribution without a copyleft
conversation; (2) it is Rust, so a malformed record is far less likely to be
a memory-safety incident than in a C parser — relevant because EVTX files are
attacker-influenceable on any host where an attacker can write to a log
source; (3) pure-Python python-evtx remains a genuine fallback (same
behaviour contract, no native wheel needed) for hosts where the binding
cannot be installed. libevtx is excluded on licence (LGPL-3.0-or-later is
weaker than GPL but is still copyleft that Stage-1 D-008 excludes from linked
code) and offers no functional advantage that would justify an
external-process arrangement.

**Adapter contract.** The adapter renders each EVTX record to the XML form
the binding exposes, then applies the Stage-2 SEC-A/SEC-B mapping tables
verbatim — the mapping tables, not the library, own the field names, so
swapping python-evtx for the Rust binding changes nothing observable except
`source.parser`.

| Budget | Proposed | Method |
|---|---|---|
| Records/second per worker | ≥ 20k `PROPOSED - TO BENCHMARK` | 1 GiB synthetic EVTX (FX-H-01) timed end-to-end |
| Memory ceiling | 128 MiB per worker `PROPOSED - TO BENCHMARK` | FX-H-01 under a job-object cap |
| Truncated/corrupt EVTX | emit `truncated_input` warning, keep records before the damage | FX-H-02…FX-H-04 |

### 4.2 Network capture and network telemetry exports

| Format | Candidate | Version | SPDX | Class | Verdict |
|---|---|---|---|---|---|
| pcap / pcapng | TShark `-T ek` (NDJSON per packet) | 4.6.9, tag 2d548b19 (2026-09-23) | GPL-2.0-or-later | external-process | **chosen**, pinned `>= 4.6.9` |
| pcap / pcapng | TShark `-T fields` | same | GPL-2.0-or-later | external-process | chosen for the columnar path (§4.2.2) |
| pcap | dpkt / scapy / pyshark | not opened in this stage | — | not evaluated | listed in Q3-009 |

**Decision (D3-002).** TShark is the only pcap parser Sentinel uses, always
as an external process. Two independent reasons force external-process:
its GPL-2.0-or-later licence bars linking, and — more importantly — TShark's
dissectors parse attacker-controlled bytes with a long history of memory
safety advisories. §0 records 19 advisories fixed in 4.6.9 alone, including
CVE-2026-96419 and CVE-2026-5402, both described as possible code
execution. Running it in-process would put a known-crashy attacker-facing
parser inside the API process. Pinning at `>= 4.6.9` is therefore a security
requirement, not a version preference, and the pin is enforced by the
deployment image, not by a runtime check.

**4.2.1 The three invocations Sentinel uses.** Only flags documented in the
TShark 4.6.9 man page (TL-TSHARK) are used; no undocumented option appears
anywhere in Sentinel.

| Invocation | Flags | Used for |
|---|---|---|
| NDJSON | `-T ek -l -n` (line-buffered, no name resolution) | the primary ingest path: one JSON object per packet, which §3 streams and maps per Stage-2 SEC-B |
| Columnar | `-T fields -E separator=\t -E quote=d -e <field> … -l -n` | when a rule needs a specific field set cheaply (the `-e`/`-E` pair is documented) |
| Display filter | `-Y <filter>` combined with either of the above | bounded subsetting before parse |

`-n` (no name resolution) is mandatory: DNS resolution from a triage worker
would be an attacker-triggered network egress, which §9 forbids outright.

**4.2.2 External-process containment contract (applies to TShark, ClamAV,
ExifTool, and any future external parser).** Each spawn MUST have: a job
object with a memory ceiling and CPU time cap; a wall-clock timeout enforced
by the runner; stdin closed and stdout streamed (never a temp file both
sides share); stderr captured and truncated; no network (job object + no
proxy env + allowlist-empty); a restricted token with no SeDebugPrivilege;
working directory set to a per-job scratch directory that is deleted
afterwards; and the input delivered as a read-only path inside the
quarantine namespace (§10). A non-zero exit, a timeout, or a broken stdout
stream yields `ParserError(kind=resource_limit|internal)` and
`COMPLETED_WITH_WARNINGS` when any packet was already emitted.

| Budget | Proposed | Method |
|---|---|---|
| Wall-clock per 100 MB pcap | 120 s `PROPOSED - TO BENCHMARK` | FX-H-05 |
| Memory per TShark job | 512 MiB `PROPOSED - TO BENCHMARK` | FX-H-06 |
| Packets dropped on limit breach | counted in `coverage.dropped_packets` | FX-H-07 |

### 4.3 Zeek, Suricata, Nmap and other structured exports

| Format | Source shape | Parser | Decision + evidence |
|---|---|---|---|
| Zeek TSV logs | tab-separated with `#separator` / `#fields` / `#types` headers (TL-ZEEK) | in-process, stdlib-only | **chosen.** Bind columns by header name, never by position — the `#fields` set varies by policy, and positional binding is the classic silent-corruption bug (Stage-2 D2-019). `ts` is an epoch float documented as UTC → `timezone_source: source_documented_utc`, precision microsecond. No third-party library is needed or wanted for a format this simple. |
| Suricata EVE JSON | JSON Lines, one object per line, `event_type` selects the payload (TL-SURICATA) | in-process, `ijson` for streaming | **chosen.** ijson (BSD-3-Clause AND ISC, ID in TL-IJSON, no advisories) streams line-by-line so a 10 GB eve.json never materialises. `orjson` is deliberately **not** used for the ingest path: TL-ORJSON records two unfixed-class recursion-depth advisories (CVE-2024-27454, CVE-2025-67221) and EVE JSON is attacker-influenceable through sensor configuration. If orjson is wanted later for *serialisation of Sentinel-produced data* (not for parsing untrusted input), it is permitted with a documented depth cap; see Q3-011. |
| Nmap XML (`-oX`) | XML with a published DTD | in-process, `defusedxml` (TL-DEFUSEDXML) | **chosen.** The DTD is authoritative for element/attribute names (Stage-2 B-NMAP-DOC). defusedxml is mandatory because Nmap XML is XML and XML from an untrusted source is an entity-expansion surface; PSFL licence, trivially compatible. The library's last release is 2021-03 — flagged as frozen-but-safe in §0, not as abandoned. |
| Syslog RFC 3164 / 5424 | text lines, optional structured-data in 5424 | in-process, stdlib regex + tokenizer | **chosen.** RFC 3164 is Informational and obsolete, RFC 5424 is Proposed Standard (TL-RFC3164 / TL-RFC5424); Sentinel parses 5424 when the line matches the 5424 grammar and falls back to the 3164 grammar, recording which grammar matched in `source.format`'s sibling metadata. Both documents were opened; no third-party library is involved. |
| CEF | syslog prefix + `CEF:…\|…\|ext` (TL-CEF) | in-process, stdlib | **chosen.** The vendor PDF is the specification and was fetched directly; header and extension grammar are implemented from it, including backslash-escaped pipes in values. |
| LEEF | optional syslog prefix + `LEEF:…\|` + key=value attributes (TL-LEEF) | in-process, stdlib | **chosen.** IBM Docs HTML is the living reference (the PDF endpoint rejects automated fetch); LEEF 1.0 and 2.0 both handled, custom delimiter honoured for 2.0. |
| Windows command exports (`netstat -ano`, `sc query`, `schtasks /query`, `reg export`, `Export-Csv`, autorunsc, sigcheck) | text / CSV / .reg | in-process, stdlib `csv` (TL-CSV) | **chosen, as Stage-2 D2-010 already fixed.** CSV columns bind by header at runtime because the vendor docs do not publish the header rows (NOT_VERIFIED rows 17–19). Multi-line quoted CSV fields are handled per the module's quoting rules with `newline=''` as the docs instruct. |
| Generic JSON / NDJSON | any | in-process, `ijson` | **chosen** for the same streaming reason as EVE. |
| Tabular bulk (analyst exports, large CSV) | CSV | `pandas` (TL-PANDAS) or `polars` (TL-POLARS) | **deferred (D3-003).** Neither is needed on the ingest hot path, and polars 2.0.0 publishes only a pure-Python meta-wheel under the `polars` distribution (TL-POLARS), so the usual "native engine via wheel" assumption does not currently hold. If bulk analytics is added in Stage 4, pandas 3.x (win_amd64 wheel confirmed) is the default and polars is re-evaluated against whatever distribution the engine has moved to. |
| Log template mining (unstructured text) | free text | Drain3 (TL-DRAIN3) | **excluded for Stage 3 (D3-004).** MIT and algorithmically sound, but ~8 months without a commit and it is not needed while every supported source has a real schema. Revisit if a free-text source is added; the maintenance flag is on the record so the decision is not re-litigated from memory. |

### 4.4 Telemetry-parser summary

| `selected` | Parser id (goes in `source.parser`) | Class | Fallback |
|---|---|---|---|
| `evtx` | `evtx.rust` | in-process | `evtx.python` |
| `pcap`, `pcapng` | `tshark.ek` / `tshark.fields` | external-process | none |
| Zeek TSV | `zeek.tsv` | in-process | none |
| Suricata EVE | `suricata.eve` | in-process | `json.ijson` generic |
| Nmap XML | `nmap.xml` | in-process | none |
| syslog | `syslog.5424` / `syslog.3164` | in-process | none |
| CEF | `cef.v1` | in-process | syslog (as transport) |
| LEEF | `leef.v2` / `leef.v1` | in-process | syslog (as transport) |
| Windows exports | `winexport.<tool>` | in-process | none |
| anything else | — | — | event is not emitted; job records `unsupported_format` |

Budgets for the whole telemetry branch, all `PROPOSED - TO BENCHMARK`:
end-to-end harvest-to-DB latency p95 ≤ 5 s per 10k records (FX-H-08); per-worker
memory 256 MiB (FX-H-09); schema-validation failure rate must be 0 in the
fixture corpus (FX-H-10) — a non-zero rate is a `source_contract` defect, not
a tunable.

---
