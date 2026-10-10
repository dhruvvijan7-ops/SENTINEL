## 12. Facts-to-Canonical Mapping

This section is the contract between the content extractors of §5 and the
canonical event model of Stage 2. It exists so that the two can change
independently: extractors may adopt a new library, a new format, or a new
fact, without touching the schema; and the schema may gain a field without
rewriting extractors.

### 12.1 The rule

> **Extractors emit facts. They never emit canonical events, never emit
> findings, and never emit a verdict.**

A fact is a typed observation about bytes: *this relationship's target is
external*, *this action key is OpenAction*, *this import table names
WinExec*, *this entry's expansion ratio is 1,412*. A fact carries no
adjective. The three transformations that turn facts into something a
detector can use are separate components with separate reviews:

1. **Fact → canonical event** (§12.3): a deterministic mapper populates the
   categories Stage 2 reserved for this stage.
2. **Fact → finding** (§12.4): fact-to-finding *rules* (configuration data,
   same shape philosophy as the Stage-2 Sigma pipelines) emit
   `artifact_finding` events. Rules are content, reviewed and attributed
   exactly like detection content (Stage-1 D-004).
3. **Finding/event → detection**: ordinary detectors over canonical events.

Nothing in step 1 or 2 lives inside an extractor. That is what makes the
"no hardcoded detections" invariant enforceable by code review: an extractor
PR that contains an `if ratio > 1000: flag()` is rejected on sight, while the
equivalent rule lives in a reviewed YAML file whose diff is obviously a
detection change.

### 12.2 Fact naming convention

```
<namespace>[.<scope>].<name>
```

- **namespace** — one of the fixed set below, matching a format family from
  §5. Lowercase, snake_case.
- **scope** — optional, names the sub-object (`relationship`, `action`,
  `section`, `stream`, `entry`, `part`, `member`, `exif`, `header`, …).
- **name** — the observation, snake_case, singular for per-object facts
  (one fact instance per object) and plural for aggregates.

**Value types** (the `value_type` field of `Fact`): `string`, `int`,
`float`, `bool`, `timestamp`, `enum`, `list`, `bytes_hex`, `state`. The
`state` type exists so a fact can honestly say the source was unparsable,
using the same vocabulary as Stage 2 (`null`, `unknown`, `invalid`,
`conflicting`, `inferred`) — facts are not schema events, so they may carry
a bare `None`, but when the *reason* matters the fact's value is a state
object with `$note`.

**Namespace registry (normative, closed set for Stage 3):** `archive`,
`ooxml`, `ole`, `pdf`, `rtf`, `onenote`, `chm`, `lnk`, `hta`, `pe`, `elf`,
`macho`, `dotnet`, `script`, `html`, `mhtml`, `image`, `msi`, `text`,
`json`, `xml`, `identification`, `motw`, `encryption`, `signature`,
`scanner`.

Adding a namespace is a Stage-3 decision (recorded in §13), not an extractor
improvisation.

### 12.3 Fact → canonical event mapping

The mapper is a pure function of (facts, artifact record, graph node). Its
output uses only categories Stage 2 defined: `document`, `archive_member`,
`executable`, `artifact`, `artifact_finding`, plus the envelope. Stage-2
D2-018's reserved categories are filled here for the first time.

| Fact family | Canonical category | `event.type` | Payload fields populated | Notes |
|---|---|---|---|---|
| `ooxml.metadata.*`, `ole.metadata.*`, `pdf.metadata.*`, `rtf.*` document properties | `document` | `document_metadata_observed` | `document.path` (from `original_filename`, marked inferred), `.title`, `.author`, `.created`, `.modified`, `.last_saved_by`, `.revision_number`, `.page_count`, `.word_count` | one event per artifact, only when at least one metadata fact exists |
| `archive.member.*` (per member) | `archive_member` | `archive_member_listed` | `archive_member.archive_path`, `.member_path`, `.size`, `.compressed_size`, `.encrypted`, `.member_type`, `.hashes` | one event per member, subject to `max_nodes`; the Stage-2 object's `member_type` takes the member's `identification.selected` |
| `archive.entry.ratio`, `archive.member_count`, `archive.total_declared_uncompressed` | `artifact_finding` (via §12.4 rules) | — | `finding: expansion_ratio_high`, `evidence` quoting the ratio | **not** a verdict; the rule decides whether a ratio is noteworthy |
| `pe.*`, `elf.*`, `macho.*`, `dotnet.*` header facts | `executable` | `executable_profiled` | `executable.path`, `.format`, `.architecture`, `.compile_time`, `.subsystem`, `.product`, `.company`, `.description`, `.original_file_name`, `.file_version`, `.hashes`, `.signature` | one event per executable node; `format` from §2 identification, not from the filename |
| `pe.import.*`, `pe.export.*`, `pe.section.*`, `pe.resource.*`, `pe.overlay.*` | — (stay as facts) | — | — | too high-cardinality to be events; reachable by rules and by the UI |
| identification facts (§2 record) | `artifact` | `artifact_identified` | `artifact.type: file`, `.identity` (sha256), `.path` (display_name, inferred), `.attributes` (a compact string: format, size, encryption, MotW zone) | one event per artifact, always emitted — this is the artifact's canonical "I exist and I am this" statement |
| `motw.*` | `artifact_finding` (via rules) | — | `finding: internet_zone_origin`, `evidence: zone_id=3` | MotW is an origin fact; whether it matters is a rule's call |
| `encryption.*` | folded into `artifact.attributes` + `analysis_status` | — | — | §7.3 owns the status; no separate event |
| `signature.*` | `executable.signature` / `file.signature` | — | `signature.signed`, `.signer`, `.status` (`unverified_offline` per §5.5) | |
| `script.*`, `html.*`, `mhtml.*`, `image.*` | `artifact_finding` (via rules) | — | — | these families have no reserved canonical payload; rules may raise findings, facts stay available |
| anything with no mapping | — (stays a fact) | — | — | the default. A fact with no canonical home is **not** an error; it is the common case |

**Envelope values for every mapper-produced event:** `event.derived_by:
sentinel` in all cases (the source here is an uploaded file, not a telemetry
taxonomy), `event.action` = `observe`/`identify`/`list`/`profile`,
`event.outcome: success` unless the extractor failed, `source.format` =
`identification.selected`, `source.record.type` = `event_record` for
event-shaped things and `byte_offset`/`part` where a locator exists,
`source.parser` = the extractor id, `raw` = the fact bundle that produced the
event (losslessness for artifact events is carried by the fact stream rather
than by a source record, so `raw` holds the JSON-serialised facts — this is a
deliberate, documented adaptation of Stage-2 D2-012), `unmapped[]` = facts
the mapper chose not to place.

### 12.4 Fact-to-finding rules

Shape (mirrors the Stage-2 Sigma-pipeline-as-configuration decision, D2-014):

```yaml
# artifact_finding_rules.yaml   (configuration data, not code)
rules:
  - id: AF-001
    title: Office document declares an external relationship target
    when:
      all:
        - fact: ooxml.relationship.external_target
          exists: true
        - fact: identification.selected
          in: [ooxml]
    emit:
      artifact_type: file
      finding: external_relationship_declared
      confidence: observed
      evidence_facts: [ooxml.relationship.external_target, ooxml.relationship.type]
    severity_hint: informational      # a hint for the UI; detectors own real severity
    attribution: >-
      Rule authored for Sentinel (DRL-compatible content, Stage-1 D-004).

  - id: AF-002
    title: PDF declares an OpenAction
    when:
      all:
        - fact: pdf.action.open_action
          exists: true
    emit:
      artifact_type: file
      finding: pdf_open_action_declared
      confidence: observed
      evidence_facts: [pdf.action.open_action]

  - id: AF-003
    title: Archive entry expansion ratio above the configured threshold
    when:
      any:
        - fact: archive.entry.ratio
          gte: 100                     # operator-configurable; the number is content, not code
        - fact: ooxml.part.ratio
          gte: 100
    emit:
      artifact_type: file
      finding: high_expansion_ratio
      confidence: derived
      evidence_facts: [archive.entry.ratio, ooxml.part.ratio]

  - id: AF-004
    title: PE imports a process-execution API
    when:
      any:
        - fact: pe.import.name
          in_list_ref: lists/exec_apis.yaml     # WinExec, ShellExecuteA, CreateProcessW, ...
    emit:
      artifact_type: file
      finding: imports_process_execution_api
      confidence: observed
      evidence_facts: [pe.import.name, pe.import.dll]

  - id: AF-005
    title: File carries the mark of the web
    when:
      all:
        - fact: motw.zone_id
          in: [3, 4]
    emit:
      artifact_type: file
      finding: internet_zone_origin
      confidence: observed
      evidence_facts: [motw.zone_id, motw.referrer_url]
```

Every rule emits `artifact_finding` canonical events, which is why detectors
never need to see a raw fact. Rule ids are stable, rules are attributed per
Stage-1 D-004, and rule content changes go through the same review as Sigma
content.

### 12.5 Worked mappings for the four required example fact names

| Required example | Full fact name | Type | Emitted by | Canonical destination | Via rule |
|---|---|---|---|---|---|
| `ooxml.relationship.external_target` | `ooxml.relationship.external_target` | `string`, one per external relationship | §5.1 relationship walk (`TargetMode="External"`) | no direct event; `unmapped[]` on the `document` event if not placed | AF-001 |
| `pdf.action.open_action` | `pdf.action.open_action` | `string` (the action dictionary serialised compactly) | §5.3 trailer/page-tree walk | no direct event | AF-002 |
| `pe.import` | `pe.import.name` (+ `pe.import.dll`, `pe.import.ordinal`) | `string`, one per import | §5.5 pefile import walk | no direct event | AF-004 |
| `archive.entry.ratio` | `archive.entry.ratio` | `float` (aggregate) + `archive.member.ratio` per member | §5.8 / §10 listing | no direct event | AF-003 |

The pattern is deliberate and uniform: **high-cardinality, low-semantics
observations stay facts; the canonical event layer receives the low-cardinality
structural summaries; and any statement about meaning is a rule.**

### 12.6 Where facts live

Facts are stored in a sidecar relation `artifact_fact(artifact_id,
node_id, namespace, name, value_json, value_type, locator, confidence,
tenant_id, workspace_id, run_id)` — same tenant/workspace/run discipline as
every other row (Stage-1 D-012). Three consumers:

1. the UI/API, which renders them;
2. the fact-to-finding rule engine (§12.4), which reads them and writes
   `artifact_finding` events;
3. replay: because facts are immutable and keyed by artifact, re-running a
   rule set against an existing artifact produces the same findings without
   re-triaging the bytes.

The "detectors consume only canonical events" invariant is therefore intact:
the only path from a fact to a detector is through an `artifact_finding`
event.

### 12.7 Losslessness and the `unmapped[]` adaptation

Stage-2 D2-012 requires lossless `raw` plus `unmapped[]`. For artifact
events there is no "source record" other than the artifact itself, so the
mapper records the fact bundle in `raw` and any fact it declined to place in
`unmapped[]`. The property that matters — *nothing an extractor observed is
silently dropped* — is preserved. A fact that is dropped only because a rule
did not fire is still in `artifact_fact`.

---
