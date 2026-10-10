## 6. Artifact Graph Model

Triage never thinks about "a file"; it thinks about a **graph** whose root is
the uploaded artifact and whose edges are containment or reference. The graph
exists because a single sha256 is not a sufficient unit of analysis: the
interesting object is often three levels down (`invoice.docx → word/embeddings/oleObject1.bin →
PE section .text`) and the analyst needs the path, not just the leaf.

### 6.1 Node types

| Node type | Identity | Produced by |
|---|---|---|
| `artifact` | `sha256` of the bytes (the root is the upload; children are extracted bytes) | gate (§1.7), extractor output |
| `archive_member` | (parent artifact sha256, member path) → **structural id**; the child artifact identity is the member's own sha256 once materialised | §10 |
| `ooxml_part` | (parent sha256, part name) | §5.1 |
| `ooxml_relationship` | (parent sha256, part name, relationship id) | §5.1 |
| `ole_storage` / `ole_stream` | (parent sha256, storage path, stream name) | §5.2 |
| `pdf_object` | (parent sha256, object number, generation) | §5.3 |
| `pdf_stream` | (parent sha256, object number, generation) | §5.3 |
| `pe_section` | (parent sha256, section name/index) | §5.5 |
| `pe_resource` | (parent sha256, resource type, name, language) | §5.5 |
| `pe_import` | (parent sha256, dll, name/ordinal) | §5.5 |
| `lnk_target` | (parent sha256, target path) — a *reference* node, not an extracted artifact | §5.4 |
| `script_reference` | (parent sha256, locator, target string) | §5.6 |
| `external_relationship` | (parent sha256, part, relationship id) | §5.1 |
| `zone_identifier` | (parent sha256) — carries the MotW facts | §1.4 / agent upload |
| `signature_node` | (parent sha256, signer, digest) | §5.5 |

A node is either **materialised** (its bytes exist in the content-addressed
store and it has a sha256) or **structural** (it is a position inside a parent
and has no independent bytes — `pe_import`, `ooxml_relationship`,
`pdf_object` for dictionary-only objects, `lnk_target`). Structural nodes are
how the graph records *things a file points at* without pretending Sentinel
possesses the target.

### 6.2 Edge types

| Edge | Meaning | Cardinality |
|---|---|---|
| `contains` | parent bytes physically embed child bytes | 1 → N |
| `extracted_from` | inverse of `contains` (materialised child → parent) | N → 1 |
| `references` | parent names or points at a target without embedding it (`lnk_target`, `external_relationship`, `html.external_resource.uri`, `script_reference`, `pdf.hyperlink.uri`, `ooxml.relationship.external_target`) | 1 → N |
| `derived_from` | a deobfuscated/re-encoded rendering of the same content (base64-decoded blob → the script that carried it) | N → 1 |
| `signed_by` | parent → `signature_node` | 0..1 |
| `motw_on` | parent → `zone_identifier` | 0..1 |
| `same_bytes_as` | two distinct structural paths that hash identically (dedup aliasing) | N ↔ N |

`references` edges are **never followed**. They are recorded, surfaced and
detected upon; the target is never fetched, never resolved, never opened. This
is the structural expression of §9.6.

### 6.3 Traversal limits (normative)

All values `PROPOSED - TO BENCHMARK`; each has a §11 fixture.

| Limit | Proposed | Rationale / fixture |
|---|---|---|
| `max_depth` | 8 | nested-archive chains; FX-B-30 |
| `max_nodes` per root | 10,000 | FX-B-28 |
| `max_materialised_bytes` per root | 256 MiB total expanded | FX-B-01…FX-B-10 |
| `max_edges_per_node` | 1,000 | FX-F-11 |
| `max_wall_clock_per_root` | 60 s | FX-G-20 |
| `max_node_bytes` | 64 MiB | FX-B-02 |

**Termination rules.** A node is not expanded a second time if its sha256 has
already been expanded in this root (cycle and shared-subtree protection: a
self-referential archive, or the same DLL embedded in four places, costs one
expansion). Structural nodes are never re-expanded. When a limit is hit the
graph is *closed, not discarded*: what was built is kept, the node that could
not be expanded gets `analysis_status: resource_limit_exhausted` (§8), and
the parent gets `COMPLETED_WITH_WARNINGS` (§3.3).

**Persistence.** The graph is stored relationally:
`artifact_node(artifact_id, root_artifact_id, node_type, structural_id,
sha256|null, parent_node_id, edge_type, depth, size, analysis_status)` and
`artifact_edge(from_node_id, to_node_id, edge_type, locator)`. Every row
carries `tenant_id`, `workspace_id`, `run_id` (Stage-1 D-012). The root
artifact id is the join key back to §1.6 and to telemetry through
`source.file_id`.

---

## 7. Encrypted-File Policy

**Governing sentence: encrypted content is not analyzed, and that fact is
reported as a fact, never as a pass.**

### 7.1 Detection (normative, structural only)

| Family | Signal | Evidence |
|---|---|---|
| OOXML | an `EncryptionInfo` part, or an `EncryptedPackage` part, or any ZIP member with general-purpose bit 0 set | §5.1 / ARC-ZIPFILE |
| OLE2 | an `EncryptedPackage` stream, or the `WordDocument`/`Workbook` encryption FIB flags | §5.2 |
| PDF | an `/Encrypt` entry in the trailer dictionary; scheme distinguished by `/Filter`, `/V`, `/R`, `/Length`, `/CF` | §5.3 / DOC-QPDF (qpdf's encryption docs describe the standard security handler) |
| ZIP | general-purpose bit flag 0 (traditional) or the AE-x extra field (AES) | ARC-ZIPFILE |
| 7z | header-encrypted or per-stream encryption, read from the 7z header | ARC-LIBARCHIVE |
| RAR | the encrypted-headers / encrypted-data flags in the archive header | ARC-RARFILE |
| BitLocker / VHD encrypted / EFS | **not detected, not analyzed, not mounted** — `not_analyzed_by_policy` | §9 |

Detection never guesses. A password-guessing attempt against a container is
itself a resource-exhaustion vector and produces no forensic value.

### 7.2 Handling

1. Structure *around* the encryption is still triaged: an encrypted ZIP's
   member names, sizes and compression methods are all readable from the
   central directory and are emitted as `archive_member` facts. That is often
   enough to answer the analyst's question ("is this a password-protected
   Office attachment?").
2. Decryption is attempted **only** when (a) an operator has configured a
   password list for the workspace, (b) the container's scheme is one
   `msoffcrypto-tool` or qpdf supports, and (c) the attempt is within the
   budget below. Password lists are configuration data; they are never
   logged, never returned in API responses, and never written into facts —
   facts record only `password_supplied: true|false`.
3. Decrypted plaintext is written to the quarantine namespace (§10), is
   re-identified (§2) — because a decrypted payload is frequently a
   *different* family than the container — and is triaged as a child node of
   the encrypted parent. It is never promoted to the root artifact.
4. Every attempt, successful or not, emits
   `*.encryption.password_supplied` and increments a counter on the parent.
   Repeated failures across artifacts from one source are themselves
   detectable behaviour, which is a detector's business, not triage's.

| Budget | Proposed | Method |
|---|---|---|
| Password attempts per artifact | 3 `PROPOSED - TO BENCHMARK` | FX-D-20…FX-D-25 |
| Wall-clock per decryption attempt | 5 s `PROPOSED - TO BENCHMARK` | FX-D-26 |
| Plaintext size after decryption | capped by §10's `max_materialised_bytes` | FX-B-05 |
| Password list size | 32 entries `PROPOSED - TO BENCHMARK` | FX-D-27 |

### 7.3 Output

Encrypted artifacts always end in one of these states (§8 defines the
vocabulary):

| Situation | `analysis_status` |
|---|---|
| detected, not attempted (no password list configured) | `encrypted_content_not_analyzed` |
| attempted, wrong password / unsupported scheme | `encrypted_content_not_analyzed` (plus `COMPLETED_WITH_WARNINGS`) |
| decrypted successfully, child triaged | parent `analyzed` with `encryption.password_supplied: true`; child carries its own status |
| encrypted container that is also structurally damaged | `corrupted` |

The words `clean` and `safe` are not in this vocabulary, and §8 explains why.

---

## 8. Triage Output Semantics

### 8.1 The verdict ban

Triage does not produce verdicts. It produces **facts**, **flags** and an
**analysis status**. There is no field, enum value, log line or API response
in Sentinel in which a triage result may be `clean`, `safe`, `ok`, `benign`,
`whitelisted`, `malicious` or `infected`. Those words are banned from the
triage vocabulary by name, and the ban is a review-blocking rule: a patch
that introduces one is rejected.

The reason is not squeamishness. "Clean" is a claim about the world that no
static analysis can make; the only honest static outputs are "no *observed*
indicator of the classes we check for, in the portion we could analyze, at
the time we checked" — and that sentence has four escape hatches (encrypted,
truncated, unsupported, resource-limited) which is exactly what
`analysis_status` captures. A product that says "clean" will be quoted as
saying "safe", and will be wrong.

### 8.2 `analysis_status` (normative enum)

| Value | Meaning | Set when |
|---|---|---|
| `analyzed` | every extractor applicable to this artifact ran to completion within budget | default success |
| `partial` | some extractors ran, some did not | any `COMPLETED_WITH_WARNINGS` |
| `encrypted_content_not_analyzed` | encryption detected (§7) | §7.3 |
| `unsupported_format` | identification returned `unknown`, or no extractor accepts the format | §2.3 |
| `truncated` | container declares more data than is present | §2.4 |
| `corrupted` | container is structurally invalid before any extractor could proceed | parser failed at offset 0 |
| `resource_limit_exhausted` | a §6.3 or §5 budget was hit | any limit breach |
| `blocked_by_policy` | an active-content prohibition (§9) stopped a step that would otherwise have run | §9 |
| `not_analyzed_by_policy` | the family is out of Stage-3 scope (disk images, NSIS/Inno unpacking) | §5.9 |
| `dependency_missing` | an optional tool the operator enabled is not installed | §3.3 |
| `error` | an unexpected internal failure | pipeline |

`partial` is the most common real-world value and must be surfaced as a
first-class state in the UI, not hidden behind a spinner. Every non-`analyzed`
status carries a machine-readable `reasons[]` list with the same entries as
`ParserResult.errors` (§3.3).

### 8.3 What triage emits

| Output | Type | Consumed by |
|---|---|---|
| `Facts` | §12 fact stream, stored per artifact | UI/API; fact-to-finding rules |
| Canonical events in `document`, `archive_member`, `executable`, `artifact` | `canonical-event/v1` (Stage-2 envelope, reserved categories) | detectors — this is how artifact knowledge reaches detection without breaking the "detectors consume only canonical events" invariant |
| `artifact_finding` events | `canonical-event/v1` | detectors and the alert stream |
| Graph | §6 | UI/API, and `archive_member`/`executable` events reference node ids in `sources[]` |
| `analysis_status` + `reasons[]` | the record in §1.6 | UI/API, policy engine |

`artifact_finding` is the only channel through which a *scanner* (YARA-X,
capa, ClamAV, or a fact-to-finding rule) may speak, and its fields are
defined by Stage 2: `artifact_type`, `artifact_identity`, `finding`,
`evidence`, `scanner`, `confidence`. `finding` is a rule id or a
configuration-defined rule name — never a free-text verdict — and `evidence`
quotes the fact(s) that caused it, with locators.

### 8.4 Confidence vocabulary (three values, not a number)

| Value | Meaning |
|---|---|
| `observed` | the extractor read it directly from the bytes |
| `derived` | Sentinel computed it (a ratio, a hash of a sub-range, a decoded blob) |
| `third_party` | an external scanner asserted it (YARA rule hit, ClamAV signature) |

A confidence number is not published: a numeric confidence implies a
calibration that no Stage-3 component has. `Magika`'s own model score is
preserved as a fact value (`identification.magika.score`) and is explicitly
*not* reinterpreted as a Sentinel confidence.

---

## 9. Active-Content Prohibitions

These prohibitions bind **every** component of Sentinel that touches an
uploaded artifact or any byte extracted from one, in every process, including
external-process tools and optional enrichers. They are not defaults that can
be flipped by configuration; a change to this section is a security design
change and requires the same review as the schema.

### 9.1 No rendering, ever

| Prohibited | Why |
|---|---|
| Rasterising a PDF page (`get_pixmap`, PDFium render, Poppler `pdftoppm`) | rendering executes a font stack, a colour-management stack and a graphics stack over attacker bytes |
| Opening a document in Word/Excel/PowerPoint/LibreOffice, including headless | macro execution, DDE, OLE activation, template fetch |
| HTML/CSS/JS rendering in a browser, WebKit, Chromium embedded, or any "preview" control | script execution by definition |
| Thumbnailing via shell preview handlers or IThumbnailProvider | runs third-party in-process handlers |
| CHM help rendering; MHTML assembly; XPS/OXPS viewing | same class |

The excluded libraries of §5.3 (PyMuPDF, pypdfium2) and any future library
whose primary advertised capability is rendering are excluded on this ground
independently of their licence.

### 9.2 No macro execution and no interpretation

| Prohibited | Note |
|---|---|
| Running VBA, XLM, JS, JScript, VBS, PowerShell, Python, shell, HTA, WSF, MSI custom actions, NSIS/Inno scripts | by definition |
| Excel COM automation (`win32com`, `xlwings`) | executes Excel, which executes the macro |
| LibreOffice `--convert-to` on a macro-bearing document | conversion runs macros |
| **XLMMacroDeobfuscator (DOC-XLM)** | excluded from the default build. It is an *emulator*, and its own README describes interpreting macros "without fully performing the code" — but an interpreter that evaluates enough XLM to reach a URL is still evaluating attacker-controlled logic. It is permitted only inside the containment of §9.8 if an operator enables it, and the enablement is recorded as a policy exception. |
| Any "sandbox" that runs the content with the goal of observing behaviour | behaviour observation is a dynamic-analysis product, not this one |

`oletools`' `olevba` is **not** in this list: it extracts and classifies VBA
source text statically. That distinction (read bytes vs. evaluate meaning) is
the whole boundary.

### 9.3 No document interpreters of any kind

Prohibited: Word/Excel/PowerPoint import filters, Visio, Project, AutoCAD,
Mathematica, MATLAB, R, notebook runtimes, TeX engines, image editors,
media players, archive "test and repair" modes that rewrite files, database
engines opening an uploaded DB file, virtual-machine monitors, and anything
else whose function is to *execute the format's semantics*.

### 9.4 No network egress from triage

Triage workers run with an empty network allowlist. This is not a firewall
rule that happens to be restrictive; it is a property of the worker's
identity and job object. Consequences that are deliberate:

- Signature databases (ClamAV, YARA rule feeds, VT lookups, certificate
  revocation, timestamp authority) are **staged out-of-band** and mounted
  read-only into the worker. A worker never downloads a signature.
- Authenticode **verification** is therefore impossible offline, so Sentinel
  reports signature *presence and identity* and sets
  `signature.status: unverified_offline` (§5.5) rather than implying a chain
  was validated.
- URLs, UNC paths, external relationships and `TargetMode="External"`
  targets are recorded as strings and never dereferenced.

### 9.5 No code-loading of the artifact into Sentinel's own process

Importing a Python package from an uploaded wheel, `dlopen`/`LoadLibrary` of
an uploaded DLL, loading an uploaded font or codec, registering an uploaded
COM class, `importlib` on any artifact-derived path, and unpickling any
artifact-derived bytes are all prohibited. The pickle prohibition extends to
dependencies: nothing in the ingest path may call `pickle.load`,
`numpy.load(allow_pickle=True)`, `torch.load` without `weights_only`, or any
equivalent, on data derived from an artifact.

### 9.6 No reference dereferencing

`references` edges (§6.2) are terminal. Nothing in Sentinel performs DNS,
HTTP, SMB, LDAP, Kerberos, FTP, TFTP or any other lookup on a value that came
from an artifact. This includes "just resolving a hostname to see if it is
malformed" and "checking whether an UNC path exists".

### 9.7 No destructive or state-changing operations

Prohibited on artifact-derived paths: deleting, renaming, chmod/chown,
setting an ACL, setting a zone identifier, creating an ADS, writing to a
registry key named by an artifact, creating a service or scheduled task named
by an artifact, printing, sending to the Recycle Bin, and touching any path
outside the quarantine namespace. Extraction (§10) is the only write Sentinel
performs, and it writes only inside a fresh per-root directory that it
created.

### 9.8 Containment requirements for anything that would break 9.1–9.7

If a future component needs a prohibited capability (a rendered preview, an
XLM emulator, a signature service with egress), it may only be added when
**all** of the following are true, and the exception is recorded in the
decision log:

1. it runs as a **separate process**, never in the API or worker process;
2. the process is under a job object with a memory ceiling, a CPU time cap
   and a wall-clock timeout;
3. the process runs as a restricted token / AppContainer with no
   `SeDebugPrivilege`, no ability to create processes, and a read-only view
   of the quarantine namespace;
4. network egress is blocked at the process level, not merely at the
   perimeter;
5. its stdout is a pipe (never a shared temp file), its stderr is captured
   and truncated, and its exit status is checked;
6. the input is delivered as a read-only path under the quarantine root and
   is deleted after the run;
7. the fixture catalogue (§11) has an entry for the new component, and the
   Stage-4 benchmark run covers it;
8. the licence review (§13) is redone for the new component.

This clause exists so that the prohibition list has a defined, expensive
escape route rather than an informal one. Nothing in the Stage-3 default
build invokes it.

---
