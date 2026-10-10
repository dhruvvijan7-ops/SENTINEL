## 2. Identification Spec

Identification answers one question — *what is this byte stream?* — and is
explicitly forbidden from answering a second one — *is it dangerous?* The
output of identification is a structured record, not a routing decision made
in secret: parsers choose their input from this record, and the record is
stored so a human can see why a parser was or was not applied.

### 2.1 Three signals, no authority

| Signal | Source | Class of answer | Authority |
|---|---|---|---|
| **S1 — Container (magic)** | libmagic through python-magic (ID-PYMAGIC, ID-LIBMAGIC); pure-Python fallback `puremagic` (ID-PUREMAGIC) when the libmagic DLL is absent or the bitness mismatch described in ID-PYMAGIC-WIN occurs | level-1 physical container (`zip`, `pdf`, `msdos/mz`, `evtx`, `pcapng`, …) | authoritative for *container* only |
| **S2 — Semantic content type** | Magika (ID-MAGIKA) over a bounded head/tail sample | level-2 semantic type (`peexe`, `word-document`, `javascript`, `pdf`, `powershell`, …) | authoritative for *content type* only |
| **S3 — Hints** | multipart filename extension, `Content-Type`, agent-declared `collection_kind`, `source.format` from a telemetry harvest manifest | nothing | **advisory only, never authoritative** |

S1 and S2 are independent measurements. Sentinel never silently prefers one
over the other, and never lets S3 override either. The whole point of keeping
them separate is that extension spoofing (`invoice.pdf.exe`), magic spoofing
(a polyglot that is a valid ZIP and a valid PDF) and model error are all
ordinary occurrences in malware, and a system that collapses them into one
answer cannot express its own uncertainty.

### 2.2 The identification record

```yaml
identification:
  artifact_id: string
  size: int
  sha256: hex64
  magic:
    mime: string|null            # e.g. application/zip
    description: string|null     # libmagic's human string, e.g. "Microsoft Excel 2007+"
    encoding: string|null
    source: libmagic|puremagic|absent
    error: string|null           # libmagic failed to load, bitness mismatch, etc.
  magika:
    label: string|null           # e.g. peexe, docx, javascript
    score: float|null            # model confidence as published by Magika
    model: string|null           # model id/version Magika reports
    error: string|null
  hints:
    filename_extension: string|null
    content_type_header: string|null
    agent_declared_format: string|null
  disagreement:
    present: bool
    kind: extension_vs_magic|magic_vs_magika|extension_vs_magika|none
    detail: string|null
  polyglot_suspected: bool       # set by §2.4
  encrypted: {detected: bool, scheme: string|null, evidence: string|null}
  truncated: {detected: bool, evidence: string|null}
  selected: string               # the chosen format id, always one of the enum below
  selected_by: magic|magika|hint_fallback|size_only
  selected_confidence: high|medium|low
```

`selected` is the only value parsers read for routing. It is chosen by the
deterministic rule in §2.3 and is never produced by a human or by a
detector.

### 2.3 Selection rule (normative)

```
if size == 0:                          selected = empty            ; selected_by = size_only ; confidence = high
elif magic.mime is absent and magika.label is absent:
                                       selected = unknown         ; selected_by = size_only ; confidence = low
elif magic and magika agree on the format family:
                                       selected = family          ; selected_by = magic     ; confidence = high
elif magic present and magika absent:  selected = magic family    ; selected_by = magic     ; confidence = medium
elif magika present and magic absent:  selected = magika family   ; selected_by = magika    ; confidence = medium
elif both present and they disagree:   selected = magic family    ; selected_by = magic     ; confidence = low
                                       AND disagreement.present = true, kind = magic_vs_magika
else:                                  selected = unknown         ; selected_by = size_only ; confidence = low
```

Hints (S3) are consulted only when both S1 and S2 are absent, and even then
produce `selected_by = hint_fallback` with `confidence = low`. When the hint
disagrees with either signal, `disagreement.present` is set and the kind is
recorded; the disagreement is itself a first-class observability signal
(a `.exe` whose extension says `pdf` is worth a detector's attention, but
the detector, not the identifier, is what decides that).

**Format-family map.** `selected` uses this fixed enum; the map from a magic
mime or Magika label into it is configuration data (YAML), not code, so new
labels can be absorbed without a rebuild.

| `selected` | Typical magic | Typical Magika label | Routes to |
|---|---|---|---|
| `empty` | — | — | nothing (rejected at gate) |
| `evtx` | `application/x-msdownload`-adjacent / vendor-specific | — | EVTX parser (§4) |
| `pcap` / `pcapng` | `application/vnd.tcpdump.pcap`, pcapng magic `0a0d0d0a` | `pcap`, `pcapng` | TShark parser (§4) |
| `ole2` | `application/x-ole-storage` | `msi`, `ole`, `cfb` | OLE triage (§5) |
| `ooxml` | `application/zip` + `[Content_Types].xml` | `docx`, `xlsx`, `pptx`, `docm`, … | OOXML triage (§5) |
| `pdf` | `application/pdf` | `pdf` | PDF triage (§5) |
| `rtf` | `text/rtf` | `rtf` | RTF triage (§5) |
| `onenote` | — | `one` | OneNote triage (§5) |
| `pe` | `application/x-dosexec` | `peexe`, `pedll` | PE triage (§5) |
| `elf` | `application/x-executable` | `elf` | informational only (Sentinel is Windows-first) |
| `macho` | `application/x-mach-binary` | `macho` | informational only |
| `dotnet` | (PE + CLR directory) | `dotnet` | PE + .NET triage (§5) |
| `lnk` | `application/x-ms-shortcut` | `windows-shortcut` | LNK triage (§5) |
| `chm` | `application/x-chm` | `chm` | metadata only (§9) |
| `script` | `text/x-…` | `powershell`, `batch`, `javascript`, `vbscript`, `python`, `shell` | script triage (§5) |
| `text` | `text/plain` | `text`, `markdown`, `json`, `csv`, `xml` | bounded text triage (§5) |
| `image` | `image/*` | `jpeg`, `png`, `gif`, `webp`, `bmp`, `tiff`, `ico`, `svg` | image triage (§5) |
| `archive` | `application/zip`, `application/x-7z-compressed`, `application/x-rar`, `application/gzip`, … | `zip`, `7z`, `rar`, `gzip`, `bzip2`, `xz`, `tar` | archive triage (§10) |
| `installer` | — | `nsis`, `inno`, `msi` | metadata only in Stage 3 (§5, Q3-016) |
| `diskimage` | `application/x-vmdk`, … | `vmdk`, `vhd`, `iso` | not triaged in Stage 3 (§9) |
| `unknown` | anything else | anything else | identification-only; no parser applied; `analysis_status: unsupported_format` |

The OOXML row is important: a `.docx` *is* a ZIP container, so S1 says
`archive`/`zip` and S2 says `docx`. Agreement at the *family* level is
therefore computed over a declared equivalence (`ooxml ⊂ archive` for
container purposes) and the more specific family wins. This equivalence is
configuration data with the same precedence rule.

### 2.4 Polyglots, truncation and encryption pre-detection

**Polyglot suspicion (not detection).** Identification sets
`polyglot_suspected = true` when any of the following holds. It never claims
to have proven a polyglot; it claims that more than one format's signature
was satisfied.

1. libmagic's description names two formats, or Magika returns a label whose
   family differs from magic's family *and* the disagreement kind is
   `magic_vs_magika`.
2. A ZIP container (central directory present) also begins with `%PDF-` at
   offset 0, or contains a member named `%PDF`/`%!/` at offset 0.
3. A PE whose first section's raw data begins with a magic of another family
   (`%PDF-`, `PK\x03\x04`, `\x1f\x8b`).
4. An image whose payload contains a complete ZIP central directory
   (the "image with an embedded document" family).

The triage stage then runs **both** family parsers (§5) rather than choosing
one, under the recursion and byte budgets of §10.

**Truncation.** A stream is flagged truncated when a container declares a
size larger than the bytes available (ZIP central-directory offsets that
extend past EOF; PE section `PointerToRawData + SizeOfRawData` past EOF;
PDF `startxref` pointing past EOF). Truncation is *not* an error: harvested
artifacts are frequently head-truncated by collection limits, and the correct
response is to parse what is present, set
`analysis_status: truncated` (§8), and put the evidence string in the
record.

**Encryption pre-detection.** §7 owns the policy; identification only
detects and labels. Detection is by structure, never by guessing:
OOXML `EncryptionInfo` part, OLE `EncryptedPackage` stream, PDF
`/Encrypt` in the trailer dictionary, ZIP general-purpose bit 0 set on any
entry, 7z header-encoded streams, RAR encrypted headers. When detected,
`selected` is still the container family (so the right parser gets a chance
to read the *structure* around the encryption), and
`encrypted.detected = true` with the scheme name.

### 2.5 Identification budgets

| Item | Proposed value | Method |
|---|---|---|
| Bytes sampled for magic | first 8 KiB + last 4 KiB `PROPOSED - TO BENCHMARK` | FX-C-01…FX-C-05 (files whose magic sits past 8 KiB) |
| Bytes sampled for Magika | Magika's own bounded sample (up to the model's window) `PROPOSED - TO BENCHMARK` | FX-C-06…FX-C-10 |
| Wall-clock per identification | 200 ms p95 `PROPOSED - TO BENCHMARK` | FX-C-11 |
| Identification memory ceiling | 32 MiB `PROPOSED - TO BENCHMARK` | FX-C-12 |

Identification MUST NOT read the whole artifact to answer; anything that
requires whole-file reading is triage (§5), not identification.

### 2.6 Licence and packaging notes for the identification stack

| Component | SPDX | Distribution class | Note |
|---|---|---|---|
| libmagic | 2-clause BSD text, GitHub metadata `NOASSERTION` (ID-LIBMAGIC) | in-process via binding | the `NOASSERTION` metadata flag is a packaging artifact, not a licence change; the COPYING text is the licence |
| python-magic | MIT + libmagic LEGAL.NOTICE clause (ID-PYMAGIC) | in-process | needs a native libmagic; on Windows the DLL bitness must match the interpreter (ID-PYMAGIC-WIN) |
| puremagic | MIT (ID-PUREMAGIC) | in-process | pure Python, no DLL; the designated Windows fallback |
| python-magic-bin | MIT but stale since 2017 and explicitly deprecated (ID-MAGICBIN) | **not used** | superseded upstream; shipping a 2017 DLL is not defensible |
| Magika | Apache-2.0 (ID-MAGIKA) | in-process | the ONNX model ships inside the repository and no separate model licence file exists; treated as Apache-2.0 by inclusion — see Q3-006 for the legal confirmation |

No GPL/AGPL component is in the identification path, so Stage-1 D-008 is
satisfied without an external-process workaround.

---
