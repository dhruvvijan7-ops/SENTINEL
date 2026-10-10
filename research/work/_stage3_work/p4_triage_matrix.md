## 5. Artifact Triage Decision Matrix

Artifact triage is the "File Intelligence" layer: given one uploaded byte
stream, produce facts (§12), a bounded set of canonical events in the
categories Stage 2 reserved for this purpose, and an `analysis_status` (§8).
It is static-only (§9), bounded (§10), and never renders a verdict.

Per family, the matrix records: what is extracted; the concrete tools and
their licence class; which facts are emitted; the recursion policy; the
budget; and the evidence id. Fact names are the normative namespace from §12
— they are the contract, the tools are swappable behind it.

### 5.1 Office — OOXML (.docx/.xlsx/.pptx/.docm/.xlsm/.pptm and siblings)

| Item | Specification |
|---|---|
| Identify | `selected: ooxml` (§2.3 equivalence rule: ZIP container + OOXML content types) |
| Container walk | Python stdlib `zipfile` (ARC-ZIPFILE) — **in-process**. The standard library is authoritative for the central directory, per-member sizes, compression method and the general-purpose bit flags (including flag 0 = encrypted, §7). |
| Part selection | `[Content_Types].xml` first, then the parts named by it; the OPC relationship graph is walked through `*.rels` |
| XML parsing | `defusedxml` (TL-DEFUSEDXML) for every XML part — OOXML parts are XML and the "billion laughs" hazard is called out by the openpyxl docs themselves (DOC-OPENPYXL) |
| Workbook/word/ppt metadata | `openpyxl` in `read_only=True` mode for spreadsheets (DOC-OPENPYXL: lazy loading, requires `wb.close()`); `python-docx` for wordprocessing (DOC-DOCX); `python-pptx` for presentations (DOC-PPTX). All three are parse-only, MIT/MIT-Expat, in-process. |
| Macro text (static) | `oletools` `olevba` (DOC-OLETOOLS) for VBA storage extraction and scoring. **Static extraction only** — oletools reads and classifies; it does not execute. |
| XLM macros | detected by oletools' XLM path; the *deobfuscation emulator* is **excluded from the default build** (§9.3) |
| Encryption | see §7; `msoffcrypto-tool` (DOC-MSOFFCRYPTO, MIT) is the decryptor, gated behind the password policy |
| External enrichment | none in the default build (Tika excluded — see D3-010) |

**Facts emitted (normative names):**

| Fact | Type | Meaning |
|---|---|---|
| `ooxml.container.member_count` | int | members in the ZIP part table |
| `ooxml.container.encrypted` | bool | any member carries general-purpose bit 0, or `EncryptionInfo` present |
| `ooxml.content_type` | enum | `wordprocessingml`, `spreadsheetml`, `presentationml`, `macroEnabled.*`, other |
| `ooxml.part.name` | string (list-valued, one fact per part) | part path inside the container |
| `ooxml.part.size_compressed` / `ooxml.part.size_uncompressed` | int | per part |
| `ooxml.part.ratio` | float | `size_uncompressed / max(1, size_compressed)` — the zip-bomb signal, per member |
| `ooxml.relationship.target` | string (per relationship) | raw `Target` attribute |
| `ooxml.relationship.external_target` | string (per relationship) | `TargetMode="External"` relationships only — **the canonical drive-by signal** |
| `ooxml.relationship.type` | string | relationship `Type` URI suffix |
| `ooxml.macro.present` | bool | VBA project present |
| `ooxml.macro.module_count` | int | number of VBA modules |
| `ooxml.macro.suspicious_api` | list[string] | API names oletools flags (static string match) |
| `ooxml.macro.auto_open` | list[string] | Auto_Open / Workbook_Open / Document_Open style entry points present |
| `ooxml.xlm.present` | bool | Excel 4.0 macro sheet present |
| `ooxml.embedded_object.name` / `.size` / `.content_type` | per object | OLE/package parts embedded in the document |
| `ooxml.custom_xml.target` | string | custom XML part references |
| `ooxml.metadata.author` / `.created` / `.modified` / `.last_modified_by` / `.revision` / `.application` | string/timestamp | from `docProps/core.xml` and `app.xml` |
| `ooxml.ooxml.security.editing_protection` / `.recommended_read_only` | bool | document protection settings |

**Canonical mapping (see §12 for the rule):** metadata facts → one
`document` category event; each ZIP member → one `archive_member` event
(this is how Stage-2 D2-018's reserved categories get their first real
content); embedded objects and macro presence → `artifact` /
`artifact_finding` under the fact-to-finding rules.

| Budget | Proposed | Method |
|---|---|---|
| Wall-clock per document | 3 s `PROPOSED - TO BENCHMARK` | FX-D-01…FX-D-10 |
| Max parts walked | 4,096 `PROPOSED - TO BENCHMARK` | FX-B-10 |
| Max XML part bytes expanded | 32 MiB `PROPOSED - TO BENCHMARK` | FX-G-05 (entity expansion) |
| Max relationship edges | 8,192 `PROPOSED - TO BENCHMARK` | FX-F-11 (relationship fan-out) |

### 5.2 Office — legacy OLE2 (.doc/.xls/.ppt and OLE-wrapped objects)

| Item | Specification |
|---|---|
| Identify | `selected: ole2` |
| Container | `olefile` (DOC-OLEFILE) — in-process, parse/read/write, no rendering. Streams are enumerated, never written. |
| Macro / DDE / embedded | `oletools` (DOC-OLETOOLS): `olevba` for VBA, `oledir`/`oleobj` for directory and embedded-object facts, `oleid` for the risk-oriented summary. Static. |
| Encryption | `msoffcrypto-tool` (§7) |
| Structured storage names | stream/storage names are preserved verbatim as fact values; the sanitiser of §1.4 is *not* applied to fact values (they are data, never paths) |

**Facts:** `ole.container.stream_count`, `ole.container.storage_count`,
`ole.stream.name`, `.size`, `.entropy`, `ole.macro.present`,
`ole.macro.module_count`, `ole.macro.suspicious_api`, `ole.macro.auto_exec`,
`ole.dde.link_target`, `ole.embedded.name`, `.class_id`, `.size`,
`ole.metadata.author`, `.last_saved_by`, `.create_time`, `.last_saved_time`,
`.company`, `.security`, `ole.encrypted.detected`, `.scheme`.

### 5.3 PDF

| Item | Specification |
|---|---|
| Identify | `selected: pdf` |
| Primary structural parser | `pikepdf` over qpdf (DOC-PIKEPDF, MPL-2.0 bindings; DOC-QPDF, Apache-2.0 engine) — in-process. Chosen because it exposes the object graph (trailer, `/Encrypt`, object streams, xref) without a rendering engine, and qpdf is the reference implementation for repair/decrypt. |
| Secondary / text | `pypdf` (DOC-PYPDF, BSD-3) for metadata and page-tree walks that pikepdf's API makes awkward; `pdfminer.six` (DOC-PDFMINER, MIT) for bounded text extraction |
| Keyword scan | a small in-house keyword scanner modelled on `pdfid`'s public behaviour (DOC-PDFID: counts `/JS`, `/JavaScript`, `/OpenAction`, `/Launch`, `/RichMedia`, `/EmbeddedFile`, `/XFA`; the disarm rewriter is *not* used). pdfid itself is public domain and may be vendored; its version is read from the source header because no formal release exists. |
| **Excluded** | **PyMuPDF (AGPL-3.0, and it renders — DOC-PYMUPDF) and pypdfium2 (renders, multi-licence — DOC-PDFIUM2). Both are excluded on two independent grounds: licence, and the rendering prohibition of §9.1.** Poppler's `pdftotext` (GPL-2.0, DOC-POPPLER) is available as an external-process text extractor but is not in the default build — see D3-011. |

**Facts:** `pdf.object_count`, `pdf.page_count`, `pdf.encrypted.detected`,
`.scheme` (`standard_v1_v2`, `adobe_aes`, `aesv3`, `unknown`),
`.permissions`, `pdf.action.open_action` (the `/OpenAction` target — an
action, not a verdict; the fact name matches the brief's required example),
`pdf.action.names` (per `/Names` tree entry), `pdf.javascript.count`,
`pdf.javascript.source` (per `/JavaScript` action), `pdf.launch.target`,
`pdf.submit_form.action`, `pdf.import_data.action`, `pdf.richmedia.type`,
`pdf.embedded_file.name`, `.size`, `.subtype`, `.checksum`,
`pdf.xfa.present`, `pdf.aa.*` (additional-actions keys),
`pdf.metadata.title` / `.author` / `.producer` / `.creator` / `.creation_date`
/ `.mod_date`, `pdf.hyperlink.uri` (per annotation), `pdf.stream.ratio`
(per stream, decompressed/declared — the PDF bomb signal),
`pdf.repaired` (qpdf reported reconstruction), `pdf.startxref.valid`.

### 5.4 RTF, OneNote, CHM, LNK, HTA

| Family | Tool(s) | Class | Facts |
|---|---|---|---|
| RTF | in-house tokenizer over the RTF grammar plus `striprtf` (DOC-STRIPRTF, BSD-3) for the text body | in-process | `rtf.object_count`, `rtf.embedded_ole.class_id`, `.name`, `rtf.pict.count`, `rtf.field.hyperlink`, `rtf.font.count`, `rtf.text.length` |
| OneNote `.one` | `pyOneNote` (DOC-ONENOTE, Apache-2.0) as primary; `one-extract` (BSD-3) as cross-check | in-process | `onenote.embedded.name`, `.size`, `.hashes.sha256`, `onenote.page_count`, `onenote.author`, `.created`, `.modified`. Maturity is weak (§0: last PyPI release 2023-03 / self-described interim tool) so both parsers run when available and disagreements are recorded as facts, not resolved silently — see Q3-014. |
| CHM | container walk only (ITSF/ITSP/LZXC); no help-viewer integration | in-process, in-house | `chm.file_count`, `chm.file.name`, `.size`, `chm.default_topic` |
| LNK | in-house parser over the Shell Link binary format (well-specified; no verified third-party library was opened for Stage 3) | in-process | `lnk.target.path`, `.args`, `.working_dir`, `.icon`, `.description`, `.hotkey`, `.show_command`, `.volume.serial`, `.machine_id`, `.target_hashes.sha256`, `.target_creation_time`, `.tracker.machine_id`, `.tracker.droid`, `.tracker.droid_file_id`, `lnk.target.is_unc`, `.target.drive_type` |
| HTA / JS / VBS / WSF | script triage (§5.6) — HTA is treated as an XML/HTML shell containing script | in-process | script facts plus `hta.script_count` |

CHM is deliberately metadata-only: opening CHM content means running an HTML
help viewer, which §9 forbids.

### 5.5 Executables — PE, .NET, ELF, Mach-O

| Item | Specification |
|---|---|
| Identify | `selected: pe` / `dotnet` / `elf` / `macho` |
| PE parse | `pefile` (ARC-PEFILE, MIT) — in-process, the workhorse for headers, sections, imports/exports, resources, TLS directory, debug directory |
| PE cross-check | `LIEF` 1.0.0 (ARC-LIEF, Apache-2.0) for structures pefile models poorly (authenticode attribute certificates, rich header, .NET metadata directory) |
| .NET metadata | `dnfile` (ARC-DNFILE, MIT) |
| ELF / Mach-O | `pyelftools` (ARC-PYELFTOOLS, public domain) for ELF; Mach-O is parsed in-house for the header and load commands only (no verified third-party library was opened — Q3-012) |
| Authenticode | signature *presence* and *signer identity* are read from the PE attribute-certificate table and (for .NET) the strong-name directory; **signature verification is not performed offline** because a valid chain requires revocation and timestamping network access, which §9 forbids. `signature.status` is therefore `unverified_offline` unless an online verifier is added later. |
| Capability labelling | `capa` (ARC-CAPA, Apache-2.0) — **in-process optional**, off by default; its README is explicit that it is static and that it handles obfuscation poorly. `FLOSS` (ARC-FLOSS, Apache-2.0) for string deobfuscation, same status. `Detect-It-Easy` (ARC-DIE, MIT) is external-process optional because it is a Qt application. |
| Fuzzy hashes | `py-tlsh` (ARC-TLSH, dual Apache-2.0 OR BSD-2-Clause) in-process. **ssdeep is excluded** (ARC-SSDEEP: LGPL-3.0-or-later *and* no commit since 2021-12 — two independent reasons). |

**Facts:** `pe.image_type` (`exe`, `dll`, `sys`, `ocx`, `cpl`, …),
`pe.machine`, `pe.timestamp`, `.timestamp_raw`, `pe.subsystem`,
`pe.linker_version`, `pe.sections.count`, `pe.section.name`, `.size_raw`,
`.size_virtual`, `.entropy`, `.characteristics`, `pe.import.dll`,
`.name`, `.ordinal` (one fact per import), `pe.export.name`, `pe.imphash`,
`pe.rich.header.products`, `.versions`, `pe.debug.type`, `.pdb_path`,
`pe.tls.callback_count`, `pe.resource.type`, `.name`, `.size`, `.lang`,
`pe.authenticode.present`, `.signer`, `.countersignature`,
`.digest_algorithm`, `pe.dotnet.present`, `.runtime_version`, `.assembly_name`,
`.entry_point`, `.strong_name.present`, `.resources.strings`,
`pe.overlay.size`, `.offset`, `.entropy`, `elf.header.*`, `elf.section.*`,
`macho.load_command.*`, `exe.signature.present`, `.signer`, `.status`,
`exe.fuzzy.tlsh`, `exe.fuzzy.tlsh_distance_to_known` (only when a local
known-hash index exists — no network lookup).

### 5.6 Scripts and plain text

Scripts are triaged by tokenisation, never by execution and never by
evaluating an expression.

| Family | Extractor | Facts |
|---|---|---|
| PowerShell (`.ps1`, `.psm1`, `.psd1`) | in-house tokenizer + AST-lite scan | `script.language`, `script.length`, `script.base64_blob.count`, `.length`, `script.obfuscation.char_replacement`, `.concat_count`, `.reverse_string`, `script.suspicious_cmdlet` (static name list from configuration, not hard-coded detection logic), `script.invoke_expression.count`, `script.download_string.count`, `script.encoded_command` |
| Batch / CMD | line scanner | `script.language`, `script.suspicious_command` (config list), `script.longest_line`, `script.redirect.count` |
| JavaScript / JScript | tokenizer | `script.language`, `script.eval.count`, `script.wscript_shell.count`, `script.activexobject.count`, `script.string_entropy_max` |
| VBScript | tokenizer | `script.language`, `script.createobject.count`, `script.execute_count` |
| Python / shell | tokenizer | `script.language`, `script.suspicious_import` (config list) |
| HTML / MHTML | tokeniser only — **no renderer, no CSS engine, no image fetch** | `html.script_count`, `html.external_resource.uri`, `html.form.action`, `html.meta.refresh_target`, `mhtml.boundary`, `mhtml.part.content_type`, `mhtml.part.filename` |
| Plain text / CSV / JSON / XML / YAML | bounded readers (ijson for JSON, defusedxml for XML) | `text.line_count`, `text.encoding`, `text.longest_line`, `json.depth`, `json.key_count`, `xml.root_element`, `xml.entity_count` |

`html.external_resource.uri` and `mhtml.part.filename` are recorded as
strings. Nothing in Sentinel fetches them (§9.6).

### 5.7 Images and media

| Item | Specification |
|---|---|
| Identify | `selected: image` |
| Metadata | `exifread` (ARC-EXIFREAD, BSD-3) for JPEG/TIFF EXIF; Pillow (ARC-PILLOW, MIT-CMU) for format, dimensions, colour mode, ICC presence and animation frames |
| **Decompression-bomb guard** | Pillow's own `MAX_IMAGE_PIXELS = 89,478,485` and `DecompressionBombError` are relied upon **and additionally capped by Sentinel to a stricter configured value**; the warning text is documented in ARC-PILLOW. Beyond the cap, the image is *not* decoded — dimensions are taken from the header and `analysis_status: resource_limit_exhausted` is set. |
| SVG | treated as XML (defusedxml) and never rendered; `svg.script_count`, `svg.external_image_href`, `svg.foreign_object_count` |
| Excluded | **ExifTool (external-process optional only)** — ARC-EXIFTOOL records dual Artistic-1.0 OR GPL with no LICENSE file on GitHub; running it as a separate process is licence-safe, but it is Perl, it spawns per invocation, and the two Python libraries cover the formats Sentinel actually receives. It remains available as operator-enabled enrichment (Q3-013). **hachoir is excluded** (ARC-HACHOIR: GPL-2.0). |

**Facts:** `image.format`, `.width`, `.height`, `.color_mode`,
`.is_animated`, `.frame_count`, `.has_icc`, `.exif.make`, `.exif.model`,
`.exif.software`, `.exif.datetime`, `.exif.gps_present`,
`image.polyglot_zip_member`, `image.steganography.suspected` (set only when
a container of another family is found appended; Sentinel does not attempt
steganalysis).

### 5.8 Archives and compound containers

Archive *expansion* is governed entirely by §10; this row is only about
*listing and choosing the decompressor*.

| Format | Library | SPDX | Class | Note |
|---|---|---|---|---|
| ZIP | stdlib `zipfile` | PSF-2.0 | in-process | authoritative for member metadata; **no built-in bomb guard** (ARC-ZIPFILE documents the hazard) — §10 supplies it |
| TAR / gzip / bzip2 / xz / zstd | stdlib `tarfile` + `gzip`/`bz2`/`lzma` | PSF-2.0 | in-process | `tarfile` extraction filters (ARC-TARFILE, PEP 706) are mandatory; since 3.14 the `data` filter is the default and still does not prevent *all* unsafe behaviour, so §10 adds its own checks on top |
| 7z, ISO, CPIO, LHA, CAB, XAR, WARC | `libarchive-c` (ARC-LIBARCHIVE) | CC0-1.0 binding over BSD-3 libarchive | in-process | the ctypes binding is CC0; the underlying C library is BSD-3 — both Stage-1-D-008 compatible |
| 7z (pure-Python alternative) | `py7zr` | LGPL-2.1-or-later | **excluded by default** | active and well-maintained (ARC-PY7ZR) but LGPL-2.1 is copyleft; D-008 excludes it from the linked build. It may be enabled only after a written licence review; Q3-007 tracks that. Note its 1.1.3 release note is literally "Fix multiple vulnerabilities", so whichever 7z library ships must be pinned and monitored. |
| RAR | `rarfile` (ARC-RARFILE) | ISC | in-process for **listing only** | the README is explicit that decompression executes an external tool (unrar/unar/7zip/bsdtar). Sentinel uses `rarfile` to read the header and emit `archive_member` facts, and performs extraction only if an operator has installed one of those tools; when absent, RAR members are listed but not extracted and `analysis_status` is `COMPLETED_WITH_WARNINGS` with a `dependency_missing` entry. The unrar licence is restrictive and is not vendored. |
| Nested/unknown carving | `unblob` (ARC-UNBLOB) | MIT | external-process optional, off by default | it extracts recursively over 30+ formats, which is exactly the behaviour §10 bounds; it may be enabled only inside the quarantined worker with §10's limits applied by the runner |
| Embedded-file carving | `binwalk` (ARC-BINWALK) | MIT | external-process optional, off by default | Rust v3 line; used for "what else is inside this blob" when a family parser found nothing |

**Facts:** `archive.format`, `archive.member_count`,
`archive.member.path`, `.size_compressed`, `.size_uncompressed`,
`.ratio`, `.is_directory`, `.is_symlink`, `.link_target`, `.method`,
`.crc32_valid`, `.encrypted`, `.encryption.scheme`,
`archive.entry.ratio` (the aggregate file-level ratio — the canonical
archive-bomb signal, matching the brief's required example name),
`archive.comment`, `archive.total_declared_uncompressed`.

### 5.9 Installers and disk images

| Family | Stage-3 treatment |
|---|---|
| MSI | container walk (OLE2 + CFB tables) with `olefile`; no installation is attempted. Facts: `msi.table_count`, `msi.property.*`, `msi.file.name`, `.size`, `msi.custom_action.target`. |
| NSIS / Inno | identified, listed, **not unpacked** in Stage 3 (no verified unpacker was opened; Q3-016) |
| VHD / VHDX / VMDK / ISO | identified and **not mounted or parsed** (§9: mounting executes a filesystem driver on attacker bytes). ISO is listed via libarchive when available. `analysis_status: not_analyzed_by_policy`. |

### 5.10 Optional enrichment services (deliberately not in the default build)

| Service | SPDX | Why not default |
|---|---|---|
| Apache Tika (4.1.0, DOC-TIKA) | Apache-2.0 | licence is fine, but its own security page states that neither tika-server nor tika-grpc is a security boundary and that only trusted callers may reach them; in-process parser denial of service is documented as "not a security vulnerability". Adopting it means owning a JVM isolation story. Deferred to Q3-008. |
| ClamAV (1.5.4, ARC-CLAMAV) | GPL-2.0 | external-process only (licence), and it is a *signature* engine whose value overlaps YARA-X. Available as operator-enabled; signature DB updates require network egress, which §9 forbids in the triage worker — the DB must be staged out-of-band. |
| ExifTool (13.59, ARC-EXIFTOOL) | Artistic-1.0 OR GPL | external-process only; see §5.7 |
| DIE, capa, FLOSS, unblob, binwalk | MIT / Apache-2.0 | licence-compatible, but each is an optional capability layer; all are off by default and each has a documented enablement condition |

---
