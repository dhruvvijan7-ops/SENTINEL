# Stage 3 — Ingestion and Universal Artifact Triage

**Project:** Sentinel — lightweight Windows-first HIDS
**Stage:** 3 of 4 (ingestion, parsers, artifact triage)
**Status:** complete draft for review
**Date:** 2026-10-09
**Companion artifacts:** `canonical_event_v1.schema.json` (unchanged from Stage 2 —
every parser in this document emits `canonical-event/v1` events);
`verification-log.yaml` and `VERIFICATION_LOG_2026-10-09.yaml` (raw evidence
harvests behind §0, kept as sibling files because the consolidated log in this
document is compressed).

This document specifies (a) the HTTP upload gate through which harvested
artifacts and uploaded files enter Sentinel, (b) the identification stage that
assigns a format to every ingested byte stream, (c) the parser interface every
telemetry parser and content extractor implements, (d) the decision matrices
choosing concrete libraries for every supported telemetry format and artifact
family, (e) the static artifact-triage ("File Intelligence") layer that turns
an uploaded file into facts and canonical events, and (f) the safety
architecture that makes running third-party parsers over attacker-controlled
bytes defensible.

It inherits, without restating, Stage 1 decisions D-001…D-012 (Python 3.12+ /
FastAPI / PostgreSQL / background worker; Sigma-compatible rule content; DRL
attribution for rule content; no GPL/AGPL code copying) and Stage 2 decisions
D2-001…D2-024 (canonical-event/v1, value-state model, lossless `raw` +
`unmapped[]`, three-level semantic classification, `document` /
`archive_member` / `executable` / `artifact` / `artifact_finding` reserved for
this stage). Where a Stage-3 choice revises an inherited assumption it says so
explicitly and is recorded in §13.

**Reading order (required):** §0 Verification Log → §1 Upload Gate Spec →
§2 Identification Spec → §3 Parser Interface → §4 Parser Decision Matrix →
§5 Artifact Triage Decision Matrix → §6 Artifact Graph Model → §7
Encrypted-File Policy → §8 Triage Output Semantics → §9 Active-Content
Prohibitions → §10 Safe Archive Extraction Design → §11 Attack Fixture
Catalogue → §12 Facts-to-Canonical Mapping → §13 DECISIONS / OPEN_QUESTIONS /
NOT_VERIFIED.

**Static-only invariant (restated, because everything downstream depends on
it).** Sentinel never executes, renders, interprets, macro-runs, prints,
emulates-as-a-program, or resolves-out-to-the-network an uploaded artifact or
any byte stream extracted from one. Parsers may decompress, decode, tokenize
and deobfuscate *bytes*; they may never cause *behaviour*. §9 is the
normative prohibition list; §10 is the containment algorithm for the one place
where untrusted bytes are expanded.

**Evidence labelling.** `VERIFIED` = the claim was confirmed against a primary
source that was actually opened and read during Stage-3 research (URL,
release/tag, commit and licence recorded in §0). `INFERRED` = a documented
Sentinel design choice made over verified facts (e.g. "we will call this
fact `pe.import` because the PE spec names the table Import Address
Table"). `UNVERIFIED` = asserted but not corroborated by an allowed source; it
never becomes a required key, a default-on path, or a licence conclusion.
Labels appear in the decision-matrix `Evidence` columns, in §12, and in the
NOT_VERIFIED table.

**Budget discipline.** Every size, time, memory, ratio, count and depth limit
in this document is a proposed engineering default, not a measurement. Each is
written `PROPOSED - TO BENCHMARK` and carries a fixture id from §11 (or a
self-measurement method) that Stage 4 must run to turn it into a number.
No number in this document is presented as a measured fact. Self-measured
numbers are labelled `MEASURED (method)` and none are used at Stage 3.

**Licence discipline.** Every third-party component named in §4 and §5 carries
an SPDX id and a commercial-distribution note. Stage 1 D-008 already excludes
GPL/AGPL from code linked or copied into Sentinel; Stage 3 additionally
classifies components as `in-process (licence-compatible)`, `external-process
(GPL/other-copyleft is acceptable because the program is not linked)`, or
`excluded`. "External-process" is not a loophole: §9 still forbids whatever
the external program would do to the artifact, and §10 still bounds what it
may expand.

---

## 0. Verification Log

Every evidence id referenced by §1–§13 appears below. Entries are compressed
relative to Stage 2; the full harvest records (fetch method, blocked hosts,
raw licence text, OSV queries) are in the sibling files
`VERIFICATION_LOG_2026-10-09.yaml` (telemetry parsers) and
`verification-log.yaml` (document triage). Group prefixes:
`ID-` identification and upload gate, `TL-` telemetry parsers and text
carriers, `DOC-` document triage, `ARC-` archive / binary / generic triage.
All retrievals happened on 2026-10-09. Where a host refused automated
retrieval (gitlab.freedesktop.org, some PyPI project pages behind bot
challenges) the substitute source and the residual gap are named, and the
affected claim is downgraded to `PARTIALLY VERIFIED` and listed in §13.

```yaml
verification_log:

  # ---------- ID: identification and upload gate ----------
  - id: ID-LIBMAGIC
    source: file / libmagic (the `file(1)` magic database and library)
    url: https://github.com/file/file
    default_branch: master
    latest_release: FILE5_48, 2026-06-07
    observed_commit: 5e57b94cdd3f2bc2f6db8581dcce76a89fc9c9f7 (head 2026-08-28)
    spdx: NOASSERTION in GitHub metadata; COPYING text is 2-clause BSD (Darwin/Zoulas)
    language: C
    maintenance: active
    read: COPYING; repository metadata
    label: VERIFIED

  - id: ID-PYMAGIC
    source: python-magic (PyPI `python-magic`, upstream ahupp/python-magic) — ctypes binding to libmagic
    url: https://github.com/ahupp/python-magic ; https://pypi.org/pypi/python-magic/json
    default_branch: master
    latest_release: 0.4.27 (PyPI, 2022-06-07)
    observed_commit: d3396fd2d4de1d7229759052625fa1bded518293
    spdx: NOASSERTION in metadata; LICENSE text = MIT + libmagic LEGAL.NOTICE clause
    language: Python
    maintenance: upstream commit 2026-09-22; last PyPI release 2022-06-07 (release cadence stale, repo active)
    read: PyPI JSON; LICENSE; README Troubleshooting section
    label: VERIFIED

  - id: ID-PYMAGIC-WIN
    source: python-magic README Troubleshooting — Windows DLL bitness behaviour
    url: https://github.com/ahupp/python-magic
    claim: "[WindowsError: [Error 193]] = 32-bit libmagic DLL loaded by 64-bit Python"; README links
      third-party 64-bit Windows libmagic DLL distributions
    label: VERIFIED

  - id: ID-MAGIKA
    source: Magika (google/magika) — content-type identification using an ONNX model
    url: https://github.com/google/magika
    default_branch: main
    latest_release: cli/v1.1.0, 2026-04-24
    observed_commit: 175a424adcc291cbe352dcb4fec92412835b9ccf (head 2026-10-09)
    spdx: Apache-2.0 (repository root; assets/models/standard_v3_3/ contains only README/config/metadata/model.onnx —
      no separate model-licence file was found, so the model is covered by the repository licence by inclusion)
    language: Rust (Python bindings published)
    maintenance: active (commit same day as retrieval)
    read: README.md (accuracy claim ~99% avg precision/recall over ~100M samples, 200+ types; paper ICSE 2025);
      assets/models/standard_v3_3/README.md (label table)
    label: VERIFIED (model-licence inference flagged in Q3-006)

  - id: ID-FILETYPE
    source: filetype.py (PyPI `filetype`, upstream h2non/filetype.py)
    url: https://github.com/h2non/filetype.py ; https://pypi.org/pypi/filetype/json
    latest_release: 1.2.0 (PyPI, 2022-11-02); observed commit 3eae5cedad2dc65076a501a9374abafb1d700602
    spdx: MIT
    language: Python
    maintenance: last upstream commit 2025-05-02 (weak); Go sibling project active
    label: VERIFIED

  - id: ID-PUREMAGIC
    source: puremagic (cdgriffith/puremagic) — pure-Python magic/mimetype identification
    url: https://github.com/cdgriffith/puremagic
    latest_release: 2.2.0 (2026-04-08); pushed_at 2026-04-09
    spdx: MIT
    language: Python
    maintenance: active; README states zero runtime dependencies, cross-platform, deep-scan mode since 2.0,
      Python 3.12+ for the 2.x line
    label: VERIFIED

  - id: ID-MAGICBIN
    source: python-magic-bin (PyPI) — legacy Windows binary wheel for python-magic
    url: https://pypi.org/pypi/python-magic-bin/json
    latest_release: 0.4.14 (2017-10-02)
    claim: PyPI README states the project is deprecated and names a successor package
    maintenance: stale since 2017
    label: VERIFIED

  - id: UP-FASTAPI
    source: FastAPI request-files documentation + Starlette formparsers source
    url: https://fastapi.tiangolo.com/tutorial/request-files/
    claim: UploadFile spools to a temporary file (memory until a limit, then disk); Starlette's
      MultiPartParser sets spool_max_size = 1024*1024 and constructs SpooledTemporaryFile(max_size=…)
    label: VERIFIED

  - id: UP-SPOOL
    source: Python `tempfile` documentation
    url: https://docs.python.org/3/library/tempfile.html
    claim: "data is spooled in memory until the file size exceeds max_size, or until the file's fileno()
      method is called, at which point the contents are written to disk"; rollover() forces rollover
    label: VERIFIED

  - id: UP-UVICORN
    source: uvicorn settings documentation (docs/settings.md) + Starlette requests documentation
    url: https://github.com/encode/uvicorn/blob/master/docs/settings.md
    claim: uvicorn's Resource Limits expose only limit-concurrency / limit-max-requests / backlog — no
      request-body size setting. Starlette form limits cover max_files / max_fields / max_part_size, and
      max_part_size applies to non-file fields; uploaded files are spooled and are NOT capped by it.
    label: VERIFIED

  - id: UP-MSNAME
    source: Microsoft Learn — "Naming files, paths, and namespaces"
    url: https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file (ms.date 2024-08-28)
    claim: reserved device names CON PRN AUX NUL COM1–COM9 LPT1–LPT9 (plus ISO-8859-1 superscript variants);
      invalid characters < > : " / \ | ? * plus NUL and code points 1–31; no trailing space or period;
      MAX_PATH 260 characters pre-Windows-10-1607 with registry/group-policy opt-out; \\?\ prefix disables parsing
    label: VERIFIED

  - id: UP-MSADS
    source: [MS-FSCC] File System Control Codes, protocol revision 60.0 (2025-11-21)
    url: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8
    claim: §5.6.1 defines the Zone.Identifier stream name (fully qualified form sample.txt:Zone.Identifier:$DATA)
      whose contents are the text stream "[ZoneTransfer]\r\nZoneId=3"; §2.1.4 states the file system MAY support
      alternate data streams; the System.ZoneIdentifier property page documents the mark-of-the-web zone
    label: VERIFIED

  # ---------- TL: telemetry parsers and text carriers ----------
  - id: TL-EVTX-RUST
    source: omerbenamram/evtx (Rust EVTX parser) and its Python bindings published on PyPI as `evtx`
    url: https://github.com/omerbenamram/evtx
    default_branch: master
    latest_release: crate/PyPI 0.12.3 / binding 0.13.1 (PyPI upload 2026-09-22)
    observed_commit: 7479d02dfaa3bdeb41c5ea87195e84116a032cfc (head 2026-10-07)
    spdx: Apache-2.0 at repository; MIT OR Apache-2.0 dual per crates.io; PyPI binding 0.13.1 MIT
    language: Rust (Python binding)
    maintenance: active
    cves: no advisory found in OSV (crates.io query)
    label: VERIFIED

  - id: TL-PYEVTX
    source: williballenthin/python-evtx — pure-Python EVTX parser
    url: https://github.com/williballenthin/python-evtx
    latest_release: PyPI python-evtx 0.8.1 (2025-05-02), Development Status 5
    observed_commit: c0007441657899c39180de10a2be1a0e43dbeaf9 (head 2026-10-06)
    spdx: Apache-2.0
    language: Python
    maintenance: active
    cves: no advisory found in OSV (PyPI query)
    label: VERIFIED

  - id: TL-LIBEVTX
    source: libyal/libevtx (C library) — checked because it is the other frequently-cited EVTX option
    url: https://github.com/libyal/libevtx
    default_branch: main
    latest_release: 20260705
    spdx: LGPL-3.0-or-later (NOT plain GPL-3.0)
    language: C
    maintenance: active (pushed 2026-09-23)
    cves: no advisory found in OSV
    note: a PyPI package named `pyevtx` does NOT exist (pypi.org/pypi/pyevtx and the simple index both 404);
      libyal ships its own python bindings only in-tree
    label: VERIFIED

  - id: TL-TSHARK
    source: TShark man page and Wireshark release notes
    url: https://www.wireshark.org/docs/man-pages/tshark.html ; https://www.wireshark.org/docs/relnotes/wireshark-4.6.9.html
    claim: the man page in force is "the manual page for TShark 4.6.9"; flags -T ek (newline-delimited JSON for
      Elasticsearch, one line per packet), -T fields, -T json, -Y, -l (line buffered), -e and -E are documented there
    latest_release: 4.6.9, tag 2d548b19, 2026-09-23 (previous stable line 4.4.19)
    spdx: GPL-2.0-or-later for Wireshark/TShark itself
    cves: 4.6.9 release notes list wnpa-sec-2026-92…110 (19 advisories), including CVE-2026-96419
      (profile import crash / possible code execution) and CVE-2026-96418 (TIFF dissector infinite loop);
      4.6.5 fixed CVE-2026-5402 (TLS dissector / possible code execution) and CVE-2026-5405 (RDP)
    label: VERIFIED

  - id: TL-ZEEK
    source: Zeek documentation set (Version 9.0.0) and the zeek/zeek repository
    url: https://docs.zeek.org/en/current/ ; https://docs.zeek.org/en/current/tutorial/logs.html
    latest_release: v9.0.0 (tag commit 970787a9f10896ff65c4758444d87bcf53eba4b7)
    observed_commit: 5b7c9c753a8e69da4a6dcd41e7a06c26226647dd (head 2026-10-09)
    spdx: repository reports NOASSERTION; COPYING is the BSD-style LBNL/ICSI variant
    language: C++
    maintenance: active
    claim: default logs are TSV with #separator / #fields / #types / #open / #close headers; zeek-cut extracts columns
    label: VERIFIED

  - id: TL-SURICATA
    source: Suricata EVE JSON format documentation and the OISF/suricata repository
    url: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html ; https://suricata.io/download/
    latest_release: 8.0.7 (2026-09-15); also published 7.0.13 / 8.0.6 / 8.0.5
    spdx: GPL-2.0
    language: C
    maintenance: active
    claim: JSON Lines, one event per line; common envelope fields timestamp, flow_id, event_type; per-event-type
      objects (alert, dns, http, fileinfo, tls, flow, …) selected by event_type
    cves: 14 historical OSS-Fuzz OSV entries; none in fetched sources for the current 8.0.x line
    label: VERIFIED

  - id: TL-RFC3164
    source: RFC 3164, "The BSD syslog Protocol" (August 2001)
    url: https://www.rfc-editor.org/rfc/rfc3164.txt ; https://www.rfc-editor.org/info/rfc3164
    standards_level: Informational; the info page states the RFC is obsolete, see RFC 5424
    copyright: Copyright (C) Internet Society 2001
    label: VERIFIED

  - id: TL-RFC5424
    source: RFC 5424, "The Syslog Protocol" (March 2009)
    url: https://www.rfc-editor.org/rfc/rfc5424.txt ; https://www.rfc-editor.org/info/rfc5424
    standards_level: Proposed Standard; obsoletes RFC 3164
    copyright: IETF Trust / BCP 78
    label: VERIFIED

  - id: TL-CEF
    source: "Implementing ArcSight Common Event Format (CEF) — Version 27", Micro Focus / Open Text
    url: https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-25.1/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf
    claim: syslog transport "<prefix> <CEF_header>|[Extension]"; header
      CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity; extension is
      space-delimited key=value with backslash-escaped pipes in values; UTF-8
    label: VERIFIED (vendor-published PDF fetched directly)

  - id: TL-LEEF
    source: IBM QRadar "Log Event Extended Format (LEEF) Version 2"
    url: https://www.ibm.com/docs/en/dsm?topic=leef-overview ; https://www.ibm.com/docs/en/SS42VS_DSM/pdf/b_Leef_format_guide.pdf
    claim: header LEEF:Version|Vendor|Product|Version|EventID|; LEEF 1.0 and 2.0; optional syslog prefix;
      attributes key=value, tab-delimited by default, LEEF 2.0 supports a custom delimiter; UTF-8 required
    label: VERIFIED via IBM Docs HTML (the PDF URL returns 403 to unauthenticated automated fetch)

  - id: TL-DEFUSEDXML
    source: defusedxml (PyPI)
    url: https://pypi.org/pypi/defusedxml/json ; https://github.com/tiran/defusedxml
    latest_release: 0.7.1 (2021-03-08)
    spdx: PSFL
    language: Python
    maintenance: last release 2021-03-08; stable/frozen rather than abandoned; still the XML entity-expansion
      defence recommended by the openpyxl docs
    cves: no advisory found in OSV
    label: VERIFIED

  - id: TL-ORJSON
    source: orjson (PyPI)
    url: https://pypi.org/pypi/orjson/json
    latest_release: 3.13.0
    spdx: MPL-2.0 AND (Apache-2.0 OR MIT)
    language: Rust (Python bindings)
    cves: GHSA-hx9q-6w63-j58v / CVE-2025-67221 and GHSA-pwr2-4v36-6qpr / CVE-2024-27454 — both
      "orjson does not limit recursion for deeply nested JSON documents" (advisories fetched from
      https://api.osv.dev/v1/vulns/…)
    label: VERIFIED

  - id: TL-IJSON
    source: ijson (PyPI)
    url: https://pypi.org/pypi/ijson/json
    latest_release: 3.5.1 (2026-07-06); Development Status 5
    spdx: BSD-3-Clause AND ISC
    cves: no advisory found in OSV
    label: VERIFIED

  - id: TL-PANDAS
    source: pandas (PyPI)
    url: https://pypi.org/pypi/pandas/json
    latest_release: 3.0.6 (2026-09-17); win_amd64 wheel present
    spdx: BSD-3-Clause (PyPI classifier not captured in this pass — see NOT_VERIFIED)
    cves: PYSEC-2020-73 / CVE-2020-13091, historical (2020), old-version pickle deserialization
    label: VERIFIED

  - id: TL-POLARS
    source: polars (PyPI + simple index)
    url: https://pypi.org/pypi/polars/json ; https://pypi.org/simple/polars/
    latest_release: 2.0.0 (2026-10-06)
    spdx: MIT (PyPI classifier)
    claim: for 2.0.0 the package publishes only polars-2.0.0-py3-none-any.whl plus an sdist — no
      platform-native win_amd64 wheel under the `polars` distribution; the native engine is no longer bundled
    label: VERIFIED

  - id: TL-CSV
    source: Python `csv` module documentation (Python 3.14.8 docs)
    url: https://docs.python.org/3/library/csv.html
    claim: RFC 4180 referenced; default dialect csv.excel; options lineterminator / quoting / quotechar /
      delimiter; documentation instructs open(..., newline='') for correct line handling
    note: the word "smearing" does not appear on the fetched page — the multi-line-field hazard is a documented
      property of the module's quoting rules, not a quotable sentence
    label: VERIFIED

  - id: TL-DRAIN3
    source: Drain3 (logpai/Drain3) — streaming log template miner
    url: https://github.com/logpai/Drain3
    latest_release: no tag; head commit 0fb6d6e1828838fa05c8f6fa5cda878e02ea79c7 (2025-02-04)
    spdx: MIT (raw LICENSE.txt content is verbatim MIT; GitHub API reports NOASSERTION because the file is
      named LICENSE.txt)
    language: Python
    maintenance: ~8 months without a commit as of retrieval
    label: VERIFIED

  # ---------- DOC: document triage ----------
  - id: DOC-PDFID
    source: pdfid.py / pdf-parser.py (Didier Stevens Suite)
    url: https://blog.didierstevens.com/programs/pdf-tools ; https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdfid.py
    version: __version__ 0.2.10, __date__ 2025/03/05 (read from the source header)
    spdx: "Source code put in public domain by Didier Stevens, no Copyright" (source header)
    language: Python
    claim: parse-only. The blog states pdf-parser.py "will not render a PDF document"; pdfid.py counts
      /JS /JavaScript /OpenAction /Launch /RichMedia /EmbeddedFile /XFA keywords and has a disarm rewriter
    label: VERIFIED (version read from source; no formal git tag exists)

  - id: DOC-PIKEPDF
    source: pikepdf (PyPI + GitHub)
    url: https://pypi.org/project/pikepdf/ ; https://github.com/pikepdf/pikepdf
    latest_release: 10.16.0 (2026-09-29)
    observed_commit: 23290bd753eaf3feeaa265da9a191c6d1cd54612 (PyPI attestation)
    spdx: MPL-2.0 (bindings) over qpdf (C++); qpdf itself Apache-2.0 (see DOC-QPDF)
    language: Python + C++
    claim: parse / repair / manipulate; README states it is "not what you want if you need to render PDFs to images"
    label: VERIFIED

  - id: DOC-PYPDF
    source: pypdf (PyPI + GitHub)
    url: https://pypi.org/project/pypdf/ ; https://github.com/py-pdf/pypdf
    latest_release: 6.19.0 (2026-09-16); observed commit d62cb58d3988b291b0435eddfd118c4f8f6b6a46
    spdx: BSD-3-Clause
    language: Python (pure)
    claim: parse / merge / split / crop and text extraction; no rendering engine
    label: VERIFIED

  - id: DOC-PDFMINER
    source: pdfminer.six (PyPI + GitHub)
    url: https://pypi.org/project/pdfminer.six/ ; https://github.com/pdfminer/pdfminer.six
    latest_release: 20260107 (2026-01-07)
    spdx: MIT
    language: Python (pure)
    claim: parse-only; extracts text / images / html / hOCR from PDF source
    label: VERIFIED

  - id: DOC-QPDF
    source: qpdf (GitHub + readthedocs)
    url: https://github.com/qpdf/qpdf ; https://qpdf.readthedocs.io/en/latest/encryption.html
    latest_release: v12.4.2 (2026-09-27); observed commit 4eba95899886e851cc41d76886483b347612f2a8
    spdx: Apache-2.0 (LICENSE.txt fetched in full)
    language: C++
    claim: parse / transform / decrypt; the standard security handler supports password-based decryption;
      no rendering
    label: VERIFIED

  - id: DOC-PYMUPDF
    source: PyMuPDF (PyPI + GitHub + COPYING)
    url: https://pypi.org/project/PyMuPDF/ ; https://raw.githubusercontent.com/pymupdf/PyMuPDF/main/COPYING
    latest_release: 1.28.2 (2026-08-06)
    spdx: AGPL-3.0 (COPYING is the full GNU AGPL v3 text); a commercial licence is offered separately
    language: Python + C (MuPDF)
    claim: CAN RENDER — README shows page.get_pixmap(dpi=150) and OCR
    label: VERIFIED

  - id: DOC-PDFIUM2
    source: pypdfium2 (GitHub releases + LICENSES/)
    url: https://github.com/pypdfium2-team/pypdfium2/releases ; https://github.com/pypdfium2-team/pypdfium2/tree/main/LICENSES
    latest_release: 5.14.0 (2026-10-04); observed commit 21f85e273036f3bade4f67d896e1d05927e5f4b1
    spdx: multi-license — BSD-3-Clause (wrapper) + Apache-2.0 (PDFium) + LGPL-3.0-or-later (freetype and others)
      + MPL-2.0 + MIT + CC-BY-4.0, enumerated in LICENSES/
    claim: CAN RENDER (release notes reference PdfBitmap / FPDFBitmap_Destroy / PdfDocument.render)
    note: the PyPI project page was bot-challenged; version, commit and licences were read from GitHub
    label: VERIFIED

  - id: DOC-POPPLER
    source: Poppler / poppler-utils `pdftotext`
    url: https://manpages.debian.org/bookworm/poppler-utils/pdftotext.1.en.html ; COPYING via the Skia
      third_party/poppler mirror (gitlab.freedesktop.org itself refused automated retrieval)
    latest_release: Poppler-26.09.0 per the Linux From Scratch page; Debian bookworm ships 22.12.0
    spdx: GPL-2.0-only
    language: C++
    claim: parse-only text/layout extraction; does not execute JavaScript
    label: PARTIALLY VERIFIED (licence and behaviour via mirrors; official repository branch/commit not opened)

  - id: DOC-OPENPYXL
    source: openpyxl documentation
    url: https://openpyxl.readthedocs.io/en/stable/ ; https://openpyxl.readthedocs.io/en/stable/optimized.html
    latest_release: 3.1.5 (PyPI, prior session)
    spdx: MIT/Expat (documentation index)
    language: Python
    claim: read_only=True uses lazy loading over a ReadOnlyWorksheet and requires wb.close(); the docs carry a
      security note recommending defusedxml against billion-laughs attacks; macros are not executed
    label: PARTIALLY VERIFIED (documentation and licence read; the upstream repository — foss.heptapod.net —
      refused automated retrieval and the GitHub mirror 404s, so branch/commit are unrecorded)

  - id: DOC-DOCX
    source: python-docx (PyPI + GitHub)
    url: https://pypi.org/project/python-docx/ ; https://github.com/python-openxml/python-docx
    latest_release: 1.2.0 (2025-06-16)
    spdx: MIT
    language: Python
    claim: parse / create / update .docx; no rendering, no macro execution
    label: VERIFIED

  - id: DOC-PPTX
    source: python-pptx (PyPI + GitHub)
    url: https://pypi.org/project/python-pptx/ ; https://github.com/scanny/python-pptx
    latest_release: 1.0.2 (2024-08-07)
    spdx: MIT
    language: Python
    claim: README states it does not require PowerPoint to be installed or licensed; no rendering
    label: VERIFIED

  - id: DOC-OLEFILE
    source: olefile (decalage2/olefile)
    url: https://github.com/decalage2/olefile
    latest_release: v0.47 (2023-12-01, from the README news section)
    spdx: BSD-2-Clause-style custom terms (plus a PIL licence portion), full text in the README
    language: Python
    claim: parse / read / write OLE2 compound files; no rendering
    label: VERIFIED

  - id: DOC-OLETOOLS
    source: oletools (decalage2/oletools)
    url: https://github.com/decalage2/oletools
    latest_release: v0.60.3 (2025-05-22, README news section)
    spdx: BSD-2-Clause-style custom terms + MIT for officeparser portions
    language: Python
    claim: analysis / forensics; extracts VBA macros, XLM macros, DDE links and embedded objects; does not
      execute them
    label: VERIFIED

  - id: DOC-MSOFFCRYPTO
    source: msoffcrypto-tool (PyPI + GitHub)
    url: https://pypi.org/project/msoffcrypto-tool/ ; https://github.com/nolze/msoffcrypto-tool
    latest_release: 6.0.0 (2026-01-12)
    spdx: MIT
    language: Python
    claim: decrypt / encrypt Microsoft Office files — OOXML agile and standard, RC4, RC4 CryptoAPI, XOR
      obfuscation and legacy Office 95 schemes
    label: VERIFIED

  - id: DOC-XLM
    source: XLMMacroDeobfuscator (DissectMalware/XLMMacroDeobfuscator)
    url: https://github.com/DissectMalware/XLMMacroDeobfuscator
    spdx: Apache-2.0
    language: Python
    claim: uses an internal XLM emulator to interpret macros "without fully performing the code"
    label: VERIFIED (release tag not observed — see NOT_VERIFIED)

  - id: DOC-STRIPRTF
    source: striprtf (PyPI + GitHub)
    url: https://pypi.org/project/striprtf/ ; https://github.com/joshy/striprtf
    latest_release: 0.0.33 (2026-08-17)
    spdx: BSD-3-Clause
    language: Python
    claim: converts RTF to plain text via rtf_to_text(); parse-only, no rendering
    label: VERIFIED

  - id: DOC-ONENOTE
    source: OneNote parsers — DissectMalware/pyOneNote and volexity/one-extract
    url: https://github.com/DissectMalware/pyOneNote ; https://github.com/volexity/one-extract
    spdx: Apache-2.0 (pyOneNote) and BSD-3-Clause (one-extract)
    claim: both are parse / extract tools for .one containers that dump embedded files and metadata; neither
      renders. pyOneNote's last PyPI release is 0.0.2 (2023-03); one-extract describes itself as an interim
      solution created in response to malspam .one campaigns
    label: VERIFIED for existence, licence and stated purpose; maturity is weak (see Q3-014)

  - id: DOC-TIKA
    source: Apache Tika documentation (4.1.x) including its security page
    url: https://tika.apache.org/docs/4.1.x/security.html ; https://tika.apache.org/download.html
    latest_release: 4.1.0 (2026-09-29); 3.x maintenance line at 3.3.2; docs built from commit 5cba7bc3b
    spdx: Apache-2.0
    language: Java
    claim: the security page states that neither tika-server nor tika-grpc is a security boundary and that they
      must only ever be exposed to trusted callers; in-process AutoDetectParser denial of service is explicitly
      described as "not a security vulnerability"; process isolation (pipes / forked JVMs) is the intended sandbox
    label: VERIFIED

  - id: DOC-MOTW
    source: Microsoft Open Specifications [MS-FSCC] (same protocol set as UP-MSADS)
    url: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e2b19412-a925-4360-b009-86e3b8a020c8
    claim: the Zone.Identifier stream is the mark-of-the-web carrier; contents are the text stream
      "[ZoneTransfer]\r\nZoneId=3"; the zone is persisted through the Attachment Execution Service
    label: VERIFIED

  # ---------- ARC: archive, binary and generic triage ----------
  - id: ARC-ZIPFILE
    source: CPython `zipfile` documentation (Doc/library/zipfile.rst on the main branch)
    url: https://raw.githubusercontent.com/python/cpython/main/Doc/library/zipfile.rst
    claim: a "Resources limitations" section states "decompression bombs (aka ZIP bomb) apply to zipfile library
      that can cause disk volume exhaustion"; zipfile.Path exists; extracting the same archive twice overwrites
      files without asking
    note: no built-in expansion guard is documented — Sentinel must supply its own (§10)
    label: VERIFIED

  - id: ARC-TARFILE
    source: CPython `tarfile` documentation (Doc/library/tarfile.rst)
    url: https://raw.githubusercontent.com/python/cpython/main/Doc/library/tarfile.rst
    claim: extraction filters were added in 3.12 (PEP 706); "Since Python 3.14, the default (data) will prevent
      the most dangerous security issues. However, it will not prevent *all* unintended or insecure behavior.";
      data_filter refuses absolute/outside-destination link targets, device files, strips group/other execute bits
      and nulls uid/gid/uname/gname; link targets normalized from 3.15
    label: VERIFIED

  - id: ARC-PY7ZR
    source: py7zr (PyPI + miurahr/py7zr)
    url: https://pypi.org/pypi/py7zr/json ; https://github.com/miurahr/py7zr
    latest_release: 1.1.3 (2026-06-19, release note "Fix multiple vulnerabilities"); observed head
      62255f06ab9a37295b06fe7e412c0a4bc7f5d7e7 (2026-09-17)
    spdx: LGPL-2.1-or-later
    language: Python (pure)
    maintenance: active
    label: VERIFIED

  - id: ARC-LIBARCHIVE
    source: libarchive-c (Changaco/python-libarchive-c — the distribution name differs from the repository name)
    url: https://pypi.org/pypi/libarchive-c/json ; repository Changaco/python-libarchive-c
    latest_release: 5.3 (2025-05-22); observed head 7e8cb8556e45d4b22ba7b0726fb640ef6253cfcc
    spdx: CC0-1.0 for the Python ctypes binding; the underlying libarchive C library is BSD-3-Clause
    language: Python (ctypes binding)
    maintenance: quiet since 2025-05
    label: VERIFIED

  - id: ARC-7ZIP
    source: 7-Zip (7-zip.org license text + download page + ip7z/7zip)
    url: https://7-zip.org/license.txt ; https://7-zip.org/download.html ; https://github.com/ip7z/7zip
    latest_release: 26.04 (site dated 2026-10-05; head 9128b80e3a471108678e2b3ec3c985861c8d7b0f, 2026-10-06)
    licence_quote: "7z.dll: The 'GNU LGPL' as main license for most of the code; The 'GNU LGPL' with 'unRAR
      license restriction' for some code; The 'BSD 3-clause License' for some code; The 'BSD 2-clause License'
      for some code"
    claim: the official Linux x86-64 console tarball was downloaded and listed; it contains the binaries 7zz and
      7zzs plus License.txt and MANUAL/
    label: VERIFIED

  - id: ARC-UNBLOB
    source: unblob (onekey-sec/unblob — the spotify/ URL no longer resolves)
    url: https://github.com/onekey-sec/unblob ; https://unblob.org
    latest_release: 26.6.4 (2026-06-04); observed head 8c68fe29b7dbe27d323632bc1d770409a076be76 (2026-10-05)
    spdx: MIT
    language: Python
    claim: "parses unknown binary blobs for more than 30 different archive, compression, and file-system formats,
      extracts their content recursively, and carves out unknown chunks"
    label: VERIFIED

  - id: ARC-RARFILE
    source: rarfile (PyPI + markokr/rarfile)
    url: https://pypi.org/pypi/rarfile/json ; https://github.com/markokr/rarfile
    latest_release: 4.5 (2026-08-02); observed head d2f7df6fc843dae356fd6b0a85971dc36fd6e757 (2026-08-23)
    spdx: ISC
    language: Python
    claim: the README states "Compressed files are extracted by executing external tool: unrar (preferred),
      unar, 7zip or bsdtar" — the Python package does not decompress by itself
    label: VERIFIED

  - id: ARC-BINWALK
    source: binwalk (ReFirmLabs/binwalk, Rust v3 line)
    url: https://github.com/ReFirmLabs/binwalk ; Cargo.toml and LICENSE read raw
    latest_release: Binwalk v3.1.0 (2024-10-31); Cargo.toml version 3.1.1; observed head
      26713972e3f9f52dc37d4a421c4554b0bd9e82ef (2026-08-11); repository is not archived
    spdx: MIT
    language: Rust
    claim: "Analyzes data for embedded file types"
    label: VERIFIED

  - id: ARC-PEFILE
    source: pefile (erocarrera/pefile)
    url: https://pypi.org/pypi/pefile/json ; https://github.com/erocarrera/pefile
    latest_release: 2024.8.26; observed head cc9f5501ba93938e505858eaa3230608b6fbc34f (2026-10-06)
    spdx: MIT
    language: Python
    maintenance: active on master despite no new tag since 2024-08
    label: VERIFIED

  - id: ARC-LIEF
    source: LIEF (lief-project/LIEF)
    url: https://pypi.org/pypi/lief/json ; https://github.com/lief-project/LIEF
    latest_release: 1.0.0 (2026-07-12); observed head 351d5f14a181c9537a8a5e724d2ea83a8f8e5c53 (2026-10-04)
    spdx: Apache-2.0
    language: C++ with Python bindings; requires_python >= 3.9
    label: VERIFIED

  - id: ARC-DNFILE
    source: dnfile (malwarefrank/dnfile — note the repository owner, which is not "malwaremuscles")
    url: https://pypi.org/pypi/dnfile/json ; https://github.com/malwarefrank/dnfile
    latest_release: v0.18.0 (2026-01-31); observed head bde05f174e10cc3df72eee45ff7189c1d9e2a28b (2026-07-26)
    spdx: MIT
    language: Python
    label: VERIFIED

  - id: ARC-PYELFTOOLS
    source: pyelftools (eliben/pyelftools)
    url: https://pypi.org/pypi/pyelftools/json ; https://github.com/eliben/pyelftools
    latest_release: v0.33 (2026-05-29); observed head 5a04389392e25d8128e1acb59828a0a85be791b1 (2026-10-08)
    spdx: LicenseRef-Public-Domain (the LICENSE file states pyelftools is in the public domain; the bundled
      pyelftools/construct subtree carries its own separate licence)
    language: Python
    label: VERIFIED

  - id: ARC-CAPA
    source: capa (mandiant/capa)
    url: https://github.com/mandiant/capa
    latest_release: v9.4.0 (2026-04-01); observed head d4cf889f20834f0418af38e9d46066048a4a72c5 (2026-10-06)
    spdx: Apache-2.0
    language: Python with Rust components
    claim: static capability identification over PE / ELF / .NET / shellcode; its dynamic mode consumes
      pre-existing sandbox reports rather than executing samples; the README states capa "cannot handle
      obfuscation well using static analysis"
    warning: the PyPI distribution named `capa` (0.1, 2016) is an unrelated squatter — only the GitHub project
      is the real tool
    label: VERIFIED

  - id: ARC-FLOSS
    source: FLOSS (mandiant/flare-floss)
    url: https://github.com/mandiant/flare-floss
    latest_release: "QUANTUMSTRAND beta 3" (2026-04-22) on the beta track; last stable v3.1.1 (2024-09-26)
    observed head 8617d875abae54f509e4cc39331e47cfcda8b11c (2026-10-07)
    spdx: Apache-2.0
    language: Python
    warning: the PyPI distribution named `floss` (0.1.0) is an unrelated squatter
    label: VERIFIED

  - id: ARC-DIE
    source: Detect-It-Easy (horsicq/Detect-It-Easy)
    url: https://github.com/horsicq/Detect-It-Easy ; LICENSE read raw
    latest_release: no versioned application tags are published — releases are database tags (db, db_extra,
      current-database, Beta), so the application version is UNVERIFIED
    observed head 2187432e81aed880c45da56284558b3645e95cfa (2026-10-08)
    spdx: MIT (the commonly assumed GPL is wrong)
    language: C++ (Qt)
    label: VERIFIED for licence and activity; application version UNVERIFIED

  - id: ARC-YARA
    source: YARA (VirusTotal/yara)
    url: https://github.com/VirusTotal/yara ; COPYING and README read raw
    latest_release: YARA v4.5.8 (2026-07-28); observed head 5e8a8ea41f73e4e24ec91382b7e6a697097b48aa (2026-09-23)
    spdx: BSD-3-Clause
    language: C
    claim: the README banner states "This project is in maintenance mode" and points at the YARA-X announcement
    label: VERIFIED

  - id: ARC-YARAX
    source: YARA-X (VirusTotal/yara-x) and its stability announcement
    url: https://github.com/VirusTotal/yara-x ; https://virustotal.github.io/yara-x/blog/yara-x-is-stable/
    latest_release: v1.21.0 (GitHub 2026-09-30; PyPI 1.21.0 2026-09-29); observed head
      b8e09cbedf5e0ca984cf36f5f956aaea5ae93a8d (2026-10-09)
    spdx: BSD-3-Clause (the commonly assumed Apache-2.0 is wrong)
    language: Rust (PyPI wheel available)
    claim: the blog "YARA-X is stable!" (2025-06-04) states 1.0.0 marked the end of the beta phase and that
      YARA-X is ready for production use; the README states VirusTotal runs it in production scanning billions
      of files
    label: VERIFIED

  - id: ARC-CLAMAV
    source: ClamAV (Cisco-Talos/clamav)
    url: https://github.com/Cisco-Talos/clamav ; COPYING.txt read raw
    latest_release: ClamAV 1.5.4 (2026-08-07; notes CVE-2026-20337 ZIP heap write and CVE-2026-20345 GPT
      out-of-bounds); observed head 72cd48c9faed4fa4afc22bc4ed0b9b19f8d3f8f7 (2026-08-27)
    spdx: GPL-2.0 (not GPL-3.0)
    language: C
    label: VERIFIED

  - id: ARC-SSDEEP
    source: ssdeep Python bindings (DinoTools/python-ssdeep)
    url: https://pypi.org/pypi/ssdeep/json ; https://github.com/DinoTools/python-ssdeep
    latest_release: PyPI 3.4 (2019-10-03); observed head 624ac7b6ec811294448d7335e1dc716c95c90009 (2021-12-21)
    spdx: LGPL-3.0-or-later
    maintenance: STALE — no commits since 2021-12
    label: VERIFIED

  - id: ARC-TLSH
    source: TLSH (trendmicro/tlsh) and the py-tlsh PyPI distribution
    url: https://pypi.org/pypi/py-tlsh/json ; https://github.com/trendmicro/tlsh
    latest_release: 5.0.0 (GitHub 2026-02-17; PyPI 2026-05-08); observed head
      ebdec8fde93a4ac359437f4f3796c78d3ae433bf (2026-07-10)
    spdx: dual Apache-2.0 OR BSD-2-Clause
    language: C++ with Python bindings; the current PyPI name is py-tlsh (python-tlsh is the older name)
    label: VERIFIED

  - id: ARC-PILLOW
    source: Pillow (python-pillow/Pillow) — LICENSE and src/PIL/Image.py read raw
    url: https://pypi.org/pypi/Pillow/json ; https://github.com/python-pillow/Pillow
    latest_release: 12.3.0 (2026-07-01); observed head 9b6d21995d8c21f3f1180fe7018391aa9a5f3cf8 (2026-10-09)
    spdx: MIT-CMU
    language: Python with C extensions
    claim: src/PIL/Image.py defines DecompressionBombWarning and DecompressionBombError and sets
      MAX_IMAGE_PIXELS = int(1024 * 1024 * 1024 // 4 // 3) — 89,478,485 pixels — with the warning text
      "Image size ({pixels} pixels) exceeds limit of {MAX_IMAGE_PIXELS} pixels, could be decompression bomb
      DOS attack."; beyond the hard limit it raises DecompressionBombError
    label: VERIFIED

  - id: ARC-EXIFREAD
    source: exifread (ianare/exif-py)
    url: https://pypi.org/pypi/exifread/json ; https://github.com/ianare/exif-py
    latest_release: 3.5.1 (2025-08-23); observed head a69bf74770caf6b333221658f5092ed69f99faac (2026-06-10)
    spdx: BSD-3-Clause
    language: Python
    label: VERIFIED

  - id: ARC-EXIFTOOL
    source: ExifTool (exiftool/exiftool) — README and exiftool.org
    url: https://github.com/exiftool/exiftool ; https://exiftool.org
    latest_release: 13.59 (2026-05-27); observed head 2200871d9cef988051d2a99d67df3bda6cbb30a8 (2026-05-27)
    spdx: dual Artistic-1.0 OR GPL (the README states the software is free under the same terms as Perl itself);
      no LICENSE file exists on GitHub and license.html on the site 404s, so the README is the only statement
    language: Perl
    label: VERIFIED

  - id: ARC-HACHOIR
    source: hachoir (vstinner/hachoir)
    url: https://pypi.org/pypi/hachoir/json ; https://github.com/vstinner/hachoir
    latest_release: 3.4.0 (2026-09-13); observed head 322a9447352e7b95e2d936743dea2bbee79c9ec2 (2026-09-13)
    spdx: GPL-2.0
    language: Python
    label: VERIFIED

  - id: PRIOR-STAGE1
    source: Stage-1 deliverable decisions (inherited, not re-verified here)
    ref: stage-1-landscape-and-rule-engine-decision.md — D-001 stack, D-004 Sigma-compatible content over a
      custom DSL, D-007 severity axes stay separate, D-008 no GPL/AGPL code copying, D-012 single-tenant now /
      multi-tenant-ready
    label: VERIFIED (document previously produced and reviewed in this repository)

  - id: PRIOR-STAGE2
    source: Stage-2 deliverable decisions (inherited, not re-verified here)
    ref: stage-2-canonical-event-and-mappings.md — canonical-event/v1 envelope and value-state model, lossless
      raw + unmapped[], three-level semantic classification, D2-018 reserving the document / archive_member /
      executable / artifact / artifact_finding categories for this stage, D2-024 schema_version gate
    label: VERIFIED (document previously produced and reviewed in this repository)

# Summary of §0
#   entries: 61
#   VERIFIED: 59   PARTIALLY VERIFIED: 2 (DOC-POPPLER, DOC-OPENPYXL — both blocked at the upstream host)
#   components with advisories found in fetched sources: TL-TSHARK (19 advisories fixed in 4.6.9),
#     TL-ORJSON (2 recursion advisories), TL-PANDAS (1 historical), ARC-CLAMAV (2 fixed in 1.5.4),
#     ARC-PY7ZR (release note "Fix multiple vulnerabilities" for 1.1.3)
#   abandoned or stalled: ID-MAGICBIN (2017, deprecated), ARC-SSDEEP (2021), TL-DRAIN3 (2025-02),
#     DOC-PDFID (no formal releases since 2025-03), ARC-BINWALK tagged releases (2024-10, master active)
#   re-licensing or licence corrections vs the prior working assumption: ARC-YARAX is BSD-3 (not Apache-2.0),
#     ARC-CLAMAV is GPL-2.0 (not GPL-3.0), ARC-DIE is MIT (not GPL), ARC-LIEV is LGPL-3.0-or-later (not GPL-3.0),
#     ID-LIBMAGIC reports NOASSERTION (the COPYING text is 2-clause BSD), ARC-PYELFTOOLS is public domain
```

---
