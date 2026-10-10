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
    claim: >-
      "[WindowsError: [Error 193]] = 32-bit libmagic DLL loaded by 64-bit Python"; README
      links third-party 64-bit Windows libmagic DLL distributions
    version_or_commit: README Troubleshooting section as of repository head d3396fd (2026-09-22)
    label: VERIFIED
    read: README.md Troubleshooting section
    licence: n/a (documentation excerpt from a MIT-licensed repo)


  - id: ID-MAGIKA
    source: Magika (google/magika) — content-type identification using an ONNX model
    url: https://github.com/google/magika
    default_branch: main
    latest_release: cli/v1.1.0, 2026-04-24
    observed_commit: 175a424adcc291cbe352dcb4fec92412835b9ccf (head 2026-10-09)
    spdx: >-
      Apache-2.0 (repository root; assets/models/standard_v3_3/ contains only
      README/config/metadata/model.onnx — no separate model-licence file was found, so the
      model is covered by the repository licence by inclusion)
    language: Rust (Python bindings published)
    maintenance: active (commit same day as retrieval)
    read: >-
      README.md (accuracy claim ~99% avg precision/recall over ~100M samples, 200+ types;
      paper ICSE 2025); assets/models/standard_v3_3/README.md (label table)
    label: VERIFIED (model-licence inference flagged in Q3-006)

  - id: ID-FILETYPE
    source: filetype.py (PyPI `filetype`, upstream h2non/filetype.py)
    url: https://github.com/h2non/filetype.py ; https://pypi.org/pypi/filetype/json
    latest_release: 1.2.0 (PyPI, 2022-11-02); observed commit 3eae5cedad2dc65076a501a9374abafb1d700602
    spdx: MIT
    language: Python
    maintenance: last upstream commit 2025-05-02 (weak); Go sibling project active
    label: VERIFIED
    read: PyPI JSON metadata; LICENSE; repository commit list


  - id: ID-PUREMAGIC
    source: puremagic (cdgriffith/puremagic) — pure-Python magic/mimetype identification
    url: https://github.com/cdgriffith/puremagic
    latest_release: 2.2.0 (2026-04-08); pushed_at 2026-04-09
    spdx: MIT
    language: Python
    maintenance: >-
      active; README states zero runtime dependencies, cross-platform, deep-scan mode since
      2.0, Python 3.12+ for the 2.x line
    label: VERIFIED
    read: repository LICENSE; README.rst; PyPI metadata


  - id: ID-MAGICBIN
    source: python-magic-bin (PyPI) — legacy Windows binary wheel for python-magic
    url: https://pypi.org/pypi/python-magic-bin/json
    latest_release: 0.4.14 (2017-10-02)
    claim: PyPI README states the project is deprecated and names a successor package
    maintenance: stale since 2017
    label: VERIFIED
    spdx: MIT
    read: PyPI JSON metadata and README (deprecation notice)


  - id: UP-FASTAPI
    source: FastAPI request-files documentation + Starlette formparsers source
    url: https://fastapi.tiangolo.com/tutorial/request-files/
    claim: >-
      UploadFile spools to a temporary file (memory until a limit, then disk); Starlette's
      MultiPartParser sets spool_max_size = 1024*1024 and constructs
      SpooledTemporaryFile(max_size=…)
    version_or_commit: >-
      FastAPI docs current as of retrieval; Starlette formparsers spool_max_size = 1024*1024
    label: VERIFIED
    read: FastAPI tutorial request-files page; starlette/formparsers.py (spool_max_size)
    licence: n/a (framework documentation)


  - id: UP-SPOOL
    source: Python `tempfile` documentation
    url: https://docs.python.org/3/library/tempfile.html
    claim: >-
      "data is spooled in memory until the file size exceeds max_size, or until the file's
      fileno() method is called, at which point the contents are written to disk";
      rollover() forces rollover
    version_or_commit: Python 3.14.8 documentation
    label: VERIFIED
    read: docs.python.org/3/library/tempfile.html SpooledTemporaryFile section
    licence: PSF-2.0 (CPython documentation)


  - id: UP-UVICORN
    source: uvicorn settings documentation (docs/settings.md) + Starlette requests documentation
    url: https://github.com/encode/uvicorn/blob/master/docs/settings.md
    claim: >-
      uvicorn's Resource Limits expose only limit-concurrency / limit-max-requests / backlog
      — no request-body size setting. Starlette form limits cover max_files / max_fields /
      max_part_size, and max_part_size applies to non-file fields; uploaded files are
      spooled and are NOT capped by it.
    version_or_commit: uvicorn docs current as of retrieval; Starlette form-multipart limits
    label: VERIFIED
    read: >-
      encode/uvicorn docs settings Resource Limits; encode/starlette docs requests form
      limits
    licence: n/a (framework documentation)


  - id: UP-MSNAME
    source: Microsoft Learn — "Naming files, paths, and namespaces"
    url: https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file (ms.date 2024-08-28)
    claim: >-
      reserved device names CON PRN AUX NUL COM1–COM9 LPT1–LPT9 (plus ISO-8859-1 superscript
      variants); invalid characters < > : " / \ | ? * plus NUL and code points 1–31; no
      trailing space or period; MAX_PATH 260 characters pre-Windows-10-1607 with
      registry/group-policy opt-out; \\?\ prefix disables parsing
    label: VERIFIED
    read: >-
      full page body: reserved-name table, invalid-character list, MAX_PATH and long-path
      guidance
    licence: n/a (Microsoft Learn documentation)
    version_or_commit: ms.date 2024-08-28; updated_at 2025-04-11


  - id: UP-MSADS
    source: "[MS-FSCC] File System Control Codes, protocol revision 60.0 (2025-11-21)"
    url: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8
    claim: >-
      §5.6.1 defines the Zone.Identifier stream name (fully qualified form
      sample.txt:Zone.Identifier:$DATA) whose contents are the text stream
      "[ZoneTransfer]\r\nZoneId=3"; §2.1.4 states the file system MAY support alternate data
      streams; the System.ZoneIdentifier property page documents the mark-of-the-web zone
    label: VERIFIED

  # ---------- TL: telemetry parsers and text carriers ----------
    read: >-
      MS-FSCC 5.6.1 Zone.Identifier stream name; 2.1.4 Alternate Data Streams;
      System.ZoneIdentifier property page
    licence: n/a (Microsoft Open Specifications)
    version_or_commit: "[MS-FSCC] protocol revision 60.0, published 2025-11-21"

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
    read: >-
      repository metadata; crates.io evtx entry; PyPI evtx 0.13.1 metadata; OSV query
      response


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
    read: repository metadata; PyPI python-evtx 0.8.1 metadata; OSV query response


  - id: TL-LIBEVTX
    source: libyal/libevtx (C library) — checked because it is the other frequently-cited EVTX option
    url: https://github.com/libyal/libevtx
    default_branch: main
    latest_release: 20260705
    spdx: LGPL-3.0-or-later (NOT plain GPL-3.0)
    language: C
    maintenance: active (pushed 2026-09-23)
    cves: no advisory found in OSV
    note: >-
      a PyPI package named `pyevtx` does NOT exist (pypi.org/pypi/pyevtx and the simple
      index both 404); libyal ships its own python bindings only in-tree
    label: VERIFIED
    read: repository README/licence; tag list; PyPI pyevtx 404 responses


  - id: TL-TSHARK
    source: TShark man page and Wireshark release notes
    url: https://www.wireshark.org/docs/man-pages/tshark.html ; https://www.wireshark.org/docs/relnotes/wireshark-4.6.9.html
    claim: >-
      the man page in force is "the manual page for TShark 4.6.9"; flags -T ek (newline-
      delimited JSON for Elasticsearch, one line per packet), -T fields, -T json, -Y, -l
      (line buffered), -e and -E are documented there
    latest_release: 4.6.9, tag 2d548b19, 2026-09-23 (previous stable line 4.4.19)
    spdx: GPL-2.0-or-later for Wireshark/TShark itself
    cves: >-
      4.6.9 release notes list wnpa-sec-2026-92…110 (19 advisories), including
      CVE-2026-96419 (profile import crash / possible code execution) and CVE-2026-96418
      (TIFF dissector infinite loop); 4.6.5 fixed CVE-2026-5402 (TLS dissector / possible
      code execution) and CVE-2026-5405 (RDP)
    label: VERIFIED
    read: >-
      wireshark.org docs man-pages tshark.html flag sections; relnotes wireshark-4.6.9.html
      wnpa-sec list


  - id: TL-ZEEK
    source: Zeek documentation set (Version 9.0.0) and the zeek/zeek repository
    url: https://docs.zeek.org/en/current/ ; https://docs.zeek.org/en/current/tutorial/logs.html
    latest_release: v9.0.0 (tag commit 970787a9f10896ff65c4758444d87bcf53eba4b7)
    observed_commit: 5b7c9c753a8e69da4a6dcd41e7a06c26226647dd (head 2026-10-09)
    spdx: repository reports NOASSERTION; COPYING is the BSD-style LBNL/ICSI variant
    language: C++
    maintenance: active
    claim: >-
      default logs are TSV with #separator / #fields / #types / #open / #close headers;
      zeek-cut extracts columns
    label: VERIFIED
    read: >-
      docs.zeek.org/en/current/ index; tutorial/logs.html; repository tag/commit metadata


  - id: TL-SURICATA
    source: Suricata EVE JSON format documentation and the OISF/suricata repository
    url: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html ; https://suricata.io/download/
    latest_release: 8.0.7 (2026-09-15); also published 7.0.13 / 8.0.6 / 8.0.5
    spdx: GPL-2.0
    language: C
    maintenance: active
    claim: >-
      JSON Lines, one event per line; common envelope fields timestamp, flow_id, event_type;
      per-event-type objects (alert, dns, http, fileinfo, tls, flow, …) selected by
      event_type
    cves: 14 historical OSS-Fuzz OSV entries; none in fetched sources for the current 8.0.x line
    label: VERIFIED
    read: >-
      docs.suricata.io/en/latest/output/eve/eve-json-format.html; suricata.io/download/


  - id: TL-RFC3164
    source: RFC 3164, "The BSD syslog Protocol" (August 2001)
    url: https://www.rfc-editor.org/rfc/rfc3164.txt ; https://www.rfc-editor.org/info/rfc3164
    standards_level: Informational; the info page states the RFC is obsolete, see RFC 5424
    copyright: Copyright (C) Internet Society 2001
    label: VERIFIED
    read: rfc-editor.org/rfc/rfc3164.txt; /info/rfc3164 (status and obsoleted-by)
    licence: IETF Trust / BCP 78
    version_or_commit: RFC 3164, August 2001, Informational


  - id: TL-RFC5424
    source: RFC 5424, "The Syslog Protocol" (March 2009)
    url: https://www.rfc-editor.org/rfc/rfc5424.txt ; https://www.rfc-editor.org/info/rfc5424
    standards_level: Proposed Standard; obsoletes RFC 3164
    copyright: IETF Trust / BCP 78
    label: VERIFIED
    read: rfc-editor.org/rfc/rfc5424.txt; /info/rfc5424 (standards level, obsoletes)
    licence: IETF Trust / BCP 78
    version_or_commit: RFC 5424, March 2009, Proposed Standard


  - id: TL-CEF
    source: >-
      "Implementing ArcSight Common Event Format (CEF) — Version 27", Micro Focus / Open
      Text
    url: https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-25.1/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf
    claim: syslog transport "<prefix> <CEF_header>|[Extension]"; header
      CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity; extension is
      space-delimited key=value with backslash-escaped pipes in values; UTF-8
    label: VERIFIED (vendor-published PDF fetched directly)
    read: >-
      full PDF fetched: header grammar, extension grammar, escape rules, encoding statement
    licence: n/a (vendor specification document; Micro Focus copyright)
    version_or_commit: Implementing CEF Version 27


  - id: TL-LEEF
    source: IBM QRadar "Log Event Extended Format (LEEF) Version 2"
    url: https://www.ibm.com/docs/en/dsm?topic=leef-overview ; https://www.ibm.com/docs/en/SS42VS_DSM/pdf/b_Leef_format_guide.pdf
    claim: >-
      header LEEF:Version|Vendor|Product|Version|EventID|; LEEF 1.0 and 2.0; optional syslog
      prefix; attributes key=value, tab-delimited by default, LEEF 2.0 supports a custom
      delimiter; UTF-8 required
    label: VERIFIED via IBM Docs HTML (the PDF URL returns 403 to unauthenticated automated fetch)
    read: >-
      IBM Docs HTML: leef-overview, leef-event-components, predefined-leef-event-attributes
    licence: n/a (vendor specification document; IBM copyright)
    version_or_commit: LEEF Version 2


  - id: TL-DEFUSEDXML
    source: defusedxml (PyPI)
    url: https://pypi.org/pypi/defusedxml/json ; https://github.com/tiran/defusedxml
    latest_release: 0.7.1 (2021-03-08)
    spdx: PSFL
    language: Python
    maintenance: >-
      last release 2021-03-08; stable/frozen rather than abandoned; still the XML entity-
      expansion defence recommended by the openpyxl docs
    cves: no advisory found in OSV
    label: VERIFIED
    read: PyPI JSON metadata; GitHub repository metadata


  - id: TL-ORJSON
    source: orjson (PyPI)
    url: https://pypi.org/pypi/orjson/json
    latest_release: 3.13.0
    spdx: MPL-2.0 AND (Apache-2.0 OR MIT)
    language: Rust (Python bindings)
    cves: >-
      GHSA-hx9q-6w63-j58v / CVE-2025-67221 and GHSA-pwr2-4v36-6qpr / CVE-2024-27454 — both
      "orjson does not limit recursion for deeply nested JSON documents" (advisories fetched
      from
      https://api.osv.dev/v1/vulns/…)
    label: VERIFIED
    read: >-
      PyPI JSON metadata; OSV advisory records GHSA-hx9q-6w63-j58v and GHSA-pwr2-4v36-6qpr


  - id: TL-IJSON
    source: ijson (PyPI)
    url: https://pypi.org/pypi/ijson/json
    latest_release: 3.5.1 (2026-07-06); Development Status 5
    spdx: BSD-3-Clause AND ISC
    cves: no advisory found in OSV
    label: VERIFIED
    read: PyPI JSON metadata; OSV query response


  - id: TL-PANDAS
    source: pandas (PyPI)
    url: https://pypi.org/pypi/pandas/json
    latest_release: 3.0.6 (2026-09-17); win_amd64 wheel present
    spdx: BSD-3-Clause (PyPI classifier not captured in this pass — see NOT_VERIFIED)
    cves: PYSEC-2020-73 / CVE-2020-13091, historical (2020), old-version pickle deserialization
    label: VERIFIED
    read: PyPI JSON metadata (incl. wheel list); OSV advisory PYSEC-2020-73


  - id: TL-POLARS
    source: polars (PyPI + simple index)
    url: https://pypi.org/pypi/polars/json ; https://pypi.org/simple/polars/
    latest_release: 2.0.0 (2026-10-06)
    spdx: MIT (PyPI classifier)
    claim: >-
      for 2.0.0 the package publishes only polars-2.0.0-py3-none-any.whl plus an sdist — no
      platform-native win_amd64 wheel under the `polars` distribution; the native engine is
      no longer bundled
    read: >-
      PyPI JSON metadata; GitHub README (streaming, lazy evaluation); OSV query response
    label: VERIFIED

  - id: TL-CSV
    source: Python `csv` module documentation (Python 3.14.8 docs)
    url: https://docs.python.org/3/library/csv.html
    claim: >-
      RFC 4180 referenced; default dialect csv.excel; options lineterminator / quoting /
      quotechar / delimiter; documentation instructs open(..., newline='') for correct line
      handling
    note: >-
      the word "smearing" does not appear on the fetched page — the multi-line-field hazard
      is a documented property of the module's quoting rules, not a quotable sentence
    label: VERIFIED
    read: >-
      docs.python.org/3/library/csv.html (dialect options, newline guidance, RFC 4180
      reference)
    licence: PSF-2.0 (CPython documentation)
    version_or_commit: Python 3.14.8 documentation


  - id: TL-DRAIN3
    source: Drain3 (logpai/Drain3) — streaming log template miner
    url: https://github.com/logpai/Drain3
    latest_release: no tag; head commit 0fb6d6e1828838fa05c8f6fa5cda878e02ea79c7 (2025-02-04)
    spdx: >-
      MIT (raw LICENSE.txt content is verbatim MIT; GitHub API reports NOASSERTION because
      the file is named LICENSE.txt)
    language: Python
    maintenance: ~8 months without a commit as of retrieval
    label: VERIFIED

  # ---------- DOC: document triage ----------
    read: repository LICENSE.txt (verbatim MIT text); commit history; OSV query response

  - id: DOC-PDFID
    source: pdfid.py / pdf-parser.py (Didier Stevens Suite)
    url: https://blog.didierstevens.com/programs/pdf-tools ; https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdfid.py
    version: __version__ 0.2.10, __date__ 2025/03/05 (read from the source header)
    spdx: >-
      "Source code put in public domain by Didier Stevens, no Copyright" (source header)
    language: Python
    claim: >-
      parse-only. The blog states pdf-parser.py "will not render a PDF document"; pdfid.py
      counts /JS /JavaScript /OpenAction /Launch /RichMedia /EmbeddedFile /XFA keywords and
      has a disarm rewriter
    label: VERIFIED (version read from source; no formal git tag exists)
    read: >-
      blog.didierstevens.com/programs/pdf-tools; full pdfid.py source (version header,
      keyword list, disarm option)


  - id: DOC-PIKEPDF
    source: pikepdf (PyPI + GitHub)
    url: https://pypi.org/project/pikepdf/ ; https://github.com/pikepdf/pikepdf
    latest_release: 10.16.0 (2026-09-29)
    observed_commit: 23290bd753eaf3feeaa265da9a191c6d1cd54612 (PyPI attestation)
    spdx: MPL-2.0 (bindings) over qpdf (C++); qpdf itself Apache-2.0 (see DOC-QPDF)
    language: Python + C++
    claim: parse / repair / manipulate; README states it is "not what you want if you need to render PDFs to images"
    label: VERIFIED
    read: PyPI project page; GitHub README (rendering disclaimer)


  - id: DOC-PYPDF
    source: pypdf (PyPI + GitHub)
    url: https://pypi.org/project/pypdf/ ; https://github.com/py-pdf/pypdf
    latest_release: 6.19.0 (2026-09-16); observed commit d62cb58d3988b291b0435eddfd118c4f8f6b6a46
    spdx: BSD-3-Clause
    language: Python (pure)
    claim: parse / merge / split / crop and text extraction; no rendering engine
    label: VERIFIED
    read: PyPI project page; GitHub README


  - id: DOC-PDFMINER
    source: pdfminer.six (PyPI + GitHub)
    url: https://pypi.org/project/pdfminer.six/ ; https://github.com/pdfminer/pdfminer.six
    latest_release: 20260107 (2026-01-07)
    spdx: MIT
    language: Python (pure)
    claim: parse-only; extracts text / images / html / hOCR from PDF source
    label: VERIFIED
    read: PyPI project page; GitHub README


  - id: DOC-QPDF
    source: qpdf (GitHub + readthedocs)
    url: https://github.com/qpdf/qpdf ; https://qpdf.readthedocs.io/en/latest/encryption.html
    latest_release: v12.4.2 (2026-09-27); observed commit 4eba95899886e851cc41d76886483b347612f2a8
    spdx: Apache-2.0 (LICENSE.txt fetched in full)
    language: C++
    claim: >-
      parse / transform / decrypt; the standard security handler supports password-based
      decryption; no rendering
    label: VERIFIED
    read: LICENSE.txt (Apache-2.0 full text); releases page; readthedocs encryption.html


  - id: DOC-PYMUPDF
    source: PyMuPDF (PyPI + GitHub + COPYING)
    url: https://pypi.org/project/PyMuPDF/ ; https://raw.githubusercontent.com/pymupdf/PyMuPDF/main/COPYING
    latest_release: 1.28.2 (2026-08-06)
    spdx: AGPL-3.0 (COPYING is the full GNU AGPL v3 text); a commercial licence is offered separately
    language: Python + C (MuPDF)
    claim: CAN RENDER — README shows page.get_pixmap(dpi=150) and OCR
    label: VERIFIED
    read: >-
      GitHub README (licensing and rendering examples); COPYING (full AGPL-3.0 text); PyPI
      page


  - id: DOC-PDFIUM2
    source: pypdfium2 (GitHub releases + LICENSES/)
    url: https://github.com/pypdfium2-team/pypdfium2/releases ; https://github.com/pypdfium2-team/pypdfium2/tree/main/LICENSES
    latest_release: 5.14.0 (2026-10-04); observed commit 21f85e273036f3bade4f67d896e1d05927e5f4b1
    spdx: >-
      multi-license — BSD-3-Clause (wrapper) + Apache-2.0 (PDFium) + LGPL-3.0-or-later
      (freetype and others) + MPL-2.0 + MIT + CC-BY-4.0, enumerated in LICENSES/
    claim: CAN RENDER (release notes reference PdfBitmap / FPDFBitmap_Destroy / PdfDocument.render)
    note: the PyPI project page was bot-challenged; version, commit and licences were read from GitHub
    label: VERIFIED
    read: >-
      GitHub releases page (5.14.0 notes, render API references); LICENSES/ directory
      listing


  - id: DOC-POPPLER
    source: Poppler / poppler-utils `pdftotext`
    url: >-
      https://manpages.debian.org/bookworm/poppler-utils/pdftotext.1.en.html ; COPYING via
      the Skia third_party/poppler mirror (gitlab.freedesktop.org itself refused automated
      retrieval)
    latest_release: Poppler-26.09.0 per the Linux From Scratch page; Debian bookworm ships 22.12.0
    spdx: GPL-2.0-only
    language: C++
    claim: parse-only text/layout extraction; does not execute JavaScript
    read: >-
      Debian manpages pdftotext.1; COPYING via the Debian source mirror; Linux From Scratch
      version note
    label: PARTIALLY VERIFIED (licence and behaviour via mirrors; official repository branch/commit not opened)

  - id: DOC-OPENPYXL
    source: openpyxl documentation
    url: https://openpyxl.readthedocs.io/en/stable/ ; https://openpyxl.readthedocs.io/en/stable/optimized.html
    latest_release: 3.1.5 (PyPI, prior session)
    spdx: MIT/Expat (documentation index)
    language: Python
    claim: >-
      read_only=True uses lazy loading over a ReadOnlyWorksheet and requires wb.close(); the
      docs carry a security note recommending defusedxml against billion-laughs attacks;
      macros are not executed
    read: >-
      openpyxl.readthedocs.io stable index and optimise-docs page (read_only/lazy loading
      behaviour)
    label: >-
      PARTIALLY VERIFIED (documentation and licence read; the upstream repository —
      foss.heptapod.net — refused automated retrieval and the GitHub mirror 404s, so
      branch/commit are unrecorded)

  - id: DOC-DOCX
    source: python-docx (PyPI + GitHub)
    url: https://pypi.org/project/python-docx/ ; https://github.com/python-openxml/python-docx
    latest_release: 1.2.0 (2025-06-16)
    spdx: MIT
    language: Python
    claim: parse / create / update .docx; no rendering, no macro execution
    label: VERIFIED
    read: PyPI project page; GitHub README


  - id: DOC-PPTX
    source: python-pptx (PyPI + GitHub)
    url: https://pypi.org/project/python-pptx/ ; https://github.com/scanny/python-pptx
    latest_release: 1.0.2 (2024-08-07)
    spdx: MIT
    language: Python
    claim: README states it does not require PowerPoint to be installed or licensed; no rendering
    label: VERIFIED
    read: PyPI project page (1.0.2); GitHub README (no PowerPoint required statement)


  - id: DOC-OLEFILE
    source: olefile (decalage2/olefile)
    url: https://github.com/decalage2/olefile
    latest_release: v0.47 (2023-12-01, from the README news section)
    spdx: BSD-2-Clause-style custom terms (plus a PIL licence portion), full text in the README
    language: Python
    claim: parse / read / write OLE2 compound files; no rendering
    label: VERIFIED
    read: GitHub README (full licence text, feature list, news/release section)


  - id: DOC-OLETOOLS
    source: oletools (decalage2/oletools)
    url: https://github.com/decalage2/oletools
    latest_release: v0.60.3 (2025-05-22, README news section)
    spdx: BSD-2-Clause-style custom terms + MIT for officeparser portions
    language: Python
    claim: >-
      analysis / forensics; extracts VBA macros, XLM macros, DDE links and embedded objects;
      does not execute them
    label: VERIFIED
    read: GitHub README (full licence text, per-tool descriptions, news/release section)


  - id: DOC-MSOFFCRYPTO
    source: msoffcrypto-tool (PyPI + GitHub)
    url: https://pypi.org/project/msoffcrypto-tool/ ; https://github.com/nolze/msoffcrypto-tool
    latest_release: 6.0.0 (2026-01-12)
    spdx: MIT
    language: Python
    claim: >-
      decrypt / encrypt Microsoft Office files — OOXML agile and standard, RC4, RC4
      CryptoAPI, XOR obfuscation and legacy Office 95 schemes
    label: VERIFIED
    read: PyPI project page (6.0.0, supported encryption methods); GitHub README


  - id: DOC-XLM
    source: XLMMacroDeobfuscator (DissectMalware/XLMMacroDeobfuscator)
    url: https://github.com/DissectMalware/XLMMacroDeobfuscator
    spdx: Apache-2.0
    language: Python
    claim: uses an internal XLM emulator to interpret macros "without fully performing the code"
    label: VERIFIED (release tag not observed — see NOT_VERIFIED)
    read: GitHub README (emulator description, CLI and library usage)
    licence: Apache-2.0
    version_or_commit: no release tag observed; 451 commits


  - id: DOC-STRIPRTF
    source: striprtf (PyPI + GitHub)
    url: https://pypi.org/project/striprtf/ ; https://github.com/joshy/striprtf
    latest_release: 0.0.33 (2026-08-17)
    spdx: BSD-3-Clause
    language: Python
    claim: converts RTF to plain text via rtf_to_text(); parse-only, no rendering
    label: VERIFIED
    read: PyPI project page; GitHub README (rtf_to_text purpose)


  - id: DOC-ONENOTE
    source: OneNote parsers — DissectMalware/pyOneNote and volexity/one-extract
    url: https://github.com/DissectMalware/pyOneNote ; https://github.com/volexity/one-extract
    spdx: Apache-2.0 (pyOneNote) and BSD-3-Clause (one-extract)
    claim: >-
      both are parse / extract tools for .one containers that dump embedded files and
      metadata; neither renders. pyOneNote's last PyPI release is 0.0.2 (2023-03); one-
      extract describes itself as an interim solution created in response to malspam .one
      campaigns
    label: VERIFIED for existence, licence and stated purpose; maturity is weak (see Q3-014)
    read: GitHub READMEs for pyOneNote and one-extract (stated purpose and maturity)
    version_or_commit: pyOneNote PyPI 0.0.2 (2023-03); one-extract repo created 2023-09


  - id: DOC-TIKA
    source: Apache Tika documentation (4.1.x) including its security page
    url: https://tika.apache.org/docs/4.1.x/security.html ; https://tika.apache.org/download.html
    latest_release: 4.1.0 (2026-09-29); 3.x maintenance line at 3.3.2; docs built from commit 5cba7bc3b
    spdx: Apache-2.0
    language: Java
    claim: >-
      the security page states that neither tika-server nor tika-grpc is a security boundary
      and that they must only ever be exposed to trusted callers; in-process
      AutoDetectParser denial of service is explicitly described as "not a security
      vulnerability"; process isolation (pipes / forked JVMs) is the intended sandbox
    label: VERIFIED
    read: >-
      tika.apache.org homepage; download.html; docs/4.1.x/index.html;
      docs/4.1.x/security.html (security model and trust boundary)


  - id: DOC-MOTW
    source: Microsoft Open Specifications [MS-FSCC] (same protocol set as UP-MSADS)
    url: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e2b19412-a925-4360-b009-86e3b8a020c8
    claim: >-
      the Zone.Identifier stream is the mark-of-the-web carrier; contents are the text
      stream "[ZoneTransfer]\r\nZoneId=3"; the zone is persisted through the Attachment
      Execution Service
    label: VERIFIED

  # ---------- ARC: archive, binary and generic triage ----------
    read: MS-FSCC Zone.Identifier stream page; ms-fscc main index (revision)
    licence: n/a (Microsoft Open Specifications)
    version_or_commit: "[MS-FSCC] revision 60.0; Zone.Identifier page updated 2025-04-07"

  - id: ARC-ZIPFILE
    source: CPython `zipfile` documentation (Doc/library/zipfile.rst on the main branch)
    url: https://raw.githubusercontent.com/python/cpython/main/Doc/library/zipfile.rst
    claim: >-
      a "Resources limitations" section states "decompression bombs (aka ZIP bomb) apply to
      zipfile library that can cause disk volume exhaustion"; zipfile.Path exists;
      extracting the same archive twice overwrites files without asking
    note: no built-in expansion guard is documented — Sentinel must supply its own (§10)
    label: VERIFIED
    read: >-
      Doc/library/zipfile.rst Resources limitations, Path objects, default extraction
      behaviour
    spdx: PSF-2.0 (CPython stdlib)
    licence: PSF-2.0
    version_or_commit: CPython main branch documentation


  - id: ARC-TARFILE
    source: CPython `tarfile` documentation (Doc/library/tarfile.rst)
    url: https://raw.githubusercontent.com/python/cpython/main/Doc/library/tarfile.rst
    claim: >-
      extraction filters were added in 3.12 (PEP 706); "Since Python 3.14, the default
      (data) will prevent the most dangerous security issues. However, it will not prevent
      *all* unintended or insecure behavior."; data_filter refuses absolute/outside-
      destination link targets, device files, strips group/other execute bits and nulls
      uid/gid/uname/gname; link targets normalized from 3.15
    label: VERIFIED
    read: >-
      Doc/library/tarfile.rst Extraction filters section (versionadded 3.12, PEP 706,
      data_filter semantics, 3.14 default note)
    spdx: PSF-2.0 (CPython stdlib)
    licence: PSF-2.0
    version_or_commit: CPython main branch documentation


  - id: ARC-PY7ZR
    source: py7zr (PyPI + miurahr/py7zr)
    url: https://pypi.org/pypi/py7zr/json ; https://github.com/miurahr/py7zr
    latest_release: >-
      1.1.3 (2026-06-19, release note "Fix multiple vulnerabilities"); observed head
      62255f06ab9a37295b06fe7e412c0a4bc7f5d7e7 (2026-09-17)
    spdx: LGPL-2.1-or-later
    language: Python (pure)
    maintenance: active
    label: VERIFIED
    read: >-
      PyPI JSON metadata; GitHub LICENSE (LGPL 2.1 text); commits atom feed; release notes
      for 1.1.3


  - id: ARC-LIBARCHIVE
    source: libarchive-c (Changaco/python-libarchive-c — the distribution name differs from the repository name)
    url: https://pypi.org/pypi/libarchive-c/json ; repository Changaco/python-libarchive-c
    latest_release: 5.3 (2025-05-22); observed head 7e8cb8556e45d4b22ba7b0726fb640ef6253cfcc
    spdx: CC0-1.0 for the Python ctypes binding; the underlying libarchive C library is BSD-3-Clause
    language: Python (ctypes binding)
    maintenance: quiet since 2025-05
    read: PyPI JSON metadata; GitHub repository metadata; commits atom
    label: VERIFIED

  - id: ARC-7ZIP
    source: 7-Zip (7-zip.org license text + download page + ip7z/7zip)
    url: https://7-zip.org/license.txt ; https://7-zip.org/download.html ; https://github.com/ip7z/7zip
    latest_release: 26.04 (site dated 2026-10-05; head 9128b80e3a471108678e2b3ec3c985861c8d7b0f, 2026-10-06)
    licence_quote: >-
      7z.dll: The 'GNU LGPL' as main license for most of the code; The 'GNU LGPL' with
      'unRAR license restriction' for some code; The 'BSD 3-clause License' for some code;
      The 'BSD 2-clause License' for some code
    claim: >-
      the official Linux x86-64 console tarball was downloaded and listed; it contains the
      binaries 7zz and 7zzs plus License.txt and MANUAL/
    label: VERIFIED
    spdx: >-
      LGPL-2.1-or-later (7z.dll main) + unRAR licence restriction on some code +
      BSD-2/3-Clause on some code
    read: >-
      7-zip.org/license.txt; 7-zip.org/download.html; official linux-x64 console tarball
      listing
    licence: LGPL-2.1-or-later with unRAR restriction (see spdx)


  - id: ARC-UNBLOB
    source: unblob (onekey-sec/unblob — the spotify/ URL no longer resolves)
    url: https://github.com/onekey-sec/unblob ; https://unblob.org
    latest_release: 26.6.4 (2026-06-04); observed head 8c68fe29b7dbe27d323632bc1d770409a076be76 (2026-10-05)
    spdx: MIT
    language: Python
    claim: >-
      parses unknown binary blobs for more than 30 different archive, compression, and file-
      system formats, extracts their content recursively, and carves out unknown chunks
    label: VERIFIED
    read: GitHub LICENSE (MIT); commits atom; unblob.org capability description


  - id: ARC-RARFILE
    source: rarfile (PyPI + markokr/rarfile)
    url: https://pypi.org/pypi/rarfile/json ; https://github.com/markokr/rarfile
    latest_release: 4.5 (2026-08-02); observed head d2f7df6fc843dae356fd6b0a85971dc36fd6e757 (2026-08-23)
    spdx: ISC
    language: Python
    claim: >-
      the README states "Compressed files are extracted by executing external tool: unrar
      (preferred), unar, 7zip or bsdtar" — the Python package does not decompress by itself
    label: VERIFIED
    read: >-
      PyPI JSON and README (external-tool extraction statement); GitHub LICENSE (ISC);
      commits atom


  - id: ARC-BINWALK
    source: binwalk (ReFirmLabs/binwalk, Rust v3 line)
    url: https://github.com/ReFirmLabs/binwalk ; Cargo.toml and LICENSE read raw
    latest_release: >-
      Binwalk v3.1.0 (2024-10-31); Cargo.toml version 3.1.1; observed head
      26713972e3f9f52dc37d4a421c4554b0bd9e82ef (2026-08-11); repository is not archived
    spdx: MIT
    language: Rust
    claim: "Analyzes data for embedded file types"
    label: VERIFIED
    read: >-
      GitHub HTML repository page; raw Cargo.toml; raw LICENSE; commits atom; releases atom


  - id: ARC-PEFILE
    source: pefile (erocarrera/pefile)
    url: https://pypi.org/pypi/pefile/json ; https://github.com/erocarrera/pefile
    latest_release: 2024.8.26; observed head cc9f5501ba93938e505858eaa3230608b6fbc34f (2026-10-06)
    spdx: MIT
    language: Python
    maintenance: active on master despite no new tag since 2024-08
    label: VERIFIED
    read: PyPI JSON; raw LICENSE (MIT); commits atom; releases atom


  - id: ARC-LIEF
    source: LIEF (lief-project/LIEF)
    url: https://pypi.org/pypi/lief/json ; https://github.com/lief-project/LIEF
    latest_release: 1.0.0 (2026-07-12); observed head 351d5f14a181c9537a8a5e724d2ea83a8f8e5c53 (2026-10-04)
    spdx: Apache-2.0
    language: C++ with Python bindings; requires_python >= 3.9
    label: VERIFIED
    read: PyPI JSON; raw LICENSE (Apache-2.0); commits atom; releases atom


  - id: ARC-DNFILE
    source: dnfile (malwarefrank/dnfile — note the repository owner, which is not "malwaremuscles")
    url: https://pypi.org/pypi/dnfile/json ; https://github.com/malwarefrank/dnfile
    latest_release: v0.18.0 (2026-01-31); observed head bde05f174e10cc3df72eee45ff7189c1d9e2a28b (2026-07-26)
    spdx: MIT
    language: Python
    label: VERIFIED
    read: PyPI JSON; raw LICENSE (MIT); commits atom


  - id: ARC-PYELFTOOLS
    source: pyelftools (eliben/pyelftools)
    url: https://pypi.org/pypi/pyelftools/json ; https://github.com/eliben/pyelftools
    latest_release: v0.33 (2026-05-29); observed head 5a04389392e25d8128e1acb59828a0a85be791b1 (2026-10-08)
    spdx: >-
      LicenseRef-Public-Domain (the LICENSE file states pyelftools is in the public domain;
      the bundled pyelftools/construct subtree carries its own separate licence)
    language: Python
    label: VERIFIED
    read: >-
      PyPI JSON; raw LICENSE (public-domain statement + bundled construct note); commits
      atom; releases atom


  - id: ARC-CAPA
    source: capa (mandiant/capa)
    url: https://github.com/mandiant/capa
    latest_release: v9.4.0 (2026-04-01); observed head d4cf889f20834f0418af38e9d46066048a4a72c5 (2026-10-06)
    spdx: Apache-2.0
    language: Python with Rust components
    claim: >-
      static capability identification over PE / ELF / .NET / shellcode; its dynamic mode
      consumes pre-existing sandbox reports rather than executing samples; the README states
      capa "cannot handle obfuscation well using static analysis"
    warning: >-
      the PyPI distribution named `capa` (0.1, 2016) is an unrelated squatter — only the
      GitHub project is the real tool
    label: VERIFIED
    read: >-
      GitHub repository page; raw LICENSE.txt (Apache-2.0); README.md (static-analysis and
      obfuscation statements); releases atom


  - id: ARC-FLOSS
    source: FLOSS (mandiant/flare-floss)
    url: https://github.com/mandiant/flare-floss
    latest_release: >-
      "QUANTUMSTRAND beta 3" (2026-04-22) on the beta track; last stable v3.1.1 (2024-09-26)
    observed head: 8617d875abae54f509e4cc39331e47cfcda8b11c (2026-10-07)
    spdx: Apache-2.0
    language: Python
    warning: the PyPI distribution named `floss` (0.1.0) is an unrelated squatter
    label: VERIFIED
    read: raw LICENSE.txt (Apache-2.0); releases atom; commits atom


  - id: ARC-DIE
    source: Detect-It-Easy (horsicq/Detect-It-Easy)
    url: https://github.com/horsicq/Detect-It-Easy ; LICENSE read raw
    latest_release: >-
      no versioned application tags are published — releases are database tags (db,
      db_extra, current-database, Beta), so the application version is UNVERIFIED
    observed head: 2187432e81aed880c45da56284558b3645e95cfa (2026-10-08)
    spdx: MIT (the commonly assumed GPL is wrong)
    language: C++ (Qt)
    label: VERIFIED for licence and activity; application version UNVERIFIED
    read: raw LICENSE (MIT); releases atom (database tags only); commits atom


  - id: ARC-YARA
    source: YARA (VirusTotal/yara)
    url: https://github.com/VirusTotal/yara ; COPYING and README read raw
    latest_release: YARA v4.5.8 (2026-07-28); observed head 5e8a8ea41f73e4e24ec91382b7e6a697097b48aa (2026-09-23)
    spdx: BSD-3-Clause
    language: C
    claim: the README banner states "This project is in maintenance mode" and points at the YARA-X announcement
    label: VERIFIED
    read: >-
      raw COPYING (BSD-3-Clause); raw README.md (maintenance-mode banner); releases atom


  - id: ARC-YARAX
    source: YARA-X (VirusTotal/yara-x) and its stability announcement
    url: https://github.com/VirusTotal/yara-x ; https://virustotal.github.io/yara-x/blog/yara-x-is-stable/
    latest_release: >-
      v1.21.0 (GitHub 2026-09-30; PyPI 1.21.0 2026-09-29); observed head
      b8e09cbedf5e0ca984cf36f5f956aaea5ae93a8d (2026-10-09)
    spdx: BSD-3-Clause (the commonly assumed Apache-2.0 is wrong)
    language: Rust (PyPI wheel available)
    claim: >-
      the blog "YARA-X is stable!" (2025-06-04) states 1.0.0 marked the end of the beta
      phase and that YARA-X is ready for production use; the README states VirusTotal runs
      it in production scanning billions of files
    label: VERIFIED
    read: >-
      raw LICENSE (BSD-3-Clause); raw README.md; blog yara-x-is-stable; releases atom; PyPI
      metadata


  - id: ARC-CLAMAV
    source: ClamAV (Cisco-Talos/clamav)
    url: https://github.com/Cisco-Talos/clamav ; COPYING.txt read raw
    latest_release: >-
      ClamAV 1.5.4 (2026-08-07; notes CVE-2026-20337 ZIP heap write and CVE-2026-20345 GPT
      out-of-bounds); observed head 72cd48c9faed4fa4afc22bc4ed0b9b19f8d3f8f7 (2026-08-27)
    spdx: GPL-2.0 (not GPL-3.0)
    language: C
    label: VERIFIED
    read: >-
      raw COPYING.txt (GPL v2 text); releases atom (1.5.4 notes, CVE list); commits atom


  - id: ARC-SSDEEP
    source: ssdeep Python bindings (DinoTools/python-ssdeep)
    url: https://pypi.org/pypi/ssdeep/json ; https://github.com/DinoTools/python-ssdeep
    latest_release: PyPI 3.4 (2019-10-03); observed head 624ac7b6ec811294448d7335e1dc716c95c90009 (2021-12-21)
    spdx: LGPL-3.0-or-later
    maintenance: STALE — no commits since 2021-12
    label: VERIFIED
    read: PyPI JSON; raw LICENSE (LGPL v3 text); commits atom (last commit 2021-12)


  - id: ARC-TLSH
    source: TLSH (trendmicro/tlsh) and the py-tlsh PyPI distribution
    url: https://pypi.org/pypi/py-tlsh/json ; https://github.com/trendmicro/tlsh
    latest_release: >-
      5.0.0 (GitHub 2026-02-17; PyPI 2026-05-08); observed head
      ebdec8fde93a4ac359437f4f3796c78d3ae433bf (2026-07-10)
    spdx: dual Apache-2.0 OR BSD-2-Clause
    language: C++ with Python bindings; the current PyPI name is py-tlsh (python-tlsh is the older name)
    label: VERIFIED
    read: PyPI JSON (py-tlsh); raw LICENSE (dual Apache/BSD grant); releases atom


  - id: ARC-PILLOW
    source: Pillow (python-pillow/Pillow) — LICENSE and src/PIL/Image.py read raw
    url: https://pypi.org/pypi/Pillow/json ; https://github.com/python-pillow/Pillow
    latest_release: 12.3.0 (2026-07-01); observed head 9b6d21995d8c21f3f1180fe7018391aa9a5f3cf8 (2026-10-09)
    spdx: MIT-CMU
    language: Python with C extensions
    claim: >-
      src/PIL/Image.py defines DecompressionBombWarning and DecompressionBombError and sets
      MAX_IMAGE_PIXELS = int(1024 * 1024 * 1024 // 4 // 3) — 89,478,485 pixels — with the
      warning text "Image size ({pixels} pixels) exceeds limit of {MAX_IMAGE_PIXELS} pixels,
      could be decompression bomb DOS attack."; beyond the hard limit it raises
      DecompressionBombError
    label: VERIFIED
    read: >-
      PyPI JSON; raw LICENSE (MIT-CMU); src/PIL/Image.py (DecompressionBomb* classes,
      MAX_IMAGE_PIXELS constant and warning text)


  - id: ARC-EXIFREAD
    source: exifread (ianare/exif-py)
    url: https://pypi.org/pypi/exifread/json ; https://github.com/ianare/exif-py
    latest_release: 3.5.1 (2025-08-23); observed head a69bf74770caf6b333221658f5092ed69f99faac (2026-06-10)
    spdx: BSD-3-Clause
    language: Python
    label: VERIFIED
    read: PyPI JSON; raw LICENSE (BSD-3-Clause); commits atom; releases atom


  - id: ARC-EXIFTOOL
    source: ExifTool (exiftool/exiftool) — README and exiftool.org
    url: https://github.com/exiftool/exiftool ; https://exiftool.org
    latest_release: 13.59 (2026-05-27); observed head 2200871d9cef988051d2a99d67df3bda6cbb30a8 (2026-05-27)
    spdx: >-
      dual Artistic-1.0 OR GPL (the README states the software is free under the same terms
      as Perl itself); no LICENSE file exists on GitHub and license.html on the site 404s,
      so the README is the only statement
    language: Perl
    label: VERIFIED
    read: >-
      raw README (licence statement, release notes); exiftool.org homepage; releases atom;
      commits atom


  - id: ARC-HACHOIR
    source: hachoir (vstinner/hachoir)
    url: https://pypi.org/pypi/hachoir/json ; https://github.com/vstinner/hachoir
    latest_release: 3.4.0 (2026-09-13); observed head 322a9447352e7b95e2d936743dea2bbee79c9ec2 (2026-09-13)
    spdx: GPL-2.0
    language: Python
    label: VERIFIED
    read: PyPI JSON; raw COPYING (GPL v2 text); commits atom; releases atom


  - id: PRIOR-STAGE1
    source: Stage-1 deliverable decisions (inherited, not re-verified here)
    ref: >-
      stage-1-landscape-and-rule-engine-decision.md — D-001 stack, D-004 Sigma-compatible
      content over a custom DSL, D-007 severity axes stay separate, D-008 no GPL/AGPL code
      copying, D-012 single-tenant now / multi-tenant-ready
    label: VERIFIED (document previously produced and reviewed in this repository)
    url: stage-1-landscape-and-rule-engine-decision.md (sibling file in this repository)
    licence: n/a (Sentinel-authored deliverable)
    read: D-001, D-004, D-007, D-008, D-012 decision records
    version_or_commit: produced 2026-10-08


  - id: PRIOR-STAGE2
    source: Stage-2 deliverable decisions (inherited, not re-verified here)
    ref: >-
      stage-2-canonical-event-and-mappings.md — canonical-event/v1 envelope and value-state
      model, lossless raw + unmapped[], three-level semantic classification, D2-018
      reserving the document / archive_member / executable / artifact / artifact_finding
      categories for this stage, D2-024 schema_version gate
    label: VERIFIED (document previously produced and reviewed in this repository)

# Summary of §0
#   entries: 75
#   VERIFIED: 73   PARTIALLY VERIFIED: 2 (DOC-POPPLER, DOC-OPENPYXL — both blocked at the upstream host)
#   components with advisories found in fetched sources: TL-TSHARK (19 advisories fixed in 4.6.9),
#     TL-ORJSON (2 recursion advisories), TL-PANDAS (1 historical), ARC-CLAMAV (2 fixed in 1.5.4),
#     ARC-PY7ZR (release note "Fix multiple vulnerabilities" for 1.1.3)
#   abandoned or stalled: ID-MAGICBIN (2017, deprecated), ARC-SSDEEP (2021), TL-DRAIN3 (2025-02),
#     DOC-PDFID (no formal releases since 2025-03), ARC-BINWALK tagged releases (2024-10, master active)
#   re-licensing or licence corrections vs the prior working assumption: ARC-YARAX is BSD-3 (not Apache-2.0),
#     ARC-CLAMAV is GPL-2.0 (not GPL-3.0), ARC-DIE is MIT (not GPL), ARC-LIEV is LGPL-3.0-or-later (not GPL-3.0),
#     ID-LIBMAGIC reports NOASSERTION (the COPYING text is 2-clause BSD), ARC-PYELFTOOLS is public domain
    url: >-
      stage-2-canonical-event-and-mappings.md and canonical_event_v1.schema.json (sibling
      files)
    licence: n/a (Sentinel-authored deliverable)
    read: >-
      Field Dictionary 1, Semantic Classification Spec 4,
      D2-001/D2-004/D2-012/D2-018/D2-024, schema defs
    version_or_commit: produced 2026-10-09


  - id: FX-CATALOGUE
    source: >-
      Sentinel Stage-3 adversarial fixture catalogue (section 11) - internally defined, not
      an external source
    url: this document, section 11 Attack Fixture Catalogue
    version_or_commit: 240 named fixtures across categories A-H, 30 per category
    licence: >-
      n/a (Sentinel-authored test corpus specification; fixture files themselves are built
      in Stage 4)
    read: >-
      cross-checked every fixture id cited in DECISIONS evidence arrays against the section
      11 tables
    claim: >-
      Fixture ids cited in DECISIONS evidence arrays (e.g. FX-A-27, FX-C-23) are references
      into section 11, not into an external source. Each fixture maps to at least one
      normative assertion in sections 1, 2, 5, 6, 7, 9 or 10.
    label: VERIFIED (internally defined; the corpus has not yet been built - see Q3-002)
```

---

## 1. Upload Gate Spec

The upload gate is the only synchronous path in Sentinel that touches
attacker-supplied bytes while an HTTP request is open. Everything expensive,
everything recursive and everything that touches a third-party parser happens
later, in the triage worker. The gate therefore does exactly five things and
nothing else: authenticate, bound, sanitise names, fingerprint, persist.

**Normative vocabulary.** MUST / MUST NOT / SHOULD / MAY per RFC 2119. Every
limit below is `PROPOSED - TO BENCHMARK` with a fixture reference (§11) or a
benchmark method attached.

### 1.1 Surface

| Item | Specification |
|---|---|
| Endpoint | `POST /v1/workspaces/{workspaceId}/uploads` (multipart/form-data, one file part named `file`; optional non-file parts `run_id`, `agent_id`, `collection_kind`, `source_path`, `motw_zone_id`, `motw_referrer_url`) — **C-4-fix**: OpenAPI `createUpload` is normative; the pre-namespace `POST /v1/artifacts` sketch is superseded |
| Companion | `GET /v1/workspaces/{workspaceId}/uploads/{artifactId}` (status, triage state, rejection reason if any) — C-4-fix (was `GET /v1/artifacts/{artifact_id}`) |
| Auth | same bearer/session scheme as the rest of the API; the authenticated principal MUST resolve to exactly one `tenant_id` and one `workspace_id` |
| Idempotency | `Idempotency-Key` header; a replay with the same key AND the same content sha256 returns the original `artifact_id` with HTTP 200; same key, different sha256 → HTTP 409 `GATE_IDEMPOTENCY_MISMATCH` |
| Response (accepted) | HTTP **202** `Upload{artifact_id, run_id, sha256, size, received_at, triage_state, …}` per OpenAPI — **C-4-fix**: the earlier HTTP 201 `{artifact_id, sha256, size, storage_key, triage_job_id, gate: {renamed, warnings[]}}` sketch is superseded by the OpenAPI `Upload` schema (`run_id` is server-generated when the client omits it — C-4b-fix) |
| Response (rejected) | HTTP 4xx `{code, message, detail}` where `code` is one of the §1.5 reject codes; the body never echoes the client filename verbatim (it is stored, see §1.4) |
| Async model | the accepted (202) response means "persisted and queued". Triage outcome is never returned synchronously. |

### 1.2 Transport-level bounds

The gate MUST reject before any library parses the body. Because neither
uvicorn nor Starlette enforces a request-body size limit natively
(UP-UVICORN: uvicorn's Resource Limits are concurrency/requests/backlog only;
Starlette's `max_part_size` applies to non-file form fields, not to uploaded
files), every bound below is implemented by Sentinel as ASGI middleware, not
by configuring a framework knob that does not exist.

| Bound | Proposed default | Enforced where | Fixture / method |
|---|---|---|---|
| `max_request_bytes` (whole HTTP body incl. multipart overhead) | 64 MiB `PROPOSED - TO BENCHMARK` | ASGI middleware, before Starlette's multipart parser runs | FX-G-21, FX-G-22 (slow-loris body, huge Content-Length) |
| `max_file_bytes` (the file part's declared or observed length) | 64 MiB `PROPOSED - TO BENCHMARK` | middleware + streaming copy counter | FX-B-01…FX-B-05 |
| `max_files_per_request` | 1 `PROPOSED - TO BENCHMARK` (Sentinel ingests one artifact per request by design; the multipart parser's own default is 1000, UP-FASTAPI) | middleware | FX-G-23 |
| `max_field_bytes` (non-file parts) | 8 KiB `PROPOSED - TO BENCHMARK` | Starlette form parsing | FX-G-24 |
| Request wall-clock | 30 s `PROPOSED - TO BENCHMARK` | ASGI middleware timeout | FX-G-25 |
| Concurrent uploads per principal | 4 `PROPOSED - TO BENCHMARK` | rate limiter | FX-G-26 |
| Uploads per principal per hour | 500 `PROPOSED - TO BENCHMARK` | rate limiter | FX-G-26 |
| Tenant artifact quota | operator-configured; default 50 GiB `PROPOSED - TO BENCHMARK` | pre-flight sum of stored sizes + post-write accounting | FX-G-27 |

**Spooling.** The file part MUST NOT be buffered in memory. Starlette's
`UploadFile` spools (`SpooledTemporaryFile`, rolling to disk past
`spool_max_size`, which the upstream default sets to 1 MiB — UP-FASTAPI /
UP-SPOOL), but Sentinel MUST NOT rely on that default: the gate calls
`await file.seek(0)` then streams to the content-addressed store with its own
fixed-size buffer (`PROPOSED - TO BENCHMARK`: 1 MiB) and a running byte
counter, aborting the moment the counter passes `max_file_bytes`. The
counter is authoritative; `Content-Length` is advisory and is checked only
for an early reject.

**Chunked transfer.** `Transfer-Encoding: chunked` with no `Content-Length`
is accepted. A declared `Content-Length` that disagrees with the bytes
actually received is a reject (`GATE_BODY_LENGTH_MISMATCH`), not a silent
truncate — silent truncation would create a hash that does not correspond to
any artifact the attacker could have sent, corrupting the dedup index.

### 1.3 What the gate deliberately does NOT do

- **No content parsing.** The gate computes sha256/SHA-1/MD5, size and
  nothing else. Format identification (§2) is a triage-stage concern.
- **No antivirus or YARA at the gate.** Those run in §5.
- **No decompression, no archive listing, no magic-byte sniff.** Sniffing
  reads the first bytes, but the gate's sniff is limited to the *hash
  preimage*: bytes are read once into the hasher and once into the store.
  Identification reads from the store afterwards.
- **No rejection on content.** A file is never rejected because of what it
  contains; it is triaged and its `analysis_status` says so (§8).

### 1.4 Filename handling

The client-supplied filename is **adversarial input and is never trusted,
never used to build a filesystem path, and never a reason to reject**. It is
preserved verbatim as evidence and replaced for storage.

1. `original_filename` — the exact bytes of the multipart filename parameter,
   stored as an opaque UTF-8 string (with `surrogateescape` if the client
   sent undecodable bytes). Never written to disk. Never rendered unescaped
   in a UI without output encoding.
2. `storage_key` — `sha256` hex of the content. The only thing that ever
   names a path in the artifact store. Content-addressed, so a name-collision
   attack has no target.
3. `display_name` — derived once, for humans, by the sanitiser below. Used
   only in API responses and UI.

**Windows sanitiser (normative, in order).** Evidence: UP-MSNAME and
UP-MSADS.

| Step | Rule |
|---|---|
| S1 | Decode percent-escapes and normalise quotes; then strip bytes 0x00–0x1F (control characters are invalid in Win32 names). |
| S2 | Replace every character in the invalid set `< > : " / \ | ? *` with `_`. A colon would otherwise open an alternate-data-stream or drive syntax. |
| S3 | Strip trailing spaces and trailing periods (Win32 silently strips these, which is a classic "payload.exe." vs "payload.exe" mismatch). |
| S4 | If the stem (text before the first dot) case-insensitively equals a reserved device name — `CON`, `PRN`, `AUX`, `NUL`, `COM1`…`COM9`, `LPT1`…`LPT9`, plus the ISO-8859-1 superscript forms (`C0`, `C1`, `C2`, `C3`, `C4`, `C5`, `C6`, `C7`, `C8`, `C9` with a combining superscript, and `LPT1`–`LPT9` superscript variants) — prefix with `_`. |
| S5 | Truncate the *display_name* to 200 UTF-8 bytes without splitting a code point; keep the extension if it fits (`PROPOSED - TO BENCHMARK` against FX-A-21…FX-A-25). The full original is retained in `original_filename` so nothing is lost. |
| S6 | Reject empty results by falling back to the first 16 hex chars of the sha256 as `display_name`. |
| S7 | Case-fold for comparison only. Two artifacts whose `display_name`s differ only by case are still two distinct content-addressed objects; the display collision is recorded as a gate warning, not an error. |

**Long paths.** Sentinel stores artifacts under a content-addressed key that
it fully controls, so the MAX_PATH 260-character limit (UP-MSNAME) is
avoided structurally (short key segments) rather than by relying on the
`\\?\` prefix or the long-path registry opt-out. When Sentinel *reports* a
path that arrived from an agent (e.g. an event-log `Image` path or an archive
member path), it reports the string as-is and does not open it; if a worker
must open a reported path, it uses the `\\?\` form and treats a
path-too-long error as a parse warning, never as a crash.

**Alternate data streams.** A colon in a client filename is replaced at S2
before anything else sees the string. If an artifact reaches Sentinel as a
*path on an endpoint agent* rather than as bytes (agent-side collection), the
agent MUST, before uploading, copy the file's `:Zone.Identifier` stream into
the structured `motw_zone_id` / `motw_referrer_url` upload fields, because
the server cannot see an endpoint's NTFS streams. UP-MSADS is the normative
reference for the stream name and the `[ZoneTransfer]` / `ZoneId=` payload;
DOC-MOTW for the mark-of-the-web semantics.

### 1.5 Reject codes

The gate has exactly these reject codes. Anything else is a 5xx and a bug.

| Code | HTTP | Condition |
|---|---|---|
| `GATE_UNAUTHENTICATED` / `GATE_FORBIDDEN` | 401 / 403 | principal missing, or not scoped to this tenant/workspace |
| `GATE_TENANT_MISMATCH` | 403 | upload claims a tenant/workspace the principal does not own |
| `GATE_BODY_LENGTH_MISMATCH` | 400 | declared Content-Length ≠ bytes received |
| `GATE_REQUEST_TOO_LARGE` | 413 | body exceeds `max_request_bytes` |
| `GATE_FILE_TOO_LARGE` | 413 | file part exceeds `max_file_bytes` |
| `GATE_EMPTY_FILE` | 400 | zero bytes (an empty file carries no bytes to triage; the client is told explicitly rather than storing a useless object) |
| `GATE_TOO_MANY_FILES` | 400 | more than one file part |
| `GATE_FIELD_TOO_LARGE` | 400 | a non-file part exceeds `max_field_bytes` |
| `GATE_QUOTA_EXCEEDED` | 402 | tenant artifact-byte quota exhausted |
| `GATE_RATE_LIMITED` | 429 | per-principal concurrency or hourly rate exceeded |
| `GATE_TIMEOUT` | 408 | request exceeded the wall-clock bound |
| `GATE_IDEMPOTENCY_MISMATCH` | 409 | Idempotency-Key reuse with different content |
| `GATE_STORE_WRITE_FAILED` | 503 | content-addressed store write failed after the hash was computed (the response MUST NOT include the hash, to avoid a hash oracle for content the client did not successfully upload) |

Rejected uploads are still **audited**: a row with the timestamp, principal,
tenant, `code`, declared size, received size and the sha256 of the first
64 KiB (not of the whole file — a whole-file hash of rejected content would
let an attacker confirm the presence of a known-bad file they were told not
to upload). Retention of that row is operator-configured; default 90 days
`PROPOSED - TO BENCHMARK`.

### 1.6 Accepted-upload record

```yaml
artifact:
  artifact_id: ulid-or-uuid          # server-generated, immutable
  tenant_id: string                  # required, from the principal, never from the body
  workspace_id: string
  run_id: string                     # harvest/run that produced the upload
  sha256: hex64
  sha1: hex40                        # computed at the gate (Stage-2 hashes object uses all three)
  md5: hex32
  size: int
  storage_key: hex64                 # == sha256; the only path component
  original_filename: string          # verbatim, opaque
  display_name: string               # sanitised per §1.4
  content_disposition_filename: string|null   # what the multipart header literally said
  motw:
    zone_id: int|null                # from the upload fields or from an agent-copied Zone.Identifier
    referrer_url: string|null
    source: agent|upload_field|absent
  agent_id: string|null
  collection_kind: string|null       # e.g. triage_upload, agent_collection, virustotal_import
  source_path: string|null           # endpoint path as reported by the agent (never opened server-side)
  received_at: timestamp
  gate_warnings: [renamed, case_collision, truncated_display_name, motw_absent]
  triage_state: queued|running|done|failed|rejected_by_policy
```

The record is the join key for everything downstream: telemetry events link to
it through `source.file_id` (Stage-2 envelope), and triage facts link through
`artifact_id`.

### 1.7 Content-addressed store

- Layout: `<root>/<sha256[0:2]>/<sha256[2:4]>/<sha256>` — flat, dedup by
  construction, no filename component anywhere in the path.
- Write protocol: write to `*.tmp`, fsync, hash-verify, atomic rename. A
  partially written object is never visible under its final name.
- Dedup is per-tenant in Stage 3 (single-tenant deployment per Stage-1
  D-012); the row carries `tenant_id` and `workspace_id` so a later
  multi-tenant store can namespace without a migration of the bytes.
- Immutability: artifacts are never mutated in place. Extraction output goes
  to a separate quarantine namespace keyed by parent sha256 + member path
  (§10).

---

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
    description: >-
      string|null     # libmagic's human string, e.g. "Microsoft Excel 2007+
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

**Telemetry-family precedence (D8-06 fix).** The generic families `text`
(and the `json`/`csv`/`tsv`/`xml` Magika labels that fall into it) would
otherwise swallow log/telemetry uploads (Suricata `eve.json`, Zeek TSV,
Nmap `-oX` XML, syslog/CEF/LEEF lines) and route them to §5.6 text triage,
where they never reach the §4.4 telemetry parsers. Therefore identification
applies a bounded content-sniff **before** the family map, in this order, and
the first match wins:

1. Nmap XML: root element `nmaprun` (XML) → `selected = nmap_xml`.
2. Suricata EVE: JSON object with `event_type` + `timestamp` keys → `suricata_eve`.
3. Zeek TSV: first line starts `#separator` (or `#open`) → `zeek_tsv`.
4. CEF: line starts `CEF:` → `cef`.
5. LEEF: line starts `LEEF:` → `leef`.
6. Syslog: line matches RFC 5424 (`<PRI>VERSION ...`) or RFC 3164 (`<PRI>Mmm dd ...`) → `syslog`.
7. Windows export: header row matches a known tool export (Autoruns/`Process Explorer`/`Sigcheck` column set) → `winexport`.

Only if none match does the normal magic/magika family map apply. The sniff
is configuration data (signatures in YAML), never a hard-coded detector, and
each hit sets `selected_by = magic` with `confidence = high` (the signature is
authoritative). Uploads whose bytes are telemetry but whose signature is not
matched still fall to `text` triage — they are analysed, just not routed to a
telemetry parser.

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
| `zeek_tsv` | (content sniff: `#separator` header) | — | Zeek TSV telemetry parser (§4.4) |
| `suricata_eve` | (content sniff: JSON `event_type`+`timestamp`) | `json` | Suricata EVE telemetry parser (§4.4) |
| `nmap_xml` | `text/xml` + root `nmaprun` | `xml` | Nmap XML telemetry parser (§4.4) |
| `syslog` | (content sniff: RFC 5424/3164) | `text` | syslog telemetry parser (§4.4) |
| `cef` | (content sniff: `CEF:` prefix) | `text` | CEF telemetry parser (§4.4) |
| `leef` | (content sniff: `LEEF:` prefix) | `text` | LEEF telemetry parser (§4.4) |
| `winexport` | (content sniff: known export header) | `csv`, `text` | Windows-export telemetry parser (§4.4) |
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

### 5.9b SQLite databases (.db, .sqlite, .sqlite3, browser stores, app DBs)

`source.format` admits `sqlite` (canonical enum), so uploaded SQLite files
must have a triage path (D8-07 / C-8 closure). SQLite is a self-contained
binary container; it is read **in-process, read-only**, never executed.

| Family | Stage-3 treatment |
|---|---|
| SQLite 3 database | Opened read-only via the stdlib `sqlite3` module in immutable/`mode=ro` URI mode (no writes, no WAL creation). `PRAGMA query_only=ON` is set. Facts: `sqlite.schema.object_count`, `.table_names` (bounded), `sqlite.page_size`, `sqlite.encoding`, per-table `sqlite.table.<name>.row_estimate` (from `dbstat` when available, else `NULL`-state). No row contents are extracted by default — row sampling is gated behind the same bounded-recursion budget as archives (§10) and only runs for tables whose schema matches a known artefact shape (browser `downloads`/`history`, Mail/Outlook store tables), emitting `artifact`/`document` facts, never verdicts. |
| Corrupt / not-SQLite (magic `SQLite format 3\0` absent) | Not opened; `analysis_status: unsupported_format` with a `source_contract` warning. |
| Encrypted (SQLCipher) | Detected by header/page-encryption markers; `analysis_status: encrypted`; §7 owns policy. Never brute-forced. |

### 5.10 Optional enrichment services (deliberately not in the default build)

| Service | SPDX | Why not default |
|---|---|---|
| Apache Tika (4.1.0, DOC-TIKA) | Apache-2.0 | licence is fine, but its own security page states that neither tika-server nor tika-grpc is a security boundary and that only trusted callers may reach them; in-process parser denial of service is documented as "not a security vulnerability". Adopting it means owning a JVM isolation story. Deferred to Q3-008. |
| ClamAV (1.5.4, ARC-CLAMAV) | GPL-2.0 | external-process only (licence), and it is a *signature* engine whose value overlaps YARA-X. Available as operator-enabled; signature DB updates require network egress, which §9 forbids in the triage worker — the DB must be staged out-of-band. |
| ExifTool (13.59, ARC-EXIFTOOL) | Artistic-1.0 OR GPL | external-process only; see §5.7 |
| DIE, capa, FLOSS, unblob, binwalk | MIT / Apache-2.0 | licence-compatible, but each is an optional capability layer; all are off by default and each has a documented enablement condition |

---

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

## 10. Safe Archive Extraction Design

Extraction is the one operation in Sentinel that turns a bounded input into
an unbounded one, so it gets a normative algorithm rather than advice. The
algorithm applies to every container: ZIP, TAR, 7z, RAR, ISO, CAB, OOXML,
OLE, and every nested container discovered by recursion.

### 10.1 The algorithm

```
EXTRACT(root_artifact, ctx):
  1.  LIST   container.list()                      # central directory / header only; no bytes written
        -> members[] (path, size_compressed, size_uncompressed, method,
                      is_directory, is_symlink, link_target, encrypted, crc32)
        if LIST fails at offset 0: emit status=corrupted; RETURN
        if container declares truncation: emit status=truncated (§2.4); continue with what exists

  2.  BUDGET init(root_artifact):
        remaining_bytes   = ctx.max_materialised_bytes
        remaining_nodes   = ctx.max_nodes
        remaining_time    = ctx.max_wall_clock
        seen_hashes       = {}                       # cycle + shared-subtree protection (§6.3)

  3.  for each member in members (in central-directory order):
        if deadline exceeded or budgets exhausted:
              close graph; status=resource_limit_exhausted; BREAK

        3a. SANITISE(member.path) -> safe_rel      # §10.2, MUST succeed or member is dropped
              if sanitisation rejected the path:
                  emit archive_member fact with rejection_reason;
                  continue                          # the member is NOT an error; it is a fact

        3b. target = quarantine_root / root_artifact.sha256 / safe_rel

        3c. CONTAIN(target, quarantine_root)        # §10.3, ancestry check
              if violated: emit rejection_reason=path_escape; continue

        3d. if member.is_symlink or member.is_hardlink:
                validate link_target with the same SANITISE rules
                  (absolute targets, targets escaping, device targets -> reject)
                NEVER create the link itself in the default build;
                record the validated target as a fact only.     # §10.5

        3e. declared = member.size_uncompressed
            if declared > ctx.max_node_bytes:          emit reason=size_limit; continue
            if member.size_uncompressed / max(1, member.size_compressed)
                 > ctx.max_compression_ratio:          emit reason=ratio_limit; continue
            if remaining_bytes <= 0:                   emit reason=budget; continue

        3f. write target with O_CREAT|O_EXCL, mode 0o600, in a directory the
            worker created and owns; stream-copy with a RUNNING COUNT:
                written = 0
                for chunk in member.stream():
                    written += len(chunk)
                    if written > ctx.max_node_bytes:            ABORT; unlink; reason=size_limit
                    if written > declared * 1 + slack:          ABORT; unlink; reason=lie_about_size
                    remaining_bytes -= len(chunk)
                    if remaining_bytes < 0:                     ABORT; unlink; reason=budget
                    if deadline exceeded:                       ABORT; unlink; reason=timeout
                    out.write(chunk)
            if member.crc32 is declared and crc32(actual) != declared:
                keep the bytes, emit reason=crc_mismatch, flag node as untrusted-content

        3g. hash = sha256(target)
            if hash in seen_hashes:
                emit edge same_bytes_as to the existing node; continue (do not re-expand)
            seen_hashes[hash] = node

        3g. IDENTIFY(target)                          # §2, from the store, not from the extension
            RECURSE EXTRACT(target, ctx) if:
                depth < ctx.max_depth
                AND identification.selected is a container family
                AND the family is enabled for recursion (§10.4)

  4.  FINALISE: every member, extracted or not, has produced an archive_member
      fact and (if the family maps) a canonical archive_member event.
      Parent status = analysed/partial per §8.2.
```

### 10.2 Path sanitisation (normative)

Applied to *every* member path before it is joined to anything. Evidence for
the Windows rules: UP-MSNAME.

| Step | Rule | On failure |
|---|---|---|
| P1 | Reject empty paths and paths that are only `.` / `..` | drop |
| P2 | Normalise separators: `\` → `/`; reject paths containing a NUL byte | drop |
| P3 | Reject absolute paths (leading `/`), drive-relative (`C:x`), drive-absolute (`C:/`), and UNC (`//host/`, `\\host\`) | drop |
| P4 | Reject Windows device namespaces: `//./`, `//?/`, `\\.\`, `\\?\`, and any component equal to `CONIN$` / `CONOUT$` | drop |
| P5 | Resolve `.` and `..` **lexically, on the normalised string** — never by filesystem resolution. If the result starts with `..`, the path escapes and is dropped | drop |
| P6 | Split into components; reject any component that is empty, `.`/`..`, longer than 255 bytes, ends with a space or a period, or whose stem case-insensitively equals a reserved device name (CON/PRN/AUX/NUL/COM1–9/LPT1–9 plus the ISO-8859-1 superscript forms) | drop that component (and therefore the member) |
| P7 | Reject any component containing `:` (an ADS or drive separator) | drop |
| P8 | Reject if the joined path would exceed 4,096 bytes, or the depth exceeds 32 components (`PROPOSED - TO BENCHMARK`) | drop |
| P9 | Unicode-normalise to NFC for comparison and storage; keep the original bytes as `archive_member.member_path_original` | — |
| P10 | Final result must be a relative POSIX-style path with no empty components | drop |

P5 is the crux. A lexical resolution cannot be tricked by a symlink that
exists on the extraction filesystem, because nothing has been created yet at
the time the check runs — and §10.3 makes sure the write target's *real*
ancestry is still inside the quarantine root afterwards, so even if something
else races the directory, the write fails closed.

### 10.3 Ancestry containment (normative)

After sanitisation and immediately before opening the target, the worker
computes the *real* path of every ancestor of the target and asserts that the
quarantine root's real path is a prefix of it, component-wise (not
string-wise: `/q/abc` must not be accepted as a prefix of `/q/abcd`). This
catches the case where a previously extracted member created a symlink that a
later member would traverse — which is why, in the default build, §10.5
prevents symlink creation outright.

```
assert_containment(target, root):
    root_real = realpath(root)                       # root was created by this worker, mode 0o700
    cur = dirname(target)
    while cur is not root_real and cur != dirname(cur):
        if not is_within(realpath(cur), root_real):   # component-wise
            raise PathEscape
        cur = dirname(cur)
    assert is_within(realpath(dirname(target)), root_real)
```

Additionally, the target is opened with `O_NOFOLLOW` semantics (Python:
`os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW)`), so a
component that became a symlink between the check and the open fails the
open rather than writing through it.

### 10.4 Recursion policy

Recursion is enabled per family and is the reason the depth limit exists:

| Parent family | Recurses into | Default |
|---|---|---|
| ZIP / TAR / 7z / RAR / ISO / CAB | any container family | on, depth 8 |
| OOXML | ZIP members, and OLE members of embedded objects | on, depth 8 (OOXML counts as one level) |
| OLE2 | embedded ZIP/OLE objects | on, depth 8 |
| PDF | embedded files (`/EmbeddedFile` streams) | on, depth 8 |
| PE | overlay carving, resources of type RCDATA/manifest containing XML | on, depth 4 (`PROPOSED - TO BENCHMARK`) |
| LNK | **never** — a LNK points outside itself; `references` only | off |
| image | appended ZIP (polyglot) | on, depth 2 |
| disk image / VHD / VMDK | **never** (§9: mounting executes a filesystem driver) | off |
| NSIS / Inno | **never** in Stage 3 (Q3-016) | off |

`unblob` and `binwalk` (§5.8) are *not* recursion targets; if an operator
enables them they run as a bounded enrichment step on leaf artifacts that no
family parser claimed, under the same budgets.

### 10.5 Symlinks, hardlinks, device nodes, setuid

The default build **never creates** a symlink, hardlink, FIFO, device node or
socket from an archive, regardless of what the container declares. Instead it
validates and records the declared target as a fact
(`archive.member.is_symlink`, `.link_target`). This is a stricter rule than
Python's own `data_filter` (ARC-TARFILE, which refuses absolute and
outside-destination link targets but does allow in-destination links), and it
is chosen because an in-destination link is still enough to defeat a naive
containment check in a later recursion step. Setuid/setgid/sticky bits are
stripped unconditionally; group/other write is stripped; resulting mode is
`0o600` for files and `0o700` for directories.

### 10.6 Delegation to the standard library

For TAR, Sentinel does not reimplement the safety logic: it passes the
`data_filter` (ARC-TARFILE) to `extractfile`/`extract` and then applies
§10.2's stricter rules on top for the paths it materialises itself. For ZIP
the standard library provides **no** equivalent guard — ARC-ZIPFILE's own
documentation names decompression bombs as a hazard and offers no limit — so
§10's counters are the only defence, which is why the ZIP branch carries the
fixture load in §11 category B.

### 10.7 Quarantine layout

```
<quarantine_root>/<root_sha256[0:2]>/<root_sha256>/<safe_rel>...    # files, mode 0o600
<quarantine_root>/.meta/<root_sha256>.json                          # per-root manifest:
    {members: [{safe_rel, original_path, sha256, size_written, size_declared,
                 rejected: null|reason, identified: <selected>, status}], limits_hit: [...]}
```

The manifest is the provenance record for every child node: it is what makes
`archive_member` canonical events reproducible, and it is what an analyst
reads when a nested artifact looks different from what the parent advertised.

---

## 11. Attack Fixture Catalogue

240 named fixtures across eight categories. Each fixture is a file (or a
script that builds one) in the Stage-4 corpus; each maps to at least one
assertion in §1, §2, §5, §6, §7, §9 or §10. Fixtures are *inputs*, never
expected outputs: the expected behaviour is stated in the assertion, so a
test can fail loudly when a parser silently "handles" a hostile input.

Naming: `FX-<category letter>-<two digits>`. Category letters:
A path/filename, B expansion, C parser-confusion, D encryption, E
active-content, F resource-exhaustion, G transport/API, H telemetry.

### Category A — path traversal and hostile filenames (30)

```yaml
fixtures_category_A:
  - {id: FX-A-01, name: zip_dotdot_plain,              desc: "ZIP member '../../etc/passwd' (POSIX traversal)"}
  - {id: FX-A-02, name: zip_dotdot_deep,               desc: "ZIP member with 64 levels of ../ prefix"}
  - {id: FX-A-03, name: zip_dotdot_embedded,           desc: "ZIP member 'docs/../../payload.exe' (mid-path traversal)"}
  - {id: FX-A-04, name: zip_backslash_traversal,       desc: "ZIP member '..\\..\\payload.exe' (Windows separator traversal)"}
  - {id: FX-A-05, name: zip_mixed_separators,          desc: "ZIP member 'a/..\\../b' mixing / and \\"}
  - {id: FX-A-06, name: zip_absolute_posix,            desc: "ZIP member '/etc/cron.d/x'"}
  - {id: FX-A-07, name: zip_absolute_drive,            desc: "ZIP member 'C:/Windows/System32/evil.dll'"}
  - {id: FX-A-08, name: zip_drive_relative,            desc: "ZIP member 'C:evil.dll' (drive-relative)"}
  - {id: FX-A-09, name: zip_unc_path,                  desc: "\\\\attacker\\share\\evil.dll as member path"}
  - {id: FX-A-10, name: zip_device_namespace_dot,      desc: "ZIP member '\\\\.\\PhysicalDrive0'"}
  - {id: FX-A-11, name: zip_device_namespace_qmark,    desc: "ZIP member '\\\\?\\C:\\evil'"}
  - {id: FX-A-12, name: zip_reserved_con,              desc: "ZIP member named 'CON'"}
  - {id: FX-A-13, name: zip_reserved_com1,             desc: "ZIP member named 'COM1.txt'"}
  - {id: FX-A-14, name: zip_reserved_lpt9_exe,         desc: "ZIP member 'LPT9.exe'"}
  - {id: FX-A-15, name: zip_reserved_superscript,      desc: "ZIP member using the superscript-COM1 reserved form"}
  - {id: FX-A-16, name: zip_ads_colon,                 desc: "ZIP member 'file.txt:Zone.Identifier' (ADS syntax)"}
  - {id: FX-A-17, name: zip_ads_colon_deep,            desc: "ZIP member 'dir/file.txt:hidden.exe'"}
  - {id: FX-A-18, name: zip_trailing_dot,              desc: "ZIP member 'payload.exe.' (Win32 silently strips)"}
  - {id: FX-A-19, name: zip_trailing_space,            desc: "ZIP member 'payload.exe '"}
  - {id: FX-A-20, name: zip_double_extension,          desc: "ZIP member 'invoice.pdf.exe'"}
  - {id: FX-A-21, name: zip_extremely_long_name,       desc: "ZIP member with a 4,000-byte filename"}
  - {id: FX-A-22, name: zip_long_component,            desc: "ZIP member with one 300-byte component"}
  - {id: FX-A-23, name: zip_deep_nesting,              desc: "ZIP with 64 nested directory components"}
  - {id: FX-A-24, name: zip_rtl_override,              desc: "ZIP member with U+202E right-to-left override spoofing the extension"}
  - {id: FX-A-25, name: zip_null_byte_name,            desc: "ZIP member whose raw name contains an embedded NUL"}
  - {id: FX-A-26, name: zip_unicode_dotdot,            desc: "ZIP member using U+2024/U+FF0E variants of '.' in '..'"}
  - {id: FX-A-27, name: tar_symlink_escape,            desc: "TAR symlink 'link -> /etc' followed by member 'link/passwd'"}
  - {id: FX-A-28, name: tar_hardlink_escape,           desc: "TAR hardlink to an absolute target outside the destination"}
  - {id: FX-A-29, name: tar_device_fifo,               desc: "TAR member declaring a FIFO/character-device entry"}
  - {id: FX-A-30, name: zip_case_collision,            desc: "ZIP with 'a.txt' and 'A.txt' on a case-insensitive target"}
```

### Category B — decompression bombs and expansion (30)

```yaml
fixtures_category_B:
  - {id: FX-B-01, name: zip_42_bomb,                   desc: "42.zip-style nested ZIP chain, ~4.5 PB declared"}
  - {id: FX-B-02, name: zip_single_huge,               desc: "single ZIP member declaring 10 GiB uncompressed of zeros"}
  - {id: FX-B-03, name: zip_high_ratio_1k,             desc: "1 KiB compressed member declaring 10 MiB output"}
  - {id: FX-B-04, name: zip_ratio_lying_size,          desc: "member declaring small size but streaming far more"}
  - {id: FX-B-05, name: zip_size_field_truncated,      desc: "ZIP64 extra field with a truncated/unreal size"}
  - {id: FX-B-06, name: zip_bzip2_bomb,                desc: "bzip2 member with extreme ratio"}
  - {id: FX-B-07, name: zip_lzma_bomb,                 desc: "LZMA member with extreme ratio"}
  - {id: FX-B-08, name: zip_deflate_stored_mismatch,   desc: "method=stored but size fields disagree"}
  - {id: FX-B-09, name: zip_central_vs_local_mismatch, desc: "central directory sizes differ from local header sizes"}
  - {id: FX-B-10, name: ooxml_10k_parts,               desc: "OOXML with 10,000 tiny parts (part-table blowup)"}
  - {id: FX-B-11, name: tar_gzip_bomb,                 desc: "tar.gz with extreme ratio across members"}
  - {id: FX-B-12, name: sevenz_bomb,                   desc: "7z with solid-block extreme ratio"}
  - {id: FX-B-13, name: gzip_header_only_oversize,     desc: "gzip member whose ISIZE trailer claims 4 GiB"}
  - {id: FX-B-14, name: zip_overlapping_members,       desc: "two members sharing the same compressed byte range"}
  - {id: FX-B-15, name: zip_million_empty,             desc: "ZIP with 1,000,000 zero-byte members"}
  - {id: FX-B-16, name: pdf_stream_bomb,               desc: "PDF stream with extreme FlateDecode ratio"}
  - {id: FX-B-17, name: pdf_jbig2_bomb,                desc: "PDF with a JBIG2 segment pattern known to expand"}
  - {id: FX-B-18, name: image_png_dimension_lie,       desc: "PNG IHDR claiming 65535x65535 with a small IDAT"}
  - {id: FX-B-19, name: image_gif_frames_bomb,         desc: "GIF with 10,000 frames"}
  - {id: FX-B-20, name: image_bmp_rle_bomb,            desc: "BMP with an RLE decompression bomb"}
  - {id: FX-B-21, name: image_tiff_tile_bomb,          desc: "TIFF with an exploding tile structure"}
  - {id: FX-B-22, name: image_webp_vp8_bomb,           desc: "WebP with extreme canvas-to-data ratio"}
  - {id: FX-B-23, name: ole_stream_oversize_declared,  desc: "OLE stream declaring a size far past EOF"}
  - {id: FX-B-24, name: cab_lzx_bomb,                  desc: "CAB with an LZX stream of extreme ratio"}
  - {id: FX-B-25, name: rar_solid_bomb,                desc: "RAR solid archive with extreme cumulative ratio"}
  - {id: FX-B-26, name: nested_zip_depth_50,           desc: "50 nested ZIPs, each 1 KiB, to hit max_depth"}
  - {id: FX-B-27, name: nested_zip_depth_8_boundary,   desc: "exactly 8 nested ZIPs (boundary of the depth limit)"}
  - {id: FX-B-28, name: fanout_20k_nodes,              desc: "one archive expanding to 20,000 nodes"}
  - {id: FX-B-29, name: zstd_bomb,                     desc: "zstd stream with extreme ratio"}
  - {id: FX-B-30, name: recursive_self_reference,      desc: "archive whose member hashes to the archive itself"}
```

### Category C — parser confusion, polyglots and format mismatch (30)

```yaml
fixtures_category_C:
  - {id: FX-C-01, name: extension_exe_as_pdf,          desc: "PE file named invoice.pdf"}
  - {id: FX-C-02, name: extension_pdf_as_exe,          desc: "PDF named setup.exe"}
  - {id: FX-C-03, name: polyglot_pdf_zip,              desc: "valid PDF whose xref is also a ZIP central directory"}
  - {id: FX-C-04, name: polyglot_pdf_js,               desc: "PDF with an embedded /JavaScript action and a JS polyglot header"}
  - {id: FX-C-05, name: polyglot_gif_exe,              desc: "GIF89a-prefixed PE (classic header splice)"}
  - {id: FX-C-06, name: polyglot_jpeg_zip,             desc: "JPEG with a complete ZIP appended after EOI"}
  - {id: FX-C-07, name: polyglot_png_pe,               desc: "PNG whose IDAT payload is a PE"}
  - {id: FX-C-08, name: polyglot_html_zip,             desc: "HTML file that is also a valid ZIP"}
  - {id: FX-C-09, name: ole_wrapping_ooxml,            desc: "OLE2 container wrapping an OOXML package"}
  - {id: FX-C-10, name: ooxml_wrapping_ole,            desc: "OOXML with an embedded OLE object containing a PE"}
  - {id: FX-C-11, name: ooxml_content_types_lie,       desc: "[Content_Types].xml declaring a type that contradicts the part bytes"}
  - {id: FX-C-12, name: zip_masquerading_ooxml,        desc: "plain ZIP with a forged [Content_Types].xml"}
  - {id: FX-C-13, name: pe_overlay_pdf,                desc: "PE with a complete PDF in its overlay"}
  - {id: FX-C-14, name: pe_fake_dos_stub,              desc: "PE whose DOS stub contains another MZ header"}
  - {id: FX-C-15, name: pe_import_table_truncated,     desc: "PE whose import table points past EOF"}
  - {id: FX-C-16, name: dotnet_in_non_pe,              desc: "CLR metadata directory declared in a non-PE"}
  - {id: FX-C-17, name: lnk_targeting_unc,             desc: "LNK whose target is an UNC path with an icon location elsewhere"}
  - {id: FX-C-18, name: lnk_with_tracker_bmp,          desc: "LNK with a Darwin/Tracker data block carrying a CLSID"}
  - {id: FX-C-19, name: rtf_with_ole_and_hex,          desc: "RTF with a hex-encoded object and an embedded OLE"}
  - {id: FX-C-20, name: rtf_objdata_cycle,             desc: "RTF \\objdata referring to itself (object graph cycle)"}
  - {id: FX-C-21, name: chm_with_pe,                   desc: "CHM whose content list includes a PE"}
  - {id: FX-C-22, name: mhtml_with_active_part,        desc: "MHTML with a part named .html and Content-Type text/html"}
  - {id: FX-C-23, name: xml_billion_laughs,             desc: "XML with recursive entity expansion (defusedxml must reject)"}
  - {id: FX-C-24, name: xml_external_entity,           desc: "XML with an external entity pointing at a file path"}
  - {id: FX-C-25, name: xml_quadratic_blowup,          desc: "XML with a single huge entity referenced many times"}
  - {id: FX-C-26, name: json_deep_nesting_10k,         desc: "JSON nested 10,000 levels (orjson/ijson recursion hazard)"}
  - {id: FX-C-27, name: csv_multiline_field,            desc: "CSV with a quoted field containing newlines and delimiters"}
  - {id: FX-C-28, name: csv_excel_formula,             desc: "CSV cell beginning =cmd|' /C calc'!A0 (injection into a spreadsheet)"}
  - {id: FX-C-29, name: zip_utf8_flag_lie,             desc: "ZIP member name claiming UTF-8 but containing invalid sequences"}
  - {id: FX-C-30, name: evtx_trailing_garbage,         desc: "EVTX with valid records followed by 1 MiB of garbage"}
```

### Category D — encryption and password handling (30)

```yaml
fixtures_category_D:
  - {id: FX-D-01, name: ooxml_encrypted_agile,         desc: "OOXML agile-encryption document, no password"}
  - {id: FX-D-02, name: ooxml_encrypted_standard,      desc: "OOXML standard (RC4) encryption"}
  - {id: FX-D-03, name: ooxml_encrypted_wrong_pw,      desc: "OOXML encrypted, attempted with the wrong password"}
  - {id: FX-D-04, name: ooxml_encrypted_known_pw,      desc: "OOXML encrypted with a workspace-configured password"}
  - {id: FX-D-05, name: ole_encrypted_doc,             desc: "legacy .doc with XOR/RC4 obfuscation"}
  - {id: FX-D-06, name: ole_encrypted_xls,             desc: "legacy .xls with CryptoAPI encryption"}
  - {id: FX-D-07, name: pdf_encrypted_v2_rc4,          desc: "PDF standard security handler V=2 R=3"}
  - {id: FX-D-08, name: pdf_encrypted_aes128,          desc: "PDF with AES-128 (V=4/R=4)"}
  - {id: FX-D-09, name: pdf_encrypted_aes256,          desc: "PDF with AES-256 (R=6)"}
  - {id: FX-D-10, name: pdf_encrypt_empty_pw,          desc: "PDF with /Encrypt and an empty user password (opens without prompting)"}
  - {id: FX-D-11, name: pdf_encrypt_owner_only,        desc: "PDF where the user password is empty but permissions are restricted"}
  - {id: FX-D-12, name: zip_crypto_entry,              desc: "ZIP with general-purpose bit 0 set on one entry"}
  - {id: FX-D-13, name: zip_aes_entry,                 desc: "ZIP with the AE-x AES extra field"}
  - {id: FX-D-14, name: zip_mixed_encrypted_plain,     desc: "ZIP with one encrypted and one plaintext member"}
  - {id: FX-D-15, name: sevenz_header_encrypted,       desc: "7z with an encrypted header"}
  - {id: FX-D-16, name: rar_encrypted_headers,         desc: "RAR with encrypted headers (listing must still work)"}
  - {id: FX-D-17, name: rar_encrypted_data,            desc: "RAR with plaintext headers and encrypted data"}
  - {id: FX-D-18, name: encrypted_nested_in_plaintext, desc: "plaintext ZIP containing an encrypted OOXML"}
  - {id: FX-D-19, name: plaintext_nested_in_encrypted, desc: "encrypted ZIP whose plaintext is a PE (decrypt-then-triage path)"}
  - {id: FX-D-20, name: pw_attempts_budget_4,          desc: "encrypted artifact needing 4 password attempts (budget is 3)"}
  - {id: FX-D-21, name: pw_slow_kdf,                   desc: "PDF with a deliberately slow KDF to hit the 5 s per-attempt budget"}
  - {id: FX-D-22, name: pw_wrong_then_right,           desc: "artifact where the 2nd configured password is correct"}
  - {id: FX-D-23, name: pw_unicode_passphrase,         desc: "password containing non-ASCII and combining characters"}
  - {id: FX-D-24, name: pw_leak_attempt,               desc: "artifact whose filename contains the password (must not be echoed into facts)"}
  - {id: FX-D-25, name: encrypted_zero_byte_plaintext, desc: "encryption wrapper around a zero-byte payload"}
  - {id: FX-D-26, name: encrypted_then_bomb,           desc: "decrypted plaintext is itself a decompression bomb"}
  - {id: FX-D-27, name: encrypted_polyglot,            desc: "encrypted OOXML that is also a valid PDF once decrypted"}
  - {id: FX-D-28, name: ooxml_encryptioninfo_truncated,desc: "EncryptionInfo part cut short"}
  - {id: FX-D-29, name: pdf_encrypt_dict_malformed,    desc: "/Encrypt referencing a missing object"}
  - {id: FX-D-30, name: efs_stream_placeholder,        desc: "file whose bytes are an EFS/BitLocker marker (must be not_analyzed_by_policy)"}
```

### Category E — active content (30)

```yaml
fixtures_category_E:
  - {id: FX-E-01, name: docm_autopen,                  desc: "DOCM with an Auto_Open VBA entry point"}
  - {id: FX-E-02, name: xlsm_workbook_open,            desc: "XLSM with Workbook_Open"}
  - {id: FX-E-03, name: pptm_auto_open,                desc: "PPTM with an auto-open macro"}
  - {id: FX-E-04, name: docx_ddefield,                 desc: "DOCX containing a DDEFIELD instruction"}
  - {id: FX-E-05, name: xlsx_xlm_sheet,                desc: "XLSX with an Excel 4.0 macro sheet and EXEC/URL calls"}
  - {id: FX-E-06, name: xlsb_binary_macro,             desc: "XLSB with a binary macro payload"}
  - {id: FX-E-07, name: ooxml_external_template,       desc: "DOCX relationship with TargetMode=External pointing at a .dotx"}
  - {id: FX-E-08, name: ooxml_external_ole,            desc: "OLE relationship to an external moniker"}
  - {id: FX-E-09, name: ooxml_html_fallback,          desc: "Word HTML fallback part with an external image"}
  - {id: FX-E-10, name: doc_vba_stomped,               desc: "OLE .doc with a stomped (empty) _VBA_PROJECT but a live module stream"}
  - {id: FX-E-11, name: ole_oleobject_package,         desc: "OLE Package object whose payload is a PE"}
  - {id: FX-E-12, name: pdf_openaction_js,             desc: "PDF /OpenAction /JavaScript"}
  - {id: FX-E-13, name: pdf_openaction_launch,         desc: "PDF /OpenAction /Launch"}
  - {id: FX-E-14, name: pdf_additional_actions,        desc: "PDF /AA /WC and /WS page actions"}
  - {id: FX-E-15, name: pdf_submit_form,               desc: "PDF /SubmitForm to an http URL"}
  - {id: FX-E-16, name: pdf_import_data,               desc: "PDF /ImportData referencing an external file"}
  - {id: FX-E-17, name: pdf_xfa_form,                  desc: "PDF with an XFA form packet"}
  - {id: FX-E-18, name: pdf_richmedia_annotation,      desc: "PDF with a /RichMedia annotation"}
  - {id: FX-E-19, name: rtf_with_objauto,              desc: "RTF using \\objauto and an embedded OLE object"}
  - {id: FX-E-20, name: rtf_includePicture_url,        desc: "RTF \\includepicture pointing at an http URL"}
  - {id: FX-E-21, name: ps1_base64_encodedcommand,     desc: "PowerShell script with -EncodedCommand style base64 blob"}
  - {id: FX-E-22, name: ps1_invoke_expression,         desc: "PowerShell script calling Invoke-Expression on a concatenated string"}
  - {id: FX-E-23, name: ps1_downloadstring,            desc: "PowerShell script with DownloadString"}
  - {id: FX-E-24, name: js_wscript_shell,              desc: "JScript using WScript.Shell and ActiveXObject"}
  - {id: FX-E-25, name: vbs_createobject,              desc: "VBScript creating Shell.Application"}
  - {id: FX-E-26, name: hta_inline_script,             desc: "HTA with an inline script block"}
  - {id: FX-E-27, name: html_meta_refresh,             desc: "HTML with <meta http-equiv=refresh content=0;url=...>"}
  - {id: FX-E-28, name: html_external_script,          desc: "HTML referencing an external script URI"}
  - {id: FX-E-29, name: lnk_powershell_arguments,      desc: "LNK whose target is powershell.exe with an encoded argument"}
  - {id: FX-E-30, name: chm_with_active_html,          desc: "CHM whose default topic contains script (metadata-only path must hold)"}
```

### Category F — resource exhaustion and fan-out (30)

```yaml
fixtures_category_F:
  - {id: FX-F-01, name: evtx_1m_records,               desc: "EVTX with 1,000,000 small records (event-count cap)"}
  - {id: FX-F-02, name: evtx_single_huge_record,       desc: "one EVTX record carrying 50 MiB of event data"}
  - {id: FX-F-03, name: evtx_deeply_nested_xml,        desc: "EVTX whose rendered XML nests 10,000 elements"}
  - {id: FX-F-04, name: pcap_10k_flows,                desc: "pcap with 10,000 distinct flows"}
  - {id: FX-F-05, name: pcap_single_huge_packet,       desc: "pcap with a snaplen-truncated 16 MiB packet"}
  - {id: FX-F-06, name: pcap_infinite_tcp_stream,      desc: "pcap with one stream of 1,000,000 segments"}
  - {id: FX-F-07, name: pcap_malformed_dissector,      desc: "pcap crafted to hit a known dissector crash class"}
  - {id: FX-F-08, name: eve_1m_lines,                  desc: "Suricata eve.json with 1,000,000 lines"}
  - {id: FX-F-09, name: eve_line_10mb,                 desc: "one eve.json line of 10 MiB"}
  - {id: FX-F-10, name: zeek_1m_rows,                  desc: "Zeek conn.log with 1,000,000 rows"}
  - {id: FX-F-11, name: ooxml_8k_relationships,        desc: "one .rels part with 8,000 relationship entries"}
  - {id: FX-F-12, name: pdf_10k_objects,               desc: "PDF with 10,000 indirect objects"}
  - {id: FX-F-13, name: pdf_circular_refs,             desc: "PDF with a reference cycle between indirect objects"}
  - {id: FX-F-14, name: ole_1k_streams,                desc: "OLE container with 1,000 streams"}
  - {id: FX-F-15, name: pe_1k_sections,                desc: "PE declaring 1,000 sections"}
  - {id: FX-F-16, name: pe_100k_imports,               desc: "PE importing 100,000 symbols"}
  - {id: FX-F-17, name: dotnet_huge_us_string_heap,    desc: ".NET metadata with a 50 MiB #US heap"}
  - {id: FX-F-18, name: rtf_1m_groups,                 desc: "RTF with 1,000,000 nested groups"}
  - {id: FX-F-19, name: rtf_hex_run_50mb,              desc: "RTF with a single 50 MiB hex-encoded run"}
  - {id: FX-F-20, name: script_10mb_line,              desc: "PowerShell script with one 10 MiB line"}
  - {id: FX-F-21, name: csv_1m_rows,                   desc: "CSV with 1,000,000 rows"}
  - {id: FX-F-22, name: csv_10k_columns,               desc: "CSV with 10,000 columns"}
  - {id: FX-F-23, name: nmap_10k_hosts,                desc: "Nmap XML with 10,000 hosts"}
  - {id: FX-F-24, name: xml_1m_elements,               desc: "XML with 1,000,000 elements (defusedxml + memory)"}
  - {id: FX-F-25, name: yaml_billion_laughs,           desc: "YAML with recursive anchor expansion (if YAML is accepted)"}
  - {id: FX-F-26, name: json_1m_keys,                  desc: "JSON object with 1,000,000 keys"}
  - {id: FX-F-27, name: zip_65535_entries_32bit,       desc: "ZIP at the 16-bit entry-count boundary without ZIP64"}
  - {id: FX-F-28, name: zip64_entry_count_huge,        desc: "ZIP64 declaring an enormous entry count"}
  - {id: FX-F-29, name: multipart_1000_parts,          desc: "multipart upload with 1,000 non-file parts"}
  - {id: FX-F-30, name: graph_shared_subtree_1k,       desc: "one archive embedding the same child 1,000 times (dedup path)"}
```

### Category G — transport and API abuse (30)

```yaml
fixtures_category_G:
  - {id: FX-G-01, name: upload_zero_bytes,             desc: "empty file part (GATE_EMPTY_FILE)"}
  - {id: FX-G-02, name: upload_over_max_size,          desc: "file part one byte over max_file_bytes"}
  - {id: FX-G-03, name: upload_declared_lie_small,     desc: "Content-Length smaller than the body actually sent"}
  - {id: FX-G-04, name: upload_declared_lie_large,     desc: "Content-Length larger than the body actually sent"}
  - {id: FX-G-05, name: upload_chunked_no_length,      desc: "chunked transfer with no Content-Length (must be accepted)"}
  - {id: FX-G-06, name: upload_slow_body,              desc: "body trickled at 1 byte/s to hit the wall-clock bound"}
  - {id: FX-G-07, name: upload_filename_nul,           desc: "multipart filename containing %00"}
  - {id: FX-G-08, name: upload_filename_traversal,     desc: "multipart filename ../../etc/passwd"}
  - {id: FX-G-09, name: upload_filename_reserved,      desc: "multipart filename CON"}
  - {id: FX-G-10, name: upload_filename_rtl,           desc: "multipart filename with U+202E override"}
  - {id: FX-G-11, name: upload_filename_huge,          desc: "multipart filename of 64 KiB"}
  - {id: FX-G-12, name: upload_filename_invalid_utf8,  desc: "multipart filename with invalid UTF-8 bytes"}
  - {id: FX-G-13, name: upload_two_files,              desc: "two file parts (GATE_TOO_MANY_FILES)"}
  - {id: FX-G-14, name: upload_field_huge,             desc: "non-file part of 1 MiB (GATE_FIELD_TOO_LARGE)"}
  - {id: FX-G-15, name: upload_tenant_mismatch,        desc: "authenticated principal uploading into another tenant"}
  - {id: FX-G-16, name: upload_unauthenticated,        desc: "request with no credentials"}
  - {id: FX-G-17, name: upload_idempotency_mismatch,   desc: "Idempotency-Key reuse with different content"}
  - {id: FX-G-18, name: upload_idempotent_replay,      desc: "identical Idempotency-Key and content (must dedupe)"}
  - {id: FX-G-19, name: upload_rate_burst,             desc: "100 concurrent uploads from one principal"}
  - {id: FX-G-20, name: upload_huge_valid,             desc: "a valid 60 MiB artifact just under the cap (timing)"}
  - {id: FX-G-21, name: upload_content_type_lie,       desc: "Content-Type: application/pdf with PE bytes"}
  - {id: FX-G-22, name: upload_boundary_attack,        desc: "multipart body crafted to confuse the boundary parser"}
  - {id: FX-G-23, name: upload_nested_multipart,       desc: "multipart inside a multipart part"}
  - {id: FX-G-24, name: upload_crlf_in_header,         desc: "header value containing CR/LF (response-splitting attempt)"}
  - {id: FX-G-25, name: upload_duplicate_hash_different_name, desc: "same bytes, different filenames (dedup + display collision)"}
  - {id: FX-G-26, name: upload_quota_exhaust,          desc: "upload that would exceed the tenant quota"}
  - {id: FX-G-27, name: upload_unicode_normalisation,  desc: "filename differing only by NFC/NFD normalization"}
  - {id: FX-G-28, name: upload_reserved_header,        desc: "Hop-by-hop and trailer header abuse"}
  - {id: FX-G-29, name: upload_expect_100_stall,       desc: "Expect: 100-continue stall"}
  - {id: FX-G-30, name: upload_disposition_filename_only, desc: "no multipart filename, only Content-Disposition in a sub-part"}
```

### Category H — telemetry parser adversarial inputs (30)

```yaml
fixtures_category_H:
  - {id: FX-H-01, name: evtx_large_clean,              desc: "1 GiB well-formed EVTX (throughput baseline)"}
  - {id: FX-H-02, name: evtx_truncated_mid_record,     desc: "EVTX cut in the middle of a record"}
  - {id: FX-H-03, name: evtx_bad_checksum,             desc: "EVTX record with a corrupted checksum"}
  - {id: FX-H-04, name: evtx_invalid_utf16,            desc: "EVTX event data with unpaired surrogates"}
  - {id: FX-H-05, name: pcap_medium_clean,             desc: "100 MiB well-formed pcap (TShark timing baseline)"}
  - {id: FX-H-06, name: pcap_memory_stress,            desc: "pcap crafted to maximise dissector memory"}
  - {id: FX-H-07, name: pcap_truncated_header,         desc: "pcap with a file header only"}
  - {id: FX-H-08, name: tenk_records_mixed,            desc: "10,000 records across channels (latency baseline)"}
  - {id: FX-H-09, name: worker_memory_stress,          desc: "harvest sized to hit the per-worker memory ceiling"}
  - {id: FX-H-10, name: schema_violating_event,        desc: "synthetic source record engineered to break a mapping (must be source_contract)"}
  - {id: FX-H-11, name: zeek_missing_fields_header,    desc: "Zeek log with no #fields line"}
  - {id: FX-H-12, name: zeek_column_count_mismatch,    desc: "Zeek row with more columns than #fields declares"}
  - {id: FX-H-13, name: zeek_missing_column,           desc: "Zeek row with fewer columns than declared"}
  - {id: FX-H-14, name: zeek_ts_not_numeric,           desc: "Zeek ts field that is not an epoch float"}
  - {id: FX-H-15, name: eve_invalid_json_line,         desc: "eve.json line 500 is truncated JSON"}
  - {id: FX-H-16, name: eve_event_type_unknown,        desc: "eve.json with an unrecognised event_type"}
  - {id: FX-H-17, name: eve_json_bomb_line,            desc: "one eve line nested 5,000 levels"}
  - {id: FX-H-18, name: syslog_rfc5424_bom,            desc: "5424 line with a UTF-8 BOM and non-UTF-8 payload"}
  - {id: FX-H-19, name: syslog_3164_truncated_pri,     desc: "3164 line with a malformed PRI"}
  - {id: FX-H-20, name: syslog_missing_newline,        desc: "syslog stream with no trailing newline"}
  - {id: FX-H-21, name: cef_escaped_pipe,              desc: "CEF extension value containing an escaped pipe"}
  - {id: FX-H-22, name: cef_unterminated_header,       desc: "CEF header cut before the final pipe"}
  - {id: FX-H-23, name: leef_custom_delimiter,         desc: "LEEF 2.0 with a custom delimiter character"}
  - {id: FX-H-24, name: leef_missing_header,           desc: "LEEF attribute block with no LEEF header"}
  - {id: FX-H-25, name: csv_injection_export,          desc: "CSV whose first cell begins with ="}
  - {id: FX-H-26, name: reg_export_utf16_bom,          desc: "reg export file with a UTF-16 BOM"}
  - {id: FX-H-27, name: netstat_locale_comma,          desc: "netstat output produced under a locale using comma decimals"}
  - {id: FX-H-28, name: nmap_xml_doctype_external,     desc: "Nmap XML with an external DOCTYPE (must be rejected)"}
  - {id: FX-H-29, name: nmap_xml_namespace_prefix,     desc: "Nmap XML with unexpected namespace prefixes"}
  - {id: FX-H-30, name: encoding_mixed_utf8_latin1,    desc: "text log mixing UTF-8 and Latin-1 in one file"}
```

**Coverage mapping.** Every normative limit in §1, §2, §5, §6, §7 and §10
names a fixture above; the four §4 telemetry budgets name FX-H-01, FX-H-05,
FX-H-08 and FX-H-09. A Stage-4 benchmark run that does not execute all 240
fixtures has not validated this document.

---

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

## DECISIONS

```yaml
# Stage-3 design decisions (ingestion, parsers, artifact triage).
# Evidence ids resolve to the Verification Log in §0; labels follow the
# three-value system used throughout Stages 1-3.

decisions:

  - id: D3-001
    title: EVTX parser is the Rust `evtx` binding, with pure-Python python-evtx as fallback; libevtx excluded on licence
    decision: >-
      Primary: PyPI `evtx` 0.13.1 (MIT) wrapping omerbenamram/evtx (Apache-2.0 /
      MIT OR Apache-2.0 dual, active 2026-10-07, no OSV advisories). Fallback
      when the native wheel cannot be installed: williballenthin/python-evtx
      0.8.1 (Apache-2.0, active, Production/Stable). libyal/libevtx is excluded:
      LGPL-3.0-or-later is copyleft and Stage-1 D-008 excludes GPL/AGPL-class
      code from the linked build; no PyPI distribution exists for its bindings
      either, so it would also require an external-process arrangement with no
      compensating benefit.
    evidence: [TL-EVTX-RUST, TL-PYEVTX, TL-LIBEVTX, PRIOR-STAGE1]
    status: accepted

  - id: D3-002
    title: TShark is external-process only, pinned >= 4.6.9, and may use only flags documented in that man page
    decision: >-
      TShark runs as a subprocess under the ExternalProcessRunner (D3-024) with
      a job object, timeout, restricted token and no network. It is pinned at
      >= 4.6.9 because that release fixed 19 advisories including
      CVE-2026-96419 and CVE-2026-5402, both described as possible code
      execution against attacker-controlled input — a pin, not a preference.
      Only -T ek, -T fields, -T json, -Y, -l, -e and -E are used, all documented
      in the TShark 4.6.9 man page; -n (no name resolution) is mandatory so a
      capture cannot trigger DNS egress (§9.4).
    evidence: [TL-TSHARK, PRIOR-STAGE1]
    status: accepted

  - id: D3-003
    title: pandas/polars are not on the ingest path; polars' 2.0.0 distribution change is recorded
    decision: >-
      No bulk tabular library is needed while every supported source has a real
      schema and streams through ijson or stdlib csv. If Stage 4 adds bulk
      analytics, pandas 3.x (win_amd64 wheel confirmed present) is the default.
      polars 2.0.0 publishes only a pure-python meta-wheel plus sdist under the
      `polars` distribution with no platform-native wheel, so the usual
      assumption that the native engine ships in that package no longer holds
      and must be re-checked before adoption.
    evidence: [TL-PANDAS, TL-POLARS]
    status: accepted

  - id: D3-004
    title: Drain3 excluded from Stage 3 on maintenance grounds
    decision: >-
      MIT-licensed and algorithmically sound, but ~8 months without a commit as
      of retrieval, and unnecessary while every supported source is structured.
      Revisit only if a free-text source is added. The maintenance flag is on
      the record so the decision is not re-litigated from memory.
    evidence: [TL-DRAIN3]
    status: accepted

  - id: D3-005
    title: Three-signal identification; magic is authoritative for container, Magika for semantic type, extension is never authoritative
    decision: >-
      S1 libmagic (via python-magic, puremagic fallback), S2 Magika, S3
      filename/content-type/agent hints. S3 never overrides S1 or S2 and is
      consulted only when both are absent. Disagreements are recorded in the
      identification record rather than silently resolved, because extension
      spoofing and polyglots are ordinary in malware and a system that
      collapses its signals cannot express its own uncertainty.
    evidence: [ID-LIBMAGIC, ID-PYMAGIC, ID-PYMAGIC-WIN, ID-PUREMAGIC, ID-MAGIKA, ID-FILETYPE]
    status: accepted

  - id: D3-006
    title: Deterministic selection rule; a magic-vs-Magika disagreement routes to BOTH parsers, not to one
    decision: >-
      §2.3's rule is total and deterministic. When magic and Magika disagree,
      magic's family is selected with confidence=low, disagreement.present is
      set, and — because that disagreement is also the polyglot signal — the
      triage stage runs both family parsers under the §10 budgets instead of
      choosing. Extension disagreement is recorded but never reroutes.
    evidence: [ID-MAGIKA, ID-LIBMAGIC]
    status: accepted

  - id: D3-007
    title: The gate does no content parsing; filenames never cause rejection; storage is content-addressed
    decision: >-
      The gate authenticates, bounds, sanitises names, hashes and persists.
      Identification, parsing, scanning and extraction are triage concerns.
      The client filename is adversarial evidence: it is preserved verbatim as
      original_filename, sanitised for display, and never used to build a path
      and never a reject reason (a weird name is signal, not error). Storage is
      keyed by sha256 only, so a name-collision attack has no target.
    evidence: [UP-FASTAPI, UP-UVICORN, UP-MSNAME]
    status: accepted

  - id: D3-008
    title: Windows filename sanitiser is normative and includes reserved device names and their superscript forms
    decision: >-
      §1.4's seven-step sanitiser is normative: strip control bytes, replace
      the invalid character set, strip trailing spaces/periods, prefix reserved
      device stems (CON/PRN/AUX/NUL/COM1-9/LPT1-9 and the ISO-8859-1 superscript
      variants) with an underscore, truncate display names without splitting a
      code point, fall back to a hash prefix on empty, and case-fold for
      comparison only. Long paths are avoided structurally by short
      content-addressed segments rather than by the \\?\ prefix.
    evidence: [UP-MSNAME]
    status: accepted

  - id: D3-009
    title: The server never reads NTFS alternate data streams; agents lift Zone.Identifier into structured upload fields
    decision: >-
      A colon in a client filename is replaced before anything sees the string,
      and the server never opens an ADS. When an artifact is collected from an
      endpoint, the agent copies the :Zone.Identifier stream into
      motw_zone_id / motw_referrer_url before upload, because the server cannot
      see an endpoint's streams. [MS-FSCC] is the normative reference for the
      stream name and the "[ZoneTransfer] / ZoneId=" payload.
    evidence: [UP-MSADS, DOC-MOTW]
    status: accepted

  - id: D3-010
    title: Apache Tika excluded from the default build
    decision: >-
      Apache-2.0 and functionally attractive, but its own security page states
      that neither tika-server nor tika-grpc is a security boundary, that only
      trusted callers may reach them, and that in-process AutoDetectParser
      denial of service is "not a security vulnerability". Adopting it means
      owning a JVM isolation story that this stage has not designed. Deferred
      to Q3-008.
    evidence: [DOC-TIKA, PRIOR-STAGE1]
    status: accepted

  - id: D3-011
    title: PyMuPDF and pypdfium2 excluded on two independent grounds; Poppler available only as an optional external text extractor
    decision: >-
      PyMuPDF is AGPL-3.0 (Stage-1 D-008 excludes AGPL) and its headline
      capability is rendering (§9.1 excludes rendering). pypdfium2 renders and
      is multi-licensed. Both are excluded twice over. Poppler's pdftotext is
      GPL-2.0-only and parse-only, so it is licence-safe as an external process
      and behaviourally safe for text extraction, but is not in the default
      build; pikepdf/qpdf + pypdf + pdfminer.six cover the default path.
    evidence: [DOC-PYMUPDF, DOC-PDFIUM2, DOC-POPPLER, DOC-PIKEPDF, DOC-QPDF, DOC-PYPDF, DOC-PDFMINER]
    status: accepted

  - id: D3-012
    title: ZIP safety is Sentinel's own responsibility; TAR delegates to the standard library's data filter and then adds stricter checks
    decision: >-
      The zipfile documentation itself names decompression bombs as a hazard
      and provides no limit, so §10's counters are the only defence on the ZIP
      path and carry the fixture load in category B. tarfile has PEP 706
      extraction filters (default `data` since 3.14) whose own documentation
      warns they do not prevent *all* unsafe behaviour, so Sentinel passes
      data_filter and applies §10.2's stricter path rules on top.
    evidence: [ARC-ZIPFILE, ARC-TARFILE]
    status: accepted

  - id: D3-013
    title: libarchive-c chosen for 7z/ISO/CAB/CPIO; py7zr excluded by default on LGPL-2.1
    decision: >-
      libarchive-c is CC0-1.0 over a BSD-3-Clause libarchive — both compatible
      with Stage-1 D-008 — and covers the non-ZIP container set in one binding.
      py7zr is active and well-maintained but LGPL-2.1-or-later, which D-008
      excludes from the linked build; it may be enabled only after a written
      licence review (Q3-007). Whichever 7z library ships must be pinned: the
      py7zr 1.1.3 release note is literally "Fix multiple vulnerabilities".
    evidence: [ARC-LIBARCHIVE, ARC-PY7ZR, PRIOR-STAGE1]
    status: accepted

  - id: D3-014
    title: RAR is listed with rarfile (ISC) but extraction requires an operator-installed external tool; unrar is never vendored
    decision: >-
      rarfile's README states that decompression executes an external tool
      (unrar/unar/7zip/bsdtar). Sentinel therefore reads headers and emits
      archive_member facts without any external tool, and extracts only if the
      operator has installed one; when absent, members are listed but not
      extracted and the run is COMPLETED_WITH_WARNINGS with a
      dependency_missing entry. The unrar licence is restrictive and its
      binaries are not redistributed (Q3-010).
    evidence: [ARC-RARFILE, ARC-7ZIP]
    status: accepted

  - id: D3-015
    title: unblob and binwalk are external-process optional and off by default
    decision: >-
      Both are MIT and active. unblob extracts recursively over 30+ formats and
      binwalk carves embedded files — exactly the behaviour §10 bounds — so
      both are admitted only as operator-enabled enrichment inside the
      quarantined worker with §10's budgets applied by the runner, and only on
      leaf artifacts no family parser claimed.
    evidence: [ARC-UNBLOB, ARC-BINWALK]
    status: accepted

  - id: D3-016
    title: YARA-X is the scanning engine; YARA 4.5.8 is not
    decision: >-
      YARA 4.5.8 (BSD-3-Clause) is in maintenance mode per its own README.
      YARA-X (BSD-3-Clause — not Apache-2.0 as commonly assumed) reached
      production stability in June 2025 and is used in VirusTotal production
      scanning billions of files. YARA-X is chosen; the rules corpus is kept
      4.x-compatible and compatibility is verified in Stage 4 rather than
      assumed.
    evidence: [ARC-YARA, ARC-YARAX]
    status: accepted

  - id: D3-017
    title: ClamAV is external-process optional; its signature database is staged out-of-band
    decision: >-
      GPL-2.0, so it may not be linked; as an external process the licence is
      satisfied. It is not in the default build because its value overlaps
      YARA-X and because signature updates require network egress, which §9.4
      forbids inside the triage worker — the database must be staged out-of-band
      and mounted read-only.
    evidence: [ARC-CLAMAV, PRIOR-STAGE1]
    status: accepted

  - id: D3-018
    title: ssdeep excluded; TLSH chosen for fuzzy hashing
    decision: >-
      The ssdeep Python bindings are LGPL-3.0-or-later *and* have had no commit
      since 2021-12 — two independent disqualifiers. py-tlsh 5.0.0 is
      dual-licensed Apache-2.0 OR BSD-2-Clause and actively maintained; the
      current PyPI name is py-tlsh, not python-tlsh.
    evidence: [ARC-SSDEEP, ARC-TLSH]
    status: accepted

  - id: D3-019
    title: Image metadata comes from exifread + Pillow; hachoir excluded; ExifTool is external-process optional only
    decision: >-
      exifread (BSD-3-Clause) and Pillow (MIT-CMU) cover JPEG/TIFF EXIF and
      format/dimension metadata in-process. Pillow's documented
      MAX_IMAGE_PIXELS (89,478,485) and DecompressionBombError are relied upon
      and additionally capped to a stricter Sentinel value. hachoir is GPL-2.0
      and excluded. ExifTool is dual Artistic-1.0 OR GPL with no LICENSE file
      on GitHub (the README is the only licence statement); as a separate Perl
      process the licence is satisfied, so it stays available as
      operator-enabled enrichment for non-image formats (Q3-013).
    evidence: [ARC-EXIFREAD, ARC-PILLOW, ARC-HACHOIR, ARC-EXIFTOOL]
    status: accepted

  - id: D3-020
    title: capa, FLOSS and Detect-It-Easy are optional capability layers, off by default; PyPI squatters are named explicitly
    decision: >-
      capa (Apache-2.0, v9.4.0) and FLOSS (Apache-2.0) are licence-compatible
      in-process optionals; both are static and capa's README is explicit that
      it handles obfuscation poorly. DIE (MIT — not GPL) is external-process
      optional because it is a Qt application. Warning recorded for deployment:
      the PyPI distributions named `capa` (0.1) and `floss` (0.1.0) are
      unrelated squatters; only the GitHub projects are the real tools, and
      they are not installed from PyPI.
    evidence: [ARC-CAPA, ARC-FLOSS, ARC-DIE]
    status: accepted

  - id: D3-021
    title: oletools static analysis allowed; XLMMacroDeobfuscator excluded from the default build
    decision: >-
      olevba/oleid/oleobj read and classify bytes and are admitted. The XLM
      emulator interprets macro semantics ("without fully performing the code"
      per its README) which crosses §9.2's boundary, so it is excluded from the
      default build and may be enabled only under §9.8's containment with a
      recorded policy exception.
    evidence: [DOC-OLETOOLS, DOC-XLM]
    status: accepted

  - id: D3-022
    title: The static-only prohibition list of §9 is normative and binding on every component, including external processes
    decision: >-
      No rendering, no macro execution, no document interpreters, no network
      egress, no loading artifact bytes into Sentinel's process, no reference
      dereferencing, no destructive operations. §9.8 defines the single,
      expensive, review-gated escape route for a future exception. The list is
      a design constraint, not a configuration surface.
    evidence: [DOC-PYMUPDF, DOC-PDFIUM2, DOC-TIKA, ARC-EXIFTOOL, PRIOR-STAGE1]
    status: accepted

  - id: D3-023
    title: Parser interface is Protocol-based with a shared error taxonomy; per-record exceptions are forbidden; COMPLETED_WITH_WARNINGS is mandatory
    decision: >-
      TelemetryParser and ContentExtractor are typing.Protocols so third-party
      and external-process adapters need not inherit. A malformed record is
      caught, counted and recorded with a locator; exceptions escape only for
      parser bugs. The eight-kind taxonomy (unsupported_format, truncated_input,
      corrupt_record, encoding, resource_limit, dependency_missing,
      source_contract, internal) is normative, and a harvest that lost 3 of
      400,000 records returns COMPLETED_WITH_WARNINGS rather than lying with
      COMPLETED or discarding the good records.
    evidence: [PRIOR-STAGE2]
    status: accepted

  - id: D3-024
    title: All subprocess spawning belongs to an ExternalProcessRunner, never to a parser object
    decision: >-
      Parsers remain side-effect-free (no temp files, no processes, no path
      opens beyond the stream they are handed). The pipeline component that
      owns spawning also owns the job object, timeout, restricted token,
      no-network property, stderr capture, exit-status check and scratch
      cleanup. This keeps §3.2's no-side-effects rule true even for TShark,
      ClamAV and ExifTool.
    evidence: [TL-TSHARK, ARC-CLAMAV, ARC-EXIFTOOL]
    status: accepted

  - id: D3-025
    title: orjson is not used to parse untrusted JSON; ijson is
    decision: >-
      orjson carries two recursion-depth advisories (CVE-2024-27454,
      CVE-2025-67221) and Suricata EVE JSON is attacker-influenceable through
      sensor configuration. Ingest parsing uses ijson (BSD-3-Clause AND ISC,
      no advisories), which also streams. orjson remains permitted for
      *serialising Sentinel-produced data* with a documented depth cap; that is
      a different trust boundary (Q3-011).
    evidence: [TL-ORJSON, TL-IJSON, TL-SURICATA]
    status: accepted

  - id: D3-026
    title: defusedxml is mandatory on every XML path
    decision: >-
      Nmap XML, OOXML parts, SVG, HTML-ish containers and any other XML
      Sentinel opens go through defusedxml (PSFL). The openpyxl documentation
      itself recommends it against billion-laughs attacks. The library's last
      release is 2021-03 — recorded as frozen-but-safe in §0, not abandoned.
    evidence: [TL-DEFUSEDXML, DOC-OPENPYXL, FX-CATALOGUE]
    status: accepted

  - id: D3-027
    title: Artifact analysis is a graph, not a file; `references` edges are terminal
    decision: >-
      Nodes are materialised (bytes + sha256) or structural (a position inside
      a parent). Edges are contains/extracted_from/references/derived_from/
      signed_by/motw_on/same_bytes_as. references edges are recorded and
      detected upon but never followed — the structural expression of §9.6.
      Traversal is bounded by the §6.3 limits and by sha256-based
      cycle/shared-subtree termination.
    evidence: [PRIOR-STAGE2]
    status: accepted

  - id: D3-028
    title: Encrypted content is never analysed without an operator-supplied password list, and the result is reported as a fact, never as a pass
    decision: >-
      Detection is structural only; no guessing. Decryption runs only when a
      workspace password list exists, the scheme is supported and the attempt
      is inside budget (3 attempts, 5 s each — PROPOSED - TO BENCHMARK).
      Passwords are never logged, never returned and never written into facts.
      Decrypted bytes go to quarantine, are re-identified and triaged as a
      child node. The terminal state is encrypted_content_not_analyzed, never
      clean.
    evidence: [DOC-MSOFFCRYPTO, DOC-QPDF, ARC-ZIPFILE, ARC-RARFILE]
    status: accepted

  - id: D3-029
    title: Triage never emits a verdict; the words clean/safe/benign/malicious are banned from the triage vocabulary by name
    decision: >-
      The only outputs are facts, flags, analysis_status and (via §12.4 rules)
      artifact_finding events whose `finding` is a rule id, not an adjective.
      The eleven-value analysis_status enum is normative, with partial as a
      first-class state rather than a hidden one. A patch introducing a banned
      word is rejected on sight.
    evidence: [PRIOR-STAGE2]
    status: accepted

  - id: D3-030
    title: "Archive extraction follows the normative algorithm of §10 (lexical sanitisation, realpath ancestry containment, O_EXCL|O_NOFOLLOW, never creating links)"
    decision: >-
      Member paths are sanitised lexically before any filesystem call, the
      target's real ancestry is asserted to be inside the quarantine root, the
      file is opened O_CREAT|O_EXCL|O_NOFOLLOW with mode 0o600, the copy is
      counted as it streams against both a declared size and a hard cap, and
      symlinks/hardlinks/device nodes are recorded as facts but never created.
      This is deliberately stricter than tarfile's own data_filter, which does
      allow in-destination links.
    evidence: [ARC-TARFILE, ARC-ZIPFILE, UP-MSNAME, FX-CATALOGUE]
    status: accepted

  - id: D3-031
    title: Extractors emit facts only; facts reach detectors solely as artifact_finding events produced by configuration rules
    decision: >-
      §12's rule keeps the "detectors consume only canonical events" invariant
      intact while giving artifact analysis its own vocabulary. The mapper
      populates the categories Stage 2 reserved (document, archive_member,
      executable, artifact); high-cardinality observations stay in the
      artifact_fact sidecar; fact-to-finding rules (configuration data,
      attributed like detection content per Stage-1 D-004) emit
      artifact_finding events. An extractor PR containing a verdict-shaped
      `if` is rejected on sight.
    evidence: [PRIOR-STAGE1, PRIOR-STAGE2]
    status: accepted

  - id: D3-032
    title: Authenticode is reported as presence and identity, with signature.status = unverified_offline
    decision: >-
      Offline verification requires revocation and timestamping lookups, which
      §9.4 forbids inside the triage worker. Sentinel therefore reports
      signed/signer from the PE attribute-certificate table and sets status to
      unverified_offline, rather than implying a chain was validated. An
      online verifier would be a §9.8 policy exception (Q3-021).
    evidence: [ARC-PEFILE, ARC-LIEF, ARC-DNFILE]
    status: accepted

  - id: D3-033
    title: LNK is parsed in-house; no third-party LNK library was opened for Stage 3
    decision: >-
      The Shell Link binary format is specified and small enough to implement
      conservatively for the fields in §5.4. No verified third-party Python
      LNK parser was opened during Stage-3 research, so the in-house parser is
      the honest choice and its unverified-structure claims are listed in
      NOT_VERIFIED rather than being attributed to a library that was not read.
    evidence: []
    status: accepted

  - id: D3-034
    title: Disk images and encrypted volumes are identified and then refused, never mounted
    decision: >-
      Mounting executes a filesystem driver over attacker-controlled bytes,
      which §9.3 prohibits. VHD/VHDX/VMDK/BitLocker/EFS artefacts are
      identified, get analysis_status not_analyzed_by_policy, and produce no
      further events. ISO may be listed through libarchive without mounting.
    evidence: [ARC-LIBARCHIVE]
    status: accepted

  - id: D3-035
    title: Identification samples a bounded head and tail and never reads the whole artifact
    decision: >-
      Magic sampling reads the first 8 KiB and last 4 KiB (PROPOSED - TO
      BENCHMARK); Magika uses its own bounded window. Anything requiring a
      whole-file read is triage, not identification, and carries the §5
      budgets instead.
    evidence: [ID-LIBMAGIC, ID-MAGIKA]
    status: accepted

  - id: D3-036
    title: Rejected uploads are audited with a partial hash, never a whole-file hash
    decision: >-
      The audit row records timestamp, principal, tenant, reject code,
      declared and received sizes, and the sha256 of the first 64 KiB only.
      A whole-file hash of rejected content would let an attacker confirm the
      presence of a known-bad file they were just told not to upload.
    evidence: []
    status: accepted

  - id: D3-037
    title: >-
      The Stage-2 reserved categories are filled by the mapper; every artifact event carries
      derived_by: sentinel
    decision: >-
      No uploaded file carries a source taxonomy, so every mapper-produced
      event sets event.derived_by: sentinel (Stage-2 D2-004). raw holds the
      JSON-serialised fact bundle that produced the event and unmapped[] holds
      facts the mapper declined to place — the documented adaptation of
      Stage-2 D2-012 for artifact events, preserving the property that nothing
      an extractor observed is dropped.
    evidence: [PRIOR-STAGE2]
    status: accepted
```

---

## OPEN_QUESTIONS

```yaml
open_questions:

  - id: Q3-001
    title: TShark job-object containment has not been designed to implementation detail
    detail: >-
      §4.2.2 specifies the containment contract (job object with memory/CPU
      caps, timeout, restricted token, no network, read-only input, pipe-only
      stdout) but the concrete Windows job-object and token configuration is
      not designed here. Given 4.6.9's "possible code execution" advisories
      this is the highest-risk open item in Stage 3.
    blocking: enabling pcap ingest
    candidate_resolution: Stage-4 design of the ExternalProcessRunner with a dedicated threat model; FX-F-07 as the regression fixture.

  - id: Q3-002
    title: No throughput numbers exist for any parser
    detail: >-
      Every budget in §4 and §5 is PROPOSED - TO BENCHMARK. The fixture
      corpus (§11) is specified but has not been built or run.
    blocking: capacity planning, worker sizing
    candidate_resolution: Stage-4 benchmark run over all 240 fixtures; replace each PROPOSED value with a MEASURED (method) value.

  - id: Q3-003
    title: Which libmagic build ships on Windows, and who signs it
    detail: >-
      python-magic needs a native libmagic; ID-PYMAGIC-WIN records the
      bitness-mismatch failure mode and points at third-party 64-bit DLL
      distributions. Shipping an unsigned third-party DLL in a commercial
      product is not acceptable, and python-magic-bin is deprecated since 2017.
    blocking: Windows packaging of the identification stage
    candidate_resolution: build and sign libmagic in our own toolchain, or make puremagic (ID-PUREMAGIC, pure Python) the sole Windows path and accept its smaller magic database.

  - id: Q3-004
    title: Magika model version pinning and update process
    detail: >-
      The model ships in the repository (standard_v3_3 at retrieval) and its
      accuracy claim comes from the README and an ICSE 2025 paper. Sentinel
      needs a policy for pinning a model version, for validating an update
      against the fixture corpus, and for recording the model id in every
      identification record.
    blocking: production identification
    candidate_resolution: Stage-4 pin + regression run; store model id in identification.magika.model.

  - id: Q3-005
    title: Magika accuracy on Windows-specific families is unmeasured
    detail: >-
      The ~99% figure is an aggregate over the published label set. Accuracy
      specifically on PE/Office/LNK/CHM inputs, and on the truncated and
      polyglot shapes of §11 categories B and C, is unknown.
    blocking: trusting S2 in the selection rule
    candidate_resolution: measure over the fixture corpus; if S2 is weak on a family, lower that family's confidence band in §2.3 configuration.

  - id: Q3-006
    title: Magika model licence needs a legal confirmation
    detail: >-
      §0 records that assets/models/standard_v3_3/ contains no separate
      licence file and that the model is therefore treated as Apache-2.0 by
      inclusion with the repository. That is an inference from the absence of
      a file, not a licence grant that was read.
    blocking: commercial distribution
    candidate_resolution: written confirmation from the Magika maintainers, or a legal opinion on the repository-licence-covers-the-model reading.

  - id: Q3-007
    title: py7zr LGPL-2.1 enablement review
    detail: >-
      D3-013 excludes py7zr by default on licence. libarchive-c covers 7z, but
      if a pure-Python 7z path is ever wanted, the LGPL question must be
      answered in writing rather than from memory.
    blocking: nothing today
    candidate_resolution: licence counsel review; record the outcome as a D3 amendment.

  - id: Q3-008
    title: Tika adoption needs an isolation design that does not exist yet
    detail: >-
      Tika's own security documentation says the server and gRPC front ends are
      not security boundaries and that in-process parser denial of service is
      not treated as a vulnerability. Using it means owning a JVM process
      isolation story under §9.8.
    blocking: nothing today
    candidate_resolution: decide explicitly to never adopt, or design the isolation and add §11 fixtures for it.

  - id: Q3-009
    title: Pure-Python pcap alternatives were not evaluated
    detail: >-
      Only TShark was opened. dpkt, scapy and pyshark were not researched in
      this stage, so the claim "TShark is the only pcap parser" means "the
      only one verified", not "the only one that could work".
    blocking: nothing today
    candidate_resolution: evaluate if TShark's containment (Q3-001) proves too expensive.

  - id: Q3-010
    title: RAR extraction tool policy
    detail: >-
      D3-014 lists RAR without extracting unless an operator installs
      unrar/unar/7zip/bsdtar. Which of those is acceptable for redistribution
      or for customer-side installation is a licensing and support question,
      not an engineering one.
    blocking: RAR extraction as a supported feature
    candidate_resolution: decide per tool; document the supported option and the fact that it is optional.

  - id: Q3-011
    title: orjson depth cap and serialisation use
    detail: >-
      D3-025 bars orjson from parsing untrusted JSON but leaves it available
      for serialising Sentinel-produced data. The depth cap value and the
      enforcement point are not specified.
    blocking: nothing today
    candidate_resolution: specify a cap in the serialiser's contract during Stage 4.

  - id: Q3-012
    title: Mach-O parsing has no verified library
    detail: >-
      §5.5 parses Mach-O headers and load commands in-house because no
      third-party Mach-O library was opened. Sentinel is Windows-first so this
      is low priority, but the in-house claims are unverified (NOT_VERIFIED).
    blocking: nothing today
    candidate_resolution: either research a library in Stage 4 or drop Mach-O beyond identification.

  - id: Q3-013
    title: ExifTool enablement policy
    detail: >-
      Dual Artistic-1.0 OR GPL, Perl, external process. Licence-safe when run
      as a separate process and valuable for non-image metadata, but it is a
      per-invocation process with its own parser attack surface.
    blocking: nothing today
    candidate_resolution: decide whether to offer it as operator-enabled enrichment with §9.8 containment.

  - id: Q3-014
    title: OneNote parsing maturity
    detail: >-
      pyOneNote's last PyPI release is 0.0.2 (2023-03) and one-extract describes
      itself as an interim solution. Both are parse-only and correctly
      licensed, but neither is a mature library, and encrypted-notebook support
      was not verified.
    blocking: OneNote triage as a supported feature
    candidate_resolution: keep both as optional cross-checks, or invest in an in-house parser, or drop the family.

  - id: Q3-015
    title: Email formats (.eml/.msg) are out of Stage-3 scope
    detail: >-
      Malspam attachments are a primary real-world source of uploaded artifacts
      and neither format is in §5.
    blocking: nothing today
    candidate_resolution: add a Stage-4 scope decision; MSG is OLE-based and would reuse §5.2.

  - id: Q3-016
    title: NSIS/Inno installers are identified but not unpacked
    detail: >-
      §5.9 lists them and stops. No verified unpacker was opened.
    blocking: installer triage
    candidate_resolution: research SevenZip/innoextract-class tools with the same licence and containment bars as everything else.

  - id: Q3-017
    title: Should high-cardinality facts ever get canonical schema homes
    detail: >-
      §12.3 deliberately leaves pe.import.*, pe.section.* and similar as
      sidecar facts. If detectors eventually need them as first-class fields,
      that is a Stage-2 schema evolution (canonical-event/v2 or an additive
      revision), not a Stage-3 change.
    blocking: nothing today
    candidate_resolution: revisit when a real detection need appears.

  - id: Q3-018
    title: Fact-to-finding rule language
    detail: >-
      §12.4 sketches a YAML rule shape. Stage 1 chose Sigma-compatible content
      for telemetry detection (D-004, D2-014); artifact facts do not fit the
      Sigma logsource model, so this is a second, smaller rule language.
      Whether to build it, or to express artifact rules in the same DRL
      pipeline, is undecided.
    blocking: implementing §12.4
    candidate_resolution: Stage-4 decision with a written comparison.

  - id: Q3-019
    title: Content-addressed dedup scope under multi-tenancy
    detail: >-
      §1.7 dedups per tenant in Stage 3 because deployment is single-tenant
      (Stage-1 D-012) while rows carry tenant/workspace ids. Whether a later
      multi-tenant deployment dedups across tenants (and the confidentiality
      implications of a cross-tenant dedup oracle) is not decided.
    blocking: nothing today
    candidate_resolution: decide before any multi-tenant migration; the row schema already permits either.

  - id: Q3-020
    title: Whether document events are emitted only when metadata exists
    detail: >-
      §12.3 emits a `document` event only when at least one metadata fact
      exists. An alternative is one document event per document artifact with
      state-object fields for everything absent. The current choice avoids
      event noise; the alternative is more uniform.
    blocking: nothing today
    candidate_resolution: revisit after the first detector that consumes document events.

  - id: Q3-021
    title: Online signature verification
    detail: >-
      §9.4 forbids egress, so D3-032 reports unverified_offline. An operator
      may want real Authenticode verification, which would be a §9.8 policy
      exception with revocation-checking egress from a dedicated component.
    blocking: nothing today
    candidate_resolution: only if a customer requirement appears; design under §9.8.

  - id: Q3-022
    title: Zeek v9 and Suricata 8.0.x field-name drift against the Stage-2 corpus pin
    detail: >-
      Stage 2 pinned its mapping work against a specific Zeek source clone and
      the Suricata EVE docs as retrieved then. Zeek v9.0.0 and Suricata 8.0.7
      were verified as current in §0, but the mapping tables were not
      re-diffed against them.
    blocking: nothing today
    candidate_resolution: Stage-4 re-diff of the SEC-B network tables against the current releases; treat any drift as a Stage-2 amendment.
```

---

## NOT_VERIFIED

Consolidated list of every claim in this document that is labelled
PARTIALLY VERIFIED or UNVERIFIED, plus every place where a design rests on a
fact that was not read from a primary source. None of these are used as
required keys, and none is a licence conclusion.

| # | Claim | Where | Why unverified |
|---|---|---|---|
| 1 | openpyxl repository branch, commit and current maintenance state | §5.1, DOC-OPENPYXL | upstream host (foss.heptapod.net) refused automated retrieval and the GitHub mirror 404s; documentation and MIT/Expat licence were read |
| 2 | Poppler official branch/commit | §5.3, DOC-POPPLER | gitlab.freedesktop.org refused automated retrieval; licence and `pdftotext` behaviour read from Debian manpage and a Skia mirror of COPYING |
| 3 | XLMMacroDeobfuscator release version/tag | §5.1, DOC-XLM | 451 commits observed, no release tag observed |
| 4 | Detect-It-Easy application version | §5.10, ARC-DIE | the project publishes only database tags (db, db_extra, current-database, Beta) — no versioned application tags exist |
| 5 | pandas SPDX classifier | §4.3, TL-PANDAS | PyPI JSON `license_expression` was empty in this pass; BSD-3-Clause is asserted from the project's long-standing licence, not from a file read here |
| 6 | Shell Link binary layout details used by the in-house LNK parser | §5.4, D3-033 | no primary specification or third-party implementation was opened during Stage-3 research |
| 7 | Mach-O load-command parsing claims | §5.5, Q3-012 | parsed in-house; no library verified |
| 8 | NSIS and Inno installer internals | §5.9, Q3-016 | no unpacker researched; families identified and stopped |
| 9 | Magika's exact sampling window size | §2.5, D3-035 | the README states an accuracy claim; the implementation's sample size was not read |
| 10 | Magika's published label set includes every family named in §2.3's enum | §2.3 | the model README's label table was read but not cross-checked line-by-line against the enum (e.g. `onenote`, `chm`) |
| 11 | `evtx` PyPI 0.13.1 publishes a win_amd64 wheel | §4.1 | the PyPI release was verified; per-platform wheel files were not enumerated |
| 12 | qpdf's per-scheme PDF decryption support matrix (which of V=2/R=3, AES-128, AES-256 R=6) | §7.1, §7.2 | qpdf's encryption documentation page was read, but the per-scheme support list was not transcribed |
| 13 | rarfile's behaviour when headers are encrypted | §5.8, D3-014 | claimed from the README's external-tool statement; not executed |
| 14 | libarchive's handling of solid 7z archives | §5.8, D3-013 | not exercised |
| 15 | CEF specification currency (Version 27 vs any later revision) | §4.3, TL-CEF | the fetched PDF is Version 27; no index of later revisions was consulted |
| 16 | LEEF specification PDF contents | §4.3, TL-LEEF | the IBM PDF endpoint returns 403 to unauthenticated automated fetch; format confirmed from IBM Docs HTML instead |
| 17 | autorunsc / sigcheck / schtasks CSV header rows | §4.3 (carried forward from Stage 2 NOT_VERIFIED 17–19) | vendor docs do not publish the CSV headers |
| 18 | The exact code points of the Windows reserved superscript device names | §1.4, §10.2 | UP-MSNAME documents that superscript variants exist; the precise code-point list was not transcribed |
| 19 | Which libmagic build Sentinel would ship on Windows | Q3-003 | not decided; third-party DLL distributions were linked from the python-magic README but not vetted |
| 20 | YARA-X rule compatibility with the existing YARA 4.x rule corpus | D3-016 | compatibility is asserted by the project's migration narrative; no rules were compiled here |
| 21 | TShark `-T ek` output contains every field the Stage-2 SEC-B network mapping needs | §4.2 | the flag is documented in the man page; the emitted field-name set was not captured and diffed |
| 22 | Zeek v9.0.0 log field names are identical to the Stage-2 corpus pin | Q3-022 | the current release was verified; the mapping tables were not re-diffed |
| 23 | Suricata 8.0.7 EVE field names are identical to the Stage-2 docs pin | Q3-022 | same |
| 24 | pyOneNote / one-extract behaviour on password-protected notebooks | Q3-014 | one-extract's README mentions password support; not exercised |
| 25 | Pillow's DecompressionBomb thresholds as they behave on the §11 image fixtures | §5.7 | the source constants were read (MAX_IMAGE_PIXELS = 89,478,485); behaviour on the fixtures is unmeasured |
| 26 | olefile's write-path behaviour | §5.2 | the README advertises read/write; Sentinel never writes, so the claim is recorded but unused |
| 27 | Which Artistic License version ExifTool's dual licence refers to | D3-019, ARC-EXIFTOOL | the README says "the same terms as Perl itself (either the Perl Artistic License or GPL)"; no LICENSE file exists on GitHub and license.html 404s |
| 28 | Whether pyelftools' bundled `construct` subtree licence applies to our usage | §5.5, ARC-PYELFTOOLS | the LICENSE file states the project is public domain and notes construct carries its own separate licence; the construct licence text was not read |
| 29 | The libmagic version inside any Windows wheel we might use | Q3-003 | depends on the unresolved packaging choice |
| 30 | TShark's `-n` flag fully prevents all name resolution in every dissector path | §4.2 | `-n` is documented as "no name resolution"; no adversarial verification was performed |

*Generated 2026-10-09 for the Sentinel HIDS Stage-3 deliverable. 75 Verification-Log
entries (73 VERIFIED, 2 PARTIALLY VERIFIED), 37 decisions,
22 open questions, 30 not-verified rows, 240 named adversarial fixtures. All
budgets in this document are labelled PROPOSED - TO BENCHMARK; none is
presented as a measurement.*
