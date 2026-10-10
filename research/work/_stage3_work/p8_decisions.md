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
    evidence: [TL-DEFUSEDXML, DOC-OPENPYXL, FX-C-23, FX-C-24, FX-C-25]
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
    title: Archive extraction follows the normative algorithm of §10: lexical sanitisation, realpath ancestry containment, O_EXCL|O_NOFOLLOW, and never creating links
    decision: >-
      Member paths are sanitised lexically before any filesystem call, the
      target's real ancestry is asserted to be inside the quarantine root, the
      file is opened O_CREAT|O_EXCL|O_NOFOLLOW with mode 0o600, the copy is
      counted as it streams against both a declared size and a hard cap, and
      symlinks/hardlinks/device nodes are recorded as facts but never created.
      This is deliberately stricter than tarfile's own data_filter, which does
      allow in-destination links.
    evidence: [ARC-TARFILE, ARC-ZIPFILE, UP-MSNAME, FX-A-27, FX-A-28]
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
    title: The Stage-2 reserved categories are filled by the mapper; every artifact event carries derived_by: sentinel
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

*Generated 2026-10-09 for the Sentinel HIDS Stage-3 deliverable. 61
Verification-Log entries (59 VERIFIED, 2 PARTIALLY VERIFIED), 37 decisions,
22 open questions, 30 not-verified rows, 240 named adversarial fixtures. All
budgets in this document are labelled PROPOSED - TO BENCHMARK; none is
presented as a measurement.*
