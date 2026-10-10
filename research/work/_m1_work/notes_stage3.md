# Stage 3 notes for M1 — exact extraction

Source: `stage-3-ingestion-and-artifact-triage.md` (Stage 3 — Ingestion and Universal Artifact Triage, status "complete draft for review", dated 2026-10-09). Read in full, all 3936 lines. Every field name / enum / code / signature below is copied verbatim; anything absent from the source is marked **not specified**.

**M1 relevance warning:** the string "M1" (or "milestone") does NOT appear anywhere in Stage 3. Stage 3 specifies the whole 4-stage system. Where this file says "M1", that is the M1 brief (API accepts EVTX upload → ingest job → canonical-event/v1 rows in PostgreSQL, partial success + counters, provenance), not Stage-3 text. Stage-3-only facts are cited as "Stage 3 §x.y".

Inherited (not restated by Stage 3): Stage 1 D-001…D-012 (Python 3.12+ / FastAPI / PostgreSQL / background worker; Sigma-compatible content; DRL attribution; no GPL/AGPL code copying; single-tenant now / multi-tenant-ready) and Stage 2 D2-001…D2-024 (canonical-event/v1 envelope, value-state model, lossless `raw` + `unmapped[]`, three-level semantic classification, reserved categories `document`/`archive_member`/`executable`/`artifact`/`artifact_finding`, D2-024 schema_version gate).

Two cross-cutting invariants (Stage 3 preamble):
- **Static-only invariant:** Sentinel never executes/renders/interprets/macro-runs/prints/emulates-as-a-program/resolves-out-to-network an uploaded artifact or any byte extracted from one. Parsers may decompress/decode/tokenise/deobfuscate *bytes*; never cause *behaviour* (§9 normative, §10 containment).
- **Budget discipline:** every size/time/memory/ratio/count/depth limit is `PROPOSED - TO BENCHMARK` with a §11 fixture id. No number in Stage 3 is a measured fact.

Evidence label prefixes (§0) — these are **evidence ids, not triage outputs**: `ID-` = identification and upload gate, `TL-` = telemetry parsers and text carriers, `DOC-` = document triage, `ARC-` = archive/binary/generic triage. §0 holds 75 entries: 73 VERIFIED, 2 PARTIALLY VERIFIED (DOC-POPPLER, DOC-OPENPYXL).

---

## 1. §1 Upload Gate

### 1.1 Surface (§1.1 table, verbatim)

| Item | Specification |
|---|---|
| Endpoint | `POST /v1/workspaces/{workspaceId}/uploads` (multipart/form-data, one file part named `file`; optional non-file parts `run_id`, `agent_id`, `collection_kind`, `source_path`, `motw_zone_id`, `motw_referrer_url`) — **C-4-fix**: OpenAPI `createUpload` is normative; the pre-namespace `POST /v1/artifacts` sketch is superseded |
| Companion | `GET /v1/workspaces/{workspaceId}/uploads/{artifactId}` (status, triage state, rejection reason if any) — C-4-fix (was `GET /v1/artifacts/{artifact_id}`) |
| Auth | same bearer/session scheme as the rest of the API; the authenticated principal MUST resolve to exactly one `tenant_id` and one `workspace_id` |
| Idempotency | `Idempotency-Key` header; a replay with the same key AND the same content sha256 returns the original `artifact_id` with HTTP 200; same key, different sha256 → HTTP 409 `GATE_IDEMPOTENCY_MISMATCH` |
| Response (accepted) | HTTP **202** `Upload{artifact_id, run_id, sha256, size, received_at, triage_state, …}` per OpenAPI — **C-4-fix**: the earlier HTTP 201 `{artifact_id, sha256, size, storage_key, triage_job_id, gate: {renamed, warnings[]}}` sketch is superseded by the OpenAPI `Upload` schema (`run_id` is server-generated when the client omits it — C-4b-fix) |
| Response (rejected) | HTTP 4xx `{code, message, detail}` where `code` is one of the §1.5 reject codes; the body never echoes the client filename verbatim (it is stored, see §1.4) |
| Async model | the accepted (202) response means "persisted and queued". Triage outcome is never returned synchronously. |

Notes: the full field list of the OpenAPI `Upload` schema beyond `artifact_id, run_id, sha256, size, received_at, triage_state, …` — the trailing `…` is in the source; the exact complete list is **not specified** in Stage 3 (it lives in the OpenAPI document). `storage_key` and `triage_job_id` appear ONLY in the superseded 201 sketch — do not return them. The artifact record still HAS `storage_key` (§1.6), it is just not in the 202 body.

### 1.2 Order of gate checks

Stage 3 §1 opening, verbatim: "The gate therefore does exactly five things and nothing else: **authenticate, bound, sanitise names, fingerprint, persist.**" That is the normative order. Additionally §1.2: "The gate MUST reject before any library parses the body."

Mapping:
1. **authenticate** — bearer/session principal; principal MUST resolve to exactly one `tenant_id` + one `workspace_id` (§1.1); tenant/workspace binding → `GATE_UNAUTHENTICATED`/`GATE_FORBIDDEN`/`GATE_TENANT_MISMATCH` (§1.5).
2. **bound** — transport bounds + rate/quota (§1.2 table below), all enforced before Starlette's multipart parser runs.
3. **sanitise names** — §1.4 S1–S7 (display name only; no rejection from a name).
4. **fingerprint** — compute sha256/SHA-1/MD5 + size, and nothing else (§1.3).
5. **persist** — content-addressed store write (§1.7) + accepted-upload record (§1.6).

Where the `Idempotency-Key` check sits relative to those five steps — **not specified** (it is specified only as behaviour in §1.1).

### 1.3 Size limits and where they come from (§1.2)

Neither uvicorn nor Starlette enforces a request-body size limit natively (UP-UVICORN: uvicorn Resource Limits are concurrency/requests/backlog only; Starlette `max_part_size` applies to non-file form fields, not uploaded files), so "every bound below is implemented by Sentinel as **ASGI middleware**, not by configuring a framework knob that does not exist."

| Bound | Proposed default | Enforced where | Fixture / method |
|---|---|---|---|
| `max_request_bytes` (whole HTTP body incl. multipart overhead) | 64 MiB `PROPOSED - TO BENCHMARK` | ASGI middleware, before Starlette's multipart parser runs | FX-G-21, FX-G-22 |
| `max_file_bytes` (the file part's declared or observed length) | 64 MiB `PROPOSED - TO BENCHMARK` | middleware + streaming copy counter | FX-B-01…FX-B-05 |
| `max_files_per_request` | 1 `PROPOSED - TO BENCHMARK` (one artifact per request by design; multipart parser's own default is 1000, UP-FASTAPI) | middleware | FX-G-23 |
| `max_field_bytes` (non-file parts) | 8 KiB `PROPOSED - TO BENCHMARK` | Starlette form parsing | FX-G-24 |
| Request wall-clock | 30 s `PROPOSED - TO BENCHMARK` | ASGI middleware timeout | FX-G-25 |
| Concurrent uploads per principal | 4 `PROPOSED - TO BENCHMARK` | rate limiter | FX-G-26 |
| Uploads per principal per hour | 500 `PROPOSED - TO BENCHMARK` | rate limiter | FX-G-26 |
| Tenant artifact quota | operator-configured; default 50 GiB `PROPOSED - TO BENCHMARK` | pre-flight sum of stored sizes + post-write accounting | FX-G-27 |

**Spooling:** file part MUST NOT be buffered in memory. Starlette `UploadFile` spools (`SpooledTemporaryFile`, upstream `spool_max_size` = 1 MiB — UP-FASTAPI / UP-SPOOL), but Sentinel MUST NOT rely on that default: gate calls `await file.seek(0)` then streams to the content-addressed store with its own fixed-size buffer (`PROPOSED - TO BENCHMARK`: 1 MiB) and a running byte counter, aborting the moment the counter passes `max_file_bytes`. **The counter is authoritative; `Content-Length` is advisory** and checked only for an early reject.

**Chunked transfer:** `Transfer-Encoding: chunked` with no `Content-Length` is accepted. A declared `Content-Length` that disagrees with bytes actually received is a reject (`GATE_BODY_LENGTH_MISMATCH`), not a silent truncate (silent truncation would corrupt the dedup index).

**What the gate deliberately does NOT do (§1.3):** no content parsing (only sha256/SHA-1/MD5 + size; format identification §2 is a triage-stage concern); no antivirus or YARA at the gate (those run in §5); no decompression, no archive listing, no magic-byte sniff (the gate's read is only "once into the hasher and once into the store"; identification reads from the store afterwards); no rejection on content — a file is never rejected because of what it contains.

### 1.4 Filename handling (§1.4)

Client filename is **adversarial input, never trusted, never used to build a filesystem path, never a reason to reject**. Three names:
1. `original_filename` — exact bytes of the multipart filename parameter, opaque UTF-8 string (with `surrogateescape` for undecodable bytes). Never written to disk. Never rendered unescaped without output encoding.
2. `storage_key` — sha256 hex of content; the only thing that names a path in the store (content-addressed → name-collision attack has no target).
3. `display_name` — derived once for humans by the sanitiser; used only in API responses and UI.

**Windows sanitiser (normative, in order; evidence UP-MSNAME, UP-MSADS):**

| Step | Rule |
|---|---|
| S1 | Decode percent-escapes and normalise quotes; then strip bytes 0x00–0x1F. |
| S2 | Replace every character in `< > : " / \ \| ? *` with `_` (colon would otherwise open ADS or drive syntax). |
| S3 | Strip trailing spaces and trailing periods. |
| S4 | If the stem (text before first dot) case-insensitively equals a reserved device name — `CON`, `PRN`, `AUX`, `NUL`, `COM1`…`COM9`, `LPT1`…`LPT9`, plus the ISO-8859-1 superscript forms (`C0`…`C9` with a combining superscript, and `LPT1`–`LPT9` superscript variants) — prefix with `_`. |
| S5 | Truncate `display_name` to 200 UTF-8 bytes without splitting a code point; keep the extension if it fits (`PROPOSED - TO BENCHMARK`, FX-A-21…FX-A-25). Full original retained in `original_filename`. |
| S6 | Reject empty results by falling back to the first 16 hex chars of the sha256 as `display_name`. |
| S7 | Case-fold for comparison only. Case-only differing display names are two distinct content-addressed objects; the display collision is recorded as a **gate warning, not an error**. |

**Long paths:** storage under a content-addressed key avoids MAX_PATH 260 structurally (short key segments), not via `\\?\` or registry opt-out. A worker opening a reported path uses `\\?\` and treats path-too-long as a parse warning, never a crash.

**ADS:** colon replaced at S2. Agent-collected artifacts: the agent MUST copy `:Zone.Identifier` into the structured `motw_zone_id` / `motw_referrer_url` upload fields before upload (server cannot see endpoint NTFS streams). Normative refs: UP-MSADS (stream name `[ZoneTransfer]` / `ZoneId=`), DOC-MOTW.

### 1.5 Reject codes (§1.5 — full table, verbatim)

"The gate has exactly these reject codes. Anything else is a 5xx and a bug."

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

13 rows / 14 distinct codes. Rejection body: `4xx {code, message, detail}`; never echoes the client filename (§1.1). Fixture cross-refs: FX-G-01 → `GATE_EMPTY_FILE`, FX-G-13 → `GATE_TOO_MANY_FILES`, FX-G-14 → `GATE_FIELD_TOO_LARGE`, FX-G-15 tenant mismatch, FX-G-16 unauthenticated, FX-G-17 idempotency mismatch, FX-G-18 idempotent replay (must dedupe).

**Tenant/principal binding (GATE_TENANT_MISMATCH):** two distinct conditions — (a) §1.5 row: "upload claims a tenant/workspace the principal does not own" → 403 `GATE_TENANT_MISMATCH`; (b) principal not scoped to this tenant/workspace → 401/403 `GATE_UNAUTHENTICATED`/`GATE_FORBIDDEN`. `tenant_id` on the record comes "from the principal, never from the body" (§1.6 comment).

**Audit for rejected uploads (§1.5):** rejected uploads are still audited — a row with the timestamp, principal, tenant, `code`, declared size, received size and the **sha256 of the first 64 KiB** (NOT the whole file — a whole-file hash of rejected content would let an attacker confirm the presence of a known-bad file they were told not to upload; D3-036). Retention operator-configured; default 90 days `PROPOSED - TO BENCHMARK`. Audit table name — **not specified**.

**Idempotency (§1.1):** same `Idempotency-Key` + same content sha256 → HTTP **200** returning the original `artifact_id`; same key + different sha256 → HTTP **409** `GATE_IDEMPOTENCY_MISMATCH`. (An idempotency storage table is not specified in Stage 3.)

### 1.6 Accepted-upload record (§1.6, verbatim YAML)

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

"The record is the join key for everything downstream: telemetry events link to it through `source.file_id` (Stage-2 envelope), and triage facts link through `artifact_id`." → **provenance anchor for M1**: every canonical event carries `source.file_id` = this `artifact_id`.

### 1.7 Content-addressed store (§1.7)

- Layout: `<root>/<sha256[0:2]>/<sha256[2:4]>/<sha256>` — flat, dedup by construction, no filename component anywhere in the path.
- Write protocol: write to `*.tmp`, fsync, hash-verify, atomic rename. A partially written object is never visible under its final name.
- Dedup is per-tenant in Stage 3 (single-tenant deployment per Stage-1 D-012); row carries `tenant_id` and `workspace_id`.
- Immutability: artifacts never mutated in place. Extraction output goes to a separate quarantine namespace keyed by parent sha256 + member path (§10).

---

## 2. §2 Identification

"Identification answers one question — *what is this byte stream?* — and is explicitly forbidden from answering a second one — *is it dangerous?*" Output is a stored structured record (so a human can see why a parser was or was not applied), not a secret routing decision.

### 2.1 Three signals (§2.1)

| Signal | Source | Class of answer | Authority |
|---|---|---|---|
| **S1 — Container (magic)** | libmagic through python-magic (ID-PYMAGIC, ID-LIBMAGIC); pure-Python fallback `puremagic` (ID-PUREMAGIC) when the libmagic DLL is absent or the bitness mismatch in ID-PYMAGIC-WIN occurs | level-1 physical container (`zip`, `pdf`, `msdos/mz`, `evtx`, `pcapng`, …) | authoritative for *container* only |
| **S2 — Semantic content type** | Magika (ID-MAGIKA) over a bounded head/tail sample | level-2 semantic type (`peexe`, `word-document`, `javascript`, `pdf`, `powershell`, …) | authoritative for *content type* only |
| **S3 — Hints** | multipart filename extension, `Content-Type`, agent-declared `collection_kind`, `source.format` from a telemetry harvest manifest | nothing | **advisory only, never authoritative** |

S1 and S2 are independent measurements; Sentinel never silently prefers one over the other and never lets S3 override either. **Filename usage:** the extension is only an S3 hint, consulted only when both S1 and S2 are absent (`selected_by = hint_fallback`, `confidence = low`); a hint disagreement sets `disagreement.present` and records the kind, but never reroutes (D3-006: "Extension disagreement is recorded but never reroutes").

### 2.2 Identification record (§2.2, verbatim YAML)

```yaml
identification:
  artifact_id: string
  size: int
  sha256: hex64
  magic:
    mime: string|null            # e.g. application/zip
    description: string|null     # libmagic's human string, e.g. "Microsoft Excel 2007+
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

"`selected` is the only value parsers read for routing. It is chosen by the deterministic rule in §2.3 and is never produced by a human or by a detector."

### 2.3 Selection rule (§2.3, normative, verbatim)

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

**Telemetry-family precedence (D8-06 fix)** — bounded content-sniff applied **before** the family map, first match wins:
1. Nmap XML: root element `nmaprun` (XML) → `selected = nmap_xml`.
2. Suricata EVE: JSON object with `event_type` + `timestamp` keys → `suricata_eve`.
3. Zeek TSV: first line starts `#separator` (or `#open`) → `zeek_tsv`.
4. CEF: line starts `CEF:` → `cef`.
5. LEEF: line starts `LEEF:` → `leef`.
6. Syslog: line matches RFC 5424 (`<PRI>VERSION ...`) or RFC 3164 (`<PRI>Mmm dd ...`) → `syslog`.
7. Windows export: header row matches a known tool export (Autoruns/`Process Explorer`/`Sigcheck` column set) → `winexport`.

Only if none match does the normal magic/magika family map apply. The sniff is **configuration data (signatures in YAML), never a hard-coded detector**; each hit sets `selected_by = magic` with `confidence = high`.

**Format-family map (§2.3; `selected` is a fixed enum; magic→enum and Magika→enum maps are configuration data in YAML, not code):**

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

OOXML equivalence: a `.docx` IS a ZIP container, so agreement at family level is computed over a declared equivalence (`ooxml ⊂ archive`) and the more specific family wins; that equivalence is configuration data.

**Magic bytes — what is and is not specified:** Stage 3 has NO table of raw hex magic signatures per format (e.g. the EVTX `ElfFile\0` header bytes are **not specified**). The only literal byte/signature checks stated anywhere are: pcapng magic `0a0d0d0a`; ZIP central directory present + `%PDF-` at offset 0 (polyglot rule 2); PE first section beginning `%PDF-`, `PK\x03\x04`, `\x1f\x8b` (polyglot rule 3); SQLite `SQLite format 3\0` (§5.9b, absent → not opened); the §2.3 seven content-sniff signatures; and the §7.1 encryption signals (OOXML `EncryptionInfo` part / `EncryptedPackage` part / ZIP general-purpose bit 0; OLE `EncryptedPackage` stream or WordDocument/Workbook FIB flags; PDF `/Encrypt` in trailer; 7z header-encoded streams; RAR encrypted-headers flags). The EVTX→`selected: evtx` magic mapping itself: "vendor-specific", exact bytes **not specified** (it lives in the YAML family map).

### 2.4 Polyglots, truncation, encryption (§2.4)

- `polyglot_suspected = true` when: (1) libmagic description names two formats, or Magika family differs from magic family with `disagreement.kind = magic_vs_magika`; (2) ZIP with central directory also begins `%PDF-` at offset 0 or contains a member named `%PDF`/`%!/` at offset 0; (3) PE whose first section begins another family's magic; (4) image payload containing a complete ZIP central directory. Triage then runs **both** family parsers under §10 budgets (D3-006).
- Truncation is NOT an error: parse what is present, set `analysis_status: truncated` (§8), put the evidence string in the record.
- Encryption pre-detection: detection by structure, never guessing; `selected` stays the container family; `encrypted.detected = true` + scheme name. §7 owns policy.

### 2.5 Identification budgets (§2.5)

| Item | Proposed value |
|---|---|
| Bytes sampled for magic | first 8 KiB + last 4 KiB `PROPOSED - TO BENCHMARK` (FX-C-01…FX-C-05) |
| Bytes sampled for Magika | Magika's own bounded sample (up to the model's window) (FX-C-06…FX-C-10) |
| Wall-clock per identification | 200 ms p95 `PROPOSED - TO BENCHMARK` (FX-C-11) |
| Identification memory ceiling | 32 MiB `PROPOSED - TO BENCHMARK` (FX-C-12) |

"Identification MUST NOT read the whole artifact to answer; anything that requires whole-file reading is triage (§5), not identification." (D3-035 restates first 8 KiB + last 4 KiB.)

### 2.6 Licence notes for the stack (§2.6)

libmagic (2-clause BSD text / GitHub NOASSERTION, in-process via binding); python-magic (MIT + libmagic LEGAL.NOTICE, in-process, needs native libmagic, Windows DLL bitness must match interpreter — ID-PYMAGIC-WIN); puremagic (MIT, pure Python, no DLL — **the designated Windows fallback**); python-magic-bin (MIT but stale 2017/deprecated — **not used**); Magika (Apache-2.0, in-process; ONNX model inside repo, no separate model licence file — see Q3-006). No GPL/AGPL in the identification path (Stage-1 D-008 satisfied without external-process workaround). `filetype.py` (ID-FILETYPE) is cited as evidence in D3-005 but its role in the pipeline is **not specified**.

---

## 3. §3 Parser Interface

Two families, one contract: **Telemetry parsers** (harvested logs → `canonical-event/v1` events) and **Content extractors** (artifact bytes → *facts*, §12; a separate mapper turns facts into canonical events). The interface is a `typing.Protocol` plus a documented ABC for shared plumbing; parsers are **not** required to inherit the ABC, only satisfy the Protocol.

### 3.1 Types (§3.1, verbatim from `sentinel/ingest/parser_api.py`)

```python
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import BinaryIO, ClassVar, Iterator, Literal, Mapping, Protocol, runtime_checkable

Status = Literal["COMPLETED", "COMPLETED_WITH_WARNINGS", "FAILED"]

CanonicalEvent = Mapping[str, object]   # Stage-2 object, typed as Mapping only; validation
                                        # against canonical_event_v1.schema.json happens once,
                                        # at the pipeline boundary


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
    coverage: Mapping[str, object]   # e.g. {"channels": {...}, "columns_unbound": [...]}

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

**Lifecycle answer for M1:** there is NO `open()`/`close()` in the contract. Lifecycle = `sniff(head, ctx)` (cheap, non-authoritative) → `parse(stream, ctx)` **generator** (lazy `Iterator[CanonicalEvent]`) → `finalize()` (idempotent, returns `ParserResult`, "Always returned — even on total failure"). ContentExtractor: `extract(stream, ctx) -> Iterator[Fact]` + `finalize()`.

**Progress reporting:** there is NO progress-callback interface — **not specified**. What parsers report is: counters in `ParserResult` (`records_seen`, `events_emitted`, `records_failed`, `bytes_read`), `warnings: list[ParserWarning]`, `errors: list[ParserError]`, `coverage` (parser-specific mapping), all delivered via the single `finalize()` call.

### 3.2 Normative behaviour of `parse`/`extract` (§3.2, all nine)

1. **Streaming.** `parse` is a generator. A parser MUST NOT require the whole stream in memory. Where a third-party library materialises the whole object (OLE container directory, OOXML part table), the parser MUST materialise *the index*, not the payload bytes, and MUST stream payloads.
2. **Never raise per record.** A malformed record is caught inside the generator, recorded as a `ParserError` with a locator, counted in `records_failed`, and iteration continues. Exceptions escape only for programmer errors (a bug in the parser), which the pipeline converts to `status: FAILED` at the job level.
3. **Never return partial objects silently.** A record that could not be fully interpreted still yields an event if the envelope could be built — with unavailable values in Stage-2 value-state form `{"$state": "invalid", "$raw": ...}`, not omitted and not bare-null (D2-001).
4. **Losslessness.** `raw` carries the verbatim source record (string for text/EVTX-rendered, object for JSON) and `unmapped[]` carries named source fields with no canonical home. Both on by default; a parser MUST NOT drop a source field with no canonical destination (D2-012).
5. **Cancellation.** Before each record a parser checks `time.monotonic() >= ctx.deadline_monotonic` and its own byte/event counters. On breach it stops cleanly and returns `status: COMPLETED_WITH_WARNINGS` with a `resource_limit` error entry that records the number of records it managed to emit.
6. **Determinism.** Same bytes + same config → same events in the same order. Parsers MUST NOT consult wall clock, randomness, network, environment variables, or locale.
7. **No side effects.** A parser writes nothing outside the pipeline's output buffers: no temp files, no spawning processes (external-process parsers are driven by the *pipeline*, §4), no opening any path other than the `stream` it was given.
8. **Timezone honesty.** Never guess a timezone (D2-003). No documented timezone and no `timezone_default` → `time.timezone_source: none`.
9. **Schema conformance is the pipeline's job, not the parser's.** The pipeline validates emitted events against `canonical_event_v1.schema.json` and records a `source_contract` error for any event that fails. Parsers SHOULD emit conforming events; they are not required to re-validate internally per record.

### 3.3 Error taxonomy (§3.3, verbatim)

| Kind | Meaning | Typical locator | Effect on status |
|---|---|---|---|
| `unsupported_format` | stream identification said it owns is not that format | byte offset 0 | FAILED if before the first record; otherwise a warning |
| `truncated_input` | stream ends inside a record/container | byte offset / record id | warning; remaining records skipped |
| `corrupt_record` | record structurally invalid (bad CRC, bad XML, bad length prefix) | record id / line | per-record; counts toward `records_failed` |
| `encoding` | byte sequence could not be decoded in the declared encoding | record id / field | per-record; raw bytes go into `$raw` with `$state: invalid` |
| `resource_limit` | deadline, `max_events`, `max_bytes_read`, `max_record_bytes`, or an external process's own limit | n/a | warning if anything was emitted; FAILED if nothing was |
| `dependency_missing` | optional native library or external binary not installed | n/a | FAILED, and the job is marked retryable-by-operator |
| `source_contract` | emitted event failed schema validation, or source violated a documented contract (e.g. `#fields` header not matching column count) | record id | warning; offending event dropped and counted |
| `internal` | a bug in the parser | stack hash | FAILED |

**COMPLETED_WITH_WARNINGS semantics (§3.3, verbatim):** "`COMPLETED_WITH_WARNINGS` is mandatory, not optional (inherited invariant): a harvest that lost 3 of 400,000 records is a *success with warnings*, and the operator's dashboard must say so, rather than either lying with `COMPLETED` or throwing away 399,997 good records with `FAILED`." (D3-023 repeats this.) `ParserResult.partial` property ⇔ `status == "COMPLETED_WITH_WARNINGS"`.

### 3.4 The pipeline around the interface (§3.4)

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

Two invariants: (a) **detectors still consume only canonical events** — artifact facts are never handed to detectors; they are mapped to reserved canonical categories and evaluated by fact-to-finding rules whose *output* is `artifact_finding` canonical events; (b) **external-process parsers are driven by the pipeline, not by the parser object** — the parser is a thin adapter reading the subprocess's stdout stream; spawn/sandbox/timeout/caps belong to the pipeline's `ExternalProcessRunner`.

### 3.5 Provenance attachment (what Stage 3 actually says)

- **Parser name+version:** `TelemetryParser.parser_id` ClassVar "appears in `source.parser`" (e.g. `"evtx.rust"`); `parser_version` ClassVar "appears in `source.parser_version`". Same values are copied into `ParserResult.parser_id` / `.parser_version`. §4.4 header: "Parser id (goes in `source.parser`)".
- **File id:** every artifact row's `artifact_id` (§1.6); "telemetry events link to it through `source.file_id` (Stage-2 envelope)" (§1.6 and §6.3: "The root artifact id is the join key back to §1.6 and to telemetry through `source.file_id`").
- **sha256:** on the artifact record (§1.6) / identification record (§2.2). Stage 3 does **not** restate a per-event `source.file.sha256` field name — that lives in the Stage-2 envelope; the per-event sha256 field name is **not specified** here beyond `source.file_id`.
- **Record/line numbers:** `ParserError.locator` and `ParserWarning.locator` — "record locator: line number, record id, byte offset, sheet name". For mapper-produced artifact events (§12.3): `source.record.type` = `event_record` for event-shaped things and `byte_offset`/`part` where a locator exists. A dedicated per-emitted-event record-number column for telemetry events is **not specified** in Stage 3 (Stage-2 envelope owns it).
- **Mapper events (§12.3 envelope values):** `event.derived_by: sentinel` in all cases; `event.action` = `observe`/`identify`/`list`/`profile`; `event.outcome: success` unless extractor failed; `source.format` = `identification.selected`; `source.parser` = extractor id; `raw` = the JSON-serialised fact bundle (deliberate adaptation of D2-012, D3-037); `unmapped[]` = facts the mapper declined to place.

### 3.6 ExternalProcessRunner contract

Stage 3 gives the contract, not a class signature (the concrete Windows job-object/token design is Q3-001, "the highest-risk open item in Stage 3"). D3-024: "All subprocess spawning belongs to an ExternalProcessRunner, never to a parser object" — that component owns job object, timeout, restricted token, no-network property, stderr capture, exit-status check and scratch cleanup.

**§4.2.2 containment contract (verbatim requirements), applies to TShark, ClamAV, ExifTool, and any future external parser.** Each spawn MUST have:
- a job object with a memory ceiling and CPU time cap;
- a wall-clock timeout enforced by the runner;
- stdin closed and stdout streamed (never a temp file both sides share);
- stderr captured and truncated (truncation size **not specified**);
- no network (job object + no proxy env + allowlist-empty);
- a restricted token with no SeDebugPrivilege;
- working directory set to a per-job scratch directory that is deleted afterwards;
- the input delivered as a read-only path inside the quarantine namespace (§10).

"A non-zero exit, a timeout, or a broken stdout stream yields `ParserError(kind=resource_limit|internal)` and `COMPLETED_WITH_WARNINGS` when any packet was already emitted."

**Budgets (TShark row, §4.2):** wall-clock per 100 MB pcap 120 s `PROPOSED - TO BENCHMARK` (FX-H-05); memory per TShark job 512 MiB (FX-H-06); packets dropped on limit breach counted in `coverage.dropped_packets` (FX-H-07). Generic external-process stdout byte caps / output caps beyond "stdout streamed, stderr captured and truncated" — **not specified**.

§9.8 (escape route for anything that would break §9.1–9.7) additionally requires: separate process; job object w/ memory ceiling + CPU cap + wall-clock timeout; restricted token/AppContainer with no `SeDebugPrivilege`, no process creation, read-only view of quarantine; network egress blocked at process level; stdout a pipe (never shared temp file), stderr captured+truncated, exit status checked; input as read-only path under quarantine root, deleted after run; a §11 fixture + Stage-4 benchmark coverage; the §13 licence review redone. "Nothing in the Stage-3 default build invokes it."

### 3.7 Streaming / bounded-memory requirements (summary)

Generator-based `parse` (§3.2.1), materialise index not payload, per-record cancellation against `deadline_monotonic`/`max_events`/`max_bytes_read`/`max_record_bytes`, no whole-file reads at identification (§2.5), graph/extraction budgets (§6.3, §10.1). Stage-3 never requires an in-memory full-file buffer anywhere.

---

## 4. §4 Parser Decision Matrix — EVTX and the rest

### 4.1 Windows event logs (§4.1 verbatim rows)

| Format | Candidate | Version / commit observed | SPDX | Class | Verdict |
|---|---|---|---|---|---|
| EVTX | `evtx` (PyPI binding of omerbenamram/evtx) | 0.13.1 (2026-09-22); head 7479d02 (2026-10-07) | MIT OR Apache-2.0 (crate); MIT (binding) | in-process | **chosen** |
| EVTX | python-evtx (williballenthin) | 0.8.1 (2025-05-02); head c000744 (2026-10-06) | Apache-2.0 | in-process | fallback when the native wheel is unavailable |
| EVTX | libevtx / pyevtx (libyal) | 20260705; no PyPI distribution exists | LGPL-3.0-or-later | excluded | see rationale |

**Decision (D3-001) rationale, verbatim key points:** (1) only candidate both actively released in the current quarter and licence-clean for commercial distribution without a copyleft conversation; (2) Rust — a malformed record is far less likely to be a memory-safety incident than in a C parser; (3) pure-Python python-evtx remains a genuine fallback (same behaviour contract, no native wheel needed). libevtx excluded on licence (LGPL-3.0-or-later is copyleft; Stage-1 D-008 excludes it from linked code) and no PyPI distribution exists.

**Adapter contract (§4.1, verbatim):** "The adapter renders each EVTX record to the **XML form** the binding exposes, then applies the **Stage-2 SEC-A/SEC-B mapping tables verbatim** — the mapping tables, not the library, own the field names, so swapping python-evtx for the Rust binding changes nothing observable except `source.parser`."

**Invocation:** in-process (library import), no subprocess, no CLI invocation specified. Licence class: `in-process`. **Version pin:** Stage 3 pins TShark (`>= 4.6.9`) but states **no pin string for `evtx`** — pin value **not specified**; observed/recommended version is PyPI `evtx` 0.13.1 (binding) / crate 0.12.3. NOT_VERIFIED row 11: "`evtx` PyPI 0.13.1 publishes a win_amd64 wheel" — per-platform wheel files were not enumerated (matters for Windows M1 packaging).

**EVTX budgets (§4.1):** Records/second per worker ≥ 20k `PROPOSED - TO BENCHMARK` (1 GiB synthetic EVTX FX-H-01 timed end-to-end); Memory ceiling 128 MiB per worker (FX-H-01 under a job-object cap); Truncated/corrupt EVTX → emit `truncated_input` warning, keep records before the damage (FX-H-02…FX-H-04).

**Parser id / class / fallback (§4.4 summary table):** `evtx` → parser id **`evtx.rust`**, class in-process, fallback **`evtx.python`**. Telemetry-branch budgets: end-to-end harvest-to-DB latency p95 ≤ 5 s per 10k records (FX-H-08); per-worker memory 256 MiB (FX-H-09); schema-validation failure rate must be **0** in the fixture corpus (FX-H-10) — "a non-zero rate is a `source_contract` defect, not a tunable".

### 4.2 Other formats (for reference; M1 needs EVTX only)

| Format | Choice | Class | Notes |
|---|---|---|---|
| pcap/pcapng | TShark `-T ek -l -n` (primary), `-T fields -E separator=\t -E quote=d -e <field> … -l -n` (columnar), `-Y <filter>` (subset) | external-process | D3-002: pinned `>= 4.6.9` (security requirement, enforced by the deployment image, not a runtime check); only documented flags: `-T ek`, `-T fields`, `-T json`, `-Y`, `-l`, `-e`, `-E`; `-n` mandatory (no DNS egress, §9.4); parser ids `tshark.ek` / `tshark.fields`; fallback none |
| Zeek TSV | in-process, stdlib-only; bind columns by header name (`#fields`), never position (D2-019); `ts` epoch float documented UTC → `timezone_source: source_documented_utc`, microsecond precision | in-process | id `zeek.tsv` |
| Suricata EVE | in-process, **`ijson`** streaming line-by-line; **orjson deliberately not used** for ingest (2 recursion advisories CVE-2024-27454, CVE-2025-67221) | in-process | id `suricata.eve`; fallback `json.ijson` generic (D3-025) |
| Nmap XML | in-process, **`defusedxml`** (mandatory for all XML — D3-026) | in-process | id `nmap.xml` |
| Syslog 3164/5424 | in-process, stdlib regex + tokenizer; parse 5424 when line matches 5424 grammar, fall back to 3164 | in-process | ids `syslog.5424` / `syslog.3164` |
| CEF / LEEF | in-process, stdlib, from the vendor PDFs (CEF Version 27 grammar; LEEF 1.0 + 2.0 custom delimiter) | in-process | ids `cef.v1`; `leef.v2` / `leef.v1` (fallback: syslog as transport) |
| Windows exports (netstat/sc/schtasks/reg export/Export-Csv/autorunsc/sigcheck) | in-process, stdlib `csv` (TL-CSV); columns bind by header at runtime; `newline=''` | in-process | id `winexport.<tool>` (D2-010) |
| Generic JSON/NDJSON | in-process, `ijson` | in-process | "chosen for the same streaming reason as EVE" |
| Tabular bulk (analyst exports, large CSV) | **deferred (D3-003)** — pandas 3.x default if added in Stage 4; polars 2.0.0 only publishes a pure-Python meta-wheel | — | not on ingest hot path |
| Log template mining (Drain3) | **excluded for Stage 3 (D3-004)** | — | maintenance flag recorded |
| anything else | — | — | "event is not emitted; job records `unsupported_format`" (§4.4) |

---

## 5. §12 Facts-to-canonical mapping (M1 relevance: artifact branch is out of M1 scope, but the contract defines what an "ingest job" may and may not do)

- **What a fact is:** a typed observation about bytes, no adjective ("this relationship's target is external", "this import table names WinExec"). **Rule (§12.1, verbatim):** "**Extractors emit facts. They never emit canonical events, never emit findings, and never emit a verdict.**"
- **Fact shape:** the `Fact` dataclass of §3.1 (`namespace`, `name`, `value`, `value_type`, `locator`, `confidence`). Naming convention §12.2: `<namespace>[.<scope>].<name>`; value types `string|int|float|bool|timestamp|enum|list|bytes_hex|state`; `state` uses Stage-2 vocabulary (`null`, `unknown`, `invalid`, `conflicting`, `inferred`) and facts may carry a bare `None`.
- **Namespace registry (§12.2, normative closed set for Stage 3):** `archive`, `ooxml`, `ole`, `pdf`, `rtf`, `onenote`, `chm`, `lnk`, `hta`, `pe`, `elf`, `macho`, `dotnet`, `script`, `html`, `mhtml`, `image`, `msi`, `text`, `json`, `xml`, `identification`, `motw`, `encryption`, `signature`, `scanner`. Adding one is a Stage-3 decision (§13), not an extractor improvisation.
- **Three transformations (§12.1):** (1) fact → canonical event (§12.3, pure mapper into `document`/`archive_member`/`executable`/`artifact`/`artifact_finding` + envelope); (2) fact → finding via fact-to-finding **rules** = configuration data (`artifact_finding_rules.yaml`, shape mirrors Stage-2 D2-014; example rule ids AF-001…AF-005) emitting `artifact_finding` events; (3) finding/event → ordinary detectors. Nothing in steps 1–2 lives inside an extractor: "an extractor PR that contains an `if ratio > 1000: flag()` is rejected on sight."
- **Key mapping rows (§12.3):** metadata facts → one `document` event (`event.type: document_metadata_observed`, only when ≥1 metadata fact exists); `archive.member.*` → one `archive_member` event (`archive_member_listed`); `pe.*` header facts → `executable` (`executable_profiled`, `format` from §2 identification, not the filename); identification facts → `artifact` (`artifact_identified`, **always emitted**); `pe.import.*`/`pe.section.*` etc. → **stay as facts** (too high-cardinality); anything with no mapping → stays a fact ("the default… the common case").
- **Where facts live:** sidecar relation `artifact_fact(artifact_id, node_id, namespace, name, value_json, value_type, locator, confidence, tenant_id, workspace_id, run_id)`. Consumers: UI/API; fact-to-finding rule engine; replay (re-running rules needs no re-triage).
- **M1 (EVTX only, no artifact triage branch):** Stage 3 does not mention M1. Per the M1 brief, the EVTX path is the **telemetry branch only**: `TelemetryParser.parse` → canonical-event/v1 → schema validation → "batch insert + outbox (events are immutable)" → Sigma-compatible detection. The `Facts` / `ContentExtractor` / mapper / `artifact_finding` path, the `artifact_fact` table, and the fact-to-finding rules are all artifact-branch components → out of M1 scope. The one artifact-branch item M1 still touches is the **`artifact` record from §1.6** (because `source.file_id` on every event points at it) plus §2 identification (`source_format` = `identification.selected` feeds `ParseContext.source_format`).

---

## 6. §10 Safe archive extraction — short summary (M1: likely not needed)

- Gate interaction: the gate **never** decompresses, never lists archives, never sniffs magic, and **never rejects on content** (§1.3). A ZIP is accepted at 202 like any file; identification later gives `selected: archive` (family map; ZIP magic `PK\x03\x04` is implied only by the polyglot rules, exact byte signature **not specified** in §2) which routes to §10 archive triage. Whether M1 accepts-then-defers archives — **not specified** in Stage 3 (no M1 text anywhere); the only M1-adjacent statement available is Stage 3's own "no rejection on content" rule.
- Algorithm (§10.1): LIST (central directory only, no bytes written; failure at offset 0 → `status=corrupted`; declared truncation → `status=truncated`, continue) → BUDGET init (`remaining_bytes = ctx.max_materialised_bytes`, `remaining_nodes = ctx.max_nodes`, `remaining_time = ctx.max_wall_clock`, `seen_hashes = {}`) → per member: SANITISE path (§10.2 P1–P10; rejected member is **a fact with rejection_reason, not an error**) → CONTAIN (§10.3 realpath ancestry check, component-wise prefix) → links validated but **never created** → size/ratio/budget checks (`size_limit`, `ratio_limit`, `budget`) → stream-copy with running count against `max_node_bytes`, declared size + slack (`lie_about_size`), remaining budget, deadline; `O_CREAT|O_EXCL`, mode `0o600`; CRC mismatch keeps bytes + `crc_mismatch` + node flagged untrusted → sha256 dedup (`same_bytes_as` edge) → IDENTIFY + RECURSE if `depth < ctx.max_depth` and family enabled → FINALISE: every member produces an `archive_member` fact; parent status per §8.2.
- §10.2 sanitiser steps P1–P10 (reject empty/`.`/`..`; `\`→`/`, reject NUL; reject absolute/drive-relative/drive-absolute/UNC; reject `//./`, `//?/`, `\\.\`, `\\?\`, `CONIN$`/`CONOUT$`; **lexical** `.`/`..` resolution, reject if result starts `..`; per-component rules incl. 255-byte, trailing space/period, reserved device names; reject `:`; reject >4,096 bytes joined or depth >32 components `PROPOSED`; NFC-normalise for comparison keeping `archive_member.member_path_original`; final relative POSIX path).
- §10.5: default build **never creates** symlink/hardlink/FIFO/device/socket; setuid/setgid/sticky stripped, group/other write stripped; files `0o600`, dirs `0o700`.
- §10.7 quarantine layout: `<quarantine_root>/<root_sha256[0:2]>/<root_sha256>/<safe_rel>...` + per-root manifest `<quarantine_root>/.meta/<root_sha256>.json` = `{members: [{safe_rel, original_path, sha256, size_written, size_declared, rejected: null|reason, identified: <selected>, status}], limits_hit: [...]}` — "the provenance record for every child node".
- Recursion defaults (§10.4): ZIP/TAR/7z/RAR/ISO/CAB on depth 8; OOXML on depth 8; OLE2 on depth 8; PDF on depth 8; PE on depth 4; LNK **never**; image appended-ZIP depth 2; disk images/VHD/VMDK **never**; NSIS/Inno **never** in Stage 3.
- D3-030: ZIP safety is Sentinel's own responsibility (stdlib zipfile has no bomb guard — ARC-ZIPFILE); TAR passes `data_filter` to `extractfile`/`extract` then adds §10.2's stricter rules.

---

## 7. §5/§8 triage — short summary (facts-not-verdicts and output semantics)

**Facts-not-verdicts rule (§8.1):** "Triage does not produce verdicts. It produces **facts**, **flags** and an **analysis status**. There is no field, enum value, log line or API response in Sentinel in which a triage result may be `clean`, `safe`, `ok`, `benign`, `whitelisted`, `malicious` or `infected`. Those words are banned from the triage vocabulary by name, and the ban is a review-blocking rule: a patch that introduces one is rejected." (D3-029.)

**`analysis_status` (§8.2, normative 11-value enum):** `analyzed` | `partial` | `encrypted_content_not_analyzed` | `unsupported_format` | `truncated` | `corrupted` | `resource_limit_exhausted` | `blocked_by_policy` | `not_analyzed_by_policy` | `dependency_missing` | `error`. `partial` is "the most common real-world value and must be surfaced as a first-class state"; every non-`analyzed` status carries a machine-readable `reasons[]` list with the same entries as `ParserResult.errors` (§3.3).

**What triage emits (§8.3):** Facts (stored per artifact); canonical events in `document`, `archive_member`, `executable`, `artifact`; `artifact_finding` events; the §6 graph; `analysis_status` + `reasons[]`. "`artifact_finding` is the only channel through which a *scanner* … may speak", with Stage-2 fields `artifact_type`, `artifact_identity`, `finding`, `evidence`, `scanner`, `confidence`; `finding` is a rule id or configuration-defined rule name — **never a free-text verdict** — and `evidence` quotes the fact(s) with locators.

**Confidence vocabulary (§8.4):** exactly three values, no number: `observed` | `derived` | `third_party`. Magika's model score stays a fact value (`identification.magika.score`) and is explicitly *not* reinterpreted as a Sentinel confidence.

**Labels TL-*/ARC-*/DOC-*/ID-*** are §0 **evidence-id group prefixes** (verification log), NOT triage output labels: `ID-` identification and upload gate; `TL-` telemetry parsers and text carriers; `DOC-` document triage; `ARC-` archive/binary/generic triage. The triage output vocabulary is `analysis_status` (11 values) + `confidence` (3 values) + fact namespaces + `finding` rule ids (AF-00x).

**M1 must / must not emit (derived — Stage 3 has no M1 text):**
- MUST: canonical-event/v1 events only from the EVTX `TelemetryParser`, validated by the pipeline (`source_contract` on failure), "batch insert + outbox", provenance `source.parser = evtx.rust`, `source.parser_version`, `source.file_id = artifact_id`, `raw` + `unmapped[]` on by default.
- MUST report partial success via `ParserResult.status = COMPLETED_WITH_WARNINGS` + counters (`records_seen`, `events_emitted`, `records_failed`, `bytes_read`) + `warnings[]`/`errors[]` with locators — never `FAILED` for a mostly-good harvest, never plain `COMPLETED` when records were lost.
- MUST NOT emit any banned verdict word anywhere (§8.1), MUST NOT emit artifact-branch outputs (Facts, `document`/`archive_member`/`executable`/`artifact`/`artifact_finding` events) if M1 has no artifact triage branch, MUST NOT spawn processes from the parser (D3-024), MUST NOT raise per record (§3.2.2), MUST NOT drop source fields without `unmapped[]` (§3.2.4).
- For an uploaded file whose identification comes back `unknown`: "no parser applied; `analysis_status: unsupported_format`" (§2.3) / job records `unsupported_format` (§4.4).

---

## 8. Stage 3 DECISIONS / OPEN_QUESTIONS / NOT_VERIFIED (compact)

### 8.1 DECISIONS — 37 rows, D3-001…D3-037 (id + one-line decision)

| id | decision (one line) |
|---|---|
| D3-001 | EVTX parser is the Rust `evtx` binding (PyPI `evtx` 0.13.1 MIT wrapping omerbenamram/evtx), python-evtx 0.8.1 fallback when the native wheel can't install; libevtx excluded on licence (LGPL-3.0-or-later, no PyPI distro). |
| D3-002 | TShark is external-process only under the ExternalProcessRunner (D3-024), pinned `>= 4.6.9` (19 advisories incl. CVE-2026-96419, CVE-2026-5402), only man-page flags `-T ek`/`-T fields`/`-T json`/`-Y`/`-l`/`-e`/`-E`, `-n` mandatory. |
| D3-003 | pandas/polars are not on the ingest path; polars 2.0.0's pure-python meta-wheel distribution change recorded; pandas 3.x is default if bulk analytics is added in Stage 4. |
| D3-004 | Drain3 excluded from Stage 3 on maintenance grounds (~8 months no commit); revisit only for a free-text source. |
| D3-005 | Three-signal identification: magic authoritative for container, Magika for semantic type, extension never authoritative; S3 only consulted when both absent. |
| D3-006 | Deterministic selection rule; a magic-vs-Magika disagreement routes to BOTH family parsers (polyglot signal), confidence=low, `disagreement.present` set; extension disagreement never reroutes. |
| D3-007 | The gate does no content parsing; filenames never cause rejection; storage is content-addressed by sha256 only. |
| D3-008 | Windows filename sanitiser (§1.4 seven steps) is normative, incl. reserved device names and their superscript forms; long paths avoided structurally by short content-addressed segments. |
| D3-009 | The server never reads NTFS alternate data streams; agents lift `:Zone.Identifier` into `motw_zone_id` / `motw_referrer_url` upload fields. |
| D3-010 | Apache Tika excluded from the default build (its own security page: servers are not a security boundary; in-process DoS "not a security vulnerability"); deferred to Q3-008. |
| D3-011 | PyMuPDF (AGPL + renders) and pypdfium2 (renders, multi-licence) excluded on two independent grounds; Poppler `pdftotext` (GPL-2.0) available only as optional external text extractor, not default. |
| D3-012 | ZIP safety is Sentinel's own responsibility (stdlib gives no bomb guard); TAR delegates to the stdlib `data_filter` then adds §10.2's stricter checks. |
| D3-013 | libarchive-c (CC0 binding over BSD-3 libarchive) chosen for 7z/ISO/CAB/CPIO; py7zr excluded by default on LGPL-2.1-or-later (Q3-007); whichever 7z library ships must be pinned. |
| D3-014 | RAR is listed with rarfile (ISC, listing only) but extraction requires an operator-installed external tool; unrar is never vendored; absent tool → `COMPLETED_WITH_WARNINGS` + `dependency_missing`. |
| D3-015 | unblob and binwalk are external-process optional and off by default, only inside the quarantined worker under §10 budgets on leaf artifacts. |
| D3-016 | YARA-X is the scanning engine (BSD-3-Clause, production-stable June 2025); YARA 4.5.8 is not (maintenance mode); rules corpus kept 4.x-compatible, verified in Stage 4. |
| D3-017 | ClamAV is external-process optional (GPL-2.0, not linked); not default — overlaps YARA-X and its signature DB must be staged out-of-band (§9.4 forbids egress). |
| D3-018 | ssdeep excluded (LGPL-3.0-or-later + no commit since 2021-12); TLSH chosen for fuzzy hashing (py-tlsh 5.0.0, dual Apache-2.0 OR BSD-2-Clause). |
| D3-019 | Image metadata from exifread + Pillow (in-process); Pillow's MAX_IMAGE_PIXELS/DecompressionBombError relied on plus a stricter Sentinel cap; hachoir excluded (GPL-2.0); ExifTool external-process optional only (Q3-013). |
| D3-020 | capa, FLOSS and Detect-It-Easy are optional capability layers, off by default; PyPI squatters named explicitly (`capa` 0.1, `floss` 0.1.0 are unrelated — never install from PyPI). |
| D3-021 | oletools static analysis allowed (olevba/oleid/oleobj read and classify bytes); XLMMacroDeobfuscator excluded from the default build (emulator crosses §9.2), enableable only under §9.8 with a recorded policy exception. |
| D3-022 | The static-only prohibition list of §9 is normative and binding on every component including external processes; §9.8 is the single, expensive, review-gated escape route; it is a design constraint, not a configuration surface. |
| D3-023 | Parser interface is Protocol-based (`TelemetryParser`, `ContentExtractor`) with a shared eight-kind error taxonomy; per-record exceptions are forbidden; `COMPLETED_WITH_WARNINGS` is mandatory (3 of 400,000 lost → success with warnings). |
| D3-024 | All subprocess spawning belongs to an ExternalProcessRunner, never to a parser object (job object, timeout, restricted token, no-network, stderr capture, exit-status check, scratch cleanup). |
| D3-025 | orjson is not used to parse untrusted JSON (2 recursion advisories); ijson is (streams, no advisories); orjson permitted only for serialising Sentinel-produced data with a documented depth cap (Q3-011). |
| D3-026 | defusedxml is mandatory on every XML path (Nmap, OOXML, SVG, HTML-ish containers); frozen-but-safe, not abandoned. |
| D3-027 | Artifact analysis is a graph, not a file; `references` edges are terminal (recorded, never followed) — structural expression of §9.6. |
| D3-028 | Encrypted content is never analysed without an operator-supplied password list; detection structural only, no guessing; result reported as a fact, never a pass; terminal state `encrypted_content_not_analyzed`. |
| D3-029 | Triage never emits a verdict; `clean`/`safe`/`benign`/`malicious` banned by name; the eleven-value `analysis_status` enum is normative with `partial` first-class; a patch introducing a banned word is rejected on sight. |
| D3-030 | Archive extraction follows the normative §10 algorithm: lexical sanitisation, realpath ancestry containment, `O_CREAT\|O_EXCL\|O_NOFOLLOW` mode 0o600, counted streaming copy, links recorded as facts but never created (stricter than tarfile `data_filter`). |
| D3-031 | Extractors emit facts only; facts reach detectors solely as `artifact_finding` events produced by configuration rules (attributed like detection content, Stage-1 D-004); a verdict-shaped `if` in an extractor PR is rejected on sight. |
| D3-032 | Authenticode is reported as presence and identity with `signature.status = unverified_offline` (offline verification would need revocation/timestamping egress, §9.4). |
| D3-033 | LNK is parsed in-house; no third-party LNK library was opened for Stage 3 (unverified-structure claims listed in NOT_VERIFIED). |
| D3-034 | Disk images and encrypted volumes are identified and then refused, never mounted (`analysis_status: not_analyzed_by_policy`); ISO may be listed via libarchive without mounting. |
| D3-035 | Identification samples a bounded head and tail (first 8 KiB + last 4 KiB, PROPOSED) and never reads the whole artifact. |
| D3-036 | Rejected uploads are audited with a partial hash (sha256 of the first 64 KiB only), never a whole-file hash; row holds timestamp, principal, tenant, reject code, declared and received sizes. |
| D3-037 | The Stage-2 reserved categories are filled by the mapper; every artifact event carries `derived_by: sentinel`; `raw` = JSON-serialised fact bundle, `unmapped[]` = facts the mapper declined to place (documented adaptation of D2-012). |

All 37 have `status: accepted`. Evidence arrays: D3-033 and D3-036 have `evidence: []`.

### 8.2 OPEN_QUESTIONS — 22 rows, Q3-001…Q3-022 (id, title, blocking)

| id | title | blocking |
|---|---|---|
| Q3-001 | TShark job-object containment has not been designed to implementation detail (highest-risk open item in Stage 3) | enabling pcap ingest |
| Q3-002 | No throughput numbers exist for any parser; every §4/§5 budget is PROPOSED - TO BENCHMARK and the fixture corpus isn't built | capacity planning, worker sizing |
| Q3-003 | Which libmagic build ships on Windows, and who signs it (python-magic-bin deprecated; unsigned 3rd-party DLL unacceptable) | Windows packaging of the identification stage |
| Q3-004 | Magika model version pinning and update process | production identification |
| Q3-005 | Magika accuracy on Windows-specific families is unmeasured | trusting S2 in the selection rule |
| Q3-006 | Magika model licence needs a legal confirmation (Apache-2.0 by inclusion is an inference) | commercial distribution |
| Q3-007 | py7zr LGPL-2.1 enablement review | nothing today |
| Q3-008 | Tika adoption needs an isolation design that does not exist yet | nothing today |
| Q3-009 | Pure-Python pcap alternatives (dpkt, scapy, pyshark) were not evaluated | nothing today |
| Q3-010 | RAR extraction tool policy (which of unrar/unar/7zip/bsdtar is redistributable) | RAR extraction as a supported feature |
| Q3-011 | orjson depth cap and serialisation use | nothing today |
| Q3-012 | Mach-O parsing has no verified library | nothing today |
| Q3-013 | ExifTool enablement policy | nothing today |
| Q3-014 | OneNote parsing maturity (pyOneNote 0.0.2 / one-extract interim) | OneNote triage as a supported feature |
| Q3-015 | Email formats (.eml/.msg) are out of Stage-3 scope | nothing today |
| Q3-016 | NSIS/Inno installers are identified but not unpacked | installer triage |
| Q3-017 | Should high-cardinality facts ever get canonical schema homes (→ Stage-2 schema evolution, not Stage 3) | nothing today |
| Q3-018 | Fact-to-finding rule language (second, smaller rule language vs same DRL pipeline) | implementing §12.4 |
| Q3-019 | Content-addressed dedup scope under multi-tenancy (cross-tenant dedup oracle) | nothing today |
| Q3-020 | Whether document events are emitted only when metadata exists | nothing today |
| Q3-021 | Online signature verification (would be a §9.8 policy exception) | nothing today |
| Q3-022 | Zeek v9 and Suricata 8.0.x field-name drift against the Stage-2 corpus pin | nothing today |

### 8.3 NOT_VERIFIED — 30 rows (#, claim, where)

| # | Claim | Where |
|---|---|---|
| 1 | openpyxl repository branch, commit and current maintenance state | §5.1, DOC-OPENPYXL |
| 2 | Poppler official branch/commit | §5.3, DOC-POPPLER |
| 3 | XLMMacroDeobfuscator release version/tag | §5.1, DOC-XLM |
| 4 | Detect-It-Easy application version | §5.10, ARC-DIE |
| 5 | pandas SPDX classifier | §4.3, TL-PANDAS |
| 6 | Shell Link binary layout details used by the in-house LNK parser | §5.4, D3-033 |
| 7 | Mach-O load-command parsing claims | §5.5, Q3-012 |
| 8 | NSIS and Inno installer internals | §5.9, Q3-016 |
| 9 | Magika's exact sampling window size | §2.5, D3-035 |
| 10 | Magika's published label set includes every family named in §2.3's enum | §2.3 |
| 11 | `evtx` PyPI 0.13.1 publishes a win_amd64 wheel | §4.1 |
| 12 | qpdf's per-scheme PDF decryption support matrix | §7.1, §7.2 |
| 13 | rarfile's behaviour when headers are encrypted | §5.8, D3-014 |
| 14 | libarchive's handling of solid 7z archives | §5.8, D3-013 |
| 15 | CEF specification currency (Version 27 vs later) | §4.3, TL-CEF |
| 16 | LEEF specification PDF contents (403 to automated fetch) | §4.3, TL-LEEF |
| 17 | autorunsc / sigcheck / schtasks CSV header rows | §4.3 (from Stage 2 NV 17–19) |
| 18 | Exact code points of the Windows reserved superscript device names | §1.4, §10.2 |
| 19 | Which libmagic build Sentinel would ship on Windows | Q3-003 |
| 20 | YARA-X rule compatibility with the existing YARA 4.x rule corpus | D3-016 |
| 21 | TShark `-T ek` output contains every field the Stage-2 SEC-B network mapping needs | §4.2 |
| 22 | Zeek v9.0.0 log field names identical to the Stage-2 corpus pin | Q3-022 |
| 23 | Suricata 8.0.7 EVE field names identical to the Stage-2 docs pin | Q3-022 |
| 24 | pyOneNote / one-extract behaviour on password-protected notebooks | Q3-014 |
| 25 | Pillow's DecompressionBomb thresholds on the §11 image fixtures | §5.7 |
| 26 | olefile's write-path behaviour | §5.2 |
| 27 | Which Artistic License version ExifTool's dual licence refers to | D3-019, ARC-EXIFTOOL |
| 28 | Whether pyelftools' bundled `construct` subtree licence applies to our usage | §5.5, ARC-PYELFTOOLS |
| 29 | The libmagic version inside any Windows wheel we might use | Q3-003 |
| 30 | TShark's `-n` flag fully prevents all name resolution in every dissector path | §4.2 |

Closing line of the document: "75 Verification-Log entries (73 VERIFIED, 2 PARTIALLY VERIFIED), 37 decisions, 22 open questions, 30 not-verified rows, 240 named adversarial fixtures. All budgets in this document are labelled PROPOSED - TO BENCHMARK."

---

## 9. Config keys, job types, table names Stage 3 presumes

### 9.1 Config keys / limits named as such (exact identifiers as written)

- Gate bounds (§1.2): `max_request_bytes`, `max_file_bytes`, `max_files_per_request`, `max_field_bytes`; plus non-identifier limits: request wall-clock 30 s, concurrent uploads per principal 4, uploads per principal per hour 500, tenant artifact quota (operator-configured, default 50 GiB); spool buffer size (PROPOSED 1 MiB). All `PROPOSED - TO BENCHMARK`.
- `ParseContext` fields acting as run config: `source_format`, `declared_format`, `parser_config`, `deadline_monotonic`, `max_events`, `max_bytes_read`, `max_record_bytes`, `emit_raw` (default true), `emit_unmapped` (default true), `timezone_default`.
- Graph/extraction limits (§6.3 + §10.1 ctx): `max_depth` (8), `max_nodes` (10,000 per root), `max_materialised_bytes` (256 MiB per root), `max_edges_per_node` (1,000), `max_wall_clock_per_root` (60 s), `max_node_bytes` (64 MiB); in EXTRACT: `remaining_bytes`/`remaining_nodes`/`remaining_time`/`seen_hashes`, `ctx.max_compression_ratio` (numeric default **not specified**).
- Identification budgets (§2.5): magic sample first 8 KiB + last 4 KiB; 200 ms p95; 32 MiB.
- EVTX budgets (§4.1): ≥20k records/s per worker; 128 MiB memory per worker. Telemetry branch: p95 ≤ 5 s per 10k records; 256 MiB per worker; schema-validation failure rate 0.
- Sanitiser/display: display_name 200 UTF-8 bytes; empty-name fallback = first 16 hex chars of sha256; audit retention 90 days.
- Encryption budgets (§7.2): password attempts per artifact 3; wall-clock per attempt 5 s; password list size 32 entries; plaintext cap = §10 `max_materialised_bytes`.
- **Configuration data (YAML, named in the text):** the format-family map (magic/Magika label → `selected`) and the OOXML family equivalence; the telemetry content-sniff signatures ("signatures in YAML, never a hard-coded detector"); `artifact_finding_rules.yaml` (fact-to-finding rules, example ids AF-001…AF-005, with `severity_hint`, `attribution`); `lists/exec_apis.yaml` (referenced by AF-004); workspace password list (§7.2, never logged/returned/written into facts); static name lists for `script.suspicious_cmdlet` / `script.suspicious_command` / `script.suspicious_import` (from configuration, not hard-coded); operator-configured archive recursion enablement per family; `timezone` run config. Dotted/prefixed config-key names (e.g. `ingest.*`) do **not** appear in Stage 3 — **not specified** here.

### 9.2 Job types

Stage 3 defines **no job-type enum** — `job_type` does not appear. What exists:
- `triage_state: queued|running|done|failed|rejected_by_policy` (§1.6 record).
- Superseded `triage_job_id` in the old 201 response sketch (C-4-fix) — not part of the current contract.
- "the pipeline converts [an escaping exception] to `status: FAILED` at the **job** level" (§3.2.2); "job records `unsupported_format`" (§4.4); "per-job scratch directory" (§4.2.2); job marked "retryable-by-operator" on `dependency_missing` (§3.3).
- The worker component is called the "triage worker" (§1, §9.4); the pipeline does "batch insert + outbox" for events (§3.4).
- Job-type names such as `ingest_file` are **not specified** in Stage 3 (they live in later-stage artifacts outside this document).

### 9.3 Table / relation names Stage 3 presumes

| Name | Definition site | Columns as written |
|---|---|---|
| `artifact` (record) | §1.6 | full field list reproduced in §1.6 above (join key for everything downstream) |
| `artifact_node` | §6.3 | `(artifact_id, root_artifact_id, node_type, structural_id, sha256\|null, parent_node_id, edge_type, depth, size, analysis_status)` — every row carries `tenant_id`, `workspace_id`, `run_id` (Stage-1 D-012) |
| `artifact_edge` | §6.3 | `(from_node_id, to_node_id, edge_type, locator)` (+ tenant/workspace/run per §6.3) |
| `artifact_fact` | §12.6 | `(artifact_id, node_id, namespace, name, value_json, value_type, locator, confidence, tenant_id, workspace_id, run_id)` |
| rejected-upload audit row | §1.5 | timestamp, principal, tenant, `code`, declared size, received size, sha256(first 64 KiB); retention default 90 days — table name **not specified** |
| quarantine manifest | §10.7 | JSON file, not a table: `<quarantine_root>/.meta/<root_sha256>.json` |

Stage 3 does **not** emit DDL; it inherits PostgreSQL (Stage 1 D-001). Canonical events go to "batch insert + outbox (events are immutable)" — the concrete events table name is **not specified** in Stage 3 (the join column is `source.file_id`). Cross-row discipline: every row carries `tenant_id`, `workspace_id`, `run_id` (Stage-1 D-012).

### 9.4 Other exact identifiers an M1 implementer will need

- Parser ids (→ `source.parser`): `evtx.rust`, `evtx.python`, `tshark.ek`, `tshark.fields`, `zeek.tsv`, `suricata.eve`, `nmap.xml`, `syslog.5424`, `syslog.3164`, `cef.v1`, `leef.v2`, `leef.v1`, `winexport.<tool>`.
- `Status` literal: `COMPLETED`, `COMPLETED_WITH_WARNINGS`, `FAILED`.
- Error kinds: `unsupported_format`, `truncated_input`, `corrupt_record`, `encoding`, `resource_limit`, `dependency_missing`, `source_contract`, `internal`.
- Gate warnings enum: `renamed`, `case_collision`, `truncated_display_name`, `motw_absent`.
- `triage_state`: `queued|running|done|failed|rejected_by_policy`.
- `analysis_status` 11 values (§8.2, listed in §7 above).
- `selected_by`: `magic|magika|hint_fallback|size_only`; `selected_confidence`: `high|medium|low`.
- Confidence: `observed|derived|third_party` (§8.4); Fact.confidence: `observed|derived` (§3.1).
- Fixtures most relevant to M1: FX-G-01…FX-G-30 (transport/API incl. idempotency, tenant mismatch, chunked accept), FX-H-01…FX-H-04 + FX-H-08…FX-H-10 (EVTX/telemetry), FX-C-01…FX-C-05 (identification), FX-B-01…FX-B-05 (file-size caps).
- Doc fix-tags referenced inline: **C-4-fix** (endpoint namespace/OpenAPI `createUpload` normative), **C-4b-fix** (`run_id` server-generated when omitted), **D8-06 fix** (telemetry-family precedence sniff), **C-8 closure / D8-07** (SQLite triage path, §5.9b).
