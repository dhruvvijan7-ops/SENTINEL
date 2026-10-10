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
| Endpoint | `POST /v1/artifacts` (multipart/form-data, one file part named `file`; optional non-file parts `agent_id`, `collection_kind`, `source_path`, `motw_zone_id`, `motw_referrer_url`) |
| Companion | `GET /v1/artifacts/{artifact_id}` (status, triage state, rejection reason if any) |
| Auth | same bearer/session scheme as the rest of the API; the authenticated principal MUST resolve to exactly one `tenant_id` and one `workspace_id` |
| Idempotency | `Idempotency-Key` header; a replay with the same key AND the same content sha256 returns the original `artifact_id` with HTTP 200; same key, different sha256 → HTTP 409 `GATE_IDEMPOTENCY_MISMATCH` |
| Response (accepted) | HTTP 201 `{artifact_id, sha256, size, storage_key, triage_job_id, gate: {renamed, warnings[]}}` |
| Response (rejected) | HTTP 4xx `{code, message, detail}` where `code` is one of the §1.5 reject codes; the body never echoes the client filename verbatim (it is stored, see §1.4) |
| Async model | the 201 response means "persisted and queued". Triage outcome is never returned synchronously. |

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
