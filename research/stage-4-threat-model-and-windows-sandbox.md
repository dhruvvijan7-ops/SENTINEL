# Stage 4: Threat Model and Windows Sandbox

**Status:** Draft for review  
**Date:** 2026-10-08  
**Inherits:** Stage 1 (D-001, D-004, D-008, D-012), Stage 2 (canonical-event/v1), Stage 3 (D3-001…D3-037, §9/§10, FX-A…FX-H, ExternalProcessRunner contract, Q3-001…Q3-022)

---

## 1. Trust Boundaries and Data-Flow Diagram

### 1.1 Trust Boundaries

| ID | Boundary | Crosses | Attacker on Outer Side Controls |
|----|----------|---------|----------------------------------|
| TB-1 | Network edge (analyst client → API) | TLS termination, auth token validation | Request bodies, headers, timing, auth tokens |
| TB-2 | API process ↔ Quarantine storage | Object-store / filesystem ACLs | File bytes, metadata, archive structure |
| TB-3 | Quarantine storage ↔ Parser worker | Job-object / AppContainer boundary | All bytes handed to parsers |
| TB-4 | Parser worker ↔ OS kernel | Syscalls, handles, tokens | Parser process memory, handles |
| TB-5 | Worker ↔ Rule/IOC feed (egress) | Host firewall / egress proxy | Content served by feed hosts (untrusted) |
| TB-6 | Analyst UI (browser) ↔ API responses | CSP, output encoding, SameSite cookies | Rendered DOM, downloaded exports |
| TB-7 | CI/CD / supply-chain update ↔ Runtime images | Image signing, SBOM gates | Package contents, rule-pack binaries |
| TB-8 | Database ↔ Application | Row-level authz, tenant scoping | SQL-shaped inputs via app features |

### 1.2 Data-Flow Diagram

```mermaid
flowchart LR
  subgraph OuterUntrusted
    A[Analyst / Upload Client]
    F1[Rule feed HTTPS]
    F2[IOC feed HTTPS]
  end

  subgraph TB1[Boundary: Network Edge - mTLS/TLS + AuthN]
    direction LR
  end

  subgraph AppTier
    API[FastAPI - API process]
    DB[(PostgreSQL)]
    Q[(Quarantine Storage - object store / filesystem)]
  end

  subgraph TB3[Boundary: Worker Isolation - AppContainer+Job / WSB VM]
    W1[Archive worker]
    W2[Document parser worker - OOXML/OLE/PDF]
    W3[Media/image worker]
    W4[PE/ELF worker]
    W5[Event parser worker - EVTX/JSON/CSV]
    W6[Rule evaluator - YARA / Sigma]
  end

  subgraph AnalystUI
    UI[Web UI - SPA]
  end

  A -->|TB-1 HTTPS upload| API
  API -->|write immutable blob| Q
  API -->|metadata rows| DB
  API -->|dispatch job| Q
  Q -->|read-only mount| W1 & W2 & W3 & W4 & W5
  W1 -.->|extracted artifacts| Q
  W5 -->|canonical events| DB
  W6 -->|matches| DB
  F1 -->|signed rule-pack| API
  F2 -->|SSRF-guarded fetch| API
  DB -->|events / findings| API
  API -->|JSON (CSP-secured)| UI
  UI -->|CSV/XLSX export| API
```

---

## 2. Threat Model (STRIDE)

| # | Asset | STRIDE | Attacker capability | Attack path | Mitigation | Acceptance test | Residual risk |
|---|-------|--------|---------------------|-------------|------------|-----------------|---------------|
| T-01 | Quarantine files | Tampering | Local untrusted code | Archive traversal (`../`) writes outside workdir | Canonical path resolution inside workdir only; reject absolute / `..` / drive-relative paths before write; Stage-3 §10 | FX-A (240 fixtures) must all stay in workdir; fuzz traversal | Path normalization bug in exotic Unicode |
| T-02 | Worker memory / host | Tampering | Crafted archive | Zip-bomb / nested compression exhausts CPU/RAM | Job-object memory + CPU time + process-count limits; nesting depth & total-size caps in Stage-3 extractor | FX-D bomb fixture must terminate within `PROPOSED - TO BENCHMARK` timeout with limit flag, no OOM of host | CPU-limit bypass on IO-bound stalls |
| T-03 | Parser process | Tampering | Memory-safety bug | Malformed PE/PDF/OOXML hits C parser bug | External-process isolation (AppContainer / WSB VM); ASLR+CFG+ACG mitigations enabled on child | Fuzz corpus (Atheris/cargo-fuzz) run nightly; crash ≠ host compromise in sandbox-escape test | 0-days in mature libs (TShark, poppler) |
| T-04 | API / worker | Tampering (DoS) | ReDoS | Malicious Sigma/rule regex catastrophic backtracking on user event | Rule-compiler sandbox: timeout per rule; prefer Rust `regex` crate / RE2 semantics for user rules; Python `re` possessive quantifiers `(?>...)` where CPython ≥3.11 | Rule with nested-quantifier pattern must hit compile timeout, not hang worker | Non-backtracking engine gaps |
| T-05 | Parser | Tampering | XXE / entity bomb | Malicious OOXML/XML declares billion-laughs entities | Disable DTD resolution in XML parsers; entity-expansion limits; no external entity fetch | XXE fixture FX-E yields parse error, no outbound DNS | Alternative XML stack config |
| T-06 | Rule pipeline | Tampering | Malicious rule author | Rule pack with path traversal / code exec / ReDoS | Rule-pack signing (Ed25519); allowlisted fields only; no arbitrary code in rules (Sigma-compatible schema per D-004); review gate | Tampered rule signature rejected at load; fuzzed rule cannot escape YAML schema | Compromised signing key |
| T-07 | API | Tampering / Info disclosure | SSRF via feed fetcher | Analyst-supplied feed URL hits `169.254.169.254` or internal hosts | Egress proxy allowlist; block link-local / private ranges; no redirects to private; DNS rebinding guard | SSRF test suite (metadata IP, RFC1918, redirect chain) all blocked | IPv6/DNS rebinding variants |
| T-08 | Analyst session | Elevation | Stored XSS | Malicious filename / artifact content rendered in UI | Contextual auto-escaping in templates/JS framework; strict CSP (`script-src 'self'`, no `unsafe-inline`); sanitize before DOM insertion | Payload in filename + event field renders inert; CSP violation report logged | Browser 0-day |
| T-09 | Exports | Tampering | Formula injection | Artifact field begins `=`, `@`, `\t`, `\r` and re-executes in Excel | CSV/XLSX export prefixes dangerous cells with `'`; XLSX cells typed as text | Export of `=cmd\|'/c calc'!A1` opens inert in Excel | LibreOffice variance |
| T-10 | Logs / secrets | Info disclosure | Log scraping | API keys, DB creds, file paths in logs | Structured logging with allowlist fields; secrets redaction; no file content in logs | Log-scanner test: no secret patterns (regex for AKIA, PRIVATE KEY, etc.) | Analyst pastes secrets into notes |
| T-11 | Data | Repudiation / Disclosure | Tenant pivot | Query escapes tenant scope → sees other tenant's events | Row-level security / mandatory tenant filter in every query; CI test | Cross-tenant IDOR test returns 403/404 | Missing filter in new endpoint |
| T-12 | Rule packs | Tampering | Supply-chain | Compromised upstream Sigma repo | Signature verification; pinned commits; diff review; SBOM | Unsigned / wrong-key rule pack rejected | Key compromise |
| T-13 | Runtime images | Tampering | Dependency compromise | Typosquat or maintainer account takeover in pip/npm | Lockfiles with hashes; private index mirror; license + vuln scan in CI; sigstore/cosign attestation where available | CI fails on hash mismatch or unscanned dep | Transitive CVE with no fix |
| T-14 | Host / workers | Tampering / DoS | Resource exhaustion | Many concurrent bombs starve host | Per-tenant + global concurrency caps; queue backpressure; job-object limits | Flood test: queue rejects with 429, workers stay under memory cap | Scheduler starvation |
| T-15 | Evidence | Repudiation | Evidence tampering | Analyst or malware edits quarantine blob | Write-once store (object-lock / hash-chained manifest); re-hash on read | Bit-flip in store detected by re-hash; audit log records attempt | Compromised root credentials |
| T-16 | Host | Elevation | Worker privilege escalation | Malware in parser escapes AppContainer via kernel bug | Nested boundary: worker runs under dedicated low-priv service account; no network capability; WSB VM mode for hardened tier | Sandbox-escape harness: container breakout attempts fail; host process list unchanged | Kernel 0-day |
| T-17 | Parser I/O | Tampering | TOCTOU | Symlink swap between hash and parse | Open handle once; parse from handle not path; disable symlink follow on workdir; re-hash after open | TOCTOU fuzz (rapid symlink swap) does not escape workdir | Exotic FS drivers |
| T-18 | UI | CSRF | Session riding | Cross-site POST to state-changing API | SameSite=strict cookies or bearer-token-only; CSRF token for cookie auth | CSRF suite on every mutating endpoint | Subdomain takeover |
| T-19 | API | Tampering | Command injection via filename/args | Artifact name contains `; rm -rf` | `ExternalProcessRunner`: fixed exe path, argv array only, no shell (D3-024) | Filename with shell metacharacters does not execute | DLL search order hijack on child (mitigate with full path + safe search order) |
| T-20 | Rule evaluator | Tampering | YARA compiler bug | Crafted YARA rule exploits yara-python native code | Run YARA in isolated worker; rule allowlist fields; timeout | Fuzzed YARA rule cannot escape worker | Native bug in libyara |

---

## 3. Sandbox Decision Matrix

| Option | Isolation strength | What it does NOT block | Effort | Performance overhead | Windows edition availability | Operability | Failure modes |
|--------|-------------------|------------------------|--------|---------------------|-----------------------------|-------------|---------------|
| **Baseline: restricted token + Job Object + mitigations** | Medium (privilege + UI + resource limits) | **Network egress; arbitrary file reads on volumes the token can access (job objects have no network/file ACL members — verified: `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` / `BASIC` contain only CPU/memory/IO/process-count/affinity/UI limits)**; kernel exploits; named-pipe servers the process opens itself | Low | Low (~ms setup) | All editions (Win8/Server2012+ for mitigation policies; token APIs older) | Simplest ops; same-host density | Token/job misconfig; handle inheritance leaks; child re-launches outside job (mitigate with KILL_ON_JOB_CLOSE + silent-breakaway-ok off) |
| **AppContainer (LowBox token + capability SIDs)** | High (default-deny file/registry/network) | Kernel exploits; capabilities explicitly granted (avoid granting `internetClient`); COM activation abuse if allowed; named objects outside package SID scope | Medium | Low | Win8+; Win32 app isolation surface (packaging/MSIX) best on Win11 24H2 (build 26100+) per Microsoft | Requires profile creation + capability list; harder for unpackaged Python workers | Missing capability breaks parser I/O; profile cleanup leaks; some legacy DLLs fail in AC |
| **Windows Sandbox (WSB) disposable VM** | Very high (separate kernel, hypervisor) | Not for unattended high-throughput: **single instance only** (Microsoft: "doesn't allow multiple instances"); boot latency; no nested Hyper-V on Home; host-shared mapped folders are a trust boundary if configured RW | Medium (.wsb; CLI `wsb start --config` automation requires **Windows 11 24H2+**, else GUI `.wsb` launch only) | Medium (GB RAM, seconds-to-boot) | **Pro, Enterprise, Pro Education/SE, Education** (E3/E5/A3/A5 entitlements). **Not on Home** | Good for hardened tier / analyst manual detonation; not baseline path | Hypervisor unavailable (third-party HV blocked); network accidentally enabled by default (must set `<Networking>Disable</Networking>`); mapped-folder escape if RW; **CLI (`wsb start/exec/stop`) is Win11 24H2+ only** |
| **Full Hyper-V VM pool** | Very high | Same as WSB plus higher ops burden; snapshot management; not real-time | High | High | Requires Hyper-V-capable SKU + SLAT | Enterprise fleets | Snapshot drift; image staleness |
| **WSL2 + Linux toolchain** | Medium-high (separate kernel) | Windows-native parser coverage; Windows-specific attack surface not exercised | Medium | Medium | Win10 2004+ / Win11; glibc tooling | Good for fuzzing (AFL++, cargo-fuzz) | 9P/DrvFs mount escape; WSL init compromise |

**Key evidence for "restricted token + Job Object alone does not block network or file reads":** Microsoft's `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` / `JOBOBJECT_BASIC_LIMIT_INFORMATION` structures contain members only for CPU rate, job/memory limits, process/memory counts, affinity, I/O rate, UI restrictions (`JOBOBJECT_BASIC_UI_RESTRICTIONS`) — **no network or filesystem-access members** exist in the job-object API surface. Network denial requires AppContainer (capability SID model), WSB `<Networking>Disable</Networking>`, or host firewall; file denial requires token integrity/capability restrictions or WSB mapped-folder isolation. *(Verified via learn.microsoft.com Win32 job-object API docs, retrieved 2026-10-08.)*

---

## 4. Recommended Baseline + Hardened Modes

### 4.1 Modes

| Mode | When | Boundary stack |
|------|------|----------------|
| **Baseline (default)** | Production ingest of known-benign-ish formats (EVTX, JSON, CSV, YARA eval) | Dedicated service account (no interactive logon) + restricted token (`DISABLE_MAX_PRIVILEGE`) + Job Object (memory, CPU, process count, `KILL_ON_JOB_CLOSE`) + mitigation policies (ACG, CFG, DEP, restricted fonts) + **no `internetClient` capability** (use AppContainer where packaging permits) + host egress firewall deny-by-default for worker SID/account |
| **Hardened** | Untrusted archives, active-content docs (OOXML/OLE/PDF), PE/ELF, first-seen MIME | Everything in Baseline **plus** Windows Sandbox VM (`.wsb`: `<Networking>Disable</Networking>`, `<VGpu>Disable</VGpu>`, `<MappedFolders>` read-only input, write-only output channel) or AppContainer + LPAC; fresh VM per job or pooled reset |

### 4.2 ExternalProcessRunner launch design (implements D3-024)

1. **Executable path:** absolute, fixed, admin-owned, not writable by worker SID (e.g. `C:\Program Files\Sentinel\bin\tshark.exe`). No PATH resolution.
2. **Invocation:** `CreateProcessW` with argv array; **never** `cmd.exe /c`, never string-concatenated command lines. Quote via `argv` builder; reject embedded NULs.
3. **Environment:** scrubbed minimal env (e.g. `SystemRoot`, `TEMP` → private workdir); no inherited secrets, no `PATH` pointing at user dirs.
4. **Working directory:** fresh per-job private dir under quarantine volume; ACL: worker SID only.
5. **Input:** read-only handle to artifact (or read-only mapped folder in WSB); no write access to source path (TOCTOU: keep handle open, parse from handle).
6. **Output:** stream to bounded pipe/file with hard byte cap (`PROPOSED - TO BENCHMARK`); discard beyond cap; structured result JSON via separate IPC pipe (schema-validated, size-capped).
7. **Timeouts & kill:** wall-clock timeout + CPU-time limit in job; on expiry terminate **process tree** (job kill covers children; `KILL_ON_JOB_CLOSE` as backstop).
8. **Resource limits:** Job memory limit, active-process limit (e.g. max 1), UI restrictions (no clipboard/desktop/exit-windows), CPU rate cap.
9. **Network denial:** Baseline — AppContainer without network capabilities **or** host firewall rule scoped to worker account; Hardened — WSB `<Networking>Disable</Networking>`.
10. **Handle inheritance:** `bInheritHandles=FALSE` except explicitly needed pipes, set with `SECURITY_ATTRIBUTES` inherit flags; close unnecessary handles.
11. **Crash handling:** treat non-zero exit / signal as parse failure (not host event); log exit code + timeout flag; never auto-restart in place.
12. **IPC result validation:** JSON schema (canonical-event subset), max depth/size, reject unknown fields; treat all parser output as untrusted strings (encoding validation, length caps).

---

## 5. Per-Component Isolation Assignment

| Component | Mode | Notes |
|-----------|------|-------|
| TShark (pcap) | Baseline or Hardened | External process pinned ≥4.6.9 (D3-002); highest Q3-001 risk — prefer Hardened for public pcaps |
| EVTX parser | Baseline | Rust/Python parser in-process OK if memory-safe lang; else external |
| Archive extraction (zip/7z/tar/rar) | Hardened | Bomb + traversal surface (FX-A/D); py7zr/libarchive in isolated worker |
| OOXML / OLE (oletools) | Hardened | Active-content + XXE + VBA; §9.8 containment; oletools ≥0.46.1 (D3-037) |
| PDF (pdfminer/pypdf/pdfium) | Hardened | JS/lua in PDFs; memory-safety history in PDFium/poppler |
| Image parsers (Pillow, libpng, libjpeg-turbo) | Baseline | Memory-safe wrappers but native deps; still job-limited |
| PE/ELF parsers (pefile, LIEF) | Baseline | Header-only; no code execution; job-limited |
| YARA evaluator | Baseline | Compiled rules; rule-timeout; isolate if loading third-party rulesets |
| CSV / JSON / XLSX ingest | Baseline | Schema validation in API tier before worker |
| Rule compiler / evaluator (Sigma) | Baseline | Non-backtracking regex engine preference; compile timeout |
| Feed fetchers (SSRF surface) | API tier, not worker | Egress proxy; no parser runs on feed bytes until quarantined |

---

## 6. Analyst-Surface Security Spec

| Concern | Requirement |
|---------|-------------|
| Output encoding | Contextual auto-escape (HTML/JS/URL/CSV); treat filenames, event fields, rule names, IOC values as hostile |
| CSP | `default-src 'self'`; `script-src 'self'`; `object-src 'none'`; `base-uri 'none'`; `frame-ancestors 'none'`; report-uri to ingest |
| Command-line / path rendering | Never render raw shells; show as text nodes; neutralize bidi/zero-width chars in UI |
| Export sanitization | CSV/XLSX: prefix `'` for cells starting `= + - @ \t \r`; force text cell type in XLSX |
| AuthN | OIDC/SSO preferred; local accounts argon2id; MFA required for admin; short-lived sessions |
| AuthZ | Tenant-scoped RBAC; every endpoint deny-by-default; no IDOR on artifact/event IDs |
| Audit logging | Append-only log of login, upload, download, export, rule change, admin action; hash-chained |
| Secrets handling | API keys / DB creds in env or Windows DPAPI-protected store; never in logs, URLs, client JS; redaction filter |
| Key management at rest | Envelope encryption: per-tenant DEKs wrapped by master key in HSM/KMS or DPAPI machine+user scope; quarantine blobs integrity-hash (SHA-256) + optional envelope encryption |

---

## 7. Supply-Chain Spec

| Control | Spec |
|---------|------|
| Dependency pinning | `pip`/`npm` lockfiles with hashes (`--require-hashes`); exact versions in requirements |
| SBOM | CycloneDX 1.5+ JSON per build; generate on CI; archive with release |
| License scanner | `pip-licenses` (Python), `syft` (multi-ecosystem); gate: no GPL/AGPL copy-paste (D-008); flag unknown licenses |
| Vulnerability scanner | `pip-audit` (Python), `osv-scanner` or `grype` (containers); fail CI on CRITICAL/HIGH with fix available |
| Image / binary signing | cosign (sigstore) for container images where registry supports; Windows binaries: Authenticode signing for installer |
| Rule-pack / IOC signing | Ed25519 detached signatures over canonical JSON/YAML; public key pinned in config; algorithm: Ed25519 (justify: small keys, fast verify, widespread libs: `cryptography`, `ed25519-dalek`); rotate keys with dual-key overlap window |
| Update + rollback | Signed rule-pack manifests with monotonic version; atomic swap + previous-version cache; automatic rollback on post-load health-check failure; audit log of pack version served |
| Provenance | Build metadata (git SHA, builder ID) in SBOM; reproduce where feasible |

---

## 8. Security Test Plan

| Area | Tool / method | Automation | Pass criterion |
|------|---------------|------------|----------------|
| Archive parser fuzzing (Python) | Atheris + `atheris.instrument_package` on Stage-3 extractor entrypoints; seed corpus from FX-A…FX-H | Nightly CI job (Linux runner via WSL2 OK) | No uncaught crash; job-object timeout catches hangs |
| Property-based fixtures | Hypothesis strategies over archive headers / path components | CI on PR | No path escapes; depth/size caps enforced |
| Native parser fuzzing (TShark etc.) | `cargo-fuzz` (Rust wrappers) or AFL++ / WinAFL under WSL2 | Weekly + release | Crash triage → patch or quarantine format |
| Adversarial fixtures | Run all 240 Stage-3 fixtures + new FX-* corpus under each isolation mode | CI matrix (Baseline / Hardened) | Expected triage outcome per §matrix; sandbox-escape = fail |
| Sandbox-escape checks | Attempt: outbound connect, write outside workdir, open host handle, spawn shell, symlink race | Security gate before release | All denied; host process/network snapshot unchanged |
| ReDoS | Rule-compile fuzzer + known catastrophic patterns; timeout harness | CI | Timeout < `PROPOSED - TO BENCHMARK`, no worker hang |
| XXE / entity bomb | FX-E + billion-laughs variants | CI | Parse error, zero outbound DNS (pcap assert) |
| SSRF | Metadata IP, RFC1918, redirect chains, DNS rebinding test host | CI | All blocked at egress proxy |
| Stored XSS / CSV injection | Playwright + fixture exports; formula-injection cells | CI | Payload inert; CSP violations logged |
| Supply-chain | Tamper a rule pack / dep hash in test branch | CI | Signature/hash gate rejects |
| Tenant isolation | Automated IDOR/cross-tenant suite per endpoint | CI | 403/404 on foreign IDs |
| Secret leakage | Log + API response scanner (regex AKIA…, PRIVATE KEY, JWT secrets) | CI | Zero matches |

---

## 9. DECISIONS

```yaml
- id: D4-001
  decision: Use Windows Sandbox (.wsb, networking disabled, read-only mapped input) as the Hardened isolation tier for active-content and archive detonation; use restricted token + Job Object (+ AppContainer where packaging allows) as Baseline for lower-risk parsers.
  status: proposed
  evidence: Microsoft Windows Sandbox docs (editions Pro/Enterprise/Education, not Home; hypervisor isolation; networking enabled by default must be disabled via <Networking>Disable</Networking>; single instance limit); AppContainer capability SID model (default-deny network without capability); JOBOBJECT structs verified to lack network/file members.
  alternatives_rejected:
    - Restricted token + Job Object alone for all tiers (does not block network/file reads — evidence: job-object API surface).
    - Full Hyper-V pool for baseline (ops cost, latency).
    - WSL2-only isolation (does not exercise Windows-native parser attack surface).
  consequences: Two-tier ops; WSB unavailable on Home SKU and single-instance limits throughput on hardened path; CLI automation (`wsb start/exec/stop`) requires Windows 11 24H2+ — earlier hosts drive WSB via GUI `.wsb` launch only; must monitor .wsb config drift.
  depends_on: [D3-001, D3-024]

- id: D4-002
  decision: Implement ExternalProcessRunner per §4.2 (fixed path, argv-only, scrubbed env, private workdir, stream+cap output, timeout+tree-kill, no shell).
  status: proposed
  evidence: Stage-3 D3-024 contract; Windows CreateProcess command-injection class (T-19).
  alternatives_rejected:
    - subprocess with shell=True (injection).
    - Shared workdir across jobs (TOCTOU, cross-contamination).
  consequences: Slightly more runner code; strict path validation required.
  depends_on: [D3-024]

- id: D4-003
  decision: Enforce Ed25519 detached signatures on all rule-packs and IOC bundles; pin public keys in config; dual-key rotation.
  status: proposed
  evidence: TUF/sigstore patterns; Stage-1 D-004 rule-engine trust; supply-chain T-06/T-12.
  alternatives_rejected:
    - HTTPS-only trust (no integrity after delivery).
    - Minisign/age (less uniform ecosystem fit).
  consequences: Key custody responsibility; offline verification tooling needed. Storage implication resolved (C-11-fix, Stage-8 round 1): `ioc_pack.status` DDL default is `pending_verify` (was `active`) — packs are inserted unverified and only flip to `active` after signature verification, matching this decision's verify-before-trust posture.
  depends_on: []

- id: D4-004
  decision: Prefer non-backtracking regex semantics for user-authored rules (Rust regex crate or equivalent) with compile-time timeout; restrict Python re to fixed internal patterns with possessive/atomic constructs where CPython ≥3.11.
  status: proposed
  evidence: Python re docs (possessive quantifiers / atomic groups added 3.11); ReDoS threat T-04.
  alternatives_rejected:
    - Unlimited Python re on analyst-supplied patterns (ReDoS).
  consequences: Some exotic regex features unsupported; document in rule schema.
  depends_on: [D-004]

- id: D4-005
  decision: Run every third-party/native parser as an external process under the isolation stack; in-process only for memory-safe, schema-validated pure-Python/Rust helpers.
  status: proposed
  evidence: Stage-3 parser interface; T-03/T-20 memory-safety history.
  alternatives_rejected:
    - In-process oletools/TShark bindings (blast radius).
  consequences: IPC overhead; must validate all results as hostile.
  depends_on: [D3-002, D3-037]
```

---

## OPEN QUESTIONS

| ID | Question | Owner | Target stage |
|----|----------|-------|--------------|
| Q4-001 | What throughput does WSB single-instance impose on hardened detonation, and is a warm-pool reset strategy acceptable latency-wise? | Ops | Stage 5 capacity |
| Q4-002 | Can AppContainer profile creation be automated for unpackaged Python workers on all supported SKUs, or is MSIX packaging required in practice? | Engineering | Stage 5 packaging |
| Q4-003 | Which egress-proxy product/API do we standardize on for SSRF guard (Windows Firewall rules vs. explicit proxy)? | Security | Stage 5 network |
| Q4-004 | Do we require envelope encryption of quarantine blobs at rest now, or hash-only integrity until multi-tenant GA? | Product | Stage 5 data-at-rest |
| Q4-005 | Is Authenticode signing in scope for the first Windows installer release? | Release | Stage 6 |
| Q4-006 | Preferred SBOM generator when both Python and Rust workers coexist (syft vs cyclonedx-py + cargo-cyclonedx)? | Security | Stage 5 CI |

---

## NOT_VERIFIED

| Item | Status | Note |
|------|--------|------|
| Exact CPU/memory `PROPOSED - TO BENCHMARK` numbers for job-object limits | UNVERIFIED | Must be measured against Stage-3 fixture corpus on target hardware |
| DPAPI best-practice integration details for key wrapping on non-domain-joined hosts | UNVERIFIED | Follow-up research; cryptography.io AESGCM for envelope DEKs is INFERRED |
| WinAFL vs AFL++ parity on Windows-native binaries | UNVERIFIED | Toolchain trial in Stage 5 |
| AppContainer support gaps for specific legacy DLLs used by oletools/pdfium | UNVERIFIED | PoC required |
| Full CVE inventory for poppler/pdfium/libarchive versions pinned | UNVERIFIED | OSV/pip-audit run at lock time; historical advisories from subagent research truncated in transcript |
| Cosign Windows binary distribution URL stability | UNVERIFIED | Verify at integration time |
| CPython version on target deployment (affects `re` possessive-quantifier availability) | INFERRED | Stage 1 pinned Python 3.12+; confirm runtime |

---

## Verification Log

| Source | URL | Retrieved | Used for |
|--------|-----|-----------|----------|
| Windows Sandbox overview | https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/ | 2026-10-08 | Edition matrix, disposable VM, networking default, hypervisor isolation |
| Use and configure Windows Sandbox (.wsb) | https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file | 2026-10-08 | `<Networking>Enable/Disable/Default>`, mapped folders, memory, vGPU |
| Windows Sandbox sample configuration | https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-sample-configuration | 2026-10-08 | Read-only Downloads.wsb pattern with Networking Disable |
| Windows Sandbox CLI | https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli | 2026-10-08 | `wsb start --config`, share/connect/stop automation surface; **CLI requires Windows 11 24H2+** (MS: "Starting with Windows 11, version 24H2") |
| AppContainer isolation | https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation | 2026-10-08 | Default-deny network/file without capabilities |
| Launch an AppContainer (capabilities / LPAC) | https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer | 2026-10-08 | Capability SID model, LPAC, `internetClient` |
| Win32 app isolation overview | https://learn.microsoft.com/en-us/windows/win32/secauthz/app-isolation-overview | 2026-10-08 | Minimum requirements (Win11 24H2 build 26100+) |
| Job objects overview | https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects | 2026-10-08 (prior turn) | Job limits without network/file members |
| JOBOBJECT_EXTENDED_LIMIT_INFORMATION | https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information | 2026-10-08 (prior turn) | Struct fields — no network/file ACLs |
| JOBOBJECT_BASIC_LIMIT_INFORMATION | https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information | 2026-10-08 (prior turn) | CPU/memory/process-count limit flags |
| JOBOBJECT_BASIC_UI_RESTRICTIONS | https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_ui_restrictions | 2026-10-08 (prior turn) | UI restriction flags |
| CreateRestrictedToken | https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken | 2026-10-08 (prior turn) | DISABLE_MAX_PRIVILEGE, LUA_TOKEN, WRITE_RESTRICTED, SANDBOX_INERT |
| PROCESS_MITIGATION_POLICY | https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-process_mitigation_policy | 2026-10-08 (prior turn) | ACG, CFG, DEP, font/image-load mitigations |
| Python re module (3.14 docs) | https://docs.python.org/3/library/re.html | 2026-10-09 | Possessive quantifiers / atomic groups (3.11+); ReDoS context |
