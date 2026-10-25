# Sentinel — Windows-First Security-Data Analysis & Threat Detection Platform

## 🛡️ Overview

**Sentinel** is a Windows-first, multi-tenant host-based intrusion detection system (HIDS) that ingests forensic artifacts, normalizes them into canonical events, and evaluates detection rules to produce findings and evidence. It is designed for security analysts, threat hunters, and incident responders who need to analyze Windows security data at scale.

The pipeline flows: **upload → identification → parsing → canonical events → enrichment → data-driven detection → evidence → findings/alerts → investigation**.

## 📦 Current Implementation Status

| Milestone | Status | Notes |
|-----------|--------|-------|
| **M0 (Foundation)** | ✅ Complete | Contracts frozen, config keys frozen, RLS policies, schema, OpenAPI |
| **M1 (Ingest + API)** | ✅ Complete | Upload gate, parsers, API surface, 113-rule Sigma pack |
| **M2 (Detection Engine)** | ✅ Complete | SQL-over-events primary with native fallback, cold-start gates |
| **M3 (IOC + Packaging)** | ✅ Complete | Ed25519 verification, pack staleness, native rule import |
| **M4-M6** | 🚧 In Progress | Worker pipelines, scoring, conformance oracle |

The project ships with a **pinned SigmaHQ rule pack** (112 rules, DRL-1.1 MIT-licensed) and a **demo EVTX file** for the end-to-end upload flow.

## 🏁 Problem Sentinel Solves

- **Forensic data silos:** EVTX, Sysmon, Security, UNSW-NB15, and CSV captures are difficult to query uniformly.
- **Rule distribution:** Sigma rules need a stable import surface with schema validation and provenance.
- **Detection pipelines:** SQL-based detection with native fallback ensures rules always execute (never silently skipped).
- **Multi-tenant isolation:** RLS-scoped PostgreSQL ensures tenant/workspace separation at the database layer.
- **Evidence provenance:** Immutable evidence snapshots with cryptographic hashes chain back to raw artifacts.

## 🧱 Technology Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | FastAPI + Python 3.12+ |
| **Database** | PostgreSQL 18 (RLS-enforced, 21 tables) |
| **Detection** | SQL compiler + native Python evaluator for Sigma rules |
| **Rule format** | `sentinel-rule/v1` + Sigma 2.1.0 |
| **IOC verification** | Ed25519 signatures via `cryptography` |
| **Storage** | Content-addressed filesystem ( SHA-256 object store ) |
| **Jobs** | Poll-driven worker process with lease-based claiming |
| **Config** | TOML file + `SENTINEL_*` environment variables |
| **Testing** | `pytest` (contract, unit, integration, e2e, scoring, tripwire) |
| **CI** | GitHub Actions (Windows + Ubuntu) |

## 📥 Supported Input Formats

| Format | Description | Pipeline |
|--------|-------------|----------|
| **EVTX** | Windows Event Log files (System, Security, Application) | Parsed → canonical events (Stage 3) |
| **Sysmon XML** | Sysmon operational log | Parsed → canonical events |
| **Security Log** | Windows Security channel (4688, 4624, etc.) | Parsed → canonical events |
| **CSV** | Flow records (UNSW-NB15, custom) | Mapped via field-pipeline → canonical events |
| **JSON** | Arbitrary structured data | Normalized to canonical events |

## 🏗️ Architecture & Processing Pipeline

```
upload (POST /v1/workspaces/{w}/uploads)
  → Stage-3 upload gate (size, policy, content-length pre-check)
  → parse (format-specific parser → canonical-event/v1 events + artifact_facts)
  → triage (fact extraction only, no verdicts)
  → detection job (Stage-5: SQL-over-events primary, native fallback)
  → findings + immutable evidence_snapshot (JSONB)
  → API read paths (findings, evidence, events, rules, runs, jobs)
```

Key invariants:
- **Never silently skip:** Every rule returns `imported`, `disabled`, or `rejected` with reason codes
- **Detection path recorded:** Every finding carries `detection_path: sql` or `native`
- **Evidence immutability:** `evidence_snapshot` is the authoritative record; raw objects can be purged after retention
- **RLS everywhere:** Tenant/workspace scoping on all 21 tables via `sentinel.tenant_id` / `sentinel.workspace_id`

## 👥 Main Components

| Package | Purpose |
|---------|---------|
| `packages/core/sentinel_core` | Config, DB tx, errors, RLS, logging, Argon2 params |
| `packages/detect/sentinel_detect` | Rule pipeline: parse → normalize → compile → evaluate (SQL + native) |
| `packages/ingest/sentinel_ingest` | Corpus UNSW-NB15 mapper, rule loading |
| `packages/storage/sentinel_storage` | PostgreSQL repo layer: uploads, events, findings, detects, rules |
| `apps/api/sentinel_api` | FastAPI surface: uploads, rules, findings, IOC packs, jobs, health |
| `apps/worker/sentinel_worker` (planned) | Background job worker (poll, claim, process) |

## ⚙️ Windows Installation & Setup

### Prerequisites

- **Python** ≥ 3.12 (developed on 3.14)
- **PostgreSQL 18** (Docker recommended)
- **Git** for clone

### 1. Python Environment

```powershell
# Create and activate venv
python -m venv .venv
.venv\Scripts\Activate.ps1

# Install deps
pip install -r requirements.txt
pip install -e .
```

### 2. Start PostgreSQL

```powershell
# From the project root
docker compose up -d --wait
```

This starts `sentinel-db` on `127.0.0.1:54321`. The compose file creates the `sentinel` database with a `postgres` superuser.

### 3. Initialize the Database

The `packaging/docker-init/` directory contains SQL scripts run on first startup. They create:
- The 21-table schema with RLS policies
- Three roles: `sentinel_app`, `sentinel_migrator`, `sentinel_worker`
- RLS policies for tenant/workspace scoping

### 4. Configuration

Sentinel uses environment-variable precedence (`SENTINEL_*` > `sentinel.toml` > built-in defaults). Copy `.env.example` and adjust:

```powershell
copy .env.example .env
# Edit .env — passwords (DSNs) are supplied at runtime; do not commit .env
```

Key environment variables:

| Variable | Purpose | Default |
|---|---|---|
| `SENTINEL_SERVER__HOST` | API bind address | `127.0.0.1` |
| `SENTINEL_SERVER__PORT` | API port | `8080` |
| `SENTINEL_DATABASE_URL` | App role DSN | see .env.example |
| `SENTINEL_STORAGE_ROOT` | Content-addressed data root | `C:\ProgramData\Sentinel\data` |
| `SENTINEL_INGEST_MAX_FILE_BYTES` | Max upload size | `67108864` (64 MiB) |
| `SENTINEL_DETECTION_NATIVE_ENABLED` | Native fallback | `true` |

### 5. Start the API Server

```powershell
# From the project root
python -m sentinel_api.main
# or, using the app factory:
python -c "from apps.api.sentinel_api.app import create_app; from sentinel_core.config import load_settings; app = create_app(load_settings()); app"
```

The server starts at `http://127.0.0.1:8080` (configurable).

### 6. Run the Detection Worker (M2+)

The worker process polls for jobs, runs detection, and persists findings. It is started automatically when uploads are enqueued, but can also be run manually:

```powershell
python -m packages.detect.sentinel_detect.runner
```

## 🗂️ Environment-Variable Configuration

All config keys from `spec §4` are exposed as `SENTINEL_SECTION__KEY` (double underscore = nesting). For example:

- `SENTINEL_DATABASE_URL` → `database.url` in TOML
- `SENTINEL_SERVER__PORT` → `server.port` in TOML
- `SENTINEL_STORAGE_ROOT` → `storage.root` in TOML

The frozen key inventory lives in `configs/config_keys.json`. Keys marked `origin: "M0-A2"` are extensions required by the 3-role topology (migrator DSN, worker DSN, ingest rate limits, dev API keys).

## 🗄️ Database Initialization & Migrations

- **Schema:** `schema.sql` defines 21 tables, RLS policies, and Check constraints
- **Alembic migrations:** `migrations/versions/` (tracked, idempotent)
- **First-start:** `packaging/docker-init/00-roles.sql` runs on `docker compose up`
- **Upgrade:** `alembic upgrade head` applies pending migrations

The config-freeze test (`tests/contract/test_config_freeze.py`) ensures every Settings field has a corresponding entry in `configs/config_keys.json`.

## 🔧 Running Tests & Linters

```powershell
# Contract + unit + tripwire (no database needed)
pytest tests/contract tests/unit tests/tripwire

# Integration (needs PostgreSQL)
pytest tests/integration

# E2E upload flow (needs PostgreSQL)
pytest tests/e2e

# Scoring (UNSW-NB15 corpus, fetched out-of-tree)
pytest tests/scoring

# Schema lint + migration catalog
python tools/schema_lint.py

# Config freeze verification
python tools/config_freeze.py
```

## 🚀 Example Usage — Safe Upload + Detection

### 1. Upload an EVTX file

```powershell
curl -X POST "http://127.0.0.1:8080/v1/workspaces/default/uploads" `
  -H "X-API-Key: dev-key-default-0000000000000001" `
  -F "file=@tests/fixtures/sentinel_m1.evtx"
```

Response: `202 Accepted` with `artifact_id`, `run_id`, `sha256`, etc.

### 2. Check detection run status

```powershell
curl -H "X-API-Key: dev-key-default-0000000000000001" "http://127.0.0.1:8080/v1/workspaces/default/runs"
```

### 3. List findings

```powershell
curl -H "X-API-Key: dev-key-default-0000000000000001" "http://127.0.0.1:8080/v1/workspaces/default/findings?limit=20"
```

### 4. IOC pack verification

```powershell
# Import a signed IOC pack
curl -X POST "http://127.0.0.1:8080/v1/workspaces/default/ioc-packs" `
  -H "X-API-Key: dev-key-default-0000000000000001" `
  -d @configs/demo-ioc-key-2026.json
```

## 📏 Known Limitations & Troubleshooting

| Issue | Resolution |
|-------|-----------|
| **No detections on cold-start** | Cold-start codes (`BASELINE_MISSING`, `BASELINE_WARMUP`) are emitted; meet `min_observations` or the rule is suppressed |
| **Rules flip to `native` path** | Cost budget exceeded (`COST_BUDGET_EXCEEDED`) — the SQL statement > 64 KiB; the rule continues on the native path |
| **`UNMAPPED_FIELD` reason codes** | Sigma field names that cannot be mapped to canonical paths; the rule still runs, fields land in `unmapped.<name>` |
| **Native-only modifiers** | `re`, `fieldref`, `cidr` are evaluated by the native evaluator only; SQL path emits `REGEX_NATIVE_ONLY` / `FIELDREF_NATIVE_ONLY` |
| **EVTX parsing errors** | Ensure the EVTX file is not corrupted; verify Event Viewer can read it |
| **Docker compose port conflict** | `docker-compose.override.yml` remaps Windows-excluded ports; adjust if needed |
| **401 GATE_UNAUTHENTICATED** | Include `X-API-Key` header with a registered dev principal |

## 🔐 Security Considerations & Responsible-Use Boundaries

- **Never run untrusted parsers on host memory:** Detonation is sandboxed via Job Objects / AppContainers (Stage 4). The API enforces a content-length pre-check and streamed byte count.
- **Uploaded artifacts are analyzed statically:** Files are hashed (`sha256`) and stored content-addressed; they are **not** executed in-process.
- **IOC signature verification is verify-then-activate:** Unsigned / expired / bad-signature IOCs are `rejected`; only verified packs become `active`.
- **RLS enforces tenant/workspace scoping:** Every database query scoped through `sentinel.tenant_id` / `sentinel.workspace_id`. The app role has no `BYPASSRLS`.
- **Evidence snapshot is the authoritative record:** After purge, the `evidence_snapshot` JSONB is the only evidence of record (spec §1.5, reject-condition R1).
- **Config secrets are env‑only:** The three DSN passwords (`sentinel_app`, `sentinel_migrator`, `sentinel_worker`) are never checked into VCS; they are supplied at runtime via `docker compose` or `SENTINEL_*` env vars.
- **Sigma rule authorship:** Committed rule files are DRL-1.1 (MIT-based). Distribution and modification are permitted with the copyright notice and author attribution (`tests/conformance/ATTRIBUTION.md`).

## 📄 Licensing & Third-Party Attribution

| Component | License | Attribution |
|-----------|---------|-------------|
| **Sentinel core** | Apache 2.0 (project-level) | See `LICENSE` file |
| **DRL-1.1 Sigma rules** | MIT | `tests/conformance/ATTRIBUTION.md` + author field in each rule |
| **UNSW-NB15 dataset** | Academic-use only (V-6-035) | Moustafa & Slay, MilCIS 2015; never committed; fetched out-of-tree |
| **cryptography (Ed25519)** | Apache 2.0 / BSD | `requirements.txt` pins `cryptography==50.0.2` |
| **pySigma / SigmaHQ rules** | DRL-1.1 (MIT) | `tests/conformance/rules/` with SHA-256 pins |
| **Uvicorn** | ASL 2.0 | ASGI server |
| **FastAPI** | ASL 2.0 | API framework |
| **PostgreSQL** | PostgreSQL License | Database engine |

### License gate

`tests/contract/test_licence_register.py` enforces that every dependency in `requirements.txt` has a licence entry in `research/verification/DEPENDENCY_LICENCES.yaml`. New dependencies must be added there before the gate passes.

## 📞 Contact & Contributing

- **Issues:** Use the GitHub issue tracker
- **Pull requests:** Follow the contribution guidelines; all new code is contract-gated
- **Security disclosures:** Send to the maintainer privately; do not post secrets publicly

---

*Generated from the Sentinel implementation specification (Stages 1–6, assembled 2026-10-10). See `research/SENTINEL_IMPLEMENTATION_SPEC.md` for the full merged spec, `research/DEVIATION_REGISTER.md` for M0–M3 amendments, and `consistency_report.md` for open conflicts.*