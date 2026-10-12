# Sentinel — light Windows-first HIDS backend

Machine-normative contracts live at the repo root (`schema.sql`, `openapi.yaml`,
`canonical_event_v1.schema.json`, `rule_schema.json`). The authored plan is
`research/SENTINEL_IMPLEMENTATION_SPEC.md`; deviations are recorded in
`research/DEVIATION_REGISTER.md`.

## Build

### 1. Python environment

Python ≥ 3.12 (developed on 3.14).

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1          # Windows
# source .venv/bin/activate         # Linux/macOS
pip install -r requirements.txt
pip install -e .
```

`pip install -e .` is required — `pytest` sets `pythonpath = ["."]`, but the
packages themselves are laid out under `packages/` and `apps/`.

### 2. PostgreSQL 18

```powershell
docker compose up -d --wait
```

Publishes the compose DB on `127.0.0.1:54321` and runs
`packaging/docker-init/00-roles.sql` on first start, creating the three roles
the topology needs:

| Role | Purpose | BYPASSRLS |
|---|---|---|
| `sentinel_app` | API / RLS-enforced queries | no |
| `sentinel_migrator` | schema owner, DDL, `alembic upgrade head` | no |
| `sentinel_worker` | cross-tenant job claiming | yes |

### 3. Configuration

Precedence (D6-010): `SENTINEL_*` environment > config file > built-in default.
Tests pin `SENTINEL_CONFIG=configs/config.example.toml` automatically. The
frozen key inventory is `configs/config_keys.json` (41 keys).

## Test

```powershell
# everything — 379 tests
pytest

# the three CI jobs, individually
pytest tests/contract tests/unit tests/tripwire          # 256, no database
pytest tests/integration tests/e2e -m "not slow"         # 121, needs PostgreSQL
python tools/schema_lint.py                              # exit (1) gate
```

`-m "not slow"` is the contract declared in `tests/integration/conftest.py`:
the 10k-job soak and the docker stop/start readiness flip are local diagnostics.

Other gates:

```powershell
python tools/extract_examples.py --check   # fixture corpora == spec (exit ③)
python tools/corpus_fetch.py               # pin + fetch the out-of-tree corpus
```

CI: `.github/workflows/ci.yml` runs the three jobs above on every push and PR.
Which spec exit criterion each job discharges is in spec §9a.

## Datasets

### Committed (run on every test)

| Path | What |
|---|---|
| `tests/fixtures/canonical_events/` | 121 Stage-2 canonical-event YAMLs |
| `tests/fixtures/stage5_rules/`, `stage3_af/` | 25 + 5 rule fixtures, with `manifest.json` provenance |
| `tests/fixtures/sentinel_m1.evtx` | 1.07 MiB System-channel EVTX for the M1 e2e upload flow |
| `tests/conformance/rules/` | 20 pinned SigmaHQ rules (DRL-1.1) + 3 Sentinel-authored; pin + per-file sha256 in `tests/conformance/expected.json`, obligations in `tests/conformance/ATTRIBUTION.md` |

Rule files are the only third-party code committed: DRL-1.1 (MIT-based)
permits distribution and modification with the licence notice and author
attribution. Datasets and raw captures are not committed — see below.

### Out-of-tree (pinned, sha256-verified, never committed)

Spec §6.2; fetched by `tools/corpus_fetch.py`, stored in `.corpus/`
(gitignored), CI-secret gated. Includes the sigma-spec golden corpus
(`sigma-specification/tests/` @ `ba9251aa834b`), `EVTX-ATTACK-SAMPLES`,
`LID-DS`, `suricata-verify`, Zeek `testing/` traces, `attack_data`,
`Security-Datasets` and, for detection scoring, `UNSW-NB15`.

### UNSW-NB15 — the dataset for building and testing detection and analysis

**UNSW-NB15 is mandatory** for the detection and analysis system: it is the
dataset those systems are *built against* while they are constructed (M2–M4)
and *tested against* after they ship (nightly + every release). Full plan,
gates and rules: **spec §6.3a**; milestone hooks in **spec §9** (M2/M3/M4 exit
criteria); test-layer hook in **spec §6.1** (Detection scoring row).

Why it and not another corpus: it carries per-flow ground truth — an
`attack_cat` class plus a binary `label` — so detection quality is reported as
**precision / recall / FPR**, never as "a rule matched". The `Normal` class is
the false-positive baseline.

Current status: licence **VERIFIED 2026-10-12** (UNSW's own terms: free use
for academic research, commercial use prohibited) — so the corpus is fetched
out-of-tree on demand into `.corpus/unsw-nb15/` (gitignored, pinned URL +
sha256 + row counts + citation at first fetch) and no dataset row is ever
committed. Parser and harness still develop and unit-test against the
committed synthetic flow fixture first; only commercial corpus automation
remains gated (spec §12).

Attribution: UNSW-NB15 is academic-use with mandatory citation —
see V-6-035 in the spec's Verification Log.
