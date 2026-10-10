# Sentinel — Stage 1: Landscape Study & Rule-Engine Decision

**Deliverable for the downstream coding agent. Compiled 2026-10-08. Workspace: `C:\Users\dhruv\OneDrive\Desktop\College\Light HIDS\`**

How to read this document:

- Every factual claim carries one of three labels: **VERIFIED** (primary source fetched/read, cited inline), **INFERRED** (logical deduction from VERIFIED facts, stated as such), **UNVERIFIED** (could not confirm; never build on these).
- Every number is either attributed to a cited source or marked **PROPOSED - TO BENCHMARK**.
- Evidence citation styles: `REPORT §SECTION` (e.g. `EVTX §CHAINSAW-6`) refers to the four companion research files in this workspace (`wazuh-falco-research.md`, `evtx-hunting-tools-report.md`, `osquery-velociraptor-tetragon-research.md`, `primary-source-research.md`); `repo@commit:path` expands to `https://github.com/<repo>/tree/<commit>`; bare URLs were fetched on 2026-10-08.
- Product fixed decisions (given, not re-litigated): Python 3.12+/FastAPI/PostgreSQL/background worker; native tools (Rust EVTX parser, TShark, YARA) run as isolated external processes; parsers understand formats, detectors understand security behavior, detectors only consume canonical events; zero hardcoded detections (empty rule pack ⇒ zero detections); static analysis only on uploads; three classification levels never collapsed; `COMPLETED_WITH_WARNINGS` = partial success; single-tenant first, multi-tenant-ready (tenant id on every row); out of scope: live agents, kernel drivers, active response, Kafka/K8s, SOAR. Assume commercial/closed-source distribution.

---

## 1. Verification Log

One row per project inspected. "Files read" states exactly what was examined; rows marked *metadata only* were **not** used as evidence for Sections 3–7. Branch/head/release dates from GitHub API, `releases.atom`, `commits/<branch>.atom`, `raw.githubusercontent.com`, and depth-1 clones (API rate limits forced the atom/raw fallback).

### 1.1 Repository projects

| # | Project | URL | Branch | Latest release (date) | Commit inspected | SPDX / licence evidence | Lang | Last commit | Maintenance | Files read |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Wazuh | github.com/wazuh/wazuh | main | v4.14.8 stable (2026-09-25); feed also v4.14.9-rc2 (2026-10-08), v5.0.0-rc1 (2026-10-05) | `7c901686a30c28467559687472ca755d2df77230` | GPL-2.0-only (LICENSE: code **and** rules/decoders, OpenSSL exception) | C++ | 2026-10-08 | ACTIVE | `LICENSE` (raw @v4.14.8 + main), `ruleset/README.md` (main), `ruleset/rules/` listing @v4.14.8, `0015-ossec_rules.xml`/`0095-sshd_rules.xml` (raw), docs pages (rules syntax, ruleset conf, analysisd, internal-options, statistics, syscheck, SCA, offline install, migration-to-5x) → `wazuh-falco-research.md §WAHUH-1..8` |
| 2 | OSSEC HIDS | github.com/ossec/ossec-hids | main | 4.4.0 (2026-10-05) | `10c204af0c78…` | GPL-2.0 (API + LICENSE) | C | 2026-10-08 | ACTIVE | metadata only — **not** used in §3–7 |
| 3 | Falco | github.com/falcosecurity/falco | master | 0.45.0 stable (2026-09-21); 0.45.1-rc1 (2026-10-05) | `b608d820c8a3…` | Apache-2.0 (COPYING) | C++ | 2026-10-03 | ACTIVE | `COPYING`, `falco.yaml`, `CHANGELOG.md`, docs (rules concepts/fields/exceptions, event-sources, kernel/tuning, plugins, CLI, performance, custom-ruleset) → `wazuh-falco-research.md §FALCO-1..7` |
| 4 | Falco rules | github.com/falcosecurity/rules | main | falco-sandbox-rules-6.2.0 (2026-09-07) | `21ef6d5f5fdd…` | Apache-2.0 (LICENSE; `# SPDX-License-Identifier` in rule files) | YAML | 2026-09-25 | ACTIVE | `LICENSE`, `rules/falco_rules.yaml` (full read; counted 25 rules / 88 macros / 49 lists / 0 exceptions) |
| 5 | Tetragon | github.com/cilium/tetragon | main | v1.7.1 (2026-08-25) | `1ac2010c48c5…` | Apache-2.0 (LICENSE; README also carries BSD-2/GPL-2 badges, scope UNVERIFIED) | C | 2026-10-08 | ACTIVE | `LICENSE`, `README.md`, `MAINTAINERS.md`, `docs/…` (overview, events, tracing-policy, selectors, faq, daemon-configuration, grpc-api), `examples/tracingpolicy/sys_setuid.yaml`, `examples/configuration/tetragon.yaml`, `pkg/k8s/apis/…/tracing_policy_types.go`, `bpf/windows/process_monitor.c` → `osquery-velociraptor-tetragon-research.md §TETRAGON-1..5` |
| 6 | osquery | github.com/osquery/osquery | master | 5.23.1 (2026-06-24) | `d9db97e3a86cf3e3ed4b3f8abbb8c4175b107855` | Apache-2.0 **OR** GPL-2.0-only (dual; no OpenSSL exception) | C++ | 2026-10-07 | ACTIVE | `LICENSE`, `LICENSE-GPL-2.0`, `README.md`, `CONTRIBUTING.md`, `docs/wiki/**` (index, configuration, FIM, cli-flags, install-windows, using-osqueryi, creating-tables, pubsub-framework), `specs/*` (13 Windows/POSIX tables), `packs/` → `osquery-velociraptor-tetragon-research.md §OSQUERY-1..6` |
| 7 | Velociraptor | github.com/Velocidex/velociraptor | master | 0.77.3 (2026-10-05) | `fa9a5b4cd1a26f4a630f1ccdcb12713efc195af7` | AGPL-3.0 (LICENSE) | Go | 2026-10-07 | ACTIVE | `LICENSE`, `vql/sigma/{sigma.go,evaluator/,correlation.go,logsource.go}`, `vql/plugins.go`, `artifacts/definitions/**` (423 YAML), `bin/offline.go`, `accessors/collector/collector.go`, docs repo `95588f0` (overview, VQL, artifacts, offline collections, deaddisk, notebooks, resources) → `…§VELOCIRAPTOR-1..7` |
| 8 | SwiftOnSecurity Sysmon config | github.com/SwiftOnSecurity/sysmon-config | master | none | `1836897f12fbd6a0a473665ef6abc34a6b497e31` | **No LICENSE file**; CC-BY-4.0 claimed in `sysmonconfig-export.xml` header only (repo-level licence UNVERIFIED) | XML | 2021-10-17 | STALE (>4 yrs) | `sysmonconfig-export.xml` (header + RuleGroup scan), `README.md`, GitHub API → `…§SYSMON-3(a)` |
| 9 | sysmon-modular | github.com/olafhartong/sysmon-modular | master | configs-082cba578667 (2026-09-18) | `082cba578667a5f57b44a8e64bc02548d2338859` | MIT (`license.md`, API spdx) | Go | 2026-09-18 | ACTIVE | `README.md`, `license.md`, release API, tree listing (529 files) → `…§SYSMON-3(b)` |
| 10 | AIDE | github.com/aide/aide | master | v0.19.4 (2026-08-30) | `b4fc3aee8ad7da205a7d5e8f27c5f99a8936be40` | GPL-2.0 (COPYING) | C | 2026-09-22 | ACTIVE | `COPYING`, `doc/aide.conf.5` (full), `doc/aide.1`, `src/aide.c` (:411-415, :850) → `primary-source-research.md §AIDE-1..5` |
| 11 | OpenSCAP | github.com/OpenSCAP/openscap | main | 1.4.4 (2026-04-09) | `a567a7584203801467f1326137cbe9dbad23edd4` | LGPL-2.1 (COPYING) | C/XSLT | 2026-10-08 | ACTIVE | `COPYING`, `README.md`, `docs/windows.md`, `docs/manual/manual.adoc` (:1641 etc.), `utils/oscap-chroot`, `src/OVAL/probes/` (tree) → `…§OPENSCAP-1..5` |
| 12 | Tripwire OSS | github.com/Tripwire/tripwire-open-source | master | 2018 (per release feed) | `4c84a88471…` | GPL-2.0 (API + LICENSE) | C++ | 2019-03-16 | DORMANT | metadata only — **not** used in §3–7 |
| 13 | Chainsaw | github.com/WithSecureOpenSource/chainsaw (Cargo.toml still says WithSecureLabs — redirect) | master | v2.16.5 (2026-08-25) | `af12749f6d0acdcfa274efce2643b5399b9ca8d1` | GPL-3.0 — `Cargo.toml` `license = "GPL3"` (**non-SPDX string**) + `LICENCE` (full GPLv3 text); no root `LICENSE` file | Rust | 2026-09-23 | ACTIVE | `Cargo.toml`, `LICENCE`, `src/main.rs`, `src/rule/{sigma.rs,chainsaw.rs}`, `src/{cli,hunt,file}/`, `mappings/sigma-event-logs-all.yml`, `rules/evtx/**` → `evtx-hunting-tools-report.md §CHAINSAW-1..10` |
| 14 | Hayabusa | github.com/Yamato-Security/hayabusa | main | v4.1.0 (2026-09-12) | `19a1d1db87831e976170395051c8dbc7d6c939eb` | AGPL-3.0 (code, `LICENSE.txt`) + **DRL 1.1** (rules submodule `hayabusa-rules@18afcb376e13e965037b2fc12c1e3470bc5e333d`) | Rust | 2026-10-04 | ACTIVE | `LICENSE.txt`, `README.md`, `Cargo.toml`, `.gitmodules`, `src/detections/configs.rs`, `src/yaml.rs`, `src/detections/rule/{correlation_parser,aggregation_parser}.rs`, `config/{default_profile,profiles}.yaml`, `OLD-README.md` → `…§HAYABUSA-1..10` |
| 15 | Zircolite | github.com/wagga40/Zircolite | master | v4.2.0 (2026-10-03, == HEAD) | `a575d5fe1bd704bf4d9604b5d327aa53c8bf20f2` | LGPL-3.0-or-later (`pyproject.toml` `license`, LICENSE text) | Python | 2026-10-03 | ACTIVE | `pyproject.toml`, `README.md`, `docs/{Usage,Advanced,Benchmark}.md`, `zircolite/{cli,core,config_loader,rules,results}.py`, `config/config.yaml` → `…§ZIRCOLITE-1..9` |
| 16 | DeepBlueCLI | github.com/sans-blue-team/DeepBlueCLI | master | none (no tags) | `2eecc65698e8666408ece67525577c895676d579` | GPL-3.0 (LICENSE) | PowerShell | 2023-06-28 | STALE | `DeepBlue.ps1` (870 lines), `README.md`, `READMEs/README-DeepBlue.py.md`, `DeepBlue.py` → `…§DEEPBLUECLI-1..7` |
| 17 | Rust evtx crate | github.com/omerbenamram/evtx | master | v0.12.3 (2026-09-22) | `7479d02dfaa3bdeb41c5ea87195e84116a032cfc` | MIT OR Apache-2.0 (`Cargo.toml` `license = "MIT/Apache-2.0"`, dual LICENSE files) | Rust | 2026-10-07 | ACTIVE | `Cargo.toml`, `src/lib.rs`, `src/evtx_parser.rs`, `src/evtx_record.rs`, `src/bin/evtx_dump.rs` → `…§EVTXLIB-1` |
| 18 | python-evtx | github.com/williballenthin/python-evtx | master | **v0.8.1** (2025-05-02); tag `v8.1.0` is a digit-transposed tag (VERIFIED, see `…§EVTXLIB-3` correction #1) | `c0007441657899c39180de10a2be1a0e43dbeaf9` | Apache-2.0 (LICENSE.TXT, pyproject) | Python | 2026-10-06 | ACTIVE (low cadence) | `pyproject.toml`, `Evtx/Evtx.py`, `evtx_scripts/evtx_dump_json.py` → `…§EVTXLIB-3` |
| 19 | Sigma specification | github.com/SigmaHQ/sigma-specification | main | v2.1.0 (release entry 2025-09-12; spec document v2.1.0) | `ba9251aa834b…` | Specification + logo: public domain (LICENSE) | Markdown | 2026-06-09 | MAINTAINED (spec stable) | `LICENSE`, `specification/sigma-rules-specification.md`, `specification/sigma-correlation-rules-specification.md`, `specification/sigma-appendix-modifiers.md`, tree of `tests/` + `json-schema/` |
| 20 | pySigma | github.com/SigmaHQ/pySigma | main | **v2.0.0 (2026-10-04)** — breaking release | `50708bae1fd24c75a5342187e34c126c13c69a18` | LGPL-2.1-only (pyproject `license`) | Python | 2026-10-04 | ACTIVE | `pyproject.toml`, `sigma/conversion/base.py` (`Backend` :68, abstract `convert()` :192, `TextQueryBackend`), `sigma/conditions.py`, `sigma/correlations.py`, `sigma/plugins.py`, `sigma/rule/`, `sigma/processing/`, `sigma/validators/` |
| 21 | SigmaHQ rules | github.com/SigmaHQ/sigma | master | r2026-07-01 (2026-07-09; quarterly cadence) | `8a4813404ea3074890e0cda9272d4d1a8b2941d6` | **DRL 1.1** for rules (LICENSE; spec portion public domain) | YAML | 2026-10-06 | ACTIVE | `LICENSE`, `Releases.md`, full-tree counts (4063 active .yml), sample rule (windows process_creation 7-Zip dump) |
| 22 | sigma-cli | github.com/SigmaHQ/sigma-cli | main | v3.1.0 (2026-07-07) | `863c714109…` | LGPL-2.1 (LICENSE.txt) | Python | 2026-10-04 | ACTIVE | metadata + LICENSE only |
| 23 | YARA | github.com/VirusTotal/yara | master | v4.5.8 (2026-07-28) | `5e8a8ea41f73e4e24ec91382b7e6a697097b48aa` | BSD-3-Clause (COPYING) | C | 2026-09-23 | ACTIVE | `COPYING`, `docs/writingrules.rst`, `docs/modules.rst`, `docs/capi.rst` → `primary-source-research.md §YARA-1..6` |
| 24 | YARA-X | github.com/VirusTotal/yara-x | main | v1.21.0 (2026-09-30) | `ee7c4c7a01fb4e5f9028e1a6da1b24bfc53cfc11` | BSD-3-Clause (LICENSE) | Rust | 2026-10-08 | ACTIVE | `LICENSE`, `README.md`, `lib/Cargo.toml`, docs pages (yara-x-vs-yara, differences-with-yara) → `…§YARA-3..5` |
| 25 | Suricata | github.com/OISF/suricata | main | 8.0.7 (2026-09-15) | `215961d67239ba2594a0d43f031829ecf710e3e9` | GPL-2.0 (LICENSE); built-in rules carry no per-file header | C | 2026-10-03 | ACTIVE | `LICENSE`, `rules/decoder-events.rules`, `rules/README.md`, docs (intro, manpage, eve-json) → `…§SURICATA-1..6` |
| 26 | Elastic detection rules | github.com/elastic/detection-rules | main | dev-v3.0.10 (2026-10-07, releases feed) | metadata: `bc5b7c3e95…`; content read at `4cb67c5b965bc1ba41a98d54adbbe247ae2afb27` (2026-10-08) | **Elastic License 2.0** (LICENSE.txt; each rule `license = "Elastic License v2"`) | Python/TOML | 2026-10-08 | ACTIVE | `LICENSE.txt` (full — restriction clause cited in §2), `README.md`, sample `rules/windows/execution_shared_modules_local_sxs_dll.toml`, count 2216 .toml → `…§IOC-11` |
| 27 | MISP | github.com/MISP/MISP | 2.5 | v2.4.222 (2026-10-01) | `fb54b3e4a4…` | AGPL-3.0 (API + LICENSE) | PHP | 2026-09-29 | ACTIVE | metadata + LICENSE head; spec via `MISP/misp-rfc` (cited in `…§IOC-8`) |
| 28 | cti-python-stix2 | github.com/oasis-open/cti-python-stix2 | master | 3.0.2 (2026-02-12) | `2270361774215de49717c1a6028a80c91075b400` | BSD-3-Clause (LICENSE) | Python | 2026-02-12 | MAINTAINED | `LICENSE`, `README.rst`, `version.py`, docs (taxii notebook) → `…§IOC-7` |
| 29 | OpenIOC 1.1 | github.com/fireeye/OpenIOC_1.1 | master | none (still "DRAFT") | `f4973b80d4fcf9ae067a09df656ce6dd2d6899ba` | Apache-2.0 (LICENSE; README enumerates covered files) | XML schema | 2020-12-14 | DORMANT (not archived) | `LICENSE`, `README.md`, `schemas/ioc.xsd` → `…§IOC-9` |
| 30 | DuckDB | github.com/duckdb/duckdb | v2.0-cyanoptera (default) | v1.5.6 (2026-09-28) | `0dc65ff31f…` | MIT (LICENSE text; gather recorded "MIT-or-BSD (manual review)" — VERIFIED MIT text 2026-10-08) | C++ | 2026-10-08 | ACTIVE | `LICENSE` head |
| 31 | pySigma SQLite backend | github.com/SigmaHQ/pySigma-backend-sqlite (canonical URL used by plugin directory; wagga40 URL redirects — same HEAD) | main | no git release tag verified; `pyproject.toml` `version = "2.0.0"` | `017306687567723ed2fec271194d1c65f2abfde5` | **LGPL-3.0-only** (LICENSE + API spdx) | Python | 2026-09-26 | ACTIVE | `pyproject.toml` (incl. pin `pysigma>=1.5.1,<2`), `README.md`, `sigma/backends/sqlite/{sqlite,correlation,runtime}.py` (incl. `execute_plan()`), `tools/benchmark_correlations.py` |
| 32 | pySigma Athena backend | github.com/SigmaHQ/pySigma-backend-athena | main | none | `e8a11bdb93…` | MIT | Python | 2025-12-07 | LOW CADENCE | metadata + LICENSE only |
| 33 | pySigma SQLite backend (DenizenB) | github.com/DenizenB/pySigma-backend-sqlite | main | none | `68c74fd3cf…` | MIT | Python | 2023-08-03 | STALE | metadata + LICENSE only — superseded by #31 |
| 34 | sigma2sql | github.com/Security-Bits/sigma2sql | — | — | — | — | — | — | **DEAD — repository not found** (git + raw both 404, 2026-10-08) | REJECTED per evidence rules; no claim in this document depends on it |

URL corrections discovered during gathering (both attempts logged): raw1 used `tripwire/tripwire` (→ #12 `Tripwire/tripwire-open-source`), `oasis-tc/cti-stix2` (→ #28), `fireeye/openioc` (→ #29 `OpenIOC_1.1`), `ericzimmer/DeepBlueCLI` (→ #16 `sans-blue-team/DeepBlueCLI`). All raw1 rows for these were superseded by raw2.

### 1.2 Non-repository primary sources

| Source | Version / stage (date) | Licence | Files read | Status |
|---|---|---|---|---|
| Microsoft Sysmon (Sysinternals) | v15.22 (2026-09-10); built-in optional feature on Windows 11/Server 2025 — first shipped to Insiders 2026-02-03 (announced 2025-11-18); GA date UNVERIFIED | Proprietary freeware (MS EULA, `sysinternals/license-terms`) — no SPDX | `learn.microsoft.com/sysinternals/downloads/sysmon`, `…/windows/security/operating-system-security/sysmon/{sysmon-events,sysmon-configuration-files}` (old `sysinternals/sysmon-*` URLs 404), `…/windows-commands/sysmon`, `…/sysmon/overview` → `sysmon-sysinternals-research.md §SYSMON-1..5` | ACTIVE |
| Microsoft Autoruns | v14.3 (2026-06-17) | Proprietary freeware | `learn.microsoft.com/sysinternals/downloads/autoruns`, What's New page, Microsoft Press chapter by tool authors → `sysmon-sysinternals-research.md §SYSINTERNALS-6` | ACTIVE |
| Microsoft Sigcheck | v2.92 (2026-09-10) | Proprietary freeware | `learn.microsoft.com/sysinternals/downloads/sigcheck` → `sysmon-sysinternals-research.md §SYSINTERNALS-7` | ACTIVE |
| `wevtutil` docs (EVTX export path) | current | Proprietary freeware | `learn.microsoft.com/…/windows-commands/wevtutil` → `sysmon-sysinternals-research.md §SYSMON-5` | ACTIVE |
| LIGHT-HIDS paper | arXiv:2509.13464v1 (2025-09-16, accepted ICMLA'25 — stated in arXiv Comments) | arXiv non-exclusive licence; **no code/data released** | full HTML `arxiv.org/html/2509.13464v1` → `light-hids-research-report.md §LIGHT-HIDS-1..7` | Paper only |
| Wazuh documentation | `/current/` ≡ `/4.14/` (byte-identical, SHA-256 compared) | docs licence not fetched → UNVERIFIED | internal-options, rules syntax, daemons, statistics, SCA, FIM, rootcheck, offline install | USED |
| Falco documentation | falco.org/docs (site changelog lags repo: shows 0.44.1 vs 0.45.0) | docs licence not fetched → UNVERIFIED | concepts/rules, event-sources, tuning, performance, CLI | USED |
| pySigma plugin directory | `pySigma-plugins-v1.json` (fetched 2026-10-08) | repo licence UNVERIFIED | data file: **38 plugins = 33 backends + 5 pipelines** (windows, sysmon, ossem, ocsf, rclinuxedr) | USED (§5) |
| Emerging Threats Open ruleset | index dated 2026-10-07 | **Mixed**: sids 1–3464 & 100000000–100000908 GPLv2; 2000000–2799999 BSD; 2800000–2900000 ETPRO | `rules.emergingthreats.net/open/suricata-5.0/LICENSE` → `primary-source-research.md §SURICATA-4` | USED (§2) |
| ComplianceAsCode content | master | BSD-3-Clause (LICENSE raw) | LICENSE only → `§OPENSCAP-4` | USED (§2) |
| abuse.ch Feodo Tracker / URLhaus | checked 2026-10-08 | Feodo: CC0 (page ToS); URLhaus: ToS + Auth-Key for bulk | blocklist page, FAQ, `csv_recent` header → `§IOC-10` | USED (§2); Feodo data currently **empty** (takedowns) |
| NIST SCAP specs (XCCDF/OVAL/CPE) | CPE page "Updated June 09, 2026"; CPE 2.3 current | NIST public | csrc.nist.gov spec pages → `§OPENSCAP-1` | USED |
| LID-DS dataset (LIGHT-HIDS input) | ref [25] of paper | UNVERIFIED (repo not inspected) | paper only | UNVERIFIED — see §8 |

---

## 2. Licence Register

Usage classes: **DEPENDENCY** = code/content shipped in or imported into Sentinel; **EXTERNAL_PROCESS** = separate binary executed at runtime (never linked); **REFERENCE_ONLY** = study only, no code/content copied; **AVOID** = do not redistribute, embed, or serve. Commercial/closed-source distribution assumed. "Legal flag" = recommendation for counsel review before first use (LOW/MED/HIGH).

### 2.1 Code & engines

| Project | Code licence (evidence) | Usage class | Commercial-distribution impact (VERIFIED terms) | Legal flag |
|---|---|---|---|---|
| Rust `evtx` crate | MIT OR Apache-2.0 (`evtx@7479d0:Cargo.toml`, dual LICENSE files) | DEPENDENCY (our Rust parser helper) / EXTERNAL_PROCESS (`evtx_dump`) | Permissive; retain notices; no source obligation | LOW |
| python-evtx | Apache-2.0 (`pyproject.toml`, LICENSE.TXT) | DEPENDENCY (fallback parser) | Apache patent grant + notice retention | LOW |
| pySigma | LGPL-2.1-only (pyproject) | DEPENDENCY **or** EXTERNAL_PROCESS (`sigma-cli`, also LGPL-2.1) | Closed-source use OK if library unmodified + dynamically loadable + licence text + relink ability shipped; modifications to pySigma itself force source release of the modified library | MED |
| pySigma pipelines `windows` / `sysmon` | LGPL-2.1 (LICENSE fetched 2026-10-08, both repos) | DEPENDENCY (import-time field mapping) | Same LGPL-2.1 obligations as pySigma | MED |
| pySigma SQLite backend | **LGPL-3.0-only** (LICENSE + API) | DEPENDENCY / EXTERNAL_PROCESS; copying its code into our backend = creating a derivative | LGPL-3.0 obligations (source of the library, no additional restrictions); LGPL-3 vs LGPL-2.1 incompatibility with older components must be checked | MED–HIGH |
| SigmaHQ pipelines other than windows/sysmon (ossem, ocsf, rclinuxedr) | not fetched | not assigned | UNVERIFIED — fetch before use | — |
| YARA | BSD-3-Clause (`COPYING`) | DEPENDENCY / EXTERNAL_PROCESS | Permissive; retain notice | LOW |
| YARA-X | BSD-3-Clause (`LICENSE`) | DEPENDENCY (Rust) / EXTERNAL_PROCESS | Permissive; retain notice | LOW |
| yara-python | Apache-2.0 (LICENSE + PyPI metadata); bundles libyara (BSD-3) | DEPENDENCY | Permissive; notice retention for both | LOW |
| DuckDB | MIT (`LICENSE`) | DEPENDENCY (analytics/scratch, if needed) | Permissive | LOW |
| cti-python-stix2 | BSD-3-Clause (`LICENSE`) | DEPENDENCY (STIX 2.1 import) | Permissive | LOW |
| misp-stix | BSD-3-Clause (`pyproject.toml`) | DEPENDENCY (MISP↔STIX conversion, if needed) | Permissive | LOW |
| osquery | **Apache-2.0 OR GPL-2.0-only** (`osquery@d9db97e:LICENSE`); no OpenSSL exception | REFERENCE_ONLY in MVP (live agent out of scope); DEPENDENCY/EXTERNAL_PROCESS permissible by **electing Apache-2.0** | Election must be documented in our NOTICE; GPL branch avoided | LOW |
| Tetragon | Apache-2.0 (`LICENSE`); README BSD-2/GPL-2 badge scope UNVERIFIED | REFERENCE_ONLY (Linux live telemetry, out of scope) | None if not shipped | LOW |
| Falco engine + libs + plugins | Apache-2.0 (`COPYING`, `libs/COPYING`, plugin table) | EXTERNAL_PROCESS (customer-installed) / REFERENCE_ONLY | Apache requires notice preservation on redistribution; no source obligation | LOW |
| OpenSCAP | LGPL-2.1 (`COPYING`) | EXTERNAL_PROCESS (Linux-only customer install) / REFERENCE_ONLY | LGPL obligations only if we redistribute the binary | LOW–MED |
| ComplianceAsCode content | BSD-3-Clause (LICENSE) | DEPENDENCY (optional SCAP content pack) | Permissive | LOW |
| Suricata engine | GPL-2.0 (`suricata@215961d:LICENSE`) | **AVOID bundling**; EXTERNAL_PROCESS only if installed by customer under its own licence | Distributing the binary inside a closed-source product triggers GPLv2 source obligations for the combined distribution | HIGH |
| AIDE | GPL-2.0 (`COPYING`) | REFERENCE_ONLY (FIM semantics); EXTERNAL_PROCESS if customer-run | Same bundling risk as Suricata | MED |
| Wazuh manager/agent/ruleset | GPL-2.0-only + OpenSSL exception (`wazuh@v4.14.8/LICENSE` — applies to "decoders, rules and any other data file") | REFERENCE_ONLY; **AVOID** copying rules or code; EXTERNAL_PROCESS only as customer-installed third party | GPLv2 explicitly covers Wazuh detection content — no rule copying into closed-source product | HIGH |
| Wazuh indexer / dashboard (separate repos) | Apache-2.0 (LICENSE.txt each) | REFERENCE_ONLY (out of scope) | Permissive if ever used | LOW |
| OSSEC HIDS | GPL-2.0 (API + LICENSE) | REFERENCE_ONLY | Same as Wazuh | MED |
| Chainsaw | GPL-3.0 — `Cargo.toml:8` `license = "GPL3"` (non-SPDX), `LICENCE` GPLv3 text; **no root LICENSE file** | REFERENCE_ONLY (architecture lessons); EXTERNAL_PROCESS only if customer-run, unmodified, not bundled | GPLv3 adds patent + anti-tivoization terms; bundling in closed-source = AVOID. Licence string non-SPDX is itself a packaging defect to note | HIGH |
| Hayabusa code | **AGPL-3.0** (`LICENSE.txt`) | **AVOID** (dependency, bundling, modification); REFERENCE_ONLY for reading architecture | Sentinel is a network service: AGPL §13 can require releasing our service's modifications if we run modified AGPL code interacting with users | HIGH |
| Hayabusa rule corpus (`hayabusa-rules`) | DRL 1.1 (README: "detection rules are released under the Detection Rule License (DRL) 1.1") | DEPENDENCY (optional import pack) **with attribution obligations** — see §2.3 | Alerts generated from these rules must retain `author` attribution if supplied (DRL 1.1 condition) | MED |
| Zircolite | LGPL-3.0-or-later (`pyproject.toml`, LICENSE) | REFERENCE_ONLY (do not copy code); EXTERNAL_PROCESS if run unmodified | Reimplementing ideas (SQL prefilter, auto-mode) is fine; copying code creates LGPL-3.0 derivative | MED |
| Velociraptor | **AGPL-3.0** (`LICENSE`) | **AVOID**; REFERENCE_ONLY | Same AGPL network clause as Hayabusa; also Rapid7-owned (commercial) | HIGH |
| DeepBlueCLI | GPL-3.0 (LICENSE) | REFERENCE_ONLY | Hard-coded heuristics not importable | MED |
| MISP core | AGPL-3.0 (LICENSE) | **AVOID** (code); format study = REFERENCE_ONLY via `misp-rfc` spec | AGPL + PHP service code not usable in our stack | HIGH |
| elastic/detection-rules | **Elastic License 2.0** (`LICENSE.txt`) — verbatim limitation: "You may not provide the software to third parties as a hosted or managed service, where the service provides users with access to any substantial set of the features or functionality of the software." | **AVOID** for shipping rules; REFERENCE_ONLY for format study | Sentinel is exactly a hosted/managed service — serving substantial Elastic detection content is prohibited | HIGH |
| Sysmon / Autoruns / Sigcheck | Proprietary Microsoft freeware (no SPDX) | EXTERNAL_PROCESS (runs on customer machines; we do not redistribute) / REFERENCE_ONLY | Redistribution of MS tools not permitted without MS terms; collection is customer-side | MED |
| pySigma plugin directory JSON | repo licence UNVERIFIED | REFERENCE_ONLY until fetched | Data file used only for §5 counts (fetched, not redistributed) | LOW |

### 2.2 Detection content & data feeds

| Content | Licence (evidence) | Usage class | Commercial impact | Legal flag |
|---|---|---|---|---|
| Sigma specification v2.1.0 | Public domain (`sigma-specification@ba9251aa:LICENSE`) | DEPENDENCY (adopted as conformance spec) | None | LOW |
| SigmaHQ rule corpus (4063 active rules) | **DRL 1.1** (`sigma@8a481340:LICENSE`) | DEPENDENCY (default optional rule pack) | Free commercial use **subject to**: retain `author` field on shared rules **and** on match outputs ("messages based on matches with the Rules must retain … identification of the authors"), retain licence notice/URI. ⇒ our alert records MUST carry rule `author` end-to-end | MED (implementable) |
| Falco rule files | Apache-2.0 (LICENSE + SPDX headers) | DEPENDENCY (optional; only useful if Falco-format adapters land) | Notices only | LOW |
| Wazuh rules/decoders | GPLv2 incl. content (`wazuh@v4.14.8/LICENSE`) | **AVOID** (copying); REFERENCE_ONLY | Rule text is explicitly licensed code-equivalent | HIGH |
| Chainsaw native rules + mappings | GPLv3 (in-repo `rules/`, `mappings/`) | **AVOID**; REFERENCE_ONLY | See code row | HIGH |
| ET Open ruleset (Suricata) | Mixed: GPLv2 range + BSD range + ETPRO range (`…/open/suricata-5.0/LICENSE`) | **AVOID as a pack**; only BSD-range sids could be imported after per-sid audit (not done → UNVERIFIED) | GPLv2 sids cannot ship in closed-source product; ETPRO is commercial | HIGH |
| SwiftOnSecurity Sysmon config | CC-BY-4.0 claimed **only in XML file header**; no LICENSE file (UNVERIFIED repo-level) | REFERENCE_ONLY until verified | Attribution required if ever used; verification needed first | MED |
| sysmon-modular configs | MIT (`license.md`) | DEPENDENCY (config modules we derive from) | Notices only | LOW |
| abuse.ch Feodo CSV | CC0 (page ToS, `§IOC-10`) | DEPENDENCY (feed; currently empty) | None (data empty due to takedowns) | LOW |
| abuse.ch URLhaus CSV | Custom ToS; Auth-Key required for bulk (`§IOC-10`) | DEPENDENCY (feed, subject to ToS) | ToS compliance + key handling | MED |
| Elastic detection rules | ELv2 (see above) | **AVOID** | Hosted-service prohibition | HIGH |
| LIGHT-HIDS paper | No code released; facts are citations | REFERENCE_ONLY | Academic citation only | LOW |

### 2.3 Licence rules of engagement (binding for the coding agent)

1. **Never** copy rule text, config text, or source from: Wazuh, Chainsaw, Hayabusa code, Velociraptor, MISP, elastic/detection-rules, ET Open (GPLv2/ETPRO ranges), SwiftOnSecurity (unverified).
2. **Allowed content imports with conditions**: SigmaHQ rules (DRL 1.1 → persist rule `author` on every alert row and expose it in API/exports), sysmon-modular (MIT → notice), Falco rules (Apache → notice), ComplianceAsCode (BSD → notice), Feodo (CC0).
3. **LGPL components** (pySigma, pipelines, SQLite backend): prefer EXTERNAL_PROCESS (`sigma-cli` subprocess) during PoC to defer obligations; if used as a library, ship full licence text + a documented relink/replace procedure; never patch pySigma in place without releasing the modified library source.
4. Legal flags HIGH above require counsel sign-off **before** the component enters `pyproject.toml` or a default rule pack.

---

## 3. Capability Matrix

Rows = 11 capabilities that decide Sentinel's architecture. Columns = studied products (versions from §1). Cells: `Yes / Partial / No / Not studied` + evidence id (`§WAHUH-x`, `§FALCO-x`, … = companion research files; §1.1 #n = metadata-only row). OSSEC received no deep read (§1.1 #2); its cells are honestly `Not studied` except where a fetched source covers it.

| # | Capability | Wazuh 4.14.8 | OSSEC 4.4.0 | Falco 0.45.0 | Tetragon 1.7.1 | osquery 5.23.1 | Velociraptor 0.77.3 | Chainsaw 2.16.5 | Hayabusa 4.1.0 | Zircolite 4.2.0 |
|---|---|---|---|---|---|---|---|---|---|---|
| C1 | **Offline analysis of uploaded/historical files** (no live agent) | No — agent/manager live pipeline; "offline" docs = package install only (`§WAHUH-8`) | Not studied | Partial — replay of Falco's own `.scap` captures only, not EVTX (`§FALCO-3`) | No — live eBPF stream, no replay documented (`§TETRAGON-4`) | No — queries run against live OS; no archived-EVTX import (`§OSQUERY-4`) | **Yes** — import collection container, run artifacts on uploaded files, dead-disk remapping (`§VELOCIRAPTOR-3`) | **Yes** — EVTX/JSON/XML/MFT/registry/ESE inputs (`§CHAINSAW-3`, `§CHAINSAW-2`) | **Yes** — `.evtx` file/dir, JSON input, record carving (`§HAYABUSA-2`) | **Yes** — EVTX/JSON/XML/CSV/auditd/archives/prior SQLite (`§ZIRCOLITE-2`) |
| C2 | **Windows event-log / EVTX coverage** | Yes (live) — Windows event decoder queue, `winevt_threads` (`§WAHUH-2`) | Not studied | No — Linux-only syscall source; non-Linux sources UNVERIFIED (`§FALCO-3`) | No — Linux only; Windows = experimental CI (`§TETRAGON-3`) | Yes (live) — `windows_eventlog` / `windows_events` channels + manifest install (`§OSQUERY-5`) | Yes — `watch_evtx`, ETW artifacts (`§VELOCIRAPTOR-5`) | Yes (`§CHAINSAW-3`) | Yes — evtx pipeline + EID/channel filters (`§HAYABUSA-6`) | Yes — auto-detected formats incl. EVTX (`§ZIRCOLITE-2`) |
| C3 | **File integrity monitoring** | Yes — SQLite baseline, periodic + realtime; Windows local FS only since 4.13 (`§WAHUH-4`) | Not studied (ancestral FIM, no read) | Partial — file events from syscalls, no baseline diff (`§FALCO-3`) | Partial — kprobe file hooks via TracingPolicy, no baseline (`§TETRAGON-2`) | **Yes** — inotify / NTFS journal / FSEvents; observational, no enforcement (`§OSQUERY-2`) | Partial — ETW Kernel-File client-event artifact (`§VELOCIRAPTOR-5`) | No (offline hunter) | No (offline hunter) | No (offline hunter) |
| C4 | **Config assessment / compliance** | **Yes** — SCA YAML policies (own language, NOT OVAL/XCCDF) (`§WAHUH-3`, `§OPENSCAP-5`) | Not studied | No | No | Partial — compliance via SQL packs (`packs/it-compliance.conf`, `§OSQUERY-1`) | Partial — enumerable artifacts (INFERRED from `§VELOCIRAPTOR-2`) | No | No | No |
| C5 | **Rule format + validation tooling** | XML rules; `wazuh-logtest` validates without restart, manager restart needed to alert (`§WAHUH-1`, `§WAHUH-2`) | Not studied | YAML (rules/macros/lists/exceptions) + `-V` / `--dry-run` / `--rule-schema` (`§FALCO-1`, `§FALCO-2`) | YAML CRD `TracingPolicy`; lint tooling not studied | SQL queries/packs scheduled (`§OSQUERY-1`) | YAML artifacts wrapping VQL; 423 shipped (`§VELOCIRAPTOR-2`) | Native YAML + Sigma via mapping; `lint` verb (chainsaw/sigma/stalker) (`§CHAINSAW-2`, `§CHAINSAW-5`) | Sigma-style YAML + own keys; required-key validation (`§HAYABUSA-4`) | JSON ruleset **or** Sigma YAML converted at load with explicit skip/fail counts (`§ZIRCOLITE-4`) |
| C6 | **Sigma support incl. v2 correlation** | No — XML native; 5.x uses a different, XML-free content system (migration of custom XML rules unsupported, `§WAHUH-2`) | Not studied | No — own format | No | No | **Yes** — native `sigma()` evaluator + correlation subsystem (`§VELOCIRAPTOR-4`) | **Partial** — modifier allow-list, `count()` only, `timeframe` ignored, no correlation rules (`§CHAINSAW-6`) | **Yes** — v2 correlation across whole run; legacy aggregation = `count` only (`§HAYABUSA-7`) | **Yes** — full correlation set incl. correlations-of-correlations via pySigma SQLite backend 2 (`§ZIRCOLITE-5`) |
| C7 | **Cross-event / temporal correlation** | Yes — `frequency`/`timeframe`/`if_matched_sid`/`ignore` (`§WAHUH-1`) | Not studied | No cross-source correlation by design; first-match within source (`§FALCO-3`, `§FALCO-2`) | No temporal aggregation documented (`§TETRAGON-1`, `§TETRAGON-4`) | Partial — scheduled differentials, no rule windows (INFERRED from `§OSQUERY-1`) | Yes — VQL over rows/hunts + Sigma correlation (`§VELOCIRAPTOR-1`, `§VELOCIRAPTOR-4`) | Partial — aggregation state **per file**, not corpus-wide (`§CHAINSAW-6`) | Yes — run-wide windows, `timespan`, ordered stages (`§HAYABUSA-7`) | Yes — unified DB windows, `incomplete_window` reporting, evidence rows (`§ZIRCOLITE-5`) |
| C8 | **Linux runtime syscall telemetry (eBPF/kmod)** | Partial — rootcheck syscall checks only (`§WAHUH-5`) | Not studied | **Yes** — modern eBPF (default) / kmod drivers (`§FALCO-3`) | **Yes** — in-kernel eBPF filtering/enforcement (`§TETRAGON-1`) | Partial — audit subsystem for `process_file_events` only (`§OSQUERY-2`) | Partial — `watch_ebpf` plugin (`§VELOCIRAPTOR-5`) | No | No | No |
| C9 | **Detection evidence model** (raw event + severity + provenance) | Alerts carry rule level, decoded fields → `alerts.log`/`alerts.json` (`§WAHUH-2`) | Not studied | `output` string interpolating `%fields` + priority (`§FALCO-1`) | JSON event objects via log/gRPC (`§TETRAGON-1`) | Differential result rows (JSON) (`§OSQUERY-1`) | Artifact rows (`§VELOCIRAPTOR-2`) | `Detection` struct = full raw event + file path + Sigma metadata (id/logsource/tags/authors) (`§CHAINSAW-7`); outputs table/CSV/JSON/JSONL (`§CHAINSAW-8`) | Output **profiles** define evidence columns (`Timestamp/RuleTitle/Level/…/RuleID`) (`§HAYABUSA-3`) | Rule metadata + flattened event row; CSV formula-injection sanitisation (`§ZIRCOLITE-7`) |
| C10 | **Documented performance / scale figures** | None published; `wazuh-analysisd.state` provided *for self-benchmarking* (`§WAHUH-6`) | Not studied | None published; single-threaded hot path + metrics hooks documented (`§FALCO-7`) | None found (not studied) | None cited | **Yes** — server sizing: t2.large ≈ 10k endpoints; 2.5k endpoints ≈ 10–20% of one core (`§VELOCIRAPTOR-7`) | Third-party bench: 13.3 GB / 1.72 M events = 206.3 s, 338 MiB (`§CHAINSAW-10`) | Third-party bench: 13.3 GB = 518.8 s, 1 599 MiB; vendor 2023 numbers stale (`§HAYABUSA-10`) | Third-party bench (vendor harness): 13.3 GB = 104.8 s, 8 103 MiB (`§ZIRCOLITE-8`) |
| C11 | **Air-gapped deployment documented** | Yes — offline installation procedure (`§WAHUH-8`); ruleset/vuln-DB updates offline = UNVERIFIED | Not studied | Not studied | Not studied | Not studied | **Yes** — offline collectors write local containers (`§VELOCIRAPTOR-3`) | Yes by design — fully offline CLI (`§CHAINSAW-1`) | Yes by design — offline CLI (`§HAYABUSA-2`) | Yes by design — offline CLI, archives, DB reuse (`§ZIRCOLITE-2`) |

**Matrix-derived facts (INFERRED from the cells above):**

- **M1** No studied product combines offline file-upload analysis (C1) with Windows/EVTX depth (C2) and a modern Sigma-capable engine (C6) *inside the licence envelope from §2*. The offline hunters (Chainsaw/Hayabusa/Zircolite) match the workload but are AGPL/GPLv3/LGPL reference material; the permissive-licence platforms (Falco/Tetragon/osquery) are live-telemetry systems that do not ingest EVTX uploads. **This gap is Sentinel's product fit.**
- **M2** The only three *architectures* proven against tens-of-millions-of-events offline corpora are the hunters; the only published comparable numbers are Zircolite's harness (vendor-run, rule sets differ, `§ZIRCOLITE-8`) ⇒ any Sentinel performance claim starts as **PROPOSED - TO BENCHMARK** (§5 PoC).
- **M3** Correlation windows over a whole corpus (C7) are implemented by exactly three engines (Hayabusa run-wide, Zircolite unified-DB, Velociraptor VQL) — Chainsaw's per-file aggregation is the documented anti-pattern to avoid (`§CHAINSAW-6`).
- **M4** FIM (C3) and config assessment (C4) require a *live baseline* or a *running agent*; both are structurally incompatible with point-in-time file uploads ⇒ out of MVP scope (§4).

---

## 4. Minimum Viable Light-HIDS Scope

### 4.1 In scope (MVP)

| ID | Capability | Input (upload) | Detection path | Evidence base |
|---|---|---|---|---|
| MVP-1 | EVTX ingestion → canonical events | `.evtx` files (Windows Security, System, Application, PowerShell-Operational, Sysmon channels) | external Rust EVTX parser (process `evtx_dump` or our Rust helper built on `evtx` crate, §2.1) → canonical events → detector | `§EVTXLIB-1`, `§SYSMON-5` (channel `Microsoft-Windows-Sysmon/Operational`, export via `wevtutil epl`) |
| MVP-2 | Sigma detection pack (optional, default **empty**) | rule pack (SigmaHQ corpus under DRL 1.1, or customer rules) | engine per §5 decision; zero hardcoded detections ⇒ empty pack yields zero detections (invariant, test in CI) | §2.2, §5 |
| MVP-3 | PCAP analysis | `.pcap`/`.pcapng` | external TShark (field extraction) + Suricata `-r` offline replay **only if customer-installed** (licence §2.1) | `§SURICATA-2`, `§SURICATA-3` (EVE alert JSON ingested as canonical events) |
| MVP-4 | File content scanning | any uploaded file | external YARA/YARA-X process, rules from our own + DRL/permissive packs | `§YARA-1..5` |
| MVP-5 | Static analysis of endpoint exports | Autoruns CSV (`autorunsc -c`), Sigcheck CSV (`sigcheck -c -h`), Sysmon config XML | parsers → canonical events → detector; **static only** | `§SYSINTERNALS-6..8`, `§SYSMON-2` |
| MVP-6 | Evidence-preserving alerts | detections store: full canonical event + rule provenance (`repo@commit:path`) + rule `author` (DRL obligation §2.3) + original rule level **and** 3-level severity (never collapsed) + `COMPLETED_WITH_WARNINGS` partial status | — | `§CHAINSAW-7`, `§HAYABUSA-3`, `§ZIRCOLITE-7`, DRL 1.1 |
| MVP-7 | Batch job lifecycle | upload → parse → detect → report; background worker; per-stage timings | engine emits stage timing (model: Zircolite `--performance-json`) | `§ZIRCOLITE-3`, `§ZIRCOLITE-8` |
| MVP-8 | Benchmark harness (build in MVP, not optional) | synthetic + sample corpora (§5 PoC) | measures throughput/memory/conformance from day 1 | §5 |

Explicit non-goals for MVP: multi-tenant enablement (schema carries `tenant_id` from day 1 but UI/API is single-tenant), ML detection (see 4.3), live agents, dashboards, SOAR.

### 4.2 Out of scope (whole product, reaffirmed)

Live agents · kernel drivers / eBPF / ETW subscription · active response or blocking · FIM baselines (needs live host, matrix M4) · SCAP/OVAL/XCCDF compliance scanning (OpenSCAP Windows support void since 2022-02-01, `§OPENSCAP-2`; Wazuh SCA is its own YAML language, `§OPENSCAP-5`) · Kafka/Kubernetes · SOAR · cross-source live correlation · bundling GPL/AGPL engines (§2.1).

### 4.3 Deferred with rationale

| Item | Why deferred | Revisit trigger |
|---|---|---|
| LIGHT-HIDS ML detector | Paper requires **integer-mapped system-call name sequences**; collection mechanism, window length, vocabulary, and OS of training data are all UNVERIFIED/absent (`§LIGHT-HIDS-1..3`, `§LIGHT-HIDS-5` — paper never mentions Windows), and **no code/weights/data were released** (`§LIGHT-HIDS-6`). Feedstock (syscall traces) does not exist in our upload set | When a Windows-compatible syscall-trace collector is specified, or authors release code |
| Wazuh XML / Falco YAML as *first-class* import adapters beyond v1 | GPLv2 content (Wazuh) unusable; Falco engine not in our runtime path | Adapter demand proven by customers; format isolated from licensed content |
| osquery/Tetragon as data sources | Live-only (matrix C1/C2) — belong to a future agent product | Agent phase |
| Velociraptor-native artifact execution | AGPL code (§2.1) | Never as code; format study only |

### 4.4 Scale & status targets (all **PROPOSED - TO BENCHMARK** via §5 PoC)

| Target | Proposed value | Basis |
|---|---|---|
| Ingest corpus, benchmark run 1 | 10 M canonical events (≈ 1 × 478 MB Sysmon-class EVTX scaled up, or a 4 GB mixed set) | Comparable to public harness corpora (452 k and 1.72 M events, `§ZIRCOLITE-8`) extended ×6 |
| Ingest corpus, benchmark run 2 | 50 M events | Brief's "tens of millions of events" |
| Detection wall-clock (run 1, full SigmaHQ active pack) | ≤ 120 s on a stated 8-core/32 GB reference box | PROPOSED - TO BENCHMARK |
| Detection wall-clock (run 2) | ≤ 600 s | PROPOSED - TO BENCHMARK |
| Peak RSS, detection stage | ≤ 8 GB at 13.3 GB input class | Public best case is 8 103 MiB for Zircolite (`§ZIRCOLITE-8`); beat or match with streaming |
| Partial-success semantics | any parse/rule failure ⇒ job status `COMPLETED_WITH_WARNINGS`, never `SUCCESS`, never silent skip | Fixed product decision; mirrors Zircolite's explicit `[✓] Converted 245 rules (3 invalid skipped, 2 failed)` reporting (`§ZIRCOLITE-4`) |
| Empty rule pack | exactly 0 detections on any input | Fixed product decision (invariant) |

---

## 5. Rule-Engine Decision Record (RED-001)

**Status:** RECOMMENDED (pending §5.7 PoC) · **Date:** 2026-10-08 · **Scope:** the Sigma-compatible detection engine that evaluates canonical events. YARA (MVP-4) and Suricata (MVP-3) remain external processes and are *not* part of this decision.

### 5.1 Context (VERIFIED)

- Sentinel stores **canonical events in PostgreSQL**; detectors may only consume canonical events (fixed invariant). Detection runs in a background worker over uploads of **tens of millions of events**.
- The de-facto interchange rule language is Sigma (specification v2.1.0, public domain, `sigma-specification@ba9251aa:LICENSE`): rules YAML + detection selections + condition expressions + modifiers (`specification/sigma-appendix-modifiers.md`) + correlation rules of four types — `event_count`, `value_count`, `temporal`, `temporal_ordered`, with `group-by`/`timespan`/conditions and filters (`specification/sigma-correlation-rules-specification.md`).
- A **conformance corpus exists**: `tests/` and `json-schema/` trees in `sigma-specification@ba9251aa` (public domain) — usable directly as an acceptance suite.
- Rule supply: SigmaHQ corpus @`8a4813404e` = **4063 active rules** (levels: critical 192, high 1848, medium 1614, low 367, informational 30; statuses: test 3345, experimental 350, stable 105, deprecated 167, unsupported 84), licence **DRL 1.1** (§2.2).
- pySigma is a **conversion library, not an evaluator**: `Backend` ABC at `pySigma@50708bae:sigma/conversion/base.py:68`, abstract `convert()` at `:192` returns `Any` (backends emit SQL strings, KQL, AST nodes — whatever they like); condition AST model lives in `sigma/conditions.py`, correlation model in `sigma/correlations.py`. The public plugin directory (`raw.githubusercontent.com/SigmaHQ/pySigma-plugin-directory/main/pySigma-plugins-v1.json`, fetched 2026-10-08) lists **33 backends + 5 pipelines** — backends are SIEM query translators (splunk/kusto/loki/…); there is **no general-purpose "evaluate rules against a stream of events" backend** (a `dictquery` backend exists at `unqork-external/pySigma-backend-dictquery`; its maintenance/completeness is UNVERIFIED and it is not part of any verified path).
- The one verified end-to-end "compile Sigma → run on events" implementation is `pySigma-backend-sqlite` @`0173066875`: it compiles rules **and correlation plans** to SQL (`sigma/backends/sqlite/correlation.py`, runtime `execute_plan()` in `sigma/backends/sqlite/runtime.py`) and ships its own benchmark (`tools/benchmark_correlations.py`). It requires SQLite ≥ 3.38 JSON functions (`§ZIRCOLITE-5`).
- **Version skew (VERIFIED 2026-10-08):** pySigma released **v2.0.0 (2026-10-04, breaking)** while both the SQLite backend (`pyproject.toml`: `pysigma>=1.5.1,<2`) and Zircolite (`pyproject.toml:8-31`: `pysigma>=1.5.1,<2`) still pin `<2.0`. The SQL path cannot today run on pySigma 2.x.
- **Licence skew (VERIFIED):** pySigma = LGPL-2.1-only; pipelines `windows`/`sysmon` = LGPL-2.1 (LICENSE fetched 2026-10-08); SQLite backend = **LGPL-3.0-only** (§2.1). Copyleft obligations are MED–HIGH for a closed-source product (§2.3 rule 3).
- Native-evaluator reality check: mature native implementations are *partial*. Chainsaw supports exactly 7 modifiers (`chainsaw@af12749:src/rule/sigma.rs:264-277`), `count()` only, **silently ignores `timeframe`** (`sigma.rs:530-533`), has no correlation rules and aggregates **per input file** (`§CHAINSAW-6`). Hayabusa implements run-wide v2 correlation (`§HAYABUSA-7`) but its legacy aggregation is `count`-only (`aggregation_parser.rs:157-158`). Velociraptor maintains a dedicated evaluator subsystem (`velociraptor@fa9a5b4:vql/sigma/evaluator/`, `correlation.go`). ⇒ full spec compliance is a real engineering project in any language; it is *not* free with a parser library.
- Comparable offline-corpus timings (third-party harness, rule sets differ, `§ZIRCOLITE-8`/`§CHAINSAW-10`/`§HAYABUSA-10`), 13.3 GB / 1 720 377 events: **Zircolite (SQL-compile) 104.8 s / 8 103 MiB**; Chainsaw (native) 206.3 s / 338 MiB; Hayabusa (native) 518.8 s / 1 599 MiB. Treat as directional only — **PROPOSED - TO BENCHMARK** for Sentinel.

### 5.2 Options considered

| Option | One-line description | Evidence |
|---|---|---|
| **A** | pySigma-as-library: parse/validate/convert with pySigma (pinned `<2.0` initially) + **our own in-process evaluator** executing the parsed model over canonical events | parsed model exists (`pySigma@50708bae:sigma/conditions.py`, `sigma/correlations.py`); evaluation code still 100 % ours (`base.py:192` returns `Any`) |
| **B** | **Fully native**: our own parser + evaluator written from the public-domain spec + public conformance tests; zero Sigma-project code dependency | spec + `tests/` public domain (`sigma-specification@ba9251aa:LICENSE`); precedent: Chainsaw/Hayabusa/Velociraptor all wrote native evaluators (§5.1) |
| **C** | **Compile detections to SQL** executed in PostgreSQL where canonical events already live; correlation compiled to SQL plans (window functions / temp aggregates), model = SQLite backend 2's `execute_plan` design | `pySigma-backend-sqlite@0173066875` (`correlation.py`, `runtime.py`, benchmark tool); Zircolite architecture (`§ZIRCOLITE-3`, `§ZIRCOLITE-5`); timings §5.1 |
| **D** | Outsource to an external hunter (Zircolite/Chainsaw) as a subprocess on raw logs | **REJECTED as product path**: bypasses canonical events (violates fixed invariant) + LGPL-3/GPLv3/AGPL packaging risk (§2.1). Retained only as a **dev-time comparison oracle** in §5.7 |

### 5.3 Comparison

| Criterion | A (pySigma + our evaluator) | B (fully native) | **C (SQL compile)** |
|---|---|---|---|
| Licence exposure (§2.1) | LGPL-2.1 dep (MED): pySigma + pipelines, obligations if shipped as library | **None** — spec/tests public domain (LOW) | Backend LGPL-3.0 (MED–HIGH) if used as library; **clean if we write our own backend** and keep LGPL code out of the closed-source tree (PoC path C2, §5.5) |
| Spec coverage achievable | Same ceiling as B — we write all evaluation anyway; pySigma helps parsing/validation only | Full ceiling; conformance proven by public `tests/` | Full ceiling **if** SQL can express every construct; otherwise hybrid (see fallback) |
| Correlation (4 types + windows + ordered + correlations-of-correlations) | Must implement from scratch over Python row sets | Must implement from scratch | Already designed as *plans* in reference implementation (`execute_plan()`); maps naturally to SQL window/temp-table semantics (`§ZIRCOLITE-5`) |
| Performance at 10–50 M events (in Postgres) | Row-by-row Python over rows fetched from Postgres — weakest; needs coarse SQL pre-filter to be viable (INFERRED) | Same as A unless we push selections into SQL | **Strongest**: set-based, no event export, indexes/materialisations reusable; directionally consistent with §5.1 timings |
| Ecosystem stability | pySigma 2.0 broke API 4 days ago; pin `<2.0` (VERIFIED skew) | Immune to pySigma churn | Same pin risk during import-time conversion; **runtime SQL is ours** |
| Debuggability / explainability | Python debugger | Python debugger | `EXPLAIN`, stored per-rule SQL as evidence (precedent: Zircolite stores SQL per rule, `§ZIRCOLITE-4`); harder for regex/base64 constructs |
| Engineering effort (INFERRED, to be calibrated in §5.7) | Parser: reuse ≈ weeks; evaluator: weeks | Parser + evaluator + correlation: **6–10 weeks** | Converter + SQL dialect layer + correlation plans: **4–8 weeks** (reference implementation shortens design) |
| Keeps "detectors only consume canonical events" | Yes | Yes | Yes |
| Fallback cost if a rule can't compile | n/a | n/a | Needs path-B-style row evaluator for failures ⇒ C and B share conformance suite |

### 5.4 Decision

**DECIDE (RED-001): Option C as primary — compile canonical detections (Sigma and Sigma-shaped rules) to SQL executed against canonical events in PostgreSQL, with a mandatory native row-level evaluator as fallback for non-compilable rules and as the conformance oracle. Option B is the contingency engine if §5.7 thresholds fail. Option A is rejected as a standalone path (it pays the LGPL cost without buying evaluation code). Option D stays a dev-only oracle.**

Rationale: (i) it is the only option where the engine's workload (set membership, grouping, windows) lands in the store that already holds the events — no export, no second copy of tens of millions of rows; (ii) the correlation-plan design exists and is proven end-to-end (`§ZIRCOLITE-5`); (iii) licence: conversion-time use of LGPL tools can be done in an isolated converter service/CLI (§2.3 rule 3), while the shipped runtime can be **our own backend code** (path **C2**), removing LGPL from the product binary; (iv) the fallback row-evaluator is *required anyway* for constructs SQL can't carry, and doubles as the conformance oracle that keeps C honest (prevents the silent-compliance failure Chainsaw demonstrates).

Implementation fork to be settled by the PoC:

- **C1 — depend on `pysigma-backend-sqlite` (LGPL-3.0) as a library/CLI:** fastest to working state; ships LGPL obligations.
- **C2 — write our own Sigma→PostgreSQL backend**, using C1 only as a behavioural reference (no code copying; conformance judged by public `tests/`): slower; clean licence posture. **Default preference: C2**, with C1 permitted in the *PoC* only.

### 5.5 Fallback (trigger-based)

| Trigger | Action |
|---|---|
| PoC threshold T2 or T3 fails (§5.7) | Switch primary to **B**: native evaluator for all rules; SQL used only as coarse pre-filter (channel/EID/field indexes) — engine contract unchanged |
| Single rule fails to compile | Route that rule to the **native fallback evaluator** for the remainder of the job; record `detection_path: native` + reason code on every alert; job status `COMPLETED_WITH_WARNINGS` if fallback share > 0 |
| pySigma 2.x backends still pin `<2.0` at implementation start | Stay pinned `pysigma<2.0` for the converter; re-evaluate at first backend release supporting 2.x; **never** block runtime on pySigma (runtime consumes compiled SQL / our own parsed IR) |
| Dialect mismatch SQLite→PostgreSQL in reference material | Implement Postgres functions ourselves (ILIKE/case rules, JSONB access, timestamp windows); prove via conformance suite, not by copying |

### 5.6 Engine contract (normative for the coding agent)

1. Input: canonical rule documents (§6) + canonical events (§6) — nothing else.
2. Emits detections with: rule id, source provenance (`repo@commit:path`), rule `author` (DRL obligation), original rule level, 3-level severity, matched canonical event(s) (full), window info for correlations, `detection_path` (sql|native), compile/fallback reason codes.
3. Empty pack ⇒ zero detections; every non-matching rule is still *accounted for* (loaded / skipped-with-reason counts like `§ZIRCOLITE-4`).
4. Partial results ⇒ `COMPLETED_WITH_WARNINGS`.
5. No detection logic in parsers, no parsing logic in detectors (fixed invariant).

### 5.7 PoC experiment (exact protocol — results become §9 of implementation report)

**All thresholds below are PROPOSED - TO BENCHMARK.** Reference box to be recorded (target: 8 cores / 32 GB / local PostgreSQL, Python 3.12).

1. **Pin inputs:** SigmaHQ rules @`8a4813404e` (4063 active + 259 inactive as stress set); `sigma-specification` @`ba9251aa834b` (`tests/`, `json-schema/`); converter deps recorded exactly (`pysigma` resolved `<2.0`, `pysigma-backend-sqlite@0173066875` for reference runs).
2. **Conformance:** run the public `tests/` suite through the engine's **native evaluator** first (oracle), then through the **SQL path**; record pass/fail/unsupported per test case. *T1: 100 % pass on implemented constructs; unsupported constructs listed with reason codes — zero silent skips.*
3. **Compile rate:** convert all 4063 active rules. *T2: ≥ 95 % compile to SQL without fallback; each failure classified (modifier | condition form | correlation | other).*
4. **Event corpora:** (a) synthetic canonical events, seeded from documented Windows schemas (Security 4624/4625/4688/4720/1102; Sysmon 1/3/11/22 — field lists from `sysmon-events` docs, §1.2) at **N1 = 10 M** and **N2 = 50 M** rows, plus any real EVTX corpus supplied at implementation time (record provenance + licence); (b) same corpus re-parsed from source EVTX through MVP-1 to prove parse→detect round-trip.
5. **Cross-check (correctness):** run path C and fallback path B over N1 with the full pack; **detection sets must be equal** (rule id × event id). Any divergence = defect, not variance. *T3 (part a): zero unexplained divergences.*
6. **Performance:** 3 timed runs per path (cold cache + warm), report p50 wall-clock, peak RSS, SQL time vs fallback time split. *T3 (part b): C-primary is ≥ 3× faster than B-only at N1, and meets §4.4 wall-clock targets.*
7. **Licence gate:** decide C1 vs C2 by whether obligations of shipping LGPL-3.0 are accepted by counsel (§2.1 legal flag); C2 is the standing preference.
8. **Output:** `ENGINE_POC.md` containing every measured number (labelled MEASURED), the T1–T3 verdicts, fallback rate, and the final C1/C2 + C/B selection. If T2 or T3(b) fail ⇒ execute §5.5 row 1 (B primary).

### 5.8 Risks

| Risk | Evidence | Mitigation |
|---|---|---|
| Silent partial Sigma compliance | Chainsaw ignores `timeframe`, `count`-only, per-file aggregation (`§CHAINSAW-6`) | T1/T2 cross-check + per-rule `detection_path` + no-silent-skip rule (§5.6.3) |
| pySigma major-version churn | v2.0.0 breaking release vs `<2.0` pins (§5.1) | Converter pinned; runtime never imports pySigma |
| Copyleft creep into closed source | LGPL-2.1/LGPL-3.0/AGPL/GPLv3 inventory §2 | C2 default; §2.3 rules; counsel gate in PoC step 7 |
| SQL expressiveness gaps (base64offset, cidr, utf16/windash, regex) | Modifier appendix (`sigma-appendix-modifiers.md`); Chainsaw's allow-list shows real-world attrition (`§CHAINSAW-6`) | Fallback evaluator is first-class, not an error path |
| Performance claims unsourced | No vendor publishes Sentinel-class numbers; §5.1 harness is vendor-run | Every number ships as MEASURED from PoC step 6 only |

---

## 6. Canonical Rule Representation & v1 Import Adapters

Two canonical objects exist; **parsers produce them, detectors only consume them.**

### 6.1 Canonical event (storage + detector input)

> **SUPERSEDED (C-1-fix, Stage-8 round 1).** The sketch below is a pre-Stage-2 design sketch, retained for provenance only. The normative canonical-event envelope is `canonical_event_v1.schema.json` (`canonical-event/v1`), which supersedes this sketch in every detail — including the duplicate `event_id` key bug visible here (one uuid, one Windows EventID integer; the schema separates `event_id` from the envelope identity). File precedence: `canonical_event_v1.schema.json` > `schema.sql` > `openapi.yaml` > stage bodies.

PostgreSQL: `events` table, one row per source record; `tenant_id` on every row (multi-tenant-ready). JSONB payload keeps unknown fields losslessly (never drop raw data).

```jsonc
// canonical event — normative envelope
{
  "event_id": "uuid-v7",                  // sortable
  "tenant_id": "default",                 // present from day 1 (fixed decision)
  "upload_id": "uuid",                    // provenance: which upload produced it
  "source_format": "evtx",                // evtx | autoruns_csv | sigcheck_csv | sysmon_xml | pcap_eve | json | xml | csv
  "source_ref": "channel=Microsoft-Windows-Sysmon/Operational",  // channel/tool + file path inside upload
  "event_time": "2026-10-08T09:14:22.031Z",   // UTC, from source (Sysmon: TimeCreated SystemTime, §SYSMON-2)
  "ingest_time": "2026-10-08T10:02:11.442Z",
  "channel": "Microsoft-Windows-Sysmon/Operational",
  "provider": "Microsoft-Windows-Sysmon",
  "event_id": 1,
  "record_id": 123456,                    // EventRecordID; used for gap analysis (cf. Chainsaw analyse gaps, §CHAINSAW-2)
  "computer": "HOST01",
  "classification": "internal",           // DATA CLASSIFICATION LEVEL 1 of 3 — see §6.4
  "fields": {
    // canonical field taxonomy — flat, lowercase, dotted namespaces:
    "process.image": "c:\\windows\\system32\\cmd.exe",
    "process.command_line": "cmd.exe /c whoami",
    "process.parent_image": "c:\\program files\\...",
    "process.guid": "{...}", "process.pid": 4321, "process.parent_pid": 1000,
    "user.name": "alice", "user.domain": "CORP", "user.sid": "S-1-5-21-...",
    "file.path": "C:\\Temp\\a.exe", "file.hash.sha256": "...", "file.size": 12345,
    "registry.path": "HKLM\\...", "registry.value": "...",
    "network.src_ip": "10.0.0.5", "network.dst_ip": "93.184.216.34",
    "network.dst_port": 443, "network.protocol": "tcp",
    "dns.query": "evil.example",
    "raw": { }                            // unmapped EventData keys, lossless
  },
  "raw_ref": "s3://…/original.evtx#rec=123456"  // pointer back to raw bytes
}
```

Field-name mapping evidence: Chainsaw's mapping file (`from`/`to`/`visible`, EVTX attribute separation `chainsaw@af12749:mappings/sigma-event-logs-all.yml`, `src/file/evtx.rs:20`), Hayabusa's `eventkey_alias.txt` + `data_mapping/*.yaml` (`§HAYABUSA-5`), Zircolite's `config/config.yaml` `mappings`/`alias` blocks (`§ZIRCOLITE-6`). **Rule of the house:** aliasing lives in *one* mapping layer (import adapters), never inside detectors.

### 6.2 Canonical rule document (detector input, storage: `rules` table)

```yaml
# canonical rule — normative shape (values below are the normalized form of the real
# SigmaHQ rule proc_creation_win_7zip_exfil_dmp_files.yml @8a4813404e — every field verifiable)
schema: sentinel-rule/v1
id: 9f1c2e8a-...                       # our uuid (stable across reimports)
source: sigma                           # sigma | falco | yara | suricata | wazuh | native
source_id: ec570e53-4c76-45a9-804d-dc3f355ff7a7   # upstream Sigma rule id (verbatim)
source_ref: "SigmaHQ/sigma@8a4813404e:rules/windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml"
source_spec: "sigma-spec/2.1.0"         # which spec version it was parsed against
license: DRL-1.1                        # from §2; drives attribution obligations
author: "Nasreddine Bencherchali (Nextron Systems)"   # DRL 1.1: persisted to every alert (§2.3)
title: "7Zip Compressing Dump Files"
description: "Detects execution of 7z in order to compress a file with a .dmp/.dump extension…"
status: test                            # stable|test|experimental|deprecated|unsupported (verbatim upstream)
level_original: medium                  # VERBATIM upstream level — never rewritten
severity: MEDIUM                        # one of exactly 3 levels: LOW|MEDIUM|HIGH — never collapsed (§6.4)
logsource:
  category: process_creation
  product: windows
tags: ["attack.collection", "attack.t1560.001"]   # ATT&CK ids preserved (§CHAINSAW-6, §HAYABUSA-7)
detection:
  # normalized predicate AST — modifiers already resolved to canonical ops
  selection_img:
    - { field: process.description, op: contains, value: "7-Zip" }
    - { field: process.image, op: endswith, value: ["\\7z.exe", "\\7zr.exe", "\\7za.exe"] }
    - { field: process.original_filename, op: in, value: ["7z.exe", "7za.exe", "7zr.exe"] }
  selection_extension:
    - { field: process.command_line, op: contains, value: [".dmp", ".dump", ".hdmp"] }
  condition: "all of selection_*"        # upstream condition, kept verbatim
correlation: null                      # or { type, rules: [ids], group_by: [...], timespan: "5m", condition: {...} }
enabled: true
provenance: { imported_at, imported_by, repo_commit: "8a4813404e" }
compile:
  detection_path: null                 # sql | native — filled by engine (§5.6)
  sql: null                            # compiled artifact, stored as evidence
  fallback_reason: null
```

Non-negotiables encoded above: **(a)** `level_original` and `severity` are separate columns — upstream granularity is preserved while the product exposes exactly three levels; **(b)** `source_ref` at `repo@commit:path` granularity (traceability rule of this stage); **(c)** `author` flows to alerts (DRL 1.1: match outputs must retain author identification — §2.2); **(d)** compiled SQL stored per rule as evidence (precedent `§ZIRCOLITE-4`).

### 6.3 v1 import adapters

| Adapter | Parses | Maps to | Known-unsupported in v1 (explicit reason codes, never silent) | Evidence |
|---|---|---|---|---|
| **Sigma v1/v2** (primary) | Sigma rules YAML incl. correlation rules, spec 2.1.0 | detection AST + correlation block (§6.2) | modifiers outside appendix list ⇒ `UNSUPPORTED_MODIFIER` (mirrors Chainsaw's allow-list approach but *reported*, not fatal-only); `compare`/`fieldref`/time-range modifiers routed to native path first | `specification/sigma-rules-specification.md`, `sigma-appendix-modifiers.md`, `§CHAINSAW-6` |
| **Falco** | rules + macros + lists + exceptions YAML | macros/list expansion at import → detection AST; `priority` → severity map; `output` template kept as alert template | `source`-scoped events we don't ingest (`k8s_audit`, cloud) ⇒ `OUT_OF_SCOPE_SOURCE`; engine-version gates honoured via `required_engine_version` | `§FALCO-1`, `§FALCO-2` |
| **YARA** | `.yar` rules | **not converted**: registered as `source: yara`, executed by external YARA/YARA-X process (MVP-4); canonical *file* events are its input | condition semantics remain YARA's (no AST translation) | `§YARA-1`, `§YARA-3` |
| **Suricata** | `.rules` | `source: suricata`, executed by external Suricata `-r` (MVP-3); EVE alerts ingested as canonical events with `fields.raw.alert.*` | engine-side only; sid ranges / TLS rules untouched | `§SURICATA-1..3` |
| **Wazuh XML** | `<group><rule>` trees | `if_sid` chains → condition graph, `level` → severity, `frequency/timeframe` → correlation draft | CDB `<list>` lookups ⇒ `UNSUPPORTED_CDB`; decoders are *out* (parsers own format understanding, not detectors); GPLv2 rule text **never stored** — adapter is for customer-owned rules only (§2.2) | `§WAHUH-1`, §2.1 |
| **Sysmon config XML** (not a rule) | `<EventFiltering>` include/exclude filters | telemetry-profile object (what the customer collects) — used to validate coverage expectations, not to detect | conditions `less/more than` VERIFIED; `image` matches full path or bare image name → path-tail match with `PARTIAL_CONDITION` (INFERRED, `§SYSMON-2`) | `§SYSMON-2` |

Import outcome per rule is always one of `OK | OK_PARTIAL(fallback) | REJECTED(reason_code)` with counts surfaced (pattern: Zircolite's `[✓] Converted 245 rules (3 invalid skipped, 2 failed)`, `§ZIRCOLITE-4`).

### 6.4 The three classification levels (never collapsed)

> **Naming note (C-2-fix, Stage-8 round 1).** The `alerts.*` column references below (and the "alert records" phrasing in MVP-6 / the engine contract) realize as the **`findings`** table delivered in Stage-6 `schema.sql` (D6-001 lineage). Same semantics, storage name `findings`; `alerts` is the superseded conceptual name. The OpenAPI `Finding` schema is the API projection of that table.

Interpretation adopted for this stage (flagged for confirmation in §8 OPEN_QUESTIONS):

| Level type | Values | Where stored | Rule |
|---|---|---|---|
| **Detection severity (product-facing)** | exactly `LOW`, `MEDIUM`, `HIGH` | `alerts.severity` | mapped from upstream (`informational|low→LOW`, `medium→MEDIUM`, `high|critical→HIGH`); never merged into one bucket, never dropped |
| **Upstream rule level (fidelity)** | Sigma's five (`informational…critical`) or tool-native (Falco priority, Wazuh 0–16) | `alerts.level_original` | verbatim; feeds sorting/tuning; independent of severity |
| **Data classification (payload sensitivity)** | `public`, `internal`, `restricted` | `events.classification` (envelope §6.1) + inherited by alerts | set by parser per source (e.g. Security log EVTX ⇒ `restricted`); drives export/redaction policy |

These are three *different axes* and must never be collapsed into a single enum — storage, API and exports keep them distinct (fixed product decision; concrete axis naming is my interpretation → §8).

### 6.5 Engine boundary (recap)

Parsers: EVTX/CSV/XML/PCAP → canonical events (§6.1). Detectors: canonical events + canonical rules → alerts (§5.6). Native tools (evtx parser, TShark, YARA, Suricata) are isolated external processes whose stdout is parsed *as data*, never imported as code or rules-by-execution.

---

## 7. Lessons — 3 adopt / 3 avoid per tool

Evidence format: `repo@commit:path[:line]` (commits from §1). "Adopt" = copy the *idea* into Sentinel's design; "Avoid" = documented defect or hazard not to reproduce.

### 7.1 Chainsaw (`WithSecureOpenSource/chainsaw@af12749f6d0acdcfa274efce2643b5399b9ca8d1`)

**ADOPT**
1. **Explicit modifier allow-list with contextual failure** — supported modifiers enumerated in one place (`chainsaw@af12749:src/rule/sigma.rs:264-277`) and any unknown modifier fails with rule context (`src/rule/sigma.rs:279-287`) instead of mis-evaluating. Sentinel keeps this *and* converts the hard-fail into a per-rule `UNSUPPORTED_MODIFIER` status (§6.3) so one bad rule can't sink an import.
2. **A single mapping layer between raw event shape and rule fields** — `mappings/sigma-event-logs-all.yml` separates `kind: evtx`, preconditions (`extensions.preconditions` = Provider/EID pre-filters), `exclusions`, and `fields:` `from`/`to`/`visible` triples (`mappings/sigma-event-logs-all.yml:1-10`, `:333`), with EVTX attribute separation applied at parse (`src/file/evtx.rs:20`, `:38`, `:55`). This is exactly §6.1's one-alias-layer rule (evidence also for pre-filter design: skip events by channel/EID before heavy work).
3. **Whole-raw-event evidence on every detection** — `Detection` struct serialises with flattened `kind`/`name`/`level`/`source` + Sigma metadata, and `Document.data` carries the complete event + source path (`chainsaw@af12749:src/cli.rs:980-1009`, `src/hunt.rs:83-105`). MVP-6 requires the same (alert row ⇒ full canonical event + `raw_ref`).

**AVOID**
1. **Silently ignored spec semantics** — `timeframe` is skipped with `// TODO: Ignore for now as this would make the aggregator more complex…` (`chainsaw@af12749:src/rule/sigma.rs:530-533`) while only `count(` parses (`:372-385`). Rules "load successfully" but mean something else — the exact failure mode T1/T2 in §5.7 exists to catch.
2. **Per-file (not corpus) aggregation state** — aggregator state is created inside `hunt()` (`src/hunt.rs:788`) and `hunt()` runs once per input file (`src/main.rs:811`), so a "3 failures in 2m" rule can never see across files. Violates any batch-corpus product; Sentinel windows must span the whole job (precedent: Zircolite unified DB `§ZIRCOLITE-5`, Hayabusa run-wide `§HAYABUSA-7`).
3. **Silent rule exclusions living in a side file** — 16 Sigma titles are refused by an `exclusions:` list inside the mapping (`mappings/sigma-event-logs-all.yml:6-21`) with no load-time report. Sentinel: every exclusion/rejection is counted and shown (`§ZIRCOLITE-4` reporting style; §5.6.3).

### 7.2 Hayabusa (`Yamato-Security/hayabusa@19a1d1db87831e976170395051c8dbc7d6c939eb`, rules `hayabusa-rules@18afcb376e13e965037b2fc12c1e3470bc5e333d`)

**ADOPT**
1. **Run-wide Sigma v2 correlation** — correlation rules reference child rules by id/title/name, support `eq/lte/gte/lt/gt` conditions, `group-by`, `timespan`, and aggregate across the *entire* run (`hayabusa@19a1d1:src/detections/rule/correlation_parser.rs`; real rule: `hayabusa-rules@18afcb3:hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml:15-33`). This is the semantic target for §5 correlation plans.
2. **Rule-volume / false-positive controls as first-class config** — `--min-level`/`--exact-level`, include/exclude `--status`/`--tag`/`--category`, `--eid-filter`, and file-driven deny/noisy/proven lists (`hayabusa@19a1d1:src/detections/configs.rs:1507-1672`, `src/filter.rs:22-58`). Sentinel exposes the same knobs per job (noise suppression without editing packs).
3. **Output profiles as data, not code** — `config/default_profile.yaml` defines evidence columns (`Timestamp/RuleTitle/Level/Computer/Channel/EventID/RecordID/Details/ExtraFieldInfo/RuleID`) with named variants in `config/profiles.yaml` (`hayabusa@19a1d1:config/`). MVP-6 report columns become configuration; adds/removes never touch engine code.

**AVOID**
1. **Partial spec support sold as full support** — legacy aggregation is deliberately `count`-only (`hayabusa@19a1d1:src/detections/rule/aggregation_parser.rs:157-158`) while the README claims "the only open-source tool with full Sigma support, including v2 correlation rules" (`README`, marketing). Sentinel states coverage as measured conformance numbers (PoC T1/T2), never as adjectives.
2. **AGPL-3.0 code** (`hayabusa@19a1d1:LICENSE.txt`, §2.1) — lessons only; the implementation, its rule corpus structure beyond DRL-licensed content, and its binaries stay out of the product. Rule *content* may be imported under DRL 1.1 with attribution (§2.2).
3. **Stale performance claims presented as current** — headline numbers live in `OLD-README.md:1732-1739` (2023, Lenovo P51) and speed anecdotes at `OLD-README.md:1214-1218`. Sentinel: perf claims exist only as measured outputs of the MVP-8 harness (§4.4, §5.7 step 6).

### 7.3 Zircolite (`wagga40/Zircolite@a575d5fe1bd704bf4d9604b5d327aa53c8bf20f2`)

**ADOPT**
1. **Detection-as-compiled-SQL with layered pre-work** — rules execute as SQL over an events DB (`zircolite@a575d5:docs/Usage.md:960-964`), preceded by channel/EID event filtering (`zircolite/rules.py:98-404`, `config/config.yaml` `event_filter`), a literal prefilter over rule-referenced `LIKE` fields (identical detections with it on/off, `docs/Usage.md:451-455`), auto-indexing of the top-N filtered columns (`:393-396`), and `--performance-json` stage timings (`:436-449`). This layered design *is* RED-001 (§5.4) plus MVP-7 instrumentation.
2. **Unified database mode for correlation across files** — when correlation rules are loaded, all inputs go into one DB "whatever auto mode would have chosen" (`zircolite@a575d5:docs/Usage.md:1070-1078`) with window semantics `[t-timespan, t]`, ordered stages requiring strictly increasing timestamps, absence conditions waiting out the window, and open windows reported `incomplete_window` (`:1048-1056`). Sentinel's worker materialises one detection workspace per job for exactly this reason.
3. **CSV export hardening** — values with leading `=`, `+`, `-`, `@` or tab get a quote prefix "so a logged string cannot execute as a formula", with the explicit rule "Use JSON when you need the values exactly as stored" (`zircolite@a575d5:docs/Usage.md:567-586`). Mandatory for MVP-6 exports.

**AVOID**
1. **Dependency pin drift** — `pysigma>=1.5.1,<2` and `pysigma-backend-sqlite>=2.0.0,<3` in `zircolite@a575d5:pyproject.toml:8-31` mean the detection core cannot move to pySigma 2.x until upstream backends do (§5.1 skew). Sentinel isolates conversion (§5.5 row 3) so runtime never inherits this pin.
2. **Unbounded correlation cost** — "A correlation builds indexed temporary tables from the whole events table… `--limit` discards a rule with too many alerts, but the work to find them is already done" (`zircolite@a575d5:docs/Usage.md:1083-1088`). Sentinel pushes thresholds/windows into SQL predicates and enforces per-rule work budgets before execution.
3. **Memory ceiling set by process-tree totals** — 8 103 MiB peak on the 13.3 GB corpus, with benchmark methodology noting memory "covers the whole process tree" for worker processes (`zircolite@a575d5:docs/Benchmark.md`, `§ZIRCOLITE-8`). §4.4 sets RSS targets; the worker streams (or spills to disk) rather than buffering whole corpora — Chainsaw's `--cache-to-disk` trade-off (`chainsaw@af12749:src/main.rs:811-825`) is the pattern reference.

### 7.4 Wazuh (`wazuh/wazuh`, rules cited at tag `v4.14.8`, tree `7c901686a30c…` on main)

**ADOPT**
1. **Layered rule trees that survive upgrades** — default `ruleset/rules` is overwritten on upgrade while custom rules live in `etc/rules` with ID range guidance 100000–120000 and `overwrite="yes"` for overrides (`§WAHUH-2`, docs `ruleset/rules/custom.html`). Sentinel: immutable vendor packs + versioned customer packs in DB, never file-mutation-in-place (our equivalent of "upgrade clobbering" is an import version bump).
2. **Built-in self-benchmarking instrumentation** — `wazuh-analysisd.state` reports `events_processed`, per-source `*_edps`, `events_dropped`, and queue usage/size pairs refreshed every 5 s, documented explicitly "when benchmarking our Wazuh manager analysis engine in highly loaded environments" (`§WAHUH-6`, docs `statistics-files/wazuh-analysisd-state.html`). MVP-7 job stats mirror this: per-stage counts, queue/backpressure, drops — never guess throughput (nobody publishes Wazuh EPS numbers, `§WAHUH-6`).
3. **Declarative check-policy shape (SCA YAML)** — `policy`/`requirements`/`variables`/`checks` with `condition: all|any|none`, typed rule strings (`f:`/`d:`/`p:`/`c:`/`r:`), `regex_type: pcre2|osregex` (`§WAHUH-3`) is a clean template for any future *content* language we design (config assessment stays out of MVP, §4.2, but the YAML discipline informs §6).

**AVOID**
1. **Copyleft detection content** — `LICENSE` states the licence "applies to the source code, as well as decoders, rules and any other data file included with Wazuh" (`wazuh/wazuh@v4.14.8:LICENSE`, `§WAHUH-7`). Never copy a Wazuh rule/decoder into Sentinel (§2.2); the XML adapter (§6.3) accepts only customer-authored rules.
2. **Mutable-by-default shipped trees + restart-to-apply** — edits under `ruleset/rules` are clobbered on upgrade and "you need to restart the Wazuh manager to generate alerts based on these changes" (`§WAHUH-2`). Sentinel: rules are DB rows with `enabled`, per-job activation, immediate effect — no restart semantics, no on-disk mutation.
3. **Proprietary-format lock-in across versions** — Wazuh 5.x cannot migrate 4.x XML rules: "You cannot migrate custom Wazuh 4.x rules and decoders in XML format to Wazuh 5.x. Recreate the required detection content…" (`§WAHUH-2`, migration doc), and the 5.x engine's equivalence is UNVERIFIED. Lesson: Sentinel's canonical rules (§6.2) stay *Sigma-shaped and spec-versioned* (`source_spec`) so content survives engine rewrites; we never invent an unexportable house language.

### 7.5 Falco (`falcosecurity/falco@b608d820c8a3…` master; rules `falcosecurity/rules@21ef6d5f5fdd…`)

**ADOPT**
1. **Engine/content version gating + self-describing rule files** — `required_engine_version` / `required_plugin_versions` with documented load behaviour when too new, rules/macros/lists/exceptions as three element types (`§FALCO-1`; `falco_rules.yaml@21ef6d5f` header `- required_engine_version: 0.57.0`). Sentinel stores `source_spec` per rule (§6.2) and refuses loads against a newer spec than the engine implements — with a `REJECTED(reason)` row, not a crash.
2. **Validation-first CLI surface** — `-V/--validate`, `--dry-run`, `--rule-schema`/`--config-schema`, `-L`/`-l` rule introspection, `--support` dump (`§FALCO-2`, docs CLI page). Sentinel ships `rules lint` / `rules test` (Chainsaw's `lint` verb agrees: `chainsaw@af12749:src/main.rs:196`) before any pack can be enabled — enforces the empty-pack/zero-detection invariant's complement: *invalid packs never half-load*.
3. **Ordered loading + explicit override/enable semantics** — `rules_files` order matters, later files override, first-match-wins guidance, `append` key to extend without redefining, and post-load enable/disable by name/tag (`§FALCO-2`). Sentinel's pack model gets deterministic ordering + `enabled` + override rules recorded in `provenance` (§6.2).

**AVOID**
1. **A live-only, single-OS data path** — native source is Linux syscalls via drivers; replay only reads Falco's own `.scap` (`§FALCO-3`), and the README scopes it as "a cloud native runtime security tool for Linux" (`§FALCO-3`). Building Sentinel around a *stream* assumption would make uploads second-class; the engine is batch-first over files by design (§4.1).
2. **Source isolation that forbids cross-source correlation** — "Falco does not support correlating events from different sources" (`§FALCO-3`). Sentinel's uploads deliberately mix sources (EVTX + Autoruns CSV + Sigcheck CSV + EVE alerts, §4.1); canonical events must stay joinable (job-scoped detection workspace, §7.3 item 2).
3. **Breaking rule-semantics changes at engine upgrades** — v0.45.0 "evaluate rule conditions on raw field bytes… rules that matched the replacement character with non-regex operators must be reviewed", `FALCO_ENGINE_VERSION` 0.62.0→0.63.0 (`§FALCO-5`, CHANGELOG). Sentinel treats engine upgrades as conformance events: re-run the public `tests/` suite + full-pack compile (§5.7) before shipping, and pin `source_spec` on every rule.

---

## 8. DECISIONS / OPEN_QUESTIONS / NOT_VERIFIED

### 8.1 DECISIONS

```yaml
# Stage 1 decisions — Sentinel (compiled 2026-10-08)
decisions:
  - id: D-001
    decision: >-
      Evidence base for Stage 1 = 4 companion research files in this workspace +
      verification metadata (34 repo rows + 12 non-repo sources) + 2 delegated
      reports (LIGHT-HIDS; Sysmon/Sysinternals). Claims outside them are labelled
      INFERRED or UNVERIFIED.
    status: ACCEPTED
    evidence: [§1, §1.2]
    confidence: high

  - id: D-002
    decision: >-
      Product-fit gap (matrix M1): no studied product combines offline file-upload
      analysis, Windows/EVTX depth, and a modern Sigma engine inside a
      commercially usable licence envelope. Sentinel pursues exactly that gap.
    status: ACCEPTED
    evidence: [§3 C1/C2/C6, §2]
    confidence: high

  - id: D-003
    decision: >-
      MVP scope frozen as MVP-1..MVP-8 (EVTX ingest, Sigma pack, PCAP/TShark+Suricata,
      YARA scan, endpoint-export static analysis, evidence-preserving alerts,
      staged job lifecycle, benchmark harness). FIM, SCAP/SCA, live agents,
      LIGHT-HIDS ML explicitly out/deferred with triggers.
    status: ACCEPTED
    evidence: [§4.1, §4.2, §4.3]
    confidence: high

  - id: D-004
    decision: >-
      RED-001 rule-engine: Option C primary (compile detections to SQL executed on
      canonical events in PostgreSQL; correlation as compiled plans), mandatory
      native row-level evaluator as fallback + conformance oracle; Option B
      (fully native) is the contingency if PoC thresholds T2/T3 fail; Option A
      rejected standalone; Option D (external hunter) dev-oracle only.
    status: RECOMMENDED_PENDING_POC   # thresholds in §5.7
    evidence: [§5.1, §5.3, §5.4, §5.5]
    confidence: medium-high
    poc_gate: >-
      ENGINE_POC.md — T1 100% conformance on implemented constructs;
      T2 >=95% SQL compile rate; T3 zero path divergences + >=3x speedup at N1

  - id: D-005
    decision: >-
      Shipped runtime must not embed LGPL/GPL/AGPL code: converter tooling runs
      isolated (C1 acceptable in PoC only); standing preference is C2 = our own
      Sigma-to-PostgreSQL backend, judged against the public conformance suite.
    status: ACCEPTED
    evidence: [§2.1, §2.3, §5.4 C1/C2]
    confidence: high
    legal_gate: counsel review of LGPL-3.0 (MED-HIGH flag) before dependency freeze

  - id: D-006
    decision: >-
      Canonical event envelope + canonical rule document (sentinel-rule/v1) fixed
      as normative; aliasing lives in one import layer; compiled SQL stored per
      rule as evidence; tenant_id on every row from day 1.
    status: ACCEPTED
    evidence: [§6.1, §6.2, §5.6]
    confidence: high

  - id: D-007
    decision: >-
      Three classification axes kept separate and never collapsed:
      alerts.severity (LOW|MEDIUM|HIGH), alerts.level_original (upstream verbatim),
      events.classification (public|internal|restricted).
    status: ACCEPTED_INTERPRETATION   # axis naming confirmed via OPEN_QUESTIONS Q1
    evidence: [§6.4]
    confidence: medium

  - id: D-008
    decision: >-
      v1 adapters: Sigma (primary, incl. correlation), Falco, YARA, Suricata,
      Wazuh-XML (customer-owned rules only), Sysmon config (telemetry profile, not
      detection). Every unsupported construct produces an explicit reason code;
      silent skips forbidden.
    status: ACCEPTED
    evidence: [§6.3, §7.1 item 3]
    confidence: high

  - id: D-009
    decision: >-
      Licence rules of engagement (§2.3) binding: no copying from Wazuh/Chainsaw/
      Hayabusa-code/Velociraptor/MISP/Elastic/ET-GPL-range/SwiftOnSecurity;
      allowed imports = SigmaHQ rules (DRL 1.1 w/ author carried to alerts),
      sysmon-modular (MIT), Falco rules (Apache-2.0), ComplianceAsCode (BSD-3),
      Feodo (CC0); HIGH legal flags need sign-off before dependency freeze.
    status: ACCEPTED
    evidence: [§2.1, §2.2, §2.3]
    confidence: high

  - id: D-010
    decision: >-
      Performance truth policy: no throughput/memory number ships unless produced
      by the MVP-8 harness (protocol §5.7; targets §4.4). Public third-party
      numbers are directional context only (labelled PROPOSED - TO BENCHMARK).
    status: ACCEPTED
    evidence: [§4.4, §5.1, §7.2 avoid-3]
    confidence: high

  - id: D-011
    decision: >-
      Architecture lessons adopted as named principles: one alias layer
      (Chainsaw), run-wide correlation + profiles + FP knobs (Hayabusa),
      layered prefilter/unified workspace/CSV hardening (Zircolite), layered rule
      trees + self-benchmark stats (Wazuh), version gating + validation-first CLI
      + ordered override semantics (Falco).
    status: ACCEPTED
    evidence: [§7.1..§7.5]
    confidence: high

  - id: D-012
    decision: >-
      Job status semantics: any partial parse/convert/execute => COMPLETED_WITH_WARNINGS
      (never SUCCESS, never silent drop); empty rule pack => exactly zero detections;
      parse errors keep original bytes reachable via raw_ref.
    status: ACCEPTED
    evidence: [§4.4, §5.6]
    confidence: high
```

### 8.2 OPEN_QUESTIONS (unanswered — must be resolved during implementation or by brief-owner confirmation)

1. **Q1 — "Three classification levels" axis:** I interpreted the fixed decision as *three separate non-collapsible axes* (severity / upstream level / data classification, §6.4). Is the intended meaning instead one 3-value enum (e.g. benign/suspicious/malicious, or public/internal/restricted alone)? Affects schema D-007.
2. **Q2 — PoC thresholds:** are T1 = 100 %, T2 = ≥95 %, T3 ≥3× acceptable as go/no-go, or does the brief specify its own numbers?
3. **Q3 — C1 vs C2 licence gate:** counsel must decide whether shipping the LGPL-3.0 SQLite backend (as library/CLI) is acceptable, or whether C2 (own backend, no LGPL runtime) is mandatory.
4. **Q4 — Benchmark corpus:** do we have a real, licence-clean EVTX corpus (tens of millions of events), or is the synthetic generator (§5.7 step 4) the only input? Synthetic distributions risk flattering the engine.
5. **Q5 — OSQUERY-7:** the original brief's OSQUERY-7 wording was never re-checked this stage; offline/historical nuances are covered by `§OSQUERY-4/5` — confirm no separate question remains.
6. **Q6 — Suricata in MVP-3:** ship as "customer-installed external process" (GPL-safe path) or drop from MVP and ingest EVE alerts only? Depends on target deployment model.
7. **Q7 — DRL attribution surface:** exactly which fields/exports must show rule `author` to satisfy DRL 1.1 (§2.2)? Alert detail page only, or every CSV/JSON export + API?
8. **Q8 — Wazuh XML adapter:** keep in v1 (customer-owned rules only) or defer to v1.1 given its narrow usefulness and GPL-adjacent format risk?
9. **Q9 — LIGHT-HIDS:** does the course brief *require* an ML component? If yes, the deferral (§4.3) needs an alternate plan — no code/data exists (`§LIGHT-HIDS-6`).
10. **Q10 — PostgreSQL deployment assumptions:** single Postgres instance co-located with the worker? Affects workspace isolation (§5.5) and the §4.4 memory targets.
11. **Q11 — Sigma case-sensitivity semantics:** exact case-sensitivity mandate for string operators per spec v2.1.0 must be read and pinned in the conformance plan before C2 coding starts (not asserted in this document).
12. **Q12 — Non-Sigma formats as first-class:** should native Sentinel rules (beyond §6.3 adapters) exist at v1, or is everything imported? (Zero hardcoded detections ⇒ v1 likely import-only.)

### 8.3 NOT_VERIFIED (known unknowns — none of them underpins §1–§7 conclusions)

**Wazuh:** 5.x content-engine load order/equivalence to 4.x XML pipeline; published EPS/latency benchmarks (none exist in docs, `§WAHUH-6`); rootcheck deprecation status (no notice found, `§WAHUH-5`); fully-offline ruleset/index/vuln-DB updates beyond package install (`§WAHUH-8`); `wazuh/wazuh-ruleset` repo licence; third-party SCA content licences (`§WAHUH-7`).

**Falco:** non-Linux syscall sources (`§FALCO-3`); quantitative benchmarks (none published, `§FALCO-7`); explicit "libs forked from Sysdig" statement/date (`§FALCO-4`); payload of `--rule-schema` (`§FALCO-1`); release-cadence stats.

**EVTX hunters:** Chainsaw `v2.16.5` release *publication* timestamp vs tag date (tag 2026-08-25 VERIFIED); Chainsaw root licence file absence + non-SPDX `GPL3` string needs upstream confirmation; Hayabusa v4.1.0 release assets/signing inventory; DeepBlueCLI releases existence (no tags); python-evtx runtime performance vs Rust crate; Zircolite `docs/Benchmark.md` numbers not independently reproduced (vendor harness, `§ZIRCOLITE-8`).

**Platforms:** osquery `osquery.io/stabilities` 404 ⇒ per-table stability labels; osquery offline-snapshot querying (does not exist, `§OSQUERY-4`); Velociraptor "rummager" (zero hits) & cloud free tier (zero hits) (`§VELOCIRAPTOR-3/6`); Velociraptor Sigma docs page is `draft: true` (`§VELOCIRAPTOR-4`); Tetragon "Triton" (zero hits), Tetragon-on-Windows (experimental CI only, `§TETRAGON-3`), scope of README BSD/GPL badges (`§TETRAGON-5`); OSSEC/Tripwire/ossec-hids deep behaviour (metadata-only rows §1.1 #2/#12).

**Sysinternals/Sysmon:** literal CSV header names of `autorunsc -c` and `sigcheck -c` (no official sample; whether `sigcheck -c` even emits a header row is unknown — `-h` VERIFIED as *show hashes*, not header, `§SYSINTERNALS-6/7`); shell-redirect-to-file of CSVs (undocumented, `§SYSINTERNALS-8`); `sigcheck` offline-image switch — no documented switch scans a mounted image (`-o` only does VT lookups of a previously captured CSV, "intended for scans of offline systems", `§SYSINTERNALS-7`); `sysmon -c` dump output format (XML?) (`§SYSMON-5`); on-disk Sysmon EVTX filename; Sysmon 15.20–15.22 changelog (no What's New section at all, `§SYSMON-1`); GA date of built-in Sysmon (`§SYSMON-1`).

**LIGHT-HIDS:** dataset collection OS/mechanism (paper silent — "Linux host" appears only as a Fig. 1 label), sequence length/vocabulary/Conv1D dims/DeepSVDD+IF hyperparameters, latency *aggregation* basis (per-sequence vs aggregate; the definition itself IS stated — §IV-A3, `§LIGHT-HIDS-7`), model size, Windows applicability (0 occurrences of "Windows" in text+figures, `§LIGHT-HIDS-5`), code/weights release (none found after 7 GitHub searches, `§LIGHT-HIDS-6`).

**Sigma ecosystem:** `unqork-external/pySigma-backend-dictquery` status/completeness; licences of `pySigma-pipeline-ossem/-ocsf/-rclinuxedr` (windows+sysmon verified LGPL-2.1); `pySigma-plugin-directory` repo licence; readiness of backends for pySigma 2.x (§5.1 skew); exact publish date of sigma-specification v2.1.0 (release feed 2025-09-12 vs document 2025-08-02); `Security-Bits/sigma2sql` (repository gone, §1.1 #34).

**Licensing (legal, not factual):** ELv2 and DRL 1.1 interpretations as applied to Sentinel (§2.2) need counsel; SwiftOnSecurity repo-level licence (header-only CC-BY claim); ET Open BSD-range per-sid audit (not performed); `MISP/misp-rfc` spec licence (not fetched); PostgreSQL licence itself (not inspected this stage); docs-site licences for Wazuh/Falco documentation.

---

*End of Stage 1. This stage does not claim completeness: §8.2 and §8.3 list what remains open. Stage 2 may begin only with ENGINE_POC.md results (§5.7) resolving D-004's gate.*

