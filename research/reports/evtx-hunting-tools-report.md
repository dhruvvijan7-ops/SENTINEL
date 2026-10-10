# Offline EVTX / Sigma Hunting Tools — Primary-Source Research Report

Date of research: 2026-10-08
Scope: Chainsaw, Hayabusa, Zircolite, DeepBlueCLI, and the underlying EVTX parsing libraries
(Rust `evtx`, `python-evtx`), assessed for an offline (agent-less) EVTX + Sigma hunting product.

## Method

All repositories were cloned at depth 1 on 2026-10-08 into a local scratch directory and read
directly; release/tag facts were taken from `git ls-remote --tags`, tag object dates and the
GitHub release pages. Every factual claim below carries an exact citation: either a URL, or a
`repo@commit:path[:line]` pointer into the pinned tree.

Citation shorthand — `repo@commit` expands to `https://github.com/<repo>/tree/<commit>`:

| Short | Repository | Pinned commit | HEAD commit date (clone) | Latest tag / release |
|---|---|---|---|---|
| `chainsaw` | https://github.com/WithSecureOpenSource/chainsaw (clone origin `WithSecureLabs/chainsaw`, redirects) | `af12749f6d0acdcfa274efce2643b5399b9ca8d1` | 2026-09-23 | tag `v2.16.5`, 2026-08-25, https://github.com/WithSecureOpenSource/chainsaw/releases/tag/v2.16.5 |
| `hayabusa` | https://github.com/Yamato-Security/hayabusa | `19a1d1db87831e976170395051c8dbc7d6c939eb` | 2026-10-05 | tag `v4.1.0`, 2026-09-12, https://github.com/Yamato-Security/hayabusa/releases/tag/v4.1.0 |
| `hayabusa-rules` | https://github.com/Yamato-Security/hayabusa-rules (hayabusa submodule) | `18afcb376e13e965037b2fc12c1e3470bc5e333d` | — | — |
| `zircolite` | https://github.com/wagga40/Zircolite | `a575d5fe1bd704bf4d9604b5d327aa53c8bf20f2` | 2026-10-03 | tag `v4.2.0` == this commit, https://github.com/wagga40/Zircolite/releases/tag/v4.2.0 |
| `DeepBlueCLI` | https://github.com/sans-blue-team/DeepBlueCLI | `2eecc65698e8666408ece67525577c895676d579` | 2023-06-28 | no tag observed (`git ls-remote --tags` returned none) — **UNVERIFIED whether releases exist** |
| `evtx` | https://github.com/omerbenamram/evtx | `7479d02dfaa3bdeb41c5ea87195e84116a032cfc` | 2026-10-07 | tag `v0.12.3`, 2026-09-22, https://github.com/omerbenamram/evtx/releases/tag/v0.12.3 |
| `python-evtx` | https://github.com/williballenthin/python-evtx | `c0007441657899c39180de10a2be1a0e43dbeaf9` | 2026-10-06 | latest **release** `v0.8.1`, 2025-05-02, https://github.com/williballenthin/python-evtx/releases/tag/v0.8.1 |

### Corrections to working assumptions carried into this research

1. **python-evtx "v8.1.0" does not exist as a release.** The release list
   (https://github.com/williballenthin/python-evtx/releases) shows `v0.8.1` as *Latest*, released
   02 May 2025 08:24; `v8.1.0` does not appear anywhere in the release list. A **tag** named
   `v8.1.0` does exist (`git ls-remote --tags`), created 02 May 2025 08:07, pointing at commit
   `1575f30` ("ci: publish via trusted-publishing") whose `pyproject.toml` says
   `version = "0.8.0"`, while tag `v0.8.1` points at `cab997a` with `version = "0.8.1"`
   (`git show v8.1.0:pyproject.toml`, `git show v0.8.1:pyproject.toml`; the two trees differ only
   in `.github/workflows/publish.yml` and `pyproject.toml`). The tag page renders as
   https://github.com/williballenthin/python-evtx/releases/tag/v8.1.0 with the wording
   "williballenthin tagged this 02 May 08:07". Conclusion: the authoritative version is **0.8.1**;
   `v8.1.0` looks like a digit-transposed tag on a pre-bump commit.
2. **Chainsaw has no `grep` or `cuff` verbs.** `git grep -E '"grep"|"cuff"' -- src` over
   `chainsaw@af12749` returns no matches; the subcommand enum is `Dump | Hunt | Lint | Search |
   Analyse` (`chainsaw@af12749:src/main.rs:60`). Chained/absence logic exists only as Sigma
   `count()` aggregation (`chainsaw@af12749:src/rule/sigma.rs:365`).
3. **Chainsaw moved.** `Cargo.toml` still says `repository = "https://github.com/WithSecureLabs/chainsaw"`
   (`chainsaw@af12749:Cargo.toml:4`) but that URL now serves **WithSecureOpenSource/chainsaw**
   (fetched 2026-10-08: page title `GitHub - WithSecureOpenSource/chainsaw`, "GPL-3.0 license").
4. **Zircolite has no `--avoid-flagged-rules` flag.** `git grep -i 'flagged'` over
   `zircolite@a575d5` yields nothing; the equivalent controls are `--min-level`, `-R/--rulefilter`
   and the config `filters` key (`zircolite@a575d5:zircolite/cli.py:178`,
   `zircolite@a575d5:zircolite/core.py:1196`, `zircolite@a575d5:config_loader.py:513`).

### Cross-tool comparison (each cell sourced in the sections below)

| | Chainsaw 2.16.5 | Hayabusa 4.1.0 | Zircolite 4.2.0 | DeepBlueCLI |
|---|---|---|---|---|
| Language | Rust | Rust | Python (Cython kernel) | PowerShell |
| Licence | GPL-3.0 | AGPL-3.0 (code) + DRL 1.1 (rules) | LGPL-3.0-or-later | GPL-3.0 |
| Rule source | Chainsaw rules + Sigma via mapping | Hayabusa/Sigma YAML (own corpus) | JSON ruleset or native Sigma YAML via pySigma | none (hard-coded heuristics) |
| Sigma correlation | not supported | supported (Sigma v2 correlation + `count()`) | supported (compiled via SQLite backend 2) | n/a |
| Output | table/CSV/JSON/JSONL/log | CSV/JSON/JSONL + profiles | JSON/CSV + Jinja templates | PowerShell objects (CSV/JSON via pipeline) |
| Multi-threading | rayon (per-file sequential loop) | rayon (`--threads`) | process/thread workers (auto) | none |

---

# CHAINSAW

## CHAINSAW-1 — Identity, version, licence, maintenance

- Latest release is **v2.16.5**, tag dated 2026-08-25 (`git for-each-ref` on fetched tag;
  https://github.com/WithSecureOpenSource/chainsaw/releases/tag/v2.16.5). `Cargo.toml` at that
  tag reads `version = "2.16.5"`.
- The pinned tree's `Cargo.toml` declares `version = "2.16.5"`, `license = "GPL3"`,
  `edition = "2024"` (`chainsaw@af12749:Cargo.toml:3,8,9`); `LICENCE` contains the full GNU GPL v3
  text (`chainsaw@af12749:LICENCE`). GitHub renders the repo as "GPL-3.0 license".
- Repo activity: HEAD commit dated 2026-09-23; GitHub shows "516 Commits", 3.7k stars
  (fetched 2026-10-08).
- Self-description: "Rapidly Search and Hunt Through Windows Forensic Artefacts"; Rust, "wrapping
  the EVTX parser library by @OBenamram" (https://github.com/WithSecureOpenSource/chainsaw).

## CHAINSAW-2 — CLI surface (verbs and options)

- Subcommand enum: `Dump | Hunt | Lint | Search | Analyse` (`chainsaw@af12749:src/main.rs:60`);
  `Analyse` delegates to `AnalyseCommand` = `Shimcache | Gaps | Evtx | Srum`
  (`chainsaw@af12749:src/main.rs:274` and following).
  - `analyse shimcache` — execution timeline from SYSTEM hive with optional `--amcache`
    enrichment and `--tspair` near-timestamp pairing.
  - `analyse gaps` — RecordID holes and long time gaps ("possible selective record deletion"),
    `--min-time-gap-minutes` default 30.
  - `analyse evtx` — per-Channel record counts and per-Event-ID frequency summary.
  - `analyse srum` — SRUM ESE database, requires `--software <SOFTWARE hive>`.
- `lint` accepts `chainsaw, sigma or stalker` rule kinds (`chainsaw@af12749:src/main.rs:196`).
- Global flags: `--no-banner`, `--num-threads` ("Limit the thread number (default: num of CPUs)"),
  `-v` count (`chainsaw@af12749:src/main.rs:46-53`).
- `hunt` flags verified in source: `-s/--sigma` (`requires = "mapping"`), `-m/--mapping`,
  `-r/--rule` (`chainsaw@af12749:src/main.rs:169-176`, `:105-110`), `--kind`, `--level`, `--status`
  rule filters (`:142-147`, `:180-182`), `--csv` (`:123-125`), `--json` (`:136-138`), `--jsonl`
  (`:139-141`), `--log` (`:160-162`), `--full` (`:133-135`), `--metadata` (`:154-156`),
  `--column-width` (`:120-122`), `--from`/`--to` (`:129-132`, `:186-189`), `--extension`
  (`:126-128`), `--load-unknown` (`:148-150`), `--skip-errors` (`:177-179`), `-o/--output`
  (`:157-159`), `--preprocess` ("(BETA) Enable preprocessing, which can result in increased
  performance", `:163-165`) —
  (https://github.com/WithSecureOpenSource/chainsaw#hunting).
- `-c/--cache-to-disk`: "Cache results to disk to reduce memory usage at the cost of performance";
  `requires = "jsonl"`, `conflicts_with = "json"` (`chainsaw@af12749:src/main.rs:112-119`).

## CHAINSAW-3 — Artefact kinds it can read

- `src/file/` contains `evtx.rs`, `json.rs`, `xml.rs`, `mft.rs`, plus `esedb/` and `hve/`
  (registry hives); the `Kind` enum is at `chainsaw@af12749:src/file/mod.rs:40`.
- README: "dump the raw content of forensic artefacts (MFT, registry hives, ESE databases)";
  "Support for loading and parsing Event Logs in both JSON and XML format"
  (https://github.com/WithSecureOpenSource/chainsaw).

## CHAINSAW-4 — Rule sources and the mapping requirement

- Two rule families: native Chainsaw rules (`-r/--rule`) and Sigma (`-s/--sigma`), where Sigma
  **requires** `--mapping` (`chainsaw@af12749:src/main.rs:169-186`; usage example
  `chainsaw@af12749:src/main.rs:31-35`).
- Mapping file format (header, verbatim from `chainsaw@af12749:mappings/sigma-event-logs-all.yml:1-10`, 825 lines total):

  ```yaml
  ---
  name: Chainsaw's groupless Sigma mappings for Event Logs
  kind: evtx
  rules: sigma

  exclusions:
  - Defense evasion via process reimaging
  - Exports Registry Key To an Alternate Data Stream
  - NetNTLM Downgrade Attack
  - Non Interactive PowerShell
  ```

- The mapping also carries `extensions.preconditions` (log-source → Provider/EID pre-filters) and a
  `fields:` list (`mappings/sigma-event-logs-all.yml:333`) of `from`/`to`/`visible` entries, e.g.
  `- from: PreAuthType` / `to: int(Event.EventData.PreAuthType)` / `visible: false` (file tail).
  Field aliasing for EVTX XML attributes is applied at lookup time: the parser is configured with
  `ParserSettings::default().separate_json_attributes(true)`
  (`chainsaw@af12749:src/file/evtx.rs:20`) and `"Event.System.Provider"` resolves through
  `Event.System.Provider_attributes.Name` (`chainsaw@af12749:src/file/evtx.rs:38`, `:55`), likewise
  `Event.System.TimeCreated` → `Event.System.TimeCreated_attributes.SystemTime`.
- The mapping carries an explicit `exclusions:` list of 16 Sigma rule titles Chainsaw refuses to
  load (`mappings/sigma-event-logs-all.yml:6-21`), followed by the `extensions:` block.

## CHAINSAW-5 — Native Chainsaw rule format

- Parsed by `chainsaw@af12749:src/rule/chainsaw.rs`: `format: json|kv`, `Container{field, format}`,
  `Field{name, from, to, cast, container, visible}`, plus `filter: Filter` and
  `aggregate: Option<Aggregate>`.
- Verbatim example, `chainsaw@af12749:rules/evtx/account_tampering/new_user_created.yml:1-19`:

  ```yaml
  ---
  title: New User Created
  group: Account Tampering
  description: A new user was created.
  authors:
    - FranticTyping
  kind: evtx
  level: info
  status: stable
  timestamp: Event.System.TimeCreated
  fields:
    - name: Event ID
      to: Event.System.EventID
    - name: Record ID
      to: Event.System.EventRecordID
  ```

  (blank lines elided for length) …followed by `filter: { Event.System.EventID: 4720 }` in the
  same file.
- Built-in rule corpus is organised under `rules/evtx/<category>/` (account_tampering, antivirus,
  applocker, credential_access, defense_evasion, indicator_removal, lateral_movement,
  login_attacks, log_tampering, powershell, …) plus `rules/mft/` (`chainsaw@af12749:rules/`).
- Rule-level filtering by `kind`, `level` and `status` is applied while loading
  (`load_rule(RuleKind::Sigma, &file, &kinds, &levels, &statuses)`,
  `chainsaw@af12749:src/main.rs:690`).

## CHAINSAW-6 — Sigma support: modifiers, conditions, aggregation, correlations

- Supported modifiers are an explicit allow-list — verbatim,
  `chainsaw@af12749:src/rule/sigma.rs:264-277`:

  ```rust
  // NOTE: We list the supported ones, so if any new ones appear we don't silently error.
  lazy_static::lazy_static! {
      static ref SUPPORTED_MODIFIERS: HashSet<String> = {
          let mut set = HashSet::new();
          set.insert("all".to_owned());
          set.insert("base64".to_owned());
          set.insert("base64offset".to_owned());
          set.insert("contains".to_owned());
          set.insert("endswith".to_owned());
          set.insert("startswith".to_owned());
          set.insert("re".to_owned());
          set
      };
  }
  ```

  Any other modifier makes the rule fail with context `"unsupported modifiers"`
  (`chainsaw@af12749:src/rule/sigma.rs:279-287`). Notably absent from the list: `windash`,
  `utf16`, `cidr`, `expand`, `fieldref`.
- Condition handling: a non-string `detection.condition` returns error `"unsupported condition"`
  (`chainsaw@af12749:src/rule/sigma.rs:512-517`, second site at `:776`).
- Aggregation: only `count(...)` is parsed — verbatim comment
  `chainsaw@af12749:src/rule/sigma.rs:372-385`:

  ```rust
  // NOTE: We only support count atm...
  // agg-function(agg-field) [ by group-field ] comparison-op value
  if let Some(kind) = parts.next() {
      if let Some(rest) = kind.strip_prefix("count(") {
          ...
      } else {
          anyhow::bail!("unsupported agg function - {}", kind);
      }
  ```

  Multiple aggregation expressions in one rule are rejected:
  `"multiple aggregation expressions are not supported"` (`chainsaw@af12749:src/rule/sigma.rs:461`).
- **`timeframe` is ignored**: the `timeframe` identifier is skipped with
  `// TODO: Ignore for now as this would make the aggregator more complex...`
  (`chainsaw@af12749:src/rule/sigma.rs:530-533`) — i.e. Sigma temporal/correlation semantics are
  not implemented.
- **No Sigma correlation rules**: `git grep -i 'correlation' -- src` over `chainsaw@af12749`
  returns no matches. Aggregation state is created fresh inside each `hunt()` call
  (`let aggregates: Mutex<…>` at `chainsaw@af12749:src/hunt.rs:788`), and `hunt()` is invoked per
  input file (`for file in &files` at `chainsaw@af12749:src/main.rs:811`) — so aggregation is
  **per file, not corpus-wide**.
- **No ATT&CK enrichment**: `git grep -i -E 'mitre|attack\.' -- src` over `chainsaw@af12749`
  returns no matches; Sigma `tags` are passed through to output unchanged
  (`chainsaw@af12749:src/cli.rs:1008`).

## CHAINSAW-7 — Evidence recorded per detection

- `Detection` struct — verbatim, `chainsaw@af12749:src/cli.rs:980-1009`:

  ```rust
  #[derive(Debug, Serialize)]
  pub struct Detection<'a> {
      pub group: &'a String,
      #[serde(flatten)]
      pub kind: &'a Kind<'a>,
      pub name: &'a String,
      pub timestamp: String,
      pub authors: &'a Vec<String>,
      pub level: &'a Level,
      pub source: RuleKind,
      pub status: &'a Status,
      #[serde(flatten, skip_serializing_if = "Option::is_none")]
      pub sigma: Option<Sigma<'a>>,
  }
  ```

  with `Sigma` carrying `falsepositives`, `id`, `logsource`, `references`, `tags`.
- The `kind` payload is `Individual { document }` / `Aggregate { documents }` / `Cached { … }`
  (`chainsaw@af12749:src/hunt.rs:116-132`); a `Document` holds `kind`, `path`, and `data` which is
  `// NOTE: Serialised Value using bincode` — the full event, decoded back to JSON on serialisation
  (`chainsaw@af12749:src/hunt.rs:83-105`). So every detection can carry the complete raw event plus
  source path.

## CHAINSAW-8 — Output formats

- `hunt` output: ASCII table (default, `--column-width`, `--full`, `--metadata`), `--csv`
  (requires `-o`), `--json`, `--jsonl`, `--log`
  (`chainsaw@af12749:src/main.rs:120-162`); `dump` has `-j/--json` and `--jsonl`
  (`chainsaw@af12749:src/main.rs:62-96`).
- CSV writer emits one row per hit with localised timestamp, joined rule names and document path
  (`chainsaw@af12749:src/cli.rs:960-972`).
- Tabular output groups hits by `group` (README sample output shows `Group: Antivirus`,
  `Group: Log Tampering`, `Group: Sigma` — https://github.com/WithSecureOpenSource/chainsaw).

## CHAINSAW-9 — Parallelism and memory model

- Rayon thread pool configured from `--num-threads`
  (`rayon::ThreadPoolBuilder::new().num_threads(...)` at `chainsaw@af12749:src/main.rs:461-463`).
- Within one file, records are processed with `.par_bridge()`
  (`chainsaw@af12749:src/hunt.rs:796`); across files, `hunt` loops **sequentially**
  (`for file in &files`, `chainsaw@af12749:src/main.rs:811`) while `search` uses
  `files.par_iter().try_for_each(...)` (`chainsaw@af12749:src/main.rs:1051`).
- Detections are accumulated in memory; `--cache-to-disk` switches to a `tempfile` per file and
  stores bincode-encoded raw events with offsets (`chainsaw@af12749:src/main.rs:811-825`,
  `chainsaw@af12749:src/hunt.rs:125-131`).

## CHAINSAW-10 — Performance (third-party measurement, with caveats)

- Zircolite's benchmark harness measured Chainsaw 2.16.0 against Hayabusa 4.1.0 and Zircolite on
  the same machine (`zircolite@a575d5:docs/Benchmark.md`, URL:
  https://github.com/wagga40/Zircolite/blob/master/docs/Benchmark.md):
  - 4 Sysmon EVTX, 478 MB, 452,554 events: **113.5 s** (92.8–125.5), peak 346 MiB, 40,843
    detections, 86 rules matched, 3,524 rules loaded (388 could not be loaded).
  - 8 EVTX, 13.3 GB, 1,720,377 events: **206.3 s** (197.4–215.3), peak 338 MiB, 6,871 detections,
    67 rules matched.
  - Method: medians of three timed passes after a warm-up on an Apple M1 Max (10 cores, 64 GB),
    macOS, order rotated; Chainsaw rules = SigmaHQ `2e8fd89` (2026-09-15) plus Chainsaw's own
    `rules/`, through `mappings/sigma-event-logs-all.yml`.
- Caveat stated by the benchmark author: "The rule sets differ" and "Detection totals therefore do
  not measure relative detection quality"; Chainsaw's times "varied the most between passes"
  (`docs/Benchmark.md`, *Reading the numbers*).

---

# HAYABUSA

## HAYABUSA-1 — Identity, version, licence, maintenance

- Latest tag **v4.1.0** ("Suzumushi"), 2026-09-12 (`git for-each-ref` on fetched tag; merge commit
  "Merge pull request #1927 from Shirofune-Security/release/4.1.0-suzumushi");
  https://github.com/Yamato-Security/hayabusa/releases/tag/v4.1.0.
- `Cargo.toml` at the tag: `name = "hayabusa"`, `version = "4.1.0"`, `repository =
  "https://github.com/Yamato-Security/hayabusa"`, `rust-version = "1.97.1"`
  (`hayabusa@v4.1.0:Cargo.toml`).
- Licence split, verbatim from README: "Hayabusa is released under the GNU AGPLv3 license;
  detection rules are released under the Detection Rule License (DRL) 1.1"
  (https://github.com/Yamato-Security/hayabusa#contributing--license, badge `License-AGPLv3`).
- README claim (marketing, flagged as such): "the only open-source tool with full Sigma support,
  including v2 correlation rules" (https://github.com/Yamato-Security/hayabusa, *About* banner).
  The mechanism for that claim is in HAYABUSA-7.
- Rules ship as a git submodule → https://github.com/Yamato-Security/hayabusa-rules.git
  (`.gitmodules`: `path = rules`, `url = …hayabusa-rules.git`; `hayabusa@19a1d1:.gitmodules`),
  pinned here at `18afcb37`.

## HAYABUSA-2 — Commands, input, output types

- Current subcommand set (`hayabusa@19a1d1:src/detections/configs.rs`, `Action` enum): `DfirTimeline`,
  `LogMetrics`, `LogonSummary`, `EidMetrics`, `ExpandList`, `ExtractBase64`, `PivotKeywordsList`,
  `Search`, `UpdateRules`, `LevelTuning`, `SetDefaultProfile`, `ComputerMetrics`,
  `ConfigCriticalSystems`, `SortCsv`.
- Timeline output format: `-t, --output-type` = `csv` (default) | `json` | `jsonl`
  (`hayabusa@19a1d1:src/detections/configs.rs:1721-1749`), `-o/--output FILE` (`:1771-1773`).
- Input: `-d/--directory` (multiple .evtx), `-f/--file` (one .evtx), `-l/--live-analysis`
  (`:1700-1710`), `-J/--json-input` "Scan JSON formatted logs instead of .evtx (.json or .jsonl)"
  (`:1070-1073`), `-x/--recover-records` "Carve evtx records from slack space (default: disabled)"
  (`:1712-1714`), `-V/--validate-checksums` (`:1074-1076`), `--target-file-ext` (`:1078-1080`).
- Also `-G/--geo-ip` for MaxMind GeoIP enrichment of IP fields (`:1761-1769`).

## HAYABUSA-3 — Output profiles (evidence columns)

- Profile files: `config/default_profile.yaml` and `config/profiles.yaml`, which defines profiles
  `minimal`, `standard`, `verbose`, `all-field-info`, `all-field-info-verbose`, `super-verbose`,
  `timesketch-minimal`, `timesketch-verbose`; profile templating lives in
  `hayabusa@19a1d1:src/options/profile.rs`.
- Default profile, verbatim (`hayabusa@19a1d1:config/default_profile.yaml`):

  ```yaml
  ---
  Timestamp: "%Timestamp%"
  RuleTitle: "%RuleTitle%"
  Level: "%Level%"
  Computer: "%Computer%"
  Channel: "%Channel%"
  EventID: "%EventID%"
  RecordID: "%RecordID%"
  Details: "%Details%"
  ExtraFieldInfo: "%ExtraFieldInfo%"
  RuleID: "%RuleID%"
  ```

- `verbose` adds `MitreTactics`, `MitreTags`, `OtherTags`, `RuleFile`, `EvtxFile`;
  `all-field-info` swaps `Details`/`ExtraFieldInfo` for `AllFieldInfo` (the whole event)
  (`hayabusa@19a1d1:config/profiles.yaml`).
- `sort-csv` dedupes rows that differ only by `EvtxFile` (`hayabusa@19a1d1:src/timeline/sort_csv.rs:141-143`).

## HAYABUSA-4 — Rule format and validation

- Required keys, verbatim `hayabusa@19a1d1:src/yaml.rs:893-941` (abridged):

  ```rust
  pub fn check_hayabusa_rule_fmt(yaml: &Yaml) -> Result<(), String> {
      let mut required_keys = vec![
          "author", "title", "logsource", "detection", "level", "status", "date", "id",
      ];

      if yaml["correlation"].is_hash() {
          required_keys.retain(|&key| key != "logsource" && key != "detection");
      }
      ...
      "level" => { ... ["informational", "low", "medium", "high", "critical"].contains(&value) ... }
      "status" => { ... ["stable","test","experimental","deprecated","unsupported"] ... }
  ```

  (comment above the fn: "correlation rules do not need `logsource`/`detection`").
- Hayabusa-specific keys observed in its own corpus: `ruletype: Hayabusa` and `sample-evtx`
  (e.g. `hayabusa-rules@18afcb3:hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml`).
- Corpus size: 5,000 `.yml` files under `hayabusa/` and `sigma/` subtrees of
  `hayabusa-rules@18afcb3` (count from directory scan).
- Rule loading, counting, and deprecation of `..._Cnt_Deprecated.yml` in favour of
  `..._Correlation.yml` are handled in `hayabusa@19a1d1:src/yaml.rs` (`update_correlation_counts`,
  `validate`).

## HAYABUSA-5 — Config files that carry field mappings and tuning

- Default rules-config directory is `./rules/config` (`-c, --rules-config`,
  `hayabusa@19a1d1:src/detections/configs.rs`, `DetectCommonOption::config`), resolved by
  `resolve_config_file` (`hayabusa@19a1d1:src/detections/configs.rs:196`). The `rules/` path is the
  submodule: `.gitmodules` declares `path = rules`, `url = https://github.com/Yamato-Security/hayabusa-rules.git`
  (`hayabusa@19a1d1:.gitmodules`), so on disk these files are `hayabusa-rules/config/…`.
- Files present in `hayabusa-rules@18afcb3:config/`:
  - `channel_eid_info.txt` — CSV `Channel,EventID,EventTitle`
  - `eventkey_alias.txt` — EVTX field-name aliasing used by detection
  - `exclude_rules.txt`, `noisy_rules.txt`, `proven_rules.txt` — rule-ID deny/allow lists
    (loader: `hayabusa@19a1d1:src/filter.rs:22-58`: "IDs from exclude_rules.txt are always skipped;
    IDs from noisy_rules.txt are skipped unless --enable-noisy-rules is set")
  - `level_tuning.txt` — per-rule level overrides (`LevelTuning` action)
  - `target_event_IDs.txt` — EID allow-list for `-E/--eid-filter`
  - `data_mapping/*.yaml` — 12 per-channel/EID rewrite-rule files, e.g.
    `Security_4688_ProcessCreation.yaml` with `RewriteFieldData`, `HexToDecimal`
    (`hayabusa-rules@18afcb3:config/data_mapping/`)
  - `windash_characters.txt`, `geoip_field_mapping.yaml` (`hayabusa-rules@18afcb3:config/`)
- Field-mapping code paths: `src/detections/field_data_map.rs`, `field_extract.rs`, `message.rs`;
  disable switch `-F, --no-field-data-mapping` (`hayabusa@19a1d1:src/detections/configs.rs:1646`).

## HAYABUSA-6 — EVTX parsing pipeline

- Uses a **fork of the Rust evtx crate**: `evtx` from
  `https://github.com/Yamato-Security/hayabusa-evtx.git`, rev
  `170c7a5f28fa4ef853e60e1b620dfacb19138c4f`, described in release notes as 0.9.12, with
  feature `fast-alloc` (`hayabusa@19a1d1:Cargo.toml`).
- Parser usage: `use evtx::{EvtxParser, ParserSettings, RecordAllocation}`
  (`hayabusa@19a1d1:src/main.rs:15`); `EvtxParser::from_path` then `parser.records_json_value()`
  (`hayabusa@19a1d1:src/main.rs:2521-2530`, `:3257`).
- Records with `allocation == RecordAllocation::EmptyPage` are counted as recovered records
  (`recover_records_cnt`, `hayabusa@19a1d1:src/main.rs:2554-2558`).
- Per-record filters applied before detection: computer name include/exclude, EID include/exclude
  plus `target_event_IDs.txt`, null-channel skip (`hayabusa@19a1d1:src/main.rs:2585-2619`).
- Detection runs in batches of `MAX_DETECT_RECORDS` records per detect pass
  (`hayabusa@19a1d1:src/main.rs:2543-2546`).

## HAYABUSA-7 — Sigma correlation and aggregation support

- Dedicated parser: `hayabusa@19a1d1:src/detections/rule/correlation_parser.rs`.
  - Correlation rules reference other rules "by any of the three" of `id`, `title` or `name`
    (`is_referenced_rule`, `correlation_parser.rs` top).
  - `correlation.condition` supports operators `eq, lte, gte, lt, gt`
    (`process_condition_pairs`), plus optional `field` used only for `type: value_count`
    (`find_condition_field_value`).
  - Referenced rules are OR-ed into one selection (`to_or_selection_node`).
- Legacy single-rule aggregation (`condition: selection | count(X) by Y >= N`) is parsed by
  `aggregation_parser.rs`, and only `count` is implemented — verbatim,
  `hayabusa@19a1d1:src/detections/rule/aggregation_parser.rs:157-158`:

  ```rust
  // The Sigma spec defines other aggregation functions besides count, but supporting
  // the many possible patterns would get complex, so only the count keyword is
  ```

  Regex entry point: `^count\( *\w* *\)` (`aggregation_parser.rs:9`).
- Correlation rules are compiled/aggregated across the whole run (`CorrelationType`,
  `AggResult`, "Sigma temporal correlation" handling in
  `hayabusa@19a1d1:src/detections/detection.rs`), unlike Chainsaw's per-file aggregation.
- Verbatim example, `hayabusa-rules@18afcb3:hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml:15-33`:

  ```yaml
  correlation:
      type: value_count
      rules:
          - non_existent_user
      group-by:
          - IpAddress
          - LogonType
          - TargetDomainName
          - ProcessName
          - LogonProcessName
          - WorkstationName
      timespan: 5m
      condition:
          gt: 3
          field: TargetUserName
  ```

  followed by `---` and the referenced rule document with `name: non_existent_user` (`:35-45`).
- ATT&CK enrichment: `MitreTactics` / `MitreTags` / `OtherTags` are populated from rule tags into
  the profile (`hayabusa@19a1d1:src/detections/detection.rs:34`), i.e. tag pass-through plus profile
  columns, not a separate mapping engine.

## HAYABUSA-8 — False-positive / rule-volume controls

Verified in `hayabusa@19a1d1:src/detections/configs.rs` inside `OutputOption`
(`:1507-1672`, "Options that can be set when outputting results (flattened into
csv-timeline/json-timeline)"), which `dfir-timeline` flattens:

| Flag | Behaviour | Line |
|---|---|---|
| `-m, --min-level` (default `informational`) / `-e, --exact-level` | mutually exclusive level filter (`level_rule_filtering` ArgGroup) | `:1509`, `:1559-1582` |
| `--exclude-status` / `--include-status` | rule status filter (conflicting) | `:1539-1545` |
| `--include-tag` / `--exclude-tag` | e.g. `attack.execution,attack.discovery` | `:1547-1549`, `:1599-1601` |
| `--include-category` / `--exclude-category` | logsource categories, e.g. `process_creation,pipe_created` | `:1551-1557` |
| `-D, --enable-deprecated-rules` / `-u, --enable-unsupported-rules` | opt-in statuses | `:1531-1537` |
| `-n, --enable-noisy-rules` | enable `rules/config/noisy_rules.txt` | `:1584-1586` |
| `-P, --proven-rules` | "Scan with only proven rules for faster speed (./rules/config/proven_rules.txt)" | `:1595-1597` |
| `-E, --eid-filter` | "Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)" | `:1591-1593` |
| `--include-eid` / `--exclude-eid` | explicit EID lists | `:1603-1609` |
| `-p, --profile` | output profile (see HAYABUSA-3) | `:1524-1526` |
| `-R, --remove-duplicate-data` | "Duplicate field data will be replaced with "DUP" (sort required)" | `:1514-1522` |
| `--enable-all-rules` | bypass the rule wizard | `configs.rs:1667`, `:586` |

Additional related options: `--timeline-start/--timeline-end`, `--time-offset`,
`--include-computer/--exclude-computer`, `--no-field-data-mapping` (`-F`).
Rule-ID-level exclusion is driven by `exclude_rules.txt` / `noisy_rules.txt`
(`hayabusa@19a1d1:src/filter.rs:22-24`).

## HAYABUSA-9 — Threading and memory

- `--threads <NUMBER>` — "Number of threads (default: optimal number for performance)"; it is a
  **long option only** (no `-t` short form) and appears on every detect-style action
  (`hayabusa@19a1d1:src/detections/configs.rs:1082-1089`, `:1248-1255`).
- Low-memory mode is implicit in unsorted output: `is_low_memory = !opt.output_options.sort_events`
  (`hayabusa@19a1d1:src/detections/configs.rs:581-584`), with `-s, --sort` documented as
  "Sort results before saving the file (warning: this uses much more memory!)".
- README/OLD-README feature list: "Low memory usage. (Note: this is possible by not sorting
  results. Best for running on agents or big data.)"
  (`hayabusa@19a1d1:OLD-README.md:301`).
- Speed levers documented in OLD-README: rule filtering "usually gives a 20% to 10x speed
  improvement" (`:1214`); EID filtering "…around 10% with normal scans and up to 60%+ performance
  increase when scanning with a single rule" (`:1218`); "By default, Hayabusa will scan all events,
  but if you want to improve performance, please use the `-E, --EID-filter` option" (`:1481`).

## HAYABUSA-10 — Performance numbers

- Vendor benchmark (OLD-README, dated 2023/06/01): 2018 Lenovo P51 (Xeon 4-core / 64 GB), 3 GB of
  evtx, 3891 rules enabled — `minimal` 8m50s / 770 MB (-30%), `standard` 9m00s / 1.1 GB,
  `verbose` 9m10s / 1.3 GB (+20%), `all-field-info` 9m03s / 1.2 GB (+10%)
  (`hayabusa@19a1d1:OLD-README.md:1732-1739`).
- Third-party (2026, `zircolite@a575d5:docs/Benchmark.md`): Hayabusa 4.1.0 loaded 4,658 rules
  (its channel filter kept 2,293 on the Sysmon corpus and 4,409 on the mixed corpus) — 478 MB
  corpus **24.7 s** (23.3–25.1), 900 MiB peak, 589,409 detections, 132 rules matched; 13.3 GB
  corpus **518.8 s** (515.6–520.0), 1,599 MiB peak, 704,533 detections, 181 rules matched. Note the
  benchmark's own caveat that Hayabusa's informational/"Sysmon Alert" rules account for most of its
  detection lead (`Benchmark.md:43-51`).

---

# ZIRCOLITE

## ZIRCOLITE-1 — Identity, version, licence, dependencies

- Version **4.2.0**, tag == pinned HEAD, 2026-10-03
  (`zircolite@a575d5:pyproject.toml:3`; https://github.com/wagga40/Zircolite/releases/tag/v4.2.0).
- Licence: `license = "LGPL-3.0-or-later"` (`pyproject.toml`) and `LICENSE` opens "GNU Lesser
  General Public License … version 3 or (at your option) later version".
- Requires Python `>=3.10` (`pyproject.toml:requires-python`); key dependencies
  (`zircolite@a575d5:pyproject.toml:8-31`): `orjson`, `pysigma>=1.5.1,<2`,
  `pysigma-backend-sqlite>=2.0.0,<3`, `pysigma-pipeline-sysmon`, `pysigma-pipeline-windows`,
  `evtx>=0.6.2` (the Rust EVTX Python bindings), `lxml`, `ijson`, `pyahocorasick`, `pyroaring`,
  `regex` (with a CPU-time limit in `zircolite/core.py`), `RestrictedPython` (transform sandbox).
- Build: Cython flattening kernel compiled by `setup.py` (`flatten_kernel.py` →
  `zircolite._flatten_native`); "If compilation fails, the build backend warns and installation
  continues with the slower Python kernel" (README, *Install a C compiler first*).

## ZIRCOLITE-2 — Input formats and auto-detection

- Formats: EVTX (default), JSON lines, JSON array, XML, CSV, auditd, Sysmon for Linux, EVTXtract,
  and previously-saved SQLite databases (`-D/--db-input`); default extensions per format
  (`zircolite@a575d5:docs/Usage.md:319-334`).
- Auto-detection of log type and timestamp field: "Zircolite detects the log format and timestamp
  field of its input, so explicit format flags [are] optional" (`docs/Usage.md:602-652`).
- Archives: "Reads gzip, bzip2, ZIP and 7-Zip inputs" with `--ask-archive-password` /
  `ZIRCOLITE_ARCHIVE_PASSWORD` (README *Key Features*).
- Time/Event filtering: `-A/--after`, `-B/--before`, `--no-event-filter` (`docs/Usage.md:311-317`).

## ZIRCOLITE-3 — Architecture: SQLite, flattening, prefilter, indexing, parallelism

- Detection runs as SQL over an SQLite events database: rules carry `rule` = "the SQL it runs"
  (`docs/Usage.md:960-964`).
- Automatic processing mode: "For multiple files, Zircolite selects a database layout and worker
  count using file sizes, available RAM and CPU count. It throttles new work under memory
  pressure." Override with `--no-auto-mode`, `--unified-db`, `--no-parallel`, `--parallel-workers`
  (README *Automatic Processing Optimization*; details `docs/Advanced.md`).
- Executor choice: `auto` uses **separate Python processes** when ≥2 files average ≥50 MiB and
  CPU/RAM allow, otherwise threads (`docs/Usage.md:410-434`); `--parallel-memory-limit` default 85%.
- Early **event filter**: channel/EventID extraction config so "events that won't match any rules
  [are] skipped before expensive processing" (`zircolite@a575d5:config/config.yaml`,
   `event_filter` block; implementation `zircolite@a575d5:zircolite/rules.py:98-404`).
- **Literal prefilter**: reads fields named by rules' `LIKE` patterns once and marks candidate
  events; "the detections are identical with the filter on or off"; `auto` engages at ≥1,000 events
  and ≥32 usable queries (`docs/Usage.md:451-455`).
- Indexing: `--add-index`, `--remove-index`, `--auto-index` ("Index the top-N columns that the most
  rules in the ruleset filter on", N defaults to 5) (`docs/Usage.md:393-396`).
- Memory knobs: `--working-db memory|disk`, `--working-db-dir`, `--sqlite-cache-mib` (default 64),
  `--performance-json` stage-timing report (`docs/Usage.md:436-449`).

## ZIRCOLITE-4 — Ruleset format and Sigma ingestion

- Native Sigma YAML is converted with pySigma at load time: "Native Sigma rules in YAML work
  directly — Zircolite detects the format and converts them with pySigma" (`docs/Usage.md:966-973`);
  `-p/--pipeline` selects installed pipelines, `-pl/--pipeline-list` lists them (`:341-343`).
- Own ruleset format is a single JSON file — verbatim requirements,
  `zircolite@a575d5:docs/Usage.md:960-964`:

  ```text
  A JSON ruleset is an array of rules, each with its `title`, `level`, `tags` and the SQL it
  runs (`rule`). Rulesets converted by pySigma's SQLite backend 2 also carry
  `schema_version: 2`, the fields each rule reads (`required_fields`) and, for a
  correlation, its `correlation_plan`.
  ```
- Shipped rulesets: `rules_windows_merged.json` (default when `--ruleset` omitted),
  `rules_windows_sysmon.json`, `rules_windows_generic.json`, `rules_linux.json`; `-U/--update-rules`
  installs published rulesets plus community sets (Hayabusa, Joe Security, Micah Babinski,
  mdecrevoisier, tsale) each keeping "their own licences — DRL 1.1, GPL 3.0 or CC0 1.0", verified
  against `release-manifest.json` (`docs/Usage.md:918-958`).
- Conversion summary line: `[✓] Converted 245 rules (3 invalid skipped, 2 failed)`
  (`docs/Usage.md:588-596`).

## ZIRCOLITE-5 — Correlation support

- Full Sigma correlation set, verbatim `zircolite@a575d5:docs/Usage.md:977-983`:

  ```text
  Zircolite runs Sigma correlation rules as pySigma's SQLite backend 2 compiles them:
  event_count, value_count, value_sum, value_avg, value_median, value_percentile,
  temporal and temporal_ordered, including extended conditions such as `a and not b`,
  field aliases, and correlations of correlations. They need SQLite 3.38 or newer with
  its JSON functions
  ```

- Two run modes: precompiled (`rules/experimental/*.json`) or native YAML, where "All the YAML
  paths of a run form one Sigma collection, so a correlation can refer to a rule defined in another
  file or directory" (`docs/Usage.md:985-999`).
- Window semantics: counts/statistics look back over `[t - timespan, t]`; ordered stages need
  strictly increasing timestamps; absence conditions wait for the window to end; an open window at
  the end of input is reported `incomplete_window` (`docs/Usage.md:1048-1056`).
- Cross-file: "When correlation rules are loaded and there are several input files, Zircolite puts
  them all in one database (unified mode) whatever auto mode would have chosen"
  (`docs/Usage.md:1070-1078`).
- Alert payload includes `group_keys`, `window_start/end`, `metric_name`, `metric_value`,
  `event_ids`, `child_alert_ids` and `evidence` (per-event rows "as they were ingested,
  `OriginalLogfile` included") — full JSON example at `docs/Usage.md:1005-1034`.
- Cost warning: "A correlation builds indexed temporary tables from the whole events table…
  `--limit` discards a rule with too many alerts, but the work to find them is already done"
  (`docs/Usage.md:1083-1088`).

## ZIRCOLITE-6 — Rule/volume filtering (the "false positive" controls)

- `--min-level` — "Load only the rules at this level or above: informational, low, medium, high or
  critical. A rule without a level counts as informational" (`docs/Usage.md:345`;
  `zircolite@a575d5:zircolite/cli.py:178`).
- `-R, --rulefilter` — "Skip rules whose title contains this text (case-sensitive); repeatable"
  (`docs/Usage.md:346`; applied in `zircolite@a575d5:zircolite/core.py:1196`).
- `-L, --limit` — "Discard results from any rule matching more than this many events … or `-1` to
  disable" (`docs/Usage.md:359`).
- `-s/--select`, `-a/--avoid` (filename-level inclusion/exclusion), `--file-pattern`,
  `--no-recursion` (`docs/Usage.md:298-309`).
- YAML run config `filters` (e.g. `["Noisy Rule", "Test"]`) at
  `zircolite@a575d5:config_loader.py:513`; `rules.min_level` validated against `RULE_LEVELS`
  (`config_loader.py:364-365`).
- Field-level config: `config/config.yaml` sections `exclusions`, `useless`, `mappings`, `alias`,
  `split`, `transforms`, `enabled_transforms` (`zircolite@a575d5:config/config.yaml` header);
  transforms are RestrictedPython-sandboxed Python (README *Field processing*).
- No `--avoid-flagged-rules` flag exists (see correction #4 above).

## ZIRCOLITE-7 — Output and evidence fields

- Per-rule result metadata, verbatim `zircolite@a575d5:zircolite/core.py:1091-1103`:

  ```python
  def _rule_result(self, rule: dict[str, Any], **counts: Any) -> dict[str, Any]:
      """A rule's result metadata; the caller adds its matches last."""
      description = rule.get("description", "")
      return {
          "title": rule.get("title", "Unnamed Rule"),
          "id": rule.get("id", ""),
          "description": ...,
          "sigmafile": rule.get("filename", ""),
          "sigma": rule.get("rule"),
          "rule_level": rule.get("level", "unknown"),
          "tags": rule.get("tags", []),
          **counts,
      }
  ```

  `matches` is then attached (`core.py:1086-1087`) — each match is the flattened event row as
  ingested (spooled through a temp file, `zircolite@a575d5:zircolite/results.py:9-67`).
- CSV mode flattens to `rule_title, rule_description, rule_level, rule_count` plus event columns,
  drops `row_id`, and sanitises values: newlines → spaces, and leading `=`, `+`, `-`, `@` or tab
  get a single quote prefix "so a logged string cannot execute as a formula" — "Use JSON when you
  need the values exactly as stored" (`docs/Usage.md:567-586`).
- Templates: JSON, CSV, Jinja templates for JSONL, Splunk, Elastic, OpenSearch, Timesketch, SARIF
  and ATT&CK Navigator (`README` *Key Features*; `templates/`, `-t/-T`, `--timesketch`,
  `--navigator-output`).
- Console evidence: summary panel with stage timings, executor, event/file counts, sampled peak
  memory, detections by severity, rule-coverage bar, top-5 detections, plus a MITRE ATT&CK tactics
  heatmap derived from rule tags (`docs/Usage.md:525-540`).
- `--profile-rules` times each rule and prints the slowest 20 (forces sequential processing)
  (`docs/Usage.md:553-565`).

## ZIRCOLITE-8 — Performance (vendor-published, third-party run of three tools)

- `docs/Benchmark.md` (URL: https://github.com/wagga40/Zircolite/blob/master/docs/Benchmark.md):
  - 478 MB / 452,554 events: Zircolite **11.6 s** (11.6–14.4), 1,207 MiB, 149,069 detections,
    4,319 rules, 88 matched.
  - 13.3 GB / 1,720,377 events: Zircolite **104.8 s** (102.8–106.3), 8,103 MiB, 257,678 detections.
  - Reproduction harness: `tools/tool-benchmark.py` writes a JSON report "with every pass, each
    tool's version and loaded rule count, and the commit of every rule checkout".
  - Stated limitations: memory "covers the whole process tree" (Zircolite uses worker processes),
    Zircolite's time "includes Python start-up and loading 7.6 MB of rule SQL", and rule sets differ
    between tools (`docs/Benchmark.md`, *Reading the numbers*).

## ZIRCOLITE-9 — Maintenance state

- HEAD == tag `v4.2.0` (2026-10-03), i.e. a release was cut from the current tip; active docs site
  (https://wagga40.github.io/Zircolite/), Docker image `wagga40/zircolite:latest`, standalone
  binaries per platform (README).

---

# DEEPBLUECLI

## DEEPBLUECLI-1 — Identity, licence, repository contents

- Repository: https://github.com/sans-blue-team/DeepBlueCLI (clone origin; author line in README:
  "Eric Conrad, Backshore Communications, LLC").
- Licence: GPL-3.0 — `LICENSE` opens with the GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007.
- Contents: `DeepBlue.ps1` (870 lines, 42,009 bytes), `DeepBlue.py` (alpha), `DeepBlueHash-checker.ps1`,
  `DeepBlueHash-collector.ps1`, `regexes.txt`, `safelist.txt`, `safelists/`, `hashes/`, `evtx/`
  (sample logs), `READMEs/` (`DeepBlueCLI@2eecc65`).
- Maintenance: HEAD commit dated **2023-06-28** ("New Sliver and Metasploit EVTX files…");
  `git ls-remote --tags` returns no tags — **UNVERIFIED whether any GitHub releases exist**.

## DEEPBLUECLI-2 — Usage and inputs

- `.\DeepBlue.ps1 <event log name> <evtx filename>`; bare run or `-log security` / `-log system`
  processes the local log (requires Administrator); a bare path processes an EVTX file
  (`DeepBlueCLI@2eecc65:README.md:27-48`).
- Event logs processed: Windows Security, System, Application, Windows PowerShell, Sysmon
  (`README.md:50-56`).
- Command-line sources: Security 4688, PowerShell 4103/4104, Sysmon 1 (`README.md:58-64`).
- Offline reading uses `Get-WinEvent`: `$events = iex "Get-WinEvent $filter -ErrorAction Stop"`
  (`DeepBlueCLI@2eecc65:DeepBlue.ps1:77`) and `Get-WinEvent -path $file -max 1` to validate an EVTX
  path (`DeepBlue.ps1:664`).

## DEEPBLUECLI-3 — Event IDs handled

Extracted from the `$event.id -eq …` branches in `DeepBlueCLI@2eecc65:DeepBlue.ps1`:
`1` (Sysmon process), `2` (EMET), `7`, `8`, `104`, `1102`, `4103`, `4104`, `4625`, `4648`, `4672`,
`4673`, `4674`, `4688`, `4720`, `4728/4732/4756` (group membership), `5861`, `7030`, `7036`, `7040`,
`7045`, `8003`, `8004`.

## DEEPBLUECLI-4 — Detection approach and thresholds

- No rules engine: heuristics are hard-coded in `Main` with inline thresholds, verbatim
  `DeepBlueCLI@2eecc65:DeepBlue.ps1:48-73` (abridged):

  ```powershell
  # Password guessing/spraying variables:
  $maxfailedlogons=5 # Alert after this many failed logons
  ...
  $maxtotalsensprivuse=4
  # Admin logon variables:
  $totaladminlogons=0  # Total number of logons with SeDebugPrivilege
  $maxadminlogons=10   # Alert after this many admin logons
  ...
  $minpercent=.65  # minimum percentage of alphanumeric and common symbols
  $maxbinary=.50   # Maximum percentage of zeros and ones to detect binary encoding
  # Password spray variables:
  $passsprayuniqusermax = 6
  $passsprayloginmax = 6
  ```

- Command-line minimum length for alerting: `$minlength=1000` (`DeepBlue.ps1:40`); obfuscation
  check `Check-Obfu` (`DeepBlue.ps1:808`) and base64 `-Enc` decoding + re-scan
  (`DeepBlue.ps1:749-760`, `Check-Command` at `:730`).
- Pattern lists load from CSV at runtime: `regexes.txt` (detection) and `safelist.txt` (suppression)
  via `Get-Content … | Select-String '^[^#]' | ConvertFrom-Csv` (`DeepBlue.ps1:42-44`); safelist
  check in `Check-Command` (`DeepBlue.ps1:736-742`).
- Custom output object, verbatim `DeepBlueCLI@2eecc65:DeepBlue.ps1:86-95`:

  ```powershell
  ForEach ($event in $events) {
      # Custom reporting object:
      $obj = [PSCustomObject]@{
          Date    = $event.TimeCreated
          Log     = $logname
          EventID = $event.id
          Message = $event.message
          Results = ""
          Command = ""
          Decoded = ""
      }
  ```

- README documents the check categories: suspicious account behaviour (user creation, group adds,
  password guessing, spraying — failed-logon and explicit-credential variants, Bloodhound
  "admin privileges assigned to the same account with multiple Security IDs"), command-line /
  Sysmon / PowerShell auditing (long command lines, regex searches, obfuscated commands, PowerShell
  via WMIC/PsExec, `Net.WebClient Downloadstring`, compressed/base64 commands with automatic
  decode, unsigned EXEs/DLLs), service auditing (suspicious service creation, service creation
  errors, stopping/starting the Windows Event Log service), Mimikatz `lsadump::sam`, EMET and
  AppLocker blocks (`README.md:66-92`).

## DEEPBLUECLI-5 — Output

- "DeepBlueCLI outputs in PowerShell objects, allowing a variety of output methods and types,
  including JSON, HTML, CSV, etc." with examples `| ConvertTo-Csv`, `| ConvertTo-Json`,
  `| Format-List`, `| Out-GridView` (`README.md:114-128`).
- No built-in file writer, no structured ATT&CK mapping, no rule IDs.

## DEEPBLUECLI-6 — Limitations relevant to a product spec

- All matching events are materialised in memory before processing (`$events = Get-WinEvent …`,
  `DeepBlue.ps1:77`) — no streaming, no `--threads`, no chunked processing (single-threaded
  PowerShell foreach, `DeepBlue.ps1:85`).
- No Sigma/YAML rule support, no correlation/windowing beyond in-run counters, no ATT&CK tagging,
  no per-rule level/status/tag filters (nothing to filter).
- Reads only the log types in DEEPBLUECLI-2; requires the fields it indexes (e.g. command-line
  auditing must be enabled — `README.md:130-149`).
- Sample EVTX corpus ships in-repo for regression testing (`DeepBlueCLI@2eecc65:evtx/`).

## DEEPBLUECLI-7 — Python port

- `DeepBlue.py` is "Alpha 0.12 (post-DerbyCon release)", "Currently alpha level functionality,
  supports CLI parsing only", "Requires libevtx: https://github.com/libyal/libevtx"
  (`DeepBlueCLI@2eecc65:DeepBlue.py:3-12`).
- The port's README records why python-evtx was not used: "I ran into trouble with *some* .evtx
  files, where it would crash with this error: `UnicodeDecodeError: 'utf16' codec can't decode
  bytes in position 0-1: illegal UTF-16 surrogate` — I found libevtx 'just worked'"
  (`DeepBlueCLI@2eecc65:READMEs/README-DeepBlue.py.md`).
- `DeepBlueHash` provides "detective safelisting using Sysmon event logs"
  (`README.md:25`).

---

# EVTXLIB

## EVTXLIB-1 — Rust `evtx` crate (omerbenamram/evtx)

- Identity: `version = "0.12.3"`, `license = "MIT/Apache-2.0"`, `repository =
  "https://github.com/omerbenamram/EVTX"`, `edition = "2024"`
  (`evtx@7479d0:Cargo.toml:5,6,9,11`); tag `v0.12.3` dated 2026-09-22
  (https://github.com/omerbenamram/evtx/releases/tag/v0.12.3); HEAD 2026-10-07.
- Dual licence files: `LICENSE-APACHE`, `LICENSE-MIT` (`evtx@7479d0`).
- Feature flags (`evtx@7479d0:Cargo.toml` `[features]`): `default = ["multithreading", "evtx_dump"]`,
  `multithreading = ["rayon"]`, `fast-alloc` (jemalloc/rpmalloc), `evtx_dump`, `wevt_templates`,
  `bench`. Optional deps: `rayon`, `clap`, `goblin` (WEVT template PE parsing), `glob`.
- Public API (`evtx@7479d0:src/lib.rs:9-25`): `EvtxParser`, `ParserSettings`, `IntoIterChunks`,
  `IterChunks`, `EvtxFileHeader`, `EvtxChunk`, `EvtxRecord`, `EvtxRecordHeader`,
  `SerializedEvtxRecord`, `Timestamp`, `binxml`, `model`, `wevt_templates`.
- `ParserSettings` knobs (`evtx@7479d0:src/evtx_parser.rs:321-350`): `num_threads` ("`0` will let rayon
  decide", `:400-404`), `validate_checksums` (skip chunks with bad checksums when enabled),
  `separate_json_attributes` (moves `#attributes` to `EventID_attributes`), `indent`, `ansi_codec`,
  `wevt_cache` (offline WEVT template fallback for missing/corrupt embedded templates).
- Record surface (`evtx@7479d0:src/evtx_record.rs:34-40`, `:91-178`):

  ```rust
  pub struct SerializedEvtxRecord<T> {
      pub event_record_id: RecordId,
      pub timestamp: Timestamp,
      pub data: T,
  }
  ```

  with `into_json_value()`, `into_json()`, `into_json_bytes()`, `into_xml()`, `into_xml_bytes()`,
  `template_instances()`; a record with `allocation == RecordAllocation::EmptyPage` marks a
  recovered/empty-page record (consumed by Hayabusa, see HAYABUSA-6).
- Doc example (single/multi-threaded) at `evtx@7479d0:src/evtx_parser.rs:265-300`:

  ```rust
  let mut parser = EvtxParser::from_path(fp).unwrap();
  for record in parser.records() {
      match record {
          Ok(r) => println!("Record {}\n{}", r.event_record_id, r.data),
          Err(e) => eprintln!("{}", e),
      }
  }
  ```

- CLI `evtx_dump` (`evtx@7479d0:src/bin/evtx_dump.rs:445-556`): positional `INPUT`,
  `--threads` ("defaults to number of CPU cores"), `--output-format`, `--output-target`,
  `--event-ranges`, `--validate-checksums`, `--no-indent`, `--separate-json-attributes`,
  `--no-show-record-number`, `--ansi-codec`, `--wevt-cache`, `--stop-after-one-error`, `--verbose`.
  README notes: "by default, `evtx_dump` will try to utilize multithreading, this means that the
  records may be returned out of order. To force single threaded usage (which will also ensure
  order), `-t 1` can be passed."
- README feature claims: 100% safe Rust, XML and JSON outputs built from a shared IR (no xml2json
  conversion), basic recovery of missing records/chunks, Python bindings at
  https://github.com/omerbenamram/pyevtx-rs (https://github.com/omerbenamram/evtx#features).
- Also ships a browser EVTX viewer compiled to WebAssembly (https://omerbenamram.github.io/evtx/).

## EVTXLIB-2 — Who depends on what

- **Chainsaw** depends on the Rust `evtx` crate: `evtx = { version = "0.12", default-features = false }`
  (`chainsaw@af12749:Cargo.toml:22`), alongside `rayon = "1.5"` (`:32`) and
  `tau-engine = { version = "1.0", features = ["core", "json", "sync"] }` (`:40`) — note
  `default-features = false` means the crate's own `multithreading`/`evtx_dump` features are off;
  Chainsaw brings its own rayon pool (CHAINSAW-9).
- **Hayabusa** depends on its own fork: `evtx` from `https://github.com/Yamato-Security/hayabusa-evtx.git`
  pinned to rev `170c7a5f28fa4ef853e60e1b620dfacb19138c4f` (0.9.12) with `fast-alloc`
  (`hayabusa@19a1d1:Cargo.toml`).
- **Zircolite** depends on the Python `evtx` bindings (`evtx>=0.6.2`, `pyproject.toml`) for EVTX
  ingestion, plus `lxml`/`ijson` for other formats.

## EVTXLIB-3 — python-evtx (williballenthin/python-evtx)

- Identity: `name = "python-evtx"`, `version = "0.8.1"`, `license = "Apache-2.0"`,
  `requires-python = ">=3.9"`, sole runtime dependency `hexdump>=3.3`
  (`python-evtx@c00074:pyproject.toml`).
- Licence file: `LICENSE.TXT` = Apache License Version 2.0 (`python-evtx@c00074:LICENSE.TXT`).
- Latest **release**: `v0.8.1`, released 02 May 2025 08:24 by williballenthin, commit `cab997a`,
  notes "migrate to pyproject.toml (and using uv and just)" / "ci: use trusted publishing to push
  to PyPI" (https://github.com/williballenthin/python-evtx/releases). The `v8.1.0` tag/release
  question is resolved in *Corrections* #1 above.
- API: `Evtx.Evtx.Evtx(path)` → `log.chunks()` (`Evtx/Evtx.py:92`), `log.records()` (`:103`, `:436`),
  `log.templates()` (`:424`), and per record `record.xml()` (`Evtx/Evtx.py:449` `class Record`,
  `:490` `def xml`).
  README demonstrates the whole workflow in three lines:

  ```python
  for record in log.records():
      print(record.xml())
  ```

- Output is XML-centric; JSON comes from the `evtx_dump_json` script, which converts via `xmltodict`
  and emits "only the EventRecordID from the System section … and all of the information within the
  EventData section" (`python-evtx@c00074:evtx_scripts/evtx_dump_json.py:1-40`).
- Console scripts (10): `evtx_dump`, `evtx_dump_json`, `evtx_dump_chunk_slack`,
  `evtx_eid_record_numbers`, `evtx_extract_record`, `evtx_filter_records`, `evtx_info`,
  `evtx_record_structure`, `evtx_structure`, `evtx_templates` (`pyproject.toml [project.scripts]`).
- Maintenance: HEAD commit 2026-10-06 ("Merge pull request #100 … render-fixed-width-arrays");
  Development Status classifier "5 - Production/Stable" (`pyproject.toml`).
- Performance: **UNVERIFIED** — no published throughput benchmark was found in the repository;
  it is pure Python (README: "python-evtx is a pure Python 3 module"). Known third-party caveat
  from DeepBlueCLI's port: a UTF-16 decode crash on some EVTX files
  (`DeepBlueCLI@2eecc65:READMEs/README-DeepBlue.py.md`).

## EVTXLIB-4 — Practical implications for the product spec

- Both hunting tools in scope are Rust and share the same parser lineage: Chainsaw uses upstream
  `evtx 0.12`, Hayabusa uses a pinned fork (`evtx@7479d0:Cargo.toml`, `hayabusa@19a1d1:Cargo.toml`,
  `chainsaw@af12749:Cargo.toml`).
- The Rust crate exposes the two things a spec normally needs from a low-level parser: a
  `timestamp`/`event_record_id` envelope (`SerializedEvtxRecord`) and raw JSON/XML payload, with
  multithreading opt-in via `ParserSettings::num_threads` (`evtx@7479d0:src/evtx_parser.rs:400`).
- python-evtx is a reference/forensics library (chunk headers, templates, structure dumps), not a
  high-throughput detector — its scripts expose structure-level inspection
  (`python-evtx@c00074:pyproject.toml [project.scripts]`).

---

## Open items / explicitly unverified

1. DeepBlueCLI GitHub Releases existence (no tags seen; release page not fetched) — **UNVERIFIED**.
2. Hayabusa release *asset* list and signing details for v4.1.0 (tag + Cargo version verified;
   asset inventory not enumerated) — **UNVERIFIED**.
3. Whether Chainsaw's `v2.16.5` GitHub release page shows the same publish date as the tag object
   (tag object date 2026-08-25 verified; release *publication* timestamp not re-fetched today) —
   **UNVERIFIED**.
4. python-evtx runtime performance relative to the Rust crate — no primary-source benchmark found.
5. Zircolite `docs/Benchmark.md` numbers were not independently reproduced; they are published by
   the Zircolite author but include runs of the other two tools under a stated methodology.
