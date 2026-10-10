# Primary-Source Research: osquery / Velociraptor / Tetragon (Sentinel brief)

**Date of research: 2026-10-08.** Every claim below traces to a URL fetched in this session, or to
`repo@commit:path` from a clone performed on 2026-10-08. Verbatim snippets are ≤15 lines.
Anything not confirmed against a primary source is marked **UNVERIFIED**.

### Source-of-truth clones (verified `git rev-parse HEAD`)
| Repo | Commit | Branch |
|---|---|---|
| `osquery/osquery` | `d9db97e3a86cf3e3ed4b3f8abbb8c4175b107855` | master (2026-10-07) |
| `Velocidex/velociraptor` | `fa9a5b4cd1a26f4a630f1ccdcb12713efc195af7` | master (2026-10-07) |
| `Velocidex/velociraptor-docs` | `95588f0dadbe41fc4520dd68d801f0c65eedbacf` | master (2026-10-08) |
| `cilium/tetragon` | `1ac2010c48c5036c053faf9177756bec53c7c14f` | main (2026-10-08) |

Clones live under `C:\Users\dhruv\AppData\Local\Temp\opencode\research\`. Citation shorthand:
`osquery@d9db97e:…`, `velociraptor@fa9a5b4:…`, `velociraptor-docs@95588f0:…`, `tetragon@1ac2010:…`
each expands to `https://github.com/<org>/<repo>/tree/<commit>`.

---

# OSQUERY

## OSQUERY-1 — Architecture: agent + embedded DB + SQL, virtual tables, schedule, packs, decorators

**Confirmed.** osquery exposes the OS as a relational DB queried with SQL; the interactive shell
(`osqueryi`) is standalone, the daemon (`osqueryd`) schedules queries.

> "osquery exposes an operating system as a high-performance relational database. This allows you to
> write SQL queries to explore operating system data. With osquery, SQL tables represent abstract
> concepts such as running processes…"
> — `osquery@d9db97e:docs/wiki/index.md:3` (same text in `README.md` "What is osquery?")

> "`osqueryi` is the osquery interactive query console/shell. In this mode, it is completely
> standalone, does not communicate with a daemon…"
> — `osquery@d9db97e:docs/wiki/introduction/using-osqueryi.md:3`

**RocksDB — precise scope (important nuance):** RocksDB is the *state/backing store*, not a cached
copy of the OS.

> "The results of your query are cached on disk using RocksDB. On the first query run, all of the
> results are stored in RocksDB. On subsequent runs, only result-set-difference (changes) are logged
> to RocksDB."
> — `osquery@d9db97e:docs/wiki/deployment/configuration.md:75-77`

> "`--database_path=/var/osquery/osquery.db` … osquery will keep state using a 'backing store' using
> RocksDB by default. This state holds event information such that it may be queried later according
> to a schedule. It holds the results of the most recent query for each query within the schedule.
> This last-queried result allows query-differential logging."
> — `osquery@d9db97e:docs/wiki/installation/cli-flags.md:170-174`

**Virtual tables:** "Under the hood, osquery uses libraries from SQLite core to create 'virtual
tables'." — `osquery@d9db97e:docs/wiki/development/creating-tables.md:17`. Shell schema output
confirms `CREATE VIRTUAL TABLE routes USING routes(...)` — `using-osqueryi.md:77`.

**Scheduled queries:** config `schedule` map, unique keys, `interval` in seconds (max 604800) —
`configuration.md:44-68`.

**Packs:** "Configuration supports sets, called packs, of queries…" with `discovery`, `platform`,
`version`, `shard` keys — `configuration.md:89-131`. Shipped packs: `osquery@d9db97e:packs/`
(`windows-attacks.conf`, `incident-response.conf`, `ossec-rootkit.conf`, `it-compliance.conf`,
`windows-hardening.conf`, …).

**Decorators:** three types `load` / `always` / `interval`; results appended to each log line under
a `decorations` top-level key — `configuration.md:466-541`.

Doc URL (fetched, HTTP 200): https://osquery.readthedocs.io/en/latest/deployment/file-integrity-monitoring/
— the wiki is served at `osquery.readthedocs.io/en/latest/…` (`index.md:40`).

## OSQUERY-2 — File Integrity Monitoring

**Confirmed, and platform-split (a Windows-relevant detail):**

> "File integrity monitoring (FIM) is available for Linux (in `file_events`, using the inotify
> subsystem, and in `process_file_events` using the Audit subsystem), **Windows (in
> `ntfs_journal_events`, using NTFS Journaling)** and macOS (in `file_events`, using FSEvents)."
> — https://osquery.readthedocs.io/en/latest/deployment/file-integrity-monitoring/ (fetched); same
> text at `osquery@d9db97e:docs/wiki/deployment/file-integrity-monitoring.md:3`

Mechanics (all from that page):
- Paths come from config: `file_paths` (categories), `exclude_paths`, optional `file_paths_query`;
  fnmatch/`%`/`%%` wildcards (lines 5-7).
- Disabled by default; enable with `--disable_events=false` **and** `--enable_file_events=true`
  (Linux/macOS) or `--enable_ntfs_event_publisher=true` (Windows) (line 9).
- Three config elements: scheduled `file_events` query + `file_paths` + `exclude_paths` (line 22).
- "events are always recorded in real time; the interval is just how often the already recorded
  events will be logged" (line 24).
- On event: md5/sha1/sha256 calculated if possible (line 97); sample event JSON (lines 99-110) with
  `action`, `category`, `target_path`, `transaction_id`.
- Table specs: `description("Track time/action changes to files specified in configuration data.")`
  — `osquery@d9db97e:specs/posix/file_events.table`, `specs/windows/ntfs_journal_events.table`.

**Read-only?** The docs describe FIM *only* as event generation + hashing; there is **no
block/quarantine/enforce option** anywhere in the wiki (verified by grepping
`block|quarantine|enforce` across `docs/wiki/**/*.md` — only unrelated hits: AppArmor "blocking
osquery", `carver_block_size`, CIDR `in_cidr_block`). ⇒ **osquery FIM is observational/read-only in
effect; no enforcement mechanism exists** (negative claim verified by exhaustive grep of the docs
tree at this commit).

## OSQUERY-3 — Persistence / startup artifact tables (~13)

Table docs: `https://osquery.io/schema/` (cited by `using-osqueryi.md:7` and
`creating-tables.md:7`). ⚠️ The schema site is a JavaScript SPA — no readable body returned to the
fetch, so per-table `description()` text below is quoted from the spec files (the authoritative
source).

| # | Table | Platform | Description (verbatim from spec) | Source |
|---|---|---|---|---|
| 1 | `processes` | all | "All running processes on the host system." | `specs/processes.table` |
| 2 | `services` | Windows | "Lists all installed Windows services and their relevant data." | `specs/windows/services.table` |
| 3 | `listening_ports` | all | "Processes with listening (bound) network sockets/ports." | `specs/listening_ports.table` |
| 4 | `logged_in_users` | all | "Users with an active shell on the system." | `specs/logged_in_users.table` |
| 5 | `crontab` | POSIX | "Line parsed values from system and user cron/tab." | `specs/posix/crontab.table` |
| 6 | `startup_items` | all | "Applications and binaries set as startup items." | `specs/startup_items.table` |
| 7 | `scheduled_tasks` | Windows | "Lists all of the tasks in the Windows task scheduler." | `specs/windows/scheduled_tasks.table` |
| 8 | `registry` | Windows | "All of the Windows registry hives." | `specs/windows/registry.table` |
| 9 | `users` | all | "Local user accounts (including domain accounts that have logged on locally (Windows))." | `specs/users.table` |
| 10 | `autoexec` | Windows | Aggregate of autorun executables. | `specs/windows/autoexec.table` |
| 11 | `prefetch` | Windows | "Prefetch files show metadata related to file execution." | `specs/windows/prefetch.table` |
| 12 | `windows_eventlog` | Windows | "Table for querying all recorded Windows event logs." | `specs/windows/windows_eventlog.table` |
| 13 | `wmi_event_filters` | Windows | "Lists WMI event filters." | `specs/windows/wmi_event_filters.table` |

All paths are `osquery@d9db97e:<path>`.

## OSQUERY-4 — Offline / historical analysis

**Answer: partially — with hard limits.**

Confirmed:
1. **`osqueryi` runs standalone against the live OS** — "completely standalone, does not communicate
   with a daemon, and does not need to run as an administrator" (`using-osqueryi.md:3`). Scriptable:
   `osqueryi --json "SELECT …"` or piped stdin (`using-osqueryi.md:36-46`).
2. **Attach to an existing on-disk event DB:** "`osqueryi` uses an in-memory database by default. To
   connect to an existing events database, use the flag `--database_path=/var/osquery/osquery.db`
   (only one process may attach to the database…)" (`using-osqueryi.md:113`). ⚠️ That DB holds
   *osquery's own* differential results/event buffer, **not** a snapshot of the OS
   (`cli-flags.md:172-174`).
3. **Point-in-time reads of persisted OS stores:** `windows_eventlog` — "Table for querying all
   recorded Windows event logs" with `channel`/`xpath`/`timestamp` filters
   (`specs/windows/windows_eventlog.table`); `file`/`hash` utility tables read arbitrary paths
   (`specs/utility/file.table` — "Interactive filesystem attributes and metadata.").
4. **Auto Table Construction — expose any local SQLite DB as a table:** "Osquery can be configured
   to expose local SQLite databases as tables without having to write custom extensions"
   (`configuration.md:543-564`, `auto_table_construction`).

Not documented (⇒ **UNVERIFIED / does not exist**):
- No "load a snapshot/exported DB and query OS state offline" mode. Tables are generated at query
  time from the running OS (`creating-tables.md:17`, `pubsub-framework.md:3-15`).
- **No historical Windows Event Log import:** `windows_events` is a *live subscriber*
  (`attributes(event_subscriber=True)` in `specs/windows/windows_events.table`), not a loader of past
  logs. No documented way to feed archived `.evtx` into osquery — **UNVERIFIED**.
- Event tables are empty in the shell by default: "When using the `osqueryi` shell, these tables
  will mostly remain empty… event loops start and stop with the process" + "Event publishers are not
  started by default. To enable event-based tables, use `--disable_events=false`"
  (`pubsub-framework.md:15`, `using-osqueryi.md:111`).

## OSQUERY-5 — Windows support level + native event-log subscription

**First-class supported platform:**
- "Available for Linux, macOS, and Windows." — `osquery@d9db97e:README.md`.
- Full install guide: `docs/wiki/installation/install-windows.md` (Chocolatey, MSI, `SYSTEM`
  service, `--install`).
- Windows artifacts in release 5.23.1: `osquery-5.23.1.msi`, `.windows_x86_64.zip`,
  `.windows_arm64.zip`, `osquery.5.23.1.nupkg` — https://api.github.com/repos/osquery/osquery/releases?per_page=5 (fetched).

**Native Windows Event Log subscription — exact doc page:** https://osquery.readthedocs.io/en/latest/installation/cli-flags/
(`osquery@d9db97e:docs/wiki/installation/cli-flags.md`, "Windows-only events control flags"):
```
--enable_windows_events_publisher       Enables the Windows events publisher
--enable_windows_events_subscriber      Enables Windows Event Log events
--windows_event_channels=System,Application,Setup,Security
```
Plus: "each category of evented data must also be enabled individually… Note that an event
publisher within osquery subscribes to events *from the OS*"; PowerShell script-block logging via
`--windows_event_channels=Microsoft-Windows-PowerShell/Operational`. Related:
`--enable_ntfs_event_publisher`, `--enable_powershell_events_subscriber`, umbrella
`--disable_events=false`.

**Manifest install requirement:** "In order to enable support for the Windows Event Log, you first
have to install the manifest file… `wevtutil im "C:\Program Files\osquery\osquery.man"`"
(`docs/wiki/installation/install-windows.md:96-108`).

**⚠️ `https://osquery.io/stabilities` → HTTP 404** (fetched). Current table reference is
https://osquery.io/schema (per `README.md` "Table Schema" and `using-osqueryi.md:7`); the schema
site is a JS app and returned no readable body ⇒ **per-table stability labels: UNVERIFIED.**

## OSQUERY-6 — Licence, release 5.23.1, maintenance

- **Licence — NOT "GPL-2.0 with OpenSSL exception".** `osquery@d9db97e:LICENSE` →
  `SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only` … "you are free to choose one of the
  provided licenses" (dual: `LICENSE-Apache-2.0` + `LICENSE-GPL-2.0`).
  `LICENSE-GPL-2.0` is **verbatim GPLv2 text (340 lines)**; searching it for `OpenSSL|exception`
  yields only the GPL's generic interactive-clause boilerplate — **no OpenSSL exception at this
  commit.**
- **Latest release 5.23.1 — 2026-06-24.** https://api.github.com/repos/osquery/osquery/releases?per_page=5 (fetched):
  `"tag_name": "5.23.1"`, `"published_at": "2026-06-24T14:57:05Z"`, body "This is a bug and security
  fix release" (heap-buffer-overflow fixes in Windows `processes` and `authenticode` tables).
- **Maintenance — osquery Technical Steering Committee (TSC), not Fleet:**
  > "As defined by the [osquery charter](https://github.com/osquery/foundation/blob/master/CHARTER.md),
  > the Technical Steering Committee (or TSC for short) is responsible for oversight of the osquery
  > project… Current Members: Alessandro, Nick, seph, Sharvil, Teddy, Victor, Zach. The Technical
  > Steering Commit is chaired by seph."
  > — `osquery@d9db97e:CONTRIBUTING.md:242-263`
  `CODEOWNERS`: `* @osquery/osquery-committers @osquery/technical-steering-committee`.
  Release 5.23.1 authored by GitHub user `zwass` (a TSC member) per the releases API.
  **Fleet is not the maintainer** — README lists it only as one of many third-party fleet managers:
  "The osquery project does not endorse, recommend, or test these." (`README.md:113-119`).

---

# VELOCIRAPTOR

## VELOCIRAPTOR-1 — What it is; VQL's role

**Client/server DFIR platform.** Official docs: https://docs.velociraptor.app/ (fetched; footer
"Brought to you by Rapid7, © 2026").

> "Velociraptor is a unique, enterprise grade, open-source platform for endpoint monitoring, digital
> forensic and cyber response…"
> — https://docs.velociraptor.app/docs/overview/ (`velociraptor-docs@95588f0:content/docs/overview/_index.md:13-16`)

Client/server terminology: "the Velociraptor server gives the client the VQL to run…"
(`velociraptor-docs@95588f0:content/docs/deployment/offline_collections/_index.md:20-23`).

**VQL's role — query + detection + artifact definition** (fetched page https://docs.velociraptor.app/docs/vql/):

> "VQL is central to the design and functionality of Velociraptor… A query language can accelerate
> the time it takes to discover an IOC, design a rule to detect it, and then deploy the detection at
> scale… a DFIR investigator can… write relevant VQL queries, **package them in an artifact**, and
> hunt for the artifact across the entire deployment."

> "At it's core Velociraptor is simply a VQL engine. It processes a VQL query producing a series of
> rows and sends those rows to the server."
> — `velociraptor-docs@95588f0:content/docs/artifacts/_index.md:28-29`

Detection role: "By tapping into live event sources, such as Event Tracing for Windows (ETW) or
eBPF on Linux, and utilizing Sigma rules, Velociraptor's detection engine can identify suspicious
activity in real time." — `content/docs/overview/_index.md`.

## VELOCIRAPTOR-2 — Artifacts are YAML; verbatim example

**YAML confirmed:** "Velociraptor Artifacts are structured YAML files that encapsulate VQL
queries…" — `velociraptor-docs@95588f0:content/docs/artifacts/_index.md:7-9`; "package one or more
VQL queries and related data into a human-readable YAML file" (lines 33-35).

**423 artifact YAML files** under `velociraptor@fa9a5b4:artifacts/definitions/` (counted from clone).

Verbatim, 15 lines — `velociraptor@fa9a5b4:artifacts/definitions/Windows/Sys/CertificateAuthorities.yaml`:
```yaml
name: Windows.Sys.CertificateAuthorities
description: |
  Enumerates certificate authorities from Windows certificate stores.

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    query: |
        SELECT Store, IsCA, Subject,
               encode(string=SubjectKeyId, type='hex') AS SubjectKeyId,
               encode(string=AuthorityKeyId, type='hex') AS AuthorityKeyId,
               Issuer, KeyUsageString,
               IsSelfSigned, SHA1, SignatureAlgorithm, PublicKeyAlgorithm, KeyStrength,
               NotBefore, NotAfter, HexSerialNumber
        FROM certificates()
```
(Second, pack-style example: `artifacts/definitions/Windows/Packs/Persistence.yaml`, 20 lines —
omitted for the ≤15-line limit.)

## VELOCIRAPTOR-3 — Offline capability (uploaded/collected files, no live client)

**Yes — three documented mechanisms:**

1. **Offline collector:** "Velociraptor is capable of creating special binaries that are
   pre-configured to automatically collect a selected set of artifacts. We call these binaries
   **offline collectors**… Instead of sending their data back to the server they write it to a local
   collection container file" — https://docs.velociraptor.app/docs/deployment/offline_collections/
   (`velociraptor-docs@95588f0:content/docs/deployment/offline_collections/_index.md:33-40`).
   CLI: `collector_cmd = app.Command("collector", "Build an offline collector")`
   (`velociraptor@fa9a5b4:bin/offline.go:23`). **Caveat (verbatim):** "The endpoint needs to have a
   running operating system" (lines 44-47).

2. **Dead Disk Analysis / import a collection container, then run artifacts on the uploaded files.**
   Two post-import options documented: "Run artifacts on the collected files *after* importing the
   collection… The remapping is generated and applied to a notebook cell's scope using VQL, along
   with running the chosen artifacts." —
   https://docs.velociraptor.app/docs/deployment/offline_collections/collection_data/
   (`velociraptor-docs@95588f0:content/docs/deployment/offline_collections/collection_data/index.md`).
   Disk images too: "Velociraptor's remapping feature makes it possible to impersonate a live system
   and provide access to the disk image as if it was a real disk attached to the client" —
   https://docs.velociraptor.app/docs/forensic/deaddisk/
   (`…/forensic/deaddisk/_index.md:37-41`).
   Code: dedicated accessor for reading collector zips — "An accessor for reading collector
   containers." (`velociraptor@fa9a5b4:accessors/collector/collector.go:26`); `deaddisk` CLI command
   (docs nav: `/docs/cli/commands/deaddisk/`).

3. **Notebooks:** "interactive collaborative workspaces that combine markdown text with live VQL
   queries… post-process the results of hunts and collections" —
   https://docs.velociraptor.app/docs/notebooks/ (`content/docs/notebooks/_index.md:13-16`).

**"rummager": UNVERIFIED** — zero hits for `rummager` in `velociraptor@fa9a5b4` (`*.go`, `*.md`,
`*.yaml`) and zero in the docs clone. No such feature/name found.

## VELOCIRAPTOR-4 — Sigma support (native)

**Yes, native.**
- VQL plugin `sigma()` with args `rules`, `log_sources`, `field_mapping`, `debug`, `rule_filter`,
  `default_details`; comment "/* This provides support for direct evaluation of sigma rules. */" —
  `velociraptor@fa9a5b4:vql/sigma/sigma.go:14-30`; registered via `vql/plugins.go:44`. Companion
  `sigma_log_sources()` (`sigma.go:48`).
- Whole subsystem: `velociraptor@fa9a5b4:vql/sigma/` (`evaluator/`, `logsource.go`,
  `correlation.go`, `tracker.go`).
- Docs: published **Sigma Tracker** debug page at
  https://docs.velociraptor.app/docs/troubleshooting/debugging/global/vql/plugins/sigma/ (present in
  the nav of the fetched https://docs.velociraptor.app/docs/vql/ page). A dedicated "Sigma rules"
  page exists in the docs repo but is **`draft: true`**
  (`velociraptor-docs@95588f0:content/docs/sigma/index.md:6`) and is *not* in the live nav ⇒
  unpublished; its content does say "Velociraptor supports the Sigma rule format, allowing you to
  leverage pre-built community rules…".
- Shipped artifact: `velociraptor@fa9a5b4:artifacts/definitions/Notebooks/Sigma/Studio.yaml`.
- Overview: "utilizing `Sigma` rules, Velociraptor's detection engine can identify suspicious
  activity in real time" (`content/docs/overview/_index.md`).

## VELOCIRAPTOR-5 — FIM capability: watch plugins + file scanning

**Watch/event plugins registered in source (`velociraptor@fa9a5b4`):**

| Plugin | Path |
|---|---|
| `watch_etw` | `vql/windows/etw/watch_etw.go:197` (Windows) |
| `watch_ebpf` | Linux (`vql/unimplemented_test.go:33-36` shows `watch_etw`/`watch_ebpf` split by architecture) |
| `watch_syslog` | `vql/parsers/syslog/scanner.go:327` |
| `watch_auditd` | `vql/parsers/syslog/auditd.go:127` |
| `watch_evtx` | `vql/parsers/event_logs/evtx.go:227` |
| `watch_journald` | `vql/parsers/journald/journald.go:162` |
| `watch_usn` (NTFS USN journal) | `vql/parsers/usn/usn.go:313` |
| `watch_jsonl` / `watch_csv` | `vql/parsers/json.go:781`, `vql/parsers/csv/csv.go:329` |
| `watch_monitoring` (server-side) | `vql/server/flows/monitoring.go:271` |

**File-integrity artifact (ETW-based, Windows):** `artifacts/definitions/Windows/ETW/KernelFile.yaml`
— `type: CLIENT_EVENT`, "Monitors file create, delete, open, and rename events via the Kernel-File
ETW provider… NOTE: We can only attach to this provider when running as NT_USER/SYSTEM." (Also
`Windows/ETW/Registry.yaml`, `Windows/ETW/KernelProcess.yaml`, `Windows/Events/TrackProcesses.yaml`.)

**File scanning — hashes:** `hash(path=Exe)` used in `artifacts/definitions/Linux/Sys/Pslist.yaml`;
dedicated `artifacts/definitions/Generic/Detection/HashHunter.yaml` and
`Generic/Forensic/HashLookup.yaml`.
**YARA:** `artifacts/definitions/Generic/Detection/Yara/Glob.yaml` (parameters `YaraUrl`, `YaraRule`
of `type: yara`, calls `yara(rules=…, files=OSPath, context=…)`), plus `Yara/Zip.yaml`. Docs:
`velociraptor-docs@95588f0:content/docs/vql/yara/`.

## VELOCIRAPTOR-6 — Licence, 0.77.3, commercial model

- **AGPL-3.0 confirmed:** `velociraptor@fa9a5b4:LICENSE` opens "GNU AFFERO GENERAL PUBLIC LICENSE /
  Version 3, 19 November 2007".
- **Latest release 0.77.3 — 2026-10-05.** https://github.com/Velocidex/velociraptor/releases.atom
  (fetched): entry `v0.77.3`, `<updated>2026-10-05T12:30:41Z</updated>`, "This release is a bug fix
  release and addresses the CVEs published in the 0.77.3 release cycle." Corroborated by the live
  docs banner "Please update to the latest release **0.77.3** to address Multiple CVEs" on
  https://docs.velociraptor.app/docs/vql/. (Prior: v0.77.2 = 2026-09-25.)
- **Commercial model — Rapid7 since 2021:**
  > "Boston, MA — April 21, 2021 … Rapid7, Inc. (NASDAQ: RPD) … today announced it has acquired
  > Velociraptor… 'Velociraptor will greatly benefit from the investment, experience, and resources
  > Rapid7 can bring…' — Velociraptor Founder, Mike Cohen, who will also join Rapid7."
  > — https://www.rapid7.com/about/press-releases/rapid7-acquires-digital-forensics-and-incident-response-open-source-project-velociraptor (fetched)
  Rapid7 product page: https://www.rapid7.com/products/velociraptor. Docs nav links "Rapid7 Docs →
  https://docs.rapid7.com/insightidr/velociraptor-integration"; deployment page: "Using Velociraptor
  integrated with Rapid7 InsightIDR? … These deployment steps apply to open source Velociraptor
  only." (`content/docs/deployment/_index.md:25-28`). Source headers carry "Copyright (C) 2019-2025
  Rapid7 Inc." (e.g. `velociraptor@fa9a5b4:accessors/ntfs/mft.go:3`).
- **Open-source support stance:** "Ultimately, Velociraptor is an open source project maintained and
  run by the community." — https://docs.velociraptor.app/docs/overview/support/
  (`content/docs/overview/support/index.md:17-19`; also documents semantic versioning, ~2-week RC).
- **"Cloud free tier": UNVERIFIED.** Searched `velociraptor-docs@95588f0:content/docs/**` for
  `free tier|cloud service|Velociraptor Cloud|managed service|SaaS` → **zero hits.** No cloud
  free-tier offering documented on the official docs site.

## VELOCIRAPTOR-7 — Documented performance claims

Source: https://docs.velociraptor.app/docs/deployment/resources/
(`velociraptor-docs@95588f0:content/docs/deployment/resources/index.md`), verbatim:

> "We typically deploy on AWS a `t2.large` (8Gb 2 core VM) to support up to 10k endpoints. Below is
> a deployment we have that is mostly idle. CPU load is in the range 10-20% of one core, memory <
> 400mb when idle. This is a typical medium sized deployment of around 2.5k endpoints. Load
> typically increases linearly - so a 5,000 endpoint deployment might use twice the CPU load etc.
> For 20,000 endpoint deployment a larger size VM would be required."

> "even hunts that intuitively seem expensive are actually very light on the server. For example,
> consider an artifact that applies a Yara signature to many files on the endpoints. This might
> search through many Terabytes of data collectively on all endpoints, but if the signature is good
> will only report few relevant results."

Also: file-based datastore only — "With the present architecture, Velociraptor only supports a file
based data store… inherently limited to a single machine." Default `Frontend.expected_clients` =
10,000 endpoints (RSA key cache).

---

# TETRAGON

## TETRAGON-1 — What it does; "security events" vs "tracing"; Triton

**eBPF kernel telemetry, confirmed:**
> "Cilium Tetragon component enables powerful realtime, eBPF-based Security Observability and
> Runtime Enforcement. Tetragon detects and is able to react to security-significant events, such as
> * Process execution events * System call activity * I/O activity including network & file access"
> — https://tetragon.io/docs/overview/ (`tetragon@1ac2010:docs/content/en/docs/overview/_index.md:6-14`;
> identical text in `README.md`)

**Filtering happens *in* the kernel:** "Tetragon applies policy and filtering directly in eBPF in the
kernel. It performs the filtering, blocking, and reacting to events directly in the kernel instead
of sending events to a user space agent." — `docs/content/en/docs/overview/_index.md:31-34`.

**Event delivery (the "security events" surface):** "Tetragon's events are exposed to the system
through either the gRPC endpoint or JSON logs." — https://tetragon.io/docs/concepts/events/
(`tetragon@1ac2010:docs/content/en/docs/concepts/events.md:7-8`); sample `process_exec` JSON at
lines 20-70.

**"security events" vs "tracing":** both terms are used; "tracing" is the mechanism
(TracingPolicy/hooks), "security events" the output. E.g. "Tetragon records security events, they
obtain comprehensive insight into the…" (`threat-model/_index.md:224`); "Tetragon is able to observe
various security events and even enforce security…" (`use-cases/security-profiles/_index.md:7`);
while `TracingPolicy` is defined as "a user-configurable Kubernetes custom resource (CR) that allows
users to trace arbitrary events in the kernel and optionally define actions to take on a match"
(`concepts/tracing-policy/_index.md:7-9`). **No formal glossary distinguishes the two terms — any
hard "X vs Y" taxonomy = UNVERIFIED.**

**"Triton": UNVERIFIED — no such thing found.** Searches for `Triton` across `tetragon@1ac2010`
(all file types) and `docs/content/**/*.md` returned **zero matches**. No Tetragon component called
"Triton" exists.

## TETRAGON-2 — Rule/policy format + verbatim example

**Format:** YAML Kubernetes CRD, `apiVersion: cilium.io/v1alpha1`, `kind: TracingPolicy`.

> "Tetragon's `TracingPolicy` is a user-configurable Kubernetes custom resource (CR)… Policies
> consist of a hook point (kprobes, tracepoints, and uprobes are supported), and selectors for
> in-kernel filtering and specifying actions." — `tetragon@1ac2010:docs/content/en/docs/concepts/tracing-policy/_index.md:7-10`
> …works outside Kubernetes too: "they can also be used in non-Kubernetes environments" via the
> `tetra` gRPC CLI or `--tracing-policy` / `--tracing-policy-dir` flags (same file, lines 18-21).

**Resource kinds:** `TracingPolicy` and `TracingPolicyNamespaced` —
`tetragon@1ac2010:pkg/k8s/apis/cilium.io/v1alpha1/tracing_policy_types.go:22,34`; confirmed in the
generated reference: "Resource Types: - TracingPolicy - TracingPolicyNamespaced"
(`docs/content/en/docs/reference/tracing-policy.md:26-29`).

**`CiliumTracingPolicy`:** one surviving mention — "The `selector` semantics of the
`CiliumTracingPolicy` follows the standard Kubernetes semantics…"
(`docs/content/en/docs/concepts/tracing-policy/selectors.md:1872`). No CRD kind and no examples with
`kind: CiliumTracingPolicy` in `examples/` ⇒ appears to be a **legacy/renamed kind; UNVERIFIED-legacy.**

Verbatim, 12 lines — `tetragon@1ac2010:examples/tracingpolicy/sys_setuid.yaml`:
```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "syscalls"
spec:
  kprobes:
  # int setuid(uid_t uid);
  - call: "sys_setuid"
    syscall: true
    args:
    - index: 0
      type: "int"
```
(Richer file-FIM policy, 170 lines: `examples/quickstart/file_monitoring.yaml`, referenced by
`docs/content/en/docs/getting-started/file-events.md:15`.)

## TETRAGON-3 — Does Tetragon run on Windows?

**Documented support = Linux only. Agent Windows status = in-progress/experimental, NOT documented
as supported.**

Linux-only evidence:
- "What is the minimum Linux kernel version to run Tetragon? Tetragon needs Linux kernel version
  4.19 or greater… Note that Tetragon needs BTF support" — https://tetragon.io/docs/installation/faq
  (`tetragon@1ac2010:docs/content/en/docs/installation/faq.md:7-19`). All requirements
  (kprobe/tracepoint/BTF/CGROUP_BPF) are Linux kernel config options.
- The **only** Windows items in the entire docs tree are the `tetra` CLI binaries:
  `tetra-windows-amd64.tar.gz` / `tetra-windows-arm64.tar.gz` —
  `docs/content/en/docs/installation/tetra-cli.md:72-80` (verified by grepping `docs/content` +
  `examples` for "Windows" → only those hits).

Upstream Windows work exists but is not productised:
- `.github/workflows/windows-build-smoke-test.yml` — jobs `windows-ebpf-prog-build` ("Build Windows
  ebpf programs", `runs-on: windows-2022`, builds `bpf/windows/process_monitor.c`) and
  `windows-tetragon-build` ("Build, Unit Test and Upload Windows Tetragon and Tetra Binaries",
  `runs-on: windows-2025`, `GOOS: windows`).
- Source tree contains `tetragon@1ac2010:bpf/windows/process_monitor.c`.
- v1.7.1 release notes: "Improved the reliability of Windows CI…", "Switched Windows CI to
  `microsoft/ntosebpfext` repository" (https://github.com/cilium/tetragon/releases.atom, fetched).

**Verdict:** not supported per official docs; active upstream experimentation against Microsoft's
NT-EbPF extension. **Any claim that "Tetragon runs on Windows today" = UNVERIFIED.**

## TETRAGON-4 — Offline / historical analysis; exported event format

**Live-only; no historical/offline analysis mode documented.**
- Live kernel tracing: "Tetragon is a runtime security enforcement and observability tool… applies
  policy and filtering directly in eBPF in the kernel" (`overview/_index.md:31-34`). Output is a
  **stream**: "Tetragon exposes the execution events over JSON logs and GRPC stream"
  (`getting-started/execution.md:12-13`); observe with `tetra getevents -o compact` (line 24).
- Searched all `docs/content/**/*.md` for `historical|replay|retention` → only 2 unrelated
  threat-model hits (`threat-model/_index.md:234,401`). **No documented way to analyse historical
  data or re-run policies against past events ⇒ UNVERIFIED / does not exist.**

**Exported event format (this *does* exist):** JSON event log file(s) with rotation/allowlist:
- `export-filename`: "`/etc/tetragon/tetragon.conf.d/export-filename` with a corresponding value of:
  `/var/log/tetragon/tetragon.log`" — https://tetragon.io/docs/reference/daemon-configuration
  (`tetragon@1ac2010:docs/content/en/docs/reference/daemon-configuration.md:96-100`).
- Full option set, `tetragon@1ac2010:examples/configuration/tetragon.yaml:17-31`:
  `enable-export-aggregation`, `export-aggregation-buffer-size: 10000`,
  `export-aggregation-window-size: 15s`, `export-allowlist`, `export-denylist`,
  `export-file-compress`, `export-file-max-backups: 5`, `export-file-max-size-mb: 10`,
  `export-file-rotation-interval: 0s`, `export-filename`.
- gRPC API reference: https://tetragon.io/docs/reference/grpc-api (generated from
  `api/v1/tetragon` protobuf).
- **Caveat for Sentinel:** these are append/rotate log files of a live stream — *not* a queryable
  store, and nothing in the docs offers query/replay over them.

## TETRAGON-5 — Licence, v1.7.1, maintenance

- **Apache-2.0 confirmed:** `tetragon@1ac2010:LICENSE` → "Apache License / Version 2.0, January
  2004". GitHub reports "Apache-2.0 license". README also carries BSD-2-Clause and GPL-2.0 badges
  alongside Apache-2.0 (`README.md:8-10`) — these reflect permissive/copyleft components (e.g.
  eBPF/BPF bits), **not** a change of the top-level licence. **Exact scope of the BSD/GPL-badged
  components: UNVERIFIED** (not audited file-by-file).
- **Latest release v1.7.1 — 2026-08-25.** https://github.com/cilium/tetragon/releases.atom (fetched):
  entry `v1.7.1`, `<updated>2026-08-25T11:41:49Z</updated>`, "total: 84 commits, prs: 52".
  (v1.7.0 = 2026-04-29; `v1.8.0-pre.0` also tagged 2026-04-29 as "Starting v1.8 development".)
- **Maintenance — Cilium project / Isovalent at Cisco.**
  - `tetragon@1ac2010:MAINTAINERS.md`: "Maintainers can be found in the
    [Cilium Maintainers file](https://github.com/cilium/community/blob/main/roles/Maintainers.md)".
  - Release-note authors use `@isovalent.com` addresses and `will-isovalent` / `ygvalent` handles
    (release atom, fetched).
  - Corporate ownership (fetched): "SAN JOSE, Calif., April 12, 2024 — Cisco (NASDAQ: CSCO) today
    announced the completion of the acquisition of Isovalent… Cisco is committed to nurturing and
    supporting eBPF, Cilium, Tetragon, and cloud native open source communities… The Isovalent team
    joins the Cisco Security Business Group." —
    https://investor.cisco.com/news/news-details/2024/Cisco-Completes-Acquisition-of-Isovalent-to-Define-the-Future-of-Multicloud-Networking-and-Security/default.aspx

---

# SUMMARY OF UNVERIFIED / NEGATIVE FINDINGS

| # | Item | Status |
|---|---|---|
| OSQ-1/3 | `osquery.io/stabilities` | **404** (fetched). Use `osquery.io/schema`; per-table stability labels **UNVERIFIED** (JS SPA, no body returned). |
| OSQ-2 | FIM "read-only" wording | No explicit wording, but **no block/quarantine/enforce option exists** in the docs tree (exhaustive grep) ⇒ observational only. |
| OSQ-4 | Offline snapshot/exported-DB querying of OS state | **Not documented ⇒ does not exist.** Only `--database_path` (osquery's own differential store), `windows_eventlog` (on-disk EVTX), `auto_table_construction` (local SQLite), `file`/`hash`. |
| OSQ-4 | Loading historical Windows Event Logs into `windows_events` | **UNVERIFIED — no such feature.** `windows_events` is a live subscriber. |
| OSQ-6 | "GPL-2.0 with OpenSSL exception" | **False at this commit.** Dual `Apache-2.0 OR GPL-2.0-only`; `LICENSE-GPL-2.0` is verbatim GPLv2 with no OpenSSL clause. |
| VEL-3 | "rummager" | **UNVERIFIED — zero hits** in code or docs. |
| VEL-6 | Cloud free tier | **UNVERIFIED — zero hits** in official docs. |
| VEL-4 | Dedicated Sigma docs page | Exists in repo but `draft: true` and unpublished; published page is the *Sigma Tracker* debug page. |
| VEL-6 | "Velocidex company" as current owner | **Outdated:** Rapid7 acquired Velociraptor 2021-04-21 (press release fetched). |
| TET-1 | "Triton" | **UNVERIFIED — zero matches** anywhere in the repo or docs. |
| TET-1 | Formal "security events vs tracing" definition | Both terms used, **no glossary distinction documented.** |
| TET-2 | `CiliumTracingPolicy` | **Legacy name**; current CRD kinds are `TracingPolicy` / `TracingPolicyNamespaced`. |
| TET-3 | Tetragon agent on Windows | **Not supported per docs** (Linux ≥4.19 + BTF). Windows CI + `bpf/windows/process_monitor.c` show in-progress experimental work ⇒ any "runs on Windows" claim = **UNVERIFIED**. |
| TET-4 | Historical/offline replay analysis | **Not documented ⇒ does not exist.** Only live streams + rotating JSON export files. |
| TET-5 | Scope of BSD/GPL badges in README | **UNVERIFIED** (not audited). |
