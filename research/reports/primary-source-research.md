# Primary-Source Research: FIM / SCAP / YARA / Suricata / IOC Formats

Research date: **2026-10-08**. Every claim below is cited to an exact URL or `repo@commit:path`.
Local clones are under `C:\Users\dhruv\AppData\Local\Temp\opencode\`. Verbatim snippets are ≤15 lines.
Anything not confirmed against a primary source is explicitly marked **UNVERIFIED**.

---

## AIDE

### AIDE-1 — Configuration-file / FIM rule semantics

**File format & basic options** — `aide@b4fc3aee8ad7da205a7d5e8f27c5f99a8936be40:doc/aide.conf.5` (online mirror: https://www.aide.ca/manpages/aide.5.html):

- Config is plain text, one statement per line, `#` and `%%` start comments (FILE FORMAT section, `doc/aide.conf.5:11-26`).
- Key config options: `database_in=file:/var/lib/aide/aide.db` (and `database_out`, `database_new`, `report_url`, `grouped`, `numerical_uid`) — `doc/aide.conf.5:34-45`.

**Rule grammar (RULES section, `doc/aide.conf.5:439-492`):**

- Regular rule: `/regex attributes` — selects matching files, recursively.
- Negative recursive rule: `!/regex` — ignore matching files *and their descendants*.
- Negative non-recursive rule: `- /regex` (`-/regex`) — ignore the entry but still descend (added in v0.19).
- Equals rule: `=/regex attributes` — matches only the exact path, never children.
- The regex must start with `/`; `^` is implicit at the start of the pattern.
- Verbatim examples (man page EXAMPLES, `doc/aide.conf.5:1085-1117`):

```
/ R                 -> all files on your machine (a fully qualified config on its own line)
!/dev$              -> ignore the /dev directory structure
=/foo R             -> only /foo and /foobar, none of their children
=/foo/ R            -> /foo and its children, not grandchildren
/run d R-m-c-i      -> per-file-type rules
```

**There is NO `select` keyword in AIDE.** `grep -c 'select' doc/aide.conf.5` matches only
`#include <sys/select.h>` in example code (1 hit, header include). Rule selectors are the regex forms above.

**Attribute-expression concatenation (`p+`, `+`)**: group definitions concatenate attribute names,
e.g. verbatim from `doc/aide.conf.5:1120-1136`:

```
OwnerMode = p+u+g+ftype
Size      = s+b
InodeData = OwnerMode+n+i+Size+l+X
Full      = ftype+p+l+u+g+s+m+c+a+i+b+n+H+X
/ 0 Full            <- catch-all rule at the end of the rule list
```

**Groups** (GROUPS, `doc/aide.conf.5:401-435`): built-in groups `R`, `L`, `>`, `H`, `X`, `E` are predefined;
user groups are defined by `Group = expression` lines and referenced from rules.

**Macros / conditionals** (MACRO LINES, `doc/aide.conf.5:677+`): `@@define VAR value`, `@@undef VAR`,
`@@ifdef/@@ifndef/@@else/@@endif`, `@@ifnotdef` (and the deprecated `@@if/@@endif`).

**Report options** (REPORT OPTIONS, `doc/aide.conf.5:175-270`):
`report_url=file:|stdout|syslog:<FACILITY>` (default `stdout`), `report_level`,
`report_format`. Option order matters: *"to take effect they have to be set before `report_url`"*
(`doc/aide.conf.5:220-221`).

### AIDE-2 — File types and attributes

From `aide@b4fc3ae:doc/aide.conf.5`:

- **File types** (l.569-609): `f` file, `d` directory, `l` symlink, `c` char device, `b` block device,
  `p` FIFO, `s` socket, `D` deleted file, `P` any file type (file type wildcards may be combined, e.g. `/ d,f R`).
- **Attributes** (l.870-935): `s` size, `b` block count, `m` mtime, `a` ctime, `c` inode-change time,
  `acl`, `selinux`, `xattrs`, `e2fsattrs`, `caps`. Special/composite: `S` (check for growing),
  `I`/`i` (inode), `H` (all compiled-in hash sums), `X` (compiled-in extra file attributes).
- Hash algorithms are compiled in — *"See `--version` output for the compiled in hashsums and extra groups"*
  (`doc/aide.conf.5:1140`).

### AIDE-3 — Report / diff output semantics

AIDE produces a **batch diff-style report**, not per-change alert streaming:

- Report levels (`aide@b4fc3ae:doc/aide.conf.5:224-258`): `minimal`, `summary`, `database_attributes`,
  `list_entries`, `changed_attributes` (default, added v0.17), `added_removed_attributes`, `added_removed_entries`.
- Verbatim old|new example (`doc/aide.conf.5:243-252`):

```
File: /var/lib/apt/extended_states
 Perm      : -rw-r--r--                       | -rw-------
 Uid       : 0                                | 106
```
*"The left column shows the old value (e.g. from the `database_in` database) and the right column
shows the new value (e.g. from the file system)."*

- Report formats (`doc/aide.conf.5:261-269`): `plain` (default), `json`, `ndjson` (added v0.18).
  Implementations: `aide@b4fc3ae:src/report_plain.c`, `src/report_json.c`, `src/report_ndjson.c`.
- Exit status is documented in `aide@b4fc3ae:doc/aide.1:113` (non-zero when differences are found — check
  `aide.1` EXIT STATUS block before quoting a specific code).

### AIDE-4 — Licence, release, maintenance status

- Licence: **GPL-2.0** — `aide@b4fc3ae:COPYING` begins *"GNU GENERAL PUBLIC LICENSE
  Version 2, June 1991"* (https://github.com/aide/aide/blob/master/COPYING).
- Latest release: **v0.19.4, updated 2026-08-30T16:24:12Z** per https://github.com/aide/aide/releases.atom
  (v0.19.3 was 2026-01-31). Project is actively maintained.

### AIDE-5 — Offline / mounted-image scanning, commands, database paths

- `root_prefix` is applied for both `DO_INIT` and `DO_COMPARE`, with an `opendir()` validation of the
  prefix: `aide@b4fc3ae:src/aide.c:850`. Because `--check` maps to `DO_COMPARE`
  (`src/aide.c:411`) and `--compare` maps to `DO_DIFF` (`src/aide.c:413`), the man-page note
  *"no effect in compare mode"* refers to `--compare` (database-vs-database diff), **not** `--check`.
  ⇒ `aide --init` / `aide --check --root /mnt/image` is supported for scanning an offline mounted image.
  (Flag name `--root`/`-r` should be confirmed against `doc/aide.1` OPTIONS before final use —
  **UNVERIFIED** at flag-exactness level; the `root_prefix` config option itself is verified at `src/aide.c:850`.)
- `database_in`/`database_out` accept URLs (e.g. `file:/var/lib/aide/aide.db`) — `doc/aide.conf.5:34-45`.
- Commands: `--init` (DO_INIT), `--check` (DO_COMPARE), `--compare` (DO_DIFF) — `aide@b4fc3ae:src/aide.c:411-415`.

---

## OpenSCAP

### OPENSCAP-1 — Specification definitions (primary sources)

- **XCCDF**: https://csrc.nist.gov/Projects/security-content-automation-automation-protocol/Specifications/xccdf
  (NIST SCAP Specifications → *Extensible Configuration Checklist Description Format*).
- **OVAL**: https://csrc.nist.gov/Projects/security-content-automation-protocol/Specifications/Open-Vulnerability-Assessment-Language
  — redirects to MITRE's OVAL pages; MITRE's site is now in **Archive** status and the community moved to
  https://github.com/OVAL-Community/OVAL.
- **CPE** (verbatim, https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe,
  page "Updated June 09, 2026"):

> "Common Platform Enumeration (CPE) is a standardized method of describing and identifying classes of
> applications, operating systems, and hardware devices present among an enterprise's computing assets.
> CPE names product classes rather than specific installed instances…"

  CPE 2.3 = current published version (four-spec stack); CPE 3.0 = "In early development" (same page).
- OpenSCAP's own framing of the formats: `openscap@a567a7584203801467f1326137cbe9dbad23edd4:docs/manual/manual.adoc:39-72`.

### OPENSCAP-2 — Offline scanning + Windows support

- Offline scanning is via the **`OSCAP_PROBE_ROOT` environment variable**, *not* a CLI flag
  (`--root` does not exist; `utils/oscap.c` `getopt_root` is the root-module argument parser):
  verbatim `openscap@a567a75:docs/manual/manual.adoc:1641` —

  > `OSCAP_PROBE_ROOT` — "Path to a directory which contains mounted filesystem to be evaluated.
  > Used for offline scanning."

  Also `OSCAP_EVALUATION_TARGET` (`manual.adoc:1637`). Helper wrappers set it for you:
  `utils/oscap-chroot:96-98`, `utils/oscap-vm:134`, `utils/oscap-podman:105`,
  `utils/oscap_docker_python/oscap_docker_common.py:36`; probes consume it, e.g.
  `src/OVAL/probes/unix/file_probe.c:508`.
- **Windows**: probes exist (`src/OVAL/probes/windows/` = accesstoken, registry, wmi57) but support was
  dropped — `openscap@a567a75:README.md`: *"Microsoft Windows support is officially void as of
  Febuary 1, 2022"*; `docs/windows.md`: *"The last somewhat working release for Windows is 1.3.4"*
  and core developers will not produce Windows release builds.

### OPENSCAP-3 — Profile selection (XCCDF)

Verbatim `openscap@a567a75:docs/manual/manual.adoc:297-316`:

```
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_ospp \
  --results results.xml /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml
```

- Profile IDs are XCCDF `id` values in the `xccdf_org.ssgproject.content_profile_*` namespace
  (`manual.adoc:297-316` uses `…_ospp`; `manual.adoc:1281` uses `…_common`; `manual.adoc:1907+` uses `…_cis`).
- Other useful flags seen in the manual: `--results`, `--report`, `--fetch-remote-resources`.

### OPENSCAP-4 — Licences, release, content

- OpenSCAP engine: **LGPL-2.1** — `openscap@a567a75:COPYING` (https://github.com/OpenSCAP/openscap/blob/master/COPYING).
- Latest release: **1.4.4, updated 2026-04-09T14:56:17Z** — https://github.com/OpenSCAP/openscap/releases.atom.
- SCAP content (ComplianceAsCode/content): **BSD-3-Clause** —
  https://raw.githubusercontent.com/ComplianceAsCode/content/master/LICENSE.

### OPENSCAP-5 — Wazuh SCA (not OVAL/XCCDF)

Primary source: https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/how-to-configure.html
(note: path is `sec-config-assessment`; `security-configuration-assessment` 404s).

- Policies are **Wazuh-native YAML** files (`*.yaml`/`*.yml`) named `<provider>_<policy>.yaml`, stored in
  `/var/ossec/ruleset/sca` (Linux/macOS) and `C:\Program Files (x86)\ossec-agent\ruleset\sca` (Windows).
- Each policy has `policy`, `requirements`, `variables`, `checks` (with `condition:`) and
  `rules:` blocks referencing Wazuh rule IDs (`type: 'int'`, `field:`, `regex:`, `command:`).
- Conclusion for the spec: SCA does **not** parse OVAL/XCCDF; it is a separate YAML rule language.

---

## YARA / YARA-X

### YARA-1 — Rule syntax (verbatim)

Source: `yara@5e8a8ea41f73e4e24ec91382b7e6a697097b48aa:docs/writingrules.rst` (HTML: https://yara.readthedocs.io/en/stable/writingrules.html).

Example rule (l.96-104):

```
rule ExampleRule
{
    strings:
        $text = "This program cannot be run in DOS mode"
        $hex1 = { E8 00 00 00 00 }
    condition:
        $text
}
```

- Condition keywords (l.1227-1232): `all of them`, `any of them`, `1 of ($*)`, `none of ($b*)`.
- Counting matches: `#a in (filesize-500..filesize) == 2` (l.959).
- Range membership: `$a in (0..100) and $b in (100..filesize)` (l.1009).
- `filesize > 200KB` (l.1048-1051); `include "other.yar"` directive (l.1837-1847);
  keyword list incl. `xor`, `wide`, `nocase`, `defined`, `at`, `in` (l.60-79).

### YARA-2 — Licences + latest releases

- YARA: **BSD-3-Clause** — `yara@5e8a8ea:COPYING` (https://github.com/VirusTotal/yara/blob/master/COPYING).
- YARA-X: **BSD-3-Clause** — `yara-x@ee7c4c7a01fb4e5f9028e1a6da1b24bfc53cfc11:LICENSE`.
- Latest releases (https://github.com/VirusTotal/yara/releases.atom,
  https://github.com/VirusTotal/yara-x/releases.atom):
  - **yara v4.5.8 — 2026-07-28** (atom updated 2026-07-28T07:12:15Z).
  - **yara-x v1.21.0 — 2026-09-30** (atom updated 2026-09-30T08:12:00Z; docs.rs shows the crate dated 29 Sep 2026 — timezone difference).

### YARA-3 — YARA-X positioning / compatibility

- `yara-x@ee7c4c7:README.md`: *"…intends to be faster, safer and more user-friendly. …ultimate goal is
  replacing YARA."*
- https://virustotal.github.io/yara-x/docs/intro/yara-x-vs-yara/ — performance claims (~10x faster than YARA;
  exact multiplier **UNVERIFIED** wording-wise).
- https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/ — concrete differences:
  no `#` (count) operator inside hex strings; `for`-of loops restricted to `any/all/none`; `pe.imphash()` /
  `pe.sections` behaviour differs; `import "cuckoo"` string support dropped; deprecated keywords
  (`ascii`, `fullword`) replaced; no `entrypoint`.
- docs.rs crate description (https://docs.rs/yara-x/latest/yara_x/): *"A YARA compiler and scanner
  completely written in Rust from scratch. It is 99% compatible with existing YARA rules…"*

### YARA-4 — APIs / SDKs

- C API: `yara@5e8a8ea:docs/capi.rst` — `yr_initialize()`, `yr_finalize()`, `yr_compiler_create()`,
  `yr_compiler_add_file()`, `yr_rules_scan_file()`.
- Rust crate **`yara-x`** exists: crates.io `https://crates.io/crates/yara-x`; docs
  `https://docs.rs/yara-x/latest/yara_x/` (v1.21.0, BSD-3-Clause, 100% documented);
  package defined in `yara-x@ee7c4c7:lib/Cargo.toml`; API = `Compiler` / `Scanner` / `Rules`.
- Python: **yara-python** (see AIDE-6/YARA-6 below) — PyPI `https://pypi.org/project/yara/`.

### YARA-5 — Modules — no network/fetch capability

- YARA modules (`yara@5e8a8ea:docs/modules.rst`, sources in `yara@5e8a8ea:libyara/modules/`):
  `console`, `cuckoo`, `demo`, `dex`, `dotnet`, `elf`, `hash`, `macho`, `magic`, `math`, `pe`, `string`, `time`.
  **No network/HTTP/DNS module** — rules cannot fetch data at scan time.
- YARA-X modules (`yara-x@ee7c4c7:lib/src/modules/`) include `vt`. The `vt` module
  (`lib/src/modules/vt/mod.rs`) is described as *"VirusTotal-specific module that provides additional context
  and metadata"* for content *"scanned in VirusTotal"*; its `fn main` returns `LiveHuntData::new()` —
  it reads injected live-hunt data, it performs no I/O.
  No `reqwest`/`ureq`/`hyper`/`curl` dependency appears in `yara-x@ee7c4c7:lib/Cargo.toml` or the workspace
  `Cargo.toml` (grep = no matches) ⇒ **no network fetching in the scanner**.

### YARA-6 — yara-python licence

- **Apache-2.0**, not BSD-3: https://raw.githubusercontent.com/VirusTotal/yara-python/master/LICENSE
  (Apache License 2.0 text, HTTP 200) and PyPI metadata for yara-python 4.5.4
  (`license: "Apache 2.0"`, classifier *License :: OSI Approved :: Apache Software License*) —
  https://pypi.org/pypi/yara-python/json.
- Note: yara-python *bundles* libyara, which itself is BSD-3-Clause (`yara@5e8a8ea:COPYING`).

---

## Suricata

### SURICATA-1 — Rule syntax (verbatim)

Source: https://docs.suricata.io/en/latest/rules/intro.html

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI";
  flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule";
  fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```

- Structure = **action + header + rule options** (same page).
- Actions: `alert`, `pass`, `drop`, `reject`, `rejectsrc`, `rejectdst`, `rejectboth`.
- Protocols include `ip`, `tcp`, `udp`, `icmp`, `pkthdr`, `ether`, `arp`, plus app-layer
  (`http`, `tls`, `quic`, `dns`, `smb`, `ssh`, `smtp`, … — full list on the same page; `--list-rule-protos`).
- Direction: `->`, `=>` (transactional), `<>` (both directions); there is **no `<-`**.
- Decoder-event rules (also present in-repo), e.g. `suricata@215961d67239ba2594a0d43f031829ecf710e3e9:rules/decoder-events.rules`:
  `alert pkthdr any any -> any any (msg:"SURICATA IPv4 truncated packet"; decode-event:ipv4.trunc_pkt; … sid:2200003; rev:2;)`
  (SID ranges documented in `suricata@215961d:rules/README.md`, https://sidallocation.org/).

### SURICATA-2 — Offline pcap reading

Source: https://docs.suricata.io/en/latest/manpages/suricata.html

- `-r <path>` — *"Run in pcap offline mode (replay mode) reading files from pcap file. If `<path>`
  specifies a directory, all files in that directory will be processed in order of modified time
  maintaining flow state between files."*
- Related: `--pcap-file-continuous`, `--pcap-file-recursive`, `--pcap-file-delete`, `-S <file>` (exclusive rules),
  `-s <file>` (additional rules, globbing allowed).
- Examples on the same page:
  `suricata -r /path/to/capture.pcap` and `suricata -r /pcap/to/capture.pcap -S /path/to/custom.rules`.

### SURICATA-3 — EVE JSON alert output (verbatim)

Source: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html

```json
{
  "timestamp": "2017-04-07T22:24:37.251547+0100",
  "flow_id": 586497171462735,
  "pcap_cnt": 53381,
  "event_type": "alert",
  "src_ip": "192.168.2.14",
  "src_port": 50096,
  "dest_ip": "209.53.113.5",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "allowed", "gid": 1, "signature_id": 2018358, "rev": 10,
    "signature": "ET HUNTING GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser 1",
    "category": "Potentially Bad Traffic", "severity": 2
  }
}
```

- `signature_id` = rule `sid`, `signature` = rule `msg`; `pcap_cnt` appears in pcap mode
  (same page, §"Event type: Alert").
- Output is enabled/configured via the `eve-log` output in `suricata.yaml`
  (https://docs.suricata.io/en/latest/output/eve/eve-json-output.html): `filetype: regular|syslog|unix_dgram|unix_stream|redis`,
  `types: [alert, anomaly, http, dns, tls, …]`.

### SURICATA-4 — Rule licences

- **Engine: GPL-2.0** — `suricata@215961d:LICENSE` begins *"GNU GENERAL PUBLIC LICENSE / Version 2, June 1991"*.
- Built-in `rules/*.rules` files carry **no per-file licence header** (grep for GPL/Copyright in
  `suricata@215961d:rules/*.rules` = 0 hits); they ship in the GPL-2.0 tree.
- **ET Open ruleset** (https://rules.emergingthreats.net/open/suricata-5.0/) is **mixed-licence** —
  verbatim from https://rules.emergingthreats.net/open/suricata-5.0/LICENSE:

```
#  Rules with sids 1 through 3464, and 100000000 through 100000908 are under the GPLv2.
#  Rules with sids 2000000 through 2799999 are from Emerging Threats and are covered under the BSD License
#  Copyright (c) 2003-2026, Emerging Threats
#  Rules with sids 2800000 through 2900000 are provided by Emerging Threats Pro and are covered by
#  the license provided in this distribution titled ETPRO-License.txt
```

  Index also ships `BSD-License.txt`, `gpl-2.0.txt`, `emerging-all.rules`, `version.txt`
  (files listed 2026-10-07T20:22:58Z on the directory index).

### SURICATA-5 — Latest release / maintenance

- **8.0.7 — 2026-09-15** (https://github.com/OISF/suricata/releases.atom, entry `suricata-8.0.7`
  updated 2026-09-15T13:22:14Z); 7.0.17 (EOL branch) same day; 8.0.6 = 2026-07-07.
- Release notes: https://forum.suricata.io/t/suricata-8-0-7-released/ ; docs: https://docs.suricata.io/en/suricata-8.0.7

### SURICATA-6 — Windows availability

Source: https://suricata.io/download/ (page text):

> "Suricata (Stable) version 8.0.7 was released September 15, 2026 …
> **Windows 64-bit installer: [Suricata-8.0.7-1-64bit.msi](https://www.openinfosecfoundation.org/download/windows/Suricata-8.0.7-1-64bit.msi)**"

- 7.0.17 Windows MSI also listed (EOL branch).
- Windows capture backends referenced by the man page: `WinDivert` (inline), pcap mode
  (https://docs.suricata.io/en/latest/manpages/suricata.html).

---

## IOC / CTI formats

### IOC-7 — STIX 2.1 + TAXII 2.1

**Specifications (primary):**
- STIX 2.1 latest stage: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
  — *"STIX Version 2.1 Errata 01 … 02 April 2025 … OASIS Committee Specification Draft 01"*.
  Base OASIS Standard text: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html.
  Patterning = §9 (§9.8 Examples); Indicator SDO = §4.7.
- TAXII 2.1: https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html (latest stage);
  OASIS Standard: *"TAXII Version 2.1. Edited by Bret Jordan and Drew Varner. 10 June 2021.
  OASIS Standard."* → https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html

**Reference implementation (OASIS TC Open Repository):** `oasis-open/cti-python-stix2`
- Licence: **BSD-3-Clause** (OASIS Open copyright) — `cti-python-stix2@2270361774215de49717c1a6028a80c91075b400:LICENSE`.
- Version: **3.0.2** — `stix2@…/version.py`: `__version__ = "3.0.2"`, `DEFAULT_VERSION = '2.1'`;
  released **2026-02-12** (https://github.com/oasis-open/cti-python-stix2/releases.atom).
- Indicator pattern, verbatim `README.rst:35-40`:

```python
from stix2 import Indicator
indicator = Indicator(name="File hash for malware variant",
                      indicator_types=["malicious-activity"],
                      pattern_type="stix",
                      pattern="[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']")
```

- TAXII client integration: `TAXIICollectionSource`/`Sink` over `taxii2client.Collection`
  (`cti-python-stix2@2270361:docs/guide/taxii.ipynb:547-553, 980-982`);
  TAXII datastore docs: `docs/api/datastore/stix2.datastore.taxii.rst`.

### IOC-8 — MISP

- **MISP core format spec (primary):** https://github.com/MISP/misp-rfc — *"official source of the
  specification and formats used in the MISP project."* Core format = `misp-rfc@9ee0b9ce5313dabc82724980064016d44f756030:misp-core-format/raw.md`
  (`docName = "draft-dulaunoy-misp-core-format"`, `value = "draft-20"` at `raw.md:10`;
  datatracker: https://datatracker.ietf.org/doc/draft-dulaunoy-misp-core-format/).
  Note: the repo README says "Current Internet-Draft: 16" — the draft file header (draft-20) supersedes it.
- Overview page: https://www.misp-project.org/datamodels/
  (*"MISP includes a simple and practical information sharing format expressed in JSON…"*);
  standard site: https://www.misp-standard.org/.
- Structure (verbatim `misp-core-format/raw.md:274-279`):

> "Attributes are used to describe the indicators and contextual data of an event. The main information
> contained in an attribute is made up of a **category-type-value triplet** … A MISP document MUST at least
> includes category-type-value triplet…"

- Sample attribute object, verbatim `raw.md:284-302`:

```json
"Attribute": { "id": "346056", "type": "comment", "category": "Other", "to_ids": false,
  "uuid": "57f4f6d9-cd20-458b-84fd-109ec0a83869", "event_id": "3357", "distribution": "5",
  "timestamp": "1475679332", "comment": "", "deleted": false, "value": "Hello world", ... }
```

  (`to_ids` distinguishes detection-ready attributes from context-only.)
- Event-level required fields: `uuid` MUST, `id` SHALL, `published` MUST (boolean), `info` MUST,
  `threat_level_id` SHALL (4=Undefined … 1=High) — `raw.md:87-133`.
- **MISP ↔ STIX converter:** `MISP/misp-stix` — licence **BSD-3-Clause**, version **2026.9.16**
  (`misp-stix@b63c26e78c1eb8e589b46c0a3c051858809206bb:pyproject.toml`).
  README: *"Python library (>=3.10) to handle all the conversions between the MISP standard format
  and STIX formats"* — bidirectional MISP↔STIX 1.x (1.1.1/1.2) and 2.x (2.0/2.1);
  attributes with `to_ids=True` produce an Indicator (with a STIX pattern) **and** Observed Data
  (`misp-stix@b63c26e:README.md:10,16-18`).

### IOC-9 — OpenIOC 1.1

- Repository: https://github.com/fireeye/OpenIOC_1.1 (`OpenIOC_1.1@f4973b80d4fcf9ae067a09df656ce6dd2d6899ba`).
- **Licence: Apache-2.0** — `OpenIOC_1.1@f4973b8:LICENSE` (Apache 2.0 text);
  README lists exactly which files are Apache-2.0 (`schemas/ioc.xsd`, changelogs, `iocterms/current.iocterms`,
  `IOC_Terms_Defs.md`).
- Format: XML document with three sections — **Metadata / Criteria / Parameters**
  (verbatim `README.md`): *"Criteria - the 'matching' section -- a boolean logical evaluation that
  determines whether or not you have found evil…"*.
- Schema root (verbatim `schemas/ioc.xsd`):

```xml
<xs:schema ... targetNamespace="http://openioc.org/schemas/OpenIOC_1.1" ...>
  <xs:element name="OpenIOC" nillable="true" type="tns:IndicatorOfCompromise" />
  <xs:complexType name="IndicatorOfCompromise"> <xs:sequence>
    <xs:element ... name="metadata" type="tns:IOCMetadata" />
    <xs:element ... name="criteria" type="tns:ArrayOfIocIndicator" />
    <xs:element ... name="parameters" type="tns:ArrayOfIOCParameter" /> ...
```

- Status: still a **draft** (*"OpenIOC 1.1 DRAFT"*, published "for garnering public comment").
  Last commit **2020-12-14** (`git log`: `f4973b8 … 2020-12-14 15:19:12 -0500`); the GitHub page showed
  **no "archived" banner** on 2026-10-08 (137 stars, 46 commits) ⇒ dormant but not archived.
- Companion tooling: https://github.com/mandiant/ioc_writer (referenced by README).

### IOC-10 — CSV threat feeds (abuse.ch)

**Feodo Tracker** — https://feodotracker.abuse.ch/blocklist/
- CSV: `https://feodotracker.abuse.ch/downloads/ipblocklist.csv` (JSON and IPs-only variants alongside).
- Generated every 5 minutes; recommended refresh ≥ every 15 minutes.
- Licence (verbatim ToS on the blocklist page): *"All datasets offered by Feodo Tracker can be used for
  both, commercial and non-commercial purpose without any limitations (**CC0**)"*, served as-is, no liability.
- ⚠ **Currently empty** — banner on every page; FAQ (https://feodotracker.abuse.ch/faq/): datasets are empty
  *"thanks to various successful takedowns conducted by Law Enforcement Agencies, including Emotet in 2021
  and Operation Endgame in 2024"* ⇒ no active C2s for those families right now.

**URLhaus** — https://urlhaus.abuse.ch/
- Recent-URLs CSV dump: `https://urlhaus.abuse.ch/downloads/csv_recent/` (public, no key at time of check).
  Header/columns, verbatim from the file:

```
# abuse.ch URLhaus Database Dump (CSV - recent URLs only)
# Terms Of Use: https://urlhaus.abuse.ch/api/
id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3911826","2026-09-03 09:56:06","http://…/i","online",…,"malware_download","None",…
```

- Newer bulk exports require an Auth-Key: `https://urlhaus-api.abuse.ch/v2/files/exports/<AUTH-KEY>/recent.csv`
  (https://urlhaus.abuse.ch/api/).
- Geo/ASN/TLD feeds: https://urlhaus.abuse.ch/feeds/ (CSV/JSON generators; explicitly *"not intended for
  blocking / blacklisting nor for being used as an Indicator Of Compromise"* — use the API datasets instead).

### IOC-11 — Elastic detection rules (detection-as-code)

- Repository: https://github.com/elastic/detection-rules (`detection-rules@4cb67c5b965bc1ba41a98d54adbbe247ae2afb27`,
  latest commit 2026-10-08 — actively maintained).
- **Licence: Elastic License 2.0** — `detection-rules@4cb67c5:LICENSE.txt` (*"Elastic License 2.0 /
  URL: https://www.elastic.co/licensing/elastic-license"*); each rule also declares
  `license = "Elastic License v2"` in its `[rule]` block.
- Format: one **TOML file per rule** under `rules/` (2216 `.toml` files at this commit), plus
  `rules_building_block/`, `detection_rules/` (parser/validator), `tests/` — `README.md:31-43`.
  README: *"Although rules can be added by manually creating `.toml` files, we don't recommend it."*
- Verbatim excerpt, `rules/windows/execution_shared_modules_local_sxs_dll.toml`:

```toml
[rule]
author = ["Elastic"]
from = "now-9m"
index = ["winlogbeat-*", "logs-endpoint.events.file-*", "logs-windows.sysmon_operational-*", ...]
language = "eql"
name = "Execution via local SxS Shared Module"
risk_score = 47
rule_id = "a3ea12f3-0d4e-4667-8b44-4230c63f3c75"
severity = "medium"
type = "eql"
query = '''file where host.os.type == "windows" and file.extension : "dll" and ...'''

[[rule.threat]]
framework = "MITRE ATT&CK"
[rule.threat.tactic]
id = "TA0002"
name = "Execution"
```

- Rule fields observed: `metadata` (creation/updated dates, integration, maturity), `rule_id` (UUID),
  `type` (`eql` — also `query`/`kql`/`esql` family), `risk_score`, `severity`, `language`, `index`,
  `references`, `tags`, `timestamp_override`, and `[[rule.threat]]` blocks mapping
  MITRE ATT&CK tactic/technique/sub-technique IDs.

---

## Quick corrigenda to the brief's assumptions

| Assumption in brief | Verified reality |
|---|---|
| AIDE `select` keyword | Does not exist; rules are `/regex attrs`, `!/regex`, `-/regex`, `=/regex attrs` (`aide@b4fc3ae:doc/aide.conf.5:439-492`) |
| OpenSCAP `--root` flag | No such flag; offline scanning = `OSCAP_PROBE_ROOT` env var (`openscap@a567a75:docs/manual/manual.adoc:1641`) |
| OpenSCAP on Windows | Officially void since 2022-02-01 (`README.md`); last working = 1.3.4 (`docs/windows.md`) |
| yara-python = BSD-3 | Apache-2.0 (LICENSE + PyPI metadata); bundled libyara is BSD-3 |
| Feodo Tracker CSV as a live feed | Datasets currently **empty** (takedowns) — see FAQ |
