# Wazuh and Falco: primary-source research report

Compiled 2026-10-08. Every factual claim below is followed by the exact URL that was fetched to obtain it. Claims that could not be confirmed from a fetched source are marked **UNVERIFIED**. Quoted snippets are verbatim and are each 15 lines or fewer.

## Sources and scope notes

- Wazuh documentation `/current/` was verified to be byte-identical to `/4.14/`: the extracted text of both copies of the internal-options page produced the same SHA-256 (`A6-23-A2-96-…-43-D2`) and both had length 50263 characters. [https://documentation.wazuh.com/current/user-manual/reference/internal-options.html] [https://documentation.wazuh.com/4.14/user-manual/reference/internal-options.html] So all `/current/` citations below are Wazuh **4.14.x** documentation, not 5.x documentation.
- `documentation.wazuh.com/5.0/` returns HTTP 404; `documentation.wazuh.com/4.14/` returns HTTP 200; `documentation.wazuh.com/4.15/` returns HTTP 404. [https://documentation.wazuh.com/5.0/index.html] [https://documentation.wazuh.com/4.14/] [https://documentation.wazuh.com/4.15/]
- Wazuh release tags fetched from the releases Atom feed (10 most recent entries): `Wazuh v4.14.9 RC 2` (2026-10-08), `v5.0.0-rc1` (2026-10-05), `Wazuh v4.14.9 RC 1` (2026-10-01), `Wazuh v4.14.8` (2026-09-25), `coverity-w38-4.14.9` (2026-09-15), `Wazuh v4.10.5` (2026-09-15), `Wazuh v5.0.0 Beta 5` (2026-09-07), `Wazuh v4.14.7` (2026-07-30). Latest stable 4.x tag = `v4.14.8`; 5.0.0 is at release-candidate stage, not GA. [https://github.com/wazuh/wazuh/releases.atom]
- Falco release tags fetched from the releases Atom feed: `0.45.1-rc1` (updated 2026-10-05), `0.45.0` (2026-09-21), `0.45.0-rc4` (2026-09-18), `0.45.0-rc3` (2026-09-15), `0.45.0-rc2` (2026-09-11), `0.45.0-rc1` (2026-09-09). Latest stable = `0.45.0`. [https://github.com/falcosecurity/falco/releases.atom]
- The GitHub REST API (api.github.com) was rate-limited (unauthenticated 60 requests/hour) part-way through research, so repository contents below are cited from `raw.githubusercontent.com` and `github.com` HTML pages instead.

---

# WAHUH

## WAHUH-1 — Wazuh rule format

**Format.** Wazuh rules are XML. The documentation defines the rules syntax page as the set of XML labels used to configure rules, and states: "The Wazuh ruleset, combined with any custom rules, analyzes incoming events. It generates alerts when all specified conditions within a rule are met." [https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html]

**Top-level structure.** Each rule is wrapped in a `<group name="...">` element; the documentation says "Every rule must belong to at least one group" and shows:

```xml
<group name="limits,">
 <rule id="100234" level="3">
   <if_sid>230</if_sid>
   <field name="alert_type">normal</field>
   <description>The file limit set for this agent is $(file_limit). Now, $(file_count) files are being monitored.</description>
 </rule>
</group>
```
[https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html]

**`<rule>` attributes** (documented values, all from the same page):

| Attribute | Allowed values | Definition (abridged from the page) |
|---|---|---|
| `level` | 0 to 16 | severity used by alerts and responses |
| `id` | 1 to 999999 | rule ID |
| `maxsize` | 1 to 9999 | maximum event size |
| `frequency` | 2 to 9999 | number of times the rule must match before generating an alert |
| `timeframe` | 1 to 99999 | seconds, intended to be used with `frequency` |
| `ignore` | 1 to 999999 | seconds to ignore the rule after it triggers, to avoid floods |
| `overwrite` | yes, no | replace a rule with local changes |
| `noalert` | 0, 1 | 1 = do not trigger an alert if the rule matches |
[https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html]

**Correlation example** (verbatim from the docs):

```xml
<rule id="50180" level="10" frequency="8" timeframe="120" ignore="60">
  <if_matched_sid>50125</if_matched_sid>
  <description>MySQL: Multiple errors.</description>
  <mitre>
    <id>T1499</id>
  </mitre>
  <group>service_availability,pci_dss_10.6.1,gpg13_4.3,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.6,tsc_CC7.2,tsc_CC7.3,</group>
</rule>
```
[https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html]

**`<options>` values** are documented as `alert_by_email`, `no_email_alert`, `no_log`, `no_full_log`, `no_counter` (`no_full_log` = "Do not include the `full_log` field in the alert"), with the note "Use one `<options>` tag for each option you want to add." [https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html] Example from the shipped rules: `<options>no_log</options>` inside rule 534. [https://raw.githubusercontent.com/wazuh/wazuh/v4.14.8/ruleset/rules/0015-ossec_rules.xml]

**Match operators.** `<match>` accepts osmatch/sregex by default and osregex via `<regex>`; the `match` label has `negate` and `type` attributes where `type` may be `osmatch`, `osregex` or `pcre2`. [https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html]

**Same-source correlation.** The canonical element is `<same_srcip />`; the page states: "The deprecated label `same_source_ip` works like an alias for `same_srcip`." and "The deprecated label `not_same_source_ip` works like an alias for `different_srcip`." [https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html] The shipped SSH rules still use the deprecated form:

```xml
<rule id="5703" level="10" frequency="6" timeframe="360">
<if_matched_sid>5702</if_matched_sid>
<same_source_ip />
```
[https://raw.githubusercontent.com/wazuh/wazuh/v4.14.8/ruleset/rules/0095-sshd_rules.xml]

**Field matching and CDB lists.** `<field>` compares a decoder-extracted field against a regex; `<list>` performs "a CDB lookup using a CDB list". [https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html]

**Other documented labels** include `decoded_as`, `category`, `srcip`, `dstip`, `srcport`, `dstport`, `data`, `extra_data`, `user`, `sys_name`, `prog_name`, `protocol`, `hostname`, `time`, `weekday`, `id`, `url`, `location`, `action`, `status`, `srcgeoip`, `dstgeoip`, `if_sid`, `if_group`, `if_level`, `if_matched_sid`, `if_matched_group`, `same_*`/`different_*` families, `description`, `info`, `check_diff`, `group`, `mitre`, `var`. [https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html]

## WAHUH-2 — How Wazuh loads rules

**Configuration-driven loading.** Rules are selected through the `<ruleset>` section of `ossec.conf`. Documented options: `rule_include` (single file), `rule_dir` (directory, "The files will be loaded in alphabetical order, and any duplicate filenames will be skipped", default value `ruleset/rules`, optional regex `pattern` attribute), `rule_exclude`, `decoder_include`, `decoder_dir` (default `ruleset/decoders`), `decoder_exclude`, `list` (CDB list, extension omitted). [https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/ruleset.html] Documented example:

```xml
<ruleset>
  <rule_include>ruleset/rules/my_rules.xml</rule_include>
  <rule_dir pattern="_rules.xml$">ruleset/rules</rule_dir>
  <rule_exclude>0215-policy_rules.xml</rule_exclude>
  <decoder_include>ruleset/decoders/my_decoder.xml</decoder_include>
  <decoder_dir pattern=".xml$">ruleset/decoders</decoder_dir>
  <decoder_exclude>ruleset/decoders/my_decoder.xml</decoder_exclude>
  <list>etc/lists/blocked_hosts</list>
</ruleset>
```
[https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/ruleset.html]

**Default vs custom locations.** Default (out-of-the-box) rules live at `/var/ossec/ruleset/rules/` on the server. [https://documentation.wazuh.com/current/user-manual/ruleset/rules/default.html] Custom rules go under `/var/ossec/etc/rules/` — the docs recommend `/var/ossec/etc/rules/local_rules.xml` for minor adjustments and new files in `/var/ossec/etc/rules/` for larger changes, with the note "Use ID numbers between 100000 and 120000 for custom rules to avoid conflicts with out-of-the-box system rules." [https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html] The ruleset directory layout documented for the server is `/var/ossec/etc/{decoders,rules}` plus `/var/ossec/ruleset/{decoders,rules}`, with the warning that everything under `/var/ossec/ruleset/` "is overwritten or modified during the Wazuh upgrade process". [https://documentation.wazuh.com/current/user-manual/ruleset/index.html]

**Startup / apply semantics.** Testing with `wazuh-logtest` requires only saving the rule file, but "you need to restart the Wazuh manager to generate alerts based on these changes." [https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html] Modifications to files inside `/var/ossec/ruleset/rules` are overwritten on upgrade, so users must copy rules into `/var/ossec/etc/rules/` and add `overwrite="yes"`. [https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html]

**Runtime.** `wazuh-analysisd` "receives the log messages and compares them to the rules. It then creates an alert when a log message matches an applicable rule." CLI flags: `-c <config>`, `-D <dir>` (chroot), `-d` (debug, repeatable), `-f` (foreground), `-g <group>`, `-h`, `-t` (test configuration), `-u`, `-V` (version and license). [https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html]

**Multithreaded pipeline** (verbatim from the daemon page):

```
The socket receives the message and sends it to the respective decoder queue.
They can be one of the following: Syscheck event decoder queue. Syscollector
event decoder queue. Rootcheck event decoder queue. Hostinfo event decoder
queue. Event decoder queue. Windows event decoder queue. If the selected queue
is full, the event is dropped.
```
[https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html] The same page documents "Automatic leveling of the threads": by default Analysisd spawns decoder and rule-matching thread counts from the machine's CPU core count (example given: 4 cores → 4 threads each for Syscheck, Syscollector, Rootcheck, Hostinfo, other decoders, plus 4 rule-matching threads), overridable via `analysisd.event_threads`, `analysisd.syscheck_threads`, `analysisd.syscollector_threads`, `analysisd.rootcheck_threads`, `analysisd.hostinfo_threads`, `analysisd.rule_matching_threads`, `analysisd.winevt_threads`. [https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html]

**Alert outputs.** Alerts are written to `/var/ossec/logs/alerts/alerts.log` and `/var/ossec/logs/alerts/alerts.json` and forwarded to the indexer with Filebeat. [https://documentation.wazuh.com/current/user-manual/ruleset/index.html]

**4.x vs 5.x divergence (important).** On the `main` branch of the Wazuh repository the `ruleset` directory contains only `mitre`, `sca` and `README.md` — no XML rules:

```
    ├── wazuh/ruleset
    │   ├── mitre                # MITRE ATT&CK Enterprise dataset ...
    │   ├── sca                 # Security Configuration Assessment created/updated by Wazuh
    │   └── README.md
```
[https://raw.githubusercontent.com/wazuh/wazuh/main/ruleset/README.md] The 5.x migration documentation states: "You cannot migrate custom Wazuh 4.x rules and decoders in XML format to Wazuh 5.x. Recreate the required detection content using the Wazuh 5.x content management." [https://raw.githubusercontent.com/wazuh/wazuh-documentation/main/source/migration-to-5x/transition-plan.rst] The XML rules referenced throughout this section therefore exist only on 4.x refs (verified: `ruleset/rules/` listing on `v4.14.8`). [https://github.com/wazuh/wazuh/tree/v4.14.8/ruleset/rules]

- Whether the 5.x content-management engine performs an equivalent XML-free load pipeline in the same order as `rule_dir`: **UNVERIFIED** (the `src/analysisd` tree does not exist on `main`; the 5.x engine source was not read in full).

## WAHUH-3 — Security Configuration Assessment (SCA)

**Policies are YAML, not XML.** The agent scans "every policy (`.yaml` or `.yml` files) present in the ruleset directory", at `/var/ossec/ruleset/sca` on Linux/Unix, `C:\Program Files (x86)\ossec-agent\ruleset\sca` on Windows, `/Library/Ossec/ruleset/sca` on macOS. [https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/how-it-works.html]

**Result model.** After each scan the agent synchronises results with the manager; agents "only send the differences detected between scans", sending only a summary if nothing changed. Each check event has three possible results: Passed, Failed, Not applicable. [https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/how-it-works.html]

**Policy file sections** are `policy` (Required), `requirements` (Not required), `variables` (Not required), `checks` (Required). [https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html] Verbatim opening of the documented example policy:

```yaml
policy:
  id: "unix_audit"
  file: "sca_unix_audit.yml"
  name: "System audit for Unix based systems"
  description: "Guidance for establishing a secure configuration for Unix based systems."
  references:
    - https://www.ssh.com/ssh/
requirements:
  title: "Check that the SSH service and password-related files are present on the system"
```
[https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html]

**Policy metadata fields:** `id`, `file`, `name`, `description` (mandatory); `references`, `regex_type` (optional; `regex_type` allowed values `"osregex"` (default) or `"pcre2"`). [https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html]

**Checks:** mandatory `id` (numeric), `title`, `condition` (`all`, `any`, `none`), `rules` (array of strings); optional `description`, `rationale`, `remediation`, `compliance`, `references`, `regex_type` (`"pcre2"` or `"osregex"`). "The `id` field under policy and checks must be unique across policy files." [https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html]

**Rule language:** five rule types — File `f`, Directory `d`, Process `p`, Commands `c`, Registry (Windows only) `r`. Content operators: literal (by omission), `r:` regex, `n:` numeric with `< <= == != > >=` comparisons. Examples given: `f:/etc/sshd_config`, `not f:/path/to/file`, `f:/path/to/file -> r:REGEX`, `p:process_name`, `not p:process_name`, `c:command -> r:REGEX`, `r:HKEY_LOCAL_MACHINE\...\LimitBlankPasswordUse -> 1`. Chaining uses `&&` with mandatory surrounding spaces; negation uses a leading `!` on an operator or a leading `not` on the rule. "Process rules only allow existence checks. Command rules only allow content (output) checks." [https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html]

**Condition semantics:** `all` passes when all rules are satisfied and fails as soon as one is not; `any` passes as soon as one rule is satisfied; `none` passes if none are satisfied. Each aggregator has documented "Not applicable" propagation rules. [https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html]

**Agent configuration** is the `<sca>` section of `ossec.conf`: `enabled`, `skip_nfs`, `policies` (containing `<policy>` with optional `enabled="no"` attribute), scheduling `scan_on_start`, `interval` (default `12h`), `day`, `wday`, `time`. The page notes: "Since Wazuh v3.10.0, although this section is missing, the Wazuh Agent will run scans for every policy (.yaml or .yml files) present in their ruleset folder." and "Since Wazuh v4.2.0, when a policy is defined by a relative path, this path is relative to the Wazuh installation directory." [https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/sca.html]

**Centralised distribution** is supported by placing a policy in `/var/ossec/etc/shared/default/` and referencing it from `agent.conf` as `<policy>etc/shared/<NEW_POLICY_FILE></policy>`; remote command execution (disabled by default) is required for Wazuh to push and execute installation steps on agents. [https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/how-to-configure.html]

**Policies shipped in-tree** are confirmed present in the repository under `ruleset/sca`. [https://raw.githubusercontent.com/wazuh/wazuh/main/ruleset/README.md]

## WAHUH-4 — File Integrity Monitoring (FIM)

**Mechanism.** "The FIM module runs periodic scans on specific paths and monitors specific directories for changes in real time." It stores file checksums and attributes in a local SQLite database; a scan compares current checksums/attributes to stored values and alerts on discrepancies. [https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/how-it-works.html]

**Two databases.** Agent-side SQLite at `C:\Program Files (x86)\ossec-agent\queue\fim\db` (Windows), `/var/ossec/queue/fim/db` (Linux), `/Library/Ossec/queue/fim/db` (macOS); plus a per-agent database on the Wazuh server created and managed by `wazuh-db`, stored at `/var/ossec/queue/db`. "The synchronization mechanism only updates the Wazuh server with information from the Wazuh agents such as checksums and file attributes that have changed." [https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/how-it-works.html]

**Windows scope limitation** (verbatim): "From Wazuh 4.13.0, the FIM module only monitors files and directories located on local file systems for Windows. Monitoring of UNC network paths such as \\server\share\folder and mapped drives such as Z:\folder is not supported." [https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/how-it-works.html]

**Alert rules.** The shipped FIM rules decode on `syscheck_*` decoder names:

```xml
<rule id="550" level="7">
  <category>ossec</category>
  <decoded_as>syscheck_integrity_changed</decoded_as>
  <description>Integrity checksum changed.</description>
```
```xml
<rule id="553" level="7">
  <decoded_as>syscheck_deleted</decoded_as>
  <description>File deleted.</description>
<rule id="554" level="5">
  <decoded_as>syscheck_new_entry</decoded_as>
  <description>File added to the system.</description>
```
[https://raw.githubusercontent.com/wazuh/wazuh/v4.14.8/ruleset/rules/0015-ossec_rules.xml] Also rule 555 (agentless integrity change) and rule 560 ("FIM real-time queue is full. Some real-time events may be lost.", matched on `^ossec: Real-time inotify kernel queue is full.`). [https://raw.githubusercontent.com/wazuh/wazuh/v4.14.8/ruleset/rules/0015-ossec_rules.xml]

**Configuration.** The `<syscheck>` section documents `<directories>` (with `realtime="yes"` attribute and `check_all`/`check_sha256`-style attribute overrides), `<disabled>`, `<frequency>` (default `43200` seconds, "Frequency that the syscheck will be run"), `<ignore>`, `<alert_new_files>`, `<skip_nfs>`. [https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html]

**Dashboard views.** FIM results appear in Inventory, Dashboard and Events sections; the Events section shows "the agent name, the file path of the monitored file, the type of FIM event, a description of the alert, and the rule level of the alert." [https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/interpreting-fim-module-analysis.html]

- Published FIM throughput/overhead numbers: **UNVERIFIED**.

## WAHUH-5 — Rootcheck

**What it does.** "Wazuh uses the Rootcheck module to detect anomalies that might indicate the presence of malware in an endpoint. By default, Rootcheck scans run every 12 hours." The agent "uses the Rootcheck module to monitor specified directories, registry entries, and system calls for abnormal behavior" using out-of-the-box and optional custom rootkit signatures. [https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/rootkits-behavior-detection.html]

**Four check families documented:**
1. *Check running processes* — inspects every PID using system calls such as `getsid` and `getpgid`; example alert: `Rule: 521 (level 11) -> 'Possible kernel level rootkit'`.
2. *Check hidden ports* — "Rootcheck scans every port in the system using the C language function bind(). If it can't bind to a port and that port isn't in the netstat output, it means malware might be present."
3. *Check unusual files and permissions* — scans the whole filesystem for unusual files/permissions, suid files, hidden directories.
4. *Check hidden files using system calls* — compares `stat` size against `fopen`+`read` size, and directory node counts against `opendir`+`readdir`.
[https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/rootkits-behavior-detection.html]

**Example alert quoted in the docs:**

```
** Alert 1668497750.1838326: - ossec,rootcheck,pci_dss_10.6.1,gdpr_IV_35.7.d,
2022 Nov 15 09:35:50 (Ubuntu) any->rootcheck
Rule: 510 (level 7) -> 'Host-based anomaly detection event (rootcheck).'
Rootkit 't0rn' detected by the presence of file '/usr/bin/.t0rn'.
```
[https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/rootkits-behavior-detection.html]

**Default monitored directories** — Unix: `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/dev`, `/lib`, `/etc`, `/root`, `/var/log`, `/var/mail`, `/var/lib`, `/var/www`, `/usr/lib`, `/usr/include`, `/tmp`, `/boot`, `/usr/local`, `/var/tmp`, `/sys`; Windows: `C:\WINDOWS` and `C:\Program Files`. [https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/rootkits-behavior-detection.html]

**Rule integration.** Rootcheck results are decoded and matched by rules 509–522 in the shipped ruleset: rule 509 `<decoded_as>rootcheck</decoded_as>` "Rootcheck event." (level 0), rule 510 "Host-based anomaly detection event (rootcheck)." (level 7), rule 513 (level 9), rule 518 (level 9), rule 521 (level 11, group `rootcheck`); rule 515 matches both `^Starting rootcheck scan|^Ending rootcheck scan.` and `^Starting syscheck scan|^Ending syscheck scan.` [https://raw.githubusercontent.com/wazuh/wazuh/v4.14.8/ruleset/rules/0015-ossec_rules.xml]

**Configuration section** `<rootcheck>` exists in `ossec.conf`. [https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html]

**Source layout.** The rootcheck implementation exists as a self-contained C module at `src/rootcheck/` in the Wazuh repository, containing files such as `check_open_ports.c`, `check_rc_dev.c`, `check_rc_if.c`, `check_rc_pids.c`, `check_rc_ports.c`, `check_rc_readproc.c`, `check_rc_sys.c`, `run_rk_check.c`, `rootcheck.c`, `unix-process.c`, `win-common.c`, `win-process.c`. These filenames were obtained from a local `git clone` of the Wazuh repository (branch `main`, sparse checkout) rather than from a fetched URL, so treat the exact file list as **not URL-cited**; the repository root it belongs to is [https://github.com/wazuh/wazuh].

- Any statement that rootcheck is deprecated/removed in current stable Wazuh: **UNVERIFIED** (no deprecation notice was found on the fetched 4.14 pages; the 4.14 documentation presents it as a live capability).

## WAHUH-6 — Wazuh performance tuning and observability

**Where tuning lives.** "The main configuration is located in the ossec.conf file, however some internal configuration features are located in the `/var/ossec/etc/internal_options.conf` file." The file "will be overwritten during upgrades", so custom changes go in `/var/ossec/etc/local_internal_options.conf`. [https://documentation.wazuh.com/current/user-manual/reference/internal-options.html]

**Thread counts** (all default `0` = "Sets the number of threads according to the number of CPU cores", allowed integer 0–32): `analysisd.event_threads`, `analysisd.syscheck_threads`, `analysisd.syscollector_threads`, `analysisd.rootcheck_threads`, `analysisd.sca_threads`, `analysisd.hostinfo_threads`, `analysisd.rule_matching_threads`, `analysisd.dbsync_threads`, `analysisd.winevt_threads`. [https://documentation.wazuh.com/current/user-manual/reference/internal-options.html] [https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html]

**Queue sizing.** All decode/output queue sizes default to `16384` with allowed range "Any integer between 128 and 2000000": `analysisd.decode_event_queue_size`, `analysisd.decode_syscheck_queue_size`, `analysisd.decode_syscollector_queue_size`, `analysisd.decode_rootcheck_queue_size`, `analysisd.decode_sca_queue_size`, `analysisd.decode_hostinfo_queue_size`, `analysisd.decode_output_queue_size`, `analysisd.decode_winevt_queue_size`, `analysisd.archives_queue_size`, `analysisd.statistical_queue_size`, `analysisd.alerts_queue_size`, `analysisd.firewall_queue_size`, `analysisd.fts_queue_size`, `analysisd.dbsync_queue_size`, `analysisd.upgrade_queue_size`. Also `analysisd.rlimit_nofile` (default 458752, range 1024–1048576) and `analysisd.decoder_order_size` (max fields per decoder, default 256, range 32–1024). [https://documentation.wazuh.com/current/user-manual/reference/internal-options.html]

**Statistics/alerting thresholds:** `analysisd.default_timeframe` (360), `analysisd.stats_maxdiff` (999000), `analysisd.stats_mindiff` (1250), `analysisd.stats_percent_diff` (150), `analysisd.fts_list_size` (32), `analysisd.fts_min_size_for_str` (14), `analysisd.min_rotate_interval` (600), `analysisd.state_interval` (5 seconds). [https://documentation.wazuh.com/current/user-manual/reference/internal-options.html]

**Benchmarking file.** "The statistical file for wazuh-analysisd is located at `/var/ossec/var/run/wazuh-analysisd.state`. It can be useful when benchmarking our Wazuh manager analysis engine in highly loaded environments. By default, this file is updated every 5 seconds." It reports `total_events_decoded`, per-source `*_events_decoded` and `*_edps` (events per second) for syscheck/syscollector/rootcheck/sca/hostinfo, `events_processed`, `events_received`, `events_dropped`, `alerts_written`, plus queue usage/size pairs (e.g. `event_queue_usage='0.53'`, `event_queue_size='16384'`, `rule_matching_queue_usage='0.42'`). [https://documentation.wazuh.com/current/user-manual/reference/statistics-files/wazuh-analysisd-state.html]

**Agent-side backpressure:** `agent.tolerance` (seconds before a flooding alert, default 15, range 0–600), `agent.warn_level` (default 90, range 1–100), `agent.normal_level` (default 70), `agent.min_eps` (default 50, range 1–1000), `agent.recv_timeout` (default 60). [https://documentation.wazuh.com/current/user-manual/reference/internal-options.html]

**FIM-side knobs:** `syscheck.sleep` (time to sleep between scans), `syscheck.debug` (0/1/2), `syscheck.rt_delay` (delay before processing real-time events). [https://documentation.wazuh.com/current/user-manual/reference/internal-options.html]

**Logcollector knobs** relevant to I/O load: `logcollector.loop_timeout` (default 2, range 1–120), `logcollector.open_attempts` (default 8), `logcollector.vcheck_files` (default 64), `logcollector.max_lines` (default 10000, range 100–100000), `logcollector.input_threads` (default 4, range 1–128), `logcollector.max_files` (default 1000, range 1–100000), `logcollector.rlimit_nofile` (default 1100). [https://documentation.wazuh.com/current/user-manual/reference/internal-options.html]

**Debug flags** on the daemon: `-d` (repeatable to increase verbosity) and `-f` for foreground operation. [https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html]

- Published events-per-second benchmark figures for the Wazuh analysis engine (on specified hardware): **UNVERIFIED**. The fetched documentation provides tuning knobs and a state file for measuring, but no quantitative benchmark.

## WAHUH-7 — Licensing

**Core repository (server/agent/rules/decoders):** `wazuh/wazuh` `LICENSE` states:

```
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License (version 2) as
 published by the FSF - Free Software Foundation.
```
and explicitly extends to detection content:

```
 Note that this license applies to the source code, as well as
 decoders, rules and any other data file included with Wazuh (unless
 otherwise specified).
```
The file also carries the OpenSSL linking exception ("certain source files in this program permit linking with the OpenSSL library … under the GPL") and an interpretation section for "derivative work" ("Integrates source code/data files from Wazuh.", "Includes Wazuh copyrighted material.", "Includes/integrates Wazuh into a proprietary executable installer.", "Links to a library or executes a program that does any of the above."). The full text includes `GNU GENERAL PUBLIC LICENSE / Version 2, June 1991`. [https://raw.githubusercontent.com/wazuh/wazuh/v4.14.8/LICENSE] Identical file on `main`: [https://raw.githubusercontent.com/wazuh/wazuh/main/LICENSE]

**Wazuh indexer:** `wazuh-indexer` `LICENSE.txt` is the Apache License, Version 2.0 ("Apache License / Version 2.0, January 2004"). [https://raw.githubusercontent.com/wazuh/wazuh-indexer/main/LICENSE.txt]

**Wazuh dashboard:** `wazuh-dashboard` `LICENSE.txt` is the Apache License, Version 2.0. [https://raw.githubusercontent.com/wazuh/wazuh-dashboard/main/LICENSE.txt]

**Result:** Wazuh's components are not uniformly licensed — the manager/agent/rules tree is GPLv2 (with OpenSSL exception), while the indexer and dashboard forks are Apache-2.0.

- License of `wazuh/wazuh-ruleset` and of third-party SCA benchmark content: **UNVERIFIED** (not fetched).

## WAHUH-8 — Offline (air-gapped) mode

**Documented capability:** "You can install Wazuh even without an Internet connection. Installing the solution offline involves first downloading the Wazuh central components on a system with Internet access, then transferring and installing them on the offline system." Supported deployments: all-in-one and distributed; supported architectures x86_64/AMD64 and AARCH64/ARM64. [https://documentation.wazuh.com/current/deployment-options/offline-installation/index.html]

**Prerequisites on the offline target:** `curl`, `tar`, `setcap`, and possibly `gnupg`; root privileges required. [https://documentation.wazuh.com/current/deployment-options/offline-installation/index.html]

**Download step (verbatim commands from the page):**

```
# curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
# chmod 744 wazuh-install.sh
# ./wazuh-install.sh -dw rpm -da x86_64     # or: -dw deb -da amd64 / aarch64 / arm64
# curl -sO https://packages.wazuh.com/4.14/config.yml
# ./wazuh-install.sh -g                      # certificates
```
Artifacts to transfer: `wazuh-install.sh`, `wazuh-offline.tar.gz`, `wazuh-install-files.tar`. [https://documentation.wazuh.com/current/deployment-options/offline-installation/index.html]

**Sub-pages:** assisted-method install and step-by-step install of the offline bundle. [https://documentation.wazuh.com/current/deployment-options/offline-installation/step-by-step.html] [https://documentation.wazuh.com/current/deployment-options/offline-installation/installation-assistant.html]

- Whether Wazuh ruleset/index updates, license activation, or vulnerability-database refreshes have a documented fully-offline path (beyond package installation): **UNVERIFIED** — no such page was located in the fetched documentation.

---

# FALCO

## FALCO-1 — Falco rule format

**File format.** "A Falco rules file is a YAML file containing mainly three types of elements": **Rules** ("Conditions under which an alert should be generated. A rule is accompanied by a descriptive output string that is sent with the alert."), **Macros** ("Rule condition snippets that can be re-used inside rules and even other macros."), **Lists** ("Collections of items that can be included in rules, macros, or other lists. Unlike rules and macros, lists cannot be parsed as filtering expressions."). Two optional versioning elements: `required_engine_version` and `required_plugin_versions`. [https://falco.org/docs/concepts/rules/]

**Required/optional keys per rule:**

| Key | Required | Notes (abridged) |
|---|---|---|
| `rule` | yes | short, unique name |
| `condition` | yes | filtering expression applied against events |
| `desc` | yes | longer description |
| `output` | yes | message emitted on a matching event |
| `priority` | yes | case-insensitive; emergency, alert, critical, error, warning, notice, informational, debug |
| `exceptions` | no | exceptions that cause the rule to not generate an alert |
| `enabled` | no | default `true`; if false the rule is neither loaded nor matched |
| `tags` | no | list of tags |
| `warn_evttypes` | no | default `true` |
| `skip-if-unknown-filter` | no | default `false` |
| `source` | no | default `syscall`; e.g. `syscall`, `k8s_audit`, or a plugin-advertised source |
| `append` | no | adds conditions/exceptions to a previously defined rule or macro instead of overriding it |
[https://falco.org/docs/reference/rules/rule-fields/]

**Minimal rule example** (verbatim from the docs):

```yaml
- rule: shell_in_container
  desc: notice shell activity within a container
  condition: >
    (evt.type in (execve, execveat)) and container.id != host and proc.name = bash
  output: >
    shell in a container | user=%user.name container_id=%container.id container_name=%container.name shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline
  priority: WARNING
```
[https://falco.org/docs/concepts/rules/basic-elements/]

**Versioning.** `required_engine_version: N` sets the minimum engine version; "If a rules file has an engine_version greater than the Falco engine version, the rules file is loaded and an error is returned." Engine version can be checked with `falco --version`. [https://falco.org/docs/concepts/rules/versioning/]

**Exceptions.** "Starting in 0.28.0, Falco supports an optional `exceptions` property to rules. The `exceptions` key is a list of identifier plus list of tuples of filtercheck fields", with `fields`, `comps` and optional `values`. [https://falco.org/docs/concepts/rules/exceptions/]

**Shipped ruleset contents** (`falcosecurity/rules`, branch `main`, file `rules/falco_rules.yaml`): header carries `# SPDX-License-Identifier: Apache-2.0` and `# Copyright (C) 2025 The Falco Authors.`; `- required_engine_version: 0.57.0`; `- required_plugin_versions: - name: container / version: 0.4.0`. Counted from the fetched file: **25 `- rule:` entries, 88 `- macro:` entries, 49 `- list:` entries, 0 occurrences of `exceptions:`**. Priorities actually used: WARNING ×11, NOTICE ×7, CRITICAL ×3, INFO ×1 (22 priority values across 25 rules; the remainder have no `priority` line counted by the pattern used). The file itself notes: "Starting with version 8, the Falco engine supports exceptions. However the Falco rules file does not use them by default." [https://raw.githubusercontent.com/falcosecurity/rules/main/rules/falco_rules.yaml]

**Sample rule from that file:**

```yaml
- rule: Directory traversal monitored file read
  condition: >
    (open_read or open_file_failed)
    and (etc_dir or user_ssh_directory or
         fd.name startswith /root/.ssh or
         fd.name contains "id_rsa")
    and directory_traversal
    and not proc.pname in (shell_binaries)
  enabled: true
  priority: WARNING
  tags: [maturity_stable, host, container, filesystem, mitre_credential_access, T1555]
```
[https://raw.githubusercontent.com/falcosecurity/rules/main/rules/falco_rules.yaml]

- Whether a JSON-schema (`--rule-schema`) machine-readable definition exists and its exact contents: the flag exists [https://falco.org/docs/reference/daemon/cli-arguments/] but the schema payload itself was not fetched — **UNVERIFIED**.

## FALCO-2 — How Falco loads rules

**Config key.** Rules are loaded from `rules_files` in `/etc/falco/falco.yaml` (or a configmap in Kubernetes). Default value:

```yaml
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/falco_rules.local.yaml
  - /etc/falco/rules.d
```
[https://raw.githubusercontent.com/falcosecurity/falco/master/falco.yaml] The same default is described in the docs: "Falco loads a set of predefined rules by default, followed by any custom rules located in the /etc/falco/rules.d directory. This configuration is specified in the /etc/falco/falco.yaml file, under the rules_files key." [https://falco.org/docs/concepts/rules/custom-ruleset/]

**Ordering semantics.** "It's important to note that the files or directories are read in the order specified here. In addition, rules are loaded by Falco in the order they appear within each rule file." Later files take precedence for overrides; among rules with the same event type, "rules are evaluated on a 'first match wins' basis". [https://raw.githubusercontent.com/falcosecurity/falco/master/falco.yaml]

**Extension and key-name history:** "Since Falco 0.41 only files with .yml and .yaml extensions are considered, including directory contents." and "Before Falco 0.38, this config key was `rules_file` (singular form), which is now deprecated in favor of `rules_files` (plural form)." [https://raw.githubusercontent.com/falcosecurity/falco/master/falco.yaml]

**Placement guidance.** "when loading syscall rules, Falco groups them per system call (evt.type) for faster matching and processes them later in sequential order, ensuring that two rules are not triggered simultaneously for the same evt.type field value. Consequently, more general rules should be positioned at the end of the rule set, while more specific rules should be placed at the beginning." [https://falco.org/docs/concepts/rules/custom-ruleset/] The same page documents overriding an existing rule by rewriting it or by using the `append` key.

**Selective enable/disable.** The `rules:` configuration key can enable/disable rules by name (wildcards allowed) and/or by tag, and "is applied after all rules files have been loaded, including their overrides". [https://raw.githubusercontent.com/falcosecurity/falco/master/falco.yaml]

**CLI loading/validation flags:**

- `-c <path>` — configuration file (default `/etc/falco/falco.yaml`)
- `-r <rules_file>` — "Rules file or directory to be loaded. This option can be passed multiple times. Falco defaults to the values in the configuration file when this option is not specified. Only files with .yml or .yaml extension are considered."
- `-V, --validate <rules_file>` — "Read the contents of the specified … file(s), validate the loaded rules, and exit."
- `--dry-run` — "Run Falco without processing events. It can help check that the configuration and rules do not have any errors."
- `-L` — "Show the name and description of all rules and exit."
- `-l <rule>` — "Show the name and description of the rule specified <rule> and exit."
- `--rule-schema`, `--config-schema` — print schemas and exit
- `--support` — "Print support information, including version, rules files used, loaded configuration, etc., and exit."
- `-o, --option <opt>=<val>` — overrides any configuration value from the command line
[https://falco.org/docs/reference/daemon/cli-arguments/]

**Config layering.** `config_files` (default includes `/etc/falco/config.d`) loads additional config files/dirs after the main one; since 0.41.0 per-entry merge strategies `append` (default), `override`, `add-only` are supported; "Configuration merging occurs only at the root key level, not for nested keys." [https://falco.org/docs/reference/daemon/config-options/]

**Official rules distribution.** Default/sandbox/incubating rule files are separate artifacts (`falco-rules`, `falco-incubating-rules`, `falco-sandbox-rules`) managed via falcoctl and selected in `falco.rules_files`; "By default, only the stable rules are loaded by Falco". [https://falco.org/docs/reference/rules/default-rules/]

## FALCO-3 — Falco data sources

**Native source.** "Falco natively supports the syscall event source, which is enabled by default, consuming events from the Linux Kernel via drivers." A plugin system extends Falco with new event sources. [https://falco.org/docs/concepts/event-sources/]

**Isolation and no cross-source correlation.** "Each event source operates in an isolated thread … Rules are partitioned by event source, meaning each rule applies to a specific source and is triggered exclusively by events from that source. Falco does not support correlating events from different sources." By default all known sources are enabled; `--enable-source` / `--disable-source` control this (example: `falco --enable-source=syscall --enable-source=k8s_audit`). Disabling all sources is an error. [https://falco.org/docs/concepts/event-sources/]

**Drivers (syscall source).** Supported drivers listed: **Modern eBPF probe (default)** and **Kernel module**, both with `x86_64 >= 3.10` and `aarch64 >= 3.10` "Minimal set of features". The kernel module "requires full privileges and cannot run with Linux capabilities". The modern eBPF probe "is embedded into Falco … if your kernel is recent enough Falco will automatically inject it", requires BPF ring buffer support and BTF (usually kernel >= 5.8), is selected with `engine.kind: modern_ebpf`, and needs `CAP_SYS_BPF`/`CAP_SYS_PERFMON`/`CAP_SYS_RESOURCE`/`CAP_SYS_PTRACE` in least-privileged mode (with `CAP_SYS_ADMIN` as the fallback for loading programs). [https://falco.org/docs/concepts/event-sources/kernel/]

**Driver-free mode:** `falco -o engine.kind=nodriver` — "Falco will continue to process syscall events in this mode, but it will not use a driver to capture them." [https://falco.org/docs/concepts/event-sources/]

**Replay mode:** `engine.replay.capture_file` sets "Path to the capture file to replay (eg: /path/to/file.scap)"; `falco.yaml` `engine:` block supports `kmod`, `modern_ebpf` and `replay` engine-specific settings. [https://raw.githubusercontent.com/falcosecurity/falco/master/falco.yaml]

**Plugin-provided sources.** "Examples of event source defined by officially-supported plugins are: Kubernetes Audit Events, AWS CloudTrail, Okta." "At the implementation level, the plugin system sends events to Falco using the same protocol that is used for syscalls, but the encoding and decoding of the payload is performed by the plugin itself." [https://falco.org/docs/concepts/event-sources/plugins/]

**Registered plugins table** (fetched): 28 numbered entries with `source` names including `k8s_audit`, `aws_cloudtrail`, `okta`, `docker`, `github`, `gcp_auditlog`, `journald`, `kafka`, `gitlab`, `keycloak`, `nginx`, `syslogsrv`, `nomad`, plus extraction plugins `-json`, `-k8smeta`, `-container`, `-krsi`, `-collector`. Every licence cell shown is `Apache-2.0`. [https://falco.org/docs/concepts/plugins/registered-plugins/]

**Event coverage.** "Here are the system call event types and args supported by the kernel module and modern eBPF probe via libscap included in the Falco libs. Note that, for performance reasons, by default Falco will only consider a subset of them". Event classes: Syscall, Tracepoint, Metaevent, Plugin events. "The events below are valid for Falco Schema Version: 4.3.0". [https://falco.org/docs/reference/rules/supported-events/]

**Platform scope:** "Falco is a cloud native runtime security tool for Linux operating systems." [https://raw.githubusercontent.com/falcosecurity/falco/master/README.md]

- Windows, macOS or eBPF-off-Linux syscall capture support: **UNVERIFIED** (no fetched source documents non-Linux syscall event sources).

## FALCO-4 — Falco's relationship to Sysdig

**Origin.** "Falco, originally created by Sysdig, is a graduated project under the Cloud Native Computing Foundation (CNCF) used in production by various organisations." [https://raw.githubusercontent.com/falcosecurity/falco/master/README.md]

**Component split.** "The Falco Project codebase is maintained under the falcosecurity GitHub organization. The primary repository, falcosecurity/falco, holds the source code for the Falco binary, while other sub-projects are hosted in dedicated repositories." Notable core repositories listed: `falcosecurity/libs` ("Falco's core libraries, which constitute the majority of the binary's source code and provide essential features, such as kernel drivers"), `falcosecurity/rules` ("the official ruleset for Falco"), `falcosecurity/plugins`, `falcosecurity/falcoctl`, `falcosecurity/charts`. [https://raw.githubusercontent.com/falcosecurity/falco/master/README.md]

**What libs contains** (verbatim): "This repository contains **libsinsp**, **libscap**, the **kernel module** and the **modern eBPF probe** sources. These components are at the foundation of Falco and other projects that work with the same kind of data." Division of labour: "We monitor syscalls using either a kernel module or an eBPF probe, which we call *drivers*. On top of the drivers, `libscap` manages the data capture process, while `libsinsp` enriches the data, and provides a rich set of API to consume the data. Furthermore, these two libraries also implement a plugin framework." [https://raw.githubusercontent.com/falcosecurity/libs/master/README.md]

**Library roles:** `libscap` ("lib for System CAPture") "directly communicates with the drivers, reading syscall events from the ring buffer … and forwarding them up to libsinsp. Moreover, libscap implements OS state collection and supports reading/writing to scap files." `libsinsp` ("lib for System INSPection") "receives events from libscap and enriches them with machine state: moreover, it performs events filtering with rule evaluation through its internal rule engine. Finally, it manages outputs." [https://raw.githubusercontent.com/falcosecurity/libs/master/README.md]

**Licence of libs:** `COPYING` is Apache License 2.0. [https://raw.githubusercontent.com/falcosecurity/libs/master/COPYING]

- An explicit statement in fetched sources that `falcosecurity/libs` is a *fork of the Sysdig agent codebase* (or the date/commit of the fork): **UNVERIFIED**. Only the "originally created by Sysdig" statement about Falco itself was found.
- Specific Sysdig commercial-product feature deltas vs. Falco: **UNVERIFIED**.

## FALCO-5 — Falco releases

**Latest stable:** `0.45.0`, "Released on 2026-09-21", per the project changelog. [https://raw.githubusercontent.com/falcosecurity/falco/master/CHANGELOG.md] Corroborated by the releases feed (`<title>0.45.0</title>` with `<updated>2026-09-21T13:10:41Z</updated>`) and by the releases page tag list (`0.45.1-rc1`, `0.45.0`, `0.45.0-rc4`, `0.45.0-rc3`, `0.45.0-rc2`). [https://github.com/falcosecurity/falco/releases.atom] [https://github.com/falcosecurity/falco/releases]

**v0.45.0 breaking change** (verbatim, abridged to one bullet):

```
* feat(userspace)!: evaluate rule conditions on raw field bytes (invalid and
non-printable UTF-8 sequences are now matchable with string operators, single
bytes with the new `\xHH` escape sequence) ... `FALCO_ENGINE_VERSION` bumped
from `0.62.0` to `0.63.0`; rules that matched the replacement character with
non-regex operators must be reviewed [#3942]
```
[https://raw.githubusercontent.com/falcosecurity/falco/master/CHANGELOG.md]

**Recent history from the same changelog headings:** `v0.44.0` (preceding release) introduced "drop gRPC output and server support", "drop gVisor engine support", "drop legacy BPF probe"; `v0.44.1` "Released on 2026-06-11". [https://falco.org/docs/reference/changelog/] [https://raw.githubusercontent.com/falcosecurity/falco/master/CHANGELOG.md]

**Documentation caveat:** the `falco.org` changelog page still presents `0.44.1` (2026-06-11) as its newest entry while the repository changelog and GitHub releases already carry `0.45.0` (2026-09-21) — the website page lags the repository. [https://falco.org/docs/reference/changelog/] [https://raw.githubusercontent.com/falcosecurity/falco/master/CHANGELOG.md]

- Release cadence statistics (mean days between minor releases) computed over the full history: **UNVERIFIED** (only the top of the changelog was read).

## FALCO-6 — Falco licensing

**Falco binary repository:** `COPYING` is the Apache License, Version 2.0 ("Apache License / Version 2.0, January 2004"). [https://raw.githubusercontent.com/falcosecurity/falco/master/COPYING] Confirmed independently via the GitHub license endpoint for `falcosecurity/falco`, which returned Apache-2.0 text. [https://api.github.com/repos/falcosecurity/falco/license]

**Rules repository:** `falcosecurity/rules` `LICENSE` is Apache License 2.0. [https://raw.githubusercontent.com/falcosecurity/rules/main/LICENSE] Individual rule files carry `# SPDX-License-Identifier: Apache-2.0`. [https://raw.githubusercontent.com/falcosecurity/rules/main/rules/falco_rules.yaml]

**Core libraries:** `falcosecurity/libs` `COPYING` is Apache License 2.0. [https://raw.githubusercontent.com/falcosecurity/libs/master/COPYING]

**Plugins:** every entry in the official registered-plugins table shows licence `Apache-2.0`. [https://falco.org/docs/concepts/plugins/registered-plugins/]

**Contrast with Wazuh:** Falco (binary, libs, rules, plugins) is uniformly Apache-2.0, whereas Wazuh's manager/agent/rules tree is GPLv2 + OpenSSL exception while its indexer and dashboard are Apache-2.0. [https://raw.githubusercontent.com/falcosecurity/falco/master/COPYING] [https://raw.githubusercontent.com/wazuh/wazuh/v4.14.8/LICENSE] [https://raw.githubusercontent.com/wazuh/wazuh-indexer/main/LICENSE.txt]

## FALCO-7 — Falco performance

**Guidance location.** Falco's performance documentation is at the troubleshooting performance page. It frames the concern as "Resource utilization and system impact: Strive to minimize compute overhead while ensuring the desired monitoring scope is achieved." and notes "a partnership with the CNCF TAG Environmental Sustainability, aimed at enhancing Falco's performance and assessing its impact on the system." [https://falco.org/docs/troubleshooting/performance/]

**CPU model** (verbatim): "CPU usage: Typically measured as a percentage of one CPU, it can be compared with the number of available CPUs on the host. Falco's hot path is single-threaded, so it should not be able to exceed the capacity of one full CPU." [https://falco.org/docs/troubleshooting/performance/]

**Load is workload-dependent** (verbatim): "A common misconception is to think that Falco has constant resource utilization. However, that is not accurate. Falco's utilization is directly dependent on the current workload on the host. The more system calls the applications make, the more work Falco has to handle." [https://falco.org/docs/troubleshooting/performance/]

**Metrics available for measurement:** "event drop counters, kernel tracepoint invocation counters, timeouts, and internal state handling", plus "Kernel side and userspace event counts", "Kernel side and userspace event drop counts", "Kernel tracepoint invocation counts", "Userspace timeouts", "Falco internal state counters". Memory metrics: RSS and VSZ, plus `container_memory_working_set_bytes` in Kubernetes. [https://falco.org/docs/troubleshooting/performance/] Metrics are configured in `falco.yaml` under `metrics:` (`enabled: false` by default, `interval: 1h`, `output_rule: true`). [https://raw.githubusercontent.com/falcosecurity/falco/master/falco.yaml]

**Rule-matching cost.** Default `rule_matching: first`. The shipped config comment warns: "With Falco 0.36 and beyond, it's now possible to apply multiple rules that match the same event type … However, enabling the `all` matching option may result in a performance penalty. We recommend carefully testing this alternative setting before deploying it in production." [https://raw.githubusercontent.com/falcosecurity/falco/master/falco.yaml]

**Syscall-set tuning** (the main documented lever): default `base_syscalls.custom_set: []`, `base_syscalls.repair: false`, `base_syscalls.all: false` — traces only syscalls required by enabled rules plus a compile-time set for the state engine. `base_syscalls.all: true` "enables monitoring all events supported by Falco, including typically ignored events such as write" with the caution "Use with caution, as this may negatively impact performance due to increased resource usage." `base_syscalls.repair: true` is "Recommended for most scenarios … allows Falco to automatically select the minimal necessary set of syscalls beyond those explicitly required by enabled rules", ensuring "internal state engine integrity with minimal performance overhead". `falco -i` lists events ignored by default. [https://falco.org/docs/concepts/event-sources/kernel/tuning/]

**Buffer sizing:** `engine.modern_ebpf.cpus_for_each_buffer` (default 2) and `engine.modern_ebpf.buf_size_preset` (default 4); "If you have low event throughputs and minimal drops, reducing the number of buffers (higher `cpus_for_each_buffer`) can lower the memory footprint." [https://raw.githubusercontent.com/falcosecurity/falco/master/falco.yaml] Auxiliary-map storage since 0.45 is "two auxiliary map segments per possible CPU … Each segment has 128 KiB of event storage, plus metadata. This doubles auxiliary event storage from 128 KiB to 256 KiB per possible CPU". [https://falco.org/docs/concepts/event-sources/kernel/]

**Output cost:** `-U, --unbuffered` "Turn off output buffering for configured outputs. This causes every single line emitted by Falco to be flushed, which generates higher CPU usage but is useful when piping those outputs into another process or a script." [https://falco.org/docs/reference/daemon/cli-arguments/]

- Published quantitative benchmarks (CPU % / memory MB / events-per-second for Falco at a given syscall rate on named hardware): **UNVERIFIED**. The fetched sources describe how to measure (metrics, drop counters, state file equivalents) but contain no numeric benchmark results.
- Comparative performance figures vs. other HIDS/EBPF agents: **UNVERIFIED**.

---

## Cross-cutting summary of open items (all UNVERIFIED)

1. Wazuh 5.x engine's exact rule-load order and any 5.x benchmark data.
2. Wazuh published analysis-engine EPS/latency benchmark numbers.
3. Rootcheck deprecation status (no deprecation notice found in fetched 4.14 pages).
4. Wazuh fully-offline paths for ruleset/index/vulnerability-database updates beyond package install.
5. `wazuh/wazuh-ruleset` repository licence.
6. Explicit "libs is a fork of Sysdig" statement and fork date.
7. Falco support for non-Linux syscall sources.
8. Falco quantitative performance benchmarks and cross-tool comparisons.
