---

## 11. Worked Rule Examples (25 documents, schema-valid)

Every block below is a **stored-form** document (`sentinel-rule/v1`): the post-import shape the engine persists and executes. Sigma examples show pipeline-resolved canonical fields (Stage-2 D2-014 applied once at import; the verbatim upstream text lives in `rule_source` per D5-001). Thresholds are content, not code — operators edit them without redeploying the engine (Stage-3 §12.4 precedent). CI validates all examples against `rule_schema.json` (§10.6, §12.3).

### 11.1 `kind: sigma` (5)

```yaml
# S-01 — Encoded PowerShell launched from cmd.exe (process creation)
schema: sentinel-rule/v1
id: 7c1a9e40-2f6b-4d8a-9c3e-1b2d3e4f5a60
kind: sigma
source: sigma
source_id: 5f0d8b2a-9c4e-4a1f-8e7d-6b5a4c3d2e10
source_ref: "sigma-rules@8a4813404e:rules/windows/process_creation/example_s01.yml"
source_spec: sigma-spec/2.1.0
license: DRL-1.1
author: Example Sigma Author
title: Encoded PowerShell Launched From cmd.exe
name: win_process_encoded_ps_from_cmd
description: cmd.exe spawning PowerShell with an encoded command and execution-policy bypass.
status: test
severity: HIGH
level_original: high
logsource:
  product: windows
  category: process_creation
tags: [attack.t1059.001, attack.t1027]
falsepositives: [Software deployment tooling that encodes installer commands]
fields: [process.exe, process.command_line, process.parent_image, user.name]
detection:
  selection:
    process.exe|endswith: ['\cmd.exe', '\powershell.exe', '\pwsh.exe']
    process.command_line|contains|all: ['-enc', 'bypass']
  filter_legit:
    process.parent_image|endswith: '\services.exe'
  condition: selection and not filter_legit
enabled: true
compile:
  detection_path: sql
  cost_class: standard
  prefilter:
    - {column: source.channel, op: eq, values: [security, sysmon]}
```

```yaml
# S-02 — Suspicious registry persistence value written
schema: sentinel-rule/v1
id: 3d5e7f80-1a2b-4c6d-8e9f-0a1b2c3d4e51
kind: sigma
source: sigma
source_spec: sigma-spec/2.1.0
license: DRL-1.1
author: Example Sigma Author
title: Run Key Persistence Written Under Winlogon
name: win_registry_winlogon_shell_replace
description: A value named Shell under Winlogon is set to a non-standard interpreter.
status: test
severity: HIGH
level_original: high
logsource:
  product: windows
  category: registry_set
tags: [attack.t1547.001]
detection:
  selection:
    registry.path|endswith: '\CurrentVersion\Winlogon\Shell'
    registry.data|contains: ['.exe', '.vbs', '.js', '.hta', '.bat', '.cmd']
  condition: selection
enabled: true
compile:
  detection_path: sql
  cost_class: prefilter
  prefilter:
    - {column: source.event_id, op: in, values: [13, 14]}
```

```yaml
# S-03 — Outbound connection to a raw-IP destination on a high port
schema: sentinel-rule/v1
id: 9b8c7d6e-5f4a-4b3c-8d2e-1f0a9b8c7d62
kind: sigma
source: sigma
source_spec: sigma-spec/2.1.0
license: DRL-1.1
author: Example Sigma Author
title: Network Connection To Literal IP Address
name: win_network_literal_ip_high_port
description: Process opens a connection to a dotted-quad address on a non-standard port.
status: test
severity: MEDIUM
level_original: medium
logsource:
  product: windows
  category: network_connection
tags: [attack.t1071]
detection:
  selection:
    network.dst_ip|re: '^\d{1,3}(\.\d{1,3}){3}$'
    network.dst_port|gte: 1024
  filter_corp:
    network.dst_ip|cidr: [10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12]
  condition: selection and not filter_corp
enabled: true
compile:
  detection_path: native          # one `re` predicate: regex check runs in the RE2 pass; SQL still applies the envelope/category prefilter
  cost_class: standard
  prefilter:
    - {column: event.category, op: eq, values: [network]}
```

```yaml
# S-04 — Suspicious PowerShell script block content
schema: sentinel-rule/v1
id: 1e2f3a4b-5c6d-4e7f-8a9b-0c1d2e3f4a53
kind: sigma
source: sigma
source_spec: sigma-spec/2.1.0
license: DRL-1.1
author: Example Sigma Author
title: PowerShell Downloads And Invokes A Remote Bytecode Loader
name: win_ps_downloadstring_assembly
description: Script block combines DownloadString with Assembly Load — classic cradle pattern.
status: test
severity: HIGH
level_original: high
logsource:
  product: windows
  service: powershell
tags: [attack.t1059.001, attack.t1105]
detection:
  selection:
    powershell.script_block_text|contains|all: ['DownloadString', 'Assembly']
    powershell.script_block_text|contains: ['Load(', 'GetType']
  condition: selection
enabled: true
compile:
  detection_path: sql              # contains-predicates only: ILIKE over the payload, no regex
  cost_class: heavy                # long-text scan class
```

```yaml
# S-05 — Keyword search across the whole event (OR list, search-identifier list form)
schema: sentinel-rule/v1
id: 0f9e8d7c-6b5a-4c3d-2e1f-0a9b8c7d6e54
kind: sigma
source: sigma
source_spec: sigma-spec/2.1.0
license: DRL-1.1
author: Example Sigma Author
title: Mimikatz-Like Strings Anywhere In The Event
name: win_keyword_mimikatz_strings
description: Whole-event keyword search; condition is a list of items (OR across items per spec).
status: experimental
severity: MEDIUM
level_original: medium
logsource:
  product: windows
tags: [attack.t1003]
detection:
  keywords:
    - 'sekurlsa::logonpasswords'
    - 'privilege::debug'
    - 'lsadump::sam'
  condition: keywords
enabled: true
compile:
  detection_path: native
  cost_class: heavy
```

### 11.2 `kind: correlation` (4)

```yaml
# C-01 — Brute force: repeated failed logons per account per host
schema: sentinel-rule/v1
id: a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c55
kind: correlation
source: sigma
source_spec: sigma-spec/2.1.0
license: DRL-1.1
author: Sentinel content team
title: Repeated Failed Interactive Logons (Brute Force Candidate)
name: corr_bruteforce_failed_logons
description: >-
  More than 5 failed logon events for the same account on the same host within 10m.
  Referenced rules are ordinary kind:sigma rules resolved by name through the load-time name index;
  a missing/disabled member produces MEMBER_RULE_INACTIVE (never a silent no-op).
severity: HIGH
level_original: high
correlation:
  type: event_count
  rules: [win_auth_failure_4625, win_auth_failure_4768]
  group-by: [authentication.account_name, host.agent_id]
  timespan: 10m
  condition: {gt: 5}
  generate: true
enabled: true
compile:
  cost_class: window
```

```yaml
# C-02 — Ordered lateral movement: new service followed by remote logon
schema: sentinel-rule/v1
id: b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d66
kind: correlation
source: sigma
source_spec: sigma-spec/2.1.0
license: DRL-1.1
author: Sentinel content team
title: Remote Service Creation Followed By Interactive Logon
name: corr_service_then_logon
description: >-
  Stage-ordered correlation - service install, then logon, on the same host within 30m.
severity: HIGH
level_original: high
correlation:
  type: temporal_ordered
  rules: [win_service_install, win_auth_success_4624]
  group-by: [host.agent_id]
  timespan: 30m
enabled: true
compile:
  cost_class: window
```

```yaml
# C-03 — Password spray: many distinct accounts failed from one source IP
schema: sentinel-rule/v1
id: c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e77
kind: correlation
source: sigma
source_spec: sigma-spec/2.1.0
license: DRL-1.1
author: Sentinel content team
title: Many Distinct Failed Accounts From One Source (Password Spray Candidate)
name: corr_password_spray
description: 10+ distinct failing account names from the same source IP within 15m.
severity: HIGH
level_original: high
correlation:
  type: value_count
  rules: [win_auth_failure_4625]
  group-by: [authentication.source_ip]
  timespan: 15m
  condition: {field: authentication.account_name, gte: 10}
enabled: true
compile:
  cost_class: window
```

```yaml
# C-04 — Bulk data egress: summed bytes_sent far above the peer baseline
schema: sentinel-rule/v1
id: d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f88
kind: correlation
source: sigma
source_spec: sigma-spec/2.1.0
license: DRL-1.1
author: Sentinel content team
title: Sustained Outbound Byte Volume From One Host
name: corr_egress_byte_sum
description: Summed network.bytes_sent above 50 MB per host within 1h across network events.
severity: MEDIUM
level_original: medium
correlation:
  type: value_sum
  rules: [win_network_literal_ip_high_port]
  group-by: [host.agent_id]
  timespan: 1h
  condition: {field: network.bytes_sent, gt: 50000000}
enabled: true
compile:
  cost_class: window
```

### 11.3 `kind: ioc` (2)

```yaml
# I-01 — Known-bad SHA-256 in process or file hashes
schema: sentinel-rule/v1
id: e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8a99
kind: ioc
source: native
author: Sentinel content team
title: Process Hash Matches Signed Intelligence Pack
description: Bloom prefilter then exact confirm; indicator values live only in the pack (D5-007).
severity: HIGH
ioc:
  packs:
    - pack: acme-intel
      version: "2026.10.0"
      digest_sha256: "6b8e1f0c2d3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4"
      subset: botnet-c2
  match:
    fields: [process.hashes.sha256, file.hashes.sha256]
    kinds: [sha256]
    normalize: [hash_lower, trim]
  confirm_exact: true
  on_stale: last_known_good
  emit_fields: [process.hashes.sha256, process.exe]
enabled: true
compile:
  detection_path: sql
  cost_class: prefilter
```

```yaml
# I-02 — DNS query or connection destination matches domain/IP intelligence
schema: sentinel-rule/v1
id: f6a7b8c9-d0e1-4f2a-3b4c-5d6e7f8a9b0a
kind: ioc
source: native
author: Sentinel content team
title: DNS Or Connection Destination Matches Signed Intelligence Pack
description: Domain suffix-exact match plus IP/CIDR membership from the same signed pack.
severity: HIGH
ioc:
  packs:
    - pack: acme-intel
      version: "2026.10.0"
      digest_sha256: "6b8e1f0c2d3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4"
  match:
    fields: [dns.query_name, network.dst_ip]
    kinds: [domain, ipv4, cidr]
    normalize: [lowercase, strip_trailing_dot, ip_canonical]
  confirm_exact: true
  on_stale: last_known_good
  emit_fields: [dns.query_name, network.dst_ip, network.dst_port]
enabled: true
compile:
  detection_path: sql
  cost_class: prefilter
```

### 11.4 `kind: fim` (2)

```yaml
# F-01 — Security audit log cleared (Security 1102 -> category fim, VERIFIED Stage-2)
schema: sentinel-rule/v1
id: 1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c1b
kind: fim
source: native
author: Sentinel content team
title: Security Event Log Cleared
description: fim.operation = audit_log_cleared is produced by the Stage-2 pipeline from Security EID 1102.
severity: HIGH
fim:
  paths:
    include: ['**']
  operations: [audit_log_cleared]
  baseline: {source: event_old_new}
enabled: true
compile:
  detection_path: sql
  cost_class: prefilter
  prefilter:
    - {column: source.event_id, op: eq, values: [1102]}
```

```yaml
# F-02 — Critical system binary changed versus uploaded baseline inventory
schema: sentinel-rule/v1
id: 2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d2c
kind: fim
source: native
author: Sentinel content team
title: System32 Executable Hash Drift Against Uploaded Baseline
description: >-
  Requires an uploaded baseline pair (fim_baseline rows). Absent baseline = SNAPSHOT_MISSING,
  rule inert for the job, job COMPLETED_WITH_WARNINGS (cold-start policy 4.8) — never a silent pass.
severity: HIGH
fim:
  paths:
    include: ['C:\\Windows\\System32\\*.exe']
    exclude: ['C:\\Windows\\System32\\*.log']
  operations: [modify, attribute_change]
  require: {hash_changed: true}
  baseline: {source: upload_pair}
enabled: true
compile:
  cost_class: standard
```

### 11.5 `kind: sca` (2)

```yaml
# SC-01 — Local security policy check failed
schema: sentinel-rule/v1
id: 3c4d5e6f-7a8b-4c9d-0e1f-2a3b4c5d6e3d
kind: sca
source: native
author: Sentinel content team
title: Unsupported Security Provider Registered
description: Fires only on config_check.status = fail for the selected checks; wording is Sentinel's own.
severity: MEDIUM
sca:
  select:
    checks: ["sc.win.local_policy.*"]
  fail_status_only: true
  assert:
    field: config_check.observed
    op: neq
    value: "2"
  benchmark:
    framework: cis
    control_id: "18.9.1"
    note: "Control ID cited factually; check wording is Sentinel's own (no CIS benchmark text shipped)."
  evidence: [config_check.observed, config_check.expected, config_check.source]
enabled: true
compile:
  cost_class: prefilter
```

```yaml
# SC-02 — Autorun entry outside the organisation's allowlist
schema: sentinel-rule/v1
id: 4d5e6f7a-8b9c-4d0e-1f2a-3b4c5d6e7f4e
kind: sca
source: native
author: Sentinel content team
title: Autorun Entry Not In The Approved Allowlist
description: >-
  config_check plugins emit pass/fail/unknown events; unknown never counts as pass (D3-029 mirror).
severity: MEDIUM
sca:
  select:
    checks: ["sc.win.autorun.*"]
    categories: [persistence]
  fail_status_only: true
  assert:
    field: config_check.observed
    op: contains
    value: "\\Temp\\"
  evidence: [config_check.observed, config_check.source]
enabled: true
compile:
  cost_class: prefilter
```

### 11.6 `kind: statistical` (2)

```yaml
# ST-01 — Per-host byte-rate outlier versus its own trailing baseline
schema: sentinel-rule/v1
id: 5e6f7a8b-9c0d-4e1f-2a3b-4c5d6e7f8a5f
kind: statistical
source: native
author: Sentinel content team
title: Network Byte Rate Above Peer Baseline
description: >-
  median + k*MAD over 5m buckets spanning 7d; k and thresholds are content.
  Warm-up (suppress) accounts BASELINE_WARMUP — never silent silence (4.8).
severity: MEDIUM
statistical:
  kind: rate
  group_by: [host.agent_id]
  measure: {op: sum, field: network.bytes_sent}
  window: {bucket: 5m, span: 7d}
  baseline: {min_observations: 84, warmup_action: suppress, estimator: median_mad, k: 6}
  threshold: {op: gt, value: 50000000, for_buckets: 3}
  scope_filter: {event.category: [network]}
enabled: true
compile:
  cost_class: window
```

```yaml
# ST-02 — Rare authenticated user on a host
schema: sentinel-rule/v1
id: 6f7a8b9c-0d1e-4f2a-3b4c-5d6e7f8a9b6a
kind: statistical
source: native
author: Sentinel content team
title: First-Time Interactive User On Host
description: >-
  rare_value over authentication.account_name per host; a name absent from the 30d
  observed set is flagged. No ML (Stage-1 4.3): set-membership only.
severity: LOW
statistical:
  kind: rare_value
  group_by: [host.agent_id]
  measure: {op: distinct_count, field: authentication.account_name}
  window: {bucket: 1h, span: 30d}
  baseline: {min_observations: 24, warmup_action: flag, estimator: none}
  threshold: {op: gte, value: 1}
  scope_filter: {authentication.logon_type: [2, 10, 11]}
enabled: true
compile:
  cost_class: window
```

### 11.7 `kind: artifact` (8: AF-001…AF-005 verbatim + AF-006…AF-008 new)

Import wraps Stage-3 §12.4 rules: adds `schema`/`kind`/`source`/`severity`/`enabled`, keeps `id`/`title`/`when`/`emit`/`severity_hint`/`attribution` **verbatim** (D5-001; schema allows rule-level `severity_hint`/`attribution` for `kind: artifact` only). AF-001…AF-005 below reproduce the Stage-3 keys exactly; AF-006…AF-008 are new rules resolving Q3-018's "we want a few more" gap, using only Stage-3-verified fact names (`pe.authenticode.present` §5.5, `pe.import.name` §5.5, `motw.zone_id` §12.4, `pdf.action.open_action` §5.3, `pdf.javascript.count` §5.3, `lnk.target.is_unc`/`lnk.target.path` §5.6).

```yaml
# A-01 = AF-001
schema: sentinel-rule/v1
id: AF-001
kind: artifact
source: native
title: Office document declares an external relationship target
severity: LOW
when:
  all:
    - fact: ooxml.relationship.external_target
      exists: true
    - fact: identification.selected
      in: [ooxml]
emit:
  artifact_type: file
  finding: external_relationship_declared
  confidence: observed
  evidence_facts: [ooxml.relationship.external_target, ooxml.relationship.type]
severity_hint: informational
attribution: >-
  Rule authored for Sentinel (DRL-compatible content, Stage-1 D-004).
enabled: true
```

```yaml
# A-02 = AF-002
schema: sentinel-rule/v1
id: AF-002
kind: artifact
source: native
title: PDF declares an OpenAction
severity: LOW
when:
  all:
    - fact: pdf.action.open_action
      exists: true
emit:
  artifact_type: file
  finding: pdf_open_action_declared
  confidence: observed
  evidence_facts: [pdf.action.open_action]
enabled: true
```

```yaml
# A-03 = AF-003
schema: sentinel-rule/v1
id: AF-003
kind: artifact
source: native
title: Archive entry expansion ratio above the configured threshold
severity: MEDIUM
when:
  any:
    - fact: archive.entry.ratio
      gte: 100                     # operator-configurable; the number is content, not code
    - fact: ooxml.part.ratio
      gte: 100
emit:
  artifact_type: file
  finding: high_expansion_ratio
  confidence: derived
  evidence_facts: [archive.entry.ratio, ooxml.part.ratio]
enabled: true
```

```yaml
# A-04 = AF-004
schema: sentinel-rule/v1
id: AF-004
kind: artifact
source: native
title: PE imports a process-execution API
severity: MEDIUM
when:
  any:
    - fact: pe.import.name
      in_list_ref: lists/exec_apis.yaml     # WinExec, ShellExecuteA, CreateProcessW, ...
emit:
  artifact_type: file
  finding: imports_process_execution_api
  confidence: observed
  evidence_facts: [pe.import.name, pe.import.dll]
enabled: true
```

```yaml
# A-05 = AF-005
schema: sentinel-rule/v1
id: AF-005
kind: artifact
source: native
title: File carries the mark of the web
severity: LOW
when:
  all:
    - fact: motw.zone_id
      in: [3, 4]
emit:
  artifact_type: file
  finding: internet_zone_origin
  confidence: observed
  evidence_facts: [motw.zone_id, motw.referrer_url]
enabled: true
```

```yaml
# A-06 = AF-006 (new) — unsigned PE + exec API import + MotW, ANDed
schema: sentinel-rule/v1
id: AF-006
kind: artifact
source: native
title: Unsigned PE with process-execution import and Internet-zone origin
description: >-
  Composite of three Stage-3 facts. All three must hold; each fact alone is weak,
  the conjunction is the finding. confidence: derived because authenticity is inferred
  from presence flags, not from chain verification (offline, unverified_offline).
severity: MEDIUM
when:
  all:
    - fact: pe.authenticode.present
      eq: false
    - fact: pe.import.name
      in_list_ref: lists/exec_apis.yaml
    - fact: motw.zone_id
      in: [3, 4]
emit:
  artifact_type: file
  finding: unsigned_pe_exec_api_from_internet
  confidence: derived
  evidence_facts: [pe.authenticode.present, pe.import.name, motw.zone_id]
severity_hint: medium
enabled: true
```

```yaml
# A-07 = AF-007 (new) — PDF OpenAction combined with embedded JavaScript
schema: sentinel-rule/v1
id: AF-007
kind: artifact
source: native
title: PDF declares an OpenAction and embeds JavaScript
description: AF-002 alone is weak (many benign PDFs declare OpenAction); JavaScript raises the bar.
severity: MEDIUM
when:
  all:
    - fact: pdf.action.open_action
      exists: true
    - fact: pdf.javascript.count
      gte: 1
emit:
  artifact_type: file
  finding: pdf_open_action_with_javascript
  confidence: derived
  evidence_facts: [pdf.action.open_action, pdf.javascript.count, pdf.javascript.source]
severity_hint: medium
enabled: true
```

```yaml
# A-08 = AF-008 (new) — LNK pointing at a UNC path
schema: sentinel-rule/v1
id: AF-008
kind: artifact
source: native
title: LNK shortcut targets a UNC path
description: UNC LNK targets are the classic phishing-payload delivery shape; facts come from the in-house LNK parser (Stage-3 5.6).
severity: LOW
when:
  all:
    - fact: lnk.target.is_unc
      eq: true
emit:
  artifact_type: file
  finding: lnk_unc_target
  confidence: observed
  evidence_facts: [lnk.target.is_unc, lnk.target.path, lnk.target_hashes.sha256]
severity_hint: low
enabled: true
```

<!-- CONTINUED-PART-E -->
