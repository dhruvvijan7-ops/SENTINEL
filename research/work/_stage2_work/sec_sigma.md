---

## 2. Source Mapping Tables

*(Assembled from SEC-A and SEC-B fragments — see Verification Log for the
evidence ids used throughout.)*

<!--ASSEMBLER:INSERT-SEC-A-->

<!--ASSEMBLER:INSERT-SEC-B-->

---

## 3. Sigma Field-Mapping Pipelines

**Purpose (normative).** Sentinel detectors run over canonical events, not
raw Sigma-shaped records. SigmaHQ rules reference source-native field names
(`Image`, `CommandLine`, `ParentImage`, `TargetObject`, ...). The pipelines
below are **configuration data, not code**: each block declares, for one
Sigma `logsource`, the canonical `event.category` / `event.type` selector
and the field-name translation a rule-translation layer must apply before a
Sigma condition can be evaluated against canonical events. They are derived
from the `fields` inventories published with SigmaHQ rules at corpus pin
`8a4813404e` (A6-SIGMAHQ-INV), cross-checked against the source-mapping
tables in §2 (SEC-A/SEC-B). The YAML shape mirrors pySigma pipeline
structure (`logsource`, `name`, `field_mapping`) so it can later be adapted
to a pySigma backend without semantic change; pySigma itself is not a
runtime dependency of the detector path (Stage-1 D-004/D-008: Sigma
compatibility is a content-level goal, not a library dependency).

**Conventions.**
- `selector`: the canonical event filter (`event.category`, plus
  `event.type` list when a Sigma rule's logsource is narrower than the
  category).
- `field_mapping`: Sigma field name → canonical path (dotted). Absent
  target = no canonical equivalent; such Sigma fields must be matched
  against `raw`/`unmapped` by a documented fallback or the rule is
  translated with that condition dropped and flagged.
- `value_transform`: declarative value-level adjustments required before
  comparison (e.g. Sysmon `Hashes` is a `KEY=value,KEY=value` string;
  canonical stores `process.hashes.sha256` directly, so a rule matching
  `Hashes` with `| contains` on `SHA256=` must be rewritten to compare the
  scalar field). Described as data (`source_shape`, `target`, `rule_action`).
- All field names in `field_mapping` values are schema paths from
  `canonical_event_v1.schema.json` (§1).

```yaml
# sigma_field_mapping_pipelines.yaml
# Sentinel — Sigma-to-canonical field-mapping pipelines (config data, not code)
# schema: canonical-event/v1
# corpus_pin: SigmaHQ/sigma-rules @ 8a4813404ea3074890e0cda9272d4d1a8b2941d6
# cross_ref: stage-2 doc §2 mapping tables (SEC-A, SEC-B)
version: 1

pipelines:

  # ---------- Sysmon (Microsoft-Windows-Sysmon/Operational) ----------
  - id: sysmon_process_creation
    title: Sysmon process creation
    logsource:
      product: windows
      category: process_creation
      service: sysmon
    selector:
      event.category: process
      event.type: [process_create]
    field_mapping:
      UtcTime: time.original          # utc derived; timezone_source=source_documented_utc
      ProcessGuid: process.guid
      ProcessId: process.pid
      Image: process.exe
      CommandLine: process.command_line
      CurrentDirectory: process.current_dir
      User: process.owner_name        # often DOMAIN\user; SID unavailable in Sysmon User
      LogonGuid: process.logon_guid
      LogonId: process.logon_id
      TerminalSessionId: process.terminal_session_id
      IntegrityLevel: process.integrity_level
      OriginalFileName: process.original_file_name
      ParentProcessGuid: process.parent.guid
      ParentProcessId: process.parent.pid
      ParentImage: process.parent.exe
      ParentCommandLine: process.parent.command_line
      ParentUser: process.parent.owner_sid   # see SEC-A trap: Sysmon ParentUser may carry SID
      # FileVersion / Description / Product / Company -> unmapped[]
      # RuleName -> unmapped[] (noise)
    value_transform:
      - source_shape: "Hashes (KEY=value,KEY=value)"
        target: [process.hashes.md5, process.hashes.sha1, process.hashes.sha256, process.hashes.imphash, process.hashes.other]
        rule_action: split_kv_and_compare_scalar   # rules using 'Hashes contains SHA256=' → process.hashes.sha256 startswith
      - source_shape: "User (DOMAIN\\user or user@domain)"
        target: [process.owner_name]
        rule_action: compare_as_is                  # no SID expansion in pipeline; rules needing SID use enrichment

  - id: sysmon_registry
    title: Sysmon registry events
    logsource:
      product: windows
      category: registry_event
      service: sysmon
    selector:
      event.category: registry
      event.type: [registry_create, registry_set, registry_delete, registry_rename]
    field_mapping:
      UtcTime: time.original
      ProcessGuid: process.guid
      ProcessId: process.pid
      Image: process.exe
      TargetObject: registry.path
      Details: registry.data
      EventType: registry.operation   # createKey→create, setValue→set, deleteKey/deleteValue→delete, renameKey/renameValue→rename
    value_transform:
      - source_shape: "EventType literal strings (createKey|deleteKey|deleteValue|setValue|renameKey|renameValue)"
        target: registry.operation
        rule_action: map_to_enum
      - source_shape: "TargetObject full path (hive\\key\\value)"
        target: [registry.hive, registry.key, registry.value_name]
        rule_action: optional_derived_split        # parser may fill hive/key/value_name (inferred); path always present

  - id: sysmon_network
    title: Sysmon network connection
    logsource:
      product: windows
      category: network_connection
      service: sysmon
    selector:
      event.category: network
      event.type: [network_connection]
    field_mapping:
      UtcTime: time.original
      ProcessGuid: process.guid
      ProcessId: process.pid
      Image: process.exe
      Protocol: network.protocol
      SourceIp: network.src_ip
      SourcePort: network.src_port
      DestinationIp: network.dst_ip
      DestinationPort: network.dst_port
      SourceHostname: unmapped        # no schema home (Q2-xxx)
      DestinationHostname: unmapped
      Initiated: network.direction    # true→outbound, false→inbound (INFERRED mapping)
    value_transform:
      - source_shape: "Initiated boolean"
        target: network.direction
        rule_action: map_bool_to_direction_enum

  - id: sysmon_image_load
    title: Sysmon image (DLL) load
    logsource:
      product: windows
      category: image_load
      service: sysmon
    selector:
      event.category: image_load
      event.type: [image_load]
    field_mapping:
      UtcTime: time.original
      ProcessGuid: process.guid
      ProcessId: process.pid
      Image: process.exe
      ImageLoaded: image_load.image
      Signed: image_load.signature.signed
      Signature: image_load.signature.signer
      SignatureStatus: image_load.signature.status
    value_transform:
      - source_shape: "Hashes KEY=value string"
        target: [image_load.hashes.md5, image_load.hashes.sha1, image_load.hashes.sha256, image_load.hashes.imphash]
        rule_action: split_kv_and_compare_scalar

  - id: sysmon_file_create
    title: Sysmon file create
    logsource:
      product: windows
      category: file_event
      service: sysmon
    selector:
      event.category: file
      event.type: [file_create]
    field_mapping:
      UtcTime: time.original
      ProcessGuid: process.guid
      ProcessId: process.pid
      Image: process.exe
      TargetFilename: file.path
      CreationUtcTime: file.created

  - id: sysmon_pipe
    title: Sysmon named pipe create/connect
    logsource:
      product: windows
      category: pipe_created   # SigmaHQ also uses pipe_connected via filter; same category family
      service: sysmon
    selector:
      event.category: pipe
      event.type: [pipe_created, pipe_connected]
    field_mapping:
      UtcTime: time.original
      ProcessGuid: process.guid
      ProcessId: process.pid
      Image: process.exe
      PipeName: pipe.name

  - id: sysmon_wmi
    title: Sysmon WMI events (19/20/21)
    logsource:
      product: windows
      category: wmi_event
      service: sysmon
    selector:
      event.category: wmi
      event.type: [wmi_filter, wmi_consumer, wmi_binding]
    field_mapping:
      UtcTime: time.original
      Operation: wmi.operation
      Query: wmi.query
      # Consumer/Filter/Binding object details: see SEC-A EID 19/21 tables;
      # several sub-fields currently land in unmapped[] (Q2-xxx)

  - id: sysmon_ps_script
    title: Sysmon/PowerShell script block (EID 4104 via ps_script)
    logsource:
      product: windows
      category: ps_script
    selector:
      event.category: powershell
      event.type: [script_block]
    field_mapping:
      ScriptBlockText: powershell.script_block_text
      Path: powershell.script_path
      MessageNumber: powershell.message_number
      MessageTotal: powershell.message_total

  - id: sysmon_dns
    title: Sysmon DNS query (EID 22)
    logsource:
      product: windows
      category: dns_query
      service: sysmon
    selector:
      event.category: dns
      event.type: [dns_query]
    field_mapping:
      UtcTime: time.original
      ProcessGuid: process.guid
      ProcessId: process.pid
      Image: process.exe
      QueryName: dns.query_name
      QueryResults: dns.answers
      QueryStatus: dns.query_status

  # ---------- Windows Security channel ----------
  - id: security_auth
    title: Security logon/logoff/authorization
    logsource:
      product: windows
      service: security
    selector:
      event.category: authentication
    field_mapping:
      SubjectUserSid: user.sid
      SubjectUserName: user.name
      SubjectDomainName: user.domain
      SubjectLogonId: user.logon_id
      TargetUserSid: authentication.target_sid
      TargetUserName: authentication.target_name
      TargetDomainName: authentication.target_domain
      TargetLogonId: authentication.target_logon_id
      LogonType: authentication.logon_type
      LogonProcessName: unmapped          # schema wish: authentication.logon_process (Q2-xxx)
      AuthenticationPackageName: authentication.auth_package
      WorkstationName: authentication.workstation
      LogonGuid: authentication.logon_guid
      CallerProcessId: authentication.caller_process_id
      CallerProcessName: authentication.caller_process_name
      ElevatedToken: authentication.elev_token
      Status: authentication.status
      SubStatus: authentication.sub_status
      IpAddress: authentication.source_ip
      IpPort: unmapped                    # schema wish: authentication.source_port (Q2-xxx)
      KeyLength: authentication.key_length
    value_transform:
      - source_shape: "ElevatedToken (%16384 / true/false renderings — see SEC-A UNVERIFIED note)"
        target: authentication.elev_token
        rule_action: parse_documented_variants
      - source_shape: "LogonType numeric codes (2,3,4,5,7,8,9,10,11)"
        target: authentication.logon_type
        rule_action: compare_numeric

  - id: security_process
    title: Security process creation/termination (4688/4689)
    logsource:
      product: windows
      service: security
      category: process_creation
    selector:
      event.category: process
      event.type: [process_create, process_terminate]
    field_mapping:
      NewProcessName: process.exe
      ProcessId: process.pid
      ParentProcessName: process.parent.exe
      ParentProcessId: process.parent.pid
      CommandLine: process.command_line
      TokenElevationType: unmapped        # schema wish: process.token_elevation_type (Q2-xxx)
      MandatoryLabel: process.integrity_level
      SubjectUserSid: user.sid
      SubjectUserName: user.name
      SubjectDomainName: user.domain
      Status: process.exit_code           # schema wish exists? currently unmapped — see SEC-A EID 4689 table

  - id: security_share
    title: Security share access (5140/5145)
    logsource:
      product: windows
      service: security
      category: share_access   # SigmaHQ taxonomy
    selector:
      event.category: network
      event.type: [share_access, share_object_access]
    field_mapping:
      SubjectUserSid: user.sid
      SubjectUserName: user.name
      SubjectDomainName: user.domain
      IpAddress: network.src_ip
      IpPort: unmapped
      ShareName: unmapped        # schema wish: network.share_name (Q2-xxx)
      RelativeTargetName: file.path
      AccessMask: unmapped

  - id: security_wfp
    title: Security WFP packet/connection events (5156/5158)
    logsource:
      product: windows
      service: security
      category: firewall   # SigmaHQ taxonomy (netfilter/wfp family)
    selector:
      event.category: network
      event.type: [packet_filtered, connection_listening]
    field_mapping:
      ProcessId: process.pid
      Application: process.exe
      Direction: network.direction   # %%14592=inbound? verify per SEC-A UNVERIFIED note on %%-codes
      SourceAddress: network.src_ip
      SourcePort: network.src_port
      DestAddress: network.dst_ip
      DestPort: network.dst_port
      Protocol: network.protocol
      LayerName: unmapped
      LayerId: unmapped
      FilterRunTimeId: unmapped

  - id: security_account
    title: Security account/group changes (4720/4722/4724/4726/4728/4732/4738/4740/4756/4767)
    logsource:
      product: windows
      service: security
      category: user_account   # includes group_change family in SigmaHQ
    selector:
      event.category: [account, group_membership]
    field_mapping:
      TargetUserName: [account.name, group_membership.member_name]
      TargetDomainName: [account.domain, group_membership.domain]
      TargetSid: [account.sid, group_membership.member_sid]
      SubjectUserSid: user.sid
      SubjectUserName: user.name
      SubjectDomainName: user.domain
      MemberName: group_membership.member_name
      MemberSid: group_membership.member_sid
      SamAccountName: account.sam_account_name
      DisplayName: account.display_name
      UserPrincipalName: account.upn
      SidHistory: account.sid_history
      PasswordLastSet: unmapped
      AccountExpires: unmapped

  - id: security_service_task
    title: Security service install (4697) and scheduled task changes (4698/4946)
    logsource:
      product: windows
      service: security
      category: [service_install, scheduled_task]
    selector:
      event.category: [service, scheduled_task]
    field_mapping:
      ServiceName: service.name
      ServiceFileName: service.image_path
      ServiceType: service.service_type
      StartType: service.start_type
      ServiceAccount: service.account_name
      TaskName: scheduled_task.name
      TaskContent: scheduled_task.task_xml
      SubjectUserSid: user.sid
      SubjectUserName: user.name
      SubjectDomainName: user.domain

  # ---------- PowerShell ----------
  - id: powershell_operational
    title: PowerShell Operational script block / module logging (4103/4104)
    logsource:
      product: windows
      category: ps_module   # + ps_script pipeline above for 4104-class rules
      service: powershell
    selector:
      event.category: powershell
      event.type: [pipeline_execution_detail, script_block]
    field_mapping:
      ContextInfo: powershell.context_info
      UserData: powershell.payload
      Payload: powershell.payload
      ScriptBlockText: powershell.script_block_text
      ScriptBlockId: powershell.script_block_id
      Path: powershell.script_path
      MessageNumber: powershell.message_number
      MessageTotal: powershell.message_total

  - id: powershell_classic
    title: Classic Windows PowerShell log (400/403/600)
    logsource:
      product: windows
      category: ps_operation   # engine/provider state transitions
      service: powershell
    selector:
      event.category: powershell
      event.type: [engine_state_change, provider_state_change]
    field_mapping:
      # classic events carry UNNAMED <Data> elements + Key=Value detail blob;
      # parser extracts blob keys to canonical fields (SEC-B table):
      NewEngineState: powershell.engine_state
      PreviousEngineState: powershell.previous_engine_state
      HostName: powershell.host_name
      HostId: powershell.host_id
      HostVersion: powershell.host_version
      HostApplication: powershell.host_application
      EngineVersion: powershell.engine_version
      RunspaceId: powershell.runspace_id
      PipelineId: powershell.pipeline_id
      CommandName: powershell.command_name
      CommandType: powershell.command_type
      ScriptName: powershell.script_name
      CommandPath: powershell.command_path
      CommandLine: powershell.command_line
      ProviderName: powershell.provider_name
      NewProviderState: powershell.new_provider_state

  # ---------- Zeek (network sensor) ----------
  - id: zeek_conn
    title: Zeek conn.log
    logsource:
      product: zeek
      category: conn
    selector:
      event.category: network
      event.type: [connection]
    field_mapping:
      ts: time.original                # epoch float → utc derived, precision microsecond
      uid: network.uid
      id.orig_h: network.src_ip
      id.orig_p: network.src_port
      id.resp_h: network.dst_ip
      id.resp_p: network.dst_port
      proto: network.protocol
      service: unmapped                # schema wish: network.service (Q2-xxx)
      duration: network.duration
      orig_bytes: network.bytes_sent
      resp_bytes: network.bytes_received
      conn_state: network.state
      history: unmapped
      # localOrig/remoteOrig/missed_bytes/etc. -> unmapped[]

  - id: zeek_dns
    title: Zeek dns.log
    logsource:
      product: zeek
      category: dns
    selector:
      event.category: dns
      event.type: [dns_observed]
    field_mapping:
      ts: time.original
      uid: network.uid
      id.orig_h: network.src_ip
      id.resp_h: network.dst_ip
      query: dns.query_name
      qtype_name: dns.query_type
      rcode_name: dns.response_code
      answers: dns.answers

  - id: zeek_http
    title: Zeek http.log
    logsource:
      product: zeek
      category: http
    selector:
      event.category: http
      event.type: [http_transaction]
    field_mapping:
      ts: time.original
      uid: network.uid
      id.orig_h: network.src_ip
      id.resp_h: network.dst_ip
      method: http.method
      host: http.host
      uri: http.uri
      user_agent: http.user_agent
      referrer: http.referrer
      status_code: http.status_code
      resp_body_len: http.response_body_length
      request_body_len: http.request_body_length
      mime_type: http.mime_type

  - id: zeek_ssl
    title: Zeek ssl.log
    logsource:
      product: zeek
      category: ssl
    selector:
      event.category: tls
      event.type: [tls_handshake]
    field_mapping:
      ts: time.original
      uid: network.uid
      id.resp_h: network.dst_ip
      server_name: tls.sni          # Zeek server_name = SNI
      version: tls.version
      cipher: tls.cipher
      ja3: tls.ja3
      ja3s: tls.ja3s
      certificate_subject: tls.subject
      certificate_issuer: tls.issuer
      resumed: tls.resumed

  # ---------- Suricata EVE ----------
  - id: suricata_eve
    title: Suricata EVE JSON (flow + per-type payloads)
    logsource:
      product: suricata
      category: eve_json
    selector:
      event.category: [network, http, dns, tls, third_party_alert]
    field_mapping:
      timestamp: time.original
      flow_id: network.uid
      src_ip: network.src_ip
      src_port: network.src_port
      dest_ip: network.dst_ip
      dest_port: network.dst_port
      proto: network.protocol
      event_type: (drives selector narrowing; see SEC-B EVE table)
      http.method: http.method
      http.hostname: http.host
      http.url: http.uri
      http.user_agent: http.user_agent
      http.status: http.status_code
      dns.rrname: dns.query_name
      dns.rrtype: dns.query_type
      dns.rcode_name: dns.response_code
      dns.answers: dns.answers
      tls.sni: tls.sni
      tls.ja3: tls.ja3
      alert.signature: third_party_alert.rule_name
      alert.signature_id: third_party_alert.rule_id
      alert.category: third_party_alert.category
      alert.severity: third_party_alert.severity_raw
      alert.action: third_party_alert.mitigation

  # ---------- Windows Defender ----------
  - id: defender_operational
    title: Windows Defender detection/action (1116/1117)
    logsource:
      product: windows
      service: defender
    selector:
      event.category: third_party_alert
      event.type: [malware_detected, malware_action]
    field_mapping:
      "Threat Name": third_party_alert.rule_name
      "Threat ID": third_party_alert.rule_id
      "Category Name": third_party_alert.category
      "Severity Name": third_party_alert.severity_raw
      "Process Name": process.exe
      "Detection User": user.name
      Path: third_party_alert.observable
      "Action Name": third_party_alert.mitigation
      "Product Name": third_party_alert.product
      "Product Version": unmapped
      FWLink: unmapped
      # full 42-element table incl. Unused* placeholders: SEC-B §Defender

  # ---------- WMI-Activity ----------
  - id: wmi_activity
    title: WMI-Activity Operational (5857/5858/5860)
    logsource:
      product: windows
      service: wmi
    selector:
      event.category: wmi
      event.type: [wmi_operation, wmi_client_failure, wmi_temporary_ess]
    field_mapping:
      ProviderName: wmi.provider_name
      Code: wmi.result_code
      HostProcess: wmi.process.exe
      ProcessID: wmi.process.pid
      ProviderPath: unmapped
      Id: unmapped
      ClientMachine: wmi.client_machine
      User: wmi.client_user
      ClientProcessId: wmi.client_process_id
      Component: unmapped
      Operation: wmi.operation
      ResultCode: wmi.result_code
      PossibleCause: unmapped
      NamespaceName: wmi.namespace
      Query: wmi.query
      Processid: wmi.process.pid       # NOTE: lowercase 'd' element name (5860 only) — parser must match exactly

  # ---------- RDP (TerminalServices-LSM) ----------
  - id: rdp_lsm
    title: RDP session events (LSM 21-25/39)
    logsource:
      product: windows
      service: terminalservices
    selector:
      event.category: authentication
      event.type: [rdp_logon, rdp_logoff, rdp_shadow_notify, rdp_disconnect]
    field_mapping:
      User: user.name
      SessionID: authentication.logon_id   # INFERRED: SessionID used as logon/session identity (Q2-xxx)
      Address: authentication.source_ip    # literal 'LOCAL' for console
```

---
