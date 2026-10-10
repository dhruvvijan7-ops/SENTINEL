# SEC-C — Canonical Event Example Corpus

Status: DRAFT for review. Each block below is a complete, self-contained
canonical event (schema_version `canonical-event/v1`) valid against
`canonical_event_v1.schema.json` (JSON Schema Draft 2020-12).

<!-- verification_log:
  C-SCHEMA: validated against canonical_event_v1.schema.json
  C-LOC: raw samples from _stage2_work/local_eventfields.json (local harvest)
  C-MAP-A: mappings follow _stage2_work/sec_sysmon_security.md (SEC-A)
  C-MAP-B: mappings follow _stage2_work/sec_network_exports.md (SEC-B)
  C-DFIR-LSM: LSM 21-39 semantics cross-checked via Microsoft docs / DFIR literature
-->

## Preamble

- Every example carries the full envelope: `schema_version`, `event`,
  `tenant_id`/`workspace_id`/`run_id` (`tenant-demo`/`ws-demo`/`run-2026-10-09-001`),
  `time`, `host`, `user`, `source`, `raw`, plus its category payload.
- Bare JSON `null` appears only for `time.utc` where the source has no
  usable timestamp; unknown/invalid values use state objects
  (`{"$state": ...}`) and never bare null.
- `unmapped` arrays list source fields with no canonical home — a field
  may appear there even when a partial mapping exists (e.g. Sysmon
  RuleName kept as noise).
- `raw` strings are shortened but real-shaped: EVTX single-quoted XML;
  local-harvest records slimmed via `slim_evtx` (Version/Level/Task/etc.
  dropped, provider Guid removed); Defender/4103/4104 EventData subsets
  noted per example cover comment. Abbreviations are noted in the cover.
- Secondary payloads (e.g. acting process on file/registry events) are
  included only where SEC-A/SEC-B explicitly map them; the category
  payload is always present.
- Examples labelled UNVERIFIED contain fields whose element names or
  semantics are not confirmed by a local sample or an authoritative
  reference (legacy Defender 1006-1012/1118/1119 not built; sc qc
  BINARY_PATH_NAME list UNVERIFIED per B-PRIOR; LSM labels diverge from
  SEC-B per Microsoft docs — see each cover comment).
- Divergences from SEC-B noted per example: AppLocker 8003/8004 map to
  `applocker_audit` (not SEC-B `applocker_block`); LSM 39 is disconnect-by-
  session; EID 24 → clipboard_change; EID 255 → sysmon_error sentinel.

## Example index

| ID | Title | Category | derived_by | Label |
|---|---|---|---|---|
| EX-SYSMON-1 | Process creation (Sysmon EID 1) | process | source | VERIFIED |
| EX-SYSMON-2 | File creation time change (Sysmon EID 2) | file | source | VERIFIED |
| EX-SYSMON-3 | Network connection (Sysmon EID 3) | network | source | VERIFIED |
| EX-SYSMON-4 | Sysmon service state change (Sysmon EID 4) | service | source | VERIFIED |
| EX-SYSMON-5 | Process terminated (Sysmon EID 5) | process | source | VERIFIED |
| EX-SYSMON-6 | Driver loaded (Sysmon EID 6) | driver | source | VERIFIED |
| EX-SYSMON-7 | Image loaded (Sysmon EID 7) | image_load | source | VERIFIED |
| EX-SYSMON-8 | CreateRemoteThread (Sysmon EID 8) | thread_access | source | VERIFIED |
| EX-SYSMON-9 | Raw device read (Sysmon EID 9) | file | sentinel | VERIFIED |
| EX-SYSMON-10 | Process accessed (Sysmon EID 10) | thread_access | source | VERIFIED |
| EX-SYSMON-11 | File created (Sysmon EID 11) | file | source | VERIFIED |
| EX-SYSMON-12 | Registry key created (Sysmon EID 12) | registry | source | VERIFIED |
| EX-SYSMON-13 | Registry value set (Sysmon EID 13) | registry | source | VERIFIED |
| EX-SYSMON-14 | Registry renamed (Sysmon EID 14) | registry | source | VERIFIED |
| EX-SYSMON-15 | File stream created (Sysmon EID 15) | file | source | VERIFIED |
| EX-SYSMON-16 | Sysmon configuration change (Sysmon EID 16) | config_check | sentinel | VERIFIED |
| EX-SYSMON-17 | Named pipe created (Sysmon EID 17) | pipe | source | VERIFIED |
| EX-SYSMON-18 | Named pipe connected (Sysmon EID 18) | pipe | source | VERIFIED |
| EX-SYSMON-19 | WMI filter created (Sysmon EID 19) | wmi | source | VERIFIED |
| EX-SYSMON-20 | WMI consumer created (Sysmon EID 20) | wmi | source | VERIFIED |
| EX-SYSMON-21 | WMI consumer bound to filter (Sysmon EID 21) | wmi | source | VERIFIED |
| EX-SYSMON-22 | DNS query (Sysmon EID 22) | dns | source | VERIFIED |
| EX-SYSMON-23 | File deleted and archived (Sysmon EID 23) | file | source | VERIFIED |
| EX-SYSMON-24 | Clipboard change (Sysmon EID 24) | process | sentinel | VERIFIED |
| EX-SYSMON-25 | Process tampering (Sysmon EID 25) | process | source | VERIFIED |
| EX-SYSMON-26 | File delete logged (Sysmon EID 26) | file | source | VERIFIED |
| EX-SYSMON-27 | Executable write blocked (Sysmon EID 27) | file | source | VERIFIED |
| EX-SYSMON-28 | File shredding blocked (Sysmon EID 28) | file | source | VERIFIED |
| EX-SYSMON-29 | Executable detected (Sysmon EID 29) | file | source | VERIFIED |
| EX-SYSMON-255 | Sysmon internal error (Sysmon EID 255) | third_party_alert | sentinel | UNVERIFIED |
| EX-SEC-1102 | Audit log cleared (Security EID 1102) | fim | sentinel | VERIFIED |
| EX-SEC-4624 | Logon success (Security EID 4624) | authentication | source | VERIFIED |
| EX-SEC-4625 | Logon failure (Security EID 4625) | authentication | source | VERIFIED |
| EX-SEC-4634 | Account logged off (Security EID 4634) | authentication | source | VERIFIED |
| EX-SEC-4647 | User-initiated logoff (Security EID 4647) | authentication | source | VERIFIED |
| EX-SEC-4648 | Explicit credential logon (Security EID 4648) | authentication | source | VERIFIED |
| EX-SEC-4672 | Special privileges assigned (Security EID 4672) | authentication | source | VERIFIED |
| EX-SEC-4688 | Process created (Security EID 4688) | process | source | VERIFIED |
| EX-SEC-4689 | Process exited (Security EID 4689) | process | source | VERIFIED |
| EX-SEC-4697 | Service installed (Security EID 4697) | service | source | VERIFIED |
| EX-SEC-4698 | Scheduled task created (Security EID 4698) | scheduled_task | source | VERIFIED |
| EX-SEC-4720 | User account created (Security EID 4720) | account | source | VERIFIED |
| EX-SEC-4722 | User account enabled (Security EID 4722) | account | source | VERIFIED |
| EX-SEC-4724 | Password reset attempted (Security EID 4724) | account | source | VERIFIED |
| EX-SEC-4726 | User account deleted (Security EID 4726) | account | source | VERIFIED |
| EX-SEC-4728 | Member added to global group (Security EID 4728) | group_membership | source | VERIFIED |
| EX-SEC-4732 | Member added to local group (Security EID 4732) | group_membership | source | VERIFIED |
| EX-SEC-4738 | User account changed (Security EID 4738) | account | source | VERIFIED |
| EX-SEC-4740 | Account locked out (Security EID 4740) | account | source | VERIFIED |
| EX-SEC-4756 | Member added to universal group (Security EID 4756) | group_membership | source | VERIFIED |
| EX-SEC-4767 | Account unlocked (Security EID 4767) | account | source | VERIFIED |
| EX-SEC-4768 | Kerberos TGT requested (Security EID 4768) | authentication | source | VERIFIED |
| EX-SEC-4769 | Kerberos service ticket requested (Security EID 4769) | authentication | source | VERIFIED |
| EX-SEC-4771 | Kerberos pre-auth failed (Security EID 4771) | authentication | source | VERIFIED |
| EX-SEC-4776 | Credential validation (Security EID 4776) | authentication | source | VERIFIED |
| EX-SEC-5140 | Network share accessed (Security EID 5140) | network | source | VERIFIED |
| EX-SEC-5145 | Network share access check (Security EID 5145) | network | source | VERIFIED |
| EX-SEC-5156 | WFP connection permitted (Security EID 5156) | network | source | VERIFIED |
| EX-SEC-5158 | WFP bind permitted (Security EID 5158) | network | source | VERIFIED |
| EX-SEC-4946 | Firewall rule added (Security EID 4946) | config_check | sentinel | VERIFIED |
| EX-SEC-4947 | Firewall rule modified (Security EID 4947) | config_check | sentinel | VERIFIED |
| EX-SEC-4948 | Firewall rule deleted (Security EID 4948) | config_check | sentinel | VERIFIED |
| EX-WIN-7034 | Service crashed (System EID 7034) | service | source | VERIFIED |
| EX-WIN-7036 | Service state change (System EID 7036) | service | source | VERIFIED |
| EX-WIN-7040 | Service start type changed (System EID 7040) | service | source | VERIFIED |
| EX-WIN-7043 | Service terminated unexpectedly (System EID 7043) | service | source | VERIFIED |
| EX-WIN-7045 | Service installed (System EID 7045) | service | source | VERIFIED |
| EX-WIN-104 | Event log cleared (System EID 104) | config_check | sentinel | UNVERIFIED |
| EX-WIN-PS400 | PowerShell engine started (Windows PowerShell EID 400) | powershell | source | VERIFIED |
| EX-WIN-PS403 | PowerShell engine stopped (Windows PowerShell EID 403) | powershell | source | VERIFIED |
| EX-WIN-PS600 | Provider started (Windows PowerShell EID 600) | powershell | source | VERIFIED |
| EX-WIN-PS800 | PowerShell pipeline executed (classic EID 800) | powershell | source | UNVERIFIED |
| EX-WIN-PS4103 | Module logging (PowerShell/Operational EID 4103) | powershell | source | VERIFIED |
| EX-WIN-PS4104 | Script block logging (PowerShell/Operational EID 4104) | powershell | source | VERIFIED |
| EX-WIN-PS4105 | Pipeline execution start (PowerShell/Operational EID 4105) | powershell | source | VERIFIED |
| EX-WIN-PS4106 | Pipeline execution stop (PowerShell/Operational EID 4106) | powershell | source | VERIFIED |
| EX-WIN-WMI5857 | WMI operation started (WMI-Activity EID 5857) | wmi | source | VERIFIED |
| EX-WIN-WMI5858 | WMI client failure (WMI-Activity EID 5858) | wmi | source | VERIFIED |
| EX-WIN-WMI5860 | WMI temporary ESS started (WMI-Activity EID 5860) | wmi | source | VERIFIED |
| EX-WIN-DEF1116 | Malware detected (Defender EID 1116) | third_party_alert | sentinel | VERIFIED |
| EX-WIN-DEF1117 | Malware action taken (Defender EID 1117) | file | sentinel | VERIFIED |
| EX-WIN-DEF5001 | Real-time protection disabled (Defender EID 5001) | config_check | sentinel | VERIFIED |
| EX-WIN-DEF5007 | Defender settings changed (Defender EID 5007) | config_check | source | VERIFIED |
| EX-WIN-TS106 | Task registered (TaskScheduler EID 106) | scheduled_task | source | UNVERIFIED |
| EX-WIN-TS140 | Task registration updated (TaskScheduler EID 140) | scheduled_task | source | UNVERIFIED |
| EX-WIN-TS141 | Task registration deleted (TaskScheduler EID 141) | scheduled_task | source | UNVERIFIED |
| EX-WIN-TS200 | Scheduled task executed (TaskScheduler EID 200) | scheduled_task | source | UNVERIFIED |
| EX-WIN-TS201 | Scheduled task completed (TaskScheduler EID 201) | scheduled_task | source | UNVERIFIED |
| EX-WIN-LSM21 | Session logon (LSM EID 21) | authentication | source | VERIFIED |
| EX-WIN-LSM22 | Shell start notification (LSM EID 22) | authentication | source | VERIFIED |
| EX-WIN-LSM23 | Session logoff (LSM EID 23) | authentication | source | VERIFIED |
| EX-WIN-LSM24 | Session disconnected (LSM EID 24) | authentication | source | VERIFIED |
| EX-WIN-LSM25 | Session reconnect (LSM EID 25) | authentication | source | VERIFIED |
| EX-WIN-LSM39 | Session disconnected by session (LSM EID 39) | authentication | source | VERIFIED |
| EX-WIN-RCM1149 | RDP pre-auth (RCM EID 1149) | authentication | sentinel | UNVERIFIED |
| EX-WIN-AL8003 | AppLocker audit allowed (AppLocker EID 8003) | config_check | sentinel | UNVERIFIED |
| EX-WIN-AL8004 | AppLocker audit blocked (AppLocker EID 8004) | config_check | sentinel | UNVERIFIED |
| EX-WIN-AL8006 | AppLocker enforce allowed (AppLocker EID 8006) | config_check | sentinel | UNVERIFIED |
| EX-WIN-AL8007 | AppLocker enforce blocked (AppLocker EID 8007) | config_check | sentinel | UNVERIFIED |
| EX-ZEEK-CONN | Zeek conn.log connection | network | source | VERIFIED |
| EX-ZEEK-DNS | Zeek dns.log query | dns | source | VERIFIED |
| EX-ZEEK-HTTP | Zeek http.log request | http | source | VERIFIED |
| EX-ZEEK-SSL | Zeek ssl.log handshake | tls | source | VERIFIED |
| EX-ZEEK-NOTICE | Zeek notice.log alert | third_party_alert | sentinel | VERIFIED |
| EX-ZEEK-FILES | Zeek files.log seen file | file | source | VERIFIED |
| EX-EVE-ALERT | Suricata EVE alert | third_party_alert | source | VERIFIED |
| EX-EVE-HTTP | Suricata EVE http | http | source | VERIFIED |
| EX-EVE-DNS | Suricata EVE dns | dns | source | VERIFIED |
| EX-EVE-TLS | Suricata EVE tls | tls | source | VERIFIED |
| EX-EVE-FLOW | Suricata EVE flow | network | source | VERIFIED |
| EX-EVE-FILEINFO | Suricata EVE fileinfo | file | source | VERIFIED |
| EX-NMAP-1 | Nmap XML scan result | config_check | sentinel | VERIFIED |
| EX-NETSTAT-1 | netstat -ano snapshot | config_check | sentinel | VERIFIED |
| EX-SCHTASKS-1 | schtasks /query snapshot | scheduled_task | sentinel | VERIFIED |
| EX-SCQUERY-1 | sc query snapshot | service | sentinel | VERIFIED |
| EX-SCQC-1 | sc qc snapshot | service | sentinel | UNVERIFIED |
| EX-REGEXPORT-1 | reg export .reg snapshot | registry | sentinel | VERIFIED |
| EX-EXPORTCSV-1 | Export-Csv process inventory | process | sentinel | VERIFIED |
| EX-AUTORUNS-1 | autorunsc autostart inventory | artifact | sentinel | VERIFIED |
| EX-SIGCHECK-1 | sigcheck file inventory | executable | sentinel | VERIFIED |
| EX-SIGCHECK-VT | sigcheck -vt VirusTotal result | artifact_finding | sentinel | VERIFIED |

## Sysmon (Microsoft-Windows-Sysmon/Operational) (30)

### EX-SYSMON-1 — Process creation (Sysmon EID 1)

<!-- covers: SEC-A Sysmon EID 1 process_create; RuleName/FileVersion/Description/Product/Company/HashType unmapped; ProcessID casing trap -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "process",
    "type": "process_create",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:00:00.000Z",
    "original": "2026-10-09 12:00:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-1",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 1,
    "record": {
      "type": "event_record",
      "record_id": 1024
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID><TimeCreated SystemTime='2026-10-09T12:00:00.000Z'/><EventRecordID>1024</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='FileVersion'>10.0.26100.1</Data><Data Name='Description'>Windows Command Processor</Data><Data Name='Product'>Microsoft Windows Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>Cmd.Exe</Data><Data Name='CommandLine'>cmd.exe /c whoami</Data><Data Name='CurrentDirectory'>C:\\Users\\jdoe\\</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='LogonGuid'>{9e8f7a6b-0002-0000-0000-000000000002}</Data><Data Name='LogonId'>0x3e7</Data><Data Name='TerminalSessionId'>1</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>SHA256=aa11bb22cc33dd44ee55ff6677889900aabbccddeeff00112233445566778899,MD5=11223344556677889900aabbccddeeff</Data><Data Name='ParentProcessGuid'>{1a2b3c4d-0000-0000-0000-000000000000}</Data><Data Name='ParentProcessId'>1204</Data><Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data><Data Name='ParentCommandLine'>C:\\Windows\\explorer.exe</Data><Data Name='ParentUser'>S-1-5-21-1000-2000-3000-1001</Data></EventData></Event>",
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "command_line": "cmd.exe /c whoami",
    "current_dir": "C:\\Users\\jdoe\\",
    "integrity_level": "Medium",
    "logon_guid": "{9e8f7a6b-0002-0000-0000-000000000002}",
    "logon_id": "0x3e7",
    "terminal_session_id": 1,
    "original_file_name": "Cmd.Exe",
    "hashes": {
      "sha256": "aa11bb22cc33dd44ee55ff6677889900aabbccddeeff00112233445566778899",
      "md5": "11223344556677889900aabbccddeeff"
    },
    "parent": {
      "guid": "{1a2b3c4d-0000-0000-0000-000000000000}",
      "pid": 1204,
      "exe": "C:\\Windows\\explorer.exe",
      "name": "explorer.exe",
      "command_line": "C:\\Windows\\explorer.exe",
      "owner_sid": "S-1-5-21-1000-2000-3000-1001"
    }
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "FileVersion",
      "value": "10.0.26100.1"
    },
    {
      "name": "Description",
      "value": "Windows Command Processor"
    },
    {
      "name": "Product",
      "value": "Microsoft Windows Operating System"
    },
    {
      "name": "Company",
      "value": "Microsoft Corporation"
    }
  ]
}
```

### EX-SYSMON-2 — File creation time change (Sysmon EID 2)

<!-- covers: SEC-A Sysmon EID 2 file_creation_time_change; PreviousCreationUtcTime unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_creation_time_change",
    "action": "change",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:01:00.000Z",
    "original": "2026-10-09 12:01:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-2",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 2,
    "record": {
      "type": "event_record",
      "record_id": 1025
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>2</EventID><TimeCreated SystemTime='2026-10-09T12:01:00.000Z'/><EventRecordID>1025</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='TargetFilename'>C:\\Users\\jdoe\\Documents\\report.pdf</Data><Data Name='CreationUtcTime'>2026-10-09 09:15:00.000</Data><Data Name='PreviousCreationUtcTime'>2026-10-01 11:00:00.000</Data></EventData></Event>",
  "file": {
    "path": "C:\\Users\\jdoe\\Documents\\report.pdf",
    "name": "report.pdf",
    "directory": "C:\\Users\\jdoe\\Documents",
    "created": "2026-10-09T09:15:00Z"
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "PreviousCreationUtcTime",
      "value": "2026-10-01 11:00:00.000"
    }
  ]
}
```

### EX-SYSMON-3 — Network connection (Sysmon EID 3)

<!-- covers: SEC-A Sysmon EID 3 network_connection; Initiated→direction INFERRED; hostnames/port names unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "network",
    "type": "network_connection",
    "action": "connect",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:02:00.000Z",
    "original": "2026-10-09 12:02:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-3",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 3,
    "record": {
      "type": "event_record",
      "record_id": 1026
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>3</EventID><TimeCreated SystemTime='2026-10-09T12:02:00.000Z'/><EventRecordID>1026</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='Protocol'>tcp</Data><Data Name='Initiated'>true</Data><Data Name='SourceIsIpv6'>false</Data><Data Name='SourceIp'>10.10.5.23</Data><Data Name='SourceHostname'>WS-DEMO01.corp.local</Data><Data Name='SourcePort'>51514</Data><Data Name='SourcePortName'>-</Data><Data Name='DestinationIsIpv6'>false</Data><Data Name='DestinationIp'>93.184.216.34</Data><Data Name='DestinationHostname'>example.com</Data><Data Name='DestinationPort'>443</Data><Data Name='DestinationPortName'>https</Data></EventData></Event>",
  "network": {
    "protocol": "tcp",
    "direction": {
      "$state": "inferred",
      "$note": "mapped from Initiated=true"
    },
    "src_ip": "10.10.5.23",
    "src_port": 51514,
    "dst_ip": "93.184.216.34",
    "dst_port": 443
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "SourceIsIpv6",
      "value": "false"
    },
    {
      "name": "DestinationIsIpv6",
      "value": "false"
    },
    {
      "name": "SourceHostname",
      "value": "WS-DEMO01.corp.local"
    },
    {
      "name": "DestinationHostname",
      "value": "example.com"
    },
    {
      "name": "SourcePortName",
      "value": "-"
    },
    {
      "name": "DestinationPortName",
      "value": "https"
    }
  ]
}
```

### EX-SYSMON-4 — Sysmon service state change (Sysmon EID 4)

<!-- covers: SEC-A Sysmon EID 4 sysmon_service_state_change; Version/SchemaVersion unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "service",
    "type": "sysmon_service_state_change",
    "action": "stop",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:03:00.000Z",
    "original": "2026-10-09 12:03:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sysmon-4",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 4,
    "record": {
      "type": "event_record",
      "record_id": 1027
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>4</EventID><TimeCreated SystemTime='2026-10-09T12:03:00.000Z'/><EventRecordID>1027</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='UtcTime'>2026-10-09 12:03:00.000</Data><Data Name='State'>Stopped</Data><Data Name='Version'>15.01</Data><Data Name='SchemaVersion'>4.90</Data></EventData></Event>",
  "service": {
    "name": "Sysmon64",
    "state": "Stopped"
  },
  "unmapped": [
    {
      "name": "Version",
      "value": "15.01"
    },
    {
      "name": "SchemaVersion",
      "value": "4.90"
    }
  ]
}
```

### EX-SYSMON-5 — Process terminated (Sysmon EID 5)

<!-- covers: SEC-A Sysmon EID 5 process_terminate; join to EID 1 via ProcessGuid -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "process",
    "type": "process_terminate",
    "action": "terminate",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:03:30.000Z",
    "original": "2026-10-09 12:03:30.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-5",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 5,
    "record": {
      "type": "event_record",
      "record_id": 1028
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>5</EventID><TimeCreated SystemTime='2026-10-09T12:03:30.000Z'/><EventRecordID>1028</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>CORP\\jdoe</Data></EventData></Event>",
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-6 — Driver loaded (Sysmon EID 6)

<!-- covers: SEC-A Sysmon EID 6 driver_load; Hashes/Signed/Signature/SignatureStatus→secondary executable payload -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "driver",
    "type": "driver_load",
    "action": "load",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:04:00.000Z",
    "original": "2026-10-09 12:04:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sysmon-6",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 6,
    "record": {
      "type": "event_record",
      "record_id": 1029
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>6</EventID><TimeCreated SystemTime='2026-10-09T12:04:00.000Z'/><EventRecordID>1029</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='ImageLoaded'>C:\\Windows\\System32\\drivers\\mydrv.sys</Data><Data Name='Hashes'>SHA256=bb22cc33dd44ee55ff6677889900aabbccddeeff11223344556677889900aabbcc,MD5=22334455667788990011aabbccddeeff</Data><Data Name='Signed'>true</Data><Data Name='Signature'>Microsoft Windows</Data><Data Name='SignatureStatus'>Valid</Data></EventData></Event>",
  "driver": {
    "name": "mydrv.sys",
    "image_path": "C:\\Windows\\System32\\drivers\\mydrv.sys",
    "state": {
      "$state": "inferred",
      "$note": "operation 'load' has no driver.operation enum value; state inferred from load event"
    }
  },
  "executable": {
    "path": "C:\\Windows\\System32\\drivers\\mydrv.sys",
    "format": "pe",
    "hashes": {
      "sha256": "bb22cc33dd44ee55ff6677889900aabbccddeeff11223344556677889900aabbcc",
      "md5": "22334455667788990011aabbccddeeff"
    },
    "signature": {
      "signed": true,
      "signer": "Microsoft Windows",
      "status": "Valid"
    }
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-7 — Image loaded (Sysmon EID 7)

<!-- covers: SEC-A Sysmon EID 7 image_load; FileVersion/Description/Product/Company/OriginalFileName unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "image_load",
    "type": "image_load",
    "action": "load",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:05:00.000Z",
    "original": "2026-10-09 12:05:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-7",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 7,
    "record": {
      "type": "event_record",
      "record_id": 1030
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>7</EventID><TimeCreated SystemTime='2026-10-09T12:05:00.000Z'/><EventRecordID>1030</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='ImageLoaded'>C:\\Windows\\System32\\amsi.dll</Data><Data Name='FileVersion'>10.0.26100.1</Data><Data Name='Description'>Antimalware Scan Interface</Data><Data Name='Product'>Microsoft Windows Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>amsi.dll</Data><Data Name='Hashes'>SHA256=cc33dd44ee55ff6677889900aabbccddeeff11223344556677889900aabbccdd</Data><Data Name='Signed'>true</Data><Data Name='Signature'>Microsoft Windows</Data><Data Name='SignatureStatus'>Valid</Data></EventData></Event>",
  "image_load": {
    "image": "C:\\Windows\\System32\\amsi.dll",
    "process": {
      "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
      "pid": 4521,
      "exe": "C:\\Windows\\System32\\cmd.exe",
      "owner_name": "jdoe"
    },
    "hashes": {
      "sha256": "cc33dd44ee55ff6677889900aabbccddeeff11223344556677889900aabbccdd"
    },
    "signature": {
      "signed": true,
      "signer": "Microsoft Windows",
      "status": "Valid"
    }
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "FileVersion",
      "value": "10.0.26100.1"
    },
    {
      "name": "Description",
      "value": "Antimalware Scan Interface"
    },
    {
      "name": "Product",
      "value": "Microsoft Windows Operating System"
    },
    {
      "name": "Company",
      "value": "Microsoft Corporation"
    },
    {
      "name": "OriginalFileName",
      "value": "amsi.dll"
    }
  ]
}
```

### EX-SYSMON-8 — CreateRemoteThread (Sysmon EID 8)

<!-- covers: SEC-A Sysmon EID 8 create_remote_thread; NewThreadId/StartAddress/StartModule/StartFunction unmapped; empty StartModule/StartFunction→null state -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "thread_access",
    "type": "create_remote_thread",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:06:00.000Z",
    "original": "2026-10-09 12:06:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-8",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 8,
    "record": {
      "type": "event_record",
      "record_id": 1031
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>8</EventID><TimeCreated SystemTime='2026-10-09T12:06:00.000Z'/><EventRecordID>1031</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='SourceProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='SourceProcessId'>4521</Data><Data Name='SourceImage'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='SourceUser'>CORP\\jdoe</Data><Data Name='TargetProcessGuid'>{1a2b3c4d-0002-0000-0000-000000000002}</Data><Data Name='TargetProcessId'>6788</Data><Data Name='TargetImage'>C:\\Windows\\System32\\notepad.exe</Data><Data Name='TargetUser'>CORP\\jdoe</Data><Data Name='NewThreadId'>9012</Data><Data Name='StartAddress'>0x0000000000401000</Data><Data Name='StartModule'/><Data Name='StartFunction'/></EventData></Event>",
  "thread_access": {
    "source_process": {
      "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
      "pid": 4521,
      "exe": "C:\\Windows\\System32\\cmd.exe",
      "owner_name": "jdoe"
    },
    "target_process": {
      "guid": "{1a2b3c4d-0002-0000-0000-000000000002}",
      "pid": 6788,
      "exe": "C:\\Windows\\System32\\notepad.exe",
      "owner_name": "jdoe"
    }
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "NewThreadId",
      "value": "9012"
    },
    {
      "name": "StartAddress",
      "value": "0x0000000000401000"
    },
    {
      "name": "StartModule",
      "value": {
        "$state": "null",
        "$note": "documented may-be-empty per MS docs"
      }
    },
    {
      "name": "StartFunction",
      "value": {
        "$state": "null",
        "$note": "documented may-be-empty per MS docs"
      }
    }
  ]
}
```

### EX-SYSMON-9 — Raw device read (Sysmon EID 9)

<!-- covers: SEC-A Sysmon EID 9 raw_device_read; derived_by sentinel (Device→file.path) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "raw_device_read",
    "action": "read",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:07:00.000Z",
    "original": "2026-10-09 12:07:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-9",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 9,
    "record": {
      "type": "event_record",
      "record_id": 1032
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>9</EventID><TimeCreated SystemTime='2026-10-09T12:07:00.000Z'/><EventRecordID>1032</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='Device'>\\\\.\\PhysicalDrive0</Data></EventData></Event>",
  "file": {
    "path": {
      "$state": "inferred",
      "$note": "Device path mapped to file.path by Sentinel",
      "$raw": "\\\\.\\PhysicalDrive0"
    }
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-10 — Process accessed (Sysmon EID 10)

<!-- covers: SEC-A Sysmon EID 10 process_access; SourceThreadId unmapped; GUID casing trap -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "thread_access",
    "type": "process_access",
    "action": "access",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:08:00.000Z",
    "original": "2026-10-09 12:08:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-10",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 10,
    "record": {
      "type": "event_record",
      "record_id": 1033
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>10</EventID><TimeCreated SystemTime='2026-10-09T12:08:00.000Z'/><EventRecordID>1033</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='SourceProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='SourceProcessId'>4521</Data><Data Name='SourceThreadId'>9012</Data><Data Name='SourceImage'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='SourceUser'>CORP\\jdoe</Data><Data Name='TargetProcessGuid'>{1a2b3c4d-0003-0000-0000-000000000003}</Data><Data Name='TargetProcessId'>777</Data><Data Name='TargetImage'>C:\\Windows\\System32\\lsass.exe</Data><Data Name='TargetUser'>NT AUTHORITY\\SYSTEM</Data><Data Name='GrantedAccess'>0x1010</Data><Data Name='CallTrace'>C:\\Windows\\System32\\cmd.exe+0x1a2b3|ntdll.dll+0x9f876</Data></EventData></Event>",
  "thread_access": {
    "source_process": {
      "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
      "pid": 4521,
      "exe": "C:\\Windows\\System32\\cmd.exe",
      "owner_name": "jdoe"
    },
    "target_process": {
      "guid": "{1a2b3c4d-0003-0000-0000-000000000003}",
      "pid": 777,
      "exe": "C:\\Windows\\System32\\lsass.exe",
      "owner_name": "SYSTEM"
    },
    "access_mask": "0x1010",
    "call_trace": "C:\\Windows\\System32\\cmd.exe+0x1a2b3|ntdll.dll+0x9f876"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "SourceThreadId",
      "value": "9012"
    }
  ]
}
```

### EX-SYSMON-11 — File created (Sysmon EID 11)

<!-- covers: SEC-A Sysmon EID 11 file_create -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_create",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:09:00.000Z",
    "original": "2026-10-09 12:09:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-11",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 11,
    "record": {
      "type": "event_record",
      "record_id": 1034
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>11</EventID><TimeCreated SystemTime='2026-10-09T12:09:00.000Z'/><EventRecordID>1034</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='TargetFilename'>C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe</Data><Data Name='CreationUtcTime'>2026-10-09 12:09:00.000</Data></EventData></Event>",
  "file": {
    "path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe",
    "name": "payload.exe",
    "directory": "C:\\Users\\jdoe\\AppData\\Local\\Temp",
    "created": "2026-10-09T12:09:00Z"
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-12 — Registry key created (Sysmon EID 12)

<!-- covers: SEC-A Sysmon EID 12 registry_object_create_delete; EventType literal UNVERIFIED; hive/key/value split INFERRED -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "registry",
    "type": "registry_object_create_delete",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:10:00.000Z",
    "original": "2026-10-09 12:10:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-12",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 12,
    "record": {
      "type": "event_record",
      "record_id": 1035
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>12</EventID><TimeCreated SystemTime='2026-10-09T12:10:00.000Z'/><EventRecordID>1035</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>CreateKey</Data><Data Name='UtcTime'>2026-10-09 12:10:00.000</Data><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\reg.exe</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='TargetObject'>HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater</Data></EventData></Event>",
  "registry": {
    "path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
    "hive": "HKLM",
    "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "value_name": "Updater",
    "operation": "create"
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\reg.exe",
    "name": "reg.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-13 — Registry value set (Sysmon EID 13)

<!-- covers: SEC-A Sysmon EID 13 registry_value_set; value_type absent (do not infer) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "registry",
    "type": "registry_value_set",
    "action": "set",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:11:00.000Z",
    "original": "2026-10-09 12:11:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-13",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 13,
    "record": {
      "type": "event_record",
      "record_id": 1036
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>13</EventID><TimeCreated SystemTime='2026-10-09T12:11:00.000Z'/><EventRecordID>1036</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>SetValue</Data><Data Name='UtcTime'>2026-10-09 12:11:00.000</Data><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\reg.exe</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='TargetObject'>HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater</Data><Data Name='Details'>C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe</Data></EventData></Event>",
  "registry": {
    "path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
    "hive": "HKLM",
    "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "value_name": "Updater",
    "data": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe",
    "operation": "set"
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\reg.exe",
    "name": "reg.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-14 — Registry renamed (Sysmon EID 14)

<!-- covers: SEC-A Sysmon EID 14 registry_rename; NewName unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "registry",
    "type": "registry_rename",
    "action": "rename",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:12:00.000Z",
    "original": "2026-10-09 12:12:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-14",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 14,
    "record": {
      "type": "event_record",
      "record_id": 1037
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>14</EventID><TimeCreated SystemTime='2026-10-09T12:12:00.000Z'/><EventRecordID>1037</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>RenameKey</Data><Data Name='UtcTime'>2026-10-09 12:12:00.000</Data><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\reg.exe</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='TargetObject'>HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OldName</Data><Data Name='Details'>-</Data><Data Name='NewName'>NewName</Data></EventData></Event>",
  "registry": {
    "path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OldName",
    "hive": "HKLM",
    "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "value_name": "OldName",
    "operation": "rename"
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\reg.exe",
    "name": "reg.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "NewName",
      "value": "NewName"
    }
  ]
}
```

### EX-SYSMON-15 — File stream created (Sysmon EID 15)

<!-- covers: SEC-A Sysmon EID 15 file_stream_create; stream suffix kept lossless; Hash→hashes.other; Contents unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_stream_create",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:13:00.000Z",
    "original": "2026-10-09 12:13:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-15",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 15,
    "record": {
      "type": "event_record",
      "record_id": 1038
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>15</EventID><TimeCreated SystemTime='2026-10-09T12:13:00.000Z'/><EventRecordID>1038</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='TargetFilename'>C:\\Users\\jdoe\\Downloads\\doc.docx:Zone.Identifier</Data><Data Name='CreationUtcTime'>2026-10-09 12:13:00.000</Data><Data Name='Hash'>dd44ee55ff6677889900aabbccddeeff11223344556677889900aabbccdd44ee5</Data><Data Name='Contents'>cc55dd66ee77ff889900aabbccddeeff11223344556677889900aabbccdd</Data></EventData></Event>",
  "file": {
    "path": "C:\\Users\\jdoe\\Downloads\\doc.docx:Zone.Identifier",
    "name": "doc.docx:Zone.Identifier",
    "directory": "C:\\Users\\jdoe\\Downloads",
    "created": "2026-10-09T12:13:00Z",
    "hashes": {
      "other": "dd44ee55ff6677889900aabbccddeeff11223344556677889900aabbccdd44ee5"
    }
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "Contents",
      "value": "cc55dd66ee77ff889900aabbccddeeff11223344556677889900aabbccdd"
    }
  ]
}
```

### EX-SYSMON-16 — Sysmon configuration change (Sysmon EID 16)

<!-- covers: SEC-A Sysmon EID 16 sysmon_config_change; derived_by sentinel; ConfigurationFileHash unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "sysmon_config_change",
    "action": "change",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:14:00.000Z",
    "original": "2026-10-09 12:14:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sysmon-16",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 16,
    "record": {
      "type": "event_record",
      "record_id": 1039
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>16</EventID><TimeCreated SystemTime='2026-10-09T12:14:00.000Z'/><EventRecordID>1039</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='Configuration'>Sysmon64.exe -c C:\\Windows\\config.xml</Data><Data Name='ConfigurationFileHash'>SHA256=ee66ff77889900aabbccddeeff11223344556677889900aabbccddeeff667788</Data></EventData></Event>",
  "config_check": {
    "check": "sysmon_configuration",
    "observed": "Sysmon64.exe -c C:\\Windows\\config.xml"
  },
  "unmapped": [
    {
      "name": "ConfigurationFileHash",
      "value": "SHA256=ee66ff77889900aabbccddeeff11223344556677889900aabbccddeeff667788"
    }
  ]
}
```

### EX-SYSMON-17 — Named pipe created (Sysmon EID 17)

<!-- covers: SEC-A Sysmon EID 17 pipe_create; PipeName lossless with prefix -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "pipe",
    "type": "pipe_create",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:15:00.000Z",
    "original": "2026-10-09 12:15:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-17",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 17,
    "record": {
      "type": "event_record",
      "record_id": 1040
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>17</EventID><TimeCreated SystemTime='2026-10-09T12:15:00.000Z'/><EventRecordID>1040</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>CreatePipe</Data><Data Name='UtcTime'>2026-10-09 12:15:00.000</Data><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='PipeName'>\\testpipe</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>CORP\\jdoe</Data></EventData></Event>",
  "pipe": {
    "name": "\\testpipe",
    "operation": "create"
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-18 — Named pipe connected (Sysmon EID 18)

<!-- covers: SEC-A Sysmon EID 18 pipe_connect -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "pipe",
    "type": "pipe_connect",
    "action": "connect",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:16:00.000Z",
    "original": "2026-10-09 12:16:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-18",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 18,
    "record": {
      "type": "event_record",
      "record_id": 1041
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>18</EventID><TimeCreated SystemTime='2026-10-09T12:16:00.000Z'/><EventRecordID>1041</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>ConnectPipe</Data><Data Name='UtcTime'>2026-10-09 12:16:00.000</Data><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0002-0000-0000-000000000002}</Data><Data Name='ProcessId'>6788</Data><Data Name='PipeName'>\\testpipe</Data><Data Name='Image'>C:\\Windows\\System32\\notepad.exe</Data><Data Name='User'>CORP\\jdoe</Data></EventData></Event>",
  "pipe": {
    "name": "\\testpipe",
    "operation": "connect"
  },
  "process": {
    "guid": "{1a2b3c4d-0002-0000-0000-000000000002}",
    "pid": 6788,
    "exe": "C:\\Windows\\System32\\notepad.exe",
    "name": "notepad.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-19 — WMI filter created (Sysmon EID 19)

<!-- covers: SEC-A Sysmon EID 19 wmi_filter_create; Name/Type/Destination/Consumer/Filter/EventType unmapped; no process payload -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "wmi",
    "type": "wmi_filter_create",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:17:00.000Z",
    "original": "2026-10-09 12:17:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-19",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 19,
    "record": {
      "type": "event_record",
      "record_id": 1042
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>19</EventID><TimeCreated SystemTime='2026-10-09T12:17:00.000Z'/><EventRecordID>1042</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>WmiFilterCreate</Data><Data Name='UtcTime'>2026-10-09 12:17:00.000</Data><Data Name='Operation'>Created</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='EventNamespace'>root\\subscription</Data><Data Name='Name'>EvilFilter</Data><Data Name='Query'>SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Process'</Data><Data Name='Type'>WQL</Data><Data Name='Destination'>-</Data><Data Name='Consumer'>-</Data><Data Name='Filter'>-</Data><Data Name='RuleName'>-</Data></EventData></Event>",
  "wmi": {
    "operation": "Created",
    "namespace": "root\\subscription",
    "client_user": "CORP\\jdoe",
    "query": "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Process'"
  },
  "unmapped": [
    {
      "name": "EventType",
      "value": "WmiFilterCreate"
    },
    {
      "name": "Name",
      "value": "EvilFilter"
    },
    {
      "name": "Type",
      "value": "WQL"
    },
    {
      "name": "Destination",
      "value": "-"
    },
    {
      "name": "Consumer",
      "value": "-"
    },
    {
      "name": "Filter",
      "value": "-"
    },
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-20 — WMI consumer created (Sysmon EID 20)

<!-- covers: SEC-A Sysmon EID 20 wmi_consumer_create; Name/Type/Destination unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "wmi",
    "type": "wmi_consumer_create",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:18:00.000Z",
    "original": "2026-10-09 12:18:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-20",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 20,
    "record": {
      "type": "event_record",
      "record_id": 1043
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>20</EventID><TimeCreated SystemTime='2026-10-09T12:18:00.000Z'/><EventRecordID>1043</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>WmiConsumerCreate</Data><Data Name='UtcTime'>2026-10-09 12:18:00.000</Data><Data Name='Operation'>Created</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='EventNamespace'>root\\subscription</Data><Data Name='Name'>EvilConsumer</Data><Data Name='Type'>Command Line</Data><Data Name='Destination'>C:\\Windows\\System32\\cmd.exe /c calc.exe</Data><Data Name='Consumer'>-</Data><Data Name='Filter'>-</Data><Data Name='Query'>-</Data><Data Name='RuleName'>-</Data></EventData></Event>",
  "wmi": {
    "operation": "Created",
    "namespace": "root\\subscription",
    "client_user": "CORP\\jdoe"
  },
  "unmapped": [
    {
      "name": "EventType",
      "value": "WmiConsumerCreate"
    },
    {
      "name": "Name",
      "value": "EvilConsumer"
    },
    {
      "name": "Type",
      "value": "Command Line"
    },
    {
      "name": "Destination",
      "value": "C:\\Windows\\System32\\cmd.exe /c calc.exe"
    },
    {
      "name": "Consumer",
      "value": "-"
    },
    {
      "name": "Filter",
      "value": "-"
    },
    {
      "name": "Query",
      "value": "-"
    },
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-21 — WMI consumer bound to filter (Sysmon EID 21)

<!-- covers: SEC-A Sysmon EID 21 wmi_consumer_filter_bind; Consumer/Filter unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "wmi",
    "type": "wmi_consumer_filter_bind",
    "action": "bind",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:19:00.000Z",
    "original": "2026-10-09 12:19:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-21",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 21,
    "record": {
      "type": "event_record",
      "record_id": 1044
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>21</EventID><TimeCreated SystemTime='2026-10-09T12:19:00.000Z'/><EventRecordID>1044</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>WmiConsumerToFilter</Data><Data Name='UtcTime'>2026-10-09 12:19:00.000</Data><Data Name='Operation'>Created</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='EventNamespace'>root\\subscription</Data><Data Name='Name'>EvilConsumer</Data><Data Name='Consumer'>CommandLineEventConsumer.Name=\"EvilConsumer\"</Data><Data Name='Filter'>__EventFilter.Name=\"EvilFilter\"</Data><Data Name='Type'>-</Data><Data Name='Destination'>-</Data><Data Name='Query'>-</Data><Data Name='RuleName'>-</Data></EventData></Event>",
  "wmi": {
    "operation": "Created",
    "namespace": "root\\subscription",
    "client_user": "CORP\\jdoe"
  },
  "unmapped": [
    {
      "name": "EventType",
      "value": "WmiConsumerToFilter"
    },
    {
      "name": "Name",
      "value": "EvilConsumer"
    },
    {
      "name": "Consumer",
      "value": "CommandLineEventConsumer.Name=\"EvilConsumer\""
    },
    {
      "name": "Filter",
      "value": "__EventFilter.Name=\"EvilFilter\""
    },
    {
      "name": "Type",
      "value": "-"
    },
    {
      "name": "Destination",
      "value": "-"
    },
    {
      "name": "Query",
      "value": "-"
    },
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-22 — DNS query (Sysmon EID 22)

<!-- covers: SEC-A Sysmon EID 22 dns_query; QueryStatus 0→success; QueryResults→answers INFERRED -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "dns",
    "type": "dns_query",
    "action": "query",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:20:00.000Z",
    "original": "2026-10-09 12:20:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-22",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 22,
    "record": {
      "type": "event_record",
      "record_id": 1045
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>22</EventID><TimeCreated SystemTime='2026-10-09T12:20:00.000Z'/><EventRecordID>1045</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-10-09 12:20:00.000</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='QueryName'>example.com</Data><Data Name='QueryStatus'>0</Data><Data Name='QueryResults'>93.184.216.34;</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>CORP\\jdoe</Data></EventData></Event>",
  "dns": {
    "query_name": "example.com",
    "query_status": "0",
    "answers": [
      "93.184.216.34"
    ],
    "process": {
      "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
      "pid": 4521,
      "exe": "C:\\Windows\\System32\\cmd.exe",
      "owner_name": "jdoe"
    }
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-23 — File deleted and archived (Sysmon EID 23)

<!-- covers: SEC-A Sysmon EID 23 file_delete; IsExecutable/Archived unmapped; archived flag via source.event_id -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_delete",
    "action": "delete",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:21:00.000Z",
    "original": "2026-10-09 12:21:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-23",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 23,
    "record": {
      "type": "event_record",
      "record_id": 1046
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>23</EventID><TimeCreated SystemTime='2026-10-09T12:21:00.000Z'/><EventRecordID>1046</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-10-09 12:21:00.000</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='TargetFilename'>C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe</Data><Data Name='Hashes'>SHA256=ff77889900aabbccddeeff11223344556677889900aabbccddeeff77889900</Data><Data Name='IsExecutable'>true</Data><Data Name='Archived'>true</Data></EventData></Event>",
  "file": {
    "path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe",
    "name": "payload.exe",
    "directory": "C:\\Users\\jdoe\\AppData\\Local\\Temp",
    "hashes": {
      "sha256": "ff77889900aabbccddeeff11223344556677889900aabbccddeeff77889900"
    }
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "IsExecutable",
      "value": "true"
    },
    {
      "name": "Archived",
      "value": "true"
    }
  ]
}
```

### EX-SYSMON-24 — Clipboard change (Sysmon EID 24)

<!-- covers: SEC-A Sysmon EID 24 clipboard_change; derived_by sentinel; no clipboard payload — Session/ClientInfo/Hashes/Archived unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "process",
    "type": "clipboard_change",
    "action": "change",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:22:00.000Z",
    "original": "2026-10-09 12:22:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-24",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 24,
    "record": {
      "type": "event_record",
      "record_id": 1047
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>24</EventID><TimeCreated SystemTime='2026-10-09T12:22:00.000Z'/><EventRecordID>1047</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>ClipboardChange</Data><Data Name='UtcTime'>2026-10-09 12:22:00.000</Data><Data Name='RuleName'>-</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='Session'>1</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='ClientInfo'>-</Data><Data Name='Hashes'>aa99bb00cc11dd22ee33ff44556677889900aabbccddeeff1122334455667788</Data><Data Name='Archived'>false</Data></EventData></Event>",
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "EventType",
      "value": "ClipboardChange"
    },
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "Session",
      "value": "1"
    },
    {
      "name": "ClientInfo",
      "value": "-"
    },
    {
      "name": "Hashes",
      "value": "aa99bb00cc11dd22ee33ff44556677889900aabbccddeeff1122334455667788"
    },
    {
      "name": "Archived",
      "value": "false"
    }
  ]
}
```

### EX-SYSMON-25 — Process tampering (Sysmon EID 25)

<!-- covers: SEC-A Sysmon EID 25 process_tampering; Type/EventType unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "process",
    "type": "process_tampering",
    "action": "modify",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:23:00.000Z",
    "original": "2026-10-09 12:23:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-25",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 25,
    "record": {
      "type": "event_record",
      "record_id": 1048
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>25</EventID><TimeCreated SystemTime='2026-10-09T12:23:00.000Z'/><EventRecordID>1048</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='EventType'>ImagePatch</Data><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-10-09 12:23:00.000</Data><Data Name='ProcessGuid'>{1a2b3c4d-0004-0000-0000-000000000004}</Data><Data Name='ProcessId'>8888</Data><Data Name='Image'>C:\\Users\\jdoe\\AppData\\Local\\Temp\\host.exe</Data><Data Name='Type'>Image is patched</Data><Data Name='User'>CORP\\jdoe</Data></EventData></Event>",
  "process": {
    "guid": "{1a2b3c4d-0004-0000-0000-000000000004}",
    "pid": 8888,
    "exe": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\host.exe",
    "name": "host.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "EventType",
      "value": "ImagePatch"
    },
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "Type",
      "value": "Image is patched"
    }
  ]
}
```

### EX-SYSMON-26 — File delete logged (Sysmon EID 26)

<!-- covers: SEC-A Sysmon EID 26 file_delete; no Archived field (vs EID 23) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_delete",
    "action": "delete",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:24:00.000Z",
    "original": "2026-10-09 12:24:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-26",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 26,
    "record": {
      "type": "event_record",
      "record_id": 1049
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>26</EventID><TimeCreated SystemTime='2026-10-09T12:24:00.000Z'/><EventRecordID>1049</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-10-09 12:24:00.000</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='TargetFilename'>C:\\Users\\jdoe\\AppData\\Local\\Temp\\notes.txt</Data><Data Name='Hashes'>SHA256=1122aabb33cc44dd55ee66ff778899001122aabb33cc44dd55ee66ff77889900</Data><Data Name='IsExecutable'>false</Data></EventData></Event>",
  "file": {
    "path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\notes.txt",
    "name": "notes.txt",
    "directory": "C:\\Users\\jdoe\\AppData\\Local\\Temp",
    "hashes": {
      "sha256": "1122aabb33cc44dd55ee66ff778899001122aabb33cc44dd55ee66ff77889900"
    }
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "IsExecutable",
      "value": "false"
    }
  ]
}
```

### EX-SYSMON-27 — Executable write blocked (Sysmon EID 27)

<!-- covers: SEC-A Sysmon EID 27 file_block_executable; outcome=block succeeded (INFERRED semantics) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_block_executable",
    "action": "block",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:25:00.000Z",
    "original": "2026-10-09 12:25:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-27",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 27,
    "record": {
      "type": "event_record",
      "record_id": 1050
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>27</EventID><TimeCreated SystemTime='2026-10-09T12:25:00.000Z'/><EventRecordID>1050</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-10-09 12:25:00.000</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='TargetFilename'>C:\\Users\\jdoe\\AppData\\Local\\Temp\\blocked.exe</Data><Data Name='Hashes'>SHA256=2233aabb44cc55dd66ee77ff889900112233aabb44cc55dd66ee77ff88990011</Data></EventData></Event>",
  "file": {
    "path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\blocked.exe",
    "name": "blocked.exe",
    "directory": "C:\\Users\\jdoe\\AppData\\Local\\Temp",
    "hashes": {
      "sha256": "2233aabb44cc55dd66ee77ff889900112233aabb44cc55dd66ee77ff88990011"
    }
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-28 — File shredding blocked (Sysmon EID 28)

<!-- covers: SEC-A Sysmon EID 28 file_block_shredding; IsExecutable unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_block_shredding",
    "action": "block",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:26:00.000Z",
    "original": "2026-10-09 12:26:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-28",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 28,
    "record": {
      "type": "event_record",
      "record_id": 1051
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>28</EventID><TimeCreated SystemTime='2026-10-09T12:26:00.000Z'/><EventRecordID>1051</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-10-09 12:26:00.000</Data><Data Name='ProcessGuid'>{1a2b3c4d-0005-0000-0000-000000000005}</Data><Data Name='ProcessId'>9999</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='Image'>C:\\Tools\\sdelete64.exe</Data><Data Name='TargetFilename'>C:\\Users\\jdoe\\Documents\\evidence.docx</Data><Data Name='Hashes'>SHA256=3344aabb55cc66dd77ee88ff990011223344aabb55cc66dd77ee88ff99001122</Data><Data Name='IsExecutable'>true</Data></EventData></Event>",
  "file": {
    "path": "C:\\Users\\jdoe\\Documents\\evidence.docx",
    "name": "evidence.docx",
    "directory": "C:\\Users\\jdoe\\Documents",
    "hashes": {
      "sha256": "3344aabb55cc66dd77ee88ff990011223344aabb55cc66dd77ee88ff99001122"
    }
  },
  "process": {
    "guid": "{1a2b3c4d-0005-0000-0000-000000000005}",
    "pid": 9999,
    "exe": "C:\\Tools\\sdelete64.exe",
    "name": "sdelete64.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    },
    {
      "name": "IsExecutable",
      "value": "true"
    }
  ]
}
```

### EX-SYSMON-29 — Executable detected (Sysmon EID 29)

<!-- covers: SEC-A Sysmon EID 29 file_executable_detected; no signature fields (absent≠unsigned) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_executable_detected",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:27:00.000Z",
    "original": "2026-10-09 12:27:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sysmon-29",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 29,
    "record": {
      "type": "event_record",
      "record_id": 1052
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>29</EventID><TimeCreated SystemTime='2026-10-09T12:27:00.000Z'/><EventRecordID>1052</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-10-09 12:27:00.000</Data><Data Name='ProcessGuid'>{1a2b3c4d-0001-0000-0000-000000000001}</Data><Data Name='ProcessId'>4521</Data><Data Name='User'>CORP\\jdoe</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='TargetFilename'>C:\\Users\\jdoe\\Downloads\\newtool.exe</Data><Data Name='Hashes'>SHA256=4455aabb66cc77dd88ee99ff001122334455aabb66cc77dd88ee99ff00112233</Data></EventData></Event>",
  "file": {
    "path": "C:\\Users\\jdoe\\Downloads\\newtool.exe",
    "name": "newtool.exe",
    "directory": "C:\\Users\\jdoe\\Downloads",
    "hashes": {
      "sha256": "4455aabb66cc77dd88ee99ff001122334455aabb66cc77dd88ee99ff00112233"
    }
  },
  "process": {
    "guid": "{1a2b3c4d-0001-0000-0000-000000000001}",
    "pid": 4521,
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "owner_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "RuleName",
      "value": "-"
    }
  ]
}
```

### EX-SYSMON-255 — Sysmon internal error (Sysmon EID 255)

<!-- covers: SEC-A Sysmon EID 255 sysmon_error; envelope-only; no verified EventData; derived_by sentinel; UNVERIFIED fields -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "third_party_alert",
    "type": "sysmon_error",
    "action": "error",
    "outcome": "unknown",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T12:28:00.000Z",
    "original": "2026-10-09 12:28:00.000",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "millisecond",
    "state": "inferred"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sysmon-255",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 255,
    "record": {
      "type": "event_record",
      "record_id": 1053
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>255</EventID><TimeCreated SystemTime='2026-10-09T12:28:00.000Z'/><EventRecordID>1053</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><RenderingInfo><Message>Sysmon error: failed to load driver</Message><Level>Error</Level><Task>None</Task><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Provider>Microsoft-Windows-Sysmon</Provider></RenderingInfo></Event>",
  "third_party_alert": {
    "vendor": "Microsoft",
    "product": "Sysmon",
    "description": {
      "$state": "inferred",
      "$note": "description synthesized from RenderingInfo/Message; EventData names UNVERIFIED",
      "$raw": "Sysmon error: failed to load driver"
    }
  }
}
```

## Windows Security channel (32)

### EX-SEC-1102 — Audit log cleared (Security EID 1102)

<!-- covers: SEC-A Security EID 1102 audit_log_cleared; derived_by sentinel; UserData not EventData -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "fim",
    "type": "audit_log_cleared",
    "action": "clear",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:00:00.000000Z",
    "original": "2026-10-09T13:00:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x3e7"
  },
  "source": {
    "file_id": "evt-sec-1102",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 1102,
    "record": {
      "type": "event_record",
      "record_id": 2001
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID><TimeCreated SystemTime='2026-10-09T13:00:00.0000000Z'/><EventRecordID>2001</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security/></System><UserData><LogFileCleared xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><SubjectUserSid>S-1-5-21-1000-2000-3000-1001</SubjectUserSid><SubjectUserName>jdoe</SubjectUserName><SubjectDomainName>CORP</SubjectDomainName><SubjectLogonId>0x3e7</SubjectLogonId></LogFileCleared></UserData></Event>",
  "fim": {
    "path": "Security",
    "operation": "audit_log_cleared"
  }
}
```

### EX-SEC-4624 — Logon success (Security EID 4624)

<!-- covers: SEC-A Security EID 4624 logon_success; hex PID→int INFERRED; ElevatedToken %%1842→invalid state -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "logon_success",
    "action": "logon",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:01:00.000000Z",
    "original": "2026-10-09T13:01:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-18",
    "name": "SYSTEM",
    "domain": "NT AUTHORITY",
    "logon_id": "0x3e7"
  },
  "source": {
    "file_id": "evt-sec-4624",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4624,
    "record": {
      "type": "event_record",
      "record_id": 2002
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><TimeCreated SystemTime='2026-10-09T13:01:00.0000000Z'/><EventRecordID>2002</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>SYSTEM</Data><Data Name='SubjectDomainName'>NT AUTHORITY</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='TargetUserName'>jdoe</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetLogonId'>0x123456</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32</Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>CLIENT01</Data><Data Name='LogonGuid'>{aa00bb11-cc22-dd33-ee44-ff5566778899}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x4c8</Data><Data Name='ProcessName'>C:\\Windows\\System32\\winlogon.exe</Data><Data Name='IpAddress'>10.10.5.50</Data><Data Name='IpPort'>51515</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event>",
  "authentication": {
    "logon_type": 10,
    "logon_id": "0x123456",
    "logon_guid": "{aa00bb11-cc22-dd33-ee44-ff5566778899}",
    "account_sid": "S-1-5-21-1000-2000-3000-1001",
    "account_name": "jdoe",
    "account_domain": "CORP",
    "source_ip": "10.10.5.50",
    "workstation": "CLIENT01",
    "auth_package": "Negotiate",
    "key_length": 0,
    "process_pid": {
      "$state": "inferred",
      "$note": "hex 0x4c8→int",
      "$raw": "0x4c8"
    },
    "process_name": "C:\\Windows\\System32\\winlogon.exe",
    "elev_token": {
      "$state": "invalid",
      "$note": "%%nnnn message-table constant; expansion lives in message table, not EVTX",
      "$raw": "%%1842"
    }
  },
  "unmapped": [
    {
      "name": "LogonProcessName",
      "value": "User32"
    },
    {
      "name": "TransmittedServices",
      "value": "-"
    },
    {
      "name": "LmPackageName",
      "value": "-"
    },
    {
      "name": "IpPort",
      "value": "51515"
    },
    {
      "name": "ImpersonationLevel",
      "value": "%%1833"
    },
    {
      "name": "RestrictedAdminMode",
      "value": "-"
    },
    {
      "name": "TargetOutboundUserName",
      "value": "-"
    },
    {
      "name": "TargetOutboundDomainName",
      "value": "-"
    },
    {
      "name": "VirtualAccount",
      "value": "%%1843"
    },
    {
      "name": "TargetLinkedLogonId",
      "value": "0x0"
    }
  ]
}
```

### EX-SEC-4625 — Logon failure (Security EID 4625)

<!-- covers: SEC-A Security EID 4625 logon_failure; Status/SubStatus kept as strings; PID reuse trap -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "logon_failure",
    "action": "logon",
    "outcome": "failure",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:02:00.000000Z",
    "original": "2026-10-09T13:02:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-0-0",
    "name": {
      "$state": "null",
      "$raw": "-"
    },
    "domain": {
      "$state": "null",
      "$raw": "-"
    },
    "logon_id": "0x0"
  },
  "source": {
    "file_id": "evt-sec-4625",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4625,
    "record": {
      "type": "event_record",
      "record_id": 2003
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><TimeCreated SystemTime='2026-10-09T13:02:00.0000000Z'/><EventRecordID>2003</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>administrator</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetLogonId'>0x0</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp</Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>EVILPC</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>10.10.5.99</Data><Data Name='IpPort'>44444</Data></EventData></Event>",
  "authentication": {
    "logon_type": 3,
    "logon_id": "0x0",
    "account_sid": "S-1-0-0",
    "account_name": "administrator",
    "account_domain": "CORP",
    "source_ip": "10.10.5.99",
    "workstation": "EVILPC",
    "auth_package": "NTLM",
    "key_length": 0,
    "status": "0xc000006d",
    "sub_status": "0xc0000064",
    "failure_reason": "%%2313",
    "process_pid": {
      "$state": "inferred",
      "$note": "hex 0x0→int",
      "$raw": "0x0"
    },
    "process_name": {
      "$state": "null",
      "$raw": "-"
    }
  },
  "unmapped": [
    {
      "name": "LogonProcessName",
      "value": "NtLmSsp"
    },
    {
      "name": "TransmittedServices",
      "value": "-"
    },
    {
      "name": "LmPackageName",
      "value": "-"
    },
    {
      "name": "IpPort",
      "value": "44444"
    }
  ]
}
```

### EX-SEC-4634 — Account logged off (Security EID 4634)

<!-- covers: SEC-A Security EID 4634 logoff; envelope user mirrored from Target* (INFERRED) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "logoff",
    "action": "logoff",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:03:00.000000Z",
    "original": "2026-10-09T13:03:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sec-4634",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4634,
    "record": {
      "type": "event_record",
      "record_id": 2004
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4634</EventID><TimeCreated SystemTime='2026-10-09T13:03:00.0000000Z'/><EventRecordID>2004</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='TargetUserName'>jdoe</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetLogonId'>0x123456</Data><Data Name='LogonType'>10</Data></EventData></Event>",
  "authentication": {
    "logon_type": 10,
    "logon_id": "0x123456",
    "account_sid": "S-1-5-21-1000-2000-3000-1001",
    "account_name": "jdoe",
    "account_domain": "CORP"
  }
}
```

### EX-SEC-4647 — User-initiated logoff (Security EID 4647)

<!-- covers: SEC-A Security EID 4647 logoff_initiated; pairs with 4634/4624 via TargetLogonId -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "logoff_initiated",
    "action": "logoff",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:04:00.000000Z",
    "original": "2026-10-09T13:04:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP"
  },
  "source": {
    "file_id": "evt-sec-4647",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4647,
    "record": {
      "type": "event_record",
      "record_id": 2005
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4647</EventID><TimeCreated SystemTime='2026-10-09T13:04:00.0000000Z'/><EventRecordID>2005</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='TargetUserName'>jdoe</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetLogonId'>0x123456</Data></EventData></Event>",
  "authentication": {
    "logon_id": "0x123456",
    "account_sid": "S-1-5-21-1000-2000-3000-1001",
    "account_name": "jdoe",
    "account_domain": "CORP"
  }
}
```

### EX-SEC-4648 — Explicit credential logon (Security EID 4648)

<!-- covers: SEC-A Security EID 4648 explicit_credential_logon; TargetLogonGuid/TargetServerName/TargetInfo unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "explicit_credential_logon",
    "action": "logon",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:05:00.000000Z",
    "original": "2026-10-09T13:05:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4648",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4648,
    "record": {
      "type": "event_record",
      "record_id": 2006
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4648</EventID><TimeCreated SystemTime='2026-10-09T13:05:00.0000000Z'/><EventRecordID>2006</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='LogonGuid'>{bb11cc22-dd33-ee44-ff55-667788990011}</Data><Data Name='TargetUserName'>svc_admin</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetLogonGuid'>{cc22dd33-ee44-ff55-6677-889900112233}</Data><Data Name='TargetServerName'>FILESRV01</Data><Data Name='TargetInfo'>CORP\\svc_admin</Data><Data Name='ProcessId'>0x1f40</Data><Data Name='ProcessName'>C:\\Windows\\System32\\runas.exe</Data><Data Name='IpAddress'>10.10.5.23</Data><Data Name='IpPort'>51520</Data></EventData></Event>",
  "authentication": {
    "logon_guid": "{bb11cc22-dd33-ee44-ff55-667788990011}",
    "target_name": "svc_admin",
    "target_domain": "CORP",
    "source_ip": "10.10.5.23",
    "caller_process_id": {
      "$state": "inferred",
      "$note": "hex 0x1f40→int",
      "$raw": "0x1f40"
    },
    "caller_process_name": "C:\\Windows\\System32\\runas.exe"
  },
  "unmapped": [
    {
      "name": "TargetLogonGuid",
      "value": "{cc22dd33-ee44-ff55-6677-889900112233}"
    },
    {
      "name": "TargetServerName",
      "value": "FILESRV01"
    },
    {
      "name": "TargetInfo",
      "value": "CORP\\svc_admin"
    },
    {
      "name": "IpPort",
      "value": "51520"
    }
  ]
}
```

### EX-SEC-4672 — Special privileges assigned (Security EID 4672)

<!-- covers: SEC-A Security EID 4672 special_privileges_assigned; PrivilegeList unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "special_privileges_assigned",
    "action": "assign",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:06:00.000000Z",
    "original": "2026-10-09T13:06:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4672",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4672,
    "record": {
      "type": "event_record",
      "record_id": 2007
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4672</EventID><TimeCreated SystemTime='2026-10-09T13:06:00.0000000Z'/><EventRecordID>2007</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='PrivilegeList'>SeDebugPrivilege\r\nSeBackupPrivilege\r\nSeRestorePrivilege</Data></EventData></Event>",
  "authentication": {
    "logon_id": "0x123456"
  },
  "unmapped": [
    {
      "name": "PrivilegeList",
      "value": "SeDebugPrivilege\r\nSeBackupPrivilege\r\nSeRestorePrivilege"
    }
  ]
}
```

### EX-SEC-4688 — Process created (Security EID 4688)

<!-- covers: SEC-A Security EID 4688 process_create; ProcessId=parent PID; hex→int INFERRED; MandatoryLabel overrides TokenElevationType -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "process",
    "type": "process_create",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:07:00.000000Z",
    "original": "2026-10-09T13:07:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4688",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4688,
    "record": {
      "type": "event_record",
      "record_id": 2008
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4688</EventID><TimeCreated SystemTime='2026-10-09T13:07:00.0000000Z'/><EventRecordID>2008</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='NewProcessId'>0x1234</Data><Data Name='NewProcessName'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='TokenElevationType'>%%1968</Data><Data Name='ProcessId'>0x8fc</Data><Data Name='CommandLine'>cmd.exe /c powershell -enc SQBFAFgA</Data><Data Name='TargetUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='TargetUserName'>jdoe</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetLogonId'>0x123456</Data><Data Name='ParentProcessName'>C:\\Windows\\explorer.exe</Data><Data Name='MandatoryLabel'>S-1-16-8192</Data></EventData></Event>",
  "process": {
    "pid": {
      "$state": "inferred",
      "$note": "hex 0x1234→int",
      "$raw": "0x1234"
    },
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe",
    "command_line": "cmd.exe /c powershell -enc SQBFAFgA",
    "integrity_level": "S-1-16-8192",
    "owner_sid": "S-1-5-21-1000-2000-3000-1001",
    "owner_name": "jdoe",
    "parent": {
      "pid": {
        "$state": "inferred",
        "$note": "hex 0x8fc→int (ProcessId field is PARENT pid)",
        "$raw": "0x8fc"
      },
      "exe": "C:\\Windows\\explorer.exe",
      "name": "explorer.exe"
    }
  },
  "unmapped": [
    {
      "name": "TokenElevationType",
      "value": "%%1968"
    },
    {
      "name": "TargetDomainName",
      "value": "CORP"
    },
    {
      "name": "TargetLogonId",
      "value": "0x123456"
    }
  ]
}
```

### EX-SEC-4689 — Process exited (Security EID 4689)

<!-- covers: SEC-A Security EID 4689 process_terminate; Status→unmapped (no process.exit_code) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "process",
    "type": "process_terminate",
    "action": "terminate",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:08:00.000000Z",
    "original": "2026-10-09T13:08:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4689",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4689,
    "record": {
      "type": "event_record",
      "record_id": 2009
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4689</EventID><TimeCreated SystemTime='2026-10-09T13:08:00.0000000Z'/><EventRecordID>2009</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='Status'>0x0</Data><Data Name='ProcessId'>0x1234</Data><Data Name='ProcessName'>C:\\Windows\\System32\\cmd.exe</Data></EventData></Event>",
  "process": {
    "pid": {
      "$state": "inferred",
      "$note": "hex 0x1234→int",
      "$raw": "0x1234"
    },
    "exe": "C:\\Windows\\System32\\cmd.exe",
    "name": "cmd.exe"
  },
  "unmapped": [
    {
      "name": "Status",
      "value": "0x0"
    }
  ]
}
```

### EX-SEC-4697 — Service installed (Security EID 4697)

<!-- covers: SEC-A Security EID 4697 service_install -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "service",
    "type": "service_install",
    "action": "install",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:09:00.000000Z",
    "original": "2026-10-09T13:09:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4697",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4697,
    "record": {
      "type": "event_record",
      "record_id": 2010
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4697</EventID><TimeCreated SystemTime='2026-10-09T13:09:00.0000000Z'/><EventRecordID>2010</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='ServiceName'>EvilSvc</Data><Data Name='ServiceFileName'>C:\\Temp\\evil.exe</Data><Data Name='ServiceType'>0x10</Data><Data Name='ServiceStartType'>demand</Data><Data Name='ServiceAccount'>LocalSystem</Data></EventData></Event>",
  "service": {
    "name": "EvilSvc",
    "image_path": "C:\\Temp\\evil.exe",
    "service_type": "0x10",
    "start_type": "demand",
    "account_name": "LocalSystem"
  }
}
```

### EX-SEC-4698 — Scheduled task created (Security EID 4698)

<!-- covers: SEC-A Security EID 4698 scheduled_task_create; TaskContent kept raw; ClientProcessStartKey/FQDN unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "scheduled_task",
    "type": "scheduled_task_create",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:10:00.000000Z",
    "original": "2026-10-09T13:10:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4698",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4698,
    "record": {
      "type": "event_record",
      "record_id": 2011
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4698</EventID><TimeCreated SystemTime='2026-10-09T13:10:00.0000000Z'/><EventRecordID>2011</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='TaskName'>\\Updater</Data><Data Name='TaskContent'>&lt;Task&gt;&lt;Actions&gt;&lt;Exec&gt;&lt;Command&gt;C:\\Temp\\evil.exe&lt;/Command&gt;&lt;/Exec&gt;&lt;/Actions&gt;&lt;/Task&gt;</Data><Data Name='ClientProcessStartKey'>1337777</Data><Data Name='ClientProcessId'>0x8fc</Data><Data Name='ParentProcessId'>0x4e4</Data><Data Name='RpcCallClientLocality'>0</Data><Data Name='FQDN'>WS-DEMO01.corp.local</Data></EventData></Event>",
  "scheduled_task": {
    "name": "\\Updater",
    "task_xml": "<Task><Actions><Exec><Command>C:\\Temp\\evil.exe</Command></Exec></Actions></Task>"
  },
  "process": {
    "pid": {
      "$state": "inferred",
      "$note": "hex 0x8fc→int (ClientProcessId)",
      "$raw": "0x8fc"
    },
    "parent": {
      "pid": {
        "$state": "inferred",
        "$note": "hex 0x4e4→int (ParentProcessId)",
        "$raw": "0x4e4"
      }
    }
  },
  "unmapped": [
    {
      "name": "ClientProcessStartKey",
      "value": "1337777"
    },
    {
      "name": "RpcCallClientLocality",
      "value": "0"
    },
    {
      "name": "FQDN",
      "value": "WS-DEMO01.corp.local"
    }
  ]
}
```

### EX-SEC-4720 — User account created (Security EID 4720)

<!-- covers: SEC-A Security EID 4720 account_created; UAC fields unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "account",
    "type": "account_created",
    "action": "create",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:11:00.000000Z",
    "original": "2026-10-09T13:11:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4720",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4720,
    "record": {
      "type": "event_record",
      "record_id": 2012
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4720</EventID><TimeCreated SystemTime='2026-10-09T13:11:00.0000000Z'/><EventRecordID>2012</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>backdoor</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-1050</Data><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='PrivilegeList'>-</Data><Data Name='SamAccountName'>backdoor</Data><Data Name='DisplayName'>Back Door</Data><Data Name='UserPrincipalName'>backdoor@corp.local</Data><Data Name='HomeDirectory'>-</Data><Data Name='HomePath'>-</Data><Data Name='ScriptPath'>-</Data><Data Name='ProfilePath'>-</Data><Data Name='UserWorkstations'>-</Data><Data Name='PasswordLastSet'>10/9/2026 1:11:00 PM</Data><Data Name='AccountExpires'>Never</Data><Data Name='PrimaryGroupId'>513</Data><Data Name='AllowedToDelegateTo'>-</Data><Data Name='OldUacValue'>0x0</Data><Data Name='NewUacValue'>0x15</Data><Data Name='UserAccountControl'>0x15</Data><Data Name='UserParameters'>-</Data><Data Name='SidHistory'>-</Data><Data Name='LogonHours'>-</Data></EventData></Event>",
  "account": {
    "sid": "S-1-5-21-1000-2000-3000-1050",
    "name": "backdoor",
    "domain": "CORP",
    "upn": "backdoor@corp.local",
    "display_name": "Back Door",
    "sam_account_name": "backdoor",
    "account_type": "user"
  },
  "unmapped": [
    {
      "name": "PrivilegeList",
      "value": "-"
    },
    {
      "name": "HomeDirectory",
      "value": "-"
    },
    {
      "name": "HomePath",
      "value": "-"
    },
    {
      "name": "ScriptPath",
      "value": "-"
    },
    {
      "name": "ProfilePath",
      "value": "-"
    },
    {
      "name": "UserWorkstations",
      "value": "-"
    },
    {
      "name": "PasswordLastSet",
      "value": "10/9/2026 1:11:00 PM"
    },
    {
      "name": "AccountExpires",
      "value": "Never"
    },
    {
      "name": "PrimaryGroupId",
      "value": "513"
    },
    {
      "name": "AllowedToDelegateTo",
      "value": "-"
    },
    {
      "name": "OldUacValue",
      "value": "0x0"
    },
    {
      "name": "NewUacValue",
      "value": "0x15"
    },
    {
      "name": "UserAccountControl",
      "value": "0x15"
    },
    {
      "name": "UserParameters",
      "value": "-"
    },
    {
      "name": "LogonHours",
      "value": "-"
    }
  ]
}
```

### EX-SEC-4722 — User account enabled (Security EID 4722)

<!-- covers: SEC-A Security EID 4722 account_enabled; account.enabled=true is derived constant, not a source field -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "account",
    "type": "account_enabled",
    "action": "enable",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:12:00.000000Z",
    "original": "2026-10-09T13:12:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4722",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4722,
    "record": {
      "type": "event_record",
      "record_id": 2013
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4722</EventID><TimeCreated SystemTime='2026-10-09T13:12:00.0000000Z'/><EventRecordID>2013</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>backdoor</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-1050</Data><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data></EventData></Event>",
  "account": {
    "sid": "S-1-5-21-1000-2000-3000-1050",
    "name": "backdoor",
    "domain": "CORP"
  }
}
```

### EX-SEC-4724 — Password reset attempted (Security EID 4724)

<!-- covers: SEC-A Security EID 4724 password_reset; title (S,F) but no Status field → outcome unknown -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "account",
    "type": "password_reset",
    "action": "reset",
    "outcome": "unknown",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:13:00.000000Z",
    "original": "2026-10-09T13:13:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4724",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4724,
    "record": {
      "type": "event_record",
      "record_id": 2014
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4724</EventID><TimeCreated SystemTime='2026-10-09T13:13:00.0000000Z'/><EventRecordID>2014</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>backdoor</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-1050</Data><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data></EventData></Event>",
  "account": {
    "sid": "S-1-5-21-1000-2000-3000-1050",
    "name": "backdoor",
    "domain": "CORP"
  }
}
```

### EX-SEC-4726 — User account deleted (Security EID 4726)

<!-- covers: SEC-A Security EID 4726 account_deleted; SID is durable join key -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "account",
    "type": "account_deleted",
    "action": "delete",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:14:00.000000Z",
    "original": "2026-10-09T13:14:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4726",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4726,
    "record": {
      "type": "event_record",
      "record_id": 2015
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4726</EventID><TimeCreated SystemTime='2026-10-09T13:14:00.0000000Z'/><EventRecordID>2015</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>backdoor</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-1050</Data><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='PrivilegeList'>-</Data></EventData></Event>",
  "account": {
    "sid": "S-1-5-21-1000-2000-3000-1050",
    "name": "backdoor",
    "domain": "CORP"
  },
  "unmapped": [
    {
      "name": "PrivilegeList",
      "value": "-"
    }
  ]
}
```

### EX-SEC-4728 — Member added to global group (Security EID 4728)

<!-- covers: SEC-A Security EID 4728; field names by documented equivalence to 4732 (A-SEC-GRPMGMT) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "group_membership",
    "type": "member_added_to_global_group",
    "action": "add",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:15:00.000000Z",
    "original": "2026-10-09T13:15:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4728",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4728,
    "record": {
      "type": "event_record",
      "record_id": 2016
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4728</EventID><TimeCreated SystemTime='2026-10-09T13:15:00.0000000Z'/><EventRecordID>2016</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='MemberName'>CORP\\backdoor</Data><Data Name='MemberSid'>S-1-5-21-1000-2000-3000-1050</Data><Data Name='TargetUserName'>Domain Admins</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-512</Data><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='PrivilegeList'>-</Data></EventData></Event>",
  "group_membership": {
    "action": "added",
    "group_sid": "S-1-5-21-1000-2000-3000-512",
    "group_name": "Domain Admins",
    "domain": "CORP",
    "member_sid": "S-1-5-21-1000-2000-3000-1050",
    "member_name": "CORP\\backdoor",
    "subject_sid": "S-1-5-21-1000-2000-3000-1001",
    "subject_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "PrivilegeList",
      "value": "-"
    }
  ]
}
```

### EX-SEC-4732 — Member added to local group (Security EID 4732)

<!-- covers: SEC-A Security EID 4732 member_added_to_local_group -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "group_membership",
    "type": "member_added_to_local_group",
    "action": "add",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:16:00.000000Z",
    "original": "2026-10-09T13:16:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4732",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4732,
    "record": {
      "type": "event_record",
      "record_id": 2017
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4732</EventID><TimeCreated SystemTime='2026-10-09T13:16:00.0000000Z'/><EventRecordID>2017</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='MemberName'>CORP\\backdoor</Data><Data Name='MemberSid'>S-1-5-21-1000-2000-3000-1050</Data><Data Name='TargetUserName'>Administrators</Data><Data Name='TargetDomainName'>WS-DEMO01</Data><Data Name='TargetSid'>S-1-5-32-544</Data><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='PrivilegeList'>-</Data></EventData></Event>",
  "group_membership": {
    "action": "added",
    "group_sid": "S-1-5-32-544",
    "group_name": "Administrators",
    "domain": "WS-DEMO01",
    "member_sid": "S-1-5-21-1000-2000-3000-1050",
    "member_name": "CORP\\backdoor",
    "subject_sid": "S-1-5-21-1000-2000-3000-1001",
    "subject_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "PrivilegeList",
      "value": "-"
    }
  ]
}
```

### EX-SEC-4738 — User account changed (Security EID 4738)

<!-- covers: SEC-A Security EID 4738 account_changed; Dummy placeholder kept; post-change values only -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "account",
    "type": "account_changed",
    "action": "modify",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:17:00.000000Z",
    "original": "2026-10-09T13:17:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4738",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4738,
    "record": {
      "type": "event_record",
      "record_id": 2018
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4738</EventID><TimeCreated SystemTime='2026-10-09T13:17:00.0000000Z'/><EventRecordID>2018</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='Dummy'/><Data Name='TargetUserName'>backdoor</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-1050</Data><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='PrivilegeList'>-</Data><Data Name='SamAccountName'>backdoor</Data><Data Name='DisplayName'>Totally Legit</Data><Data Name='UserPrincipalName'>backdoor@corp.local</Data><Data Name='HomeDirectory'>-</Data><Data Name='HomePath'>-</Data><Data Name='ScriptPath'>-</Data><Data Name='ProfilePath'>-</Data><Data Name='UserWorkstations'>-</Data><Data Name='PasswordLastSet'>10/9/2026 1:11:00 PM</Data><Data Name='AccountExpires'>Never</Data><Data Name='PrimaryGroupId'>513</Data><Data Name='AllowedToDelegateTo'>-</Data><Data Name='OldUacValue'>0x15</Data><Data Name='NewUacValue'>0x15</Data><Data Name='UserAccountControl'>0x15</Data><Data Name='UserParameters'>-</Data><Data Name='SidHistory'>-</Data><Data Name='LogonHours'>-</Data></EventData></Event>",
  "account": {
    "sid": "S-1-5-21-1000-2000-3000-1050",
    "name": "backdoor",
    "domain": "CORP",
    "upn": "backdoor@corp.local",
    "display_name": "Totally Legit",
    "sam_account_name": "backdoor"
  },
  "unmapped": [
    {
      "name": "Dummy",
      "value": {
        "$state": "null",
        "$note": "literal placeholder element"
      }
    },
    {
      "name": "PrivilegeList",
      "value": "-"
    },
    {
      "name": "HomeDirectory",
      "value": "-"
    },
    {
      "name": "HomePath",
      "value": "-"
    },
    {
      "name": "ScriptPath",
      "value": "-"
    },
    {
      "name": "ProfilePath",
      "value": "-"
    },
    {
      "name": "UserWorkstations",
      "value": "-"
    },
    {
      "name": "PasswordLastSet",
      "value": "10/9/2026 1:11:00 PM"
    },
    {
      "name": "AccountExpires",
      "value": "Never"
    },
    {
      "name": "PrimaryGroupId",
      "value": "513"
    },
    {
      "name": "AllowedToDelegateTo",
      "value": "-"
    },
    {
      "name": "OldUacValue",
      "value": "0x15"
    },
    {
      "name": "NewUacValue",
      "value": "0x15"
    },
    {
      "name": "UserAccountControl",
      "value": "0x15"
    },
    {
      "name": "UserParameters",
      "value": "-"
    },
    {
      "name": "LogonHours",
      "value": "-"
    }
  ]
}
```

### EX-SEC-4740 — Account locked out (Security EID 4740)

<!-- covers: SEC-A Security EID 4740 account_locked_out; subject=trigger source, target=victim -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "account",
    "type": "account_locked_out",
    "action": "lock",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:18:00.000000Z",
    "original": "2026-10-09T13:18:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-18",
    "name": "WS-DEMO01$",
    "domain": "WORKGROUP",
    "logon_id": "0x3e7"
  },
  "source": {
    "file_id": "evt-sec-4740",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4740,
    "record": {
      "type": "event_record",
      "record_id": 2019
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4740</EventID><TimeCreated SystemTime='2026-10-09T13:18:00.0000000Z'/><EventRecordID>2019</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>jdoe</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>WS-DEMO01$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data></EventData></Event>",
  "account": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP"
  }
}
```

### EX-SEC-4756 — Member added to universal group (Security EID 4756)

<!-- covers: SEC-A Security EID 4756; field names by documented equivalence to 4732 (A-SEC-GRPMGMT) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "group_membership",
    "type": "member_added_to_universal_group",
    "action": "add",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:19:00.000000Z",
    "original": "2026-10-09T13:19:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-4756",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4756,
    "record": {
      "type": "event_record",
      "record_id": 2020
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4756</EventID><TimeCreated SystemTime='2026-10-09T13:19:00.0000000Z'/><EventRecordID>2020</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='MemberName'>CORP\\backdoor</Data><Data Name='MemberSid'>S-1-5-21-1000-2000-3000-1050</Data><Data Name='TargetUserName'>Enterprise Admins</Data><Data Name='TargetDomainName'>corp.local</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-519</Data><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='PrivilegeList'>-</Data></EventData></Event>",
  "group_membership": {
    "action": "added",
    "group_sid": "S-1-5-21-1000-2000-3000-519",
    "group_name": "Enterprise Admins",
    "domain": "corp.local",
    "member_sid": "S-1-5-21-1000-2000-3000-1050",
    "member_name": "CORP\\backdoor",
    "subject_sid": "S-1-5-21-1000-2000-3000-1001",
    "subject_name": "jdoe"
  },
  "unmapped": [
    {
      "name": "PrivilegeList",
      "value": "-"
    }
  ]
}
```

### EX-SEC-4767 — Account unlocked (Security EID 4767)

<!-- covers: SEC-A Security EID 4767 account_unlocked; pair with 4740 via account.sid -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "account",
    "type": "account_unlocked",
    "action": "unlock",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:20:00.000000Z",
    "original": "2026-10-09T13:20:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "admin",
    "domain": "CORP",
    "logon_id": "0x654321"
  },
  "source": {
    "file_id": "evt-sec-4767",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4767,
    "record": {
      "type": "event_record",
      "record_id": 2021
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4767</EventID><TimeCreated SystemTime='2026-10-09T13:20:00.0000000Z'/><EventRecordID>2021</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>jdoe</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>admin</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x654321</Data></EventData></Event>",
  "account": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP"
  }
}
```

### EX-SEC-4768 — Kerberos TGT requested (Security EID 4768)

<!-- covers: SEC-A Security EID 4768 kerberos_tgt_requested; Status 0x0→success (INFERRED code table) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "kerberos_tgt_requested",
    "action": "request",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:21:00.000000Z",
    "original": "2026-10-09T13:21:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sec-4768",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4768,
    "record": {
      "type": "event_record",
      "record_id": 2022
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4768</EventID><TimeCreated SystemTime='2026-10-09T13:21:00.0000000Z'/><EventRecordID>2022</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>jdoe</Data><Data Name='TargetDomainName'>CORP.LOCAL</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='ServiceName'>krbtgt</Data><Data Name='ServiceSid'>-</Data><Data Name='TicketOptions'>0x40810010</Data><Data Name='Status'>0x0</Data><Data Name='TicketEncryptionType'>0x12</Data><Data Name='PreAuthType'>15</Data><Data Name='IpAddress'>10.10.5.23</Data><Data Name='IpPort'>51521</Data><Data Name='CertIssuerName'>-</Data><Data Name='CertSerialNumber'>-</Data><Data Name='CertThumbprint'>-</Data><Data Name='ResponseTicket'>-</Data></EventData></Event>",
  "authentication": {
    "account_sid": "S-1-5-21-1000-2000-3000-1001",
    "account_name": "jdoe",
    "account_domain": "CORP.LOCAL",
    "target_name": "krbtgt",
    "target_sid": {
      "$state": "null",
      "$raw": "-"
    },
    "status": "0x0",
    "source_ip": "10.10.5.23"
  },
  "unmapped": [
    {
      "name": "TicketOptions",
      "value": "0x40810010"
    },
    {
      "name": "TicketEncryptionType",
      "value": "0x12"
    },
    {
      "name": "PreAuthType",
      "value": "15"
    },
    {
      "name": "IpPort",
      "value": "51521"
    },
    {
      "name": "CertIssuerName",
      "value": "-"
    },
    {
      "name": "CertSerialNumber",
      "value": "-"
    },
    {
      "name": "CertThumbprint",
      "value": "-"
    },
    {
      "name": "ResponseTicket",
      "value": "-"
    }
  ]
}
```

### EX-SEC-4769 — Kerberos service ticket requested (Security EID 4769)

<!-- covers: SEC-A Security EID 4769 kerberos_service_ticket_requested; TicketEncryptionType 0x17=RC4 (Kerberoast signal) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "kerberos_service_ticket_requested",
    "action": "request",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:22:00.000000Z",
    "original": "2026-10-09T13:22:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sec-4769",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4769,
    "record": {
      "type": "event_record",
      "record_id": 2023
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4769</EventID><TimeCreated SystemTime='2026-10-09T13:22:00.0000000Z'/><EventRecordID>2023</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>svc_sql</Data><Data Name='TargetDomainName'>CORP.LOCAL</Data><Data Name='ServiceName'>MSSQLSvc/sql01.corp.local:1433</Data><Data Name='ServiceSid'>S-1-5-21-1000-2000-3000-1051</Data><Data Name='TicketOptions'>0x40810000</Data><Data Name='TicketEncryptionType'>0x17</Data><Data Name='IpAddress'>10.10.5.23</Data><Data Name='IpPort'>51522</Data><Data Name='Status'>0x0</Data><Data Name='LogonGuid'>{dd33ee44-ff55-6677-8899-001122334455}</Data><Data Name='TransmittedServices'>-</Data></EventData></Event>",
  "authentication": {
    "account_name": "svc_sql",
    "account_domain": "CORP.LOCAL",
    "target_name": "MSSQLSvc/sql01.corp.local:1433",
    "target_sid": "S-1-5-21-1000-2000-3000-1051",
    "status": "0x0",
    "logon_guid": "{dd33ee44-ff55-6677-8899-001122334455}",
    "source_ip": "10.10.5.23"
  },
  "unmapped": [
    {
      "name": "TargetSid/SubjectUserSid",
      "value": {
        "$state": "null",
        "$note": "account_sid omitted (absent in source; absent = omit key per schema)"
      }
    },
    {
      "name": "TicketOptions",
      "value": "0x40810000"
    },
    {
      "name": "TicketEncryptionType",
      "value": "0x17"
    },
    {
      "name": "IpPort",
      "value": "51522"
    },
    {
      "name": "TransmittedServices",
      "value": "-"
    }
  ]
}
```

### EX-SEC-4771 — Kerberos pre-auth failed (Security EID 4771)

<!-- covers: SEC-A Security EID 4771 kerberos_preauth_failed; no TargetDomainName (absence source-true) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "kerberos_preauth_failed",
    "action": "request",
    "outcome": "failure",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:23:00.000000Z",
    "original": "2026-10-09T13:23:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sec-4771",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4771,
    "record": {
      "type": "event_record",
      "record_id": 2024
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4771</EventID><TimeCreated SystemTime='2026-10-09T13:23:00.0000000Z'/><EventRecordID>2024</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='TargetUserName'>administrator</Data><Data Name='TargetSid'>S-1-5-21-1000-2000-3000-1000</Data><Data Name='ServiceName'>krbtgt</Data><Data Name='TicketOptions'>0x40810010</Data><Data Name='Status'>0x18</Data><Data Name='PreAuthType'>15</Data><Data Name='IpAddress'>10.10.5.99</Data><Data Name='IpPort'>44445</Data><Data Name='CertIssuerName'>-</Data><Data Name='CertSerialNumber'>-</Data><Data Name='CertThumbprint'>-</Data></EventData></Event>",
  "authentication": {
    "account_sid": "S-1-5-21-1000-2000-3000-1000",
    "account_name": "administrator",
    "target_name": "krbtgt",
    "status": "0x18",
    "source_ip": "10.10.5.99"
  },
  "unmapped": [
    {
      "name": "TicketOptions",
      "value": "0x40810010"
    },
    {
      "name": "PreAuthType",
      "value": "15"
    },
    {
      "name": "IpPort",
      "value": "44445"
    },
    {
      "name": "CertIssuerName",
      "value": "-"
    },
    {
      "name": "CertSerialNumber",
      "value": "-"
    },
    {
      "name": "CertThumbprint",
      "value": "-"
    }
  ]
}
```

### EX-SEC-4776 — Credential validation (Security EID 4776)

<!-- covers: SEC-A Security EID 4776 credential_validation; Status 0x0=success VERIFIED; NTLM validation signal -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "credential_validation",
    "action": "validate",
    "outcome": "failure",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:24:00.000000Z",
    "original": "2026-10-09T13:24:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sec-4776",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4776,
    "record": {
      "type": "event_record",
      "record_id": 2025
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4776</EventID><TimeCreated SystemTime='2026-10-09T13:24:00.0000000Z'/><EventRecordID>2025</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='PackageName'>MSV1_0</Data><Data Name='TargetUserName'>jdoe</Data><Data Name='Workstation'>EVILPC</Data><Data Name='Status'>0xc000006a</Data></EventData></Event>",
  "authentication": {
    "auth_package": "MSV1_0",
    "account_name": "jdoe",
    "workstation": "EVILPC",
    "status": "0xc000006a"
  }
}
```

### EX-SEC-5140 — Network share accessed (Security EID 5140)

<!-- covers: SEC-A Security EID 5140 network_share_access; ShareName/AccessMask unmapped; no dst_port -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "network",
    "type": "network_share_access",
    "action": "access",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:25:00.000000Z",
    "original": "2026-10-09T13:25:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-5140",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 5140,
    "record": {
      "type": "event_record",
      "record_id": 2026
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>5140</EventID><TimeCreated SystemTime='2026-10-09T13:25:00.0000000Z'/><EventRecordID>2026</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='ObjectType'>File</Data><Data Name='IpAddress'>10.10.5.50</Data><Data Name='IpPort'>0x1412</Data><Data Name='ShareName'>\\\\*\\C$</Data><Data Name='ShareLocalPath'>C:\\</Data><Data Name='AccessMask'>0x1</Data><Data Name='AccessList'>%%4416</Data></EventData></Event>",
  "network": {
    "src_ip": "10.10.5.50",
    "src_port": {
      "$state": "inferred",
      "$note": "hex 0x1412→int",
      "$raw": "0x1412"
    }
  },
  "unmapped": [
    {
      "name": "ObjectType",
      "value": "File"
    },
    {
      "name": "ShareName",
      "value": "\\\\*\\C$"
    },
    {
      "name": "ShareLocalPath",
      "value": "C:\\"
    },
    {
      "name": "AccessMask",
      "value": "0x1"
    },
    {
      "name": "AccessList",
      "value": "%%4416"
    }
  ]
}
```

### EX-SEC-5145 — Network share access check (Security EID 5145)

<!-- covers: SEC-A Security EID 5145 network_share_access_check; RelativeTargetName unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "network",
    "type": "network_share_access_check",
    "action": "check",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:26:00.000000Z",
    "original": "2026-10-09T13:26:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001",
    "name": "jdoe",
    "domain": "CORP",
    "logon_id": "0x123456"
  },
  "source": {
    "file_id": "evt-sec-5145",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 5145,
    "record": {
      "type": "event_record",
      "record_id": 2027
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>5145</EventID><TimeCreated SystemTime='2026-10-09T13:26:00.0000000Z'/><EventRecordID>2027</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1000-2000-3000-1001</Data><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x123456</Data><Data Name='ObjectType'>File</Data><Data Name='IpAddress'>10.10.5.50</Data><Data Name='IpPort'>0x1413</Data><Data Name='ShareName'>\\\\*\\C$</Data><Data Name='ShareLocalPath'>C:\\</Data><Data Name='RelativeTargetName'>Users\\admin\\secret.txt</Data><Data Name='AccessMask'>0x1</Data><Data Name='AccessList'>%%4416</Data><Data Name='AccessReason'>Granted ReadData</Data></EventData></Event>",
  "network": {
    "src_ip": "10.10.5.50",
    "src_port": {
      "$state": "inferred",
      "$note": "hex 0x1413→int",
      "$raw": "0x1413"
    }
  },
  "unmapped": [
    {
      "name": "ObjectType",
      "value": "File"
    },
    {
      "name": "ShareName",
      "value": "\\\\*\\C$"
    },
    {
      "name": "ShareLocalPath",
      "value": "C:\\"
    },
    {
      "name": "RelativeTargetName",
      "value": "Users\\admin\\secret.txt"
    },
    {
      "name": "AccessMask",
      "value": "0x1"
    },
    {
      "name": "AccessList",
      "value": "%%4416"
    },
    {
      "name": "AccessReason",
      "value": "Granted ReadData"
    }
  ]
}
```

### EX-SEC-5156 — WFP connection permitted (Security EID 5156)

<!-- covers: SEC-A Security EID 5156 wfp_connection_permitted; Direction %%14592→unknown state (UNVERIFIED expansion) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "network",
    "type": "wfp_connection_permitted",
    "action": "permit",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:27:00.000000Z",
    "original": "2026-10-09T13:27:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sec-5156",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 5156,
    "record": {
      "type": "event_record",
      "record_id": 2028
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>5156</EventID><TimeCreated SystemTime='2026-10-09T13:27:00.0000000Z'/><EventRecordID>2028</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='ProcessID'>0x1234</Data><Data Name='Application'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='Direction'>%%14592</Data><Data Name='SourceAddress'>10.10.5.23</Data><Data Name='SourcePort'>51530</Data><Data Name='DestAddress'>93.184.216.34</Data><Data Name='DestPort'>443</Data><Data Name='Protocol'>6</Data><Data Name='FilterRTID'>123456</Data><Data Name='LayerName'>%%13312</Data><Data Name='LayerRTID'>44</Data><Data Name='RemoteUserID'>-</Data><Data Name='RemoteMachineID'>-</Data></EventData></Event>",
  "network": {
    "protocol": "6",
    "direction": {
      "$state": "unknown",
      "$note": "%%14592 expansion UNVERIFIED; message-table constant not resolvable in EVTX",
      "$raw": "%%14592"
    },
    "src_ip": "10.10.5.23",
    "src_port": 51530,
    "dst_ip": "93.184.216.34",
    "dst_port": 443,
    "process": {
      "pid": {
        "$state": "inferred",
        "$note": "hex 0x1234→int",
        "$raw": "0x1234"
      },
      "exe": "C:\\Windows\\System32\\cmd.exe"
    }
  },
  "unmapped": [
    {
      "name": "FilterRTID",
      "value": "123456"
    },
    {
      "name": "LayerName",
      "value": "%%13312"
    },
    {
      "name": "LayerRTID",
      "value": "44"
    },
    {
      "name": "RemoteUserID",
      "value": "-"
    },
    {
      "name": "RemoteMachineID",
      "value": "-"
    }
  ]
}
```

### EX-SEC-5158 — WFP bind permitted (Security EID 5158)

<!-- covers: SEC-A Security EID 5158 wfp_bind_permitted; ProcessId casing vs 5156 ProcessID; local bind only -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "network",
    "type": "wfp_bind_permitted",
    "action": "permit",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:28:00.000000Z",
    "original": "2026-10-09T13:28:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sec-5158",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 5158,
    "record": {
      "type": "event_record",
      "record_id": 2029
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>5158</EventID><TimeCreated SystemTime='2026-10-09T13:28:00.0000000Z'/><EventRecordID>2029</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='ProcessId'>0x1234</Data><Data Name='Application'>C:\\Tools\\nc.exe</Data><Data Name='SourceAddress'>0.0.0.0</Data><Data Name='SourcePort'>4444</Data><Data Name='Protocol'>6</Data><Data Name='FilterRTID'>654321</Data><Data Name='LayerName'>%%13312</Data><Data Name='LayerRTID'>44</Data></EventData></Event>",
  "network": {
    "protocol": "6",
    "src_ip": "0.0.0.0",
    "src_port": 4444,
    "process": {
      "pid": {
        "$state": "inferred",
        "$note": "hex 0x1234→int (casing ProcessId)",
        "$raw": "0x1234"
      },
      "exe": "C:\\Tools\\nc.exe"
    }
  },
  "unmapped": [
    {
      "name": "FilterRTID",
      "value": "654321"
    },
    {
      "name": "LayerName",
      "value": "%%13312"
    },
    {
      "name": "LayerRTID",
      "value": "44"
    }
  ]
}
```

### EX-SEC-4946 — Firewall rule added (Security EID 4946)

<!-- covers: SEC-A Security EID 4946 firewall_rule_added; derived_by sentinel; RuleId→check, RuleName→source INFERRED -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "firewall_rule_added",
    "action": "add",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:29:00.000000Z",
    "original": "2026-10-09T13:29:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sec-4946",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4946,
    "record": {
      "type": "event_record",
      "record_id": 2030
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4946</EventID><TimeCreated SystemTime='2026-10-09T13:29:00.0000000Z'/><EventRecordID>2030</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='ProfileChanged'>Domain,Private,Public</Data><Data Name='RuleId'>{1a2b3c4d-9999-8888-7777-666655554444}</Data><Data Name='RuleName'>Allow nc</Data></EventData></Event>",
  "config_check": {
    "check": "{1a2b3c4d-9999-8888-7777-666655554444}",
    "status": "pass",
    "source": "Allow nc",
    "observed": "Domain,Private,Public"
  }
}
```

### EX-SEC-4947 — Firewall rule modified (Security EID 4947)

<!-- covers: SEC-A Security EID 4947 firewall_rule_modified; no expected/diff -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "firewall_rule_modified",
    "action": "modify",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:30:00.000000Z",
    "original": "2026-10-09T13:30:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sec-4947",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4947,
    "record": {
      "type": "event_record",
      "record_id": 2031
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4947</EventID><TimeCreated SystemTime='2026-10-09T13:30:00.0000000Z'/><EventRecordID>2031</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='ProfileChanged'>Public</Data><Data Name='RuleId'>{1a2b3c4d-9999-8888-7777-666655554444}</Data><Data Name='RuleName'>Allow nc updated</Data></EventData></Event>",
  "config_check": {
    "check": "{1a2b3c4d-9999-8888-7777-666655554444}",
    "status": "pass",
    "source": "Allow nc updated",
    "observed": "Public"
  }
}
```

### EX-SEC-4948 — Firewall rule deleted (Security EID 4948)

<!-- covers: SEC-A Security EID 4948 firewall_rule_deleted; RuleId stable join key across 4946/4947/4948 -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "firewall_rule_deleted",
    "action": "delete",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:31:00.000000Z",
    "original": "2026-10-09T13:31:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "evt-sec-4948",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4948,
    "record": {
      "type": "event_record",
      "record_id": 2032
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4948</EventID><TimeCreated SystemTime='2026-10-09T13:31:00.0000000Z'/><EventRecordID>2032</EventRecordID><Channel>Security</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='ProfileChanged'>Domain,Private,Public</Data><Data Name='RuleId'>{1a2b3c4d-9999-8888-7777-666655554444}</Data><Data Name='RuleName'>Allow nc</Data></EventData></Event>",
  "config_check": {
    "check": "{1a2b3c4d-9999-8888-7777-666655554444}",
    "status": "pass",
    "source": "Allow nc",
    "observed": "Domain,Private,Public"
  }
}
```

## Other Windows channels (System, PowerShell, WMI, Defender, TaskScheduler, LSM, RCM, AppLocker) (37)

### EX-WIN-7034 — Service crashed (System EID 7034)

<!-- covers: SEC-B System 7034 service_crash; param2=occurrence count (NOT exit code); Binary→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "service",
    "type": "service_crash",
    "action": "terminate",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-09-30T13:25:40.993119Z",
    "original": "2026-09-30T13:25:40.9931197Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {},
  "source": {
    "file_id": "loc-sys-7034",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "System",
    "provider": "Service Control Manager",
    "event_id": 7034,
    "record": {
      "type": "event_record",
      "record_id": 71278
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager'/><EventID Qualifiers='49152'>7034</EventID><TimeCreated SystemTime='2026-09-30T13:25:40.9931197Z'/><EventRecordID>71278</EventRecordID><Channel>System</Channel><Computer>Dhruvs_Victus</Computer><Security/></System><EventData><Data Name='param1'>Claude</Data><Data Name='param2'>1</Data><Binary>43006F0077006F0072006B0056004D0053006500720076006900630065000000</Binary></EventData></Event>",
  "service": {
    "name": "Claude"
  },
  "unmapped": [
    {
      "name": "param2",
      "value": {
        "$state": "null",
        "$note": "occurrence count per B-SYS-ARCHIVE"
      }
    },
    {
      "name": "Binary",
      "value": {
        "$state": "null",
        "$note": "UTF-16LE hex blob; no canonical home"
      }
    }
  ]
}
```

### EX-WIN-7036 — Service state change (System EID 7036)

<!-- covers: SEC-B System 7036 service_state_change; unnamed <Data>[0]=name,[1]=state per B-LOC-HARVEST -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "service",
    "type": "service_state_change",
    "action": "state_change",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T03:14:29.684742Z",
    "original": "2026-10-09T03:14:29.6847423Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {},
  "source": {
    "file_id": "loc-sys-7036",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "System",
    "provider": "VfpExt",
    "event_id": 7036,
    "record": {
      "type": "event_record",
      "record_id": 72886
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='VfpExt'/><EventID Qualifiers='16384'>7036</EventID><TimeCreated SystemTime='2026-10-09T03:14:29.6847423Z'/><EventRecordID>72886</EventRecordID><Channel>System</Channel><Computer>Dhruvs_Victus</Computer><Security/></System><EventData><Data></Data><Data>Filter restart complete</Data><Binary>0000000002002C00000000007C1B0040000000000000000000000000000000000000000000000000</Binary></EventData></Event>",
  "service": {
    "name": {
      "$state": "inferred",
      "$note": "unnamed <Data>[0] positional bind",
      "$raw": ""
    },
    "state": "Filter restart complete"
  },
  "unmapped": [
    {
      "name": "Binary",
      "value": "0000000002002C00000000007C1B0040000000000000000000000000000000000000000000000000"
    }
  ]
}
```

### EX-WIN-7040 — Service start type changed (System EID 7040)

<!-- covers: SEC-B System 7040 service_start_type_change; param2=old, param3=new→start_type; param4 caller unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "service",
    "type": "service_start_type_change",
    "action": "change",
    "outcome": "success",
    "severity": "low",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T03:24:33.009777Z",
    "original": "2026-10-09T03:24:33.0097777Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "sid": "S-1-5-18"
  },
  "source": {
    "file_id": "loc-sys-7040",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "System",
    "provider": "Service Control Manager",
    "event_id": 7040,
    "record": {
      "type": "event_record",
      "record_id": 72925
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager'/><EventID Qualifiers='16384'>7040</EventID><TimeCreated SystemTime='2026-10-09T03:24:33.0097777Z'/><EventRecordID>72925</EventRecordID><Channel>System</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='param1'>Background Intelligent Transfer Service</Data><Data Name='param2'>auto start</Data><Data Name='param3'>demand start</Data><Data Name='param4'>BITS</Data></EventData></Event>",
  "service": {
    "name": "Background Intelligent Transfer Service",
    "start_type": "demand start"
  },
  "unmapped": [
    {
      "name": "param2 old start_type",
      "value": "auto start"
    },
    {
      "name": "param4",
      "value": "BITS"
    }
  ]
}
```

### EX-WIN-7043 — Service terminated unexpectedly (System EID 7043)

<!-- covers: SEC-B System 7043 service_config_change; Binary UTF-16LE→image_path INFERRED -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "service",
    "type": "service_config_change",
    "action": "change",
    "outcome": "success",
    "severity": "low",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-05-28T02:02:10.502078Z",
    "original": "2026-05-28T02:02:10.5020782Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {},
  "source": {
    "file_id": "loc-sys-7043",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "System",
    "provider": "Service Control Manager",
    "event_id": 7043,
    "record": {
      "type": "event_record",
      "record_id": 44369
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager'/><EventID Qualifiers='49152'>7043</EventID><TimeCreated SystemTime='2026-05-28T02:02:10.5020782Z'/><EventRecordID>44369</EventRecordID><Channel>System</Channel><Computer>Dhruvs_Victus</Computer><Security/></System><EventData><Data Name='param1'>Windows Security Service</Data><Binary>530065006300750072006900740079004800650061006C007400680053006500720076006900630065000000</Binary></EventData></Event>",
  "service": {
    "name": "Windows Security Service",
    "image_path": {
      "$state": "inferred",
      "$note": "Binary UTF-16LE hex decoded to SecurityHealthService",
      "$raw": "530065006300750072006900740079004800650061006C007400680053006500720076006900630065000000"
    }
  }
}
```

### EX-WIN-7045 — Service installed (System EID 7045)

<!-- covers: SEC-B System 7045 service_install; VERIFIED-LOCAL element names (no MS page) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "service",
    "type": "service_install",
    "action": "install",
    "outcome": "success",
    "severity": "medium",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T03:16:33.307102Z",
    "original": "2026-10-09T03:16:33.3071024Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "sid": "S-1-5-18"
  },
  "source": {
    "file_id": "loc-sys-7045",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "System",
    "provider": "Service Control Manager",
    "event_id": 7045,
    "record": {
      "type": "event_record",
      "record_id": 72904
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager'/><EventID Qualifiers='16384'>7045</EventID><TimeCreated SystemTime='2026-10-09T03:16:33.3071024Z'/><EventRecordID>72904</EventRecordID><Channel>System</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='ServiceName'>ChatGPT</Data><Data Name='ImagePath'>\"C:\\Program Files\\WindowsApps\\OpenAI.Codex_26.1002.7124.0_x64__2p2nqsd0c76g0\\app\\resources\\codex-windows-sandbox-service.exe\"</Data><Data Name='ServiceType'>user mode service</Data><Data Name='StartType'>auto start</Data><Data Name='AccountName'>LocalSystem</Data></EventData></Event>",
  "service": {
    "name": "ChatGPT",
    "image_path": "\"C:\\Program Files\\WindowsApps\\OpenAI.Codex_26.1002.7124.0_x64__2p2nqsd0c76g0\\app\\resources\\codex-windows-sandbox-service.exe\"",
    "service_type": "user mode service",
    "start_type": "auto start",
    "account_name": "LocalSystem"
  }
}
```

### EX-WIN-104 — Event log cleared (System EID 104)

<!-- covers: SEC-B System 104 log_clear; UNVERIFIED element names (B-PRIOR); param3 VERIFIED slot -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "log_clear",
    "action": "clear",
    "outcome": "success",
    "severity": "medium",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:00:00.000000Z",
    "original": "2026-10-09T14:00:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED candidate SubjectUserName",
      "$raw": "CORP\\jdoe"
    },
    "domain": {
      "$state": "inferred",
      "$note": "UNVERIFIED candidate",
      "$raw": "CORP"
    }
  },
  "source": {
    "file_id": "demo-sys-104",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "System",
    "provider": "Microsoft-Windows-Eventlog",
    "event_id": 104,
    "record": {
      "type": "event_record",
      "record_id": 73000
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog'/><EventID>104</EventID><TimeCreated SystemTime='2026-10-09T14:00:00.0000000Z'/><EventRecordID>73000</EventRecordID><Channel>System</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data>Security</Data><Data>S-1-5-21-1000-2000-3000-1001</Data><Data>CORP\\jdoe</Data><Data>CORP</Data><Data>0x123456</Data></EventData></Event>",
  "config_check": {
    "check": "log_clear",
    "observed": "Security"
  },
  "unmapped": [
    {
      "name": "SubjectUserSid",
      "value": "S-1-5-21-1000-2000-3000-1001"
    },
    {
      "name": "SubjectLogonId",
      "value": "0x123456"
    }
  ]
}
```

### EX-WIN-PS400 — PowerShell engine started (Windows PowerShell EID 400)

<!-- covers: SEC-B PS classic 400 engine_state_change; detail-blob KEY=Value parsed; SequenceNumber unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "powershell",
    "type": "engine_state_change",
    "action": "state_change",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T04:34:39.771168Z",
    "original": "2026-10-09T04:34:39.7711688Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {},
  "source": {
    "file_id": "loc-ps-400",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Windows PowerShell",
    "provider": "PowerShell",
    "event_id": 400,
    "record": {
      "type": "event_record",
      "record_id": 49769
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='PowerShell'/><EventID Qualifiers='0'>400</EventID><TimeCreated SystemTime='2026-10-09T04:34:39.7711688Z'/><EventRecordID>49769</EventRecordID><Channel>Windows PowerShell</Channel><Computer>Dhruvs_Victus</Computer><Security/></System><EventData><Data>Available</Data><Data>None</Data><Data>\tNewEngineState=Available\r\n\tPreviousEngineState=None\r\n\r\n\tSequenceNumber=13\r\n\r\n\tHostName=ConsoleHost\r\n\tHostVersion=5.1.26100.9444\r\n\tHostId=8b5a1d01-7e7a-4bde-ac5e-f65eefe8c287\r\n\tHostApplication=C:\\windows\\System32\\WindowsPowerShell\\v1.0\\powershell.EXE -NoLogo -NoProfile -NonInteractive -Command &amp; \"C:\\Users\\dhruv\\OneDrive\\Desktop\\College\\Light HIDS\\_stage2_work\\harvest_local_events.ps1\"\r\n\tEngineVersion=5.1.26100.9444\r\n\tRunspaceId=3d04b614-6f40-45ef-a245-3edc3a56bf81\r\n\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine=</Data></EventData></Event>",
  "powershell": {
    "engine_state": "Available",
    "previous_engine_state": "None",
    "host_name": "ConsoleHost",
    "host_version": "5.1.26100.9444",
    "host_id": "8b5a1d01-7e7a-4bde-ac5e-f65eefe8c287",
    "host_application": "C:\\windows\\System32\\WindowsPowerShell\\v1.0\\powershell.EXE -NoLogo -NoProfile -NonInteractive -Command & \"C:\\Users\\dhruv\\OneDrive\\Desktop\\College\\Light HIDS\\_stage2_work\\harvest_local_events.ps1\"",
    "engine_version": "5.1.26100.9444",
    "runspace_id": "3d04b614-6f40-45ef-a245-3edc3a56bf81"
  },
  "unmapped": [
    {
      "name": "SequenceNumber",
      "value": "13"
    }
  ]
}
```

### EX-WIN-PS403 — PowerShell engine stopped (Windows PowerShell EID 403)

<!-- covers: SEC-B PS classic 403 engine_state_change -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "powershell",
    "type": "engine_state_change",
    "action": "state_change",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T04:34:15.538511Z",
    "original": "2026-10-09T04:34:15.5385112Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {},
  "source": {
    "file_id": "loc-ps-403",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Windows PowerShell",
    "provider": "PowerShell",
    "event_id": 403,
    "record": {
      "type": "event_record",
      "record_id": 49762
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='PowerShell'/><EventID Qualifiers='0'>403</EventID><TimeCreated SystemTime='2026-10-09T04:34:15.5385112Z'/><EventRecordID>49762</EventRecordID><Channel>Windows PowerShell</Channel><Computer>Dhruvs_Victus</Computer><Security/></System><EventData><Data>Stopped</Data><Data>Available</Data><Data>\tNewEngineState=Stopped\r\n\tPreviousEngineState=Available\r\n\r\n\tSequenceNumber=23\r\n\r\n\tHostName=ConsoleHost\r\n\tHostVersion=5.1.26100.9444\r\n\tHostId=8a5d8a78-6fbd-4b6a-8048-90754f8588b5\r\n\tHostApplication=C:\\windows\\System32\\WindowsPowerShell\\v1.0\\powershell.EXE -NoLogo -NoProfile -NonInteractive -Command python -c \"import jsonschema; print('jsonschema OK', jsonschema.__version__)\"\r\n\tEngineVersion=5.1.26100.9444\r\n\tRunspaceId=5a1a0ee0-50e7-454f-9bfa-5823332390b9\r\n\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine=</Data></EventData></Event>",
  "powershell": {
    "engine_state": "Stopped",
    "previous_engine_state": "Available",
    "host_name": "ConsoleHost",
    "host_version": "5.1.26100.9444",
    "host_id": "8a5d8a78-6fbd-4b6a-8048-90754f8588b5",
    "host_application": "C:\\windows\\System32\\WindowsPowerShell\\v1.0\\powershell.EXE -NoLogo -NoProfile -NonInteractive -Command python -c \"import jsonschema; print('jsonschema OK', jsonschema.__version__)\"",
    "engine_version": "5.1.26100.9444",
    "runspace_id": "5a1a0ee0-50e7-454f-9bfa-5823332390b9"
  },
  "unmapped": [
    {
      "name": "SequenceNumber",
      "value": "23"
    }
  ]
}
```

### EX-WIN-PS600 — Provider started (Windows PowerShell EID 600)

<!-- covers: SEC-B PS classic 600 provider_state_change; new_provider_state -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "powershell",
    "type": "provider_state_change",
    "action": "state_change",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T04:34:39.767848Z",
    "original": "2026-10-09T04:34:39.7678482Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {},
  "source": {
    "file_id": "loc-ps-600",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Windows PowerShell",
    "provider": "PowerShell",
    "event_id": 600,
    "record": {
      "type": "event_record",
      "record_id": 49768
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='PowerShell'/><EventID Qualifiers='0'>600</EventID><TimeCreated SystemTime='2026-10-09T04:34:39.7678482Z'/><EventRecordID>49768</EventRecordID><Channel>Windows PowerShell</Channel><Computer>Dhruvs_Victus</Computer><Security/></System><EventData><Data>Variable</Data><Data>Started</Data><Data>\tProviderName=Variable\r\n\tNewProviderState=Started\r\n\r\n\tSequenceNumber=11\r\n\r\n\tHostName=ConsoleHost\r\n\tHostVersion=5.1.26100.9444\r\n\tHostId=8b5a1d01-7e7a-4bde-ac5e-f65eefe8c287\r\n\tHostApplication=C:\\windows\\System32\\WindowsPowerShell\\v1.0\\powershell.EXE -NoLogo -NoProfile -NonInteractive -Command &amp; \"C:\\Users\\dhruv\\OneDrive\\Desktop\\College\\Light HIDS\\_stage2_work\\harvest_local_events.ps1\"\r\n\tEngineVersion=\r\n\tRunspaceId=\r\n\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine=</Data></EventData></Event>",
  "powershell": {
    "new_provider_state": "Started",
    "previous_engine_state": {
      "$state": "null",
      "$note": "unnamed <Data>[1]"
    },
    "provider_name": "Variable"
  },
  "unmapped": [
    {
      "name": "SequenceNumber",
      "value": "11"
    }
  ]
}
```

### EX-WIN-PS800 — PowerShell pipeline executed (classic EID 800)

<!-- covers: SEC-B PS classic 800; element names UNVERIFIED (B-PRIOR, not found locally) -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "powershell",
    "type": "pipeline_execution",
    "action": "start",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:01:00.000000Z",
    "original": "2026-10-09T14:01:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "demo-ps-800",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Windows PowerShell",
    "provider": "PowerShell",
    "event_id": 800,
    "record": {
      "type": "event_record",
      "record_id": 49900
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='PowerShell'/><EventID>800</EventID><TimeCreated SystemTime='2026-10-09T14:01:00.0000000Z'/><EventRecordID>49900</EventRecordID><Channel>Windows PowerShell</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data>Command started: Get-Process</Data></EventData></Event>",
  "powershell": {
    "payload": {
      "$state": "inferred",
      "$note": "UNVERIFIED element name; message-template param binding",
      "$raw": "Command started: Get-Process"
    }
  }
}
```

### EX-WIN-PS4103 — Module logging (PowerShell/Operational EID 4103)

<!-- covers: SEC-B PS-Op 4103 module_logging; ContextInfo+Payload VERIFIED; UserData→unmapped if populated -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "powershell",
    "type": "module_logging",
    "action": "log",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-09-30T13:31:32.589707Z",
    "original": "2026-09-30T13:31:32.5897071Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "sid": "S-1-5-21-392970859-1592143220-1055403080-1001"
  },
  "source": {
    "file_id": "loc-psop-4103",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-PowerShell/Operational",
    "provider": "Microsoft-Windows-PowerShell",
    "event_id": 4103,
    "record": {
      "type": "event_record",
      "record_id": 67645
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-PowerShell'/><EventID>4103</EventID><TimeCreated SystemTime='2026-09-30T13:31:32.5897071Z'/><EventRecordID>67645</EventRecordID><Channel>Microsoft-Windows-PowerShell/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-21-392970859-1592143220-1055403080-1001'/></System><EventData><Data Name='ContextInfo'>        Severity = Informational\r\n        Host Name = ConsoleHost\r\n        Host Version = 5.1.26100.9444\r\n        Host ID = cd1c8ee3-71a5-42ab-98f7-1f56710b1f0f\r\n        Host Application = powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $ErrorActionPreference='SilentlyContinue'\n$code=@'\nusing System; using System.Runtime.InteropServices;\npublic static class NativeMethods {\n  [DllImport(user32.dll,SetLastError=true,CharSet=CharSet.Auto)]\n  public static extern IntPtr SendMessageTimeout(IntPtr hWnd,uint Msg,UIntPtr wParam,IntPtr lParam,uint fuFlags,uint uTimeout,out UIntPtr lpdwResult);\n}\n'@\nAdd-Type -TypeDefinition $code -ErrorAction SilentlyContinue | Out-Null\n$out=[UIntPtr]::Zero\n[void][NativeMethods]::SendMessageTimeout([IntPtr]0xffff,0x1A,[UIntPtr]::Zero,[IntPtr]::Zero,0x2,5000,[ref]$out)\nStart-Sleep -Milliseconds 200\nGet-Process ShellExperienceHost -ErrorAction SilentlyContinue | Stop-Process -Force\nStart-Sleep -Milliseconds 300\nGet-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force\r\n        Engine Version = 5.1.26100.9444\r\n        Runspace ID = e2b94bfd-ed3e-4f8a-be33-d253e7f1ee0f\r\n        Pipeline ID = 1\r\n        Command Name = Add-Type\r\n        Command Type = Cmdlet\r\n        Script Name = \r\n        Command Path = \r\n        Sequence Number = 23\r\n        User = DHRUVS_VICTUS\\dhruv\r\n        Connected User = \r\n        Shell ID = Microsoft.PowerShell\r\n</Data><Data Name='UserData'></Data><Data Name='Payload'>CommandInvocation(Add-Type): \"Add-Type\"\r\nParameterBinding(Add-Type): name=\"TypeDefinition\"; value=\"using System; using System.Runtime.InteropServices;\npublic static class NativeMethods {\n  [DllImport(user32.dll,SetLastError=true,CharSet=CharSet.Auto)]\n  public static extern IntPtr SendMessageTimeout(IntPtr hWnd,uint Msg,UIntPtr wParam,IntPtr lParam,uint fuFlags,uint uTimeout,out UIntPtr lpdwResult);\n}\"\r\nParameterBinding(Add-Type): name=\"ErrorAction\"; value=\"SilentlyContinue\"\r\nCommandInvocation(Out-Null): \"Out-Null\"\r\nNonTerminatingError(Add-Type): \"c:\\Users\\dhruv\\AppData\\Local\\Temp\\dig12vz1.0.cs(3) : The name 'user32' does not exist in the current context\n\nc:\\Users\\dhruv\\AppData\\Local\\Temp\\dig12vz1.0.cs(2) : public static class NativeMethods {\n\nc:\\Users\\dhruv\\AppData\\Local\\Temp\\dig12vz1.0.cs(3) : &gt;&gt;&gt;   [DllImport(user32.dll,SetLastError=true,CharSet=CharSet.Auto)]\n\nc:\\Users\\dhruv\\AppData\\Local\\Temp\\dig12vz1.0.cs(4) :   public static extern IntPtr SendMessageTimeout(IntPtr hWnd,uint Msg,UIntPtr wParam,IntPtr lParam,uint fuFlags,uint uTimeout,out UIntPtr lpdwResult);\n\"\r\nTerminatingError(Add-Type): \"Cannot add type. Compilation errors occurred.\"\r\n</Data></EventData></Event>",
  "powershell": {
    "context_info": {
      "$state": "inferred",
      "$note": "ContextInfo truncated to first 200 chars for example brevity; full value in raw",
      "$raw": "        Severity = Informational\r\n        Host Name = ConsoleHost\r\n        Host Version = 5.1.26100.9444\r\n        Host ID = cd1c8ee3-71a5-42ab-98f7-1f56710b1f0f\r\n        Host Application = powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $ErrorActionPreference='SilentlyContinue'\n... [truncated in example; full in raw]\n        Command Name = Add-Type\r\n        Command Type = Cmdlet"
    },
    "payload": {
      "$state": "inferred",
      "$note": "Payload CommandInvocation/ParameterBinding text; truncated for example brevity",
      "$raw": "CommandInvocation(Add-Type): \"/bin/Add-Type\""
    }
  }
}
```

### EX-WIN-PS4104 — Script block logging (PowerShell/Operational EID 4104)

<!-- covers: SEC-B PS-Op 4104 script_block_logging; Path=interactive/absent vs file; MessageNumber/Total for reassembly -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "powershell",
    "type": "script_block_logging",
    "action": "log",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-08T16:26:20.010508Z",
    "original": "2026-10-08T16:26:20.0105082Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "sid": "S-1-5-21-392970859-1592143220-1055403080-1001"
  },
  "source": {
    "file_id": "loc-psop-4104",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-PowerShell/Operational",
    "provider": "Microsoft-Windows-PowerShell",
    "event_id": 4104,
    "record": {
      "type": "event_record",
      "record_id": 72802
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-PowerShell'/><EventID>4104</EventID><TimeCreated SystemTime='2026-10-08T16:26:20.0105082Z'/><EventRecordID>72802</EventRecordID><Channel>Microsoft-Windows-PowerShell/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-21-392970859-1592143220-1055403080-1001'/></System><EventData><Data Name='MessageNumber'>1</Data><Data Name='MessageTotal'>1</Data><Data Name='ScriptBlockText'>#!/usr/bin/env pwsh\r\n\r\nSet-StrictMode -Version 'Latest'\r\n\r\n$NODE_EXE=\"$PSScriptRoot/node.exe\"\r\nif (-not (Test-Path $NODE_EXE)) {\r\n  $NODE_EXE=\"$PSScriptRoot/node\"\r\n}\r\nif (-not (Test-Path $NODE_EXE)) {\r\n  $NODE_EXE=\"node\"\r\n}\r\n\r\n$NPM_PREFIX_JS=\"$PSScriptRoot/node_modules/npm/bin/npm-prefix.js\"\r\n$NPM_CLI_JS=\"$PSScriptRoot/node_modules/npm/bin/npm-cli.js\"\r\n$NPM_PREFIX=(&amp; $NODE_EXE $NPM_PREFIX_JS)\r\n\r\nif ($LASTEXITCODE -ne 0) {\r\n  Write-Host \"Could not determine Node.js install directory\"\r\n  exit 1\r\n}\r\n\r\n$NPM_PREFIX_NPM_CLI_JS=\"$NPM_PREFIX/node_modules/npm/bin/npm-cli.js\"\r\nif (Test-Path $NPM_PREFIX_NPM_CLI_JS) {\r\n  $NPM_CLI_JS=$NPM_PREFIX_NPM_CLI_JS\r\n}\r\n\r\nif ($MyInvocation.ExpectingInput) { # takes pipeline input\r\n  $input | &amp; $NODE_EXE $NPM_CLI_JS $args\r\n} elseif (-not $MyInvocation.Line) { # used \"-File\" argument\r\n  &amp; $NODE_EXE $NPM_CLI_JS $args\r\n} else { # used \"-Command\" argument\r\n  if (($MyInvocation | Get-Member -Name 'Statement') -and $MyInvocation.Statement) {\r\n    $NPM_ORIGINAL_COMMAND = $MyInvocation.Statement\r\n  } else {\r\n    $NPM_ORIGINAL_COMMAND = (\r\n      [Management.Automation.InvocationInfo].GetProperty('ScriptPosition', [Reflection.BindingFlags] 'Instance, NonPublic')\r\n    ).GetValue($MyInvocation).Text\r\n  }\r\n\r\n  $NODE_EXE = $NODE_EXE.Replace(\"\u0060\u0060\", \"\u0060\u0060\u0060\u0060\")\r\n  $NPM_CLI_JS = $NPM_CLI_JS.Replace(\"\u0060\u0060\", \"\u0060\u0060\u0060\u0060\")\r\n\r\n  $NPM_COMMAND_ARRAY = [Management.Automation.Language.Parser]::ParseInput($NPM_ORIGINAL_COMMAND, [ref] $null, [ref] $null).\r\n    EndBlock.Statements.PipelineElements.CommandElements.Extent.Text\r\n  $NPM_ARGS = ($NPM_COMMAND_ARRAY | Select-Object -Skip 1) -join ' '\r\n\r\n  Invoke-Expression \"&amp; \u0060\"$NODE_EXE\u0060\" \u0060\"$NPM_CLI_JS\u0060\" $NPM_ARGS\"\r\n}\r\n\r\nexit $LASTEXITCODE\r\n</Data><Data Name='ScriptBlockId'>d8bf42e3-4f0c-46c9-8794-41d6bf5ba3e0</Data><Data Name='Path'>C:\\Program Files\\nodejs\\npm.ps1</Data></EventData></Event>",
  "powershell": {
    "message_number": 1,
    "message_total": 1,
    "script_block_text": {
      "$state": "inferred",
      "$note": "ScriptBlockText truncated to first 200 chars for example brevity; full value in raw",
      "$raw": "#!/usr/bin/env pwsh\r\n\r\nSet-StrictMode -Version 'Latest'\r\n\r\n$NODE_EXE=\"$PSScriptRoot/node.exe\"\nif (-not (Test-Path $NODE_EXE)) {\n  $NODE_EXE=\"$PSScriptRoot/node\"\n}\n... [truncated in example; full in raw]\n"
    },
    "script_block_id": "0a1b2c3d-4e5f-6789-abcd-ef0123456789",
    "script_path": "C:\\Program Files\\nodejs\\npm.ps1"
  }
}
```

### EX-WIN-PS4105 — Pipeline execution start (PowerShell/Operational EID 4105)

<!-- covers: SEC-B PS-Op 4105 pipeline_execution start; element names VERIFIED-by-manifest only (B-PS-MANIFEST, no local sample) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "powershell",
    "type": "pipeline_execution",
    "action": "start",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:02:00.000000Z",
    "original": "2026-10-09T14:02:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001"
  },
  "source": {
    "file_id": "demo-psop-4105",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-PowerShell/Operational",
    "provider": "Microsoft-Windows-PowerShell",
    "event_id": 4105,
    "record": {
      "type": "event_record",
      "record_id": 72803
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-PowerShell'/><EventID>4105</EventID><TimeCreated SystemTime='2026-10-09T14:02:00.0000000Z'/><EventRecordID>72803</EventRecordID><Channel>Microsoft-Windows-PowerShell/Operational</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-21-1000-2000-3000-1001'/></System><EventData><Data Name='ScriptBlockId'>0a1b2c3d-4e5f-6789-abcd-ef0123456789</Data><Data Name='RunspaceId'>e2b94bfd-ed3e-4f8a-be33-d253e7f1ee0f</Data></EventData></Event>",
  "powershell": {
    "script_block_id": "0a1b2c3d-4e5f-6789-abcd-ef0123456789",
    "runspace_id": "e2b94bfd-ed3e-4f8a-be33-d253e7f1ee0f"
  }
}
```

### EX-WIN-PS4106 — Pipeline execution stop (PowerShell/Operational EID 4106)

<!-- covers: SEC-B PS-Op 4106 pipeline_execution stop; manifest-only element names -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "powershell",
    "type": "pipeline_execution",
    "action": "stop",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:02:05.000000Z",
    "original": "2026-10-09T14:02:05.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "sid": "S-1-5-21-1000-2000-3000-1001"
  },
  "source": {
    "file_id": "demo-psop-4106",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-PowerShell/Operational",
    "provider": "Microsoft-Windows-PowerShell",
    "event_id": 4106,
    "record": {
      "type": "event_record",
      "record_id": 72804
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-PowerShell'/><EventID>4106</EventID><TimeCreated SystemTime='2026-10-09T14:02:00.0000000Z'/><EventRecordID>72804</EventRecordID><Channel>Microsoft-Windows-PowerShell/Operational</Channel><Computer>WS-DEMO01</Computer><Security UserID='S-1-5-21-1000-2000-3000-1001'/></System><EventData><Data Name='ScriptBlockId'>0a1b2c3d-4e5f-6789-abcd-ef0123456789</Data><Data Name='RunspaceId'>e2b94bfd-ed3e-4f8a-be33-d253e7f1ee0f</Data></EventData></Event>",
  "powershell": {
    "script_block_id": "0a1b2c3d-4e5f-6789-abcd-ef0123456789",
    "runspace_id": "e2b94bfd-ed3e-4f8a-be33-d253e7f1ee0f"
  }
}
```

### EX-WIN-WMI5857 — WMI operation started (WMI-Activity EID 5857)

<!-- covers: SEC-B WMI 5857 wmi_operation; ProcessID casing trap; HostProcess/ProviderPath→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "wmi",
    "type": "wmi_operation",
    "action": "connect",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T04:34:14.174730Z",
    "original": "2026-10-09T04:34:14.1747309Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {},
  "source": {
    "file_id": "loc-wmi-5857",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-WMI-Activity/Operational",
    "provider": "Microsoft-Windows-WMI-Activity",
    "event_id": 5857,
    "record": {
      "type": "event_record",
      "record_id": 289056
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-WMI-Activity'/><EventID>5857</EventID><TimeCreated SystemTime='2026-10-09T04:34:14.1747309Z'/><EventRecordID>289056</EventRecordID><Channel>Microsoft-Windows-WMI-Activity/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-20'/></System><UserData><Operation_StartedOperational xmlns='http://manifests.microsoft.com/win/2006/windows/WMI'><ProviderName>CIMWin32</ProviderName><Code>0x0</Code><HostProcess>wmiprvse.exe</HostProcess><ProcessID>13660</ProcessID><ProviderPath>%systemroot%\\system32\\wbem\\cimwin32.dll</ProviderPath></Operation_StartedOperational></UserData></Event>",
  "wmi": {
    "provider_name": "CIMWin32",
    "result_code": "0x0"
  },
  "unmapped": [
    {
      "name": "HostProcess",
      "value": "wmiprvse.exe"
    },
    {
      "name": "ProcessID",
      "value": "13660"
    },
    {
      "name": "ProviderPath",
      "value": "%systemroot%\\system32\\wbem\\cimwin32.dll"
    }
  ]
}
```

### EX-WIN-WMI5858 — WMI client failure (WMI-Activity EID 5858)

<!-- covers: SEC-B WMI 5858 wmi_client_failure; Id/Component/PossibleCause unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "wmi",
    "type": "wmi_client_failure",
    "action": "connect",
    "outcome": "failure",
    "severity": "low",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T04:34:33.450413Z",
    "original": "2026-10-09T04:34:33.4504134Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "sid": "S-1-5-18"
  },
  "source": {
    "file_id": "loc-wmi-5858",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-WMI-Activity/Operational",
    "provider": "Microsoft-Windows-WMI-Activity",
    "event_id": 5858,
    "record": {
      "type": "event_record",
      "record_id": 289057
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-WMI-Activity'/><EventID>5858</EventID><TimeCreated SystemTime='2026-10-09T04:34:33.4504134Z'/><EventRecordID>289057</EventRecordID><Channel>Microsoft-Windows-WMI-Activity/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><UserData><Operation_ClientFailure xmlns='http://manifests.microsoft.com/win/2006/windows/WMI'><Id>{00000000-0000-0000-0000-000000000000}</Id><ClientMachine>DHRUVS_VICTUS</ClientMachine><User>NT AUTHORITY\\SYSTEM</User><ClientProcessId>3660</ClientProcessId><Component>Unknown</Component><Operation>Start IWbemServices::CreateInstanceEnum - root\\wmi : HpqBIntM</Operation><ResultCode>0x80041032</ResultCode><PossibleCause>Unknown</PossibleCause></Operation_ClientFailure></UserData></Event>",
  "wmi": {
    "client_machine": "DHRUVS_VICTUS",
    "client_user": "NT AUTHORITY\\SYSTEM",
    "client_process_id": "3660",
    "operation": "Start IWbemServices::CreateInstanceEnum - root\\wmi : HpqBIntM",
    "result_code": "0x80041032"
  },
  "unmapped": [
    {
      "name": "Id",
      "value": "{00000000-0000-0000-0000-000000000000}"
    },
    {
      "name": "Component",
      "value": "Unknown"
    },
    {
      "name": "PossibleCause",
      "value": "Unknown"
    }
  ]
}
```

### EX-WIN-WMI5860 — WMI temporary ESS started (WMI-Activity EID 5860)

<!-- covers: SEC-B WMI 5860; Processid lowercase-d casing trap vs 5857 ProcessID; PossibleCause unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "wmi",
    "type": "wmi_operation",
    "action": "connect",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T03:17:56.173368Z",
    "original": "2026-10-09T03:17:56.1733684Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "name": "dhruv",
    "domain": "Dhruvs_Victus"
  },
  "source": {
    "file_id": "loc-wmi-5860",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-WMI-Activity/Operational",
    "provider": "Microsoft-Windows-WMI-Activity",
    "event_id": 5860,
    "record": {
      "type": "event_record",
      "record_id": 288722
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-WMI-Activity'/><EventID>5860</EventID><TimeCreated SystemTime='2026-10-09T03:17:56.1733684Z'/><EventRecordID>288722</EventRecordID><Channel>Microsoft-Windows-WMI-Activity/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><UserData><Operation_TemporaryEssStarted xmlns='http://manifests.microsoft.com/win/2006/windows/WMI'><NamespaceName>root\\wmi</NamespaceName><Query>select * from hpqbevnt</Query><User>Dhruvs_Victus\\dhruv</User><Processid>20272</Processid><ClientMachine>DHRUVS_VICTUS</ClientMachine><PossibleCause>Temporary</PossibleCause></Operation_TemporaryEssStarted></UserData></Event>",
  "wmi": {
    "namespace": "root\\wmi",
    "query": "select * from hpqbevnt",
    "client_user": "Dhruvs_Victus\\dhruv",
    "client_machine": "DHRUVS_VICTUS"
  },
  "unmapped": [
    {
      "name": "Processid",
      "value": "20272"
    },
    {
      "name": "PossibleCause",
      "value": "Temporary"
    }
  ]
}
```

### EX-WIN-DEF1116 — Malware detected (Defender EID 1116)

<!-- covers: SEC-B Defender 1116 malware_detected; 42-element set VERIFIED-LOCAL; severity=high from Severity ID 4 -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "third_party_alert",
    "type": "malware_detected",
    "action": "detect",
    "outcome": "success",
    "severity": "high",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-08T14:55:43.556373Z",
    "original": "2026-10-08T14:55:43.5563739Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "Detection User field",
      "$raw": "Dhruvs_Victus\\dhruv"
    }
  },
  "source": {
    "file_id": "loc-def-1116",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Windows Defender/Operational",
    "provider": "Microsoft-Windows-Windows Defender",
    "event_id": 1116,
    "record": {
      "type": "event_record",
      "record_id": 5432
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Windows Defender'/><EventID>1116</EventID><TimeCreated SystemTime='2026-10-08T14:55:43.5563739Z'/><EventRecordID>5432</EventRecordID><Channel>Microsoft-Windows-Windows Defender/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='Product Name'>Microsoft Defender Antivirus</Data><Data Name='Product Version'>4.18.26080.4</Data><Data Name='Detection ID'>{CDF36DC1-A236-4131-A603-00FFE0588A74}</Data><Data Name='Detection Time'>2026-10-08T14:55:43.466Z</Data><Data Name='Unused'></Data><Data Name='Unused2'></Data><Data Name='Threat ID'>2147725066</Data><Data Name='Threat Name'>HackTool:PowerShell/Mimikatz</Data><Data Name='Severity ID'>4</Data><Data Name='Severity Name'>High</Data><Data Name='Category ID'>34</Data><Data Name='Category Name'>Tool</Data><Data Name='FWLink'>https://go.microsoft.com/fwlink/?linkid=37020&amp;name=HackTool:PowerShell/Mimikatz&amp;threatid=2147725066&amp;enterprise=0</Data><Data Name='Status Code'>1</Data><Data Name='Status Description'></Data><Data Name='State'>1</Data><Data Name='Source ID'>3</Data><Data Name='Source Name'>Real-Time Protection</Data><Data Name='Process Name'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data><Data Name='Detection User'>Dhruvs_Victus\\dhruv</Data><Data Name='Unused3'></Data><Data Name='Path'>file:_C:\\Users\\dhruv\\AppData\\Local\\Temp\\opencode\\research\\velociraptor-docs\\content\\knowledge_base\\tips\\decimaldecode.md</Data><Data Name='Origin ID'>1</Data><Data Name='Origin Name'>Local machine</Data><Data Name='Execution ID'>1</Data><Data Name='Execution Name'>Suspended</Data><Data Name='Type ID'>0</Data><Data Name='Type Name'>Concrete</Data><Data Name='Pre Execution Status'>0</Data><Data Name='Action ID'>9</Data><Data Name='Action Name'>Not Applicable</Data><Data Name='Unused4'></Data><Data Name='Error Code'>0x00000000</Data><Data Name='Error Description'>The operation completed successfully. </Data><Data Name='Unused5'></Data><Data Name='Post Clean Status'>0</Data><Data Name='Additional Actions ID'>0</Data><Data Name='Additional Actions String'>No additional actions required</Data><Data Name='Remediation User'></Data><Data Name='Unused6'></Data><Data Name='Security intelligence Version'>AV: 1.459.601.0, AS: 1.459.601.0, NIS: 1.459.601.0</Data><Data Name='Engine Version'>AM: 1.1.26080.3, NIS: 1.1.26080.3</Data></EventData></Event>",
  "third_party_alert": {
    "vendor": "Microsoft",
    "product": "Microsoft Defender Antivirus",
    "rule_name": "HackTool:PowerShell/Mimikatz",
    "category": "Tool",
    "severity_raw": "4 (High)",
    "description": {
      "$state": "inferred",
      "$note": "Status Description empty; description from Threat Name/category",
      "$raw": "HackTool:PowerShell/Mimikatz"
    }
  },
  "process": {
    "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "owner_name": {
      "$state": "inferred",
      "$note": "Detection User",
      "$raw": "Dhruvs_Victus\\dhruv"
    }
  },
  "file": {
    "path": "C:\\Users\\dhruv\\AppData\\Local\\Temp\\opencode\\research\\velociraptor-docs\\content\\knowledge_base\\tips\\decimaldecode.md"
  },
  "unmapped": [
    {
      "name": "Product Version",
      "value": "4.18.26080.4"
    },
    {
      "name": "Detection ID",
      "value": "{CDF36DC1-A236-4131-A603-00FFE0588A74}"
    },
    {
      "name": "Threat ID",
      "value": "2147725066"
    },
    {
      "name": "FWLink",
      "value": "https://go.microsoft.com/fwlink/?linkid=37020&name=HackTool:PowerShell/Mimikatz&threatid=2147725066&enterprise=0"
    },
    {
      "name": "Status Code",
      "value": "1"
    },
    {
      "name": "State",
      "value": "1"
    },
    {
      "name": "Source Name",
      "value": "Real-Time Protection"
    },
    {
      "name": "Origin Name",
      "value": "Local machine"
    },
    {
      "name": "Type Name",
      "value": "SingleFile"
    }
  ]
}
```

### EX-WIN-DEF1117 — Malware action taken (Defender EID 1117)

<!-- covers: SEC-B Defender 1117 malware_action; derived_by sentinel (file/quarantine outcome) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "malware_action",
    "action": "quarantine",
    "outcome": "success",
    "severity": "high",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-08T14:56:49.230758Z",
    "original": "2026-10-08T14:56:49.2307586Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "Detection User",
      "$raw": "Dhruvs_Victus\\dhruv"
    }
  },
  "source": {
    "file_id": "loc-def-1117",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Windows Defender/Operational",
    "provider": "Microsoft-Windows-Windows Defender",
    "event_id": 1117,
    "record": {
      "type": "event_record",
      "record_id": 5433
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Windows Defender'/><EventID>1117</EventID><TimeCreated SystemTime='2026-10-08T14:56:49.2307586Z'/><EventRecordID>5433</EventRecordID><Channel>Microsoft-Windows-Windows Defender/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='Product Name'>Microsoft Defender Antivirus</Data><Data Name='Product Version'>4.18.26080.4</Data><Data Name='Detection ID'>{CDF36DC1-A236-4131-A603-00FFE0588A74}</Data><Data Name='Detection Time'>2026-10-08T14:55:43.466Z</Data><Data Name='Unused'></Data><Data Name='Unused2'></Data><Data Name='Threat ID'>2147725066</Data><Data Name='Threat Name'>HackTool:PowerShell/Mimikatz</Data><Data Name='Severity ID'>4</Data><Data Name='Severity Name'>High</Data><Data Name='Category ID'>34</Data><Data Name='Category Name'>Tool</Data><Data Name='FWLink'>https://go.microsoft.com/fwlink/?linkid=37020&amp;name=HackTool:PowerShell/Mimikatz&amp;threatid=2147725066&amp;enterprise=0</Data><Data Name='Status Code'>3</Data><Data Name='Status Description'></Data><Data Name='State'>2</Data><Data Name='Source ID'>3</Data><Data Name='Source Name'>Real-Time Protection</Data><Data Name='Process Name'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data><Data Name='Detection User'>Dhruvs_Victus\\dhruv</Data><Data Name='Unused3'></Data><Data Name='Path'>file:_C:\\Users\\dhruv\\AppData\\Local\\Temp\\opencode\\research\\velociraptor-docs\\content\\knowledge_base\\tips\\decimaldecode.md</Data><Data Name='Origin ID'>1</Data><Data Name='Origin Name'>Local machine</Data><Data Name='Execution ID'>1</Data><Data Name='Execution Name'>Suspended</Data><Data Name='Type ID'>0</Data><Data Name='Type Name'>Concrete</Data><Data Name='Pre Execution Status'>0</Data><Data Name='Action ID'>2</Data><Data Name='Action Name'>Quarantine</Data><Data Name='Unused4'></Data><Data Name='Error Code'>0x00000000</Data><Data Name='Error Description'>The operation completed successfully. </Data><Data Name='Unused5'></Data><Data Name='Post Clean Status'>0</Data><Data Name='Additional Actions ID'>0</Data><Data Name='Additional Actions String'>No additional actions required</Data><Data Name='Remediation User'>NT AUTHORITY\\SYSTEM</Data><Data Name='Unused6'></Data><Data Name='Security intelligence Version'>AV: 1.459.601.0, AS: 1.459.601.0, NIS: 1.459.601.0</Data><Data Name='Engine Version'>AM: 1.1.26080.3, NIS: 1.1.26080.3</Data></EventData></Event>",
  "third_party_alert": {
    "vendor": "Microsoft",
    "product": "Microsoft Defender Antivirus",
    "rule_name": "HackTool:PowerShell/Mimikatz",
    "category": "Tool",
    "severity_raw": "4 (High)",
    "mitigation": {
      "$state": "inferred",
      "$note": "Action Name field",
      "$raw": "Quarantine"
    }
  },
  "process": {
    "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "owner_name": {
      "$state": "inferred",
      "$note": "Detection User",
      "$raw": "Dhruvs_Victus\\dhruv"
    }
  },
  "file": {
    "path": "C:\\Users\\dhruv\\AppData\\Local\\Temp\\opencode\\research\\velociraptor-docs\\content\\knowledge_base\\tips\\decimaldecode.md"
  },
  "unmapped": [
    {
      "name": "Product Version",
      "value": "4.18.26080.4"
    },
    {
      "name": "Detection ID",
      "value": "{CDF36DC1-A236-4131-A603-00FFE0588A74}"
    },
    {
      "name": "Threat ID",
      "value": "2147725066"
    },
    {
      "name": "Status Code",
      "value": "3"
    },
    {
      "name": "State",
      "value": "2"
    },
    {
      "name": "Action ID",
      "value": "2"
    },
    {
      "name": "Action Name",
      "value": "Quarantine"
    }
  ]
}
```

### EX-WIN-DEF5001 — Real-time protection disabled (Defender EID 5001)

<!-- covers: SEC-B Defender 5001 realtime_protection_disabled; config_check derived_by sentinel -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "realtime_protection_disabled",
    "action": "disable",
    "outcome": "success",
    "severity": "high",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2025-10-22T11:25:39.109797Z",
    "original": "2025-10-22T11:25:39.1097979Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "sid": "S-1-5-18"
  },
  "source": {
    "file_id": "loc-def-5001",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Windows Defender/Operational",
    "provider": "Microsoft-Windows-Windows Defender",
    "event_id": 5001,
    "record": {
      "type": "event_record",
      "record_id": 126
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Windows Defender'/><EventID>5001</EventID><TimeCreated SystemTime='2025-10-22T11:25:39.1097979Z'/><EventRecordID>126</EventRecordID><Channel>Microsoft-Windows-Windows Defender/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='Product Name'>Microsoft Defender Antivirus</Data><Data Name='Product Version'>4.18.24090.11</Data></EventData></Event>",
  "third_party_alert": {
    "product": "Microsoft Defender Antivirus"
  },
  "config_check": {
    "check": "realtime_protection",
    "status": "fail",
    "observed": {
      "$state": "inferred",
      "$note": "5001 EventData has only Product Name/Version; disable state from event type",
      "$raw": "real-time protection disabled"
    }
  }
}
```

### EX-WIN-DEF5007 — Defender settings changed (Defender EID 5007)

<!-- covers: SEC-B Defender 5007 settings_change; Old Value→unmapped, New Value→config_check.observed -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "settings_change",
    "action": "change",
    "outcome": "success",
    "severity": "low",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T03:32:46.387776Z",
    "original": "2026-10-09T03:32:46.3877763Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "sid": "S-1-5-18"
  },
  "source": {
    "file_id": "loc-def-5007",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-Windows Defender/Operational",
    "provider": "Microsoft-Windows-Windows Defender",
    "event_id": 5007,
    "record": {
      "type": "event_record",
      "record_id": 5460
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Windows Defender'/><EventID>5007</EventID><TimeCreated SystemTime='2026-10-09T03:32:46.3877763Z'/><EventRecordID>5460</EventRecordID><Channel>Microsoft-Windows-Windows Defender/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='Product Name'>Microsoft Defender Antivirus</Data><Data Name='Product Version'>4.18.26080.4</Data><Data Name='Old Value'>HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\CoreService\\WdConfigHash = 0xDA61671A</Data><Data Name='New Value'>HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\CoreService\\WdConfigHash = 0x100D2E74</Data></EventData></Event>",
  "third_party_alert": {
    "product": "Microsoft Defender Antivirus"
  },
  "config_check": {
    "check": "defender_settings",
    "observed": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\CoreService\\WdConfigHash = 0x100D2E74"
  },
  "unmapped": [
    {
      "name": "Product Version",
      "value": "4.18.26080.4"
    },
    {
      "name": "Old Value",
      "value": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\CoreService\\WdConfigHash = 0xDA61671A"
    }
  ]
}
```

### EX-WIN-TS106 — Task registered (TaskScheduler EID 106)

<!-- covers: SEC-B TaskScheduler 106 task_register; ALL element names UNVERIFIED (B-COMMUNITY/B-PRIOR; channel disabled locally) -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "scheduled_task",
    "type": "task_register",
    "action": "register",
    "outcome": "success",
    "severity": "low",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:03:00.000000Z",
    "original": "2026-10-09T14:03:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED UserContext candidate",
      "$raw": "CORP\\jdoe"
    },
    "domain": {
      "$state": "inferred",
      "$note": "UNVERIFIED",
      "$raw": "CORP"
    }
  },
  "source": {
    "file_id": "demo-ts-106",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TaskScheduler/Operational",
    "provider": "Microsoft-Windows-TaskScheduler",
    "event_id": 106,
    "record": {
      "type": "event_record",
      "record_id": 9001
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TaskScheduler'/><EventID>106</EventID><TimeCreated SystemTime='2026-10-09T14:03:00.0000000Z'/><EventRecordID>9001</EventRecordID><Channel>Microsoft-Windows-TaskScheduler/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='ActionName'>C:\\Temp\\evil.exe</Data><Data Name='TaskName'>\\Updater</Data><Data Name='TaskPath'>\\</Data><Data Name='UserContext'>CORP\\jdoe</Data></EventData></Event>",
  "scheduled_task": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED element name (B-PRIOR)",
      "$raw": "\\Updater"
    },
    "path": {
      "$state": "inferred",
      "$note": "UNVERIFIED",
      "$raw": "\\"
    }
  }
}
```

### EX-WIN-TS140 — Task registration updated (TaskScheduler EID 140)

<!-- covers: SEC-B TaskScheduler 140 task_update; UNVERIFIED element names -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "scheduled_task",
    "type": "task_update",
    "action": "change",
    "outcome": "success",
    "severity": "low",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:03:10.000000Z",
    "original": "2026-10-09T14:03:10.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED UserContext",
      "$raw": "CORP\\jdoe"
    },
    "domain": {
      "$state": "inferred",
      "$raw": "CORP"
    }
  },
  "source": {
    "file_id": "demo-ts-140",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TaskScheduler/Operational",
    "provider": "Microsoft-Windows-TaskScheduler",
    "event_id": 140,
    "record": {
      "type": "event_record",
      "record_id": 9002
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TaskScheduler'/><EventID>140</EventID><TimeCreated SystemTime='2026-10-09T14:03:10.0000000Z'/><EventRecordID>9002</EventRecordID><Channel>Microsoft-Windows-TaskScheduler/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='TaskName'>\\Updater</Data><Data Name='TaskPath'>\\</Data><Data Name='UserContext'>CORP\\jdoe</Data><Data Name='Author'>CORP\\jdoe</Data></EventData></Event>",
  "scheduled_task": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED",
      "$raw": "\\Updater"
    },
    "path": {
      "$state": "inferred",
      "$raw": "\\"
    },
    "author": {
      "$state": "inferred",
      "$note": "UNVERIFIED Author",
      "$raw": "CORP\\jdoe"
    }
  }
}
```

### EX-WIN-TS141 — Task registration deleted (TaskScheduler EID 141)

<!-- covers: SEC-B TaskScheduler 141 task_delete; UNVERIFIED element names -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "scheduled_task",
    "type": "task_delete",
    "action": "delete",
    "outcome": "success",
    "severity": "low",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:03:20.000000Z",
    "original": "2026-10-09T14:03:20.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED UserContext",
      "$raw": "CORP\\jdoe"
    },
    "domain": {
      "$state": "inferred",
      "$raw": "CORP"
    }
  },
  "source": {
    "file_id": "demo-ts-141",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TaskScheduler/Operational",
    "provider": "Microsoft-Windows-TaskScheduler",
    "event_id": 141,
    "record": {
      "type": "event_record",
      "record_id": 9003
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TaskScheduler'/><EventID>141</EventID><TimeCreated SystemTime='2026-10-09T14:03:20.0000000Z'/><EventRecordID>9003</EventRecordID><Channel>Microsoft-Windows-TaskScheduler/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='TaskName'>\\Updater</Data><Data Name='TaskPath'>\\</Data><Data Name='UserContext'>CORP\\jdoe</Data></EventData></Event>",
  "scheduled_task": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED",
      "$raw": "\\Updater"
    },
    "path": {
      "$state": "inferred",
      "$raw": "\\"
    }
  }
}
```

### EX-WIN-TS200 — Scheduled task executed (TaskScheduler EID 200)

<!-- covers: SEC-B TaskScheduler 200 task_action_start; UNVERIFIED element names; Path→command INFERRED -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "scheduled_task",
    "type": "task_action_start",
    "action": "start",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:03:30.000000Z",
    "original": "2026-10-09T14:03:30.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "demo-ts-200",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TaskScheduler/Operational",
    "provider": "Microsoft-Windows-TaskScheduler",
    "event_id": 200,
    "record": {
      "type": "event_record",
      "record_id": 9004
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TaskScheduler'/><EventID>200</EventID><TimeCreated SystemTime='2026-10-09T14:03:30.0000000Z'/><EventRecordID>9004</EventRecordID><Channel>Microsoft-Windows-TaskScheduler/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='ActionName'>C:\\Temp\\evil.exe</Data><Data Name='TaskName'>\\Updater</Data><Data Name='TaskPath'>\\</Data></EventData></Event>",
  "scheduled_task": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED TaskName",
      "$raw": "\\Updater"
    },
    "command": {
      "$state": "inferred",
      "$note": "UNVERIFIED ActionName→command",
      "$raw": "C:\\Temp\\evil.exe"
    }
  }
}
```

### EX-WIN-TS201 — Scheduled task completed (TaskScheduler EID 201)

<!-- covers: SEC-B TaskScheduler 201 task_action_complete; UNVERIFIED element names -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "scheduled_task",
    "type": "task_action_complete",
    "action": "complete",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:03:40.000000Z",
    "original": "2026-10-09T14:03:40.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "demo-ts-201",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TaskScheduler/Operational",
    "provider": "Microsoft-Windows-TaskScheduler",
    "event_id": 201,
    "record": {
      "type": "event_record",
      "record_id": 9005
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TaskScheduler'/><EventID>201</EventID><TimeCreated SystemTime='2026-10-09T14:03:40.0000000Z'/><EventRecordID>9005</EventRecordID><Channel>Microsoft-Windows-TaskScheduler/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='ActionName'>C:\\Temp\\evil.exe</Data><Data Name='TaskName'>\\Updater</Data><Data Name='TaskPath'>\\</Data><Data Name='ResultCode'>0</Data></EventData></Event>",
  "scheduled_task": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED TaskName",
      "$raw": "\\Updater"
    },
    "result_code": {
      "$state": "inferred",
      "$note": "UNVERIFIED ResultCode",
      "$raw": "0"
    }
  }
}
```

### EX-WIN-LSM21 — Session logon (LSM EID 21)

<!-- covers: SEC-B LSM 21 session_logon; SessionID→unmapped; Address LOCAL→invalid state; DFIR semantics (21=logon) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "session_logon",
    "action": "logon",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T03:15:59.822772Z",
    "original": "2026-10-09T03:15:59.8227726Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UserData/User DOMAIN\\user",
      "$raw": "DHRUVS_VICTUS\\dhruv"
    },
    "domain": "DHRUVS_VICTUS"
  },
  "source": {
    "file_id": "loc-lsm-21",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "provider": "Microsoft-Windows-TerminalServices-LocalSessionManager",
    "event_id": 21,
    "record": {
      "type": "event_record",
      "record_id": 3370
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager'/><EventID>21</EventID><TimeCreated SystemTime='2026-10-09T03:15:59.8227726Z'/><EventRecordID>3370</EventRecordID><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><UserData><EventXML xmlns='Event_NS'><User>DHRUVS_VICTUS\\dhruv</User><SessionID>26</SessionID><Address>LOCAL</Address></EventXML></UserData></Event>",
  "authentication": {
    "logon_id": {
      "$state": "inferred",
      "$note": "SessionID mapped to logon_id (session identifier, INFERRED)",
      "$raw": "26"
    }
  },
  "network": {
    "src_ip": {
      "$state": "invalid",
      "$note": "LSM renders literal 'LOCAL' for console sessions — not an IP",
      "$raw": "LOCAL"
    }
  }
}
```

### EX-WIN-LSM22 — Shell start notification (LSM EID 22)

<!-- covers: SEC-B LSM 22; DFIR semantics: 22='Shell start notification received' (diverges from SEC-B logoff label) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "session_shell_start",
    "action": "shell_start",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T03:16:01.732713Z",
    "original": "2026-10-09T03:16:01.7327133Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UserData/User DOMAIN\\user",
      "$raw": "DHRUVS_VICTUS\\dhruv"
    },
    "domain": "DHRUVS_VICTUS"
  },
  "source": {
    "file_id": "loc-lsm-22",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "provider": "Microsoft-Windows-TerminalServices-LocalSessionManager",
    "event_id": 22,
    "record": {
      "type": "event_record",
      "record_id": 3371
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager'/><EventID>22</EventID><TimeCreated SystemTime='2026-10-09T03:16:01.7327133Z'/><EventRecordID>3371</EventRecordID><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><UserData><EventXML xmlns='Event_NS'><User>DHRUVS_VICTUS\\dhruv</User><SessionID>26</SessionID><Address>LOCAL</Address></EventXML></UserData></Event>",
  "authentication": {
    "logon_id": {
      "$state": "inferred",
      "$note": "SessionID mapped to logon_id (INFERRED)",
      "$raw": "26"
    }
  },
  "network": {
    "src_ip": {
      "$state": "invalid",
      "$note": "LSM 'LOCAL' literal — not an IP",
      "$raw": "LOCAL"
    }
  }
}
```

### EX-WIN-LSM23 — Session logoff (LSM EID 23)

<!-- covers: SEC-B LSM 23 logoff; NO Address on 23 (only User+SessionID) — do not expect src_ip -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "session_logoff",
    "action": "logoff",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-08T17:07:21.494425Z",
    "original": "2026-10-08T17:07:21.4944255Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UserData/User DOMAIN\\user",
      "$raw": "DHRUVS_VICTUS\\dhruv"
    },
    "domain": "DHRUVS_VICTUS"
  },
  "source": {
    "file_id": "loc-lsm-23",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "provider": "Microsoft-Windows-TerminalServices-LocalSessionManager",
    "event_id": 23,
    "record": {
      "type": "event_record",
      "record_id": 3363
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager'/><EventID>23</EventID><TimeCreated SystemTime='2026-10-08T17:07:21.4944255Z'/><EventRecordID>3363</EventRecordID><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><UserData><EventXML xmlns='Event_NS'><User>DHRUVS_VICTUS\\dhruv</User><SessionID>25</SessionID></EventXML></UserData></Event>",
  "authentication": {
    "logon_id": {
      "$state": "inferred",
      "$note": "SessionID mapped to logon_id (INFERRED); no Address on EID 23",
      "$raw": "25"
    }
  }
}
```

### EX-WIN-LSM24 — Session disconnected (LSM EID 24)

<!-- covers: SEC-B LSM 24 disconnect; DFIR semantics (24=disconnect) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "session_disconnect",
    "action": "disconnect",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-08T17:07:21.557158Z",
    "original": "2026-10-08T17:07:21.5571582Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UserData/User DOMAIN\\user",
      "$raw": "DHRUVS_VICTUS\\dhruv"
    },
    "domain": "DHRUVS_VICTUS"
  },
  "source": {
    "file_id": "loc-lsm-24",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "provider": "Microsoft-Windows-TerminalServices-LocalSessionManager",
    "event_id": 24,
    "record": {
      "type": "event_record",
      "record_id": 3367
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager'/><EventID>24</EventID><TimeCreated SystemTime='2026-10-08T17:07:21.5571582Z'/><EventRecordID>3367</EventRecordID><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><UserData><EventXML xmlns='Event_NS'><User>DHRUVS_VICTUS\\dhruv</User><SessionID>25</SessionID><Address>LOCAL</Address></EventXML></UserData></Event>",
  "authentication": {
    "logon_id": {
      "$state": "inferred",
      "$note": "SessionID mapped to logon_id (INFERRED)",
      "$raw": "25"
    }
  },
  "network": {
    "src_ip": {
      "$state": "invalid",
      "$note": "LSM 'LOCAL' literal — not an IP",
      "$raw": "LOCAL"
    }
  }
}
```

### EX-WIN-LSM25 — Session reconnect (LSM EID 25)

<!-- covers: SEC-B LSM 25 reconnect; DFIR semantics (25=reconnect) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "session_reconnect",
    "action": "reconnect",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-09-20T16:04:59.627557Z",
    "original": "2026-09-20T16:04:59.6275575Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UserData/User DOMAIN\\user",
      "$raw": "DHRUVS_VICTUS\\dhruv"
    },
    "domain": "DHRUVS_VICTUS"
  },
  "source": {
    "file_id": "loc-lsm-25",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "provider": "Microsoft-Windows-TerminalServices-LocalSessionManager",
    "event_id": 25,
    "record": {
      "type": "event_record",
      "record_id": 3205
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager'/><EventID>25</EventID><TimeCreated SystemTime='2026-09-20T16:04:59.6275575Z'/><EventRecordID>3205</EventRecordID><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><UserData><EventXML xmlns='Event_NS'><User>DHRUVS_VICTUS\\dhruv</User><SessionID>8</SessionID><Address>LOCAL</Address></EventXML></UserData></Event>",
  "authentication": {
    "logon_id": {
      "$state": "inferred",
      "$note": "SessionID mapped to logon_id (INFERRED)",
      "$raw": "8"
    }
  },
  "network": {
    "src_ip": {
      "$state": "invalid",
      "$note": "LSM 'LOCAL' literal — not an IP",
      "$raw": "LOCAL"
    }
  }
}
```

### EX-WIN-LSM39 — Session disconnected by session (LSM EID 39)

<!-- covers: SEC-B LSM 39; TargetSession/Source→unmapped; no User on 39; DFIR semantics (39=disconnect by session/shadow) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "session_disconnected_by_session",
    "action": "disconnect",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-08T17:07:21.526853Z",
    "original": "2026-10-08T17:07:21.5268533Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "Dhruvs_Victus",
    "os": {
      "family": "windows",
      "build": "26200"
    }
  },
  "user": {},
  "source": {
    "file_id": "loc-lsm-39",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "provider": "Microsoft-Windows-TerminalServices-LocalSessionManager",
    "event_id": 39,
    "record": {
      "type": "event_record",
      "record_id": 3364
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager'/><EventID>39</EventID><TimeCreated SystemTime='2026-10-08T17:07:21.5268533Z'/><EventRecordID>3364</EventRecordID><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>Dhruvs_Victus</Computer><Security UserID='S-1-5-18'/></System><UserData><EventXML xmlns='Event_NS'><TargetSession>25</TargetSession><Source>25</Source></EventXML></UserData></Event>",
  "authentication": {
    "logon_id": {
      "$state": "inferred",
      "$note": "TargetSession mapped to logon_id (INFERRED); Source unmapped",
      "$raw": "25"
    }
  },
  "unmapped": [
    {
      "name": "Source",
      "value": "25"
    }
  ]
}
```

### EX-WIN-RCM1149 — RDP pre-auth (RCM EID 1149)

<!-- covers: SEC-B RCM 1149 rdp_auth; element names UNVERIFIED (B-COMMUNITY/B-PRIOR); derived_by sentinel -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "authentication",
    "type": "rdp_auth",
    "action": "connect",
    "outcome": "success",
    "severity": "low",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:04:00.000000Z",
    "original": "2026-10-09T14:04:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "UNVERIFIED Param1 candidate",
      "$raw": "jdoe"
    },
    "domain": {
      "$state": "inferred",
      "$note": "UNVERIFIED Param2",
      "$raw": "CORP"
    }
  },
  "source": {
    "file_id": "demo-rcm-1149",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "provider": "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
    "event_id": 1149,
    "record": {
      "type": "event_record",
      "record_id": 5001
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-RemoteConnectionManager'/><EventID>1149</EventID><TimeCreated SystemTime='2026-10-09T14:04:00.0000000Z'/><EventRecordID>5001</EventRecordID><Channel>Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data Name='Param1'>jdoe</Data><Data Name='Param2'>CORP</Data><Data Name='Param3'>10.10.5.50</Data></EventData></Event>",
  "authentication": {
    "account_name": {
      "$state": "inferred",
      "$note": "UNVERIFIED Param1",
      "$raw": "jdoe"
    },
    "account_domain": {
      "$state": "inferred",
      "$note": "UNVERIFIED Param2",
      "$raw": "CORP"
    },
    "source_ip": {
      "$state": "inferred",
      "$note": "UNVERIFIED Param3",
      "$raw": "10.10.5.50"
    }
  }
}
```

### EX-WIN-AL8003 — AppLocker audit allowed (AppLocker EID 8003)

<!-- covers: SEC-B AppLocker 8003 applocker_audit; element names UNVERIFIED (B-PRIOR); template-verified file path only -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "applocker_audit",
    "action": "allow",
    "outcome": "success",
    "severity": "low",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:05:00.000000Z",
    "original": "2026-10-09T14:05:00.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "demo-al-8003",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-AppLocker/EXE and DLL",
    "provider": "Microsoft-Windows-AppLocker",
    "event_id": 8003,
    "record": {
      "type": "event_record",
      "record_id": 6001
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-AppLocker'/><EventID>8003</EventID><TimeCreated SystemTime='2026-10-09T14:05:00.0000000Z'/><EventRecordID>6001</EventRecordID><Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data>C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe was allowed.</Data></EventData></Event>",
  "config_check": {
    "check": "applocker_policy",
    "status": "pass",
    "observed": {
      "$state": "inferred",
      "$note": "UNVERIFIED element names; message-template param binding",
      "$raw": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe was allowed."
    }
  },
  "file": {
    "path": {
      "$state": "inferred",
      "$note": "UNVERIFIED element name; from template param",
      "$raw": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe"
    }
  }
}
```

### EX-WIN-AL8004 — AppLocker audit blocked (AppLocker EID 8004)

<!-- covers: SEC-B AppLocker 8004 applocker_audit; UNVERIFIED element names -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "applocker_audit",
    "action": "block",
    "outcome": "failure",
    "severity": "low",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:05:10.000000Z",
    "original": "2026-10-09T14:05:10.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "demo-al-8004",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-AppLocker/EXE and DLL",
    "provider": "Microsoft-Windows-AppLocker",
    "event_id": 8004,
    "record": {
      "type": "event_record",
      "record_id": 6002
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-AppLocker'/><EventID>8004</EventID><TimeCreated SystemTime='2026-10-09T14:05:10.0000000Z'/><EventRecordID>6002</EventRecordID><Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data>C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe was blocked.</Data></EventData></Event>",
  "config_check": {
    "check": "applocker_policy",
    "status": "fail",
    "observed": {
      "$state": "inferred",
      "$note": "UNVERIFIED element names; message-template param binding",
      "$raw": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe was blocked."
    }
  },
  "file": {
    "path": {
      "$state": "inferred",
      "$note": "UNVERIFIED element name",
      "$raw": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe"
    }
  }
}
```

### EX-WIN-AL8006 — AppLocker enforce allowed (AppLocker EID 8006)

<!-- covers: SEC-B AppLocker 8006; '<File name>' template VERIFIED (B-APPLOCKER-DOC) but element name UNVERIFIED; type applocker_enforce diverges from SEC-B applocker_block -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "applocker_enforce",
    "action": "allow",
    "outcome": "success",
    "severity": "low",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:05:20.000000Z",
    "original": "2026-10-09T14:05:20.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "demo-al-8006",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-AppLocker/EXE and DLL",
    "provider": "Microsoft-Windows-AppLocker",
    "event_id": 8006,
    "record": {
      "type": "event_record",
      "record_id": 6003
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-AppLocker'/><EventID>8006</EventID><TimeCreated SystemTime='2026-10-09T14:05:20.0000000Z'/><EventRecordID>6003</EventRecordID><Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data>C:\\Program Files\\legit\\app.exe</Data></EventData></Event>",
  "config_check": {
    "check": "applocker_policy",
    "status": "pass",
    "observed": {
      "$state": "inferred",
      "$note": "template-verified file path; element name UNVERIFIED",
      "$raw": "C:\\Program Files\\legit\\app.exe"
    }
  },
  "file": {
    "path": {
      "$state": "inferred",
      "$note": "template-verified param; element name UNVERIFIED",
      "$raw": "C:\\Program Files\\legit\\app.exe"
    }
  }
}
```

### EX-WIN-AL8007 — AppLocker enforce blocked (AppLocker EID 8007)

<!-- covers: SEC-B AppLocker 8007; template-verified file param; type applocker_enforce diverges from SEC-B applocker_block -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "applocker_enforce",
    "action": "block",
    "outcome": "failure",
    "severity": "medium",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:05:30.000000Z",
    "original": "2026-10-09T14:05:30.0000000Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {
    "hostname": "WS-DEMO01",
    "os": {
      "family": "windows",
      "build": "26100"
    }
  },
  "user": {},
  "source": {
    "file_id": "demo-al-8007",
    "format": "evtx",
    "parser": "evtx-canonical",
    "parser_version": "1.0.0",
    "channel": "Microsoft-Windows-AppLocker/EXE and DLL",
    "provider": "Microsoft-Windows-AppLocker",
    "event_id": 8007,
    "record": {
      "type": "event_record",
      "record_id": 6004
    }
  },
  "raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-AppLocker'/><EventID>8007</EventID><TimeCreated SystemTime='2026-10-09T14:05:30.0000000Z'/><EventRecordID>6004</EventRecordID><Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel><Computer>WS-DEMO01</Computer><Security/></System><EventData><Data>C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe</Data></EventData></Event>",
  "config_check": {
    "check": "applocker_policy",
    "status": "fail",
    "observed": {
      "$state": "inferred",
      "$note": "template-verified file path; element name UNVERIFIED",
      "$raw": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe"
    }
  },
  "file": {
    "path": {
      "$state": "inferred",
      "$note": "template-verified param; element name UNVERIFIED",
      "$raw": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe"
    }
  }
}
```

## Zeek JSON logs (6)

### EX-ZEEK-CONN — Zeek conn.log connection

<!-- covers: SEC-B Zeek conn; id.orig_h/orig_p/resp_h/resp_p/resp.proto flat names; service/history/pkts→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "network",
    "type": "network_connection",
    "action": "connect",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:00:00.123456Z",
    "original": "1791550800.123456",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "microsecond",
    "state": "inferred"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "zeek-conn-001",
    "format": "json",
    "parser": "zeek-json",
    "parser_version": "1.0.0"
  },
  "raw": {
    "ts": "1791550800.123456",
    "uid": "CnKxvG3DkQ8Qe4L9h",
    "id.orig_h": "10.10.5.23",
    "id.orig_p": 51540,
    "id.resp_h": "93.184.216.34",
    "id.resp_p": 443,
    "id.proto": "tcp",
    "proto": "tcp",
    "service": "ssl",
    "duration": 12.4,
    "orig_bytes": 8421,
    "resp_bytes": 245310,
    "conn_state": "S1",
    "missed_bytes": 0,
    "history": "ShADadFf",
    "orig_pkts": 42,
    "orig_ip_bytes": 3409,
    "resp_pkts": 187,
    "resp_ip_bytes": 253566,
    "local_orig": false,
    "local_resp": false,
    "tunnel_parents": []
  },
  "network": {
    "protocol": "tcp",
    "direction": {
      "$state": "inferred",
      "$note": "Zeek orig→resp; direction from conn role"
    },
    "src_ip": "10.10.5.23",
    "src_port": 51540,
    "dst_ip": "93.184.216.34",
    "dst_port": 443,
    "state": "S1",
    "duration": 12.4,
    "bytes_sent": 8421,
    "bytes_received": 245310,
    "uid": "CnKxvG3DkQ8Qe4L9h"
  },
  "unmapped": [
    {
      "name": "service",
      "value": "ssl"
    },
    {
      "name": "history",
      "value": "ShADadFf"
    },
    {
      "name": "orig_pkts",
      "value": 42
    },
    {
      "name": "orig_ip_bytes",
      "value": 3409
    },
    {
      "name": "resp_pkts",
      "value": 187
    },
    {
      "name": "resp_ip_bytes",
      "value": 253566
    },
    {
      "name": "local_orig",
      "value": false
    },
    {
      "name": "local_resp",
      "value": false
    }
  ]
}
```

### EX-ZEEK-DNS — Zeek dns.log query

<!-- covers: SEC-B Zeek dns; query/qtype_name/rcode_name/answers canonical; trans_id/qclass/flags/TTLs→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "dns",
    "type": "dns_query",
    "action": "query",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:00:00.123456Z",
    "original": "1791550800.123456",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "microsecond",
    "state": "inferred"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "zeek-dns-001",
    "format": "json",
    "parser": "zeek-json",
    "parser_version": "1.0.0"
  },
  "raw": {
    "ts": "1791550800.123456",
    "uid": "CyQpTj1V7Kj8Qe4L9h",
    "id.orig_h": "10.10.5.23",
    "id.orig_p": 51541,
    "id.resp_h": "10.10.0.1",
    "id.resp_p": 53,
    "id.proto": "udp",
    "proto": "udp",
    "service": "dns",
    "trans_id": 4321,
    "query": "example.com",
    "qclass": 1,
    "qclass_name": "C_INTERNET",
    "qtype": 1,
    "qtype_name": "A",
    "rcode": 0,
    "rcode_name": "NOERROR",
    "AA": false,
    "TC": false,
    "RD": true,
    "RA": true,
    "Z": 0,
    "answers": [
      "93.184.216.34"
    ],
    "TTLs": [
      300.0
    ],
    "rejected": false
  },
  "dns": {
    "query_name": "example.com",
    "query_type": "A",
    "response_code": "NOERROR",
    "answers": [
      "93.184.216.34"
    ],
    "server": "10.10.0.1"
  },
  "network": {
    "protocol": "udp",
    "src_ip": "10.10.5.23",
    "src_port": 51541,
    "dst_ip": "10.10.0.1",
    "dst_port": 53,
    "uid": "CyQpTj1V7Kj8Qe4L9h"
  },
  "unmapped": [
    {
      "name": "trans_id",
      "value": 4321
    },
    {
      "name": "qclass_name",
      "value": "C_INTERNET"
    },
    {
      "name": "qtype",
      "value": 1
    },
    {
      "name": "AA",
      "value": false
    },
    {
      "name": "TC",
      "value": false
    },
    {
      "name": "RD",
      "value": true
    },
    {
      "name": "RA",
      "value": true
    },
    {
      "name": "Z",
      "value": 0
    },
    {
      "name": "TTLs",
      "value": [
        300.0
      ]
    },
    {
      "name": "rejected",
      "value": false
    }
  ]
}
```

### EX-ZEEK-HTTP — Zeek http.log request

<!-- covers: SEC-B Zeek http; method/host/uri/user_agent/status_code/body lengths canonical; referrer/status_msg/tags→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "http",
    "type": "http_request",
    "action": "request",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:00:00.123456Z",
    "original": "1791550800.123456",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "microsecond",
    "state": "inferred"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "zeek-http-001",
    "format": "json",
    "parser": "zeek-json",
    "parser_version": "1.0.0"
  },
  "raw": {
    "ts": "1791550800.123456",
    "uid": "CHjKmL3NpQ8Qe4L9h",
    "id.orig_h": "10.10.5.23",
    "id.orig_p": 51542,
    "id.resp_h": "93.184.216.34",
    "id.resp_p": 80,
    "id.proto": "tcp",
    "service": "http",
    "trans_depth": 1,
    "method": "GET",
    "host": "example.com",
    "uri": "/payload.bin",
    "version": "1.1",
    "user_agent": "curl/8.5.0",
    "origin": "-",
    "referrer": "-",
    "request_body_len": 0,
    "response_body_len": 4096,
    "status_code": 200,
    "status_msg": "OK",
    "info_code": 0,
    "info_msg": "-",
    "tags": []
  },
  "http": {
    "method": "GET",
    "host": "example.com",
    "uri": "/payload.bin",
    "user_agent": "curl/8.5.0",
    "status_code": 200,
    "request_body_length": 0,
    "response_body_length": 4096
  },
  "network": {
    "protocol": "tcp",
    "src_ip": "10.10.5.23",
    "src_port": 51542,
    "dst_ip": "93.184.216.34",
    "dst_port": 80,
    "uid": "CHjKmL3NpQ8Qe4L9h"
  },
  "unmapped": [
    {
      "name": "version",
      "value": "1.1"
    },
    {
      "name": "origin",
      "value": "-"
    },
    {
      "name": "referrer",
      "value": "-"
    },
    {
      "name": "status_msg",
      "value": "OK"
    },
    {
      "name": "info_code",
      "value": 0
    },
    {
      "name": "tags",
      "value": []
    }
  ]
}
```

### EX-ZEEK-SSL — Zeek ssl.log handshake

<!-- covers: SEC-B Zeek ssl; server_name→tls.sni (INFERRED prefer sni); ja3/ja3s NOT in base Zeek; curve/dp/next_protocol→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "tls",
    "type": "tls_handshake",
    "action": "handshake",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:00:00.123456Z",
    "original": "1791550800.123456",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "microsecond",
    "state": "inferred"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "zeek-ssl-001",
    "format": "json",
    "parser": "zeek-json",
    "parser_version": "1.0.0"
  },
  "raw": {
    "ts": "1791550800.123456",
    "uid": "CSsTtUvWxY8Qe4L9h",
    "id.orig_h": "10.10.5.23",
    "id.orig_p": 51543,
    "id.resp_h": "93.184.216.34",
    "id.resp_p": 443,
    "id.proto": "tcp",
    "service": "ssl",
    "version": "TLSv12",
    "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "server_name": "example.com",
    "resumed": false,
    "established": true,
    "curve": "x25519",
    "dp": "ec",
    "next_protocol": "http/1.1",
    "last_alert": "-",
    "ssl_history": "Cc"
  },
  "tls": {
    "sni": "example.com",
    "server_name": "example.com",
    "version": "TLSv12",
    "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "resumed": false
  },
  "network": {
    "protocol": "tcp",
    "src_ip": "10.10.5.23",
    "src_port": 51543,
    "dst_ip": "93.184.216.34",
    "dst_port": 443,
    "uid": "CSsTtUvWxY8Qe4L9h"
  },
  "unmapped": [
    {
      "name": "curve",
      "value": "x25519"
    },
    {
      "name": "dp",
      "value": "ec"
    },
    {
      "name": "next_protocol",
      "value": "http/1.1"
    },
    {
      "name": "last_alert",
      "value": "-"
    },
    {
      "name": "ssl_history",
      "value": "Cc"
    }
  ]
}
```

### EX-ZEEK-NOTICE — Zeek notice.log alert

<!-- covers: SEC-B Zeek notice; derived_by sentinel; note→rule_id, msg→description; src/dst/p canonical -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "third_party_alert",
    "type": "zeek_notice",
    "action": "notice",
    "outcome": "success",
    "severity": "medium",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:00:00.123456Z",
    "original": "1791550800.123456",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "microsecond",
    "state": "inferred"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "zeek-notice-001",
    "format": "json",
    "parser": "zeek-json",
    "parser_version": "1.0.0"
  },
  "raw": {
    "ts": "1791550800.123456",
    "uid": "CnNnOoPpQq8Qe4L9h",
    "id.orig_h": "10.10.5.23",
    "id.orig_p": 51544,
    "id.resp_h": "10.10.0.5",
    "id.resp_p": 80,
    "note": "HTTP::SQL_Injection_Attack",
    "msg": "SQL injection attempt in URI",
    "sub": "/search?q=1' OR 1=1--",
    "src": "10.10.5.23",
    "dst": "10.10.0.5",
    "p": 80,
    "peer_descr": "zeek-sensor-01",
    "actions": [
      "Notice::ACTION_LOG"
    ],
    "suppress_for": 3600.0,
    "dropped": false
  },
  "third_party_alert": {
    "vendor": "Zeek",
    "product": "Zeek",
    "rule_id": "HTTP::SQL_Injection_Attack",
    "description": "SQL injection attempt in URI",
    "observable": "/search?q=1' OR 1=1--"
  },
  "network": {
    "src_ip": "10.10.5.23",
    "src_port": 51544,
    "dst_ip": "10.10.0.5",
    "dst_port": 80,
    "uid": "CnNnOoPpQq8Qe4L9h"
  },
  "unmapped": [
    {
      "name": "sub",
      "value": "/search?q=1' OR 1=1--"
    },
    {
      "name": "peer_descr",
      "value": "zeek-sensor-01"
    },
    {
      "name": "actions",
      "value": [
        "Notice::ACTION_LOG"
      ]
    },
    {
      "name": "suppress_for",
      "value": 3600.0
    },
    {
      "name": "dropped",
      "value": false
    }
  ]
}
```

### EX-ZEEK-FILES — Zeek files.log seen file

<!-- covers: SEC-B Zeek files; uid=conn uid (NO tx_uid); md5/sha1/sha256 canonical; fuid/source/analyzers→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_seen",
    "action": "seen",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:00:00.123456Z",
    "original": "1791550800.123456",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "microsecond",
    "state": "inferred"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "zeek-files-001",
    "format": "json",
    "parser": "zeek-json",
    "parser_version": "1.0.0"
  },
  "raw": {
    "ts": "1791550800.123456",
    "fuid": "FhHhIiJjKk8Qe4L9h",
    "uid": "CHjKmL3NpQ8Qe4L9h",
    "id.orig_h": "10.10.5.23",
    "id.orig_p": 51542,
    "id.resp_h": "93.184.216.34",
    "id.resp_p": 80,
    "id.proto": "tcp",
    "source": "HTTP",
    "depth": 0,
    "analyzers": [
      "MD5",
      "SHA1",
      "SHA256",
      "EXTRACT"
    ],
    "mime_type": "application/x-msdownload",
    "filename": "payload.bin",
    "duration": 0.5,
    "orig_bytes": 0,
    "resp_bytes": 4096,
    "seen_bytes": 4096,
    "total_bytes": 4096,
    "missing_bytes": 0,
    "overflow_bytes": 0,
    "timedout": false,
    "parent_fuid": "-",
    "is_orig": false,
    "local_orig": false,
    "md5": "5d41402abc4b2a76b9719d911017c592",
    "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
    "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
  },
  "file": {
    "name": "payload.bin",
    "type": "application/x-msdownload",
    "size": 4096,
    "hashes": {
      "md5": "5d41402abc4b2a76b9719d911017c592",
      "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
      "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    }
  },
  "network": {
    "uid": "CHjKmL3NpQ8Qe4L9h",
    "src_ip": "10.10.5.23",
    "src_port": 51542,
    "dst_ip": "93.184.216.34",
    "dst_port": 80
  },
  "unmapped": [
    {
      "name": "fuid",
      "value": "FhHhIiJjKk8Qe4L9h"
    },
    {
      "name": "source",
      "value": "HTTP"
    },
    {
      "name": "depth",
      "value": 0
    },
    {
      "name": "analyzers",
      "value": [
        "MD5",
        "SHA1",
        "SHA256",
        "EXTRACT"
      ]
    },
    {
      "name": "duration",
      "value": 0.5
    },
    {
      "name": "orig_bytes",
      "value": 0
    },
    {
      "name": "resp_bytes",
      "value": 4096
    },
    {
      "name": "seen_bytes",
      "value": 4096
    },
    {
      "name": "total_bytes",
      "value": 4096
    },
    {
      "name": "missing_bytes",
      "value": 0
    },
    {
      "name": "overflow_bytes",
      "value": 0
    }
  ]
}
```

## Suricata EVE JSON (6)

### EX-EVE-ALERT — Suricata EVE alert

<!-- covers: SEC-B EVE alert; alert.* → third_party_alert; severity 1→critical; flow_id→network.uid INFERRED -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "third_party_alert",
    "type": "suricata_alert",
    "action": "alert",
    "outcome": "success",
    "severity": "critical",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:20:00.123456Z",
    "original": "2026-10-09T14:20:00.123456+0000",
    "original_timezone": "+00:00",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "eve-alert-001",
    "format": "json",
    "parser": "suricata-eve",
    "parser_version": "1.0.0"
  },
  "raw": {
    "timestamp": "2026-10-09T14:20:00.123456+0000",
    "flow_id": 987654321,
    "pcap_cnt": 42,
    "event_type": "alert",
    "src_ip": "10.10.5.99",
    "src_port": 44444,
    "dest_ip": "10.10.5.23",
    "dest_port": 445,
    "proto": "TCP",
    "alert": {
      "action": "allowed",
      "gid": 1,
      "signature_id": 2024218,
      "rev": 4,
      "signature": "ET EXPLOIT SMBv1 Trans2 Request - EternalBlue",
      "category": "Attempted Administrator Privilege Gain",
      "severity": 1
    }
  },
  "third_party_alert": {
    "vendor": "Suricata",
    "product": "Suricata",
    "rule_name": "ET EXPLOIT SMBv1 Trans2 Request - EternalBlue",
    "rule_id": "2024218",
    "category": "Attempted Administrator Privilege Gain",
    "severity_raw": "1"
  },
  "network": {
    "protocol": "TCP",
    "src_ip": "10.10.5.99",
    "src_port": 44444,
    "dst_ip": "10.10.5.23",
    "dst_port": 445,
    "uid": "987654321"
  },
  "unmapped": [
    {
      "name": "action",
      "value": "allowed"
    },
    {
      "name": "gid",
      "value": 1
    },
    {
      "name": "rev",
      "value": 4
    },
    {
      "name": "pcap_cnt",
      "value": 42
    }
  ]
}
```

### EX-EVE-HTTP — Suricata EVE http

<!-- covers: SEC-B EVE http; http.* canonical; length→request_body_length (INFERRED as request/response body length carrier) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "http",
    "type": "http_request",
    "action": "request",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:21:00.654321Z",
    "original": "2026-10-09T14:21:00.654321+0000",
    "original_timezone": "+00:00",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "eve-http-001",
    "format": "json",
    "parser": "suricata-eve",
    "parser_version": "1.0.0"
  },
  "raw": {
    "timestamp": "2026-10-09T14:21:00.654321+0000",
    "flow_id": 123456789,
    "event_type": "http",
    "src_ip": "10.10.5.23",
    "src_port": 51550,
    "dest_ip": "93.184.216.34",
    "dest_port": 80,
    "proto": "TCP",
    "http": {
      "hostname": "example.com",
      "url": "/payload.bin",
      "http_user_agent": "curl/8.5.0",
      "http_method": "GET",
      "protocol": "HTTP/1.1",
      "status": 200,
      "length": 4096
    }
  },
  "http": {
    "host": "example.com",
    "url": "/payload.bin",
    "user_agent": "curl/8.5.0",
    "method": "GET",
    "status_code": 200,
    "request_body_length": 4096
  },
  "network": {
    "protocol": "TCP",
    "src_ip": "10.10.5.23",
    "src_port": 51550,
    "dst_ip": "93.184.216.34",
    "dst_port": 80,
    "uid": "123456789"
  }
}
```

### EX-EVE-DNS — Suricata EVE dns

<!-- covers: SEC-B EVE dns; dns.rrname/rrtype/rdata/answers canonical; id/rcode/ttl→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "dns",
    "type": "dns_query",
    "action": "response",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:22:00.111222Z",
    "original": "2026-10-09T14:22:00.111222+0000",
    "original_timezone": "+00:00",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "eve-dns-001",
    "format": "json",
    "parser": "suricata-eve",
    "parser_version": "1.0.0"
  },
  "raw": {
    "timestamp": "2026-10-09T14:22:00.111222+0000",
    "flow_id": 223344556,
    "event_type": "dns",
    "src_ip": "10.10.5.23",
    "src_port": 51541,
    "dest_ip": "10.10.0.1",
    "dest_port": 53,
    "proto": "UDP",
    "dns": {
      "type": "answer",
      "id": 4321,
      "rrname": "example.com",
      "rrtype": "A",
      "rcode": "NOERROR",
      "ttl": 300,
      "answers": [
        {
          "rrname": "example.com",
          "rrtype": "A",
          "ttl": 300,
          "rdata": "93.184.216.34"
        }
      ]
    }
  },
  "dns": {
    "query_name": "example.com",
    "query_type": "A",
    "response_code": "NOERROR",
    "answers": [
      "93.184.216.34"
    ],
    "server": "10.10.0.1"
  },
  "network": {
    "protocol": "UDP",
    "src_ip": "10.10.5.23",
    "src_port": 51541,
    "dst_ip": "10.10.0.1",
    "dst_port": 53,
    "uid": "223344556"
  },
  "unmapped": [
    {
      "name": "id",
      "value": 4321
    },
    {
      "name": "ttl",
      "value": 300
    }
  ]
}
```

### EX-EVE-TLS — Suricata EVE tls

<!-- covers: SEC-B EVE tls; sni/ja3/ja3s/version/subject/issuer canonical -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "tls",
    "type": "tls_handshake",
    "action": "handshake",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:23:00.999888Z",
    "original": "2026-10-09T14:23:00.999888+0000",
    "original_timezone": "+00:00",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "eve-tls-001",
    "format": "json",
    "parser": "suricata-eve",
    "parser_version": "1.0.0"
  },
  "raw": {
    "timestamp": "2026-10-09T14:23:00.999888+0000",
    "flow_id": 334455667,
    "event_type": "tls",
    "src_ip": "10.10.5.23",
    "src_port": 51543,
    "dest_ip": "93.184.216.34",
    "dest_port": 443,
    "proto": "TCP",
    "tls": {
      "subject": "CN=example.com",
      "issuer": "CN=Example CA",
      "serial": "0a1b2c3d4e5f",
      "fingerprint": "ab:cd:ef:...",
      "sni": "example.com",
      "version": "TLS 1.2",
      "ja3": "e7d705a3286e19ea42f587b344ee6865",
      "ja3s": "aaf33f89f218dd09568c70de42a0186d"
    }
  },
  "tls": {
    "sni": "example.com",
    "version": "TLS 1.2",
    "subject": "CN=example.com",
    "issuer": "CN=Example CA",
    "ja3": "e7d705a3286e19ea42f587b344ee6865",
    "ja3s": "aaf33f89f218dd09568c70de42a0186d"
  },
  "network": {
    "protocol": "TCP",
    "src_ip": "10.10.5.23",
    "src_port": 51543,
    "dst_ip": "93.184.216.34",
    "dst_port": 443,
    "uid": "334455667"
  },
  "unmapped": [
    {
      "name": "serial",
      "value": "0a1b2c3d4e5f"
    },
    {
      "name": "fingerprint",
      "value": "ab:cd:ef:..."
    }
  ]
}
```

### EX-EVE-FLOW — Suricata EVE flow

<!-- covers: SEC-B EVE flow; bytes_toserver/toclient→bytes_sent/received; pkts_*→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "network",
    "type": "network_connection",
    "action": "connect",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:24:00.333444Z",
    "original": "2026-10-09T14:24:00.333444+0000",
    "original_timezone": "+00:00",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "eve-flow-001",
    "format": "json",
    "parser": "suricata-eve",
    "parser_version": "1.0.0"
  },
  "raw": {
    "timestamp": "2026-10-09T14:24:00.333444+0000",
    "flow_id": 445566778,
    "event_type": "flow",
    "src_ip": "10.10.5.23",
    "src_port": 51560,
    "dest_ip": "93.184.216.34",
    "dest_port": 443,
    "proto": "TCP",
    "flow": {
      "pkts_toserver": 42,
      "pkts_toclient": 187,
      "bytes_toserver": 3409,
      "bytes_toclient": 253566,
      "start": "2026-10-09T14:20:00.000000+0000",
      "end": "2026-10-09T14:20:12.400000+0000"
    }
  },
  "network": {
    "protocol": "TCP",
    "src_ip": "10.10.5.23",
    "src_port": 51560,
    "dst_ip": "93.184.216.34",
    "dst_port": 443,
    "bytes_sent": 3409,
    "bytes_received": 253566,
    "uid": "445566778"
  },
  "unmapped": [
    {
      "name": "pkts_toserver",
      "value": 42
    },
    {
      "name": "pkts_toclient",
      "value": 187
    },
    {
      "name": "start",
      "value": "2026-10-09T14:20:00.000000+0000"
    },
    {
      "name": "end",
      "value": "2026-10-09T14:20:12.400000+0000"
    }
  ]
}
```

### EX-EVE-FILEINFO — Suricata EVE fileinfo

<!-- covers: SEC-B EVE fileinfo; filename/magic/md5/sha256/size canonical; state/gaps/sid→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "file",
    "type": "file_seen",
    "action": "seen",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "source"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:25:00.777888Z",
    "original": "2026-10-09T14:25:00.777888+0000",
    "original_timezone": "+00:00",
    "timezone_source": "source_explicit",
    "precision": "microsecond",
    "state": "ok"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "eve-fileinfo-001",
    "format": "json",
    "parser": "suricata-eve",
    "parser_version": "1.0.0"
  },
  "raw": {
    "timestamp": "2026-10-09T14:25:00.777888+0000",
    "flow_id": 556677889,
    "event_type": "fileinfo",
    "src_ip": "10.10.5.23",
    "src_port": 51542,
    "dest_ip": "93.184.216.34",
    "dest_port": 80,
    "proto": "TCP",
    "fileinfo": {
      "filename": "payload.bin",
      "sid": null,
      "magic": "PE32 executable (GUI) Intel 80386, for MS Windows",
      "gaps": false,
      "state": "CLOSED",
      "md5": "5d41402abc4b2a76b9719d911017c592",
      "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
      "size": 4096
    }
  },
  "file": {
    "name": "payload.bin",
    "type": "PE32 executable (GUI) Intel 80386, for MS Windows",
    "size": 4096,
    "hashes": {
      "md5": "5d41402abc4b2a76b9719d911017c592",
      "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    }
  },
  "network": {
    "protocol": "TCP",
    "src_ip": "10.10.5.23",
    "src_port": 51542,
    "dst_ip": "93.184.216.34",
    "dst_port": 80,
    "uid": "556677889"
  },
  "unmapped": [
    {
      "name": "state",
      "value": "CLOSED"
    },
    {
      "name": "gaps",
      "value": false
    }
  ]
}
```

## Nmap XML export (1)

### EX-NMAP-1 — Nmap XML scan result

<!-- covers: SEC-B Nmap; config_check port_scan derived_by sentinel; almost everything unmapped under nmap.*; @start epoch→unmapped -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "port_scan",
    "action": "scan",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": null,
    "original": "Sat Oct  9 14:21:40 2026",
    "timezone_source": "none",
    "precision": "second",
    "state": "unknown"
  },
  "host": {
    "hostname": "fileserver01.corp.local",
    "ips": [
      "10.10.0.5"
    ],
    "os": {
      "family": {
        "$state": "inferred",
        "$note": "nmap osmatch",
        "$raw": "Windows Server 2022"
      }
    }
  },
  "user": {},
  "source": {
    "file_id": "nmap-001",
    "format": "nmap_xml",
    "parser": "nmap-xml",
    "parser_version": "1.0.0"
  },
  "raw": "<nmaprun scanner='nmap' args='nmap -sV -oX scan.xml 10.10.0.5' start='1791550900' startstr='Sat Oct  9 14:21:40 2026' version='7.95' xmloutputversion='1.05'><host starttime='1791550901' endtime='1791550960'><status state='up' reason='echo-reply' reason_ttl='63'/><address addr='10.10.0.5' addrtype='ipv4'/><hostname name='fileserver01.corp.local' type='PTR'/><ports><port protocol='tcp' portid='445'><state state='open' reason='syn-ack' reason_ttl='63'/><service name='microsoft-ds' product='Windows Server 2022' method='probed' conf='10'><cpe>cpe:/o:microsoft:windows_server_2022</cpe></service></port></ports><times srtt='250' rttvar='100' to='100000'/><runstats><finished time='1791550960' timestr='Sat Oct  9 14:22:40 2026' elapsed='60.00' summary='Nmap done at Sat Oct  9 14:22:40 2026; 1 IP address (1 host up) scanned in 60.00 seconds' exit='success'/><hosts up='1' down='0' total='1'/></runstats></nmaprun>",
  "config_check": {
    "check": "port_scan",
    "status": "pass",
    "observed": {
      "$state": "inferred",
      "$note": "scanned host inventory summary",
      "$raw": "10.10.0.5 tcp/445 open microsoft-ds"
    }
  },
  "network": {
    "protocol": "tcp",
    "dst_port": 445,
    "state": "open",
    "dst_ip": {
      "$state": "inferred",
      "$note": "address@addr is scan target, not scanner — mapped to dst_ip INFERRED",
      "$raw": "10.10.0.5"
    }
  },
  "unmapped": [
    {
      "name": "nmap.args",
      "value": "nmap -sV -oX scan.xml 10.10.0.5"
    },
    {
      "name": "nmap.version",
      "value": "7.95"
    },
    {
      "name": "nmap.start_epoch",
      "value": "1791550900"
    },
    {
      "name": "host.state_reason",
      "value": "echo-reply"
    },
    {
      "name": "nmap.hostname",
      "value": "fileserver01.corp.local"
    },
    {
      "name": "nmap.service.name",
      "value": "microsoft-ds"
    },
    {
      "name": "nmap.service.product",
      "value": "Windows Server 2022"
    },
    {
      "name": "nmap.cpe",
      "value": "cpe:/o:microsoft:windows_server_2022"
    },
    {
      "name": "nmap.runstats.finished_epoch",
      "value": "1791550960"
    }
  ]
}
```

## netstat snapshot (1)

### EX-NETSTAT-1 — netstat -ano snapshot

<!-- covers: SEC-B netstat; config_check derived_by sentinel; Local/Foreign Address split INFERRED; PID→process.pid INFERRED; time unknown (no timestamp) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "config_check",
    "type": "connection_inventory",
    "action": "inventory",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": null,
    "timezone_source": "none",
    "precision": "unknown",
    "state": "unknown"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "netstat-001",
    "format": "text",
    "parser": "netstat-parser",
    "parser_version": "1.0.0"
  },
  "raw": "Active Connections\n\n  Proto  Local Address        Foreign Address      State           PID\n  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234\n  TCP    10.10.5.23:51540      93.184.216.34:443      ESTABLISHED     4521\n",
  "config_check": {
    "check": "netstat_connections",
    "status": "pass",
    "observed": {
      "$state": "inferred",
      "$note": "one row promoted as example; full table in raw",
      "$raw": "TCP 10.10.5.23:51540 -> 93.184.216.34:443 ESTABLISHED PID 4521"
    }
  },
  "network": {
    "protocol": "TCP",
    "state": "ESTABLISHED",
    "src_ip": "10.10.5.23",
    "src_port": 51540,
    "dst_ip": "93.184.216.34",
    "dst_port": 443,
    "process": {
      "pid": {
        "$state": "inferred",
        "$note": "netstat PID is snapshot; join to process record INFERRED; PID reuse trap",
        "$raw": "4521"
      }
    }
  }
}
```

## schtasks /query snapshot (1)

### EX-SCHTASKS-1 — schtasks /query snapshot

<!-- covers: SEC-B schtasks; scheduled_task fields; command/args/user_id/author INFERRED column mapping -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "scheduled_task",
    "type": "task_inventory",
    "action": "inventory",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": null,
    "timezone_source": "none",
    "precision": "unknown",
    "state": "unknown"
  },
  "host": {},
  "user": {
    "name": {
      "$state": "inferred",
      "$note": "Run As User",
      "$raw": "CORP\\jdoe"
    },
    "domain": "CORP"
  },
  "source": {
    "file_id": "schtasks-001",
    "format": "text",
    "parser": "schtasks-parser",
    "parser_version": "1.0.0"
  },
  "raw": "TaskName: \\Updater\nNext Run Time: 10/9/2026 6:00:00 PM\nStatus: Ready\nLogon Mode: Interactive/Background\nLast Run Time: 10/9/2026 2:00:00 PM\nLast Result: 0\nAuthor: CORP\\jdoe\nTask To Run: C:\\Temp\\evil.exe \nStart In: C:\\Temp\nRun As User: CORP\\jdoe\n",
  "scheduled_task": {
    "name": {
      "$state": "inferred",
      "$raw": "\\Updater"
    },
    "command": {
      "$state": "inferred",
      "$note": "Task To Run column",
      "$raw": "C:\\Temp\\evil.exe"
    },
    "arguments": {
      "$state": "null",
      "$note": "no args in sample"
    },
    "working_directory": {
      "$state": "inferred",
      "$raw": "C:\\Temp"
    },
    "user_id": {
      "$state": "inferred",
      "$raw": "CORP\\jdoe"
    },
    "author": {
      "$state": "inferred",
      "$raw": "CORP\\jdoe"
    },
    "result_code": {
      "$state": "inferred",
      "$raw": "0"
    },
    "trigger": {
      "$state": "inferred",
      "$note": "Next Run Time implies schedule",
      "$raw": "10/9/2026 6:00:00 PM"
    }
  }
}
```

## sc query snapshot (1)

### EX-SCQUERY-1 — sc query snapshot

<!-- covers: SEC-B sc query; SERVICE_NAME/TYPE/STATE/exit codes/checkpoint/wait_hint canonical -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "service",
    "type": "service_inventory",
    "action": "inventory",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": null,
    "timezone_source": "none",
    "precision": "unknown",
    "state": "unknown"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "sc-query-001",
    "format": "text",
    "parser": "sc-query-parser",
    "parser_version": "1.0.0"
  },
  "raw": "SERVICE_NAME: EvilSvc\n        TYPE               : 10  WIN32_OWN_PROCESS  \n        STATE              : 4  RUNNING  \n                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)\n        WIN32_EXIT_CODE    : 0  (0x0)\n        SERVICE_EXIT_CODE  : 0  (0x0)\n        CHECKPOINT         : 0x0\n        WAIT_HINT          : 0x0\n",
  "service": {
    "name": "EvilSvc",
    "service_type": "10  WIN32_OWN_PROCESS",
    "state": "4  RUNNING",
    "exit_code": "0  (0x0)",
    "checkpoint": {
      "$state": "inferred",
      "$raw": "0x0"
    },
    "wait_hint": {
      "$state": "inferred",
      "$raw": "0x0"
    }
  }
}
```

## sc qc snapshot (1)

### EX-SCQC-1 — sc qc snapshot

<!-- covers: SEC-B sc qc; BINARY_PATH_NAME UNVERIFIED (B-PRIOR; MS sc-qc URL 404s) -->
<!-- labels: UNVERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "service",
    "type": "service_config_inventory",
    "action": "inventory",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": null,
    "timezone_source": "none",
    "precision": "unknown",
    "state": "unknown"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "sc-qc-001",
    "format": "text",
    "parser": "sc-qc-parser",
    "parser_version": "1.0.0"
  },
  "raw": "[SC] QueryServiceConfig SUCCESS\nSERVICE_NAME: EvilSvc\n        TYPE               : 10  WIN32_OWN_PROCESS\n        START_TYPE         : 3   DEMAND_START\n        ERROR_CONTROL     : 1   NORMAL\n        BINARY_PATH_NAME  : \"C:\\Temp\\evil.exe\" -k netsvcs\n        LOAD_ORDER_GROUP  : NetWork\n        TAG                : 0\n        DISPLAY_NAME       : Evil Service\n        DEPENDENCIES      : \n        SERVICE_START_NAME : LocalSystem\n",
  "service": {
    "name": "EvilSvc",
    "image_path": {
      "$state": "inferred",
      "$note": "BINARY_PATH_NAME field list UNVERIFIED (B-PRIOR); map observed value INFERRED",
      "$raw": "\"C:\\Temp\\evil.exe\" -k netsvcs"
    },
    "start_type": {
      "$state": "inferred",
      "$raw": "3   DEMAND_START"
    },
    "error_control": {
      "$state": "inferred",
      "$raw": "1   NORMAL"
    },
    "display_name": {
      "$state": "inferred",
      "$raw": "Evil Service"
    },
    "load_order_group": {
      "$state": "inferred",
      "$raw": "NetWork"
    },
    "account_name": {
      "$state": "inferred",
      "$raw": "LocalSystem"
    }
  }
}
```

## reg export .reg snapshot (1)

### EX-REGEXPORT-1 — reg export .reg snapshot

<!-- covers: SEC-B reg export; registry payload from .reg content; operation=export INFERRED; time unknown -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "registry",
    "type": "registry_export",
    "action": "export",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": null,
    "timezone_source": "none",
    "precision": "unknown",
    "state": "unknown"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "reg-export-001",
    "format": "text",
    "parser": "reg-export-parser",
    "parser_version": "1.0.0"
  },
  "raw": "Windows Registry Editor Version 5.00\n\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]\n\"Updater\"=\"C:\\\\Temp\\\\evil.exe\"\n",
  "registry": {
    "path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
    "hive": "HKLM",
    "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "value_name": "Updater",
    "data": "C:\\Temp\\evil.exe",
    "operation": {
      "$state": "inferred",
      "$note": "export is not a runtime registry operation; snapshot semantics"
    }
  }
}
```

## PowerShell Export-Csv inventory (1)

### EX-EXPORTCSV-1 — Export-Csv process inventory

<!-- covers: SEC-B Export-Csv; structure only — property names→header; process payload from Get-Process-style rows -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "process",
    "type": "process_inventory",
    "action": "inventory",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T13:00:00.123456Z",
    "original": "1791550800.123456",
    "original_timezone": "Z",
    "timezone_source": "source_documented_utc",
    "precision": "microsecond",
    "state": "inferred"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "export-csv-001",
    "format": "csv",
    "parser": "export-csv-parser",
    "parser_version": "1.0.0"
  },
  "raw": "\"Id\",\"ProcessName\",\"Path\",\"StartTime\"\r\n\"1234\",\"cmd\",\"C:\\Windows\\System32\\cmd.exe\",\"2026-10-09T12:00:00\"\r\n\"4521\",\"powershell\",\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\",\"2026-10-09T12:05:00\"\r\n",
  "process": {
    "pid": {
      "$state": "inferred",
      "$note": "CSV Id column from Get-Process",
      "$raw": "4521"
    },
    "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "name": "powershell",
    "start_time": {
      "$state": "inferred",
      "$raw": "2026-10-09T12:05:00"
    }
  }
}
```

## autorunsc autostart inventory (1)

### EX-AUTORUNS-1 — autorunsc autostart inventory

<!-- covers: SEC-B autorunsc; Path/Launch String→process.exe INFERRED; -h hashes→file.hashes; Publisher unmapped (no service.provider_path/publisher) -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "artifact",
    "type": "autostart_inventory",
    "action": "inventory",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-09-01T10:00:00Z",
    "original": "2026-09-01T10:00:00Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "second",
    "state": "inferred"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "autoruns-001",
    "format": "csv",
    "parser": "autorunsc-parser",
    "parser_version": "1.0.0"
  },
  "raw": "\"Entry Location\",\"Entry\",\"Enabled\",\"Hidden\",\"Path\",\"Launch String\",\"Publisher\",\"Image Path\",\"Version\",\"Last Modified\",\"MD5\",\"SHA-1\",\"SHA-256\",\"Verification Status\"\r\n\"Logon\",\"OneDrive\",\"Enabled\",\"false\",\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\",\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background\",\"Microsoft Corporation\",\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\",\"25.0.1.1\",\"2026-09-01T10:00:00\",\"aa11...\",\"bb22...\",\"cc33...\",\"Verified\"\r\n",
  "artifact": {
    "type": "process",
    "identity": "OneDrive",
    "path": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
    "attributes": "Enabled; Publisher=Microsoft Corporation; Verification=Verified"
  },
  "process": {
    "exe": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
    "name": "OneDrive.exe",
    "original_file_name": "OneDrive.exe",
    "hashes": {
      "md5": {
        "$state": "inferred",
        "$note": "abbreviated for example",
        "$raw": "aa11..."
      },
      "sha1": {
        "$state": "inferred",
        "$raw": "bb22..."
      },
      "sha256": {
        "$state": "inferred",
        "$raw": "cc33..."
      }
    }
  },
  "unmapped": [
    {
      "name": "autoruns.location",
      "value": "Logon"
    },
    {
      "name": "publisher",
      "value": "Microsoft Corporation"
    },
    {
      "name": "enabled",
      "value": "Enabled"
    },
    {
      "name": "hidden",
      "value": "false"
    }
  ]
}
```

## sigcheck / sigcheck -vt (2)

### EX-SIGCHECK-1 — sigcheck file inventory

<!-- covers: SEC-B sigcheck; Path→file.path, Publisher→executable.product INFERRED; signature status Unsigned -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "executable",
    "type": "executable_inventory",
    "action": "inventory",
    "outcome": "success",
    "severity": "informational",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": "2026-10-09T14:00:00Z",
    "original": "2026-10-09T14:00:00Z",
    "original_timezone": "Z",
    "timezone_source": "source_explicit",
    "precision": "second",
    "state": "inferred"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "sigcheck-001",
    "format": "csv",
    "parser": "sigcheck-parser",
    "parser_version": "1.0.0"
  },
  "raw": "\"Path\",\"Time\",\"Company\",\"Product\",\"Description\",\"Version\",\"MD5\",\"SHA1\",\"SHA-256\",\"PESHA1\",\"PESHA256\",\"PEMD5\",\"ImpHash\",\"Verified Signer\",\"Signer Certificate\",\"Status\",\"Signing Date\",\"Counter Signers\",\"Counter Signer Certificate\",\"Counter Signer Status\",\"Description URL\"\r\n\"C:\\Temp\\evil.exe\",\"2026-10-09 14:00:00\",\"(n/a)\",\"(n/a)\",\"(n/a)\",\"1.0.0.0\",\"aa11\",\"bb22\",\"cc33\",\"dd44\",\"ee55\",\"ff66\",\"11223344\",\"(n/a)\",\"(n/a)\",\"Unsigned\",\"\",\"\",\"\",\"\",\"\"\r\n",
  "executable": {
    "path": "C:\\Temp\\evil.exe",
    "format": "pe",
    "file_version": "1.0.0.0",
    "product": {
      "$state": "null",
      "$raw": "(n/a)"
    },
    "hashes": {
      "md5": "aa11",
      "sha1": "bb22",
      "sha256": "cc33"
    },
    "signature": {
      "signed": false,
      "status": "Unsigned",
      "signer": {
        "$state": "null",
        "$raw": "(n/a)"
      }
    }
  }
}
```

### EX-SIGCHECK-VT — sigcheck -vt VirusTotal result

<!-- covers: SEC-B sigcheck -vt; VT detection→artifact_finding derived_by sentinel; extra example beyond brief's tool list -->
<!-- labels: VERIFIED -->

```json
{
  "schema_version": "canonical-event/v1",
  "event": {
    "category": "artifact_finding",
    "type": "virustotal_detection",
    "action": "scan",
    "outcome": "success",
    "severity": "low",
    "derived_by": "sentinel"
  },
  "tenant_id": "tenant-demo",
  "workspace_id": "ws-demo",
  "run_id": "run-2026-10-09-001",
  "time": {
    "utc": null,
    "timezone_source": "none",
    "precision": "unknown",
    "state": "unknown"
  },
  "host": {},
  "user": {},
  "source": {
    "file_id": "sigcheck-vt-001",
    "format": "csv",
    "parser": "sigcheck-vt-parser",
    "parser_version": "1.0.0"
  },
  "raw": "\"Path\",\"MD5\",\"SHA-1\",\"SHA-256\",\"VT Detection\",\"VT URL\",\"Verified Signer\",\"Status\"\r\n\"C:\\Temp\\evil.exe\",\"aa11\",\"bb22\",\"cc33\",\"12/72\",\"https://www.virustotal.com/gui/file/cc33\",\"(n/a)\",\"Unsigned\"\r\n",
  "artifact_finding": {
    "artifact_type": "file",
    "artifact_identity": "C:\\Temp\\evil.exe",
    "finding": {
      "$state": "inferred",
      "$note": "VT Detection column ratio",
      "$raw": "12/72"
    },
    "evidence": {
      "$state": "inferred",
      "$raw": "https://www.virustotal.com/gui/file/cc33"
    },
    "scanner": "VirusTotal",
    "confidence": {
      "$state": "inferred",
      "$note": "12/72 engines",
      "$raw": "low"
    }
  }
}
```

## Example coverage matrix

| Group | Count | IDs |
|---|---|---|
| Sysmon (Microsoft-Windows-Sysmon/Operational) | 30 | EX-SYSMON-1, EX-SYSMON-2, EX-SYSMON-3, EX-SYSMON-4, EX-SYSMON-5, EX-SYSMON-6, EX-SYSMON-7, EX-SYSMON-8, EX-SYSMON-9, EX-SYSMON-10, EX-SYSMON-11, EX-SYSMON-12, EX-SYSMON-13, EX-SYSMON-14, EX-SYSMON-15, EX-SYSMON-16, EX-SYSMON-17, EX-SYSMON-18, EX-SYSMON-19, EX-SYSMON-20, EX-SYSMON-21, EX-SYSMON-22, EX-SYSMON-23, EX-SYSMON-24, EX-SYSMON-25, EX-SYSMON-26, EX-SYSMON-27, EX-SYSMON-28, EX-SYSMON-29, EX-SYSMON-255 |
| Windows Security channel | 32 | EX-SEC-1102, EX-SEC-4624, EX-SEC-4625, EX-SEC-4634, EX-SEC-4647, EX-SEC-4648, EX-SEC-4672, EX-SEC-4688, EX-SEC-4689, EX-SEC-4697, EX-SEC-4698, EX-SEC-4720, EX-SEC-4722, EX-SEC-4724, EX-SEC-4726, EX-SEC-4728, EX-SEC-4732, EX-SEC-4738, EX-SEC-4740, EX-SEC-4756, EX-SEC-4767, EX-SEC-4768, EX-SEC-4769, EX-SEC-4771, EX-SEC-4776, EX-SEC-5140, EX-SEC-5145, EX-SEC-5156, EX-SEC-5158, EX-SEC-4946, EX-SEC-4947, EX-SEC-4948 |
| Other Windows channels (System, PowerShell, WMI, Defender, TaskScheduler, LSM, RCM, AppLocker) | 37 | EX-WIN-7034, EX-WIN-7036, EX-WIN-7040, EX-WIN-7043, EX-WIN-7045, EX-WIN-104, EX-WIN-PS400, EX-WIN-PS403, EX-WIN-PS600, EX-WIN-PS800, EX-WIN-PS4103, EX-WIN-PS4104, EX-WIN-PS4105, EX-WIN-PS4106, EX-WIN-WMI5857, EX-WIN-WMI5858, EX-WIN-WMI5860, EX-WIN-DEF1116, EX-WIN-DEF1117, EX-WIN-DEF5001, EX-WIN-DEF5007, EX-WIN-TS106, EX-WIN-TS140, EX-WIN-TS141, EX-WIN-TS200, EX-WIN-TS201, EX-WIN-LSM21, EX-WIN-LSM22, EX-WIN-LSM23, EX-WIN-LSM24, EX-WIN-LSM25, EX-WIN-LSM39, EX-WIN-RCM1149, EX-WIN-AL8003, EX-WIN-AL8004, EX-WIN-AL8006, EX-WIN-AL8007 |
| Zeek JSON logs | 6 | EX-ZEEK-CONN, EX-ZEEK-DNS, EX-ZEEK-HTTP, EX-ZEEK-SSL, EX-ZEEK-NOTICE, EX-ZEEK-FILES |
| Suricata EVE JSON | 6 | EX-EVE-ALERT, EX-EVE-HTTP, EX-EVE-DNS, EX-EVE-TLS, EX-EVE-FLOW, EX-EVE-FILEINFO |
| Nmap XML export | 1 | EX-NMAP-1 |
| netstat snapshot | 1 | EX-NETSTAT-1 |
| schtasks /query snapshot | 1 | EX-SCHTASKS-1 |
| sc query snapshot | 1 | EX-SCQUERY-1 |
| sc qc snapshot | 1 | EX-SCQC-1 |
| reg export .reg snapshot | 1 | EX-REGEXPORT-1 |
| PowerShell Export-Csv inventory | 1 | EX-EXPORTCSV-1 |
| autorunsc autostart inventory | 1 | EX-AUTORUNS-1 |
| sigcheck / sigcheck -vt | 2 | EX-SIGCHECK-1, EX-SIGCHECK-VT |

Total examples: 121

Schema categories with no example in this corpus (gaps, documented in
the handoff): `document`, `archive_member` — no harvested source maps to
them yet.

<!-- END SEC-C -->
