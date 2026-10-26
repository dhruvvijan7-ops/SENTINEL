# Sentinel demo set (`UNS DEMO SET`)

`UNS DEMO SET.evtx` (repo root) is a 30-event Sysmon EID 1 corpus built to
exercise the pinned 112-rule SigmaHQ process-creation pack. On a workspace with
that pack imported it produces **67 findings across 36 distinct rule names**.

## Important

* Use the `master` branch. The GitHub `main` branch is an older, unrelated
  project and does not contain this file.
* This is **not** `tests/planted/sysmon_planted.evtx`. The planted fixture is a
  single-rule M2 test (`tests/planted/pack.json`) and yields only
  `WhoAmI as Parameter`.
* Import the full 112-rule pack from `configs/rule_pack.json` before running.
  The pack's Sigma YAML sources live outside this repo (gitignored upstream
  checkout), so import them from your local project copy first.

## Files

| File | Purpose |
|---|---|
| `../UNS DEMO SET.evtx` | 30 Sysmon process-creation events (this demo) |
| `rules/demo_whoami.yml` | Extra Sigma demo rule matching `whoami` |
| `ioc/demo-intel.pack.json` | Signed Ed25519 IOC pack (3 indicators) |
| `ioc/demo-intel.rule.json` | IOC rule pinned to the pack digest |
| `ioc/trusted_keys.demo.json` | Public key for the demo pack |
| `ioc/demo-intel.unsigned.json` | Unsigned pack for the rejection path |
| `runs/detect-demo.json` | Example detection-run body |

## Run

```powershell
$Api = "http://127.0.0.1:8090"
$Ws  = "ws-b"
$H   = @{ "X-API-Key" = "dev-key-tenantb-0000000000000002" }

# Upload the EVTX, then wait for triage_state=done.
curl.exe -s -X POST "$Api/v1/workspaces/$Ws/uploads" `
  -H "X-API-Key: $($H['X-API-Key'])" `
  -F "file=@UNS DEMO SET.evtx;type=application/octet-stream"

# Optional IOC demo: trust the demo key, import the pack and its rule.
Copy-Item .\demo\ioc\trusted_keys.demo.json .\configs\ioc_trusted_keys.json -Force
Invoke-RestMethod -Method Post -Uri "$Api/v1/workspaces/$Ws/ioc-packs" `
  -Headers $H -ContentType "application/json" `
  -Body (Get-Content .\demo\ioc\demo-intel.pack.json -Raw)
Invoke-RestMethod -Method Post -Uri "$Api/v1/workspaces/$Ws/rules" `
  -Headers $H -ContentType "application/json" `
  -Body (Get-Content .\demo\ioc\demo-intel.rule.json -Raw)

# Run every imported rule against the upload's run_id.
$upload = Invoke-RestMethod "$Api/v1/workspaces/$Ws/uploads?limit=1" -Headers $H
$body = @{ run_ids = @($upload.items[0].run_id) } | ConvertTo-Json
$run = Invoke-RestMethod -Method Post -Uri "$Api/v1/workspaces/$Ws/runs" `
  -Headers $H -ContentType "application/json" -Body $body

# Inspect distinct finding names.
Invoke-RestMethod "$Api/v1/workspaces/$Ws/findings?run_id=$($run.run_id)&limit=500" `
  -Headers $H | ForEach-Object { $_.items } |
  Group-Object rule_name | Sort-Object Name | Select-Object Count, Name
```

Expected: **36 distinct `rule_name` values** (34 from the Sigma pack, plus the
two demo rules if imported).
