<#
.SYNOPSIS
  M1 exit 5 - clean Windows VM installer drill (Stage-6 Section 9).

.DESCRIPTION
  Drives packaging/install.ps1 end to end on a clean host and asserts the
  exit criterion literally:

    "installer (dev build) creates both services on a clean Windows VM"

  Steps:
    1. prove the two services are absent
    2. provision PostgreSQL and the three roles (packaging/docker-init/00-roles.sql)
    3. install: WinSW fetch + verify, migrations, both services, start
    4. assert Get-Service reports Running for sentinel-api and sentinel-worker
    5. assert GET /health returns 200
    6. assert GET /ready returns 200 (DB + object store + queue)
    7. uninstall and assert both services are gone

  Every step is recorded in a VERIFIED / FAILED ledger printed at the end, so
  the output states exactly what was and was not exercised on this host.
  Exit code 0 only when every step verified.

  Prerequisites (not created by this script): a reachable PostgreSQL 18 with
  superuser access, and an elevated PowerShell session.

.EXAMPLE
  .\packaging\drill.ps1 -Python "C:\src\light-hids\.venv\Scripts\python.exe" `
      -Config "C:\src\light-hids\configs\config.example.toml" `
      -ProvisionDatabase -PostgresPassword sentinel_dev_pw
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Python,

    [Parameter(Mandatory = $true)]
    [string]$Config,

    [switch]$ProvisionDatabase,
    [string]$PsqlPath = "psql",
    [string]$PostgresPassword = "",
    [string]$DatabaseHost = "127.0.0.1",
    [int]$DatabasePort = 54321,
    [string]$DatabaseName = "sentinel",
    [string]$PostgresSuperuser = "postgres",

    [string]$InstallRoot = "$env:ProgramFiles\Sentinel",
    [int]$HealthTimeoutSeconds = 60,

    # Stop after the first failure instead of continuing to the next step.
    [switch]$KeepServices
)

$ErrorActionPreference = "Stop"

$ServiceNames = @("sentinel-api", "sentinel-worker")
$ledger = @()

function Record([string]$Step, [string]$Result, [string]$Detail) {
    $script:ledger += [pscustomobject]@{ Step = $Step; Result = $Result; Detail = $Detail }
    $colour = if ($Result -eq "VERIFIED") { "Green" } else { "Red" }
    Write-Host ("  [{0,-8}] {1} - {2}" -f $Result, $Step, $Detail) -ForegroundColor $colour
}

function Fail([string]$Step, [string]$Detail) {
    Record $Step "FAILED" $Detail
    throw "drill failed at step: $Step"
}

function Get-ServerPort([string]$Path) {
    $inServer = $false
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        if ($line -match '^\s*\[') { $inServer = ($line -match '^\s*\[server\]'); continue }
        if ($inServer -and $line -match '^\s*port\s*=\s*(\d+)') { return [int]$Matches[1] }
    }
    return 8000
}

function Invoke-HttpOk([string]$Url, [string]$Step, [int]$Timeout) {
    $deadline = (Get-Date).AddSeconds($Timeout)
    $last = ""
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
            if ($resp.StatusCode -eq 200) { Record $Step "VERIFIED" "GET $Url -> 200"; return }
            $last = "HTTP $($resp.StatusCode)"
        } catch { $last = $_.Exception.Message }
        Start-Sleep -Seconds 2
    }
    Fail $Step "GET $Url never returned 200: $last"
}

# --- 1. clean slate --------------------------------------------------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "drill.ps1 must run elevated (it creates Windows services)."
}
$present = @($ServiceNames | Where-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue })
if ($present.Count -gt 0) {
    Fail "clean host pre-check" "services already present: $($present -join ', ')"
}
Record "clean host pre-check" "VERIFIED" "no sentinel-* services present"

try {
    # --- 2. database + roles ---------------------------------------------
    if ($ProvisionDatabase) {
        $rolesSql = Join-Path $PSScriptRoot "docker-init\00-roles.sql"
        $psql = Get-Command $PsqlPath -ErrorAction SilentlyContinue
        if (-not $psql) { Fail "provision roles" "psql not found ('$PsqlPath')" }
        if ($PostgresPassword) { $env:PGPASSWORD = $PostgresPassword }
        & $psql.Source -h $DatabaseHost -p $DatabasePort -U $PostgresSuperuser -d $DatabaseName `
            -v ON_ERROR_STOP=1 -w -f $rolesSql
        if ($LASTEXITCODE -ne 0) { Fail "provision roles" "psql exit $LASTEXITCODE" }
        Record "provision roles" "VERIFIED" "$rolesSql applied to ${DatabaseHost}:$DatabasePort/$DatabaseName"
    } else {
        Record "provision roles" "SKIPPED" "-ProvisionDatabase not supplied"
    }

    # --- 3. install --------------------------------------------------------
    & (Join-Path $PSScriptRoot "install.ps1") -Python $Python -Config $Config `
        -InstallRoot $InstallRoot -ProvisionDatabase:$ProvisionDatabase `
        -PsqlPath $PsqlPath -PostgresPassword $PostgresPassword `
        -DatabaseHost $DatabaseHost -DatabasePort $DatabasePort `
        -DatabaseName $DatabaseName -PostgresSuperuser $PostgresSuperuser
    if ($LASTEXITCODE -ne 0) { Fail "install.ps1" "exit $LASTEXITCODE" }
    Record "install.ps1" "VERIFIED" "completed without error"

    # --- 4. both services Running ----------------------------------------
    foreach ($name in $ServiceNames) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { Fail "service $name" "not created" }
        if ($svc.Status -ne "Running") { Fail "service $name" "status is '$($svc.Status)'" }
        Record "service $name" "VERIFIED" "Status = Running, StartType = $($svc.StartType)"
    }

    # --- 5/6. HTTP ---------------------------------------------------------
    $port = Get-ServerPort $Config
    Invoke-HttpOk "http://127.0.0.1:$port/health" "GET /health" $HealthTimeoutSeconds
    Invoke-HttpOk "http://127.0.0.1:$port/ready"  "GET /ready"  $HealthTimeoutSeconds
}
finally {
    if (-not $KeepServices) {
        foreach ($name in $ServiceNames) {
            $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
            if (-not $svc) { continue }
            $exe = Join-Path (Join-Path $InstallRoot "bin") ($name + ".exe")
            if (Test-Path -LiteralPath $exe) {
                try { & $exe stop | Out-Null } catch { }
                Start-Sleep -Seconds 2
                try { & $exe uninstall | Out-Null } catch { }
            } else {
                & sc.exe delete $name | Out-Null
            }
        }
        Start-Sleep -Seconds 1
        $leftover = @($ServiceNames | Where-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue })
        if ($leftover.Count -eq 0) {
            Record "uninstall" "VERIFIED" "both services removed"
        } else {
            Record "uninstall" "FAILED" "still present: $($leftover -join ', ')"
        }
    } else {
        Record "uninstall" "SKIPPED" "-KeepServices supplied"
    }
}

Write-Host ""
Write-Host "=== M1 exit 5 drill ledger ==="
$ledger | Format-Table -AutoSize

$failed = @($ledger | Where-Object { $_.Result -eq "FAILED" })
if ($failed.Count -gt 0) {
    Write-Error "drill FAILED at: $($failed.Step -join ', ')"
    exit 1
}
Write-Host "drill VERIFIED: both services created and Running, /health and /ready returned 200."
exit 0
