<#
.SYNOPSIS
  Sentinel Light HIDS — Windows dev installer (Milestone 1).

.DESCRIPTION
  Creates the two Windows services mandated by Stage-6 §9:
    - sentinel-api    : uvicorn app (sentinel_api.main)
    - sentinel-worker : job worker  (sentinel_worker.main)
  via NSSM (Non-Sucking Service Manager).  This is the dev/single-node
  installer; a signed MSI and Group Policy deployment are post-M1.

.EXAMPLE
  .\packaging\install.ps1 -Python "C:\path\to\.venv\Scripts\python.exe" `
      -Config "C:\path\to\configs\config.toml"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Python,

    [Parameter(Mandatory = $true)]
    [string]$Config,

    [string]$NssmDir = "$env:ProgramFiles\nssm",
    [string]$InstallRoot = "$env:ProgramFiles\Sentinel",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$id
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "install.ps1 must run elevated (services + Program Files writes)."
    }
}
Assert-Admin

if (-not (Test-Path $Python)) { throw "Python interpreter not found: $Python" }
if (-not (Test-Path $Config)) { throw "Config not found: $Config" }

# --- NSSM ------------------------------------------------------------------
$nssm = Join-Path $NssmDir "nssm.exe"
if (-not (Test-Path $nssm)) {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        Write-Host "installing NSSM via winget..."
        winget install --id NSSM --exact --accept-source-agreements --accept-package-agreements
    }
    if (-not (Test-Path $nssm)) {
        throw "nssm.exe not found at $nssm. Install NSSM (https://nssm.cc) and re-run."
    }
}

New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
$logDir = Join-Path $InstallRoot "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

# --- Roles / migration ----------------------------------------------------
Write-Host "applying migrations (migrator role)..."
$env:SENTINEL_CONFIG = $Config
& $Python -m migrations.apply
if ($LASTEXITCODE -ne 0) { throw "migration failed (exit $LASTEXITCODE)" }

# --- Services --------------------------------------------------------------
$services = @(
    @{ Name = "sentinel-api";    App = $Python; Arguments = "-m sentinel_api.main" },
    @{ Name = "sentinel-worker"; App = $Python; Arguments = "-m sentinel_worker.main" }
)

foreach ($svc in $services) {
    $existing = & $nssm status $svc.Name 2>$null
    if ($existing) {
        if (-not $Force) {
            Write-Warning "$($svc.Name) already exists; use -Force to replace."
            continue
        }
        & $nssm stop $svc.Name | Out-Null
        & $nssm remove $svc.Name confirm | Out-Null
    }

    & $nssm install $svc.Name $svc.App $svc.Arguments
    & $nssm set $svc.Name AppDirectory (Get-Location).Path
    & $nssm set $svc.Name AppEnvironmentExtra "SENTINEL_CONFIG=$Config"
    & $nssm set $svc.Name Start SERVICE_AUTO_START
    & $nssm set $svc.Name AppStdout (Join-Path $logDir "$($svc.Name).out.log")
    & $nssm set $svc.Name AppStderr (Join-Path $logDir "$($svc.Name).err.log")
    & $nssm set $svc.Name AppRotateFiles 1
    & $nssm set $svc.Name AppRotateOnline 1
    & $nssm set $svc.Name AppRotateBytes 10485760
    & $nssm set $svc.Name AppExit Default Restart
    & $nssm set $svc.Name AppRestartDelay 5000
    & $nssm start $svc.Name
    Write-Host "service $($svc.Name) installed and started."
}

Write-Host "`ninstall complete."
Write-Host "  api    : http://127.0.0.1:8080/health   (bind from config [api])"
Write-Host "  logs   : $logDir"
Write-Host "  uninstall: .\packaging\uninstall.ps1"
