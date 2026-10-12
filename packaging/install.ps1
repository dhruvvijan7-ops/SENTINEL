<#
.SYNOPSIS
  Sentinel Light HIDS - Windows dev installer (Milestone 1).

.DESCRIPTION
  Creates the two Windows services mandated by Stage-6 Section 9 / Section 7.2:
    - sentinel-api    : uvicorn app (sentinel_api.main)
    - sentinel-worker : job worker  (sentinel_worker.main)
  wrapped by WinSW (D6-004: MIT, VERIFIED LICENSE). The alternative wrapper
  rejected by D6-004 is deliberately not used: its licence is UNVERIFIED
  (OQ-6-09), so WinSW is the only wrapper allowed in this repository.

  Steps, in order:
    1. resolve + sha256-verify WinSW-x64.exe
    2. optionally provision PostgreSQL and the three roles (-ProvisionDatabase)
    3. apply migrations with the migrator role
    4. render the WinSW XML templates, install both services, start them
    5. assert both services report Running and GET /health answers 200

  This is the dev/single-node installer; a signed Inno Setup MSI and Group
  Policy deployment are M4. packaging/drill.ps1 drives this script as the
  M1 exit 5 clean-VM drill.

.EXAMPLE
  .\packaging\install.ps1 -Python "C:\path\to\.venv\Scripts\python.exe" `
      -Config "C:\path\to\configs\sentinel.toml" -ProvisionDatabase
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Python,

    [Parameter(Mandatory = $true)]
    [string]$Config,

    [string]$InstallRoot = "$env:ProgramFiles\Sentinel",

    # Pre-downloaded WinSW binary; when absent the pinned release is fetched.
    [string]$WinSwExe = "",

    [string]$WinSwUrl =
        "https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe",
    [string]$WinSwSha256 =
        "05b82d46ad331cc16bdc00de5c6332c1ef818df8ceefcd49c726553209b3a0da",

    # PostgreSQL bootstrap (Stage-6 Section 7.2: the installer creates the roles).
    [switch]$ProvisionDatabase,
    [string]$PsqlPath = "psql",
    [string]$PostgresPassword = "",
    [string]$DatabaseHost = "127.0.0.1",
    [int]$DatabasePort = 54321,
    [string]$DatabaseName = "sentinel",
    [string]$PostgresSuperuser = "postgres",

    [switch]$Force
)

$ErrorActionPreference = "Stop"

$Services = @(
    @{ Name = "sentinel-api";    App = $Python; Arguments = "-m sentinel_api.main";    Template = "sentinel-api.xml" },
    @{ Name = "sentinel-worker"; App = $Python; Arguments = "-m sentinel_worker.main"; Template = "sentinel-worker.xml" }
)

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$id
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "install.ps1 must run elevated (services + Program Files writes)."
    }
}

function Get-ServerPort([string]$Path) {
    $inServer = $false
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        if ($line -match '^\s*\[') { $inServer = ($line -match '^\s*\[server\]'); continue }
        if ($inServer -and $line -match '^\s*port\s*=\s*(\d+)') { return [int]$Matches[1] }
    }
    return 8000
}

function Get-WinSw([string]$Cache) {
    if ($WinSwExe) {
        if (-not (Test-Path -LiteralPath $WinSwExe)) { throw "WinSW not found: $WinSwExe" }
        return (Resolve-Path -LiteralPath $WinSwExe).Path
    }
    New-Item -ItemType Directory -Force -Path (Split-Path $Cache) | Out-Null
    if (-not (Test-Path -LiteralPath $Cache)) {
        Write-Host "downloading WinSW (D6-004, MIT)..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $WinSwUrl -OutFile $Cache -UseBasicParsing
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Cache).Hash.ToLower()
    if ($actual -ne $WinSwSha256.ToLower()) {
        Remove-Item -LiteralPath $Cache -Force
        throw "WinSW sha256 mismatch: expected $WinSwSha256, got $actual"
    }
    Write-Host "WinSW sha256 verified ($actual)."
    return (Resolve-Path -LiteralPath $Cache).Path
}

function Provision-Roles {
    $rolesSql = Join-Path $PSScriptRoot "docker-init\00-roles.sql"
    if (-not (Test-Path -LiteralPath $rolesSql)) { throw "roles script missing: $rolesSql" }
    $psql = Get-Command $PsqlPath -ErrorAction SilentlyContinue
    if (-not $psql) {
        throw ("psql not found ('$PsqlPath'). Install the PostgreSQL 18 client, " +
               "or pass -PsqlPath, or re-run without -ProvisionDatabase.")
    }
    if ($PostgresPassword) { $env:PGPASSWORD = $PostgresPassword }
    & $psql.Source -h $DatabaseHost -p $DatabasePort -U $PostgresSuperuser -d $DatabaseName `
        -v ON_ERROR_STOP=1 -w -f $rolesSql
    if ($LASTEXITCODE -ne 0) { throw "role provisioning failed (exit $LASTEXITCODE)" }
    Write-Host "roles provisioned (sentinel_app / sentinel_migrator / sentinel_worker)."
}

function Render-ServiceConfig([hashtable]$Service, [string]$TemplateDir, [string]$BinDir,
                              [string]$LogDir) {
    $templatePath = Join-Path $TemplateDir $Service.Template
    if (-not (Test-Path -LiteralPath $templatePath)) { throw "template missing: $templatePath" }
    $xml = Get-Content -LiteralPath $templatePath -Raw
    $xml = $xml.Replace("{{PYTHON}}", $Service.App)
    $xml = $xml.Replace("{{INSTALL_ROOT}}", $InstallRoot)
    $xml = $xml.Replace("{{CONFIG}}", $Config)
    $xml = $xml.Replace("{{LOG_DIR}}", $LogDir)
    if ($xml -match '\{\{[A-Z_]+\}\}') { throw "unrendered token in $($Service.Template)" }
    $rendered = Join-Path $BinDir ($Service.Name + ".xml")
    [IO.File]::WriteAllText($rendered, $xml, (New-Object Text.UTF8Encoding($false)))
    return $rendered
}

function Assert-ServiceRunning([string]$Name) {
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { throw "service '$Name' was not created." }
    if ($svc.Status -ne "Running") {
        throw "service '$Name' is '$($svc.Status)', expected 'Running'."
    }
    Write-Host "service $Name : Running"
}

function Assert-Health([string]$Url) {
    $deadline = (Get-Date).AddSeconds(60)
    $lastError = ""
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
            if ($resp.StatusCode -eq 200) { Write-Host "GET $Url -> 200"; return }
            $lastError = "HTTP $($resp.StatusCode)"
        } catch { $lastError = $_.Exception.Message }
        Start-Sleep -Seconds 2
    }
    throw "health probe never returned 200 ($Url): $lastError"
}

# --- preconditions ---------------------------------------------------------
Assert-Admin
if (-not (Test-Path -LiteralPath $Python)) { throw "Python interpreter not found: $Python" }
if (-not (Test-Path -LiteralPath $Config)) { throw "Config not found: $Config" }

$BinDir = Join-Path $InstallRoot "bin"
$LogDir = Join-Path $InstallRoot "logs"
$Cache = Join-Path $env:LOCALAPPDATA "Sentinel\WinSW-x64.exe"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# --- WinSW (D6-004) --------------------------------------------------------
$winsw = Get-WinSw $Cache

# --- database / roles (Stage-6 Section 7.2) --------------------------------------
if ($ProvisionDatabase) { Provision-Roles }

Write-Host "applying migrations (migrator role)..."
$env:SENTINEL_CONFIG = $Config
& $Python -m migrations.apply
if ($LASTEXITCODE -ne 0) { throw "migration failed (exit $LASTEXITCODE)" }

# --- services --------------------------------------------------------------
foreach ($svc in $Services) {
    $exeTarget = Join-Path $BinDir ($svc.Name + ".exe")
    Copy-Item -LiteralPath $winsw -Destination $exeTarget -Force
    $null = Render-ServiceConfig $svc (Join-Path $PSScriptRoot "winsw") $BinDir $LogDir

    $existing = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($existing) {
        if (-not $Force) {
            Write-Warning "$($svc.Name) already exists; use -Force to replace it."
            continue
        }
        & $exeTarget uninstall | Out-Null
        Start-Sleep -Seconds 2
    }

    & $exeTarget install
    if ($LASTEXITCODE -ne 0) { throw "WinSW install failed for $($svc.Name)" }
    & $exeTarget start
    if ($LASTEXITCODE -ne 0) { throw "WinSW start failed for $($svc.Name)" }
    Write-Host "service $($svc.Name) installed and started."
}

# --- exit-5 assertions -----------------------------------------------------
foreach ($svc in $Services) { Assert-ServiceRunning $svc.Name }

$port = Get-ServerPort $Config
$health = "http://127.0.0.1:$port/health"
Assert-Health $health

Write-Host ""
Write-Host "install complete. VERIFIED on this host: both services Running, GET $health -> 200."
Write-Host "  install root : $InstallRoot"
Write-Host "  config       : $Config"
Write-Host "  logs         : $LogDir"
Write-Host "  uninstall    : .\packaging\uninstall.ps1"
