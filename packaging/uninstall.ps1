<#
.SNOPSIS
  Remove Sentinel Windows services (dev installer counterpart).

.DESCRIPTION
  Unregisters the two WinSW-wrapped services created by packaging/install.ps1
  (D6-004: WinSW only - the alternative wrapper's licence is UNVERIFIED,
  OQ-6-09) and optionally removes the install root.
  The database and its data are never touched.
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = "$env:ProgramFiles\Sentinel",
    [switch]$PurgeFiles
)
$ErrorActionPreference = "Stop"

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "uninstall.ps1 must run elevated."
}

function Invoke-WinSw([string]$Exe, [string]$Verb) {
    $global:LASTEXITCODE = 0
    try { & $Exe $Verb | Out-Null } catch { }
    return $global:LASTEXITCODE
}

foreach ($name in @("sentinel-worker", "sentinel-api")) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Host "service $name not present."
        continue
    }
    $exe = Join-Path (Join-Path $InstallRoot "bin") ($name + ".exe")
    if (Test-Path -LiteralPath $exe) {
        $null = Invoke-WinSw $exe "stop"
        Start-Sleep -Seconds 2
        $null = Invoke-WinSw $exe "uninstall"
    } else {
        & sc.exe stop $name | Out-Null
        Start-Sleep -Seconds 2
        & sc.exe delete $name | Out-Null
    }
    Start-Sleep -Seconds 1
    if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
        throw "service $name could not be removed."
    }
    Write-Host "service $name removed."
}

if ($PurgeFiles -and (Test-Path -LiteralPath $InstallRoot)) {
    Remove-Item -LiteralPath $InstallRoot -Recurse -Force
    Write-Host "removed $InstallRoot."
}

Write-Host "done. (Database and its data were not touched.)"
