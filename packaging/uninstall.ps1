<#
.SYNOPSIS
  Remove Sentinel Windows services (dev installer counterpart).
#>
[CmdletBinding()]
param(
    [string]$NssmDir = "$env:ProgramFiles\nssm"
)
$ErrorActionPreference = "Stop"

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "uninstall.ps1 must run elevated."
}

$nssm = Join-Path $NssmDir "nssm.exe"
if (-not (Test-Path $nssm)) { throw "nssm.exe not found at $nssm" }

foreach ($name in @("sentinel-worker", "sentinel-api")) {
    $status = & $nssm status $name 2>$null
    if ($status) {
        & $nssm stop $name 2>$null | Out-Null
        & $nssm remove $name confirm | Out-Null
        Write-Host "service $name removed."
    } else {
        Write-Host "service $name not present."
    }
}
Write-Host "done. (Database and files were not touched.)"
