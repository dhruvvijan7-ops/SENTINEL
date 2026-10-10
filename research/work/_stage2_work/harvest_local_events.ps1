# Stage 2 evidence harvest: exact EventData field names from local Windows event logs.
# Method: Get-WinEvent -> record.ToXml() -> extract <Data Name="..."> attribute names.
# Output: _stage2_work\local_eventfields.json
$ErrorActionPreference = 'SilentlyContinue'
$outDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$targets = @(
  @{ log = 'System'; ids = @(104, 7034, 7036, 7040, 7043, 7045) },
  @{ log = 'Windows PowerShell'; ids = @(400, 403, 600, 800) },
  @{ log = 'Microsoft-Windows-PowerShell/Operational'; ids = @(4103, 4104, 4105, 4106) },
  @{ log = 'Microsoft-Windows-Windows Defender/Operational'; ids = @(1006, 1007, 1008, 1009, 1010, 1011, 1012, 1116, 1117, 1118, 1119, 5001, 5007, 5012) },
  @{ log = 'Microsoft-Windows-WMI-Activity/Operational'; ids = @(5857, 5858, 5859, 5860, 5861) },
  @{ log = 'Microsoft-Windows-TaskScheduler/Operational'; ids = @(106, 140, 141, 200, 201, 102, 129, 329) },
  @{ log = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; ids = @(21, 22, 23, 24, 25, 39) },
  @{ log = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; ids = @(1149, 1150) },
  @{ log = 'Security'; ids = @(1102, 4624, 4625, 4634, 4648, 4672, 4688, 4720, 4732, 4768) },
  @{ log = 'Microsoft-Windows-Sysmon/Operational'; ids = @(1, 3, 11, 22) },
  @{ log = 'Microsoft-Windows-AppLocker/EXE and DLL'; ids = @(8003, 8004) }
)

$os = Get-CimInstance Win32_OperatingSystem
$elev = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$result = [ordered]@{
  method        = 'Get-WinEvent -FilterHashtable; EventRecord.ToXml(); regex <Data Name="...">'
  harvested_on  = (Get-Date).ToString('o')
  os_caption    = $os.Caption
  os_build      = $os.BuildNumber
  elevated      = $elev
  logs          = @()
}

foreach ($t in $targets) {
  $logEntry = [ordered]@{ log = $t.log; log_exists = $false; log_error = $null; events = @() }
  try {
    $cfg = Get-WinEvent -ListLog $t.log -ErrorAction Stop
    $logEntry.log_exists = $true
    $logEntry.log_recordcount = $cfg.RecordCount
    $logEntry.log_is_enabled = $cfg.IsEnabled
  } catch {
    $logEntry.log_error = $_.Exception.Message
  }
  if ($logEntry.log_exists) {
    foreach ($id in $t.ids) {
      $ev = [ordered]@{ id = $id; found = $false; field_names = @(); sample_xml = $null; error = $null }
      try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $t.log; Id = $id } -MaxEvents 2 -ErrorAction Stop
        $e = $events[0]
        $xml = $e.ToXml()
        $names = [regex]::Matches($xml, '<Data Name="([^"]+)"') | ForEach-Object { $_.Groups[1].Value }
        $ev.found = $true
        $ev.field_names = @($names | Select-Object -Unique)
        $ev.time_created = $e.TimeCreated.ToString('o')
        $ev.provider = $e.ProviderName
        $ev.count_queried = -1
        $ev.sample_xml = $xml
      } catch {
        $ev.error = $_.Exception.Message
      }
      $logEntry.events += $ev
    }
  }
  $result.logs += $logEntry
}

$json = $result | ConvertTo-Json -Depth 8
Set-Content -LiteralPath (Join-Path $outDir 'local_eventfields.json') -Value $json -Encoding UTF8
Write-Output "wrote $(Join-Path $outDir 'local_eventfields.json') size=$($json.Length)"
# summary
foreach ($l in $result.logs) {
  $found = ($l.events | Where-Object { $_.found }) | ForEach-Object { $_.id }
  Write-Output ("{0} | exists={1} | found_ids: {2}" -f $l.log, $l.log_exists, ($found -join ','))
}
