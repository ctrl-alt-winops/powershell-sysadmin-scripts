<#
.SYNOPSIS
    Queries the event logs of a remote machine for a date/time window and
    produces an HTML report (saved to C:\temp on THIS machine, then opened).

.DESCRIPTION
    Prompts for mode, machine, date and time window. All queries run ON THE
    TARGET in a single WinRM session (Invoke-Command); only the formatted rows
    come back. The HTML report is built locally.

    Modes 1-3 (each mode is the previous one + more channels):
      [1] Simple    : Application, Security, Setup, System (Critical + Error + Warning)
      [2] Extended  : Simple + static channel list: Citrix, FSLogix, profile/SMB,
                      AppX/Teams, Office, session/logon, printing, Windows
                      platform (Critical + Error)
      [3] Full scan : Simple + ALL enabled, non-empty channels enumerated live on
                      the target (Critical + Error). Slow.
    Separate mode:
      [4] Security Audit Failures : Security log failed audits ONLY
                      (newest 100 in the window). Nothing else is queried.

    Audit Failure note: audit events are logged at Level 0 (Information) and are
    told apart by Keywords, so mode 4 filters on Keywords = Audit Failure
    (0x10000000000000), not on Level. Capped at the newest 100 because some
    audit categories (e.g. firewall 5152/5157) can produce thousands per hour.

.NOTES
    Execution : from an admin workstation, against a remote machine
    Requires  : WinRM enabled on the target, admin rights on the target
    Changes   : No - read only

    Requirements:
    - Admin rights on the target (Security log access) + WinRM enabled.
    - Writes the report to C:\temp on the machine running the script.

    Read-only on the target: nothing is changed there.
    The time window cannot cross midnight (single date + start/end time).
    One machine per run. Exit codes: 0 = report written or no events found,
    1 = aborted / failed.
#>

# Load System.Web for HTML encoding
Add-Type -AssemblyName System.Web

$AuditFailureCap = 100
$ScriptName      = if ($PSCommandPath) { Split-Path $PSCommandPath -Leaf } else { 'EventsViewer_REMOTE_html.ps1' }

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   Remote Event Log Query Tool" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# -----------------------------------------------------------------------------
# PRE-FLIGHT - Ensure C:\temp exists locally
# -----------------------------------------------------------------------------
if (-not (Test-Path "C:\temp")) {
    try {
        New-Item -ItemType Directory -Path "C:\temp" -Force | Out-Null
        Write-Host "Created output folder: C:\temp" -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR: Could not create C:\temp - $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Please create C:\temp manually or run PowerShell as Administrator." -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-Host "Output folder confirmed: C:\temp" -ForegroundColor Green
}
Write-Host ""

# -----------------------------------------------------------------------------
# SECTION 1 - MODE SELECTION
# -----------------------------------------------------------------------------
Write-Host "Select query mode:" -ForegroundColor Cyan
Write-Host "  [1] Simple          - Application, Security, Setup, System (Critical + Error + Warning)" -ForegroundColor White
Write-Host "  [2] Extended        - Simple + static channel list: Citrix, FSLogix, Windows, Office (Critical + Error)" -ForegroundColor White
Write-Host "  [3] Full Event Scan - Simple + ALL enabled, non-empty channels on the target (Critical + Error) - Slow" -ForegroundColor White
Write-Host "  [4] Security Audit Failures - Security log failed audits ONLY (newest $AuditFailureCap max)" -ForegroundColor White
Write-Host ""

do {
    $modeInput = Read-Host "Enter mode (1, 2, 3 or 4)"
} while ($modeInput -notin @("1", "2", "3", "4"))

$mode = [int]$modeInput
switch ($mode) {
    1 { $modeName = "Simple";                  $modeTag = "Simple" }
    2 { $modeName = "Extended";                $modeTag = "Extended" }
    3 { $modeName = "Full Event Scan - Slow";  $modeTag = "FullScan" }
    4 { $modeName = "Security Audit Failures"; $modeTag = "AuditFailures" }
}
Write-Host "Mode selected: $modeName" -ForegroundColor Green
if ($mode -eq 3) {
    Write-Host "WARNING : Full Scan can return a LOT of events. Please keep the time window to 10 minutes max." -ForegroundColor Red
}
Write-Host ""

# -----------------------------------------------------------------------------
# SECTION 2 - USER INPUT
# -----------------------------------------------------------------------------

$targetMachine = (Read-Host "Enter the remote machine name").Trim()
if ([string]::IsNullOrWhiteSpace($targetMachine)) {
    Write-Host "ERROR: No machine name provided. Exiting." -ForegroundColor Red
    exit 1
}

# --- DATE SELECTION ---
Write-Host ""
Write-Host "Select date:" -ForegroundColor Cyan
Write-Host "  [1] Today" -ForegroundColor White
Write-Host "  [2] Yesterday" -ForegroundColor White
Write-Host "  [3] Custom date" -ForegroundColor White
Write-Host ""

do {
    $dateChoice = Read-Host "Enter choice (1, 2, or 3)"
} while ($dateChoice -ne "1" -and $dateChoice -ne "2" -and $dateChoice -ne "3")

switch ($dateChoice) {
    "1" {
        $targetDate = (Get-Date).Date
        Write-Host "Date selected: Today ($($targetDate.ToString('yyyy-MM-dd')))" -ForegroundColor Green
    }
    "2" {
        $targetDate = (Get-Date).Date.AddDays(-1)
        Write-Host "Date selected: Yesterday ($($targetDate.ToString('yyyy-MM-dd')))" -ForegroundColor Green
    }
    "3" {
        do {
            $customDate = Read-Host "Enter date (yyyy-MM-dd, e.g. 2024-05-20)"
            try {
                $targetDate = [DateTime]::ParseExact($customDate, "yyyy-MM-dd", $null).Date
                $validDate = $true
                Write-Host "Date selected: $($targetDate.ToString('yyyy-MM-dd'))" -ForegroundColor Green
            }
            catch {
                Write-Host "Invalid date format. Please use yyyy-MM-dd" -ForegroundColor Yellow
                $validDate = $false
            }
        } while (-not $validDate)
    }
}

Write-Host ""

do {
    $startInput = Read-Host "Enter START time (HHmm, e.g. 0830)"
    $validStart = $startInput -match '^\d{4}$'
    if (-not $validStart) { Write-Host "Invalid format. Please use HHmm (e.g. 0830)" -ForegroundColor Yellow }
} while (-not $validStart)

do {
    $endInput = Read-Host "Enter END time (HHmm, e.g. 1700)"
    $validEnd = $endInput -match '^\d{4}$'
    if (-not $validEnd) { Write-Host "Invalid format. Please use HHmm (e.g. 1700)" -ForegroundColor Yellow }
} while (-not $validEnd)

$startDateTime = [DateTime]::ParseExact(("$($targetDate.ToString('yyyy-MM-dd')) $startInput"), "yyyy-MM-dd HHmm", $null)
$endDateTime   = [DateTime]::ParseExact(("$($targetDate.ToString('yyyy-MM-dd')) $endInput"),   "yyyy-MM-dd HHmm", $null)

if ($endDateTime -le $startDateTime) {
    Write-Host "ERROR: End time must be after start time. Exiting." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Query details:" -ForegroundColor Green
Write-Host "  Machine  : $targetMachine"
Write-Host "  Mode     : $modeName"
Write-Host "  Date     : $($targetDate.ToString('yyyy-MM-dd'))"
Write-Host "  From     : $startDateTime"
Write-Host "  To       : $endDateTime"
Write-Host ""

# -----------------------------------------------------------------------------
# SECTION 3 - REACHABILITY CHECK (WinRM - the transport used for all queries)
# -----------------------------------------------------------------------------

Write-Host "Checking WinRM on $targetMachine ..." -ForegroundColor Cyan
try {
    Test-WSMan -ComputerName $targetMachine -ErrorAction Stop | Out-Null
    Write-Host "WinRM reachable. Proceeding with log query..." -ForegroundColor Green
}
catch {
    Write-Host "ERROR: cannot reach '$targetMachine' via WinRM. Machine offline, hostname wrong, or PS Remoting not enabled." -ForegroundColor Red
    Write-Host "Details: $($_.Exception.Message)" -ForegroundColor DarkRed
    exit 1
}

# Query currently logged-in user on remote machine (via WinRM)
$loggedInUser = "Unknown"
try {
    $cimSession = New-CimSession -ComputerName $targetMachine -ErrorAction Stop
    $wmi = Get-CimInstance -CimSession $cimSession -ClassName Win32_ComputerSystem -ErrorAction Stop
    Remove-CimSession $cimSession
    if ($wmi.UserName) {
        $loggedInUser = $wmi.UserName
    } else {
        $loggedInUser = "No user logged in"
    }
    Write-Host "  Logged-in user: $loggedInUser" -ForegroundColor Cyan
}
catch {
    Write-Host "  Could not retrieve logged-in user: $($_.Exception.Message)" -ForegroundColor Yellow
}
Write-Host ""

# -----------------------------------------------------------------------------
# SECTION 4 - LOG SOURCE DEFINITIONS
# -----------------------------------------------------------------------------

# Severity levels (Windows event Level: 1=Critical, 2=Error, 3=Warning)
$classicLevels = @(1, 2, 3)   # classic logs, all modes
$channelLevels = @(1, 2)      # Extended / Full scan channels

# Classic logs - always included in all modes
$classicLogs = @(
    "Application",
    "Security",
    "Setup",
    "System"
)

# Static named channels - used by Extended mode [2] (and as Full scan fallback)
$staticChannels = @(
    # --- Citrix ---
    "Citrix-AppExperience-Seamless/Admin",
    "Citrix-AppExperience-Seamless/Operational",
    "Citrix-CDF-ErrorReporter/Admin",
    "Citrix-Device-Redirector/Admin",
    "Citrix-HostCore-HDX Direct/Admin",
    "Citrix-HostCore-HDX Direct/Operational",
    "Citrix-HostCore-ICA Service/Admin",
    "Citrix-HostCore-ICA Service/Operational",
    "Citrix-HostCore-ICA SSOn Credential Provider/Admin",
    "Citrix-HostCore-Remote Credential Guard/Admin",
    "Citrix-HostCore-Remote Credential Guard/Operational",
    "Citrix-HostCore-Session Agent/Admin",
    "Citrix-HostCore-Session Agent/Operational",
    "Citrix-HostCore-User Agent/Admin",
    "Citrix-HostCore-User Agent/Operational",
    "Citrix-Multimedia-Audio/Admin",
    "Citrix-Multimedia-BCR/Admin",
    "Citrix-Multimedia-Rave/Admin",
    # --- FSLogix ---
    "Microsoft-FSLogix-Apps/Admin",
    "Microsoft-FSLogix-Apps/Operational",
    "Microsoft-FSLogix-CloudCache/Admin",
    "Microsoft-FSLogix-CloudCache/Operational",
    # --- FSLogix-adjacent: profile / storage / AV ---
    "Microsoft-Windows-User Profile Service/Operational",
    "Microsoft-Windows-SMBClient/Operational",
    "Microsoft-Windows-SmbClient/Connectivity",
    "Microsoft-Windows-SmbClient/Security",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-Folder Redirection/Operational",
    # --- Teams (MSIX) / AppX / Start menu ---
    "Microsoft-Windows-AppXDeployment/Operational",
    "Microsoft-Windows-AppXDeploymentServer/Operational",
    "Microsoft-Windows-AppXDeploymentServer/Restricted",
    "Microsoft-Windows-AppxPackaging/Operational",
    "Microsoft-Windows-TWinUI/Operational",
    # --- Office ---
    "OAlerts",
    # --- Session lifecycle / logon ---
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-Winlogon/Operational",
    "Microsoft-Windows-Shell-Core/Operational",
    "Microsoft-Windows-Diagnostics-Performance/Operational",
    # --- Printing (frequent pain point in VDI environments) ---
    "Microsoft-Windows-PrintService/Admin",
    # --- Windows platform / identity / policy ---
    "Microsoft-Windows-AAD/Operational",
    "Microsoft-Windows-User Device Registration/Admin",
    "Microsoft-Windows-AppReadiness/Admin",
    "Microsoft-Windows-AppReadiness/Operational",
    "Microsoft-Windows-Audio/Operational",
    "Microsoft-Windows-BranchCache/Operational",
    "Microsoft-Windows-CloudStore/Operational",
    "Microsoft-Windows-Crypto-NCrypt/Operational",
    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Enrollment",
    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational",
    "Microsoft-Windows-DeviceSetupManager/Admin",
    "Microsoft-Windows-DeviceSetupManager/Operational",
    "Microsoft-Windows-GroupPolicy/Operational",
    "Microsoft-Windows-LiveId/Operational",
    "Microsoft-Windows-Ntfs/Operational",
    "Microsoft-Windows-NTLM/Operational",
    "Microsoft-Windows-Security-LessPrivilegedAppContainer/Operational",
    "Microsoft-Windows-Security-Netlogon/Operational",
    "Microsoft-Windows-StorageManagement/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-WindowsUpdateClient/Operational",
    "Microsoft-Windows-WMI-Activity/Operational"
)

# -----------------------------------------------------------------------------
# SECTION 5 - REMOTE QUERY (runs entirely on the target, one WinRM session)
# -----------------------------------------------------------------------------

$remoteQuery = {
    param($Mode, $StartStr, $EndStr, [string[]]$ClassicLogs, [string[]]$StaticChannels,
          [int[]]$ClassicLevels, [int[]]$ChannelLevels, [int]$AuditFailureCap)

    # Times travel as strings and are parsed here, in the target's local time.
    $start = [DateTime]::ParseExact($StartStr, 'yyyy-MM-dd HH:mm:ss', $null)
    $end   = [DateTime]::ParseExact($EndStr,   'yyyy-MM-dd HH:mm:ss', $null)

    $levelLabels = @{ 1 = "Critical"; 2 = "Error"; 3 = "Warning" }
    $rows        = New-Object System.Collections.Generic.List[object]
    $auditCapped = $false

    function Get-ChannelEvents {
        param([string]$LogName, [int[]]$Levels, [hashtable]$ExtraFilter, [int]$MaxEvents = 0)

        try {
            Get-WinEvent -ListLog $LogName -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Host "  [NOT FOUND] $LogName - Log not registered on this machine." -ForegroundColor Red
            return @()
        }

        $filter = @{ LogName = $LogName; StartTime = $start; EndTime = $end }
        if ($Levels)      { $filter.Level = $Levels }
        if ($ExtraFilter) { foreach ($k in $ExtraFilter.Keys) { $filter[$k] = $ExtraFilter[$k] } }

        try {
            if ($MaxEvents -gt 0) { return @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop) }
            return @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)
        }
        catch [System.Exception] {
            $msg = $_.Exception.Message
            if ($msg -like "*No events were found*") {
                Write-Host "  [EMPTY] $LogName - Log exists, no matching events in this window." -ForegroundColor DarkGray
            } else {
                Write-Host "  [WARN] $LogName - Query failed: $msg" -ForegroundColor Yellow
            }
            return @()
        }
    }

    function Add-Rows {
        param($Events, [string]$LogName, [string]$LevelOverride)
        foreach ($e in $Events) {
            # Bug fix: collapse line breaks FIRST, then truncate the resulting string.
            $msg = if ($e.Message) {
                $m = $e.Message -replace "`r`n|`n|`r", " "
                if ($m.Length -gt 1000) { $m.Substring(0, 1000) } else { $m }
            } else {
                "<no message rendered - provider metadata unavailable (EventID $($e.Id), Provider $($e.ProviderName))>"
            }
            $rows.Add([pscustomobject]@{
                RowType         = 'Event'
                Timestamp       = $e.TimeCreated
                LogSource       = $LogName
                EventID         = $e.Id
                Level           = if ($LevelOverride) { $LevelOverride } else { $levelLabels[[int]$e.Level] }
                ProviderName    = $e.ProviderName
                TaskDisplayName = $e.TaskDisplayName
                Message         = $msg
            })
        }
    }

    # --- Resolve channel list for the mode ---
    $namedChannels = @()
    switch ($Mode) {
        2 { $namedChannels = $StaticChannels }
        3 {
            Write-Host "--- Full Event Scan: enumerating ALL event channels on $env:COMPUTERNAME ---" -ForegroundColor Cyan
            try {
                $discoveredLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
                    Where-Object { $_.IsEnabled -and $_.RecordCount -gt 0 }

                $namedChannels = @($discoveredLogs |
                    Select-Object -ExpandProperty LogName |
                    Where-Object { $ClassicLogs -notcontains $_ } |
                    Sort-Object -Unique)

                if ($namedChannels.Count -eq 0) {
                    Write-Host "  No enabled/non-empty channels discovered. Only classic logs will be queried." -ForegroundColor Yellow
                } else {
                    Write-Host "  Discovered $($namedChannels.Count) enabled, non-empty channel(s)." -ForegroundColor Green
                }
            }
            catch {
                Write-Host "  ERROR during channel discovery: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "  Falling back to the static Extended channel list." -ForegroundColor Yellow
                $namedChannels = $StaticChannels
            }
            Write-Host ""
        }
    }

    # --- Mode 4: Security Audit Failures ONLY (Level 0, filtered on Keywords), capped ---
    if ($Mode -eq 4) {
        Write-Host "--- Querying Security Audit Failures (newest $AuditFailureCap max) ---" -ForegroundColor Cyan
        $audit = Get-ChannelEvents -LogName 'Security' -ExtraFilter @{ Keywords = [long]4503599627370496 } -MaxEvents $AuditFailureCap
        if ($audit.Count -gt 0) {
            $auditCapped = ($audit.Count -ge $AuditFailureCap)
            Write-Host "  [OK] Security - $($audit.Count) Audit Failure event(s) found$(if ($auditCapped) { ' (CAP REACHED - older ones omitted)' })." -ForegroundColor Green
            Add-Rows -Events $audit -LogName 'Security' -LevelOverride 'Audit Failure'
        }
        Write-Host ""
        $rows.ToArray()
        [pscustomobject]@{ RowType = 'Meta'; AuditCapped = $auditCapped }
        return
    }

    # --- Classic logs (Critical + Error + Warning), modes 1-3 ---
    Write-Host "--- Querying Classic Logs ---" -ForegroundColor Cyan
    foreach ($log in $ClassicLogs) {
        Write-Host "  Querying: $log" -ForegroundColor White
        $events = Get-ChannelEvents -LogName $log -Levels $ClassicLevels
        if ($events.Count -gt 0) {
            Write-Host "  [OK] $log - $($events.Count) event(s) found." -ForegroundColor Green
            Add-Rows -Events $events -LogName $log
        }
    }
    Write-Host ""

    # --- Extended / Full scan channels (Critical + Error) ---
    if ($namedChannels.Count -gt 0) {
        $sectionLabel = if ($Mode -eq 3) { "Full Event Scan Channels" } else { "Extended Channels (Citrix / FSLogix / Windows / Office)" }
        Write-Host "--- Querying $sectionLabel ---" -ForegroundColor Cyan
        foreach ($channel in $namedChannels) {
            Write-Host "  Querying: $channel" -ForegroundColor White
            $events = Get-ChannelEvents -LogName $channel -Levels $ChannelLevels
            if ($events.Count -gt 0) {
                Write-Host "  [OK] $channel - $($events.Count) event(s) found." -ForegroundColor Green
                Add-Rows -Events $events -LogName $channel
            }
        }
        Write-Host ""
    }

    # Rows are emitted as flat top-level objects (no nesting -> no remoting
    # serialization-depth surprises), followed by one Meta object.
    $rows.ToArray()
    [pscustomobject]@{ RowType = 'Meta'; AuditCapped = $auditCapped }
}

Write-Host "Running queries on $targetMachine (one remote session)..." -ForegroundColor Cyan
Write-Host ""

$result = Invoke-Command -ComputerName $targetMachine -ScriptBlock $remoteQuery -ArgumentList `
    $mode, $startDateTime.ToString('yyyy-MM-dd HH:mm:ss'), $endDateTime.ToString('yyyy-MM-dd HH:mm:ss'),
    $classicLogs, $staticChannels, $classicLevels, $channelLevels, $AuditFailureCap

# The Meta object is always emitted last, so its absence means the remote run failed.
$meta = @($result) | Where-Object RowType -eq 'Meta' | Select-Object -First 1
if ($null -eq $meta) {
    Write-Host "ERROR: no result returned from $targetMachine (session failure / access denied?). See error above." -ForegroundColor Red
    exit 1
}

# -----------------------------------------------------------------------------
# SECTION 6 - BUILD HTML REPORT
# -----------------------------------------------------------------------------

$allResults = @(@($result) | Where-Object RowType -eq 'Event' | Sort-Object Timestamp -Descending)

$countCritical = @($allResults | Where-Object Level -eq "Critical").Count
$countError    = @($allResults | Where-Object Level -eq "Error").Count
$countWarning  = @($allResults | Where-Object Level -eq "Warning").Count
$countAudit    = @($allResults | Where-Object Level -eq "Audit Failure").Count
$countTotal    = @($allResults).Count

if ($countTotal -eq 0) {
    Write-Host "No matching events found on $targetMachine in the specified time range." -ForegroundColor Yellow
    exit 0
}

# Build HTML rows (StringBuilder: string += gets very slow on large Full Scan reports)
$sb = New-Object System.Text.StringBuilder
foreach ($evt in $allResults) {
    $levelClass = switch ($evt.Level) {
        "Critical"      { "critical" }
        "Error"         { "error" }
        "Warning"       { "warning" }
        "Audit Failure" { "audit" }
        default         { "" }
    }

    $msg      = [System.Web.HttpUtility]::HtmlEncode($evt.Message)
    $provider = [System.Web.HttpUtility]::HtmlEncode($evt.ProviderName)
    $source   = [System.Web.HttpUtility]::HtmlEncode($evt.LogSource)
    $task     = if ($evt.TaskDisplayName -and $evt.TaskDisplayName -ne "None") {
        [System.Web.HttpUtility]::HtmlEncode($evt.TaskDisplayName)
    } else { "<span class='na'>-</span>" }

    $ts = ([DateTime]$evt.Timestamp).ToString("yyyy-MM-dd HH:mm:ss")

    # data-level / data-source drive the in-page filters
    $row = @"
        <tr class="row-$levelClass" data-level="$levelClass" data-source="$source">
            <td class="ts">$ts</td>
            <td><span class="badge $levelClass">$($evt.Level)</span></td>
            <td class="log-source">$source</td>
            <td class="evtid">$($evt.EventID)</td>
            <td>$provider</td>
            <td>$task</td>
            <td class="msg">$msg</td>
        </tr>
"@
    [void]$sb.Append($row)
}
$htmlRows = $sb.ToString()

# In-page filters. Plain JS, no external libraries. Event text is only ever read
# via textContent / getAttribute and written via textContent - never parsed as HTML.
# Without JavaScript the report still shows every row (toolbar stays hidden).
$reportScript = @'
<script>
(function () {
  'use strict';
  var tbody = document.querySelector('table tbody');
  if (!tbody) { return; }
  var rows   = Array.prototype.slice.call(tbody.querySelectorAll('tr[data-level]'));
  var empty  = document.getElementById('f-empty');
  var search = document.getElementById('f-search');
  var source = document.getElementById('f-source');
  var count  = document.getElementById('f-count');
  var cards  = Array.prototype.slice.call(document.querySelectorAll('.card[data-filter]'));
  var active = {};   // selected levels; empty = all

  // Lower-cased row text computed once, so searching large reports stays fast
  var index = rows.map(function (r) { return (r.textContent || '').toLowerCase(); });

  // Log source dropdown, with per-source counts
  var sources = {};
  rows.forEach(function (r) {
    var s = r.getAttribute('data-source') || '';
    sources[s] = (sources[s] || 0) + 1;
  });
  Object.keys(sources).sort().forEach(function (s) {
    var o = document.createElement('option');
    o.value = s;
    o.textContent = s + ' (' + sources[s] + ')';
    source.appendChild(o);
  });

  function apply() {
    var q = search.value.trim().toLowerCase();
    var src = source.value;
    var anyLevel = Object.keys(active).length > 0;
    var shown = 0;
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      var ok = (!anyLevel || active[r.getAttribute('data-level')] === true) &&
               (!src || r.getAttribute('data-source') === src) &&
               (!q || index[i].indexOf(q) !== -1);
      r.hidden = !ok;
      if (ok) { shown++; }
    }
    empty.hidden = (shown !== 0);
    count.textContent = 'Showing ' + shown + ' of ' + rows.length;
    cards.forEach(function (c) {
      var f = c.getAttribute('data-filter');
      c.classList.toggle('active', f === 'all' ? !anyLevel : active[f] === true);
    });
  }

  cards.forEach(function (c) {
    c.setAttribute('role', 'button');
    c.setAttribute('tabindex', '0');
    function toggle() {
      var f = c.getAttribute('data-filter');
      if (f === 'all')      { active = {}; }
      else if (active[f])   { delete active[f]; }
      else                  { active[f] = true; }
      apply();
    }
    c.addEventListener('click', toggle);
    c.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); }
    });
  });

  var timer = null;
  search.addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(apply, 150); });
  source.addEventListener('change', apply);
  document.getElementById('f-reset').addEventListener('click', function () {
    active = {}; search.value = ''; source.value = ''; apply();
  });

  document.getElementById('toolbar').hidden = false;
  document.body.classList.add('js');
  apply();
})();
</script>
'@

$reportDate  = (Get-Date).ToString("yyyy-MM-dd HH:mm")
$windowLabel = "$($startDateTime.ToString('HH:mm')) - $($endDateTime.ToString('HH:mm'))"
$auditNote   = if ($meta.AuditCapped) { "<div class=`"card-note`">cap $AuditFailureCap reached - newest only</div>" } else { "" }

$levelCards = if ($mode -eq 4) { @"
  <div class="card audit" data-filter="audit">
    <div class="card-label">Audit Failures</div>
    <div class="card-value">$countAudit</div>
    $auditNote
  </div>
"@ } else { @"
  <div class="card crit" data-filter="critical">
    <div class="card-label">Critical</div>
    <div class="card-value">$countCritical</div>
  </div>
  <div class="card err" data-filter="error">
    <div class="card-label">Errors</div>
    <div class="card-value">$countError</div>
  </div>
  <div class="card warn" data-filter="warning">
    <div class="card-label">Warnings</div>
    <div class="card-value">$countWarning</div>
  </div>
"@ }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Event Log Report - $targetMachine</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:        #0d1117;
    --surface:   #161b22;
    --surface2:  #1c2128;
    --border:    #30363d;
    --text:      #c9d1d9;
    --muted:     #6e7681;
    --accent:    #58a6ff;

    --critical-bg:     #3d0f0f;
    --critical-border: #f85149;
    --critical-text:   #ff7b72;

    --error-bg:     #2d1a0e;
    --error-border: #f0883e;
    --error-text:   #ffa657;

    --warning-bg:     #2d2700;
    --warning-border: #d29922;
    --warning-text:   #e3b341;

    --audit-bg:     #231335;
    --audit-border: #a371f7;
    --audit-text:   #d2a8ff;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Syne', sans-serif;
    font-size: 14px;
    min-height: 100vh;
  }

  .header {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 28px 40px 24px;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    gap: 24px;
  }

  .header-left h1 {
    font-size: 26px;
    font-weight: 800;
    letter-spacing: -0.5px;
    color: #fff;
  }

  .header-left h1 span { color: var(--accent); }

  .logged-user {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: var(--muted);
    margin-top: 4px;
  }
  .logged-user span {
    color: var(--accent);
    font-weight: 600;
  }

  .mode-badge {
    display: inline-block;
    margin-top: 6px;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.5px;
    border: 1px solid var(--border);
    color: var(--muted);
    background: var(--surface2);
  }

  .header-meta {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: var(--muted);
    margin-top: 6px;
    display: flex;
    gap: 20px;
  }

  .header-meta span::before {
    content: attr(data-label) ' ';
    color: var(--accent);
    font-weight: 600;
  }

  .summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 16px;
    padding: 28px 40px;
    background: var(--bg);
  }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px 24px;
    position: relative;
    overflow: hidden;
  }

  .card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
  }

  .card.total::before  { background: var(--accent); }
  .card.crit::before   { background: var(--critical-border); }
  .card.err::before    { background: var(--error-border); }
  .card.warn::before   { background: var(--warning-border); }

  .card-label {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 10px;
  }

  .card-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 36px;
    font-weight: 600;
    line-height: 1;
    color: #fff;
  }

  .card.crit .card-value { color: var(--critical-text); }
  .card.err  .card-value { color: var(--error-text); }
  .card.warn .card-value { color: var(--warning-text); }

  .table-wrap {
    padding: 0 40px 40px;
    overflow-x: auto;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    table-layout: fixed;
  }

  colgroup col.ts   { width: 140px; }
  colgroup col.lvl  { width: 90px; }
  colgroup col.src  { width: 200px; }
  colgroup col.eid  { width: 70px; }
  colgroup col.prv  { width: 200px; }
  colgroup col.task { width: 160px; }
  colgroup col.msg  { width: auto; }

  thead th {
    background: var(--surface2);
    border: 1px solid var(--border);
    padding: 10px 14px;
    text-align: left;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    color: var(--muted);
    white-space: nowrap;
  }

  tbody tr {
    border-bottom: 1px solid var(--border);
    transition: background 0.1s;
  }

  tbody tr:hover { background: var(--surface2); }

  tbody td {
    padding: 10px 14px;
    vertical-align: top;
    border-left: 1px solid var(--border);
    border-right: 1px solid var(--border);
    word-break: break-word;
  }

  tr.row-critical { border-left: 3px solid var(--critical-border); background: rgba(61,15,15,0.3); }
  tr.row-error    { border-left: 3px solid var(--error-border);    background: rgba(45,26,14,0.3); }
  tr.row-warning  { border-left: 3px solid var(--warning-border);  background: rgba(45,39,0,0.3); }

  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.5px;
    font-family: 'JetBrains Mono', monospace;
    white-space: nowrap;
  }

  .badge.critical { background: var(--critical-bg); color: var(--critical-text); border: 1px solid var(--critical-border); }
  .badge.error    { background: var(--error-bg);    color: var(--error-text);    border: 1px solid var(--error-border); }
  .badge.warning  { background: var(--warning-bg);  color: var(--warning-text);  border: 1px solid var(--warning-border); }

  .ts         { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--muted); white-space: nowrap; }
  .evtid      { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--accent); text-align: center; }
  .log-source { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text); }
  .msg        { font-size: 12px; line-height: 1.5; color: var(--text); }
  .na         { color: var(--muted); }

  .footer {
    text-align: center;
    padding: 20px;
    font-size: 11px;
    color: var(--muted);
    border-top: 1px solid var(--border);
    font-family: 'JetBrains Mono', monospace;
  }

  /* Audit Failure (Security log, Keywords = Audit Failure) */
  .card.audit::before { background: var(--audit-border); }
  .card.audit .card-value { color: var(--audit-text); }
  .card-note { font-size: 10px; color: var(--muted); margin-top: 8px; font-family: 'JetBrains Mono', monospace; }
  tr.row-audit   { border-left: 3px solid var(--audit-border); background: rgba(40,20,60,0.3); }
  .badge.audit   { background: var(--audit-bg); color: var(--audit-text); border: 1px solid var(--audit-border); }

  /* In-page filters (toolbar is only revealed when JavaScript runs) */
  [hidden] { display: none !important; }
  .toolbar { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; padding: 0 40px 16px; }
  .toolbar input[type=search], .toolbar select, .toolbar button {
    background: var(--surface); color: var(--text); border: 1px solid var(--border);
    border-radius: 6px; padding: 8px 12px; font-size: 13px; font-family: inherit;
  }
  .toolbar input[type=search] { flex: 1 1 320px; min-width: 220px; }
  .toolbar select { max-width: 380px; }
  .toolbar button { cursor: pointer; }
  .toolbar button:hover, .toolbar select:hover { border-color: var(--accent); }
  .toolbar input:focus, .toolbar select:focus, .toolbar button:focus { outline: none; border-color: var(--accent); }
  .f-count { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--accent); }
  .f-hint  { font-size: 11px; color: var(--muted); }
  .js .card[data-filter] { cursor: pointer; user-select: none; transition: border-color 0.1s; }
  .js .card[data-filter]:hover { border-color: var(--muted); }
  .js .card.active { border-color: var(--accent); box-shadow: inset 0 0 0 1px var(--accent); }
  tr.f-empty td { text-align: center; color: var(--muted); padding: 24px; }
</style>
</head>
<body>

<div class="header">
  <div class="header-left">
    <h1>Event Log Report &mdash; <span>$targetMachine</span></h1>
    <div class="logged-user">Logged-in user: <span>$loggedInUser</span></div>
    <div class="mode-badge">$modeName</div>
    <div class="header-meta">
      <span data-label="DATE">$($targetDate.ToString('yyyy-MM-dd'))</span>
      <span data-label="WINDOW">$windowLabel</span>
      <span data-label="GENERATED">$reportDate</span>
    </div>
  </div>
</div>

<div class="summary">
  <div class="card total" data-filter="all">
    <div class="card-label">Total Events</div>
    <div class="card-value">$countTotal</div>
  </div>
$levelCards
</div>

<div class="toolbar" id="toolbar" hidden>
  <input type="search" id="f-search" placeholder="Search: Event ID, provider, message, user..." autocomplete="off">
  <select id="f-source"><option value="">All log sources</option></select>
  <button type="button" id="f-reset">Reset filters</button>
  <span class="f-count" id="f-count"></span>
  <span class="f-hint">Tip: click the summary cards to filter by level (several can be combined)</span>
</div>

<div class="table-wrap">
  <table>
    <colgroup>
      <col class="ts">
      <col class="lvl">
      <col class="src">
      <col class="eid">
      <col class="prv">
      <col class="task">
      <col class="msg">
    </colgroup>
    <thead>
      <tr>
        <th>Timestamp</th>
        <th>Level</th>
        <th>Log Source</th>
        <th>Event ID</th>
        <th>Provider</th>
        <th>Task</th>
        <th>Message</th>
      </tr>
    </thead>
    <tbody>
$htmlRows
        <tr class="f-empty" id="f-empty" hidden><td colspan="7">No events match the current filters.</td></tr>
    </tbody>
  </table>
</div>

<div class="footer">
  Generated by $ScriptName &bull; $reportDate &bull; $targetMachine &bull; $modeName
</div>

$reportScript
</body>
</html>
"@

# -----------------------------------------------------------------------------
# SECTION 7 - SAVE REPORT
# -----------------------------------------------------------------------------

$timestamp   = (Get-Date).ToString("yyyyMMdd_HHmm")
$safeMachine = $targetMachine -replace '[\\/:*?"<>|]', '_'
$htmlPath    = "C:\temp\EventLogs_${safeMachine}_${modeTag}_${timestamp}.html"

try {
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  Total events   : $countTotal" -ForegroundColor Green
    if ($mode -eq 4) {
        Write-Host "  Audit Failures : $countAudit$(if ($meta.AuditCapped) { " (cap $AuditFailureCap reached)" })" -ForegroundColor Magenta
    } else {
        Write-Host "  Critical       : $countCritical" -ForegroundColor Red
        Write-Host "  Errors         : $countError" -ForegroundColor Yellow
        Write-Host "  Warnings       : $countWarning" -ForegroundColor Yellow
    }
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "HTML report saved:" -ForegroundColor Green
    Write-Host "  $htmlPath" -ForegroundColor White
    Write-Host ""
    Start-Process $htmlPath
}
catch {
    Write-Host "ERROR: Could not save report - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "Done." -ForegroundColor Cyan
