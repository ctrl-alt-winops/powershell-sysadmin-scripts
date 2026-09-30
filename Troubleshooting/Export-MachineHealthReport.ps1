<#
.SYNOPSIS
    Read-only health snapshot of a remote Windows machine, saved as an HTML
    report (C:\temp on THIS machine) and summarised in the console.

.DESCRIPTION
    Prompts for the machine name, checks WinRM, then collects in ONE remote
    session (nothing is changed on the target):
      - System        : OS, build, last boot / uptime, CPU load, RAM
      - Time          : time zone, local time, sync source (w32tm), clock offset
                        measured against the time source / a domain controller
      - Disks         : free space per local disk
      - Pending reboot: Windows Update, component servicing, pending file renames
      - Sessions      : logged-on users (owners of explorer.exe)
      - Top programs  : 5 heaviest by memory and by CPU time, processes grouped
                        by program + user (e.g. all msedge.exe of one user = 1 line)
      - Network       : IP, gateway, DNS per connected adapter
      - Group Policy  : last computer policy refresh; errors / warnings of the
                        last 24 h (System + GroupPolicy/Operational logs), listed
                        with event ID, time, repeat count and message
      - Antivirus     : product(s) registered in Windows Security Center

    Problems are flagged with the thresholds set at the top of the script
    (disk space, uptime, Group Policy age) and shown first in the report.

    Language-independent by design: no quser / performance counters (their
    output is localised), only CIM classes, registry and event IDs.

.NOTES
    Requirements:
    - Admin rights on the target + WinRM enabled (domain-joined machines /
      Kerberos; workgroup targets need extra WinRM configuration).
    - Windows 8 / Server 2012 or later on the target (Get-NetIPConfiguration).
    - Clock offset: UDP 123 from the target to its time source / a DC (the
      port domain members already use for time sync).

    Two values come from undocumented but widely used sources:
    - Last Group Policy refresh: registry EndTimeHi/EndTimeLo under
      ...\Group Policy\State\Machine\Extension-List\{00000000-...}.
    - Antivirus on/off and up to date: decoded from Security Center's
      productState. Security Center exists on client Windows only; on servers
      the antivirus section shows "not available".
    CPU "time" for programs = total CPU seconds since the processes started,
    not the current load.

    Read-only. One machine per run. Exit codes: 0 = report written (warnings
    or not), 1 = aborted / failed.
#>

# ------------------------- Thresholds (adjust to taste) -------------------------
$MinDiskFreePct  = 10    # WARN below this % free on a local disk
$MaxUptimeDays   = 30    # WARN above this uptime
$MaxGpoAgeHours  = 24    # WARN if the last computer policy refresh is older
$TopProcessCount = 5
$MaxGpoEventsListed = 10   # distinct Group Policy errors/warnings listed in the report
$MaxClockOffsetSec = 60    # WARN above this clock difference (Kerberos fails at 300 s by default)

# ------------------------- Remote collection (runs ON THE TARGET) -------------------------
# Returns flat rows: Section / Item / Value / Status (OK, WARN, INFO).
# Each section has its own try/catch: one failing section never hides the others.
$CollectHealth = {
    param([int]$MinDiskFreePct, [int]$MaxUptimeDays, [int]$MaxGpoAgeHours, [int]$TopProcessCount, [int]$MaxGpoEventsListed, [int]$MaxClockOffsetSec)

    function ConvertTo-HealthRow {
        param([string]$Section, [string]$Item, [string]$Value, [string]$Status = 'INFO', [switch]$Detail)
        [pscustomobject]@{ Section = $Section; Item = $Item; Value = $Value; Status = $Status; Detail = [bool]$Detail }
    }

    # --- System ---
    try {
        $os   = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $cs   = Get-CimInstance -ClassName Win32_ComputerSystem  -ErrorAction Stop
        $cv   = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
        $up   = (Get-Date) - $os.LastBootUpTime
        $cpu  = (Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Measure-Object -Property LoadPercentage -Average).Average
        $ramT = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
        $ramF = [math]::Round($os.FreePhysicalMemory / 1MB, 1)

        ConvertTo-HealthRow -Section 'System' -Item 'Computer' -Value "$($cs.Name) ($($cs.Manufacturer) $($cs.Model))"
        ConvertTo-HealthRow -Section 'System' -Item 'Domain' -Value $(if ($cs.PartOfDomain) { $cs.Domain } else { "Workgroup: $($cs.Workgroup)" })
        ConvertTo-HealthRow -Section 'System' -Item 'OS' -Value "$($os.Caption) $($cv.DisplayVersion) - build $($os.BuildNumber)$(if ($null -ne $cv.UBR) { ".$($cv.UBR)" })"
        ConvertTo-HealthRow -Section 'System' -Item 'Last boot' -Value $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')
        ConvertTo-HealthRow -Section 'System' -Item 'Uptime' -Value ('{0} days {1} h' -f $up.Days, $up.Hours) -Status $(if ($up.TotalDays -gt $MaxUptimeDays) { 'WARN' } else { 'OK' })
        ConvertTo-HealthRow -Section 'System' -Item 'CPU load' -Value $(if ($null -ne $cpu) { "$([math]::Round($cpu))% (now)" } else { 'n/a' })
        ConvertTo-HealthRow -Section 'System' -Item 'RAM' -Value ('{0} GB free of {1} GB ({2}% free)' -f $ramF, $ramT, [math]::Round(100 * $ramF / $ramT))
    }
    catch { ConvertTo-HealthRow -Section 'System' -Item 'Error' -Value "Could not read: $($_.Exception.Message)" }

    # --- Time: zone, sync source, clock offset (Kerberos fails beyond 5 min by default) ---
    try {
        $tz  = [System.TimeZoneInfo]::Local
        $now = Get-Date
        $off = $tz.GetUtcOffset($now)
        $utcTxt = 'UTC{0}{1:hh\:mm}' -f $(if ($off -lt [TimeSpan]::Zero) { '-' } else { '+' }), $off
        ConvertTo-HealthRow -Section 'Time' -Item 'Time zone' -Value ('{0} - now {1}{2}' -f $tz.DisplayName, $utcTxt, $(if ($tz.IsDaylightSavingTime($now)) { ' (summer time)' } else { '' }))
        ConvertTo-HealthRow -Section 'Time' -Item 'Local time' -Value $now.ToString('yyyy-MM-dd HH:mm:ss')

        # Sync source, e.g. "dc01.corp.example", "time.windows.com,0x9" or "Local CMOS Clock"
        $source = ((& w32tm /query /source 2>$null) | Out-String).Trim() -replace ',0x[0-9A-Fa-f]+$', ''
        $isHost = $source -match '^[A-Za-z0-9.-]+$'
        $srcStatus = if (-not $source -or $source -match 'CMOS|Free-running') { 'WARN' } else { 'INFO' }
        ConvertTo-HealthRow -Section 'Time' -Item 'Time source' -Status $srcStatus `
            -Value $(if (-not $source) { 'unknown (w32tm gave no answer)' } elseif ($srcStatus -eq 'WARN') { "$source - not synchronising with a time server" } else { $source })

        # Reference for the offset: the sync source if it is a server, else a DC of the domain
        $ref = if ($isHost) { $source } else {
            try { [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().FindDomainController().Name } catch { $null }
        }
        if ($ref) {
            # One SNTP request (UDP 123): offset = server time - local midpoint of the exchange
            $udp = New-Object System.Net.Sockets.UdpClient
            try {
                $udp.Client.ReceiveTimeout = 3000
                $udp.Connect($ref, 123)
                $req = New-Object byte[] 48
                $req[0] = 0x1B                      # NTP v3, client mode
                $t1 = [DateTime]::UtcNow
                [void]$udp.Send($req, 48)
                $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $resp = $udp.Receive([ref]$ep)
                $t4 = [DateTime]::UtcNow
                # Transmit timestamp = bytes 40-47, big-endian seconds since 1900 + fraction
                $sec  = [BitConverter]::ToUInt32([byte[]]@($resp[43], $resp[42], $resp[41], $resp[40]), 0)
                $frac = [BitConverter]::ToUInt32([byte[]]@($resp[47], $resp[46], $resp[45], $resp[44]), 0)
                $srvTime = (New-Object DateTime 1900, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc)).AddSeconds($sec + $frac / 4294967296.0)
                $offset  = ($srvTime - $t1.AddTicks([int64](($t4 - $t1).Ticks / 2))).TotalSeconds
                $sign    = if ($offset -ge 0) { '+' } else { '-' }
                ConvertTo-HealthRow -Section 'Time' -Item "Clock offset vs $ref" `
                    -Value ('{0}{1:N2} s ({2}){3}' -f $sign, [math]::Abs($offset), $(if ($offset -ge 0) { 'this machine is behind' } else { 'this machine is ahead' }),
                            $(if ([math]::Abs($offset) -gt 300) { ' - beyond the 5 min Kerberos limit: domain logons and access to servers will fail' } else { '' })) `
                    -Status $(if ([math]::Abs($offset) -gt $MaxClockOffsetSec) { 'WARN' } else { 'OK' })
            }
            catch { ConvertTo-HealthRow -Section 'Time' -Item "Clock offset vs $ref" -Value "could not measure (UDP 123 blocked or no answer): $($_.Exception.Message)" }
            finally { $udp.Close() }
        }
        else { ConvertTo-HealthRow -Section 'Time' -Item 'Clock offset' -Value 'not measured (no time server or domain controller found)' }
    }
    catch { ConvertTo-HealthRow -Section 'Time' -Item 'Error' -Value "Could not read: $($_.Exception.Message)" }

    # --- Disks ---
    try {
        $disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)
        foreach ($d in $disks) {
            if (-not $d.Size) { continue }
            $pct = [math]::Round(100 * $d.FreeSpace / $d.Size)
            ConvertTo-HealthRow -Section 'Disks' -Item $d.DeviceID -Value ('{0} GB free of {1} GB ({2}%)' -f [math]::Round($d.FreeSpace / 1GB, 1), [math]::Round($d.Size / 1GB, 1), $pct) -Status $(if ($pct -lt $MinDiskFreePct) { 'WARN' } else { 'OK' })
        }
        if ($disks.Count -eq 0) { ConvertTo-HealthRow -Section 'Disks' -Item 'Local disks' -Value 'none found' }
    }
    catch { ConvertTo-HealthRow -Section 'Disks' -Item 'Error' -Value "Could not read: $($_.Exception.Message)" }

    # --- Pending reboot ---
    try {
        $wu   = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        $cbs  = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        $pfro = [bool](Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)

        ConvertTo-HealthRow -Section 'Pending reboot' -Item 'Windows Update' -Value $(if ($wu)  { 'Reboot required' } else { 'No' }) -Status $(if ($wu)  { 'WARN' } else { 'OK' })
        ConvertTo-HealthRow -Section 'Pending reboot' -Item 'Component servicing' -Value $(if ($cbs) { 'Reboot pending' }  else { 'No' }) -Status $(if ($cbs) { 'WARN' } else { 'OK' })
        # File renames are often queued by harmless installers/AV updates: informational only.
        ConvertTo-HealthRow -Section 'Pending reboot' -Item 'Pending file renames' -Value $(if ($pfro) { 'Yes (often harmless on its own)' } else { 'No' })
    }
    catch { ConvertTo-HealthRow -Section 'Pending reboot' -Item 'Error' -Value "Could not read: $($_.Exception.Message)" }

    # --- Sessions (owners of explorer.exe = interactive users; language-independent) ---
    try {
        $shells = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop)
        foreach ($p in $shells) {
            $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue
            $who = if ($o -and $o.User) { "$($o.Domain)\$($o.User)" } else { 'unknown' }
            ConvertTo-HealthRow -Section 'Sessions' -Item $who -Value ("session {0}, since {1}" -f $p.SessionId, $p.CreationDate.ToString('yyyy-MM-dd HH:mm'))
        }
        if ($shells.Count -eq 0) { ConvertTo-HealthRow -Section 'Sessions' -Item 'Logged-on users' -Value 'none' }
    }
    catch { ConvertTo-HealthRow -Section 'Sessions' -Item 'Error' -Value "Could not read: $($_.Exception.Message)" }

    # --- Top programs: processes grouped by program + user (msedge, ms-teams... run
    # as many processes), with the file's description and the owner. -IncludeUserName
    # needs admin, which the remote session is.
    try {
        $programs = @(Get-Process -IncludeUserName -ErrorAction Stop | Where-Object { $_.ProcessName -ne 'Idle' } |
            Group-Object -Property { "$($_.ProcessName)|$($_.UserName)" } | ForEach-Object {
                $g = $_.Group
                $desc = ($g | Where-Object { $_.Description } | Select-Object -First 1).Description
                [pscustomobject]@{
                    Name  = $g[0].ProcessName
                    Label = if ($desc -and $desc -ne $g[0].ProcessName) { "$($g[0].ProcessName) ($desc)" } else { $g[0].ProcessName }
                    User  = if ($g[0].UserName) { $g[0].UserName } else { 'n/a' }
                    Count = $g.Count
                    Cpu   = [math]::Round(($g | Measure-Object -Property CPU -Sum).Sum)
                    MemMB = [math]::Round(($g | Measure-Object -Property WorkingSet64 -Sum).Sum / 1MB)
                }
            })
        $fmt = { param($x) '{0} - {1} process(es) - {2} MB - {3} s CPU' -f $x.User, $x.Count, $x.MemMB, $x.Cpu }
        foreach ($x in ($programs | Sort-Object MemMB -Descending | Select-Object -First $TopProcessCount)) {
            ConvertTo-HealthRow -Section 'Top programs (memory)' -Item $x.Label -Value (& $fmt $x)
        }
        foreach ($x in ($programs | Where-Object { $_.Cpu -gt 0 } | Sort-Object Cpu -Descending | Select-Object -First $TopProcessCount)) {
            ConvertTo-HealthRow -Section 'Top programs (CPU time)' -Item $x.Label -Value (& $fmt $x)
        }
    }
    catch { ConvertTo-HealthRow -Section 'Top programs' -Item 'Error' -Value "Could not read: $($_.Exception.Message)" }

    # --- Network (connected adapters only) ---
    try {
        $nics = @(Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.NetAdapter.Status -eq 'Up' })
        foreach ($n in $nics) {
            $ip  = ($n.IPv4Address.IPAddress) -join ', '
            $gw  = ($n.IPv4DefaultGateway.NextHop) -join ', '
            $dns = ($n.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses }) -join ', '
            ConvertTo-HealthRow -Section 'Network' -Item $n.InterfaceAlias -Value ("IP {0} - gateway {1} - DNS {2}" -f $(if ($ip) { $ip } else { 'none' }), $(if ($gw) { $gw } else { 'none' }), $(if ($dns) { $dns } else { 'none' }))
        }
        if ($nics.Count -eq 0) { ConvertTo-HealthRow -Section 'Network' -Item 'Adapters' -Value 'no connected adapter' -Status 'WARN' }
    }
    catch { ConvertTo-HealthRow -Section 'Network' -Item 'Error' -Value "Could not read: $($_.Exception.Message)" }

    # --- Group Policy ---
    try {
        $gpKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{00000000-0000-0000-0000-000000000000}'
        $gp = Get-ItemProperty -Path $gpKey -ErrorAction SilentlyContinue
        if ($gp -and $null -ne $gp.EndTimeHi) {
            # FILETIME split in two 32-bit halves. Depending on how the value was written,
            # PowerShell returns each half as a negative Int32 OR as a number above 2^31:
            # go through Int64 and fold negatives back into 0..2^32-1, so both work.
            $half = { param($v) $n = [int64]$v; if ($n -lt 0) { $n += 4294967296 }; $n }
            $ft   = ((& $half $gp.EndTimeHi) -shl 32) -bor (& $half $gp.EndTimeLo)
            $last = [DateTime]::FromFileTime($ft)
            $age  = ((Get-Date) - $last).TotalHours
            ConvertTo-HealthRow -Section 'Group Policy' -Item 'Last computer refresh' -Value ('{0} ({1} h ago)' -f $last.ToString('yyyy-MM-dd HH:mm'), [math]::Round($age)) -Status $(if ($age -gt $MaxGpoAgeHours) { 'WARN' } else { 'OK' })
        }
        else { ConvertTo-HealthRow -Section 'Group Policy' -Item 'Last computer refresh' -Value 'unknown (no record on this machine)' }

        # Classic GP problems (1058/1030 DC unreachable, 1085 extension failed, 1129 no
        # network...) are in the System log; details are in the Operational log.
        $since = (Get-Date).AddHours(-24)
        $gpEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-GroupPolicy'; Level = 1, 2, 3; StartTime = $since } -ErrorAction SilentlyContinue) +
                    @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-GroupPolicy/Operational'; Level = 1, 2; StartTime = $since } -ErrorAction SilentlyContinue)

        # Error code from the event data, when the event carries one (e.g. 7016
        # "Completed ... Extension Processing" logged as Error: the text hides the code).
        function Get-GpErrorCode {
            param($GpEvent)
            try {
                $data = ([xml]$GpEvent.ToXml()).Event.EventData.Data
                $code = ($data | Where-Object { $_.Name -eq 'ErrorCode' }).'#text'
                $desc = ($data | Where-Object { $_.Name -eq 'ErrorDescription' }).'#text'
                if ($code -and $code -ne '0') { return " (error code $code$(if ($desc) { ": $desc" }))" }
            } catch { $null = $_ }   # no XML / no such field: nothing to add
            return ''
        }

        # Same event ID + same message = one line, with a count and the latest time.
        # Numbers are ignored when comparing (7016 lines differ only by milliseconds).
        $distinct = @($gpEvents | Group-Object -Property { "$($_.Id)|$($_.Message -replace '\d+', '#')|$(Get-GpErrorCode -GpEvent $_)" } | ForEach-Object {
            $latest = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $msg = if ($latest.Message) { ($latest.Message -replace '\s+', ' ').Trim() } else { '(no message text)' }
            if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) + '...' }
            [pscustomobject]@{ Id = $latest.Id; Level = $latest.LevelDisplayName; LevelNum = [int]$latest.Level; Time = $latest.TimeCreated
                               Count = $_.Count; Message = $msg + (Get-GpErrorCode -GpEvent $latest) }
        } | Sort-Object Time -Descending)

        ConvertTo-HealthRow -Section 'Group Policy' -Item 'Errors / warnings (last 24 h)' `
            -Value $(if ($gpEvents.Count) { "$($gpEvents.Count) event(s), $($distinct.Count) distinct$(if ($distinct.Count -gt $MaxGpoEventsListed) { " - newest $MaxGpoEventsListed listed" })" } else { 'none' }) `
            -Status $(if ($gpEvents.Count) { 'WARN' } else { 'OK' })
        foreach ($d in ($distinct | Select-Object -First $MaxGpoEventsListed)) {
            ConvertTo-HealthRow -Section 'Group Policy' -Item ('Event {0} ({1}) - {2}' -f $d.Id, $d.Level, $d.Time.ToString('yyyy-MM-dd HH:mm')) `
                -Value ('{0}{1}' -f $(if ($d.Count -gt 1) { "[x$($d.Count)] " } else { '' }), $d.Message) `
                -Status $(if ($d.LevelNum -le 2) { 'ERROR' } else { 'WARN' }) -Detail
        }
    }
    catch { ConvertTo-HealthRow -Section 'Group Policy' -Item 'Error' -Value "Could not read: $($_.Exception.Message)" }

    # --- Antivirus (Windows Security Center; client Windows only) ---
    try {
        $avs = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)
        foreach ($av in $avs) {
            # productState, as hex 0xAABBCC: BB = real-time protection (10/11 = on), CC = signatures (00 = up to date).
            $hex  = '{0:X6}' -f [int64]$av.productState
            $hex  = $hex.Substring($hex.Length - 6)
            $on   = $hex.Substring(2, 2) -in '10', '11'
            $fresh = $hex.Substring(4, 2) -eq '00'
            ConvertTo-HealthRow -Section 'Antivirus' -Item $av.displayName -Value ('Protection {0} - signatures {1}' -f $(if ($on) { 'ON' } else { 'OFF' }), $(if ($fresh) { 'up to date' } else { 'OUT OF DATE' })) -Status $(if ($on -and $fresh) { 'OK' } else { 'WARN' })
        }
        if ($avs.Count -eq 0) { ConvertTo-HealthRow -Section 'Antivirus' -Item 'Products' -Value 'none registered' -Status 'WARN' }
    }
    catch { ConvertTo-HealthRow -Section 'Antivirus' -Item 'Security Center' -Value 'not available (Windows Server, or access denied)' }
}

# ------------------------- Prompt + WinRM check -------------------------

$ComputerName = (Read-Host 'Target machine name').Trim()
if (-not $ComputerName) { Write-Host 'ERROR: no machine name. Aborting.' -ForegroundColor Red; exit 1 }

Write-Host "`nChecking WinRM on '$ComputerName'..." -ForegroundColor Cyan
try {
    Test-WSMan -ComputerName $ComputerName -ErrorAction Stop | Out-Null
    Write-Host 'WinRM reachable.' -ForegroundColor Green
}
catch {
    Write-Host "ERROR: cannot reach '$ComputerName' via WinRM. Machine offline, name wrong, or PS Remoting not enabled." -ForegroundColor Red
    Write-Host "Details: $($_.Exception.Message)" -ForegroundColor DarkRed
    exit 1
}

# ------------------------- Collect -------------------------

Write-Host "Collecting health data from '$ComputerName' (read-only)..." -ForegroundColor Cyan
$rows = @(Invoke-Command -ComputerName $ComputerName -ScriptBlock $CollectHealth `
            -ArgumentList $MinDiskFreePct, $MaxUptimeDays, $MaxGpoAgeHours, $TopProcessCount, $MaxGpoEventsListed, $MaxClockOffsetSec)
if ($rows.Count -eq 0) {
    Write-Host 'ERROR: no data returned (session failure / access denied?). See error above.' -ForegroundColor Red
    exit 1
}
$warnings = @($rows | Where-Object { $_.Status -in 'WARN', 'ERROR' -and -not $_.Detail })

# ------------------------- HTML report -------------------------

$enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
$sb  = New-Object System.Text.StringBuilder

# Sections in collection order
$sections = @($rows | ForEach-Object { $_.Section } | Select-Object -Unique)
foreach ($sec in $sections) {
    [void]$sb.Append("<h2>$(& $enc $sec)</h2>`n<table><tbody>`n")
    foreach ($r in ($rows | Where-Object Section -eq $sec)) {
        $cls = $r.Status.ToLower()
        [void]$sb.Append("<tr class=`"$cls`"><td class=`"item`">$(& $enc $r.Item)</td><td>$(& $enc $r.Value)</td><td class=`"st`"><span class=`"badge $cls`">$($r.Status)</span></td></tr>`n")
    }
    [void]$sb.Append("</tbody></table>`n")
}

$warnHtml = if ($warnings.Count -gt 0) {
    '<ul class="warnlist">' + (($warnings | ForEach-Object { "<li><b>$(& $enc $_.Section)</b> / $(& $enc $_.Item) - $(& $enc $_.Value)</li>" }) -join '') + '</ul>'
} else { '<p class="allok">No warning - all checks within thresholds.</p>' }

$generated  = (Get-Date).ToString('yyyy-MM-dd HH:mm')
$scriptName = if ($PSCommandPath) { Split-Path $PSCommandPath -Leaf } else { 'Export-MachineHealthReport.ps1' }

# System fonts only: the report makes no outbound request when opened.
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Health - $(& $enc $ComputerName)</title>
<style>
  :root { --bg:#0d1117; --surface:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e; --accent:#58a6ff;
          --ok:#3fb950; --warn:#d29922; --warn-bg:#2d2208; --err:#f85149; --err-bg:#2d1214; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font-family:'Segoe UI', system-ui, sans-serif; font-size:14px; }
  .header { padding:28px 40px 18px; border-bottom:1px solid var(--border); }
  h1 { margin:0 0 6px; font-size:22px; } h1 span { color:var(--accent); }
  .meta { color:var(--muted); font-size:12px; font-family:Consolas, monospace; }
  .summary { margin:20px 40px; padding:16px 20px; background:var(--surface); border:1px solid var(--border); border-radius:8px; }
  .summary.has-warn { border-left:4px solid var(--warn); } .summary.all-ok { border-left:4px solid var(--ok); }
  .summary h3 { margin:0 0 8px; font-size:15px; }
  .warnlist { margin:0; padding-left:20px; } .warnlist li { margin:4px 0; } .allok { margin:0; color:var(--ok); }
  .content { padding:0 40px 30px; }
  h2 { font-size:15px; color:var(--accent); margin:26px 0 8px; text-transform:uppercase; letter-spacing:0.5px; }
  table { width:100%; border-collapse:collapse; background:var(--surface); border:1px solid var(--border); border-radius:8px; overflow:hidden; }
  td { padding:8px 12px; border-bottom:1px solid var(--border); vertical-align:top; overflow-wrap:anywhere; }
  tr:last-child td { border-bottom:none; }
  td.item { width:26%; color:var(--muted); font-weight:600; } td.st { width:80px; text-align:right; }
  tr.warn { background:var(--warn-bg); } tr.error { background:var(--err-bg); }
  .badge { font-size:11px; font-weight:700; padding:2px 8px; border-radius:10px; font-family:Consolas, monospace; }
  .badge.ok { color:var(--ok); border:1px solid var(--ok); } .badge.warn { color:var(--warn); border:1px solid var(--warn); }
  .badge.info { color:var(--muted); border:1px solid var(--border); }
  .badge.error { color:var(--err); border:1px solid var(--err); }
  .footer { padding:14px 40px; color:var(--muted); font-size:11px; border-top:1px solid var(--border); font-family:Consolas, monospace; }
</style>
</head>
<body>
<div class="header">
  <h1>Machine health &mdash; <span>$(& $enc $ComputerName)</span></h1>
  <div class="meta">Generated $generated &bull; thresholds: disk &lt; $MinDiskFreePct% free, uptime &gt; $MaxUptimeDays days, Group Policy older than $MaxGpoAgeHours h, clock offset &gt; $MaxClockOffsetSec s</div>
</div>
<div class="summary $(if ($warnings.Count -gt 0) { 'has-warn' } else { 'all-ok' })">
  <h3>$($warnings.Count) warning(s)</h3>
  $warnHtml
</div>
<div class="content">
$($sb.ToString())
</div>
<div class="footer">Generated by $(& $enc $scriptName) &bull; read-only snapshot</div>
</body>
</html>
"@

# ------------------------- Save + console summary -------------------------

if (-not (Test-Path 'C:\temp')) {
    try { New-Item -ItemType Directory -Path 'C:\temp' -Force -ErrorAction Stop | Out-Null }
    catch { Write-Host "ERROR: could not create C:\temp - $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
}
$safeName = $ComputerName -replace '[\\/:*?"<>|]', '_'
$htmlPath = "C:\temp\MachineHealth_${safeName}_$((Get-Date).ToString('yyyyMMdd_HHmm')).html"

try { $html | Out-File -FilePath $htmlPath -Encoding UTF8 -ErrorAction Stop }
catch { Write-Host "ERROR: could not save report - $($_.Exception.Message)" -ForegroundColor Red; exit 1 }

Write-Host ''
if ($warnings.Count -gt 0) {
    Write-Host "$($warnings.Count) warning(s):" -ForegroundColor Yellow
    foreach ($w in $warnings) { Write-Host "  - $($w.Section) / $($w.Item) - $($w.Value)" -ForegroundColor Yellow }
} else {
    Write-Host 'No warning - all checks within thresholds.' -ForegroundColor Green
}
Write-Host "`nReport saved: $htmlPath" -ForegroundColor Green
Start-Process $htmlPath
exit 0
