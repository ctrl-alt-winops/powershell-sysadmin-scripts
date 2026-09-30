<#
.SYNOPSIS
    Read-only investigation of an Active Directory account's failed sign-ins:
    lockouts, bad or expired passwords, clock skew... Shows the account status,
    where the failures come from, and (optionally) what on the top source
    machine still uses the old password. HTML report in C:\temp.

.DESCRIPTION
    Prompts for the user and a look-back window, then:
      1. Account status (from the PDC emulator): enabled, locked out, lockout
         time, password last set / expiry, and the lockout policy that applies
         (fine-grained password policy if any, else the domain policy).
      2. Bad-password count and last bad password per DC (this counter is not
         replicated, so every DC is asked).
      3. On every DC, in parallel, from the Security log:
           4740 = account locked out  (gives the "caller computer")
           4771 = Kerberos pre-authentication failed (gives the client IP)
           4776 = NTLM credential validation failed (gives the workstation)
         4740/4771 are matched on the user's SID; 4776 (no SID) on the name.
      4. Failure sources ranked by count, IPs resolved to names (DNS), with a
         hint for common patterns.
      5. Optional (YES/NO): on the top source machine, services and scheduled
         tasks running as the user, the user's open sessions, and persistent
         mapped drives (flagging drives mapped with explicit credentials).

    Typical readings:
      - Source = a server (mail, VPN / RADIUS, web sign-in): the real client is
        behind it, usually a phone mail app or VPN client with an old password.
      - Source = a workstation: saved credential, mapped drive, service, task or
        an old session there with the old password.
      - No source recorded: often a device outside the domain, or an app doing
        NTLM without sending a workstation name.

.NOTES
    Requirements:
    - RSAT ActiveDirectory module on this machine
      (Windows 10/11: Settings > Optional features > "RSAT: Active Directory
      Domain Services and Lightweight Directory Services Tools").
    - Rights to read the Security log on the DCs: Domain Admins, or membership
      of "Event Log Readers" on the DCs plus WinRM access to them.
    - WinRM on the DCs (enabled by default on Windows Server 2012 and later).
    - DC audit policy: 4740 needs "Audit User Account Management" (success);
      4771 / 4776 need FAILURE auditing of "Kerberos Authentication Service" and
      "Credential Validation". Without it those events simply do not exist.
    - Step 5 (optional): admin rights + WinRM on the source machine.

    NTLM failures (4776) carry no SID and the event filter is case-sensitive: they
    are matched on the name as stored in AD, in lower and in upper case. A client
    that sends an unusual casing (e.g. "JDoe" for jdoe) is not matched. Kerberos
    (4771) and lockout (4740) events are matched on the SID and are not affected.
    Saved passwords in Credential Manager cannot be read remotely (they are
    encrypted per user); the report explains how to check them on the machine.
    Read-only: nothing is changed (no unlock, no reset).
    Exit codes: 0 = report written, 1 = aborted / failed.
#>

# ------------------------- Settings -------------------------
$DefaultHours   = 24     # look-back window proposed at the prompt
$MaxEventsPerDc = 5000   # per event query per DC (a broken phone can generate thousands)
$ResolveTopIps  = 10     # reverse-DNS lookups for the top N source IPs
$LatestListed   = 50     # latest failure events listed in the report

# Status codes of 4771 (Kerberos) and 4776 (NTLM), lower case
$StatusText = @{
    '0x18' = 'bad password';  '0x12' = 'account locked / disabled';  '0x17' = 'password expired'
    '0x25' = 'clock skew too large';  '0x6' = 'unknown user'
    '0xc000006a' = 'bad password';  '0xc0000234' = 'account locked';  '0xc0000064' = 'unknown user'
    '0xc0000071' = 'password expired';  '0xc0000072' = 'account disabled';  '0xc000006f' = 'outside logon hours'
    '0xc0000070' = 'workstation not allowed';  '0xc0000193' = 'account expired';  '0xc0000224' = 'must change password'
}

# ------------------------- Remote blocks -------------------------

# Runs ON EACH DC. Returns flat rows: one per event + one Meta row per DC.
$QueryAuthEvents = {
    param([string]$Sid, [string[]]$Names, [int]$Hours, [int]$Max)

    $ms = [int64]$Hours * 3600000
    # XPath string literal: single quotes, or double quotes if the value contains one
    $q = { param($v) if ($v -like "*'*") { '"' + $v + '"' } else { "'" + $v + "'" } }
    $bySid  = "*[System[(EventID=4740 or EventID=4771) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[Data[@Name='TargetSid']=$(& $q $Sid)]]"
    $byName = "*[System[EventID=4776 and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[" +
              (($Names | ForEach-Object { "Data[@Name='TargetUserName']=$(& $q $_)" }) -join ' or ') + ']]'

    $events = @(); $capped = $false; $err = ''
    foreach ($xp in $bySid, $byName) {
        try {
            $r = @(Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents $Max -ErrorAction Stop)
            if ($r.Count -ge $Max) { $capped = $true }
            $events += $r
        }
        catch {
            # "No events found" is a normal empty result, any other error is reported
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' -and $_.Exception.Message -notlike '*No events were found*') { $err = $_.Exception.Message }
        }
    }

    foreach ($e in $events) {
        $d = @{}
        foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' }
        $src = switch ($e.Id) {
            4740 { $d['TargetDomainName'] }                      # "Caller Computer Name" is stored in this field
            4771 { $d['IpAddress'] -replace '^::ffff:', '' }
            4776 { $d['Workstation'] }
        }
        [pscustomobject]@{
            RowType = 'Event'; DC = $env:COMPUTERNAME; Time = $e.TimeCreated; Id = $e.Id
            Source  = [string]$src; Status = $(if ($e.Id -eq 4740) { 'locked out' } else { [string]$d['Status'] })
        }
    }
    [pscustomobject]@{ RowType = 'Meta'; DC = $env:COMPUTERNAME; Capped = $capped; Error = $err }
}

# Runs ON THE SOURCE MACHINE (optional step). Flat rows Section / Item / Value / Flag.
$CheckSource = {
    param([string]$Sam, [string]$Sid)

    $me = "(^|\\)$([regex]::Escape($Sam))$|^$([regex]::Escape($Sam))@"
    function ConvertTo-CheckRow { param([string]$Section, [string]$Item, [string]$Value, [bool]$Flag = $false)
        [pscustomobject]@{ Section = $Section; Item = $Item; Value = $Value; Flag = $Flag } }

    try {
        $svc = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Where-Object { $_.StartName -match $me })
        foreach ($s in $svc) { ConvertTo-CheckRow -Section 'Services running as the user' -Item $s.Name -Value "$($s.DisplayName) - $($s.State)" -Flag $true }
        if (-not $svc) { ConvertTo-CheckRow -Section 'Services running as the user' -Item '-' -Value 'none' }
    } catch { ConvertTo-CheckRow -Section 'Services running as the user' -Item 'Error' -Value $_.Exception.Message }

    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.Principal.UserId -match $me -or $_.Principal.UserId -eq $Sid })
        foreach ($t in $tasks) { ConvertTo-CheckRow -Section 'Scheduled tasks running as the user' -Item "$($t.TaskPath)$($t.TaskName)" -Value "$($t.State)" -Flag $true }
        if (-not $tasks) { ConvertTo-CheckRow -Section 'Scheduled tasks running as the user' -Item '-' -Value 'none' }
    } catch { ConvertTo-CheckRow -Section 'Scheduled tasks running as the user' -Item 'Error' -Value $_.Exception.Message }

    try {
        $sessions = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop | Where-Object {
            $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue; $o -and $o.User -eq $Sam })
        foreach ($p in $sessions) { ConvertTo-CheckRow -Section "User's sessions on this machine" -Item "session $($p.SessionId)" -Value "open since $($p.CreationDate.ToString('yyyy-MM-dd HH:mm')) - an old session keeps using the old password" -Flag $true }
        if (-not $sessions) { ConvertTo-CheckRow -Section "User's sessions on this machine" -Item '-' -Value 'none' }
    } catch { ConvertTo-CheckRow -Section "User's sessions on this machine" -Item 'Error' -Value $_.Exception.Message }

    $net = "Registry::HKEY_USERS\$Sid\Network"
    if (Test-Path -LiteralPath "Registry::HKEY_USERS\$Sid") {
        $drives = @(Get-ChildItem -LiteralPath $net -ErrorAction SilentlyContinue)
        foreach ($k in $drives) {
            $v = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
            $explicit = [bool]$v.UserName
            ConvertTo-CheckRow -Section 'Persistent mapped drives (user profile)' -Item "$($k.PSChildName):" `
                -Value ("$($v.RemotePath)" + $(if ($explicit) { " - mapped WITH explicit credentials ($($v.UserName)): a stored password" } else { '' })) -Flag $explicit
        }
        if (-not $drives) { ConvertTo-CheckRow -Section 'Persistent mapped drives (user profile)' -Item '-' -Value 'none' }
    }
    else { ConvertTo-CheckRow -Section 'Persistent mapped drives (user profile)' -Item '-' -Value 'not checked: the user profile is not loaded (user not logged on here)' }
}

# ------------------------- Local helpers -------------------------

function Confirm-YesNo {
    do { $a = (Read-Host 'CONTINUE : YES\NO').Trim().ToUpper() } while ($a -notin 'YES', 'NO')
    return ($a -eq 'YES')
}

function Get-StatusText {
    param([string]$Code)
    $c = $Code.ToLower()
    if ($StatusText.ContainsKey($c)) { return $StatusText[$c] }
    return $Code
}

# ------------------------- Module + user -------------------------

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host 'ERROR: the ActiveDirectory module (RSAT) is not installed on this machine.' -ForegroundColor Red
    Write-Host '       Windows 10/11: Settings > Optional features > add "RSAT: Active Directory Domain Services and Lightweight Directory Services Tools".' -ForegroundColor Yellow
    exit 1
}
try   { Import-Module ActiveDirectory -ErrorAction Stop }
catch { Write-Host "ERROR: could not load the ActiveDirectory module: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }

try {
    $domain = Get-ADDomain -ErrorAction Stop
    $pdc    = $domain.PDCEmulator
    $dcs    = @(Get-ADDomainController -Filter * -ErrorAction Stop | Sort-Object HostName)
}
catch { Write-Host "ERROR: could not read the domain / domain controllers: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }

$props = 'Enabled', 'LockedOut', 'AccountLockoutTime', 'PasswordLastSet', 'PasswordNeverExpires', 'msDS-UserPasswordExpiryTimeComputed', 'DisplayName', 'UserPrincipalName'
$user = $null
while (-not $user) {
    $in = (Read-Host 'User (sAMAccountName, DOMAIN\user or UPN; blank = quit)').Trim()
    if (-not $in) { Write-Host 'No user - nothing done.' -ForegroundColor Yellow; exit 1 }
    try {
        $user = if ($in -like '*@*') {
                    Get-ADUser -Filter "UserPrincipalName -eq '$($in -replace "'", "''")'" -Server $pdc -Properties $props -ErrorAction Stop | Select-Object -First 1
                } else {
                    Get-ADUser -Identity (($in -split '\\')[-1]) -Server $pdc -Properties $props -ErrorAction Stop
                }
    } catch { $user = $null }
    if (-not $user) { Write-Host "ERROR: '$in' not found in $($domain.DNSRoot). Try again." -ForegroundColor Red }
}
$sam = $user.SamAccountName
$sid = $user.SID.Value

$h = (Read-Host "Look back how many hours? (Enter = $DefaultHours)").Trim()
$hours = 0
if (-not $h) { $hours = $DefaultHours }
elseif (-not ([int]::TryParse($h, [ref]$hours) -and $hours -ge 1 -and $hours -le 720)) {
    Write-Host "Invalid value - using $DefaultHours h." -ForegroundColor Yellow; $hours = $DefaultHours
}

# ------------------------- 1. Account status + policy -------------------------

Write-Host "`nAccount '$sam' ($($user.DisplayName)) - domain $($domain.DNSRoot), PDC $pdc" -ForegroundColor Cyan
$status = [ordered]@{}
$status['Enabled']          = if ($user.Enabled) { 'Yes' } else { 'NO (disabled)' }
$status['Locked out']       = if ($user.LockedOut) { "YES - since $($user.AccountLockoutTime)" } else { 'No' }
$status['Password last set'] = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('yyyy-MM-dd HH:mm') } else { 'never / must change at next logon' }
$exp = $user.'msDS-UserPasswordExpiryTimeComputed'
$status['Password expires'] = if ($user.PasswordNeverExpires) { 'never (password never expires)' }
                              elseif ($exp -and $exp -gt 0 -and $exp -lt [int64]::MaxValue) { [DateTime]::FromFileTime($exp).ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
try {
    $pol = Get-ADUserResultantPasswordPolicy -Identity $user -Server $pdc -ErrorAction Stop
    $polName = if ($pol) { "fine-grained policy '$($pol.Name)'" } else { 'domain policy' }
    if (-not $pol) { $pol = Get-ADDefaultDomainPasswordPolicy -Server $pdc -ErrorAction Stop }
    $status['Lockout policy'] = if ($pol.LockoutThreshold -eq 0) { "$polName - no lockout (threshold 0)" } else {
        "$polName - locks after $($pol.LockoutThreshold) bad passwords within $($pol.LockoutObservationWindow.TotalMinutes) min, for $(if ($pol.LockoutDuration.TotalMinutes -eq 0) { 'ever (until an admin unlocks)' } else { "$($pol.LockoutDuration.TotalMinutes) min" })" }
} catch { $status['Lockout policy'] = "could not read ($($_.Exception.Message))" }

# ------------------------- 2. Bad-password counter per DC -------------------------

$perDc = foreach ($dc in $dcs) {
    try {
        $u = Get-ADUser -Identity $sam -Server $dc.HostName -Properties badPwdCount, badPasswordTime -ErrorAction Stop
        [pscustomobject]@{ DC = $dc.HostName; Count = [int]$u.badPwdCount
                           Last = $(if ($u.badPasswordTime -gt 0) { [DateTime]::FromFileTime($u.badPasswordTime).ToString('yyyy-MM-dd HH:mm:ss') } else { 'never' }) }
    } catch { [pscustomobject]@{ DC = $dc.HostName; Count = $null; Last = "unreachable: $($_.Exception.Message)" } }
}

# ------------------------- 3. Events on every DC (parallel) -------------------------

$names = @($sam, $sam.ToLower(), $sam.ToUpper()) | Select-Object -Unique    # 4776 name match is case-sensitive
Write-Host "Reading lockout / failed-authentication events of the last $hours h on $($dcs.Count) DC(s)..." -ForegroundColor Cyan
$remoteErr = $null
$rows = @(Invoke-Command -ComputerName ($dcs.HostName) -ScriptBlock $QueryAuthEvents -ArgumentList $sid, $names, $hours, $MaxEventsPerDc `
            -ErrorAction SilentlyContinue -ErrorVariable remoteErr)
$metas  = @($rows | Where-Object RowType -eq 'Meta')
$events = @($rows | Where-Object RowType -eq 'Event')
$dcNotes = New-Object System.Collections.Generic.List[string]
foreach ($m in $metas) {
    if ($m.Error)  { $dcNotes.Add("$($m.DC): query error - $($m.Error)") }
    if ($m.Capped) { $dcNotes.Add("$($m.DC): more than $MaxEventsPerDc events - only the newest were read") }
}
foreach ($e in @($remoteErr)) {
    if ($e) { $dcNotes.Add("$(if ($e.TargetObject) { $e.TargetObject } else { 'a DC' }): not queried - $($e.Exception.Message)") }
}

# Lockouts (4740): logged on the DC that locked AND on the PDC -> de-duplicate
$lockouts = @($events | Where-Object Id -eq 4740 | Sort-Object Time -Descending |
              Group-Object { "$(([datetime]$_.Time).ToString('yyyy-MM-dd HH:mm:ss'))|$($_.Source)" } | ForEach-Object { $_.Group[0] })

# Failures (4771 / 4776), ranked by source
$failures = @($events | Where-Object Id -ne 4740)
$dcHosts  = @($dcs | ForEach-Object { $_.Name.ToLower(); $_.HostName.ToLower(); [string]$_.IPv4Address })
$ranked = @($failures | Group-Object { ([string]$_.Source).ToLower() } | ForEach-Object {
    $g = $_.Group | Sort-Object Time
    [pscustomobject]@{
        Source   = $g[0].Source
        Count    = $_.Count
        First    = ([datetime]$g[0].Time).ToString('yyyy-MM-dd HH:mm')
        Last     = ([datetime]$g[-1].Time).ToString('yyyy-MM-dd HH:mm')
        DCs      = (($g.DC | Select-Object -Unique) -join ', ')
        Statuses = (($g | Group-Object Status | ForEach-Object { "$(Get-StatusText $_.Name) x$($_.Count)" }) -join ', ')
        Name     = ''
        Hint     = ''
    }
} | Sort-Object Count -Descending)

# Reverse DNS for the top source IPs; hints for known patterns
$canResolve = [bool](Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)
foreach ($r in ($ranked | Select-Object -First $ResolveTopIps)) {
    if ($canResolve -and $r.Source -match '^[0-9a-fA-F.:]+$' -and $r.Source -notin '127.0.0.1', '::1') {
        $ptr = Resolve-DnsName -Name $r.Source -Type PTR -QuickTimeout -DnsOnly -ErrorAction SilentlyContinue | Where-Object NameHost | Select-Object -First 1
        if ($ptr) { $r.Name = $ptr.NameHost }
    }
}
foreach ($r in $ranked) {
    $s = ([string]$r.Source).ToLower(); $n = ([string]$r.Name).ToLower()
    $r.Hint = if (-not $s -or $s -eq '-') { 'no source recorded: often a device outside the domain, or an app doing NTLM without a workstation name' }
              elseif ($s -in '127.0.0.1', '::1' -or $s -in $dcHosts -or ($n -and ($n -in $dcHosts -or ($n -split '\.')[0] -in $dcHosts))) { 'a domain controller itself: authentication relayed by a service on that DC' }
              else { '' }
}

# ------------------------- 4. Optional: check the top source machine -------------------------

$check = @(); $checked = ''
$top = $ranked | Where-Object { $_.Source -and $_.Source -ne '-' -and -not $_.Hint } | Select-Object -First 1
if (-not $top) { $top = $lockouts | Where-Object { $_.Source } | ForEach-Object { [pscustomobject]@{ Source = $_.Source; Name = '' } } | Select-Object -First 1 }
if ($top) {
    $target = if ($top.Name) { $top.Name } else { $top.Source }
    Write-Host ''
    Write-Host "Top source: $target. Check it for services, scheduled tasks, sessions and mapped drives using '$sam' (read-only) ?" -ForegroundColor Cyan
    if (Confirm-YesNo) {
        try {
            Test-WSMan -ComputerName $target -ErrorAction Stop | Out-Null
            $check = @(Invoke-Command -ComputerName $target -ScriptBlock $CheckSource -ArgumentList $sam, $sid -ErrorAction Stop)
            $checked = $target
        }
        catch { Write-Host "Could not check '$target': $($_.Exception.Message)" -ForegroundColor Yellow; $checked = "$target (not reachable: $($_.Exception.Message))" }
    }
}

# ------------------------- Report -------------------------

$enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
function ConvertTo-HtmlTable {
    param([string[]]$Headers, [object[]]$Rows, [scriptblock]$Cells, [string]$Empty)
    if (-not $Rows -or $Rows.Count -eq 0) { return "<p class=`"none`">$(& $enc $Empty)</p>" }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table><thead><tr>' + (($Headers | ForEach-Object { "<th>$(& $enc $_)</th>" }) -join '') + '</tr></thead><tbody>')
    foreach ($r in $Rows) { [void]$sb.Append((& $Cells $r)) }
    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}
$td = { param($v, $cls) $c = if ($cls) { ' class="' + $cls + '"' } else { '' }; '<td' + $c + '>' + (& $enc $v) + '</td>' }

$statusHtml = ConvertTo-HtmlTable -Headers 'Item', 'Value' -Rows @($status.GetEnumerator()) -Empty '' -Cells {
    param($r) $bad = ($r.Key -eq 'Locked out' -and $r.Value -like 'YES*') -or ($r.Key -eq 'Enabled' -and $r.Value -like 'NO*')
    "<tr$(if ($bad) { ' class="hl"' })>$(& $td $r.Key 'item')$(& $td $r.Value)</tr>" }
$perDcHtml = ConvertTo-HtmlTable -Headers 'Domain controller', 'Bad-password count', 'Last bad password' -Rows $perDc -Empty 'no DC' -Cells {
    param($r) "<tr$(if ($r.Count -gt 0) { ' class="hl"' })>$(& $td $r.DC 'mono')$(& $td $r.Count)$(& $td $r.Last)</tr>" }
$lockHtml = ConvertTo-HtmlTable -Headers 'Time', 'Caller computer', 'Logged on DC' -Rows $lockouts -Empty "No lockout event (4740) in the last $hours h." -Cells {
    param($r) "<tr>$(& $td ([datetime]$r.Time).ToString('yyyy-MM-dd HH:mm:ss') 'mono')$(& $td $(if ($r.Source) { $r.Source } else { '(none recorded)' }))$(& $td $r.DC 'mono')</tr>" }
$rankHtml = ConvertTo-HtmlTable -Headers 'Source', 'Name (DNS)', 'Failures', 'First', 'Last', 'Seen on DC', 'Status', 'Hint' -Rows $ranked `
    -Empty "No failed authentication (4771 / 4776) in the last $hours h - if the user IS being locked out, check that failure auditing is enabled on the DCs." -Cells {
    param($r) "<tr$(if (-not $r.Hint) { ' class="hl"' })>$(& $td $(if ($r.Source) { $r.Source } else { '(none)' }) 'mono')$(& $td $r.Name 'mono')$(& $td $r.Count)$(& $td $r.First 'mono')$(& $td $r.Last 'mono')$(& $td $r.DCs 'mono')$(& $td $r.Statuses)$(& $td $r.Hint)</tr>" }
$latest = @($failures | Sort-Object Time -Descending | Select-Object -First $LatestListed)
$latestHtml = ConvertTo-HtmlTable -Headers 'Time', 'Event', 'Source', 'Status', 'DC' -Rows $latest -Empty 'none' -Cells {
    param($r) "<tr>$(& $td ([datetime]$r.Time).ToString('yyyy-MM-dd HH:mm:ss') 'mono')$(& $td $(if ($r.Id -eq 4771) { '4771 Kerberos' } else { '4776 NTLM' }))$(& $td $r.Source 'mono')$(& $td (Get-StatusText $r.Status))$(& $td $r.DC 'mono')</tr>" }
$checkHtml = if ($check.Count -gt 0) {
    ConvertTo-HtmlTable -Headers 'What', 'Item', 'Details' -Rows $check -Empty '' -Cells {
        param($r) "<tr$(if ($r.Flag) { ' class="hl"' })>$(& $td $r.Section 'item')$(& $td $r.Item 'mono')$(& $td $r.Value)</tr>" }
} elseif ($checked) { "<p class=`"none`">$(& $enc $checked)</p>" } else { '<p class="none">Not checked.</p>' }
$notesHtml = if ($dcNotes.Count) { '<ul class="notes">' + (($dcNotes | ForEach-Object { "<li>$(& $enc $_)</li>" }) -join '') + '</ul>' } else { '' }

$generated  = (Get-Date).ToString('yyyy-MM-dd HH:mm')
$scriptName = if ($PSCommandPath) { Split-Path $PSCommandPath -Leaf } else { 'Export-ADSignInFailureReport.ps1' }
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Account - $(& $enc $sam)</title>
<style>
  :root { --bg:#0d1117; --surface:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e; --accent:#58a6ff; --warn:#d29922; --warn-bg:#2d2208; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font-family:'Segoe UI', system-ui, sans-serif; font-size:14px; }
  .header { padding:28px 40px 18px; border-bottom:1px solid var(--border); }
  h1 { margin:0 0 6px; font-size:22px; } h1 span { color:var(--accent); }
  .meta { color:var(--muted); font-size:12px; font-family:Consolas, monospace; }
  .content { padding:0 40px 30px; }
  h2 { font-size:15px; color:var(--accent); margin:26px 0 8px; text-transform:uppercase; letter-spacing:0.5px; }
  .wrap { overflow-x:auto; }
  table { width:100%; border-collapse:collapse; background:var(--surface); border:1px solid var(--border); }
  th { text-align:left; font-size:11px; color:var(--muted); text-transform:uppercase; padding:9px 12px; border-bottom:1px solid var(--border); }
  td { padding:8px 12px; border-bottom:1px solid var(--border); vertical-align:top; overflow-wrap:anywhere; }
  td.item { color:var(--muted); font-weight:600; width:24%; } td.mono { font-family:Consolas, monospace; font-size:12px; }
  tr.hl { background:var(--warn-bg); }
  .none { color:var(--muted); padding:8px 0; } .notes { color:var(--warn); margin:8px 0 0; }
  .guide { background:var(--surface); border:1px solid var(--border); border-left:4px solid var(--accent); border-radius:8px; padding:12px 18px; }
  .guide li { margin:4px 0; }
  .footer { padding:14px 40px; color:var(--muted); font-size:11px; border-top:1px solid var(--border); font-family:Consolas, monospace; }
</style>
</head>
<body>
<div class="header">
  <h1>Account investigation &mdash; <span>$(& $enc $sam)</span></h1>
  <div class="meta">$(& $enc $user.DisplayName) &bull; $(& $enc $domain.DNSRoot) &bull; last $hours h &bull; generated $generated &bull; read-only</div>
</div>
<div class="content">
<h2>Account status</h2><div class="wrap">$statusHtml</div>
<h2>Bad-password counter per DC</h2><div class="wrap">$perDcHtml</div>
<h2>Lockout events (4740)</h2><div class="wrap">$lockHtml</div>
<h2>Failure sources (4771 Kerberos / 4776 NTLM), ranked</h2><div class="wrap">$rankHtml</div>$notesHtml
<h2>Source machine check</h2><div class="wrap">$checkHtml</div>
<p class="none">Saved passwords in Credential Manager cannot be read remotely: on the source machine, as the user, run <b>cmdkey /list</b> (or Control Panel &gt; Credential Manager).</p>
<h2>Latest $LatestListed failures</h2><div class="wrap">$latestHtml</div>
<h2>How to read this</h2>
<div class="guide"><ul>
  <li><b>Source is a server</b> (mail, VPN / RADIUS, web sign-in): the real client is behind it - usually a phone mail app or a VPN client still using the old password.</li>
  <li><b>Source is a workstation</b>: a saved credential, mapped drive, service, scheduled task or an old session there still uses the old password.</li>
  <li><b>No source recorded</b>: often a device outside the domain, or an application doing NTLM without sending a workstation name.</li>
  <li>No 4771 / 4776 at all while the account keeps locking: failure auditing is probably not enabled on the DCs.</li>
</ul></div>
</div>
<div class="footer">Generated by $(& $enc $scriptName) &bull; read-only investigation</div>
</body>
</html>
"@

try {
    if (-not (Test-Path 'C:\temp')) { New-Item -ItemType Directory -Path 'C:\temp' -Force -ErrorAction Stop | Out-Null }
    $path = "C:\temp\ADAccount_$($sam -replace '[\\/:*?"<>|]', '_')_$((Get-Date).ToString('yyyyMMdd_HHmm')).html"
    $html | Out-File -FilePath $path -Encoding UTF8 -ErrorAction Stop
}
catch { Write-Host "ERROR: could not save the report - $($_.Exception.Message)" -ForegroundColor Red; exit 1 }

# ------------------------- Console summary -------------------------

Write-Host ''
Write-Host "Locked out     : $($status['Locked out'])" -ForegroundColor $(if ($user.LockedOut) { 'Red' } else { 'Green' })
Write-Host "Lockout events : $($lockouts.Count) in the last $hours h$(if ($lockouts) { " - latest caller: $(if ($lockouts[0].Source) { $lockouts[0].Source } else { '(none recorded)' })" })"
Write-Host "Failures       : $($failures.Count) from $($ranked.Count) source(s)"
foreach ($r in ($ranked | Select-Object -First 3)) {
    Write-Host ("  {0,5} x  {1}{2}{3}" -f $r.Count, $(if ($r.Source) { $r.Source } else { '(none)' }), $(if ($r.Name) { " ($($r.Name))" }), $(if ($r.Hint) { " - $($r.Hint)" })) -ForegroundColor Yellow
}
foreach ($n in $dcNotes) { Write-Host "  Note: $n" -ForegroundColor DarkYellow }
foreach ($c in ($check | Where-Object Flag)) { Write-Host "  FOUND on $checked : $($c.Section) - $($c.Item) $($c.Value)" -ForegroundColor Red }
Write-Host "`nReport: $path" -ForegroundColor Green
Start-Process $path
exit 0
