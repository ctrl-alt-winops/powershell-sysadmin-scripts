<#
.SYNOPSIS
    Read-only, domain-wide overview of account lockouts over a time window:
    which accounts were locked, by which machine, and which sources kept trying
    to sign in with an account while it was locked. HTML report in C:\temp.

.DESCRIPTION
    Prompts for a look-back window (default 24 h), then reads on every domain
    controller, in parallel, from the Security log:
      4740 = account locked out (gives the "caller computer")
      4771 with status 0x12       = Kerberos sign-in refused, account locked
      4776 with status 0xC0000234 = NTLM sign-in refused, account locked
    Lockouts are reported to the PDC emulator but also logged on the DC that
    locked the account: asking every DC keeps the overview complete even if one
    DC does not answer, and duplicates are merged.

    For each account: number of lockouts, last lockout, caller computer(s),
    attempts while locked and their top sources, and whether it is still locked
    NOW (read from the PDC). Accounts are ranked, the report can be searched and
    filtered to accounts still locked.

    Each DC's Security log is also checked for how far back it actually goes:
    a busy DC may only keep a few hours, so "no event" can mean "already gone".

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

    Run time: each DC filters its own log, so only matching events travel; the
    DC still scans its log over the window (seconds to tens of seconds on a
    busy DC). Events are capped per DC and per query (see Settings).
    Read-only: nothing is changed (no unlock).
    Exit codes: 0 = report written, 1 = aborted / failed.
#>

# ------------------------- Settings -------------------------
$DefaultHours    = 24     # look-back window proposed at the prompt
$MaxEventsPerDc  = 5000   # per event query per DC
$ResolveTopIps   = 20     # reverse-DNS lookups for the most frequent source IPs
$MaxAccountsInAd = 200    # "still locked now" lookups (one AD query per account)
$LockoutsListed  = 200    # latest lockout events listed in the detail table

# ------------------------- Remote block (runs ON EACH DC) -------------------------
# Returns flat rows: one per event + one Meta row per DC.
$QueryLockoutEvents = {
    param([int]$Hours, [int]$Max)

    $ms   = [int64]$Hours * 3600000
    $time = "TimeCreated[timediff(@SystemTime) <= $ms]"
    # The status is stored as text and the filter is case-sensitive: both spellings.
    $locked = "Data[@Name='Status']='0x12' or Data[@Name='Status']='0xc0000234' or Data[@Name='Status']='0xC0000234'"
    $queries = @(
        "*[System[EventID=4740 and $time]]",
        "*[System[(EventID=4771 or EventID=4776) and $time]] and *[EventData[$locked]]"
    )

    $events = @(); $capped = $false; $err = ''
    foreach ($xp in $queries) {
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
            Account = [string]$d['TargetUserName']; Source = [string]$src
        }
    }

    # How far back this DC's Security log goes
    $oldest = try { (Get-WinEvent -LogName Security -MaxEvents 1 -Oldest -ErrorAction Stop).TimeCreated } catch { $null }
    [pscustomobject]@{ RowType = 'Meta'; DC = $env:COMPUTERNAME; Capped = $capped; Error = $err; Oldest = $oldest }
}

# ------------------------- Module + domain -------------------------

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

$h = (Read-Host "Look back how many hours? (Enter = $DefaultHours)").Trim()
$hours = 0
if (-not $h) { $hours = $DefaultHours }
elseif (-not ([int]::TryParse($h, [ref]$hours) -and $hours -ge 1 -and $hours -le 720)) {
    Write-Host "Invalid value - using $DefaultHours h." -ForegroundColor Yellow; $hours = $DefaultHours
}
$windowStart = (Get-Date).AddHours(-$hours)

# ------------------------- Events from every DC (parallel) -------------------------

Write-Host "`nReading lockout events of the last $hours h on $($dcs.Count) DC(s) of $($domain.DNSRoot)..." -ForegroundColor Cyan
$remoteErr = $null
$rows = @(Invoke-Command -ComputerName ($dcs.HostName) -ScriptBlock $QueryLockoutEvents -ArgumentList $hours, $MaxEventsPerDc `
            -ErrorAction SilentlyContinue -ErrorVariable remoteErr)
$metas  = @($rows | Where-Object RowType -eq 'Meta')
$events = @($rows | Where-Object RowType -eq 'Event')

$notes = New-Object System.Collections.Generic.List[string]
foreach ($m in $metas) {
    if ($m.Error)  { $notes.Add("$($m.DC): query error - $($m.Error)") }
    if ($m.Capped) { $notes.Add("$($m.DC): more than $MaxEventsPerDc events for one query - only the newest were read") }
    if ($m.Oldest -and ([datetime]$m.Oldest) -gt $windowStart) {
        $notes.Add("$($m.DC): Security log only goes back to $(([datetime]$m.Oldest).ToString('yyyy-MM-dd HH:mm')) ($([math]::Round(((Get-Date) - [datetime]$m.Oldest).TotalHours, 1)) h) - older events of the window are gone")
    }
}
foreach ($e in @($remoteErr)) {
    if ($e) { $notes.Add("$(if ($e.TargetObject) { $e.TargetObject } else { 'a DC' }): not queried - $($e.Exception.Message)") }
}

# Lockouts: logged on the locking DC AND on the PDC -> de-duplicate
$lockouts = @($events | Where-Object Id -eq 4740 | Sort-Object Time -Descending |
              Group-Object { "$(([datetime]$_.Time).ToString('yyyy-MM-dd HH:mm:ss'))|$(([string]$_.Account).ToLower())|$(([string]$_.Source).ToLower())" } |
              ForEach-Object { $_.Group[0] })
$attempts = @($events | Where-Object Id -ne 4740)

# Reverse DNS for the most frequent source IPs
$ipNames = @{}
if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
    $ips = @($attempts | Where-Object { $_.Source -match '^[0-9a-fA-F.:]+$' -and $_.Source -notin '127.0.0.1', '::1' } |
             Group-Object Source | Sort-Object Count -Descending | Select-Object -First $ResolveTopIps)
    foreach ($ip in $ips) {
        $ptr = Resolve-DnsName -Name $ip.Name -Type PTR -QuickTimeout -DnsOnly -ErrorAction SilentlyContinue | Where-Object NameHost | Select-Object -First 1
        if ($ptr) { $ipNames[$ip.Name] = $ptr.NameHost }
    }
}
$label = { param($s) if (-not $s -or $s -eq '-') { '(none recorded)' } elseif ($ipNames.ContainsKey($s)) { "$s ($($ipNames[$s]))" } else { $s } }

# ------------------------- Per-account summary -------------------------

$accounts = @(@($lockouts) + @($attempts) | Where-Object Account | Group-Object { ([string]$_.Account).ToLower() } | ForEach-Object {
    $lk = @($_.Group | Where-Object Id -eq 4740 | Sort-Object Time -Descending)
    $at = @($_.Group | Where-Object Id -ne 4740)
    [pscustomobject]@{
        Account     = $_.Group[0].Account
        DisplayName = ''
        LockedNow   = '?'
        Lockouts    = $lk.Count
        LastLockout = if ($lk) { ([datetime]$lk[0].Time).ToString('yyyy-MM-dd HH:mm') } else { '-' }
        Callers     = (($lk | Group-Object { ([string]$_.Source).ToLower() } | Sort-Object Count -Descending |
                        ForEach-Object { "$(& $label $_.Group[0].Source) x$($_.Count)" }) -join ', ')
        Attempts    = $at.Count
        TopSources  = (($at | Group-Object { ([string]$_.Source).ToLower() } | Sort-Object Count -Descending | Select-Object -First 5 |
                        ForEach-Object { "$(& $label $_.Group[0].Source) x$($_.Count)" }) -join ', ')
    }
} | Sort-Object @{ e = 'Lockouts'; Descending = $true }, @{ e = 'Attempts'; Descending = $true })

# Still locked NOW? (read from the PDC; one query per account, capped)
$i = 0
foreach ($a in $accounts) {
    if (++$i -gt $MaxAccountsInAd) { break }
    try {
        $u = Get-ADUser -Identity $a.Account -Server $pdc -Properties LockedOut, DisplayName, Enabled -ErrorAction Stop
        $a.DisplayName = [string]$u.DisplayName
        $a.LockedNow   = if ($u.LockedOut) { 'YES' } elseif (-not $u.Enabled) { 'no (disabled)' } else { 'no' }
    } catch { $a.LockedNow = 'not found in AD' }
}
$stillLocked = @($accounts | Where-Object LockedNow -eq 'YES').Count

# ------------------------- Report -------------------------

$enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
$td  = { param($v, $cls) $c = if ($cls) { ' class="' + $cls + '"' } else { '' }; '<td' + $c + '>' + (& $enc $v) + '</td>' }

$sb = New-Object System.Text.StringBuilder
foreach ($a in $accounts) {
    $lockedAttr = if ($a.LockedNow -eq 'YES') { 'yes' } else { 'no' }
    $rowClass   = if ($a.LockedNow -eq 'YES') { ' class="hl"' } else { '' }
    [void]$sb.Append("<tr$rowClass data-locked=`"$lockedAttr`">" +
        (& $td $a.Account 'mono') + (& $td $a.DisplayName) + (& $td $a.LockedNow 'st') + (& $td $a.Lockouts 'num') +
        (& $td $a.LastLockout 'mono') + (& $td $(if ($a.Callers) { $a.Callers } else { '-' })) + (& $td $a.Attempts 'num') +
        (& $td $(if ($a.TopSources) { $a.TopSources } else { '-' })) + "</tr>`n")
}
$accountsHtml = if ($accounts.Count) { $sb.ToString() } else { '' }

$sb2 = New-Object System.Text.StringBuilder
foreach ($l in ($lockouts | Select-Object -First $LockoutsListed)) {
    [void]$sb2.Append('<tr>' + (& $td ([datetime]$l.Time).ToString('yyyy-MM-dd HH:mm:ss') 'mono') + (& $td $l.Account 'mono') +
        (& $td (& $label $l.Source)) + (& $td $l.DC 'mono') + "</tr>`n")
}
$notesHtml = if ($notes.Count) { '<div class="notes"><b>Coverage / notes</b><ul>' + (($notes | ForEach-Object { '<li>' + (& $enc $_) + '</li>' }) -join '') + '</ul></div>' } else { '' }

$js = @'
<script>
(function () {
  'use strict';
  var rows = Array.prototype.slice.call(document.querySelectorAll('#acc tbody tr[data-locked]'));
  var search = document.getElementById('f-search'), count = document.getElementById('f-count');
  var lockedCard = document.getElementById('c-locked'), empty = document.getElementById('f-empty');
  var index = rows.map(function (r) { return (r.textContent || '').toLowerCase(); });
  var onlyLocked = false;
  function apply() {
    var q = search.value.trim().toLowerCase(), shown = 0;
    for (var i = 0; i < rows.length; i++) {
      var ok = (!onlyLocked || rows[i].getAttribute('data-locked') === 'yes') && (!q || index[i].indexOf(q) !== -1);
      rows[i].hidden = !ok; if (ok) { shown++; }
    }
    empty.hidden = shown !== 0 || rows.length === 0;
    count.textContent = 'Showing ' + shown + ' of ' + rows.length + ' account(s)';
    lockedCard.classList.toggle('active', onlyLocked);
  }
  function toggle() { onlyLocked = !onlyLocked; apply(); }
  lockedCard.setAttribute('role', 'button'); lockedCard.setAttribute('tabindex', '0');
  lockedCard.addEventListener('click', toggle);
  lockedCard.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
  var t = null; search.addEventListener('input', function () { clearTimeout(t); t = setTimeout(apply, 150); });
  document.getElementById('toolbar').hidden = false; document.body.classList.add('js'); apply();
})();
</script>
'@

$generated  = (Get-Date).ToString('yyyy-MM-dd HH:mm')
$scriptName = if ($PSCommandPath) { Split-Path $PSCommandPath -Leaf } else { 'Export-ADLockoutReport.ps1' }
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lockout overview - $(& $enc $domain.DNSRoot)</title>
<style>
  :root { --bg:#0d1117; --surface:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e; --accent:#58a6ff; --warn:#d29922; --warn-bg:#2d2208; --err:#f85149; }
  * { box-sizing:border-box; } [hidden] { display:none !important; }
  body { margin:0; background:var(--bg); color:var(--text); font-family:'Segoe UI', system-ui, sans-serif; font-size:14px; }
  .header { padding:28px 40px 18px; border-bottom:1px solid var(--border); }
  h1 { margin:0 0 6px; font-size:22px; } h1 span { color:var(--accent); }
  .meta { color:var(--muted); font-size:12px; font-family:Consolas, monospace; }
  .summary { display:flex; gap:14px; flex-wrap:wrap; padding:18px 40px; }
  .card { flex:1 1 150px; background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:14px 18px; }
  .card .v { font-size:28px; font-weight:700; } .card .l { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; }
  .card.locked .v { color:var(--err); } .js #c-locked { cursor:pointer; user-select:none; }
  .js #c-locked.active { border-color:var(--accent); box-shadow:inset 0 0 0 1px var(--accent); }
  .notes { margin:0 40px 14px; padding:10px 16px; border:1px solid var(--warn); border-radius:8px; color:var(--warn); }
  .notes ul { margin:6px 0 0; padding-left:18px; }
  .toolbar { display:flex; gap:12px; align-items:center; padding:0 40px 14px; flex-wrap:wrap; }
  .toolbar input { flex:1 1 320px; background:var(--surface); color:var(--text); border:1px solid var(--border); border-radius:6px; padding:8px 12px; font-size:13px; }
  .toolbar input:focus { outline:none; border-color:var(--accent); } .f-count { font-family:Consolas, monospace; font-size:12px; color:var(--accent); }
  .content { padding:0 40px 30px; } .wrap { overflow-x:auto; }
  h2 { font-size:15px; color:var(--accent); margin:22px 0 8px; text-transform:uppercase; letter-spacing:0.5px; }
  table { width:100%; border-collapse:collapse; background:var(--surface); border:1px solid var(--border); }
  th { text-align:left; font-size:11px; color:var(--muted); text-transform:uppercase; padding:9px 12px; border-bottom:1px solid var(--border); }
  td { padding:8px 12px; border-bottom:1px solid var(--border); vertical-align:top; overflow-wrap:anywhere; }
  td.mono { font-family:Consolas, monospace; font-size:12px; white-space:nowrap; } td.num { text-align:right; font-weight:600; }
  tr.hl { background:var(--warn-bg); } tr.hl td.st { color:var(--err); font-weight:700; }
  .none { color:var(--muted); padding:16px; text-align:center; }
  .guide { background:var(--surface); border:1px solid var(--border); border-left:4px solid var(--accent); border-radius:8px; padding:12px 18px; margin-top:22px; }
  .footer { padding:14px 40px; color:var(--muted); font-size:11px; border-top:1px solid var(--border); font-family:Consolas, monospace; }
</style>
</head>
<body>
<div class="header">
  <h1>Lockout overview &mdash; <span>$(& $enc $domain.DNSRoot)</span></h1>
  <div class="meta">Last $hours h (since $($windowStart.ToString('yyyy-MM-dd HH:mm'))) &bull; $($dcs.Count) DC(s) &bull; generated $generated &bull; read-only</div>
</div>
<div class="summary">
  <div class="card"><div class="l">Accounts</div><div class="v">$($accounts.Count)</div></div>
  <div class="card"><div class="l">Lockouts</div><div class="v">$($lockouts.Count)</div></div>
  <div class="card locked" id="c-locked" title="Click to show only accounts still locked"><div class="l">Still locked now</div><div class="v">$stillLocked</div></div>
  <div class="card"><div class="l">Attempts while locked</div><div class="v">$($attempts.Count)</div></div>
</div>
$notesHtml
<div class="toolbar" id="toolbar" hidden>
  <input type="search" id="f-search" placeholder="Search: account, name, computer, IP..." autocomplete="off">
  <span class="f-count" id="f-count"></span>
</div>
<div class="content">
<h2>Accounts</h2>
<div class="wrap"><table id="acc">
<thead><tr><th>Account</th><th>Name</th><th>Locked now</th><th>Lockouts</th><th>Last lockout</th><th>Caller computer(s)</th><th>Attempts while locked</th><th>Top attempt sources</th></tr></thead>
<tbody>
$accountsHtml<tr id="f-empty" hidden><td colspan="8" class="none">No account matches the current filters.</td></tr>
</tbody></table></div>
$(if ($accounts.Count -eq 0) { "<p class=`"none`">No lockout and no attempt on a locked account in the last $hours h.</p>" })
<h2>Lockout events (latest $LockoutsListed)</h2>
<div class="wrap"><table>
<thead><tr><th>Time</th><th>Account</th><th>Caller computer</th><th>Logged on DC</th></tr></thead>
<tbody>
$($sb2.ToString())</tbody></table></div>
<div class="guide">
  A server as caller / source (mail, VPN / RADIUS, web sign-in) usually hides a phone or VPN client with an old password.
</div>
</div>
<div class="footer">Generated by $(& $enc $scriptName) &bull; read-only overview</div>
$js
</body>
</html>
"@

try {
    if (-not (Test-Path 'C:\temp')) { New-Item -ItemType Directory -Path 'C:\temp' -Force -ErrorAction Stop | Out-Null }
    $path = "C:\temp\ADLockout_Overview_$((Get-Date).ToString('yyyyMMdd_HHmm')).html"
    $html | Out-File -FilePath $path -Encoding UTF8 -ErrorAction Stop
}
catch { Write-Host "ERROR: could not save the report - $($_.Exception.Message)" -ForegroundColor Red; exit 1 }

# ------------------------- Console summary -------------------------

Write-Host ''
Write-Host ("{0} account(s), {1} lockout(s), {2} attempt(s) while locked, {3} still locked now" -f $accounts.Count, $lockouts.Count, $attempts.Count, $stillLocked) `
    -ForegroundColor $(if ($stillLocked) { 'Red' } elseif ($accounts.Count) { 'Yellow' } else { 'Green' })
foreach ($a in ($accounts | Select-Object -First 5)) {
    Write-Host ("  {0,-20} locked now: {1,-4} lockouts: {2,-3} attempts: {3,-5} caller: {4}" -f $a.Account, $a.LockedNow, $a.Lockouts, $a.Attempts, $(if ($a.Callers) { $a.Callers } else { '-' })) `
        -ForegroundColor $(if ($a.LockedNow -eq 'YES') { 'Red' } else { 'Gray' })
}
foreach ($n in $notes) { Write-Host "  Note: $n" -ForegroundColor DarkYellow }
Write-Host "`nReport: $path" -ForegroundColor Green
Start-Process $path
exit 0
