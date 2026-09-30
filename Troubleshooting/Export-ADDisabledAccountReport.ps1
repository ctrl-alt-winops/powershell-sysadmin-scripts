<#
.SYNOPSIS
    Lists every disabled Active Directory user account with basic information,
    in a searchable HTML report (C:\temp).

.DESCRIPTION
    Read-only. For each disabled user account: username, display name, UPN,
    description, OU, created, last logon, password last set, last modified and
    the number of groups it is still a member of.

    Built-in accounts disabled by design (krbtgt, Guest, DefaultAccount,
    WDAGUtilityAccount) are kept in the list and marked "built-in".

    Notes on the dates:
      - Last logon comes from lastLogonTimestamp: replicated between DCs but
        only updated about every 14 days, so it is approximate.
      - Last modified is the last change of ANY attribute of the account. AD
        does not store the date an account was disabled; this is the closest
        cheap value, not an exact disable date.

.NOTES
    Requirements:
    - RSAT ActiveDirectory module on this machine
      (Windows 10/11: Settings > Optional features > "RSAT: Active Directory
      Domain Services and Lightweight Directory Services Tools").
    - Any domain account can read these attributes (no admin right needed).

    Read-only: nothing is changed.
    Exit codes: 0 = report written, 1 = failed.
#>

# RIDs of built-in accounts that are disabled by design
$BuiltInRids = @{ 501 = 'Guest'; 502 = 'krbtgt'; 503 = 'DefaultAccount'; 504 = 'WDAGUtilityAccount' }

# ------------------------- Module + query -------------------------

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host 'ERROR: the ActiveDirectory module (RSAT) is not installed on this machine.' -ForegroundColor Red
    Write-Host '       Windows 10/11: Settings > Optional features > add "RSAT: Active Directory Domain Services and Lightweight Directory Services Tools".' -ForegroundColor Yellow
    exit 1
}
try   { Import-Module ActiveDirectory -ErrorAction Stop }
catch { Write-Host "ERROR: could not load the ActiveDirectory module: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }

try {
    $domain = Get-ADDomain -ErrorAction Stop
    Write-Host "Reading disabled user accounts in $($domain.DNSRoot)..." -ForegroundColor Cyan
    $props = 'DisplayName', 'UserPrincipalName', 'Description', 'whenCreated', 'whenChanged', 'LastLogonDate', 'PasswordLastSet', 'MemberOf'
    $users = @(Get-ADUser -Filter 'Enabled -eq $false' -Properties $props -ErrorAction Stop)
}
catch { Write-Host "ERROR: could not read AD: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }

# ------------------------- Shape the rows -------------------------

$fmt = { param($d) if ($d) { ([datetime]$d).ToString('yyyy-MM-dd') } else { '-' } }
$rows = @($users | ForEach-Object {
    $rid = [int](($_.SID.Value -split '-')[-1])
    # OU = the distinguished name without the account's own "CN=...," part
    $ou  = ($_.DistinguishedName -replace '^CN=(\\,|[^,])+,', '')
    [pscustomobject]@{
        Username     = $_.SamAccountName
        DisplayName  = [string]$_.DisplayName
        UPN          = [string]$_.UserPrincipalName
        Description  = [string]$_.Description
        OU           = $ou
        Created      = & $fmt $_.whenCreated
        LastLogon    = if ($_.LastLogonDate) { & $fmt $_.LastLogonDate } else { 'never' }
        PasswordSet  = if ($_.PasswordLastSet) { & $fmt $_.PasswordLastSet } else { 'never' }
        LastModified = & $fmt $_.whenChanged
        Groups       = @($_.MemberOf).Count
        BuiltIn      = $BuiltInRids.ContainsKey($rid)
    }
} | Sort-Object Username)

$inGroups = @($rows | Where-Object { $_.Groups -gt 0 -and -not $_.BuiltIn }).Count

# ------------------------- Report -------------------------

$enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
$td  = { param($v, $cls) $c = if ($cls) { ' class="' + $cls + '"' } else { '' }; '<td' + $c + '>' + (& $enc $v) + '</td>' }

$sb = New-Object System.Text.StringBuilder
foreach ($r in $rows) {
    $user = (& $enc $r.Username) + $(if ($r.BuiltIn) { ' <span class="badge">built-in</span>' } else { '' })
    [void]$sb.Append('<tr><td class="mono">' + $user + '</td>' + (& $td $r.DisplayName) + (& $td $r.UPN 'mono') + (& $td $r.Description) +
        (& $td $r.OU 'ou') + (& $td $r.Created 'mono') + (& $td $r.LastLogon 'mono') + (& $td $r.PasswordSet 'mono') +
        (& $td $r.LastModified 'mono') + (& $td $r.Groups 'num') + "</tr>`n")
}

$js = @'
<script>
(function () {
  'use strict';
  var rows = Array.prototype.slice.call(document.querySelectorAll('tbody tr:not(#f-empty)'));
  var search = document.getElementById('f-search'), count = document.getElementById('f-count'), empty = document.getElementById('f-empty');
  var index = rows.map(function (r) { return (r.textContent || '').toLowerCase(); });
  function apply() {
    var q = search.value.trim().toLowerCase(), shown = 0;
    for (var i = 0; i < rows.length; i++) { var ok = !q || index[i].indexOf(q) !== -1; rows[i].hidden = !ok; if (ok) { shown++; } }
    empty.hidden = shown !== 0 || rows.length === 0;
    count.textContent = 'Showing ' + shown + ' of ' + rows.length;
  }
  var t = null; search.addEventListener('input', function () { clearTimeout(t); t = setTimeout(apply, 120); });
  document.getElementById('toolbar').hidden = false; search.focus(); apply();
})();
</script>
'@

$generated  = (Get-Date).ToString('yyyy-MM-dd HH:mm')
$scriptName = if ($PSCommandPath) { Split-Path $PSCommandPath -Leaf } else { 'Export-ADDisabledAccountReport.ps1' }
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Disabled accounts - $(& $enc $domain.DNSRoot)</title>
<style>
  :root { --bg:#0d1117; --surface:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e; --accent:#58a6ff; }
  * { box-sizing:border-box; } [hidden] { display:none !important; }
  body { margin:0; background:var(--bg); color:var(--text); font-family:'Segoe UI', system-ui, sans-serif; font-size:14px; }
  .header { padding:28px 40px 18px; border-bottom:1px solid var(--border); }
  h1 { margin:0 0 6px; font-size:22px; } h1 span { color:var(--accent); }
  .meta { color:var(--muted); font-size:12px; font-family:Consolas, monospace; }
  .summary { display:flex; gap:14px; flex-wrap:wrap; padding:18px 40px 8px; }
  .card { flex:0 1 220px; background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:14px 18px; }
  .card .v { font-size:28px; font-weight:700; } .card .l { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; }
  .toolbar { display:flex; gap:12px; align-items:center; padding:10px 40px 14px; flex-wrap:wrap; }
  .toolbar input { flex:1 1 360px; background:var(--surface); color:var(--text); border:1px solid var(--border); border-radius:6px; padding:9px 12px; font-size:14px; }
  .toolbar input:focus { outline:none; border-color:var(--accent); } .f-count { font-family:Consolas, monospace; font-size:12px; color:var(--accent); }
  .wrap { padding:0 40px 30px; overflow-x:auto; }
  table { width:100%; border-collapse:collapse; background:var(--surface); border:1px solid var(--border); }
  th { text-align:left; font-size:11px; color:var(--muted); text-transform:uppercase; padding:9px 10px; border-bottom:1px solid var(--border); position:sticky; top:0; background:var(--surface); }
  td { padding:7px 10px; border-bottom:1px solid var(--border); vertical-align:top; overflow-wrap:anywhere; }
  td.mono { font-family:Consolas, monospace; font-size:12px; white-space:nowrap; } td.num { text-align:right; }
  td.ou { font-size:12px; color:var(--muted); }
  .badge { font-size:10px; font-weight:700; padding:1px 6px; border-radius:8px; border:1px solid var(--border); color:var(--muted); margin-left:4px; }
  .none { color:var(--muted); padding:16px; text-align:center; }
  .footer { padding:14px 40px; color:var(--muted); font-size:11px; border-top:1px solid var(--border); font-family:Consolas, monospace; }
</style>
</head>
<body>
<div class="header">
  <h1>Disabled user accounts &mdash; <span>$(& $enc $domain.DNSRoot)</span></h1>
  <div class="meta">Generated $generated &bull; read-only &bull; "last logon" is approximate (about 14 days) &bull; "last modified" = last change of any attribute, not the exact disable date</div>
</div>
<div class="summary">
  <div class="card"><div class="l">Disabled accounts</div><div class="v">$($rows.Count)</div></div>
  <div class="card"><div class="l">Still in groups (excl. built-in)</div><div class="v">$inGroups</div></div>
</div>
<div class="toolbar" id="toolbar" hidden>
  <input type="search" id="f-search" placeholder="Search username, name, UPN, description, OU..." autocomplete="off">
  <span class="f-count" id="f-count"></span>
</div>
<div class="wrap"><table>
<thead><tr><th>Username</th><th>Display name</th><th>UPN</th><th>Description</th><th>OU</th><th>Created</th><th>Last logon</th><th>Password set</th><th>Last modified</th><th>Groups</th></tr></thead>
<tbody>
$($sb.ToString())<tr id="f-empty" hidden><td colspan="10" class="none">No account matches the search.</td></tr>
</tbody></table>
$(if ($rows.Count -eq 0) { '<p class="none">No disabled user account.</p>' })
</div>
<div class="footer">Generated by $(& $enc $scriptName) &bull; read-only list</div>
$js
</body>
</html>
"@

try {
    if (-not (Test-Path 'C:\temp')) { New-Item -ItemType Directory -Path 'C:\temp' -Force -ErrorAction Stop | Out-Null }
    $path = "C:\temp\ADDisabledAccounts_$((Get-Date).ToString('yyyyMMdd_HHmm')).html"
    $html | Out-File -FilePath $path -Encoding UTF8 -ErrorAction Stop
}
catch { Write-Host "ERROR: could not save the report - $($_.Exception.Message)" -ForegroundColor Red; exit 1 }

Write-Host "$($rows.Count) disabled user account(s), $inGroups still member of groups (excluding built-in)." -ForegroundColor Green
Write-Host "Report: $path" -ForegroundColor Green
Start-Process $path
exit 0
