<#
.SYNOPSIS
    Inventory of the software installed on a remote machine, or a comparison of
    two machines. Filterable HTML report + CSV in C:\temp.

.DESCRIPTION
    Read-only. Prompts for the mode and the machine name(s), checks WinRM, then
    collects on each machine (two machines are read in parallel):

      Programs   : the registry uninstall entries - machine-wide 64-bit and
                   32-bit, plus per-user installs of the users whose profile is
                   loaded (logged on). Name, version, publisher, install date,
                   scope (machine / user).
      Store apps : MSIX / Store packages of all users (Get-AppxPackage -AllUsers),
                   e.g. new Teams, new Outlook. Framework and resource packages
                   are skipped. One line per app: highest version installed and
                   the number of users who have it (user list in the CSV).

    Hidden by default (one click shows them; always included in the CSV):
      - system components and Windows updates (flagged so in the registry);
      - Windows system apps (system-signed or non-removable packages).

    Compare mode: programs are matched by name between the two machines; a
    version number embedded in the name ("... Redistributable - 14.38.33130",
    "7-Zip 23.01") is ignored for the match, so a different version shows as
    "Different version" rather than as two unrelated lines. Status per line:
    Only on A, Only on B, Different version, Same. The report shows the
    differences by default; one click on "Same" shows everything.

.NOTES
    Execution : from an admin workstation, against one or two remote machines
    Requires  : WinRM enabled on the target(s), admin rights on the target(s)
    Changes   : No - read-only

    Per-user programs are only visible for users whose profile is loaded
    (logged on, e.g. with FSLogix). Store apps of all users are listed.
    Listing Store apps over WinRM relies on Windows PowerShell 5.1 on the target
    (the default); if it fails, the report says so and still lists programs.
    Exit codes: 0 = report written, 1 = aborted / failed.
#>

# ------------------------- Remote block (runs ON EACH TARGET) -------------------------
# Returns flat rows: one Meta row + one row per program / Store app.
$CollectSoftware = {
    $meta = [pscustomobject]@{ RowType = 'Meta'; Computer = $env:COMPUTERNAME; OS = ''; AppxNote = '' }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $meta.OS = "$($os.Caption) - build $($os.BuildNumber)"
    } catch { $meta.OS = 'unknown' }
    $meta

    # ---- Programs (registry) ----
    $sources = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';             Scope = 'Machine (64-bit)' },
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'Machine (32-bit)' }
    )
    # Loaded user profiles (S-1-5-21-..., not the _Classes hives)
    foreach ($k in @(Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
        $who = try { (New-Object System.Security.Principal.SecurityIdentifier($k.PSChildName)).Translate([System.Security.Principal.NTAccount]).Value } catch { $k.PSChildName }
        $sources += @{ Path = "Registry::HKEY_USERS\$($k.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"; Scope = "User: $who" }
    }

    foreach ($src in $sources) {
        foreach ($key in @(Get-ChildItem -Path $src.Path -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if (-not $p -or -not $p.DisplayName) { continue }
            $hidden = ''
            if ($p.SystemComponent -eq 1) { $hidden = 'System component' }
            elseif ($p.ParentKeyName -or $p.ReleaseType -in 'Update', 'Hotfix', 'Security Update' -or $p.DisplayName -match '^(Security )?Update for |^Hotfix for ') { $hidden = 'Update' }
            $date = [string]$p.InstallDate
            if ($date -match '^(\d{4})(\d{2})(\d{2})$') { $date = "$($Matches[1])-$($Matches[2])-$($Matches[3])" }
            [pscustomobject]@{
                RowType = 'App'; Source = 'Program'; Name = ([string]$p.DisplayName).Trim(); Version = ([string]$p.DisplayVersion).Trim()
                Publisher = ([string]$p.Publisher).Trim(); Installed = $date; Scope = $src.Scope; Hidden = $hidden; Users = ''
            }
        }
    }

    # ---- Store apps (MSIX), all users; one line per app ----
    try {
        $pkgs = @(Get-AppxPackage -AllUsers -ErrorAction Stop | Where-Object { -not $_.IsFramework -and -not $_.IsResourcePackage })
        foreach ($g in ($pkgs | Group-Object Name)) {
            $best = $g.Group | Sort-Object { $v = $null; if ([version]::TryParse([string]$_.Version, [ref]$v)) { $v } else { [version]'0.0' } } -Descending | Select-Object -First 1
            $users = @($g.Group | ForEach-Object { $_.PackageUserInformation } |
                       Where-Object { [string]$_.InstallState -eq 'Installed' } |
                       ForEach-Object { [string]$_.UserSecurityId.Username } | Where-Object { $_ } | Sort-Object -Unique)
            $system = $g.Group | Where-Object { [string]$_.SignatureKind -eq 'System' -or $_.NonRemovable } | Select-Object -First 1
            [pscustomobject]@{
                RowType = 'App'; Source = 'Store app'; Name = $g.Name; Version = [string]$best.Version
                Publisher = ([string]$best.Publisher -replace '^CN=([^,]+).*$', '$1'); Installed = ''
                Scope = "Users ($($users.Count))"; Hidden = $(if ($system) { 'Windows system app' } else { '' }); Users = ($users -join '; ')
            }
        }
    }
    catch { $meta.AppxNote = "Store apps could not be listed: $($_.Exception.Message)" }
}

# ------------------------- Helpers -------------------------

# Name used to match a program between two machines: lower case, version numbers
# removed (dotted "14.38.33130", or a trailing number of 3+ digits as in
# "Update 401" / "Workspace 2402"), spaces / dashes tidied.
function Get-MatchKey {
    param([string]$Source, [string]$Name)
    $n = $Name.ToLower() -replace '\bv?\d+(\.\d+)+\b', '' -replace '\(\s*\)', '' -replace '\s{2,}', ' '
    $n = $n.Trim(" -`t") -replace '\s\d{3,}$', ''
    $n = $n.Trim(" -`t")
    return "$Source|$n"
}

function Test-Machine {
    param([string]$Name)
    try   { Test-WSMan -ComputerName $Name -ErrorAction Stop | Out-Null; Write-Host "  $Name : WinRM reachable." -ForegroundColor Green; return $true }
    catch { Write-Host "  $Name : cannot reach via WinRM ($($_.Exception.Message))" -ForegroundColor Red; return $false }
}

# ------------------------- Prompts -------------------------

Write-Host 'Mode:' -ForegroundColor Cyan
Write-Host '  [1] Inventory of one machine' -ForegroundColor White
Write-Host '  [2] Compare two machines' -ForegroundColor White
do { $mode = (Read-Host 'Enter mode (1 or 2)').Trim() } while ($mode -notin '1', '2')

$A = (Read-Host $(if ($mode -eq '2') { 'Machine A' } else { 'Machine name' })).Trim()
if (-not $A) { Write-Host 'ERROR: no machine name. Aborting.' -ForegroundColor Red; exit 1 }
$B = ''
if ($mode -eq '2') {
    $B = (Read-Host 'Machine B').Trim()
    if (-not $B) { Write-Host 'ERROR: no second machine name. Aborting.' -ForegroundColor Red; exit 1 }
    if ($B -eq $A) { Write-Host 'ERROR: machine A and B are the same. Aborting.' -ForegroundColor Red; exit 1 }
}

Write-Host "`nChecking WinRM..." -ForegroundColor Cyan
$targets = @($A) + @($B | Where-Object { $_ })
$ok = $true
foreach ($t in $targets) { if (-not (Test-Machine -Name $t)) { $ok = $false } }
if (-not $ok) { exit 1 }

# ------------------------- Collect (parallel) -------------------------

Write-Host "Collecting installed software (read-only)..." -ForegroundColor Cyan
$remoteErr = $null
$raw = @(Invoke-Command -ComputerName $targets -ScriptBlock $CollectSoftware -ErrorAction SilentlyContinue -ErrorVariable remoteErr)
$data = @{}
foreach ($t in $targets) {
    $rows = @($raw | Where-Object { $_.PSComputerName -eq $t })
    $m    = $rows | Where-Object RowType -eq 'Meta' | Select-Object -First 1
    if (-not $m) {
        $why = ($remoteErr | Where-Object { $_.TargetObject -eq $t -or "$($_.OriginInfo.PSComputerName)" -eq $t } | Select-Object -First 1).Exception.Message
        Write-Host "ERROR: no data from '$t'$(if ($why) { ": $why" })." -ForegroundColor Red
        exit 1
    }
    $apps = @($rows | Where-Object RowType -eq 'App')
    $data[$t] = [pscustomobject]@{ Meta = $m; Apps = $apps }
    $hid = @($apps | Where-Object Hidden).Count
    Write-Host ("  {0}: {1} programs, {2} Store apps ({3} hidden by default){4}" -f $t, @($apps | Where-Object Source -eq 'Program').Count,
        @($apps | Where-Object Source -eq 'Store app').Count, $hid, $(if ($m.AppxNote) { " - $($m.AppxNote)" })) -ForegroundColor Green
}

# ------------------------- Build report rows -------------------------

if ($mode -eq '1') {
    $lines = @($data[$A].Apps | Sort-Object Source, Name | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Version = $_.Version; Publisher = $_.Publisher; Source = $_.Source; Scope = $_.Scope
                           Installed = $_.Installed; Hidden = $_.Hidden; Users = $_.Users; Status = '' } })
}
else {
    # Group each machine's apps by match key; several entries per key (e.g. two
    # Python versions side by side) are kept together as a version list.
    $index = @{}
    foreach ($side in 'A', 'B') {
        $machine = if ($side -eq 'A') { $A } else { $B }
        foreach ($app in $data[$machine].Apps) {
            $k = Get-MatchKey -Source $app.Source -Name $app.Name
            if (-not $index.ContainsKey($k)) { $index[$k] = @{ A = @(); B = @() } }
            $index[$k][$side] += $app
        }
    }
    $lines = @($index.GetEnumerator() | ForEach-Object {
        $inA = @($_.Value.A); $inB = @($_.Value.B)   # not $a/$b: variable names ignore case ($A/$B = machine names)
        $va = (@($inA | ForEach-Object { $_.Version } | Sort-Object -Unique) -join ', ')
        $vb = (@($inB | ForEach-Object { $_.Version } | Sort-Object -Unique) -join ', ')
        $status = if (-not $inB.Count) { 'Only on A' } elseif (-not $inA.Count) { 'Only on B' } elseif ($va -eq $vb) { 'Same' } else { 'Different version' }
        $ref = if ($inA.Count) { $inA[0] } else { $inB[0] }
        # Hidden only if hidden wherever it exists
        $hidden = if (@(@($inA) + @($inB) | Where-Object { -not $_.Hidden }).Count -eq 0) { $ref.Hidden } else { '' }
        [pscustomobject]@{
            Name = $(if ($inA.Count -and $inB.Count -and $inA[0].Name -ne $inB[0].Name) { "$($inA[0].Name)  /  $($inB[0].Name)" } else { $ref.Name })
            VersionA = $va; VersionB = $vb; Publisher = $ref.Publisher; Source = $ref.Source; Status = $status; Hidden = $hidden
            ScopeA = (@($inA | ForEach-Object { $_.Scope } | Sort-Object -Unique) -join ', ')
            ScopeB = (@($inB | ForEach-Object { $_.Scope } | Sort-Object -Unique) -join ', ')
        }
    } | Sort-Object Source, Name)
}

# ------------------------- HTML -------------------------

$enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
$td  = { param($v, $cls) $c = if ($cls) { ' class="' + $cls + '"' } else { '' }; '<td' + $c + '>' + (& $enc $v) + '</td>' }
$sb  = New-Object System.Text.StringBuilder
$statusClass = @{ 'Only on A' = 'onlya'; 'Only on B' = 'onlyb'; 'Different version' = 'diff'; 'Same' = 'same' }

foreach ($l in $lines) {
    $src = if ($l.Source -eq 'Store app') { 'store' } else { 'program' }
    $hid = if ($l.Hidden) { 'yes' } else { 'no' }
    $nameCell = (& $enc $l.Name) + $(if ($l.Hidden) { ' <span class="tag">' + (& $enc $l.Hidden) + '</span>' } else { '' })
    if ($mode -eq '1') {
        $scopeCell = if ($l.Users) { $l.Scope + ': ' + $(if ($l.Users.Length -gt 120) { $l.Users.Substring(0, 120) + '...' } else { $l.Users }) } else { $l.Scope }
        [void]$sb.Append("<tr data-src=`"$src`" data-hidden=`"$hid`"><td>$nameCell</td>" + (& $td $l.Version 'mono') + (& $td $l.Publisher) +
            (& $td $l.Source) + (& $td $scopeCell 'small') + (& $td $l.Installed 'mono') + "</tr>`n")
    }
    else {
        $st = $statusClass[$l.Status]
        [void]$sb.Append("<tr class=`"st-$st`" data-src=`"$src`" data-hidden=`"$hid`" data-status=`"$st`"><td>$nameCell</td>" + (& $td $l.VersionA 'mono') +
            (& $td $l.VersionB 'mono') + "<td><span class=`"badge $st`">$(& $enc $l.Status)</span></td>" + (& $td $l.Publisher) + (& $td $l.Source) +
            (& $td "A: $(if ($l.ScopeA) { $l.ScopeA } else { '-' }) | B: $(if ($l.ScopeB) { $l.ScopeB } else { '-' })" 'small') + "</tr>`n")
    }
}

$hiddenCount = @($lines | Where-Object Hidden).Count
$progCount   = @($lines | Where-Object { $_.Source -eq 'Program' -and -not $_.Hidden }).Count
$storeCount  = @($lines | Where-Object { $_.Source -eq 'Store app' -and -not $_.Hidden }).Count
$notes = @($targets | ForEach-Object { $data[$_].Meta } | Where-Object AppxNote | ForEach-Object { "$($_.Computer): $($_.AppxNote)" })
$notesHtml = if ($notes) { '<div class="notes">' + (($notes | ForEach-Object { & $enc $_ }) -join '<br>') + '</div>' } else { '' }

if ($mode -eq '1') {
    $title    = "Software inventory - $A"
    $h1       = "Software inventory &mdash; <span>$(& $enc $A)</span>"
    $metaLine = (& $enc $data[$A].Meta.OS)
    $cards    = ''
    $thead    = '<th>Name</th><th>Version</th><th>Publisher</th><th>Source</th><th>Scope</th><th>Installed</th>'
    $cols     = 6
}
else {
    $sCount = @{}; foreach ($s in 'onlya', 'onlyb', 'diff', 'same') { $sCount[$s] = @($lines | Where-Object { $statusClass[$_.Status] -eq $s -and -not $_.Hidden }).Count }
    $title    = "Software compare - $A vs $B"
    $h1       = "Software compare &mdash; <span>A: $(& $enc $A)</span> vs <span>B: $(& $enc $B)</span>"
    $metaLine = "A: $(& $enc $data[$A].Meta.OS) &bull; B: $(& $enc $data[$B].Meta.OS)"
    $cards    = @"
  <div class="card onlya active" data-status="onlya"><div class="l">Only on A</div><div class="v">$($sCount.onlya)</div></div>
  <div class="card onlyb active" data-status="onlyb"><div class="l">Only on B</div><div class="v">$($sCount.onlyb)</div></div>
  <div class="card diff active" data-status="diff"><div class="l">Different version</div><div class="v">$($sCount.diff)</div></div>
  <div class="card same" data-status="same"><div class="l">Same</div><div class="v">$($sCount.same)</div></div>
"@
    $thead    = '<th>Name</th><th>Version A</th><th>Version B</th><th>Status</th><th>Publisher</th><th>Source</th><th>Scope</th>'
    $cols     = 7
}

# Filters: plain JS, cells only read via textContent. Status cards (compare mode)
# start with "Same" off; hidden items (system components, updates, Windows
# system apps) start hidden.
$js = @'
<script>
(function () {
  'use strict';
  var rows = Array.prototype.slice.call(document.querySelectorAll('tbody tr[data-src]'));
  var search = document.getElementById('f-search'), source = document.getElementById('f-source');
  var hiddenBtn = document.getElementById('f-hidden'), count = document.getElementById('f-count'), empty = document.getElementById('f-empty');
  var cards = Array.prototype.slice.call(document.querySelectorAll('.card[data-status]'));
  var index = rows.map(function (r) { return (r.textContent || '').toLowerCase(); });
  var showHidden = false, active = {};
  cards.forEach(function (c) { if (c.classList.contains('active')) { active[c.getAttribute('data-status')] = true; } });
  function apply() {
    var q = search.value.trim().toLowerCase(), src = source.value, shown = 0, hiddenNow = 0;
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i], st = r.getAttribute('data-status');
      var ok = (showHidden || r.getAttribute('data-hidden') !== 'yes') &&
               (!src || r.getAttribute('data-src') === src) &&
               (!st || active[st] === true) &&
               (!q || index[i].indexOf(q) !== -1);
      r.hidden = !ok; if (ok) { shown++; }
    }
    empty.hidden = shown !== 0;
    count.textContent = 'Showing ' + shown + ' of ' + rows.length;
    hiddenBtn.textContent = (showHidden ? 'Hide ' : 'Show ') + hiddenBtn.getAttribute('data-count') + ' system components / updates / Windows system apps';
    cards.forEach(function (c) { c.classList.toggle('active', active[c.getAttribute('data-status')] === true); });
  }
  cards.forEach(function (c) {
    c.setAttribute('role', 'button'); c.setAttribute('tabindex', '0');
    function toggle() { var s = c.getAttribute('data-status'); if (active[s]) { delete active[s]; } else { active[s] = true; } apply(); }
    c.addEventListener('click', toggle);
    c.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
  });
  hiddenBtn.addEventListener('click', function () { showHidden = !showHidden; apply(); });
  source.addEventListener('change', apply);
  var t = null; search.addEventListener('input', function () { clearTimeout(t); t = setTimeout(apply, 120); });
  document.getElementById('toolbar').hidden = false; document.body.classList.add('js'); apply();
})();
</script>
'@

$generated  = (Get-Date).ToString('yyyy-MM-dd HH:mm')
$scriptName = if ($PSCommandPath) { Split-Path $PSCommandPath -Leaf } else { 'Export-SoftwareInventoryReport.ps1' }
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>$(& $enc $title)</title>
<style>
  :root { --bg:#0d1117; --surface:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e; --accent:#58a6ff;
          --a:#58a6ff; --b:#d2a8ff; --diff:#d29922; --same:#3fb950; --warn:#d29922; }
  * { box-sizing:border-box; } [hidden] { display:none !important; }
  body { margin:0; background:var(--bg); color:var(--text); font-family:'Segoe UI', system-ui, sans-serif; font-size:14px; }
  .header { padding:28px 40px 18px; border-bottom:1px solid var(--border); }
  h1 { margin:0 0 6px; font-size:22px; } h1 span { color:var(--accent); }
  .meta { color:var(--muted); font-size:12px; font-family:Consolas, monospace; }
  .summary { display:flex; gap:14px; flex-wrap:wrap; padding:18px 40px 4px; }
  .card { flex:1 1 150px; background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:12px 16px; }
  .card .v { font-size:26px; font-weight:700; } .card .l { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; }
  .card.onlya .v { color:var(--a); } .card.onlyb .v { color:var(--b); } .card.diff .v { color:var(--diff); } .card.same .v { color:var(--same); }
  .js .card[data-status] { cursor:pointer; user-select:none; opacity:0.55; }
  .js .card[data-status].active { opacity:1; border-color:var(--accent); box-shadow:inset 0 0 0 1px var(--accent); }
  .notes { margin:12px 40px 0; padding:10px 14px; border:1px solid var(--warn); border-radius:8px; color:var(--warn); }
  .toolbar { display:flex; gap:12px; align-items:center; padding:14px 40px; flex-wrap:wrap; }
  .toolbar input, .toolbar select, .toolbar button { background:var(--surface); color:var(--text); border:1px solid var(--border); border-radius:6px; padding:8px 12px; font-size:13px; font-family:inherit; }
  .toolbar input { flex:1 1 300px; } .toolbar button { cursor:pointer; }
  .toolbar input:focus, .toolbar select:focus { outline:none; border-color:var(--accent); }
  .f-count { font-family:Consolas, monospace; font-size:12px; color:var(--accent); }
  .wrap { padding:0 40px 30px; overflow-x:auto; }
  table { width:100%; border-collapse:collapse; background:var(--surface); border:1px solid var(--border); }
  th { text-align:left; font-size:11px; color:var(--muted); text-transform:uppercase; padding:9px 10px; border-bottom:1px solid var(--border); position:sticky; top:0; background:var(--surface); }
  td { padding:7px 10px; border-bottom:1px solid var(--border); vertical-align:top; overflow-wrap:anywhere; }
  td.mono { font-family:Consolas, monospace; font-size:12px; white-space:nowrap; } td.small { font-size:12px; color:var(--muted); }
  .tag { font-size:10px; padding:1px 6px; border-radius:8px; border:1px solid var(--border); color:var(--muted); margin-left:4px; }
  .badge { font-size:11px; font-weight:700; padding:2px 8px; border-radius:10px; white-space:nowrap; }
  .badge.onlya { color:var(--a); border:1px solid var(--a); } .badge.onlyb { color:var(--b); border:1px solid var(--b); }
  .badge.diff { color:var(--diff); border:1px solid var(--diff); } .badge.same { color:var(--same); border:1px solid var(--same); }
  .none { color:var(--muted); padding:16px; text-align:center; }
  .footer { padding:14px 40px; color:var(--muted); font-size:11px; border-top:1px solid var(--border); font-family:Consolas, monospace; }
</style>
</head>
<body>
<div class="header">
  <h1>$h1</h1>
  <div class="meta">$metaLine &bull; $progCount programs, $storeCount Store apps (+ $hiddenCount hidden) &bull; generated $generated &bull; read-only</div>
</div>
$(if ($cards) { "<div class=`"summary`">$cards</div>" })
$notesHtml
<div class="toolbar" id="toolbar" hidden>
  <input type="search" id="f-search" placeholder="Search name, version, publisher..." autocomplete="off">
  <select id="f-source"><option value="">Programs + Store apps</option><option value="program">Programs</option><option value="store">Store apps</option></select>
  <button type="button" id="f-hidden" data-count="$hiddenCount"></button>
  <span class="f-count" id="f-count"></span>
</div>
<div class="wrap"><table>
<thead><tr>$thead</tr></thead>
<tbody>
$($sb.ToString())<tr id="f-empty" hidden><td colspan="$cols" class="none">Nothing matches the current filters.</td></tr>
</tbody></table></div>
<div class="footer">Generated by $(& $enc $scriptName) &bull; read-only inventory</div>
$js
</body>
</html>
"@

# ------------------------- Save + console summary -------------------------

try {
    if (-not (Test-Path 'C:\temp')) { New-Item -ItemType Directory -Path 'C:\temp' -Force -ErrorAction Stop | Out-Null }
    $safe = { param($s) $s -replace '[\\/:*?"<>|]', '_' }
    $base = "C:\temp\SoftwareInventory_$(& $safe $A)$(if ($B) { "_vs_$(& $safe $B)" })_$((Get-Date).ToString('yyyyMMdd_HHmm'))"
    $html | Out-File -FilePath "$base.html" -Encoding UTF8 -ErrorAction Stop
    if ($mode -eq '1') { $lines | Select-Object Name, Version, Publisher, Source, Scope, Installed, Hidden, Users | Export-Csv -Path "$base.csv" -NoTypeInformation -Encoding UTF8 -ErrorAction Stop }
    else { $lines | Select-Object Name, @{ n = "Version $A"; e = { $_.VersionA } }, @{ n = "Version $B"; e = { $_.VersionB } }, Status, Publisher, Source, ScopeA, ScopeB, Hidden |
           Export-Csv -Path "$base.csv" -NoTypeInformation -Encoding UTF8 -ErrorAction Stop }
}
catch { Write-Host "ERROR: could not save the report - $($_.Exception.Message)" -ForegroundColor Red; exit 1 }

Write-Host ''
if ($mode -eq '2') {
    Write-Host ("Compare {0} vs {1}: {2} only on A, {3} only on B, {4} different version, {5} same (system items not counted)" -f $A, $B,
        $sCount.onlya, $sCount.onlyb, $sCount.diff, $sCount.same) -ForegroundColor Cyan
}
Write-Host "Report: $base.html" -ForegroundColor Green
Write-Host "CSV   : $base.csv" -ForegroundColor Green
Start-Process "$base.html"
exit 0
