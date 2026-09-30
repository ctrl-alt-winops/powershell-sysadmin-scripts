<#
.SYNOPSIS
    Read-only audit of Exchange Online mailboxes for forwarding, suspicious
    inbox rules and delegates - the classic signs of a mailbox compromised for
    payment fraud. HTML report + CSV in C:\temp.

.DESCRIPTION
    Connects to Exchange Online (interactive sign-in, MFA supported), prompts for
    the scope (all user + shared mailboxes / one mailbox / a list), then checks:
      - Tenant settings : outbound spam policy AutoForwardingMode and the Default
                          remote domain's AutoForwardEnabled (either can block
                          forwarding to external addresses for the whole tenant).
      - Mailbox forwarding (ForwardingSmtpAddress / ForwardingAddress), and whether
        a copy is kept in the mailbox.
      - Inbox rules that forward / redirect, delete, or move + mark as read.
      - Delegates: FullAccess (explicit grants) and SendAs.

    Severity (means "review", not "compromised" - a shared mailbox forwarding to
    a partner can be legitimate):
      HIGH   : forwarding to an external address (mailbox setting or rule).
      MEDIUM : a rule that hides mail (deletes it, or moves it and marks it read),
               or a tenant policy that allows external auto-forwarding.
      INFO   : internal forwarding, FullAccess / SendAs delegates, read errors.

    "External" = not one of the tenant's accepted domains, read automatically:
    nothing about the organisation is hard-coded.

.PARAMETER SignIn
    How to sign in to Exchange Online. No single method works everywhere:
      Default    : Windows account broker (WAM). Works in a normal PowerShell
                   console. Fails in hosts without a console window (PowerShell
                   ISE, some tools) with "A window handle must be configured".
      Classic    : classic sign-in window (-DisableWAM, module 3.7+). Works in
                   ISE. On Windows Server it can be blocked by Internet Explorer
                   Enhanced Security Configuration (seen on repeated sign-ins).
      DeviceCode : shows a code to enter at microsoft.com/devicelogin in any
                   browser, even on another machine. PowerShell 7 only.
    The sign-in method is fixed by the first attempt in a PowerShell session:
    after a failed attempt, retry from a NEW PowerShell window.

.EXAMPLE
    .\Export-MailboxForwardingReport.ps1
    Default sign-in, then prompts for the scope.

.EXAMPLE
    .\Export-MailboxForwardingReport.ps1 -SignIn DeviceCode
    Sign in with a code in any browser (PowerShell 7).

.NOTES
    Requirements:
    - ExchangeOnlineManagement module v3 or later on this machine:
          Install-Module ExchangeOnlineManagement -Scope CurrentUser
    - An Exchange Online role able to read mailboxes, inbox rules and mailbox
      permissions (e.g. Exchange Administrator; a view-only role may be enough -
      check in your tenant). Tenant policy rows need read access to
      anti-spam / remote domain settings; if missing they show as read errors.
    - Interactive sign-in; no password is stored. See -SignIn if the default
      sign-in fails in your environment. An existing Exchange Online
      session is reused and left connected; a session opened by the script is
      closed at the end.

    Run time: inbox rules and FullAccess are read per mailbox (about 1-2 s per
    mailbox, depending on Exchange Online). A warning with an estimate is shown
    before large runs.
    Read-only: nothing is changed in the tenant.
    Exit codes: 0 = report written (findings or not), 1 = aborted / failed.
#>

[CmdletBinding()]
param(
    [ValidateSet('Default', 'Classic', 'DeviceCode')]
    [string]$SignIn = 'Default'
)

# ------------------------- Settings -------------------------
$WarnAboveMailboxes = 20     # ask for confirmation above this many mailboxes
$SecondsPerMailbox  = 1, 2   # rough range used for the time estimate

# ------------------------- Helpers -------------------------

function Read-Menu {
    param([string]$Prompt, [int]$Max)
    do {
        $a = (Read-Host $Prompt).Trim()
        $n = 0
        $ok = [int]::TryParse($a, [ref]$n) -and $n -ge 1 -and $n -le $Max
    } while (-not $ok)
    return $n
}

function Confirm-YesNo {
    do { $a = (Read-Host 'CONTINUE : YES\NO').Trim().ToUpper() } while ($a -notin 'YES', 'NO')
    return ($a -eq 'YES')
}

# SMTP addresses inside a rule recipient string, e.g. '"John" [SMTP:john@example.com]'.
# Internal recipients often appear as display names only: no address = internal.
function Get-SmtpAddress {
    param([string]$Text)
    $m = [regex]::Matches($Text, '(?i)smtp:([^\]\s">]+)')
    if ($m.Count -gt 0) { return @($m | ForEach-Object { $_.Groups[1].Value }) }
    return @([regex]::Matches($Text, '[A-Za-z0-9._%+''-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}') | ForEach-Object { $_.Value })
}

function Test-ExternalAddress {
    param([string]$Address, [string[]]$Accepted)
    $domain = ($Address -split '@')[-1].ToLower()
    return -not ($Accepted | Where-Object { $domain -eq $_ -or $domain.EndsWith(".$_") })
}

function ConvertTo-Finding {
    param([string]$Severity, [string]$Mailbox, [string]$Type, [string]$Detail)
    [pscustomobject]@{ Severity = $Severity; Mailbox = $Mailbox; Type = $Type; Detail = $Detail }
}

# ------------------------- Module + connection -------------------------

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-Host 'ERROR: the ExchangeOnlineManagement module is not installed on this machine.' -ForegroundColor Red
    Write-Host '       Install it with:  Install-Module ExchangeOnlineManagement -Scope CurrentUser' -ForegroundColor Yellow
    exit 1
}
try   { Import-Module ExchangeOnlineManagement -ErrorAction Stop }
catch { Write-Host "ERROR: could not load ExchangeOnlineManagement: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }

$weConnected = $false
$existing = @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Connected' })
if ($existing.Count -gt 0) {
    Write-Host "Using the existing Exchange Online session ($($existing[0].UserPrincipalName))." -ForegroundColor Cyan
}
else {
    # Sign-in method: see -SignIn in the help. Checked against what the installed
    # module and PowerShell edition actually support.
    $connectArgs = @{ ShowBanner = $false; ErrorAction = 'Stop' }
    $connectCmd  = Get-Command Connect-ExchangeOnline
    switch ($SignIn) {
        'Classic' {
            if ($connectCmd.Parameters.ContainsKey('DisableWAM')) { $connectArgs.DisableWAM = $true }
            else { Write-Host 'Note: this module version does not use the Windows broker; signing in normally.' -ForegroundColor DarkGray; $SignIn = 'Default' }
        }
        'DeviceCode' {
            if ($PSVersionTable.PSEdition -ne 'Core' -or -not $connectCmd.Parameters.ContainsKey('Device')) {
                Write-Host 'ERROR: -SignIn DeviceCode needs PowerShell 7 (pwsh.exe) with ExchangeOnlineManagement.' -ForegroundColor Red
                exit 1
            }
            $connectArgs.Device = $true
        }
    }
    Write-Host "Connecting to Exchange Online ($(switch ($SignIn) { 'Default' { 'sign-in window' } 'Classic' { 'classic sign-in window' } 'DeviceCode' { 'device code - follow the instructions below' } }))..." -ForegroundColor Cyan

    try { Connect-ExchangeOnline @connectArgs; $weConnected = $true }
    catch {
        $msg  = $_.Exception.Message
        $self = if ($PSCommandPath) { Split-Path $PSCommandPath -Leaf } else { 'the script' }
        Write-Host "ERROR: could not connect to Exchange Online: $msg" -ForegroundColor Red
        # The sign-in method is fixed by the first attempt in a PowerShell session.
        if ($msg -match 'window handle') {
            Write-Host 'Tip: this PowerShell host has no console window for the default sign-in (e.g. ISE).' -ForegroundColor Yellow
            Write-Host "     Run it from a normal PowerShell console, or open a NEW window and run: .\$self -SignIn Classic" -ForegroundColor Yellow
        }
        elseif ($SignIn -eq 'Classic') {
            Write-Host 'Tip: the classic sign-in window uses the Internet Explorer engine, which Windows Server can block' -ForegroundColor Yellow
            Write-Host '     (IE Enhanced Security Configuration). From a NEW PowerShell window, retry, use the default sign-in,' -ForegroundColor Yellow
            Write-Host "     or in PowerShell 7: .\$self -SignIn DeviceCode" -ForegroundColor Yellow
        }
        else {
            Write-Host "Tip: other sign-in methods, from a NEW PowerShell window: .\$self -SignIn Classic   or (PowerShell 7) -SignIn DeviceCode" -ForegroundColor Yellow
        }
        exit 1
    }
}

# The whole audit; returns its exit code. Kept in a function so an early stop
# (operator says NO, no mailbox found) still reaches the sign-out below.
function Invoke-MailboxAudit {
    # ------------------------- Scope -------------------------
    Write-Host ''
    Write-Host 'Scope:' -ForegroundColor Cyan
    Write-Host '  [1] All user + shared mailboxes' -ForegroundColor White
    Write-Host '  [2] One mailbox' -ForegroundColor White
    Write-Host '  [3] A list of mailboxes (comma-separated)' -ForegroundColor White
    $scope = Read-Menu -Prompt 'Enter scope (1, 2 or 3)' -Max 3

    $props = 'ForwardingAddress', 'ForwardingSmtpAddress', 'DeliverToMailboxAndForward'
    $mailboxes = @()
    if ($scope -eq 1) {
        Write-Host 'Listing mailboxes...' -ForegroundColor Cyan
        $mailboxes = @(Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox -Properties $props -ErrorAction Stop)
    }
    else {
        $ids = if ($scope -eq 2) { @((Read-Host 'Mailbox (e-mail address or alias)').Trim()) }
               else { @((Read-Host 'Mailboxes (comma-separated)') -split ',' | ForEach-Object { $_.Trim() }) }
        foreach ($id in ($ids | Where-Object { $_ } | Select-Object -Unique)) {
            try   { $mailboxes += Get-EXOMailbox -Identity $id -Properties $props -ErrorAction Stop }
            catch { Write-Host "  Not found, skipped: $id" -ForegroundColor Yellow }
        }
    }
    if ($mailboxes.Count -eq 0) { Write-Host 'No mailbox in scope. Nothing to audit.' -ForegroundColor Yellow; return 1 }

    # ------------------------- Heavy-run warning -------------------------
    if ($mailboxes.Count -gt $WarnAboveMailboxes) {
        $minM = [math]::Ceiling($mailboxes.Count * $SecondsPerMailbox[0] / 60)
        $maxM = [math]::Ceiling($mailboxes.Count * $SecondsPerMailbox[1] / 60)
        $dur  = if ($maxM -le 1) { 'about 1 minute' } elseif ($minM -eq $maxM) { "about $maxM minutes" } else { "about $minM to $maxM minutes" }
        $reqs = $mailboxes.Count * 2    # inbox rules + FullAccess, per mailbox
        Write-Host ''
        Write-Host "WARNING : $($mailboxes.Count) mailboxes in scope. Reading their inbox rules and delegates is heavy:" -ForegroundColor Red
        Write-Host "          $dur and about $reqs requests to Exchange Online (Microsoft may slow them down)." -ForegroundColor Red
        Write-Host '          Nothing is changed. Do you want to continue ?' -ForegroundColor Red
        if (-not (Confirm-YesNo)) { Write-Host 'Aborted by operator. Nothing read.' -ForegroundColor Yellow; return 1 }
    }

    # ------------------------- Tenant settings -------------------------
    $findings = New-Object System.Collections.Generic.List[object]
    $tenant   = New-Object System.Collections.Generic.List[string]

    $accepted = @(Get-AcceptedDomain -ErrorAction Stop | ForEach-Object { $_.DomainName.ToString().ToLower() })
    $tenant.Add("Accepted (internal) domains: $($accepted -join ', ')")

    try {
        foreach ($pol in @(Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop)) {
            $mode = [string]$pol.AutoForwardingMode
            $tenant.Add("Outbound spam policy '$($pol.Name)': AutoForwardingMode = $mode$(switch ($mode) { 'On' { ' (external auto-forwarding ALLOWED)' } 'Off' { ' (blocked)' } 'Automatic' { ' (Microsoft default: blocks external auto-forwarding)' } })")
            if ($mode -eq 'On') { $findings.Add((ConvertTo-Finding -Severity 'MEDIUM' -Mailbox '(tenant)' -Type 'Tenant policy' -Detail "Outbound spam policy '$($pol.Name)' allows automatic forwarding to external addresses.")) }
        }
    }
    catch { $tenant.Add("Outbound spam policies: could not read ($($_.Exception.Message))") }

    try {
        $rd = Get-RemoteDomain -Identity Default -ErrorAction Stop
        $tenant.Add("Remote domain 'Default': AutoForwardEnabled = $($rd.AutoForwardEnabled)")
    }
    catch { $tenant.Add("Remote domain 'Default': could not read ($($_.Exception.Message))") }

    # ------------------------- Per-mailbox audit -------------------------
    # -IncludeHidden also returns rules hidden from Outlook (a known attacker trick),
    # when this module version supports it.
    $useHidden = (Get-Command Get-InboxRule -ErrorAction SilentlyContinue).Parameters.ContainsKey('IncludeHidden')

    $i = 0
    $sw = [Diagnostics.Stopwatch]::StartNew()
    foreach ($m in $mailboxes) {
        $i++
        $id = [string]$m.PrimarySmtpAddress
        $eta = if ($i -gt 1) { [int](($sw.Elapsed.TotalSeconds / ($i - 1)) * ($mailboxes.Count - $i + 1)) } else { -1 }
        Write-Progress -Activity 'Auditing mailboxes (read-only)' -Status "$i / $($mailboxes.Count): $id" -PercentComplete (100 * ($i - 1) / $mailboxes.Count) -SecondsRemaining $eta

        # --- Mailbox-level forwarding ---
        $copy = if ($m.DeliverToMailboxAndForward) { 'a copy is kept in the mailbox' } else { 'NO copy kept in the mailbox' }
        if ($m.ForwardingSmtpAddress) {
            $addr = [string]$m.ForwardingSmtpAddress -replace '^(?i)smtp:', ''
            if (Test-ExternalAddress -Address $addr -Accepted $accepted) {
                $findings.Add((ConvertTo-Finding -Severity 'HIGH' -Mailbox $id -Type 'Mailbox forwarding' -Detail "Forwards all mail to EXTERNAL $addr ($copy)."))
            } else {
                $findings.Add((ConvertTo-Finding -Severity 'INFO' -Mailbox $id -Type 'Mailbox forwarding' -Detail "Forwards all mail to internal $addr ($copy)."))
            }
        }
        if ($m.ForwardingAddress) {
            # A recipient object: may be a mail contact pointing outside the tenant.
            $addr = try { [string](Get-EXORecipient -Identity ([string]$m.ForwardingAddress) -ErrorAction Stop).PrimarySmtpAddress } catch { '' }
            if ($addr -and (Test-ExternalAddress -Address $addr -Accepted $accepted)) {
                $findings.Add((ConvertTo-Finding -Severity 'HIGH' -Mailbox $id -Type 'Mailbox forwarding' -Detail "Forwards all mail to '$($m.ForwardingAddress)' = EXTERNAL $addr ($copy)."))
            } else {
                $findings.Add((ConvertTo-Finding -Severity 'INFO' -Mailbox $id -Type 'Mailbox forwarding' -Detail "Forwards all mail to internal recipient '$($m.ForwardingAddress)'$(if ($addr) { " ($addr)" }) ($copy)."))
            }
        }

        # --- Inbox rules ---
        try {
            $rules = if ($useHidden) { @(Get-InboxRule -Mailbox $id -IncludeHidden -ErrorAction Stop) }
                     else            { @(Get-InboxRule -Mailbox $id -ErrorAction Stop) }
        }
        catch {
            $rules = @()
            $findings.Add((ConvertTo-Finding -Severity 'INFO' -Mailbox $id -Type 'Read error' -Detail "Could not read inbox rules: $($_.Exception.Message)"))
        }
        foreach ($r in $rules) {
            $targets  = @(@($r.ForwardTo) + @($r.ForwardAsAttachmentTo) + @($r.RedirectTo) | Where-Object { $_ })
            $addrs    = @($targets | ForEach-Object { Get-SmtpAddress -Text ([string]$_) })
            $external = @($addrs | Where-Object { Test-ExternalAddress -Address $_ -Accepted $accepted } | Select-Object -Unique)
            $deletes  = [bool]($r.DeleteMessage -or $r.SoftDeleteMessage)
            $moves    = [bool]$r.MoveToFolder
            $hides    = $deletes -or ($moves -and $r.MarkAsRead)
            $words    = @(@($r.SubjectContainsWords) + @($r.BodyContainsWords) + @($r.SubjectOrBodyContainsWords) | Where-Object { $_ })

            $what = @()
            if ($targets) { $what += "forwards/redirects to $($targets -join '; ')" }
            if ($deletes) { $what += 'deletes the message' }
            if ($moves)   { $what += "moves it to '$($r.MoveToFolder)'" }
            if ($r.MarkAsRead) { $what += 'marks it as read' }
            if ($words)   { $what += "when it contains: $($words -join ', ')" }
            $label = "Rule '$($r.Name)'$(if ($r.Enabled -eq $false) { ' [DISABLED]' }): $($what -join ', ')."

            if ($external.Count -gt 0) {
                $findings.Add((ConvertTo-Finding -Severity 'HIGH' -Mailbox $id -Type 'Inbox rule' -Detail "$label EXTERNAL: $($external -join ', ')"))
            }
            elseif ($hides) {
                $findings.Add((ConvertTo-Finding -Severity 'MEDIUM' -Mailbox $id -Type 'Inbox rule' -Detail "$label Hides mail from the user."))
            }
            elseif ($targets) {
                $findings.Add((ConvertTo-Finding -Severity 'INFO' -Mailbox $id -Type 'Inbox rule' -Detail $label))
            }
            # Any other rule (plain filing into folders) is normal and not reported.
        }

        # --- FullAccess delegates (explicit grants only; inherited = admin groups) ---
        try {
            $perms = @(Get-EXOMailboxPermission -Identity $id -ErrorAction Stop | Where-Object {
                $_.AccessRights -contains 'FullAccess' -and -not $_.IsInherited -and -not $_.Deny -and $_.User -notlike 'NT AUTHORITY\*' })
            foreach ($p in $perms) {
                $who = [string]$p.User
                $note = if ($who -match '^S-1-5-') { ' (orphaned SID - deleted account)' } else { '' }
                $findings.Add((ConvertTo-Finding -Severity 'INFO' -Mailbox $id -Type 'FullAccess' -Detail "$who has FullAccess$note."))
            }
        }
        catch { $findings.Add((ConvertTo-Finding -Severity 'INFO' -Mailbox $id -Type 'Read error' -Detail "Could not read FullAccess: $($_.Exception.Message)")) }

        # --- SendAs, per mailbox for a one / list scope ---
        if ($scope -ne 1) {
            try {
                foreach ($s in @(Get-EXORecipientPermission -Identity $id -ErrorAction Stop | Where-Object { $_.AccessRights -contains 'SendAs' -and $_.Trustee -notlike 'NT AUTHORITY\*' })) {
                    $findings.Add((ConvertTo-Finding -Severity 'INFO' -Mailbox $id -Type 'SendAs' -Detail "$($s.Trustee) can send as this mailbox."))
                }
            }
            catch { $findings.Add((ConvertTo-Finding -Severity 'INFO' -Mailbox $id -Type 'Read error' -Detail "Could not read SendAs: $($_.Exception.Message)")) }
        }
    }
    Write-Progress -Activity 'Auditing mailboxes (read-only)' -Completed

    # --- SendAs for the whole tenant in one call (all-mailboxes scope) ---
    if ($scope -eq 1) {
        try {
            foreach ($s in @(Get-EXORecipientPermission -ResultSize Unlimited -ErrorAction Stop | Where-Object { $_.AccessRights -contains 'SendAs' -and $_.Trustee -notlike 'NT AUTHORITY\*' })) {
                $findings.Add((ConvertTo-Finding -Severity 'INFO' -Mailbox ([string]$s.Identity) -Type 'SendAs' -Detail "$($s.Trustee) can send as this mailbox."))
            }
        }
        catch { $findings.Add((ConvertTo-Finding -Severity 'INFO' -Mailbox '(tenant)' -Type 'Read error' -Detail "Could not read SendAs: $($_.Exception.Message)")) }
    }

    # ------------------------- Report -------------------------
    $order  = @{ HIGH = 0; MEDIUM = 1; INFO = 2 }
    $sorted = @($findings | Sort-Object { $order[$_.Severity] }, Mailbox, Type)
    $count  = @{}
    foreach ($s in 'HIGH', 'MEDIUM', 'INFO') { $count[$s] = @($sorted | Where-Object Severity -eq $s).Count }

    if (-not (Test-Path 'C:\temp')) { New-Item -ItemType Directory -Path 'C:\temp' -Force -ErrorAction Stop | Out-Null }
    $base = "C:\temp\Exchange_MailForwarding_$((Get-Date).ToString('yyyyMMdd_HHmm'))"

    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $sb  = New-Object System.Text.StringBuilder
    foreach ($f in $sorted) {
        $c = $f.Severity.ToLower()
        [void]$sb.Append("<tr class=`"row-$c`" data-sev=`"$c`"><td><span class=`"badge $c`">$($f.Severity)</span></td><td class=`"mbx`">$(& $enc $f.Mailbox)</td><td>$(& $enc $f.Type)</td><td>$(& $enc $f.Detail)</td></tr>`n")
    }
    $tenantHtml = ($tenant | ForEach-Object { "<li>$(& $enc $_)</li>" }) -join ''
    $scopeTxt   = switch ($scope) { 1 { 'all user + shared mailboxes' } 2 { 'one mailbox' } 3 { 'list of mailboxes' } }
    $generated  = (Get-Date).ToString('yyyy-MM-dd HH:mm')
    $scriptName = if ($PSCommandPath) { Split-Path $PSCommandPath -Leaf } else { 'Export-MailboxForwardingReport.ps1' }

    # Filters: plain JS, event text only read/written via textContent. System fonts: no outbound request.
    $js = @'
<script>
(function () {
  'use strict';
  var rows = Array.prototype.slice.call(document.querySelectorAll('tbody tr[data-sev]'));
  var cards = Array.prototype.slice.call(document.querySelectorAll('.card[data-filter]'));
  var search = document.getElementById('f-search'), count = document.getElementById('f-count'), empty = document.getElementById('f-empty');
  var index = rows.map(function (r) { return (r.textContent || '').toLowerCase(); });
  var active = {};
  function apply() {
    var q = search.value.trim().toLowerCase(), any = Object.keys(active).length > 0, shown = 0;
    for (var i = 0; i < rows.length; i++) {
      var ok = (!any || active[rows[i].getAttribute('data-sev')] === true) && (!q || index[i].indexOf(q) !== -1);
      rows[i].hidden = !ok; if (ok) { shown++; }
    }
    empty.hidden = shown !== 0 || rows.length === 0;
    count.textContent = 'Showing ' + shown + ' of ' + rows.length;
    cards.forEach(function (c) { var f = c.getAttribute('data-filter'); c.classList.toggle('active', f === 'all' ? !any : active[f] === true); });
  }
  cards.forEach(function (c) {
    c.setAttribute('role', 'button'); c.setAttribute('tabindex', '0');
    function toggle() { var f = c.getAttribute('data-filter'); if (f === 'all') { active = {}; } else if (active[f]) { delete active[f]; } else { active[f] = true; } apply(); }
    c.addEventListener('click', toggle);
    c.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
  });
  var t = null; search.addEventListener('input', function () { clearTimeout(t); t = setTimeout(apply, 150); });
  document.getElementById('toolbar').hidden = false; document.body.classList.add('js'); apply();
})();
</script>
'@

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mailbox forwarding audit - $generated</title>
<style>
  :root { --bg:#0d1117; --surface:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e; --accent:#58a6ff;
          --high:#f85149; --high-bg:#2d1214; --med:#d29922; --med-bg:#2d2208; --info:#8b949e; }
  * { box-sizing:border-box; } [hidden] { display:none !important; }
  body { margin:0; background:var(--bg); color:var(--text); font-family:'Segoe UI', system-ui, sans-serif; font-size:14px; }
  .header { padding:28px 40px 18px; border-bottom:1px solid var(--border); }
  h1 { margin:0 0 6px; font-size:22px; } h1 span { color:var(--accent); }
  .meta { color:var(--muted); font-size:12px; font-family:Consolas, monospace; }
  .tenant { margin:18px 40px 0; padding:12px 18px; background:var(--surface); border:1px solid var(--border); border-radius:8px; }
  .tenant h3 { margin:0 0 6px; font-size:13px; color:var(--accent); text-transform:uppercase; } .tenant ul { margin:0; padding-left:18px; }
  .summary { display:flex; gap:14px; flex-wrap:wrap; padding:18px 40px; }
  .card { flex:1 1 150px; background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:14px 18px; }
  .card .v { font-size:28px; font-weight:700; } .card .l { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; }
  .card.high .v { color:var(--high); } .card.medium .v { color:var(--med); } .card.info .v { color:var(--info); }
  .js .card[data-filter] { cursor:pointer; user-select:none; } .js .card.active { border-color:var(--accent); box-shadow:inset 0 0 0 1px var(--accent); }
  .toolbar { display:flex; gap:12px; align-items:center; padding:0 40px 14px; flex-wrap:wrap; }
  .toolbar input { flex:1 1 320px; background:var(--surface); color:var(--text); border:1px solid var(--border); border-radius:6px; padding:8px 12px; font-size:13px; }
  .toolbar input:focus { outline:none; border-color:var(--accent); } .f-count { font-family:Consolas, monospace; font-size:12px; color:var(--accent); }
  .wrap { padding:0 40px 30px; overflow-x:auto; }
  table { width:100%; border-collapse:collapse; background:var(--surface); border:1px solid var(--border); }
  th { text-align:left; font-size:11px; color:var(--muted); text-transform:uppercase; padding:10px 12px; border-bottom:1px solid var(--border); }
  td { padding:8px 12px; border-bottom:1px solid var(--border); vertical-align:top; overflow-wrap:anywhere; }
  td.mbx { font-family:Consolas, monospace; font-size:12px; white-space:nowrap; }
  tr.row-high { background:var(--high-bg); } tr.row-medium { background:var(--med-bg); }
  .badge { font-size:11px; font-weight:700; padding:2px 8px; border-radius:10px; font-family:Consolas, monospace; }
  .badge.high { color:var(--high); border:1px solid var(--high); } .badge.medium { color:var(--med); border:1px solid var(--med); } .badge.info { color:var(--info); border:1px solid var(--border); }
  .none { padding:24px; text-align:center; color:var(--muted); }
  .footer { padding:14px 40px; color:var(--muted); font-size:11px; border-top:1px solid var(--border); font-family:Consolas, monospace; }
</style>
</head>
<body>
<div class="header">
  <h1>Mailbox forwarding audit &mdash; <span>$($mailboxes.Count) mailbox(es)</span></h1>
  <div class="meta">Generated $generated &bull; scope: $scopeTxt &bull; HIGH / MEDIUM = to review, not necessarily malicious</div>
</div>
<div class="tenant"><h3>Tenant settings</h3><ul>$tenantHtml</ul></div>
<div class="summary">
  <div class="card total" data-filter="all"><div class="l">Findings</div><div class="v">$($sorted.Count)</div></div>
  <div class="card high" data-filter="high"><div class="l">High</div><div class="v">$($count.HIGH)</div></div>
  <div class="card medium" data-filter="medium"><div class="l">Medium</div><div class="v">$($count.MEDIUM)</div></div>
  <div class="card info" data-filter="info"><div class="l">Info</div><div class="v">$($count.INFO)</div></div>
</div>
<div class="toolbar" id="toolbar" hidden>
  <input type="search" id="f-search" placeholder="Search: mailbox, address, rule name, keyword..." autocomplete="off">
  <span class="f-count" id="f-count"></span>
</div>
<div class="wrap">
<table>
<thead><tr><th>Severity</th><th>Mailbox</th><th>Type</th><th>Details</th></tr></thead>
<tbody>
$($sb.ToString())<tr id="f-empty" hidden><td colspan="4" class="none">No finding matches the current filters.</td></tr>
</tbody>
</table>
$(if ($sorted.Count -eq 0) { '<div class="none">No finding: no forwarding, no suspicious rule, no explicit delegate.</div>' })
</div>
<div class="footer">Generated by $(& $enc $scriptName) &bull; read-only audit</div>
$js
</body>
</html>
"@

    $html | Out-File -FilePath "$base.html" -Encoding UTF8 -ErrorAction Stop
    $sorted | Export-Csv -Path "$base.csv" -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

    # ------------------------- Console summary -------------------------
    Write-Host ''
    Write-Host "Audited $($mailboxes.Count) mailbox(es) in $([math]::Round($sw.Elapsed.TotalMinutes, 1)) min." -ForegroundColor Cyan
    Write-Host ("Findings: {0} HIGH, {1} MEDIUM, {2} INFO" -f $count.HIGH, $count.MEDIUM, $count.INFO) -ForegroundColor $(if ($count.HIGH) { 'Red' } elseif ($count.MEDIUM) { 'Yellow' } else { 'Green' })
    foreach ($f in ($sorted | Where-Object Severity -eq 'HIGH')) { Write-Host "  HIGH  $($f.Mailbox) - $($f.Detail)" -ForegroundColor Red }
    Write-Host "`nReport: $base.html" -ForegroundColor Green
    Write-Host "CSV   : $base.csv" -ForegroundColor Green
    Start-Process "$base.html"
    return 0
}

$exitCode = 1
try     { $exitCode = @(Invoke-MailboxAudit)[-1] }
catch   { Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red }
finally { if ($weConnected) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } }
exit $exitCode
