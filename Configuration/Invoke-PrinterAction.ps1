<#
.SYNOPSIS
    Manages a user's printers on a remote machine from one menu: add network
    printers, remove printers, change the default printer.

.DESCRIPTION
    Prompts for machine name and username, checks WinRM and that the user is
    logged on, turns OFF "Let Windows manage my default printer" for the user
    (otherwise Windows keeps switching the default to the last printer used),
    then shows the user's printers and a menu. After each action the printers
    are read again and the menu comes back, until Quit.

    Printers listed (read-only, numbered):
      - User connection    : the user's own network printers, read from their
                             profile (HKU\<SID>\Printers\Connections). The
                             user's default printer is marked.
      - Local printer      : printers installed on the machine for all users.
      - Machine connection : network printers added for all users of the
                             machine (printui /ga), read from
                             HKLM\SYSTEM\CurrentControlSet\Control\Print\Connections.

    Actions:
      [1] Add            : prompts for a print server and one or more share
                           names (comma-separated; an entry starting with \\ is
                           used as a full path). Added with Add-Printer
                           -ConnectionName in the user's OWN session, so the
                           spooler provisions the already-deployed driver via
                           point-and-print.
      [2] Remove         : pick numbers, confirm with YES. User connections are
                           removed in the user's session; local printers with
                           Remove-Printer (admin); machine connections with
                           printui /gd (applies to each user at next logon).
      [3] Change default : pick a printer; set in the user's session.
    Every change is confirmed by reading the printers / default back.

    How user-session actions run: a ONE-SHOT interactive scheduled task runs a
    helper script in the user's session (a remote admin session cannot see or
    change the user's own printers). The helper and its log live in the user's
    own profile (only that user + admins can write there) and are deleted
    afterwards.

    Printers deployed by Group Policy or another management tool come back at
    the next policy refresh / logon: change them at the source instead. If a
    Group Policy enforces Windows default printer management, it wins over the
    user setting.

.NOTES
    Execution : from an admin workstation, against a remote machine
    Requires  : WinRM enabled on the target, admin rights on the target
    Changes   : Yes - turns off Windows default printer management for the user;
                then only what you choose: adds printers, removes printers
                (after a YES confirmation), sets the default printer

    Detailed requirements:
    - Admin rights on the target machine + WinRM enabled.
    - Target user currently logged on (their profile is only loaded during
      their session, e.g. with FSLogix).
    - Printer drivers already present on the machine for printers you add
      (point-and-print without an admin prompt for standard users).

    One machine and one user per run.
    Exit code (on Quit): 0 = every action succeeded, 1 = aborted / something failed.
#>

$TaskName   = 'TEMP_PrinterAction'
$TimeoutSec = 180   # point-and-print driver staging can be slow on first connect

# ------------------------- Remote blocks (run ON THE TARGET) -------------------------

# Read-only listing. Returns flat rows: one Meta row + one row per printer.
$GetPrintersBlock = {
    param($TargetUser)

    $meta = [pscustomobject]@{ RowType = 'Meta'; Ok = $false; Sid = ''; ProfilePath = ''; Default = ''; Message = '' }
    try {
        $meta.Sid = (New-Object System.Security.Principal.NTAccount($TargetUser)).Translate(
                     [System.Security.Principal.SecurityIdentifier]).Value
    } catch { $meta.Message = "Cannot resolve '$TargetUser' to an account on $env:COMPUTERNAME."; return $meta }
    $hive = "Registry::HKEY_USERS\$($meta.Sid)"
    if (-not (Test-Path -LiteralPath $hive)) { $meta.Message = "Profile of '$TargetUser' is not loaded - the user must be logged on to $env:COMPUTERNAME."; return $meta }
    $meta.ProfilePath = (Get-ItemProperty -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($meta.Sid)" -ErrorAction SilentlyContinue).ProfileImagePath
    # Default printer: "Name,winspool,Ne01:"
    $dev = (Get-ItemProperty -LiteralPath "$hive\Software\Microsoft\Windows NT\CurrentVersion\Windows" -ErrorAction SilentlyContinue).Device
    if ($dev) { $meta.Default = ($dev -split ',')[0] }
    $meta.Ok = $true
    $meta

    # User connections: subkeys named ",,server,share"
    foreach ($k in @(Get-ChildItem -LiteralPath "$hive\Printers\Connections" -ErrorAction SilentlyContinue)) {
        $name = $k.PSChildName -replace ',', '\'
        [pscustomobject]@{ RowType = 'Printer'; Kind = 'User connection'; Name = $name; Driver = ''; Port = '' }
    }
    # Local printers (installed for all users)
    foreach ($p in @(Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'Local' })) {
        [pscustomobject]@{ RowType = 'Printer'; Kind = 'Local printer'; Name = $p.Name; Driver = $p.DriverName; Port = $p.PortName }
    }
    # Machine-wide connections (printui /ga)
    foreach ($k in @(Get-ChildItem -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Connections' -ErrorAction SilentlyContinue)) {
        $name = (Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue).Printer
        if ($name) { [pscustomobject]@{ RowType = 'Printer'; Kind = 'Machine connection'; Name = $name; Driver = ''; Port = '' } }
    }
}

# Machine-wide removals (admin session). Items are "kind|name".
$RemoveMachineBlock = {
    param([string[]]$Items)
    foreach ($i in $Items) {
        $kind, $name = $i -split '\|', 2
        $r = [pscustomobject]@{ Name = $name; Result = 'FAIL'; Message = '' }
        try {
            if ($kind -eq 'Local printer') { Remove-Printer -Name $name -ErrorAction Stop }
            else {
                $p = Start-Process -FilePath 'rundll32.exe' -ArgumentList "printui.dll,PrintUIEntry /gd /n `"$name`"" -Wait -PassThru -WindowStyle Hidden
                if ($p.ExitCode -ne 0) { throw "printui /gd exited with code $($p.ExitCode)" }
            }
            $r.Result = 'OK'
        } catch { $r.Message = $_.Exception.Message }
        $r
    }
}

# Turns off "Let Windows manage my default printer" in the user's loaded profile.
$LegacyModeBlock = {
    param($Sid)
    $key = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Windows NT\CurrentVersion\Windows"
    $out = [pscustomobject]@{ WasOn = $false; Ok = $false; Message = '' }
    try {
        $cur = (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).LegacyDefaultPrinterMode
        $out.WasOn = ($cur -ne 1)           # missing or 0 = Windows manages the default
        if ($out.WasOn) { Set-ItemProperty -LiteralPath $key -Name LegacyDefaultPrinterMode -Value 1 -Type DWord -ErrorAction Stop }
        $out.Ok = $true
    } catch { $out.Message = $_.Exception.Message }
    $out
}

# Runs IN THE USER'S SESSION via a one-shot task: adds and/or removes user
# connections and/or sets the default printer (all need the user's own session).
# Lists are "|"-delimited strings, rebuilt here: an array alone in -ArgumentList
# can collapse into one bogus name.
$UserSessionBlock = {
    param($TargetUser, $TaskName, $ProfilePath, [string]$AddList, [string]$RemoveList, [string]$DefaultPrinter, $TimeoutSec)

    $out = [pscustomobject]@{ Status = 'Failed'; Code = $null; Log = ''; Message = '' }

    # In the user's own profile: only that user and admins can write there.
    $dir        = Join-Path $ProfilePath 'AppData\Local'
    $helperPath = Join-Path $dir "$TaskName.ps1"
    $logPath    = Join-Path $dir "$TaskName.log"

    Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue |
        Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $helperPath, $logPath -Force -ErrorAction SilentlyContinue

    # Single quotes doubled: a name containing ' cannot break the generated script.
    $lit = { param($s) "'" + ($s -replace "'", "''") + "'" }
    $arr = { param($list) ($list -split '\|' | Where-Object { $_ } | ForEach-Object { & $lit $_ }) -join ',' }
    $helper = @"
`$ErrorActionPreference = 'Stop'
`$log = $(& $lit $logPath)
"START" | Set-Content -Path `$log -Encoding UTF8
`$fail = 0
foreach (`$p in @($(& $arr $AddList))) {
    try {
        Add-Printer -ConnectionName `$p -ErrorAction Stop
        "ADD OK : `$p" | Add-Content -Path `$log -Encoding UTF8
    } catch {
        `$fail++
        "ADD FAIL : `$p :: `$(`$_.Exception.Message)" | Add-Content -Path `$log -Encoding UTF8
    }
}
foreach (`$p in @($(& $arr $RemoveList))) {
    `$first = `$null
    try { Remove-Printer -Name `$p -ErrorAction Stop }
    catch {
        `$first = `$_.Exception.Message      # keep the original reason if the fallback fails too
        try { (New-Object -ComObject WScript.Network).RemovePrinterConnection(`$p, `$true, `$true); `$first = `$null } catch { `$null = `$_ }
    }
    if (`$first) { `$fail++; "REMOVE FAIL : `$p :: `$first" | Add-Content -Path `$log -Encoding UTF8 }
    else         { "REMOVE OK : `$p" | Add-Content -Path `$log -Encoding UTF8 }
}
`$def = $(& $lit $DefaultPrinter)
if (`$def) {
    try { (New-Object -ComObject WScript.Network).SetDefaultPrinter(`$def); "DEFAULT OK : `$def" | Add-Content -Path `$log -Encoding UTF8 }
    catch {
        # printui /y does not report errors: keep the first reason; the result is read back by the admin side
        "DEFAULT FAIL : `$def :: `$(`$_.Exception.Message) (printui fallback tried)" | Add-Content -Path `$log -Encoding UTF8
        & rundll32.exe printui.dll,PrintUIEntry /y /n "`$def"; Start-Sleep -Seconds 2
    }
}
"DONE" | Add-Content -Path `$log -Encoding UTF8
exit `$fail
"@

    try {
        Set-Content -Path $helperPath -Value $helper -Encoding UTF8 -ErrorAction Stop
        $action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
                        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$helperPath`""
        $principal = New-ScheduledTaskPrincipal -UserId $TargetUser -LogonType Interactive
        Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop

        # Poll until finished. State can flip to Ready a beat before
        # LastTaskResult finalizes (transient 0x41301 = 267009).
        $deadline = (Get-Date).AddSeconds($TimeoutSec)
        do {
            Start-Sleep -Seconds 2
            $state = (Get-ScheduledTask     -TaskName $TaskName -ErrorAction Stop).State
            $code  = (Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop).LastTaskResult
        } while ( ($state -eq 'Running' -or $code -eq 267009) -and (Get-Date) -lt $deadline )

        $out.Code = $code
        if (Test-Path $logPath) { $out.Log = (Get-Content $logPath -Raw -ErrorAction SilentlyContinue) }
        if ($out.Log) { $out.Log = $out.Log.Trim() }

        if ($state -eq 'Running' -or $code -eq 267009) { $out.Status = 'Timeout'; $out.Message = "Task did not finish within ${TimeoutSec}s (a printer may still be staging its driver). Partial results shown; re-check the list." }
        elseif ($code -eq 267011) { $out.Status = 'Aborted'; $out.Message = "Task did not run - is '$TargetUser' logged on to '$($env:COMPUTERNAME)'? No interactive session." }
        elseif (-not $out.Log)    { $out.Message = "Task ran (exit $code) but produced no log. Verify manually." }
        elseif ($code -eq 0)      { $out.Status = 'Success'; $out.Message = 'Done in the user session.' }
        else                      { $out.Status = 'Partial'; $out.Message = "$code action(s) failed in the user session." }
    }
    catch { $out.Message = "Setup/execution error: $($_.Exception.Message)" }
    finally {
        Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue |
            Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item $helperPath, $logPath -Force -ErrorAction SilentlyContinue
    }
    return $out
}

# ------------------------- Local helpers -------------------------

$order = @{ 'User connection' = 0; 'Local printer' = 1; 'Machine connection' = 2 }

# Reads the printers + meta (default printer, profile) from the target.
function Get-TargetPrinter {
    $rows = @(Invoke-Command -ComputerName $ComputerName -ScriptBlock $GetPrintersBlock -ArgumentList $TargetUser)
    [pscustomobject]@{
        Meta     = $rows | Where-Object RowType -eq 'Meta' | Select-Object -First 1
        Printers = @($rows | Where-Object RowType -eq 'Printer' | Sort-Object { $order[$_.Kind] }, Name)
    }
}

function Show-PrinterList {
    param($State)
    if ($State.Printers.Count -eq 0) { Write-Host '  (no printer)' -ForegroundColor Yellow; return }
    for ($i = 0; $i -lt $State.Printers.Count; $i++) {
        $p = $State.Printers[$i]
        $isDefault = $State.Meta.Default -and $p.Name -eq $State.Meta.Default
        $extra = @()
        if ($p.Driver) { $extra += $p.Driver }
        if ($p.Port)   { $extra += "port $($p.Port)" }
        Write-Host ("  [{0,2}] {1,-19} {2}{3}{4}" -f ($i + 1), $p.Kind, $p.Name, $(if ($extra) { "  ($($extra -join ', '))" }), $(if ($isDefault) { '  <- DEFAULT' })) `
            -ForegroundColor $(if ($isDefault) { 'Green' } else { 'White' })
    }
}

# Runs the user-session task; returns its status object (or $null), prints problems.
function Invoke-UserSession {
    param([string]$Add = '', [string]$Remove = '', [string]$Default = '')
    $us = Invoke-Command -ComputerName $ComputerName -ScriptBlock $UserSessionBlock `
            -ArgumentList $TargetUser, $TaskName, $script:ProfilePath, $Add, $Remove, $Default, $TimeoutSec
    if ($null -eq $us) { Write-Host '  ERROR: no result returned from the user session. Verify manually.' -ForegroundColor Red }
    elseif ($us.Status -notin 'Success', 'Partial') { Write-Host "  $($us.Status.ToUpper()) : $($us.Message)" -ForegroundColor Red }
    return $us
}

# "ADD FAIL : name :: reason" -> reason, for one name and one verb
function Get-LogReason {
    param($UserStatus, [string]$Verb, [string]$Name)
    if (-not $UserStatus -or -not $UserStatus.Log) { return $null }
    foreach ($l in ($UserStatus.Log -split "`r?`n")) {
        if ($l.StartsWith("$Verb FAIL : $Name :: ")) { return $l.Substring("$Verb FAIL : $Name :: ".Length) }
    }
    return $null
}

# ------------------------- Prompts + checks -------------------------

$ComputerName = (Read-Host 'Target machine name').Trim()
if (-not $ComputerName) { Write-Host 'ERROR: no machine name. Aborting.' -ForegroundColor Red; exit 1 }

$TargetUser = (Read-Host 'Target username (DOMAIN\user or plain username)').Trim()
if (-not $TargetUser) { Write-Host 'ERROR: no username. Aborting.' -ForegroundColor Red; exit 1 }

Write-Host "`nChecking WinRM on '$ComputerName'..." -ForegroundColor Cyan
try {
    Test-WSMan -ComputerName $ComputerName -ErrorAction Stop | Out-Null
    Write-Host 'WinRM reachable.' -ForegroundColor Green
}
catch {
    Write-Host "ERROR: cannot reach '$ComputerName' via WinRM. Enable-PSRemoting on the target." -ForegroundColor Red
    Write-Host "Details: $($_.Exception.Message)" -ForegroundColor DarkRed
    exit 1
}

$state = Get-TargetPrinter
if ($null -eq $state.Meta) { Write-Host 'ERROR: no result returned (session failure?). Verify target manually.' -ForegroundColor Red; exit 1 }
if (-not $state.Meta.Ok)   { Write-Host "ERROR: $($state.Meta.Message)" -ForegroundColor Red; exit 1 }
if (-not $state.Meta.ProfilePath) { Write-Host "ERROR: profile path of '$TargetUser' not found on '$ComputerName'." -ForegroundColor Red; exit 1 }
$script:ProfilePath = $state.Meta.ProfilePath
$allOk = $true

# ------------------------- Windows default printer management (every run) -------------------------

$lm = Invoke-Command -ComputerName $ComputerName -ScriptBlock $LegacyModeBlock -ArgumentList $state.Meta.Sid
if ($null -eq $lm -or -not $lm.Ok) {
    $allOk = $false
    Write-Host "FAIL : could not turn off 'Let Windows manage my default printer': $(if ($lm) { $lm.Message } else { 'no result returned' })" -ForegroundColor Red
}
elseif ($lm.WasOn) { Write-Host "'Let Windows manage my default printer' was ON for '$TargetUser' - turned OFF." -ForegroundColor Green }
else               { Write-Host "'Let Windows manage my default printer' is already OFF for '$TargetUser'." -ForegroundColor DarkGray }

# ------------------------- Menu loop -------------------------

while ($true) {
    Write-Host "`nPrinters for '$TargetUser' on '$ComputerName':" -ForegroundColor Cyan
    Show-PrinterList -State $state
    Write-Host "`nAction: [1] Add  [2] Remove  [3] Change default  [4] Quit" -ForegroundColor Cyan
    do { $action = (Read-Host 'Enter action (1, 2, 3 or 4)').Trim() } while ($action -notin '1', '2', '3', '4')

    switch ($action) {

        # ---------------- Add ----------------
        '1' {
            $server = (Read-Host 'Print server name (e.g. printsrv01)').Trim().TrimStart('\')
            $names  = Read-Host $(if ($server) { "Printer share name(s) on \\$server (comma-separated, e.g. PRN01,PRN02)" } else { 'Printer path(s) (comma-separated, e.g. \\server\PRN01)' })
            # Plain names get the server prefix, full \\ paths are kept as-is
            $paths = @($names -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object {
                if ($_.StartsWith('\\')) { $_ } elseif ($server) { "\\$server\$($_.TrimStart('\'))" }
            } | Select-Object -Unique)
            $ignored = @($names -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $server -and -not $_.StartsWith('\\') })
            if ($ignored) { Write-Host "Ignored (no print server given, use \\server\share): $($ignored -join ', ')" -ForegroundColor Yellow }
            if ($paths.Count -eq 0) { Write-Host 'No printer to add.' -ForegroundColor Yellow; break }

            Write-Host "Adding $($paths.Count) printer(s) in the session of '$TargetUser'..." -ForegroundColor Cyan
            $us    = Invoke-UserSession -Add ($paths -join '|')
            $state = Get-TargetPrinter
            foreach ($p in $paths) {
                $present = [bool]($state.Printers | Where-Object { $_.Kind -eq 'User connection' -and $_.Name -eq $p })
                if ($present) { Write-Host "  OK   : $p - added" -ForegroundColor Green }
                else {
                    $allOk = $false
                    $why = Get-LogReason -UserStatus $us -Verb 'ADD' -Name $p
                    Write-Host "  FAIL : $p - $(if ($why) { $why } else { 'not present after the add' })" -ForegroundColor Red
                }
            }
        }

        # ---------------- Remove ----------------
        '2' {
            if ($state.Printers.Count -eq 0) { Write-Host 'No printer to remove.' -ForegroundColor Yellow; break }
            $pick = (Read-Host 'Number(s) to remove, comma-separated (e.g. 1,3; blank = cancel)').Trim()
            $idx  = @($pick -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } |
                      ForEach-Object { [int]$_ } | Where-Object { $_ -ge 1 -and $_ -le $state.Printers.Count } | Select-Object -Unique)
            $sel  = @($idx | ForEach-Object { $state.Printers[$_ - 1] })
            if ($sel.Count -eq 0) { Write-Host 'Nothing selected - no printer removed.' -ForegroundColor Yellow; break }

            Write-Host ''
            Write-Host "WARNING : this will remove $($sel.Count) printer(s) on '$ComputerName':" -ForegroundColor Red
            foreach ($s in $sel) {
                $note = switch ($s.Kind) { 'User connection' { "for '$TargetUser'" } 'Local printer' { 'for ALL users of the machine' } 'Machine connection' { 'for ALL users, at their next logon' } }
                Write-Host ("          {0} ({1} - {2}){3}" -f $s.Name, $s.Kind, $note, $(if ($state.Meta.Default -and $s.Name -eq $state.Meta.Default) { ' - this is the DEFAULT printer' })) -ForegroundColor Red
            }
            Write-Host '          Do you want to continue ?' -ForegroundColor Red
            do { $a = (Read-Host 'CONTINUE : YES\NO').Trim().ToUpper() } while ($a -notin 'YES', 'NO')
            if ($a -ne 'YES') { Write-Host 'Cancelled. Nothing changed.' -ForegroundColor Yellow; break }

            $machRes = @()
            $machSel = @($sel | Where-Object Kind -ne 'User connection')
            $userSel = @($sel | Where-Object Kind -eq 'User connection')
            if ($machSel.Count) {
                Write-Host 'Removing machine-wide printer(s)...' -ForegroundColor Cyan
                $machRes = @(Invoke-Command -ComputerName $ComputerName -ScriptBlock $RemoveMachineBlock `
                                -ArgumentList (, [string[]]@($machSel | ForEach-Object { "$($_.Kind)|$($_.Name)" })))
            }
            $us = $null
            if ($userSel.Count) {
                Write-Host "Removing user printer(s) in the session of '$TargetUser'..." -ForegroundColor Cyan
                $us = Invoke-UserSession -Remove ($userSel.Name -join '|')
            }

            $state = Get-TargetPrinter
            foreach ($s in $sel) {
                $still = [bool]($state.Printers | Where-Object { $_.Kind -eq $s.Kind -and $_.Name -eq $s.Name })
                if (-not $still) {
                    $suffix = if ($s.Kind -eq 'Machine connection') { 'removed for all users (applies at their next logon)' } else { 'removed' }
                    Write-Host "  OK   : $($s.Name) - $suffix" -ForegroundColor Green
                }
                else {
                    $allOk = $false
                    $why = if ($s.Kind -eq 'User connection') { Get-LogReason -UserStatus $us -Verb 'REMOVE' -Name $s.Name }
                           else { ($machRes | Where-Object { $_.Name -eq $s.Name -and $_.Message } | Select-Object -First 1).Message }
                    Write-Host "  FAIL : $($s.Name) - $(if ($why) { $why } else { 'still present after removal' })" -ForegroundColor Red
                }
            }
            Write-Host 'Note: printers deployed by Group Policy / management tools come back at the next policy refresh or logon.' -ForegroundColor DarkGray
        }

        # ---------------- Change default ----------------
        '3' {
            if ($state.Printers.Count -eq 0) { Write-Host 'No printer to choose from.' -ForegroundColor Yellow; break }
            $choice = $null
            do {
                $c = (Read-Host 'Number of the new default printer (blank = cancel)').Trim()
                if (-not $c) { break }
                $n = 0
                if ([int]::TryParse($c, [ref]$n) -and $n -ge 1 -and $n -le $state.Printers.Count) { $choice = $state.Printers[$n - 1] }
            } while (-not $choice)
            if (-not $choice) { Write-Host 'Default printer unchanged.' -ForegroundColor DarkGray; break }

            Write-Host "Setting '$($choice.Name)' as default printer in the session of '$TargetUser'..." -ForegroundColor Cyan
            $us    = Invoke-UserSession -Default $choice.Name
            $state = Get-TargetPrinter
            $now   = $state.Meta.Default
            if ($now -and $now -eq $choice.Name) { Write-Host "  OK   : default printer is now '$now'" -ForegroundColor Green }
            else {
                $allOk = $false
                $why = Get-LogReason -UserStatus $us -Verb 'DEFAULT' -Name $choice.Name
                Write-Host "  FAIL : could not set '$($choice.Name)' as default - $(if ($why) { "$why - " })default is '$now'" -ForegroundColor Red
                Write-Host '         If this keeps failing, check whether a Group Policy enforces Windows default printer management.' -ForegroundColor DarkGray
            }
        }

        # ---------------- Quit ----------------
        '4' {
            if ($allOk) { Write-Host "`nDone - every action succeeded." -ForegroundColor Green; exit 0 }
            Write-Host "`nDone - some actions failed (see above)." -ForegroundColor Yellow
            exit 1
        }
    }
}