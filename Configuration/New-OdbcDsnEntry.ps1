<#
.SYNOPSIS
    Lists, creates or removes ODBC DSNs (User or System, 32/64-bit) on a
    remote machine. Everything is prompted; nothing is hard-coded.

.DESCRIPTION
    [1] List   : read-only. Shows User DSNs (for one logged-on user), System
                 DSNs (32 + 64-bit), or both, with their driver and settings.
                 Password values, if any exist, are masked.
    [2] Create : pick a driver from the list of drivers INSTALLED ON THE TARGET
                 (the choice also sets 32/64-bit), one or more DSN names, then:
                   - Microsoft SQL Server drivers: guided prompts (server,
                     database, Windows authentication, encryption);
                   - any other driver: free "Key=Value; Key=Value" input.
                 Existing DSNs with the same name: skip / replace / abort.
                 Summary + YES/NO before anything is written, read-back after.
    [3] Remove : numbered list, pick one or more, YES/NO, read-back after.

    How DSNs are created: with Add-OdbcDsn, which calls the driver's own setup
    routine (what the ODBC wizard does). The driver writes the values it
    expects, so this script needs no knowledge of any driver's registry layout.
      - System DSN : Add-OdbcDsn -DsnType System, run in the admin remote session.
      - User DSN   : Add-OdbcDsn -DsnType User writes to the hive of whoever runs
                     it, so it is run IN THE USER'S SESSION via a one-shot
                     interactive scheduled task (same technique as the remote
                     process tool). Per-DSN results come back through a log in
                     the user's own LocalAppData (only that user + admins can
                     write there), which is deleted afterwards.
    Listing and removing User DSNs read/delete the user's registry keys
    directly from the admin session (HKU\<SID>\Software\ODBC\ODBC.INI).

    Security: passwords are never accepted (PWD / Password keys are refused).
    Some drivers would store them in the registry in plain text. Windows
    authentication only for the guided SQL Server mode.

.NOTES
    Execution : from an admin workstation, against a remote machine
    Requires  : WinRM enabled on the target, admin rights on the target
    Changes   : Yes - adds or remove ODBC connections to the user's session and/or system session. 
    
    Detailed requirements:
    - Admin rights on the target + WinRM enabled (domain-joined machines /
      Kerberos; workgroup targets need extra WinRM configuration).
    - User DSN (any action): the target user must be logged on (profile hive
      loaded - with FSLogix it is only mounted during the session).
    - Windows 8 / Server 2012 or later on the target (Wdac module: Add-OdbcDsn).

    The User-DSN task passes its commands as a Base64-encoded PowerShell
    command (-EncodedCommand), so no quoting can break. Some EDR / antivirus
    products alert on encoded PowerShell; if yours does, tell IT security the
    task name below is expected.

    Limitations: property values cannot contain ';' (used as the separator).
    One machine per run; after each action the menu comes back, [4] Quit ends.
    Exit code (on Quit) = result of the last action: 0 = done, 1 = aborted / failed / partial.
#>

$TaskName        = 'TEMP_RemoteOdbcDsn'
$TimeoutSec      = 60
$InvalidDsnChars = '[\[\]{}(),;?*=!@\\]'          # characters ODBC does not allow in a DSN name
$SecretKeys      = 'pwd', 'password', 'passwd', 'pass'

# ============================ Remote script blocks ============================

# Resolves the user's SID and profile path, and checks their hive is loaded.
$GetUserContext = {
    param($TargetUser)
    $out = [pscustomobject]@{ Ok = $false; Sid = ''; ProfilePath = ''; Message = '' }
    try {
        $out.Sid = (New-Object System.Security.Principal.NTAccount($TargetUser)).Translate(
                    [System.Security.Principal.SecurityIdentifier]).Value
    }
    catch { $out.Message = "Cannot resolve '$TargetUser' to an account on $env:COMPUTERNAME."; return $out }

    $out.ProfilePath = (Get-ItemProperty -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($out.Sid)" -ErrorAction SilentlyContinue).ProfileImagePath
    if (-not (Test-Path -LiteralPath "Registry::HKEY_USERS\$($out.Sid)")) {
        $out.Message = "Profile hive of '$TargetUser' is not loaded - the user must be logged on to $env:COMPUTERNAME."
        return $out
    }
    $out.Ok = $true
    return $out
}

# Drivers installed on the target (flat objects).
$GetDrivers = {
    Get-OdbcDriver -Platform All -ErrorAction Stop |
        ForEach-Object { [pscustomobject]@{ Name = $_.Name; Platform = $_.Platform } }
}

# Read-only listing straight from the registry, the same place the ODBC
# administrator reads from. User DSNs share one key for 32 and 64-bit; their
# bitness is worked out by matching the driver DLL against ODBCINST.INI.
$ListDsns = {
    param([string[]]$Scopes, $Sid, [string[]]$SecretKeys)

    $psProps = 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider'

    function Get-DriverDll($Driver, [bool]$Wow) {
        $base = if ($Wow) { 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\ODBC\ODBCINST.INI' }
                else      { 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\ODBC\ODBCINST.INI' }
        (Get-ItemProperty -LiteralPath "$base\$Driver" -ErrorAction SilentlyContinue).Driver
    }

    function Read-OdbcIni($Root, $Type, $Platform) {
        $srcKey = "$Root\ODBC Data Sources"
        if (-not (Test-Path -LiteralPath $srcKey)) { return }
        $src = Get-ItemProperty -LiteralPath $srcKey
        foreach ($name in (Get-Item -LiteralPath $srcKey).Property) {
            $driver   = $src.$name
            $dll      = ''
            $settings = @()
            $vals = Get-ItemProperty -LiteralPath "$Root\$name" -ErrorAction SilentlyContinue
            if ($vals) {
                foreach ($p in $vals.PSObject.Properties) {
                    if ($psProps -contains $p.Name) { continue }
                    if ($p.Name -eq 'Driver') { $dll = $p.Value; continue }
                    $v = if ($SecretKeys -contains $p.Name.ToLower()) { '********' } else { $p.Value }
                    $settings += "$($p.Name)=$v"
                }
            }
            $plat = $Platform
            if (-not $plat) {
                if     ($dll -and $dll -eq (Get-DriverDll $driver $true))  { $plat = '32-bit' }
                elseif ($dll -and $dll -eq (Get-DriverDll $driver $false)) { $plat = '64-bit' }
                else   { $plat = '?' }
            }
            [pscustomobject]@{ Name = $name; Type = $Type; Platform = $plat; Driver = $driver; Settings = ($settings -join '; ') }
        }
    }

    if ($Scopes -contains 'System') {
        Read-OdbcIni 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\ODBC\ODBC.INI'             'System' '64-bit'
        Read-OdbcIni 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\ODBC\ODBC.INI' 'System' '32-bit'
    }
    if ($Scopes -contains 'User' -and $Sid) {
        Read-OdbcIni "Registry::HKEY_USERS\$Sid\Software\ODBC\ODBC.INI" 'User' $null
    }
}

# System DSNs: created in the admin session.
$CreateSystemDsns = {
    param([string[]]$Names, $Driver, $Platform, [string[]]$Props, [bool]$DbFromName, [string[]]$Replace)
    foreach ($n in $Names) {
        $r = [pscustomobject]@{ Name = $n; Result = 'FAIL'; Message = '' }
        try {
            $p = @($Props | Where-Object { $_ })
            if ($DbFromName) { $p += "Database=$n" }
            if ($Replace -contains $n) { Remove-OdbcDsn -Name $n -DsnType System -Platform $Platform -ErrorAction Stop }
            if ($p.Count -gt 0) { Add-OdbcDsn -Name $n -DriverName $Driver -DsnType System -Platform $Platform -SetPropertyValue $p -ErrorAction Stop }
            else                { Add-OdbcDsn -Name $n -DriverName $Driver -DsnType System -Platform $Platform -ErrorAction Stop }
            $r.Result = 'OK'
        }
        catch { $r.Message = $_.Exception.Message }
        $r
    }
}

# System DSNs: removed in the admin session. Items are "name|platform".
$RemoveSystemDsns = {
    param([string[]]$Items)
    foreach ($i in $Items) {
        $cut  = $i.LastIndexOf('|')
        $n    = $i.Substring(0, $cut)
        $plat = $i.Substring($cut + 1)
        $r = [pscustomobject]@{ Name = $n; Result = 'FAIL'; Message = '' }
        try   { Remove-OdbcDsn -Name $n -DsnType System -Platform $plat -ErrorAction Stop; $r.Result = 'OK' }
        catch { $r.Message = $_.Exception.Message }
        $r
    }
}

# User DSNs: removed by deleting the user's ODBC.INI entries (what ODBC itself
# does on removal). Also used for "replace" before re-creating.
$RemoveUserDsns = {
    param($Sid, [string[]]$Names)
    $root = "Registry::HKEY_USERS\$Sid\Software\ODBC\ODBC.INI"
    $src  = "$root\ODBC Data Sources"
    foreach ($n in $Names) {
        $r = [pscustomobject]@{ Name = $n; Result = 'FAIL'; Message = '' }
        try {
            if (Test-Path -LiteralPath "$root\$n") { Remove-Item -LiteralPath "$root\$n" -Recurse -Force -ErrorAction Stop }
            if ((Get-Item -LiteralPath $src -ErrorAction SilentlyContinue).Property -contains $n) {
                Remove-ItemProperty -LiteralPath $src -Name $n -Force -ErrorAction Stop
            }
            $r.Result = 'OK'
        }
        catch { $r.Message = $_.Exception.Message }
        $r
    }
}

# User DSNs: runs the prepared (encoded) command in the user's session, then
# reads back its per-DSN log. The log sits in the user's own LocalAppData.
$RunInSession = {
    param($TargetUser, $TaskName, $EncodedCommand, $TimeoutSec, $LogPath)

    $out = [pscustomobject]@{ Status = 'Failed'; Code = $null; Log = ''; Message = '' }

    Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue |
        Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $LogPath -Force -ErrorAction SilentlyContinue

    try {
        $action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
                        -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $EncodedCommand"
        $principal = New-ScheduledTaskPrincipal -UserId $TargetUser -LogonType Interactive
        Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -ErrorAction Stop | Out-Null
        Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop

        # Poll until finished. State can flip to Ready a beat before
        # LastTaskResult finalizes (transient 0x41301 = 267009).
        $deadline = (Get-Date).AddSeconds($TimeoutSec)
        do {
            Start-Sleep -Seconds 1
            $state = (Get-ScheduledTask     -TaskName $TaskName -ErrorAction Stop).State
            $code  = (Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop).LastTaskResult
        } while ( ($state -eq 'Running' -or $code -eq 267009) -and (Get-Date) -lt $deadline )
        $out.Code = $code

        if (Test-Path -LiteralPath $LogPath) { $out.Log = (Get-Content -LiteralPath $LogPath -Raw -ErrorAction SilentlyContinue) }

        if     ($code -eq 267011)                          { $out.Status = 'Aborted'; $out.Message = "Task did not run - is '$TargetUser' logged on to '$($env:COMPUTERNAME)'? No interactive session." }
        elseif ($state -eq 'Running' -or $code -eq 267009) { $out.Status = 'Timeout'; $out.Message = "Task did not finish within ${TimeoutSec}s. Partial results (if any) below." }
        elseif (-not $out.Log)                             { $out.Message = "Task ran (code $code) but wrote no log - the session could not run the commands. Verify manually." }
        else                                               { $out.Status = 'Done' }
    }
    catch { $out.Message = "Setup/execution error: $($_.Exception.Message)" }
    finally {
        Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue |
            Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $LogPath -Force -ErrorAction SilentlyContinue
    }
    return $out
}

# ============================ Local helpers ============================

function Read-Menu {
    param([string]$Prompt, [int]$Max)
    do {
        $a = (Read-Host $Prompt).Trim()
        $n = 0
        $ok = [int]::TryParse($a, [ref]$n) -and $n -ge 1 -and $n -le $Max
    } while (-not $ok)
    return $n
}

function Read-YesNoDefault {
    param([string]$Prompt, [string]$Default)
    do {
        $a = (Read-Host "$Prompt [Yes/No, Enter = $Default]").Trim()
        if (-not $a) { $a = $Default }
        $a = (Get-Culture).TextInfo.ToTitleCase($a.ToLower())
    } while ($a -notin 'Yes', 'No')
    return $a
}

function Confirm-YesNo {
    do { $a = (Read-Host 'CONTINUE : YES\NO').Trim().ToUpper() } while ($a -notin 'YES', 'NO')
    return ($a -eq 'YES')
}

function Show-Dsns {
    param($Rows)
    $Rows | Sort-Object Type, Name, Platform |
        Format-Table Name, Type, Platform, Driver, Settings -AutoSize -Wrap |
        Out-String -Width 220 | Write-Host
}

function Show-Results {
    param($Results)
    foreach ($r in $Results) {
        if ($r.Result -eq 'OK') { Write-Host "  OK   : $($r.Name)" -ForegroundColor Green }
        else                    { Write-Host "  FAIL : $($r.Name) :: $($r.Message)" -ForegroundColor Red }
    }
}

# "Key=Value; Key=Value" -> ordered dictionary. Returns $null (after printing why) on bad input.
function ConvertFrom-PropertyString {
    param([string]$Text, [System.Collections.Specialized.OrderedDictionary]$Into)
    foreach ($part in ($Text -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        if ($part -notmatch '^\s*([^=]+?)\s*=\s*(.*)$') {
            Write-Host "ERROR: '$part' is not Key=Value." -ForegroundColor Red
            return $null
        }
        $k = $Matches[1]; $v = $Matches[2]
        if ($SecretKeys -contains $k.ToLower()) {
            Write-Host "ERROR: '$k' refused - this script never stores passwords in a DSN (use Windows authentication)." -ForegroundColor Red
            return $null
        }
        $Into[$k] = $v     # a later value for the same key wins
    }
    return $Into
}

# ============================ Prompts ============================

$ComputerName = (Read-Host 'Target machine name').Trim()
if (-not $ComputerName) { Write-Host 'ERROR: no machine name. Aborting.' -ForegroundColor Red; exit 1 }

# ============================ WinRM + user context ============================

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

# ============================ Action loop ============================
# After each action the menu comes back (same machine); [4] Quit ends the script.
# The action runs in its own scope, so nothing leaks from one action to the next.
$lastCode = 0
while ($true) {
    $lastCode = @(& {
    Write-Host ''
    Write-Host 'Action:' -ForegroundColor Cyan
    Write-Host '  [1] List DSNs (read-only)' -ForegroundColor White
    Write-Host '  [2] Create DSN(s)' -ForegroundColor White
    Write-Host '  [3] Remove DSN(s)' -ForegroundColor White
    Write-Host '  [4] Quit' -ForegroundColor White
    $action = Read-Menu -Prompt 'Enter action (1, 2, 3 or 4)' -Max 4
    if ($action -eq 4) { exit $lastCode }

    Write-Host ''
    Write-Host 'DSN type:' -ForegroundColor Cyan
    Write-Host '  [1] User DSN   (one user; must be logged on)' -ForegroundColor White
    Write-Host '  [2] System DSN (all users of the machine)' -ForegroundColor White
    if ($action -eq 1) { Write-Host '  [3] Both' -ForegroundColor White }
    $typeChoice = Read-Menu -Prompt "Enter type (1, 2$(if ($action -eq 1) { ' or 3' } else { '' }))" -Max $(if ($action -eq 1) { 3 } else { 2 })
    $Scopes = switch ($typeChoice) { 1 { @('User') } 2 { @('System') } 3 { @('User', 'System') } }
    $DsnType = if ($typeChoice -eq 2) { 'System' } else { 'User' }   # used by Create / Remove

    $TargetUser = ''
    if ($Scopes -contains 'User') {
        $TargetUser = (Read-Host 'Target username (DOMAIN\user or user)').Trim()
        if (-not $TargetUser) { Write-Host 'ERROR: a username is required for User DSNs. Aborting.' -ForegroundColor Red; return 1 }
    }

    $ctx = $null
    if ($TargetUser) {
        $ctx = Invoke-Command -ComputerName $ComputerName -ScriptBlock $GetUserContext -ArgumentList $TargetUser
        if ($null -eq $ctx -or -not $ctx.Ok) {
            Write-Host "ERROR: $($ctx.Message)" -ForegroundColor Red
            return 1
        }
    }
    $Sid = if ($ctx) { $ctx.Sid } else { '' }

    # ============================ [1] List ============================

    if ($action -eq 1) {
        $rows = @(Invoke-Command -ComputerName $ComputerName -ScriptBlock $ListDsns -ArgumentList $Scopes, $Sid, $SecretKeys)
        Write-Host ''
        if ($rows.Count -eq 0) { Write-Host 'No DSN found.' -ForegroundColor Yellow; return 0 }
        Write-Host "$($rows.Count) DSN(s) on '$ComputerName'$(if ($TargetUser) { " (User DSNs for '$TargetUser')" }):" -ForegroundColor Cyan
        Show-Dsns $rows
        return 0
    }

    # ============================ [3] Remove ============================

    if ($action -eq 3) {
        $rows = @(Invoke-Command -ComputerName $ComputerName -ScriptBlock $ListDsns -ArgumentList $Scopes, $Sid, $SecretKeys |
                  Sort-Object Name, Platform)
        if ($rows.Count -eq 0) { Write-Host "`nNo $DsnType DSN found. Nothing to remove." -ForegroundColor Yellow; return 0 }

        Write-Host "`n$DsnType DSNs on '$ComputerName':" -ForegroundColor Cyan
        for ($i = 0; $i -lt $rows.Count; $i++) {
            Write-Host ("  [{0}] {1}  ({2}, {3})" -f ($i + 1), $rows[$i].Name, $rows[$i].Platform, $rows[$i].Driver) -ForegroundColor White
        }
        $pick = (Read-Host "`nNumber(s) to remove, comma-separated (e.g. 1,3)").Trim()
        $idx  = @($pick -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } |
                  ForEach-Object { [int]$_ } | Where-Object { $_ -ge 1 -and $_ -le $rows.Count } | Select-Object -Unique)
        if ($idx.Count -eq 0) { Write-Host 'Nothing selected. Aborting.' -ForegroundColor Yellow; return 1 }
        $sel = @($idx | ForEach-Object { $rows[$_ - 1] })

        Write-Host ''
        Write-Host "WARNING : this will remove $($sel.Count) $DsnType DSN(s) on '$ComputerName'$(if ($TargetUser) { " for '$TargetUser'" }): $(($sel | ForEach-Object { "$($_.Name) ($($_.Platform))" }) -join ', '). Do you want to continue ?" -ForegroundColor Red
        if (-not (Confirm-YesNo)) { Write-Host 'Aborted by operator. Nothing done.' -ForegroundColor Yellow; return 1 }

        if ($DsnType -eq 'System') {
            $res = @(Invoke-Command -ComputerName $ComputerName -ScriptBlock $RemoveSystemDsns -ArgumentList (, [string[]]@($sel | ForEach-Object { "$($_.Name)|$($_.Platform)" })))
        } else {
            $res = @(Invoke-Command -ComputerName $ComputerName -ScriptBlock $RemoveUserDsns -ArgumentList $Sid, ([string[]]@($sel.Name | Select-Object -Unique)))
        }
        Write-Host "`nResults:" -ForegroundColor Cyan
        Show-Results $res

        # Read-back: nothing selected should still be listed
        $after = @(Invoke-Command -ComputerName $ComputerName -ScriptBlock $ListDsns -ArgumentList $Scopes, $Sid, $SecretKeys)
        $left  = @($sel | Where-Object { $s = $_; $after | Where-Object { $_.Name -eq $s.Name -and $_.Platform -eq $s.Platform } })
        Write-Host ''
        if ($left.Count -eq 0 -and -not ($res | Where-Object Result -ne 'OK')) { Write-Host 'SUCCESS : read-back confirms the DSN(s) are gone.' -ForegroundColor Green; return 0 }
        Write-Host "PARTIAL : still present: $(($left | ForEach-Object { $_.Name }) -join ', ')" -ForegroundColor Yellow
        return 1
    }

    # ============================ [2] Create ============================

    # --- Driver (from the target) ---
    try   { $drivers = @(Invoke-Command -ComputerName $ComputerName -ScriptBlock $GetDrivers -ErrorAction Stop | Sort-Object Name, Platform) }
    catch { Write-Host "ERROR: could not list ODBC drivers on '$ComputerName': $($_.Exception.Message)" -ForegroundColor Red; return 1 }
    if ($drivers.Count -eq 0) { Write-Host "ERROR: no ODBC driver installed on '$ComputerName'." -ForegroundColor Red; return 1 }

    Write-Host "`nODBC drivers installed on '$ComputerName':" -ForegroundColor Cyan
    for ($i = 0; $i -lt $drivers.Count; $i++) {
        Write-Host ("  [{0}] {1}  ({2})" -f ($i + 1), $drivers[$i].Name, $drivers[$i].Platform) -ForegroundColor White
    }
    $drv      = $drivers[(Read-Menu -Prompt 'Enter driver number' -Max $drivers.Count) - 1]
    $Driver   = $drv.Name
    $Platform = $drv.Platform

    # --- DSN name(s) ---
    $Names = @((Read-Host "`nDSN name(s), comma-separated for several with the same settings") -split ',' |
               ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
    if ($Names.Count -eq 0) { Write-Host 'ERROR: no DSN name. Aborting.' -ForegroundColor Red; return 1 }
    $bad = @($Names | Where-Object { $_ -match $InvalidDsnChars })
    if ($bad) { Write-Host "ERROR: invalid character in: $($bad -join ', ')  (not allowed: [ ] { } ( ) , ; ? * = ! @ \)" -ForegroundColor Red; return 1 }

    # --- Settings ---
    $props      = New-Object System.Collections.Specialized.OrderedDictionary
    $DbFromName = $false
    $isSql      = $Driver -match '^(SQL Server|SQL Server Native Client [\d.]+|ODBC Driver \d+ for SQL Server)$'

    if ($isSql) {
        Write-Host "`nMicrosoft SQL Server driver - guided settings." -ForegroundColor Cyan
        $server = (Read-Host 'SQL server (e.g. sqlsrv01, sqlsrv01\INSTANCE, sqlsrv01,1433)').Trim()
        if (-not $server) { Write-Host 'ERROR: no server. Aborting.' -ForegroundColor Red; return 1 }
        $props['Server'] = $server

        $db = (Read-Host 'Database (blank = login default, * = same as each DSN name)').Trim()
        if ($db -eq '*') { $DbFromName = $true } elseif ($db) { $props['Database'] = $db }

        $props['Trusted_Connection'] = 'Yes'
        Write-Host 'Authentication: Windows (Trusted_Connection=Yes). SQL logins / passwords are not supported by this script.' -ForegroundColor DarkGray

        if ($Driver -match '^ODBC Driver (\d+) for SQL Server$') {
            $ver        = [int]$Matches[1]
            $encDefault = if ($ver -ge 18) { 'Yes' } else { 'No' }   # the driver's own default
            if ($ver -ge 18) {
                Write-Host "Note: Driver $ver encrypts by default. The SQL server then needs a certificate this machine trusts," -ForegroundColor Yellow
                Write-Host "      otherwise set TrustServerCertificate=Yes (connection still encrypted, but the certificate is not checked)." -ForegroundColor Yellow
            }
            $props['Encrypt']                = Read-YesNoDefault -Prompt 'Encrypt' -Default $encDefault
            $props['TrustServerCertificate'] = Read-YesNoDefault -Prompt 'TrustServerCertificate' -Default 'No'
        }

        $extra = Read-Host 'Additional properties (Key=Value; Key=Value, blank = none)'
        if ($extra.Trim() -and $null -eq (ConvertFrom-PropertyString -Text $extra -Into $props)) { return 1 }
    }
    else {
        Write-Host "`n'$Driver' is not a Microsoft SQL Server driver - enter its properties as documented by the vendor." -ForegroundColor Cyan
        $free = Read-Host 'Properties (Key=Value; Key=Value, blank = none)'
        if ($free.Trim() -and $null -eq (ConvertFrom-PropertyString -Text $free -Into $props)) { return 1 }
    }
    if ($DbFromName -and $props.Contains('Database')) { $props.Remove('Database') }   # '*' wins over an explicit Database
    $PropList = [string[]]@($props.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" })

    # --- Existing DSNs with the same name ---
    $existingRows = @(Invoke-Command -ComputerName $ComputerName -ScriptBlock $ListDsns -ArgumentList $Scopes, $Sid, $SecretKeys |
                      Where-Object { $Names -contains $_.Name -and ($DsnType -eq 'User' -or $_.Platform -eq $Platform) })
    $Replace = @()
    if ($existingRows.Count -gt 0) {
        Write-Host "`nAlready existing ($DsnType$(if ($DsnType -eq 'System') { ", $Platform" })):" -ForegroundColor Yellow
        Show-Dsns $existingRows
        do { $a = (Read-Host '[S]kip them / [R]eplace them / [A]bort').Trim().ToUpper() } while ($a -notin 'S', 'R', 'A')
        switch ($a) {
            'A' { Write-Host 'Aborted by operator. Nothing done.' -ForegroundColor Yellow; return 1 }
            'S' { $Names = @($Names | Where-Object { $existingRows.Name -notcontains $_ }) }
            'R' { $Replace = @($existingRows.Name | Select-Object -Unique) }
        }
        if ($Names.Count -eq 0) { Write-Host 'Nothing left to create.' -ForegroundColor Yellow; return 0 }
    }

    # --- Summary + confirmation ---
    Write-Host ''
    Write-Host '---------------- Summary ----------------' -ForegroundColor Cyan
    Write-Host "  Machine    : $ComputerName"
    Write-Host "  DSN type   : $DsnType$(if ($TargetUser) { " (user '$TargetUser')" })"
    Write-Host "  Driver     : $Driver ($Platform)"
    Write-Host "  DSN name(s): $($Names -join ', ')"
    Write-Host "  Properties : $(if ($PropList) { $PropList -join '; ' } else { '(none)' })$(if ($DbFromName) { '; Database=<DSN name>' })"
    if ($Replace) { Write-Host "  REPLACING  : $($Replace -join ', ')" -ForegroundColor Yellow }
    Write-Host '-----------------------------------------' -ForegroundColor Cyan
    Write-Host "WARNING : this will create $($Names.Count) $DsnType DSN(s) on '$ComputerName'$(if ($Replace) { ' and replace existing ones' }). Do you want to continue ?" -ForegroundColor Red
    if (-not (Confirm-YesNo)) { Write-Host 'Aborted by operator. Nothing done.' -ForegroundColor Yellow; return 1 }

    # --- Execute ---
    if ($DsnType -eq 'System') {
        $res = @(Invoke-Command -ComputerName $ComputerName -ScriptBlock $CreateSystemDsns `
                    -ArgumentList $Names, $Driver, $Platform, $PropList, $DbFromName, $Replace)
    }
    else {
        if ($Replace) {
            $rem = @(Invoke-Command -ComputerName $ComputerName -ScriptBlock $RemoveUserDsns -ArgumentList $Sid, ([string[]]$Replace))
            if ($rem | Where-Object Result -ne 'OK') {
                Write-Host "`nERROR: could not remove the DSN(s) to replace - nothing created:" -ForegroundColor Red
                Show-Results $rem
                return 1
            }
        }

        # Command run in the user's session. Every value is a single-quoted literal
        # (quotes doubled); the whole command is then Base64-encoded.
        $lit = { param($s) "'" + ($s -replace "'", "''") + "'" }
        $arr = { param($a) '@(' + (@($a | ForEach-Object { & $lit $_ }) -join ',') + ')' }
        if (-not $ctx.ProfilePath) { Write-Host "ERROR: profile path of '$TargetUser' not found on '$ComputerName'. Nothing created." -ForegroundColor Red; return 1 }
        $LogPath = Join-Path $ctx.ProfilePath 'AppData\Local\TEMP_RemoteOdbcDsn.log'

        $cmd = @(
            "`$log = $(& $lit $LogPath)"
            'Set-Content -LiteralPath $log -Value START -Encoding UTF8 -ErrorAction Stop'
            '$fail = 0'
            "foreach (`$n in $(& $arr $Names)) {"
            '    try {'
            "        `$p = $(& $arr $PropList)"
            "        if (`$$DbFromName) { `$p += ""Database=`$n"" }"
            "        `$a = @{ Name = `$n; DriverName = $(& $lit $Driver); DsnType = 'User'; Platform = $(& $lit $Platform); ErrorAction = 'Stop' }"
            '        if ($p.Count -gt 0) { $a.SetPropertyValue = [string[]]$p }'
            '        Add-OdbcDsn @a'
            '        Add-Content -LiteralPath $log -Value "OK|$n" -Encoding UTF8'
            '    } catch {'
            '        $fail++'
            '        Add-Content -LiteralPath $log -Value ("FAIL|$n|" + ($_.Exception.Message -replace ''\s*[\r\n]+\s*'', '' '')) -Encoding UTF8'
            '    }'
            '}'
            'Add-Content -LiteralPath $log -Value DONE -Encoding UTF8'
            'exit $fail'
        ) -join "`n"
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))

        Write-Host "`nCreating in '$TargetUser''s session..." -ForegroundColor Cyan
        $run = Invoke-Command -ComputerName $ComputerName -ScriptBlock $RunInSession -ArgumentList $TargetUser, $TaskName, $enc, $TimeoutSec, $LogPath
        if ($null -eq $run) { Write-Host 'ERROR: no result returned (session failure?). Verify target manually.' -ForegroundColor Red; return 1 }
        if ($run.Status -ne 'Done') { Write-Host "$($run.Status.ToUpper()) : $($run.Message)" -ForegroundColor Red }

        $res = @($run.Log -split "`r?`n" | Where-Object { $_ -like 'OK|*' -or $_ -like 'FAIL|*' } | ForEach-Object {
            $f = $_ -split '\|', 3
            [pscustomobject]@{ Name = $f[1]; Result = $(if ($f[0] -eq 'OK') { 'OK' } else { 'FAIL' }); Message = $(if ($f.Count -gt 2) { $f[2] } else { '' }) }
        })
    }

    Write-Host "`nResults:" -ForegroundColor Cyan
    if ($res.Count -eq 0) { Write-Host '  (no per-DSN result returned)' -ForegroundColor Red } else { Show-Results $res }

    # --- Read-back (what the driver actually stored) ---
    $after = @(Invoke-Command -ComputerName $ComputerName -ScriptBlock $ListDsns -ArgumentList $Scopes, $Sid, $SecretKeys |
               Where-Object { $Names -contains $_.Name })
    Write-Host "`nRead-back from '$ComputerName':" -ForegroundColor Cyan
    if ($after.Count -gt 0) { Show-Dsns $after } else { Write-Host '  none of the DSNs are present.' -ForegroundColor Red }

    $okCount = @($res | Where-Object Result -eq 'OK').Count
    if ($okCount -eq $Names.Count -and $after.Count -ge $Names.Count) { Write-Host 'SUCCESS : all DSNs created and confirmed by read-back.' -ForegroundColor Green; return 0 }
    Write-Host "PARTIAL : $okCount of $($Names.Count) created. See results above." -ForegroundColor Yellow
    return 1
    })[-1]
    Write-Host "`n=========================================== (back to menu)`n" -ForegroundColor DarkCyan
}
