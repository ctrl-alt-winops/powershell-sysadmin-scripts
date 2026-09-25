<#
.SYNOPSIS
    Starts, kills or restarts a process on a remote machine.

.DESCRIPTION
    Prompts for machine, action, process/program and user.

    [1] Start   : starts a program IN THE TARGET USER'S SESSION, as that user
                  (e.g. explorer.exe, outlook.exe, ms-teams.exe, or a full path).
    [2] Kill    : stops every process with that name, for ONE user, or for ALL
                  sessions if the username is left blank. The matching processes
                  are listed first (read-only) and must be confirmed with YES.
    [3] Restart : Kill for one user (listed + confirmed), then Start again in
                  that user's session. If the process comes back on its own
                  (Windows restarts Explorer automatically), no second copy is
                  started.

    How Start works: a one-shot interactive scheduled task runs a hidden
    PowerShell in the user's session, which calls Start-Process and exits.
    Start-Process finds programs the way Win+R does: full paths, the user's
    PATH, registered App Paths (outlook.exe, winword.exe...) and app execution
    aliases (ms-teams.exe). The program is not a child of the task, so it is
    not affected by the task's time limit or by the task being deleted.
    Why a task and not Invoke-Command: Invoke-Command would start the program
    in the admin's own invisible remote session, not on the user's screen.

    Safety: critical Windows processes (csrss, lsass, winlogon, svchost...) are
    refused, because killing them crashes or logs off the whole machine.

.NOTES
    Execution : from an admin workstation, against a remote machine
    Requires  : WinRM enabled on the target, admin rights on the target
    Changes   : Yes - kills or starts processes on the user session

    Detailed requirements:
    - Admin rights on the target + WinRM enabled (domain-joined machines /
      Kerberos; workgroup targets need extra WinRM configuration).
    - Start / Restart: the target user must be logged on.

    The program and arguments are passed to the task as a Base64-encoded
    PowerShell command (-EncodedCommand), so no quoting can break. Some EDR /
    antivirus products alert on encoded PowerShell; if yours does, tell IT
    security this task name is expected, or ask for the -File variant.
    A PowerShell console may flash for a split second in the user's session.

    Read-only until you confirm: the Kill/Restart preview changes nothing.
    One machine per run. Exit codes: 0 = done, 1 = aborted / failed / partial.
#>

$TaskName   = 'TEMP_RemoteStartProcess'
$TimeoutSec = 20

# Killing any of these crashes, locks or logs off the machine for everyone.
$Protected = 'system', 'idle', 'registry', 'memcompression', 'smss', 'csrss', 'wininit',
             'winlogon', 'services', 'lsass', 'lsaiso', 'svchost', 'fontdrvhost'

# ============================ Remote script blocks ============================

# Read-only: lists processes by name, optionally filtered on one user.
# A plain username matches any domain (DOMAIN\jdoe or .\jdoe); DOMAIN\user matches exactly.
$GetMatches = {
    param($Name, $User)
    Get-Process -Name $Name -IncludeUserName -ErrorAction SilentlyContinue |
        Where-Object {
            if (-not $User)        { $true }
            elseif (-not $_.UserName) { $false }
            elseif ($User -like '*\*') { $_.UserName -ieq $User }
            else                   { ($_.UserName -split '\\')[-1] -ieq $User }
        } |
        ForEach-Object {
            [pscustomobject]@{
                Id        = $_.Id
                Name      = $_.ProcessName
                UserName  = $_.UserName
                SessionId = $_.SessionId
                StartTime = $_.StartTime
                Path      = $_.Path
            }
        }
}

# Kills exactly the PIDs that were previewed and confirmed (re-checking the name,
# in case a PID was freed and reused in between), then reports survivors.
$KillPids = {
    param([string]$PidList, $Name)
    $out = [pscustomobject]@{ Killed = @(); Gone = @(); Failed = @(); StillRunning = @() }
    $ids = @($PidList -split ',' | ForEach-Object { [int]$_ })
    foreach ($id in $ids) {
        $p = Get-Process -Id $id -ErrorAction SilentlyContinue
        if (-not $p -or $p.ProcessName -ine $Name) { $out.Gone += "$id"; continue }
        try   { Stop-Process -Id $id -Force -ErrorAction Stop; $out.Killed += "$id" }
        catch { $out.Failed += "$id ($($_.Exception.Message))" }
    }
    Start-Sleep -Seconds 2
    foreach ($id in $ids) {
        $p = Get-Process -Id $id -ErrorAction SilentlyContinue
        if ($p -and $p.ProcessName -ieq $Name) { $out.StillRunning += "$id" }
    }
    return $out
}

# Starts a program in the user's interactive session via a one-shot scheduled task.
$StartInSession = {
    param($TargetUser, $TaskName, $FilePath, $Arguments, $TimeoutSec)

    $out = [pscustomobject]@{ Status = 'Failed'; Code = $null; Running = $false; Message = '' }

    # Values embedded as single-quoted PowerShell literals (quotes doubled), then the
    # whole command is Base64-encoded: nothing the operator types can break the quoting.
    $lit = { param($s) "'" + ($s -replace "'", "''") + "'" }
    $cmd = "try { Start-Process -FilePath $(& $lit $FilePath)"
    if ($Arguments) { $cmd += " -ArgumentList $(& $lit $Arguments)" }
    $cmd += ' -WindowStyle Normal -ErrorAction Stop; exit 0 } catch { ' +
            'if ($_.Exception.InnerException -is [ComponentModel.Win32Exception] -and ' +
            '$_.Exception.InnerException.NativeErrorCode -eq 2) { exit 2 }; exit 1 }'
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))

    Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue |
        Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

    try {
        $action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
                        -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $enc"
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

        switch ($code) {
            0       { $out.Status = 'Started'; $out.Message = "Start-Process succeeded in the user's session." }
            2       { $out.Message = "Program not found for that user: '$FilePath'. Try the full path." }
            1       { $out.Message = "Start-Process failed in the user's session (access denied, blocked by policy/AppLocker, or invalid arguments)." }
            267011  { $out.Status = 'Aborted'; $out.Message = "Task did not run - is '$TargetUser' logged on to '$($env:COMPUTERNAME)'? No interactive session." }
            267009  { $out.Message = "Launcher did not finish within ${TimeoutSec}s. Check the user's screen." }
            default { $out.Message = "Launcher returned code $code. Check the user's screen." }
        }

        # Informational: is a process with that name now running for the user?
        Start-Sleep -Seconds 2
        $procName = [IO.Path]::GetFileNameWithoutExtension($FilePath)
        $sam      = ($TargetUser -split '\\')[-1]
        $out.Running = [bool](Get-Process -Name $procName -IncludeUserName -ErrorAction SilentlyContinue |
                              Where-Object { $_.UserName -and ($_.UserName -split '\\')[-1] -ieq $sam })
    }
    catch {
        $out.Message = "Setup/execution error: $($_.Exception.Message)"
    }
    finally {
        Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue |
            Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
    }
    return $out
}

# ============================ Local helpers ============================

function Show-ProcessMatch {
    param($List)
    $List | Sort-Object UserName, Id |
        Format-Table Id, UserName, SessionId, @{ N = 'Started'; E = { if ($_.StartTime) { ([datetime]$_.StartTime).ToString('yyyy-MM-dd HH:mm') } } }, Path -AutoSize |
        Out-String -Width 200 | Write-Host
}

function Confirm-YesNo {
    do { $a = (Read-Host 'CONTINUE : YES\NO').Trim().ToUpper() } while ($a -notin 'YES', 'NO')
    return ($a -eq 'YES')
}

function Show-StartResult {
    param($Start, $FilePath, $TargetUser)
    $running = if ($Start.Running) { "'$([IO.Path]::GetFileNameWithoutExtension($FilePath))' is running for '$TargetUser'." }
               else { "No '$([IO.Path]::GetFileNameWithoutExtension($FilePath))' process seen for '$TargetUser' yet (normal for launchers that hand off to another process)." }
    switch ($Start.Status) {
        'Started' { Write-Host "SUCCESS : $($Start.Message) $running" -ForegroundColor Green; return 0 }
        'Aborted' { Write-Host "ABORTED : $($Start.Message)" -ForegroundColor Red; return 1 }
        default   { Write-Host "FAILED  : $($Start.Message) $running" -ForegroundColor Red; return 1 }
    }
}

# ============================ Prompts ============================

$ComputerName = (Read-Host 'Target machine name').Trim()
if (-not $ComputerName) { Write-Host 'ERROR: no machine name. Aborting.' -ForegroundColor Red; exit 1 }

Write-Host ''
Write-Host 'Action:' -ForegroundColor Cyan
Write-Host '  [1] Start a program in a user''s session' -ForegroundColor White
Write-Host '  [2] Kill a process (one user or ALL sessions)' -ForegroundColor White
Write-Host '  [3] Restart a process for a user (kill + start)' -ForegroundColor White
do { $action = (Read-Host 'Enter action (1, 2 or 3)').Trim() } while ($action -notin '1', '2', '3')

if ($action -eq '1') {
    $FilePath = (Read-Host 'Program to start (e.g. explorer.exe, outlook.exe, or full path)').Trim().Trim('"')
    if (-not $FilePath) { Write-Host 'ERROR: no program. Aborting.' -ForegroundColor Red; exit 1 }
    $Arguments = (Read-Host 'Arguments (leave blank for none)').Trim()
}
else {
    # Accept "outlook", "outlook.exe" or a full path: Get-Process wants the bare name.
    $rawName  = (Read-Host 'Process name (e.g. ms-teams, outlook.exe)').Trim().Trim('"')
    $ProcName = [IO.Path]::GetFileNameWithoutExtension($rawName)
    if (-not $ProcName) { Write-Host 'ERROR: no process name. Aborting.' -ForegroundColor Red; exit 1 }
    if ($ProcName.ToLower() -in $Protected) {
        Write-Host "ERROR: '$ProcName' is a critical Windows process. Killing it would crash or log off the machine. Refused." -ForegroundColor Red
        exit 1
    }
}

$userPrompt = switch ($action) {
    '2'     { 'Target username (DOMAIN\user or user; leave BLANK for ALL sessions)' }
    default { 'Target username (DOMAIN\user or user)' }
}
$TargetUser = (Read-Host $userPrompt).Trim()
if (-not $TargetUser -and $action -ne '2') { Write-Host 'ERROR: a username is required for Start / Restart. Aborting.' -ForegroundColor Red; exit 1 }

# ============================ WinRM check ============================

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

# ============================ [1] Start ============================

if ($action -eq '1') {
    Write-Host "Starting '$FilePath' for '$TargetUser' on '$ComputerName'...`n" -ForegroundColor Cyan
    $start = Invoke-Command -ComputerName $ComputerName -ScriptBlock $StartInSession `
                -ArgumentList $TargetUser, $TaskName, $FilePath, $Arguments, $TimeoutSec
    if ($null -eq $start) { Write-Host 'ERROR: no result returned (session failure?). Verify target manually.' -ForegroundColor Red; exit 1 }
    exit (Show-StartResult -Start $start -FilePath $FilePath -TargetUser $TargetUser)
}

# ============================ [2] Kill / [3] Restart: preview ============================

$scope = if ($TargetUser) { "user '$TargetUser'" } else { 'ALL SESSIONS' }
Write-Host "Looking for '$ProcName' ($scope) on '$ComputerName' (read-only)..." -ForegroundColor Cyan

$found = @(Invoke-Command -ComputerName $ComputerName -ScriptBlock $GetMatches -ArgumentList $ProcName, $TargetUser)
if ($found.Count -eq 0) {
    Write-Host "No '$ProcName' process found for $scope." -ForegroundColor Yellow
    if ($action -eq '2') { exit 0 }
    Write-Host 'Nothing to kill - continuing with Start only.' -ForegroundColor Yellow
}
else {
    Write-Host "`n$($found.Count) process(es) found:" -ForegroundColor Cyan
    Show-ProcessMatch -List $found
}

# Restart: decide what to start afterwards. Default = the path of the running
# process, except MSIX apps (WindowsApps folder) which must be started by name/alias.
if ($action -eq '3') {
    $firstPath = ($found | Where-Object Path | Select-Object -First 1).Path
    $default   = if ($firstPath -and $firstPath -notlike '*\WindowsApps\*') { $firstPath } else { "$ProcName.exe" }
    $typed     = (Read-Host "Program to start after the kill [Enter = $default]").Trim().Trim('"')
    $FilePath  = if ($typed) { $typed } else { $default }
    $Arguments = (Read-Host 'Arguments (leave blank for none)').Trim()
}

# ============================ Confirmation ============================

if ($found.Count -gt 0) {
    Write-Host ''
    if (-not $TargetUser) {
        Write-Host "WARNING : this will kill '$ProcName' for ALL SESSIONS on '$ComputerName' ($($found.Count) process(es), users: $((($found.UserName | Where-Object { $_ } | Sort-Object -Unique) -join ', '))). Unsaved work is lost. Do you want to continue ?" -ForegroundColor Red
    } else {
        Write-Host "WARNING : this will kill $($found.Count) '$ProcName' process(es) for '$TargetUser' on '$ComputerName'. Unsaved work is lost. Do you want to continue ?" -ForegroundColor Red
    }
    if (-not (Confirm-YesNo)) { Write-Host 'Aborted by operator. Nothing done.' -ForegroundColor Yellow; exit 1 }
}

# ============================ Kill ============================

$killOk = $true
if ($found.Count -gt 0) {
    Write-Host "`nKilling..." -ForegroundColor Cyan
    $kill = Invoke-Command -ComputerName $ComputerName -ScriptBlock $KillPids -ArgumentList (($found.Id) -join ','), $ProcName
    if ($null -eq $kill) { Write-Host 'ERROR: no result returned (session failure?). Verify target manually.' -ForegroundColor Red; exit 1 }

    if ($kill.Killed)       { Write-Host "  Killed        : PID $($kill.Killed -join ', ')" -ForegroundColor Green }
    if ($kill.Gone)         { Write-Host "  Already gone  : PID $($kill.Gone -join ', ')" -ForegroundColor DarkGray }
    if ($kill.Failed)       { Write-Host "  Failed        : $($kill.Failed -join '; ')" -ForegroundColor Red }
    if ($kill.StillRunning) { Write-Host "  Still running : PID $($kill.StillRunning -join ', ')" -ForegroundColor Red }
    $killOk = -not ($kill.Failed -or $kill.StillRunning)
}

if ($action -eq '2') {
    Write-Host ''
    if ($killOk) { Write-Host "SUCCESS : '$ProcName' stopped for $scope." -ForegroundColor Green; exit 0 }
    Write-Host "PARTIAL : some '$ProcName' processes could not be stopped (see above)." -ForegroundColor Yellow
    exit 1
}

# ============================ [3] Restart: start again ============================

if (-not $killOk) {
    Write-Host "`nABORTED : not every process was stopped, so no new copy was started." -ForegroundColor Red
    exit 1
}

if ($found.Count -gt 0) {
    Start-Sleep -Seconds 3
    $back = @(Invoke-Command -ComputerName $ComputerName -ScriptBlock $GetMatches -ArgumentList $ProcName, $TargetUser)
    if ($back.Count -gt 0) {
        Write-Host "`nSUCCESS : '$ProcName' came back on its own for '$TargetUser' (PID $($back.Id -join ', ')) - not starting a second copy." -ForegroundColor Green
        exit 0
    }
}

Write-Host "`nStarting '$FilePath' for '$TargetUser'..." -ForegroundColor Cyan
$start = Invoke-Command -ComputerName $ComputerName -ScriptBlock $StartInSession `
            -ArgumentList $TargetUser, $TaskName, $FilePath, $Arguments, $TimeoutSec
if ($null -eq $start) { Write-Host 'ERROR: no result returned (session failure?). Verify target manually.' -ForegroundColor Red; exit 1 }
exit (Show-StartResult -Start $start -FilePath $FilePath -TargetUser $TargetUser)
