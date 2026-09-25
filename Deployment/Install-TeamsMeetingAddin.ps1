# =============================================================================
# WARNING: BE CAREFUL - KILLS OUTLOOK AND TEAMS PROCESSES FOR ALL SESSIONS ON
#          THE TARGET MACHINE, WITHOUT WARNING THE USER (UNSAVED DRAFTS CAN BE
#          LOST). ON A MULTI-SESSION HOST THIS HITS EVERY LOGGED-ON USER.
# =============================================================================

<#
.SYNOPSIS
    Installs the Teams Meeting Add-in (TMA, new Teams) on a remote machine:
    stages teamsbootstrapper.exe in a locked-down folder, verifies its hash,
    force-closes Outlook + Teams, then runs teamsbootstrapper.exe --installTMA.

.DESCRIPTION
    WARNING: KILLS OUTLOOK AND TEAMS FOR ALL SESSIONS ON THE TARGET.

    Prompts for the machine and the path of teamsbootstrapper.exe (local or
    UNC path; a folder containing it is also accepted). Then:
      1. Verifies the bootstrapper exists and hashes it (SHA256) from THIS
         management server.
      2. On the target: creates C:\ProgramData\IT_Staging\TeamsTMA (and its parent)
         with an explicit SYSTEM + Administrators-only ACL, owner Administrators,
         inheritance removed. Previously staged copies of the files are deleted.
      3. Copies the bootstrapper to the staging folder via \\<machine>\c$. (Copy runs from the mgmt server, not via Invoke-Command,
         to avoid the Kerberos double-hop that would block the target from
         reading the share.)
      4. On the target (elevated, via Invoke-Command): re-hashes the staged file
         and ABORTS BEFORE CLOSING ANYTHING if it differs from the source. Then
         stops outlook / ms-teams / Teams so no add-in DLL is locked, and runs
         teamsbootstrapper --installTMA from the staging folder.

    Why the locked-down folder + hash: the bootstrapper runs as admin. From a
    user-writable folder (e.g. C:\Temp) a standard user could swap the file
    before it runs.

    CONTEXT NOTE: teamsbootstrapper requires admin, so --installTMA is run in the
    ADMIN context of the remote session, not the unelevated user session. The
    add-in becomes active in classic Outlook when users reopen it.
    Result = bootstrapper exit code AND its JSON output ({"success": true/false}).

.NOTES
    Execution : from an admin workstation, against a remote machine
    Requires  : WinRM enabled on the target, admin rights on the target
    Changes   : Yes - kills outlook and teams processes and installes addin to user session

    Detailed requirements:
    - The account running this script: read access to the bootstrapper path AND
      admin rights on the target (c$ + WinRM).
    - WinRM enabled on the target.
    - New Teams already installed on the target: --installTMA installs the add-in
      MSI that ships inside the installed new Teams package.

    The staging folder is kept between runs (only the staged file is replaced).
    --installTMA is run alone: it does not reinstall / re-provision Teams itself.
    (Microsoft's documented examples combine it with -p, which also provisions
    Teams; add -p only if the bootstrapper reports that Teams is missing.)
    One machine per run. Exit codes: 0 = bootstrapper reported success,
    1 = aborted / failed.
#>

$StagingDir = 'C:\ProgramData\IT_Staging\TeamsTMA'

# Keeps the window open on the final line when launched via "Run with PowerShell".
function Close-WithPause {
    param([int]$Code)
    Read-Host "`nPress Enter to close" | Out-Null
    exit $Code
}

# Runs ON THE TARGET. Creates/locks the staging folder and its parent:
# owner = Administrators, DACL = SYSTEM + Administrators full control only,
# inheritance removed. SIDs are used so it works on any OS language.
# Fails closed: re-reads the ACL and errors if anything else is present.
$PrepareStaging = {
    param($StagingDir, [string[]]$FileNames)

    $out = [pscustomobject]@{ Ok = $false; Message = '' }
    $allowed   = 'S-1-5-18', 'S-1-5-32-544'   # SYSTEM, BUILTIN\Administrators
    $sidAdmins = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'

    try {
        foreach ($dir in (Split-Path $StagingDir -Parent), $StagingDir) {
            if (Test-Path -LiteralPath $dir) {
                $item = Get-Item -LiteralPath $dir -Force -ErrorAction Stop
                if (-not $item.PSIsContainer) { throw "'$dir' exists but is not a folder." }
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "'$dir' is a junction/symlink - refusing to use it." }
            }
            else {
                New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }

            $acl = New-Object System.Security.AccessControl.DirectorySecurity
            $acl.SetOwner($sidAdmins)
            $acl.SetAccessRuleProtection($true, $false)   # break inheritance, drop inherited ACEs
            foreach ($sid in $allowed) {
                $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    (New-Object System.Security.Principal.SecurityIdentifier $sid),
                    'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
            }
            Set-Acl -LiteralPath $dir -AclObject $acl -ErrorAction Stop

            $check  = Get-Acl -LiteralPath $dir -ErrorAction Stop
            $owner  = $check.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            $extra  = $check.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
                      Where-Object { $_.IdentityReference.Value -notin $allowed }
            if ($owner -ne 'S-1-5-32-544') { throw "owner of '$dir' is $owner, expected Administrators." }
            if ($extra) { throw "unexpected ACEs on '$dir': $(($extra.IdentityReference.Value | Sort-Object -Unique) -join ', ')" }
        }

        # Drop previously staged copies: an old file keeps its own ACL when overwritten.
        foreach ($n in $FileNames) {
            $f = Join-Path $StagingDir $n
            if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force -ErrorAction Stop }
        }
        $out.Ok = $true
    }
    catch {
        $out.Message = $_.Exception.Message
    }
    return $out
}

# ------------------------- Prompts -------------------------

$ComputerName = (Read-Host 'Target machine name').Trim()
if (-not $ComputerName) { Write-Host 'ERROR: no machine name. Aborting.' -ForegroundColor Red; Close-WithPause 1 }

$SourceBoot = (Read-Host 'Path to teamsbootstrapper.exe (local or UNC; a folder is accepted)').Trim().Trim('"')
if (-not $SourceBoot) { Write-Host 'ERROR: no path. Aborting.' -ForegroundColor Red; Close-WithPause 1 }
if (Test-Path -LiteralPath $SourceBoot -PathType Container) { $SourceBoot = Join-Path $SourceBoot 'teamsbootstrapper.exe' }

# ------------------------- Verify + hash the bootstrapper (mgmt server side) -------------------------

if (-not (Test-Path -LiteralPath $SourceBoot -PathType Leaf)) {
    Write-Host "ERROR: file not found: '$SourceBoot'. Check the path and your access to it." -ForegroundColor Red
    Close-WithPause 1
}
if ([IO.Path]::GetExtension($SourceBoot) -ne '.exe') {
    Write-Host "ERROR: '$SourceBoot' is not an .exe file." -ForegroundColor Red
    Close-WithPause 1
}
$BootName = Split-Path $SourceBoot -Leaf

Write-Host "`nBootstrapper found. Hashing (SHA256)..." -ForegroundColor Cyan
$SourceHashes = @{}
try {
    $SourceHashes[$BootName] = (Get-FileHash -LiteralPath $SourceBoot -Algorithm SHA256 -ErrorAction Stop).Hash
    Write-Host "SHA256: $($SourceHashes[$BootName])" -ForegroundColor Green
}
catch {
    Write-Host "ERROR: could not hash '$SourceBoot': $($_.Exception.Message)" -ForegroundColor Red
    Close-WithPause 1
}

# ------------------------- WinRM check -------------------------

Write-Host "Checking WinRM on '$ComputerName'..." -ForegroundColor Cyan
try {
    Test-WSMan -ComputerName $ComputerName -ErrorAction Stop | Out-Null
    Write-Host 'WinRM reachable.' -ForegroundColor Green
}
catch {
    Write-Host "ERROR: cannot reach '$ComputerName' via WinRM. Enable-PSRemoting on the target." -ForegroundColor Red
    Write-Host "Details: $($_.Exception.Message)" -ForegroundColor DarkRed
    Close-WithPause 1
}

# ------------------------- Prepare locked-down staging folder (target) -------------------------

Write-Host "Preparing staging folder '$StagingDir' on '$ComputerName'..." -ForegroundColor Cyan
$prep = Invoke-Command -ComputerName $ComputerName -ScriptBlock $PrepareStaging -ArgumentList $StagingDir, @($BootName)
if ($null -eq $prep -or -not $prep.Ok) {
    Write-Host "ERROR: staging folder preparation failed: $($prep.Message)" -ForegroundColor Red
    Write-Host 'Nothing was copied or run.' -ForegroundColor Red
    Close-WithPause 1
}
Write-Host 'Staging folder ready (SYSTEM + Administrators only).' -ForegroundColor Green

# ------------------------- Copy sources to the staging folder -------------------------

$destUnc = "\\$ComputerName\" + ($StagingDir -replace '^([A-Za-z]):', '$1$')

Write-Host "Copying '$BootName' to '$destUnc'..." -ForegroundColor Cyan
try {
    Copy-Item -LiteralPath $SourceBoot -Destination $destUnc -Force -ErrorAction Stop
    Write-Host 'Copy done.' -ForegroundColor Green
}
catch {
    Write-Host "ERROR: copy failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check admin share access (\\$ComputerName\c$) and disk space." -ForegroundColor Red
    Close-WithPause 1
}

# ------------------------- Verify hashes, close apps, run installTMA (target, elevated) -------------------------

Write-Host "Verifying staged file, then closing Outlook/Teams and running --installTMA on '$ComputerName'...`n" -ForegroundColor Cyan

# Runs ON THE TARGET (stored in a variable, like the other scripts' remote blocks).
$InstallTmaBlock = {
    param($StagingDir, $BootName, $SourceHashes)

    $out = [pscustomobject]@{ Status = 'Failed'; Code = $null; Closed = @(); Output = ''; Message = '' }

    # Hash check BEFORE touching any process: a mismatch leaves the user's session untouched.
    foreach ($name in $SourceHashes.Keys) {
        $staged = Join-Path $StagingDir $name
        if (-not (Test-Path -LiteralPath $staged)) {
            $out.Status  = 'Aborted'
            $out.Message = "'$staged' not found after copy. Nothing closed or run."
            return $out
        }
        $h = (Get-FileHash -LiteralPath $staged -Algorithm SHA256).Hash
        if ($h -ne $SourceHashes[$name]) {
            $out.Status  = 'Aborted'
            $out.Message = "HASH MISMATCH on '$name' (source $($SourceHashes[$name]), staged $h). Nothing closed or run."
            return $out
        }
    }

    # Close anything that would lock the add-in (all sessions, admin context)
    foreach ($p in 'outlook', 'ms-teams', 'Teams') {
        $procs = Get-Process -Name $p -ErrorAction SilentlyContinue
        if ($procs) {
            $procs | Stop-Process -Force -ErrorAction SilentlyContinue
            $out.Closed += $p
        }
    }
    Start-Sleep -Seconds 2

    $exe = Join-Path $StagingDir $BootName
    try {
        $captured   = & $exe --installTMA 2>&1 | Out-String
        $out.Code   = $LASTEXITCODE
        $out.Output = $captured.Trim()

        # The bootstrapper prints JSON such as {"success": true}. A reported
        # failure counts even when the exit code is 0.
        $json = $null
        $m = [regex]::Match($out.Output, '\{[\s\S]*\}')
        if ($m.Success) { try { $json = $m.Value | ConvertFrom-Json -ErrorAction Stop } catch { $json = $null } }

        if ($out.Code -eq 0 -and -not ($json -and $json.success -eq $false)) {
            $out.Status  = 'Success'
            $out.Message = if ($json) { 'teamsbootstrapper --installTMA reported success.' } else { 'teamsbootstrapper --installTMA exited 0 (no JSON result to confirm).' }
        } else {
            $out.Message = "teamsbootstrapper --installTMA reported failure (exit code $($out.Code))."
        }
    }
    catch {
        $out.Message = "Execution error: $($_.Exception.Message)"
    }

    return $out
}

$result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $InstallTmaBlock `
    -ArgumentList $StagingDir, $BootName, $SourceHashes

# ------------------------- Report -------------------------

if ($null -eq $result) {
    Write-Host 'ERROR: no result returned (session failure?). Verify target manually.' -ForegroundColor Red
    Close-WithPause 1
}

if ($result.Closed -and $result.Closed.Count -gt 0) {
    Write-Host "Closed before install: $($result.Closed -join ', ')" -ForegroundColor DarkGray
}

if ($result.Output) {
    Write-Host 'Bootstrapper output:' -ForegroundColor Cyan
    Write-Host $result.Output
    Write-Host ''
}

switch ($result.Status) {
    'Success' { Write-Host "SUCCESS : $($result.Message) The add-in loads when users reopen Outlook." -ForegroundColor Green; Close-WithPause 0 }
    'Aborted' { Write-Host "ABORTED : $($result.Message)" -ForegroundColor Red; Close-WithPause 1 }
    default   { Write-Host "FAILED  : $($result.Message)" -ForegroundColor Red; Close-WithPause 1 }
}
