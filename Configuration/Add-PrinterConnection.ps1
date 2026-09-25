<#
.SYNOPSIS
    Adds one or more network printers to a user's session on a remote machine.

.DESCRIPTION
    Prompts for machine name, username, print server, and one or more printer
    share names (comma-separated). An entry starting with \\ is used as a full
    path as-is, so printers on another server can be mixed in.
    Via PowerShell Remoting, registers a ONE-SHOT interactive
    scheduled task that runs Add-Printer -ConnectionName in the target user's
    OWN session, so the spooler provisions the (already-deployed) driver via
    point-and-print and the printer appears immediately.

    Why a task and not Add-Printer inside Invoke-Command: the latter would add
    the printer to the admin's remote session, not the user's. Why the user
    must be logged on: FSLogix mounts the profile only during the session.

.NOTES
    Execution : from an admin workstation, against a remote machine
    Requires  : WinRM enabled on the target, admin rights on the target
    Changes   : Yes - adds printer connections to the user's session

    Detailed requirements:
    - Admin rights on the target machine + WinRM enabled.
    - Target user currently logged on.
    - Printer drivers already present on the fleet (point-and-print, no admin
      prompt for standard users).

    One machine per run. Exit code: 0 = all requested printers added,
    1 = aborted / at least one printer failed.
#>

$TaskName     = 'TEMP_AddPrinters'
$TimeoutSec   = 180   # point-and-print driver staging can be slow on first connect

# ------------------------- Prompts -------------------------

$ComputerName = (Read-Host 'Target machine name').Trim()
if (-not $ComputerName) { Write-Host 'ERROR: no machine name. Aborting.' -ForegroundColor Red; exit 1 }

$TargetUser = (Read-Host 'Target username (DOMAIN\user or plain username)').Trim()
if (-not $TargetUser) { Write-Host 'ERROR: no username. Aborting.' -ForegroundColor Red; exit 1 }

# Leading backslashes are tolerated ("\\server" or "server")
$PrintServer = (Read-Host 'Print server name (e.g. printsrv01)').Trim().TrimStart('\')
if (-not $PrintServer) { Write-Host 'ERROR: no print server. Aborting.' -ForegroundColor Red; exit 1 }

$PrinterInput = Read-Host "Printer share name(s) on \\$PrintServer (comma-separated, e.g. PRN01,PRN02)"

# Build the printer connection list: plain names get the server prefix, full \\ paths are kept as-is
$PrinterPaths = @($PrinterInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object {
    if ($_.StartsWith('\\')) { $_ } else { "\\$PrintServer\$($_.TrimStart('\'))" }
} | Select-Object -Unique)
if ($PrinterPaths.Count -eq 0) { Write-Host 'ERROR: no printer name. Aborting.' -ForegroundColor Red; exit 1 }

Write-Host "`nPrinters to add:" -ForegroundColor Cyan
$PrinterPaths | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }

# ------------------------- WinRM check -------------------------

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

# ------------------------- Remote execution -------------------------

Write-Host "Adding printers for '$TargetUser' on '$ComputerName'...`n" -ForegroundColor Cyan

$result = Invoke-Command -ComputerName $ComputerName `
    -ArgumentList $TargetUser, $TaskName, ($PrinterPaths -join '|'), $TimeoutSec `
    -ScriptBlock {
    param($TargetUser, $TaskName, $PrinterList, $TimeoutSec)

    $out = [pscustomobject]@{ Status = 'Failed'; Code = $null; Log = ''; Message = '' }

    # Rebuild the array from the delimited string. Passing the array directly
    # via -ArgumentList can collapse it (nested-array wrapping), which joins
    # all paths into one bogus printer name - a delimited string is immune.
    $PrinterPaths = $PrinterList -split '\|'

    $helperPath = "C:\Users\Public\$TaskName.ps1"
    $logPath    = "C:\Users\Public\$TaskName.log"

    # Clean leftovers from any prior run
    Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue |
        Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $helperPath, $logPath -Force -ErrorAction SilentlyContinue

    # Build the helper script the user's session will execute.
    # $logPath / $listLiteral expand now; all other $ are escaped (backtick)
    # so they stay literal in the generated file.
    # Single quotes are doubled so a name containing ' cannot break the generated script.
    $listLiteral = ($PrinterPaths | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ','

    $helper = @"
`$ErrorActionPreference = 'Stop'
`$log = '$logPath'
`$printers = @($listLiteral)
"START" | Set-Content -Path `$log -Encoding UTF8
`$fail = 0
foreach (`$p in `$printers) {
    try {
        Add-Printer -ConnectionName `$p -ErrorAction Stop
        "OK   : `$p" | Add-Content -Path `$log -Encoding UTF8
    } catch {
        `$fail++
        "FAIL : `$p :: `$(`$_.Exception.Message)" | Add-Content -Path `$log -Encoding UTF8
    }
}
"DONE" | Add-Content -Path `$log -Encoding UTF8
exit `$fail
"@

    try {
        Set-Content -Path $helperPath -Value $helper -Encoding UTF8 -ErrorAction Stop

        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
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

        if ($state -eq 'Running' -or $code -eq 267009) {
            $out.Status  = 'Timeout'
            $out.Message = "Task did not finalize within ${TimeoutSec}s. Partial results (if any) shown above; the slow printer is likely staging a driver. Re-run to confirm, or raise `$TimeoutSec."
        }
        elseif ($code -eq 267011) {
            $out.Status  = 'Aborted'
            $out.Message = "Task did not run - is '$TargetUser' logged on to '$($env:COMPUTERNAME)'? No interactive session."
        }
        elseif (-not $out.Log) {
            $out.Message = "Task ran (exit $code) but produced no log. Verify manually."
        }
        elseif ($code -eq 0) {
            $out.Status  = 'Success'
            $out.Message = "All requested printers added for '$TargetUser'."
        }
        else {
            $out.Status  = 'Partial'
            $out.Message = "$code printer(s) failed. See per-printer results."
        }
    }
    catch {
        $out.Message = "Setup/execution error: $($_.Exception.Message)"
    }
    finally {
        Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue |
            Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item $helperPath, $logPath -Force -ErrorAction SilentlyContinue
    }

    return $out
}

# ------------------------- Report -------------------------

if ($null -eq $result) {
    Write-Host 'ERROR: no result returned (session failure?). Verify target manually.' -ForegroundColor Red
    exit 1
}

if ($result.Log) {
    Write-Host "`nPer-printer results:" -ForegroundColor Cyan
    $result.Log -split "`r?`n" | Where-Object { $_ -like 'OK*' -or $_ -like 'FAIL*' } | ForEach-Object {
        $color = if ($_ -like 'OK*') { 'Green' } else { 'Red' }
        Write-Host "  $_" -ForegroundColor $color
    }
}

Write-Host ''
switch ($result.Status) {
    'Success' { Write-Host "SUCCESS : $($result.Message)" -ForegroundColor Green;  exit 0 }
    'Partial' { Write-Host "PARTIAL : $($result.Message)" -ForegroundColor Yellow; exit 1 }
    'Timeout' { Write-Host "TIMEOUT : $($result.Message)" -ForegroundColor Yellow; exit 1 }
    'Aborted' { Write-Host "ABORTED : $($result.Message)" -ForegroundColor Red;    exit 1 }
    default   { Write-Host "FAILED  : $($result.Message)" -ForegroundColor Red;    exit 1 }
}
