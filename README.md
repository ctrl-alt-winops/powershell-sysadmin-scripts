# powershell-sysadmin-scripts

Interactive PowerShell tools for remote Windows helpdesk and administration tasks.

## Scripts

| Script | Folder | Runs | Changes state | Description |
|---|---|:---:|:---:|---|
| [Install-TeamsMeetingAddin](Deployment/Install-TeamsMeetingAddin.ps1) | Deployment | Remote (WinRM) | Yes | Installs the Teams Meeting Add-in (new Teams). ⚠️ Closes Outlook and Teams on the target |
| [Add-PrinterConnection](Configuration/Add-PrinterConnection.ps1) | Configuration | Remote (WinRM) | Yes | Adds network printers to a user's session |
| [New-OdbcDsnEntry](Configuration/New-OdbcDsnEntry.ps1) | Configuration | Remote (WinRM) | Yes | Creates ODBC DSN entries |
| [Export-EventLogReport](Troubleshooting/Export-EventLogReport.ps1) | Troubleshooting | Remote (WinRM) | No | Queries event logs for a time window and exports an HTML report |
| [Invoke-ProcessAction](Troubleshooting/Invoke-ProcessAction.ps1) | Troubleshooting | Remote (WinRM) | Yes | Starts, stops or restarts a process |

All scripts are interactive: they prompt for the target machine and any other input they need (e.g. print server and printer names).

## Requirements

- Windows PowerShell 5.1 on the admin workstation
- WinRM enabled on the target machine
- An account with administrative rights on the target machine

## Usage

1. Download the script.
2. Unblock it, since files downloaded from the internet may be blocked by the execution policy:
```powershell
   Unblock-File .\Add-PrinterConnection.ps1
```
3. Read the built-in help:
```powershell
   Get-Help .\Add-PrinterConnection.ps1 -Full
```
4. Run it and follow the prompts.

## Disclaimer

Test in a non-production environment first, and review each script before running it against production machines. Provided as-is, without warranty; see [LICENSE](LICENSE).

## Acknowledgements

Developed with assistance from Claude (Anthropic) for consistency checks, bug fixes, documentation, naming and logic review. All code reviewed and tested by the author.

## License

[MIT](LICENSE)
