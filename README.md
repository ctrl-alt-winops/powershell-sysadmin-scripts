# powershell-sysadmin-scripts

Interactive PowerShell tools for Windows helpdesk and administration tasks: deployment, printer and ODBC configuration, remote troubleshooting (event logs, processes, machine health, AD sign-in failures and lockouts) and read-only security audits (disabled AD accounts, Exchange Online mail forwarding).

## Scripts

| Script | Folder | Runs | Changes state | Description |
|---|---|:---:|:---:|---|
| [Install-TeamsMeetingAddin](Deployment/Install-TeamsMeetingAddin.ps1) | Deployment | Remote (WinRM) | Yes | Installs the Teams Meeting Add-in (new Teams). ⚠️ Closes Outlook and Teams on the target |
| [Add-PrinterConnection](Configuration/Add-PrinterConnection.ps1) | Configuration | Remote (WinRM) | Yes | Adds network printers to a user's session |
| [New-OdbcDsnEntry](Configuration/New-OdbcDsnEntry.ps1) | Configuration | Remote (WinRM) | Yes | Creates ODBC DSN entries |
| [Export-EventLogReport](Troubleshooting/Export-EventLogReport.ps1) | Troubleshooting | Remote (WinRM) | No | Queries event logs for a time window and exports an HTML report |
| [Invoke-ProcessAction](Troubleshooting/Invoke-ProcessAction.ps1) | Troubleshooting | Remote (WinRM) | Yes | Starts, stops or restarts a process |
| [Export-MachineHealthReport](Troubleshooting/Export-MachineHealthReport.ps1) | Troubleshooting | Remote (WinRM) | No | Health snapshot of a machine: uptime, disks, pending reboot, sessions, top programs, network, Group Policy, antivirus |
| [Export-ADSignInFailureReport](Troubleshooting/Export-ADSignInFailureReport.ps1) | Troubleshooting | DCs (WinRM) | No | Investigates one account's failed sign-ins and lockouts: status, failure sources, and what still uses the old password |
| [Export-ADLockoutReport](Troubleshooting/Export-ADLockoutReport.ps1) | Troubleshooting | DCs (WinRM) | No | Domain-wide lockout overview: locked accounts, caller computers, accounts still locked |
| [Export-ADDisabledAccountReport](Auditing/Export-ADDisabledAccountReport.ps1) | Auditing | Local (AD query) | No | Lists disabled AD user accounts, flagging those still in groups |
| [Export-MailboxForwardingReport](Auditing/Export-MailboxForwardingReport.ps1) | Auditing | Exchange Online | No | Audits mailbox forwarding, suspicious inbox rules and delegates (signs of payment-fraud compromise) |

All scripts are interactive: they prompt for the target machine, user or scope and any other input they need. Report scripts write an HTML report to `C:\temp` on the admin workstation.

## Requirements

- Windows PowerShell 5.1 on the admin workstation
- Remote (WinRM) scripts: WinRM enabled on the target and an account with administrative rights on it
- Additional requirements for some scripts:

| Script | Needs |
|---|---|
| Export-ADSignInFailureReport, Export-ADLockoutReport | RSAT ActiveDirectory module; rights to read the DCs' Security log (Domain Admins, or Event Log Readers + WinRM access); failure auditing of Kerberos Authentication Service and Credential Validation on the DCs |
| Export-ADDisabledAccountReport | RSAT ActiveDirectory module (any domain account can run it) |
| Export-MailboxForwardingReport | ExchangeOnlineManagement module v3+; an Exchange Online role that can read mailboxes, inbox rules and permissions. PowerShell 7 for `-SignIn DeviceCode` |

Full details for each script: `Get-Help .\<script>.ps1 -Full`.

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
