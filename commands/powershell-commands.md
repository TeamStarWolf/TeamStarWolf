# PowerShell Command Reference

PowerShell is an object pipeline shell and scripting host built on .NET. It ships on Windows and runs cross-platform as PowerShell 7+. This page is a cmdlet cheat sheet for daily administration, log review, and incident work. It is distinct from the PowerShell language page, which covers syntax and script structure.

## What it is and where it runs

Windows PowerShell 5.1 ships in every modern Windows build. PowerShell 7+ (the `pwsh` binary) runs on Windows, Linux, and macOS. Commands are cmdlets named as `Verb-Noun`, and they pass .NET objects down the pipeline rather than plain text. Run `Get-Verb` to see the approved verb list that keeps names predictable.

```powershell
$PSVersionTable.PSVersion   # which PowerShell you are in
Get-Command -Noun Service   # discover cmdlets by noun
```

## Core commands

### Discovery and help

```powershell
Get-Help Get-ChildItem -Full
Get-Help Get-Process -Examples
Get-Command -Verb Get -Noun Event*
Update-Help
```

`Get-Help` reads the documentation for a cmdlet. `Get-Command` finds cmdlets, functions, and executables. `Update-Help` pulls current help content.

### Files and content

```powershell
Get-ChildItem -Path C:\Logs -Recurse -Filter *.log
Get-Content .\app.log -Tail 50 -Wait
Get-Content .\data.json -Raw | ConvertFrom-Json
```

| Cmdlet | Purpose |
|--------|---------|
| `Get-ChildItem` | List files and directories (alias `ls`, `dir`) |
| `Get-Content` | Read a file (alias `cat`) |
| `Set-Content` | Write or replace file content |
| `Get-Acl` / `Set-Acl` | Read or apply a file or registry ACL |

### Processes and services

```powershell
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
Get-Service | Where-Object Status -eq 'Running'
Stop-Process -Name notepad -Force
```

`Get-Process` returns live process objects. `Get-Service` lists Windows services and their state.

### Event logs

```powershell
Get-WinEvent -LogName Security -MaxEvents 100
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625 } -MaxEvents 50
Get-EventLog -LogName System -Newest 20   # Windows PowerShell 5.1 only
```

`Get-WinEvent` is the current cmdlet for both classic and ETW logs. `Get-EventLog` is legacy and absent from PowerShell 7+.

### Web requests

```powershell
Invoke-WebRequest -Uri https://example.com/health -UseBasicParsing
Invoke-RestMethod -Uri https://api.example.com/v1/items -Method Get
```

`Invoke-RestMethod` parses JSON or XML into objects. `Invoke-WebRequest` returns the full response including headers and status.

### Local accounts and groups

```powershell
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember -Group Administrators
```

### Network checks

```powershell
Test-NetConnection -ComputerName 10.0.0.5 -Port 443
Test-NetConnection -ComputerName dc01 -TraceRoute
```

### The pipeline and object shaping

```powershell
Get-Process |
  Where-Object WorkingSet -gt 200MB |
  Select-Object Name, Id, @{ n='WS_MB'; e={ [math]::Round($_.WorkingSet/1MB) } } |
  Sort-Object WS_MB -Descending
```

| Cmdlet | Purpose |
|--------|---------|
| `Where-Object` | Filter objects by a condition (alias `?`) |
| `Select-Object` | Pick properties, first/last N, or computed columns |
| `ForEach-Object` | Run a script block per object (alias `%`) |
| `Sort-Object` | Order objects by a property |
| `Export-Csv` | Write objects to CSV |

## Common workflows

Find failed logons in the Security log and save them:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625 } -MaxEvents 500 |
  Select-Object TimeCreated, @{ n='Account'; e={ $_.Properties[5].Value } } |
  Export-Csv .\failed-logons.csv -NoTypeInformation
```

Audit a folder tree for files writable by Everyone:

```powershell
Get-ChildItem C:\inetpub -Recurse -File |
  ForEach-Object {
    $acl = Get-Acl $_.FullName
    if ($acl.Access | Where-Object { $_.IdentityReference -eq 'Everyone' -and $_.FileSystemRights -match 'Write' }) {
      $_.FullName
    }
  }
```

Poll an HTTP health endpoint and act on the status code:

```powershell
$r = Invoke-WebRequest -Uri https://example.com/health -UseBasicParsing
if ($r.StatusCode -ne 200) { Write-Warning "Unhealthy: $($r.StatusCode)" }
```

Open an interactive remote session on another host:

```powershell
Enter-PSSession -ComputerName dc01 -Credential (Get-Credential)
```

## Flags and options worth knowing

| Flag | Applies to | Purpose |
|------|-----------|---------|
| `-Recurse` | `Get-ChildItem` | Descend into subdirectories |
| `-Filter` | `Get-ChildItem` | Provider-side name filter, faster than `-Include` |
| `-Tail`, `-Wait` | `Get-Content` | Show last N lines and follow appends |
| `-FilterHashtable` | `Get-WinEvent` | Server-side filter, far faster than piping to `Where-Object` |
| `-NoTypeInformation` | `Export-Csv` | Drop the `#TYPE` header line |
| `-UseBasicParsing` | `Invoke-WebRequest` | Skip the legacy DOM parser |
| `-WhatIf`, `-Confirm` | state-changing cmdlets | Preview or prompt before acting |

## Security notes

Execution policy is not a security boundary. `Set-ExecutionPolicy` controls accidental script runs, not a determined attacker: `-ExecutionPolicy Bypass`, piping to `powershell -`, and dot-sourcing all sidestep it. Do not treat it as a control.

Attackers favor `-EncodedCommand` (base64) and string obfuscation to hide intent from casual review and some logging. Treat long base64 blobs in `powershell.exe` command lines as suspect and decode them during triage.

For defense, enable script block logging (Event ID 4104) and module logging through Group Policy, and turn on transcription to write a record of every session to a protected path. These capture the decoded script even when `-EncodedCommand` is used. Constrained Language Mode limits access to risky .NET types and COM objects and pairs well with application control such as WDAC or AppLocker.

Remoting over `Enter-PSSession` and `Invoke-Command` uses WinRM. Restrict it to administrators, require HTTPS listeners, and avoid passing plaintext credentials. Never embed secrets in scripts or command history; this is the hardcoded-credentials weakness (CWE-798). Validate and constrain any input passed to `Invoke-Expression`, which enables code injection (CWE-94), and prefer calling the cmdlet directly. See /SECURE_CODING_REFERENCE.md for input-handling and secret-storage guidance.

## Resources

- `Get-Help` and `about_*` conceptual help topics (`about_Pipelines`, `about_Execution_Policies`, `about_Remote`)
- Microsoft Learn: PowerShell documentation
- "Windows PowerShell in Action" by Bruce Payette
- Microsoft: "PowerShell Logging" and security hardening guidance

## Related pages

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/windows-cmd.md
- /commands/systemctl.md
- /commands/networking-commands.md
