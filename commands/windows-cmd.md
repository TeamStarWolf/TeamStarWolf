# Windows Command Prompt Reference

The Windows Command Prompt (`cmd.exe`) runs built-in commands and console utilities on every Windows release. It is the oldest Windows shell and still the home of batch scripting and many administrative tools. This page covers the builtins and utilities a sysadmin or security engineer uses at the prompt. PowerShell is the modern shell, but `cmd.exe` remains on every host and in countless scripts.

## What it is and where it runs

`cmd.exe` is the Windows command interpreter, present on Windows client and server editions. Some commands listed here are interpreter builtins (`dir`, `copy`, `del`); others are separate executables in `%SystemRoot%\System32` (`ipconfig.exe`, `sc.exe`, `reg.exe`). Many administrative commands require an elevated prompt, started with "Run as administrator". Paths use backslashes, and environment variables are written `%VAR%`.

## Core commands

Files and directories:

```bat
dir /a C:\Users            :: list all entries, including hidden
cd /d D:\projects          :: change drive and directory
copy report.txt D:\backup\ :: copy a file
move old.txt archive\      :: move or rename
del /p temp.log            :: delete, prompt for confirmation
type config.ini            :: print a file to the console
```

| Command | Purpose |
|---|---|
| `dir` | List directory contents |
| `cd` | Change the current directory |
| `copy` / `xcopy` | Copy files |
| `move` | Move or rename |
| `del` | Delete files |
| `type` | Display a text file |

Searching and processes:

```bat
findstr /s /i "password" *.config   :: recursive case-insensitive search
tasklist /v                         :: list processes with detail
tasklist /svc                       :: show services hosted per process
taskkill /pid 4821 /f               :: force-terminate a process by PID
```

| Command | Purpose |
|---|---|
| `findstr` | Search text with patterns |
| `tasklist` | List running processes |
| `taskkill` | Terminate processes |

Accounts and groups:

```bat
whoami /all                         :: user, groups, and privileges
net user                            :: list local accounts
net user alice                      :: detail for one account
net localgroup administrators       :: members of the admins group
```

| Command | Purpose |
|---|---|
| `whoami` | Show current user and token detail |
| `net user` | View or manage local accounts |
| `net localgroup` | View or manage local groups |

System, services, and configuration:

```bat
ipconfig /all                       :: full network adapter detail
systeminfo                          :: OS, patches, and hardware summary
sc query wuauserv                   :: query a service state
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
schtasks /query /fo LIST /v         :: list scheduled tasks in detail
icacls C:\srv\app                   :: show file permissions
```

| Command | Purpose |
|---|---|
| `ipconfig` | Show and manage IP configuration |
| `systeminfo` | Report system and patch level |
| `sc` | Query and control services |
| `reg` | Read and write the registry |
| `schtasks` | Manage scheduled tasks |
| `icacls` | View and edit file ACLs |

## Common workflows

Find which process holds a listening port, then inspect it:

```bat
netstat -ano | findstr LISTENING
tasklist /fi "pid eq 4821"
```

Collect a quick host baseline for an incident note:

```bat
systeminfo > host.txt
whoami /all >> host.txt
net localgroup administrators >> host.txt
```

Grant a service account read access to a folder with `icacls`:

```bat
icacls C:\srv\app /grant "DOMAIN\svc_app:(OI)(CI)R"
```

List the autostart registry run keys for both machine and user:

```bat
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

## Flags and options worth knowing

| Flag | Command | Effect |
|---|---|---|
| `/s` | `findstr`, `del` | Recurse into subdirectories |
| `/i` | `findstr` | Case-insensitive match |
| `/f` | `taskkill` | Force termination |
| `/p` | `del` | Prompt before deleting |
| `/a` | `dir` | Include hidden and system entries |
| `/fo LIST` | `schtasks`, `tasklist` | Format output as a readable list |
| `/grant` `/deny` | `icacls` | Add or remove an ACL entry |

## Security notes

`icacls` edits discretionary ACLs. A careless `icacls path /grant Everyone:F` grants full control to all users and maps to CWE-732. Use `/inheritance:r` deliberately, and prefer least-privilege rights such as `R` or `(OI)(CI)R` over `F`. Review ACLs after any install that writes to a shared path.

`net user` and `net localgroup` are standard account-enumeration commands for attackers after initial access. Watch for them, plus `whoami /all`, in process-creation logs (Event ID 4688). Membership changes in the local administrators group deserve an alert.

`schtasks` and `reg` run keys are common persistence mechanisms. A new scheduled task or a new value under a `...\CurrentVersion\Run` key that points to a script or a binary in a user-writable path is a red flag. Baseline these and diff them.

Many of these binaries are living-off-the-land binaries (LOLBins). `certutil`, `bitsadmin`, `regsvr32`, and `mshta` can download or execute code and are frequently abused to avoid dropping new tools. `wmic` is deprecated and removed from current Windows; prefer PowerShell CIM cmdlets, and treat residual `wmic` process-call-create activity as suspicious. See `/SECURE_CODING_REFERENCE.md` for guidance on handling untrusted input in scripts that build command lines.

## Resources

- Microsoft Windows Commands reference (the `/?` help on each command).
- Microsoft `icacls` and `net` documentation.
- Windows Internals, Russinovich, Solomon, and Ionescu.

## Related pages

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/powershell-commands.md
- /commands/networking-commands.md
- /commands/linux-commands.md
