# Digital Forensics Reference

A practitioner reference covering disk forensics, memory forensics, log analysis, and DFIR procedures — scoped to host and endpoint evidence. For network capture analysis see [Network Forensics Reference](NETWORK_FORENSICS_REFERENCE.md).

---

## Forensic Fundamentals

### Order of Volatility

RFC 3227 guidance — collect the most volatile evidence first to preserve what will be lost when the system is powered off or changes state.

| Priority | Data Type | Notes |
|---|---|---|
| 1 | CPU registers, CPU cache | Lost immediately on halt |
| 2 | Routing table, ARP cache, process table, kernel stats | In-memory, cleared on reboot |
| 3 | Memory (RAM) | Requires live acquisition or crash dump |
| 4 | Temporary files, swap / pagefile | May persist across reboots but often wiped |
| 5 | Running processes and open file handles | State changes continuously |
| 6 | Network connections | State changes continuously |
| 7 | Disk (non-volatile) | Can be modified by attacker; image before analysis |
| 8 | Remote logging (SIEM, syslog) | Off-system; may lag or be incomplete |
| 9 | Physical configuration, network topology | Mostly static; document for context |

### Chain of Custody

A documented record of who handled evidence, when, and how — required for legal admissibility.

**Required elements per item**:
- Case number and exhibit number
- Description of the evidence (make, model, serial number, capacity)
- Hash value (SHA-256) of the original and of each acquired image
- Date and time of collection
- Collector name and affiliation
- Original location (system, physical location)
- Storage location and access controls applied
- Access log: every person who accessed the evidence and when

```bash
# Hash at acquisition
sha256sum /dev/sdb | tee original_hash.txt

# Hash the acquired image and compare
sha256sum /cases/evidence.dd | tee image_hash.txt
diff original_hash.txt image_hash.txt   # must be identical
```

**Legal admissibility checklist**:
- Evidence collected with documented authorization (warrant, consent, corporate policy)
- Original media write-blocked before any examination
- Hash recorded at collection and verified at every subsequent access
- Examiner notes contemporaneous and signed

### Write Blockers

| Type | Examples | Notes |
|---|---|---|
| Hardware | Tableau T35es, WiebeTech Forensic UltraDock | Physically intercepts write commands on SATA/USB; preferred for court |
| Software (Linux) | `hdparm -r1 /dev/sdb`, `mount -o ro,noexec,nodev` | Configure before mounting; risk of driver writes on plug-in |
| Software (Windows) | Registry key `HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies\WriteProtect=1` | Enables OS-level block for removable media |

**Forensic image formats**:
| Format | Notes |
|---|---|
| raw / dd | No compression; exact sector-for-sector copy; universally compatible |
| E01 / EWF | Expert Witness Format; compressed, segmented, MD5+SHA1 embedded |
| AFF4 | Advanced Forensic Format 4; open standard, supports logical containers |

---

## Disk Forensics

### Acquiring Disk Images

```bash
# Raw image with dd
dd if=/dev/sdb of=/cases/evidence.dd bs=4M conv=noerror,sync status=progress

# Compressed E01 with ewfacquire (libewf)
ewfacquire -t /cases/evidence -f ewf -S 4G /dev/sdb

# Remote acquisition via SSH (network-limited; use only when no physical access)
ssh root@192.168.1.100 "dd if=/dev/sdb bs=4M" | dd of=/cases/remote_evidence.dd

# Verify integrity — hashes must match
sha256sum /dev/sdb > original_hash.txt
sha256sum /cases/evidence.dd > image_hash.txt

# Mount E01 read-only for analysis
ewfmount /cases/evidence.E01 /mnt/ewf/
mount -o ro,loop,noexec /mnt/ewf/ewf1 /mnt/disk/
```

### Autopsy / Sleuth Kit

**Command-line (TSK)**:
```bash
mmls evidence.dd                          # Partition table layout
fls -r -l -m / -o 2048 evidence.dd        # Recursive file listing from sector offset 2048
icat evidence.dd 2048                     # Extract inode contents
ffind evidence.dd 2048                    # Find filename associated with inode

# Deleted file recovery
tsk_recover -e evidence.dd /output/recovered/

# MACB timeline generation
fls -r -m / -o 2048 evidence.dd > /tmp/bodyfile.txt
mactime -b /tmp/bodyfile.txt -d -z UTC > timeline.txt

# String search across raw image
srch_strings -a evidence.dd | grep -i "password\|api_key\|token"
```

**Autopsy GUI workflow**:
1. Create new case → add data source (disk image or logical files)
2. Run ingest modules: keyword search, hash lookup (NSRL), EXIF extractor, email parser, web browser artifacts, recent documents, registry analysis
3. Review flagged items in Results tree; export reports as HTML/CSV

---

### Key Forensic Artifacts — Windows

#### Registry Artifacts

Hive files are located in `C:\Windows\System32\config\` (system hives) and `C:\Users\<user>\NTUSER.DAT` (per-user hive).

```
NTUSER.DAT (per user):
  Software\Microsoft\Windows\CurrentVersion\Run              → user persistence
  Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs → recently opened files
  Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist → program execution counts (ROT-13 encoded)
  Software\Microsoft\Internet Explorer\TypedURLs              → URLs typed in IE/Edge legacy

SYSTEM hive:
  CurrentControlSet\Services                                  → installed services and drivers
  CurrentControlSet\Enum\USBSTOR                              → USB storage device history
  CurrentControlSet\Control\TimeZoneInformation               → system timezone offset

SOFTWARE hive:
  Microsoft\Windows\CurrentVersion\Run                        → HKLM persistence
  Microsoft\Windows NT\CurrentVersion\ProfileList             → user profile SIDs and paths

SECURITY hive:
  LSA Secrets (encrypted) — last logon info, cached domain credentials
```

**Registry forensic tools**:
```bash
# RegRipper — automated artifact extraction from offline hives
rip.pl -r NTUSER.DAT -f ntuser > ntuser_report.txt
rip.pl -r SYSTEM   -f system  > system_report.txt
rip.pl -r SOFTWARE -f software > software_report.txt

# regipy — Python library for offline registry parsing
regipy parse NTUSER.DAT --outfile ntuser.json
```

#### Windows Event Log Forensics

Log path: `C:\Windows\System32\winevt\Logs\`

**Key event IDs**:

| Event ID | Log | Description |
|---|---|---|
| 4624 | Security | Successful logon — note Logon Type (2=interactive, 3=network, 10=remote interactive) |
| 4625 | Security | Failed logon |
| 4634 | Security | Logoff |
| 4648 | Security | Logon with explicit credentials (runas, pass-the-hash indicators) |
| 4688 | Security | Process creation (includes command line if process auditing enabled) |
| 4698 | Security | Scheduled task created |
| 4699 | Security | Scheduled task deleted |
| 4702 | Security | Scheduled task updated |
| 4720 | Security | User account created |
| 4726 | Security | User account deleted |
| 4732 | Security | Member added to security-enabled local group |
| 4740 | Security | Account lockout |
| 4768 | Security | Kerberos TGT request |
| 4769 | Security | Kerberos service ticket request |
| 4771 | Security | Kerberos pre-authentication failure |
| 4776 | Security | NTLM authentication attempt |
| 5140 | Security | Network share accessed |
| 7045 | System | New service installed |
| 1102 | Security | Audit log cleared (high priority indicator) |
| 4104 | PowerShell/Operational | Script block logged (catches encoded/obfuscated PS) |

```bash
# Parse EVTX with python-evtx
pip install python-evtx
python3 -m evtx.script.evtx_dump Security.evtx \
  | python3 -c "import sys,json; [print(l) for l in sys.stdin if '4688' in l]"

# evtxtract — carve EVTX records from raw memory or disk images
evtxtract memory.raw > carved_events.xml

# Windows LogParser (on-host)
LogParser "SELECT TimeGenerated,EventID,Message FROM Security.evtx WHERE EventID=4624" -i:EVT
```

#### Browser Forensics

**Chrome** (`%LOCALAPPDATA%\Google\Chrome\User Data\Default\`):
```bash
# History (SQLite)
sqlite3 History "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 50"

# Downloads
sqlite3 History "SELECT target_path, tab_url, start_time FROM downloads ORDER BY start_time DESC"

# Cookies (SQLite, values DPAPI-encrypted)
sqlite3 Cookies "SELECT host_key, name, creation_utc, last_access_utc FROM cookies"
```

**Firefox** (`%APPDATA%\Mozilla\Firefox\Profiles\<profile>\`):
- `places.sqlite` — history and bookmarks
- `cookies.sqlite` — cookies
- `logins.json` — saved passwords (encrypted with NSS key3.db / key4.db)

#### Prefetch Files

Location: `C:\Windows\Prefetch\`

Each `.pf` file stores: executable name, hash of full path, run count, last eight run timestamps, and files/directories accessed. Prefetch survives binary deletion — proof of execution.

```bash
# PECmd (Eric Zimmermann tools)
PECmd.exe -d C:\Windows\Prefetch --csv C:\Output\prefetch.csv
# Alternatively: WinPrefetchView GUI
```

#### Windows 10/11 Timeline

Location: `%LOCALAPPDATA%\ConnectedDevicesPlatform\<user>\ActivitiesCache.db`

Stores up to 30 days of application and document activity.

```bash
sqlite3 ActivitiesCache.db \
  "SELECT AppId, StartTime, EndTime, DisplayText FROM Activity ORDER BY StartTime DESC LIMIT 50"
```

#### Jump Lists, LNK Files, and Shellbags

```bash
# Jump Lists — recently and frequently opened files per application
JLECmd.exe -d "%AppData%\Microsoft\Windows\Recent\AutomaticDestinations" --csv output/

# LNK files — shortcut metadata reveals target path, timestamps, volume serial
LECmd.exe -d "%AppData%\Microsoft\Windows\Recent" --csv output/

# Shellbags — folder browsing history (persists even after folder deletion)
SBECmd.exe -d . --csv output/
```

---

### Key Forensic Artifacts — Linux

```bash
# Command history
cat ~/.bash_history          # No timestamps unless HISTTIMEFORMAT is set
HISTTIMEFORMAT="%F %T "      # Enable timestamped history (active session only)

# Authentication logs
/var/log/auth.log            # Debian/Ubuntu
/var/log/secure              # RHEL/CentOS/Fedora

# System logs
/var/log/syslog              # General (Debian/Ubuntu)
/var/log/messages            # General (RHEL)
/var/log/audit/audit.log     # auditd — most forensically valuable on hardened systems

# Web server logs
/var/log/apache2/access.log  # Apache
/var/log/nginx/access.log    # Nginx

# Login history
last -F                      # All logins from /var/log/wtmp (full timestamps)
lastb                        # Failed logins from /var/log/btmp
who                          # Currently logged-in users
w                            # Logged-in users + what they are running

# File timestamps (MACB: Modified / Accessed / Changed / Birth)
stat /path/to/file
ls -la --time=atime          # Last access time
ls -la --time=ctime          # Metadata change time

# Find files modified after a reference timestamp
touch -t 202501010000 /tmp/ref_time
find / -newer /tmp/ref_time -type f 2>/dev/null

# Scheduled tasks / persistence
crontab -l -u root
ls /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
cat /var/spool/cron/crontabs/*

# Systemd persistence
ls /etc/systemd/system/         # System-level units
ls ~/.config/systemd/user/      # User-level units
systemctl list-units --type=service --all

# Other common persistence locations
/etc/rc.local
/etc/init.d/
~/.config/autostart/            # Desktop autostart (GNOME/KDE)
/etc/profile.d/                 # Shell init scripts
```

---

## Memory Forensics

### Acquiring Memory

| Method | Platform | Command / Notes |
|---|---|---|
| LiME (Linux Memory Extractor) | Linux | `sudo insmod lime-$(uname -r).ko "path=/mnt/usb/memory.lime format=lime"` — kernel module, safest method |
| /dev/mem or /proc/kcore | Linux | Limited; kernel may restrict access; not preferred |
| WinPMem | Windows | `winpmem_mini_x64_rc2.exe memory.aff4` — open source, supports raw and AFF4 output |
| Magnet RAM Capture | Windows | GUI tool; outputs raw .mem file |
| FTK Imager | Windows | GUI; memory + disk acquisition |
| VM snapshot | VMware/Hyper-V | Extract .vmem (VMware) or .bin/.sav (Hyper-V) — no agent needed |
| Crash dump | Windows | `%SystemRoot%\MEMORY.DMP` (full dump configured via Advanced System Settings) |

### Volatility 3 — Complete Reference

```bash
# Install
pip install volatility3

# Auto-detect profile and show system info
vol.py -f memory.dmp windows.info

# ── Process Analysis ──────────────────────────────────────────────────────
vol.py -f memory.dmp windows.pslist            # Active processes via EPROCESS linked list
vol.py -f memory.dmp windows.pstree            # Process tree (parent-child relationships)
vol.py -f memory.dmp windows.psscan            # Pool-tag scan — finds hidden/terminated processes
vol.py -f memory.dmp windows.cmdline           # Full command line for each process
vol.py -f memory.dmp windows.dlllist --pid 1234  # Loaded DLLs for a specific process
vol.py -f memory.dmp windows.handles --pid 1234  # Open handles (files, registry keys, mutexes)

# ── Network ───────────────────────────────────────────────────────────────
vol.py -f memory.dmp windows.netstat           # Active TCP/UDP connections and sockets
vol.py -f memory.dmp windows.netscan           # Pool scan for network structures (finds closed conns)

# ── Malware Detection ─────────────────────────────────────────────────────
vol.py -f memory.dmp windows.malfind           # VAD regions with PE headers in RWX memory = injected code
vol.py -f memory.dmp windows.hollowfind        # Detect process hollowing (VAD vs PEB mismatch)
vol.py -f memory.dmp windows.driverirp         # Hooked IRP dispatch tables (rootkit indicator)

# ── Credential Extraction ─────────────────────────────────────────────────
vol.py -f memory.dmp windows.hashdump          # SAM database password hashes (NTLM)
vol.py -f memory.dmp windows.lsadump           # LSA secrets (service account passwords)
vol.py -f memory.dmp windows.cachedump         # Cached domain credentials (DCC2 hashes)

# ── Registry ──────────────────────────────────────────────────────────────
vol.py -f memory.dmp windows.registry.hivelist
vol.py -f memory.dmp windows.registry.printkey \
    --key "Software\Microsoft\Windows\CurrentVersion\Run"

# ── File System ───────────────────────────────────────────────────────────
vol.py -f memory.dmp windows.filescan                    # Scan for FILE_OBJECT structures
vol.py -f memory.dmp windows.dumpfiles --physaddr ADDR   # Extract a file from memory by physical address

# ── Linux ─────────────────────────────────────────────────────────────────
vol.py -f memory.lime linux.pslist
vol.py -f memory.lime linux.pstree
vol.py -f memory.lime linux.bash              # Bash history from memory
vol.py -f memory.lime linux.netfilter         # Netfilter hooks (rootkit indicator)
vol.py -f memory.lime linux.check_syscall     # Syscall table integrity check
```

### Memory Analysis Workflow

1. **Process comparison**: Run `windows.pslist` + `windows.psscan`; processes in psscan but not pslist are hidden (rootkit / DKOM indicator).
2. **Process tree review**: `windows.pstree` — look for orphaned processes (parent PID points to non-existent process), unexpected parent-child pairs (Word spawning `cmd.exe`, `explorer.exe` spawning `powershell.exe`).
3. **Command lines**: `windows.cmdline` — flag base64-encoded PowerShell (`-EncodedCommand`), unusual paths in `%TEMP%`, `-nop -w hidden` flags.
4. **Network review**: `windows.netstat` / `windows.netscan` — correlate connections to process PIDs; look for non-browser processes with external HTTPS/443 connections.
5. **Injection detection**: `windows.malfind` — an MZ header (`4D 5A`) at the start of an RWX VAD region is a strong indicator of injected PE (shellcode loaders, Cobalt Strike, Meterpreter).
6. **File extraction**: `windows.dumpfiles` on suspicious process → scan dumped sections with YARA rules.
7. **Credential check**: `windows.hashdump` + `windows.lsadump` — confirm scope of credential access.

**Cobalt Strike / C2 beacon indicators in memory**:
```bash
vol.py -f memory.dmp windows.malfind | grep -A5 "EXECUTE_READWRITE"
# Look for: MZ header in RWX region, PE sections named other than standard names,
# strings containing "ReflectiveDllInjection", sleep mask patterns
```

---

## Log Analysis for Forensics

### Linux Audit Log Analysis

```bash
# ausearch — structured queries against audit.log
ausearch -m EXECVE -ts today                          # All exec events today
ausearch -m USER_LOGIN -ts yesterday                  # Logon events yesterday
ausearch -f /etc/passwd -ts recent                    # Access to sensitive file
ausearch -ua root -ts this-week                       # All events attributed to root

# aureport — summary reports
aureport -au                                          # Authentication summary
aureport -x --summary                                 # Top executed commands
aureport -f -i --summary                              # Top accessed files
aureport --failed                                     # All failed events

# Manually decode EXECVE arguments from audit.log
grep 'type=EXECVE' /var/log/audit/audit.log | python3 -c "
import sys, re
for line in sys.stdin:
    m = re.search(r'argc=(\d+)(.*)', line)
    if m:
        args = re.findall(r'a\d+=\"([^\"]+)\"', m.group(2))
        print(' '.join(args))
"
```

### SIEM Forensic Queries

**Splunk — establish compromise timeline**:
```spl
index=windows earliest=-7d latest=now
| eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| where (EventCode=4688 AND (New_Process_Name="*cmd.exe" OR New_Process_Name="*powershell.exe"))
   OR EventCode=4720 OR EventCode=4732 OR EventCode=7045 OR EventCode=1102
| table time, EventCode, Account_Name, New_Process_Name, Process_Command_Line, ServiceName
| sort time
```

**Splunk — detect encoded PowerShell**:
```spl
index=windows EventCode=4104
| where match(ScriptBlockText, "(?i)-enc|-encodedcommand|frombase64string|invoke-expression")
| table _time, ComputerName, ScriptBlockText
| sort -_time
```

**KQL (Microsoft Sentinel / Defender) — security event timeline**:
```kusto
SecurityEvent
| where TimeGenerated between (starttime .. endtime)
| where EventID in (4688, 4720, 4726, 4732, 4698, 4699, 7045, 1102)
| project TimeGenerated, EventID, Account, Computer, Process, CommandLine, ServiceName
| order by TimeGenerated asc
```

**KQL — lateral movement detection**:
```kusto
SecurityEvent
| where EventID == 4648
| where TargetServerName !endswith "." and TargetServerName != "-"
| summarize count() by Account, TargetUserName, TargetServerName, bin(TimeGenerated, 1h)
| where count_ > 3
```

**Elastic ECS — process execution**:
```json
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.category": "process" } },
        { "term": { "event.type": "start" } },
        { "wildcard": { "process.command_line": "*-EncodedCommand*" } }
      ],
      "filter": { "range": { "@timestamp": { "gte": "now-7d" } } }
    }
  }
}
```

---

## Incident Response Integration

### DFIR Triage — Rapid Artifact Collection

**KAPE (Kroll Artifact Parser and Extractor)** — Windows triage on live or mounted image:
```bash
# Collect common artifacts (registry, event logs, prefetch, browser, LNK)
kape.exe --tsource C: --tdest D:\triage --target !BasicCollection --module !EZParser

# Memory acquisition + artifact collection
kape.exe --msource C: --mdest D:\triage --module WinPmem
```

**Velociraptor** — enterprise-scale DFIR:
```bash
# Deploy server
velociraptor config generate > server.config.yaml
velociraptor --config server.config.yaml frontend -v

# Hunt for persistence (scheduled tasks, services, run keys) across fleet
# Via GUI: Hunts > New Hunt > select artifact Windows.Persistence.PersistenceSniper
```

### Evidence Collection Order (Live System)

```bash
# 1. Record system time and timezone
date; timedatectl

# 2. Capture network state
ip neigh show      # ARP cache
ss -antp           # Active connections
ip route           # Routing table

# 3. Capture process list
ps auxf > /tmp/processes.txt
ls -la /proc/*/exe 2>/dev/null > /tmp/proc_exe.txt

# 4. Capture open files and network sockets
lsof -n > /tmp/lsof.txt

# 5. Acquire memory (LiME)
sudo insmod lime-$(uname -r).ko "path=/tmp/memory.lime format=lime"

# 6. Hash and image disk
sha256sum /dev/sda > /tmp/disk_hash.txt
dd if=/dev/sda bs=4M conv=noerror,sync | gzip > /cases/evidence.dd.gz
```

### Malware Analysis Integration

After isolating suspicious files from disk or memory:

```bash
# Static — PE analysis
file suspicious.exe
strings -a suspicious.exe | grep -E "http|cmd|powershell|regsvr32"
pe-sieve.exe /pid 1234    # Scan live process for implants

# YARA scanning
yara -r /rules/malware_index.yar /suspect_dir/

# Dynamic — sandbox submission
# Upload to: any.run, Triage (tria.ge), Hybrid Analysis, VirusTotal sandbox

# Hash lookups
sha256sum suspicious.exe | cut -d' ' -f1 | xargs -I{} curl -s "https://mb-api.abuse.ch/api/v1/" -d "query=get_info&hash={}"
```

---

## Forensics Tools Reference

| Tool | Category | Platform | Key Use |
|---|---|---|---|
| Autopsy | Disk forensics | Win/Linux | Full disk investigation GUI with ingest modules |
| Sleuth Kit (TSK) | Disk forensics | CLI | Low-level partition, file system, and timeline analysis |
| Volatility 3 | Memory | Python | Memory analysis framework; plugins for Windows/Linux/Mac |
| Rekall | Memory | Python | Alternative memory framework; now mostly superseded by Vol3 |
| RegRipper | Registry | Windows | Automated registry hive artifact extraction |
| Plaso / log2timeline | Timeline | Python | Multi-source timeline creation (disk, logs, browser, registry) |
| KAPE | Triage | Windows | Rapid artifact collection and parsing (EZ Tools integration) |
| Velociraptor | DFIR | Cross-platform | Enterprise DFIR platform with VQL hunting language |
| GRR Rapid Response | DFIR | Cross-platform | Google's remote forensics at scale |
| FTK Imager | Acquisition | Windows | Disk and memory acquisition GUI (free) |
| X-Ways Forensics | Commercial | Windows | Professional forensics suite with low disk footprint |
| Magnet AXIOM | Commercial | Windows | Comprehensive digital forensics with cloud artifact support |
| CAINE | Live OS | Linux | Forensic Linux distribution (non-destructive by default) |
| SANS SIFT Workstation | Live OS | Linux | SANS Institute forensic workstation (Ubuntu-based) |
| LiME | Memory acquisition | Linux kernel | Loadable kernel module for Linux memory imaging |
| WinPMem | Memory acquisition | Windows | Open source Windows memory acquisition |
| Eric Zimmermann Tools | Artifact parsing | Windows | PECmd, LECmd, JLECmd, SBECmd, MFTECmd — free artifact parsers |
| Chainsaw | Log analysis | Windows/Linux | Rapid EVTX hunting with Sigma rule support |
| Hayabusa | Log analysis | Windows/Linux | Windows event log fast forensics and threat hunting |

---

## Standards and Framework Alignment

| Standard / Framework | Relevance |
|---|---|
| NIST SP 800-86 | Guide to Integrating Forensic Techniques into IR |
| NIST SP 800-61 r2 | Computer Security Incident Handling Guide — evidence handling section |
| ISO/IEC 27037 | Guidelines for identification, collection, acquisition, and preservation of digital evidence |
| ACPO Good Practice Guide | UK law enforcement digital evidence principles |
| RFC 3227 | Guidelines for Evidence Collection and Archiving — order of volatility basis |
| MITRE ATT&CK | Discovery (TA0007) and Defense Evasion (TA0005) techniques map to common forensic findings |

**ATT&CK techniques most relevant to forensic findings**:
- T1059 — Command and Scripting Interpreter (PowerShell, cmd, bash history)
- T1053 — Scheduled Task / Job (event IDs 4698/4702, crontab)
- T1547 — Boot or Logon Autostart Execution (Run keys, services, startup folders)
- T1055 — Process Injection (malfind RWX regions, hollowfind)
- T1070 — Indicator Removal (event 1102, log deletion, timestomping)
- T1003 — Credential Dumping (hashdump, lsadump, LSASS process access)
- T1078 — Valid Accounts (event 4624 Logon Type 3, pass-the-hash 4648)
