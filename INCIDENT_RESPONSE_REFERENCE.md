# Incident Response Reference

A comprehensive, hands-on incident response reference covering IR frameworks, live response procedures, enterprise DFIR tooling, and incident-specific playbooks.

---

## 1. IR Frameworks & Standards

### NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide

The foundational US federal standard for incident response. Defines four phases:

| Phase | Description |
|---|---|
| **Preparation** | Establish IR capability, tools, training, and communication plans before incidents occur |
| **Detection & Analysis** | Identify and validate incidents; determine scope, severity, and impact |
| **Containment, Eradication & Recovery** | Stop spread, remove attacker presence, restore normal operations |
| **Post-Incident Activity** | Lessons learned, reporting, evidence retention, and process improvement |

**NIST Incident Categories**:

| Category | Description |
|---|---|
| Denial of Service (DoS) | Attack that prevents or impairs authorized use of networks, systems, or applications |
| Malicious Code | Virus, worm, Trojan horse, ransomware, rootkit, spyware installed on host |
| Unauthorized Access | Person gains logical or physical access to a network, system, or application without permission |
| Inappropriate Usage | Person violates acceptable use policies (e.g., harassment, data theft, misuse of resources) |
| Scans / Probes / Attempted Access | Reconnaissance activity — port scans, vulnerability scans, failed login attempts |
| Investigation | Unconfirmed potential incident; activity suspected but not yet verified |

**Reference**: NIST SP 800-61 Rev 2 — https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final

---

### SANS PICERL Model

A practitioner-oriented refinement of NIST's phases with explicit identification and lessons learned steps:

| Phase | Key Actions |
|---|---|
| **Preparation** | IR plan, tools, training, communication tree, pre-authorized access, forensic toolkit ready |
| **Identification** | Detect the event, validate it as an incident, determine scope, assign severity |
| **Containment** | Short-term: isolate affected systems. Long-term: block attacker, preserve evidence |
| **Eradication** | Remove malware, backdoors, unauthorized accounts; patch exploited vulnerability |
| **Recovery** | Restore systems from known-good state; monitor closely; confirm clean |
| **Lessons Learned** | Document timeline, what worked/failed, gaps, and action items within 2 weeks |

---

### CISA Incident Response Playbooks (2021)

Federal civilian agency guidance for incident and vulnerability response:

- **Incident Response Playbook**: Standard operating procedures for detecting, analyzing, and responding to cybersecurity incidents affecting federal agencies
- **Vulnerability Response Playbook**: Procedures for responding to identified vulnerabilities
- Source: https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf

---

### ISO/IEC 27035 — Information Security Incident Management

International standard for structuring an information security incident management process:

- **Part 1**: Principles of incident management
- **Part 2**: Guidelines for planning and preparation
- **Part 3**: Guidelines for ICT incident response operations

Key requirements: defined incident response policy, documented procedures, trained personnel, communication protocols, post-incident review process.

---

### Incident Severity Classification

| Severity | Criteria | Examples | Response SLA |
|---|---|---|---|
| **P1 / Critical** | Active compromise, data exfiltration, ransomware actively encrypting, critical infrastructure disruption | Ransomware outbreak, APT breach, data breach affecting >10k records | 15 minutes |
| **P2 / High** | Confirmed attacker presence, privilege escalation, suspicious lateral movement, credential theft | DCSync attack, mass internal recon, domain admin account compromise | 1 hour |
| **P3 / Medium** | Policy violation, isolated malware on single endpoint, suspicious but unconfirmed activity | Single endpoint malware, phishing click without credential theft, insider threat investigation | 4 hours |
| **P4 / Low** | Failed attacks, reconnaissance, minor policy violation, no confirmed impact | Port scan, blocked phishing attempt, failed brute force | 24 hours |

---

## 2. Preparation Phase

### IR Team Roles

| Role | Responsibilities |
|---|---|
| **IR Lead** | Overall incident command; escalation decisions; external communications coordination |
| **SOC Analyst** | Alert triage, initial investigation, SIEM queries, initial scope assessment |
| **Forensics Analyst** | Evidence collection, memory and disk forensics, artifact analysis, timeline creation |
| **Threat Intelligence** | Attacker attribution, IOC enrichment, TTP mapping to MITRE ATT&CK, threat context |
| **Legal / Compliance** | Evidence preservation obligations, regulatory notification requirements, law enforcement liaison |
| **Communications** | Internal executive updates, external communications, customer notification drafting |
| **Executive Stakeholder** | Resource authorization, business continuity decisions, media/regulatory interface |
| **IT / Infrastructure** | System isolation, network changes, backup and recovery operations, credential resets |

---

### Communication Plan

- **Out-of-band channel**: Assume primary corporate communication channels (email, Slack, Teams) may be compromised during an incident
- Use: Signal (encrypted mobile messaging), pre-established encrypted email (S/MIME or PGP), secure dedicated bridge line
- Pre-distribute emergency contact list with personal phone numbers for all IR team members
- Define escalation thresholds: who to notify for P1 vs P2 vs P3 incidents
- Pre-draft communication templates for: executive briefing, customer notification, law enforcement referral, regulatory notification

---

### IR Toolkit Preparation

```
Hardware:
  - Write blocker: Tableau T35689IU, WiebeTech Forensic UltraDock, or CRU WiebeTech
  - External storage: 4TB+ USB 3.0 drives (forensic images), smaller drives for triage collections
  - Forensic laptop: dedicated machine never connected to target network, clean OS image restorable
  - Network tap: for passive packet capture on incident segments
  - Bootable forensic OS: SANS SIFT Workstation, CAINE on USB

Software (pre-installed):
  - Memory acquisition: winpmem, Magnet RAM Capture, LiME
  - Disk imaging: FTK Imager, dd, ewfacquire
  - Triage collection: KAPE, CyLR, Velociraptor
  - Memory analysis: Volatility 3, Rekall
  - Disk forensics: Autopsy, Sleuth Kit
  - Packet analysis: Wireshark, NetworkMiner, Zeek
  - Malware analysis: FLARE VM toolset, PEStudio, Ghidra

Response USB:
  - Pre-built IR toolkit with static Linux binaries (no dependencies)
  - Tools: netstat-static, ss-static, curl-static, yara-static
  - IR scripts: triage.sh, memory_capture.sh, evidence_package.sh
```

---

### Legal Considerations

- **Preservation obligations**: Once litigation or law enforcement involvement is anticipated, preserve all relevant evidence — do NOT delete logs or wipe systems
- **Search and seizure**: Obtain proper authorization before examining employee-owned devices; BYOD policy should pre-authorize IR access
- **Law enforcement notification thresholds**: Nation-state activity, critical infrastructure attacks, and theft of government information typically warrant FBI/CISA notification
- **Chain of custody**: Required for any evidence that may be used in legal proceedings
- **Attorney-client privilege**: Engage legal counsel early to protect IR communications and reports under privilege where possible
- **CFAA / Computer Fraud and Abuse Act**: Ensure IR activities stay within authorized scope; "hacking back" is illegal in the US

---

### Evidence Handling

- **Chain of custody documentation** required for each evidence item: case number, exhibit number, description, SHA-256 hash, collection date/time, collector name, storage location
- **Write blockers**: Always use hardware write blocker before connecting media; prevents modification of original evidence
- **Hash verification**: Hash original media at collection; hash acquired image; hashes must match

```bash
# Hash original device before acquisition
sha256sum /dev/sdb | tee original_hash.txt

# Acquire image
dd if=/dev/sdb of=/cases/evidence.dd bs=4M conv=noerror,sync status=progress

# Verify image integrity
sha256sum /cases/evidence.dd | tee image_hash.txt
diff original_hash.txt image_hash.txt  # Must match
```

---

### Tabletop Exercise Planning

- **Scenario types**: Ransomware, BEC, insider threat, supply chain compromise, cloud account takeover
- **Participants**: All IR team roles + executive stakeholders + legal
- **Objectives**: Test decision-making, communication, escalation paths, and technical response procedures
- **Gap identification**: Document response gaps, missing tools, unclear ownership, communication failures
- **After-action review**: Update IR plan, runbooks, and training based on gaps identified
- **Frequency**: Minimum annually; quarterly for mature programs; after-incident as supplemental

---

## 3. Detection & Triage

### Alert Sources

| Source | Examples | Value |
|---|---|---|
| SIEM | Splunk, Microsoft Sentinel, Elastic SIEM | Correlation, behavioral detection, log aggregation |
| EDR | CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint | Endpoint telemetry, process tree, behavioral IOAs |
| Email Security | Proofpoint, Mimecast, Microsoft Defender for Office 365 | Phishing, BEC, malware delivery detection |
| Network IDS/IPS | Suricata, Zeek, Palo Alto Threat Prevention | Network-level signatures, anomaly detection |
| Threat Intel Feeds | MISP, CrowdStrike Intel, Mandiant, CISA advisories | Known IOCs, TTPs, emerging threats |
| User Reports | Phishing report button, security@company.com | Often first detection of targeted attacks |
| External Notification | FBI, CISA, MSSP, peer organizations, ISACs | Breach notification, threat sharing |
| Cloud Security | AWS GuardDuty, Azure Defender, GCP SCC | Cloud-native behavioral detection |

---

### Initial Triage Questions

When an alert fires or a potential incident is reported, answer these questions to determine scope and severity:

1. **What assets are affected?** — Identify all impacted hosts, accounts, and systems (scope)
2. **What data may be at risk?** — Determine sensitivity of data accessible from affected systems (impact)
3. **Is the attack ongoing?** — Active vs. historical incident changes response urgency (active vs. historical)
4. **What is the attack vector?** — Phishing, RDP exposure, supply chain, insider? (entry point)
5. **Is there lateral movement?** — Has the attacker moved beyond the initial foothold? (spread)
6. **Is there C2 communication?** — Active C2 indicates ongoing attacker control (persistence)
7. **Is this a false positive?** — Can the activity be explained by authorized behavior? (validation)

---

### MITRE ATT&CK Mapping During Triage

Map observed indicators to ATT&CK techniques during triage to:
- Identify the likely attack stage (Initial Access through Impact)
- Predict attacker's next moves based on known TTP sequences
- Guide containment priorities
- Enable consistent reporting

**Common triage-to-TTP mappings**:

| Observed Indicator | ATT&CK Technique |
|---|---|
| Encoded PowerShell command | T1059.001 — PowerShell |
| Scheduled task creation | T1053.005 — Scheduled Task |
| New service installed | T1543.003 — Windows Service |
| Admin share access (C$, IPC$) | T1021.002 — SMB/Windows Admin Shares |
| LSASS process access | T1003.001 — LSASS Memory |
| DCSync activity | T1003.006 — DCSync |
| Outbound HTTPS to unknown IP | T1071.001 — Web Protocols (C2) |
| Ransomware file extension change | T1486 — Data Encrypted for Impact |

---

### Incident Ticket Creation

Every confirmed or suspected incident should have a ticket containing:
- **Unique incident ID** and creation timestamp
- **Severity classification** (P1–P4) with justification
- **Affected systems** (hostnames, IPs, business function)
- **Affected accounts** (usernames, privilege level)
- **Initial indicators** (alert source, IOCs, timestamps)
- **Attack vector** (if known)
- **Timeline** (chronological log of all response actions with timestamps and responder names)
- **Current status** (active investigation, contained, remediated)
- **Owner** (assigned IR lead)
- **Escalation status** (who has been notified)

---

## 4. Containment Strategies

### Evidence Preservation Before Containment

> Collect volatile evidence BEFORE isolating systems when possible — isolation destroys volatile data.

**Order of operations**:
1. Capture memory (most volatile): `winpmem`, Magnet RAM Capture, LiME
2. Capture network state: `netstat -ano`, packet capture if network tap in place
3. Snapshot VMs before shutdown (preserves disk state and can include memory)
4. Ensure logs are flowing to central SIEM (prevent local log deletion)
5. Then proceed with containment

---

### Short-Term Containment (Stop the Bleeding)

| Action | Method |
|---|---|
| **Network isolation** | VLAN quarantine (move port to isolated VLAN), firewall ACL block, DNS sinkhole for C2 domains |
| **Endpoint isolation** | CrowdStrike: Network Containment in Falcon console or `falconctl containment`; SentinelOne: Network Quarantine; Microsoft Defender: Isolate device in Security Center |
| **Account disablement** | Disable AD accounts: `Disable-ADAccount -Identity username`; Revoke Entra ID tokens: `Revoke-AzureADUserAllRefreshToken` |
| **Block indicators at perimeter** | Add C2 IPs and domains to firewall deny list, DNS RPZ, proxy blocklist, EDR IOC block list |
| **Disable compromised VPN** | Revoke compromised VPN certificates; disable MFA tokens for compromised accounts |
| **Cloud isolation** | Quarantine EC2 instances with Security Group allowing no ingress/egress; suspend Azure AD account |

---

### Long-Term Containment

- Patch the exploited vulnerability on all affected and adjacent systems
- Reset all potentially compromised credentials (see credential scope assessment)
- Rebuild affected systems from clean golden images rather than attempting to clean in place
- Enable enhanced monitoring on all systems adjacent to the incident scope
- Review and tighten network segmentation to limit future lateral movement

---

## 5. Windows Live Response Commands

Quick triage commands to run on a suspected compromised Windows host. Run from elevated PowerShell or CMD.

```powershell
# ── System Information ────────────────────────────────────────────────────────
hostname
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Domain"
date /t; time /t
[System.TimeZone]::CurrentTimeZone.StandardName

# ── Logged-In Users ───────────────────────────────────────────────────────────
query user
net sessions
wmic computersystem get username

# ── Processes ─────────────────────────────────────────────────────────────────
tasklist /v
Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 Name,Id,CPU,Path
wmic process get ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath | more

# ── Network Connections ───────────────────────────────────────────────────────
netstat -ano
Get-NetTCPConnection | Where-Object State -eq "Established" | Sort-Object RemoteAddress |
    Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess

# Resolve PIDs to process names
$conns = Get-NetTCPConnection | Where-Object State -eq "Established"
$conns | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Remote = "$($_.RemoteAddress):$($_.RemotePort)"
        PID    = $_.OwningProcess
        Process = $proc.Name
        Path   = $proc.Path
    }
} | Sort-Object Remote

# ── Autorun / Persistence ────────────────────────────────────────────────────
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# ── Scheduled Tasks ───────────────────────────────────────────────────────────
schtasks /query /fo LIST /v | findstr /i "task name\|run as user\|task to run\|status"
Get-ScheduledTask | Where-Object State -ne "Disabled" |
    Select-Object TaskName,TaskPath,@{n="Action";e={$_.Actions.Execute}} | Format-Table -AutoSize

# ── Services ──────────────────────────────────────────────────────────────────
Get-Service | Where-Object Status -eq "Running" | Sort-Object Name
sc query | findstr /i "state\|service_name"
# List services with binaries not in System32 (suspicious)
Get-WmiObject Win32_Service | Where-Object { $_.PathName -notmatch "system32|SysWOW64" } |
    Select-Object Name,State,PathName

# ── Recent Files ──────────────────────────────────────────────────────────────
Get-ChildItem C:\Users -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object LastWriteTime -gt (Get-Date).AddDays(-7) |
    Sort-Object LastWriteTime -Descending | Select-Object -First 50 FullName,LastWriteTime

# ── Prefetch (Execution History) ─────────────────────────────────────────────
Get-ChildItem C:\Windows\Prefetch -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 20 Name,LastWriteTime

# ── Event Logs (Authentication) ──────────────────────────────────────────────
Get-EventLog -LogName Security -InstanceId 4624,4625,4634 -Newest 50 | Format-List

# PowerShell Script Block Logging
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
    Where-Object Id -eq 4104 | Select-Object -First 20 |
    Format-List TimeCreated,Message

# ── WMI Persistence ───────────────────────────────────────────────────────────
Get-WmiObject -Namespace root/subscription -Class __EventFilter
Get-WmiObject -Namespace root/subscription -Class __EventConsumer
Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding

# ── Local Admins ──────────────────────────────────────────────────────────────
net localgroup administrators
Get-LocalGroupMember -Group "Administrators"

# ── DNS Cache ─────────────────────────────────────────────────────────────────
ipconfig /displaydns | findstr "Record Name"
```

---

## 6. Linux Live Response Commands

```bash
# ── System Information ────────────────────────────────────────────────────────
uname -a
hostname
uptime
last reboot | head -5
cat /etc/os-release

# ── Logged-In Users ───────────────────────────────────────────────────────────
who
w
last -25 | head -25
lastb | head -10   # Failed logins (/var/log/btmp)

# ── Processes ─────────────────────────────────────────────────────────────────
ps auxf

# Map process executable paths (detect deleted executables running in memory)
ls -la /proc/*/exe 2>/dev/null | grep -v "Permission denied"

# Find recently created/modified executables in suspicious locations
find /tmp /var/tmp /dev/shm /run -type f -executable 2>/dev/null

# Find processes with no associated file on disk (sign of running from deleted binary)
ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"

# ── Network Connections ───────────────────────────────────────────────────────
ss -anp
netstat -tlnp 2>/dev/null
lsof -i
# Show established connections with process names
ss -tp state established

# ── Persistence ───────────────────────────────────────────────────────────────
# Cron jobs
crontab -l 2>/dev/null
for user in $(cut -f1 -d: /etc/passwd); do
    echo "=== $user ==="; crontab -u $user -l 2>/dev/null
done
ls -la /etc/cron.* /var/spool/cron/ 2>/dev/null

# Init / rc.local
ls -la /etc/init.d/ 2>/dev/null
cat /etc/rc.local 2>/dev/null

# Systemd services
systemctl list-units --type=service --state=running
# Find service files modified recently
find /etc/systemd/system /lib/systemd/system -name "*.service" -newer /tmp -ls 2>/dev/null

# LD_PRELOAD hijacking (rootkit indicator)
cat /etc/ld.so.preload 2>/dev/null

# Profile and bashrc modifications
ls -la /etc/profile.d/
cat /etc/bash.bashrc 2>/dev/null | grep -v "^#\|^$"
cat /root/.bashrc 2>/dev/null | grep -v "^#\|^$"

# ── SSH Authorized Keys ───────────────────────────────────────────────────────
cat ~/.ssh/authorized_keys 2>/dev/null
cat /root/.ssh/authorized_keys 2>/dev/null
find / -name authorized_keys 2>/dev/null -exec ls -la {} \;

# ── SUID Binaries (Unexpected) ────────────────────────────────────────────────
find / -perm -4000 -type f 2>/dev/null | sort

# ── Recent Logins and Command History ────────────────────────────────────────
grep -E "Accepted|Failed" /var/log/auth.log 2>/dev/null | tail -50
grep -E "Accepted|Failed" /var/log/secure 2>/dev/null | tail -50
cat ~/.bash_history 2>/dev/null
find / -name .bash_history 2>/dev/null -exec ls -la {} \;

# ── Kernel Modules (Rootkit Check) ────────────────────────────────────────────
lsmod
# Check for modules not in modprobe list (manually loaded rootkits)
diff <(lsmod | awk 'NR>1{print $1}' | sort) \
     <(find /lib/modules/$(uname -r) -name "*.ko" -exec basename {} .ko \; | sort)

# ── File Integrity Quick Check ────────────────────────────────────────────────
# Find files modified in last 24 hours in system directories
find /etc /usr/bin /usr/sbin /bin /sbin -newer /tmp -type f -ls 2>/dev/null | head -20

# Check for hidden files in common locations
find /tmp /var/tmp /dev/shm -name ".*" -ls 2>/dev/null
```

---

## 7. Velociraptor for Enterprise IR

Velociraptor is an open-source DFIR platform for collecting forensic artifacts and hunting across large endpoint fleets simultaneously.

**Source**: https://github.com/Velocidex/velociraptor
**Docs**: https://docs.velociraptor.app/

### Deployment

```bash
# Generate server config
velociraptor config generate --merge '{"autocert_domain": "ir.company.com"}' > server.config.yaml

# Start frontend (server)
velociraptor --config server.config.yaml frontend -v

# Generate client config from server config
velociraptor --config server.config.yaml config client > client.config.yaml

# Deploy agent (MSI on Windows, .deb/.rpm on Linux)
velociraptor-v0.7.0-windows-amd64.msi /quiet CONFIGFILE=client.config.yaml
```

### Key VQL (Velociraptor Query Language) Examples

```sql
-- List running processes with hashes
SELECT Pid, Ppid, Name, Exe, CommandLine,
       hash(path=Exe).SHA256 AS Hash
FROM pslist()

-- Detect process injection (suspicious RWX memory regions)
SELECT * FROM Artifact.Windows.Detection.ProcessInjection()

-- Collect all persistence mechanisms
SELECT * FROM Artifact.Windows.Persistence.PersistenceChecker()

-- Hunt for specific YARA rule across all process memory
SELECT * FROM hunt(
    artifacts=["Windows.Detection.Yara.Process"],
    parameters=dict(YaraRule="rule detect_beacon { strings: $s = {4D 5A} condition: $s }")
)

-- Windows event log hunting (custom EventID filter)
SELECT System.TimeCreated.SystemTime AS Time,
       System.EventID.Value AS EventID,
       EventData
FROM parse_evtx(filename="C:/Windows/System32/winevt/Logs/Security.evtx")
WHERE EventID IN (4624, 4625, 4672, 4698, 4720)

-- Find files matching a hash IOC
SELECT FullPath, Size, Mtime
FROM glob(globs="C:/**")
WHERE hash(path=FullPath).MD5 = "d41d8cd98f00b204e9800998ecf8427e"
```

### Hunting at Scale

- Deploy a hunt to 10,000+ endpoints simultaneously from the server UI
- Results stream back in real time — no polling required
- Key built-in artifacts to deploy during IR:
  - `Windows.KapeFiles.Targets` — collect KAPE triage artifacts remotely
  - `Windows.EventLogs.EvtxHunter` — hunt across all EVTX logs with regex
  - `Windows.Persistence.PersistenceChecker` — enumerate persistence mechanisms
  - `Generic.Forensic.LocalDisk` — full disk collection
  - `Windows.Memory.Acquisition` — remote memory capture
  - `Windows.Network.NetstatEnriched` — network connections with process context

---

## 8. KAPE (Kroll Artifact Parser and Extractor)

KAPE provides rapid, targeted collection and processing of forensic artifacts from a live system or mounted image.

**Source**: https://github.com/EricZimmerer/KapeFiles
**Download**: https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape

### Targets (What to Collect)

Key KAPE targets for IR triage:

| Target | Artifacts Collected |
|---|---|
| `$MFT` | Master File Table (complete file system metadata) |
| `EventLogs` | All Windows Event Log (.evtx) files |
| `Prefetch` | Prefetch files (.pf) — execution evidence |
| `RegistryHives` | All registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT) |
| `BrowserHistory` | Chrome, Firefox, Edge history, downloads, cookies |
| `RecycleBin` | Deleted file metadata from $Recycle.Bin |
| `LNKFiles` | Shortcut files — recently accessed file evidence |
| `Amcache` | Application compatibility cache — application execution |
| `SRUM` | System Resource Usage Monitor — program execution history |
| `ShimCache` | Application Compatibility Cache — application execution evidence |

### KAPE Command Examples

```cmd
REM Basic triage collection from live system (C:) to external drive
kape.exe --tsource C: --tdest E:\Cases\Case001\Collection --target KapeTriage

REM Collection + parsing in one pass
kape.exe --tsource C: --tdest E:\Cases\Case001\Collection ^
         --target KapeTriage ^
         --mdest E:\Cases\Case001\Processed ^
         --module !EZParser

REM Collect from mounted image
kape.exe --tsource M: --tdest E:\Cases\Case001\Collection ^
         --target !BasicCollection

REM Target specific artifact types
kape.exe --tsource C: --tdest E:\Output ^
         --target EventLogs,RegistryHives,$MFT,Prefetch
```

### KAPE Output and Analysis

- **CSV timelines**: !EZParser module generates CSV files for each artifact type, ready for timeline analysis in Timeline Explorer
- **Parsed registry**: RegRipper output for each hive
- **Prefetch CSV**: Execution history with timestamps and run counts
- **NTFS artifacts**: MFT, $LogFile, $UsnJrnl for file system activity

---

## 9. Memory Forensics (Incident-Focused)

### Memory Acquisition

```cmd
REM WinPMem (Windows) — open source
winpmem_mini_x64.exe memdump.raw

REM Magnet RAM Capture (Windows GUI) — free
REM Download from: https://www.magnetforensics.com/resources/magnet-ram-capture/

REM Via Velociraptor remote
REM Artifact: Windows.Memory.Acquisition
```

```bash
# LiME (Linux) — kernel module
sudo insmod lime-$(uname -r).ko "path=/external/memory.lime format=lime"

# FTK Imager (Windows CLI)
ftkimager --memory --outfile memdump.mem
```

### Critical Volatility 3 Plugins for IR

```bash
# Install Volatility 3
pip install volatility3

# Basic system profile
vol -f memdump.raw windows.info

# ── Process Analysis ──────────────────────────────────────────────────────────
vol -f memdump.raw windows.pslist         # Process list from EPROCESS linked list
vol -f memdump.raw windows.pstree         # Process tree — spot injections and anomalous parents
vol -f memdump.raw windows.psscan         # Pool-tag scan — finds hidden/unlinked processes
vol -f memdump.raw windows.cmdline        # Command line for each process

# ── Malware Detection ─────────────────────────────────────────────────────────
vol -f memdump.raw windows.malfind        # RWX VAD regions with PE headers = injected code
vol -f memdump.raw windows.hollowfind     # Process hollowing detection (VAD vs PEB mismatch)
vol -f memdump.raw windows.dlllist        # Loaded DLLs per process (detect reflective injection)
vol -f memdump.raw windows.driverirp     # IRP hook detection (rootkit indicator)

# ── Network State ─────────────────────────────────────────────────────────────
vol -f memdump.raw windows.netstat        # Active network connections at time of capture
vol -f memdump.raw windows.netscan        # Pool scan for network structures (finds closed conns)

# ── File and Registry ─────────────────────────────────────────────────────────
vol -f memdump.raw windows.handles        # Open handles (files, registry, mutexes)
vol -f memdump.raw windows.filescan       # All file objects in memory
vol -f memdump.raw windows.mftscan.MFTScan  # NTFS MFT artifacts in memory
vol -f memdump.raw windows.registry.userassist  # User execution history

# ── Credential Extraction ─────────────────────────────────────────────────────
vol -f memdump.raw windows.hashdump       # SAM NTLM hashes (requires SYSTEM privileges)
vol -f memdump.raw windows.lsadump        # LSA secrets
vol -f memdump.raw windows.cachedump      # Cached domain credentials

# ── Linux Memory Analysis ─────────────────────────────────────────────────────
vol -f memory.lime linux.pslist
vol -f memory.lime linux.pstree
vol -f memory.lime linux.bash             # Bash history from memory
vol -f memory.lime linux.check_syscall    # Syscall table integrity (rootkit check)
vol -f memory.lime linux.netfilter        # Netfilter hooks (rootkit indicator)
```

### Memory Analysis Workflow for IR

1. **Run pslist vs psscan**: Processes in psscan but not pslist = hidden process (DKOM rootkit indicator)
2. **Review process tree**: Look for anomalous parent-child pairs — `Word.exe` → `cmd.exe`, `explorer.exe` → `powershell.exe`, `svchost.exe` with unusual parent
3. **Check cmdlines**: Base64-encoded `-EncodedCommand`, `-nop -w hidden`, unusual paths in `%TEMP%` or `%APPDATA%`
4. **Network connections**: Map established connections to process PIDs; non-browser processes with external HTTPS/443 = potential C2
5. **Malfind analysis**: MZ header (`4D 5A`) at start of RWX VAD region = injected PE (Cobalt Strike, Meterpreter, shellcode loader)
6. **DLL list review**: DLLs loaded without corresponding file on disk = reflective DLL injection
7. **Extract and scan**: Dump suspicious processes with `windows.dumpfiles`; scan with YARA rules

---

## 10. Ransomware Response Playbook

### Immediate Actions (0–1 Hour)

1. **Isolate affected systems** — network isolation (do NOT power off; preserve memory for evidence and may disrupt encryption)
2. **Identify patient zero** — first infected host; earliest timestamp of ransom note or file extension changes
3. **Identify ransomware family**: examine ransom note filename and text, encrypted file extension → use ID Ransomware (https://id-ransomware.malwarehunterteam.com)
4. **Capture memory on actively encrypting systems** — volatile evidence of encryption keys and malware
5. **Preserve shadow copies on unaffected systems** immediately:
   ```cmd
   vssadmin list shadows
   vssadmin list shadowstorage
   REM Do NOT let attacker run vssadmin delete shadows on remaining systems
   ```
6. **Block C2 communication** — extract C2 indicators from ransom note, malware config, or network traffic; block at firewall and DNS
7. **Notify**: IR lead → legal → cyber insurance carrier → executive team

---

### Short-Term Response (1–24 Hours)

8. **Scope assessment**: How many systems encrypted? What business-critical data is affected? Any unencrypted data still at risk?
9. **Determine entry point**: Phishing email? RDP exposure (check Event 4624 Type 10)? Exploited vulnerability? Compromised VPN credential?
10. **Map lateral movement**: Event 4624 Type 3 (network logon), Event 4648 (explicit credential use), PSExec artifacts, WMI remote execution, DCOM
11. **Remove persistence**: Delete scheduled tasks, malicious services, Run key entries associated with ransom binary
12. **Do NOT pay ransom** without legal and cyber insurance consultation (payment may violate OFAC sanctions if attacker is sanctioned entity)
13. **Check for double extortion**: Was data exfiltrated before encryption? Review network logs for large outbound transfers, cloud storage uploads, C2 exfiltration
14. **Contact FBI / CISA**: Strongly recommended; ransomware is a federal crime; may have decryption keys

---

### Recovery (1–7 Days)

14. **Restore from backups** — verify backup integrity before restoration; test a subset of backup files first; confirm backups are free of malware
15. **Rebuild compromised systems** from scratch using golden images — do NOT attempt to clean ransomware-infected systems
16. **Rotate ALL credentials** — domain admin, service accounts, application accounts, VPN credentials, cloud IAM; assume all credentials in-scope are compromised
17. **Patch** the vulnerability that allowed initial access before bringing systems back online
18. **Enhanced monitoring** for 30–90 days post-recovery — attackers frequently return to re-compromise

---

### Ransomware Family Quick Identification

| File Extension | Family | Ransom Note | Notes |
|---|---|---|---|
| `.locked` / `.LOCKBIT` / `.lockbit3` | LockBit | `!!!-Readme-!!!.txt` | Most prolific 2022–2024; LockBit 3.0 (Black) |
| `.akira` | Akira | `akira_readme.txt` | Double extortion; targets SMBs |
| `.blackcat` / `.alphv` / randomized | ALPHV/BlackCat | `RECOVER-*.txt` | Rust-based; cross-platform; seized 2024 |
| `.cl0p` / `.clop` | Cl0p | `ClopReadMe.txt` | MOVEit, GoAnywhere exploitation campaigns |
| `.hive` | Hive | `HOW_TO_DECRYPT.txt` | FBI seized infrastructure Jan 2023; decryptors available |
| `.rhysida` | Rhysida | `CriticalBreachDetected.pdf` | Targets healthcare and education |
| `.play` | Play | `ReadMe.txt` | Targets RACI, critical infrastructure |
| `.royal` | Royal | `README.TXT` | Successor to Conti; targets critical infrastructure |

---

## 11. BEC (Business Email Compromise) Response

### Detection Indicators

- Unexpected mail forwarding rules (auto-forward to external address)
- Login from foreign IP address or new country not in user's travel history
- Inbox rules that delete emails containing keywords ("invoice", "wire transfer", "bank")
- Large number of outbound emails to external domains
- OAuth application added to account (persistent access even after password reset)
- MFA fatigue attack indicators (repeated MFA push notifications)

---

### Investigation Steps (Microsoft 365)

```powershell
# ── Unified Audit Log — mailbox activity last 30 days ────────────────────────
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
    -UserIds victim@company.com `
    -Operations "MailboxLogin,Set-InboxRule,New-InboxRule,UpdateInboxRules,Send,SendAs"

# ── Check forwarding rules ────────────────────────────────────────────────────
Get-InboxRule -Mailbox victim@company.com
Get-Mailbox victim@company.com |
    Select-Object ForwardingAddress,ForwardingSMTPAddress,DeliverToMailboxAndForward

# ── Check OAuth app grants ────────────────────────────────────────────────────
Get-AzureADUserOAuth2PermissionGrant -ObjectId (Get-AzureADUser -UserPrincipalName victim@company.com).ObjectId

# ── MFA status ────────────────────────────────────────────────────────────────
Get-MsolUser -UserPrincipalName victim@company.com | Select-Object StrongAuthenticationMethods

# ── Sign-in log review (Azure AD) ────────────────────────────────────────────
Get-AzureADAuditSignInLogs -Filter "userPrincipalName eq 'victim@company.com'" |
    Select-Object CreatedDateTime,IpAddress,Location,ClientAppUsed,Status

# ── Revoke all active sessions ────────────────────────────────────────────────
Revoke-AzureADUserAllRefreshToken -ObjectId (Get-AzureADUser -UserPrincipalName victim@company.com).ObjectId
```

---

### BEC Containment

1. Revoke all active sessions and OAuth tokens for compromised account
2. Disable or delete malicious inbox rules
3. Reset password to strong random value
4. Enable MFA if not already enabled; register only on a known-clean device
5. Block attacker's IP address in Conditional Access policy
6. Review and remove unauthorized OAuth app grants
7. Audit email sent by compromised account for fraudulent communications

**Financial impact — immediate actions**:
- Notify your bank immediately if fraudulent wire transfers were made — there is a ~24–72 hour window to attempt recall through SWIFT/Fed recall process
- Contact recipient bank's fraud department
- File IC3 complaint (FBI Internet Crime Complaint Center): https://ic3.gov
- Contact Secret Service Financial Crimes if transfer exceeds $25,000

---

## 12. Active Directory Compromise Response

### Evidence of Compromise Indicators

| Event ID | Description | Significance |
|---|---|---|
| 4662 | Object access with DCSync-required rights | DCSync attack (Mimikatz dcsync) |
| 4720 | User account created | Backdoor account creation |
| 4728 / 4732 / 4756 | Member added to privileged group | Privilege escalation |
| 5136 | Directory service object modified | GPO modification, AdminSDHolder change |
| 4769 + RC4 encryption | Kerberos service ticket with RC4 | Kerberoasting attack |
| 4771 | Kerberos pre-auth failure | Password spray or brute force |
| 7045 | New service installed on DC | Attacker installing persistence on domain controller |
| 4742 | Computer account changed | DC modification (DCSync setup) |

---

### AD Compromise Response Steps

**1. Identify blast radius**

```powershell
# What accounts are Domain Admins?
Get-ADGroupMember "Domain Admins" -Recursive | Select-Object Name,SamAccountName

# What accounts are in other privileged groups?
Get-ADGroupMember "Enterprise Admins" -Recursive | Select-Object Name,SamAccountName
Get-ADGroupMember "Schema Admins" -Recursive | Select-Object Name,SamAccountName
Get-ADGroupMember "Backup Operators" -Recursive | Select-Object Name,SamAccountName

# Run BloodHound to visualize attack paths and determine what the attacker could access
# SharpHound collection: SharpHound.exe -c All --domain company.com
```

**2. Rotate krbtgt password TWICE (invalidates all Kerberos tickets)**

```powershell
# First rotation
Set-ADAccountPassword -Identity krbtgt -Reset `
    -NewPassword (ConvertTo-SecureString "NewKrbtgtP@ssw0rd!$(Get-Random)" -AsPlainText -Force)

# Wait 10 hours (maximum Kerberos ticket lifetime) — then second rotation
Set-ADAccountPassword -Identity krbtgt -Reset `
    -NewPassword (ConvertTo-SecureString "NewKrbtgtP@ssw0rd2!$(Get-Random)" -AsPlainText -Force)

# Note: This invalidates ALL Kerberos tickets in the domain — expect service disruption
# Golden Tickets created before the first rotation will be invalid after the second rotation
```

**3. Identify and remove DC/domain-level persistence**

```powershell
# Check AdminSDHolder for unauthorized ACEs
Get-ACL "AD:\CN=AdminSDHolder,CN=System,DC=company,DC=com" |
    Select-Object -ExpandProperty Access | Where-Object IdentityReference -notmatch "BUILTIN|NT AUTHORITY|company\\(Domain|Enterprise|Schema) Admins"

# Check domain trusts
Get-ADTrust -Filter * | Select-Object Name,Direction,TrustType,Source

# Check DCShadow persistence (rogue DCs)
Get-ADDomainController -Filter * | Select-Object Name,IPv4Address,IsGlobalCatalog,OperatingSystem

# Review all GPOs for unexpected scripts or settings
Get-GPO -All | Select-Object DisplayName,Id,CreationTime,ModificationTime | Sort-Object ModificationTime -Descending | Select-Object -First 20
```

**4. Audit all Domain Admin and Tier 0 accounts**

```powershell
# Accounts with recent password changes (potential attacker-created accounts)
Search-ADAccount -PasswordNeverExpires | Where-Object Enabled -eq $true |
    Select-Object Name,SamAccountName,PasswordLastSet,LastLogonDate

# Disabled accounts that were recently enabled
Get-ADUser -Filter {Enabled -eq $true} -Properties WhenChanged,WhenCreated,LastLogonDate |
    Where-Object WhenChanged -gt (Get-Date).AddDays(-30) |
    Sort-Object WhenChanged -Descending | Select-Object -First 20 Name,SamAccountName,WhenChanged
```

**5. Enable comprehensive logging**

```powershell
# Enable advanced audit policy on DCs
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Increase Security event log size
Limit-EventLog -LogName Security -MaximumSize 1GB

# Deploy Sysmon with SwiftOnSecurity or olafhartong config via GPO
```

---

## 13. Cloud Incident Response

### AWS Incident Response

```bash
# List recent CloudTrail events for a user
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=compromised-user \
    --start-time 2025-01-01T00:00:00Z \
    --end-time 2025-01-31T23:59:59Z

# Check for unauthorized IAM changes
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser

# Disable compromised IAM user
aws iam update-login-profile --user-name compromised-user --no-password-reset-required
aws iam delete-login-profile --user-name compromised-user
# Revoke access keys
aws iam update-access-key --user-name compromised-user --access-key-id AKIAXXXXXXX --status Inactive

# Isolate EC2 instance with empty Security Group
aws ec2 create-security-group --group-name "IR-Quarantine" --description "IR quarantine - no traffic"
aws ec2 modify-instance-attribute --instance-id i-XXXXXXXXX --groups sg-QUARANTINE-ID

# Check for unauthorized Lambda functions
aws lambda list-functions | jq '.Functions[] | {FunctionName, LastModified}'

# GuardDuty findings
aws guardduty list-findings --detector-id DETECTOR-ID
aws guardduty get-findings --detector-id DETECTOR-ID --finding-ids FINDING-ID
```

---

### Azure / Entra ID Incident Response

```powershell
# Revoke all sessions for compromised user
Revoke-AzureADUserAllRefreshToken -ObjectId USER-OBJECT-ID

# Check conditional access policy gaps
Get-AzureADMSConditionalAccessPolicy | Select-Object DisplayName,State,Conditions

# Review recent role assignments
Get-AzureADDirectoryRoleAssignment |
    Where-Object CreatedDateTime -gt (Get-Date).AddDays(-30) |
    Sort-Object CreatedDateTime -Descending

# Check for new service principals (attacker persistence)
Get-AzureADServicePrincipal -All $true |
    Where-Object AccountEnabled -eq $true |
    Sort-Object CreatedDateTime -Descending | Select-Object -First 20

# Microsoft Sentinel — find all sign-ins from suspicious IP
# KQL query in Sentinel:
# SigninLogs
# | where IPAddress == "x.x.x.x"
# | project TimeGenerated, UserPrincipalName, AppDisplayName, ResultType, Location
# | order by TimeGenerated desc
```

---

## 14. Post-Incident Activities

### Lessons Learned Meeting

Schedule within 2 weeks of incident closure. Required participants: all IR team members, relevant IT staff, management stakeholders.

**Agenda**:
1. Incident timeline — from initial compromise to detection to containment to recovery
2. What worked well — effective tools, decisions, and communication
3. What didn't work — delayed detection, unclear ownership, tool gaps, communication failures
4. **Detection gap analysis**: How long was the attacker in the environment before detection? (dwell time)
5. **Response gap analysis**: What slowed containment or recovery?
6. Action items — each with an owner and due date

---

### Root Cause Analysis (RCA)

**5 Whys example** (ransomware via phishing):
1. Why did systems get encrypted? → Ransomware executed successfully
2. Why did ransomware execute? → User ran malicious email attachment
3. Why did user run attachment? → Email bypassed email security filters
4. Why did email bypass filters? → DMARC policy was in monitor mode, not enforcement
5. Why was DMARC not enforced? → No process for email security policy review post-deployment

→ **Root cause**: Lack of DMARC enforcement policy and periodic email security review process

---

### IR Metrics to Track

| Metric | Description | Target |
|---|---|---|
| **MTTD** (Mean Time to Detect) | Time from initial compromise to first alert/detection | < 24 hours (mature SOC) |
| **MTTR** (Mean Time to Respond) | Time from detection to initial containment | < 4 hours for P1 |
| **MTTC** (Mean Time to Contain) | Time from detection to full containment | < 24 hours for P1 |
| **Dwell Time** | Time from initial access to detection | Industry average: 16 days (Mandiant 2024) |
| **False Positive Rate** | Percentage of alerts that are false positives | < 20% target |
| **Incident Volume by Severity** | Count of P1–P4 incidents per month | Track trend over time |
| **Time to Lessons Learned** | Days between incident closure and LL meeting | < 14 days |

---

### Reporting

**Executive Summary** (1–2 pages, non-technical):
- What happened (plain language)
- Business impact (systems affected, data at risk, downtime)
- How it was detected and resolved
- Key actions taken
- Recommendations and estimated implementation cost/effort

**Technical Report** (detailed):
- Complete incident timeline with timestamps
- Attack vector and TTPs (MITRE ATT&CK mapping)
- Indicators of Compromise (IOCs)
- Systems and accounts affected
- Evidence collected and forensic findings
- Containment and eradication actions taken
- Vulnerabilities exploited and remediation

---

### Regulatory Notification Timelines

| Regulation | Notification Requirement | Recipients |
|---|---|---|
| **HIPAA** | 60 days from discovery | Affected individuals; HHS OCR; media (if >500 per state) |
| **GDPR** | 72 hours from discovery | Supervisory authority (DPA); affected individuals if high risk |
| **SEC** (public companies) | 4 business days (material incidents) | SEC Form 8-K; shareholders |
| **CISA (CIRCIA)** | 72 hours (pending final rules) | CISA; applies to covered entities/critical infrastructure |
| **PCI DSS** | Immediately upon suspicion | Acquiring bank; card brands (Visa, Mastercard) |
| **NY SHIELD / NYDFS** | 72 hours | NYDFS Superintendent |
| **CCPA** | Expedient | California AG if >500 CA residents affected |
| **FTC Safeguards Rule** | 30 days | FTC; applies to non-banking financial institutions |

**Note**: Consult legal counsel before any regulatory notification — timing, content, and scope requirements vary.

---

### Threat Intelligence Sharing

Share IOCs and TTPs after incident closure to benefit the broader community:

- **ISACs** (Information Sharing and Analysis Centers): FS-ISAC, H-ISAC, E-ISAC — sector-specific sharing
- **MISP** (Malware Information Sharing Platform): https://misp-project.org — structured IOC sharing
- **US-CERT / CISA**: Submit IOCs via https://us-cert.cisa.gov/forms/report
- **FBI InfraGard**: Private-sector threat sharing with FBI
- **STIX/TAXII**: Standard format for machine-readable threat intelligence sharing

---

## 15. IR Tools Quick Reference

| Tool | Purpose | Source / Download |
|---|---|---|
| **Velociraptor** | Enterprise DFIR platform — endpoint hunting and artifact collection | github.com/Velocidex/velociraptor |
| **KAPE** | Rapid targeted artifact collection and processing | github.com/EricZimmerman/KapeFiles |
| **Volatility 3** | Memory forensics framework | github.com/volatilityfoundation/volatility3 |
| **FTK Imager** | Disk and memory acquisition (free GUI) | Free from Exterro (exterro.com) |
| **Autopsy** | Disk forensics platform | sleuthkit.org/autopsy |
| **NetworkMiner** | PCAP analysis and network forensics | netresec.com |
| **Wireshark** | Packet capture and analysis | wireshark.org |
| **CyberChef** | Data manipulation and decoding | gchq.github.io/CyberChef |
| **MISP** | IOC sharing and threat intelligence platform | misp-project.org |
| **TheHive** | Open source security incident response platform | thehive-project.org |
| **Cortex** | Automated observable analysis (enrichment, sandboxing) | thehive-project.org/cortex |
| **GRR Rapid Response** | Remote forensics at scale (Google) | github.com/google/grr |
| **Chainsaw** | Windows event log fast forensics with Sigma rules | github.com/WithSecureLabs/chainsaw |
| **Hayabusa** | Windows event log threat hunting | github.com/Yamato-Security/hayabusa |
| **Eric Zimmermann Tools** | PECmd, LECmd, JLECmd, MFTECmd — artifact parsers | ericzimmerman.github.io |
| **BloodHound** | AD attack path mapping and blast radius analysis | github.com/BloodHoundAD/BloodHound |
| **Magnet AXIOM** | Commercial comprehensive DFIR platform | magnetforensics.com |
| **DFIR.training** | Tool catalog for the DFIR community | dfir.training |
| **ID Ransomware** | Ransomware family identification by note/extension | id-ransomware.malwarehunterteam.com |
| **any.run** | Interactive malware sandbox | any.run |

---

## References

- NIST SP 800-61 Rev 2: https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- NIST SP 800-86 (Forensics Integration): https://csrc.nist.gov/publications/detail/sp/800-86/final
- CISA IR Playbooks: https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf
- SANS Incident Handler's Handbook: https://www.sans.org/white-papers/33901/
- Microsoft AD Forest Recovery: https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-guide
- MITRE ATT&CK: https://attack.mitre.org
- Mandiant M-Trends 2024: https://www.mandiant.com/m-trends
- Velociraptor Documentation: https://docs.velociraptor.app/
- KAPE Documentation: https://ericzimmerman.github.io/KapeDocs/
