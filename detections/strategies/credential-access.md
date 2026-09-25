# Credential Access — Detection Strategies

> MITRE ATT&CK detection strategies and analytics (v18.1) for techniques whose primary tactic is **Credential Access**. Each analytic lists the **log sources / channels** it needs, the **detection logic**, and the **tunable elements** to adapt it to your environment. Authoritative source: the ATT&CK detection-strategy model in the Enterprise STIX.

See also: [all detection strategies index](/detections/strategies/README.md) · [Technique Detection Library](../TECHNIQUE_DETECTION_LIBRARY.md) (ready-to-run SIEM queries) · [Data Components & Log Sources](../../ATTACK_DATA_COMPONENTS.md) · [Technique Detail Pages](../../techniques/README.md)

---

### T1003 — OS Credential Dumping
<a id="t1003"></a>

**Detection strategy:** Credential Dumping via Sensitive Memory and Registry Access Correlation (`DET0234`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1003](https://attack.mitre.org/techniques/T1003/) · [detail page](../../techniques/credential-access.md#t1003)

- **`AN0648` Analytic 0648** · Windows
  Processes accessing LSASS memory or SAM registry hives outside of trusted security tools, often followed by file creation or lateral movement. Detects unauthorized access to sensitive OS subsystems for credential extraction.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:Security` (EventCode=4662)
  - *Tune:* `AccessMask` — Set to detect full access rights (0x1F0FFF) or modify based on tool behavior.; `TimeWindow` — Define how soon access to LSASS is followed by suspicious file or registry activity.; `ParentProcessFilter` — Allowlist known security tools or system processes accessing LSASS.
- **`AN0649` Analytic 0649** · Linux
  Processes opening /proc/*/mem or /proc/*/maps targeting credential-storing services like sshd or login. Behavior often includes high privilege escalation and memory inspection tools such as gcore or gdb.
  - *Log sources:* `auditd:SYSCALL` (open); `auditd:SYSCALL` (ptrace); `auditd:SYSCALL` (execve)
  - *Tune:* `TargetProcessName` — Define sensitive targets (e.g., sshd, login) being memory-read.; `ToolProcessName` — Flag use of memory dump tools like gcore, gdb, pmap.
- **`AN0650` Analytic 0650** · macOS
  Unsigned processes accessing system memory or launching known credential scraping tools (e.g., osascript, dylib injections) to access the Keychain or sensitive memory regions.
  - *Log sources:* `macos:unifiedlog` (Code Execution & Entitlement Access); `macos:keychain` (Access to Keychain DB or system.keychain); `macos:osquery` (Invocation of osascript or dylib injection)
  - *Tune:* `KeychainAccessPath` — Path to watch for abnormal access, e.g., /Library/Keychains/; `SignedBinaryStatus` — Filter out signed/trusted binaries.

---

### T1003.001 — LSASS Memory
<a id="t1003001"></a>

**Detection strategy:** Detection of Credential Dumping from LSASS Memory via Access and Dump Sequence (`DET0363`)  
**Platforms:** Windows  
**ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/) · [detail page](../../techniques/credential-access.md#t1003001)

- **`AN1030` Analytic 1030** · Windows
  A non-privileged or abnormal process attempts to open a handle with full access (0x1F0FFF) to lsass.exe and subsequently invokes memory dump, file creation, or registry modification indicative of credential scraping. This behavior chain reflects staged credential theft activity.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Security` (EventCode=4673); `WinEventLog:Sysmon` (EventCode=13, 14)
  - *Tune:* `AccessMask` — Set to 0x1F0FFF to detect full memory access attempts; can be scoped down to reduce noise.; `TimeWindow` — Defines time between LSASS access and dump file creation or registry modification (e.g., 5 minutes).; `ParentProcessName` — Allowlist known legitimate tools (e.g., AV/EDR) accessing lsass.exe.; `DumpFilePath` — Paths where memory dumps are written, e.g., %TEMP%, C:\Windows\Temp.; `CommandLinePattern` — Common dumping syntax like rundll32, procdump, comsvcs.dll, Invoke-Mimikatz.

---

### T1003.002 — Security Account Manager
<a id="t1003002"></a>

**Detection strategy:** Credential Dumping from SAM via Registry Dump and Local File Access (`DET0085`)  
**Platforms:** Windows  
**ATT&CK:** [T1003.002](https://attack.mitre.org/techniques/T1003/002/) · [detail page](../../techniques/credential-access.md#t1003002)

- **`AN0235` Analytic 0235** · Windows
  An adversary running with SYSTEM-level privileges executes commands or accesses registry keys to dump the SAM hive or directly reads sensitive local files from the config directory. This behavior often involves sequential access to HKLM\SAM, HKLM\SYSTEM, and creation of .save or .dmp files, enabling offline hash extraction.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=2)
  - *Tune:* `CommandLinePattern` — Detectable variations include `reg save`, `reg.exe save`, or PowerShell equivalents for dumping SAM/SYSTEM hives.; `TargetFilePath` — Defenders can tune based on dump file path patterns (e.g., `%TEMP%\sam.save`, `C:\Users\Public\*.dmp`).; `RegistryPath` — Tune for HKLM\SAM, HKLM\SYSTEM or access via direct \Device\Harddisk paths.; `TimeWindow` — Temporal gap between SAM and SYSTEM hive dumping can be tuned (e.g., 3 minutes).; `ParentProcessName` — Useful for suppressing known-good access (e.g., backup tools).

---

### T1003.003 — NTDS
<a id="t1003003"></a>

**Detection strategy:** Detection of NTDS.dit Credential Dumping from Domain Controllers (`DET0586`)  
**Platforms:** Windows  
**ATT&CK:** [T1003.003](https://attack.mitre.org/techniques/T1003/003/) · [detail page](../../techniques/credential-access.md#t1003003)

- **`AN1611` Analytic 1611** · Windows
  Detects credential dumping attempts targeting the NTDS.dit database by monitoring shadow copy creation, suspicious file access to %SystemRoot%\NTDS\ntds.dit, and the use of tooling like ntdsutil.exe or volume management APIs.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=2); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Microsoft-Windows-VSS` (Volume Shadow Copy Creation)
  - *Tune:* `TargetFilePath` — Tunable for NTDS file location or backup paths if organization uses custom domain controller storage structure.; `ParentProcessName` — Can suppress backup-related parent processes to reduce false positives.; `TimeWindow` — Temporal correlation between shadow copy creation and NTDS file access (e.g., 5 min window).; `UserContext` — Tune based on expected privileged user/service account behavior.

---

### T1003.004 — LSA Secrets
<a id="t1003004"></a>

**Detection strategy:** Detection of LSA Secrets Dumping via Registry and Memory Extraction (`DET0437`)  
**Platforms:** Windows  
**ATT&CK:** [T1003.004](https://attack.mitre.org/techniques/T1003/004/) · [detail page](../../techniques/credential-access.md#t1003004)

- **`AN1212` Analytic 1212** · Windows
  Detects adversary activity aimed at accessing LSA Secrets, including registry key export of HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets or memory scraping via tools such as Mimikatz or PowerSploit's Invoke-Mimikatz.
  - *Log sources:* `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `TargetObject` — Target registry paths like HKLM\SECURITY\Policy\Secrets or variants can be tuned depending on OS version or registry redirection settings.; `ImageLoaded` — Module names such as `lsasrv.dll`, `sechost.dll`, or suspicious DLLs loaded by user processes may require tuning for known-good service operations.; `AccessMask` — Tuning based on whether processes are using specific sensitive access rights (e.g., 0x2 or 0x4).; `TimeWindow` — Temporal window between registry access and command-line tool execution.

---

### T1003.005 — Cached Domain Credentials
<a id="t1003005"></a>

**Detection strategy:** Detection of Cached Domain Credential Dumping via Local Hash Cache Access (`DET0513`)  
**Platforms:** Linux, Windows  
**ATT&CK:** [T1003.005](https://attack.mitre.org/techniques/T1003/005/) · [detail page](../../techniques/credential-access.md#t1003005)

- **`AN1417` Analytic 1417** · Windows
  Detects adversary behavior accessing Windows cached domain credential files using tools like Mimikatz, reg.exe, or PowerShell, often combined with registry exports or LSASS memory scraping.
  - *Log sources:* `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=10)
  - *Tune:* `TargetFilename` — Location of cached credential files may vary with OS version or custom registry hive exports.; `CommandLine` — Patterns for reg save, secretsdump, or PowerShell dumping tools may be tuned to org-specific tooling.; `TimeWindow` — Temporal correlation window between process execution and registry/file access.
- **`AN1418` Analytic 1418** · Linux
  Detects access to SSSD or Quest VAS cached credential databases using tdbdump or other file access patterns, requiring sudo/root access.
  - *Log sources:* `auditd:SYSCALL` (file); `auditd:EXECVE` (EXECVE); `linux:osquery` (process_events)
  - *Tune:* `filepath` — SSSD and Quest cache paths differ by deployment and OS variant.; `CommandLine` — Tunable to capture specific tools (e.g., tdbdump, cat) or scripts accessing cache files.; `TimeWindow` — Time between elevation and file access can be adjusted to account for legitimate system behavior.

---

### T1003.006 — DCSync
<a id="t1003006"></a>

**Detection strategy:** Detection of Unauthorized DCSync Operations via Replication API Abuse (`DET0594`)  
**Platforms:** Windows  
**ATT&CK:** [T1003.006](https://attack.mitre.org/techniques/T1003/006/) · [detail page](../../techniques/credential-access.md#t1003006)

- **`AN1632` Analytic 1632** · Windows
  Detects unauthorized invocation of replication operations (DCSync) via Directory Replication Service (DRS), often executed by threat actors using Mimikatz or similar tools from non-DC endpoints.
  - *Log sources:* `WinEventLog:Security` (EventCode=4662); `WinEventLog:Security` (EventCode=4929); `NSM:Content` (Traffic on RPC DRSUAPI)
  - *Tune:* `TimeWindow` — Defines the correlation window for unusual account access followed by DRSUAPI traffic.; `UserContext` — Allows tuning for specific accounts known to legitimately request replication.; `SourceIP` — Expected replication should only come from known DCs; this field allows excluding trusted DCs.

---

### T1003.007 — Proc Filesystem
<a id="t1003007"></a>

**Detection strategy:** Detecting OS Credential Dumping via /proc Filesystem Access on Linux (`DET0593`)  
**Platforms:** Linux  
**ATT&CK:** [T1003.007](https://attack.mitre.org/techniques/T1003/007/) · [detail page](../../techniques/credential-access.md#t1003007)

- **`AN1631` Analytic 1631** · Linux
  Monitoring adversary access to sensitive process memory via the /proc filesystem to extract credential material, often involving multi-step access to /proc/[pid]/mem or /proc/[pid]/maps combined with privilege escalation or credential scraping binaries.
  - *Log sources:* `auditd:SYSCALL` (open, read); `auditd:SYSCALL` (write); `auditd:SYSCALL` (ptrace or process_vm_readv); `linux:Sysmon` (EventCode=1)
  - *Tune:* `AccessedFilePath` — Monitored paths such as /proc/[pid]/mem or /proc/[pid]/maps may need to be scoped based on environment; `ProcessName` — Command-line or binary names associated with credential scraping tools may vary; `UserContext` — Elevated user or unexpected user context accessing other process memory may indicate malicious activity; `TimeWindow` — Correlating memory access with process creation or ptrace activity within a specific time range

---

### T1003.008 — /etc/passwd and /etc/shadow
<a id="t1003008"></a>

**Detection strategy:** Credential Access via /etc/passwd and /etc/shadow Parsing (`DET0446`)  
**Platforms:** Linux  
**ATT&CK:** [T1003.008](https://attack.mitre.org/techniques/T1003/008/) · [detail page](../../techniques/credential-access.md#t1003008)

- **`AN1234` Analytic 1234** · Linux
  Adversaries attempt to read sensitive files such as /etc/passwd and /etc/shadow for credential dumping. This may involve access to the files directly via command-line utilities (e.g., cat, less), creation of backup copies, or parsing through post-exploitation frameworks. Multi-event correlation includes elevated process execution, file access/read on sensitive paths, and anomalous read behaviors tied to non-root or unusual users.
  - *Log sources:* `auditd:SYSCALL` (open, read); `auditd:SYSCALL` (execve)
  - *Tune:* `exe` — Executable name used to access credentials (e.g., cat, cp, awk); can vary across environments; `user` — User context under which the access occurs; typically root, but can be non-standard in attacks; `PATH` — Target file paths (e.g., /etc/passwd, /etc/shadow); may vary in containerized or customized systems; `TimeWindow` — Time correlation threshold for chaining access and execution events

---

### T1040 — Network Sniffing
<a id="t1040"></a>

**Detection strategy:** Detection Strategy for Network Sniffing Across Platforms (`DET0314`)  
**Platforms:** IaaS, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1040](https://attack.mitre.org/techniques/T1040/) · [detail page](../../techniques/credential-access.md#t1040)

- **`AN0875` Analytic 0875** · Windows
  Detects suspicious execution of network monitoring tools (e.g., Wireshark, tshark, Microsoft Message Analyzer), driver loading indicative of promiscuous mode, or non-admin user privilege escalation to access NICs for capture.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:System` (EventCode=7045)
  - *Tune:* `ToolNames` — Adjust list of known sniffing tools based on environment and known administrator usage.; `TimeWindow` — Tune time of day or frequency of capture sessions to reduce false positives from authorized use.
- **`AN0876` Analytic 0876** · Linux
  Correlates interface mode changes to promiscuous with execution of sniffing tools like tcpdump, tshark, or custom pcap libraries. Detects abnormal NIC configurations and unauthorized sniffing from non-root sessions.
  - *Log sources:* `auditd:SYSCALL` (execve, setifflags); `auditd:SYSCALL` (promiscuous mode transitions (ioctl or ifconfig)); `networkconfig ` (interface flag PROMISC, netstat | ip link | ethtool)
  - *Tune:* `InterfaceList` — Limit analysis to external interfaces (e.g., eth0, wlan0) and exclude virtual adapters.; `PromiscuousSessionThreshold` — Raise alerts if interface remains in PROMISC longer than threshold duration.
- **`AN0877` Analytic 0877** · macOS
  Detects enabling of interface sniffing via packet capture tools or AppleScript triggering `tcpdump`. Leverages Unified Logs and process lineage to identify suspicious use of `pfctl`, `tcpdump`, or `libpcap` libraries.
  - *Log sources:* `macos:unifiedlog` (eventMessage = 'promiscuous'); `macos:osquery` (process_events where path like '%tcpdump%'); `fs:fsusage` (access to BPF devices or interface IOCTLs)
  - *Tune:* `AllowedTools` — Whitelist Apple-native tools used by IT admins and mobile device management (MDM).; `UserContext` — Prioritize detections from non-admin or low-privilege users performing packet captures.
- **`AN0878` Analytic 0878** · IaaS
  Detects creation of traffic mirroring sessions (e.g., AWS VPC Traffic Mirroring, Azure vTAP) that redirect traffic from critical assets to other virtual instances, often followed by file creation or session establishment.
  - *Log sources:* `AWS:CloudTrail` (CreateTrafficMirrorSession / ModifyTrafficMirrorTarget)
  - *Tune:* `MirrorSourceList` — Identify VMs or containers where mirror sessions are abnormal or unexpected.; `TargetIAMRole` — Monitor whether mirror target roles match administrative expectations.
- **`AN0879` Analytic 0879** · Network Devices
  Detects execution of capture commands via CLI (`monitor capture`, `debug packet`, etc.) or unauthorized CLI access followed by logging configuration changes on Cisco/Juniper/Arista gear.
  - *Log sources:* `networkdevice:syslog` (admin login events); `networkdevice:syslog` (exec command='monitor capture'); `networkdevice:syslog` (config change (e.g., logging buffered, pcap buffers))
  - *Tune:* `AdminSessionDuration` — Tunable alerting threshold for interactive CLI sessions.; `CaptureCommandList` — Define set of known capture/debug commands per vendor to flag unexpected usage.

---

### T1110 — Brute Force
<a id="t1110"></a>

**Detection strategy:** Brute Force Authentication Failures with Multi-Platform Log Correlation (`DET0463`)  
**Platforms:** Identity Provider, Linux, SaaS, Windows, macOS  
**ATT&CK:** [T1110](https://attack.mitre.org/techniques/T1110/) · [detail page](../../techniques/credential-access.md#t1110)

- **`AN1275` Analytic 1275** · Windows
  High volume of failed logon attempts followed by a successful one from a suspicious user, host, or timeframe
  - *Log sources:* `WinEventLog:Security` (EventCode=4776, 4625)
  - *Tune:* `TimeWindow` — Adjustable window to correlate failed logons, e.g., 5-10 minutes; `UserContext` — Define scope of monitored users (e.g., service accounts, admins); `FailureThreshold` — Count of failed logons before raising an alert (e.g., 10-15)
- **`AN1276` Analytic 1276** · Linux
  Multiple authentication failures for valid or invalid users followed by success from same IP/user
  - *Log sources:* `auditd:USER_LOGIN` (USER_AUTH)
  - *Tune:* `TimeWindow` — Period of brute force activity correlation (e.g., 5 mins); `IPWhitelist` — Exclude known monitoring IPs or jump boxes; `LoginSource` — Filter SSH vs. local logins
- **`AN1277` Analytic 1277** · Identity Provider
  Password spraying or brute force attempts across user pool within short time intervals
  - *Log sources:* `azure:signinlogs` (Sign-in logs)
  - *Tune:* `UsernameSprayThreshold` — Max number of accounts targeted from a single IP; `GeoAnomaly` — Mismatch between user location and request location
- **`AN1278` Analytic 1278** · macOS
  Multiple failed authentications in unified logs (e.g., loginwindow or sshd)
  - *Log sources:* `macos:unifiedlog` (auth)
  - *Tune:* `TimeWindow` — Scope of authentication failures (e.g., 10-15 mins); `TargetUser` — Filter known service or decoy accounts
- **`AN1279` Analytic 1279** · SaaS
  Excessive login attempts followed by success from SaaS apps like O365, Dropbox, etc.
  - *Log sources:* `m365:unified` (Sign-in logs)
  - *Tune:* `AppName` — Detect brute force attempts targeting specific apps; `UserGroup` — Limit alert scope to high-value user groups

---

### T1110.001 — Password Guessing
<a id="t1110001"></a>

**Detection strategy:** Password Guessing via Multi-Source Authentication Failure Correlation (`DET0551`)  
**Platforms:** Identity Provider, Linux, Network Devices, SaaS, Windows, macOS  
**ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001/) · [detail page](../../techniques/credential-access.md#t1110001)

- **`AN1521` Analytic 1521** · Windows
  Series of authentication failures (Event ID 4625) targeting the same or similar user accounts over time from one or more remote IPs
  - *Log sources:* `WinEventLog:Security` (EventCode=4625)
  - *Tune:* `TimeWindow` — Defines the period in which multiple failed attempts are aggregated (e.g., 10 minutes); `UsernamePattern` — Filter for common account naming conventions, e.g., service accounts or administrator variants; `SourceIPThreshold` — Limit on unique IPs trying to authenticate against a single account
- **`AN1522` Analytic 1522** · Linux
  Repeated failed SSH login attempts followed by a possible success from the same remote host
  - *Log sources:* `linux:syslog` (sshd[pid]: Failed password)
  - *Tune:* `PortScope` — Can be tuned to non-standard ports if SSH is moved from default; `UserScope` — Filter high-value or restricted users (e.g., root, service); `AttemptThreshold` — Number of consecutive failures before flagging (e.g., >5 in 2 minutes)
- **`AN1523` Analytic 1523** · macOS
  Series of failed logins from loginwindow or sshd with repeated usernames or password prompts
  - *Log sources:* `macos:unifiedlog` (authd)
  - *Tune:* `AuthMechanism` — Local console vs. SSH vs. remote Apple Admin tools; `FailurePattern` — Use regex to isolate brute force messages among other log noise
- **`AN1524` Analytic 1524** · Identity Provider
  Multiple failed sign-in attempts from external sources across many users followed by success from the same IP
  - *Log sources:* `azure:signinlogs` (Sign-in logs)
  - *Tune:* `GeoRiskScore` — Elevate anomalies from uncommon geolocations; `MFAStatus` — Elevate logins missing MFA on high-value accounts
- **`AN1525` Analytic 1525** · Network Devices
  Login attempt failures over SNMP, Telnet, or SSH interface, often reflected in logs or syslog events
  - *Log sources:* `networkdevice:syslog` (login failed)
  - *Tune:* `InterfaceType` — Specify monitoring of Telnet/SSH/SNMP for login activity; `FailedAttemptThreshold` — How many failures in short succession should trigger alerting
- **`AN1526` Analytic 1526** · SaaS
  Password guessing attempts against web-based apps (e.g., Dropbox, Google Workspace) reflected in API or sign-in logs
  - *Log sources:* `GCPAuditLogs:login.googleapis.com` (Failed sign-in events)
  - *Tune:* `AppContext` — Which SaaS apps should be monitored for brute force attempts; `EmailPattern` — Limit scope to enterprise domains or service accounts

---

### T1110.002 — Password Cracking
<a id="t1110002"></a>

**Detection strategy:** Post-Credential Dump Password Cracking Detection via Suspicious File Access and Hash Analysis Tools (`DET0105`)  
**Platforms:** Identity Provider, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1110.002](https://attack.mitre.org/techniques/T1110/002/) · [detail page](../../techniques/credential-access.md#t1110002)

- **`AN0292` Analytic 0292** · Windows
  Use of hash-cracking tools (e.g., John the Ripper, Hashcat) after credential dumping, combined with high CPU usage or GPU invocation via unsigned binaries accessing password hash files
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=10)
  - *Tune:* `HashToolName` — Match execution against known cracking toolnames like hashcat.exe, john.exe, etc.; `FilePathIndicators` — Watch for access to common hash dump locations (e.g., SAM, SYSTEM, NTDS.dit); `ExecutionContext` — Run context: local interactive user vs. scheduled task or remote session
- **`AN0293` Analytic 0293** · Linux
  Execution of hash cracking binaries or scripts (e.g., john, hashcat) following access to shadow file or dumped hashes
  - *Log sources:* `auditd:SYSCALL` (execve); `linux:syslog` (auth.log or custom tool logs)
  - *Tune:* `ShadowAccessPattern` — Access to /etc/shadow or known dumped hash files; `CrackingBinaryPath` — Tool path or name associated with hash cracking; `CPUUsageThreshold` — Sustained CPU load post-credential dump can be an indicator
- **`AN0294` Analytic 0294** · macOS
  Unsigned or scripting-based processes invoking password cracking binaries or accessing hashed credential artifacts post-login
  - *Log sources:* `macos:unifiedlog` (process and file events via log stream)
  - *Tune:* `UnsignedBinaryPath` — Path to untrusted binaries launched by user; `UserPrivilegeLevel` — Helps distinguish between system and user-launched activity
- **`AN0295` Analytic 0295** · Identity Provider
  Sudden valid logins from accounts that previously had credentials dumped but had not authenticated successfully in the past; correlated with timeline of suspected hash cracking
  - *Log sources:* `azure:signinlogs` (Success logs from high-risk accounts)
  - *Tune:* `PostDumpTimeWindow` — Detection window after credential dumping to watch for successful logins; `LoginLocationRisk` — Use IP/geolocation risk scoring to flag unusual access
- **`AN0296` Analytic 0296** · Network Devices
  Offline cracking inferred by subsequent successful CLI or web-based authentications into routers or switches from previously dumped accounts
  - *Log sources:* `networkdevice:syslog` (config access, authentication logs)
  - *Tune:* `LogonTimeCorrelation` — Window to link credential theft and reuse; `SourceDeviceTag` — Filters based on where cracking may have occurred externally

---

### T1110.003 — Password Spraying
<a id="t1110003"></a>

**Detection strategy:** Distributed Password Spraying via Authentication Failures Across Multiple Accounts (`DET0487`)  
**Platforms:** Containers, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS  
**ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/) · [detail page](../../techniques/credential-access.md#t1110003)

- **`AN1336` Analytic 1336** · Windows
  A high volume of authentication failures using a single password (or small set) across many different user accounts within a defined time window
  - *Log sources:* `WinEventLog:Security` (EventCode=4625, 4771, 4648)
  - *Tune:* `PasswordReuseThreshold` — Number of distinct accounts a password is used against before alerting; `TimeWindow` — Window over which the correlation is measured (e.g., 10 mins); `TargetGroupFilter` — Limit detection to sensitive or monitored user groups (e.g., Admins)
- **`AN1337` Analytic 1337** · Linux
  Authentication failures across different accounts using a repeated or similar password via SSH or PAM stack within a short window
  - *Log sources:* `linux:syslog` (Failed password for invalid user)
  - *Tune:* `PasswordReusePattern` — Repetition or minor variation of the same password across user attempts; `IPAggregationWindow` — Length of time to observe distributed spray attempts from single source
- **`AN1338` Analytic 1338** · macOS
  Multiple failed login attempts across different users using common password patterns (e.g., 'Welcome2023')
  - *Log sources:* `macos:unifiedlog` (Login Window and Authd errors)
  - *Tune:* `RetryCountThreshold` — Total number of attempts before alerting; `CommonPasswordList` — List of passwords considered suspicious due to widespread use
- **`AN1339` Analytic 1339** · Identity Provider
  Sign-in failures across enterprise SSO applications or SaaS platforms from same IP address using the same password against multiple user identities
  - *Log sources:* `azure:signinlogs` (Failure Reason + UserPrincipalName)
  - *Tune:* `GeoIPAnomalyCheck` — Use geolocation mismatches to strengthen signal; `FailedUserRatio` — Proportion of total user base affected to filter noise
- **`AN1340` Analytic 1340** · Network Devices
  Authentication failure logs on routers/switches showing repeated use of default or common passwords across multiple accounts
  - *Log sources:* `networkdevice:syslog` (AAA or TACACS authentication failures)
  - *Tune:* `AuthFailureBurst` — Cluster of failed attempts in short period indicating spray; `InterfaceFilter` — Limit detection to console/SSH vs web UI interfaces
- **`AN1341` Analytic 1341** · Containers
  Repeated failed authentication attempts to container APIs, control planes, or login shells across many user names using same password
  - *Log sources:* `kubernetes:audit` (Failed login)
  - *Tune:* `OrchestrationScope` — Detect spray attempts scoped to single pod vs full cluster; `ServiceAccountFilter` — Limit detection to non-service accounts to reduce noise
- **`AN1342` Analytic 1342** · Office Suite
  Failed authentication attempts across user mailboxes using identical or common passwords (e.g., OWA brute attempts)
  - *Log sources:* `m365:exchange` (FailedLogin)
  - *Tune:* `MailboxAccessAttempts` — Threshold on mailbox login failures by same IP; `EmailPatternAnalysis` — Match target usernames to common spray dictionaries
- **`AN1343` Analytic 1343** · SaaS
  SaaS applications receiving authentication failures for dozens of accounts using same password or login signature
  - *Log sources:* `saas:auth` (signin_failed)
  - *Tune:* `CloudAppScope` — Restrict detection to identity providers or select high-risk SaaS platforms; `UserPopulationSensitivity` — Adjust based on size and role of account pool

---

### T1110.004 — Credential Stuffing
<a id="t1110004"></a>

**Detection strategy:** Credential Stuffing Detection via Reused Breached Credentials Across Services (`DET0460`)  
**Platforms:** Containers, IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS  
**ATT&CK:** [T1110.004](https://attack.mitre.org/techniques/T1110/004/) · [detail page](../../techniques/credential-access.md#t1110004)

- **`AN1262` Analytic 1262** · Windows
  Multiple failed authentication attempts using distinct username/password pairs from a single IP address or session within a short time window, targeting common services like RDP or SMB
  - *Log sources:* `WinEventLog:Security` (EventCode=4625)
  - *Tune:* `UsernameUniquenessThreshold` — Minimum number of unique usernames in failed login attempts before triggering alert; `TimeWindow` — Duration (e.g., 5 minutes) to observe the behavior chain of rapid login attempts; `SourceIPScope` — Whether to group by full IP or CIDR block for bursty behavior from botnets
- **`AN1263` Analytic 1263** · Linux
  Rapid login failures across different users from a single IP address, targeting SSH or PAM login with distinct username-password pairs
  - *Log sources:* `linux:syslog` (SSH failed login)
  - *Tune:* `LoginFailureRatio` — Ratio of failed logins per unique user attempted; `AuthServiceFilter` — Restrict detection to certain protocols (e.g., sshd, login, su)
- **`AN1264` Analytic 1264** · macOS
  Burst of failed authentications with rotating usernames against loginwindow or remote management service using reused breached credentials
  - *Log sources:* `macos:unifiedlog` (Login failure / authorization denied)
  - *Tune:* `DistinctUsernameCount` — Tunable threshold for number of attempted usernames in a time window; `RemoteAccessFilter` — Restrict behavior detection to remote login interfaces
- **`AN1265` Analytic 1265** · Identity Provider
  Same source IP performing multiple authentication attempts using known breached username/password combinations across different identities in Azure AD, Okta, or Duo
  - *Log sources:* `azure:signinlogs` (status = failure)
  - *Tune:* `BreachedCredentialSourceMatch` — Optional enrichment using known leaked credentials database; `SSOServiceScope` — Targeting only federated or hybrid identity auth flows
- **`AN1266` Analytic 1266** · SaaS
  Multiple sign-in failures against cloud-based applications using username/password combinations leaked from unrelated domains
  - *Log sources:* `saas-app:auth` (login_failure)
  - *Tune:* `UserAccountOverlap` — Correlate credentials reused across multiple SaaS platforms; `FailedAttemptsPerIP` — Number of failed logins from same IP before alerting
- **`AN1267` Analytic 1267** · Network Devices
  Router/firewall/syslog logs showing authentication failures with unique usernames and reused credentials from same source IP
  - *Log sources:* `networkdevice:syslog` (AAA, RADIUS, or TACACS authentication)
  - *Tune:* `AuthProtocolFilter` — Limit detection to interactive logins rather than SNMP/RPC; `FailedAuthBurst` — Detection trigger when failure rate exceeds normal profile
- **`AN1268` Analytic 1268** · Containers
  Credential stuffing attempts against Kubernetes API or containerized login shells using stolen or leaked user credentials
  - *Log sources:* `kubernetes:apiserver` (authentication.k8s.io/v1beta1)
  - *Tune:* `PodAccessScope` — Detect attempts across multiple pods/namespaces using same IP; `CredentialSetSize` — Number of username/password pairs used in attack attempt
- **`AN1269` Analytic 1269** · Office Suite
  Use of leaked credential pairs against Outlook Web Access (OWA), Microsoft 365, or Exchange from a single client IP with multiple failures
  - *Log sources:* `m365:exchange` (Logon failure)
  - *Tune:* `PasswordSourceMatch` — Optional: cross-reference to haveibeenpwned or internal credential dumps; `MailboxLoginThreshold` — Tunable value for how many unique mailbox attempts trigger alert
- **`AN1270` Analytic 1270** · IaaS
  Burst of failed login attempts across VM instances using leaked credential pairs from single IP in public cloud environments
  - *Log sources:* `AWS:CloudTrail` (eventName=ConsoleLogin | eventType=AwsConsoleSignIn)
  - *Tune:* `InstanceIDScope` — Define if detection should group logins per host or across cluster; `IPBehaviorHistory` — Correlate against past IP reputation or behavioral profiles

---

### T1111 — Multi-Factor Authentication Interception
<a id="t1111"></a>

**Detection strategy:** Detection Strategy for MFA Interception via Input Capture and Smart Card Proxying (`DET0246`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1111](https://attack.mitre.org/techniques/T1111/) · [detail page](../../techniques/credential-access.md#t1111)

- **`AN0687` Analytic 0687** · Windows
  Behavior chain involving unexpected API calls to capture keyboard input, driver loads for keyloggers, or remote use of smart card authentication via logon sessions not initiated by local user interaction
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Security` (EventCode=4624, 4648); `WinEventLog:Sysmon` (EventCode=13, 14)
  - *Tune:* `AccessMask` — Tunable based on what memory-level access the keylogger uses (e.g., 0x10 for read); `ProcessNameExclusions` — Legitimate accessibility tools may use similar API calls (e.g., Magnifier.exe); `TimeWindow` — Define how quickly access + registry mod + smart card use must co-occur
- **`AN0688` Analytic 0688** · Linux
  Detection of unauthorized keylogger behavior through access to `/dev/input`, loading kernel modules (e.g., via insmod), or polling user input devices from non-user shells
  - *Log sources:* `linux:syslog` (syscalls (open, read, ioctl) on /dev/input or /proc/*/fd/*); `linux:syslog` (dmesg or syslog for module loads)
  - *Tune:* `PathTarget` — Can tune based on device paths accessed for keyboard input (e.g., /dev/input/event0); `UserContext` — Exclude root or admin-auth shell sessions if needed; `ModuleWhitelist` — Set a known list of allowed kernel modules
- **`AN0689` Analytic 0689** · macOS
  Processes accessing TCC-protected input APIs or polling HID services without user interaction, or dynamically loaded keylogging frameworks using accessibility privileges
  - *Log sources:* `macos:unifiedlog` (com.apple.securityd, com.apple.tccd); `macos:osquery` (query: process_events, launchd, and tcc.db access)
  - *Tune:* `AccessibilityAPIUsage` — Detection of programs requesting access to input monitoring (e.g., CGEventTap); `TCCBypassAttempt` — Alert if TCC settings are altered or bypassed; `SignedBinaryCheck` — Tunable based on developer signing status (legitimate software vs unsigned)

---

### T1187 — Forced Authentication
<a id="t1187"></a>

**Detection strategy:** Detect Forced SMB/WebDAV Authentication via lure files and outbound NTLM (`DET0022`)  
**Platforms:** Windows  
**ATT&CK:** [T1187](https://attack.mitre.org/techniques/T1187/) · [detail page](../../techniques/credential-access.md#t1187)

- **`AN0065` Analytic 0065** · Windows
  Adversary stages a lure that references a remote resource (e.g., LNK/SCF/Office template). When the user opens/renders the file or a shell enumerates icons, the host automatically attempts SMB or WebDAV authentication to the attacker host. The chain is: (1) lure file is created or modified in a user-exposed location → (2) user or system accesses the lure → (3) host makes outbound NTLM (SMB 139/445 or WebDAV over 80/443) to an untrusted destination → (4) repeated attempts from multiple users/hosts or from privileged workstations.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Security` (EventCode=4663, 4670, 4656); `NSM:Flow` (HTTP/WebDAV requests that contain NTLMSSP or PROPFIND/MOVE/OPTIONS with Authorization: NTLM); `NSM:Flow` (Outbound connections to TCP 139,445 and HTTP/HTTPS to WebDAV endpoints from workstation subnets)
  - *Tune:* `UserLocations` — Folders where lures are most effective (Desktop, Public, Downloads, Temp, Cache, Start Menu, Startup). Adjust to enterprise layout.; `LureExtensions` — File types commonly abused (.lnk, .scf, .url, .doc/.xls/.ppt/.pdf/.html). Extend for your tooling and languages.; `UntrustedCIDR/DNS` — Org-specific list of external/unknown networks or domains; used to suppress sanctioned file servers and WebDAV gateways.; `TimeWindow` — Correlation horizon (e.g., 15–30 minutes) between file access and outbound NTLM attempt.; `WorkstationZones` — Asset/zone tags that distinguish workstations from servers; helps flag workstation→workstation SMB, which is often abnormal.; `OfficeTemplatePaths` — Paths to Office templates to catch template injection references and abnormal loads.

---

### T1212 — Exploitation for Credential Access
<a id="t1212"></a>

**Detection strategy:** Detection Strategy for Exploitation for Credential Access (`DET0174`)  
**Platforms:** Identity Provider, Linux, Windows, macOS  
**ATT&CK:** [T1212](https://attack.mitre.org/techniques/T1212/) · [detail page](../../techniques/credential-access.md#t1212)

- **`AN0493` Analytic 0493** · Windows
  Detects adversary exploitation of authentication mechanisms or credential validation processes. Defender perspective includes forged Kerberos tickets (e.g., MS14-068), abnormal LSASS memory access, replayed authentication attempts, and unexpected crashes of authentication services. Multi-event correlation ties exploitation attempts to abnormal process creation, service instability, and suspicious authentication events.
  - *Log sources:* `WinEventLog:Security` (EventCode=4768, 4769, 4770); `WinEventLog:Sysmon` (EventCode=10)
  - *Tune:* `MonitoredAccounts` — High-value accounts (e.g., Domain Admins) for anomalous ticket issuance or replay activity.; `ReplayDetectionWindow` — Time window for correlating duplicate or replayed Kerberos authentications.
- **`AN0494` Analytic 0494** · Linux
  Detects exploitation of authentication daemons or PAM modules. Defender perspective includes failed or anomalous PAM authentications, abnormal segfaults in authentication services, and exploitation attempts followed by successful unauthorized logins. Correlation identifies memory corruption, replay attempts, and privilege escalation tied to credential services.
  - *Log sources:* `auditd:SYSCALL` (execve: Suspicious binaries or scripts interacting with authentication binaries (sshd, gdm, login)); `NSM:Connections` (Repeated failed authentication attempts or replay patterns)
  - *Tune:* `AuthServiceList` — List of monitored authentication services (e.g., sshd, gdm, PAM modules).; `FailureThreshold` — Number of failed authentications within a window before escalating to replay suspicion.
- **`AN0495` Analytic 0495** · macOS
  Detects exploitation attempts against macOS authentication frameworks such as OpenDirectory or Keychain. Defender perspective includes abnormal crashes in opendirectoryd, unauthorized Keychain API usage, and unusual sudo or login events. Correlation links unexpected process behavior with credential access anomalies.
  - *Log sources:* `macos:unifiedlog` (opendirectoryd crashes or abnormal authentication errors); `macos:osquery` (execve: Processes unexpectedly invoking Keychain or authentication APIs)
  - *Tune:* `WatchedAPIs` — List of authentication and Keychain-related APIs to monitor for unauthorized access.; `CrashCorrelationWindow` — Time window for correlating authentication service crashes with subsequent suspicious access.
- **`AN0496` Analytic 0496** · Identity Provider
  Detects exploitation of vulnerabilities in cloud identity providers (IdPs) such as Azure AD or Okta for credential access. Defender perspective includes anomalous token creation or renewal, authentication bypass events, and API abuse to mint unauthorized tokens. Correlation highlights exploitation attempts tied to absent or inconsistent audit logs.
  - *Log sources:* `azure:signinlogs` (TokenIssued, TokenRenewed: Unexpected or anomalous token issuance events); `m365:unified` (ConsentGranted: Abuse of application integrations to mint tokens bypassing MFA)
  - *Tune:* `TokenAnomalyThreshold` — Threshold for anomalous token creation or renewal before alerting.; `MonitoredAppIntegrations` — Applications with privileged access that should be tightly monitored for misuse.

---

### T1528 — Steal Application Access Token
<a id="t1528"></a>

**Detection strategy:** Detection Strategy for T1528 - Steal Application Access Token (`DET0515`)  
**Platforms:** Containers, IaaS, Identity Provider, Office Suite, SaaS  
**ATT&CK:** [T1528](https://attack.mitre.org/techniques/T1528/) · [detail page](../../techniques/credential-access.md#t1528)

- **`AN1423` Analytic 1423** · Containers
  Access and retrieval of container service account tokens followed by unauthorized API requests using those tokens to interact with the Kubernetes API server or internal services.
  - *Log sources:* `kubernetes:audit` (GET or LIST requests to /var/run/secrets/kubernetes.io/serviceaccount/ followed by access to the Kubernetes API server)
  - *Tune:* `TimeWindow` — Adjust based on how quickly tokens are expected to be used post-access; `UserContext` — Tuning for known service accounts that legitimately access the API
- **`AN1424` Analytic 1424** · IaaS
  Token retrieval from instance metadata endpoints such as AWS IMDS or Azure IMDS, followed by API usage using the obtained token from non-standard applications.
  - *Log sources:* `AWS:CloudTrail` (GetInstanceIdentityDocument or IMDSv2 token requests); `AWS:CloudTrail` (Use of temporary credentials issued from IMDS access)
  - *Tune:* `UserAgent` — May need tuning for known automation tools versus unexpected curl usage; `TimeWindow` — Correlate retrieval and use of token within expected timeout window
- **`AN1425` Analytic 1425** · Identity Provider
  Unusual OAuth app registration followed by user-granted OAuth tokens and subsequent high-privilege resource access via those tokens.
  - *Log sources:* `azure:audit` (App registrations or consent grants by abnormal users or at unusual times)
  - *Tune:* `ConsentScope` — Tunable based on risky or privileged scopes in the environment; `AppUserRatio` — Threshold of how many users have authorized a given app
- **`AN1426` Analytic 1426** · Office Suite
  Use of OAuth tokens by third-party apps to access user mail, calendar, or SharePoint resources where the token was granted recently or via spearphishing.
  - *Log sources:* `m365:unified` (App-only or delegated access patterns where client_id != known enterprise apps)
  - *Tune:* `ClientAppIDAllowList` — Defenders may allow known app IDs, flag unknowns; `AccessVolumeThreshold` — Rate of resource access by a newly consented app
- **`AN1427` Analytic 1427** · SaaS
  Programmatic access to user content via stolen access tokens in platforms like Slack, GitHub, Google Workspace — especially from new IPs, apps, or excessive resource access.
  - *Log sources:* `saas:googleworkspace` (Access via OAuth credentials with unusual scopes or from anomalous IPs); `saas:slack` (OAuth token use by unknown app client_id accessing private channels or files)
  - *Tune:* `GeoVelocity` — Flag when token use appears across geographically distant logins; `OAuthScopeSensitivity` — Weight certain scopes (admin, file.read) as higher risk

---

### T1539 — Steal Web Session Cookie
<a id="t1539"></a>

**Detection strategy:** Detection of Web Session Cookie Theft via File, Memory, and Network Artifacts (`DET0509`)  
**Platforms:** Linux, Office Suite, SaaS, Windows, macOS  
**ATT&CK:** [T1539](https://attack.mitre.org/techniques/T1539/) · [detail page](../../techniques/credential-access.md#t1539)

- **`AN1402` Analytic 1402** · Windows
  Detects suspicious access to browser session cookie storage (e.g., Chrome’s `Cookies` SQLite DB) or memory reads of browser processes. Anomalous injection or memory dump utilities targeting browser processes such as `chrome.exe`, `firefox.exe`, or `msedge.exe`.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=2); `WinEventLog:Security` (EventCode=4688)
  - *Tune:* `TargetProcessList` — Monitored browsers (e.g., chrome.exe, firefox.exe); `AccessToolList` — Suspicious tools used for injection or memory access (e.g., mimikatz, procdump); `TargetCookiePaths` — Locations of cookie stores like `AppData\Local\Google\Chrome\User Data\Default\Cookies`
- **`AN1403` Analytic 1403** · Linux
  Detects access to known browser cookie files (e.g., `~/.mozilla/firefox/*.default/cookies.sqlite`, `~/.config/google-chrome/`) and suspicious reads of browser memory via `/proc/[pid]/mem` or ptrace.
  - *Log sources:* `auditd:SYSCALL` (open or read to browser cookie storage); `auditd:SYSCALL` (ptrace syscall or access to /proc/*/mem)
  - *Tune:* `CookieFilePatterns` — Regex paths to known browser cookie locations; `TimeWindow` — Correlated time range between cookie read and web upload or process injection; `BrowserProcPatterns` — Expected names for browser processes being accessed
- **`AN1404` Analytic 1404** · macOS
  Detects unauthorized access to browser cookie paths (e.g., `~/Library/Application Support/Google/Chrome/Default/Cookies`) or `task_for_pid`/`vm_read` calls to Safari/Chrome memory space.
  - *Log sources:* `macos:unifiedlog` (vm_read, task_for_pid, or file open to cookie databases); `fs:fsusage` (file open for known browser cookie paths)
  - *Tune:* `TargetBrowserList` — List of processes considered web browsers on macOS; `BrowserCookiePathList` — Cookie database paths specific to each browser
- **`AN1405` Analytic 1405** · Office Suite
  Detects automation macros or VBA scripts in documents that access browser file paths, read cookie data, or attempt to exfiltrate browser session tokens over HTTP.
  - *Log sources:* `m365:unified` (RunMacro); `WinEventLog:Sysmon` (EventCode=2)
  - *Tune:* `MacroTargetPath` — Files or directories macros are attempting to access; `HTTPDestinationIPList` — List of IPs or domains that are uncommon for macro-based HTTP POSTs
- **`AN1406` Analytic 1406** · SaaS
  Detects use of session cookies or authentication tokens from unusual user agents or locations. Identifies token reuse without reauthentication or attempts to bypass MFA using previously stolen cookies.
  - *Log sources:* `saas:googleworkspace` (login with reused session token and mismatched user agent or IP); `saas:okta` (session.token.reuse)
  - *Tune:* `TokenReuseTimeWindow` — Max allowed delta between token issuance and second use; `UserAgentAnomalyScore` — Deviation score from normal browser/device fingerprint; `GeoLocationAnomalyScore` — Deviation in IP region or ASN per user profile

---

### T1552 — Unsecured Credentials
<a id="t1552"></a>

**Detection strategy:** Detect Access or Search for Unsecured Credentials Across Platforms (`DET0412`)  
**Platforms:** Containers, Identity Provider, Linux, Network Devices, SaaS, Windows, macOS  
**ATT&CK:** [T1552](https://attack.mitre.org/techniques/T1552/) · [detail page](../../techniques/credential-access.md#t1552)

- **`AN1153` Analytic 1153** · Windows
  Unusual access to bash history, registry credentials paths, or private key files by unauthorized or scripting tools, with correlated file and process activity.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=13, 14)
  - *Tune:* `TimeWindow` — Defines the threshold time for accessing multiple sensitive files indicating automation.; `SuspiciousProcessList` — Process names to monitor (e.g., reg.exe, cmd.exe, powershell.exe, etc.)
- **`AN1154` Analytic 1154** · Linux
  Reading of sensitive files like .bash_history, /etc/shadow, or private key directories by unauthorized users or unusual processes.
  - *Log sources:* `auditd:SYSCALL` (open/read system calls to ~/.bash_history or /etc/shadow); `auditd:SYSCALL` (execution of tools like cat, grep, or awk on credential files)
  - *Tune:* `SensitivePaths` — Paths to credential files such as /etc/shadow or ~/.bash_history; `UserContext` — Whether the process runs under a privileged or non-interactive session
- **`AN1155` Analytic 1155** · macOS
  Unusual access to ~/Library/Keychains, ~/.bash_history, or Terminal command history by unauthorized processes or users.
  - *Log sources:* `macos:unifiedlog` (read access to ~/Library/Keychains or history files by terminal processes); `macos:unifiedlog` (execution of 'security', 'cat', or 'grep' commands accessing credential storage)
  - *Tune:* `ProcessName` — Tool or command used to query credentials (e.g., security, grep); `TargetPath` — Credential file paths (e.g., ~/Library/Keychains)
- **`AN1156` Analytic 1156** · SaaS
  Unusual web-based access or API scraping of password managers, single sign-on sessions, or credential sync services via browser automation or anomalous API tokens.
  - *Log sources:* `saas:googleworkspace` (Accessed third-party credential management service); `saas:zoom` (unusual web session tokens and automation patterns during login)
  - *Tune:* `TokenAnomalyThreshold` — Scoring threshold for access token entropy, reuse, or bot-like patterns; `AccessGeoLocation` — Region anomalies in SaaS portal access
- **`AN1157` Analytic 1157** · Identity Provider
  Unauthorized API or console calls to retrieve or reset password credentials, download key material, or modify SSO settings.
  - *Log sources:* `azure:signinlogs` (Reset password or download key from portal); `AWS:CloudTrail` (GetSecretValue)
  - *Tune:* `SSOSettingScope` — Subset of IdP settings monitored for unauthorized changes; `SecretType` — Which secrets (passwords, keys, tokens) are monitored
- **`AN1158` Analytic 1158** · Containers
  Access to container image layers or mounted secrets (e.g., Docker secrets) by processes not tied to entrypoint or orchestration context.
  - *Log sources:* `auditd:SYSCALL` (read of /run/secrets or docker volumes by non-entrypoint process); `containerd:Events` (unusual process spawned from container image context)
  - *Tune:* `EntrypointAllowlist` — Container entrypoints that are permitted to read secrets; `VolumeMountPath` — Paths to credentials/secrets inside container images
- **`AN1159` Analytic 1159** · Network Devices
  Use of configuration backup utilities or CLI access to dump plaintext passwords, local user hashes, or SNMP strings.
  - *Log sources:* `linux:syslog` (CLI access to 'show running-config', 'show password', or 'cat config.txt'); `NSM:Flow` (large transfer from management IPs to unauthorized host)
  - *Tune:* `ManagementInterfaceIPs` — IP ranges authorized to perform credential dumps; `CommandPattern` — Regex patterns for suspicious CLI commands

---

### T1552.001 — Credentials In Files
<a id="t1552001"></a>

**Detection strategy:** Detect Access to Unsecured Credential Files Across Platforms (`DET0307`)  
**Platforms:** Containers, IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1552.001](https://attack.mitre.org/techniques/T1552/001/) · [detail page](../../techniques/credential-access.md#t1552001)

- **`AN0856` Analytic 0856** · Windows
  Correlated file access to insecure credential files (e.g., *.env, *.xml, *.ps1) followed by suspicious process execution or authentication using retrieved credentials. Detected through Sysmon logs and Windows Security Event logs.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Security` (EventCode=4624, 4648)
  - *Tune:* `FileNamePattern` — Patterns like *.env, *credential* can be tuned to reduce noise or catch custom implementations; `ProcessAccessScope` — Defines scope of access (e.g., only untrusted parent processes or high-risk processes); `TimeWindow` — Time delta between credential file access and use in logon attempt
- **`AN0857` Analytic 0857** · Linux
  File reads or process executions involving insecurely stored credential files (e.g., config files with password fields) by non-root or anomalous users followed by ssh authentication attempts.
  - *Log sources:* `auditd:SYSCALL` (open/read of sensitive config or secret files); `auditd:EXECVE` (grep/cat/awk on files with password fields); `linux:syslog` (authentication success after file access)
  - *Tune:* `RegexPatterns` — Patterns like password, secret, token can be expanded or customized; `UserContextScope` — Scope of users monitored (e.g., root vs all users); `TimeWindow` — Time between suspicious file access and credential use
- **`AN0858` Analytic 0858** · macOS
  Terminal-based grep or open of plist/config files containing credentials, correlated with Keychain or system login attempts.
  - *Log sources:* `macos:unifiedlog` (grep/cat on files matching credential patterns); `macos:unifiedlog` (open/read of *.plist or .env files); `macos:unifiedlog` (Keychain or user login post-access)
  - *Tune:* `KeychainToolAccess` — Monitor unexpected use of security CLI or Keychain helper binaries; `FileTypeList` — Add or remove watched file types based on system usage
- **`AN0859` Analytic 0859** · Containers
  Container processes accessing mounted secrets or configuration paths (e.g., /run/secrets, /mnt/config) followed by network access or credential use.
  - *Log sources:* `ebpf:syscalls` (open/read on secret mount paths); `kubernetes:audit` (process execution involving curl, grep, or awk on secrets); `cni:netflow` (outbound connection to internal or external APIs)
  - *Tune:* `SecretMountPaths` — Customize based on deployment structure (e.g., /mnt/, /run/secrets/); `ProcessBaselineDeviation` — Tune anomaly scoring for container image deviations
- **`AN0860` Analytic 0860** · IaaS
  Access to local credential/config files (e.g., ~/.aws/credentials) followed by metadata API calls or cloud role assumptions.
  - *Log sources:* `CloudTrail:GetObject` (sensitive credential files in buckets or local image storage); `AWS:CloudTrail` (command-line execution invoking credential enumeration); `AWS:CloudTrail` (sudden role assumption after credential file access)
  - *Tune:* `CredentialFilePattern` — Regex to match common credential files (e.g., *.aws/credentials, token.txt); `RoleAssumptionScope` — Adjust scope of roles monitored (e.g., admin, service accounts); `TimeWindow` — Correlation timing between file access and AssumeRole

---

### T1552.002 — Credentials in Registry
<a id="t1552002"></a>

**Detection strategy:** Detect Credential Discovery via Windows Registry Enumeration (`DET0250`)  
**Platforms:** Windows  
**ATT&CK:** [T1552.002](https://attack.mitre.org/techniques/T1552/002/) · [detail page](../../techniques/credential-access.md#t1552002)

- **`AN0694` Analytic 0694** · Windows
  Defenders observe command-line executions or API-based registry reads targeting sensitive paths like HKLM or HKCU with keyword filters such as 'password', 'cred', or 'logon'. Typically performed by Reg.exe, PowerShell, custom binaries, or offensive tools such as Cobalt Strike. Correlation with process ancestry and command-line arguments indicates suspicious credential discovery activity.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=13, 14); `EDR:hunting` (Behavioral rule for registry enumeration under credential-related paths)
  - *Tune:* `KeywordMatch` — List of strings searched in registry queries (e.g., password, credential, login). May need to expand for localized OS or app-specific terms.; `ParentProcessFilter` — Parent process used for registry access. Can tune for suspicious ancestry (e.g., cmd.exe > reg.exe vs. services.exe > reg.exe).; `TimeWindow` — Time-based correlation window for detecting chained activity between registry reads and subsequent credential use or exfiltration.; `RegistryHiveScope` — HKLM vs. HKCU vs. others. May limit scope to user or system context depending on risk appetite.

---

### T1552.003 — Shell History
<a id="t1552003"></a>

**Detection strategy:** Detect Access and Parsing of .bash_history Files for Credential Harvesting (`DET0385`)  
**Platforms:** Linux, macOS  
**ATT&CK:** [T1552.003](https://attack.mitre.org/techniques/T1552/003/) · [detail page](../../techniques/credential-access.md#t1552003)

- **`AN1085` Analytic 1085** · Linux
  A process outside of interactive shell context reads ~/.bash_history directly (e.g., using cat, less, grep), often shortly after privilege escalation or user switch (su/sudo). This may be followed by credential scanning in memory or file writes to new locations.
  - *Log sources:* `auditd:SYSCALL` (open/read access to ~/.bash_history); `auditd:EXECVE` (cat|less|grep accessing .bash_history from a non-shell process); `auditd:SYSCALL` (write or create file after .bash_history access)
  - *Tune:* `UserContext` — Filter by users with elevated privileges or service accounts; `TimeWindow` — Correlate access to .bash_history within X seconds of user switch or privilege escalation; `ProcessNamePatterns` — Add/remove CLI utilities used to read bash history
- **`AN1086` Analytic 1086** · macOS
  A process or terminal command outside of standard shell utilities reads the user's .bash_history file. On macOS, unified logs or telemetry tools like EndpointSecurity (ESF) may observe file read APIs or terminal process lineage that shows non-user-initiated access.
  - *Log sources:* `macos:endpointsecurity` (open or read syscall to ~/.bash_history); `macos:unifiedlog` (non-shell process tree accessing bash history)
  - *Tune:* `ParentProcessCheck` — Scope access to .bash_history only if parent is not Terminal.app or bash/zsh; `AccessFrequency` — Raise priority if .bash_history is accessed multiple times in short window

---

### T1552.004 — Private Keys
<a id="t1552004"></a>

**Detection strategy:** Detect Suspicious Access to Private Key Files and Export Attempts Across Platforms (`DET0549`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1552.004](https://attack.mitre.org/techniques/T1552/004/) · [detail page](../../techniques/credential-access.md#t1552004)

- **`AN1516` Analytic 1516** · Windows
  A process (non-system or user-initiated) accesses private key files in user profile paths or system certificate stores followed by potential network connections or compression activity.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Security` (EventCode=5145); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `FilePathRegex` — Regex for matching key file extensions (.pem, .pfx, .ppk, etc.) or known certificate directories like C:\Users\*\.ssh\; `ParentProcessName` — Set of known benign certificate management tools to exclude (e.g., certutil.exe, ssh.exe)
- **`AN1517` Analytic 1517** · Linux
  User or script-based access to ~/.ssh or other directories containing private keys followed by unusual shell activity or network connections.
  - *Log sources:* `auditd:SYSCALL` (openat); `auditd:EXECVE` (execve)
  - *Tune:* `FilePathRegex` — Directory/file path regex for ~/.ssh, *.pem, *.key, *.p12; `CommandLineMatch` — Script or user agent seen accessing keys (e.g., cat ~/.ssh/id_rsa, tar ~/.gnupg)
- **`AN1518` Analytic 1518** · macOS
  Access to user private key directories (e.g., /Users/*/.ssh) via Terminal, scripting engines, or non-default processes.
  - *Log sources:* `macos:unifiedlog` (open/read access to private key files (id_rsa, *.pem, *.p12)); `macos:unifiedlog` (launch of bash/zsh/python/osascript targeting key file locations)
  - *Tune:* `ProcessName` — Processes reading key files (osascript, python, bash, etc.); `FileAccessPath` — Private key and certificate paths like /Users/*/.ssh, /Library/Keychains/
- **`AN1519` Analytic 1519** · Network Devices
  CLI-based export of private key material (e.g., 'crypto pki export') with anomalous user session or AAA role escalation.
  - *Log sources:* `networkdevice:syslog` (Detected CLI command to export key material)
  - *Tune:* `CLICommandMatch` — Regex for export commands (e.g., crypto pki export, export ssh-key); `AAAUserContext` — Source username or role performing export — may tune for known admins

---

### T1552.005 — Cloud Instance Metadata API
<a id="t1552005"></a>

**Detection strategy:** Detect Access to Cloud Instance Metadata API (IaaS) (`DET0001`)  
**Platforms:** IaaS  
**ATT&CK:** [T1552.005](https://attack.mitre.org/techniques/T1552/005/) · [detail page](../../techniques/credential-access.md#t1552005)

- **`AN0001` Analytic 0001** · IaaS
  Detects access attempts to cloud instance metadata endpoints (e.g., 169.254.169.254) from virtual machines or containerized workloads. This includes both direct access and SSRF exploitation patterns.
  - *Log sources:* `AWS:VPCFlowLogs` (Outbound connection to 169.254.169.254 from EC2 workload); `AWS:CloudTrail` (GetInstanceIdentityDocument); `ebpf:syscalls` (Process within container accesses link-local address 169.254.169.254)
  - *Tune:* `TimeWindow` — Adjust temporal window for correlation of access attempts and SSRF triggers; `UserContext` — Tune based on expected roles that access metadata APIs (e.g., root, service accounts); `RequestHeaderMatch` — Customize detection for HTTP Host headers indicating SSRF

---

### T1552.006 — Group Policy Preferences
<a id="t1552006"></a>

**Detection strategy:** Detect Access and Decryption of Group Policy Preference (GPP) Credentials in SYSVOL (`DET0381`)  
**Platforms:** Windows  
**ATT&CK:** [T1552.006](https://attack.mitre.org/techniques/T1552/006/) · [detail page](../../techniques/credential-access.md#t1552006)

- **`AN1075` Analytic 1075** · Windows
  Correlates file enumeration of XML files in the SYSVOL share with suspicious process execution that decodes or reads encrypted credentials embedded in Group Policy Preference files (e.g., Get-GPPPassword.ps1, gpprefdecrypt.py, Metasploit). Detects abnormal access to \DOMAIN\SYSVOL combined with XML file parsing or decryption logic.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Security` (EventCode=5145); `WinEventLog:PowerShell` (Scripts with references to XML parsing, AES decryption, or gpprefdecrypt logic)
  - *Tune:* `UserContext` — Tune to exclude authorized admin users or domain controllers accessing SYSVOL; `TimeWindow` — Adjust for correlation timing between file access and script execution; `KnownToolsSignature` — Extend to include known GPP parsing tool names or script hashes; `HostType` — Distinguish between expected access from DCs vs. lateral movement from workstations

---

### T1552.007 — Container API
<a id="t1552007"></a>

**Detection strategy:** Detect Abuse of Container APIs for Credential Access (`DET0198`)  
**Platforms:** Containers  
**ATT&CK:** [T1552.007](https://attack.mitre.org/techniques/T1552/007/) · [detail page](../../techniques/credential-access.md#t1552007)

- **`AN0571` Analytic 0571** · Containers
  Detection correlates anomalous Docker or Kubernetes API requests with access to logs, secrets, or service accounts. Observes unauthorized use of `docker logs`, `kubectl get secrets`, or direct API calls to Kubernetes API server endpoints. Identifies behavioral patterns where adversaries escalate from basic pod/container interaction to privileged API calls exposing sensitive credential material.
  - *Log sources:* `docker:api` (docker logs access or container inspect commands from non-administrative users); `kubernetes:apiserver` (get/list requests to /api/v1/secrets or /api/v1/namespaces/*/serviceaccounts); `kubernetes:apiserver` (exec into pod followed by secret retrieval via API); `kubernetes:orchestrator` (Access to orchestrator logs containing credentials (Docker/Kubernetes logs))
  - *Tune:* `UserContext` — Tune to exclude known orchestrator admin service accounts or CI/CD pipelines that legitimately access secrets; `NamespaceScope` — Restrict detection to sensitive namespaces (e.g., kube-system, production apps); `TimeWindow` — Adjust correlation timing between pod execution and subsequent API secret retrieval; `SourceIP` — Filter based on allowed internal API calls vs anomalous external or cross-cluster access

---

### T1552.008 — Chat Messages
<a id="t1552008"></a>

**Detection strategy:** Detect Unsecured Credentials Shared in Chat Messages (`DET0111`)  
**Platforms:** Office Suite, SaaS  
**ATT&CK:** [T1552.008](https://attack.mitre.org/techniques/T1552/008/) · [detail page](../../techniques/credential-access.md#t1552008)

- **`AN0309` Analytic 0309** · Office Suite
  Detection correlates message events in email and collaboration tools (e.g., Outlook, Teams) that contain regex-like patterns resembling credentials, API keys, or tokens. Anomalous forwarding or bulk copy activity of chat/email content containing secrets is flagged. Suspicious behavior includes users pasting secrets into direct messages or attaching config files with passwords.
  - *Log sources:* `m365:unified` (MessageSend, MessageRead, or FileAttached events containing credential-like patterns)
  - *Tune:* `RegexPatterns` — Customizable credential-detection regex (e.g., API_KEY=, bearer token formats) depending on enterprise apps in use; `AllowedDomains` — Exclude known trusted domains or automated system-to-system messages; `TimeWindow` — Adjust correlation period for bulk credential sharing events
- **`AN0310` Analytic 0310** · SaaS
  Detection monitors SaaS collaboration tools (e.g., Slack, Zoom, Jira) for messages or files containing credential-like patterns, or for suspicious API calls retrieving bulk chat histories by non-admin users. Identifies adversary behavior chains where chat logs are queried via APIs or integration bots to systematically extract sensitive material.
  - *Log sources:* `saas:slack` (chat.postMessage, files.upload, or discovery API calls involving token/credential regex); `saas:okta` (Unusual OAuth app requesting message-read scopes for Slack/Teams/Jira)
  - *Tune:* `IntegrationScope` — Tune to ignore known enterprise bots with message-read access (e.g., DLP scanners); `RegexPatterns` — Customizable regex for detecting secret formats (JWT, OAuth tokens, SSH keys); `UserContext` — Correlate with user role to filter developers vs standard users

---

### T1555 — Credentials from Password Stores
<a id="t1555"></a>

**Detection strategy:** Detect Credentials Access from Password Stores (`DET0430`)  
**Platforms:** IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1555](https://attack.mitre.org/techniques/T1555/) · [detail page](../../techniques/credential-access.md#t1555)

- **`AN1198` Analytic 1198** · Windows
  Monitors suspicious access to password stores such as LSASS, DPAPI, Windows Credential Manager, or browser credential databases. Detects anomalous process-to-process access (e.g., Mimikatz accessing LSASS) and correlation of credential store file reads with execution of non-standard processes.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `TargetProcesses` — List of sensitive processes to monitor (e.g., lsass.exe, svchost.exe); `KeywordPatterns` — Regex for suspicious command-line arguments such as 'dpapi', 'credman', 'mimikatz'
- **`AN1199` Analytic 1199** · Linux
  Detects access to known password store files (e.g., /etc/shadow, GNOME Keyring, KWallet, browser credential databases). Monitors anomalous process read attempts and suspicious API calls that attempt to extract stored credentials.
  - *Log sources:* `auditd:SYSCALL` (open/read); `auditd:EXECVE` (execve)
  - *Tune:* `MonitoredFiles` — Paths to password storage files (e.g., /etc/shadow, ~/.local/share/keyrings/); `SuspiciousCommands` — Process or command-line keywords that indicate password extraction attempts
- **`AN1200` Analytic 1200** · macOS
  Monitors Keychain database access and suspicious invocations of security and osascript utilities. Correlates process execution with attempts to dump or unlock Keychain data.
  - *Log sources:* `macos:unifiedlog` (access to keychain database); `macos:unifiedlog` (execution of security or osascript)
  - *Tune:* `AllowedApplications` — Whitelist of legitimate processes accessing the Keychain; `AlertThreshold` — Number of failed access attempts before raising an alert
- **`AN1201` Analytic 1201** · IaaS
  Detects attempts to access or enumerate cloud password/secrets storage services such as AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager. Monitors API calls for abnormal enumeration or bulk retrieval of secrets.
  - *Log sources:* `AWS:CloudTrail` (GetSecretValue); `AWS:CloudTrail` (Decrypt)
  - *Tune:* `UserContext` — Correlate cloud API calls with IAM role, user, or service account context; `AccessThreshold` — Number of secret retrievals within a time window before flagging

---

### T1555.001 — Keychain
<a id="t1555001"></a>

**Detection strategy:** Detect Access to macOS Keychain for Credential Theft (`DET0396`)  
**Platforms:** macOS  
**ATT&CK:** [T1555.001](https://attack.mitre.org/techniques/T1555/001/) · [detail page](../../techniques/credential-access.md#t1555001)

- **`AN1112` Analytic 1112** · macOS
  Detects suspicious access to macOS Keychain files and APIs. Observes processes invoking the 'security' utility or accessing Keychain databases directly, correlates these with abnormal parent process lineage or unexpected user context. Monitors attempts to dump, unlock, or read credential storage beyond normal application workflows.
  - *Log sources:* `macos:unifiedlog` (execution of security or osascript); `macos:unifiedlog` (access or unlock attempt to keychain database); `macos:unifiedlog` (read access to ~/Library/Keychains/login.keychain-db)
  - *Tune:* `AllowedApplications` — Whitelist of applications (e.g., Safari, Mail) normally permitted to access Keychain; `AlertThreshold` — Number of failed keychain unlock attempts before raising an alert; `ParentProcessContext` — Legitimate parent-child process relationships for security tool invocations

---

### T1555.002 — Securityd Memory
<a id="t1555002"></a>

**Detection strategy:** Detect Suspicious Access to securityd Memory for Credential Extraction (`DET0057`)  
**Platforms:** Linux, macOS  
**ATT&CK:** [T1555.002](https://attack.mitre.org/techniques/T1555/002/) · [detail page](../../techniques/credential-access.md#t1555002)

- **`AN0156` Analytic 0156** · macOS
  Detects suspicious memory access attempts targeting the `securityd` process. Observes tools invoking process memory read operations (e.g., ptrace, task_for_pid) against `securityd`. Correlates with anomalous parent process lineage, root privilege escalation, or repeated unauthorized attempts.
  - *Log sources:* `macos:unifiedlog` (ptrace or task_for_pid); `macos:unifiedlog` (execution of memory inspection tools (lldb, gdb, osqueryi))
  - *Tune:* `AllowedDebuggers` — List of authorized debugging tools permitted in dev/test environments; `TimeWindow` — Correlation period between memory inspection and Keychain API access; `PrivilegedUsers` — Expected set of admin accounts with legitimate debugging permissions
- **`AN0157` Analytic 0157** · Linux
  Detects adversaries attempting to attach debuggers or memory dump utilities to credential storage daemons analogous to macOS `securityd`. Observes ptrace syscalls, /proc/<pid>/mem access, or gcore dumps against sensitive processes. Correlates anomalies with privilege escalation or credential dumping attempts.
  - *Log sources:* `auditd:SYSCALL` (ptrace attach); `auditd:FILE` (/proc/*/mem read attempt); `auditd:EXECVE` (gcore, gdb, strings, hexdump execution)
  - *Tune:* `MonitoredProcesses` — List of credential storage daemons (e.g., securityd, gnome-keyring, kwallet) monitored for memory access attempts; `CorrelationDepth` — Defines how many chained events (process execution + syscall + file read) to correlate before raising an alert; `PrivilegeContext` — Expected user/group context for processes allowed to access protected memory

---

### T1555.003 — Credentials from Web Browsers
<a id="t1555003"></a>

**Detection strategy:** Detect Suspicious Access to Browser Credential Stores (`DET0037`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1555.003](https://attack.mitre.org/techniques/T1555/003/) · [detail page](../../techniques/credential-access.md#t1555003)

- **`AN0105` Analytic 0105** · Windows
  Detects unauthorized access to web browser credential stores (e.g., Chrome Login Data, Edge Credential Locker) by processes other than the browser itself. Correlates file reads of credential databases with subsequent API calls to `CryptUnprotectData` or memory inspection attempts.
  - *Log sources:* `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `MonitoredPaths` — Browser-specific credential storage paths such as Chrome Login Data, IE Credential Locker; `TimeWindow` — Correlation window between file read and process memory/API access
- **`AN0106` Analytic 0106** · Linux
  Detects attempts to access browser credential stores (e.g., Firefox `logins.json`, Chrome SQLite DB) or processes (e.g., gnome-keyring-daemon). Observes unauthorized file reads and memory inspection of browser processes using ptrace or gdb.
  - *Log sources:* `auditd:FILE` (/home/*/.mozilla/firefox/*/logins.json OR /home/*/.config/google-chrome/*/Login Data); `auditd:SYSCALL` (ptrace attach)
  - *Tune:* `BrowserCredentialFiles` — Paths of web browser credential databases to monitor; `AllowedDebuggers` — List of expected debugging tools for dev/test environments
- **`AN0107` Analytic 0107** · macOS
  Detects abnormal access to Safari credential stores (Keychain-backed) or Chrome/Firefox login databases. Observes processes executing `security dump-keychain` or directly reading credential files in `~/Library/Application Support`. Correlates file access with suspicious process ancestry or unsigned binaries.
  - *Log sources:* `macos:unifiedlog` (execution of security, sqlite3, or unauthorized binaries); `macos:unifiedlog` (~/Library/Application Support/Google/Chrome/*/Login Data OR ~/Library/Application Support/Firefox/*/logins.json)
  - *Tune:* `PrivilegedUsers` — Expected user context authorized to unlock Keychain or browser databases; `TimeWindow` — Correlation window for process execution and credential file access

---

### T1555.004 — Windows Credential Manager
<a id="t1555004"></a>

**Detection strategy:** Detect Suspicious Access to Windows Credential Manager (`DET0134`)  
**Platforms:** Windows  
**ATT&CK:** [T1555.004](https://attack.mitre.org/techniques/T1555/004/) · [detail page](../../techniques/credential-access.md#t1555004)

- **`AN0378` Analytic 0378** · Windows
  Detects unauthorized access to Windows Credential Manager through anomalous process execution (vaultcmd.exe, rundll32.exe keymgr.dll), suspicious API calls (CredEnumerateA), or direct file access to Credential Locker files. Correlates process creation with subsequent file reads of .vcrd/.vpol files under user Credential Locker directories.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=15)
  - *Tune:* `MonitoredPaths` — Credential Locker paths such as %Systemdrive%\Users\*\AppData\Local\Microsoft\Credentials and %Systemdrive%\Users\*\AppData\Local\Microsoft\Vault; `TimeWindow` — Correlation window between process execution, file access, and API calls; `PrivilegedUsers` — Baseline of expected administrative/service accounts with legitimate Credential Manager access

---

### T1555.005 — Password Managers
<a id="t1555005"></a>

**Detection strategy:** Detect Unauthorized Access to Password Managers (`DET0597`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1555.005](https://attack.mitre.org/techniques/T1555/005/) · [detail page](../../techniques/credential-access.md#t1555005)

- **`AN1641` Analytic 1641** · Windows
  Detection of suspicious access to password manager processes (KeePass, 1Password, LastPass, Bitwarden) through abnormal process injection, memory reads, or command-line usage of vault-related DLLs. Correlates process creation with OS API calls and file access to vault databases (.kdbx, .opvault, .ldb).
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=15)
  - *Tune:* `PasswordManagerBinaries` — List of monitored binaries and file formats for password managers in use (e.g., KeePass, 1Password, Bitwarden, LastPass).; `TimeWindow` — Window to correlate process creation, API access, and file reads indicative of credential extraction.; `UserContext` — Filter for administrative accounts vs. expected users of password managers.
- **`AN1642` Analytic 1642** · Linux
  Suspicious access to password manager vaults (KeePassXC, gnome-keyring, pass) via memory scraping or unauthorized file reads. Detects unusual command execution involving gdb/strace attached to password manager processes.
  - *Log sources:* `auditd:SYSCALL` (open/read on ~/.local/share/keepassxc/* OR ~/.password-store/*); `auditd:SYSCALL` (ptrace)
  - *Tune:* `VaultFilePaths` — Linux paths to monitor for vault database files (KeePassXC, pass, gnome-keyring).; `TimeWindow` — Correlation interval to detect multiple suspicious access events.
- **`AN1643` Analytic 1643** · macOS
  Detection of password manager database access (1Password .opvault, LastPass caches, KeePass .kdbx) outside expected parent processes. Identifies memory scraping attempts via suspicious API calls or tools attaching to password manager processes.
  - *Log sources:* `macos:unifiedlog` (security OR injection attempts into 1Password OR LastPass); `macos:unifiedlog` (*.opvault OR *.ldb OR *.kdbx); `macos:osquery` (unexpected memory inspection)
  - *Tune:* `VaultFileExtensions` — Password manager file extensions (.opvault, .kdbx, .ldb) to monitor for anomalous access.; `ParentProcessWhitelist` — Expected parent processes that normally access password manager files, for filtering false positives.

---

### T1555.006 — Cloud Secrets Management Stores
<a id="t1555006"></a>

**Detection strategy:** Detect Unauthorized Access to Cloud Secrets Management Stores (`DET0130`)  
**Platforms:** IaaS  
**ATT&CK:** [T1555.006](https://attack.mitre.org/techniques/T1555/006/) · [detail page](../../techniques/credential-access.md#t1555006)

- **`AN0366` Analytic 0366** · IaaS
  Detection of suspicious access to cloud-native secret management systems (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault). Focuses on abnormal secret retrieval activity, such as secrets being accessed by unusual identities, from unexpected regions, outside business hours, or at high volume. Correlates API calls to secret retrieval with surrounding authentication events, role assumptions, and anomalous execution patterns.
  - *Log sources:* `AWS:CloudTrail` (GetSecretValue)
  - *Tune:* `PrivilegedRoles` — Set of accounts or roles allowed to retrieve secrets; deviations may indicate misuse.; `TimeWindow` — Temporal window to correlate secret access with authentication and anomalous context.; `AccessPatterns` — Expected frequency and volume of secret retrievals per user/service; anomalies may indicate exfiltration.; `RegionConstraints` — Regions in which secret access is expected; access from unusual geographies may indicate compromise.

---

### T1556 — Modify Authentication Process
<a id="t1556"></a>

**Detection strategy:** Detect Modification of Authentication Processes Across Platforms (`DET0104`)  
**Platforms:** IaaS, Identity Provider, Linux, Windows, macOS  
**ATT&CK:** [T1556](https://attack.mitre.org/techniques/T1556/) · [detail page](../../techniques/credential-access.md#t1556)

- **`AN0287` Analytic 0287** · Windows
  Detects modification of LSASS and authentication DLLs, suspicious registry changes to password filter packages, and abnormal process access to lsass.exe. Correlates registry modifications, DLL loads, and process handle access events.
  - *Log sources:* `WinEventLog:Security` (EventCode=4657); `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `MonitoredRegistryKeys` — Specific LSASS and password filter registry paths monitored for modification.; `TimeWindow` — Correlation window between registry change, DLL load, and lsass.exe access.
- **`AN0288` Analytic 0288** · Linux
  Detects modification of PAM configuration files, unauthorized new PAM modules, and suspicious process execution accessing PAM-related binaries. Correlates file modification events in /etc/pam.d/ with process execution of unauthorized binaries.
  - *Log sources:* `auditd:SYSCALL` (open, write); `auditd:SYSCALL` (execve)
  - *Tune:* `WatchedPaths` — Critical PAM directories and configuration files monitored for modification.
- **`AN0289` Analytic 0289** · macOS
  Detects unauthorized additions or changes to /Library/Security/SecurityAgentPlugins and suspicious process activity attempting to hook authentication APIs. Correlates file modifications with abnormal plugin loads in authentication flows.
  - *Log sources:* `macos:unifiedlog` (SecurityAgentPlugins modification); `macos:osquery` (process_open)
  - *Tune:* `PluginPaths` — List of approved authentication plugin directories to baseline.
- **`AN0290` Analytic 0290** · Identity Provider
  Detects suspicious configuration changes in IdP authentication flows such as enabling reversible password encryption, MFA bypass, or policy weakening. Correlates policy modification events with unusual administrative activity.
  - *Log sources:* `azure:policy` (UpdatePolicy); `m365:unified` (Set-ADUser OR Set-ADAccountControl)
  - *Tune:* `PolicyBaseline` — Expected authentication-related policy configurations to compare against.
- **`AN0291` Analytic 0291** · IaaS
  Detects unauthorized changes to IAM authentication configurations such as disabling MFA, creating backdoor access keys, or altering trust policies. Correlates identity policy updates with unusual login behavior.
  - *Log sources:* `AWS:CloudTrail` (UpdateLoginProfile); `AWS:CloudTrail` (UpdateAccountPasswordPolicy)
  - *Tune:* `ApprovedAccounts` — Baseline list of service accounts expected to modify IAM authentication policies.

---

### T1556.001 — Domain Controller Authentication
<a id="t1556001"></a>

**Detection strategy:** Detect Domain Controller Authentication Process Modification (Skeleton Key) (`DET0271`)  
**Platforms:** Windows  
**ATT&CK:** [T1556.001](https://attack.mitre.org/techniques/T1556/001/) · [detail page](../../techniques/credential-access.md#t1556001)

- **`AN0757` Analytic 0757** · Windows
  Detects anomalous process access to LSASS on domain controllers, suspicious module loads of authentication DLLs, and registry or file modifications indicative of Skeleton Key–style patching. Correlates LSASS access attempts with subsequent abnormal logon activity patterns.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Security` (EventCode=4624, 4648); `WinEventLog:System` (Unexpected modification to lsass.exe or cryptdll.dll)
  - *Tune:* `MonitoredDLLs` — Specific authentication DLLs such as cryptdll.dll and samsrv.dll monitored for tampering.; `TimeWindow` — Correlation window between LSASS memory access, module load, and suspicious logons.; `UserContext` — Baseline expected accounts performing domain controller logon operations.

---

### T1556.002 — Password Filter DLL
<a id="t1556002"></a>

**Detection strategy:** Detect Malicious Password Filter DLL Registration (`DET0472`)  
**Platforms:** Windows  
**ATT&CK:** [T1556.002](https://attack.mitre.org/techniques/T1556/002/) · [detail page](../../techniques/credential-access.md#t1556002)

- **`AN1303` Analytic 1303** · Windows
  Detects suspicious registration of new password filter DLLs into the authentication process. Correlates registry modifications to LSASS Notification Packages with subsequent DLL creation and loading events. Observes anomalous file placement of DLLs in system directories followed by LSASS loading the new filter during logon/password change activity.
  - *Log sources:* `WinEventLog:Security` (EventCode=4657); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `RegistryPath` — Specific registry path monitored for modification (e.g., HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages).; `AllowedDLLs` — Known and approved password filter DLLs; deviations from baseline may indicate malicious injection.; `TimeWindow` — Time window for correlating registry modification, file creation, and module load events.; `FilePathPatterns` — Expected directories for legitimate password filter DLLs; anomalous paths may signal compromise.

---

### T1556.003 — Pluggable Authentication Modules
<a id="t1556003"></a>

**Detection strategy:** Detect Malicious Modification of Pluggable Authentication Modules (PAM) (`DET0454`)  
**Platforms:** Linux, macOS  
**ATT&CK:** [T1556.003](https://attack.mitre.org/techniques/T1556/003/) · [detail page](../../techniques/credential-access.md#t1556003)

- **`AN1250` Analytic 1250** · Linux
  Detects unauthorized modifications to PAM configuration files or shared object modules. Correlates file modification events under /etc/pam.d/ or /lib/security/ with unusual authentication activity such as multiple simultaneous logins, off-hours logins, or logons without corresponding physical/VPN access.
  - *Log sources:* `auditd:SYSCALL` (open, write); `auditd:SYSCALL` (execve); `NSM:Connections` (simultaneous or anomalous logon sessions across multiple systems)
  - *Tune:* `MonitoredPaths` — List of PAM configuration and module directories monitored (e.g., /etc/pam.d/, /lib/security/).; `TimeWindow` — Timeframe for correlating suspicious file modifications with anomalous login events.; `BaselineAccounts` — Expected login frequency and systems per user account; deviations may indicate compromise.
- **`AN1251` Analytic 1251** · macOS
  Detects suspicious changes to macOS authorization and PAM plugin files. Correlates file modifications under /etc/pam.d/ or /Library/Security/SecurityAgentPlugins with unexpected authentication attempts or anomalous account usage.
  - *Log sources:* `macos:unifiedlog` (authentication plugin load or modification events); `macos:osquery` (write)
  - *Tune:* `WatchedPlugins` — Expected set of PAM and authorization plugins; unknown additions may indicate malicious insertion.; `CorrelatedSources` — Cross-correlation with VPN/physical access logs to identify impossible or anomalous login patterns.

---

### T1556.004 — Network Device Authentication
<a id="t1556004"></a>

**Detection strategy:** Detect Modification of Network Device Authentication via Patched System Images (`DET0272`)  
**Platforms:** Network Devices  
**ATT&CK:** [T1556.004](https://attack.mitre.org/techniques/T1556/004/) · [detail page](../../techniques/credential-access.md#t1556004)

- **`AN0758` Analytic 0758** · Network Devices
  Detects unauthorized modification of network device authentication by correlating OS image file changes, checksum mismatches, or memory verification failures with anomalous authentication events. Focus is on behaviors where patched images introduce hardcoded passwords or bypass native authentication.
  - *Log sources:* `networkconfig` (unexpected OS image file upload or modification events); `network:auth` (repeated successful authentications with previously unknown accounts or anomalous password acceptance)
  - *Tune:* `BaselineChecksums` — Trusted baseline cryptographic hashes for OS images, used to detect unauthorized modifications.; `AuthFailureThreshold` — Threshold for correlating unusual authentication successes following failed attempts or unknown account use.; `VerificationInterval` — Frequency of runtime OS image and memory integrity checks.

---

### T1556.005 — Reversible Encryption
<a id="t1556005"></a>

**Detection strategy:** Detect Modification of Authentication Process via Reversible Encryption (`DET0589`)  
**Platforms:** Windows  
**ATT&CK:** [T1556.005](https://attack.mitre.org/techniques/T1556/005/) · [detail page](../../techniques/credential-access.md#t1556005)

- **`AN1621` Analytic 1621** · Windows
  Detects enabling of reversible password encryption in Active Directory or Group Policy, suspicious PowerShell commands modifying AD user properties, and unusual account configuration changes correlated with policy modifications. Multi-event correlation links Group Policy edits, PowerShell command execution, and user account property changes to identify tampering with authentication encryption settings.
  - *Log sources:* `WinEventLog:Security` (EventCode=4739); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106)
  - *Tune:* `MonitoredOUs` — Scope of Organizational Units where reversible encryption property monitoring is enabled.; `TimeWindow` — Time window in which to correlate Group Policy modification and subsequent user property changes.; `SuspiciousCmdletList` — List of PowerShell cmdlets to monitor for account configuration changes.

---

### T1556.006 — Multi-Factor Authentication
<a id="t1556006"></a>

**Detection strategy:** Detect MFA Modification or Disabling Across Platforms (`DET0190`)  
**Platforms:** IaaS, Identity Provider, Linux, Office Suite, SaaS, Windows, macOS  
**ATT&CK:** [T1556.006](https://attack.mitre.org/techniques/T1556/006/) · [detail page](../../techniques/credential-access.md#t1556006)

- **`AN0543` Analytic 0543** · Windows
  Detects registry and Group Policy modifications that disable or weaken MFA, suspicious PowerShell usage modifying MFA-related attributes, and anomalous login sessions succeeding without expected MFA challenge.
  - *Log sources:* `WinEventLog:Security` (EventCode=4739); `WinEventLog:PowerShell` (Set-ADUser or Set-ADAuthenticationPolicy with MFA attributes disabled)
  - *Tune:* `WatchedAttributes` — List of AD attributes or policy fields tied to MFA enforcement that may vary by organization.; `TimeWindow` — Correlation window between MFA policy changes and anomalous login behavior.
- **`AN0544` Analytic 0544** · Identity Provider
  Detects conditional access policy changes, exclusion of accounts from MFA enforcement, or registration of new MFA factors by non-admin or anomalous users.
  - *Log sources:* `azure:signinlogs` (Modify Conditional Access Policy); `m365:unified` (User excluded from MFA or MFA method registered)
  - *Tune:* `PrivilegedRoles` — Roles permitted to modify MFA settings in IdP; helps tune detection of unauthorized changes.
- **`AN0545` Analytic 0545** · IaaS
  Detects API calls to cloud secrets/MFA configurations where MFA enforcement policies are disabled or bypassed.
  - *Log sources:* `AWS:CloudTrail` (UpdateIdentityPolicy or DisableMFA)
  - *Tune:* `MonitoredServices` — Specific cloud services or IAM policies relevant to MFA enforcement.
- **`AN0546` Analytic 0546** · Linux
  Detects PAM module modifications or removal of MFA hooks in /etc/pam.d/ configurations, correlated with successful authentications lacking MFA prompts.
  - *Log sources:* `auditd:SYSCALL` (open/write to /etc/pam.d/*); `NSM:Connections` (Successful login without expected MFA challenge)
  - *Tune:* `MFAHooks` — Paths to organization-specific PAM modules enforcing MFA.
- **`AN0547` Analytic 0547** · macOS
  Detects modifications to authorization plugins responsible for MFA enforcement and correlates with suspicious login sessions missing MFA prompts.
  - *Log sources:* `macos:unifiedlog` (Modification of /Library/Security/SecurityAgentPlugins); `macos:unifiedlog` (Login success without MFA step)
  - *Tune:* `WatchedPluginPaths` — Paths to organization-deployed MFA authorization plugins.
- **`AN0548` Analytic 0548** · SaaS
  Detects suspicious MFA method changes, such as registration of weaker factors (e.g., SMS), or removal of MFA requirements for specific accounts or groups.
  - *Log sources:* `saas:zoom` (DisableMFA or RegisterNewFactor)
  - *Tune:* `AcceptedFactors` — Configured MFA factors allowed in SaaS environment; tuned to organizational policies.
- **`AN0549` Analytic 0549** · Office Suite
  Detects MFA bypass attempts by modifying tenant-wide authentication policies or excluding high-value accounts from MFA enforcement.
  - *Log sources:* `m365:unified` (Set-CsOnlineUser or UpdateAuthPolicy)
  - *Tune:* `MonitoredPolicies` — Specific tenant or suite policies tied to MFA enforcement.

---

### T1556.007 — Hybrid Identity
<a id="t1556007"></a>

**Detection strategy:** Detect Hybrid Identity Authentication Process Modification (`DET0293`)  
**Platforms:** IaaS, Identity Provider, Office Suite, SaaS, Windows  
**ATT&CK:** [T1556.007](https://attack.mitre.org/techniques/T1556/007/) · [detail page](../../techniques/credential-access.md#t1556007)

- **`AN0814` Analytic 0814** · Windows
  Detects injection or tampering of DLLs in hybrid identity agents (e.g., AzureADConnectAuthenticationAgentService), registry or configuration changes tied to PTA/AD FS, and anomalous LSASS or AD FS module loads correlated with authentication anomalies.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Security` (EventCode=5136); `WinEventLog:Security` (Anomalous logon without MFA enforcement)
  - *Tune:* `WatchedServices` — Hybrid identity services monitored for tampering, e.g., PTA agent, AD FS.; `TimeWindow` — Window correlating DLL/module load events with logon anomalies.
- **`AN0815` Analytic 0815** · Identity Provider
  Detects registration of new PTA agents, conditional access changes disabling hybrid MFA enforcement, or suspicious updates to AD FS token-signing configurations.
  - *Log sources:* `azure:signinlogs` (Register PTA Agent or Modify AD FS trust); `m365:unified` (New agent registration by non-admin user)
  - *Tune:* `PrivilegedRoles` — Roles authorized to configure PTA/AD FS integrations.
- **`AN0816` Analytic 0816** · IaaS
  Detects API calls registering or updating hybrid identity connectors, modification of cloud-to-on-premises federation trust, and unusual token issuance logs.
  - *Log sources:* `AWS:CloudTrail` (UpdateFederationSettings or RegisterHybridConnector)
  - *Tune:* `MonitoredFederations` — Federation trusts and connectors relevant to hybrid identity setup.
- **`AN0817` Analytic 0817** · Office Suite
  Detects tenant-wide authentication or conditional access changes that weaken hybrid identity enforcement, including disabling AD FS or bypassing hybrid MFA policies.
  - *Log sources:* `m365:unified` (Modify Federation Settings or Update Authentication Policy)
  - *Tune:* `PolicyScope` — Scope of authentication and federation policies to be monitored.
- **`AN0818` Analytic 0818** · SaaS
  Detects suspicious changes to SAML/OAuth federation configurations, such as new signing certificates, altered endpoints, or claims issuance rules granting elevated privileges.
  - *Log sources:* `saas:okta` (Federation configuration update or signing certificate change)
  - *Tune:* `FederationEndpoints` — Federation/SAML endpoints monitored for modification.

---

### T1556.008 — Network Provider DLL
<a id="t1556008"></a>

**Detection strategy:** Detect Network Provider DLL Registration and Credential Capture (`DET0580`)  
**Platforms:** Windows  
**ATT&CK:** [T1556.008](https://attack.mitre.org/techniques/T1556/008/) · [detail page](../../techniques/credential-access.md#t1556008)

- **`AN1598` Analytic 1598** · Windows
  Detects registration of new or modified network provider DLLs via registry changes, anomalous file creation of DLLs in system directories, and suspicious process activity (mpnotify.exe interacting with non-standard DLLs). Multi-event correlation ties registry modification events to subsequent DLL loads during user logon activity.
  - *Log sources:* `WinEventLog:Security` (EventCode=4657); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `MonitoredRegistryKeys` — Specific registry keys to monitor for DLL registration (e.g., NetworkProvider Order).; `SuspiciousDLLPaths` — Directories or file name patterns outside of normal system DLL locations.; `TimeWindow` — Window correlating registry modification, DLL creation, and subsequent logon activity.

---

### T1556.009 — Conditional Access Policies
<a id="t1556009"></a>

**Detection strategy:** Detect Conditional Access Policy Modification in Identity and Cloud Platforms (`DET0030`)  
**Platforms:** IaaS, Identity Provider  
**ATT&CK:** [T1556.009](https://attack.mitre.org/techniques/T1556/009/) · [detail page](../../techniques/credential-access.md#t1556009)

- **`AN0087` Analytic 0087** · IaaS
  Detects modifications to IAM conditions or policies that alter authentication behavior, such as adding permissive trusted IPs, removing MFA requirements, or changing regional access restrictions. Behavioral detection focuses on anomalous policy updates tied to privileged accounts and subsequent suspicious logon activity from previously blocked regions or devices.
  - *Log sources:* `AWS:CloudTrail` (PutUserPolicy, PutGroupPolicy, PutRolePolicy, CreatePolicyVersion)
  - *Tune:* `MonitoredIAMConditions` — Specific condition keys (SourceIp, RequestedRegion, MFAAuthenticated) tuned per environment.; `TimeWindow` — Correlates policy modification with follow-on logins from newly permitted sources.; `PrivilegedAccounts` — List of administrative accounts to prioritize when monitoring for conditional access changes.
- **`AN0088` Analytic 0088** · Identity Provider
  Detects suspicious updates to conditional access or MFA enforcement policies in identity providers such as Entra ID, Okta, or JumpCloud. Focus is on removal of policy blocks, addition of broad exclusions, or registration of adversary-controlled MFA methods, followed by anomalous login activity that takes advantage of the modified policies.
  - *Log sources:* `azure:activity` (Update conditionalAccessPolicy); `saas:okta` (Conditional Access policy rule modified or MFA requirement disabled)
  - *Tune:* `TargetedApplications` — Specific SaaS or cloud apps most sensitive to conditional access changes.; `RiskThresholds` — Risk scores or signals that may be tuned for anomaly detection in login behavior.; `UserContext` — Business roles or expected MFA patterns per user/group to reduce false positives.

---

### T1557 — Adversary-in-the-Middle
<a id="t1557"></a>

**Detection strategy:** Detect Adversary-in-the-Middle via Network and Configuration Anomalies (`DET0296`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1557](https://attack.mitre.org/techniques/T1557/) · [detail page](../../techniques/credential-access.md#t1557)

- **`AN0823` Analytic 0823** · Windows
  Detects suspicious DNS/ARP poisoning attempts, unauthorized modifications to registry/network configuration, or abnormal TLS downgrade activity. Correlates changes in system configuration with subsequent unusual network flows or authentication events.
  - *Log sources:* `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `MonitoredRegistryPaths` — Specific network stack and DNS registry keys that vary by enterprise configuration.; `DowngradeCipherList` — List of weak/legacy ciphers tuned per environment for TLS downgrade detection.; `TimeWindow` — Correlation period between config changes and abnormal network connections.
- **`AN0824` Analytic 0824** · Linux
  Detects unauthorized edits to /etc/hosts, /etc/resolv.conf, or suspicious ARP broadcasts. Correlates file modifications with subsequent unexpected network sessions or service creation.
  - *Log sources:* `auditd:SYSCALL` (open, write); `NSM:Flow` (Unexpected ARP replies or DNS responses inconsistent with authoritative servers)
  - *Tune:* `MonitoredFiles` — List of system files shaping traffic flow (hosts, resolv.conf, PAM modules).; `ARPThreshold` — Rate/volume thresholds for ARP/DNS anomalies tuned per subnet.
- **`AN0825` Analytic 0825** · macOS
  Detects unauthorized edits to system configuration profiles, unexpected certificate trust changes, or abnormal ARP/DNS patterns indicative of interception.
  - *Log sources:* `macos:unifiedlog` (Configuration profile modified or new profile installed); `NSM:Flow` (TLS downgrade or inconsistent DNS answers)
  - *Tune:* `ProfileIdentifiers` — Known good vs suspicious configuration profiles per enterprise baseline.; `TLSVersionThreshold` — Minimum TLS version accepted in network traffic inspection.
- **`AN0826` Analytic 0826** · Network Devices
  Detects unauthorized firmware or configuration changes enabling adversary-in-the-middle positioning (e.g., route injection, DNS spoofing, SSL downgrade). Behavioral analytics focus on sudden changes to routing tables or image file integrity failures.
  - *Log sources:* `NSM:Flow` (Unexpected route changes or duplicate gateway advertisements); `networkdevice:config` (Configuration file modified or replaced on network device)
  - *Tune:* `RoutingPolicyBaseline` — Expected routing and BGP/OSPF paths for validation.; `FirmwareChecksum` — Baseline image checksum per device type used to detect tampering.

---

### T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay
<a id="t1557001"></a>

**Detection strategy:** Detect LLMNR/NBT-NS Poisoning and SMB Relay on Windows (`DET0462`)  
**Platforms:** Windows  
**ATT&CK:** [T1557.001](https://attack.mitre.org/techniques/T1557/001/) · [detail page](../../techniques/credential-access.md#t1557001)

- **`AN1274` Analytic 1274** · Windows
  Detects anomalous network traffic on UDP 5355 (LLMNR) and UDP 137 (NBT-NS) combined with unauthorized SMB relay attempts, registry modifications re-enabling multicast name resolution, or suspicious service creation indicative of adversary-in-the-middle credential interception.
  - *Log sources:* `WinEventLog:Security` (EventCode=4697); `WinEventLog:Security` (Registry key modification HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast); `NSM:Flow` (Unusual responses to LLMNR (UDP 5355) or NBT-NS (UDP 137) queries from unauthorized hosts); `NSM:Flow` (Abnormal SMB authentication attempts correlated with poisoned LLMNR/NBT-NS sessions)
  - *Tune:* `TrustedResponderList` — Defines expected LLMNR/NBT-NS responders to tune out legitimate services.; `TimeWindow` — Correlation period for linking poisoned name resolution with SMB relay attempts.; `SMBServiceBaseline` — Normal services and SMB relay patterns in the enterprise environment.

---

### T1557.002 — ARP Cache Poisoning
<a id="t1557002"></a>

**Detection strategy:** Detect ARP Cache Poisoning Across Linux, Windows, and macOS (`DET0387`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1557.002](https://attack.mitre.org/techniques/T1557/002/) · [detail page](../../techniques/credential-access.md#t1557002)

- **`AN1091` Analytic 1091** · Windows
  Detects anomalous ARP traffic or cache modifications on Windows endpoints that indicate ARP poisoning. Behavioral focus is on multiple IP addresses resolving to a single MAC, or unsolicited ARP replies from unauthorized devices.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Security` (ARP cache modification attempts observed through event tracing or security baselines)
  - *Tune:* `TrustedGatewayMAC` — Expected MAC address for default gateways; deviations may indicate poisoning.; `TimeWindow` — Correlation interval for repeated unsolicited ARP replies.
- **`AN1092` Analytic 1092** · Linux
  Detects suspicious gratuitous ARP responses or inconsistent IP-to-MAC mappings using auditd and packet capture. Behavioral focus is on unsolicited replies overriding legitimate ARP ownership.
  - *Log sources:* `auditd:SYSCALL` (setsockopt, ioctl modifying ARP entries); `NSM:Flow` (Gratuitous ARP replies with mismatched IP-MAC binding)
  - *Tune:* `AllowedARPUpdates` — Expected legitimate IP-to-MAC updates for servers or virtual routers.; `AlertThreshold` — Number of anomalous ARP packets per second before triggering detection.
- **`AN1093` Analytic 1093** · macOS
  Detects anomalous ARP cache changes and unsolicited ARP broadcasts using unified logs and packet capture. Behavioral detection includes multiple IP addresses mapped to the same MAC address and repeated gratuitous ARP traffic.
  - *Log sources:* `macos:unifiedlog` (ARP table updates inconsistent with expected gateway or DHCP lease assignments); `NSM:Flow` (Excessive gratuitous ARP replies on local subnet)
  - *Tune:* `GatewayMACBaseline` — Known MAC addresses for gateways or DHCP servers; used to detect spoofed ARP entries.; `CorrelationDepth` — How many ARP inconsistencies to tolerate before escalating detection.

---

### T1557.003 — DHCP Spoofing
<a id="t1557003"></a>

**Detection strategy:** Detect DHCP Spoofing Across Linux, Windows, and macOS (`DET0468`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1557.003](https://attack.mitre.org/techniques/T1557/003/) · [detail page](../../techniques/credential-access.md#t1557003)

- **`AN1290` Analytic 1290** · Windows
  Detects rogue DHCP server activity and anomalous DHCP OFFER/ACK messages assigning unexpected DNS or gateway values. Detection correlates DHCP server role changes, DHCP exhaustion warnings, and sudden network configuration changes across endpoints.
  - *Log sources:* `WinEventLog:System` (EventCode=1341, 1342, 1020, 1063); `NSM:Flow` (DHCP OFFER or ACK with unauthorized DNS/gateway parameters)
  - *Tune:* `AuthorizedDHCPServers` — List of known DHCP servers; unexpected sources are suspicious.; `TimeWindow` — Interval to correlate DHCP OFFER/ACK anomalies with subsequent misconfigurations.
- **`AN1291` Analytic 1291** · Linux
  Detects rogue DHCP activity by monitoring syslog for dhclient messages assigning unauthorized DNS/gateway values. Packet capture or IDS can detect multiple competing DHCP OFFERs from non-authorized servers.
  - *Log sources:* `linux:syslog` (suspicious DHCP lease assignment with unexpected DNS or gateway); `NSM:Flow` (Gratuitous or duplicate DHCP OFFER packets from non-legitimate servers)
  - *Tune:* `AllowedDHCPMACs` — Expected MAC addresses of DHCP servers on subnet.; `DHCPLeaseChangeThreshold` — Number of suspicious DHCP leases before raising an alert.
- **`AN1292` Analytic 1292** · macOS
  Detects DHCP spoofing by monitoring unified logs for unexpected DHCP ACK/OFFER parameters and correlating with packet captures for multiple DHCP servers. Behavioral emphasis is on inconsistent DNS and gateway assignments that redirect traffic.
  - *Log sources:* `macos:unifiedlog` (new DHCP configuration with anomalous DNS or router values); `NSM:Flow` (Multiple DHCP OFFER responses for a single DISCOVER)
  - *Tune:* `BaselineDNS` — Expected DNS server list; deviations may indicate spoofing.; `AlertSensitivity` — Threshold for number of anomalous DHCP responses before alerting.

---

### T1557.004 — Evil Twin
<a id="t1557004"></a>

**Detection strategy:** Detect Evil Twin Wi-Fi Access Points on Network Devices (`DET0379`)  
**Platforms:** Network Devices  
**ATT&CK:** [T1557.004](https://attack.mitre.org/techniques/T1557/004/) · [detail page](../../techniques/credential-access.md#t1557004)

- **`AN1069` Analytic 1069** · Network Devices
  Detects rogue Wi-Fi access points broadcasting the same SSID as legitimate APs with stronger signal strength, unexpected MAC/BSSID values, or inconsistent encryption settings. Correlates authentication attempts, captive portal redirections, and anomalous traffic flows through unauthorized APs.
  - *Log sources:* `WLANLogs:Association` (Multiple APs advertising the same SSID but with different BSSID/MAC or encryption type); `NSM:Flow` (Probe responses from unauthorized APs responding to client probe requests); `networkdevice:syslog` (Failed authentication requests redirected to non-standard portals)
  - *Tune:* `KnownSSIDs` — Baseline of authorized SSIDs; deviations may indicate rogue AP.; `AllowedBSSIDs` — Whitelist of BSSID/MAC addresses mapped to corporate SSIDs.; `SignalStrengthThreshold` — Used to flag unusually strong signals from unexpected APs.; `CaptivePortalDomains` — Trusted login domains; unrecognized portals may be malicious.

---

### T1558 — Steal or Forge Kerberos Tickets
<a id="t1558"></a>

**Detection strategy:** Detect Kerberos Ticket Theft or Forgery (T1558) (`DET0522`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1558](https://attack.mitre.org/techniques/T1558/) · [detail page](../../techniques/credential-access.md#t1558)

- **`AN1443` Analytic 1443** · Windows
  Detects anomalous Kerberos activity such as forged or stolen tickets by correlating malformed fields in logon events, RC4-encrypted TGTs, or TGS requests without corresponding TGT requests. Also detects suspicious processes accessing LSASS memory for ticket extraction.
  - *Log sources:* `WinEventLog:Security` (EventCode=4672, 4634); `WinEventLog:Sysmon` (EventCode=10)
  - *Tune:* `TicketLifetimeThreshold` — Threshold for Kerberos TGT lifetimes deviating from domain defaults.; `EncryptionTypes` — Monitor for downgraded encryption types (e.g., RC4) in Kerberos tickets.; `ProcessAllowlist` — List of expected processes accessing LSASS; deviations may be suspicious.
- **`AN1444` Analytic 1444** · Linux
  Detects suspicious access to SSSD secrets database and Kerberos key material indicating ticket theft or replay attempts. Correlates anomalous file access with unusual Kerberos service ticket requests.
  - *Log sources:* `auditd:SYSCALL` (Access to /var/lib/sss/secrets/secrets.ldb or .secrets.mkey); `linux:syslog` (Unusual kinit or klist activity)
  - *Tune:* `SecretsAccessThreshold` — Alert threshold for frequency of access to Kerberos secrets files.; `UnusualServiceAccounts` — Baseline accounts normally performing Kerberos requests; anomalies flagged.
- **`AN1445` Analytic 1445** · macOS
  Detects attempts to forge or replay Kerberos tickets by monitoring Unified Logs for anomalous kinit/klist activity and correlating unusual authentication sequences.
  - *Log sources:* `macos:unifiedlog` (Unusual Kerberos TGS-REQ without TGT or anomalous ticket lifetime)
  - *Tune:* `TicketRequestPatterns` — Expected sequence of TGT followed by TGS requests; deviations may indicate forgery.; `TicketLifetime` — Expected ticket lifetimes; anomalies may indicate Golden or Silver Tickets.

---

### T1558.001 — Golden Ticket
<a id="t1558001"></a>

**Detection strategy:** Detect Forged Kerberos Golden Tickets (T1558.001) (`DET0144`)  
**Platforms:** Windows  
**ATT&CK:** [T1558.001](https://attack.mitre.org/techniques/T1558/001/) · [detail page](../../techniques/credential-access.md#t1558001)

- **`AN0405` Analytic 0405** · Windows
  Detects forged Kerberos Golden Tickets by correlating anomalous Kerberos ticket lifetimes, unexpected encryption types (e.g., RC4 in modern domains), malformed fields in logon/logoff events, and TGS requests without preceding TGT requests. Also monitors for abnormal patterns of access associated with elevated privileges across multiple systems.
  - *Log sources:* `WinEventLog:Security` (EventCode=4672, 4634); `WinEventLog:Security` (EventCode=4769); `WinEventLog:Sysmon` (EventCode=10)
  - *Tune:* `TicketLifetimeThreshold` — Kerberos TGT ticket lifetime exceeding default domain duration; tunable to environment-specific policies.; `AllowedEncryptionTypes` — Valid encryption algorithms for Kerberos tickets; anomalies (e.g., RC4) may indicate forgery.; `PrivilegedAccountPatterns` — Baseline of privileged accounts expected to perform Kerberos operations; deviations indicate suspicious activity.; `ProcessAllowlist` — Expected processes interacting with lsass.exe; deviations may indicate credential dumping.

---

### T1558.002 — Silver Ticket
<a id="t1558002"></a>

**Detection strategy:** Detect Forged Kerberos Silver Tickets (T1558.002) (`DET0241`)  
**Platforms:** Windows  
**ATT&CK:** [T1558.002](https://attack.mitre.org/techniques/T1558/002/) · [detail page](../../techniques/credential-access.md#t1558002)

- **`AN0675` Analytic 0675** · Windows
  Detects forged Kerberos Silver Tickets by identifying anomalous Kerberos service ticket activity such as malformed fields in logon events, TGS requests without interaction with the KDC, and access attempts using service accounts outside expected hosts/resources. Also monitors suspicious processes accessing LSASS memory for credential dumping.
  - *Log sources:* `WinEventLog:Security` (EventCode=4672, 4634); `WinEventLog:Kerberos` (Kerberos TGS-REQ anomalies without KDC validation (Silver Ticket behavior)); `WinEventLog:Sysmon` (EventCode=10)
  - *Tune:* `ServiceAccountScope` — Expected mapping of service accounts to specific resources; deviations may indicate Silver Ticket use.; `TicketValidationBaseline` — Expected TGS issuance patterns including KDC validation; anomalies may signal forged tickets.; `ProcessAllowlist` — Known processes that legitimately interact with LSASS; others may indicate dumping attempts.; `TimeWindow` — Correlate Kerberos requests within a tunable timeframe to reduce false positives.

---

### T1558.003 — Kerberoasting
<a id="t1558003"></a>

**Detection strategy:** Detect Kerberoasting Attempts (T1558.003) (`DET0157`)  
**Platforms:** Windows  
**ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/) · [detail page](../../techniques/credential-access.md#t1558003)

- **`AN0444` Analytic 0444** · Windows
  Detects Kerberoasting attempts by monitoring for anomalous Kerberos TGS requests (Event ID 4769) with RC4 encryption (etype 0x17), accounts requesting an unusual number of service tickets in a short period, or service accounts targeted outside normal usage baselines. Also correlates suspicious process activity (e.g., Mimikatz invoking LSASS access) with Kerberos ticket anomalies.
  - *Log sources:* `WinEventLog:Security` (EventCode=4769); `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Security` (EventCode=4624, 4648); `WinEventLog:Security` (EventCode=4672)
  - *Tune:* `TGSRequestThreshold` — Number of TGS requests per account within a defined window; higher than baseline may indicate Kerberoasting.; `AllowedEncryptionTypes` — Permitted Kerberos encryption algorithms; RC4 (etype 0x17) usage in modern environments is suspicious.; `ServiceAccountBaselines` — Expected SPNs requested by specific accounts; anomalies may indicate adversarial targeting.; `TimeWindow` — Correlation window for bursts of TGS requests; adjustable to reduce false positives.

---

### T1558.004 — AS-REP Roasting
<a id="t1558004"></a>

**Detection strategy:** Detect AS-REP Roasting Attempts (T1558.004) (`DET0113`)  
**Platforms:** Windows  
**ATT&CK:** [T1558.004](https://attack.mitre.org/techniques/T1558/004/) · [detail page](../../techniques/credential-access.md#t1558004)

- **`AN0316` Analytic 0316** · Windows
  Detects AS-REP roasting attempts by monitoring for Kerberos AS-REQ/AS-REP authentication patterns where preauthentication is disabled (Event ID 4768 with Pre-Auth Type 0). Correlates these requests with subsequent service ticket activity (Event ID 4769) and anomalies such as requests using weak RC4 encryption (etype 0x17). Excessive enumeration of accounts with 'Do not require Kerberos preauthentication' set in Active Directory is another key detection point.
  - *Log sources:* `WinEventLog:Security` (EventCode=4768); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `PreAuthDisabledAccountsBaseline` — Baseline of accounts legitimately configured without Kerberos preauthentication; deviations may indicate adversary enumeration.; `TGTRequestThreshold` — Number of AS-REQ/AS-REP exchanges per account within a short timeframe; higher counts may indicate AS-REP roasting.; `AllowedEncryptionTypes` — Permitted Kerberos encryption algorithms; RC4 usage (etype 0x17) should be closely monitored.; `TimeWindow` — Correlation window for linking AS-REQs, AS-REPs, and subsequent service ticket requests.

---

### T1558.005 — Ccache Files
<a id="t1558005"></a>

**Detection strategy:** Detect Kerberos Ccache File Theft or Abuse (T1558.005) (`DET0024`)  
**Platforms:** Linux, macOS  
**ATT&CK:** [T1558.005](https://attack.mitre.org/techniques/T1558/005/) · [detail page](../../techniques/credential-access.md#t1558005)

- **`AN0069` Analytic 0069** · Linux
  Detects unauthorized access, copying, or modification of Kerberos ccache files (krb5cc_%UID% or krb5.ccache) in /tmp or custom paths defined by KRB5CCNAME. Correlates file access with suspicious processes (e.g., credential dumping tools) and subsequent anomalous Kerberos authentication requests from non-standard processes.
  - *Log sources:* `auditd:SYSCALL` (open: File access attempt on /tmp/krb5cc_* or /tmp/krb5.ccache); `auditd:SYSCALL` (execve: Execution of klist, kinit, or tools interacting with ccache outside normal user context)
  - *Tune:* `CcachePathBaseline` — Expected directories or environment variable (KRB5CCNAME) paths for ccache files in the environment.; `AllowedProcesses` — Baseline list of processes legitimately interacting with ccache (e.g., klist, kinit).; `TimeWindow` — Correlation window for linking file access, process execution, and Kerberos requests.
- **`AN0070` Analytic 0070** · macOS
  Detects abnormal interaction with memory-based Kerberos ccache (API:{uuid}) or file-based overrides. Focus on processes attempting to enumerate or extract Kerberos tickets outside of built-in utilities. Detects use of open-source tools (e.g., Bifrost, modified Mimikatz ports) that interact with the Kerberos framework APIs.
  - *Log sources:* `macos:unifiedlog` (Kerberos framework calls to API:{uuid} cache outside normal process lineage); `macos:osquery` (Execution of non-standard binaries accessing Kerberos APIs)
  - *Tune:* `KerberosAPIProcessBaseline` — Expected processes using the Kerberos framework (e.g., loginwindow, kinit).; `SuspiciousBinaryList` — List of tools or binaries not normally expected to query Kerberos ccache entries.; `TimeWindow` — Window to link suspicious process activity with Kerberos authentication anomalies.

---

### T1606 — Forge Web Credentials
<a id="t1606"></a>

**Detection strategy:** Detection Strategy for Forged Web Credentials (`DET0260`)  
**Platforms:** IaaS, Identity Provider, Linux, Office Suite, SaaS, Windows, macOS  
**ATT&CK:** [T1606](https://attack.mitre.org/techniques/T1606/) · [detail page](../../techniques/credential-access.md#t1606)

- **`AN0717` Analytic 0717** · IaaS
  Defenders may detect adversaries forging web credentials in IaaS environments by monitoring for anomalous API activity such as AssumeRole or GetFederationToken being executed by unusual principals. These events often correlate with sudden logon sessions from unfamiliar IP addresses or regions. The chain is usually secret material misuse (stolen private key or password) → API request generating a new token → access to high-value resources.
  - *Log sources:* `AWS:CloudTrail` (AssumeRole, GetFederationToken API calls by unusual or new entities); `AWS:CloudTrail` (Temporary security credentials used to authenticate into management console or APIs)
  - *Tune:* `AuthorizedRoleMappings` — Define expected users and roles allowed to use AssumeRole or federation APIs.; `GeoVelocityThreshold` — Alert if the same user authenticates from geographically disparate locations within a short time.
- **`AN0718` Analytic 0718** · Identity Provider
  Forged web credentials may manifest as anomalous SAML token issuance, OpenID Connect token minting, or Zimbra pre-auth key usage. Defenders may see tokens issued without normal authentication events, multiple valid tokens generated simultaneously, or signing anomalies in IdP logs.
  - *Log sources:* `azure:signinlogs` (SAML/OIDC tokens issued without corresponding MFA or password validation); `NSM:Connections` (Pre-authentication keys generated or token signing anomalies)
  - *Tune:* `TokenLifetimeThreshold` — Limit the maximum time temporary tokens are valid.; `ExpectedAuthFlows` — Define normal authentication flows (e.g., password+MFA) to baseline token issuance.
- **`AN0719` Analytic 0719** · Windows
  Forged web credentials on Windows endpoints may be detected by anomalous browser cookie files, local token cache manipulations, or tools injecting tokens into sessions. Defenders may observe processes accessing LSASS or browser credential stores unexpectedly, followed by unusual logon sessions.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Security` (EventCode=4624, 4648)
  - *Tune:* `ProcessWhitelist` — Define expected processes that access LSASS or browser credential files.
- **`AN0720` Analytic 0720** · Linux
  On Linux systems, forged credentials may be injected into browser session files, curl/wget headers, or token caches in memory. Detection can leverage auditd to track processes accessing sensitive files (~/.mozilla, ~/.config/chromium, ~/.aws/credentials) and correlate with suspicious outbound connections.
  - *Log sources:* `auditd:SYSCALL` (Processes reading credential or token cache files); `WinEventLog:Sysmon` (Outbound requests with forged tokens/cookies in headers)
  - *Tune:* `CredentialFilePaths` — Define which credential and session files should trigger monitoring.
- **`AN0721` Analytic 0721** · macOS
  Forged credentials on macOS may be visible through Unified Logs showing abnormal access to Keychain or browser session files. Correlated with anomalous web session usage from Safari or Chrome processes outside typical user context.
  - *Log sources:* `macos:unifiedlog` (Access to Keychain items or browser credential stores); `macos:unifiedlog` (Web sessions initiated with newly forged tokens)
  - *Tune:* `AuthorizedKeychainApps` — List applications that normally request Keychain credentials.
- **`AN0722` Analytic 0722** · SaaS
  SaaS platforms may show forged credentials as unusual API keys, tokens, or session cookies being used without corresponding authentication. Correlated patterns include simultaneous valid sessions from multiple geographies, unusual API calls with new tokens, or bypass of expected MFA enforcement.
  - *Log sources:* `m365:unified` (Session creation without MFA or login event); `saas:auth` (API requests made with tokens not associated with expected user logins)
  - *Tune:* `GeoLocationAlerts` — Trigger on logins from unusual or high-risk geographies.; `TokenReplayThreshold` — Detect multiple simultaneous uses of the same forged credential.
- **`AN0723` Analytic 0723** · Office Suite
  Forged web credentials in Office Suite contexts may appear as abnormal authentication headers in Outlook or Teams traffic, or unexplained OAuth grants in M365/Azure logs. Defenders should correlate token usage events with missing authentication flows and mismatched device/user context.
  - *Log sources:* `m365:oauth` (OAuth grants or tokens issued without expected user consent); `m365:signinlogs` (Token usage events with device/user mismatch)
  - *Tune:* `OAuthAppAllowlist` — Approved OAuth apps and flows; flag unapproved or unexpected token grants.

---

### T1606.001 — Web Cookies
<a id="t1606001"></a>

**Detection strategy:** Detection Strategy for Forged Web Cookies (`DET0171`)  
**Platforms:** IaaS, Linux, SaaS, Windows, macOS  
**ATT&CK:** [T1606.001](https://attack.mitre.org/techniques/T1606/001/) · [detail page](../../techniques/credential-access.md#t1606001)

- **`AN0483` Analytic 0483** · IaaS
  Forged cookies in IaaS environments may appear as authentication attempts that bypass MFA, leveraging AssumeRole or session APIs with cookies that were never legitimately issued. Defenders should correlate cloud logs for cookie-based sessions without prior valid authentication, often followed by resource access from unfamiliar IP addresses.
  - *Log sources:* `AWS:CloudTrail` (Web console logins using session cookies without corresponding MFA event); `AWS:CloudTrail` (GetSessionToken, AssumeRoleWithWebIdentity)
  - *Tune:* `GeoVelocityThreshold` — Flag logins from geographically distant locations in a short timeframe.; `AuthorizedCookieIssuers` — Expected systems and services that may legitimately mint session cookies.
- **`AN0484` Analytic 0484** · Windows
  Forged web cookies on Windows endpoints can be detected by monitoring unusual modifications of browser cookie stores (e.g., Chrome SQLite DB, Edge cache) by processes outside of browsers, followed by authentication events to SaaS or IaaS services. Defenders may observe processes writing directly to cookie storage paths or injecting tokens into browser sessions.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Security` (EventCode=4624, 4648)
  - *Tune:* `BrowserCookiePaths` — List of monitored cookie file paths on Windows systems.; `ProcessWhitelist` — Approved processes allowed to write to browser cookie stores.
- **`AN0485` Analytic 0485** · Linux
  On Linux, defenders may observe forged cookie activity as unauthorized modifications to browser cookie databases (e.g., ~/.mozilla/firefox/*/cookies.sqlite, ~/.config/chromium/Default/Cookies) or scripted injection of session tokens. Suspicious usage includes curl/wget commands embedding forged cookies in headers, correlated with abnormal session activity in SaaS or IaaS logs.
  - *Log sources:* `auditd:SYSCALL` (Unusual processes accessing or modifying cookie databases); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `CredentialFilePaths` — Paths to cookie/session storage files to monitor.
- **`AN0486` Analytic 0486** · macOS
  Forged cookies on macOS may show up as abnormal access to Safari/Chrome cookie databases in ~/Library/Cookies, combined with unexpected logon sessions authenticated by those cookies. Unified Logs may show cookie injection events or abnormal access patterns to Keychain when linked to browser authentication flows.
  - *Log sources:* `macos:unifiedlog` (Abnormal process access to Safari or Chrome cookie storage); `macos:unifiedlog` (New session initiated using cookies without normal MFA or password validation)
  - *Tune:* `AuthorizedKeychainApps` — Applications permitted to use Keychain to generate cookies or tokens.
- **`AN0487` Analytic 0487** · SaaS
  Forged cookies in SaaS environments manifest as valid web sessions without matching login activity, MFA enforcement bypass, or cookies reused across multiple devices/IPs. Defenders should look for cookie replay, concurrent sessions from multiple geographies, or session tokens generated by unrecognized apps.
  - *Log sources:* `m365:unified` (Session activity without correlated login event); `saas:access` (Multiple concurrent logins using same cookie from different locations)
  - *Tune:* `TokenReplayThreshold` — Number of concurrent uses of a cookie that should trigger an alert.; `GeoLocationAlerts` — Unusual SaaS logins from geographically distant locations in short timeframes.

---

### T1606.002 — SAML Tokens
<a id="t1606002"></a>

**Detection strategy:** Detection Strategy for Forged SAML Tokens (`DET0148`)  
**Platforms:** IaaS, Identity Provider, Office Suite, SaaS, Windows  
**ATT&CK:** [T1606.002](https://attack.mitre.org/techniques/T1606/002/) · [detail page](../../techniques/credential-access.md#t1606002)

- **`AN0418` Analytic 0418** · Identity Provider
  Forged SAML tokens can be observed as authentication attempts with valid signatures but missing expected preceding Kerberos or authentication events. Defenders may correlate SAML assertions with absent Event IDs 4769, 1200, or 1202, or tokens issued with abnormal lifetimes, issuers, or claims compared to baseline.
  - *Log sources:* `azure:signinlogs` (SAML-based login with anomalous issuer or NotOnOrAfter lifetime); `WinEventLog:Security` (EventCode=4769, 1200, 1202)
  - *Tune:* `TokenLifetimeThreshold` — Defines the maximum expected lifetime of a SAML token (e.g., >1 hour considered anomalous).; `TrustedIssuerList` — List of approved SAML issuers and certificate thumbprints.
- **`AN0419` Analytic 0419** · IaaS
  Forged SAML tokens in IaaS environments often manifest as cross-cloud or cross-account authentication without matching STS events. Defenders may see AssumeRole or GetFederationToken API usage without a corresponding SAML assertion log from the trusted IdP.
  - *Log sources:* `AWS:CloudTrail` (AssumeRoleWithSAML); `CloudTrail:Signin` (SAML login without corresponding IdP authentication log)
  - *Tune:* `CrossAccountUsage` — Flag SAML tokens used across unexpected accounts or cloud tenants.
- **`AN0420` Analytic 0420** · Windows
  Forged SAML tokens may be used on Windows systems to authenticate to federated apps without normal Kerberos activity. Defenders may detect anomalous event correlation, where access to SaaS/O365 via SAML occurs without prior TGT requests or user logons.
  - *Log sources:* `WinEventLog:Security` (EventCode=4624, 4648); `WinEventLog:ADFS` (Token issuance events showing anomalous claims or issuers)
  - *Tune:* `ClaimAnomalyThreshold` — Number of unusual claims in a SAML token (e.g., excessive privileges).
- **`AN0421` Analytic 0421** · SaaS
  Forged SAML tokens can appear as SaaS logins where authentication succeeded without MFA, or where tokens contain claims inconsistent with the user profile. Look for concurrent sessions across different geographies with the same SAML assertion ID.
  - *Log sources:* `saas:access` (SAML token accepted without preceding login challenge); `m365:unified` (Abnormal user claims or unexpected elevated role assignment in SAML assertion)
  - *Tune:* `GeoVelocityThreshold` — Triggers when same SAML token used in different geographies within short timeframe.
- **`AN0422` Analytic 0422** · Office Suite
  Forged SAML tokens may be leveraged to access O365 apps such as Outlook or SharePoint. Defenders should monitor for token replay across multiple clients or access attempts to privileged mailboxes without prior interactive login.
  - *Log sources:* `m365:exchange` (Mailbox access using SAML token without corresponding MFA event); `m365:sharepoint` (File access with forged or anomalous SAML claims)
  - *Tune:* `ReplayDetectionThreshold` — Number of times a token is reused within short timeframe.

---

### T1621 — Multi-Factor Authentication Request Generation
<a id="t1621"></a>

**Detection strategy:** Detection Strategy for Multi-Factor Authentication Request Generation (T1621) (`DET0160`)  
**Platforms:** IaaS, Identity Provider, Linux, SaaS, Windows, macOS  
**ATT&CK:** [T1621](https://attack.mitre.org/techniques/T1621/) · [detail page](../../techniques/credential-access.md#t1621)

- **`AN0449` Analytic 0449** · Identity Provider
  Monitor for excessive or anomalous MFA push notifications or token requests, especially when login attempts originate from unusual IPs or geolocations and do not correspond to legitimate user-initiated sessions.
  - *Log sources:* `azure:signinlogs` (Multiple MFA challenge requests without successful primary login); `NSM:Connections` (PushNotificationSent)
  - *Tune:* `TimeWindow` — Threshold of MFA prompts per user within a short time period; `GeoIPAllowList` — Expected login locations for workforce; deviations can be tuned
- **`AN0450` Analytic 0450** · IaaS
  Detect abnormal MFA activity within cloud service provider logs, such as repeated generation of MFA challenges for the same user session or mismatched MFA device and login origin.
  - *Log sources:* `AWS:CloudTrail` (AssumeRole or ConsoleLogin with repeated MFA failures followed by repeated MFA requests)
  - *Tune:* `FailedLoginThreshold` — Number of failed logins before raising detection
- **`AN0451` Analytic 0451** · Windows
  Detect repeated failed login events followed by MFA challenges triggered in rapid succession, especially if originating from service accounts or anomalous IP addresses.
  - *Log sources:* `WinEventLog:Security` (EventCode=4625)
  - *Tune:* `ServiceAccountExclusion` — Exclude specific accounts where automated MFA requests are legitimate
- **`AN0452` Analytic 0452** · Linux
  Monitor PAM and syslog entries for unusual frequency of login attempts that trigger MFA prompts, particularly when MFA challenges do not match expected user behavior.
  - *Log sources:* `auditd:AUTH` (pam_unix or pam_google_authenticator invoked repeatedly within short interval)
  - *Tune:* `AuthRetryThreshold` — Number of retries per user allowed before detection is triggered
- **`AN0453` Analytic 0453** · SaaS
  Detect anomalous OAuth or SSO logins that repeatedly generate MFA challenges, particularly where MFA approvals are denied or timed out by the user.
  - *Log sources:* `saas:okta` (MFAChallengeIssued)
  - *Tune:* `MFAProvider` — Identify which MFA service provider logs are in use (Okta, Duo, Microsoft Authenticator)
- **`AN0454` Analytic 0454** · macOS
  Detect user account logon attempts that trigger multiple MFA challenges through enterprise identity integrations, especially if MFA push requests are generated without successful interactive login.
  - *Log sources:* `macos:unifiedlog` (authd generating multiple MFA token requests)
  - *Tune:* `DeviceEnrollmentStatus` — Exclude unmanaged macOS devices that use different MFA providers

---

### T1649 — Steal or Forge Authentication Certificates
<a id="t1649"></a>

**Detection strategy:** Detection Strategy for Steal or Forge Authentication Certificates (`DET0240`)  
**Platforms:** Identity Provider, Linux, Windows, macOS  
**ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/) · [detail page](../../techniques/credential-access.md#t1649)

- **`AN0671` Analytic 0671** · Windows
  Monitor for abnormal certificate enrollment and usage activity in Active Directory Certificate Services (AD CS), registry access to certificate storage locations, and unusual process executions that attempt to export or access private keys.
  - *Log sources:* `WinEventLog:Security` (EventCode=4768); `WinEventLog:Security` (EventCode=4657)
  - *Tune:* `EKU_Thresholds` — Organizations may tune which Extended Key Usage (EKU) values are considered risky.; `TimeWindow` — Defines how quickly multiple certificate enrollments from the same entity should trigger correlation alerts.; `LogonContext` — Differentiate between service accounts and interactive user accounts to reduce false positives.
- **`AN0672` Analytic 0672** · Linux
  Monitor for file access to certificate directories, commands invoking OpenSSL or PKCS#12 utilities to export or modify certificates, and processes accessing sensitive key storage paths.
  - *Log sources:* `auditd:SYSCALL` (open, read: /etc/ssl/, /etc/pki/, ~/.pki/nssdb/); `auditd:SYSCALL` (execve: openssl pkcs12, certutil, keytool)
  - *Tune:* `PathExclusions` — Exempt trusted automated services regularly accessing PKI stores.; `UserContext` — Differentiate root/system accounts versus user-level access to key material.
- **`AN0673` Analytic 0673** · macOS
  Monitor for security commands and API calls interacting with the Keychain, as well as file access attempts to stored certificates and private keys in ~/Library/Keychains or /Library/Keychains.
  - *Log sources:* `macos:unifiedlog` (process calling security find-certificate, export, or import); `macos:keychain` (~/Library/Keychains, /Library/Keychains)
  - *Tune:* `ApplicationAllowList` — Whitelist legitimate apps that interact with Keychain to reduce false positives.
- **`AN0674` Analytic 0674** · Identity Provider
  Monitor for abnormal certificate enrollment events in identity platforms, unexpected use of token-signing certificates, and unusual CA configuration modifications.
  - *Log sources:* `azure:signinlogs` (Add certificate credential, Update certificate credential); `m365:unified` (certificate added or modified in application credentials)
  - *Tune:* `GeoContext` — Detect certificate-related changes occurring from unusual geographic locations.; `Thresholds` — Adjust enrollment/issuance request volume thresholds per tenant size.

---

