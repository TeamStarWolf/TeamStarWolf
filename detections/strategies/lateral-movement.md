# Lateral Movement — Detection Strategies

> MITRE ATT&CK detection strategies and analytics (v18.1) for techniques whose primary tactic is **Lateral Movement**. Each analytic lists the **log sources / channels** it needs, the **detection logic**, and the **tunable elements** to adapt it to your environment. Authoritative source: the ATT&CK detection-strategy model in the Enterprise STIX.

See also: [all detection strategies index](/detections/strategies/README.md) · [Technique Detection Library](../TECHNIQUE_DETECTION_LIBRARY.md) (ready-to-run SIEM queries) · [Data Components & Log Sources](../../ATTACK_DATA_COMPONENTS.md) · [Technique Detail Pages](../../techniques/README.md)

---

### T1021 — Remote Services
<a id="t1021"></a>

**Detection strategy:** Behavioral Detection Strategy for Remote Service Logins and Post-Access Activity (`DET0269`)  
**Platforms:** ESXi, IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1021](https://attack.mitre.org/techniques/T1021/) · [detail page](../../techniques/lateral-movement.md#t1021)

- **`AN0750` Analytic 0750** · Windows
  Logon via RDP or WMI by a user account followed by uncommon command execution, file manipulation, or lateral network connections.
  - *Log sources:* `WinEventLog:Security` (EventCode=4624, 4648); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `TimeWindow` — Correlation window between remote login and post-access activity; `LogonUser` — Limit to service accounts or privileged users for higher fidelity; `RemoteHostList` — Allowlisting known admin jumpboxes or deployment tools
- **`AN0751` Analytic 0751** · Linux
  SSH session from new source IP followed by interactive shell or privilege escalation (e.g., sudo, su) and outbound lateral connection.
  - *Log sources:* `linux:syslog` (sshd: Accepted password/publickey); `auditd:SYSCALL` (execve, USER_CMD)
  - *Tune:* `SourceIP` — Limit to new/unexpected SSH source IPs; `CommandList` — Flag suspicious post-SSH command patterns
- **`AN0752` Analytic 0752** · macOS
  Remote login via ARD or SSH followed by screensharingd process activity or modification of TCC-protected files.
  - *Log sources:* `macos:unifiedlog` (eventMessage CONTAINS 'screensharingd' or 'AuthorizationRefCreate'); `macos:osquery` (process_events)
  - *Tune:* `RemoteService` — Differentiate ARD vs SSH access patterns; `TargetedPath` — Tunable list of sensitive directories or TCC targets
- **`AN0753` Analytic 0753** · IaaS
  Use of cloud-based bastion or VM console session followed by commands that initiate outbound SSH or RDP sessions from the cloud instance to other environments.
  - *Log sources:* `AWS:CloudTrail` (AWS ConsoleLogin, StartSession); `AWS:VPCFlowLogs` (Outbound connections to port 22, 3389)
  - *Tune:* `SourceAssetTag` — Limit detection to cloud admin/bastion hosts; `TargetPortList` — Define critical remote service ports to flag
- **`AN0754` Analytic 0754** · ESXi
  vSphere API logins (vimService) or SSH to ESXi host followed by unauthorized shell commands or lateral remote logins from the ESXi host.
  - *Log sources:* `esxi:vmkernel` (vim.fault.*, DCUI login, SSH shell); `esxi:shell` (Command execution trace)
  - *Tune:* `SessionType` — Filter by DCUI, SSH, vSphere API; `CommandPattern` — Watch for remote access tool invocations (e.g., netcat, ssh)

---

### T1021.001 — Remote Desktop Protocol
<a id="t1021001"></a>

**Detection strategy:** Multi-event Detection Strategy for RDP-Based Remote Logins and Post-Access Activity (`DET0327`)  
**Platforms:** Windows  
**ATT&CK:** [T1021.001](https://attack.mitre.org/techniques/T1021/001/) · [detail page](../../techniques/lateral-movement.md#t1021001)

- **`AN0931` Analytic 0931** · Windows
  Remote Desktop (RDP) logon by a user followed by unusual process execution, file access, or lateral movement activity within a short timeframe.
  - *Log sources:* `WinEventLog:Security` (EventCode=4624, 4648); `WinEventLog:Security` (EventCode=4778, EventCode=4779); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `TimeWindow` — Temporal threshold to correlate login with post-login activity (e.g., 5 minutes); `UserContext` — Tune for non-admin users or service accounts expected to use RDP; `ProcessList` — Define suspicious post-login processes such as cmd.exe, powershell.exe, certutil.exe; `HostAccessPatterns` — Scope detection to uncommon or first-time access between source and destination hosts

---

### T1021.002 — SMB/Windows Admin Shares
<a id="t1021002"></a>

**Detection strategy:** Multi-Event Detection for SMB Admin Share Lateral Movement (`DET0530`)  
**Platforms:** Windows  
**ATT&CK:** [T1021.002](https://attack.mitre.org/techniques/T1021/002/) · [detail page](../../techniques/lateral-movement.md#t1021002)

- **`AN1468` Analytic 1468** · Windows
  An SMB-based remote file share access followed by lateral movement actions such as remote service creation, task scheduling, or suspicious process execution on the target host using ADMIN$ or C$ shares.
  - *Log sources:* `WinEventLog:Security` (EventCode=4624, 4648); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `ShareName` — Targeted admin share path, such as C$, ADMIN$, IPC$; `TimeWindow` — Correlation window between remote file access and remote execution (e.g., 5-10 minutes); `UserContext` — Distinguish expected remote administrators vs. rare/first-time access by specific users; `ProcessList` — List of suspicious binaries or tools executed post remote copy (e.g., cmd.exe, powershell.exe, runonce.exe)

---

### T1021.003 — Distributed Component Object Model
<a id="t1021003"></a>

**Detection strategy:** Multi-Event Behavioral Detection for DCOM-Based Remote Code Execution (`DET0285`)  
**Platforms:** Windows  
**ATT&CK:** [T1021.003](https://attack.mitre.org/techniques/T1021/003/) · [detail page](../../techniques/lateral-movement.md#t1021003)

- **`AN0791` Analytic 0791** · Windows
  A remote DCOM invocation by a privileged account using RPC (port 135), followed by abnormal process instantiation or module loading on the remote system indicative of code execution.
  - *Log sources:* `WinEventLog:Security` (EventCode=4624, 4648); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `TimeWindow` — Correlate RPC activity with remote process creation within a configurable time window (e.g., 300s); `UserContext` — Identify rare or first-time DCOM invocations by specific accounts; `ProcessName` — List of suspicious executables commonly abused via DCOM (e.g., excel.exe, wmiprvse.exe); `RemoteHostList` — Known set of systems that should or should not be invoking DCOM activity

---

### T1021.004 — SSH
<a id="t1021004"></a>

**Detection strategy:** Behavioral Detection of Remote SSH Logins Followed by Post-Login Execution (`DET0596`)  
**Platforms:** ESXi, Linux, macOS  
**ATT&CK:** [T1021.004](https://attack.mitre.org/techniques/T1021/004/) · [detail page](../../techniques/lateral-movement.md#t1021004)

- **`AN1638` Analytic 1638** · Linux
  SSH login from a remote system (via sshd), followed by user context execution of suspicious binaries or privilege escalation behavior.
  - *Log sources:* `auditd:EXECVE` (EXECVE); `linux:syslog`; `NSM:Flow` (TCP port 22 traffic)
  - *Tune:* `TimeWindow` — Defines correlation window from login to first post-SSH process (e.g., 60s); `SuspiciousProcessList` — List of binaries considered unusual in SSH context (e.g., nc, base64, bash -i); `UsernameFilter` — Accounts of interest for SSH logins (e.g., root, admin)
- **`AN1639` Analytic 1639** · macOS
  SSH login detected via Unified Logs, followed by unusual process execution, especially outside normal user behavior patterns.
  - *Log sources:* `macos:unifiedlog` (process = 'sshd'); `macos:unifiedlog` (process = 'ssh' OR eventMessage CONTAINS 'ssh'); `macos:osquery` (process_events)
  - *Tune:* `TimeWindow` — Time range to correlate post-SSH activities (e.g., 45s); `UserContext` — Define authorized users to reduce false positives; `CommandLineKeywords` — Suspicious terms like reverse shells, base64, curl
- **`AN1640` Analytic 1640** · ESXi
  SSH login via hostd or `/var/log/auth.log`, followed by CLI access to host shell or file manipulation in restricted areas.
  - *Log sources:* `esxi:auth`; `esxi:shell`; `esxi:vmkernel` (port 22 access)
  - *Tune:* `AllowedUsers` — Legitimate SSH users to this host; `TimeWindow` — Correlate SSH login and unauthorized commands or shell access; `CommandList` — Flag commands like esxcli, rm, chmod post-login

---

### T1021.005 — VNC
<a id="t1021005"></a>

**Detection strategy:** Behavioral Detection of Unauthorized VNC Remote Control Sessions (`DET0178`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1021.005](https://attack.mitre.org/techniques/T1021/005/) · [detail page](../../techniques/lateral-movement.md#t1021005)

- **`AN0504` Analytic 0504** · Windows
  Detection of VNC service or executable starting unexpectedly, followed by user session creation and interactive desktop activity (mouse/keyboard simulation).
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Security` (EventCode=4624, 4648); `NSM:Flow` (port 5900 inbound)
  - *Tune:* `TimeWindow` — Correlate VNC process with user logon activity within defined time span; `VNCBinaryList` — Trackable VNC executable names (e.g., vncserver.exe, winvnc.exe); `LogonType` — Limit detection to interactive logons (type 10)
- **`AN0505` Analytic 0505** · Linux
  Spawning of VNC-related processes (e.g., `x11vnc`, `vncserver`) coupled with authentication logs and port listening behavior on TCP 5900.
  - *Log sources:* `auditd:EXECVE`; `linux:syslog`; `NSM:Flow` (TCP port 5900 open)
  - *Tune:* `ListeningPort` — Default VNC port (5900) but may vary in config; `ProcessNameFilter` — Filter specific VNC binaries in process execution logs; `UserContext` — Scope detection to non-service or high-privilege accounts
- **`AN0506` Analytic 0506** · macOS
  Detection of VNC-based remote control via `screensharingd` activity in Unified Logs along with concurrent remote login activity or suspicious user interaction.
  - *Log sources:* `macos:unifiedlog` (authentication); `macos:osquery` (process_events); `NSM:firewall` (inbound connection to port 5900)
  - *Tune:* `AuthenticationPredicate` — Unified log predicate to refine suspicious screensharing access; `TimeWindow` — Time between VNC connection and follow-on activity (e.g., 30s); `UserActivitySpike` — Mouse/keyboard interaction spike immediately post-VNC login

---

### T1021.006 — Windows Remote Management
<a id="t1021006"></a>

**Detection strategy:** Behavioral Detection of WinRM-Based Remote Access (`DET0477`)  
**Platforms:** Windows  
**ATT&CK:** [T1021.006](https://attack.mitre.org/techniques/T1021/006/) · [detail page](../../techniques/lateral-movement.md#t1021006)

- **`AN1313` Analytic 1313** · Windows
  Adversaries using WinRM to remotely execute commands, launch child processes, or access WMI. The detection chain includes service use, network activity, remote session logon, and process creation within a short temporal window.
  - *Log sources:* `WinEventLog:Security` (EventCode=4624, 4648); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:WinRM` (EventCode=6); `NSM:Connections` (Inbound on ports 5985/5986)
  - *Tune:* `TimeWindow` — Defines max time between remote shell creation and child process execution (e.g., 60 seconds); `UserContext` — Scope to unexpected remote user logons (non-admins, service accounts); `CommandLineAnomalyScore` — Score for suspicious command usage via WinRM (e.g., encoded PowerShell); `KnownAdminHosts` — List of trusted systems allowed to use WinRM legitimately

---

### T1021.007 — Cloud Services
<a id="t1021007"></a>

**Detection strategy:** Behavioral Detection of Remote Cloud Logins via Valid Accounts (`DET0008`)  
**Platforms:** IaaS, Identity Provider, Office Suite, SaaS  
**ATT&CK:** [T1021.007](https://attack.mitre.org/techniques/T1021/007/) · [detail page](../../techniques/lateral-movement.md#t1021007)

- **`AN0017` Analytic 0017** · IaaS
  Cloud login from atypical geolocation or user-agent string, followed by resource enumeration or infrastructure manipulation using cloud CLI/API
  - *Log sources:* `AWS:CloudTrail` (ConsoleLogin, AssumeRole, ListResources); `gcp:audit`
  - *Tune:* `IPGeoRiskScore` — Tunable scoring system for evaluating geo-divergent or TOR-origin logins; `UserAgentFingerprint` — Flag rare CLI tools or browser-based sessions; `SessionDuration` — Threshold for how long between login and API access; `CloudResourceScope` — Limit monitoring to high-value resource groups or sensitive tenants
- **`AN0018` Analytic 0018** · Identity Provider
  Federated login using SSO or OAuth grant to cloud control plane, followed by directory or permissions enumeration
  - *Log sources:* `Okta:SystemLog` (user.authentication.sso, app.oauth.grant)
  - *Tune:* `SSOApplicationScope` — Tune based on applications federated to high-priv cloud assets; `ClientIDScope` — Filter based on expected OIDC clients used for login; `LoginVelocity` — Track multiple geographic logins within short windows
- **`AN0019` Analytic 0019** · Office Suite
  Login to M365 or Google Workspace from CLI tools or unexpected source IPs, followed by mailbox or document access
  - *Log sources:* `m365:unified` (FileAccessed, MailboxAccessed); `m365:unified` (UserLoggedIn)
  - *Tune:* `DevicePlatformMismatch` — Raise alerts on login from CLI when user typically uses web-only; `SensitiveDocumentAccessPattern` — Track access to documents labeled as internal/confidential; `AccessFrequencyThreshold` — Tune for high-volume document reads post login
- **`AN0020` Analytic 0020** · SaaS
  Remote access to third-party SaaS with OAuth or API tokens post-initial compromise, followed by sensitive data access or configuration changes
  - *Log sources:* `saas:auth` (LoginSuccess, APIKeyUse, AdminAction)
  - *Tune:* `OAuthTokenAge` — Older tokens issued before password change may indicate compromise; `AppScope` — Restrict detection to high-value or regulated SaaS apps

---

### T1021.008 — Direct Cloud VM Connections
<a id="t1021008"></a>

**Detection strategy:** Detection of Direct VM Console Access via Cloud-Native Methods (`DET0211`)  
**Platforms:** IaaS  
**ATT&CK:** [T1021.008](https://attack.mitre.org/techniques/T1021/008/) · [detail page](../../techniques/lateral-movement.md#t1021008)

- **`AN0594` Analytic 0594** · IaaS
  Direct login to cloud-hosted virtual machines via cloud-native access methods (e.g., EC2 Instance Connect, Azure Serial Console, SSM), followed by command execution or privilege escalation on the VM
  - *Log sources:* `AWS:CloudTrail` (SendSSHPublicKey, StartSession (SSM), EC2InstanceConnect); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `TimeWindow` — Correlates cloud login to host activity within a reasonable time span (e.g., < 60 seconds); `CloudAuthMethod` — Filters based on access vector: SSH key, SSM session, or Console connect; `SessionOriginRegion` — Identifies sessions from out-of-region or untrusted networks; `TargetInstanceTags` — Filters sensitive systems or production assets for alert tuning

---

### T1080 — Taint Shared Content
<a id="t1080"></a>

**Detection strategy:** Detection of Tainted Content Written to Shared Storage (`DET0471`)  
**Platforms:** Linux, Office Suite, SaaS, Windows, macOS  
**ATT&CK:** [T1080](https://attack.mitre.org/techniques/T1080/) · [detail page](../../techniques/lateral-movement.md#t1080)

- **`AN1298` Analytic 1298** · Windows
  Detects adversary tampering of shared directories via file drops (e.g., malicious LNK, EXE, VBS) followed by user execution or suspicious network activity.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Security` (EventCode=5145)
  - *Tune:* `SharedPathPrefix` — Defines monitored shared directories (e.g., \\server\HR\).; `ExecutableExtensions` — Monitored file types dropped in shared paths (e.g., .lnk, .exe, .vbs).
- **`AN1299` Analytic 1299** · Linux
  Detects script or binary modification within shared NFS/SMB directories followed by process execution from those paths.
  - *Log sources:* `auditd:SYSCALL` (write); `NSM:Flow` (smb_files.log)
  - *Tune:* `MountPath` — Mount path of monitored shared volumes (e.g., /mnt/shared).; `FilenamePattern` — Pattern matching of abnormal or disguised filenames.
- **`AN1300` Analytic 1300** · macOS
  Detects modification of shared network folders via .app bundles or scripting files with hidden extensions (e.g., double extensions like docx.app).
  - *Log sources:* `fs:fsevents` (Directory events (kFSEventStreamEventFlagItemCreated)); `macos:unifiedlog` (file writes)
  - *Tune:* `FileExtensionDeception` — Monitors use of hidden extensions or double extensions.; `TargetSharedFolder` — Defines sensitive shared folders (e.g., /Users/Shared/HR).
- **`AN1301` Analytic 1301** · SaaS
  Detects upload of malicious or unusual file types into cloud-shared folders, followed by user downloads or interactions.
  - *Log sources:* `gcp:workspaceaudit` (drive.activity logs); `m365:unified` (FileUploaded, FileAccessed)
  - *Tune:* `UserUploadRateThreshold` — Abnormal upload patterns into shared drives.; `MaliciousFileIndicator` — File hash or known-bad filename pattern matching.
- **`AN1302` Analytic 1302** · Office Suite
  Detects embedded macros or scripts added to shared documents or use of external references to execute code.
  - *Log sources:* `m365:defender` (OfficeTelemetry or DLP)
  - *Tune:* `MacroExecutionPolicy` — Controls macro execution based on user or group policy.; `SuspiciousKeywordMatch` — Regex match on suspicious VBA function names or calls.

---

### T1091 — Replication Through Removable Media
<a id="t1091"></a>

**Detection strategy:** Removable Media Execution Chain Detection via File and Process Activity (`DET0301`)  
**Platforms:** Windows  
**ATT&CK:** [T1091](https://attack.mitre.org/techniques/T1091/) · [detail page](../../techniques/lateral-movement.md#t1091)

- **`AN0841` Analytic 0841** · Windows
  Execution of files originating from removable media after drive mount, with correlation to file write activity, autorun usage, or lateral spread via staged tools.
  - *Log sources:* `WinEventLog:System` (EventCode=1006); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Microsoft-Windows-Windows Defender/Operational` (Suspicious file execution on removable media path)
  - *Tune:* `DriveLetterMatch` — Detect activity on mounted drives typically used by USB (e.g., E:, F:, G:). Tune based on enterprise usage.; `FileExecutionWindow` — Set timing threshold for execution shortly after drive mount (e.g., < 5 minutes).; `ParentProcess` — Restrict detection to suspicious process lineage like explorer.exe, powershell.exe, or unsigned binaries.; `FileEntropy` — Use entropy thresholding to detect packed/obfuscated payloads dropped to removable media.

---

### T1210 — Exploitation of Remote Services
<a id="t1210"></a>

**Detection strategy:** Exploitation of Remote Services – multi-platform lateral movement detection (`DET0118`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1210](https://attack.mitre.org/techniques/T1210/) · [detail page](../../techniques/lateral-movement.md#t1210)

- **`AN0327` Analytic 0327** · Windows
  Correlates inbound network access to remote service ports (e.g., SMB/RPC 445/135, RDP 3389, WinRM 5985/5986) with near-time instability in the target service (crash, abnormal restart), suspicious child process creation under the service, and post-access lateral-movement behaviors. The chain indicates likely exploitation rather than normal administration.
  - *Log sources:* `WinEventLog:System` (EventCode=1000); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=11); `NSM:Flow` (Inbound connections to 445, 3389, 5985-5986 with high error/connection-reset rate, followed by new outbound sessions from the same host to internal assets within short interval.)
  - *Tune:* `ServicePortSet` — List of monitored service ports (default: 445,135,3389,5985,5986,1433,3306).; `TimeWindow` — Correlation window between inbound access and crash/child-process (default: 10 minutes).; `AllowedAdminCIDRs` — Known management networks to suppress benign admin traffic.; `MinConnErrorRate` — Percent of failed/aborted connections to treat as anomalous (default: 30%).
- **`AN0328` Analytic 0328** · Linux
  Links inbound network access to SSHD/SMB/NFS/Databases or custom daemons with subsequent daemon crash/restart, core dump, or spawning of shells/reverse shells from the service context, indicating remote exploitation.
  - *Log sources:* `linux:syslog` (kernel|systemd messages indicating 'segmentation fault'|'core dumped'|'service terminated unexpectedly' for sshd, smbd, vsftpd, mysqld, httpd, etc.); `auditd:SYSCALL` (execve of /bin/sh,/bin/bash,/usr/bin/curl,/usr/bin/python by service accounts (e.g., apache, mysql, nobody) immediately after inbound network activity.); `NSM:Flow` (Inbound connections to monitored service ports from external or unusual internal sources; rapid follow-on lateral connections from the same host.)
  - *Tune:* `ServiceNames` — Linux daemons to watch (sshd, smbd, nfsd, httpd/nginx, mysqld, postgres, redis).; `CoreDumpPaths` — Paths indicating crash artifacts (/var/crash, /var/lib/systemd/coredump).; `ShellSpawnAllowlist` — Paths/users allowed to spawn shells from services (default: empty).; `TimeWindow` — Correlation window (default 10m).
- **`AN0329` Analytic 0329** · ESXi
  Detects exploitation targeting ESXi/vCenter by correlating attempts to reach known exploitable endpoints (OpenSLP 427, CIM 5989, Hostd/Vpxa HTTPS 443, ESXi SOAP) with vmkernel/hostd crashes, unexpected hostd/vpxa restarts, or new reverse/outbound connections from ESXi host/vCenter to internal assets.
  - *Log sources:* `esxi:hostd` (Keywords: 'Backtrace','Signal 11','PANIC','hostd restarted','assert' or 'Service terminated unexpectedly' in /var/log/hostd.log, /var/log/vmkernel.log, /var/log/syslog.log.); `NSM:Flow` (Inbound to tcp/427 (OpenSLP), tcp/443 (vSphere APIs), tcp/902, tcp/5989 followed by new unexpected outbound sessions from the ESXi/vCenter host.)
  - *Tune:* `ESXiServicePorts` — 427, 443, 902, 5989; modify per version/hardening.; `MgmtCIDRs` — Legit management networks for vCenter/ESXi.; `RestartKeywords` — Crash/restart patterns to match in logs.
- **`AN0330` Analytic 0330** · macOS
  Ties inbound access to exposed services (ARD/VNC 5900, SSH 22, ScreenSharing, web services) with process crashes in unified logs and abnormal child processes spawned under those services (e.g., bash, curl) to indicate exploitation.
  - *Log sources:* `macos:unifiedlog` (process 'crashed'|'EXC_BAD_ACCESS' for sshd, screensharingd, httpd; launchd restarts of these daemons.); `macos:osquery` (parent_name in ('sshd','httpd','screensharingd') spawning shells or scripting runtimes.); `NSM:Flow` (Inbound to 22/5900/8080 and follow-on internal connections.)
  - *Tune:* `ServicePortSet` — 22, 5900, 8080/8443 by default.; `AllowedAdmins` — MDM/jump-host IPs allowed to manage endpoints.; `TimeWindow` — Default: 10 minutes.

---

### T1534 — Internal Spearphishing
<a id="t1534"></a>

**Detection strategy:** Internal Spearphishing via Trusted Accounts (`DET0054`)  
**Platforms:** Linux, Office Suite, SaaS, Windows, macOS  
**ATT&CK:** [T1534](https://attack.mitre.org/techniques/T1534/) · [detail page](../../techniques/lateral-movement.md#t1534)

- **`AN0147` Analytic 0147** · Windows
  Sequence of internal email sent from a recently compromised user account (preceded by abnormal logon or device activity), with attachments or links leading to execution or credential harvesting. Defender observes: internal mail delivery to peers with high entropy attachments, followed by click events, process initiation, or credential prompts.
  - *Log sources:* `WinEventLog:Security` (EventCode=4624, 4648); `WinEventLog:Security` (EventCode=4625); `WinEventLog:Security` (EventCode=4672); `m365:unified` (SendOnBehalf, MessageSend, ClickThrough, MailItemsAccessed); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `TimeWindow` — Expected time between internal email and link execution or file dropper; `UserContext` — Baseline logon locations and device usage for sender accounts; `AttachmentEntropyThreshold` — Entropy value over which attachment is considered suspicious
- **`AN0148` Analytic 0148** · Linux
  Delivery of suspicious internal communication (e.g., Thunderbird, Evolution) using compromised internal accounts. Sequence of: unexpected user activity + mail transfer logs + download or execution of attachments.
  - *Log sources:* `auditd:SYSCALL` (execve); `Application:Mail` (smtpd$.*$: .*from=[.*@internaldomain.com](mailto:.*@internaldomain.com) to=[.*@internaldomain.com](mailto:.*@internaldomain.com)); `linux:syslog` (curl|wget|python .*http)
  - *Tune:* `SubjectLineAnomaly` — Deviation from typical internal email subjects; `AttachmentType` — Executable types allowed or flagged by mail relay
- **`AN0149` Analytic 0149** · macOS
  Abnormal Apple Mail use, including internal email relays followed by file execution or script events (e.g., attachments launched via Preview, terminal triggered from Mail.app)
  - *Log sources:* `macos:unifiedlog` (com.apple.mail.* exec.*); `macos:unifiedlog` (curl|osascript.*open location)
  - *Tune:* `ExecutionChainDepth` — Number of child processes stemming from Mail.app; `MailScriptFlag` — Toggle on scripting detection within mail context
- **`AN0150` Analytic 0150** · SaaS
  Internal spearphishing via SaaS applications (e.g., Slack, Teams, Gmail): message sent from compromised user with attachment or URL, followed by click and credential access behavior.
  - *Log sources:* `saas:slack` (file_upload, message_send, message_click)
  - *Tune:* `UserAnomalyThreshold` — Volume or timing of messages sent after compromise; `FileRiskScoring` — Whether SaaS DLP assigns risk scores to attachments
- **`AN0151` Analytic 0151** · Office Suite
  Outlook or Word used to forward suspicious internal attachments with macro content. Defender observes attachment forwarding, auto-opening behaviors, or macro prompt interactions.
  - *Log sources:* `m365:unified` (SendOnBehalf, MessageSend, AttachmentPreviewed); `WinEventLog:Security` (EventCode=4103, 4104, 4105, 4106)
  - *Tune:* `MacroExecutionWindow` — Timing between mail open and macro invocation; `AttachmentNameHeuristics` — Patterns of known internal spearphishing lures (e.g., invoice, HR_policy)

---

### T1563 — Remote Service Session Hijacking
<a id="t1563"></a>

**Detection strategy:** Detection of Remote Service Session Hijacking (`DET0079`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1563](https://attack.mitre.org/techniques/T1563/) · [detail page](../../techniques/lateral-movement.md#t1563)

- **`AN0216` Analytic 0216** · Windows
  Detection of anomalous RDP or remote service session activity where a logon session is hijacked rather than newly created. Indicators include mismatched user credentials vs. active session tokens, service session takeovers without corresponding successful logon events, or RDP shadowing activity without user consent.
  - *Log sources:* `WinEventLog:Security` (EventCode=4624, 4648); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `ExpectedUserSessionMap` — Mapping of users to hosts they are expected to access; deviations indicate possible hijacking.; `TimeWindow` — Threshold for detecting rapid pivoting via hijacked sessions.
- **`AN0217` Analytic 0217** · Linux
  Detection of SSH/Telnet session hijacking via discrepancies between authentication logs and active session tables. Adversary behavior includes reusing or stealing active PTY sessions, attaching to screen/tmux, or issuing commands without corresponding login events.
  - *Log sources:* `auditd:SYSCALL` (execve: Commands executed within an SSH session where no matching logon/authentication event exists); `NSM:Connections` (Mismatch between recorded user logon and active sessions (e.g., wtmp/utmp entries without corresponding authentication in auth.log)); `NSM:Flow` (Long-lived or hijacked SSH sessions maintained with no active user activity)
  - *Tune:* `MonitoredServicePorts` — Ports for SSH/Telnet/RDP monitored for session hijacking; may vary by environment.
- **`AN0218` Analytic 0218** · macOS
  Detection of hijacked VNC or SSH sessions on macOS where adversaries take over an existing session rather than authenticating directly. Indicators include process execution from active sessions without new logon events, manipulation of TTY sessions, or anomalous network activity tied to dormant sessions.
  - *Log sources:* `macos:unifiedlog` (Authentication inconsistencies where commands are executed without corresponding login events); `macos:unifiedlog` (Execution of processes linked to hijacked sessions (e.g., anomalous parent-child process lineage)); `NSM:Flow` (Suspicious long-lived or reattached remote desktop sessions from unexpected IPs)
  - *Tune:* `SessionIdleThreshold` — Time threshold for inactive sessions flagged as suspicious when commands suddenly resume.

---

### T1563.001 — SSH Hijacking
<a id="t1563001"></a>

**Detection strategy:** Detection Strategy for SSH Session Hijacking (`DET0256`)  
**Platforms:** Linux, macOS  
**ATT&CK:** [T1563.001](https://attack.mitre.org/techniques/T1563/001/) · [detail page](../../techniques/lateral-movement.md#t1563001)

- **`AN0710` Analytic 0710** · Linux
  Suspicious reuse of SSH agent sockets across multiple users or processes, anomalous access to ~/.ssh/ or /tmp/ssh-* sockets, and abnormal patterns of lateral movement via SSH without new authentication events. Defender view: detect when one process accesses another user's SSH agent or when an existing SSH connection is used to pivot unexpectedly.
  - *Log sources:* `auditd:SYSCALL` (open or connect syscalls on /tmp/ssh-* or $SSH_AUTH_SOCK); `auditd:EXECVE` (Execution of ssh/scp/sftp without corresponding authentication log); `NSM:Connections` (Missing new login event but session activity continues)
  - *Tune:* `UserContext` — Tune alerts for cross-user access to SSH agent sockets.; `TimeWindow` — Correlate lack of authentication with lateral SSH activity within a short timeframe.
- **`AN0711` Analytic 0711** · macOS
  Unusual access to SSH agent sockets in /tmp/ or /private/tmp, process access to another user’s $SSH_AUTH_SOCK, and lateral SSH activity without corresponding login events. Defender view: correlation of socket access with anomalous network flows to internal systems.
  - *Log sources:* `macos:unifiedlog` (Process opening SSH_AUTH_SOCK or /tmp/ssh-* socket not owned by same UID); `macos:unifiedlog` (Execution of ssh or sftp without corresponding login event); `macos:unifiedlog` (Session reuse without new auth event)
  - *Tune:* `SocketPathScope` — Limit detection to monitored SSH agent socket directories.; `BaselineUsers` — Establish normal SSH agent ownership and expected usage for tuning.

---

### T1563.002 — RDP Hijacking
<a id="t1563002"></a>

**Detection strategy:** Detection fo Remote Service Session Hijacking for RDP. (`DET0588`)  
**Platforms:** Windows  
**ATT&CK:** [T1563.002](https://attack.mitre.org/techniques/T1563/002/) · [detail page](../../techniques/lateral-movement.md#t1563002)

- **`AN1620` Analytic 1620** · Windows
  Detection of suspicious use of `tscon.exe` or equivalent methods to hijack legitimate RDP sessions. Defenders can observe anomalies such as session reassignments without corresponding authentication, processes spawned in the context of hijacked sessions, or unusual RDP network traffic flows that deviate from expected baselines.
  - *Log sources:* `WinEventLog:Security` (EventCode=4624, 4648); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:System` (EventCode=7045)
  - *Tune:* `ExpectedRDPHosts` — Whitelist of systems and accounts authorized to use RDP; deviations indicate possible hijacking.; `TimeWindow` — Time threshold for correlating logon events with session reassignment and process execution.; `SessionIDMapping` — Environment-specific mapping of user accounts to session IDs; inconsistencies may reveal hijacking.

---

### T1570 — Lateral Tool Transfer
<a id="t1570"></a>

**Detection strategy:** Detection Strategy for Lateral Tool Transfer across OS platforms (`DET0183`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1570](https://attack.mitre.org/techniques/T1570/) · [detail page](../../techniques/lateral-movement.md#t1570)

- **`AN0516` Analytic 0516** · Windows
  Correlate suspicious file transfers over SMB or Admin$ shares with process creation events (e.g., cmd.exe, powershell.exe, certutil.exe) that do not align with normal administrative behavior. Detect remote file writes followed by execution of transferred binaries.
  - *Log sources:* `WinEventLog:Security` (EventCode=5140); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `TimeWindow` — Time period between file transfer and execution used to correlate events; `UserContext` — Accounts allowed to perform legitimate administrative transfers; `FilePathWhitelist` — Exclude known legitimate software update directories
- **`AN0517` Analytic 0517** · Linux
  Monitor scp, rsync, curl, sftp, or ftp processes initiating transfers to internal systems combined with file creation events in unusual directories. Correlate transfer activity with subsequent execution of those binaries.
  - *Log sources:* `auditd:SYSCALL` (execve: Invocation of scp, rsync, curl, or sftp); `auditd:FILE` (create: New file created in system binaries or temp directories)
  - *Tune:* `AllowedTools` — Define legitimate transfer utilities expected in the environment; `DestinationDirectories` — Restrict to suspicious or non-standard directories for transferred files
- **`AN0518` Analytic 0518** · macOS
  Detect anomalous use of scp, rsync, curl, or third-party sync apps transferring executables into user directories. Correlate new file creation with immediate execution events.
  - *Log sources:* `macos:unifiedlog` (Execution of scp, rsync, curl with remote destination); `macos:unifiedlog` (File created in ~/Library/LaunchAgents or executable directories)
  - *Tune:* `SyncApplications` — Whitelisted apps like Dropbox or OneDrive if sanctioned; `EntropyThreshold` — Adjust threshold for unusual filenames/hashes transferred internally
- **`AN0519` Analytic 0519** · ESXi
  Identify lateral transfer via datastore file uploads or internal scp/ssh sessions that result in new VMX/VMDK or script files. Correlate transfer with VM execution or datastore modification.
  - *Log sources:* `esxi:vmkernel` (Upload of file to datastore); `esxi:hostd` (scp/ssh used to move file across hosts)
  - *Tune:* `DatastoreWhitelist` — Known authorized paths for legitimate VM operations; `TransferProtocol` — Protocols allowed for intra-VM host transfers

---

