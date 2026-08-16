# Exfiltration — Detection Strategies

> MITRE ATT&CK detection strategies and analytics (v18.1) for techniques whose primary tactic is **Exfiltration**. Each analytic lists the **log sources / channels** it needs, the **detection logic**, and the **tunable elements** to adapt it to your environment. Authoritative source: the ATT&CK detection-strategy model in the Enterprise STIX.

See also: [all detection strategies index](README.md) · [Technique Detection Library](../TECHNIQUE_DETECTION_LIBRARY.md) (ready-to-run SIEM queries) · [Data Components & Log Sources](../../ATTACK_DATA_COMPONENTS.md) · [Technique Detail Pages](../../techniques/README.md)

---

### T1011 — Exfiltration Over Other Network Medium
<a id="t1011"></a>

**Detection strategy:** Detection of Exfiltration Over Alternate Network Interfaces (`DET0077`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1011](https://attack.mitre.org/techniques/T1011/) · [detail page](../../techniques/exfiltration.md#t1011)

- **`AN0212` Analytic 0212** · Windows
  Execution of file transfer or network access activity through non-primary interfaces (e.g., WiFi, Bluetooth, cellular) by processes not typically associated with such behavior (e.g., rundll32, powershell, regsvr32).
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:System` (EventCode=5005 (WLAN), EventCode=302 (Bluetooth)); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `InterfaceType` — Filter for specific interface categories (e.g., WiFi, Bluetooth, 4G).; `FileSizeThreshold` — Tunable for environment-specific large file access events pre-transfer.; `TimeWindow` — Temporal correlation window for file read followed by network activity.
- **`AN0213` Analytic 0213** · Linux
  Use of `rfkill`, `nmcli`, or low-level tools (e.g., `iw`, `hcitool`, `pppd`) to enable alternate interfaces followed by data transfer via non-primary NICs.
  - *Log sources:* `auditd:SYSCALL`; `NSM:Flow`
  - *Tune:* `CommandPattern` — Match known interface manipulation utilities or driver invocations.; `NetworkDevice` — Tunable to non-default or rarely used interfaces (e.g., wlan1, hci0).
- **`AN0214` Analytic 0214** · macOS
  AppleScript or system calls to activate WiFi/Bluetooth interfaces (`networksetup`, `blueutil`), followed by exfiltration via AirDrop, cloud sync, or network socket.
  - *Log sources:* `macos:unifiedlog`; `macos:osquery` (process_events); `macos:osquery` (interface_details )
  - *Tune:* `Protocol` — Protocol used for exfil (e.g., AirDrop, mDNS, Apple File Service).; `InterfaceActivityWindow` — Time period between interface activation and transfer.

---

### T1011.001 — Exfiltration Over Bluetooth
<a id="t1011001"></a>

**Detection strategy:** Detection of Bluetooth-Based Data Exfiltration (`DET0554`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1011.001](https://attack.mitre.org/techniques/T1011/001/) · [detail page](../../techniques/exfiltration.md#t1011001)

- **`AN1531` Analytic 1531** · Windows
  Detection of non-interactive or suspicious processes accessing Bluetooth interfaces and transmitting outbound traffic following file access or staging activity.
  - *Log sources:* `WinEventLog:System` (EventCode=8001); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `TimeWindow` — Defines how quickly a file access and Bluetooth activity must occur to be correlated.; `InterfaceType` — May focus on Bluetooth-specific interfaces or drivers like 'bthport.sys'.; `FileSizeThreshold` — Tune to trigger only on significant exfiltratable file reads.
- **`AN1532` Analytic 1532** · Linux
  Use of hcitool, bluetoothctl, or rfcomm to initialize Bluetooth connection paired with recent file reads by the same user or session.
  - *Log sources:* `auditd:SYSCALL`; `linux:syslog`; `linux:osquery`
  - *Tune:* `BluetoothUtility` — List of CLI tools to monitor (e.g., hcitool, rfcomm, obexftp).; `SessionWindow` — Amount of time after interface config a file must be accessed to be linked.
- **`AN1533` Analytic 1533** · macOS
  Observation of `blueutil`/`networksetup` commands or low-level APIs toggling Bluetooth or initiating transfers, especially if paired with recent large file read activity by non-GUI processes.
  - *Log sources:* `macos:unifiedlog`; `macos:osquery`; `macos:osquery`
  - *Tune:* `ProcessContext` — Limit to background processes or scripts with no GUI interaction.; `PayloadType` — Focus on specific sensitive file types (e.g., zip, docx, keychain db).

---

### T1020 — Automated Exfiltration
<a id="t1020"></a>

**Detection strategy:** Automated Exfiltration Detection Strategy (`DET0397`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1020](https://attack.mitre.org/techniques/T1020/) · [detail page](../../techniques/exfiltration.md#t1020)

- **`AN1113` Analytic 1113** · Windows
  Detection of automated tools or scripts periodically transmitting data to external destinations using scheduled tasks or background processes.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `TimeWindow` — Used to detect repeated exfil activity over intervals (e.g., every 5 minutes).; `DestinationIP` — Can be tuned to filter known internal or trusted destinations.
- **`AN1114` Analytic 1114** · Linux
  Background scripts (e.g., via cron) or daemons transmitting data repeatedly to remote IPs or URLs.
  - *Log sources:* `auditd:SYSCALL` (execve); `NSM:Flow` (Outbound Connections)
  - *Tune:* `CronJobInterval` — Tunable time range for recurring tasks seen creating outbound connections.; `UserContext` — Tunable for scope — service accounts vs user accounts.
- **`AN1115` Analytic 1115** · macOS
  Observation of LaunchAgents or LaunchDaemons establishing periodic external connections indicative of automated data transfer.
  - *Log sources:* `macos:unifiedlog` (process: exec); `macos:unifiedlog` (network); `macos:cron` (cron/launchd)
  - *Tune:* `LaunchInterval` — Frequency of task recurrence linked to external communication.; `DestinationPort` — Port number used for detection filtering.

---

### T1020.001 — Traffic Duplication
<a id="t1020001"></a>

**Detection strategy:** Detection Strategy for Traffic Duplication via Mirroring in IaaS and Network Devices (`DET0403`)  
**Platforms:** IaaS, Network Devices  
**ATT&CK:** [T1020.001](https://attack.mitre.org/techniques/T1020/001/) · [detail page](../../techniques/exfiltration.md#t1020001)

- **`AN1131` Analytic 1131** · IaaS
  Configuration changes to virtual TAP/mirror policies that forward traffic to unapproved destinations. Detection correlates management plane API calls with mirrored traffic observation.
  - *Log sources:* `AWS:CloudTrail` (CreateTrafficMirrorSession or ModifyTrafficMirrorTarget); `AWS:VPCFlowLogs` (Traffic observed on mirror destination instance)
  - *Tune:* `TimeWindow` — Detect mirror session creation followed by mirrored traffic within X seconds (e.g., 60s); `MirrorDestinationCIDR` — Define suspicious or external mirror targets (e.g., non-enterprise ranges); `UserIdentity` — Flag traffic mirror activity by non-privileged or unexpected IAM roles
- **`AN1132` Analytic 1132** · Network Devices
  Unauthorized mirroring sessions initiated on routers/switches (e.g., via `monitor session`, `mirror port`) coupled with outbound traffic from mirrored interface to unexpected destinations.
  - *Log sources:* `networkdevice:syslog` (Config change: CLI/NETCONF/SNMP – 'monitor session', 'mirror port'); `networkdevice:Flow` (Traffic from mirrored interface to mirror target IP)
  - *Tune:* `ConfigChangeType` — Tune based on accepted interface config changes (e.g., audit only mirror session creation); `MirrorDestinationPort` — Define high-risk ports used for exfil (e.g., 4443, 8443, 2055); `DeviceRole` — Define whether mirroring is expected on edge vs core vs distribution devices

---

### T1029 — Scheduled Transfer
<a id="t1029"></a>

**Detection strategy:** Detection Strategy for Scheduled Transfer and Recurrent Exfiltration Patterns (`DET0399`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1029](https://attack.mitre.org/techniques/T1029/) · [detail page](../../techniques/exfiltration.md#t1029)

- **`AN1118` Analytic 1118** · Windows
  Recurring network exfiltration initiated by scheduled or script-based processes exhibiting time-based regularity and consistent external destinations.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:System` (EventCode=106, 200)
  - *Tune:* `TimeWindow` — Duration threshold to consider a connection repetitive (e.g., same hour daily); `DestIPAllowlist` — Known external destinations to exclude (e.g., approved SFTP/backup servers); `ParentProcessBaseline` — Allowlisted job runners or scripts known to schedule legitimate transfers
- **`AN1119` Analytic 1119** · Linux
  Detection of cron-based or script-based recurring transfers where the same script, user, or destination reappears at predictable intervals.
  - *Log sources:* `auditd:SYSCALL` (execve); `linux:cron` (cron activity); `NSM:Flow` (Outbound Connections)
  - *Tune:* `ScriptPathRegex` — Path patterns for shell scripts responsible for scheduled transfers; `CronIntervalThreshold` — Minimum repetition frequency (e.g., 24h for daily jobs); `ExfilUserContext` — Suspicious or unexpected users launching scheduled transfers
- **`AN1120` Analytic 1120** · macOS
  LaunchAgent or launchd recurring jobs initiating data transfer to consistent external IPs or domains with repeat timing signatures.
  - *Log sources:* `macos:endpointsecurity` (ES_EVENT_TYPE_NOTIFY_EXEC); `macos:launchd` (launchd.plist and logs); `macos:unifiedlog` (networkd or com.apple.network)
  - *Tune:* `AgentPathPatterns` — Regex for job locations like ~/Library/LaunchAgents/; `RepeatIntervalDelta` — Time-based logic to determine schedule (e.g., ~24h ± 5m); `UserHomeJobs` — Transfers originating from non-admin user context

---

### T1030 — Data Transfer Size Limits
<a id="t1030"></a>

**Detection strategy:** Detection Strategy for Data Transfer Size Limits and Chunked Exfiltration (`DET0213`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1030](https://attack.mitre.org/techniques/T1030/) · [detail page](../../techniques/exfiltration.md#t1030)

- **`AN0596` Analytic 0596** · Windows
  Adversary uses a process to establish outbound connections that transmit uniform packet sizes at a consistent interval, avoiding threshold-based network alerts.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `NSM:Flow` (NetFlow/sFlow/PCAP)
  - *Tune:* `PacketSizeThreshold` — Minimum repetitive size in bytes to consider as anomalous behavior (e.g., 512B or 1024B); `IntervalRepeatWindow` — Timeframe over which repeated, evenly spaced transfers are flagged; `KnownServicePorts` — Common ports expected to exhibit protocol behavior; outliers flagged if not matching expected usage
- **`AN0597` Analytic 0597** · Linux
  Outbound connections from non-network-facing processes repeatedly send similarly sized payloads within uniform time intervals.
  - *Log sources:* `auditd:SYSCALL` (connect/sendto); `NSM:Flow` (Outbound Network Flow)
  - *Tune:* `ProcessNetworkBaseline` — Whitelist of typical binaries expected to generate outbound connections (e.g., wget, curl); `PayloadLengthVariance` — Deviation threshold to consider data 'fixed size' (e.g., ±5% size delta); `RepeatFrequencyThreshold` — Number of observed transfers per minute/hour that signals anomalous repetition
- **`AN0598` Analytic 0598** · macOS
  Processes on macOS initiate external connections that consistently transmit data in fixed sizes using LaunchAgents or unexpected users.
  - *Log sources:* `macos:unifiedlog` (com.apple.network); `macos:endpointsecurity` (ES_EVENT_TYPE_NOTIFY_CONNECT)
  - *Tune:* `LaunchdJobContext` — Agent context in which transfer occurs (e.g., user/privileged); `TransferSizeMedian` — Used to define what constitutes 'fixed size' chunks; `TransferProtocolOutlier` — Detect if protocol usage deviates from common apps for given destination

---

### T1041 — Exfiltration Over C2 Channel
<a id="t1041"></a>

**Detection strategy:** Detection Strategy for Exfiltration Over C2 Channel (`DET0348`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1041](https://attack.mitre.org/techniques/T1041/) · [detail page](../../techniques/exfiltration.md#t1041)

- **`AN0988` Analytic 0988** · Windows
  Identifies suspicious outbound traffic volume mismatches from processes that typically do not generate network activity, particularly over C2 protocols like HTTPS, DNS, or custom TCP/UDP ports, following file or data access.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=3, 22); `NSM:Flow` (Flow/PCAP analysis for outbound payloads); `WinEventLog:Security` (EventCode=4663, 4670, 4656)
  - *Tune:* `DataVolumeThreshold` — Set threshold for outbound transfer size exceeding typical C2 traffic (e.g., >1MB in <5min).; `KnownBenignProcesses` — List of approved processes that may exhibit high outbound traffic (e.g., updates).
- **`AN0989` Analytic 0989** · Linux
  Monitors for processes reading sensitive files then immediately initiating unusual outbound connections or bulk transfer sessions over persistent sockets, particularly with encrypted or binary payloads.
  - *Log sources:* `auditd:SYSCALL` (execve); `auditd:SYSCALL` (connect); `NSM:Flow` (conn.log + files.log + ssl.log); `NSM:Flow` (session stats with bytes_out > bytes_in)
  - *Tune:* `OutboundEntropyScore` — Threshold for high-entropy payloads indicative of encoded or encrypted exfil data.; `ConnectionDuration` — Defines length of time over which transfer size must be aggregated to trigger detection.
- **`AN0990` Analytic 0990** · macOS
  Detects unauthorized applications or scripts accessing sensitive data followed by establishing encrypted outbound communication to rare external destinations or with abnormal byte ratios.
  - *Log sources:* `macos:unifiedlog` (eventMessage = 'open', 'sendto', 'connect'); `macos:osquery` (socket_events); `macos:osquery` (process_events)
  - *Tune:* `ParentProcessAncestry` — Enables defenders to tune legitimate vs. suspicious lineage (e.g., launchd → curl is uncommon).; `ProtocolList` — Focus detection on unusual protocols (e.g., IRC, FTP, DNS over HTTPS).
- **`AN0991` Analytic 0991** · ESXi
  Detects VMs sending outbound traffic through non-standard services or to unknown destinations. Exfiltration over reverse shells tunneled via VMkernel or custom payloads routed via hostd/vpxa.
  - *Log sources:* `esxi:vpxa` (connection attempts and data transmission logs); `esxi:vmkernel` (network stack module logs); `esxi:syslog` (guest OS outbound transfer logs)
  - *Tune:* `GuestOSAllowList` — Limit detection to sensitive or externally-exposed VMs handling confidential data.; `TransferSizeThresholdMB` — Minimum outbound transfer size before flagging anomalous C2-based exfiltration.; `ProtocolAllowList` — Define expected protocols for outbound data (e.g., disallow FTP/SCP over high ports).

---

### T1048 — Exfiltration Over Alternative Protocol
<a id="t1048"></a>

**Detection strategy:** Behavioral Detection Strategy for Exfiltration Over Alternative Protocol (`DET0131`)  
**Platforms:** ESXi, IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1048](https://attack.mitre.org/techniques/T1048/) · [detail page](../../techniques/exfiltration.md#t1048)

- **`AN0367` Analytic 0367** · Windows
  Detects unusual outbound file transfer behavior using protocols like FTP, SMB, SMTP, or DNS, involving non-standard processes, off-hour activity, or uncommonly high volume.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Security` (EventCode=4688)
  - *Tune:* `DataVolumeThresholdMB` — Set threshold for outbound volume (e.g., >50MB in a single connection).; `ProtocolAllowList` — Allow-listed protocols in use for specific machines or users (e.g., FTP allowed for backups).; `TimeWindow` — Define allowed time-of-day windows (e.g., flag after-hours file transfer).; `ParentProcessAnomaly` — Identify anomalous parent-child process relationships (e.g., `winword.exe` spawning `ftp.exe`).
- **`AN0368` Analytic 0368** · Linux
  Detects file exfiltration using tools like curl, scp, or custom binaries over protocols such as FTP, HTTP/S, or DNS tunneling, especially outside baseline user behavior.
  - *Log sources:* `auditd:SYSCALL` (execve); `auditd:SYSCALL` (connect); `auditd:SYSCALL` (open); `auditd:SYSCALL` (write); `NSM:Flow` (NetFlow/Zeek conn.log)
  - *Tune:* `ProtocolType` — Flag unexpected protocols (e.g., HTTP on port 53 or FTP traffic from non-standard tools).; `UserContext` — Scope for privilege escalation or service account behavior.; `FileExtensionSensitivity` — Track movement of file types of interest (e.g., `.csv`, `.sql`, `.key`).
- **`AN0369` Analytic 0369** · macOS
  Detects non-native file transfer via curl, Python scripts, or AppleScript using uncommon protocols like FTP, SMTP, or DNS exfiltration through mDNSResponder abuse.
  - *Log sources:* `macos:unifiedlog` (log stream (subsystem: com.apple.system.networking)); `macos:osquery` (process_events); `macos:osquery` (file_events)
  - *Tune:* `ProtocolUnusualnessScore` — Weight rarely-used protocols in user space.; `ExecutableBaselining` — Track which binaries usually call curl/nc and alert on deviation.
- **`AN0370` Analytic 0370** · IaaS
  Detects access to cloud APIs or CLI tools to move or sync files from sensitive buckets to external endpoints using protocols like HTTPS or S3 APIs.
  - *Log sources:* `AWS:CloudTrail` (GetObject, CopyObject); `AWS:VPCFlowLogs` (Outbound data flows)
  - *Tune:* `IAMRoleContext` — Detect unauthorized use of roles for cloud storage manipulation.; `GeoDestinationThreshold` — Alert on outbound flows to geo-locations not seen in training baseline.
- **`AN0371` Analytic 0371** · ESXi
  Detects outbound traffic from hostd/vpxa or guest VM interfaces using unauthorized protocols such as FTP, HTTP POST bursts, or long-lived DNS tunnels.
  - *Log sources:* `esxi:hostd` (logline inspection); `esxi:vmkernel` (protocol egress)
  - *Tune:* `GuestTrafficBaseline` — Expected protocols used by VMs attached to host interfaces.; `ServiceAccountProfile` — Unexpected network activity from hypervisor processes or monitoring agents.

---

### T1048.001 — Exfiltration Over Symmetric Encrypted Non-C2 Protocol
<a id="t1048001"></a>

**Detection strategy:** Behavioral Detection Strategy for Exfiltration Over Symmetric Encrypted Non-C2 Protocol (`DET0503`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1048.001](https://attack.mitre.org/techniques/T1048/001/) · [detail page](../../techniques/exfiltration.md#t1048001)

- **`AN1389` Analytic 1389** · Windows
  Detects the execution of non-browser processes establishing outbound encrypted network connections using uncommon symmetric encryption protocols (e.g., AES via PowerShell or custom scripts) to alternate external destinations.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `PayloadEntropyThreshold` — Flag high-entropy payloads sent over unexpected protocols.; `TimeWindow` — Define allowable transfer window (e.g., abnormal traffic outside business hours).; `ExecutableAllowlist` — List of known-good binaries for encrypted traffic (e.g., Chrome, Outlook).
- **`AN1390` Analytic 1390** · Linux
  Detects command-line utilities or scripts using encryption libraries or symmetric algorithms (e.g., OpenSSL AES, GPG, Python + PyCrypto) in conjunction with outbound file transfers or traffic to external destinations.
  - *Log sources:* `auditd:SYSCALL` (execve); `auditd:SYSCALL` (connect); `NSM:Flow` (conn.log or flow data); `NSM:Flow` (ssl.log (for TLS handshake analysis), dns.log (tunneling indicators))
  - *Tune:* `FileTransferIndicator` — Threshold for transferred data size or extension type.; `LibraryCallTracking` — Hooks into use of encryption libraries like `libcrypto.so`, `pycrypto`, `gpg`.
- **`AN1391` Analytic 1391** · macOS
  Detects symmetric key-based encryption operations (e.g., AES via Python, AppleScript, or OpenSSL) followed by unusual outbound connections from non-browser applications or scripted tools.
  - *Log sources:* `macos:unifiedlog` (log stream process subsystem); `macos:osquery` (socket_events); `macos:unifiedlog` (log stream network activity)
  - *Tune:* `ApplicationProfileBaseline` — Expected outbound connection profiles per app.; `EncryptionRoutinePattern` — Indicators of manual encryption operations (e.g., script strings invoking AES).
- **`AN1392` Analytic 1392** · ESXi
  Detects unexpected encrypted egress traffic from management services (e.g., hostd) or guest VMs utilizing symmetric encryption without traditional protocols (e.g., FTP with embedded AES ciphertext).
  - *Log sources:* `esxi:vmkernel` (egress log analysis); `esxi:hostd` (execution + payload hints); `NSM:Flow` (host switch egress data)
  - *Tune:* `GuestVMExfilWatchlist` — VMs with data sensitivity labels or outside normal behavior.; `ServiceEgressProfile` — Expected egress destinations and volume for core services.

---

### T1048.002 — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
<a id="t1048002"></a>

**Detection strategy:** Detection of Exfiltration Over Asymmetric Encrypted Non-C2 Protocol (`DET0512`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1048.002](https://attack.mitre.org/techniques/T1048/002/) · [detail page](../../techniques/exfiltration.md#t1048002)

- **`AN1413` Analytic 1413** · Windows
  Detects non-browser processes that establish encrypted outbound connections (e.g., TLS/SSL) to unfamiliar or atypical destinations for the host/user, following a data staging or compression event.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Security` (EventCode=4663, 4670, 4656); `NSM:Flow` (ssl.log - Certificate Analysis)
  - *Tune:* `TimeWindow` — Correlates file access, encryption, and network transmission within a timeframe (e.g., 5 minutes).; `CertificateIssuerDenylist` — Blocks or flags untrusted certificate authorities in SSL/TLS handshakes.; `BinaryAllowlist` — Whitelist for known-good applications allowed to use encrypted outbound traffic.
- **`AN1414` Analytic 1414** · Linux
  Detects staged file access (e.g., archive or obfuscation), followed by an encrypted outbound connection (TLS/HTTPS) from unusual processes such as curl/wget, Python scripts, or custom binaries.
  - *Log sources:* `auditd:SYSCALL` (execve); `auditd:SYSCALL` (connect); `NSM:Flow` (ssl.log, conn.log); `auditd:SYSCALL` (open, read)
  - *Tune:* `ConnectionDestinationScope` — Restrict outbound connections to non-corporate domains or IPs.; `FileAccessExtensionList` — List of extensions considered sensitive or exfil-worthy (e.g., .zip, .db, .xlsx).; `SSLClientProcessBaseline` — Define normal encrypted-traffic-capable binaries.
- **`AN1415` Analytic 1415** · macOS
  Detects abnormal encrypted network connections (via TLS/HTTPS) initiated by non-browser binaries, particularly after sensitive file access or compression events.
  - *Log sources:* `macos:osquery` (socket_events); `macos:osquery` (process_events); `macos:unifiedlog` (log stream - file provider subsystem); `NSM:Flow` (ssl.log, x509.log)
  - *Tune:* `OutboundTrafficVolumeThreshold` — Trigger detection for large amounts of outbound encrypted data.; `FileSensitivityContext` — Tagging and prioritizing high-value directories/files in detection logic.
- **`AN1416` Analytic 1416** · ESXi
  Detects unexpected encrypted outbound connections from management components or guest VMs using TLS, particularly after data volume spikes or script-based orchestration from within guest environments.
  - *Log sources:* `esxi:hostd` (event stream); `esxi:vmkernel` (egress logs)
  - *Tune:* `VMToEgressPathWatchlist` — Expected traffic routes for monitored VMs.; `TLSClientAppIdentifier` — Applications allowed to initiate TLS sessions from hypervisor level.

---

### T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol
<a id="t1048003"></a>

**Detection strategy:** Detection of Exfiltration Over Unencrypted Non-C2 Protocol (`DET0149`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1048.003](https://attack.mitre.org/techniques/T1048/003/) · [detail page](../../techniques/exfiltration.md#t1048003)

- **`AN0423` Analytic 0423** · Windows
  Detects data access or staging events followed by outbound data flows using unencrypted protocols (e.g., FTP, HTTP) initiated by unexpected processes or to rare destinations.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Security` (EventCode=4663, 4670, 4656); `NSM:Flow` (http.log, ftp.log)
  - *Tune:* `UnencryptedProtocolList` — Set of protocols considered suspicious for outbound data exfiltration (e.g., FTP, HTTP).; `DataTransferSizeThreshold` — Defines what amount of outbound data is considered abnormal for a host/user.; `ParentProcessDenylist` — Processes that should not launch FTP/HTTP clients (e.g., winword.exe launching ftp.exe).
- **`AN0424` Analytic 0424** · Linux
  Detects file access or compression utilities followed by outbound connections using curl, wget, ftp, or custom binaries communicating over unencrypted protocols.
  - *Log sources:* `auditd:SYSCALL` (execve); `auditd:SYSCALL` (connect); `NSM:Flow` (http.log, ftp.log); `NSM:Flow` (flow records)
  - *Tune:* `SensitiveDirectoryWatchlist` — Flag access to paths known to store sensitive or regulated data.; `ProcessBaseline` — Define which binaries are allowed to communicate externally using HTTP/FTP.; `TimeWindow` — Correlates process/file/network within a defined time window.
- **`AN0425` Analytic 0425** · macOS
  Detects abnormal outbound HTTP/FTP connections by local scripts or binaries outside of standard browser activity, following access to local documents or user data.
  - *Log sources:* `macos:osquery` (socket_events); `macos:osquery` (process_events); `macos:unifiedlog` (log stream - file subsystem); `NSM:Flow` (http.log, ftp.log)
  - *Tune:* `ScriptedClientAllowlist` — Defines allowed automated agents that may transmit HTTP or FTP data (e.g., backup tools).; `PayloadInspectionKeywordList` — Terms or patterns indicating structured or sensitive data leaving via HTTP/FTP.
- **`AN0426` Analytic 0426** · ESXi
  Detects shell-based scripts accessing configuration files or snapshots and transmitting them over unencrypted protocols such as FTP or HTTP to non-management IPs.
  - *Log sources:* `esxi:hostd` (event stream); `NSM:Flow` (flow records); `NSM:Flow` (http.log)
  - *Tune:* `VMConfigAccessPathWatchlist` — Locations of VMX/CFG/SNAPSHOT files that should not be accessed by non-admin shells.; `OutboundProtocolProfile` — Expected network protocols for guest and host interfaces.
- **`AN0427` Analytic 0427** · Network Devices
  Detects use of unencrypted protocols (e.g., TFTP, FTP, HTTP) to transfer configuration files, routing tables, or logs to untrusted IP addresses, especially using administrative commands like `copy run ftp:`.
  - *Log sources:* `networkdevice:cli` (CLI command logs); `networkdevice:syslog` (flow records); `NSM:Flow` (PCAP inspection)
  - *Tune:* `ProtocolCommandWatchlist` — Flag commands like `copy`, `archive tar`, or `upload` directed at external hosts.; `DestinationIPBlocklist` — Define external IP ranges unauthorized to receive router/switch configs.

---

### T1052 — Exfiltration Over Physical Medium
<a id="t1052"></a>

**Detection strategy:** Detection of Data Exfiltration via Removable Media (`DET0123`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1052](https://attack.mitre.org/techniques/T1052/) · [detail page](../../techniques/exfiltration.md#t1052)

- **`AN0342` Analytic 0342** · Windows
  Detects removable drive insertion followed by unusual file access, compression, or staging activity by unauthorized users or unexpected processes.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:System` (EventCode=1006, 10001)
  - *Tune:* `DriveTypeFilter` — Filter on removable (e.g., USB) drives only.; `ProcessNameExclusionList` — Exclude known, approved backup or sync utilities.; `TimeWindow` — Limit correlation of file access and device mount to a defined window (e.g., <5 minutes).
- **`AN0343` Analytic 0343** · Linux
  Detects mounted external devices (via /media or /mnt) followed by large file read or copy operations by shell scripts, unauthorized users, or staging tools (e.g., tar, rsync).
  - *Log sources:* `auditd:SYSCALL` (open); `auditd:SYSCALL` (device event logs)
  - *Tune:* `MountPointPattern` — Monitor mount points like /media, /mnt, or /run/media.; `UserGroupScope` — Restrict detection to non-root or unexpected users.; `AccessVolumeThreshold` — Alert on large file access or copy events.
- **`AN0344` Analytic 0344** · macOS
  Detects mounting of external volumes followed by high-volume or sensitive file access via Finder, terminal, or third-party apps (e.g., rsync, zip).
  - *Log sources:* `macos:unifiedlog` (Volume Mount + File Read); `macos:osquery` (file_events); `fs:fsusage` (file system activity monitor)
  - *Tune:* `VolumeNamePattern` — Detect suspicious or unrecognized drive labels (e.g., UNTITLED, BACKUP_VOL).; `ProcessOrigin` — Detect CLI-based copy operations vs. expected GUI usage.; `UserSessionCheck` — Alert if process and session context are mismatched (e.g., script from screensaver context).

---

### T1052.001 — Exfiltration over USB
<a id="t1052001"></a>

**Detection strategy:** Detection of USB-Based Data Exfiltration (`DET0220`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1052.001](https://attack.mitre.org/techniques/T1052/001/) · [detail page](../../techniques/exfiltration.md#t1052001)

- **`AN0616` Analytic 0616** · Windows
  Detects USB device insertion followed by high-volume or sensitive file access and staging activity by suspicious processes or accounts.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:System` (EventCode=2003)
  - *Tune:* `SensitiveFilePathRegex` — Match data staging or export paths (e.g., *.docx, *.csv, *.db) to USB volume letters.; `UserContext` — Limit to users who do not normally use removable devices (e.g., service accounts).; `TimeWindow` — Correlate events within a short period following USB insert (e.g., 5–10 minutes).
- **`AN0617` Analytic 0617** · Linux
  Detects USB block device mount followed by file access in sensitive directories or high-volume copy operations by user-controlled processes.
  - *Log sources:* `auditd:SYSCALL` (open, read); `auditd:SYSCALL` (Kernel Device Events - USB Block Devices)
  - *Tune:* `MountPath` — Look for /media/, /mnt/, /run/media/ paths associated with removable storage.; `CopyCommandSignature` — Detect rsync, cp, tar, zip activity writing to USB mount point.; `AccessRateThreshold` — Define abnormal access patterns (e.g., >100 files in <5 min).
- **`AN0618` Analytic 0618** · macOS
  Detects external volume mount with Finder, Terminal, or script-initiated file copy from user profiles, sensitive folders, or cloud storage sync directories to USB.
  - *Log sources:* `macos:unifiedlog` (Volume Mount + Process Trace + File Read); `fs:fsusage` (Disk Activity Tracing); `macos:osquery` (process_events)
  - *Tune:* `DriveLabelFilter` — Flag removable volumes with suspicious or default names (e.g., NO NAME, BACKUP_01).; `ScriptExecutionContext` — Watch for shell or AppleScript execution tied to USB copy.; `VolumeMountFrequency` — Detect repeated or abnormal device mounts during work hours.

---

### T1537 — Transfer Data to Cloud Account
<a id="t1537"></a>

**Detection strategy:** Cross-Platform Detection of Data Transfer to Cloud Account (`DET0573`)  
**Platforms:** IaaS, Office Suite, SaaS  
**ATT&CK:** [T1537](https://attack.mitre.org/techniques/T1537/) · [detail page](../../techniques/exfiltration.md#t1537)

- **`AN1580` Analytic 1580** · IaaS
  Detects snapshot sharing, backup exports, or data object transfers from victim-owned cloud accounts to other cloud identities within the same provider (e.g., AWS, Azure) using snapshot sharing, S3 bucket policy updates, or SAS URI generation.
  - *Log sources:* `AWS:CloudTrail` (ModifySnapshotAttribute); `AWS:CloudTrail` (PutBucketPolicy); `AWS:CloudTrail` (CreateSnapshot); `AWS:CloudTrail` (CopySnapshot); `AWS:VPCFlowLogs` (High volume internal-to-internal IP transfer or cross-account cloud transfer)
  - *Tune:* `CrossAccountIDList` — List of external cloud accounts authorized for snapshot or bucket sharing; `Region` — Geographic region in which the sharing occurs (may impact logging availability); `VolumeSizeThresholdGB` — Threshold to alert on snapshot size or object volume; `TimeWindow` — Temporal window between snapshot creation and external sharing
- **`AN1581` Analytic 1581** · Office Suite
  Detects user activity that shares or syncs files with external domains via link generation, OneDrive external sharing, or file transfer actions involving non-whitelisted partner tenants.
  - *Log sources:* `m365:unified` (SharingSet); `m365:unified` (AnonymousLinkCreated); `m365:unified` (FileAccessed)
  - *Tune:* `ExternalDomainList` — Known partner or adversarial cloud identities/domains; `TimeWindow` — Duration between file access and external sharing; `SharingMethod` — Type of link (anonymous, internal, organization-wide) to alert on
- **`AN1582` Analytic 1582** · SaaS
  Detects use of built-in SaaS sharing mechanisms to transfer ownership or share access of critical data to external tenants or untrusted users through API calls or link generation features.
  - *Log sources:* `saas:googledrive` (drive.permission.add); `saas:box` (collaboration.invite)
  - *Tune:* `UserContext` — Whether the user is in a high-privileged or VIP group; `DomainReputationList` — Allowlist or blocklist of external SaaS domains; `PayloadVolumeThreshold` — Size or number of shared files triggering alert

---

### T1567 — Exfiltration Over Web Service
<a id="t1567"></a>

**Detection strategy:** Detection Strategy for Exfiltration Over Web Service (`DET0548`)  
**Platforms:** ESXi, Linux, SaaS, Windows, macOS  
**ATT&CK:** [T1567](https://attack.mitre.org/techniques/T1567/) · [detail page](../../techniques/exfiltration.md#t1567)

- **`AN1511` Analytic 1511** · Windows
  Processes that normally do not initiate network communications suddenly making outbound HTTPS connections with high outbound-to-inbound data ratios. Defender view: correlation between process creation logs (e.g., Word, Excel, PowerShell) and subsequent anomalous network traffic volumes toward common web services (Dropbox, Google Drive, OneDrive).
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `MonitoredServices` — List of legitimate web services to baseline (Dropbox, OneDrive, Google Drive).; `ExfilVolumeThreshold` — Outbound data threshold for flagging unusual activity, tunable by environment.; `TimeWindow` — Aggregation period to calculate anomalies in outbound data volume.
- **`AN1512` Analytic 1512** · Linux
  Processes (tar, curl, python scripts) accessing large file sets and initiating outbound HTTPS POST requests with payload sizes inconsistent with baseline activity. Defender perspective: detect abnormal sequence of file archival followed by encrypted uploads to external web services.
  - *Log sources:* `auditd:EXECVE` (curl or wget with POST/PUT options); `auditd:SYSCALL` (open/read of sensitive directories (/etc, /home/*)); `NSM:Flow` (sustained outbound HTTPS sessions with high data volume)
  - *Tune:* `MonitoredTools` — Suspicious command-line utilities used for exfiltration (curl, wget, python).; `DataVolumeThreshold` — Bytes transferred threshold per session to flag unusual uploads.
- **`AN1513` Analytic 1513** · macOS
  Office apps or scripts writing files followed by xattr manipulation (to evade quarantine) and subsequent HTTPS uploads. Defender perspective: anomalous file modification + outbound TLS traffic originating from non-networking apps (Word, Excel, Preview).
  - *Log sources:* `macos:unifiedlog` (execution of Office binaries with network activity); `macos:unifiedlog` (read/write of user documents prior to upload); `macos:unifiedlog` (outbound TLS connections to cloud storage providers)
  - *Tune:* `WatchedApplications` — Applications not expected to perform bulk data transfers (Office apps, Preview).
- **`AN1514` Analytic 1514** · SaaS
  Abnormal API calls from user accounts invoking file upload endpoints outside normal baselines (M365, Google Drive, Box). Defender perspective: monitor unified audit logs for elevated frequency of Upload, Create, or Copy operations from compromised accounts.
  - *Log sources:* `m365:unified` (FileUploaded or FileCopied events); `saas:box` (API calls exceeding baseline thresholds)
  - *Tune:* `APICallThreshold` — Maximum number of API calls per user/session before triggering alert.; `UserBaselineProfiles` — Baseline normal data transfer patterns by user/role.
- **`AN1515` Analytic 1515** · ESXi
  ESXi guest OS or management interface processes establishing unexpected external HTTPS connections. Defender perspective: monitor vmx or hostd processes making outbound web requests with significant data transfer.
  - *Log sources:* `esxi:vmkernel` (network session initiation with external HTTPS services); `esxi:hostd` (file copy or datastore upload via HTTPS)
  - *Tune:* `DatastoreTransferThreshold` — Threshold for outbound transfers from ESXi datastores.

---

### T1567.001 — Exfiltration to Code Repository
<a id="t1567001"></a>

**Detection strategy:** Detection Strategy for Exfiltration to Code Repository (`DET0318`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1567.001](https://attack.mitre.org/techniques/T1567/001/) · [detail page](../../techniques/exfiltration.md#t1567001)

- **`AN0895` Analytic 0895** · Windows
  Processes such as PowerShell, Git, or curl initiating outbound HTTPS POST requests to known code repository APIs (e.g., github.com, gitlab.com) immediately following large file reads. Defender view: correlation between file access of sensitive directories (e.g., Documents, Finance) and abnormal data uploads to repository domains.
  - *Log sources:* `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `MonitoredDomains` — List of external code repository domains to monitor (github.com, gitlab.com, bitbucket.org).; `ExfilVolumeThreshold` — Threshold for outbound data volume per session to flag suspicious uploads.
- **`AN0896` Analytic 0896** · Linux
  Processes like git, curl, or python scripts executing commands that package files (tar, gzip) followed by HTTPS uploads to code repository endpoints. Defender view: detect unusual git push activity or scripted HTTPS requests outside normal developer work hours.
  - *Log sources:* `auditd:EXECVE` (git push, curl -X POST); `auditd:SYSCALL` (open/read of sensitive directories); `NSM:Flow` (large outbound HTTPS uploads to repo domains)
  - *Tune:* `WorkHours` — Baseline normal developer activity periods to reduce false positives.; `RepoDomainList` — Known allowed internal or external repository domains.
- **`AN0897` Analytic 0897** · macOS
  Office or scripting applications initiating unusual HTTPS traffic to code repository APIs with high outbound-to-inbound ratios. Defender perspective: monitor for sensitive file access in combination with network connections to github.com, gitlab.com, or bitbucket.org.
  - *Log sources:* `macos:unifiedlog` (execution of curl, git, or Office processes with network connections); `macos:unifiedlog` (read of user document directories); `macos:unifiedlog` (outbound HTTPS connections to code repository APIs)
  - *Tune:* `MonitoredApplications` — Applications not expected to upload large data sets to repos (Word, Excel, Preview).
- **`AN0898` Analytic 0898** · ESXi
  ESXi host processes (vmx, hostd) initiating HTTPS sessions toward external code repositories. Defender perspective: detect datastore reads followed by outbound web traffic inconsistent with administrative baselines.
  - *Log sources:* `esxi:hostd` (datastore file access); `esxi:vmkernel` (HTTPS traffic to repository domains)
  - *Tune:* `DatastoreTransferThreshold` — Amount of data moved from datastore to external services before raising alert.

---

### T1567.002 — Exfiltration to Cloud Storage
<a id="t1567002"></a>

**Detection strategy:** Detection Strategy for Exfiltration to Cloud Storage (`DET0570`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1567.002](https://attack.mitre.org/techniques/T1567/002/) · [detail page](../../techniques/exfiltration.md#t1567002)

- **`AN1571` Analytic 1571** · Windows
  Unusual processes (e.g., powershell.exe, excel.exe) accessing large local files and subsequently initiating HTTPS POST requests to domains associated with cloud storage services (e.g., dropbox.com, drive.google.com, box.com). Defender perspective: correlation between file reads in sensitive directories and high outbound traffic volume to known storage APIs.
  - *Log sources:* `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `CloudStorageDomains` — List of monitored domains for cloud services (dropbox.com, drive.google.com, onedrive.live.com).; `ExfilVolumeThreshold` — Data volume threshold (e.g., >10MB in single session) used to flag abnormal transfers.; `UserContext` — User accounts permitted to use sanctioned cloud services versus unexpected accounts.
- **`AN1572` Analytic 1572** · Linux
  Processes such as curl, wget, rclone, or custom scripts executing uploads to cloud storage endpoints. Defender perspective: detect chained events where tar/gzip is executed to compress files followed by HTTPS PUT/POST requests to known storage services.
  - *Log sources:* `auditd:EXECVE` (curl -T, rclone copy); `auditd:SYSCALL` (read/open of sensitive file directories); `NSM:Flow` (large HTTPS outbound uploads)
  - *Tune:* `AllowedTools` — Known tools used legitimately for backups (rclone, gsutil). Deviations raise suspicion.; `WorkHours` — Baseline normal data transfer hours to reduce false positives.
- **`AN1573` Analytic 1573** · macOS
  Applications or scripts invoking cloud storage APIs (Dropbox sync, iCloud, Google Drive client) in unexpected contexts. Defender perspective: detect sensitive file reads by non-standard applications followed by unusual encrypted uploads to external cloud storage domains.
  - *Log sources:* `macos:unifiedlog` (execution of curl, rclone, or Office apps invoking network sessions); `macos:unifiedlog` (file read of sensitive directories); `macos:unifiedlog` (outbound HTTPS connections to cloud storage APIs)
  - *Tune:* `WatchedApps` — Track processes that normally should not upload data (e.g., Preview, Calculator).; `EntropyThreshold` — High-entropy file uploads may indicate encrypted payloads designed for exfiltration.
- **`AN1574` Analytic 1574** · ESXi
  Unusual ESXi processes (vmx, hostd) reading datastore files and generating outbound HTTPS traffic toward external cloud storage endpoints. Defender perspective: anomalous datastore activity followed by network transfers to Dropbox, AWS S3, or other storage services.
  - *Log sources:* `esxi:hostd` (datastore file access); `esxi:vmkernel` (network flows to external cloud services)
  - *Tune:* `DatastoreTransferThreshold` — Threshold for outbound data exfiltration from ESXi datastore files.; `ApprovedStorageServices` — Whitelist of sanctioned storage providers used by admins for backup operations.

---

### T1567.003 — Exfiltration to Text Storage Sites
<a id="t1567003"></a>

**Detection strategy:** Detection Strategy for Exfiltration to Text Storage Sites (`DET0284`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1567.003](https://attack.mitre.org/techniques/T1567/003/) · [detail page](../../techniques/exfiltration.md#t1567003)

- **`AN0787` Analytic 0787** · Windows
  Unexpected processes (e.g., powershell.exe, wscript.exe, office apps) initiating HTTP POST/PUT requests to text storage domains like pastebin.com or hastebin.com, particularly when preceded by file access in sensitive directories. Defender perspective: correlation of process lineage, large clipboard/file read operations, and outbound uploads to text storage services.
  - *Log sources:* `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `TextStorageDomains` — Domains to monitor such as pastebin.com, hastebin.com, ghostbin.com.; `UploadSizeThreshold` — Minimum data size (e.g., >500KB) to trigger alerts for suspicious uploads.; `UserContext` — User accounts with legitimate business justification for posting to text storage sites.
- **`AN0788` Analytic 0788** · Linux
  Use of curl, wget, or custom scripts to POST data to pastebin-like services. Defender perspective: identify chained behavior where files are compressed/read followed by HTTPS POST requests to text-sharing endpoints.
  - *Log sources:* `auditd:EXECVE` (curl -d, wget --post-data); `auditd:SYSCALL` (read/open of sensitive file directories); `NSM:Flow` (large HTTPS POST requests to text storage domains)
  - *Tune:* `AllowedTools` — Whitelist of tools (e.g., curl for package repos) to reduce false positives.; `WorkHours` — Expected time ranges for developer interactions with external paste sites.
- **`AN0789` Analytic 0789** · macOS
  Processes such as osascript, curl, or office applications sending data to text storage APIs/domains. Defender perspective: anomalous clipboard or file reads by unexpected applications immediately followed by outbound HTTPS requests to pastebin-like services.
  - *Log sources:* `macos:unifiedlog` (execution of curl, osascript, or unexpected Office processes); `macos:unifiedlog` (file read of sensitive directories); `macos:unifiedlog` (HTTPS POST requests to pastebin.com or similar)
  - *Tune:* `WatchedApps` — Processes not normally associated with data uploads (e.g., Preview, Calculator).; `EntropyThreshold` — High entropy detection to flag encoded or encrypted data exfiltration.
- **`AN0790` Analytic 0790** · ESXi
  ESXi services (vmx, hostd) generating outbound HTTPS POST requests to text storage sites. Defender perspective: anomalous datastore or log reads chained with traffic to pastebin-like destinations.
  - *Log sources:* `esxi:hostd` (datastore/log file access); `esxi:vmkernel` (HTTPS POST connections to pastebin-like domains)
  - *Tune:* `DatastoreExfilThreshold` — Threshold of bytes exfiltrated from ESXi datastore files.; `ApprovedDestinations` — Whitelist of domains approved for API communication to prevent false positives.

---

### T1567.004 — Exfiltration Over Webhook
<a id="t1567004"></a>

**Detection strategy:** Detection Strategy for Exfiltration Over Webhook (`DET0153`)  
**Platforms:** ESXi, Linux, SaaS, Windows, macOS  
**ATT&CK:** [T1567.004](https://attack.mitre.org/techniques/T1567/004/) · [detail page](../../techniques/exfiltration.md#t1567004)

- **`AN0436` Analytic 0436** · Windows
  Unusual processes (e.g., powershell.exe, wscript.exe, mshta.exe) posting data to webhook endpoints (Discord, Slack, webhook.site) using HTTP POST/PUT requests. Defender perspective: suspicious process lineage followed by outbound HTTPS traffic to webhook domains.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Security` (EventCode=4663, 4670, 4656)
  - *Tune:* `WebhookDomains` — Domains to monitor such as discord.com/api/webhooks, slack.com/api, webhook.site.; `UploadSizeThreshold` — Threshold for abnormal data sent via webhook requests.; `ApprovedApps` — List of approved business apps using webhooks to reduce noise.
- **`AN0437` Analytic 0437** · Linux
  Processes such as curl, wget, or custom scripts initiating POST requests to webhook endpoints with encoded or bulk data. Defender perspective: abnormal chaining of file compression or access followed by outbound data to webhook URLs.
  - *Log sources:* `auditd:EXECVE` (curl -X POST, wget --post-data); `auditd:SYSCALL` (read/open of sensitive files); `NSM:Flow` (large HTTPS POST requests to webhook endpoints)
  - *Tune:* `AllowedTools` — Expected command-line utilities allowed to interact with webhooks in enterprise environments.; `TimeWindow` — Expected timeframe for legitimate webhook traffic (e.g., CI/CD deployments).
- **`AN0438` Analytic 0438** · macOS
  Unexpected apps or scripts (osascript, curl, Automator workflows) exfiltrating data via webhooks. Defender perspective: correlation of clipboard/file read operations followed by HTTPS POST traffic to webhook services.
  - *Log sources:* `macos:unifiedlog` (execution of osascript, curl, or unexpected automation); `macos:unifiedlog` (file read of sensitive directories); `macos:unifiedlog` (HTTPS POST to known webhook URLs)
  - *Tune:* `WebhookEndpoints` — Webhook URLs monitored for exfiltration.; `EntropyThreshold` — High entropy payloads may indicate encoded/encrypted exfiltration.
- **`AN0439` Analytic 0439** · ESXi
  VMware services or management daemons generating HTTP POST requests to webhook endpoints, chained with unusual datastore or log access. Defender perspective: exfiltration from VM logs or disk images over webhook URLs.
  - *Log sources:* `esxi:hostd` (datastore file access); `esxi:vmkernel` (HTTPS POST connections to webhook endpoints)
  - *Tune:* `DatastoreExfilThreshold` — Minimum data volume to flag exfiltration attempts from VM files.; `ApprovedIntegrations` — Whitelisted CI/CD or automation webhooks tied to vSphere/ESXi.
- **`AN0440` Analytic 0440** · SaaS
  Suspicious SaaS tenant activity involving webhook configurations pointing to external or untrusted domains. Defender perspective: repeated automated exports or suspicious webhook endpoint registrations.
  - *Log sources:* `m365:unified` (Set-Mailbox, Add-InboxRule, RegisterWebhook); `saas:api` (Webhook registrations or repeated POST activity)
  - *Tune:* `WebhookRegistrations` — Monitor new webhook creation events in SaaS environments.; `ExternalDomains` — Flag webhooks pointing to domains not owned by the enterprise.

---

