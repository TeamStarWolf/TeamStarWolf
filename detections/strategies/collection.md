# Collection — Detection Strategies

> MITRE ATT&CK detection strategies and analytics (v18.1) for techniques whose primary tactic is **Collection**. Each analytic lists the **log sources / channels** it needs, the **detection logic**, and the **tunable elements** to adapt it to your environment. Authoritative source: the ATT&CK detection-strategy model in the Enterprise STIX.

See also: [all detection strategies index](/detections/strategies/README.md) · [Technique Detection Library](../TECHNIQUE_DETECTION_LIBRARY.md) (ready-to-run SIEM queries) · [Data Components & Log Sources](../../ATTACK_DATA_COMPONENTS.md) · [Technique Detail Pages](../../techniques/README.md)

---

### T1005 — Data from Local System
<a id="t1005"></a>

**Detection strategy:** Detection of Local Data Collection Prior to Exfiltration (`DET0380`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1005](https://attack.mitre.org/techniques/T1005/) · [detail page](../../techniques/collection.md#t1005)

- **`AN1070` Analytic 1070** · Windows
  Adversaries collecting local files via PowerShell, WMI, or direct file API calls often include recursive file listings, targeted file reads, and temporary file staging.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `TargetFilePathRegex` — Allows tuning for file extensions or paths of sensitive data (e.g., *.xls, *.db, *.pdf).; `ParentProcessFilter` — Used to scope monitoring to suspicious parent/child process trees like PowerShell or WMI spawning file reads.
- **`AN1071` Analytic 1071** · Linux
  Adversaries using bash scripts or tools to recursively enumerate user home directories, config files, or SSH keys.
  - *Log sources:* `auditd:SYSCALL` (open); `auditd:SYSCALL` (execve)
  - *Tune:* `TimeWindow` — Time span to correlate multiple file access events indicative of scripted or bulk access.; `ScriptToolName` — List of tools (e.g., `find`, `grep`, `tar`, `scp`) that may be benign but are context-sensitive.
- **`AN1072` Analytic 1072** · macOS
  Adversary use of bash/zsh or AppleScript to locate files and exfil targets like user keychains or documents.
  - *Log sources:* `macos:unifiedlog` (process:spawn); `fs:fsusage` (read/write)
  - *Tune:* `UserContext` — Useful for excluding known admin or scheduled jobs.; `TargetVolume` — Focus monitoring on removable drives or external paths.
- **`AN1073` Analytic 1073** · Network Devices
  Collection of device configuration via CLI commands (e.g., `show running-config`, `copy flash`, `more`), often followed by TFTP/SCP transfers.
  - *Log sources:* `networkdevice:cli` (command logging)
  - *Tune:* `CommandScope` — Defines list of configuration or diagnostic commands to monitor.; `AuthenticatedUserList` — Helps reduce false positives by whitelisting known admins.
- **`AN1074` Analytic 1074** · ESXi
  Adversaries accessing datastore or configuration files via `vim-cmd`, `esxcli`, or SCP to extract logs, VMs, or host configurations.
  - *Log sources:* `esxis:vmkernel` (Datastore Access); `esxi:hostd` (Command Execution)
  - *Tune:* `AccessPathRegex` — Regex for filtering targeted VM paths or files like *.vmdk, *.vmx.; `InteractiveShellUsage` — Tune to distinguish between interactive and script-driven data access.

---

### T1025 — Data from Removable Media
<a id="t1025"></a>

**Detection strategy:** Detection of Data Access and Collection from Removable Media (`DET0511`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1025](https://attack.mitre.org/techniques/T1025/) · [detail page](../../techniques/collection.md#t1025)

- **`AN1410` Analytic 1410** · Windows
  Adversary mounts a USB device and begins enumerating, copying, or compressing files using scripting engines, cmd, or remote access tools.
  - *Log sources:* `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:System` (EventCode=2003); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `VolumeLabel` — Can tune based on known removable device labels or whitelist; `TimeWindow` — Controls timing between device mount and sensitive file access; `TargetFileType` — Tune for sensitive file extensions (e.g., .docx, .pdf, .csv)
- **`AN1411` Analytic 1411** · Linux
  Adversary mounts external drive to /media or /mnt then accesses or copies targeted data via shell, cp, or tar.
  - *Log sources:* `auditd:SYSCALL` (open, read, mount); `journald:systemd` (udisks2 or udevd logs); `auditd:SYSCALL` (execve)
  - *Tune:* `MountPathRegex` — Filter for unexpected or user-defined mount locations (e.g., /media/usb*); `AccessMask` — Tune based on read/write access types seen during collection
- **`AN1412` Analytic 1412** · macOS
  Adversary attaches USB drive and accesses sensitive files using Finder, cp, or bash scripts.
  - *Log sources:* `macos:unifiedlog` (log stream --predicate 'eventMessage contains "USBMSC"'); `fs:fsusage` (file reads/writes from /Volumes/); `macos:osquery` (process_events)
  - *Tune:* `VolumePath` — Tune by filtering removable media mounted under /Volumes; `UserContext` — Correlate activity to admin or service accounts for priority

---

### T1039 — Data from Network Shared Drive
<a id="t1039"></a>

**Detection strategy:** Detection Strategy for Data from Network Shared Drive (`DET0410`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1039](https://attack.mitre.org/techniques/T1039/) · [detail page](../../techniques/collection.md#t1039)

- **`AN1145` Analytic 1145** · Windows
  Monitoring of file access to network shares (e.g., C$, Admin$) followed by unusual read or copy operations by processes not typically associated with such activity (e.g., PowerShell, certutil).
  - *Log sources:* `WinEventLog:Security` (EventCode=5145); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `ShareName` — Organizations may use custom share paths outside of default C$, Admin$, etc.; `ProcessName` — Common toolsets vary; defenders should tailor to unusual processes for their environment.; `TimeWindow` — Time of day and access duration may need to be tuned to reduce false positives.
- **`AN1146` Analytic 1146** · Linux
  Unusual access or copying of files from mounted network drives (e.g., NFS, CIFS/SMB) by user shells or scripts followed by large data transfer.
  - *Log sources:* `auditd:SYSCALL` (open,read); `linux:syslog` (mount/umount or file copy logs)
  - *Tune:* `MountPoint` — Organization-specific share mount paths may vary (/mnt/share1, /srv/data etc.); `UID` — May need to scope to service accounts or user ID patterns specific to enterprise policy.
- **`AN1147` Analytic 1147** · macOS
  Detection of file access from mounted SMB shares followed by copy or exfil commands from Terminal or script interpreter processes.
  - *Log sources:* `macos:unifiedlog` (filesystem and process events); `fs:fsusage` (open/read/mount operations)
  - *Tune:* `ProcessPath` — Script interpreters may vary (e.g., zsh, bash, python, osascript).; `SharePath` — Network drive mount points may differ across enterprises.

---

### T1056 — Input Capture
<a id="t1056"></a>

**Detection strategy:** Behavioral Detection of Input Capture Across Platforms (`DET0102`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1056](https://attack.mitre.org/techniques/T1056/) · [detail page](../../techniques/collection.md#t1056)

- **`AN0282` Analytic 0282** · Windows
  Monitors for abnormal process behavior and API calls like SetWindowsHookEx, GetAsyncKeyState, or device input polling commonly used for keystroke logging.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Security` (EventCode=4663, 4670, 4656)
  - *Tune:* `TargetImage` — Can be scoped to sensitive GUI processes like explorer.exe or winlogon.exe; `TimeWindow` — Time threshold for detecting multiple suspicious accesses
- **`AN0283` Analytic 0283** · Linux
  Detects use of tools/scripts accessing input devices like /dev/input/* or evdev via suspicious processes lacking GUI context.
  - *Log sources:* `auditd:SYSCALL` (open, read); `auditd:SYSCALL` (write); `auditd:SYSCALL` (ptrace, ioctl)
  - *Tune:* `ProcessName` — Unusual process accessing device files; `DevicePath` — Typically /dev/input/*, but tunable to exact endpoint config
- **`AN0284` Analytic 0284** · macOS
  Monitors for TCC-bypassing or unauthorized access to input services like IOHIDSystem or Quartz Event Services used in keylogging or screen monitoring.
  - *Log sources:* `macos:unifiedlog` (subsystem=com.apple.TCC); `macos:osquery` (launchd or process_events)
  - *Tune:* `Service` — com.apple.accessibility, com.apple.quartz, etc. depending on the API path used; `ParentProcess` — Unusual parent/child pairings can indicate malicious injection
- **`AN0285` Analytic 0285** · Network Devices
  Detects web-based credential phishing by analyzing traffic to suspicious URLs that mimic login portals and POST credential content.
  - *Log sources:* `NSM:Flow` (http.log); `NSM:Firewall` (proxy or TLS inspection logs)
  - *Tune:* `UserAgent` — Mismatched browser identifiers used by phishing kits; `URL_Path` — Paths resembling known login forms but hosted on unknown domains

---

### T1056.001 — Keylogging
<a id="t1056001"></a>

**Detection strategy:** Behavioral Detection of Keylogging Activity Across Platforms (`DET0089`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1056.001](https://attack.mitre.org/techniques/T1056/001/) · [detail page](../../techniques/collection.md#t1056001)

- **`AN0243` Analytic 0243** · Windows
  Monitors suspicious usage of Windows API calls like SetWindowsHookEx, GetKeyState, or polling functions within non-UI service processes, combined with Registry or driver modifications.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:System` (EventCode=7045); `WinEventLog:Sysmon` (EventCode=13, 14)
  - *Tune:* `TargetImage` — Scope to sensitive GUI/session processes like winlogon.exe or osk.exe; `AccessMask` — Can be tuned to 0x1fffff for full-access injection detection; `TimeWindow` — Tunable for sustained polling or multiple registry edits in short succession
- **`AN0244` Analytic 0244** · Linux
  Detects non-system processes accessing /dev/input/* or issuing ptrace/evdev syscalls used for reading keystroke buffers directly.
  - *Log sources:* `auditd:SYSCALL` (open, read); `auditd:SYSCALL` (ptrace, ioctl)
  - *Tune:* `ProcessName` — Exclude known good applications (e.g. Xorg, GNOME Shell); `DevicePath` — Typically /dev/input/event*, but tunable to match custom input buses
- **`AN0245` Analytic 0245** · macOS
  Detects unauthorized TCC access or use of Quartz Event Services (CGEventTapCreate) or IOHID for event tap installation within unexpected processes.
  - *Log sources:* `macos:unifiedlog` (subsystem=com.apple.TCC); `macos:osquery` (process_events OR launchd)
  - *Tune:* `Service` — com.apple.inputmonitoring, com.apple.accessibility, etc.; `ExecutablePath` — Tunable to exclude trusted endpoint monitoring tools
- **`AN0246` Analytic 0246** · Network Devices
  Keylogging on legacy network devices via unauthorized system image modification or remote capture of console keystrokes (telnet, SSH) through altered firmware or man-in-the-middle key sniffing.
  - *Log sources:* `networkdevice:syslog` (Image Upgrade / Configuration Change); `NSM:Flow` (packet capture or DPI logs)
  - *Tune:* `FirmwareVersion` — Baseline hash or expected version for config/image integrity; `Protocol` — Scope to plaintext channels or low-assurance SSH versions

---

### T1056.002 — GUI Input Capture
<a id="t1056002"></a>

**Detection strategy:** Behavioral Detection of Spoofed GUI Credential Prompts (`DET0521`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1056.002](https://attack.mitre.org/techniques/T1056/002/) · [detail page](../../techniques/collection.md#t1056002)

- **`AN1440` Analytic 1440** · Windows
  Detects suspicious use of PowerShell, .NET, or script interpreters to spawn processes that mimic UAC prompts, often with credential capture dialogue boxes invoked from non-standard parent processes.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106)
  - *Tune:* `CommandLine` — Tunable to detect suspicious prompts like 'Enter your password' or 'CredentialRequired'; `ParentProcessName` — Tune to flag UI prompts spawned from unexpected processes like cmd.exe or user scripts; `TimeWindow` — Scope correlation of script execution and prompt appearance
- **`AN1441` Analytic 1441** · Linux
  Detects GUI-based credential prompts invoked via zenity/kdialog/dialog or X11 APIs from non-user-facing scripts or background shell sessions, often with authentication-related text.
  - *Log sources:* `auditd:SYSCALL` (execve); `linux:cli` (Terminal Command History)
  - *Tune:* `ExecutableName` — Filter zenity/kdialog prompts launched from unexpected parent shells; `PromptString` — Look for 'password', 'authentication required', or similar tokens
- **`AN1442` Analytic 1442** · macOS
  Detects AppleScript or Objective-C usage to generate fake authentication windows (e.g., using display dialog or NSAlert) from user-launched or persistence-related processes.
  - *Log sources:* `macos:unifiedlog` (subsystem=com.apple.Security or com.apple.applescript); `macos:osquery` (process_events)
  - *Tune:* `ScriptContent` — AppleScript snippets like 'display dialog' or 'with hidden answer'; `ProcessPath` — Tune out Apple-signed and expected automation tasks

---

### T1056.003 — Web Portal Capture
<a id="t1056003"></a>

**Detection strategy:** Detection of Credential Harvesting via Web Portal Modification (`DET0480`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1056.003](https://attack.mitre.org/techniques/T1056/003/) · [detail page](../../techniques/collection.md#t1056003)

- **`AN1320` Analytic 1320** · Linux
  Detects unauthorized modifications to login-facing web server files (e.g., index.php, login.js) typically tied to VPN, SSO, or intranet portals. Correlates suspicious file changes with remote access artifacts or web shell behavior.
  - *Log sources:* `auditd:SYSCALL` (write); `NSM:Flow` (HTTP Request Logging)
  - *Tune:* `MonitoredFilePaths` — Target login-related files (e.g., /var/www/html/login.php) for integrity monitoring; `TimeWindow` — Tune detection to correlate file edits and web access within a short duration
- **`AN1321` Analytic 1321** · Windows
  Detects tampering of IIS-based login pages (e.g., default.aspx, login.aspx) tied to VPN, OWA, or SharePoint via script injection or unexpected editor processes modifying web roots.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:iis` (IIS Logs)
  - *Tune:* `FilePath` — Define path to monitored IIS web root (e.g., C:\inetpub\wwwroot\login.aspx); `ProcessName` — Exclude legitimate updates (e.g., msdeploy.exe) and alert on suspicious editors (e.g., notepad.exe, certutil.exe)
- **`AN1322` Analytic 1322** · macOS
  Detects unauthorized changes to locally hosted login pages on macOS (common in developer VPN environments) and links file edits to cron jobs, background scripts, or SUID binaries.
  - *Log sources:* `fs:fsusage` (Filesystem Access Logging); `macos:unifiedlog` (subsystem=com.apple.WebKit)
  - *Tune:* `WebRootPath` — Specify custom web service directories (e.g., /Library/WebServer/Documents/); `AnomalousProcess` — Alert on web root changes from non-web processes or scripts

---

### T1056.004 — Credential API Hooking
<a id="t1056004"></a>

**Detection strategy:** Detection of Credential Harvesting via API Hooking (`DET0139`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1056.004](https://attack.mitre.org/techniques/T1056/004/) · [detail page](../../techniques/collection.md#t1056004)

- **`AN0389` Analytic 0389** · Windows
  Detects credential harvesting via userland API hooking (e.g., SetWindowsHookEx, IAT, or inline patching) by correlating memory modifications with hook installation functions and suspicious module loads in credential-sensitive processes like lsass.exe, explorer.exe, or winlogon.exe.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=8)
  - *Tune:* `TargetProcess` — Credential-sensitive targets (e.g., explorer.exe, winlogon.exe) may vary by environment; `AccessMask` — Tuning for access rights like 0x1FFFFF for full access vs. thread injection; `TimeWindow` — Correlate memory access and hook setup in short windows (5–10 seconds)
- **`AN0390` Analytic 0390** · Linux
  Detects credential interception via malicious LD_PRELOAD-based shared libraries loaded into ssh, sudo, or scp processes. Correlates environment variable injection, unexpected library loads, and memory patching behavior.
  - *Log sources:* `auditd:SYSCALL` (execve); `auditd:SYSCALL` (LD_PRELOAD Logging)
  - *Tune:* `InjectedLibraryName` — Watch for user-defined suspicious .so files (e.g., libhook.so, libshadow.so); `TargetProcessName` — Hooked binaries vary by use case (e.g., ssh, login, gdm)
- **`AN0391` Analytic 0391** · macOS
  Detects DYLD_INSERT_LIBRARIES abuse to hook credential-sensitive applications by correlating process spawns with unauthorized library injection and monitoring changes to the __TEXT segment (code) of credential handling binaries.
  - *Log sources:* `macos:unifiedlog` (DYLD event subsystem); `fs:fsusage` (File Access Monitor); `macos:osquery` (Memory Mappings)
  - *Tune:* `DYLDInjectedPath` — Tunable based on naming patterns or location of malicious dylibs; `ParentProcessName` — Hooking attempts may stem from terminal.app, bash, or AppleScript-based launchers

---

### T1074 — Data Staged
<a id="t1074"></a>

**Detection strategy:** Detection of Data Staging Prior to Exfiltration (`DET0014`)  
**Platforms:** ESXi, IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1074](https://attack.mitre.org/techniques/T1074/) · [detail page](../../techniques/collection.md#t1074)

- **`AN0040` Analytic 0040** · Windows
  Detects staging of sensitive files into temporary or public directories, compression with 7zip/WinRAR, or batch copy prior to exfiltration.
  - *Log sources:* `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `StagingDirectoryList` — Temp folders or user profile staging directories; `CompressionToolList` — 7z.exe, rar.exe, zip.exe paths; `TimeWindow` — Temporal bounds for detecting batch staging activities
- **`AN0041` Analytic 0041** · Linux
  Detects script or user activity copying files to a central temp or /mnt directory followed by archive/compression utilities.
  - *Log sources:* `auditd:SYSCALL` (creat); `auditd:SYSCALL` (execve)
  - *Tune:* `StagingDirectoryList` — e.g., /tmp/, /var/tmp/, /mnt/; `ArchivingCommandPatterns` — grep for 'tar', 'zip', 'gzip', '7z'; `UserContext` — Interactive or elevated shells running archiving commands
- **`AN0042` Analytic 0042** · macOS
  Detects files collected into user temp or shared directories followed by compression with ditto, zip, or custom scripts.
  - *Log sources:* `macos:unifiedlog` (file events); `macos:unifiedlog` (exec logs)
  - *Tune:* `CompressionUtilityList` — e.g., 'ditto', 'zip', 'tar'; `SharedDirectoryIndicators` — e.g., /Users/Shared/ or /private/tmp/; `ScriptInvocationContext` — osascript or Terminal automation by non-GUI processes
- **`AN0043` Analytic 0043** · IaaS
  Detects virtual disk expansion or file copy operations to cloud buckets or mounted volumes from isolated instances.
  - *Log sources:* `AWS:CloudTrail` (GetObject, CopyObject); `gcp:audit` (Write operations to storage)
  - *Tune:* `CloudBucketList` — Staging bucket or mount point for data; `InstanceTag` — Behavior restricted to specific ephemeral instances; `ObjectWriteThreshold` — Volume or size of files pushed in burst
- **`AN0044` Analytic 0044** · ESXi
  Detects snapshots or data stored in VMFS volumes from root CLI or remote agents.
  - *Log sources:* `esxi:vmkernel` (VMFS access logs); `esxi:shell` (snapshot create/copy, esxcli)
  - *Tune:* `SnapshotFrequency` — Number of snapshots in short time period; `AccessUserList` — Non-admins or automation accounts writing to datastores; `CLIContext` — Manual or unexpected API calls triggering snapshots

---

### T1074.001 — Local Data Staging
<a id="t1074001"></a>

**Detection strategy:** Detection of Local Data Staging Prior to Exfiltration (`DET0261`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1074.001](https://attack.mitre.org/techniques/T1074/001/) · [detail page](../../techniques/collection.md#t1074001)

- **`AN0724` Analytic 0724** · Windows
  Detects file reads across locations followed by writes to temp or staging directories, often compressed or encrypted, indicating local staging behavior.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Security` (EventCode=4663, 4670, 4656)
  - *Tune:* `StagingDirList` — Paths such as C:\Temp, C:\Windows\Tasks, etc.; `ArchivingToolPatterns` — Matches to 7z.exe, rar.exe, zip.exe, or custom scripts.; `TimeWindow` — How long to correlate file reads followed by compression.
- **`AN0725` Analytic 0725** · Linux
  Detects aggregation of files from different directories into /tmp, /mnt, or user-specified directories with archiving tools like tar or gzip.
  - *Log sources:* `auditd:SYSCALL` (open); `auditd:SYSCALL` (execve)
  - *Tune:* `StagingDirs` — e.g., /tmp, /var/tmp, custom user dirs; `ArchiveUtilities` — tar, gzip, zip, 7z; `UserThreshold` — Number of files or size written in short time
- **`AN0726` Analytic 0726** · macOS
  Detects staged data aggregated in /Users/Shared, /private/tmp with compression tools like ditto or zip, initiated via Terminal or AppleScript.
  - *Log sources:* `macos:unifiedlog` (file events); `macos:unifiedlog` (exec logs)
  - *Tune:* `StagingTargets` — Shared dirs commonly abused for local collection; `CompressionBinaries` — zip, tar, ditto; `TimeWindow` — Seconds/minutes between source file read and output staging write
- **`AN0727` Analytic 0727** · ESXi
  Detects local staging behavior via snapshot creation or files written into VMFS partitions by scripts or unauthorized shell access.
  - *Log sources:* `esxi:vmkernel` (snapshot create/write events); `esxi:shell` (CLI usage logs)
  - *Tune:* `SnapshotThreshold` — Rapid creation or deletion of snapshots; `CLIInvoker` — Unexpected CLI/script invocation outside maintenance windows; `VMFSWriteRate` — Volume of data written locally in short time

---

### T1074.002 — Remote Data Staging
<a id="t1074002"></a>

**Detection strategy:** Detection of Remote Data Staging Prior to Exfiltration (`DET0071`)  
**Platforms:** ESXi, IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1074.002](https://attack.mitre.org/techniques/T1074/002/) · [detail page](../../techniques/collection.md#t1074002)

- **`AN0194` Analytic 0194** · Windows
  Detects file transfers or mounting operations from remote hosts followed by write actions into a local staging directory, often using SMB or remote shell activity.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Microsoft-Windows-SMBClient/Security` (EventCode=31001); `WinEventLog:PowerShell` (CommandLine=copy-item or robocopy from UNC path)
  - *Tune:* `StagingDirectory` — Common directories such as C:\Temp, Downloads, or hidden folders used for remote staging; `RemotePathPatterns` — UNC paths like \\10.* or \\domain\share indicating lateral data staging; `CopyToolPatterns` — Usage of robocopy, xcopy, copy-item, or scheduled tasks performing cross-host copies
- **`AN0195` Analytic 0195** · Linux
  Detects inbound SCP, rsync, or NFS mounts from remote systems followed by aggregation of files into known staging paths like /mnt/staging or /var/tmp.
  - *Log sources:* `auditd:SYSCALL` (open); `auditd:SYSCALL` (execve); `NSM:Flow` (SSH logins or scp activity)
  - *Tune:* `RemoteHosts` — Expected inbound transfer hosts to filter normal activity from staging behavior; `MountTargets` — Directory destinations used as centralized locations; `TransferVolumeThreshold` — Threshold of transferred files or data volume over time
- **`AN0196` Analytic 0196** · macOS
  Detects rsync or scp inbound from other hosts that then aggregate content into /Users/Shared or /private/tmp, often involving compressed files or scripts.
  - *Log sources:* `macos:unifiedlog` (exec logs); `macos:unifiedlog` (file events); `NSM:Flow` (remote login and transfer)
  - *Tune:* `StagingPaths` — Monitored remote-to-local write destinations such as /Users/Shared; `CompressionIndicators` — Presence of .zip, .7z, or tar.gz indicating consolidation; `TimeWindow` — Temporal correlation of transfer and staging write operations
- **`AN0197` Analytic 0197** · ESXi
  Detects remote writes or snapshots mounted from other systems into a central ESXi VMFS path or NFS store used for remote staging of files before exfiltration.
  - *Log sources:* `esxi:vmkernel` (VMFS file creation); `esxi:vob` (NFS/remote access logs); `esxi:shell` (invoked remote scripts (esxcli))
  - *Tune:* `SnapshotFrequency` — How often snapshots are mounted or restored from peer nodes; `RemoteWriteVolume` — Threshold for staging behavior vs. backup/operational activity; `StorageMountPaths` — Common local destinations for incoming data
- **`AN0198` Analytic 0198** · IaaS
  Detects remote write activity across cloud VMs or object storage buckets within the same region/account that correlate with data aggregation across hosts.
  - *Log sources:* `AWS:CloudTrail` (GetObject, CopyObject); `AWS:VPCFlowLogs` (Traffic between instances); `esxi:hostd` (process execution across cloud VM)
  - *Tune:* `BucketNamePatterns` — Destination naming convention used for staging (e.g., temp-store); `IAMContext` — IAM role or user performing multi-host write ops; `TransferWindow` — Burst of high-volume inter-VM transfers indicating staging

---

### T1113 — Screen Capture
<a id="t1113"></a>

**Detection strategy:** Detect Screen Capture via Commands and API Calls (`DET0346`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1113](https://attack.mitre.org/techniques/T1113/) · [detail page](../../techniques/collection.md#t1113)

- **`AN0980` Analytic 0980** · Windows
  Unusual use of screen capture APIs (e.g., CopyFromScreen) or command-line tools to write image files to disk.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `ParentProcessName` — Depends on allowed parent process behaviors in the environment (e.g., explorer.exe vs powershell.exe); `TimeWindow` — Can tune alert thresholds for rapid or scheduled screenshots (e.g., interval-based screen capture); `ImageExtension` — To detect file writes (e.g., .bmp, .png) that deviate from typical user activity
- **`AN0981` Analytic 0981** · macOS
  Invocation of built-in commands like screencapture or use of undocumented APIs from suspicious parent processes.
  - *Log sources:* `macos:unifiedlog` (process: exec)
  - *Tune:* `CommandLineRegex` — Customize regex for flag detection (e.g., `screencapture -x`) based on usage patterns; `ParentProcessName` — May vary depending on expected screencapture behavior (Terminal vs remote agent)
- **`AN0982` Analytic 0982** · Linux
  Use of tools like xwd or import to generate screenshots, especially under non-GUI parent processes.
  - *Log sources:* `auditd:SYSCALL` (execve)
  - *Tune:* `TerminalSession` — Filter based on TTY sessions or remote terminal usage; `ExecutablePath` — Match against known location of xwd/import binaries or renamed variants

---

### T1114 — Email Collection
<a id="t1114"></a>

**Detection strategy:** Email Collection via Local Email Access and Auto-Forwarding Behavior (`DET0476`)  
**Platforms:** Linux, Office Suite, Windows, macOS  
**ATT&CK:** [T1114](https://attack.mitre.org/techniques/T1114/) · [detail page](../../techniques/collection.md#t1114)

- **`AN1309` Analytic 1309** · Windows
  Correlates creation of email forwarding rules or header anomalies (e.g., X-MS-Exchange-Organization-AutoForwarded) with suspicious process execution, file access of .pst/.ost files, and network connections to external SMTP servers.
  - *Log sources:* `WinEventLog:Security` (EventCode=5145); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106); `WinEventLog:Application` (Exchange logs or header artifacts); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `TimeWindow` — Defines correlation window across email rule creation and outbound SMTP.; `UserContext` — Filters for admin or service accounts to reduce false positives.; `SMTPDomainList` — Allows tuning based on expected external email domains.
- **`AN1310` Analytic 1310** · Linux
  Detects file access to mbox/maildir files in conjunction with curl/wget/postfix execution, or anomalous shell scripts harvesting user mail directories.
  - *Log sources:* `auditd:SYSCALL` (open); `linux:syslog` (postfix/smtpd); `linux:osquery` (process_events)
  - *Tune:* `WatchedMailDirs` — Specify user mail directories (/var/mail, ~/Maildir); `ProcessNameList` — Tune based on local mail clients or curl usage in environment; `TimeWindow` — Define how close together access and exfil events must occur
- **`AN1311` Analytic 1311** · macOS
  Monitors Mail.app database or maildir file access, automation via AppleScript, and abnormal mail rule creation using scripting or UI automation frameworks.
  - *Log sources:* `macos:unifiedlog` (Mail or AppleScript subsystem); `macos:endpointsecurity` (es_event_open, es_event_exec)
  - *Tune:* `ScriptProcessNameList` — Script interpreters or automation tools (osascript, Automator, etc.); `WatchedMailFiles` — Mail.app SQLite DB or .emlx directory
- **`AN1312` Analytic 1312** · Office Suite
  Correlates unusual auto-forwarding rule creation via Exchange Web Services or Outlook rules engine, presence of X-MS-Exchange-Organization-AutoForwarded headers, and logon session anomalies from abnormal IPs.
  - *Log sources:* `m365:unified` (Set-Mailbox, New-InboxRule); `m365:exchange` (MessageTrace logs); `azure:ad` (SignInEvents)
  - *Tune:* `UserAgentList` — Restrict rules from non-browser agents; `ExternalSMTPDomainList` — Allow listing for org-sanctioned forwarding domains; `TimeWindow` — Time delta between rule creation and suspicious sign-in

---

### T1114.001 — Local Email Collection
<a id="t1114001"></a>

**Detection strategy:** Detect Local Email Collection via Outlook Data File Access and Command Line Tooling (`DET0047`)  
**Platforms:** Windows  
**ATT&CK:** [T1114.001](https://attack.mitre.org/techniques/T1114/001/) · [detail page](../../techniques/collection.md#t1114001)

- **`AN0130` Analytic 0130** · Windows
  Detection focuses on processes that attempt to locate, access, or exfiltrate local Outlook data files (.pst/.ost) using file system access, native Windows utilities (e.g., PowerShell, WMI), or remote access tools with file browsing capabilities. The behavior chain includes directory enumeration, file access, optional compression or staging, and network transfer.
  - *Log sources:* `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `TargetFilePathPattern` — Regex or wildcard patterns for sensitive Outlook file paths (.ost/.pst) depending on organizational deployment.; `TimeWindow` — Timeframe used to correlate related file access, process creation, and exfiltration events.; `UserContext` — Limit detection to user accounts not normally interacting with Outlook file locations (e.g., service accounts, low-privileged users).; `ProcessAllowList` — Filter known legitimate Outlook-accessing processes to reduce false positives.

---

### T1114.002 — Remote Email Collection
<a id="t1114002"></a>

**Detection strategy:** Detect Remote Email Collection via Abnormal Login and Programmatic Access (`DET0048`)  
**Platforms:** Office Suite, Windows  
**ATT&CK:** [T1114.002](https://attack.mitre.org/techniques/T1114/002/) · [detail page](../../techniques/collection.md#t1114002)

- **`AN0131` Analytic 0131** · Windows
  Detects adversaries accessing remote mail systems (e.g., Exchange Online, O365) using stolen credentials or OAuth tokens, followed by scripted access to mailbox contents via PowerShell, AADInternals, or unattended API queries. Detection focuses on abnormal logon sessions, user agents, IP locations, and scripted or tool-based email data access.
  - *Log sources:* `azure:signinlogs` (Abnormal sign-in from scripting tools (PowerShell, AADInternals)); `m365:purview` (MailItemsAccessed & Exchange Audit); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `UserAgentPattern` — Filters user agents like 'PowerShell', 'AADInternals', 'python-requests' which can vary depending on script/tool.; `TimeWindow` — Defines the temporal correlation window between login, command execution, and outbound email access.; `KnownIPLocations` — Defines baseline geo/IP address ranges to suppress known corporate access.; `PrivilegedUserList` — Defines the accounts considered privileged (admin, execs) and worthy of tighter thresholds.
- **`AN0132` Analytic 0132** · Office Suite
  Monitors programmatic access to user mailboxes in cloud-based email systems (e.g., O365, Exchange Online) using APIs or tokens. Focuses on OAuth misuse, suspicious MailItemsAccessed patterns, scripted keyword searches, and connections from untrusted agents or locations.
  - *Log sources:* `m365:purview` (MailItemsAccessed, Search-Mailbox events); `azure:signinlogs` (Suspicious login to cloud mailbox system); `m365:unified` (Search-Mailbox, Get-MessageTrace, eDiscovery requests)
  - *Tune:* `MailAccessVolumeThreshold` — Number of emails accessed within time window to flag anomaly.; `OAuthClientIDAllowList` — Allows tuning based on known app registrations.; `KeywordSearchFrequency` — Flag high volumes of message searches using suspicious patterns.; `LoginGeolocationVariance` — Trigger when IP geolocation varies significantly from user's historical profile.

---

### T1114.003 — Email Forwarding Rule
<a id="t1114003"></a>

**Detection strategy:** Email Forwarding Rule Abuse Detection Across Platforms (`DET0576`)  
**Platforms:** Linux, Office Suite, Windows, macOS  
**ATT&CK:** [T1114.003](https://attack.mitre.org/techniques/T1114/003/) · [detail page](../../techniques/collection.md#t1114003)

- **`AN1589` Analytic 1589** · Windows
  Creation of inbox rules via PowerShell (New-InboxRule) or transport rules using Exchange cmdlets. Correlates user behavior, cmdlet usage, and rule properties.
  - *Log sources:* `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106); `WinEventLog:Security` (EventCode=4688); `m365:exchange` (Cmdlet - New-InboxRule)
  - *Tune:* `UserContext` — Certain service accounts or admin contexts may be expected to run these rules.; `TimeWindow` — Correlate between rule creation and follow-on message forwarding within this timeframe.; `TargetMailbox` — Whitelisted or trusted destination addresses may be tuned per org policy.
- **`AN1590` Analytic 1590** · macOS
  Creation or modification of Apple Mail rules by accessing plist files or GUI automation (AppleScript).
  - *Log sources:* `macos:unifiedlog` (log stream --predicate); `fs:plist_monitoring` (/Users/*/Library/Mail/V*/MailData/RulesActiveState.plist)
  - *Tune:* `RuleFilePath` — Different Mail versions store rules in slightly different locations.; `ScriptTrigger` — AppleScript usage for GUI automation may be common in automation workflows.
- **`AN1591` Analytic 1591** · Office Suite
  Creation of email forwarding/redirect rules in Exchange Online via New-InboxRule or transport rule cmdlets, including auto-forwarding address field usage.
  - *Log sources:* `m365:unified` (New-InboxRule, Set-InboxRule); `m365:messagetrace` (X-MS-Exchange-Organization-AutoForwarded)
  - *Tune:* `ForwardingSMTPAddress` — Destination domain may vary; commonly tuned per org policies.; `ActorId` — Differentiate service/admin users vs standard user population.
- **`AN1592` Analytic 1592** · Linux
  Modification of Thunderbird message filters file or execution of CLI tools (e.g., formail/procmail) that alter .forward behavior.
  - *Log sources:* `auditd:SYSCALL` (write); `linux:cli` (/home/*/.bash_history)
  - *Tune:* `.forwardPath` — User-based home directories; tune for specific user patterns.; `ExecContext` — Expected email client behavior may trigger similar file edits.

---

### T1115 — Clipboard Data
<a id="t1115"></a>

**Detection strategy:** Clipboard Data Access with Anomalous Context (`DET0341`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1115](https://attack.mitre.org/techniques/T1115/) · [detail page](../../techniques/collection.md#t1115)

- **`AN0965` Analytic 0965** · Windows
  Detection of clipboard access via OS utilities (e.g., clip.exe, Get-Clipboard) by non-interactive or abnormal parent processes, potentially chained with staging or exfiltration commands.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=10)
  - *Tune:* `TimeWindow` — Defines how far back to look for parent-child relationships and follow-on network activity.; `UserContext` — Filters based on service vs interactive users to reduce noise.; `ParentProcessName` — Tunable list of expected/benign clipboard accessors.
- **`AN0966` Analytic 0966** · macOS
  Detection of pbpaste/pbcopy clipboard access by processes without terminal sessions or linked to launch agents, potentially staged for collection.
  - *Log sources:* `macos:unifiedlog` (process)
  - *Tune:* `ExecutionChainLength` — How many chained or embedded processes to track for correlation.; `TerminalSession` — Whether the pbpaste/pbcopy action is tied to a user terminal.; `BinaryPath` — Adjust if clipboard tooling is relocated (e.g., /opt/empyre/pbpaste).
- **`AN0967` Analytic 0967** · Linux
  Detection of xclip or xsel access to clipboard buffers outside of user terminal context, especially when chained to staging (gzip, base64) or network exfiltration (curl, scp).
  - *Log sources:* `auditd:SYSCALL` (execve)
  - *Tune:* `ClipboardCommand` — Tool used (xclip, xsel, custom clipboard-read binary).; `CorrelationWindow` — Temporal window to chain staging or network activity with clipboard access.; `TTYLinked` — Was access linked to interactive user TTY?

---

### T1119 — Automated Collection
<a id="t1119"></a>

**Detection strategy:** Automated File and API Collection Detection Across Platforms (`DET0186`)  
**Platforms:** Linux, SaaS, Windows, macOS  
**ATT&CK:** [T1119](https://attack.mitre.org/techniques/T1119/) · [detail page](../../techniques/collection.md#t1119)

- **`AN0531` Analytic 0531** · Windows
  Automated execution of native utilities and scripts to discover, enumerate, and exfiltrate files and clipboard content. Focus is on detecting repeated file access, scripting engine use, and use of command-line utilities commonly leveraged by collection scripts.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `TimeWindow` — Defines the lookback period for identifying burst activity or patterns in process/file events.; `SuspiciousFileExtensions` — Tunable list of file extensions associated with collection (e.g., .pdf, .docx).; `ProcessCountThreshold` — The number of times a process executes before considered anomalous.
- **`AN0532` Analytic 0532** · Linux
  Repeated or automated access to user document directories or clipboard using shell scripts or utilities like xclip/pbpaste. Detectable via auditd syscall logs or osquery file events.
  - *Log sources:* `auditd:SYSCALL` (execve); `auditd:SYSCALL` (open)
  - *Tune:* `AccessPath` — Tunable location for sensitive files like /home/*/Documents.; `ScriptInterpreterList` — Shells or scripting engines to monitor (e.g., bash, python, perl).
- **`AN0533` Analytic 0533** · macOS
  Use of pbpaste, AppleScript, or third-party automation frameworks (e.g., Automator) to collect clipboard or file content in bursts. Observable via unified logs.
  - *Log sources:* `macos:unifiedlog` (logMessage contains pbpaste or osascript); `macos:unifiedlog` (subsystem=launchservices)
  - *Tune:* `AutomationTool` — Detectable script interpreters or clipboard tools (pbpaste, osascript).; `ClipboardCheckRate` — Threshold for how often clipboard access occurs within a given time window.
- **`AN0534` Analytic 0534** · SaaS
  Suspicious sign-ins to Graph API or sensitive resources using non-browser scripting agents (e.g., Python, PowerShell), often for programmatic access to mailbox or OneDrive content.
  - *Log sources:* `azure:signinlogs` (Operation=UserLogin)
  - *Tune:* `UserAgentFilter` — Filter for scripting agents (e.g., Python, PowerShell) which may vary by org.; `ExpectedClientIPList` — Set of known internal or managed IPs to filter benign automation.; `DeviceProperties` — Expected managed device profiles used to detect unmanaged devices.

---

### T1123 — Audio Capture
<a id="t1123"></a>

**Detection strategy:** Behavioral Detection Strategy for T1123 Audio Capture Across Windows, Linux, macOS (`DET0221`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1123](https://attack.mitre.org/techniques/T1123/) · [detail page](../../techniques/collection.md#t1123)

- **`AN0619` Analytic 0619** · Windows
  Unusual or unauthorized processes accessing microphone APIs (e.g., winmm.dll, avrt.dll) followed by audio file writes to user-accessible or temp directories.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Security` (EventCode=4688)
  - *Tune:* `TimeWindow` — Time span in which the process accesses audio APIs and writes files, to reduce false positives.; `TargetProcess` — Set of approved processes known to legitimately use microphone (e.g., Zoom, Teams).; `WriteDirectory` — Allowlist of paths where legitimate apps store audio (e.g., user media folders).
- **`AN0620` Analytic 0620** · Linux
  Processes accessing ALSA/PulseAudio devices or executing audio capture binaries like 'arecord', followed by file creation or suspicious child process spawning.
  - *Log sources:* `auditd:SYSCALL` (open); `linux:Sysmon` (EventCode=1); `auditd:SYSCALL` (write)
  - *Tune:* `ExecutableName` — Capture binaries like arecord, parecord, or ffmpeg.; `DevicePath` — Log attempts to access /dev/snd/*, /dev/dsp, /proc/asound/*.; `UserContext` — Whether the user has audio access rights or is running under elevated privileges.
- **`AN0621` Analytic 0621** · macOS
  Processes invoking AVFoundation or CoreAudio frameworks, accessing input devices via TCC logs or Unified Logs, followed by writing AIFF/WAV/MP3 files to disk.
  - *Log sources:* `macos:unifiedlog` (audio APIs); `Apple TCC Logs` (Microphone Access Events); `fs:fsusage` (File IO)
  - *Tune:* `FrameworkCall` — CoreAudio vs. AVFoundation vs. lower-level device access APIs.; `TargetDirectory` — Suspicious file drops (e.g., ~/Library/Caches/, /tmp/, nonstandard user folders).; `AnomalousParent` — Unexpected parent-child relationship between non-media apps and AV capture.

---

### T1125 — Video Capture
<a id="t1125"></a>

**Detection strategy:** Behavior-chain, platform-aware detection strategy for T1125 Video Capture (`DET0197`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1125](https://attack.mitre.org/techniques/T1125/) · [detail page](../../techniques/collection.md#t1125)

- **`AN0568` Analytic 0568** · Windows
  A non-standard process (or script-hosted process) loads camera/video-capture libraries (e.g., avicap32.dll, mf.dll, ksproxy.ax), opens the Camera Frame Server/device, writes video/image artifacts (e.g., .mp4/.avi/.yuv) to unusual locations, and optionally initiates outbound transfer shortly after.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:Microsoft-Windows-Windows Camera Frame Server/Operational` (Process session start/stop events for camera pipeline by unexpected executables)
  - *Tune:* `TimeWindow` — Correlation window (e.g., 0–20 minutes) between device access, file creation, and egress.; `AllowedProcesses` — Known legitimate camera consumers (e.g., Teams.exe, zoom.exe, obs64.exe) to suppress.; `VideoExtensions` — List of extensions to flag (.mp4, .avi, .mov, .yuv, .mkv, .h264) – tune for your estate.; `RarePathRegex` — Regex for unusual storage locations (e.g., %TEMP%\*, C:\Windows\Tasks\*, user profile hidden dirs).; `MinFileSizeMB` — Minimum size to reduce FP from thumbnails/snapshots.; `ParentProcessAllowList` — Service/agent parents permitted to broker camera access.
- **`AN0569` Analytic 0569** · Linux
  A process opens/reads /dev/video* (V4L2), performs ioctl/read loops, writes large/continuous video artifacts to disk, and/or quickly establishes outbound connections for exfiltration.
  - *Log sources:* `auditd:SYSCALL` (openat/read/ioctl: openat/read/ioctl on /dev/video* by uncommon user/process); `auditd:SYSCALL` (PATH records referencing /dev/video*); `linux:osquery` (select: path LIKE '/dev/video%'); `linux:syslog` (sudo execution of ffmpeg/gst-launch/v4l2-ctl by non-standard user); `NSM:Flow` (http/file-xfer: Outbound transfer of large video-like MIME types soon after capture)
  - *Tune:* `SyscallSet` — Which syscalls to audit (openat, read, ioctl) – performance sensitive.; `AllowedCallers` — Legitimate processes (e.g., motion, Zoom, Chrome) that access /dev/video*.; `VideoExtensions` — List of file extensions to flag (.mp4/.avi/.mov/.mkv/.yuv/.h264).; `MinContinuousReadCount` — Minimum read/ioctl count to infer continuous capture.; `TimeWindow` — Correlate device open → file write → network exfil (e.g., 30m).
- **`AN0570` Analytic 0570** · macOS
  A non-whitelisted process receives TCC camera entitlement (kTCCServiceCamera), opens AppleCamera/AVFoundation device handles, writes .mov/.mp4 artifacts to unusual locations, and/or beacons/exfiltrates soon after.
  - *Log sources:* `macos:unifiedlog` (Access decisions to kTCCServiceCamera for unexpected binaries); `macos:endpointsecurity` (open: Process opens AppleCamera/IOUSB device nodes or AVFoundation frameworks); `macos:endpointsecurity` (exec: Exec of ffmpeg, avfoundation-based binaries, or custom signed apps accessing camera); `macos:unifiedlog` (Process wrote large .mov/.mp4 in user temp/hidden dirs)
  - *Tune:* `TCCAllowList` — Legitimate apps (Zoom, Teams, FaceTime) that are permitted to camera.; `VideoExtensions` — Mov/mp4/mkv/yuv etc., tuned to environment workloads.; `TimeWindow` — Correlation between TCC grant → file write → network egress.; `MinFileSizeMB` — Reduce FP from thumbnails/snapshots.; `LaunchAgentPaths` — Allowed persistence paths to reduce false positives when correlating with persistence.

---

### T1185 — Browser Session Hijacking
<a id="t1185"></a>

**Detection strategy:** Detect browser session hijacking via privilege, handle access, and remote thread into browsers (`DET0507`)  
**Platforms:** Windows  
**ATT&CK:** [T1185](https://attack.mitre.org/techniques/T1185/) · [detail page](../../techniques/collection.md#t1185)

- **`AN1398` Analytic 1398** · Windows
  Adversary gains high integrity or special privileges (e.g., SeDebugPrivilege), locates a running browser process, opens it with write/inject rights, and modifies it (e.g., CreateRemoteThread / DLL load) to inherit cookies/tokens or establish a browser pivot. Optional step: create a new logon session or use explicit credentials, then drive the victim browser to intranet resources.
  - *Log sources:* `WinEventLog:Security` (EventCode=4672); `WinEventLog:Security` (EventCode=4673); `WinEventLog:Security` (EventCode=4624, 4648); `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=8); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `BrowserList` — Set of monitored browsers (chrome.exe, msedge.exe, firefox.exe, iexplore.exe). Adjust per fleet.; `AccessMaskSet` — Access rights implying injection (e.g., 0x1FFFFF, 0x1F3FF, VM_WRITE, VM_OPERATION, CREATE_THREAD). Tune by EDR mapping.; `SignerAllowList` — Allowed module signers within browser processes (e.g., Microsoft, Google). Helps flag unsigned/unknown ImageLoad into browsers.; `InternalCIDR` — Enterprise internal ranges or DNS suffixes to identify intranet pivoting via the browser.; `TimeWindow` — Correlation interval (e.g., 10–20 minutes) linking privilege gain → access → modification → network usage.; `ParentAllowList` — Legitimate tools that may automate browsers (e.g., Selenium drivers). Reduce FPs by allowlisting.; `UserContext` — Scope analytics to high-value users, admin workstations, or servers where browsers shouldn’t be automated.

---

### T1213 — Data from Information Repositories
<a id="t1213"></a>

**Detection strategy:** Abuse of Information Repositories for Data Collection (`DET0413`)  
**Platforms:** Linux, SaaS, Windows, macOS  
**ATT&CK:** [T1213](https://attack.mitre.org/techniques/T1213/) · [detail page](../../techniques/collection.md#t1213)

- **`AN1160` Analytic 1160** · Windows
  Programmatic or excessive access to file shares, SharePoint, or database repositories by users not typically interacting with them. This includes abnormal access by privileged accounts, enumeration of large numbers of files, or downloads of sensitive content in bursts.
  - *Log sources:* `WinEventLog:Security` (EventCode=5145); `m365:unified` (Accessed SharePoint files or pages)
  - *Tune:* `UserContext` — Privileged users may be excluded if they routinely perform admin actions on SharePoint or file shares.; `AccessVolumeThreshold` — The number of files accessed or pages retrieved in a short window to flag as abnormal.; `TimeWindow` — The time range (e.g., 5 minutes, 1 hour) in which burst access patterns are considered anomalous.
- **`AN1161` Analytic 1161** · Linux
  Command-line tools (e.g., curl, rsync, wget, or custom Python scripts) used to scrape documentation systems or internal REST APIs. Unusual access patterns to knowledge base folders or shared team drives.
  - *Log sources:* `auditd:SYSCALL` (execve of curl, rsync, wget with internal knowledge base or IPs); `linux:Sysmon` (EventCode=3, 22)
  - *Tune:* `CommandRegex` — Regex matching internal doc servers, knowledge base paths, or IP patterns.; `TimeWindow` — Burst access of repositories over a short time window.
- **`AN1162` Analytic 1162** · SaaS
  Abuse of SaaS platforms such as Confluence, GitHub, SharePoint Online, or Slack to access excessive internal documentation or export source code/data. Includes use of tokens or browser automation from unapproved IPs.
  - *Log sources:* `saas:confluence` (access.content); `saas:slack` (Exported file or accessed admin API)
  - *Tune:* `APIUsageThreshold` — Number of API calls or files accessed before triggering detection.; `KnownSafeIPs` — Whitelist of internal IPs/users that may be excluded from detection.
- **`AN1163` Analytic 1163** · macOS
  Access of mounted cloud shares or document repositories via browser, terminal, or Finder by users not typically interacting with those resources. Includes script-based enumeration or mass download.
  - *Log sources:* `macos:unifiedlog` (access to /Volumes/SharePoint or network mount); `macos:osquery` (curl, python scripts, rsync with internal share URLs)
  - *Tune:* `AccessedMountPath` — Paths to sensitive volumes may differ based on org setup.; `UserGroup` — Expected user groups that typically access shared data.

---

### T1213.001 — Confluence
<a id="t1213001"></a>

**Detection strategy:** Programmatic and Excessive Access to Confluence Documentation (`DET0358`)  
**Platforms:** SaaS  
**ATT&CK:** [T1213.001](https://attack.mitre.org/techniques/T1213/001/) · [detail page](../../techniques/collection.md#t1213001)

- **`AN1019` Analytic 1019** · SaaS
  Detection of excessive or programmatic access to Confluence spaces or pages, particularly by privileged users, through a combination of access logs, API usage, and identity context. Correlates logon sessions, user roles, and abnormal document viewing or export behavior. Identifies burst access patterns and tools/scripts abusing the Confluence API for mass enumeration or data scraping.
  - *Log sources:* `saas:confluence` (access.content); `saas:confluence` (logon); `saas:confluence` (REST API access from non-browser agents)
  - *Tune:* `TimeWindow` — Defines the time span (e.g., 5m, 1h) in which excessive access behavior becomes suspicious.; `UserContext` — Privileged user roles (e.g., domain admins) should be excluded or flagged if found accessing documentation repositories.; `AccessThreshold` — The number of pages viewed or exported by a single user before triggering detection logic.; `AgentFilter` — User agent strings that may indicate scripted, automated, or non-interactive access methods.

---

### T1213.002 — Sharepoint
<a id="t1213002"></a>

**Detection strategy:** Detecting Abnormal SharePoint Data Mining by Privileged or Rare Users (`DET0500`)  
**Platforms:** Windows  
**ATT&CK:** [T1213.002](https://attack.mitre.org/techniques/T1213/002/) · [detail page](../../techniques/collection.md#t1213002)

- **`AN1380` Analytic 1380** · Windows
  Privileged or rarely used accounts performing bulk access to SharePoint files or metadata over a short time window, indicating potential scripted collection of sensitive internal documents.
  - *Log sources:* `m365:unified` (FileAccessed, FileDownloaded, SearchQueried); `azure:signinlogs` (UserLogin, ConditionalAccessPolicyEvaluated); `m365:sharepoint` (Multiple file download operations on a site by a privileged account in a short time window)
  - *Tune:* `UserContext` — Can be adjusted to focus on specific high-privilege or rarely-used service accounts; `TimeWindow` — Defines the aggregation period for multiple download events (e.g., 10 minutes); `DownloadThreshold` — Minimum number of documents accessed/downloaded to trigger alert; `SiteScope` — Limit detection to sensitive SharePoint sites such as HR, Finance, Engineering

---

### T1213.003 — Code Repositories
<a id="t1213003"></a>

**Detection strategy:** Detecting Bulk or Anomalous Access to Private Code Repositories via SaaS Platforms (`DET0263`)  
**Platforms:** SaaS  
**ATT&CK:** [T1213.003](https://attack.mitre.org/techniques/T1213/003/) · [detail page](../../techniques/collection.md#t1213003)

- **`AN0732` Analytic 0732** · SaaS
  Anomalous or bulk download activity from private or restricted repositories by non-developer or privileged accounts, often preceded by unusual login behavior (e.g., unfamiliar geo, OAuth token use, elevated API rate).
  - *Log sources:* `saas:github` (repo.download, repo.clone, oauth.authorize, repo.getContent); `saas:github` (Login from unusual IP, device fingerprint, or location; access token creation from new client); `saas:github` (Bulk access to multiple files or large volume of repo requests within short time window)
  - *Tune:* `TimeWindow` — Threshold for file access volume over short duration (e.g., 10+ repos accessed in <5 min); `UserContext` — Role or permission profile expected to interact with repositories (e.g., developers vs. admins); `GeoAnomalyThreshold` — Distance or variance allowed before a login is flagged as anomalous; `RepoSensitivityTag` — Whether a repository is labeled sensitive or restricted

---

### T1213.004 — Customer Relationship Management Software
<a id="t1213004"></a>

**Detection strategy:** Detecting Suspicious Access to CRM Data in SaaS Environments (`DET0550`)  
**Platforms:** SaaS  
**ATT&CK:** [T1213.004](https://attack.mitre.org/techniques/T1213/004/) · [detail page](../../techniques/collection.md#t1213004)

- **`AN1520` Analytic 1520** · SaaS
  Anomalous high-volume access to customer records in CRM software by a non-CRM admin user account, especially following initial authentication from a rare location or device. Behavior includes abnormal access to PII fields or data exports within a short time window.
  - *Log sources:* `saas:salesforce` (DataExport, RestAPI, Login, ReportExport); `m365:signinlogs` (UserLoggedIn)
  - *Tune:* `TimeWindow` — Duration over which bulk CRM queries occur (e.g., 1 minute, 5 minutes); varies by organization usage pattern; `UserContext` — User's CRM role, department, or job function (e.g., non-sales user accessing customer PII); `AnomalousExportThreshold` — Number of CRM objects (contacts, deals, logs) accessed or exported above normal; `SourceLocation` — Rare or impossible geolocation/IP address for legitimate CRM user access

---

### T1213.005 — Messaging Applications
<a id="t1213005"></a>

**Detection strategy:** Detecting Unauthorized Collection from Messaging Applications in SaaS and Office Environments (`DET0567`)  
**Platforms:** Office Suite, SaaS  
**ATT&CK:** [T1213.005](https://attack.mitre.org/techniques/T1213/005/) · [detail page](../../techniques/collection.md#t1213005)

- **`AN1565` Analytic 1565** · SaaS
  Atypical access to Slack or Teams conversations via APIs, automation tokens, or bulk message export functionality, particularly after an account takeover or rare sign-in pattern. Often includes mass retrieval of chat history, download of message content, or scraping of workspace/channel metadata.
  - *Log sources:* `saas:slack` (conversations.history, files.list, users.info, audit_logs); `m365:signinlogs` (UserLoggedIn)
  - *Tune:* `TimeWindow` — Time interval to observe post-login message scraping behavior; `MessageExportThreshold` — Number of messages or files accessed/downloaded to flag for review; `UserContext` — User privilege level, team membership, or role context to suppress false positives; `AccessMethod` — Direct user access vs API token, OAuth app, or bot interaction
- **`AN1566` Analytic 1566** · Office Suite
  Suspicious access to Microsoft Teams chat messages via eDiscovery, Graph API, or export methods after rare or compromised sign-in. Often associated with excessive file access, sensitive content review, or anomaly from expected user behavior.
  - *Log sources:* `m365:unified` (TeamsMessagesAccessedViaEDiscovery, TeamsGraphMessageExport); `m365:signinlogs` (UserLoggedIn)
  - *Tune:* `UserRole` — Whether user is part of InfoSec, Legal, or expected to use Teams eDiscovery tools; `GeoRiskScore` — Unusual country/IP sign-in patterns prior to Teams data export; `AccessVolume` — Message or file threshold for triggering alert

---

### T1213.006 — Databases
<a id="t1213006"></a>

**Detection strategy:** Suspicious Database Access and Dump Activity Across Environments (T1213.006) (`DET0242`)  
**Platforms:** IaaS, Linux, SaaS, Windows, macOS  
**ATT&CK:** [T1213.006](https://attack.mitre.org/techniques/T1213/006/) · [detail page](../../techniques/collection.md#t1213006)

- **`AN0676` Analytic 0676** · Linux
  Unusual database command-line access (e.g., `psql`, `mysql`, `mongo`) from non-admin users, occurring outside typical automation windows or without known service context. Often followed by data dumps to .sql/.csv files or outbound data transfers. Defender sees CLI tools launched interactively or by unusual parent processes, file writes to dump-like filenames, and external connections shortly after.
  - *Log sources:* `auditd:SYSCALL` (execve: Execution of CLI tools like psql, mysql, mongo, sqlite3); `auditd:PATH` (Creation of files with extensions .sql, .csv, .sqlite, especially in user directories); `NSM:Flow` (http::post: Outbound HTTP POST from host shortly after DB export activity)
  - *Tune:* `AllowedDBClients` — List of user or automation accounts expected to use database clients; `DumpFilePattern` — Filename patterns used to identify data dumps (e.g., *.sql, backup_*.csv); `TimeWindow` — Time threshold for correlating execution, file write, and outbound transfer
- **`AN0677` Analytic 0677** · Windows
  Database client execution (e.g., sqlcmd.exe, isql.exe) by users or from locations not tied to enterprise automation or backups. Often followed by creation of .sql/.bak/.csv files, registry artifacts for ODBC/JDBC drivers, or encrypted ZIPs. Defender sees SQL tools launched by explorer.exe, Powershell, or odd parent processes, plus file writes in user temp locations.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `KnownDBToolPaths` — Directories where legitimate database tools are installed; `ExportExtensionPatterns` — List of file extensions commonly used for DB exports; `MaxTransferVolume` — Threshold for outbound data volume that may suggest large DB dumps
- **`AN0678` Analytic 0678** · macOS
  Execution of Java-based or CLI database tools (e.g., DBeaver, Beekeeper, mysql, psql) from user profiles not tied to dev/admin roles, especially when followed by file writes and cloud sync activity. Defender correlates GUI tool launches, file write events in ~/Downloads or ~/Documents, and outbound API calls to known cloud services.
  - *Log sources:* `macos:unifiedlog` (Process start of Java or native DB client tools); `macos:unifiedlog` (Writes of .sql/.csv/.xlsx files to user documents/downloads); `NSM:Flow` (HTTPS API requests to Dropbox, iCloud, Google Drive, OneDrive shortly after DB tool usage)
  - *Tune:* `CloudSyncDomainList` — FQDNs of sync services used to detect likely outbound DB leakages; `UserPrivilegeLevel` — Whether to treat low-privilege users accessing DB tools as higher risk
- **`AN0679` Analytic 0679** · IaaS
  Database enumeration and export activity (e.g., `SELECT * FROM`, `SHOW DATABASES`) issued via ephemeral VMs, admin APIs, or cloud shell from non-monitoring accounts. Defender correlates audit logs (CloudTrail, GCP Admin, AzureDiagnostics), storage write ops, and cross-region transfers by identities not tied to DB operations.
  - *Log sources:* `AWS:CloudTrail` (rds:ExecuteStatement: Large data access via RDS or Aurora with unknown session context); `AWS:CloudTrail` (PutObject: S3 writes with .sql/.csv extension by same identity or within 5 min of DB access); `AWS:VPCFlowLogs` (Large transfer volume (>20MB) from RDS IP range to external public IPs)
  - *Tune:* `IAMAccessPatterns` — Define which IAM roles/accounts are allowed DB operations; `S3ExportThreshold` — Size threshold (MB) or file pattern for S3-based exfil monitoring; `DBQueryVerbosityThreshold` — Number of rows/columns or duration to flag long-running queries
- **`AN0680` Analytic 0680** · SaaS
  Unusual or excessive database/table exports from SaaS database platforms (e.g., Snowflake, Firebase, BigQuery, Airtable) by users or apps not in known analytics or dev groups. Defender observes access patterns outside baseline working hours or with new query templates, and correlates those with audit logs or file downloads.
  - *Log sources:* `saas:Snowflake` (QUERY: Large or repeated SELECT * queries to sensitive tables); `m365:unified` (Bulk downloads or API extractions from Microsoft-hosted data repositories (e.g., Dynamics 365))
  - *Tune:* `BaselineQueryTemplates` — Query hash or shape for common BI/ETL jobs to reduce false positives; `OffHoursAccessWindow` — Window to define after-hours activity thresholds for DB access

---

### T1530 — Data from Cloud Storage
<a id="t1530"></a>

**Detection strategy:** Multi-Platform Cloud Storage Exfiltration Behavior Chain (`DET0484`)  
**Platforms:** IaaS, Office Suite, SaaS  
**ATT&CK:** [T1530](https://attack.mitre.org/techniques/T1530/) · [detail page](../../techniques/collection.md#t1530)

- **`AN1328` Analytic 1328** · IaaS
  Spike in object access from new IAM user or role followed by data exfiltration to external IPs
  - *Log sources:* `AWS:CloudTrail` (GetObject, CopyObject); `AWS:CloudTrail` (AssumeRole); `AWS:VPCFlowLogs` (Unusual volume of data transferred from S3 storage endpoints to non-corporate IPs)
  - *Tune:* `TimeWindow` — Timeframe for data transfer correlation (e.g., 10 minutes); `ExternalIPAllowList` — Known list of corporate and expected outbound IP addresses
- **`AN1329` Analytic 1329** · SaaS
  OAuth token granted to external app followed by download of high-volume files in OneDrive/Google Drive
  - *Log sources:* `m365:unified` (FileAccessed, FileDownloaded, ConsentGranted)
  - *Tune:* `AppRegistrationNamePattern` — Pattern of suspicious OAuth app names (e.g., `rclone`, `mega`, `backup*`); `DownloadThresholdMB` — Flag file downloads over X MB (e.g., >100MB) within short intervals
- **`AN1330` Analytic 1330** · Office Suite
  Internal user account accesses shared links outside org followed by mass file download
  - *Log sources:* `m365:sharepoint` (AnonymousLinkCreated, FileDownloaded); `azure:signinlogs` (SigninSuccess)
  - *Tune:* `LinkVisibilityScope` — Whether links allow anonymous/external access; `DownloadBurstThreshold` — # of files downloaded within <5 mins (e.g., >50 files)

---

### T1560 — Archive Collected Data
<a id="t1560"></a>

**Detection strategy:** Detect Archiving and Encryption of Collected Data (T1560) (`DET0526`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1560](https://attack.mitre.org/techniques/T1560/) · [detail page](../../techniques/collection.md#t1560)

- **`AN1458` Analytic 1458** · Windows
  Detects adversarial archiving of files prior to exfiltration by correlating execution of compression/encryption utilities (e.g., makecab.exe, rar.exe, 7z.exe, powershell Compress-Archive) with subsequent creation of large compressed or encrypted files. Identifies abnormal process lineage involving crypt32.dll usage, command-line arguments invoking compression switches, and file write operations to temporary or staging directories.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `ArchiveExtensions` — List of file extensions treated as suspicious when created outside of expected paths.; `ProcessAllowlist` — Known business processes permitted to use compression/encryption utilities.; `FileSizeThresholdMB` — Minimum file size for flagging archive creation to reduce noise from benign small compressions.
- **`AN1459` Analytic 1459** · Linux
  Detects adversarial archiving activity through invocation of utilities like tar, gzip, bzip2, or openssl used in non-administrative or unusual contexts. Correlates command execution patterns with file creation of compressed/encrypted outputs in staging directories (e.g., /tmp, /var/tmp).
  - *Log sources:* `auditd:SYSCALL` (execve: Execution of tar, gzip, bzip2, or openssl with output redirection); `auditd:FILE` (create: Creation of files ending in .tar, .gz, .bz2, .zip in /tmp or /var/tmp)
  - *Tune:* `ArchiveCommands` — List of archiving/encryption utilities considered sensitive in the monitored environment.; `SuspiciousDirectories` — Paths where archive creation is suspicious (e.g., /tmp, user home directories).; `TimeWindow` — Temporal window to correlate command execution with file creation events.
- **`AN1460` Analytic 1460** · macOS
  Detects use of macOS-native archiving or encryption tools (zip, ditto, hdiutil) for staging collected data. Identifies unexpected invocation of archive utilities by Office apps, browsers, or background daemons. Correlates file creation of .zip/.dmg containers with process lineage anomalies.
  - *Log sources:* `macos:unifiedlog` (Execution of zip, ditto, hdiutil, or openssl by non-terminal parent processes); `macos:unifiedlog` (Creation of .zip or .dmg files in user-accessible or temporary directories)
  - *Tune:* `AllowedArchiveUtilities` — Business-approved applications (e.g., Time Machine, backup agents) that generate archives.; `UserContext` — Threshold for flagging archive creation under privileged or service accounts.; `PayloadEntropyThreshold` — Entropy threshold for detecting encrypted archives versus standard compressed files.

---

### T1560.001 — Archive via Utility
<a id="t1560001"></a>

**Detection strategy:** Detect Archiving via Utility (T1560.001) (`DET0298`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1560.001](https://attack.mitre.org/techniques/T1560/001/) · [detail page](../../techniques/collection.md#t1560001)

- **`AN0831` Analytic 0831** · Windows
  Detects adversarial archiving using built-in or third-party utilities (makecab, diantz, xcopy, certutil, 7z, WinRAR, WinZip). Correlates suspicious process creation events with command-line arguments for compression/encoding, followed by creation of archive files (.cab, .zip, .7z, .rar). Identifies anomalous loading of crypt32.dll for encryption operations or execution of diantz.exe to compress remotely staged files.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `SuspiciousExtensions` — List of archive extensions considered high risk (.cab, .zip, .7z, .rar).; `ProcessAllowlist` — Known business utilities allowed to create archives without alerting.; `FileSizeThresholdMB` — Minimum archive size threshold to filter out benign small compressions.
- **`AN0832` Analytic 0832** · Linux
  Detects execution of archiving utilities (tar, gzip, bzip2, xz, zip, openssl) followed by suspicious archive file creation. Correlates archive creation in temporary or staging directories with execution of commands involving compression or encryption options.
  - *Log sources:* `auditd:SYSCALL` (execve: Execution of tar, gzip, bzip2, xz, zip, or openssl with compression/encryption arguments); `auditd:FILE` (create: Creation of archive files in /tmp, /var/tmp, or user home directories)
  - *Tune:* `ArchiveCommands` — List of archiving utilities considered suspicious.; `MonitoredDirectories` — Paths where archive creation is flagged as unusual (e.g., /tmp, /var/tmp).; `TimeWindow` — Correlation window for linking utility execution with archive creation.
- **`AN0833` Analytic 0833** · macOS
  Detects invocation of macOS-native archiving utilities (zip, ditto, hdiutil) or openssl used for encryption. Correlates execution with archive or encrypted file creation (.zip, .dmg, .tar.gz) in user or temporary directories. Identifies anomalous use of archiving commands by Office applications or daemons.
  - *Log sources:* `macos:unifiedlog` (Execution of zip, ditto, hdiutil, or openssl by processes not normally associated with archiving); `macos:unifiedlog` (Creation of .zip, .dmg, .tar.gz files in /Users, /tmp, or application directories)
  - *Tune:* `AllowedArchivers` — Business-approved applications permitted to create archives (e.g., backup agents).; `UserContext` — Flag archiving under privileged or service accounts as higher risk.; `PayloadEntropyThreshold` — Entropy threshold for detecting encrypted archives versus normal compression.

---

### T1560.002 — Archive via Library
<a id="t1560002"></a>

**Detection strategy:** Detect Archiving via Library (T1560.002) (`DET0268`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1560.002](https://attack.mitre.org/techniques/T1560/002/) · [detail page](../../techniques/collection.md#t1560002)

- **`AN0747` Analytic 0747** · Windows
  Detects adversarial archiving using libraries (zlib, zip APIs) invoked by scripts or binaries. Correlates process executions of Python, PowerShell, or custom .NET binaries with DLL/module loads linked to compression libraries, followed by archive file creation.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `LibraryAllowlist` — Known business applications using compression libraries.; `SuspiciousExtensions` — Archive extensions considered sensitive in monitored environments.; `TimeWindow` — Correlation window between script/library invocation and file creation.
- **`AN0748` Analytic 0748** · Linux
  Detects adversarial archiving by scripts or binaries calling compression libraries (libzip, zlib, bzip2). Correlates execution of Python, Perl, or compiled binaries with dynamic linking to archiving libraries and creation of compressed files in /tmp or user directories.
  - *Log sources:* `auditd:SYSCALL` (execve: Execution of python, perl, or custom binaries invoking compression libraries); `auditd:MMAP` (load: Loading of libzip.so, libz.so, or libbz2.so by processes not normally associated with archiving); `auditd:FILE` (create: Creation of .zip, .gz, .bz2 files in /tmp, /var/tmp, or /home directories)
  - *Tune:* `MonitoredLibraries` — List of shared objects linked to compression/encryption.; `ArchivePaths` — Directories where archive creation is flagged as anomalous.; `EntropyThreshold` — Entropy level used to distinguish encryption from normal compression.
- **`AN0749` Analytic 0749** · macOS
  Detects malicious archiving via system or third-party libraries (libz, libarchive) invoked by Python, Swift, or Objective-C binaries. Correlates unified logs of library loads with creation of compressed or encrypted archives (.zip, .gz, .bz2, .dmg).
  - *Log sources:* `macos:unifiedlog` (Execution of Python, Swift, or other binaries invoking archiving libraries); `macos:unifiedlog` (Loading of libz.dylib, libarchive.dylib by non-standard applications); `macos:unifiedlog` (Creation of .zip, .gz, .dmg archives in /Users, /tmp, or application directories)
  - *Tune:* `AllowedProcesses` — Applications allowed to load compression libraries (e.g., backup agents).; `UserContext` — Flag archiving under privileged or system accounts as suspicious.; `FileExtensionFilter` — Targeted monitoring of sensitive file formats or compressed containers.

---

### T1560.003 — Archive via Custom Method
<a id="t1560003"></a>

**Detection strategy:** Detect Archiving via Custom Method (T1560.003) (`DET0438`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1560.003](https://attack.mitre.org/techniques/T1560/003/) · [detail page](../../techniques/collection.md#t1560003)

- **`AN1213` Analytic 1213** · Windows
  Detects suspicious custom compression/encryption routines through anomalous script or binary execution that produces high-entropy files without standard archiving utilities. Correlates script execution, memory API usage (bitwise ops, CryptoAPI calls), and creation of archive-like files with uncommon headers.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=10)
  - *Tune:* `EntropyThreshold` — Minimum entropy level that flags suspicious custom archives.; `AllowedProcesses` — Known business processes performing encryption or compression.; `TimeWindow` — Correlation timeframe between script execution and file creation.
- **`AN1214` Analytic 1214** · Linux
  Detects custom archive routines by correlating script execution (Python, Perl, Bash) with creation of high-entropy files in temporary or user directories. Flags processes performing unusual bitwise operations or writing files without standard compression headers.
  - *Log sources:* `auditd:SYSCALL` (execve: Execution of interpreters creating archive-like outputs without calling tar/gzip); `auditd:FILE` (create: Creation of files with anomalous headers and entropy levels in /tmp or user directories); `linux:osquery` (Detection of bitwise operations or custom encryption functions in memory traces)
  - *Tune:* `ArchivePaths` — Directories monitored for anomalous archive creation (e.g., /tmp, /home).; `EntropyThreshold` — Entropy score to flag files lacking recognizable compression headers.; `ScriptAllowlist` — Scripts/processes known to use custom compression methods.
- **`AN1215` Analytic 1215** · macOS
  Detects custom archiving by monitoring execution of Swift/Objective-C apps or scripts producing high-entropy files with non-standard headers. Correlates unified logs of abnormal NSFileHandle/NSData operations, memory use of XOR/bitwise operations, and file creation events.
  - *Log sources:* `macos:unifiedlog` (Suspicious Swift/Objective-C or scripting processes writing archive-like outputs); `macos:unifiedlog` (Creation of files with anomalous headers and entropy values); `macos:unifiedlog` (Abnormal memory operations (XOR/bitwise loops) during archive generation)
  - *Tune:* `UserContext` — Flag if archiving occurs under privileged/system accounts.; `EntropyThreshold` — Entropy score cutoff for identifying custom compressed or encrypted files.; `AllowedApps` — Applications legitimately using custom archiving for business purposes.

---

### T1602 — Data from Configuration Repository
<a id="t1602"></a>

**Detection strategy:** Detection Strategy for Data from Configuration Repository on Network Devices (`DET0592`)  
**Platforms:** Network Devices  
**ATT&CK:** [T1602](https://attack.mitre.org/techniques/T1602/) · [detail page](../../techniques/collection.md#t1602)

- **`AN1630` Analytic 1630** · Network Devices
  Defenders may observe adversary attempts to extract configuration data from management repositories by monitoring for anomalous SNMP queries, API calls, or protocol requests (e.g., NETCONF, RESTCONF) that enumerate system configuration. Suspicious sequences include repeated queries from untrusted IPs, abnormal query types requesting sensitive configuration data, or repository access occurring outside of normal administrative maintenance windows. Abnormal authentication attempts, sudden enumeration of device inventory, or bulk data transfer of configuration files may also be observed.
  - *Log sources:* `NSM:Flow` (Unexpected or unauthorized inbound connections to SNMP, NETCONF, or RESTCONF services); `networkdevice:syslog` (Authentication failures or unusual community string usage in SNMP queries)
  - *Tune:* `AuthorizedAdminIPs` — Expected IP ranges or hosts permitted to query configuration repositories; deviations may indicate compromise.; `NormalAccessTimeWindow` — Time periods when configuration queries normally occur; anomalies outside these windows may be suspicious.; `QueryVolumeThreshold` — Number of queries allowed within a given period before an anomaly is triggered.; `ProtocolUsageBaseline` — Expected usage of SNMP, NETCONF, or RESTCONF; deviations from baseline patterns may indicate misuse.

---

### T1602.001 — SNMP (MIB Dump)
<a id="t1602001"></a>

**Detection strategy:** Detection Strategy for SNMP (MIB Dump) on Network Devices (`DET0453`)  
**Platforms:** Network Devices  
**ATT&CK:** [T1602.001](https://attack.mitre.org/techniques/T1602/001/) · [detail page](../../techniques/collection.md#t1602001)

- **`AN1249` Analytic 1249** · Network Devices
  Defenders may observe suspicious SNMP MIB enumeration through abnormal queries for large sets of OIDs, repeated SNMP GETBULK/GETNEXT requests, or queries originating from non-administrative IP addresses. Anomalous use of community strings, authentication failures, or enumeration activity outside maintenance windows may also indicate attempts to dump MIB contents. Correlation across syslog, NetFlow, and SNMP audit data can reveal chains of behavior such as repeated authentication failures followed by successful large-scale OID retrieval.
  - *Log sources:* `networkdevice:syslog` (Authentication failures, unexpected community string usage, or unauthorized SNMPv1/v2 requests); `NSM:Flow` (High-volume or repeated SNMP GETBULK/GETNEXT queries from untrusted or external IPs); `networkdevice:audit` (SNMP configuration changes, such as enabling read/write access or modifying community strings)
  - *Tune:* `AuthorizedAdminIPs` — Expected IP ranges allowed to query SNMP. Deviation indicates possible misuse.; `NormalSNMPQueryRate` — Baseline frequency and volume of SNMP queries; anomalies above threshold may indicate dumping.; `CommunityStringPatterns` — Expected community strings (e.g., hashed or custom values). Unrecognized strings may signal abuse.; `TimeWindow` — Time periods during which SNMP queries are authorized. Queries outside these hours may be malicious.

---

### T1602.002 — Network Device Configuration Dump
<a id="t1602002"></a>

**Detection strategy:** Detection Strategy for Network Device Configuration Dump via Config Repositories (`DET0233`)  
**Platforms:** Network Devices  
**ATT&CK:** [T1602.002](https://attack.mitre.org/techniques/T1602/002/) · [detail page](../../techniques/collection.md#t1602002)

- **`AN0647` Analytic 0647** · Network Devices
  Defenders may observe adversary attempts to collect or export full device configurations by detecting unusual SNMP queries, Smart Install (SMI) activity, or CLI/API commands that request running or startup configuration dumps. Correlated behaviors include high-volume read requests for sensitive OIDs, repeated use of 'show running-config' or equivalent commands from untrusted IPs, or unexpected TFTP/SCP/FTP transfers containing configuration files. These behaviors often appear in sequence: anomalous authentication or privilege escalation, followed by bulk configuration retrieval and outbound transfer.
  - *Log sources:* `networkdevice:syslog` (Failed and successful logins to network devices outside approved admin IP ranges); `networkdevice:cli` (Execution of commands like 'show running-config', 'copy running-config', or 'export config'); `NSM:Flow` (Outbound SCP, TFTP, or FTP sessions carrying configuration file content); `snmp:access` (GETBULK/GETNEXT requests for OIDs associated with configuration parameters)
  - *Tune:* `AuthorizedAdminIPs` — Known trusted IP addresses permitted to execute configuration dump commands.; `NormalConfigExportRate` — Baseline frequency of legitimate configuration exports; anomalies above threshold may indicate malicious activity.; `AllowedTransferProtocols` — Expected transfer methods (e.g., SCP vs. TFTP). Unexpected use of weak protocols may indicate exfiltration.; `TimeWindow` — Normal maintenance windows for authorized configuration exports; activity outside these windows may be suspicious.

---

