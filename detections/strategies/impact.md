# Impact — Detection Strategies

> MITRE ATT&CK detection strategies and analytics (v18.1) for techniques whose primary tactic is **Impact**. Each analytic lists the **log sources / channels** it needs, the **detection logic**, and the **tunable elements** to adapt it to your environment. Authoritative source: the ATT&CK detection-strategy model in the Enterprise STIX.

See also: [all detection strategies index](/detections/strategies/README.md) · [Technique Detection Library](../TECHNIQUE_DETECTION_LIBRARY.md) (ready-to-run SIEM queries) · [Data Components & Log Sources](../../ATTACK_DATA_COMPONENTS.md) · [Technique Detail Pages](../../techniques/README.md)

---

### T1485 — Data Destruction
<a id="t1485"></a>

**Detection strategy:** Detection of Data Destruction Across Platforms via Mass Overwrite and Deletion Patterns (`DET0146`)  
**Platforms:** Containers, ESXi, IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1485](https://attack.mitre.org/techniques/T1485/) · [detail page](../../techniques/impact.md#t1485)

- **`AN0411` Analytic 0411** · Windows
  Adversary spawns command-line tools (e.g., del, cipher /w, SDelete) or scripts to recursively delete or overwrite user/system files. This may be correlated with abnormal file IO activity, registry writes, or tampering in critical system directories.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=23)
  - *Tune:* `TargetFilename` — Filter file deletion activity to sensitive locations (e.g., %System32%, Documents, DB paths).; `ProcessCommandLine` — Tune for aggressive overwrite flags (e.g., /w, /q, /s) or temp file overwrites.; `VolumeThreshold` — Threshold of unique file deletions or modifications within time window.; `TimeWindow` — Correlate rapid file delete/overwrite behavior from same process/user.
- **`AN0412` Analytic 0412** · Linux
  Massive recursive deletions or overwrites via `rm -rf`, `shred`, `dd`, or wiper binaries. May include unlink syscalls, deletion of known config/data paths, or sequential overwrite patterns.
  - *Log sources:* `auditd:SYSCALL` (unlink, unlinkat, openat, write); `auditd:SYSCALL` (execve)
  - *Tune:* `ExecutablePath` — Focus on binaries like shred, dd, wipe, custom wipers, or bash execution chains.; `DeletedPathPattern` — Tune for critical mount points or home/data directories.; `SyscallBurstRate` — Rate of unlink/unlinkat syscalls to indicate mass deletion in a short period.
- **`AN0413` Analytic 0413** · macOS
  Destruction via `rm -rf`, overwrite with `dd` or `srm`, often executed by script in /tmp or /private/tmp, may also involve file overwrite to political or decoy image data.
  - *Log sources:* `macos:unifiedlog` (exec rm -rf|dd if=/dev|srm|file unlink); `macos:unifiedlog` (process.*exit.*code)
  - *Tune:* `CommandPattern` — Focus on high-risk patterns in temporary directories or key system paths.; `EntropyChangeRate` — Optional anomaly detection on overwritten files with high-entropy payloads.
- **`AN0414` Analytic 0414** · IaaS
  Adversary deletes critical infrastructure: EC2 instances, S3 buckets, snapshots, or volumes using elevated IAM credentials. Frequently includes batch API calls with `Delete*` or `TerminateInstances`.
  - *Log sources:* `AWS:CloudTrail` (DeleteBucket, DeleteDBCluster, DeleteSnapshot, TerminateInstances)
  - *Tune:* `OperationType` — Correlate multiple destructive API calls over short intervals.; `UserAgent` — Flag non-console/API clients initiating destructive behavior.; `RegionScope` — Observe whether deletions span multiple regions or org accounts.
- **`AN0415` Analytic 0415** · ESXi
  Adversary destroys virtual disks (VMDK), images, or VMs by invoking `vim-cmd`, deleting datastore contents, or purging snapshots.
  - *Log sources:* `esxi:vmkernel` (file delete|datastore purge)
  - *Tune:* `DatastorePath` — Targeted deletion of critical VMDKs or VM configuration files.; `InitiatingUser` — Detect deletions from users outside normal maintenance windows.
- **`AN0416` Analytic 0416** · Containers
  Container process executes destructive file operations inside volume mounts or host paths. Includes `rm -rf /mnt/volumes/`, container breakout followed by host deletion attempts.
  - *Log sources:* `auditd:SYSCALL` (unlink, unlinkat, rmdir); `docker:events` (container exec rm|container stop --force)
  - *Tune:* `MountPoint` — Identify when deletions occur inside persistent or shared volume paths.; `ContainerImage` — Correlate destructive behavior with unknown or untrusted container sources.

---

### T1485.001 — Lifecycle-Triggered Deletion
<a id="t1485001"></a>

**Detection strategy:** Detection of Lifecycle Policy Modifications for Triggered Deletion in IaaS Cloud Storage (`DET0041`)  
**Platforms:** IaaS  
**ATT&CK:** [T1485.001](https://attack.mitre.org/techniques/T1485/001/) · [detail page](../../techniques/impact.md#t1485001)

- **`AN0117` Analytic 0117** · IaaS
  Adversary with write access to storage modifies lifecycle policies (e.g., via PutBucketLifecycle) to schedule rapid object deletion across one or more storage buckets. This is often used to trigger impact (destruction), remove logs (defense evasion), or force extortion (ransomware).
  - *Log sources:* `AWS:CloudTrail` (PutBucketLifecycle, PutLifecycleConfiguration, SetBucketLifecycle, storage.buckets.update)
  - *Tune:* `LifecycleExpirationDays` — Policy values setting Expiration in fewer than N days (e.g., 0–1) are highly suspicious.; `TargetBucket` — Filter by bucket types (e.g., log storage, production DB snapshots) to prioritize detection.; `Principal` — Correlate rare or anomalous IAM principals making destructive lifecycle changes.; `TimeWindow` — Link lifecycle policy change with API activity suggesting staged deletion or extortion attempt.

---

### T1486 — Data Encrypted for Impact
<a id="t1486"></a>

**Detection strategy:** Detection of Multi-Platform File Encryption for Impact (`DET0215`)  
**Platforms:** ESXi, IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1486](https://attack.mitre.org/techniques/T1486/) · [detail page](../../techniques/impact.md#t1486)

- **`AN0602` Analytic 0602** · Windows
  High-frequency file write operations using uncommon extensions, followed by ransom note creation, registry tampering, or shadow copy deletion. Often uses CLI tools like vssadmin, wbadmin, cipher, or PowerShell.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=2)
  - *Tune:* `FileExtension` — Non-standard or randomly generated file extensions may indicate encrypted content.; `TargetFolder` — Focus on user document folders, network shares, or system paths like %System32%.; `TimeWindow` — Correlate rapid writes and renames within seconds across high file count.; `CommandLine` — Flag common ransomware tools or functions (vssadmin delete shadows /all /quiet).
- **`AN0603` Analytic 0603** · Linux
  Encryption via custom or open-source tools (e.g., openssl, gpg, aescrypt) recursively targeting user or system directories. Also includes overwrite of existing data and ransom note drops.
  - *Log sources:* `auditd:SYSCALL` (openat, write, rename, unlink); `auditd:SYSCALL` (execve)
  - *Tune:* `FilenamePattern` — Look for creation of ransom note files (e.g., READ_ME.txt, HELP_DECRYPT.html).; `SyscallBurstRate` — High write/open/unlink activity in short intervals indicates encryption attempts.; `DirectoryTargeted` — Correlate activity in /home, /etc, /opt, or mounted volumes.
- **`AN0604` Analytic 0604** · macOS
  Userland or kernel-level ransomware encrypting user files (Documents, Desktop) using `srm`, `gpg`, or compiled payloads. Often correlated with ransom note creation in multiple directories.
  - *Log sources:* `macos:unifiedlog` (file encrypted|new file with .encrypted extension|disk write burst); `macos:unifiedlog` (exec srm|exec openssl|exec gpg)
  - *Tune:* `ExtensionPattern` — Encrypted files may use .locked, .enc, or ransom-specific extensions.; `VolumeTargeted` — Detect activity targeting mounted external or backup volumes.
- **`AN0605` Analytic 0605** · ESXi
  Ransomware encrypts .vmdk, .vmx, .log, or VM config files in VMFS datastores. May rename to .locked or delete/overwrite with encrypted versions. Often correlates with shell commands run through `dcui`, SSH, or vSphere.
  - *Log sources:* `esxi:vmkernel` (rename .vmdk to .*.locked|datastore write spike); `esxi:shell` (openssl|tar|dd)
  - *Tune:* `FileType` — Detect renames or write patterns involving .vmdk, .vmx, .nvram.; `UserContext` — Identify shell sessions opened by root or unexpected users outside maintenance window.
- **`AN0606` Analytic 0606** · IaaS
  Encryption of cloud storage objects (e.g., S3 buckets) via Server-Side Encryption (SSE-C) or by replacing objects with encrypted variants. May include API patterns like PutObject with SSE-C headers.
  - *Log sources:* `AWS:CloudTrail` (PutObject (with SSE-C), UploadPart (SSE-C))
  - *Tune:* `SSEHeader` — SSE-C headers indicate attacker-controlled encryption keys.; `AffectedBucket` — Prioritize logs, backups, or shared document storage buckets.; `UserAgent` — Detect scripted automation vs console-based API behavior.

---

### T1489 — Service Stop
<a id="t1489"></a>

**Detection strategy:** Behavioral Detection for Service Stop across Platforms (`DET0021`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1489](https://attack.mitre.org/techniques/T1489/) · [detail page](../../techniques/impact.md#t1489)

- **`AN0061` Analytic 0061** · Windows
  Adversary disables or stops critical services (e.g., Exchange, SQL, AV, endpoint monitoring) using native utilities or API calls, often preceding destructive actions (T1485, T1486). Behavioral chain: Elevated execution context + stop-service or sc.exe or ChangeServiceConfigW + terminated or disabled service + possible follow-up file manipulation.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Security` (EventCode=4672); `WinEventLog:System` (EventCode=7036); `WinEventLog:Sysmon` (EventCode=4)
  - *Tune:* `TimeWindow` — Time span between elevated privilege use and critical service stop; `ServiceName` — Service names of interest (e.g., MSExchangeIS, SQLSERVERAGENT); `ParentProcess` — Upstream process lineage leading to service stop
- **`AN0062` Analytic 0062** · Linux
  Adversary executes systemctl or service stop targeting high-value services (e.g., mysql, sshd), possibly followed by rm or shred against data stores. Behavioral chain: sudo/su usage + stop command + /var/log/messages or syslog entries + file access/delete.
  - *Log sources:* `auditd:SYSCALL` (execve of systemctl or service stop); `auditd:SYSCALL` (unlink/unlinkat on service binaries or data targets); `linux:syslog` (service stopped messages)
  - *Tune:* `TimeWindow` — Window between service stop and suspicious file deletion; `ExecUser` — Username or UID executing service stop command
- **`AN0063` Analytic 0063** · macOS
  Use of launchctl to stop services or kill critical background processes (e.g., securityd, com.apple.*), typically followed by command-line tools like rm or diskutil. Behavioral chain: Terminal or remote shell + launchctl bootout/disable + process termination + follow-on modification.
  - *Log sources:* `macos:unifiedlog` (launchctl disable or bootout calls); `auditd:SYSCALL` (execve of launchctl or pkill)
  - *Tune:* `ServiceLabel` — Launch daemon label or name targeted by command; `LaunchType` — Whether the command disables or boots out the service
- **`AN0064` Analytic 0064** · ESXi
  Attacker disables VM-related services or stops VMs forcibly to target vmdk or logs. Behavioral chain: esxcli or vim-cmd stop + audit log showing user privilege use + datastore file manipulation.
  - *Log sources:* `esxi:hostd` (Stop VM or disable service events via vim-cmd); `esxi:hostd` (Log entries indicating VM powered off or forcibly terminated)
  - *Tune:* `VMName` — Targeted virtual machine name; `InitiatorUser` — User who issued stop or disable command

---

### T1490 — Inhibit System Recovery
<a id="t1490"></a>

**Detection strategy:** Behavioral Detection for T1490 - Inhibit System Recovery (`DET0329`)  
**Platforms:** ESXi, IaaS, Linux, Network Devices, Windows  
**ATT&CK:** [T1490](https://attack.mitre.org/techniques/T1490/) · [detail page](../../techniques/impact.md#t1490)

- **`AN0933` Analytic 0933** · Windows
  Process chains that use native utilities (vssadmin, wbadmin, diskshadow, bcdedit, REAgentC, wmic) with arguments to delete shadow copies, disable recovery, or remove backup catalogs
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Microsoft-Windows-Backup` (Windows Backup Catalog deletion or catalog corruption); `WinEventLog:System` (Service stopped or RecoveryDisabled set via REAgentC); `WinEventLog:Sysmon` (EventCode=13, 14)
  - *Tune:* `TimeWindow` — Used to track rapid recovery feature changes over short intervals; `CommandLinePattern` — Can be tuned to catch variations in destructive flags (/all, /quiet, -delete); `ParentProcessContext` — Tune based on common parent-child chains (e.g., powershell → diskshadow)
- **`AN0934` Analytic 0934** · Linux
  Shell utilities or scripts deleting `/etc/systemd/system/rescue.target`, `/etc/fstab` backups, or `/boot/efi` partitions; chattr used to block snapshot auto-recovery
  - *Log sources:* `auditd:SYSCALL` (chattr, rm, shred, dd run on recovery directories or partitions); `auditd:CONFIG_CHANGE` (/etc/fstab, /etc/systemd/*)
  - *Tune:* `WatchedFilePaths` — Modify to include specific OS backup configs or LVM snapshots; `ShellProcessUser` — Restrict detection to root or sudo users
- **`AN0935` Analytic 0935** · ESXi
  ESXi shell or vim-cmd execution that deletes all VM snapshots using vmsvc/snapshot.removeall or rm on snapshot paths
  - *Log sources:* `esxi:hostd` (snapshot.removeall or snapshot file deletion)
  - *Tune:* `TargetVMNames` — Limit to critical VM names to reduce false positives
- **`AN0936` Analytic 0936** · Network Devices
  Execution of `erase`, `format`, and `reload` in immediate sequence from a privileged AAA session
  - *Log sources:* `networkdevice:syslog` (command sequence: erase → format → reload)
  - *Tune:* `CommandSequenceWindow` — Time between erase and reload command to establish causality; `UserPrivilegeLevel` — Filter for high-privilege user sessions
- **`AN0937` Analytic 0937** · IaaS
  Cloud API calls disabling snapshot scheduling, backup policies, versioning, followed by DeleteSnapshot/DeleteVolume operations
  - *Log sources:* `AWS:CloudTrail` (DeleteSnapshot); `AWS:CloudTrail` (DeleteBucket, DeleteDBCluster, DeleteSnapshot, TerminateInstances)
  - *Tune:* `UserAgent` — Tune for legitimate backup automation vs unknown tools; `ResourceType` — Filter only on production images or vaults

---

### T1491 — Defacement
<a id="t1491"></a>

**Detection strategy:** Defacement via File and Web Content Modification Across Platforms (`DET0238`)  
**Platforms:** ESXi, IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1491](https://attack.mitre.org/techniques/T1491/) · [detail page](../../techniques/impact.md#t1491)

- **`AN0662` Analytic 0662** · Windows
  Adversary modifies website or application-hosted content via unauthorized file changes or script injections, often by exploiting web servers or CMS access.
  - *Log sources:* `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Application` (Unexpected web application errors or CMS logs showing modification to index.html, default.aspx, or other public-facing files)
  - *Tune:* `target_filenames` — Environment-specific naming of defacement-prone files like 'index.html', 'main.css', 'app.js'.; `TimeWindow` — Detection based on rapid sequence of file writes and script injections within short time intervals.
- **`AN0663` Analytic 0663** · Linux
  Adversary gains shell access or uploads a malicious script to deface hosted web content in Nginx, Apache, or other services.
  - *Log sources:* `auditd:SYSCALL` (write); `apache:access_log` (Unusual HTTP POST or PUT requests to paths such as '/uploads/', '/admin/', or CMS plugin folders); `linux:syslog` (Unauthorized sudo or shell access, especially leading to file changes in /var/www or /srv/http)
  - *Tune:* `UploadPathRegex` — Regex for CMS-specific upload directories subject to defacement (e.g., wp-content/uploads).; `FileExtensionScope` — Types of files to monitor for defacement (e.g., .html, .php, .jsp).
- **`AN0664` Analytic 0664** · macOS
  Adversary modifies internal or external site content through manipulated application bundles, hosted content, or web server configs.
  - *Log sources:* `macos:unifiedlog` (Execution of unexpected terminal or web scripts modifying /Library/WebServer/Documents); `macos:unifiedlog` (File creation or overwrite in common web-hosting folders)
  - *Tune:* `TargetDirectoryPath` — Web root folders will vary depending on how services are configured on macOS (e.g., /Library/WebServer/Documents).
- **`AN0665` Analytic 0665** · ESXi
  Adversary defaces internal VM-hosted portals or web UIs by modifying static content on datastore-mounted paths.
  - *Log sources:* `esxi:vmkernel` (Unauthorized file modifications within datastore volumes via shell access or vCLI)
  - *Tune:* `DatastoreVolumeName` — Each environment’s VMFS/volume mounts will vary in name and path.
- **`AN0666` Analytic 0666** · IaaS
  Adversary uses compromised instance credentials or web application access to deface content hosted in S3 buckets, Azure Blob Storage, or GCP Buckets.
  - *Log sources:* `CloudTrail:PutObject` (PutObject); `AWS:CloudTrail` (GetObject, CopyObject)
  - *Tune:* `BucketNameRegex` — Patterns of S3 or GCP buckets used for static website hosting may vary by organization.; `IAMRoleContext` — Some uploads may appear benign unless enriched with user/role metadata.

---

### T1491.001 — Internal Defacement
<a id="t1491001"></a>

**Detection strategy:** Internal Website and System Content Defacement via UI or Messaging Modifications (`DET0082`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1491.001](https://attack.mitre.org/techniques/T1491/001/) · [detail page](../../techniques/impact.md#t1491001)

- **`AN0229` Analytic 0229** · Windows
  Adversary modifies internal UI messages (e.g., login banners, desktop wallpapers) or hosted intranet web pages by creating or altering content files using scripts or unauthorized access. Often preceded by privilege escalation or web shell deployment.
  - *Log sources:* `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=2); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `FilePathPattern` — Location of web content or system UI config files that may vary across deployments (e.g., %SystemRoot%\Web, %APPDATA%\wallpaper.jpg); `TimeWindow` — Allowed hours for file/content modification events; defacement likely occurs during off-hours; `UserContext` — System or domain accounts used to perform the modifications may be anomalous
- **`AN0230` Analytic 0230** · Linux
  Adversary leverages root or sudo access to alter system banners, web content directories (e.g., /var/www/html), or login configurations (/etc/issue). File creation or overwrites may coincide with suspicious script execution or cron job activity.
  - *Log sources:* `auditd:SYSCALL` (open/write/unlink); `auditd:SYSCALL` (execve); `linux:syslog` (sudo or su access prior to content change)
  - *Tune:* `TargetDirectories` — Paths like /var/www/html, /etc/issue, or /etc/motd may vary across distros; `UserContext` — Non-web-admin users modifying site content or banners should be rare; `TimeWindow` — Defacement often happens outside normal maintenance hours
- **`AN0231` Analytic 0231** · macOS
  Modification of user desktop backgrounds, login screen messages, or system banners by adversaries using admin privileges or script execution. May coincide with tampering in /Library/Desktop Pictures/ or use of AppleScript.
  - *Log sources:* `macos:unifiedlog` (loginwindow or desktopservices modified settings or files); `macos:unifiedlog` (osascript or AppleScript invocation modifying UI)
  - *Tune:* `ScriptNames` — Uncommon scripts like AppleScript variants or osascript for wallpaper changes; `UserContext` — Normal users should not alter global visual settings
- **`AN0232` Analytic 0232** · ESXi
  Adversary modifies ESXi host login banner or MOTD file (/etc/motd), either through SSH or host console access. May involve configuration file overwrite or API calls from compromised vSphere clients.
  - *Log sources:* `ESXiLogs:messages` (changes to /etc/motd or /etc/vmware/welcome); `esxi:hostd` (modification of config files or shell command execution)
  - *Tune:* `LoginBannerFilePath` — Target file paths (e.g., /etc/motd) may be changed via symbolic link or override; `AccessOrigin` — ESXi hostd vs. SSH-based defacement origin may affect visibility

---

### T1491.002 — External Defacement
<a id="t1491002"></a>

**Detection strategy:** Behavioral Detection of External Website Defacement across Platforms (`DET0590`)  
**Platforms:** IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1491.002](https://attack.mitre.org/techniques/T1491/002/) · [detail page](../../techniques/impact.md#t1491002)

- **`AN1622` Analytic 1622** · Windows
  Adversary modifies externally-facing web content by accessing and overwriting hosted HTML/JS/CSS files, typically following web shell deployment, credential abuse, or exploitation of web application vulnerabilities.
  - *Log sources:* `WinEventLog:Security` (EventCode=4663, 4670, 4656); `NSM:Connections` (Unusual POST requests to admin or upload endpoints); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `target_directory` — Web root folder varies by environment, e.g., C:\inetpub\wwwroot; `UserContext` — May vary based on which service account hosts the website; `TimeWindow` — Time between webshell upload and file overwrite may vary
- **`AN1623` Analytic 1623** · Linux
  Adversary compromises a Linux-based web server and modifies hosted web files by exploiting upload vulnerabilities, remote code execution, or replacing index.html via SSH/webshell.
  - *Log sources:* `auditd:SYSCALL` (open/write syscalls targeting web directory files); `NSM:Connections` (Successful sudo or ssh from unknown IPs); `NSM:Flow` (Suspicious POSTs to upload endpoints)
  - *Tune:* `web_root` — May differ (e.g., /var/www/html, /srv/http, etc.); `payload_hash` — Adversary content hash may change across campaigns; `UserContext` — Can range from apache/nginx user to root if escalated
- **`AN1624` Analytic 1624** · macOS
  Adversary modifies web-facing content on macOS via web development environments like MAMP or misconfigured Apache instances, typically with access to the hosting user account or via persistence tools.
  - *Log sources:* `macos:unifiedlog` (Terminal/Editor processes modifying web folder); `macos:unifiedlog` (loginwindow or sshd events with external IP)
  - *Tune:* `web_root_dir` — May include ~/Sites or custom Apache paths; `editor_name` — Text editor or script modifying the files may vary (e.g., nano, VS Code)
- **`AN1625` Analytic 1625** · IaaS
  Adversary modifies content in cloud-hosted websites (e.g., AWS S3-backed, Azure Blob-hosted sites) by gaining access to management consoles or APIs and uploading altered HTML/JS files.
  - *Log sources:* `AWS:CloudTrail` (PutObject); `AWS:CloudTrail` (ListBuckets); `AWS:CloudTrail` (GetObject, CopyObject)
  - *Tune:* `bucket_name` — Website bucket name varies per org; `region` — Adversary may target multi-region failover setups; `IAMRole` — Attack may leverage stolen cross-account roles or elevated policies

---

### T1495 — Firmware Corruption
<a id="t1495"></a>

**Detection strategy:** Firmware Modification via Flash Tool or Corrupted Firmware Upload (`DET0167`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1495](https://attack.mitre.org/techniques/T1495/) · [detail page](../../techniques/impact.md#t1495)

- **`AN0474` Analytic 0474** · Windows
  Firmware flash utility invoked with elevated privileges followed by raw access to firmware device path or changes to boot configuration.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=6); `WinEventLog:Microsoft-Windows-Kernel-Boot` (Firmware integrity validation failed or boot configuration tampered)
  - *Tune:* `ParentImage` — Common legitimate flash tool chains can be allowlisted; `CommandLine` — Flags indicating silent or forced flash may vary
- **`AN0475` Analytic 0475** · Linux
  Direct write access to /dev/mem or /sys/firmware combined with usage of firmware flashing utilities (e.g., flashrom).
  - *Log sources:* `auditd:SYSCALL` (write access to /dev/mem or /sys/firmware/efi/efivars); `auditd:SYSCALL` (execution of known flash tools (e.g., flashrom, fwupd))
  - *Tune:* `ToolName` — Custom or renamed firmware tools may require pattern matching
- **`AN0476` Analytic 0476** · macOS
  EFI updates executed via system processes or binaries outside of expected patch windows or using unsigned firmware packages.
  - *Log sources:* `macos:unifiedlog` (com.apple.firmwareupdater activity or update-firmware binary invoked); `macos:unifiedlog` (boot failure events or SMC validation errors)
  - *Tune:* `UpdateTimeWindow` — Firmware updates usually occur after OS update; out-of-band patterns may indicate compromise
- **`AN0477` Analytic 0477** · Network Devices
  Firmware image uploaded via TFTP/SCP or web interface followed by reboot or unexpected loss of connectivity.
  - *Log sources:* `NSM:Flow` (large upload to firmware interface port or path); `networkdevice:firmware` (Firmware update initiated or bootloader tampering detected)
  - *Tune:* `UploadSizeThreshold` — Size of firmware images varies by vendor; `RebootWindow` — Reboots outside of patch maintenance may be suspicious

---

### T1496 — Resource Hijacking
<a id="t1496"></a>

**Detection strategy:** Resource Hijacking Detection Strategy (`DET0267`)  
**Platforms:** Containers, IaaS, Linux, SaaS, Windows, macOS  
**ATT&CK:** [T1496](https://attack.mitre.org/techniques/T1496/) · [detail page](../../techniques/impact.md#t1496)

- **`AN0741` Analytic 0741** · Windows
  Persistent high CPU utilization combined with suspicious command-line execution (e.g., mining tools or obfuscated scripts) and outbound connections to mining/proxy networks.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `Windows:perfmon` (High sustained CPU usage by a single process); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `TimeWindow` — Duration threshold for sustained CPU activity (e.g., >15 minutes); `DestinationIPList` — Known mining pool IPs or proxy service endpoints; `ExecutableNamePatterns` — Regex list of suspicious or known mining tools
- **`AN0742` Analytic 0742** · Linux
  Abnormal CPU/memory usage by unauthorized processes with outbound connections to known mining pools or using cron jobs/scripts to maintain persistence.
  - *Log sources:* `auditd:SYSCALL` (execve); `linux:procfs` (Sustained high /proc/[pid]/stat usage); `NSM:Flow` (Outbound traffic to mining pools or proxies)
  - *Tune:* `ProcessPath` — Location of resource-heavy binaries (e.g., /tmp/.xmr); `CPUThreshold` — Acceptable baseline for CPU overuse; `KnownMiningDomains` — List of domains/IPs for known cryptomining services
- **`AN0743` Analytic 0743** · macOS
  Background launch agents/daemons with high CPU use and network access to external mining services.
  - *Log sources:* `macos:unifiedlog` (launchctl activity and process creation); `macos:unifiedlog` (Persistent outbound traffic to mining domains)
  - *Tune:* `launchdLabel` — Suspicious or unknown launch agents; `TrafficVolumeThreshold` — Outbound bandwidth usage thresholds
- **`AN0744` Analytic 0744** · IaaS
  Sudden spikes in cloud VM CPU usage with outbound traffic to mining pools and unauthorized instance creation.
  - *Log sources:* `AWS:CloudTrail` (RunInstances); `AWS:CloudWatch` (Sustained EC2 CPU usage above normal baseline); `AWS:VPCFlowLogs` (Outbound flow logs to known mining pools)
  - *Tune:* `CPUUtilizationThreshold` — CloudWatch alarm trigger for sustained CPU; `UnusualRegionList` — Instances launched in unexpected regions
- **`AN0745` Analytic 0745** · Containers
  High CPU usage by unauthorized containers running mining binaries or public proxy tools.
  - *Log sources:* `containerd:events` (New container with suspicious image name or high resource usage); `prometheus:metrics` (Container CPU/Memory usage exceeding threshold); `container:cni` (Outbound network traffic to mining proxies)
  - *Tune:* `ImageName` — Suspicious or unknown container image used; `CPUQuotaThreshold` — Container-level resource limits
- **`AN0746` Analytic 0746** · SaaS
  Abuse of cloud messaging platforms to send mass spam or consume quota-based resources.
  - *Log sources:* `m365:unified` (SendMessage); `saas:application` (High-volume API calls or traffic via messaging or webhook service)
  - *Tune:* `MessageRateThreshold` — Max allowable outbound message rate per user/account; `APIKeyList` — Known authorized API clients for messaging usage

---

### T1496.001 — Compute Hijacking
<a id="t1496001"></a>

**Detection strategy:** Multi-Platform Behavioral Detection for Compute Hijacking (`DET0540`)  
**Platforms:** Containers, IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1496.001](https://attack.mitre.org/techniques/T1496/001/) · [detail page](../../techniques/impact.md#t1496001)

- **`AN1489` Analytic 1489** · Windows
  Sustained execution of resource-intensive processes (e.g., cryptocurrency miners), often launched via scheduled tasks, WMI, or PowerShell. These processes frequently establish persistent external connections and attempt to evade detection using masqueraded or renamed binaries.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Security` (EventCode=4698)
  - *Tune:* `Image` — The executable name of the miner or wrapper—can vary across campaigns.; `DestinationIP` — May differ depending on the mining pool or proxy server.; `ParentProcessName` — Useful for filtering known-good automation vs malicious task runners.
- **`AN1490` Analytic 1490** · Linux
  Unusual long-running processes consuming high CPU cycles (e.g., via 'top' or 'ps') initiated via cron, shell scripts, or Docker. Connections to known mining pools or DNS over HTTPS usage as evasion.
  - *Log sources:* `auditd:SYSCALL` (execve); `NSM:Flow` (Outbound connection to mining pool port (3333, 4444, 5555)); `linux:cron` (Scheduled execution of unknown or unusual script/binary)
  - *Tune:* `CommandLine` — The miner's execution path and options may vary by campaign.; `CPUThreshold` — Environment-specific definition of anomalous CPU usage.
- **`AN1491` Analytic 1491** · macOS
  Persistent or background daemons (e.g., plist or launchd jobs) spawning high-CPU processes like xmrig or cpuminer. Outbound encrypted traffic to IPs/domains commonly used by mining proxies.
  - *Log sources:* `macos:unifiedlog` (launchd or cron spawning mining binaries); `macos:unifiedlog` (Persistent outbound connections with consistent periodicity)
  - *Tune:* `launchd.plist_label` — May be disguised with benign-looking names.; `DestinationDomain` — Varying mining pool or obfuscated destination.
- **`AN1492` Analytic 1492** · Containers
  Ephemeral or unauthorized container instantiation using public images (e.g., from DockerHub) that initiate high CPU usage shortly after startup. Often scheduled via Kubernetes or Docker socket abuse.
  - *Log sources:* `containerd:events` (create); `auditd:SYSCALL` (execve); `NSM:Flow` (Outbound traffic to mining pool upon container launch)
  - *Tune:* `ImageSource` — May vary depending on where the image is pulled from (registry or custom URL).; `Namespace` — Helps differentiate attacker-created namespaces.
- **`AN1493` Analytic 1493** · IaaS
  Unauthorized instance creation in unmonitored or unused regions. Burst of compute-intensive jobs in spot instances or sudden spike in resource usage in legitimate VMs.
  - *Log sources:* `AWS:CloudTrail` (RunInstances); `AWS:CloudWatch` (Unusual CPU burst or metric anomalies)
  - *Tune:* `Region` — Adversaries may deploy resources in rarely used or misconfigured regions.; `TagKey` — Used to evade detection with benign-looking tags or names.

---

### T1496.002 — Bandwidth Hijacking
<a id="t1496002"></a>

**Detection strategy:** Detect Excessive or Unauthorized Bandwidth Usage for Botnet, Proxyjacking, or Scanning Purposes (`DET0028`)  
**Platforms:** Containers, IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1496.002](https://attack.mitre.org/techniques/T1496/002/) · [detail page](../../techniques/impact.md#t1496002)

- **`AN0080` Analytic 0080** · Windows
  Processes invoking network-intensive child processes or uploading large data volumes, often from non-standard user or system contexts, with evidence of long-duration TCP/UDP sessions to unusual destinations.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `TimeWindow` — Bandwidth anomalies should be assessed over 5-15 min or hourly windows depending on environment size.; `DestinationCountry` — Some organizations whitelist traffic to countries based on geolocation.; `ProcessName` — Legitimate processes using high bandwidth (e.g., backup tools) must be excluded.
- **`AN0081` Analytic 0081** · Linux
  User-initiated processes generating sustained outbound traffic over common or non-standard ports, often outside business hours, potentially linked to scanning or proxyjacking. Includes curl, wget, masscan, or proxy clients.
  - *Log sources:* `auditd:SYSCALL` (execve calls with high-frequency or known bandwidth-intensive tools); `NSM:Flow` (large outbound data flows or long-duration connections)
  - *Tune:* `ToolPattern` — Can be tuned for specific bandwidth abuse tools (e.g., proxychains, 3proxy).; `TrafficRateThreshold` — Baseline deviation thresholds must be environment-specific.
- **`AN0082` Analytic 0082** · macOS
  Suspicious long-lived or high-throughput connections by non-Apple signed apps or processes not commonly associated with network uploads. Detect background processes using open sockets for data egress.
  - *Log sources:* `macos:unifiedlog` (process + network metrics correlation for bandwidth saturation); `macos:unifiedlog` (exec or spawn calls to proxy tools or torrent clients)
  - *Tune:* `ProcessSignedStatus` — Non-signed or non-Apple signed binaries can raise confidence levels.; `DataRateThreshold` — Observed data rate per process over time (e.g., MB/s).
- **`AN0083` Analytic 0083** · Containers
  Containerized apps or sidecar containers generating excessive outbound traffic or being leveraged for proxy networks. Includes sudden increases in network interface stats, especially in dormant or low-util apps.
  - *Log sources:* `containers:osquery` (bandwidth-intensive command execution from within a container namespace); `docker:stats` (unusual network TX/RX byte deltas)
  - *Tune:* `ContainerBaselineNetworkUsage` — Baseline per container must be defined by app purpose and normal traffic.; `ImageName` — Certain image names or registries may be prone to abuse (e.g., public image hosting mining or proxyware).
- **`AN0084` Analytic 0084** · IaaS
  Virtual instances or workloads generating sustained outbound data rates, often to TOR, VPN, or proxy endpoints. Often coincides with unusual IAM usage or deployed scripts (e.g., cron jobs using proxy clients).
  - *Log sources:* `AWS:CloudTrail` (StartInstances); `AWS:VPCFlowLogs` (egress > 90th percentile or frequent connection reuse)
  - *Tune:* `InstanceType` — High-throughput instance types are more likely to be targeted for hijacking.; `TrafficEgressThreshold` — Customize detection thresholds based on cloud provider quotas or billing alerts.

---

### T1496.003 — SMS Pumping
<a id="t1496003"></a>

**Detection strategy:** Detection Strategy for Resource Hijacking: SMS Pumping via SaaS Application Logs (`DET0156`)  
**Platforms:** SaaS  
**ATT&CK:** [T1496.003](https://attack.mitre.org/techniques/T1496/003/) · [detail page](../../techniques/impact.md#t1496003)

- **`AN0443` Analytic 0443** · SaaS
  Automated and repetitive triggering of SMS messages through OTP/account verification fields on SaaS platforms, leveraging background messaging APIs such as Twilio, AWS SNS, or Amazon Cognito to generate traffic toward attacker-controlled numbers.
  - *Log sources:* `saas:application` (High-frequency invocation of SMS-related API endpoints from publicly accessible OTP or verification forms (e.g., Twilio: SendMessage, Cognito: AdminCreateUser) with irregular destination patterns.); `saas:audit` (Repeated requests to SMS-generating endpoints using anomalous or new user agents, IP ranges, or geographies.)
  - *Tune:* `TimeWindow` — Defines the rolling window over which SMS API invocation frequency is measured. Tunable based on average platform traffic.; `SMSFrequencyThreshold` — Number of SMS requests per endpoint or per user that should trigger investigation. Should align with business logic and user behavior.; `DestinationCountryCodeFilter` — Monitors if requests target known high-risk, revenue-sharing regions. Tunable to reflect SMS tariff rates or abuse history.; `UserAgentAnomalyThreshold` — Defines outlier score or list of unknown/automated user agents submitting forms.; `IPGeoVarianceScore` — Tracks abnormal geographic spread of traffic sourcing OTP triggers.

---

### T1496.004 — Cloud Service Hijacking
<a id="t1496004"></a>

**Detection strategy:** Detection Strategy for Cloud Service Hijacking via SaaS Abuse (`DET0147`)  
**Platforms:** SaaS  
**ATT&CK:** [T1496.004](https://attack.mitre.org/techniques/T1496/004/) · [detail page](../../techniques/impact.md#t1496004)

- **`AN0417` Analytic 0417** · SaaS
  Adversary gains access to cloud-hosted services such as AWS SES, SNS, or OpenAI API, enables or modifies usage policies, and initiates resource-intensive actions (e.g., mass email/SMS or LLM queries), often from unauthorized regions or under anomalous identity conditions.
  - *Log sources:* `AWS:CloudTrail` (PutIdentityPolicy); `AWS:CloudTrail` (SendEmail); `AWS:CloudTrail` (AssumeRole)
  - *Tune:* `TimeWindow` — Define threshold period over which request spikes are measured. E.g., 10 min or 1 hour windows.; `UserContext` — Alert only if role/user is outside expected automation identity list.; `RequestVolumeThreshold` — Customize the number of emails/SMS or API calls considered anomalous.; `GeoVelocityThreshold` — Tune geolocation jump logic (e.g., login from US, then use service in Asia within minutes).; `ModelUsageQuotaSpike` — Set maximum allowable deviation from past 7-day average OpenAI/GPT token usage.

---

### T1498 — Network Denial of Service
<a id="t1498"></a>

**Detection strategy:** Behavioral Detection of T1498 – Network Denial of Service Across Platforms (`DET0518`)  
**Platforms:** Linux, Windows  
**ATT&CK:** [T1498](https://attack.mitre.org/techniques/T1498/) · [detail page](../../techniques/impact.md#t1498)

- **`AN1434` Analytic 1434** · Windows
  Executable or script generating large outbound network traffic targeting remote hosts or known amplification ports
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `ThresholdEventVolume` — Number of connections per second that should trigger anomaly logic; `DestinationDiversity` — Count of unique destination IPs or ports
- **`AN1435` Analytic 1435** · Linux
  Flooding tools like hping3 or nping sending large volumes of packets across multiple ports or IPs
  - *Log sources:* `auditd:SYSCALL` (Execution of network stress tools or anomalies in socket/syscall behavior); `NSM:Flow` (High volume flows with incomplete TCP sessions or single-packet bursts)
  - *Tune:* `PacketRateThreshold` — Packets per second beyond normal behavior

---

### T1498.001 — Direct Network Flood
<a id="t1498001"></a>

**Detection strategy:** Direct Network Flood Detection across IaaS, Linux, Windows, and macOS (`DET0343`)  
**Platforms:** IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1498.001](https://attack.mitre.org/techniques/T1498/001/) · [detail page](../../techniques/impact.md#t1498001)

- **`AN0969` Analytic 0969** · Windows
  High-volume packet generation by local processes (e.g., PowerShell, cmd, curl.exe) or network service processes resulting in excessive outbound traffic over short time window, correlated with abnormal resource usage or degraded host responsiveness.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Security` (EventCode=4688)
  - *Tune:* `PacketRateThreshold` — Defines the burst threshold (e.g., 10,000 pps) above which activity should be flagged as anomalous.; `TimeWindow` — Duration over which to aggregate and analyze flow volume.
- **`AN0970` Analytic 0970** · Linux
  Kernel or userland processes generating high-rate network traffic (ICMP, UDP, TCP SYN) beyond expected interface throughput or user behavior norms.
  - *Log sources:* `auditd:SYSCALL` (connect or sendto system call with burst pattern); `auditd:SYSCALL` (execve)
  - *Tune:* `SyscallBurstCount` — Threshold of repeated socket calls within a short interval indicating flood behavior.; `UserContext` — Restrict to non-admin user traffic unless elevated access is detected.
- **`AN0971` Analytic 0971** · macOS
  Excessive outbound traffic via `ping`, `curl`, or custom scripts indicating flooding behavior, especially with no UI context or user interaction.
  - *Log sources:* `macos:unifiedlog` (process created with repeated ICMP or UDP flood behavior); `macos:unifiedlog` (sudden burst in outgoing packets from same PID)
  - *Tune:* `BurstTimeWindow` — Tunable range (e.g., 15s, 30s) for detecting packet floods.
- **`AN0972` Analytic 0972** · IaaS
  VM or cloud instance generating anomalously high network egress targeting same destination IP or service, especially using stateless protocols.
  - *Log sources:* `AWS:VPCFlowLogs` (source instance sends large volume of traffic in short window); `AWS:CloudWatch` (NetworkOut spike beyond baseline)
  - *Tune:* `InstanceTrafficThreshold` — Alert when egress exceeds normal usage by X%.; `ProtocolType` — Prioritize alerts on stateless protocols such as UDP and ICMP.

---

### T1498.002 — Reflection Amplification
<a id="t1498002"></a>

**Detection strategy:** Detection Strategy for Reflection Amplification DoS (T1498.002) (`DET0408`)  
**Platforms:** IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1498.002](https://attack.mitre.org/techniques/T1498/002/) · [detail page](../../techniques/impact.md#t1498002)

- **`AN1140` Analytic 1140** · Windows
  Outbound spoofed traffic to known amplification protocols (e.g., DNS, NTP, Memcached) combined with abnormal network traffic volume targeting remote reflectors, resulting in disproportionate traffic returned to a victim
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `Windows:perfmon` (Sudden spike in outbound throughput without corresponding inbound traffic)
  - *Tune:* `TimeWindow` — Interval for measuring sudden outbound spike or volume pattern; `AmplificationProtocolPorts` — List of known ports used for reflection amplification (e.g., 53/DNS, 123/NTP, 11211/Memcached); `PacketToByteRatio` — Heuristic threshold where the response volume far outweighs the request volume
- **`AN1141` Analytic 1141** · Linux
  Spoofed outbound packets sent to amplification services from command-line tools or scripts, combined with abnormal outbound packet volume on known reflector ports
  - *Log sources:* `auditd:SYSCALL` (Execution of spoofing tools (e.g., hping3, nping, scapy) sending UDP packets to known amplifier ports); `NSM:Flow` (Outbound UDP floods targeting common reflection services with spoofed IP headers); `sar:network` (Outbound network saturation with minimal process activity)
  - *Tune:* `TimeWindow` — Sliding interval for detecting volumetric anomalies; `AmplificationProtocolList` — Which protocols to watch (e.g., DNS, NTP, SSDP, Memcached); `ExecutionToolList` — Set of binaries and scripts commonly abused for spoofing/reflection
- **`AN1142` Analytic 1142** · macOS
  Command-line initiated UDP traffic bursts to external reflection amplification ports using built-in scripting or binaries with network anomalies
  - *Log sources:* `macos:unifiedlog` (Execution of ping, nping, or crafted network packets via bash or python to reflection services); `macos:unifiedlog` (Outbound UDP spikes to external reflector IPs)
  - *Tune:* `ReflectionPorts` — Ports known for reflection abuse — DNS, NTP, SSDP, Memcached; `TrafficSpikeThreshold` — How much deviation in outbound traffic constitutes a suspicious spike
- **`AN1143` Analytic 1143** · IaaS
  Cloud-hosted VM or container generates spoofed UDP requests to third-party services on known amplifier ports, with high outbound-to-inbound traffic ratios in VPC Flow Logs
  - *Log sources:* `AWS:CloudTrail` (Create egress rule allowing UDP to port 53, 123, 11211); `AWS:VPCFlowLogs` (Large outbound UDP traffic to multiple public reflector IPs); `AWS:CloudWatch` (Sudden spike in network output without a corresponding inbound request ratio)
  - *Tune:* `EgressRulePorts` — Cloud security group rules permitting UDP to reflector protocols; `OutboundToInboundRatio` — Ratio threshold to flag traffic as potential reflection behavior; `VMInstanceTagContext` — Cloud metadata that can help scope anomalous behavior to development, testing, or external-facing services

---

### T1499 — Endpoint Denial of Service
<a id="t1499"></a>

**Detection strategy:** Endpoint Resource Saturation and Crash Pattern Detection Across Platforms (`DET0208`)  
**Platforms:** Containers, IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1499](https://attack.mitre.org/techniques/T1499/) · [detail page](../../techniques/impact.md#t1499)

- **`AN0584` Analytic 0584** · Windows
  Excessive resource exhaustion or service crash induced by processes launched by users or scripts that rapidly consume CPU/memory or attempt malformed service interactions.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Application` (Service crash, unhandled exception, or application hang warnings for critical services (e.g., IIS, DNS, SQL Server)); `WinEventLog:System` (System shutdowns due to bugcheck (Event ID 1001) or watchdog timer expirations)
  - *Tune:* `TimeWindow` — Number of service crashes or high-CPU events within a defined time period; `ServiceTarget` — Specific service name or executable targeted for DoS (e.g., svchost.exe, w3wp.exe); `CPUThresholdPercent` — CPU usage percent considered anomalous over duration
- **`AN0585` Analytic 0585** · Linux
  Malicious script or binary causes repeated kernel panics, OOM kills, or systemd service restarts targeting services like nginx, httpd, sshd.
  - *Log sources:* `auditd:SYSCALL` (execve); `linux:syslog` (Out of memory killer invoked or kernel panic entries); `journald:systemd` (Repeated service restart attempts or unit failures)
  - *Tune:* `ServiceName` — Targeted daemon/service such as sshd, nginx, mysql; `RestartThreshold` — Number of restarts in short succession to trigger alert; `OOMKillCount` — Count of OOM kills over a time window
- **`AN0586` Analytic 0586** · macOS
  Adversary launches high-entropy process or malformed app bundle causing repeated application crashes and system slowdowns.
  - *Log sources:* `macos:unifiedlog` (Repeated process crashes logged by CrashReporter or system instability logs in com.apple.console); `macos:unifiedlog` (Spike in CPU or memory use from non-user-initiated processes)
  - *Tune:* `CrashCountThreshold` — Number of app crashes within monitoring window; `PayloadEntropyThreshold` — Used for high-entropy binaries often observed in DoS malware samples
- **`AN0587` Analytic 0587** · IaaS
  Instance enters degraded/unhealthy state due to abnormal process load or memory exhaustion, often caused by automation or script-based attacks.
  - *Log sources:* `AWS:CloudWatch` (StatusCheckFailed or StatusCheckFailed_System for burstable instances (t2/t3)); `AWS:CloudTrail` (StartInstances); `VPCFlowLogs:All` (High volume internal traffic with low entropy indicating looped or malicious DoS script)
  - *Tune:* `InstanceType` — Burstable vs compute-optimized instances impact DoS effect; `FailureThreshold` — How many consecutive StatusCheckFailed events to consider critical
- **`AN0588` Analytic 0588** · Containers
  Container orchestrator logs show crashlooping pods, repeated resource exhaustion, or malicious binaries with infinite loops consuming systemd/cgroup limits.
  - *Log sources:* `kubernetes:events` (CrashLoopBackOff, OOMKilled, container restart count exceeds threshold); `docker:events` (Container exited with non-zero code repeatedly in short period)
  - *Tune:* `RestartCountThreshold` — Number of container restarts within a time window; `ContainerImageEntropy` — Payload entropy of container image as an anomaly factor

---

### T1499.001 — OS Exhaustion Flood
<a id="t1499001"></a>

**Detection strategy:** Endpoint DoS via OS Exhaustion Flood Detection Strategy (`DET0356`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1499.001](https://attack.mitre.org/techniques/T1499/001/) · [detail page](../../techniques/impact.md#t1499001)

- **`AN1012` Analytic 1012** · Windows
  Burst of incomplete TCP handshakes (e.g., SYN floods) or uncorrelated ACK packets targeting the state table resulting in OS resource exhaustion.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Microsoft-Windows-TCPIP` (Connection queue overflow or failure to allocate TCP state object); `NSM:Firewall` (High rate of inbound TCP SYN or ACK packets with missing 3-way handshake completion)
  - *Tune:* `TimeWindow` — Threshold for burst traffic over short period (e.g., 30s - 2min); `ConnectionRateThreshold` — SYN/ACK packet rate threshold that triggers investigation; `ProcessParentCheck` — Whether parent process of flooding tool is a known admin shell or unexpected context
- **`AN1013` Analytic 1013** · Linux
  Flood of spoofed SYN or ACK packets causing exhaustion of OS TCP state table, potentially via user-space utilities or kernel-level DoS agents.
  - *Log sources:* `auditd:SYSCALL` (Invocation of packet generation tools (e.g., hping3, nping) or fork bombs); `NSM:Flow` (High volumes of SYN/ACK packets with unacknowledged TCP handshakes); `NSM:Flow` (TCP: possible SYN flood or backlog limit exceeded)
  - *Tune:* `AmplificationThreshold` — Volume of fake TCP requests before OS begins degradation; `Interface` — Which network interface is being targeted or impacted
- **`AN1014` Analytic 1014** · macOS
  Adversary tool/script issuing mass SYN/ACK floods that degrade OS responsiveness and interrupt service response on macOS endpoints.
  - *Log sources:* `macos:unifiedlog` (network stack resource exhaustion, tcp_accept queue overflow, repeated resets); `macos:osquery` (Execution of flooding tools or compiled packet generators); `NSM:Firewall` (Anomalous TCP SYN or ACK spikes from specific source or interface)
  - *Tune:* `SystemLoadThreshold` — Observed CPU/network degradation level that triggers response; `ToolExecutionPath` — Where DoS tools are commonly dropped or compiled

---

### T1499.002 — Service Exhaustion Flood
<a id="t1499002"></a>

**Detection strategy:** Detection Strategy for Endpoint DoS via Service Exhaustion Flood (`DET0173`)  
**Platforms:** IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1499.002](https://attack.mitre.org/techniques/T1499/002/) · [detail page](../../techniques/impact.md#t1499002)

- **`AN0489` Analytic 0489** · Windows
  High-frequency, repetitive service requests (e.g., HTTP, TLS renegotiation) originating from a single or small set of source IPs targeting endpoint web services or application ports, leading to exhaustion of CPU or memory on targeted Windows services.
  - *Log sources:* `WinEventLog:Application` (Unexpected spikes in request volume, application-level errors, or thread pool exhaustion in web or API logs); `WinEventLog:Sysmon` (EventCode=3, 22); `Windows:perfmon` (Sustained CPU/memory exhaustion by service process (e.g., w3wp.exe))
  - *Tune:* `TimeWindow` — Defines burst threshold (e.g., 1 min, 5 min) for connection spikes; `TargetServicePort` — Specific ports/services likely to be abused (e.g., 80, 443, 8080); `CPUThreshold` — Level of sustained CPU usage considered anomalous for a given service
- **`AN0490` Analytic 0490** · Linux
  Excessive inbound HTTP or TLS connections to services such as Apache or Nginx, causing worker thread exhaustion or segmentation faults.
  - *Log sources:* `auditd:SYSCALL` (High frequency of accept(), read(), or SSL_read() syscalls tied to nginx/apache processes); `NSM:Flow` (Sudden spike in incoming flows to web service ports from single/multiple IPs); `linux:syslog` (Repetitive HTTP 408, 500, or 503 errors logged within short timeframe)
  - *Tune:* `ErrorCodeWindow` — Tunable count of specific HTTP error codes in timeframe; `ConnectionRateThreshold` — Defines number of connections per second considered anomalous
- **`AN0491` Analytic 0491** · macOS
  Flood of incoming TLS or HTTP(S) connections to macOS-hosted services (e.g., MAMP, Apache), causing high CPU usage and system unresponsiveness.
  - *Log sources:* `macos:unifiedlog` (Web service process (e.g., httpd) entering crash loop or consuming excessive CPU); `macos:unifiedlog` (Rapid incoming TLS handshakes or HTTP requests in quick succession)
  - *Tune:* `TLSHandshakeRate` — Number of renegotiations per minute considered suspicious; `ServiceCrashFrequency` — Threshold of crashes before alerting on instability
- **`AN0492` Analytic 0492** · IaaS
  Automated or scripted HTTP/TLS flooding from one VM or cloud instance against another service, exploiting compute-based billing or exhaustion of service infrastructure.
  - *Log sources:* `AWS:CloudTrail` (AuthorizeSecurityGroupIngress); `AWS:VPCFlowLogs` (Unusual volume of inbound packets from single source across short time interval); `AWS:CloudWatch` (Sustained spike in CPU usage on EC2 instance with web service role)
  - *Tune:* `VPCFlowBurstRate` — Threshold for traffic burst on target service port; `EC2CPUThreshold` — Compute saturation level for alerting (e.g., >90% for 3 minutes)

---

### T1499.003 — Application Exhaustion Flood
<a id="t1499003"></a>

**Detection strategy:** Application Exhaustion Flood Detection Across Platforms (`DET0415`)  
**Platforms:** IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1499.003](https://attack.mitre.org/techniques/T1499/003/) · [detail page](../../techniques/impact.md#t1499003)

- **`AN1165` Analytic 1165** · Windows
  Repeated invocation of high-resource application endpoints or GUI components causing CPU and memory spikes, logged as elevated request volumes, prolonged handle locks, or frequent crash recoveries.
  - *Log sources:* `WinEventLog:Application` (High-frequency errors or hangs from resource-intensive application components (e.g., .NET, IIS, Office Suite)); `WinEventLog:Sysmon` (EventCode=1); `Windows:perfmon` (Sudden spikes in CPU/Memory usage linked to specific application processes)
  - *Tune:* `CPUThreshold` — Define what percentage of CPU usage indicates abnormal behavior.; `MemoryConsumptionWindow` — Window (e.g., 5 mins) during which sustained memory usage may be abnormal.; `AppCrashFrequency` — Threshold for frequency of application faults within a specific interval.
- **`AN1166` Analytic 1166** · Linux
  Automated scripts or repeated CLI/API requests that trigger application backends to consume high CPU or memory (e.g., Apache/PHP, MySQL, mail servers), resulting in syslog errors and excessive process spawning.
  - *Log sources:* `auditd:SYSCALL` (execve); `linux:syslog` (Error/warning logs from services indicating load spike or worker exhaustion); `NSM:Flow` (Sustained abnormal inbound request rate targeting application ports (e.g., 80/443/25))
  - *Tune:* `SyslogErrorRate` — Defines number of critical errors in logs within time window.; `PortRequestSpikeThreshold` — Spike rate on monitored service port triggering alert.; `ProcessSpawnRate` — Rate of process creation that may overwhelm the system.
- **`AN1167` Analytic 1167** · macOS
  Repetitive triggering of GUI or backend application workflows that cause increased CPU/memory usage, logged in unified logs as spin reports or crash dumps.
  - *Log sources:* `macos:unifiedlog` (Application errors or resource contention from excessive frontend or script invocation); `macos:osquery` (Rapid spawning of resource-heavy applications (e.g., Preview, Safari, Office))
  - *Tune:* `SpinReportCount` — Threshold for number of system spin/crash reports in a defined window.; `HeavyAppReopenRate` — Frequency of user or script reopening GUI-heavy apps.
- **`AN1168` Analytic 1168** · IaaS
  Automated abuse of cloud-hosted applications (e.g., web apps, REST endpoints, internal APIs) causing compute exhaustion, high 5xx error rates, or frequent autoscaling triggers logged in app insights or cloudwatch.
  - *Log sources:* `AWS:CloudWatch` (Elevated 5xx response rates in application logs or gateway layer); `AWS:CloudTrail` (InvokeFunction); `AWS:CloudMetrics` (Autoscaling, memory/cpu alarms, or instance unhealthiness)
  - *Tune:* `HTTP5xxRateThreshold` — Ratio of 5xx error codes over requests indicating resource exhaustion.; `FunctionInvocationRate` — Spike in lambda/API gateway executions indicating scripted behavior.; `AutoscaleEventCount` — Triggers linked to app DoS where legitimate scaling is mimicked.

---

### T1499.004 — Application or System Exploitation
<a id="t1499004"></a>

**Detection strategy:** Detection Strategy for Endpoint DoS via Application or System Exploitation (`DET0304`)  
**Platforms:** IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1499.004](https://attack.mitre.org/techniques/T1499/004/) · [detail page](../../techniques/impact.md#t1499004)

- **`AN0850` Analytic 0850** · Windows
  Exploitation of system or application vulnerability (e.g., CVE-based exploit) followed by service crash, restart, or repeated failure within a short time frame, impacting application/system availability.
  - *Log sources:* `WinEventLog:Application` (EventCode=1000); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:System` (EventCode=7031, 7034)
  - *Tune:* `TimeWindow` — Time window between repeated service crashes or restarts (e.g., 5 crashes within 1 hour); `TargetApplication` — Critical applications to monitor based on environment (e.g., web server, database, VPN)
- **`AN0851` Analytic 0851** · Linux
  User or remote input triggers application crash or segmentation fault (e.g., SIGSEGV) with service recovery attempts, observed via audit logs and systemd journaling.
  - *Log sources:* `auditd:SYSCALL` (Process segfault or abnormal termination after invoking vulnerable syscall sequence); `journald:Application` (Segfault or crash log entry associated with specific application binary); `NSM:Flow` (Unusual request pattern leading up to service crash (e.g., malformed or oversized payload))
  - *Tune:* `CrashPattern` — Specific binary fault signature or stack trace identifiers unique to the application context; `ExploitSourceIP` — Suspect source IPs for correlation across requests and service failure timing
- **`AN0852` Analytic 0852** · macOS
  Application crash or repeated restart cycle triggered by malformed input or exploit file, observed via unified logs and process crash monitoring.
  - *Log sources:* `macos:unifiedlog` (Crash log entries for a process receiving malformed input or known exploit patterns); `macos:unifiedlog` (Unusual child process tree indicating attempted recovery after crash)
  - *Tune:* `CrashSignature` — Binary crash hash or affected dylib for distinguishing malicious faults from benign ones; `InputVector` — File, IPC, or network-based input that may be triggering exploitation (e.g., PDF file, POST request)
- **`AN0853` Analytic 0853** · IaaS
  Cloud workload exploitation leads to repeated container, service, or VM termination/restart, typically associated with CVE-based crash triggers or fuzzed payloads.
  - *Log sources:* `AWS:CloudTrail` (TerminateInstances); `AWS:CloudWatch` (Repeated crash pattern within container or instance logs); `AWS:VPCFlowLogs` (Large volume of malformed or synthetic payloads to application endpoints prior to failure)
  - *Tune:* `CrashThreshold` — Number of repeated crashes or terminations observed before triggering alert; `ServiceID` — Cloud service name, workload, or container ID to scope alerting

---

### T1529 — System Shutdown/Reboot
<a id="t1529"></a>

**Detection strategy:** Multi-Platform Shutdown or Reboot Detection via Execution and Host Status Events (`DET0559`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1529](https://attack.mitre.org/techniques/T1529/) · [detail page](../../techniques/impact.md#t1529)

- **`AN1538` Analytic 1538** · Windows
  Correlate process execution of shutdown/reboot commands (e.g., shutdown.exe, restart-computer) with host status change logs (Event IDs 1074, 6006) and absence of related administrative context (e.g., user not in Helpdesk group).
  - *Log sources:* `WinEventLog:Security` (EventCode=1074); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `UserContext` — Defines if user has appropriate privileges to initiate shutdown/reboot.; `TimeWindow` — Unexpected shutdowns during business hours may warrant increased scrutiny.
- **`AN1539` Analytic 1539** · Linux
  Detect 'shutdown', 'reboot', or 'systemctl poweroff' executions with auditd/syslog and absence of scheduled maintenance windows or approved user context.
  - *Log sources:* `auditd:SYSCALL` (execve=/sbin/shutdown or /sbin/reboot); `linux:syslog` (system is powering down)
  - *Tune:* `CommandLineMatch` — Supports multiple binary names or symlinked utilities.; `UserContext` — Privileged user (e.g., root or via sudo) context matching expected roles.
- **`AN1540` Analytic 1540** · macOS
  Identify use of 'shutdown', 'reboot', or 'osascript' system shutdown invocations within unified logs and track unexpected shutdown sequences initiated by GUI or script. Cross-reference with user activity or absence thereof.
  - *Log sources:* `macos:unifiedlog` (shutdown -h now or reboot); `macos:unifiedlog` (System shutdown or reboot requested)
  - *Tune:* `LaunchMechanism` — Scripted vs interactive shutdowns.; `LogGranularity` — May vary depending on macOS version and unified log verbosity.
- **`AN1541` Analytic 1541** · ESXi
  Detect commands such as 'esxcli system shutdown' or 'vim-cmd vmsvc/power.shutdown' executed outside of maintenance windows or via unusual users. Reboot logs in hostd.log and shell logs should be correlated.
  - *Log sources:* `esxi:hostd` (Powering off or restarting host); `esxi:shell` (esxcli system shutdown or reboot invoked)
  - *Tune:* `AccountRole` — Administrative account context validation.; `MaintenanceWindow` — Expected times for reboot/shutdown behavior.
- **`AN1542` Analytic 1542** · Network Devices
  Monitor CLI 'reload' commands issued without scheduled maintenance, and correlate to TACACS+/AAA logs for privilege validation.
  - *Log sources:* `networkdevice:syslog` (reload command issued); `networkdevice:syslog` (System reboot scheduled or performed)
  - *Tune:* `PrivilegeLevel` — TACACS+/AAA role thresholds for command execution.; `ChangeTicketCorrelation` — Track change control windows or ITSM integration.

---

### T1531 — Account Access Removal
<a id="t1531"></a>

**Detection strategy:** Account Access Removal via Multi-Platform Audit Correlation (`DET0120`)  
**Platforms:** ESXi, Linux, Office Suite, SaaS, Windows, macOS  
**ATT&CK:** [T1531](https://attack.mitre.org/techniques/T1531/) · [detail page](../../techniques/impact.md#t1531)

- **`AN0334` Analytic 0334** · Windows
  Correlated user account modification (reset, disable, deletion) events with anomalous process lineage (e.g., PowerShell or net.exe from an interactive session), especially outside of IT admin change windows or by non-admin users.
  - *Log sources:* `WinEventLog:Security` (EventCode=4723, 4724, 4740); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `UserContext` — Account performing the operation (e.g., Domain Admins vs. local users); `TimeWindow` — Alert only on actions outside of maintenance windows; `ParentProcessName` — Detect suspicious process lineage (e.g., powershell.exe launching net.exe)
- **`AN0335` Analytic 0335** · Linux
  Password changes or account deletions via 'passwd', 'userdel', or 'chage' preceded by interactive shell or remote command execution from non-privileged accounts.
  - *Log sources:* `auditd:SYSCALL` (SYSCALL record where exe contains passwd/userdel/chage and auid != root); `NSM:Connections` (Accepted password or publickey for user from remote IP)
  - *Tune:* `ExecPath` — Binary path for passwd or userdel, which may vary by distro; `NonRootUIDThreshold` — Alert only if auid != root or expected service account
- **`AN0336` Analytic 0336** · macOS
  Execution of dscl or sysadminctl commands to disable, delete, or modify users combined with anomalous process ancestry or terminal session launch.
  - *Log sources:* `macos:unifiedlog` (command includes dscl . delete or sysadminctl --deleteUser); `macos:unifiedlog` (successful sudo or authentication for account not normally associated with admin actions)
  - *Tune:* `CommandLinePattern` — Allow variation in dscl/sysadminctl command structure; `AnomalousUserFlag` — Detect new or rarely seen users performing user removal
- **`AN0337` Analytic 0337** · ESXi
  Invocation of esxcli 'system account remove' from vCLI, SSH, or vSphere API with anomalous user access or outside maintenance windows.
  - *Log sources:* `esxi:hostd` (method=RemoveUser or esxcli system account remove invocation); `esxi:vpxa` (user login from unexpected IP or non-admin user role)
  - *Tune:* `RemoteUserRole` — ESXi role triggering the change (e.g., Administrator vs. Viewer); `ExpectedIPs` — IP ranges authorized to conduct admin-level actions
- **`AN0338` Analytic 0338** · Office Suite
  O365 UnifiedAuditLog entries for Remove-Mailbox or Set-Mailbox with account disable or delete actions correlated with suspicious login locations or MFA bypass.
  - *Log sources:* `m365:unified` (Remove-Mailbox, Set-Mailbox); `m365:signinlogs` (Sign-in from anomalous location or impossible travel condition)
  - *Tune:* `RoleAssignment` — Determine if operation was delegated to expected admin group; `GeoThreshold` — Trigger on unusual geographic login sources
- **`AN0339` Analytic 0339** · SaaS
  Deletion or disablement of user accounts in platforms like Okta, Salesforce, or Zoom with anomalies in admin session attributes or mass actions within short duration.
  - *Log sources:* `saas:okta` (user.lifecycle.delete, user.account.lock)
  - *Tune:* `BulkActionThreshold` — Trigger if multiple deletions occur within a short period; `SessionDeviceType` — Alert on deletions initiated from unfamiliar device contexts

---

### T1561 — Disk Wipe
<a id="t1561"></a>

**Detection strategy:** Detection Strategy for Disk Wipe via Direct Disk Access and Destructive Commands (`DET0137`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1561](https://attack.mitre.org/techniques/T1561/) · [detail page](../../techniques/impact.md#t1561)

- **`AN0384` Analytic 0384** · Windows
  Unusual direct disk access attempts (e.g., use of \\.\PhysicalDrive notation), abnormal writes to MBR/boot sectors, and installation of kernel drivers that grant raw disk access. Correlate anomalous process creation with disk modification attempts and driver loads.
  - *Log sources:* `WinEventLog:Security` (EventCode=4673); `WinEventLog:Sysmon` (Raw disk write access via \\.\PhysicalDrive* or \\.\C:); `WinEventLog:Sysmon` (EventCode=6)
  - *Tune:* `ProcessWhitelist` — Legitimate disk imaging or backup tools may trigger raw disk access — must be excluded per environment.; `TimeWindow` — Correlate disk access, driver load, and process execution within a short timeframe to minimize false positives.
- **`AN0385` Analytic 0385** · Linux
  Processes invoking destructive commands (dd, shred, wipe) with raw device targets (e.g., /dev/sda, /dev/nvme0n1). Detect direct writes to disk partitions and abnormal superblock or bootloader modifications. Correlate shell execution with subsequent block device I/O.
  - *Log sources:* `auditd:SYSCALL` (open/write syscalls on /dev/sd* or /dev/nvme*); `auditd:EXECVE` (Execution of dd, shred, wipe targeting block devices)
  - *Tune:* `TargetDevices` — Tune to exclude removable drives or test partitions commonly written by administrators.; `EntropyThreshold` — Detects large blocks of pseudorandom data being written; may need tuning for backup/crypto workloads.
- **`AN0386` Analytic 0386** · macOS
  Abnormal invocation of diskutil, asr, or low-level APIs (IOKit) to erase/partition drives. Correlate process execution with unified log entries showing destructive disk operations.
  - *Log sources:* `macos:unifiedlog` (diskutil eraseDisk / asr restore with destructive flags); `macos:unifiedlog` (IOKit disk write calls targeting raw devices)
  - *Tune:* `AdminToolWhitelist` — System administrators may legitimately use diskutil/asr for provisioning — whitelist by user or context.
- **`AN0387` Analytic 0387** · Network Devices
  Execution of destructive CLI commands such as 'erase startup-config', 'erase flash:' or 'format disk' on routers/switches. Detect privilege level escalation preceding destructive commands.
  - *Log sources:* `networkdevice:cli` (erase flash:, erase startup-config, format disk); `networkdevice:syslog` (User privilege escalation to level 15/root prior to destructive commands)
  - *Tune:* `PrivilegedUsers` — Tune to exclude approved maintenance sessions by known administrators.; `CommandPatterns` — Adjust monitored destructive command list depending on device vendor and OS.

---

### T1561.001 — Disk Content Wipe
<a id="t1561001"></a>

**Detection strategy:** Detection Strategy for Disk Content Wipe via Direct Access and Overwrite (`DET0316`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1561.001](https://attack.mitre.org/techniques/T1561/001/) · [detail page](../../techniques/impact.md#t1561001)

- **`AN0882` Analytic 0882** · Windows
  Processes attempting raw disk access via \\.\PhysicalDrive paths, abnormal file I/O to MBR/boot sectors, or loading of third-party drivers (e.g., RawDisk) that enable disk overwrite. Correlate process creation, privilege usage, and disk modification events within a short time window.
  - *Log sources:* `WinEventLog:Security` (EventCode=4673); `WinEventLog:Sysmon` (Raw disk writes targeting \\.\PhysicalDrive* or MBR locations); `WinEventLog:Sysmon` (EventCode=6)
  - *Tune:* `ProcessWhitelist` — Backup, forensics, or imaging tools may perform legitimate raw disk access — requires tuning per environment.; `TimeWindow` — Correlation threshold for process execution, driver load, and raw disk writes.
- **`AN0883` Analytic 0883** · Linux
  Execution of destructive utilities (dd, shred, wipe) targeting block devices, or processes invoking syscalls to directly overwrite /dev/sd* or /dev/nvme* partitions. Correlate abnormal file write attempts with shell process execution and block device access.
  - *Log sources:* `auditd:SYSCALL` (open/write syscalls to block devices (/dev/sd*, /dev/nvme*)); `auditd:EXECVE` (Execution of dd, shred, or wipe with arguments targeting block devices)
  - *Tune:* `TargetDevices` — Exclude removable drives or designated partitions that may be overwritten during maintenance.; `EntropyThreshold` — Tune detection for pseudorandom write patterns to reduce false positives during high-volume I/O.
- **`AN0884` Analytic 0884** · macOS
  Abnormal invocation of diskutil or asr with destructive flags (eraseDisk, zeroDisk), or low-level IOKit calls that overwrite raw disk content. Detect correlation between elevated process execution and disk erase operations.
  - *Log sources:* `macos:unifiedlog` (diskutil eraseDisk/zeroDisk or asr restore with destructive flags); `macos:unifiedlog` (IOKit raw disk write activity targeting physical devices)
  - *Tune:* `AdminToolWhitelist` — Provisioning workflows may legitimately use diskutil/asr — whitelist by user or system context.
- **`AN0885` Analytic 0885** · Network Devices
  Execution of CLI commands erasing file systems or storage (erase flash:, format disk, erase nvram:). Detect authentication events followed by destructive commands within the same privileged session.
  - *Log sources:* `networkdevice:cli` (erase flash:, erase nvram:, format disk); `networkdevice:syslog` (Privileged login followed by destructive command sequence)
  - *Tune:* `PrivilegedUsers` — Tune to exclude approved maintenance performed by authorized administrators.; `CommandPatterns` — Expand or narrow destructive command coverage depending on vendor-specific syntax.

---

### T1561.002 — Disk Structure Wipe
<a id="t1561002"></a>

**Detection strategy:** Detection Strategy for Disk Structure Wipe via Boot/Partition Overwrite (`DET0297`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1561.002](https://attack.mitre.org/techniques/T1561/002/) · [detail page](../../techniques/impact.md#t1561002)

- **`AN0827` Analytic 0827** · Windows
  Processes attempting raw disk access to overwrite sensitive structures such as the MBR or partition table using \\.\PhysicalDrive notation. Detection relies on correlating process creation, privilege escalation, and raw sector writes in Sysmon and Security logs.
  - *Log sources:* `WinEventLog:Security` (EventCode=4673); `WinEventLog:Sysmon` (Raw write attempts targeting \\.\PhysicalDrive0 or sector 0 (MBR/partition table)); `WinEventLog:Sysmon` (EventCode=6)
  - *Tune:* `SectorRange` — Specify which sectors are considered critical (MBR, partition table) to reduce noise.; `ProcessWhitelist` — Exclude legitimate low-level disk management or imaging tools used by administrators.
- **`AN0828` Analytic 0828** · Linux
  Execution of utilities (dd, hdparm, sgdisk) or custom binaries attempting to overwrite disk boot structures (/dev/sda MBR sector or partition tables). Detection correlates shell execution with syscalls writing to sector 0 or disk metadata blocks.
  - *Log sources:* `auditd:SYSCALL` (write syscalls to /dev/sd* targeting offset 0); `auditd:EXECVE` (Execution of dd/sgdisk with arguments writing to sector 0 or partition table)
  - *Tune:* `TargetDevices` — Define specific device paths to monitor (e.g., /dev/sda, /dev/nvme0n1).; `OffsetThreshold` — Focus on suspicious writes at disk offsets corresponding to MBR/partition structures.
- **`AN0829` Analytic 0829** · macOS
  Abnormal invocation of diskutil or asr that modifies partition tables or initializes raw devices. Monitor for IOKit system calls targeting disk headers or EFI boot sectors, correlated with elevated privileges.
  - *Log sources:* `macos:unifiedlog` (diskutil partitionDisk or eraseVolume with partition scheme modifications); `macos:unifiedlog` (IOKit raw disk write to EFI/boot partition sectors)
  - *Tune:* `AdminToolWhitelist` — System provisioning workflows may legitimately re-partition disks; whitelist by context.
- **`AN0830` Analytic 0830** · Network Devices
  Execution of destructive CLI commands such as format flash:, format disk, or equivalent vendor-specific commands that erase filesystem structures. Detection correlates AAA logs showing privileged access with immediate format/erase commands.
  - *Log sources:* `networkdevice:cli` (format flash:, format disk, reformat commands); `networkdevice:syslog` (Privileged login followed by destructive format command)
  - *Tune:* `CommandPatterns` — Expand detection to cover vendor-specific destructive commands.; `PrivilegedUsers` — Whitelist authorized maintenance sessions to reduce false positives.

---

### T1565 — Data Manipulation
<a id="t1565"></a>

**Detection strategy:** Detection Strategy for Data Manipulation (`DET0059`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1565](https://attack.mitre.org/techniques/T1565/) · [detail page](../../techniques/impact.md#t1565)

- **`AN0162` Analytic 0162** · Windows
  Correlate unauthorized or anomalous file modifications, deletions, or metadata changes with suspicious process execution or API calls. Detect abnormal changes to structured data (e.g., database files, logs, financial records) outside expected business process activity.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=2); `WinEventLog:Sysmon` (EventCode=15); `WinEventLog:Security` (EventCode=4663, 4670, 4656)
  - *Tune:* `MonitoredFilePaths` — List of critical data directories or files; environment-specific tuning required.; `TimeWindow` — Threshold for correlating process execution with rapid data changes.; `AuthorizedProcesses` — Expected processes permitted to modify business-critical data.
- **`AN0163` Analytic 0163** · Linux
  Detect unauthorized manipulation of log files, database entries, or system configuration files through auditd and syslog. Correlate shell commands that alter HISTFILE or data-related processes with abnormal file access patterns.
  - *Log sources:* `auditd:SYSCALL` (open, unlink, rename: Suspicious file access, deletion, or modification of sensitive paths); `linux:syslog` (Unexpected SQL or application log entries showing tampered or malformed data)
  - *Tune:* `WatchedDirectories` — Specific log or data directories critical to integrity; tune per organization.; `CommandExclusions` — Legitimate scripts/tools excluded from data manipulation monitoring.
- **`AN0164` Analytic 0164** · macOS
  Detect manipulation of system or application files in `/Library`, `/System`, or user data directories using FSEvents and Unified Logs. Identify anomalous process execution modifying plist files, structured data, or logs outside expected update cycles.
  - *Log sources:* `macos:unifiedlog` (Anomalous plist modifications or sensitive file overwrites by non-standard processes); `macos:osquery` (open, execve: Unexpected processes accessing or modifying critical files)
  - *Tune:* `AllowedPlistEditors` — Whitelisted processes authorized to modify plist or configuration files.; `FileIntegrityBaseline` — Baseline hash values for key files to support integrity validation.

---

### T1565.001 — Stored Data Manipulation
<a id="t1565001"></a>

**Detection strategy:** Detection Strategy for Stored Data Manipulation across OS Platforms. (`DET0193`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1565.001](https://attack.mitre.org/techniques/T1565/001/) · [detail page](../../techniques/impact.md#t1565001)

- **`AN0555` Analytic 0555** · Windows
  Identify unauthorized creation, deletion, or modification of business-critical stored data such as Office documents, database files, and log archives. Detect anomalous processes modifying stored data outside of expected workflows (e.g., non-database processes modifying database files).
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=23); `WinEventLog:Sysmon` (EventCode=15); `WinEventLog:Security` (EventCode=4663, 4670, 4656)
  - *Tune:* `MonitoredDirectories` — Paths to sensitive stored data files such as database directories or email archives.; `AuthorizedProcesses` — List of legitimate processes expected to create, delete, or modify stored data.; `TimeWindow` — Threshold for correlating multiple suspicious file operations within a short period.
- **`AN0556` Analytic 0556** · Linux
  Detect suspicious file creation, modification, or deletion in stored data directories (e.g., `/var/lib/mysql/`, `/var/log/`, mail spools). Identify shell commands interacting directly with structured data files instead of legitimate database utilities.
  - *Log sources:* `auditd:SYSCALL` (open, unlink, rename: File creation or deletion involving critical stored data); `auditd:SYSCALL` (write: Modification of structured stored data by suspicious processes)
  - *Tune:* `WatchedPaths` — Environment-specific paths where business-critical stored data resides.; `CommandExclusions` — Legitimate scripts/utilities excluded to minimize false positives.
- **`AN0557` Analytic 0557** · macOS
  Monitor sensitive data files such as plist-based storage, mail archives, or Office files for unexpected modifications. Detect anomalous processes modifying stored data outside expected update cycles using FSEvents and Unified Logs.
  - *Log sources:* `macos:unifiedlog` (Unexpected creation or modification of stored data files in protected directories); `macos:osquery` (CREATE, DELETE, WRITE: Stored data manipulation attempts by unauthorized processes)
  - *Tune:* `FileIntegrityBaseline` — Baseline hash values or metadata for stored data files to detect manipulation.; `AllowedEditors` — Whitelisted applications permitted to update stored data (e.g., Outlook, MySQL).

---

### T1565.002 — Transmitted Data Manipulation
<a id="t1565002"></a>

**Detection strategy:** Detection Strategy of Transmitted Data Manipulation (`DET0254`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1565.002](https://attack.mitre.org/techniques/T1565/002/) · [detail page](../../techniques/impact.md#t1565002)

- **`AN0702` Analytic 0702** · Windows
  Monitor for anomalies in transmitted data streams, including mismatched file integrity checks, API interception, or man-in-the-middle modifications. Detect unexpected use of APIs that handle network I/O where transmitted data integrity could be manipulated.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=15)
  - *Tune:* `IntegrityBaseline` — Hash baselines or digital signature references to validate transmitted data.; `MonitoredPorts` — List of ports/services where data integrity validation is enforced.
- **`AN0703` Analytic 0703** · Linux
  Detect alterations of transmitted data via monitoring syscalls (`send`, `recv`, `write`) or middleware interception. Identify mismatched file hashes when compared at origin vs. destination. Watch for anomalous activity from processes interacting with secure transmission services (e.g., OpenSSL, scp).
  - *Log sources:* `auditd:SYSCALL` (send, recv, write: Abnormal interception or alteration of transmitted data); `linux:syslog` (Integrity mismatch warnings or malformed packets detected)
  - *Tune:* `WatchedProcesses` — List of processes authorized to handle transmitted data (e.g., sshd, nginx).; `HashCheckInterval` — Frequency of out-of-band integrity verification checks.
- **`AN0704` Analytic 0704** · macOS
  Monitor system APIs such as CFNetwork and SecureTransport for anomalies in transmitted data streams. Detect mismatches in file hashes or SSL/TLS downgrade attempts that enable manipulation of transmitted data.
  - *Log sources:* `macos:unifiedlog` (Suspicious anomalies in transmitted data integrity during application network operations); `macos:osquery` (CALCULATE: Integrity validation of transmitted data via hash checks)
  - *Tune:* `TLSValidationRules` — Custom rules for enforcing HTTPS/TLS integrity checks to prevent downgrade manipulation.; `AllowedApps` — Whitelisted macOS apps permitted to transmit critical data.

---

### T1565.003 — Runtime Data Manipulation
<a id="t1565003"></a>

**Detection strategy:** Detection Strategy for Runtime Data Manipulation. (`DET0391`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1565.003](https://attack.mitre.org/techniques/T1565/003/) · [detail page](../../techniques/impact.md#t1565003)

- **`AN1097` Analytic 1097** · Windows
  Monitor for runtime data manipulations by detecting suspicious modification of application binaries, API hooking, or unexpected behavior from processes responsible for rendering or displaying data. Correlate registry edits, process creation, and unexpected binary hash mismatches.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=15); `WinEventLog:Security` (EventCode=4657)
  - *Tune:* `MonitoredPaths` — Directory paths of business-critical applications where runtime manipulations are most impactful.; `HashBaseline` — Expected cryptographic hashes of application binaries used for runtime data display.
- **`AN1098` Analytic 1098** · Linux
  Detect runtime manipulation by monitoring system calls for modifications to shared libraries, ELF binaries, or environment variables that affect how data is displayed. Look for suspicious writes to application directories and mismatch in binary integrity baselines.
  - *Log sources:* `auditd:SYSCALL` (open, write: File writes to application binaries or libraries at runtime); `linux:syslog` (Execution of modified binaries or abnormal library load sequences)
  - *Tune:* `WatchedBinaries` — Specific critical application binaries or libraries to monitor for unauthorized changes.; `IntegrityCheckFrequency` — Interval for verifying hashes of executables and libraries.
- **`AN1099` Analytic 1099** · macOS
  Monitor for runtime manipulation by observing changes in application bundles, unexpected signing modifications, and runtime API calls that inject or alter how data is displayed. Detect alterations in CFNetwork or CoreFoundation frameworks responsible for rendering data.
  - *Log sources:* `macos:unifiedlog` (Unexpected application binary modifications or altered signing status); `macos:osquery` (CALCULATE: Mismatch in file integrity of critical macOS applications)
  - *Tune:* `AllowedApps` — Whitelisted applications expected to handle sensitive runtime data.; `SignatureEnforcement` — Policy enforcement for validating application code signing integrity.

---

### T1657 — Financial Theft
<a id="t1657"></a>

**Detection strategy:** Detection Strategy for Financial Theft (`DET0495`)  
**Platforms:** Linux, Office Suite, SaaS, Windows, macOS  
**ATT&CK:** [T1657](https://attack.mitre.org/techniques/T1657/) · [detail page](../../techniques/impact.md#t1657)

- **`AN1361` Analytic 1361** · Windows
  Monitor for anomalous access to financial applications, browser-based banking sessions, or enterprise ERP systems from Windows endpoints. Detect mass emailing of payment instructions, sudden rule changes in Outlook for financial staff, or use of clipboard data exfiltration tied to cryptocurrency wallet addresses.
  - *Log sources:* `WinEventLog:Security` (EventCode=4624, 4648); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `FinanceAppList` — Baseline of finance-related executables or ERP processes to monitor closely.; `HighRiskAccounts` — Accounts belonging to finance, treasury, or executives that should be monitored with higher sensitivity.
- **`AN1362` Analytic 1362** · Linux
  Monitor server and endpoint logs for unusual outbound network connections to cryptocurrency nodes, unauthorized scripts accessing financial systems, or automation targeting payment file formats. Detect curl/wget activity aimed at exfiltrating transaction data or credentials from financial apps.
  - *Log sources:* `auditd:SYSCALL` (execve: Execution of curl, wget, or custom scripts accessing financial endpoints); `linux:syslog` (Authentication attempts into finance-related servers from unusual IPs or times)
  - *Tune:* `KnownFinanceIPs` — Whitelisted IPs for finance-related traffic to reduce noise.
- **`AN1363` Analytic 1363** · macOS
  Monitor unified logs for access to payment applications, browser plug-ins, or Apple Pay services from non-standard processes. Detect anomalous use of Automator scripts or keychain extraction targeting financial account credentials.
  - *Log sources:* `macos:unifiedlog` (Non-standard processes invoking financial applications or payment APIs); `macos:unifiedlog` (Anomalous keychain access attempts targeting payment credentials)
  - *Tune:* `MonitoredApps` — Financial or payment applications to explicitly monitor for unauthorized use.
- **`AN1364` Analytic 1364** · SaaS
  Monitor SaaS financial systems (e.g., QuickBooks, Workday, SAP S/4HANA cloud) for unauthorized access, rule changes, or mass export of financial data. Detect anomalous transfers initiated via SaaS APIs or new MFA-disabled logins targeting finance apps.
  - *Log sources:* `saas:finance` (Transaction/Transfer: Unusual or large transactions initiated outside business hours or by unusual accounts)
  - *Tune:* `TransactionThreshold` — Customizable monetary threshold above which financial transactions should be flagged.
- **`AN1365` Analytic 1365** · Office Suite
  Monitor email and document management systems for fraudulent invoices, impersonation of vendors, or BEC-style payment redirections. Detect abnormal editing of invoice templates, or emails containing known fraud language combined with attachment delivery.
  - *Log sources:* `m365:unified` (MailSend: Outlook messages with suspicious subject/body terms (e.g., urgent payment, wire transfer) targeting finance teams); `m365:office` (Anomalous editing of invoice or payment document templates)
  - *Tune:* `FraudTerms` — Adjustable keyword list for email and document fraud detection.

---

### T1667 — Email Bombing
<a id="t1667"></a>

**Detection strategy:** Detection Strategy for Email Bombing (`DET0355`)  
**Platforms:** Linux, Office Suite, Windows, macOS  
**ATT&CK:** [T1667](https://attack.mitre.org/techniques/T1667/) · [detail page](../../techniques/impact.md#t1667)

- **`AN1008` Analytic 1008** · Windows
  Detect abnormally high volume of inbound email messages or repetitive attachments being delivered to a single mailbox within a short time window. Defenders should look for anomalous spikes in message counts and repetitive attachment file creation events correlated with targeted users.
  - *Log sources:* `m365:unified` (Send/Receive: Unusual spikes in inbound messages to a single recipient); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `TimeWindow` — Defines the aggregation interval (e.g., 5 minutes, 1 hour) for detecting spikes in inbound email traffic.; `RecipientThreshold` — Defines maximum number of acceptable messages per user before triggering anomaly.; `AttachmentSizeThreshold` — Defines the size threshold for repetitive attachments to be flagged.
- **`AN1009` Analytic 1009** · Linux
  Monitor mail server logs (e.g., Postfix, Sendmail) for excessive connections or inbound message counts targeting a single recipient. Correlate with repetitive attachment storage in /var/mail or /var/spool/mail directories.
  - *Log sources:* `auditd:SYSCALL` (File creation events in /var/mail or /var/spool/mail exceeding baseline thresholds); `Application:Mail` (High-frequency inbound mail activity to a specific recipient address)
  - *Tune:* `MailVolumeThreshold` — Tunable value for the maximum acceptable emails per minute per user.; `AttachmentPatternList` — List of suspicious attachment extensions that may be abused for repetitive delivery.
- **`AN1010` Analytic 1010** · Office Suite
  Detect abnormal use of email clients (e.g., Outlook, Thunderbird) showing mass arrival of messages or repetitive attachments being locally stored. Correlate message volume with file creation activity in mail cache directories.
  - *Log sources:* `m365:exchange` (MailDelivery: High-frequency delivery of messages or attachments to a single recipient)
  - *Tune:* `UserContext` — Context for distinguishing between VIP or sensitive recipients and general users.
- **`AN1011` Analytic 1011** · macOS
  Monitor unified logs and Mail.app activity for repetitive incoming messages with attachments. Defenders should look for large volumes of incoming mail stored under ~/Library/Mail with unusual timing or repetitive subjects.
  - *Log sources:* `macos:unifiedlog` (Repetitive inbound email delivery activity logged within a short time window); `fs:fsusage` (create: Attachment file creation in ~/Library/Mail directories)
  - *Tune:* `FileCountThreshold` — Threshold for repetitive attachment files created within a defined interval.

---

