# Execution — Detection Strategies

> MITRE ATT&CK detection strategies and analytics (v18.1) for techniques whose primary tactic is **Execution**. Each analytic lists the **log sources / channels** it needs, the **detection logic**, and the **tunable elements** to adapt it to your environment. Authoritative source: the ATT&CK detection-strategy model in the Enterprise STIX.

See also: [all detection strategies index](README.md) · [Technique Detection Library](../TECHNIQUE_DETECTION_LIBRARY.md) (ready-to-run SIEM queries) · [Data Components & Log Sources](../../ATTACK_DATA_COMPONENTS.md) · [Technique Detail Pages](../../techniques/README.md)

---

### T1047 — Windows Management Instrumentation
<a id="t1047"></a>

**Detection strategy:** Behavioral Detection Strategy for WMI Execution Abuse on Windows (`DET0364`)  
**Platforms:** Windows  
**ATT&CK:** [T1047](https://attack.mitre.org/techniques/T1047/) · [detail page](../../techniques/execution.md#t1047)

- **`AN1031` Analytic 1031** · Windows
  Detects adversarial abuse of WMI to execute local or remote commands via WMIC, PowerShell, or COM API through a multi-event chain: process creation, command execution, and corresponding network connection if remote.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:WMI` (EventCode=5857, 5858, 5860, 5861)
  - *Tune:* `WMIQueryScope` — Restrict detection scope to suspicious WMI namespaces like `\root\cimv2`, `\root\subscription`.; `TimeWindow` — Set maximum allowable time window to correlate WMI process creation and remote connections.; `UserContext` — Tune based on interactive vs. system-level execution (e.g., via SYSTEM or low-privileged users).; `RemoteDestinationThreshold` — Number of unique remote hosts contacted using WMI within a time window.; `SuspiciousCommandPatterns` — Regex patterns to identify adversary-like usage (e.g., `wmic process call`, `powershell Invoke-WmiMethod`).

---

### T1053 — Scheduled Task/Job
<a id="t1053"></a>

**Detection strategy:** Cross-Platform Behavioral Detection of Scheduled Task/Job Abuse (`DET0094`)  
**Platforms:** Containers, ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1053](https://attack.mitre.org/techniques/T1053/) · [detail page](../../techniques/execution.md#t1053)

- **`AN0258` Analytic 0258** · Windows
  Detects creation or modification of scheduled tasks using schtasks.exe, at.exe, or COM objects followed by execution of outlier processes tied to the scheduled job.
  - *Log sources:* `WinEventLog:Security` (EventCode=4698); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=2)
  - *Tune:* `TaskAuthor` — Unexpected user or account context initiating the task.; `CommandLineRegex` — Suspicious binaries or script usage tied to scheduled tasks.; `ExecutionWindow` — Lookback window to correlate process execution after task registration.
- **`AN0259` Analytic 0259** · Linux
  Detects creation or modification of cron jobs via crontab, /etc/cron.* directories, or systemd timer units with execution by unusual users or non-standard intervals.
  - *Log sources:* `auditd:SYSCALL` (write, rename); `auditd:SYSCALL` (execve); `linux:osquery` (crontab, systemd_timers)
  - *Tune:* `CronSchedulePattern` — Look for high-frequency or off-hour scheduling patterns.; `ServiceUser` — Unusual users scheduling jobs (e.g., www-data, nobody).; `BinaryEntropy` — Abnormal scripts or binaries tied to the scheduled job.
- **`AN0260` Analytic 0260** · macOS
  Detects creation or alteration of LaunchAgents or LaunchDaemons with corresponding plist modification followed by execution of associated binaries.
  - *Log sources:* `macos:unifiedlog` (process launch); `fs:fsusage` (disk activity on /Library/LaunchAgents or LaunchDaemons); `macos:osquery` (launchd_jobs)
  - *Tune:* `PlistLabel` — Labels not associated with known applications or vendors.; `LaunchPath` — Executable path outside of standard directories (/usr/bin, /Applications).; `JobRunInterval` — Unexpected periodic job intervals (e.g., every minute).
- **`AN0261` Analytic 0261** · Containers
  Detects unusual use of `cron` or `sleep` loops inside containers executing unfamiliar scripts or binaries repeatedly.
  - *Log sources:* `auditd:SYSCALL` (execve); `containerd:runtime` (file change monitoring within /etc/cron.*, /tmp, or mounted volumes)
  - *Tune:* `ContainerLabel` — Labels or tags indicating dev/test containers executing scheduled tasks.; `ScriptFrequency` — Repetitive invocation pattern within short container lifespan.; `ImageSource` — Unexpected container image sources creating cron entries.
- **`AN0262` Analytic 0262** · ESXi
  Detects modification of ESXi cron jobs, local.sh scripts, or scheduled API calls to persist custom binaries or shell scripts.
  - *Log sources:* `esxi:vmkernel` (Startup script and task execution logs); `esxi:hostd` (shell access or job registration); `esxi:cron` (manual edits to /etc/rc.local.d/local.sh or cron.d)
  - *Tune:* `StartupScriptName` — Filename not matching expected initialization scripts.; `ExecutionContext` — Commands run from unexpected SSH sessions or elevated shells.; `PersistenceInterval` — Rare scheduling triggers (e.g., @reboot + hourly repetition).

---

### T1053.002 — At
<a id="t1053002"></a>

**Detection strategy:** Cross-Platform Detection of Scheduled Task/Job Abuse via `at` Utility (`DET0333`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1053.002](https://attack.mitre.org/techniques/T1053/002/) · [detail page](../../techniques/execution.md#t1053002)

- **`AN0943` Analytic 0943** · Windows
  Detects creation of scheduled tasks via `at.exe` or WMI `Win32_ScheduledJob` class, followed by execution of anomalous processes by svchost.exe or taskeng.exe.
  - *Log sources:* `WinEventLog:Security` (EventCode=4698); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `TaskUser` — Unusual users creating jobs (e.g., non-admin accounts or service users).; `ExecutionTimeWindow` — Delay between task registration and execution.; `CommandLinePattern` — Unexpected script or binary execution (e.g., cmd.exe /c PowerShell payload).
- **`AN0944` Analytic 0944** · Linux
  Detects usage of `at` command to schedule jobs, followed by job execution and modification of job files under /var/spool/cron/atjobs.
  - *Log sources:* `auditd:SYSCALL` (execve); `auditd:SYSCALL` (write)
  - *Tune:* `AtJobPath` — Monitoring additional paths (e.g., tmp-mounted spool dirs) for modified at jobs.; `ScheduleLatency` — Expected delay between at job creation and execution.; `JobScriptEntropy` — High entropy or obfuscation in at job payloads.
- **`AN0945` Analytic 0945** · macOS
  Detects user or root invocation of `at` command to schedule a job, followed by job execution using LaunchServices and activity in /usr/lib/cron/at.
  - *Log sources:* `macos:unifiedlog` (process: at, job runner); `fs:fsusage` (file access to /usr/lib/cron/at and job execution path); `macos:osquery` (process_events)
  - *Tune:* `AtPermissions` — Whether `at.allow` and `at.deny` are properly configured.; `ExecutionCommand` — Target binary executed via the at job.; `RunUser` — Detection of root user scheduling job with unusual command.

---

### T1053.003 — Cron
<a id="t1053003"></a>

**Detection strategy:** Cross-Platform Detection of Cron Job Abuse for Persistence and Execution (`DET0290`)  
**Platforms:** ESXi, Linux, macOS  
**ATT&CK:** [T1053.003](https://attack.mitre.org/techniques/T1053/003/) · [detail page](../../techniques/execution.md#t1053003)

- **`AN0805` Analytic 0805** · Linux
  Detects creation or modification of crontab entries by non-root users or from abnormal parent processes, followed by the execution of uncommon binaries at scheduled intervals.
  - *Log sources:* `auditd:SYSCALL` (write); `auditd:SYSCALL` (execve)
  - *Tune:* `CronFilePath` — System-specific crontab paths may vary across distros or deployments.; `RunUser` — Define if only root or specific admin users are allowed to schedule jobs.; `ExecutionFrequency` — Threshold for suspicious repetition (e.g., every minute jobs).
- **`AN0806` Analytic 0806** · macOS
  Detects crontab job additions or modifications via `crontab` utility or direct edits, especially those created by interactive users executing hidden or renamed scripts.
  - *Log sources:* `macos:unifiedlog` (process: crontab edits, launch of cron job); `fs:fsusage` (file access to /usr/lib/cron/tabs/ and cron output files)
  - *Tune:* `ScriptPath` — Match scheduled binary path to trusted directory baseline.; `CronScheduleSyntax` — Flags excessive frequency or wildcard-heavy cron expressions.; `InteractiveUserContext` — Limit cron job writes from interactive shells.
- **`AN0807` Analytic 0807** · ESXi
  Detects direct modification of crontab entries in /var/spool/cron/crontabs/root or /etc/rc.local.d/local.sh followed by execution of scripts linked to lateral movement or malware persistence.
  - *Log sources:* `esxi:hostd` (modification of crontab or local.sh entries); `esxi:cron` (execution of scheduled job); `esxi:vmkernel` (spawned shell or execution environment activity)
  - *Tune:* `CrontabFileMonitored` — Admins may customize paths in hardened deployments.; `ShellCommandPayload` — Flag shell-based persistence indicators in local.sh or cron payloads.; `JobInterval` — Time interval of task repetition for outlier identification.

---

### T1053.005 — Scheduled Task
<a id="t1053005"></a>

**Detection strategy:** Detection of Suspicious Scheduled Task Creation and Execution on Windows (`DET0441`)  
**Platforms:** Windows  
**ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/) · [detail page](../../techniques/execution.md#t1053005)

- **`AN1221` Analytic 1221** · Windows
  Detects the creation, modification, or deletion of scheduled tasks through Task Scheduler, WMI, PowerShell, or API-based methods followed by execution from svchost.exe or taskeng.exe. Includes detection of hidden or anomalous scheduled tasks, especially those created under SYSTEM or suspicious user contexts.
  - *Log sources:* `WinEventLog:Security` (EventCode=4698); `WinEventLog:Security` (EventCode=4702); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=13, 14)
  - *Tune:* `TimeWindow` — Defines threshold for grouping task creation and associated execution within suspicious time proximity.; `UserContext` — Filters based on non-standard user accounts or execution under SYSTEM when not typical for the environment.; `TaskNamePattern` — Allows defenders to flag obfuscated, randomized, or suspicious task names outside normal conventions.; `CommandLineEntropyThreshold` — Flags tasks executing heavily obfuscated PowerShell or binary blobs via base64 or encoding.

---

### T1053.006 — Systemd Timers
<a id="t1053006"></a>

**Detection strategy:** Behavioral Detection of Systemd Timer Abuse for Scheduled Execution (`DET0231`)  
**Platforms:** Linux  
**ATT&CK:** [T1053.006](https://attack.mitre.org/techniques/T1053/006/) · [detail page](../../techniques/execution.md#t1053006)

- **`AN0645` Analytic 0645** · Linux
  Detects adversarial abuse of systemd timers by correlating file creation/modification of .timer and .service units in system directories with the execution of abnormal child processes launched by 'systemd' (PID 1), especially as root.
  - *Log sources:* `auditd:SYSCALL` (creat, open, write on /etc/systemd/system and /usr/lib/systemd/system); `auditd:SYSCALL` (execve logging for /usr/bin/systemctl and systemd-run); `linux:osquery` (file_events)
  - *Tune:* `TimerIntervalThreshold` — The interval threshold used to determine if a newly created timer is unusually frequent or immediate (e.g., < 5 minutes).; `ParentProcessID` — Whether the child process has a parent PID of 1, indicating systemd as the invoker. Can be tuned to include known benign cases.; `UserContext` — User under which the timer/service is created or executed (e.g., root vs. non-root).; `TimerCreationPath` — The path where the timer or service file is created; system-wide vs. user space can be scoped.

---

### T1053.007 — Container Orchestration Job
<a id="t1053007"></a>

**Detection strategy:** Detection of Malicious Kubernetes CronJob Scheduling (`DET0206`)  
**Platforms:** Containers  
**ATT&CK:** [T1053.007](https://attack.mitre.org/techniques/T1053/007/) · [detail page](../../techniques/execution.md#t1053007)

- **`AN0582` Analytic 0582** · Containers
  Detects abuse of container orchestration platforms (e.g., Kubernetes) where adversaries create CronJobs to maintain persistence or execute malicious Jobs across the cluster.
  - *Log sources:* `kubernetes:apiserver` (verb=create, resource=cronjobs, group=batch); `kubernetes:events` (container start/stop activity via Docker, containerd, or CRI-O); `container:proxy` (outbound/inbound network activity from spawned pods)
  - *Tune:* `NamespaceScope` — Kubernetes namespace the job is deployed to—scoping this to known trusted namespaces may reduce noise.; `ImageRepository` — The container image registry or repository the job pulls from—can be filtered by trusted registries.; `ScheduleWindow` — Time window or frequency of CronJob execution (e.g., ‘@hourly’)—jobs running at odd hours may be suspicious.; `ExecutionCommand` — The command or entrypoint executed by the Job—unexpected shell commands or interpreters may warrant inspection.

---

### T1059 — Command and Scripting Interpreter
<a id="t1059"></a>

**Detection strategy:** Behavioral Detection of Command and Scripting Interpreter Abuse (`DET0516`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1059](https://attack.mitre.org/techniques/T1059/) · [detail page](../../techniques/execution.md#t1059)

- **`AN1428` Analytic 1428** · Windows
  Detects the execution of scripting or command interpreters (e.g., powershell.exe, cmd.exe, wscript.exe) outside expected administrative time windows or from abnormal user contexts, often followed by encoded/obfuscated arguments or secondary execution events.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `CommandLinePattern` — Tunable to match encoded or uncommon script execution patterns specific to the environment.; `ParentProcessName` — May vary across managed/unmanaged workstations or user-driven script activity.; `TimeWindow` — Used to restrict analysis to work hours or known admin maintenance windows.
- **`AN1429` Analytic 1429** · Linux
  Detects use of shell interpreters (e.g., bash, sh, python, perl) initiated by users or processes not normally executing them, especially when chaining suspicious utilities like netcat, curl, or ssh.
  - *Log sources:* `auditd:SYSCALL` (execve)
  - *Tune:* `InterpreterName` — Regex to identify which interpreters (bash, python, ruby) to monitor based on typical usage.; `UserContext` — Scope to users or service accounts not expected to run interpreters interactively.; `ExecutionChainLength` — Defines maximum process tree depth to correlate interpreter execution with its effects.
- **`AN1430` Analytic 1430** · macOS
  Detects launch of command-line interpreters via Terminal, Automator, or hidden `osascript`, especially when parent process lineage deviates from user-initiated applications.
  - *Log sources:* `macos:unifiedlog` (log stream --info --predicate 'eventMessage CONTAINS "exec"')
  - *Tune:* `LaunchAgentName` — Monitor for specific plist agents frequently abused for persistence or payload execution.; `ScriptName` — Path or script name pattern (e.g., hidden files, /tmp locations).; `TerminalAppUsage` — Adjust based on whether Terminal.app use is common or restricted in user policy.
- **`AN1431` Analytic 1431** · ESXi
  Detects use of 'esxcli system' or direct interpreter commands (e.g., busybox shell) invoked from SSH or host terminal unexpectedly.
  - *Log sources:* `esxi:vobd` (shell session start)
  - *Tune:* `ShellEnabledFlag` — Control alerting based on whether ESXi shell access is typically disabled.; `SSHContext` — Scope detection to SSH session origins or internal vs. remote access.
- **`AN1432` Analytic 1432** · Network Devices
  Identifies CLI interpreter access (e.g., Cisco IOS, Juniper JUNOS) via `enable` mode or scripting-capable sessions used by uncommon accounts or from unknown IPs.
  - *Log sources:* `networkdevice:cli` (shell command); `networkdevice:syslog` (authentication & authorization)
  - *Tune:* `UserRole` — Which roles or privilege levels should be monitored for interpreter misuse.; `DeviceType` — Support filtering for routers, switches, firewalls depending on network segmentation.

---

### T1059.001 — PowerShell
<a id="t1059001"></a>

**Detection strategy:** Abuse of PowerShell for Arbitrary Execution (`DET0455`)  
**Platforms:** Windows  
**ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/) · [detail page](../../techniques/execution.md#t1059001)

- **`AN1252` Analytic 1252** · Windows
  Detects behavioral chains where PowerShell is launched with encoded commands, unusual parent processes, or suspicious modules loaded, potentially followed by network connections or child process spawning. Supports detection of both direct (powershell.exe) and indirect (.NET automation) invocations.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106); `WinEventLog:PowerShell` (EventCode=400, 403); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `CommandLinePattern` — Regex pattern for encoded, obfuscated, or hidden PowerShell arguments (e.g., '-enc', '-nop').; `ParentProcessName` — Filter based on abnormal parents like Excel, WinWord, or mshta spawning PowerShell.; `TimeWindow` — Scope detection to off-hours, lateral movement timeframes, or non-maintenance windows.; `LoadedModuleList` — Tuneable to monitor rare or never-before-seen .NET assemblies tied to PowerShell abuse.; `ScriptBlockLengthThreshold` — Adjustable threshold for length of script blocks logged by Event ID 4104 (useful for filtering noise).

---

### T1059.002 — AppleScript
<a id="t1059002"></a>

**Detection strategy:** Detection of AppleScript-Based Execution on macOS (`DET0414`)  
**Platforms:** macOS  
**ATT&CK:** [T1059.002](https://attack.mitre.org/techniques/T1059/002/) · [detail page](../../techniques/execution.md#t1059002)

- **`AN1164` Analytic 1164** · macOS
  Detects AppleScript execution via 'osascript', NSAppleScript/OSAScript APIs, and abnormal application control events across user sessions. Focuses on causal chains such as osascript spawning child processes, script-induced keystrokes, or API-backed dialog spoofing.
  - *Log sources:* `macos:unifiedlog` (process: spawn, exec)
  - *Tune:* `ScriptInvocationParent` — Identify rare or suspicious parent processes launching AppleScript (e.g., Safari, Mail, msedge).; `TimeWindow` — Flag AppleScript execution during user-inactive hours, especially for automation frameworks.; `AppleEventActionType` — Filter AppleEvent-based automation involving UI interaction, keystrokes, or remote control.; `TargetApplicationSet` — Scope AppleScript use toward security-sensitive apps (e.g., Terminal, ssh, Keychain Access).; `ExecutionPathRegex` — Restrict to unusual paths like /tmp/, ~/Library/, or embedded in Automator workflows.

---

### T1059.003 — Windows Command Shell
<a id="t1059003"></a>

**Detection strategy:** Behavioral Detection of Windows Command Shell Execution (`DET0202`)  
**Platforms:** Windows  
**ATT&CK:** [T1059.003](https://attack.mitre.org/techniques/T1059/003/) · [detail page](../../techniques/execution.md#t1059003)

- **`AN0578` Analytic 0578** · Windows
  Detects interactive or scripted abuse of cmd.exe, batch files, or shell invocation chains. Focuses on parent-child relationships (e.g., cmd.exe launched from unusual parents), anomalous command-line parameters, and chaining with discovery, credential access, or lateral movement behaviors.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=7); `EDR:scriptblock` (Process Tree + Script Block Logging)
  - *Tune:* `ParentProcessName` — Cmd.exe launched from uncommon parents (e.g., msedge.exe, winword.exe) may indicate abuse.; `TimeWindow` — Cmd or .bat execution during non-working hours may indicate automation or C2 activity.; `CommandLinePattern` — Flags suspicious switches (e.g., /c ping, /k whoami) or command chaining (&&, ^).; `ScriptStoragePath` — Batch file execution from %TEMP%, C:\Users\Public, or external drives.; `UserContext` — Flags admin-level users executing cmd outside expected baselines.

---

### T1059.004 — Unix Shell
<a id="t1059004"></a>

**Detection strategy:** Behavioral Detection of Unix Shell Execution (`DET0384`)  
**Platforms:** ESXi, Linux, Network Devices, macOS  
**ATT&CK:** [T1059.004](https://attack.mitre.org/techniques/T1059/004/) · [detail page](../../techniques/execution.md#t1059004)

- **`AN1081` Analytic 1081** · Linux
  Detects bash, sh, zsh, or BusyBox shell execution initiated via remote sessions, unauthorized users, or embedded within secondary script interpreters. Focus is on chained behavior: shell > suspicious commands > network discovery or persistence indicators.
  - *Log sources:* `auditd:SYSCALL` (execve); `linux:osquery` (socket_events); `linux:syslog` (auth.log / secure.log)
  - *Tune:* `ExecutableName` — Detect variants like /bin/sh, /usr/local/bin/zsh, /bin/busybox sh.; `UserContext` — Shell used by service accounts, root, or rare accounts.; `ParentProcess` — Shell invoked by unexpected parents (e.g., curl, mail, apache2).; `TimeWindow` — Execution outside maintenance windows or normal activity periods.; `CommandLinePattern` — Flags use of loops, download commands, chaining (|, &&), or reverse shells.
- **`AN1082` Analytic 1082** · macOS
  Identifies use of sh/bash/zsh in suspicious context, such as user scripts launched from non-standard apps (e.g., Preview.app), embedded in LaunchDaemons, or executed outside Terminal.app. Looks for misuse in Automator, LaunchAgents, or NSAppleScript-executed shell.
  - *Log sources:* `macos:unifiedlog` (log stream --predicate 'eventMessage contains "exec"'); `macos:osquery` (launchd + process_events); `macos:syslog` (system.log, asl.log)
  - *Tune:* `ScriptLocation` — Execution from /Users/Shared, ~/Library/LaunchAgents, /tmp.; `ParentProcess` — Shells spawned from Preview, Safari, or AppleScript.; `UserRole` — Detection thresholds may differ for admin vs standard users.
- **`AN1083` Analytic 1083** · ESXi
  Detects BusyBox or Ash shell execution from unauthorized logins or remote connections. Focus is on rare shell invocations from DCUI, SSH sessions, or remote management paths. Also watches for payload droppers or persistence artifacts using shell.
  - *Log sources:* `esxi:vmkernel` (DCUI shell start, BusyBox activity); `esxi:auth` (Shell login or escalation)
  - *Tune:* `UserContext` — Non-root use of shell (or root outside maintenance window).; `CommandPattern` — Use of ‘nc’, ‘wget’, or dropper-like behavior in shell.; `ShellPath` — Unexpected invocation of BusyBox/ash from mounted ISO or datastore.
- **`AN1084` Analytic 1084** · Network Devices
  Detects Unix shell usage on network appliances (e.g., routers, firewalls, embedded Linux) through rare console commands, CLI interfaces, or script injection via exposed APIs or SSH.
  - *Log sources:* `networkdevice:syslog` (CLI Command Audit); `NSM:Flow` (remote access)
  - *Tune:* `Interface` — Flags command line access via remote console (telnet/SSH/API) from non-whitelisted source.; `CommandString` — Monitors rare/privileged shell commands (e.g., enable, tftp, firmware mod).

---

### T1059.005 — Visual Basic
<a id="t1059005"></a>

**Detection strategy:** Behavioral Detection of Visual Basic Execution (VBS/VBA/VBScript) (`DET0076`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1059.005](https://attack.mitre.org/techniques/T1059/005/) · [detail page](../../techniques/execution.md#t1059005)

- **`AN0209` Analytic 0209** · Windows
  Detects execution of VB-based scripts or macros (VBS/VBA/VBScript) through cscript.exe/wscript.exe, Office-based process chains, or HTA usage. Focuses on chained behavior: Office or HTML container spawns script host > script host spawns PowerShell, network connections, or process injection.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `ParentProcess` — Microsoft Word/Excel or mshta.exe spawning wscript.exe/cscript.exe.; `UserContext` — Script execution by non-admin users or service accounts.; `TimeWindow` — Script execution outside normal business hours or patching cycle.; `PayloadEntropyThreshold` — High entropy indicative of obfuscation or encoding in the script.; `ModuleName` — Loading of vbscript.dll, scrrun.dll, or other scripting engine modules.
- **`AN0210` Analytic 0210** · macOS
  Detects embedded or emulated VBScript/VBA execution via Wine-based apps, Office for Mac abusing cross-platform .NET features, or macros dropped and invoked via AppleScript or third-party automation tools.
  - *Log sources:* `macos:unifiedlog` (log stream --predicate 'eventMessage contains "wscript" OR "vbs"'); `macos:osquery` (process_events); `macos:syslog` (system.log)
  - *Tune:* `ScriptLocation` — Script run from ~/Downloads, ~/Library, or /tmp/; `EmulationContext` — Wine or CrossOver launching legacy Windows scripting engines.; `UserContext` — VB execution from non-standard or shared users on endpoint.
- **`AN0211` Analytic 0211** · Linux
  Detects abuse of Mono/.NET Core environments to execute VB-like scripts, often in environments with Office emulation or WINE. Focus is on rare invocations of scripting hosts like mono.exe or .NET shells, often seen in spam filtering or forensic labs with Office support.
  - *Log sources:* `auditd:SYSCALL` (execve); `linux:syslog` (/var/log/syslog)
  - *Tune:* `InterpreterPath` — Mono/.NET Core binary location may differ per distro or Docker container.; `FileExtension` — .vbs, .vb, or .vba run under non-standard interpreters.; `ExecContext` — Execution by low-privilege users or from /tmp/.

---

### T1059.006 — Python
<a id="t1059006"></a>

**Detection strategy:** Cross-Platform Behavioral Detection of Python Execution (`DET0063`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1059.006](https://attack.mitre.org/techniques/T1059/006/) · [detail page](../../techniques/execution.md#t1059006)

- **`AN0172` Analytic 0172** · Windows
  Detects Python execution via python.exe or py.exe with anomalous parent lineage (e.g., Office macros, LOLBAS), execution from unusual directories, or chained network/PowerShell/system-level activity.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `EDR:hunting` (Advanced Hunting: DeviceProcessEvents + DeviceNetworkEvents)
  - *Tune:* `ParentProcess` — Non-standard processes spawning python.exe (e.g., winword.exe, mshta.exe).; `ScriptPath` — Execution of .py from temp directories or user profile paths.; `TimeWindow` — Execution outside maintenance or patch windows.; `UserContext` — Execution by low-privileged or service accounts.; `ChildProcess` — Python spawning suspicious binaries or scripts (e.g., PowerShell, certutil).
- **`AN0173` Analytic 0173** · macOS
  Detects native Python or framework-based execution from Terminal, embedded apps, or launchd jobs. Flags network calls, persistence writes, or system enumeration after Python launch.
  - *Log sources:* `macos:unifiedlog` (log stream --predicate 'eventMessage contains "python"'); `macos:osquery` (process_events); `macos:syslog` (system.log)
  - *Tune:* `ExecutionPath` — Detects python scripts from ~/Downloads/, /Volumes/, or /tmp/.; `ScriptName` — Obfuscated or high entropy script names.; `SpawnChain` — Chained behavior: Python → bash → curl or Python → osascript.
- **`AN0174` Analytic 0174** · Linux
  Detects Python execution from non-standard user contexts or cron jobs that invoke outbound traffic, access sensitive files, or perform process injection (e.g., ptrace or /proc memory maps).
  - *Log sources:* `auditd:SYSCALL` (execve); `linux:syslog` (/var/log/syslog)
  - *Tune:* `ScriptDir` — Script invoked from /tmp, /var/tmp, or .hidden/ folders.; `ScheduledContext` — Execution from user cron or systemd timers outside of approved scripts.; `NetworkActivity` — Python performing HTTP/HTTPS without package updates.
- **`AN0175` Analytic 0175** · ESXi
  Detects Python script or interpreter execution on ESXi hosts via embedded BusyBox shells, nested installations, or dropped files via SSH or datastore mount. Flags unusual scripting or post-compromise enumeration behavior.
  - *Log sources:* `esxi:vobd` (/var/log/vobd.log); `esxi:hostd` (/var/log/hostd.log)
  - *Tune:* `ExecutionSource` — Script loaded from mounted datastore, SSH upload, or dropped via guest-to-host tools.; `HostUser` — Python launched under root or unknown user.; `InstallPath` — Custom Python binaries or packages in non-default paths (/tmp/python/bin/python3).

---

### T1059.007 — JavaScript
<a id="t1059007"></a>

**Detection strategy:** Cross-Platform Detection of JavaScript Execution Abuse (`DET0264`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1059.007](https://attack.mitre.org/techniques/T1059/007/) · [detail page](../../techniques/execution.md#t1059007)

- **`AN0733` Analytic 0733** · Windows
  Detects JavaScript execution through WSH (wscript.exe, cscript.exe) or HTA (mshta.exe), particularly when spawned from Office macros, web browsers, or abnormal user paths. Correlates script execution with outbound network activity or system modification.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `m365:defender` (ScriptBlockLogging + AMSI); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `ParentProcess` — Execution of wscript.exe, cscript.exe, or mshta.exe from suspicious parent like Excel or Outlook.; `ScriptPath` — Script loaded from %TEMP%, user download folder, or via UNC/web path.; `TimeWindow` — Execution of JavaScript during non-business or patch windows.; `UserContext` — Execution by accounts not typically authorized for scripting (e.g., non-admin users).; `EntropyScore` — Obfuscated JS with high entropy detected by AMSI or ScriptBlock logging.
- **`AN0734` Analytic 0734** · macOS
  Detects JavaScript for Automation (JXA) via osascript or compiled scripts using OSAKit APIs. Flags execution involving system modification, inter-process scripting, or browser abuse.
  - *Log sources:* `macos:unifiedlog` (log stream with predicate 'eventMessage CONTAINS "osascript"'); `macos:osquery` (process_events); `macos:syslog` (/var/log/system.log)
  - *Tune:* `ScriptLocation` — Execution of JXA from user-controlled paths like ~/Downloads or /Volumes.; `ParentProcess` — osascript invoked by third-party apps (VSCode, browsers, etc.).; `APIInvocation` — Use of OSAKit API by apps not typically scripting-enabled.
- **`AN0735` Analytic 0735** · Linux
  Detects Node.js or JavaScript interpreter execution from web shells, cron jobs, or local users. Correlates execution with reverse shell behavior, file modifications, or abnormal outbound connections.
  - *Log sources:* `auditd:SYSCALL` (execve); `linux:syslog` (/var/log/syslog)
  - *Tune:* `ScriptPath` — Script launched from /tmp, /var/tmp, or hidden dot directories.; `BinaryName` — Custom compiled JS binaries like node_shell or interpreter disguises.; `UserExecutionContext` — Execution by service accounts or low-privilege users running cron scripts.; `NetworkFollowUp` — Connection attempts to C2 post-node.js execution.

---

### T1059.008 — Network Device CLI
<a id="t1059008"></a>

**Detection strategy:** Behavioral Detection of CLI Abuse on Network Devices (`DET0142`)  
**Platforms:** Network Devices  
**ATT&CK:** [T1059.008](https://attack.mitre.org/techniques/T1059/008/) · [detail page](../../techniques/execution.md#t1059008)

- **`AN0399` Analytic 0399** · Network Devices
  Detects unauthorized or anomalous use of command-line interfaces (CLI) on network devices. Focuses on remote access sessions (e.g., SSH/Telnet), privilege escalation within CLI sessions, execution of high-risk commands (e.g., config replace, terminal monitor, no logging), and configuration changes outside of approved windows.
  - *Log sources:* `networkdevice:syslog` (command_exec); `NSM:Flow` (remote CLI session detection); `networkdevice:syslog` (authorization/accounting logs)
  - *Tune:* `TimeWindow` — Config changes made outside of maintenance windows are more suspicious.; `UserContext` — Unexpected CLI activity by service accounts or users not assigned to manage network devices.; `CommandPattern` — Regex or keyword match on dangerous or unusual commands (e.g., 'no logging', 'reload', 'copy tftp', 'config replace').; `SourceIP` — Remote CLI sessions originating from untrusted networks or jump hosts.; `SessionDuration` — Abnormally short or long SSH/Telnet CLI sessions compared to baseline.

---

### T1059.009 — Cloud API
<a id="t1059009"></a>

**Detection strategy:** Behavioral Detection of Malicious Cloud API Scripting (`DET0078`)  
**Platforms:** IaaS  
**ATT&CK:** [T1059.009](https://attack.mitre.org/techniques/T1059/009/) · [detail page](../../techniques/execution.md#t1059009)

- **`AN0215` Analytic 0215** · IaaS
  Detects adversarial use of cloud APIs for command execution, resource control, or reconnaissance. Focuses on CLI/SDK/scripting language abuse via stolen credentials or in-browser Cloud Shells. Monitors for anomalous API calls chained with authentication context shifts (e.g., stolen token -> privileged action) and cross-service impacts.
  - *Log sources:* `AWS:CloudTrail` (eventName: RunInstances, CreateUser, PutRolePolicy, InvokeCommand); `azure:activity` (operationName: Write, Access Review, RoleAssignment); `Okta:SystemLog` (eventType: user.authentication.sso, app.oauth2.token.grant)
  - *Tune:* `TimeWindow` — Off-hours API usage or configuration changes are more suspicious outside business context.; `UserAgent` — Unexpected SDK usage (e.g., `boto3`, `azcopy`, unknown User-Agent strings).; `CredentialType` — High-risk if access token or API key used outside expected geographic/IP behavior.; `APISequence` — Unusual or rapid chaining of provisioning, IAM, and execution APIs.; `ConsoleContext` — Browser-based Cloud Shell vs local CLI may indicate insider vs external use case.

---

### T1059.010 — AutoHotKey & AutoIT
<a id="t1059010"></a>

**Detection strategy:** Detection Strategy for AutoHotKey & AutoIT Abuse (`DET0332`)  
**Platforms:** Windows  
**ATT&CK:** [T1059.010](https://attack.mitre.org/techniques/T1059/010/) · [detail page](../../techniques/execution.md#t1059010)

- **`AN0942` Analytic 0942** · Windows
  Detects execution of AutoHotKey or AutoIT interpreters or compiled scripts used for unauthorized automation, command execution, or payload delivery, correlated with anomalous process lineage, command-line arguments, or script creation events.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=10)
  - *Tune:* `TimeWindow` — Tuning this helps identify automation behavior outside expected user work hours.; `ParentProcessName` — Used to isolate cases where AHK or AutoIT scripts are spawned by suspicious or unusual processes.; `ScriptExtension` — Extensions such as .ahk, .au3, or unknown .exe names compiled from these.; `ChildProcessCount` — Threshold for number of spawned children to detect automation or modular malware behavior.

---

### T1059.011 — Lua
<a id="t1059011"></a>

**Detection strategy:** Detection Strategy for Lua Scripting Abuse (`DET0101`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1059.011](https://attack.mitre.org/techniques/T1059/011/) · [detail page](../../techniques/execution.md#t1059011)

- **`AN0278` Analytic 0278** · Windows
  Detects execution of Lua interpreters or scripts (.lua), especially when correlated with suspicious parent processes or file drop events, indicating malicious use of embedded scripting.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `ParentProcessName` — May vary depending on delivery vector (e.g., explorer.exe, cmd.exe, rundll32.exe); `TimeWindow` — Used to correlate file drop and execution of Lua scripts in close succession.
- **`AN0279` Analytic 0279** · Linux
  Detects invocation of lua or luajit interpreters by users or services outside of expected packages, chained with script drop or memory artifacts.
  - *Log sources:* `auditd:SYSCALL` (execve); `auditd:SYSCALL` (PATH)
  - *Tune:* `ExecutablePath` — Lua interpreter path may vary based on distro or adversary staging.; `UserContext` — May need to exclude service or admin accounts that use Lua legitimately.
- **`AN0280` Analytic 0280** · macOS
  Detects Lua script execution via native or 3rd party interpreters, chained with unsigned binaries or unexpected parent lineage.
  - *Log sources:* `macos:unifiedlog` (log stream)
  - *Tune:* `ParentProcessName` — Adjustable based on system activity patterns (e.g., Terminal vs GUI); `SignatureStatus` — Helps filter unsigned or self-signed Lua payloads.
- **`AN0281` Analytic 0281** · Network Devices
  Detects embedded Lua interpreter execution or script injection on devices supporting Lua scripting (e.g., routers, firewalls), often seen in modified firmware or abused APIs.
  - *Log sources:* `networkdevice:runtime` (runtime)
  - *Tune:* `FirmwareBuildHash` — Used to baseline known good versions versus injected scripts.; `ScriptInjectionPath` — Path to where scripts are allowed or denied based on config.

---

### T1059.012 — Hypervisor CLI
<a id="t1059012"></a>

**Detection strategy:** Detection Strategy for ESXi Hypervisor CLI Abuse (`DET0558`)  
**Platforms:** ESXi  
**ATT&CK:** [T1059.012](https://attack.mitre.org/techniques/T1059/012/) · [detail page](../../techniques/execution.md#t1059012)

- **`AN1537` Analytic 1537** · ESXi
  Detects suspicious use of ESXi native CLI tools like esxcli and vim-cmd by unauthorized users or outside expected maintenance windows. Focus is on actions such as stopping VMs, reconfiguring network/firewall settings, and enabling SSH or logging.
  - *Log sources:* `esxi:vmkernel` (esxcli, vim-cmd invocation); `esxi:auth` (SSH session/login)
  - *Tune:* `TimeWindow` — Helps scope detection to off-hours or change control gaps.; `UserContext` — Environment-specific users may run these commands as part of normal ops.; `CommandPattern` — CLI commands vary by adversary intent (e.g., 'stop', 'reboot', 'firewall set')

---

### T1059.013 — Container CLI/API
<a id="t1059013"></a>

**Detection strategy:** Container CLI and API Abuse via Docker/Kubernetes (T1059.013) (`DET0083`)  
**Platforms:** Containers  
**ATT&CK:** [T1059.013](https://attack.mitre.org/techniques/T1059/013/) · [detail page](../../techniques/execution.md#t1059013)

- **`AN0233` Analytic 0233** · Containers
  Execution of container orchestration commands (e.g., `docker exec`, `kubectl exec`) or API-driven interactions with running containers from unauthorized hosts or non-standard user contexts. Defender sees programmatic or interactive command execution within containers outside expected CI/CD tools or automation frameworks, often followed by file writes, privilege escalation, or lateral discovery.
  - *Log sources:* `auditd:SYSCALL` (execve: Execution of container management CLIs (docker, crictl, kubectl) or interpreted shells (sh, bash, python) within container context); `docker:events` (exec_create: docker exec events targeting running containers from non-CI sources); `kubernetes:apiserver` (create/exec: Kubernetes API calls to exec into containers or create pods from curl, kubectl, or SDK clients); `AWS:CloudTrail` (CreatePod: Programmatic creation of new pod resources using container images not seen before in the environment); `kubernetes:audit` (Shell process (e.g., /bin/sh, /bin/bash) spawned in a container without an interactive session attached (i.e., automation anomaly))
  - *Tune:* `AuthorizedUserAgents` — List of CI/CD pipeline runners, SRE tools, or cluster mgmt agents allowed to invoke API/CLI commands in containers.; `NewImageThreshold` — Threshold for alerting on unseen container images pulled and executed. Adjust to reduce noise from frequent deploys.; `TimeWindow` — Temporal window to correlate container exec with shell spawn and network activity (default: 2 minutes).; `InteractiveSessionExpectation` — Set whether shell spawns without TTY or PTY should be flagged — based on org deployment model.

---

### T1072 — Software Deployment Tools
<a id="t1072"></a>

**Detection strategy:** Detection of Adversary Abuse of Software Deployment Tools (`DET0223`)  
**Platforms:** Linux, Network Devices, SaaS, Windows, macOS  
**ATT&CK:** [T1072](https://attack.mitre.org/techniques/T1072/) · [detail page](../../techniques/execution.md#t1072)

- **`AN0623` Analytic 0623** · Windows
  Detects SCCM, Intune, or remote push execution spawning scripts or binaries from SYSTEM context or unusual consoles (e.g., cmtrace.exe launching PowerShell or cmd.exe).
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Application` (SCCM, Intune logs)
  - *Tune:* `ParentImageList` — Allowlist of known SCCM-related binary spawners (e.g., 'CCMExec.exe'); `UserContext` — Expected deployment activity from scheduled system accounts; `TimeWindow` — Unusual deployment timing outside standard maintenance hours
- **`AN0624` Analytic 0624** · Linux
  Detects remote scripts or binaries deployed via Puppet, Chef, Ansible, or shell scripts from orchestration servers executing outside maintenance windows or in unmanaged nodes.
  - *Log sources:* `auditd:SYSCALL` (execve)
  - *Tune:* `DeployingHostAllowList` — Approved orchestration or jump box IPs; `ScriptExecutionBaseline` — Expected scripts, interpreters, or package managers used
- **`AN0625` Analytic 0625** · macOS
  Detects script or binary execution initiated via JAMF, Munki, or custom MDM agents outside of baseline, or JAMF launching new Terminal or osascript processes from remote command payloads.
  - *Log sources:* `macos:unifiedlog` (process and signing chain events); `macos:jamf` (RemoteCommandExecution)
  - *Tune:* `SigningAuthorityList` — Expected signing authorities for JAMF and MDM scripts; `RemoteCommandInterval` — Frequency of remote execution from MDM servers
- **`AN0626` Analytic 0626** · SaaS
  Detects cloud-native software deployment or management (e.g., SSM Run Command, Intune) initiating script execution on endpoints outside expected org IDs, admin groups, or maintenance windows.
  - *Log sources:* `AWS:CloudTrail` (SSM RunCommand)
  - *Tune:* `IAMRoleAllowList` — Approved deployment administrators or service accounts; `ExecutionTargetList` — Expected endpoints targeted by SaaS deployments
- **`AN0627` Analytic 0627** · Network Devices
  Detects central router or switch config management tools (e.g., FortiManager, Cisco Prime) triggering device reboots or config pushes using abnormal accounts or IPs.
  - *Log sources:* `networkdevice:syslog` (config push events); `NSM:Flow` (Device-to-Device Deployment Flows)
  - *Tune:* `PushSourceAllowList` — Devices or IPs allowed to push firmware or scripts; `AuthUserPattern` — Expected CLI or API user performing configuration

---

### T1106 — Native API
<a id="t1106"></a>

**Detection strategy:** Behavioral Detection of Native API Invocation via Unusual DLL Loads and Direct Syscalls (`DET0529`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1106](https://attack.mitre.org/techniques/T1106/) · [detail page](../../techniques/execution.md#t1106)

- **`AN1465` Analytic 1465** · Windows
  Unusual or suspicious processes loading critical native API DLLs (e.g., ntdll.dll, kernel32.dll) followed by direct syscall behavior, memory manipulation, or hollowing.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `DllName` — May tune DLL filters to focus on low-level API providers (e.g., ntdll.dll); `Image` — Tune for expected parent processes (e.g., explorer.exe, winlogon.exe); `TargetProcess` — Scope to suspicious targets like LSASS, csrss, etc.
- **`AN1466` Analytic 1466** · Linux
  Userland processes invoking syscall-heavy libraries (libc, glibc) followed by fork, mmap, or ptrace behavior commonly associated with code injection or memory manipulation.
  - *Log sources:* `auditd:SYSCALL` (execve, fork, mmap, ptrace); `auditd:SYSCALL` (module load or memory map path)
  - *Tune:* `SyscallType` — Filter for fork, mmap, ptrace based on context; `ProcessName` — Whitelist known daemon and scheduled task patterns; `MAPS Path` — Tune suspicious memory map regions (e.g., /tmp/.evilshmem)
- **`AN1467` Analytic 1467** · macOS
  Execution of processes that link to CoreServices or Foundation APIs followed by creation of memory regions, code execution, or abnormal library injection.
  - *Log sources:* `macos:unifiedlog` (launch and dylib load); `macos:endpointsecurity` (ES_EVENT_TYPE_NOTIFY_EXEC)
  - *Tune:* `API Framework Name` — Filter on CoreServices, Cocoa, Foundation framework usage; `Execution Context` — Tune to exclude known developer tools or test environments

---

### T1129 — Shared Modules
<a id="t1129"></a>

**Detection strategy:** Behavior-chain, platform-aware detection strategy for T1129 Shared Modules (`DET0018`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1129](https://attack.mitre.org/techniques/T1129/) · [detail page](../../techniques/execution.md#t1129)

- **`AN0052` Analytic 0052** · Windows
  A process (often LOLBin or user-launched program) loads a DLL from a user-writable/UNC/Temp path or unsigned/invalid signer. Within a short window the DLL is (a) newly written to disk, (b) spawned as follow-on execution (rundll32/regsvr32), or (c) establishes outbound C2.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` (CodeIntegrity/WDAC events indicating unsigned/invalid DLL loads)
  - *Tune:* `TimeWindow` — Correlation window between file write → module load → network (e.g., 0–20 minutes).; `SuspiciousPathRegex` — Regex for user-writable/UNC/temp paths to flag (e.g., %TEMP%, %APPDATA%, \\*\share\).; `UnsignedOnly` — Alert only when SignatureStatus != Valid to reduce noise.; `RareSignerThreshold` — Frequency threshold for unseen/rare signers in last N days.; `MinFileSizeKB` — Ignore tiny DLL stubs to cut noise.
- **`AN0053` Analytic 0053** · Linux
  A process loads a shared object (.so) via dlopen/LD_PRELOAD/open from non-standard or temporary locations (e.g., /tmp, /dev/shm), especially shortly after that .so is written or fetched, or linked via manipulated environment variables (LD_PRELOAD/LD_LIBRARY_PATH).
  - *Log sources:* `auditd:SYSCALL` (openat/read/mmap: Open/mmap .so files from non-standard paths); `auditd:EXECVE` (execve: Processes launched with LD_PRELOAD/LD_LIBRARY_PATH pointing to non-system dirs); `linux:syslog` (sudo or service accounts invoking loaders with suspicious env vars); `NSM:Flow` (http/file-xfer: Inbound/outbound transfer of ELF shared objects)
  - *Tune:* `SuspiciousDirs` — (/tmp, /dev/shm, /var/tmp, user home dirs) – adjust to your environment.; `TimeWindow` — Correlate write/fetch of .so to its load (e.g., 0–30 minutes).; `EnvVarWatchlist` — LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT.; `AllowedSigning/HashList` — Known-good signed or hashed shared objects.
- **`AN0054` Analytic 0054** · macOS
  A process loads a non-system .dylib/.so via dyld (dlopen/dlsym) from user-writable locations (~/Library, /tmp) or after the library was recently created/downloaded, often followed by network egress or persistence.
  - *Log sources:* `macos:unifiedlog` (dyld/unified log entries indicating image load from non-system paths); `macos:endpointsecurity` (exec: Process execution context for loaders calling dlopen/dlsym); `macos:endpointsecurity` (ES_EVENT_TYPE_NOTIFY_OPEN: Open of .dylib/.so in user-writable locations)
  - *Tune:* `SuspiciousDirs` — ~/Library, /tmp, /Users/*/.* (hidden dirs) – tune to enterprise layout.; `UnsignedOnly` — Alert only when code-signing is invalid or absent.; `TimeWindow` — Correlate write/open to module load within N minutes.

---

### T1203 — Exploitation for Client Execution
<a id="t1203"></a>

**Detection strategy:** Exploitation for Client Execution – cross-platform behavior chain (browser/Office/3rd-party apps) (`DET0287`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1203](https://attack.mitre.org/techniques/T1203/) · [detail page](../../techniques/execution.md#t1203)

- **`AN0797` Analytic 0797** · Windows
  Cause→effect chain: (1) A client app (browser, Office, PDF/Flash/reader) experiences a crash/abnormal exit or loads from an unusual location, then (2) drops or modifies a file in user-writable paths, and/or (3) spawns an unexpected child (e.g., powershell/cmd/mshta/rundll32/wscript/installer), and (4) establishes outbound C2-like connections shortly after. Correlate application logs, file writes, process lineage, and network egress within a short window.
  - *Log sources:* `WinEventLog:Application` (EventCode=1000); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `TimeWindow` — Correlation window (e.g., 15m) between crash/write/child/network.; `HighRiskChildren` — List of child processes that should rarely spawn from Office/browsers (powershell.exe, cmd.exe, wscript.exe, mshta.exe, rundll32.exe, regsvr32.exe, msiexec.exe, curl.exe).; `UserPaths` — Writable paths to watch (Downloads, %TEMP%, %APPDATA%, OneDrive, Office startup folders).; `AllowedPlugins` — Known add-ins/extensions and updater binaries to reduce noise.; `EgressAllowlist` — Known update/CDN domains and proxy egress CIDRs for suppression.
- **`AN0798` Analytic 0798** · Linux
  Cause→effect chain: (1) Browser/Office/reader process logs crash/segfault or abnormal sandbox message, (2) new executable/script/write occurs in $HOME (Downloads, ~/.cache, /tmp), (3) unexpected child like curl/wget/bash/python opens network connections soon after.
  - *Log sources:* `linux:syslog` (browser/office crash, segfault, abnormal termination); `auditd:SYSCALL` (open); `auditd:SYSCALL` (creat); `auditd:SYSCALL` (rename,chmod); `auditd:SYSCALL` (execve); `NetFlow:Flow` (new outbound connections from exploited process tree)
  - *Tune:* `TimeWindow` — 5–20m correlation window.; `UserPaths` — HOME write targets: ~/Downloads, ~/.config/autostart, ~/.local/share, /tmp.; `HighRiskChildren` — bash, sh, python, perl, node, curl, wget, socat, openssl, xxd.; `PackageUpdaters` — Allow-list common updaters (snap, flatpak, packagekit) to reduce FP.
- **`AN0799` Analytic 0799** · macOS
  Cause→effect chain: (1) App crash/abnormal termination in unified logs for Safari/Chrome/Office/Preview, (2) new files/scripts in ~/Library, ~/Downloads, /private/var/folders/*, (3) unexpected child (osascript, zsh, bash, curl) spawned by those apps, (4) new outbound connections.
  - *Log sources:* `macos:unifiedlog` (process crash, abort, code signing violations); `fs:fsevents` (create/write/rename under user-writable paths); `macos:osquery` (exec); `NSM:Connections` (new connections from exploited lineage)
  - *Tune:* `TimeWindow` — 10–30m correlation window.; `HighRiskChildren` — osascript, bash, zsh, curl, python, pbpaste/pbcopy, open -a Terminal.; `UserPaths` — ~/Library/LaunchAgents, ~/Library/Containers/*/Data, /private/var/folders/*.; `QuarantineBypass` — Flag files with missing com.apple.quarantine extended attribute when sourced from internet.

---

### T1204 — User Execution
<a id="t1204"></a>

**Detection strategy:** User Execution – multi-surface behavior chain (documents/links → helper/unpacker → LOLBIN/child → egress) (`DET0478`)  
**Platforms:** Containers, IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1204](https://attack.mitre.org/techniques/T1204/) · [detail page](../../techniques/execution.md#t1204)

- **`AN1314` Analytic 1314** · Windows
  Cause→effect chain: (1) User-facing app (Office/PDF/archiver/browser) records an open/click or abnormal event, then (2) a downloaded file is created in a user-writable path and/or decompressed, (3) the parent user app spawns a living-off-the-land binary (e.g., powershell/cmd/mshta/rundll32/msiexec/wscript/expand/zip) or installer, and (4) immediate outbound HTTP(S)/DNS/SMB from the same lineage.
  - *Log sources:* `WinEventLog:Application` (EventCode=1000); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `TimeWindow` — Correlation window (e.g., 15 minutes) from document open to child/egress.; `HighRiskParents` — Apps that should rarely spawn OS utilities (winword.exe, excel.exe, powerpnt.exe, acrord32.exe, chrome/msedge/firefox, 7zFM.exe, winrar.exe, explorer.exe).; `HighRiskChildren` — LOLBIN list: powershell.exe, cmd.exe, wscript.exe, cscript.exe, mshta.exe, rundll32.exe, regsvr32.exe, msiexec.exe, curl.exe, bitsadmin.exe, pcalua.exe, expand.exe, tar.exe.; `UserPaths` — Writable paths to watch: %USERPROFILE%\Downloads, %TEMP%, %APPDATA%\*, OneDrive/Teams cache, Office startup folders.; `EgressAllowList` — Corporate update/CDN domains and proxy egress CIDRs to suppress benign updater traffic.
- **`AN1315` Analytic 1315** · Linux
  Cause→effect chain: (1) User app/browser/archiver logs an open/click or abnormal exit, (2) new executable/script/archive extracted into $HOME/Downloads, /tmp, or ~/.cache, (3) parent app spawns shell/interpreter (bash/sh/python/node/curl/wget) or desktop file, and (4) new outbound connection(s) from the child lineage.
  - *Log sources:* `linux:syslog` (opened document|clicked link|segfault|abnormal termination|sandbox); `auditd:SYSCALL` (open); `auditd:SYSCALL` (creat); `auditd:SYSCALL` (rename,chmod); `auditd:SYSCALL` (execve); `NSM:Flow` (new outbound connection from browser/office lineage)
  - *Tune:* `TimeWindow` — 5–20 minute correlation window.; `UserPaths` — $HOME/Downloads, /tmp, ~/.cache, ~/.config/autostart, ~/.local/share.; `HighRiskChildren` — bash, sh, zsh, python*, perl, node, curl, wget, xdg-open, kde-open, gio open, unzip/tar extraction leading to exec.; `PkgUpdaters` — Allow-list snap/flatpak/packagekit/apt workers to reduce false positives.
- **`AN1316` Analytic 1316** · macOS
  Cause→effect chain: (1) unified logs show application open/click or crash for Safari/Chrome/Office/Preview/archiver, (2) file write/extraction into ~/Downloads, /private/var/folders/* or ~/Library, (3) parent app spawns osascript/bash/zsh/curl/python or opens a quarantined app with Gatekeeper prompts, (4) network egress from child.
  - *Log sources:* `macos:unifiedlog` (opened document|clicked link|EXC_BAD_ACCESS|abort|LSQuarantine); `fs:fileevents` (create/write/rename in user-writable paths); `macos:osquery` (exec); `NSM:Flow` (new outbound connection from exploited lineage)
  - *Tune:* `TimeWindow` — 10–30 minute correlation window.; `HighRiskChildren` — osascript, bash, zsh, curl, python, open -a Terminal, installer, tccutil misuse.; `QuarantineSignals` — Flag new apps lacking com.apple.quarantine or with quarantine='0081' (downloaded then auto-opened).
- **`AN1317` Analytic 1317** · Containers
  Cause→effect chain in CI/dev desktops: (1) user triggers container run/pull after opening a doc/link/script, (2) newly created image/container uses unexpected external registry or entrypoint, (3) container starts and immediately egresses to suspicious destinations.
  - *Log sources:* `docker:events` (created,started: new container from untrusted registry or unexpected entrypoint); `docker:events` (start); `NSM:Flow` (container egress to unknown IPs/domains)
  - *Tune:* `TrustedRegistries` — Approved registries/namespaces.; `AllowedEntrypoints` — Expected CMD/ENTRYPOINT for known images.; `TimeWindow` — Correlate user action → docker/podman run within 10 minutes.
- **`AN1318` Analytic 1318** · IaaS
  Cause→effect chain in cloud consoles: (1) user clicks link then invokes instance/image creation via API, (2) instance/image originates from external AMI or unknown image, (3) instance immediately egresses or retrieves payloads.
  - *Log sources:* `AWS:CloudTrail` (RunInstances,CreateImage); `AWS:CloudTrail` (StartInstances); `gcp:vpcflow` (first 5m egress to unknown ASNs)
  - *Tune:* `ApprovedImages` — AMI/image allow-list with owners.; `UserContext` — High-risk identities (federated, external IdP).; `TimeWindow` — 5–30 minutes from console/API action to network egress.

---

### T1204.001 — Malicious Link
<a id="t1204001"></a>

**Detection strategy:** User Execution – Malicious Link (click → suspicious egress → download/write → follow-on activity) (`DET0066`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1204.001](https://attack.mitre.org/techniques/T1204/001/) · [detail page](../../techniques/execution.md#t1204001)

- **`AN0178` Analytic 0178** · Windows
  Behavioral chain: (1) a user-facing app (browser/Office/email client) launches a URL or handles a link, then (2) the same process lineage makes an outbound connection to an untrusted domain/IP, (3) a file is downloaded or unpacked to a user-writable location shortly after the click. Optional enrichment: subsequent child execution by LOLBINs.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=11); `NSM:Flow` (Suspicious URL patterns, uncommon TLDs, short-lived domains, URL shorteners; HTTP method GET/POST)
  - *Tune:* `TimeWindow` — Correlation window (e.g., 15m) between link click / first egress / file write.; `BrowserParents` — Processes considered link sources: chrome.exe, msedge.exe, firefox.exe, winword.exe, outlook.exe, teams.exe.; `UserPaths` — User-writable directories to monitor (%USERPROFILE%\Downloads, %TEMP%, %APPDATA%\*, OneDrive caches).; `SuspiciousTLDs` — High-risk TLD and domain list (e.g., .top .xyz .monster; newly observed domains/NOD).; `AllowedCDNs` — Corporate CDNs/update hosts to reduce false positives.
- **`AN0179` Analytic 0179** · Linux
  Behavioral chain: (1) browser/office/GUI mail client opens a URL, (2) outbound connection to untrusted domain, (3) a new file is saved in $HOME/Downloads, /tmp, or cache immediately after.
  - *Log sources:* `auditd:SYSCALL` (execve: Execs of chromium, google-chrome, firefox, libreoffice with http(s) in cmdline); `auditd:SYSCALL` (open,creat,rename: Writes in $HOME/Downloads, /tmp, ~/.cache with exe/script/archive/office extensions); `NSM:Flow` (Suspicious URL patterns, uncommon TLDs, URL shorteners)
  - *Tune:* `TimeWindow` — Typical 10–20m between click and write.; `UserPaths` — $HOME/Downloads, /tmp, ~/.cache, ~/.local/share.; `HighRiskExtensions` — exe, elf, sh, js, py, jar, iso, img, zip, rar, xlsm, docm, xll.; `DomainRiskScore` — Heuristic or TI score threshold for domains.
- **`AN0180` Analytic 0180** · macOS
  Behavioral chain: (1) Safari/Chrome/Firefox/Office handles a URL; unified logs show open/click or LSQuarantine assignment, (2) outbound connection to untrusted domain, (3) a new file appears in ~/Downloads or /private/var/folders/* with quarantine flag.
  - *Log sources:* `macos:unifiedlog` (open URL|clicked link|LSQuarantineAttach); `NSM:Connections` (New outbound connection from Safari/Chrome/Firefox/Word); `fs:fsevents` (Create in /Users/*/Downloads or /private/var/folders/* with quarantine attribute)
  - *Tune:* `TimeWindow` — 10–30m correlation.; `QuarantinePolicy` — Alert when com.apple.quarantine missing on newly downloaded executables.; `SuspiciousTLDs` — Org-specific risky domains/TLDs.

---

### T1204.002 — Malicious File
<a id="t1204002"></a>

**Detection strategy:** User Execution – Malicious File via download/open → spawn chain (T1204.002) (`DET0294`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1204.002](https://attack.mitre.org/techniques/T1204/002/) · [detail page](../../techniques/execution.md#t1204002)

- **`AN0819` Analytic 0819** · Windows
  User opens a file delivered by email, web, chat, or share. The handler application (Word/PDF reader/archiver) creates a file in user-controlled paths (Downloads, Temp, Desktop) and then spawns a new or unusual child process (e.g., powershell.exe, wscript.exe, cmd.exe, regsvr32.exe, rundll32.exe, msiexec.exe). Optional precursors include FileStreamCreated (URL/UNC) and Office → system32 batch writes.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=15)
  - *Tune:* `TimeWindow` — Seconds/minutes to correlate file write to child spawn (e.g., 0–5m).; `SuspiciousExtensions` — Extensions and double-extension patterns to flag (exe,scr,lnk,pif,cpl,js,vbs,bat,cmd,ps1,hta,iso,lnk->cmd,docm,xlsm,pdf->exe, etc.).; `UserPaths` — Paths considered user-controlled (Downloads, Temp, Desktop, profile AppData staging).; `ParentApps` — List of user-facing apps that commonly open attachments for your org (reduce FPs or add weight).; `SignerAllowList` — Trusted code signers/publishers to suppress benign admin tools.
- **`AN0820` Analytic 0820** · macOS
  User opens a downloaded document/installer leading to EndpointSecurity file create in ~/Downloads or ~/Library paths then an exec of a suspicious utility (osascript, bash/zsh, curl, chmod, open with -a Terminal). Correlates File Creation with subsequent process exec and, optionally, quarantine/LSQuarantine events.
  - *Log sources:* `macos:unifiedlog` (process_exec: image in {/bin/bash,/bin/zsh,/usr/bin/osascript,/usr/bin/python*,/usr/bin/curl,/usr/bin/ssh,/usr/bin/open} AND parent in {Preview, TextEdit, Microsoft Word, Microsoft Excel, AdobeReader, Archive Utility, Finder}); `macos:endpointsecurity` (ES_EVENT_TYPE_NOTIFY_CREATE: path under /Users/*/(Downloads|Desktop|Library/*/Containers|Library/Group Containers) AND extension in SuspiciousExtensions)
  - *Tune:* `TimeWindow` — Correlation window between file create and exec (e.g., ≤10m).; `QuarantineRequired` — Require com.apple.quarantine attribute present on the file for higher fidelity.; `ParentApps` — Approved document viewers/editors to anchor lineage.
- **`AN0821` Analytic 0821** · Linux
  User or desktop application writes a new file to ~/Downloads, /tmp, or mounted removable media followed by execve of a risky interpreter/loader (bash, sh, python, perl, php, node, curl|wget piping to sh, ld.so, rdesktop, xdg-open - with unusual args). Uses auditd PATH+SYSCALL (open/creat/write/rename) with execve event linking.
  - *Log sources:* `auditd:SYSCALL` (open/create/rename: name in (/home/*/Downloads/*|/tmp/*|/run/user/*|/media/*) AND ext in SuspiciousExtensions); `auditd:SYSCALL` (execve: exe in {/bin/bash,/bin/sh,/usr/bin/python*,/usr/bin/perl,/usr/bin/php,/usr/bin/node,/usr/bin/curl,/usr/bin/wget,/usr/bin/xdg-open,/usr/bin/ssh,/usr/bin/rundll32 (wine)} AND ppid process is a document viewer/browser)
  - *Tune:* `TimeWindow` — Correlation window for audit events (e.g., ≤5m).; `DesktopParentMap` — Map common desktop apps (libreoffice, evince, firefox, chromium) for lineage anchoring.

---

### T1204.003 — Malicious Image
<a id="t1204003"></a>

**Detection strategy:** User Execution – Malicious Image (containers & IaaS) – pull/run → start → anomalous behavior (T1204.003) (`DET0248`)  
**Platforms:** Linux, Windows  
**ATT&CK:** [T1204.003](https://attack.mitre.org/techniques/T1204/003/) · [detail page](../../techniques/execution.md#t1204003)

- **`AN0691` Analytic 0691** · Linux
  CONTAINERS (Docker/K8s/containerd): A user pulls an untrusted image from a public/unknown registry and then creates/starts a container from that image. Shortly after start, the container spawns unexpected utilities (e.g., curl/wget/bash/python), or makes outbound network connections atypical for the namespace/workload. The analytic correlates Image Creation/Download → Container Creation → Container Start → Command Execution/Network activity within a short window and with a consistent image digest.
  - *Log sources:* `containerd:events` (Image pull from untrusted registry (name NOT IN allowlist) or new digest never seen before); `kubernetes:audit` (create: Pod/Container created with image tag 'latest' or mutable tag; imagePullPolicy=Always; noDigest=true); `kubernetes:events` (start: ContainerStarted or Pulling image → Started container); `auditd:SYSCALL` (execve: Process in container namespace executes curl|wget|bash|sh|python|nc with outbound args); `NSM:Flow` (New egress from container IP/namespace to Internet or non-approved CIDRs/ASNs)
  - *Tune:* `ImageRegistryAllowList` — Approved registries/namespaces (e.g., ECR/GCR/ACR org repos).; `TimeWindow` — Correlation window from image pull to container activity (e.g., ≤15m).; `SuspiciousBinaries` — Executables treated as high-risk when run in app containers (bash, sh, curl, wget, nc, powershell for Windows containers).; `NamespaceScope` — K8s namespaces that should never pull from Internet or run mutable tags.; `OutboundCIDRBlockList` — Destination networks/domains that should not be contacted by containers.
- **`AN0692` Analytic 0692** · Windows
  IAAS (Cloud images/VMs): A new VM/instance is launched from a non-approved or newly-seen image (AMI/GCP Image/Azure Image). On first boot, cloud-init/user-data or embedded agents download code, spawn system utilities, or open outbound C2/mining traffic. The analytic correlates Instance/Image Creation → Instance Start → in-guest Process/Command Execution and/or anomalous network traffic.
  - *Log sources:* `AWS:CloudTrail` (RunInstances); `azure:activity` (Microsoft.Compute/virtualMachines/write: imageReference publisher NOT IN allowlist OR plan is new/unknown); `WinEventLog:Sysmon` (EventCode=1); `NSM:Flow` (New VM egress to crypto-mining pools or non-approved Internet ranges within minutes of boot)
  - *Tune:* `ApprovedImageCatalog` — Set of golden images/owners and digest/IDs allowed to launch.; `UserDataInspection` — Whether to alert when userData/cloud-init contains exec or download directives.; `FirstBootWindow` — Time after start considered first-boot (e.g., ≤30m) for correlation.; `VMTagScope` — Restrict detection to prod or internet-facing subnets to reduce noise.

---

### T1204.004 — Malicious Copy and Paste
<a id="t1204004"></a>

**Detection strategy:** User Execution – Malicious Copy & Paste (browser/email → shell with obfuscated one-liner) – T1204.004 (`DET0340`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1204.004](https://attack.mitre.org/techniques/T1204/004/) · [detail page](../../techniques/execution.md#t1204004)

- **`AN0962` Analytic 0962** · Windows
  A user is socially engineered (web page, email, document) to open Run/PowerShell/CMD and paste an obfuscated one-liner. The chain is: (1) user context active in a browser/email/office app → (2) process creation of a command interpreter with suspicious arguments (base64/Invoke-Expression/web download/pipeline to shell) → (3) optional file drop in %TEMP% or %APPDATA% → (4) outbound network connection to an external domain. Events are correlated within a short window and with consistent user/session.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=3, 22); `NSM:Flow` (HTTP(S) requests with User-Agents typical of PowerShell or curl from desktop; or URIs matching paste-inspired payload hosts)
  - *Tune:* `TimeWindow` — Correlation horizon from parent app (browser/email/office) to interpreter spawn (e.g., 15 minutes).; `ParentProcessAllowList` — Legitimate automation that spawns PowerShell/CMD from Office/Email/Browser.; `SuspiciousArgPatterns` — List of command-line substrings indicating pasted one-liners (e.g., '-enc', 'FromBase64String', 'IEX(', 'DownloadString', 'Invoke-WebRequest', 'curl|wget.*\|\s*(sh|bash|powershell)').; `WritePaths` — Directories treated as risky for first-stage drops (%TEMP%, %APPDATA%, %PUBLIC%).; `OutboundCIDRBlockList` — Internet ranges/domains to alert on for first-run egress.
- **`AN0963` Analytic 0963** · Linux
  User pastes a multi-line or one-liner into a terminal (bash/zsh) that downloads/decodes and executes content. Chain: terminal exec of curl/wget/bash/sh with pipe to interpreter or base64-decode → transient file under /tmp|~/.cache → immediate outbound egress.
  - *Log sources:* `auditd:SYSCALL` (execve: exe in (/usr/bin/bash,/usr/bin/sh,/usr/bin/zsh,/usr/bin/python*) AND cmdline matches '(curl|wget).*(\||\|\s*sh|bash)|base64\s*-d|python\s*-c'); `auditd:SYSCALL` (open: File creation under /tmp, /var/tmp, ~/.cache with executable bit or shell shebang); `NSM:Flow` (New egress to Internet by the same UID/host shortly after terminal exec)
  - *Tune:* `TerminalProcessNames` — Gui/tty terminals to monitor (gnome-terminal, konsole, iTerm2, tmux).; `RiskyFilePaths` — Temp/cache paths to watch for first-stage drops.; `AnomalousUserSet` — Users who should never run curl/wget or compilers.; `TimeWindow` — Exec→file→egress correlation window (e.g., 10 minutes).
- **`AN0964` Analytic 0964** · macOS
  User pastes an obfuscated command into Terminal.app/iTerm2 that decodes or downloads code and executes. Detects Terminal/iTerm2 spawning bash/zsh/python with suspicious pipeline/base64 patterns followed by file writes in ~/Library or /tmp and outbound network connections.
  - *Log sources:* `macos:unifiedlog` (exec: ParentImage in (Terminal, iTerm2) AND Image in (/bin/zsh,/bin/bash,/usr/bin/python*) AND CommandLine matches '(curl|wget).*(\||\|\s*sh|bash)|base64 -D|python -c'); `macos:osquery` (Interpreter exec with suspicious arguments as above); `macos:unifiedlog` (create: New files in /tmp or ~/Library/Application Support/* with executable or script extensions); `NSM:Flow` (Egress to non-approved networks from host after terminal exec)
  - *Tune:* `ParentAppScope` — Terminal apps to treat as user-paste origins (Terminal, iTerm2, VSCode integrated terminal).; `CommandPatternList` — macOS-specific one-liner traits (pbpaste|base64 -D|curl ... | sh).; `AllowListedDevUsers` — Developers/automation accounts expected to run such commands.

---

### T1204.005 — Malicious Library
<a id="t1204005"></a>

**Detection strategy:** User-Initiated Malicious Library Installation via Package Manager (T1204.005) (`DET0252`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1204.005](https://attack.mitre.org/techniques/T1204/005/) · [detail page](../../techniques/execution.md#t1204005)

- **`AN0698` Analytic 0698** · Linux
  User-initiated installation of Python (pip), NodeJS (npm), or other language libraries, followed by unexpected network connections, credential access, or startup file modifications. Defender sees `pip install` or `npm install` commands run by a non-root user, followed shortly by new `.py`, `.sh`, or `.js` files in hidden directories, or interpreter-based execution during boot/login.
  - *Log sources:* `auditd:SYSCALL` (execve: Execution of pip, npm, gem, or similar package managers); `auditd:PATH` (New .py/.js/.sh files written to ~/.local/, ~/.cache/, or /tmp/ within 5 min of package install); `NSM:Flow` (http::request: Network connection to package registry or C2 from interpreter shortly after install)
  - *Tune:* `PackageManagerList` — Monitored package managers (e.g., pip, npm, gem, poetry, conda); `InstallWritePaths` — Directories to watch for post-install execution artifacts (e.g., ~/.local/, /usr/lib/python3.8/site-packages/); `UserContextScope` — Filter to focus on non-system accounts (e.g., interactive shell users); `TimeWindow` — Correlate install command to subsequent network/file activity (default: 5 min)
- **`AN0699` Analytic 0699** · Windows
  Execution of `pip.exe`, `npm.cmd`, or MSI installers within user context, followed by script interpreter startup (e.g., python.exe) or PowerShell with unusual child processes or file writes in `%APPDATA%`, `%TEMP%`, or `%LOCALAPPDATA%`. Defender correlates command-line install tools with Sysmon and Event Logs to trace downstream behavior.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `AllowedParentProcesses` — Filter expected automation tools (e.g., enterprise installers, known IDEs); `InstallPathsToWatch` — Suspicious post-install write paths (e.g., %APPDATA%, %TEMP%); `ExecutableEntropyThreshold` — Used for evaluating if dropped files are packed/obfuscated
- **`AN0700` Analytic 0700** · macOS
  Execution of Homebrew, pip3, npm, or manually downloaded PKGs from Terminal or shell, followed by the creation of startup agents, interpreter spawns, or outbound connections to unfamiliar domains. Defender links Terminal commands to plist creation, unsigned binary launches, and `python3` or `node` processes connecting to remote endpoints.
  - *Log sources:* `macos:unifiedlog` (Command line invocation of pip3, brew install, npm install from interactive Terminal); `macos:unifiedlog` (Creation of new LaunchAgent or LoginItem plist files in ~/Library/LaunchAgents/); `NSM:Flow` (Outbound HTTP/S initiated by newly installed interpreter process)
  - *Tune:* `StartupAgentPaths` — Filter user persistence plist directories like ~/Library/LaunchAgents; `UnsignedBinaryAlerting` — Enable alerting for new binaries lacking Apple or organization signature; `InstallToNetWindow` — Correlate install action to interpreter-based network behavior

---

### T1559 — Inter-Process Communication
<a id="t1559"></a>

**Detection strategy:** Detect Abuse of Inter-Process Communication (T1559) (`DET0493`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1559](https://attack.mitre.org/techniques/T1559/) · [detail page](../../techniques/execution.md#t1559)

- **`AN1357` Analytic 1357** · Windows
  Detects anomalous use of COM, DDE, or named pipes for execution. Correlates creation or access of IPC mechanisms (e.g., named pipes, COM objects) with unusual parent-child process relationships or code injection patterns (e.g., Office spawning cmd.exe via DDE).
  - *Log sources:* `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:Sysmon` (EventCode=17)
  - *Tune:* `PipeNamePattern` — Environment-specific pipe names used legitimately vs anomalous (e.g., \\.\pipe\svcctl).; `AllowedParentChildPairs` — Expected parent-child process lineage to minimize false positives (e.g., explorer.exe spawning outlook.exe).
- **`AN1358` Analytic 1358** · Linux
  Detects abuse of UNIX domain sockets, pipes, or message queues for unauthorized code execution. Correlates unexpected socket creation with suspicious binaries, abnormal shell pipelines, or injected processes establishing IPC channels.
  - *Log sources:* `auditd:SYSCALL` (socket: Suspicious creation of AF_UNIX sockets outside expected daemons); `auditd:SYSCALL` (open: Access to named pipes or FIFO in /tmp or /dev/shm by unexpected processes)
  - *Tune:* `SocketPathBaseline` — Expected UNIX socket paths used by system services and applications.; `FIFOAccessPatterns` — Legitimate processes expected to open pipes in shared directories.
- **`AN1359` Analytic 1359** · macOS
  Detects anomalous use of Mach ports, Apple Events, or XPC services for inter-process execution or code injection. Focuses on unexpected processes attempting to send privileged Apple Events (e.g., automation scripts injecting into security-sensitive apps).
  - *Log sources:* `macos:unifiedlog` (Unusual Mach port registration or access attempts between unrelated processes); `macos:osquery` (exec: Unexpected execution of osascript or AppleScript targeting sensitive apps)
  - *Tune:* `AllowedAppleEventTargets` — Whitelisted app-to-app Apple Event communications (e.g., Finder automation).; `MachPortBaseline` — Baseline of Mach ports and XPC services normally used in the environment.

---

### T1559.001 — Component Object Model
<a id="t1559001"></a>

**Detection strategy:** Detect Abuse of Component Object Model (T1559.001) (`DET0224`)  
**Platforms:** Windows  
**ATT&CK:** [T1559.001](https://attack.mitre.org/techniques/T1559/001/) · [detail page](../../techniques/execution.md#t1559001)

- **`AN0628` Analytic 0628** · Windows
  Detects anomalous use of COM objects for execution, such as Office applications spawning scripting engines, enumeration of COM interfaces via registry queries, or processes loading atypical DLLs through COM activation. Correlates process creation, module loads, and registry queries to flag suspicious COM-based code execution or persistence.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Security` (EventCode=4663, 4670, 4656)
  - *Tune:* `COMObjectAllowList` — Legitimate COM CLSIDs and ProgIDs used by enterprise applications, to reduce false positives.; `ParentProcessExclusions` — Expected parent-child process relationships (e.g., explorer.exe spawning dllhost.exe).; `TimeWindow` — Threshold for correlating COM object execution with subsequent process creation or DLL load.

---

### T1559.002 — Dynamic Data Exchange
<a id="t1559002"></a>

**Detection strategy:** Detect Abuse of Dynamic Data Exchange (T1559.002) (`DET0504`)  
**Platforms:** Windows  
**ATT&CK:** [T1559.002](https://attack.mitre.org/techniques/T1559/002/) · [detail page](../../techniques/execution.md#t1559002)

- **`AN1393` Analytic 1393** · Windows
  Detects anomalous use of Dynamic Data Exchange (DDE) for code execution, such as Office applications (WINWORD.EXE, EXCEL.EXE) spawning command interpreters, or loading unusual modules through DDEAUTO/DDE formulas. Correlates suspicious parent-child process relationships, registry keys enabling DDE, and module loads inconsistent with normal Office usage.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Security` (EventCode=4663, 4670, 4656)
  - *Tune:* `AllowedParentChildPairs` — Define legitimate parent-child relationships for Office processes to reduce false positives.; `TimeWindow` — Threshold for correlating Office process creation with subsequent command execution via DDE.; `SuspiciousDLLList` — Maintain allow/block list of DLLs that Office is expected to load.

---

### T1559.003 — XPC Services
<a id="t1559003"></a>

**Detection strategy:** Detect Abuse of XPC Services (T1559.003) (`DET0335`)  
**Platforms:** macOS  
**ATT&CK:** [T1559.003](https://attack.mitre.org/techniques/T1559/003/) · [detail page](../../techniques/execution.md#t1559003)

- **`AN0948` Analytic 0948** · macOS
  Detects anomalous use of macOS XPC services for code execution. Monitors for processes invoking privileged XPC daemons with abnormal parameters, unexpected binaries communicating over NSXPCConnection, or helper tools executing code outside of their expected parent process lineage. Correlates process access attempts to system-level daemons, privilege escalations via XPC misconfigurations, and injection of malicious payloads through inter-process communication.
  - *Log sources:* `macos:unifiedlog` (Unexpected NSXPCConnection calls by non-Apple-signed or abnormal binaries); `macos:unifiedlog` (execve: Helper tools invoked through XPC executing unexpected binaries); `macos:unifiedlog` (XPC messages requesting privileged actions from untrusted or unsigned clients)
  - *Tune:* `AllowedXPCClients` — Maintain allowlist of binaries permitted to invoke specific XPC services to minimize false positives.; `TimeWindow` — Threshold for correlating abnormal XPC requests with subsequent privilege escalation or process creation.; `UnsignedBinaryAlertLevel` — Adjust sensitivity of alerts for unsigned or non-Apple-signed clients initiating XPC communication.

---

### T1569 — System Services
<a id="t1569"></a>

**Detection strategy:** Detection Strategy for System Services across OS platforms. (`DET0279`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1569](https://attack.mitre.org/techniques/T1569/) · [detail page](../../techniques/execution.md#t1569)

- **`AN0778` Analytic 0778** · Windows
  Monitor for abnormal creation or modification of Windows services (e.g., via sc.exe, PowerShell, or API calls) that load non-standard executables. Correlate registry changes in service keys with service creation events and process execution to detect service abuse for persistence or execution.
  - *Log sources:* `WinEventLog:Security` (EventCode=4697); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=13, 14)
  - *Tune:* `ServiceAllowlist` — Known good services and installers that regularly modify or create services; `TimeWindow` — Threshold for correlating service creation with unusual process execution
- **`AN0779` Analytic 0779** · Linux
  Detect unusual invocations of systemctl, service, or init scripts creating or modifying daemons. Monitor audit logs for execution of binaries from unexpected paths linked to service start/stop activity.
  - *Log sources:* `auditd:SYSCALL` (execve); `linux:syslog` (systemctl start/enable with uncommon binary paths); `auditd:SYSCALL` (write)
  - *Tune:* `ServiceBinaryPaths` — Valid directories for service binaries to filter out benign changes; `UserContext` — Expected accounts performing service management (e.g., root/admin)
- **`AN0780` Analytic 0780** · macOS
  Monitor launchd service definitions and property list (.plist) modifications for non-standard executables. Detect unauthorized processes registered as launch daemons or agents.
  - *Log sources:* `macos:unifiedlog` (Unexpected processes registered with launchd); `macos:unifiedlog` (Modification of LaunchAgents or LaunchDaemons plist files)
  - *Tune:* `PlistAllowlist` — Known launch agents/daemons expected to be modified by updates or IT tools; `PayloadEntropyThreshold` — Entropy level for detecting suspicious binary payloads in launchd services

---

### T1569.001 — Launchctl
<a id="t1569001"></a>

**Detection strategy:** Detection Strategy for System Services: Launchctl (`DET0265`)  
**Platforms:** macOS  
**ATT&CK:** [T1569.001](https://attack.mitre.org/techniques/T1569/001/) · [detail page](../../techniques/execution.md#t1569001)

- **`AN0736` Analytic 0736** · macOS
  Abuse of launchctl to execute or manage Launch Agents and Daemons. Defender perspective: correlation of suspicious plist file creation or modification in LaunchAgents/LaunchDaemons directories with subsequent execution of the launchctl command. Abnormal executable paths (e.g., /tmp, /Shared) or launchctl activity followed by network connections are highly suspicious.
  - *Log sources:* `macos:unifiedlog` (execution of launchctl load/unload/start commands); `macos:unifiedlog` (write of plist files in /Library/LaunchAgents or /Library/LaunchDaemons); `macos:unifiedlog` (launchctl spawning new processes); `macos:unifiedlog` (creation or loading of new launchd services)
  - *Tune:* `MonitoredPaths` — Paths to monitor for suspicious plist files, such as /Library/LaunchAgents, /Library/LaunchDaemons, ~/Library/LaunchAgents.; `SuspiciousExecPaths` — Uncommon executable paths (e.g., /tmp, /Shared) that should raise alerts when associated with launchctl services.; `TimeWindow` — Correlation window for detecting plist file creation and subsequent launchctl execution.

---

### T1569.002 — Service Execution
<a id="t1569002"></a>

**Detection strategy:** Detection Strategy for System Services Service Execution (`DET0421`)  
**Platforms:** Windows  
**ATT&CK:** [T1569.002](https://attack.mitre.org/techniques/T1569/002/) · [detail page](../../techniques/execution.md#t1569002)

- **`AN1185` Analytic 1185** · Windows
  Detection focuses on abnormal service executions initiated via service control manager APIs, sc.exe, net.exe, or PsExec creating temporary services. Defenders observe process creation of services.exe spawning non-standard binaries, registry changes in service keys followed by rapid execution, and network connections originating from processes tied to transient services. Correlation across process lineage, registry activity, and service logs provides strong signals of malicious service execution.
  - *Log sources:* `WinEventLog:Security` (EventCode=4697); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `ServiceBinaryAllowlist` — Known binaries/services expected to be invoked via services.exe; `ParentProcessCorrelationWindow` — Time window for correlating service creation with execution events; `RemoteExecutionHosts` — Approved remote hosts that may trigger service execution (e.g., via PsExec)

---

### T1569.003 — Systemctl
<a id="t1569003"></a>

**Detection strategy:** Detection Strategy for System Services: Systemctl (`DET0073`)  
**Platforms:** Linux  
**ATT&CK:** [T1569.003](https://attack.mitre.org/techniques/T1569/003/) · [detail page](../../techniques/execution.md#t1569003)

- **`AN0200` Analytic 0200** · Linux
  Abuse of systemctl to execute commands or manage systemd services. Defender perspective: correlate suspicious service creation or modification with execution of systemctl subcommands such as start, enable, or status. Detect cases where systemctl is used to load services from unusual locations (e.g., /tmp, /dev/shm) or where new service units are created outside of expected administrative workflows.
  - *Log sources:* `auditd:EXECVE` (execution of systemctl with subcommands start, stop, enable, disable); `auditd:SYSCALL` (open/write of .service unit files); `auditd:EXECVE` (systemctl spawning managed processes); `auditd:CONFIG_CHANGE` (creation or modification of systemd services)
  - *Tune:* `MonitoredPaths` — Paths to monitor for service unit files, typically /etc/systemd/system and /usr/lib/systemd/system. Adversaries may use uncommon locations such as /tmp.; `SuspiciousSubcommands` — Focus on systemctl subcommands start, enable, or daemon-reload when used outside expected change windows.; `CorrelationWindow` — Time window to correlate service file modification with subsequent systemctl execution.

---

### T1609 — Container Administration Command
<a id="t1609"></a>

**Detection strategy:** Detection Strategy for Container Administration Command Abuse (`DET0065`)  
**Platforms:** Containers  
**ATT&CK:** [T1609](https://attack.mitre.org/techniques/T1609/) · [detail page](../../techniques/execution.md#t1609)

- **`AN0177` Analytic 0177** · Containers
  Defenders may detect abuse of container administration commands by observing anomalous use of management utilities (`docker exec`, `kubectl exec`, or API calls to kubelet) correlated with unexpected process creation inside containers. Behavioral chains include unauthorized API requests followed by command execution within running pods or containers, often originating from unusual user accounts, automation scripts, or IP addresses outside the expected cluster management plane.
  - *Log sources:* `docker:daemon` (docker exec or docker run with unexpected command/entrypoint); `kubernetes:apiserver` (kubectl exec or kubelet API calls targeting running pods)
  - *Tune:* `AuthorizedAdminUsers` — Expected admin accounts allowed to use exec commands; anomalies outside this list indicate possible abuse.; `ExecFrequencyThreshold` — Defines how often `docker exec` or `kubectl exec` is normally observed; sudden spikes may indicate adversary behavior.; `SourceIPRange` — Expected IP ranges for management actions (e.g., cluster control plane). Requests from external/unexpected ranges may indicate compromise.; `NamespaceScope` — Defines which namespaces typically allow exec operations; anomalous activity outside these may indicate lateral movement.

---

### T1648 — Serverless Execution
<a id="t1648"></a>

**Detection strategy:** Detection Strategy for Serverless Execution (T1648) (`DET0374`)  
**Platforms:** IaaS, Office Suite, SaaS  
**ATT&CK:** [T1648](https://attack.mitre.org/techniques/T1648/) · [detail page](../../techniques/execution.md#t1648)

- **`AN1053` Analytic 1053** · IaaS
  Correlate creation or modification of serverless functions (e.g., AWS Lambda, GCP Cloud Functions, Azure Functions) with anomalous IAM role assignments or permissions escalation events. Detect subsequent executions of newly created functions that perform unexpected actions such as spawning outbound network connections, accessing sensitive resources, or creating additional credentials.
  - *Log sources:* `AWS:CloudTrail` (CreateFunction / UpdateFunctionConfiguration: Function creation, role assignment, or configuration change events); `AWS:CloudTrail` (InvokeFunction: Unexpected or repeated invocation of functions not tied to known workflows)
  - *Tune:* `RoleScope` — Which IAM roles or privileges are considered sensitive when applied to functions; `AllowedFunctions` — Known baseline list of approved serverless functions to reduce false positives; `TimeWindow` — Temporal threshold for correlating function creation with anomalous execution
- **`AN1054` Analytic 1054** · Office Suite
  Monitor for creation of new Power Automate flows or equivalent automation scripts that trigger on user or file events. Detect anomalous actions performed by these automations, such as email forwarding, anonymous link creation, or unexpected API calls to external endpoints.
  - *Log sources:* `m365:unified` (AddFlow / UpdateFlow: New automation or workflow creation events); `m365:exchange` (New-InboxRule: Automation that triggers abnormal forwarding or external link generation)
  - *Tune:* `UserContext` — Business units or users where automation creation is expected (developers, admins); `FlowActions` — Specific automation actions (email forwarding, file sharing) that should be considered suspicious
- **`AN1055` Analytic 1055** · SaaS
  Track creation or update of SaaS automation scripts (e.g., Google Workspace Apps Script). Detect when these scripts are bound to user events such as file opens or account modifications, and correlate with subsequent abnormal API calls that exfiltrate or modify user data.
  - *Log sources:* `saas:appsscript` (Create / Update: Deployment of scripts with event-driven triggers); `saas:googledrive` (FileOpen / FileAccess: Event-driven script triggering on user file actions)
  - *Tune:* `ScriptScope` — Which SaaS apps or APIs can be legitimately automated in the environment; `TriggerTypes` — Event-driven triggers (e.g., on file open, on user creation) considered suspicious

---

### T1651 — Cloud Administration Command
<a id="t1651"></a>

**Detection strategy:** Detection Strategy for Cloud Administration Command (`DET0545`)  
**Platforms:** IaaS  
**ATT&CK:** [T1651](https://attack.mitre.org/techniques/T1651/) · [detail page](../../techniques/execution.md#t1651)

- **`AN1502` Analytic 1502** · IaaS
  Monitor for suspicious use of cloud-native administrative command services (e.g., AWS Systems Manager Run Command, Azure RunCommand, GCP OS Config) to execute code inside VMs. Detect anomalies such as commands/scripts executed by unexpected users, execution outside of maintenance windows, or commands initiated by service accounts not normally tied to administration. Correlate cloud control-plane activity logs with host-level execution (process creation, script execution) to validate if commands materialized inside the guest OS.
  - *Log sources:* `AWS:CloudTrail` (SendCommand, StartSession, ExecuteCommand: Unexpected AWS Systems Manager command execution targeting EC2 instances); `azure:activity` (Microsoft.Compute/virtualMachines/runCommand/action: Abnormal initiation of Azure RunCommand jobs or PowerShell/Bash payloads); `azure:vmguest` (Unexpected execution of cloud agent processes (e.g., WindowsAzureGuestAgent.exe, ssm-agent) followed by arbitrary script or binary execution)
  - *Tune:* `UserContext` — Differentiate between known admin/service accounts and non-administrative users triggering RunCommand or SSM.; `TimeWindow` — Correlate cloud control-plane API calls with host-side execution events within a bounded timeframe (e.g., 5 minutes).; `AllowedScripts` — Whitelist approved scripts or automation invoked via RunCommand to reduce false positives.

---

### T1674 — Input Injection
<a id="t1674"></a>

**Detection strategy:** Detection Strategy for Input Injection (`DET0568`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1674](https://attack.mitre.org/techniques/T1674/) · [detail page](../../techniques/execution.md#t1674)

- **`AN1567` Analytic 1567** · Windows
  Detects suspicious USB HID device enumeration and keystroke injection patterns, such as rapid sequences of input with no user context, scripts executed through simulated keystrokes, or rogue devices presenting themselves as keyboards.
  - *Log sources:* `WinEventLog:System` (EventCode=2003); `WinEventLog:Security` (EventCode=4688); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106)
  - *Tune:* `AuthorizedUSBDevices` — List of known, legitimate USB vendor/product IDs authorized for use in the enterprise.; `ExecutionTimeWindow` — Restrict detection to times when no user is logged in or activity is outside business hours.; `ParentProcessWhitelist` — List of legitimate parent processes expected to spawn PowerShell or scripting engines.
- **`AN1568` Analytic 1568** · Linux
  Detects USB HID device enumeration under `/sys/bus/usb/devices/` and rapid keystroke injection resulting in command execution such as bash or Python scripts launched without interactive user activity.
  - *Log sources:* `auditd:SYSCALL` (execve: parent process is usb/hid device handler, child process bash/python invoked); `linux:syslog` (New HID device enumeration with type 'keyboard' followed by immediate input injection)
  - *Tune:* `USBVendorIDs` — Track suspicious or unapproved USB vendor/product IDs.; `ScriptExecutionThreshold` — Time threshold for script execution after HID injection, e.g., less than 10 seconds.
- **`AN1569` Analytic 1569** · macOS
  Detects abnormal HID device enumeration via I/O Registry (ioreg -p IOUSB) and keystroke injection targeting AppleScript, osascript, or PowerShell equivalents. Defender correlates new USB device connections with rapid script execution.
  - *Log sources:* `macos:unifiedlog` (New IOUSB keyboard/HID device enumerated with suspicious attributes); `macos:unifiedlog` (osascript, AppleScript, or Python execution triggered immediately after HID connection)
  - *Tune:* `AllowedAppleScripts` — Whitelist of AppleScripts expected in the environment, to minimize false positives.; `TimeWindow` — Timeframe between HID injection and script execution considered suspicious.

---

### T1675 — ESXi Administration Command
<a id="t1675"></a>

**Detection strategy:** Detection Strategy for ESXi Administration Command (`DET0232`)  
**Platforms:** ESXi  
**ATT&CK:** [T1675](https://attack.mitre.org/techniques/T1675/) · [detail page](../../techniques/execution.md#t1675)

- **`AN0646` Analytic 0646** · ESXi
  Detects anomalous usage of ESXi Guest Operations APIs such as StartProgramInGuest, ListProcessesInGuest, ListFileInGuest, or InitiateFileTransferFromGuest. Defender perspective focuses on unusual frequency of guest API calls, invocation from unexpected management accounts, or execution outside of business hours. These correlated signals indicate adversarial abuse of ESXi administrative services to run commands on guest VMs.
  - *Log sources:* `esxi:hostd` (Guest Operations API invocation: StartProgramInGuest, ListProcessesInGuest, ListFileInGuest, InitiateFileTransferFromGuest)
  - *Tune:* `ExpectedAdminUsers` — Whitelist of management accounts authorized to use ESXi Guest Ops APIs.; `TimeWindow` — Business hours during which Guest Ops API usage is expected; activity outside may be suspicious.; `OperationThreshold` — Number of Guest Ops API calls considered anomalous if exceeded in a given timeframe.; `AuthorizedVMs` — List of VMs where Guest Ops usage is permitted; usage on other VMs may indicate malicious activity.

---

### T1677 — Poisoned Pipeline Execution
<a id="t1677"></a>

**Detection strategy:** Detection Strategy for Poisoned Pipeline Execution via SaaS CI/CD Workflows (`DET0533`)  
**Platforms:** SaaS  
**ATT&CK:** [T1677](https://attack.mitre.org/techniques/T1677/) · [detail page](../../techniques/execution.md#t1677)

- **`AN1473` Analytic 1473** · SaaS
  Detects anomalous CI/CD workflow execution originating from forked repositories, with pull request (PR) metadata or commit messages containing suspicious patterns (e.g., encoded payloads), coupled with the use of insecure pipeline triggers like `pull_request_target` or excessive API usage of CI/CD secrets. Correlation with unusual artifact generation or secret exfiltration via encoded or external network destination URLs confirms suspicious behavior.
  - *Log sources:* `saas:github` (Workflow triggered via pull_request_target from forked repo); `saas:github` (CI/CD secret accessed or exported); `saas:github` (Artifact generated includes base64/encoded exfil payload or URL); `saas:RepoEvents` (New file added or modified in PR targeting CI/CD or build config (e.g., `gitlab-ci.yml`, `build.gradle`, `pom.xml`, `.github/workflows/*.yml`)); `saas:PRMetadata` (Commit message or branch name contains encoded strings or payload indicators)
  - *Tune:* `TimeWindow` — Time delta between PR creation and workflow execution to flag rapid attempts; `UserContext` — Forked or external user accounts triggering workflows; may differ across orgs; `TriggerTypeAllowlist` — CI trigger types (e.g., `pull_request_target`) that should or shouldn't be used for forks; `ArtifactEntropyThreshold` — Entropy threshold for detecting encoded payloads in artifacts; `SecretAccessRateThreshold` — Rate of secret access in a single workflow run that might indicate abuse

---

