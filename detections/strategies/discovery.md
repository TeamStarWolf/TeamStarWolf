# Discovery — Detection Strategies

> MITRE ATT&CK detection strategies and analytics (v18.1) for techniques whose primary tactic is **Discovery**. Each analytic lists the **log sources / channels** it needs, the **detection logic**, and the **tunable elements** to adapt it to your environment. Authoritative source: the ATT&CK detection-strategy model in the Enterprise STIX.

See also: [all detection strategies index](/detections/strategies/README.md) · [Technique Detection Library](../TECHNIQUE_DETECTION_LIBRARY.md) (ready-to-run SIEM queries) · [Data Components & Log Sources](../../ATTACK_DATA_COMPONENTS.md) · [Technique Detail Pages](../../techniques/README.md)

---

### T1007 — System Service Discovery
<a id="t1007"></a>

**Detection strategy:** Detection of System Service Discovery Commands Across OS Platforms (`DET0483`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1007](https://attack.mitre.org/techniques/T1007/) · [detail page](../../techniques/discovery.md#t1007)

- **`AN1325` Analytic 1325** · Windows
  Enumeration of services via native CLI tools (e.g., `sc query`, `tasklist /svc`, `net start`) or API calls via PowerShell and WMI.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106)
  - *Tune:* `ProcessName` — Can be tuned to specific binaries used for service enumeration (e.g., `sc.exe`, `tasklist.exe`).; `CommandLineMatch` — Filters for variations like `sc query`, `net start`, `Get-Service`.; `ParentProcess` — Used to suppress known admin scripts or automation jobs.
- **`AN1326` Analytic 1326** · Linux
  Execution of service management commands like `systemctl list-units`, `service --status-all`, or direct reading of `/etc/init.d`.
  - *Log sources:* `auditd:EXECVE` (execve)
  - *Tune:* `CommandPattern` — Includes service enumeration commands like `systemctl`, `service`, or custom scripts.; `ExecutionUser` — Tunable by user context (e.g., root vs. standard user).; `TimeWindow` — Used for correlation with privilege escalation or lateral movement.
- **`AN1327` Analytic 1327** · macOS
  Discovery via launchctl commands, or process enumeration using `ps aux | grep com.apple.` to identify daemons and services.
  - *Log sources:* `macos:unifiedlog`; `macos:osquery` (process_events)
  - *Tune:* `CommandLineContent` — Tune to recognize `launchctl list`, `launchctl print`, or service grep strings.; `ProcessParent` — Filter known benign automation or MDM agent invocations.

---

### T1010 — Application Window Discovery
<a id="t1010"></a>

**Detection strategy:** Detection of Application Window Enumeration via API or Scripting (`DET0097`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1010](https://attack.mitre.org/techniques/T1010/) · [detail page](../../techniques/discovery.md#t1010)

- **`AN0271` Analytic 0271** · Windows
  Processes using Win32 API calls (e.g., EnumWindows, GetForegroundWindow) or scripting tools (e.g., PowerShell, VBScript) to enumerate open windows. These often appear with reconnaissance or data collection TTPs.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106)
  - *Tune:* `AccessedFunction` — Tune to focus on suspicious function calls (e.g., user32.dll!EnumWindows).; `UserContext` — Detect behavior from non-interactive or low-privileged users where enumeration is uncommon.; `TimeWindow` — Shorten detection scope to rapid successive window enumeration attempts.
- **`AN0272` Analytic 0272** · Linux
  Scripted or binary usage of X11 utilities (e.g., xdotool, wmctrl) or direct /proc/*/window mappings to discover open GUI windows and active desktops.
  - *Log sources:* `auditd:EXECVE` (execve); `linus:syslog`
  - *Tune:* `ExecutableName` — Common window management utilities can be tuned to reduce noise (e.g., xprop, xwininfo).; `DisplayContext` — Restrict detection to processes executing under graphical sessions (e.g., DISPLAY=:0).
- **`AN0273` Analytic 0273** · macOS
  Processes that utilize AppleScript, `CGWindowListCopyWindowInfo`, or `NSRunningApplication` APIs to list active application windows and foreground processes.
  - *Log sources:* `macos:unifiedlog`; `macos:osquery` (process_events)
  - *Tune:* `AppleScriptTarget` — Tunable to ignore benign scripting like automation by known apps.; `ParentProcess` — Useful to suppress expected automation processes.

---

### T1012 — Query Registry
<a id="t1012"></a>

**Detection strategy:** Detection of Registry Query for Environmental Discovery (`DET0209`)  
**Platforms:** Windows  
**ATT&CK:** [T1012](https://attack.mitre.org/techniques/T1012/) · [detail page](../../techniques/discovery.md#t1012)

- **`AN0589` Analytic 0589** · Windows
  Registry read access associated with suspicious or non-interactive processes querying system config, installed software, or security settings.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106)
  - *Tune:* `TargetRegistryPath` — Focus detection on registry hives or keys likely to reveal environment info (e.g., HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion).; `ParentProcess` — May tune for suspicious parent processes such as cmd.exe, wscript.exe, or mshta.exe.; `TimeWindow` — Controls how closely registry access must follow process creation for correlation.

---

### T1016 — System Network Configuration Discovery
<a id="t1016"></a>

**Detection strategy:** Behavioral Detection of System Network Configuration Discovery (`DET0195`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1016](https://attack.mitre.org/techniques/T1016/) · [detail page](../../techniques/discovery.md#t1016)

- **`AN0559` Analytic 0559** · Windows
  Execution of built-in tools (e.g., ipconfig, route, netsh) or PowerShell/WMI queries to enumerate IP, MAC, interface status, or routing configuration.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106)
  - *Tune:* `ParentProcess` — Filter known/legit CLI chains (e.g., explorer.exe → cmd.exe) to reduce FP; `UserContext` — Target executions by non-admin or unexpected users; `TimeWindow` — Cluster enumeration commands within short time windows
- **`AN0560` Analytic 0560** · Linux
  Execution of `ifconfig`, `ip a`, or access to `/proc/net/` indicating collection of local interface and route configuration.
  - *Log sources:* `auditd:EXECVE` (execve)
  - *Tune:* `CommandLinePattern` — Match regex for variations in enumeration syntax (e.g., `ip -4 addr show`); `InteractiveShellIndicator` — Differentiate scripted versus interactive sessions
- **`AN0561` Analytic 0561** · macOS
  Execution of `ifconfig`, `networksetup`, or `system_profiler` to query IP/MAC/interface configuration and status.
  - *Log sources:* `macos:unifiedlog` (process)
  - *Tune:* `ScriptedContext` — Scripted tools (e.g., bash calling `ifconfig`) vs GUI-initiated inspection; `ExecutionFrequency` — Enumerations executed frequently or across multiple interfaces may indicate enumeration loops
- **`AN0562` Analytic 0562** · ESXi
  Use of `esxcli network` commands (e.g., `esxcli network nic list`, `esxcli network ip interface ipv4 get`) via SSH or hostd to enumerate adapter and IP information.
  - *Log sources:* `esxi:hostd`
  - *Tune:* `SSHSessionOrigin` — Detection may vary based on internal vs remote terminal usage; `esxcliCommandDepth` — Distinguish between benign status checks and deep enumeration chains
- **`AN0563` Analytic 0563** · Network Devices
  CLI-based execution of interface and routing discovery commands (e.g., `show ip interface`, `show arp`, `show route`) over Telnet, SSH, or console.
  - *Log sources:* `networkdevice:cli`
  - *Tune:* `Username` — Highlight low-privileged or non-routine users performing discovery; `CommandString` — Allow for tuning based on command regex or frequency; `TransportType` — SSH vs Telnet vs Console session logging scope

---

### T1016.001 — Internet Connection Discovery
<a id="t1016001"></a>

**Detection strategy:** Behavioral Detection of Internet Connection Discovery (`DET0357`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1016.001](https://attack.mitre.org/techniques/T1016/001/) · [detail page](../../techniques/discovery.md#t1016001)

- **`AN1015` Analytic 1015** · Windows
  Execution of utilities (e.g., ping, tracert, Test-NetConnection) or scripted methods to test Internet connectivity by interacting with external IPs/domains.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106); `WinEventLog:Security` (EventCode=5156, 5157)
  - *Tune:* `DestinationIP` — Tunable external IP ranges or domains used to verify Internet access (e.g., 8.8.8.8, example.com); `TimeWindow` — Cluster rapid test connections with command execution in < 60 seconds; `UserContext` — Filter out known admin/script contexts to reduce false positives
- **`AN1016` Analytic 1016** · Linux
  Execution of ping, traceroute, or curl/wget against public IPs/domains to verify Internet reachability.
  - *Log sources:* `auditd:EXECVE` (execve); `linux:syslog` (network)
  - *Tune:* `DomainPatterns` — Regex for common test domains like example.com, google.com; `ProtocolType` — Adjust focus to ICMP, HTTP, or mixed protocol testing
- **`AN1017` Analytic 1017** · macOS
  Execution of ping, traceroute, or network utility tools to external destinations; may include `scutil` or system_profiler.
  - *Log sources:* `macos:unifiedlog` (process)
  - *Tune:* `ExecutionFrequency` — Rare use of ICMP utilities may be tuned based on user/host baselines; `EnrichmentLevel` — Tune data joins with parent process and user activity context
- **`AN1018` Analytic 1018** · ESXi
  Execution of `ping`, `vmkping`, or `curl` from shell or through automation jobs/scripts to verify Internet egress.
  - *Log sources:* `esxi:shell`; `esxi:hostd` (process)
  - *Tune:* `SSHSessionOrigin` — Distinguish external SSH sessions from internal admin maintenance; `TargetIP` — Egress test destination may be filtered to known CDNs/test nodes

---

### T1016.002 — Wi-Fi Discovery
<a id="t1016002"></a>

**Detection strategy:** Behavioral Detection of Wi-Fi Discovery Activity (`DET0464`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1016.002](https://attack.mitre.org/techniques/T1016/002/) · [detail page](../../techniques/discovery.md#t1016002)

- **`AN1280` Analytic 1280** · Windows
  Enumeration of saved Wi-Fi profiles and cleartext password retrieval using `netsh wlan` or API-level access to `wlanAPI.dll`.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106)
  - *Tune:* `WiFiProfileName` — Filter by known saved SSID names to reduce benign usage of network diagnostics; `ParentProcess` — Anomalous parent-child relationships may be used to spot abuse (e.g., Office → netsh); `TimeWindow` — Correlate profile enumeration and password dumping within short timeframe (e.g., 60 seconds)
- **`AN1281` Analytic 1281** · Linux
  File access to NetworkManager connection configs and attempts to read PSK credentials from `/etc/NetworkManager/system-connections/*`.
  - *Log sources:* `auditd:PATH` (file read); `auditd:EXECVE` (execve)
  - *Tune:* `FilenamePattern` — Filter for filenames like *.nmconnection or profiles containing SSID names; `UserContext` — Distinguish between root/admin script usage vs. non-privileged terminal access
- **`AN1282` Analytic 1282** · macOS
  Use of the `security` command or Keychain API to extract known Wi-Fi passwords for target SSIDs.
  - *Log sources:* `macos:unifiedlog` (process)
  - *Tune:* `WiFiNetworkFilter` — Match suspicious SSIDs being queried via `security find-generic-password -wa`; `ExecutionUser` — Monitor root/admin usage of credential tools not linked to UI/system processes

---

### T1018 — Remote System Discovery
<a id="t1018"></a>

**Detection strategy:** Detection Strategy for Remote System Enumeration Behavior (`DET0574`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1018](https://attack.mitre.org/techniques/T1018/) · [detail page](../../techniques/discovery.md#t1018)

- **`AN1583` Analytic 1583** · Windows
  Execution of network enumeration utilities (e.g., net.exe, ping.exe, tracert.exe) in short succession, often chained with lateral movement tools or system enumeration commands.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `TimeWindow` — Define bursty execution patterns of enumeration commands (e.g., <30s); `CommandLinePattern` — Tunable per org’s scripting/IT tools (e.g., exclude SCCM, PsExec); `ParentProcess` — Flag suspicious process ancestry (e.g., Word.exe spawning net.exe)
- **`AN1584` Analytic 1584** · Linux
  Use of bash scripts or interactive shells to issue sequential ping, arp, or traceroute commands to map remote hosts.
  - *Log sources:* `auditd:EXECVE` (execve); `linux:syslog` (network)
  - *Tune:* `TargetIPRange` — Tune for sensitive internal segments or known lateral targets; `ShellContext` — Distinguish user-interactive enumeration vs. cronjob or baseline tooling
- **`AN1585` Analytic 1585** · macOS
  Execution of built-in or AppleScript-based system enumeration via `arp`, `netstat`, `ping`, and discovery of `/etc/hosts` contents.
  - *Log sources:* `macos:unifiedlog` (process); `macos:osquery` (file_events)
  - *Tune:* `ExecutionUser` — Limit detection to suspicious users or automation contexts; `CommandSignature` — Adapt for expected enumeration tooling used in IT
- **`AN1586` Analytic 1586** · ESXi
  ESXi shell or SSH access issuing `esxcli network diag ping` or viewing routing tables to identify connected hosts.
  - *Log sources:* `esxi:hostd`
  - *Tune:* `ESXCommandPattern` — Match specific diag/debug commands abused for recon; `RemoteUserShell` — Detect unauthorized shell use or user context (e.g., root over SSH)
- **`AN1587` Analytic 1587** · Network Devices
  Execution of discovery commands like `show cdp neighbors`, `show arp`, and other interface-level introspection on Cisco or Juniper devices.
  - *Log sources:* `networkdevice:syslog` (syslog facility LOCAL7 or trap messages)
  - *Tune:* `CommandList` — Device-specific recon commands to monitor based on make/model; `PrivLevel` — Trigger detection for privilege escalation prior to recon commands

---

### T1033 — System Owner/User Discovery
<a id="t1033"></a>

**Detection strategy:** Behavioral Detection of User Discovery via Local and Remote Enumeration (`DET0093`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1033](https://attack.mitre.org/techniques/T1033/) · [detail page](../../techniques/discovery.md#t1033)

- **`AN0254` Analytic 0254** · Windows
  Adversary launches built-in system tools (e.g., whoami, query user, net user) or scripts that enumerate user account information via local execution or remote API queries (e.g., WMI, PowerShell).
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106)
  - *Tune:* `ParentProcessContext` — Identify if enumeration originates from non-interactive shell or system service; `TimeWindow` — Tune temporal grouping of enumeration + lateral movement attempts; `UserContext` — Flag unexpected users issuing enumeration commands (e.g., service accounts)
- **`AN0255` Analytic 0255** · Linux
  Adversary runs commands like `whoami`, `id`, `w`, or `cat /etc/passwd` from non-interactive or scripting contexts to enumerate system user details.
  - *Log sources:* `auditd:SYSCALL` (execve)
  - *Tune:* `CommandLineRegex` — Tune detection based on argument presence (e.g., `cat /etc/passwd` vs. `cat` alone); `ShellContext` — Identify if command issued via cron, systemd, or reverse shell; `AccessFrequency` — Define how often user/account commands are expected on endpoint
- **`AN0256` Analytic 0256** · macOS
  Adversary uses `dscl`, `who`, or environment variables like `$USER` to identify accounts or sessions via Terminal or malicious LaunchAgents.
  - *Log sources:* `macos:unifiedlog` (subsystem:com.apple.Terminal); `macos:endpointsecurity` (ES_EVENT_TYPE_NOTIFY_EXEC)
  - *Tune:* `LaunchAgentPersistence` — Correlate dscl usage with known persistence vectors; `CommandExecutionPath` — Distinguish between user-initiated terminal vs. script execution; `UsernameEnumerationPattern` — Regex-based pattern tuning for `dscl . -list /Users` + grep filters
- **`AN0257` Analytic 0257** · Network Devices
  Adversary executes CLI commands like `show users`, `show ssh`, or attempts to dump AAA user lists from routers or switches.
  - *Log sources:* `networkdevice:syslog` (aaa privilege_exec); `networkdevice:syslog` (eventlog)
  - *Tune:* `CLICommandBaseline` — Expected command set per device role/user role combination; `DeviceRoleSensitivity` — Correlate access with core vs. edge vs. management plane sensitivity; `CommandFrequencyThreshold` — Detect burst usage of `show` or `debug` commands by non-admin users

---

### T1046 — Network Service Discovery
<a id="t1046"></a>

**Detection strategy:** Behavioral Detection Strategy for Network Service Discovery Across Platforms (`DET0376`)  
**Platforms:** Containers, Linux, Windows, macOS  
**ATT&CK:** [T1046](https://attack.mitre.org/techniques/T1046/) · [detail page](../../techniques/discovery.md#t1046)

- **`AN1057` Analytic 1057** · Windows
  Detects processes performing network enumeration (e.g., port scans, service probing) by correlating process creation, socket connections, and sequential destination IP probing within a time window.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `ScanRateThreshold` — Defines the number of unique destination IPs or ports accessed within a time window that may indicate a scan.; `KnownScannerExeList` — List of binaries allowed to scan or used by IT (e.g., Nmap, Nessus).; `TimeWindow` — Temporal bounds for correlating sequential connections (e.g., 60 seconds).
- **`AN1058` Analytic 1058** · Linux
  Detects use of network scanning utilities or scripts performing rapid connections to multiple services or hosts using auditd and netflow/pcap telemetry.
  - *Log sources:* `auditd:SYSCALL` (execve); `NSM:Flow` (Outbound TCP SYN or UDP to multiple ports/hosts)
  - *Tune:* `PortScanThreshold` — Defines number of ports targeted per host within a short period.; `ToolPatternRegex` — Regex to match common scanner arguments (e.g., `nmap -sS`, `nc -zv`).; `ExpectedScanSources` — Trusted IPs or systems performing routine discovery.
- **`AN1059` Analytic 1059** · macOS
  Detects Bonjour-based mDNS enumeration or use of system tools (e.g., dns-sd, nmap) to find active services via multicast probing or targeted scans.
  - *Log sources:* `macos:unifiedlog` (dns-sd, mDNSResponder, socket activity); `macos:osquery` (process_events)
  - *Tune:* `MDNSServiceQueryPatterns` — mDNS queries such as _ssh._tcp.local that may indicate service discovery.; `UserContext` — Adjust alerting based on whether discovery activity originates from a background daemon vs. interactive session.; `ScanToolList` — Expected tools that could trigger mDNS or TCP/UDP scans (e.g., dns-sd, nmap).
- **`AN1060` Analytic 1060** · Containers
  Detects lateral discovery or container breakout attempts using netcat, curl, or custom binaries probing other services within the same namespace or VPC subnet.
  - *Log sources:* `ebpf:syscalls` (socket connect); `ebpf:syscalls` (execve); `containerd:runtime` (container-level outbound traffic events)
  - *Tune:* `ExecutablePath` — Custom or renamed versions of tools may use different paths; `TimeWindow` — Aggregation interval for identifying anomalous traffic; `NetworkDestinationCount` — Tunable count of unique destinations to classify discovery

---

### T1049 — System Network Connections Discovery
<a id="t1049"></a>

**Detection strategy:** Detection of System Network Connections Discovery Across Platforms (`DET0320`)  
**Platforms:** ESXi, IaaS, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1049](https://attack.mitre.org/techniques/T1049/) · [detail page](../../techniques/discovery.md#t1049)

- **`AN0903` Analytic 0903** · Windows
  Detects usage of commands or binaries (e.g., netstat, PowerShell Get-NetTCPConnection) and WMI or API calls to enumerate local or remote network connections.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106)
  - *Tune:* `SuspiciousParentProcesses` — Non-standard binaries launching PowerShell or netstat (e.g., winword.exe spawning powershell.exe).; `TimeWindow` — Correlates discovery behavior before lateral movement or credential access.; `CommandPatternList` — Regex or keyword patterns to match discovery utilities (e.g., `netstat`, `Get-NetTCPConnection`).
- **`AN0904` Analytic 0904** · Linux
  Detects use of netstat, ss, lsof, or custom shell scripts to list current network connections. Often paired with privilege escalation or staging.
  - *Log sources:* `auditd:SYSCALL` (execve); `linux:cli` (command logging)
  - *Tune:* `UtilityNameList` — List of binaries used for discovery (e.g., netstat, ss, lsof).; `UserContextScope` — Limit detection to non-administrative or service accounts performing enumeration.; `ExecutionFrequencyThreshold` — Unusual number of executions within a short time window.
- **`AN0905` Analytic 0905** · macOS
  Detects shell-based enumeration of active connections using `netstat`, `lsof -i`, or AppleScript-based system discovery.
  - *Log sources:* `macos:osquery` (process_events)
  - *Tune:* `ShellCommandWatchlist` — Matches terminal commands like `lsof -i`, `netstat`, or scripts issued via Automator or AppleScript.; `TerminalBinaryDenylist` — Tracks execution of networking discovery tools by apps outside Terminal.app or iTerm.
- **`AN0906` Analytic 0906** · ESXi
  Detects shell or API usage of `esxcli network ip connection list` or `netstat` to enumerate ESXi host connections.
  - *Log sources:* `esxi:hostd` (command log)
  - *Tune:* `ExecutionOriginCheck` — Detect commands executed outside normal management interfaces (e.g., SSH or root shell).; `ExpectedAdminAccessWindow` — Timeframe when host connection audits are expected (e.g., maintenance windows).
- **`AN0907` Analytic 0907** · Network Devices
  Detects interactive or automated use of CLI commands like `show ip sockets`, `show tcp brief`, or SNMP queries for active sessions on routers/switches.
  - *Log sources:* `networkdevice:cli` (command logs); `snmp:trap` (management queries)
  - *Tune:* `CommandPatternList` — Monitors for known socket/session query strings.; `PrivilegedUserCheck` — Restrict detections to non-admin roles executing advanced queries.
- **`AN0908` Analytic 0908** · IaaS
  Detects enumeration of cloud network interfaces, VPCs, subnets, or peer connections using CLI or SDKs (e.g., AWS CLI, Azure CLI, GCloud CLI).
  - *Log sources:* `AWS:CloudTrail` (Describe* or List* API calls); `azure:activity` (networkInsightsLogs)
  - *Tune:* `ServicePrincipalAllowlist` — Allow certain automation roles to perform discovery during provisioning.; `BurstQueryThreshold` — Unusual number of Describe* or List* network API calls in a short timeframe.

---

### T1057 — Process Discovery
<a id="t1057"></a>

**Detection strategy:** Detection of Adversarial Process Discovery Behavior (`DET0034`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1057](https://attack.mitre.org/techniques/T1057/) · [detail page](../../techniques/discovery.md#t1057)

- **`AN0095` Analytic 0095** · Windows
  Identifies adversary behavior that launches commands or invokes APIs to enumerate active processes (e.g., tasklist.exe, Get-Process, or CreateToolhelp32Snapshot). Detects execution combined with parent process lineage, network session context, or remote origin.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=10)
  - *Tune:* `ParentProcessName` — Used to scope suspicious discovery from non-interactive or non-standard parent processes like Office macros, WMI, or script engines; `CommandLinePattern` — Adversaries may obfuscate or vary process discovery commands (e.g., aliases, PowerShell variants); `TimeWindow` — Helps detect bursty discovery behavior within a short timeframe
- **`AN0096` Analytic 0096** · Linux
  Detects execution of common process enumeration utilities (e.g., ps, top, htop) or access to /proc with suspicious ancestry. Correlates command usage with interactive shell context and user role.
  - *Log sources:* `auditd:SYSCALL` (execve); `auditd:SYSCALL` (openat); `linux:osquery` (Process State)
  - *Tune:* `AccessedPath` — Filter based on suspicious /proc directory enumeration or high-volume ls/readlink usage; `UserContext` — Helps tune for root vs. low-priv users during interactive vs. scripted activity
- **`AN0097` Analytic 0097** · macOS
  Monitors execution of ps, top, or launchctl with unusual parent processes or from terminal scripts. Also detects AppleScript-based process listing or `system_profiler SPApplicationsDataType` misuse.
  - *Log sources:* `macos:unifiedlog` (process launch); `macos:osquery` (Process Context)
  - *Tune:* `ParentApp` — Tunable to detect discovery from non-UI tools or script-based execution (osascript, zsh, cron)
- **`AN0098` Analytic 0098** · ESXi
  Detects process enumeration using `esxcli system process list` or `ps` on ESXi shell or via unauthorized SSH sessions. Correlates with interactive sessions and abnormal user roles.
  - *Log sources:* `esxi:shell` (interactive shell); `esxi:auth` (user session)
  - *Tune:* `User` — Admins are expected to run these commands—flag if non-admin or unknown users do
- **`AN0099` Analytic 0099** · Network Devices
  Monitors CLI-based execution of `show process` or equivalent on routers/switches. Correlates unusual device access, unauthorized roles, or config mode changes.
  - *Log sources:* `networkdevice:cli` (CLI command); `networkdevice:syslog` (Admin activity)
  - *Tune:* `Username` — Tunable based on authorized operators for network infrastructure; `CommandString` — Pattern match or regex scope for discovery commands

---

### T1069 — Permission Groups Discovery
<a id="t1069"></a>

**Detection strategy:** Behavioral Detection of Permission Groups Discovery (`DET0179`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1069](https://attack.mitre.org/techniques/T1069/) · [detail page](../../techniques/discovery.md#t1069)

- **`AN0507` Analytic 0507** · Windows
  Detection of adversary enumeration of domain or local group memberships via native tools such as net.exe, PowerShell, or WMI. This activity may precede lateral movement or privilege escalation.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106)
  - *Tune:* `CommandLineRegex` — Regex filters for matching suspicious group enumeration commands (e.g., 'net group', 'Get-ADGroupMember').; `TimeWindow` — Time threshold for correlating group discovery with subsequent suspicious activity (e.g., lateral movement).; `UserContext` — Whether the user performing discovery is in a sensitive group or running under unusual context (e.g., non-admin querying Domain Admins).
- **`AN0508` Analytic 0508** · Linux
  Detection of group enumeration using commands like 'id', 'groups', or 'getent group', often followed by privilege escalation or SSH lateral movement.
  - *Log sources:* `auditd:SYSCALL` (execve)
  - *Tune:* `CommandLine` — Variations of enumeration commands tailored to different Linux distros (e.g., 'getent group', 'cut -d' in /etc/group parsing).; `TTYSession` — TTY context or source terminal (remote shell vs local login) to reduce noise.
- **`AN0509` Analytic 0509** · macOS
  Group membership checks via 'dscl', 'dscacheutil', or 'id', typically executed via terminal or automation scripts.
  - *Log sources:* `macos:unifiedlog` (process:launch)
  - *Tune:* `CommandLine` — Filters for suspicious execution of 'dscl . -read /Groups', etc.; `ParentProcess` — Flag group enumeration from automation tools (e.g., LaunchAgents or suspicious apps).

---

### T1069.001 — Local Groups
<a id="t1069001"></a>

**Detection strategy:** Behavioral Detection of Local Group Enumeration Across OS Platforms (`DET0114`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1069.001](https://attack.mitre.org/techniques/T1069/001/) · [detail page](../../techniques/discovery.md#t1069001)

- **`AN0317` Analytic 0317** · Windows
  Detects attempts to enumerate local groups via Net.exe, PowerShell, or native API calls that precede lateral movement or privilege abuse.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688)
  - *Tune:* `TimeWindow` — Time window between group enumeration and lateral movement or privilege escalation activity.; `UserContext` — Whether the process was executed by a privileged or low-privilege account.
- **`AN0318` Analytic 0318** · Linux
  Detects enumeration of local groups using common binaries (groups, getent, cat /etc/group) or scripting with suspicious lineage.
  - *Log sources:* `auditd:SYSCALL` (execve)
  - *Tune:* `ProcessName` — Detection tuning for binaries like `groups`, `getent`, `awk`, or `cut` that may be used in pipelines.; `ParentProcess` — Used to determine whether enumeration was triggered by a script or terminal.
- **`AN0319` Analytic 0319** · macOS
  Detects use of dscl or id/group commands to enumerate local system groups, often by post-exploitation tools or persistence checks.
  - *Log sources:* `macos:unifiedlog` (process:exec)
  - *Tune:* `CommandLineContains` — Match on specific dscl paths like '/Groups' or known enumeration options.; `InteractiveSession` — Used to scope out enumeration from user terminals versus background utilities.

---

### T1069.002 — Domain Groups
<a id="t1069002"></a>

**Detection strategy:** Behavioral Detection of Domain Group Discovery (`DET0360`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1069.002](https://attack.mitre.org/techniques/T1069/002/) · [detail page](../../techniques/discovery.md#t1069002)

- **`AN1025` Analytic 1025** · Windows
  Detection of domain group enumeration through command-line utilities such as 'net group /domain' or PowerShell cmdlets, followed by suspicious access to API calls or LSASS memory.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106)
  - *Tune:* `TimeWindow` — Adjustable window to track chained discovery activity (e.g., 5-10 minutes).; `UserContext` — Tune to focus on non-admin users or service accounts performing enumeration.; `ProcessLineageDepth` — How far back the parent-child process chain is correlated.
- **`AN1026` Analytic 1026** · Linux
  Behavioral detection of domain group enumeration via ldapsearch or custom scripts leveraging LDAP over the network.
  - *Log sources:* `auditd:SYSCALL` (execve); `linux:syslog` (sshd logs); `NSM:Flow` (ldap.log)
  - *Tune:* `LDAPQueryDepth` — Tunable based on number of LDAP queries before flagging suspicious behavior.; `CommandPattern` — Pattern matching against common ldapsearch or shell enumeration flags.
- **`AN1027` Analytic 1027** · macOS
  Enumeration of domain groups using dscacheutil or dscl commands, often following initial login or domain trust queries.
  - *Log sources:* `macos:unifiedlog` (process events)
  - *Tune:* `CommandSignatureThreshold` — Defines how strictly command patterns must match known enumeration syntax.; `TimeWindow` — Adjustable window to correlate chained behavior such as group enumeration followed by user targeting.

---

### T1069.003 — Cloud Groups
<a id="t1069003"></a>

**Detection strategy:** Behavioral Detection of Cloud Group Enumeration via API and CLI Access (`DET0251`)  
**Platforms:** IaaS, Office Suite, SaaS  
**ATT&CK:** [T1069.003](https://attack.mitre.org/techniques/T1069/003/) · [detail page](../../techniques/discovery.md#t1069003)

- **`AN0695` Analytic 0695** · IaaS
  Detects adversarial use of cloud-native APIs (e.g., AWS IAM, Azure RBAC, GCP Identity) to enumerate cloud group memberships or policy mappings via unauthorized sessions or scripts.
  - *Log sources:* `AWS:CloudTrail` (ListGroups, ListAttachedRolePolicies)
  - *Tune:* `UserContext` — Scope to anomalous IAM principals or assume-role usage.; `TimeWindow` — Correlate enumeration activity within lateral movement prep windows.
- **`AN0696` Analytic 0696** · Office Suite
  Identifies unauthorized access or enumeration of administrative roles, security groups, or distribution groups via Exchange/SharePoint/Teams APIs or role discovery scripts.
  - *Log sources:* `m365:exchange` (Get-RoleGroup, Get-DistributionGroup); `m365:sharepoint` (Enumerate ACLs/role bindings)
  - *Tune:* `AccessScope` — Adjust based on tenant-level vs. site-level group visibility.; `ScriptExecutionContext` — Detect script-based role listing (e.g., Graph API call chains).
- **`AN0697` Analytic 0697** · SaaS
  Monitors API calls and service-specific logs for enumeration of organizational roles, permissions, and group structure, particularly outside of normal admin behavior baselines.
  - *Log sources:* `saas:salesforce` (GET /services/data/vXX.X/groups)
  - *Tune:* `OrgScope` — Scope to cross-team access or unfamiliar org enumeration.; `RequestRate` — Tuning for excessive group-list API calls.

---

### T1082 — System Information Discovery
<a id="t1082"></a>

**Detection strategy:** System Discovery via Native and Remote Utilities (`DET0525`)  
**Platforms:** ESXi, IaaS, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1082](https://attack.mitre.org/techniques/T1082/) · [detail page](../../techniques/discovery.md#t1082)

- **`AN1452` Analytic 1452** · Windows
  Process creation and command-line execution of native system discovery utilities such as `systeminfo`, `hostname`, `wmic`, or use of PowerShell/WMI for system enumeration.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106)
  - *Tune:* `TimeWindow` — Detect multiple discovery commands executed in short succession.; `UserContext` — Scope alerts to unusual user accounts or service accounts.
- **`AN1453` Analytic 1453** · Linux
  Execution of system enumeration commands such as `uname`, `df`, `uptime`, `hostname`, `lscpu`, and `cat /etc/os-release` through local terminal or scripts.
  - *Log sources:* `auditd:SYSCALL` (execve)
  - *Tune:* `CommandList` — Customize list of commands of interest (e.g., uname, lscpu, etc.); `TerminalSessionID` — Correlate sessions for behavior context.
- **`AN1454` Analytic 1454** · macOS
  Execution of system info utilities like `systemsetup`, `sw_vers`, `uname`, or `sysctl` by terminal or scripted processes.
  - *Log sources:* `macos:unifiedlog` (log show --predicate 'process == <utility>')
  - *Tune:* `ParentProcess` — Determine if script or terminal executed the command.; `FrequencyThreshold` — Number of discovery commands in a short window.
- **`AN1455` Analytic 1455** · ESXi
  Execution of `esxcli system hostname get`, `esxcli system version get`, or `esxcli hardware` commands through SSH or local shell.
  - *Log sources:* `esxi:vmkernel` (/var/log/vmkernel.log)
  - *Tune:* `SessionOrigin` — Track SSH or console-based entry points.; `CommandString` — Customize detection for expected CLI queries.
- **`AN1456` Analytic 1456** · IaaS
  Use of cloud API calls (e.g., AWS EC2 DescribeInstances, Azure VM Inventory) to enumerate system configurations across assets.
  - *Log sources:* `AWS:CloudTrail` (DescribeInstances, GetConsoleOutput, DescribeImages)
  - *Tune:* `IAMRoleContext` — Limit detection to non-standard identities performing these calls.; `APIFrequency` — Identify enumeration sweeps by volume.
- **`AN1457` Analytic 1457** · Network Devices
  Execution of `show version`, `show hardware`, or `show system` commands through CLI via SSH or console.
  - *Log sources:* `networkdevice:syslog` (Privilege-level command execution)
  - *Tune:* `Username` — Highlight unexpected users issuing diagnostic commands.; `CommandList` — Tailor to vendor-specific command syntax.

---

### T1083 — File and Directory Discovery
<a id="t1083"></a>

**Detection strategy:** Recursive Enumeration of Files and Directories Across Privilege Contexts (`DET0370`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1083](https://attack.mitre.org/techniques/T1083/) · [detail page](../../techniques/discovery.md#t1083)

- **`AN1040` Analytic 1040** · Windows
  Execution of file enumeration commands (e.g., 'dir', 'tree') from non-standard processes or unusual user contexts, followed by recursive directory traversal or access to sensitive locations.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `CommandLineRegex` — Allows tuning based on tools/scripts used for enumeration (e.g., tree, dir /s /b); `UserContext` — Scoping for standard vs elevated or service accounts; `TimeWindow` — Defines burst activity over short periods (e.g., >50 directory queries in 30s)
- **`AN1041` Analytic 1041** · Linux
  Use of file enumeration commands (e.g., 'ls', 'find', 'locate') executed by suspicious users or scripts accessing broad file hierarchies or restricted directories.
  - *Log sources:* `auditd:SYSCALL` (execve); `auditd:PATH` (PATH)
  - *Tune:* `FilePathDepth` — Max depth of recursive access to tune noise vs anomaly; `UserContext` — Helpful to exclude known scripts or automation accounts
- **`AN1042` Analytic 1042** · macOS
  Execution of file or directory discovery commands (e.g., 'ls', 'find') from terminal or script-based tooling, especially outside normal user workflows.
  - *Log sources:* `macos:unifiedlog` (log collect --predicate); `fs:fsusage` (Filesystem Call Monitoring)
  - *Tune:* `PredicateScope` — Adjust macOS unified log filter to include/exclude system paths; `TimeWindow` — Tune based on burst access patterns
- **`AN1043` Analytic 1043** · ESXi
  Execution of esxcli commands to enumerate datastore, configuration files, or directory structures by unauthorized or remote users.
  - *Log sources:* `esxi:shell` (Shell Access/Command Execution); `esxi:hostd` (vSphere File API Access)
  - *Tune:* `CLICommandPattern` — Match on esxcli storage|filesystem commands; `AccessSource` — Limit alerting to non-vCenter or remote IPs
- **`AN1044` Analytic 1044** · Network Devices
  Execution of file discovery commands (e.g., 'dir', 'show flash', 'nvram:') from CLI interfaces, especially by unauthorized users or from abnormal source IPs.
  - *Log sources:* `networkdevice:syslog` (CLI Command Logging)
  - *Tune:* `CommandWhitelist` — Filter allowed commands by account or IP; `SessionOrigin` — Tunable to restrict detection to remote terminal or Telnet/SSH

---

### T1087 — Account Discovery
<a id="t1087"></a>

**Detection strategy:** Enumeration of User or Account Information Across Platforms (`DET0587`)  
**Platforms:** ESXi, IaaS, Identity Provider, Linux, Office Suite, SaaS, Windows, macOS  
**ATT&CK:** [T1087](https://attack.mitre.org/techniques/T1087/) · [detail page](../../techniques/discovery.md#t1087)

- **`AN1612` Analytic 1612** · Windows
  Detection of suspicious enumeration of local or domain accounts via command-line tools, WMI, or scripts.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `CommandLinePattern` — Match variations in enumeration commands like 'net user', 'Get-ADUser', 'dsquery'.; `TimeWindow` — Short burst of account enumeration commands may indicate automation.; `UserContext` — Restrict to non-admin accounts or unexpected users executing enumeration commands.
- **`AN1613` Analytic 1613** · Linux
  Enumeration of users and groups through suspicious shell commands or unauthorized access to /etc/passwd or /etc/shadow.
  - *Log sources:* `auditd:SYSCALL` (PATH); `linux:Sysmon` (EventCode=1)
  - *Tune:* `AccessedFile` — Tune based on file paths such as '/etc/passwd', '/etc/group', '/etc/shadow'.; `ParentProcessName` — Filter known admin processes to reduce false positives.
- **`AN1614` Analytic 1614** · macOS
  Detection of user account enumeration through tools like dscl, dscacheutil, or loginshell enumeration via command-line.
  - *Log sources:* `macos:unifiedlog` (process event)
  - *Tune:* `CommandLine` — Tune for dscl -list, dscacheutil -q user, id -un, etc.; `ExecutionContext` — Alert if enumeration is performed in non-console session or by unusual users.
- **`AN1615` Analytic 1615** · IaaS
  Detection of API calls listing users, IAM roles, or groups in cloud environments.
  - *Log sources:* `AWS:CloudTrail` (DescribeUsers / ListUsers / GetUser)
  - *Tune:* `API_Method` — Tune based on which IAM APIs are used and their frequency.; `CallerType` — Differentiate user-initiated from automated/scripted enumeration.
- **`AN1616` Analytic 1616** · Identity Provider
  Enumeration of user or role objects via IdP API endpoints or LDAP queries.
  - *Log sources:* `azure:signinlogs` (Graph API Query); `saas:okta` (User Enumeration Events)
  - *Tune:* `QueryType` — Detect user vs role enumeration. Tune based on query scope.; `AppContext` — Correlate enumeration with unexpected app registrations or identities.
- **`AN1617` Analytic 1617** · ESXi
  Account enumeration via esxcli, vim-cmd, or API calls to vSphere.
  - *Log sources:* `esxi:vpxd` (vCenter Management)
  - *Tune:* `CommandPattern` — Tune based on known enumeration commands: 'vim-cmd vimsvc/auth/userlist'.; `PrivilegedSession` — Elevated enumeration from vpxuser or root may indicate threat activity.
- **`AN1618` Analytic 1618** · SaaS
  Account enumeration via bulk access to user directory features or hidden APIs.
  - *Log sources:* `gcp:audit` (Directory API Access)
  - *Tune:* `EndpointURL` — Tune based on enumeration from directory endpoints such as /users, /groups.; `UserAgent` — Detect scripted enumeration via curl/wget or unknown tools.
- **`AN1619` Analytic 1619** · Office Suite
  Account discovery via VBA macros, COM objects, or embedded scripting.
  - *Log sources:* `m365:unified` (Scripted Activity)
  - *Tune:* `MacroName` — Alert on auto-running macros accessing directory or user info.; `ExecutionScope` — Focus on macros invoking LDAP, ADODB, or WMI queries.

---

### T1087.001 — Local Account
<a id="t1087001"></a>

**Detection strategy:** Local Account Enumeration Across Host Platforms (`DET0303`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1087.001](https://attack.mitre.org/techniques/T1087/001/) · [detail page](../../techniques/discovery.md#t1087001)

- **`AN0846` Analytic 0846** · Windows
  Adversary enumeration of local user accounts using Net.exe, WMI, or PowerShell.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `CommandLinePattern` — Detects variations of 'net user', 'net localgroup', 'Get-LocalUser'.; `UserContext` — Restrict monitoring to low-privileged or unexpected users executing enumeration.; `TimeWindow` — Tune for bursts of enumeration commands in short succession.
- **`AN0847` Analytic 0847** · Linux
  Enumeration of local users or groups via file access (/etc/passwd) or commands like id, groups.
  - *Log sources:* `auditd:PATH` (PATH); `linux:Sysmon` (EventCode=1)
  - *Tune:* `AccessedFile` — Monitors sensitive file access such as '/etc/passwd', '/etc/group'.; `ExecutionScope` — Restrict detection to user-initiated sessions or specific parent processes.
- **`AN0848` Analytic 0848** · macOS
  Enumeration of macOS local users using dscl, id, dscacheutil, or /etc/passwd access.
  - *Log sources:* `macos:unifiedlog`
  - *Tune:* `CommandLine` — Monitor dscl . list /Users, dscacheutil -q user, id -un.; `InteractiveSession` — Focus on enumeration from non-console users or untrusted apps.
- **`AN0849` Analytic 0849** · ESXi
  Enumeration of local ESXi accounts using esxcli or vSphere API from unauthorized sessions.
  - *Log sources:* `vpxd.log` (vCenter Management); `esxi:shell` (Shell Execution)
  - *Tune:* `CommandPattern` — Look for 'esxcli system account list' and API calls from unusual sources.; `SessionType` — Restrict detection to interactive sessions vs. maintenance/automation jobs.

---

### T1087.002 — Domain Account
<a id="t1087002"></a>

**Detection strategy:** Domain Account Enumeration Across Platforms (`DET0129`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/) · [detail page](../../techniques/discovery.md#t1087002)

- **`AN0363` Analytic 0363** · Windows
  Adversary enumeration of domain accounts using net.exe, PowerShell, WMI, or LDAP queries from non-domain controllers or non-admin endpoints.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106); `NSM:Flow` (LDAP Bind/Search)
  - *Tune:* `CommandLinePattern` — Detect variations of 'net user /domain', 'Get-ADUser', 'Get-ADGroupMember'.; `TimeWindow` — Tune detection for bursts of enumeration commands or search queries.; `SourceHost` — Restrict detection to non-DC or non-admin systems where such commands are unexpected.
- **`AN0364` Analytic 0364** · Linux
  Domain account enumeration using ldapsearch, samba tools (e.g., 'wbinfo -u'), or winbindd lookups.
  - *Log sources:* `auditd:SYSCALL` (execve); `linuxsyslog` (nslcd or winbind logs); `NSM:Flow` (LDAP Query)
  - *Tune:* `ProcessName` — Detect suspicious use of ldapsearch, wbinfo, getent passwd, or samba enumeration tools.; `LDAPSearchFilter` — Tune for high-volume or broad-scope LDAP queries.; `UserContext` — Apply filters for unexpected users or service accounts executing the behavior.
- **`AN0365` Analytic 0365** · macOS
  Domain group and user enumeration via dscl or dscacheutil, or queries to directory services from non-admin endpoints.
  - *Log sources:* `macos:unifiedlog` (Process Execution); `macos:unifiedlog` (DS daemon log entries)
  - *Tune:* `CommandPattern` — Match patterns such as 'dscl /Active\ Directory/All\ Domains -list /Users'.; `EndpointRole` — Flag this activity only on non-directory hosts or non-admin accounts.

---

### T1087.003 — Email Account
<a id="t1087003"></a>

**Detection strategy:** Enumeration of Global Address Lists via Email Account Discovery (`DET0229`)  
**Platforms:** Office Suite, Windows  
**ATT&CK:** [T1087.003](https://attack.mitre.org/techniques/T1087/003/) · [detail page](../../techniques/discovery.md#t1087003)

- **`AN0641` Analytic 0641** · Windows
  Enumeration of global address lists or email account metadata via PowerShell cmdlets (e.g., Get-GlobalAddressList) or MAPI/RPC from non-admin, non-mailserver systems.
  - *Log sources:* `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `CommandLinePattern` — Match variations of Get-GlobalAddressList, Get-Recipient, and related cmdlets.; `HostRole` — Suppress expected usage on Exchange servers or known IT admin consoles.; `TimeWindow` — Detect bulk execution patterns in short intervals, often used during recon.
- **`AN0642` Analytic 0642** · Office Suite
  Suspicious querying of organization-wide directory data via Google Workspace Directory API or Outlook GAL sync in high volume from abnormal users, service accounts, or unknown device contexts.
  - *Log sources:* `gcp:audit` (Directory API Access: users.list or groups.list); `m365:unified` (GAL Lookup or Address Book download); `azure:signinlogs` (Unusual Token Usage or Application Consent)
  - *Tune:* `APIQueryVolume` — Set thresholds for excessive use of 'users.list' or recursive group enumerations.; `UserContext` — Flag non-admin or previously unseen user agents requesting directory information.; `AppSource` — Distinguish between sanctioned sync tools and unauthorized scripts or OAuth tokens.

---

### T1087.004 — Cloud Account
<a id="t1087004"></a>

**Detection strategy:** Cloud Account Enumeration via API, CLI, and Scripting Interfaces (`DET0386`)  
**Platforms:** IaaS, Identity Provider, Office Suite, SaaS  
**ATT&CK:** [T1087.004](https://attack.mitre.org/techniques/T1087/004/) · [detail page](../../techniques/discovery.md#t1087004)

- **`AN1087` Analytic 1087** · Identity Provider
  Enumeration of identity roles and users via API calls such as `Get-MsolRoleMember`, `az ad user list`, or Graph API tokens from unauthorized users or automation accounts.
  - *Log sources:* `Microsoft Entra ID Audit Logs` (RoleManagement.Read.Directory or Directory.Read.All); `azure:signinlogs` (Interactive/Non-Interactive Sign-In); `m365:defender` (Activity Log: Command Invocation)
  - *Tune:* `TokenScope` — Flags excessive or abnormal use of directory read scopes by unexpected principals.; `AppContext` — Differentiate authorized automation from rogue access tokens or external tools.; `TimeWindow` — Trigger correlation across short bursts of high-volume enumeration.
- **`AN1088` Analytic 1088** · IaaS
  Use of AWS CLI (`aws iam list-users`, `list-roles`), Azure CLI (`az ad user list`), or GCP CLI (`gcloud iam service-accounts list`) from endpoints or cloud shells where such activity is unexpected.
  - *Log sources:* `AWS:CloudTrail` (AWS IAM: ListUsers, ListRoles); `azure:activity` (Azure CLI Operation: Microsoft.Graph/users/read)
  - *Tune:* `CallerType` — Suppress known admin accounts and alert on developer/test/service identities.; `CLIUserAgent` — Correlate unexpected CLI user-agents and geolocation anomalies.; `CloudRegion` — Suppress noise from known IP ranges or whitelisted accounts per region.
- **`AN1089` Analytic 1089** · Office Suite
  Bulk enumeration of cloud user email identities through `Get-Recipient`, `Get-Mailbox`, `Get-User`, or Graph API directory listings by abnormal accounts or suspicious sessions.
  - *Log sources:* `WinEventLog:PowerShell` (CmdletName: Get-Recipient, Get-User); `Microsoft Graph API Logs` (users.list, directoryObjects.getByIds)
  - *Tune:* `CmdletVolume` — Tune threshold for recipient/mailbox queries by volume per hour.; `UserAgent` — Match known admin consoles and exclude sanctioned tools like MSOL PowerShell.; `SessionContext` — Elevate sessions from unmanaged or external endpoints.
- **`AN1090` Analytic 1090** · SaaS
  Access to organizational directories via Google Workspace Directory API, Slack SCIM, or Okta SCIM by apps or identities outside normal roles.
  - *Log sources:* `Google Admin Audit` (users.list, groups.list); `saas:okta` (System API Call: user.read, group.read)
  - *Tune:* `APIRequestRate` — Detect rapid enumeration attempts or recursive group expansion.; `AppIntegrationID` — Tag expected SCIM clients and suppress false positives from enterprise sync tools.; `GeoContext` — Trigger alerts if enumeration occurs from anomalous IPs or regions.

---

### T1120 — Peripheral Device Discovery
<a id="t1120"></a>

**Detection strategy:** Peripheral Device Enumeration via System Utilities and API Calls (`DET0491`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1120](https://attack.mitre.org/techniques/T1120/) · [detail page](../../techniques/discovery.md#t1120)

- **`AN1353` Analytic 1353** · Windows
  Suspicious enumeration of attached peripherals via WMI, PowerShell, or low-level API calls potentially chained with removable device interactions.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=10)
  - *Tune:* `CommandLineRegex` — Regex patterns for device enumeration utilities (e.g., 'Get-PnpDevice', 'wmic path Win32_USBController'); `TimeWindow` — Time threshold for grouping device discovery with follow-on access or manipulation; `UserContext` — Filter privileged or service accounts known to legitimately execute enumeration scripts
- **`AN1354` Analytic 1354** · Linux
  Enumeration of USB and other peripheral hardware via udevadm, lshw, or /sys or /proc interfaces in proximity to collection or mounting behavior.
  - *Log sources:* `auditd:SYSCALL` (execve); `auditd:SYSCALL` (open/read); `linux:osquery` (hardware_events)
  - *Tune:* `ExecutableList` — Set of binaries used for peripheral enumeration (e.g., 'lshw', 'lsusb', 'udevadm'); `UserContext` — Tuning based on which users/scripts are authorized to query device state
- **`AN1355` Analytic 1355** · macOS
  Execution of system utilities like 'system_profiler' and 'ioreg' to enumerate hardware components or USB devices, particularly if followed by clipboard, file, or network activity.
  - *Log sources:* `macos:unifiedlog` (process exec); `macos:osquery` (usb_devices)
  - *Tune:* `BinaryList` — Commands like 'system_profiler SPUSBDataType', 'ioreg -p IOUSB' that may indicate enumeration; `TimeWindow` — Temporal grouping of enumeration with follow-on activity (e.g., clipboard capture, exfiltration)

---

### T1124 — System Time Discovery
<a id="t1124"></a>

**Detection strategy:** Behavior-chain, platform-aware detection strategy for T1124 System Time Discovery (`DET0151`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1124](https://attack.mitre.org/techniques/T1124/) · [detail page](../../techniques/discovery.md#t1124)

- **`AN0430` Analytic 0430** · Windows
  Untrusted or unusual process/script (cmd.exe, powershell.exe, w32tm.exe, net.exe, custom binaries) queries system time/timezone (e.g., w32tm /tz, net time \\host, Get-TimeZone, GetTickCount API) and (optionally) is followed within a short window by time-based scheduling or conditional execution (e.g., schtasks /create, at.exe, PowerShell Start-Sleep with large values).
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106); `etw:Microsoft-Windows-Kernel-Process` (High-frequency or suspicious sequence of QueryPerformanceCounter/GetTickCount API calls from a non-standard process lineage); `WinEventLog:TaskScheduler` (EventCode=106); `WinEventLog:TaskScheduler` (Task registration/execution shortly after a time discovery event); `EDR:Telemetry` (Process lineage and API usage enrichment (GetSystemTime, GetTimeZoneInformation, NtQuerySystemTime))
  - *Tune:* `TimeWindow` — Correlation window (e.g., 5–15 minutes) between time discovery and follow-on scheduling/conditional actions.; `AllowedParents` — Legitimate parent processes (e.g., corporate scripts, management agents) that frequently call time APIs.; `CommandlineKeywordList` — Extend/restrict keyword list for time queries (e.g., custom PS functions, .NET calls).; `UserContextScope` — Restrict to non-service, non-administrative, or newly created/rare users.; `ProcessPrevalenceThreshold` — Frequency threshold to exclude common estate-wide benign usage.
- **`AN0431` Analytic 0431** · Linux
  A process (often spawned by a shell, interpreter, or malware implant) executes time discovery via commands (date, timedatectl, hwclock, cat /etc/timezone, /proc/uptime) or direct syscalls (time(), clock_gettime) and is (optionally) followed by scheduled task creation/modification (crontab, at) or conditional sleep logic.
  - *Log sources:* `auditd:SYSCALL` (type=EXECVE or SYSCALL for /bin/date, /usr/bin/timedatectl, /sbin/hwclock, /bin/cat /etc/timezone, /bin/cat /proc/uptime); `auditd:SYSCALL` (Rules capturing clock_gettime, time, gettimeofday syscalls when enabled); `linux:syslog` (sudo/date/timedatectl execution by non-standard users); `linux:cron` (cron activity)
  - *Tune:* `AuditRulesSyscalls` — Scope of syscalls (time, clock_gettime, gettimeofday) monitored; may be performance-sensitive.; `AllowedBinaries` — List of legitimate automation/orchestration tools frequently querying time.; `TimeWindow` — Correlation window (e.g., 5–20 minutes) to link time discovery to follow-on cron/at changes.; `UserContextScope` — Ignore root-owned maintenance agents if desired; focus on interactive or newly created users.
- **`AN0432` Analytic 0432** · macOS
  Process/script execution of systemsetup -gettimezone, date, ioreg, or API usage (timeIntervalSinceNow, gettimeofday) followed by time-based scheduling (launchd plist modification) or sleep-based execution.
  - *Log sources:* `macos:unifiedlog` (process exec events of systemsetup, date, ioreg with command_line parameters indicating time discovery); `macos:unifiedlog` (New/modified launchd plist (persistence/scheduling) within TimeWindow after time query)
  - *Tune:* `LaunchdPaths` — Organization-specific list of allowed launchd write locations to filter benign agents.; `TimeWindow` — Correlation window to link time discovery to launchd persistence/scheduling.; `AllowedCallers` — Known management agents (e.g., JAMF) that legitimately call systemsetup/date.
- **`AN0433` Analytic 0433** · ESXi
  Interactive or remote shell/API invocation of esxcli system clock get or querying time parameters via hostd/vpxa shortly followed by time/ntp configuration checks or scheduled task creation, executed by non-standard accounts or outside maintenance windows.
  - *Log sources:* `esxi:shell` (/var/log/shell.log entries containing "esxcli system clock get"); `esxi:hostd` (/var/log/hostd.log API calls reading/altering time/ntp settings); `esxi:syslog` (/var/log/vpxa.log task invocations tied to time configuration)
  - *Tune:* `MaintenanceWindow` — Only alert if outside approved ops windows.; `PrivilegedAccountsAllowList` — Suppress alerts for known service accounts.; `RemoteIPAllowList` — Whitelist management station IPs.; `TimeWindow` — Correlation between esxcli time query and subsequent hostd/vpxa config calls.
- **`AN0434` Analytic 0434** · Network Devices
  Non-standard or rare users/locations issue CLI commands like "show clock detail" or "show timezone"; optionally followed by configuration of time/timezone or NTP sources. AAA/TACACS+ accounting and syslog correlate execution to identity, source IP, and privilege level.
  - *Log sources:* `networkdevice:syslog` (command-exec: CLI commands containing "show clock", "show clock detail", "show timezone" executed by suspicious user/source); `networkdevice:config` (config-change: timezone or ntp server configuration change after a time query command)
  - *Tune:* `AllowedAdminSubnets` — Only alert on access from outside the NOC/management subnets.; `KnownMaintenanceUsers` — Whitelist known automation/orchestration accounts.; `TimeWindow` — Correlation window between time query and config change.

---

### T1135 — Network Share Discovery
<a id="t1135"></a>

**Detection strategy:** Behavior-chain detection for T1135 Network Share Discovery across Windows, Linux, and macOS (`DET0182`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1135](https://attack.mitre.org/techniques/T1135/) · [detail page](../../techniques/discovery.md#t1135)

- **`AN0513` Analytic 0513** · Windows
  Process or script enumerates network shares via CLI (net view/net share, PowerShell Get-SmbShare/WMI) or OS APIs (NetShareEnum/ srvsvc.NetShareEnumAll RPC) → bursts of outbound SMB/RPC connections (445/139, \\host\IPC$ / srvsvc) to many hosts inside a short window → optional follow-on file listing or copy operations.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=17); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106); `etw:Microsoft-Windows-RPC` (rpc_call: srvsvc.NetShareEnum / NetShareEnumAll from non-admin or unusual processes)
  - *Tune:* `BurstHostThreshold` — Minimum number of unique destination hosts over SMB within TimeWindow to treat as scanning (e.g., ≥5).; `TimeWindow` — Correlation window between the discovery process start and SMB fan-out (default 10m).; `AllowedDiscoveryAccounts` — Service/admin accounts legitimately running inventory scripts.; `PipeNameAllowList` — Pipes (e.g., \PIPE\spoolss) normally accessed by management agents; exclude from alerts.
- **`AN0514` Analytic 0514** · Linux
  CLI tools (smbclient -L, smbmap, rpcclient, nmblookup) or custom scripts enumerate SMB shares on many internal hosts → corresponding SMB connections (445/139) captured by Zeek/Netflow within a short window.
  - *Log sources:* `auditd:SYSCALL` (execve of smbclient, smbmap, rpcclient, nmblookup, crackmapexec smb); `NSM:Flow` (connection: TCP connections to ports 139/445 to multiple hosts); `NSM:Flow` (smb_command: TreeConnectAndX to \\*\IPC$ / srvsvc or Trans2/NT_CREATE for listing shares)
  - *Tune:* `BurstHostThreshold` — Minimum unique hosts to flag (e.g., ≥5).; `TimeWindow` — Correlation window between tool exec and SMB fan-out (default 10m).; `ApprovedInventoryHosts` — IPs of vulnerability scanners or config mgmt systems.
- **`AN0515` Analytic 0515** · macOS
  Use of native/mac tools (sharing -l, smbutil view, mount_smbfs) or scripts to enumerate SMB shares across many hosts, followed by outbound SMB connections observed in PF/Zeek logs.
  - *Log sources:* `macos:endpointsecurity` (ES_EVENT_TYPE_NOTIFY_EXEC: Process execution of "sharing -l", "smbutil view", "mount_smbfs"); `macos:unifiedlog` (Command line contains smbutil view //, mount_smbfs //); `NSM:Firewall` (Outbound connections to 139/445 to multiple destinations); `NSM:Flow` (connection: SMB connections to multiple internal hosts)
  - *Tune:* `BurstHostThreshold` — Minimum unique SMB destinations (e.g., ≥3–5 in smaller mac fleets).; `TimeWindow` — Correlation window between exec and SMB connections (default 10m).; `AllowedMgmtTools` — Jamf/IT scripts legitimately running smbutil/mount_smbfs.

---

### T1201 — Password Policy Discovery
<a id="t1201"></a>

**Detection strategy:** Password Policy Discovery – cross-platform behavior-chain analytics (`DET0161`)  
**Platforms:** IaaS, Identity Provider, Linux, Network Devices, SaaS, Windows, macOS  
**ATT&CK:** [T1201](https://attack.mitre.org/techniques/T1201/) · [detail page](../../techniques/discovery.md#t1201)

- **`AN0455` Analytic 0455** · Windows
  Cause→effect chain: (1) a user or service spawns a shell/PowerShell that queries local/domain password policy via commands/cmdlets (e.g., `net accounts`, `Get-ADDefaultDomainPasswordPolicy`, `secedit /export`); (2) optional directory/LDAP reads from DCs; (3) same principal performs adjacent Discovery or credential-related actions within a short window. Correlate sysmon process creation with PowerShell ScriptBlock and Security logs.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106); `WinEventLog:Security` (EventCode=4662)
  - *Tune:* `TimeWindow` — Correlation window between policy query and adjacent suspicious activity (e.g., 15–30 minutes).; `PrivilegedUserAllowList` — Accounts (e.g., Helpdesk) allowed to run policy queries routinely.; `HostRoleScope` — Limit alerts on DCs/management servers; raise on user workstations/VDI.; `PS_ScriptBlockPatterns` — Cmdlet/function names to treat as high-signal in your environment.
- **`AN0456` Analytic 0456** · Linux
  Chain: (1) interactive/non-interactive `chage -l`, `grep`/`cat` of PAM config (e.g., `/etc/pam.d/common-password`, `/etc/security/pwquality.conf`); (2) optional reads of `/etc/login.defs`; (3) same user performs account enumeration or password change attempts shortly after. Use auditd `execve` and file read events plus shell history collection.
  - *Log sources:* `auditd:SYSCALL` (execve); `auditd:SYSCALL` (open,openat,read); `linux:syslog` (sudo chage|grep pam_pwquality|cat /etc/login.defs)
  - *Tune:* `MonitoredPaths` — Exact PAM/QoP config files used by your distro (Debian vs. RHEL paths differ).; `ServiceAccountsExclude` — System daemons that legitimately parse policies on boot.; `TerminalType` — TTY vs. non-interactive—raise risk for non-interactive remote execution.
- **`AN0457` Analytic 0457** · macOS
  Chain: (1) execution of `pwpolicy` or MDM/DirectoryService reads of account policies; (2) optional read of `/Library/Preferences/com.apple.loginwindow` or config profiles; (3) follow-on credential probing or lateral movement by same user/session. Use unified logs and process telemetry.
  - *Log sources:* `macos:unifiedlog` (pwpolicy|PasswordPolicy); `macos:unifiedlog` (exec /usr/bin/pwpolicy); `macos:MDM` (profiles -P|getaccountpolicies)
  - *Tune:* `MDMProfileIDs` — Approved profiles reading/updating auth policies.; `AdminConsoleHosts` — Jamf or management hosts where queries are expected.
- **`AN0458` Analytic 0458** · IaaS
  Chain: (1) cloud API calls that fetch tenant/organization password policy (e.g., AWS `GetAccountPasswordPolicy`, GCP/OCI equivalents or IAM settings reads); (2) within a short window, the same principal creates users, rotates creds, or changes auth settings. Use cloud audit logs.
  - *Log sources:* `AWS:CloudTrail` (GetAccountPasswordPolicy)
  - *Tune:* `CloudReadOnlyApps` — Approved security tooling principals that routinely read policy.; `ApiClientIPAllowList` — Corporate egress IPs for administrative API access.
- **`AN0459` Analytic 0459** · Identity Provider
  Chain: (1) IdP policy/read operations by a principal (e.g., Microsoft Entra/Graph requests to read password or authentication policies); (2) adjacent risky changes (role assignment, app consent) by same principal. Use IdP audit logs.
  - *Log sources:* `azure:audit` (operation contains 'Get*Password*Policy' OR 'List*Authentication*Policy' OR 'Get-ADDefaultDomainPasswordPolicy')
  - *Tune:* `TrustedPartnerAppIds` — Legitimate partner apps that enumerate policies.; `GeoRiskTolerance` — Raise risk for unusual geo or TOR/VPN egress.
- **`AN0460` Analytic 0460** · SaaS
  Chain: (1) SaaS admin API or PowerShell remote session reads tenant password/authentication settings (e.g., M365 Unified Audit Log ‘Cmdlet’ with `Get-MsolPasswordPolicy`/`Get-OrganizationConfig` parameters that expose password settings); (2) same session proceeds to mailbox or tenant changes.
  - *Log sources:* `m365:unified` (Workload=AzureActiveDirectory OR Exchange AND (Operation=Cmdlet AND Parameters contains 'Password' AND (CmdletName='Get-*' OR CmdletName='Get-OrganizationConfig')))
  - *Tune:* `SaaSAdminGroup` — Known admin groups or break-glass accounts.; `SessionAnomalyThreshold` — Rate/volume of read operations per session considered anomalous.
- **`AN0461` Analytic 0461** · Network Devices
  Chain: (1) privileged CLI sessions run read-only commands that dump AAA/password policies (e.g., `show aaa`, `show password-policy`); (2) same account changes AAA or user DB shortly after. Use network device AAA/command accounting or syslog.
  - *Log sources:* `networkdevice:syslog` (cmd='show aaa*' OR 'show running-config | include password|aaa' OR 'show aaa common-criteria policy all')
  - *Tune:* `ApprovedNOCSources` — Jump hosts permitted to run show commands.; `DeviceTier` — Higher risk weight on edge/critical devices.

---

### T1217 — Browser Information Discovery
<a id="t1217"></a>

**Detection strategy:** Detection of Local Browser Artifact Access for Reconnaissance (`DET0013`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1217](https://attack.mitre.org/techniques/T1217/) · [detail page](../../techniques/discovery.md#t1217)

- **`AN0037` Analytic 0037** · Windows
  Access to browser artifact locations (e.g., Chrome, Edge, Firefox) by processes like PowerShell, cmd.exe, or unknown tools, followed by file reads, decoding, or export operations indicating enumeration of bookmarks, autofill, or history databases.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106)
  - *Tune:* `TargetPathRegex` — Location of browser data folders like %APPDATA%\Google\Chrome\User Data or %APPDATA%\Mozilla\Firefox; `ParentProcess` — Used to exclude known browser maintenance or backup processes; `ScriptBlockPattern` — Used to detect suspicious PowerShell commands targeting browser data
- **`AN0038` Analytic 0038** · Linux
  Unauthorized shell or script-based access to browser config or SQLite history files, typically in ~/.config/google-chrome/, ~/.mozilla/, or ~/.var/app folders, indicating enumeration of bookmarks or saved credentials.
  - *Log sources:* `auditd:SYSCALL` (open, read, or stat of browser config files); `linux:syslog` (Suspicious script or command execution targeting browser folders)
  - *Tune:* `BrowserProfilePath` — User-specific browser data folders, e.g., ~/.config/chromium/Default/History; `ShellRegex` — Shell pattern detecting suspicious access to .sqlite or .json files
- **`AN0039` Analytic 0039** · macOS
  Scripting or CLI tool access to ~/Library/Application Support/Google/Chrome or ~/Library/Safari bookmarks, cookies, or history databases. Detection relies on unexpected processes accessing or reading from these locations.
  - *Log sources:* `macos:unifiedlog` (Access to ~/Library/*/Safari or Chrome directories by non-browser processes); `macos:osquery` (process reading browser configuration paths)
  - *Tune:* `BrowserDBPath` — System-specific paths to browser databases in user Library folders; `NonBrowserProcessList` — Processes not expected to touch browser DBs (e.g., curl, bash, python)

---

### T1482 — Domain Trust Discovery
<a id="t1482"></a>

**Detection strategy:** Detection of Domain Trust Discovery via API, Script, and CLI Enumeration (`DET0007`)  
**Platforms:** Windows  
**ATT&CK:** [T1482](https://attack.mitre.org/techniques/T1482/) · [detail page](../../techniques/discovery.md#t1482)

- **`AN0016` Analytic 0016** · Windows
  Adversary uses nltest, PowerShell, or Win32/.NET API to enumerate domain trust relationships (via DSEnumerateDomainTrusts, GetAllTrustRelationships, or LDAP queries), followed by discovery or authentication staging.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:PowerShell` (Get-ADTrust|GetAllTrustRelationships); `WinEventLog:Security` (EventCode=4662)
  - *Tune:* `ParentImage` — Tune based on expected script hosts or authorized administrators invoking trust enumeration.; `TimeWindow` — Correlate enumeration + subsequent Kerberos activity or DC interaction within a bounded window.; `UserContext` — Prioritize detection for non-admin or unexpected user accounts performing enumeration.; `API_Name` — Flag uncommon or low-prevalence API calls like DSEnumerateDomainTrusts for inspection.

---

### T1518 — Software Discovery
<a id="t1518"></a>

**Detection strategy:** Multi-Platform Software Discovery Behavior Chain (`DET0392`)  
**Platforms:** ESXi, IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1518](https://attack.mitre.org/techniques/T1518/) · [detail page](../../techniques/discovery.md#t1518)

- **`AN1100` Analytic 1100** · Windows
  Adversary spawns a process or script to enumerate installed software using WMI, registry, or PowerShell, potentially followed by additional discovery or evasion behavior.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:PowerShell` (Execution of 'Get-WmiObject Win32_Product' or similar PowerShell cmdlets)
  - *Tune:* `TimeWindow` — Detection may be scoped to multiple discovery commands within a short timeframe.; `ParentProcess` — Tuning based on whether discovery activity stems from suspicious versus approved management tools.
- **`AN1101` Analytic 1101** · Linux
  Adversary invokes 'dpkg -l', 'rpm -qa', or other package managers via shell or script to enumerate installed software.
  - *Log sources:* `auditd:SYSCALL` (Execution of dpkg, rpm, or other package manager with list flag); `linux:shell` (Manual invocation of software enumeration commands via interactive shell)
  - *Tune:* `ScriptName` — Path to the wrapper script that invokes enumeration commands.; `TTYContext` — Scope detection to interactive vs. background shell contexts.
- **`AN1102` Analytic 1102** · macOS
  Adversary runs 'system_profiler SPApplicationsDataType' or queries plist files to enumerate software via Terminal or scripts.
  - *Log sources:* `macos:unifiedlog` (Execution of system_profiler or osascript invoking enumeration); `auditd:SYSCALL` (Command line arguments including SPApplicationsDataType)
  - *Tune:* `AppScope` — Whether enumeration targets user apps or system apps.; `ProcessGroup` — Parent process or scripting environment (e.g., Python, osascript).
- **`AN1103` Analytic 1103** · IaaS
  Adversary uses cloud-native APIs or CLI (e.g., AWS Systems Manager, Azure Resource Graph) to list installed software on cloud workloads.
  - *Log sources:* `AWS:CloudTrail` (ssm:ListInventoryEntries); `AWS:CloudTrail` (ssm:GetCommandInvocation)
  - *Tune:* `UserAgent` — Differentiate access from automated scripts vs. authorized console.; `InventoryType` — May focus on Application or Platform inventory only.
- **`AN1104` Analytic 1104** · ESXi
  Adversary uses 'esxcli software vib list' to enumerate installed VIBs, drivers, and modules.
  - *Log sources:* `esxi:shell` (esxcli software vib list); `esxi:hostd` (Host daemon command log entries related to vib enumeration)
  - *Tune:* `HostAccessMode` — Detection may vary based on whether enumeration is local or remote.; `ScriptChain` — Presence of enumeration in broader scripted sequence.

---

### T1518.001 — Security Software Discovery
<a id="t1518001"></a>

**Detection strategy:** Security Software Discovery Across Platforms (`DET0016`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1518.001](https://attack.mitre.org/techniques/T1518/001/) · [detail page](../../techniques/discovery.md#t1518001)

- **`AN0048` Analytic 0048** · Windows
  Adversary executes commands to enumerate installed antivirus, EDR, or firewall agents using WMI, registry queries, and built-in tools (e.g., tasklist, netsh, sc query). Correlated with elevated process privileges or scripting engine usage.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `ParentProcess` — Defenders can tune based on trusted or known-good parent process relationships; `ImagePathContains` — Regex match on adversary tool or enumeration script used
- **`AN0049` Analytic 0049** · Linux
  Adversary runs discovery commands such as `ps aux`, `systemctl status`, or `cat /etc/init.d/` to enumerate security software or services. Often occurs alongside privilege escalation or bash script execution.
  - *Log sources:* `auditd:SYSCALL` (execve)
  - *Tune:* `ExecutableName` — Adjust for custom script names or wrappers used in the environment; `TimeWindow` — Tuning threshold for multiple enumeration commands within short duration
- **`AN0050` Analytic 0050** · macOS
  Adversary attempts to detect monitoring agents such as Little Snitch, KnockKnock, or other system daemons via process listing (`ps -e`), application folder checks, and system extension listing.
  - *Log sources:* `macos:unifiedlog` (execution of security-agent detection or enumeration commands); `auditd:SYSCALL` (execve)
  - *Tune:* `ToolNameMatch` — Adversary may search for specific software names; defenders can tune based on local deployments

---

### T1518.002 — Backup Software Discovery
<a id="t1518002"></a>

**Detection strategy:** Backup Software Discovery via CLI, Registry, and Process Inspection (T1518.002) (`DET0088`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1518.002](https://attack.mitre.org/techniques/T1518/002/) · [detail page](../../techniques/discovery.md#t1518002)

- **`AN0240` Analytic 0240** · Windows
  Defender observes execution of commands like `tasklist`, `sc query`, `reg query`, or PowerShell WMI/Registry queries targeting known backup products (e.g., Veeam, Acronis, CrashPlan). Behavior often includes parent-child lineage involving PowerShell or cmd.exe with discovery syntax, and enumeration of services, directories, or registry paths tied to backup software.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `KnownBackupVendors` — List of software vendors to match in command-line or registry queries; `UserContextScope` — Focus on low-privilege or interactive user contexts rather than service accounts; `SuspiciousParentProcesses` — Flag execution from scripting tools, interpreters, or LOLBins
- **`AN0241` Analytic 0241** · Linux
  Defender observes use of CLI tools (`find`, `grep`, `ls`, `dpkg`, `rpm`, `systemctl`, `ps aux`) to discover backup agents or config files (e.g., rsnapshot, duplicity, veeam). This often includes command lines that recursively search `/etc/`, `/opt/`, or `/var/` directories for keywords like `backup`, and parent-child relationships involving shell or Python scripts.
  - *Log sources:* `auditd:SYSCALL` (execve: Execution of discovery commands targeting backup binaries, processes, or config paths); `auditd:PATH` (Read access to known backup software configuration files (e.g., /etc/rsnapshot.conf, /opt/veeam/config.ini))
  - *Tune:* `BackupConfigPaths` — Directory paths and filenames related to backup agents; `ToolchainScope` — Shells, interpreters, or binaries used by attacker scripts for discovery
- **`AN0242` Analytic 0242** · macOS
  Defender detects execution of `mdfind`, `launchctl`, or GUI-based enumeration (e.g., `/Applications/Time Machine.app`) along with command-line usage of `find`, `grep`, or `system_profiler` to identify installed backup tools like Time Machine, Carbon Copy Cloner, or Backblaze. Often triggered from Terminal sessions or within post-exploitation scripts.
  - *Log sources:* `macos:unifiedlog` (Process execution logs showing discovery commands like mdfind, system_profiler, or launchctl list); `macos:unifiedlog` (Read access to Time Machine plist files or CCC configurations in ~/Library/Preferences/)
  - *Tune:* `InstallLocationScope` — Directories or bundles where backup tools are commonly installed; `KnownAppPlistPaths` — Plist files related to backup software configurations

---

### T1526 — Cloud Service Discovery
<a id="t1526"></a>

**Detection strategy:** Detection Strategy for Cloud Service Discovery (`DET0402`)  
**Platforms:** IaaS, Identity Provider, Office Suite, SaaS  
**ATT&CK:** [T1526](https://attack.mitre.org/techniques/T1526/) · [detail page](../../techniques/discovery.md#t1526)

- **`AN1127` Analytic 1127** · IaaS
  Unusual enumeration of services and resources through cloud APIs such as AWS CLI `describe-*`, Azure Resource Manager queries, or GCP project listings. Defender perspective includes anomalous API calls, unexpected volume of service enumeration, and correlation of discovery with recently compromised sessions.
  - *Log sources:* `AWS:CloudTrail` (DescribeInstances, DescribeServices, ListFunctions: High frequency enumeration calls or unusual user agents performing discovery); `AWS:CloudTrail` (AssumeRole: Discovery actions tied to assumed identities outside of normal context)
  - *Tune:* `EnumerationRateThreshold` — Rate of API calls used to enumerate services; tuned to reduce noise from automated inventory tools.; `UserAgentFilter` — Expected user agents for cloud management tools; deviations may indicate adversarial tools.
- **`AN1128` Analytic 1128** · Identity Provider
  Enumeration of directories, applications, or service principals through APIs such as Microsoft Graph or Okta API. Defender perspective includes unexpected listing of users, roles, applications, and abnormal access to identity management endpoints.
  - *Log sources:* `azure:audit` (ListApplications, ListServicePrincipals: Large-scale queries against identity or application objects); `azure:signinlogs` (InteractiveUserLogin: Discovery behavior linked to privileged logins from atypical IP ranges)
  - *Tune:* `QueryVolumeThreshold` — Threshold for number of object enumeration calls before triggering detection.; `PrivilegedRoleList` — High-value identity roles (Global Admin, Application Admin) for targeted discovery monitoring.
- **`AN1129` Analytic 1129** · Office Suite
  Discovery of SaaS services connected to productivity platforms (e.g., Microsoft 365, Google Workspace). Defender perspective includes unexpected enumeration of enabled services, API integrations, or OAuth applications tied to user accounts.
  - *Log sources:* `m365:unified` (Get-MsolServicePrincipal, ListAppRoles: Service discovery operations executed by accounts not normally performing administrative tasks); `m365:signinlogs` (UserLogin: Discovery operations shortly after account logins from new geolocations)
  - *Tune:* `MonitoredAppIntegrations` — Specific Office Suite applications or plugins that may be enumerated or targeted.; `GeoLocationDeviation` — Geographic deviation threshold for discovery actions linked to recent logins.
- **`AN1130` Analytic 1130** · SaaS
  Discovery of connected SaaS applications, APIs, or configurations within platforms like Salesforce, Slack, or Zoom. Defender perspective includes enumeration of available integrations, abnormal querying of service metadata, and follow-on attempts to exploit or persist via discovered services.
  - *Log sources:* `saas:adminapi` (ListIntegrations, ListServices: Repeated service discovery requests from accounts without administrative responsibilities); `saas:auth` (Login, TokenGranted: Discovery actions tied to anomalous login sessions or tokens)
  - *Tune:* `IntegrationDiscoveryThreshold` — Number of SaaS integrations enumerated before triggering detection.; `ServiceAccountScope` — Expected permissions for service accounts to distinguish benign from malicious discovery.

---

### T1538 — Cloud Service Dashboard
<a id="t1538"></a>

**Detection strategy:** Detection of Cloud Service Dashboard Usage via GUI-Based Cloud Access (`DET0291`)  
**Platforms:** IaaS, Identity Provider, Office Suite, SaaS  
**ATT&CK:** [T1538](https://attack.mitre.org/techniques/T1538/) · [detail page](../../techniques/discovery.md#t1538)

- **`AN0808` Analytic 0808** · IaaS
  Detects web console login events followed by read-only or metadata retrieval activity from GUI sources (e.g., browser session, mobile client) rather than API/CLI sources. Correlates across CloudTrail, IAM identity logs, and user-agent context.
  - *Log sources:* `AWS:CloudTrail` (ConsoleLogin); `AWS:CloudTrail` (Post-authentication metadata enumeration from GUI session)
  - *Tune:* `UserAgentFilter` — Allowlist/denylist of user agents to distinguish browser-based vs. CLI/API sessions; `TimeWindow` — Maximum time delta between login and suspicious GUI activity; `PrivilegedSessionThreshold` — Login attempts to dashboard using elevated IAM roles
- **`AN0809` Analytic 0809** · Identity Provider
  Detects successful login to cloud identity portals (e.g., Okta, Azure AD, Google Identity) from atypical geolocations, devices, or user agents immediately followed by dashboard/portal navigation to sensitive pages such as user or app configuration.
  - *Log sources:* `azure:signinlogs` (Sign-in with unfamiliar location/device + portal navigation); `saas:okta` (user.session.start); `saas:okta` (WebUI access to administrator dashboard)
  - *Tune:* `GeoIPAnomalyThreshold` — Threshold for location anomalies per user profile; `UserAgentReputation` — Unknown browser/device fingerprint list; `PrivilegedPageAccess` — List of sensitive dashboard views for alerting
- **`AN0810` Analytic 0810** · Office Suite
  Detects login to admin consoles (e.g., Microsoft 365 Admin Center) from unrecognized users, devices, or geolocations followed by non-API data review or configuration read actions that suggest GUI dashboard use.
  - *Log sources:* `m365:signinlogs` (UserLoginSuccess); `m365:unified` (ViewAdminReport); `m365:unified` (Read-only configuration review from GUI)
  - *Tune:* `AdminRoleList` — Roles allowed to access dashboard views; `DashboardNavigationSequence` — Pageview paths or clickstreams indicating use of GUI admin console; `GeoLocationRisk` — List of high-risk regions or unexpected geos
- **`AN0811` Analytic 0811** · SaaS
  Detects SaaS web login followed by dashboard or web GUI page views from unfamiliar locations, devices, or access patterns. Identifies use of sensitive reporting or configuration consoles accessed from high-risk accounts.
  - *Log sources:* `saas:zoom` (Zoom Admin Dashboard accessed from unfamiliar IP/device); `saas:salesforce` (Login); `saas:box` (User navigated to admin interface)
  - *Tune:* `SaaSDashboardViewList` — List of GUI pages or endpoints considered sensitive; `IPReputationThreshold` — Reputation score or allowlist of source IPs; `LoginBehaviorBaseline` — Typical user/device login pairings or login frequency

---

### T1580 — Cloud Infrastructure Discovery
<a id="t1580"></a>

**Detection strategy:** Detection Strategy for Cloud Infrastructure Discovery (`DET0169`)  
**Platforms:** IaaS  
**ATT&CK:** [T1580](https://attack.mitre.org/techniques/T1580/) · [detail page](../../techniques/discovery.md#t1580)

- **`AN0481` Analytic 0481** · IaaS
  Defenders should monitor for suspicious enumeration of cloud infrastructure components via APIs or CLI tools. Observable behaviors include repeated listing or description operations for compute instances, snapshots, storage buckets, and volumes. From a defender’s perspective, risky activity is often identified by new or untrusted identities making discovery calls (e.g., DescribeInstances, ListBuckets, az vm list, gcloud compute instances list), enumeration from unusual geolocations or IPs, or rapid multi-service discovery in sequence. Correlating discovery API usage with later snapshot creation or instance modification provides further context of adversary behavior.
  - *Log sources:* `AWS:CloudTrail` (DescribeInstances); `AWS:CloudTrail` (ListBuckets); `AWS:CloudTrail` (DescribeDBInstances)
  - *Tune:* `UserContext` — Identity performing the discovery operation; tuned to filter known administrative or inventory accounts.; `GeoLocation` — Source region or IP of discovery requests; tuned to expected operational regions to detect unusual access.; `TimeWindow` — Correlation period to link enumeration calls with subsequent provisioning or exfiltration activity.; `APIThreshold` — Rate or volume of discovery calls; tuned to suppress noise from inventory management tools.

---

### T1613 — Container and Resource Discovery
<a id="t1613"></a>

**Detection strategy:** Detection Strategy for Container and Resource Discovery (`DET0490`)  
**Platforms:** Containers  
**ATT&CK:** [T1613](https://attack.mitre.org/techniques/T1613/) · [detail page](../../techniques/discovery.md#t1613)

- **`AN1352` Analytic 1352** · Containers
  Detection of adversary attempts to enumerate containers, pods, nodes, and related resources within containerized environments. Defenders may observe anomalous API calls to Docker or Kubernetes (e.g., 'docker ps', 'kubectl get pods', 'kubectl get nodes'), unusual account activity against the Kubernetes dashboard, or unexpected queries against container metadata endpoints. These events should be correlated with user context and network activity to reveal resource discovery attempts.
  - *Log sources:* `kubernetes:apiserver` (list or get requests against pods, deployments, or nodes); `docker:daemon` (docker ps, docker inspect, or docker images commands)
  - *Tune:* `UserAllowList` — Defines which service accounts and admin roles are expected to perform discovery actions. Activity by non-allowlisted identities may indicate adversary discovery.; `TimeWindow` — Specifies correlation period (e.g., 10m) for linking multiple discovery attempts across API and daemon logs.; `PodQueryThreshold` — Defines threshold for number of pod/node enumeration requests by a single user. Excessive queries may indicate scanning activity.

---

### T1614 — System Location Discovery
<a id="t1614"></a>

**Detection strategy:** Detection Strategy for System Location Discovery (`DET0043`)  
**Platforms:** IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1614](https://attack.mitre.org/techniques/T1614/) · [detail page](../../techniques/discovery.md#t1614)

- **`AN0119` Analytic 0119** · Windows
  Unusual process or API usage attempting to query system locale, timezone, or keyboard layout (e.g., calls to GetLocaleInfoW, GetTimeZoneInformation). Detection can be enhanced by correlating with processes not typically associated with system configuration queries, such as unknown binaries or scripts.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `etw:Microsoft-Windows-Kernel-Base` (GetLocaleInfoW, GetTimeZoneInformation API calls)
  - *Tune:* `ParentProcessAllowList` — Defines trusted processes expected to call locale APIs. Deviations may indicate adversarial activity.; `TimeWindow` — Specifies correlation window for API calls and suspicious process execution (e.g., 2m).
- **`AN0120` Analytic 0120** · Linux
  Detection of commands accessing locale, timezone, or language settings such as 'locale', 'timedatectl', or parsing /etc/timezone. Anomalous execution by unusual users or automation scripts should be flagged.
  - *Log sources:* `auditd:SYSCALL` (execve calls to locale, timedatectl, or cat /etc/timezone); `linux:Sysmon` (EventCode=1)
  - *Tune:* `UserContext` — Unexpected users running location discovery commands may indicate malicious behavior.
- **`AN0121` Analytic 0121** · macOS
  Detection of system calls or commands accessing system locale (e.g., 'defaults read -g AppleLocale', 'systemsetup -gettimezone'). Correlate with unusual parent processes or execution contexts.
  - *Log sources:* `macos:unifiedlog` (defaults read -g AppleLocale, systemsetup -gettimezone); `macos:osquery` (execve)
  - *Tune:* `ExecutionPath` — Restrict known binaries allowed to query system locale on macOS.
- **`AN0122` Analytic 0122** · IaaS
  Detection of queries to instance metadata services (e.g., AWS IMDS, Azure Metadata Service) for availability zone, region, or network geolocation details. Correlation with non-management accounts or non-standard workloads may indicate adversary reconnaissance.
  - *Log sources:* `AWS:CloudTrail` (GetMetadata, DescribeInstanceIdentity); `azure:vpcflow` (HTTP requests to 169.254.169.254 or Azure Metadata endpoints)
  - *Tune:* `MetadataQueryAllowList` — Expected services that query cloud metadata APIs. Any additional sources may be malicious.

---

### T1614.001 — System Language Discovery
<a id="t1614001"></a>

**Detection strategy:** Detection Strategy for System Language Discovery (`DET0565`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1614.001](https://attack.mitre.org/techniques/T1614/001/) · [detail page](../../techniques/discovery.md#t1614001)

- **`AN1561` Analytic 1561** · Windows
  Registry access to system language keys (e.g., HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language) or suspicious processes invoking locale-related APIs (e.g., GetUserDefaultUILanguage, GetSystemDefaultUILanguage, GetKeyboardLayoutList). Defender visibility focuses on anomalous or non-standard processes issuing these queries, especially when run by unknown binaries or scripts.
  - *Log sources:* `WinEventLog:Security` (EventCode=4657); `WinEventLog:Sysmon` (EventCode=1); `ETW` (Calls to GetUserDefaultUILanguage, GetSystemDefaultUILanguage, GetKeyboardLayoutList)
  - *Tune:* `ParentProcessAllowList` — Defines trusted processes allowed to query registry language keys or APIs. Unexpected parent-child process chains may indicate adversary use.; `QueryThreshold` — Frequency threshold for language registry or API calls within a set time window.
- **`AN1562` Analytic 1562** · Linux
  Processes executing commands to query system locale and language settings, such as 'locale', 'echo $LANG', or parsing environment variables. Suspicious activity is indicated by these commands being run by unusual users, automation scripts, or non-administrative processes.
  - *Log sources:* `auditd:SYSCALL` (execve calls to /usr/bin/locale or shell execution of $LANG); `linux:Sysmon` (EventCode=1)
  - *Tune:* `UserContext` — Unexpected or non-admin users executing locale commands may suggest malicious behavior.
- **`AN1563` Analytic 1563** · macOS
  Execution of commands to query system locale and language settings, such as 'defaults read -g AppleLocale' or 'systemsetup -gettimezone'. Unusual parent processes or execution contexts of these commands may indicate adversarial discovery.
  - *Log sources:* `macos:unifiedlog` (defaults read -g AppleLocale or systemsetup -gettimezone); `macos:osquery` (execve)
  - *Tune:* `ExecutionPath` — Restrict or monitor processes outside of system utilities that query AppleLocale or system language settings.

---

### T1615 — Group Policy Discovery
<a id="t1615"></a>

**Detection strategy:** Detection strategy for Group Policy Discovery on Windows (`DET0055`)  
**Platforms:** Windows  
**ATT&CK:** [T1615](https://attack.mitre.org/techniques/T1615/) · [detail page](../../techniques/discovery.md#t1615)

- **`AN0152` Analytic 0152** · Windows
  Detection of adversary attempts to enumerate Group Policy settings through suspicious command execution (gpresult), PowerShell enumeration (Get-DomainGPO, Get-DomainGPOLocalGroup), and abnormal LDAP queries targeting groupPolicyContainer objects. Defenders observe unusual process lineage, script execution, or LDAP filter activity against domain controllers.
  - *Log sources:* `WinEventLog:Security` (EventCode=4661); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106); `NSM:Flow` (query: High-volume LDAP traffic with filters targeting groupPolicyContainer attributes)
  - *Tune:* `TimeWindow` — Defines the correlation window to link suspicious PowerShell activity, gpresult execution, and LDAP enumeration.; `UserContext` — Identifies accounts expected to perform GPO enumeration (administrators vs. standard users).; `CommandLinePatterns` — Patterns for detecting suspicious gpresult or PowerShell cmdlets; tunable to reduce noise in environments where these tools are common.

---

### T1619 — Cloud Storage Object Discovery
<a id="t1619"></a>

**Detection strategy:** Detection Strategy for Cloud Storage Object Discovery (`DET0578`)  
**Platforms:** IaaS  
**ATT&CK:** [T1619](https://attack.mitre.org/techniques/T1619/) · [detail page](../../techniques/discovery.md#t1619)

- **`AN1594` Analytic 1594** · IaaS
  Detection of suspicious enumeration of cloud storage objects via API calls such as AWS S3 ListObjectsV2, Azure List Blobs, or GCP ListObjects. Correlate access with account role, user context, and prior authentication activity to identify anomalous usage patterns (e.g., unusual account, unexpected regions, or large-scale enumeration in short time windows).
  - *Log sources:* `AWS:CloudTrail` (ListObjectsV2); `AWS:CloudTrail` (GetObject, CopyObject)
  - *Tune:* `TimeWindow` — Correlation window (e.g., multiple enumeration calls within 5 minutes) may indicate automated discovery versus normal user activity.; `UserContext` — Expected service accounts and IAM roles that regularly enumerate storage; deviations may indicate suspicious activity.; `RegionScope` — Unusual enumeration of buckets across multiple geographic regions in short succession may indicate adversary reconnaissance.

---

### T1652 — Device Driver Discovery
<a id="t1652"></a>

**Detection strategy:** Detection Strategy for Device Driver Discovery (`DET0579`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1652](https://attack.mitre.org/techniques/T1652/) · [detail page](../../techniques/discovery.md#t1652)

- **`AN1595` Analytic 1595** · Windows
  Monitor for suspicious usage of driver enumeration utilities (driverquery.exe) or API calls such as EnumDeviceDrivers(). Registry queries against HKLM\SYSTEM\CurrentControlSet\Services and HardwareProfiles that are abnormal may also indicate attempts to discover installed drivers and services. Correlate command execution, process creation, and registry access to build a behavioral chain of driver discovery.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=13, 14)
  - *Tune:* `AllowedUtilities` — Whitelist expected administrative usage of driverquery.exe or other enumeration utilities.; `TimeWindow` — Correlation window between process creation and registry queries to identify suspicious chaining of events.
- **`AN1596` Analytic 1596** · Linux
  Detect attempts to enumerate kernel modules through lsmod, modinfo, or inspection of /proc/modules and /dev entries. Focus on unusual execution contexts such as unprivileged users or processes outside expected administrative workflows.
  - *Log sources:* `auditd:SYSCALL` (execve: Execution of lsmod, modinfo, or cat /proc/modules); `auditd:FS` (read: File access to /proc/modules or /sys/module/)
  - *Tune:* `KnownAdminUsers` — Limit detection noise by filtering expected kernel module inspection by root or system maintenance scripts.
- **`AN1597` Analytic 1597** · macOS
  Detect loading or inspection of kernel extensions (kextstat, kextfind) and file access to /System/Library/Extensions/. Monitor unexpected usage of these utilities by non-administrative users or scripts.
  - *Log sources:* `macos:unifiedlog` (exec: Execution of kextstat, kextfind, or ioreg targeting driver information); `macos:unifiedlog` (read: File access to /System/Library/Extensions/ or related kernel extension paths)
  - *Tune:* `AllowedMaintenanceTasks` — Tune detection by excluding expected system diagnostic or patch-related invocations of kext utilities.

---

### T1654 — Log Enumeration
<a id="t1654"></a>

**Detection strategy:** Detection Strategy for Log Enumeration (`DET0255`)  
**Platforms:** ESXi, IaaS, Linux, Windows, macOS  
**ATT&CK:** [T1654](https://attack.mitre.org/techniques/T1654/) · [detail page](../../techniques/discovery.md#t1654)

- **`AN0705` Analytic 0705** · Windows
  Monitor for use of native utilities such as wevtutil.exe or PowerShell cmdlets (Get-WinEvent, Get-EventLog) to enumerate or export logs. Unusual access to security or system event channels, especially by non-administrative users or processes, should be correlated with subsequent file export or network transfer activity.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Security` (EventCode=4663, 4670, 4656)
  - *Tune:* `WhitelistedAdminTools` — Expected log management scripts executed by administrators should be excluded from alerts.; `TimeWindow` — Correlate enumeration attempts with file export or network transfer within a defined timeframe.
- **`AN0706` Analytic 0706** · Linux
  Monitor for suspicious use of commands such as cat, less, grep, or journalctl accessing /var/log/ files. Abnormal enumeration of authentication logs (auth.log, secure) or bulk access to multiple logs in short time windows should be flagged.
  - *Log sources:* `auditd:SYSCALL` (execve: Execution of cat, less, grep, journalctl targeting log directories (/var/log/)); `auditd:PATH` (open: Access to sensitive log files (/var/log/auth.log, /var/log/secure, /var/log/syslog))
  - *Tune:* `AdminMaintenanceScripts` — Filter routine scripts used for log rotation or troubleshooting.
- **`AN0707` Analytic 0707** · macOS
  Detect abnormal access to unified logs via log show or fs_usage targeting system log files. Monitor for execution of shell utilities (cat, grep) against /var/log/system.log and for plist modifications enabling verbose logging.
  - *Log sources:* `macos:unifiedlog` (Execution of log show, fs_usage, or cat targeting system.log); `macos:unifiedlog` (open: Access to /var/log/system.log or related security event logs)
  - *Tune:* `DebugToolsContext` — Allowlist developers or administrators expected to review logs during debugging.
- **`AN0708` Analytic 0708** · IaaS
  Monitor for cloud API calls that export or collect guest or system logs. Abnormal use of Azure VM Agent’s CollectGuestLogs.exe or AWS CloudWatch GetLogEvents across multiple instances should be correlated with lateral movement or data staging.
  - *Log sources:* `AWS:CloudTrail` (GetLogEvents: High frequency log exports from CloudWatch or equivalent services); `azure:activity` (CollectGuestLogs: Unexpected collection of guest logs by Azure VM Agent outside normal maintenance windows)
  - *Tune:* `LogExportThreshold` — Define thresholds for volume/frequency of log export requests considered suspicious.
- **`AN0709` Analytic 0709** · ESXi
  Monitor ESXi shell or API access to host logs under /var/log/. Abnormal enumeration of vmkernel.log, hostd.log, or vpxa.log by unauthorized accounts should be flagged.
  - *Log sources:* `esxi:shell` (Execution of cat, tail, grep targeting /var/log/vmkernel.log or /var/log/hostd.log); `esxi:hostd` (read: Access to sensitive log files by non-admin users)
  - *Tune:* `AdminSessions` — Correlate with legitimate administrator access sessions to reduce noise.

---

### T1673 — Virtual Machine Discovery
<a id="t1673"></a>

**Detection strategy:** Detection Strategy for Virtual Machine Discovery (`DET0199`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1673](https://attack.mitre.org/techniques/T1673/) · [detail page](../../techniques/discovery.md#t1673)

- **`AN0572` Analytic 0572** · ESXi
  Monitor for execution of hypervisor management commands such as `esxcli vm process list` or `vim-cmd vmsvc/getallvms` that enumerate virtual machines. Defenders observe unexpected users issuing VM listing commands outside normal administrative workflows.
  - *Log sources:* `esxi:shell` (command IN ("esxcli vm process list", "vim-cmd vmsvc/getallvms"))
  - *Tune:* `ExpectedAdminUsers` — List of known administrators authorized to run ESXi enumeration commands.; `UnexpectedCommandPaths` — Defines restricted paths or contexts where VM enumeration should not occur.
- **`AN0573` Analytic 0573** · Linux
  Detects attempts to enumerate VMs via hypervisor tools like `virsh`, `VBoxManage`, or `qemu-img`. Defender correlates suspicious command invocations with parent process lineage and unexpected users.
  - *Log sources:* `auditd:SYSCALL` (execve: process_name IN ("virsh", "VBoxManage", "qemu-img") AND command IN ("list", "info"))
  - *Tune:* `NonRootAccounts` — Monitor non-root users invoking hypervisor management utilities.; `KnownAdminScripts` — Whitelist of scripts expected to run VM enumeration as part of routine operations.
- **`AN0574` Analytic 0574** · Windows
  Detects enumeration of VMs using PowerShell (`Get-VM`), VMware Workstation (`vmrun.exe`), or Hyper-V (`VBoxManage.exe`). Defender observes suspicious command lines executed by unexpected users or outside normal administrative sessions.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688)
  - *Tune:* `ExpectedAdminAccounts` — Defines which accounts are authorized to execute VM discovery commands.; `RoutineScripts` — Whitelist of approved administrative scripts that legitimately invoke VM enumeration.
- **`AN0575` Analytic 0575** · macOS
  Detects VM enumeration attempts using virtualization utilities such as VirtualBox (`VBoxManage`) or Parallels CLI. Defender observes abnormal invocation of VM listing commands correlated with non-admin users or unusual parent processes.
  - *Log sources:* `macos:unifiedlog` (process_name IN ("VBoxManage", "prlctl") AND command CONTAINS ("list", "show"))
  - *Tune:* `UserContext` — Adjust sensitivity depending on whether the command is executed by admin or non-admin users.; `ExecutionTimeWindow` — Restrict alerts to unusual times when VM management is not expected.

---

### T1680 — Local Storage Discovery
<a id="t1680"></a>

**Detection strategy:** Local Storage Discovery via Drive Enumeration and Filesystem Probing (`DET0188`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1680](https://attack.mitre.org/techniques/T1680/) · [detail page](../../techniques/discovery.md#t1680)

- **`AN0536` Analytic 0536** · Windows
  Drive enumeration using PowerShell (`Get-PSDrive`), `wmic logicaldisk`, or Win32 API indicative of local volume enumeration by non-admin users or executed outside of baseline system inventory scripts.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `user_context` — Non-system accounts performing drive enumeration may be higher fidelity indicators; `parent_process_name` — Baseline parent-child process lineage can help distinguish admin tools from malicious scripts
- **`AN0537` Analytic 0537** · Linux
  Abnormal use of `lsblk`, `fdisk -l`, `lshw -class disk`, or `parted` by non-admin users or within non-interactive shells suggests suspicious disk enumeration activity.
  - *Log sources:* `auditd:SYSCALL` (execve call with argv matching known disk enumeration commands (lsblk, parted, fdisk)); `auditd:EXECVE` (command line arguments containing lsblk, fdisk, parted)
  - *Tune:* `TTY_type` — Detection can exclude interactive TTY sessions to reduce false positives from admin usage; `shell_parent` — Differentiate between interactive user shells vs. script-based execution
- **`AN0538` Analytic 0538** · macOS
  Disk enumeration via `diskutil list` or `system_profiler SPStorageDataType` run outside of user login or not associated with system inventory tools
  - *Log sources:* `macos:unifiedlog` (process launch of diskutil or system_profiler with SPStorageDataType); `macos:unifiedlog` (log messages related to disk enumeration context or Terminal session)
  - *Tune:* `launch_agent_context` — Unexpected use of disk enumeration tools from GUI apps or LaunchAgents may indicate abuse; `volume_name_filter` — Filter known baseline volume names or identifiers used by common device configurations
- **`AN0539` Analytic 0539** · ESXi
  Use of `esxcli storage` or `vim-cmd vmsvc/getallvms` by unusual sessions or through interactive shells unrelated to administrative maintenance tasks.
  - *Log sources:* `esxi:hostd` (execution of esxcli with args matching 'storage', 'filesystem', 'core device list'); `esxi:auth` (interactive shell or SSH access preceding storage enumeration)
  - *Tune:* `ssh_source_ip` — Restrict alerts to unexpected remote sessions accessing host storage commands; `esxcli_command_scope` — Tailor detection based on subcommands more likely to be abused

---

