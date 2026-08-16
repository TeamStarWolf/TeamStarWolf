# Privilege Escalation — Detection Strategies

> MITRE ATT&CK detection strategies and analytics (v18.1) for techniques whose primary tactic is **Privilege Escalation**. Each analytic lists the **log sources / channels** it needs, the **detection logic**, and the **tunable elements** to adapt it to your environment. Authoritative source: the ATT&CK detection-strategy model in the Enterprise STIX.

See also: [all detection strategies index](README.md) · [Technique Detection Library](../TECHNIQUE_DETECTION_LIBRARY.md) (ready-to-run SIEM queries) · [Data Components & Log Sources](../../ATTACK_DATA_COMPONENTS.md) · [Technique Detail Pages](../../techniques/README.md)

---

### T1068 — Exploitation for Privilege Escalation
<a id="t1068"></a>

**Detection strategy:** Detection Strategy for Exploitation for Privilege Escalation (`DET0514`)  
**Platforms:** Containers, Linux, Windows, macOS  
**ATT&CK:** [T1068](https://attack.mitre.org/techniques/T1068/) · [detail page](../../techniques/privilege-escalation.md#t1068)

- **`AN1419` Analytic 1419** · Windows
  Detects exploitation attempts targeting vulnerable kernel drivers or OS components, often followed by unusual process or token behavior.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=6); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Security` (EventCode=4672)
  - *Tune:* `DriverNamePattern` — Targeted BYOVD drivers may vary based on campaign and tooling.; `TimeWindow` — Controls temporal linking of driver load → process spawn → privilege use.; `ParentProcessPath` — Parent-child relationships vary by exploitation vector (e.g., LOLBin vs. dropper).
- **`AN1420` Analytic 1420** · Linux
  Detects escalation via vulnerable setuid binaries or kernel modules, often chained with unusual access to /proc/kallsyms or /dev/kmem.
  - *Log sources:* `auditd:SYSCALL` (execve); `auditd:SYSCALL` (ACCESS); `auditd:SYSCALL` (dmesg)
  - *Tune:* `SetUIDBinaryList` — Legitimate SUID binaries vary across distributions; false positives may arise.; `TimeWindow` — Allows chaining kernel module load with privilege spike or privilege-sensitive process activity.; `EffectiveUIDThreshold` — Default is uid=0, but environments may vary with containerized root-like accounts.
- **`AN1421` Analytic 1421** · macOS
  Detects use of vulnerable kernel extensions or entitlements abused via setuid or AppleScript injection chains.
  - *Log sources:* `macos:unifiedlog` (process:exec and kext load events); `macos:endpointsecurity` (ES_EVENT_TYPE_NOTIFY_KEXTLOAD)
  - *Tune:* `EntitlementList` — Entitlements vary by app and OS version; some allow unexpected behavior.; `TimeWindow` — Correlate SUID execution or AppleScript injection with privilege gain or module load.
- **`AN1422` Analytic 1422** · Containers
  Detects container breakout behavior via exploitation (e.g., DirtyPipe, CVE-2022-0847), followed by host OS interaction or escalated capability assignment.
  - *Log sources:* `auditd:SYSCALL` (capset or setns); `containerd:runtime` (e.g., containerd, Docker events)
  - *Tune:* `NamespaceEscapePattern` — May vary with CVE technique or custom syscall wrapper.; `TimeWindow` — Controls correlation of breakout → host interaction.

---

### T1546 — Event Triggered Execution
<a id="t1546"></a>

**Detection strategy:** Behavioral Detection of Event Triggered Execution Across Platforms (`DET0010`)  
**Platforms:** IaaS, Linux, Office Suite, SaaS, Windows, macOS  
**ATT&CK:** [T1546](https://attack.mitre.org/techniques/T1546/) · [detail page](../../techniques/privilege-escalation.md#t1546)

- **`AN0024` Analytic 0024** · Windows
  Correlates unexpected modifications to WMI event filters, scheduled task triggers, or registry autorun keys with subsequent execution of non-standard binaries by SYSTEM-level processes.
  - *Log sources:* `WinEventLog:Security` (EventCode=4698); `WinEventLog:WMI` (Creation or modification of __EventFilter, __FilterToConsumerBinding, or CommandLineEventConsumer); `WinEventLog:Security` (EventCode=4657); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `UserContext` — Filters triggering on SYSTEM or LOCAL SERVICE vs. user-initiated triggers; `TimeWindow` — Correlates trigger definition and execution timing (e.g., within 5 minutes); `PathAnomalyThreshold` — Process or binary path deviation scoring for execution anomalies
- **`AN0025` Analytic 0025** · Linux
  Detects inotify or auditd configuration changes that monitor system files coupled with execution of script interpreters or binaries by cron or systemd timers.
  - *Log sources:* `auditd:SYSCALL` (Inotify watch creation or auditctl changes on /etc/cron* or /lib/systemd/system/); `linux:syslog` (Execution of non-standard script or binary by cron); `auditd:SYSCALL` (Execution of script interpreters by systemd timer (ExecStart))
  - *Tune:* `ExecutablePathRegex` — Regex defining suspicious binary/script paths triggered by cron/systemd; `WatchTargetPaths` — Paths monitored by auditd/inotify for suspicious event registration
- **`AN0026` Analytic 0026** · macOS
  Correlates launchd plist modifications with subsequent unauthorized script execution or anomalous parent-child process trees involving user agents.
  - *Log sources:* `macos:unifiedlog` (Modification of ~/Library/LaunchAgents or /Library/LaunchDaemons plist); `macos:unifiedlog` (Execution of launchctl with suspicious arguments)
  - *Tune:* `PlistNamePattern` — Regex pattern matching known rogue or unrecognized launchd plist names; `ParentProcessBaseline` — Expected parent-child relationships during plist-triggered execution
- **`AN0027` Analytic 0027** · IaaS
  Monitors cloud function creation triggered by specific audit log events (e.g., IAM changes, object creation), followed by anomalous behavior from new service accounts.
  - *Log sources:* `AWS:CloudTrail` (CreateFunction); `AWS:CloudTrail` (InvokeFunction)
  - *Tune:* `TriggerEventType` — Specific cloud event (e.g., PutObject, CreateRole) that causes function invocation; `ServiceAccountRole` — Expected permissions for roles used in function execution
- **`AN0028` Analytic 0028** · SaaS
  Correlates Power Automate or similar logic app workflows triggered by SaaS file uploads or email rules with data forwarding or anomalous access patterns.
  - *Log sources:* `m365:unified` (Creation of Power Automate flow triggered by OneDrive or Exchange event); `m365:unified` (Automated forwarding or file sync initiated by a logic app)
  - *Tune:* `TriggerCondition` — Event types that initiate SaaS automation (e.g., file add, new email); `AppIdentityScope` — Scopes/permissions granted to automation app accounts
- **`AN0029` Analytic 0029** · Office Suite
  Detects macros or VBA triggers set to execute on document open or close events, often correlating with embedded payloads or C2 traffic shortly after execution.
  - *Log sources:* `m365:office` (VBA auto_open, auto_close, or document_open events); `m365:office` (External HTTP/DNS connection from Office binary shortly after macro trigger)
  - *Tune:* `MacroFunctionNames` — Names of event-bound functions like Auto_Open that initiate execution; `TimeDeltaMacroToC2` — Time threshold to correlate macro execution with outbound connections

---

### T1546.001 — Change Default File Association
<a id="t1546001"></a>

**Detection strategy:** Detect Default File Association Hijack via Registry & Execution Correlation on Windows (`DET0061`)  
**Platforms:** Windows  
**ATT&CK:** [T1546.001](https://attack.mitre.org/techniques/T1546/001/) · [detail page](../../techniques/privilege-escalation.md#t1546001)

- **`AN0170` Analytic 0170** · Windows
  Detects modification of registry keys used for default file handlers, followed by anomalous process execution from user-initiated file opens. This includes tracking changes under HKCU and HKCR for file extension mappings, and correlating them with new or suspicious handler paths launching unusual child processes (e.g., PowerShell, cmd, wscript).
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Security` (EventCode=4672)
  - *Tune:* `TimeWindow` — Defines how long after the registry modification to correlate a suspicious process execution; `UserContext` — Tune to ignore known admin or installer behavior in specific user profiles; `SuspiciousHandlerPathRegex` — Pattern match for suspicious handler paths (e.g., powershell.exe, rundll32.exe)

---

### T1546.002 — Screensaver
<a id="t1546002"></a>

**Detection strategy:** Detect Screensaver-Based Persistence via Registry and Execution Chains (`DET0154`)  
**Platforms:** Windows  
**ATT&CK:** [T1546.002](https://attack.mitre.org/techniques/T1546/002/) · [detail page](../../techniques/privilege-escalation.md#t1546002)

- **`AN0441` Analytic 0441** · Windows
  Unusual screensaver (.scr) executions correlated with recent registry modifications to HKCU\Control Panel\Desktop values such as SCRNSAVE.exe, ScreenSaveTimeout, and ScreenSaveActive. Detection focuses on PE image paths not consistent with known legitimate screensavers and triggered after user inactivity timeout.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=13, 14)
  - *Tune:* `TimeWindow` — Adjust the user inactivity threshold that defines 'screensaver trigger window'; shorter timeouts may increase sensitivity.; `SuspiciousPathRegex` — Allow tuning based on expected paths for legitimate .scr files vs suspicious locations (e.g., user temp directories).; `ParentProcessAllowList` — Allowlisting known legitimate initiators of .scr files (e.g., user32.dll context) to reduce false positives.; `RegistryEditorProcessName` — Monitor for registry modification performed by unusual processes (e.g., powershell.exe, reg.exe).

---

### T1546.003 — Windows Management Instrumentation Event Subscription
<a id="t1546003"></a>

**Detection strategy:** Detect WMI Event Subscription for Persistence via WmiPrvSE Process and MOF Compilation (`DET0086`)  
**Platforms:** Windows  
**ATT&CK:** [T1546.003](https://attack.mitre.org/techniques/T1546/003/) · [detail page](../../techniques/privilege-escalation.md#t1546003)

- **`AN0236` Analytic 0236** · Windows
  Monitor for creation of WMI EventFilter, EventConsumer, and FilterToConsumerBinding objects through WMI or MOF file execution. Detect command-line execution of `mofcomp.exe`, usage of `Register-WmiEvent` via PowerShell, and anomalous child processes of `WmiPrvSE.exe` that indicate triggered execution. Look for lateral anomalies in process lineage and WMI logging channels.
  - *Log sources:* `WinEventLog:WMI` (EventCode=5857, 5858, 5860, 5861); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `TimeWindow` — Defines temporal correlation range between WMI creation and child process execution; `UserContext` — Tune for specific accounts (e.g., SYSTEM or attacker-controlled users); `ProcessNameAllowlist` — Used to exclude known benign consumers triggered via WMI (e.g., backup tools); `ParentProcessAnomalyThreshold` — Defines what constitutes anomalous spawning from WmiPrvSE.exe

---

### T1546.004 — Unix Shell Configuration Modification
<a id="t1546004"></a>

**Detection strategy:** Detect Shell Configuration Modification for Persistence via Event-Triggered Execution (`DET0020`)  
**Platforms:** Linux, macOS  
**ATT&CK:** [T1546.004](https://attack.mitre.org/techniques/T1546/004/) · [detail page](../../techniques/privilege-escalation.md#t1546004)

- **`AN0059` Analytic 0059** · Linux
  Detects modification of shell startup/logout scripts such as ~/.bashrc, ~/.bash_profile, or /etc/profile, followed by anomalous process execution or network connections upon interactive or remote shell login.
  - *Log sources:* `auditd:SYSCALL` (AUDIT_SYSCALL (open, write, rename, unlink)); `auditd:EXECVE` (execution of unexpected binaries during user shell startup); `NSM:Flow` (unexpected network activity initiated shortly after shell session starts)
  - *Tune:* `TimeWindow` — Defines how soon after shell startup process execution or network activity is considered suspicious.; `TargetUser` — Limits detection to specific user accounts or roles such as root or service accounts.; `FilePathRegex` — Defines what shell configuration paths are considered relevant (e.g., .bashrc, .bash_logout, etc.)
- **`AN0060` Analytic 0060** · macOS
  Correlates zsh shell configuration file changes (e.g., ~/.zshrc, ~/.zlogin, /etc/zprofile) with execution of unauthorized binaries or unexpected network activity triggered on Terminal.app launch.
  - *Log sources:* `macos:unifiedlog` (launch of Terminal.app or shell with non-standard environment setup); `macos:endpointsecurity` (ES_EVENT_TYPE_NOTIFY_WRITE, targeting .zshrc, .zlogin, .zprofile)
  - *Tune:* `FileTargetList` — Customizable list of shell config files considered sensitive for detection.; `PayloadEntropyThreshold` — Used to distinguish benign from potentially obfuscated commands written to config files.; `UserContext` — Scoping based on user login class, e.g., administrative vs standard users.

---

### T1546.005 — Trap
<a id="t1546005"></a>

**Detection strategy:** Detection Strategy for Event Triggered Execution via Trap (T1546.005) (`DET0369`)  
**Platforms:** Linux, macOS  
**ATT&CK:** [T1546.005](https://attack.mitre.org/techniques/T1546/005/) · [detail page](../../techniques/privilege-escalation.md#t1546005)

- **`AN1038` Analytic 1038** · Linux
  Correlate file modifications in shell startup scripts (e.g., .bashrc, .profile) with embedded `trap` commands and observe if those changes are followed by the unexpected execution of child processes when terminal signals (e.g., SIGINT) are triggered. Use contextual linking with user session activity to detect privilege misuse.
  - *Log sources:* `auditd:SYSCALL` (execve); `auditd:SYSCALL` (Modification of user shell profile or trap registration via echo/redirection (e.g., echo "trap 'malicious_cmd' INT" >> ~/.bashrc)); `auditd:SYSCALL` (open)
  - *Tune:* `TargetShellFilePath` — The path to user profile scripts (e.g., ~/.bashrc, ~/.zshrc); may differ by distro or shell type.; `SignalTrapName` — Trap signal (e.g., INT, HUP, TERM) can be environment-specific or attacker-tuned to evade.; `TimeWindow` — Temporal threshold to correlate trap insertion and process execution (e.g., 10s-5min)
- **`AN1039` Analytic 1039** · macOS
  Detect unauthorized `trap` command registrations in shell startup files (e.g., .zprofile, .bash_profile, .zshrc) followed by execution chains during user terminal interaction. Use Unified Logs and EDR telemetry to correlate shell command parsing and process tree anomalies.
  - *Log sources:* `macos:unifiedlog` (Command line containing `trap` or `echo 'trap` written to login shell files); `macos:unifiedlog` (File write or append to .zshrc, .bash_profile, .zprofile, etc.)
  - *Tune:* `LoginShellConfigPaths` — Startup files vary by shell (.bash_profile, .zshrc, etc.); `TrapCommandLengthThreshold` — Short benign traps may differ from longer/multi-command malicious traps; `ParentProcessAnomalyThreshold` — Score or detect if new child process deviates from shell’s typical behavior

---

### T1546.006 — LC_LOAD_DYLIB Addition
<a id="t1546006"></a>

**Detection strategy:** Detection Strategy for LC_LOAD_DYLIB Modification in Mach-O Binaries on macOS (`DET0216`)  
**Platforms:** macOS  
**ATT&CK:** [T1546.006](https://attack.mitre.org/techniques/T1546/006/) · [detail page](../../techniques/privilege-escalation.md#t1546006)

- **`AN0607` Analytic 0607** · macOS
  Detection focuses on unauthorized modification of Mach-O binaries to include LC_LOAD_DYLIB headers pointing to malicious dylibs. Behavior is identified via a chain of file metadata changes, removal of code signatures, and subsequent anomalous dylib loads at runtime. Correlation of file changes with lack of authorized updates and process memory mapping of unrecognized or unsigned libraries is crucial.
  - *Log sources:* `macos:unifiedlog` (Process memory maps new dylib (dylib_load event)); `macos:unifiedlog` (Mach-O binary modified or LC_LOAD_DYLIB segment inserted); `macos:unifiedlog` (Code signature validation fails or is absent post-binary modification)
  - *Tune:* `TimeWindow` — Correlates binary modification and dylib load within a defined time interval (e.g., 1 hour); `DylibPathRegex` — Regular expression to match known malicious or uncommon library paths; `UnsignedDylibThreshold` — Number of unsigned or unrecognized dylibs mapped into memory per process; `UserContext` — Scope monitoring to non-admin users or sensitive system directories

---

### T1546.007 — Netsh Helper DLL
<a id="t1546007"></a>

**Detection strategy:** Detection Strategy for Netsh Helper DLL Persistence via Registry and Child Process Monitoring (Windows) (`DET0575`)  
**Platforms:** Windows  
**ATT&CK:** [T1546.007](https://attack.mitre.org/techniques/T1546/007/) · [detail page](../../techniques/privilege-escalation.md#t1546007)

- **`AN1588` Analytic 1588** · Windows
  Detection focuses on monitoring registry modifications under HKLM\SOFTWARE\Microsoft\Netsh that indicate the addition of helper DLLs, followed by anomalous child process activity or module load behavior initiated by netsh.exe. These behaviors are rarely legitimate and may represent an adversary establishing persistence.
  - *Log sources:* `WinEventLog:Security` (EventCode=4657); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `TimeWindow` — Defines the time window in which correlated registry and execution events are considered suspicious (e.g., within 10 minutes); `NetshChildProcessWhitelist` — List of expected or approved child processes spawned by netsh.exe in the enterprise environment; `DLLLoadPath` — Directory or filename heuristics to distinguish benign DLLs from malicious helper DLLs

---

### T1546.008 — Accessibility Features
<a id="t1546008"></a>

**Detection strategy:** Detection Strategy for Accessibility Feature Hijacking via Binary Replacement or Registry Modification (`DET0033`)  
**Platforms:** Windows  
**ATT&CK:** [T1546.008](https://attack.mitre.org/techniques/T1546/008/) · [detail page](../../techniques/privilege-escalation.md#t1546008)

- **`AN0094` Analytic 0094** · Windows
  Defenders can observe suspicious replacement or tampering of system accessibility binaries (e.g., utilman.exe, sethc.exe, osk.exe) and anomalous modifications to registry keys used to redirect accessibility programs (such as IFEO keys). Additionally, execution of cmd.exe or other suspicious binaries triggered from the login screen by SYSTEM can be correlated as part of a behavior chain.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:Sysmon` (EventCode=15)
  - *Tune:* `TimeWindow` — Time between registry modification and suspicious binary execution (e.g., < 1 hour) can be tuned.; `TargetBinaryNames` — Specific binaries monitored (e.g., utilman.exe, sethc.exe) can be adjusted per OS version and risk tolerance.; `ParentProcess` — Parent process of cmd.exe (e.g., winlogon.exe) may vary across legitimate and adversarial cases.; `UserContext` — Context of SYSTEM account execution vs. administrative sessions may influence tuning.; `CommandLineContains` — Tunable patterns such as launching cmd.exe, powershell, or LOLBins from accessibility binaries.

---

### T1546.009 — AppCert DLLs
<a id="t1546009"></a>

**Detection strategy:** Detection Strategy for AppCert DLLs Persistence via Registry Injection (`DET0362`)  
**Platforms:** Windows  
**ATT&CK:** [T1546.009](https://attack.mitre.org/techniques/T1546/009/) · [detail page](../../techniques/privilege-escalation.md#t1546009)

- **`AN1029` Analytic 1029** · Windows
  Detection of AppCert DLL abuse involves correlating registry modifications to the AppCertDLLs key with subsequent unexpected DLL load behavior during process creation events. Specifically, defenders can observe abnormal DLLs being loaded into standard Windows processes after changes to the 'AppCertDLLs' registry value. Monitoring CreateProcess-family API executions with injected DLLs and linking those DLLs back to recent registry edits is key to identifying misuse. This is often accompanied by elevated privileges and potential lateral movement or discovery behavior.
  - *Log sources:* `WinEventLog:Security` (EventCode=4657); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `TargetObject` — Registry path for AppCertDLLs may vary by control set or group policy context; `ImageLoaded` — Loaded DLLs may differ by malware family or environment; `ParentImage` — Parent processes to monitor for DLL injection can be tuned to exclude known-good cases; `TimeWindow` — Time correlation between registry modification and DLL load events may vary

---

### T1546.010 — AppInit DLLs
<a id="t1546010"></a>

**Detection strategy:** Detection Strategy for Event Triggered Execution: AppInit DLLs (Windows) (`DET0557`)  
**Platforms:** Windows  
**ATT&CK:** [T1546.010](https://attack.mitre.org/techniques/T1546/010/) · [detail page](../../techniques/privilege-escalation.md#t1546010)

- **`AN1536` Analytic 1536** · Windows
  Registry key modification to AppInit_DLLs value followed by anomalous DLL loading by processes importing user32.dll, especially unsigned or uncommon DLLs, suggesting unauthorized AppInit persistence or privilege escalation.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=13, 14)
  - *Tune:* `ImagePathWhitelist` — Paths or filenames of known-good DLLs to exclude from alerting; `UserContext` — Context of the user modifying the registry key (e.g., admin vs standard user); `TimeWindow` — Temporal threshold for correlating registry modification and DLL load; `DLLSignatureStatus` — Filter or flag unsigned or suspiciously signed DLLs

---

### T1546.011 — Application Shimming
<a id="t1546011"></a>

**Detection strategy:** Detection Strategy for Application Shimming via sdbinst.exe and Registry Artifacts (Windows) (`DET0017`)  
**Platforms:** Windows  
**ATT&CK:** [T1546.011](https://attack.mitre.org/techniques/T1546/011/) · [detail page](../../techniques/privilege-escalation.md#t1546011)

- **`AN0051` Analytic 0051** · Windows
  Correlated modification of AppCompat registry keys and execution of sdbinst.exe to install custom shim databases. Followed by DLL injection via shim behavior into target application processes.
  - *Log sources:* `WinEventLog:Security` (EventCode=4657); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `CustomShimPathAllowlist` — Filter out known-good .sdb paths in AppPatch\Custom folders; `TimeWindow` — Tunable window for correlating registry modification and sdbinst.exe execution; `DLLInjectionTarget` — Expected target applications or binaries for injected DLLs; `UserContext` — Limit alerting to admin or SYSTEM-context initiated shim installations; `ShimCommandLinePattern` — Expected or benign sdbinst.exe command-line patterns to exclude

---

### T1546.012 — Image File Execution Options Injection
<a id="t1546012"></a>

**Detection strategy:** Detection Strategy for IFEO Injection on Windows (`DET0422`)  
**Platforms:** Windows  
**ATT&CK:** [T1546.012](https://attack.mitre.org/techniques/T1546/012/) · [detail page](../../techniques/privilege-escalation.md#t1546012)

- **`AN1186` Analytic 1186** · Windows
  Registry key modifications under IFEO paths (e.g., Debugger value set under Image File Execution Options), especially for security-related or accessibility binaries, followed by anomalous process execution with debugger flags or SYSTEM-level access at login. Detectable by correlating registry modifications, process creation, and parent-child anomalies with unusual command-line usage or access tokens.
  - *Log sources:* `WinEventLog:Security` (EventCode=4657); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=12)
  - *Tune:* `TimeWindow` — Time delta for correlating registry modification and debugger-triggered execution; `TargetBinary` — Specific executables that trigger defenders’ alerts when IFEO values are set; `ParentProcessAnomaly` — Tunable logic for detecting parent-child anomalies (e.g., non-standard parent processes); `TokenElevationContext` — May require tuning based on normal SYSTEM or admin process elevation patterns

---

### T1546.013 — PowerShell Profile
<a id="t1546013"></a>

**Detection strategy:** Detection Strategy for PowerShell Profile Persistence via profile.ps1 Modification (`DET0451`)  
**Platforms:** Windows  
**ATT&CK:** [T1546.013](https://attack.mitre.org/techniques/T1546/013/) · [detail page](../../techniques/privilege-escalation.md#t1546013)

- **`AN1245` Analytic 1245** · Windows
  Defenders can identify PowerShell profile-based persistence by correlating file creation or modification in known profile locations with subsequent PowerShell process launches that do not use the `-NoProfile` flag. Profile scripts loading unusual modules or launching external programs, particularly under elevated contexts, are suspicious and may represent adversary persistence or privilege escalation.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=2); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:PowerShell` (Execution of PowerShell without -NoProfile flag)
  - *Tune:* `ProfilePathList` — Custom PowerShell host profiles or redirection to alternate profile paths; `ExecutionContext` — Whether profile execution occurs under elevated user (e.g., Administrator, SYSTEM); `ModuleOrScriptName` — Specific modules or external programs loaded within profile; `TimeWindow` — Correlation time between profile modification and PowerShell process start

---

### T1546.014 — Emond
<a id="t1546014"></a>

**Detection strategy:** Detection Strategy for Event Triggered Execution via emond on macOS (`DET0555`)  
**Platforms:** macOS  
**ATT&CK:** [T1546.014](https://attack.mitre.org/techniques/T1546/014/) · [detail page](../../techniques/privilege-escalation.md#t1546014)

- **`AN1534` Analytic 1534** · macOS
  Detection focuses on identifying unauthorized file creation or modification within `/etc/emond.d/rules/` or `/private/var/db/emondClients`, which indicate attempts to register a malicious emond rule. Correlate with process execution of `/sbin/emond` and any launched commands it invokes, especially during boot or login events. Anomalies may include rules created by non-root users or unexpected shell commands executed by emond.
  - *Log sources:* `macos:unifiedlog` (file create or modify in /etc/emond.d/rules or /private/var/db/emondClients); `macos:unifiedlog` (execution of /sbin/emond with child processes launched); `macos:unifiedlog` (rule definitions written to emond rule plists); `macos:unifiedlog` (command execution triggered by emond (e.g., shell, curl, python))
  - *Tune:* `PathPrefix` — Paths such as `/etc/emond.d/rules/` and `/private/var/db/emondClients` may vary slightly or be symlinked in some setups; `TimeWindow` — The time range for correlating rule file creation to emond execution may be tuned based on system performance and usage; `ParentProcessFilter` — Defenders may wish to restrict alerts to emond processes not spawned from trusted system update or provisioning tools; `CommandPatternList` — List of known suspicious commands or binaries used by adversaries (e.g., reverse shells, persistence scripts)

---

### T1546.015 — Component Object Model Hijacking
<a id="t1546015"></a>

**Detection strategy:** Windows COM Hijacking Detection via Registry and DLL Load Correlation (`DET0481`)  
**Platforms:** Windows  
**ATT&CK:** [T1546.015](https://attack.mitre.org/techniques/T1546/015/) · [detail page](../../techniques/privilege-escalation.md#t1546015)

- **`AN1323` Analytic 1323** · Windows
  Correlate suspicious registry modifications to known COM object CLSIDs with subsequent DLL loads or unexpected binary execution paths. Detect placement of COM CLSID entries under HKEY_CURRENT_USER\Software\Classes\CLSID\ overriding default HKLM paths. Flag anomalous DLL loads traced back to hijacked COM registry changes.
  - *Log sources:* `WinEventLog:Security` (EventCode=4657); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `RegistryPathScope` — Defenders may tune specific monitored CLSIDs depending on known-good application behavior.; `BinaryPathAnomalyThreshold` — May require tuning based on environment to distinguish rare-but-legit COM DLLs vs suspicious ones.; `TimeWindow` — Correlating registry changes to DLL load or process execution may require configurable time window.; `UserContextFilter` — Tuning detection by isolating activity to specific user SIDs or admin-level activity may reduce false positives.

---

### T1546.016 — Installer Packages
<a id="t1546016"></a>

**Detection strategy:** Detection Strategy for T1546.016 - Event Triggered Execution via Installer Packages (`DET0330`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1546.016](https://attack.mitre.org/techniques/T1546/016/) · [detail page](../../techniques/privilege-escalation.md#t1546016)

- **`AN0938` Analytic 0938** · macOS
  Correlation of package install event with execution of postinstall scripts containing unknown binaries or abnormal CLI usage. Look for `/usr/sbin/installer` execution followed by child processes originating from postinstall script.
  - *Log sources:* `macos:unifiedlog` (Execution of /usr/sbin/installer spawning child process from within /private/tmp or package contents); `macos:unifiedlog` (Creation or modification of postinstall scripts within .pkg or .mpkg contents)
  - *Tune:* `ScriptLocation` — Path to postinstall script varies depending on .pkg packaging and user temp directories.; `ParentProcessName` — Installers may vary (e.g., /usr/sbin/installer, Jamf, Munki).
- **`AN0939` Analytic 0939** · Linux
  Detection of maintainer scripts (e.g., postinst, preinst) being modified or executed during dpkg or rpm operations. Watch for script content that spawns additional processes or writes outside package scope.
  - *Log sources:* `auditd:SYSCALL` (Execution of dpkg or rpm followed by fork/execve from within postinst, prerm, etc.); `auditd:SYSCALL` (write)
  - *Tune:* `ScriptName` — May be postinst, preinst, prerm, or postrm depending on packaging system; `PackageManager` — Depends on system: dpkg, apt, rpm, yum, etc.
- **`AN0940` Analytic 0940** · Windows
  Detection of msiexec.exe running installer packages that result in anomalous process creation. Look for unexpected binaries executed by msiexec or custom action DLLs in the temp directory.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `InstallerParent` — Could be msiexec.exe or third-party wrapper like setup.exe.; `ChildImagePath` — Payload paths vary based on where installer extracts to (e.g., %TEMP%, C:\Users\Public).; `ExecutionTimeWindow` — Threshold for how soon a payload must run after msiexec to be considered related.

---

### T1548 — Abuse Elevation Control Mechanism
<a id="t1548"></a>

**Detection strategy:** Detection Strategy for Abuse Elevation Control Mechanism (T1548) (`DET0345`)  
**Platforms:** IaaS, Identity Provider, Linux, Windows, macOS  
**ATT&CK:** [T1548](https://attack.mitre.org/techniques/T1548/) · [detail page](../../techniques/privilege-escalation.md#t1548)

- **`AN0975` Analytic 0975** · Windows
  Correlate registry modifications (e.g., UAC bypass registry keys), unusual parent-child process relationships (e.g., control.exe spawning cmd.exe), and unsigned elevated process executions with non-standard tokens or elevation flags.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Security` (EventCode=4672); `WinEventLog:Sysmon` (EventCode=13, 14)
  - *Tune:* `ElevatedProcessPath` — Paths to monitor for unsigned or unexpected elevated binaries; `ParentProcessName` — Parent-child execution chains that are suspicious in the local environment; `TimeWindow` — Time between registry modification and elevated process spawn
- **`AN0976` Analytic 0976** · Linux
  Monitor audit logs for setuid/setgid bit changes, executions where UID ≠ EUID (indicative of sudo or privilege escalation), and high-integrity binaries launched by unprivileged users.
  - *Log sources:* `auditd:SYSCALL` (setuid or setgid bit changes); `auditd:SYSCALL` (execve with UID ≠ EUID); `auditd:SYSCALL` (sudo or pkexec invocation)
  - *Tune:* `WatchedDirectories` — Paths where unauthorized setuid binaries may be dropped; `UserContext` — Which users are allowed to run sudo/pkexec or modify binaries; `TimeWindow` — Duration between file permission change and elevated command execution
- **`AN0977` Analytic 0977** · macOS
  Detect execution of `/usr/libexec/security_authtrampoline` or use of AuthorizationExecuteWithPrivileges API, and monitor process lineage for unusual launches of GUI apps with escalated privileges.
  - *Log sources:* `macos:unifiedlog` (authorization execute privilege requests); `auditd:SYSCALL` (execve with escalated privileges); `fs:fsusage` (binary execution of security_authtrampoline)
  - *Tune:* `WatchedBinaries` — Specify binaries frequently targeted for privilege escalation; `ExecutionParent` — Which applications should never be allowed to spawn elevated processes
- **`AN0978` Analytic 0978** · Identity Provider
  Monitor for unexpected privilege elevation operations via SAML assertion manipulation, role injection, or changes to identity mappings that result in access escalation.
  - *Log sources:* `azure:signinlogs` (unusual role assumption or elevation path)
  - *Tune:* `AuthorizedRoleMappings` — Roles or groups that should never be assumed outside designated paths; `TimeWindow` — Time between assertion issuance and critical privilege use
- **`AN0979` Analytic 0979** · IaaS
  Detect sudden privilege escalations such as IAM role changes, user-assigned privilege boundaries, or elevation via assumed roles beyond normal behavior.
  - *Log sources:* `AWS:CloudTrail` (role privilege expansion detected); `AWS:CloudTrail` (cross-account or unexpected assume role)
  - *Tune:* `PermittedRoleTransitions` — Define valid transitions between IAM roles; `CrossAccountBoundary` — Should flag if assumption crosses trust boundary

---

### T1548.001 — Setuid and Setgid
<a id="t1548001"></a>

**Detection strategy:** Setuid/Setgid Privilege Abuse Detection (Linux/macOS) (`DET0110`)  
**Platforms:** Linux, macOS  
**ATT&CK:** [T1548.001](https://attack.mitre.org/techniques/T1548/001/) · [detail page](../../techniques/privilege-escalation.md#t1548001)

- **`AN0307` Analytic 0307** · Linux
  Correlation of chmod operations setting setuid/setgid bits followed by privileged process execution (EUID != UID), especially from user-writable or abnormal paths.
  - *Log sources:* `auditd:SYSCALL` (chmod, execve); `auditd:SYSCALL` (execve)
  - *Tune:* `UserContext` — Track execution of setuid binaries where UID != EUID or executed from unexpected user context; `FilePathScope` — Restrict detection to non-standard locations (e.g., /tmp, /home/*, /var/tmp); `TimeWindow` — Time delta between chmod setting setuid/gid and process execution to define a suspicious window
- **`AN0308` Analytic 0308** · macOS
  Observation of chmod commands setting setuid/setgid bits, paired with launch of binaries under elevated execution context (e.g., root-owned binaries launched by unprivileged users).
  - *Log sources:* `macos:unifiedlog` (chmod command with arguments including '+s', 'u+s', or numeric values 4000–6777); `macos:unifiedlog` (exec of binary with setuid/setgid and EUID != UID)
  - *Tune:* `UserContext` — Monitor execution chains where UID != EUID or child process inherits root without known sudo context; `ExecutionPath` — Focus on binaries in user-writable locations or abnormal directories; `ChmodPattern` — Tailor detection to chmod commands that imply privilege elevation via numeric mode or symbolic mode

---

### T1548.002 — Bypass User Account Control
<a id="t1548002"></a>

**Detection strategy:** Detection Strategy for T1548.002 – Bypass User Account Control (UAC) (`DET0388`)  
**Platforms:** Windows  
**ATT&CK:** [T1548.002](https://attack.mitre.org/techniques/T1548/002/) · [detail page](../../techniques/privilege-escalation.md#t1548002)

- **`AN1094` Analytic 1094** · Windows
  Detects a multi-event behavior chain involving UAC bypass attempts via known auto-elevated binaries (e.g., eventvwr.exe, sdclt.exe), unauthorized Registry changes to UAC-related keys, and anomalous process execution with elevated privileges but lacking standard parent-child lineage. Suspicious patterns include invocation of auto-elevated COM objects or manipulation of isolatedCommand Registry entries without consent prompts.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Security` (EventCode=4672); `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `TimeWindow` — Correlate registry tampering and elevation within a tunable time window (e.g., 30 seconds) to reduce noise from benign admin activity.; `ElevatedProcessNameList` — Tunable list of suspicious elevated binaries (e.g., sdclt.exe, eventvwr.exe, computerdefaults.exe) known to support UAC bypass.; `ParentProcessAnomalyThreshold` — Define logic for parent-child mismatch (e.g., non-elevated process spawning auto-elevated one) to flag uncommon elevation paths.

---

### T1548.003 — Sudo and Sudo Caching
<a id="t1548003"></a>

**Detection strategy:** Behavioral Detection Strategy for Abuse of Sudo and Sudo Caching (`DET0052`)  
**Platforms:** Linux, macOS  
**ATT&CK:** [T1548.003](https://attack.mitre.org/techniques/T1548/003/) · [detail page](../../techniques/privilege-escalation.md#t1548003)

- **`AN0142` Analytic 0142** · Linux
  Correlate command executions involving 'sudo' with elevated effective user ID (euid=0), especially when tty_tickets is disabled or timestamp_timeout is actively abused.
  - *Log sources:* `auditd:SYSCALL` (execve call for sudo where euid != uid); `auditd:SYSCALL` (execve call for modification of /etc/sudoers or writing to /var/db/sudo)
  - *Tune:* `timestamp_timeout_threshold` — Tune the valid sudo session duration to reduce false positives; `command_allowlist` — Filter benign sudo usage (e.g., approved admin scripts)
- **`AN0143` Analytic 0143** · macOS
  Detect sudo activity with NOPASSWD in /etc/sudoers or disabling tty_tickets, followed by immediate privileged commands (e.g., echo 'Defaults !tty_tickets' >> /etc/sudoers).
  - *Log sources:* `macos:unifiedlog` (exec or sudo usage with NOPASSWD context or echo modifying sudoers); `macos:unifiedlog` (Terminal process killed (killall Terminal) immediately after sudoers modification)
  - *Tune:* `admin_user_context` — Define allowed users who may modify sudoers without investigation; `terminal_restart_window` — Time window after sudoers file change to monitor for Terminal restarts

---

### T1548.004 — Elevated Execution with Prompt
<a id="t1548004"></a>

**Detection strategy:** macOS AuthorizationExecuteWithPrivileges Elevation Prompt Detection (`DET0395`)  
**Platforms:** macOS  
**ATT&CK:** [T1548.004](https://attack.mitre.org/techniques/T1548/004/) · [detail page](../../techniques/privilege-escalation.md#t1548004)

- **`AN1111` Analytic 1111** · macOS
  Detects abuse of AuthorizationExecuteWithPrivileges API to gain elevated privileges via user credential prompts, typically through invocation of /usr/libexec/security_authtrampoline. Detection involves correlation of API usage, binary reputation, and prompt context.
  - *Log sources:* `macos:unifiedlog` (Execution of /usr/libexec/security_authtrampoline or child processes originating from non-trusted binaries triggering credential prompts); `macos:unifiedlog` (Calls to AuthorizationExecuteWithPrivileges() observed via Apple System Logger or security_auditing tools); `macos:unifiedlog` (User credential prompt events without associated trusted installer package)
  - *Tune:* `BinaryReputationList` — Allow list of trusted binaries invoking elevation prompts; `TimeWindow` — Temporal correlation threshold between API call and credential prompt; `PromptContextValidation` — Heuristic filters to determine whether a prompt context matches known legitimate installers

---

### T1548.005 — Temporary Elevated Cloud Access
<a id="t1548005"></a>

**Detection strategy:** Detection Strategy for Temporary Elevated Cloud Access Abuse (T1548.005) (`DET0393`)  
**Platforms:** IaaS, Identity Provider, Office Suite  
**ATT&CK:** [T1548.005](https://attack.mitre.org/techniques/T1548/005/) · [detail page](../../techniques/privilege-escalation.md#t1548005)

- **`AN1105` Analytic 1105** · IaaS
  Multiple AWS CloudTrail events indicating temporary privilege escalation via PassRole and AssumeRole targeting newly created services or non-interactive infrastructure.
  - *Log sources:* `AWS:CloudTrail` (PassRole)
  - *Tune:* `targetRoleName` — Define which roles are allowed to be assumed or passed; restrict highly privileged roles.; `TimeWindow` — Time range between PassRole and AssumeRole events to link the privilege chain.; `invokingService` — Restrict which services are authorized to invoke role passing (e.g., Lambda, EC2).
- **`AN1106` Analytic 1106** · Identity Provider
  Token creation or access delegation where a user impersonates a higher-privileged service account or performs domain-wide delegation actions, such as GCP's serviceAccountTokenCreator or Workspace impersonation.
  - *Log sources:* `gcp:iam` (PrincipalEmail with serviceAccountTokenCreator impersonating new identity); `gcp:workspaceaudit` (Token Generation via Domain Delegation)
  - *Tune:* `userEmailFilter` — Tune based on legitimate service accounts allowed to impersonate user accounts.; `delegatedScope` — Limit delegated access to specific scopes relevant to business functions.
- **`AN1107` Analytic 1107** · Office Suite
  Detection of ApplicationImpersonation role assignment or delegated mailbox access to service principals or rarely used users, especially outside of normal hours or geographic norms.
  - *Log sources:* `m365:unified` (Add-MailboxPermission or Set-ManagementRoleAssignment); `m365:signinlogs` (Unusual sign-in from service principal to user mailbox)
  - *Tune:* `TargetMailbox` — Mailbox of interest where impersonation or access delegation occurs.; `UserAgent` — Tune based on expected application or script-based mailbox access.; `GeoLocation` — Restrict based on corporate geography or travel expectations.

---

### T1611 — Escape to Host
<a id="t1611"></a>

**Detection strategy:** Detection Strategy for Escape to Host (`DET0219`)  
**Platforms:** Containers, ESXi, Linux, Windows  
**ATT&CK:** [T1611](https://attack.mitre.org/techniques/T1611/) · [detail page](../../techniques/privilege-escalation.md#t1611)

- **`AN0612` Analytic 0612** · Containers
  Detection of container escape attempts via bind mounts, privileged containers, or abuse of docker.sock. Defenders may observe anomalous volume mount configurations (e.g., hostPath to / or /proc), unexpected privileged container launches, or use of container administration commands to access host resources. These events typically correlate with subsequent process execution on the host outside of normal container isolation.
  - *Log sources:* `docker:daemon` (container create/start with privileged flag or host volume mount); `kubernetes:apiserver` (Pod spec with hostPath or privileged securityContext)
  - *Tune:* `AllowedHostPaths` — List of directories permitted for hostPath volumes. Any access beyond these paths may be suspicious.; `PrivilegedContainerThreshold` — Number of privileged container launches expected in the environment. Exceeding this may indicate adversary behavior.
- **`AN0613` Analytic 0613** · Linux
  Detection of Linux container escape attempts via syscalls (`unshare`, `keyctl`, `mount`) or process execution outside container namespaces. Defenders may correlate unusual system calls from containerized processes with subsequent process creation on the host or modification of host resources.
  - *Log sources:* `auditd:SYSCALL` (unshare, mount, keyctl, setns syscalls executed by containerized processes); `linux:Sysmon` (process creation events linked to container namespaces executing host-level binaries)
  - *Tune:* `SyscallWhitelist` — Expected syscalls by containerized workloads. Deviations may signal an escape attempt.; `TimeWindow` — Defines correlation window (e.g., 60s) between suspicious syscalls and follow-on host process activity.
- **`AN0614` Analytic 0614** · Windows
  Detection of Windows container escape attempts by observing processes accessing host directories, symbolic link abuse, or privilege escalation attempts. Defenders may detect anomalous process execution with access to system-level directories outside of container boundaries.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `RestrictedHostDirs` — Critical system paths containers should not access (e.g., C:\Windows, C:\ProgramData).
- **`AN0615` Analytic 0615** · ESXi
  Detection of ESXi escape attempts by monitoring for anomalies in hypervisor logs such as unexpected VM operations, privilege escalation events, or attempts to load malicious kernel modules within the hypervisor environment.
  - *Log sources:* `esxi:vmkernel` (VM exit/entry anomalies, unexpected hypercalls, or kernel module loading)
  - *Tune:* `AllowedKernelModules` — Modules permitted in the hypervisor. Loading any module outside of this list may indicate compromise.

---

