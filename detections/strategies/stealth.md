# Stealth — Detection Strategies

> MITRE ATT&CK detection strategies and analytics (v19.2) for techniques whose primary tactic is **Stealth**. Each analytic lists the **log sources / channels** it needs, the **detection logic**, and the **tunable elements** to adapt it to your environment. Authoritative source: the ATT&CK detection-strategy model in the Enterprise STIX.

See also: [all detection strategies index](/detections/strategies/README.md) · [Technique Detection Library](../TECHNIQUE_DETECTION_LIBRARY.md) (ready-to-run SIEM queries) · [Data Components & Log Sources](../../ATTACK_DATA_COMPONENTS.md) · [Technique Detail Pages](../../techniques/README.md)

---

### T1006 — Direct Volume Access
<a id="t1006"></a>

**Detection strategy:** Detection of Direct Volume Access for File System Evasion (`DET0426`)  
**Platforms:** Network Devices, Windows  
**ATT&CK:** [T1006](https://attack.mitre.org/techniques/T1006/) · [detail page](../../techniques/stealth.md#t1006)

- **`AN1193` Analytic 1193** · Windows
  Processes accessing raw logical drives (e.g., \.\C:) to bypass file system protections or directly manipulate data structures.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Security (EventCode=4688)`
  - *Tune:* `TargetObjectPattern` — Regex pattern to detect access to raw disk volumes like `\Device\HarddiskVolume` or `\.\PhysicalDrive*`.; `ParentProcess` — Tune for known tools/scripts (e.g., powershell.exe, cmd.exe) often used in misuse scenarios.; `TimeWindow` — Correlate file access and creation across a short time window to avoid false positives.
- **`AN1194` Analytic 1194** · Network Devices
  CLI or automated utilities accessing raw device volumes or flash storage directly (e.g., via `copy flash:`, `format`, or `partition` commands).
  - *Log sources:* `networkdevice:cli (command logging)`
  - *Tune:* `CommandScope` — Limit detection to volume-level commands (e.g., `format`, `copy`, `mount`, `erase`).; `DeviceTypeFilter` — Filter by internal vs. removable volume interactions (e.g., flash, SD card).

---

### T1014 — Rootkit
<a id="t1014"></a>

**Detection strategy:** Detection of Kernel/User-Level Rootkit Behavior Across Platforms (`DET0377`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1014](https://attack.mitre.org/techniques/T1014/) · [detail page](../../techniques/stealth.md#t1014)

- **`AN1061` Analytic 1061** · Windows
  Unauthorized or anomalous loading of kernel-mode drivers or DLLs, concealed services, or abnormal modification of boot components indicative of rootkit activity.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=6)`; `WinEventLog:System (EventCode=7045)`; `WinEventLog:Sysmon (EventCode=11)`
  - *Tune:* `DriverSignatureStatus` — Signed vs unsigned drivers; many environments restrict unsigned drivers, but some legacy systems allow them.; `TargetDirectory` — Suspicious driver or DLL drop locations, e.g., \System32\Drivers\ or \Temp\; `UserContext` — Rootkit installation via admin or SYSTEM account.
- **`AN1062` Analytic 1062** · Linux
  Abnormal loading of kernel modules, direct tampering with /dev, /proc, or LD_PRELOAD behaviors hiding processes or files.
  - *Log sources:* `auditd:EXECVE`; `linux:osquery (file_events)`; `linux:syslog (kmod)`
  - *Tune:* `MonitoredDirectories` — Directories where kernel modules or tampering could be staged (e.g., /lib/modules/).; `ModuleNamePattern` — Regex or heuristic match to anomalous module names (e.g., suspicious entropy or gibberish).; `LD_PRELOAD` — Monitor presence of suspicious preload values that mask processes or files.
- **`AN1063` Analytic 1063** · macOS
  Execution of unsigned kernel extensions (KEXTs), tampering with LaunchDaemons, or userspace hooks into system libraries.
  - *Log sources:* `macos:unifiedlog (subsystem=com.apple.kextd)`; `macos:osquery (launch_daemons)`; `fs:fsevents (Extensions)`
  - *Tune:* `KextSignatureStatus` — Allowable level of unsigned/3rd-party kernel extensions varies by organization.; `KextLoadOrigin` — Detect whether the extension was loaded by an untrusted process or non-root user.; `AnomalousLaunchAgent` — Detection tuned based on deviation from known/approved LaunchDaemon plist files.

---

### T1027 — Obfuscated Files or Information
<a id="t1027"></a>

**Detection strategy:** Behavioral Detection of Obfuscated Files or Information (`DET0378`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1027](https://attack.mitre.org/techniques/T1027/) · [detail page](../../techniques/stealth.md#t1027)

- **`AN1064` Analytic 1064** · Windows
  Correlates script execution or suspicious parent processes with creation or modification of encoded, compressed, or encrypted file formats (e.g., .zip, .7z, .enc) and abnormal command-line syntax or PowerShell obfuscation.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `PayloadEntropyThreshold` — Tune entropy threshold to distinguish obfuscation from legitimate compression; `TimeWindow` — Adjust correlation window between script execution and encoded file creation; `SuspiciousParentProcessList` — Customize based on environment to include LOLBins or admin tools misused for obfuscation
- **`AN1065` Analytic 1065** · Linux
  Detects use of gzip, base64, tar, or openssl in scripts or commands that encode/encrypt files after file staging or system enumeration.
  - *Log sources:* `auditd:SYSCALL (execve)`; `auditd:SYSCALL (open, write)`; `linux:cli (Shell history logs)`
  - *Tune:* `CommandRegex` — Customize for tools seen in environment (e.g., gzip, bzip2, xz); `SensitivePathList` — Specify file paths likely targeted for obfuscation (e.g., /etc/, /home/)
- **`AN1066` Analytic 1066** · macOS
  Monitors use of archive or encryption tools (zip, openssl) tied to user-scripted activity or binaries writing encoded payloads under /Users or /Volumes.
  - *Log sources:* `macos:unifiedlog (log stream --predicate 'processImagePath contains "zip" OR "base64"')`; `macos:osquery (file_events)`
  - *Tune:* `FilenameExtensionList` — Tunable to identify uncommon or encrypted file formats (e.g., .enc, .b64, .xz); `UserContext` — Tune to prioritize unexpected file access by service accounts
- **`AN1067` Analytic 1067** · Network Devices
  Identifies transfer of base64, uuencoded, or high-entropy files over HTTP, FTP, or custom protocols in lateral movement or exfiltration streams.
  - *Log sources:* `networkdevice:IDS (content inspection / PCAP / HTTP body)`
  - *Tune:* `EntropyThreshold` — Adjust threshold to reduce false positives in compressed but benign data; `ProtocolScope` — Refine by enabling inspection of specific exfil vectors (e.g., FTP, HTTP POST)
- **`AN1068` Analytic 1068** · ESXi
  Detects encoded PowerCLI or Base64-encoded payloads staged via datastore uploads or shell access (e.g., ESXi Shell or backdoored VIBs).
  - *Log sources:* `esxi:vmkernel (Datastore modification events)`; `esxi:hostd (Remote access API calls and file uploads)`
  - *Tune:* `StagingLocation` — Tune based on observed adversary paths (e.g., /vmfs/volumes/...); `EncodedLengthThreshold` — Tune length of encoded payloads before triggering detection

---

### T1027.001 — Binary Padding
<a id="t1027001"></a>

**Detection strategy:** Detection Strategy for Obfuscated Files or Information: Binary Padding (`DET0553`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1027.001](https://attack.mitre.org/techniques/T1027/001/) · [detail page](../../techniques/stealth.md#t1027001)

- **`AN1528` Analytic 1528** · Windows
  Detects the creation or execution of padded binary files (e.g., large size but minimal legitimate content) followed by process execution or lateral movement from the host.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Security (EventCode=4663, 4670, 4656)`; `WinEventLog:Sysmon (EventCode=11)`
  - *Tune:* `FileSizeThresholdMB` — Threshold size in MB to determine suspicious padding; `TimeWindow` — Correlation time window between file creation and execution; `UserContext` — Scope the detection to suspicious or non-standard user accounts
- **`AN1529` Analytic 1529** · Linux
  Detects abnormal creation of binary files with significant size that are subsequently executed or accessed by non-standard users.
  - *Log sources:* `auditd:SYSCALL (open)`; `auditd:SYSCALL (execve)`; `linux:osquery (file_events)`
  - *Tune:* `FileSizeThresholdMB` — Defines how large a file must be to consider it padded; `UserContext` — Target abnormal user behavior outside of expected automation; `TimeWindow` — Time window for correlating file creation and execution
- **`AN1530` Analytic 1530** · macOS
  Monitors for anomalous binary files written to disk with padded size and subsequent execution by user or service context.
  - *Log sources:* `macos:unifiedlog (process:spawn)`; `fs:fsusage (file write)`
  - *Tune:* `FileSizeThresholdMB` — Padded binary threshold for file size; `TimeWindow` — Detection correlation window for execution after file creation; `UserContext` — Filters for specific users or groups such as admin or service accounts

---

### T1027.002 — Software Packing
<a id="t1027002"></a>

**Detection strategy:** Obfuscated Binary Unpacking Detection via Behavioral Patterns (`DET0023`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1027.002](https://attack.mitre.org/techniques/T1027/002/) · [detail page](../../techniques/stealth.md#t1027002)

- **`AN0066` Analytic 0066** · Windows
  Detection of unpacking behavior through abnormal memory allocation, followed by executable code injection and execution from non-image sections.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `ParentProcessName` — To scope detections to suspicious parent-child process relationships typical of loaders or droppers.; `AllocationSizeThreshold` — To tune for unusually large virtual memory allocations that might indicate unpacked payloads.
- **`AN0067` Analytic 0067** · Linux
  Correlates ELF file execution with high-entropy writable memory segments and self-modifying code patterns.
  - *Log sources:* `auditd:SYSCALL (execve)`; `auditd:SYSCALL (mprotect)`
  - *Tune:* `EntropyThreshold` — Useful for tuning unpacked sections containing high entropy indicative of compression or encryption.; `TimeWindow` — Can be tuned to correlate file writes to execution within a set timeframe.
- **`AN0068` Analytic 0068** · macOS
  Detection of packed Mach-O binaries unpacking into memory and transferring control to dynamically modified code segments.
  - *Log sources:* `macos:unifiedlog (process::exec)`; `macos:endpointsecurity (ES_EVENT_MMAP)`
  - *Tune:* `SignedBinaryContext` — Helps to distinguish between signed/unsigned packed binaries (common in legitimate vs. malicious cases).; `UserContext` — Can be used to scope to specific users or service accounts targeted in attacks.

---

### T1027.003 — Steganography
<a id="t1027003"></a>

**Detection strategy:** Detection Strategy for Steganographic Abuse in File & Script Execution (`DET0119`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1027.003](https://attack.mitre.org/techniques/T1027/003/) · [detail page](../../techniques/stealth.md#t1027003)

- **`AN0331` Analytic 0331** · Windows
  Detects execution of image viewers or PowerShell scripts accessing or decoding files with mismatched MIME headers or embedded script-like byte patterns; often correlated with suspicious parent-child process lineage and outbound connections.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=3, 22)`; `WinEventLog:Security (EventCode=4663, 4670, 4656)`
  - *Tune:* `ParentProcessImage` — Tune to identify image editors/viewers invoking script interpreters (e.g., `mspaint.exe` > `powershell.exe`); `MimeHeaderMismatchTolerance` — Adjust tolerance for image file headers that do not match file extensions or content structure; `TimeWindow` — Define the temporal range to correlate decoding → execution → network beaconing
- **`AN0332` Analytic 0332** · Linux
  Detects access to media files followed by execution of scripts (bash, Python, etc.) referencing those same files, or outbound traffic triggered shortly after file read. Correlates unusual use of tools like `steghide`, `exiftool`, or image libraries.
  - *Log sources:* `auditd:SYSCALL (open)`; `auditd:SYSCALL (execve)`; `auditd:SYSCALL (connect)`
  - *Tune:* `MonitoredToolsList` — Define the list of steganographic or image-parsing tools to alert on (e.g., `steghide`, `imagemagick`); `ScriptInterpreterMatch` — Tune to detect script engines accessing media files (e.g., `python script.py image.png`)
- **`AN0333` Analytic 0333** · macOS
  Detects manipulation of PNG, JPG, or GIF files by user-initiated scripts followed by script execution or exfiltration behavior, especially from `osascript`, `python`, or `bash`, in combination with LaunchAgent persistence or curl activity.
  - *Log sources:* `macos:osquery (file_events)`; `macos:osquery (process_events)`; `macos:unifiedlog (network connection events)`
  - *Tune:* `StegoToolNamePatterns` — Adapt to known or emerging tools using stego methods on macOS (e.g., `Invoke-PSImage`, `stegsolve`); `ParentScriptSources` — Update list of trusted versus unknown scripting hosts launching activity tied to image handling

---

### T1027.004 — Compile After Delivery
<a id="t1027004"></a>

**Detection strategy:** Detection Strategy for Compile After Delivery - Source Code to Executable Transformation (`DET0501`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1027.004](https://attack.mitre.org/techniques/T1027/004/) · [detail page](../../techniques/stealth.md#t1027004)

- **`AN1381` Analytic 1381** · Windows
  Detects compilation activity using csc.exe, ilasm.exe, or msbuild.exe initiated by user-space processes outside typical development environments, followed by execution or network activity from newly written binaries.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=3, 22)`
  - *Tune:* `ParentProcessName` — Filter for unexpected users (non-dev) launching compilers like csc.exe or msbuild.exe; `OutputDirectoryPath` — Adjust paths for sensitive file write zones (e.g., `C:\Users\Public\`, `%TEMP%`, or Desktop); `TimeWindow` — Tune the correlation window between compilation and subsequent execution or C2
- **`AN1382` Analytic 1382** · Linux
  Detects GCC or Clang invoked on suspicious file paths (e.g., /tmp/, ~/Downloads) with output to executable binaries, followed by execution or outbound traffic from these binaries.
  - *Log sources:* `auditd:SYSCALL (execve)`; `auditd:SYSCALL (open,create)`; `NSM:Flow (conn.log)`
  - *Tune:* `CompilerBinaryPath` — Specify path and binaries for detection (e.g., `/usr/bin/gcc`, `/opt/mingw/bin/gcc`); `FilePermissionProfile` — Match uncommon chmod behavior post-compilation (e.g., +x in `/tmp` or home directories)
- **`AN1383` Analytic 1383** · macOS
  Detects non-standard compilation activity via Xcode CLI tools or bundled GCC/MONO packages writing new executable files and executing them outside dev environments (e.g., user Downloads folder).
  - *Log sources:* `macos:unifiedlog (process activity, exec events)`; `macos:osquery (file_events)`; `macos:unifiedlog (networkd or socket)`
  - *Tune:* `CompilerInvocationPattern` — Detect calls to `xcodebuild`, `clang`, or `/Applications/Mono.app/...` from non-admin users; `OutputBinaryPath` — Monitor for output files in user-writable paths (e.g., `~/Library/Caches`, `~/Downloads`)

---

### T1027.005 — Indicator Removal from Tools
<a id="t1027005"></a>

**Detection strategy:** Detection Strategy for Indicator Removal from Tools - Post-AV Evasion Modification (`DET0189`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1027.005](https://attack.mitre.org/techniques/T1027/005/) · [detail page](../../techniques/stealth.md#t1027005)

- **`AN0540` Analytic 0540** · Windows
  Detection of known tools or malware flagged by antivirus, followed by a near-term drop of a similar binary with modified signature and resumed activity (execution, C2, or persistence).
  - *Log sources:* `WinEventLog:Application (EventCode=1000)`; `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=11)`
  - *Tune:* `AVAlertMessage` — Vendor-specific signature string or detection message that can be correlated to threat intel context.; `TimeWindow` — The time between AV alert and similar file/process activity (e.g., 5–30 minutes); `FilenameSimilarityThreshold` — String or hash similarity thresholds between original and modified binary.
- **`AN0541` Analytic 0541** · Linux
  Detection of anti-malware quarantining or flagging a tool, followed by a new binary written to disk with a similar function or name and a resumed process chain.
  - *Log sources:* `auditd:SYSCALL (execve)`; `auditd:SYSCALL (open, rename)`; `linux:osquery (file_events)`; `EDR:detection (ThreatDetected, QuarantineLog)`
  - *Tune:* `PathWatchlist` — Tunable list of directories often abused for dropped binaries (e.g., /tmp, ~/.cache, /opt/soft/).; `ProcessAncestryDepth` — Limit how far up the tree to trace tool modification behavior for detection.
- **`AN0542` Analytic 0542** · macOS
  Detection of XProtect or AV quarantining a known tool, followed by modification (file size, hash, string) and subsequent re-execution by the same or related user.
  - *Log sources:* `macos:unifiedlog (quarantine or AV-related subsystem)`; `macos:osquery (file_events)`
  - *Tune:* `BinaryChangeThreshold` — File hash delta or binary string diff score to tolerate renamed/mutated variants.; `UserContext` — User or group expected to use dev tools; reduce false positives from legitimate repacking.

---

### T1027.006 — HTML Smuggling
<a id="t1027006"></a>

**Detection strategy:** Detection Strategy for HTML Smuggling via JavaScript Blob + Dynamic File Drop (`DET0313`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1027.006](https://attack.mitre.org/techniques/T1027/006/) · [detail page](../../techniques/stealth.md#t1027006)

- **`AN0872` Analytic 0872** · Windows
  Detection of browser-based or email client-driven file creation (often from temp directories) following navigation to or execution of HTML files containing JavaScript Blob APIs or base64 Data URLs, with follow-on execution of the dropped payload. Leveraging Sysmon EventID 15 to inspect Zone.Identifier ADS for HostUrl/ReferrerUrl indicators (e.g., HostUrl=about:internet). Optional: absence of a large HTTP download record for the same URL/client in proxy logs (suggests local assembly)
  - *Log sources:* `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=1)`; `EDR:detection (App reputation telemetry)`; `WinEventLog:Sysmon (EventCode=15)`; `Network Traffic`
  - *Tune:* `TimeWindow` — Time range between HTML file open and file drop + execution (e.g., 1–10 minutes); `DroppedFileExtensionWatchlist` — Tunable list of file extensions of interest (e.g., .js, .hta, .exe); `ParentProcessName` — Expected processes that may drop files (e.g., browser, Outlook); tune for normal behavior
- **`AN0873` Analytic 0873** · Linux
  Detection of browser-based downloads from HTML sources that trigger file creation in temp or user directories followed by execution of new files within short timeframes and suspicious parent-child lineage.
  - *Log sources:* `auditd:SYSCALL (execve)`; `linux:osquery (file_events)`
  - *Tune:* `DownloadPathRegex` — Regular expressions for common download paths (e.g., /tmp/, ~/Downloads/); `ExecutableTriggerWindow` — Tunable range for follow-up process execution from dropped file (e.g., 5–15 minutes)
- **`AN0874` Analytic 0874** · macOS
  Detection of HTML-based downloads via Safari/Chrome that create obfuscated files (e.g., .zip, .app, .js) in user directories and are followed by suspicious executions from preview or launch services.
  - *Log sources:* `macos:unifiedlog (File Events)`; `macos:osquery (process_events)`; `gatekeeper/quarantine database (LaunchServices quarantine)`
  - *Tune:* `QuarantineFlagCheck` — Whether downloaded file has a quarantine flag and is bypassed via Gatekeeper; `BlobKeywordAlertList` — JavaScript strings that may indicate smuggling: msSaveBlob, download.href, createObjectURL

---

### T1027.007 — Dynamic API Resolution
<a id="t1027007"></a>

**Detection strategy:** Detection Strategy for Dynamic API Resolution via Hash-Based Function Lookups (`DET0091`)  
**Platforms:** Windows  
**ATT&CK:** [T1027.007](https://attack.mitre.org/techniques/T1027/007/) · [detail page](../../techniques/stealth.md#t1027007)

- **`AN0250` Analytic 0250** · Windows
  Behavioral chain involving suspicious use of GetProcAddress and LoadLibrary following memory allocation and manual mapping, often paired with low entropy strings, abnormal API use without static import tables, or delayed module load behaviors.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=7)`; `etw:Microsoft-Windows-Kernel-Process (API tracing / stack tracing via ETW or telemetry-based EDR)`
  - *Tune:* `APILoadWithoutImport` — Tunable logic to flag suspicious modules used without static IAT entries; `TimeWindow` — Correlates module load to suspicious memory allocation or API lookup within timeframe; `EntropyThreshold` — Used to detect obfuscated strings or hashed function names; `StackTraceFilter` — Optional filtering of known safe modules or patterns from telemetry

---

### T1027.008 — Stripped Payloads
<a id="t1027008"></a>

**Detection strategy:** Detection Strategy for Stripped Payloads Across Platforms (`DET0019`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1027.008](https://attack.mitre.org/techniques/T1027/008/) · [detail page](../../techniques/stealth.md#t1027008)

- **`AN0055` Analytic 0055** · Windows
  Executable or script payloads lacking symbol information and readable strings that are created or dropped by unusual or short-lived processes.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=11)`; `EDR:file (File Metadata Inspection (Low String Entropy, Missing PDB))`
  - *Tune:* `EntropyThreshold` — Payloads with extremely low string entropy may indicate stripped or obfuscated binaries; `ParentProcessName` — Used to scope or whitelist common system builders, compilers, or admin tools; `TimeWindow` — Correlates file creation and process spawning within a short timeframe
- **`AN0056` Analytic 0056** · Linux
  Executable or binary files created without symbol tables or with stripped sections, especially by non-user shell processes or compilers invoked outside standard dev paths.
  - *Log sources:* `auditd:EXECVE (EXECVE)`; `auditd:SYSCALL (open, write)`; `linux:osquery (hash, elf_info, file_metadata)`
  - *Tune:* `StripFlags` — Flag combinations in compiled binaries indicating symbol table removal; `DirectoryScope` — Whitelist compiler output directories to reduce false positives; `FileSizeRange` — Heuristic boundaries for abnormal small or overly large stripped binaries
- **`AN0057` Analytic 0057** · macOS
  Creation of run-only AppleScripts or Mach-O binaries lacking symbol table and string references, especially when dropped by user space scripting engines or staging apps.
  - *Log sources:* `macos:unifiedlog (file write)`; `macos:endpointsecurity (ES_EVENT_TYPE_NOTIFY_EXEC)`; `macos:osquery (code_signing, file_metadata)`
  - *Tune:* `RunOnlyFlag` — AppleScript flag to disable reverse engineering (run-only compiled scripts); `ParentProcess` — Filter to isolate staging or suspicious scripting engines; `SignedStatus` — Tuning based on unsigned vs. developer-signed payloads
- **`AN0058` Analytic 0058** · Network Devices
  Inbound binary payloads transferred over HTTP/S with compressed or encoded headers, lacking signature markers or metadata indicative of compiler/toolchain.
  - *Log sources:* `NSM:Flow (http.log, files.log)`
  - *Tune:* `MIMEType` — Tune for octet-stream or mismatched Content-Type headers; `PayloadSize` — Payload threshold for executable-sized artifacts; `TransferEncoding` — Suspicious base64 or chunked encoding not matching normal app behavior

---

### T1027.009 — Embedded Payloads
<a id="t1027009"></a>

**Detection strategy:** Detection Strategy for Embedded Payloads (`DET0214`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1027.009](https://attack.mitre.org/techniques/T1027/009/) · [detail page](../../techniques/stealth.md#t1027009)

- **`AN0599` Analytic 0599** · Windows
  Detection of executables or scripts containing hidden embedded resources or secondary payloads, often with anomalies in file size vs. functionality or dropped child binaries.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=1)`; `EDR:file (File Metadata Analysis (PE overlays, entropy))`
  - *Tune:* `OverlaySizeThreshold` — Threshold in bytes where appended sections to binaries are considered suspicious; `ProcessTreeDepth` — Controls how far child process lineage is analyzed for dropped embedded payloads; `TimeWindow` — Defines correlation interval between file write and process execution
- **`AN0600` Analytic 0600** · Linux
  Detection of shell scripts, ELF binaries, or archives containing embedded secondary payloads, self-extracting components, or unusual compression behavior during runtime.
  - *Log sources:* `auditd:SYSCALL (open, write)`; `linux:osquery (elf_info, hash, yara_matches)`; `ebpf:syscalls (container_file_activity)`
  - *Tune:* `FileSectionCount` — Tuning value for ELF binaries with appended sections or resources; `ScriptLength` — Threshold for long shell scripts with base64-encoded binary content; `ExtractedFileCount` — Number of files written from a single script execution
- **`AN0601` Analytic 0601** · macOS
  Detection of Mach-O binaries or AppleScripts that contain nested, encoded, or run-only embedded payloads dropped at runtime.
  - *Log sources:* `macos:unifiedlog (logd:file write)`; `macos:endpointsecurity (ES_EVENT_TYPE_NOTIFY_EXEC)`; `macos:osquery (mach_o_info, file_metadata)`
  - *Tune:* `ScriptFormatType` — Run-only AppleScripts or signed scripting payloads may require scoped detection; `DroppedBinaryCount` — Threshold on number of binaries created by the parent payload; `ParentProcessName` — Allows focusing on suspicious interpreter or staging tools

---

### T1027.010 — Command Obfuscation
<a id="t1027010"></a>

**Detection strategy:** Detection Strategy for Command Obfuscation (`DET0505`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1027.010](https://attack.mitre.org/techniques/T1027/010/) · [detail page](../../techniques/stealth.md#t1027010)

- **`AN1394` Analytic 1394** · Windows
  Detection of command-line activity exhibiting syntactic obfuscation patterns, such as excessive escape characters, base64 encoding, command concatenation, or outlier command length and entropy.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`
  - *Tune:* `CommandLineEntropyThreshold` — Used to flag base64 or token-heavy command-line strings; `SuspiciousCharacterCount` — Escape character and symbol frequency in command-line strings; `TimeWindow` — Window between command execution and follow-up child or file write behavior
- **`AN1395` Analytic 1395** · Linux
  Detection of shell commands that leverage encoded execution, command chaining, excessive piping, or unusual token patterns indicative of obfuscation.
  - *Log sources:* `auditd:SYSCALL (execve)`; `linux:osquery (process_events.command_line)`
  - *Tune:* `CommandLineTokenCount` — Tuning value for token or argument count in shell invocations; `EncodedExecRegex` — Environment-specific regex patterns for encoded or eval'd command lines; `GlobPatternAnomalies` — Shell-specific globbing or directory traversal string detection
- **`AN1396` Analytic 1396** · macOS
  Detection of obfuscated commands via shell, osascript, or AppleScript interpreters using unusual tokens, encoding, variable substitution, or runtime string reconstruction.
  - *Log sources:* `macos:unifiedlog (process:spawn, process:exec)`; `macos:endpointsecurity (ES_EVENT_TYPE_NOTIFY_EXEC)`
  - *Tune:* `InterpreterParentFilter` — Limits detection scope to shell or scripting interpreters like zsh, bash, osascript; `ScriptEntropyThreshold` — Minimum entropy required to consider the command or script obfuscated; `ArgumentLengthDeviation` — Deviation from baseline for long or highly nested arguments

---

### T1027.011 — Fileless Storage
<a id="t1027011"></a>

**Detection strategy:** Detection Strategy for Fileless Storage via Registry, WMI, and Shared Memory (`DET0344`)  
**Platforms:** Linux, Windows  
**ATT&CK:** [T1027.011](https://attack.mitre.org/techniques/T1027/011/) · [detail page](../../techniques/stealth.md#t1027011)

- **`AN0973` Analytic 0973** · Windows
  Detects abuse of fileless storage mechanisms such as Registry keys, WMI classes, and Event Logs used to stage payloads, scripts, or encoded content outside traditional files.
  - *Log sources:* `WinEventLog:Security (EventCode=4657)`; `WinEventLog:Application (WMI Object Creation Events)`
  - *Tune:* `RegistryPathFilter` — Scoped to suspicious or abused paths like HKCU\Software\Classes\ or HKLM\SYSTEM\CurrentControlSet\Services\; `PayloadEntropyThreshold` — Minimum entropy level to flag suspicious registry or WMI content as encoded payloads; `TimeWindow` — Temporal window for correlating WMI/registry modifications with process creation or network usage
- **`AN0974` Analytic 0974** · Linux
  Detects usage of shared memory directories (/dev/shm, /run/shm) for temporary storage of obfuscated, encoded, or executable data without persistence to disk.
  - *Log sources:* `auditd:SYSCALL (open, write, unlink)`; `linux:osquery (file_events.path)`
  - *Tune:* `PathPrefix` — Shared memory mount path used (e.g., /dev/shm/ or /run/shm/); `FilenameRegex` — Regex to match non-standard, suspicious, or encoded filenames; `ExecCorrelationWindow` — Time window to correlate process execution from shared memory directories

---

### T1027.012 — LNK Icon Smuggling
<a id="t1027012"></a>

**Detection strategy:** Detection Strategy for LNK Icon Smuggling (`DET0405`)  
**Platforms:** Windows  
**ATT&CK:** [T1027.012](https://attack.mitre.org/techniques/T1027/012/) · [detail page](../../techniques/stealth.md#t1027012)

- **`AN1134` Analytic 1134** · Windows
  Correlates LNK file execution with embedded resource extraction or suspicious network activity following initial launch, often leading to payload delivery via disguised icons.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=15)`; `WinEventLog:Sysmon (EventCode=3, 22)`
  - *Tune:* `ParentProcessName` — Can be tuned to focus on common launcher processes like explorer.exe or winword.exe.; `DestinationIP` — Filtered to exclude known good domains and internal IPs to reduce false positives.; `TimeWindow` — Time between LNK execution and subsequent suspicious activity may vary based on adversary delay.; `FileExtension` — Could be used to focus on .lnk files only or track associated dropped payloads like .dat, .exe, etc.

---

### T1027.013 — Encrypted/Encoded File
<a id="t1027013"></a>

**Detection strategy:** Encrypted or Encoded File Payload Detection Strategy (`DET0087`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1027.013](https://attack.mitre.org/techniques/T1027/013/) · [detail page](../../techniques/stealth.md#t1027013)

- **`AN0237` Analytic 0237** · Windows
  Detection of processes that load or decode encrypted/encoded files in memory and subsequently execute or inject them, indicating payload unpacking or memory-resident malware.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Security (EventCode=4688)`
  - *Tune:* `Image` — Path of decoder utilities (e.g., certutil.exe, powershell.exe) can vary across environments.; `CommandLine` — Base64/hex strings used may change per encoded payload.; `TimeWindow` — The duration between file decode and execution may differ across implementations.
- **`AN0238` Analytic 0238** · Linux
  Detection of suspicious use of shell utilities or scripts that decode or decrypt a payload and execute it without writing to disk.
  - *Log sources:* `auditd:SYSCALL (execve)`; `linux:Sysmon (EventCode=3, 22)`
  - *Tune:* `UserContext` — Normal usage of `base64`, `openssl`, or `gpg` varies by user/role.; `ProcessLineage` — Parent-child process chains may differ across deployments.; `TimeWindow` — Time between decode and execution is implementation-specific.
- **`AN0239` Analytic 0239** · macOS
  Detection of encoded payloads being decoded and executed in-memory using scripting tools or third-party decoders.
  - *Log sources:* `macos:unifiedlog (log stream)`; `macos:endpointsecurity (es_event_exec)`; `macos:unifiedlog (memory mapping)`
  - *Tune:* `ScriptContent` — Encoded payload content varies across adversaries.; `ExecutionChain` — Sequence of tools or scripts executed can differ.; `UserContext` — May depend on whether user is admin, daemon, or system account.

---

### T1027.014 — Polymorphic Code
<a id="t1027014"></a>

**Detection strategy:** Detection Strategy for Polymorphic Code Mutation and Execution (`DET0324`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1027.014](https://attack.mitre.org/techniques/T1027/014/) · [detail page](../../techniques/stealth.md#t1027014)

- **`AN0919` Analytic 0919** · Windows
  Identifies self-modifying executables that exhibit changes in binary hash, entropy, or memory sections during or between executions—often tied to dynamic unpacking or decryption behaviors.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=10)`
  - *Tune:* `EntropyThreshold` — Tune based on expected baseline entropy for executables; higher values may indicate polymorphic packing.; `TimeWindow` — Correlate rapid process spawn + image load activity suggesting mutation engine usage.; `ParentProcessPatterns` — Define expected or suspicious parent-child chains (e.g., script runner -> encoded PE)
- **`AN0920` Analytic 0920** · Linux
  Detects files or processes where execution results in frequent re-creation or modification of ELF binaries or interpreter scripts, often using chmod + execve with abnormal entropy.
  - *Log sources:* `auditd:SYSCALL (execve)`; `auditd:SYSCALL (mmap)`; `auditd:SYSCALL (chmod)`
  - *Tune:* `WriteExecThreshold` — Tune to alert on write followed by chmod + exec in quick succession.; `FileEntropyDeviation` — Detect high deviation from average entropy score of baseline ELF/script files.; `ExecutionFrequency` — Abnormal burst executions of file with identical functionality but varying hash.
- **`AN0921` Analytic 0921** · macOS
  Tracks modification of executables or interpreter payloads (e.g., Mach-O, dylib) that mutate across runs—using scripting engines, JIT compilers, or side-loaded plugins.
  - *Log sources:* `macos:unifiedlog (code signature/memory protection)`; `fs:fsusage (file open/write)`; `macos:endpointsecurity (ES_EVENT_TYPE_NOTIFY_EXEC)`; `macos:endpointsecurity (ES_EVENT_TYPE_NOTIFY_MMAP)`
  - *Tune:* `ScriptEnginePatterns` — Detection may vary based on whether Python/Swift/AppleScript is used to mutate payloads.; `MachOEntropyThreshold` — Entropy tuning based on expected baseline for system vs user binaries.; `SignedBinaryChangeRate` — Helps flag apps that change but maintain signed status across invocations.

---

### T1027.015 — Compression
<a id="t1027015"></a>

**Detection strategy:** Detection Strategy for Compressed Payload Creation and Execution (`DET0281`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1027.015](https://attack.mitre.org/techniques/T1027/015/) · [detail page](../../techniques/stealth.md#t1027015)

- **`AN0782` Analytic 0782** · Windows
  Monitors for compression tool usage (e.g., 7zip, WinRAR, MakeCab) that follows or precedes file modification, suspicious file types (e.g., .exe, .dll) being compressed, or dropped from self-extracting archives followed by immediate execution.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=11)`
  - *Tune:* `CompressedFileType` — Zip, .rar, .cab, .gz – tune based on expected legitimate use of compression in environment; `SFXExecutionDelay` — Expected time between archive unpacking and first execution – short delays are suspicious; `UserContext` — Restrict detection to non-admin or interactive users if excessive FPs from sys admin activity
- **`AN0783` Analytic 0783** · Linux
  Detects sequential command-line compression utilities (e.g., gzip, tar, zip, 7z) followed by execution of unpacked files, especially in temp directories or under non-standard locations like /dev/shm or /tmp with ELF binaries.
  - *Log sources:* `auditd:SYSCALL (execve)`; `auditd:SYSCALL (write)`; `auditd:SYSCALL (openat)`; `auditd:SYSCALL (chmod)`
  - *Tune:* `PathRegex` — Flag compressed archives extracted to /tmp, /dev/shm, or user’s home dir; `CompressionToolPatterns` — gzip, tar, bzip2, xz, 7z – tune to suppress admin packaging workflows; `ExecutionAfterUnpackWindow` — How soon a new file is executed after it’s unpacked
- **`AN0784` Analytic 0784** · macOS
  Identifies archive utilities (e.g., ditto, unzip, xar, pkgutil) used to extract payloads to non-standard paths, then correlates with execution or file permission changes (e.g., `chmod +x`) and process spawns from decompressed location.
  - *Log sources:* `macos:unifiedlog (Process launch)`; `macos:unifiedlog (filesystem events)`; `fs:fsusage (file open/write)`
  - *Tune:* `DecompressionPathMatch` — Target unusual extraction paths (~/Library/, /tmp/, /private/tmp/); `ToolBinaryNames` — List of decompression utilities used in the environment; `FollowOnExecutionDelta` — Time between decompression and first binary execution

---

### T1027.016 — Junk Code Insertion
<a id="t1027016"></a>

**Detection strategy:** Detection Strategy for Junk Code Obfuscation with Suspicious Execution Patterns (`DET0322`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1027.016](https://attack.mitre.org/techniques/T1027/016/) · [detail page](../../techniques/stealth.md#t1027016)

- **`AN0913` Analytic 0913** · Windows
  Detects the presence of executables with high NOP padding, unusually large binary size for their function, and follow-on execution or memory injection from such files, especially when originating from temp or user-space paths.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `NOPThreshold` — High proportion of 0x90 opcodes indicating junk code – tune to suppress noise from some packing tools; `ExecutableSizeThreshold` — Size range for abnormally large binaries relative to their runtime behavior; `TimeWindow` — Window between file creation and execution – short intervals may indicate staged payload execution
- **`AN0914` Analytic 0914** · Linux
  Detects ELF binaries written to disk that demonstrate anomalous file size or entropy, quickly followed by execution or memory region writes into remote processes (e.g., using ptrace).
  - *Log sources:* `auditd:SYSCALL (write)`; `auditd:SYSCALL (execve)`; `auditd:SYSCALL (SYSCALL ptrace/mprotect)`
  - *Tune:* `BinarySizeThreshold` — Used to flag binaries much larger than typical shell utilities or payloads; `MemoryWriteTargets` — Which processes are allowed ptrace/mprotect – can limit to suspicious child-to-parent targeting; `ExecutionAfterWriteWindow` — Temporal threshold for file write to execution
- **`AN0915` Analytic 0915** · macOS
  Identifies Mach-O binaries dropped into temporary directories with abnormally high binary size or padding patterns, followed by privilege escalation, `exec`, or memory mapping of other processes.
  - *Log sources:* `macos:endpointsecurity (ES_EVENT_TYPE_NOTIFY_EXEC)`; `macos:endpointsecurity (ES_EVENT_TYPE_NOTIFY_MMAP)`; `macos:endpointsecurity (ES_EVENT_TYPE_NOTIFY_OPEN)`
  - *Tune:* `TempFilePaths` — Track dropped executables in ~/Library/, /tmp/, or /private/tmp/; `MachOPaddingThreshold` — Define padding size or section entropy anomalies in Mach-O file format; `FollowOnPrivilegeEscalation` — Detects whether the binary attempts privilege escalation within short execution window

---

### T1027.017 — SVG Smuggling
<a id="t1027017"></a>

**Detection strategy:** Detection Strategy for SVG Smuggling with Script Execution and Delivery Behavior (`DET0510`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1027.017](https://attack.mitre.org/techniques/T1027/017/) · [detail page](../../techniques/stealth.md#t1027017)

- **`AN1407` Analytic 1407** · Windows
  Detects suspicious SVG file creation or download events followed by script engine execution (e.g., wscript.exe, mshta.exe, rundll32.exe), network callbacks, or browser-based credential collection.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=3, 22)`
  - *Tune:* `TimeWindow` — Threshold between SVG file write and script execution (e.g., < 60s); `ParentProcessWhitelist` — Allowlisted script engines that may invoke browsers or JS in benign cases; `FileExtensionPattern` — Regex or string match for .svg, .svgz, or embedded .svg inside HTML or PDF
- **`AN1408` Analytic 1408** · Linux
  Detects downloaded SVG files followed by execution of browser processes or tools like xdg-open, and rapid follow-on network connections or process spawns to interpreters like python or bash.
  - *Log sources:* `auditd:SYSCALL (open, write)`; `auditd:SYSCALL (execve)`; `NSM:Flow (Outbound HTTP/S)`
  - *Tune:* `TargetPaths` — Suspicious write locations such as /tmp/, ~/Downloads/; `ExecutionContext` — Processes spawned by browsers or svg-viewing apps that invoke interpreters; `NetworkDestinations` — URLs/IPs contacted post-SVG access – may reflect initial C2
- **`AN1409` Analytic 1409** · macOS
  Detects SVGs downloaded via browser that invoke AppleScript, osascript, or JavaScriptCore processes, followed by network egress or file drop to LaunchAgents or ~/Library.
  - *Log sources:* `macos:endpointsecurity (ES_EVENT_TYPE_NOTIFY_EXEC)`; `macos:unifiedlog (subsystem: com.apple.WebKit or com.apple.WebKit.Networking)`
  - *Tune:* `ScriptEngines` — Scriptable binaries such as osascript, jsc, JavaScriptCore – may vary by OS version; `UserContext` — Restrict to non-system users or only specific login sessions; `EmbeddedContentIndicators` — SVGs embedded inside PDFs or HTML with script-based triggers

---

### T1036 — Masquerading
<a id="t1036"></a>

**Detection strategy:** Behavioral Detection of Masquerading Across Platforms via Metadata and Execution Discrepancy (`DET0127`)  
**Platforms:** Containers, ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1036](https://attack.mitre.org/techniques/T1036/) · [detail page](../../techniques/stealth.md#t1036)

- **`AN0355` Analytic 0355** · Windows
  Adversary renames LOLBINs or deploys binaries with spoofed file names, internal PE metadata, or misleading icons to appear legitimate. File creation is followed by execution or service registration inconsistent with known usage.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:System (EventCode=7045)`
  - *Tune:* `OriginalFilenameMismatch` — Compare executable file name with PE metadata OriginalFilename field; `KnownSystemUtilityPaths` — Tune based on expected installation directories for signed binaries; `TimeWindow` — Correlation window between file creation and service/process execution
- **`AN0356` Analytic 0356** · Linux
  Adversary drops renamed binaries in uncommon directories (e.g., /tmp, /dev/shm) or uses special characters in names (e.g., trailing space, Unicode RLO). Execution or cronjob registration follows shortly after file drop.
  - *Log sources:* `auditd:SYSCALL (execve)`; `linux:syslog (rename)`; `linux:osquery (file_events)`
  - *Tune:* `DropLocationPattern` — Directories where new binaries are suspicious (e.g., /tmp); `FilenameAnomalies` — Regex for Unicode/RLO/space abuse in filenames; `ExecutionDelayWindow` — Time range between file write and execution used for joining
- **`AN0357` Analytic 0357** · macOS
  Adversary creates disguised launch daemons or apps with misleading names and bundle metadata (e.g., Info.plist values inconsistent with binary path or icon). Launch is correlated with user logon or persistence setup.
  - *Log sources:* `macos:unifiedlog (process)`; `macos:endpointsecurity (ES_EVENT_TYPE_NOTIFY_EXEC)`; `fs:fileevents (/var/log/install.log)`
  - *Tune:* `InfoPlistDiscrepancy` — Mismatch between bundle metadata and file system path/name; `LaunchAgentPath` — Unusual LaunchDaemon/LaunchAgent paths can be tuned per org; `ExecutionTrigger` — Window between install and first execution (e.g., at user login)
- **`AN0358` Analytic 0358** · Containers
  Adversary uses renamed container images, injects files into containers with misleading names or metadata (e.g., renamed system binaries), and executes them during startup or scheduled jobs.
  - *Log sources:* `containerd:runtime (/var/log/containers/*.log)`; `docker:events (docker.events.json)`; `ebpf:syscalls (file_write)`
  - *Tune:* `ImageLabelMismatch` — Tune detection based on mismatch between image name and labels; `StartupScriptLocation` — Detect binaries added or modified in startup path (e.g., /entrypoint.sh); `ProcessNamePattern` — Allow tuning based on suspicious binary naming inside containers
- **`AN0359` Analytic 0359** · ESXi
  Adversary places scripts or binaries with misleading names in /etc/rc.local.d or /var/spool/cron, or registers services with legitimate-sounding names not present in default ESXi builds.
  - *Log sources:* `esxi:hostd (registers services with legitimate-sounding names)`; `esxi:shell (scripts or binaries with misleading names)`
  - *Tune:* `ServiceNameBaseline` — Tune based on default service names vs. suspicious new entries; `ScriptFilePath` — Watch for new binaries/scripts in boot or cron folders; `ExecutionContext` — Determine if execution happens at boot or scheduled interval

---

### T1036.001 — Invalid Code Signature
<a id="t1036001"></a>

**Detection strategy:** Invalid Code Signature Execution Detection via Metadata and Behavioral Context (`DET0031`)  
**Platforms:** Windows, macOS  
**ATT&CK:** [T1036.001](https://attack.mitre.org/techniques/T1036/001/) · [detail page](../../techniques/stealth.md#t1036001)

- **`AN0089` Analytic 0089** · Windows
  Execution of binaries with invalid digital signatures, where metadata claims code is signed but validation fails. Behavior is often correlated with suspicious parent processes or unexpected execution paths.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Windows Defender (Operational log)`; `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`
  - *Tune:* `SignatureValidationResult` — Allow tuning to include 'invalid', 'expired', or 'untrusted root' based on environment tolerance; `ParentProcessName` — Helps tune false positives by limiting to suspicious parent process executions; `TimeWindow` — Defines correlation window between metadata check and process execution
- **`AN0090` Analytic 0090** · macOS
  Binaries or applications executed with tampered or unverifiable code signatures. Often tied to Gatekeeper bypasses, App Translocation, or use of unsigned launch daemons by untrusted users.
  - *Log sources:* `macos:unifiedlog (subsystem:syspolicyd)`; `macos:endpointsecurity (ES_EVENT_TYPE_NOTIFY_EXEC)`; `fs:fileevents (/var/log/install.log)`
  - *Tune:* `CodeSigningStatus` — Filters such as 'Unsigned', 'NotTrusted', or 'ModifiedSinceSigning' may vary by policy enforcement level; `UserContext` — Tune whether detection applies to all users or excludes trusted admin accounts; `ExecutablePathPrefix` — Enable tuning for known valid locations (e.g., /Applications) vs. suspicious paths (/Users/Shared)

---

### T1036.002 — Right-to-Left Override
<a id="t1036002"></a>

**Detection strategy:** Right-to-Left Override Masquerading Detection via Filename and Execution Context (`DET0527`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1036.002](https://attack.mitre.org/techniques/T1036/002/) · [detail page](../../techniques/stealth.md#t1036002)

- **`AN1461` Analytic 1461** · Windows
  Execution of files containing right-to-left override characters (U+202E) to masquerade true file extensions. Often found in phishing payloads or file downloads.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`; `WinEventLog:Windows Defender (Operational)`
  - *Tune:* `FilenamePattern` — RTLO variants such as \u202E, %E2%80%AE, or byte-encoded forms; `ExecutionContext` — Allows tuning for untrusted sources, e.g., browser downloads or email attachments; `TimeWindow` — Defines correlation between file creation and process execution
- **`AN1462` Analytic 1462** · macOS
  Execution of files with reversed filename extensions using Unicode RTLO character. Frequently used to deceive Gatekeeper and users in Safari or Mail-based phishing.
  - *Log sources:* `macos:unifiedlog (subsystem=com.apple.lsd)`; `macos:endpointsecurity (ES_EVENT_TYPE_NOTIFY_EXEC)`; `fs:quarantine (/var/log/quarantine.log)`
  - *Tune:* `FilenameDisplay` — Whether user-facing tools display the spoofed name or the true extension; `GatekeeperBypassFlag` — Whether the execution bypassed translocation or quarantine checks; `UserContext` — Scope detection to untrusted or non-admin users
- **`AN1463` Analytic 1463** · Linux
  Execution of user-downloaded or created scripts with hidden extensions due to RTLO character insertion in filename, often present in desktop environments or phishing campaigns.
  - *Log sources:* `auditd:SYSCALL (execve)`; `linux:osquery (event-based)`; `desktop:file_manager (nautilus, dolphin, or gvfs logs)`
  - *Tune:* `ExtensionMismatch` — Filter based on mismatched visible extension vs. magic bytes or mime-type; `ProcessLineage` — Correlation between file open and subsequent script interpreter invocation; `FilenameEntropy` — Suspicious Unicode sequences or byte entropy in filenames

---

### T1036.003 — Rename Legitimate Utilities
<a id="t1036003"></a>

**Detection strategy:** Renamed Legitimate Utility Execution with Metadata Mismatch and Suspicious Path (`DET0005`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1036.003](https://attack.mitre.org/techniques/T1036/003/) · [detail page](../../techniques/stealth.md#t1036003)

- **`AN0012` Analytic 0012** · Windows
  Execution of binaries where the on-disk filename does not match PE metadata such as OriginalFilename or InternalName. Often observed with renamed LOLBAS or system binaries like rundll32, powershell, or psexec.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=11)`; `EDR:AMSI`
  - *Tune:* `ImagePath` — Filter by suspicious or non-standard directory paths; `PEInternalNameMismatch` — Enable tuning based on mismatch rules between metadata and disk filename; `CommandLinePattern` — Flag unusual or rare argument combinations for LOLBAS-like tools
- **`AN0013` Analytic 0013** · macOS
  Execution of renamed or relocated native macOS utilities with uncommon names or non-default paths (e.g., renamed `osascript`, `bash`, or `curl`).
  - *Log sources:* `macos:unifiedlog (subsystem=com.apple.process)`; `macos:endpointsecurity (ES_EVENT_TYPE_NOTIFY_EXEC)`; `fs:fileevents (/var/log/quarantine.log)`
  - *Tune:* `PathDeviation` — Path deviation from expected directory (e.g., /usr/bin/ vs /tmp/); `BinaryHashReputation` — Enable tuning based on hash matching known signed versions vs suspicious clones; `UserRole` — Scope detections based on non-admin users using admin-level tools
- **`AN0014` Analytic 0014** · Linux
  Execution of renamed common utilities (e.g., `bash`, `nc`, `python`, `sh`) from atypical directories or with names intended to deceive defenders or EDRs.
  - *Log sources:* `auditd:SYSCALL (execve)`; `linux:osquery (event-based)`; `linux:syslog (cron activity)`
  - *Tune:* `ExecutionPath` — Path anomalies such as execution from /dev/shm, /tmp, or user home directories; `ParentProcessContext` — Unusual lineage such as scripts invoking renamed tools; `TimeWindow` — Correlate between file rename and immediate execution

---

### T1036.004 — Masquerade Task or Service
<a id="t1036004"></a>

**Detection strategy:** Detection of Masqueraded Tasks or Services with Suspicious Naming and Execution (`DET0117`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1036.004](https://attack.mitre.org/techniques/T1036/004/) · [detail page](../../techniques/stealth.md#t1036004)

- **`AN0324` Analytic 0324** · Windows
  Creation or modification of Windows services or scheduled tasks with names or descriptions mimicking legitimate entries, followed by anomalous execution of untrusted binaries or LOLBAS.
  - *Log sources:* `WinEventLog:System (EventCode=7045)`; `WinEventLog:Security (EventCode=4698)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `TaskNameSimilarityThreshold` — Similarity threshold for comparing new task/service names to known legitimate names (e.g., Levenshtein distance); `BinaryReputationScore` — Confidence level required for allowing a binary, often from unsigned or untrusted source; `ExecutionContext` — Whether the execution came from SYSTEM, service accounts, or user contexts
- **`AN0325` Analytic 0325** · Linux
  Creation or modification of `systemd` service units or cron jobs using deceptive naming and untrusted command paths, often followed by lateral network activity or privilege escalation.
  - *Log sources:* `auditd:CONFIG_CHANGE (/var/log/audit/audit.log)`; `linux:osquery (scheduled/real-time)`; `linux:cron (cron activity)`
  - *Tune:* `UnitFilePath` — Unusual or user-space paths for systemd unit files; `ServiceNameDeviation` — Detect units with names similar to legitimate ones (e.g., `networks.service` instead of `network.service`); `ExecStartPath` — Track uncommon or suspicious binaries in `ExecStart=` directives
- **`AN0326` Analytic 0326** · macOS
  Creation of LaunchAgents or LaunchDaemons with names resembling known system services but executing non-Apple signed code or scripts.
  - *Log sources:* `fs:fileevents (/Library/LaunchDaemons/*.plist, ~/Library/LaunchAgents/*.plist)`; `macos:endpointsecurity (ES_EVENT_TYPE_NOTIFY_EXEC)`; `macos:unifiedlog (subsystem=com.apple.launchservices)`
  - *Tune:* `PlistLabelSimilarity` — Detect plists with labels that closely resemble legitimate ones (e.g., `com.apple.updates.plist`); `UnsignedBinaryExecution` — Toggle sensitivity for unsigned binaries or scripts launched by daemons; `UserContext` — Scope detection based on whether LaunchAgent ran in user or system context

---

### T1036.005 — Match Legitimate Resource Name or Location
<a id="t1036005"></a>

**Detection strategy:** Detection Strategy for Masquerading via Legitimate Resource Name or Location (`DET0347`)  
**Platforms:** Containers, ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1036.005](https://attack.mitre.org/techniques/T1036/005/) · [detail page](../../techniques/stealth.md#t1036005)

- **`AN0983` Analytic 0983** · Windows
  Detects processes or binaries executed from trusted directories (e.g., System32) or using trusted names (e.g., svchost.exe) where the metadata, hash, or parent process does not align with legitimate activity patterns.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=11)`
  - *Tune:* `trusted_directory_list` — Paths such as C:\Windows\System32 that adversaries may abuse; `process_baseline_age` — Time window to determine process novelty (e.g., 30 days)
- **`AN0984` Analytic 0984** · Linux
  Detects renamed binaries or scripts placed into trusted paths like /usr/bin or /lib with mismatched metadata or unexpected creation/modification times.
  - *Log sources:* `auditd:SYSCALL (execve)`; `auditd:SYSCALL (open)`; `auditd:SYSCALL (rename)`; `linux:osquery (Filesystem modifications to trusted paths)`
  - *Tune:* `monitored_paths` — Set of system or application directories considered sensitive or trusted; `hash_validation_window` — Timeframe during which a newly created file should have its hash validated (e.g., within 5 minutes of write)
- **`AN0985` Analytic 0985** · macOS
  Detects binaries or launch daemons in /System/Library or /Applications with mismatched bundle names, unexpected metadata, or improper installation origin.
  - *Log sources:* `macos:unifiedlog (log collect from launchd and process start)`; `fs:fsusage (filesystem monitoring of exec/open)`
  - *Tune:* `expected_bundle_names` — List of known application names and paths to validate against; `signed_by_apple_check` — Toggle to enforce checks for Apple-signed binaries in trusted directories
- **`AN0986` Analytic 0986** · Containers
  Detects malicious containers or pods using names, labels, or namespaces that mimic legitimate workloads; also checks for image layer mismatches and unauthorized resource deployments.
  - *Log sources:* `kubernetes:apiserver (Resource creation and update logs)`; `containerd:events (Docker or containerd image pulls and process executions)`
  - *Tune:* `trusted_namespace_list` — List of namespaces that should not be used by unprivileged users or workloads; `image_baseline_hashes` — Reference hashes of approved container images
- **`AN0987` Analytic 0987** · ESXi
  Detects VIBs, scripts, or binaries placed into directories like /bin or /etc/vmware with names mimicking standard ESXi components. Also monitors unauthorized creation of services.
  - *Log sources:* `esxi:vmkernel (Exec)`; `esxi:vmkernel (module load)`; `esxi:hostd (Service events)`; `esxi:hostd (task creation events)`
  - *Tune:* `esxi_baseline_file_list` — Known good binaries and their expected paths; `service_creation_alert_threshold` — Threshold for unknown service names or mismatched digital signatures

---

### T1036.006 — Space after Filename
<a id="t1036006"></a>

**Detection strategy:** Masquerading via Space After Filename - Behavioral Detection Strategy (`DET0292`)  
**Platforms:** Linux, macOS  
**ATT&CK:** [T1036.006](https://attack.mitre.org/techniques/T1036/006/) · [detail page](../../techniques/stealth.md#t1036006)

- **`AN0812` Analytic 0812** · Linux
  Detection of file execution where the file name contains a trailing space to masquerade as a known executable. Adversaries may exploit the way command line interpreters handle file names with trailing whitespace.
  - *Log sources:* `auditd:SYSCALL (execve)`; `linux:syslog (application or system execution logs)`
  - *Tune:* `ExecutableNameTrailingSpace` — This detection may vary based on how different shells and file systems treat trailing spaces. Normalize or regex-match file names with trailing space.; `UserContext` — Monitor for untrusted or lower-privileged users executing suspicious scripts with disguised names.; `TimeWindow` — Tune for execution patterns during off-hours to reduce false positives.
- **`AN0813` Analytic 0813** · macOS
  Execution of renamed or dropped files with a trailing space to deceive users or analysts, especially in LaunchAgents or LaunchDaemons.
  - *Log sources:* `macos:unifiedlog (process events)`; `fs:fsusage (filesystem activity)`
  - *Tune:* `FilenamePattern` — Tunable regex or path rule to match common masquerade attempts (e.g., 'Terminal .app').; `TargetPath` — Analytic can be scoped to key directories (e.g., /Users/Library/LaunchAgents/).; `UserContext` — Focus detection on suspicious user sessions or service creation under non-admin users.

---

### T1036.007 — Double File Extension
<a id="t1036007"></a>

**Detection strategy:** Detection Strategy for Double File Extension Masquerading (`DET0366`)  
**Platforms:** Windows  
**ATT&CK:** [T1036.007](https://attack.mitre.org/techniques/T1036/007/) · [detail page](../../techniques/stealth.md#t1036007)

- **`AN1033` Analytic 1033** · Windows
  Detects adversary behavior where a file with a benign-looking first extension (e.g., .txt, .jpg) ends with a dangerous second extension (e.g., .exe, .scr), and is subsequently executed. The behavior chain includes file creation with misleading naming and user or system-initiated process execution from the disguised file.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=11)`
  - *Tune:* `benign_extensions` — List of extensions typically used to masquerade malicious files (.txt, .jpg, .doc, .pdf); `dangerous_extensions` — List of true executable extensions that may be abused (.exe, .scr, .hta, .lnk); `monitored_paths` — Specific directories to focus on (e.g., Downloads folder, %TEMP%, Desktop); `TimeWindow` — Duration between file creation and process execution to correlate activity; `UserContext` — Whether the behavior occurs in a standard user session or elevated context

---

### T1036.008 — Masquerade File Type
<a id="t1036008"></a>

**Detection strategy:** Detection Strategy for Masquerading via File Type Modification (`DET0226`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1036.008](https://attack.mitre.org/techniques/T1036/008/) · [detail page](../../techniques/stealth.md#t1036008)

- **`AN0630` Analytic 0630** · Windows
  Detects behavior where files with non-executable or misleading extensions (e.g., .jpg, .txt) are created or modified but subsequently executed as binaries based on internal file headers or abnormal parent process lineage. This includes identifying polyglot files or malformed magic bytes indicative of masquerading attempts.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `benign_extensions` — List of non-executable file types commonly used to mask payloads (.jpg, .txt, .gif); `monitored_directories` — Targeted directories for initial access and downloads (e.g., %TEMP%, Downloads, AppData); `MagicByteMismatchThreshold` — Detection tolerance for mismatches between extension and file signature (magic bytes); `TimeWindow` — Time range between file creation and first execution; `ParentProcessAnomalyScore` — Anomaly score threshold for suspicious parent-child process combinations
- **`AN0631` Analytic 0631** · Linux
  Detects when a script or binary is named with misleading or benign-looking extensions (.jpg, .doc) and is then executed via command line or a scheduled task. Includes ELF header mismatches and content-type inconsistencies on disk.
  - *Log sources:* `auditd:SYSCALL (execve)`; `linux:osquery (Read headers and detect MIME type mismatch)`
  - *Tune:* `benign_extensions` — Linux-targeted masquerade extensions (.jpg, .pdf, .png); `HeaderInspectionEnabled` — Whether to parse file signatures or MIME types from file headers; `ExecPathScope` — Monitored directory scope for adversarial execution (e.g., /tmp/, /home/username/Downloads)
- **`AN0632` Analytic 0632** · macOS
  Detects binaries disguised as media or document types through extension-only masquerading or by modifying the file signature. Observes execution of files whose extension is not typically executable (.jpg, .txt), yet have valid Mach-O headers or execute via Terminal or launch services.
  - *Log sources:* `macos:unifiedlog (launchservices events for misleading extensions)`
  - *Tune:* `LaunchAgentScope` — Scope of services monitored for unusual launches (e.g., Finder, Terminal, Preview); `SignatureEnforcementLevel` — How strictly the detection checks header validity vs. file extension; `TimeWindow` — Time range for linking file modification and execution events

---

### T1036.009 — Break Process Trees
<a id="t1036009"></a>

**Detection strategy:** Detection Strategy for Masquerading via Breaking Process Trees (`DET0443`)  
**Platforms:** Linux, macOS  
**ATT&CK:** [T1036.009](https://attack.mitre.org/techniques/T1036/009/) · [detail page](../../techniques/stealth.md#t1036009)

- **`AN1223` Analytic 1223** · Linux
  Detects anomalous process execution patterns where a process's parent terminates quickly after process creation or is re-parented to 'init' (PID 1), often indicating double-fork or daemon-style detachment. These behaviors sever the parent-child relationship and obscure the execution origin in process tree analysis.
  - *Log sources:* `auditd:SYSCALL (fork/clone/daemon syscall tracing)`; `auditd:SYSCALL (execve of re-parented process)`
  - *Tune:* `TimeWindow` — Maximum time between parent and child process creation and parent process termination; `ReparentingDetectionScope` — Scope for detecting unexpected re-parenting to init/systemd; `ExecutableScope` — Subset of monitored executables or services likely to abuse double-fork
- **`AN1224` Analytic 1224** · macOS
  Detects execution patterns where a child process is detached from its original parent, often showing up under 'launchd' (PID 1) with no parent lineage. These breakages in the process tree are indicative of evasive techniques using `daemon()`, `fork()` or background execution flags.
  - *Log sources:* `macos:unifiedlog (Process creation with parent PID of 1 (launchd))`; `fs:fsusage (Detached process execution with no associated parent)`
  - *Tune:* `AnomalyParentPID` — Triggering PID used to flag abnormal child adoption (commonly PID 1); `AllowedServices` — Allowlist of background daemons legitimately using launchd as parent; `ProcessNameEntropy` — Entropy score threshold for abnormal process names in detached state

---

### T1036.010 — Masquerade Account Name
<a id="t1036010"></a>

**Detection strategy:** Detection Strategy for Masquerading via Account Name Similarity (`DET0383`)  
**Platforms:** Containers, Identity Provider, Linux, Windows  
**ATT&CK:** [T1036.010](https://attack.mitre.org/techniques/T1036/010/) · [detail page](../../techniques/stealth.md#t1036010)

- **`AN1077` Analytic 1077** · Windows
  Detects adversary behavior where a newly created or renamed user account closely resembles existing service or administrator accounts to blend in and avoid detection. Common patterns include prefix/suffix modifications, homoglyphs, or use of names like 'admin1', 'adm1n', or 'backup_help'.
  - *Log sources:* `WinEventLog:Security (EventCode=4720)`; `windows:osquery (User enumeration with creation/last modified timestamps)`
  - *Tune:* `SimilarityThreshold` — Defines how close in Levenshtein or visual distance an account name must be to a legitimate one to raise an alert.; `MonitoredAccountList` — Set of known legitimate accounts to compare new account names against.; `TimeWindow` — Period within which anomalous account creation or renaming is evaluated in relation to discovery or deletion activity.
- **`AN1078` Analytic 1078** · Linux
  Detects creation or renaming of accounts with names that closely match known service, root, or admin accounts. Behavior often follows account discovery or deletion, attempting to blend into system activity logs using trusted name conventions.
  - *Log sources:* `auditd:SYSCALL (adduser)`; `auditd:SYSCALL (usermod, or account rename system calls)`; `linux:osquery (Listing of /etc/passwd and /etc/shadow metadata)`
  - *Tune:* `AllowedSystemAccounts` — Whitelist of legitimate service accounts used for validation.; `LevenshteinThreshold` — Edit distance sensitivity between created account and existing account names.; `ScriptInitiatorDetection` — Whether to flag account creation events triggered from suspicious scripts or shell histories.
- **`AN1079` Analytic 1079** · Identity Provider
  Detects adversary creation of cloud or IdP accounts whose names resemble existing privileged or service accounts. May indicate preparation for privilege escalation or defense evasion.
  - *Log sources:* `azure:audit (Add user)`; `azure:audit (Rename user)`; `saas:okta (User lifecycle events)`
  - *Tune:* `RoleScope` — Whether created users have privileged or scoped roles assigned at creation.; `NamingHeuristics` — Regex patterns or heuristics for detecting suspicious naming conventions (e.g., helpdesk_support_, root-admin).
- **`AN1080` Analytic 1080** · Containers
  Monitors for the creation of accounts inside containers using names that resemble legitimate orchestrator or backup identities to mask adversary persistence.
  - *Log sources:* `docker:daemon (ExecCreate + usermod or useradd)`
  - *Tune:* `ContainerContextScope` — Limit detection to containers with persistent volumes or specific workloads; `MasqueradePatternList` — Custom list of commonly abused names to blend into container environments (e.g., kubelet, cronjob_sync)

---

### T1036.011 — Overwrite Process Arguments
<a id="t1036011"></a>

**Detection strategy:** Detection Strategy for Overwritten Process Arguments Masquerading (`DET0164`)  
**Platforms:** Linux  
**ATT&CK:** [T1036.011](https://attack.mitre.org/techniques/T1036/011/) · [detail page](../../techniques/stealth.md#t1036011)

- **`AN0466` Analytic 0466** · Linux
  Detects adversary behavior where the command-line arguments of a running process are overwritten in memory to spoof the process name, typically replacing it with a benign or misleading string. The detection correlates unexpected null byte sequences, discrepancies between `/proc/<pid>/cmdline` and process ancestry, and suspicious memory writes shortly after process start.
  - *Log sources:* `auditd:SYSCALL (execve, prctl, or ptrace activity affecting process memory or command-line arguments)`; `ebpf:tracepoints (Runtime memory overwrite of argv[] memory region)`
  - *Tune:* `TimeWindow` — Time threshold after process creation during which argv memory manipulation is expected to be rare; anomalies occurring outside this window may be more suspicious.; `AllowedArgvMismatchPatterns` — List of known legitimate processes where argv[0] mismatch is expected due to application logic or packaging quirks.; `ParentExecutableTrustList` — Trusted parent binaries allowed to spawn processes with altered command-line names.

---

### T1036.012 — Browser Fingerprint
<a id="t1036012"></a>

**Detection strategy:** Detection of Spoofed User-Agent (`DET0898`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1036.012](https://attack.mitre.org/techniques/T1036/012/) · [detail page](../../techniques/stealth.md#t1036012)

- **`AN2029` Analytic 2029** · Windows
  Process execution without GUI context (e.g., powershell.exe, wscript.exe) generates HTTP traffic with a spoofed User-Agent mimicking a legitimate browser. No corresponding UI application (e.g., msedge.exe) is active or in parent lineage. The User-Agent deviates from known enterprise baselines or contains spoofed platform indicators. User-Agent strings can be gathered with API calls such as `ShellExecuteW` to open the default browser on a socket to receive an HTTP reply, or by hard coding the User-Agent string for a specific browser.
  - *Log sources:* `NSM:Flow (Inbound HTTP POST with suspicious payload size or user-agent)`; `WinEventLog:Sysmon (EventCode=3, 22)`; `etw:Microsoft-Windows-Kernel-Process (API Calls)`
  - *Tune:* `HeaderSignatureMatch` — Specific HTTP header anomalies or patterns (e.g., spoofed User-Agent).; `UserAgentFingerprint` — Flag browser-based sessions; `NonBrowserProcessList` — List of non-browser binaries expected not to initiate web requests (e.g., powershell.exe, cscript.exe)
- **`AN2031` Analytic 2031** · Linux
  Detection of HTTP outbound requests with inconsistent or spoofed User-Agent headers from command-line tools (e.g., curl, wget, python requests) following interactive user shells or scheduled jobs outside of normal user session behavior.
  - *Log sources:* `NSM:Flow (http.log, conn.log)`; `auditd:SYSCALL (outbound connections)`; `auditd:SYSCALL (execve)`
  - *Tune:* `HeaderSignatureMatch` — Specific HTTP header anomalies or patterns (e.g., spoofed User-Agent).; `UserAgentFingerprint` — Flag browser-based sessions
- **`AN2032` Analytic 2032** · macOS
  Observation of scripted network requests (e.g., using osascript, curl, or python) that include mismatched or spoofed browser User-Agent strings compared to the typical macOS Safari or Chrome baseline, especially when triggered by non-interactive launch agents, login hooks, or background daemons.
  - *Log sources:* `macos:unifiedlog (network connection events)`; `NSM:Flow (Inbound HTTP POST with suspicious payload size or user-agent)`; `macos:unifiedlog (exec logs)`
  - *Tune:* `UserAgentFingerprint` — Flag browser-based sessions; `HeaderSignatureMatch` — Specific HTTP header anomalies or patterns (e.g., spoofed User-Agent).

---

### T1055 — Process Injection
<a id="t1055"></a>

**Detection strategy:** Behavioral Detection of Process Injection Across Platforms (`DET0508`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055/) · [detail page](../../techniques/stealth.md#t1055)

- **`AN1399` Analytic 1399** · Windows
  Detects process injection by correlating memory manipulation API calls (e.g., VirtualAllocEx, WriteProcessMemory), suspicious thread creation (e.g., CreateRemoteThread), and unusual DLL loads within another process's context.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=7)`; `etw:Microsoft-Windows-Kernel-Process (API calls)`
  - *Tune:* `AccessMask` — Specific access rights used during process handle acquisition, e.g., PROCESS_VM_WRITE; `TimeWindow` — Time correlation window between API calls and thread creation events; `InjectedProcessList` — Known high-value targets often abused for injection (e.g., lsass.exe, explorer.exe)
- **`AN1400` Analytic 1400** · Linux
  Detects ptrace- or memfd-based process injection through audit logs capturing system calls (e.g., ptrace, mmap) targeting running processes along with suspicious file descriptors or memory writes.
  - *Log sources:* `auditd:SYSCALL (ptrace, mmap, process_vm_writev)`; `auditd:SYSCALL (open)`; `linux:procfs (/proc/[pid]/maps, /proc/[pid]/mem)`
  - *Tune:* `TargetPIDThreshold` — Limit to sensitive or unexpected processes being targeted (e.g., sshd, init); `TimeWindow` — Correlate mmap or writev usage to process access within a short timeframe
- **`AN1401` Analytic 1401** · macOS
  Detects memory-based injection by monitoring `task_for_pid`, `mach_vm_write`, and dylib injection patterns through `DYLD_INSERT_LIBRARIES` or manual memory mapping.
  - *Log sources:* `macos:unifiedlog (subsystem=com.apple.security, library=libsystem_kernel.dylib)`; `macos:endpointsecurity (ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_MMAP)`; `macos:syslog (DYLD_INSERT_LIBRARIES anomalies)`
  - *Tune:* `TargetProcessSignature` — Expected signing identity or origin of process being injected; `MachSyscallContext` — Observed syscall combinations (e.g., task_for_pid followed by vm_write)

---

### T1055.001 — Dynamic-link Library Injection
<a id="t1055001"></a>

**Detection strategy:** Behavioral Detection of DLL Injection via Windows API (`DET0389`)  
**Platforms:** Windows  
**ATT&CK:** [T1055.001](https://attack.mitre.org/techniques/T1055/001/) · [detail page](../../techniques/stealth.md#t1055001)

- **`AN1095` Analytic 1095** · Windows
  Detects DLL injection through correlation of memory allocation and writing to remote process memory (e.g., VirtualAllocEx, WriteProcessMemory), followed by remote thread creation (e.g., CreateRemoteThread) that loads a suspicious or unsigned DLL using LoadLibrary or reflective loading.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=17)`
  - *Tune:* `InjectedDLLSignatureStatus` — Whether the DLL is unsigned, untrusted, or loaded from a non-standard path; `TimeWindow` — Temporal correlation threshold between memory operations and thread creation; `TargetProcessList` — List of sensitive or high-value processes targeted for injection (e.g., explorer.exe, winlogon.exe); `ParentProcessAnomalyThreshold` — Degree of deviation from expected parent-child lineage

---

### T1055.002 — Portable Executable Injection
<a id="t1055002"></a>

**Detection strategy:** Behavioral Detection of PE Injection via Remote Memory Mapping (`DET0106`)  
**Platforms:** Windows  
**ATT&CK:** [T1055.002](https://attack.mitre.org/techniques/T1055/002/) · [detail page](../../techniques/stealth.md#t1055002)

- **`AN0297` Analytic 0297** · Windows
  Detects PE injection through a behavioral sequence where one process opens (OpenProcess) a handle to another, allocates remote memory (VirtualAllocEx), writes a PE header (MZ) or shellcode (WriteProcessMemory), then initiates a new thread (CreateRemoteThread or NtCreateThreadEx) in that process—executing injected code in memory without touching disk. Optional: injects a trampoline or shellcode that unpacks/reflectively maps the payload.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Sysmon (EventCode=8)`; `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=11)`
  - *Tune:* `PayloadEntropyThreshold` — Controls for detecting high-entropy memory writes indicating shellcode or encrypted PE; `TargetProcessList` — High-value or sensitive processes that should never have remote threads injected; `TimeWindow` — Max allowed delay between memory write and thread execution; `ParentProcessAnomalyThreshold` — Used to filter legitimate process hierarchies vs anomalous injection sources

---

### T1055.003 — Thread Execution Hijacking
<a id="t1055003"></a>

**Detection strategy:** Behavioral Detection of Thread Execution Hijacking via Thread Suspension and Context Switching (`DET0295`)  
**Platforms:** Windows  
**ATT&CK:** [T1055.003](https://attack.mitre.org/techniques/T1055/003/) · [detail page](../../techniques/stealth.md#t1055003)

- **`AN0822` Analytic 0822** · Windows
  Detects hijacking of an existing thread (OpenThread) through a behavioral chain involving thread suspension (SuspendThread), memory modification (VirtualAllocEx + WriteProcessMemory), context manipulation (SetThreadContext), and thread resumption—all within another live process's address space (ResumeThread).
  - *Log sources:* `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Sysmon (EventCode=8)`; `etw:Microsoft-Windows-Kernel-Process (API Calls)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `TargetProcessList` — Sensitive processes that should never be targeted for thread hijack attempts; `TimeWindow` — Expected delay between SuspendThread and ResumeThread events; tight thresholds reduce evasion; `SuspiciousThreadContextRegions` — Memory regions or offsets that should not be targeted for SetThreadContext; `ParentProcessAnomalyThreshold` — Score deviation of the parent/child relationship in a thread injection chain

---

### T1055.004 — Asynchronous Procedure Call
<a id="t1055004"></a>

**Detection strategy:** Behavioral Detection of Asynchronous Procedure Call (APC) Injection via Remote Thread Queuing (`DET0100`)  
**Platforms:** Windows  
**ATT&CK:** [T1055.004](https://attack.mitre.org/techniques/T1055/004/) · [detail page](../../techniques/stealth.md#t1055004)

- **`AN0277` Analytic 0277** · Windows
  Detects malicious injection behavior involving memory allocation, remote thread queuing via APC (e.g., QueueUserAPC), and altered thread context within another live process to execute unauthorized code under legitimate context.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Sysmon (EventCode=8)`; `etw:Microsoft-Windows-Kernel-Process (APCQueueOperations)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `APCTargetProcessList` — Processes that are rarely or never valid targets for legitimate APC queuing (e.g., lsass.exe, winlogon.exe); `ThreadQueueDepthThreshold` — The number of APCs queued within a short time window that could signal abuse; `TimeWindow` — Expected latency between memory allocation and thread execution through APC; `UserContextSensitivity` — Used to filter based on expected vs unexpected user to target process pairings

---

### T1055.005 — Thread Local Storage
<a id="t1055005"></a>

**Detection strategy:** Detection Strategy for TLS Callback Injection via PE Memory Modification and Hollowing (`DET0467`)  
**Platforms:** Windows  
**ATT&CK:** [T1055.005](https://attack.mitre.org/techniques/T1055/005/) · [detail page](../../techniques/stealth.md#t1055005)

- **`AN1289` Analytic 1289** · Windows
  Detects thread local storage (TLS) callback injection by monitoring memory modifications to PE headers and TLS directory structures during or after process hollowing events, followed by anomalous thread behavior prior to main entry point execution.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Sysmon (EventCode=8)`; `EDR:memory (MemoryWriteToExecutable)`
  - *Tune:* `TargetProcessFilter` — Subset of processes whose TLS callbacks should not change post-load (e.g., explorer.exe, lsass.exe); `TimeWindowBetweenLoadAndTLSModification` — Acceptable delay between image load and memory tampering in .tls or .data sections; `AnomalousThreadStartThreshold` — Number of threads executing prior to main entry point that is considered suspicious; `PayloadEntropyThreshold` — Optional threshold to distinguish injected shellcode from benign memory writes

---

### T1055.008 — Ptrace System Calls
<a id="t1055008"></a>

**Detection strategy:** Detection Strategy for Ptrace-Based Process Injection on Linux (`DET0203`)  
**Platforms:** Linux  
**ATT&CK:** [T1055.008](https://attack.mitre.org/techniques/T1055/008/) · [detail page](../../techniques/stealth.md#t1055008)

- **`AN0579` Analytic 0579** · Linux
  Detects ptrace-based process injection by correlating audit logs of ptrace syscalls, memory modifications (e.g., poketext, pokedata), and suspicious register manipulation on a target process not normally debugged by the originator. Alerts on processes attempting to ptrace non-child or privileged processes, especially those followed by abnormal memory or execution behavior.
  - *Log sources:* `auditd:SYSCALL (mmap, ptrace, process_vm_writev or direct memory ops)`; `auditd:SYSCALL (execve)`; `linux:osquery (state=attached/debugged)`
  - *Tune:* `TargetProcessNameFilter` — List of sensitive or rarely-debugged processes (e.g., sshd, systemd, container daemons) to alert on if ptraced; `TimeWindowBetweenPtraceAndMemoryWrite` — Threshold time (e.g., <10 seconds) between ptrace attach and pokedata syscall; `UserContextMismatch` — Flag when UID of tracer differs from UID of target process (e.g., privilege escalation or container breakout); `ProcessRelationshipConstraint` — Allowlist relationships (e.g., parent-child) under which ptrace is considered benign

---

### T1055.009 — Proc Memory
<a id="t1055009"></a>

**Detection strategy:** Detection Strategy for /proc Memory Injection on Linux (`DET0541`)  
**Platforms:** Linux  
**ATT&CK:** [T1055.009](https://attack.mitre.org/techniques/T1055/009/) · [detail page](../../techniques/stealth.md#t1055009)

- **`AN1494` Analytic 1494** · Linux
  Detects adversary behavior where a process enumerates and modifies another process's memory using /proc/[pid]/maps and /proc/[pid]/mem files. This includes identifying gadgets via memory mappings and overwriting process memory via low-level file modification or dd usage.
  - *Log sources:* `auditd:SYSCALL (open/write to /proc/*/mem or /proc/*/maps)`; `auditd:SYSCALL (execve of dd or sed targeting /proc/*/mem)`; `linux:osquery (/proc/*/maps access)`
  - *Tune:* `TargetProcNameRegex` — Regex list of high-value processes attackers may inject into, such as `sshd`, `nginx`, or `sleep`; `TimeWindowBetweenMapAccessAndMemWrite` — Time span (e.g., <15s) between map read and memory write that may indicate enumeration-to-injection; `InvokerBinaryAllowlist` — Allowlist of processes allowed to access /proc/[pid]/mem (e.g., gdb, strace); `FileWriteThreshold` — Alert if written bytes to /proc/[pid]/mem exceed a suspicious threshold (e.g., >4096 bytes)

---

### T1055.011 — Extra Window Memory Injection
<a id="t1055011"></a>

**Detection strategy:** Detection Strategy for Extra Window Memory (EWM) Injection on Windows (`DET0217`)  
**Platforms:** Windows  
**ATT&CK:** [T1055.011](https://attack.mitre.org/techniques/T1055/011/) · [detail page](../../techniques/stealth.md#t1055011)

- **`AN0608` Analytic 0608** · Windows
  Detects adversary manipulation of Extra Window Memory (EWM) in a GUI process, where the attacker uses SetWindowLong or SetClassLong to redirect function pointers to injected shellcode stored in shared memory, then triggers execution via a window message like SendNotifyMessage.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=10)`; `etw:Microsoft-Windows-Win32k (SetWindowLong, SetClassLong, NtUserMessageCall, SendNotifyMessage, PostMessage)`; `WinEventLog:Security (EventCode=4688)`
  - *Tune:* `TargetWindowClassRegex` — Regex to scope suspicious or uncommon GUI class names registered by user-created processes; `ExecutionTriggerWindowMessage` — API calls like SendNotifyMessage or PostMessage that deliver execution to the shellcode location; `SharedSectionWriteThreshold` — Set byte count thresholds on suspicious memory writes to known shared sections; `TimeWindowSetWindowLongToMessageTrigger` — Define max time (e.g., <10s) between API call to set window memory and the message call to trigger it

---

### T1055.012 — Process Hollowing
<a id="t1055012"></a>

**Detection strategy:** Detection Strategy for Process Hollowing on Windows (`DET0382`)  
**Platforms:** Windows  
**ATT&CK:** [T1055.012](https://attack.mitre.org/techniques/T1055/012/) · [detail page](../../techniques/stealth.md#t1055012)

- **`AN1076` Analytic 1076** · Windows
  Detects adversary use of suspended process creation, using the CREATE_SUSPENDED flag via CreateProcess, followed by unmapping the memory of the child process (NtUnmapViewOfSection) and replacing it with malicious code via VirtualAllocEx/WriteProcessMemory, then SetThreadContext and ResumeThread to begin execution within the hollowed process.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Sysmon (EventCode=8)`; `etw:Microsoft-Windows-Kernel-Process (NtUnmapViewOfSection, VirtualAllocEx, WriteProcessMemory, SetThreadContext, ResumeThread)`
  - *Tune:* `HollowedImageNamePattern` — Regex to match common decoy executables used for hollowing (e.g., 'svchost.exe', 'notepad.exe'); `TimeWindow_ProcessCreateToResume` — Temporal threshold for unmap/write/execute sequence (e.g., within 5–10 seconds); `SuspendedProcessStartFlag` — CreateProcess flag used to identify suspended thread creation; `MemoryWriteSizeThreshold` — Minimum byte size to flag suspicious memory overwrite in hollowed process

---

### T1055.013 — Process Doppelgänging
<a id="t1055013"></a>

**Detection strategy:** Detection Strategy for Process Doppelgänging on Windows (`DET0544`)  
**Platforms:** Windows  
**ATT&CK:** [T1055.013](https://attack.mitre.org/techniques/T1055/013/) · [detail page](../../techniques/stealth.md#t1055013)

- **`AN1501` Analytic 1501** · Windows
  Detects adversary abuse of Transactional NTFS (TxF) and undocumented process loading mechanisms (e.g., NtCreateProcessEx) to create a hollowed process from an uncommitted, maliciously tainted file image in memory, later executed via NtCreateThreadEx.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Sysmon (EventCode=11)`; `etw:Microsoft-Windows-Kernel-Process (CreateTransaction, CreateFileTransacted, RollbackTransaction, NtCreateProcessEx, NtCreateThreadEx)`
  - *Tune:* `TransactionExecutableNamePattern` — Pattern of legitimate executables often used as doppelgänging targets (e.g., svchost.exe, calc.exe); `TimeWindow_TransactionToExecution` — Time delta between TxF rollback and thread creation in hollowed process; `ThreadStartEntropyThreshold` — Entropy level of thread start address in memory used to detect obfuscated shellcode; `TxF API Call Frequency Threshold` — Limit on CreateTransaction + RollbackTransaction sequences per process

---

### T1055.014 — VDSO Hijacking
<a id="t1055014"></a>

**Detection strategy:** Detection Strategy for VDSO Hijacking on Linux (`DET0448`)  
**Platforms:** Linux  
**ATT&CK:** [T1055.014](https://attack.mitre.org/techniques/T1055/014/) · [detail page](../../techniques/stealth.md#t1055014)

- **`AN1241` Analytic 1241** · Linux
  Detects the redirection of syscall execution flow via modification of VDSO code stubs or GOT entries to load and execute a malicious shared object through mmap and ptrace.
  - *Log sources:* `auditd:SYSCALL (ptrace, mmap, mprotect, open, dlopen)`; `auditd:memprotect (change from PROT_READ|PROT_WRITE to PROT_EXEC)`; `auditd:file-events (open of suspicious .so from non-standard paths)`; `linux:osquery (child process invoking dynamic linker post-ptrace)`
  - *Tune:* `SuspiciousSharedObjectPathRegex` — Regex to filter dynamic library paths outside of `/lib`, `/usr/lib`, etc. (e.g., `/tmp`, `/dev/shm`); `TimeWindow_PtraceToMmap` — Max delay allowed between ptrace attach and mmap/mprotect execution in target process; `ExecMemoryProtectionThreshold` — Flag when executable memory mappings deviate from normal runtime behavior; `AnomalousParentProcessList` — Parent processes unlikely to legitimately call ptrace (e.g., nginx, apache2, sshd)

---

### T1055.015 — ListPlanting
<a id="t1055015"></a>

**Detection strategy:** Detection Strategy for ListPlanting Injection on Windows (`DET0331`)  
**Platforms:** Windows  
**ATT&CK:** [T1055.015](https://attack.mitre.org/techniques/T1055/015/) · [detail page](../../techniques/stealth.md#t1055015)

- **`AN0941` Analytic 0941** · Windows
  Detects the use of message-based injection by monitoring for sequences involving FindWindow (EnumWindows or EnumChildWindows), VirtualAllocEx or related API calls, combined with suspicious PostMessage/SendMessage (e.g., LVM_SETITEMPOSITION) use to SysListView32 controls, followed by LVM_SORTITEMS invocation instead of WriteProcessMemory.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Sysmon (EventCode=8)`; `WinEventLog:Sysmon (EventCode=1)`; `etw:Microsoft-Windows-Win32k (SendMessage, PostMessage, LVM_*)`
  - *Tune:* `TimeWindow_PostMessage_to_LVM_SORTITEMS` — Defines temporal distance between payload copy and execution trigger; `TargetWindowClassName` — Restrict detection to SysListView32 or similar GUI elements; `UserContextAnomalyThreshold` — Adjusts detection sensitivity to users sending window messages across session boundaries; `InterprocessWindowMessagingFrequency` — Raise alert when rate of message-passing to foreign GUI processes exceeds baseline

---

### T1070 — Indicator Removal
<a id="t1070"></a>

**Detection strategy:** Behavioral Detection of Indicator Removal Across Platforms (`DET0184`)  
**Platforms:** Containers, ESXi, Linux, Office Suite, Windows, macOS  
**ATT&CK:** [T1070](https://attack.mitre.org/techniques/T1070/) · [detail page](../../techniques/stealth.md#t1070)

- **`AN0520` Analytic 0520** · Windows
  Monitors sequences involving deletion/modification of logs, registry keys, scheduled tasks, or prefetch files following suspicious process activity or elevated access escalation.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=23)`; `WinEventLog:Security (EventCode=1102)`; `WinEventLog:Sysmon (EventCode=13, 14)`
  - *Tune:* `TimeWindow` — Correlate indicator removal within X mins after persistence/setup activities; `TargetFilePathPattern` — Customize detection to log file paths or common registry hives
- **`AN0521` Analytic 0521** · Linux
  Detects deletion or overwriting of bash history, syslog, audit logs, and .ssh metadata following privilege elevation or suspicious process spawning.
  - *Log sources:* `auditd:SYSCALL (unlink, rename, open)`; `linux:cli (cleared or truncated .bash_history)`
  - *Tune:* `MonitoredPaths` — Adjust based on syslog/auditd file paths (/var/log/messages, /var/log/audit/audit.log); `UserContext` — Scope to root/sudo usage or anomalous user behavior
- **`AN0522` Analytic 0522** · macOS
  Detects clearing of unified logs, deletion of plist files tied to persistence, and manipulation of Terminal history after initial execution.
  - *Log sources:* `macos:unifiedlog (log stream cleared or truncated)`; `fs:fsusage (unlink, fs_delete)`; `macos:osquery (File modifications in ~/Library/Preferences/)`
  - *Tune:* `PlistTargetPaths` — Define which plist paths relate to LaunchAgents or LaunchDaemons; `ExecutionChainDepth` — Allow tuning for multi-process persistence chains
- **`AN0523` Analytic 0523** · Containers
  Monitors tampering with audit logs, volumes, or mounted storage often used for side-channel logging (e.g., /var/log inside containers) post-compromise.
  - *Log sources:* `docker:daemon (container file operations)`; `ebpf:syscalls (Unexpected container volume unmount + file deletion)`
  - *Tune:* `LogMountPaths` — Tune based on how logs are exported (bind-mount, overlay); `ContainerLabelScope` — Limit detection to suspicious containers or runtime classes
- **`AN0524` Analytic 0524** · ESXi
  Tracks suspicious use of ESXi shell commands or PowerCLI to delete logs, rotate system files, or tamper with hostd/vpxa history.
  - *Log sources:* `esxi:hostd (rm, clearlogs, logrotate)`
  - *Tune:* `LogSourceType` — Tune per vCenter, vSphere, ESXi CLI telemetry collection; `LogPathPattern` — Target specific high-value log paths (e.g., /var/log/hostd.log)
- **`AN0525` Analytic 0525** · Office Suite
  Detects deletion or hiding of security-related mail rules, audit mailboxes, or calendar/log sync artifacts indicative of tampering post-intrusion.
  - *Log sources:* `m365:exchange (Remove-InboxRule, Clear-Mailbox)`; `m365:unified (PurgeAuditLogs, Remove-MailboxAuditLog)`
  - *Tune:* `TargetMailboxScope` — Limit by VIP mailboxes or external-facing users; `AuditLogDepth` — Tune for log deletion following lateral movement

---

### T1070.003 — Clear Command History
<a id="t1070003"></a>

**Detection strategy:** Behavioral Detection of Command History Clearing (`DET0165`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1070.003](https://attack.mitre.org/techniques/T1070/003/) · [detail page](../../techniques/stealth.md#t1070003)

- **`AN0467` Analytic 0467** · Linux
  Detects adversary behavior clearing command history via `history -c`, deletion or modification of ~/.bash_history, or manipulation of the HISTFILE environment variable post-login.
  - *Log sources:* `auditd:SYSCALL (execve)`; `auditd:SYSCALL (PATH)`
  - *Tune:* `TimeWindow` — Detect shell history clearing shortly after login or command execution.; `UserContext` — Elevated shell sessions (e.g., root or sudo) without command history may be more suspicious.; `HistoryFilePath` — Bash/Zsh history file paths (e.g., ~/.bash_history, ~/.zsh_history).
- **`AN0468` Analytic 0468** · macOS
  Detects adversary clearing shell history using `history -c` or deleting/altering ~/.zsh_history or ~/.bash_history. Focus on sessions with missing or wiped history.
  - *Log sources:* `macos:unifiedlog (process)`; `fs:fsusage (unlink, write)`
  - *Tune:* `TimeWindow` — Duration after terminal usage where deletion or modification is considered suspicious.; `UserContext` — Flag unexpected user activity, especially from users who normally don’t use terminal.; `HistoryFilePath` — Zsh or Bash history files under the user's home directory.
- **`AN0469` Analytic 0469** · Windows
  Detects PowerShell `Clear-History` invocation or deletion of `ConsoleHost_history.txt` to erase past PowerShell session history.
  - *Log sources:* `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`; `WinEventLog:Sysmon (EventCode=23)`; `WinEventLog:Security (EventCode=4663, 4670, 4656)`
  - *Tune:* `HistoryFilePath` — Path to PSReadLine file, typically in APPDATA.; `UserContext` — User account or role performing deletion (e.g., low-priv user deleting history).; `CommandPattern` — Support detection of `Clear-History` and variations.
- **`AN0470` Analytic 0470** · ESXi
  Detects modification or truncation of `/var/log/shell.log` used to persist ESXi shell command history. Especially suspicious shortly after login or config changes.
  - *Log sources:* `esxi:shell (/var/log/shell.log)`
  - *Tune:* `LogFilePath` — Path to shell command history on ESXi.; `TimeWindow` — Time range post-login or privileged escalation.
- **`AN0471` Analytic 0471** · Network Devices
  Detects use of `clear history` or `clear logging` commands on network device CLI to remove past activity logs.
  - *Log sources:* `networkdevice:syslog (CLI command audit)`
  - *Tune:* `CommandPattern` — Support detection of known variants: 'clear history', 'clear logging', etc.; `DeviceType` — Router, switch, firewall—may have different CLI behaviors.

---

### T1070.004 — File Deletion
<a id="t1070004"></a>

**Detection strategy:** Behavioral Detection of Malicious File Deletion (`DET0140`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1070.004](https://attack.mitre.org/techniques/T1070/004/) · [detail page](../../techniques/stealth.md#t1070004)

- **`AN0392` Analytic 0392** · Windows
  Detects adversary behavior deleting artifacts (e.g., dropped payloads, evidence files) using native or external utilities (e.g., del, erase, SDelete). Detects deletion events correlated with unusual process lineage or timing post-execution.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=23)`; `WinEventLog:Security (EventCode=4663, 4670, 4656)`; `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`
  - *Tune:* `TimeWindow` — Defines correlation window after suspicious binary execution or login session.; `FilePathPattern` — Focuses on deletion of temp files, malware staging dirs, or known indicators.; `UserContext` — Privilege level or impersonated user deleting sensitive files.
- **`AN0393` Analytic 0393** · Linux
  Detects deletion of suspicious files (e.g., payloads, temp exes, scripts) via `rm`, `unlink`, or secure deletion tools like `shred`, especially when performed by unexpected users or shortly after execution.
  - *Log sources:* `auditd:SYSCALL (PATH)`; `auditd:SYSCALL (execve)`
  - *Tune:* `PathRegex` — Pattern matching known attacker staging directories or hidden file paths.; `TimeWindow` — Deletion shortly after process execution or privilege escalation.; `SecureDeletionTool` — Uncommon presence or use of `shred`, `wipe`, or `srm`.
- **`AN0394` Analytic 0394** · macOS
  Detects removal of adversary artifacts via `rm`, `unlink`, or secure tools, with focus on shell sessions, temp files, and modified LaunchAgents or system directories.
  - *Log sources:* `fs:fsusage (unlink, write)`; `macos:unifiedlog (process)`
  - *Tune:* `FilePathRegex` — Focus on LaunchAgents, /tmp/, or user folders.; `ToolUsageAnomaly` — Detecting use of unfamiliar tools by common users.
- **`AN0395` Analytic 0395** · ESXi
  Detects manual or scripted removal of logs, artifacts, or malware droppings via `rm` or PowerCLI in ESXi shell. Focus on deletions from /tmp/, /var/core/, or /scratch.
  - *Log sources:* `esxi:shell (/var/log/shell.log)`
  - *Tune:* `LogFilePath` — Match deletion actions in system-critical locations or malware drop zones.; `TimeWindow` — Typically follows suspicious admin login or unexpected shell session.

---

### T1070.005 — Network Share Connection Removal
<a id="t1070005"></a>

**Detection strategy:** Behavioral Detection of Network Share Connection Removal via CLI and SMB Disconnects (`DET0103`)  
**Platforms:** Windows  
**ATT&CK:** [T1070.005](https://attack.mitre.org/techniques/T1070/005/) · [detail page](../../techniques/stealth.md#t1070005)

- **`AN0286` Analytic 0286** · Windows
  Detects network share disconnection attempts using command-line tools like `net use /delete`, PowerShell `Remove-SmbMapping`, and correlation with process lineage and SMB session teardown activity.
  - *Log sources:* `WinEventLog:Security (EventCode=4624, 4648)`; `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`; `NSM:Flow (SMB2_LOGOFF/SMB_TREE_DISCONNECT)`
  - *Tune:* `TimeWindow` — Adjustable window to correlate CLI disconnection command with SMB session teardown (e.g., 5 mins); `UserContext` — Used to filter on non-interactive users or highly privileged accounts; `ProcessCommandLineRegex` — Patterns to match `net use \\host\share /delete`, `Remove-SmbMapping`, or suspicious batched disconnections; `NetworkShareNamePattern` — Tunable list of shares likely targeted (e.g., ADMIN$, C$, IPC$)

---

### T1070.006 — Timestomp
<a id="t1070006"></a>

**Detection strategy:** Cross-Platform Behavioral Detection of File Timestomping via Metadata Tampering (`DET0591`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1070.006](https://attack.mitre.org/techniques/T1070/006/) · [detail page](../../techniques/stealth.md#t1070006)

- **`AN1626` Analytic 1626** · Windows
  Detects attempts to modify file timestamps via API usage (e.g., `SetFileTime`), CLI tools (e.g., `w32tm`, PowerShell), or double-timestomp behavior where $SI and $FN timestamps are mismatched or reverted.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=15)`; `WinEventLog:Security (EventCode=4663, 4670, 4656)`; `EDR:file (SetFileTime)`
  - *Tune:* `TimeWindow` — Correlate timestamp change with preceding file creation or suspicious access; `APINamePattern` — Include SetFileTime, NtSetInformationFile, or other timestamp APIs; `TimestampDeltaThreshold` — Trigger on excessive backdating (e.g., >90 days)
- **`AN1627` Analytic 1627** · Linux
  Detects use of timestamp-altering commands like `touch -a -m -t` or `touch -r`, particularly when executed by unusual users or in suspicious directories.
  - *Log sources:* `auditd:SYSCALL (execve)`; `linux:osquery (file_events)`
  - *Tune:* `MonitoredCommandList` — Commands like `touch -r`, `debugfs`, `stat` used in sequence; `FilePathRegex` — Suspicious paths like `/tmp/`, `/var/lib/`, `/mnt/esxi/`; `DeltaThreshold` — Mismatch between timestamp and file activity time
- **`AN1628` Analytic 1628** · macOS
  Detects timestamp changes using `touch`, `SetFile`, or direct metadata tampering (e.g., xattr manipulation) from Terminal, scripts, or low-level APIs.
  - *Log sources:* `macos:unifiedlog (log stream --predicate)`; `macos:osquery (file_events)`
  - *Tune:* `CommandMatch` — Touch/setfile and backdated timestamps; `UserContext` — Detects execution under non-interactive/system accounts
- **`AN1629` Analytic 1629** · ESXi
  Detects abuse of busybox commands (e.g., `touch`) or log timestamp tampering during backdoor persistence or evasion.
  - *Log sources:* `esxi:vmkernel (/var/log/vmkernel.log)`
  - *Tune:* `TimestampAgeComparison` — Unusual backdating to match legit files; `PersistenceOverlap` — Overlap with known persistence paths

---

### T1070.007 — Clear Network Connection History and Configurations
<a id="t1070007"></a>

**Detection strategy:** Behavioral Detection of Network History and Configuration Tampering (`DET0049`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1070.007](https://attack.mitre.org/techniques/T1070/007/) · [detail page](../../techniques/stealth.md#t1070007)

- **`AN0133` Analytic 0133** · Windows
  Detects attempts to clear RDP/network history and modify network configuration artifacts through command execution, registry key deletion, firewall rule changes, and suspicious file deletions (e.g., Default.rdp, registry edits to Terminal Server Client keys).
  - *Log sources:* `WinEventLog:Security (EventCode=4663, 4670, 4656)`; `WinEventLog:Sysmon (EventCode=1)`; `EDR:cli (Command Line Telemetry)`; `WinEventLog:Security (Firewall Rule Modification)`
  - *Tune:* `TargetPathRegex` — Filter file/registry paths like *\Terminal Server Client\* or *Default.rdp*; `TimeWindow` — Correlate command/registry edits within close proximity to suspicious connection activity; `UserContext` — Detect cleanup behavior from non-interactive or SYSTEM accounts
- **`AN0134` Analytic 0134** · Linux
  Detects deletion or overwriting of logs/configs that store SSH or proxy activity, such as /var/log/auth.log or custom .bash_history clearing tied to SSH sessions or firewall rule changes.
  - *Log sources:* `auditd:SYSCALL (execve)`; `auditd:SYSCALL (PATH)`
  - *Tune:* `CommandMatchPattern` — Commands like `> /var/log/auth.log`, `rm ~/.bash_history`, `iptables -F`; `LogPathFilter` — Focus on /var/log/auth.log, /etc/ssh/, ~/.bash_history
- **`AN0135` Analytic 0135** · macOS
  Detects removal of Remote Login or Screen Sharing logs in Unified Logging, deletion of `com.apple.UTun`, or suspicious Terminal use of `rm`, `sudo pfctl -F all` to clear network state/config history.
  - *Log sources:* `macos:unifiedlog (log stream --predicate 'eventMessage contains "loginwindow" or "pfctl"')`; `macos:osquery (file_events)`
  - *Tune:* `FilenameMatch` — e.g., *com.apple.UTun*, *RemoteManagement* log files; `TimeDeltaFromLogin` — Correlate deletion with recent SSH or GUI remote login session
- **`AN0136` Analytic 0136** · Network Devices
  Detects firewall rule modifications or reset of logs/connection tables (e.g., `clear logging`, `erase startup-config`, `write erase`) following remote access activity on routers, switches, or VPN appliances.
  - *Log sources:* `networkdevice:syslog (Command Audit / Configuration Change)`; `NSM:Flow (Session History Reset)`
  - *Tune:* `CommandPattern` — e.g., `clear logging`, `no logging buffered`, `no ip domain-lookup`; `DeviceTypeFilter` — Switches vs VPN vs routers

---

### T1070.008 — Clear Mailbox Data
<a id="t1070008"></a>

**Detection strategy:** Behavioral Detection of Mailbox Data and Log Deletion for Anti-Forensics (`DET0266`)  
**Platforms:** Linux, Office Suite, Windows, macOS  
**ATT&CK:** [T1070.008](https://attack.mitre.org/techniques/T1070/008/) · [detail page](../../techniques/stealth.md#t1070008)

- **`AN0737` Analytic 0737** · Windows
  Detects mailbox manipulation or deletion via PowerShell (e.g., Remove-MailboxExportRequest), file deletion from Outlook data stores (Unistore.db), or tampering with quarantined mail logs.
  - *Log sources:* `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`; `WinEventLog:Sysmon (EventCode=23)`; `WinEventLog:Security (EventCode=4663, 4670, 4656)`; `m365:exchange (Transport Rule Modification)`
  - *Tune:* `MailstorePath` — Outlook files in AppData\Local\Comms\Unistore\data; `TransportRuleNames` — Target suspicious rule changes (e.g., header removal); `PowerShellCommandMatch` — Regex match on `Remove-MailboxExportRequest` and similar Exchange cmdlets
- **`AN0738` Analytic 0738** · Linux
  Detects the use of mail utilities like `mail` or `mailx` to delete mailbox content, or file-level deletion of inbox files from `/var/spool/mail/` or `/var/mail/` following suspicious sessions.
  - *Log sources:* `auditd:SYSCALL (execve)`; `auditd:SYSCALL (unlink/unlinkat)`
  - *Tune:* `MailFolderPath` — Common inbox file locations like /var/spool/mail/, /var/mail/; `CommandPattern` — Usage of mailx or echo piped to mail followed by deletion
- **`AN0739` Analytic 0739** · macOS
  Detects removal of Apple Mail artifacts via AppleScript or direct deletion of mailbox content in ~/Library/Mail/, especially when preceded by Remote Login or C2-related API access.
  - *Log sources:* `macos:unifiedlog (log stream)`; `macos:osquery (file_events)`
  - *Tune:* `ScriptCommandMatch` — AppleScript references to Mail.app and delete commands; `LibraryPathMatch` — Files within ~/Library/Mail/V*/ folders
- **`AN0740` Analytic 0740** · Office Suite
  Detects Exchange Online or on-prem transport rule changes (e.g., header stripping) and mailbox export cleanup via `Remove-MailboxExportRequest`, as well as admin actions via Exchange PowerShell sessions.
  - *Log sources:* `m365:exchange (Admin Audit Logs, Transport Rules)`; `WinEventLog:PowerShell (Exchange Cmdlets)`
  - *Tune:* `CmdletFilter` — Include `New-TransportRule`, `Set-TransportRule`, `Remove-*` actions; `UserRoleScope` — Track role assignments for admins performing deletions

---

### T1070.009 — Clear Persistence
<a id="t1070009"></a>

**Detection strategy:** Detection of Persistence Artifact Removal Across Host Platforms (`DET0040`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1070.009](https://attack.mitre.org/techniques/T1070/009/) · [detail page](../../techniques/stealth.md#t1070009)

- **`AN0113` Analytic 0113** · Windows
  Detects adversary activity that removes persistence artifacts such as services, registry keys, scheduled tasks, user accounts, and binaries through commands like `sc delete`, `schtasks /delete`, or `reg delete`.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Security (EventCode=4726, 4657)`; `WinEventLog:TaskScheduler (EventCode=106)`; `WinEventLog:Security (EventCode=4657)`
  - *Tune:* `TargetRegistryPathRegex` — Filters known persistence keys like Run/RunOnce, Image File Execution Options; `DeletedScheduledTaskName` — Monitors known or suspicious task names deleted post-persistence; `DeletedAccountGroupScope` — Focuses on highly privileged or recently created accounts
- **`AN0114` Analytic 0114** · Linux
  Detects removal of persistence artifacts such as crontab entries, systemd service units, and malicious user accounts through commands like `crontab -r`, `rm /etc/systemd/system/*.service`, or `userdel`.
  - *Log sources:* `auditd:SYSCALL (execve)`; `auditd:SYSCALL (file deletion)`
  - *Tune:* `ServicePathMatch` — Targets suspicious or orphaned unit files in /etc/systemd/system/; `CronUserScope` — Focus on crontab activity from root or uncommon users; `UserDeletionActivity` — Looks for userdel or passwd deletion
- **`AN0115` Analytic 0115** · macOS
  Detects deletion of launch agents (~/Library/LaunchAgents/) and launch daemons (/Library/LaunchDaemons/), especially after suspicious process execution or when tied to known persistence methods.
  - *Log sources:* `macos:unifiedlog (log stream)`; `macos:osquery (file_events)`
  - *Tune:* `LaunchDaemonPath` — Common plist file paths for persistence: ~/Library/LaunchAgents/*.plist; `CorrelatedProcessImage` — Ties deletion to parent process (e.g., suspicious AppleScript runner)
- **`AN0116` Analytic 0116** · ESXi
  Detects adversary removal of persistence implants (e.g., rc.local entries or crontab injections) via CLI (`rm`, `sed`, `crontab -r`) and deletion of startup or management scripts.
  - *Log sources:* `esxi:vmkernel (/var/log/vmkernel.log)`; `esxi:shell (shell history)`
  - *Tune:* `ScriptRemovalPath` — e.g., /etc/rc.local, /etc/init.d/custom.sh; `StartupEntryClearance` — Wipe or truncate of persistence locations

---

### T1070.010 — Relocate Malware
<a id="t1070010"></a>

**Detection strategy:** Detection of Malware Relocation via Suspicious File Movement (`DET0439`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1070.010](https://attack.mitre.org/techniques/T1070/010/) · [detail page](../../techniques/stealth.md#t1070010)

- **`AN1216` Analytic 1216** · Windows
  Detects the relocation of malicious executables via copy/move actions across suspicious folders (e.g., from Downloads to System32), followed by deletion of the original source or renaming to blend into legitimate binaries.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=23)`
  - *Tune:* `SuspiciousTargetPathRegex` — Patterns like \Windows\*, \System32\*, or temp+execution directories; `TimeWindow` — Correlate copy+rename+delete chains within 5-minute window; `FileExtensionFilter` — Limit to .exe, .dll, .js, .bat unless context suggests otherwise
- **`AN1217` Analytic 1217** · Linux
  Detects binary movement or copying between untrusted and trusted paths (e.g., /tmp/ → /usr/bin/ or /etc/init.d/) that may indicate persistence attempts or cleanup of origin traces.
  - *Log sources:* `auditd:SYSCALL (PATH)`
  - *Tune:* `RelocationPathPatterns` — Match movement into known persistence or exclusion directories; `BinaryEntropyThreshold` — Apply threshold to detect high-entropy relocations (e.g., packed malware)
- **`AN1218` Analytic 1218** · macOS
  Detects movement of binaries to `~/Library/`, `/System/`, or app bundle locations, especially after initial execution or download from Safari or Mail.
  - *Log sources:* `macos:unifiedlog (log stream)`; `macos:osquery (file_events)`
  - *Tune:* `TargetBundlePathPattern` — Monitor relocation to .app/Contents/MacOS/ or ~/Library/Launch*; `QuarantineFlagCheck` — Check for disappearance of com.apple.quarantine attribute post-move
- **`AN1219` Analytic 1219** · Network Devices
  Detects firmware or script relocation attempts (e.g., CLI-based `copy`, `move`, or `rename`) between temporary partitions and config startup folders on routers or switches.
  - *Log sources:* `networkdevice:syslog (command audit)`
  - *Tune:* `StartupConfigPath` — Targeted config folders like flash:/startup-config or nvram:; `CommandPatternMatch` — e.g., `copy tftp flash`, `rename`, `move flash:/old.bin flash:/new.bin`

---

### T1078 — Valid Accounts
<a id="t1078"></a>

**Detection strategy:** Detection of Valid Account Abuse Across Platforms (`DET0560`)  
**Platforms:** Containers, Identity Provider, Linux, Windows, macOS  
**ATT&CK:** [T1078](https://attack.mitre.org/techniques/T1078/) · [detail page](../../techniques/stealth.md#t1078)

- **`AN1543` Analytic 1543** · Windows
  Detection of compromised or misused valid accounts via anomalous logon patterns, abnormal logon types, and inconsistent geographic or time-based activity across Windows endpoints.
  - *Log sources:* `WinEventLog:Security (EventCode=4624)`; `WinEventLog:Security (EventCode=4776, 4625)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `LogonType` — Flag unexpected logon types (e.g., Type 10 for remote interactive logins) for sensitive accounts.; `TimeWindow` — Define acceptable hours for interactive logon activity (e.g., 9AM-6PM local).; `GeoIPMismatch` — Trigger on location anomalies based on prior user behavior or policy.
- **`AN1544` Analytic 1544** · Linux
  Detection of valid account misuse through SSH logins, sudo/su abuse, and service account anomalies outside expected patterns.
  - *Log sources:* `auditd:SYSCALL (execve)`; `NSM:Connections (sshd or PAM logins)`
  - *Tune:* `UserContext` — Identify logins to root or sudoers not aligned with normal usage profiles.; `HostDensityThreshold` — Number of unique systems a user authenticates to in a time window.; `LoginMethod` — Trigger on rarely used access methods such as password instead of SSH key.
- **`AN1545` Analytic 1545** · macOS
  Detection of interactive and remote logins by service accounts or users at unusual times, with unexpected child process activity.
  - *Log sources:* `macos:unifiedlog (loginwindow, sshd)`; `macos:unifiedlog (exec logs)`
  - *Tune:* `LoginOrigin` — Login sourced from unexpected remote addresses.; `ProcessTreeDepth` — Track execution depth or anomalous chains post-login.
- **`AN1546` Analytic 1546** · Identity Provider
  Detection of valid account abuse in IdP logs via geographic anomalies, impossible travel, risky sign-ins, and multiple MFA attempts or failures.
  - *Log sources:* `saas:okta (Sign-in logs / audit events)`
  - *Tune:* `MFAFailureCount` — Threshold of failed MFA attempts before alerting.; `RiskScoreThreshold` — Custom threshold based on calculated identity risk.; `IPGeoVelocity` — Detect impossible travel (logins from two distant geolocations within short time).
- **`AN1547` Analytic 1547** · Containers
  Detection of containerized service accounts or compromised kubeconfigs being used for cluster access from unexpected nodes or IPs.
  - *Log sources:* `kubernetes:audit (authentication.k8s.io)`
  - *Tune:* `ServiceAccountScope` — Validate access from expected namespaces only.; `ClusterIPWhitelist` — Permit kubeconfig usage from a limited set of IPs.

---

### T1078.001 — Default Accounts
<a id="t1078001"></a>

**Detection strategy:** Detection of Default Account Abuse Across Platforms (`DET0465`)  
**Platforms:** ESXi, Identity Provider, Linux, Network Devices, Windows  
**ATT&CK:** [T1078.001](https://attack.mitre.org/techniques/T1078/001/) · [detail page](../../techniques/stealth.md#t1078001)

- **`AN1283` Analytic 1283** · Windows
  Detection of default account usage such as Guest or Administrator performing interactive or remote logons on systems outside of installation or maintenance windows.
  - *Log sources:* `WinEventLog:Security (EventCode=4624, 4648)`
  - *Tune:* `UserContext` — Default usernames like 'Administrator' or 'Guest' may be renamed or disabled by the organization. Detection logic should account for name changes.; `TimeWindow` — Restrict detection to unusual hours or outside of expected maintenance windows.
- **`AN1284` Analytic 1284** · Linux
  Monitoring for SSH logins from default accounts such as 'root', especially when login is via password and not key-based authentication.
  - *Log sources:* `auditd:USER_LOGIN (USER_LOGIN)`
  - *Tune:* `SSHMethod` — Environments using passwordless SSH should not have password logins enabled for root or other default accounts.; `RemoteIPWhitelist` — Logins from jump boxes may be whitelisted depending on environment policies.
- **`AN1285` Analytic 1285** · Identity Provider
  Use of known default service accounts or root-level cloud accounts performing authentication or changes to IAM policy.
  - *Log sources:* `AWS:CloudTrail (ConsoleLogin or AssumeRole)`
  - *Tune:* `AccountList` — Organizations may rename or rotate default IAM accounts; detection logic should be updated with any renamed or aliased default identities.; `GeoLocation` — Authentication attempts from unusual geographic regions should trigger anomaly detection.
- **`AN1286` Analytic 1286** · ESXi
  Abuse of system-generated or default privileged accounts such as 'root' or 'vpxuser' logging into ESXi hosts.
  - *Log sources:* `esxi:auth (/var/log/auth.log)`
  - *Tune:* `AccountName` — If 'vpxuser' is replaced or configured differently, detection logic must reflect the change.; `IPRange` — Legitimate vCenter IP ranges may be whitelisted to avoid false positives.
- **`AN1287` Analytic 1287** · Network Devices
  Login activity from default admin credentials (e.g., 'admin', 'cisco') on routers, firewalls, and switches.
  - *Log sources:* `networkdevice:syslog (authentication logs)`
  - *Tune:* `Username` — Default usernames vary by vendor; defenders should adapt logic to their specific appliance list.; `InterfaceType` — Telnet and HTTP-based access to network devices should be blocked and monitored if enabled.

---

### T1078.002 — Domain Accounts
<a id="t1078002"></a>

**Detection strategy:** Abuse of Domain Accounts (`DET0210`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1078.002](https://attack.mitre.org/techniques/T1078/002/) · [detail page](../../techniques/stealth.md#t1078002)

- **`AN0590` Analytic 0590** · Windows
  Detection of suspicious logon behavior using valid domain accounts across multiple hosts, off-hours, or simultaneous sessions from geographically distant locations.
  - *Log sources:* `WinEventLog:Security (EventCode=4624, 4625, 4768, 4769)`; `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=3, 22)`
  - *Tune:* `TimeWindow` — Tune for detection of off-hours or abnormal logon spikes.; `UserContext` — Scope to sensitive domain accounts (e.g., Domain Admins).; `LogonType` — Distinguish between interactive, service, and network logons.
- **`AN0591` Analytic 0591** · Linux
  Use of domain accounts via sssd or winbind for logon activity outside of typical patterns, especially on sensitive systems or with lateral movement tools.
  - *Log sources:* `auditd:SYSCALL (pam_authenticate, sshd)`; `linux:syslog (sssd / sudo logs)`
  - *Tune:* `HostnameScope` — Filter to high-value systems (e.g., domain-joined servers).; `AccountDomain` — Identify trusted domains versus external or misconfigured domains.
- **`AN0592` Analytic 0592** · macOS
  Domain logins using network accounts or mobile accounts via Open Directory or Active Directory plugins, especially outside business hours or on atypical endpoints.
  - *Log sources:* `macos:unifiedlog (log show --predicate 'eventMessage contains "Authentication"')`
  - *Tune:* `UserLocation` — Geo-IP or VPN source context for abnormal remote access.; `LogonMethod` — Control for expected services (e.g., GUI login vs. SSH).
- **`AN0593` Analytic 0593** · ESXi
  Login to vSphere or ESXi hosts using domain accounts, especially those associated with vpxuser or unexpected group memberships.
  - *Log sources:* `esxi:vpxd (/var/log/vmware/vpxd.log)`; `esxi:hostd (/var/log/hostd.log)`
  - *Tune:* `AccountType` — Prioritize detection on accounts with elevated access.; `LoginInterface` — Distinguish interactive UI login from API or SSH access.

---

### T1078.003 — Local Accounts
<a id="t1078003"></a>

**Detection strategy:** Detection of Local Account Abuse for Initial Access and Persistence (`DET0407`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1078.003](https://attack.mitre.org/techniques/T1078/003/) · [detail page](../../techniques/stealth.md#t1078003)

- **`AN1137` Analytic 1137** · Windows
  Detects anomalous usage of local accounts to log into a system, especially accounts not typically used interactively or outside business hours.
  - *Log sources:* `WinEventLog:Security (EventCode=4624, 4648)`; `WinEventLog:Security (EventCode=4672)`
  - *Tune:* `TimeWindow` — Tune for normal business hours to reduce false positives from legitimate after-hours work.; `UserContext` — Define list of legitimate local users for interactive access.
- **`AN1138` Analytic 1138** · Linux
  Detects interactive or service logins from local accounts outside expected operational context or at anomalous times.
  - *Log sources:* `auditd:USER_LOGIN (USER_LOGIN)`; `linux:auth (sshd login)`
  - *Tune:* `TimeWindow` — Define operational hours or expected login times per host.; `HostRole` — Differentiate expected behavior for server vs. workstation.
- **`AN1139` Analytic 1139** · macOS
  Detects abnormal or rare logins via local accounts through system or remote mechanisms such as SSH.
  - *Log sources:* `macos:unifiedlog (loginwindow or sshd)`
  - *Tune:* `UserContext` — Restrict expected local users by device owner or role.; `TimeWindow` — Set appropriate bounds based on endpoint usage patterns.

---

### T1078.004 — Cloud Accounts
<a id="t1078004"></a>

**Detection strategy:** Detection of Abused or Compromised Cloud Accounts for Access and Persistence (`DET0546`)  
**Platforms:** IaaS, Identity Provider, Office Suite, SaaS  
**ATT&CK:** [T1078.004](https://attack.mitre.org/techniques/T1078/004/) · [detail page](../../techniques/stealth.md#t1078004)

- **`AN1503` Analytic 1503** · Identity Provider
  Detects anomalous authentication activity such as sign-ins from impossible geolocations or legacy protocols from high-privileged accounts.
  - *Log sources:* `azure:signinlogs (Sign-in activity)`; `saas:okta (user.authentication.sso)`
  - *Tune:* `AnomalousLocationThreshold` — Defines geographic separation (e.g., impossible travel) considered suspicious.; `ProtocolType` — Filter based on legacy or deprecated authentication mechanisms.
- **`AN1504` Analytic 1504** · IaaS
  Detects cloud account use for API calls that exceed normal scope, such as IAM changes or access to services never used before.
  - *Log sources:* `AWS:CloudTrail (ConsoleLogin, AssumeRole, ListAccessKeys, CreateUser)`; `gcp:audit (admin.googleapis.com)`
  - *Tune:* `ServiceInteractionBaseline` — Custom list of expected service interactions per user or role.; `RoleSwitchRateThreshold` — Frequency of assume-role operations that triggers an alert.
- **`AN1505` Analytic 1505** · SaaS
  Detects unexpected access or usage of cloud productivity tools (e.g., downloading large numbers of files, creating external shares) by internal users.
  - *Log sources:* `m365:unified (FileAccessed, SharingSet)`; `gcp:audit (drive.activity)`
  - *Tune:* `FileDownloadThreshold` — Defines excessive access based on number or size of downloads.; `SharingPolicyViolationThreshold` — Defines external sharing behaviors that violate policy.
- **`AN1506` Analytic 1506** · Office Suite
  Detects login and usage patterns deviating from typical Microsoft 365 or Google Workspace user profiles.
  - *Log sources:* `m365:signinlogs (UserLogin)`; `gcp:audit (login.event)`
  - *Tune:* `BusinessHours` — Used to identify logins outside of expected work times.; `OfficeProductivityToolBaseline` — Defines expected application usage per department or role.

---

### T1127 — Trusted Developer Utilities Proxy Execution
<a id="t1127"></a>

**Detection strategy:** Behavior-chain, platform-aware detection strategy for T1127 Trusted Developer Utilities Proxy Execution (Windows) (`DET0172`)  
**Platforms:** Windows  
**ATT&CK:** [T1127](https://attack.mitre.org/techniques/T1127/) · [detail page](../../techniques/stealth.md#t1127)

- **`AN0488` Analytic 0488** · Windows
  A trusted/signed developer utility (parent) is executed in a non-developer context and (a) spawns suspicious children (e.g., powershell.exe, cmd.exe, rundll32.exe, regsvr32.exe, wscript.exe), (b) loads unsigned/user-writable DLLs, (c) writes and then runs a new PE from user-writable paths, and/or (d) immediately makes outbound network connections.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=3, 22)`; `WinEventLog:AppLocker (AppLocker audit/blocks showing developer utilities executing scripts/binaries outside policy)`
  - *Tune:* `TimeWindow` — Correlation window between developer utility execution, payload write, and network egress (e.g., 0–30 minutes).; `AllowedUtilitiesList` — Org-specific list of dev utilities legitimately used on build/dev hosts to suppress noise.; `DeveloperHosts` — List of known developer/build systems where these tools are expected; raise severity off-host.; `SuspiciousChildList` — Child processes considered high-risk when spawned by dev utilities (powershell.exe, rundll32.exe, regsvr32.exe, cmd.exe, wscript.exe, mshta.exe).; `RarePathRegex` — Regex of user-writable or atypical paths (e.g., %TEMP%, %APPDATA%, recycle bin, public profile) for payload drops.; `UnsignedOrInvalidSignatureOnly` — Toggle to alert only when child/payload is unsigned or signature invalid to reduce noise.; `ParentProcessAllowList` — Known orchestrators (e.g., CI/CD agents) that often run these utilities legitimately.; `NetworkReputationThreshold` — Heuristic for rare/unknown destination (no DNS reputation, new domain, geo outside region).

---

### T1127.001 — MSBuild
<a id="t1127001"></a>

**Detection strategy:** Behavior-chain detection strategy for T1127.001 Trusted Developer Utilities Proxy Execution: MSBuild (Windows) (`DET0556`)  
**Platforms:** Windows  
**ATT&CK:** [T1127.001](https://attack.mitre.org/techniques/T1127/001/) · [detail page](../../techniques/stealth.md#t1127001)

- **`AN1535` Analytic 1535** · Windows
  MSBuild.exe is invoked outside expected developer/build contexts or with anomalous arguments (e.g., non-canonical paths, remote shares, Base64/obfuscated property values). Within a short window, it (a) spawns high-risk LOLBins/script interpreters, (b) writes new PE/DLL/script artifacts into user-writable paths and executes them, (c) loads unsigned/user-writable modules, (d) performs memory injection/thread creation into other processes, and/or (e) initiates outbound network connections.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=3, 22)`; `WinEventLog:Sysmon (EventCode=8)`; `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational (Unsigned/invalid signature modules or images loaded by msbuild.exe or its children)`; `EDR:AMSI (Malicious inline C#/script blobs embedded in MSBuild projects if intercepted by AMSI-aware loaders (rare but possible via chained LOLBins))`
  - *Tune:* `TimeWindow` — Correlation window between msbuild.exe start, payload write, suspicious child spawn, and network (e.g., 0–30 minutes).; `DeveloperHosts` — Tag/allowlist known developer or CI/CD hosts to reduce noise.; `SuspiciousChildList` — High-risk children (powershell.exe, rundll32.exe, regsvr32.exe, cmd.exe, wscript.exe, mshta.exe) spawned by msbuild.exe.; `RarePathRegex` — Regex of user-writable or atypical paths (e.g., %TEMP%, %APPDATA%, OneDrive sync dirs) used to drop payloads.; `UnsignedOrInvalidSignatureOnly` — Tighten alerting to cases with invalid or missing signatures on modules/children.; `NetworkReputationThreshold` — Minimum rarity/risk score for external destinations to alert.; `BehaviorRiskScoreThreshold` — Numeric threshold for fused, scored correlation (e.g., ≥70/100 triggers an alert).

---

### T1127.002 — ClickOnce
<a id="t1127002"></a>

**Detection strategy:** Behavior-chain detection strategy for T1127.002 Trusted Developer Utilities Proxy Execution: ClickOnce (Windows) (`DET0191`)  
**Platforms:** Windows  
**ATT&CK:** [T1127.002](https://attack.mitre.org/techniques/T1127/002/) · [detail page](../../techniques/stealth.md#t1127002)

- **`AN0550` Analytic 0550** · Windows
  Abuse of ClickOnce applications where rundll32.exe invokes dfshim.dll with ShOpenVerbApplication or dfsvc.exe spawns unexpected child processes or loads unsigned modules.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Microsoft-Windows-Security-Mitigations/KernelMode (ETW telemetry indicating ClickOnce deployment (dfsvc.exe) launching payloads)`
  - *Tune:* `TimeWindow` — The correlation window for dfsvc.exe/rundll32.exe execution and subsequent module loads or child processes (e.g., 0–10 minutes).; `KnownClickOnceApps` — Whitelist of legitimate ClickOnce applications and paths.; `SuspiciousChildList` — Child processes considered abnormal when launched by dfsvc.exe or rundll32.exe.

---

### T1127.003 — JamPlus
<a id="t1127003"></a>

**Detection strategy:** Behavior-chain detection strategy for T1127.003 Trusted Developer Utilities Proxy Execution: JamPlus (Windows) (`DET0585`)  
**Platforms:** Windows  
**ATT&CK:** [T1127.003](https://attack.mitre.org/techniques/T1127/003/) · [detail page](../../techniques/stealth.md#t1127003)

- **`AN1610` Analytic 1610** · Windows
  Abuse of JamPlus.exe to launch malicious payloads via crafted .jam files, resulting in abnormal process creation, command execution, or artifact generation outside of standard development workflows.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=3, 22)`; `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational (Unsigned or untrusted modules loaded during JamPlus.exe runtime)`
  - *Tune:* `TimeWindow` — Correlation time window (e.g., 0–30 minutes) for JamPlus.exe execution, child processes, and file/network events.; `AllowedBuildHosts` — Known developer systems where JamPlus.exe usage is expected; alerts are raised if executed elsewhere.; `SuspiciousChildList` — Child processes considered anomalous (e.g., PowerShell, cmd, wscript) when spawned by JamPlus.exe.; `RarePathRegex` — Regex patterns for non-standard or user-writable paths where JamPlus.exe drops artifacts.

---

### T1134 — Access Token Manipulation
<a id="t1134"></a>

**Detection strategy:** Behavior-chain detection for T1134 Access Token Manipulation on Windows (`DET0283`)  
**Platforms:** Windows  
**ATT&CK:** [T1134](https://attack.mitre.org/techniques/T1134/) · [detail page](../../techniques/stealth.md#t1134)

- **`AN0786` Analytic 0786** · Windows
  Detection of suspicious token manipulation chains: use of token-related APIs (e.g., LogonUser, DuplicateTokenEx) or commands (runas) → spawning of a new process under a different security context (e.g., SYSTEM) → mismatched parent-child process lineage or anomalies in Event Tracing for Windows (ETW) token/PPID data → abnormal lateral or privilege escalation activity.
  - *Log sources:* `WinEventLog:Security (EventCode=4672, 4634)`; `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=10)`; `ETW:Token (token_analysis: API calls such as DuplicateTokenEx or ImpersonateLoggedOnUser)`; `WinEventLog:Security (EventCode=5136)`
  - *Tune:* `TimeWindow` — Correlation time between suspicious API usage, runas, and process creation (e.g., 5–10m).; `AllowedServiceAccounts` — Whitelist of service accounts permitted to spawn SYSTEM-level processes.; `KnownAdminTools` — Legitimate administrative utilities that trigger token changes.; `ParentProcessAnomalyThreshold` — Deviation threshold for PPID mismatches detected via ETW.

---

### T1134.001 — Token Impersonation/Theft
<a id="t1134001"></a>

**Detection strategy:** Behavior-chain detection for T1134.001 Access Token Manipulation: Token Impersonation/Theft on Windows (`DET0482`)  
**Platforms:** Windows  
**ATT&CK:** [T1134.001](https://attack.mitre.org/techniques/T1134/001/) · [detail page](../../techniques/stealth.md#t1134001)

- **`AN1324` Analytic 1324** · Windows
  Detection of token duplication and impersonation attempts by correlating suspicious command-line executions (e.g., runas) with API calls to DuplicateToken, DuplicateTokenEx, ImpersonateLoggedOnUser, or SetThreadToken. The chain includes the initial command execution or in-memory API invocation → token handle duplication or thread token assignment → a new or existing process assuming the impersonated user's context.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=10)`; `ETW:Token (api_call: DuplicateTokenEx, ImpersonateLoggedOnUser, SetThreadToken)`
  - *Tune:* `AllowedSystemProcesses` — Whitelist of known processes that legitimately duplicate tokens (e.g., services.exe).; `TimeWindow` — Time interval between API call and subsequent impersonated process (e.g., 5m).; `UserContextFilter` — Filter for service accounts or known administrative accounts that perform legitimate impersonation.; `ParentProcessAnomalyThreshold` — Threshold for parent-child process lineage anomalies indicating token theft.

---

### T1134.002 — Create Process with Token
<a id="t1134002"></a>

**Detection strategy:** Behavior-chain detection for T1134.002 Create Process with Token (Windows) (`DET0456`)  
**Platforms:** Windows  
**ATT&CK:** [T1134.002](https://attack.mitre.org/techniques/T1134/002/) · [detail page](../../techniques/stealth.md#t1134002)

- **`AN1253` Analytic 1253** · Windows
  A process (often after stealing/creating a token) calls CreateProcessWithTokenW/CreateProcessAsUserW or uses runas to spawn a **new** process whose security context (SID/LogonId/IntegrityLevel) differs from its parent. Chain: (1) suspicious command/API → (2) privileged handle or token duplication/open → (3) new child process running as another user / higher integrity → (4) optional follow‑on privileged/lateral actions.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=10)`; `ETW:ProcThread (api_call: CreateProcessWithTokenW, CreateProcessAsUserW)`; `WinEventLog:Security (EventCode=4672, 4634)`; `WinEventLog:Security (EventCode=5136)`
  - *Tune:* `TimeWindow` — Correlation window between API/handle access and the spawned process (default 5–10 minutes).; `AllowedImpersonators` — Service accounts/binaries legitimately using CreateProcessWithTokenW (e.g., PsExec service, SCCM, backup agents).; `IntegrityEscalationDelta` — Minimum jump in integrity level (e.g., Medium→System) to flag.; `ParentChildUserMismatch` — Treat any parent/child SID or LogonId mismatch as suspicious unless on allow-list.; `SensitiveTargets` — List of processes (e.g., lsass.exe, winlogon.exe, services.exe) whose token access prior to the spawn raises score.

---

### T1134.003 — Make and Impersonate Token
<a id="t1134003"></a>

**Detection strategy:** Behavior‑chain detection for T1134.003 Make and Impersonate Token (Windows) (`DET0498`)  
**Platforms:** Windows  
**ATT&CK:** [T1134.003](https://attack.mitre.org/techniques/T1134/003/) · [detail page](../../techniques/stealth.md#t1134003)

- **`AN1375` Analytic 1375** · Windows
  A process creates a brand‑new logon session/token (LogonUser*/LsaLogonUser) and then assigns/impersonates it (SetThreadToken/ImpersonateLoggedOnUser) to run actions under that freshly created security context. Chain: (1) suspicious command or script block (e.g., runas /netonly, PowerShell P/Invoke of LogonUser) → (2) ETW/API evidence of LogonUser*/SetThreadToken → (3) Security 4624 New Logon (often LogonType=9 NewCredentials or 2/3 from a non‑interactive parent) with no interactive desktop → (4) sysmon 1 process(es) executing with the new LogonId/SID different from the parent process → (5) optional privileged ops/lateral movement.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Security (EventCode=4672)`; `etw:Microsoft-Windows-Security-Auditing (api_call: LogonUser(A|W), LsaLogonUser, SetThreadToken, ImpersonateLoggedOnUser)`
  - *Tune:* `TimeWindow` — Correlation window between LogonUser*/SetThreadToken and the first spawned process (default 5–10 minutes).; `SuspiciousLogonTypes` — Which 4624 LogonTypes to treat as high risk (e.g., 9 NewCredentials, 3 Network when sourced locally).; `AllowedImpersonators` — Processes/accounts legitimately creating tokens (e.g., winlogon.exe, lsass.exe, IIS worker, trusted service accounts).; `ParentChildUserMismatch` — Whether to alert on any SID/LogonId mismatch between parent/child not in allow-list.; `IntegrityEscalationDelta` — Minimum integrity level jump (e.g., Medium→High/System) to raise severity.

---

### T1134.004 — Parent PID Spoofing
<a id="t1134004"></a>

**Detection strategy:** Behavior-chain detection for T1134.004 Access Token Manipulation: Parent PID Spoofing (Windows) (`DET0489`)  
**Platforms:** Windows  
**ATT&CK:** [T1134.004](https://attack.mitre.org/techniques/T1134/004/) · [detail page](../../techniques/stealth.md#t1134004)

- **`AN1351` Analytic 1351** · Windows
  A process explicitly forges its parent using EXTENDED_STARTUPINFO + PROC_THREAD_ATTRIBUTE_PARENT_PROCESS (UpdateProcThreadAttribute → CreateProcess[A/W]/CreateProcessAsUserW) or other Native API paths, resulting in **mismatched/implausible lineage** across ETW EventHeader ProcessId, Security 4688 Creator Process ID/Name, and sysmon ParentProcessGuid. Often paired with privilege escalation when the chosen parent runs as SYSTEM.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `etw:Microsoft-Windows-Kernel-Process (api_call: UpdateProcThreadAttribute (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) and CreateProcess* with EXTENDED_STARTUPINFO_PRESENT / StartupInfoEx)`; `etw:Microsoft-Windows-Kernel-Process (process_start: EventHeader.ProcessId true parent vs reported PPID mismatch)`
  - *Tune:* `TimeWindow` — Correlation window between UpdateProcThreadAttribute/CreateProcess* and the resulting process (default 5–10 minutes).; `AllowedSpoofers` — Legitimate binaries that commonly use StartupInfoEx/PPID assignment (e.g., consent.exe, svchost.exe during UAC).; `ParentPrivilegeDeltaThreshold` — Minimum privilege/integrity gap between chosen parent and real caller to raise severity.; `LineageMismatchTolerance` — Number of mismatched sources (0–3) before alerting to reduce noise.; `SensitiveParents` — List of SYSTEM parents that, if spoofed, auto‑escalate severity (e.g., lsass.exe, services.exe, wininit.exe).

---

### T1134.005 — SID-History Injection
<a id="t1134005"></a>

**Detection strategy:** Behavior-chain detection for T1134.005 Access Token Manipulation: SID-History Injection (Windows) (`DET0136`)  
**Platforms:** Windows  
**ATT&CK:** [T1134.005](https://attack.mitre.org/techniques/T1134/005/) · [detail page](../../techniques/stealth.md#t1134005)

- **`AN0383` Analytic 0383** · Windows
  Detection of unauthorized modification of Active Directory SID-History attributes to escalate privileges. This chain involves: (1) privileged operations or API calls to DsAddSidHistory or related AD modification functions, (2) observed attribute changes in SID-History (Event ID 5136), (3) new logon sessions where the token includes unexpected or privileged SID-History values, and (4) follow-on resource access using elevated privileges derived from SID-History injection.
  - *Log sources:* `WinEventLog:Security (EventCode=5136)`; `WinEventLog:Security (EventCode=4720, 4738)`; `etw:Microsoft-Windows-Directory-Services-SAM (api_call: Calls to DsAddSidHistory or related RPC operations)`
  - *Tune:* `AllowedSIDHistoryChanges` — Approved migration windows or known SID-History population events.; `TimeWindow` — Correlation window between attribute change and suspicious logon activity (default 15–30 minutes).; `PrivilegedSIDList` — List of sensitive SIDs (e.g., Enterprise Admins, Domain Admins) that should never appear in SID-History.; `UserContextFilter` — Exclude trusted migration service accounts or pre-approved administrative tasks.; `AnomalousSIDCountThreshold` — Raise alerts when a token contains more than X SID-History entries (default X=2).

---

### T1140 — Deobfuscate/Decode Files or Information
<a id="t1140"></a>

**Detection strategy:** Detect Adversary Deobfuscation or Decoding of Files and Payloads (`DET0275`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1140](https://attack.mitre.org/techniques/T1140/) · [detail page](../../techniques/stealth.md#t1140)

- **`AN0767` Analytic 0767** · Windows
  An adversary leverages built-in tools such as certutil.exe, powershell.exe, or copy.exe to decode, reassemble, or extract hidden malicious content from obfuscated containers or encoded formats. The decoding utility often spawns shortly after file staging or download and may be chained with script interpreters or further payload execution.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=10)`
  - *Tune:* `ToolName` — May vary across environments (e.g., certutil, powershell, copy, expand, 7zip); `FileExtensionFilter` — Targets may use .txt, .cer, .enc, .b64, .zip, etc. to disguise payloads; `CommandLineRegex` — Command syntax varies between base64 decoding, copy /b, and expand switches; `TimeWindow` — Deobfuscation typically follows staging/download within a short timeframe
- **`AN0768` Analytic 0768** · Linux
  The adversary uses native utilities like base64, gzip, tar, or openssl to decode, decompress, or decrypt files that were previously staged or downloaded. These tools may be chained with curl/wget and executed via bash/zsh, often to extract an embedded payload or reverse shell script.
  - *Log sources:* `auditd:SYSCALL (bash/zsh of base64, tar, gzip, or openssl immediately after file write)`
  - *Tune:* `ShellProcessName` — Shell interpreter may vary (bash, zsh, dash, sh); `DecodeUtility` — May include base64, openssl, gunzip, tar, uudecode; `ParentProcess` — Expected parent process may vary in attacker chain (e.g., curl, bash, ssh); `ArgumentPattern` — Detection regex should support flexible patterning of decode switches
- **`AN0769` Analytic 0769** · macOS
  The adversary invokes built-in scripting or decoding tools like base64, plutil, or AppleScript-based utilities to decode files embedded in staging artifacts. Decoding often occurs post-download or as part of post-exploitation payload deployment via zsh, python, or osascript.
  - *Log sources:* `macos:unifiedlog (base64 -d or osascript invoked on staged file)`
  - *Tune:* `DecodeInterpreter` — Could involve base64, osascript, python, perl, or plutil; `ExecutionContext` — Deobfuscation may happen within GUI app context or LaunchAgent/Daemon; `UserContext` — May differ depending on local user, root escalation, or persistence method

---

### T1197 — BITS Jobs
<a id="t1197"></a>

**Detection strategy:** Detect abuse of Windows BITS Jobs for download, execution and persistence (`DET0098`)  
**Platforms:** Windows  
**ATT&CK:** [T1197](https://attack.mitre.org/techniques/T1197/) · [detail page](../../techniques/stealth.md#t1197)

- **`AN0274` Analytic 0274** · Windows
  Behavioral chain: (1) An actor creates or modifies a BITS job via bitsadmin.exe, PowerShell BITS cmdlets, or COM; (2) the job performs HTTP(S)/SMB network transfers while the owning user is logged on; (3) upon job completion/error, BITS launches a notify command (SetNotifyCmdLine) from svchost.exe -k netsvcs -s BITS, often establishing persistence by keeping long-lived jobs. The strategy correlates process creation, command/script telemetry, BITS-Client operational events, and network connections initiated by BITS.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=3, 22)`; `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`; `WinEventLog:System (EventCode=7036)`
  - *Tune:* `TimeWindow` — Correlation window linking job creation, transfer, and notify execution (e.g., 30m–24h depending on environment and BITS retry behavior).; `ExpectedUpdateHosts` — Allow-list of corporate update/CDN endpoints that legitimately use BITS (WSUS, MEMCM, vendor updaters).; `SuspiciousCliSwitches` — BITSAdmin flags of interest (/transfer, /addfile, /SetNotifyCmdLine, /resume, /setcustomheaders, /setminretrydelay).; `NotifyCmdBlockList` — Known risky binaries or folders (e.g., %TEMP%\*.exe, powershell.exe, cmd.exe) used as BITS notify commands.; `UserContext` — Scope by interactive users, service accounts, or high-value targets (admins/servers) to reduce benign noise.; `ExternalNetCIDRs` — Definition of external/non-corp destinations for network correlation.; `JobLifetimeThreshold` — Maximum age or retry count for benign jobs before flagging persistence (e.g., >3 days or retry>20).

---

### T1202 — Indirect Command Execution
<a id="t1202"></a>

**Detection strategy:** Indirect Command Execution – Windows utility abuse behavior chain (`DET0200`)  
**Platforms:** Windows  
**ATT&CK:** [T1202](https://attack.mitre.org/techniques/T1202/) · [detail page](../../techniques/stealth.md#t1202)

- **`AN0576` Analytic 0576** · Windows
  Cause→effect chain: (1) A user or service launches an indirection utility (e.g., forfiles.exe, pcalua.exe, wsl.exe, scriptrunner.exe, ssh.exe with -o ProxyCommand/LocalCommand). (2) That utility spawns a secondary program/command (PowerShell, cmd, msiexec, regsvr32, curl, arbitrary EXE) and/or opens outbound network connections. (3) Optional precursor modification of SSH config to persist LocalCommand/ProxyCommand. Correlate process creation, command/script content, file access to %USERPROFILE%\.ssh\config, and network connections from the utility or its child.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=3, 22)`; `WinEventLog:Sysmon (EventCode=11)`
  - *Tune:* `TimeWindow` — Correlation window between indirect launcher and spawned child/network activity (e.g., 10–30 minutes).; `AllowedUtilities` — Utilities permitted on admin/Jumphosts (forfiles, wsl, ssh) to reduce noise.; `HighRiskChildren` — Child images that indicate abuse (powershell.exe, cmd.exe, rundll32.exe, regsvr32.exe, mshta.exe, msiexec.exe, curl.exe, bitsadmin.exe).; `UserContext` — Raise severity when the actor is a standard/interactive user on a workstation rather than a server or CI agent.; `DestCIDRs` — Known-good egress networks for SSH/WSL activity to suppress expected admin automations.

---

### T1205 — Traffic Signaling
<a id="t1205"></a>

**Detection strategy:** Traffic Signaling (Port-knock / magic-packet → firewall or service activation) – T1205 (`DET0524`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1205](https://attack.mitre.org/techniques/T1205/) · [detail page](../../techniques/stealth.md#t1205)

- **`AN1448` Analytic 1448** · Windows
  A remote host sends a short sequence of failed connection attempts (RST/ICMP unreachable) to a set of closed ports. Within a brief window the endpoint (a) adds/enables a firewall rule or (b) a sniffer-backed process begins listening or opens a new socket, after which a successful connection occurs. Also detects Wake-on-LAN magic packets seen on local segment.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=3, 22)`; `WinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall (EventCode=2004, 2005, 2006)`; `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`
  - *Tune:* `TimeWindowKnock` — Window to correlate knock sequence → rule change → successful connect (e.g., 120s).; `PortSequenceMinLen` — Minimum number of distinct closed ports hit before success (e.g., 3).; `SuspiciousProcesses` — List of binaries that commonly toggle firewall/sniff (netsh.exe, powershell.exe, npcapservice.exe, windivert, rawsock tools).; `AllowedFirewallChangers` — Service accounts or software update agents allowed to change firewall.; `WoLAllowedWindows` — Maintenance windows when magic packets are expected.
- **`AN1449` Analytic 1449** · Linux
  Closed-port knock sequence from a remote IP followed by on-host firewall change (iptables/nftables) or daemon starts listening (socket open) and a successful TCP/UDP connect. Optional detection of libpcap/raw-socket sniffers spawning to watch for secret values.
  - *Log sources:* `auditd:SYSCALL (execve: Commands altering firewall or enabling listeners (iptables, nft, ufw, firewall-cmd, systemctl start *ssh*/*telnet*, ip route add, tcpdump, tshark))`; `auditd:SYSCALL (socket/bind: Process binds to a new local port shortly after knock)`; `NSM:Flow (Knock pattern: multiple REJ/S0 to distinct closed ports then successful connection to service_port)`; `NSM:Flow (Packets with unusual flags or payloads outside established flows (e.g., WoL magic FF×6 + 16×MAC))`
  - *Tune:* `ServicePort` — Port that becomes available post-knock (e.g., 22/8022/2323).; `KnockResetRatio` — Percentage of failed attempts with RST/ICMP vs SYN/SYN-ACK to qualify as closed-port probing.; `ProcessAllowList` — Automation expected to touch firewall/daemon configs (config-mgmt agents).
- **`AN1450` Analytic 1450** · macOS
  Remote knock sequence followed by PF/socketfilterfw rule update or a background process listening on a new port; then a successful TCP session. Also flags WoL magic packets on local segment.
  - *Log sources:* `macos:unifiedlog (exec: Execution of /sbin/pfctl, /usr/libexec/ApplicationFirewall/socketfilterfw, ifconfig, tcpdump, npcap/libpcap consumers)`; `macos:unifiedlog (Firewall rule enable/disable or listen socket changes)`; `NSM:Flow (Closed-port hits followed by success from same src_ip)`
  - *Tune:* `PFAnchorPaths` — Anchors or conf files monitored for change (/etc/pf.conf, /etc/pf.anchors/*).; `DeveloperMode` — Reduce noise on dev endpoints compiling or testing PF rules.
- **`AN1451` Analytic 1451** · Network Devices
  Crafted ‘synful knock’ patterns toward routers/switches (same src hits interface/broadcast/network address on same port in short order) followed by ACL/telnet/SSH enablement or module change. Detect device image/ACL updates then a new mgmt session.
  - *Log sources:* `networkdevice:syslog (Config/ACL/line vty changes, service enable (telnet/ssh/http(s)), module reloads)`; `NSM:Flow (Port-knock pattern from one src to device unicast,broadcast,network addresses on same port within TimeWindowKnock)`
  - *Tune:* `MgmtPortSet` — Ports whose sudden enablement should alert (23, 22, 2323, 80/443, 4786).; `DeviceRole` — Applies different thresholds to core/edge/branch devices.

---

### T1205.001 — Port Knocking
<a id="t1205001"></a>

**Detection strategy:** Port-knock → rule/daemon change → first successful connect (T1205.001) (`DET0302`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1205.001](https://attack.mitre.org/techniques/T1205/001/) · [detail page](../../techniques/stealth.md#t1205001)

- **`AN0842` Analytic 0842** · Windows
  A remote source rapidly touches a short sequence of closed ports (SYN→RST/S0) on a Windows host. Within a short window the host changes firewall state (WFP rule added/modified or service starts listening) and then the same source completes the first successful handshake to the newly opened port.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=3, 22)`; `WinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall (EventCode=2004, 2005, 2006)`
  - *Tune:* `TimeWindow` — Seconds to correlate knock sequence → rule change → successful connect (60–300s typical).; `MinSequenceLen` — Minimum number of distinct destination ports in the sequence (≥3 by default).; `RuleChangeAllowList` — Accounts/processes allowed to adjust Windows Firewall (e.g., update agents).; `WatchedPorts` — Ports of interest to flag when opened (e.g., 22,23,2323,8022,3389,8080).
- **`AN0843` Analytic 0843** · Linux
  A source performs a short closed-port sequence; the host then modifies iptables/nftables/ufw rules or starts a daemon binding a new socket, followed by a successful connection from the same source.
  - *Log sources:* `auditd:SYSCALL (execve: Commands that alter firewall or start listeners: iptables|nft|ufw|firewall-cmd|pfctl|systemctl start sshd/telnet/dropbear; raw-socket/libpcap tools (tcpdump, tshark, nmap --raw).)`; `auditd:SYSCALL (socket/bind: New bind() to a previously closed port shortly after the sequence.)`; `NSM:Flow (Knock pattern: repeated REJ/S0 across ≥MinSequenceLen ports from same src_ip then SF success.)`
  - *Tune:* `ServicePort` — Candidate port expected to open after knock (e.g., 22/2323).; `KnockTolerance` — Max seconds between hits inside the sequence.; `MgmtAllowList` — Automation allowed to change firewall/daemon state (config mgmt, orchestration).
- **`AN0844` Analytic 0844** · macOS
  A source performs a closed-port sequence; the endpoint enables a PF/socketfilterfw rule or a background process binds a port; then a successful connection completes from the same source.
  - *Log sources:* `macos:unifiedlog (exec: Execution of pfctl, socketfilterfw, launchctl start ssh/telnet, libpcap consumers.)`; `macos:unifiedlog (Firewall/PF anchor load or rule change events.)`; `NSM:Flow (Sequence of REJ/S0 then SF success from same src_ip within TimeWindow.)`
  - *Tune:* `PFAnchorPaths` — Anchors/confs to monitor (/etc/pf.conf, /etc/pf.anchors/*).; `DevMode` — Suppress expected PF testing on developer devices.
- **`AN0845` Analytic 0845** · Network Devices
  Router/switch receives a knock pattern (same src touches device unicast, broadcast, and network-address on same or stepped ports) followed by ACL/line-vty/service enable and the first mgmt session success.
  - *Log sources:* `networkdevice:syslog (Config/ACL changes, line vty transport input changes, telnet/ssh/http(s) enable, image/feature module changes.)`; `NSM:Flow (Series of denied/closed flows to distinct ports then success to mgmt port from same src_ip within TimeWindow.)`
  - *Tune:* `MgmtPortSet` — Mgmt ports to focus on: 22,23,2323,80,443,161,4786.; `DeviceRole` — Tighten thresholds on edge/internet-facing devices.

---

### T1205.002 — Socket Filters
<a id="t1205002"></a>

**Detection strategy:** Socket-filter trigger → on-host raw-socket activity → reverse connection (T1205.002) (`DET0162`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1205.002](https://attack.mitre.org/techniques/T1205/002/) · [detail page](../../techniques/stealth.md#t1205002)

- **`AN0462` Analytic 0462** · Windows
  Adversary installs/uses packet-capture or raw-socket capability (WinPcap/Npcap, wpcap/packet DLLs or raw socket attach) and sets a filter. A crafted inbound packet is observed; within a short window the host process that loaded capture libraries initiates an outbound connection (e.g., reverse shell) to the packet origin.
  - *Log sources:* `WinEventLog:System (EventCode=7045)`; `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=3, 22)`; `WinEventLog:Sysmon (EventCode=6)`; `WinEventLog:Sysmon (EventCode=7)`; `NSM:Flow (Single, low-volume inbound packet (REJ/S0/OTH or uncommon dport/protocol) from src_ip followed by outbound SF connection to src_ip.)`
  - *Tune:* `TimeWindow` — Seconds to correlate inbound trigger → process library load/driver start → outbound connect (default 120s).; `CaptureLibIndicators` — DLL/driver names to match (wpcap.dll, packet.dll, npcap.sys, npf.sys) – extend for EDR drivers in your fleet.; `AllowedInstallers` — Signed/expected processes allowed to install/start Npcap (software distribution tools).; `ReversePorts` — Likely egress ports to watch after trigger (4444, 53, 80/443, 8080, high ephemeral).
- **`AN0463` Analytic 0463** · Linux
  Process creates a raw/packet socket and attaches a (e)BPF filter (setsockopt SO_ATTACH_FILTER/ATTACH_BPF or bpf(BPF_PROG_LOAD)). Immediately after a matching inbound packet, the same process binds/connects outward to a remote host (reverse shell or beacon).
  - *Log sources:* `auditd:SYSCALL (socket(AF_PACKET|AF_INET, SOCK_RAW, *), setsockopt(… SO_ATTACH_FILTER|SO_ATTACH_BPF …), bpf(cmd=BPF_PROG_LOAD), open/openat path="/dev/bpf*" (BSD/macOS-like) or setcap cap_net_raw.)`; `linux:osquery (family=AF_PACKET or protocol raw; process name not in allowlist.)`; `NSM:Flow (Rare inbound packet characteristics (ICMP/UDP/TCP to uncommon port) from src_ip followed ≤TimeWindow by outbound SF from same host to src_ip.)`
  - *Tune:* `UserContext` — Flag raw-socket activity outside privileged daemons (root-only by default).; `MinPayloadEntropy` — If using packet content (Zeek), treat high-entropy single-packet triggers as suspicious.; `AFPacketAllowList` — System services allowed to open AF_PACKET (dhclient, keepalived, LLDP, monitoring agents).
- **`AN0464` Analytic 0464** · macOS
  Process opens /dev/bpf* (libpcap) or loads NetworkExtension filter, then after a crafted inbound packet the same process initiates an outbound connection to the trigger origin.
  - *Log sources:* `OpenBSM:AuditTrail (open/openat of /dev/bpf*; ioctl BIOCSETF-like operations.)`; `macos:unifiedlog (First outbound connection from the same PID/user shortly after an inbound trigger.)`; `NSM:Flow (Inbound one-off packet to uncommon port → outbound SF to same src_ip within TimeWindow.)`
  - *Tune:* `BPFDevicePath` — Alternate BPF device paths if customized (default /dev/bpf*).; `DeveloperMode` — Relax thresholds on known developer tooling hosts (Xcode, instrumenting tools).

---

### T1211 — Exploitation for Stealth
<a id="t1211"></a>

**Detection strategy:** Detection Strategy for Exploitation for Defense Evasion (`DET0595`)  
**Platforms:** IaaS, Linux, SaaS, Windows, macOS  
**ATT&CK:** [T1211](https://attack.mitre.org/techniques/T1211/) · [detail page](../../techniques/stealth.md#t1211)

- **`AN1633` Analytic 1633** · Windows
  Detects exploitation attempts targeting defensive security software or OS services. Defender observation includes abnormal process behavior (e.g., AV or EDR crashing unexpectedly), unsigned/untrusted modules loaded into defensive processes, or privilege escalation from security agent services. Multi-event correlation ties exploitation attempts to subsequent evasive behavior like service termination or missing logs.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=7)`
  - *Tune:* `DefensiveProcessList` — List of defensive services/processes (e.g., AV, EDR) monitored in the environment.; `AllowedModulePaths` — Whitelisted DLL/module paths normally loaded by defensive tools.; `CrashThreshold` — Number of abnormal terminations of defensive processes tolerated before triggering an alert.
- **`AN1634` Analytic 1634** · Linux
  Detects kernel- or user-space exploitation attempts targeting auditd, AV daemons, or security monitoring agents. Defender observation includes unexpected segfaults, privilege escalation attempts from low-privileged processes, or modifications to security binaries. Correlates exploitation attempts with subsequent gaps in logging or terminated processes.
  - *Log sources:* `auditd:SYSCALL (execve: Execution of suspicious exploit binaries targeting security daemons)`; `linux:syslog (Segfaults, kernel oops, or crashes in security software processes)`
  - *Tune:* `WatchedBinaries` — List of critical security daemons (e.g., auditd, falco, AV agents) to monitor for exploitation.; `CrashPatterns` — Regex or patterns for kernel/syslog errors correlated with exploitation attempts.
- **`AN1635` Analytic 1635** · macOS
  Detects exploitation of macOS security and integrity services, such as Gatekeeper, XProtect, or EDR agents. Defender observations include unsigned processes attempting privileged operations, abnormal termination of security daemons, or modification of system integrity logs.
  - *Log sources:* `macos:unifiedlog (Abnormal terminations of com.apple.security.* or 3rd-party security daemons)`; `macos:osquery (execve: Unsigned or unnotarized processes launched with high privileges)`
  - *Tune:* `SecurityDaemons` — Monitored Apple and third-party EDR/AV daemon names.; `UnsignedProcessThreshold` — Number of unsigned high-privilege executions before alerting.
- **`AN1636` Analytic 1636** · IaaS
  Detects exploitation of IaaS cloud security boundaries to evade defense controls. Defender perspective includes anomalous API calls that bypass audit logging, disable monitoring, or manipulate guardrails (e.g., CloudTrail tampering). Correlation highlights when exploitation attempts precede sudden absence of expected telemetry.
  - *Log sources:* `AWS:CloudTrail (StopLogging, DeleteTrail, UpdateTrail: API calls that disable or modify logging services)`
  - *Tune:* `CriticalAPIs` — List of sensitive cloud API operations that should be rare and tightly monitored.; `TimeWindow` — Duration for correlation of API exploitation with sudden logging gaps.
- **`AN1637` Analytic 1637** · SaaS
  Detects adversary abuse of SaaS platform vulnerabilities to bypass logging, monitoring, or consent boundaries. Defender perspective focuses on abnormal application integration events, missing audit logs, or API calls from unauthorized service principals that align with exploitation attempts.
  - *Log sources:* `m365:unified (ApplicationModified, ConsentGranted: Unexpected app consent or modification events linked to security evasion)`
  - *Tune:* `MonitoredApps` — Applications and integrations expected in the environment; deviations may be suspect.; `ConsentAnomalyThreshold` — Threshold for anomalous OAuth or app consent events before flagging exploitation.

---

### T1216 — System Script Proxy Execution
<a id="t1216"></a>

**Detection strategy:** Detection of Script-Based Proxy Execution via Signed Microsoft Utilities (`DET0466`)  
**Platforms:** Windows  
**ATT&CK:** [T1216](https://attack.mitre.org/techniques/T1216/) · [detail page](../../techniques/stealth.md#t1216)

- **`AN1288` Analytic 1288** · Windows
  Execution of Microsoft-signed scripts (e.g., pubprn.vbs, installutil.exe, wscript.exe, cscript.exe) used to proxy execution of untrusted or external binaries. Behavior is detected through command-line process lineage, child process spawning, and unsigned payload execution from signed parent.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Sysmon (EventCode=11)`
  - *Tune:* `ParentProcessName` — Environment-specific paths to script interpreters like wscript.exe, cscript.exe, pubprn.vbs, or installutil.exe.; `TimeWindow` — Time delta between signed script execution and suspicious child process creation.; `ChildCommandLineRegex` — Regex pattern used to detect malicious payload execution (e.g., download cradle, PowerShell decode).; `SignedToUnsignedTransition` — Indicates whether the parent is signed by Microsoft but child is unsigned or unknown.

---

### T1216.001 — PubPrn
<a id="t1216001"></a>

**Detection strategy:** Detecting Remote Script Proxy Execution via PubPrn.vbs (`DET0528`)  
**Platforms:** Windows  
**ATT&CK:** [T1216.001](https://attack.mitre.org/techniques/T1216/001/) · [detail page](../../techniques/stealth.md#t1216001)

- **`AN1464` Analytic 1464** · Windows
  Execution of PubPrn.vbs via cscript.exe using the 'script:' moniker to load and execute a remote .sct scriptlet file, bypassing signature validation and proxying remote payloads through a signed Microsoft script host.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`; `WinEventLog:Sysmon (EventCode=3, 22)`; `WinEventLog:Sysmon (EventCode=7)`
  - *Tune:* `CommandLineRegex` — Detects 'script:' moniker with HTTP/HTTPS URI as argument to pubprn.vbs; `ParentProcessName` — May vary between cscript.exe, wscript.exe, or cmd.exe depending on execution method; `NetworkDestinationDomain` — Used to detect external domains being contacted for remote scriptlet execution; `TimeWindow` — Maximum allowed time delta between pubprn.vbs invocation and network connection or child process

---

### T1216.002 — SyncAppvPublishingServer
<a id="t1216002"></a>

**Detection strategy:** Detecting PowerShell Execution via SyncAppvPublishingServer.vbs Proxy Abuse (`DET0440`)  
**Platforms:** Windows  
**ATT&CK:** [T1216.002](https://attack.mitre.org/techniques/T1216/002/) · [detail page](../../techniques/stealth.md#t1216002)

- **`AN1220` Analytic 1220** · Windows
  Execution of SyncAppvPublishingServer.vbs through wscript.exe with a command-line containing embedded PowerShell, proxying malicious PowerShell execution through a Microsoft-signed VBScript interpreter to evade detection and restrictions.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=10)`
  - *Tune:* `CommandLineRegex` — Detects embedded PowerShell commands in SyncAppvPublishingServer.vbs invocation, e.g., `{powershell -nop -enc ...}`; `ScriptInterpreter` — May vary between `wscript.exe`, `cscript.exe`, or called via `cmd.exe`; `PowerShellObfuscationScore` — Used to detect encoding, obfuscation, or entropy level in embedded PowerShell payloads; `TimeWindow` — Time delta between VBScript proxy invocation and PowerShell payload execution

---

### T1218 — System Binary Proxy Execution
<a id="t1218"></a>

**Detection strategy:** Detection of Proxy Execution via Trusted Signed Binaries Across Platforms (`DET0081`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1218](https://attack.mitre.org/techniques/T1218/) · [detail page](../../techniques/stealth.md#t1218)

- **`AN0226` Analytic 0226** · Windows
  Execution of trusted, Microsoft-signed binaries such as `rundll32.exe`, `msiexec.exe`, or `regsvr32.exe` used to execute externally hosted, unsigned, or suspicious payloads through command-line parameters or network retrieval.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=3, 22)`; `WinEventLog:Sysmon (EventCode=7)`
  - *Tune:* `ParentProcessName` — Used to profile unexpected parent-child relationships (e.g., regsvr32.exe not launched by explorer.exe); `SignedBinaryList` — List of known signed binaries allowed for execution (e.g., msiexec.exe, regsvr32.exe); `CommandLineRegex` — Regex to match suspicious arguments, such as URLs, script paths, or DLL entrypoints; `RemoteDomainAllowlist` — Filter to suppress activity contacting legitimate enterprise domains
- **`AN0227` Analytic 0227** · Linux
  Execution of trusted system binaries (e.g., `split`, `tee`, `bash`, `env`) used in uncommon sequences or chained behaviors to execute malicious payloads or perform actions inconsistent with normal system or script behavior.
  - *Log sources:* `auditd:SYSCALL (execve)`; `auditd:SYSCALL (connect)`
  - *Tune:* `TrustedBinaryList` — Binaries like `split`, `tee`, `env`, `awk`, `gzip`, often used in benign scripts; `AnomalyScore` — Outlier model for process tree and command arguments
- **`AN0228` Analytic 0228** · macOS
  Use of system binaries such as `osascript`, `bash`, or `curl` to download or execute unsigned code or files in conjunction with application proxying.
  - *Log sources:* `macos:unifiedlog (exec of osascript, bash, curl with suspicious parameters)`; `macos:osquery (execution of trusted tools interacting with external endpoints)`
  - *Tune:* `TrustedUtilityList` — macOS binary whitelist including `/usr/bin/osascript`, `/bin/bash`, `/usr/bin/curl`; `SignedToUnsignedTransition` — Used to detect proxy execution from signed binary to unsigned payload

---

### T1218.001 — Compiled HTML File
<a id="t1218001"></a>

**Detection strategy:** Detection of Suspicious Compiled HTML File Execution via hh.exe (`DET0342`)  
**Platforms:** Windows  
**ATT&CK:** [T1218.001](https://attack.mitre.org/techniques/T1218/001/) · [detail page](../../techniques/stealth.md#t1218001)

- **`AN0968` Analytic 0968** · Windows
  Execution of hh.exe to open a .chm file followed by suspicious child processes or script engine invocation (VBScript, JScript, mshta, powershell). Behavior includes loading a CHM file from untrusted locations, or immediately spawning commands indicative of payload execution.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=3, 22)`
  - *Tune:* `CHMPathRegex` — Regex matching CHM file locations; tune to exclude trusted internal software help files; `ChildProcessList` — List of suspicious children of hh.exe (powershell.exe, cmd.exe, mshta.exe, wscript.exe); `NetworkDestinationAllowlist` — Filter for legitimate update/help servers accessed by hh.exe; `TimeWindow` — Threshold time between hh.exe execution and suspicious follow-on activity

---

### T1218.002 — Control Panel
<a id="t1218002"></a>

**Detection strategy:** Detection of Malicious Control Panel Item Execution via control.exe or Rundll32 (`DET0194`)  
**Platforms:** Windows  
**ATT&CK:** [T1218.002](https://attack.mitre.org/techniques/T1218/002/) · [detail page](../../techniques/stealth.md#t1218002)

- **`AN0558` Analytic 0558** · Windows
  Execution of control.exe or rundll32.exe with parameters pointing to CPL files, especially from non-standard directories or newly created files, followed by suspicious child process execution or registry modifications registering new Control Panel items.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=12)`
  - *Tune:* `CPLPathRegex` — Regex to match CPL file paths; tune to exclude legitimate CPLs in System32; `ParentProcessName` — Helps filter known parent processes that legitimately use control.exe; `NewFileTimeWindow` — Time delta between CPL file creation and execution to detect rapid execution of newly dropped files; `RegistryKeyAllowlist` — Whitelist of known good CPL registry entries

---

### T1218.003 — CMSTP
<a id="t1218003"></a>

**Detection strategy:** Detection of Malicious Profile Installation via CMSTP.exe (`DET0328`)  
**Platforms:** Windows  
**ATT&CK:** [T1218.003](https://attack.mitre.org/techniques/T1218/003/) · [detail page](../../techniques/stealth.md#t1218003)

- **`AN0932` Analytic 0932** · Windows
  Execution of CMSTP.exe with arguments pointing to suspicious or remote INF/SCT/DLL payloads, optionally followed by outbound network connections to untrusted IPs, process injection via COM interfaces (CMSTPLUA, CMLUAUTIL), registry modifications registering malicious profiles, or creation of suspicious INF/DLL/SCT files prior to execution.
  - *Log sources:* `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`; `WinEventLog:Sysmon (EventCode=3, 22)`; `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Sysmon (EventCode=12)`; `WinEventLog:Sysmon (EventCode=13, 14)`; `WinEventLog:Sysmon (EventCode=11)`
  - *Tune:* `INFPathRegex` — Regex for identifying suspicious INF files; adjust to suppress known safe profiles; `ExternalIPAllowlist` — Domains or IP ranges allowed for CMSTP network connections; `COMInterfaceGUIDs` — Set of auto-elevated COM interface GUIDs to flag (e.g., CMSTPLUA, CMLUAUTIL); `RegistryKeyAllowlist` — Known good registry entries for CMSTP profile registration; `TimeWindow` — Correlate CMSTP execution with subsequent network activity or process creation within N seconds

---

### T1218.004 — InstallUtil
<a id="t1218004"></a>

**Detection strategy:** Detection of Malicious Code Execution via InstallUtil.exe (`DET0138`)  
**Platforms:** Windows  
**ATT&CK:** [T1218.004](https://attack.mitre.org/techniques/T1218/004/) · [detail page](../../techniques/stealth.md#t1218004)

- **`AN0388` Analytic 0388** · Windows
  Execution of InstallUtil.exe from .NET framework directories with arguments specifying non-standard or attacker-supplied assemblies, especially when followed by suspicious child process creation or script execution. Detection also includes correlation of newly created binaries prior to InstallUtil invocation and anomalous command-line usage compared to historical baselines.
  - *Log sources:* `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`; `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=7)`
  - *Tune:* `InstallUtilPathRegex` — Regex pattern for InstallUtil.exe in .NET directories; tune to exclude known good administrative scripts; `AssemblyPathRegex` — Patterns for identifying suspicious assemblies (e.g., in temp folders, user profiles); `ChildProcessList` — List of suspicious child processes spawned from InstallUtil.exe (e.g., cmd.exe, powershell.exe, rundll32.exe); `TimeWindow` — Time correlation window between file creation of assembly and its execution via InstallUtil.exe

---

### T1218.005 — Mshta
<a id="t1218005"></a>

**Detection strategy:** Detecting Mshta-based Proxy Execution via Suspicious HTA or Script Invocation (`DET0506`)  
**Platforms:** Windows  
**ATT&CK:** [T1218.005](https://attack.mitre.org/techniques/T1218/005/) · [detail page](../../techniques/stealth.md#t1218005)

- **`AN1397` Analytic 1397** · Windows
  Detection of mshta.exe execution where command-line arguments reference remote or local HTA/script content (VBScript/JScript) followed by subsequent file creation, network retrieval, or process spawning that indicates payload execution outside standard Internet Explorer security context. Correlation includes parent process lineage, command-line inspection, and network connection creation to untrusted or anomalous endpoints.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=3, 22)`; `WinEventLog:Sysmon (EventCode=11)`
  - *Tune:* `CommandLinePattern` — Regex patterns for mshta.exe arguments referencing remote HTA/script content; may need tuning to exclude known-good internal scripts.; `SuspiciousParentProcesses` — List of parent processes considered suspicious when spawning mshta.exe (e.g., Office applications, script interpreters).; `AllowedHTASources` — Whitelist of domains/paths from which legitimate HTAs are executed.; `TimeWindow` — Time threshold for correlating mshta.exe execution with subsequent network connections or file creations.

---

### T1218.007 — Msiexec
<a id="t1218007"></a>

**Detection strategy:** Detection of Msiexec Abuse for Local, Network, and DLL Execution (`DET0158`)  
**Platforms:** Windows  
**ATT&CK:** [T1218.007](https://attack.mitre.org/techniques/T1218/007/) · [detail page](../../techniques/stealth.md#t1218007)

- **`AN0445` Analytic 0445** · Windows
  Detection of msiexec.exe execution where command-line arguments reference remote MSI packages, UNC paths, HTTP/HTTPS URLs, or DLLs, correlated with subsequent module loads and/or network connections to previously unseen destinations. The behavioral chain links process creation of msiexec.exe with suspicious parameters, network activity to retrieve payloads, and module loading indicative of malicious installation or DLL execution.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=3, 22)`
  - *Tune:* `SuspiciousCommandlinePatterns` — Patterns for identifying malicious msiexec.exe usage (e.g., UNC paths, external domains, DLL execution flags); `SuspiciousDestinationList` — List of external domains or IP ranges considered suspicious for msiexec network connections; `TimeWindow` — Time range in seconds/minutes for correlating msiexec.exe execution with module load and network activity; `LegitimateMSIHashes` — Hash list of MSI packages considered known-good to reduce false positives

---

### T1218.008 — Odbcconf
<a id="t1218008"></a>

**Detection strategy:** Detecting Odbcconf Proxy Execution of Malicious DLLs (`DET0486`)  
**Platforms:** Windows  
**ATT&CK:** [T1218.008](https://attack.mitre.org/techniques/T1218/008/) · [detail page](../../techniques/stealth.md#t1218008)

- **`AN1335` Analytic 1335** · Windows
  Identifies abuse of odbcconf.exe to execute malicious DLLs using the REGSVR command flag. Behavior chain: (1) Process creation of odbcconf.exe with /REGSVR or /A {REGSVR ...} arguments → (2) DLL load by odbcconf.exe of non-standard or unsigned modules → (3) Optional follow-on process creation or network activity from loaded DLL.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=3, 22)`
  - *Tune:* `ParentProcessName` — List of approved processes that may legitimately invoke odbcconf.exe; `AllowedCommandPatterns` — Known-good odbcconf.exe arguments in the environment; `TimeWindow` — Time range for correlating module loads and network activity after odbcconf.exe execution; `ApprovedModuleHashes` — Baseline of legitimate DLLs loaded by odbcconf.exe

---

### T1218.009 — Regsvcs/Regasm
<a id="t1218009"></a>

**Detection strategy:** Detecting .NET COM Registration Abuse via Regsvcs/Regasm (`DET0361`)  
**Platforms:** Windows  
**ATT&CK:** [T1218.009](https://attack.mitre.org/techniques/T1218/009/) · [detail page](../../techniques/stealth.md#t1218009)

- **`AN1028` Analytic 1028** · Windows
  Abuse of Regsvcs.exe or Regasm.exe to execute arbitrary code embedded in .NET assemblies via [ComRegisterFunction]/[ComUnregisterFunction]. Behavioral chain: (1) Process creation of regsvcs/regasm with suspicious assembly paths/flags → (2) Assembly/DLL load inside regsvcs/regasm → (3) Registry writes to HKCR\CLSID/ProgID during COM registration → (4) Optional child process or network activity spawned by installer/registration code.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=12)`; `WinEventLog:Sysmon (EventCode=13, 14)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`; `WinEventLog:Sysmon (EventCode=3, 22)`
  - *Tune:* `AssemblyPathRegex` — Environment-specific paths to flag (e.g., %TEMP%, Downloads, OneDrive, SMB shares). Helps suppress known-good installers.; `SuspiciousFlags` — Arguments like /unregister (/u), /codebase, /regfile which may indicate abuse. Tune per enterprise use of regasm/regsvcs.; `ParentProcessAllowList` — Legitimate parents (e.g., setup.exe, msiexec.exe). Analyst can prune false positives from Office or script hosts.; `KnownGoodAssemblies` — Hashes or publisher info for approved assemblies commonly registered in the environment.; `RegistryKeyAllowList` — Approved CLSIDs/ProgIDs written during sanctioned software installs.; `TimeWindow` — Correlation window (e.g., 5–10 min) between file drop → regasm/regsvcs exec → registry writes → child activity.; `SignedToUnsignedTransition` — Alert if Microsoft-signed regasm/regsvcs loads or triggers unsigned assemblies/children.

---

### T1218.010 — Regsvr32
<a id="t1218010"></a>

**Detection strategy:** Detection Strategy for System Binary Proxy Execution: Regsvr32 (`DET0282`)  
**Platforms:** Windows  
**ATT&CK:** [T1218.010](https://attack.mitre.org/techniques/T1218/010/) · [detail page](../../techniques/stealth.md#t1218010)

- **`AN0785` Analytic 0785** · Windows
  Detection focuses on identifying anomalous regsvr32.exe executions that deviate from normal administrative or system use. Defenders may observe regsvr32.exe loading scriptlets or DLLs from unusual paths (especially temporary directories or remote URLs), command-line arguments invoking /i or /u with suspicious file references, network connections initiated by regsvr32.exe, and unsigned or untrusted DLLs being loaded shortly after regsvr32.exe invocation. Correlated sequences include regsvr32.exe process creation, module load of DLL/scriptlet, and optional outbound network traffic.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=3, 22)`
  - *Tune:* `AllowedDLLPaths` — Directories where DLL loading via regsvr32.exe is expected (e.g., C:\Windows\System32).; `ScriptletExtensions` — File extensions considered suspicious when executed by regsvr32.exe (e.g., .sct, .ocx).; `TimeWindow` — Timeframe to correlate regsvr32.exe process creation with subsequent module loads and network connections.; `ParentProcessWhitelist` — Parent processes from which regsvr32.exe is expected (e.g., explorer.exe during legitimate COM object registration).

---

### T1218.011 — Rundll32
<a id="t1218011"></a>

**Detection strategy:** Detection Strategy for T1218.011 Rundll32 Abuse (`DET0475`)  
**Platforms:** Windows  
**ATT&CK:** [T1218.011](https://attack.mitre.org/techniques/T1218/011/) · [detail page](../../techniques/stealth.md#t1218011)

- **`AN1308` Analytic 1308** · Windows
  Detects rundll32.exe invoked with atypical arguments (.dll, .cpl, javascript:, mshtml). DLLs not normally loaded by rundll32 are mapped into memory. Control_RunDLL or RunHTMLApplication invoked. Suspicious DLLs or scripts accessed from disk or network. Rundll32 reaches out to external domains (e.g., fetching .sct or .hta).
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=3, 22)`
  - *Tune:* `TimeWindow` — Correlating rundll32 invocation with DLL load or network activity within X seconds.; `ParentProcessFilter` — Limit detection to suspicious parent processes (e.g., explorer.exe, office apps) vs. trusted installers.; `AllowedDLLs` — Baseline list of legitimate DLLs frequently executed by rundll32 in the environment.; `ExternalIPRange` — Scope of external IP ranges considered anomalous for rundll32 network connections.

---

### T1218.012 — Verclsid
<a id="t1218012"></a>

**Detection strategy:** Detection Strategy for T1218.012 Verclsid Abuse (`DET0042`)  
**Platforms:** Windows  
**ATT&CK:** [T1218.012](https://attack.mitre.org/techniques/T1218/012/) · [detail page](../../techniques/stealth.md#t1218012)

- **`AN0118` Analytic 0118** · Windows
  Detects abuse of verclsid.exe to execute COM objects by monitoring process creation, CLSID arguments, DLLs or scriptlet engines loaded into memory, and If the CLSID points to remote SCT/HTA content, verclsid.exe makes outbound connections.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=13, 14)`; `WinEventLog:Sysmon (EventCode=3, 22)`
  - *Tune:* `AllowedCLSIDs` — Baseline CLSIDs frequently invoked by verclsid.exe in normal shell extension verification.; `ParentProcessFilter` — Unusual parents (e.g., winword.exe, excel.exe) spawning verclsid.exe should be treated as suspicious.; `TimeWindow` — Correlation window between verclsid.exe start, module load, and network activity.; `ExternalIPRange` — Restrict detection to external IPs not in approved ranges to cut noise.

---

### T1218.013 — Mavinject
<a id="t1218013"></a>

**Detection strategy:** Detecting Code Injection via mavinject.exe (App-V Injector) (`DET0433`)  
**Platforms:** Windows  
**ATT&CK:** [T1218.013](https://attack.mitre.org/techniques/T1218/013/) · [detail page](../../techniques/stealth.md#t1218013)

- **`AN1207` Analytic 1207** · Windows
  Abuse of mavinject.exe to inject DLLs or import descriptors into another running process. Chain: (1) mavinject.exe starts with /INJECTRUNNING or /HMODULE → (2) mavinject obtains high-access handles to a target process (VM_WRITE/CREATE_THREAD) → (3) target process loads attacker DLL (module load) → (4) optional follow-on child activity or network egress from the target process.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`; `WinEventLog:Sysmon (EventCode=3, 22)`
  - *Tune:* `TimeWindow` — Correlation interval (e.g., 5–10 minutes) linking mavinject start → ProcessAccess → module load/network from the target process.; `DLLPathRegex` — Patterns for suspicious DLL locations (e.g., %TEMP%, Downloads, UNC shares) to reduce noise from legitimate injections.; `TargetProcessAllowList` — Common legitimate targets for App-V (if used) to suppress; flag unusual targets like browsers, LSASS, Winlogon, EDR processes.; `MinGrantedAccessSet` — Set of access rights that imply injection (VM_WRITE, VM_OPERATION, CREATE_THREAD). Tune for your EDR/sysmon formatting.; `ParentProcessFilter` — Legitimate parents starting mavinject (e.g., App-V services) vs. suspicious parents (Office, script hosts, browsers).; `ExternalIPAllowlist` — Known enterprise update/CDN ranges to exclude when correlating post-injection network activity.; `SignedToUnsignedTransition` — Alerting when Microsoft-signed mavinject leads to loading unsigned DLLs in a target process.

---

### T1218.014 — MMC
<a id="t1218014"></a>

**Detection strategy:** Detecting MMC (.msc) Proxy Execution and Malicious COM Activation (`DET0222`)  
**Platforms:** Windows  
**ATT&CK:** [T1218.014](https://attack.mitre.org/techniques/T1218/014/) · [detail page](../../techniques/stealth.md#t1218014)

- **`AN0622` Analytic 0622** · Windows
  Abuse of mmc.exe to execute non-Microsoft or user-staged .msc files and malicious COM CLSIDs. Behavioral chain: (1) suspicious mmc.exe invocation with /a or -Embedding and non-standard .msc path → (2) COM activation of non-baseline CLSIDs by mmc.exe → (3) mmc.exe loads non-baseline DLLs (user-writable/UNC/unsigned) → (4) optional network/DNS activity from mmc.exe.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=12)`; `WinEventLog:Sysmon (EventCode=13, 14)`; `WinEventLog:Microsoft-Windows-COM/Operational (CLSID activation events where ProcessName=mmc.exe and CLSID not in allowed baseline)`; `WinEventLog:Sysmon (EventCode=3, 22)`; `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`
  - *Tune:* `TimeWindow` — Correlation window (e.g., 5–10 minutes) tying .msc creation → mmc.exe start → module loads → COM/net activity.; `AllowedMSCList` — Set of Microsoft-supplied .msc names/paths allowed in the environment to suppress noise.; `SuspiciousMSCPathRegex` — Regex for user-writable and network paths indicating risky .msc staging (Users, AppData, Downloads, Desktop, UNC).; `AllowedCLSIDs` — Baseline of CLSIDs expected to be activated by mmc.exe; alert on unknown/new.; `ParentProcessAllowList` — Expected parents for mmc.exe (explorer.exe, services) vs. unusual (powershell, wscript, office apps).; `SignedToUnsignedTransition` — Flag when signed mmc.exe results in loading unsigned DLLs.; `ExternalIPAllowlist` — Approved external ranges/domains to exclude when mmc.exe makes network requests.

---

### T1218.015 — Electron Applications
<a id="t1218015"></a>

**Detection strategy:** Detecting Electron Application Abuse for Proxy Execution (`DET0025`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1218.015](https://attack.mitre.org/techniques/T1218/015/) · [detail page](../../techniques/stealth.md#t1218015)

- **`AN0071` Analytic 0071** · Windows
  Abuse of trusted Electron apps (Teams, Slack, Chrome) to spawn child processes or execute payloads via malicious command-line arguments (e.g., --gpu-launcher) and modified app resources (.asar). Behavior chain: suspicious parent process (Electron app) → unusual command-line args → child process creation → optional DLL/network artifacts.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=3, 22)`
  - *Tune:* `TimeWindow` — Correlation window tying app launch, file tampering, child process, and network events (5–10 minutes typical).; `UserContext` — Flag admin/service accounts versus standard users executing Electron apps.; `AllowedElectronApps` — Baseline of Electron-based executables expected in the enterprise.; `AllowedChildProcesses` — Whitelist normal child processes (chrome.exe → crashpad_handler.exe) versus anomalies (powershell.exe).; `ElectronAppDomainAllowlist` — Approved service domains for Teams, Slack, etc. to suppress benign traffic.; `AsarIntegrityHash` — Expected hash/signature of app.asar resources to detect tampering.
- **`AN0072` Analytic 0072** · Linux
  Abuse of Linux Electron binaries by modifying app.asar or config JS files and spawning unexpected child processes (bash, curl, python).
  - *Log sources:* `auditd:SYSCALL (execve: Electron-based binary spawning shell or script interpreter)`; `WinEventLog:Sysmon (EventCode=11)`
  - *Tune:* `AsarIntegrityCheck` — Baseline of expected asar package signatures per app.; `SuspiciousChildProcesses` — Flag shells/python spawned from Electron parent.
- **`AN0073` Analytic 0073** · macOS
  Abuse of macOS Electron apps by modifying app.asar bundles and spawning child processes (osascript, curl, sh) from Electron executables.
  - *Log sources:* `macos:unifiedlog (Electron app spawning unexpected child process)`; `macos:osquery (CREATE/MODIFY: Modification of app.asar inside .app bundle)`
  - *Tune:* `AllowedAppBundlePaths` — Baseline of legitimate Electron app paths under /Applications.; `SignedToUnsignedTransition` — Alert when signed Electron parent spawns unsigned child.

---

### T1220 — XSL Script Processing
<a id="t1220"></a>

**Detection strategy:** Detect XSL Script Abuse via msxsl and wmic (`DET0205`)  
**Platforms:** Windows  
**ATT&CK:** [T1220](https://attack.mitre.org/techniques/T1220/) · [detail page](../../techniques/stealth.md#t1220)

- **`AN0581` Analytic 0581** · Windows
  Execution of XSL scripts via msxsl.exe or wmic.exe using embedded JScript or VBScript for proxy execution. Detection correlates process creation, command-line patterns, and module load behavior of scripting components (e.g., jscript.dll).
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=7)`
  - *Tune:* `CommandLinePattern` — May need to tune based on encoded input or custom extensions (e.g., .jpeg instead of .xsl).; `ParentProcess` — Legitimate administrative or developer tools may use msxsl; validate the parent process chain.; `TimeWindow` — Temporal correlation window between script engine DLL load and suspicious process spawn.; `RemoteXSLDomainWhitelist` — Filter known safe URLs used by enterprise for XSL transformations.

---

### T1221 — Template Injection
<a id="t1221"></a>

**Detection strategy:** Template Injection Detection - Windows (`DET0566`)  
**Platforms:** Windows  
**ATT&CK:** [T1221](https://attack.mitre.org/techniques/T1221/) · [detail page](../../techniques/stealth.md#t1221)

- **`AN1564` Analytic 1564** · Windows
  Detection of Office or document viewer processes (e.g., winword.exe) initiating network connections to remote templates or executing scripts due to manipulated template references (e.g., embedded in .docx, .rtf, or .dotm files), followed by suspicious child process creation (e.g., PowerShell).
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=3, 22)`
  - *Tune:* `TemplateURLPatterns` — Can be tuned to flag known bad domains or external resources in template fields.; `ParentProcess` — May be environment-specific; typically Word, Excel, PowerPoint.; `TimeWindow` — Correlation window for process + network activity.; `ChildProcessAnomalyThreshold` — Trigger when document-spawned child process deviates from expected profile.

---

### T1480 — Execution Guardrails
<a id="t1480"></a>

**Detection strategy:** Multi-Platform Execution Guardrails Environmental Validation Detection Strategy (`DET0562`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1480](https://attack.mitre.org/techniques/T1480/) · [detail page](../../techniques/stealth.md#t1480)

- **`AN1551` Analytic 1551** · Windows
  Windows environmental validation behavioral chain: (1) Rapid system discovery reconnaissance through WMI queries, registry enumeration, and network share discovery, (2) Environment-specific artifact collection (hostname, domain, IP addresses, installed software, hardware identifiers), (3) Cryptographic operations or conditional logic based on collected environmental values, (4) Selective payload execution contingent on environmental validation results, (5) Temporal correlation between discovery activities and subsequent execution or network communication
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Security (EventCode=4648)`; `WinEventLog:Security (EventCode=4624, 4648)`; `WinEventLog:Sysmon (EventCode=3, 22)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=8)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=13, 14)`; `WinEventLog:WMI (EventCode=5857, 5858, 5860, 5861)`; `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`
  - *Tune:* `DiscoveryTimeWindow` — Maximum time window for correlating multiple discovery activities indicating reconnaissance phase - adjust based on normal system behavior (default: 300 seconds); `DiscoveryActivityThreshold` — Minimum number of different discovery techniques within time window to trigger detection - balance between false positives and coverage (default: 4 activities); `CryptographicLibraryWhitelist` — Approved cryptographic libraries and modules for legitimate organizational use - maintain based on approved software inventory; `WMIQueryComplexityThreshold` — Complexity score for WMI queries indicating reconnaissance vs. legitimate administration - tune based on administrative patterns; `EnvironmentalArtifactList` — Environment-specific values commonly targeted by guardrails (hostnames, domains, network shares) - customize for organizational environment; `ExecutionDelayBaseline` — Statistical baseline for normal delay between discovery and execution activities - establish through historical analysis
- **`AN1552` Analytic 1552** · Linux
  Linux environmental validation behavioral chain: (1) Intensive system enumeration through command execution (uname, hostname, ifconfig, lsblk, mount), (2) File system reconnaissance targeting specific paths, network configurations, and installed packages, (3) Process and user enumeration to validate target environment characteristics, (4) Conditional script execution or binary activation based on environmental criteria, (5) Network connectivity validation and external IP address resolution for geolocation verification
  - *Log sources:* `auditd:SYSCALL (execve)`; `auditd:SYSCALL (open)`; `auditd:SYSCALL (openat,connect -k discovery)`; `auditd:PROCTITLE (command-line execution patterns for system discovery utilities (uname, hostname, ifconfig, netstat, lsof, ps, mount))`; `linux:syslog (authentication and authorization events during environmental validation phase)`
  - *Tune:* `SystemDiscoveryCommandList` — Linux commands commonly used for system reconnaissance - customize based on environment-specific discovery patterns; `ReconnaissanceBurstThreshold` — Number of discovery commands within time window indicating reconnaissance burst - tune based on legitimate administrative activity; `EnvironmentalCheckPatterns` — File paths and system properties commonly validated by environmental keying - adapt to organizational infrastructure; `NetworkDiscoveryBaseline` — Normal network discovery activity patterns to distinguish from malicious reconnaissance; `ConditionalExecutionIndicators` — Script patterns and conditional logic indicating environment-based execution decisions
- **`AN1553` Analytic 1553** · macOS
  macOS environmental validation behavioral chain: (1) System profiling through system_profiler, sysctl, and hardware discovery commands, (2) Network interface and configuration enumeration for geolocation and network environment validation, (3) Application installation and version discovery for software environment fingerprinting, (4) Security feature detection (SIP, Gatekeeper, XProtect status), (5) Conditional payload execution based on macOS-specific environmental criteria and System Integrity Protection bypass validation
  - *Log sources:* `macos:unifiedlog (process execution events for system discovery utilities (system_profiler, sysctl, networksetup, ioreg) with parameter analysis)`; `fs:fileevents (File system access events with kFSEventStreamEventFlagItemRemoved, kFSEventStreamEventFlagItemRenamed flags for environmental artifact collection (/System/Library, /usr/sbin, plist files))`
  - *Tune:* `MacOSDiscoveryTools` — macOS-specific system discovery utilities commonly used for environmental validation; `SecurityFeatureEnumeration` — Security features and configurations typically validated by macOS execution guardrails; `HardwareFingerprintBaseline` — Normal hardware discovery patterns to distinguish from environmental validation attempts; `SIPBypassIndicators` — Patterns indicating attempts to validate or bypass System Integrity Protection
- **`AN1554` Analytic 1554** · ESXi
  ESXi hypervisor environmental validation behavioral chain: (1) Virtual machine inventory and configuration enumeration through vim-cmd and esxcli commands, (2) Host hardware and network configuration discovery for hypervisor environment validation, (3) Datastore and storage configuration reconnaissance, (4) vCenter connectivity and cluster membership validation, (5) Selective malware deployment based on virtualization infrastructure characteristics and target VM validation
  - *Log sources:* `esxi:shell (shell command execution for system discovery (vim-cmd, esxcli, vmware-cmd) targeting VM inventory and host configuration)`; `esxi:hostd (host daemon events related to VM operations and configuration queries during reconnaissance)`
  - *Tune:* `ESXiDiscoveryCommands` — ESXi commands commonly used for hypervisor and VM reconnaissance; `VMInventoryEnumerationThreshold` — Number of VM inventory queries within time window indicating reconnaissance activity; `HypervisorEnvironmentBaseline` — Normal hypervisor management activity patterns for distinguishing malicious reconnaissance; `DatastoreAccessPatterns` — Unusual datastore access patterns indicating environmental validation or target selection

---

### T1480.001 — Environmental Keying
<a id="t1480001"></a>

**Detection strategy:** Environmental Keying Discovery-to-Decryption Behavioral Chain Detection Strategy (`DET0474`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1480.001](https://attack.mitre.org/techniques/T1480/001/) · [detail page](../../techniques/stealth.md#t1480001)

- **`AN1305` Analytic 1305** · Windows
  Windows-specific environmental keying behavioral chain: (1) Rapid system information discovery through multiple techniques (WMI queries, registry enumeration, network share discovery, hostname/domain checks), (2) Target validation through specific environmental artifact collection (AD domain membership, network topology, installed software versions), (3) Cryptographic operation correlation indicating payload decryption based on collected environmental values, (4) Subsequent malicious code execution following successful environmental validation, (5) Temporal clustering of discovery activities suggesting automated environmental assessment
  - *Log sources:* `WinEventLog:Security (EventCode=4624, 4648)`; `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=3, 22)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=25)`; `WinEventLog:WMI (EventCode=5857, 5858, 5860, 5861)`; `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`
  - *Tune:* `DiscoveryTimeWindow` — Time window for correlating multiple discovery activities as part of environmental assessment - adjust based on observed attack patterns and system performance (default: 300 seconds); `CriticalDiscoveryThreshold` — Minimum number of distinct discovery techniques within time window to trigger detection - tune based on environment's normal administrative activity levels; `TargetSpecificArtifacts` — Organization-specific environmental elements that adversaries might target (domain names, network shares, specific hostnames, software versions); `CryptographicIndicatorPatterns` — Process names, command lines, and API calls indicating potential decryption operations - customize based on observed cryptographic tool usage in environment; `LegitimateAdminAccounts` — User accounts authorized to perform extensive system discovery - maintain current list to reduce false positives from legitimate administrative activities; `BusinessHoursBaseline` — Normal business hours for risk scoring adjustment - discovery activities outside these hours receive higher risk scores; `WMIQueryComplexityThreshold` — Complexity metric for WMI queries to identify sophisticated environmental assessment versus simple system checks
- **`AN1306` Analytic 1306** · Linux
  Linux environmental keying behavioral chain: (1) System information gathering through native commands (uname, hostname, id, whoami, ifconfig/ip) and file system enumeration, (2) Network configuration discovery (route tables, DNS settings, network interfaces), (3) Filesystem and mount point analysis for target-specific directories or devices, (4) Process and service enumeration to identify target-specific software, (5) Cryptographic library usage correlation with collected environmental data, (6) Payload execution following successful environmental validation
  - *Log sources:* `auditd:SYSCALL (execve syscalls for discovery commands (uname, hostname, id, whoami, ps, netstat, mount) with command-line parameter analysis)`; `linux:syslog (kernel messages related to cryptographic operations, module loading, and filesystem access patterns)`; `linux:osquery (process_events)`
  - *Tune:* `DiscoveryCommandSequenceThreshold` — Number of distinct discovery commands within time window to trigger detection - adjust based on normal system administration patterns in environment; `ProcessAncestryDepth` — Depth of process parent-child relationships to analyze for discovery activity clustering - balance between detection efficacy and performance; `CryptographicLibraryIndicators` — Shared libraries and system calls indicating cryptographic operations (libcrypto, libssl, openssl) - customize based on environment-specific crypto tools; `TargetSpecificFilesystems` — Organization-specific mount points, network filesystems, or device paths that adversaries might validate against; `AuthorizedDiscoveryUsers` — User accounts and service accounts authorized for extensive system discovery operations - maintain for false positive reduction; `NetworkConfigurationBaseline` — Normal network interface configurations and routing tables to identify anomalous network discovery patterns; `ContainerContextIdentifiers` — Container runtime identifiers and namespace patterns to detect environmental assessment targeting container environments
- **`AN1307` Analytic 1307** · macOS
  macOS environmental keying behavioral chain: (1) System information discovery through native utilities (system_profiler, sw_vers, hostname, dscl) and Security framework queries, (2) Hardware and software enumeration including serial numbers, installed applications, and system versions, (3) Network configuration assessment (networksetup, scutil) and wireless network discovery, (4) Keychain and security context validation, (5) Unified Logs correlation with cryptographic framework usage (CommonCrypto, Security.framework), (6) Application bundle execution following environmental validation
  - *Log sources:* `macos:unifiedlog (process execution events for discovery utilities (system_profiler, sw_vers, dscl, networksetup) with command-line parameter analysis)`; `macos:unifiedlog (Security framework operations including keychain access, cryptographic operations, and certificate validation)`; `fs:fsevents (file system events indicating access to system configuration files and environmental information sources)`
  - *Tune:* `SystemProfilerDataTypes` — Specific system_profiler data types that adversaries commonly target (SPHardwareDataType, SPSoftwareDataType, SPNetworkDataType) - customize based on threat intelligence; `SecurityFrameworkOperationPatterns` — Security.framework and CommonCrypto API usage patterns indicating cryptographic operations for environmental keying; `UnifiedLogRetentionWindow` — Time window for correlating discovery activities with subsequent cryptographic operations - balance between detection coverage and log volume; `ApplicationBundleValidationPaths` — Specific application bundle paths and identifiers that might be subject to environmental validation; `NetworkConfigurationIdentifiers` — Organization-specific network configurations, WiFi SSIDs, and network services that adversaries might validate against; `MacOSVersionBaseline` — Expected macOS versions and configurations in environment to identify version-specific environmental targeting; `FSEventsFilteringCriteria` — File system event filtering criteria to focus on security-relevant file access patterns while managing event volume

---

### T1480.002 — Mutual Exclusion
<a id="t1480002"></a>

**Detection strategy:** Detection of Mutex-Based Execution Guardrails Across Platforms (`DET0132`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1480.002](https://attack.mitre.org/techniques/T1480/002/) · [detail page](../../techniques/stealth.md#t1480002)

- **`AN0372` Analytic 0372** · Windows
  Adversary-created named mutex using system APIs (e.g., CreateMutexW) followed by conditional process termination or alternate code path indicating malware avoiding reinfection.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=11)`
  - *Tune:* `mutex_name_entropy_threshold` — Filter out common benign mutex names; highlight suspicious high-entropy/dynamic names.; `parent_process_path` — Limit alerting to non-standard parent-child relationships indicative of malware staging or self-spawning.; `TimeWindow` — Correlate mutex creation + rapid process exit or lack of further activity within a short timeframe.
- **`AN0373` Analytic 0373** · Linux
  File lock acquired via open() + flock() or lockf() on predictable path (e.g., /tmp/.lock123) followed by conditional early exit or divergent process behavior.
  - *Log sources:* `auditd:SYSCALL (open, flock, fcntl, unlink)`; `auditd:SYSCALL (exit_group)`
  - *Tune:* `lockfile_path_regex` — Detect patterns like /tmp/.lock*, /var/run/*lock used by malware.; `exit_code` — Track specific exit codes (e.g., 1, 2) that signal lock acquisition failure.; `TimeWindow` — Correlate lockfile access + early process termination within N seconds.
- **`AN0374` Analytic 0374** · macOS
  User-mode application uses flock() or NSDistributedLock to gain exclusive access to a resource file (e.g., /tmp/guard.lock), conditional logic alters execution if already locked.
  - *Log sources:* `macos:unifiedlog (flock|NSDistributedLock|FileHandle.*lockForWriting)`; `macos:unifiedlog (process.*exit.*code)`
  - *Tune:* `lockfile_path` — Path to mutex file (e.g., /tmp/*, /private/tmp/*), tune per environment.; `user_context` — Flag non-user processes using these APIs.; `TimeWindow` — Detection correlation across short time intervals between lock attempt and process exit.

---

### T1497 — Virtualization/Sandbox Evasion
<a id="t1497"></a>

**Detection strategy:** Detection Strategy for T1497 Virtualization/Sandbox Evasion (`DET0046`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1497](https://attack.mitre.org/techniques/T1497/) · [detail page](../../techniques/stealth.md#t1497)

- **`AN0127` Analytic 0127** · Windows
  Execution of discovery commands or API calls for virtualization artifacts (e.g., registry keys, device drivers, services), sleep/skipped execution behavior, or sandbox evasion DLLs before payload deployment.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=7)`
  - *Tune:* `TimeWindow` — Time range in which multiple discovery processes or sleep/delay operations are executed to avoid sandbox detonation.; `KnownVMArtifactList` — Registry paths, DLLs, services or device names indicative of sandbox/VM environments.
- **`AN0128` Analytic 0128** · Linux
  Execution of commands to enumerate virtualization-related files or processes (e.g., '/sys/class/dmi/id/product_name', dmesg, lscpu, lspci), or querying hypervisor interfaces prior to malware execution.
  - *Log sources:* `auditd:SYSCALL (execve or syscall invoking vm artifact check commands (e.g., dmidecode, lspci, dmesg))`; `auditd:SYSCALL (sleep function usage or loops (nanosleep, usleep) in scripts)`
  - *Tune:* `TimeWindow` — Duration between VM discovery commands and payload execution; `CommandArtifactMatchList` — Command-line regex patterns indicative of sandbox evasion (e.g., grep QEMU, strings vmware)
- **`AN0129` Analytic 0129** · macOS
  Execution of scripts or binaries that check for virtualization indicators (e.g., system_profiler, ioreg -l, kextstat), combined with delay functions or anomalous launchd activity.
  - *Log sources:* `macos:unifiedlog (execution of system_profiler, ioreg, kextstat with argument patterns related to VM/sandbox checks)`; `macos:unifiedlog (dynamic loading of sleep-related functions or sandbox detection libraries)`
  - *Tune:* `ProcessCommandPattern` — Detection regex or substring matching sandbox-related checks; `SleepThreshold` — Maximum duration of sleep execution before alert (e.g., > 5 minutes)

---

### T1497.001 — System Checks
<a id="t1497001"></a>

**Detection strategy:** Virtualization/Sandbox Evasion via System Checks across Windows, Linux, macOS (`DET0168`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1497.001](https://attack.mitre.org/techniques/T1497/001/) · [detail page](../../techniques/stealth.md#t1497001)

- **`AN0478` Analytic 0478** · Windows
  Script or binary performs a rapid sequence of system discovery checks (e.g., CPU count, RAM size, registry keys, running processes) indicative of VM detection
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Sysmon (EventCode=10)`
  - *Tune:* `TimeWindow` — Sequence of system enumeration events within X seconds; `ProcessAncestry` — Parent-child lineage to identify potentially suspicious launch sources (e.g., Office, browser, WMI, PowerShell); `UserContext` — Limit to non-admin or interactive sessions if desired
- **`AN0479` Analytic 0479** · Linux
  Shell script or binary uses multiple system commands (e.g., dmidecode, lscpu, lspci) in quick succession to detect virtualization environment
  - *Log sources:* `auditd:SYSCALL (execve of system tools like dmidecode, lspci, lscpu, dmesg, systemd-detect-virt)`
  - *Tune:* `TimeWindow` — Burst of system info commands within X seconds; `CommandPattern` — Regex or substring matching virtualization artifact checks
- **`AN0480` Analytic 0480** · macOS
  Bash, Swift, or Objective-C programs enumerate system profile, I/O registry, or inspect kernel extensions to identify VM artifacts
  - *Log sources:* `macos:unifiedlog (exec or spawn of 'system_profiler', 'ioreg', 'kextstat', 'sysctl', or calls to sysctl API)`
  - *Tune:* `ExecutionBurst` — Threshold of sequential system checks or tools used in a short time; `ToolName` — Specific tools used for querying device and system metadata

---

### T1497.002 — User Activity Based Checks
<a id="t1497002"></a>

**Detection strategy:** Detect User Activity Based Sandbox Evasion via Input & Artifact Probing (`DET0420`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1497.002](https://attack.mitre.org/techniques/T1497/002/) · [detail page](../../techniques/stealth.md#t1497002)

- **`AN1182` Analytic 1182** · Windows
  Process execution that probes user activity artifacts (e.g., desktop files, registry history) following recent user login/unlock events.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Security (EventCode=4800, 4801)`
  - *Tune:* `TimeWindow` — Window between user unlock and access to user history; `UserContext` — Focus on non-system accounts doing user activity probing
- **`AN1183` Analytic 1183** · Linux
  Access to shell history or GUI input state (xdotool, xinput) for presence validation prior to payload execution.
  - *Log sources:* `auditd:SYSCALL (Reads of ~/.bash_history, ~/.mozilla, or access to /dev/input)`; `auditd:SYSCALL (Execution of xev, xdotool, or input activity emulators)`
  - *Tune:* `ArtifactCountThreshold` — Number of distinct user files accessed before trigger; `KnownToolSignatures` — Suppress expected automation tools
- **`AN1184` Analytic 1184** · macOS
  API usage or filesystem access revealing user state or browser artifacts (e.g., Safari bookmarks, CGEventState).
  - *Log sources:* `macos:unifiedlog (Execution of input detection APIs (e.g., CGEventSourceKeyState))`; `macos:unifiedlog (Access to ~/Library/Safari/Bookmarks.plist or recent files)`
  - *Tune:* `TimeWindow` — Temporal correlation between login and file access; `UserContext` — Exclude expected UI activity from login agents

---

### T1497.003 — Time Based Checks
<a id="t1497003"></a>

**Detection strategy:** Detect Time-Based Evasion via Sleep, Timer Loops, and Delayed Execution (`DET0141`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1497.003](https://attack.mitre.org/techniques/T1497/003/) · [detail page](../../techniques/stealth.md#t1497003)

- **`AN0396` Analytic 0396** · Windows
  Process creation involving suspicious delays (e.g., Sleep, ping -n loops, WaitForSingleObject), followed by sensitive system access or lateral movement behaviors.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=7)`
  - *Tune:* `SleepDurationThreshold` — Defines maximum allowable sleep duration in milliseconds before triggering anomaly detection.; `TimeBetweenExecutionAndNextStage` — Temporal window between initial process and next stage (e.g., lateral movement or persistence), used to correlate dormant activity.; `UserContext` — Whether the activity occurs in SYSTEM or user context may affect legitimacy scoring.
- **`AN0397` Analytic 0397** · Linux
  Script-based execution of sleep loops or time delay commands (e.g., sleep, ping delay, while-loops) followed by file creation or network connections.
  - *Log sources:* `auditd:SYSCALL (execve of sleep or ping command within script interpreted by bash/python)`; `auditd:SYSCALL (file write after sleep delay)`
  - *Tune:* `SleepLoopCount` — Defines how many loop iterations or sleep cycles are considered anomalous in the monitored environment.; `ExecutionScriptType` — Identifies which scripting interpreter is used (e.g., bash, python, perl) to adjust detection logic.
- **`AN0398` Analytic 0398** · macOS
  Use of `usleep`, `nanosleep`, or `NSTimer` calls in executables or binaries with no GUI interaction, especially followed by disk/network activity.
  - *Log sources:* `macos:unifiedlog (application logs referencing NSTimer, sleep, or launchd delays)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `AppBundleIdentifier` — Correlate with known/expected signed apps vs. unsigned binaries to reduce noise.; `TimeToNextEvent` — Minimum time expected between process start and observable I/O for normal apps.

---

### T1535 — Unused/Unsupported Cloud Regions
<a id="t1535"></a>

**Detection strategy:** Detection of Adversary Use of Unused or Unsupported Cloud Regions (IaaS) (`DET0247`)  
**Platforms:** IaaS  
**ATT&CK:** [T1535](https://attack.mitre.org/techniques/T1535/) · [detail page](../../techniques/stealth.md#t1535)

- **`AN0690` Analytic 0690** · IaaS
  Detects creation of cloud instances, services, or resources in normally unused or unsupported regions, especially following initial account access or credential use from known regions. Correlates resource provisioning across regions with absence of historical usage and alerting from standard logging services (e.g., GuardDuty not enabled in that region).
  - *Log sources:* `AWS:CloudTrail (RunInstances)`; `AWS:CloudTrail (CreateBucket)`; `CloudTrail:GetCallerIdentity (GetCallerIdentity)`; `AWS:VPCFlowLogs (High outbound traffic from new region resource)`
  - *Tune:* `UnusedRegionList` — List of regions historically unused by the organization (can vary per tenant/project); `TimeWindow` — Time interval for correlating activity following account access; `AllowedServiceList` — Whitelist of services allowed in secondary/DR regions; `OutboundTrafficThreshold` — Volume threshold to flag suspicious outbound activity

---

### T1542 — Pre-OS Boot
<a id="t1542"></a>

**Detection strategy:** Detection Strategy for T1542 Pre-OS Boot (`DET0278`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1542](https://attack.mitre.org/techniques/T1542/) · [detail page](../../techniques/stealth.md#t1542)

- **`AN0774` Analytic 0774** · Windows
  Unusual modification of boot records (MBR, VBR) or EFI partitions not associated with legitimate patch cycles or OS upgrades. Registry or WMI events associated with firmware update tools executed from unexpected parent processes. API calls (e.g., DeviceIoControl) writing directly to raw disk sectors. Subsequent abnormal boot configuration changes followed by unsigned driver loads.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=9)`
  - *Tune:* `AllowedFirmwareUpdateTools` — Legitimate vendor tools or processes authorized to modify firmware or boot records.; `TimeWindow` — Correlating boot-sector modification with subsequent reboot events.; `EntropyThreshold` — Heuristic threshold for detecting obfuscated/packed boot code.
- **`AN0775` Analytic 0775** · Linux
  Detection of writes to /boot or EFI directories outside of expected package manager updates. Monitoring kernel log and auditd events for attempts to overwrite bootloader binaries (e.g., grub, shim). Unexpected execution of efibootmgr or dd writing to /dev/sdX devices followed by boot parameter changes.
  - *Log sources:* `auditd:SYSCALL (open, write: Modification of /boot/grub/* or /boot/efi/*)`; `auditd:EXECVE (exec: Execution of dd, efibootmgr, or flashrom modifying firmware/boot partitions)`
  - *Tune:* `PackageManagerUpdateWhitelist` — Allowlist of legitimate grub/shim updates via apt, yum, or rpm.; `FilesystemPaths` — Directories (e.g., /boot/efi, /boot/grub) monitored for unauthorized modification.
- **`AN0776` Analytic 0776** · macOS
  Abnormal modification of EFI firmware binaries in /System/Library/CoreServices/ or NVRAM parameters not associated with OS updates. Unified logs capturing calls to bless or nvram commands executed from untrusted parent processes. Sudden unsigned kext loads after EFI variable tampering.
  - *Log sources:* `macos:unifiedlog (Execution of bless or nvram modifying boot parameters)`; `macos:unifiedlog (Modification of /System/Library/CoreServices/boot.efi)`
  - *Tune:* `AllowedBootUtilities` — Known Apple-signed processes responsible for firmware updates.; `BootParamBaseline` — Baseline set of allowed NVRAM boot parameters for anomaly detection.
- **`AN0777` Analytic 0777** · Network Devices
  Unexpected firmware image uploads via TFTP/FTP/SCP. Configuration changes modifying boot image pointers. Logs showing boot variable redirection to non-standard images. Anomalous reboots immediately following firmware changes not tied to patch schedules.
  - *Log sources:* `networkdevice:config (Boot variable modified to point to non-standard or unsigned image)`; `networkdevice:firmware (Unexpected firmware image upload events via TFTP/FTP/SCP)`
  - *Tune:* `ApprovedFirmwareHashes` — Known good firmware image hashes allowed for boot.; `MaintenanceWindows` — Timeframes during which firmware updates are expected.

---

### T1542.001 — System Firmware
<a id="t1542001"></a>

**Detection strategy:** Detection Strategy for T1542.001 Pre-OS Boot: System Firmware (`DET0099`)  
**Platforms:** Network Devices, Windows  
**ATT&CK:** [T1542.001](https://attack.mitre.org/techniques/T1542/001/) · [detail page](../../techniques/stealth.md#t1542001)

- **`AN0275` Analytic 0275** · Windows
  Unexpected write operations to BIOS/UEFI firmware regions or EFI boot partitions that do not correlate with legitimate vendor firmware updates. API calls or utilities such as fwupdate.exe or vendor flash tools executed from non-administrative or non-IT management accounts. Suspicious raw disk writes targeting System Firmware GUID partitions followed by abnormal reboot sequences.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=9)`; `WinEventLog:Sysmon (EventCode=11)`
  - *Tune:* `AllowedFirmwareUpdateTools` — Legitimate vendor tools permitted to perform firmware flashing or BIOS updates.; `TimeWindow` — Expected time periods for approved firmware updates, used for correlating suspicious activity outside patch cycles.; `KnownGoodFirmwareHashes` — Baseline hashes of vendor BIOS/UEFI firmware for integrity comparison.
- **`AN0276` Analytic 0276** · Network Devices
  Unauthorized firmware uploads to routers, switches, or firewalls via TFTP/FTP/SCP. Logs showing boot variable or startup image path changes redirecting to non-standard firmware images. Abnormal reboots or firmware rollback attempts following configuration modification events.
  - *Log sources:* `networkdevice:config (Boot image path or firmware configuration variable modified outside of maintenance windows)`; `networkdevice:runtime (Firmware image uploaded via TFTP/FTP/SCP)`
  - *Tune:* `ApprovedFirmwareHashes` — Known good firmware image hashes stored for validation.; `MaintenanceWindows` — Expected time periods when firmware uploads or reboots are considered normal.; `SourceIPWhitelist` — List of trusted management IPs allowed to initiate firmware uploads.

---

### T1542.002 — Component Firmware
<a id="t1542002"></a>

**Detection strategy:** Detection Strategy for T1542.002 Pre-OS Boot: Component Firmware (`DET0323`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1542.002](https://attack.mitre.org/techniques/T1542/002/) · [detail page](../../techniques/stealth.md#t1542002)

- **`AN0916` Analytic 0916** · Windows
  Detection of anomalous driver and firmware interactions, including unsigned or unexpected firmware updates, driver loads linked to hardware components, and suspicious use of privileged APIs to read/write firmware or controller memory.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=6)`; `firmware:integrity  (Firmware integrity verification failures or mismatches against expected UEFI/firmware image baselines)`
  - *Tune:* `KnownGoodFirmwareHashes` — Environment-specific list of baseline firmware images for integrity comparison; `DriverAllowList` — Drivers approved for loading in production environments; `TimeWindow` — Correlation period between firmware modification attempt and abnormal driver or process behavior
- **`AN0917` Analytic 0917** · Linux
  Detection of suspicious use of ioctl/sysfs calls to access device firmware, unexpected flashing tools execution, and anomalous firmware checksums logged by SMART or kernel audit mechanisms.
  - *Log sources:* `auditd:SYSCALL (ioctl/write: Direct firmware update or device memory manipulation syscalls)`; `linux:syslog (Driver load events or firmware load failures for hardware devices)`
  - *Tune:* `FirmwareImageBaseline` — Baseline firmware checksums for comparison; `AlertThresholds` — Tolerance levels for SMART errors before triggering alerts
- **`AN0918` Analytic 0918** · macOS
  Detection of EFI/firmware manipulation attempts via abnormal driver loads, unsigned kexts, or tampered NVRAM variables associated with component firmware configuration.
  - *Log sources:* `macos:unifiedlog (Firmware update events or kernel extension (kext) loads not signed by Apple)`
  - *Tune:* `ApprovedKextList` — List of trusted and signed kexts permitted in production systems; `EFIHashBaseline` — Known-clean EFI image hashes used for verification

---

### T1542.003 — Bootkit
<a id="t1542003"></a>

**Detection strategy:** Detection Strategy for File Creation or Modification of Boot Files (`DET0150`)  
**Platforms:** Linux, Windows  
**ATT&CK:** [T1542.003](https://attack.mitre.org/techniques/T1542/003/) · [detail page](../../techniques/stealth.md#t1542003)

- **`AN0428` Analytic 0428** · Windows
  Detection of raw access to physical drives, modification of boot records (MBR/VBR), and suspicious file creation or alteration within the EFI System Partition (ESP). Correlates privileged process execution with low-level disk modification and unexpected driver or firmware interactions.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=9)`; `WinEventLog:Sysmon (EventCode=11)`
  - *Tune:* `KnownGoodMBRHashes` — Baseline hashes of clean MBR/VBR sectors for comparison; `ESPFileWhitelist` — Approved EFI executables within ESP directories; `TimeWindow` — Correlation window between privileged access, raw disk modification, and EFI file creation
- **`AN0429` Analytic 0429** · Linux
  Detection of suspicious write operations to block devices, modifications of bootloader files (GRUB, initrd, vmlinuz), and unexpected changes within the EFI System Partition. Monitors privileged execution of utilities like dd, grub-install, or efibootmgr that modify boot sectors or loader entries.
  - *Log sources:* `auditd:SYSCALL (open, write: Write operations targeting /dev/sda, /dev/nvme0n1, or EFI partition mounts)`; `linux:syslog (Block device write errors or unusual bootloader activity)`
  - *Tune:* `BootloaderHashBaseline` — Baseline checksums of GRUB, kernel, and initramfs images; `EFIFileAllowlist` — Trusted EFI executables for Linux environments; `AlertThresholds` — Tunable thresholds for triggering alerts on repeated EFI/bootloader writes

---

### T1542.004 — ROMMONkit
<a id="t1542004"></a>

**Detection strategy:** Detection Strategy for T1542.004 Pre-OS Boot: ROMMONkit (`DET0175`)  
**Platforms:** Network Devices  
**ATT&CK:** [T1542.004](https://attack.mitre.org/techniques/T1542/004/) · [detail page](../../techniques/stealth.md#t1542004)

- **`AN0497` Analytic 0497** · Network Devices
  Detection of anomalous ROMMON image changes or upgrades, unexpected reboots following firmware updates, and unauthorized use of firmware upgrade commands or TFTP transfers. Correlation of config modification, privilege escalation, and boot cycle anomalies provides visibility into ROMMON tampering attempts.
  - *Log sources:* `networkdevice:config (Log entries indicating ROMMON image upgrade commands (boot system, upgrade rom-monitor))`; `networkdevice:syslog (Unexpected reload, crashinfo, or boot message not tied to scheduled maintenance)`; `NSM:Flow (Outbound or inbound TFTP file transfers of ROMMON or firmware binaries)`
  - *Tune:* `ApprovedROMMONVersions` — Baseline ROMMON image versions authorized for the environment; `TimeWindow` — Correlation window between ROMMON update command, TFTP file transfer, and device reboot; `AdminUserContext` — Expected privileged accounts allowed to execute ROMMON upgrade commands

---

### T1542.005 — TFTP Boot
<a id="t1542005"></a>

**Detection strategy:** Detection Strategy for T1542.005 Pre-OS Boot: TFTP Boot (`DET0582`)  
**Platforms:** Network Devices  
**ATT&CK:** [T1542.005](https://attack.mitre.org/techniques/T1542/005/) · [detail page](../../techniques/stealth.md#t1542005)

- **`AN1603` Analytic 1603** · Network Devices
  Detection of unauthorized changes to boot configurations pointing to TFTP servers, unusual firmware loads during netbooting, or suspicious TFTP traffic. Correlation of boot config modifications, command history logs, and unexpected system image hashes provides detection coverage for adversaries attempting to persist via malicious TFTP boot images.
  - *Log sources:* `networkdevice:config (Configuration changes referencing 'boot system tftp' or modification of startup-config pointing to external TFTP servers)`; `networkdevice:syslog (Boot information log showing image loaded from TFTP server instead of local storage)`; `NSM:Flow (Unexpected inbound/outbound TFTP traffic for device image files)`
  - *Tune:* `ApprovedTFTPServers` — Whitelist of TFTP servers authorized for netbooting in the environment; `TimeWindow` — Detection correlation window between config change, TFTP activity, and system reboot; `BaselineBootImageHash` — Expected system image hashes to validate integrity of boot images loaded via TFTP

---

### T1564 — Hide Artifacts
<a id="t1564"></a>

**Detection strategy:** Detection Strategy for Hidden Artifacts Across Platforms (`DET0502`)  
**Platforms:** ESXi, Linux, Office Suite, Windows, macOS  
**ATT&CK:** [T1564](https://attack.mitre.org/techniques/T1564/) · [detail page](../../techniques/stealth.md#t1564)

- **`AN1384` Analytic 1384** · Windows
  Abuse of file/registry attributes to hide malicious files, directories, or services. Defender view: detection of attrib.exe setting hidden/system flags, creation of Alternate Data Streams, or registry keys altering file visibility.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=13, 14)`
  - *Tune:* `FileExtensions` — Filter for sensitive file types likely targeted for hiding.; `ADSDetection` — Enable or disable detection of Alternate Data Streams depending on business use.
- **`AN1385` Analytic 1385** · Linux
  Hidden file creation using leading '.' or file attribute changes with chattr (immutable/hidden flags). Defender view: detect execution of chattr, lsattr anomalies, and unusual hidden files appearing in system directories.
  - *Log sources:* `auditd:EXECVE (Execution of chattr to set +i or +a attributes)`; `auditd:FILE (Creation of hidden files (.*) in sensitive directories (/etc, /var, /usr/bin))`
  - *Tune:* `DirectoryScope` — Restrict hidden file detection to privileged system directories.; `AttributeFlags` — Tune for specific chattr flags (+i immutable, +a append-only) most abused for persistence.
- **`AN1386` Analytic 1386** · macOS
  Hidden files via 'chflags hidden' or Apple-specific attributes, LaunchAgents/LaunchDaemons placed in non-standard hidden directories. Defender view: detect command execution modifying file flags and unusual plist creation in hidden paths.
  - *Log sources:* `macos:unifiedlog (Execution of chflags hidden or setfile -a V)`; `macos:unifiedlog (Creation of LaunchAgents/LaunchDaemons in hidden or non-standard directories)`
  - *Tune:* `HiddenDirectories` — List of directories monitored for hidden plist or agent placement.
- **`AN1387` Analytic 1387** · ESXi
  Abuse of VMFS or ESXi shell to hide datastore files, renaming/moving VMDK or VMX files into hidden directories. Defender view: anomalous ESXi shell commands or file operations obscuring VM artifacts.
  - *Log sources:* `esxi:shell (mv, rename, or chmod commands moving VM files into hidden directories)`; `esxi:syslog (Datastore file hidden or renamed unexpectedly)`
  - *Tune:* `VMFileScope` — Restrict to VMDK, VMX, or log files critical for VM operations.
- **`AN1388` Analytic 1388** · Office Suite
  Malicious macros or embedded objects hidden within Office documents by renaming streams or using hidden OLE objects. Defender view: detection of hidden macro streams or objects in documents correlated with anomalous execution.
  - *Log sources:* `m365:unified (Detection of hidden macro streams or SetHiddenAttribute actions)`
  - *Tune:* `MacroScope` — Tune detection to specific Office apps and document types where macros are disallowed.

---

### T1564.001 — Hidden Files and Directories
<a id="t1564001"></a>

**Detection strategy:** Detection Strategy for Hidden Files and Directories (`DET0032`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1564.001](https://attack.mitre.org/techniques/T1564/001/) · [detail page](../../techniques/stealth.md#t1564001)

- **`AN0091` Analytic 0091** · Windows
  Suspicious use of attrib.exe or PowerShell commands to set hidden attributes on files/directories. Defender view: processes modifying file attributes to 'hidden' or creating files with ADS (alternate data streams).
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=11)`
  - *Tune:* `MonitoredExtensions` — Filter hidden file detection by sensitive file extensions (.exe, .dll, .bat).; `ADSMonitoring` — Enable detection of alternate data streams depending on organizational usage.
- **`AN0092` Analytic 0092** · Linux
  Creation of files or directories with a leading '.' in privileged directories (/etc, /var, /usr/bin). Defender view: monitoring auditd logs for file creations where name begins with '.' and correlated with unusual user/process context.
  - *Log sources:* `auditd:FILE (File creation with name starting with '.')`; `auditd:EXECVE (Use of mv or cp to rename files with '.' prefix)`
  - *Tune:* `DirectoryScope` — Restrict detection to critical directories to avoid noise from benign hidden files like .ssh or .config.
- **`AN0093` Analytic 0093** · macOS
  Use of chflags hidden or SetFile -a V commands to hide files, or creation of hidden files with leading '.'. Defender view: monitoring process execution and file metadata changes setting UF_HIDDEN attribute.
  - *Log sources:* `macos:unifiedlog (Execution of chflags hidden or SetFile -a V)`; `macos:unifiedlog (File metadata updated with UF_HIDDEN flag)`
  - *Tune:* `HiddenAttributeScope` — Restrict detection to non-standard directories where hidden flags are unexpected.

---

### T1564.002 — Hidden Users
<a id="t1564002"></a>

**Detection strategy:** Detection Strategy for Hidden User Accounts (`DET0353`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1564.002](https://attack.mitre.org/techniques/T1564/002/) · [detail page](../../techniques/stealth.md#t1564002)

- **`AN1001` Analytic 1001** · Windows
  Registry modifications to HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList setting user visibility to 0, or creation of user accounts not shown on login screen. Defender view: correlation of account creation with registry edits that mark users hidden.
  - *Log sources:* `WinEventLog:Security (EventCode=4720)`; `WinEventLog:Sysmon (EventCode=13, 14)`
  - *Tune:* `AccountScope` — Restrict monitoring to privileged or unexpected accounts.; `BaselineHiddenUsers` — Whitelist accounts that are intentionally hidden by administrators.
- **`AN1002` Analytic 1002** · Linux
  Use of gsettings or direct Display Manager modifications to hide users from greeter login screen. Defender view: anomalous command execution modifying org.gnome.login-screen or other greeter configurations.
  - *Log sources:* `auditd:EXECVE (Execution of gsettings set org.gnome.login-screen disable-user-list true)`; `auditd:FILE (Modification of Display Manager configuration files (/etc/gdm3/*, /etc/lightdm/*))`
  - *Tune:* `DisplayManagerScope` — Specify which Display Managers are in use to minimize noise.
- **`AN1003` Analytic 1003** · macOS
  User creation or modification via dscl with IsHidden=1, UID<500, or plist edits to com.apple.loginwindow Hide500Users flag. Defender view: correlation of hidden account attributes with login screen exclusion.
  - *Log sources:* `macos:unifiedlog (Execution of dscl . create with IsHidden=1)`; `macos:unifiedlog (Modification of /Library/Preferences/com.apple.loginwindow plist)`; `macos:unifiedlog (Creation of user account with UID <500)`
  - *Tune:* `UIDThreshold` — Tune detection based on acceptable UID ranges for hidden/system accounts.; `PlistScope` — Restrict plist monitoring to com.apple.loginwindow to reduce false positives.

---

### T1564.003 — Hidden Window
<a id="t1564003"></a>

**Detection strategy:** Detection Strategy for Hidden Windows (`DET0128`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1564.003](https://attack.mitre.org/techniques/T1564/003/) · [detail page](../../techniques/stealth.md#t1564003)

- **`AN0360` Analytic 0360** · Windows
  Suspicious use of scripting parameters or registry edits to hide process windows (e.g., powershell.exe -WindowStyle Hidden, or registry modifications pushing window positions off screen). Defender view: correlation of hidden execution with anomalous process lineage or hVNC-like CreateDesktop API calls.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=13, 14)`
  - *Tune:* `HiddenProcessScope` — Restrict to processes where hidden execution is unexpected (e.g., PowerShell, cmd, wscript).; `ParentProcessCorrelation` — Correlate hidden execution with suspicious parent processes to reduce false positives.
- **`AN0361` Analytic 0361** · Linux
  Suspicious invocation of GUI utilities or scripts with suppressed or redirected windowing options. Defender view: detection of X11 or Wayland calls to spawn windows that do not appear on active displays, or use of nohup/screen/tmux to mask interactive shells.
  - *Log sources:* `auditd:EXECVE (Execution of GUI-related binaries with suppressed window/display flags)`; `auditd:SYSCALL (Use of fork/exec with DISPLAY unset or redirected)`
  - *Tune:* `DisplayScope` — Restrict monitoring to interactive GUI contexts rather than server/headless processes.
- **`AN0362` Analytic 0362** · macOS
  Modification of plist files to set apple.awt.UIElement or similar flags hiding app icons and windows, and dscl/command-line activity that suppresses visibility. Defender view: correlation of plist modifications with unexpected hidden user applications.
  - *Log sources:* `macos:unifiedlog (Modification of plist with apple.awt.UIElement set to TRUE)`; `macos:unifiedlog (Execution of Java apps or other processes with hidden window attributes)`
  - *Tune:* `PlistScope` — Restrict detection to application plists where UIElement flag is unexpected.; `UserContext` — Correlate plist modifications with the creating/modifying user to tune results.

---

### T1564.004 — NTFS File Attributes
<a id="t1564004"></a>

**Detection strategy:** Detection Strategy for NTFS File Attribute Abuse (ADS/EAs) (`DET0432`)  
**Platforms:** Windows  
**ATT&CK:** [T1564.004](https://attack.mitre.org/techniques/T1564/004/) · [detail page](../../techniques/stealth.md#t1564004)

- **`AN1206` Analytic 1206** · Windows
  Suspicious use of NTFS file attributes such as Alternate Data Streams (ADS) or Extended Attributes (EA) to hide data. Defender perspective: anomalous file creations or modifications containing colon syntax (file.ext:ads), API calls like ZwSetEaFile/ZwQueryEaFile, or PowerShell/Windows utilities interacting with -stream parameters. Correlation across file metadata anomalies, process lineage, and command execution provides context.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=15)`; `etw:Microsoft-Windows-Kernel-File (ZwSetEaFile or ZwQueryEaFile function calls)`
  - *Tune:* `ADSPathWhitelist` — Exclude legitimate ADS usage by system or AV tools.; `ProcessScope` — Restrict monitoring to suspicious parent processes (e.g., powershell.exe, cmd.exe, wscript.exe).; `TimeWindow` — Correlate ADS creation with subsequent process execution to strengthen malicious context.

---

### T1564.005 — Hidden File System
<a id="t1564005"></a>

**Detection strategy:** Detection Strategy for Hidden File System Abuse (`DET0461`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1564.005](https://attack.mitre.org/techniques/T1564/005/) · [detail page](../../techniques/stealth.md#t1564005)

- **`AN1271` Analytic 1271** · Windows
  Anomalous creation or mounting of hidden partitions or virtual file systems. Defender view: detection of registry modifications linked to non-standard file systems, suspicious disk I/O patterns, or bootkit-like behavior where hidden volumes are accessed outside normal file system APIs.
  - *Log sources:* `WinEventLog:Security (EventCode=4663, 4670, 4656)`; `WinEventLog:Sysmon (EventCode=13, 14)`; `etw:Microsoft-Windows-Kernel-Storage (Raw disk I/O operations bypassing NTFS APIs)`
  - *Tune:* `MonitoredRegistryKeys` — Specify registry paths for mount points and hidden partition configs.; `DiskIOThreshold` — Tune thresholds for raw disk access outside expected drivers.; `TimeWindow` — Correlate boot-time anomalies with hidden file system mounting activity.
- **`AN1272` Analytic 1272** · Linux
  Unusual mounting of loopback or pseudo file systems not aligned with legitimate administrative activity. Defender view: monitoring auditd and syslog for mount commands involving suspicious mount points, reserved blocks, or device mappings indicative of hidden partitions.
  - *Log sources:* `auditd:SYSCALL (mount or losetup commands creating hidden or encrypted FS)`; `linux:syslog (Sudo or root escalation followed by filesystem mount commands)`
  - *Tune:* `AllowedMountPoints` — Whitelist standard mount points to reduce false positives.; `UserContext` — Flag root escalation during mount operations.
- **`AN1273` Analytic 1273** · macOS
  Hidden file system use through APFS containers or custom plist configuration. Defender view: anomalous use of hdiutil or diskutil to attach hidden partitions, modification of plist entries tied to system volumes, or suspicious raw disk access.
  - *Log sources:* `macos:unifiedlog (Execution of diskutil or hdiutil attaching hidden partitions)`; `macos:unifiedlog (Hidden volume attachment or modification events)`
  - *Tune:* `MonitoredPlistPaths` — Adjust to target only relevant plist files linked to volume mounting.; `ProcessScope` — Restrict monitoring to sensitive processes like diskutil and hdiutil.

---

### T1564.006 — Run Virtual Instance
<a id="t1564006"></a>

**Detection strategy:** Detection Strategy for Hidden Virtual Instance Execution (`DET0321`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1564.006](https://attack.mitre.org/techniques/T1564/006/) · [detail page](../../techniques/stealth.md#t1564006)

- **`AN0909` Analytic 0909** · Windows
  Unusual execution of virtualization binaries (VBoxManage.exe, vmware-vmx.exe, vmwp.exe) with headless or suppressed notification arguments. Registry and service modifications linked to virtualization installs. Defender view: anomalies in process creation, service metadata, and registry writes tied to enabling hidden VMs.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:System (EventCode=7045)`; `WinEventLog:Security (EventCode=4657)`
  - *Tune:* `VirtualizationBinaryWhitelist` — Exclude known administrative VM software usage in enterprise environments.; `TimeWindow` — Correlate registry and service modifications with VM process starts within a narrow time frame.
- **`AN0910` Analytic 0910** · Linux
  Execution of QEMU, KVM, or VirtualBox processes with unusual flags (e.g., '-nographic', '-snapshot'). File creation of VM images in atypical directories. Defender view: monitoring audit logs for process executions and file modifications linked to hidden virtualization.
  - *Log sources:* `auditd:SYSCALL (execve calls for qemu-system*, kvm, or VBoxHeadless)`; `auditd:SYSCALL (File creations of *.qcow2, *.vdi, *.vmdk outside standard VM directories)`
  - *Tune:* `ImageDirectoryWhitelist` — Legitimate VM image storage paths to reduce false positives.; `UserContext` — Correlate suspicious VM execution with non-admin or service accounts.
- **`AN0911` Analytic 0911** · macOS
  Execution of virtualization binaries (Parallels, VMware Fusion, VirtualBox) with arguments to hide UI. File monitoring for plist modifications indicating hidden virtualization behavior. Defender perspective: tracking process lineage and file modifications in system configs.
  - *Log sources:* `macos:unifiedlog (Process execution for VBoxHeadless, prl_vm_app, vmware-vmx)`; `macos:unifiedlog (Plist modifications containing virtualization run configurations)`
  - *Tune:* `PlistKeyScope` — Focus monitoring on UI suppression or VM auto-run keys.
- **`AN0912` Analytic 0912** · ESXi
  Direct execution of /bin/vmx or presence of rogue .vmx files not registered in vCenter inventory. Defender perspective: anomalous commands in shell history, edits to rc.local.d/local.sh for persistence.
  - *Log sources:* `esxi:hostd (Execution of '/bin/vmx' or modifications to '/etc/rc.local.d/local.sh')`; `esxi:vmkernel (VMX startup messages without associated vCenter inventory records)`
  - *Tune:* `VMInventorySync` — Cross-verify running VMs with vCenter inventory for rogue instances.

---

### T1564.007 — VBA Stomping
<a id="t1564007"></a>

**Detection strategy:** Detection Strategy for VBA Stomping (`DET0012`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1564.007](https://attack.mitre.org/techniques/T1564/007/) · [detail page](../../techniques/stealth.md#t1564007)

- **`AN0034` Analytic 0034** · Windows
  Discrepancies between VBA source code and p-code inside Office documents. Defender perspective: anomalies in file metadata streams, execution of Office processes loading macros without source code consistency, and script execution with no corresponding source metadata.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `MonitoredExtensions` — Expand or restrict which Office file types (.docm, .xlsm, .pptm) are flagged for VBA project analysis.; `TimeWindow` — Correlate Office process execution with subsequent script execution within a narrow window.
- **`AN0035` Analytic 0035** · Linux
  Execution of Wine or LibreOffice macros with inconsistent VBA metadata. Defender perspective: file analysis showing p-code embedded without matching source streams.
  - *Log sources:* `auditd:SYSCALL (execve calls to soffice.bin with suspicious macro execution flags)`; `linux:syslog (Discrepancies in _VBA_PROJECT p-code vs source code extracted with oletools/pcodedmp)`
  - *Tune:* `ScannerTooling` — Choice of OLE/P-code analysis utilities (oletools, pcodedmp, custom disassembler).
- **`AN0036` Analytic 0036** · macOS
  Opening of Office files where VBA source code appears benign or missing, but p-code remains active. Defender perspective: process execution of Office apps with macro execution lacking visible source components.
  - *Log sources:* `macos:unifiedlog (Process execution of Microsoft Word, Excel, PowerPoint with macro execution attempts)`; `macos:unifiedlog (Detection of altered _VBA_PROJECT or PerformanceCache streams)`
  - *Tune:* `OfficeVersionScope` — Adjust for specific Office versions in use across macOS endpoints.

---

### T1564.008 — Email Hiding Rules
<a id="t1564008"></a>

**Detection strategy:** Detection Strategy for Email Hiding Rules (`DET0192`)  
**Platforms:** Linux, Office Suite, Windows, macOS  
**ATT&CK:** [T1564.008](https://attack.mitre.org/techniques/T1564/008/) · [detail page](../../techniques/stealth.md#t1564008)

- **`AN0551` Analytic 0551** · Windows
  Suspicious creation or modification of inbox rules through PowerShell (New-InboxRule, Set-InboxRule) to automatically delete, move, or hide emails. Defender perspective: unusual rule activity correlated with mailbox access and filtering patterns.
  - *Log sources:* `WinEventLog:Security (EventCode=4103, 4104, 4105, 4106)`; `m365:unified (New-InboxRule or Set-InboxRule events recorded in Exchange Online)`
  - *Tune:* `SuspiciousKeywords` — Keywords like 'phish', 'malware', 'suspicious' used in inbox rules to hide emails.; `UserContext` — Scope mailbox monitoring to high-value users such as executives or admins.
- **`AN0552` Analytic 0552** · macOS
  Alterations to plist configuration files (RulesActiveState.plist, SyncedRules.plist, UnsyncedRules.plist, MessageRules.plist) that define email hiding or filtering rules. Defender perspective: unexpected changes in these files associated with Mail.app processes.
  - *Log sources:* `macos:unifiedlog (Modifications to Mail.app plist files controlling message rules)`; `macos:unifiedlog (Mail.app executing with parameters updating rules state)`
  - *Tune:* `WatchedPlistFiles` — Adjust to monitor only rule-related plist files relevant to the environment.
- **`AN0553` Analytic 0553** · Linux
  Rule manipulation through local email clients (e.g., Evolution, Thunderbird) or server-side filtering scripts (e.g., sieve) creating conditions to move or discard emails with security-related keywords.
  - *Log sources:* `auditd:SYSCALL (execve calls modifying local mail filter configuration files)`; `ApplicationLog:MailServer (Unexpected additions of sieve rules or filtering directives)`
  - *Tune:* `MailServerLogs` — Customize based on mail server software (Postfix, Dovecot, Exim).
- **`AN0554` Analytic 0554** · Office Suite
  Suspicious rule creation within Outlook or Exchange clients, including auto-move or delete conditions tied to incident or security alert keywords. Defender perspective: correlation between missing inbound emails and newly added mailbox rules.
  - *Log sources:* `m365:unified (Transport rule or inbox rule creation events)`
  - *Tune:* `RuleScope` — Decide whether to monitor individual mailbox rules, org-wide transport rules, or both.

---

### T1564.009 — Resource Forking
<a id="t1564009"></a>

**Detection strategy:** Detection Strategy for Resource Forking on macOS (`DET0584`)  
**Platforms:** macOS  
**ATT&CK:** [T1564.009](https://attack.mitre.org/techniques/T1564/009/) · [detail page](../../techniques/stealth.md#t1564009)

- **`AN1609` Analytic 1609** · macOS
  Unexpected creation or modification of files with `com.apple.ResourceFork` extended attributes containing unusually large or non-standard data. Defender perspective: detection of resource forks in contexts where they are uncommon, especially when paired with process execution or network activity.
  - *Log sources:* `macos:unifiedlog (File creation or modification with com.apple.ResourceFork extended attribute)`; `macos:unifiedlog (Execution of commands like `ls -l@`, `xattr -l`, or custom tools interacting with resource forks)`; `macos:unifiedlog (Process creation involving binaries interacting with resource fork data)`
  - *Tune:* `ResourceForkSizeThreshold` — Adjust thresholds for 'unusually large' resource fork data based on baseline usage in the environment.; `MonitoredDirectories` — Scope monitoring to sensitive directories such as /Users, /Applications, or temporary paths.; `CorrelatedActivityWindow` — Time window for correlating resource fork activity with subsequent execution or network activity.

---

### T1564.010 — Process Argument Spoofing
<a id="t1564010"></a>

**Detection strategy:** Detection Strategy for Process Argument Spoofing on Windows (`DET0045`)  
**Platforms:** Windows  
**ATT&CK:** [T1564.010](https://attack.mitre.org/techniques/T1564/010/) · [detail page](../../techniques/stealth.md#t1564010)

- **`AN0126` Analytic 0126** · Windows
  Inconsistencies between process command-line arguments logged at creation time and subsequent process behavior. Defender perspective: monitoring for processes launched in a suspended state, followed by memory modifications (e.g., WriteProcessMemory targeting the PEB) that overwrite arguments before execution resumes. Detection also includes observing anomalous behaviors from processes whose logged arguments do not align with executed activity (e.g., network connections, file writes, or registry modifications).
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=10)`
  - *Tune:* `SuspendedProcessWindow` — Time window in which a process remains in suspended state before being modified. Tunable based on baseline activity in the environment.; `SensitiveProcesses` — List of critical processes (e.g., explorer.exe, lsass.exe) where argument spoofing is highly suspicious. Can be customized per organization.; `BehavioralCorrelationWindow` — Time span in which to correlate command-line inconsistencies with anomalous behavior such as network activity or registry modification.

---

### T1564.011 — Ignore Process Interrupts
<a id="t1564011"></a>

**Detection strategy:** Detection Strategy for Ignore Process Interrupts (`DET0067`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1564.011](https://attack.mitre.org/techniques/T1564/011/) · [detail page](../../techniques/stealth.md#t1564011)

- **`AN0181` Analytic 0181** · Linux
  Execution of processes using nohup or shell redirection to ignore SIGHUP and continue running after session termination. Defender perspective: correlation between commands including nohup, disowned jobs, or `&` suffix with continued process execution after parent terminal exit.
  - *Log sources:* `auditd:SYSCALL (execve call including 'nohup' or trailing '&')`; `auditd:SYSCALL (process persists beyond parent shell termination)`
  - *Tune:* `IgnoredSignals` — Specific signals to monitor (e.g., SIGHUP, SIGINT) depending on environment baseline.; `ProcessLifetimeThreshold` — Duration a process continues running after session logout, adjustable to reduce noise from benign long-lived jobs.
- **`AN0182` Analytic 0182** · Windows
  PowerShell or script execution with parameters that suppress errors or ignore user interrupts, such as `-ErrorAction SilentlyContinue`. Defender perspective: detecting discrepancies between suppressed error arguments and continued execution behavior.
  - *Log sources:* `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `MonitoredCmdlets` — List of PowerShell cmdlets where suppressed error handling is suspicious (e.g., Invoke-Expression, Invoke-WebRequest).; `ErrorActionThreshold` — Frequency of suppressed error actions within time window that should trigger detection.
- **`AN0183` Analytic 0183** · macOS
  Use of nohup, disown, or AppleScript constructs to suppress process interrupts. Defender perspective: commands containing nohup or hidden background tasks (`osascript` with persistent execution) correlated with processes surviving user logouts.
  - *Log sources:* `macos:unifiedlog (nohup, disown, or osascript execution patterns)`; `macos:unifiedlog (background process persists beyond user logout)`
  - *Tune:* `WatchedShells` — Shells or interpreters where nohup/disown usage is suspicious, configurable to environment.; `PersistenceCorrelationWindow` — Time window to correlate process continuation after logout with suspicious commands.

---

### T1564.012 — File/Path Exclusions
<a id="t1564012"></a>

**Detection strategy:** Detection Strategy for File/Path Exclusions (`DET0051`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1564.012](https://attack.mitre.org/techniques/T1564/012/) · [detail page](../../techniques/stealth.md#t1564012)

- **`AN0139` Analytic 0139** · Windows
  Creation or modification of files in directories known to be excluded from AV scanning (e.g., C:\Windows\Temp, Exchange server directories, or default AV exclusions). Defender perspective: correlate file creation with execution behavior or anomalous parent processes writing to excluded paths.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Security (EventCode=4663, 4670, 4656)`
  - *Tune:* `ExcludedPaths` — List of directories excluded from scanning in the environment (customizable per organization).; `ProcessAllowlist` — Legitimate processes typically writing to excluded paths to minimize false positives.
- **`AN0140` Analytic 0140** · Linux
  Adversaries writing or moving payloads into directories configured as AV/EDR exclusion paths (e.g., /tmp, /var/lib, or custom directories from auditd exclusion rules). Defender perspective: detect file creation in paths matching known exclusions correlated with unusual parent processes.
  - *Log sources:* `auditd:SYSCALL (open or creat syscalls targeting excluded paths)`; `auditd:PATH (file path matches exclusion directories)`
  - *Tune:* `ExcludedDirectories` — System- or security-tool-configured exclusion directories where files should rarely change.; `CorrelationWindow` — Time window to correlate file creation in excluded paths with execution or network activity.
- **`AN0141` Analytic 0141** · macOS
  Suspicious file creation or modification in directories ignored by XProtect or AV exclusions (e.g., ~/Library, temporary cache directories). Defender perspective: monitor file events in ignored paths with correlation to execution or persistence activity.
  - *Log sources:* `macos:unifiedlog (file creation in AV exclusion directories)`; `macos:unifiedlog (process writes or modifies files in excluded paths)`
  - *Tune:* `AVExclusionPaths` — Paths ignored by AV/XProtect that should be monitored for abnormal writes.; `ProcessContext` — Expected user or application context writing to excluded directories.

---

### T1564.013 — Bind Mounts
<a id="t1564013"></a>

**Detection strategy:** Detection Strategy for Bind Mounts on Linux (`DET0428`)  
**Platforms:** Linux  
**ATT&CK:** [T1564.013](https://attack.mitre.org/techniques/T1564/013/) · [detail page](../../techniques/stealth.md#t1564013)

- **`AN1196` Analytic 1196** · Linux
  Abuse of bind mounts to obscure process directories. Defender perspective: detecting anomalous mount operations where a process’s /proc entry is remapped to another directory, often hiding malicious activity from native utilities (ps, top). Behavior chain includes: (1) execution of `mount` with `-o bind` or `-B` flags, (2) modification of /proc entries inconsistent with expected process lineage, and (3) subsequent anomalous activity from processes whose metadata no longer matches execution context.
  - *Log sources:* `auditd:SYSCALL (mount system call with bind or remap flags)`; `auditd:PATH (mount target path within /proc/*)`; `linux:osquery (process metadata mismatch between /proc and runtime attributes)`
  - *Tune:* `BindMountFlags` — Flags or options used in mount commands (e.g., -o bind, -B). Can vary across distributions and kernels.; `WatchedProcPaths` — List of /proc paths to monitor. Tunable to reduce noise from benign bind mounts used in containers or chroot environments.; `CorrelationWindow` — Timeframe to correlate bind mount creation with anomalous process or file activity.

---

### T1564.014 — Extended Attributes
<a id="t1564014"></a>

**Detection strategy:** Detection Strategy for Extended Attributes Abuse (`DET0406`)  
**Platforms:** Linux, macOS  
**ATT&CK:** [T1564.014](https://attack.mitre.org/techniques/T1564/014/) · [detail page](../../techniques/stealth.md#t1564014)

- **`AN1135` Analytic 1135** · Linux
  Abuse of extended attributes (xattrs) to embed hidden payloads into legitimate files. Defender perspective: detect anomalous use of setfattr or getfattr commands, or direct syscalls (setxattr, getxattr) where attributes are unusually large or contain encoded data. Behavior chain includes: (1) execution of setfattr with suspicious namespaces (user., trusted.), (2) file metadata modification inconsistent with file size/hash, and (3) subsequent process execution reading attributes followed by decoding activity.
  - *Log sources:* `auditd:SYSCALL (setxattr or getxattr system call)`; `auditd:EXECVE (execution of setfattr or getfattr commands)`
  - *Tune:* `XattrNamespaces` — Namespaces monitored for suspicious activity (user., trusted., security.). Organizations may tune to reduce noise from benign use.; `PayloadSizeThreshold` — Size of xattr values above which they should be considered anomalous (e.g., >1KB).; `CorrelationWindow` — Time window to correlate xattr modification with process execution from the same file.
- **`AN1136` Analytic 1136** · macOS
  Abuse of extended attributes (xattrs) to hide payloads in com.apple.* or custom keys. Defender perspective: monitor suspicious use of xattr command with -w (write) and -p (print) flags, especially when followed by execution of interpreters like bash, Python, or osascript. Behavior chain includes: (1) suspicious file modification with new com.apple.* attributes, (2) attribute content inconsistent with expected metadata tags (e.g., high entropy), (3) subsequent process execution correlated with extraction of the attribute.
  - *Log sources:* `macos:unifiedlog (xattr utility execution with -w or -p flags)`; `macos:unifiedlog (extended attribute write or modification)`
  - *Tune:* `WatchedXattrKeys` — Specific xattr keys to monitor (e.g., com.apple.quarantine, com.apple.ResourceFork, unknown custom keys).; `EntropyThreshold` — High entropy attribute values may indicate encoded or encrypted payloads.; `ProcessContext` — Expected legitimate applications interacting with xattrs (Finder, Spotlight) to help reduce false positives.

---

### T1612 — Build Image on Host
<a id="t1612"></a>

**Detection strategy:** Detection Strategy for Build Image on Host (`DET0459`)  
**Platforms:** Containers  
**ATT&CK:** [T1612](https://attack.mitre.org/techniques/T1612/) · [detail page](../../techniques/stealth.md#t1612)

- **`AN1261` Analytic 1261** · Containers
  Detection of container image build activity directly on the host using Docker or Kubernetes APIs. Defenders may observe Docker build requests, anomalous Dockerfile instructions (such as downloading code from unknown IPs), or creation of new images followed by immediate deployment. This behavior chain typically consists of an unexpected image creation event correlated with outbound network communication to non-standard or untrusted destinations.
  - *Log sources:* `docker:daemon (docker build or POST /build API request)`; `NSM:Flow (outbound connections from host during or immediately after image build)`
  - *Tune:* `RegistryAllowList` — Defines trusted registries for image pulls/builds. Builds referencing unapproved registries may indicate adversary behavior.; `NewImageThreshold` — Threshold for number of new custom images created in a given time window. Exceeding this threshold may indicate malicious builds.; `TimeWindow` — Defines correlation window (e.g., 5m) between suspicious build activity and subsequent network traffic anomalies.

---

### T1620 — Reflective Code Loading
<a id="t1620"></a>

**Detection strategy:** Detection Strategy for Reflective Code Loading (`DET0300`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1620](https://attack.mitre.org/techniques/T1620/) · [detail page](../../techniques/stealth.md#t1620)

- **`AN0838` Analytic 0838** · Windows
  Detect anomalous chains of memory allocation and execution inside the same process (e.g., VirtualAlloc → memcpy → VirtualProtect → CreateThread). Unlike process injection, reflective code loading does not perform cross-process memory writes — the suspicious activity occurs entirely within the process’s own PID context.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=7)`; `etw:Microsoft-Windows-DotNETRuntime (AssemblyLoad/ModuleLoad (Loader keyword) from Microsoft-Windows-DotNETRuntime)`; `etw:Microsoft-Antimalware-Scan-Interface (Amsi/Script content + API verdicts during in-memory staging)`; `WinEventLog:Sysmon (EventCode=10)`
  - *Tune:* `ParentProcessWhitelist` — Certain processes may legitimately use Assembly.Load(); defenders may whitelist known developer/admin tools.; `MemoryRegionPermissions` — Detection logic can tune for RWX memory allocations; some legitimate tools may allocate with RW permissions only.
- **`AN0839` Analytic 0839** · Linux
  Monitor for in-process mmap + mprotect + execve/execveat activity where memory permissions are changed from writable to executable inside the same process without a corresponding ELF on disk.
  - *Log sources:* `auditd:SYSCALL (execve)`; `auditd:MMAP (memory region with RWX permissions allocated)`
  - *Tune:* `ProcessNameScope` — Uncommon for service binaries to call memfd_create; detection tuned for high-risk processes.; `RWXMemoryThreshold` — Adjust threshold for allowed RWX allocations to reduce false positives in JIT runtimes.
- **`AN0840` Analytic 0840** · macOS
  Suspicious calls to dlopen(), dlsym(), or mmap with RWX flags in processes that do not typically perform dynamic module loading. Monitor anonymous memory regions executed by user processes.
  - *Log sources:* `macos:unifiedlog (execve or dylib load from memory without backing file)`; `macos:unifiedlog (suspicious dlopen/dlsym usage in non-development processes)`
  - *Tune:* `ApplicationScope` — Developer tools may legitimately call dlopen/dlsym; narrow scope to production workloads.; `ExecutionTimeWindow` — Correlate suspicious loads with subsequent process activity in a defined window.

---

### T1622 — Debugger Evasion
<a id="t1622"></a>

**Detection strategy:** Detection Strategy for Debugger Evasion (T1622) (`DET0371`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1622](https://attack.mitre.org/techniques/T1622/) · [detail page](../../techniques/stealth.md#t1622)

- **`AN1045` Analytic 1045** · Windows
  Monitor for suspicious use of Windows API calls such as IsDebuggerPresent() and NtQueryInformationProcess(), or processes manually checking the BeingDebugged flag in the Process Environment Block (PEB). Detect sequences of OutputDebugStringW() calls in short intervals that may indicate debugger flooding attempts.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `etw:Microsoft-Windows-Kernel-Process (NtQueryInformationProcess)`
  - *Tune:* `ApiCallFrequencyThreshold` — Number of repeated debug-related API calls allowed before raising an alert; `ProcessAllowList` — Legitimate debuggers or developer tools that may trigger similar behaviors
- **`AN1046` Analytic 1046** · Linux
  Monitor access to /proc/self/status where TracerPID field is queried, as this is a common technique for debugger detection. Detect processes that attempt to trigger exceptions intentionally and monitor whether exception handling indicates presence of a debugger.
  - *Log sources:* `auditd:SYSCALL (open/read: Access to /proc/self/status with focus on TracerPID field)`
  - *Tune:* `MonitoredPaths` — Set of /proc paths to monitor for suspicious access; `SyscallThreshold` — Rate of syscalls (open/read) used to detect repeated probing for debug artifacts
- **`AN1047` Analytic 1047** · macOS
  Detect suspicious calls to sysctl or ptrace API used to determine if a process is being debugged. Monitor for processes that flood OutputDebugString equivalents or generate abnormal exceptions to evade analysis.
  - *Log sources:* `macos:unifiedlog (ptrace: Processes invoking ptrace with PTRACE_TRACEME flag)`
  - *Tune:* `PtraceInvocationThreshold` — Number of ptrace calls in a time window that should raise suspicion; `DevToolExclusionList` — Exclude known developer tools and monitoring agents

---

### T1678 — Delay Execution
<a id="t1678"></a>

**Detection strategy:** Multi-Platform Detection Strategy for T1678 - Delay Execution (`DET0372`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1678](https://attack.mitre.org/techniques/T1678/) · [detail page](../../techniques/stealth.md#t1678)

- **`AN1048` Analytic 1048** · Windows
  Correlated use of sleep/delay mechanisms (e.g., kernel32!Sleep, NTDLL APIs) in short-lived processes, combined with parent processes invoking suspicious scripts (e.g., wscript, powershell) with minimal user interaction.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=7)`
  - *Tune:* `TimeWindow` — Delay duration that distinguishes benign scripts from evasive behavior.; `ParentProcessName` — Legitimate parent-child combinations may differ across environments.; `SleepFunctionPattern` — Different APIs may be used to invoke sleep (e.g., Sleep, NtDelayExecution).
- **`AN1049` Analytic 1049** · Linux
  Shell scripts or binaries invoking repeated 'sleep', 'ping', or low-level syscalls (e.g., nanosleep) in short-lived execution chains with no user or system interaction. Frequently seen in malicious cron jobs or payload stagers.
  - *Log sources:* `auditd:SYSCALL (execve or nanosleep with no stdout/stderr I/O)`; `auditd:PROCTITLE (scripting loop invoking sleep/ping)`
  - *Tune:* `CommandLineRegex` — Environment-specific delay scripts may vary (sleep 300, ping -n 60, etc.).; `TimeBetweenSyscalls` — Threshold for determining if delay is artificially extended.; `UserContext` — Root vs. service user context alters risk profile.
- **`AN1050` Analytic 1050** · macOS
  Execution of AppleScript, bash, or launchd jobs that invoke delay functions (e.g., sleep, delay in AppleScript) with limited parent interaction and staged follow-on commands.
  - *Log sources:* `macos:unifiedlog (launchd or osascript spawns process with delay command)`; `macos:unifiedlog (delay/sleep library usage in user context)`
  - *Tune:* `ScriptPattern` — AppleScript vs shell scripts differ per threat and org.; `UserContext` — Execution under user vs daemon context changes severity.; `DelayDurationThreshold` — Amount of delay that distinguishes benign usage vs evasion.

---

### T1679 — Selective Exclusion
<a id="t1679"></a>

**Detection strategy:** Detection of Selective Exclusion (`DET0897`)  
**Platforms:** Windows  
**ATT&CK:** [T1679](https://attack.mitre.org/techniques/T1679/) · [detail page](../../techniques/stealth.md#t1679)

- **`AN2030` Analytic 2030** · Windows
  A process with no prior history or outside of known whitelisted tools initiates file or registry modifications to configure exclusion rules for antivirus, backup, or file-handling systems. Or a file system enumeration for specific file names andcritical extensions like .dll, .exe, .sys, or specific directories such as 'Program Files' or security tool paths or system component discovery for the exclusion of the files or components.
  - *Log sources:* `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`; `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Security (EventCode=4663, 4670, 4656)`
  - *Tune:* `TimeWindow` — Correlate multiply discovery activities and file enumeration activities.; `DiscoveryActivityThreshold` — Minimum number of different discovery techniques within time window to trigger detection - balance between false positives and coverage (default: 4 activities); `ExclusionTargetList` — List of extensions or folders considered suspicious when excluded (e.g., .dll, .exe, C:\\Program Files\\); `AuthorizedExclusionModifiers` — Whitelist of known system management tools/processes allowed to modify exclusion settings

---

### T1684.001 — Impersonation
<a id="t1684001"></a>

**Detection strategy:** Detection Strategy for Impersonation (`DET0286`)  
**Platforms:** Linux, Office Suite, SaaS, Windows, macOS  
**ATT&CK:** [T1684.001](https://attack.mitre.org/techniques/T1684/001/) · [detail page](../../techniques/stealth.md#t1684001)

- **`AN0792` Analytic 0792** · Windows
  Monitor for anomalous email activity originating from Windows-hosted applications (e.g., Outlook) where the sending account name or display name does not match the underlying SMTP address. Detect abnormal volume of outbound messages containing sensitive keywords (e.g., 'payment', 'wire transfer') or anomalous login locations for accounts associated with email sending activity.
  - *Log sources:* `WinEventLog:Security (EventCode=4624, 4648)`; `m365:unified (SendOnBehalf/SendAs: Emails sent where the sending identity mismatches account ownership)`
  - *Tune:* `KeywordList` — Adjust impersonation detection keywords based on local business risk terms (e.g., 'ACH', 'Invoice').; `GeoLocationBaseline` — Define trusted geographic regions for normal user email activity.
- **`AN0793` Analytic 0793** · Linux
  Monitor mail server logs (Postfix, Sendmail, Exim) for anomalous From headers mismatching authenticated SMTP identities. Detect abnormal relay attempts, spoofed envelope-from values, or large-scale outbound campaigns targeting internal users.
  - *Log sources:* `auditd:SYSCALL (execve: Processes executing sendmail/postfix with forged headers)`; `Application:Mail (Mismatch between authenticated username and From header in email)`
  - *Tune:* `KnownRelayHosts` — Filter trusted relays or automated notification systems from impersonation alerts.
- **`AN0794` Analytic 0794** · macOS
  Monitor Mail.app activity or unified logs for anomalous SMTP usage, including mismatches between display name and authenticated AppleID or Exchange credentials. Detect use of third-party mail utilities that attempt to send on behalf of corporate identities.
  - *Log sources:* `macos:unifiedlog (Mail.app or third-party clients sending messages with mismatched From headers)`
  - *Tune:* `TrustedMailClients` — Allowlist known third-party clients used for legitimate email activity.
- **`AN0795` Analytic 0795** · SaaS
  Monitor SaaS mail platforms (Google Workspace, M365, Okta-integrated apps) for SendAs/SendOnBehalfOf operations where the delegated permissions are unusual or newly granted. Detect impersonation attempts where adversaries configure rules to auto-forward or auto-reply with impersonated content.
  - *Log sources:* `gcp:workspaceaudit (SendAs: Outbound messages with alias identities that differ from primary account)`
  - *Tune:* `DelegationBaseline` — Maintain baseline of normal SendAs/SendOnBehalf relationships to reduce false positives.
- **`AN0796` Analytic 0796** · Office Suite
  Monitor Office Suite applications (Outlook, Word mail merge, Excel macros) for abnormal automated message sending, especially when macros or scripts trigger email delivery. Detect patterns of impersonation language (urgent, payment, executive request) combined with anomalous execution of Office macros.
  - *Log sources:* `m365:unified (SendOnBehalf/SendAs: Office Suite initiated messages using impersonated identities)`
  - *Tune:* `MacroExecutionThreshold` — Threshold for correlating macro execution with email sending activity.

---

### T1684.002 — Email Spoofing
<a id="t1684002"></a>

**Detection strategy:** Detection Strategy for Email Spoofing (`DET0431`)  
**Platforms:** Linux, Office Suite, Windows, macOS  
**ATT&CK:** [T1684.002](https://attack.mitre.org/techniques/T1684/002/) · [detail page](../../techniques/stealth.md#t1684002)

- **`AN1202` Analytic 1202** · Windows
  Monitor email message traces and headers for failed SPF, DKIM, or DMARC checks indicating spoofed sender identities. Correlate abnormal sender domains or mismatched return-paths with elevated spoofing likelihood.
  - *Log sources:* `m365:messagetrace (AuthenticationDetails=fail OR SPF=fail OR DKIM=fail OR DMARC=fail)`
  - *Tune:* `SpoofScoreThreshold` — Defines sensitivity to SPF/DKIM/DMARC failures; higher thresholds reduce false positives but may miss stealthier spoofing.; `MonitoredDomains` — Specifies which domains to enforce strict validation against; enterprise-specific tuning may be required.
- **`AN1203` Analytic 1203** · Linux
  Detects spoofed emails by analyzing mail server logs (e.g., Postfix, Sendmail) for mismatched header fields, failed SPF/DKIM checks, and anomalies in SMTP proxy logs. Defender observes discrepancies between sending domain, return-path domain, and message metadata.
  - *Log sources:* `linux:syslog (SPF fail OR DKIM fail OR DMARC fail OR mismatched from_domain vs return_path_domain)`
  - *Tune:* `SenderDomainWhitelist` — Defines approved sender domains to suppress alerts for expected mismatches, reducing false positives.; `TimeWindow` — Sets correlation period for repeated spoofing attempts to flag campaigns vs. isolated misconfigurations.
- **`AN1204` Analytic 1204** · macOS
  Detects suspicious inbound mail traffic where SPF/DKIM/DMARC authentication fails or where sender and return-path domains mismatch, observable in Apple Mail unified logs or MDM-controlled logging pipelines.
  - *Log sources:* `macos:unifiedlog (SPF fail OR DKIM fail OR DMARC fail OR mismatched header vs envelope domains)`
  - *Tune:* `RecipientSensitivity` — Allows tuning based on which users (e.g., executives, finance staff) receive stricter spoofing detection policies.; `HeaderMismatchTolerance` — Defines tolerance for minor discrepancies in domain alignment, balancing detection with usability.
- **`AN1205` Analytic 1205** · Office Suite
  Correlates Office 365 or Google Workspace audit logs for spoofed sender addresses, failed email authentication, and anomalies in message delivery metadata. Defender observes failed SPF/DKIM checks and domain mismatches tied to suspicious campaigns.
  - *Log sources:* `saas:email (AuthenticationFailures (SPF/DKIM/DMARC) OR Domain Mismatch)`
  - *Tune:* `MessageVolumeThreshold` — Defines thresholds for spoofed messages volume before alerts trigger, reducing noise for isolated misconfigs.; `TargetedUserGroups` — Restricts higher-sensitivity detection to high-value groups (executives, admins, finance) for efficiency.

---
