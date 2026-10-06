# Defense Impairment: Detection Strategies

> MITRE ATT&CK detection strategies and analytics (v19.2) for techniques whose primary tactic is Defense Impairment. Each analytic lists the log sources / channels it needs, the detection logic, and the tunable elements to adapt it to your environment. Authoritative source: the ATT&CK detection-strategy model in the Enterprise STIX.

See also: [all detection strategies index](/detections/strategies/README.md), [Technique Detection Library](../TECHNIQUE_DETECTION_LIBRARY.md) (ready-to-run SIEM queries), [Data Components & Log Sources](../../ATTACK_DATA_COMPONENTS.md), [Technique Detail Pages](../../techniques/README.md)

---

### T1112: Modify Registry
<a id="t1112"></a>

Detection strategy: Behavior-Based Registry Modification Detection on Windows (`DET0280`)  
Platforms: Windows  
ATT&CK: [T1112](https://attack.mitre.org/techniques/T1112/), [detail page](../../techniques/defense-impairment.md#t1112)

- `AN0781` Analytic 0781, Windows
  Behavior chain involving abnormal registry modifications via CLI, PowerShell, WMI, or direct API calls, especially targeting persistence, privilege escalation, or defense evasion keys, potentially followed by service restart or process execution. Such as editing Notify/Userinit/Startup keys, or disabling SafeDllSearchMode.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=13, 14)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `RegistryKeyPathPatterns`: Environment-specific list of monitored or critical registry keys, e.g., Run, Services, Security Settings, LSASS; `ParentProcessAllowList` — Allowlist of legitimate registry tools (e.g., regedit.exe, msiexec.exe); used to filter known safe writes; `TimeWindow` — Correlate registry change with nearby process/service execution within a defined timeframe; `SignatureCheck` — Flag unsigned executables or abnormal parent-child lineage performing registry modification

---

### T1207: Rogue Domain Controller
<a id="t1207"></a>

Detection strategy: Detection Strategy for Rogue Domain Controller (DCShadow) Registration and Replication Abuse (`DET0276`)  
Platforms: Windows  
ATT&CK: [T1207](https://attack.mitre.org/techniques/T1207/), [detail page](../../techniques/defense-impairment.md#t1207)

- `AN0770` Analytic 0770, Windows
  Detection of rogue Domain Controller registration and Active Directory replication abuse by correlating: (1) creation/modification of nTDSDSA and server objects in the Configuration partition, (2) unexpected usage of Directory Replication Service SPNs (GC/ or E3514235-4B06-11D1-AB04-00C04FC2DCD2), (3) replication RPC calls (DrsAddEntry, DrsReplicaAdd, GetNCChanges) originating from non-DC hosts, and (4) Kerberos authentication by non-DC machines using DRS-related SPNs. These events in combination, especially from hosts outside the Domain Controllers OU, may indicate DCShadow or rogue DC activity.
  - *Log sources:* `WinEventLog:Security (EventCode=4928)`; `WinEventLog:Security (EventCode=4929)`; `WinEventLog:Security (EventCode=4662)`; `m365:dirsync (Replication cookie changes involving Configuration partition with new server/nTDSDSA objects.)`; `NSM:Flow (DrsAddEntry, DrsReplicaAdd, GetNCChanges calls between non-DC and DCs.)`
  - *Tune:* `TimeWindow`: Window (seconds) between nTDSDSA object creation and subsequent replication traffic from same host (default 300s).; `AllowedReplicationPartners` — List of legitimate DCs authorized for replication to reduce false positives.; `SuspiciousSPNs` — SPNs indicating replication service usage (GC/, GUID E3514235-4B06-11D1-AB04-00C04FC2DCD2).; `NonDCObjectCreationAlert` — Trigger alerts only when AD object creation is by accounts not in Domain Admins or Enterprise Admins groups.

---

### T1222: File and Directory Permissions Modification
<a id="t1222"></a>

Detection strategy: Multi-Platform File and Directory Permissions Modification Detection Strategy (`DET0299`)  
Platforms: ESXi, Linux, Windows, macOS  
ATT&CK: [T1222](https://attack.mitre.org/techniques/T1222/), [detail page](../../techniques/defense-impairment.md#t1222)

- `AN0834` Analytic 0834, Windows
  Sequential behavioral chain of privilege escalation through permission modification: (1) Process creation of permission-modifying utilities (icacls, takeown, attrib, cacls), (2) Correlation with unusual user context or timing, (3) DACL modification events targeting sensitive files/directories, (4) Subsequent file access or modification attempts indicating successful privilege bypass
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Security (EventCode=4663, 4670, 4656)`; `WinEventLog:Security (EventCode=4663, 4670, 4656)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`
  - *Tune:* `TimeWindow`: Temporal correlation window for linking permission modification with subsequent access attempts (default: 300 seconds); `SensitivePathList` — Environment-specific critical file and directory paths requiring permission change monitoring; `TrustedUserContext` — Administrative accounts authorized to perform legitimate permission modifications; `BusinessHoursThreshold` — Time-based threshold for elevated alerting on permission changes outside business hours
- `AN0835` Analytic 0835, Linux
  Behavioral sequence of unauthorized privilege escalation via permission modification: (1) chmod/chown/setfacl process execution with suspicious parameters, (2) Targeting of critical system files or unusual permission values, (3) Correlation with non-privileged user context or unusual timing patterns, (4) Follow-on file access indicating successful permission bypass
  - *Log sources:* `auditd:SYSCALL (syscall in (chmod, fchmod, fchmodat, chown, fchown, fchownat, setxattr, lsetxattr, fsetxattr))`; `auditd:PROCTITLE (proctitle contains chmod, chown, setfacl, or attr commands with suspicious parameters)`
  - *Tune:* `SuspiciousPermissionValues`: Octal permission values that indicate potential malicious intent (default: 777, 755, 4755); `CriticalPathPatterns` — Linux filesystem paths requiring enhanced monitoring (/etc/, /usr/bin/, /home/); `AuthorizedAdminUsers` — User accounts permitted to perform system-level permission modifications; `AnomalyThreshold` — Statistical threshold for detecting unusual permission modification frequency
- `AN0836` Analytic 0836, macOS
  macOS-specific permission modification behavioral chain: (1) chmod/chown/chflags process execution, (2) System Integrity Protection (SIP) bypass attempts, (3) Extended attribute (xattr) modifications, (4) Unified log correlation with file system events, (5) Subsequent access to previously restricted resources
  - *Log sources:* `macos:unifiedlog (process execution events for chmod, chown, chflags with unusual parameters or targets)`; `fs:fsevents (file system events indicating permission or attribute changes)`
  - *Tune:* `SIPProtectedPaths`: macOS system paths protected by SIP that should never have permission modifications; `SuspiciousFlagCombinations` — chflags parameter combinations indicating evasive behavior (uchg, schg, hidden); `XattrMonitoringScope` — Extended attributes to monitor for unauthorized modifications; `UnifiedLogRetention` — Log retention period for correlating permission changes with subsequent access
- `AN0837` Analytic 0837, ESXi
  ESXi hypervisor permission modification behavioral chain: (1) SSH access to ESXi host, (2) chmod/chown execution on VMFS datastore files or system configuration, (3) Modification of VM configuration files (.vmx) or virtual disk permissions, (4) Hostd service log correlation, (5) vCenter permission change events if centrally managed
  - *Log sources:* `esxi:shell (shell command execution for chmod, chown, or file permission modification on VMFS or system files)`; `esxi:hostd (host daemon events related to file or VM permission changes)`; `esxi:vpxd (permission change operations on datastores or VMs)`
  - *Tune:* `AuthorizedSSHUsers`: ESXi user accounts authorized for shell access and file system operations; `CriticalVMFSPaths` — VMFS datastore paths requiring permission change monitoring; `ShellAccessTimeWindow` — Time correlation window for linking SSH access with permission modifications; `vCenterIntegrationScope` — Scope of vCenter audit event correlation with ESXi host activities

---

### T1222.001: Windows Permissions
<a id="t1222001"></a>

Detection strategy: Windows DACL Manipulation Behavioral Chain Detection Strategy (`DET0418`)  
Platforms: Windows  
ATT&CK: [T1222.001](https://attack.mitre.org/techniques/T1222/001/), [detail page](../../techniques/defense-impairment.md#t1222001)

- `AN1177` Analytic 1177, Windows
  Multi-stage Windows DACL manipulation behavioral chain: (1) Process creation of permission-modifying utilities (icacls.exe, takeown.exe, attrib.exe, cacls.exe) or PowerShell ACL cmdlets, (2) Command-line analysis revealing privilege escalation intent through suspicious parameters (/grant, /takeown, /T, Set-Acl), (3) DACL modification events (4670) correlating with process execution, (4) Subsequent file access attempts (4663) indicating successful permission bypass, (5) Potential follow-on persistence or lateral movement activities
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Security (EventCode=4663, 4670, 4656)`; `WinEventLog:Security (EventCode=4663, 4656, 4658)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`; `WinEventLog:WMI (EventCode=5857, 5858, 5860, 5861)`
  - *Tune:* `TemporalCorrelationWindow`: Time window for correlating process creation (4688/sysmon 1) with DACL changes (4670) and subsequent access (4663) - default 300 seconds, adjust based on system performance and network latency; `SensitivePathWhitelist` — Environment-specific critical directories requiring enhanced monitoring (e.g., C:\Windows\System32, C:\Program Files, %USERPROFILE%\AppData) - customize per organizational security requirements; `AuthorizedAdministratorAccounts` — User accounts and service accounts authorized to perform legitimate DACL modifications - update to reflect current administrative staff and automated processes; `SuspiciousCommandLinePatterns` — Regex patterns for detecting malicious intent in permission modification commands - tune to reduce false positives while maintaining detection efficacy; `BusinessHoursThreshold` — Time-based risk scoring modifier for permission changes occurring outside standard business hours - adjust based on organizational work patterns; `PowerShellScriptBlockSizeThreshold` — Minimum PowerShell script block size for ACL-related content analysis - balance between detection coverage and log volume; `FileAccessFrequencyBaseline` — Statistical baseline for normal file access patterns post-permission change - establish through historical analysis and update periodically; `WMIMethodInvocationWhitelist` — Approved WMI classes and methods for legitimate permission operations (e.g., Win32_SecurityDescriptor) - maintain based on authorized management tools

---

### T1222.002: Linux and Mac Permissions
<a id="t1222002"></a>

Detection strategy: Unix-like File Permission Manipulation Behavioral Chain Detection Strategy (`DET0351`)  
Platforms: Linux, macOS  
ATT&CK: [T1222.002](https://attack.mitre.org/techniques/T1222/002/), [detail page](../../techniques/defense-impairment.md#t1222002)

- `AN0998` Analytic 0998, Linux
  Linux permission escalation behavioral chain: (1) Process creation of permission modification utilities (chmod, chown, chgrp, setfacl) with suspicious parameters indicating privilege escalation intent, (2) System call analysis revealing direct file metadata manipulation (chmod, fchmod, chown, fchown syscalls), (3) Extended attribute and ACL modifications targeting critical system paths, (4) Temporal correlation with subsequent file access or process execution from modified locations, (5) Anomalous permission patterns deviating from system baselines
  - *Log sources:* `auditd:SYSCALL (syscall in (chmod, fchmod, fchmodat, chown, fchown, fchownat, lchown, setxattr, lsetxattr, fsetxattr, removexattr, lremovexattr, fremovexattr))`; `auditd:PROCTITLE (proctitle contains chmod, chown, chgrp, setfacl, or attr with suspicious parameters (777, 755, +x, -R))`; `linux:osquery (process execution events for permission modification utilities with command-line analysis)`
  - *Tune:* `SuspiciousPermissionValues`: Octal permission values indicating potential malicious intent - customize based on organizational security policy (default: 777, 755, 4755, 2755, 1755 for sticky/setuid/setgid); `CriticalSystemPaths` — Linux filesystem paths requiring enhanced permission change monitoring - adapt to environment-specific critical directories (/etc, /usr/bin, /usr/sbin, /var, /opt, /root, /boot); `AuthorizedSystemAdministrators` — User accounts and service accounts authorized for system-level permission modifications - maintain current list of legitimate administrators; `TemporalCorrelationWindow` — Time window for correlating permission changes with subsequent file access or process execution - adjust based on system performance (default: 300 seconds); `RecursiveOperationThreshold` — Maximum depth or file count for recursive permission operations before triggering anomaly detection (-R flag monitoring); `ACLComplexityBaseline` — Baseline complexity metrics for setfacl operations to detect anomalous extended ACL configurations; `FileAccessFrequencyBaseline` — Statistical baseline for normal file access patterns post-permission modification to detect privilege abuse
- `AN0999` Analytic 0999, macOS
  macOS permission and attribute manipulation behavioral chain: (1) Process execution of permission utilities (chmod, chown, chgrp) or macOS-specific tools (chflags) with suspicious parameters, (2) System Integrity Protection (SIP) bypass attempts through permission modifications, (3) File flags manipulation (uchg, schg, hidden) for evasion or persistence, (4) Extended attribute (xattr) modifications affecting security metadata, (5) Unified log correlation with file system events and subsequent access patterns, (6) Gatekeeper and code signing bypass through permission/attribute manipulation
  - *Log sources:* `macos:unifiedlog (process execution events for chmod, chown, chflags with parameter analysis and target path examination)`; `fs:fsevents (file system events indicating permission, ownership, or extended attribute changes on critical paths. File system modification events with kFSEventStreamEventFlagItemChangeOwner, kFSEventStreamEventFlagItemXattrMod flags)`; `OpenBSM:AuditTrail (BSM audit events for file permission, ownership, and attribute modifications with user context)`
  - *Tune:* `SIPProtectedPaths`: macOS system paths protected by SIP that should never have permission modifications - maintain current list based on macOS version (/System, /usr, /bin, /sbin); `SuspiciousFileFlags` — chflags parameter combinations indicating potential evasive behavior - customize based on security requirements (uchg, schg, hidden, archived); `CriticalExtendedAttributes` — Extended attributes requiring monitoring for unauthorized removal or modification (com.apple.quarantine, com.apple.metadata, com.apple.FinderInfo); `GatekeeperBypassIndicators` — Patterns in permission/attribute changes that may indicate Gatekeeper bypass attempts; `ApplicationBundleMonitoring` — Scope of .app directory monitoring for internal permission modifications indicating bundle tampering; `UnifiedLogRetentionPeriod` — Log retention period for correlating permission changes with subsequent access patterns - balance storage with detection capability; `FSEventsFilteringThreshold` — File system event filtering threshold to manage high-volume environments while maintaining detection coverage

---

### T1484: Domain or Tenant Policy Modification
<a id="t1484"></a>

Detection strategy: Detection of Domain or Tenant Policy Modifications via AD and Identity Provider (`DET0270`)  
Platforms: Identity Provider, Windows  
ATT&CK: [T1484](https://attack.mitre.org/techniques/T1484/), [detail page](../../techniques/defense-impairment.md#t1484)

- `AN0755` Analytic 0755, Windows
  Adversary modifies Group Policy Objects (GPOs), domain trust, or directory service objects via GUI, CLI, or programmatic APIs. Behavior includes creation/modification of GPOs, delegation permissions, trust objects, or rogue domain controller registration.
  - *Log sources:* `WinEventLog:Security (EventCode=5136)`; `WinEventLog:Security (EventCode=4663, 4670, 4656)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `ObjectDN`: Filter to specific AD containers (e.g., CN=Policies,CN=System,DC=domain,DC=com) for GPOs.; `AttributeModified` — Focus on high-risk attributes such as gPCFileSysPath, ntSecurityDescriptor.; `TimeWindow` — Correlate changes with suspicious process creation or privileged user logon.; `UserContext` — Alert on unexpected user or service account modifying domain policy.
- `AN0756` Analytic 0756, Identity Provider
  Adversary modifies tenant policy through changes to federation configuration, trust settings, or identity provider additions in Microsoft 365/AzureAD via Portal, PowerShell, or Graph API. Includes setting authentication to federated or updating federated domains.
  - *Log sources:* `m365:unified (Set federation settings on domain|Set domain authentication|Add federated identity provider)`; `azure:signinlogs (OperationName=SetDomainAuthentication OR Set-FederatedDomain)`
  - *Tune:* `OperationName`: Identify rare modification operations that are not part of standard admin lifecycle.; `InitiatedBy` — Filter by known administrators or service principals. Flag unknown initiators.; `UserAgent` — Detect scripted modifications (e.g., PowerShell/Graph API vs Azure Portal).; `TimeWindow` — Correlate tenant policy changes with new sign-ins or token forgery attempts.

---

### T1484.001: Group Policy Modification
<a id="t1484001"></a>

Detection strategy: Detection of Group Policy Modifications via AD Object Changes and File Activity (`DET0305`)  
Platforms: Windows  
ATT&CK: [T1484.001](https://attack.mitre.org/techniques/T1484/001/), [detail page](../../techniques/defense-impairment.md#t1484001)

- `AN0854` Analytic 0854, Windows
  Adversary modifies GPO containers or files under SYSVOL using LDAP, ADSI, PowerShell (e.g., New-GPOImmediateTask) or GUI tools. This includes directory object changes (e.g., gPCFileSysPath), delegation assignments (SeEnableDelegationPrivilege), and SYSVOL file writes (ScheduledTasks.xml, GptTmpl.inf).
  - *Log sources:* `WinEventLog:Security (EventCode=5136)`; `WinEventLog:Security (EventCode=4663, 4670, 4656)`; `WinEventLog:Security (EventCode=4704)`; `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=11)`
  - *Tune:* `ObjectDN`: Focus detection on AD paths like CN=Policies,CN=System,DC=domain,DC=com.; `TargetFilename` — Target specific files like ScheduledTasks.xml or GptTmpl.inf in SYSVOL.; `TimeWindow` — Correlate GPO object change and SYSVOL file modification within N seconds.; `UserContext` — Alert on unexpected modification by non-admins or uncommon accounts.; `CommandLine` — Flag usage of GPO manipulation tools like Set-GPRegistryValue, New-GPOImmediateTask.

---

### T1484.002: Trust Modification
<a id="t1484002"></a>

Detection strategy: Detection of Trust Relationship Modifications in Domain or Tenant Policies (`DET0458`)  
Platforms: Identity Provider, Windows  
ATT&CK: [T1484.002](https://attack.mitre.org/techniques/T1484/002/), [detail page](../../techniques/defense-impairment.md#t1484002)

- `AN1259` Analytic 1259, Windows
  Adversary modifies Active Directory domain trust settings via `netdom`, `nltest`, or PowerShell to add new domain trust or alter federation. Modifications occur in AD object attributes like trustDirection, trustType, trustAttributes, often paired with SeEnableDelegationPrivilege or certificate injection.
  - *Log sources:* `WinEventLog:Security (EventCode=5136)`; `WinEventLog:Security (EventCode=4704)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `ObjectType`: Focus on `trustedDomain` or `foreignSecurityPrincipal` AD objects in trust containers.; `AttributeModified` — Monitor attributes like `trustPartner`, `trustDirection`, `trustType`, `msDS-TrustForestTrustInfo`.; `TimeWindow` — Correlate trust creation with unusual logon events or certificate modifications.; `UserContext` — Flag rare accounts or non-standard admin users performing trust changes.
- `AN1260` Analytic 1260, Identity Provider
  Adversary adds federated identity provider (IdP) or modifies tenant domain authentication from Managed to Federated. Detected via API, PowerShell, or Admin Portal through federation events like `Set domain authentication`, `Add federated identity provider`, or `Update-MsolFederatedDomain`.
  - *Log sources:* `m365:unified (Set federation settings on domain|Set domain authentication|Add federated identity provider)`; `azure:signinlogs (OperationName=SetDomainAuthentication OR Update-MsolFederatedDomain)`
  - *Tune:* `OperationName`: Identify rare trust-modification operations (SetDomainAuthentication, Update-MsolFederatedDomain).; `InitiatedBy` — Flag federated trust changes performed by unknown users, service principals, or tokens.; `UserAgent` — Separate scripted/API interactions from GUI-based administrative changes.; `TimeWindow` — Correlate trust change to federated login or SAML token injection within short window.

---

### T1553: Subvert Trust Controls
<a id="t1553"></a>

Detection strategy: Detect Subversion of Trust Controls via Certificate, Registry, and Attribute Manipulation (`DET0452`)  
Platforms: Linux, Windows, macOS  
ATT&CK: [T1553](https://attack.mitre.org/techniques/T1553/), [detail page](../../techniques/defense-impairment.md#t1553)

- `AN1246` Analytic 1246, Windows
  Detection correlates abnormal installation or modification of root or code-signing certificates, creation/modification of suspicious registry keys for trust providers, and unusual module loads from non-standard locations. Identifies unsigned or improperly signed executables bypassing trust prompts, combined with persistence artifacts.
  - *Log sources:* `WinEventLog:Security (EventCode=4657)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `TrustedPublisherList`: Baseline list of approved certificate authorities that should not change frequently; `FilePathAllowList` — Exclusions for legitimate enterprise-signed binaries stored in unusual directories; `TimeWindow` — Correlation window for registry + file + process activity
- `AN1247` Analytic 1247, Linux
  Detection monitors extended attribute manipulation (xattr) to strip quarantine or trust metadata, anomalous installation of root certificates in /etc/ssl or /usr/local/share/ca-certificates, and unauthorized modification of system trust stores. Correlates with unexpected process execution involving package managers or custom certificate utilities.
  - *Log sources:* `auditd:SYSCALL (chmod, chown, setxattr, or file writes to /etc/ssl/* or /usr/local/share/ca-certificates/*)`; `auditd:EXECVE (Process execution of update-ca-certificates or openssl with suspicious arguments)`
  - *Tune:* `CertificatePathList`: Paths to monitor for changes depending on distro-specific trust locations; `RegexPatterns` — Regex patterns for suspicious use of xattr or openssl parameters
- `AN1248` Analytic 1248, macOS
  Detection monitors modification of code signing attributes, Gatekeeper/quarantine flags, and insertion of new trust certificates via security add-trusted-cert. Identifies adversary use of xattr to strip quarantine flags from downloaded binaries. Correlates with abnormal module loads bypassing SIP protections.
  - *Log sources:* `macos:unifiedlog (New certificate trust settings added by unexpected process)`; `macos:unifiedlog (xattr -d com.apple.quarantine or similar removal commands)`; `macos:osquery (Unsigned or ad-hoc signed process executions in user contexts)`
  - *Tune:* `QuarantineBypassAllowList`: List of enterprise apps where quarantine flag removal is expected; `CertificateAuthorityList` — Baseline trusted root and intermediate CAs for comparison

---

### T1553.001: Gatekeeper Bypass
<a id="t1553001"></a>

Detection strategy: Detect Gatekeeper Bypass via Quarantine Flag and Trust Control Manipulation (`DET0288`)  
Platforms: macOS  
ATT&CK: [T1553.001](https://attack.mitre.org/techniques/T1553/001/), [detail page](../../techniques/defense-impairment.md#t1553001)

- `AN0800` Analytic 0800, macOS
  Correlates suspicious removal or modification of the com.apple.quarantine extended attribute, manipulation of LSFileQuarantineEnabled values in Info.plist, and unexpected process execution of unsigned or non-notarized binaries. Also monitors abnormal trust validation failures in unified logs and unusual activity in QuarantineEvents database entries.
  - *Log sources:* `macos:unifiedlog (xattr -d com.apple.quarantine or similar attribute removal commands)`; `macos:unifiedlog (Trust validation failures or bypass attempts during notarization and code signing checks)`; `macos:osquery (Changes to LSFileQuarantineEnabled field in Info.plist)`
  - *Tune:* `QuarantineBypassAllowList`: Legitimate enterprise update tools or deployment frameworks that may strip quarantine flags; `CertificateAuthorityList` — Baseline trusted Apple Developer IDs and enterprise certs used for code signing; `TimeWindow` — Time correlation window for xattr modification followed by suspicious process execution

---

### T1553.002: Code Signing
<a id="t1553002"></a>

Detection strategy: Detect Suspicious or Malicious Code Signing Abuse (`DET0230`)  
Platforms: Windows, macOS  
ATT&CK: [T1553.002](https://attack.mitre.org/techniques/T1553/002/), [detail page](../../techniques/defense-impairment.md#t1553002)

- `AN0643` Analytic 0643, Windows
  Detects execution of binaries signed with unusual or recently issued certificates, correlation of process execution with abnormal publisher metadata, and mismatched certificate chains. Monitors for revoked or unknown code signing certificates used in high-privilege contexts.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=7)`
  - *Tune:* `AllowedCertificateAuthorities`: Define trusted issuers to suppress noise from legitimate enterprise signing chains; `TimeWindow` — Correlation window for detecting execution of binaries with newly observed or anomalous certificates; `CertificateAgeThreshold` — Baseline normal age of certificates; flag very recent or expired certificates
- `AN0644` Analytic 0644, macOS
  Monitors Gatekeeper, spctl, and unified log entries for binaries executed with unexpected or untrusted signatures. Correlates file metadata changes with process launches where signature validation is skipped, altered, or fails but the process still executes.
  - *Log sources:* `macos:unifiedlog (Code signing verification failures or bypassed trust decisions)`; `macos:unifiedlog (Execution of binaries with unsigned or anomalously signed certificates)`
  - *Tune:* `DeveloperIDAllowList`: Maintain list of expected Developer IDs to minimize false positives from enterprise apps; `TimeWindow` — Correlates file signature changes with subsequent executions

---

### T1553.003: SIP and Trust Provider Hijacking
<a id="t1553003"></a>

Detection strategy: Detection Strategy for Subvert Trust Controls using SIP and Trust Provider Hijacking. (`DET0442`)  
Platforms: Windows  
ATT&CK: [T1553.003](https://attack.mitre.org/techniques/T1553/003/), [detail page](../../techniques/defense-impairment.md#t1553003)

- `AN1222` Analytic 1222, Windows
  Detection of anomalous registry modifications to Subject Interface Packages (SIPs) or trust provider DLL mappings, unexpected loading of non-Microsoft cryptographic modules, or attempts to redirect WinVerifyTrust validation logic. Defender view focuses on registry tampering, suspicious DLL loads into trusted processes, and abnormal trust validation failures correlated across event streams.
  - *Log sources:* `WinEventLog:Security (EventCode=4657)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:CodeIntegrity (EventCode=3033)`
  - *Tune:* `RegistryPathBaselines`: Monitor for changes in Registry paths.; `TimeWindow` — Correlate between changes in Registry values, system files, and modules loaded.

---

### T1553.004: Install Root Certificate
<a id="t1553004"></a>

Detection strategy: Detection Strategy for Subvert Trust Controls via Install Root Certificate. (`DET0056`)  
Platforms: Linux, Windows, macOS  
ATT&CK: [T1553.004](https://attack.mitre.org/techniques/T1553/004/), [detail page](../../techniques/defense-impairment.md#t1553004)

- `AN0153` Analytic 0153, Windows
  Detection of unauthorized modifications to Windows root certificate stores by monitoring registry keys, certificate installation processes, and creation of new certificate entries not in baseline trusted lists.
  - *Log sources:* `WinEventLog:Security (EventCode=4657)`; `WinEventLog:Sysmon (EventCode=12)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `TrustedRootHashList`: Baseline list of root certificate hashes; defenders can tune based on organizational certificate policies.; `MonitoredProcesses` — Processes associated with certificate management that should be flagged if executed by non-admin users or in unusual contexts.; `TimeWindow` — Correlation window for registry modifications, certificate installation, and process creation to strengthen detection.
- `AN0154` Analytic 0154, Linux
  Detection of unexpected additions or modifications to system-wide certificate stores or execution of commands adding certificates to trusted stores.
  - *Log sources:* `auditd:SYSCALL (open, write: File modifications under /etc/ssl/certs, /usr/local/share/ca-certificates, or /etc/pki/ca-trust/source/anchors)`; `auditd:EXECVE (execve: Execution of update-ca-certificates or trust anchor modification commands)`
  - *Tune:* `CertificatePaths`: Paths monitored for certificate modifications; can be tuned depending on Linux distribution.; `AdminAccounts` — Expected user accounts with privileges to install root certificates; anomalies outside this context are suspicious.
- `AN0155` Analytic 0155, macOS
  Detection of malicious certificate installation via monitoring execution of the `security add-trusted-cert` command and modifications to system keychains.
  - *Log sources:* `macos:unifiedlog (Execution of /usr/bin/security add-trusted-cert or keychain modifications to System.keychain)`; `macos:osquery (query: Enumeration of root certificates showing unexpected additions)`
  - *Tune:* `MonitoredCommands`: Commands related to certificate management (e.g., security, profiles) that can be tuned per environment.; `KeychainBaseline` — Baseline of expected certificates in System.keychain to reduce false positives from legitimate enterprise certificates.

---

### T1553.005: Mark-of-the-Web Bypass
<a id="t1553005"></a>

Detection strategy: Detect Mark-of-the-Web (MOTW) Bypass via Container and Disk Image Files (`DET0257`)  
Platforms: Windows  
ATT&CK: [T1553.005](https://attack.mitre.org/techniques/T1553/005/), [detail page](../../techniques/defense-impairment.md#t1553005)

- `AN0712` Analytic 0712, Windows
  Detects extraction or mounting of container/archive files (e.g., .iso, .vhd, .zip) that originated from the Internet but whose contained files lack Zone.Identifier MOTW tagging. Correlates file creation metadata with subsequent execution of unsigned or untrusted binaries launched outside SmartScreen or Protected View.
  - *Log sources:* `WinEventLog:Security (EventCode=4663, 4670, 4656)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=15)`
  - *Tune:* `WatchedExtensions`: Adjust monitored file types (e.g., .iso, .vhd, .zip, .gz, .rar) based on enterprise usage; `TimeWindow` — Defines correlation window between extraction/mount and first execution of inner files; `TrustedExtractionTools` — Whitelist known enterprise archivers and deployment mechanisms to reduce false positives

---

### T1553.006: Code Signing Policy Modification
<a id="t1553006"></a>

Detection strategy: Detect Code Signing Policy Modification (Windows & macOS) (`DET0523`)  
Platforms: Windows, macOS  
ATT&CK: [T1553.006](https://attack.mitre.org/techniques/T1553/006/), [detail page](../../techniques/defense-impairment.md#t1553006)

- `AN1446` Analytic 1446, Windows
  Monitors execution of administrative utilities (e.g., bcdedit.exe) or registry modifications that disable Driver Signature Enforcement (DSE) or enable Test Signing. Correlates command-line activity, registry changes, and subsequent process executions that bypass signing enforcement.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Security (EventCode=4657)`
  - *Tune:* `MonitoredExecutables`: Expand or restrict monitored utilities (e.g., bcdedit.exe, reg.exe) based on enterprise usage; `RegistryPaths` — Customize registry paths tied to Driver Signing enforcement depending on OS version; `TimeWindow` — Correlation window between registry modification and subsequent unsigned binary execution
- `AN1447` Analytic 1447, macOS
  Detects modification of System Integrity Protection (SIP) or code signing enforcement policies through csrutil or kernel variable tampering. Correlates execution of csrutil disable commands with subsequent policy state changes and anomalous unsigned process executions.
  - *Log sources:* `macos:unifiedlog (csrutil disable)`; `macos:unifiedlog (g_CiOptions modification or SIP state change)`; `macos:unifiedlog (Unsigned binary execution following SIP change)`
  - *Tune:* `PolicyPaths`: Track configuration files and kernel extensions tied to SIP enforcement; `AllowedUsers` — Restrict or expand which privileged accounts are monitored for SIP/CSRUTIL changes; `TimeWindow` — Define correlation between csrutil execution and unsigned process activity

---

### T1556: Modify Authentication Process
<a id="t1556"></a>

Detection strategy: Detect Modification of Authentication Processes Across Platforms (`DET0104`)  
Platforms: IaaS, Identity Provider, Linux, Windows, macOS  
ATT&CK: [T1556](https://attack.mitre.org/techniques/T1556/), [detail page](../../techniques/defense-impairment.md#t1556)

- `AN0287` Analytic 0287, Windows
  Detects modification of LSASS and authentication DLLs, suspicious registry changes to password filter packages, and abnormal process access to lsass.exe. Correlates registry modifications, DLL loads, and process handle access events.
  - *Log sources:* `WinEventLog:Security (EventCode=4657)`; `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Sysmon (EventCode=7)`
  - *Tune:* `MonitoredRegistryKeys`: Specific LSASS and password filter registry paths monitored for modification.; `TimeWindow` — Correlation window between registry change, DLL load, and lsass.exe access.
- `AN0288` Analytic 0288, Linux
  Detects modification of PAM configuration files, unauthorized new PAM modules, and suspicious process execution accessing PAM-related binaries. Correlates file modification events in /etc/pam.d/ with process execution of unauthorized binaries.
  - *Log sources:* `auditd:SYSCALL (open, write)`; `auditd:SYSCALL (execve)`
  - *Tune:* `WatchedPaths`: Critical PAM directories and configuration files monitored for modification.
- `AN0289` Analytic 0289, macOS
  Detects unauthorized additions or changes to /Library/Security/SecurityAgentPlugins and suspicious process activity attempting to hook authentication APIs. Correlates file modifications with abnormal plugin loads in authentication flows.
  - *Log sources:* `macos:unifiedlog (SecurityAgentPlugins modification)`; `macos:osquery (process_open)`
  - *Tune:* `PluginPaths`: List of approved authentication plugin directories to baseline.
- `AN0290` Analytic 0290, Identity Provider
  Detects suspicious configuration changes in IdP authentication flows such as enabling reversible password encryption, MFA bypass, or policy weakening. Correlates policy modification events with unusual administrative activity.
  - *Log sources:* `azure:policy (UpdatePolicy)`; `m365:unified (Set-ADUser OR Set-ADAccountControl)`
  - *Tune:* `PolicyBaseline`: Expected authentication-related policy configurations to compare against.
- `AN0291` Analytic 0291, IaaS
  Detects unauthorized changes to IAM authentication configurations such as disabling MFA, creating backdoor access keys, or altering trust policies. Correlates identity policy updates with unusual login behavior.
  - *Log sources:* `AWS:CloudTrail (UpdateLoginProfile)`; `AWS:CloudTrail (UpdateAccountPasswordPolicy)`
  - *Tune:* `ApprovedAccounts`: Baseline list of service accounts expected to modify IAM authentication policies.

---

### T1556.001: Domain Controller Authentication
<a id="t1556001"></a>

Detection strategy: Detect Domain Controller Authentication Process Modification (Skeleton Key) (`DET0271`)  
Platforms: Windows  
ATT&CK: [T1556.001](https://attack.mitre.org/techniques/T1556/001/), [detail page](../../techniques/defense-impairment.md#t1556001)

- `AN0757` Analytic 0757, Windows
  Detects anomalous process access to LSASS on domain controllers, suspicious module loads of authentication DLLs, and registry or file modifications indicative of Skeleton Key-style patching. Correlates LSASS access attempts with subsequent abnormal logon activity patterns.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Security (EventCode=4624, 4648)`; `WinEventLog:System (Unexpected modification to lsass.exe or cryptdll.dll)`
  - *Tune:* `MonitoredDLLs`: Specific authentication DLLs such as cryptdll.dll and samsrv.dll monitored for tampering.; `TimeWindow` — Correlation window between LSASS memory access, module load, and suspicious logons.; `UserContext` — Baseline expected accounts performing domain controller logon operations.

---

### T1556.002: Password Filter DLL
<a id="t1556002"></a>

Detection strategy: Detect Malicious Password Filter DLL Registration (`DET0472`)  
Platforms: Windows  
ATT&CK: [T1556.002](https://attack.mitre.org/techniques/T1556/002/), [detail page](../../techniques/defense-impairment.md#t1556002)

- `AN1303` Analytic 1303, Windows
  Detects suspicious registration of new password filter DLLs into the authentication process. Correlates registry modifications to LSASS Notification Packages with subsequent DLL creation and loading events. Observes anomalous file placement of DLLs in system directories followed by LSASS loading the new filter during logon/password change activity.
  - *Log sources:* `WinEventLog:Security (EventCode=4657)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=7)`
  - *Tune:* `RegistryPath`: Specific registry path monitored for modification (e.g., HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages).; `AllowedDLLs` — Known and approved password filter DLLs; deviations from baseline may indicate malicious injection.; `TimeWindow` — Time window for correlating registry modification, file creation, and module load events.; `FilePathPatterns` — Expected directories for legitimate password filter DLLs; anomalous paths may signal compromise.

---

### T1556.003: Pluggable Authentication Modules
<a id="t1556003"></a>

Detection strategy: Detect Malicious Modification of Pluggable Authentication Modules (PAM) (`DET0454`)  
Platforms: Linux, macOS  
ATT&CK: [T1556.003](https://attack.mitre.org/techniques/T1556/003/), [detail page](../../techniques/defense-impairment.md#t1556003)

- `AN1250` Analytic 1250, Linux
  Detects unauthorized modifications to PAM configuration files or shared object modules. Correlates file modification events under /etc/pam.d/ or /lib/security/ with unusual authentication activity such as multiple simultaneous logins, off-hours logins, or logons without corresponding physical/VPN access.
  - *Log sources:* `auditd:SYSCALL (open, write)`; `auditd:SYSCALL (execve)`; `NSM:Connections (simultaneous or anomalous logon sessions across multiple systems)`
  - *Tune:* `MonitoredPaths`: List of PAM configuration and module directories monitored (e.g., /etc/pam.d/, /lib/security/).; `TimeWindow` — Timeframe for correlating suspicious file modifications with anomalous login events.; `BaselineAccounts` — Expected login frequency and systems per user account; deviations may indicate compromise.
- `AN1251` Analytic 1251, macOS
  Detects suspicious changes to macOS authorization and PAM plugin files. Correlates file modifications under /etc/pam.d/ or /Library/Security/SecurityAgentPlugins with unexpected authentication attempts or anomalous account usage.
  - *Log sources:* `macos:unifiedlog (authentication plugin load or modification events)`; `macos:osquery (write)`
  - *Tune:* `WatchedPlugins`: Expected set of PAM and authorization plugins; unknown additions may indicate malicious insertion.; `CorrelatedSources` — Cross-correlation with VPN/physical access logs to identify impossible or anomalous login patterns.

---

### T1556.004: Network Device Authentication
<a id="t1556004"></a>

Detection strategy: Detect Modification of Network Device Authentication via Patched System Images (`DET0272`)  
Platforms: Network Devices  
ATT&CK: [T1556.004](https://attack.mitre.org/techniques/T1556/004/), [detail page](../../techniques/defense-impairment.md#t1556004)

- `AN0758` Analytic 0758, Network Devices
  Detects unauthorized modification of network device authentication by correlating OS image file changes, checksum mismatches, or memory verification failures with anomalous authentication events. Focus is on behaviors where patched images introduce hardcoded passwords or bypass native authentication.
  - *Log sources:* `networkconfig (unexpected OS image file upload or modification events)`; `network:auth (repeated successful authentications with previously unknown accounts or anomalous password acceptance)`
  - *Tune:* `BaselineChecksums`: Trusted baseline cryptographic hashes for OS images, used to detect unauthorized modifications.; `AuthFailureThreshold` — Threshold for correlating unusual authentication successes following failed attempts or unknown account use.; `VerificationInterval` — Frequency of runtime OS image and memory integrity checks.

---

### T1556.005: Reversible Encryption
<a id="t1556005"></a>

Detection strategy: Detect Modification of Authentication Process via Reversible Encryption (`DET0589`)  
Platforms: Windows  
ATT&CK: [T1556.005](https://attack.mitre.org/techniques/T1556/005/), [detail page](../../techniques/defense-impairment.md#t1556005)

- `AN1621` Analytic 1621, Windows
  Detects enabling of reversible password encryption in Active Directory or Group Policy, suspicious PowerShell commands modifying AD user properties, and unusual account configuration changes correlated with policy modifications. Multi-event correlation links Group Policy edits, PowerShell command execution, and user account property changes to identify tampering with authentication encryption settings.
  - *Log sources:* `WinEventLog:Security (EventCode=4739)`; `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`
  - *Tune:* `MonitoredOUs`: Scope of Organizational Units where reversible encryption property monitoring is enabled.; `TimeWindow` — Time window in which to correlate Group Policy modification and subsequent user property changes.; `SuspiciousCmdletList` — List of PowerShell cmdlets to monitor for account configuration changes.

---

### T1556.006: Multi-Factor Authentication
<a id="t1556006"></a>

Detection strategy: Detect MFA Modification or Disabling Across Platforms (`DET0190`)  
Platforms: IaaS, Identity Provider, Linux, Office Suite, SaaS, Windows, macOS  
ATT&CK: [T1556.006](https://attack.mitre.org/techniques/T1556/006/), [detail page](../../techniques/defense-impairment.md#t1556006)

- `AN0543` Analytic 0543, Windows
  Detects registry and Group Policy modifications that disable or weaken MFA, suspicious PowerShell usage modifying MFA-related attributes, and anomalous login sessions succeeding without expected MFA challenge.
  - *Log sources:* `WinEventLog:Security (EventCode=4739)`; `WinEventLog:PowerShell (Set-ADUser or Set-ADAuthenticationPolicy with MFA attributes disabled)`
  - *Tune:* `WatchedAttributes`: List of AD attributes or policy fields tied to MFA enforcement that may vary by organization.; `TimeWindow` — Correlation window between MFA policy changes and anomalous login behavior.
- `AN0544` Analytic 0544, Identity Provider
  Detects conditional access policy changes, exclusion of accounts from MFA enforcement, or registration of new MFA factors by non-admin or anomalous users.
  - *Log sources:* `azure:signinlogs (Modify Conditional Access Policy)`; `m365:unified (User excluded from MFA or MFA method registered)`
  - *Tune:* `PrivilegedRoles`: Roles permitted to modify MFA settings in IdP; helps tune detection of unauthorized changes.
- `AN0545` Analytic 0545, IaaS
  Detects API calls to cloud secrets/MFA configurations where MFA enforcement policies are disabled or bypassed.
  - *Log sources:* `AWS:CloudTrail (UpdateIdentityPolicy or DisableMFA)`
  - *Tune:* `MonitoredServices`: Specific cloud services or IAM policies relevant to MFA enforcement.
- `AN0546` Analytic 0546, Linux
  Detects PAM module modifications or removal of MFA hooks in /etc/pam.d/ configurations, correlated with successful authentications lacking MFA prompts.
  - *Log sources:* `auditd:SYSCALL (open/write to /etc/pam.d/*)`; `NSM:Connections (Successful login without expected MFA challenge)`
  - *Tune:* `MFAHooks`: Paths to organization-specific PAM modules enforcing MFA.
- `AN0547` Analytic 0547, macOS
  Detects modifications to authorization plugins responsible for MFA enforcement and correlates with suspicious login sessions missing MFA prompts.
  - *Log sources:* `macos:unifiedlog (Modification of /Library/Security/SecurityAgentPlugins)`; `macos:unifiedlog (Login success without MFA step)`
  - *Tune:* `WatchedPluginPaths`: Paths to organization-deployed MFA authorization plugins.
- `AN0548` Analytic 0548, SaaS
  Detects suspicious MFA method changes, such as registration of weaker factors (e.g., SMS), or removal of MFA requirements for specific accounts or groups.
  - *Log sources:* `saas:zoom (DisableMFA or RegisterNewFactor)`
  - *Tune:* `AcceptedFactors`: Configured MFA factors allowed in SaaS environment; tuned to organizational policies.
- `AN0549` Analytic 0549, Office Suite
  Detects MFA bypass attempts by modifying tenant-wide authentication policies or excluding high-value accounts from MFA enforcement.
  - *Log sources:* `m365:unified (Set-CsOnlineUser or UpdateAuthPolicy)`
  - *Tune:* `MonitoredPolicies`: Specific tenant or suite policies tied to MFA enforcement.

---

### T1556.007: Hybrid Identity
<a id="t1556007"></a>

Detection strategy: Detect Hybrid Identity Authentication Process Modification (`DET0293`)  
Platforms: IaaS, Identity Provider, Office Suite, SaaS, Windows  
ATT&CK: [T1556.007](https://attack.mitre.org/techniques/T1556/007/), [detail page](../../techniques/defense-impairment.md#t1556007)

- `AN0814` Analytic 0814, Windows
  Detects injection or tampering of DLLs in hybrid identity agents (e.g., AzureADConnectAuthenticationAgentService), registry or configuration changes tied to PTA/AD FS, and anomalous LSASS or AD FS module loads correlated with authentication anomalies.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=7)`; `WinEventLog:Security (EventCode=5136)`; `WinEventLog:Security (Anomalous logon without MFA enforcement)`
  - *Tune:* `WatchedServices`: Hybrid identity services monitored for tampering, e.g., PTA agent, AD FS.; `TimeWindow` — Window correlating DLL/module load events with logon anomalies.
- `AN0815` Analytic 0815, Identity Provider
  Detects registration of new PTA agents, conditional access changes disabling hybrid MFA enforcement, or suspicious updates to AD FS token-signing configurations.
  - *Log sources:* `azure:signinlogs (Register PTA Agent or Modify AD FS trust)`; `m365:unified (New agent registration by non-admin user)`
  - *Tune:* `PrivilegedRoles`: Roles authorized to configure PTA/AD FS integrations.
- `AN0816` Analytic 0816, IaaS
  Detects API calls registering or updating hybrid identity connectors, modification of cloud-to-on-premises federation trust, and unusual token issuance logs.
  - *Log sources:* `AWS:CloudTrail (UpdateFederationSettings or RegisterHybridConnector)`
  - *Tune:* `MonitoredFederations`: Federation trusts and connectors relevant to hybrid identity setup.
- `AN0817` Analytic 0817, Office Suite
  Detects tenant-wide authentication or conditional access changes that weaken hybrid identity enforcement, including disabling AD FS or bypassing hybrid MFA policies.
  - *Log sources:* `m365:unified (Modify Federation Settings or Update Authentication Policy)`
  - *Tune:* `PolicyScope`: Scope of authentication and federation policies to be monitored.
- `AN0818` Analytic 0818, SaaS
  Detects suspicious changes to SAML/OAuth federation configurations, such as new signing certificates, altered endpoints, or claims issuance rules granting elevated privileges.
  - *Log sources:* `saas:okta (Federation configuration update or signing certificate change)`
  - *Tune:* `FederationEndpoints`: Federation/SAML endpoints monitored for modification.

---

### T1556.008: Network Provider DLL
<a id="t1556008"></a>

Detection strategy: Detect Network Provider DLL Registration and Credential Capture (`DET0580`)  
Platforms: Windows  
ATT&CK: [T1556.008](https://attack.mitre.org/techniques/T1556/008/), [detail page](../../techniques/defense-impairment.md#t1556008)

- `AN1598` Analytic 1598, Windows
  Detects registration of new or modified network provider DLLs via registry changes, anomalous file creation of DLLs in system directories, and suspicious process activity (mpnotify.exe interacting with non-standard DLLs). Multi-event correlation ties registry modification events to subsequent DLL loads during user logon activity.
  - *Log sources:* `WinEventLog:Security (EventCode=4657)`; `WinEventLog:Sysmon (EventCode=11)`; `WinEventLog:Sysmon (EventCode=10)`; `WinEventLog:Sysmon (EventCode=7)`
  - *Tune:* `MonitoredRegistryKeys`: Specific registry keys to monitor for DLL registration (e.g., NetworkProvider Order).; `SuspiciousDLLPaths` — Directories or file name patterns outside of normal system DLL locations.; `TimeWindow` — Window correlating registry modification, DLL creation, and subsequent logon activity.

---

### T1556.009: Conditional Access Policies
<a id="t1556009"></a>

Detection strategy: Detect Conditional Access Policy Modification in Identity and Cloud Platforms (`DET0030`)  
Platforms: IaaS, Identity Provider  
ATT&CK: [T1556.009](https://attack.mitre.org/techniques/T1556/009/), [detail page](../../techniques/defense-impairment.md#t1556009)

- `AN0087` Analytic 0087, IaaS
  Detects modifications to IAM conditions or policies that alter authentication behavior, such as adding permissive trusted IPs, removing MFA requirements, or changing regional access restrictions. Behavioral detection focuses on anomalous policy updates tied to privileged accounts and subsequent suspicious logon activity from previously blocked regions or devices.
  - *Log sources:* `AWS:CloudTrail (PutUserPolicy, PutGroupPolicy, PutRolePolicy, CreatePolicyVersion)`
  - *Tune:* `MonitoredIAMConditions`: Specific condition keys (SourceIp, RequestedRegion, MFAAuthenticated) tuned per environment.; `TimeWindow` — Correlates policy modification with follow-on logins from newly permitted sources.; `PrivilegedAccounts` — List of administrative accounts to prioritize when monitoring for conditional access changes.
- `AN0088` Analytic 0088, Identity Provider
  Detects suspicious updates to conditional access or MFA enforcement policies in identity providers such as Entra ID, Okta, or JumpCloud. Focus is on removal of policy blocks, addition of broad exclusions, or registration of adversary-controlled MFA methods, followed by anomalous login activity that takes advantage of the modified policies.
  - *Log sources:* `azure:activity (Update conditionalAccessPolicy)`; `saas:okta (Conditional Access policy rule modified or MFA requirement disabled)`
  - *Tune:* `TargetedApplications`: Specific SaaS or cloud apps most sensitive to conditional access changes.; `RiskThresholds` — Risk scores or signals that may be tuned for anomaly detection in login behavior.; `UserContext` — Business roles or expected MFA patterns per user/group to reduce false positives.

---

### T1578: Modify Cloud Compute Infrastructure
<a id="t1578"></a>

Detection strategy: Detection Strategy for Modify Cloud Compute Infrastructure (`DET0308`)  
Platforms: IaaS  
ATT&CK: [T1578](https://attack.mitre.org/techniques/T1578/), [detail page](../../techniques/defense-impairment.md#t1578)

- `AN0861` Analytic 0861, IaaS
  Detection focuses on identifying unauthorized or anomalous changes to compute infrastructure components. Defender perspective: monitor for creation, deletion, or modification of instances, volumes, and snapshots outside of approved change management windows; correlate abnormal activity such as rapid snapshot creation followed by new instance mounts, or repeated infrastructure changes by rarely used accounts. Flagging activity linked to unusual geolocation, API client, or automation script is suspicious.
  - *Log sources:* `AWS:CloudTrail (RunInstances)`; `AWS:CloudTrail (TerminateInstances)`; `AWS:CloudTrail (ModifyVolume)`; `AWS:CloudTrail (DeleteVolume, ModifyVolume)`; `AWS:CloudTrail (CreateVolume)`; `AWS:CloudTrail (CreateSnapshot)`; `AWS:CloudTrail (DeleteSnapshot)`; `AWS:CloudTrail (ModifySnapshotAttribute)`; `AWS:CloudWatch (unexpected IAM user or role assuming privileges for instance/snapshot operations)`
  - *Tune:* `ChangeWindow`: Approved maintenance or deployment windows. Helps reduce false positives by distinguishing scheduled activity.; `UserContext` — IAM user, role, or service account performing the operation. Tunable to allowlist known automation services.; `RateThreshold` — Number of infrastructure changes (e.g., snapshot creations) in a defined period. Adjusted based on workload scale.; `GeoLocation` — Region or source IP where changes originate. Useful for tuning alerts to account for multi-region deployments.

---

### T1578.001: Create Snapshot
<a id="t1578001"></a>

Detection strategy: Detection Strategy for Modify Cloud Compute Infrastructure: Create Snapshot (`DET0423`)  
Platforms: IaaS  
ATT&CK: [T1578.001](https://attack.mitre.org/techniques/T1578/001/), [detail page](../../techniques/defense-impairment.md#t1578001)

- `AN1187` Analytic 1187, IaaS
  Detection focuses on correlating snapshot creation events with subsequent instance creation and mounting activities. From a defender perspective, suspicious sequences include snapshot creation by unexpected or newly created IAM users, snapshots created from sensitive volumes without preceding change-control activity, or snapshots immediately followed by mounting to unauthorized instances. Cross-referencing with user behavior, IP geolocation, and automation context helps distinguish benign backup operations from adversary-driven snapshot exploitation.
  - *Log sources:* `AWS:CloudTrail (CreateSnapshot)`; `AWS:CloudTrail (DescribeSnapshots)`
  - *Tune:* `UserContext`: IAM user, service account, or role performing snapshot creation. Tuned to allowlist known backup automation services.; `TimeWindow` — Frequency of snapshot creation in a defined period. Adjusted for environments with frequent automated backups.; `GeoLocation` — Unusual regions or IPs from which snapshot creation API calls originate. Helps identify cross-region snapshot abuse.; `VolumeSensitivity` — Tagging or classification of volumes being snapshotted. Tuned to prioritize alerts when sensitive volumes are copied.

---

### T1578.002: Create Cloud Instance
<a id="t1578002"></a>

Detection strategy: Detection Strategy for Modify Cloud Compute Infrastructure: Create Cloud Instance (`DET0449`)  
Platforms: IaaS  
ATT&CK: [T1578.002](https://attack.mitre.org/techniques/T1578/002/), [detail page](../../techniques/defense-impairment.md#t1578002)

- `AN1242` Analytic 1242, IaaS
  Detection focuses on abnormal or unauthorized cloud instance creation events. From a defender’s perspective, suspicious behavior includes VM/instance creation by rarely used or newly created accounts, creation events from unusual geolocations, or rapid sequences of snapshot creation followed by instance creation and mounting. Unexpected network or IAM policy changes applied to new instances can indicate adversarial use rather than legitimate provisioning.
  - *Log sources:* `AWS:CloudTrail (RunInstances)`; `AWS:CloudTrail (DescribeInstances)`; `azure:activity (MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE)`
  - *Tune:* `UserContext`: IAM user, service account, or role creating the instance. Tuned to allowlist known automation services.; `GeoLocation` — Region or source IP where the creation request originates. Helps detect cross-region or unusual location abuse.; `RateThreshold` — Number of instances created per user or account in a time window. Tuned for environments with elastic scaling.; `TaggingPolicy` — Expected tags (e.g., owner, purpose, cost center) for new instances. Deviations may indicate adversarial creation.

---

### T1578.003: Delete Cloud Instance
<a id="t1578003"></a>

Detection strategy: Detection Strategy for Modify Cloud Compute Infrastructure: Delete Cloud Instance (`DET0084`)  
Platforms: IaaS  
ATT&CK: [T1578.003](https://attack.mitre.org/techniques/T1578/003/), [detail page](../../techniques/defense-impairment.md#t1578003)

- `AN0234` Analytic 0234, IaaS
  Defenders can detect suspicious cloud instance deletions by correlating events across authentication, instance lifecycle, and account activity. From a defender’s perspective, behaviors of interest include instances deleted shortly after creation, deletions initiated by new or rarely used accounts, deletions following snapshot creation, and deletions originating from anomalous geolocations or access keys. These may indicate adversarial attempts to destroy forensic evidence or evade detection.
  - *Log sources:* `AWS:CloudTrail (TerminateInstances)`; `AWS:CloudTrail (DescribeInstances)`; `azure:activity (MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE)`
  - *Tune:* `UserContext`: Identity of the user/service account performing deletions; tuned to exclude automation or known administrative workflows.; `TimeWindow` — Threshold for detecting rapid instance lifecycle events (e.g., creation and deletion within minutes).; `GeoLocation` — Region or source IP where the delete request originated; can be tuned to align with enterprise cloud geography.; `RateThreshold` — Number of deletions per user/account in a defined window; tuned for organizations with high elasticity.

---

### T1578.004: Revert Cloud Instance
<a id="t1578004"></a>

Detection strategy: Detection Strategy for Modify Cloud Compute Infrastructure: Revert Cloud Instance (`DET0337`)  
Platforms: IaaS  
ATT&CK: [T1578.004](https://attack.mitre.org/techniques/T1578/004/), [detail page](../../techniques/defense-impairment.md#t1578004)

- `AN0953` Analytic 0953, IaaS
  Defenders can detect suspicious reversion of cloud compute instances by monitoring for unusual snapshot restores, rollback actions, or ephemeral storage resets that occur outside expected administrative workflows. From a defender’s perspective, relevant detection chains include: a snapshot restore triggered by a new or rarely used account, a sequence of snapshot creation immediately followed by a restore and instance start, or rollbacks performed from anomalous geographic or network locations. These patterns may indicate attempts to remove forensic evidence or re-establish a clean execution state for persistence.
  - *Log sources:* `AWS:CloudTrail (RevertSnapshot)`; `AWS:CloudTrail (StartInstances)`; `AWS:CloudTrail (StopInstances)`
  - *Tune:* `UserContext`: Identity of the user or service account performing rollback actions; tuned to exclude automation or approved workflows.; `TimeWindow` — Threshold for correlating snapshot creation followed by reversion within minutes; tuned to environment activity norms.; `GeoLocation` — Region or source IP where the revert request originated; tuned to align with enterprise cloud geography.; `ChangeTags` — Use of administrative tags or headers to distinguish legitimate restores from malicious activity.

---

### T1578.005: Modify Cloud Compute Configurations
<a id="t1578005"></a>

Detection strategy: Detection Strategy for Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations (`DET0492`)  
Platforms: IaaS  
ATT&CK: [T1578.005](https://attack.mitre.org/techniques/T1578/005/), [detail page](../../techniques/defense-impairment.md#t1578005)

- `AN1356` Analytic 1356, IaaS
  Defenders should monitor for anomalous or unauthorized changes to cloud compute configurations that alter quotas, tenant-wide policies, subscription associations, or allowed deployment regions. From a defender’s perspective, suspicious behavior chains include a sudden increase in compute quota requests followed by new instance or resource creation, policy modifications that weaken security restrictions, or enabling previously unused/unsupported cloud regions. Correlation across identity, configuration, and subsequent provisioning logs is critical to distinguish legitimate administrative activity from adversarial abuse.
  - *Log sources:* `AWS:CloudTrail (RequestServiceQuotaIncrease)`
  - *Tune:* `UserContext`: Identity performing the quota or configuration change; tuned to filter known admins or automation accounts.; `TimeWindow` — Correlation period for configuration change followed by resource creation; tuned to environment norms.; `ChangeType` — Type of configuration being modified (quota, policy, region); tuned to organization-specific risk thresholds.; `GeoLocation` — Region where the configuration change originates; tuned to enterprise’s expected operational geography.

---

### T1599: Network Boundary Bridging
<a id="t1599"></a>

Detection strategy: Detection Strategy for Network Boundary Bridging (`DET0006`)  
Platforms: Network Devices  
ATT&CK: [T1599](https://attack.mitre.org/techniques/T1599/), [detail page](../../techniques/defense-impairment.md#t1599)

- `AN0015` Analytic 0015, Network Devices
  From a defender’s perspective, suspicious bridging is observed when network devices begin allowing traffic that contradicts existing segmentation or access policies. Observable behaviors include sudden modifications to ACLs or firewall rules, unusual cross-boundary traffic flows (e.g., east-west communications across separated VLANs), or simultaneous ingress/egress anomalies. Multi-event correlation is key: configuration changes on a router/firewall followed by unexpected traffic patterns, especially from unusual sources, is a strong indicator of compromise.
  - *Log sources:* `NSM:Flow (Unexpected flows between segmented networks or prohibited ports)`; `networkdevice:syslog (ACL/Firewall rule modification or new route injection)`
  - *Tune:* `TimeWindow`: Correlation window between configuration changes and abnormal traffic; tuned to match expected administrative change cycles.; `ApprovedChangeList` — Known authorized ACL/firewall changes; suppresses noise from legitimate maintenance.; `GeoLocation` — Geographic origin of new traffic patterns; helps distinguish benign remote offices from suspicious foreign access.; `TrafficVolumeThreshold` — Volume of cross-segment traffic; tuned to detect large-scale lateral flows without flagging small test connections.

---

### T1599.001: Network Address Translation Traversal
<a id="t1599001"></a>

Detection strategy: Detection Strategy for Network Address Translation Traversal (`DET0163`)  
Platforms: Network Devices  
ATT&CK: [T1599.001](https://attack.mitre.org/techniques/T1599/001/), [detail page](../../techniques/defense-impairment.md#t1599001)

- `AN0465` Analytic 0465, Network Devices
  Defenders may observe unauthorized or anomalous changes to NAT configurations, including the addition of new translation rules or modifications to existing ones. Suspicious behaviors include sudden introduction of NAT mappings bridging segmented networks, new port address translation rules that obscure true source IPs, or traffic flows inconsistent with expected network design. Multi-event correlation includes detecting configuration changes on routers/firewalls, followed by traffic traversing unexpected internal/external address pairs.
  - *Log sources:* `networkdevice:config (NAT table modification (add/update/delete rule))`; `NSM:Flow (Source/destination IP translation inconsistent with intended policy)`
  - *Tune:* `TimeWindow`: Time correlation window between NAT rule change and unexpected traffic; adjustable to align with change management practices.; `AuthorizedNATRules` — Whitelist of approved NAT policies and rules; prevents false positives from legitimate operations.; `TrafficVolumeThreshold` — Threshold for abnormal traffic across NAT; tuned to differentiate testing from large-scale exfiltration or bridging.; `InterfaceScope` — Specific interfaces or zones monitored for NAT translation; allows tuning for internal vs. external-facing boundaries.

---

### T1600: Weaken Encryption
<a id="t1600"></a>

Detection strategy: Detection Strategy for Weaken Encryption on Network Devices (`DET0339`)  
Platforms: Network Devices  
ATT&CK: [T1600](https://attack.mitre.org/techniques/T1600/), [detail page](../../techniques/defense-impairment.md#t1600)

- `AN0961` Analytic 0961, Network Devices
  Defenders may observe unauthorized modifications to encryption-related configuration files, firmware, or crypto modules on network devices. Suspicious patterns include changes to cipher suite configurations, unexpected firmware updates affecting crypto libraries, disabling of hardware cryptographic accelerators, or reductions in key length policies. Correlating configuration changes with anomalies in encrypted traffic characteristics (e.g., weaker ciphers or sudden plaintext transmission) strengthens detection.
  - *Log sources:* `networkdevice:config (Configuration change events referencing encryption, TLS/SSL, or IPSec settings)`; `NSM:Flow (Traffic patterns showing downgrade from strong encryption (AES-256) to weaker or plaintext protocols)`; `snmp:status (Status change in cryptographic hardware modules (enabled -> disabled))`
  - *Tune:* `CipherSuiteWhitelist`: List of approved encryption algorithms and key lengths; customizable to organizational policy.; `TimeWindow` — Correlation period between configuration changes and abnormal traffic; adjustable to reduce false positives.; `AuthorizedFirmwareSources` — Known trusted sources of firmware updates; deviations indicate possible compromise.; `TrafficEntropyThreshold` — Baseline entropy measurements of encrypted traffic; deviations may reveal weakening of encryption.

---

### T1600.001: Reduce Key Space
<a id="t1600001"></a>

Detection strategy: Detection Strategy for Weaken Encryption: Reduce Key Space on Network Devices (`DET0243`)  
Platforms: Network Devices  
ATT&CK: [T1600.001](https://attack.mitre.org/techniques/T1600/001/), [detail page](../../techniques/defense-impairment.md#t1600001)

- `AN0681` Analytic 0681, Network Devices
  Defenders may observe attempts to alter cryptographic settings on network devices that reduce key strength or allowable cipher suites. Suspicious indicators include configuration changes that downgrade encryption algorithms, key length parameters, or the disabling of strong encryption in favor of legacy ciphers. These activities often appear as CLI commands modifying crypto policies, firmware changes affecting crypto libraries, or unexpected updates to key management files. Correlation across device config logs and traffic analysis showing weaker ciphers provides higher confidence of malicious key space reduction.
  - *Log sources:* `networkdevice:config (Configuration changes referencing 'crypto', 'key length', 'cipher', or downgrade of encryption settings)`; `networkdevice:cli (Execution of CLI commands altering crypto parameters (e.g., 'crypto key generate rsa modulus 512'))`; `NSM:Flow (Observed downgrade in negotiated cipher suites or TLS/SSH versions across sessions)`
  - *Tune:* `AllowedKeyLengths`: Defines the minimum acceptable encryption key sizes; tunable to organizational policy.; `CipherSuiteBaseline` — Baseline list of approved cipher suites for network sessions; deviations may indicate tampering.; `AuthorizedAdminAccounts` — Whitelisted accounts for executing crypto configuration changes; ensures alerts only trigger on unauthorized actions.; `TimeWindow` — Time correlation period between configuration change and anomalous traffic downgrade; adjustable to reduce noise.

---

### T1600.002: Disable Crypto Hardware
<a id="t1600002"></a>

Detection strategy: Detection Strategy for Weaken Encryption: Disable Crypto Hardware on Network Devices (`DET0494`)  
Platforms: Network Devices  
ATT&CK: [T1600.002](https://attack.mitre.org/techniques/T1600/002/), [detail page](../../techniques/defense-impairment.md#t1600002)

- `AN1360` Analytic 1360, Network Devices
  Defenders may observe attempts to disable dedicated crypto hardware on network devices, often visible through anomalous CLI commands, unexpected firmware or configuration updates, and degraded encryption performance. Suspicious indicators include commands that alter hardware acceleration settings (e.g., disabling AES-NI or crypto engines), modification of system image files, or logs showing fallback from hardware to software encryption. Network traffic analysis may also reveal a sudden downgrade in throughput or cipher negotiation behavior consistent with the absence of hardware acceleration.
  - *Log sources:* `networkdevice:cli (Execution of commands disabling crypto hardware acceleration (e.g., 'no crypto engine enable'))`; `networkdevice:config (Configuration changes referencing cryptographic hardware modules or disabling hardware acceleration)`; `NSM:Flow (Degraded encryption throughput or switch to weaker cipher suites compared to historical baselines)`
  - *Tune:* `AuthorizedAdminAccounts`: Defines trusted administrator accounts allowed to modify encryption hardware settings; deviations trigger alerts.; `BaselineThroughput` — Expected performance metrics with hardware acceleration enabled; drops may indicate tampering.; `ApprovedFirmwareVersions` — Whitelist of vendor-signed firmware versions; unexpected updates could signal malicious modification.; `TimeWindow` — Period of correlation between configuration change and observed traffic downgrade; tunable to reduce false positives.

---

### T1601: Modify System Image
<a id="t1601"></a>

Detection strategy: Detection Strategy for Modify System Image on Network Devices (`DET0170`)  
Platforms: Network Devices  
ATT&CK: [T1601](https://attack.mitre.org/techniques/T1601/), [detail page](../../techniques/defense-impairment.md#t1601)

- `AN0482` Analytic 0482, Network Devices
  Defenders may observe adversary attempts to alter or replace a network device’s operating system image through anomalous CLI commands, unexpected firmware updates, integrity check failures, or mismatches in version and checksum validation. Suspicious behavior includes modification of image files on storage, OS version output inconsistent with baselines, unexpected reloads or reboots after image replacement, and changes to boot configuration that load non-standard system images.
  - *Log sources:* `networkdevice:cli (Execution of commands to load, copy, or replace system images (e.g., 'copy tftp flash', 'boot system'))`; `networkdevice:config (Configuration changes to boot variables, startup image paths, or checksum verification failures)`
  - *Tune:* `AuthorizedAdminAccounts`: Defines trusted administrator accounts allowed to modify system images; deviations indicate possible malicious modification.; `ApprovedFirmwareVersions` — Whitelist of validated vendor OS images; unexpected versions may suggest adversarial tampering.; `TimeWindow` — Correlation window for detecting config changes followed by firmware updates or reboots.; `ChecksumBaseline` — Baseline cryptographic hashes of approved system images; deviations may indicate compromise.

---

### T1601.001: Patch System Image
<a id="t1601001"></a>

Detection strategy: Detection Strategy for Patch System Image on Network Devices (`DET0469`)  
Platforms: Network Devices  
ATT&CK: [T1601.001](https://attack.mitre.org/techniques/T1601/001/), [detail page](../../techniques/defense-impairment.md#t1601001)

- `AN1293` Analytic 1293, Network Devices
  Defenders may observe adversary attempts to patch system images by monitoring for anomalous file transfers (TFTP, SCP, FTP) of image files, unauthorized CLI commands altering boot system variables, integrity check mismatches between running and baseline OS images, and runtime memory manipulation attempts. Suspicious sequences include uploading a new image, modifying boot parameters, and subsequent reload/reboot of the device. In-memory patching attempts may manifest as debug commands or boot loader manipulation inconsistent with normal administrative activity.
  - *Log sources:* `networkdevice:cli (Execution of privileged commands such as 'copy tftp flash', 'boot system', or 'debug memory')`; `networkdevice:config (Configuration changes to startup image paths, boot loader parameters, or debug flags)`; `firmware:runtime (Debug or memory access commands indicating attempts to alter OS instructions in memory)`
  - *Tune:* `ApprovedFirmwareVersions`: Whitelist of validated vendor OS versions; deviations may indicate tampering.; `AuthorizedAdminAccounts` — Trusted admin accounts permitted to update images; anomalies suggest compromise.; `ChecksumBaseline` — Baseline hash of approved images; used for detecting file tampering.; `TimeWindow` — Correlation period for detecting chained behaviors (file upload -> boot config change -> reboot).

---

### T1601.002: Downgrade System Image
<a id="t1601002"></a>

Detection strategy: Detection Strategy for Downgrade System Image on Network Devices (`DET0569`)  
Platforms: Network Devices  
ATT&CK: [T1601.002](https://attack.mitre.org/techniques/T1601/002/), [detail page](../../techniques/defense-impairment.md#t1601002)

- `AN1570` Analytic 1570, Network Devices
  Defenders may observe adversary attempts to downgrade system images by monitoring for anomalous file transfers of OS image files (via TFTP, FTP, SCP), configuration changes pointing boot system variables to older image files, unexpected OS version strings after reboot, and checksum mismatches against approved baseline images. Suspicious chains include transfer of an older image, alteration of boot configuration, and reboot/reload of the device. Adversaries may also tamper with CLI output to disguise downgrade attempts, requiring independent validation of OS version and integrity.
  - *Log sources:* `networkdevice:cli (Execution of commands such as 'copy tftp flash', 'boot system <image>', 'reload')`; `networkdevice:config (Configuration changes referencing older image versions or unexpected boot parameters)`; `networkdevice:syslog (OS version query results inconsistent with expected or approved version list)`
  - *Tune:* `ApprovedFirmwareVersions`: Whitelist of supported and validated OS versions for devices; helps reduce false positives.; `ChecksumBaseline` — Baseline cryptographic hashes of valid OS images; deviations indicate possible downgrade or tampering.; `TimeWindow` — Correlation period to detect the chain of file transfer -> boot config change -> reboot event.; `AuthorizedAdminAccounts` — Accounts authorized to perform OS upgrades/downgrades; anomalies suggest misuse or compromise.

---

### T1647: Plist File Modification
<a id="t1647"></a>

Detection strategy: Detection Strategy for Plist File Modification (T1647) (`DET0109`)  
Platforms: macOS  
ATT&CK: [T1647](https://attack.mitre.org/techniques/T1647/), [detail page](../../techniques/defense-impairment.md#t1647)

- `AN0306` Analytic 0306, macOS
  Monitor for unexpected modifications of plist files in persistence or configuration directories (e.g., ~/Library/LaunchAgents, ~/Library/Preferences, /Library/LaunchDaemons). Detect when modifications are followed by execution of new or unexpected binaries. Track use of utilities such as defaults, plutil, or text editors making changes to Info.plist files. Correlate file modifications with subsequent process launches or service starts that reference the altered plist.
  - *Log sources:* `macos:unifiedlog (write: File modifications to *.plist within LaunchAgents, LaunchDaemons, Application Support, or Preferences directories)`; `macos:unifiedlog (exec: Execution of defaults, plutil, or common editors (vim/nano) targeting plist files)`; `macos:unifiedlog (exec: Invocation of /usr/bin/defaults write or /usr/bin/plutil modifying plist keys)`
  - *Tune:* `MonitoredDirectories`: Set of directories where plist modifications are considered suspicious (e.g., ~/Library/LaunchAgents, /Library/LaunchDaemons); `SuspiciousKeys` — List of plist keys associated with evasion or persistence (e.g., LSUIElement, LSEnvironment, ProgramArguments); `TimeWindow` — Temporal correlation window to link plist file modifications with subsequent suspicious process launches

---

### T1666: Modify Cloud Resource Hierarchy
<a id="t1666"></a>

Detection strategy: Detection Strategy for Modify Cloud Resource Hierarchy (`DET0155`)  
Platforms: IaaS  
ATT&CK: [T1666](https://attack.mitre.org/techniques/T1666/), [detail page](../../techniques/defense-impairment.md#t1666)

- `AN0442` Analytic 0442, IaaS
  Monitor for unauthorized or unusual modifications to cloud resource hierarchies such as AWS Organizations or Azure Management Groups. Defenders may observe anomalous calls to APIs like `LeaveOrganization`, `CreateAccount`, `MoveAccount`, or Azure subscription transfers. Correlate account activity with administrative role assignments, tenant transfers, or new subscription creation that deviates from organizational baselines. Multi-event correlation should track role elevation followed by hierarchy modifications within a short time window.
  - *Log sources:* `AWS:CloudTrail (LeaveOrganization: API calls severing accounts from AWS Organizations)`
  - *Tune:* `TimeWindow`: Threshold for correlating role elevation with hierarchy modification events.; `PrivilegedRoleList` — List of high-privilege roles (e.g., Global Administrator, OrganizationAccountAccessRole) used to monitor sensitive modifications.; `SubscriptionTransferPatterns` — Patterns of subscription changes that may indicate hijacking or unauthorized tenant transfers.

---

### T1685: Disable or Modify Tools
<a id="t1685"></a>

Detection strategy: Detection Strategy for Impair Defenses Across Platforms (`DET0317`)  
Platforms: Containers, ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, Windows, macOS  
ATT&CK: [T1685](https://attack.mitre.org/techniques/T1685/), [detail page](../../techniques/defense-impairment.md#t1685)

- `AN0886` Analytic 0886, Windows
  Unusual service stop events, termination of AV/EDR processes, registry modifications disabling security tools, and firewall/defender configuration changes. Correlate process creation with service stop requests and registry edits.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:System (EventCode=7045)`; `WinEventLog:Sysmon (EventCode=12)`
  - *Tune:* `ProcessWhitelist`: Exclude authorized administrative tools that stop services during maintenance.; `ServiceNamePatterns` — Refine which services are considered security-critical (e.g., AV, EDR, firewall).
- `AN0887` Analytic 0887, Linux
  Execution of commands that stop or kill processes associated with logging or security daemons (auditd, syslog, falco). Detect modifications to iptables or disabling SELinux/AppArmor enforcement. Correlate sudo/root context with abrupt service halts.
  - *Log sources:* `auditd:EXECVE (systemctl stop auditd, kill -9 <pid>, or modifications to /etc/selinux/config)`; `auditd:SYSCALL (kill syscalls targeting logging/security processes)`; `linux:syslog (iptables or nftables rule changes)`
  - *Tune:* `ServiceList`: Adjust monitored security service names depending on host configuration.; `TimeWindow` — Correlate multiple kill/stop events in short succession.
- `AN0888` Analytic 0888, macOS
  Execution of commands or APIs that disable Gatekeeper, XProtect, or system integrity protections. Detect configuration changes through unified logs. Monitor termination of system security daemons (e.g., syspolicyd).
  - *Log sources:* `macos:unifiedlog (spctl --master-disable, csrutil disable, or defaults write to disable Gatekeeper)`; `macos:unifiedlog (Termination of syspolicyd or XProtect processes)`
  - *Tune:* `AdminToolWhitelist`: Developers may legitimately disable Gatekeeper; whitelist approved contexts.
- `AN0889` Analytic 0889, Containers
  Modification of container runtime security profiles (AppArmor, seccomp) or removal of monitoring agents within containers. Detect unauthorized mounting/unmounting of host /proc or /sys to disable logging or auditing.
  - *Log sources:* `kubernetes:audit (seccomp or AppArmor profile changes)`; `docker:runtime (Termination of monitoring sidecar or security container)`
  - *Tune:* `RuntimeProfiles`: Specify which security profiles should be monitored for modification.
- `AN0890` Analytic 0890, ESXi
  Unusual ESXi shell commands disabling syslog forwarding or stopping hostd/vpxa daemons. Detect modifications to firewall rules on ESXi host or disabling of lockdown mode.
  - *Log sources:* `esxi:shell (esxcli system syslog config set --loghost='' or stopping hostd service)`; `esxi:vmkernel (Disabling or modifying firewall rules)`
  - *Tune:* `LogDestination`: Tune for environment-specific log forwarding hosts.
- `AN0891` Analytic 0891, IaaS
  Cloud control plane actions disabling security services (CloudTrail logging, GuardDuty, Security Hub). Detect IAM role abuse correlating with service disable events.
  - *Log sources:* `AWS:CloudTrail (StopLogging, DeleteTrail, or DisableSecurityService)`
  - *Tune:* `ServiceScope`: Specify which cloud services (logging, monitoring, threat detection) must never be disabled.
- `AN0892` Analytic 0892, Identity Provider
  Changes to security configurations such as disabling MFA requirements, reducing session token lifetimes, or turning off risk-based policies. Correlate admin logins with sudden policy downgrades.
  - *Log sources:* `azure:policy (DisableMfaPolicy or change to ConditionalAccess rules)`
  - *Tune:* `PolicyList`: Adjust for the critical identity provider security policies to monitor.
- `AN0893` Analytic 0893, Network Devices
  Execution of commands disabling AAA, logging, or security features on routers/switches. Detect privilege escalation followed by config changes that disable defense mechanisms.
  - *Log sources:* `networkdevice:syslog (no logging buffered, no aaa new-model, disable firewall)`
  - *Tune:* `CommandPatterns`: Customize destructive command list per vendor platform.
- `AN0894` Analytic 0894, Office Suite
  Disabling of security macros or safe mode settings within Word/Excel/Outlook. Detect registry edits or configuration file changes that weaken macro enforcement.
  - *Log sources:* `m365:unified (MacroSecuritySettingsChanged or SafeModeDisabled)`
  - *Tune:* `ApplicationScope`: Specify which Office applications are monitored for macro security configuration changes.

---

### T1685.001: Disable or Modify Windows Event Log
<a id="t1685001"></a>

Detection strategy: Detect disabled Windows event logging (`DET0187`)  
Platforms: Windows  
ATT&CK: [T1685.001](https://attack.mitre.org/techniques/T1685/001/), [detail page](../../techniques/defense-impairment.md#t1685001)

- `AN0535` Analytic 0535, Windows
  Detection of attempts to disable or tamper with Windows Event Logging. This includes stopping or disabling the EventLog service, modifying registry keys related to EventLog and Autologger, using `auditpol` or `wevtutil` to disable categories or clear audit policies, and detecting suspicious gaps or resets in event logs. Defenders observe registry changes, service state changes, process execution of disabling commands, and anomalies in event record sequences.
  - *Log sources:* `WinEventLog:System (EventCode=7035)`; `WinEventLog:Security (EventCode=1102)`; `WinEventLog:Sysmon (EventCode=13, 14)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `AuthorizedAdminAccounts`: List of accounts authorized to legitimately modify audit policies or disable services.; `TimeWindow` — Correlation window between registry modification, service stop, and audit policy commands.; `ServiceNames` — Customizable set of monitored services such as EventLog, Sysmon, or custom loggers.

---

### T1685.002: Disable or Modify Cloud Log
<a id="t1685002"></a>

Detection strategy: Detection Strategy for Disable or Modify Cloud Logs (`DET0289`)  
Platforms: IaaS, Identity Provider, Office Suite, SaaS  
ATT&CK: [T1685.002](https://attack.mitre.org/techniques/T1685/002/), [detail page](../../techniques/defense-impairment.md#t1685002)

- `AN0801` Analytic 0801, IaaS
  Cloud API events where logging services are stopped, deleted, or modified in a way that disables audit visibility. Defender view: unauthorized StopLogging, DeleteTrail, or UpdateSink operations correlated with privileged user activity.
  - *Log sources:* `AWS:CloudTrail (Stop logging for an existing CloudTrail)`; `gcp:config (UpdateSink request modifying log export destinations)`
  - *Tune:* `AdminRoles`: Define which roles are authorized to stop or modify logging.; `RegionScope` — Adjust monitoring to ensure multi-region logging tampering is caught.
- `AN0802` Analytic 0802, Identity Provider
  Disabling or modifying sign-in or audit log collection for user activities. Defender view: policy or configuration updates removing logging coverage for critical accounts.
  - *Log sources:* `azure:policy (DisableAuditLogs or ConditionalAccess logging changes)`
  - *Tune:* `CriticalAccounts`: Tune to prioritize logging changes that affect administrative or high-value accounts.
- `AN0803` Analytic 0803, Office Suite
  Disabling mailbox or tenant-level audit logging, often using Set-MailboxAuditBypassAssociation or downgrading license tiers. Defender view: sudden absence of mailbox activity logging for monitored users.
  - *Log sources:* `m365:unified (Set-MailboxAuditBypassAssociation or disabling Advanced Auditing)`
  - *Tune:* `UserScope`: Tune alerts for users where mailbox auditing should always remain enabled.
- `AN0804` Analytic 0804, SaaS
  Disabling or altering security and audit logs in SaaS admin panels (e.g., Slack, Zoom, Salesforce). Defender view: API calls or admin console changes that stop event exports or logging integrations.
  - *Log sources:* `saas:audit (Log export integration removed or disabled)`
  - *Tune:* `IntegrationScope`: Define which SaaS log integrations are required and alert if removed.

---

### T1685.003: Modify or Spoof Tool UI
<a id="t1685003"></a>

Detection strategy: Detection for Spoofing Security Alerting across OS Platforms (`DET0311`)  
Platforms: Linux, Windows, macOS  
ATT&CK: [T1685.003](https://attack.mitre.org/techniques/T1685/003/), [detail page](../../techniques/defense-impairment.md#t1685003)

- `AN0868` Analytic 0868, Windows
  Detection of inconsistencies between reported sensor health and actual process/service state. For example, Windows Defender tray icon/UI showing healthy status while corresponding Defender services (WinDefend, MsMpEng) are stopped or disabled. Correlates process creation events with missing or terminated security processes and spoofed health events.
  - *Log sources:* `WinEventLog:System (EventCode=7036)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `ServiceNameList`: Monitored list of critical security service names; environment-specific.; `FakeUIProcessPatterns` — Patterns of filenames or paths mimicking Windows Security GUI elements.
- `AN0869` Analytic 0869, Linux
  Monitoring for discrepancies between system daemon/service state and reported health messages (e.g., syslog shows AV/IDS daemon stopped, but spoofed messages claim it is still running). Detects userland processes impersonating AV/IDS command-line outputs or modifying log forwarding configurations.
  - *Log sources:* `auditd:SYSCALL (execve: Execution of binaries/scripts presenting false health messages for security daemons)`; `linux:syslog (Service stop or disable messages for security tools not reflected in SIEM alerts)`
  - *Tune:* `SecurityDaemonList`: Names of AV/IDS/EDR daemons monitored in Linux environments.
- `AN0870` Analytic 0870, macOS
  Detection of fake or spoofed macOS Security & Privacy GUIs showing healthy status after XProtect, Gatekeeper, or AV processes are disabled. Correlates user-space UI process creation with terminated or missing security daemons.
  - *Log sources:* `macos:unifiedlog (Execution of processes mimicking Apple Security & Privacy GUIs)`; `macos:unifiedlog (Termination or disabling of XProtect, Gatekeeper, or third-party AV daemons)`
  - *Tune:* `TrustedDaemonList`: Monitored list of macOS security daemons such as XProtect, Gatekeeper, or third-party AV.

---

### T1685.004: Disable or Modify Linux Audit System Log
<a id="t1685004"></a>

Detection strategy: Detection Strategy for Disable or Modify Linux Audit System (`DET0062`)  
Platforms: Linux  
ATT&CK: [T1685.004](https://attack.mitre.org/techniques/T1685/004/), [detail page](../../techniques/defense-impairment.md#t1685004)

- `AN0171` Analytic 0171, Linux
  Disabling or modifying the Linux Audit system through process termination (auditd killed), service management (systemctl stop auditd), or tampering with rule/configuration files (/etc/audit/audit.rules, audit.conf). Defender view: suspicious execution of auditctl/systemctl commands, file modifications to audit rules, or sudden absence of audit logs correlated with privileged execution.
  - *Log sources:* `auditd:EXECVE (Execution of auditctl, systemctl stop auditd, or kill -9 auditd)`; `auditd:SYSCALL (kill syscalls targeting auditd process)`; `auditd:FILE (Modification or deletion of /etc/audit/audit.rules or /etc/audit/audit.conf)`; `linux:syslog (auditd service stopped or disabled)`
  - *Tune:* `ServiceWhitelist`: Exclude legitimate administrative service stops during system maintenance.; `FilePathScope` — Specify monitored paths (/etc/audit/audit.rules, audit.conf) to avoid false positives from unrelated file writes.; `TimeWindow` — Correlate suspicious commands, file modifications, and audit log gaps in short succession.

---

### T1685.005: Clear Windows Event Logs
<a id="t1685005"></a>

Detection strategy: Detection of Event Log Clearing on Windows via Behavioral Chain (`DET0532`)  
Platforms: Windows  
ATT&CK: [T1685.005](https://attack.mitre.org/techniques/T1685/005/), [detail page](../../techniques/defense-impairment.md#t1685005)

- `AN1472` Analytic 1472, Windows
  Detects behavioral sequence where an adversary gains elevated privileges and clears event logs using native binaries (e.g., wevtutil), PowerShell, or direct file deletion of .evtx files.
  - *Log sources:* `WinEventLog:Security (EventCode=1102)`; `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Sysmon (EventCode=23)`
  - *Tune:* `TimeWindow`: Time range between log-clearing command and 1102 event; tunable to reduce false positives; `UserContext` — Filter by admin/elevated users; allow tuning to detect abuse of high-privilege accounts; `CommandLinePattern` — Match common variations of log-clearing commands like `Remove-EventLog`, `wevtutil cl`; `TargetLogName` — Scope detection to Security, System, Application, or custom logs based on environment

---

### T1685.006: Clear Linux or Mac System Logs
<a id="t1685006"></a>

Detection strategy: Behavioral Detection of Log File Clearing on Linux and macOS (`DET0520`)  
Platforms: Linux, macOS  
ATT&CK: [T1685.006](https://attack.mitre.org/techniques/T1685/006/), [detail page](../../techniques/defense-impairment.md#t1685006)

- `AN1438` Analytic 1438, Linux
  Detects log-clearing behavior by correlating suspicious command execution targeting log files under /var/log/, anomalous deletions or truncations of system logs, and unusual child processes (e.g., shell pipelines or redirections).
  - *Log sources:* `auditd:SYSCALL (execve)`; `auditd:SYSCALL (PATH)`
  - *Tune:* `TimeWindow`: The time window used to correlate log file interaction and suspicious command execution.; `LogFilePathPattern` — Regex pattern used to match monitored log file paths (e.g., /var/log/auth.log).; `UserContext` — User or group (e.g., root) that should trigger higher severity detection.
- `AN1439` Analytic 1439, macOS
  Detects adversary clearing log files on macOS by correlating calls to shell utilities (e.g., echo >, rm, truncate) targeting files in /var/log/ with unusual context (non-administrative users or abnormal process lineage).
  - *Log sources:* `macos:unifiedlog (process)`; `fs:fsusage (truncate, unlink, write)`
  - *Tune:* `TimeWindow`: Duration in which process activity and file I/O should be temporally linked.; `LogFilePathPattern` — Tunable path filter for macOS logs such as /var/log/system.log or /var/log/asl.log.; `UserContext` — Detects higher risk when log deletion is performed by unusual users (e.g., interactive vs. system users).

---

### T1686: Disable or Modify System Firewall
<a id="t1686"></a>

Detection strategy: Detection of Disabled or Modified System Firewalls across OS Platforms. (`DET0145`)  
Platforms: ESXi, Linux, Network Devices, Windows, macOS  
ATT&CK: [T1686](https://attack.mitre.org/techniques/T1686/), [detail page](../../techniques/defense-impairment.md#t1686)

- `AN0406` Analytic 0406, Windows
  Detection of firewall tampering by monitoring processes executing netsh, PowerShell Set-NetFirewallProfile, or sc stop mpssvc. Registry modifications under HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy also indicate adversarial actions.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=13, 14)`
  - *Tune:* `MonitoredCommands`: List of admin tools and scripts allowed to legitimately modify firewall settings.; `AlertThreshold` — Number of firewall rule changes within a time window before triggering alert.
- `AN0407` Analytic 0407, Linux
  Detection of iptables, nftables, or firewalld rule modifications. Correlation of sudden drops in active firewall rules with suspicious processes suggests adversarial evasion.
  - *Log sources:* `auditd:SYSCALL (execve: iptables, nft, firewall-cmd modifications)`; `linux:osquery (execution of known firewall binaries)`
  - *Tune:* `AllowedScripts`: Baseline admin scripts allowed to make firewall modifications.
- `AN0408` Analytic 0408, macOS
  Detection of PF firewall rule modifications via pfctl, socketfilterfw, or defaults write to com.apple.alf. Adversaries often disable firewall profiles entirely or whitelist malicious processes.
  - *Log sources:* `macos:unifiedlog (pfctl -d, socketfilterfw --setglobalstate off, or modifications to com.apple.alf)`
  - *Tune:* `PFConfigFiles`: Monitor for baseline pf.conf and custom rule file modifications.
- `AN0409` Analytic 0409, ESXi
  Detection of firewall changes using esxcli network firewall set or vSphere API modifications. Sudden disabling of firewall rules across management interfaces is a strong adversarial signal.
  - *Log sources:* `esxi:hostd (esxcli network firewall set commands)`; `esxi:hostd (vSphere API calls modifying firewall settings)`
  - *Tune:* `APIMethods`: Whitelist of authorized vSphere API methods for firewall configuration.
- `AN0410` Analytic 0410, Network Devices
  Detection of firewall ACL or rule base changes through CLI (e.g., no access-list, permit any any). Monitor configuration commits from unusual users or sessions.
  - *Log sources:* `networkdevice:cli (firewall disable commands or suspicious ACL modifications)`
  - *Tune:* `AuthorizedAdmins`: List of approved admin accounts allowed to modify firewall ACLs.

---

### T1686.001: Cloud Firewall
<a id="t1686001"></a>

Detection strategy: Detection Strategy for Disable or Modify Cloud Firewall (`DET0424`)  
Platforms: IaaS  
ATT&CK: [T1686.001](https://attack.mitre.org/techniques/T1686/001/), [detail page](../../techniques/defense-impairment.md#t1686001)

- `AN1188` Analytic 1188, IaaS
  Creation, deletion, or modification of security groups and firewall rules in cloud control plane logs that expand access to cloud resources beyond expected baselines. Defender view: unexpected ingress/egress rules permitting 0.0.0.0/0 or opening atypical ports, often correlated with privileged role or API key activity.
  - *Log sources:* `AWS:CloudTrail (Ingress rule creation or modification for security group)`; `AWS:CloudTrail (Removal of restrictive egress rules from a security group)`
  - *Tune:* `AllowedIPRanges`: Whitelist approved IP ranges; detect unexpected addition of 0.0.0.0/0 or untrusted CIDRs.; `PortScope` — Define expected ports for services; flag additions outside this range (e.g., SSH/RDP open to all).; `RoleContext` — Tune alerts based on whether changes are made by break-glass or admin roles versus automation accounts.; `TimeWindow` — Correlate rule changes with subsequent suspicious network activity to reduce false positives.

---

### T1686.002: Network Device Firewall
<a id="t1686002"></a>

Detection strategy: Unauthorized Network Firewall Rule Modification (T1562.013) (`DET0306`)  
Platforms: Network Devices  
ATT&CK: [T1686.002](https://attack.mitre.org/techniques/T1686/002/), [detail page](../../techniques/defense-impairment.md#t1686002)

- `AN0855` Analytic 0855, Network Devices
  Defender observes configuration changes on firewall/network appliance involving rule creation, modification, or deletion from abnormal management IPs or non-console channels (e.g., remote CLI, API). These are often correlated with a spike in previously blocked outbound traffic, unexpected allow-all rules, or bulk rule deletions. Behavior often follows unauthorized login, privilege escalation, or API abuse.
  - *Log sources:* `networkdevice:Firewall (update_rule: Access control or NAT rule modified or disabled outside maintenance window)`; `networkdevice:Firewall (Login from untrusted IP, or new admin account accessing firewall console/API)`; `networkdevice:Firewall (Audit trail or CLI/API access indicating commands like no access-list, delete rule-set, clear config)`; `NSM:Flow (Outbound traffic spike through formerly blocked ports/subnets following config change)`
  - *Tune:* `TrustedAdminIPs`: Allowlisted IPs/subnets where administrative access is expected (e.g., jump box, VPN mgmt); `ConfigChangeWindow` — Expected maintenance window (e.g., 02:00-04:00 UTC) to filter benign changes; `RuleScopeThreshold` — Number of rules affected or port ranges modified to determine severity; `NewUserPrivilegeThreshold` — Flag new users making changes without observed privilege elevation path

---

### T1688: Safe Mode Boot
<a id="t1688"></a>

Detection strategy: Detection Strategy for Safe Mode Boot Abuse (`DET0116`)  
Platforms: Windows  
ATT&CK: [T1688](https://attack.mitre.org/techniques/T1688/), [detail page](../../techniques/defense-impairment.md#t1688)

- `AN0323` Analytic 0323, Windows
  Abuse of safe mode via BCD modification, boot configuration utilities (bcdedit.exe, bootcfg.exe), and registry persistence under SafeBoot keys. Defender view: suspicious boot configuration changes correlated with registry edits that enable adversary persistence or disable defenses.
  - *Log sources:* `WinEventLog:Security (EventCode=4688)`; `WinEventLog:Sysmon (EventCode=13, 14)`; `WinEventLog:Sysmon (EventCode=12)`
  - *Tune:* `SafeBootRegistryPaths`: Customize monitored registry paths for safe mode service additions.; `AllowedAdminTools` — Whitelist legitimate administrative use of bcdedit/bootcfg for troubleshooting.; `TimeWindow` — Correlate registry modifications and boot configuration commands within a short timeframe.

---

### T1689: Downgrade Attack
<a id="t1689"></a>

Detection strategy: Detecting Downgrade Attacks (`DET0350`)  
Platforms: Linux, Windows, macOS  
ATT&CK: [T1689](https://attack.mitre.org/techniques/T1689/), [detail page](../../techniques/defense-impairment.md#t1689)

- `AN0995` Analytic 0995, Windows
  Detection of processes launching downgraded PowerShell versions (e.g., v2) or other legacy binaries that lack logging or security features. Correlates command-line arguments, process metadata, and version fields. Monitors registry changes to Defender or HVCI keys that could indicate intentional downgrades.
  - *Log sources:* `WinEventLog:Sysmon (EventCode=1)`; `WinEventLog:Security (EventCode=4657)`
  - *Tune:* `AllowedInterpreterVersions`: Defines which versions of interpreters like PowerShell are permitted in the environment.; `RegistryDefenderKeys` — Specific registry paths for monitoring Defender/HVCI configurations that may vary by Windows version.
- `AN0996` Analytic 0996, Linux
  Monitors execution of older or legacy interpreters (e.g., python2, bash with restricted history logging), downgrade of TLS/SSL configurations, or forced fallback to unencrypted protocols. Detects suspicious reconfiguration of kernel modules or boot loaders to reduce integrity controls.
  - *Log sources:* `auditd:SYSCALL (execve: Execution of downgraded interpreters such as python2 or forced fallback commands)`; `linux:syslog (Kernel or daemon warnings of downgraded TLS or cryptographic settings)`
  - *Tune:* `AllowedCryptoProtocols`: List of TLS/SSL versions approved for use; alerts triggered if older protocols (e.g., TLS 1.0) are used.
- `AN0997` Analytic 0997, macOS
  Detection of execution of legacy scripting runtimes (e.g., older versions of Python, Bash, or PowerShell Core) lacking auditing. Monitoring for changes to EFI or system boot files indicative of downgrade-based persistence or bypass of integrity features.
  - *Log sources:* `macos:unifiedlog (Execution of older or non-standard interpreters)`; `macos:unifiedlog (Modifications or writes to EFI system partition for downgraded bootloaders)`
  - *Tune:* `ApprovedInterpreterVersions`: Defines the minimal version of interpreters expected; older versions flagged as downgrade attempts.

---

### T1690: Prevent Command History Logging
<a id="t1690"></a>

Detection strategy: Detection Strategy for Impair Defenses via Impair Command History Logging across OS platforms. (`DET0563`)  
Platforms: ESXi, Linux, Network Devices, Windows, macOS  
ATT&CK: [T1690](https://attack.mitre.org/techniques/T1690/), [detail page](../../techniques/defense-impairment.md#t1690)

- `AN1555` Analytic 1555, Linux
  Detection of environment variable tampering (HISTFILE, HISTCONTROL, HISTFILESIZE) and absence of expected bash history writes. Correlation of unset or zeroed history variables with active shell sessions is indicative of adversarial evasion.
  - *Log sources:* `auditd:SYSCALL (execve calls modifying HISTFILE or HISTCONTROL via unset/export)`; `linux:osquery (processes modifying environment variables related to history logging)`
  - *Tune:* `MonitoredUsers`: Specific accounts or groups where history logging must always be enforced.; `TimeWindow` — Correlation period to detect unset/export of history variables during active shells.
- `AN1556` Analytic 1556, macOS
  Detection of bash/zsh history suppression via HISTFILE/HISTCONTROL manipulation and absence of ~/.bash_history updates. Observing environment variable changes tied to terminal processes is a strong indicator.
  - *Log sources:* `macos:unifiedlog (Set or unset HIST* variables in shell environment)`
  - *Tune:* `ShellProfiles`: Different shells (bash, zsh, fish) may require customized monitoring for history tampering.
- `AN1557` Analytic 1557, Windows
  Detection of PowerShell history suppression using Set-PSReadLineOption with SaveNothing or altered HistorySavePath. Correlating these options with PowerShell usage highlights adversarial evasion attempts.
  - *Log sources:* `WinEventLog:PowerShell (EventCode=4103, 4104, 4105, 4106)`; `WinEventLog:Sysmon (EventCode=1)`
  - *Tune:* `AllowedPaths`: List of acceptable PowerShell history save paths for baseline comparison.
- `AN1558` Analytic 1558, ESXi
  Detection of unset HISTFILE or modified history variables in ESXi shell sessions. Correlation of suspicious shell sessions with no recorded commands despite active usage.
  - *Log sources:* `esxi:shell (unset HISTFILE or HISTFILESIZE modifications)`
  - *Tune:* `AdminSessions`: Differentiate root/admin shell sessions from adversarial misuse of ESXi shell.
- `AN1559` Analytic 1559, Network Devices
  Detection of CLI commands that disable history logging such as 'no logging'. Anomalous lack of new commands in session logs while activity persists is a strong signal.
  - *Log sources:* `networkdevice:cli (Commands like 'no logging' or equivalents that disable session history)`
  - *Tune:* `DeviceVendors`: Command syntax differs across Cisco, Juniper, Fortinet, etc., requiring vendor-aware tuning.

---
