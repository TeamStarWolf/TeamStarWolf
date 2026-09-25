# Persistence — Detection Strategies

> MITRE ATT&CK detection strategies and analytics (v18.1) for techniques whose primary tactic is **Persistence**. Each analytic lists the **log sources / channels** it needs, the **detection logic**, and the **tunable elements** to adapt it to your environment. Authoritative source: the ATT&CK detection-strategy model in the Enterprise STIX.

See also: [all detection strategies index](/detections/strategies/README.md) · [Technique Detection Library](../TECHNIQUE_DETECTION_LIBRARY.md) (ready-to-run SIEM queries) · [Data Components & Log Sources](../../ATTACK_DATA_COMPONENTS.md) · [Technique Detail Pages](../../techniques/README.md)

---

### T1037 — Boot or Logon Initialization Scripts
<a id="t1037"></a>

**Detection strategy:** Boot or Logon Initialization Scripts Detection Strategy (`DET0112`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1037](https://attack.mitre.org/techniques/T1037/) · [detail page](../../techniques/persistence.md#t1037)

- **`AN0311` Analytic 0311** · Windows
  Monitoring modification and execution of user or system logon scripts such as in registry Run keys or startup folders.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Security` (EventCode=4657); `WinEventLog:TaskScheduler` (EventCode=106)
  - *Tune:* `TargetObject` — Registry path that may vary by user or policy configuration.; `ParentProcessName` — Can be tuned to known parent processes to reduce false positives.; `TimeWindow` — Logon activity clustered during specific user shifts.
- **`AN0312` Analytic 0312** · Linux
  Detection of changes or execution of shell initialization scripts like .bashrc, .profile, or /etc/profile for persistence.
  - *Log sources:* `auditd:SYSCALL` (EXECVE); `auditd:PATH` (PATH); `linux:osquery` (file_events)
  - *Tune:* `FilePath` — Initialization script path that can differ across user and system profiles.; `UserContext` — User-level vs root-level configuration.; `TimeWindow` — Useful to correlate between file change and subsequent execution.
- **`AN0313` Analytic 0313** · macOS
  Monitoring for modification and execution of login hook scripts or LaunchAgents/LaunchDaemons used for persistence.
  - *Log sources:* `macos:unifiedlog` (log); `fs:fsusage` (file); `macos:osquery` (launchd)
  - *Tune:* `Label` — LaunchAgent or LaunchDaemon label name, often environment-specific.; `ProgramArguments` — Arguments passed to scripts, which may need tuning by environment.; `UserContext` — Distinguish between user login and system startup agents.
- **`AN0314` Analytic 0314** · ESXi
  Detection of modification to ESXi rc.local.d or rc scripts that are used to execute on boot.
  - *Log sources:* `esxi:vmkernel` (boot); `esxi:hostd` (boot)
  - *Tune:* `ScriptName` — Script path or name may vary across hypervisor versions.; `LogSeverity` — Log verbosity settings may alter visibility of activity.
- **`AN0315` Analytic 0315** · Network Devices
  Detection of changes to device startup-config files that include boot scripts or scheduled execution routines.
  - *Log sources:* `networkdevice:syslog` (config)
  - *Tune:* `Interface` — Affected interface or subsystem; varies per device.; `CommandPattern` — Patterns of authorized config changes differ by vendor or policy.

---

### T1037.001 — Logon Script (Windows)
<a id="t1037001"></a>

**Detection strategy:** Detect Logon Script Modifications and Execution (`DET0072`)  
**Platforms:** Windows  
**ATT&CK:** [T1037.001](https://attack.mitre.org/techniques/T1037/001/) · [detail page](../../techniques/persistence.md#t1037001)

- **`AN0199` Analytic 0199** · Windows
  Detects adversary use of logon script configuration via Group Policy or user object attributes, followed by script execution post-authentication. Behavior includes modification of script path or file, then process execution under user logon context.
  - *Log sources:* `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:System` (EventCode=1502, 1503); `WinEventLog:Security` (EventCode=4624, 4648); `WinEventLog:Security` (EventCode=4688)
  - *Tune:* `script_path_keywords` — Defenders may tune for known script locations such as NETLOGON, SYSVOL, or \domain\sysvol\*.bat/.ps1; `execution_time_window` — May be scoped to user logon hours or first X minutes post-authentication; `user_context` — Organizations may focus on specific users/groups with high privilege or remote access

---

### T1037.002 — Login Hook
<a id="t1037002"></a>

**Detection strategy:** Detection Strategy for Login Hook Persistence on macOS (`DET0244`)  
**Platforms:** macOS  
**ATT&CK:** [T1037.002](https://attack.mitre.org/techniques/T1037/002/) · [detail page](../../techniques/persistence.md#t1037002)

- **`AN0682` Analytic 0682** · macOS
  Detection of persistent login hooks configured via defaults or plist modifications that result in execution of scripts or binaries at user login, breaking expected parent-child process lineage.
  - *Log sources:* `macos:unifiedlog` (loginwindow or tccd-related entries); `fs:plist` (/var/root/Library/Preferences/com.apple.loginwindow.plist)
  - *Tune:* `login_hook_path` — Path of script or binary assigned to login hook; may vary by environment; `user_context` — Login hook may be applied to specific user accounts; tune by privilege level; `time_window` — Correlate plist file modification to execution within a short timeframe; `parent_process_name` — Expected parent process (e.g., loginwindow); anomalies can indicate masquerading

---

### T1037.003 — Network Logon Script
<a id="t1037003"></a>

**Detection strategy:** Detect Network Logon Script Abuse via Multi-Event Correlation on Windows (`DET0367`)  
**Platforms:** Windows  
**ATT&CK:** [T1037.003](https://attack.mitre.org/techniques/T1037/003/) · [detail page](../../techniques/persistence.md#t1037003)

- **`AN1034` Analytic 1034** · Windows
  Correlates Group Policy updates that configure network logon scripts with subsequent remote file execution behaviors triggered by user logons to identify potential persistence or execution chains tied to adversarial manipulation of logon scripts.
  - *Log sources:* `WinEventLog:Security` (EventCode=5145); `WinEventLog:Security` (EventCode=4688); `WinEventLog:System` (EventCode=4016, 5312)
  - *Tune:* `TargetObject` — Path to network-based script execution; tuning required for environment-specific network shares.; `ParentProcessName` — Initial execution process that launches the script; may vary depending on script language or user context.; `TimeWindow` — Acceptable time window to correlate Group Policy update with script execution (e.g., 2–10 minutes).; `UserContext` — Account initiating execution; useful for filtering known administrative activity.

---

### T1037.004 — RC Scripts
<a id="t1037004"></a>

**Detection strategy:** Detection Strategy for Boot or Logon Initialization Scripts: RC Scripts (`DET0237`)  
**Platforms:** ESXi, Linux, Network Devices, macOS  
**ATT&CK:** [T1037.004](https://attack.mitre.org/techniques/T1037/004/) · [detail page](../../techniques/persistence.md#t1037004)

- **`AN0658` Analytic 0658** · Linux
  Detection of modified or newly created /etc/rc.local or /etc/init.d scripts followed by suspicious execution during system startup.
  - *Log sources:* `auditd:SYSCALL` (execve); `linux:syslog` (boot logs)
  - *Tune:* `script_path` — Specific path of init script (e.g., /etc/rc.local, /etc/init.d/*) may vary by distribution; `user_context` — Root vs. non-root modification context depending on configuration; `time_window` — Tuning window for script creation or modification relative to system boot
- **`AN0659` Analytic 0659** · macOS
  Detection of edits or additions to /etc/rc.common, /Library/StartupItems, or /System/Library/StartupItems and associated script execution during login or reboot.
  - *Log sources:* `macos:unifiedlog` (process events); `fs:fsusage` (file activity)
  - *Tune:* `script_name` — Name of script or LaunchDaemon plist is tunable across environments; `event_interval` — Time window between modification and reboot/login; `file_permission` — Permissions on modified RC files can vary between systems
- **`AN0660` Analytic 0660** · ESXi
  Detection of changes to /etc/rc.local.d/local.sh or rc.local during post-boot script execution with abnormal commands or additions.
  - *Log sources:* `esxi:syslog` (boot logs); `esxi:shell` (admin command usage)
  - *Tune:* `script_section` — Tunable script section edited by adversary (beginning, end, inline); `command_type` — Nature of embedded command or payload affects detection scope; `execution_trigger` — Boot vs. manual script re-invocation
- **`AN0661` Analytic 0661** · Network Devices
  Detection of modified boot-time configuration scripts that persist malicious CLI commands across reboots.
  - *Log sources:* `networkdevice:syslog` (startup-config); `networkdevice:syslog` (system boot logs)
  - *Tune:* `firmware_family` — Device type or OS determines specific init script location; `config_line_pattern` — Regex or pattern matching approach to detect suspicious CLI; `reboot_time_window` — Time window between config change and first boot post-modification

---

### T1037.005 — Startup Items
<a id="t1037005"></a>

**Detection strategy:** Detect Modification of macOS Startup Items (`DET0429`)  
**Platforms:** macOS  
**ATT&CK:** [T1037.005](https://attack.mitre.org/techniques/T1037/005/) · [detail page](../../techniques/persistence.md#t1037005)

- **`AN1197` Analytic 1197** · macOS
  Detects the modification or addition of Launch Agents or Startup Items to establish persistence. Adversaries may write plist or executable files to ~/Library/LaunchAgents/, /Library/StartupItems/, or similar directories and configure them to run at user or system boot. Detection requires correlating file creation or modification events with subsequent user logon or boot-time process execution.
  - *Log sources:* `macos:unifiedlog` (launchservices or loginwindow events); `macos:fsevents` (/Library/StartupItems/, ~/Library/LaunchAgents/)
  - *Tune:* `directory_path` — Specific paths to monitor may differ across macOS versions or enterprise baselines.; `user_context` — Different users may have unique LaunchAgents folders—tuning may be required.; `time_window` — The correlation time between file creation and process execution may need to be adjusted for boot persistence.; `process_name` — Specific startup binaries (e.g., bash, osascript) may vary across implementations.

---

### T1098 — Account Manipulation
<a id="t1098"></a>

**Detection strategy:** Account Manipulation Behavior Chain Detection (`DET0096`)  
**Platforms:** ESXi, Identity Provider, Linux, SaaS, Windows, macOS  
**ATT&CK:** [T1098](https://attack.mitre.org/techniques/T1098/) · [detail page](../../techniques/persistence.md#t1098)

- **`AN0265` Analytic 0265** · Windows
  Account attribute changes (e.g., password set, group membership, servicePrincipalName, logon hours) correlated with unusual process lineage or timing, indicating privilege escalation or persistence via valid accounts.
  - *Log sources:* `WinEventLog:Security` (EventCode=4738, 4728, 4670); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `TimeWindow` — Time between suspicious process and account change (e.g., 5m).; `HighPrivilegeGroupList` — Customize group list (e.g., Domain Admins, Enterprise Admins) to monitor.; `SubjectTargetMismatch` — Flag if account modifier != modified user (potential hijack).
- **`AN0266` Analytic 0266** · Linux
  Use of native tools or scripting (e.g., `usermod`, `passwd`, `groupmod`) to escalate permissions or persist access on existing users, correlated with login or process events.
  - *Log sources:* `auditd:SYSCALL` (usermod, groupmod, passwd); `auditd:PATH` (/etc/passwd or /etc/group file write)
  - *Tune:* `SudoPath` — Common sudo or privilege escalation paths (e.g., `/usr/bin/passwd`).; `ModifiedShellList` — Detect if user shell is changed to unusual one (e.g., /bin/sh -> /bin/bash).
- **`AN0267` Analytic 0267** · macOS
  Modifications to user accounts via `dscl`, `pwpolicy`, or System Preferences CLI (`sysadminctl`) that alter user groups, enable root, or bypass MDM restrictions.
  - *Log sources:* `macos:unifiedlog` (com.apple.accountsd, com.apple.opendirectoryd)
  - *Tune:* `ModifiedUserList` — Track known non-system user UIDs or service accounts.; `GroupMembershipChanges` — List of sensitive groups (admin, _developer, _analyticsd).
- **`AN0268` Analytic 0268** · Identity Provider
  Modifications to SSO/SAML user attributes (e.g., `isAdmin`, `role`, MFA bypass, App assignments) often through CLI, API, or rogue IdP apps.
  - *Log sources:* `saas:okta` (User Attribute Modified / Role Assignment Changed)
  - *Tune:* `RoleAssignmentBaseline` — Expected user-role pairings per app or org unit.; `APIUsageContext` — Caller identity or IP address ranges for identity admin actions.
- **`AN0269` Analytic 0269** · ESXi
  Addition of new users or changes to role permissions (e.g., ReadOnly -> Admin) via API or vSphere Client, particularly from non-jumpbox IPs.
  - *Log sources:* `esxi:vpxa` (vim.SessionManager.login / vim.AccountManager.createUser)
  - *Tune:* `VMAdminAccountName` — Expected account name patterns for ESXi/vCenter admins.; `NetworkAccessLocation` — Expected IPs/subnets for legitimate ESXi access.
- **`AN0270` Analytic 0270** · SaaS
  Role escalation (e.g., Editor → Owner) in cloud collaboration tools (Google Workspace, O365) or file sharing apps to maintain elevated access.
  - *Log sources:* `m365:unified` (Admin Activity > Role Change or Sharing Change)
  - *Tune:* `SharingSensitivityLabel` — Threshold for labeling sensitive document access escalation.; `CrossOrgChanges` — Track changes made across organizational boundaries (e.g., guest users).

---

### T1098.001 — Additional Cloud Credentials
<a id="t1098001"></a>

**Detection strategy:** Detection Strategy for Additional Cloud Credentials in IaaS/IdP/SaaS (`DET0531`)  
**Platforms:** IaaS, Identity Provider, SaaS  
**ATT&CK:** [T1098.001](https://attack.mitre.org/techniques/T1098/001/) · [detail page](../../techniques/persistence.md#t1098001)

- **`AN1469` Analytic 1469** · Identity Provider
  Addition of credentials (keys, app passwords, x.509 certs) to existing cloud accounts, service principals, or OAuth apps via portal or API by non-standard identities or IP ranges.
  - *Log sources:* `azure:audit` (Add service principal credentials, app password added, app role assignment)
  - *Tune:* `MFABypassMechanism` — App password or legacy auth activity bypassing MFA policies.; `SourceIPAllowlist` — Expected IPs allowed to perform admin identity operations.; `ApplicationCredentialType` — Track types like `client_secret`, `certificate`, `password`, `federated`.
- **`AN1470` Analytic 1470** · IaaS
  Cloud API usage to create/import SSH keys or generate new access keys (CreateAccessKey, ImportKeyPair, CreateLoginProfile) from non-console access or unusual principals.
  - *Log sources:* `AWS:CloudTrail` (CreateAccessKey, ImportKeyPair, CreateLoginProfile, CreateKeyPair); `gcp:audit` (iam.serviceAccounts.keys.create, os-login.sshPublicKeys.add)
  - *Tune:* `CallerIdentityContext` — Track root, federated identities, and STS tokens separately.; `NewCredentialUsageWindow` — Time between key creation and first use (default: 5 min).; `IAMRoleBaseline` — Expected services/accounts allowed to create keys.
- **`AN1471` Analytic 1471** · SaaS
  Credential-related configuration changes in productivity apps, such as API key creation in Google Workspace, app tokens in Slack, or user-level OAuth credentials in M365.
  - *Log sources:* `gcp:audit` (API Key Created, OAuth Client Registered); `m365:unified` (Set-Mailbox, Set-AppPassword, Add-MailboxPermission)
  - *Tune:* `OAuthClientRedirectURIBaseline` — Detect suspicious redirect URI mismatches in new clients.; `TokenScopeSensitivity` — Highlight credentials granting excessive read/write org-wide.

---

### T1098.002 — Additional Email Delegate Permissions
<a id="t1098002"></a>

**Detection strategy:** Detection Strategy for Addition of Email Delegate Permissions (`DET0373`)  
**Platforms:** Office Suite, Windows  
**ATT&CK:** [T1098.002](https://attack.mitre.org/techniques/T1098/002/) · [detail page](../../techniques/persistence.md#t1098002)

- **`AN1051` Analytic 1051** · Office Suite
  Detection of anomalous or unauthorized mailbox delegation activity (e.g., Add-MailboxPermission, Default/Anonymous mailbox permissions, Gmail delegation setup).
  - *Log sources:* `m365:unified` (Add-MailboxPermission, UpdateFolderPermissions)
  - *Tune:* `DelegatePermissionLevel` — Threshold for unexpected delegate roles such as FullAccess or SendAs.; `FolderTargetScope` — Mailbox folder targeted by delegation (Inbox, Root, Calendar, etc.).; `DelegatorToDelegatePairing` — Pairings of delegate and delegator users that are expected.; `MailflowAnomalyThreshold` — Spike in outbound mail after delegate addition, used to catch phishing or mass exfil.
- **`AN1052` Analytic 1052** · Windows
  Execution of PowerShell commands that modify mailbox permissions using Exchange cmdlets (e.g., Add-MailboxPermission), often tied to BEC or post-compromise persistence.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `m365:unified` (PowerShell: Add-MailboxPermission)
  - *Tune:* `PowerShellCmdletFilter` — Exchange cmdlets to include or exclude based on scope (e.g., Add-MailboxPermission, Set-MailboxFolderPermission).; `ExecutionParent` — Flag suspicious script or interactive shell launch by non-admins.; `TimeWindow` — Window in which Add-MailboxPermission is followed by anomalous usage (e.g., SendAs events).

---

### T1098.003 — Additional Cloud Roles
<a id="t1098003"></a>

**Detection strategy:** Detection Strategy for Role Addition to Cloud Accounts (`DET0277`)  
**Platforms:** IaaS, Identity Provider, Office Suite  
**ATT&CK:** [T1098.003](https://attack.mitre.org/techniques/T1098/003/) · [detail page](../../techniques/persistence.md#t1098003)

- **`AN0771` Analytic 0771** · IaaS
  Detection of new IAM roles or policies attached to a user/service in AWS/GCP/Azure outside normal patterns or hours, often following account compromise.
  - *Log sources:* `AWS:CloudTrail` (AttachUserPolicy, CreatePolicyVersion, PutRolePolicy)
  - *Tune:* `RoleScope` — IAM Role type or privilege level assigned (e.g., Admin, Billing, Viewer); `UserContext` — User, service account, or external federated identity context performing the action; `PolicyChangeTimeWindow` — How quickly multiple roles or policies are added after initial access; `ExternalRoleOrigin` — Cross-account roles from outside trusted tenant list
- **`AN0772` Analytic 0772** · Identity Provider
  Behavioral chain of a user being granted elevated privileges or roles in Entra ID or Okta following suspicious login or account creation activity.
  - *Log sources:* `m365:audit` (Add member to role, Add app role assignment)
  - *Tune:* `AdminRoleThreshold` — Number of accounts allowed to hold sensitive roles like Global Admin; `RoleAssignmentMethod` — Mechanism by which role was added (PowerShell, API, UI); `GrantContext` — Expected user-to-role mapping defined by org policy
- **`AN0773` Analytic 0773** · Office Suite
  Detection of new admin or role assignment actions within Microsoft 365/O365 environments to elevate access for persistence or lateral movement.
  - *Log sources:* `m365:unified` (Add member to role, Set-Mailbox)
  - *Tune:* `OfficeRoleType` — Admin role type or application role granted; `TimeWindow` — Time between initial login and privilege change; `ActionOrigin` — Was the role assignment local or via federated SSO account

---

### T1098.004 — SSH Authorized Keys
<a id="t1098004"></a>

**Detection strategy:** Detection Strategy for SSH Key Injection in Authorized Keys (`DET0126`)  
**Platforms:** ESXi, IaaS, Linux, Network Devices, macOS  
**ATT&CK:** [T1098.004](https://attack.mitre.org/techniques/T1098/004/) · [detail page](../../techniques/persistence.md#t1098004)

- **`AN0350` Analytic 0350** · Linux
  Adversary attempts to gain persistence by modifying ~/.ssh/authorized_keys via shell, text editor, echo or redirected output.
  - *Log sources:* `auditd:SYSCALL` (write | PATH=/home/*/.ssh/authorized_keys); `auditd:SYSCALL` (execve)
  - *Tune:* `TimeWindow` — Temporal window to correlate file writes and suspicious process launches (e.g., <60s); `UserContext` — Expected user-to-process correlation (e.g., root writing to non-root authorized_keys); `TargetPath` — Custom SSH path or user home variation (e.g., /etc/skel/.ssh/)
- **`AN0351` Analytic 0351** · macOS
  Insertion of public keys into authorized_keys using bash/zsh or editor tools, correlated with suspicious process ancestry.
  - *Log sources:* `macos:unifiedlog` (process: exec + filewrite: ~/.ssh/authorized_keys); `macos:auth` (~/.ssh/authorized_keys)
  - *Tune:* `ParentProcess` — Track unusual parent process writing to SSH config (e.g., curl -> bash); `InteractiveSessionFlag` — Flag whether shell session was interactive (normal) or spawned remotely (potential abuse)
- **`AN0352` Analytic 0352** · IaaS
  Abuse of cloud metadata APIs or CLI to push SSH public keys to authorized_keys of virtual machines.
  - *Log sources:* `gcp:audit` (compute.instances.setMetadata)
  - *Tune:* `MetadataFieldName` — Custom metadata field (e.g., ssh-keys or custom-key); `AccountType` — Was it an admin, service principal, or automation user initiating?; `TargetRoleEscalation` — Privilege level of the VM account receiving the key
- **`AN0353` Analytic 0353** · ESXi
  Direct modification of /etc/ssh/keys-<user>/authorized_keys or enabling SSH in sshd_config to support public key auth.
  - *Log sources:* `esxi:shell` (file write or edit)
  - *Tune:* `SSHConfigPath` — Could be modified SSH path in hypervisor; `ESXiShellActivity` — Whether shell was enabled beforehand via DCUI or API
- **`AN0354` Analytic 0354** · Network Devices
  Use of command-line like `ip ssh pubkey-chain` to bind SSH keys to privileged accounts on routers or switches.
  - *Log sources:* `networkdevice:cli` (ip ssh pubkey-chain)
  - *Tune:* `CLIUserRole` — Was the role allowed to push persistent config changes?; `DeviceModel` — Variations in syntax or log behavior across device OS

---

### T1098.005 — Device Registration
<a id="t1098005"></a>

**Detection strategy:** Suspicious Device Registration via Entra ID or MFA Platform (`DET0036`)  
**Platforms:** Identity Provider, Windows  
**ATT&CK:** [T1098.005](https://attack.mitre.org/techniques/T1098/005/) · [detail page](../../techniques/persistence.md#t1098005)

- **`AN0103` Analytic 0103** · Identity Provider
  Adversary registers new devices to compromised user accounts to bypass MFA or conditional access policies via Azure Entra ID, Okta, or Duo self-enrollment portals.
  - *Log sources:* `azure:audit` (Operation IN ("Add device", "Add registered users to device", "Add registered owner to device")); `ApplicationLog:EntraIDPortal` (DeviceRegistration events); `azure:audit` (New device object creation)
  - *Tune:* `ActorUserPrincipalName` — Define expected admin users to exclude known enrollment behavior; `IP Address` — Scope internal vs. external device enrollment sources; `TimeWindow` — Adjust for expected hours of legitimate self-enrollment
- **`AN0104` Analytic 0104** · Windows
  Adversary registers a Windows device to Entra ID or bypasses conditional access by adding device via Intune registration pipeline using stolen credentials.
  - *Log sources:* `WinEventLog:Security` (Device Object Creation); `ApplicationLog:Intune/MDM Logs` (Enrollment events (e.g., MDMDeviceRegistration))
  - *Tune:* `DeviceNamePattern` — Adjust pattern matching logic for unusual or non-corporate device names; `UserContext` — Correlate with prior logon location or device usage behavior; `EnrollmentMethod` — Distinguish between MDM vs manual onboarding vs automated scripts

---

### T1098.006 — Additional Container Cluster Roles
<a id="t1098006"></a>

**Detection strategy:** Suspicious RoleBinding or ClusterRoleBinding Assignment in Kubernetes (`DET0572`)  
**Platforms:** Containers  
**ATT&CK:** [T1098.006](https://attack.mitre.org/techniques/T1098/006/) · [detail page](../../techniques/persistence.md#t1098006)

- **`AN1579` Analytic 1579** · Containers
  Detects assignment of high-privilege roles to user or service accounts via Kubernetes RoleBinding or ClusterRoleBinding objects, especially outside of CI/CD automation or from unknown IPs.
  - *Log sources:* `kubernetes:audit` (create or update events for RoleBinding or ClusterRoleBinding objects)
  - *Tune:* `UserAgent` — Filter expected sources of automated role assignment (e.g., CI/CD tooling); `RoleName` — Scope to privileged roles like cluster-admin, edit, admin; `TimeWindow` — Detect after-hours or irregular-time assignments; `UserContext` — Define known service accounts and privileged operators to reduce noise

---

### T1098.007 — Additional Local or Domain Groups
<a id="t1098007"></a>

**Detection strategy:** Suspicious Addition to Local or Domain Groups (`DET0310`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1098.007](https://attack.mitre.org/techniques/T1098/007/) · [detail page](../../techniques/persistence.md#t1098007)

- **`AN0865` Analytic 0865** · Windows
  Detects unauthorized additions of users or machine accounts to privileged local or domain groups (e.g., Administrators, Remote Desktop Users).
  - *Log sources:* `WinEventLog:Security` (EventCode=4728, 4729, 4732, 4733, 4756, 4757)
  - *Tune:* `TargetGroup` — Set to detect high-privileged groups like 'Administrators', 'Domain Admins', or 'Remote Desktop Users'; `TimeWindow` — Restrict detections to business hours or approved maintenance windows; `UserContext` — Filter out known automated processes or provisioning systems
- **`AN0866` Analytic 0866** · Linux
  Detects unexpected use of usermod, gpasswd, or direct modification of /etc/group to elevate user group membership.
  - *Log sources:* `auditd:SYSCALL` (SYSCALL for usermod or /etc/group file modification)
  - *Tune:* `GroupName` — Focus on 'sudo', 'wheel', or custom high-privilege groups; `UserContext` — Account that initiated the change (e.g., service account or unrecognized user); `TimeWindow` — Detect elevation outside change windows
- **`AN0867` Analytic 0867** · macOS
  Detects use of `dseditgroup` or `dscl` to add users to privileged macOS groups (e.g., admin).
  - *Log sources:* `macos:unifiedlog` (Process execution or directory service changes)
  - *Tune:* `GroupName` — Focus on 'admin' or 'com.apple.access_ssh'; `UserContext` — Detect unknown or transient users making group changes; `TimeWindow` — Detect group modifications at suspicious times

---

### T1133 — External Remote Services
<a id="t1133"></a>

**Detection strategy:** Behavior-chain detection for T1133 External Remote Services across Windows, Linux, macOS, Containers (`DET0354`)  
**Platforms:** Containers, Linux, Windows, macOS  
**ATT&CK:** [T1133](https://attack.mitre.org/techniques/T1133/) · [detail page](../../techniques/persistence.md#t1133)

- **`AN1004` Analytic 1004** · Windows
  Unusual or unauthorized external remote access attempts (e.g., RDP, VPN, Citrix) → repeated failed logins followed by a successful session from uncommon geolocations or outside business hours → subsequent internal lateral movement or data exfiltration activities.
  - *Log sources:* `WinEventLog:Security` (EventCode=4776, 4625); `WinEventLog:Application` (VPN, Citrix, or remote access gateway logs showing external IP addresses); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `BusinessHours` — Normal business hours for logon activity.; `KnownRemoteIPs` — List of approved external IPs or VPN endpoints.; `FailedLogonThreshold` — Number of failed logons before raising suspicion (e.g., >5).; `GeoIPWhitelist` — Geographic regions allowed for remote access.; `TimeWindow` — Time window to correlate failed attempts and success (e.g., 15m).
- **`AN1005` Analytic 1005** · Linux
  Repeated SSH, VPN, or RDP gateway authentication attempts from external IPs → subsequent successful logon → remote shell or lateral movement activity (e.g., scp/sftp).
  - *Log sources:* `auditd:SYSCALL` (ssh logins or execve of remote commands); `NSM:Connections` (Failed password or accepted password for SSH users); `NSM:Flow` (connection: Inbound connections to SSH or VPN ports)
  - *Tune:* `KnownSSHClients` — Legitimate IPs or client fingerprints for SSH/VPN.; `FailedLogonThreshold` — Number of failed SSH logins to trigger alert.; `TimeWindow` — Correlation window for failed attempts and success.
- **`AN1006` Analytic 1006** · macOS
  Unexpected inbound or outbound VNC/SSH/Screen Sharing connections from external sources → repeated failed logins followed by success → remote interactive sessions or abnormal file transfers.
  - *Log sources:* `macos:unifiedlog` (Remote login (ssh) or screen sharing authentication attempts); `macos:unifiedlog` (Inbound connections to VNC/SSH ports); `PF:Logs` (External traffic to remote access services)
  - *Tune:* `KnownVNCServers` — List of approved VNC/SSH sources.; `TimeWindow` — Time correlation between failed attempts and success.
- **`AN1007` Analytic 1007** · Containers
  Connections to exposed container services (e.g., Docker API, Kubernetes API server) from unauthorized external IPs → abnormal container creation/start → lateral activity within cluster nodes.
  - *Log sources:* `ApplicationLog:API` (Docker/Kubernetes API access from external sources); `kubernetes:audit` (Unauthorized container creation or kubelet exec logs); `NSM:Flow` (External access to container ports (2375, 6443))
  - *Tune:* `AllowedCIDRs` — Approved external IP ranges for container APIs.; `TimeWindow` — Correlation window for API calls and container starts.

---

### T1136 — Create Account
<a id="t1136"></a>

**Detection strategy:** Detection Strategy for T1136 - Create Account across platforms (`DET0583`)  
**Platforms:** IaaS, Identity Provider, Linux, Windows, macOS  
**ATT&CK:** [T1136](https://attack.mitre.org/techniques/T1136/) · [detail page](../../techniques/persistence.md#t1136)

- **`AN1604` Analytic 1604** · Windows
  Adversary uses built-in OS tools or API calls to create local or domain accounts for persistence or lateral movement. Tools such as 'net user', PowerShell, or MMC snap-ins may be used. Detection focuses on Event ID 4720 paired with process lineage and user context.
  - *Log sources:* `WinEventLog:Security` (EventCode=4720); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `TimeWindow` — Correlation between Event ID 4720 and creating process may vary by environment and automation delays; `ParentProcessName` — Tools like net.exe or powershell.exe can be normal or malicious depending on user context; `UserContext` — System vs. administrator vs. low-privilege user context changes alert criticality
- **`AN1605` Analytic 1605** · Linux
  Adversary invokes 'useradd', 'adduser', or equivalent system commands or scripts to create local users. Detection focuses on command execution and audit trail of passwd/shadow file modifications.
  - *Log sources:* `auditd:SYSCALL` (useradd or adduser executed); `auditd:SYSCALL` (chmod/chown to /etc/passwd or /etc/shadow)
  - *Tune:* `BinaryPath` — Custom scripts or renamed binaries may evade simple path-based detection; `ExecutionTime` — Account creation outside maintenance windows may indicate compromise
- **`AN1606` Analytic 1606** · macOS
  Adversary creates new users using 'dscl' commands, GUI tools, or by modifying user plist files. Detection includes monitoring dscl invocation and user-related plist changes.
  - *Log sources:* `macos:unifiedlog` (dscl . -create); `macos:unifiedlog` (modification to /var/db/dslocal/nodes/Default/users/)
  - *Tune:* `UsernamePattern` — Attackers may use service-like names to hide malicious accounts; `ExecutionSource` — Accounts created via Terminal vs GUI vs remote session can affect confidence
- **`AN1607` Analytic 1607** · Identity Provider
  Adversary creates users via IAM/IdP API or portal (e.g., Azure AD, Okta). Detection involves monitoring API calls, admin action logs, and correlation with role assignments.
  - *Log sources:* `azure:audit` (Add user)
  - *Tune:* `AdminThreshold` — Trigger alert only when account is assigned privileged roles; `AutomationExemptions` — Exclude accounts from known automation processes or provisioning pipelines
- **`AN1608` Analytic 1608** · IaaS
  Account creation via cloud service APIs or CLI, often associated with key generation. Monitored via CloudTrail or equivalent audit logs.
  - *Log sources:* `AWS:CloudTrail` (CreateUser); `AWS:CloudTrail` (AttachUserPolicy)
  - *Tune:* `Region` — Alert on account creation outside expected geographies; `ServiceScope` — Filter on creation of users scoped to sensitive services

---

### T1136.001 — Local Account
<a id="t1136001"></a>

**Detection strategy:** T1136.001 Detection Strategy - Local Account Creation Across Platforms (`DET0447`)  
**Platforms:** Containers, ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1136.001](https://attack.mitre.org/techniques/T1136/001/) · [detail page](../../techniques/persistence.md#t1136001)

- **`AN1235` Analytic 1235** · Windows
  Adversary uses built-in tools like 'net user /add', PowerShell, or WMI to create a local user. Sequence: Account creation event (4720) follows process creation of a suspicious executable (e.g., powershell.exe or net.exe).
  - *Log sources:* `WinEventLog:Security` (EventCode=4720); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `ParentProcessName` — Attackers may use cmd.exe, wscript.exe, or renamed binaries to evade detection; `TimeWindow` — Define time threshold between process start and user creation event (e.g., 5s–2m); `UserContext` — Correlate if process runs under SYSTEM, Administrator, or untrusted account
- **`AN1236` Analytic 1236** · Linux
  Local user accounts are created via binaries like 'useradd', 'adduser', or by editing passwd/shadow. Behavior chain includes execution of user management binaries or modification of user database files.
  - *Log sources:* `auditd:SYSCALL` (useradd or adduser executed); `auditd:SYSCALL` (write operation on /etc/passwd or /etc/shadow)
  - *Tune:* `BinaryPath` — Account creation may be scripted via shell scripts, cron jobs, or remote shells; `ExecutionSource` — Flag if commands are issued from remote sessions (e.g., sshd)
- **`AN1237` Analytic 1237** · macOS
  Account creation using 'dscl -create' or via GUI tools. Detection involves command execution and file changes to the local directory services database.
  - *Log sources:* `macos:unifiedlog` (dscl -create); `macos:unifiedlog` (modification to /var/db/dslocal/nodes/Default/users/)
  - *Tune:* `UsernamePattern` — Accounts like 'svc*', 'backup*' may blend into legit naming patterns; `SessionOrigin` — Identify if dscl was run locally, via ARD, or Terminal.app
- **`AN1238` Analytic 1238** · ESXi
  Account created using esxcli commands. Sequence includes esxcli execution and successful modification to account DB.
  - *Log sources:* `esxi:vmkernel` (esxcli system account add)
  - *Tune:* `CommandOrigin` — Console sessions vs SSH vs vSphere CLI session may affect alert fidelity
- **`AN1239` Analytic 1239** · Containers
  Account created in a running container (e.g., via 'useradd' or by modifying /etc/passwd directly). Detectable via runtime telemetry (e.g., Falco or eBPF hooks).
  - *Log sources:* `ebpf:syscalls` (useradd or /etc/passwd modified inside container)
  - *Tune:* `ContainerContext` — Distinguish between ephemeral containers and long-lived service containers; `NamespaceScope` — Determine if account was added inside host, user, or PID namespace
- **`AN1240` Analytic 1240** · Network Devices
  Account created via CLI using 'username' command or REST API. Detectable through AAA logging or CLI history telemetry.
  - *Log sources:* `networkdevice:syslog` (username <user> privilege <level>)
  - *Tune:* `PrivilegeLevel` — Some devices allow unprivileged user creation—adjust based on role risk; `RemoteSessionFlag` — Creation via Telnet, SSH, or serial console affects detection priority

---

### T1136.002 — Domain Account
<a id="t1136002"></a>

**Detection strategy:** T1136.002 Detection Strategy - Domain Account Creation Across Platforms (`DET0003`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1136.002](https://attack.mitre.org/techniques/T1136/002/) · [detail page](../../techniques/persistence.md#t1136002)

- **`AN0006` Analytic 0006** · Windows
  Adversary uses built-in tools such as 'net user /add /domain' or PowerShell to create a domain user account. The behavior chain includes: (1) suspicious process execution on a domain controller followed by (2) user account creation event (Event ID 4720) on the same host.
  - *Log sources:* `WinEventLog:Security` (EventCode=4720); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `TimeWindow` — Detection triggers when Event ID 4720 follows a suspicious process within 2 minutes.; `ParentProcessName` — Allow filtering of known admin tools vs adversarial misuse (e.g., net.exe, powershell.exe).; `UserContext` — Filter accounts with domain admin privileges creating new users vs standard helpdesk roles.; `HostRole` — Restrict to only domain controller hosts to reduce noise from workstations.
- **`AN0007` Analytic 0007** · Linux
  Adversary with access to domain management tools (e.g., `realmd`, `samba-tool`, `ldapmodify`) creates a new domain user via command-line utilities. Behavior chain: LDAP command or script triggers → user entry added in AD via Kerberos/LDAP traffic.
  - *Log sources:* `auditd:SYSCALL` (execution of realmd, samba-tool, or ldapmodify with user-related arguments); `NSM:Flow` (TGS-REQ and AS-REQ seen for new user shortly after domain-modifying process)
  - *Tune:* `DomainToolUsed` — realmd, samba-tool, ldapmodify or custom script; `TrafficWindow` — Expected Kerberos traffic from new domain account within X minutes of command; `SessionType` — Script execution from interactive shell vs scheduled task
- **`AN0008` Analytic 0008** · macOS
  macOS clients joined to AD via LDAP may script account provisioning via `dsconfigad`, `dscl`, or LDAP scripts. Detection occurs when such tools run on a domain-joined system, followed by authentication attempts by a previously unseen account.
  - *Log sources:* `macos:unifiedlog` (dsconfigad or dscl with create or append options for AD-bound users); `macos:unifiedlog` (UserLoggedIn)
  - *Tune:* `EnrollmentStatus` — Only flag on AD-bound systems with valid LDAP context; `AccountType` — Distinguish between user accounts and computer accounts

---

### T1136.003 — Cloud Account
<a id="t1136003"></a>

**Detection strategy:** Detection Strategy for T1136.003 - Cloud Account Creation across IaaS, IdP, SaaS, Office (`DET0319`)  
**Platforms:** IaaS, Identity Provider, Office Suite, SaaS  
**ATT&CK:** [T1136.003](https://attack.mitre.org/techniques/T1136/003/) · [detail page](../../techniques/persistence.md#t1136003)

- **`AN0899` Analytic 0899** · Identity Provider
  Adversaries create user accounts via identity provider APIs or admin portals (e.g., Azure AD, Okta). These accounts may be assigned elevated privileges or used in chained authentication. Detection monitors Add User activity from suspicious IPs or automation sources, followed by role/permission escalation.
  - *Log sources:* `azure:audit` (Add user); `azure:audit` (Add member to role); `azure:signinlogs` (Login from newly created account)
  - *Tune:* `IPAddress` — Filter on IPs outside known admin networks or geographies; `RoleThreshold` — Raise alert if total admins exceeds historical baseline; `ServicePrincipalFlag` — Differentiate between user and service principal creation
- **`AN0900` Analytic 0900** · IaaS
  Adversaries use cloud API, CLI, or console to create IAM users or roles. Initial CreateUser is followed by policy/role attachment. Detection monitors temporal chains involving IAM:CreateUser, AttachUserPolicy, and credential generation, especially from automation or foreign IP ranges.
  - *Log sources:* `AWS:CloudTrail` (CreateUser); `AWS:CloudTrail` (AttachUserPolicy)
  - *Tune:* `Region` — Alert when creation happens in unexpected regions; `TimeWindow` — Chain CreateUser → AttachPolicy → AccessKey within short timeframe; `UserAgent` — Monitor API calls from non-console or automation tools
- **`AN0901` Analytic 0901** · SaaS
  Adversaries create SaaS accounts via admin dashboards or integrations (e.g., Zoom, Salesforce, Slack). Monitor lifecycle.create or account provisioning events from non-standard sources or times.
  - *Log sources:* `saas:zoom` (New user created)
  - *Tune:* `ApplicationScope` — Trigger only for high-privilege or sensitive applications; `AdminUserList` — Compare actor to list of approved SaaS administrators
- **`AN0902` Analytic 0902** · Office Suite
  Adversaries leverage M365 or Google Workspace APIs to create users, service accounts, or guest accounts. Follow-on behaviors include login activity, role escalation, or service principal token generation.
  - *Log sources:* `m365:unified` (Add user); `m365:unified` (Add member to group)
  - *Tune:* `GroupSensitivity` — Only alert on additions to high-value groups (e.g., Domain Admins); `GuestFlag` — Tune alerts based on guest vs internal user creation

---

### T1137 — Office Application Startup
<a id="t1137"></a>

**Detection strategy:** Detect Office Startup-Based Persistence via Macros, Forms, and Registry Hooks (`DET0398`)  
**Platforms:** Office Suite, Windows  
**ATT&CK:** [T1137](https://attack.mitre.org/techniques/T1137/) · [detail page](../../techniques/persistence.md#t1137)

- **`AN1116` Analytic 1116** · Windows
  Office-based persistence via Office template macros, Outlook forms/rules/homepage, or registry-persistent scripts. Adversary modifies registry keys or Office application directories to load malicious scripts at startup.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:Application` (Outlook rule creation, form load, or homepage redirection)
  - *Tune:* `ParentProcessName` — Tune based on expected Office process tree (e.g., WINWORD.EXE spawning cmd.exe); `RegistryPath` — Specific keys related to Office startup such as Outlook Today, AddIns, or Template Macros; `TimeWindow` — Window of process execution after user login or Outlook launch; `UserContext` — Detect persistence within high-value user mailboxes (e.g., admin, finance, C-suite)
- **`AN1117` Analytic 1117** · Office Suite
  Startup-based persistence mechanisms within Microsoft Office Suite like template macros and home page redirects being configured through internal automation or client-side settings.
  - *Log sources:* `m365:unified` (Set-Mailbox, Set-InboxRule, Set-MailboxFolderPermission); `m365:mailboxaudit` (Outlook rule creation or custom form deployment)
  - *Tune:* `RuleAction` — Identify rule actions that execute scripts, forward emails externally, or start external content; `MailboxTarget` — Focus on users with sensitive roles or shared mailboxes; `TimeWindow` — Detect persistence artifacts created shortly after credential access or login from an unusual location

---

### T1137.001 — Office Template Macros
<a id="t1137001"></a>

**Detection strategy:** Detect Persistence via Office Template Macro Injection or Registry Hijack (`DET0519`)  
**Platforms:** Office Suite, Windows  
**ATT&CK:** [T1137.001](https://attack.mitre.org/techniques/T1137/001/) · [detail page](../../techniques/persistence.md#t1137001)

- **`AN1436` Analytic 1436** · Windows
  Adversaries inject VBA macros into Office templates such as Normal.dotm or Personal.xlsb or redirect Office template load path via registry key (GlobalDotName) to gain persistence. Template macros trigger execution of malicious code on application startup.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=15); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:Microsoft-Office-Alerts` (Office application warning or alert on macro execution from template)
  - *Tune:* `TemplatePath` — Path to Normal.dotm, Personal.xlsb, or Excel/Word startup templates may vary by Office version and user; `RegistryPath` — GlobalDotName or equivalent registry keys may differ across Office versions or deployments; `TimeWindow` — Office process creation and macro execution timing after system or user login; `UserContext` — May be scoped to high-value users or those with access to sensitive templates
- **`AN1437` Analytic 1437** · Office Suite
  Malicious VBA macros embedded in base templates like Normal.dotm or Personal.xlsb are automatically loaded and executed at startup. Template path may be hijacked to load a remote or attacker-controlled template via GlobalDotName registry setting.
  - *Log sources:* `m365:unified` (Set-Mailbox, Set-MailboxPolicy, Set-TrustedLocation)
  - *Tune:* `TemplateSource` — Macros may be embedded in local user templates or retrieved from shared network paths; `MacroSecurityLevel` — Macro execution policy (disabled, warn, enabled) varies by tenant or user configuration

---

### T1137.002 — Office Test
<a id="t1137002"></a>

**Detection strategy:** Detect Persistence via Office Test Registry DLL Injection (`DET0315`)  
**Platforms:** Office Suite, Windows  
**ATT&CK:** [T1137.002](https://attack.mitre.org/techniques/T1137/002/) · [detail page](../../techniques/persistence.md#t1137002)

- **`AN0880` Analytic 0880** · Windows
  Adversaries create the 'Office Test\Special\Perf' registry key and specify a malicious DLL path that is auto-loaded when an Office application starts. This DLL is injected into the Office process memory space and can provide persistent execution without requiring macro enablement.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Microsoft-Office-Alerts` (Unexpected DLL or component loaded at Office startup)
  - *Tune:* `RegistryPath` — Path to 'Office test\Special\Perf' may vary by Office version, 32/64-bit, or architecture (HKCU vs HKLM); `DLLPath` — Injected DLL may reside in different user-writable locations (e.g., %APPDATA%, %TEMP%, or network shares); `OfficeProcessName` — Process name (e.g., winword.exe, excel.exe) may vary by Office deployment and usage; `TimeWindow` — Time between DLL registry creation and first Office execution may vary depending on user activity; `UserContext` — Malicious DLL may target only specific users, necessitating correlation with interactive logon sessions
- **`AN0881` Analytic 0881** · Office Suite
  Office application auto-loads a non-standard DLL during startup triggered via Office Test Registry key, often without macro warning banners. DLL persistence mechanism circumvents traditional macro defenses.
  - *Log sources:* `m365:unified` (Non-standard Office startup component detected (e.g., unexpected DLL path)); `m365:office` (Startup execution includes non-default component)
  - *Tune:* `TrustedLocationBypass` — DLL may be placed in location trusted by Office configuration or signed to evade alerts; `AuditPolicyScope` — Only specific tenants or users may have Office auditing enabled at granular DLL load level

---

### T1137.003 — Outlook Forms
<a id="t1137003"></a>

**Detection strategy:** Detect Persistence via Outlook Custom Forms Triggered by Malicious Email (`DET0029`)  
**Platforms:** Office Suite, Windows  
**ATT&CK:** [T1137.003](https://attack.mitre.org/techniques/T1137/003/) · [detail page](../../techniques/persistence.md#t1137003)

- **`AN0085` Analytic 0085** · Windows
  Adversary uses a tool like Ruler to insert a malicious custom form into the user's Outlook mailbox. The form is designed to auto-execute on Outlook startup or on receipt of a specially crafted email. This results in child processes launched from outlook.exe and possibly network connections or payload loading.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Application` (Outlook errors loading or processing custom form templates); `WinEventLog:PowerShell` (Execution of Microsoft script to enumerate custom forms in Outlook mailbox)
  - *Tune:* `FormStorageLocation` — Malicious forms may be stored in various user-specific locations in the Outlook mailbox (e.g., IPM.Note class); `ChildProcessName` — Child process spawned by outlook.exe may vary (e.g., powershell.exe, rundll32.exe, mshta.exe); `TimeWindow` — Form-triggered execution may happen immediately upon Outlook startup or with delay after crafted message arrival; `OutlookVersion` — Form behavior and error logs may vary across Outlook 2013, 2016, and M365 builds; `UserContext` — Attack may target only specific users; contextual correlation needed for account baselining
- **`AN0086` Analytic 0086** · Office Suite
  Outlook form execution upon message receipt or client launch results in automated code execution within user session. Form definitions deviate from standard templates and include script logic or COM object calls embedded in form fields.
  - *Log sources:* `m365:unified` (Unusual form activity within Outlook client, including load of non-default forms); `m365:messagetrace` (Inbound email triggers execution of mailbox-stored custom form)
  - *Tune:* `AuditPolicyScope` — Not all tenants may enable audit logs of custom form activity or COM component usage in Office; `MessageSenderAnomalyThreshold` — Ruler-style delivery may come from external accounts with forged headers or low reputation; `FormExecutionRate` — Frequency of form triggers may be anomalously high compared to baseline Outlook usage

---

### T1137.004 — Outlook Home Page
<a id="t1137004"></a>

**Detection strategy:** Detect Persistence via Outlook Home Page Exploitation (`DET0177`)  
**Platforms:** Office Suite, Windows  
**ATT&CK:** [T1137.004](https://attack.mitre.org/techniques/T1137/004/) · [detail page](../../techniques/persistence.md#t1137004)

- **`AN0502` Analytic 0502** · Windows
  Adversary uses a tool like Ruler to configure a malicious Outlook folder Home Page that loads a remote or embedded HTML payload upon folder interaction. Execution chain begins with Outlook launching, a specific folder being accessed, and a suspicious child process being spawned or COM-based execution invoked.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Application` (Outlook logs indicating failure to load or render HTML page in Home Page view); `WinEventLog:PowerShell` (Execution of PowerShell script to enumerate or remove malicious Home Page folder config)
  - *Tune:* `TargetFolder` — Home Page can be configured on any folder like Calendar, Inbox, or custom folders; `HTMLPayloadLocation` — The Home Page URL may point to internal or external content, hosted on trusted or unknown domains; `ChildProcessName` — Execution may result in launch of scripting hosts (e.g., mshta.exe, wscript.exe) from outlook.exe; `TimeWindow` — Execution may occur only when the specific folder is accessed after launch, not immediately at startup; `FormViewBehavior` — Behavior may vary if the folder's form view is customized or suppressed via GPO
- **`AN0503` Analytic 0503** · Office Suite
  Malicious HTML or script is rendered as a Home Page for a specific Outlook folder. Outlook accesses that folder, loads remote content, and executes embedded JavaScript or ActiveX/COM logic resulting in unauthorized actions or local execution.
  - *Log sources:* `m365:unified` (Folder configuration updated with external or HTML-formatted Home Page via Set-MailboxFolder); `m365:messagetrace` (Inbound email triggering Outlook to auto-access folder tied to malicious Home Page)
  - *Tune:* `AuditPolicyScope` — Home Page customization may not be audited unless detailed message or folder auditing is enabled; `FolderAccessRate` — Anomalous access to folders not usually interacted with can signal triggering of malicious view; `ExternalURLAllowlist` — Mail clients may restrict remote Home Page content unless domain is explicitly allowed

---

### T1137.005 — Outlook Rules
<a id="t1137005"></a>

**Detection strategy:** Detect Persistence via Malicious Outlook Rules (`DET0095`)  
**Platforms:** Office Suite, Windows  
**ATT&CK:** [T1137.005](https://attack.mitre.org/techniques/T1137/005/) · [detail page](../../techniques/persistence.md#t1137005)

- **`AN0263` Analytic 0263** · Windows
  Adversary uses a tool like Ruler or MFCMapi to create a malicious Outlook rule that triggers execution upon receipt of a crafted email. On email delivery, Outlook executes the rule, resulting in code execution (e.g., launching mshta.exe or PowerShell). Outlook spawns a non-standard child process, often unsanctioned, without user interaction.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Application` (Outlook rule execution failure or abnormal rule execution context); `WinEventLog:PowerShell` (PowerShell launched from outlook.exe or triggered without user invocation)
  - *Tune:* `ChildProcessName` — Outlook may spawn mshta.exe, powershell.exe, or wscript.exe depending on attacker payload; `RuleTriggerCondition` — Rule execution may depend on message subject, sender, or message header content; `ParentProcessName` — Legitimate Outlook activity should not spawn scripting or interpreter processes; `TimeWindow` — Execution may occur with delay after message receipt or folder interaction
- **`AN0264` Analytic 0264** · Office Suite
  Adversary adds a new Outlook rule with modified or obfuscated PR_RULE_MSG_NAME and PR_RULE_MSG_PROVIDER attributes using MFCMapi or Ruler. Rule is triggered when email arrives, executing embedded or external code. Mailbox audit logs or Unified Audit Log shows automated rule-triggered action without user interaction.
  - *Log sources:* `m365:unified` (Creation or modification of inbox rule outside of normal user behavior); `m365:messagetrace` (Inbound email matches crafted rule trigger pattern tied to persistence logic)
  - *Tune:* `AuditPolicyScope` — Mailbox rule changes may not be captured unless advanced audit logging is enabled; `RuleProviderName` — Malicious rules may use spoofed or non-standard PR_RULE_MSG_PROVIDER values; `TriggerSubjectKeywords` — Triggering emails may contain uncommon but benign-looking subjects; `UserContext` — Target user account may be inactive or high-value (e.g., VIP, service account)

---

### T1137.006 — Add-ins
<a id="t1137006"></a>

**Detection strategy:** Detect Persistence via Malicious Office Add-ins (`DET0050`)  
**Platforms:** Office Suite, Windows  
**ATT&CK:** [T1137.006](https://attack.mitre.org/techniques/T1137/006/) · [detail page](../../techniques/persistence.md#t1137006)

- **`AN0137` Analytic 0137** · Windows
  An adversary writes or drops a malicious Office Add-in (e.g., WLL, XLL, COM) to a trusted directory or modifies registry keys to load malicious add-ins on Office application launch. Upon user opening Word or Excel, the add-in is automatically loaded, triggering execution of the payload, often spawning scripting engines or anomalous child processes.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=2); `WinEventLog:Sysmon` (EventCode=13, 14)
  - *Tune:* `AddInExtension` — Malicious add-ins may have varying extensions (.wll, .xll, .dll, .vsto); `TrustedPath` — Office trusted add-in paths may differ across enterprise configurations; `RegistryPath` — Registry keys used to load add-ins may be version- and app-specific; `ChildProcessName` — Office processes spawning mshta.exe, powershell.exe, or rundll32.exe are abnormal; `TimeWindow` — Add-in loading may occur only during Office launch windows
- **`AN0138` Analytic 0138** · Office Suite
  Malicious Office add-ins loaded via VSTO, COM, or VBA auto-load paths. Upon launch of Word/Excel/Outlook, the add-in executes code without user action. Add-in resides in trusted directory or registered via Office COM/VBE subsystem. Behavior includes unsigned add-in execution, anomalous load context, or add-in spawning interpreter process.
  - *Log sources:* `WinEventLog:Application` (Office Add-in load errors, abnormal loading context, or unsigned add-in warnings); `WinEventLog:Microsoft-Office/OutlookAddinMonitor` (Outlook loading add-in via unexpected load path or non-default profile context)
  - *Tune:* `UnsignedAddInBehavior` — Admins may allow or block unsigned add-ins depending on GPO configuration; `OfficeProductVersion` — Different Office versions store trusted paths and add-in configs in version-specific locations; `AddInTrigger` — Some add-ins only load on specific actions (new document, open file, etc.)

---

### T1176 — Software Extensions
<a id="t1176"></a>

**Detection strategy:** Detection of Malicious or Unauthorized Software Extensions (`DET0092`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1176](https://attack.mitre.org/techniques/T1176/) · [detail page](../../techniques/persistence.md#t1176)

- **`AN0251` Analytic 0251** · Windows
  Installation or execution of a malicious browser or IDE extension, followed by abnormal registry entries or outbound network connections from the host application
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `Image` — Path of browser or IDE launching subprocesses—may vary depending on installed applications; `ParentImage` — Legitimate parent-child process relationships for known safe extensions; `RegistryPath` — Expected registry keys under HKCU/HKLM for installed extensions; `TimeWindow` — Tunable interval to correlate extension install with follow-on C2 traffic
- **`AN0252` Analytic 0252** · macOS
  Installation of configuration profiles or plist entries associated with malicious or unauthorized browser extensions
  - *Log sources:* `macos:unifiedlog` (Execution of 'profiles install -type=configuration'); `macos:unifiedlog` (Creation of .plist under /Library/Managed Preferences/); `macos:unifiedlog` (Suspicious outbound traffic from browser binary to non-standard domains)
  - *Tune:* `PlistPath` — Directory path for user-specific extension configuration files; `CommandLine` — Usage of profiles CLI tool—can be modified by legitimate tools or MDMs; `TimeWindow` — Correlation window between configuration install and observable extension behavior
- **`AN0253` Analytic 0253** · Linux
  Manual or script-based installation of extension-like modules into browser config directories or IDE plugin paths, followed by suspicious network activity
  - *Log sources:* `auditd:SYSCALL` (execve); `fs:fileevents` (creat); `NSM:Flow` (Abnormal browser traffic volume or destination)
  - *Tune:* `DirectoryPath` — Common plugin or extension directories may vary by distro or browser (e.g., ~/.config/google-chrome/Default/Extensions); `ExecPath` — Path to scripting tools used in installation (e.g., bash, curl, unzip); `TimeWindow` — Tunable interval between install and first network beacon

---

### T1176.001 — Browser Extensions
<a id="t1176001"></a>

**Detection strategy:** Detecting Malicious Browser Extensions Across Platforms (`DET0044`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1176.001](https://attack.mitre.org/techniques/T1176/001/) · [detail page](../../techniques/persistence.md#t1176001)

- **`AN0123` Analytic 0123** · Windows
  Installation of a new browser extension followed by suspicious file writes or outbound network connections to untrusted domains by the browser process.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=13, 14)
  - *Tune:* `UserContext` — Extension installation by privileged or domain users may require higher scrutiny; `BrowserExecutablePath` — Custom or portable browsers may not match default paths; `ExtensionInstallPath` — Installation paths may vary by version or user profile
- **`AN0124` Analytic 0124** · macOS
  Installation of malicious .mobileconfig profiles or browser extension plist entries followed by abnormal browser child process activity.
  - *Log sources:* `macos:unifiedlog` (profiles install -type=configuration); `macos:unifiedlog` (Creation or modification of browser extension .plist files); `macos:unifiedlog` (Unexpected child process of Safari or Chrome)
  - *Tune:* `PlistPath` — Different versions may store extensions in variant preference folders; `CommandLineFlags` — May vary with OS version; some install flags deprecated in macOS 11+
- **`AN0125` Analytic 0125** · Linux
  Manual or scripted installation of Chrome extensions using user scripts or config files, followed by unexpected network connections from browser processes.
  - *Log sources:* `auditd:SYSCALL` (open); `NSM:Flow` (Browser connections to known C2 or dynamic DNS domains); `auditd:SYSCALL` (execve)
  - *Tune:* `ExtensionDir` — Location of Chrome/Chromium extensions under user profile may vary; `DomainWatchlist` — Custom list of suspicious destination domains for browser traffic

---

### T1176.002 — IDE Extensions
<a id="t1176002"></a>

**Detection strategy:** Detect malicious IDE extension install/usage and IDE tunneling (`DET0561`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1176.002](https://attack.mitre.org/techniques/T1176/002/) · [detail page](../../techniques/persistence.md#t1176002)

- **`AN1548` Analytic 1548** · Windows
  Adversary installs or side-loads an IDE extension (VS Code, IntelliJ/JetBrains, Eclipse) or enables IDE tunneling. Chain: (1) IDE binary starts on a non-developer endpoint or server, often with install/force/tunnel flags → (2) extension files/registrations appear under user profile → (3) browser/IDE initiates outbound connections to extension marketplaces, update endpoints, or IDE remote/tunnel services → (4) optional child tools (ssh, node, powershell) execute under the IDE context.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `IDEList` — Executable names/paths (e.g., code.exe, idea64.exe, eclipse.exe, jetbrains-gateway.exe) vary by version and packaging.; `SuspiciousCLI` — Flags such as --install-extension, --force, --disable-extensions, --user-data-dir, --uninstall-extension, tunnel/remote flags are tunable.; `ServerZones` — List of hosts where IDEs should never run (prod servers, DCs).; `AllowedHosts` — Approved extension marketplaces/ide services; use to suppress benign traffic.; `TimeWindow` — Correlation horizon (e.g., 15–30m) between process start, file writes, and outbound IDE/tunnel connections.
- **`AN1549` Analytic 1549** · Linux
  Adversary installs or abuses IDE extensions via CLI or direct write to profile directories and then communicates with marketplaces or remote tunnel services. Chain: auditd execve (code/idea/eclipse) with install/update flags or writes under ~/.vscode/extensions, ~/.config/JetBrains → outbound flows to *.visualstudio.com, marketplace.visualstudio.com, *.jetbrains.com, githubusercontent.com, or SSH/WebSocket tunnel endpoints → optional ssh/node processes spawned by IDE.
  - *Log sources:* `auditd:SYSCALL` (execve); `auditd:SYSCALL` (open,creat,rename,write); `NSM:Flow` (Connections from IDE hosts to marketplace/tunnel domains)
  - *Tune:* `IDEPaths` — Per-distro/profile extension directories differ; tune for Chromium/JetBrains snap/flatpak paths.; `DomainAllowlist` — Enterprise-approved repos and proxies to reduce FPs.; `UserRoleScope` — Limit to non-developer users or production servers.; `TimeWindow` — Join horizon across file, process, and network telemetry.
- **`AN1550` Analytic 1550** · macOS
  Adversary adds IDE extensions or plugins (VS Code, JetBrains Toolbox/EAP, Eclipse) via GUI or CLI, possibly via managed profiles. Chain: process start with install/update flags → plist/extension folder changes under ~/Library/Application Support/Code or ~/Library/Application Support/JetBrains → outbound connections to marketplaces/tunnel services → optional helper (ssh/node) spawned.
  - *Log sources:* `macos:unifiedlog` (Execution of Code.app, idea, JetBrainsToolbox, eclipse with install/extension flags); `macos:unifiedlog` (Writes under ~/Library/Application Support/Code*/extensions or JetBrains plugins); `macos:unifiedlog` (Outbound connections from IDE processes to marketplace/tunnel domains)
  - *Tune:* `PlistLocations` — Per-app preference domains and plugin directories vary by version.; `MDMProfiles` — If MDM installs extensions, allowlist those events to avoid FPs.; `TimeWindow` — Correlation range between install and first beacon.

---

### T1505 — Server Software Component
<a id="t1505"></a>

**Detection strategy:** Detection Strategy for T1505 - Server Software Component (`DET0547`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1505](https://attack.mitre.org/techniques/T1505/) · [detail page](../../techniques/persistence.md#t1505)

- **`AN1507` Analytic 1507** · Windows
  Installation of malicious IIS/Apache/SQL server modules that later execute command-line interpreters or establish outbound connections.
  - *Log sources:* `WinEventLog:Security` (EventCode=4698); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Application` (Unusual DLL/plugin registration for IIS/SQL/Apache or unexpected error logs)
  - *Tune:* `TimeWindow` — Time delta between module install and process execution (e.g., persistence delay).; `ParentProcessName` — Custom server wrapper processes or renamed webserver processes may require tuning.
- **`AN1508` Analytic 1508** · Linux
  Abuse of extensible server modules (e.g., Apache, Nginx, Tomcat) to load rogue plugins that initiate bash, connect to C2, or spawn reverse shells.
  - *Log sources:* `auditd:SYSCALL` (execve); `linux:syslog` (Module registration or stacktrace logs indicating segmentation faults or unknown module errors); `NSM:Flow` (Outbound connections from web server binaries (apache2, nginx, php-fpm) to unknown external IPs)
  - *Tune:* `ServerBinaryPath` — Alternate install paths like /opt/httpd or user-compiled binaries; `OutboundPortRange` — Tunable to match expected versus suspicious outbound traffic patterns
- **`AN1509` Analytic 1509** · macOS
  Malicious use of webserver plugins (e.g., for nginx, PHP, Node.js) that execute AppleScript or open network sockets.
  - *Log sources:* `macos:unifiedlog` (Script interpreter invoked by nginx/apache worker process); `macos:unifiedlog` (Web server process initiating outbound TCP connections not tied to normal server traffic)
  - *Tune:* `ParentBinaryPath` — If homebrew or manually compiled nginx/httpd used, baseline accordingly.
- **`AN1510` Analytic 1510** · ESXi
  Use of ESXi web interface plugins or vSphere extensions to embed persistent malicious scripts or services.
  - *Log sources:* `esxi:hostd` (New extension/module install with unknown vendor ID); `esxi:vmkernel` (Unexpected restarts of management agents or shell access)
  - *Tune:* `PluginVendorName` — Whitelist known vendor plug-in names for extension correlation; `AccessVector` — Limit exposure of plugin installation via HTTPS or SSH

---

### T1505.001 — SQL Stored Procedures
<a id="t1505001"></a>

**Detection strategy:** Detection Strategy for SQL Stored Procedures Abuse via T1505.001 (`DET0181`)  
**Platforms:** Linux, Windows  
**ATT&CK:** [T1505.001](https://attack.mitre.org/techniques/T1505/001/) · [detail page](../../techniques/persistence.md#t1505001)

- **`AN0511` Analytic 0511** · Windows
  Creation or modification of stored procedures invoking xp_cmdshell or CLR assemblies for command execution and persistence.
  - *Log sources:* `WinEventLog:Application` (Stored procedure creation, modification, or xp_cmdshell invocation via SQL logs or SQL Server auditing); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Application` (CLR Assembly creation, loading, or modification logs via MSSQL CLR integration)
  - *Tune:* `xp_cmdshell_invocation_threshold` — Adjust if legitimate procedures use xp_cmdshell often in environment; `CLRAssemblyNameWhitelist` — Organization-defined whitelist of legitimate CLR assemblies; `TimeWindow` — Tune time window to correlate stored procedure creation with process execution
- **`AN0512` Analytic 0512** · Linux
  SQL stored procedures that invoke OS-level commands via `xp_cmdshell` equivalent or via UDF (User-Defined Functions) mechanisms.
  - *Log sources:* `auditd:SYSCALL` (execve); `ApplicationLogs:SQL` (Stored procedure creation or modification with shell invocation (e.g., system(), exec()))
  - *Tune:* `CommandRegex` — Regex used to detect suspicious OS commands via SQL; `TimeWindow` — Window for correlating procedure creation and command execution

---

### T1505.002 — Transport Agent
<a id="t1505002"></a>

**Detection strategy:** Detection Strategy for T1505.002 - Transport Agent Abuse (Windows/Linux) (`DET0166`)  
**Platforms:** Linux, Windows  
**ATT&CK:** [T1505.002](https://attack.mitre.org/techniques/T1505/002/) · [detail page](../../techniques/persistence.md#t1505002)

- **`AN0472` Analytic 0472** · Windows
  Adversary registers a malicious Microsoft Exchange transport agent DLL (.NET assembly), configures it via PowerShell or Exchange Management Shell, and persists code execution by manipulating email processing logic based on rules or headers.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Application` (Exchange Transport Service loads unusual .NET assembly or errors upon transport agent execution); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `TimeWindow` — May need tuning based on frequency of Exchange agent updates in environment.; `AssemblyPath` — Specific DLL paths used by Exchange for registered agents may vary between deployments.; `CmdletInvocationThreshold` — Tunable threshold for repeated use of transport agent management cmdlets.
- **`AN0473` Analytic 0473** · Linux
  Adversary installs or modifies email content filters or transport scripts (e.g., Postfix milter, Sendmail milter, Exim filters) using shell access or configuration manipulation.
  - *Log sources:* `auditd:SYSCALL` (write); `linux:syslog` (milter configuration updated, transport rule initialized, unexpected script execution); `auditd:EXECVE` (/usr/sbin/postfix, /usr/sbin/exim, /usr/sbin/sendmail); `auditd:SYSCALL` (write); `linux:Sysmon` (EventCode=7)
  - *Tune:* `MailTransportScriptPath` — Path to custom scripts or filters depends on mail daemon (e.g., /etc/postfix/milter/, /etc/exim4/).; `UserContext` — Mail agents may run under different service users (postfix, exim, etc.), which should be scoped.; `ExecFrequencyThreshold` — Frequency of filter script re-execution per daemon restart or reload may vary.

---

### T1505.003 — Web Shell
<a id="t1505003"></a>

**Detection strategy:** Web Shell Detection via Server Behavior and File Execution Chains (`DET0394`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1505.003](https://attack.mitre.org/techniques/T1505/003/) · [detail page](../../techniques/persistence.md#t1505003)

- **`AN1108` Analytic 1108** · Windows
  Unexpected file creation in web directories followed by web server processes (e.g., w3wp.exe) spawning command shells or script interpreters (e.g., cmd.exe, powershell.exe)
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Security` (EventCode=4624, 4648); `NSM:Flow` (Inbound HTTP POST with suspicious payload size or user-agent)
  - *Tune:* `WebRootPath` — Custom web server directory depending on IIS or third-party hosting environment; `ParentProcess` — Different server binaries (e.g., php-cgi.exe, apache.exe) that may launch scripts
- **`AN1109` Analytic 1109** · Linux
  File creation of unauthorized script (e.g., .php, .sh) in /var/www/html followed by execution of unexpected system utilities (e.g., curl, bash, nc) by apache/nginx
  - *Log sources:* `auditd:SYSCALL` (new file created in /var/www/html, /srv/http, or similar web root); `auditd:SYSCALL` (apache2 or nginx spawning sh, bash, or python interpreter); `NSM:Flow` (POST requests to .php, .jsp, .aspx files with high entropy body)
  - *Tune:* `WebRootPath` — Web server root varies by distro and hosting configuration; `PayloadEntropyThreshold` — Base64 or XOR encoded shells may exceed this value; `TimeWindow` — Correlate file creation with process spawn within X seconds
- **`AN1110` Analytic 1110** · macOS
  Web servers (e.g., httpd) spawning abnormal processes post file upload into /Library/WebServer/Documents or /usr/local/var/www
  - *Log sources:* `macos:unifiedlog` (httpd spawning bash, zsh, python, or osascript); `auditd:SYSCALL` (file write operations in /Library/WebServer/Documents)
  - *Tune:* `InterpreterName` — Adversary may use different scripting environments; `ExecutionParent` — Not all web servers are named httpd; may differ in custom deployments

---

### T1505.004 — IIS Components
<a id="t1505004"></a>

**Detection strategy:** Detection Strategy for T1505.004 - Malicious IIS Components (`DET0068`)  
**Platforms:** Windows  
**ATT&CK:** [T1505.004](https://attack.mitre.org/techniques/T1505/004/) · [detail page](../../techniques/persistence.md#t1505004)

- **`AN0184` Analytic 0184** · Windows
  Adversary installs or modifies IIS components (ISAPI filters, extensions, or modules) using DLL files registered via configuration changes or administrative tools like AppCmd.exe. These components intercept or manipulate HTTP requests/responses for persistence or C2.
  - *Log sources:* `WinEventLog:Security` (EventCode=4663, 4670, 4656); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:System` (Changes to applicationhost.config or DLLs loaded by w3wp.exe); `WinEventLog:Microsoft-IIS-Configuration` (Module or ISAPI filter registration events)
  - *Tune:* `TimeWindow` — Adjustable time frame for detecting chained events (e.g., config change + module load); `UserContext` — Scope detection to specific users or roles allowed to modify IIS components; `WatchedPaths` — Specific directories such as %windir%\System32\inetsrv\ for DLL monitoring; `DLLNameEntropyThreshold` — Entropy or name patterns to flag suspicious DLLs registered as components; `ParentProcessName` — Restrict to DLLs loaded by w3wp.exe or invoked via AppCmd.exe

---

### T1505.005 — Terminal Services DLL
<a id="t1505005"></a>

**Detection strategy:** Detection Strategy for T1505.005 – Terminal Services DLL Modification (Windows) (`DET0212`)  
**Platforms:** Windows  
**ATT&CK:** [T1505.005](https://attack.mitre.org/techniques/T1505/005/) · [detail page](../../techniques/persistence.md#t1505005)

- **`AN0595` Analytic 0595** · Windows
  Adversary modifies or replaces the Terminal Services DLL (`termsrv.dll`) or changes the associated `ServiceDll` Registry value to load an arbitrary or patched DLL that enables persistent and enhanced RDP access. This may include binary replacement, registry tampering, and unexpected module loads by the `svchost.exe -k termsvcs` process.
  - *Log sources:* `WinEventLog:Security` (EventCode=4657); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `TargetDLLPath` — Defenders may tune for non-standard DLLs loaded by svchost.exe or termsrv.exe processes.; `RegistryKeyTarget` — Environment-specific variations in the path to `ServiceDll` registry key (e.g., nested group policies).; `TimeWindow` — Correlation time window for registry change followed by DLL load or svchost restart.; `ParentProcessName` — Some environments may spawn registry changes from automation tools or administrative scripts.

---

### T1505.006 — vSphere Installation Bundles
<a id="t1505006"></a>

**Detection strategy:** Detect Abuse of vSphere Installation Bundles (VIBs) for Persistent Access (`DET0535`)  
**Platforms:** ESXi  
**ATT&CK:** [T1505.006](https://attack.mitre.org/techniques/T1505/006/) · [detail page](../../techniques/persistence.md#t1505006)

- **`AN1475` Analytic 1475** · ESXi
  Malicious VIB installation for persistence via `esxcli software vib install` using `--force` or `--no-sig-check`, enabling custom startup scripts or firewall rules. Behavior chain: (1) unsigned/suspicious VIB installation → (2) startup script or binary placed in persistent boot path → (3) persistence across reboot via /etc/rc.local.d or other boot hook).
  - *Log sources:* `esxi:esxupdate` (/var/log/esxupdate.log contains VIB installed with `--force` or `--no-sig-check` and non-standard acceptance levels); `esxi:shell` (`esxcli software vib install` with `--force` or `--no-sig-check` from shell history or `shell.log`); `linux:fim` (Changes to /etc/rc.local.d/local.sh or creation of unexpected startup files in persistent partitions (/etc/init.d, /store, /locker))
  - *Tune:* `AcceptanceLevel` — Some environments may intentionally permit CommunitySupported or unsigned VIBs—filter by known allowed publishers.; `InstallCommandThreshold` — Set alerting thresholds for frequency of VIB install attempts per host/user/time window.; `StartupPathRegex` — Tune regex for monitoring startup file locations based on ESXi image customization.

---

### T1525 — Implant Internal Image
<a id="t1525"></a>

**Detection strategy:** Detection Strategy for T1525 – Implant Internal Image (`DET0334`)  
**Platforms:** Containers, IaaS  
**ATT&CK:** [T1525](https://attack.mitre.org/techniques/T1525/) · [detail page](../../techniques/persistence.md#t1525)

- **`AN0946` Analytic 0946** · Containers
  Implantation of malicious code into container images followed by registry push and use in new deployments.
  - *Log sources:* `docker:daemon` (docker build or docker commit commands followed by docker push to internal registry); `docker:registry` (push event of new image version from unrecognized user or context)
  - *Tune:* `TimeWindow` — Time threshold between image creation and use in deployment – typically rapid in adversarial activity.; `UserContext` — The expected users or service accounts performing image pushes.; `RegistryNameRegex` — Expected naming patterns for trusted registries.
- **`AN0947` Analytic 0947** · IaaS
  Creation or modification of cloud virtual machine images (AMIs, custom images) with persistence mechanisms, followed by infrastructure provisioning that uses these implanted images.
  - *Log sources:* `AWS:CloudTrail` (RegisterImage); `AWS:CloudTrail` (ModifyImageAttribute); `AWS:CloudTrail` (RunInstances)
  - *Tune:* `IAMRole` — Roles that are allowed to register and modify images should be scoped narrowly.; `ImageTagRegex` — Expected tags or naming patterns for images (e.g., 'golden-image', 'base-image').; `LaunchWindow` — Time interval between image creation and instance launch.

---

### T1542.001 — System Firmware
<a id="t1542001"></a>

**Detection strategy:** Detection Strategy for T1542.001 Pre-OS Boot: System Firmware (`DET0099`)  
**Platforms:** Network Devices, Windows  
**ATT&CK:** [T1542.001](https://attack.mitre.org/techniques/T1542/001/) · [detail page](../../techniques/persistence.md#t1542001)

- **`AN0275` Analytic 0275** · Windows
  Unexpected write operations to BIOS/UEFI firmware regions or EFI boot partitions that do not correlate with legitimate vendor firmware updates. API calls or utilities such as fwupdate.exe or vendor flash tools executed from non-administrative or non-IT management accounts. Suspicious raw disk writes targeting System Firmware GUID partitions followed by abnormal reboot sequences.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=9); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `AllowedFirmwareUpdateTools` — Legitimate vendor tools permitted to perform firmware flashing or BIOS updates.; `TimeWindow` — Expected time periods for approved firmware updates, used for correlating suspicious activity outside patch cycles.; `KnownGoodFirmwareHashes` — Baseline hashes of vendor BIOS/UEFI firmware for integrity comparison.
- **`AN0276` Analytic 0276** · Network Devices
  Unauthorized firmware uploads to routers, switches, or firewalls via TFTP/FTP/SCP. Logs showing boot variable or startup image path changes redirecting to non-standard firmware images. Abnormal reboots or firmware rollback attempts following configuration modification events.
  - *Log sources:* `networkdevice:config` (Boot image path or firmware configuration variable modified outside of maintenance windows); `networkdevice:runtime` (Firmware image uploaded via TFTP/FTP/SCP)
  - *Tune:* `ApprovedFirmwareHashes` — Known good firmware image hashes stored for validation.; `MaintenanceWindows` — Expected time periods when firmware uploads or reboots are considered normal.; `SourceIPWhitelist` — List of trusted management IPs allowed to initiate firmware uploads.

---

### T1542.002 — Component Firmware
<a id="t1542002"></a>

**Detection strategy:** Detection Strategy for T1542.002 Pre-OS Boot: Component Firmware (`DET0323`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1542.002](https://attack.mitre.org/techniques/T1542/002/) · [detail page](../../techniques/persistence.md#t1542002)

- **`AN0916` Analytic 0916** · Windows
  Detection of anomalous driver and firmware interactions, including unsigned or unexpected firmware updates, driver loads linked to hardware components, and suspicious use of privileged APIs to read/write firmware or controller memory.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=6); `firmware:integrity ` (Firmware integrity verification failures or mismatches against expected UEFI/firmware image baselines)
  - *Tune:* `KnownGoodFirmwareHashes` — Environment-specific list of baseline firmware images for integrity comparison; `DriverAllowList` — Drivers approved for loading in production environments; `TimeWindow` — Correlation period between firmware modification attempt and abnormal driver or process behavior
- **`AN0917` Analytic 0917** · Linux
  Detection of suspicious use of ioctl/sysfs calls to access device firmware, unexpected flashing tools execution, and anomalous firmware checksums logged by SMART or kernel audit mechanisms.
  - *Log sources:* `auditd:SYSCALL` (ioctl/write: Direct firmware update or device memory manipulation syscalls); `linux:syslog` (Driver load events or firmware load failures for hardware devices)
  - *Tune:* `FirmwareImageBaseline` — Baseline firmware checksums for comparison; `AlertThresholds` — Tolerance levels for SMART errors before triggering alerts
- **`AN0918` Analytic 0918** · macOS
  Detection of EFI/firmware manipulation attempts via abnormal driver loads, unsigned kexts, or tampered NVRAM variables associated with component firmware configuration.
  - *Log sources:* `macos:unifiedlog` (Firmware update events or kernel extension (kext) loads not signed by Apple)
  - *Tune:* `ApprovedKextList` — List of trusted and signed kexts permitted in production systems; `EFIHashBaseline` — Known-clean EFI image hashes used for verification

---

### T1542.003 — Bootkit
<a id="t1542003"></a>

**Detection strategy:** Detection Strategy for File Creation or Modification of Boot Files (`DET0150`)  
**Platforms:** Linux, Windows  
**ATT&CK:** [T1542.003](https://attack.mitre.org/techniques/T1542/003/) · [detail page](../../techniques/persistence.md#t1542003)

- **`AN0428` Analytic 0428** · Windows
  Detection of raw access to physical drives, modification of boot records (MBR/VBR), and suspicious file creation or alteration within the EFI System Partition (ESP). Correlates privileged process execution with low-level disk modification and unexpected driver or firmware interactions.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=9); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `KnownGoodMBRHashes` — Baseline hashes of clean MBR/VBR sectors for comparison; `ESPFileWhitelist` — Approved EFI executables within ESP directories; `TimeWindow` — Correlation window between privileged access, raw disk modification, and EFI file creation
- **`AN0429` Analytic 0429** · Linux
  Detection of suspicious write operations to block devices, modifications of bootloader files (GRUB, initrd, vmlinuz), and unexpected changes within the EFI System Partition. Monitors privileged execution of utilities like dd, grub-install, or efibootmgr that modify boot sectors or loader entries.
  - *Log sources:* `auditd:SYSCALL` (open, write: Write operations targeting /dev/sda, /dev/nvme0n1, or EFI partition mounts); `linux:syslog` (Block device write errors or unusual bootloader activity)
  - *Tune:* `BootloaderHashBaseline` — Baseline checksums of GRUB, kernel, and initramfs images; `EFIFileAllowlist` — Trusted EFI executables for Linux environments; `AlertThresholds` — Tunable thresholds for triggering alerts on repeated EFI/bootloader writes

---

### T1543 — Create or Modify System Process
<a id="t1543"></a>

**Detection strategy:** Detection of System Process Creation or Modification Across Platforms (`DET0571`)  
**Platforms:** Containers, Linux, Windows, macOS  
**ATT&CK:** [T1543](https://attack.mitre.org/techniques/T1543/) · [detail page](../../techniques/persistence.md#t1543)

- **`AN1575` Analytic 1575** · Windows
  Detects command-line or API-based creation/modification of Windows Services via `sc.exe`, `powershell.exe`, `services.exe`, or `ChangeServiceConfig`. Looks for creation/modification of autostart services via registry changes, file drops to `System32\services`, and anomalous parent-child process trees.
  - *Log sources:* `WinEventLog:Security` (EventCode=4697); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=13, 14)
  - *Tune:* `ServiceNamePattern` — Regex patterns to flag unusual service names or binaries; `ParentProcessFilter` — List of non-administrative processes starting service management tools; `RegistryPathList` — Monitored autorun locations (e.g., `HKLM\System\CurrentControlSet\Services`)
- **`AN1576` Analytic 1576** · Linux
  Detects creation or modification of `systemd` service units, addition of cron jobs that invoke binaries on boot, or suspicious writes to `/etc/init.d/`. Monitors `chmod +x` and `systemctl` execution paths, especially from non-root parent processes.
  - *Log sources:* `auditd:SYSCALL` (write or rename to /etc/systemd/system or /etc/init.d); `auditd:SYSCALL` (execution of systemctl or service with enable/start/modify)
  - *Tune:* `ServicePathRegex` — Path-based filters to identify service unit files or init scripts; `UserContextList` — List of expected user contexts that normally perform service changes; `CommandNameList` — Binaries used to register/modify services
- **`AN1577` Analytic 1577** · macOS
  Detects creation or modification of `LaunchDaemon` or `LaunchAgent` plist files under `/Library/LaunchDaemons/`, `~/Library/LaunchAgents/`, or similar. Monitors execution of `launchctl`, property list edits, and file permission changes.
  - *Log sources:* `macos:unifiedlog` (launchctl load/unload or plist file modification); `fs:fsusage` (file write to launchd plist paths)
  - *Tune:* `PlistPathList` — Watched directories for LaunchDaemons and LaunchAgents; `PlistKeyMonitor` — Monitored keys such as `RunAtLoad`, `KeepAlive`, or `ProgramArguments`; `UnsignedBinaryAlert` — Flag execution of unsigned or non-Apple-signed binaries within plist
- **`AN1578` Analytic 1578** · Containers
  Detects creation of new container system processes via `docker run --restart`, `kubectl exec` to init containers, or modification of container init specs. Flags container images that override entrypoints to embed persistence behaviors.
  - *Log sources:* `docker:events` (docker run with restart=always or modifying init); `auditd:SYSCALL` (modification of entrypoint scripts or init containers)
  - *Tune:* `EntrypointOverridePattern` — Patterns used to detect modified container start scripts; `RestartPolicyMatch` — Policy values triggering alert (e.g., always, on-failure); `KubeInitModPath` — Path filters for `/etc/init.d/`-like behaviors inside containers

---

### T1543.001 — Launch Agent
<a id="t1543001"></a>

**Detection strategy:** Detection of Launch Agent Creation or Modification on macOS (`DET0434`)  
**Platforms:** macOS  
**ATT&CK:** [T1543.001](https://attack.mitre.org/techniques/T1543/001/) · [detail page](../../techniques/persistence.md#t1543001)

- **`AN1208` Analytic 1208** · macOS
  Detects creation or modification of user-level Launch Agents in monitored directories using `.plist` files with suspicious `ProgramArguments` or `RunAtLoad` keys. Correlates file write activity with execution of `launchctl` or unsigned binaries invoked at login.
  - *Log sources:* `macos:unifiedlog` (launchctl load or boot-time plist registration); `fs:fsusage` (write or chmod to ~/Library/LaunchAgents/*.plist); `fs:fsusage` (modification of existing LaunchAgents plist); `macos:osquery` (detection of new launch agents with suspicious paths or unsigned binaries)
  - *Tune:* `PlistDirectoryList` — Monitored directories (e.g., `/Library/LaunchAgents`, `~/Library/LaunchAgents`) for plist drops; `PlistKeyMonitor` — Monitored keys such as `RunAtLoad`, `KeepAlive`, or `ProgramArguments` for policy alignment; `ExecutablePathPattern` — Patterns used to detect execution from non-standard or suspicious locations like `/tmp`, `/var`, or `/Users/Shared`; `UnsignedBinaryAlert` — Raise alerts if the binary referenced in the Launch Agent is unsigned or unverified; `UserContextScope` — List of users whose LaunchAgents are considered high-sensitivity (e.g., admins)

---

### T1543.002 — Systemd Service
<a id="t1543002"></a>

**Detection strategy:** Detection of Systemd Service Creation or Modification on Linux (`DET0253`)  
**Platforms:** Linux  
**ATT&CK:** [T1543.002](https://attack.mitre.org/techniques/T1543/002/) · [detail page](../../techniques/persistence.md#t1543002)

- **`AN0701` Analytic 0701** · Linux
  Detects the creation or modification of `.service` unit files in system/user-level directories, combined with execution of `systemctl`, `service`, or dynamically created drop-ins via systemd generators. Detects persistence by analyzing the `ExecStart` path, file entropy, and symlink usage, especially when paired with execution from `/tmp`, `/dev/shm`, or unmounted volumes.
  - *Log sources:* `auditd:SYSCALL` (write, open, or rename to /etc/systemd/system/*.service); `auditd:SYSCALL` (modification of existing .service file); `auditd:SYSCALL` (execution of systemctl or service with enable/start parameters); `auditd:SYSCALL` (fork/exec of service via PID 1 (systemd)); `linux:osquery` (newly registered unit file with ExecStart pointing to unknown binary)
  - *Tune:* `ServicePathRegex` — Regex filters for systemd unit locations (e.g., `/etc/systemd/system/*.service`, `/lib/systemd/system/`); `ExecStartPathAllowlist` — Allowlist of trusted `ExecStart` binary paths (e.g., `/usr/bin/`, `/bin/`); `UserContextFilter` — List of usernames that are authorized to define user-level services; `FileEntropyThreshold` — Entropy level of binaries referenced in `ExecStart` to detect packed or obfuscated payloads; `SystemctlOperationSet` — Flags suspicious combinations such as `systemctl enable` + `systemctl start` within short interval

---

### T1543.003 — Windows Service
<a id="t1543003"></a>

**Detection strategy:** Detection of Windows Service Creation or Modification (`DET0552`)  
**Platforms:** Windows  
**ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003/) · [detail page](../../techniques/persistence.md#t1543003)

- **`AN1527` Analytic 1527** · Windows
  Detects creation or modification of Windows Services through command-line tools (e.g., `sc.exe`, `powershell.exe`), Registry key changes under `HKLM\System\CurrentControlSet\Services`, and service execution under SYSTEM with unsigned or anomalous binary paths. Detects privilege escalation via driver installation or `CreateServiceW` usage. Correlates parent-child lineage, startup behavior, and rare service names.
  - *Log sources:* `WinEventLog:Security` (EventCode=4697); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:Sysmon` (EventCode=6)
  - *Tune:* `ServiceNamePattern` — Regex for suspicious or uncommon service names (e.g., `svhostx`, `winhelp`, etc.); `ImagePathFilter` — Flag services whose image path resides in uncommon directories (e.g., `C:\Users\`, `C:\Temp\`); `DriverExtensionList` — Watch for `.sys` files loaded by `sc`, Registry, or `ZwLoadDriver` APIs; `StartupTypeChangeWindow` — Temporal window to correlate Registry `Start` key changes with service creation; `UnsignedBinaryAlert` — Raise alerts for unsigned binaries registered as services

---

### T1543.004 — Launch Daemon
<a id="t1543004"></a>

**Detection strategy:** Detection Strategy for Launch Daemon Creation or Modification (macOS) (`DET0401`)  
**Platforms:** macOS  
**ATT&CK:** [T1543.004](https://attack.mitre.org/techniques/T1543/004/) · [detail page](../../techniques/persistence.md#t1543004)

- **`AN1126` Analytic 1126** · macOS
  Creation or modification of `.plist` files in /Library/LaunchDaemons/, especially those with suspicious Program or ProgramArguments paths, combined with execution activity under launchd with elevated privileges. Detectable through correlated Unified Logs, file monitoring, and process telemetry.
  - *Log sources:* `macos:unifiedlog` (launchd spawning processes tied to new or modified LaunchDaemon .plist entries); `fs:launchdaemons` (file_create); `fs:launchdaemons` (file_modify); `macos:unifiedlog` (launchd loading new LaunchDaemon or changes to existing daemon configuration)
  - *Tune:* `ProgramPathRegex` — Regex patterns to match anomalous executable paths or names in .plist files; `TimeWindow` — Correlation window between file modification and launchd process execution; `UserContext` — Admin or root context used during daemon installation; `UnsignedBinaryFlag` — Whether the binary associated with the LaunchDaemon is signed or trusted

---

### T1543.005 — Container Service
<a id="t1543005"></a>

**Detection strategy:** Detect persistent or elevated container services via container runtime or cluster manipulation (`DET0473`)  
**Platforms:** Containers  
**ATT&CK:** [T1543.005](https://attack.mitre.org/techniques/T1543/005/) · [detail page](../../techniques/persistence.md#t1543005)

- **`AN1304` Analytic 1304** · Containers
  Correlate the creation or modification of containers using restart policies (e.g., 'always') or DaemonSets with elevated host access, service account misuse, or privileged container contexts. Watch for manipulation of systemd units involving containers or pod scheduling targeting specific nodes or namespaces.
  - *Log sources:* `auditd:SYSCALL` (execve); `systemd:unit` (container run with restart policy set to 'always' or 'unless-stopped'); `kubernetes:audit` (create); `kubernetes:audit` (create)
  - *Tune:* `restartPolicy` — Tune for environments that legitimately use 'always' or 'unless-stopped' in trusted containers; `targetNamespace` — Scope detection to high-risk namespaces (e.g., kube-system); `nodeSelector|nodeName` — Adjust if targeting known cluster configurations or test environments; `unitFilePath` — Adapt to your OS/systemd hierarchy and container binary references; `TimeWindow` — Adjust temporal correlation (e.g., container launch → privilege escalation)

---

### T1546.017 — Udev Rules
<a id="t1546017"></a>

**Detection strategy:** Detection Strategy for T1546.017 - Udev Rules (Linux) (`DET0375`)  
**Platforms:** Linux  
**ATT&CK:** [T1546.017](https://attack.mitre.org/techniques/T1546/017/) · [detail page](../../techniques/persistence.md#t1546017)

- **`AN1056` Analytic 1056** · Linux
  Monitor for creation or modification of udev rules files in key directories (/etc/udev/rules.d/, /lib/udev/rules.d/, /usr/lib/udev/rules.d/). Look for RUN+= or IMPORT keys invoking suspicious binaries or scripts. Correlate this with process execution from systemd-udevd context, and file writes near udev reload/restart events. Combine this with unexpected background process spawning from udevd-related forks.
  - *Log sources:* `auditd:SYSCALL` (chmod, write, create, open); `auditd:SYSCALL` (execve); `auditd:CONFIG_CHANGE` (udev rule reload or trigger command executed)
  - *Tune:* `UdevRulePath` — Path to udev rules (may vary by distro or user configuration); `SuspiciousRunPattern` — Regex or string pattern to flag suspicious command executions in RUN+=; `TimeWindow` — Max interval between rule change and execution to correlate activity; `ParentProcess` — Expected parent of RUN-invoked commands (e.g., systemd-udevd)

---

### T1546.018 — Python Startup Hooks
<a id="t1546018"></a>

**Detection strategy:** Linux Python Startup Hook Persistence via .pth and Customize Files (T1546.018) (`DET0258`)  
**Platforms:** Linux  
**ATT&CK:** [T1546.018](https://attack.mitre.org/techniques/T1546/018/) · [detail page](../../techniques/persistence.md#t1546018)

- **`AN0713` Analytic 0713** · Linux
  Defender observes unauthorized modification or creation of Python hook files such as `.pth`, `sitecustomize.py`, or `usercustomize.py` in Python `site-packages`, `dist-packages`, or user paths. This is often correlated with subsequent unexpected interpreter execution (e.g., python3 running without user interaction), changes in interpreter behavior (e.g., malicious imports), and outbound connections initiated from Python. Defender links write/modify actions on hook files with execve of python process and/or anomalous child process or network activity.
  - *Log sources:* `auditd:SYSCALL` (execve: execve where exe=/usr/bin/python3 or similar interpreter); `auditd:PATH` (write or create events on *.pth, sitecustomize.py, usercustomize.py in site-packages or dist-packages); `auditd:CONFIG_CHANGE` (chmod or chown of hook files indicating privilege escalation or execution permission change); `NSM:Flow` (http::request: Outbound HTTP initiated by Python interpreter)
  - *Tune:* `HookFilePathPatterns` — Absolute or regex paths to Python startup files (.pth, customize.py); vary by distro or virtual environment location; `UserContext` — Restrict alerts to non-root users, service accounts, or interactive shell sessions; `TimeWindow` — Correlate file modification and Python execution within short time span (default: 2–5 minutes); `InterpreterWhitelist` — Filter out known legitimate Python executions tied to expected cron jobs or automation

---

### T1547 — Boot or Logon Autostart Execution
<a id="t1547"></a>

**Detection strategy:** Boot or Logon Autostart Execution Detection Strategy (`DET0274`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1547](https://attack.mitre.org/techniques/T1547/) · [detail page](../../techniques/persistence.md#t1547)

- **`AN0764` Analytic 0764** · Windows
  Correlation of registry key modification for Run/RunOnce with abnormal parent-child process relationships and outlier execution at user logon or system startup
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=13, 14)
  - *Tune:* `ParentProcessName` — Customize based on expected parent-child process lineage for autostarts; `StartupRegistryPath` — May vary based on organization policy or installed software
- **`AN0765` Analytic 0765** · Linux
  Correlates creation/modification of systemd service files or /etc/init.d scripts with outlier process behavior during boot
  - *Log sources:* `auditd:SYSCALL` (creat); `auditd:SYSCALL` (write); `auditd:SYSCALL` (Execution of binaries located in /etc/init.d/ or systemd service paths)
  - *Tune:* `FilePath` — Organizations may use different init systems or custom startup paths; `UserContext` — Autostart scripts should run as root or system users; deviations are suspect
- **`AN0766` Analytic 0766** · macOS
  Observes creation or modification of LaunchAgent/LaunchDaemon property list files combined with anomalous plist payload execution after user logon
  - *Log sources:* `macos:unifiedlog` (Observed loading of new LaunchAgent or LaunchDaemon plist); `macos:unifiedlog` (write); `macos:unifiedlog` (Execution of binary listed in newly modified LaunchAgent plist)
  - *Tune:* `PlistKey` — Organizations may use specific keys or additional payload parameters; `TimeWindow` — Tunable based on expected delay between plist write and execution

---

### T1547.001 — Registry Run Keys / Startup Folder
<a id="t1547001"></a>

**Detection strategy:** Detect Registry and Startup Folder Persistence (Windows) (`DET0365`)  
**Platforms:** Windows  
**ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/) · [detail page](../../techniques/persistence.md#t1547001)

- **`AN1032` Analytic 1032** · Windows
  Correlation of Registry key creation/modification events under known Run/Startup keys with new or unusual binary paths or script-based payloads. Multi-event detection includes registry modification followed by process execution from non-standard directories or abnormal parent-child process relationships.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:Microsoft-Windows-Shell-Core` (New startup folder shortcut or binary placed in Startup directory)
  - *Tune:* `ImagePath` — Full path of the binary/script being registered in Run keys. Tunable to exclude known software baselines.; `RegistryKeyPath` — Tunable list of startup-related registry keys to monitor more/less aggressively based on enterprise software context.; `TimeWindow` — Correlate registry key creation and process execution within this window. Defaults between 5–10 minutes.; `UserContext` — Filter for specific user SIDs or exclude known admin/script accounts.

---

### T1547.002 — Authentication Package
<a id="t1547002"></a>

**Detection strategy:** Detect LSA Authentication Package Persistence via Registry and LSASS DLL Load (`DET0207`)  
**Platforms:** Windows  
**ATT&CK:** [T1547.002](https://attack.mitre.org/techniques/T1547/002/) · [detail page](../../techniques/persistence.md#t1547002)

- **`AN0583` Analytic 0583** · Windows
  Registry modification of the LSA Authentication Packages key followed by LSASS loading a non-standard or unsigned DLL. This includes unusual write access to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`, especially during non-installation timeframes. Correlated with `lsass.exe` loading DLLs not present in baseline or lacking valid signatures.
  - *Log sources:* `WinEventLog:Security` (EventCode=4657); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `TimeWindow` — Time between registry write and DLL load; tune based on reboot cycles or scheduled maintenance; `ImageSignatureStatus` — Allow listing of known signed LSASS-authenticated DLLs versus unknown/untrusted ones; `RegistryPathScope` — Allow tuning for subkeys beyond just `Authentication Packages` (e.g., `Security Packages`, `Notification Packages`); `UserContext` — Correlate user responsible for registry edit; tune for expected administrative/service accounts; `ParentProcess` — Validate process lineage for registry modification; expected tools like `reg.exe` or `powershell.exe`

---

### T1547.003 — Time Providers
<a id="t1547003"></a>

**Detection strategy:** Detect Abuse of Windows Time Providers for Persistence (`DET0122`)  
**Platforms:** Windows  
**ATT&CK:** [T1547.003](https://attack.mitre.org/techniques/T1547/003/) · [detail page](../../techniques/persistence.md#t1547003)

- **`AN0341` Analytic 0341** · Windows
  Behavioral correlation of privileged registry key creation under the W32Time TimeProviders path combined with a new DLL written to disk and potential process activity by LocalService. Indicates abuse of Time Providers for persistence.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `RegistryPathScope` — May need to be tuned to only monitor `W32Time\TimeProviders` subkey path for performance optimization; `UserContext` — Should focus on activity from administrative or SYSTEM accounts; `TimeWindow` — Controls correlation window between registry modification and DLL drop; `DllPathEntropyThreshold` — Used for anomaly scoring on DLL path patterns (e.g., random names or temp directories)

---

### T1547.004 — Winlogon Helper DLL
<a id="t1547004"></a>

**Detection strategy:** Detect Winlogon Helper DLL Abuse via Registry and Process Artifacts on Windows (`DET0404`)  
**Platforms:** Windows  
**ATT&CK:** [T1547.004](https://attack.mitre.org/techniques/T1547/004/) · [detail page](../../techniques/persistence.md#t1547004)

- **`AN1133` Analytic 1133** · Windows
  Monitor Windows Registry modifications to Winlogon keys (Shell, Userinit, Notify) that introduce new executable or DLL paths. Correlate these changes with subsequent DLL loading, image loads, or process creation originating from winlogon.exe or userinit.exe. Abnormal child process lineage or unauthorized binaries in C:\Windows\System32 may indicate abuse.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Security` (modification to Winlogon registry keys such as Shell, Notify, or Userinit); `Autoruns:RegistryScan` (Enumerate Winlogon subkeys for unknown or unsigned binaries)
  - *Tune:* `TimeWindow` — Time correlation between registry modification and malicious module load or process creation; `UserContext` — Privilege level or user context under which registry changes or process executions occur; `BinarySignatureValidation` — Whether to validate binary signatures when DLLs are loaded via Winlogon helper paths; `ExecutablePathScope` — Scope of directories considered suspicious for helper DLLs (e.g., temp paths, non-System32 locations)

---

### T1547.005 — Security Support Provider
<a id="t1547005"></a>

**Detection strategy:** Registry and LSASS Monitoring for Security Support Provider Abuse (`DET0542`)  
**Platforms:** Windows  
**ATT&CK:** [T1547.005](https://attack.mitre.org/techniques/T1547/005/) · [detail page](../../techniques/persistence.md#t1547005)

- **`AN1495` Analytic 1495** · Windows
  Monitor registry modifications to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` or `...\OSConfig\Security Packages`, especially insertions of new DLL entries. Correlate this with subsequent DLL module loads into `lsass.exe`. Track unsigned or anomalous DLLs loading into LSASS using image load auditing. LSASS loads unsigned DLL due to AuditLevel=8 registry configuration or System reboot followed by DLL load into lsass.exe
  - *Log sources:* `WinEventLog:Security` (EventCode=4657); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `TimeWindow` — Controls how long after registry modification to expect a DLL load into LSASS (e.g., after reboot); `DLLSignatureValidation` — Use to detect unsigned DLLs or those not matching known trusted publisher certificates; `CustomSSPNameList` — Define allowed SSP values for your org to reduce false positives; `BootContextCorrelation` — Whether detection should correlate boot-time registry and process events

---

### T1547.006 — Kernel Modules and Extensions
<a id="t1547006"></a>

**Detection strategy:** Detection Strategy for Kernel Modules and Extensions Autostart Execution (`DET0450`)  
**Platforms:** Linux, macOS  
**ATT&CK:** [T1547.006](https://attack.mitre.org/techniques/T1547/006/) · [detail page](../../techniques/persistence.md#t1547006)

- **`AN1243` Analytic 1243** · Linux
  Monitor kernel module load/unload activity via modprobe, insmod, rmmod, or direct manipulation of /lib/modules. Correlate with installation of kernel headers, compilation commands, or downloads of .ko files. Detect anomalies in unsigned module loading or repeated module load attempts under non-root users.
  - *Log sources:* `auditd:SYSCALL` (Execution of insmod, modprobe, or rmmod commands by non-standard users or outside expected timeframes); `auditd:SYSCALL` (Access or modification to /lib/modules or creation of .ko files); `linux:osquery` (New or modified kernel object files (.ko) within /lib/modules directory)
  - *Tune:* `UserContext` — Scope detection to non-root or unexpected users performing module-related activity; `TimeWindow` — Limit alerts to module activity outside approved change windows; `FilePathRegex` — Adjust regex pattern for directories to monitor depending on kernel version or distro
- **`AN1244` Analytic 1244** · macOS
  Detect user-initiated kextload commands or modifications to /Library/Extensions. Correlate with changes to KextPolicy database or unauthorized developer signing identities. Alert on attempts to disable SIP or load legacy extensions from unsigned sources.
  - *Log sources:* `macos:unifiedlog` (kextload execution from Terminal or suspicious paths); `macos:osquery` (Processes executing kextload, spctl, or modifying kernel extension directories); `macos:osquery` (New kext entries not signed by Apple or outside standard identifier prefix); `macos:osquery` (Modifications to /var/db/SystemPolicyConfiguration/KextPolicy or kext_policy table)
  - *Tune:* `DeveloperIDAllowlist` — Approved developer IDs whose kexts should not trigger alerts; `KextLoadTimeWindow` — Threshold for detecting kext loads outside standard install/update operations; `SignatureCheckFlag` — Flag to enforce strict signing checks depending on SIP status

---

### T1547.007 — Re-opened Applications
<a id="t1547007"></a>

**Detection strategy:** Detect persistence via reopened application plist modification (macOS) (`DET0125`)  
**Platforms:** macOS  
**ATT&CK:** [T1547.007](https://attack.mitre.org/techniques/T1547/007/) · [detail page](../../techniques/persistence.md#t1547007)

- **`AN0349` Analytic 0349** · macOS
  Unusual modification or creation of loginwindow-related plist files in '~/Library/Preferences/ByHost' correlated with unauthorized application paths and execution upon login.
  - *Log sources:* `macos:unifiedlog` (Execution of process launched via loginwindow session restore); `fs:filesystem` (Modification or creation of files matching 'com.apple.loginwindow.*.plist' in ~/Library/Preferences/ByHost); `macos:unifiedlog` (LoginWindow context with associated PID linked to reopened plist paths); `macos:endpointsecurity` (es_event_file_rename_t or es_event_file_write_t)
  - *Tune:* `UserContext` — Restrict to targeted users or unexpected users writing to plist; `FilePathPattern` — Allow tuning for alternative persistence paths or directory redirection; `TimeWindow` — Correlate plist write and process execution within logon window; `BinaryAnomalyScore` — Optional scoring of launched binary based on code signing, entropy, and known safe apps

---

### T1547.008 — LSASS Driver
<a id="t1547008"></a>

**Detection strategy:** Detect unauthorized LSASS driver persistence via LSA plugin abuse (Windows) (`DET0225`)  
**Platforms:** Windows  
**ATT&CK:** [T1547.008](https://attack.mitre.org/techniques/T1547/008/) · [detail page](../../techniques/persistence.md#t1547008)

- **`AN0629` Analytic 0629** · Windows
  Unauthorized creation or modification of DLLs loaded by LSASS, abnormal registry values under LSA extensions, and anomalous DLL load activity into the lsass.exe process context—correlated during boot or logon events.
  - *Log sources:* `WinEventLog:Security` (EventCode=3033); `WinEventLog:Sysmon` (EventCode=6); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=2); `WinEventLog:Sysmon` (EventCode=12); `WinEventLog:Sysmon` (EventCode=13, 14)
  - *Tune:* `TimeWindow` — Correlate DLL file creation/modification with LSASS execution within a configurable timeframe (e.g., 5 min); `ImagePathPattern` — Tune based on known legitimate LSASS plugin DLL paths; `SignatureValidation` — Flag unsigned DLLs loaded into lsass.exe or those signed by unexpected publishers; `RegistryKeyScope` — Scope to specific registry keys: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages; `FileHashAllowList` — Exclude known-good LSASS plugin DLLs based on cryptographic hash

---

### T1547.009 — Shortcut Modification
<a id="t1547009"></a>

**Detection strategy:** Detection Strategy for T1547.009 – Shortcut Modification (Windows) (`DET0180`)  
**Platforms:** Windows  
**ATT&CK:** [T1547.009](https://attack.mitre.org/techniques/T1547/009/) · [detail page](../../techniques/persistence.md#t1547009)

- **`AN0510` Analytic 0510** · Windows
  Detection correlates file creation or modification of `.lnk` (shortcut) files in autostart locations with anomalous parent-child process lineage or unsigned binaries. Defenders should watch for LNK creation/modification events outside of known software installations, patch events, or OS updates. Flag shortcut targets pointing to suspicious locations or unknown binaries, particularly those written by script interpreters or spawned from phishing delivery chains.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=2); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=15)
  - *Tune:* `TargetPathRegex` — Tunable regex to flag suspicious shortcut target paths (e.g., temp folder, base64 in target, unusual executable names); `TimeWindow` — Time window used to correlate shortcut creation with process execution (e.g., 5-minute window); `UserContextScope` — Filter for expected administrative installs versus end-user initiated shortcut creation; `ZoneIdentifierThreshold` — Configurable value to filter LNK files tagged with external source markers (e.g., ZoneId=3 for Internet)

---

### T1547.010 — Port Monitors
<a id="t1547010"></a>

**Detection strategy:** Detection Strategy for T1547.010 – Port Monitor DLL Persistence via spoolsv.exe (Windows) (`DET0204`)  
**Platforms:** Windows  
**ATT&CK:** [T1547.010](https://attack.mitre.org/techniques/T1547/010/) · [detail page](../../techniques/persistence.md#t1547010)

- **`AN0580` Analytic 0580** · Windows
  Detects suspicious registry modifications under `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\*\Driver`, DLL loads by `spoolsv.exe` of non-standard or unsigned modules, and abnormal usage of the `AddMonitor` API by non-installation processes. This pattern often indicates an attempt to persist a malicious DLL via the print monitor mechanism, particularly when correlated with creation of files in `C:\Windows\System32` not tied to known patches or installations.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=13); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Application` (API call to AddMonitor invoked by non-installer process)
  - *Tune:* `TargetDLLDirectory` — Expected directory path for legitimate monitor DLLs (e.g., C:\Windows\System32); `SignedImageValidation` — Enable/disable signature validation on DLLs loaded by spoolsv.exe; `UserContextScope` — Define whether only SYSTEM/user installs are expected to make changes to the port monitor registry keys; `TimeWindow` — Timeframe between registry modification and subsequent spoolsv.exe DLL load; `AddMonitorCallContext` — Filter on calling process of AddMonitor API to detect anomalies outside installer/updater

---

### T1547.012 — Print Processors
<a id="t1547012"></a>

**Detection strategy:** Windows Detection Strategy for T1547.012 - Print Processor DLL Persistence (`DET0026`)  
**Platforms:** Windows  
**ATT&CK:** [T1547.012](https://attack.mitre.org/techniques/T1547/012/) · [detail page](../../techniques/persistence.md#t1547012)

- **`AN0074` Analytic 0074** · Windows
  Correlated registry modifications under Print Processors path, followed by DLL file creation within the system print processor directory, and DLL load by spoolsv.exe. Malicious execution often occurs during service restart or system boot, with SYSTEM-level privileges.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=10)
  - *Tune:* `TimeWindow` — Correlate Registry + DLL Write + Module Load within a short boot or spooler restart window (e.g., 5 minutes).; `PrintProcessorDirectory` — System-specific path derived from GetPrintProcessorDirectory API call; may differ across Windows versions or configurations.; `DLLNamePattern` — Some environments may use custom or non-standard DLL naming conventions for print processors. Allowlist known values.; `SignedImageValidation` — Check Authenticode signature and issuer chain for loaded DLLs to reduce false positives.; `ServiceRestartTrigger` — Monitor for spoolsv.exe restart events that trigger malicious print processor loading.

---

### T1547.013 — XDG Autostart Entries
<a id="t1547013"></a>

**Detection strategy:** Linux Detection Strategy for T1547.013 - XDG Autostart Entries (`DET0390`)  
**Platforms:** Linux  
**ATT&CK:** [T1547.013](https://attack.mitre.org/techniques/T1547/013/) · [detail page](../../techniques/persistence.md#t1547013)

- **`AN1096` Analytic 1096** · Linux
  Correlation of file creation/modification of `.desktop` files within XDG autostart directories, followed by execution of processes at user login initiated by the desktop environment. Malicious entries typically include suspicious Exec paths or anomalous names and are not associated with installed packages.
  - *Log sources:* `auditd:SYSCALL` (creat); `auditd:SYSCALL` (open); `auditd:EXECVE` (Process execution via .desktop Exec path from /etc/xdg/autostart or ~/.config/autostart); `linux:osquery` (Write or modify .desktop file in XDG autostart path); `linux:auth` (User login event followed by unexpected process tree)
  - *Tune:* `ExecCommandPattern` — Regex or allowlist of expected Exec paths within .desktop files. Deviations may be suspicious.; `AutostartDirectory` — May vary by user config (e.g., $XDG_CONFIG_HOME). Must enumerate actual values per system.; `TimeWindow` — Correlate file creation/mod + exec within login window (e.g., 0–5 min of user logon).; `UserContext` — Should filter to non-system users, as XDG persistence typically targets interactive sessions.; `PackageOriginBaseline` — Compare .desktop entries to known package sources (e.g., `dpkg -S`). Unexpected origins may be suspicious.

---

### T1547.014 — Active Setup
<a id="t1547014"></a>

**Detection strategy:** Detect Active Setup Persistence via StubPath Execution (`DET0312`)  
**Platforms:** Windows  
**ATT&CK:** [T1547.014](https://attack.mitre.org/techniques/T1547/014/) · [detail page](../../techniques/persistence.md#t1547014)

- **`AN0871` Analytic 0871** · Windows
  Multi-event correlation of Registry creation under Active Setup with anomalous execution of processes at user logon. Behavioral patterns include creation/modification of HKLM Active Setup keys with non-standard StubPath values, followed by process execution from uncommon paths, unsigned binaries, or unusual parent-child lineage post-user login.
  - *Log sources:* `WinEventLog:Security` (EventCode=4672); `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:Sysmon` (EventCode=12)
  - *Tune:* `TimeWindow` — Correlate registry change and process execution within a specific user logon session (e.g., 5–10 minutes); `ParentProcessName` — Expected parent processes for Active Setup launched binaries (e.g., explorer.exe). Deviations may indicate abuse.; `StubPathValueEntropy` — Degree of randomness/uncommonness in StubPath values. High entropy may indicate obfuscation.; `SignedBinaryStatus` — Flag if launched binary in StubPath is unsigned or uncommon for baseline; `RegistryKeyOwner` — Check which user/context added the Active Setup key to detect privilege abuse

---

### T1547.015 — Login Items
<a id="t1547015"></a>

**Detection strategy:** Detection Strategy for T1547.015 – Login Items on macOS (`DET0121`)  
**Platforms:** macOS  
**ATT&CK:** [T1547.015](https://attack.mitre.org/techniques/T1547/015/) · [detail page](../../techniques/persistence.md#t1547015)

- **`AN0340` Analytic 0340** · macOS
  Creation or modification of Login Items using AppleScript or Service Management Framework. Detection focuses on file creation/modification of `backgrounditems.btm`, new executables in `Contents/Library/LoginItems/`, use of `SMLoginItemSetEnabled` API, or suspicious processes triggered post-login without user interaction. Behavioral pivot includes anomalous AppleEvents, suspicious parent-child process pairs, and login-triggered execution chains.
  - *Log sources:* `macos:unifiedlog` (Post-login execution of unrecognized child process from launchd or loginwindow); `macos:unifiedlog` (Modification of backgrounditems.btm or creation of LoginItems subdirectory in .app bundle); `macos:unifiedlog` (Invocation of SMLoginItemSetEnabled by non-system or recently installed application); `macos:unifiedlog` (AppleScript creating login item via 'System Events' dictionary)
  - *Tune:* `TimeWindow` — Correlate file and process activity within a defined interval post-login (e.g., 0–5 minutes); `UserContext` — Distinguish between system users, interactive users, and daemon contexts; `ExecutableAllowlist` — Define known-good login items to suppress false positives; `PathRegexExclusion` — Exclude common enterprise paths (e.g., Jamf, MDM-managed apps)

---

### T1554 — Compromise Host Software Binary
<a id="t1554"></a>

**Detection strategy:** Detect Compromise of Host Software Binaries (`DET0336`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1554](https://attack.mitre.org/techniques/T1554/) · [detail page](../../techniques/persistence.md#t1554)

- **`AN0949` Analytic 0949** · Windows
  Monitors for unexpected modifications of system or application binaries, particularly signed executables. Correlates file write events with subsequent unsigned or anomalously signed process execution, and checks for tampered binaries outside normal patch cycles.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=2); `WinEventLog:Security` (EventCode=4688)
  - *Tune:* `MonitoredPaths` — Define critical directories (e.g., C:\Windows\System32, Program Files) for binary integrity checks; `SignatureValidation` — Adjust enforcement level of digital signature verification based on enterprise risk appetite; `TimeWindow` — Correlate file modification with subsequent process execution within a defined time window
- **`AN0950` Analytic 0950** · Linux
  Detects modification of system or application binaries by monitoring /usr/bin, /bin, and other privileged directories. Correlates file integrity monitoring (FIM) events with unexpected process executions or service restarts.
  - *Log sources:* `auditd:SYSCALL` (open, write); `auditd:EXECVE` (execve)
  - *Tune:* `WatchedDirectories` — Customize monitored directories (e.g., /usr/bin, /usr/sbin, /opt/apps) for binary tampering; `BaselineHashes` — Maintain golden file hashes for integrity validation
- **`AN0951` Analytic 0951** · macOS
  Monitors binary modification in /Applications and system library paths. Detects unsigned or improperly signed binaries executed after modification. Tracks Gatekeeper or notarization bypass attempts tied to modified binaries.
  - *Log sources:* `macos:unifiedlog` (binary modified or replaced); `macos:unifiedlog` (execution of modified binary without valid signature)
  - *Tune:* `ApplicationPaths` — Tune which application and library directories are monitored for tampering; `SignatureVerificationDepth` — Define strictness of code-signing validation checks
- **`AN0952` Analytic 0952** · ESXi
  Detects unauthorized modification of host binaries, modules, or services within ESXi. Correlates tampered files with subsequent unexpected service behavior or malicious module load attempts.
  - *Log sources:* `esxi:hostd` (binary or module replacement event); `esxi:vmkernel` (unexpected module load)
  - *Tune:* `MonitoredModules` — Define critical ESXi binaries and kernel modules requiring integrity validation; `CorrelationWindow` — Adjust timing correlation between binary modification and module/service anomalies

---

### T1574 — Hijack Execution Flow
<a id="t1574"></a>

**Detection strategy:** Detection Strategy for Hijack Execution Flow across OS platforms. (`DET0218`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1574](https://attack.mitre.org/techniques/T1574/) · [detail page](../../techniques/persistence.md#t1574)

- **`AN0609` Analytic 0609** · Windows
  Unusual modifications to service binary paths, registry keys, or DLL load paths resulting in alternate execution flow. Defender observes registry key modifications, suspicious file writes into system directories, and processes loading libraries from abnormal paths.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Security` (EventCode=4657); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `ServiceBaseline` — Expected registry keys and service paths for comparison.; `AllowedDllPaths` — Directories considered valid for DLL loading.; `TimeWindow` — Correlation interval between registry/file modification and process execution.
- **`AN0610` Analytic 0610** · Linux
  Adversary manipulation of shared library paths, environment variables, or replacement of service binaries. Defender observes suspicious modifications in /etc/ld.so.preload, service config changes, or file writes replacing existing executables.
  - *Log sources:* `auditd:SYSCALL` (open/write syscalls targeting /etc/ld.so.preload or binaries in /usr/bin); `linux:syslog` (Service restart with modified executable path); `linux:osquery` (Process execution with LD_PRELOAD or modified library path)
  - *Tune:* `MonitoredDirectories` — Directories where binary replacement should trigger alerts.; `EnvVarMonitors` — Environment variables like LD_PRELOAD or PATH to monitor.
- **`AN0611` Analytic 0611** · macOS
  Abuse of DYLD_INSERT_LIBRARIES or hijacking framework paths for malicious libraries. Defender observes processes invoking abnormal dylibs, modified plist files, or persistence entries pointing to altered binaries.
  - *Log sources:* `macos:unifiedlog` (Execution of process with DYLD_INSERT_LIBRARIES set); `macos:unifiedlog` (Modified application plist or binary replacement in /Applications); `macos:unifiedlog` (Dylib loaded from abnormal location)
  - *Tune:* `AllowedDylibPaths` — Baseline directories for dylib loading.; `PlistMonitors` — Specific plist files used for persistence monitoring.

---

### T1574.001 — DLL
<a id="t1574001"></a>

**Detection strategy:** Detection Strategy for Hijack Execution Flow for DLLs (`DET0201`)  
**Platforms:** Windows  
**ATT&CK:** [T1574.001](https://attack.mitre.org/techniques/T1574/001/) · [detail page](../../techniques/persistence.md#t1574001)

- **`AN0577` Analytic 0577** · Windows
  DLL hijacking behaviors including unexpected DLL loads from non-standard directories, replacement of DLLs, phantom DLL insertion, redirection file creation, and substitution of legitimate DLLs. Defender correlates file system modifications, registry changes, and module load telemetry to detect abnormal DLL behavior in trusted processes.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=15); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Security` (EventCode=4657); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `AllowedDllPaths` — Known safe DLL directories to suppress false positives (e.g., C:\Windows\System32).; `ProcessAllowList` — Applications expected to load DLLs from non-standard locations (e.g., development tools).; `TimeWindow` — Correlation interval between DLL file creation, registry changes, and module load.; `HashBaseline` — Baseline hashes for legitimate DLLs used to detect substitution.

---

### T1574.004 — Dylib Hijacking
<a id="t1574004"></a>

**Detection strategy:** Detection Strategy for Hijack Execution Flow: Dylib Hijacking (`DET0152`)  
**Platforms:** macOS  
**ATT&CK:** [T1574.004](https://attack.mitre.org/techniques/T1574/004/) · [detail page](../../techniques/persistence.md#t1574004)

- **`AN0435` Analytic 0435** · macOS
  Detection focuses on adversaries placing or modifying malicious dylibs in locations searched by legitimate applications. From the defender’s perspective, observable patterns include unexpected creation or modification of dylib files in application bundle paths, unusual module loads by processes compared to historical baselines, and execution of applications loading dylibs from suspicious directories (e.g., /tmp, user-controlled paths). Correlation across file system changes, process execution, and module loads provides high-fidelity detection.
  - *Log sources:* `macos:unifiedlog` (process execution events with dylib load activity); `macos:unifiedlog` (create/modify dylib files in monitored directories); `macos:unifiedlog` (replace existing dylibs)
  - *Tune:* `MonitoredDirectories` — Application bundle directories (e.g., /Applications/*/Contents/MacOS, /Library/Frameworks). Adversaries may use non-standard paths like /tmp.; `BaselineDylibs` — Historical record of dylibs typically loaded by applications. Deviations should be flagged.; `CorrelationWindow` — Timeframe to correlate dylib file modification with subsequent process execution and module loads.

---

### T1574.005 — Executable Installer File Permissions Weakness
<a id="t1574005"></a>

**Detection strategy:** Detection Strategy for Hijack Execution Flow using Executable Installer File Permissions Weakness (`DET0038`)  
**Platforms:** Windows  
**ATT&CK:** [T1574.005](https://attack.mitre.org/techniques/T1574/005/) · [detail page](../../techniques/persistence.md#t1574005)

- **`AN0108` Analytic 0108** · Windows
  Executables written or modified in installer directories (e.g., %TEMP% subdirectories or Program Files installer paths) followed by execution under elevated context. Defender observes abnormal file replacement activity, process creation by installer processes pointing to attacker-supplied binaries, and unexpected module loads in elevated processes.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=15); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `MonitoredDirectories` — Specific writable directories to monitor (e.g., %TEMP%, C:\ProgramData, installer unpack paths).; `HashBaseline` — Known good hashes of installer binaries to detect replacement.; `TimeWindow` — Correlation interval between file overwrite and execution event.; `UserContext` — Differentiate expected admin-installer execution vs. anomalous user writes.

---

### T1574.006 — Dynamic Linker Hijacking
<a id="t1574006"></a>

**Detection strategy:** Detection Strategy for Hijack Execution Flow: Dynamic Linker Hijacking (`DET0435`)  
**Platforms:** Linux, macOS  
**ATT&CK:** [T1574.006](https://attack.mitre.org/techniques/T1574/006/) · [detail page](../../techniques/persistence.md#t1574006)

- **`AN1209` Analytic 1209** · Linux
  Detection focuses on identifying abuse of LD_PRELOAD and related linker variables. Defender perspective: monitor unexpected setting or modification of LD_PRELOAD in shell initialization scripts or environment exports, file creation of suspicious shared libraries, and correlation of these modifications with anomalous process execution. Key signals include execve events with LD_PRELOAD defined, newly created .so files in user directories, and processes hooking libc functions exhibiting abnormal behavior.
  - *Log sources:* `auditd:SYSCALL` (execve with LD_PRELOAD or linker-related environment variables set); `auditd:PATH` (creation of .so files in non-standard directories (e.g., /tmp, /home/*)); `linux:osquery` (process environment variables containing LD_PRELOAD)
  - *Tune:* `WatchedEnvVars` — Environment variables like LD_PRELOAD, LD_LIBRARY_PATH. Defenders can tune based on development vs. production systems.; `MonitoredDirectories` — Non-standard library paths (e.g., /tmp, user home dirs). May be tuned to reduce false positives from benign development activity.; `CorrelationWindow` — Timeframe to correlate suspicious library creation with process execution that loads it.
- **`AN1210` Analytic 1210** · macOS
  Detection centers on DYLD_INSERT_LIBRARIES and DYLD_LIBRARY_PATH abuse. Defender perspective: monitor for modification of these environment variables in shell or plist files, file creation of dylibs in user-controlled paths, and correlation of environment variable usage with unexpected module loads by user applications. Suspicious indicators include processes with DYLD_INSERT_LIBRARIES set, execution of applications loading untrusted dylibs, and anomalies in module load history.
  - *Log sources:* `macos:unifiedlog` (execution of process with DYLD_INSERT_LIBRARIES set); `macos:unifiedlog` (create/modify dylib in monitored directories); `macos:unifiedlog` (loading of unexpected dylibs compared to historical baselines)
  - *Tune:* `WatchedEnvVars` — macOS linker variables like DYLD_INSERT_LIBRARIES. Tunable to development environments where use may be expected.; `BaselineDylibs` — Known dylibs typically loaded by apps. Deviations highlight potential hijacking.; `MonitoredDirectories` — Locations where dylibs are monitored for tampering (e.g., /Applications, /System/Library, /tmp).

---

### T1574.007 — Path Interception by PATH Environment Variable
<a id="t1574007"></a>

**Detection strategy:** Detection Strategy for Hijack Execution Flow using Path Interception by PATH Environment Variable. (`DET0004`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1574.007](https://attack.mitre.org/techniques/T1574/007/) · [detail page](../../techniques/persistence.md#t1574007)

- **`AN0009` Analytic 0009** · Windows
  Abnormal modification of the PATH environment variable or registry keys controlling system paths, combined with execution of binaries named after legitimate system tools from user-writable directories. Defender correlates registry modifications, file creation of suspicious binaries, and process execution paths inconsistent with baseline system directories.
  - *Log sources:* `WinEventLog:Security` (EventCode=4657); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `MonitoredRegistryKeys` — PATH environment keys under HKCU and HKLM to monitor for changes.; `SuspiciousBinaryList` — List of high-value system binaries commonly hijacked (e.g., net.exe, python.exe, powershell.exe).; `TimeWindow` — Correlation window between PATH modification and execution of a hijacked binary.
- **`AN0010` Analytic 0010** · Linux
  User modification of the $PATH environment variable in shell configuration files or direct runtime PATH changes, followed by execution of binaries from user-controlled directories. Defender observes file edits to ~/.bashrc, ~/.profile, or /etc/paths.d and process execution resolving to unexpected binary locations.
  - *Log sources:* `auditd:SYSCALL` (open/write calls modifying ~/.bashrc, ~/.profile, or /etc/paths.d); `linux:osquery` (Execution of binary resolved from $PATH not located in /usr/bin or /bin)
  - *Tune:* `MonitoredShellConfigs` — Set of shell startup files where PATH changes should be flagged.; `AllowedUserBins` — Directories (e.g., /usr/local/bin) considered safe to avoid FP.
- **`AN0011` Analytic 0011** · macOS
  Modification of PATH or HOME environment variables through shell config files, launchctl, or /etc/paths.d entries, combined with process execution from attacker-controlled directories. Defender correlates file changes in /etc/paths.d with process execution resolving to malicious binaries.
  - *Log sources:* `macos:unifiedlog` (File modification in /etc/paths.d or user shell rc files); `macos:unifiedlog` (Process execution path inconsistent with baseline PATH directories)
  - *Tune:* `WatchedPathsDirs` — Monitor /etc/paths.d and $HOME for unauthorized entries.; `TrustedExecutables` — Baseline applications expected in user PATH directories.

---

### T1574.008 — Path Interception by Search Order Hijacking
<a id="t1574008"></a>

**Detection strategy:** Detection Strategy for Hijack Execution Flow using Path Interception by Search Order Hijacking (`DET0564`)  
**Platforms:** Windows  
**ATT&CK:** [T1574.008](https://attack.mitre.org/techniques/T1574/008/) · [detail page](../../techniques/persistence.md#t1574008)

- **`AN1560` Analytic 1560** · Windows
  Processes executing binaries named after legitimate system utilities (e.g., net.exe, findstr.exe, python.exe) from non-standard or application-specific directories, combined with file creation or modification events for such binaries. Defender correlates file writes in vulnerable directories, process execution paths inconsistent with baseline system paths, and abnormal parent-child relationships in process lineage.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=15); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `SuspiciousBinaryList` — Common system utilities often hijacked (e.g., net.exe, cmd.exe, powershell.exe, python.exe).; `MonitoredDirectories` — Directories where executables should not normally be written (e.g., application folders, user profile subdirs).; `TimeWindow` — Correlation window between file creation and subsequent process execution.; `ParentProcessBaseline` — Expected parent processes for critical system binaries, deviations may indicate hijacking.

---

### T1574.009 — Path Interception by Unquoted Path
<a id="t1574009"></a>

**Detection strategy:** Detection Strategy for Hijack Execution Flow through Path Interception by Unquoted Path (`DET0064`)  
**Platforms:** Windows  
**ATT&CK:** [T1574.009](https://attack.mitre.org/techniques/T1574/009/) · [detail page](../../techniques/persistence.md#t1574009)

- **`AN0176` Analytic 0176** · Windows
  Unquoted service or shortcut paths that contain spaces and allow path interception by higher-level executables. Defender observes registry service configurations with unquoted paths, file creation of executables in parent directories of unquoted paths, and subsequent process execution from unexpected locations.
  - *Log sources:* `WinEventLog:Security` (EventCode=4657); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=15)
  - *Tune:* `MonitoredServices` — List of critical services to check for unquoted paths in ImagePath registry keys.; `SuspiciousBinaryList` — Executables with names matching potential interception targets (e.g., program.exe, net.exe).; `TimeWindow` — Correlation interval between file creation in parent directories and execution of unquoted path process.; `BaselineServiceConfig` — Known good service paths for comparison against modified or unquoted values.

---

### T1574.010 — Services File Permissions Weakness
<a id="t1574010"></a>

**Detection strategy:** Detection Strategy for Hijack Execution Flow through Services File Permissions Weakness. (`DET0436`)  
**Platforms:** Windows  
**ATT&CK:** [T1574.010](https://attack.mitre.org/techniques/T1574/010/) · [detail page](../../techniques/persistence.md#t1574010)

- **`AN1211` Analytic 1211** · Windows
  Modification or replacement of service executables due to weak file or directory permissions. Defender observes file writes to service binary paths, unexpected modifications of executables associated with registered services, and subsequent service execution of attacker-supplied binaries under elevated permissions.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=15); `WinEventLog:System` (EventCode=7045); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `MonitoredServices` — List of critical services and their expected executable paths for integrity checking.; `HashBaseline` — Baseline hashes of legitimate service executables for tamper detection.; `TimeWindow` — Correlation interval between file modification of service executables and service execution.; `PrivilegedAccounts` — Accounts allowed to legitimately modify service executables.

---

### T1574.011 — Services Registry Permissions Weakness
<a id="t1574011"></a>

**Detection strategy:** Detection Strategy for Hijack Execution Flow through Service Registry Premission Weakness. (`DET0427`)  
**Platforms:** Windows  
**ATT&CK:** [T1574.011](https://attack.mitre.org/techniques/T1574/011/) · [detail page](../../techniques/persistence.md#t1574011)

- **`AN1195` Analytic 1195** · Windows
  Unauthorized modification of service-related registry keys such as ImagePath, FailureCommand, ServiceDll, or Performance/Parameters keys. Defender correlates registry modifications, anomalous service metadata changes, and subsequent service process executions that deviate from baseline configurations.
  - *Log sources:* `WinEventLog:Security` (EventCode=4657); `WinEventLog:System` (EventCode=7040); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `MonitoredServiceKeys` — Registry subkeys for critical services (ImagePath, ServiceDll, FailureCommand, Parameters).; `BaselineServiceConfig` — Known good service registry configurations and paths for comparison.; `TimeWindow` — Correlation interval between registry/service modifications and service execution.; `PrivilegedAccounts` — Accounts permitted to modify service configurations.

---

### T1574.012 — COR_PROFILER
<a id="t1574012"></a>

**Detection strategy:** Detection Strategy for Hijack Execution Flow using the Windows COR_PROFILER. (`DET0479`)  
**Platforms:** Windows  
**ATT&CK:** [T1574.012](https://attack.mitre.org/techniques/T1574/012/) · [detail page](../../techniques/persistence.md#t1574012)

- **`AN1319` Analytic 1319** · Windows
  Modification of COR_PROFILER-related environment variables or Registry keys (COR_ENABLE_PROFILING, COR_PROFILER, COR_PROFILER_PATH), combined with anomalous .NET process creation or unmanaged DLL loads. Defender observes registry modifications, suspicious process creation with altered environment variables, and profiler DLLs loaded unexpectedly into .NET CLR processes.
  - *Log sources:* `WinEventLog:Security` (EventCode=4657); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=11)
  - *Tune:* `AllowedProfilers` — List of known good COR_PROFILER CLSIDs and DLLs expected in developer or monitoring environments.; `ProcessScope` — Processes expected to load COR_PROFILER (e.g., Visual Studio) for baseline comparison.; `TimeWindow` — Interval between registry modification or file creation and profiler DLL load into .NET processes.; `ProfilerDllPaths` — Directories considered legitimate for profiler DLLs; deviations should raise alerts.

---

### T1574.013 — KernelCallbackTable
<a id="t1574013"></a>

**Detection strategy:** Detection Strategy for Hijack Execution Flow through the KernelCallbackTable on Windows. (`DET0577`)  
**Platforms:** Windows  
**ATT&CK:** [T1574.013](https://attack.mitre.org/techniques/T1574/013/) · [detail page](../../techniques/persistence.md#t1574013)

- **`AN1593` Analytic 1593** · Windows
  Unexpected modification of the KernelCallbackTable in a process’s PEB followed by invocation of modified callback functions (e.g., fnCOPYDATA) through Windows messages. Defender observes suspicious API call chains such as NtQueryInformationProcess → WriteProcessMemory → abnormal GUI callback execution, often correlating to anomalous process behavior such as network activity or code injection.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=10); `WinEventLog:Sysmon` (EventCode=1); `etw:Microsoft-Windows-Kernel-Process` (WriteProcessMemory: WriteProcessMemory targeting regions containing KernelCallbackTable addresses)
  - *Tune:* `MonitoredProcesses` — GUI applications (e.g., explorer.exe, notepad.exe) where KernelCallbackTable abuse is more likely.; `CallbackFunctions` — Specific callback functions (e.g., fnCOPYDATA, fnDWORD) expected to remain stable.; `TimeWindow` — Correlation interval between WriteProcessMemory calls and execution of modified callback functions.; `AccessMaskThresholds` — Access rights values that should be flagged when targeting GUI processes.

---

### T1574.014 — AppDomainManager
<a id="t1574014"></a>

**Detection strategy:** Detection Strategy for Hijack Execution Flow through the AppDomainManager on Windows. (`DET0517`)  
**Platforms:** Windows  
**ATT&CK:** [T1574.014](https://attack.mitre.org/techniques/T1574/014/) · [detail page](../../techniques/persistence.md#t1574014)

- **`AN1433` Analytic 1433** · Windows
  Detection focuses on unauthorized manipulation of .NET AppDomainManager behavior. Defenders may observe suspicious creation of new AppDomains within trusted processes, anomalous loading of assemblies via non-standard configuration files, or registry/environment variable changes redirecting AppDomainManager to malicious assemblies. Correlated events include config file tampering, new process creation of .NET host processes (e.g., w3wp.exe, powershell.exe) with modified runtime parameters, and module loads of unusual or unsigned .NET DLLs.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `TargetProcesses` — List of monitored .NET host processes (e.g., powershell.exe, w3wp.exe, svchost.exe).; `AssemblyWhitelist` — Known benign .NET assemblies expected to load via AppDomainManager.; `ConfigFilePaths` — Directory paths where configuration tampering should be monitored (application directories, system32, program files).; `TimeWindow` — Correlation period between file modification of config/environment settings and subsequent anomalous module load.

---

### T1653 — Power Settings
<a id="t1653"></a>

**Detection strategy:** Detection Strategy for Power Settings Abuse (`DET0417`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1653](https://attack.mitre.org/techniques/T1653/) · [detail page](../../techniques/persistence.md#t1653)

- **`AN1174` Analytic 1174** · Windows
  Monitor command execution of powercfg.exe with arguments modifying sleep, hibernate, or display timeouts. Abnormal or repeated modifications to power settings outside administrative baselines may indicate persistence attempts. Correlate process creation with registry and system configuration changes to build behavioral chains.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688)
  - *Tune:* `AllowedAdminTools` — Whitelist expected administrative scripts that legitimately modify power settings.; `TimeWindow` — Correlation period between powercfg.exe invocation and registry/policy changes.
- **`AN1175` Analytic 1175** · Linux
  Detect execution of system utilities (systemctl, systemd-inhibit, systemdsleep) modifying sleep or hibernate behavior. Abnormal edits to system configuration files (e.g., /etc/systemd/sleep.conf) should be correlated with process execution to identify persistence techniques.
  - *Log sources:* `auditd:SYSCALL` (execve: Execution of systemctl, loginctl, or systemd-inhibit commands related to sleep/hibernate); `auditd:PATH` (write: File modifications to /etc/systemd/sleep.conf or related power configuration files)
  - *Tune:* `KnownMaintenanceWindows` — Filter benign modifications during patching or system maintenance intervals.
- **`AN1176` Analytic 1176** · macOS
  Monitor pmset command executions altering sleep/hibernate/standby parameters. Unexpected modifications to /Library/Preferences/SystemConfiguration/com.apple.PowerManagement.plist or similar files should be correlated with process activity.
  - *Log sources:* `macos:unifiedlog` (Process creation events where command line = pmset with arguments affecting sleep, hibernatemode, displaysleep); `macos:unifiedlog` (write: File modification to com.apple.PowerManagement.plist or related system preference files)
  - *Tune:* `AdminWhitelists` — Allowlist expected pmset invocations by IT administrators for power policy enforcement.

---

### T1668 — Exclusive Control
<a id="t1668"></a>

**Detection strategy:** Detection Strategy for Exclusive Control (`DET0015`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1668](https://attack.mitre.org/techniques/T1668/) · [detail page](../../techniques/persistence.md#t1668)

- **`AN0045` Analytic 0045** · Windows
  Detects unusual command executions and service modifications that indicate self-patching or disabling of vulnerable services post-compromise. Defenders should monitor for service stop commands, suspicious process termination, and execution of binaries or scripts aligned with known patching or service management tools outside of expected admin contexts.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=5)
  - *Tune:* `ServiceList` — Tunable list of critical or vulnerable services that defenders want to monitor for unexpected disabling.; `TimeWindow` — Defines correlation window (e.g., 5–15 minutes) between suspicious command execution and subsequent process termination.
- **`AN0046` Analytic 0046** · Linux
  Detects adversary attempts to monopolize control of compromised systems by issuing service stop commands, unloading vulnerable modules, or forcefully killing competing processes. Defenders should monitor audit logs and syslog for administrative utilities (systemctl, service, kill) being invoked outside of normal change management.
  - *Log sources:* `auditd:SYSCALL` (execve: Commands like systemctl stop <service>, service <service> stop, or kill -9 <pid>); `linux:syslog` (Unexpected termination of daemons or critical services not aligned with admin change tickets)
  - *Tune:* `CriticalProcessList` — Defines specific Linux daemons and processes that should not be terminated outside maintenance windows.; `AdminUserContext` — Defines expected accounts permitted to execute service stop commands; deviations may be suspicious.
- **`AN0047` Analytic 0047** · macOS
  Detects unauthorized termination of system daemons or commands issued through launchctl or kill to stop competing services or malware processes. Defenders should monitor unified logs and EDR telemetry for unusual service modifications or terminations.
  - *Log sources:* `macos:unifiedlog` (launchctl unload, kill, or pkill commands affecting daemons or background services); `macos:osquery` (process_termination: Unexpected termination of processes tied to vulnerable or high-value services)
  - *Tune:* `ProtectedServiceList` — Defines macOS services (e.g., securityd, keychain-related daemons) that should never be disabled.

---

### T1671 — Cloud Application Integration
<a id="t1671"></a>

**Detection strategy:** Detection Strategy for Cloud Application Integration (`DET0539`)  
**Platforms:** Office Suite, SaaS  
**ATT&CK:** [T1671](https://attack.mitre.org/techniques/T1671/) · [detail page](../../techniques/persistence.md#t1671)

- **`AN1487` Analytic 1487** · Office Suite
  Detects suspicious OAuth application integrations within Office 365 or Google Workspace environments, such as new app registrations, unexpected consent grants, or privilege assignments. Defenders should correlate between application creation/modification events and associated user or service principal activity to identify persistence via app integrations.
  - *Log sources:* `m365:unified` (Add app role assignment grant to user: Consent to application by privileged or unexpected accounts); `azure:audit` (Consent to application: OAuth application consent granted to service principal)
  - *Tune:* `PrivilegedUserList` — Defines which accounts are authorized to consent or register applications; deviations indicate possible adversary persistence.; `ApplicationScopeThreshold` — Defines which OAuth scopes are considered risky (e.g., Mail.ReadWrite, Files.ReadWrite.All).
- **`AN1488` Analytic 1488** · SaaS
  Detects anomalous SaaS application integration activity across environments such as Slack, Salesforce, or other enterprise SaaS services. Focus is on unauthorized app additions, unusual permission grants, and persistence through service principal tokens.
  - *Log sources:* `saas:integration` (New or modified third-party application integrations with elevated permissions); `saas:audit` (Application added or consent granted: Integration persisting after original user disabled)
  - *Tune:* `AppWhitelist` — Defines approved SaaS integrations for the enterprise; deviations indicate suspicious persistence.; `ConsentDelegationPolicy` — Threshold for which users can self-consent integrations; lowering this may reduce false positives.

---

