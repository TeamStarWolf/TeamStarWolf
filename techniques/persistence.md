# Persistence — Technique Detail

> Full detail pages for the **80 ATT&CK techniques** whose primary tactic is [Persistence](https://attack.mitre.org/tactics/TA0003/) (ATT&CK Enterprise v18.1). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](/techniques/README.md).

---

### T1037 — Boot or Logon Initialization Scripts
<a id="t1037"></a>

**Tactics:** Persistence, Privilege Escalation · **Platforms:** macOS, Windows, Linux, Network Devices, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1037)  

Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence. Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server.

**ATT&CK mitigations (2):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024)  
**NIST 800-53 R5 controls (9):** `AC-17`, `AC-3`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Boot or Logon Initialization Scripts Detection Strategy  
**Used by 4 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 2 software:** [S1078 RotaJakiro](https://attack.mitre.org/software/S1078), [S1217 VIRTUALPITA](https://attack.mitre.org/software/S1217)  

---

### T1037.001 — Logon Script (Windows)
<a id="t1037001"></a>

sub-technique of [T1037](/techniques/persistence.md#t1037) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1037/001)  

Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence. Windows allows logon scripts to be run whenever a specific user or group of users log into a system.

**ATT&CK mitigations (1):** [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024)  
**NIST 800-53 R5 controls (2):** `AC-17`, `CM-7`  
**ATT&CK detection strategy:** Detect Logon Script Modifications and Execution  
**Used by 2 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080)  
**Implemented by 4 software:** [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0251 Zebrocy](https://attack.mitre.org/software/S0251), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0526 KGH_SPY](https://attack.mitre.org/software/S0526)  

---

### T1037.002 — Login Hook
<a id="t1037002"></a>

sub-technique of [T1037](/techniques/persistence.md#t1037) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1037/002)  

Adversaries may use a Login Hook to establish persistence executed upon user logon. A login hook is a plist file that points to a specific script to execute with root privileges upon user logon.

**ATT&CK mitigations (1):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022)  
**NIST 800-53 R5 controls (7):** `AC-3`, `CA-7`, `CM-2`, `CM-6`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Login Hook Persistence on macOS  

---

### T1037.003 — Network Logon Script
<a id="t1037003"></a>

sub-technique of [T1037](/techniques/persistence.md#t1037) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1037/003)  

Adversaries may use network logon scripts automatically executed at logon initialization to establish persistence. Network logon scripts can be assigned using Active Directory or Group Policy Objects. These logon scripts run with the privileges of the user they are assigned to.

**ATT&CK mitigations (1):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022)  
**NIST 800-53 R5 controls (7):** `AC-3`, `CA-7`, `CM-2`, `CM-6`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Network Logon Script Abuse via Multi-Event Correlation on Windows  

---

### T1037.004 — RC Scripts
<a id="t1037004"></a>

sub-technique of [T1037](/techniques/persistence.md#t1037) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** macOS, Linux, Network Devices, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1037/004)  

Adversaries may establish persistence by modifying RC scripts, which are executed during a Unix-like system’s startup. These files allow system administrators to map and start custom services at startup for different run levels. RC scripts require root privileges to modify.

**ATT&CK mitigations (1):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022)  
**NIST 800-53 R5 controls (7):** `AC-3`, `CA-7`, `CM-2`, `CM-6`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Boot or Logon Initialization Scripts: RC Scripts  
**Used by 3 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 4 software:** [S0278 iKitten](https://attack.mitre.org/software/S0278), [S0394 HiddenWasp](https://attack.mitre.org/software/S0394), [S0687 Cyclops Blink](https://attack.mitre.org/software/S0687), [S0690 Green Lambert](https://attack.mitre.org/software/S0690)  

---

### T1037.005 — Startup Items
<a id="t1037005"></a>

sub-technique of [T1037](/techniques/persistence.md#t1037) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1037/005)  

Adversaries may use startup items automatically executed at boot initialization to establish persistence.

**ATT&CK mitigations (1):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022)  
**NIST 800-53 R5 controls (7):** `AC-3`, `CA-7`, `CM-2`, `CM-6`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Modification of macOS Startup Items  
**Implemented by 1 software:** [S0283 jRAT](https://attack.mitre.org/software/S0283)  

---

### T1098 — Account Manipulation
<a id="t1098"></a>

**Tactics:** Persistence, Privilege Escalation · **Platforms:** Containers, ESXi, IaaS, Identity Provider, Linux, macOS, Network Devices, Office Suite, SaaS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1098)  

Adversaries may manipulate accounts to maintain and/or elevate access to victim systems. Account manipulation may consist of any action that preserves or modifies adversary access to a compromised account, such as modifying credentials or permission groups.

**ATT&CK mitigations (7):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `SC-7`, `SI-4`  
**ATT&CK detection strategy:** Account Manipulation Behavior Chain Detection  
**Used by 3 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015)  
**Implemented by 2 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0274 Calisto](https://attack.mitre.org/software/S0274)  

---

### T1098.001 — Additional Cloud Credentials
<a id="t1098001"></a>

sub-technique of [T1098](/techniques/persistence.md#t1098) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** IaaS, Identity Provider, SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1098/001)  

Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment. For example, adversaries may add credentials for Service Principals and Applications in addition to existing legitimate credentials in Azure / Entra ID.

**ATT&CK mitigations (5):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (15):** `AC-2`, `AC-20`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SC-46`, `SC-7`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Additional Cloud Credentials in IaaS/IdP/SaaS  
**Used by 1 threat groups:** [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 1 software:** [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1098.002 — Additional Email Delegate Permissions
<a id="t1098002"></a>

sub-technique of [T1098](/techniques/persistence.md#t1098) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1098/002)  

Adversaries may grant additional permission levels to maintain persistent access to an adversary-controlled email account. For example, the <code>Add-MailboxPermission</code> PowerShell cmdlet, available in on-premises Exchange and in the cloud-based service Office 365, adds permissions to a mailbox.

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Addition of Email Delegate Permissions  
**Used by 3 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059)  

---

### T1098.003 — Additional Cloud Roles
<a id="t1098003"></a>

sub-technique of [T1098](/techniques/persistence.md#t1098) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** IaaS, Identity Provider, Office Suite, SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1098/003)  

An adversary may add additional roles or permissions to an adversary-controlled cloud account to maintain persistent access to a tenant. For example, adversaries may update IAM policies in cloud-based environments or add a new global administrator in Office 365 environments.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Role Addition to Cloud Accounts  
**Used by 3 threat groups:** [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  

---

### T1098.004 — SSH Authorized Keys
<a id="t1098004"></a>

sub-technique of [T1098](/techniques/persistence.md#t1098) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Linux, macOS, IaaS, Network Devices, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1098/004)  

Adversaries may modify the SSH <code>authorized_keys</code> file to maintain persistence on a victim host. Linux distributions, macOS, and ESXi hypervisors commonly use key-based authentication to secure the authentication process of SSH sessions for remote management.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (15):** `AC-20`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-5`, `RA-5`, `SC-12`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for SSH Key Injection in Authorized Keys  
**Used by 3 threat groups:** [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045)  
**Implemented by 3 software:** [S0468 Skidmap](https://attack.mitre.org/software/S0468), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0658 XCSSET](https://attack.mitre.org/software/S0658)  

---

### T1098.005 — Device Registration
<a id="t1098005"></a>

sub-technique of [T1098](/techniques/persistence.md#t1098) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1098/005)  

Adversaries may register a device to an adversary-controlled account. Devices may be registered in a multifactor authentication (MFA) system, which handles authentication to the network, or in a device management system, which handles device access and compliance.

**ATT&CK mitigations (1):** [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (7):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`  
**ATT&CK detection strategy:** Suspicious Device Registration via Entra ID or MFA Platform  
**Used by 1 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016)  
**Implemented by 1 software:** [S0677 AADInternals](https://attack.mitre.org/software/S0677)  

---

### T1098.006 — Additional Container Cluster Roles
<a id="t1098006"></a>

sub-technique of [T1098](/techniques/persistence.md#t1098) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1098/006)  

An adversary may add additional roles or permissions to an adversary-controlled user or service account to maintain persistent access to a container orchestration system.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (4):** `AC-2`, `AC-3`, `AC-6`, `IA-5`  
**ATT&CK detection strategy:** Suspicious RoleBinding or ClusterRoleBinding Assignment in Kubernetes  

---

### T1098.007 — Additional Local or Domain Groups
<a id="t1098007"></a>

sub-technique of [T1098](/techniques/persistence.md#t1098) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows, macOS, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1098/007)  

An adversary may add additional local or domain groups to an adversary-controlled account to maintain persistent access to a system or domain. On Windows, accounts may use the `net localgroup` and `net group` commands to add existing users to local and domain groups.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-4`, `SI-4`  
**ATT&CK detection strategy:** Suspicious Addition to Local or Domain Groups  
**Used by 7 threat groups:** [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1023 APT5](https://attack.mitre.org/groups/G1023)  
**Implemented by 4 software:** [S0039 Net](https://attack.mitre.org/software/S0039), [S0382 ServHelper](https://attack.mitre.org/software/S0382), [S0649 SMOKEDHAM](https://attack.mitre.org/software/S0649), [S1111 DarkGate](https://attack.mitre.org/software/S1111)  

---

### T1133 — External Remote Services
<a id="t1133"></a>

**Tactics:** Persistence, Initial Access · **Platforms:** Containers, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1133)  

Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations.

**ATT&CK mitigations (5):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (17):** `AC-17`, `AC-20`, `AC-3`, `AC-4`, `AC-6`, `AC-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-5`, `RA-5`, `SC-46`, `SC-7`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavior-chain detection for T1133 External Remote Services across Windows, Linux, macOS, Containers  
**Used by 26 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0026 APT18](https://attack.mitre.org/groups/G0026), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0053 FIN5](https://attack.mitre.org/groups/G0053), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0115 GOLD SOUTHFIELD](https://attack.mitre.org/groups/G0115), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1024 Akira](https://attack.mitre.org/groups/G1024), [G1040 Play](https://attack.mitre.org/groups/G1040) _(+2 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 5 software:** [S0362 Linux Rabbit](https://attack.mitre.org/software/S0362), [S0599 Kinsing](https://attack.mitre.org/software/S0599), [S0600 Doki](https://attack.mitre.org/software/S0600), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S1060 Mafalda](https://attack.mitre.org/software/S1060)  

---

### T1136 — Create Account
<a id="t1136"></a>

**Tactics:** Persistence · **Platforms:** Windows, IaaS, Linux, macOS, Network Devices, Containers, SaaS, Office Suite, Identity Provider, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1136)  

Adversaries may create an account to maintain access to victim systems. With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

**ATT&CK mitigations (4):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (15):** `AC-2`, `AC-20`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SC-46`, `SC-7`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for T1136 - Create Account across platforms  
**Used by 3 threat groups:** [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045)  
**Implemented by 1 software:** [S1199 LockBit 2.0](https://attack.mitre.org/software/S1199)  

---

### T1136.001 — Local Account
<a id="t1136001"></a>

sub-technique of [T1136](/techniques/persistence.md#t1136) · **Tactics:** Persistence · **Platforms:** Linux, macOS, Windows, Network Devices, Containers, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1136/001)  

Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** T1136.001 Detection Strategy - Local Account Creation Across Platforms  
**Used by 14 threat groups:** [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1023 APT5](https://attack.mitre.org/groups/G1023), [G1034 Daggerfly](https://attack.mitre.org/groups/G1034)  
**Implemented by 15 software:** [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0039 Net](https://attack.mitre.org/software/S0039), [S0084 Mis-Type](https://attack.mitre.org/software/S0084), [S0085 S-Type](https://attack.mitre.org/software/S0085), [S0143 Flame](https://attack.mitre.org/software/S0143), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0274 Calisto](https://attack.mitre.org/software/S0274), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0382 ServHelper](https://attack.mitre.org/software/S0382), [S0394 HiddenWasp](https://attack.mitre.org/software/S0394), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0493 GoldenSpy](https://attack.mitre.org/software/S0493), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0649 SMOKEDHAM](https://attack.mitre.org/software/S0649), [S1111 DarkGate](https://attack.mitre.org/software/S1111)  

---

### T1136.002 — Domain Account
<a id="t1136002"></a>

sub-technique of [T1136](/techniques/persistence.md#t1136) · **Tactics:** Persistence · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1136/002)  

Adversaries may create a domain account to maintain access to victim systems. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover user, administrator, and service accounts.

**ATT&CK mitigations (4):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (15):** `AC-2`, `AC-20`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SC-46`, `SC-7`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** T1136.002 Detection Strategy - Domain Account Creation Across Platforms  
**Used by 5 threat groups:** [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 4 software:** [S0029 PsExec](https://attack.mitre.org/software/S0029), [S0039 Net](https://attack.mitre.org/software/S0039), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0363 Empire](https://attack.mitre.org/software/S0363)  

---

### T1136.003 — Cloud Account
<a id="t1136003"></a>

sub-technique of [T1136](/techniques/persistence.md#t1136) · **Tactics:** Persistence · **Platforms:** IaaS, SaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1136/003)  

Adversaries may create a cloud account to maintain access to victim systems. With a sufficient level of access, such accounts may be used to establish secondary credentialed access that does not require persistent remote access tools to be deployed on the system.

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-20`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SC-7`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for T1136.003 - Cloud Account Creation across IaaS, IdP, SaaS, Office  
**Used by 2 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004)  
**Implemented by 1 software:** [S0677 AADInternals](https://attack.mitre.org/software/S0677)  

---

### T1137 — Office Application Startup
<a id="t1137"></a>

**Tactics:** Persistence · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1137)  

Adversaries may leverage Microsoft Office-based applications for persistence between startups. Microsoft Office is a fairly common application suite on Windows-based operating systems within an enterprise network.

**ATT&CK mitigations (4):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (13):** `AC-10`, `AC-17`, `AC-6`, `CM-2`, `CM-6`, `CM-8`, `RA-5`, `SC-18`, `SC-44`, `SI-2`, `SI-3`, `SI-4`, `SI-8`  
**ATT&CK detection strategy:** Detect Office Startup-Based Persistence via Macros, Forms, and Registry Hooks  
**Used by 2 threat groups:** [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0050 APT32](https://attack.mitre.org/groups/G0050)  

---

### T1137.001 — Office Template Macros
<a id="t1137001"></a>

sub-technique of [T1137](/techniques/persistence.md#t1137) · **Tactics:** Persistence · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1137/001)  

Adversaries may abuse Microsoft Office templates to obtain persistence on a compromised system. Microsoft Office contains templates that are part of common Office applications and are used to customize styles. The base templates within the application are used each time an application starts.

**ATT&CK mitigations (2):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (10):** `AC-6`, `CM-2`, `CM-6`, `CM-8`, `RA-5`, `SC-18`, `SC-44`, `SI-3`, `SI-4`, `SI-8`  
**ATT&CK detection strategy:** Detect Persistence via Office Template Macro Injection or Registry Hijack  
**Used by 1 threat groups:** [G0069 MuddyWater](https://attack.mitre.org/groups/G0069)  
**Implemented by 2 software:** [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0475 BackConfig](https://attack.mitre.org/software/S0475)  

---

### T1137.002 — Office Test
<a id="t1137002"></a>

sub-technique of [T1137](/techniques/persistence.md#t1137) · **Tactics:** Persistence · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1137/002)  

Adversaries may abuse the Microsoft Office "Office Test" Registry key to obtain persistence on a compromised system. An Office Test Registry location exists that allows a user to specify an arbitrary DLL that will be executed every time an Office application is started.

**ATT&CK mitigations (2):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (10):** `AC-10`, `AC-14`, `AC-17`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `SC-18`, `SC-44`, `SI-8`  
**ATT&CK detection strategy:** Detect Persistence via Office Test Registry DLL Injection  
**Used by 1 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007)  

---

### T1137.003 — Outlook Forms
<a id="t1137003"></a>

sub-technique of [T1137](/techniques/persistence.md#t1137) · **Tactics:** Persistence · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1137/003)  

Adversaries may abuse Microsoft Outlook forms to obtain persistence on a compromised system. Outlook forms are used as templates for presentation and functionality in Outlook messages.

**ATT&CK mitigations (2):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (7):** `AC-6`, `CM-2`, `CM-6`, `SC-18`, `SC-44`, `SI-2`, `SI-8`  
**ATT&CK detection strategy:** Detect Persistence via Outlook Custom Forms Triggered by Malicious Email  
**Implemented by 1 software:** [S0358 Ruler](https://attack.mitre.org/software/S0358)  

---

### T1137.004 — Outlook Home Page
<a id="t1137004"></a>

sub-technique of [T1137](/techniques/persistence.md#t1137) · **Tactics:** Persistence · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1137/004)  

Adversaries may abuse Microsoft Outlook's Home Page feature to obtain persistence on a compromised system. Outlook Home Page is a legacy feature used to customize the presentation of Outlook folders. This feature allows for an internal or external URL to be loaded and presented whenever a folder is opened.

**ATT&CK mitigations (2):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (7):** `AC-6`, `CM-2`, `CM-6`, `SC-18`, `SC-44`, `SI-2`, `SI-8`  
**ATT&CK detection strategy:** Detect Persistence via Outlook Home Page Exploitation  
**Used by 1 threat groups:** [G0049 OilRig](https://attack.mitre.org/groups/G0049)  
**Implemented by 1 software:** [S0358 Ruler](https://attack.mitre.org/software/S0358)  

---

### T1137.005 — Outlook Rules
<a id="t1137005"></a>

sub-technique of [T1137](/techniques/persistence.md#t1137) · **Tactics:** Persistence · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1137/005)  

Adversaries may abuse Microsoft Outlook rules to obtain persistence on a compromised system. Outlook rules allow a user to define automated behavior to manage email messages.

**ATT&CK mitigations (2):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (7):** `AC-6`, `CM-2`, `CM-6`, `SC-18`, `SC-44`, `SI-2`, `SI-8`  
**ATT&CK detection strategy:** Detect Persistence via Malicious Outlook Rules  
**Implemented by 1 software:** [S0358 Ruler](https://attack.mitre.org/software/S0358)  

---

### T1137.006 — Add-ins
<a id="t1137006"></a>

sub-technique of [T1137](/techniques/persistence.md#t1137) · **Tactics:** Persistence · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1137/006)  

Adversaries may abuse Microsoft Office add-ins to obtain persistence on a compromised system. Office add-ins can be used to add functionality to Office programs.

**ATT&CK mitigations (1):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (6):** `AC-6`, `CM-2`, `CM-6`, `SC-18`, `SC-44`, `SI-8`  
**ATT&CK detection strategy:** Detect Persistence via Malicious Office Add-ins  
**Used by 1 threat groups:** [G0019 Naikon](https://attack.mitre.org/groups/G0019)  
**Implemented by 3 software:** [S0268 Bisonal](https://attack.mitre.org/software/S0268), [S1142 LunarMail](https://attack.mitre.org/software/S1142), [S1143 LunarLoader](https://attack.mitre.org/software/S1143)  

---

### T1176 — Software Extensions
<a id="t1176"></a>

**Tactics:** Persistence · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1176)  

Adversaries may abuse software extensions to establish persistent access to victim systems. Software extensions are modular components that enhance or customize the functionality of software applications, including web browsers, Integrated Development Environments (IDEs), and other platforms.

**ATT&CK mitigations (5):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (14):** `AC-6`, `CA-7`, `CM-11`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `RA-5`, `SC-7`, `SI-10`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Malicious or Unauthorized Software Extensions  

---

### T1176.001 — Browser Extensions
<a id="t1176001"></a>

sub-technique of [T1176](/techniques/persistence.md#t1176) · **Tactics:** Persistence · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1176/001)  

Adversaries may abuse internet browser extensions to establish persistent access to victim systems. Browser extensions or plugins are small programs that can add functionality to and customize aspects of internet browsers.

**ATT&CK mitigations (5):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detecting Malicious Browser Extensions Across Platforms  
**Used by 1 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094)  
**Implemented by 6 software:** [S0402 OSX/Shlayer](https://attack.mitre.org/software/S0402), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S1122 Mispadu](https://attack.mitre.org/software/S1122), [S1201 TRANSLATEXT](https://attack.mitre.org/software/S1201), [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213)  

---

### T1176.002 — IDE Extensions
<a id="t1176002"></a>

sub-technique of [T1176](/techniques/persistence.md#t1176) · **Tactics:** Persistence · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1176/002)  

Adversaries may abuse an integrated development environment (IDE) extension to establish persistent access to victim systems.

**ATT&CK mitigations (5):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect malicious IDE extension install/usage and IDE tunneling  
**Used by 1 threat groups:** [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129)  

---

### T1505 — Server Software Component
<a id="t1505"></a>

**Tactics:** Persistence · **Platforms:** Windows, Linux, macOS, Network Devices, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1505)  

Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems. Enterprise server applications may include features that allow developers to write and install software or scripts to extend the functionality of the main application.

**ATT&CK mitigations (7):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (21):** `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-11`, `CM-2`, `CM-5`, `CM-6`, `CM-8`, `IA-2`, `RA-5`, `SA-10`, `SA-11`, `SC-16`, `SI-14`, `SI-4`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Detection Strategy for T1505 - Server Software Component  

---

### T1505.001 — SQL Stored Procedures
<a id="t1505001"></a>

sub-technique of [T1505](/techniques/persistence.md#t1505) · **Tactics:** Persistence · **Platforms:** Windows, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1505/001)  

Adversaries may abuse SQL stored procedures to establish persistent access to systems. SQL Stored Procedures are code that can be saved and reused so that database users do not waste time rewriting frequently used SQL queries.

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (12):** `CM-11`, `CM-2`, `CM-6`, `CM-8`, `RA-5`, `SA-10`, `SA-11`, `SI-14`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Detection Strategy for SQL Stored Procedures Abuse via T1505.001  
**Implemented by 1 software:** [S0603 Stuxnet](https://attack.mitre.org/software/S0603)  

---

### T1505.002 — Transport Agent
<a id="t1505002"></a>

sub-technique of [T1505](/techniques/persistence.md#t1505) · **Tactics:** Persistence · **Platforms:** Linux, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1505/002)  

Adversaries may abuse Microsoft transport agents to establish persistent access to systems.

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (21):** `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-11`, `CM-2`, `CM-5`, `CM-6`, `CM-8`, `IA-2`, `RA-5`, `SA-10`, `SA-11`, `SC-16`, `SI-14`, `SI-4`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Detection Strategy for T1505.002 - Transport Agent Abuse (Windows/Linux)  
**Implemented by 1 software:** [S0395 LightNeuron](https://attack.mitre.org/software/S0395)  

---

### T1505.003 — Web Shell
<a id="t1505003"></a>

sub-technique of [T1505](/techniques/persistence.md#t1505) · **Tactics:** Persistence · **Platforms:** Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1505/003)  

Adversaries may backdoor web servers with web shells to establish persistent access to systems. A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to access the Web server as a gateway into a network.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (8):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-6`, `RA-5`, `SI-4`  
**ATT&CK detection strategy:** Web Shell Detection via Server Behavior and File Execution Chains  
**Used by 31 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0009 Deep Panda](https://attack.mitre.org/groups/G0009), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0123 Volatile Cedar](https://attack.mitre.org/groups/G0123), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0131 Tonto Team](https://attack.mitre.org/groups/G0131), [G0135 BackdoorDiplomacy](https://attack.mitre.org/groups/G0135), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1009 Moses Staff](https://attack.mitre.org/groups/G1009), [G1012 CURIUM](https://attack.mitre.org/groups/G1012) _(+7 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 19 software:** [S0020 China Chopper](https://attack.mitre.org/software/S0020), [S0072 OwaAuth](https://attack.mitre.org/software/S0072), [S0073 ASPXSpy](https://attack.mitre.org/software/S0073), [S0185 SEASHARPEE](https://attack.mitre.org/software/S0185), [S0578 SUPERNOVA](https://attack.mitre.org/software/S0578), [S0598 P.A.S. Webshell](https://attack.mitre.org/software/S0598), [S1108 PULSECHECK](https://attack.mitre.org/software/S1108), [S1110 SLIGHTPULSE](https://attack.mitre.org/software/S1110), [S1112 STEADYPULSE](https://attack.mitre.org/software/S1112), [S1113 RAPIDPULSE](https://attack.mitre.org/software/S1113), [S1115 WIREFIRE](https://attack.mitre.org/software/S1115), [S1117 GLASSTOKEN](https://attack.mitre.org/software/S1117), [S1118 BUSHWALK](https://attack.mitre.org/software/S1118), [S1119 LIGHTWIRE](https://attack.mitre.org/software/S1119), [S1120 FRAMESTING](https://attack.mitre.org/software/S1120), [S1163 SnappyTCP](https://attack.mitre.org/software/S1163), [S1187 reGeorg](https://attack.mitre.org/software/S1187), [S1188 Line Runner](https://attack.mitre.org/software/S1188), [S1189 Neo-reGeorg](https://attack.mitre.org/software/S1189)  

---

### T1505.004 — IIS Components
<a id="t1505004"></a>

sub-technique of [T1505](/techniques/persistence.md#t1505) · **Tactics:** Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1505/004)  

Adversaries may install malicious components that run on Internet Information Services (IIS) web servers to establish persistence. IIS provides several mechanisms to extend the functionality of the web servers.

**ATT&CK mitigations (4):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (22):** `AC-17`, `AC-3`, `AC-4`, `AC-6`, `CM-11`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `RA-5`, `SA-10`, `SA-11`, `SC-7`, `SI-14`, `SI-16`, `SI-3`, `SI-4`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Detection Strategy for T1505.004 - Malicious IIS Components  
**Implemented by 3 software:** [S0072 OwaAuth](https://attack.mitre.org/software/S0072), [S0258 RGDoor](https://attack.mitre.org/software/S0258), [S1022 IceApple](https://attack.mitre.org/software/S1022)  

---

### T1505.005 — Terminal Services DLL
<a id="t1505005"></a>

sub-technique of [T1505](/techniques/persistence.md#t1505) · **Tactics:** Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1505/005)  

Adversaries may abuse components of Terminal Services to enable persistent access to systems. Microsoft Terminal Services, renamed to Remote Desktop Services in some Windows Server OSs as of 2022, enable remote terminal connections to hosts.

**ATT&CK mitigations (2):** [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (11):** `AC-12`, `AC-17`, `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-6`, `RA-5`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for T1505.005 – Terminal Services DLL Modification (Windows)  

---

### T1505.006 — vSphere Installation Bundles
<a id="t1505006"></a>

sub-technique of [T1505](/techniques/persistence.md#t1505) · **Tactics:** Persistence · **Platforms:** ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1505/006)  

Adversaries may abuse vSphere Installation Bundles (VIBs) to establish persistent access to ESXi hypervisors. VIBs are collections of files used for software distribution and virtual system management in VMware environments.

**ATT&CK mitigations (3):** [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect Abuse of vSphere Installation Bundles (VIBs) for Persistent Access  
**Used by 1 threat groups:** [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 1 software:** [S1218 VIRTUALPIE](https://attack.mitre.org/software/S1218)  

---

### T1525 — Implant Internal Image
<a id="t1525"></a>

**Tactics:** Persistence · **Platforms:** IaaS, Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1525)  

Adversaries may implant cloud or container images with malicious code to establish persistence after gaining access to an environment.

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (15):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-9`, `RA-5`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for T1525 – Implant Internal Image  

---

### T1543 — Create or Modify System Process
<a id="t1543"></a>

**Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows, macOS, Linux, Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1543)  

Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services.

**ATT&CK mitigations (9):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (20):** `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-11`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-4`, `RA-5`, `SA-22`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of System Process Creation or Modification Across Platforms  
**Implemented by 6 software:** [S0401 Exaramel for Linux](https://attack.mitre.org/software/S0401), [S1121 LITTLELAMB.WOOLTEA](https://attack.mitre.org/software/S1121), [S1142 LunarMail](https://attack.mitre.org/software/S1142), [S1152 IMAPLoader](https://attack.mitre.org/software/S1152), [S1184 BOLDMOVE](https://attack.mitre.org/software/S1184), [S1194 Akira _v2](https://attack.mitre.org/software/S1194)  

---

### T1543.001 — Launch Agent
<a id="t1543001"></a>

sub-technique of [T1543](/techniques/persistence.md#t1543) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1543/001)  

Adversaries may create or modify launch agents to repeatedly execute malicious payloads as part of persistence.

**ATT&CK mitigations (1):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022)  
**NIST 800-53 R5 controls (8):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-11`, `CM-2`, `CM-5`, `IA-2`  
**ATT&CK detection strategy:** Detection of Launch Agent Creation or Modification on macOS  
**Used by 1 threat groups:** [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 20 software:** [S0162 Komplex](https://attack.mitre.org/software/S0162), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0235 CrossRAT](https://attack.mitre.org/software/S0235), [S0274 Calisto](https://attack.mitre.org/software/S0274), [S0276 Keydnap](https://attack.mitre.org/software/S0276), [S0277 FruitFly](https://attack.mitre.org/software/S0277), [S0279 Proton](https://attack.mitre.org/software/S0279), [S0281 Dok](https://attack.mitre.org/software/S0281), [S0282 MacSpy](https://attack.mitre.org/software/S0282), [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0369 CoinTicker](https://attack.mitre.org/software/S0369), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0492 CookieMiner](https://attack.mitre.org/software/S0492), [S0497 Dacls](https://attack.mitre.org/software/S0497), [S0595 ThiefQuest](https://attack.mitre.org/software/S0595), [S0690 Green Lambert](https://attack.mitre.org/software/S0690), [S1016 MacMa](https://attack.mitre.org/software/S1016), [S1048 macOS.OSAMiner](https://attack.mitre.org/software/S1048), [S1153 Cuckoo Stealer](https://attack.mitre.org/software/S1153), [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245)  

---

### T1543.002 — Systemd Service
<a id="t1543002"></a>

sub-technique of [T1543](/techniques/persistence.md#t1543) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1543/002)  

Adversaries may create or modify systemd services to repeatedly execute malicious payloads as part of persistence. Systemd is a system and service manager commonly used for managing background daemon processes (also known as services) and other system resources.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033)  
**NIST 800-53 R5 controls (16):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-11`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `IA-2`, `SA-22`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Systemd Service Creation or Modification on Linux  
**Used by 3 threat groups:** [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015)  
**Implemented by 8 software:** [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0401 Exaramel for Linux](https://attack.mitre.org/software/S0401), [S0410 Fysbis](https://attack.mitre.org/software/S0410), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0663 SysUpdate](https://attack.mitre.org/software/S0663), [S1078 RotaJakiro](https://attack.mitre.org/software/S1078), [S1198 Gomir](https://attack.mitre.org/software/S1198), [S1222 RIFLESPINE](https://attack.mitre.org/software/S1222)  

---

### T1543.003 — Windows Service
<a id="t1543003"></a>

sub-technique of [T1543](/techniques/persistence.md#t1543) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1543/003)  

Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions.

**ATT&CK mitigations (5):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (8):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-11`, `CM-2`, `CM-5`, `IA-2`  
**ATT&CK detection strategy:** Detection of Windows Service Creation or Modification  
**Used by 26 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0008 Carbanak](https://attack.mitre.org/groups/G0008), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0056 PROMETHIUM](https://attack.mitre.org/groups/G0056), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0105 DarkVishnya](https://attack.mitre.org/groups/G0105), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1021 Cinnamon Tempest](https://attack.mitre.org/groups/G1021), [G1030 Agrius](https://attack.mitre.org/groups/G1030) _(+2 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 108 software:** [S0004 TinyZBot](https://attack.mitre.org/software/S0004), [S0012 PoisonIvy](https://attack.mitre.org/software/S0012), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0024 Dyre](https://attack.mitre.org/software/S0024), [S0029 PsExec](https://attack.mitre.org/software/S0029), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0046 CozyCar](https://attack.mitre.org/software/S0046), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0071 hcdLoader](https://attack.mitre.org/software/S0071), [S0074 Sakula](https://attack.mitre.org/software/S0074), [S0081 Elise](https://attack.mitre.org/software/S0081), [S0082 Emissary](https://attack.mitre.org/software/S0082), [S0086 ZLib](https://attack.mitre.org/software/S0086), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0118 Nidiran](https://attack.mitre.org/software/S0118), [S0127 BBSRAT](https://attack.mitre.org/software/S0127), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0141 Winnti for Windows](https://attack.mitre.org/software/S0141), [S0142 StreamEx](https://attack.mitre.org/software/S0142), [S0149 MoonWind](https://attack.mitre.org/software/S0149), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154) _(+84 more)_  

---

### T1543.004 — Launch Daemon
<a id="t1543004"></a>

sub-technique of [T1543](/techniques/persistence.md#t1543) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1543/004)  

Adversaries may create or modify Launch Daemons to execute malicious payloads as part of persistence. Launch Daemons are plist files used to interact with Launchd, the service management framework used by macOS.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (8):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-11`, `CM-2`, `CM-5`, `IA-2`  
**ATT&CK detection strategy:** Detection Strategy for Launch Daemon Creation or Modification (macOS)  
**Implemented by 10 software:** [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0451 LoudMiner](https://attack.mitre.org/software/S0451), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0497 Dacls](https://attack.mitre.org/software/S0497), [S0584 AppleJeus](https://attack.mitre.org/software/S0584), [S0595 ThiefQuest](https://attack.mitre.org/software/S0595), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S0690 Green Lambert](https://attack.mitre.org/software/S0690), [S1105 COATHANGER](https://attack.mitre.org/software/S1105), [S1219 REPTILE](https://attack.mitre.org/software/S1219)  

---

### T1543.005 — Container Service
<a id="t1543005"></a>

sub-technique of [T1543](/techniques/persistence.md#t1543) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1543/005)  

Adversaries may create or modify container or container cluster management tools that run as daemons, agents, or services on individual hosts. These include software for creating and managing individual containers, such as Docker and Podman, as well as container cluster node-level agents such as kubelet.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (5):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `IA-2`  
**ATT&CK detection strategy:** Detect persistent or elevated container services via container runtime or cluster manipulation  

---

### T1547 — Boot or Logon Autostart Execution
<a id="t1547"></a>

**Tactics:** Persistence, Privilege Escalation · **Platforms:** Linux, macOS, Windows, Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547)  

Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Boot or Logon Autostart Execution Detection Strategy  
**Used by 1 threat groups:** [G1044 APT42](https://attack.mitre.org/groups/G1044)  
**Implemented by 5 software:** [S0083 Misdat](https://attack.mitre.org/software/S0083), [S0084 Mis-Type](https://attack.mitre.org/software/S0084), [S0567 Dtrack](https://attack.mitre.org/software/S0567), [S0651 BoxCaon](https://attack.mitre.org/software/S0651), [S0653 xCaon](https://attack.mitre.org/software/S0653)  

---

### T1547.001 — Registry Run Keys / Startup Folder
<a id="t1547001"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/001)  

Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**Detection:** ✅ ready-to-adapt queries in the [Technique Detection Library](../detections/TECHNIQUE_DETECTION_LIBRARY.md#t1547001) (Splunk · Elastic · Microsoft · Chronicle · CrowdStrike)  
**Used by 55 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0019 Naikon](https://attack.mitre.org/groups/G0019), [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0024 Putter Panda](https://attack.mitre.org/groups/G0024), [G0026 APT18](https://attack.mitre.org/groups/G0026), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0048 RTM](https://attack.mitre.org/groups/G0048), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0051 FIN10](https://attack.mitre.org/groups/G0051), [G0056 PROMETHIUM](https://attack.mitre.org/groups/G0056), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0064 APT33](https://attack.mitre.org/groups/G0064) _(+31 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 194 software:** [S0004 TinyZBot](https://attack.mitre.org/software/S0004), [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0012 PoisonIvy](https://attack.mitre.org/software/S0012), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0015 Ixeshe](https://attack.mitre.org/software/S0015), [S0018 Sykipot](https://attack.mitre.org/software/S0018), [S0028 SHIPSHAPE](https://attack.mitre.org/software/S0028), [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0031 BACKSPACE](https://attack.mitre.org/software/S0031), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0034 NETEAGLE](https://attack.mitre.org/software/S0034), [S0035 SPACESHIP](https://attack.mitre.org/software/S0035), [S0036 FLASHFLOOD](https://attack.mitre.org/software/S0036), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0046 CozyCar](https://attack.mitre.org/software/S0046), [S0053 SeaDuke](https://attack.mitre.org/software/S0053), [S0058 SslMM](https://attack.mitre.org/software/S0058), [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0070 HTTPBrowser](https://attack.mitre.org/software/S0070), [S0074 Sakula](https://attack.mitre.org/software/S0074), [S0080 Mivast](https://attack.mitre.org/software/S0080), [S0081 Elise](https://attack.mitre.org/software/S0081), [S0082 Emissary](https://attack.mitre.org/software/S0082) _(+170 more)_  

---

### T1547.002 — Authentication Package
<a id="t1547002"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/002)  

Adversaries may abuse authentication packages to execute DLLs when the system boots. Windows authentication package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system.

**ATT&CK mitigations (1):** [M1025 Privileged Process Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1025)  
**NIST 800-53 R5 controls (5):** `CM-6`, `SC-39`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect LSA Authentication Package Persistence via Registry and LSASS DLL Load  
**Implemented by 1 software:** [S0143 Flame](https://attack.mitre.org/software/S0143)  

---

### T1547.003 — Time Providers
<a id="t1547003"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/003)  

Adversaries may abuse time providers to execute DLLs when the system boots. The Windows Time service (W32Time) enables time synchronization across and within domains. W32Time time providers are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients.

**ATT&CK mitigations (2):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024)  
**NIST 800-53 R5 controls (10):** `AC-17`, `AC-3`, `AC-4`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Abuse of Windows Time Providers for Persistence  

---

### T1547.004 — Winlogon Helper DLL
<a id="t1547004"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/004)  

Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in. Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (13):** `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-7`, `IA-2`, `SI-10`, `SI-14`, `SI-16`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Winlogon Helper DLL Abuse via Registry and Process Artifacts on Windows  
**Used by 3 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102)  
**Implemented by 10 software:** [S0168 Gazer](https://attack.mitre.org/software/S0168), [S0200 Dipsind](https://attack.mitre.org/software/S0200), [S0351 Cannon](https://attack.mitre.org/software/S0351), [S0375 Remexi](https://attack.mitre.org/software/S0375), [S0379 Revenge RAT](https://attack.mitre.org/software/S0379), [S0387 KeyBoy](https://attack.mitre.org/software/S0387), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S1066 DarkTortilla](https://attack.mitre.org/software/S1066), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202), [S1242 Qilin](https://attack.mitre.org/software/S1242)  

---

### T1547.005 — Security Support Provider
<a id="t1547005"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/005)  

Adversaries may abuse security support providers (SSPs) to execute DLLs when the system boots. Windows SSP DLLs are loaded into the Local Security Authority (LSA) process at system start.

**ATT&CK mitigations (1):** [M1025 Privileged Process Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1025)  
**NIST 800-53 R5 controls (5):** `CM-6`, `SC-39`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Registry and LSASS Monitoring for Security Support Provider Abuse  
**Implemented by 3 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0363 Empire](https://attack.mitre.org/software/S0363)  

---

### T1547.006 — Kernel Modules and Extensions
<a id="t1547006"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** macOS, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/006)  

Adversaries may modify the kernel to automatically execute programs on system boot. Loadable Kernel Modules (LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls (18):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-4`, `IA-8`, `RA-5`, `SI-10`, `SI-14`, `SI-16`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Kernel Modules and Extensions Autostart Execution  
**Implemented by 3 software:** [S0468 Skidmap](https://attack.mitre.org/software/S0468), [S0502 Drovorub](https://attack.mitre.org/software/S0502), [S1219 REPTILE](https://attack.mitre.org/software/S1219)  

---

### T1547.007 — Re-opened Applications
<a id="t1547007"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/007)  

Adversaries may modify plist files to automatically run an application when a user logs in. When a user logs out or restarts via the macOS Graphical User Interface (GUI), a prompt is provided to the user with a checkbox to "Reopen windows when logging back in".

**ATT&CK mitigations (2):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (11):** `AC-16`, `AC-3`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detect persistence via reopened application plist modification (macOS)  

---

### T1547.008 — LSASS Driver
<a id="t1547008"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/008)  

Adversaries may modify or add LSASS drivers to obtain persistence on compromised systems. The Windows security subsystem is a set of components that manage and enforce the security policy for a computer or domain.

**ATT&CK mitigations (3):** [M1025 Privileged Process Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1025), [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043), [M1044 Restrict Library Loading](../ATTACK_MITIGATIONS_REFERENCE.md#m1044)  
**NIST 800-53 R5 controls (7):** `CM-2`, `CM-6`, `RA-5`, `SC-39`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect unauthorized LSASS driver persistence via LSA plugin abuse (Windows)  
**Implemented by 2 software:** [S0176 Wingbird](https://attack.mitre.org/software/S0176), [S0208 Pasam](https://attack.mitre.org/software/S0208)  

---

### T1547.009 — Shortcut Modification
<a id="t1547009"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/009)  

Adversaries may create or modify shortcuts that can execute a program during system boot or user login. Shortcuts or symbolic links are used to reference other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (11):** `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for T1547.009 – Shortcut Modification (Windows)  
**Used by 4 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0078 Gorgon Group](https://attack.mitre.org/groups/G0078), [G0087 APT39](https://attack.mitre.org/groups/G0087)  
**Implemented by 25 software:** [S0004 TinyZBot](https://attack.mitre.org/software/S0004), [S0028 SHIPSHAPE](https://attack.mitre.org/software/S0028), [S0031 BACKSPACE](https://attack.mitre.org/software/S0031), [S0035 SPACESHIP](https://attack.mitre.org/software/S0035), [S0053 SeaDuke](https://attack.mitre.org/software/S0053), [S0058 SslMM](https://attack.mitre.org/software/S0058), [S0085 S-Type](https://attack.mitre.org/software/S0085), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0153 RedLeaves](https://attack.mitre.org/software/S0153), [S0168 Gazer](https://attack.mitre.org/software/S0168), [S0170 Helminth](https://attack.mitre.org/software/S0170), [S0172 Reaver](https://attack.mitre.org/software/S0172), [S0244 Comnie](https://attack.mitre.org/software/S0244), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0267 FELIXROOT](https://attack.mitre.org/software/S0267), [S0270 RogueRobin](https://attack.mitre.org/software/S0270), [S0339 Micropsia](https://attack.mitre.org/software/S0339), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0534 Bazar](https://attack.mitre.org/software/S0534) _(+1 more)_  

---

### T1547.010 — Port Monitors
<a id="t1547010"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/010)  

Adversaries may use port monitors to run an adversary supplied DLL during system boot for persistence or privilege escalation. A port monitor can be set through the <code>AddMonitor</code> API call to set a DLL to be loaded at startup.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for T1547.010 – Port Monitor DLL Persistence via spoolsv.exe (Windows)  

---

### T1547.012 — Print Processors
<a id="t1547012"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/012)  

Adversaries may abuse print processors to run malicious DLLs during system boot for persistence and/or privilege escalation. Print processors are DLLs that are loaded by the print spooler service, `spoolsv.exe`, during boot.

**ATT&CK mitigations (1):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018)  
**NIST 800-53 R5 controls (8):** `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `IA-2`, `SI-4`  
**ATT&CK detection strategy:** Windows Detection Strategy for T1547.012 - Print Processor DLL Persistence  
**Used by 1 threat groups:** [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006)  
**Implemented by 2 software:** [S0501 PipeMon](https://attack.mitre.org/software/S0501), [S0666 Gelsemium](https://attack.mitre.org/software/S0666)  

---

### T1547.013 — XDG Autostart Entries
<a id="t1547013"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/013)  

Adversaries may add or modify XDG Autostart Entries to execute malicious programs or commands when a user’s desktop environment is loaded at login. XDG Autostart entries are available for any XDG-compliant Linux system.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033)  
**NIST 800-53 R5 controls (15):** `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-11`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `IA-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Linux Detection Strategy for T1547.013 - XDG Autostart Entries  
**Used by 1 threat groups:** [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 6 software:** [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0235 CrossRAT](https://attack.mitre.org/software/S0235), [S0410 Fysbis](https://attack.mitre.org/software/S0410), [S1078 RotaJakiro](https://attack.mitre.org/software/S1078), [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245)  

---

### T1547.014 — Active Setup
<a id="t1547014"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/014)  

Adversaries may achieve persistence by adding a Registry key to the Active Setup of the local machine. Active Setup is a Windows mechanism that is used to execute programs when a user logs in. The value stored in the Registry key will be executed after a user logs into the computer.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect Active Setup Persistence via StubPath Execution  
**Implemented by 1 software:** [S0012 PoisonIvy](https://attack.mitre.org/software/S0012)  

---

### T1547.015 — Login Items
<a id="t1547015"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/015)  

Adversaries may add login items to execute upon user login to gain persistence or escalate privileges. Login items are applications, documents, folders, or server connections that are automatically launched when a user logs in. Login items can be added via a shared file list or Service Management Framework.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for T1547.015 – Login Items on macOS  
**Implemented by 3 software:** [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0281 Dok](https://attack.mitre.org/software/S0281), [S0690 Green Lambert](https://attack.mitre.org/software/S0690)  

---

### T1554 — Compromise Host Software Binary
<a id="t1554"></a>

**Tactics:** Persistence · **Platforms:** Linux, macOS, Windows, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1554)  

Adversaries may modify host software binaries to establish persistent access to systems. Software binaries/executables provide a wide range of system commands or services, programs, and libraries.

**ATT&CK mitigations (1):** [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045)  
**NIST 800-53 R5 controls (9):** `CM-2`, `CM-5`, `CM-6`, `IA-9`, `SI-3`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Detect Compromise of Host Software Binaries  
**Used by 2 threat groups:** [G1023 APT5](https://attack.mitre.org/groups/G1023), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 16 software:** [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0486 Bonadan](https://attack.mitre.org/software/S0486), [S0487 Kessel](https://attack.mitre.org/software/S0487), [S0595 ThiefQuest](https://attack.mitre.org/software/S0595), [S0604 Industroyer](https://attack.mitre.org/software/S0604), [S0641 Kobalos](https://attack.mitre.org/software/S0641), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S1104 SLOWPULSE](https://attack.mitre.org/software/S1104), [S1115 WIREFIRE](https://attack.mitre.org/software/S1115), [S1116 WARPWIRE](https://attack.mitre.org/software/S1116), [S1118 BUSHWALK](https://attack.mitre.org/software/S1118), [S1119 LIGHTWIRE](https://attack.mitre.org/software/S1119), [S1120 FRAMESTING](https://attack.mitre.org/software/S1120), [S1121 LITTLELAMB.WOOLTEA](https://attack.mitre.org/software/S1121), [S1136 BFG Agonizer](https://attack.mitre.org/software/S1136), [S1184 BOLDMOVE](https://attack.mitre.org/software/S1184)  

---

### T1574 — Hijack Execution Flow
<a id="t1574"></a>

**Tactics:** Persistence, Privilege Escalation, Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1574)  

Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time.

**ATT&CK mitigations (10):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1044 Restrict Library Loading](../ATTACK_MITIGATIONS_REFERENCE.md#m1044), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051), [M1052 User Account Control](../ATTACK_MITIGATIONS_REFERENCE.md#m1052)  
**NIST 800-53 R5 controls (18):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `RA-5`, `SI-10`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Hijack Execution Flow across OS platforms.  
**Implemented by 8 software:** [S0354 Denis](https://attack.mitre.org/software/S0354), [S0444 ShimRat](https://attack.mitre.org/software/S0444), [S0567 Dtrack](https://attack.mitre.org/software/S0567), [S1018 Saint Bot](https://attack.mitre.org/software/S1018), [S1105 COATHANGER](https://attack.mitre.org/software/S1105), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1147 Nightdoor](https://attack.mitre.org/software/S1147)  

---

### T1574.001 — DLL
<a id="t1574001"></a>

sub-technique of [T1574](/techniques/persistence.md#t1574) · **Tactics:** Persistence, Privilege Escalation, Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1574/001)  

Adversaries may abuse dynamic-link library files (DLLs) in order to achieve persistence, escalate privileges, and evade defenses. DLLs are libraries that contain code and data that can be simultaneously utilized by multiple programs.

**ATT&CK mitigations (5):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1044 Restrict Library Loading](../ATTACK_MITIGATIONS_REFERENCE.md#m1044), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (8):** `CM-2`, `CM-6`, `CM-7`, `RA-5`, `SI-10`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Hijack Execution Flow for DLLs  
**Used by 32 threat groups:** [G0019 Naikon](https://attack.mitre.org/groups/G0019), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0048 RTM](https://attack.mitre.org/groups/G0048), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0098 BlackTech](https://attack.mitre.org/groups/G0098), [G0107 Whitefly](https://attack.mitre.org/groups/G0107), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0120 Evilnum](https://attack.mitre.org/groups/G0120), [G0121 Sidewinder](https://attack.mitre.org/groups/G0121), [G0126 Higaisa](https://attack.mitre.org/groups/G0126), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0131 Tonto Team](https://attack.mitre.org/groups/G0131), [G0135 BackdoorDiplomacy](https://attack.mitre.org/groups/G0135), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143) _(+8 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 67 software:** [S0009 Hikit](https://attack.mitre.org/software/S0009), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0070 HTTPBrowser](https://attack.mitre.org/software/S0070), [S0074 Sakula](https://attack.mitre.org/software/S0074), [S0098 T9000](https://attack.mitre.org/software/S0098), [S0109 WEBC2](https://attack.mitre.org/software/S0109), [S0113 Prikormka](https://attack.mitre.org/software/S0113), [S0127 BBSRAT](https://attack.mitre.org/software/S0127), [S0128 BADNEWS](https://attack.mitre.org/software/S0128), [S0134 Downdelph](https://attack.mitre.org/software/S0134), [S0153 RedLeaves](https://attack.mitre.org/software/S0153), [S0176 Wingbird](https://attack.mitre.org/software/S0176), [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0230 ZeroT](https://attack.mitre.org/software/S0230), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0280 MirageFox](https://attack.mitre.org/software/S0280), [S0354 Denis](https://attack.mitre.org/software/S0354), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0384 Dridex](https://attack.mitre.org/software/S0384), [S0398 HyperBro](https://attack.mitre.org/software/S0398), [S0415 BOOSTWRITE](https://attack.mitre.org/software/S0415) _(+43 more)_  

---

### T1574.004 — Dylib Hijacking
<a id="t1574004"></a>

sub-technique of [T1574](/techniques/persistence.md#t1574) · **Tactics:** Persistence, Privilege Escalation, Defense Evasion · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1574/004)  

Adversaries may execute their own payloads by placing a malicious dynamic library (dylib) with an expected name in a path a victim application searches at runtime. The dynamic loader will try to find the dylibs based on the sequential order of the search paths.

**ATT&CK mitigations (1):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022)  
**NIST 800-53 R5 controls (13):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-8`, `RA-5`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Hijack Execution Flow: Dylib Hijacking  
**Implemented by 1 software:** [S0363 Empire](https://attack.mitre.org/software/S0363)  

---

### T1574.005 — Executable Installer File Permissions Weakness
<a id="t1574005"></a>

sub-technique of [T1574](/techniques/persistence.md#t1574) · **Tactics:** Persistence, Privilege Escalation, Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1574/005)  

Adversaries may execute their own malicious payloads by hijacking the binaries used by an installer. These processes may automatically execute specific binaries as part of their functionality or to perform other actions.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1052 User Account Control](../ATTACK_MITIGATIONS_REFERENCE.md#m1052)  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `RA-5`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Hijack Execution Flow using Executable Installer File Permissions Weakness  
**Used by 1 threat groups:** [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129)  

---

### T1574.006 — Dynamic Linker Hijacking
<a id="t1574006"></a>

sub-technique of [T1574](/techniques/persistence.md#t1574) · **Tactics:** Persistence, Privilege Escalation, Defense Evasion · **Platforms:** Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1574/006)  

Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries.

**ATT&CK mitigations (2):** [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (4):** `CM-6`, `CM-7`, `SI-10`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Hijack Execution Flow: Dynamic Linker Hijacking  
**Used by 3 threat groups:** [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143)  
**Implemented by 6 software:** [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0394 HiddenWasp](https://attack.mitre.org/software/S0394), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S1105 COATHANGER](https://attack.mitre.org/software/S1105), [S1220 MEDUSA](https://attack.mitre.org/software/S1220)  

---

### T1574.007 — Path Interception by PATH Environment Variable
<a id="t1574007"></a>

sub-technique of [T1574](/techniques/persistence.md#t1574) · **Tactics:** Persistence, Privilege Escalation, Defense Evasion · **Platforms:** Windows, macOS, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1574/007)  

Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries. The PATH environment variable contains a list of directories (User and System) that the OS searches sequentially through in search of the binary that was called from a script or the command line.

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (15):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SI-10`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Hijack Execution Flow using Path Interception by PATH Environment Variable.  
**Implemented by 3 software:** [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0363 Empire](https://attack.mitre.org/software/S0363), [S1111 DarkGate](https://attack.mitre.org/software/S1111)  

---

### T1574.008 — Path Interception by Search Order Hijacking
<a id="t1574008"></a>

sub-technique of [T1574](/techniques/persistence.md#t1574) · **Tactics:** Persistence, Privilege Escalation, Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1574/008)  

Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs.

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (15):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SI-10`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Hijack Execution Flow using Path Interception by Search Order Hijacking  
**Implemented by 2 software:** [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0363 Empire](https://attack.mitre.org/software/S0363)  

---

### T1574.009 — Path Interception by Unquoted Path
<a id="t1574009"></a>

sub-technique of [T1574](/techniques/persistence.md#t1574) · **Tactics:** Persistence, Privilege Escalation, Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1574/009)  

Adversaries may execute their own malicious payloads by hijacking vulnerable file path references. Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch.

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (15):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SI-10`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Hijack Execution Flow through Path Interception by Unquoted Path  
**Implemented by 2 software:** [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0363 Empire](https://attack.mitre.org/software/S0363)  

---

### T1574.010 — Services File Permissions Weakness
<a id="t1574010"></a>

sub-technique of [T1574](/techniques/persistence.md#t1574) · **Tactics:** Persistence, Privilege Escalation, Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1574/010)  

Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1052 User Account Control](../ATTACK_MITIGATIONS_REFERENCE.md#m1052)  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `RA-5`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Hijack Execution Flow through Services File Permissions Weakness.  
**Implemented by 1 software:** [S0089 BlackEnergy](https://attack.mitre.org/software/S0089)  

---

### T1574.011 — Services Registry Permissions Weakness
<a id="t1574011"></a>

sub-technique of [T1574](/techniques/persistence.md#t1574) · **Tactics:** Persistence, Privilege Escalation, Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1574/011)  

Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services. Flaws in the permissions for Registry keys related to services can allow adversaries to redirect the originally specified executable to one they control, launching their own code when a service starts.

**ATT&CK mitigations (1):** [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024)  
**NIST 800-53 R5 controls (2):** `AC-6`, `CM-5`  
**ATT&CK detection strategy:** Detection Strategy for Hijack Execution Flow through Service Registry Premission Weakness.  

---

### T1574.012 — COR_PROFILER
<a id="t1574012"></a>

sub-technique of [T1574](/techniques/persistence.md#t1574) · **Tactics:** Persistence, Privilege Escalation, Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1574/012)  

Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the .NET CLR.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (9):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-7`, `IA-2`, `SI-10`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Hijack Execution Flow using the Windows COR_PROFILER.  
**Used by 1 threat groups:** [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108)  
**Implemented by 1 software:** [S1066 DarkTortilla](https://attack.mitre.org/software/S1066)  

---

### T1574.013 — KernelCallbackTable
<a id="t1574013"></a>

sub-technique of [T1574](/techniques/persistence.md#t1574) · **Tactics:** Persistence, Privilege Escalation, Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1574/013)  

Adversaries may abuse the <code>KernelCallbackTable</code> of a process to hijack its execution flow in order to run their own payloads.

**ATT&CK mitigations (1):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (7):** `CA-7`, `CM-2`, `SI-10`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Hijack Execution Flow through the KernelCallbackTable on Windows.  
**Used by 1 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032)  
**Implemented by 1 software:** [S0182 FinFisher](https://attack.mitre.org/software/S0182)  

---

### T1574.014 — AppDomainManager
<a id="t1574014"></a>

sub-technique of [T1574](/techniques/persistence.md#t1574) · **Tactics:** Persistence, Privilege Escalation, Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1574/014)  

Adversaries may execute their own malicious payloads by hijacking how the .NET `AppDomainManager` loads assemblies.

**ATT&CK mitigations (1):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CA-7`, `CM-5`, `CM-6`, `CM-7`, `SI-10`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Hijack Execution Flow through the AppDomainManager on Windows.  
**Implemented by 1 software:** [S1152 IMAPLoader](https://attack.mitre.org/software/S1152)  

---

### T1653 — Power Settings
<a id="t1653"></a>

**Tactics:** Persistence · **Platforms:** Windows, Linux, macOS, Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1653)  

Adversaries may impair a system's ability to hibernate, reboot, or shut down in order to extend access to infected machines. When a computer enters a dormant state, some or all software and hardware may cease to operate which can disrupt malicious activity.

**ATT&CK mitigations (1):** [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (4):** `CM-2`, `CM-3`, `CM-7`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Power Settings Abuse  
**Implemented by 2 software:** [S1186 Line Dancer](https://attack.mitre.org/software/S1186), [S1188 Line Runner](https://attack.mitre.org/software/S1188)  

---

### T1668 — Exclusive Control
<a id="t1668"></a>

**Tactics:** Persistence · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1668)  

Adversaries who successfully compromise a system may attempt to maintain persistence by “closing the door” behind them – in other words, by preventing other threat actors from initially accessing or maintaining a foothold on the same system.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Exclusive Control  

---

### T1671 — Cloud Application Integration
<a id="t1671"></a>

**Tactics:** Persistence · **Platforms:** Office Suite, SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1671)  

Adversaries may achieve persistence by leveraging OAuth application integrations in a software-as-a-service environment. Adversaries may create a custom application, add a legitimate application into the environment, or even co-opt an existing integration to achieve malicious ends.

**ATT&CK mitigations (2):** [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Cloud Application Integration  

---

### T1542.001 — System Firmware
<a id="t1542001"></a>

sub-technique of [T1542](/techniques/defense-evasion.md#t1542) · **Tactics:** Persistence, Defense Evasion · **Platforms:** Windows, Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1542/001)  

Adversaries may modify system firmware to persist on systems.The BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) or Extensible Firmware Interface (EFI) are examples of system firmware that operate as the software interface between the operating system and hardware of a computer.

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (17):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-3`, `CM-5`, `CM-6`, `CM-8`, `IA-2`, `IA-7`, `IA-8`, `RA-9`, `SA-10`, `SA-11`, `SC-34`, `SI-2`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for T1542.001 Pre-OS Boot: System Firmware  
**Implemented by 3 software:** [S0001 Trojan.Mebromi](https://attack.mitre.org/software/S0001), [S0047 Hacking Team UEFI Rootkit](https://attack.mitre.org/software/S0047), [S0397 LoJax](https://attack.mitre.org/software/S0397)  

---

### T1542.002 — Component Firmware
<a id="t1542002"></a>

sub-technique of [T1542](/techniques/defense-evasion.md#t1542) · **Tactics:** Persistence, Defense Evasion · **Platforms:** Windows, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1542/002)  

Adversaries may modify component firmware to persist on systems. Some adversaries may employ sophisticated means to compromise computer components and install malicious firmware that will execute adversary code outside of the operating system and main system firmware or BIOS.

**ATT&CK mitigations (1):** [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for T1542.002 Pre-OS Boot: Component Firmware  
**Used by 1 threat groups:** [G0020 Equation](https://attack.mitre.org/groups/G0020)  
**Implemented by 1 software:** [S0687 Cyclops Blink](https://attack.mitre.org/software/S0687)  

---

### T1542.003 — Bootkit
<a id="t1542003"></a>

sub-technique of [T1542](/techniques/defense-evasion.md#t1542) · **Tactics:** Persistence, Defense Evasion · **Platforms:** Linux, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1542/003)  

Adversaries may use bootkits to persist on systems. A bootkit is a malware variant that modifies the boot sectors of a hard drive, allowing malicious code to execute before a computer's operating system has loaded.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046)  
**NIST 800-53 R5 controls (18):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-8`, `IA-2`, `IA-7`, `IA-8`, `RA-9`, `SA-10`, `SA-11`, `SC-34`, `SI-2`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for File Creation or Modification of Boot Files  
**Used by 3 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0096 APT41](https://attack.mitre.org/groups/G0096)  
**Implemented by 6 software:** [S0112 ROCKBOOT](https://attack.mitre.org/software/S0112), [S0114 BOOTRASH](https://attack.mitre.org/software/S0114), [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0484 Carberp](https://attack.mitre.org/software/S0484), [S0689 WhisperGate](https://attack.mitre.org/software/S0689)  

---

### T1546.017 — Udev Rules
<a id="t1546017"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/017)  

Adversaries may maintain persistence through executing malicious content triggered using udev rules.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for T1546.017 - Udev Rules (Linux)  
**Implemented by 1 software:** [S1219 REPTILE](https://attack.mitre.org/software/S1219)  

---

### T1546.018 — Python Startup Hooks
<a id="t1546018"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/018)  

Adversaries may achieve persistence by leveraging Python’s startup mechanisms, including path configuration (`.pth`) files and the `sitecustomize.py` or `usercustomize.py` modules.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Linux Python Startup Hook Persistence via .pth and Customize Files (T1546.018)  

---

